//! The host program of the credential enclave (enclave.md section 9).
//!
//! ```text
//! credential-enclave-host
//! ```
//!
//! The host program runs in the parent pod of a Nitro enclave and takes no argument. It
//!
//! 1. starts the enclave from the enclave image file of its container image (`launch`);
//! 2. relays TCP 8080 to the listener of the node, vsock 16:8080 (`relay`);
//! 3. relays the outbound connections of the node, vsock port 8443, to port 443 of the hosts of
//!    the provider definitions and of the log store (`egress`);
//! 4. sends the operator configuration, with the log store of the node, to the node once the
//!    node answers (`config`);
//! 5. reports the state of the node on TCP 9091, `/healthz` and `/metrics` (`health`);
//! 6. on SIGTERM asks the backend to collect the state of the node, then ends the enclave
//!    (`drain`, `launch`).
//!
//! The host program is an untrusted component: nothing a node guarantees depends on it. It sees
//! the calls to the node and the TLS ciphertext between the node and the providers. It holds
//! the OAuth client values of the operator and never writes them to its output.
//!
//! Environment: `CHARACTER_API_BASE_URL` and the client values of `config`,
//! `CREDENTIAL_ENCLAVE_LOG_BUCKET` and `CREDENTIAL_ENCLAVE_LOG_REGION` of the log store, and
//! `CREDENTIAL_ENCLAVE_DRAIN_URL`, `CREDENTIAL_ENCLAVE_DRAIN_TOKEN` and
//! `CREDENTIAL_ENCLAVE_POD_NAME` of `drain`.

#![forbid(unsafe_code)]

mod config;
mod drain;
mod egress;
mod health;
mod http;
mod launch;
mod relay;
#[cfg(test)]
mod testing;

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::signal::unix::{signal, Signal, SignalKind};

use config::{ConfigError, Injection, LogStore};
use drain::Drain;
use egress::{Allowlist, TcpOutbound};
use relay::{NodeConnector, VsockListener, VsockNode};

/// The provider definitions of the node. The host program is built from the same file.
pub const DEFINITIONS: &str = include_str!("../../enclave/src/providers/definitions.json");

/// Where the inbound relay listens.
const INBOUND_PORT: u16 = 8080;
/// Where the status surface listens.
const STATUS_PORT: u16 = 9091;

/// Writes one line to the standard output. The lines of the host program are its log.
pub fn log(message: &str) {
    let _ = writeln!(
        std::io::stdout().lock(),
        "credential-enclave-host: {message}"
    );
}

/// Reads one environment variable. An empty value is a missing value.
fn variable(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Resolves when the process is asked to end. Returns the name of the signal.
async fn termination(terminate: &mut Signal, interrupt: &mut Signal) -> &'static str {
    tokio::select! {
        _ = terminate.recv() => "SIGTERM",
        _ = interrupt.recv() => "SIGINT",
    }
}

/// Pause between two `health` calls while the host program waits for the first answer.
const FIRST_ANSWER_POLL_PAUSE: Duration = Duration::from_millis(250);
/// When the host program first says that the node does not answer. The time doubles after
/// every such line.
const FIRST_SILENCE_REPORT: Duration = Duration::from_secs(10);

/// Writes one line when the node first answers its `health` call, and lines at growing
/// distances while it does not: the log then shows how long the node took to start, or that it
/// did not.
async fn report_first_answer(node: Arc<dyn NodeConnector>) {
    let started = tokio::time::Instant::now();
    let mut next_report = FIRST_SILENCE_REPORT;
    loop {
        if health::node_health(node.as_ref()).await.is_some() {
            log(&format!(
                "node: answering, {} ms after the start of the enclave",
                started.elapsed().as_millis()
            ));
            return;
        }
        if started.elapsed() >= next_report {
            log(&format!(
                "node: no answer to the health call, {} s after the start of the enclave",
                started.elapsed().as_secs()
            ));
            next_report *= 2;
        }
        tokio::time::sleep(FIRST_ANSWER_POLL_PAUSE).await;
    }
}

/// Sends the operator configuration when the node answers, and reports how the node took it.
async fn configure(node: Arc<dyn NodeConnector>, body: Vec<u8>) {
    match config::inject(node.as_ref(), &body).await {
        Injection::Accepted => log("operator configuration: accepted by the node"),
        Injection::Rejected { status, code } => log(&format!(
            "operator configuration: refused by the node with status {status} {code}, not repeated"
        )),
    }
}

/// Asks the backend to collect the state of the node, when the call is configured.
async fn collect(drain: Option<Drain>) {
    let Some(drain) = drain else {
        log("shutdown collection: skipped, its variables are not set");
        return;
    };
    log("shutdown collection: calling the backend");
    match drain.call().await {
        Ok(status) => log(&format!(
            "shutdown collection: the backend answered {status}"
        )),
        Err(reason) => log(&format!("shutdown collection: failed, {reason}")),
    }
}

async fn run() -> Result<(), String> {
    log(&format!("version {}", env!("CARGO_PKG_VERSION")));
    log(&launch::release_line(Path::new(launch::MEASUREMENTS_PATH)));

    let allowlist = Allowlist::from_definitions(DEFINITIONS)?;
    let providers = config::provider_names(DEFINITIONS)?;
    log(&format!(
        "egress: port 443 of {} provider hosts",
        allowlist.len()
    ));
    // The log store of the node: the configuration names it, and the egress relay lets the
    // node reach it. Without it a node of the nitro platform refuses every use of a
    // credential.
    let log_store = match LogStore::from_variables(&variable) {
        Ok(Some(log_store)) => {
            log(&format!(
                "log store: bucket {} in {}, egress to port 443 of {}",
                log_store.bucket,
                log_store.region,
                log_store.host()
            ));
            Some(log_store)
        }
        Ok(None) => {
            log(&format!(
                "log store: none, {} and {} are not set",
                config::LOG_BUCKET_VARIABLE,
                config::LOG_REGION_VARIABLE
            ));
            None
        }
        Err(reason) => {
            log(&format!("log store: none, {reason}"));
            None
        }
    };
    let allowlist = Arc::new(match &log_store {
        Some(log_store) => allowlist.with_log_store(log_store.host()),
        None => allowlist,
    });
    log(&config::summary(&providers, &variable));
    let operator_config = config::operator_config(&providers, &variable, log_store.as_ref());
    let drain = match Drain::from_variables(&variable) {
        Ok(drain) => drain,
        Err(reason) => {
            log(&format!(
                "shutdown collection: {} cannot be used, {reason}",
                drain::URL_VARIABLE
            ));
            None
        }
    };

    // The handlers exist before the enclave starts: from here on a termination signal is
    // something this function reads, at the two places below.
    let mut terminate = signal(SignalKind::terminate())
        .map_err(|error| format!("cannot handle SIGTERM: {error}"))?;
    let mut interrupt = signal(SignalKind::interrupt())
        .map_err(|error| format!("cannot handle SIGINT: {error}"))?;

    // Every listener is open before the enclave starts: a port that cannot be opened ends the
    // program before there is an enclave.
    let status_address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, STATUS_PORT));
    let status_listener = relay::listen_tcp(status_address)
        .map_err(|error| format!("cannot listen on TCP {status_address}: {error}"))?;
    let inbound_address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, INBOUND_PORT));
    let inbound_listener = relay::listen_tcp(inbound_address)
        .map_err(|error| format!("cannot listen on TCP {inbound_address}: {error}"))?;
    let egress_listener = VsockListener::bind(egress::EGRESS_PORT).map_err(|error| {
        format!(
            "cannot listen on vsock port {}: {error}",
            egress::EGRESS_PORT
        )
    })?;

    let node: Arc<dyn NodeConnector> = Arc::new(VsockNode);
    tokio::spawn(health::serve(status_listener, node.clone()));
    tokio::spawn(egress::serve(
        egress_listener,
        allowlist,
        Arc::new(TcpOutbound),
    ));

    // A termination signal during the start ends the program at once: the node has served no
    // call yet, and the end of the first process of the container ends `nitro-cli` and the
    // enclave with it.
    log("enclave: starting");
    tokio::select! {
        outcome = tokio::task::spawn_blocking(launch::run_enclave) => {
            outcome.map_err(|_| "the start of the enclave did not complete".to_string())??;
        }
        signal_name = termination(&mut terminate, &mut interrupt) => {
            return Err(format!("{signal_name} during the start of the enclave"));
        }
    }
    log("enclave: started");

    tokio::spawn(relay::serve(inbound_listener, node.clone()));
    tokio::spawn(report_first_answer(node.clone()));
    match operator_config {
        Ok(body) => {
            tokio::spawn(configure(node, body));
        }
        Err(ConfigError::NoBaseUrl) => log(&format!(
            "operator configuration: not sent, {} is not set",
            config::BASE_URL_VARIABLE
        )),
    }

    let signal_name = termination(&mut terminate, &mut interrupt).await;
    log(&format!("{signal_name}: shutting down"));
    collect(drain).await;
    log("enclave: ending");
    match tokio::task::spawn_blocking(launch::terminate_enclave).await {
        Ok(Ok(())) => log("enclave: ended"),
        Ok(Err(reason)) => log(&format!("enclave: {reason}")),
        Err(_) => log("enclave: the end of the enclave did not complete"),
    }
    Ok(())
}

fn main() -> ExitCode {
    if std::env::args().len() > 1 {
        eprintln!("usage: credential-enclave-host (no arguments, see the environment variables)");
        return ExitCode::from(2);
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("credential-enclave-host: cannot start the runtime");
            return ExitCode::FAILURE;
        }
    };
    let outcome = runtime.block_on(run());
    // The relays and the status surface end with the process: nothing waits for their tasks.
    runtime.shutdown_background();
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("credential-enclave-host: {error}");
            ExitCode::FAILURE
        }
    }
}
