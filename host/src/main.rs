//! The host program of the credential enclave (enclave.md section 9).
//!
//! ```text
//! credential-enclave-host
//! credential-enclave-host drain
//! ```
//!
//! The host program runs in the parent pod of a Nitro enclave. Without an argument it
//!
//! 1. starts the enclave from the enclave image file of its container image, with the memory
//!    the environment gives it (`launch`);
//! 2. relays TCP 8080 to the listener of the node, vsock 16:8080 (`relay`);
//! 3. relays the outbound connections of the node, vsock port 8443, to port 443 of the hosts of
//!    the provider definitions and of the log store or, for a node of the forward role, to
//!    port 443 of any host at a public address (`egress`);
//! 4. sends the operator configuration to the node once the node answers: the client values
//!    and the log store of a node of the delegation role, or the role of a node of the
//!    forward role (`config`);
//! 5. reports the state of the node, the life of the enclave and the counts of the two relays
//!    on TCP 9091, `/healthz`, `/livez` and `/metrics` (`health`);
//! 6. watches the enclave with `nitro-cli describe-enclaves` every 10 seconds (`watch`): when
//!    the enclave ended on its own, it asks the backend to collect what is left, ends the
//!    enclave and exits with a status that is not 0, so that the container runtime starts it
//!    again with a new enclave;
//! 7. on SIGTERM logs the enclaves `nitro-cli` describes, asks the backend to collect the state
//!    of the node and waits for a time that grows with the delegations of the node, then ends the
//!    enclave (`drain`, `launch`).
//!
//! With the argument `drain` it makes the shutdown collection call of step 7 alone, logs its
//! outcome and ends with the status 0 whatever the outcome: the pre-stop hook of the pod runs
//! it before the termination signal reaches the host program.
//!
//! The host program is an untrusted component: nothing a node guarantees depends on it. It sees
//! the calls to the node and the TLS ciphertext between the node and the providers. It holds
//! the OAuth client values of the operator and never writes them to its output.
//!
//! Environment: `CREDENTIAL_ENCLAVE_ROLE` (the role of the node of the pod: not set for the
//! delegation role, `forward` for the forward role), `CHARACTER_API_BASE_URL` and the client
//! values of `config`, `CREDENTIAL_ENCLAVE_LOG_BUCKET` and `CREDENTIAL_ENCLAVE_LOG_REGION` of
//! the log store, `CREDENTIAL_ENCLAVE_MEMORY_MIB` of `launch`, and
//! `CREDENTIAL_ENCLAVE_DRAIN_URL`, `CREDENTIAL_ENCLAVE_DRAIN_TOKEN` and
//! `CREDENTIAL_ENCLAVE_POD_NAME` of `drain`. A pod of the forward role reads the first and the
//! memory, and none of the others: its node holds no client value, has no log store and
//! holds nothing a shutdown could collect.

#![forbid(unsafe_code)]
// The host program is built to abort on a panic, and the enclave ends with it. So:
// No input ends the program. Its code (not the code of its tests) holds no `unwrap`, no
// `expect`, no `panic!`, and no index or slice expression that can fail. A place that keeps
// one of them says, where it stands, why no input reaches its failure
// (`#[expect(clippy::.., reason = "..")]`).
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::get_unwrap
    )
)]

mod config;
mod descriptors;
mod drain;
mod egress;
mod health;
mod http;
mod launch;
mod memory;
mod relay;
#[cfg(test)]
mod testing;
mod watch;

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::signal::unix::{signal, Signal, SignalKind};

use config::{ConfigError, Injection, LogStore, Role};
use drain::Drain;
use egress::{Allowlist, EgressCounters, Reach, TcpOutbound};
use relay::{InboundCounters, NodeConnector, VsockListener, VsockNode};
use watch::EnclaveWatch;

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

/// Sets the connections of callers the inbound relay holds at once from what the node says of
/// the connections it holds itself (`inbound_limit` of `load` of its `health` call: a node
/// computes that bound from the memory of its kernel, enclave.md section 8), and writes one
/// line with the two numbers. A node that does not say it leaves the relay at the most it
/// holds.
fn follow_node_connections(health: &health::NodeHealth, inbound: &InboundCounters) {
    let node_connections = health.load.as_ref().and_then(|load| load.inbound_limit);
    match node_connections {
        Some(node_connections) => {
            let pipes = relay::inbound_pipes_for(node_connections);
            inbound.pipes().set_limit(pipes);
            log(&format!(
                "inbound: the node holds {node_connections} connections at once, the relay \
                 holds {pipes} connections of callers"
            ));
        }
        None => log(&format!(
            "inbound: the node does not say how many connections it holds, the relay holds \
             {} connections of callers",
            inbound.pipes().limit()
        )),
    }
}

/// Writes one line when the node first answers its `health` call, and lines at growing
/// distances while it does not: the log then shows how long the node took to start, or that it
/// did not. The first answer also says how many connections the node holds at once, and the
/// inbound relay follows it ([`follow_node_connections`]).
async fn report_first_answer(node: Arc<dyn NodeConnector>, inbound: Arc<InboundCounters>) {
    let started = tokio::time::Instant::now();
    let mut next_report = FIRST_SILENCE_REPORT;
    loop {
        if let Some(health) = health::node_health(node.as_ref()).await {
            log(&format!(
                "node: answering, {} ms after the start of the enclave",
                started.elapsed().as_millis()
            ));
            follow_node_connections(&health, &inbound);
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

/// The delegations of the node from its `health` call (`grants`: the accounts with a grant
/// within its time), for the wait of the shutdown collection call (`drain::response_timeout`).
/// `None` when the node does not answer: the wait is then the base, and the collection fails
/// at its first stage.
async fn node_delegations(node: &dyn NodeConnector) -> Option<u64> {
    health::node_health(node)
        .await
        .and_then(|health| health.grants)
}

/// One line that names the wait of a shutdown collection call and what it was computed from.
fn wait_line(delegations: Option<u64>, wait: Duration) -> String {
    match delegations {
        Some(delegations) => format!(
            "waiting {} s for the handover of {delegations} delegations",
            wait.as_secs()
        ),
        None => format!(
            "waiting {} s, the node did not answer its health call",
            wait.as_secs()
        ),
    }
}

/// Asks the backend to collect the state of the node, when the call is configured, and waits
/// for the response for the time of the delegations of the node.
async fn collect(drain: Option<Drain>, node: &dyn NodeConnector) {
    let Some(drain) = drain else {
        log("shutdown collection: skipped, its variables are not set");
        return;
    };
    let delegations = node_delegations(node).await;
    log(&format!(
        "shutdown collection: calling the backend, {}",
        wait_line(delegations, drain::response_timeout(delegations))
    ));
    match drain.call(delegations).await {
        Ok(status) => log(&format!(
            "shutdown collection: the backend answered {status}"
        )),
        Err(reason) => log(&format!("shutdown collection: failed, {reason}")),
    }
}

/// What the subcommand `drain` adds to the wait of the shutdown collection call for its own
/// start and its health call.
const DRAIN_SUBCOMMAND_MARGIN: Duration = Duration::from_secs(10);

/// The subcommand `drain`: the shutdown collection call of [`collect`] on its own, for the
/// pre-stop hook of the pod. It logs one line with the outcome and ends with the status 0 in
/// every case: a collection that fails does not hold the end of the pod, and the termination
/// signal that follows makes the same call again (the backend takes a repeated call for the
/// same pod as the same collection).
async fn run_drain() {
    if Role::from_variables(&variable) == Ok(Role::Forward) {
        log("drain: skipped, a node of the forward role holds nothing to collect");
        return;
    }
    let drain = match Drain::from_variables(&variable) {
        Ok(Some(drain)) => drain,
        Ok(None) => {
            log("drain: skipped, its variables are not set");
            return;
        }
        Err(reason) => {
            log(&format!(
                "drain: skipped, {} cannot be used, {reason}",
                drain::URL_VARIABLE
            ));
            return;
        }
    };
    let started = tokio::time::Instant::now();
    let delegations = node_delegations(&VsockNode).await;
    let wait = drain::response_timeout(delegations);
    log(&format!("drain: {}", wait_line(delegations, wait)));
    let outcome =
        tokio::time::timeout(wait + DRAIN_SUBCOMMAND_MARGIN, drain.call(delegations)).await;
    let elapsed_ms = started.elapsed().as_millis();
    match outcome {
        Ok(Ok(status)) => log(&format!(
            "drain: the backend answered {status} after {elapsed_ms} ms"
        )),
        Ok(Err(reason)) => log(&format!("drain: failed after {elapsed_ms} ms, {reason}")),
        Err(_) => log(&format!(
            "drain: no response within {} seconds",
            (wait + DRAIN_SUBCOMMAND_MARGIN).as_secs()
        )),
    }
}

/// What the role of the node of the pod decides before the enclave starts: what the egress
/// relay connects to, the operator configuration, and the shutdown collection call.
type Setup = (Reach, Result<Vec<u8>, ConfigError>, Option<Drain>);

/// The setup of a pod of the delegation role: the egress relay connects to the hosts of the
/// provider definitions and of the log store, the configuration carries the client values of
/// the operator and the log store, and a shutdown asks the backend to collect the state of the
/// node.
fn delegation_setup() -> Result<Setup, String> {
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
                "log store: {} in {}, egress to port 443 of {}",
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
    let allowlist = match &log_store {
        Some(log_store) => allowlist.with_log_store(log_store.host()),
        None => allowlist,
    };
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
    Ok((Reach::Listed(allowlist), operator_config, drain))
}

/// The setup of a pod of the forward role: the egress relay connects to port 443 of any host
/// at a public address, the configuration names the role and nothing else, and there is no
/// shutdown collection call. A node of the forward role holds no client value, has no log
/// store and holds no delegation: the variables of those are not read.
fn forward_setup() -> Setup {
    log("role: forward, the node sends the requests of secret uses");
    log("egress: port 443 of any host at a public address");
    log("log store: none, a node of the forward role writes no entry");
    log("operator configuration: the forward role, no client value");
    log("shutdown collection: none, a node of the forward role holds nothing to collect");
    (Reach::PublicHosts, Ok(config::forward_config()), None)
}

async fn run() -> Result<(), String> {
    log(&format!("version {}", env!("CARGO_PKG_VERSION")));
    log(&launch::release_line(Path::new(launch::MEASUREMENTS_PATH)));
    match descriptors::raise_limit() {
        Some((soft, hard)) => log(&format!("descriptors: limit {soft}, hard limit {hard}")),
        None => log("descriptors: the platform has no limit of open descriptors"),
    }
    let memory_mib = launch::memory_mib(&variable)?;
    log(&format!("enclave: memory {memory_mib} MiB, 2 vCPUs"));

    let role = Role::from_variables(&variable)?;
    let (reach, operator_config, drain) = match role {
        Role::Delegation => delegation_setup()?,
        Role::Forward => forward_setup(),
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
    let status_listener = relay::listen_tcp(status_address, relay::LISTEN_BACKLOG)
        .map_err(|error| format!("cannot listen on TCP {status_address}: {error}"))?;
    let inbound_address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, INBOUND_PORT));
    let inbound_listener = relay::listen_tcp(inbound_address, relay::INBOUND_LISTEN_BACKLOG)
        .map_err(|error| format!("cannot listen on TCP {inbound_address}: {error}"))?;
    let egress_listener = VsockListener::bind(egress::EGRESS_PORT).map_err(|error| {
        format!(
            "cannot listen on vsock port {}: {error}",
            egress::EGRESS_PORT
        )
    })?;
    // The queue of the egress listener holds the connections the node opens at once. A kernel
    // that refuses the length leaves the listener with its default queue: the program goes on.
    match egress_listener.widen_backlog() {
        Ok(backlog) => log(&format!("egress: vsock listener backlog {backlog}")),
        Err(error) => log(&format!(
            "egress: the backlog of the vsock listener stays at the default: {error}"
        )),
    }

    let node: Arc<dyn NodeConnector> = Arc::new(VsockNode);
    let counters = Arc::new(EgressCounters::default());
    let inbound_counters = Arc::new(InboundCounters::default());
    let watch = EnclaveWatch::new();
    tokio::spawn(health::serve(
        status_listener,
        node.clone(),
        counters.clone(),
        inbound_counters.clone(),
        watch.clone(),
    ));
    tokio::spawn(egress::serve(
        egress_listener,
        Arc::new(reach),
        Arc::new(TcpOutbound),
        counters,
    ));

    // A termination signal during the start ends the program at once: the node has served no
    // call yet, and the end of the first process of the container ends `nitro-cli` and the
    // enclave with it.
    log("enclave: starting");
    tokio::select! {
        outcome = tokio::task::spawn_blocking(move || launch::run_enclave(memory_mib)) => {
            outcome.map_err(|_| "the start of the enclave did not complete".to_string())??;
        }
        signal_name = termination(&mut terminate, &mut interrupt) => {
            return Err(format!("{signal_name} during the start of the enclave"));
        }
    }
    log("enclave: started");

    tokio::spawn(report_first_answer(node.clone(), inbound_counters.clone()));
    tokio::spawn(watch::keep_watching(
        watch.clone(),
        launch::describe_enclaves,
        node.clone(),
    ));
    match (role, operator_config) {
        // A node takes its role once, and a call of the delegation role gives a node without
        // a role that role. So the node of this pod takes the forward role before the inbound
        // relay lets a caller reach it, and a node that refuses the role ends the program:
        // the container starts again with a new enclave.
        (Role::Forward, Ok(body)) => {
            let injection = tokio::select! {
                injection = config::inject(node.as_ref(), &body) => injection,
                signal_name = termination(&mut terminate, &mut interrupt) => {
                    return Err(format!("{signal_name} before the node took its role"));
                }
            };
            match injection {
                Injection::Accepted => {
                    log("operator configuration: the node took the forward role")
                }
                Injection::Rejected { status, code } => {
                    return Err(format!(
                        "the node refused the forward role with status {status} {code}"
                    ));
                }
            }
        }
        (Role::Delegation, Ok(body)) => {
            tokio::spawn(configure(node.clone(), body));
        }
        (_, Err(ConfigError::NoBaseUrl)) => log(&format!(
            "operator configuration: not sent, {} is not set",
            config::BASE_URL_VARIABLE
        )),
    }
    tokio::spawn(relay::serve(
        inbound_listener,
        node.clone(),
        inbound_counters,
    ));

    // The host program ends on a termination signal, or when the watch confirmed that the
    // enclave ended on its own: the state of the node is gone then, and the one recovery is
    // the restart of the container with a new enclave.
    let enclave_ended = tokio::select! {
        signal_name = termination(&mut terminate, &mut interrupt) => {
            log(&format!("{signal_name}: shutting down"));
            false
        }
        _ = watch.wait_ended() => {
            log("enclave ended: shutting down, the container restarts with a new enclave");
            true
        }
    };
    // Whether the node was alive at that moment: the enclave object `nitro-cli` describes,
    // or `[]`.
    match tokio::task::spawn_blocking(launch::describe_enclaves).await {
        Ok(Ok(line)) => log(&format!("enclave: describe-enclaves {line}")),
        Ok(Err(reason)) => log(&format!("enclave: describe-enclaves failed, {reason}")),
        Err(_) => log("enclave: describe-enclaves did not complete"),
    }
    if role == Role::Delegation {
        collect(drain, node.as_ref()).await;
    }
    log("enclave: ending");
    match tokio::task::spawn_blocking(launch::terminate_enclave).await {
        Ok(Ok(())) => log("enclave: ended"),
        Ok(Err(reason)) => log(&format!("enclave: {reason}")),
        Err(_) => log("enclave: the end of the enclave did not complete"),
    }
    if enclave_ended {
        return Err("the enclave ended on its own".to_string());
    }
    Ok(())
}

/// What the arguments ask for: the host program, or the subcommand `drain`.
#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Host,
    Drain,
}

/// Reads the arguments after the program name. Anything but no argument or the one argument
/// `drain` is a usage error.
fn invocation(arguments: impl Iterator<Item = String>) -> Option<Invocation> {
    let arguments: Vec<String> = arguments.collect();
    match arguments.iter().map(String::as_str).collect::<Vec<&str>>()[..] {
        [] => Some(Invocation::Host),
        ["drain"] => Some(Invocation::Drain),
        _ => None,
    }
}

fn main() -> ExitCode {
    let Some(invocation) = invocation(std::env::args().skip(1)) else {
        eprintln!("usage: credential-enclave-host [drain] (see the environment variables)");
        return ExitCode::from(2);
    };
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
    let outcome = match invocation {
        Invocation::Host => runtime.block_on(run()),
        Invocation::Drain => {
            runtime.block_on(run_drain());
            Ok(())
        }
    };
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

#[cfg(test)]
mod argument_tests {
    use super::{invocation, Invocation};

    fn parse(arguments: &[&str]) -> Option<Invocation> {
        invocation(arguments.iter().map(|argument| argument.to_string()))
    }

    #[test]
    fn the_one_argument_is_the_subcommand_drain() {
        assert_eq!(parse(&[]), Some(Invocation::Host));
        assert_eq!(parse(&["drain"]), Some(Invocation::Drain));
        assert_eq!(parse(&["drain", "now"]), None);
        assert_eq!(parse(&["--drain"]), None);
        assert_eq!(parse(&["start"]), None);
    }
}
