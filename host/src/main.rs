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
//!    the provider definitions and of the log store, for a node of the reserve role to port
//!    443 of the host of the log store alone, and for a node of the forward role to port 443
//!    of any host at a public address (`egress`);
//! 4. sends the operator configuration to the node once the node answers: the client values
//!    and the log store of a node of the delegation role, the role and the log store of a
//!    node of the reserve role, or the role of a node of the forward role (`config`);
//! 5. reports the state of the node, the life of the enclave and the counts of the two relays
//!    on TCP 9091, `/healthz`, `/livez` and `/metrics` (`health`), and keeps the ready mark of
//!    the pod there: the backend sets it with `POST /ready` once the node of a pod of the
//!    delegation role or of the reserve role holds what it has to hold, the host program
//!    sets it itself once the node of a pod of the forward role took its role, and the
//!    readiness probe of the pod reads it with `/readyz` (`ready`);
//! 6. watches the enclave with `nitro-cli describe-enclaves` every 10 seconds (`watch`): when
//!    the enclave ended on its own, it asks the backend to collect what is left, ends the
//!    enclave and exits with a status that is not 0, so that the container runtime starts it
//!    again with a new enclave;
//! 7. on SIGTERM logs the enclaves `nitro-cli` describes and lets the node hand on and finish
//!    what must not end with it, then ends the enclave (`launch`). From the signal on the pod
//!    is not ready (`ready`). It closes the node, so that the node begins no further use of a
//!    credential. In a pod of the delegation role or of the reserve role it then asks the
//!    backend to collect the state of the node and waits for a time that grows with the
//!    delegations of the node (`drain`). In a pod of each of the three roles it waits for the
//!    calls the node is in the middle of and for the connections of their callers (`calls`).
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
//! delegation role, `reserve` for the reserve role, `forward` for the forward role),
//! `CHARACTER_API_BASE_URL` and the client values of `config`,
//! `CREDENTIAL_ENCLAVE_LOG_BUCKET` and `CREDENTIAL_ENCLAVE_LOG_REGION` of the log store,
//! `CREDENTIAL_ENCLAVE_MEMORY_MIB` of `launch`, and `CREDENTIAL_ENCLAVE_DRAIN_URL`,
//! `CREDENTIAL_ENCLAVE_DRAIN_TOKEN` and `CREDENTIAL_ENCLAVE_POD_NAME` of `drain`
//! (`CREDENTIAL_ENCLAVE_DRAIN_TOKEN` is the token of the call that sets the ready mark as
//! well). A pod of the reserve role reads neither the base address nor a client value: its
//! node calls no provider. A pod of the forward role reads the role and the memory, and none
//! of the others: its node holds no client value, has no log store and holds no delegation a
//! shutdown could collect or a ready mark could wait for.

#![forbid(unsafe_code)]
// The enclave ends with the host program, and a panic ends a connection or the program
// (`faults`). So:
// No input makes the program panic. Its code (not the code of its tests) holds no `unwrap`,
// no `expect`, no `panic!`, and no index or slice expression that can fail. A place that
// keeps one of them says, where it stands, why no input reaches its failure
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

mod calls;
mod config;
mod descriptors;
mod drain;
mod egress;
mod faults;
mod health;
mod http;
mod launch;
mod memory;
mod ready;
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
use faults::vital;
use ready::Readiness;
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

/// What happens to the node between the termination signal and the end of its enclave: what
/// must not end with the node is handed on, and what the node is in the middle of ends.
///
/// The node is closed first (`calls`), so that it begins no further use of a credential and
/// its calls in progress end within a time that counts from here. In a pod of the delegation
/// role or of the reserve role the backend then collects the state of the node, and moves its
/// delegations while its calls in progress end. A node of the forward role holds nothing to
/// collect. Then the calls the node is in the middle of, and the connections of their
/// callers, are waited for.
///
/// With `enclave_ended` the watch confirmed that the enclave ended on its own: the node is
/// gone and holds no call, so it is not closed and not waited for, and the collection tells
/// the backend that the node of the pod is gone.
async fn hand_on_and_finish(
    role: Role,
    drain: Option<Drain>,
    node: &dyn NodeConnector,
    callers: &relay::Pipes,
    watch: &EnclaveWatch,
    enclave_ended: bool,
) {
    let wait = match enclave_ended {
        true => None,
        false => Some(calls::Wait::begin(node, callers).await),
    };
    match role {
        Role::Delegation | Role::Reserve => collect(drain, node).await,
        Role::Forward => {}
    }
    if let Some(wait) = wait {
        log(&wait.finish_unless_ended(watch).await.line());
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

/// The log store of the node of the pod, as the environment names it: the configuration
/// names it, and the egress relay lets the node reach it. Without it a node of the nitro
/// platform takes no grant and refuses every use of a credential.
fn log_store_of_the_pod() -> Option<LogStore> {
    match LogStore::from_variables(&variable) {
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
    }
}

/// The shutdown collection call of a pod whose node holds delegations, as the environment
/// configures it.
fn drain_of_the_pod() -> Option<Drain> {
    match Drain::from_variables(&variable) {
        Ok(drain) => drain,
        Err(reason) => {
            log(&format!(
                "shutdown collection: {} cannot be used, {reason}",
                drain::URL_VARIABLE
            ));
            None
        }
    }
}

/// The ready mark of the pod (`ready`), not set, and one line of the log that says who sets
/// it. The backend sets the mark of a pod whose node holds delegations, with the token of the
/// shutdown collection call: a pod without that token is never marked. The host program sets
/// the mark of a pod of the forward role itself, and such a pod takes no call that sets it.
fn readiness_of_the_pod(role: Role) -> Readiness {
    let token = match role {
        Role::Delegation | Role::Reserve => variable(drain::TOKEN_VARIABLE),
        Role::Forward => None,
    };
    match (role, &token) {
        (Role::Forward, _) => {
            log("ready mark: set by the host program once the node took the forward role")
        }
        (_, Some(_)) => log("ready mark: set by the backend, once the node holds its delegations"),
        (_, None) => log(&format!(
            "ready mark: never set, {} is not set",
            drain::TOKEN_VARIABLE
        )),
    }
    Readiness::new(token)
}

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
    let log_store = log_store_of_the_pod();
    let allowlist = match &log_store {
        Some(log_store) => allowlist.with_log_store(log_store.host()),
        None => allowlist,
    };
    log(&config::summary(&providers, &variable));
    let operator_config = config::operator_config(&providers, &variable, log_store.as_ref());
    Ok((
        Reach::Listed(allowlist),
        operator_config,
        drain_of_the_pod(),
    ))
}

/// The setup of a pod of the reserve role: the egress relay connects to the host of the log
/// store and to nothing else, the configuration names the role and the log store and carries
/// no client value, and a shutdown asks the backend to collect the state of the node, as in a
/// pod of the delegation role. A node of the reserve role holds delegations and uses no
/// credential: the base address and the client values of the operator are not read.
fn reserve_setup() -> Setup {
    log("role: reserve, the node holds delegations and uses no credential");
    log("egress: no provider host and no mail endpoint");
    let log_store = log_store_of_the_pod();
    let allowlist = match &log_store {
        Some(log_store) => Allowlist::without_providers().with_log_store(log_store.host()),
        None => Allowlist::without_providers(),
    };
    log("operator configuration: the reserve role, no client value");
    (
        Reach::Listed(allowlist),
        Ok(config::reserve_config(log_store.as_ref())),
        drain_of_the_pod(),
    )
}

/// The setup of a pod of the forward role: the egress relay connects to port 443 of any host
/// at a public address, the configuration names the role and nothing else, and there is no
/// shutdown collection call. A node of the forward role holds no client value, has no log
/// store and holds no delegation: the variables of those are not read. What its shutdown
/// waits for is its calls in progress, the sends of the node (`calls`).
fn forward_setup() -> Setup {
    log("role: forward, the node sends the requests of secret uses");
    log("egress: port 443 of any host at a public address");
    log("log store: none, a node of the forward role writes no entry");
    log("operator configuration: the forward role, no client value");
    log(&format!(
        "shutdown: no collection, a node of the forward role holds no delegation; the sends \
         in progress have {} s to end",
        calls::WAIT_LONGEST.as_secs()
    ));
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
        Role::Reserve => reserve_setup(),
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
    let readiness = Arc::new(readiness_of_the_pod(role));
    // The tasks that accept connections serve each connection on a task of its own. The
    // program cannot do without the tasks that accept (`faults::vital`).
    tokio::spawn(vital(health::serve(
        status_listener,
        Arc::new(health::Surface {
            node: node.clone(),
            counters: counters.clone(),
            inbound: inbound_counters.clone(),
            watch: watch.clone(),
            readiness: readiness.clone(),
        }),
    )));
    tokio::spawn(vital(egress::serve(
        egress_listener,
        Arc::new(reach),
        Arc::new(TcpOutbound),
        counters,
    )));

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
    tokio::spawn(vital(watch::keep_watching(
        watch.clone(),
        launch::describe_enclaves,
        node.clone(),
    )));
    match (role, operator_config) {
        // A node takes its role once, and the first call that only a node that holds
        // delegations answers gives a node without a role the delegation role. So the node of
        // this pod takes the reserve role or the forward role before the inbound relay lets a
        // caller reach it, and a node that refuses the role ends the program: the container
        // starts again with a new enclave.
        (Role::Reserve | Role::Forward, Ok(body)) => {
            let injection = tokio::select! {
                injection = config::inject(node.as_ref(), &body) => injection,
                signal_name = termination(&mut terminate, &mut interrupt) => {
                    return Err(format!("{signal_name} before the node took its role"));
                }
            };
            match injection {
                Injection::Accepted => log(&format!(
                    "operator configuration: the node took the {} role",
                    role.name()
                )),
                Injection::Rejected { status, code } => {
                    return Err(format!(
                        "the node refused the {} role with status {status} {code}",
                        role.name()
                    ));
                }
            }
            // A node of the forward role holds nothing a backend has to fill it with: the pod
            // is ready once the node took the role.
            if role == Role::Forward && readiness.mark() {
                log("ready: the node took the forward role, the ready mark of the pod is set");
            }
        }
        (Role::Delegation, Ok(body)) => {
            tokio::spawn(vital(configure(node.clone(), body)));
        }
        (_, Err(ConfigError::NoBaseUrl)) => log(&format!(
            "operator configuration: not sent, {} is not set",
            config::BASE_URL_VARIABLE
        )),
    }
    tokio::spawn(vital(relay::serve(
        inbound_listener,
        node.clone(),
        inbound_counters.clone(),
    )));

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
    // From here on the pod is not ready, whatever its mark: no caller is to choose it.
    readiness.end();
    // Whether the node was alive at that moment: the enclave object `nitro-cli` describes,
    // or `[]`.
    match tokio::task::spawn_blocking(launch::describe_enclaves).await {
        Ok(Ok(line)) => log(&format!("enclave: describe-enclaves {line}")),
        Ok(Err(reason)) => log(&format!("enclave: describe-enclaves failed, {reason}")),
        Err(_) => log("enclave: describe-enclaves did not complete"),
    }
    hand_on_and_finish(
        role,
        drain,
        node.as_ref(),
        inbound_counters.pipes(),
        &watch,
        enclave_ended,
    )
    .await;
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
    // From here on a panic is counted and logged with its place (`faults`).
    faults::report();
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
        Invocation::Host => runtime.block_on(vital(run())),
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
mod shutdown_tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{hand_on_and_finish, Drain, EnclaveWatch, Role};
    use crate::relay::Pipes;
    use crate::testing::{health_body_with_limit, Behavior, Call, FakeNode};

    /// A node that answers `close` with 200 and whose `health` says that `calls` forward calls
    /// hold a place.
    fn node_with(calls: Arc<AtomicU64>) -> Arc<FakeNode> {
        FakeNode::new(Behavior::Answer(Arc::new(move |call: &Call| {
            match call.path.as_str() {
                "/v1/close" => (200, r#"{"accounts":0}"#.to_string()),
                "/v1/health" => {
                    let health = health_body_with_limit(true, 0, 1).replace(
                        r#""forward_calls":5"#,
                        &format!(r#""forward_calls":{}"#, calls.load(Ordering::SeqCst)),
                    );
                    (200, health)
                }
                _ => (404, "{}".to_string()),
            }
        })))
    }

    /// The shutdown collection call of a pod whose backend listens on `port`.
    fn drain_to(port: u16) -> Drain {
        let address = format!("http://127.0.0.1:{port}/api/credential-enclave/drain");
        let variable = move |name: &str| match name {
            crate::drain::URL_VARIABLE => Some(address.clone()),
            crate::drain::TOKEN_VARIABLE => Some("0123abcd".to_string()),
            crate::drain::POD_VARIABLE => Some("credential-enclave-1".to_string()),
            _ => None,
        };
        Drain::from_variables(&variable).unwrap().unwrap()
    }

    /// A backend that takes one collection call, reads its head, and answers it with 200.
    /// Returns the paths of the calls the node had received when the call arrived.
    async fn backend(listener: TcpListener, node: Arc<FakeNode>) -> Vec<String> {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        let received = node.calls().into_iter().map(|call| call.path).collect();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 17\r\n\r\n{\"complete\":true}")
            .await
            .unwrap();
        received
    }

    #[tokio::test]
    async fn a_pod_of_the_delegation_role_closes_its_node_collects_and_lets_its_calls_end() {
        let calls = Arc::new(AtomicU64::new(1));
        let node = node_with(calls.clone());
        let callers = Pipes::new(16);
        // The connection of the caller of the call in progress.
        let caller = callers.admit().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let drain = drain_to(listener.local_addr().unwrap().port());
        let backend = tokio::spawn(backend(listener, node.clone()));
        let shutdown = {
            let (node, callers) = (node.clone(), callers.clone());
            tokio::spawn(async move {
                let watch = EnclaveWatch::new();
                hand_on_and_finish(
                    Role::Delegation,
                    Some(drain),
                    node.as_ref(),
                    &callers,
                    &watch,
                    false,
                )
                .await;
            })
        };

        // The node was closed before the backend was asked to collect: from the close on, the
        // node begins no use of a credential. The call after it read the delegations of the
        // node for the wait of the collection.
        let received = backend.await.unwrap();
        assert_eq!(received, ["/v1/close", "/v1/health"]);

        // The collection is done and a call is still in progress: the enclave does not end.
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert!(!shutdown.is_finished());
        // The call ended. The connection of its caller is still open.
        calls.store(0, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert!(!shutdown.is_finished());
        drop(caller);
        tokio::time::timeout(Duration::from_secs(5), shutdown)
            .await
            .unwrap()
            .unwrap();

        // The node was closed once, and every call after the collection read its health.
        let paths: Vec<String> = node.calls().into_iter().map(|call| call.path).collect();
        assert_eq!(paths[..2], ["/v1/close", "/v1/health"]);
        assert!(paths.len() > 3 && paths[2..].iter().all(|path| path == "/v1/health"));
    }

    #[tokio::test]
    async fn a_pod_of_the_reserve_role_closes_its_node_and_collects() {
        // A node of the reserve role holds delegations, which the backend collects, and no
        // call that holds a place: the wait ends at its first look at the node.
        let node = node_with(Arc::new(AtomicU64::new(0)));
        let callers = Pipes::new(16);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let drain = drain_to(listener.local_addr().unwrap().port());
        let backend = tokio::spawn(backend(listener, node.clone()));
        let watch = EnclaveWatch::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            hand_on_and_finish(
                Role::Reserve,
                Some(drain),
                node.as_ref(),
                &callers,
                &watch,
                false,
            ),
        )
        .await
        .unwrap();
        // The backend was asked to collect after the node was closed and its delegations
        // were read, and the one call after the collection read the places of the node.
        assert_eq!(backend.await.unwrap(), ["/v1/close", "/v1/health"]);
        let paths: Vec<String> = node.calls().into_iter().map(|call| call.path).collect();
        assert_eq!(paths, ["/v1/close", "/v1/health", "/v1/health"]);
    }

    #[tokio::test]
    async fn a_pod_without_a_collection_call_lets_its_calls_end_all_the_same() {
        // The variables of the collection are not set in a pod of the delegation role or of
        // the reserve role, and a pod of the forward role has no collection: in each of the
        // three roles the node is closed and its calls are waited for.
        for role in [Role::Delegation, Role::Reserve, Role::Forward] {
            let node = node_with(Arc::new(AtomicU64::new(0)));
            let callers = Pipes::new(16);
            let watch = EnclaveWatch::new();
            hand_on_and_finish(role, None, node.as_ref(), &callers, &watch, false).await;
            let paths: Vec<String> = node.calls().into_iter().map(|call| call.path).collect();
            assert_eq!(paths, ["/v1/close", "/v1/health"], "{role:?}");
        }
    }

    #[tokio::test]
    async fn an_enclave_that_ended_on_its_own_is_collected_and_not_waited_for() {
        // The node is gone: nothing answers its calls.
        let node = FakeNode::new(Behavior::Unreachable);
        let callers = Pipes::new(16);
        let _caller = callers.admit().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let drain = drain_to(listener.local_addr().unwrap().port());
        let backend = tokio::spawn(backend(listener, node.clone()));
        let watch = EnclaveWatch::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            hand_on_and_finish(
                Role::Delegation,
                Some(drain),
                node.as_ref(),
                &callers,
                &watch,
                true,
            ),
        )
        .await
        .unwrap();
        // The backend was told, and the connection of a caller that is still open held
        // nothing up.
        assert!(backend.await.unwrap().is_empty());
        assert_eq!(callers.held(), 1);
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
