//! The status surface of the host program (enclave.md section 9): TCP 9091.
//!
//! - `GET /healthz`: 200 when the `health` call of the node completes within 8 seconds, 503
//!   otherwise. The responsiveness of the node: the startup and readiness probes of the pod
//!   read it.
//! - `GET /livez`: 200 while the enclave runs, 503 once the watch of the enclave (`watch.rs`)
//!   confirmed that it ended. The life of the enclave, without a call to the node: the
//!   liveness probe of the pod reads it. A node that does not answer is not a dead enclave,
//!   and a pod replaced for that reason would lose the delegations of a living node.
//! - `GET /metrics`: the Prometheus text format. Four gauges from the `health` call; the
//!   series of the `log` object of the call (six counters and one gauge, and the write counts
//!   of a node of release v2.1.0 or later), of its `log_store` object, of its `load` object
//!   (two gauges, three counters and two gauges, and the two counts of the connections from
//!   the backend and the two values of the descriptors of a node of release v2.2.0 or later),
//!   of its `egress` object and of its `refresh` object, each when the node answers with one;
//!   the gauge of its `grants` value and the four gauges of its `state` object, each when the
//!   node answers with it; and, with every answer, the series of the host program itself: the
//!   gauge of the watch of the enclave, the two gauges of its own descriptors, and the four
//!   series of the two relays.
//!
//! Every request of `/healthz` and `/metrics` makes one `health` call over a new connection to
//! the node. Nothing is cached: an answer says what the node answered just now.

use std::convert::Infallible;
use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Deserialize;
use tokio::net::TcpListener;

use crate::descriptors;
use crate::egress::EgressCounters;
use crate::http;
use crate::relay::{self, AcceptFailure, InboundCounters, NodeConnector};
use crate::watch::EnclaveWatch;

/// Longest `health` round trip that counts as a success.
pub const HEALTH_TIMEOUT: Duration = Duration::from_secs(8);
/// Longest `health` body the host program reads.
const HEALTH_BODY_LIMIT_BYTES: usize = 64 * 1024;
/// Longest wait for the head of a request on the status port.
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(10);

const TEXT: &str = "text/plain; charset=utf-8";
const PROMETHEUS_TEXT: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The values of the `health` call the host program reads (enclave.md 5.1). The response has
/// more fields: they are not read. `log` is absent in the response of a node of a release
/// before v2.0.0, `load` in the response of a node of a release before v2.0.1, and `egress`,
/// `refresh` and `state` in the response of a node of a release before v2.1.0. `log_store` is
/// null in the response of a node without a log store. `grants` is read when the response has
/// it.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct NodeHealth {
    pub configured: bool,
    pub accounts: u64,
    pub started_ms: u64,
    #[serde(default)]
    pub grants: Option<u64>,
    #[serde(default)]
    pub log: Option<LogCounts>,
    #[serde(default)]
    pub load: Option<Load>,
    #[serde(default)]
    pub log_store: Option<LogStoreState>,
    #[serde(default)]
    pub egress: Option<EgressCounts>,
    #[serde(default)]
    pub refresh: Option<RefreshCounts>,
    #[serde(default)]
    pub state: Option<StateCounts>,
}

/// The `state` object of the `health` call: the sizes of the variable state of the accounts of
/// the node and its idle connections at the moment of the call.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct StateCounts {
    pub kept_refreshes: u64,
    pub merge_keys: u64,
    pub pending_entries: u64,
    pub idle_connections: IdleConnections,
}

/// `idle_connections` of the `state` object: the idle connections of the node, by peer.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct IdleConnections {
    pub provider: u64,
    pub log_store: u64,
}

/// The `log` object of the `health` call: counts since the node started. The five values after
/// `batch_requests` are the write counts of a node of release v2.1.0 or later, and absent
/// before.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct LogCounts {
    pub entries: u64,
    pub events: u64,
    pub writes: u64,
    pub write_failures: u64,
    pub open_batches: u64,
    pub batch_calls: u64,
    pub batch_requests: u64,
    #[serde(default)]
    pub write_attempt_failures: Option<WriteAttemptFailures>,
    #[serde(default)]
    pub write_retries: Option<u64>,
    #[serde(default)]
    pub write_ms_buckets: Option<WriteMsBuckets>,
    #[serde(default)]
    pub write_ms_sum: Option<u64>,
    #[serde(default)]
    pub write_count: Option<u64>,
}

/// `write_attempt_failures` of the `log` object: PUT attempts to the log store that failed, by
/// cause.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct WriteAttemptFailures {
    pub connect: u64,
    pub tls: u64,
    pub closed: u64,
    pub timeout: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
}

/// `write_ms_buckets` of the `log` object: the writes the log store confirmed within the
/// milliseconds of each key, cumulative.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct WriteMsBuckets {
    #[serde(rename = "25")]
    pub within_25: u64,
    #[serde(rename = "50")]
    pub within_50: u64,
    #[serde(rename = "100")]
    pub within_100: u64,
    #[serde(rename = "250")]
    pub within_250: u64,
    #[serde(rename = "500")]
    pub within_500: u64,
    #[serde(rename = "1000")]
    pub within_1000: u64,
    #[serde(rename = "2500")]
    pub within_2500: u64,
    #[serde(rename = "5000")]
    pub within_5000: u64,
}

impl WriteMsBuckets {
    /// The buckets with their bounds in seconds, as the `le` label of the histogram.
    pub fn seconds(&self) -> [(&'static str, u64); 8] {
        [
            ("0.025", self.within_25),
            ("0.05", self.within_50),
            ("0.1", self.within_100),
            ("0.25", self.within_250),
            ("0.5", self.within_500),
            ("1", self.within_1000),
            ("2.5", self.within_2500),
            ("5", self.within_5000),
        ]
    }
}

/// The `log_store` object of the `health` call: the two values the host program reads. The
/// object names the bucket and the region too: they are not read. `pending_oldest_ms` is absent
/// in the response of a node of a release before v2.1.0.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct LogStoreState {
    pub pending: u64,
    #[serde(default)]
    pub pending_oldest_ms: Option<u64>,
}

/// The `egress` object of the `health` call: the outbound connections of the node since it
/// started, and those it opens at this moment.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct EgressCounts {
    pub opens: u64,
    pub open_failures: OpenFailures,
    pub open_retries: u64,
    pub open_inflight: u64,
    pub idle_reuses: IdleReuses,
}

/// `open_failures` of the `egress` object: attempts to open an outbound connection that
/// failed, by cause.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct OpenFailures {
    pub transport: u64,
    pub relay_refused: u64,
    pub tls: u64,
    pub http: u64,
}

/// `idle_reuses` of the `egress` object: requests sent over an idle connection, by peer.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct IdleReuses {
    pub provider: u64,
    pub log_store: u64,
}

/// The `refresh` object of the `health` call: the token address calls of `refresh` that passed
/// the time limit of their call.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct RefreshCounts {
    pub late: LateRefreshes,
    pub late_inflight: u64,
}

/// `late` of the `refresh` object: the late token address calls since the node started, by
/// outcome.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct LateRefreshes {
    pub kept: u64,
    pub dropped: u64,
    pub failed: u64,
    pub abandoned: u64,
}

/// The `load` object of the `health` call: the load of the node at the moment of the call. The
/// five values of the kernel are null when the kernel of the node exposes no procfs value.
/// The two counts of the connections from the backend and the two values of the descriptors
/// are absent in the response of a node of a release before v2.2.0, and each of the two
/// values of the descriptors is null when the kernel of the node exposes none.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Load {
    pub provider_inflight: u64,
    pub forward_calls: u64,
    #[serde(default)]
    pub inbound_connections: Option<u64>,
    #[serde(default)]
    pub inbound_refused: Option<u64>,
    pub cpu_user_ms: Option<u64>,
    pub cpu_system_ms: Option<u64>,
    pub cpu_idle_ms: Option<u64>,
    pub memory_total_bytes: Option<u64>,
    pub memory_available_bytes: Option<u64>,
    #[serde(default)]
    pub descriptors_open: Option<u64>,
    #[serde(default)]
    pub descriptors_limit: Option<u64>,
}

/// Calls `GET /v1/health` of the node. `None` when the connection, the call or the reading of
/// the response fails, when the status is not 200 or when the round trip takes longer than 8
/// seconds.
pub async fn node_health(node: &dyn NodeConnector) -> Option<NodeHealth> {
    let call = async {
        let stream = node.connect().await.ok()?;
        let request =
            http::request(Method::GET, http::NODE_HOST, "/v1/health", &[], Vec::new()).ok()?;
        let reply = http::exchange(stream, request, HEALTH_BODY_LIMIT_BYTES)
            .await
            .ok()?;
        if reply.status != 200 {
            return None;
        }
        serde_json::from_slice::<NodeHealth>(&reply.body).ok()
    };
    tokio::time::timeout(HEALTH_TIMEOUT, call)
        .await
        .ok()
        .flatten()
}

fn series(text: &mut String, kind: &str, name: &str, help: &str, value: std::fmt::Arguments<'_>) {
    let _ = writeln!(text, "# HELP {name} {help}");
    let _ = writeln!(text, "# TYPE {name} {kind}");
    let _ = writeln!(text, "{name} {value}");
}

fn gauge(text: &mut String, name: &str, help: &str, value: std::fmt::Arguments<'_>) {
    series(text, "gauge", name, help, value);
}

fn counter(text: &mut String, name: &str, help: &str, value: u64) {
    series(text, "counter", name, help, format_args!("{value}"));
}

/// A series of seconds from a value in milliseconds, with three decimals.
fn seconds(text: &mut String, kind: &str, name: &str, help: &str, ms: u64) {
    series(
        text,
        kind,
        name,
        help,
        format_args!("{}.{:03}", ms / 1000, ms % 1000),
    );
}

/// A counter of seconds from a value in milliseconds, with three decimals.
fn seconds_counter(text: &mut String, name: &str, help: &str, ms: u64) {
    seconds(text, "counter", name, help, ms);
}

/// A gauge of seconds from a value in milliseconds, with three decimals.
fn seconds_gauge(text: &mut String, name: &str, help: &str, ms: u64) {
    seconds(text, "gauge", name, help, ms);
}

/// A series with one label: one sample per value of the label, in the order given.
fn labeled_series(
    text: &mut String,
    kind: &str,
    name: &str,
    help: &str,
    label: &str,
    samples: &[(&str, u64)],
) {
    let _ = writeln!(text, "# HELP {name} {help}");
    let _ = writeln!(text, "# TYPE {name} {kind}");
    for (value, count) in samples {
        let _ = writeln!(text, "{name}{{{label}=\"{value}\"}} {count}");
    }
}

/// A counter with one label.
fn labeled_counter(
    text: &mut String,
    name: &str,
    help: &str,
    label: &str,
    samples: &[(&str, u64)],
) {
    labeled_series(text, "counter", name, help, label, samples);
}

/// A gauge with one label.
fn labeled_gauge(text: &mut String, name: &str, help: &str, label: &str, samples: &[(&str, u64)]) {
    labeled_series(text, "gauge", name, help, label, samples);
}

/// A histogram of seconds: one `_bucket` sample per bound with the cumulative count within it,
/// the `+Inf` bucket and `_count` from `count`, and `_sum` from a value in milliseconds with
/// three decimals.
fn seconds_histogram(
    text: &mut String,
    name: &str,
    help: &str,
    buckets: &[(&str, u64)],
    sum_ms: u64,
    count: u64,
) {
    let _ = writeln!(text, "# HELP {name} {help}");
    let _ = writeln!(text, "# TYPE {name} histogram");
    for (bound, within) in buckets {
        let _ = writeln!(text, "{name}_bucket{{le=\"{bound}\"}} {within}");
    }
    let _ = writeln!(text, "{name}_bucket{{le=\"+Inf\"}} {count}");
    let _ = writeln!(text, "{name}_sum {}.{:03}", sum_ms / 1000, sum_ms % 1000);
    let _ = writeln!(text, "{name}_count {count}");
}

/// The metrics of one `health` call and of the host program itself. A failed call gives
/// `credential_enclave_up 0` and the series of the host program: the other series repeat
/// values of the response, and there is none. The series of the response come after the four
/// gauges in the order of its objects, each when the node answered with the object: the seven
/// series of the `log` object and, when the node gave its write counts, their series; the
/// gauges of the `log_store` object; the series of the `load` object (two gauges, then the
/// gauge and the counter of the connections from the backend when the node gave the two
/// counts, then the three CPU counters when the node gave the three values, then the two
/// memory gauges when it gave the two values, then the two gauges of the descriptors, each
/// when the node gave the value); the series of the `egress` object; the series of the
/// `refresh` object; the gauge of the `grants` value; the gauges of the `state` object. The
/// series of the host program come last: the gauge of the watch of the enclave
/// (`enclave_running`: what the last answer of `describe-enclaves` said, 1 before the first
/// answer), the two gauges of the descriptors of the host program (`descriptors`: the open
/// descriptors and the limit in force, when the kernel gives both), and the four series of the
/// two relays. A counter of the node restarts at 0 when the node restarts (the started
/// timestamp changes then), a CPU counter when the kernel of the node boots, and a counter of
/// the host program when the host program starts.
pub fn metrics(
    health: Option<&NodeHealth>,
    counters: &EgressCounters,
    inbound: &InboundCounters,
    enclave_running: Option<bool>,
    descriptors: Option<(u64, u64)>,
) -> String {
    let mut text = String::new();
    gauge(
        &mut text,
        "credential_enclave_up",
        "1 when the health call of the enclave node succeeds, 0 when it fails.",
        format_args!("{}", u8::from(health.is_some())),
    );
    if let Some(health) = health {
        node_series(&mut text, health);
    }
    host_series(&mut text, counters, inbound, enclave_running, descriptors);
    text
}

/// The open descriptors of the host program and the limit in force, when the kernel gives
/// both: the values of the two `descriptors` gauges of [`metrics`].
fn host_descriptors() -> Option<(u64, u64)> {
    Some((descriptors::open_count()?, descriptors::soft_limit()?))
}

/// The series of the response of the `health` call.
fn node_series(text: &mut String, health: &NodeHealth) {
    gauge(
        text,
        "credential_enclave_configured",
        "1 when the enclave node holds the operator configuration.",
        format_args!("{}", u8::from(health.configured)),
    );
    gauge(
        text,
        "credential_enclave_accounts",
        "Accounts with a log chain on the enclave node.",
        format_args!("{}", health.accounts),
    );
    gauge(
        text,
        "credential_enclave_started_timestamp_seconds",
        "Start time of the enclave node in seconds since the Unix epoch.",
        format_args!(
            "{}.{:03}",
            health.started_ms / 1000,
            health.started_ms % 1000
        ),
    );
    if let Some(log) = &health.log {
        log_series(text, log);
    }
    if let Some(log_store) = &health.log_store {
        log_store_series(text, log_store);
    }
    if let Some(load) = &health.load {
        load_series(text, load);
    }
    if let Some(egress) = &health.egress {
        egress_series(text, egress);
    }
    if let Some(refresh) = &health.refresh {
        refresh_series(text, refresh);
    }
    if let Some(grants) = health.grants {
        gauge(
            text,
            "credential_enclave_grants",
            "Accounts of the enclave node that have a grant within its time.",
            format_args!("{grants}"),
        );
    }
    if let Some(state) = &health.state {
        state_series(text, state);
    }
}

/// The gauges of the `state` object.
fn state_series(text: &mut String, state: &StateCounts) {
    gauge(
        text,
        "credential_enclave_kept_refreshes",
        "Kept refresh responses of the enclave node over every account at this moment.",
        format_args!("{}", state.kept_refreshes),
    );
    gauge(
        text,
        "credential_enclave_merge_keys",
        "Merge keys of identical GET requests of the enclave node over every account at this moment.",
        format_args!("{}", state.merge_keys),
    );
    gauge(
        text,
        "credential_enclave_pending_entries",
        "Log entries of the enclave node that the log store has not confirmed at this moment.",
        format_args!("{}", state.pending_entries),
    );
    labeled_gauge(
        text,
        "credential_enclave_idle_connections",
        "Idle connections the enclave node keeps at this moment, by peer.",
        "peer",
        &[
            ("provider", state.idle_connections.provider),
            ("log_store", state.idle_connections.log_store),
        ],
    );
}

/// The series of the `log` object: six counters and one gauge, then the series of the write
/// counts of a node of release v2.1.0 or later, each when the object holds its values.
fn log_series(text: &mut String, log: &LogCounts) {
    counter(
        text,
        "credential_enclave_log_entries_total",
        "Log entries the enclave node created since it started.",
        log.entries,
    );
    counter(
        text,
        "credential_enclave_log_events_total",
        "Events in the log entries the enclave node created since it started.",
        log.events,
    );
    counter(
        text,
        "credential_enclave_log_store_writes_total",
        "PUT requests the enclave node sent to its log store since it started.",
        log.writes,
    );
    counter(
        text,
        "credential_enclave_log_store_write_failures_total",
        "PUT requests to the log store that the store did not confirm since the enclave node started.",
        log.write_failures,
    );
    counter(
        text,
        "credential_enclave_forward_batch_calls_total",
        "forward/batch calls that passed the common front of the enclave node since it started.",
        log.batch_calls,
    );
    counter(
        text,
        "credential_enclave_forward_batch_requests_total",
        "Provider requests in the forward/batch calls of the enclave node since it started.",
        log.batch_requests,
    );
    gauge(
        text,
        "credential_enclave_log_open_batches",
        "Accounts of the enclave node whose open batch holds events at this moment.",
        format_args!("{}", log.open_batches),
    );
    if let Some(failures) = &log.write_attempt_failures {
        labeled_counter(
            text,
            "credential_enclave_log_store_write_attempt_failures_total",
            "PUT attempts to the log store that failed since the enclave node started, by cause.",
            "cause",
            &[
                ("connect", failures.connect),
                ("tls", failures.tls),
                ("closed", failures.closed),
                ("timeout", failures.timeout),
                ("status_4xx", failures.status_4xx),
                ("status_5xx", failures.status_5xx),
            ],
        );
    }
    if let Some(retries) = log.write_retries {
        counter(
            text,
            "credential_enclave_log_store_write_retries_total",
            "PUT attempts to the log store that repeated a failed attempt since the enclave node started.",
            retries,
        );
    }
    if let (Some(buckets), Some(sum_ms), Some(count)) =
        (&log.write_ms_buckets, log.write_ms_sum, log.write_count)
    {
        seconds_histogram(
            text,
            "credential_enclave_log_store_write_seconds",
            "Time from the start of the write of a log entry to its confirmation by the log store, in seconds, for the writes since the enclave node started.",
            &buckets.seconds(),
            sum_ms,
            count,
        );
    }
}

/// The gauges of the `log_store` object.
fn log_store_series(text: &mut String, log_store: &LogStoreState) {
    gauge(
        text,
        "credential_enclave_log_store_pending_accounts",
        "Accounts of the enclave node that have a pending log entry at this moment.",
        format_args!("{}", log_store.pending),
    );
    if let Some(oldest_ms) = log_store.pending_oldest_ms {
        seconds_gauge(
            text,
            "credential_enclave_log_store_pending_oldest_seconds",
            "Age of the oldest pending log entry of the enclave node in seconds, 0 when there is none.",
            oldest_ms,
        );
    }
}

/// The series of the `load` object: two gauges, then the gauge and the counter of the
/// connections from the backend when the node gave the two counts, then the three CPU counters
/// when the node gave the three values, then the two memory gauges when it gave the two
/// values, then the two gauges of the descriptors, each when the node gave the value.
fn load_series(text: &mut String, load: &Load) {
    gauge(
        text,
        "credential_enclave_provider_inflight",
        "Provider requests of the enclave node in flight at this moment.",
        format_args!("{}", load.provider_inflight),
    );
    gauge(
        text,
        "credential_enclave_forward_calls",
        "forward and forward/batch calls of the enclave node that hold a concurrency slot at this moment.",
        format_args!("{}", load.forward_calls),
    );
    if let (Some(connections), Some(refused)) = (load.inbound_connections, load.inbound_refused) {
        gauge(
            text,
            "credential_enclave_inbound_connections",
            "Connections from the backend the enclave node holds open at this moment.",
            format_args!("{connections}"),
        );
        counter(
            text,
            "credential_enclave_inbound_refused_total",
            "Connections from the backend the enclave node closed at accept because its bound of open connections was reached, since it started.",
            refused,
        );
    }
    if let (Some(user), Some(system), Some(idle)) =
        (load.cpu_user_ms, load.cpu_system_ms, load.cpu_idle_ms)
    {
        seconds_counter(
            text,
            "credential_enclave_cpu_user_seconds_total",
            "CPU time in user mode of the enclave kernel since it booted, in seconds.",
            user,
        );
        seconds_counter(
            text,
            "credential_enclave_cpu_system_seconds_total",
            "CPU time in system mode of the enclave kernel since it booted, in seconds.",
            system,
        );
        seconds_counter(
            text,
            "credential_enclave_cpu_idle_seconds_total",
            "CPU time in idle mode of the enclave kernel since it booted, in seconds.",
            idle,
        );
    }
    if let (Some(total), Some(available)) = (load.memory_total_bytes, load.memory_available_bytes) {
        gauge(
            text,
            "credential_enclave_memory_total_bytes",
            "Memory of the enclave kernel in bytes.",
            format_args!("{total}"),
        );
        gauge(
            text,
            "credential_enclave_memory_available_bytes",
            "Memory of the enclave kernel that it estimates it can give out, in bytes.",
            format_args!("{available}"),
        );
    }
    if let Some(open) = load.descriptors_open {
        gauge(
            text,
            "credential_enclave_descriptors_open",
            "Open file descriptors of the enclave node process at this moment.",
            format_args!("{open}"),
        );
    }
    if let Some(limit) = load.descriptors_limit {
        gauge(
            text,
            "credential_enclave_descriptors_limit",
            "Limit of open file descriptors of the enclave node process in force.",
            format_args!("{limit}"),
        );
    }
}

/// The series of the `egress` object.
fn egress_series(text: &mut String, egress: &EgressCounts) {
    counter(
        text,
        "credential_enclave_egress_opens_total",
        "Outbound connections the enclave node opened since it started.",
        egress.opens,
    );
    labeled_counter(
        text,
        "credential_enclave_egress_open_failures_total",
        "Attempts of the enclave node to open an outbound connection that failed since it started, by cause.",
        "cause",
        &[
            ("transport", egress.open_failures.transport),
            ("relay_refused", egress.open_failures.relay_refused),
            ("tls", egress.open_failures.tls),
            ("http", egress.open_failures.http),
        ],
    );
    counter(
        text,
        "credential_enclave_egress_open_retries_total",
        "Attempts of the enclave node to open an outbound connection that repeated a failed attempt since it started.",
        egress.open_retries,
    );
    gauge(
        text,
        "credential_enclave_egress_open_inflight",
        "Outbound connections the enclave node is opening at this moment.",
        format_args!("{}", egress.open_inflight),
    );
    labeled_counter(
        text,
        "credential_enclave_egress_idle_reuses_total",
        "Requests the enclave node sent over an idle connection since it started, by peer.",
        "peer",
        &[
            ("provider", egress.idle_reuses.provider),
            ("log_store", egress.idle_reuses.log_store),
        ],
    );
}

/// The series of the `refresh` object.
fn refresh_series(text: &mut String, refresh: &RefreshCounts) {
    labeled_counter(
        text,
        "credential_enclave_refresh_late_total",
        "Token address calls of refresh that passed the time limit of their call since the enclave node started, by outcome.",
        "outcome",
        &[
            ("kept", refresh.late.kept),
            ("dropped", refresh.late.dropped),
            ("failed", refresh.late.failed),
            ("abandoned", refresh.late.abandoned),
        ],
    );
    gauge(
        text,
        "credential_enclave_refresh_late_inflight",
        "Token address calls of refresh that continue after the time limit of their call at this moment.",
        format_args!("{}", refresh.late_inflight),
    );
}

/// The series of the host program itself: the gauge of the watch of the enclave, the two
/// gauges of its descriptors when the kernel gives both values, and the four series of the two
/// relays: three of the egress relay (the `cause` label takes the three classes of
/// [`AcceptFailure`], and the `outcome` label the four outcomes of a connection) and one of
/// the inbound relay.
fn host_series(
    text: &mut String,
    counters: &EgressCounters,
    inbound: &InboundCounters,
    enclave_running: Option<bool>,
    descriptors: Option<(u64, u64)>,
) {
    gauge(
        text,
        "credential_enclave_host_enclave_running",
        "1 while the last describe-enclaves of the host program listed a running enclave (or none ran yet), 0 when it listed none.",
        format_args!("{}", u8::from(enclave_running != Some(false))),
    );
    if let Some((open, limit)) = descriptors {
        gauge(
            text,
            "credential_enclave_host_descriptors_open",
            "Open file descriptors of the host program at this moment.",
            format_args!("{open}"),
        );
        gauge(
            text,
            "credential_enclave_host_descriptors_limit",
            "Limit of open file descriptors of the host program in force.",
            format_args!("{limit}"),
        );
    }
    labeled_counter(
        text,
        "credential_enclave_host_egress_accept_errors_total",
        "Failed accepts of the egress relay of the host program since it started, by cause.",
        "cause",
        &counters.accept_errors(),
    );
    labeled_counter(
        text,
        "credential_enclave_host_egress_relays_total",
        "Connections of the node the egress relay of the host program served since it started, by outcome.",
        "outcome",
        &counters.relays(),
    );
    gauge(
        text,
        "credential_enclave_host_egress_relays_inflight",
        "Connections of the node whose bytes the egress relay of the host program moves at this moment.",
        format_args!("{}", counters.relays_inflight()),
    );
    counter(
        text,
        "credential_enclave_host_inbound_node_connect_failures_total",
        "Connections of callers for which the inbound relay of the host program could not open its connection to the node since it started.",
        inbound.node_connect_failures(),
    );
}

fn respond(status: StatusCode, content_type: &'static str, body: String) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        hyper::header::HeaderValue::from_static(content_type),
    );
    response
}

async fn answer(
    method: &Method,
    path: &str,
    node: &dyn NodeConnector,
    counters: &EgressCounters,
    inbound: &InboundCounters,
    watch: &EnclaveWatch,
) -> Response<Full<Bytes>> {
    if method != Method::GET {
        return respond(
            StatusCode::METHOD_NOT_ALLOWED,
            TEXT,
            "method not allowed\n".into(),
        );
    }
    match path {
        "/healthz" => match node_health(node).await {
            Some(_) => respond(StatusCode::OK, TEXT, "ok\n".into()),
            None => respond(
                StatusCode::SERVICE_UNAVAILABLE,
                TEXT,
                "the enclave node does not answer\n".into(),
            ),
        },
        "/livez" => {
            if watch.ended() {
                respond(
                    StatusCode::SERVICE_UNAVAILABLE,
                    TEXT,
                    "the enclave ended\n".into(),
                )
            } else {
                respond(StatusCode::OK, TEXT, "ok\n".into())
            }
        }
        "/metrics" => {
            let health = node_health(node).await;
            respond(
                StatusCode::OK,
                PROMETHEUS_TEXT,
                metrics(
                    health.as_ref(),
                    counters,
                    inbound,
                    watch.running(),
                    host_descriptors(),
                ),
            )
        }
        _ => respond(StatusCode::NOT_FOUND, TEXT, "not found\n".into()),
    }
}

/// Serves the status surface on every connection of `listener`. `counters` are the counts of
/// the egress relay and `inbound` those of the inbound relay, read for `/metrics`; `watch` is
/// the watch of the enclave, read for `/livez` and `/metrics`.
pub async fn serve(
    listener: TcpListener,
    node: Arc<dyn NodeConnector>,
    counters: Arc<EgressCounters>,
    inbound: Arc<InboundCounters>,
    watch: Arc<EnclaveWatch>,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                relay::pause_after_failed_accept(AcceptFailure::of(&error)).await;
                continue;
            }
        };
        let node = node.clone();
        let counters = counters.clone();
        let inbound = inbound.clone();
        let watch = watch.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let node = node.clone();
                let counters = counters.clone();
                let inbound = inbound.clone();
                let watch = watch.clone();
                async move {
                    let response = answer(
                        request.method(),
                        request.uri().path(),
                        node.as_ref(),
                        counters.as_ref(),
                        inbound.as_ref(),
                        watch.as_ref(),
                    )
                    .await;
                    Ok::<_, Infallible>(response)
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(REQUEST_HEAD_TIMEOUT)
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    use super::*;
    use crate::egress::{Allowlist, Outcome, TcpOutbound};
    use crate::testing::{
        health_body, health_body_with_descriptors, health_body_with_egress_and_refresh,
        health_body_with_load, Behavior, FakeNode,
    };

    /// The series of the host program before any describe-enclaves answered, without the
    /// gauges of its descriptors (the tests pass none), and before either relay served a
    /// connection: the gauge of the watch and the four series of the relays.
    const HOST_SERIES_AT_START: &str =
        "# HELP credential_enclave_host_enclave_running 1 while the last describe-enclaves of the host program listed a running enclave (or none ran yet), 0 when it listed none.\n\
         # TYPE credential_enclave_host_enclave_running gauge\n\
         credential_enclave_host_enclave_running 1\n\
         # HELP credential_enclave_host_egress_accept_errors_total Failed accepts of the egress relay of the host program since it started, by cause.\n\
         # TYPE credential_enclave_host_egress_accept_errors_total counter\n\
         credential_enclave_host_egress_accept_errors_total{cause=\"aborted\"} 0\n\
         credential_enclave_host_egress_accept_errors_total{cause=\"resources\"} 0\n\
         credential_enclave_host_egress_accept_errors_total{cause=\"other\"} 0\n\
         # HELP credential_enclave_host_egress_relays_total Connections of the node the egress relay of the host program served since it started, by outcome.\n\
         # TYPE credential_enclave_host_egress_relays_total counter\n\
         credential_enclave_host_egress_relays_total{outcome=\"relayed\"} 0\n\
         credential_enclave_host_egress_relays_total{outcome=\"malformed\"} 0\n\
         credential_enclave_host_egress_relays_total{outcome=\"not_allowed\"} 0\n\
         credential_enclave_host_egress_relays_total{outcome=\"unreachable\"} 0\n\
         # HELP credential_enclave_host_egress_relays_inflight Connections of the node whose bytes the egress relay of the host program moves at this moment.\n\
         # TYPE credential_enclave_host_egress_relays_inflight gauge\n\
         credential_enclave_host_egress_relays_inflight 0\n\
         # HELP credential_enclave_host_inbound_node_connect_failures_total Connections of callers for which the inbound relay of the host program could not open its connection to the node since it started.\n\
         # TYPE credential_enclave_host_inbound_node_connect_failures_total counter\n\
         credential_enclave_host_inbound_node_connect_failures_total 0\n";

    /// The names of the series that a node of release v2.1.0 adds, the gauge of `grants`
    /// among them (the value is in the answer of every release, and the gauge follows the
    /// series of the objects).
    const NEW_SERIES: [&str; 17] = [
        "credential_enclave_log_store_write_attempt_failures_total",
        "credential_enclave_log_store_write_retries_total",
        "credential_enclave_log_store_write_seconds",
        "credential_enclave_log_store_pending_accounts",
        "credential_enclave_log_store_pending_oldest_seconds",
        "credential_enclave_egress_opens_total",
        "credential_enclave_egress_open_failures_total",
        "credential_enclave_egress_open_retries_total",
        "credential_enclave_egress_open_inflight",
        "credential_enclave_egress_idle_reuses_total",
        "credential_enclave_refresh_late_total",
        "credential_enclave_refresh_late_inflight",
        "credential_enclave_grants",
        "credential_enclave_kept_refreshes",
        "credential_enclave_merge_keys",
        "credential_enclave_pending_entries",
        "credential_enclave_idle_connections",
    ];

    /// The series of a response without the series of the host program, which come last.
    fn node_part(text: &str) -> &str {
        text.strip_suffix(HOST_SERIES_AT_START).unwrap()
    }

    /// The counts of an inbound relay that served no connection.
    fn no_inbound() -> InboundCounters {
        InboundCounters::default()
    }

    /// The `load` object of `testing::LOAD_OBJECT`, as the host program reads it.
    fn load_of_the_body() -> Load {
        Load {
            provider_inflight: 4,
            forward_calls: 5,
            cpu_user_ms: Some(1234),
            cpu_system_ms: Some(567),
            cpu_idle_ms: Some(89012),
            memory_total_bytes: Some(4_294_967_296),
            memory_available_bytes: Some(3_221_225_472),
            ..Load::default()
        }
    }

    async fn status_surface(
        node: Arc<FakeNode>,
        counters: Arc<EgressCounters>,
        inbound: Arc<InboundCounters>,
    ) -> SocketAddr {
        let listener = relay::listen_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve(
            listener,
            node,
            counters,
            inbound,
            EnclaveWatch::new(),
        ));
        address
    }

    async fn call(address: SocketAddr, method: Method, path: &str) -> (u16, String) {
        let stream = TcpStream::connect(address).await.unwrap();
        let request = http::request(method, "status.test", path, &[], Vec::new()).unwrap();
        let reply = http::exchange(stream, request, 64 * 1024).await.unwrap();
        (reply.status, String::from_utf8(reply.body).unwrap())
    }

    #[tokio::test]
    async fn the_health_call_reads_the_values_it_uses_and_ignores_the_others() {
        let node =
            FakeNode::answering(|_| (200, health_body_with_load(true, 7, 1_790_000_000_123)));
        let log = LogCounts {
            entries: 70,
            events: 700,
            writes: 71,
            write_failures: 1,
            open_batches: 2,
            batch_calls: 3,
            batch_requests: 400,
            ..LogCounts::default()
        };
        assert_eq!(
            node_health(node.as_ref()).await,
            Some(NodeHealth {
                configured: true,
                accounts: 7,
                started_ms: 1_790_000_000_123,
                grants: Some(0),
                log: Some(log.clone()),
                load: Some(load_of_the_body()),
                log_store: None,
                egress: None,
                refresh: None,
                state: None,
            })
        );
        let calls = node.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            (calls[0].method.as_str(), calls[0].path.as_str()),
            ("GET", "/v1/health")
        );

        // A node of release v2.0.0 answers without `load`, and the five values of the kernel
        // are null in the answer of a node whose kernel exposes no procfs value.
        let node = FakeNode::answering(|_| (200, health_body(true, 7, 1_790_000_000_123)));
        assert_eq!(
            node_health(node.as_ref()).await,
            Some(NodeHealth {
                configured: true,
                accounts: 7,
                started_ms: 1_790_000_000_123,
                grants: Some(0),
                log: Some(log.clone()),
                load: None,
                log_store: None,
                egress: None,
                refresh: None,
                state: None,
            })
        );

        // A node of release v2.1.0 answers with the write counts of the log, the log store it
        // holds, and the egress, refresh and state objects.
        let node = FakeNode::answering(|_| {
            (
                200,
                health_body_with_egress_and_refresh(true, 7, 1_790_000_000_123),
            )
        });
        assert_eq!(
            node_health(node.as_ref()).await,
            Some(NodeHealth {
                configured: true,
                accounts: 7,
                started_ms: 1_790_000_000_123,
                grants: Some(0),
                log: Some(LogCounts {
                    write_attempt_failures: Some(WriteAttemptFailures {
                        connect: 1,
                        tls: 2,
                        closed: 3,
                        timeout: 4,
                        status_4xx: 5,
                        status_5xx: 6,
                    }),
                    write_retries: Some(7),
                    write_ms_buckets: Some(WriteMsBuckets {
                        within_25: 10,
                        within_50: 20,
                        within_100: 30,
                        within_250: 40,
                        within_500: 50,
                        within_1000: 60,
                        within_2500: 70,
                        within_5000: 80,
                    }),
                    write_ms_sum: Some(123_456),
                    write_count: Some(90),
                    ..log
                }),
                load: Some(load_of_the_body()),
                log_store: Some(LogStoreState {
                    pending: 6,
                    pending_oldest_ms: Some(12_345),
                }),
                egress: Some(EgressCounts {
                    opens: 100,
                    open_failures: OpenFailures {
                        transport: 1,
                        relay_refused: 2,
                        tls: 3,
                        http: 4,
                    },
                    open_retries: 5,
                    open_inflight: 6,
                    idle_reuses: IdleReuses {
                        provider: 200,
                        log_store: 300,
                    },
                }),
                refresh: Some(RefreshCounts {
                    late: LateRefreshes {
                        kept: 1,
                        dropped: 2,
                        failed: 3,
                        abandoned: 4,
                    },
                    late_inflight: 5,
                }),
                state: Some(StateCounts {
                    kept_refreshes: 11,
                    merge_keys: 22,
                    pending_entries: 33,
                    idle_connections: IdleConnections {
                        provider: 44,
                        log_store: 55,
                    },
                }),
            })
        );

        // The `log_store` object of a node of release v2.0.1 has no `pending_oldest_ms`.
        let node = FakeNode::answering(|_| {
            let body = r#"{"configured":true,"accounts":1,"started_ms":5,"log_store":{"bucket":"b","region":"us-west-2","credentials_expires_ms":0,"pending":3}}"#;
            (200, body.to_string())
        });
        assert_eq!(
            node_health(node.as_ref())
                .await
                .and_then(|health| health.log_store),
            Some(LogStoreState {
                pending: 3,
                pending_oldest_ms: None,
            })
        );
        let node = FakeNode::answering(|_| {
            let body = r#"{"configured":true,"accounts":1,"started_ms":5,"load":{"provider_inflight":1,"forward_calls":0,"cpu_user_ms":null,"cpu_system_ms":null,"cpu_idle_ms":null,"memory_total_bytes":null,"memory_available_bytes":null}}"#;
            (200, body.to_string())
        });
        assert_eq!(
            node_health(node.as_ref())
                .await
                .and_then(|health| health.load),
            Some(Load {
                provider_inflight: 1,
                forward_calls: 0,
                ..Load::default()
            })
        );

        // Fields a later node adds do not change the reading, and a node of a release before
        // v2.0.0 answers without `log`. `grants` is read from every release that answers it.
        let node = FakeNode::answering(|_| {
            let body = r#"{"node":"n","custody":"enclave","grants":3,"configured":false,"accounts":0,"started_ms":5,"closing":true}"#;
            (200, body.to_string())
        });
        assert_eq!(
            node_health(node.as_ref()).await,
            Some(NodeHealth {
                configured: false,
                accounts: 0,
                started_ms: 5,
                grants: Some(3),
                log: None,
                load: None,
                log_store: None,
                egress: None,
                refresh: None,
                state: None,
            })
        );
    }

    #[tokio::test]
    async fn a_health_call_without_a_usable_answer_is_a_failure() {
        for (status, body) in [
            (500, health_body(true, 1, 1)),
            (404, String::new()),
            (200, String::new()),
            (200, "not json".to_string()),
            (200, r#"{"configured":true,"accounts":1}"#.to_string()),
            (
                200,
                r#"{"configured":"yes","accounts":1,"started_ms":1}"#.to_string(),
            ),
        ] {
            let node = FakeNode::answering(move |_| (status, body.clone()));
            assert_eq!(node_health(node.as_ref()).await, None);
        }
        let node = FakeNode::new(Behavior::Unreachable);
        assert_eq!(node_health(node.as_ref()).await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_health_call_that_gets_no_answer_fails_after_the_health_timeout() {
        let node = FakeNode::new(Behavior::Silent);
        let started = tokio::time::Instant::now();
        assert_eq!(node_health(node.as_ref()).await, None);
        let waited = started.elapsed();
        assert!(waited >= HEALTH_TIMEOUT && waited < HEALTH_TIMEOUT + Duration::from_millis(100));
    }

    #[test]
    fn the_metrics_are_four_gauges_of_the_health_call_and_the_series_of_its_log_and_load() {
        let no_counts = EgressCounters::default();
        let no_inbound = no_inbound();
        let health = NodeHealth {
            configured: true,
            accounts: 12,
            started_ms: 1_790_000_000_042,
            grants: None,
            log: None,
            load: None,
            log_store: None,
            egress: None,
            refresh: None,
            state: None,
        };
        assert_eq!(
            metrics(Some(&health), &no_counts, &no_inbound, None, None),
            [
                "# HELP credential_enclave_up 1 when the health call of the enclave node succeeds, 0 when it fails.\n\
                 # TYPE credential_enclave_up gauge\n\
                 credential_enclave_up 1\n\
                 # HELP credential_enclave_configured 1 when the enclave node holds the operator configuration.\n\
                 # TYPE credential_enclave_configured gauge\n\
                 credential_enclave_configured 1\n\
                 # HELP credential_enclave_accounts Accounts with a log chain on the enclave node.\n\
                 # TYPE credential_enclave_accounts gauge\n\
                 credential_enclave_accounts 12\n\
                 # HELP credential_enclave_started_timestamp_seconds Start time of the enclave node in seconds since the Unix epoch.\n\
                 # TYPE credential_enclave_started_timestamp_seconds gauge\n\
                 credential_enclave_started_timestamp_seconds 1790000000.042\n",
                HOST_SERIES_AT_START,
            ]
            .concat()
        );
        let unconfigured = NodeHealth {
            configured: false,
            accounts: 0,
            started_ms: 1000,
            grants: None,
            log: None,
            load: None,
            log_store: None,
            egress: None,
            refresh: None,
            state: None,
        };
        let text = metrics(Some(&unconfigured), &no_counts, &no_inbound, None, None);
        assert!(text.contains("\ncredential_enclave_configured 0\n"));
        assert!(text.contains("\ncredential_enclave_accounts 0\n"));
        assert!(text.contains("\ncredential_enclave_started_timestamp_seconds 1.000\n"));
        assert!(!text.contains("credential_enclave_log_"));
        assert_eq!(text.matches("# TYPE ").count(), 4 + 5);

        // With the `log` object of a node of release v2.0.0 or later: six counters and one
        // gauge after the four gauges, and none of the series of release v2.1.0.
        let with_log = NodeHealth {
            log: Some(LogCounts {
                entries: 5,
                events: 40,
                writes: 6,
                write_failures: 1,
                open_batches: 2,
                batch_calls: 3,
                batch_requests: 35,
                ..LogCounts::default()
            }),
            ..health
        };
        let text = metrics(Some(&with_log), &no_counts, &no_inbound, None, None);
        assert!(text.starts_with("# HELP credential_enclave_up "));
        assert!(text.contains(
            "# HELP credential_enclave_log_entries_total Log entries the enclave node created since it started.\n\
             # TYPE credential_enclave_log_entries_total counter\n\
             credential_enclave_log_entries_total 5\n"
        ));
        assert!(text.contains("\n# TYPE credential_enclave_log_events_total counter\ncredential_enclave_log_events_total 40\n"));
        assert!(text.contains("\n# TYPE credential_enclave_log_store_writes_total counter\ncredential_enclave_log_store_writes_total 6\n"));
        assert!(text.contains("\n# TYPE credential_enclave_log_store_write_failures_total counter\ncredential_enclave_log_store_write_failures_total 1\n"));
        assert!(text.contains("\n# TYPE credential_enclave_forward_batch_calls_total counter\ncredential_enclave_forward_batch_calls_total 3\n"));
        assert!(text.contains("\n# TYPE credential_enclave_forward_batch_requests_total counter\ncredential_enclave_forward_batch_requests_total 35\n"));
        assert!(node_part(&text).ends_with("\n# TYPE credential_enclave_log_open_batches gauge\ncredential_enclave_log_open_batches 2\n"));
        assert_eq!(text.matches("# TYPE ").count(), 11 + 5);
        for series in LOAD_SERIES.iter().chain(NEW_SERIES.iter()) {
            assert!(!text.contains(series), "{series}");
        }

        // With the `load` object of a node of release v2.0.1 or later: two gauges, three
        // counters and two gauges after the series of the log.
        let with_load = NodeHealth {
            load: Some(load_of_the_body()),
            ..with_log.clone()
        };
        let text = metrics(Some(&with_load), &no_counts, &no_inbound, None, None);
        assert_eq!(text.matches("# TYPE ").count(), 18 + 5);
        for series in NEW_SERIES {
            assert!(!text.contains(series), "{series}");
        }
        let load_text = node_part(&text)
            .split_once("credential_enclave_log_open_batches 2\n")
            .unwrap()
            .1;
        assert_eq!(
            load_text,
            "# HELP credential_enclave_provider_inflight Provider requests of the enclave node in flight at this moment.\n\
             # TYPE credential_enclave_provider_inflight gauge\n\
             credential_enclave_provider_inflight 4\n\
             # HELP credential_enclave_forward_calls forward and forward/batch calls of the enclave node that hold a concurrency slot at this moment.\n\
             # TYPE credential_enclave_forward_calls gauge\n\
             credential_enclave_forward_calls 5\n\
             # HELP credential_enclave_cpu_user_seconds_total CPU time in user mode of the enclave kernel since it booted, in seconds.\n\
             # TYPE credential_enclave_cpu_user_seconds_total counter\n\
             credential_enclave_cpu_user_seconds_total 1.234\n\
             # HELP credential_enclave_cpu_system_seconds_total CPU time in system mode of the enclave kernel since it booted, in seconds.\n\
             # TYPE credential_enclave_cpu_system_seconds_total counter\n\
             credential_enclave_cpu_system_seconds_total 0.567\n\
             # HELP credential_enclave_cpu_idle_seconds_total CPU time in idle mode of the enclave kernel since it booted, in seconds.\n\
             # TYPE credential_enclave_cpu_idle_seconds_total counter\n\
             credential_enclave_cpu_idle_seconds_total 89.012\n\
             # HELP credential_enclave_memory_total_bytes Memory of the enclave kernel in bytes.\n\
             # TYPE credential_enclave_memory_total_bytes gauge\n\
             credential_enclave_memory_total_bytes 4294967296\n\
             # HELP credential_enclave_memory_available_bytes Memory of the enclave kernel that it estimates it can give out, in bytes.\n\
             # TYPE credential_enclave_memory_available_bytes gauge\n\
             credential_enclave_memory_available_bytes 3221225472\n"
        );

        // The values of the kernel are null when the kernel of the node exposes none: the two
        // gauges of the node stand alone then.
        let without_kernel_values = NodeHealth {
            load: Some(Load {
                provider_inflight: 0,
                forward_calls: 1,
                ..Load::default()
            }),
            ..with_log
        };
        let text = metrics(
            Some(&without_kernel_values),
            &no_counts,
            &no_inbound,
            None,
            None,
        );
        assert_eq!(text.matches("# TYPE ").count(), 13 + 5);
        assert!(node_part(&text).ends_with(
            "\n# TYPE credential_enclave_forward_calls gauge\ncredential_enclave_forward_calls 1\n"
        ));
        assert!(!text.contains("credential_enclave_cpu_"));
        assert!(!text.contains("credential_enclave_memory_"));
    }

    #[tokio::test]
    async fn the_series_of_a_node_of_release_v2_1_0_follow_their_objects() {
        let node = FakeNode::answering(|_| {
            (
                200,
                health_body_with_egress_and_refresh(true, 3, 1_790_000_000_500),
            )
        });
        let health = node_health(node.as_ref()).await.unwrap();
        let text = metrics(
            Some(&health),
            &EgressCounters::default(),
            &no_inbound(),
            None,
            None,
        );
        assert_eq!(text.matches("# TYPE ").count(), 18 + 17 + 5);

        // The series of the write counts follow the seven series of the log, the two gauges of
        // the log store follow them, and the series of the load come next.
        let (log_text, rest) = text
            .split_once("credential_enclave_log_open_batches 2\n")
            .unwrap()
            .1
            .split_once("# HELP credential_enclave_provider_inflight ")
            .unwrap();
        assert_eq!(
            log_text,
            "# HELP credential_enclave_log_store_write_attempt_failures_total PUT attempts to the log store that failed since the enclave node started, by cause.\n\
             # TYPE credential_enclave_log_store_write_attempt_failures_total counter\n\
             credential_enclave_log_store_write_attempt_failures_total{cause=\"connect\"} 1\n\
             credential_enclave_log_store_write_attempt_failures_total{cause=\"tls\"} 2\n\
             credential_enclave_log_store_write_attempt_failures_total{cause=\"closed\"} 3\n\
             credential_enclave_log_store_write_attempt_failures_total{cause=\"timeout\"} 4\n\
             credential_enclave_log_store_write_attempt_failures_total{cause=\"status_4xx\"} 5\n\
             credential_enclave_log_store_write_attempt_failures_total{cause=\"status_5xx\"} 6\n\
             # HELP credential_enclave_log_store_write_retries_total PUT attempts to the log store that repeated a failed attempt since the enclave node started.\n\
             # TYPE credential_enclave_log_store_write_retries_total counter\n\
             credential_enclave_log_store_write_retries_total 7\n\
             # HELP credential_enclave_log_store_write_seconds Time from the start of the write of a log entry to its confirmation by the log store, in seconds, for the writes since the enclave node started.\n\
             # TYPE credential_enclave_log_store_write_seconds histogram\n\
             credential_enclave_log_store_write_seconds_bucket{le=\"0.025\"} 10\n\
             credential_enclave_log_store_write_seconds_bucket{le=\"0.05\"} 20\n\
             credential_enclave_log_store_write_seconds_bucket{le=\"0.1\"} 30\n\
             credential_enclave_log_store_write_seconds_bucket{le=\"0.25\"} 40\n\
             credential_enclave_log_store_write_seconds_bucket{le=\"0.5\"} 50\n\
             credential_enclave_log_store_write_seconds_bucket{le=\"1\"} 60\n\
             credential_enclave_log_store_write_seconds_bucket{le=\"2.5\"} 70\n\
             credential_enclave_log_store_write_seconds_bucket{le=\"5\"} 80\n\
             credential_enclave_log_store_write_seconds_bucket{le=\"+Inf\"} 90\n\
             credential_enclave_log_store_write_seconds_sum 123.456\n\
             credential_enclave_log_store_write_seconds_count 90\n\
             # HELP credential_enclave_log_store_pending_accounts Accounts of the enclave node that have a pending log entry at this moment.\n\
             # TYPE credential_enclave_log_store_pending_accounts gauge\n\
             credential_enclave_log_store_pending_accounts 6\n\
             # HELP credential_enclave_log_store_pending_oldest_seconds Age of the oldest pending log entry of the enclave node in seconds, 0 when there is none.\n\
             # TYPE credential_enclave_log_store_pending_oldest_seconds gauge\n\
             credential_enclave_log_store_pending_oldest_seconds 12.345\n"
        );
        // The `+Inf` bucket and the count of the histogram are `write_count`.
        let write_count = health.log.as_ref().unwrap().write_count.unwrap();
        assert_eq!(write_count, 90);
        assert!(log_text.contains(&format!(
            "_bucket{{le=\"+Inf\"}} {write_count}\ncredential_enclave_log_store_write_seconds_sum 123.456\ncredential_enclave_log_store_write_seconds_count {write_count}\n"
        )));

        // The series of the egress and refresh objects follow the load, the gauge of the grants
        // and the gauges of the state object follow them, and the series of the host program
        // come last.
        let tail = rest
            .split_once("credential_enclave_memory_available_bytes 3221225472\n")
            .unwrap()
            .1;
        assert_eq!(
            tail,
            [
                "# HELP credential_enclave_egress_opens_total Outbound connections the enclave node opened since it started.\n\
                 # TYPE credential_enclave_egress_opens_total counter\n\
                 credential_enclave_egress_opens_total 100\n\
                 # HELP credential_enclave_egress_open_failures_total Attempts of the enclave node to open an outbound connection that failed since it started, by cause.\n\
                 # TYPE credential_enclave_egress_open_failures_total counter\n\
                 credential_enclave_egress_open_failures_total{cause=\"transport\"} 1\n\
                 credential_enclave_egress_open_failures_total{cause=\"relay_refused\"} 2\n\
                 credential_enclave_egress_open_failures_total{cause=\"tls\"} 3\n\
                 credential_enclave_egress_open_failures_total{cause=\"http\"} 4\n\
                 # HELP credential_enclave_egress_open_retries_total Attempts of the enclave node to open an outbound connection that repeated a failed attempt since it started.\n\
                 # TYPE credential_enclave_egress_open_retries_total counter\n\
                 credential_enclave_egress_open_retries_total 5\n\
                 # HELP credential_enclave_egress_open_inflight Outbound connections the enclave node is opening at this moment.\n\
                 # TYPE credential_enclave_egress_open_inflight gauge\n\
                 credential_enclave_egress_open_inflight 6\n\
                 # HELP credential_enclave_egress_idle_reuses_total Requests the enclave node sent over an idle connection since it started, by peer.\n\
                 # TYPE credential_enclave_egress_idle_reuses_total counter\n\
                 credential_enclave_egress_idle_reuses_total{peer=\"provider\"} 200\n\
                 credential_enclave_egress_idle_reuses_total{peer=\"log_store\"} 300\n\
                 # HELP credential_enclave_refresh_late_total Token address calls of refresh that passed the time limit of their call since the enclave node started, by outcome.\n\
                 # TYPE credential_enclave_refresh_late_total counter\n\
                 credential_enclave_refresh_late_total{outcome=\"kept\"} 1\n\
                 credential_enclave_refresh_late_total{outcome=\"dropped\"} 2\n\
                 credential_enclave_refresh_late_total{outcome=\"failed\"} 3\n\
                 credential_enclave_refresh_late_total{outcome=\"abandoned\"} 4\n\
                 # HELP credential_enclave_refresh_late_inflight Token address calls of refresh that continue after the time limit of their call at this moment.\n\
                 # TYPE credential_enclave_refresh_late_inflight gauge\n\
                 credential_enclave_refresh_late_inflight 5\n\
                 # HELP credential_enclave_grants Accounts of the enclave node that have a grant within its time.\n\
                 # TYPE credential_enclave_grants gauge\n\
                 credential_enclave_grants 0\n\
                 # HELP credential_enclave_kept_refreshes Kept refresh responses of the enclave node over every account at this moment.\n\
                 # TYPE credential_enclave_kept_refreshes gauge\n\
                 credential_enclave_kept_refreshes 11\n\
                 # HELP credential_enclave_merge_keys Merge keys of identical GET requests of the enclave node over every account at this moment.\n\
                 # TYPE credential_enclave_merge_keys gauge\n\
                 credential_enclave_merge_keys 22\n\
                 # HELP credential_enclave_pending_entries Log entries of the enclave node that the log store has not confirmed at this moment.\n\
                 # TYPE credential_enclave_pending_entries gauge\n\
                 credential_enclave_pending_entries 33\n\
                 # HELP credential_enclave_idle_connections Idle connections the enclave node keeps at this moment, by peer.\n\
                 # TYPE credential_enclave_idle_connections gauge\n\
                 credential_enclave_idle_connections{peer=\"provider\"} 44\n\
                 credential_enclave_idle_connections{peer=\"log_store\"} 55\n",
                HOST_SERIES_AT_START,
            ]
            .concat()
        );

        // The histogram needs its three values, and the gauge of the oldest pending entry its
        // value: a response with a part of them gives the series of the values it holds.
        let partial = NodeHealth {
            log: Some(LogCounts {
                write_count: Some(5),
                write_retries: Some(1),
                ..LogCounts::default()
            }),
            log_store: Some(LogStoreState {
                pending: 2,
                pending_oldest_ms: None,
            }),
            egress: None,
            refresh: None,
            state: None,
            ..health
        };
        let text = metrics(
            Some(&partial),
            &EgressCounters::default(),
            &no_inbound(),
            None,
            None,
        );
        assert!(text.contains("\ncredential_enclave_log_store_write_retries_total 1\n"));
        assert!(text.contains("\ncredential_enclave_log_store_pending_accounts 2\n"));
        assert!(!text.contains("credential_enclave_log_store_write_seconds"));
        assert!(!text.contains("credential_enclave_log_store_write_attempt_failures_total"));
        assert!(!text.contains("credential_enclave_log_store_pending_oldest_seconds"));
        assert!(!text.contains("credential_enclave_egress_"));
        assert!(!text.contains("credential_enclave_refresh_"));
        assert!(!text.contains("credential_enclave_kept_refreshes"));
        assert!(!text.contains("credential_enclave_idle_connections"));
        assert!(node_part(&text).ends_with("\ncredential_enclave_grants 0\n"));
    }

    /// The names of the seven series of the `load` object.
    const LOAD_SERIES: [&str; 7] = [
        "credential_enclave_provider_inflight",
        "credential_enclave_forward_calls",
        "credential_enclave_cpu_user_seconds_total",
        "credential_enclave_cpu_system_seconds_total",
        "credential_enclave_cpu_idle_seconds_total",
        "credential_enclave_memory_total_bytes",
        "credential_enclave_memory_available_bytes",
    ];

    #[test]
    fn a_failed_health_call_gives_the_up_gauge_and_the_series_of_the_host_program() {
        assert_eq!(
            metrics(None, &EgressCounters::default(), &no_inbound(), None, None),
            [
                "# HELP credential_enclave_up 1 when the health call of the enclave node succeeds, 0 when it fails.\n\
                 # TYPE credential_enclave_up gauge\n\
                 credential_enclave_up 0\n",
                HOST_SERIES_AT_START,
            ]
            .concat()
        );
    }

    #[tokio::test]
    async fn healthz_follows_the_node() {
        let node = FakeNode::answering(|_| (200, health_body(false, 0, 1_790_000_000_000)));
        let address = status_surface(
            node.clone(),
            Arc::new(EgressCounters::default()),
            Arc::new(no_inbound()),
        )
        .await;
        assert_eq!(
            call(address, Method::GET, "/healthz").await,
            (200, "ok\n".to_string())
        );

        // Readiness does not depend on the operator configuration, only on the answer.
        node.set(Behavior::Unreachable);
        let (status, _) = call(address, Method::GET, "/healthz").await;
        assert_eq!(status, 503);

        node.set(Behavior::Answer(Arc::new(|_| (500, String::new()))));
        let (status, _) = call(address, Method::GET, "/healthz").await;
        assert_eq!(status, 503);
    }

    #[tokio::test]
    async fn the_metrics_route_reports_the_node_its_absence_and_the_two_relays() {
        let node =
            FakeNode::answering(|_| (200, health_body_with_load(true, 3, 1_790_000_000_500)));
        let counters = Arc::new(EgressCounters::default());
        let inbound_counters = Arc::new(no_inbound());
        let address =
            status_surface(node.clone(), counters.clone(), inbound_counters.clone()).await;
        let (status, text) = call(address, Method::GET, "/metrics").await;
        assert_eq!(status, 200);
        assert!(text.contains("\ncredential_enclave_up 1\n"), "{text}");
        assert!(
            text.contains("\ncredential_enclave_configured 1\n"),
            "{text}"
        );
        assert!(text.contains("\ncredential_enclave_accounts 3\n"), "{text}");
        assert!(
            text.contains("\ncredential_enclave_started_timestamp_seconds 1790000000.500\n"),
            "{text}"
        );
        assert!(
            text.contains("\ncredential_enclave_log_entries_total 30\n"),
            "{text}"
        );
        assert!(
            text.contains("\ncredential_enclave_log_open_batches 2\n"),
            "{text}"
        );
        assert!(
            text.contains("\ncredential_enclave_provider_inflight 4\n"),
            "{text}"
        );
        assert!(
            text.contains("\ncredential_enclave_cpu_user_seconds_total 1.234\n"),
            "{text}"
        );
        // The gauge of the grants follows the series of the objects of the answer.
        assert!(
            node_part(&text).ends_with(
                "\ncredential_enclave_memory_available_bytes 3221225472\n\
                 # HELP credential_enclave_grants Accounts of the enclave node that have a grant within its time.\n\
                 # TYPE credential_enclave_grants gauge\n\
                 credential_enclave_grants 0\n"
            ),
            "{text}"
        );

        // The egress relay refuses one connection of the node, and the inbound relay cannot
        // reach the node for one connection of a caller: the series of the host program count
        // both, whatever the node answers.
        let (mut node_side, inbound) = tokio::io::duplex(64);
        node_side.write_all(b"\n").await.unwrap();
        let allowlist = Allowlist::from_definitions(crate::DEFINITIONS).unwrap();
        assert_eq!(
            crate::egress::relay(inbound, &allowlist, &TcpOutbound, &counters).await,
            Outcome::Malformed
        );
        let relay_listener = relay::listen_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let relay_address = relay_listener.local_addr().unwrap();
        tokio::spawn(relay::serve(
            relay_listener,
            FakeNode::new(Behavior::Unreachable),
            inbound_counters.clone(),
        ));
        let mut caller = TcpStream::connect(relay_address).await.unwrap();
        let mut buffer = [0u8; 8];
        assert!(matches!(
            tokio::io::AsyncReadExt::read(&mut caller, &mut buffer).await,
            Ok(0) | Err(_)
        ));
        for _ in 0..200 {
            if inbound_counters.node_connect_failures() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // A node of release v2.0.0 answers without `load`: none of its series, and the gauge
        // of the grants after the series of the log.
        node.set(Behavior::Answer(Arc::new(|_| {
            (200, health_body(true, 3, 1_790_000_000_500))
        })));
        let (status, text) = call(address, Method::GET, "/metrics").await;
        assert_eq!(status, 200);
        // The series of the host program start with the gauge of the watch; the gauges of
        // its descriptors between it and the relays depend on the kernel that runs the test.
        let (node_text, host_text) = text
            .split_once("# HELP credential_enclave_host_enclave_running ")
            .unwrap();
        assert!(
            node_text.ends_with(
                "\ncredential_enclave_log_open_batches 2\n\
                 # HELP credential_enclave_grants Accounts of the enclave node that have a grant within its time.\n\
                 # TYPE credential_enclave_grants gauge\n\
                 credential_enclave_grants 0\n"
            ),
            "{text}"
        );
        let host_descriptor_series = if host_descriptors().is_some() { 2 } else { 0 };
        for series in LOAD_SERIES {
            assert!(!text.contains(series), "{series}: {text}");
        }
        assert!(
            host_text.contains(
                "\ncredential_enclave_host_egress_relays_total{outcome=\"malformed\"} 1\n"
            ),
            "{text}"
        );
        assert!(
            text.ends_with(
                "\ncredential_enclave_host_egress_relays_inflight 0\n\
                 # HELP credential_enclave_host_inbound_node_connect_failures_total Connections of callers for which the inbound relay of the host program could not open its connection to the node since it started.\n\
                 # TYPE credential_enclave_host_inbound_node_connect_failures_total counter\n\
                 credential_enclave_host_inbound_node_connect_failures_total 1\n"
            ),
            "{text}"
        );

        node.set(Behavior::Unreachable);
        let (status, text) = call(address, Method::GET, "/metrics").await;
        assert_eq!(status, 200);
        assert!(text.starts_with("# HELP credential_enclave_up "), "{text}");
        assert!(
            text.contains(
                "\ncredential_enclave_up 0\n# HELP credential_enclave_host_enclave_running "
            ),
            "{text}"
        );
        assert!(!text.contains("credential_enclave_configured"), "{text}");
        assert!(
            text.contains(
                "\ncredential_enclave_host_egress_relays_total{outcome=\"malformed\"} 1\n"
            ),
            "{text}"
        );
        assert!(
            text.ends_with("\ncredential_enclave_host_inbound_node_connect_failures_total 1\n"),
            "{text}"
        );
        assert_eq!(
            text.matches("# TYPE ").count(),
            1 + 5 + host_descriptor_series
        );
    }

    #[tokio::test]
    async fn other_paths_and_methods_are_refused() {
        let node = FakeNode::answering(|_| (200, health_body(true, 0, 1)));
        let address = status_surface(
            node.clone(),
            Arc::new(EgressCounters::default()),
            Arc::new(no_inbound()),
        )
        .await;
        assert_eq!(call(address, Method::GET, "/").await.0, 404);
        assert_eq!(call(address, Method::GET, "/v1/health").await.0, 404);
        assert_eq!(call(address, Method::POST, "/healthz").await.0, 405);
        assert_eq!(call(address, Method::POST, "/metrics").await.0, 405);
        assert_eq!(call(address, Method::POST, "/livez").await.0, 405);
        // None of them reached the node.
        assert!(node.calls().is_empty());
    }

    #[tokio::test]
    async fn the_series_of_a_node_of_release_v2_2_0_follow_the_counts_of_the_load() {
        let node = FakeNode::answering(|_| {
            (
                200,
                health_body_with_descriptors(true, 3, 1_790_000_000_500),
            )
        });
        let health = node_health(node.as_ref()).await.unwrap();
        assert_eq!(
            health.load,
            Some(Load {
                inbound_connections: Some(7),
                inbound_refused: Some(2),
                descriptors_open: Some(321),
                descriptors_limit: Some(65_536),
                ..load_of_the_body()
            })
        );
        let text = metrics(
            Some(&health),
            &EgressCounters::default(),
            &no_inbound(),
            Some(true),
            Some((45, 1_048_576)),
        );
        // The gauge and the counter of the connections from the backend follow the two gauges
        // of the calls, and the two gauges of the descriptors follow the memory gauges.
        assert!(text.contains(
            "\ncredential_enclave_forward_calls 5\n\
             # HELP credential_enclave_inbound_connections Connections from the backend the enclave node holds open at this moment.\n\
             # TYPE credential_enclave_inbound_connections gauge\n\
             credential_enclave_inbound_connections 7\n\
             # HELP credential_enclave_inbound_refused_total Connections from the backend the enclave node closed at accept because its bound of open connections was reached, since it started.\n\
             # TYPE credential_enclave_inbound_refused_total counter\n\
             credential_enclave_inbound_refused_total 2\n\
             # HELP credential_enclave_cpu_user_seconds_total "
        ), "{text}");
        assert!(text.contains(
            "\ncredential_enclave_memory_available_bytes 3221225472\n\
             # HELP credential_enclave_descriptors_open Open file descriptors of the enclave node process at this moment.\n\
             # TYPE credential_enclave_descriptors_open gauge\n\
             credential_enclave_descriptors_open 321\n\
             # HELP credential_enclave_descriptors_limit Limit of open file descriptors of the enclave node process in force.\n\
             # TYPE credential_enclave_descriptors_limit gauge\n\
             credential_enclave_descriptors_limit 65536\n\
             # HELP credential_enclave_egress_opens_total "
        ), "{text}");
        // The series of the host program: the watch (a running enclave), its descriptors, then
        // the four series of the relays.
        assert!(text.ends_with(
            &[
                "\ncredential_enclave_idle_connections{peer=\"log_store\"} 55\n\
                 # HELP credential_enclave_host_enclave_running 1 while the last describe-enclaves of the host program listed a running enclave (or none ran yet), 0 when it listed none.\n\
                 # TYPE credential_enclave_host_enclave_running gauge\n\
                 credential_enclave_host_enclave_running 1\n\
                 # HELP credential_enclave_host_descriptors_open Open file descriptors of the host program at this moment.\n\
                 # TYPE credential_enclave_host_descriptors_open gauge\n\
                 credential_enclave_host_descriptors_open 45\n\
                 # HELP credential_enclave_host_descriptors_limit Limit of open file descriptors of the host program in force.\n\
                 # TYPE credential_enclave_host_descriptors_limit gauge\n\
                 credential_enclave_host_descriptors_limit 1048576\n",
                HOST_SERIES_AT_START
                    .split_once("# HELP credential_enclave_host_egress_accept_errors_total ")
                    .map(|(_, rest)| format!("# HELP credential_enclave_host_egress_accept_errors_total {rest}"))
                    .unwrap()
                    .as_str(),
            ]
            .concat()
        ), "{text}");
        assert_eq!(text.matches("# TYPE ").count(), 18 + 17 + 4 + 5 + 2);
        // A node of a release before v2.2.0 gives none of the four series, and a last
        // describe-enclaves without a running enclave turns the gauge of the watch to 0.
        let earlier = NodeHealth {
            load: Some(load_of_the_body()),
            ..health
        };
        let text = metrics(
            Some(&earlier),
            &EgressCounters::default(),
            &no_inbound(),
            Some(false),
            None,
        );
        for series in [
            "credential_enclave_inbound_connections",
            "credential_enclave_inbound_refused_total",
            "credential_enclave_descriptors_open",
            "credential_enclave_descriptors_limit",
            "credential_enclave_host_descriptors_open",
            "credential_enclave_host_descriptors_limit",
        ] {
            assert!(!text.contains(series), "{series}");
        }
        assert!(
            text.contains("\ncredential_enclave_host_enclave_running 0\n"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn livez_follows_the_watch_of_the_enclave_and_not_the_node() {
        // The node does not answer: /healthz is 503 and /livez is 200, the enclave runs.
        let node = FakeNode::new(Behavior::Unreachable);
        let watch = EnclaveWatch::new();
        let listener = relay::listen_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve(
            listener,
            node.clone(),
            Arc::new(EgressCounters::default()),
            Arc::new(no_inbound()),
            watch.clone(),
        ));
        assert_eq!(call(address, Method::GET, "/healthz").await.0, 503);
        assert_eq!(
            call(address, Method::GET, "/livez").await,
            (200, "ok\n".to_string())
        );
        // Two answers without a running enclave do not confirm its end, the third does.
        watch.observe(Some(false));
        watch.observe(Some(false));
        assert_eq!(call(address, Method::GET, "/livez").await.0, 200);
        let (_, text) = call(address, Method::GET, "/metrics").await;
        assert!(
            text.contains("\ncredential_enclave_host_enclave_running 0\n"),
            "{text}"
        );
        watch.observe(Some(false));
        assert_eq!(
            call(address, Method::GET, "/livez").await,
            (503, "the enclave ended\n".to_string())
        );
        // /livez never reached the node.
        assert!(node.calls().is_empty());
    }
}
