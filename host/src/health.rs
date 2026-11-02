//! The status surface of the host program (enclave.md section 9): TCP 9091.
//!
//! - `GET /healthz`: 200 when the `health` call of the node completes within 8 seconds, 503
//!   otherwise. The probes of the pod read it.
//! - `GET /metrics`: the Prometheus text format. Four gauges from the same call; the series of
//!   the `log` object of the call (six counters and one gauge, and the write counts of a node
//!   of release v2.1.0 or later), of its `log_store` object, of its `load` object (two gauges,
//!   three counters and two gauges), of its `egress` object and of its `refresh` object, each
//!   when the node answers with one; and the three series of the egress relay of the host
//!   program itself, with every answer.
//!
//! Every request makes one `health` call over a new connection to the node. Nothing is cached:
//! an answer says what the node answered just now.

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

use crate::egress::EgressCounters;
use crate::http;
use crate::relay::{self, AcceptFailure, NodeConnector};

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
/// before v2.0.0, `load` in the response of a node of a release before v2.0.1, and `egress` and
/// `refresh` in the response of a node of a release before v2.1.0. `log_store` is null in the
/// response of a node without a log store.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct NodeHealth {
    pub configured: bool,
    pub accounts: u64,
    pub started_ms: u64,
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
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Load {
    pub provider_inflight: u64,
    pub forward_calls: u64,
    pub cpu_user_ms: Option<u64>,
    pub cpu_system_ms: Option<u64>,
    pub cpu_idle_ms: Option<u64>,
    pub memory_total_bytes: Option<u64>,
    pub memory_available_bytes: Option<u64>,
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

/// A counter with one label: one sample per value of the label, in the order given.
fn labeled_counter(
    text: &mut String,
    name: &str,
    help: &str,
    label: &str,
    samples: &[(&str, u64)],
) {
    let _ = writeln!(text, "# HELP {name} {help}");
    let _ = writeln!(text, "# TYPE {name} counter");
    for (value, count) in samples {
        let _ = writeln!(text, "{name}{{{label}=\"{value}\"}} {count}");
    }
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
/// `credential_enclave_up 0` and the three series of the host program: the other series repeat
/// values of the response, and there is none. The series of the response come after the four
/// gauges in the order of its objects, each when the node answered with the object: the seven
/// series of the `log` object and, when the node gave its write counts, their series; the
/// gauges of the `log_store` object; the series of the `load` object (two gauges, then the
/// three CPU counters when the node gave the three values, then the two memory gauges when it
/// gave the two values); the series of the `egress` object; the series of the `refresh` object.
/// The three series of the host program come last. A counter of the node restarts at 0 when
/// the node restarts (the started timestamp changes then), a CPU counter when the kernel of the
/// node boots, and a counter of the host program when the host program starts.
pub fn metrics(health: Option<&NodeHealth>, counters: &EgressCounters) -> String {
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
    host_series(&mut text, counters);
    text
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

/// The series of the `load` object: two gauges, then the three CPU counters when the node gave
/// the three values, then the two memory gauges when it gave the two values.
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

/// The three series of the egress relay of the host program. The `cause` label takes the three
/// classes of [`AcceptFailure`], and the `outcome` label the four outcomes of a connection.
fn host_series(text: &mut String, counters: &EgressCounters) {
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
        "/metrics" => {
            let health = node_health(node).await;
            respond(
                StatusCode::OK,
                PROMETHEUS_TEXT,
                metrics(health.as_ref(), counters),
            )
        }
        _ => respond(StatusCode::NOT_FOUND, TEXT, "not found\n".into()),
    }
}

/// Serves the status surface on every connection of `listener`. `counters` are the counts of
/// the egress relay, read for `/metrics`.
pub async fn serve(
    listener: TcpListener,
    node: Arc<dyn NodeConnector>,
    counters: Arc<EgressCounters>,
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
        tokio::spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let node = node.clone();
                let counters = counters.clone();
                async move {
                    let response = answer(
                        request.method(),
                        request.uri().path(),
                        node.as_ref(),
                        counters.as_ref(),
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
        health_body, health_body_with_egress_and_refresh, health_body_with_load, Behavior, FakeNode,
    };

    /// The three series of the host program before the egress relay served a connection.
    const HOST_SERIES_AT_START: &str =
        "# HELP credential_enclave_host_egress_accept_errors_total Failed accepts of the egress relay of the host program since it started, by cause.\n\
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
         credential_enclave_host_egress_relays_inflight 0\n";

    /// The names of the series that a node of release v2.1.0 adds.
    const NEW_SERIES: [&str; 12] = [
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
    ];

    /// The series of a response without the series of the host program, which come last.
    fn node_part(text: &str) -> &str {
        text.strip_suffix(HOST_SERIES_AT_START).unwrap()
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
        }
    }

    async fn status_surface(node: Arc<FakeNode>, counters: Arc<EgressCounters>) -> SocketAddr {
        let listener = relay::listen_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, node, counters));
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
                log: Some(log.clone()),
                load: Some(load_of_the_body()),
                log_store: None,
                egress: None,
                refresh: None,
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
                log: Some(log.clone()),
                load: None,
                log_store: None,
                egress: None,
                refresh: None,
            })
        );

        // A node of release v2.1.0 answers with the write counts of the log, the log store it
        // holds, and the egress and refresh objects.
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
                cpu_user_ms: None,
                cpu_system_ms: None,
                cpu_idle_ms: None,
                memory_total_bytes: None,
                memory_available_bytes: None,
            })
        );

        // Fields a later node adds do not change the reading, and a node of a release before
        // v2.0.0 answers without `log`.
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
                log: None,
                load: None,
                log_store: None,
                egress: None,
                refresh: None,
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
        let health = NodeHealth {
            configured: true,
            accounts: 12,
            started_ms: 1_790_000_000_042,
            log: None,
            load: None,
            log_store: None,
            egress: None,
            refresh: None,
        };
        assert_eq!(
            metrics(Some(&health), &no_counts),
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
            log: None,
            load: None,
            log_store: None,
            egress: None,
            refresh: None,
        };
        let text = metrics(Some(&unconfigured), &no_counts);
        assert!(text.contains("\ncredential_enclave_configured 0\n"));
        assert!(text.contains("\ncredential_enclave_accounts 0\n"));
        assert!(text.contains("\ncredential_enclave_started_timestamp_seconds 1.000\n"));
        assert!(!text.contains("credential_enclave_log_"));
        assert_eq!(text.matches("# TYPE ").count(), 4 + 3);

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
        let text = metrics(Some(&with_log), &no_counts);
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
        assert_eq!(text.matches("# TYPE ").count(), 11 + 3);
        for series in LOAD_SERIES.iter().chain(NEW_SERIES.iter()) {
            assert!(!text.contains(series), "{series}");
        }

        // With the `load` object of a node of release v2.0.1 or later: two gauges, three
        // counters and two gauges after the series of the log.
        let with_load = NodeHealth {
            load: Some(load_of_the_body()),
            ..with_log.clone()
        };
        let text = metrics(Some(&with_load), &no_counts);
        assert_eq!(text.matches("# TYPE ").count(), 18 + 3);
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
                cpu_user_ms: None,
                cpu_system_ms: None,
                cpu_idle_ms: None,
                memory_total_bytes: None,
                memory_available_bytes: None,
            }),
            ..with_log
        };
        let text = metrics(Some(&without_kernel_values), &no_counts);
        assert_eq!(text.matches("# TYPE ").count(), 13 + 3);
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
        let text = metrics(Some(&health), &EgressCounters::default());
        assert_eq!(text.matches("# TYPE ").count(), 18 + 12 + 3);

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

        // The series of the egress and refresh objects follow the load, and the series of the
        // host program come last.
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
                 credential_enclave_refresh_late_inflight 5\n",
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
            ..health
        };
        let text = metrics(Some(&partial), &EgressCounters::default());
        assert!(text.contains("\ncredential_enclave_log_store_write_retries_total 1\n"));
        assert!(text.contains("\ncredential_enclave_log_store_pending_accounts 2\n"));
        assert!(!text.contains("credential_enclave_log_store_write_seconds"));
        assert!(!text.contains("credential_enclave_log_store_write_attempt_failures_total"));
        assert!(!text.contains("credential_enclave_log_store_pending_oldest_seconds"));
        assert!(!text.contains("credential_enclave_egress_"));
        assert!(!text.contains("credential_enclave_refresh_"));
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
            metrics(None, &EgressCounters::default()),
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
        let address = status_surface(node.clone(), Arc::new(EgressCounters::default())).await;
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
    async fn the_metrics_route_reports_the_node_its_absence_and_the_egress_relay() {
        let node =
            FakeNode::answering(|_| (200, health_body_with_load(true, 3, 1_790_000_000_500)));
        let counters = Arc::new(EgressCounters::default());
        let address = status_surface(node.clone(), counters.clone()).await;
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
        assert!(
            node_part(&text).ends_with("\ncredential_enclave_memory_available_bytes 3221225472\n"),
            "{text}"
        );

        // The egress relay refuses one connection of the node: the series of the host program
        // count it, whatever the node answers.
        let (mut node_side, inbound) = tokio::io::duplex(64);
        node_side.write_all(b"\n").await.unwrap();
        let allowlist = Allowlist::from_definitions(crate::DEFINITIONS).unwrap();
        assert_eq!(
            crate::egress::relay(inbound, &allowlist, &TcpOutbound, &counters).await,
            Outcome::Malformed
        );

        // A node of release v2.0.0 answers without `load`: none of its series.
        node.set(Behavior::Answer(Arc::new(|_| {
            (200, health_body(true, 3, 1_790_000_000_500))
        })));
        let (status, text) = call(address, Method::GET, "/metrics").await;
        assert_eq!(status, 200);
        let (node_text, host_text) = text
            .split_once("# HELP credential_enclave_host_egress_accept_errors_total ")
            .unwrap();
        assert!(
            node_text.ends_with("\ncredential_enclave_log_open_batches 2\n"),
            "{text}"
        );
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
            text.ends_with("\ncredential_enclave_host_egress_relays_inflight 0\n"),
            "{text}"
        );

        node.set(Behavior::Unreachable);
        let (status, text) = call(address, Method::GET, "/metrics").await;
        assert_eq!(status, 200);
        assert!(text.starts_with("# HELP credential_enclave_up "), "{text}");
        assert!(
            text.contains("\ncredential_enclave_up 0\n# HELP credential_enclave_host_egress_accept_errors_total "),
            "{text}"
        );
        assert!(!text.contains("credential_enclave_configured"), "{text}");
        assert!(
            text.contains(
                "\ncredential_enclave_host_egress_relays_total{outcome=\"malformed\"} 1\n"
            ),
            "{text}"
        );
        assert_eq!(text.matches("# TYPE ").count(), 1 + 3);
    }

    #[tokio::test]
    async fn other_paths_and_methods_are_refused() {
        let node = FakeNode::answering(|_| (200, health_body(true, 0, 1)));
        let address = status_surface(node.clone(), Arc::new(EgressCounters::default())).await;
        assert_eq!(call(address, Method::GET, "/").await.0, 404);
        assert_eq!(call(address, Method::GET, "/v1/health").await.0, 404);
        assert_eq!(call(address, Method::POST, "/healthz").await.0, 405);
        assert_eq!(call(address, Method::POST, "/metrics").await.0, 405);
        // None of them reached the node.
        assert!(node.calls().is_empty());
    }
}
