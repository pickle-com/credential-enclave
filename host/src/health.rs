//! The status surface of the host program (enclave.md section 9): TCP 9091.
//!
//! - `GET /healthz`: 200 when the `health` call of the node completes within 2 seconds, 503
//!   otherwise. The probes of the pod read it.
//! - `GET /metrics`: four gauges in the Prometheus text format, from the same call, and the
//!   seven series of the `log` object of the call (six counters and one gauge) when the node
//!   answers with one.
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

use crate::http;
use crate::relay::{self, NodeConnector};

/// Longest `health` round trip that counts as a success.
pub const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);
/// Longest `health` body the host program reads.
const HEALTH_BODY_LIMIT_BYTES: usize = 64 * 1024;
/// Longest wait for the head of a request on the status port.
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(10);

const TEXT: &str = "text/plain; charset=utf-8";
const PROMETHEUS_TEXT: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The values of the `health` call the host program reads (enclave.md 5.1). The response has
/// more fields: they are not read. `log` is absent in the response of a node of a release
/// before v2.0.0.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct NodeHealth {
    pub configured: bool,
    pub accounts: u64,
    pub started_ms: u64,
    #[serde(default)]
    pub log: Option<LogCounts>,
}

/// The `log` object of the `health` call: counts since the node started.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct LogCounts {
    pub entries: u64,
    pub events: u64,
    pub writes: u64,
    pub write_failures: u64,
    pub open_batches: u64,
    pub batch_calls: u64,
    pub batch_requests: u64,
}

/// Calls `GET /v1/health` of the node. `None` when the connection, the call or the reading of
/// the response fails, when the status is not 200 or when the round trip takes longer than 2
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

/// The metrics of one `health` call. A failed call gives `credential_enclave_up 0` alone: the
/// other series repeat values of the response, and there is none. The seven series of the `log`
/// object come after the four gauges, when the node answered with one. A counter restarts at 0
/// when the node restarts (the started timestamp changes then).
pub fn metrics(health: Option<&NodeHealth>) -> String {
    let mut text = String::new();
    gauge(
        &mut text,
        "credential_enclave_up",
        "1 when the health call of the enclave node succeeds, 0 when it fails.",
        format_args!("{}", u8::from(health.is_some())),
    );
    let Some(health) = health else {
        return text;
    };
    gauge(
        &mut text,
        "credential_enclave_configured",
        "1 when the enclave node holds the operator configuration.",
        format_args!("{}", u8::from(health.configured)),
    );
    gauge(
        &mut text,
        "credential_enclave_accounts",
        "Accounts with a log chain on the enclave node.",
        format_args!("{}", health.accounts),
    );
    gauge(
        &mut text,
        "credential_enclave_started_timestamp_seconds",
        "Start time of the enclave node in seconds since the Unix epoch.",
        format_args!(
            "{}.{:03}",
            health.started_ms / 1000,
            health.started_ms % 1000
        ),
    );
    let Some(log) = &health.log else {
        return text;
    };
    counter(
        &mut text,
        "credential_enclave_log_entries_total",
        "Log entries the enclave node created since it started.",
        log.entries,
    );
    counter(
        &mut text,
        "credential_enclave_log_events_total",
        "Events in the log entries the enclave node created since it started.",
        log.events,
    );
    counter(
        &mut text,
        "credential_enclave_log_store_writes_total",
        "PUT requests the enclave node sent to its log store since it started.",
        log.writes,
    );
    counter(
        &mut text,
        "credential_enclave_log_store_write_failures_total",
        "PUT requests to the log store that the store did not confirm since the enclave node started.",
        log.write_failures,
    );
    counter(
        &mut text,
        "credential_enclave_forward_batch_calls_total",
        "forward/batch calls that passed the common front of the enclave node since it started.",
        log.batch_calls,
    );
    counter(
        &mut text,
        "credential_enclave_forward_batch_requests_total",
        "Provider requests in the forward/batch calls of the enclave node since it started.",
        log.batch_requests,
    );
    gauge(
        &mut text,
        "credential_enclave_log_open_batches",
        "Accounts of the enclave node whose open batch holds events at this moment.",
        format_args!("{}", log.open_batches),
    );
    text
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

async fn answer(method: &Method, path: &str, node: &dyn NodeConnector) -> Response<Full<Bytes>> {
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
            respond(StatusCode::OK, PROMETHEUS_TEXT, metrics(health.as_ref()))
        }
        _ => respond(StatusCode::NOT_FOUND, TEXT, "not found\n".into()),
    }
}

/// Serves the status surface on every connection of `listener`.
pub async fn serve(listener: TcpListener, node: Arc<dyn NodeConnector>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            relay::pause_after_failed_accept().await;
            continue;
        };
        let node = node.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let node = node.clone();
                async move {
                    let response =
                        answer(request.method(), request.uri().path(), node.as_ref()).await;
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

    use tokio::net::TcpStream;

    use super::*;
    use crate::testing::{health_body, Behavior, FakeNode};

    async fn status_surface(node: Arc<FakeNode>) -> SocketAddr {
        let listener = relay::listen_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, node));
        address
    }

    async fn call(address: SocketAddr, method: Method, path: &str) -> (u16, String) {
        let stream = TcpStream::connect(address).await.unwrap();
        let request = http::request(method, "status.test", path, &[], Vec::new()).unwrap();
        let reply = http::exchange(stream, request, 64 * 1024).await.unwrap();
        (reply.status, String::from_utf8(reply.body).unwrap())
    }

    #[tokio::test]
    async fn the_health_call_reads_four_values_and_ignores_the_others() {
        let node = FakeNode::answering(|_| (200, health_body(true, 7, 1_790_000_000_123)));
        assert_eq!(
            node_health(node.as_ref()).await,
            Some(NodeHealth {
                configured: true,
                accounts: 7,
                started_ms: 1_790_000_000_123,
                log: Some(LogCounts {
                    entries: 70,
                    events: 700,
                    writes: 71,
                    write_failures: 1,
                    open_batches: 2,
                    batch_calls: 3,
                    batch_requests: 400,
                }),
            })
        );
        let calls = node.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            (calls[0].method.as_str(), calls[0].path.as_str()),
            ("GET", "/v1/health")
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
    async fn a_health_call_that_gets_no_answer_fails_after_two_seconds() {
        let node = FakeNode::new(Behavior::Silent);
        let started = tokio::time::Instant::now();
        assert_eq!(node_health(node.as_ref()).await, None);
        let waited = started.elapsed();
        assert!(waited >= HEALTH_TIMEOUT && waited < HEALTH_TIMEOUT + Duration::from_millis(100));
    }

    #[test]
    fn the_metrics_are_four_gauges_of_the_health_call_and_the_seven_series_of_its_log() {
        let health = NodeHealth {
            configured: true,
            accounts: 12,
            started_ms: 1_790_000_000_042,
            log: None,
        };
        assert_eq!(
            metrics(Some(&health)),
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
             credential_enclave_started_timestamp_seconds 1790000000.042\n"
        );
        let unconfigured = NodeHealth {
            configured: false,
            accounts: 0,
            started_ms: 1000,
            log: None,
        };
        let text = metrics(Some(&unconfigured));
        assert!(text.contains("\ncredential_enclave_configured 0\n"));
        assert!(text.contains("\ncredential_enclave_accounts 0\n"));
        assert!(text.contains("\ncredential_enclave_started_timestamp_seconds 1.000\n"));
        assert!(!text.contains("credential_enclave_log_"));

        // With the `log` object of a node of release v2.0.0 or later: six counters and one
        // gauge after the four gauges.
        let with_log = NodeHealth {
            log: Some(LogCounts {
                entries: 5,
                events: 40,
                writes: 6,
                write_failures: 1,
                open_batches: 2,
                batch_calls: 3,
                batch_requests: 35,
            }),
            ..health
        };
        let text = metrics(Some(&with_log));
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
        assert!(text.ends_with("\n# TYPE credential_enclave_log_open_batches gauge\ncredential_enclave_log_open_batches 2\n"));
        assert_eq!(text.matches("# TYPE ").count(), 11);
    }

    #[test]
    fn a_failed_health_call_gives_the_up_gauge_alone() {
        assert_eq!(
            metrics(None),
            "# HELP credential_enclave_up 1 when the health call of the enclave node succeeds, 0 when it fails.\n\
             # TYPE credential_enclave_up gauge\n\
             credential_enclave_up 0\n"
        );
    }

    #[tokio::test]
    async fn healthz_follows_the_node() {
        let node = FakeNode::answering(|_| (200, health_body(false, 0, 1_790_000_000_000)));
        let address = status_surface(node.clone()).await;
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
    async fn the_metrics_route_reports_the_node_and_its_absence() {
        let node = FakeNode::answering(|_| (200, health_body(true, 3, 1_790_000_000_500)));
        let address = status_surface(node.clone()).await;
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

        node.set(Behavior::Unreachable);
        let (status, text) = call(address, Method::GET, "/metrics").await;
        assert_eq!(status, 200);
        assert!(text.ends_with("\ncredential_enclave_up 0\n"), "{text}");
        assert!(!text.contains("credential_enclave_configured"), "{text}");
    }

    #[tokio::test]
    async fn other_paths_and_methods_are_refused() {
        let node = FakeNode::answering(|_| (200, health_body(true, 0, 1)));
        let address = status_surface(node.clone()).await;
        assert_eq!(call(address, Method::GET, "/").await.0, 404);
        assert_eq!(call(address, Method::GET, "/v1/health").await.0, 404);
        assert_eq!(call(address, Method::POST, "/healthz").await.0, 405);
        assert_eq!(call(address, Method::POST, "/metrics").await.0, 405);
        // None of them reached the node.
        assert!(node.calls().is_empty());
    }
}
