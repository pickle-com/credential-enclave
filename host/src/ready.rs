//! The ready mark of the pod (enclave.md 9.2).
//!
//! A node that answers its `health` call is not yet a node that holds what it has to hold. A
//! node that started again waits for its operator configuration, for the credentials of its
//! log store, for the write of its node document, and for the delegations of its accounts,
//! which the backend hands over from the nodes that hold them. The backend knows when all of
//! that has arrived, and says so with one call, `POST /ready`. The readiness of the pod,
//! `GET /readyz`, follows the mark: whoever replaces the pods of a fleet one after another
//! waits for the readiness of the pod it replaced, and so goes on only when the node of that
//! pod is filled.
//!
//! - A pod whose node holds delegations (the delegation role, the reserve role) is marked by
//!   the backend. The call carries the token of the shutdown collection call and names the
//!   node the backend judged: the host program checks the token and that the pod runs that
//!   node, and judges nothing else about the node.
//! - A pod of the forward role has nothing to be filled with. The host program sets its mark
//!   itself, once the node took the role.
//! - A pod is not ready once its node is closing or the host program received its
//!   termination signal, whatever its mark: no caller is to choose it for a new call.
//!
//! The mark lives in the memory of the host program. A host program runs one enclave and ends
//! with it, so a container that starts again has a new node and no mark. Like everything the
//! host program does, the mark is no part of what a node guarantees.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Bytes};
use hyper::header::{HeaderValue, AUTHORIZATION};
use hyper::{Request, Response, StatusCode};

use crate::health::{node_health, respond, JSON};
use crate::relay::NodeConnector;

/// Longest wait for the body of `POST /ready`, from the head of the request to the end of the
/// body.
const BODY_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest body of `POST /ready` the host program reads.
const BODY_LIMIT_BYTES: usize = 4 * 1024;

/// The ready mark of the pod, and whether the pod is ending.
pub struct Readiness {
    /// The bearer token of the call that sets the mark: the token of the shutdown collection
    /// call (`CREDENTIAL_ENCLAVE_DRAIN_TOKEN`). `None` when the pod has none: every call is
    /// refused then.
    token: Option<String>,
    marked: AtomicBool,
    /// True once the host program began to end: it received its termination signal, or the
    /// watch confirmed that the enclave ended on its own.
    ending: AtomicBool,
}

impl Readiness {
    /// The ready mark of a pod whose backend authenticates with `token`. The mark is not set.
    pub fn new(token: Option<String>) -> Readiness {
        Readiness {
            token,
            marked: AtomicBool::new(false),
            ending: AtomicBool::new(false),
        }
    }

    /// True once the mark was set.
    pub fn marked(&self) -> bool {
        self.marked.load(Ordering::SeqCst)
    }

    /// Sets the mark. True when this call set it, false when it was set before.
    pub fn mark(&self) -> bool {
        !self.marked.swap(true, Ordering::SeqCst)
    }

    /// True once the host program began to end.
    pub fn ending(&self) -> bool {
        self.ending.load(Ordering::SeqCst)
    }

    /// The host program begins to end: from here on the pod is not ready.
    pub fn end(&self) {
        self.ending.store(true, Ordering::SeqCst);
    }

    /// True when `authorization` is `Bearer` and the token of this pod. The comparison takes
    /// the same time for every value of the same length.
    fn authorizes(&self, authorization: Option<&HeaderValue>) -> bool {
        let (Some(token), Some(authorization)) = (&self.token, authorization) else {
            return false;
        };
        let Some(given) = authorization.as_bytes().strip_prefix(b"Bearer ") else {
            return false;
        };
        let token = token.as_bytes();
        given.len() == token.len()
            && given
                .iter()
                .zip(token)
                .fold(0u8, |difference, (given, token)| {
                    difference | (given ^ token)
                })
                == 0
    }
}

/// A failure of `POST /ready`: the status and the body `{"code":"..."}`.
fn refused(status: StatusCode, code: &str) -> Response<Full<Bytes>> {
    respond(
        status,
        JSON,
        serde_json::json!({ "code": code }).to_string(),
    )
}

/// The node a body of `POST /ready` names: the string `node` of a JSON object, when it is not
/// empty.
fn named_node(body: &[u8]) -> Option<String> {
    let body: serde_json::Value = serde_json::from_slice(body).ok()?;
    let node = body.as_object()?.get("node")?.as_str()?;
    (!node.is_empty()).then(|| node.to_string())
}

/// `POST /ready`: sets the ready mark for the node the body names.
///
/// The body is read to its end, at most [`BODY_LIMIT_BYTES`], before any answer: an answer
/// that leaves while the body is still on its way can be lost with the connection. A body
/// that has not ended after [`BODY_TIMEOUT`] is not waited for any longer, so a caller that
/// stops sending does not hold its connection.
///
/// Then, in this order: a call without the bearer token of the pod is 401 `unauthenticated`
/// (every call, when the pod has no token); a body that is not `{"node":"<id>"}`, is longer
/// than the limit or did not end in time is 400 `invalid_request`; a pod that is ending is
/// 503 `closing`; a node that does not answer its `health` call is 503 `unavailable`; a body
/// that names another node than the one that answered is 409 `node_mismatch` (the backend
/// judged a node that is gone: this pod runs a new one); a node that is closing is 503
/// `closing`. Otherwise the mark is set and the answer is 200 `{"ready":true,"node":"<id>"}`,
/// also when the mark was set before.
pub async fn set<B>(
    request: Request<B>,
    node: &dyn NodeConnector,
    readiness: &Readiness,
) -> Response<Full<Bytes>>
where
    B: Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let authorized = readiness.authorizes(request.headers().get(AUTHORIZATION));
    let body = Limited::new(request.into_body(), BODY_LIMIT_BYTES).collect();
    let body = tokio::time::timeout(BODY_TIMEOUT, body)
        .await
        .ok()
        .and_then(|body| body.ok())
        .map(|body| body.to_bytes());
    if !authorized {
        return refused(StatusCode::UNAUTHORIZED, "unauthenticated");
    }
    let Some(named) = body.and_then(|body| named_node(&body)) else {
        return refused(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if readiness.ending() {
        return refused(StatusCode::SERVICE_UNAVAILABLE, "closing");
    }
    let Some(health) = node_health(node).await else {
        return refused(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    };
    if health.node != named {
        return refused(StatusCode::CONFLICT, "node_mismatch");
    }
    if health.closing {
        return refused(StatusCode::SERVICE_UNAVAILABLE, "closing");
    }
    if readiness.mark() {
        crate::log("ready: the backend set the ready mark of the pod");
    }
    respond(
        StatusCode::OK,
        JSON,
        serde_json::json!({ "ready": true, "node": named }).to_string(),
    )
}

/// `GET /readyz`: 200 when the pod is ready, 503 otherwise, with the body
/// `{"ready":<bool>,"marked":<bool>}`. A pod is ready when its mark is set, the host program
/// is not ending, and its node answers its `health` call and is not closing. A pod that is
/// not marked, and a pod that is ending, make no call to the node for the answer.
pub async fn answer(node: &dyn NodeConnector, readiness: &Readiness) -> Response<Full<Bytes>> {
    let marked = readiness.marked();
    let ready = marked
        && !readiness.ending()
        && node_health(node)
            .await
            .is_some_and(|health| !health.closing);
    let status = match ready {
        true => StatusCode::OK,
        false => StatusCode::SERVICE_UNAVAILABLE,
    };
    respond(
        status,
        JSON,
        serde_json::json!({ "ready": ready, "marked": marked }).to_string(),
    )
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Arc;

    use hyper::header::CONTENT_TYPE;
    use hyper::Method;

    use super::*;
    use crate::testing::{health_body, Behavior, FakeNode};

    const TOKEN: &str = "status-token";
    const NOT_READY: &str = r#"{"ready":false,"marked":false}"#;
    const UNAUTHENTICATED: &str = r#"{"code":"unauthenticated"}"#;
    const INVALID_REQUEST: &str = r#"{"code":"invalid_request"}"#;
    const CLOSING: &str = r#"{"code":"closing"}"#;

    /// A node of the id `n` that answers its `health` call, closing or not.
    fn node_of_the_pod(closing: bool) -> Arc<FakeNode> {
        FakeNode::answering(move |_| {
            let health = health_body(true, 0, 1)
                .replace(r#""closing":false"#, &format!(r#""closing":{closing}"#));
            (200, health)
        })
    }

    /// The status and the body of a response.
    async fn read(response: Response<Full<Bytes>>) -> (u16, String) {
        let status = response.status().as_u16();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    /// `POST /ready` with the bearer token `token` and `body`: the status and the body of the
    /// answer.
    async fn mark(
        node: &FakeNode,
        readiness: &Readiness,
        token: Option<&str>,
        body: &[u8],
    ) -> (u16, String) {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/ready")
            .header(CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = request
            .body(Full::new(Bytes::copy_from_slice(body)))
            .unwrap();
        read(set(request, node, readiness).await).await
    }

    /// `GET /readyz`: the status and the body of the answer.
    async fn readyz(node: &FakeNode, readiness: &Readiness) -> (u16, String) {
        read(answer(node, readiness).await).await
    }

    #[tokio::test]
    async fn the_ready_mark_is_set_by_the_call_of_the_backend_that_names_the_node() {
        let node = node_of_the_pod(false);
        let readiness = Readiness::new(Some(TOKEN.to_string()));
        let named = br#"{"node":"n"}"#;

        // No mark: the pod is not ready although its node answers, and the readiness makes
        // no call to the node.
        assert_eq!(
            readyz(&node, &readiness).await,
            (503, NOT_READY.to_string())
        );
        assert!(node.calls().is_empty());

        // A call without the token of the pod sets nothing, whatever its body.
        for token in [None, Some(""), Some("status-toke"), Some("status-token2")] {
            assert_eq!(
                mark(&node, &readiness, token, named).await,
                (401, UNAUTHENTICATED.to_string()),
                "{token:?}"
            );
        }
        assert_eq!(
            mark(&node, &readiness, Some("wrong"), b"not json").await,
            (401, UNAUTHENTICATED.to_string())
        );
        // A body that does not name a node.
        let long = format!(r#"{{"node":"n","pad":"{}"}}"#, "x".repeat(4096));
        for body in [
            &b""[..],
            b"not json",
            b"[]",
            b"{}",
            br#"{"node":""}"#,
            br#"{"node":5}"#,
            br#"{"node":null}"#,
            long.as_bytes(),
        ] {
            assert_eq!(
                mark(&node, &readiness, Some(TOKEN), body).await,
                (400, INVALID_REQUEST.to_string()),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        // None of these calls reached the node.
        assert!(node.calls().is_empty());
        // Another node than the one of this pod: the backend judged a node that is gone.
        assert_eq!(
            mark(&node, &readiness, Some(TOKEN), br#"{"node":"m"}"#).await,
            (409, r#"{"code":"node_mismatch"}"#.to_string())
        );
        // A node that does not answer cannot be named: the form of the body is judged first.
        node.set(Behavior::Unreachable);
        assert_eq!(
            mark(&node, &readiness, Some(TOKEN), named).await,
            (503, r#"{"code":"unavailable"}"#.to_string())
        );
        assert_eq!(
            mark(&node, &readiness, Some(TOKEN), b"{}").await,
            (400, INVALID_REQUEST.to_string())
        );
        assert!(!readiness.marked());

        // The call of the backend for this node sets the mark, and a second one changes
        // nothing. A key the host program does not know does not change the reading.
        let node = node_of_the_pod(false);
        let marked = (200, r#"{"ready":true,"node":"n"}"#.to_string());
        assert_eq!(mark(&node, &readiness, Some(TOKEN), named).await, marked);
        assert!(readiness.marked());
        assert_eq!(
            mark(
                &node,
                &readiness,
                Some(TOKEN),
                br#"{"node":"n","reason":"filled"}"#
            )
            .await,
            marked
        );
        assert_eq!(
            readyz(&node, &readiness).await,
            (200, r#"{"ready":true,"marked":true}"#.to_string())
        );

        // The mark stays, and the readiness also follows the node: a marked pod whose node
        // does not answer is not ready.
        node.set(Behavior::Unreachable);
        assert_eq!(
            readyz(&node, &readiness).await,
            (503, r#"{"ready":false,"marked":true}"#.to_string())
        );
    }

    #[tokio::test]
    async fn a_pod_without_a_token_refuses_every_call_that_would_set_its_mark() {
        let node = node_of_the_pod(false);
        let readiness = Readiness::new(None);
        for token in [None, Some(""), Some(TOKEN)] {
            assert_eq!(
                mark(&node, &readiness, token, br#"{"node":"n"}"#).await,
                (401, UNAUTHENTICATED.to_string()),
                "{token:?}"
            );
        }
        assert_eq!(
            readyz(&node, &readiness).await,
            (503, NOT_READY.to_string())
        );
        // None of the calls reached the node.
        assert!(node.calls().is_empty());

        // The host program of a pod of the forward role sets the mark itself: the pod is
        // ready from then on, and the call of a backend is refused as before.
        assert!(readiness.mark());
        assert!(!readiness.mark());
        assert_eq!(
            readyz(&node, &readiness).await,
            (200, r#"{"ready":true,"marked":true}"#.to_string())
        );
        assert_eq!(
            mark(&node, &readiness, Some(TOKEN), br#"{"node":"n"}"#).await,
            (401, UNAUTHENTICATED.to_string())
        );
    }

    #[tokio::test]
    async fn a_pod_whose_node_is_closing_or_whose_host_program_is_ending_is_not_ready() {
        let named = br#"{"node":"n"}"#;
        let not_ready = (503, r#"{"ready":false,"marked":true}"#.to_string());

        // A marked pod whose node was closed (the shutdown collection of the backend closes
        // it before the termination signal reaches the host program) is not ready, and a
        // closing node gets no mark.
        let open = node_of_the_pod(false);
        let readiness = Readiness::new(Some(TOKEN.to_string()));
        assert_eq!(mark(&open, &readiness, Some(TOKEN), named).await.0, 200);
        assert_eq!(readyz(&open, &readiness).await.0, 200);
        let closing = node_of_the_pod(true);
        assert_eq!(readyz(&closing, &readiness).await, not_ready);
        let unmarked = Readiness::new(Some(TOKEN.to_string()));
        assert_eq!(
            mark(&closing, &unmarked, Some(TOKEN), named).await,
            (503, CLOSING.to_string())
        );
        assert!(!unmarked.marked());

        // The host program received its termination signal: the pod is not ready although
        // its node still answers as an open one, the readiness makes no call to the node,
        // and the pod takes no mark.
        let calls = open.calls().len();
        readiness.end();
        assert_eq!(readyz(&open, &readiness).await, not_ready);
        assert_eq!(open.calls().len(), calls);
        unmarked.end();
        assert_eq!(
            mark(&open, &unmarked, Some(TOKEN), named).await,
            (503, CLOSING.to_string())
        );
        assert_eq!(open.calls().len(), calls);
        assert!(!unmarked.marked());
        // The token and the form of the body are judged first.
        assert_eq!(
            mark(&open, &unmarked, None, named).await,
            (401, UNAUTHENTICATED.to_string())
        );
        assert_eq!(
            mark(&open, &unmarked, Some(TOKEN), b"{}").await,
            (400, INVALID_REQUEST.to_string())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_ready_call_whose_body_does_not_end_is_answered_at_the_time_limit() {
        let node = node_of_the_pod(false);
        let readiness = Readiness::new(Some(TOKEN.to_string()));
        // A call with the token of the pod whose body never ends.
        let request = Request::builder()
            .method(Method::POST)
            .uri("/ready")
            .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Stalled(false))
            .unwrap();
        let started = tokio::time::Instant::now();
        let response = set(request, node.as_ref(), &readiness).await;
        assert_eq!(started.elapsed(), BODY_TIMEOUT);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!readiness.marked());
    }

    /// A request body that gives the first half of `{"node":"n"}` and then no further byte.
    struct Stalled(bool);

    impl Body for Stalled {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
            if std::mem::replace(&mut self.0, true) {
                return std::task::Poll::Pending;
            }
            let half = Bytes::from_static(b"{\"node\":");
            std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(half))))
        }
    }
}
