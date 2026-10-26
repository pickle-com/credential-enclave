//! Test-only code: a stand-in for the node that answers HTTP calls over in-memory pipes.

use std::convert::Infallible;
use std::io;
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;

use crate::relay::{BoxFuture, NodeConnector, Stream};

/// One call the stand-in received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

/// Answers one call: status and body.
pub type Answer = Arc<dyn Fn(&Call) -> (u16, String) + Send + Sync>;

/// How the stand-in answers a connection.
#[derive(Clone)]
pub enum Behavior {
    /// The connection cannot be opened.
    Unreachable,
    /// The connection opens and no response ever comes.
    Silent,
    /// Every call is answered by the function.
    Answer(Answer),
}

/// A node stand-in. Its behavior can be changed while a test runs.
pub struct FakeNode {
    behavior: Mutex<Behavior>,
    calls: Arc<Mutex<Vec<Call>>>,
    /// The far ends of silent connections, kept open.
    silent: Mutex<Vec<tokio::io::DuplexStream>>,
}

impl FakeNode {
    pub fn new(behavior: Behavior) -> Arc<FakeNode> {
        Arc::new(FakeNode {
            behavior: Mutex::new(behavior),
            calls: Arc::new(Mutex::new(Vec::new())),
            silent: Mutex::new(Vec::new()),
        })
    }

    /// A stand-in that answers every call with `answer`.
    pub fn answering(
        answer: impl Fn(&Call) -> (u16, String) + Send + Sync + 'static,
    ) -> Arc<FakeNode> {
        FakeNode::new(Behavior::Answer(Arc::new(answer)))
    }

    pub fn set(&self, behavior: Behavior) {
        *self.behavior.lock().unwrap() = behavior;
    }

    /// The calls received so far.
    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }
}

/// The `health` body of a node with the given values, in the form of enclave.md 5.1.
pub fn health_body(configured: bool, accounts: u64, started_ms: u64) -> String {
    format!(
        concat!(
            r#"{{"node":"n","release":"v2.0.0","platform":"nitro","started_ms":{started_ms},"time_ms":{time_ms},"#,
            r#""configured":{configured},"closing":false,"accounts":{accounts},"grants":0,"#,
            r#""mail_providers":["naver_mail"],"log_store":null,"#,
            r#""log":{{"entries":{entries},"events":{events},"writes":{writes},"write_failures":1,"#,
            r#""open_batches":2,"batch_calls":3,"batch_requests":{batch_requests}}}}}"#
        ),
        started_ms = started_ms,
        time_ms = started_ms + 1000,
        configured = configured,
        accounts = accounts,
        entries = accounts * 10,
        events = accounts * 100,
        writes = accounts * 10 + 1,
        batch_requests = accounts * 100 / 2 + 50,
    )
}

impl NodeConnector for FakeNode {
    fn connect(&self) -> BoxFuture<'_, io::Result<Stream>> {
        Box::pin(async move {
            let behavior = self.behavior.lock().unwrap().clone();
            let (near, far) = tokio::io::duplex(64 * 1024);
            match behavior {
                Behavior::Unreachable => {
                    return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
                }
                Behavior::Silent => self.silent.lock().unwrap().push(far),
                Behavior::Answer(answer) => {
                    let calls = self.calls.clone();
                    tokio::spawn(async move {
                        let service = service_fn(move |request: Request<Incoming>| {
                            let answer = answer.clone();
                            let calls = calls.clone();
                            async move {
                                let method = request.method().to_string();
                                let path = request.uri().path().to_string();
                                let body = request
                                    .into_body()
                                    .collect()
                                    .await
                                    .map(|body| body.to_bytes().to_vec())
                                    .unwrap_or_default();
                                let call = Call { method, path, body };
                                let (status, text) = answer(&call);
                                calls.lock().unwrap().push(call);
                                let response = Response::builder()
                                    .status(status)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(text)))
                                    .unwrap();
                                Ok::<_, Infallible>(response)
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(far), service)
                            .await;
                    });
                }
            }
            Ok(Box::new(near) as Stream)
        })
    }
}
