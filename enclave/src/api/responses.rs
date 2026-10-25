//! Every body the node writes to the operator domain (rule E3 of the egress policy,
//! `docs/egress-policy.md`).
//!
//! A response body is a value of a type that implements [`OperatorResponse`], and the functions
//! that turn a value into a response ([`json_ok`], [`forward_frame`], the failure body of
//! [`super::ApiError`]) take nothing else. The trait is implemented in this file only: its
//! supertrait is private to it. So this file lists everything the operator domain can receive
//! from a node. Adding a response type means changing this file.
//!
//! Every field carries the class of its value:
//!
//! | class | meaning |
//! | --- | --- |
//! | P | public: a constant of the source, the node clock, a count or a size, node randomness, a public key, a hash of public values |
//! | E | echo: a value the operator domain gave in this call or in the operator configuration |
//! | D | declassified: a value from a sealed input or from a secret that the protocol makes public (the full list is in `docs/egress-policy.md`) |
//! | C | ciphertext that only the account, or a verified peer node, can open |
//! | S | a signature of the node over values of the classes above, or an attestation document |
//! | V | one vault value, handed out by `release` after its log entry |
//! | R | a value a provider sent, after the checks of rule E4 |
//!
//! A secret cannot be a field here: the secret types of the protocol crate do not implement
//! `Serialize`, so a response type that holds one does not compile.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use credential_enclave_protocol::encoding::{to_json, Signed};
use credential_enclave_protocol::envelope::TransferEnvelope;
use credential_enclave_protocol::record::Record;
use hyper::body::{Body as HttpBody, Bytes, Frame, SizeHint};
use serde::Serialize;
use tokio::sync::OwnedSemaphorePermit;

use crate::frame;
use crate::oauth::PublicFields;
use crate::provider_response::CheckedResponse;
use crate::state::GrantStatus;
use crate::vault::ReleasedValue;

mod sealed {
    pub trait Sealed {}
}

/// A type whose values the node writes to the operator domain.
pub trait OperatorResponse: Serialize + sealed::Sealed {}

macro_rules! operator_response {
    ($($type:ty),+ $(,)?) => {
        $(
            impl sealed::Sealed for $type {}
            impl OperatorResponse for $type {}
        )+
    };
}

operator_response!(
    Health<'_>,
    Configured,
    CredentialsStored,
    Attestation<'_>,
    Messages,
    Status,
    Begin,
    Complete,
    Merged,
    Refreshed,
    Revoked,
    ForwardMeta,
    ForwardBatchMeta,
    Released,
    Closed,
    Heads,
    Exported,
    Imported,
    ErrorBody<'_>,
);

/// The `log` object of a response (enclave.md section 4): where the event of the call is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct LogRef {
    /// P: the `seq` of the entry that holds the event.
    pub seq: u64,
    /// P: the index of the event in that entry.
    pub index: u32,
    /// P: true when this call created the event, false when it shares the event of an earlier
    /// identical request.
    pub created: bool,
}

/// One entry a `peer/export` or `peer/import` call created: the account and the `seq`.
#[derive(Serialize)]
pub struct AccountLogRef {
    /// E
    pub user_id: String,
    /// P
    pub seq: u64,
}

/// `log` of `GET /v1/health`: counts since the node started.
#[derive(Serialize)]
pub struct LogCounts {
    /// P: entries the node created.
    pub entries: u64,
    /// P: the events in them.
    pub events: u64,
    /// P: PUT requests sent to the log store.
    pub writes: u64,
    /// P: those that were not confirmed.
    pub write_failures: u64,
    /// P: accounts whose open batch holds events at this moment.
    pub open_batches: usize,
    /// P: `forward/batch` calls that passed the common front.
    pub batch_calls: u64,
    /// P: the requests in them.
    pub batch_requests: u64,
}

/// `GET /v1/health`.
#[derive(Serialize)]
pub struct Health<'a> {
    /// P: the signing public key of the node.
    pub node: &'a str,
    /// P: the release tag compiled into the binary.
    pub release: &'a str,
    /// P
    pub platform: &'a str,
    /// P
    pub custody: &'a str,
    /// P: node clock.
    pub started_ms: u64,
    /// P: node clock.
    pub time_ms: u64,
    /// P
    pub configured: bool,
    /// P
    pub closing: bool,
    /// P: a count.
    pub accounts: usize,
    /// P: a count.
    pub grants: usize,
    /// P: mail providers compiled into the measured program.
    pub mail_providers: &'a [&'a str],
    /// E and P: the log store of the node, null when it has none.
    pub log_store: Option<LogStoreState<'a>>,
    /// P: the counts of the log.
    pub log: LogCounts,
}

/// `log_store` of `GET /v1/health`.
#[derive(Serialize)]
pub struct LogStoreState<'a> {
    /// E: the bucket the operator configuration named.
    pub bucket: &'a str,
    /// E: its region.
    pub region: &'a str,
    /// E: the end of the credentials the operator domain gave, 0 when the node holds none.
    pub credentials_expires_ms: u64,
    /// P: a count, the accounts that have a pending entry.
    pub pending: usize,
}

/// `POST /v1/config`.
#[derive(Serialize)]
pub struct Configured {
    /// P
    pub configured: bool,
}

/// `POST /v1/log-store/credentials`.
#[derive(Serialize)]
pub struct CredentialsStored {
    /// E: the end of the credentials the call gave.
    pub credentials_expires_ms: u64,
}

/// `POST /v1/attestation`.
#[derive(Serialize)]
pub struct Attestation<'a> {
    /// P
    pub v: u8,
    /// P
    pub platform: &'a str,
    /// S: the attestation document of the platform over the binding (the two public keys of
    /// the node and the release) and the nonce of the caller (E).
    pub document: String,
    /// P: the signing public key of the node.
    pub node: &'a str,
    /// P: node randomness.
    pub challenge: String,
    /// P
    pub release: &'a str,
    /// S: the signature of the node over its identifier (P), the nonce of the caller (E), the
    /// challenge above (P) and the node clock (P).
    pub challenge_statement: Signed,
}

/// `POST /v1/messages`.
#[derive(Serialize)]
pub struct Messages {
    /// S: the body holds P, E and D values (`type`, `ok`, `code`, `node`, `user_id`,
    /// `challenge`, `key_id`, `not_after_ms`, `head`, `time_ms`).
    pub reply: Signed,
    /// P: the entry and the index of the event the command created, null when it created
    /// none.
    pub log: Option<LogRef>,
    /// D: `state`, `key_id`, `custody`, `not_after_ms` of the grant.
    pub grant: GrantStatus,
}

/// `POST /v1/status`.
#[derive(Serialize)]
pub struct Status {
    /// S: the body holds the end of the chain (P), the nonce of the caller (E) and the node
    /// clock (P).
    pub head: Signed,
    /// D: `state`, `key_id`, `custody`, `not_after_ms` of the grant.
    pub grant: GrantStatus,
}

/// `POST /v1/oauth/begin`.
#[derive(Serialize)]
pub struct Begin {
    /// P and E, and one D value: the address of the definition (P), `client_id` and
    /// `redirect_uri` of the operator configuration (E), the parameters of the caller (E), the
    /// state (P and E) and the S256 challenge of the PKCE verifier (D).
    pub authorization_url: String,
    /// P and E: node randomness, then the `operator_state` of the caller.
    pub state: String,
    /// S: the body holds P, E and D values (the account key of the grant, the hash of the
    /// authorization address).
    pub statement: Signed,
    /// P: node clock.
    pub expires_ms: u64,
}

/// `POST /v1/oauth/complete`.
#[derive(Serialize)]
pub struct Complete {
    /// C: encrypted under the user key.
    pub record: Record,
    /// R, P and D: the public fields.
    pub public: PublicFields,
    /// S
    pub statement: Signed,
    /// P
    pub log: LogRef,
}

/// `POST /v1/oauth/merge`.
#[derive(Serialize)]
pub struct Merged {
    /// C
    pub record: Record,
    /// R, P and D
    pub public: PublicFields,
}

/// `POST /v1/refresh`. A node keeps the value of a successful refresh for a repeated call
/// with the same record, so the type is cloned.
#[derive(Clone, Serialize)]
pub struct Refreshed {
    /// C
    pub record: Record,
    /// R, P and D
    pub public: PublicFields,
    /// P
    pub log: LogRef,
}

/// `POST /v1/revoke-token`.
#[derive(Serialize)]
pub struct Revoked {
    /// R: one bit, whether the revocation address answered with a 2xx status.
    pub revoked: bool,
    /// P
    pub log: LogRef,
}

/// The meta of a `POST /v1/forward` response frame. The payload of the frame is the provider
/// body (R).
#[derive(Serialize)]
pub struct ForwardMeta {
    /// R
    status: u16,
    /// R
    headers: Vec<(String, String)>,
    /// P: the event of the request, null for a mail call that created no event of its own.
    log: Option<LogRef>,
}

/// The meta of a `POST /v1/forward/batch` response frame. The payload of the frame is the
/// provider bodies of the results one after another (R), `body_bytes` each.
#[derive(Serialize)]
pub struct ForwardBatchMeta {
    results: Vec<BatchResultMeta>,
}

/// One result of a `forward/batch` call: the provider response of the request, or the failure
/// code the request had.
#[derive(Serialize)]
pub struct BatchResultMeta {
    /// R
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    /// R
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<Vec<(String, String)>>,
    /// P: a size.
    #[serde(skip_serializing_if = "Option::is_none")]
    body_bytes: Option<usize>,
    /// P: a code of the closed list of protocol.md section 11.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
    /// P
    log: LogRef,
}

/// The outcome of one request of a `forward/batch` call.
pub enum BatchResult {
    Response(CheckedResponse, LogRef),
    Failure(&'static str, LogRef),
}

/// `POST /v1/release`.
#[derive(Serialize)]
pub struct Released {
    /// V
    pub value: ReleasedValue,
    /// P
    pub log: LogRef,
}

/// `POST /v1/close`.
#[derive(Serialize)]
pub struct Closed {
    /// P: a count.
    pub accounts: usize,
}

/// `POST /v1/close/heads`.
#[derive(Serialize)]
pub struct Heads {
    /// S: each body holds the end of a chain (P).
    pub heads: Vec<Signed>,
    /// E: the `user_id` of the last head of the page.
    pub next: String,
}

/// `POST /v1/peer/export`.
#[derive(Serialize)]
pub struct Exported {
    /// C: sealed to the sealing key of the verified peer (sink K2).
    pub envelope: Option<TransferEnvelope>,
    /// E and P: the entries `grant_transferred_out` this call created.
    pub logs: Vec<AccountLogRef>,
    /// E: the `user_id` the listing continues after.
    pub next: String,
}

/// `POST /v1/peer/import`.
#[derive(Serialize)]
pub struct Imported {
    /// P: a count.
    pub imported: usize,
    /// E and P: the entries `grant_transferred_in` this call created.
    pub logs: Vec<AccountLogRef>,
}

/// The body of every failure.
#[derive(Serialize)]
pub struct ErrorBody<'a> {
    /// P: a code of the closed list of protocol.md section 11.
    pub code: &'a str,
    /// P: a fixed string of the source.
    pub message: &'static str,
    /// R: the HTTP status of the provider, 0 for a transport failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_status: Option<u16>,
    /// R: a word of the closed vocabulary of rule E5.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_error: Option<&'static str>,
    /// P: the index of the request of a `forward/batch` call that the failure is about.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
}

pub(super) fn json_bytes(status: StatusCode, body: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// A 200 response with a JSON body. The keys are in the order the type declares them.
pub fn json_ok<T: OperatorResponse>(value: &T) -> Response {
    json_bytes(StatusCode::OK, to_json(value))
}

/// A failure response.
pub(super) fn json_error(status: StatusCode, body: &ErrorBody<'_>) -> Response {
    json_bytes(status, to_json(body))
}

/// A response frame of `forward`: the meta, then the provider body. The share of the body
/// budget that the provider body occupies is held until the frame was written out.
struct FrameBody {
    parts: VecDeque<Bytes>,
    remaining: u64,
    _budget: OwnedSemaphorePermit,
}

impl HttpBody for FrameBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let next = self.parts.pop_front();
        if let Some(part) = &next {
            self.remaining -= part.len() as u64;
        }
        Poll::Ready(next.map(|part| Ok(Frame::data(part))))
    }

    fn is_end_stream(&self) -> bool {
        self.parts.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

/// The 200 response of `forward`: the frame of a provider response that passed the checks of
/// rule E4, and the place of the event of the request.
pub fn forward_frame(
    checked: CheckedResponse,
    log: Option<LogRef>,
    budget: OwnedSemaphorePermit,
) -> Response {
    let (status, headers, body) = checked.into_parts();
    let head = frame::encode_head(&ForwardMeta {
        status,
        headers,
        log,
    });
    frame_response(vec![Bytes::from(head), Bytes::from(body)], budget)
}

/// The 200 response of `forward/batch`: one frame whose meta lists the results in the order
/// of the requests and whose payload is their bodies one after another.
pub fn forward_batch_frame(results: Vec<BatchResult>, budget: OwnedSemaphorePermit) -> Response {
    let mut metas = Vec::with_capacity(results.len());
    let mut bodies = Vec::with_capacity(results.len());
    for result in results {
        match result {
            BatchResult::Response(checked, log) => {
                let (status, headers, body) = checked.into_parts();
                metas.push(BatchResultMeta {
                    status: Some(status),
                    headers: Some(headers),
                    body_bytes: Some(body.len()),
                    error: None,
                    log,
                });
                bodies.push(Bytes::from(body));
            }
            BatchResult::Failure(code, log) => metas.push(BatchResultMeta {
                status: None,
                headers: None,
                body_bytes: None,
                error: Some(code),
                log,
            }),
        }
    }
    let head = frame::encode_head(&ForwardBatchMeta { results: metas });
    let mut parts = Vec::with_capacity(1 + bodies.len());
    parts.push(Bytes::from(head));
    parts.extend(bodies);
    frame_response(parts, budget)
}

fn frame_response(parts: Vec<Bytes>, budget: OwnedSemaphorePermit) -> Response {
    let remaining = parts.iter().map(|part| part.len() as u64).sum();
    let frame_body = FrameBody {
        parts: VecDeque::from(parts),
        remaining,
        _budget: budget,
    };
    let mut response = Response::new(Body::new(frame_body));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(frame::CONTENT_TYPE));
    response
}
