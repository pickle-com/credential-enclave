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
use credential_enclave_protocol::envelope::{ReplyHead, TransferEnvelope};
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
    Released,
    Entries,
    Acknowledged,
    Closed,
    Heads,
    Exported,
    Imported,
    ErrorBody<'_>,
);

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
    /// C: sealed to the log public key of the account.
    pub entry: Option<Signed>,
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
    /// C
    pub entry: Signed,
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
    /// C
    pub entry: Signed,
}

/// `POST /v1/revoke-token`.
#[derive(Serialize)]
pub struct Revoked {
    /// R: one bit, whether the revocation address answered with a 2xx status.
    pub revoked: bool,
    /// C
    pub entry: Signed,
}

/// The meta of a `POST /v1/forward` response frame. The payload of the frame is the provider
/// body (R).
#[derive(Serialize)]
pub struct ForwardMeta {
    /// R
    status: u16,
    /// R
    headers: Vec<(String, String)>,
    /// C
    entry: Option<Signed>,
}

/// `POST /v1/release`.
#[derive(Serialize)]
pub struct Released {
    /// V
    pub value: ReleasedValue,
    /// C
    pub entry: Signed,
}

/// `POST /v1/log/entries`.
#[derive(Serialize)]
pub struct Entries {
    /// C
    pub entries: Vec<Signed>,
    /// P: the end of the chain.
    pub head: ReplyHead,
}

/// `POST /v1/log/ack`.
#[derive(Serialize)]
pub struct Acknowledged {
    /// P: a count.
    pub unacked: usize,
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
    /// C
    pub entries: Vec<Signed>,
    /// E: the `user_id` the listing continues after.
    pub next: String,
}

/// `POST /v1/peer/import`.
#[derive(Serialize)]
pub struct Imported {
    /// P: a count.
    pub imported: usize,
    /// C
    pub entries: Vec<Signed>,
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
/// rule E4, and the entry of the request.
pub fn forward_frame(
    checked: CheckedResponse,
    entry: Option<Signed>,
    budget: OwnedSemaphorePermit,
) -> Response {
    let (status, headers, body) = checked.into_parts();
    let head = frame::encode_head(&ForwardMeta {
        status,
        headers,
        entry,
    });
    let remaining = (head.len() + body.len()) as u64;
    let frame_body = FrameBody {
        parts: VecDeque::from([Bytes::from(head), Bytes::from(body)]),
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
