//! Every body the node writes to the operator domain (rule E3 of the egress policy,
//! `docs/egress-policy.md`).
//!
//! A response body is a value of a type that implements [`OperatorResponse`], and the functions
//! that turn a value into a response ([`json_ok`], [`forward_frame`], [`send_stream`], the
//! failure body of [`super::ApiError`]) take nothing else. The trait is implemented in this file only: its
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
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use credential_enclave_protocol::encoding::{to_json, Signed};
use credential_enclave_protocol::envelope::TransferEnvelope;
use credential_enclave_protocol::record::Record;
use credential_enclave_protocol::secret_use::SecretUseEnvelope;
use credential_enclave_protocol::ProtocolError;
use hyper::body::{Body as HttpBody, Bytes, Frame, SizeHint};
use serde::Serialize;
use tokio::sync::OwnedSemaphorePermit;

use super::ApiError;
use crate::egress::Exchange;
use crate::frame;
use crate::oauth::PublicFields;
use crate::provider_response::{CheckedHead, CheckedResponse, StreamCheck};
use crate::state::{lock, GrantStatus};
use crate::vault::HandedOut;

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
    Stored,
    HandedOff,
    SendMeta,
    StreamEnd,
    Closed,
    Heads,
    Exported,
    Imported,
    Pruned,
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
    /// P: attempts to write an entry to the log store (PUT requests), confirmed or not.
    pub writes: u64,
    /// P: entries the store did not confirm within the budget of their attempts.
    pub write_failures: u64,
    /// P: accounts whose open batch holds events at this moment.
    pub open_batches: usize,
    /// P: `forward/batch` calls that passed the common front.
    pub batch_calls: u64,
    /// P: the requests in them.
    pub batch_requests: u64,
    /// P: the attempts the store did not confirm, by cause.
    pub write_attempt_failures: WriteAttemptFailureCounts,
    /// P: attempts that followed an attempt the store did not confirm.
    pub write_retries: u64,
    /// P: the confirmed attempts by their time to confirmation, cumulative.
    pub write_ms_buckets: WriteMsBuckets,
    /// P: the sum of the times to confirmation of the confirmed attempts, in milliseconds.
    pub write_ms_sum: u64,
    /// P: the confirmed attempts.
    pub write_count: u64,
}

/// `write_attempt_failures` of `log` of health: the keys are the causes of
/// `crate::log_store::WriteFailure`, constants of the source.
#[derive(Serialize)]
pub struct WriteAttemptFailureCounts {
    /// P
    pub connect: u64,
    /// P
    pub tls: u64,
    /// P
    pub closed: u64,
    /// P
    pub timeout: u64,
    /// P
    pub status_4xx: u64,
    /// P
    pub status_5xx: u64,
}

/// `write_ms_buckets` of `log` of health: the confirmed attempts whose time to confirmation
/// was at most the milliseconds of the key (`crate::state::WRITE_MS_BOUNDS`). The counts are
/// cumulative: every attempt counted under a key is counted under every larger key as well.
#[derive(Serialize)]
pub struct WriteMsBuckets {
    /// P
    #[serde(rename = "25")]
    pub le_25: u64,
    /// P
    #[serde(rename = "50")]
    pub le_50: u64,
    /// P
    #[serde(rename = "100")]
    pub le_100: u64,
    /// P
    #[serde(rename = "250")]
    pub le_250: u64,
    /// P
    #[serde(rename = "500")]
    pub le_500: u64,
    /// P
    #[serde(rename = "1000")]
    pub le_1000: u64,
    /// P
    #[serde(rename = "2500")]
    pub le_2500: u64,
    /// P
    #[serde(rename = "5000")]
    pub le_5000: u64,
}

/// `egress` of `GET /v1/health`: the outbound connections since the node started, and those
/// being opened at this moment (enclave.md 5.1).
#[derive(Serialize)]
pub struct EgressCounts {
    /// P: connections that were opened.
    pub opens: u64,
    /// P: attempts to open a connection that failed, by cause.
    pub open_failures: OpenFailureCounts,
    /// P: attempts that followed a failed attempt.
    pub open_retries: u64,
    /// P: a count, the connections being opened at this moment.
    pub open_inflight: usize,
    /// P: requests that went over an idle connection, by peer.
    pub idle_reuses: IdleReuseCounts,
}

/// `open_failures` of `egress` of health: the keys are the causes of
/// `crate::egress::OpenError`, constants of the source.
#[derive(Serialize)]
pub struct OpenFailureCounts {
    /// P
    pub transport: u64,
    /// P
    pub relay_refused: u64,
    /// P
    pub tls: u64,
    /// P
    pub http: u64,
}

/// `idle_reuses` of `egress` of health.
#[derive(Serialize)]
pub struct IdleReuseCounts {
    /// P: requests to a provider over an idle connection of their account and host.
    pub provider: u64,
    /// P: writes to the log store over an idle connection to it.
    pub log_store: u64,
}

/// `refresh` of `GET /v1/health`: the token address calls of `refresh` that the node continued
/// after their time limit (enclave.md 5.7).
#[derive(Serialize)]
pub struct RefreshCounts {
    /// P: the outcomes of the late calls since the node started.
    pub late: LateRefreshCounts,
    /// P: a count, the late calls in progress at this moment.
    pub late_inflight: usize,
}

/// `late` of `refresh` of health.
#[derive(Serialize)]
pub struct LateRefreshCounts {
    /// P: late successes that became the kept response of their record.
    pub kept: u64,
    /// P: late successes that were not kept (the grant had ended or the node was closing).
    pub dropped: u64,
    /// P: late calls that ended with a refusal, a transport failure or the late limit.
    pub failed: u64,
    /// P: calls that found no place among the late calls and ended at their time limit.
    pub abandoned: u64,
}

/// `state` of `GET /v1/health`: the sizes of the variable state of the accounts and of the
/// idle connections at the moment of the call (enclave.md 5.1).
#[derive(Serialize)]
pub struct StateCounts {
    /// P: a count, the kept `refresh` responses over every account.
    pub kept_refreshes: usize,
    /// P: a count, the merge keys over every account.
    pub merge_keys: usize,
    /// P: a count, the entries the log store has not confirmed over every account.
    pub pending_entries: usize,
    /// P: the idle connections the node keeps, by peer.
    pub idle_connections: IdleConnectionCounts,
}

/// `idle_connections` of `state` of health.
#[derive(Serialize)]
pub struct IdleConnectionCounts {
    /// P: a count, the idle connections to providers over every account and host.
    pub provider: usize,
    /// P: a count, the idle connections to the log store.
    pub log_store: usize,
}

/// `load` of `GET /v1/health`: the load of the node at the moment of the call.
#[derive(Serialize)]
pub struct Load {
    /// P: a count, the provider requests in flight.
    pub provider_inflight: usize,
    /// P: a count, the calls that hold one of the places of the bound of concurrent `forward`
    /// and `forward/batch` calls.
    pub forward_calls: usize,
    /// P: a count, the connections from the backend open at this moment.
    pub inbound_connections: usize,
    /// P: a count, the connections from the backend closed at accept because the bound of
    /// open connections was reached, since the node started.
    pub inbound_refused: u64,
    /// P: the CPU time in user mode of the kernel the node runs in since it booted, in
    /// milliseconds. Null when the kernel exposes no procfs value.
    pub cpu_user_ms: Option<u64>,
    /// P: the CPU time in kernel mode, in the same way.
    pub cpu_system_ms: Option<u64>,
    /// P: the idle time, in the same way.
    pub cpu_idle_ms: Option<u64>,
    /// P: a size, the memory of the kernel in bytes. Null when the kernel exposes no procfs
    /// value.
    pub memory_total_bytes: Option<u64>,
    /// P: a size, the memory the kernel estimates it can give out, in the same way.
    pub memory_available_bytes: Option<u64>,
    /// P: a count, the open file descriptors of the node process. Null when the kernel
    /// exposes no procfs value.
    pub descriptors_open: Option<u64>,
    /// P: a count, the soft limit of open file descriptors of the node process in force. Null
    /// when the platform has no such limit.
    pub descriptors_limit: Option<u64>,
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
    /// P: `forward` on a node of the forward role, null on every other node. The role came
    /// with the operator configuration (E) and is a constant of the source.
    pub role: Option<&'a str>,
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
    /// P: the load of the node.
    pub load: Load,
    /// P: the outbound connections of the node.
    pub egress: EgressCounts,
    /// P: the late token address calls of `refresh`.
    pub refresh: RefreshCounts,
    /// P: the sizes of the variable state of the accounts.
    pub state: StateCounts,
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
    /// P: node clock, the age of the oldest pending entry in milliseconds, 0 when there is
    /// none.
    pub pending_oldest_ms: u64,
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
    /// V: the value under the key `value`, or, for a call that named a key to seal it to,
    /// the value under the seal of that key under the key `sealed`. The caller chose the key:
    /// a sealed value is a value the operator domain reads.
    #[serde(flatten)]
    pub handed_out: HandedOut,
    /// P
    pub log: LogRef,
}

/// `POST /v1/vault/store`.
#[derive(Serialize)]
pub struct Stored {
    /// C: encrypted under the user key. Its plaintext holds the value and, for a record of
    /// kind `vault_secret`, the name, the sites and the slots the call gave (E), and the
    /// source `operator` (P). Its `id` and its nonce are node randomness (P).
    pub record: Record,
    /// P
    pub log: LogRef,
}

/// `POST /v1/vault/handoff`.
#[derive(Serialize)]
pub struct HandedOff {
    /// C: one use of a vault secret, the value and the request it is for, sealed to the
    /// sealing key of the verified node of the forward role (sink K8). `from` and `to` are the
    /// identifiers of the two nodes (P).
    pub envelope: SecretUseEnvelope,
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
    /// E: the `user_id` the listing continues after.
    pub next: String,
    /// P: a count, the accounts of the page whose final head stands at the last entry the
    /// store confirmed, below pending entries that were dropped.
    pub truncated: usize,
    /// P: a count, the accounts of the page that got no final head in this call.
    pub skipped: usize,
}

/// `POST /v1/grants/prune`.
#[derive(Serialize)]
pub struct Pruned {
    /// E: the `user_id` of every account whose grant this call dropped.
    pub pruned: Vec<String>,
    /// E: the `user_id` the walk continues after.
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

/// The meta of a `POST /v1/vault/send` response: the head of the response of the host.
#[derive(Serialize)]
pub struct SendMeta {
    /// R
    status: u16,
    /// R
    headers: Vec<(String, String)>,
}

/// The end record of the response of `vault/send`: how the body ended.
#[derive(Serialize)]
pub struct StreamEnd {
    /// P: true when the body ended as the host ended it, and every byte of it was handed on.
    complete: bool,
    /// P: a code of the closed list of protocol.md section 11, when the body was cut.
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
    /// P: a fixed string of the source.
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'static str>,
}

/// The body of the response of `POST /v1/vault/send` (enclave.md 5.16): the meta, then the
/// body of the response of the host in parts as it arrives, then the end record.
///
/// ```text
/// stream = meta_len (unsigned 32 bit, big-endian) || meta (UTF-8 JSON) || part* || end
/// part   = part_len (unsigned 32 bit, big-endian, at least 1) || part_len bytes of the body
/// end    = 0 (unsigned 32 bit) || UTF-8 JSON {"complete":true}
///                               | {"complete":false,"code":"...","message":"..."}
/// ```
///
/// Every piece of the body passes the search of rule E4 before a byte of it is queued
/// (`StreamCheck`), and what is queued lags behind what arrived by the bytes that search
/// keeps back. When the body ends as the host ended it, the kept bytes follow and the end
/// record says `complete`. When the search finds the value, when the host or the connection
/// fails, or when the time limit of the call passes, the body is cut there: the connection to
/// the host is dropped, the kept bytes are overwritten and not handed on, and the end record
/// names the reason. A stream that ends without an end record was cut by something else, and
/// a reader takes it for a failure.
///
/// The stream reads a piece of the body when its caller took what was queued before, and it
/// queues no more than what one piece gives: the node holds of a body the piece it reads and
/// the bytes the search keeps back, whatever the length of the body.
///
/// The time limit of the call holds whatever its caller does. A stream is read only while
/// its caller takes what it hands on, so a caller that stops reading would keep the response
/// of the host, and the places of the call, for as long as its connection to the node lasts.
/// The watch of the time limit ([`BodyStream::watch`]) runs apart from the reading: at the
/// time limit it drops what the call holds, read or not.
struct BodyStream {
    /// What is ready to be written: the meta first, then the parts, then the end record.
    queue: VecDeque<Bytes>,
    /// What the call holds while its body goes on. `None` once the body ended or was cut:
    /// by this stream, or by the watch of the time limit.
    held: Arc<Mutex<Option<Held>>>,
    /// True once the end record is queued.
    ended: bool,
    /// The time limit of the call, for a stream whose caller reads: the body is cut when it
    /// passes while the stream waits for the host.
    deadline: Pin<Box<tokio::time::Sleep>>,
    /// The watch of the time limit, ended with the stream.
    watch: tokio::task::AbortHandle,
}

/// What a call whose response is a stream holds until the body of that response ended or
/// was cut.
struct Held {
    /// The response of the host, with the connection to it and the place of the call among
    /// the provider requests in flight.
    exchange: Exchange,
    check: StreamCheck,
    /// The place among the forward calls of the node and the share of the body budget the
    /// request body occupies.
    _places: (OwnedSemaphorePermit, OwnedSemaphorePermit),
}

/// The four bytes in front of a part that its length is written into.
const PART_LENGTH_BYTES: usize = 4;

impl BodyStream {
    /// The stream of `exchange`, behind `meta`. The watch of the time limit starts with it.
    fn new(
        meta: Vec<u8>,
        check: StreamCheck,
        exchange: Exchange,
        deadline: tokio::time::Instant,
        places: (OwnedSemaphorePermit, OwnedSemaphorePermit),
    ) -> BodyStream {
        let held = Arc::new(Mutex::new(Some(Held {
            exchange,
            check,
            _places: places,
        })));
        BodyStream {
            queue: VecDeque::from([Bytes::from(meta)]),
            watch: BodyStream::watch(held.clone(), deadline),
            held,
            ended: false,
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
        }
    }

    /// Drops what a call holds at its time limit, whether or not its stream is read: the
    /// response of the host with its connection, the search with the bytes it kept, and the
    /// places of the call. A stream that is read afterwards finds nothing held and ends with
    /// `timeout`.
    fn watch(
        held: Arc<Mutex<Option<Held>>>,
        deadline: tokio::time::Instant,
    ) -> tokio::task::AbortHandle {
        tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            let dropped = lock(&held).take();
            drop(dropped);
        })
        .abort_handle()
    }

    /// A part without a byte of the body yet: the place of its length.
    fn open_part() -> Vec<u8> {
        vec![0; PART_LENGTH_BYTES]
    }

    /// Queues a part, when it holds a byte of the body.
    fn queue_part(&mut self, mut part: Vec<u8>) {
        // A part begins with the room for its length. One without that room, and one whose
        // length the four bytes cannot state, is not queued.
        let length = part
            .len()
            .checked_sub(PART_LENGTH_BYTES)
            .and_then(|length| u32::try_from(length).ok());
        if let (Some(length @ 1..), Some(prefix)) = (length, part.get_mut(..PART_LENGTH_BYTES)) {
            prefix.copy_from_slice(&length.to_be_bytes());
            self.queue.push_back(Bytes::from(part));
        }
    }

    /// Ends the body: drops what the call still holds (the response of the host, the search
    /// with the bytes it kept, the places of the call) and queues the end record.
    fn end(&mut self, cut: Option<ProtocolError>) {
        let dropped = lock(&self.held).take();
        drop(dropped);
        self.watch.abort();
        self.ended = true;
        let record = StreamEnd {
            complete: cut.is_none(),
            code: cut.map(|error| error.code()),
            message: cut.map(|error| ApiError::from(error).message),
        };
        let mut bytes = 0u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&to_json(&record));
        self.queue.push_back(Bytes::from(bytes));
    }

    /// Reads the next piece of the body and queues what the search hands on of it. `Ready`
    /// with how the body ended once it ended or was cut (`None` in it for a body that ended
    /// as the host ended it), and `Ready(None)` for a body that goes on.
    fn read(&mut self, context: &mut Context<'_>) -> Poll<Option<Option<ProtocolError>>> {
        let mut held = lock(&self.held);
        // The watch took what the call held: the time limit passed.
        let Some(state) = held.as_mut() else {
            return Poll::Ready(Some(Some(ProtocolError::Timeout)));
        };
        let piece = match state.exchange.poll_piece(context) {
            Poll::Ready(piece) => piece,
            Poll::Pending => return Poll::Pending,
        };
        let mut part = BodyStream::open_part();
        let ended = match piece {
            // A piece: what the search hands on of it and of the pieces before it.
            Some(Ok(piece)) => match state.check.push(&piece, &mut part) {
                Ok(()) => None,
                Err(_) => Some(Some(ProtocolError::ResponseWithheld)),
            },
            // The end of the body as the host ended it: the bytes the search kept.
            None => match held.take().map(|state| state.check.finish(&mut part)) {
                Some(Ok(())) => Some(None),
                _ => Some(Some(ProtocolError::ResponseWithheld)),
            },
            // The connection failed inside the body.
            Some(Err(_)) => Some(Some(ProtocolError::ProviderUnreachable)),
        };
        drop(held);
        // A part of a body that was cut is not handed on: the cut is in front of it.
        if !matches!(ended, Some(Some(_))) {
            self.queue_part(part);
        }
        Poll::Ready(ended)
    }
}

/// A stream whose caller went away: what the call still holds is dropped with it, here and
/// not when the watch of the time limit ends.
impl Drop for BodyStream {
    fn drop(&mut self) {
        let dropped = lock(&self.held).take();
        drop(dropped);
        self.watch.abort();
    }
}

impl HttpBody for BodyStream {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        loop {
            if let Some(next) = self.queue.pop_front() {
                return Poll::Ready(Some(Ok(Frame::data(next))));
            }
            if self.ended {
                return Poll::Ready(None);
            }
            if self.deadline.as_mut().poll(context).is_ready() {
                self.end(Some(ProtocolError::Timeout));
                continue;
            }
            match self.read(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {}
                Poll::Ready(Some(cut)) => self.end(cut),
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.queue.is_empty() && self.ended
    }
}

/// The 200 response of `vault/send`: the head of a response that passed the checks of rule E4
/// on its status and its headers, and its body as it arrives, each piece after the search of
/// that rule. `deadline` is the end of the time limit of the call, and `held` the place of the
/// call among the forward calls of the node with the share of the body budget of its request
/// body.
pub fn send_stream(
    head: CheckedHead,
    check: StreamCheck,
    exchange: Exchange,
    deadline: tokio::time::Instant,
    held: (OwnedSemaphorePermit, OwnedSemaphorePermit),
) -> Response {
    let (status, headers) = head.into_parts();
    let meta = frame::encode_head(&SendMeta { status, headers });
    let stream = BodyStream::new(meta, check, exchange, deadline, held);
    let mut response = Response::new(Body::new(stream));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static(frame::STREAM_CONTENT_TYPE),
    );
    response
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
