//! `POST /v1/forward` (enclave.md 5.8): sends a provider request with the credential of a
//! record injected. The functions `prepare` and `execute` are shared with `POST
//! /v1/forward/batch` (`super::forward_batch`).
//!
//! The response has one of two forms, and the caller chooses. Without `stream` in the meta of
//! the request it is a frame: the node reads the whole body of the provider into memory,
//! checks the response as a whole and answers with the meta and the body. With `"stream":
//! true` it is a stream: the head of the provider response first, and its body in parts while
//! it arrives, each part after the search of rule E4 (`provider_response::StreamCheck`).
//!
//! The credential reaches an address of the provider definition only (enclave.md section 7).
//! The entry that holds the event `provider_request` is on the chain, and the log store
//! confirmed it, before the request leaves the node. The node does not judge token expiry and
//! does not refresh: the provider response, a 401 included, goes back as it is, after the
//! checks of rule E4 of the egress policy (`crate::provider_response`).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::header::CONTENT_LENGTH;
use axum::http::HeaderValue;
use axum::response::Response;
use credential_enclave_protocol::record::Record;
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::secret_use::{header_key, names_no_other_charset};
use credential_enclave_protocol::{limits, ProtocolError};
use hyper::body::Bytes;
use serde_json::Value;
use tokio::sync::{Mutex, OwnedMutexGuard, OwnedSemaphorePermit};

use super::responses::{forward_frame, forward_stream, LogRef, StreamElement, StreamEnd};
use super::{
    above_bounds, invalid, narrowed, read_body, record_of, request_share_of, reserve, respond,
    Admission, ApiError, JsonBody,
};
use crate::egress::{self, EgressError, Exchange, OutboundBody, OutboundHeader, OutboundRequest};
use crate::faults::joined;
use crate::frame::{self, META_LIMIT_BYTES};
use crate::log_store;
use crate::oauth::{self, Withheld};
use crate::provider_response::{self, CheckedResponse, StreamCheck};
use crate::providers::Definition;
use crate::state::{events, lock, merge_key, Node};

/// The methods `forward` sends.
const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/// Caller headers the node drops: the credential header is the node's, `Accept-Encoding` is
/// set by the node, and most of the rest describe the connection or the body framing.
///
/// `Range` and `If-Range` are dropped because the node asks for the whole of a response
/// (rule E4 of the egress policy): the search for the injected credential reads what one
/// response holds. Of a response that held the credential, two parts that are asked for one
/// by one would each pass the search, and a response of several ranges
/// (`multipart/byteranges`) holds its parts with other bytes between them. A provider that
/// honours a range answers the request without one with the whole representation, and a body
/// of any length is handed on as a stream.
///
/// `Accept-Charset` is dropped because the search reads the bytes of a response: a provider
/// that honours the header would send a body in another character encoding, and under
/// UTF-16 the bytes of a credential are not the bytes the search looks for. An `Accept`
/// header that names another character encoding than UTF-8 asks for the same, and its call
/// is refused ([`caller_headers`]).
const DROPPED_HEADERS: [&str; 16] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "expect",
    "accept-encoding",
    "range",
    "if-range",
    "accept-charset",
];

/// Caller headers that ask a provider to treat a request as one of another method than the
/// method it is sent with. A call that carries one is refused: the entry `provider_request`
/// names the method of the request, and the request that leaves is of that method.
const REFUSED_HEADERS: [&str; 3] = [
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

pub(super) const TIMEOUT_DEFAULT_MS: u64 = 30_000;
pub(super) const TIMEOUT_MIN_MS: u64 = 1_000;
pub(super) const TIMEOUT_MAX_MS: u64 = 120_000;
/// The longest time limit of a call that asked for its response as a stream: the time from
/// the confirmation of its entry to the end of the body of the provider.
const STREAM_TIMEOUT_MAX_MS: u64 = 600_000;
/// The elements of a stream the task that reads the provider keeps ready for the response
/// body: two parts, each a length prefix and its bytes.
const STREAM_ELEMENTS: usize = 4;

pub async fn forward(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// The `timeout_ms` of a call: 1,000 to 120,000, 30,000 when absent.
pub(super) fn timeout_of(meta: &JsonBody) -> Result<u64, ApiError> {
    timeout_within(meta, TIMEOUT_MAX_MS)
}

/// The `timeout_ms` of a call: 1,000 to `longest`, 30,000 when absent.
fn timeout_within(meta: &JsonBody, longest: u64) -> Result<u64, ApiError> {
    match meta.get("timeout_ms") {
        None => Ok(TIMEOUT_DEFAULT_MS),
        Some(value) => value
            .as_u64()
            .filter(|timeout| (TIMEOUT_MIN_MS..=longest).contains(timeout))
            .ok_or_else(|| invalid("timeout_ms")),
    }
}

/// Whether a call asks for its response as a stream: `stream` of the meta, a boolean. An
/// absent key is false.
fn stream_of(meta: &JsonBody) -> Result<bool, ApiError> {
    match meta.get("stream") {
        None => Ok(false),
        Some(value) => value.as_bool().ok_or_else(|| invalid("stream")),
    }
}

/// The failure code of a provider call that failed.
fn failure_of(error: EgressError) -> ProtocolError {
    match error {
        EgressError::TooLarge => ProtocolError::TooLarge,
        EgressError::Invalid => ProtocolError::NotAllowed,
        EgressError::Unreachable => ProtocolError::ProviderUnreachable,
        // Rule E4: a body under a transfer coding the node does not remove is not handed on.
        EgressError::Coded => ProtocolError::from(Withheld),
    }
}

/// Reads the request headers of a request object: an array of `[name, value]` pairs under
/// `headers`. A name that is not a token and a value with CR, LF or another control
/// character are `invalid_request`. A header of [`REFUSED_HEADERS`] is `not_allowed`, and
/// so is an `Accept` header that names another character encoding than UTF-8. The headers
/// of [`DROPPED_HEADERS`] and the header the definition injects are dropped. A name is
/// compared in the form of [`header_key`], and the two rules are those of the request of a
/// vault secret (`credential_enclave_protocol::secret_use`).
fn caller_headers(
    request: &Value,
    definition: &Definition,
) -> Result<Vec<OutboundHeader>, ApiError> {
    let Some(value) = request.get("headers").filter(|value| !value.is_null()) else {
        return Ok(Vec::new());
    };
    let pairs = value.as_array().ok_or_else(|| invalid("headers"))?;
    let mut headers = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let (name, value) = match pair.as_array().map(Vec::as_slice) {
            Some([name, value]) => (
                name.as_str().ok_or_else(|| invalid("headers"))?,
                value.as_str().ok_or_else(|| invalid("headers"))?,
            ),
            _ => return Err(invalid("headers")),
        };
        if !egress::is_token(name) || HeaderValue::from_bytes(value.as_bytes()).is_err() {
            return Err(invalid("headers"));
        }
        let key = header_key(name);
        if REFUSED_HEADERS.contains(&key.as_str())
            || (key == "accept" && !names_no_other_charset(value))
        {
            return Err(ProtocolError::NotAllowed.into());
        }
        if DROPPED_HEADERS.contains(&key.as_str())
            || definition
                .inject
                .iter()
                .any(|rule| key == header_key(&rule.header))
        {
            continue;
        }
        headers.push(OutboundHeader::plain(name, value));
    }
    Ok(headers)
}

/// A request that passed steps 2 to 4 of enclave.md 5.8: the outbound request with the
/// credential injected and the token to search the response for (rule E4), the length of
/// that token, the merge key of a GET without a body, and the event `provider_request` of
/// the request.
pub(super) struct Prepared {
    /// The request and its token. `None` for a record whose plaintext, or whose token, is
    /// above what a node reads (`oauth::Unusable::AboveBounds`): no credential was made and
    /// nothing is sent. The request has its event all the same, and its call ends with
    /// `above_bounds` once the log store confirmed the entry of that event.
    pub request: Option<(OutboundRequest, Secret<String>)>,
    pub token_bytes: usize,
    pub merge_key: Option<[u8; 32]>,
    pub event: Value,
}

/// Steps 2 to 4 of enclave.md 5.8 for one request object (`method`, `url`, `headers`) with
/// its body: the address check of the definition, the method, the credential header of the
/// rule of the host, `Accept-Encoding: identity`, the headers of the caller, and the check
/// that the request can be expressed in HTTP/1.1. `parsed` is the parsed plaintext of the
/// record the credential comes from, or why the node does not use that plaintext.
pub(super) fn prepare(
    request: &Value,
    payload: &Bytes,
    record: &Record,
    definition: &Definition,
    parsed: Result<&oauth::OauthPlaintext, oauth::Unusable>,
    context: &str,
) -> Result<Prepared, ApiError> {
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("method"))?;
    let address = request
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("url"))?;
    // 2
    let target = definition.check_address(address)?;
    // 3
    if !METHODS.contains(&method) {
        return Err(ProtocolError::NotAllowed.into());
    }
    // 4: the credential header of the rule of this host, then `Accept-Encoding: identity`
    // (the node searches the response and does not decode it), then the headers of the
    // caller.
    let rule = definition
        .inject_rule(target.host())
        .ok_or(ProtocolError::NotAllowed)?;
    // A plaintext without a token for this rule ends the call here. A plaintext, or a
    // token, above what a node reads does not: that judgement depends on the content of
    // the plaintext, so it is made after the entry of the call. No credential is made of
    // such a record, and the rest of the request is checked without one.
    let credential = match parsed.and_then(|plaintext| plaintext.credential(rule)) {
        Ok(credential) => Some(credential),
        Err(oauth::Unusable::Invalid) => return Err(ProtocolError::RecordInvalid.into()),
        Err(oauth::Unusable::AboveBounds) => None,
    };
    let token_bytes = credential
        .as_ref()
        .map_or(0, oauth::Credential::token_bytes);
    let (token, mut headers) = match credential {
        Some(credential) => {
            let (header_value, token) = credential.into_parts();
            let header = OutboundHeader::secret(&rule.header, header_value);
            (Some(token), vec![header])
        }
        None => (None, Vec::new()),
    };
    headers.push(OutboundHeader::plain("accept-encoding", "identity"));
    headers.extend(caller_headers(request, definition)?);
    let outbound = OutboundRequest::new(
        target.destination(),
        method,
        headers,
        OutboundBody::Plain(payload.clone()),
    );
    if egress::check(&outbound).is_err() {
        return Err(ProtocolError::NotAllowed.into());
    }
    // 5: an identical GET of the same record within 300 seconds shares the event that is
    // already on the chain or in the open batch. A GET with a body always gets its own
    // event, which carries the size and the hash of that body: the merge key holds the
    // address only.
    let mergeable = method == "GET" && payload.is_empty();
    let merge_key = match mergeable {
        true => Some(merge_key(
            &record.id_bytes()?,
            target.host(),
            target.path(),
            target.query(),
        )),
        false => None,
    };
    let event = events::provider_request(
        &record.id,
        &record.provider,
        method,
        target.host(),
        target.path(),
        target.query(),
        payload,
        context,
        mergeable,
    );
    Ok(Prepared {
        request: token.map(|token| (outbound, token)),
        token_bytes,
        merge_key,
        event,
    })
}

/// Steps 8 and 9 of enclave.md 5.8 and rule E4 for one prepared request, within `timeout`:
/// the provider call over the connections of the account, the body under the budget of the
/// node, and the check of the response for the injected credential. `request_budget` is the
/// share of the budget the request body occupies: it is free as soon as the request is on the
/// wire, before the response body asks for its own share, so two calls never wait for each
/// other. The returned permit holds the share the response body occupies. `turns` holds the
/// share of the budget the call took for its credential ([`credential_share`]): the check
/// of the response runs in its turn under it.
pub(super) async fn execute(
    node: &Node,
    user_id: &str,
    outbound: OutboundRequest,
    token: Secret<String>,
    timeout: Duration,
    request_budget: Option<OwnedSemaphorePermit>,
    turns: SearchTurns,
) -> Result<(CheckedResponse, OwnedSemaphorePermit), ProtocolError> {
    let body_limit = node.limits.body_bytes;
    let call = async {
        let exchange = node
            .egress
            .send_to_provider(
                node.platform.as_ref(),
                Some(user_id),
                outbound,
                node.now_ms(),
                timeout,
            )
            .await?;
        drop(request_budget);
        // A declared length is reserved as it is. A body of unknown length reserves the limit
        // and gives back what it did not use.
        let reserved = match exchange.content_length {
            Some(length) if length > body_limit as u64 => return Err(EgressError::TooLarge),
            Some(length) => length as usize,
            None if matches!(exchange.status, 204 | 304) => 0,
            None => body_limit,
        };
        let mut budget = reserve(node, reserved)
            .await
            .map_err(|_| EgressError::Unreachable)?;
        let status = exchange.status;
        let headers = exchange.headers.clone();
        let body = exchange.read_body(body_limit).await?;
        if body.len() < reserved {
            drop(budget.split(reserved - body.len()));
        }
        Ok((status, headers, body, budget))
    };
    let (status, headers, body, budget) = match tokio::time::timeout(timeout, call).await {
        Err(_) => return Err(ProtocolError::Timeout),
        Ok(Err(error)) => return Err(failure_of(error)),
        Ok(Ok(outcome)) => outcome,
    };
    // The check below waits for its turn among the checks of this call, and the turn goes
    // into its task with the token: the share of the body budget the call holds for its
    // credential is held until that task has ended.
    let token = Searched {
        token,
        _turn: turns.lock_owned().await,
    };
    // Rule E4: a response that holds the injected credential, or a body the node cannot
    // search, is not handed on. The entry of the request is already on the chain. The search
    // reads the whole body, so it runs off the threads that serve the calls. A panic of the
    // search is a panic of this call (`joined`): the request has reached the provider, and a
    // failure response would say that the call can be made again.
    //
    // The share of the body budget the response body occupies goes into the task with the
    // body and comes back with its outcome: the body is in memory until that task has
    // ended, whether or not the call still waits for it, and so is its share.
    let mut search = tokio::task::spawn_blocking(move || {
        let checked = provider_response::check(&token, status, headers, body);
        (checked, budget)
    });
    let (checked, budget) = joined(&mut search)
        .await
        .ok_or(ProtocolError::ProviderUnreachable)?;
    Ok((checked.map_err(ProtocolError::from)?, budget))
}

/// The end record of a body that was cut with the failure `error`.
pub(super) fn cut(error: ProtocolError) -> StreamEnd {
    let failure = ApiError::from(error);
    StreamEnd::cut(failure.code, failure.message)
}

/// Steps 8 to 10 of enclave.md 5.8 for a call that asked for its response as a stream: the
/// provider call over the connections of the account, the checks of rule E4 on the head of the
/// response, and the 200 response whose body hands the body of the provider on in parts,
/// each after the search of that rule.
///
/// `timeout` runs from here to the end of the body. A failure before the head of the provider
/// response is the failure of the call, as for a frame. A failure after it cannot be: the
/// status 200 has left, and a body that is cut says so in the end record of its stream.
///
/// `request_budget` is the share of the body budget the request frame occupies: it is free
/// once the request is on the wire. The body of the provider is not held in memory. What the
/// node holds of it is what the search holds: the bytes it has not handed on yet, its
/// readings and the forms of the credential, as many bytes as the length of the credential
/// bounds (`StreamCheck::memory_bound`). `held` is the place of the call among the forward
/// calls of the node, the share of the body budget of that bound, and the share of the
/// request of the call (the connection to the provider keeps the buffer the head of the
/// request was written from as long as the stream lasts): the three are free when the body
/// has ended, was cut, the time limit passed or the caller is gone, whichever comes first.
#[allow(clippy::too_many_arguments)]
async fn stream(
    node: &Arc<Node>,
    user_id: &str,
    outbound: OutboundRequest,
    token: Secret<String>,
    timeout: Duration,
    log: LogRef,
    request_budget: OwnedSemaphorePermit,
    held: (
        OwnedSemaphorePermit,
        OwnedSemaphorePermit,
        OwnedSemaphorePermit,
    ),
) -> Result<Response, ApiError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let head = tokio::time::timeout_at(
        deadline,
        node.egress.send_to_provider(
            node.platform.as_ref(),
            Some(user_id),
            outbound,
            node.now_ms(),
            timeout,
        ),
    )
    .await;
    drop(request_budget);
    let mut exchange = match head {
        Err(_) => return Err(ProtocolError::Timeout.into()),
        Ok(Err(error)) => return Err(failure_of(error).into()),
        Ok(Ok(exchange)) => exchange,
    };
    let status = exchange.status;
    let mut headers = std::mem::take(&mut exchange.headers);
    // Rule E4 on the head: a response whose headers hold the credential, or whose body is
    // under a content coding, is not handed on. Nothing of it has left.
    let check = StreamCheck::begin(&token, &mut headers).map_err(ProtocolError::from)?;
    drop(token);
    let (body, late) = hand_on_body(exchange, check, deadline, held);
    Ok(forward_stream(status, headers, Some(log), body, late))
}

/// No fewer bytes than the token of `record` has that a call makes a credential of. The token
/// is a part of the plaintext of the record, and that plaintext is shorter than the
/// ciphertext, which `ct` writes with four characters for three bytes. And a node makes no
/// credential of a token of more than `limits::TOKEN_BYTES` bytes ([`prepare`]).
pub(super) fn longest_token(record: &Record) -> usize {
    record
        .ct
        .len()
        .div_ceil(4)
        .saturating_mul(3)
        .min(limits::TOKEN_BYTES)
}

/// The parsed plaintext of the record of a call, or that the node does not read it because
/// it is above its bounds (`oauth::Unusable::AboveBounds`: the call goes on to its entry and
/// ends after it). A plaintext that is no token object ends the call here, with
/// `record_invalid`.
pub(super) fn usable(
    parsed: Result<oauth::OauthPlaintext, oauth::Unusable>,
) -> Result<Result<oauth::OauthPlaintext, oauth::Unusable>, ApiError> {
    match parsed {
        Err(oauth::Unusable::Invalid) => Err(ProtocolError::RecordInvalid.into()),
        parsed => Ok(parsed),
    }
}

/// The bytes the header value of a request holds of a token of `token_bytes` bytes, at the
/// most: the token behind the prefix of its rule, or inside the base64 text of HTTP Basic,
/// four characters for three bytes. The prefix and the user name of a rule are constants of
/// the definition: they do not grow with the token.
const fn header_bytes(token_bytes: usize) -> usize {
    token_bytes.div_ceil(3).saturating_mul(4).saturating_add(4)
}

/// The share of the body budget a call that answers with a frame takes for the credential of
/// its requests (`forward` without `stream`, `forward/batch`): what the node holds for the
/// call beside its bodies that grows with the length of the token. `token_bytes` is the
/// length of the token, or more. The call sends `requests` requests, `in_flight` of them at
/// a time.
///
/// - The search of a response (`provider_response::check_memory_bound`). The searches of one
///   call run one at a time ([`SearchTurns`]), so a call holds the room of one search.
/// - For every request, from the moment it is prepared: the token its response is searched
///   for, and the header value that carries the token.
/// - For every request that is being sent, that header value twice more: in the request of
///   the HTTP client, and in the head that client writes.
///
/// A call that asks for a stream holds the same before the search of its body begins, and
/// the share of that search is the larger one (`StreamCheck::memory_bound`).
pub(crate) const fn credential_share(
    token_bytes: usize,
    requests: usize,
    in_flight: usize,
) -> usize {
    let header = header_bytes(token_bytes);
    provider_response::check_memory_bound(token_bytes)
        .saturating_add(requests.saturating_mul(token_bytes.saturating_add(header)))
        .saturating_add(in_flight.saturating_mul(header.saturating_mul(2)))
}

/// The share of the body budget a call holds for its credential ([`credential_share`]), and
/// the turns of the checks of its responses under it: a check holds the lock while it runs,
/// so one check of a call runs at a time. The share is free when the call has let go of this
/// value and no check of the call runs.
pub(super) type SearchTurns = Arc<Mutex<OwnedSemaphorePermit>>;

/// The turns of the checks of a call that holds `budget` for its credential.
pub(super) fn search_turns(budget: OwnedSemaphorePermit) -> SearchTurns {
    Arc::new(Mutex::new(budget))
}

/// The token of a request with the turn of the check of its response ([`SearchTurns`]). The
/// check reads the token through this value, which goes into the task of the check: the turn
/// ends when that task has ended, whether or not the call still waits for it.
struct Searched {
    token: Secret<String>,
    _turn: OwnedMutexGuard<OwnedSemaphorePermit>,
}

impl std::ops::Deref for Searched {
    type Target = Secret<String>;

    fn deref(&self) -> &Secret<String> {
        &self.token
    }
}

/// Starts the task of a stream (the stream form of `forward`, `vault/send`), which hands the
/// body of `exchange` on until `deadline`, each part after the search of `check`. Returns
/// what the response body of the call reads the elements of the stream from, and the end
/// record of a call whose task ended without one. `held` is what the call holds until its
/// body has ended (its place among the forward calls of the node, and the shares of the body
/// budget it keeps): the task drops it.
pub(super) fn hand_on_body<Held: Send + 'static>(
    exchange: Exchange,
    check: StreamCheck,
    deadline: tokio::time::Instant,
    held: Held,
) -> (tokio::sync::mpsc::Receiver<StreamElement>, StreamEnd) {
    let (elements, body) = tokio::sync::mpsc::channel(STREAM_ELEMENTS);
    tokio::spawn(hand_on_until(exchange, check, elements, deadline, held));
    (body, cut(ProtocolError::Timeout))
}

/// The task of a stream: hands the body of the provider on until it ends, is cut, the time
/// limit of the call passes or the caller is gone, and then frees what the call held (the
/// connection to the provider, the place among the forward calls) before the end record waits
/// for the caller. The task does not depend on the caller reading the response: a caller that
/// reads slowly, or not at all, holds the call for the time limit at the longest.
async fn hand_on_until<Held>(
    mut exchange: Exchange,
    mut check: StreamCheck,
    elements: tokio::sync::mpsc::Sender<StreamElement>,
    deadline: tokio::time::Instant,
    held: Held,
) {
    let end = tokio::select! {
        end = tokio::time::timeout_at(deadline, hand_on(&mut exchange, &mut check, &elements)) => end,
        // The response body was dropped: the connection of the caller ended.
        _ = elements.closed() => Ok(None),
    };
    drop(exchange);
    drop(check);
    drop(held);
    let record = match end {
        Ok(Some(record)) => record,
        Ok(None) => return,
        Err(_) => cut(ProtocolError::Timeout),
    };
    let end = Bytes::from(frame::encode_stream_end(&record));
    let _ = elements.send(StreamElement::End(end)).await;
}

/// Hands the body of the provider on in parts: every part of the body goes through the search
/// of rule E4, and the bytes the search lets go leave as parts of at most
/// `frame::STREAM_PART_LIMIT_BYTES`. Returns the end record of the stream, or `None` when the
/// caller is gone.
async fn hand_on(
    exchange: &mut Exchange,
    check: &mut StreamCheck,
    elements: &tokio::sync::mpsc::Sender<StreamElement>,
) -> Option<StreamEnd> {
    loop {
        let received = std::future::poll_fn(|context| exchange.poll_part(context)).await;
        let (searched, last) = match received {
            Some(Ok(bytes)) => (check.take(&bytes), false),
            Some(Err(_)) => return Some(cut(ProtocolError::ProviderUnreachable)),
            None => (check.end(), true),
        };
        let Ok(bytes) = searched else {
            // The body holds the credential: it is cut in front of it.
            return Some(cut(ProtocolError::from(Withheld)));
        };
        let mut rest = Bytes::from(bytes);
        while !rest.is_empty() {
            let part = rest.split_to(rest.len().min(frame::STREAM_PART_LIMIT_BYTES));
            let Some(prefix) = frame::stream_part_prefix(&part) else {
                return Some(cut(ProtocolError::Internal));
            };
            let prefix = StreamElement::Part(Bytes::copy_from_slice(&prefix));
            elements.send(prefix).await.ok()?;
            elements.send(StreamElement::Part(part)).await.ok()?;
        }
        if last {
            return Some(StreamEnd::complete());
        }
    }
}

/// The frame of a call, and the two shares of the body budget the call holds for it.
pub(super) struct Framed {
    /// The meta: a JSON object.
    pub meta: JsonBody,
    pub payload: Bytes,
    /// The share of the bytes of the frame, reserved for the declared length of the request
    /// before a byte of it was read. A call gives it back when its request is on the wire.
    pub frame_budget: OwnedSemaphorePermit,
    /// The share of the request (`Marks::request_share` of the meta): a bound of the parsed
    /// meta and of what the call makes of it. A call holds it to its end.
    pub request_share: OwnedSemaphorePermit,
}

/// Reads the frame of a call: its meta (a JSON object) and its payload. The frame is read
/// under a reservation of the body budget for the declared length of the request, and the
/// meta is parsed under the share of the request, which is computed from the bytes of the
/// meta ([`request_share_of`]). The call waits for both within the time of its admission.
pub(super) async fn read_frame(
    node: &Node,
    request: Request,
    admission: &Admission,
) -> Result<Framed, ApiError> {
    let frame_limit = 4 + META_LIMIT_BYTES + node.limits.body_bytes;
    let declared = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if declared.is_some_and(|length| length > frame_limit) {
        return Err(ProtocolError::TooLarge.into());
    }
    let frame_budget = admission
        .budget(node, declared.unwrap_or(frame_limit))
        .await?;
    let frame_bytes = Bytes::from(read_body(request, frame_limit).await?);
    let (meta_bytes, payload) = frame::split(&frame_bytes)?;
    drop(frame_bytes);
    let request_share = admission
        .budget(node, request_share_of(&meta_bytes)?)
        .await?;
    let meta = JsonBody::of_meta(&meta_bytes)?;
    drop(meta_bytes);
    if payload.len() > node.limits.body_bytes {
        return Err(ProtocolError::TooLarge.into());
    }
    Ok(Framed {
        meta,
        payload,
        frame_budget,
        request_share,
    })
}

async fn run(node: &Arc<Node>, request: Request) -> Result<Response, ApiError> {
    // At most 512 forward calls run at the same time. A further call waits for a slot, for
    // the time of its admission at the longest. The call holds its slot until its response
    // is made: for a frame that is the end of this function, for a stream the end of the
    // stream.
    let admission = Admission::begin();
    let slot = admission.slot(node).await?;

    // The request frame enters memory only after its share of the body budget is reserved,
    // and its meta is parsed under the share of the request, which the call holds to its
    // end: for a frame that is the end of this function, for a stream the end of the stream.
    let Framed {
        meta,
        payload,
        frame_budget: request_budget,
        request_share,
    } = read_frame(node, request, &admission).await?;
    let user_id = meta.user_id()?;
    let record = record_of(&meta, "record")?;
    let context = meta.context()?;
    // A stream may take as long as its caller takes to read it, so its time limit reaches
    // further than the time limit of a frame.
    let streamed = stream_of(&meta)?;
    let timeout_ms = match streamed {
        true => timeout_within(&meta, STREAM_TIMEOUT_MAX_MS)?,
        false => timeout_of(&meta)?,
    };
    // What a call holds beside its bodies grows with the length of its credential: the
    // search of the response, and the copies of the token its request carries. The call
    // takes that share of the body budget before anything of it is recorded or sent, within
    // the time of its admission. The credential is known once the record is open, under the
    // account lock, where a call does not wait. So the share is taken for the longest
    // credential a record of this size can hold (and a node handles: `longest_token`), and
    // what the credential does not need is given back when it is known. The search of a
    // response that is handed on as a stream lasts as long as the stream and holds a buffer
    // of received bytes as well: the share of such a call is the bound of that search.
    let share_of = |token_bytes: usize| match streamed {
        true => StreamCheck::memory_bound(token_bytes),
        false => credential_share(token_bytes, 1, 1),
    };
    let credential_budget = admission
        .budget(node, share_of(longest_token(&record)))
        .await?;

    // 1: the common front. Everything up to the event happens under the account lock, so a
    // revoke that is answered before this point leaves no request behind it.
    node.ensure_open()?;
    node.operator_config()?;
    let account = node.account(user_id).ok_or(ProtocolError::GrantRequired)?;
    log_store::admit(node, &account).await?;
    let (prepared, place) = {
        let mut account = lock(&account);
        node.ensure_open()?;
        let now_ms = node.now_ms();
        let grant = account.active(now_ms)?;
        // The record is an `oauth` record: a vault record is `not_allowed` here.
        let opened = oauth::open_record(&grant, user_id, &record)?;
        let parsed = usable(opened.parse())?;
        let definition = node
            .definitions
            .get(&record.provider)
            .ok_or(ProtocolError::ProviderUnknown)?;
        let prepared = prepare(
            meta.as_value(),
            &payload,
            &record,
            definition,
            parsed.as_ref().map_err(|unusable| *unusable),
            context,
        )?;
        // 5, 6: the merge decision and the event. `place` is where the event of this request
        // is: its own, or the one it shares.
        let place = node
            .create_events(
                &mut account,
                user_id,
                &grant.key_id,
                &grant.log_pk,
                now_ms,
                vec![(prepared.merge_key, prepared.event.clone())],
            )?
            .pop()
            .ok_or_else(ApiError::internal)?;
        (prepared, place)
    };
    drop(payload);
    // The call holds no more than the share of this credential.
    let credential_budget = narrowed(credential_budget, share_of(prepared.token_bytes));

    // 5, 6: the request leaves only after the log store confirmed the entry that holds its
    // event (the group commit of protocol.md 7.1).
    let log = log_store::commit(node, user_id, &account, &[place])
        .await?
        .into_iter()
        .next()
        .ok_or_else(ApiError::internal)?;

    // A record above what a node reads: the entry of the call is confirmed, and the call ends
    // here. Nothing is sent.
    let Some((outbound, token)) = prepared.request else {
        return Err(above_bounds());
    };

    // 8, 9: the provider call runs outside the account lock, within the time limit. The
    // reservation of the request frame goes with it and is free once the request is on the
    // wire (`execute`).
    let timeout = Duration::from_millis(timeout_ms);
    if streamed {
        let held = (slot, credential_budget, request_share);
        return stream(
            node,
            user_id,
            outbound,
            token,
            timeout,
            log,
            request_budget,
            held,
        )
        .await;
    }
    // The share of the credential goes with the call into the check of the response and is
    // free when that check has ended.
    let (checked, budget) = execute(
        node,
        user_id,
        outbound,
        token,
        timeout,
        Some(request_budget),
        search_turns(credential_budget),
    )
    .await?;
    drop(slot);
    drop(request_share);
    Ok(forward_frame(checked, Some(log), budget))
}
