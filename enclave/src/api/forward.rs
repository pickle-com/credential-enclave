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
use credential_enclave_protocol::ProtocolError;
use hyper::body::Bytes;
use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, SemaphorePermit};

use super::responses::{forward_frame, forward_stream, LogRef, StreamElement, StreamEnd};
use super::{invalid, read_body, record_of, respond, ApiError, JsonBody};
use crate::egress::{self, EgressError, Exchange, OutboundBody, OutboundHeader, OutboundRequest};
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
/// Longest time a `forward` or `forward/batch` call waits to be admitted: for one of the places
/// of the forward calls of the node and for the share of the body budget its request frame
/// occupies (enclave.md section 8).
#[cfg(not(test))]
pub(crate) const ADMISSION_WAIT: Duration = Duration::from_secs(30);
/// The tests of the node wait for a shorter time: a test that holds every place does not
/// take 30 seconds.
#[cfg(test)]
pub(crate) const ADMISSION_WAIT: Duration = Duration::from_millis(400);
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

/// One of the places of the forward calls of the node, held by a call whose response is a
/// stream until the task that reads the provider ends. Dropping it frees the place.
struct StreamPlace(Arc<Node>);

impl StreamPlace {
    /// Keeps the place `slot` of a call of `node` for as long as the value lives.
    fn keep(node: &Arc<Node>, slot: SemaphorePermit<'_>) -> StreamPlace {
        slot.forget();
        StreamPlace(node.clone())
    }
}

impl Drop for StreamPlace {
    fn drop(&mut self) {
        self.0.forward_slots.add_permits(1);
    }
}

/// The admission of a call that takes one of the places of the forward calls of the node
/// (`forward`, `forward/batch`): its place, and the share of the body budget its request frame
/// occupies. A call waits for the two together for at most [`ADMISSION_WAIT`], counted from
/// the moment it began, and ends with `capacity_unavailable` when it has not got them by then.
/// It has read nothing of its frame at that point: the frame enters memory only under its
/// share of the budget.
///
/// The limit is what bounds the time a connection is held by a call that does nothing yet.
/// The node reads nothing from the connection of a call that waits, so it does not learn
/// that the caller of such a call is gone (enclave.md section 8).
pub(super) struct Admission {
    until: tokio::time::Instant,
}

impl Admission {
    /// The admission of a call that begins now.
    pub(super) fn begin() -> Admission {
        Admission {
            until: tokio::time::Instant::now() + ADMISSION_WAIT,
        }
    }

    /// One of the places of the forward calls of the node, held until it is dropped.
    pub(super) async fn slot<'a>(&self, node: &'a Node) -> Result<SemaphorePermit<'a>, ApiError> {
        let slot = node.forward_slots.acquire();
        match tokio::time::timeout_at(self.until, slot).await {
            Ok(Ok(slot)) => Ok(slot),
            Ok(Err(_)) => Err(ApiError::internal()),
            Err(_) => Err(ProtocolError::CapacityUnavailable.into()),
        }
    }

    /// `bytes` of the body budget of the node, for the request frame of the call.
    async fn budget(&self, node: &Node, bytes: usize) -> Result<OwnedSemaphorePermit, ApiError> {
        match tokio::time::timeout_at(self.until, reserve(node, bytes)).await {
            Ok(reserved) => reserved,
            Err(_) => Err(ProtocolError::CapacityUnavailable.into()),
        }
    }
}

/// Takes `bytes` of the body budget of the node, waiting for them.
pub(super) async fn reserve(node: &Node, bytes: usize) -> Result<OwnedSemaphorePermit, ApiError> {
    let permits = u32::try_from(bytes).map_err(|_| ApiError::from(ProtocolError::TooLarge))?;
    node.body_budget
        .clone()
        .acquire_many_owned(permits)
        .await
        .map_err(|_| ApiError::internal())
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

/// The form a header name is compared in: lower case, with `-` for every `_`. Some servers
/// read the two characters as one, so `X_HTTP_Method_Override` is the header that overrides
/// the method for them, and `Content_Length` a second length of the body.
fn header_key(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

/// True when the value of an `Accept` header names no character encoding but UTF-8: every
/// place of the word `charset` in it (in any case of its letters) is followed by `=` and
/// `utf-8` or `utf8`, with or without quotes and blanks.
fn names_no_other_charset(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    let mut rest = value.as_str();
    while let Some(at) = rest.find("charset") {
        let after = rest.get(at + "charset".len()..).unwrap_or_default();
        let named = after
            .trim_start()
            .strip_prefix('=')
            .map(|named| named.trim_start().trim_start_matches('"'));
        let utf8 = named.and_then(|named| {
            named
                .strip_prefix("utf-8")
                .or_else(|| named.strip_prefix("utf8"))
        });
        match utf8 {
            // The name ends there: `utf-80` is another name.
            Some(end)
                if !end.starts_with(|next: char| next.is_ascii_alphanumeric() || next == '-') => {}
            _ => return false,
        }
        rest = after;
    }
    true
}

/// Reads the request headers of a request object: an array of `[name, value]` pairs under
/// `headers`. A name that is not a token and a value with CR, LF or another control
/// character are `invalid_request`. A header of [`REFUSED_HEADERS`] is `not_allowed`, and
/// so is an `Accept` header that names another character encoding than UTF-8. The headers
/// of [`DROPPED_HEADERS`] and the header the definition injects are dropped. A name is
/// compared in the form of [`header_key`].
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
/// credential injected, the token to search the response for (rule E4), the merge key of a GET
/// without a body, and the event `provider_request` of the request.
pub(super) struct Prepared {
    pub outbound: OutboundRequest,
    pub token: Secret<String>,
    pub merge_key: Option<[u8; 32]>,
    pub event: Value,
}

/// Steps 2 to 4 of enclave.md 5.8 for one request object (`method`, `url`, `headers`) with
/// its body: the address check of the definition, the method, the credential header of the
/// rule of the host, `Accept-Encoding: identity`, the headers of the caller, and the check
/// that the request can be expressed in HTTP/1.1. `parsed` is the parsed plaintext of the
/// record the credential comes from.
pub(super) fn prepare(
    request: &Value,
    payload: &Bytes,
    record: &Record,
    definition: &Definition,
    parsed: &oauth::OauthPlaintext,
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
    let (header_value, token) = parsed
        .credential(rule)
        .ok_or(ProtocolError::RecordInvalid)?
        .into_parts();
    let mut headers = vec![
        OutboundHeader::secret(&rule.header, header_value),
        OutboundHeader::plain("accept-encoding", "identity"),
    ];
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
        outbound,
        token,
        merge_key,
        event,
    })
}

/// Steps 8 and 9 of enclave.md 5.8 and rule E4 for one prepared request, within `timeout`:
/// the provider call over the connections of the account, the body under the budget of the
/// node, and the check of the response for the injected credential. `request_budget` is the
/// share of the budget the request body occupies: it is free as soon as the request is on the
/// wire, before the response body asks for its own share, so two calls never wait for each
/// other. The returned permit holds the share the response body occupies.
pub(super) async fn execute(
    node: &Node,
    user_id: &str,
    outbound: OutboundRequest,
    token: Secret<String>,
    timeout: Duration,
    request_budget: Option<OwnedSemaphorePermit>,
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
    // Rule E4: a response that holds the injected credential, or a body the node cannot
    // search, is not handed on. The entry of the request is already on the chain. The search
    // reads the whole body, so it runs off the threads that serve the calls.
    let checked = tokio::task::spawn_blocking(move || {
        provider_response::check(&token, status, headers, body)
    })
    .await
    .map_err(|_| ProtocolError::Internal)?
    .map_err(ProtocolError::from)?;
    Ok((checked, budget))
}

/// The end record of a body that was cut with the failure `error`.
fn cut(error: ProtocolError) -> StreamEnd {
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
/// once the request is on the wire. The body of the provider takes no share: the node holds
/// the bytes it has not handed on yet, a bounded number (`StreamCheck`). `place` is the place
/// of the call among the forward calls of the node: it is free when the body has ended, was
/// cut, the time limit passed or the caller is gone, whichever comes first.
async fn stream(
    node: &Arc<Node>,
    user_id: &str,
    prepared: Prepared,
    timeout: Duration,
    log: LogRef,
    request_budget: OwnedSemaphorePermit,
    place: StreamPlace,
) -> Result<Response, ApiError> {
    let Prepared {
        outbound, token, ..
    } = prepared;
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
    let (elements, body) = tokio::sync::mpsc::channel(STREAM_ELEMENTS);
    tokio::spawn(hand_on_until(exchange, check, elements, deadline, place));
    Ok(forward_stream(
        status,
        headers,
        Some(log),
        body,
        cut(ProtocolError::Timeout),
    ))
}

/// The task of a stream: hands the body of the provider on until it ends, is cut, the time
/// limit of the call passes or the caller is gone, and then frees what the call held (the
/// connection to the provider, the place among the forward calls) before the end record waits
/// for the caller. The task does not depend on the caller reading the response: a caller that
/// reads slowly, or not at all, holds the call for the time limit at the longest.
async fn hand_on_until(
    mut exchange: Exchange,
    mut check: StreamCheck,
    elements: tokio::sync::mpsc::Sender<StreamElement>,
    deadline: tokio::time::Instant,
    place: StreamPlace,
) {
    let end = tokio::select! {
        end = tokio::time::timeout_at(deadline, hand_on(&mut exchange, &mut check, &elements)) => end,
        // The response body was dropped: the connection of the caller ended.
        _ = elements.closed() => Ok(None),
    };
    drop(exchange);
    drop(check);
    drop(place);
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

/// The frame of a call: its meta (a JSON object) and its payload, read under a reservation of
/// the body budget for the declared length of the request. The call waits for that
/// reservation within the time of its admission.
pub(super) async fn read_frame(
    node: &Node,
    request: Request,
    admission: &Admission,
) -> Result<(JsonBody, Bytes, OwnedSemaphorePermit), ApiError> {
    let frame_limit = 4 + META_LIMIT_BYTES + node.limits.body_bytes;
    let declared = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if declared.is_some_and(|length| length > frame_limit) {
        return Err(ProtocolError::TooLarge.into());
    }
    let request_budget = admission
        .budget(node, declared.unwrap_or(frame_limit))
        .await?;
    let frame_bytes = Bytes::from(read_body(request, frame_limit).await?);
    let (meta, payload) = frame::decode(&frame_bytes)?;
    drop(frame_bytes);
    if payload.len() > node.limits.body_bytes {
        return Err(ProtocolError::TooLarge.into());
    }
    Ok((JsonBody::from_value(meta)?, payload, request_budget))
}

async fn run(node: &Arc<Node>, request: Request) -> Result<Response, ApiError> {
    // At most 512 forward calls run at the same time. A further call waits for a slot, for
    // the time of its admission at the longest. The call holds its slot until its response
    // is made: for a frame that is the end of this function, for a stream the end of the
    // stream.
    let admission = Admission::begin();
    let slot = admission.slot(node).await?;

    // The request frame enters memory only after its share of the body budget is reserved.
    let (meta, payload, request_budget) = read_frame(node, request, &admission).await?;
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
        let parsed = opened.parse()?;
        let definition = node
            .definitions
            .get(&record.provider)
            .ok_or(ProtocolError::ProviderUnknown)?;
        let prepared = prepare(
            meta.as_value(),
            &payload,
            &record,
            definition,
            &parsed,
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

    // 5, 6: the request leaves only after the log store confirmed the entry that holds its
    // event (the group commit of protocol.md 7.1).
    let log = log_store::commit(node, user_id, &account, &[place])
        .await?
        .into_iter()
        .next()
        .ok_or_else(ApiError::internal)?;

    // 8, 9: the provider call runs outside the account lock, within the time limit. The
    // reservation of the request frame goes with it and is free once the request is on the
    // wire (`execute`).
    let timeout = Duration::from_millis(timeout_ms);
    if streamed {
        let place = StreamPlace::keep(node, slot);
        return stream(node, user_id, prepared, timeout, log, request_budget, place).await;
    }
    let Prepared {
        outbound, token, ..
    } = prepared;
    let (checked, budget) = execute(
        node,
        user_id,
        outbound,
        token,
        timeout,
        Some(request_budget),
    )
    .await?;
    drop(slot);
    Ok(forward_frame(checked, Some(log), budget))
}
