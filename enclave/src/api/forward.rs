//! `POST /v1/forward` (enclave.md 5.8): sends a provider request with the credential of a
//! record injected. The functions `prepare` and `execute` are shared with `POST
//! /v1/forward/batch` (`super::forward_batch`).
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
use tokio::sync::OwnedSemaphorePermit;

use super::responses::forward_frame;
use super::{invalid, read_body, record_of, respond, ApiError, JsonBody};
use crate::egress::{self, EgressError, OutboundBody, OutboundHeader, OutboundRequest};
use crate::frame::{self, META_LIMIT_BYTES};
use crate::log_store;
use crate::oauth::{self, Withheld};
use crate::provider_response::{self, CheckedResponse};
use crate::providers::Definition;
use crate::state::{events, lock, merge_key, Node};

/// The methods `forward` sends.
const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/// Caller headers the node drops: the credential header is the node's, `Accept-Encoding` is
/// set by the node, and the rest describe the connection or the body framing.
const DROPPED_HEADERS: [&str; 13] = [
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

pub async fn forward(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
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
    match meta.get("timeout_ms") {
        None => Ok(TIMEOUT_DEFAULT_MS),
        Some(value) => value
            .as_u64()
            .filter(|timeout| (TIMEOUT_MIN_MS..=TIMEOUT_MAX_MS).contains(timeout))
            .ok_or_else(|| invalid("timeout_ms")),
    }
}

/// Reads the request headers of a request object: an array of `[name, value]` pairs under
/// `headers`. A name that is not a token and a value with CR, LF or another control
/// character are `invalid_request`. A header of [`REFUSED_HEADERS`] is `not_allowed`. The
/// headers of [`DROPPED_HEADERS`] and the header the definition injects are dropped.
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
        let lower = name.to_ascii_lowercase();
        if REFUSED_HEADERS.contains(&lower.as_str()) {
            return Err(ProtocolError::NotAllowed.into());
        }
        if DROPPED_HEADERS.contains(&lower.as_str())
            || definition
                .inject
                .iter()
                .any(|rule| lower == rule.header.to_ascii_lowercase())
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
        Ok(Err(EgressError::TooLarge)) => return Err(ProtocolError::TooLarge),
        Ok(Err(EgressError::Invalid)) => return Err(ProtocolError::NotAllowed),
        Ok(Err(EgressError::Unreachable)) => return Err(ProtocolError::ProviderUnreachable),
        // Rule E4: a body under a transfer coding the node does not remove is not handed on.
        Ok(Err(EgressError::Coded)) => return Err(ProtocolError::from(Withheld)),
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

/// The frame of a call: its meta (a JSON object) and its payload, read under a reservation of
/// the body budget for the declared length of the request.
pub(super) async fn read_frame(
    node: &Node,
    request: Request,
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
    let request_budget = reserve(node, declared.unwrap_or(frame_limit)).await?;
    let frame_bytes = Bytes::from(read_body(request, frame_limit).await?);
    let (meta, payload) = frame::decode(&frame_bytes)?;
    drop(frame_bytes);
    if payload.len() > node.limits.body_bytes {
        return Err(ProtocolError::TooLarge.into());
    }
    Ok((JsonBody::from_value(meta)?, payload, request_budget))
}

async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
    // At most 512 forward calls run at the same time. A further call waits for a slot.
    let _slot = node
        .forward_slots
        .acquire()
        .await
        .map_err(|_| ApiError::internal())?;

    // The request frame enters memory only after its share of the body budget is reserved.
    let (meta, payload, request_budget) = read_frame(node, request).await?;
    let user_id = meta.user_id()?;
    let record = record_of(&meta, "record")?;
    let context = meta.context()?;
    let timeout_ms = timeout_of(&meta)?;

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
    let Prepared {
        outbound, token, ..
    } = prepared;
    let (checked, budget) = execute(
        node,
        user_id,
        outbound,
        token,
        Duration::from_millis(timeout_ms),
        Some(request_budget),
    )
    .await?;
    Ok(forward_frame(checked, Some(log), budget))
}
