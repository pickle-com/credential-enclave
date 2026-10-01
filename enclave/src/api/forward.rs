//! `POST /v1/forward` (enclave.md 5.8): sends a provider request with the credential of a
//! record injected.
//!
//! The credential reaches an address of the provider definition only (enclave.md section 7).
//! The entry `provider_request` is on the chain, and the log store confirmed it, before the
//! request leaves the node. The node does not judge token expiry and does not refresh: the
//! provider response, a 401 included, goes back as it is, after the checks of rule E4 of the
//! egress policy (`crate::provider_response`).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::header::CONTENT_LENGTH;
use axum::http::HeaderValue;
use axum::response::Response;
use credential_enclave_protocol::{limits, ProtocolError};
use hyper::body::Bytes;
use tokio::sync::OwnedSemaphorePermit;

use super::responses::forward_frame;
use super::{invalid, read_body, record_of, respond, ApiError, JsonBody};
use crate::egress::{self, EgressError, OutboundBody, OutboundHeader, OutboundRequest};
use crate::frame::{self, META_LIMIT_BYTES};
use crate::log_store;
use crate::oauth;
use crate::provider_response;
use crate::providers::Definition;
use crate::state::{events, lock, merge_key, Node, Recent};

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

const TIMEOUT_DEFAULT_MS: u64 = 30_000;
const TIMEOUT_MIN_MS: u64 = 1_000;
const TIMEOUT_MAX_MS: u64 = 120_000;

pub async fn forward(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

async fn reserve(node: &Node, bytes: usize) -> Result<OwnedSemaphorePermit, ApiError> {
    let permits = u32::try_from(bytes).map_err(|_| ApiError::from(ProtocolError::TooLarge))?;
    node.body_budget
        .clone()
        .acquire_many_owned(permits)
        .await
        .map_err(|_| ApiError::internal())
}

/// Reads the request headers of the meta: an array of `[name, value]` pairs. A name that is
/// not a token and a value with CR, LF or another control character are `invalid_request`.
/// A header of [`REFUSED_HEADERS`] is `not_allowed`. The headers of [`DROPPED_HEADERS`] and
/// the header the definition injects are dropped.
fn caller_headers(
    meta: &JsonBody,
    definition: &Definition,
) -> Result<Vec<OutboundHeader>, ApiError> {
    let Some(value) = meta.get("headers") else {
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
            || lower == definition.inject.header.to_ascii_lowercase()
        {
            continue;
        }
        headers.push(OutboundHeader::plain(name, value));
    }
    Ok(headers)
}

async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
    // At most 64 forward calls run at the same time. A further call waits for a slot.
    let _slot = node
        .forward_slots
        .acquire()
        .await
        .map_err(|_| ApiError::internal())?;

    // The request frame enters memory only after its share of the body budget is reserved.
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
    let meta = JsonBody::from_value(meta)?;
    let user_id = meta.user_id()?;
    let record = record_of(&meta, "record")?;
    let method = meta.text("method")?;
    let address = meta.text("url")?;
    let context = meta.context()?;
    let timeout_ms = match meta.get("timeout_ms") {
        None => TIMEOUT_DEFAULT_MS,
        Some(value) => value
            .as_u64()
            .filter(|timeout| (TIMEOUT_MIN_MS..=TIMEOUT_MAX_MS).contains(timeout))
            .ok_or_else(|| invalid("timeout_ms"))?,
    };

    // 1: the common front. Everything up to the entry happens under the account lock, so a
    // revoke that is answered before this point leaves no request behind it.
    node.ensure_open()?;
    node.operator_config()?;
    let account = node.account(user_id).ok_or(ProtocolError::GrantRequired)?;
    log_store::admit(node, user_id, &account).await?;
    let (outbound, token, entry, seq) = {
        let mut account = lock(&account);
        node.ensure_open()?;
        let now_ms = node.now_ms();
        let grant = account.active(now_ms)?;
        account.ensure_capacity()?;
        // The record is an `oauth` record: a vault record is `not_allowed` here.
        let opened = oauth::open_record(&grant, user_id, &record)?;
        let definition = node
            .definitions
            .get(&record.provider)
            .ok_or(ProtocolError::ProviderUnknown)?;
        // 2
        let target = definition.check_address(address)?;
        // 3
        if !METHODS.contains(&method) {
            return Err(ProtocolError::NotAllowed.into());
        }
        // 4: the credential header, then `Accept-Encoding: identity` (the node searches the
        // response and does not decode it), then the headers of the caller.
        let (header_value, token) = opened
            .parse()?
            .credential(definition)
            .ok_or(ProtocolError::RecordInvalid)?
            .into_parts();
        let mut headers = vec![
            OutboundHeader::secret(&definition.inject.header, header_value),
            OutboundHeader::plain("accept-encoding", "identity"),
        ];
        headers.extend(caller_headers(&meta, definition)?);
        let outbound = OutboundRequest::new(
            target.destination(),
            method,
            headers,
            OutboundBody::Plain(payload.clone()),
        );
        if egress::check(&outbound).is_err() {
            return Err(ProtocolError::NotAllowed.into());
        }
        // 5: an identical GET of the same record within 300 seconds shares the entry that is
        // already on the chain. A GET with a body always gets its own entry, which carries the
        // size and the hash of that body: the merge key holds the address only. `seq` is the
        // entry the request waits for: its own, or the one it shares.
        let window_ms = limits::MERGE_WINDOW_S * 1000;
        account
            .recent
            .retain(|_, recent| now_ms < recent.entry_ms.saturating_add(window_ms));
        let mergeable = method == "GET" && payload.is_empty();
        let key = merge_key(
            &record.id_bytes()?,
            target.host(),
            target.path(),
            target.query(),
        );
        let shared = account.recent.get(&key).copied().filter(|_| mergeable);
        let (entry, seq) = if let Some(shared) = shared {
            (None, shared.seq)
        } else {
            // 6
            let event = events::provider_request(
                &record.id,
                &record.provider,
                method,
                target.host(),
                target.path(),
                target.query(),
                &payload,
                context,
                mergeable,
            );
            let entry = node.append_entry(
                &mut account,
                user_id,
                &grant.key_id,
                &grant.log_pk,
                now_ms,
                &event,
            )?;
            let seq = account.head.seq;
            if mergeable {
                account.recent.insert(
                    key,
                    Recent {
                        entry_ms: now_ms,
                        seq,
                    },
                );
            }
            (Some(entry), seq)
        };
        (outbound, token, entry, seq)
    };
    drop(payload);

    // 5, 6: the request leaves only after the log store confirmed its entry. For a request
    // that shares an entry, the store confirmed that entry before, or it is written again
    // here.
    log_store::confirm(node, user_id, &account, &[seq]).await?;

    // 8, 9: the provider call runs outside the account lock, within the time limit.
    let body_limit = node.limits.body_bytes;
    let call = async {
        let exchange = node
            .egress
            .send_to_provider(node.platform.as_ref(), outbound)
            .await?;
        // The request body was sent: its share of the budget is free before the response body
        // asks for its own, so two calls never wait for each other.
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
    let (status, headers, body, budget) =
        match tokio::time::timeout(Duration::from_millis(timeout_ms), call).await {
            Err(_) => return Err(ProtocolError::Timeout.into()),
            Ok(Err(EgressError::TooLarge)) => return Err(ProtocolError::TooLarge.into()),
            Ok(Err(EgressError::Invalid)) => return Err(ProtocolError::NotAllowed.into()),
            Ok(Err(EgressError::Unreachable)) => {
                return Err(ProtocolError::ProviderUnreachable.into())
            }
            // Rule E4: a body under a transfer coding the node does not remove is not handed
            // on.
            Ok(Err(EgressError::Coded)) => return Err(oauth::Withheld.into()),
            Ok(Ok(outcome)) => outcome,
        };

    // Rule E4: a response that holds the injected credential, or a body the node cannot
    // search, is not handed on. The entry of the request is already on the chain. The search
    // reads the whole body, so it runs off the threads that serve the calls.
    let checked = tokio::task::spawn_blocking(move || {
        provider_response::check(&token, status, headers, body)
    })
    .await
    .map_err(|_| ApiError::internal())??;
    Ok(forward_frame(checked, entry, budget))
}
