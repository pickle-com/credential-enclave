//! `POST /v1/vault/send` (enclave.md 5.16): a node of the forward role sends the one request
//! of a secret use, with the value at its place, and hands the response on while it arrives.
//!
//! The node holds no user key and opens no record. What reaches it is an envelope that a node
//! of the delegation role sealed to its sealing key (`vault/handoff`, enclave.md 5.9c) after
//! the log store confirmed the entry that holds the event `provider_request` of that use: the
//! value, and the request the value is for. This call sends that request and no other one:
//!
//! - the method, the host, the path and the query are those of the envelope: the caller does
//!   not state them again;
//! - the body of the caller is the body the envelope names, by its length and its hash;
//! - the value goes to the slot of the envelope, where the request of the caller has the
//!   placeholder, and the placeholder stands nowhere else (`crate::bound`);
//! - the envelope is used within its 30 seconds, and once: its number is marked before the
//!   request leaves, at a node time before the end of the envelope, and a marked number
//!   sends nothing;
//! - a node that is closing (`close`, enclave.md 5.11) begins no request: the call ends with
//!   `closing` before the node reads its frame, and its envelope stays unused. A call the node
//!   took before runs to the end of its response.
//!
//! The request goes to port 443 of the host, over TLS that ends inside the node, with a
//! certificate verified for that host against the trust roots of the binary, on a connection
//! that carries this one request. The response passes rule E4 of the egress policy before any
//! part of it is handed on: the head as a whole, the body part by part
//! (`crate::provider_response::StreamCheck`, the search of the stream form of `forward`).
//! The response is a stream of the form of that call (`crate::frame`).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::secret_use::{open_secret_use, SecretUseEnvelope};
use credential_enclave_protocol::{limits, ProtocolError};

use super::forward::{hand_on_body, read_frame, Admission};
use super::responses::send_stream;
use super::{invalid, respond, ApiError, JsonBody};
use crate::bound;
use crate::egress::EgressError;
use crate::oauth::Withheld;
use crate::provider_response::StreamCheck;
use crate::role::{NonceRefusal, UsedNonces};
use crate::state::{lock, Node};

/// `bad_expiry` for an envelope that is not within its time.
fn out_of_time() -> ApiError {
    ApiError::with_message(
        ProtocolError::BadExpiry,
        "the envelope is not within its time",
    )
}

const TIMEOUT_DEFAULT_MS: u64 = 30_000;
const TIMEOUT_MIN_MS: u64 = 1_000;
/// The longest time limit of one request: the time from the moment the request leaves to the
/// end of its response body.
const TIMEOUT_MAX_MS: u64 = 600_000;

pub async fn send(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// The `timeout_ms` of the call: 1,000 to 600,000, 30,000 when absent.
fn timeout_of(meta: &JsonBody) -> Result<u64, ApiError> {
    match meta.get("timeout_ms") {
        None => Ok(TIMEOUT_DEFAULT_MS),
        Some(value) => value
            .as_u64()
            .filter(|timeout| (TIMEOUT_MIN_MS..=TIMEOUT_MAX_MS).contains(timeout))
            .ok_or_else(|| invalid("timeout_ms")),
    }
}

async fn run(node: &Arc<Node>, request: Request) -> Result<Response, ApiError> {
    // A request holds one of the places of the forward calls of the node until its response
    // has ended. A further call waits for a place, and for the shares of the body budget it
    // takes below, for the time of its admission at the longest (enclave.md section 8).
    let admission = Admission::begin();
    let slot = admission.slot(node).await?;
    // A closing node begins no request. The call holds its place before it reads the flag:
    // whoever closes the node and then finds no place held knows that no call that read the
    // flag before the close is still on its way to a request.
    node.ensure_open()?;

    // The request frame enters memory only after its share of the body budget is reserved.
    let (meta, payload, request_budget) = read_frame(node, request, &admission).await?;
    let envelope = SecretUseEnvelope::from_value(meta.object("envelope")?)?;
    let timeout = Duration::from_millis(timeout_of(&meta)?);

    // The envelope: sealed to this node, signed by the node it names, and of this time. An
    // envelope whose end lies further ahead than twice the life of an envelope was not made
    // by a node whose clock is near the clock of this one. The check is made again where the
    // number is marked: this one refuses an envelope before its body is read through.
    let secret_use = open_secret_use(&node.keys, &envelope)?;
    let ahead_ms = secret_use.not_after_ms().saturating_sub(node.now_ms());
    if ahead_ms == 0 || ahead_ms > UsedNonces::KEPT_MS {
        return Err(out_of_time());
    }

    // The search of the response holds back the last bytes of the body, as many as the
    // longest form of the value can take, and a value has up to 12,000 bytes. The call takes
    // the share of the body budget that search can hold before its request leaves.
    let check_budget = admission
        .budget(node, StreamCheck::memory_bound(secret_use.value_bytes()))
        .await?;

    // The request of the caller is the request of the envelope, and the value goes to its
    // slot. A request that fails here leaves the envelope unused. The check reads the whole
    // body (its hash, the search for the placeholder), so it runs off the threads that serve
    // the calls.
    let (secret_use, bound) = tokio::task::spawn_blocking(move || {
        let bound = bound::prepare(&secret_use, meta.get("headers"), &payload);
        (secret_use, bound)
    })
    .await
    .map_err(|_| ApiError::internal())?;
    let bound = bound?;

    // One envelope, one request: the number is marked before the request leaves, also when
    // the request then fails. The end of the envelope is judged by the clock reading the
    // number is marked with, inside the lock of the marks: a call that took long to come here
    // does not mark a number the node has dropped since.
    let marked = {
        let mut used = lock(&node.used_nonces);
        used.mark(
            *secret_use.nonce(),
            secret_use.not_after_ms(),
            node.now_ms(),
        )
    };
    match marked {
        Ok(()) => {}
        Err(NonceRefusal::OutOfTime) => return Err(out_of_time()),
        Err(NonceRefusal::Used) => {
            return Err(ApiError::with_message(
                ProtocolError::BadChallenge,
                "the envelope was used before",
            ))
        }
        Err(NonceRefusal::Full) => return Err(ProtocolError::CapacityUnavailable.into()),
    }

    let deadline = tokio::time::Instant::now() + timeout;
    let sent = node
        .egress
        .send_to_bound_host(node.platform.as_ref(), bound, timeout);
    let mut exchange = match tokio::time::timeout_at(deadline, sent).await {
        Err(_) => return Err(ProtocolError::Timeout.into()),
        Ok(Err(EgressError::Invalid)) => return Err(ProtocolError::InvalidRequest.into()),
        Ok(Err(EgressError::Unreachable | EgressError::TooLarge)) => {
            return Err(ProtocolError::ProviderUnreachable.into())
        }
        // Rule E4: a body under a coding the node does not remove is not handed on.
        Ok(Err(EgressError::Coded)) => return Err(ProtocolError::from(Withheld).into()),
        Ok(Ok(exchange)) => exchange,
    };

    // Rule E4 for the head: a response under a content coding, or with the value in a header,
    // is not handed on. The body is searched part by part as it is handed on, by the task of
    // the stream, which ends at the time limit of the call whatever its caller reads.
    let status = exchange.status;
    let mut headers = std::mem::take(&mut exchange.headers);
    let check =
        StreamCheck::begin(secret_use.value(), &mut headers).map_err(ProtocolError::from)?;
    drop(secret_use);
    // The share of the body budget the request body occupies is held to the end of the
    // response: a host may answer before it read the body, and the body is in memory until
    // the connection ends.
    let held = (slot, request_budget, check_budget);
    let (body, late) = hand_on_body(exchange, check, deadline, held);
    Ok(send_stream(status, headers, body, late))
}

/// The longest envelope a request meta can carry stays far below the limit of a frame meta:
/// a value of at most 12,000 bytes and an address of at most 16,384, each under two layers of
/// base64url.
const _: () = assert!(
    (limits::SECRET_USE_VALUE_BYTES_MAX + 2 * limits::EVENT_ADDRESS_BYTES) * 2
        < crate::frame::META_LIMIT_BYTES
);
