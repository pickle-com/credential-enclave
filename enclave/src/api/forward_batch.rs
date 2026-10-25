//! `POST /v1/forward/batch` (enclave.md 5.8b): sends one to 100 provider requests of one
//! record with the credential of the record injected, after one entry names them all.
//!
//! The frame is the frame of `forward`. Its meta holds `requests`, an array of request
//! objects (`method`, `url`, `headers`, `body_bytes`), and its payload is the bodies of the
//! requests one after another. Every request passes the checks of `forward` before any event
//! is created; the events go into the open batch of the account in one step; the requests
//! leave only after the log store confirmed every entry that holds one of them; and they
//! leave over the idle connections of the account, at most
//! [`limits::FORWARD_BATCH_CONCURRENCY`] at a time. The response frame lists one result per
//! request, in the order of the requests.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::{limits, ProtocolError};
use hyper::body::Bytes;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::forward::{execute, prepare, read_frame, timeout_of, Prepared};
use super::responses::{forward_batch_frame, BatchResult, LogRef};
use super::{record_of, respond, ApiError};
use crate::log_store::{self, join_all};
use crate::oauth;
use crate::state::{lock, Node};

pub async fn forward_batch(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// The failure of a call for one request of the batch: the code and the index of the request
/// in `requests`.
fn refused(error: ApiError, index: usize) -> ApiError {
    ApiError::indexed(error, index)
}

/// Splits the payload into the bodies the request objects declare with `body_bytes`. The sum
/// of the lengths must be the length of the payload.
fn split_bodies(requests: &[serde_json::Value], payload: &Bytes) -> Result<Vec<Bytes>, ApiError> {
    let mut bodies = Vec::with_capacity(requests.len());
    let mut at = 0usize;
    for (index, request) in requests.iter().enumerate() {
        let length = match request.get("body_bytes") {
            None => 0,
            Some(value) => value
                .as_u64()
                .and_then(|length| usize::try_from(length).ok())
                .ok_or_else(|| refused(super::invalid("body_bytes"), index))?,
        };
        // The end is computed without overflow: a declared length near the limit of the
        // integer is invalid like any other that goes past the payload.
        let end = at
            .checked_add(length)
            .filter(|end| *end <= payload.len())
            .ok_or_else(|| super::invalid("body_bytes"))?;
        bodies.push(payload.slice(at..end));
        at = end;
    }
    if at != payload.len() {
        return Err(super::invalid("body_bytes"));
    }
    Ok(bodies)
}

async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
    // A batch call takes one forward slot: the slots count calls, not requests.
    let _slot = node
        .forward_slots
        .acquire()
        .await
        .map_err(|_| ApiError::internal())?;
    let (meta, payload, request_budget) = read_frame(node, request).await?;
    let user_id = meta.user_id()?;
    let record = record_of(&meta, "record")?;
    let context = meta.context()?;
    let timeout_ms = timeout_of(&meta)?;
    let requests = meta
        .get("requests")
        .and_then(serde_json::Value::as_array)
        .filter(|requests| (1..=limits::FORWARD_BATCH_REQUESTS).contains(&requests.len()))
        .ok_or_else(|| super::invalid("requests"))?
        .clone();
    let bodies = split_bodies(&requests, &payload)?;
    drop(payload);
    // Every request takes the share of the frame reservation its body occupies and gives it
    // back once it is on the wire (`execute`): the frame is not held while the responses are
    // read, so two calls never wait for each other. The rest of the reservation (the meta) is
    // free now.
    let mut request_budget = request_budget;
    let shares: Vec<Option<OwnedSemaphorePermit>> = bodies
        .iter()
        .map(|body| request_budget.split(body.len()))
        .collect();
    drop(request_budget);

    // 1: the common front, once for the call.
    node.ensure_open()?;
    node.operator_config()?;
    let account = node.account(user_id).ok_or(ProtocolError::GrantRequired)?;
    log_store::admit(node, &account).await?;
    let (prepared, places) = {
        let mut account = lock(&account);
        node.ensure_open()?;
        let now_ms = node.now_ms();
        let grant = account.active(now_ms)?;
        let opened = oauth::open_record(&grant, user_id, &record)?;
        let parsed = opened.parse()?;
        let definition = node
            .definitions
            .get(&record.provider)
            .ok_or(ProtocolError::ProviderUnknown)?;
        // 2: every request passes before any event is created. The first that fails refuses
        // the whole call with its index.
        let mut prepared: Vec<Prepared> = Vec::with_capacity(requests.len());
        for (index, (request, body)) in requests.iter().zip(&bodies).enumerate() {
            prepared.push(
                prepare(request, body, &record, definition, &parsed, context)
                    .map_err(|error| refused(error, index))?,
            );
        }
        // 3: the merge decisions and the events, in order, in one step.
        let events = prepared
            .iter()
            .map(|prepared| (prepared.merge_key, prepared.event.clone()))
            .collect();
        let places = node.create_events(
            &mut account,
            user_id,
            &grant.key_id,
            &grant.log_pk,
            now_ms,
            events,
        )?;
        (prepared, places)
    };
    drop(bodies);
    node.log_counters
        .batch_calls
        .fetch_add(1, Ordering::Relaxed);
    node.log_counters
        .batch_requests
        .fetch_add(prepared.len() as u64, Ordering::Relaxed);

    // 4: the requests leave only after the log store confirmed every entry that holds one of
    // their events.
    let logs: Vec<LogRef> = log_store::commit(node, user_id, &account, &places).await?;
    // The grant is checked once more before any request leaves: a revoke the node accepted
    // while the entry was written leaves no request of this batch behind it (the entry stays
    // on the chain, and the record of its events is larger than the acts).
    lock(&account).active(node.now_ms())?;

    // 5: the provider calls, at most FORWARD_BATCH_CONCURRENCY at a time, until the time
    // limit since the confirmation. The bodies of the results together stay under the body
    // limit of the node: a response that would take their sum over it is `too_large`, and its
    // body is not kept.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    let gate = Semaphore::new(limits::FORWARD_BATCH_CONCURRENCY);
    let body_sum = Mutex::new(0usize);
    let outcomes = join_all(prepared.into_iter().zip(shares).map(|(prepared, share)| {
        let (gate, body_sum) = (&gate, &body_sum);
        async move {
            let Ok(_permit) = gate.acquire().await else {
                return Err(ProtocolError::Internal);
            };
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(ProtocolError::Timeout);
            }
            let (checked, budget) = execute(
                node,
                user_id,
                prepared.outbound,
                prepared.token,
                remaining,
                share,
            )
            .await?;
            let mut sum = lock(body_sum);
            if *sum + checked.body_len() > node.limits.body_bytes {
                return Err(ProtocolError::TooLarge);
            }
            *sum += checked.body_len();
            Ok((checked, budget))
        }
    }))
    .await;

    // 6: the results in the order of the requests. The body budget of the response is the sum
    // of the shares of the bodies.
    let mut budget = None;
    let mut results = Vec::with_capacity(outcomes.len());
    for (outcome, log) in outcomes.into_iter().zip(logs) {
        match outcome {
            Ok((checked, permit)) => {
                match &mut budget {
                    None => budget = Some(permit),
                    Some(total) => total.merge(permit),
                }
                results.push(BatchResult::Response(checked, log));
            }
            Err(error) => results.push(BatchResult::Failure(error.code(), log)),
        }
    }
    let budget = match budget {
        Some(budget) => budget,
        None => super::forward::reserve(node, 0).await?,
    };
    Ok(forward_batch_frame(results, budget))
}
