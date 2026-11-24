//! `POST /v1/app-password/verify` (enclave.md 5.8c): the check, at the time a connection is
//! made, that a provider accepts the application password of a record whose provider
//! authenticates over HTTP.
//!
//! The call sends the one request that the application password definition of the provider
//! names (`verify`), through the machinery of `forward`: the address check, the event
//! `provider_request` on the chain and in the log store before the request leaves, the TLS
//! client, the time limit and the check of the response for the password (rule E4 of the
//! egress policy). The response of the provider stays inside the node. What leaves is made of
//! its status: a status the definition accepts gives the identity of the account and the
//! statement `app_password_verified`, a 401 the fixed code `authentication_failed`, any other
//! status the fixed frame status 502 with the fixed code `verification_failed` and that status.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::encoding::to_json;
use credential_enclave_protocol::ProtocolError;
use hyper::body::Bytes;
use serde_json::json;
use tokio::sync::OwnedSemaphorePermit;

use super::forward::{execute, prepare, read_frame, reserve, timeout_of, Password, Prepared};
use super::responses::forward_frame;
use super::{invalid, record_of, respond, ApiError};
use crate::log_store;
use crate::state::{lock, Node};

/// The frame status of an answer that is neither a status the definition accepts nor 401: the
/// node, a gateway to the provider, received an answer that is not one of the two it reads
/// (RFC 9110 15.6.3). The status of the provider is in the body.
const NOT_VERIFIED: u16 = 502;

pub async fn verify(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// The permit of the provider body, grown or cut to `bytes`: the body the node answers with
/// takes the place of the body of the provider in the budget.
async fn resized(
    node: &Node,
    mut budget: OwnedSemaphorePermit,
    bytes: usize,
) -> Result<OwnedSemaphorePermit, ApiError> {
    let held = budget.num_permits();
    if bytes > held {
        budget.merge(reserve(node, bytes - held).await?);
    } else {
        drop(budget.split(held - bytes));
    }
    Ok(budget)
}

async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
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
    // The call takes no request of its own: the definition names the one request it sends.
    let empty_request = meta
        .get("request")
        .is_none_or(|request| request.as_object().is_some_and(|fields| fields.is_empty()));
    if !empty_request {
        return Err(invalid("verify request"));
    }
    if !payload.is_empty() {
        return Err(invalid("verify payload"));
    }
    drop(payload);

    // 1: the common front of `forward`. Everything up to the event happens under the account
    // lock.
    node.ensure_open()?;
    node.operator_config()?;
    let account = node.account(user_id).ok_or(ProtocolError::GrantRequired)?;
    log_store::admit(node, &account).await?;
    let (password, prepared, place, sign_pk, key_id) = {
        let mut account = lock(&account);
        node.ensure_open()?;
        let now_ms = node.now_ms();
        let grant = account.active(now_ms)?;
        // The record opens as an application password and nothing else (5.8c step 1).
        let password = Password::open(&node.definitions, &grant, user_id, &record)?;
        let probe = &password.definition.verify;
        let request = json!({
            "method": probe.method,
            "url": probe.url,
            "headers": probe.headers,
        });
        let body = Bytes::from(probe.body.clone().into_bytes());
        // 2 to 6 of `forward`: the request of the definition passes the same checks as a
        // request of the caller, and its event `provider_request` goes on the chain.
        let prepared = prepare(&request, &body, &record, &password, context)?;
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
        (password, prepared, place, grant.sign_pk, grant.key_id)
    };
    let log = log_store::commit(node, user_id, &account, &[place])
        .await?
        .into_iter()
        .next()
        .ok_or_else(ApiError::internal)?;

    // 8 to 10 of `forward`. The response passed rule E4, and only its status is read.
    let Prepared {
        outbound,
        credential,
        ..
    } = prepared;
    let (checked, budget) = execute(
        node,
        user_id,
        outbound,
        credential,
        Duration::from_millis(timeout_ms),
        Some(request_budget),
    )
    .await?;
    let (status, _, _) = checked.into_parts();
    let credentials = &password.credentials;
    let (status, body) = if password.definition.verify.accepted.contains(&status) {
        let identity = credentials.identity();
        let statement = credentials.verified_statement(node, user_id, &record, &key_id, &sign_pk);
        (
            200,
            json!({"identity": identity, "node": node.node, "statement": statement}),
        )
    } else if status == 401 {
        (401, json!({"code": "authentication_failed"}))
    } else {
        (
            NOT_VERIFIED,
            json!({"code": "verification_failed", "status": status}),
        )
    };
    let body = to_json(&body);
    let budget = resized(node, budget, body.len()).await?;
    // Rule E4 applies to this response too, as to the responses of the mail calls.
    let response = credentials.check(
        status,
        vec![("content-type".into(), "application/json".into())],
        body,
    )?;
    Ok(forward_frame(response, Some(log), budget))
}
