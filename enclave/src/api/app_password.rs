//! `POST /v1/app-password/verify` (enclave.md 5.8c): the check, at the time a connection is
//! made, that a provider accepts the application password of a record whose provider
//! authenticates over HTTP.
//!
//! The call sends the one request that the application password definition of the provider
//! names (`verify`), through the machinery of `forward`: the address check, the event
//! `provider_request` on the chain and in the log store before the request leaves, the TLS
//! client, the time limit and the check of the response for the password (rule E4 of the
//! egress policy). The response of the provider stays inside the node. What leaves is made of
//! its status: a 2xx status gives the identity of the account and the statement
//! `app_password_verified`, a 401 the fixed code `authentication_failed`, any other status
//! that status and the fixed code `verification_failed`.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::encoding::{b64u, to_json, Signed};
use credential_enclave_protocol::record::Record;
use credential_enclave_protocol::{purpose, ProtocolError};
use hyper::body::Bytes;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::OwnedSemaphorePermit;

use super::forward::{execute, prepare, read_frame, reserve, Opened, Prepared, TIMEOUT_DEFAULT_MS};
use super::responses::forward_frame;
use super::{invalid, record_of, respond, ApiError};
use crate::log_store;
use crate::state::{lock, Node};

pub async fn verify(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// The statement `app_password_verified` (protocol.md, application password statements and
/// records): the node states that the provider of the record accepted its application
/// password, and binds the record, the account key of the grant and the identity of the
/// account. The mail verify call and this call sign the same statement.
pub(super) fn verified_statement(
    node: &Node,
    user_id: &str,
    record: &Record,
    key_id: &str,
    sign_pk: &[u8; 32],
    identity: &str,
) -> Signed {
    node.keys.sign(
        purpose::STATEMENT,
        &to_json(&json!({
            "v": 1, "type": "app_password_verified", "node": node.node,
            "user_id": user_id, "provider": record.provider, "record_id": record.id,
            "key_id": key_id, "sign_pk": b64u(sign_pk),
            "ciphertext_sha256": b64u(&Sha256::digest(record.ct.as_bytes())),
            "identity": identity, "time_ms": node.now_ms(),
        })),
    )
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
    let (opened, prepared, place, sign_pk, key_id) = {
        let mut account = lock(&account);
        node.ensure_open()?;
        let now_ms = node.now_ms();
        let grant = account.active(now_ms)?;
        let opened = Opened::open(&node.definitions, &grant, user_id, &record)?;
        // A token record has no verification: the provider accepted the token when it issued
        // it.
        let Opened::AppPassword { definition, .. } = &opened else {
            return Err(ProtocolError::NotAllowed.into());
        };
        let probe = &definition.verify;
        let request = json!({
            "method": probe.method,
            "url": probe.url,
            "headers": probe.headers,
        });
        let body = Bytes::from(probe.body.clone().into_bytes());
        // 2 to 6 of `forward`: the request of the definition passes the same checks as a
        // request of the caller, and its event `provider_request` goes on the chain.
        let prepared = prepare(&request, &body, &record, &opened, context)?;
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
        (opened, prepared, place, grant.sign_pk, grant.key_id)
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
        Duration::from_millis(TIMEOUT_DEFAULT_MS),
        Some(request_budget),
    )
    .await?;
    let (status, _, _) = checked.into_parts();
    let credentials = opened.app_password().ok_or_else(ApiError::internal)?;
    let (status, body) = match status {
        200..=299 => {
            let identity = credentials.identity();
            let statement = verified_statement(node, user_id, &record, &key_id, &sign_pk, identity);
            (
                200,
                json!({"identity": identity, "node": node.node, "statement": statement}),
            )
        }
        401 => (401, json!({"code": "authentication_failed"})),
        other => (other, json!({"code": "verification_failed"})),
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
