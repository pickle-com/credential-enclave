//! Typed mail calls. Passwords are opened only after grant checks and used after logging.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::encoding::{b64u, to_json};
use credential_enclave_protocol::{purpose, ProtocolError};
use hyper::body::Bytes;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::responses::forward_frame;
use super::{invalid, read_body, record_of, respond, ApiError, JsonBody};
use crate::frame::{self, META_LIMIT_BYTES};
use crate::log_store;
use crate::mail::{AppPassword, MailData, MailError, ReadMail};
use crate::state::{lock, Node};

pub async fn verify(State(node): State<Arc<Node>>, request: Request) -> Response {
    call(node, request, "verify").await
}
pub async fn read(State(node): State<Arc<Node>>, request: Request) -> Response {
    call(node, request, "read").await
}
pub async fn submit(State(node): State<Arc<Node>>, request: Request) -> Response {
    call(node, request, "submit").await
}

async fn call(node: Arc<Node>, request: Request, operation: &'static str) -> Response {
    respond(
        match tokio::time::timeout(Duration::from_secs(30), run(&node, request, operation)).await {
            Ok(result) => result,
            Err(_) => Err(ProtocolError::Timeout.into()),
        },
    )
}

async fn run(node: &Node, request: Request, operation: &str) -> Result<Response, ApiError> {
    let _slot = node
        .forward_slots
        .acquire()
        .await
        .map_err(|_| ApiError::internal())?;
    // The bound includes protocol buffers, MIME bytes and JSON/base64 construction.
    // The same budget also admits HTTP forwarding; no separate unbounded mail pool exists.
    let reserve = node
        .limits
        .body_bytes
        .checked_mul(6)
        .and_then(|v| v.checked_add(META_LIMIT_BYTES * 2))
        .and_then(|v| u32::try_from(v).ok())
        .ok_or(ProtocolError::TooLarge)?;
    let mut budget = node
        .body_budget
        .clone()
        .acquire_many_owned(reserve)
        .await
        .map_err(|_| ApiError::internal())?;
    let frame_bytes =
        Bytes::from(read_body(request, 4 + META_LIMIT_BYTES + node.limits.body_bytes).await?);
    let (meta_value, payload) = frame::decode(&frame_bytes)?;
    drop(frame_bytes);
    if payload.len() > node.limits.body_bytes {
        return Err(ProtocolError::TooLarge.into());
    }
    let meta = JsonBody::from_value(meta_value)?;
    let user = meta.user_id()?;
    let record = record_of(&meta, "record")?;
    let context = meta.context()?;
    let params = meta.get("request").cloned().unwrap_or_else(|| json!({}));
    let read_request = if operation == "read" {
        Some(
            serde_json::from_value::<ReadMail>(params.clone())
                .map_err(|_| invalid("mail request"))?,
        )
    } else {
        None
    };
    if let Some(read) = &read_request {
        read.validate().map_err(|_| invalid("mail request"))?;
    }
    if operation == "verify" && params != json!({}) {
        return Err(invalid("verify request"));
    }
    if operation == "submit"
        && !params
            .as_object()
            .is_some_and(|p| p.len() == 1 && p.contains_key("recipients"))
    {
        return Err(invalid("submit request"));
    }
    let recipients: Vec<String> = if operation == "submit" {
        serde_json::from_value(
            params
                .get("recipients")
                .cloned()
                .ok_or_else(|| invalid("recipients"))?,
        )
        .map_err(|_| invalid("recipients"))?
    } else {
        Vec::new()
    };
    if operation != "submit" && !payload.is_empty() {
        return Err(invalid("mail payload"));
    }

    node.ensure_open()?;
    if node.log_store.id().is_none() {
        return Err(ProtocolError::NotConfigured.into());
    }
    let account = node.account(user).ok_or(ProtocolError::GrantRequired)?;
    log_store::admit(node, user, &account).await?;
    let (credentials, entry, seq, sign_pk, key_id) = {
        let mut account = lock(&account);
        node.ensure_open()?;
        let grant = account.active(node.now_ms())?;
        account.ensure_capacity()?;
        let credentials = AppPassword::open(&grant, user, &record)?;
        if operation == "submit" {
            credentials
                .validate_submission(&recipients, &payload)
                .map_err(|_| invalid("mail submission"))?;
        }
        let event = json!({
            "t": "mail_request", "record_id": record.id, "provider": "naver_mail",
            "operation": operation, "request": params, "body_bytes": payload.len(),
            "body_sha256": b64u(&Sha256::digest(&payload)), "context": context,
        });
        let entry = node.append_entry(
            &mut account,
            user,
            &grant.key_id,
            &grant.log_pk,
            node.now_ms(),
            &event,
        )?;
        (
            credentials,
            entry,
            account.head.seq,
            grant.sign_pk,
            grant.key_id,
        )
    };
    log_store::confirm(node, user, &account, &[seq]).await?;
    let outcome = match operation {
        "verify" => credentials.verify(node).await.map(|()| {
            let identity = credentials.identity();
            let statement = node.keys.sign(
                purpose::STATEMENT,
                &to_json(&json!({
                    "v": 1, "type": "app_password_verified", "node": node.node,
                    "user_id": user, "provider": "naver_mail", "record_id": record.id,
                    "key_id": key_id, "sign_pk": b64u(&sign_pk),
                    "ciphertext_sha256": b64u(&Sha256::digest(record.ct.as_bytes())),
                    "identity": identity, "time_ms": node.now_ms(),
                })),
            );
            MailData::Json(json!({"identity": identity, "node": node.node, "statement": statement}))
        }),
        "read" => {
            credentials
                .read(
                    node,
                    read_request.as_ref().ok_or_else(|| invalid("request"))?,
                )
                .await
        }
        "submit" => credentials.submit(node, &recipients, &payload).await,
        _ => return Err(invalid("operation")),
    };
    let (status, content_type, body) = match outcome {
        Ok(MailData::Json(value)) => (200, "application/json", to_json(&value)),
        Ok(MailData::Raw(bytes)) => (200, "message/rfc822", bytes),
        Err(MailError::Auth) => (
            401,
            "application/json",
            to_json(&json!({"code": "authentication_failed"})),
        ),
        Err(MailError::MailboxChanged) => (
            409,
            "application/json",
            to_json(&json!({"code": "mailbox_changed"})),
        ),
        Err(MailError::Missing) => (
            404,
            "application/json",
            to_json(&json!({"code": "message_not_found"})),
        ),
        Err(MailError::Invalid) => (
            400,
            "application/json",
            to_json(&json!({"code": "invalid_mail_request"})),
        ),
        Err(MailError::TooLarge) => return Err(ProtocolError::TooLarge.into()),
        Err(MailError::Unavailable) => return Err(ProtocolError::ProviderUnreachable.into()),
    };
    if body.len() > node.limits.body_bytes {
        return Err(ProtocolError::TooLarge.into());
    }
    let retained = body.len() + META_LIMIT_BYTES;
    drop(payload);
    let unused = budget.num_permits().saturating_sub(retained);
    drop(budget.split(unused));
    let response = credentials.check(
        status,
        vec![("content-type".into(), content_type.into())],
        body,
    )?;
    Ok(forward_frame(response, Some(entry), budget))
}
