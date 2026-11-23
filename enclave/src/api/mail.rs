//! Typed mail calls. A record is opened after the grant checks, and its plaintext is read and
//! used after the log store confirmed the entry of the call.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use axum::extract::{Request, State};
use axum::http::header::CONTENT_LENGTH;
use axum::response::Response;
use credential_enclave_protocol::encoding::{b64u, to_json};
use credential_enclave_protocol::log::EntryKind;
use credential_enclave_protocol::{purpose, ProtocolError};
use hyper::body::Bytes;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::responses::forward_frame;
use super::{invalid, read_body, record_of, respond, ApiError, JsonBody};
use crate::frame::{self, META_LIMIT_BYTES};
use crate::log_store;
use crate::mail::{self, MailData, MailError, ReadMail, Share};
use crate::mail_sessions::{Delegation, SessionKey};
use crate::state::{events, lock, Account, GrantState, Node};

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
        match tokio::time::timeout(mail::CALL_TIMEOUT, run(&node, request, operation)).await {
            Ok(result) => result,
            Err(_) => Err(ProtocolError::Timeout.into()),
        },
    )
}

fn admission_error(error: tokio::sync::TryAcquireError) -> ApiError {
    match error {
        tokio::sync::TryAcquireError::NoPermits => ProtocolError::CapacityUnavailable.into(),
        tokio::sync::TryAcquireError::Closed => ApiError::internal(),
    }
}

/// The part of the share of the body budget of a mail call that does not follow its protocol
/// input, without its request frame (`mail::Share`). The share of a call is what the call
/// holds in memory at once:
///
/// | operation | taken before the request frame is read | taken as the protocol input arrives |
/// | --- | --- | --- |
/// | verify | the frame, `CALL_BYTES`, the input bounds of its IMAP connection and of its SMTP connection | nothing |
/// | read: folders, search | the frame, `CALL_BYTES` | 6 bytes per byte of IMAP input (bound: 4 MiB) |
/// | read: read | the frame, `CALL_BYTES` | 2 bytes per byte of IMAP input (bound: the body limit + 1 MiB) |
/// | submit | the frame (the payload is part of it), `CALL_BYTES`, the input bound of its SMTP connection | nothing |
///
/// The frame is taken by its declared length (the frame limit when none is declared) and by
/// its length once it was read. A verification and a submission take the whole of their share
/// here, before a credential is opened: such a call never ends with `capacity_unavailable`
/// after its entry was created. A read takes the second part while it reads, after its entry.
fn fixed_share(operation: &str) -> usize {
    match operation {
        "verify" => mail::CALL_BYTES + mail::LOGIN_INPUT_BYTES + mail::SMTP_INPUT_BYTES,
        "submit" => mail::CALL_BYTES + mail::SMTP_INPUT_BYTES,
        _ => mail::CALL_BYTES,
    }
}

/// The failure of a read whose input the body budget of the node had no room for. The entry
/// of the call is on the chain, the call read from the mailbox and changed nothing in it, and
/// nothing of what it read leaves.
fn no_room_for_the_input() -> ApiError {
    ApiError::with_message(
        ProtocolError::CapacityUnavailable,
        "the node has no room for the mail the call reads; the call changed nothing",
    )
}

/// True while the delegation a call ran under is in force and the node is open, at this
/// moment: the node is not closing, the grant of the account is within its time and is the
/// grant of the signing public key the call ran under, and the account accepted no revoke
/// since the call created its event. A kept session is taken, and a session is kept, only
/// while this holds (`crate::mail_sessions`).
fn in_force(node: &Node, account: &Mutex<Account>, delegation: &Delegation) -> bool {
    if node.closing.load(Ordering::SeqCst) {
        return false;
    }
    let mut account = lock(account);
    account.expire(node.now_ms());
    account.revoke_serial == delegation.revoke_serial
        && matches!(
            account.grant(),
            GrantState::Active(grant) if grant.sign_pk == delegation.sign_pk
        )
}

async fn run(node: &Node, request: Request, operation: &str) -> Result<Response, ApiError> {
    let _slot = node.forward_slots.try_acquire().map_err(admission_error)?;
    let frame_limit = 4 + META_LIMIT_BYTES + node.limits.body_bytes;
    let declared = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if declared.is_some_and(|length| length > frame_limit) {
        return Err(ProtocolError::TooLarge.into());
    }
    // The same budget also admits HTTP forwarding; no separate unbounded mail pool exists.
    // The call takes the share of its frame and its fixed share without waiting.
    let fixed = fixed_share(operation);
    let share = Share::admit(
        &node.body_budget,
        declared.unwrap_or(frame_limit).saturating_add(fixed),
    )
    .ok_or(ProtocolError::CapacityUnavailable)?;
    let frame_bytes = Bytes::from(read_body(request, frame_limit).await?);
    // The frame is in memory: its share is its length.
    if !share.rebase(frame_bytes.len().saturating_add(fixed)) {
        return Err(ProtocolError::CapacityUnavailable.into());
    }
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
    if operation == "submit" {
        // The form of the submission. Whether its sender is the account of the record is
        // judged after the entry: that answer depends on the content of the record.
        mail::submission_sender(&recipients, &payload).map_err(|_| invalid("mail submission"))?;
    }

    node.ensure_open()?;
    if node.log_store.id().is_none() {
        return Err(ProtocolError::NotConfigured.into());
    }
    let account = node.account(user).ok_or(ProtocolError::GrantRequired)?;
    log_store::admit(node, &account).await?;
    // The record a kept session belongs to: its `id` and the hash of its ciphertext, both
    // values of the caller. The record opens under the grant of the account below, so a call
    // with this key carries the application password the session was authenticated with.
    let session_key = SessionKey::of(user, &record);
    let (opened, place, sign_pk, key_id, delegation) = {
        let mut account = lock(&account);
        node.ensure_open()?;
        let now_ms = node.now_ms();
        let grant = account.active(now_ms)?;
        let delegation = Delegation::of(&grant);
        // What is judged before the event is the same for every value the record can hold:
        // the grant, the AEAD verification, and the kind and the provider of the record.
        let opened = mail::open_record(&grant, user, &record)?;
        let place = node.create_event(
            &mut account,
            user,
            &grant.key_id,
            &grant.log_pk,
            now_ms,
            EntryKind::Use,
            events::mail_request(&record.id, operation, &params, &payload, context),
        )?;
        (opened, place, grant.sign_pk, grant.key_id, delegation)
    };
    let log = log_store::commit(node, user, &account, &[(place, true)])
        .await?
        .into_iter()
        .next()
        .ok_or_else(ApiError::internal)?;
    // The plaintext of the record is read only now, after the log store confirmed the entry
    // that holds the event: an answer that depends on the content of the plaintext has an
    // entry. A plaintext the call cannot use is `record_invalid` here: nothing goes to the
    // provider, and the entry stays.
    let credentials = opened.credentials()?;
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
            MailData::Json(to_json(
                &json!({"identity": identity, "node": node.node, "statement": statement}),
            ))
        }),
        "read" => {
            let read = read_request.as_ref().ok_or_else(|| invalid("request"))?;
            let sessions = &node.egress.mail_sessions;
            // The entry of this call is confirmed: the call may send its commands, over the
            // session the node kept for this record or over a new one. A call takes a kept
            // session only here, so no command goes over one for a call without an entry,
            // and only while the delegation it ran under is in force.
            let kept = match in_force(node, &account, &delegation) {
                true => sessions.take(&log, &session_key, &delegation, node.now_ms()),
                false => {
                    sessions.end(&session_key);
                    None
                }
            };
            let (data, session) = credentials.read(node, read, kept, &share).await;
            // The session of a call that ended in step is kept for the next call of the
            // record, while the delegation is in force.
            if let Some(session) = session {
                if in_force(node, &account, &delegation) {
                    sessions.keep(session_key.clone(), delegation, session, node.now_ms());
                }
            }
            data
        }
        "submit" => credentials.submit(node, &recipients, &payload).await,
        _ => return Err(invalid("operation")),
    };
    if matches!(outcome, Err(MailError::Auth)) {
        // The server refuses the application password of the record: no session that was
        // authenticated with it carries a further call.
        node.egress.mail_sessions.end(&session_key);
    }
    let (status, content_type, body) = match outcome {
        Ok(MailData::Json(bytes)) => (200, "application/json", bytes),
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
        Err(MailError::Capacity) => return Err(no_room_for_the_input()),
        Err(MailError::Unavailable) => return Err(ProtocolError::ProviderUnreachable.into()),
    };
    if body.len() > node.limits.body_bytes {
        return Err(ProtocolError::TooLarge.into());
    }
    drop(payload);
    // The check holds at most one more copy of the body: it runs under the share the input
    // of the call took. The response frame then keeps the share of what it holds.
    let response = credentials.check(
        status,
        vec![("content-type".into(), content_type.into())],
        body,
    )?;
    let budget = share
        .settle(response.body_len().saturating_add(mail::CALL_BYTES))
        .ok_or_else(ApiError::internal)?;
    Ok(forward_frame(response, Some(log), budget))
}
