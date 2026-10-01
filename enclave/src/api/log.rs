//! `POST /v1/log/entries` and `POST /v1/log/ack` (enclave.md 5.10).
//!
//! A node keeps every entry it created until the caller acknowledges that it stored it. An
//! entry whose response was lost is fetched again with `entries`.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::envelope::ReplyHead;
use credential_enclave_protocol::log::Head;

use super::responses::{Acknowledged, Entries};
use super::{json_ok, respond, ApiError, JsonBody};
use crate::state::{lock, Node};

pub async fn entries(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(read_entries(&node, request).await)
}

/// The unacknowledged entries of `user_id` with a `seq` above `after_seq`, and the end of the
/// chain.
async fn read_entries(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let user_id = body.user_id()?;
    let after_seq = body.number("after_seq")?;
    let (entries, head) = match node.account(user_id) {
        Some(account) => {
            let account = lock(&account);
            let entries = account
                .unacked
                .iter()
                .filter(|entry| entry.seq > after_seq)
                .map(|entry| entry.signed.clone())
                .collect();
            (entries, account.head)
        }
        None => (Vec::new(), Head::EMPTY),
    };
    Ok(json_ok(&Entries {
        entries,
        head: ReplyHead::from(&head),
    }))
}

pub async fn ack(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(acknowledge(&node, request).await)
}

/// Drops the unacknowledged entries of `user_id` with a `seq` of at most `seq` and returns how
/// many remain.
async fn acknowledge(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let user_id = body.user_id()?;
    let seq = body.number("seq")?;
    let unacked = match node.account(user_id) {
        Some(account) => {
            let mut account = lock(&account);
            while account
                .unacked
                .front()
                .is_some_and(|entry| entry.seq <= seq)
            {
                account.unacked.pop_front();
            }
            account.unacked.len()
        }
        None => 0,
    };
    Ok(json_ok(&Acknowledged { unacked }))
}
