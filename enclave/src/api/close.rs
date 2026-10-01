//! `POST /v1/close` and `POST /v1/close/heads` (enclave.md 5.11): the orderly shutdown.
//!
//! `close` raises the closing flag. From then on every command and every call that uses a
//! credential is refused with `closing`, and no account chain grows. `close/heads` then hands
//! out one `final` head per account that has a chain.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::log::signed_head;
use credential_enclave_protocol::ProtocolError;

use super::responses::{Closed, Heads};
use super::{invalid, json_ok, respond, ApiError, JsonBody};
use crate::state::{lock, Node};

/// Most heads in one page.
const PAGE_LIMIT: u64 = 1000;

/// Starts the orderly shutdown. `accounts` is the number of accounts that have a chain: the
/// number of heads `close/heads` hands out.
pub async fn close(State(node): State<Arc<Node>>) -> Response {
    node.closing.store(true, Ordering::SeqCst);
    json_ok(&Closed {
        accounts: node.account_count(),
    })
}

pub async fn heads(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(final_heads(&node, request).await)
}

/// One page of `final` heads in `user_id` order. `cursor` is the last `user_id` of the page
/// before. An empty `next` ends the listing. The call is `invalid_request` before `close`: a
/// `final` head promises that the node writes no further entry for that account.
async fn final_heads(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let cursor = body.text_or_empty("cursor")?;
    let limit = match body.get("limit") {
        None => PAGE_LIMIT,
        Some(value) => value
            .as_u64()
            .filter(|limit| *limit >= 1)
            .ok_or_else(|| invalid("limit"))?
            .min(PAGE_LIMIT),
    } as usize;
    if !node.closing.load(Ordering::SeqCst) {
        return Err(ApiError::with_message(
            ProtocolError::InvalidRequest,
            "close/heads needs close first",
        ));
    }
    let now_ms = node.now_ms();
    let mut remaining = node
        .accounts_with_chain()
        .into_iter()
        .filter(|(user_id, _)| cursor.is_empty() || user_id.as_str() > cursor);
    let mut heads = Vec::new();
    let mut last = String::new();
    for (user_id, account) in remaining.by_ref().take(limit) {
        let mut account = lock(&account);
        let head = account.head;
        let signed = account
            .final_head
            .get_or_insert_with(|| signed_head(&node.keys, &user_id, &head, "", now_ms, true))
            .clone();
        heads.push(signed);
        last = user_id;
    }
    let next = if remaining.next().is_some() {
        last
    } else {
        String::new()
    };
    Ok(json_ok(&Heads { heads, next }))
}
