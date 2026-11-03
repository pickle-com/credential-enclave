//! `POST /v1/close` and `POST /v1/close/heads` (enclave.md 5.11): the orderly shutdown.
//!
//! `close` raises the closing flag. From then on every command and every call that uses a
//! credential is refused with `closing`, and no account chain grows. `close/heads` then hands
//! out one `final` head per account that has a chain, at the last entry the log store
//! confirmed.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::ProtocolError;

use super::responses::{Closed, Heads};
use super::{json_ok, limit_of, respond, ApiError, JsonBody};
use crate::log_store;
use crate::state::{lock, Account, FinalHead, Node};

/// Most heads in one page.
const PAGE_LIMIT: usize = 1000;

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

/// True when `close/heads` lists the account: it has a chain, or its final head was signed
/// (a chain whose entries were all dropped at a final head of `seq` 0 stays listed).
fn listed(account: &Mutex<Account>) -> bool {
    let account = lock(account);
    account.head.seq > 0 || account.final_head.is_some()
}

/// One page of `final` heads in `user_id` order. `cursor` is the last `user_id` of the page
/// before. An empty `next` ends the listing. The call is `invalid_request` before `close`: a
/// `final` head promises that the node writes no further entry for that account.
///
/// The page is the first `limit` accounts after the cursor that have a chain. For these
/// accounts the call closes the open batch of each into an entry and writes, in one round, the
/// entries the store has not confirmed: the entries it just closed and the pending entries. A
/// final head is then signed for each account by the rule of [`Node::final_head_of`]: at the
/// head when the store confirmed every entry, at the last confirmed entry when the pending
/// entries are the tail of the chain (the tail is dropped, and the account is counted in
/// `truncated`), and not at all in this call when a confirmed entry lies above a pending one or
/// a call still writes an entry of the account (counted in `skipped`). A final head once signed
/// is returned as it is by every later call.
async fn final_heads(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let cursor = body.text_or_empty("cursor")?;
    let limit = limit_of(&body, PAGE_LIMIT)?;
    if !node.closing.load(Ordering::SeqCst) {
        return Err(ApiError::with_message(
            ProtocolError::InvalidRequest,
            "close/heads needs close first",
        ));
    }
    let now_ms = node.now_ms();

    // The page: the accounts with a chain after the cursor, at most `limit`, and whether an
    // account with a chain follows them.
    let mut walk = node
        .accounts_after(cursor)
        .filter(|(_, account)| listed(account));
    let page: Vec<(String, Arc<Mutex<Account>>)> = walk.by_ref().take(limit).collect();
    let more = walk.next().is_some();

    // The open batch of every account of the page is closed into an entry, and the entries of
    // these accounts that the store has not confirmed are written in one round before a head
    // is signed: a final head covers every event whose entry the store holds. An entry that
    // round does not confirm is a pending entry.
    let mut awaited: Vec<(&Mutex<Account>, u64)> = Vec::new();
    for (user_id, account) in &page {
        let mut guard = lock(account);
        if guard.has_open_events() {
            node.close_batch(&mut guard, user_id, now_ms)?;
        }
        if let Some(last) = guard.unconfirmed().last() {
            awaited.push((account.as_ref(), last.seq));
        }
    }
    if !awaited.is_empty() {
        let _ = log_store::confirm_each(node, &awaited).await;
    }

    let mut heads = Vec::with_capacity(page.len());
    let (mut truncated, mut skipped) = (0, 0);
    let mut last = String::new();
    for (user_id, account) in &page {
        match node.final_head_of(user_id, &mut lock(account), now_ms) {
            FinalHead::Signed(signed) => heads.push(signed),
            FinalHead::Truncated(signed) => {
                heads.push(signed);
                truncated += 1;
            }
            FinalHead::Skipped => skipped += 1,
        }
        last.clone_from(user_id);
    }
    let next = if more { last } else { String::new() };
    Ok(json_ok(&Heads {
        heads,
        next,
        truncated,
        skipped,
    }))
}
