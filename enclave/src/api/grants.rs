//! `POST /v1/grants/prune` (enclave.md 5.15): the operator reduces which nodes hold the key of
//! an account to the nodes of the delegation subset (`crate::subset`).
//!
//! A node that held the delegations of every account before the subset rule drops the grants
//! of the accounts outside its share, one page at a time. The user key of a dropped grant is
//! overwritten with zeros. Nothing is used and no entry is created: a prune is the operator
//! choosing which nodes hold a key, and a node that holds fewer keys is the only outcome.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;

use super::responses::Pruned;
use super::{invalid, json_ok, limit_of, respond, subset_of, ApiError, JsonBody};
use crate::state::{lock, Node};

/// Most pruned accounts in one page.
const PAGE_LIMIT: usize = 1000;
/// Most accounts one call looks at: a call whose accounts are all inside the subset ends
/// after this many of them and names the last one in `next`.
pub const SCAN_LIMIT: usize = 10_000;

pub async fn prune(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// Walks the accounts after `after` in `user_id` order and drops the grant, within its time or
/// expired, of every account that the subset does not give to this node: the state of the
/// account becomes `None`, its user key is overwritten with zeros, and its kept `refresh`
/// responses and merge keys go with the grant. A revocation marker stays, and so does the
/// chain. The walk ends after `limit` pruned accounts (1 to 1,000) or after [`SCAN_LIMIT`]
/// accounts looked at; `next` is the last `user_id` it looked at, the empty string when it
/// reached the end. The call works in the state `closing` too, and `subset` is required.
async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let subset = subset_of(&body)?.ok_or_else(|| invalid("subset"))?;
    let after = body.text_or_empty("after")?;
    let limit = limit_of(&body, PAGE_LIMIT)?;
    let mut pruned = Vec::new();
    let mut last = String::new();
    let mut looked_at = 0usize;
    let mut walk = node.accounts_after(after).peekable();
    for (user_id, account) in walk.by_ref() {
        looked_at += 1;
        if !subset.contains(&user_id) && lock(&account).drop_grant() {
            pruned.push(user_id.clone());
        }
        last = user_id;
        if pruned.len() >= limit || looked_at >= SCAN_LIMIT {
            break;
        }
    }
    let next = if walk.peek().is_some() {
        last
    } else {
        String::new()
    };
    Ok(json_ok(&Pruned { pruned, next }))
}
