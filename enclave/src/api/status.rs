//! `POST /v1/status` (enclave.md 5.4): the delegation state of an account on this node.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;

use super::responses::Status;
use super::{json_ok, respond, ApiError, JsonBody};
use crate::state::{lock, GrantStatus, Node};

pub async fn status(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// Reports the delegation state of `user_id`: `none` for an account the node holds no state
/// of, and `internal` for an account the node halted. The call signs nothing: a node of this
/// release keeps no head of a chain.
async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let user_id = body.user_id()?;
    let now_ms = node.now_ms();
    let grant = match node.account(user_id) {
        Some(account) => {
            let mut account = lock(&account);
            account.ensure_usable()?;
            account.status(now_ms)
        }
        None => GrantStatus::none(),
    };
    Ok(json_ok(&Status { grant }))
}
