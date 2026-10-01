//! `POST /v1/status` (enclave.md 5.4): the signed head of an account chain and the delegation
//! state.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::encoding::b64u_decode;
use credential_enclave_protocol::log::{signed_head, Head};

use super::responses::Status;
use super::{invalid, json_ok, respond, ApiError, JsonBody};
use crate::state::{lock, GrantStatus, Node};

pub async fn status(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// Signs the end of the chain of `user_id` over the requester's nonce. The nonce is base64url
/// of 1 to 64 bytes: the empty nonce belongs to `final` heads.
async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let user_id = body.user_id()?;
    let nonce = body.text("nonce")?;
    let nonce_bytes = b64u_decode(nonce).map_err(|_| invalid("nonce"))?;
    if !(1..=64).contains(&nonce_bytes.len()) {
        return Err(invalid("nonce"));
    }
    let now_ms = node.now_ms();
    let (head, grant) = match node.account(user_id) {
        Some(account) => {
            let mut account = lock(&account);
            (account.head, account.status(now_ms))
        }
        None => (Head::EMPTY, GrantStatus::none()),
    };
    Ok(json_ok(&Status {
        head: signed_head(&node.keys, user_id, &head, nonce, now_ms, false),
        grant,
    }))
}
