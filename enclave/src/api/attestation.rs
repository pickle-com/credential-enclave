//! `POST /v1/attestation` (enclave.md 5.2, protocol.md 4.2).

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::encoding::{b64u, b64u_decode};
use credential_enclave_protocol::statement;

use super::responses::Attestation;
use super::{invalid, json_ok, respond, ApiError, JsonBody};
use crate::state::Node;

pub async fn attestation(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// Returns the platform attestation document that binds the node keys, the release and the log
/// store of the node to the requester's nonce, with a new one-time challenge and the statement
/// that binds this challenge to the same nonce. The nonce is 16 to 64 bytes.
///
/// The challenge is drawn in this call and signed with the nonce of this call only: the node
/// signs no challenge statement for a value a caller names. So a statement that verifies for a
/// nonce proves that its challenge was issued after that nonce was chosen.
async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let nonce = b64u_decode(body.text("nonce")?).map_err(|_| invalid("nonce"))?;
    if !(16..=64).contains(&nonce.len()) {
        return Err(invalid("nonce"));
    }
    let challenge = node.issue_challenge()?;
    let challenge_statement = statement::challenge(&node.keys, &nonce, &challenge, node.now_ms());
    let user_data = node.binding();
    let platform = node.platform.clone();
    // The attestation device is a blocking call.
    let document = tokio::task::spawn_blocking(move || platform.attestation(&user_data, &nonce))
        .await
        .map_err(|_| ApiError::internal())??;
    Ok(json_ok(&Attestation {
        v: 1,
        platform: node.platform.name(),
        document: b64u(&document),
        node: &node.node,
        challenge: b64u(&challenge),
        release: node.release,
        challenge_statement,
    }))
}
