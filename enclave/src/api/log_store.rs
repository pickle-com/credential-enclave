//! `POST /v1/log-store/credentials` (enclave.md 5.14): the credentials of the operator for the
//! log store.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::ProtocolError;

use super::responses::CredentialsStored;
use super::{json_ok, respond, ApiError, JsonBody};
use crate::log_store::{self, Credentials};
use crate::state::Node;

pub async fn credentials(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// Replaces the credentials the node signs its writes to the log store with: temporary
/// credentials of the operator domain. The node keeps them in memory, uses them until
/// `expires_ms` of its own clock, and returns them in no response.
///
/// The call works without the operator configuration. The credentials say nothing about
/// where the node writes: that is the log store of the configuration, which the binding of
/// the attestation names.
async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(node, request).await?;
    let expires_ms = body.number("expires_ms")?;
    let credentials = Credentials::new(
        body.text("access_key_id")?,
        body.text("secret_access_key")?,
        body.text_or_empty("session_token")?,
        expires_ms,
    )
    .ok_or_else(|| {
        ApiError::with_message(
            ProtocolError::InvalidRequest,
            "the credentials do not have the form of AWS credentials",
        )
    })?;
    node.log_store.set_credentials(credentials);
    // With credentials the node can write its node document: it does so here when the document
    // is due (protocol.md 7.7), so a node that received its log store and its credentials has
    // the document in the store before a user key arrives. The outcome does not change the
    // answer of this call: the sweep writes the document as well.
    let node_document_ms = log_store::write_node_document(node).await;
    Ok(json_ok(&CredentialsStored {
        credentials_expires_ms: expires_ms,
        node_document_ms,
    }))
}
