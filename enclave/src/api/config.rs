//! `POST /v1/config` (enclave.md 5.1): the operator configuration.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::keys::{LogStoreId, Role};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::ProtocolError;

use super::responses::Configured;
use super::{invalid, json_ok, respond, ApiError, JsonBody};
use crate::log_store::LogStoreEndpoint;
use crate::state::{Node, OperatorConfig, ProviderCredentials};

/// Longest callback address, in bytes.
const REDIRECT_URI_LIMIT_BYTES: usize = 2048;

pub async fn config(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// Replaces the client values of the operator configuration as a whole. A provider name
/// without a definition and a `redirect_uri` that is not https are `invalid_request`. The local
/// platform also accepts a `redirect_uri` that starts with `http://localhost`.
///
/// `log_store` names the log store of the node: `{"bucket":"...","region":"..."}`. A node takes
/// a log store once. A configuration that names the same one again, or none, leaves it in
/// place, and a configuration that names another one is `invalid_request` and changes nothing:
/// the binding of the attestation names the log store, and what a verifier read there holds
/// for as long as the node lives. A node of the local platform also takes an optional
/// `endpoint` in `log_store` (enclave.md 5.14): an `http://host:port` or `https://host:port`
/// origin it writes to in path-style. A node of the nitro platform refuses a configuration
/// with `endpoint`.
///
/// `role` names the role of the node (protocol.md 4.1): the one value is `forward`, and a
/// configuration without the key is the configuration of a node of the delegation role. A
/// node takes its role once. A configuration of the other role than the node has is
/// `invalid_request` and changes nothing.
async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    match body.get("role") {
        None => {}
        Some(role) if role.as_str() == Role::Forward.binding_value() => {
            return forward_role(node, &body);
        }
        Some(_) => return Err(invalid("role")),
    }
    let mut endpoint = None;
    let log_store = match body.get("log_store") {
        None => None,
        Some(value) => {
            if let Some(text) = value.get("endpoint").filter(|text| !text.is_null()) {
                if node.platform.name() != "local" {
                    return Err(ApiError::with_message(
                        ProtocolError::InvalidRequest,
                        "endpoint is accepted on the local platform only",
                    ));
                }
                endpoint = Some(
                    text.as_str()
                        .and_then(LogStoreEndpoint::parse)
                        .ok_or_else(|| invalid("endpoint"))?,
                );
            }
            Some(
                value
                    .get("bucket")
                    .and_then(serde_json::Value::as_str)
                    .zip(value.get("region").and_then(serde_json::Value::as_str))
                    .and_then(|(bucket, region)| LogStoreId::parse(bucket, region))
                    .ok_or_else(|| invalid("log_store"))?,
            )
        }
    };
    let providers = body
        .object("providers")?
        .as_object()
        .ok_or_else(|| invalid("providers"))?;
    let mut parsed = HashMap::with_capacity(providers.len());
    for (name, value) in providers {
        if node.definitions.get(name).is_none() {
            return Err(ApiError::with_message(
                ProtocolError::InvalidRequest,
                "providers names a provider without a definition",
            ));
        }
        let entry = value.as_object().ok_or_else(|| invalid("providers"))?;
        let text = |key: &str| match entry.get(key) {
            None | Some(serde_json::Value::Null) => Ok(""),
            Some(serde_json::Value::String(text)) => Ok(text.as_str()),
            Some(_) => Err(invalid("providers")),
        };
        let redirect_uri = text("redirect_uri")?;
        let scheme_accepted = redirect_uri.starts_with("https://")
            || (node.accepts_localhost_redirect() && redirect_uri.starts_with("http://localhost"));
        if !scheme_accepted
            || redirect_uri.len() > REDIRECT_URI_LIMIT_BYTES
            || redirect_uri
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(ApiError::with_message(
                ProtocolError::InvalidRequest,
                "a redirect_uri is not an https address",
            ));
        }
        parsed.insert(
            name.clone(),
            ProviderCredentials {
                client_id: text("client_id")?.to_string(),
                client_secret: Secret::new(text("client_secret")?.to_string()),
                redirect_uri: redirect_uri.to_string(),
                publishable_key: text("publishable_key")?.to_string(),
            },
        );
    }
    // The configuration is that of a node of the delegation role: a node that has no role
    // takes that role with it, and a node of the forward role refuses it.
    if !node.role.take(Role::Delegation) {
        return Err(ApiError::with_message(
            ProtocolError::InvalidRequest,
            "the node has the forward role",
        ));
    }
    if let Some(id) = log_store {
        if !node.log_store.set_id(id) || !node.log_store.set_endpoint(endpoint) {
            return Err(ApiError::with_message(
                ProtocolError::InvalidRequest,
                "the node has another log store",
            ));
        }
    }
    node.set_config(OperatorConfig { providers: parsed });
    Ok(json_ok(&Configured { configured: true }))
}

/// The configuration of a node of the forward role: `{"role":"forward"}`.
///
/// Such a node holds no client value of a provider and has no log store: it calls no token
/// address and writes no entry. A configuration that names the forward role together with a
/// log store or with the client values of a provider is `invalid_request`. So is this
/// configuration for a node that has the delegation role: a node that took a call of the
/// delegation role, or a configuration without a role, does not become a node of the forward
/// role.
fn forward_role(node: &Node, body: &JsonBody) -> Result<Response, ApiError> {
    let no_providers = match body.get("providers") {
        None => true,
        Some(providers) => providers.as_object().is_some_and(|map| map.is_empty()),
    };
    if !no_providers || body.get("log_store").is_some() {
        return Err(ApiError::with_message(
            ProtocolError::InvalidRequest,
            "a node of the forward role takes no provider and no log store",
        ));
    }
    if !node.role.take(Role::Forward) {
        return Err(ApiError::with_message(
            ProtocolError::InvalidRequest,
            "the node has the delegation role",
        ));
    }
    node.set_config(OperatorConfig {
        providers: HashMap::new(),
    });
    Ok(json_ok(&Configured { configured: true }))
}
