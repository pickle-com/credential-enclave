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
use crate::log_store::{self, LogStoreEndpoint};
use crate::state::{Node, OperatorConfig, ProviderCredentials};

/// Longest callback address, in bytes.
const REDIRECT_URI_LIMIT_BYTES: usize = 2048;

pub async fn config(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// The failure of a configuration of another role than the role the node has.
fn has_another_role(node: &Node) -> ApiError {
    let message = match node.role.get() {
        Some(Role::Reserve) => "the node has the reserve role",
        Some(Role::Forward) => "the node has the forward role",
        Some(Role::Delegation) | None => "the node has the delegation role",
    };
    ApiError::with_message(ProtocolError::InvalidRequest, message)
}

/// True when the configuration carries no client value of a provider: it has no `providers`
/// key, or an empty object.
fn names_no_provider(body: &JsonBody) -> bool {
    match body.get("providers") {
        None => true,
        Some(providers) => providers.as_object().is_some_and(|map| map.is_empty()),
    }
}

/// The log store a configuration names, and the endpoint of a node of the local platform:
/// `{"bucket":"...","region":"...","endpoint":"..."}`. `None` for a configuration without
/// the key.
fn log_store_of(
    node: &Node,
    body: &JsonBody,
) -> Result<Option<(LogStoreId, Option<LogStoreEndpoint>)>, ApiError> {
    let Some(value) = body.get("log_store") else {
        return Ok(None);
    };
    let mut endpoint = None;
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
    let id = value
        .get("bucket")
        .and_then(serde_json::Value::as_str)
        .zip(value.get("region").and_then(serde_json::Value::as_str))
        .and_then(|(bucket, region)| LogStoreId::parse(bucket, region))
        .ok_or_else(|| invalid("log_store"))?;
    if id.shard_bucket(0).is_none() {
        return Err(ApiError::with_message(
            ProtocolError::InvalidRequest,
            "the bucket name of the log store is longer than 49 characters",
        ));
    }
    Ok(Some((id, endpoint)))
}

/// The client values of the providers a configuration of the delegation role names. A
/// provider name without a definition and a `redirect_uri` that is not https are
/// `invalid_request`. The local platform also accepts a `redirect_uri` that starts with
/// `http://localhost`.
fn providers_of(
    node: &Node,
    body: &JsonBody,
) -> Result<HashMap<String, ProviderCredentials>, ApiError> {
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
    Ok(parsed)
}

/// Takes the operator configuration of a node that holds delegations, and replaces the client
/// values as a whole.
///
/// `role` names the role of the node (protocol.md 4.1): `reserve` or `forward`, and a
/// configuration without the key is the configuration of a node of the delegation role. A
/// node takes its role once. A configuration of another role than the node has is
/// `invalid_request` and changes nothing.
///
/// A configuration of the delegation role names the client values of the providers
/// (`providers`). A configuration of the reserve role names none: a node of that role calls
/// no token address. With `providers` that is not an empty object it is `invalid_request`.
///
/// `log_store` names the log store of the node: `{"bucket":"...","region":"..."}`. A node takes
/// a log store once. A configuration that names the same one again, or none, leaves it in
/// place, and a configuration that names another one is `invalid_request` and changes nothing:
/// the binding of the attestation names the log store, and what a verifier read there holds
/// for as long as the node lives. A bucket name of more than 49 characters is `invalid_request`
/// as well: the buckets the node writes to carry that name between a hash and a number
/// (protocol.md 7.6), and their names would not be bucket names. A node of the local platform
/// also takes an optional `endpoint` in `log_store` (enclave.md 5.14): an `http://host:port`
/// or `https://host:port` origin it writes to in path-style. A node of the nitro platform
/// refuses a configuration with `endpoint`.
///
/// The node takes the role before it takes the log store and writes its node document: the
/// document attests the binding, and the binding of a node of the reserve role names that
/// role.
async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(node, request).await?;
    // A value that is not a string names no role: it equals neither of the two names.
    let reserve = match body.get("role") {
        None => false,
        Some(role) if role.as_str() == Role::Reserve.binding_value() => true,
        Some(role) if role.as_str() == Role::Forward.binding_value() => {
            return forward_role(node, &body);
        }
        Some(_) => return Err(invalid("role")),
    };
    let log_store = log_store_of(node, &body)?;
    let (role, providers) = match reserve {
        true if names_no_provider(&body) => (Role::Reserve, HashMap::new()),
        true => {
            return Err(ApiError::with_message(
                ProtocolError::InvalidRequest,
                "a node of the reserve role takes no client value of a provider",
            ));
        }
        false => (Role::Delegation, providers_of(node, &body)?),
    };
    // A node that has no role takes the role of the configuration with it, and a node of
    // another role refuses it. Every check of the form of the configuration came before: a
    // configuration that is refused gives the node no role.
    if !node.role.take(role) {
        return Err(has_another_role(node));
    }
    if let Some((id, endpoint)) = log_store {
        if !node.log_store.set_id(id) || !node.log_store.set_endpoint(endpoint) {
            return Err(ApiError::with_message(
                ProtocolError::InvalidRequest,
                "the node has another log store",
            ));
        }
    }
    node.set_config(OperatorConfig { providers });
    // A node that just received its log store and holds credentials for it writes its node
    // document now (protocol.md 7.7). The outcome does not change the answer of this call: the
    // call that gives the credentials and the sweep write the document as well.
    let node_document_ms = log_store::write_node_document(node).await;
    Ok(json_ok(&Configured {
        configured: true,
        node_document_ms,
    }))
}

/// The configuration of a node of the forward role: `{"role":"forward"}`.
///
/// Such a node holds no client value of a provider and has no log store: it calls no token
/// address, writes no entry and writes no node document (`node_document_ms` of its answer is
/// 0). A configuration that names the forward role together with a log store or with the
/// client values of a provider is `invalid_request`. So is this configuration for a node that
/// has the delegation role or the reserve role: a node that took a call of a node that holds
/// delegations, or a configuration of one of those two roles, does not become a node of the
/// forward role.
fn forward_role(node: &Node, body: &JsonBody) -> Result<Response, ApiError> {
    if !names_no_provider(body) || body.get("log_store").is_some() {
        return Err(ApiError::with_message(
            ProtocolError::InvalidRequest,
            "a node of the forward role takes no provider and no log store",
        ));
    }
    if !node.role.take(Role::Forward) {
        return Err(has_another_role(node));
    }
    node.set_config(OperatorConfig {
        providers: HashMap::new(),
    });
    Ok(json_ok(&Configured {
        configured: true,
        node_document_ms: 0,
    }))
}
