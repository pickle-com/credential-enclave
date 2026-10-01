//! `POST /v1/oauth/begin`, `POST /v1/oauth/complete` and `POST /v1/oauth/merge`
//! (enclave.md 5.5 and 5.6).
//!
//! The node creates the authorization address, the state and the PKCE verifier, and later
//! exchanges the code itself. The token response becomes a record encrypted under the user
//! key. With PKCE, a code that passes through the operator's callback is of no use outside the
//! node: the verifier never leaves it.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::encoding::b64u;
use credential_enclave_protocol::{limits, statement, ProtocolError};

use super::responses::{Begin, Complete, Merged};
use super::{invalid, json_ok, provider_credentials, record_of, respond, ApiError, JsonBody};
use crate::log_store;
use crate::oauth::{
    self, authorization_url, call_token_address, check_params, token_request, ClientId,
    ClientValues, PkceVerifier, TokenGrant,
};
use crate::providers::{ClientKind, Pkce};
use crate::state::{events, lock, Node, PendingAuth};

/// Longest `operator_state`, in characters.
const OPERATOR_STATE_CHARS: usize = 1024;
/// Longest `client_id` of a dynamic client, in characters.
const CLIENT_ID_CHARS: usize = 256;
/// Longest authorization code, in bytes.
const CODE_LIMIT_BYTES: usize = 4096;

pub async fn begin(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run_begin(&node, request).await)
}

async fn run_begin(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let user_id = body.user_id()?;
    let provider = body.text("provider")?;
    let operator_state = body.text("operator_state")?;
    let valid_state = (1..=OPERATOR_STATE_CHARS).contains(&operator_state.len())
        && operator_state
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !valid_state {
        return Err(invalid("operator_state"));
    }
    let empty = serde_json::Map::new();
    let params = match body.get("params") {
        None => &empty,
        Some(value) => value.as_object().ok_or_else(|| invalid("params"))?,
    };
    let requested_client_id = body.text_or_empty("client_id")?;

    // 1
    node.ensure_open()?;
    let config = node.operator_config()?;
    let now_ms = node.now_ms();
    let (key_id, sign_pk) = {
        let account = node.account(user_id).ok_or(ProtocolError::GrantRequired)?;
        let mut account = lock(&account);
        let grant = account.active(now_ms)?;
        (grant.key_id.clone(), grant.sign_pk)
    };
    let definition = node
        .definitions
        .get(provider)
        .ok_or(ProtocolError::ProviderUnknown)?;
    let credentials = provider_credentials(definition, &config, provider)?;
    // 2
    let params = check_params(definition, params)?;
    // 3
    let client_id = match definition.client {
        ClientKind::Static => {
            if !requested_client_id.is_empty() {
                return Err(invalid("client_id"));
            }
            credentials.client_id.as_str()
        }
        ClientKind::Dynamic => {
            let length = requested_client_id.chars().count();
            if !(1..=CLIENT_ID_CHARS).contains(&length)
                || requested_client_id.chars().any(char::is_control)
            {
                return Err(invalid("client_id"));
            }
            requested_client_id
        }
    };
    // 4: the verifier stays in the node. Its S256 challenge goes into the authorization
    // address.
    let node_state = b64u(&node.random_public::<16>()?);
    let code_verifier = match definition.pkce {
        Pkce::S256 => Some(PkceVerifier::new(&node.random_secret::<32>()?)),
        Pkce::None => None,
    };
    let code_challenge = code_verifier.as_ref().map(PkceVerifier::challenge);
    // 5
    let state = format!("{node_state}.{operator_state}");
    let url = authorization_url(
        definition,
        client_id,
        &credentials.redirect_uri,
        &state,
        code_challenge.as_deref(),
        &credentials.publishable_key,
        &params,
    );
    // 6
    let expires_ms = now_ms + limits::PENDING_AUTH_MS;
    node.insert_pending(
        node_state,
        PendingAuth {
            user_id: user_id.to_string(),
            key_id: key_id.clone(),
            sign_pk,
            provider: provider.to_string(),
            code_verifier,
            client_id: client_id.to_string(),
            redirect_uri: credentials.redirect_uri.clone(),
            state: state.clone(),
            expires_ms,
        },
    );
    let statement = statement::oauth_begin(
        &node.keys, user_id, &key_id, &sign_pk, provider, &state, &url, now_ms,
    );
    Ok(json_ok(&Begin {
        authorization_url: url,
        state,
        statement,
        expires_ms,
    }))
}

pub async fn complete(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run_complete(&node, request).await)
}

async fn run_complete(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let user_id = body.user_id()?;
    let state = body.text("state")?;
    let code = body.text("code")?;
    if code.is_empty() || code.len() > CODE_LIMIT_BYTES {
        return Err(invalid("code"));
    }

    // A node that cannot write to its log store ends the call before it uses the pending
    // authorization up: the same call passes once the node can write.
    node.log_store.ensure_ready(node.now_ms())?;

    // 1: the pending authorization is found by its node_state and used once.
    let node_state = state.split('.').next().unwrap_or_default();
    let pending = node
        .take_pending(node_state)
        .filter(|pending| pending.state == state)
        .ok_or(ProtocolError::StateUnknown)?;
    if pending.user_id != user_id {
        return Err(ProtocolError::UserMismatch.into());
    }

    // 2
    node.ensure_open()?;
    let config = node.operator_config()?;
    let definition = node
        .definitions
        .get(&pending.provider)
        .ok_or(ProtocolError::ProviderUnknown)?;
    let credentials = provider_credentials(definition, &config, &pending.provider)?;
    let account = node.account(user_id).ok_or(ProtocolError::GrantRequired)?;
    // An account at its limit of pending entries does not spend the authorization code.
    log_store::admit(node, user_id, &account).await?;
    {
        let mut account = lock(&account);
        let grant = account.active(node.now_ms())?;
        account.ensure_capacity()?;
        // The grant in force is the grant the authorization started under: all 32 bytes of
        // the account signing public key, not the 8-byte key_id (protocol.md 8.2).
        if grant.sign_pk != pending.sign_pk {
            return Err(ProtocolError::KeyMismatch.into());
        }
    }

    // 3: the exchange runs outside the account lock.
    let request = token_request(
        definition,
        &ClientValues {
            client_id: ClientId::Configured(&pending.client_id),
            client_secret: &credentials.client_secret,
            publishable_key: &credentials.publishable_key,
        },
        &TokenGrant::Exchange {
            code,
            redirect_uri: &pending.redirect_uri,
            code_verifier: pending.code_verifier.as_ref(),
        },
    )?;
    let response = call_token_address(node, definition, request)
        .await
        .map_err(|failure| {
            ApiError::provider(ProtocolError::ExchangeFailed, failure.status, failure.error)
        })?;

    // 4, 5: the token response becomes the plaintext of the record. The public fields pass
    // rule E4 before anything is created: a response that fails it leaves no record, no
    // public field and no entry.
    let now_ms = node.now_ms();
    let dynamic_client =
        (definition.client == ClientKind::Dynamic).then_some(pending.client_id.as_str());
    let plaintext = response.into_plaintext(now_ms, dynamic_client);
    let public = plaintext.public_fields(definition, None)?;
    let id = node.random_public::<16>()?;
    let nonce = node.random_public::<12>()?;
    // The record and its entry are created under the account lock.
    let (record, entry, seq) = {
        let mut account = lock(&account);
        node.ensure_open()?;
        let grant = account.active(now_ms)?;
        if grant.sign_pk != pending.sign_pk {
            return Err(ProtocolError::KeyMismatch.into());
        }
        let record = plaintext.seal(&grant, &id, &nonce, user_id, &pending.provider);
        let entry = node.append_entry(
            &mut account,
            user_id,
            &grant.key_id,
            &grant.log_pk,
            now_ms,
            &events::connection_created(&record.id, &pending.provider, public.scope(definition)),
        )?;
        (record, entry, account.head.seq)
    };
    // The record leaves only after the log store confirmed the entry. When it does not, the
    // record is dropped here and the tokens with it: the connection is started again.
    log_store::confirm(node, user_id, &account, &[seq]).await?;
    let statement = statement::oauth_complete(
        &node.keys,
        user_id,
        &pending.key_id,
        &pending.sign_pk,
        &pending.provider,
        &pending.state,
        &record.id,
        now_ms,
    );
    Ok(json_ok(&Complete {
        record,
        public,
        statement,
        entry,
    }))
}

pub async fn merge(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run_merge(&node, request).await)
}

/// Moves the refresh token of the previous record into a new record that has none
/// (protocol.md 8.3) and returns the new record encrypted again under its own `id`. No entry
/// is created and no provider is called.
async fn run_merge(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let user_id = body.user_id()?;
    let record = record_of(&body, "record")?;
    let previous = record_of(&body, "previous")?;

    node.ensure_open()?;
    let grant = {
        let account = node.account(user_id).ok_or(ProtocolError::GrantRequired)?;
        let mut account = lock(&account);
        account.active(node.now_ms())?
    };
    let (new, old) = oauth::open_records(&grant, user_id, &record, &previous)?;
    if record.provider != previous.provider {
        return Err(ApiError::with_message(
            ProtocolError::InvalidRequest,
            "the two records are of different providers",
        ));
    }
    let definition = node
        .definitions
        .get(&record.provider)
        .ok_or(ProtocolError::ProviderUnknown)?;
    let merged = new
        .parse()?
        .with_refresh_token_of(&old.parse()?, &definition.token_container);
    let public = merged.public_fields(definition, None)?;
    let nonce = node.random_public::<12>()?;
    let merged = merged.seal(
        &grant,
        &record.id_bytes()?,
        &nonce,
        user_id,
        &record.provider,
    );
    Ok(json_ok(&Merged {
        record: merged,
        public,
    }))
}
