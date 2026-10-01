//! `POST /v1/refresh` (enclave.md 5.7): renews the token of an OAuth record.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::ProtocolError;

use super::responses::Refreshed;
use super::{json_ok, provider_credentials, record_of, respond, ApiError, JsonBody};
use crate::log_store;
use crate::oauth::{self, call_token_address, token_request, ClientId, ClientValues, TokenGrant};
use crate::state::{events, lock, refresh_key, Node};

pub async fn refresh(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// Creates the entry `credential_refreshed` and writes it to the log store, then calls the
/// token address with `grant_type=refresh_token` and returns the same `id` encrypted again
/// with the merged token (protocol.md 8.3). The entry is created before the call, so a refresh
/// the provider refuses is on the log as well.
///
/// A successful response is kept for 3,600 seconds under the hash of the `ct` of the record
/// that was sent. When the same account sends the same record again within that time, the
/// node answers with the kept response: it calls no provider and creates no entry. A provider
/// that rotates refresh tokens invalidates the old token at the first call, so without this a
/// response that never reached the caller would end the connection.
async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let user_id = body.user_id()?;
    let record = record_of(&body, "record")?;
    body.context()?;

    node.ensure_open()?;
    let config = node.operator_config()?;
    let account = node.account(user_id).ok_or(ProtocolError::GrantRequired)?;
    log_store::admit(node, user_id, &account).await?;
    let replay_key = refresh_key(&record);
    let (grant, old, entry, seq, definition, credentials) = {
        let mut account = lock(&account);
        node.ensure_open()?;
        let now_ms = node.now_ms();
        let grant = account.active(now_ms)?;
        account.ensure_capacity()?;
        let opened = oauth::open_record(&grant, user_id, &record)?;
        // The record opened under the grant of this account: a kept response of this record
        // is the answer.
        if let Some(kept) = account.kept_refresh(&replay_key, now_ms) {
            return Ok(json_ok(kept));
        }
        let definition = node
            .definitions
            .get(&record.provider)
            .ok_or(ProtocolError::ProviderUnknown)?;
        let credentials = provider_credentials(definition, &config, &record.provider)?;
        let old = opened.parse()?;
        // A record without a refresh token cannot be renewed: the plaintext lacks what this
        // call needs. No entry is created and no provider is called.
        if old.refresh_token(&definition.token_container).is_none() {
            return Err(ApiError::with_message(
                ProtocolError::RecordInvalid,
                "the record holds no refresh token",
            ));
        }
        let entry = node.append_entry(
            &mut account,
            user_id,
            &grant.key_id,
            &grant.log_pk,
            now_ms,
            &events::credential_refreshed(&record.id, &record.provider),
        )?;
        (grant, old, entry, account.head.seq, definition, credentials)
    };

    // The token address is called only after the log store confirmed the entry. The provider
    // call runs outside the account lock.
    log_store::confirm(node, user_id, &account, &[seq]).await?;
    let refresh_token = old
        .refresh_token(&definition.token_container)
        .ok_or(ProtocolError::RecordInvalid)?;
    // A dynamically registered client refreshes with the client id stored in the record.
    let recorded_client_id = old.client_id();
    let client_id = match &recorded_client_id {
        Some(client_id) => ClientId::Recorded(client_id),
        None => ClientId::Configured(&credentials.client_id),
    };
    let request = token_request(
        definition,
        &ClientValues {
            client_id,
            client_secret: &credentials.client_secret,
            publishable_key: &credentials.publishable_key,
        },
        &TokenGrant::Refresh {
            refresh_token: &refresh_token,
        },
    )?;
    let response = call_token_address(node, definition, request)
        .await
        .map_err(|failure| {
            ApiError::provider(ProtocolError::RefreshFailed, failure.status, failure.error)
        })?;

    let now_ms = node.now_ms();
    let renewed = old.refreshed(&response, &definition.token_container, now_ms);
    let public = renewed.public_fields(definition, Some(&response))?;
    let nonce = node.random_public::<12>()?;
    let refreshed = Refreshed {
        record: renewed.seal(
            &grant,
            &record.id_bytes()?,
            &nonce,
            user_id,
            &record.provider,
        ),
        public,
        entry,
    };
    lock(&account).keep_refresh(&grant, replay_key, now_ms, refreshed.clone());
    Ok(json_ok(&refreshed))
}
