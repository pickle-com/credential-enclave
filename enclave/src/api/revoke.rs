//! `POST /v1/revoke-token` (enclave.md 5.7): revokes the token of an OAuth record at its
//! provider.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::ProtocolError;

use super::responses::Revoked;
use super::{json_ok, provider_credentials, record_of, respond, ApiError, JsonBody};
use crate::log_store;
use crate::oauth::{self, revoke_request, ClientId, ClientValues, REVOKE_TIMEOUT};
use crate::state::{events, lock, Node};

pub async fn revoke_token(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// Creates the entry `connection_removed` and writes it to the log store, then calls the
/// revocation address when the definition has one. The token sent is the refresh token when
/// the record has one, else the access token, with its `token_type_hint`. A provider without a
/// revocation address and a revocation call that fails are not errors: the response says
/// `revoked: false`.
///
/// The entry is created before the call, so it cannot hold the outcome of the call. Its
/// `provider_revoke` field records whether the node calls the revocation address after this
/// entry. The outcome of the call is the `revoked` of the response: one bit, whether the
/// revocation address answered with a 2xx status. Nothing else of that answer leaves the node.
async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let user_id = body.user_id()?;
    let record = record_of(&body, "record")?;
    body.context()?;

    node.ensure_open()?;
    let config = node.operator_config()?;
    let account = node.account(user_id).ok_or(ProtocolError::GrantRequired)?;
    log_store::admit(node, user_id, &account).await?;
    let (entry, seq, call) = {
        let mut account = lock(&account);
        node.ensure_open()?;
        let now_ms = node.now_ms();
        let grant = account.active(now_ms)?;
        account.ensure_capacity()?;
        let opened = oauth::open_record(&grant, user_id, &record)?;
        let definition = node
            .definitions
            .get(&record.provider)
            .ok_or(ProtocolError::ProviderUnknown)?;
        let credentials = provider_credentials(definition, &config, &record.provider)?;
        let parsed = opened.parse()?;
        let recorded_client_id = parsed.client_id();
        let call = match (
            &definition.revoke,
            definition.revoke_destination(),
            parsed.revocation_token(&definition.token_container),
        ) {
            (Some(revoke), Some(destination), Some((token, hint))) => Some(revoke_request(
                revoke,
                destination,
                &ClientValues {
                    client_id: match &recorded_client_id {
                        Some(client_id) => ClientId::Recorded(client_id),
                        None => ClientId::Configured(&credentials.client_id),
                    },
                    client_secret: &credentials.client_secret,
                    publishable_key: &credentials.publishable_key,
                },
                &token,
                hint,
            )),
            _ => None,
        };
        let entry = node.append_entry(
            &mut account,
            user_id,
            &grant.key_id,
            &grant.log_pk,
            now_ms,
            &events::connection_removed(&record.id, &record.provider, call.is_some()),
        )?;
        (entry, account.head.seq, call)
    };

    // The revocation address is called only after the log store confirmed the entry.
    log_store::confirm(node, user_id, &account, &[seq]).await?;
    let revoked = match call {
        None => false,
        Some(request) => {
            let outcome = tokio::time::timeout(REVOKE_TIMEOUT, async {
                let exchange = node
                    .egress
                    .send_to_provider(node.platform.as_ref(), request)
                    .await
                    .ok()?;
                Some(exchange.status)
            })
            .await;
            matches!(outcome, Ok(Some(status)) if (200..300).contains(&status))
        }
    };
    Ok(json_ok(&Revoked { revoked, entry }))
}
