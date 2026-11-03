//! `POST /v1/refresh` (enclave.md 5.7): renews the token of an OAuth record.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::log::EntryKind;
use credential_enclave_protocol::ProtocolError;
use tokio::task::JoinHandle;

use super::responses::Refreshed;
use super::{json_ok, provider_credentials, record_of, respond, ApiError, JsonBody};
use crate::log_store;
use crate::oauth::{
    self, call_token_address, token_request, ClientId, ClientValues, ProviderError, TokenGrant,
};
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
///
/// The token address call runs on a task of its own. The call waits for it for the time limit
/// of a token address call and then fails with `refresh_failed` and `provider_status` 0; the
/// task goes on until the late limit, when a place among the late tasks is free, and a success
/// that arrives late is kept the same way: the next call with the same record gets it. Without
/// a free place the task is ended at the time limit, as the call is.
async fn run(node: &Arc<Node>, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let user_id = body.user_id()?;
    let record = record_of(&body, "record")?;
    body.context()?;

    node.ensure_open()?;
    let config = node.operator_config()?;
    let account = node.account(user_id).ok_or(ProtocolError::GrantRequired)?;
    log_store::admit(node, &account).await?;
    let replay_key = refresh_key(&record);
    let (grant, old, place, definition, credentials) = {
        let mut account = lock(&account);
        node.ensure_open()?;
        let now_ms = node.now_ms();
        let grant = account.active(now_ms)?;
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
        let place = node.create_event(
            &mut account,
            user_id,
            &grant.key_id,
            &grant.log_pk,
            now_ms,
            EntryKind::Use,
            events::credential_refreshed(&record.id, &record.provider),
        )?;
        (grant, old, place, definition, credentials)
    };

    // The token address is called only after the log store confirmed the entry that holds the
    // event. The provider call runs outside the account lock.
    let log = log_store::commit(node, user_id, &account, &[(place, true)])
        .await?
        .into_iter()
        .next()
        .ok_or_else(ApiError::internal)?;
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

    // The exchange: the call of the token address, the merge, the public fields, the record,
    // and the kept response. It holds the grant (a copy of the user key), the opened plaintext
    // and the request, all secret types that are overwritten with zeros when the task ends or
    // is ended. Its one output is the response of the call. The response is kept only when the
    // grant it ran under is still in force (`keep_refresh`) and the node is not closing: a
    // late success after a revoke, an expiry, a grant of another key or `close` is dropped
    // here.
    let exchange = {
        let node = node.clone();
        let account = account.clone();
        let user_id = user_id.to_string();
        let provider = record.provider.clone();
        let id = record.id_bytes()?;
        async move {
            let definition = node
                .definitions
                .get(&provider)
                .ok_or(ProtocolError::ProviderUnknown)?;
            let response = tokio::time::timeout(
                node.limits.token_late_limit,
                call_token_address(&node, definition, request),
            )
            .await
            .map_err(|_| ApiError::provider(ProtocolError::RefreshFailed, 0, ProviderError::NONE))?
            .map_err(|failure| {
                ApiError::provider(ProtocolError::RefreshFailed, failure.status, failure.error)
            })?;
            let now_ms = node.now_ms();
            let renewed = old.refreshed(&response, &definition.token_container, now_ms);
            let public = renewed.public_fields(definition, Some(&response))?;
            let nonce = node.random_public::<12>()?;
            let refreshed = Refreshed {
                record: renewed.seal(&grant, &id, &nonce, &user_id, &provider),
                public,
                log,
            };
            let kept = node.ensure_open().is_ok()
                && lock(&account).keep_refresh(&grant, replay_key, now_ms, refreshed.clone());
            Ok::<(Refreshed, bool), ApiError>((refreshed, kept))
        }
    };
    let mut guard = ExchangeGuard {
        task: Some(tokio::spawn(exchange)),
    };
    let task = guard.task.as_mut().ok_or_else(ApiError::internal)?;
    match tokio::time::timeout(node.limits.token_timeout, task).await {
        Ok(Ok(outcome)) => outcome.map(|(refreshed, _)| json_ok(&refreshed)),
        Ok(Err(_)) => Err(ApiError::internal()),
        Err(_) => {
            // The time limit passed. The task goes on in a place among the late tasks, and the
            // watcher of that place counts how the exchange ended. Without a free place the
            // exchange is ended here, as the call is.
            let task = guard.task.take().ok_or_else(ApiError::internal)?;
            match node.late_refreshes.clone().try_acquire_owned() {
                Ok(place) => {
                    let counters = node.clone();
                    tokio::spawn(async move {
                        let _place = place;
                        let counters = &counters.refresh_counters;
                        let counter = match task.await {
                            Ok(Ok((_, true))) => &counters.late_kept,
                            Ok(Ok((_, false))) => &counters.late_dropped,
                            Ok(Err(_)) | Err(_) => &counters.late_failed,
                        };
                        counter.fetch_add(1, Ordering::Relaxed);
                    });
                }
                Err(_) => {
                    task.abort();
                    node.refresh_counters
                        .late_abandoned
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(ApiError::provider(
                ProtocolError::RefreshFailed,
                0,
                ProviderError::NONE,
            ))
        }
    }
}

/// The exchange of a call while the call waits for it. When the call ends before its time
/// limit decided what becomes of the exchange (the caller closed the connection), the exchange
/// ends with it: no task outlives a call outside the places for late calls. The task of a call
/// that reached its time limit is taken out of the guard first.
struct ExchangeGuard {
    task: Option<JoinHandle<Result<(Refreshed, bool), ApiError>>>,
}

impl Drop for ExchangeGuard {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
