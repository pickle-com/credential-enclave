//! `POST /v1/refresh` (enclave.md 5.7): renews the token of an OAuth record.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::log::EntryKind;
use credential_enclave_protocol::ProtocolError;
use tokio::task::JoinHandle;

use super::responses::{json_refreshed, Refreshed, RefreshedBody};
use super::{
    above_bounds, narrowed, provider_credentials, record_of, respond, Admission, ApiError, JsonBody,
};
use crate::faults::joined;
use crate::log_store;
use crate::oauth::{
    self, call_token_address, token_request, ClientId, ClientValues, OauthPlaintext, ProviderError,
    TokenGrant, Unusable,
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
/// response that never reached the caller would end the connection. The node keeps those
/// responses up to a sum over every account and drops the ones it kept first above it
/// (`Node::bound_kept_refreshes`): a repeated call with the record of a response that was
/// dropped calls the token address once more.
///
/// The token address call runs on a task of its own. The call waits for it for the time limit
/// of a token address call and then fails with `refresh_failed` and `provider_status` 0; the
/// task goes on until the late limit, when a place among the late tasks is free, and a success
/// that arrives late is kept the same way: the next call with the same record gets it. Without
/// a free place the task is ended at the time limit, as the call is.
///
/// The call holds two shares of the body budget of the node. The share of its request, from
/// the reading of its body to its end (`JsonBody::read_within`). And the share of what it
/// holds while it waits for the token address (`oauth::refresh_share`): the parsed plaintext
/// of its record, which it merges the response into, and the response while it arrives. It
/// takes the second for the largest plaintext a node parses before its entry is created,
/// within the time of its admission, and ends with `capacity_unavailable` without it: no
/// entry, no provider call. It gives back what its plaintext does not need once the record
/// is open, and the exchange holds the rest until it has ended, also after the call gave up
/// waiting for it.
async fn run(node: &Arc<Node>, request: Request) -> Result<Response, ApiError> {
    let admission = Admission::of_request();
    let body = JsonBody::read_within(node, request, &admission).await?;
    let user_id = body.user_id()?;
    let record = record_of(&body, "record")?;
    body.context()?;

    node.ensure_open()?;
    let config = node.operator_config()?;
    let account = node.account(user_id).ok_or(ProtocolError::GrantRequired)?;
    log_store::admit(node, &account).await?;
    let token_share = admission.budget(node, oauth::REFRESH_SHARE_BYTES).await?;
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
            return Ok(json_refreshed(kept));
        }
        let definition = node
            .definitions
            .get(&record.provider)
            .ok_or(ProtocolError::ProviderUnknown)?;
        let credentials = provider_credentials(definition, &config, &record.provider)?;
        // A plaintext, or a token of it, above what a node reads is not judged here: that
        // judgement depends on the content of the plaintext, so the call goes on to its
        // entry and ends after it, without a provider call.
        let bounded = opened
            .parse()
            .and_then(|old| old.within_bounds(definition).map(|()| old));
        let old = match bounded {
            Ok(old) => Some(old),
            Err(Unusable::Invalid) => return Err(ProtocolError::RecordInvalid.into()),
            Err(Unusable::AboveBounds) => None,
        };
        // A record without a refresh token cannot be renewed: the plaintext lacks what this
        // call needs. No entry is created and no provider is called.
        let lacks_refresh_token = old
            .as_ref()
            .is_some_and(|old| old.refresh_token(&definition.token_container).is_none());
        if lacks_refresh_token {
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
    // The call holds no more than the share of this plaintext and of the response.
    let plaintext_room = old.as_ref().map_or(0, OauthPlaintext::room);
    let token_share = narrowed(token_share, oauth::refresh_share(plaintext_room));

    // The token address is called only after the log store confirmed the entry that holds the
    // event. The provider call runs outside the account lock.
    let log = log_store::commit(node, user_id, &account, &[(place, true)])
        .await?
        .into_iter()
        .next()
        .ok_or_else(ApiError::internal)?;
    // A record above what a node reads: the entry of the call is confirmed, and the call ends
    // here. No provider is called.
    let Some(old) = old else {
        return Err(above_bounds());
    };
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
        // The random value of the new record is drawn before the token address is called: a
        // failure of the random source ends the call with `internal` and nothing changed.
        let nonce = node.random_public::<12>()?;
        async move {
            // The share of the plaintext and of the response is held until this exchange has
            // ended: the call may have given up waiting for it by then.
            let _token_share = token_share;
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
            // The token address answered, and the merged token is one a node would not read
            // again: no record is made of it.
            let record = renewed
                .seal(&grant, &id, &nonce, &user_id, &provider)
                .ok_or_else(|| {
                    ApiError::provider(ProtocolError::RefreshFailed, 200, ProviderError::NONE)
                })?;
            // The body of the response is made once: the call answers with it, and the node
            // keeps the same bytes for a repeated call.
            let refreshed = Refreshed {
                record,
                public,
                log,
            }
            .body();
            let kept = node.ensure_open().is_ok()
                && lock(&account).keep_refresh(
                    &grant,
                    &user_id,
                    replay_key,
                    now_ms,
                    refreshed.clone(),
                );
            if kept {
                // The lock of the account is given back: the node drops the responses it
                // kept first while their sum is above its bound, whichever account holds
                // them.
                node.bound_kept_refreshes();
            }
            Ok::<(RefreshedBody, bool), ApiError>((refreshed, kept))
        }
    };
    // The failure of a call whose exchange gave no answer: the token address was called, and
    // what it did is not known.
    let no_answer = || ApiError::provider(ProtocolError::RefreshFailed, 0, ProviderError::NONE);
    let mut guard = ExchangeGuard {
        task: Some(tokio::spawn(exchange)),
    };
    let task = guard.task.as_mut().ok_or_else(no_answer)?;
    // A panic of the exchange is a panic of this call (`joined`): the token address may have
    // answered, and a failure response would say that the call can be made again.
    match tokio::time::timeout(node.limits.token_timeout, joined(task)).await {
        Ok(Some(outcome)) => outcome.map(|(refreshed, _)| json_refreshed(&refreshed)),
        Ok(None) => Err(no_answer()),
        Err(_) => {
            // The time limit passed. The task goes on in a place among the late tasks, and the
            // watcher of that place counts how the exchange ended. Without a free place the
            // exchange is ended here, as the call is.
            let task = guard.task.take().ok_or_else(no_answer)?;
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
            Err(no_answer())
        }
    }
}

/// The exchange of a call while the call waits for it. When the call ends before its time
/// limit decided what becomes of the exchange (the caller closed the connection), the exchange
/// ends with it: no task outlives a call outside the places for late calls. The task of a call
/// that reached its time limit is taken out of the guard first.
struct ExchangeGuard {
    task: Option<JoinHandle<Result<(RefreshedBody, bool), ApiError>>>,
}

impl Drop for ExchangeGuard {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
