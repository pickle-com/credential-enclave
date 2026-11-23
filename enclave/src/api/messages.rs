//! `POST /v1/messages` (enclave.md 5.3): the commands `grant` and `revoke` of an app, carried
//! by the backend in a sealed envelope (protocol.md 5.3 and 5.4).
//!
//! A command that fails is still answered with 200: the reply is signed and has `ok` false, so
//! the app receives a failure it can verify. Only a malformed call and a closing node are
//! answered with a failure status.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::envelope::{
    open_command, reply, Command, Envelope, Grant, ReplyBody, Revoke,
};
use credential_enclave_protocol::keys::key_id;
use credential_enclave_protocol::log::EntryKind;
use credential_enclave_protocol::{limits, ProtocolError};

use super::responses::{LogRef, Messages};
use super::{json_ok, respond, ApiError, JsonBody};
use crate::log_store;
use crate::state::{events, lock, ActiveGrant, EventPlace, GrantState, GrantStatus, Node};

/// What a command led to: the fields of the reply and the event it created.
struct Outcome {
    kind: &'static str,
    failure: Option<ProtocolError>,
    user_id: String,
    challenge: String,
    key_id: String,
    not_after_ms: u64,
    log: Option<LogRef>,
}

/// The `log` object of a control event: the entry the event forms on its own. A control
/// event is never in an open batch, so its place always names an entry.
fn log_of(place: &EventPlace) -> Option<LogRef> {
    Some(LogRef {
        seq: place.seq()?,
        index: place.index(),
        created: true,
    })
}

impl Outcome {
    /// A failure of the checks 1 to 10 of protocol.md 5.3: the node could not verify the
    /// command or cannot take it, so the reply carries no `user_id`, `challenge` or `key_id`.
    /// The reply type of such a command is `grant_reply`.
    fn unopened(failure: ProtocolError) -> Outcome {
        Outcome {
            kind: "grant_reply",
            failure: Some(failure),
            user_id: String::new(),
            challenge: String::new(),
            key_id: String::new(),
            not_after_ms: 0,
            log: None,
        }
    }
}

pub async fn messages(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let user_id = body.user_id()?;
    let envelope = body.object("envelope")?;
    node.ensure_open()?;
    let now_ms = node.now_ms();

    let command =
        Envelope::from_value(envelope).and_then(|envelope| open_command(&node.keys, &envelope));
    let outcome = match command {
        Err(failure) => Outcome::unopened(failure),
        Ok(Command::Grant(grant)) => accept_grant(node, user_id, grant, now_ms).await?,
        Ok(Command::Revoke(revoke)) => accept_revoke(node, user_id, revoke, now_ms).await?,
    };

    let signed = reply(
        &node.keys,
        &ReplyBody {
            v: 1,
            kind: outcome.kind.to_string(),
            ok: outcome.failure.is_none(),
            code: outcome
                .failure
                .map(|failure| failure.code().to_string())
                .unwrap_or_default(),
            node: node.node.clone(),
            user_id: outcome.user_id,
            challenge: outcome.challenge,
            key_id: outcome.key_id,
            not_after_ms: outcome.not_after_ms,
            time_ms: now_ms,
        },
    );
    // The plaintext copy for the caller is the state of the account the call named.
    let grant = match node.account(user_id) {
        Some(account) => lock(&account).status(now_ms).for_messages(),
        None => GrantStatus::none(),
    };
    Ok(json_ok(&Messages {
        reply: signed,
        log: outcome.log,
        grant,
    }))
}

/// Steps 10 to 15 of protocol.md 5.3.
///
/// A grant of the key of the grant in force renews that grant: its end becomes the end of the
/// command, earlier or later than the end it had, and the node creates no entry and writes
/// nothing. The entry `grant_accepted`
/// that the log store confirmed when the node took the user key of that grant names the key,
/// and the node holds the same key before and after the command.
///
/// Every other grant puts a user key into the memory of the node (the account has no grant,
/// its grant ended by its time or by a revoke, or its grant has another key). The node does so
/// only after the log store confirmed the entry `grant_accepted`. The entry is created inside
/// the lock of the account, the write runs outside it, and the grant is put in place inside
/// the lock again. A revoke the node accepted in between stands: the challenge of this grant
/// is older than that revoke.
async fn accept_grant(
    node: &Node,
    user_id: &str,
    grant: Grant,
    now_ms: u64,
) -> Result<Outcome, ApiError> {
    let key_id = key_id(&grant.sign_pk);
    let answered =
        |failure: Option<ProtocolError>, not_after_ms: u64, log: Option<LogRef>| Outcome {
            kind: "grant_reply",
            failure,
            user_id: grant.user_id.clone(),
            challenge: grant.challenge.clone(),
            key_id: key_id.clone(),
            not_after_ms,
            log,
        };
    let failed = |failure: ProtocolError| answered(Some(failure), 0, None);
    // 10: a node takes the user key of its own custody only. Like the checks before it, this
    // one says that the node cannot take the command, so the reply names no user, challenge
    // or key (protocol.md 5.5).
    if grant.custody != node.custody {
        return Ok(Outcome::unopened(ProtocolError::CustodyMismatch));
    }
    // 11
    if grant.user_id != user_id {
        return Ok(failed(ProtocolError::UserMismatch));
    }
    // 11a: a node that cannot write an entry to its log store takes no grant: it has no log
    // store, no credentials within their time, or no node document in the store. This refusal
    // comes before the challenge is used: the same command passes once the node can write.
    if node.log_store.ensure_ready(now_ms).is_err() {
        return Ok(failed(ProtocolError::LogStoreUnavailable));
    }
    // 12: the challenge is one this node issued, within its 300 seconds, and is used here.
    let Some(issued) = node.take_challenge(&grant.challenge) else {
        return Ok(failed(ProtocolError::BadChallenge));
    };
    let account = node.account_or_create(user_id);
    let (place, not_after_ms) = {
        let mut account = lock(&account);
        // 12, for a grant: the challenge was issued after the last revoke of the account that
        // this node accepted. A sealed grant is a value its carrier can keep: one that was
        // made before a revoke does not bring the user key back after it. The challenge
        // stays used.
        if issued < account.revoke_serial {
            return Ok(failed(ProtocolError::BadChallenge));
        }
        // 13: a grant that already ended is refused. A grant that ends later than 30 days
        // from now is taken with its end moved to that limit: the app computes the end from
        // the time of the attestation document, not from this clock.
        if grant.not_after_ms <= now_ms {
            return Ok(failed(ProtocolError::BadExpiry));
        }
        let not_after_ms = grant
            .not_after_ms
            .min(now_ms.saturating_add(limits::GRANT_MAX_MS));
        node.ensure_open()?;
        // A grant whose time passed is no grant: it ends here, with the merge keys and the
        // kept `refresh` responses of the account, before the state is read. A grant of the
        // same key that follows it is not a renewal and takes over nothing of it.
        account.expire(now_ms);
        // 13a: a grant of the key of the grant in force renews it, without an entry.
        if let GrantState::Active(held) = account.grant_mut() {
            if held.sign_pk == grant.sign_pk {
                held.not_after_ms = not_after_ms;
                return Ok(answered(None, held.not_after_ms, None));
            }
        }
        // 14: the entry (a control entry of its own; an open batch of the account is closed
        // before it).
        let place = node.create_event(
            &mut account,
            user_id,
            &key_id,
            &grant.log_pk,
            now_ms,
            EntryKind::Control,
            events::grant_accepted(not_after_ms, grant.custody),
        )?;
        (place, not_after_ms)
    };
    // 14: the user key is put in place only after the log store confirmed the entry. When it
    // does not, the entry is a pending entry and the node holds no key of this grant.
    let log = match log_store::commit(node, user_id, &account, &[(place, true)]).await {
        Ok(refs) => refs.into_iter().next().ok_or_else(ApiError::internal)?,
        Err(_) => return Ok(failed(ProtocolError::LogStoreUnavailable)),
    };
    let mut account = lock(&account);
    // The account was free while the entry was written. A revoke the node accepted in that
    // time stands: the challenge of this grant was issued before it (step 12).
    if issued < account.revoke_serial {
        return Ok(failed(ProtocolError::BadChallenge));
    }
    account.expire(now_ms);
    // A grant of the same key that another command put in place in that time is renewed: its
    // end becomes the end of this command, and what the node kept for it stays.
    if let GrantState::Active(held) = account.grant_mut() {
        if held.sign_pk == grant.sign_pk {
            held.not_after_ms = not_after_ms;
            return Ok(answered(None, held.not_after_ms, Some(log)));
        }
    }
    // The new grant replaces the grant and the revocation marker that were there. Dropping the
    // old grant overwrites its user key with zeros, and the kept `refresh` responses and the
    // merge window of a grant of another key go with it: a request under the new grant merges
    // into no event made under another key. The new grant was handed to no node yet.
    account.forget_refreshes();
    account.clear_recent();
    account.set_grant(GrantState::Active(ActiveGrant {
        key_id: key_id.clone(),
        sign_pk: grant.sign_pk,
        log_pk: grant.log_pk,
        custody: grant.custody,
        user_key: grant.user_key.clone(),
        not_after_ms,
        exported_to: Vec::new(),
    }));
    // 15: the reply carries the end the node accepted.
    Ok(answered(None, not_after_ms, Some(log)))
}

/// Steps 11 and 12 of protocol.md 5.3, then protocol.md 5.4.
///
/// A revoke does not wait for the log store: the user key is erased inside the lock of the
/// account, whatever the store answers afterwards. The node then tries to write the entry
/// `grant_revoked`. When the store does not confirm it, the entry is a pending entry and the
/// reply is the same.
async fn accept_revoke(
    node: &Node,
    user_id: &str,
    revoke: Revoke,
    now_ms: u64,
) -> Result<Outcome, ApiError> {
    let key_id = key_id(&revoke.sign_pk);
    let outcome = |failure: Option<ProtocolError>, log: Option<LogRef>| Outcome {
        kind: "revoke_reply",
        failure,
        user_id: revoke.user_id.clone(),
        challenge: revoke.challenge.clone(),
        key_id: key_id.clone(),
        not_after_ms: 0,
        log,
    };
    if revoke.user_id != user_id {
        return Ok(outcome(Some(ProtocolError::UserMismatch), None));
    }
    if node.take_challenge(&revoke.challenge).is_none() {
        return Ok(outcome(Some(ProtocolError::BadChallenge), None));
    }
    let account = node.account_or_create(user_id);
    let place = {
        let mut account = lock(&account);
        node.ensure_open()?;
        // A grant whose time passed is no grant.
        account.expire(now_ms);
        // A revoke of an account without a grant passes without a check and creates no entry.
        // With a grant, the revoke is signed by the key of that grant, and the entry is sealed
        // to the log key of the grant that ends here.
        let sealed_to = match account.grant() {
            GrantState::Active(grant) => {
                if grant.sign_pk != revoke.sign_pk {
                    return Ok(outcome(Some(ProtocolError::BadSignature), None));
                }
                Some((grant.key_id.clone(), grant.log_pk))
            }
            GrantState::None | GrantState::Expired { .. } | GrantState::Revoked { .. } => None,
        };
        let place = match sealed_to {
            Some((grant_key_id, log_pk)) => Some(node.create_event(
                &mut account,
                user_id,
                &grant_key_id,
                &log_pk,
                now_ms,
                EntryKind::Control,
                events::grant_revoked(),
            )?),
            None => None,
        };
        // Replacing the state drops the grant: its user key is overwritten with zeros. The
        // kept `refresh` responses and the merge window go with it.
        account.forget_refreshes();
        account.clear_recent();
        account.set_grant(GrantState::Revoked {
            key_id: key_id.clone(),
            sign_pk: revoke.sign_pk,
        });
        // The marker can be replaced by a later grant. That the account revoked here stays
        // known: no transfer brings a delegation back to this node for it.
        account.revoked_here = true;
        // Neither does a grant that was made before this moment: the serial drawn here, under
        // the lock of the account, is larger than the serial of every challenge issued so far.
        account.revoke_serial = node.next_serial();
        place
    };
    // The key is gone. The entry is written when the store takes it, now or with a later
    // write of the account: a revoke is never refused for the log store.
    let log = place.as_ref().and_then(log_of);
    if let Some(place) = place {
        let _ = log_store::commit(node, user_id, &account, &[(place, true)]).await;
    }
    Ok(outcome(None, log))
}
