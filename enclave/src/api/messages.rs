//! `POST /v1/messages` (enclave.md 5.3): the commands `grant` and `revoke` of an app, carried
//! by the backend in a sealed envelope (protocol.md 5.3 and 5.4).
//!
//! A command that fails is still answered with 200: the reply is signed and has `ok` false, so
//! the app receives a failure it can verify. Only a malformed call and a closing node are
//! answered with a failure status.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::encoding::Signed;
use credential_enclave_protocol::envelope::{
    open_command, reply, Command, Envelope, Grant, ReplyBody, ReplyHead, Revoke,
};
use credential_enclave_protocol::keys::key_id;
use credential_enclave_protocol::log::Head;
use credential_enclave_protocol::{limits, ProtocolError};

use super::responses::Messages;
use super::{json_ok, respond, ApiError, JsonBody};
use crate::log_store;
use crate::state::{events, lock, ActiveGrant, GrantState, GrantStatus, Node};

/// What a command led to: the fields of the reply and the entry it created.
struct Outcome {
    kind: &'static str,
    failure: Option<ProtocolError>,
    user_id: String,
    challenge: String,
    key_id: String,
    not_after_ms: u64,
    head: Head,
    entry: Option<Signed>,
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
            head: Head::EMPTY,
            entry: None,
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
            head: ReplyHead::from(&outcome.head),
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
        entry: outcome.entry,
        grant,
    }))
}

fn head_of(node: &Node, user_id: &str) -> Head {
    node.account(user_id)
        .map_or(Head::EMPTY, |account| lock(&account).head)
}

/// Steps 10 to 15 of protocol.md 5.3.
///
/// The node puts the user key in place only after the log store confirmed the entry
/// `grant_accepted`. The entry is created inside the lock of the account, the write runs
/// outside it, and the grant is put in place inside the lock again. A revoke the node accepted
/// in between stands: the challenge of this grant is older than that revoke.
async fn accept_grant(
    node: &Node,
    user_id: &str,
    grant: Grant,
    now_ms: u64,
) -> Result<Outcome, ApiError> {
    let key_id = key_id(&grant.sign_pk);
    let failed = |failure: ProtocolError, head: Head| Outcome {
        kind: "grant_reply",
        failure: Some(failure),
        user_id: grant.user_id.clone(),
        challenge: grant.challenge.clone(),
        key_id: key_id.clone(),
        not_after_ms: 0,
        head,
        entry: None,
    };
    // 10: a node takes the user key of its own custody only. Like the checks before it, this
    // one says that the node cannot take the command, so the reply names no user, challenge
    // or key (protocol.md 5.5).
    if grant.custody != node.custody {
        return Ok(Outcome::unopened(ProtocolError::CustodyMismatch));
    }
    // 11
    if grant.user_id != user_id {
        return Ok(failed(ProtocolError::UserMismatch, Head::EMPTY));
    }
    // A node that cannot write to its log store takes no grant. This refusal comes before the
    // challenge is used: the same command passes once the node can write.
    if node.log_store.ensure_ready(now_ms).is_err() {
        return Ok(failed(
            ProtocolError::LogStoreUnavailable,
            head_of(node, user_id),
        ));
    }
    // 12: the challenge is one this node issued, within its 300 seconds, and is used here.
    let Some(issued) = node.take_challenge(&grant.challenge) else {
        return Ok(failed(ProtocolError::BadChallenge, head_of(node, user_id)));
    };
    let account = node.account_or_create(user_id);
    let (entry, seq, not_after_ms) = {
        let mut account = lock(&account);
        // 12, for a grant: the challenge was issued after the last revoke of the account that
        // this node accepted. A sealed grant is a value its carrier can keep: one that was
        // made before a revoke does not bring the user key back after it. The challenge
        // stays used.
        if issued < account.revoke_serial {
            return Ok(failed(ProtocolError::BadChallenge, account.head));
        }
        // 13: a grant that already ended is refused. A grant that ends later than 30 days
        // from now is taken with its end moved to that limit: the app computes the end from
        // the time of the attestation document, not from this clock.
        if grant.not_after_ms <= now_ms {
            return Ok(failed(ProtocolError::BadExpiry, account.head));
        }
        let not_after_ms = grant
            .not_after_ms
            .min(now_ms.saturating_add(limits::GRANT_MAX_MS));
        // 14: the entry.
        node.ensure_open()?;
        let entry = node.append_entry(
            &mut account,
            user_id,
            &key_id,
            &grant.log_pk,
            now_ms,
            &events::grant_accepted(not_after_ms, grant.custody),
        )?;
        (entry, account.head.seq, not_after_ms)
    };
    // 14: the user key is put in place only after the log store confirmed the entry. When it
    // does not, the entry stays on the chain as a pending entry and the node holds no key.
    if log_store::confirm(node, user_id, &account, &[seq])
        .await
        .is_err()
    {
        let head = lock(&account).head;
        return Ok(failed(ProtocolError::LogStoreUnavailable, head));
    }
    let mut account = lock(&account);
    // The account was free while the entry was written. A revoke the node accepted in that
    // time stands: the challenge of this grant was issued before it (step 12).
    if issued < account.revoke_serial {
        return Ok(failed(ProtocolError::BadChallenge, account.head));
    }
    // The new grant replaces the grant and the revocation marker that were there. Dropping the
    // old grant overwrites its user key with zeros. The kept `refresh` responses of a grant of
    // another key go with it. The new grant was handed to no node yet.
    let same_key = matches!(
        &account.grant,
        GrantState::Active(held) if held.sign_pk == grant.sign_pk
    );
    if !same_key {
        account.forget_refreshes();
    }
    account.grant = GrantState::Active(ActiveGrant {
        key_id: key_id.clone(),
        sign_pk: grant.sign_pk,
        log_pk: grant.log_pk,
        custody: grant.custody,
        user_key: grant.user_key.clone(),
        not_after_ms,
        exported_to: Vec::new(),
    });
    // 15: the reply carries the end the node accepted.
    Ok(Outcome {
        kind: "grant_reply",
        failure: None,
        user_id: grant.user_id.clone(),
        challenge: grant.challenge.clone(),
        key_id,
        not_after_ms,
        head: account.head,
        entry: Some(entry),
    })
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
    let outcome = |failure: Option<ProtocolError>, head: Head, entry: Option<Signed>| Outcome {
        kind: "revoke_reply",
        failure,
        user_id: revoke.user_id.clone(),
        challenge: revoke.challenge.clone(),
        key_id: key_id.clone(),
        not_after_ms: 0,
        head,
        entry,
    };
    if revoke.user_id != user_id {
        return Ok(outcome(
            Some(ProtocolError::UserMismatch),
            Head::EMPTY,
            None,
        ));
    }
    if node.take_challenge(&revoke.challenge).is_none() {
        return Ok(outcome(
            Some(ProtocolError::BadChallenge),
            head_of(node, user_id),
            None,
        ));
    }
    let account = node.account_or_create(user_id);
    let (head, entry) = {
        let mut account = lock(&account);
        node.ensure_open()?;
        // A grant whose time passed is no grant.
        account.expire(now_ms);
        // A revoke of an account without a grant passes without a check and creates no entry.
        // With a grant, the revoke is signed by the key of that grant, and the entry is sealed
        // to the log key of the grant that ends here.
        let sealed_to = match &account.grant {
            GrantState::Active(grant) => {
                if grant.sign_pk != revoke.sign_pk {
                    return Ok(outcome(
                        Some(ProtocolError::BadSignature),
                        account.head,
                        None,
                    ));
                }
                Some((grant.key_id.clone(), grant.log_pk))
            }
            GrantState::None | GrantState::Expired { .. } | GrantState::Revoked { .. } => None,
        };
        let entry = match sealed_to {
            Some((grant_key_id, log_pk)) => Some(node.append_entry(
                &mut account,
                user_id,
                &grant_key_id,
                &log_pk,
                now_ms,
                &events::grant_revoked(),
            )?),
            None => None,
        };
        // Replacing the state drops the grant: its user key is overwritten with zeros. The
        // kept `refresh` responses go with it.
        account.forget_refreshes();
        account.grant = GrantState::Revoked {
            key_id: key_id.clone(),
            sign_pk: revoke.sign_pk,
        };
        // The marker can be replaced by a later grant. That the account revoked here stays
        // known: no transfer brings a delegation back to this node for it.
        account.revoked_here = true;
        // Neither does a grant that was made before this moment: the serial drawn here, under
        // the lock of the account, is larger than the serial of every challenge issued so far.
        account.revoke_serial = node.next_serial();
        (account.head, entry)
    };
    // The key is gone. The entry is written when the store takes it, now or with a later
    // write of the account: a revoke is never refused for the log store.
    if entry.is_some() {
        let _ = log_store::confirm(node, user_id, &account, &[head.seq]).await;
    }
    Ok(outcome(None, head, entry))
}
