//! `POST /v1/peer/export` and `POST /v1/peer/import` (enclave.md 5.13, protocol.md 10.1 and
//! 10.3): the delegations of a node move to another node of the same platform and measurement,
//! or to a node of a later release that the operator's release key signed and the public
//! transparency log recorded.
//!
//! A node that restarts or is replaced starts without user keys. A node that is alive hands it
//! the delegations it holds, so the accounts keep working without their apps. The operator
//! domain carries the attestation responses and the envelope between the two nodes. It learns
//! nothing from them: the envelope is sealed to the sealing key inside the receiving node's
//! verified attestation, and signed by the giving node.
//!
//! Both calls work without the operator configuration. A transfer is not stopped by the limit
//! of unacknowledged entries, like a command.
//!
//! The two nodes write to the same log store: a node takes as its peer only a node whose
//! binding names the log store it has itself (or none, when it has none). The giving node
//! hands a grant over only after the log store confirmed the entry `grant_transferred_out` of
//! that grant.
//!
//! A transfer between two releases goes one way, from the earlier release to the later one.
//! The giving node asks for an endorsement of the later release (`endorsement` of
//! `peer/export`). The receiving node takes delegations from the releases that its program
//! lists as predecessors (`enclave/release/predecessors.json`).

use std::sync::{Arc, Mutex};

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::encoding::b64u_decode;
use credential_enclave_protocol::envelope::{TransferEnvelope, TransferGrant};
use credential_enclave_protocol::keys::key_id;
use credential_enclave_protocol::release::{verify_endorsement, LogEntry, ReleaseMeasurement};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::{limits, ProtocolError};

use super::responses::{Exported, Imported};
use super::{invalid, json_ok, respond, ApiError, JsonBody};
use crate::attest::{verify_peer, Accepted, Peer};
use crate::log_store;
use crate::state::{events, lock, Account, ActiveGrant, GrantState, Handover, Node};

/// Steps 1 to 3a of protocol.md 10.1 under the rule `accepted`: the attestation response of
/// the peer verifies, the peer runs on the platform of this node and, on nitro, has a
/// measurement the rule names, and its binding names the log store of this node.
fn verified_peer(node: &Node, body: &JsonBody, accepted: Accepted<'_>) -> Result<Peer, ApiError> {
    let response = body.object("peer")?;
    Ok(verify_peer(
        node.platform.name(),
        accepted,
        node.log_store.id(),
        response,
    )?)
}

/// Checks 1 to 6 of the giving node (protocol.md 10.3): the release and the measurement that
/// the statement of an endorsement states, when the release key of this program signed that
/// statement, the transparency log of this program recorded the signature, and the release is
/// later than the release of this node. Every failure is `peer_unverified`, also an
/// endorsement that lacks a value or holds one of another type.
fn endorsed_release(
    node: &Node,
    endorsement: &serde_json::Value,
) -> Result<ReleaseMeasurement, ProtocolError> {
    read_endorsed_release(node, endorsement).ok_or(ProtocolError::PeerUnverified)
}

fn read_endorsed_release(
    node: &Node,
    endorsement: &serde_json::Value,
) -> Option<ReleaseMeasurement> {
    let statement = b64u_decode(endorsement.get("statement")?.as_str()?).ok()?;
    let entry = endorsement.get("entry")?;
    let entry = LogEntry {
        body: entry.get("body")?.as_str()?,
        integrated_time: entry.get("integrated_time")?.as_u64()?,
        log_index: entry.get("log_index")?.as_u64()?,
        log_id: entry.get("log_id")?.as_str()?,
        signed_entry_timestamp: entry.get("signed_entry_timestamp")?.as_str()?,
    };
    verify_endorsement(
        &statement,
        &entry,
        &node.lineage.keys(),
        node.release,
        node.now_ms() / 1000,
    )
    .ok()
}

pub async fn export(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run_export(&node, request).await)
}

/// Hands one page of the delegations of this node to the peer whose attestation response the
/// call carries.
///
/// The page holds the accounts with a grant within its time, in `user_id` order after `after`,
/// at most `limit` of them (1 to 1,000, a larger value is read as 1,000). For each account the
/// entry `grant_transferred_out` that names the peer is on its chain, and the log store
/// confirmed it, before its grant enters the transfer. The transfer is signed by this node and
/// sealed to the sealing key of the peer. A page without a grant answers with
/// `envelope: null`. An empty `next` ends the listing.
///
/// When the log store does not confirm the entry of one account of the page, the call ends
/// with `log_store_unavailable` and hands no grant over. The entries stay on their chains, so
/// the next call for the same peer creates none: it writes the ones that wait again.
///
/// There is one entry per grant and peer. A grant keeps the list of the peers it was handed
/// to: a repeated transfer to a peer of that list carries the grant again, so that a transfer
/// whose envelope was lost can be made again, and creates no entry. The list holds at most 64
/// peers. A grant whose list is full is handed to no further peer: its account is left out,
/// without an entry. So repeated calls add no more than 64 entries per grant to a chain.
///
/// The call also works on a closing node: the orderly shutdown hands the delegations on before
/// the node ends. An account whose `final` head was already signed is left out, because a
/// final head promises that no entry follows it.
///
/// Without `endorsement` the peer is a node of the measurement of this node. With it, the peer
/// is the node of a later release: the endorsement passes checks 1 to 6 of protocol.md 10.3,
/// and the peer has the measurement and the release of its statement (check 7). The rule of
/// the same measurement does not apply then. A node of the local platform accepts no peer
/// under an endorsement.
async fn run_export(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let after = body.text_or_empty("after")?;
    let limit = match body.get("limit") {
        None => limits::TRANSFER_GRANTS as u64,
        Some(value) => value
            .as_u64()
            .filter(|limit| *limit >= 1)
            .ok_or_else(|| invalid("limit"))?
            .min(limits::TRANSFER_GRANTS as u64),
    } as usize;

    // 1 to 3a
    let own = node.platform.measurement();
    let peer = match body.get("endorsement") {
        None => verified_peer(
            node,
            &body,
            Accepted::Own {
                measurement: own.as_ref(),
                predecessors: &[],
            },
        )?,
        Some(endorsement) => {
            if !endorsement.is_object() {
                return Err(invalid("endorsement"));
            }
            let later = endorsed_release(node, endorsement)?;
            verified_peer(node, &body, Accepted::Later(&later))?
        }
    };
    // 4
    if peer.sign_public() == node.keys.sign_public() {
        return Err(ApiError::with_message(
            ProtocolError::InvalidRequest,
            "the peer is this node",
        ));
    }

    // A node that cannot write to its log store hands no delegation over.
    let now_ms = node.now_ms();
    node.log_store.ensure_ready(now_ms)?;

    // 5: the page is chosen first, and every random value is drawn before a chain grows, so a
    // failure of the random source changes nothing.
    let to = peer.node();
    let to_public = peer.sign_public();
    let mut candidates = node.accounts_after(after).into_iter().peekable();
    let mut page = Vec::new();
    let mut last = String::new();
    while page.len() < limit {
        let Some((user_id, account)) = candidates.next() else {
            break;
        };
        if transferable(&mut lock(&account), &to_public, now_ms) {
            page.push((user_id.clone(), account));
        }
        last = user_id;
    }
    let next = if candidates.peek().is_some() {
        last
    } else {
        String::new()
    };
    let envelope_seed = node.random_secret::<32>()?;
    let mut seeds = Vec::with_capacity(page.len());
    for _ in 0..page.len() {
        seeds.push(node.random_secret::<32>()?);
    }

    // The entries. One entry per grant and peer: the first transfer of a grant to the peer
    // puts the peer on the list of the grant and creates the entry. A later one finds both.
    let mut entries = Vec::with_capacity(page.len());
    let mut handed: Vec<(String, Arc<Mutex<Account>>, u64)> = Vec::with_capacity(page.len());
    for ((user_id, account), seed) in page.into_iter().zip(seeds) {
        let seq = {
            let mut account = lock(&account);
            // The account was free between the choice of the page and this lock.
            if !transferable(&mut account, &to_public, now_ms) {
                continue;
            }
            let next_seq = account.head.seq + 1;
            let GrantState::Active(held) = &mut account.grant else {
                continue;
            };
            match held.handed_to(&to_public) {
                Some(seq) => seq,
                None => {
                    held.exported_to.push(Handover {
                        peer: to_public,
                        seq: next_seq,
                    });
                    let (key_id, log_pk) = (key_id(&held.sign_pk), held.log_pk);
                    entries.push(node.append_entry_seeded(
                        &mut account,
                        &user_id,
                        &key_id,
                        &log_pk,
                        now_ms,
                        &events::grant_transferred_out(&to),
                        &seed,
                    ));
                    next_seq
                }
            }
        };
        handed.push((user_id, account, seq));
    }

    // No grant enters the transfer before the log store confirmed the entry of each account
    // of the page: the entries this call created, and those of an earlier call that still
    // wait.
    let awaited: Vec<(&str, &Mutex<Account>, u64)> = handed
        .iter()
        .map(|(user_id, account, seq)| (user_id.as_str(), account.as_ref(), *seq))
        .collect();
    log_store::confirm_each(node, &awaited).await?;

    let mut grants: Vec<TransferGrant> = Vec::with_capacity(handed.len());
    for (user_id, account, _) in handed {
        let mut account = lock(&account);
        // The account was free while the entries were written: a revoke that was answered in
        // between leaves no transfer behind it, and a grant that took the place of the one
        // the entry was made for is not handed over under that entry.
        if !transferable(&mut account, &to_public, now_ms) {
            continue;
        }
        let GrantState::Active(held) = &account.grant else {
            continue;
        };
        let recorded = held
            .handed_to(&to_public)
            .is_some_and(|seq| account.is_confirmed(seq));
        if !recorded {
            continue;
        }
        grants.push(TransferGrant {
            user_id,
            sign_pk: held.sign_pk,
            log_pk: held.log_pk,
            custody: held.custody,
            user_key: held.user_key.clone(),
            not_after_ms: held.not_after_ms,
        });
    }

    // 6: the user keys leave this node inside the seal to the verified peer (sink K2 of the
    // egress policy).
    let envelope = if grants.is_empty() {
        None
    } else {
        Some(peer.seal_transfer(&node.keys, now_ms, &grants, &envelope_seed)?)
    };
    Ok(json_ok(&Exported {
        envelope,
        entries,
        next,
    }))
}

/// True when a transfer hands the delegation of this account on to the peer with the signing
/// public key `to`: it has a grant within its time, its `final` head was not signed yet (a
/// final head promises that no entry follows it, and a transfer is not made without its
/// entry), and the grant was handed to that peer before or to fewer than 64 peers.
fn transferable(account: &mut Account, to: &[u8; 32], now_ms: u64) -> bool {
    if !account.has_grant(now_ms) || account.final_head.is_some() {
        return false;
    }
    match &account.grant {
        GrantState::Active(held) => {
            held.handed_to(to).is_some() || held.exported_to.len() < limits::TRANSFER_PEERS
        }
        _ => false,
    }
}

pub async fn import(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run_import(&node, request).await)
}

/// Takes the delegations of a transfer that the peer whose attestation response the call
/// carries made for this node.
///
/// The entry `grant_transferred_in` of a grant this call puts in place is not written to the
/// log store by this call: it is a pending entry, and the next write of the account takes it
/// along. The entry that says where the grant went is the `grant_transferred_out` of the
/// giving node, which the log store confirmed before the transfer was made.
///
/// A grant of the custody of this node whose time has not passed is taken when the account has
/// no grant within its time here and never revoked here: the entry `grant_transferred_in` is
/// created and the grant is kept, its end moved to 30 days from now when it lies beyond that.
/// When the account already has the grant of the same signing key, the later end stays and no
/// entry is made. A grant of another signing key is never replaced by a transfer, and an
/// account that revoked on this node takes no transfer at all, also after its revocation
/// marker was replaced by a grant: an envelope can be kept and sent again, and what a revoke
/// ended only a grant command brings back. `imported` is the number of grants this call put in
/// place, one per entry.
///
/// When the orderly shutdown starts while the call runs, it stops there and answers with what
/// it took until then.
///
/// The peer is a node of the measurement of this node, or a node of a release that this
/// program lists as a predecessor: its measurement is the measurement of an element of the
/// list, and its binding names the release of that element (protocol.md 10.3).
async fn run_import(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let envelope = body.object("envelope")?;
    node.ensure_open()?;

    // 1
    let own = node.platform.measurement();
    let peer = verified_peer(
        node,
        &body,
        Accepted::Own {
            measurement: own.as_ref(),
            predecessors: &node.lineage.predecessors,
        },
    )?;
    // 2
    let envelope = TransferEnvelope::from_value(envelope)?;
    let transfer = peer.open_transfer(&node.keys, &envelope)?;

    // 3: every random value is drawn before a chain grows.
    let now_ms = node.now_ms();
    let latest_ms = now_ms.saturating_add(limits::GRANT_MAX_MS);
    let from = peer.node();
    let mut seeds: Vec<Secret<[u8; 32]>> = Vec::with_capacity(transfer.grants.len());
    for _ in 0..transfer.grants.len() {
        seeds.push(node.random_secret::<32>()?);
    }
    let mut entries = Vec::new();
    for (grant, seed) in transfer.grants.into_iter().zip(seeds) {
        if grant.custody != node.custody || grant.not_after_ms <= now_ms {
            continue;
        }
        let not_after_ms = grant.not_after_ms.min(latest_ms);
        let account = node.account_or_create(&grant.user_id);
        let mut account = lock(&account);
        if node.ensure_open().is_err() {
            break;
        }
        if account.revoked_here {
            continue;
        }
        account.expire(now_ms);
        match &mut account.grant {
            GrantState::Active(held) => {
                if held.sign_pk == grant.sign_pk {
                    held.not_after_ms = held.not_after_ms.max(not_after_ms);
                }
            }
            GrantState::Revoked { .. } => {}
            GrantState::None | GrantState::Expired { .. } => {
                let key_id = key_id(&grant.sign_pk);
                entries.push(node.append_entry_seeded(
                    &mut account,
                    &grant.user_id,
                    &key_id,
                    &grant.log_pk,
                    now_ms,
                    &events::grant_transferred_in(&from, not_after_ms, grant.custody),
                    &seed,
                ));
                let seq = account.head.seq;
                account.leave_pending(seq);
                account.grant = GrantState::Active(ActiveGrant {
                    key_id,
                    sign_pk: grant.sign_pk,
                    log_pk: grant.log_pk,
                    custody: grant.custody,
                    user_key: grant.user_key.clone(),
                    not_after_ms,
                    exported_to: Vec::new(),
                });
            }
        }
    }
    Ok(json_ok(&Imported {
        imported: entries.len(),
        entries,
    }))
}
