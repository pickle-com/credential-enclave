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
//! Both calls work without the operator configuration.
//!
//! The two nodes write to the same log store: a node takes as its peer only a node whose
//! binding names the log store it has itself (or none, when it has none).
//!
//! A transfer between two nodes of one measurement creates no entry and writes nothing to the
//! log store: the user key moves between two instances of one source, which the account
//! accepted when it delegated, and what a reader of the store needs of either node is its
//! node document. A node that restarted is filled this way without a write.
//!
//! A transfer between two releases goes one way, from the earlier release to the later one,
//! and is on the log of the account. The giving node asks for an endorsement of the later
//! release (`endorsement` of `peer/export`) and hands a grant over only after the log store
//! confirmed the entry `grant_transferred_out` of that grant, which names the receiving node,
//! its release and its measurement. The receiving node takes delegations from the releases
//! that its program lists as predecessors (`enclave/release/predecessors.json`) and creates
//! the entry `grant_transferred_in` for each. Such a transfer is not stopped by the limit of
//! pending entries, like a command.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::encoding::b64u_decode;
use credential_enclave_protocol::envelope::{TransferEnvelope, TransferGrant};
use credential_enclave_protocol::keys::key_id;
use credential_enclave_protocol::log::EntryKind;
use credential_enclave_protocol::release::{verify_endorsement, LogEntry, ReleaseMeasurement};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::{limits, ProtocolError};

use super::responses::{AccountLogRef, Exported, Imported};
use super::{invalid, json_ok, limit_of, respond, subset_of, ApiError, JsonBody};
use crate::attest::{verify_peer, Accepted, Peer, Program};
use crate::log_store;
use crate::state::{
    events, lock, Account, AccountLock, ActiveGrant, EventPlace, GrantState, Handover, Node,
};
use crate::subset::Subset;

/// The `seq` of the control entry a place names. A control event is never in an open batch,
/// so its place always names an entry.
fn seq_of(place: &EventPlace) -> Result<u64, ApiError> {
    place.seq().ok_or_else(ApiError::internal)
}

/// Steps 1 to 3b of protocol.md 10.1 under the rule `accepted`: the attestation response of
/// the peer verifies, the peer runs on the platform of this node and, on nitro, has a
/// measurement the rule names, and its binding names the log store of this node and a role
/// under which a node holds delegations.
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
/// at most `limit` of them (1 to 1,000, a larger value is read as 1,000). With a `subset`
/// (enclave.md 5.13), the page holds only the accounts that the subset gives to the peer: the
/// share of the peer, so that a transfer carries no grant the peer would not keep. The
/// transfer is signed by this node and sealed to the sealing key of the peer. A page without a
/// grant answers with `envelope: null`. An empty `next` ends the listing.
///
/// Without `endorsement` the peer is a node of the measurement of this node: the same program.
/// The call creates no entry and writes nothing to the log store, and it works while the node
/// cannot write to its log store.
///
/// With `endorsement` the peer is the node of a later release: the endorsement passes checks 1
/// to 6 of protocol.md 10.3, and the peer has the measurement and the release of its statement
/// (check 7). The rule of the same measurement does not apply then, and a node of the local
/// platform accepts no peer under an endorsement. For each account the entry
/// `grant_transferred_out` that names the peer, its release and its measurement exists, and
/// the log store confirmed it, before its grant enters the transfer. When the log store does
/// not confirm the entry of one account of the page, the call ends with
/// `log_store_unavailable` and hands no grant over; the entries are pending entries, so the
/// next call for the same peer creates none: it writes the ones that wait again.
///
/// There is one entry per grant and peer of a later release. A grant keeps the list of the
/// peers of a later release it was handed to: a repeated transfer to a peer of that list
/// carries the grant again, so that a transfer whose envelope was lost can be made again, and
/// creates no entry. The list holds at most 64 peers. A grant whose list is full is handed to
/// no further peer of a later release: its account is left out, without an entry. So repeated
/// calls add no more than 64 entries per grant.
///
/// The call also works on a closing node: the orderly shutdown hands the delegations on before
/// the node ends.
async fn run_export(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let after = body.text_or_empty("after")?;
    let limit = limit_of(&body, limits::TRANSFER_GRANTS)?;
    let subset = subset_of(&body)?;

    // 1 to 3b
    let own = node.platform.measurement();
    let (peer, later) = match body.get("endorsement") {
        None => (
            verified_peer(
                node,
                &body,
                Accepted::Own {
                    measurement: own.as_ref(),
                    predecessors: &[],
                },
            )?,
            None,
        ),
        Some(endorsement) => {
            if !endorsement.is_object() {
                return Err(invalid("endorsement"));
            }
            let later = endorsed_release(node, endorsement)?;
            (
                verified_peer(node, &body, Accepted::Later(&later))?,
                Some(later),
            )
        }
    };
    Ok(json_ok(
        &export_to(node, &peer, later.as_ref(), after, limit, subset.as_ref()).await?,
    ))
}

/// Steps 4 to 6 of protocol.md 10.1 for a peer the call verified: one page of the delegations
/// of this node for `peer`, which is a node of the measurement of this node when `later` is
/// `None`, and the node of the later release `later` otherwise.
pub(crate) async fn export_to(
    node: &Node,
    peer: &Peer,
    later: Option<&ReleaseMeasurement>,
    after: &str,
    limit: usize,
    subset: Option<&Subset>,
) -> Result<Exported, ApiError> {
    // 4
    if peer.sign_public() == node.keys.sign_public() {
        return Err(ApiError::with_message(
            ProtocolError::InvalidRequest,
            "the peer is this node",
        ));
    }

    // 4a: a node that cannot write an entry to its log store hands no delegation to a later
    // release. A transfer to a node of its own measurement needs no entry and no write.
    let now_ms = node.now_ms();
    if later.is_some() {
        node.log_store.ensure_ready(now_ms)?;
    }

    // 5: the page is chosen first, and every random value is drawn before an entry is
    // created, so a failure of the random source changes nothing.
    let to = peer.node();
    let to_public = peer.sign_public();
    let recorded = later.is_some();
    let mut candidates = node.accounts_after(after).peekable();
    let mut page = Vec::new();
    let mut last = String::new();
    while page.len() < limit {
        let Some((user_id, account)) = candidates.next() else {
            break;
        };
        if in_share(subset, &user_id)
            && transferable(&mut lock(&account), &to_public, recorded, now_ms)
        {
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

    // The entries of a transfer to a later release. One entry per grant and peer: the first
    // transfer of a grant to the peer puts the peer on the list of the grant and creates the
    // entry (a control entry, which closes an open batch of the account before it). A later
    // one finds both.
    let mut logs = Vec::new();
    if let Some(later) = later {
        let mut seeds = Vec::with_capacity(page.len());
        for _ in 0..page.len() {
            seeds.push(node.random_secret::<32>()?);
        }
        let mut handed: Vec<(&AccountLock, u64)> = Vec::with_capacity(page.len());
        for ((user_id, account), seed) in page.iter().zip(seeds) {
            let mut guard = lock(account);
            // The account was free between the choice of the page and this lock.
            if !transferable(&mut guard, &to_public, recorded, now_ms) {
                continue;
            }
            let (handed_before, key_id, log_pk) = match guard.grant() {
                GrantState::Active(held) => (
                    held.handed_to(&to_public),
                    key_id(&held.sign_pk),
                    held.log_pk,
                ),
                _ => continue,
            };
            let seq = match handed_before {
                Some(seq) => seq,
                None => {
                    let place = node.create_event_seeded(
                        &mut guard,
                        user_id,
                        &key_id,
                        &log_pk,
                        now_ms,
                        EntryKind::Control,
                        events::grant_transferred_out(&to, later),
                        &seed,
                    )?;
                    let seq = seq_of(&place)?;
                    if let GrantState::Active(held) = guard.grant_mut() {
                        held.exported_to.push(Handover {
                            peer: to_public,
                            seq,
                        });
                    }
                    logs.push(AccountLogRef {
                        user_id: user_id.clone(),
                        seq,
                    });
                    seq
                }
            };
            handed.push((account.as_ref(), seq));
        }
        // No grant enters the transfer before the log store confirmed the entry of each
        // account of the page: the entries this call created, and those of an earlier call
        // that still wait.
        log_store::confirm_each(node, &handed).await?;
    }

    let mut grants: Vec<TransferGrant> = Vec::with_capacity(page.len());
    for (user_id, account) in page {
        let mut account = lock(&account);
        // The account was free since the page was chosen, and while the entries were written:
        // a revoke that was answered in between leaves no transfer behind it, and a grant
        // that took the place of the one an entry was made for is not handed over under that
        // entry.
        if !transferable(&mut account, &to_public, recorded, now_ms) {
            continue;
        }
        let GrantState::Active(held) = account.grant() else {
            continue;
        };
        if recorded
            && !held
                .handed_to(&to_public)
                .is_some_and(|seq| account.is_confirmed(seq))
        {
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
    Ok(Exported {
        envelope,
        logs,
        next,
    })
}

/// True when a transfer hands the delegation of this account on to the peer with the signing
/// public key `to`: it has a grant within its time and, for a peer of a later release
/// (`recorded`: the transfer has an entry), the grant was handed to that peer before or to
/// fewer than 64 peers of a later release.
fn transferable(account: &mut Account, to: &[u8; 32], recorded: bool, now_ms: u64) -> bool {
    if !account.has_grant(now_ms) {
        return false;
    }
    match account.grant() {
        GrantState::Active(held) => {
            !recorded
                || held.handed_to(to).is_some()
                || held.exported_to.len() < limits::TRANSFER_PEERS
        }
        _ => false,
    }
}

/// True when the account is in the share a `subset` names, and for every account when the
/// call names no subset.
fn in_share(subset: Option<&Subset>, user_id: &str) -> bool {
    subset.is_none_or(|subset| subset.contains(user_id))
}

pub async fn import(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run_import(&node, request).await)
}

/// Takes the delegations of a transfer that the peer whose attestation response the call
/// carries made for this node.
///
/// A node takes a transfer only while its log store holds its node document (protocol.md 7.7):
/// a node that has a log store and no document in it that outlives an entry written now
/// answers `log_store_unavailable`, before it opens the envelope. A node holds no user key
/// that a reader of the store could not trace to an attested node.
///
/// With a `subset` (enclave.md 5.13), a grant of an account that the subset does not give to
/// this node is left out: not put in place, no entry, not counted. A giving node of a release
/// without the subset rule hands every account over, and this filter keeps the share of this
/// node all the same.
///
/// A grant of the custody of this node whose time has not passed is taken when the account has
/// no grant within its time here and never revoked here: the grant is kept, its end moved to
/// 30 days from now when it lies beyond that. When the account already has the grant of the
/// same signing key, the later end stays. A grant of another signing key is never replaced by
/// a transfer, and an account that revoked on this node takes no transfer at all, also after
/// its revocation marker was replaced by a grant: an envelope can be kept and sent again, and
/// what a revoke ended only a grant command brings back. An account the node halted takes no
/// transfer either (`Account::halt`). `imported` is the number of grants
/// this call put in place, and `accounts` names their accounts: the caller learns from the
/// answer which accounts this node holds a delegation of now.
///
/// The peer is a node of the measurement of this node, or a node of a release that this
/// program lists as a predecessor: its measurement is the measurement of an element of the
/// list, and its binding names the release of that element (protocol.md 10.3). A grant from a
/// node of the same measurement is put in place without an entry. For a grant from a
/// predecessor the node creates the entry `grant_transferred_in`, which names the giving node
/// and its release: the grant is put in place first, the call then writes the entries it
/// created in one round, and an entry the store did not confirm is a pending entry that the
/// next write of the account takes along. The outcome of the round does not change the outcome
/// of the call: the entry that says where the grant went is the `grant_transferred_out` of the
/// giving node, which the log store confirmed before the transfer was made.
///
/// When the orderly shutdown starts while the call runs, it stops there and answers with what
/// it took until then.
async fn run_import(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let envelope = body.object("envelope")?;
    let subset = subset_of(&body)?;
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
    Ok(json_ok(
        &import_from(node, &peer, envelope, subset.as_ref()).await?,
    ))
}

/// Steps 1a to 3 of the receiving node (protocol.md 10.1) for a peer the call verified: takes
/// the grants of the transfer `envelope` that `peer` made for this node.
pub(crate) async fn import_from(
    node: &Node,
    peer: &Peer,
    envelope: &serde_json::Value,
    subset: Option<&Subset>,
) -> Result<Imported, ApiError> {
    // 1a: no user key before the node document.
    let now_ms = node.now_ms();
    node.log_store.ensure_documented(now_ms)?;
    // 2
    let envelope = TransferEnvelope::from_value(envelope)?;
    let transfer = peer.open_transfer(&node.keys, &envelope)?;

    // 3: every random value is drawn before an entry is created.
    let latest_ms = now_ms.saturating_add(limits::GRANT_MAX_MS);
    let from = peer.node();
    let earlier = match peer.program() {
        Program::Same => None,
        Program::Release(release) => Some(release.as_str()),
    };
    let mut seeds: Vec<Secret<[u8; 32]>> = Vec::new();
    if earlier.is_some() {
        for _ in 0..transfer.grants.len() {
            seeds.push(node.random_secret::<32>()?);
        }
    }
    let mut seeds = seeds.into_iter();
    let mut accounts = Vec::new();
    let mut logs = Vec::new();
    let mut created: Vec<(Arc<AccountLock>, u64)> = Vec::new();
    for grant in transfer.grants {
        if grant.custody != node.custody
            || grant.not_after_ms <= now_ms
            || !in_share(subset, &grant.user_id)
        {
            continue;
        }
        let not_after_ms = grant.not_after_ms.min(latest_ms);
        let account = node.account_or_create(&grant.user_id);
        let mut guard = lock(&account);
        if node.ensure_open().is_err() {
            break;
        }
        if guard.revoked_here || guard.is_halted() {
            continue;
        }
        guard.expire(now_ms);
        match guard.grant_mut() {
            GrantState::Active(held) => {
                if held.sign_pk == grant.sign_pk {
                    held.not_after_ms = held.not_after_ms.max(not_after_ms);
                }
            }
            GrantState::Revoked { .. } => {}
            GrantState::None | GrantState::Expired { .. } => {
                let key_id = key_id(&grant.sign_pk);
                // The entry of a transfer from an earlier release starts as a pending entry;
                // the round below writes it when the node can, and the next write of the
                // account takes it along otherwise.
                let seq = match (earlier, seeds.next()) {
                    (Some(release), Some(seed)) => {
                        let place = node.create_event_seeded(
                            &mut guard,
                            &grant.user_id,
                            &key_id,
                            &grant.log_pk,
                            now_ms,
                            EntryKind::Control,
                            events::grant_transferred_in(
                                &from,
                                release,
                                not_after_ms,
                                grant.custody,
                            ),
                            &seed,
                        )?;
                        Some(seq_of(&place)?)
                    }
                    _ => None,
                };
                guard.set_grant(GrantState::Active(ActiveGrant {
                    key_id,
                    sign_pk: grant.sign_pk,
                    log_pk: grant.log_pk,
                    custody: grant.custody,
                    user_key: grant.user_key.clone(),
                    not_after_ms,
                    exported_to: Vec::new(),
                }));
                drop(guard);
                accounts.push(grant.user_id.clone());
                if let Some(seq) = seq {
                    logs.push(AccountLogRef {
                        user_id: grant.user_id.clone(),
                        seq,
                    });
                    created.push((account, seq));
                }
            }
        }
    }
    // The grants are in place. The entries of a transfer from an earlier release are written
    // now, in one round. The outcome of the round changes nothing: an entry that is not
    // confirmed is a pending entry.
    if !created.is_empty() {
        let awaited: Vec<(&AccountLock, u64)> = created
            .iter()
            .map(|(account, seq)| (account.as_ref(), *seq))
            .collect();
        let _ = log_store::confirm_each(node, &awaited).await;
    }
    Ok(Imported {
        imported: accounts.len(),
        accounts,
        logs,
    })
}
