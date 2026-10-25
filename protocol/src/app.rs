//! The app side of the protocol: account key derivation, the check of a challenge statement,
//! command sealing, log entry opening and chain verification (protocol.md sections 3, 4.4,
//! 5.1, 5.2 and 7.4).
//!
//! The node program never calls this module. The test vector generator and the tests use it to
//! play the part of the app, and a third party can use it to check a node from outside.

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::encoding::{b64u, b64u_decode, to_json, verify, Signed};
use crate::envelope::{hpke_open, hpke_seal, Envelope};
use crate::keys::{hkdf_sha256, key_id, node_id, Custody};
use crate::log::{
    body_hash, entry_aad, entry_hash, entry_hash_v2, EntryBody, EntryBodyV1, EntryParts, Head,
    HeadBody,
};
use crate::statement::ChallengeBody;
use crate::{limits, purpose, ProtocolError};

/// The keys an app derives from its master key (protocol.md section 3).
pub struct AccountKeys {
    /// Account signing key: Ed25519, seed `HKDF(MK, "pickle.secure.v1.sign")`.
    pub sign: SigningKey,
    /// Log decryption private key: X25519, `HKDF(MK, "pickle.secure.v1.log")` used as is.
    pub log: StaticSecret,
    /// User key of custody `enclave`: `HKDF(MK, "pickle.secure.v1.user-key")`.
    pub user_key: Zeroizing<[u8; 32]>,
    /// User key of custody `operator`: `HKDF(MK, "pickle.secure.v1.user-key.operator")`.
    pub user_key_operator: Zeroizing<[u8; 32]>,
}

impl AccountKeys {
    /// The account signing public key.
    pub fn sign_pk(&self) -> [u8; 32] {
        self.sign.verifying_key().to_bytes()
    }

    /// The log public key.
    pub fn log_pk(&self) -> [u8; 32] {
        PublicKey::from(&self.log).to_bytes()
    }

    /// `key_id` of the account signing public key.
    pub fn key_id(&self) -> String {
        key_id(&self.sign_pk())
    }

    /// The user key of a custody. An app hands a node the key of that node's custody only: the
    /// key of custody `enclave` never leaves for a node whose attestation was not verified.
    pub fn user_key_of(&self, custody: Custody) -> &Zeroizing<[u8; 32]> {
        match custody {
            Custody::Enclave => &self.user_key,
            Custody::Operator => &self.user_key_operator,
        }
    }
}

/// Derives the account keys from the 32-byte master key. Every derivation is HKDF-SHA256 with
/// the zero-length salt.
pub fn derive_account_keys(master_key: &[u8; 32]) -> AccountKeys {
    let sign_seed = hkdf_sha256(master_key, &[], purpose::SIGN);
    let log_private = hkdf_sha256(master_key, &[], purpose::LOG);
    AccountKeys {
        sign: SigningKey::from_bytes(&sign_seed),
        log: StaticSecret::from(*log_private),
        user_key: hkdf_sha256(master_key, &[], purpose::USER_KEY),
        user_key_operator: hkdf_sha256(master_key, &[], purpose::USER_KEY_OPERATOR),
    }
}

#[derive(Serialize)]
struct GrantPayload<'a> {
    v: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    user_id: &'a str,
    node: &'a str,
    challenge: &'a str,
    sign_pk: String,
    log_pk: String,
    custody: &'static str,
    user_key: String,
    not_after_ms: u64,
    policy: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize)]
struct RevokePayload<'a> {
    v: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    user_id: &'a str,
    node: &'a str,
    challenge: &'a str,
    sign_pk: String,
}

/// The `grant` command of protocol.md 5.2 as payload bytes. It carries the user key of
/// `custody`, the custody of the platform of the node it is for.
pub fn grant_payload(
    keys: &AccountKeys,
    user_id: &str,
    node: &str,
    challenge: &str,
    custody: Custody,
    not_after_ms: u64,
) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(to_json(&GrantPayload {
        v: 1,
        kind: "grant",
        user_id,
        node,
        challenge,
        sign_pk: b64u(&keys.sign_pk()),
        log_pk: b64u(&keys.log_pk()),
        custody: custody.as_str(),
        user_key: b64u(keys.user_key_of(custody).as_slice()),
        not_after_ms,
        policy: serde_json::Map::new(),
    }))
}

/// The `revoke` command of protocol.md 5.2 as payload bytes.
pub fn revoke_payload(keys: &AccountKeys, user_id: &str, node: &str, challenge: &str) -> Vec<u8> {
    to_json(&RevokePayload {
        v: 1,
        kind: "revoke",
        user_id,
        node,
        challenge,
        sign_pk: b64u(&keys.sign_pk()),
    })
}

#[derive(Serialize)]
struct SignedCommand {
    payload: String,
    sig: String,
}

/// Verifies the challenge statement of an attestation response (protocol.md 4.4).
///
/// `node_sign_public` is the node signing public key from the binding of the verified
/// attestation document, `nonce` the bytes the app sent in the attestation request and
/// `challenge` the `challenge` field of the response. When this returns `Ok`, that node issued
/// that challenge in answer to that request, so a signed reply that carries the challenge was
/// made after the app chose the nonce.
///
/// A signature that does not verify is `bad_signature`. A body that is not the statement of
/// this node for this nonce and this challenge is `bad_challenge`.
pub fn verify_challenge_statement(
    node_sign_public: &[u8; 32],
    statement: &Signed,
    nonce: &[u8],
    challenge: &str,
) -> Result<(), ProtocolError> {
    let bytes = verify(node_sign_public, purpose::CHALLENGE, statement)?;
    let body: ChallengeBody =
        serde_json::from_slice(&bytes).map_err(|_| ProtocolError::BadChallenge)?;
    if body.v != 1
        || body.kind != "challenge"
        || body.node != node_id(node_sign_public)
        || body.nonce != b64u(nonce)
        || body.challenge != challenge
    {
        return Err(ProtocolError::BadChallenge);
    }
    Ok(())
}

/// Signs `payload` with the account signing key and seals it for the node (protocol.md 5.1):
/// HPKE info `pickle.secure.v1.message`, AAD `UTF-8(node)`. `hpke_seed` is the input keying
/// material of the ephemeral key pair: an app passes fresh random bytes.
pub fn seal_command(
    sign: &SigningKey,
    node_seal_public: &[u8; 32],
    node: &str,
    payload: &[u8],
    hpke_seed: &[u8; 32],
) -> Result<Envelope, ProtocolError> {
    let mut message = Zeroizing::new(Vec::with_capacity(purpose::COMMAND.len() + payload.len()));
    message.extend_from_slice(purpose::COMMAND.as_bytes());
    message.extend_from_slice(payload);
    let signature = sign.sign(&message);
    let signed = Zeroizing::new(to_json(&SignedCommand {
        payload: b64u(payload),
        sig: b64u(&signature.to_bytes()),
    }));
    let (enc, ct) = hpke_seal(
        node_seal_public,
        purpose::MESSAGE.as_bytes(),
        node.as_bytes(),
        &signed,
        hpke_seed,
    )?;
    Ok(Envelope {
        v: 1,
        node: node.to_string(),
        enc: b64u(&enc),
        ct: b64u(&ct),
    })
}

/// Opens the event of a log entry of format 1 with the log decryption private key. `body` is
/// the verified body of the entry.
pub fn open_entry(log_private: &StaticSecret, body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let entry: EntryBodyV1 =
        serde_json::from_slice(body).map_err(|_| ProtocolError::InvalidRequest)?;
    if entry.v != 1 {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let enc = b64u_decode(&entry.enc)?;
    let ct = b64u_decode(&entry.ct)?;
    let plaintext = hpke_open(
        log_private,
        &enc,
        purpose::LOG_ENTRY_SEAL.as_bytes(),
        &entry_aad(&entry.node, &entry.user_id, &entry.key_id, entry.seq),
        &ct,
    )?;
    Ok(plaintext.to_vec())
}

/// Opens the events of a log entry of format 2 with the log decryption private key. `body` is
/// the verified body of the entry. The plaintext is the JSON array of the events in the order
/// of their creation; an array of another length than `count` is `invalid_request`.
pub fn open_entry_v2(
    log_private: &StaticSecret,
    body: &[u8],
) -> Result<Vec<serde_json::Value>, ProtocolError> {
    let entry: EntryBody =
        serde_json::from_slice(body).map_err(|_| ProtocolError::InvalidRequest)?;
    if entry.v != 2 {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let enc = b64u_decode(&entry.enc)?;
    let ct = b64u_decode(&entry.ct)?;
    let plaintext = hpke_open(
        log_private,
        &enc,
        purpose::LOG_ENTRY_SEAL_V2.as_bytes(),
        &entry_aad(&entry.node, &entry.user_id, &entry.key_id, entry.seq),
        &ct,
    )?;
    let events: Vec<serde_json::Value> =
        serde_json::from_slice(&plaintext).map_err(|_| ProtocolError::InvalidRequest)?;
    if events.len() != entry.count as usize {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(events)
}

/// Why a chain failed the verification of protocol.md 7.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainError {
    /// The head does not verify: signature, `type`, `node`, `user_id`, nonce, `final`, or a
    /// `seq` behind the checkpoint.
    Head,
    /// An entry does not verify, is out of sequence, does not link to its predecessor, or the
    /// last entry does not hash to the head: the stored log was altered or has a gap.
    Broken,
    /// The entries end before the `seq` of the head: stored entries are missing at the end.
    Incomplete,
}

/// Verifies a head (protocol.md 7.3) for the chain of `user_id` on the node of
/// `node_sign_public` and returns its `seq` and hash. `expected_nonce` is as in
/// [`verify_chain`]. A head whose `seq` is behind the checkpoint does not verify.
fn verified_head(
    node_sign_public: &[u8; 32],
    user_id: &str,
    checkpoint: &Head,
    head: &Signed,
    expected_nonce: Option<&str>,
) -> Result<Head, ChainError> {
    let head_bytes = verify(node_sign_public, purpose::HEAD, head).map_err(|_| ChainError::Head)?;
    let head_body: HeadBody = serde_json::from_slice(&head_bytes).map_err(|_| ChainError::Head)?;
    let nonce_matches = match expected_nonce {
        Some(nonce) => !head_body.is_final && head_body.nonce == nonce,
        None => head_body.is_final && head_body.nonce.is_empty(),
    };
    if head_body.v != 1
        || head_body.kind != "head"
        || head_body.node != node_id(node_sign_public)
        || head_body.user_id != user_id
        || !nonce_matches
        || head_body.seq < checkpoint.seq
    {
        return Err(ChainError::Head);
    }
    let hash = b64u_decode(&head_body.hash).map_err(|_| ChainError::Head)?;
    let hash = <[u8; 32]>::try_from(hash.as_slice()).map_err(|_| ChainError::Head)?;
    Ok(Head {
        seq: head_body.seq,
        hash,
    })
}

/// Verifies one (node, account) chain of format 1 from `checkpoint` up to `head` (protocol.md
/// 7.4, "Format 1") by its entries and returns the new checkpoint.
///
/// `entries` are the stored entries that follow the checkpoint, in order. `expected_nonce` is
/// the nonce the verifier sent to a live node. `None` verifies the `final` head of a node that
/// is gone.
pub fn verify_chain(
    node_sign_public: &[u8; 32],
    user_id: &str,
    checkpoint: &Head,
    entries: &[Signed],
    head: &Signed,
    expected_nonce: Option<&str>,
) -> Result<Head, ChainError> {
    let node = node_id(node_sign_public);
    let head = verified_head(node_sign_public, user_id, checkpoint, head, expected_nonce)?;
    let mut current = *checkpoint;
    let mut stored = entries.iter();
    while current.seq < head.seq {
        let entry = stored.next().ok_or(ChainError::Incomplete)?;
        let body_bytes =
            verify(node_sign_public, purpose::LOG_ENTRY, entry).map_err(|_| ChainError::Broken)?;
        let body: EntryBodyV1 =
            serde_json::from_slice(&body_bytes).map_err(|_| ChainError::Broken)?;
        if body.v != 1
            || body.node != node
            || body.user_id != user_id
            || body.seq != current.seq + 1
            || body.prev != b64u(&current.hash)
        {
            return Err(ChainError::Broken);
        }
        current = Head {
            seq: body.seq,
            hash: entry_hash(&body_bytes),
        };
    }
    if current.hash != head.hash {
        return Err(ChainError::Broken);
    }
    Ok(current)
}

/// Why a chain of format 2 failed the index verification of protocol.md 7.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexError {
    /// The head does not verify: signature, `type`, `node`, `user_id`, nonce, `final`, or a
    /// `seq` behind the checkpoint.
    Head,
    /// No key of this `seq` is listed while keys of later ones are: the stored log has a gap.
    Gap { seq: u64 },
    /// Keys of this `seq` are listed, but none of them follows the chain, or the chain does not
    /// end at the hash of the head: the stored log was altered.
    Broken { seq: u64 },
    /// More than one key of this `seq` follows the chain. The operator domain can add objects
    /// under any key, so the objects of these keys decide ([`verify_entry_v2`]).
    Ambiguous { seq: u64 },
    /// The listing ends before the `seq` of the head: stored entries are missing at the end.
    Incomplete,
}

/// Verifies one (node, account) chain of format 2 from `checkpoint` up to `head` by the keys
/// of a listing of the log store alone (protocol.md 7.4, index verification) and returns the
/// new checkpoint.
///
/// `keys` are the parts of the keys listed under the prefix of the chain after the checkpoint,
/// in any order; keys of other seqs are ignored. For every `seq` after the checkpoint up to the
/// head, exactly one key must satisfy `entry_hash == entry_hash_v2(cursor.hash, body_hash,
/// fields)` (the five parts of the key before its hashes are an input of the hash); the cursor
/// then moves to its `entry_hash`. At the head the cursor must equal the hash of the head. A
/// caller reads the object of a control key (`kind` c) with [`verify_entry_v2`] on top of this
/// walk: this function does not tell the kinds apart.
pub fn verify_index(
    node_sign_public: &[u8; 32],
    user_id: &str,
    checkpoint: &Head,
    keys: &[EntryParts],
    head: &Signed,
    expected_nonce: Option<&str>,
) -> Result<Head, IndexError> {
    let head = verified_head(node_sign_public, user_id, checkpoint, head, expected_nonce)
        .map_err(|_| IndexError::Head)?;
    let last_listed = keys.iter().map(|parts| parts.seq).max().unwrap_or(0);
    let mut cursor = *checkpoint;
    while cursor.seq < head.seq {
        let seq = cursor.seq + 1;
        let mut candidates = keys.iter().filter(|parts| parts.seq == seq).peekable();
        if candidates.peek().is_none() {
            return Err(match seq > last_listed {
                true => IndexError::Incomplete,
                false => IndexError::Gap { seq },
            });
        }
        // A key counts once however many versions of its object the listing shows (a write the
        // node repeated adds a version of the same key).
        let mut following: Vec<&EntryParts> = Vec::new();
        for parts in candidates {
            if parts.entry_hash == entry_hash_v2(&cursor.hash, &parts.body_hash, &parts.fields())
                && !following.contains(&parts)
            {
                following.push(parts);
            }
        }
        let [next] = following[..] else {
            return Err(match following.is_empty() {
                true => IndexError::Broken { seq },
                false => IndexError::Ambiguous { seq },
            });
        };
        cursor = Head {
            seq,
            hash: next.entry_hash,
        };
    }
    if cursor.hash != head.hash {
        return Err(IndexError::Broken { seq: cursor.seq });
    }
    Ok(cursor)
}

/// Verifies the object of a key of format 2 (protocol.md 7.4, content verification): the
/// signature of the node, the body fields `v`, `node`, `user_id`, `seq`, `kind`, `count`,
/// `key_id` and `time_ms` against the parts of the key, `body_hash` against the body bytes,
/// and `prev` against `cursor` when a cursor is given (the screen reads one entry without its
/// predecessor and passes `None`). Returns the body. Every failure is `Broken`.
pub fn verify_entry_v2(
    node_sign_public: &[u8; 32],
    user_id: &str,
    parts: &EntryParts,
    cursor: Option<&Head>,
    entry: &Signed,
) -> Result<EntryBody, ChainError> {
    let body_bytes =
        verify(node_sign_public, purpose::LOG_ENTRY_V2, entry).map_err(|_| ChainError::Broken)?;
    let body: EntryBody = serde_json::from_slice(&body_bytes).map_err(|_| ChainError::Broken)?;
    let count_fits = body.count >= 1 && body.count as usize <= limits::ENTRY_EVENTS;
    if body.v != 2
        || body.node != node_id(node_sign_public)
        || body.user_id != user_id
        || body.seq != parts.seq
        || body.time_ms != parts.time_ms
        || body.kind != parts.kind.letter().to_string()
        || body.count != parts.count
        || !count_fits
        || body.key_id != parts.key_id
        || body_hash(&body_bytes) != parts.body_hash
        || cursor.is_some_and(|cursor| body.prev != b64u(&cursor.hash))
    {
        return Err(ChainError::Broken);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::NodeKeys;
    use crate::log::{append_batch, signed_head, EntryKind};
    use crate::secret::Secret;
    use crate::statement;
    use serde_json::json;

    #[test]
    fn a_key_listed_twice_counts_once_and_a_forged_key_is_ambiguous() {
        let node = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
        let account = derive_account_keys(&[0x33; 32]);
        let events = [
            json!({"t": "grant_accepted", "time_ms": 1, "not_after_ms": 2, "custody": "enclave"}),
            json!({"t": "provider_request", "time_ms": 2}),
        ];
        let mut head = Head::EMPTY;
        let mut keys = Vec::new();
        for (index, kind) in [EntryKind::Control, EntryKind::Use].into_iter().enumerate() {
            let (_, next, parts) = append_batch(
                &node,
                &head,
                "user-1",
                &account.key_id(),
                &account.log_pk(),
                1_000 * (index as u64 + 1),
                kind,
                &events[index..=index],
                &Secret::new([index as u8 + 1; 32]),
            );
            keys.push(parts);
            head = next;
        }
        let signed = signed_head(&node, "user-1", &head, "nonce", 5, false);
        let public = node.sign_public();
        // The listing shows two versions of the key of seq 2 (a write the node repeated): the
        // key counts once.
        let twice = [keys[0].clone(), keys[1].clone(), keys[1].clone()];
        assert_eq!(
            verify_index(
                &public,
                "user-1",
                &Head::EMPTY,
                &twice,
                &signed,
                Some("nonce")
            ),
            Ok(head)
        );
        // A key of seq 2 with another body hash and a consistent entry hash is a second
        // candidate: the objects decide.
        let mut forged = keys[1].clone();
        forged.body_hash = body_hash(b"another body");
        forged.entry_hash = entry_hash_v2(&keys[0].entry_hash, &forged.body_hash, &forged.fields());
        let with_forged = [keys[0].clone(), keys[1].clone(), forged];
        assert_eq!(
            verify_index(
                &public,
                "user-1",
                &Head::EMPTY,
                &with_forged,
                &signed,
                Some("nonce")
            ),
            Err(IndexError::Ambiguous { seq: 2 })
        );
    }

    #[test]
    fn account_keys_use_four_distinct_derivations() {
        let keys = derive_account_keys(&[0x33; 32]);
        assert_eq!(
            keys.sign.to_bytes(),
            *hkdf_sha256(&[0x33; 32], &[], "pickle.secure.v1.sign")
        );
        assert_eq!(
            keys.log.to_bytes(),
            *hkdf_sha256(&[0x33; 32], &[], "pickle.secure.v1.log")
        );
        assert_eq!(
            *keys.user_key,
            *hkdf_sha256(&[0x33; 32], &[], "pickle.secure.v1.user-key")
        );
        assert_eq!(
            *keys.user_key_operator,
            *hkdf_sha256(&[0x33; 32], &[], "pickle.secure.v1.user-key.operator")
        );
        assert_ne!(keys.sign.to_bytes(), keys.log.to_bytes());
        assert_ne!(keys.log.to_bytes(), *keys.user_key);
        assert_ne!(*keys.user_key, *keys.user_key_operator);
        assert_eq!(keys.user_key_of(Custody::Enclave), &keys.user_key);
        assert_eq!(keys.user_key_of(Custody::Operator), &keys.user_key_operator);
        assert_eq!(keys.key_id(), key_id(&keys.sign_pk()));
    }

    #[test]
    fn a_challenge_statement_is_accepted_for_its_node_its_nonce_and_its_challenge_only() {
        let node = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
        let other = NodeKeys::from_random(&[0x12; 32], &[0x22; 32]);
        let public = node.sign_public();
        let nonce = [0x5a; 32];
        let challenge = [0x44; 16];
        let statement = statement::challenge(&node, &nonce, &challenge, 9);
        assert_eq!(
            verify_challenge_statement(&public, &statement, &nonce, &b64u(&challenge)),
            Ok(())
        );
        // The statement of an earlier request: the node signed it for another nonce.
        assert_eq!(
            verify_challenge_statement(&public, &statement, &[0x5b; 32], &b64u(&challenge)),
            Err(ProtocolError::BadChallenge)
        );
        // A response whose `challenge` field is not the one the statement names.
        assert_eq!(
            verify_challenge_statement(&public, &statement, &nonce, &b64u(&[0x45; 16])),
            Err(ProtocolError::BadChallenge)
        );
        // A statement another key signed, whichever node it names.
        let forged = statement::challenge(&other, &nonce, &challenge, 9);
        assert_eq!(
            verify_challenge_statement(&public, &forged, &nonce, &b64u(&challenge)),
            Err(ProtocolError::BadSignature)
        );
        // The statement of this nonce and challenge by another node, checked with that node's
        // key, names that node: it is not a statement of this one.
        assert_eq!(
            verify_challenge_statement(&other.sign_public(), &forged, &nonce, &b64u(&challenge)),
            Ok(())
        );
        // A signed value of another kind with the same key is not a challenge statement.
        let empty = Head {
            seq: 0,
            hash: [0; 32],
        };
        let head = signed_head(&node, "user-1", &empty, &b64u(&nonce), 9, false);
        assert_eq!(
            verify_challenge_statement(&public, &head, &nonce, &b64u(&challenge)),
            Err(ProtocolError::BadSignature)
        );
    }

    #[test]
    fn command_payloads_have_the_key_order_of_section_5_2() {
        let keys = derive_account_keys(&[0x33; 32]);
        let grant = grant_payload(&keys, "user-1", "NODE", "CHALLENGE", Custody::Enclave, 42);
        assert_eq!(
            String::from_utf8(grant.to_vec()).unwrap(),
            format!(
                concat!(
                    "{{\"v\":1,\"type\":\"grant\",\"user_id\":\"user-1\",\"node\":\"NODE\",",
                    "\"challenge\":\"CHALLENGE\",\"sign_pk\":\"{}\",\"log_pk\":\"{}\",",
                    "\"custody\":\"enclave\",\"user_key\":\"{}\",\"not_after_ms\":42,",
                    "\"policy\":{{}}}}"
                ),
                b64u(&keys.sign_pk()),
                b64u(&keys.log_pk()),
                b64u(keys.user_key.as_slice())
            )
        );
        // A grant for a node of custody `operator` carries the other user key.
        let operator: serde_json::Value = serde_json::from_slice(&grant_payload(
            &keys,
            "user-1",
            "NODE",
            "CHALLENGE",
            Custody::Operator,
            42,
        ))
        .unwrap();
        assert_eq!(operator["custody"], "operator");
        assert_eq!(
            operator["user_key"],
            b64u(keys.user_key_operator.as_slice())
        );
        let revoke = revoke_payload(&keys, "user-1", "NODE", "CHALLENGE");
        assert_eq!(
            String::from_utf8(revoke).unwrap(),
            format!(
                concat!(
                    "{{\"v\":1,\"type\":\"revoke\",\"user_id\":\"user-1\",\"node\":\"NODE\",",
                    "\"challenge\":\"CHALLENGE\",\"sign_pk\":\"{}\"}}"
                ),
                b64u(&keys.sign_pk())
            )
        );
    }

    #[test]
    fn an_empty_chain_verifies_against_an_empty_head() {
        let node = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
        let head = signed_head(&node, "user-1", &Head::EMPTY, "bm9uY2U", 1, false);
        assert_eq!(
            verify_chain(
                &node.sign_public(),
                "user-1",
                &Head::EMPTY,
                &[],
                &head,
                Some("bm9uY2U")
            ),
            Ok(Head::EMPTY)
        );
        // A live head is not accepted where a final head is required, and the reverse.
        assert_eq!(
            verify_chain(
                &node.sign_public(),
                "user-1",
                &Head::EMPTY,
                &[],
                &head,
                None
            ),
            Err(ChainError::Head)
        );
        let last = signed_head(&node, "user-1", &Head::EMPTY, "", 1, true);
        assert_eq!(
            verify_chain(
                &node.sign_public(),
                "user-1",
                &Head::EMPTY,
                &[],
                &last,
                None
            ),
            Ok(Head::EMPTY)
        );
        assert_eq!(
            verify_chain(
                &node.sign_public(),
                "user-1",
                &Head::EMPTY,
                &[],
                &last,
                Some("")
            ),
            Err(ChainError::Head)
        );
        // The head of another account or of another node does not verify.
        assert_eq!(
            verify_chain(
                &node.sign_public(),
                "user-2",
                &Head::EMPTY,
                &[],
                &head,
                Some("bm9uY2U")
            ),
            Err(ChainError::Head)
        );
        let other = NodeKeys::from_random(&[0x12; 32], &[0x22; 32]);
        assert_eq!(
            verify_chain(
                &other.sign_public(),
                "user-1",
                &Head::EMPTY,
                &[],
                &head,
                Some("bm9uY2U")
            ),
            Err(ChainError::Head)
        );
    }
}
