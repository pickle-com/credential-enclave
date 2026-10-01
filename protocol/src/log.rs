//! The credential log (protocol.md section 7): signed entries that only the account can read,
//! chained per (node, account), and the signed head of a chain.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::encoding::{b64u, to_json, Signed};
use crate::envelope::hpke_seal;
use crate::keys::NodeKeys;
use crate::purpose;
use crate::secret::Secret;

/// The end of a (node, account) chain: the `seq` and `entry_hash` of its last entry. A chain
/// without entries has `seq` 0 and 32 zero bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub seq: u64,
    pub hash: [u8; 32],
}

impl Head {
    /// The head of a chain without entries.
    pub const EMPTY: Head = Head {
        seq: 0,
        hash: [0u8; 32],
    };
}

/// The body of a log entry (7.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryBody {
    pub v: u8,
    pub node: String,
    pub user_id: String,
    pub key_id: String,
    pub seq: u64,
    pub prev: String,
    pub time_ms: u64,
    pub enc: String,
    pub ct: String,
}

/// The body of a head (7.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadBody {
    pub v: u8,
    #[serde(rename = "type")]
    pub kind: String,
    pub node: String,
    pub user_id: String,
    pub seq: u64,
    pub hash: String,
    pub nonce: String,
    pub time_ms: u64,
    #[serde(rename = "final")]
    pub is_final: bool,
}

/// The HPKE AAD of an entry: `UTF-8(node + "\n" + user_id + "\n" + key_id + "\n" + decimal seq)`.
pub fn entry_aad(node: &str, user_id: &str, key_id: &str, seq: u64) -> Vec<u8> {
    format!("{node}\n{user_id}\n{key_id}\n{seq}").into_bytes()
}

/// `entry_hash` = `SHA-256("pickle.secure.v1.log-chain\n" || body)`.
pub fn entry_hash(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(purpose::LOG_CHAIN.as_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

/// The key of the object of an entry in the log store (7.6):
/// `v1/accounts/{user_id}/{node}/{seq}-{hash}`, with `seq` as 20 decimal digits and `hash` as
/// `b64u(entry_hash)`. The hash is that of the bytes of the entry body, so the key names one
/// entry: a reader takes an object of this key for the entry when its body has this hash and
/// verifies under the signing key of `node`.
pub fn object_key(user_id: &str, node: &str, seq: u64, entry_hash: &[u8; 32]) -> String {
    format!(
        "v1/accounts/{user_id}/{node}/{seq:020}-{}",
        b64u(entry_hash)
    )
}

/// Creates the entry that follows `head` and returns it with the new end of the chain.
///
/// The event is sealed to `log_pk` (the log public key of the grant in force) with single-shot
/// HPKE: info `pickle.secure.v1.log-entry`, AAD [`entry_aad`]. `hpke_seed` is the input keying
/// material of the ephemeral key pair (`DeriveKeyPair(hpke_seed)`, RFC 9180 section 7.1.3): a
/// node passes 32 fresh random bytes and the vector generator passes fixed bytes. `event` is a
/// JSON object whose key order is the order of protocol.md 7.2. An event holds no secret: it is
/// built from the public parts of a call (identifiers, addresses, a body hash, the caller's
/// context).
///
/// # Panics
///
/// Panics when HPKE cannot seal to `log_pk` (a small-order X25519 point).
/// [`crate::envelope::open_command`] rejects a grant with such a key, so a `log_pk` taken from
/// an accepted grant never panics here.
#[allow(clippy::too_many_arguments)]
pub fn append(
    keys: &NodeKeys,
    head: &Head,
    user_id: &str,
    key_id: &str,
    log_pk: &[u8; 32],
    time_ms: u64,
    event: &serde_json::Value,
    hpke_seed: &Secret<[u8; 32]>,
) -> (Signed, Head) {
    let node = keys.node();
    let seq = head.seq + 1;
    let plaintext = zeroize::Zeroizing::new(to_json(event));
    let (enc, ct) = hpke_seal(
        log_pk,
        purpose::LOG_ENTRY_SEAL.as_bytes(),
        &entry_aad(&node, user_id, key_id, seq),
        &plaintext,
        hpke_seed.expose_secret(),
    )
    .expect("the log public key of an accepted grant can be sealed to");
    let body = to_json(&EntryBody {
        v: 1,
        node,
        user_id: user_id.to_string(),
        key_id: key_id.to_string(),
        seq,
        prev: b64u(&head.hash),
        time_ms,
        enc: b64u(&enc),
        ct: b64u(&ct),
    });
    let next = Head {
        seq,
        hash: entry_hash(&body),
    };
    (keys.sign(purpose::LOG_ENTRY, &body), next)
}

/// Signs the head of the chain of `user_id` on this node. `nonce` is the value the requester
/// gave. A head with `is_final` true carries the empty string as its nonce: a node creates one
/// per account in its orderly shutdown and writes no entry for that account afterwards.
pub fn signed_head(
    keys: &NodeKeys,
    user_id: &str,
    head: &Head,
    nonce: &str,
    time_ms: u64,
    is_final: bool,
) -> Signed {
    let body = to_json(&HeadBody {
        v: 1,
        kind: "head".to_string(),
        node: keys.node(),
        user_id: user_id.to_string(),
        seq: head.seq,
        hash: b64u(&head.hash),
        nonce: nonce.to_string(),
        time_ms,
        is_final,
    });
    keys.sign(purpose::HEAD, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{self, ChainError};
    use crate::encoding::{b64u_decode, verify};
    use serde_json::json;

    fn node() -> NodeKeys {
        NodeKeys::from_random(&[0x11; 32], &[0x22; 32])
    }

    #[test]
    fn the_key_of_an_entry_names_the_account_the_node_the_seq_and_the_hash() {
        assert_eq!(
            object_key("user-1", "NODE", 7, &[0xfb; 32]),
            "v1/accounts/user-1/NODE/00000000000000000007--_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s"
        );
        // The longest `seq` has the 20 digits of the key, so the keys of one chain sort in
        // the order of their entries.
        assert_eq!(
            object_key("u", "N", u64::MAX, &[0; 32]),
            format!("v1/accounts/u/N/18446744073709551615-{}", "A".repeat(43))
        );
        // The key of an entry a node created: the hash of its body.
        let keys = node();
        let account = app::derive_account_keys(&[0x33; 32]);
        let (entry, head) = append(
            &keys,
            &Head::EMPTY,
            "user-1",
            &account.key_id(),
            &account.log_pk(),
            1_000,
            &json!({"t": "grant_revoked"}),
            &Secret::new([0x44; 32]),
        );
        let body = b64u_decode(&entry.body).unwrap();
        assert_eq!(
            object_key("user-1", &keys.node(), head.seq, &head.hash),
            format!(
                "v1/accounts/user-1/{}/00000000000000000001-{}",
                keys.node(),
                b64u(&entry_hash(&body))
            )
        );
    }

    #[test]
    fn the_first_entry_has_seq_1_and_a_zero_prev() {
        let keys = node();
        let account = app::derive_account_keys(&[0x33; 32]);
        let (entry, head) = append(
            &keys,
            &Head::EMPTY,
            "user-1",
            &account.key_id(),
            &account.log_pk(),
            1_000,
            &json!({"t": "grant_accepted", "not_after_ms": 5_000, "custody": "enclave"}),
            &Secret::new([0x44; 32]),
        );
        let body_bytes = verify(&keys.sign_public(), purpose::LOG_ENTRY, &entry).unwrap();
        let body: EntryBody = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body.v, 1);
        assert_eq!(body.node, keys.node());
        assert_eq!(body.user_id, "user-1");
        assert_eq!(body.key_id, account.key_id());
        assert_eq!(body.seq, 1);
        assert_eq!(body.prev, b64u(&[0u8; 32]));
        assert_eq!(body.time_ms, 1_000);
        assert_eq!(b64u_decode(&body.enc).unwrap().len(), 32);
        assert_eq!(head.seq, 1);
        assert_eq!(head.hash, entry_hash(&body_bytes));
        // The body keys are in the order of section 7.1.
        let text = String::from_utf8(body_bytes).unwrap();
        let order = [
            "\"v\"",
            "\"node\"",
            "\"user_id\"",
            "\"key_id\"",
            "\"seq\"",
            "\"prev\"",
        ];
        let mut last = 0;
        for key in order
            .iter()
            .chain(["\"time_ms\"", "\"enc\"", "\"ct\""].iter())
        {
            let position = text.find(key).unwrap();
            assert!(position >= last, "{key}");
            last = position;
        }
    }

    #[test]
    fn only_the_log_key_of_the_grant_opens_an_entry() {
        let keys = node();
        let account = app::derive_account_keys(&[0x33; 32]);
        let event = json!({"t": "secret_released", "record_id": "r", "kind": "vault_card",
            "field": "card_cvc", "origin": "https://shop.example", "context": "browser:fill"});
        let (entry, _) = append(
            &keys,
            &Head::EMPTY,
            "user-1",
            &account.key_id(),
            &account.log_pk(),
            1,
            &event,
            &Secret::new([0x44; 32]),
        );
        let body = verify(&keys.sign_public(), purpose::LOG_ENTRY, &entry).unwrap();
        let plaintext = app::open_entry(&account.log, &body).unwrap();
        assert_eq!(plaintext, to_json(&event));
        assert_eq!(
            String::from_utf8(plaintext).unwrap(),
            concat!(
                "{\"t\":\"secret_released\",\"record_id\":\"r\",\"kind\":\"vault_card\",",
                "\"field\":\"card_cvc\",\"origin\":\"https://shop.example\",",
                "\"context\":\"browser:fill\"}"
            )
        );
        let other = app::derive_account_keys(&[0x34; 32]);
        assert!(app::open_entry(&other.log, &body).is_err());
    }

    #[test]
    fn the_same_seed_gives_the_same_entry_and_another_seed_another_entry() {
        let keys = node();
        let account = app::derive_account_keys(&[0x33; 32]);
        let build = |seed: &[u8; 32]| {
            append(
                &keys,
                &Head::EMPTY,
                "user-1",
                &account.key_id(),
                &account.log_pk(),
                1,
                &json!({"t": "grant_revoked"}),
                &Secret::new(*seed),
            )
        };
        assert_eq!(build(&[1; 32]), build(&[1; 32]));
        assert_ne!(build(&[1; 32]).0, build(&[2; 32]).0);
    }

    #[test]
    fn a_chain_verifies_and_a_missing_middle_entry_is_detected() {
        let keys = node();
        let account = app::derive_account_keys(&[0x33; 32]);
        let mut head = Head::EMPTY;
        let mut entries = Vec::new();
        for (index, event) in [
            json!({"t": "grant_accepted", "not_after_ms": 9, "custody": "enclave"}),
            json!({"t": "totp_issued", "record_id": "r", "origin": "https://a.example",
                "context": "browser:fill"}),
            json!({"t": "grant_revoked"}),
        ]
        .iter()
        .enumerate()
        {
            let (entry, next) = append(
                &keys,
                &head,
                "user-1",
                &account.key_id(),
                &account.log_pk(),
                100 + index as u64,
                event,
                &Secret::new([index as u8 + 1; 32]),
            );
            entries.push(entry);
            head = next;
        }
        let signed = signed_head(&keys, "user-1", &head, "bm9uY2U", 200, false);
        let verified = app::verify_chain(
            &keys.sign_public(),
            "user-1",
            &Head::EMPTY,
            &entries,
            &signed,
            Some("bm9uY2U"),
        )
        .unwrap();
        assert_eq!(verified, head);

        let without_middle = vec![entries[0].clone(), entries[2].clone()];
        assert_eq!(
            app::verify_chain(
                &keys.sign_public(),
                "user-1",
                &Head::EMPTY,
                &without_middle,
                &signed,
                Some("bm9uY2U"),
            ),
            Err(ChainError::Broken)
        );
        assert_eq!(
            app::verify_chain(
                &keys.sign_public(),
                "user-1",
                &Head::EMPTY,
                &entries[..2],
                &signed,
                Some("bm9uY2U"),
            ),
            Err(ChainError::Incomplete)
        );
        assert_eq!(
            app::verify_chain(
                &keys.sign_public(),
                "user-1",
                &Head::EMPTY,
                &entries,
                &signed,
                Some("b3RoZXI"),
            ),
            Err(ChainError::Head)
        );
    }

    #[test]
    fn a_head_has_the_key_order_of_section_7_3() {
        let keys = node();
        let live = signed_head(&keys, "user-1", &Head::EMPTY, "bm9uY2U", 5, false);
        let bytes = verify(&keys.sign_public(), purpose::HEAD, &live).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            format!(
                concat!(
                    "{{\"v\":1,\"type\":\"head\",\"node\":\"{}\",\"user_id\":\"user-1\",\"seq\":0,",
                    "\"hash\":\"{}\",\"nonce\":\"bm9uY2U\",\"time_ms\":5,\"final\":false}}"
                ),
                keys.node(),
                b64u(&[0u8; 32])
            )
        );
        let last = signed_head(&keys, "user-1", &Head::EMPTY, "", 6, true);
        let body: HeadBody =
            serde_json::from_slice(&verify(&keys.sign_public(), purpose::HEAD, &last).unwrap())
                .unwrap();
        assert!(body.is_final);
        assert_eq!(body.nonce, "");
        // A head is not accepted as an entry: the signature contexts differ.
        assert!(verify(&keys.sign_public(), purpose::LOG_ENTRY, &live).is_err());
    }
}
