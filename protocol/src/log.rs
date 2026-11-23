//! The credential log (protocol.md section 7): signed entries that only the account can read,
//! and the objects of the log store that hold them.
//!
//! The log has three formats. Format 3 ([`EntryBody`] with `v` 3, [`append_v3`],
//! [`object_key_v3`]) is the format of the releases from v2.4.0 on: one entry holds the events
//! of one or more acts of one account, the key of its object carries the time of the entry,
//! the node that created it and the hash of its body, and the keys of one account sort from the
//! latest entry to the earliest. A node of that format also writes its own attestation document
//! to the store ([`NodeDocument`]). Format 2 ([`EntryBody`] with `v` 2, [`append_batch`],
//! [`object_key_v2`]) is the format of the releases from v2.0.0 to v2.3.0: the entries of one
//! (node, account) pair form a chain, the key of an object carries the hash of the body and the
//! hash of the chain, and the node signed the end of the chain ([`signed_head`]). Format 1
//! ([`EntryBodyV1`], [`append`], [`object_key`]) is the format of the releases before v2.0.0:
//! one entry holds one event and the key carries the chain hash of the body. A node writes
//! format 3 and a reader reads all three; the shape of a key tells the format
//! ([`parse_object_key_v3`], [`parse_object_key`]).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::encoding::{b64u, b64u_decode_array, to_json, Signed};
use crate::envelope::hpke_seal;
use crate::keys::NodeKeys;
use crate::secret::Secret;
use crate::{limits, purpose};

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

/// The body of a log entry of format 2 and of format 3 (7.1): `v` is 2 or 3. `kind` is the
/// letter of the kind of the entry (`c` or `u`) and `count` the number of events in the
/// plaintext. `prev` is the `entry_hash` of the entry before in format 2 and the `body_hash` of
/// the entry before in format 3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryBody {
    pub v: u8,
    pub node: String,
    pub user_id: String,
    pub key_id: String,
    pub seq: u64,
    pub prev: String,
    pub time_ms: u64,
    pub kind: String,
    pub count: u32,
    pub enc: String,
    pub ct: String,
}

/// The body of a log entry of format 1 (7.1, "Format 1"): what the releases before v2.0.0
/// wrote. A reader opens it with [`crate::app::open_entry`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryBodyV1 {
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

/// The two kinds of entry of format 2 and of format 3 (7.1). A control entry holds one control
/// event (the life of a grant or of a connection) and is never merged with another event. A use
/// entry holds the use events that arrived while the write before it ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntryKind {
    Control,
    Use,
}

/// The event types of a control entry (7.1).
pub const CONTROL_EVENTS: [&str; 6] = [
    "grant_accepted",
    "grant_revoked",
    "connection_created",
    "connection_removed",
    "grant_transferred_out",
    "grant_transferred_in",
];

/// The event types of a use entry (7.1).
pub const USE_EVENTS: [&str; 5] = [
    "provider_request",
    "credential_refreshed",
    "mail_request",
    "secret_released",
    "totp_issued",
];

impl EntryKind {
    /// The letter of the kind in a key of format 2: `c` or `u`.
    pub fn letter(self) -> char {
        match self {
            EntryKind::Control => 'c',
            EntryKind::Use => 'u',
        }
    }

    /// The kind of a letter of a key, `None` for another character.
    pub fn parse(letter: char) -> Option<EntryKind> {
        match letter {
            'c' => Some(EntryKind::Control),
            'u' => Some(EntryKind::Use),
            _ => None,
        }
    }

    /// The kind of the entry that holds an event of type `t` (7.1). `None` for a type that is
    /// not an event of the log.
    pub fn of_event(t: &str) -> Option<EntryKind> {
        if CONTROL_EVENTS.contains(&t) {
            Some(EntryKind::Control)
        } else if USE_EVENTS.contains(&t) {
            Some(EntryKind::Use)
        } else {
            None
        }
    }
}

/// What the key of an entry of format 2 carries (7.6): the fields a reader verifies the chain
/// with before it reads any object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryParts {
    pub seq: u64,
    pub time_ms: u64,
    pub kind: EntryKind,
    pub count: u32,
    pub key_id: String,
    pub body_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

/// A key under the prefix of a (node, account) chain, read back by its shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedKey {
    /// `{seq}-{hash}`: the format of the releases before v2.0.0.
    V1 { seq: u64, hash: [u8; 32] },
    /// `{seq}-{time_ms}-{kind}-{count}-{key_id}-{body_hash}-{entry_hash}`.
    V2(EntryParts),
}

/// The HPKE AAD of an entry: `UTF-8(node + "\n" + user_id + "\n" + key_id + "\n" + decimal seq)`.
pub fn entry_aad(node: &str, user_id: &str, key_id: &str, seq: u64) -> Vec<u8> {
    format!("{node}\n{user_id}\n{key_id}\n{seq}").into_bytes()
}

/// Format 1: `entry_hash` = `SHA-256("pickle.secure.v1.log-chain\n" || body)`.
pub fn entry_hash(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(purpose::LOG_CHAIN.as_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

/// Format 2: `body_hash` = `SHA-256(body)`.
pub fn body_hash(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

/// Format 2: `entry_hash` = `SHA-256("pickle.secure.v2.log-chain\n" || prev || body_hash ||
/// UTF-8(fields))`. `prev` is the `entry_hash` of the entry before (32 zero bytes for the first
/// entry) and `fields` the first five parts of the key of the entry ([`key_fields`]). Every input
/// is a part of the key of the entry or of the key before it, so a reader computes the chain from
/// a listing, and a key whose `entry_hash` satisfies the equation carries the `seq`, `time_ms`,
/// `kind`, `count` and `key_id` the node wrote: no key of other parts has the same hash.
pub fn entry_hash_v2(prev: &[u8; 32], body_hash: &[u8; 32], fields: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(purpose::LOG_CHAIN_V2.as_bytes());
    hasher.update(prev);
    hasher.update(body_hash);
    hasher.update(fields.as_bytes());
    hasher.finalize().into()
}

/// The first five parts of the key of an entry of format 2, as the key writes them:
/// `{seq}-{time_ms}-{kind}-{count}-{key_id}` with `seq` as 20 decimal digits, `time_ms` as 13,
/// `kind` the letter of the kind, `count` as 3 digits and `key_id` as 16 hexadecimal characters
/// (57 characters). They are an input of [`entry_hash_v2`].
pub fn key_fields(seq: u64, time_ms: u64, kind: EntryKind, count: u32, key_id: &str) -> String {
    format!(
        "{seq:020}-{time_ms:013}-{}-{count:03}-{key_id}",
        kind.letter()
    )
}

impl EntryParts {
    /// The first five parts of the key of this entry ([`key_fields`]).
    pub fn fields(&self) -> String {
        key_fields(self.seq, self.time_ms, self.kind, self.count, &self.key_id)
    }
}

/// The prefix of the keys of one (node, account) chain: `v1/accounts/{user_id}/{node}/`.
pub fn chain_prefix(user_id: &str, node: &str) -> String {
    format!("v1/accounts/{user_id}/{node}/")
}

/// The key of the object of an entry of format 1 in the log store (7.6):
/// `v1/accounts/{user_id}/{node}/{seq}-{hash}`, with `seq` as 20 decimal digits and `hash` as
/// `b64u(entry_hash)`. The hash is that of the bytes of the entry body, so the key names one
/// entry: a reader takes an object of this key for the entry when its body has this hash and
/// verifies under the signing key of `node`.
pub fn object_key(user_id: &str, node: &str, seq: u64, entry_hash: &[u8; 32]) -> String {
    format!(
        "{}{seq:020}-{}",
        chain_prefix(user_id, node),
        b64u(entry_hash)
    )
}

/// The key of the object of an entry of format 2 in the log store (7.6):
/// `v1/accounts/{user_id}/{node}/{seq}-{time_ms}-{kind}-{count}-{key_id}-{body_hash}-{entry_hash}`:
/// the five parts of [`key_fields`] and the two hashes as b64u. Every part has a fixed width, so
/// the key is read by position ([`parse_object_key`]).
pub fn object_key_v2(user_id: &str, node: &str, parts: &EntryParts) -> String {
    format!(
        "{}{}-{}-{}",
        chain_prefix(user_id, node),
        parts.fields(),
        b64u(&parts.body_hash),
        b64u(&parts.entry_hash)
    )
}

/// Width of the fields of a key: `seq`, `time_ms`, `count`, `key_id`, a b64u hash.
const SEQ_DIGITS: usize = 20;
const TIME_DIGITS: usize = 13;
const COUNT_DIGITS: usize = 3;
const KEY_ID_CHARS: usize = 16;
const HASH_CHARS: usize = 43;
/// Length of the part of a key of format 1 after the prefix.
const V1_LENGTH: usize = SEQ_DIGITS + 1 + HASH_CHARS;
/// Length of the part of a key of format 2 after the prefix.
const V2_LENGTH: usize = SEQ_DIGITS
    + 1
    + TIME_DIGITS
    + 1
    + 1
    + 1
    + COUNT_DIGITS
    + 1
    + KEY_ID_CHARS
    + 1
    + HASH_CHARS
    + 1
    + HASH_CHARS;

fn digits<T: std::str::FromStr>(text: &str) -> Option<T> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Reads a key of the log store under `prefix` (the chain prefix of [`chain_prefix`]). A key
/// of format 2 has seven parts of fixed width, a key of format 1 two. Any other shape, a
/// `seq` of 0, a `count` outside 1 to [`limits::ENTRY_EVENTS`], a `key_id` that is not 16
/// lower-case hexadecimal characters and a hash that is not the b64u of 32 bytes are `None`:
/// such a key is not an entry of the chain and a reader leaves it out.
pub fn parse_object_key(key: &str, prefix: &str) -> Option<ParsedKey> {
    let rest = key.strip_prefix(prefix)?;
    if !rest.is_ascii() {
        return None;
    }
    match rest.len() {
        V1_LENGTH => {
            let (seq, hash) = (&rest[..SEQ_DIGITS], &rest[SEQ_DIGITS + 1..]);
            if &rest[SEQ_DIGITS..SEQ_DIGITS + 1] != "-" {
                return None;
            }
            let seq: u64 = digits(seq)?;
            if seq == 0 {
                return None;
            }
            let hash = b64u_decode_array::<32>(hash).ok()?;
            Some(ParsedKey::V1 { seq, hash })
        }
        V2_LENGTH => {
            let mut fields = Vec::with_capacity(7);
            let mut at = 0;
            for width in [
                SEQ_DIGITS,
                TIME_DIGITS,
                1,
                COUNT_DIGITS,
                KEY_ID_CHARS,
                HASH_CHARS,
                HASH_CHARS,
            ] {
                fields.push(&rest[at..at + width]);
                at += width;
                if at < rest.len() {
                    if &rest[at..at + 1] != "-" {
                        return None;
                    }
                    at += 1;
                }
            }
            let seq: u64 = digits(fields[0])?;
            let time_ms: u64 = digits(fields[1])?;
            let kind = EntryKind::parse(fields[2].chars().next()?)?;
            let count: u32 = digits(fields[3])?;
            let key_id = fields[4];
            if seq == 0
                || count == 0
                || count as usize > limits::ENTRY_EVENTS
                || !key_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return None;
            }
            Some(ParsedKey::V2(EntryParts {
                seq,
                time_ms,
                kind,
                count,
                key_id: key_id.to_string(),
                body_hash: b64u_decode_array::<32>(fields[5]).ok()?,
                entry_hash: b64u_decode_array::<32>(fields[6]).ok()?,
            }))
        }
        _ => None,
    }
}

/// Format 1: creates the entry that follows `head` and returns it with the new end of the
/// chain. The releases before v2.0.0 wrote entries this way; the vector `log_v1` and the tests
/// of a reader of format 1 use it.
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
    let plaintext = Zeroizing::new(to_json(event));
    let (enc, ct) = hpke_seal(
        log_pk,
        purpose::LOG_ENTRY_SEAL.as_bytes(),
        &entry_aad(&node, user_id, key_id, seq),
        &plaintext,
        hpke_seed.expose_secret(),
    )
    .expect("the log public key of an accepted grant can be sealed to");
    let body = to_json(&EntryBodyV1 {
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

/// Format 2: creates the entry that follows `head` from the events of an open batch (a use
/// entry) or from one control event (a control entry), and returns it with the new end of the
/// chain and the parts of its key.
///
/// The plaintext is the JSON array of `events` in the order given, sealed to `log_pk` with
/// single-shot HPKE: info `pickle.secure.v2.log-entry`, AAD [`entry_aad`]. `time_ms` is the
/// time the batch was closed. `hpke_seed` is as in [`append`]. The signature context is
/// `pickle.secure.v2.log-entry\n`, and the end of the chain is
/// [`entry_hash_v2`]`(head.hash, body_hash(body), key_fields(..))`.
///
/// # Panics
///
/// Panics when `events` is empty or longer than [`limits::ENTRY_EVENTS`], when the plaintext is
/// longer than [`limits::ENTRY_PLAINTEXT_BYTES`], when a control entry is given more than one
/// event, and when HPKE cannot seal to `log_pk`. A node checks the first three before it closes
/// a batch, and a `log_pk` of an accepted grant can be sealed to.
#[allow(clippy::too_many_arguments)]
pub fn append_batch(
    keys: &NodeKeys,
    head: &Head,
    user_id: &str,
    key_id: &str,
    log_pk: &[u8; 32],
    time_ms: u64,
    kind: EntryKind,
    events: &[serde_json::Value],
    hpke_seed: &Secret<[u8; 32]>,
) -> (Signed, Head, EntryParts) {
    assert!(
        !events.is_empty() && events.len() <= limits::ENTRY_EVENTS,
        "an entry holds 1 to {} events",
        limits::ENTRY_EVENTS
    );
    assert!(
        kind == EntryKind::Use || events.len() == 1,
        "a control entry holds one event"
    );
    let node = keys.node();
    let seq = head.seq + 1;
    let plaintext = Zeroizing::new(to_json(&serde_json::Value::Array(events.to_vec())));
    assert!(
        plaintext.len() <= limits::ENTRY_PLAINTEXT_BYTES,
        "the plaintext of an entry holds at most {} bytes",
        limits::ENTRY_PLAINTEXT_BYTES
    );
    let (enc, ct) = hpke_seal(
        log_pk,
        purpose::LOG_ENTRY_SEAL_V2.as_bytes(),
        &entry_aad(&node, user_id, key_id, seq),
        &plaintext,
        hpke_seed.expose_secret(),
    )
    .expect("the log public key of an accepted grant can be sealed to");
    let count = events.len() as u32;
    let body = to_json(&EntryBody {
        v: 2,
        node,
        user_id: user_id.to_string(),
        key_id: key_id.to_string(),
        seq,
        prev: b64u(&head.hash),
        time_ms,
        kind: kind.letter().to_string(),
        count,
        enc: b64u(&enc),
        ct: b64u(&ct),
    });
    let body_hash = body_hash(&body);
    let fields = key_fields(seq, time_ms, kind, count, key_id);
    let hash = entry_hash_v2(&head.hash, &body_hash, &fields);
    let parts = EntryParts {
        seq,
        time_ms,
        kind,
        count,
        key_id: key_id.to_string(),
        body_hash,
        entry_hash: hash,
    };
    (
        keys.sign(purpose::LOG_ENTRY_V2, &body),
        Head { seq, hash },
        parts,
    )
}

/// The last entry a node created for an account in format 3: its `seq` and the hash of its
/// body. The next entry carries that hash as `prev`. Before the first entry the `seq` is 0 and
/// the hash is 32 zero bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Last {
    pub seq: u64,
    pub body_hash: [u8; 32],
}

impl Last {
    /// The state of a (node, account) pair without an entry.
    pub const NONE: Last = Last {
        seq: 0,
        body_hash: [0u8; 32],
    };
}

/// What the key of an entry of format 3 says about the content of the entry (7.6): the name of
/// the one event of a control entry, or the number of events of a use entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryLabel {
    Control(String),
    Use(u32),
}

/// What the key of an entry of format 3 carries after the prefix of its account (7.6). A reader
/// that holds the key knows the time, the node and the kind of the entry before it reads the
/// object, and verifies the object it reads against `body_hash`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryKey {
    /// The `time_ms` of the body of the entry.
    pub time_ms: u64,
    /// The identifier of the node that created the entry.
    pub node: String,
    /// The `seq` of the entry among the entries of that node for the account.
    pub seq: u64,
    pub label: EntryLabel,
    pub key_id: String,
    pub body_hash: [u8; 32],
}

impl EntryKey {
    /// The kind of the entry.
    pub fn kind(&self) -> EntryKind {
        match self.label {
            EntryLabel::Control(_) => EntryKind::Control,
            EntryLabel::Use(_) => EntryKind::Use,
        }
    }

    /// The number of events of the entry: 1 for a control entry.
    pub fn count(&self) -> u32 {
        match self.label {
            EntryLabel::Control(_) => 1,
            EntryLabel::Use(count) => count,
        }
    }
}

/// The largest `time_ms` a key of format 3 writes: 13 decimal digits.
pub const RTIME_MAX: u64 = 9_999_999_999_999;

/// The first part of the name of an entry of format 3: `9999999999999 − time_ms`, written as 13
/// decimal digits. A listing of a prefix returns its keys in the order of their bytes, so with
/// this part in front the first page of a listing holds the latest entries.
pub fn rtime(time_ms: u64) -> u64 {
    RTIME_MAX.saturating_sub(time_ms)
}

/// The prefix of the entries of format 3 of one account and one kind (7.6): `a3/{user_id}/c/`
/// for the control entries, `a3/{user_id}/u/` for the use entries.
pub fn entry_prefix_v3(user_id: &str, kind: EntryKind) -> String {
    format!("a3/{user_id}/{}/", kind.letter())
}

/// The key of the object of an entry of format 3 in the log store (7.6):
///
/// ```text
/// a3/{user_id}/c/{rtime}.{node}.{seq}.{event}.{key_id}.{body_hash}     a control entry
/// a3/{user_id}/u/{rtime}.{node}.{seq}.{count}.{key_id}.{body_hash}     a use entry
/// ```
///
/// `rtime` is [`rtime`] of the `time_ms` of the entry as 13 decimal digits, `seq` and `count`
/// are decimal without zeros in front, `event` is the `t` of the one event of a control entry
/// and `body_hash` the b64u of the SHA-256 of the body. The parts are joined by `.`, which is no
/// character of a b64u value, of a `key_id`, of a number or of an event name.
pub fn object_key_v3(user_id: &str, key: &EntryKey) -> String {
    let label = match &key.label {
        EntryLabel::Control(event) => event.clone(),
        EntryLabel::Use(count) => count.to_string(),
    };
    format!(
        "{}{:013}.{}.{}.{label}.{}.{}",
        entry_prefix_v3(user_id, key.kind()),
        rtime(key.time_ms),
        key.node,
        key.seq,
        key.key_id,
        b64u(&key.body_hash)
    )
}

/// True for the name of an event as a key of format 3 writes it: 1 to 64 lower-case letters,
/// digits and `_`.
fn is_event_name(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// A decimal number as a key of format 3 writes it: digits without a zero in front.
fn plain_number(text: &str) -> Option<u64> {
    if text.starts_with('0') {
        return None;
    }
    digits(text)
}

/// The 32 bytes of a b64u part of a key, when the part is the one way to write them.
fn key_bytes(text: &str) -> Option<[u8; 32]> {
    let bytes = b64u_decode_array::<32>(text).ok()?;
    (b64u(&bytes) == text).then_some(bytes)
}

/// Reads a key of the log store as the key of an entry of format 3 of the account `user_id`
/// (7.6). Any other shape is `None`: a key of another account, a first part that is not 13
/// digits, a `node` or a `body_hash` that is not the b64u of 32 bytes, a `seq` of 0 or with a
/// zero in front, a `count` outside 1 to [`limits::ENTRY_EVENTS`], an event name of another
/// form than 1 to 64 lower-case letters, digits and `_`, and a `key_id` that is not 16
/// lower-case hexadecimal characters. Such a key is not an entry, and a reader leaves it out.
pub fn parse_object_key_v3(key: &str, user_id: &str) -> Option<EntryKey> {
    let rest = key
        .strip_prefix("a3/")?
        .strip_prefix(user_id)?
        .strip_prefix('/')?;
    let (kind, rest) = match (rest.strip_prefix("c/"), rest.strip_prefix("u/")) {
        (Some(rest), _) => (EntryKind::Control, rest),
        (_, Some(rest)) => (EntryKind::Use, rest),
        _ => return None,
    };
    let parts: Vec<&str> = rest.split('.').collect();
    let [time, node, seq, label, key_id, hash] = parts.as_slice() else {
        return None;
    };
    if time.len() != TIME_DIGITS {
        return None;
    }
    let time: u64 = digits(time)?;
    let seq = plain_number(seq).filter(|seq| *seq > 0)?;
    let label = match kind {
        EntryKind::Control => {
            if !is_event_name(label) {
                return None;
            }
            EntryLabel::Control((*label).to_string())
        }
        EntryKind::Use => {
            let count = plain_number(label)
                .filter(|count| (1..=limits::ENTRY_EVENTS as u64).contains(count))?;
            EntryLabel::Use(u32::try_from(count).ok()?)
        }
    };
    let hexadecimal = key_id.len() == KEY_ID_CHARS
        && key_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !hexadecimal {
        return None;
    }
    key_bytes(node)?;
    Some(EntryKey {
        time_ms: RTIME_MAX.checked_sub(time)?,
        node: (*node).to_string(),
        seq,
        label,
        key_id: (*key_id).to_string(),
        body_hash: key_bytes(hash)?,
    })
}

/// Format 3: creates the entry that follows `last` from the events of an open batch (a use
/// entry) or from one control event (a control entry), and returns it with the new last entry
/// and the parts of its key.
///
/// The body is that of format 2 with `"v":3`, and its `prev` is the hash of the body of the
/// entry before (32 zero bytes for the first entry of the node for the account). The plaintext
/// is the JSON array of `events` in the order given, sealed to `log_pk` with single-shot HPKE:
/// info `pickle.secure.v3.log-entry`, AAD [`entry_aad`]. `time_ms` is the time the batch was
/// closed and `hpke_seed` is as in [`append`]. The signature context is
/// `pickle.secure.v3.log-entry\n`.
///
/// `None` when `events` is empty or longer than [`limits::ENTRY_EVENTS`], when the plaintext is
/// longer than [`limits::ENTRY_PLAINTEXT_BYTES`], when `time_ms` is beyond [`RTIME_MAX`], when a
/// control entry is given another number of events than one or an event whose `t` is not an
/// event name, and when HPKE cannot seal to `log_pk` (a point of small order): no entry exists
/// then, and the act that waits for it does not take place.
#[allow(clippy::too_many_arguments)]
pub fn append_v3(
    keys: &NodeKeys,
    last: &Last,
    user_id: &str,
    key_id: &str,
    log_pk: &[u8; 32],
    time_ms: u64,
    kind: EntryKind,
    events: &[serde_json::Value],
    hpke_seed: &Secret<[u8; 32]>,
) -> Option<(Signed, Last, EntryKey)> {
    if events.is_empty() || events.len() > limits::ENTRY_EVENTS || time_ms > RTIME_MAX {
        return None;
    }
    let count = u32::try_from(events.len()).ok()?;
    let label = match (kind, events) {
        (EntryKind::Use, _) => EntryLabel::Use(count),
        (EntryKind::Control, [event]) => {
            let name = event.get("t")?.as_str()?;
            if !is_event_name(name) {
                return None;
            }
            EntryLabel::Control(name.to_string())
        }
        (EntryKind::Control, _) => return None,
    };
    let node = keys.node();
    let seq = last.seq.checked_add(1)?;
    let plaintext = Zeroizing::new(to_json(&serde_json::Value::Array(events.to_vec())));
    if plaintext.len() > limits::ENTRY_PLAINTEXT_BYTES {
        return None;
    }
    let (enc, ct) = hpke_seal(
        log_pk,
        purpose::LOG_ENTRY_SEAL_V3.as_bytes(),
        &entry_aad(&node, user_id, key_id, seq),
        &plaintext,
        hpke_seed.expose_secret(),
    )
    .ok()?;
    let body = to_json(&EntryBody {
        v: 3,
        node: node.clone(),
        user_id: user_id.to_string(),
        key_id: key_id.to_string(),
        seq,
        prev: b64u(&last.body_hash),
        time_ms,
        kind: kind.letter().to_string(),
        count,
        enc: b64u(&enc),
        ct: b64u(&ct),
    });
    let body_hash = body_hash(&body);
    let key = EntryKey {
        time_ms,
        node,
        seq,
        label,
        key_id: key_id.to_string(),
        body_hash,
    };
    Some((
        keys.sign(purpose::LOG_ENTRY_V3, &body),
        Last { seq, body_hash },
        key,
    ))
}

/// The node document (7.7): the attestation document of a node as the node itself wrote it to
/// its log store. It has the keys of an attestation response (4.2) without the challenge. A
/// reader of the store verifies with it that the signing key of the entries of `node` was
/// created inside an enclave of the measurement the document states.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDocument {
    pub v: u8,
    pub platform: String,
    /// b64u of the document of the platform: a Nitro attestation document, or a local document.
    pub document: String,
    pub node: String,
    pub release: String,
}

/// The key of the node document of `node` in the log store (7.7): `n3/{node}`. Its bucket is
/// the bucket of the hash of the node identifier ([`crate::keys::shard_hash`]).
pub fn node_document_key(node: &str) -> String {
    format!("n3/{node}")
}

/// The nonce of the document of the platform inside a node document (7.7):
/// `SHA-256("pickle.secure.v3.node-document\n" || the 32 bytes of the node signing public
/// key)`. No requester chose it: a reader computes it from the node identifier, and a document
/// with this nonce was made by the node for its node document.
pub fn node_document_nonce(sign_public: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(purpose::NODE_DOCUMENT.as_bytes());
    hasher.update(sign_public);
    hasher.finalize().into()
}

/// The bytes of the node document of a node: the JSON of [`NodeDocument`] with the keys in
/// the order `v`, `platform`, `document`, `node`, `release`. `document` is the document of the
/// platform over the binding of the node and the nonce [`node_document_nonce`].
pub fn node_document(platform: &str, document: &[u8], node: &str, release: &str) -> Vec<u8> {
    to_json(&NodeDocument {
        v: 1,
        platform: platform.to_string(),
        document: b64u(document),
        node: node.to_string(),
        release: release.to_string(),
    })
}

/// Signs the head of a chain of format 1 or 2 of `user_id` (7.3), as a node of a release
/// before v2.4.0 did. A node of format 3 signs no head: the vectors and the tests of a reader
/// of the earlier formats use this function. `nonce` is the value the requester gave. A head
/// with `is_final` true carries the empty string as its nonce: a node of those releases created
/// one per account in its orderly shutdown.
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
    use crate::app::{self, ChainError, IndexError};
    use crate::encoding::{b64u_decode, verify};
    use serde_json::json;

    fn node() -> NodeKeys {
        NodeKeys::from_random(&[0x11; 32], &[0x22; 32])
    }

    #[test]
    fn the_key_of_an_entry_of_format_1_names_the_account_the_node_the_seq_and_the_hash() {
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
    fn the_first_entry_of_format_1_has_seq_1_and_a_zero_prev() {
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
        let body: EntryBodyV1 = serde_json::from_slice(&body_bytes).unwrap();
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
        let mut last = 0;
        for key in [
            "\"v\"",
            "\"node\"",
            "\"user_id\"",
            "\"key_id\"",
            "\"seq\"",
            "\"prev\"",
            "\"time_ms\"",
            "\"enc\"",
            "\"ct\"",
        ] {
            let position = text.find(key).unwrap();
            assert!(position >= last, "{key}");
            last = position;
        }
    }

    #[test]
    fn only_the_log_key_of_the_grant_opens_an_entry_of_format_1() {
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
        let other = app::derive_account_keys(&[0x34; 32]);
        assert!(app::open_entry(&other.log, &body).is_err());
    }

    #[test]
    fn the_same_seed_gives_the_same_entry_and_another_seed_another_entry() {
        let keys = node();
        let account = app::derive_account_keys(&[0x33; 32]);
        let build = |seed: &[u8; 32]| {
            append_batch(
                &keys,
                &Head::EMPTY,
                "user-1",
                &account.key_id(),
                &account.log_pk(),
                1,
                EntryKind::Control,
                &[json!({"t": "grant_revoked", "time_ms": 1})],
                &Secret::new(*seed),
            )
        };
        assert_eq!(build(&[1; 32]), build(&[1; 32]));
        assert_ne!(build(&[1; 32]).0, build(&[2; 32]).0);
    }

    #[test]
    fn a_chain_of_format_1_verifies_and_a_missing_middle_entry_is_detected() {
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
        assert!(verify(&keys.sign_public(), purpose::LOG_ENTRY_V2, &live).is_err());
    }

    /// Three entries of format 2 on one chain: a control entry, a use entry of three events,
    /// a use entry of one event.
    fn chain_v2(
        keys: &NodeKeys,
        account: &app::AccountKeys,
    ) -> (Vec<Signed>, Vec<EntryParts>, Head) {
        let batches = [
            (
                EntryKind::Control,
                vec![json!({"t": "grant_accepted", "time_ms": 100, "not_after_ms": 9_000_000, "custody": "enclave"})],
            ),
            (
                EntryKind::Use,
                (0..3)
                    .map(|index| {
                        json!({"t": "provider_request", "time_ms": 200 + index, "record_id": "r",
                            "provider": "google_workspace", "method": "GET", "host": "gmail.googleapis.com",
                            "path": format!("/gmail/v1/users/me/threads/{index}"), "query": "format=metadata",
                            "body_bytes": 0, "body_sha256": "", "context": "cli:gog", "window_s": 300})
                    })
                    .collect(),
            ),
            (
                EntryKind::Use,
                vec![json!({"t": "secret_released", "time_ms": 300, "record_id": "v", "kind": "vault_card",
                    "field": "card_cvc", "origin": "https://shop.example", "context": "browser:fill"})],
            ),
        ];
        let mut head = Head::EMPTY;
        let mut entries = Vec::new();
        let mut parts = Vec::new();
        for (index, (kind, events)) in batches.iter().enumerate() {
            let (entry, next, key) = append_batch(
                keys,
                &head,
                "user-1",
                &account.key_id(),
                &account.log_pk(),
                100 * (index as u64 + 1),
                *kind,
                events,
                &Secret::new([index as u8 + 1; 32]),
            );
            entries.push(entry);
            parts.push(key);
            head = next;
        }
        (entries, parts, head)
    }

    #[test]
    fn an_entry_of_format_2_carries_its_kind_count_and_the_hashes_of_its_key() {
        let keys = node();
        let account = app::derive_account_keys(&[0x33; 32]);
        let (entries, parts, head) = chain_v2(&keys, &account);
        assert_eq!(head.seq, 3);
        let body_bytes = verify(&keys.sign_public(), purpose::LOG_ENTRY_V2, &entries[1]).unwrap();
        let body: EntryBody = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body.v, 2);
        assert_eq!(body.node, keys.node());
        assert_eq!(body.user_id, "user-1");
        assert_eq!(body.key_id, account.key_id());
        assert_eq!(body.seq, 2);
        assert_eq!(body.prev, b64u(&parts[0].entry_hash));
        assert_eq!(body.time_ms, 200);
        assert_eq!(body.kind, "u");
        assert_eq!(body.count, 3);
        assert_eq!(parts[1].body_hash, body_hash(&body_bytes));
        assert_eq!(
            parts[1].fields(),
            format!(
                "00000000000000000002-0000000000200-u-003-{}",
                account.key_id()
            )
        );
        assert_eq!(
            parts[1].entry_hash,
            entry_hash_v2(
                &parts[0].entry_hash,
                &parts[1].body_hash,
                &parts[1].fields()
            )
        );
        assert_eq!(parts[0].kind, EntryKind::Control);
        assert_eq!(parts[0].count, 1);
        assert_eq!(parts[2].seq, 3);
        assert_eq!(head.hash, parts[2].entry_hash);
        // The body keys are in the order of section 7.1.
        let text = String::from_utf8(body_bytes.clone()).unwrap();
        let mut last = 0;
        for key in [
            "\"v\"",
            "\"node\"",
            "\"user_id\"",
            "\"key_id\"",
            "\"seq\"",
            "\"prev\"",
            "\"time_ms\"",
            "\"kind\"",
            "\"count\"",
            "\"enc\"",
            "\"ct\"",
        ] {
            let position = text.find(key).unwrap();
            assert!(position >= last, "{key}");
            last = position;
        }
        // An entry of format 2 is not accepted under the context of format 1, and the reverse.
        assert!(verify(&keys.sign_public(), purpose::LOG_ENTRY, &entries[1]).is_err());
        // The plaintext opens to the events in their order, and only with the log key.
        let events = app::open_entry_v2(&account.log, &body_bytes).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[2]["path"], "/gmail/v1/users/me/threads/2");
        let other = app::derive_account_keys(&[0x34; 32]);
        assert!(app::open_entry_v2(&other.log, &body_bytes).is_err());
    }

    #[test]
    fn the_key_of_format_2_has_seven_parts_of_fixed_width_and_is_read_back() {
        let keys = node();
        let account = app::derive_account_keys(&[0x33; 32]);
        let (_, parts, _) = chain_v2(&keys, &account);
        let prefix = chain_prefix("user-1", &keys.node());
        let key = object_key_v2("user-1", &keys.node(), &parts[1]);
        assert!(key.starts_with(&prefix));
        assert_eq!(key.len(), prefix.len() + V2_LENGTH);
        assert_eq!(
            &key[prefix.len()..prefix.len() + 40],
            "00000000000000000002-0000000000200-u-003"
        );
        assert_eq!(&key[prefix.len() + 41..prefix.len() + 57], account.key_id());
        assert_eq!(
            parse_object_key(&key, &prefix),
            Some(ParsedKey::V2(parts[1].clone()))
        );
        // A key of format 1 is read by its shape.
        let v1 = object_key("user-1", &keys.node(), 7, &[0xfb; 32]);
        assert_eq!(
            parse_object_key(&v1, &prefix),
            Some(ParsedKey::V1 {
                seq: 7,
                hash: [0xfb; 32]
            })
        );
        // Keys of another shape, another prefix, a seq of 0, a count outside the limit, a key
        // id that is not hexadecimal and a hash that is not 32 bytes are left out.
        assert_eq!(parse_object_key(&key, "v1/accounts/user-2/N/"), None);
        assert_eq!(parse_object_key(&format!("{key}x"), &prefix), None);
        assert_eq!(parse_object_key(&format!("{prefix}probe"), &prefix), None);
        let zero = key.replacen("00000000000000000002", "00000000000000000000", 1);
        assert_eq!(parse_object_key(&zero, &prefix), None);
        let big = key.replacen("-u-003-", "-u-129-", 1);
        assert_eq!(parse_object_key(&big, &prefix), None);
        let none = key.replacen("-u-003-", "-u-000-", 1);
        assert_eq!(parse_object_key(&none, &prefix), None);
        let kind = key.replacen("-u-003-", "-x-003-", 1);
        assert_eq!(parse_object_key(&kind, &prefix), None);
        let hex = key.replacen(&account.key_id(), "0123456789ABCDEF", 1);
        assert_eq!(parse_object_key(&hex, &prefix), None);
        let mut padded = key.clone();
        padded.replace_range(key.len() - 43.., &"=".repeat(43));
        assert_eq!(parse_object_key(&padded, &prefix), None);
        let v1_zero = object_key("user-1", &keys.node(), 0, &[0xfb; 32]);
        assert_eq!(parse_object_key(&v1_zero, &prefix), None);
    }

    #[test]
    fn the_keys_of_a_chain_of_format_2_verify_it_without_its_objects() {
        let keys = node();
        let account = app::derive_account_keys(&[0x33; 32]);
        let (entries, parts, head) = chain_v2(&keys, &account);
        let signed = signed_head(&keys, "user-1", &head, "bm9uY2U", 400, false);
        let public = keys.sign_public();
        assert_eq!(
            app::verify_index(
                &public,
                "user-1",
                &Head::EMPTY,
                &parts,
                &signed,
                Some("bm9uY2U")
            ),
            Ok(head)
        );
        // From a later checkpoint.
        let checkpoint = Head {
            seq: 1,
            hash: parts[0].entry_hash,
        };
        assert_eq!(
            app::verify_index(
                &public,
                "user-1",
                &checkpoint,
                &parts[1..],
                &signed,
                Some("bm9uY2U")
            ),
            Ok(head)
        );
        // A gap in the middle, a listing that ends early, a key whose hash does not follow,
        // and a second key of the same seq that satisfies the equation.
        let without_middle = [parts[0].clone(), parts[2].clone()];
        assert_eq!(
            app::verify_index(
                &public,
                "user-1",
                &Head::EMPTY,
                &without_middle,
                &signed,
                Some("bm9uY2U")
            ),
            Err(IndexError::Gap { seq: 2 })
        );
        assert_eq!(
            app::verify_index(
                &public,
                "user-1",
                &Head::EMPTY,
                &parts[..2],
                &signed,
                Some("bm9uY2U")
            ),
            Err(IndexError::Incomplete)
        );
        let mut altered = parts.clone();
        altered[1].body_hash = [0x55; 32];
        assert_eq!(
            app::verify_index(
                &public,
                "user-1",
                &Head::EMPTY,
                &altered,
                &signed,
                Some("bm9uY2U")
            ),
            Err(IndexError::Broken { seq: 2 })
        );
        let mut forged = parts[1].clone();
        forged.body_hash = body_hash(b"forged body");
        forged.entry_hash =
            entry_hash_v2(&parts[0].entry_hash, &forged.body_hash, &forged.fields());
        let with_forged = [
            parts[0].clone(),
            parts[1].clone(),
            forged.clone(),
            parts[2].clone(),
        ];
        assert_eq!(
            app::verify_index(
                &public,
                "user-1",
                &Head::EMPTY,
                &with_forged,
                &signed,
                Some("bm9uY2U")
            ),
            Err(IndexError::Ambiguous { seq: 2 })
        );
        // A key with the hashes of the genuine one and other parts (another time, kind, count or
        // key id) does not satisfy the equation: the parts are an input of the hash. The genuine
        // key beside it is the one candidate, and the chain verifies.
        for alter in [
            |parts: &mut EntryParts| parts.time_ms += 1,
            |parts: &mut EntryParts| parts.kind = EntryKind::Control,
            |parts: &mut EntryParts| parts.count = 1,
            |parts: &mut EntryParts| parts.key_id = "0123456789abcdef".to_string(),
        ] {
            let mut swapped = parts[1].clone();
            alter(&mut swapped);
            let with_swapped = [
                parts[0].clone(),
                swapped.clone(),
                parts[1].clone(),
                parts[2].clone(),
            ];
            assert_eq!(
                app::verify_index(
                    &public,
                    "user-1",
                    &Head::EMPTY,
                    &with_swapped,
                    &signed,
                    Some("bm9uY2U")
                ),
                Ok(head)
            );
            let swapped_alone = [parts[0].clone(), swapped, parts[2].clone()];
            assert_eq!(
                app::verify_index(
                    &public,
                    "user-1",
                    &Head::EMPTY,
                    &swapped_alone,
                    &signed,
                    Some("bm9uY2U")
                ),
                Err(IndexError::Broken { seq: 2 })
            );
        }
        // The objects decide an ambiguous seq: the genuine key has an object that verifies,
        // the forged key has none that does.
        let cursor = Head {
            seq: 1,
            hash: parts[0].entry_hash,
        };
        assert!(
            app::verify_entry_v2(&public, "user-1", &parts[1], Some(&cursor), &entries[1]).is_ok()
        );
        assert_eq!(
            app::verify_entry_v2(&public, "user-1", &forged, Some(&cursor), &entries[1]),
            Err(ChainError::Broken)
        );
        // A chain that does not reach the head, and a head of another nonce.
        let other_head = signed_head(
            &keys,
            "user-1",
            &Head {
                seq: 3,
                hash: [9; 32],
            },
            "bm9uY2U",
            400,
            false,
        );
        assert_eq!(
            app::verify_index(
                &public,
                "user-1",
                &Head::EMPTY,
                &parts,
                &other_head,
                Some("bm9uY2U")
            ),
            Err(IndexError::Broken { seq: 3 })
        );
        assert_eq!(
            app::verify_index(
                &public,
                "user-1",
                &Head::EMPTY,
                &parts,
                &signed,
                Some("b3RoZXI")
            ),
            Err(IndexError::Head)
        );
    }

    #[test]
    fn an_entry_of_format_2_is_verified_against_its_key_and_its_predecessor() {
        let keys = node();
        let account = app::derive_account_keys(&[0x33; 32]);
        let (entries, parts, _) = chain_v2(&keys, &account);
        let public = keys.sign_public();
        let cursor = Head {
            seq: 1,
            hash: parts[0].entry_hash,
        };
        let body =
            app::verify_entry_v2(&public, "user-1", &parts[1], Some(&cursor), &entries[1]).unwrap();
        assert_eq!((body.seq, body.count, body.kind.as_str()), (2, 3, "u"));
        // Without a predecessor the link is not checked (the screen reads one entry).
        assert!(app::verify_entry_v2(&public, "user-1", &parts[1], None, &entries[1]).is_ok());
        // The key names another kind, count, key id or time than the body: not this entry.
        for alter in [
            |parts: &mut EntryParts| parts.kind = EntryKind::Control,
            |parts: &mut EntryParts| parts.count = 2,
            |parts: &mut EntryParts| parts.key_id = "0123456789abcdef".to_string(),
            |parts: &mut EntryParts| parts.time_ms += 1,
            |parts: &mut EntryParts| parts.seq = 3,
        ] {
            let mut altered = parts[1].clone();
            alter(&mut altered);
            assert_eq!(
                app::verify_entry_v2(&public, "user-1", &altered, Some(&cursor), &entries[1]),
                Err(ChainError::Broken)
            );
        }
        // Another predecessor, another account, another node, an entry of format 1.
        assert_eq!(
            app::verify_entry_v2(
                &public,
                "user-1",
                &parts[1],
                Some(&Head::EMPTY),
                &entries[1]
            ),
            Err(ChainError::Broken)
        );
        assert_eq!(
            app::verify_entry_v2(&public, "user-2", &parts[1], Some(&cursor), &entries[1]),
            Err(ChainError::Broken)
        );
        let other = NodeKeys::from_random(&[0x12; 32], &[0x22; 32]);
        assert_eq!(
            app::verify_entry_v2(
                &other.sign_public(),
                "user-1",
                &parts[1],
                Some(&cursor),
                &entries[1]
            ),
            Err(ChainError::Broken)
        );
        let (v1, _) = append(
            &keys,
            &Head::EMPTY,
            "user-1",
            &account.key_id(),
            &account.log_pk(),
            100,
            &json!({"t": "grant_revoked"}),
            &Secret::new([7; 32]),
        );
        assert_eq!(
            app::verify_entry_v2(&public, "user-1", &parts[0], None, &v1),
            Err(ChainError::Broken)
        );
    }

    #[test]
    fn the_kind_of_an_event_is_the_kind_of_its_entry() {
        for t in CONTROL_EVENTS {
            assert_eq!(EntryKind::of_event(t), Some(EntryKind::Control));
        }
        for t in USE_EVENTS {
            assert_eq!(EntryKind::of_event(t), Some(EntryKind::Use));
        }
        assert_eq!(EntryKind::of_event("head"), None);
        assert_eq!(EntryKind::parse('c'), Some(EntryKind::Control));
        assert_eq!(EntryKind::parse('u'), Some(EntryKind::Use));
        assert_eq!(EntryKind::parse('x'), None);
        assert_eq!(EntryKind::Control.letter(), 'c');
        assert_eq!(EntryKind::Use.letter(), 'u');
    }

    #[test]
    #[should_panic(expected = "a control entry holds one event")]
    fn a_control_entry_holds_one_event() {
        let keys = node();
        let account = app::derive_account_keys(&[0x33; 32]);
        append_batch(
            &keys,
            &Head::EMPTY,
            "user-1",
            &account.key_id(),
            &account.log_pk(),
            1,
            EntryKind::Control,
            &[json!({"t": "grant_revoked"}), json!({"t": "grant_revoked"})],
            &Secret::new([1; 32]),
        );
    }

    #[test]
    #[should_panic(expected = "an entry holds 1 to 128 events")]
    fn an_entry_holds_at_most_128_events() {
        let keys = node();
        let account = app::derive_account_keys(&[0x33; 32]);
        let events: Vec<serde_json::Value> =
            (0..129).map(|_| json!({"t": "totp_issued"})).collect();
        append_batch(
            &keys,
            &Head::EMPTY,
            "user-1",
            &account.key_id(),
            &account.log_pk(),
            1,
            EntryKind::Use,
            &events,
            &Secret::new([1; 32]),
        );
    }

    /// The parts of the key of a use entry of two events.
    fn use_key() -> EntryKey {
        EntryKey {
            time_ms: 1_790_000_000_000,
            node: b64u(&[0x4e; 32]),
            seq: 7,
            label: EntryLabel::Use(2),
            key_id: "0123456789abcdef".to_string(),
            body_hash: [0xfb; 32],
        }
    }

    #[test]
    fn the_key_of_an_entry_of_format_3_starts_with_the_time_counted_down() {
        let key = use_key();
        let node = b64u(&[0x4e; 32]);
        let hash = "-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s";
        assert_eq!(
            object_key_v3("user-1", &key),
            format!("a3/user-1/u/8209999999999.{node}.7.2.0123456789abcdef.{hash}")
        );
        let control = EntryKey {
            label: EntryLabel::Control("grant_accepted".to_string()),
            seq: 1,
            ..key.clone()
        };
        assert_eq!(
            object_key_v3("user-1", &control),
            format!("a3/user-1/c/8209999999999.{node}.1.grant_accepted.0123456789abcdef.{hash}")
        );
        assert_eq!((control.kind(), control.count()), (EntryKind::Control, 1));
        assert_eq!((key.kind(), key.count()), (EntryKind::Use, 2));
        // The first part has 13 digits at every time, so the keys of one prefix sort by time
        // alone, the latest first.
        assert_eq!((rtime(0), rtime(RTIME_MAX)), (RTIME_MAX, 0));
        let at = |time_ms: u64| {
            object_key_v3(
                "u",
                &EntryKey {
                    time_ms,
                    ..use_key()
                },
            )
        };
        assert!(at(0).starts_with("a3/u/u/9999999999999."));
        assert!(at(RTIME_MAX).starts_with("a3/u/u/0000000000000."));
        assert!(at(2_000) < at(1_999) && at(1_999) < at(1));
        // A key reads back to its parts, also for a `user_id` that holds the separators.
        for user_id in ["user-1", "a/b", "a.b", "사용자 1", "a3/x/c"] {
            for parts in [&key, &control] {
                let text = object_key_v3(user_id, parts);
                assert_eq!(parse_object_key_v3(&text, user_id).as_ref(), Some(parts));
            }
        }
    }

    #[test]
    fn a_key_of_another_shape_is_not_a_key_of_format_3() {
        let key = object_key_v3("user-1", &use_key());
        assert!(parse_object_key_v3(&key, "user-1").is_some());
        let node = b64u(&[0x4e; 32]);
        let hash = b64u(&[0xfb; 32]);
        let with = |rest: &str| format!("a3/user-1/u/{rest}");
        for other in [
            // Another account, another prefix, another kind letter.
            key.replacen("user-1", "user-2", 1),
            key.replacen("a3/", "a4/", 1),
            key.replacen("/u/", "/x/", 1),
            // A part too few and a part too many.
            with(&format!("8209999999999.{node}.7.2.0123456789abcdef")),
            with(&format!(
                "8209999999999.{node}.7.2.0123456789abcdef.{hash}.x"
            )),
            // A time of other than 13 digits.
            with(&format!("820999999999.{node}.7.2.0123456789abcdef.{hash}")),
            with(&format!(
                "82099999999990.{node}.7.2.0123456789abcdef.{hash}"
            )),
            with(&format!("82099999x9999.{node}.7.2.0123456789abcdef.{hash}")),
            // A node that is not the b64u of 32 bytes.
            with(&format!("8209999999999.NODE.7.2.0123456789abcdef.{hash}")),
            // A `seq` of 0, with a zero in front, with a sign.
            with(&format!("8209999999999.{node}.0.2.0123456789abcdef.{hash}")),
            with(&format!(
                "8209999999999.{node}.07.2.0123456789abcdef.{hash}"
            )),
            with(&format!(
                "8209999999999.{node}.+7.2.0123456789abcdef.{hash}"
            )),
            // A `count` of 0 and one above the cap of an entry.
            with(&format!("8209999999999.{node}.7.0.0123456789abcdef.{hash}")),
            with(&format!(
                "8209999999999.{node}.7.129.0123456789abcdef.{hash}"
            )),
            // A `key_id` of another length, and one in upper case.
            with(&format!("8209999999999.{node}.7.2.0123456789abcde.{hash}")),
            with(&format!("8209999999999.{node}.7.2.0123456789ABCDEF.{hash}")),
            // A hash of another length, and a second way to write the same 32 bytes.
            with(&format!(
                "8209999999999.{node}.7.2.0123456789abcdef.{}",
                &hash[..42]
            )),
            with(&format!(
                "8209999999999.{node}.7.2.0123456789abcdef.{}t",
                &hash[..42]
            )),
        ] {
            assert_eq!(parse_object_key_v3(&other, "user-1"), None, "{other}");
        }
        // The event name of a control key: lower-case letters, digits and `_`, 1 to 64.
        let control = |event: &str| {
            format!("a3/user-1/c/8209999999999.{node}.1.{event}.0123456789abcdef.{hash}")
        };
        for event in ["grant_accepted", "a", "event_2", &"e".repeat(64)] {
            assert!(
                parse_object_key_v3(&control(event), "user-1").is_some(),
                "{event}"
            );
        }
        for event in [
            "",
            "Grant",
            "grant-accepted",
            "grant accepted",
            &"e".repeat(65),
        ] {
            assert_eq!(
                parse_object_key_v3(&control(event), "user-1"),
                None,
                "{event}"
            );
        }
        // A key of the two earlier formats is no key of format 3, and the reverse.
        let earlier = object_key("user-1", &node, 7, &[0xfb; 32]);
        assert_eq!(parse_object_key_v3(&earlier, "user-1"), None);
        assert_eq!(parse_object_key(&key, &chain_prefix("user-1", &node)), None);
    }

    #[test]
    fn an_entry_of_format_3_carries_the_hash_of_the_body_before_it() {
        let keys = node();
        let account = app::derive_account_keys(&[0x33; 32]);
        let append = |last: &Last, kind: EntryKind, events: &[serde_json::Value]| {
            append_v3(
                &keys,
                last,
                "user-1",
                &account.key_id(),
                &account.log_pk(),
                5_000,
                kind,
                events,
                &Secret::new([0x44; 32]),
            )
        };
        let (first, last, key) = append(
            &Last::NONE,
            EntryKind::Control,
            &[json!({"t": "grant_revoked", "time_ms": 5_000})],
        )
        .unwrap();
        let body_bytes = verify(&keys.sign_public(), purpose::LOG_ENTRY_V3, &first).unwrap();
        // The body has the keys of format 2 in their order, with the version 3.
        let text = String::from_utf8(body_bytes.clone()).unwrap();
        assert!(text.starts_with(&format!(
            "{{\"v\":3,\"node\":\"{}\",\"user_id\":\"user-1\",\"key_id\":\"{}\",\"seq\":1,\"prev\":\"{}\",\"time_ms\":5000,\"kind\":\"c\",\"count\":1,\"enc\":\"",
            keys.node(),
            account.key_id(),
            b64u(&[0u8; 32])
        )));
        assert_eq!(
            last,
            Last {
                seq: 1,
                body_hash: body_hash(&body_bytes)
            }
        );
        assert_eq!(
            key,
            EntryKey {
                time_ms: 5_000,
                node: keys.node(),
                seq: 1,
                label: EntryLabel::Control("grant_revoked".to_string()),
                key_id: account.key_id(),
                body_hash: last.body_hash,
            }
        );
        // A signature of format 3 does not verify as one of format 2.
        assert!(verify(&keys.sign_public(), purpose::LOG_ENTRY_V2, &first).is_err());
        let use_events = [
            json!({"t": "secret_released", "time_ms": 5_000}),
            json!({"t": "totp_issued", "time_ms": 5_000}),
        ];
        let (second, next, key) = append(&last, EntryKind::Use, &use_events).unwrap();
        let body: EntryBody = serde_json::from_slice(
            &verify(&keys.sign_public(), purpose::LOG_ENTRY_V3, &second).unwrap(),
        )
        .unwrap();
        assert_eq!((body.seq, body.prev), (2, b64u(&last.body_hash)));
        assert_eq!((next.seq, &key.label), (2, &EntryLabel::Use(2)));
        // Only the log key of the grant opens it, to the events in their order.
        let (_, bytes) = app::verify_entry_v3("user-1", &key, &second).unwrap();
        assert_eq!(
            app::open_entry_v3(&account.log, &bytes).unwrap(),
            use_events
        );
        let other = app::derive_account_keys(&[0x34; 32]);
        assert!(app::open_entry_v3(&other.log, &bytes).is_err());

        // What is no entry: no event, too many events, a control entry of two events or of an
        // event without a name, a plaintext above its cap, a time beyond the 13 digits of a
        // key, and a log key HPKE cannot seal to. Nothing panics.
        let event = json!({"t": "secret_released", "time_ms": 5_000});
        assert!(append(&last, EntryKind::Use, &[]).is_none());
        let many = vec![event.clone(); limits::ENTRY_EVENTS + 1];
        assert!(append(&last, EntryKind::Use, &many).is_none());
        assert!(append(&last, EntryKind::Use, &many[..limits::ENTRY_EVENTS]).is_some());
        assert!(append(&last, EntryKind::Control, &many[..2]).is_none());
        assert!(append(&last, EntryKind::Control, &[json!({"time_ms": 1})]).is_none());
        assert!(append(&last, EntryKind::Control, &[json!({"t": "Not A Name"})]).is_none());
        let large =
            json!({"t": "secret_released", "context": "x".repeat(limits::ENTRY_PLAINTEXT_BYTES)});
        assert!(append(&last, EntryKind::Use, &[large]).is_none());
        let sealed = |time_ms: u64, log_pk: &[u8; 32]| {
            append_v3(
                &keys,
                &last,
                "user-1",
                &account.key_id(),
                log_pk,
                time_ms,
                EntryKind::Use,
                std::slice::from_ref(&event),
                &Secret::new([0x44; 32]),
            )
        };
        assert!(sealed(RTIME_MAX, &account.log_pk()).is_some());
        assert!(sealed(RTIME_MAX + 1, &account.log_pk()).is_none());
        assert!(sealed(5_000, &[0u8; 32]).is_none());
    }

    #[test]
    fn the_node_document_has_a_key_and_a_nonce_of_its_node() {
        let keys = node();
        assert_eq!(
            node_document_key(&keys.node()),
            format!("n3/{}", keys.node())
        );
        let nonce = node_document_nonce(&keys.sign_public());
        let mut hasher = Sha256::new();
        hasher.update(b"pickle.secure.v3.node-document\n");
        hasher.update(keys.sign_public());
        assert_eq!(nonce, <[u8; 32]>::from(hasher.finalize()));
        assert_ne!(nonce, node_document_nonce(&[0u8; 32]));
        // The object has the keys of an attestation response without the challenge, in order.
        assert_eq!(
            String::from_utf8(node_document("nitro", b"document", "NODE", "v2.4.0")).unwrap(),
            r#"{"v":1,"platform":"nitro","document":"ZG9jdW1lbnQ","node":"NODE","release":"v2.4.0"}"#
        );
    }
}
