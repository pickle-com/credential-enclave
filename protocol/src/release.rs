//! Releases (protocol.md section 9 and 10.3): the release statement, the list of the old
//! releases of a program, and a transparency log with what it returns to show that it holds an
//! entry.
//!
//! A release is a tag of the public repository and the enclave image file built from the
//! commit of that tag. Its identity is its measurement: PCR0, PCR1 and PCR2. The release
//! statement is the file `measurements.json` of the release, which states its name, its commit
//! and its measurement. Which measurement a node accepts for a peer is decided where the
//! attestation of that peer is verified (`enclave/src/attest.rs`), with the proof of
//! `release_proofs.rs` or with the list of old releases read here.
//!
//! A transparency log of this module has the form Rekor v1 (`rekor.sigstore.dev`). The log
//! answers an upload with a signed entry timestamp, its signature over the entry and the time
//! it took it, and with an inclusion proof: the audit path from the entry to the root of a
//! tree whose head it signed (a checkpoint).
//!
//! The keys of the logs are arguments: the node program passes the table that is compiled
//! into it. Nothing here sends a request to a log or reads a clock: a verdict depends on the
//! bytes of the call and on these compiled values.

use std::fmt;
use std::marker::PhantomData;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::de::{Error as _, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};

use crate::certificate::{ecdsa_verifies, Curve, Hash, P256_SPKI_PREFIX};
use crate::limits;

/// A release and the measurement of its enclave image: one element of a list of old releases,
/// and what the entry of a delegation transfer names of the node that received a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseMeasurement {
    /// The name of the release: its tag.
    pub release: String,
    /// PCR0, PCR1 and PCR2 of the enclave image of that release.
    pub pcrs: [[u8; 48]; 3],
}

/// What a release statement states of its release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseStatement {
    /// The name of the release: its tag.
    pub release: String,
    /// The commit of that tag: 40 lower-case hexadecimal characters.
    pub git_commit: String,
    /// PCR0, PCR1 and PCR2 of the enclave image of that release.
    pub pcrs: [[u8; 48]; 3],
}

impl ReleaseStatement {
    /// The release and its measurement.
    pub fn measurement(&self) -> ReleaseMeasurement {
        ReleaseMeasurement {
            release: self.release.clone(),
            pcrs: self.pcrs,
        }
    }
}

/// The keys of a JSON object that names a release and its measurement.
trait Keys {
    const KEYS: &'static [&'static str];
}

/// The keys of an element of a list of old releases.
struct MeasurementKeys;

impl Keys for MeasurementKeys {
    const KEYS: &'static [&'static str] = &["release", "pcr0", "pcr1", "pcr2"];
}

/// The keys of a release statement.
struct StatementKeys;

impl Keys for StatementKeys {
    const KEYS: &'static [&'static str] = &["release", "git_commit", "pcr0", "pcr1", "pcr2"];
}

/// The values of the keys `K` of a JSON object, as text and in the order of `K`.
struct Fields<K>(Vec<String>, PhantomData<K>);

impl<'de, K: Keys> Deserialize<'de> for Fields<K> {
    /// Reads a JSON object in which each of the keys occurs once and holds a string. Other
    /// keys are passed over. A value that is not an object, a key of `K` that occurs twice
    /// and a value of a key of `K` that is not a string are refused: the object states one
    /// value for each key.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Reader<K>(PhantomData<K>);

        impl<'de, K: Keys> Visitor<'de> for Reader<K> {
            type Value = Fields<K>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an object with {}", K::KEYS.join(", "))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values: Vec<Option<String>> = vec![None; K::KEYS.len()];
                while let Some(key) = map.next_key::<String>()? {
                    // The value of one of the keys, with the name of that key.
                    let named = K::KEYS
                        .iter()
                        .zip(values.iter_mut())
                        .find(|(name, _)| **name == key);
                    match named {
                        Some((name, Some(_))) => return Err(A::Error::duplicate_field(name)),
                        Some((_, value)) => *value = Some(map.next_value()?),
                        None => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                let fields = values
                    .into_iter()
                    .zip(K::KEYS)
                    .map(|(value, name)| value.ok_or_else(|| A::Error::missing_field(name)))
                    .collect::<Result<Vec<String>, A::Error>>()?;
                Ok(Fields(fields, PhantomData))
            }
        }

        deserializer.deserialize_map(Reader(PhantomData))
    }
}

/// Reads a PCR: 96 lower-case hexadecimal characters.
fn pcr(text: &str) -> Option<[u8; 48]> {
    hex_bytes(text)
}

/// Reads `N` bytes from twice as many lower-case hexadecimal characters.
pub(crate) fn hex_bytes<const N: usize>(text: &str) -> Option<[u8; N]> {
    let (pairs, []) = text.as_bytes().as_chunks::<2>() else {
        return None;
    };
    if pairs.len() != N {
        return None;
    }
    let mut value = [0u8; N];
    for (byte, [high, low]) in value.iter_mut().zip(pairs) {
        *byte = (nibble(*high)? << 4) | nibble(*low)?;
    }
    Some(value)
}

fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// Lower-case hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// True when `name` has the form of the name of a release: the tag of a release begins with
/// `v` and holds, after it, one character or more of `A` to `Z`, `a` to `z`, `0` to `9`, `.`,
/// `_` and `-`.
pub fn is_release_name(name: &str) -> bool {
    name.strip_prefix('v').is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    })
}

/// The measurement three PCR texts state, when each is 96 lower-case hexadecimal characters
/// and none is all zero: a PCR that is all zero is the value of a debug-mode enclave, whatever
/// that enclave runs, and the measurement of no release.
fn measurement(pcr0: &str, pcr1: &str, pcr2: &str) -> Option<[[u8; 48]; 3]> {
    let pcrs = [pcr(pcr0)?, pcr(pcr1)?, pcr(pcr2)?];
    pcrs.iter().all(|pcr| pcr != &[0u8; 48]).then_some(pcrs)
}

/// The most arrays and objects inside one another of a JSON value of a release proof.
const JSON_DEPTH: usize = 32;

/// True when a JSON value holds at most 32 arrays and objects inside one another. Every
/// reader of a release proof reads such a value the same way.
pub(crate) fn is_sound_json(value: &serde_json::Value) -> bool {
    fn within(value: &serde_json::Value, depth: usize) -> bool {
        match value {
            serde_json::Value::Array(items) => {
                depth < JSON_DEPTH && items.iter().all(|item| within(item, depth + 1))
            }
            serde_json::Value::Object(members) => {
                depth < JSON_DEPTH && members.values().all(|item| within(item, depth + 1))
            }
            _ => true,
        }
    }
    within(value, 0)
}

/// Reads a text of JSON: UTF-8 bytes that are one JSON value [`is_sound_json`] takes.
pub(crate) fn read_json(bytes: &[u8]) -> Option<serde_json::Value> {
    let text = std::str::from_utf8(bytes).ok()?;
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .filter(is_sound_json)
}

/// Reads a release statement (protocol.md section 9): the bytes of the file
/// `measurements.json` of a release.
///
/// They are at most 16,384 bytes of UTF-8 and a JSON object that states `release`,
/// `git_commit`, `pcr0`, `pcr1` and `pcr2` once each, as strings: `release` the name of a
/// release ([`is_release_name`]), `git_commit` 40 lower-case hexadecimal characters, and each
/// PCR 96 lower-case hexadecimal characters that are not all zero. The other keys of the
/// object are not read. The object holds at most 32 arrays and objects inside one another.
pub fn read_statement(statement: &[u8]) -> Option<ReleaseStatement> {
    if statement.len() > limits::RELEASE_STATEMENT_BYTES {
        return None;
    }
    if !read_json(statement)?.is_object() {
        return None;
    }
    let Fields::<StatementKeys>(fields, _) = serde_json::from_slice(statement).ok()?;
    let [release, git_commit, pcr0, pcr1, pcr2] = <[String; 5]>::try_from(fields).ok()?;
    if !is_release_name(&release) {
        return None;
    }
    hex_bytes::<20>(&git_commit)?;
    Some(ReleaseStatement {
        pcrs: measurement(&pcr0, &pcr1, &pcr2)?,
        release,
        git_commit,
    })
}

/// Reads a list of old releases (protocol.md 10.3): a JSON array of
/// `{"release":"...","pcr0":"<96 hex>","pcr1":"<96 hex>","pcr2":"<96 hex>"}`.
///
/// `None` when the list does not have that form, when the release of an element is not the
/// name of a release, and when a PCR of an element is all zero (the measurement of a
/// debug-mode enclave).
pub fn read_predecessors(list: &[u8]) -> Option<Vec<ReleaseMeasurement>> {
    let elements: Vec<Fields<MeasurementKeys>> = serde_json::from_slice(list).ok()?;
    elements
        .into_iter()
        .map(|Fields(fields, _)| {
            let [release, pcr0, pcr1, pcr2] = <[String; 4]>::try_from(fields).ok()?;
            is_release_name(&release).then_some(())?;
            Some(ReleaseMeasurement {
                pcrs: measurement(&pcr0, &pcr1, &pcr2)?,
                release,
            })
        })
        .collect()
}

/// The length of the SubjectPublicKeyInfo (DER) of an ECDSA P-256 public key.
const P256_SPKI_BYTES: usize = 91;

/// True when `spki_der` is the DER of the SubjectPublicKeyInfo of an ECDSA P-256 public key
/// with an uncompressed point: the form of the key of a transparency log.
pub fn is_p256_public_key(spki_der: &[u8]) -> bool {
    spki_der.len() == P256_SPKI_BYTES
        && spki_der
            .strip_prefix(&P256_SPKI_PREFIX)
            .is_some_and(|point| point.first() == Some(&0x04))
}

/// Reads the DER bytes of a PEM text of the kind `label` (`PUBLIC KEY`, `CERTIFICATE`): the
/// standard base64 between the line `-----BEGIN {label}-----` and the line
/// `-----END {label}-----`, without its white space.
pub fn pem_der(pem: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let inner = pem
        .trim()
        .strip_prefix(begin.as_str())?
        .strip_suffix(end.as_str())?;
    let base64: Vec<u8> = inner
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    STANDARD.decode(base64).ok()
}

/// Reads the DER bytes of a PEM `PUBLIC KEY`.
pub fn public_key_der(pem: &str) -> Option<Vec<u8>> {
    pem_der(pem, "PUBLIC KEY")
}

/// The identifier of a transparency log of the form Rekor v1: the lower-case hexadecimal
/// SHA-256 of the DER of its public key.
pub fn log_id(log_key_der: &[u8]) -> String {
    hex(&Sha256::digest(log_key_der))
}

/// A transparency log whose entries a node accepts: one row of the table of logs that is
/// compiled into the node program. The log has the form Rekor v1: its key is ECDSA P-256, and
/// its identifier is the SHA-256 of the DER of that key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparencyLog {
    /// The identifier of the log. Its first four bytes name the key of the log on a
    /// checkpoint.
    id: [u8; 32],
    /// The DER of the SubjectPublicKeyInfo of the key.
    spki: Vec<u8>,
}

impl TransparencyLog {
    /// A log of the form Rekor v1 with the key `spki_der`. `None` when the key is not the
    /// SubjectPublicKeyInfo of an ECDSA P-256 public key with an uncompressed point.
    pub fn rekor_v1(spki_der: &[u8]) -> Option<TransparencyLog> {
        is_p256_public_key(spki_der).then(|| TransparencyLog {
            id: Sha256::digest(spki_der).into(),
            spki: spki_der.to_vec(),
        })
    }

    /// The identifier of the log: 64 lower-case hexadecimal characters.
    pub fn id(&self) -> String {
        hex(&self.id)
    }

    /// True when `identifier` is the 32 bytes of the identifier of the log.
    pub fn has_id(&self, identifier: &[u8]) -> bool {
        self.id == identifier
    }

    /// True when `signature` (ASN.1 DER) is the ECDSA P-256 SHA-256 signature of the key of
    /// the log over `message`.
    fn signed(&self, message: &[u8], signature: &[u8]) -> bool {
        ecdsa_verifies(
            &self.spki,
            Some(Curve::P256),
            Hash::Sha256,
            message,
            signature,
        )
    }

    /// True when `timestamp` (ASN.1 DER) is the signed entry timestamp of the log for the
    /// entry with the body `body` (standard base64, exactly as the log returned it) that the
    /// log took at `integrated_time` (Unix epoch seconds) with the index `log_index`: the
    /// signature of the log key over the bytes of [`signed_entry`]. A body with a character
    /// outside the base64 alphabet has no signed entry timestamp.
    pub fn promised(
        &self,
        body: &str,
        integrated_time: u64,
        log_index: u64,
        timestamp: &[u8],
    ) -> bool {
        signed_entry(body, integrated_time, &self.id(), log_index)
            .is_some_and(|signed| self.signed(signed.as_bytes(), timestamp))
    }

    /// True when `checkpoint` is the note of the head of the tree of `size` leaves with the
    /// root hash `root` that the log signed (c2sp.org/tlog-checkpoint, c2sp.org/signed-note).
    ///
    /// The checkpoint holds an empty line. The part before the first empty line, with the
    /// line feed that ends it, is the note. Its first line is not empty (the origin of the
    /// log, which names the tree and is not compared), its second line is `size` in decimal
    /// and its third line the standard base64 of `root`. Its further lines are not read (the
    /// signature of the log covers them).
    ///
    /// A line after the empty line is a line of the log when it is `— ` (U+2014 and a
    /// space), a name, a space and the standard base64 of more than four bytes that begin
    /// with the first four bytes of the identifier of the log. There is at least one line of
    /// the log, and the bytes after the first four of every line of the log are an ECDSA
    /// signature of the log key over the note. Every other line (the signature of a witness,
    /// of another key) is not read.
    pub fn signed_tree_head(&self, checkpoint: &str, size: u64, root: &[u8; 32]) -> bool {
        let Some((text, signatures)) = checkpoint.split_once("\n\n") else {
            return false;
        };
        let mut lines = text.split('\n');
        let (Some(origin), Some(stated_size), Some(stated_root)) =
            (lines.next(), lines.next(), lines.next())
        else {
            return false;
        };
        if origin.is_empty()
            || stated_size != size.to_string()
            || STANDARD.decode(stated_root).ok().as_deref() != Some(root.as_slice())
        {
            return false;
        }
        let note = format!("{text}\n");
        let mut signed = false;
        for line in signatures.split('\n') {
            let of_key = line
                .strip_prefix("\u{2014} ")
                .and_then(|line| line.split_once(' '))
                .filter(|(name, _)| !name.is_empty())
                .and_then(|(_, signature)| STANDARD.decode(signature).ok());
            let Some(of_key) = of_key else {
                continue;
            };
            let Some((key_id, signature)) = of_key.split_first_chunk::<4>() else {
                continue;
            };
            if signature.is_empty() || !self.id.starts_with(key_id) {
                continue;
            }
            if !self.signed(note.as_bytes(), signature) {
                return false;
            }
            signed = true;
        }
        signed
    }
}

/// The bytes a log of the form Rekor v1 signed for an entry: the JSON object of `body`,
/// `integratedTime`, `logID` and `logIndex`, with its keys in this order and without white
/// space. `None` when `body` holds a character outside the base64 alphabet: such a character
/// could end the string of the body and state other values for the keys that follow it.
///
/// `log_id` is the identifier the node computed from the key of the log, not a text of the
/// entry.
fn signed_entry(body: &str, integrated_time: u64, log_id: &str, log_index: u64) -> Option<String> {
    let base64 = body
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='));
    base64.then(|| {
        format!(
            "{{\"body\":\"{body}\",\"integratedTime\":{integrated_time},\"logID\":\"{log_id}\",\"logIndex\":{log_index}}}"
        )
    })
}

/// The hash of the leaf of an entry in the Merkle tree of a log (RFC 6962 section 2.1): the
/// SHA-256 of the byte 0x00 and the decoded body of the entry.
pub fn leaf_hash(body: &[u8]) -> [u8; 32] {
    let mut hashed = Sha256::new();
    hashed.update([0x00]);
    hashed.update(body);
    hashed.finalize().into()
}

/// The hash of an inner node of a Merkle tree (RFC 6962 section 2.1): the SHA-256 of the byte
/// 0x01, the hash of the left child and the hash of the right child.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hashed = Sha256::new();
    hashed.update([0x01]);
    hashed.update(left);
    hashed.update(right);
    hashed.finalize().into()
}

/// The root of the tree of `size` leaves in which the leaf `index` has the hash `leaf`, by
/// the audit path `path` from that leaf upwards (RFC 6962 section 2.1.1, in the steps of RFC
/// 9162 section 2.1.3.2). `None` when the index is not below the size, and when the path is
/// shorter or longer than the way from that leaf to the root.
pub fn audit_root(leaf: [u8; 32], index: u64, size: u64, path: &[[u8; 32]]) -> Option<[u8; 32]> {
    if index >= size {
        return None;
    }
    let mut root = leaf;
    // The index of the node on the way up, and the index of the last node of its level.
    let (mut node, mut last) = (index, size - 1);
    for sibling in path {
        if last == 0 {
            return None;
        }
        if !node.is_multiple_of(2) || node == last {
            root = node_hash(sibling, &root);
            // A node that is the last of its level and a left child has no sibling on the
            // levels below the one where it becomes a right child.
            while node.is_multiple_of(2) && node != 0 {
                node >>= 1;
                last >>= 1;
            }
        } else {
            root = node_hash(&root, sibling);
        }
        node >>= 1;
        last >>= 1;
    }
    (last == 0).then_some(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    use serde_json::json;

    /// The public key of the transparency log Rekor of rekor.sigstore.dev, as the node program
    /// holds it.
    const REKOR_KEY_PEM: &str = include_str!("../../enclave/release/rekor-key.pem");
    /// The entry of that log with the index 150,000,000: `body`, `integrated_time`,
    /// `log_index`, `log_id` and `signed_entry_timestamp`.
    const REKOR_ENTRY: &str = include_str!("../tests/fixtures/rekor-entry-150000000.json");

    const PCRS: [&str; 3] = [
        "904d4e19f2cece358d8c0bcfdb278573decfcc739ce320c587c59d9ee73f5db594cd0c8e73539a087138e069223d8f47",
        "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
        "a1952bc63a9e80a3a46eda48bb60236dfcb030d50bf81f02b5c50d20d42a905d1db7c82d3f1d4c4d5649b20697889d44",
    ];
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    /// An ECDSA P-256 key of a test, in the place of the key of a log.
    struct TestKey {
        pair: EcdsaKeyPair,
        spki: Vec<u8>,
    }

    impl TestKey {
        fn new() -> TestKey {
            let random = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &random)
                    .unwrap();
            let mut spki = P256_SPKI_PREFIX.to_vec();
            spki.extend_from_slice(pair.public_key().as_ref());
            TestKey { pair, spki }
        }

        /// The ASN.1 DER signature of this key over `message`.
        fn sign(&self, message: &[u8]) -> Vec<u8> {
            self.pair
                .sign(&SystemRandom::new(), message)
                .unwrap()
                .as_ref()
                .to_vec()
        }

        /// The PEM of the public key, in lines of 64 characters.
        fn pem(&self) -> String {
            let base64 = STANDARD.encode(&self.spki);
            let lines: Vec<&str> = base64
                .as_bytes()
                .chunks(64)
                .map(|line| std::str::from_utf8(line).unwrap())
                .collect();
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                lines.join("\n")
            )
        }

        fn log(&self) -> TransparencyLog {
            TransparencyLog::rekor_v1(&self.spki).unwrap()
        }
    }

    /// The `measurements.json` of a release, with keys a reader does not read.
    fn statement_of(release: &str) -> serde_json::Value {
        json!({
            "release": release, "git_commit": COMMIT,
            "pcr0": PCRS[0], "pcr1": PCRS[1], "pcr2": PCRS[2],
            "inputs": {"file/Cargo.lock": "aa"},
        })
    }

    fn read(statement: &serde_json::Value) -> Option<ReleaseStatement> {
        read_statement(statement.to_string().as_bytes())
    }

    #[test]
    fn a_release_statement_states_a_release_its_commit_and_its_measurement() {
        let stated = read(&statement_of("v1.2.0")).unwrap();
        assert_eq!(stated.release, "v1.2.0");
        assert_eq!(stated.git_commit, COMMIT);
        assert_eq!(
            stated.pcrs.map(|pcr| hex(&pcr)),
            PCRS.map(|pcr| pcr.to_string())
        );
        assert_eq!(
            stated.measurement(),
            ReleaseMeasurement {
                release: "v1.2.0".to_string(),
                pcrs: stated.pcrs
            }
        );
        // The file as a build writes it: indented, with a line feed at its end.
        let written = serde_json::to_string_pretty(&statement_of("v1.2.0")).unwrap() + "\n";
        assert_eq!(read_statement(written.as_bytes()), Some(stated));
    }

    #[test]
    fn a_statement_with_a_missing_or_malformed_field_is_refused() {
        let with = |change: fn(&mut serde_json::Value)| {
            let mut statement = statement_of("v1.2.0");
            change(&mut statement);
            read(&statement)
        };
        assert!(with(|_| {}).is_some());

        let changes: [fn(&mut serde_json::Value); 22] = [
            |statement| {
                statement.as_object_mut().unwrap().shift_remove("release");
            },
            |statement| {
                statement
                    .as_object_mut()
                    .unwrap()
                    .shift_remove("git_commit");
            },
            |statement| {
                statement.as_object_mut().unwrap().shift_remove("pcr0");
            },
            |statement| {
                statement.as_object_mut().unwrap().shift_remove("pcr2");
            },
            |statement| statement["release"] = json!(1),
            |statement| statement["pcr1"] = json!(null),
            |statement| statement["git_commit"] = json!(7),
            // A commit of 39 and of 41 characters, in upper case, and the name of a branch.
            |statement| statement["git_commit"] = json!(COMMIT[1..]),
            |statement| statement["git_commit"] = json!(format!("{COMMIT}0")),
            |statement| statement["git_commit"] = json!(COMMIT.to_uppercase()),
            |statement| statement["git_commit"] = json!("main"),
            // 94 and 98 characters, an upper-case character, a character that is no digit.
            |statement| statement["pcr0"] = json!(PCRS[0][2..]),
            |statement| statement["pcr1"] = json!(format!("{}00", PCRS[1])),
            |statement| statement["pcr2"] = json!(PCRS[2].to_uppercase()),
            |statement| statement["pcr0"] = json!(PCRS[0].replacen('9', "g", 1)),
            |statement| statement["pcr1"] = json!([PCRS[1]]),
            // The measurement of a debug-mode enclave.
            |statement| statement["pcr0"] = json!("0".repeat(96)),
            |statement| statement["pcr1"] = json!("0".repeat(96)),
            |statement| statement["pcr2"] = json!("0".repeat(96)),
            // A release that is not the name of a release.
            |statement| statement["release"] = json!("dev"),
            |statement| statement["release"] = json!("v1.2.0 "),
            |statement| *statement = json!([statement.clone()]),
        ];
        for (index, change) in changes.into_iter().enumerate() {
            assert_eq!(with(change), None, "{index}");
        }
        // Not JSON, not an object, a text after the object, bytes that are not UTF-8 inside
        // a string no reader reads, and a byte order mark.
        let text = statement_of("v1.2.0").to_string();
        let not_utf8 = [&text.as_bytes()[..text.len() - 1], b",\"note\":\"\xff\"}"].concat();
        assert!(std::str::from_utf8(&not_utf8).is_err());
        for statement in [
            &b"not json"[..],
            b"\"text\"",
            b"",
            &[text.as_bytes(), b"x"].concat(),
            &not_utf8,
            &[b"\xef\xbb\xbf", text.as_bytes()].concat(),
        ] {
            assert_eq!(read_statement(statement), None);
        }
        // A key of the five that occurs twice: the statement states two values for it. An
        // escaped key is that key.
        for twice in [
            format!(r#"{{"pcr0":"{}",{}"#, PCRS[0], &text[1..]),
            format!(r#"{{"pcr\u0030":"{}",{}"#, PCRS[0], &text[1..]),
            format!(r#"{},"release":"v1.2.0"}}"#, &text[..text.len() - 1]),
            format!(r#"{},"git_commit":"{COMMIT}"}}"#, &text[..text.len() - 1]),
        ] {
            assert!(serde_json::from_str::<serde_json::Value>(&twice).is_ok());
            assert_eq!(read_statement(twice.as_bytes()), None, "{twice}");
        }
        // Another key that occurs twice is not read.
        let other_twice = format!(r#"{{"note":1,{},"note":2}}"#, &text[1..text.len() - 1]);
        assert!(read_statement(other_twice.as_bytes()).is_some());
    }

    #[test]
    fn a_statement_of_more_than_16384_bytes_or_of_more_than_32_levels_is_refused() {
        // White space after the object fills the statement to an exact length.
        let filled = |length: usize| {
            let mut statement = statement_of("v1.2.0").to_string().into_bytes();
            assert!(statement.len() < length);
            statement.resize(length, b' ');
            statement
        };
        assert_eq!(limits::RELEASE_STATEMENT_BYTES, 16_384);
        assert!(read_statement(&filled(16_384)).is_some());
        assert_eq!(read_statement(&filled(16_385)), None);

        // The object of the statement is the first level: a key no reader reads may hold 31
        // arrays inside one another, and not 32.
        let nested = |levels: usize| {
            let mut statement = statement_of("v1.2.0");
            statement["note"] = (0..levels).fold(json!(1), |inner, _| json!([inner]));
            read(&statement)
        };
        assert!(nested(31).is_some());
        assert_eq!(nested(32), None);
        assert!(is_sound_json(&json!(1)));
        assert!(is_sound_json(&json!({"a": [{"b": []}]})));
    }

    #[test]
    fn the_name_of_a_release_begins_with_v_and_holds_the_characters_of_a_tag() {
        for name in [
            "v1.2.3",
            "v2.4.0-rc.1",
            "v0",
            "vA_b-c.9",
            "v2026.11.24",
            "vv",
        ] {
            assert!(is_release_name(name), "{name}");
        }
        for name in [
            "", "v", "dev", "1.2.3", "V1.2.3", "v1.2.3 ", " v1.2.3", "v1.2.3\n", "v1.2.3+1",
            "v1/2", "v1@2", "v１.2.3", "vé",
        ] {
            assert!(!is_release_name(name), "{name:?}");
        }
    }

    #[test]
    fn a_list_of_old_releases_names_releases_and_their_measurements() {
        let element = |release: &str| json!({"release": release, "pcr0": PCRS[0], "pcr1": PCRS[1], "pcr2": PCRS[2]});
        let read = |list: serde_json::Value| read_predecessors(list.to_string().as_bytes());

        assert_eq!(read_predecessors(b"[]"), Some(Vec::new()));
        assert_eq!(read_predecessors(b" [ ]\n"), Some(Vec::new()));
        // The releases of the list, in its order. No release of the list is compared with
        // another one or with the release of the program that holds the list.
        let list = read(json!([
            element("v2.0.0"),
            element("v1.1.0-rc.1"),
            element("v9.0.0")
        ]))
        .unwrap();
        assert_eq!(
            list.iter()
                .map(|element| element.release.as_str())
                .collect::<Vec<_>>(),
            ["v2.0.0", "v1.1.0-rc.1", "v9.0.0"]
        );
        for predecessor in &list {
            assert_eq!(
                predecessor.pcrs.map(|pcr| hex(&pcr)),
                PCRS.map(|pcr| pcr.to_string())
            );
        }

        // Malformed elements and lists.
        let with = |change: fn(&mut serde_json::Value)| {
            let mut value = element("v1.0.0");
            change(&mut value);
            json!([value])
        };
        assert!(read(with(|_| {})).is_some());
        let changes: [fn(&mut serde_json::Value); 12] = [
            |element| element["release"] = json!("dev"),
            |element| element["release"] = json!("1.0.0"),
            |element| element["release"] = json!(1),
            |element| {
                element.as_object_mut().unwrap().shift_remove("release");
            },
            |element| {
                element.as_object_mut().unwrap().shift_remove("pcr1");
            },
            |element| element["pcr0"] = json!(PCRS[0][1..]),
            |element| element["pcr1"] = json!(PCRS[1].to_uppercase()),
            |element| element["pcr2"] = json!(format!("{}0", PCRS[2])),
            |element| element["pcr2"] = json!(7),
            // The measurement of a debug-mode enclave.
            |element| element["pcr0"] = json!("0".repeat(96)),
            |element| element["pcr2"] = json!("0".repeat(96)),
            |element| *element = json!([element["release"], PCRS[0], PCRS[1], PCRS[2]]),
        ];
        for (index, change) in changes.into_iter().enumerate() {
            assert_eq!(read(with(change)), None, "{index}");
        }
        // One such element refuses the whole list.
        assert_eq!(read(json!([element("v1.0.0"), element("dev")])), None);
        for list in [
            &b""[..],
            b"{}",
            b"null",
            b"[",
            b"[]x",
            b"[null]",
            b"[\"v1.0.0\"]",
            b"not json",
        ] {
            assert_eq!(read_predecessors(list), None);
        }
        // An element that names a key twice.
        let twice = format!(
            r#"[{{"release":"v1.0.0","release":"v1.0.1","pcr0":"{}","pcr1":"{}","pcr2":"{}"}}]"#,
            PCRS[0], PCRS[1], PCRS[2]
        );
        assert_eq!(read_predecessors(twice.as_bytes()), None);
    }

    #[test]
    fn the_signed_entry_timestamp_of_a_real_entry_of_the_log_verifies() {
        // The key of the log is the one whose identifier the log itself states.
        let log_key = public_key_der(REKOR_KEY_PEM).unwrap();
        assert!(is_p256_public_key(&log_key));
        assert_eq!(
            log_id(&log_key),
            "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
        );
        let log = TransparencyLog::rekor_v1(&log_key).unwrap();
        assert_eq!(log.id(), log_id(&log_key));
        assert!(log.has_id(&Sha256::digest(&log_key)));
        assert!(!log.has_id(&Sha256::digest(&log_key)[..31]));

        let entry: serde_json::Value = serde_json::from_str(REKOR_ENTRY).unwrap();
        let body = entry["body"].as_str().unwrap();
        let integrated_time = entry["integrated_time"].as_u64().unwrap();
        let log_index = entry["log_index"].as_u64().unwrap();
        assert_eq!(entry["log_id"], log.id());
        assert_eq!((integrated_time, log_index), (1_732_051_154, 150_000_000));
        let timestamp = STANDARD
            .decode(entry["signed_entry_timestamp"].as_str().unwrap())
            .unwrap();

        // The bytes the log signed.
        let signed = signed_entry(body, integrated_time, &log.id(), log_index).unwrap();
        assert!(signed.starts_with("{\"body\":\"eyJhcGlWZXJzaW9uIjoiMC4wLjEi"));
        assert!(signed.ends_with(
            "\",\"integratedTime\":1732051154,\"logID\":\"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d\",\"logIndex\":150000000}"
        ));
        assert!(log.promised(body, integrated_time, log_index, &timestamp));
        // Another time, another index, another body and another key do not verify.
        assert!(!log.promised(body, integrated_time + 1, log_index, &timestamp));
        assert!(!log.promised(body, integrated_time, log_index + 1, &timestamp));
        assert!(!log.promised(
            &format!("{body}AAAA"),
            integrated_time,
            log_index,
            &timestamp
        ));
        assert!(!TestKey::new()
            .log()
            .promised(body, integrated_time, log_index, &timestamp));
        // Bytes behind the signature.
        let longer = [&timestamp[..], &[0u8]].concat();
        assert!(!log.promised(body, integrated_time, log_index, &longer));
    }

    #[test]
    fn a_body_with_a_character_outside_the_base64_alphabet_has_no_signed_entry_timestamp() {
        // The log signs whatever bytes the entry gives: such a body is not put into the signed
        // bytes at all.
        let key = TestKey::new();
        let log = key.log();
        for character in ["\"", "\\", " ", "\n", "-", "_", ",", "}", "é"] {
            let body = format!("AAAA{character}");
            let signed = format!(
                "{{\"body\":\"{body}\",\"integratedTime\":1,\"logID\":\"{}\",\"logIndex\":2}}",
                log.id()
            );
            assert!(
                !log.promised(&body, 1, 2, &key.sign(signed.as_bytes())),
                "{character:?}"
            );
        }
        assert_eq!(signed_entry("ab\"cd", 1, "id", 2), None);
        assert_eq!(
            signed_entry("AZaz09+/=", 1, "id", 2).as_deref(),
            Some(r#"{"body":"AZaz09+/=","integratedTime":1,"logID":"id","logIndex":2}"#)
        );
        let signed = signed_entry("AAAA", 1, &log.id(), 2).unwrap();
        assert!(log.promised("AAAA", 1, 2, &key.sign(signed.as_bytes())));
    }

    #[test]
    fn a_public_key_and_a_certificate_are_read_from_their_pem() {
        let key = TestKey::new();
        assert_eq!(public_key_der(&key.pem()).as_deref(), Some(&key.spki[..]));
        // Without the last line break, with other line breaks and with white space around.
        let pem = key.pem();
        assert_eq!(
            public_key_der(pem.trim_end()).as_deref(),
            Some(&key.spki[..])
        );
        assert_eq!(
            public_key_der(&format!("\n {}\n", pem.replace('\n', "\r\n"))).as_deref(),
            Some(&key.spki[..])
        );
        for text in [
            "",
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----END PUBLIC KEY-----",
            &pem.replace("PUBLIC KEY", "EC PUBLIC KEY"),
            &pem.replace("-----END PUBLIC KEY-----", ""),
            &pem.replace(
                "-----BEGIN PUBLIC KEY-----",
                "-----BEGIN PUBLIC KEY-----\n!",
            ),
            &format!("x{pem}"),
            &format!("{pem}x"),
        ] {
            assert_eq!(public_key_der(text), None, "{text:?}");
        }
        // The PEM of another kind is read under the name of its kind only.
        let certificate = pem.replace("PUBLIC KEY", "CERTIFICATE");
        assert_eq!(
            pem_der(&certificate, "CERTIFICATE").as_deref(),
            Some(&key.spki[..])
        );
        assert_eq!(pem_der(&certificate, "PUBLIC KEY"), None);
        assert_eq!(pem_der(&pem, "CERTIFICATE"), None);
        // The base64 between the two lines has its padding and no bits of no byte.
        let begin = "-----BEGIN PUBLIC KEY-----";
        let end = "-----END PUBLIC KEY-----";
        assert_eq!(
            pem_der(&format!("{begin}AAAA{end}"), "PUBLIC KEY"),
            Some(vec![0, 0, 0])
        );
        assert_eq!(
            pem_der(&format!("{begin}{end}"), "PUBLIC KEY"),
            Some(Vec::new())
        );
        for inner in ["AAA", "AA=", "AB==", "AAAA=", "AA==AAAA"] {
            assert_eq!(
                pem_der(&format!("{begin}{inner}{end}"), "PUBLIC KEY"),
                None,
                "{inner}"
            );
        }

        // A key that is not the SubjectPublicKeyInfo of a P-256 key is the key of no log: one
        // byte less, one byte more, another curve identifier, a compressed point, the bare
        // point.
        assert!(is_p256_public_key(&key.spki));
        let mut other_curve = key.spki.clone();
        other_curve[22] = 0x06;
        let mut compressed = key.spki.clone();
        compressed[26] = 0x02;
        for spki in [
            &key.spki[..90],
            &[&key.spki[..], &[0u8]].concat(),
            &other_curve,
            &compressed,
            &key.spki[26..],
            &[],
        ] {
            assert!(!is_p256_public_key(spki));
            assert!(TransparencyLog::rekor_v1(spki).is_none());
        }
    }

    /// The Merkle tree hash of leaf hashes (RFC 6962 section 2.1), by its recursive
    /// definition.
    fn tree_hash(leaves: &[[u8; 32]]) -> [u8; 32] {
        match leaves {
            [leaf] => *leaf,
            _ => {
                // The largest power of two below the number of leaves.
                let split = leaves.len().next_power_of_two() / 2;
                node_hash(&tree_hash(&leaves[..split]), &tree_hash(&leaves[split..]))
            }
        }
    }

    /// The audit path of the leaf `index` (RFC 6962 section 2.1.1), by its recursive
    /// definition.
    fn audit_path(index: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
        if leaves.len() == 1 {
            return Vec::new();
        }
        let split = leaves.len().next_power_of_two() / 2;
        if index < split {
            let mut path = audit_path(index, &leaves[..split]);
            path.push(tree_hash(&leaves[split..]));
            path
        } else {
            let mut path = audit_path(index - split, &leaves[split..]);
            path.push(tree_hash(&leaves[..split]));
            path
        }
    }

    #[test]
    fn the_audit_path_of_every_leaf_of_a_tree_leads_to_its_root() {
        for size in 1..=70usize {
            let leaves: Vec<[u8; 32]> = (0..size)
                .map(|leaf| leaf_hash(format!("leaf {leaf}").as_bytes()))
                .collect();
            let root = tree_hash(&leaves);
            for index in 0..size {
                let path = audit_path(index, &leaves);
                let leaf = leaves[index];
                let (index, size) = (index as u64, size as u64);
                assert_eq!(
                    audit_root(leaf, index, size, &path),
                    Some(root),
                    "{index} of {size}"
                );
                // Another leaf, and a path without its last hash and with one hash more.
                assert_ne!(
                    audit_root([0x5a; 32], index, size, &path),
                    Some(root),
                    "{index} of {size}"
                );
                if let Some((_, shorter)) = path.split_last() {
                    assert_eq!(audit_root(leaf, index, size, shorter), None);
                }
                let longer = [&path[..], &[[0x11; 32]]].concat();
                assert_eq!(audit_root(leaf, index, size, &longer), None);
            }
            // An index that is not below the size.
            assert_eq!(audit_root(leaves[0], size as u64, size as u64, &[]), None);
        }
        assert_eq!(audit_root([1; 32], 0, 0, &[]), None);
        assert_eq!(audit_root([1; 32], 0, 1, &[]), Some([1; 32]));
        assert_eq!(audit_root([1; 32], u64::MAX, u64::MAX, &[]), None);
    }

    /// The checkpoint of a tree of `size` leaves with the root `root`, signed by `key` under
    /// the key ID of `named`.
    fn checkpoint_of(key: &TestKey, named: &TransparencyLog, size: u64, root: &[u8; 32]) -> String {
        let note = format!("log.test - 7\n{size}\n{}\n", STANDARD.encode(root));
        let signature = [&named.id[..4], &key.sign(note.as_bytes())].concat();
        format!("{note}\n\u{2014} log.test {}\n", STANDARD.encode(signature))
    }

    #[test]
    fn a_checkpoint_is_the_note_of_a_tree_head_that_the_log_signed() {
        let key = TestKey::new();
        let log = key.log();
        let root = [0x42u8; 32];
        let checkpoint = checkpoint_of(&key, &log, 11, &root);
        assert!(log.signed_tree_head(&checkpoint, 11, &root));
        // Another size and another root than the note states.
        assert!(!log.signed_tree_head(&checkpoint, 12, &root));
        assert!(!log.signed_tree_head(&checkpoint, 11, &[0x43; 32]));
        // The checkpoint of another key, also under the key ID of this log.
        let other = TestKey::new();
        assert!(!log.signed_tree_head(&checkpoint_of(&other, &other.log(), 11, &root), 11, &root));
        assert!(!log.signed_tree_head(&checkpoint_of(&other, &log, 11, &root), 11, &root));
        // A changed note under the signature of the log.
        assert!(!log.signed_tree_head(
            &checkpoint.replace("log.test - 7", "log.test - 8"),
            11,
            &root
        ));
        // No empty line, no line of the log, a note of two lines, a note without an origin, a
        // size with a leading zero.
        let (note, lines) = checkpoint.split_once("\n\n").unwrap();
        assert!(!log.signed_tree_head(&format!("{note}\n{lines}"), 11, &root));
        assert!(!log.signed_tree_head(&format!("{note}\n\n"), 11, &root));
        assert!(!log.signed_tree_head(&format!("log.test - 7\n11\n\n{lines}"), 11, &root));
        let signed_as = |note: &str| {
            let signature = [&log.id[..4], &key.sign(note.as_bytes())].concat();
            format!("{note}\n\u{2014} log.test {}\n", STANDARD.encode(signature))
        };
        let root_text = STANDARD.encode(root);
        assert!(log.signed_tree_head(&signed_as(&format!("o\n11\n{root_text}\n")), 11, &root));
        assert!(!log.signed_tree_head(&signed_as(&format!("\n11\n{root_text}\n")), 11, &root));
        assert!(!log.signed_tree_head(&signed_as(&format!("o\n011\n{root_text}\n")), 11, &root));
        assert!(!log.signed_tree_head(&signed_as(&format!("o\n11\n{root_text}=\n")), 11, &root));
        // A further line of the note is not read: the signature of the log covers it.
        assert!(log.signed_tree_head(
            &signed_as(&format!("o\n11\n{root_text}\n1795000100\n")),
            11,
            &root
        ));

        // The line of a witness and a line of another key under the name of the log are not
        // read. A second line of the key of the log that is no signature of it refuses the
        // checkpoint.
        let witness = checkpoint_of(&other, &other.log(), 11, &root);
        let (_, witness_line) = witness.split_once("\n\n").unwrap();
        assert!(log.signed_tree_head(&format!("{checkpoint}{witness_line}"), 11, &root));
        let forged = checkpoint_of(&other, &log, 11, &root);
        let (_, forged_line) = forged.split_once("\n\n").unwrap();
        assert!(!log.signed_tree_head(&format!("{checkpoint}{forged_line}"), 11, &root));
        assert!(!log.signed_tree_head(&format!("{note}\n\n{forged_line}{lines}"), 11, &root));
        // A line without a name, without the dash, with a signature that is no base64 and with
        // the four bytes of the key ID alone is no line of the log.
        let encoded = lines.trim_end().rsplit(' ').next().unwrap();
        for line in [
            format!("\u{2014}  {encoded}\n"),
            format!("- log.test {encoded}\n"),
            format!("\u{2014} log.test {encoded}!\n"),
            format!("\u{2014} log.test {}\n", STANDARD.encode(&log.id[..4])),
        ] {
            assert!(
                !log.signed_tree_head(&format!("{note}\n\n{line}"), 11, &root),
                "{line}"
            );
            assert!(
                log.signed_tree_head(&format!("{note}\n\n{line}{lines}"), 11, &root),
                "{line}"
            );
        }
    }
}
