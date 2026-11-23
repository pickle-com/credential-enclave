//! The delegation transfer to a later release (protocol.md 10.3): the release statement, the
//! entry of the public transparency log that records its signature, the order of releases and
//! the list of predecessors.
//!
//! A node hands delegations to a node of a later release when the release key of the operator
//! signed the measurements of that release and a public transparency log recorded that
//! signature. A node takes delegations from a node of a release that its own program lists as
//! a predecessor. What is decided here is whether an endorsement holds, how two releases are
//! ordered and what a list of predecessors states. Which peer a node then accepts is decided
//! where the attestation of that peer is verified (`enclave/src/attest.rs`).
//!
//! A log has one of two forms ([`LogForm`]), and an entry is verified in the form of its log.
//! A log of the form Rekor v1 answers an upload with a signed entry timestamp: its signature
//! over the entry and the time it took it. A log of the form Rekor v2 is a tiled log: it signs
//! no single entry, and what shows that it holds an entry is the audit path from the entry to
//! the root of a tree whose head it signed (a checkpoint).
//!
//! The release key and the logs are arguments: the node program passes the key and the table
//! of logs that are compiled into it. Nothing here sends a request to a log: the verdict
//! depends on the bytes of the call, on these compiled values and, for the time of an entry,
//! on the clock of the node.

use std::cmp::Ordering;
use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use serde::de::{Error as _, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};

use crate::limits;

/// Why the endorsement of a later release was not accepted. A node answers every one of them
/// with `peer_unverified`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EndorsementError {
    /// Check 1: the statement is longer than 16,384 bytes or does not state a release and
    /// three measurements.
    Statement,
    /// Check 2: the entry is of no log of the table of the node.
    LogId,
    /// Check 3, a log of the form Rekor v1: the entry carries no signed entry timestamp, or
    /// the signed entry timestamp is not the signature of the log over this entry.
    EntrySignature,
    /// Check 3, a log of the form Rekor v2: the checkpoint is not a note of a tree head of
    /// this log that the log signed.
    Checkpoint,
    /// Check 3, a log of the form Rekor v2: the entry carries no inclusion proof, or its audit
    /// path does not lead from this entry to the root of the checkpoint.
    InclusionProof,
    /// Check 4: the body of the entry is not a `hashedrekord` of the version of its log over a
    /// SHA-256 hash.
    EntryBody,
    /// Check 4: the hash of the entry is not the hash of the statement.
    StatementHash,
    /// Check 4: the public key of the entry is not the release key.
    ReleaseKey,
    /// Check 4: the signature of the entry is not the signature of the release key over the
    /// statement.
    ReleaseSignature,
    /// Check 5: the time of the entry lies too far after the clock of the node, or the notice
    /// period has not passed.
    EntryTime,
    /// Check 6: the release of the statement is not later than the release of the node, or
    /// one of the two is not a release tag.
    ReleaseOrder,
}

impl EndorsementError {
    /// The number of the check of protocol.md 10.3 that failed.
    pub fn check(&self) -> u8 {
        match self {
            EndorsementError::Statement => 1,
            EndorsementError::LogId => 2,
            EndorsementError::EntrySignature
            | EndorsementError::Checkpoint
            | EndorsementError::InclusionProof => 3,
            EndorsementError::EntryBody
            | EndorsementError::StatementHash
            | EndorsementError::ReleaseKey
            | EndorsementError::ReleaseSignature => 4,
            EndorsementError::EntryTime => 5,
            EndorsementError::ReleaseOrder => 6,
        }
    }
}

/// A release tag: `v{major}.{minor}.{patch}`, or `v{major}.{minor}.{patch}-rc.{n}` for a
/// release candidate. Every number is decimal without a leading zero (a lone `0` is a number)
/// and fits 32 bits.
///
/// Releases are ordered by (major, minor, patch). Of two releases with the same three numbers,
/// a release candidate is earlier than the release without `-rc.{n}`, and the candidate with
/// the smaller `n` is the earlier one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Release {
    major: u32,
    minor: u32,
    patch: u32,
    candidate: Option<u32>,
}

impl Release {
    /// Reads a release tag. `None` for every other text, for example `dev`.
    pub fn parse(tag: &str) -> Option<Release> {
        let numbers = tag.strip_prefix('v')?;
        let (numbers, candidate) = match numbers.split_once('-') {
            None => (numbers, None),
            Some((numbers, suffix)) => (numbers, Some(number(suffix.strip_prefix("rc.")?)?)),
        };
        let mut parts = numbers.split('.');
        let release = Release {
            major: number(parts.next()?)?,
            minor: number(parts.next()?)?,
            patch: number(parts.next()?)?,
            candidate,
        };
        match parts.next() {
            None => Some(release),
            Some(_) => None,
        }
    }

    /// The position of the release in the order: a release without a candidate number comes
    /// after every candidate of the same three numbers.
    fn position(&self) -> (u32, u32, u32, bool, u32) {
        (
            self.major,
            self.minor,
            self.patch,
            self.candidate.is_none(),
            self.candidate.unwrap_or(0),
        )
    }
}

impl Ord for Release {
    fn cmp(&self, other: &Release) -> Ordering {
        self.position().cmp(&other.position())
    }
}

impl PartialOrd for Release {
    fn partial_cmp(&self, other: &Release) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A decimal number of a release tag: digits only, no leading zero, at most `u32::MAX`.
fn number(text: &str) -> Option<u32> {
    let digits = text.as_bytes();
    let plain = !digits.is_empty()
        && digits.iter().all(u8::is_ascii_digit)
        && (digits.len() == 1 || digits.first() != Some(&b'0'));
    if !plain {
        return None;
    }
    text.parse().ok()
}

/// A release and the measurement of its enclave image: what a release statement states, and
/// one element of a list of predecessors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseMeasurement {
    /// The release tag.
    pub release: String,
    /// PCR0, PCR1 and PCR2 of the enclave image of that release.
    pub pcrs: [[u8; 48]; 3],
}

/// The four values of a JSON object that names a release and its measurement, as text:
/// `release`, `pcr0`, `pcr1`, `pcr2`.
struct MeasurementFields([String; 4]);

const MEASUREMENT_KEYS: [&str; 4] = ["release", "pcr0", "pcr1", "pcr2"];

impl<'de> Deserialize<'de> for MeasurementFields {
    /// Reads a JSON object in which each of the four keys occurs once and holds a string.
    /// Other keys are passed over. A value that is not an object, a key of the four that
    /// occurs twice and a value of the four that is not a string are refused: the object states
    /// one release and one measurement.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields;

        impl<'de> Visitor<'de> for Fields {
            type Value = MeasurementFields;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object with release, pcr0, pcr1 and pcr2")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values: [Option<String>; 4] = [None, None, None, None];
                while let Some(key) = map.next_key::<String>()? {
                    // The value of one of the four keys, with the name of that key.
                    let named = MEASUREMENT_KEYS
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
                let mut fields: [String; 4] = Default::default();
                for ((field, value), name) in fields.iter_mut().zip(values).zip(MEASUREMENT_KEYS) {
                    *field = value.ok_or_else(|| A::Error::missing_field(name))?;
                }
                Ok(MeasurementFields(fields))
            }
        }

        deserializer.deserialize_map(Fields)
    }
}

impl MeasurementFields {
    /// The release and the measurement the object states, when each PCR is 96 lower-case
    /// hexadecimal characters.
    fn read(self) -> Option<ReleaseMeasurement> {
        let [release, pcr0, pcr1, pcr2] = self.0;
        Some(ReleaseMeasurement {
            release,
            pcrs: [pcr(&pcr0)?, pcr(&pcr1)?, pcr(&pcr2)?],
        })
    }
}

/// Reads a PCR: 96 lower-case hexadecimal characters.
fn pcr(text: &str) -> Option<[u8; 48]> {
    hex_bytes(text)
}

/// Reads `N` bytes from twice as many lower-case hexadecimal characters.
fn hex_bytes<const N: usize>(text: &str) -> Option<[u8; N]> {
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Reads a release statement (protocol.md 10.3): the bytes of the file `measurements.json` of
/// a release. They are at most 16,384 bytes and a JSON object whose `release` is a string and
/// whose `pcr0`, `pcr1` and `pcr2` are 96 lower-case hexadecimal characters each. The other
/// keys of the object are not read. A statement in which one of the four keys occurs twice is
/// refused.
pub fn read_statement(statement: &[u8]) -> Option<ReleaseMeasurement> {
    if statement.len() > limits::RELEASE_STATEMENT_BYTES {
        return None;
    }
    serde_json::from_slice::<MeasurementFields>(statement)
        .ok()?
        .read()
}

/// Reads a list of predecessors for a program of the release `own_release` (protocol.md 10.3):
/// a JSON array of `{"release":"...","pcr0":"<96 hex>","pcr1":"<96 hex>","pcr2":"<96 hex>"}`.
///
/// `None` when the list does not have that form, when the release of an element is not a
/// release tag or is not earlier than `own_release`, and when a PCR of an element is all zero
/// (the measurement of a debug-mode enclave). A program whose own release is not a release tag
/// (for example `dev`) has no predecessor: every list but the empty one is `None` for it.
pub fn read_predecessors(list: &[u8], own_release: &str) -> Option<Vec<ReleaseMeasurement>> {
    let elements: Vec<MeasurementFields> = serde_json::from_slice(list).ok()?;
    let own = Release::parse(own_release);
    elements
        .into_iter()
        .map(|fields| {
            let element = fields.read()?;
            let earlier = Release::parse(&element.release)? < own?;
            let measured = element.pcrs.iter().all(|pcr| pcr != &[0u8; 48]);
            (earlier && measured).then_some(element)
        })
        .collect()
}

/// The first 26 bytes of the SubjectPublicKeyInfo (DER) of an ECDSA P-256 public key: the
/// algorithm `id-ecPublicKey` with the curve `prime256v1` and the header of the bit string.
/// The 65 bytes of the uncompressed point follow them.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The length of the SubjectPublicKeyInfo (DER) of an ECDSA P-256 public key.
const P256_SPKI_BYTES: usize = 91;

const PEM_BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
const PEM_END: &str = "-----END PUBLIC KEY-----";

/// The uncompressed point of an ECDSA P-256 public key given as the DER of its
/// SubjectPublicKeyInfo: 91 bytes that start with the fixed 26 bytes of that form. Every other
/// input is `None`.
fn p256_point(spki_der: &[u8]) -> Option<&[u8]> {
    if spki_der.len() != P256_SPKI_BYTES {
        return None;
    }
    spki_der
        .strip_prefix(&P256_SPKI_PREFIX)
        .filter(|point| point.first() == Some(&0x04))
}

/// True when `spki_der` is the DER of the SubjectPublicKeyInfo of an ECDSA P-256 public key
/// with an uncompressed point: the only form of a key that [`verify_endorsement`] verifies a
/// signature with.
pub fn is_p256_public_key(spki_der: &[u8]) -> bool {
    p256_point(spki_der).is_some()
}

/// True when `signature_der` is an ASN.1 DER ECDSA P-256 SHA-256 signature of the key
/// `spki_der` over `message`.
fn p256_verifies(spki_der: &[u8], message: &[u8], signature_der: &[u8]) -> bool {
    p256_point(spki_der).is_some_and(|point| {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
            .verify(message, signature_der)
            .is_ok()
    })
}

/// Reads the DER bytes of a PEM `PUBLIC KEY`: the standard base64 between the line
/// `-----BEGIN PUBLIC KEY-----` and the line `-----END PUBLIC KEY-----`, without its white
/// space.
pub fn public_key_der(pem: &str) -> Option<Vec<u8>> {
    let inner = pem.trim().strip_prefix(PEM_BEGIN)?.strip_suffix(PEM_END)?;
    let base64: Vec<u8> = inner
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    STANDARD.decode(base64).ok()
}

/// The identifier of a transparency log of the form Rekor v1: the lower-case hexadecimal
/// SHA-256 of the DER of its public key.
pub fn log_id(log_key_der: &[u8]) -> String {
    hex(&Sha256::digest(log_key_der))
}

/// The first 12 bytes of the SubjectPublicKeyInfo (DER) of an Ed25519 public key: the
/// algorithm `id-Ed25519` and the header of the bit string. The 32 bytes of the key follow
/// them.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The form of a transparency log: what the log returns with an entry, the form of the body of
/// an entry, the kind of its key and what its identifier is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LogForm {
    /// Rekor v1 (`rekor.sigstore.dev`). The log returns an entry with the time at which it
    /// took the entry and with a signed entry timestamp. The body of an entry is a
    /// `hashedrekord` of version 0.0.1. The key of the log is ECDSA P-256, and its identifier
    /// is the SHA-256 of the DER of that key.
    RekorV1,
    /// Rekor v2, a tiled log (`log2025-1.rekor.sigstore.dev`). The log returns an entry with
    /// its inclusion proof: the audit path of the entry and a checkpoint. It states no time
    /// and signs no single entry. The body of an entry is a `hashedrekord` of version 0.0.2.
    /// The key of the log is Ed25519, and its identifier is the key ID of its signature on a
    /// checkpoint (c2sp.org/signed-note) before it is cut to four bytes: the SHA-256 of the
    /// origin of the log, a line feed, the byte 0x01 and the 32 bytes of the key.
    RekorV2,
}

/// A transparency log whose entries a node accepts: one row of the table of logs that is
/// compiled into the node program.
#[derive(Clone, Debug)]
pub struct TransparencyLog {
    /// The identifier of the log. For a log of the form Rekor v2 its first four bytes are the
    /// key ID of the signature of the log on a checkpoint.
    id: [u8; 32],
    key: LogKey,
}

/// The key of a log, with what else the form of the log needs to verify an entry.
#[derive(Clone, Debug)]
enum LogKey {
    /// The form Rekor v1: the DER of the SubjectPublicKeyInfo of the ECDSA P-256 key.
    RekorV1 { spki: Vec<u8> },
    /// The form Rekor v2: the origin of the log, the first line of its checkpoints and the
    /// name of its key on them, and the Ed25519 key.
    RekorV2 { origin: String, key: VerifyingKey },
}

impl TransparencyLog {
    /// A log of the form Rekor v1 with the key `spki_der`. `None` when the key is not the
    /// SubjectPublicKeyInfo of an ECDSA P-256 public key with an uncompressed point.
    pub fn rekor_v1(spki_der: &[u8]) -> Option<TransparencyLog> {
        is_p256_public_key(spki_der).then(|| TransparencyLog {
            id: Sha256::digest(spki_der).into(),
            key: LogKey::RekorV1 {
                spki: spki_der.to_vec(),
            },
        })
    }

    /// A log of the form Rekor v2 that names itself `origin` in its checkpoints and signs them
    /// with the key `spki_der`. `None` when the key is not the SubjectPublicKeyInfo of an
    /// Ed25519 public key or is a key of small order, and when `origin` is empty or holds a
    /// character outside `!` to `~` or a `+` (it is the name of a key of a signed note).
    pub fn rekor_v2(origin: &str, spki_der: &[u8]) -> Option<TransparencyLog> {
        let key: &[u8; 32] = spki_der
            .strip_prefix(&ED25519_SPKI_PREFIX)?
            .try_into()
            .ok()?;
        let key = VerifyingKey::from_bytes(key)
            .ok()
            .filter(|key| !key.is_weak())?;
        let named = !origin.is_empty()
            && origin
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'+');
        named.then(|| {
            let mut hashed = Sha256::new();
            hashed.update(origin.as_bytes());
            hashed.update([0x0a, 0x01]);
            hashed.update(key.as_bytes());
            TransparencyLog {
                id: hashed.finalize().into(),
                key: LogKey::RekorV2 {
                    origin: origin.to_string(),
                    key,
                },
            }
        })
    }

    /// The identifier of the log: 64 lower-case hexadecimal characters. An entry names its log
    /// by this text (`log_id`).
    pub fn id(&self) -> String {
        hex(&self.id)
    }

    /// The form of the log.
    pub fn form(&self) -> LogForm {
        match self.key {
            LogKey::RekorV1 { .. } => LogForm::RekorV1,
            LogKey::RekorV2 { .. } => LogForm::RekorV2,
        }
    }

    /// The origin of a log of the form Rekor v2. A log of the form Rekor v1 has none.
    pub fn origin(&self) -> Option<&str> {
        match &self.key {
            LogKey::RekorV1 { .. } => None,
            LogKey::RekorV2 { origin, .. } => Some(origin),
        }
    }
}

/// What an endorsement is verified with.
#[derive(Clone, Copy, Debug)]
pub struct ReleaseKeys<'a> {
    /// The release key of the operator: the DER of its SubjectPublicKeyInfo (ECDSA P-256).
    pub release: &'a [u8],
    /// The table of transparency logs of the node. An entry of one of them records the
    /// signature of the release key.
    pub logs: &'a [TransparencyLog],
}

/// What a log of the form Rekor v1 returns with an entry: its promise that it took the entry.
#[derive(Clone, Copy, Debug)]
pub struct InclusionPromise<'a> {
    /// The time at which the log took the entry, in Unix epoch seconds.
    pub integrated_time: u64,
    /// The index of the entry in the log.
    pub log_index: u64,
    /// The signed entry timestamp: the signature of the log over the entry, in standard
    /// base64.
    pub signed_entry_timestamp: &'a str,
}

/// What a log of the form Rekor v2 returns with an entry: the proof that it holds the entry.
#[derive(Clone, Debug)]
pub struct InclusionProof<'a> {
    /// The index of the entry among the leaves of the log.
    pub log_index: u64,
    /// The hashes of the audit path, from the leaf upwards: 64 lower-case hexadecimal
    /// characters each.
    pub hashes: Vec<&'a str>,
    /// The checkpoint: the signed note of a tree head of the log, exactly as the log returned
    /// it.
    pub checkpoint: &'a str,
}

/// An entry of a transparency log, as an endorsement carries it.
#[derive(Clone, Debug)]
pub struct LogEntry<'a> {
    /// The identifier of the log: 64 lower-case hexadecimal characters.
    pub log_id: &'a str,
    /// The body of the entry, in standard base64, exactly as the log returned it.
    pub body: &'a str,
    /// The promise of a log of the form Rekor v1.
    pub promise: Option<InclusionPromise<'a>>,
    /// The proof of a log of the form Rekor v2.
    pub proof: Option<InclusionProof<'a>>,
}

impl<'a> LogEntry<'a> {
    /// Reads the `entry` of an endorsement (protocol.md 10.3). `None` when `log_id` or `body`
    /// is not a string.
    ///
    /// The promise is read when `integrated_time` and `log_index` are unsigned integers and
    /// `signed_entry_timestamp` is a string. The proof is read when `inclusion_proof` is an
    /// object whose `log_index` is an unsigned integer, whose `checkpoint` is a string and
    /// whose `hashes` is an array of at most 64 strings. A part of another form is absent, and
    /// [`verify_endorsement`] refuses an entry without the part its log returns. The other
    /// keys of the entry and of its proof are not read.
    pub fn read(entry: &'a serde_json::Value) -> Option<LogEntry<'a>> {
        let text = |value: &'a serde_json::Value, key: &str| value.get(key)?.as_str();
        let number = |value: &'a serde_json::Value, key: &str| value.get(key)?.as_u64();
        let promise = || {
            Some(InclusionPromise {
                integrated_time: number(entry, "integrated_time")?,
                log_index: number(entry, "log_index")?,
                signed_entry_timestamp: text(entry, "signed_entry_timestamp")?,
            })
        };
        let proof = || {
            let proof = entry.get("inclusion_proof")?;
            let hashes = proof.get("hashes")?.as_array()?;
            if hashes.len() > limits::RELEASE_PROOF_HASHES {
                return None;
            }
            Some(InclusionProof {
                log_index: number(proof, "log_index")?,
                hashes: hashes
                    .iter()
                    .map(serde_json::Value::as_str)
                    .collect::<Option<_>>()?,
                checkpoint: text(proof, "checkpoint")?,
            })
        };
        Some(LogEntry {
            log_id: text(entry, "log_id")?,
            body: text(entry, "body")?,
            promise: promise(),
            proof: proof(),
        })
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

/// Check 3 of [`verify_endorsement`] for a log of the form Rekor v1 with the key `spki` and
/// the identifier `log_id`: `body` holds only characters of the base64 alphabet, and the
/// signed entry timestamp of `promise` is a signature of the log over the entry.
fn verify_promise(
    spki: &[u8],
    log_id: &str,
    body: &str,
    promise: &InclusionPromise<'_>,
) -> Result<(), EndorsementError> {
    let signed = signed_entry(body, promise.integrated_time, log_id, promise.log_index)
        .ok_or(EndorsementError::EntrySignature)?;
    let timestamp = STANDARD
        .decode(promise.signed_entry_timestamp)
        .map_err(|_| EndorsementError::EntrySignature)?;
    if !p256_verifies(spki, signed.as_bytes(), &timestamp) {
        return Err(EndorsementError::EntrySignature);
    }
    Ok(())
}

/// The head of a tree, as a checkpoint states it.
struct TreeHead {
    /// The number of leaves of the tree.
    size: u64,
    /// The root hash of the tree.
    root: [u8; 32],
}

/// A non-negative integer in decimal without a leading zero (a lone `0` is a number) that
/// fits 64 bits.
fn decimal(text: &str) -> Option<u64> {
    let digits = text.as_bytes();
    let plain = !digits.is_empty()
        && digits.iter().all(u8::is_ascii_digit)
        && (digits.len() == 1 || digits.first() != Some(&b'0'));
    if !plain {
        return None;
    }
    text.parse().ok()
}

/// Check 3 of [`verify_endorsement`] for a log of the form Rekor v2, first part: the tree head
/// that `checkpoint` states, when the checkpoint is a note of a tree head of the log with the
/// origin `origin` that the key `key` of that log signed (c2sp.org/tlog-checkpoint,
/// c2sp.org/signed-note). `key_id` is the first four bytes of the identifier of the log.
///
/// The checkpoint is at most 262,144 bytes and holds an empty line. The part before the first
/// empty line, with the line feed that ends it, is the note. Its first line is `origin`, its
/// second line the size of the tree in decimal and its third line the standard base64 of the
/// 32 bytes of the root hash. Its further lines are not read (the signature of the log covers
/// them).
///
/// A line after the empty line is a line of the log when it is `— ` (U+2014 and a space),
/// `origin`, a space and the standard base64 of bytes that begin with `key_id`. There is at
/// least one line of the log, and the bytes after the first four of every line of the log are
/// an Ed25519 signature of `key` over the note. Every other line (the signature of a witness,
/// of another key under the name of the log) is not read.
fn signed_tree_head(
    origin: &str,
    key: &VerifyingKey,
    key_id: [u8; 4],
    checkpoint: &str,
) -> Option<TreeHead> {
    if checkpoint.len() > limits::RELEASE_CHECKPOINT_BYTES {
        return None;
    }
    let (text, signatures) = checkpoint.split_once("\n\n")?;
    let mut lines = text.split('\n');
    if lines.next()? != origin {
        return None;
    }
    let size = decimal(lines.next()?)?;
    let root: [u8; 32] = STANDARD.decode(lines.next()?).ok()?.try_into().ok()?;
    let note = format!("{text}\n");
    let mut signed = false;
    for line in signatures.split('\n') {
        let of_log = line
            .strip_prefix("\u{2014} ")
            .and_then(|line| line.strip_prefix(origin))
            .and_then(|line| line.strip_prefix(' '))
            .and_then(|signature| STANDARD.decode(signature).ok());
        let Some(of_log) = of_log else {
            continue;
        };
        let Some((line_key_id, signature)) = of_log.split_first_chunk::<4>() else {
            continue;
        };
        if *line_key_id != key_id {
            continue;
        }
        let signature = Signature::from_slice(signature).ok()?;
        key.verify_strict(note.as_bytes(), &signature).ok()?;
        signed = true;
    }
    signed.then_some(TreeHead { size, root })
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

/// Check 3 of [`verify_endorsement`] for a log of the form Rekor v2, second part: the root of
/// the tree of `size` leaves in which the leaf `index` is the entry with the body `body`, by
/// the audit path `hashes` (RFC 6962 section 2.1.1, in the steps of RFC 9162 section 2.1.3.2).
/// `None` when the index is not below the size, when a hash is not 64 lower-case hexadecimal
/// characters, and when the path is shorter or longer than the way from that leaf to the root.
///
/// The leaf of an entry is the SHA-256 of the byte 0x00 and the body.
fn audit_root(body: &[u8], index: u64, size: u64, hashes: &[&str]) -> Option<[u8; 32]> {
    if index >= size {
        return None;
    }
    let mut hashed = Sha256::new();
    hashed.update([0x00]);
    hashed.update(body);
    let mut root: [u8; 32] = hashed.finalize().into();
    // The index of the node on the way up, and the index of the last node of its level.
    let (mut node, mut last) = (index, size - 1);
    for sibling in hashes {
        let sibling = hex_bytes::<32>(sibling)?;
        if last == 0 {
            return None;
        }
        if !node.is_multiple_of(2) || node == last {
            root = node_hash(&sibling, &root);
            // A node that is the last of its level and a left child has no sibling on the
            // levels below the one where it becomes a right child.
            while node.is_multiple_of(2) && node != 0 {
                node >>= 1;
                last >>= 1;
            }
        } else {
            root = node_hash(&root, &sibling);
        }
        node >>= 1;
        last >>= 1;
    }
    (last == 0).then_some(root)
}

/// Check 4 of [`verify_endorsement`] for a log of the form Rekor v1: the body of the entry is
/// a `hashedrekord` of version 0.0.1 that holds the SHA-256 of `statement`, the release key
/// and a signature of that key over `statement`.
fn verify_body_rekor_v1(
    body: &str,
    statement: &[u8],
    release_key_der: &[u8],
) -> Result<(), EndorsementError> {
    let body = STANDARD
        .decode(body)
        .map_err(|_| EndorsementError::EntryBody)?;
    let body: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| EndorsementError::EntryBody)?;
    let text = |path: &[&str]| {
        path.iter()
            .try_fold(&body, |value, key| value.get(key))
            .and_then(serde_json::Value::as_str)
    };
    if text(&["apiVersion"]) != Some("0.0.1")
        || text(&["kind"]) != Some("hashedrekord")
        || text(&["spec", "data", "hash", "algorithm"]) != Some("sha256")
    {
        return Err(EndorsementError::EntryBody);
    }
    if text(&["spec", "data", "hash", "value"]) != Some(hex(&Sha256::digest(statement)).as_str()) {
        return Err(EndorsementError::StatementHash);
    }
    let key = text(&["spec", "signature", "publicKey", "content"])
        .and_then(|content| STANDARD.decode(content).ok())
        .and_then(|pem| public_key_der(std::str::from_utf8(&pem).ok()?));
    if key.as_deref() != Some(release_key_der) {
        return Err(EndorsementError::ReleaseKey);
    }
    let signature = text(&["spec", "signature", "content"])
        .and_then(|content| STANDARD.decode(content).ok())
        .ok_or(EndorsementError::ReleaseSignature)?;
    if !p256_verifies(release_key_der, statement, &signature) {
        return Err(EndorsementError::ReleaseSignature);
    }
    Ok(())
}

/// The body of an entry of a log of the form Rekor v2, as far as a node reads it: a JSON
/// object with `apiVersion`, `kind` and, under `spec.hashedRekordV002`, the hashed data and
/// its signature. A key a node reads that occurs twice is refused, like a key of the release
/// statement. The other keys of the object are not read.
#[derive(Deserialize)]
struct TiledBody {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    spec: TiledSpec,
}

#[derive(Deserialize)]
struct TiledSpec {
    #[serde(rename = "hashedRekordV002")]
    record: TiledRecord,
}

#[derive(Deserialize)]
struct TiledRecord {
    data: TiledData,
    signature: TiledSignature,
}

#[derive(Deserialize)]
struct TiledData {
    algorithm: String,
    digest: String,
}

#[derive(Deserialize)]
struct TiledSignature {
    content: String,
    verifier: TiledVerifier,
}

/// What verifies the signature of an entry: a public key, for the entry of a key its holder
/// keeps. An entry under a certificate (`x509Certificate`) names no public key.
#[derive(Deserialize)]
struct TiledVerifier {
    #[serde(rename = "keyDetails")]
    key_details: String,
    #[serde(rename = "publicKey", default)]
    public_key: Option<TiledKey>,
}

#[derive(Deserialize)]
struct TiledKey {
    #[serde(rename = "rawBytes")]
    raw_bytes: String,
}

/// Check 4 of [`verify_endorsement`] for a log of the form Rekor v2: `body`, the decoded body
/// of the entry, is a `hashedrekord` of version 0.0.2 that holds the SHA-256 of `statement`,
/// the release key as an ECDSA P-256 key and a signature of that key over `statement`.
fn verify_body_rekor_v2(
    body: &[u8],
    statement: &[u8],
    release_key_der: &[u8],
) -> Result<(), EndorsementError> {
    let body: TiledBody = serde_json::from_slice(body).map_err(|_| EndorsementError::EntryBody)?;
    let record = body.spec.record;
    if body.api_version != "0.0.2"
        || body.kind != "hashedrekord"
        || record.data.algorithm != "SHA2_256"
    {
        return Err(EndorsementError::EntryBody);
    }
    let digest = STANDARD.decode(record.data.digest).ok();
    if digest.as_deref() != Some(Sha256::digest(statement).as_slice()) {
        return Err(EndorsementError::StatementHash);
    }
    let verifier = record.signature.verifier;
    let key = verifier
        .public_key
        .filter(|_| verifier.key_details == "PKIX_ECDSA_P256_SHA_256")
        .and_then(|key| STANDARD.decode(key.raw_bytes).ok());
    if key.as_deref() != Some(release_key_der) {
        return Err(EndorsementError::ReleaseKey);
    }
    let signature = STANDARD
        .decode(record.signature.content)
        .map_err(|_| EndorsementError::ReleaseSignature)?;
    if !p256_verifies(release_key_der, statement, &signature) {
        return Err(EndorsementError::ReleaseSignature);
    }
    Ok(())
}

/// Check 5 of [`verify_endorsement`] for an entry that states its time: the entry counts when
/// its time lies at most 300 seconds after the clock of the node and, with a notice period,
/// when the entry is at least as old as that period by the clock of the node. The 300 seconds
/// allow for a clock of the node that is behind the clock of the log. They do not shorten a
/// notice period.
///
/// Both comparisons are made on differences, so no sum leaves the range of the type.
fn entry_time_counts(integrated_time: u64, now_s: u64, notice_s: u64) -> bool {
    let not_ahead = integrated_time.saturating_sub(now_s) <= limits::RELEASE_ENTRY_AHEAD_SECONDS;
    let old_enough = notice_s == 0
        || now_s
            .checked_sub(integrated_time)
            .is_some_and(|age| age >= notice_s);
    not_ahead && old_enough
}

/// Verifies the endorsement of a later release for a node of the release `own_release` whose
/// clock shows `now_s` (Unix epoch seconds), and returns the release and the measurement the
/// statement states (protocol.md 10.3, checks 1 to 6 of the giving node).
///
/// | Check | Rule | Failure |
/// | --- | --- | --- |
/// | 1 | `statement` is a release statement by [`read_statement`] | `Statement` |
/// | 2 | `log_id` of the entry is the identifier of a log of `keys` | `LogId` |
/// | 3, Rekor v1 | the entry has a promise, `body` holds only characters of the base64 alphabet, and the signed entry timestamp is a signature of the log key over the entry | `EntrySignature` |
/// | 3, Rekor v2 | the entry has a proof. Its checkpoint is a note of a tree head of the log that the log key signed. `body` decodes, and the audit path leads from the leaf of the decoded body to the root of the checkpoint, in a tree of the size of the checkpoint | `InclusionProof`, `Checkpoint` |
/// | 4 | `body` decodes to the record of `statement` under the release key, in the form of the log: a `hashedrekord` of version 0.0.1 (Rekor v1) or 0.0.2 (Rekor v2) with the SHA-256 of `statement`, with the release key, and with a signature of the release key over `statement` | `EntryBody`, `StatementHash`, `ReleaseKey`, `ReleaseSignature` |
/// | 5 | for a log of the form Rekor v1, the time of the entry lies at most 300 seconds after `now_s`, and the notice period has passed. An entry of a log of the form Rekor v2 states no time: it counts while the notice period is 0 | `EntryTime` |
/// | 6 | the release of the statement is later than `own_release` | `ReleaseOrder` |
///
/// The signatures of the release key and of a log of the form Rekor v1 are ECDSA P-256 with
/// SHA-256 in ASN.1 DER. The signature of a log of the form Rekor v2 is Ed25519. A release key
/// that is not the SubjectPublicKeyInfo of an ECDSA P-256 public key verifies nothing.
///
/// Check 7, the attestation of the node that receives the delegations, is the caller's: the
/// measurement of that node is the measurement this function returns, and its binding names
/// the release this function returns.
pub fn verify_endorsement(
    statement: &[u8],
    entry: &LogEntry<'_>,
    keys: &ReleaseKeys<'_>,
    own_release: &str,
    now_s: u64,
) -> Result<ReleaseMeasurement, EndorsementError> {
    // 1
    let later = read_statement(statement).ok_or(EndorsementError::Statement)?;
    // 2
    let log = keys
        .logs
        .iter()
        .find(|log| log.id() == entry.log_id)
        .ok_or(EndorsementError::LogId)?;
    // 3 and 4, in the form of the log. `time` is the time the log states for the entry.
    let time = match &log.key {
        LogKey::RekorV1 { spki } => {
            let promise = entry
                .promise
                .as_ref()
                .ok_or(EndorsementError::EntrySignature)?;
            verify_promise(spki, &log.id(), entry.body, promise)?;
            verify_body_rekor_v1(entry.body, statement, keys.release)?;
            Some(promise.integrated_time)
        }
        LogKey::RekorV2 { origin, key } => {
            let proof = entry
                .proof
                .as_ref()
                .ok_or(EndorsementError::InclusionProof)?;
            let [k0, k1, k2, k3, ..] = log.id;
            let head = signed_tree_head(origin, key, [k0, k1, k2, k3], proof.checkpoint)
                .ok_or(EndorsementError::Checkpoint)?;
            let body = STANDARD
                .decode(entry.body)
                .map_err(|_| EndorsementError::InclusionProof)?;
            if audit_root(&body, proof.log_index, head.size, &proof.hashes) != Some(head.root) {
                return Err(EndorsementError::InclusionProof);
            }
            verify_body_rekor_v2(&body, statement, keys.release)?;
            None
        }
    };
    // 5
    let counts = match time {
        Some(integrated_time) => {
            entry_time_counts(integrated_time, now_s, limits::RELEASE_NOTICE_SECONDS)
        }
        None => limits::RELEASE_NOTICE_SECONDS == 0,
    };
    if !counts {
        return Err(EndorsementError::EntryTime);
    }
    // 6
    let own = Release::parse(own_release).ok_or(EndorsementError::ReleaseOrder)?;
    let stated = Release::parse(&later.release).ok_or(EndorsementError::ReleaseOrder)?;
    if stated <= own {
        return Err(EndorsementError::ReleaseOrder);
    }
    Ok(later)
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
    /// The entry of that log with the index 150,000,000, in the form of the `entry` of an
    /// endorsement.
    const REKOR_ENTRY: &str = include_str!("../tests/fixtures/rekor-entry-150000000.json");

    const NOW_S: u64 = 1_790_000_000;
    const PCRS: [&str; 3] = [
        "904d4e19f2cece358d8c0bcfdb278573decfcc739ce320c587c59d9ee73f5db594cd0c8e73539a087138e069223d8f47",
        "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
        "a1952bc63a9e80a3a46eda48bb60236dfcb030d50bf81f02b5c50d20d42a905d1db7c82d3f1d4c4d5649b20697889d44",
    ];

    /// An ECDSA P-256 key of a test, in the place of the release key or of the log key.
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

        /// The standard base64 of the ASN.1 DER signature of this key over `message`.
        fn sign(&self, message: &[u8]) -> String {
            let signature = self.pair.sign(&SystemRandom::new(), message).unwrap();
            STANDARD.encode(signature.as_ref())
        }

        /// The PEM of the public key, in lines of 64 characters.
        fn pem(&self) -> String {
            let base64 = STANDARD.encode(&self.spki);
            let lines: Vec<&str> = base64
                .as_bytes()
                .chunks(64)
                .map(|line| std::str::from_utf8(line).unwrap())
                .collect();
            format!("{PEM_BEGIN}\n{}\n{PEM_END}\n", lines.join("\n"))
        }
    }

    /// The `measurements.json` of a release, with keys a node does not read.
    fn statement_of(release: &str) -> Vec<u8> {
        format!(
            "{{\n  \"release\": \"{release}\",\n  \"git_commit\": \"0123abc\",\n  \"pcr0\": \"{}\",\n  \"pcr1\": \"{}\",\n  \"pcr2\": \"{}\",\n  \"inputs\": {{\"Cargo.lock\": \"aa\"}}\n}}\n",
            PCRS[0], PCRS[1], PCRS[2]
        )
        .into_bytes()
    }

    /// The body of a `hashedrekord` entry in standard base64: the hash of `hashed`, the PEM
    /// `key_pem` and the signature `signature`.
    fn body_of(hashed: &[u8], key_pem: &str, signature: &str) -> String {
        STANDARD.encode(
            json!({
                "apiVersion": "0.0.1",
                "kind": "hashedrekord",
                "spec": {
                    "data": {"hash": {"algorithm": "sha256", "value": hex(&Sha256::digest(hashed))}},
                    "signature": {
                        "content": signature,
                        "publicKey": {"content": STANDARD.encode(key_pem)},
                    },
                },
            })
            .to_string(),
        )
    }

    /// An endorsement as a call carries it, and the keys it verifies with.
    struct Endorsement {
        release_key: TestKey,
        log_key: TestKey,
        statement: Vec<u8>,
        body: String,
        integrated_time: u64,
        log_index: u64,
        log_id: String,
        signed_entry_timestamp: String,
    }

    impl Endorsement {
        /// A valid endorsement of the release `release`: the release key signed the
        /// statement, and the log took the entry an hour before `NOW_S`.
        fn of(release: &str) -> Endorsement {
            let release_key = TestKey::new();
            let statement = statement_of(release);
            let body = body_of(
                &statement,
                &release_key.pem(),
                &release_key.sign(&statement),
            );
            let mut endorsement = Endorsement {
                release_key,
                log_key: TestKey::new(),
                statement,
                body,
                integrated_time: NOW_S - 3_600,
                log_index: 150_000_001,
                log_id: String::new(),
                signed_entry_timestamp: String::new(),
            };
            endorsement.log_id = log_id(&endorsement.log_key.spki);
            endorsement.log_signs();
            endorsement
        }

        /// The log signs the entry as it stands.
        fn log_signs(&mut self) {
            let signed = format!(
                "{{\"body\":\"{}\",\"integratedTime\":{},\"logID\":\"{}\",\"logIndex\":{}}}",
                self.body, self.integrated_time, self.log_id, self.log_index
            );
            self.signed_entry_timestamp = self.log_key.sign(signed.as_bytes());
        }

        /// The entry as a call carries it.
        fn entry(&self) -> LogEntry<'_> {
            LogEntry {
                log_id: &self.log_id,
                body: &self.body,
                promise: Some(InclusionPromise {
                    integrated_time: self.integrated_time,
                    log_index: self.log_index,
                    signed_entry_timestamp: &self.signed_entry_timestamp,
                }),
                proof: None,
            }
        }

        /// The table of logs of the node: the one log of this endorsement.
        fn logs(&self) -> Vec<TransparencyLog> {
            vec![TransparencyLog::rekor_v1(&self.log_key.spki).unwrap()]
        }

        fn verify(
            &self,
            own_release: &str,
            now_s: u64,
        ) -> Result<ReleaseMeasurement, EndorsementError> {
            verify_endorsement(
                &self.statement,
                &self.entry(),
                &ReleaseKeys {
                    release: &self.release_key.spki,
                    logs: &self.logs(),
                },
                own_release,
                now_s,
            )
        }

        fn result(&self) -> Result<ReleaseMeasurement, EndorsementError> {
            self.verify("v1.1.0", NOW_S)
        }
    }

    #[test]
    fn a_release_statement_that_the_release_key_signed_and_the_log_recorded_is_accepted() {
        let endorsement = Endorsement::of("v1.2.0");
        let later = endorsement.result().unwrap();
        assert_eq!(later.release, "v1.2.0");
        assert_eq!(hex(&later.pcrs[0]), PCRS[0]);
        assert_eq!(hex(&later.pcrs[1]), PCRS[1]);
        assert_eq!(hex(&later.pcrs[2]), PCRS[2]);
    }

    #[test]
    fn an_entry_of_another_log_is_refused() {
        // The identifier of another log, with everything else in place.
        let mut endorsement = Endorsement::of("v1.2.0");
        endorsement.log_id = log_id(&TestKey::new().spki);
        assert_eq!(endorsement.result(), Err(EndorsementError::LogId));
        // An upper-case identifier is not the identifier.
        let mut endorsement = Endorsement::of("v1.2.0");
        endorsement.log_id = endorsement.log_id.to_uppercase();
        assert_eq!(endorsement.result(), Err(EndorsementError::LogId));

        // The entry of another log under the identifier of this one: that log signed it, with
        // the identifier of this log in the signed bytes.
        let mut endorsement = Endorsement::of("v1.2.0");
        let other = TestKey::new();
        let own = std::mem::replace(&mut endorsement.log_key, other);
        endorsement.log_signs();
        endorsement.log_key = own;
        assert_eq!(endorsement.result(), Err(EndorsementError::EntrySignature));
    }

    #[test]
    fn a_signed_entry_timestamp_over_another_entry_is_refused() {
        let refused = |change: fn(&mut Endorsement)| {
            let mut endorsement = Endorsement::of("v1.2.0");
            change(&mut endorsement);
            endorsement.result()
        };
        // Another integrated time and another index than the log signed.
        assert_eq!(
            refused(|endorsement| endorsement.integrated_time += 1),
            Err(EndorsementError::EntrySignature)
        );
        assert_eq!(
            refused(|endorsement| endorsement.log_index += 1),
            Err(EndorsementError::EntrySignature)
        );
        // Another body than the log signed: a valid body for the same statement, made with
        // the same release key.
        assert_eq!(
            refused(|endorsement| {
                endorsement.body = body_of(
                    &endorsement.statement,
                    &endorsement.release_key.pem(),
                    &endorsement.release_key.sign(&endorsement.statement),
                );
            }),
            Err(EndorsementError::EntrySignature)
        );
        // A timestamp that is not base64, not a signature, and the signature of another key.
        assert_eq!(
            refused(|endorsement| endorsement.signed_entry_timestamp = "not base64!".to_string()),
            Err(EndorsementError::EntrySignature)
        );
        assert_eq!(
            refused(|endorsement| endorsement.signed_entry_timestamp = STANDARD.encode([0u8; 70])),
            Err(EndorsementError::EntrySignature)
        );
        assert_eq!(
            refused(|endorsement| {
                let signed = signed_entry(
                    &endorsement.body,
                    endorsement.integrated_time,
                    &endorsement.log_id,
                    endorsement.log_index,
                )
                .unwrap();
                endorsement.signed_entry_timestamp =
                    endorsement.release_key.sign(signed.as_bytes());
            }),
            Err(EndorsementError::EntrySignature)
        );
    }

    #[test]
    fn a_body_with_a_character_outside_the_base64_alphabet_is_refused() {
        // The log signs whatever bytes the entry gives: the node does not put such a body into
        // the signed bytes at all.
        for character in ["\"", "\\", " ", "\n", "-", "_", ",", "}", "é"] {
            let mut endorsement = Endorsement::of("v1.2.0");
            endorsement.body.push_str(character);
            endorsement.log_signs();
            assert_eq!(
                endorsement.result(),
                Err(EndorsementError::EntrySignature),
                "{character:?}"
            );
        }
        assert_eq!(signed_entry("ab\"cd", 1, "id", 2), None);
        assert_eq!(
            signed_entry("AZaz09+/=", 1, "id", 2).as_deref(),
            Some(r#"{"body":"AZaz09+/=","integratedTime":1,"logID":"id","logIndex":2}"#)
        );

        // A body that states other values after its own end verifies under no reading: the
        // log would have signed the same bytes for the entry with these other values.
        let mut endorsement = Endorsement::of("v1.2.0");
        let body = endorsement.body.clone();
        endorsement.body = format!("{body}\",\"integratedTime\":1,\"x\":\"");
        endorsement.log_signs();
        assert_eq!(endorsement.result(), Err(EndorsementError::EntrySignature));
    }

    #[test]
    fn a_body_that_is_not_the_record_of_this_statement_under_the_release_key_is_refused() {
        // Each body is in an entry the log signed: only the body decides.
        let refused = |body: fn(&Endorsement) -> String| {
            let mut endorsement = Endorsement::of("v1.2.0");
            endorsement.body = body(&endorsement);
            endorsement.log_signs();
            endorsement.result()
        };
        let changed = |endorsement: &Endorsement, change: fn(&mut serde_json::Value)| {
            let mut body: serde_json::Value =
                serde_json::from_slice(&STANDARD.decode(&endorsement.body).unwrap()).unwrap();
            change(&mut body);
            STANDARD.encode(body.to_string())
        };

        // The hash of another statement, signed by the release key.
        assert_eq!(
            refused(|endorsement| {
                let other = statement_of("v1.3.0");
                body_of(
                    &other,
                    &endorsement.release_key.pem(),
                    &endorsement.release_key.sign(&other),
                )
            }),
            Err(EndorsementError::StatementHash)
        );
        // Another public key, with the signature of that key over the statement.
        assert_eq!(
            refused(|endorsement| {
                let other = TestKey::new();
                body_of(
                    &endorsement.statement,
                    &other.pem(),
                    &other.sign(&endorsement.statement),
                )
            }),
            Err(EndorsementError::ReleaseKey)
        );
        // The release key as the public key, with the signature of another key.
        assert_eq!(
            refused(|endorsement| {
                body_of(
                    &endorsement.statement,
                    &endorsement.release_key.pem(),
                    &TestKey::new().sign(&endorsement.statement),
                )
            }),
            Err(EndorsementError::ReleaseSignature)
        );
        // The signature of the release key over other bytes, and no signature.
        assert_eq!(
            refused(|endorsement| {
                body_of(
                    &endorsement.statement,
                    &endorsement.release_key.pem(),
                    &endorsement.release_key.sign(b"other bytes"),
                )
            }),
            Err(EndorsementError::ReleaseSignature)
        );
        assert_eq!(
            refused(|endorsement| body_of(
                &endorsement.statement,
                &endorsement.release_key.pem(),
                "not base64!"
            )),
            Err(EndorsementError::ReleaseSignature)
        );
        // A public key that is not a PEM, and one that is the DER without the PEM lines.
        assert_eq!(
            refused(|endorsement| body_of(
                &endorsement.statement,
                "not a key",
                &endorsement.release_key.sign(&endorsement.statement)
            )),
            Err(EndorsementError::ReleaseKey)
        );
        assert_eq!(
            refused(|endorsement| body_of(
                &endorsement.statement,
                &STANDARD.encode(&endorsement.release_key.spki),
                &endorsement.release_key.sign(&endorsement.statement)
            )),
            Err(EndorsementError::ReleaseKey)
        );

        // Another kind, version or hash algorithm, a missing part, and a body that is not a
        // JSON object or not base64.
        type Change = fn(&mut serde_json::Value);
        let forms: [(Change, EndorsementError); 7] = [
            (
                |body| body["kind"] = json!("rekord"),
                EndorsementError::EntryBody,
            ),
            (
                |body| body["apiVersion"] = json!("0.0.2"),
                EndorsementError::EntryBody,
            ),
            (
                |body| body["spec"]["data"]["hash"]["algorithm"] = json!("sha512"),
                EndorsementError::EntryBody,
            ),
            (
                |body| body["spec"]["data"]["hash"]["value"] = json!(7),
                EndorsementError::StatementHash,
            ),
            (
                |body| {
                    let value = body["spec"]["data"]["hash"]["value"]
                        .as_str()
                        .unwrap()
                        .to_uppercase();
                    body["spec"]["data"]["hash"]["value"] = json!(value);
                },
                EndorsementError::StatementHash,
            ),
            (
                |body| {
                    body["spec"]["signature"]
                        .as_object_mut()
                        .unwrap()
                        .remove("publicKey");
                },
                EndorsementError::ReleaseKey,
            ),
            (
                |body| {
                    body["spec"]["signature"]
                        .as_object_mut()
                        .unwrap()
                        .remove("content");
                },
                EndorsementError::ReleaseSignature,
            ),
        ];
        for (index, (change, failure)) in forms.into_iter().enumerate() {
            let mut endorsement = Endorsement::of("v1.2.0");
            endorsement.body = changed(&endorsement, change);
            endorsement.log_signs();
            assert_eq!(endorsement.result(), Err(failure), "{index}");
        }
        for body in [
            STANDARD.encode("[]"),
            STANDARD.encode("text"),
            String::new(),
            "AAA".to_string(),
        ] {
            let mut endorsement = Endorsement::of("v1.2.0");
            endorsement.body = body.clone();
            endorsement.log_signs();
            assert_eq!(
                endorsement.result(),
                Err(EndorsementError::EntryBody),
                "{body}"
            );
        }
    }

    /// An endorsement of the statement `statement`, signed and recorded like a valid one.
    fn endorsement_of_statement(statement: Vec<u8>) -> Endorsement {
        let mut endorsement = Endorsement::of("v1.2.0");
        endorsement.body = body_of(
            &statement,
            &endorsement.release_key.pem(),
            &endorsement.release_key.sign(&statement),
        );
        endorsement.statement = statement;
        endorsement.log_signs();
        endorsement
    }

    #[test]
    fn a_statement_with_a_missing_or_malformed_field_is_refused() {
        let with = |change: fn(&mut serde_json::Value)| {
            let mut statement: serde_json::Value =
                serde_json::from_slice(&statement_of("v1.2.0")).unwrap();
            change(&mut statement);
            statement.to_string().into_bytes()
        };
        assert!(endorsement_of_statement(with(|_| {})).result().is_ok());

        let changes: [fn(&mut serde_json::Value); 11] = [
            |statement| {
                statement.as_object_mut().unwrap().remove("release");
            },
            |statement| {
                statement.as_object_mut().unwrap().remove("pcr0");
            },
            |statement| {
                statement.as_object_mut().unwrap().remove("pcr2");
            },
            |statement| statement["release"] = json!(1),
            |statement| statement["pcr1"] = json!(null),
            // 94 and 98 characters, an upper-case character, a character that is no digit.
            |statement| statement["pcr0"] = json!(PCRS[0][2..]),
            |statement| statement["pcr1"] = json!(format!("{}00", PCRS[1])),
            |statement| statement["pcr2"] = json!(PCRS[2].to_uppercase()),
            |statement| statement["pcr0"] = json!(PCRS[0].replacen('9', "g", 1)),
            |statement| statement["pcr1"] = json!([PCRS[1]]),
            |statement| *statement = json!([statement.clone()]),
        ];
        for (index, change) in changes.into_iter().enumerate() {
            assert_eq!(
                endorsement_of_statement(with(change)).result(),
                Err(EndorsementError::Statement),
                "{index}"
            );
        }
        // Not JSON, not an object, and a text after the object.
        for statement in [
            &b"not json"[..],
            b"\"text\"",
            b"",
            &[statement_of("v1.2.0"), b"x".to_vec()].concat(),
        ] {
            assert_eq!(
                endorsement_of_statement(statement.to_vec()).result(),
                Err(EndorsementError::Statement)
            );
        }
        // The four values in an array, in the order of the keys.
        let array = format!(r#"["v1.2.0","{}","{}","{}"]"#, PCRS[0], PCRS[1], PCRS[2]);
        assert_eq!(
            endorsement_of_statement(array.into_bytes()).result(),
            Err(EndorsementError::Statement)
        );
        // A key of the four that occurs twice: the statement states two values for it.
        let twice = format!(
            r#"{{"release":"v1.2.0","pcr0":"{}","pcr1":"{}","pcr2":"{}","pcr0":"{}"}}"#,
            PCRS[0], PCRS[1], PCRS[2], PCRS[0]
        );
        assert_eq!(
            endorsement_of_statement(twice.into_bytes()).result(),
            Err(EndorsementError::Statement)
        );
        // Another key that occurs twice is not read.
        let other_twice = format!(
            r#"{{"release":"v1.2.0","note":1,"pcr0":"{}","pcr1":"{}","pcr2":"{}","note":2}}"#,
            PCRS[0], PCRS[1], PCRS[2]
        );
        assert!(endorsement_of_statement(other_twice.into_bytes())
            .result()
            .is_ok());
    }

    #[test]
    fn a_statement_of_more_than_16384_bytes_is_refused() {
        // White space after the object fills the statement to an exact length.
        let filled = |length: usize| {
            let mut statement = statement_of("v1.2.0");
            assert!(statement.len() < length);
            statement.resize(length, b' ');
            statement
        };
        assert_eq!(limits::RELEASE_STATEMENT_BYTES, 16_384);
        assert!(endorsement_of_statement(filled(16_384)).result().is_ok());
        assert_eq!(
            endorsement_of_statement(filled(16_385)).result(),
            Err(EndorsementError::Statement)
        );
    }

    #[test]
    fn an_entry_whose_time_lies_more_than_300_seconds_ahead_is_refused() {
        let at = |integrated_time: u64| {
            let mut endorsement = Endorsement::of("v1.2.0");
            endorsement.integrated_time = integrated_time;
            endorsement.log_signs();
            endorsement.result()
        };
        assert!(at(0).is_ok());
        assert!(at(NOW_S).is_ok());
        assert!(at(NOW_S + 300).is_ok());
        assert_eq!(at(NOW_S + 301), Err(EndorsementError::EntryTime));
        assert_eq!(at(u64::MAX), Err(EndorsementError::EntryTime));

        // The notice period of this release is zero: an entry counts from the moment the log
        // took it.
        assert_eq!(limits::RELEASE_NOTICE_SECONDS, 0);
        assert_eq!(limits::RELEASE_ENTRY_AHEAD_SECONDS, 300);
        assert!(entry_time_counts(1_300, 1_000, 0));
        assert!(!entry_time_counts(1_301, 1_000, 0));
        // With a notice period, the entry is that old by the clock of the node. The 300
        // seconds do not shorten the period.
        assert!(entry_time_counts(1_000, 1_600, 600));
        assert!(!entry_time_counts(1_001, 1_600, 600));
        assert!(!entry_time_counts(1_300, 1_600, 600));
        assert!(!entry_time_counts(1_600, 1_600, 1));
        assert!(entry_time_counts(1_599, 1_600, 1));
        // The largest values of the type compare like every other value.
        assert!(!entry_time_counts(u64::MAX, 1_600, 600));
        assert!(entry_time_counts(u64::MAX, u64::MAX, 0));
        assert!(!entry_time_counts(u64::MAX, u64::MAX, 1));
        assert!(entry_time_counts(u64::MAX, u64::MAX - 300, 0));
        assert!(!entry_time_counts(u64::MAX, u64::MAX - 301, 0));
        assert!(entry_time_counts(u64::MAX - 600, u64::MAX, 600));
        assert!(!entry_time_counts(u64::MAX - 599, u64::MAX, 600));
    }

    #[test]
    fn a_release_that_is_not_later_than_the_own_release_is_refused() {
        // (own release, release of the statement, accepted)
        let cases = [
            ("v1.1.0", "v1.1.1", true),
            ("v1.1.0", "v1.2.0", true),
            ("v1.1.0", "v2.0.0", true),
            ("v1.1.0", "v1.10.0", true),
            ("v1.9.0", "v1.10.0", true),
            ("v1.1.0-rc.1", "v1.1.0-rc.2", true),
            ("v1.1.0-rc.9", "v1.1.0-rc.10", true),
            ("v1.1.0-rc.2", "v1.1.0", true),
            ("v1.1.0", "v1.1.1-rc.1", true),
            ("v1.1.0", "v1.1.0", false),
            ("v1.1.0", "v1.0.9", false),
            ("v1.1.0", "v1.0.0", false),
            ("v1.1.0", "v0.9.9", false),
            ("v1.1.0", "v1.1.0-rc.1", false),
            ("v1.1.0-rc.2", "v1.1.0-rc.2", false),
            ("v1.1.0-rc.2", "v1.1.0-rc.1", false),
            ("v1.1.0-rc.1", "v1.0.0", false),
            ("v2.0.0-rc.1", "v1.9.9", false),
            // An own release that is not a release tag accepts no endorsement.
            ("dev", "v1.2.0", false),
            ("", "v1.2.0", false),
            ("v0.0.0-test", "v1.2.0", false),
            ("1.1.0", "v1.2.0", false),
            // A statement whose release is not a release tag.
            ("v1.1.0", "dev", false),
            ("v1.1.0", "v1.2", false),
            ("v1.1.0", "v1.2.0-beta.1", false),
            ("v1.1.0", "v01.2.0", false),
        ];
        let mut endorsements = std::collections::HashMap::new();
        for (own, stated, accepted) in cases {
            let endorsement = endorsements
                .entry(stated)
                .or_insert_with(|| Endorsement::of(stated));
            let result = endorsement.verify(own, NOW_S);
            if accepted {
                assert_eq!(result.unwrap().release, stated, "{own} {stated}");
            } else {
                assert_eq!(
                    result,
                    Err(EndorsementError::ReleaseOrder),
                    "{own} {stated}"
                );
            }
        }
    }

    #[test]
    fn a_release_tag_has_three_numbers_and_at_most_a_candidate_number() {
        let release = |major, minor, patch, candidate| Release {
            major,
            minor,
            patch,
            candidate,
        };
        assert_eq!(Release::parse("v1.2.3"), Some(release(1, 2, 3, None)));
        assert_eq!(Release::parse("v0.0.0"), Some(release(0, 0, 0, None)));
        assert_eq!(
            Release::parse("v10.20.30-rc.40"),
            Some(release(10, 20, 30, Some(40)))
        );
        assert_eq!(
            Release::parse("v1.1.0-rc.0"),
            Some(release(1, 1, 0, Some(0)))
        );
        assert_eq!(
            Release::parse("v4294967295.0.0"),
            Some(release(u32::MAX, 0, 0, None))
        );
        for tag in [
            "",
            "v",
            "dev",
            "1.2.3",
            "V1.2.3",
            "v1",
            "v1.2",
            "v1.2.3.4",
            "v1.2.",
            "v1..3",
            "v.2.3",
            "v01.2.3",
            "v1.02.3",
            "v1.2.03",
            "v1.2.3-rc.01",
            "v1.2.3-rc.",
            "v1.2.3-rc",
            "v1.2.3-",
            "v1.2.3-rc.1.2",
            "v1.2.3-rc.1-rc.2",
            "v1.2.3-RC.1",
            "v1.2.3-beta.1",
            "v1.2.3+1",
            "v+1.2.3",
            "v1.2.-3",
            "v1.2.3 ",
            " v1.2.3",
            "v1.2.3\n",
            "v4294967296.0.0",
            "v1.2.3-rc.4294967296",
            "v１.2.3",
            "v0.0.0-test",
            "v0.0.0-diag.local",
        ] {
            assert_eq!(Release::parse(tag), None, "{tag:?}");
        }

        // The order: the three numbers as numbers, then a candidate before the release, then
        // the candidate number.
        let order = [
            "v0.0.0",
            "v0.0.1",
            "v0.1.0",
            "v1.0.0-rc.0",
            "v1.0.0-rc.1",
            "v1.0.0-rc.2",
            "v1.0.0-rc.10",
            "v1.0.0",
            "v1.0.1-rc.1",
            "v1.0.1",
            "v1.0.2",
            "v1.0.10",
            "v1.1.0",
            "v1.2.0",
            "v1.10.0",
            "v2.0.0-rc.1",
            "v2.0.0",
            "v10.0.0",
        ];
        for (index, earlier) in order.iter().enumerate() {
            let earlier = Release::parse(earlier).unwrap();
            assert_eq!(earlier.cmp(&earlier), Ordering::Equal);
            for later in &order[index + 1..] {
                let later = Release::parse(later).unwrap();
                assert!(earlier < later, "{earlier:?} {later:?}");
                assert!(later > earlier, "{earlier:?} {later:?}");
            }
        }
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

        let entry: serde_json::Value = serde_json::from_str(REKOR_ENTRY).unwrap();
        let body = entry["body"].as_str().unwrap();
        let integrated_time = entry["integrated_time"].as_u64().unwrap();
        let log_index = entry["log_index"].as_u64().unwrap();
        assert_eq!(entry["log_id"], log_id(&log_key));
        assert_eq!((integrated_time, log_index), (1_732_051_154, 150_000_000));
        let timestamp = STANDARD
            .decode(entry["signed_entry_timestamp"].as_str().unwrap())
            .unwrap();

        // The bytes the log signed: this is the form check 3 builds.
        let signed = signed_entry(body, integrated_time, &log_id(&log_key), log_index).unwrap();
        assert!(signed.starts_with("{\"body\":\"eyJhcGlWZXJzaW9uIjoiMC4wLjEi"));
        assert!(signed.ends_with(
            "\",\"integratedTime\":1732051154,\"logID\":\"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d\",\"logIndex\":150000000}"
        ));
        assert!(p256_verifies(&log_key, signed.as_bytes(), &timestamp));
        // Another time, another index and another key do not verify.
        for other in [
            signed_entry(body, integrated_time + 1, &log_id(&log_key), log_index).unwrap(),
            signed_entry(body, integrated_time, &log_id(&log_key), log_index + 1).unwrap(),
        ] {
            assert!(!p256_verifies(&log_key, other.as_bytes(), &timestamp));
        }
        assert!(!p256_verifies(
            &TestKey::new().spki,
            signed.as_bytes(),
            &timestamp
        ));

        // The entry is a `hashedrekord` of another signer. As the endorsement of a statement
        // it passes checks 2 and 3 and fails check 4: its hash is not the hash of the
        // statement.
        let statement = statement_of("v1.2.0");
        let result = verify_endorsement(
            &statement,
            &LogEntry::read(&entry).unwrap(),
            &ReleaseKeys {
                release: &TestKey::new().spki,
                logs: &[TransparencyLog::rekor_v1(&log_key).unwrap()],
            },
            "v1.1.0",
            NOW_S,
        );
        assert_eq!(result, Err(EndorsementError::StatementHash));
    }

    #[test]
    fn a_public_key_is_read_from_its_pem_and_used_as_a_p256_key_only() {
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

        // A key that is not the SubjectPublicKeyInfo of a P-256 key verifies nothing: one
        // byte less, one byte more, another curve identifier, a compressed point, the bare
        // point.
        let message = b"message";
        let signature = STANDARD.decode(key.sign(message)).unwrap();
        assert!(is_p256_public_key(&key.spki));
        assert!(p256_verifies(&key.spki, message, &signature));
        assert!(!p256_verifies(&key.spki, b"another message", &signature));
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
            assert!(!p256_verifies(spki, message, &signature));
        }
        // A point that is not on the curve has the form of a key and verifies nothing.
        let mut off_curve = key.spki.clone();
        off_curve[90] ^= 1;
        assert!(is_p256_public_key(&off_curve));
        assert!(!p256_verifies(&off_curve, message, &signature));

        // An endorsement under a log key or a release key of another form is refused.
        let mut endorsement = Endorsement::of("v1.2.0");
        endorsement.release_key.spki.push(0);
        assert_eq!(endorsement.result(), Err(EndorsementError::ReleaseKey));
        // Also when the entry names the same bytes as its public key: the signature of the
        // private key verifies under no key of that form.
        endorsement.body = body_of(
            &endorsement.statement,
            &endorsement.release_key.pem(),
            &endorsement.release_key.sign(&endorsement.statement),
        );
        endorsement.log_signs();
        assert_eq!(
            endorsement.result(),
            Err(EndorsementError::ReleaseSignature)
        );
        // A key of another form is the key of no log of the form Rekor v1: a table cannot hold
        // it.
        for spki in [
            &key.spki[..90],
            &other_curve,
            &compressed,
            &key.spki[26..],
            &[],
        ] {
            assert!(TransparencyLog::rekor_v1(spki).is_none());
        }
        assert!(TransparencyLog::rekor_v1(&key.spki).is_some());
    }

    #[test]
    fn a_list_of_predecessors_names_earlier_releases_and_their_measurements() {
        let element = |release: &str| json!({"release": release, "pcr0": PCRS[0], "pcr1": PCRS[1], "pcr2": PCRS[2]});
        let read = |list: serde_json::Value, own: &str| {
            read_predecessors(list.to_string().as_bytes(), own)
        };

        // The empty list, for every release.
        for own in ["v1.1.0", "dev", ""] {
            assert_eq!(read_predecessors(b"[]", own), Some(Vec::new()));
            assert_eq!(read_predecessors(b" [ ]\n", own), Some(Vec::new()));
        }
        // Earlier releases, in the order of the list.
        let list = read(json!([element("v1.0.0"), element("v1.1.0-rc.1")]), "v1.1.0").unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].release, "v1.0.0");
        assert_eq!(list[1].release, "v1.1.0-rc.1");
        for predecessor in &list {
            assert_eq!(hex(&predecessor.pcrs[0]), PCRS[0]);
            assert_eq!(hex(&predecessor.pcrs[1]), PCRS[1]);
            assert_eq!(hex(&predecessor.pcrs[2]), PCRS[2]);
        }

        // An element whose release is not earlier than the own release: the same release, a
        // later one, and the release of a candidate that the own release precedes.
        for (release, own) in [
            ("v1.1.0", "v1.1.0"),
            ("v1.1.1", "v1.1.0"),
            ("v2.0.0", "v1.1.0"),
            ("v1.1.0", "v1.1.0-rc.1"),
            ("v1.1.0-rc.2", "v1.1.0-rc.1"),
            ("v1.1.0-rc.1", "v1.1.0-rc.1"),
        ] {
            assert_eq!(
                read(json!([element(release)]), own),
                None,
                "{release} {own}"
            );
            // One such element refuses the whole list.
            assert_eq!(
                read(json!([element("v1.0.0"), element(release)]), own),
                None,
                "{release} {own}"
            );
        }
        // A program whose own release is not a release tag has no predecessor.
        for own in ["dev", "", "v0.0.0-test"] {
            assert_eq!(read(json!([element("v1.0.0")]), own), None, "{own}");
        }

        // Malformed elements and lists.
        let with = |change: fn(&mut serde_json::Value)| {
            let mut value = element("v1.0.0");
            change(&mut value);
            json!([value])
        };
        assert!(read(with(|_| {}), "v1.1.0").is_some());
        let changes: [fn(&mut serde_json::Value); 12] = [
            |element| element["release"] = json!("dev"),
            |element| element["release"] = json!("1.0.0"),
            |element| element["release"] = json!(1),
            |element| {
                element.as_object_mut().unwrap().remove("release");
            },
            |element| {
                element.as_object_mut().unwrap().remove("pcr1");
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
            assert_eq!(read(with(change), "v1.1.0"), None, "{index}");
        }
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
            assert_eq!(read_predecessors(list, "v1.1.0"), None);
        }
        // An element that names a key twice.
        let twice = format!(
            r#"[{{"release":"v1.0.0","release":"v1.0.1","pcr0":"{}","pcr1":"{}","pcr2":"{}"}}]"#,
            PCRS[0], PCRS[1], PCRS[2]
        );
        assert_eq!(read_predecessors(twice.as_bytes(), "v1.1.0"), None);
    }

    /// The public key of the transparency log `log2025-1.rekor.sigstore.dev`, as the trusted
    /// root of the public instance of Sigstore states it.
    const REKOR_LOG2025_1_KEY_PEM: &str = include_str!("../tests/fixtures/rekor-log2025-1-key.pem");
    /// The entry of that log with the index 200,000,163, in the form of the `entry` of an
    /// endorsement, with its inclusion proof.
    const REKOR_LOG2025_1_ENTRY: &str =
        include_str!("../tests/fixtures/rekor-log2025-1-entry-200000163.json");

    /// The origin of the log of the tests of the form Rekor v2.
    const ORIGIN: &str = "log.test.example/2026";

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

    fn leaf_hash(body: &[u8]) -> [u8; 32] {
        let mut hashed = Sha256::new();
        hashed.update([0x00]);
        hashed.update(body);
        hashed.finalize().into()
    }

    /// The body of a `hashedrekord` entry of version 0.0.2 in standard base64, as a log of the
    /// form Rekor v2 writes it: the keys in the order of their bytes, without white space.
    fn tiled_body_of(hashed: &[u8], key_der: &[u8], signature: &str) -> String {
        STANDARD.encode(format!(
            concat!(
                r#"{{"apiVersion":"0.0.2","kind":"hashedrekord","spec":{{"hashedRekordV002":{{"#,
                r#""data":{{"algorithm":"SHA2_256","digest":"{}"}},"#,
                r#""signature":{{"content":"{}","verifier":{{"#,
                r#""keyDetails":"PKIX_ECDSA_P256_SHA_256","publicKey":{{"rawBytes":"{}"}}}}}}}}}}}}"#
            ),
            STANDARD.encode(Sha256::digest(hashed)),
            signature,
            STANDARD.encode(key_der),
        ))
    }

    /// The key of a test log of the form Rekor v2.
    fn tiled_log_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn ed25519_spki(key: &ed25519_dalek::SigningKey) -> Vec<u8> {
        [
            &ED25519_SPKI_PREFIX[..],
            key.verifying_key().as_bytes().as_slice(),
        ]
        .concat()
    }

    /// One signature line of a signed note: the name, and the key ID in front of the
    /// signature.
    fn note_line(name: &str, key_id: &[u8], signature: &[u8]) -> String {
        format!(
            "\u{2014} {name} {}\n",
            STANDARD.encode([key_id, signature].concat())
        )
    }

    /// An endorsement whose entry is in a log of the form Rekor v2, and the keys it verifies
    /// with.
    struct Tiled {
        release_key: TestKey,
        log_key: ed25519_dalek::SigningKey,
        origin: String,
        statement: Vec<u8>,
        body: String,
        log_id: String,
        log_index: u64,
        hashes: Vec<String>,
        checkpoint: String,
        /// The leaves of the tree: the entry is one of them.
        leaves: Vec<[u8; 32]>,
    }

    impl Tiled {
        /// A valid endorsement of the release `release`: the release key signed the statement,
        /// and the log holds the entry as the leaf `index` of a tree of `size` leaves.
        fn in_tree(release: &str, index: usize, size: usize) -> Tiled {
            let release_key = TestKey::new();
            let statement = statement_of(release);
            let body = tiled_body_of(&statement, &release_key.spki, &release_key.sign(&statement));
            let log_key = tiled_log_key(7);
            let mut tiled = Tiled {
                release_key,
                log_key,
                origin: ORIGIN.to_string(),
                statement,
                body,
                log_id: String::new(),
                log_index: index as u64,
                hashes: Vec::new(),
                checkpoint: String::new(),
                leaves: (0..size)
                    .map(|leaf| Sha256::digest(format!("leaf {leaf}")).into())
                    .collect(),
            };
            tiled.log_id = tiled.log().id();
            tiled.log_takes_the_entry();
            tiled
        }

        fn of(release: &str) -> Tiled {
            Tiled::in_tree(release, 5, 11)
        }

        fn log(&self) -> TransparencyLog {
            TransparencyLog::rekor_v2(&self.origin, &ed25519_spki(&self.log_key)).unwrap()
        }

        /// The first four bytes of the identifier of the log.
        fn key_id(&self) -> Vec<u8> {
            self.log().id[..4].to_vec()
        }

        /// The note of the tree head of the leaves as they stand, with `extension` after its
        /// three lines.
        fn note(&self, extension: &str) -> String {
            format!(
                "{}\n{}\n{}\n{extension}",
                self.origin,
                self.leaves.len(),
                STANDARD.encode(tree_hash(&self.leaves))
            )
        }

        /// The signature line of the log on `note`.
        fn log_line(&self, note: &str) -> String {
            use ed25519_dalek::Signer;
            note_line(
                &self.origin,
                &self.key_id(),
                &self.log_key.sign(note.as_bytes()).to_bytes(),
            )
        }

        /// The log puts the body as it stands at the place of the entry and signs the head of
        /// its tree: the audit path and the checkpoint of the entry.
        fn log_takes_the_entry(&mut self) {
            let index = self.log_index as usize;
            self.leaves[index] = leaf_hash(&STANDARD.decode(&self.body).unwrap());
            self.hashes = audit_path(index, &self.leaves)
                .iter()
                .map(|hash| hex(hash))
                .collect();
            let note = self.note("");
            self.checkpoint = format!("{note}\n{}", self.log_line(&note));
        }

        fn entry(&self) -> LogEntry<'_> {
            LogEntry {
                log_id: &self.log_id,
                body: &self.body,
                promise: None,
                proof: Some(InclusionProof {
                    log_index: self.log_index,
                    hashes: self.hashes.iter().map(String::as_str).collect(),
                    checkpoint: &self.checkpoint,
                }),
            }
        }

        fn verify(
            &self,
            own_release: &str,
            now_s: u64,
        ) -> Result<ReleaseMeasurement, EndorsementError> {
            verify_endorsement(
                &self.statement,
                &self.entry(),
                &ReleaseKeys {
                    release: &self.release_key.spki,
                    logs: &[self.log()],
                },
                own_release,
                now_s,
            )
        }

        fn result(&self) -> Result<ReleaseMeasurement, EndorsementError> {
            self.verify("v1.1.0", NOW_S)
        }
    }

    #[test]
    fn a_statement_whose_record_a_tiled_log_holds_is_accepted() {
        let tiled = Tiled::of("v1.2.0");
        let later = tiled.result().unwrap();
        assert_eq!(later.release, "v1.2.0");
        assert_eq!(hex(&later.pcrs[0]), PCRS[0]);
        assert_eq!(hex(&later.pcrs[2]), PCRS[2]);
        assert_eq!(tiled.log().form(), LogForm::RekorV2);
        assert_eq!(tiled.log().origin(), Some(ORIGIN));

        // Every leaf of every tree of 1 to 33 leaves: the paths of a full tree, of a tree whose
        // last level is not full, and of the single leaf, which has no path.
        for size in 1..=33 {
            for index in 0..size {
                let tiled = Tiled::in_tree("v1.2.0", index, size);
                assert!(tiled.result().is_ok(), "{index} of {size}");
            }
        }
        assert!(Tiled::in_tree("v1.2.0", 0, 1).hashes.is_empty());

        // The entry states no time: the clock of the node does not decide. The notice period
        // of this release is 0 seconds.
        assert_eq!(limits::RELEASE_NOTICE_SECONDS, 0);
        for now_s in [0, 1, NOW_S, u64::MAX] {
            assert!(tiled.verify("v1.1.0", now_s).is_ok(), "{now_s}");
        }
        // The order of releases is the one of every endorsement.
        assert_eq!(
            tiled.verify("v1.2.0", NOW_S),
            Err(EndorsementError::ReleaseOrder)
        );
        assert_eq!(
            tiled.verify("dev", NOW_S),
            Err(EndorsementError::ReleaseOrder)
        );
    }

    #[test]
    fn an_entry_is_verified_in_the_form_of_its_log_and_of_no_other() {
        // A node with a table of two logs, one of each form, takes an entry of either.
        let promised = Endorsement::of("v1.2.0");
        let tiled = Tiled::of("v1.2.0");
        let logs = [promised.logs().remove(0), tiled.log()];
        assert_eq!(
            logs.iter().map(TransparencyLog::form).collect::<Vec<_>>(),
            [LogForm::RekorV1, LogForm::RekorV2]
        );
        let verify = |statement: &[u8], entry: &LogEntry<'_>, release: &TestKey| {
            verify_endorsement(
                statement,
                entry,
                &ReleaseKeys {
                    release: &release.spki,
                    logs: &logs,
                },
                "v1.1.0",
                NOW_S,
            )
        };
        assert!(verify(
            &promised.statement,
            &promised.entry(),
            &promised.release_key
        )
        .is_ok());
        assert!(verify(&tiled.statement, &tiled.entry(), &tiled.release_key).is_ok());

        // An entry with the parts of both forms is read in the form of its log.
        let mut both = promised.entry();
        both.proof = tiled.entry().proof;
        assert!(verify(&promised.statement, &both, &promised.release_key).is_ok());
        let mut both = tiled.entry();
        both.promise = promised.entry().promise;
        assert!(verify(&tiled.statement, &both, &tiled.release_key).is_ok());

        // The promise of a log of the form Rekor v1 under the identifier of the tiled log: a
        // tiled log has made no promise, and the entry has no proof.
        let mut entry = promised.entry();
        entry.log_id = &tiled.log_id;
        assert_eq!(
            verify(&promised.statement, &entry, &promised.release_key),
            Err(EndorsementError::InclusionProof)
        );
        // The proof of a tiled log under the identifier of the log of the form Rekor v1: that
        // log is asked for its signed entry timestamp.
        let mut entry = tiled.entry();
        entry.log_id = &promised.log_id;
        assert_eq!(
            verify(&tiled.statement, &entry, &tiled.release_key),
            Err(EndorsementError::EntrySignature)
        );
        // An entry of a log that is not in the table.
        let other = Tiled {
            log_key: tiled_log_key(8),
            ..Tiled::of("v1.2.0")
        };
        let mut entry = tiled.entry();
        let other_id = other.log().id();
        entry.log_id = &other_id;
        assert_eq!(
            verify(&tiled.statement, &entry, &tiled.release_key),
            Err(EndorsementError::LogId)
        );
        // A table without the tiled log refuses its entries: a node hands nothing to a release
        // whose entry is in a log it does not know.
        assert_eq!(
            verify_endorsement(
                &tiled.statement,
                &tiled.entry(),
                &ReleaseKeys {
                    release: &tiled.release_key.spki,
                    logs: &promised.logs(),
                },
                "v1.1.0",
                NOW_S,
            ),
            Err(EndorsementError::LogId)
        );
    }

    #[test]
    fn a_checkpoint_that_the_log_did_not_sign_for_this_tree_is_refused() {
        let refused = |change: fn(&mut Tiled)| {
            let mut tiled = Tiled::of("v1.2.0");
            change(&mut tiled);
            tiled.result()
        };
        let checkpoint = Err(EndorsementError::Checkpoint);

        // No checkpoint, no empty line, and a note without its three lines.
        assert_eq!(refused(|tiled| tiled.checkpoint.clear()), checkpoint);
        assert_eq!(
            refused(|tiled| tiled.checkpoint = tiled.checkpoint.replace("\n\n", "\n")),
            checkpoint
        );
        assert_eq!(
            refused(|tiled| tiled.checkpoint = tiled.checkpoint.replace('\n', "\r\n")),
            checkpoint
        );
        // The note of another log: the log signed the note of an origin that is not its own.
        assert_eq!(
            refused(|tiled| {
                let note = tiled.note("").replacen(ORIGIN, "log.test.example/2027", 1);
                tiled.checkpoint = format!("{note}\n{}", tiled.log_line(&note));
            }),
            checkpoint
        );
        // A size that is not a decimal number without a leading zero, each signed by the log.
        for size in [
            "",
            "011",
            "+11",
            "11 ",
            "0x0b",
            "18446744073709551616",
            "-1",
        ] {
            let mut tiled = Tiled::of("v1.2.0");
            let note = tiled.note("").replacen("\n11\n", &format!("\n{size}\n"), 1);
            tiled.checkpoint = format!("{note}\n{}", tiled.log_line(&note));
            assert_eq!(tiled.result(), checkpoint, "{size:?}");
        }
        // A root that is not the base64 of 32 bytes, signed by the log.
        for root in ["", "AAAA", "not base64!", &STANDARD.encode([0u8; 33])] {
            let mut tiled = Tiled::of("v1.2.0");
            let lines: Vec<String> = tiled.note("").lines().map(str::to_string).collect();
            let note = format!("{}\n{}\n{root}\n", lines[0], lines[1]);
            tiled.checkpoint = format!("{note}\n{}", tiled.log_line(&note));
            assert_eq!(tiled.result(), checkpoint, "{root:?}");
        }

        // A note that was changed after the log signed it: another size, another root, a line
        // more.
        assert_eq!(
            refused(|tiled| tiled.checkpoint = tiled.checkpoint.replacen("\n11\n", "\n12\n", 1)),
            checkpoint
        );
        assert_eq!(
            refused(|tiled| {
                let root = STANDARD.encode(tree_hash(&tiled.leaves));
                let other = STANDARD.encode([9u8; 32]);
                tiled.checkpoint = tiled.checkpoint.replacen(&root, &other, 1);
            }),
            checkpoint
        );
        assert_eq!(
            refused(|tiled| tiled.checkpoint = tiled.checkpoint.replacen("\n\n", "\nmore\n\n", 1)),
            checkpoint
        );

        // The signature of another key under the name and the key ID of the log, no line of
        // the log, a line of the log that is no signature, and the signature of the log
        // under another key ID or another name.
        assert_eq!(
            refused(|tiled| {
                use ed25519_dalek::Signer;
                let note = tiled.note("");
                let signature = tiled_log_key(8).sign(note.as_bytes()).to_bytes();
                tiled.checkpoint = format!(
                    "{note}\n{}",
                    note_line(&tiled.origin, &tiled.key_id(), &signature)
                );
            }),
            checkpoint
        );
        assert_eq!(
            refused(|tiled| tiled.checkpoint = format!("{}\n", tiled.note(""))),
            checkpoint
        );
        assert_eq!(
            refused(|tiled| {
                let note = tiled.note("");
                tiled.checkpoint = format!(
                    "{note}\n{}",
                    note_line(&tiled.origin, &tiled.key_id(), &[0u8; 63])
                );
            }),
            checkpoint
        );
        assert_eq!(
            refused(|tiled| {
                use ed25519_dalek::Signer;
                let note = tiled.note("");
                let signature = tiled.log_key.sign(note.as_bytes()).to_bytes();
                tiled.checkpoint = format!(
                    "{note}\n{}",
                    note_line(&tiled.origin, &[1, 2, 3, 4], &signature)
                );
            }),
            checkpoint
        );
        assert_eq!(
            refused(|tiled| {
                use ed25519_dalek::Signer;
                let note = tiled.note("");
                let signature = tiled.log_key.sign(note.as_bytes()).to_bytes();
                tiled.checkpoint = format!(
                    "{note}\n{}",
                    note_line("another.example", &tiled.key_id(), &signature)
                );
            }),
            checkpoint
        );
        // A second line of the log that does not verify refuses the checkpoint, before and
        // after the line that verifies.
        for first in [true, false] {
            let mut tiled = Tiled::of("v1.2.0");
            let note = tiled.note("");
            let good = tiled.log_line(&note);
            let bad = note_line(&tiled.origin, &tiled.key_id(), &[0u8; 64]);
            tiled.checkpoint = match first {
                true => format!("{note}\n{bad}{good}"),
                false => format!("{note}\n{good}{bad}"),
            };
            assert_eq!(tiled.result(), checkpoint, "{first}");
        }
        // The signature of the log over the note without the line feed that ends it.
        assert_eq!(
            refused(|tiled| {
                let note = tiled.note("");
                tiled.checkpoint =
                    format!("{note}\n{}", tiled.log_line(note.trim_end_matches('\n')));
            }),
            checkpoint
        );

        // A checkpoint of more than 262,144 bytes: lines of witnesses fill it to an exact
        // length.
        assert_eq!(limits::RELEASE_CHECKPOINT_BYTES, 262_144);
        let filled = |length: usize| {
            let mut tiled = Tiled::of("v1.2.0");
            let line = note_line("witness.example", &[1, 2, 3, 4], &[0u8; 72]);
            while tiled.checkpoint.len() + line.len() <= length {
                tiled.checkpoint.push_str(&line);
            }
            let rest = length - tiled.checkpoint.len();
            tiled.checkpoint.push_str(&"x".repeat(rest));
            assert_eq!(tiled.checkpoint.len(), length);
            tiled.result()
        };
        assert!(filled(262_144).is_ok());
        assert_eq!(filled(262_145), checkpoint);
    }

    #[test]
    fn a_checkpoint_counts_by_the_lines_of_the_log_alone() {
        use ed25519_dalek::Signer;
        // The lines of witnesses, in front of and behind the line of the log: a line with a
        // timestamp in front of its signature, a line that is no base64, a line without a
        // name, an empty line, and a line under the name of the log with the key ID of
        // another key of that name.
        let mut tiled = Tiled::of("v1.2.0");
        let note = tiled.note("");
        let witness = note_line("witness.example/w1", &[0xa3, 0xe0, 0x0f, 0xe2], &[5u8; 72]);
        let other_key_of_the_log = note_line(&tiled.origin, &[1, 2, 3, 4], &[6u8; 2420]);
        tiled.checkpoint = format!(
            "{note}\n{witness}\u{2014} witness.example/w2 not-base64!\n\u{2014} \n\nfree text\n{other_key_of_the_log}{}{witness}",
            tiled.log_line(&note)
        );
        assert!(tiled.result().is_ok());

        // A name that begins with the origin of the log is another name.
        let longer = format!("{}/shard", tiled.origin);
        let line = note_line(&longer, &tiled.key_id(), &[0u8; 64]);
        tiled.checkpoint = format!("{note}\n{line}{}", tiled.log_line(&note));
        assert!(tiled.result().is_ok());

        // Extension lines of the note that the log signed are not read.
        let note = tiled.note("extension one\nextension two\n");
        tiled.checkpoint = format!("{note}\n{}", tiled.log_line(&note));
        assert!(tiled.result().is_ok());

        // The last line without its line feed.
        let note = tiled.note("");
        tiled.checkpoint = format!("{note}\n{}", tiled.log_line(&note).trim_end());
        assert!(tiled.result().is_ok());

        // Two lines of the log that both verify (Ed25519 signatures are deterministic: the
        // same line twice).
        tiled.checkpoint = format!("{note}\n{}{}", tiled.log_line(&note), tiled.log_line(&note));
        assert!(tiled.result().is_ok());

        // A checkpoint of a later tree of the same log does not hold the root of this path.
        let later = Tiled::in_tree("v1.2.0", 5, 12);
        let later_note = later.note("");
        tiled.checkpoint = format!(
            "{later_note}\n{}",
            note_line(
                &tiled.origin,
                &tiled.key_id(),
                &tiled.log_key.sign(later_note.as_bytes()).to_bytes()
            )
        );
        assert_eq!(tiled.result(), Err(EndorsementError::InclusionProof));
    }

    #[test]
    fn an_audit_path_that_does_not_lead_from_this_entry_to_the_root_is_refused() {
        let refused = |change: fn(&mut Tiled)| {
            let mut tiled = Tiled::of("v1.2.0");
            change(&mut tiled);
            tiled.result()
        };
        let proof = Err(EndorsementError::InclusionProof);

        // Another index: a neighbor, the last leaf, the size and beyond.
        assert_eq!(refused(|tiled| tiled.log_index = 4), proof);
        assert_eq!(refused(|tiled| tiled.log_index = 10), proof);
        assert_eq!(refused(|tiled| tiled.log_index = 11), proof);
        assert_eq!(refused(|tiled| tiled.log_index = u64::MAX), proof);
        // A changed hash, a missing hash (the first, the last, all), an added hash, two
        // hashes in the other order.
        assert_eq!(refused(|tiled| tiled.hashes[1] = hex(&[3u8; 32])), proof);
        assert_eq!(
            refused(|tiled| {
                tiled.hashes.remove(0);
            }),
            proof
        );
        assert_eq!(
            refused(|tiled| {
                tiled.hashes.pop();
            }),
            proof
        );
        assert_eq!(refused(|tiled| tiled.hashes.clear()), proof);
        assert_eq!(refused(|tiled| tiled.hashes.push(hex(&[3u8; 32]))), proof);
        assert_eq!(
            refused(|tiled| {
                let root = hex(&tree_hash(&tiled.leaves));
                tiled.hashes.push(root);
            }),
            proof
        );
        assert_eq!(refused(|tiled| tiled.hashes.swap(0, 1)), proof);
        // A hash that is not 64 lower-case hexadecimal characters.
        assert_eq!(
            refused(|tiled| tiled.hashes[0] = tiled.hashes[0].to_uppercase()),
            proof
        );
        assert_eq!(
            refused(|tiled| {
                tiled.hashes[0].pop();
            }),
            proof
        );
        assert_eq!(
            refused(|tiled| {
                let hash: [u8; 32] = hex_bytes(&tiled.hashes[0]).unwrap();
                tiled.hashes[0] = STANDARD.encode(hash);
            }),
            proof
        );
        // Another body than the leaf of the tree: a valid record of the same statement under
        // the same release key (its signature differs), and a body that is no base64.
        assert_eq!(
            refused(|tiled| {
                tiled.body = tiled_body_of(
                    &tiled.statement,
                    &tiled.release_key.spki,
                    &tiled.release_key.sign(&tiled.statement),
                );
            }),
            proof
        );
        assert_eq!(refused(|tiled| tiled.body.push('!')), proof);
        assert_eq!(refused(|tiled| tiled.body.insert(0, ' ')), proof);

        // An entry without a proof.
        let tiled = Tiled::of("v1.2.0");
        let mut entry = tiled.entry();
        entry.proof = None;
        assert_eq!(
            verify_endorsement(
                &tiled.statement,
                &entry,
                &ReleaseKeys {
                    release: &tiled.release_key.spki,
                    logs: &[tiled.log()],
                },
                "v1.1.0",
                NOW_S,
            ),
            proof
        );

        // The proof of another entry of the same tree, with the body of this one.
        let mut tiled = Tiled::of("v1.2.0");
        tiled.hashes = audit_path(6, &tiled.leaves)
            .iter()
            .map(|hash| hex(hash))
            .collect();
        tiled.log_index = 6;
        assert_eq!(tiled.result(), proof);

        // The path computation itself: the root of a tree of one leaf is the leaf, and a path
        // for it is too long.
        let body = b"body";
        assert_eq!(audit_root(body, 0, 1, &[]), Some(leaf_hash(body)));
        assert_eq!(audit_root(body, 0, 1, &[&hex(&[1u8; 32])]), None);
        assert_eq!(audit_root(body, 0, 0, &[]), None);
        assert_eq!(audit_root(body, 1, 1, &[]), None);
        // The largest tree a size of 64 bits states. The path of its first leaf has 64 hashes,
        // every one on the right, and the path of its last leaf 63, every one on the left.
        let hashes: Vec<String> = (0..65u8).map(|level| hex(&[level; 32])).collect();
        let path: Vec<&str> = hashes.iter().map(String::as_str).collect();
        let first = (0..64u8).fold(leaf_hash(body), |root, level| {
            node_hash(&root, &[level; 32])
        });
        assert_eq!(limits::RELEASE_PROOF_HASHES, 64);
        assert_eq!(audit_root(body, 0, u64::MAX, &path[..64]), Some(first));
        assert_eq!(audit_root(body, 0, u64::MAX, &path[..63]), None);
        assert_eq!(audit_root(body, 0, u64::MAX, &path[..65]), None);
        let last = (0..63u8).fold(leaf_hash(body), |root, level| {
            node_hash(&[level; 32], &root)
        });
        assert_eq!(
            audit_root(body, u64::MAX - 1, u64::MAX, &path[..63]),
            Some(last)
        );
        assert_eq!(audit_root(body, u64::MAX - 1, u64::MAX, &path[..62]), None);
        assert_eq!(audit_root(body, u64::MAX - 1, u64::MAX, &path[..64]), None);
        // A tree of 2^63 + 1 leaves: its last leaf hangs directly under the root.
        let size = (1u64 << 63) + 1;
        let sibling = hex(&[9u8; 32]);
        assert_eq!(
            audit_root(body, size - 1, size, &[&sibling]),
            Some(node_hash(&[9u8; 32], &leaf_hash(body)))
        );
    }

    #[test]
    fn a_tiled_body_that_is_not_the_record_of_this_statement_under_the_release_key_is_refused() {
        // Each body is a leaf of the tree the log signed: only the body decides.
        let refused = |body: &dyn Fn(&Tiled) -> String| {
            let mut tiled = Tiled::of("v1.2.0");
            tiled.body = body(&tiled);
            tiled.log_takes_the_entry();
            tiled.result()
        };
        let own = |tiled: &Tiled| String::from_utf8(STANDARD.decode(&tiled.body).unwrap()).unwrap();

        // The hash of another statement, signed by the release key.
        assert_eq!(
            refused(&|tiled| {
                let other = statement_of("v1.3.0");
                tiled_body_of(
                    &other,
                    &tiled.release_key.spki,
                    &tiled.release_key.sign(&other),
                )
            }),
            Err(EndorsementError::StatementHash)
        );
        // Another public key, with the signature of that key over the statement.
        assert_eq!(
            refused(&|tiled| {
                let other = TestKey::new();
                tiled_body_of(&tiled.statement, &other.spki, &other.sign(&tiled.statement))
            }),
            Err(EndorsementError::ReleaseKey)
        );
        // The release key, with the signature of another key, over other bytes, and none.
        assert_eq!(
            refused(&|tiled| {
                tiled_body_of(
                    &tiled.statement,
                    &tiled.release_key.spki,
                    &TestKey::new().sign(&tiled.statement),
                )
            }),
            Err(EndorsementError::ReleaseSignature)
        );
        assert_eq!(
            refused(&|tiled| {
                tiled_body_of(
                    &tiled.statement,
                    &tiled.release_key.spki,
                    &tiled.release_key.sign(b"other bytes"),
                )
            }),
            Err(EndorsementError::ReleaseSignature)
        );
        assert_eq!(
            refused(&|tiled| tiled_body_of(&tiled.statement, &tiled.release_key.spki, "!")),
            Err(EndorsementError::ReleaseSignature)
        );
        // The release key as its PEM (the form of a log of the form Rekor v1) is not the key.
        assert_eq!(
            refused(&|tiled| {
                tiled_body_of(
                    &tiled.statement,
                    tiled.release_key.pem().as_bytes(),
                    &tiled.release_key.sign(&tiled.statement),
                )
            }),
            Err(EndorsementError::ReleaseKey)
        );

        // (what changes in the text of the body, the failure)
        let changes: [(&str, &str, EndorsementError); 12] = [
            // Another version, kind or hash algorithm.
            (
                r#""apiVersion":"0.0.2""#,
                r#""apiVersion":"0.0.1""#,
                EndorsementError::EntryBody,
            ),
            (
                r#""apiVersion":"0.0.2""#,
                r#""apiVersion":"0.0.3""#,
                EndorsementError::EntryBody,
            ),
            (
                r#""kind":"hashedrekord""#,
                r#""kind":"dsse""#,
                EndorsementError::EntryBody,
            ),
            (
                r#""algorithm":"SHA2_256""#,
                r#""algorithm":"SHA2_512""#,
                EndorsementError::EntryBody,
            ),
            // The record under another name, as an older text of the log documents it.
            (
                r#""hashedRekordV002""#,
                r#""hashedRekordV0_0_2""#,
                EndorsementError::EntryBody,
            ),
            // A value of another type.
            (
                r#""algorithm":"SHA2_256""#,
                r#""algorithm":1"#,
                EndorsementError::EntryBody,
            ),
            // Another kind of key for the same bytes, and a certificate in the place of the key.
            (
                r#""keyDetails":"PKIX_ECDSA_P256_SHA_256""#,
                r#""keyDetails":"PKIX_ECDSA_P384_SHA_384""#,
                EndorsementError::ReleaseKey,
            ),
            (
                r#""publicKey":{"rawBytes""#,
                r#""x509Certificate":{"rawBytes""#,
                EndorsementError::ReleaseKey,
            ),
            // A key the node reads that occurs twice, at each depth: the body states two
            // values for it.
            (
                r#""kind":"hashedrekord""#,
                r#""kind":"hashedrekord","kind":"hashedrekord""#,
                EndorsementError::EntryBody,
            ),
            (
                r#""data":{"#,
                r#""data":{"digest":"AAAA","#,
                EndorsementError::EntryBody,
            ),
            (
                r#""verifier":{"#,
                r#""verifier":{"publicKey":{"rawBytes":"AAAA"},"#,
                EndorsementError::EntryBody,
            ),
            (
                r#""signature":{"content""#,
                r#""signature":{"content":"AAAA","content""#,
                EndorsementError::EntryBody,
            ),
        ];
        for (from, to, failure) in changes {
            let result = refused(&|tiled| {
                let text = own(tiled);
                assert!(text.contains(from), "{from}");
                STANDARD.encode(text.replacen(from, to, 1))
            });
            assert_eq!(result, Err(failure), "{from} {to}");
        }
        // A key the node does not read may occur, also twice, and white space does not decide:
        // the body is the leaf as the log holds it.
        for (from, to) in [
            (
                r#""kind":"hashedrekord""#,
                r#""kind":"hashedrekord","note":1,"note":2"#,
            ),
            (r#""data":{"#, r#""data": {"extra":[],"#),
        ] {
            let result = refused(&|tiled| STANDARD.encode(own(tiled).replacen(from, to, 1)));
            assert!(result.is_ok(), "{to}");
        }
        // The record of a log of the form Rekor v1 for the same statement, a body that is not
        // a JSON object, and a body with a text after the object.
        assert_eq!(
            refused(&|tiled| {
                body_of(
                    &tiled.statement,
                    &tiled.release_key.pem(),
                    &tiled.release_key.sign(&tiled.statement),
                )
            }),
            Err(EndorsementError::EntryBody)
        );
        for body in ["[]", "\"text\"", "", "{}"] {
            assert_eq!(
                refused(&|_| STANDARD.encode(body)),
                Err(EndorsementError::EntryBody),
                "{body}"
            );
        }
        assert_eq!(
            refused(&|tiled| STANDARD.encode(format!("{}x", own(tiled)))),
            Err(EndorsementError::EntryBody)
        );

        // The record of a tiled log in a log of the form Rekor v1 is not the record of that
        // form.
        let mut promised = Endorsement::of("v1.2.0");
        promised.body = tiled_body_of(
            &promised.statement,
            &promised.release_key.spki,
            &promised.release_key.sign(&promised.statement),
        );
        promised.log_signs();
        assert_eq!(promised.result(), Err(EndorsementError::EntryBody));
    }

    #[test]
    fn the_parts_of_an_entry_are_read_by_their_form() {
        let promised = Endorsement::of("v1.2.0");
        let tiled = Tiled::of("v1.2.0");
        let promise = json!({
            "log_id": promised.log_id,
            "body": promised.body,
            "integrated_time": promised.integrated_time,
            "log_index": promised.log_index,
            "signed_entry_timestamp": promised.signed_entry_timestamp,
        });
        let entry = LogEntry::read(&promise).unwrap();
        assert_eq!(
            (entry.log_id, entry.body),
            (&promised.log_id[..], &promised.body[..])
        );
        assert!(entry.promise.is_some() && entry.proof.is_none());
        assert_eq!(entry.promise.unwrap().log_index, promised.log_index);

        let proof = json!({
            "log_id": tiled.log_id,
            "body": tiled.body,
            "inclusion_proof": {
                "log_index": tiled.log_index,
                "hashes": tiled.hashes,
                "checkpoint": tiled.checkpoint,
                // Keys a node does not read: the size and the root are those of the checkpoint.
                "tree_size": 1,
                "root_hash": "00",
            },
        });
        let entry = LogEntry::read(&proof).unwrap();
        assert!(entry.promise.is_none());
        let read = entry.proof.clone().unwrap();
        assert_eq!(read.log_index, tiled.log_index);
        assert_eq!(read.hashes, tiled.hashes);
        assert_eq!(read.checkpoint, tiled.checkpoint);
        assert!(verify_endorsement(
            &tiled.statement,
            &entry,
            &ReleaseKeys {
                release: &tiled.release_key.spki,
                logs: &[tiled.log()],
            },
            "v1.1.0",
            NOW_S,
        )
        .is_ok());

        // An entry without `log_id` or `body`, or with one of another type, is no entry.
        for key in ["log_id", "body"] {
            let mut entry = proof.clone();
            entry.as_object_mut().unwrap().remove(key);
            assert!(LogEntry::read(&entry).is_none(), "{key}");
            entry[key] = json!(1);
            assert!(LogEntry::read(&entry).is_none(), "{key}");
        }
        for entry in [json!(null), json!([]), json!("text")] {
            assert!(LogEntry::read(&entry).is_none());
        }
        // A promise or a proof of another form is absent.
        type Change = fn(&mut serde_json::Value);
        let promises: [Change; 5] = [
            |entry| entry["integrated_time"] = json!("1"),
            |entry| entry["integrated_time"] = json!(-1),
            |entry| entry["log_index"] = json!(1.5),
            |entry| entry["signed_entry_timestamp"] = json!(null),
            |entry| {
                entry.as_object_mut().unwrap().remove("log_index");
            },
        ];
        for (index, change) in promises.into_iter().enumerate() {
            let mut entry = promise.clone();
            change(&mut entry);
            assert!(LogEntry::read(&entry).unwrap().promise.is_none(), "{index}");
        }
        let proofs: [Change; 8] = [
            |entry| entry["inclusion_proof"] = json!("text"),
            |entry| entry["inclusion_proof"]["log_index"] = json!("5"),
            |entry| entry["inclusion_proof"]["log_index"] = json!(-5),
            |entry| entry["inclusion_proof"]["hashes"] = json!("text"),
            |entry| entry["inclusion_proof"]["hashes"][0] = json!(1),
            |entry| entry["inclusion_proof"]["checkpoint"] = json!(["text"]),
            |entry| {
                entry["inclusion_proof"]
                    .as_object_mut()
                    .unwrap()
                    .remove("checkpoint");
            },
            // More hashes than a path of a tree of 2^64 leaves has.
            |entry| entry["inclusion_proof"]["hashes"] = json!(vec!["00"; 65]),
        ];
        for (index, change) in proofs.into_iter().enumerate() {
            let mut entry = proof.clone();
            change(&mut entry);
            assert!(LogEntry::read(&entry).unwrap().proof.is_none(), "{index}");
        }
        let mut entry = proof.clone();
        entry["inclusion_proof"]["hashes"] = json!(vec!["00"; 64]);
        assert!(LogEntry::read(&entry).unwrap().proof.is_some());
    }

    #[test]
    fn a_log_of_the_table_has_a_key_and_an_identifier_of_its_form() {
        // Rekor of rekor.sigstore.dev: the identifier is the hash of the key.
        let rekor = TransparencyLog::rekor_v1(&public_key_der(REKOR_KEY_PEM).unwrap()).unwrap();
        assert_eq!(rekor.form(), LogForm::RekorV1);
        assert_eq!(rekor.origin(), None);
        assert_eq!(
            rekor.id(),
            "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
        );

        // log2025-1.rekor.sigstore.dev: the identifier is the hash of its origin, a line feed,
        // the byte 0x01 and its key. The log states it in every entry (`logId.keyId`), and
        // the first four bytes are in front of its signature on every checkpoint.
        let key = public_key_der(REKOR_LOG2025_1_KEY_PEM).unwrap();
        let tiled = TransparencyLog::rekor_v2("log2025-1.rekor.sigstore.dev", &key).unwrap();
        assert_eq!(tiled.form(), LogForm::RekorV2);
        assert_eq!(tiled.origin(), Some("log2025-1.rekor.sigstore.dev"));
        assert_eq!(
            tiled.id(),
            "cf1199155bddd051268d1f16ac5c0c75c009f6fb5a63f4177f8e18d7051e3fa0"
        );
        // Another origin with the same key is another log.
        let other = TransparencyLog::rekor_v2("log2026-1.rekor.sigstore.dev", &key).unwrap();
        assert_ne!(other.id(), tiled.id());

        // A key of the other form, a key that is not a point of the curve group of prime
        // order, and an origin that is not the name of a key of a signed note.
        let p256 = public_key_der(REKOR_KEY_PEM).unwrap();
        assert!(TransparencyLog::rekor_v2("log.example", &p256).is_none());
        assert!(TransparencyLog::rekor_v1(&key).is_none());
        assert!(TransparencyLog::rekor_v2("log.example", &key[..43]).is_none());
        assert!(TransparencyLog::rekor_v2("log.example", &key[12..]).is_none());
        let small_order = [&ED25519_SPKI_PREFIX[..], &[0u8; 32]].concat();
        assert!(TransparencyLog::rekor_v2("log.example", &small_order).is_none());
        for origin in ["", "log example", "log+example", "log\nexample", "로그"] {
            assert!(
                TransparencyLog::rekor_v2(origin, &key).is_none(),
                "{origin:?}"
            );
        }
        assert!(TransparencyLog::rekor_v2("log.example/a_b-c~1", &key).is_some());
    }

    #[test]
    fn the_inclusion_proof_of_a_real_entry_of_a_tiled_log_verifies() {
        let key = public_key_der(REKOR_LOG2025_1_KEY_PEM).unwrap();
        let log = TransparencyLog::rekor_v2("log2025-1.rekor.sigstore.dev", &key).unwrap();
        let entry: serde_json::Value = serde_json::from_str(REKOR_LOG2025_1_ENTRY).unwrap();
        assert_eq!(entry["log_id"], log.id());
        let read = LogEntry::read(&entry).unwrap();
        let proof = read.proof.clone().unwrap();
        assert_eq!(proof.log_index, 200_000_163);
        assert_eq!(proof.hashes.len(), 28);
        let LogKey::RekorV2 { origin, key } = &log.key else {
            panic!("the log is of the form Rekor v2");
        };
        let key_id = [0xcf, 0x11, 0x99, 0x15];

        // The checkpoint: the note of the tree head of 212,315,329 leaves, with the signature
        // of the log and the signatures of four witnesses, which are not read.
        assert_eq!(proof.checkpoint.matches('\u{2014}').count(), 5);
        let head = signed_tree_head(origin, key, key_id, proof.checkpoint).unwrap();
        assert_eq!(head.size, 212_315_329);
        assert_eq!(
            hex(&head.root),
            "064231d4823fc649603d2377d4e512dcb91b3de7fb2f788d4cb23910ca57543f"
        );
        // The checkpoint with the line of the log alone counts as well, and without that line
        // it does not.
        let lines: Vec<&str> = proof.checkpoint.split_inclusive('\n').collect();
        assert_eq!(lines.len(), 9);
        let own: String = lines[..5].concat();
        assert!(own.ends_with('\n') && own.contains("\u{2014} log2025-1.rekor.sigstore.dev "));
        assert!(signed_tree_head(origin, key, key_id, &own).is_some());
        let witnesses: String = [&lines[..4], &lines[5..]].concat().concat();
        assert!(signed_tree_head(origin, key, key_id, &witnesses).is_none());
        // Another size, another origin and another key do not verify.
        assert!(signed_tree_head(
            origin,
            key,
            key_id,
            &proof.checkpoint.replacen("212315329", "212315330", 1)
        )
        .is_none());
        assert!(signed_tree_head(
            "log2026-1.rekor.sigstore.dev",
            key,
            key_id,
            proof.checkpoint
        )
        .is_none());
        assert!(signed_tree_head(
            origin,
            &tiled_log_key(7).verifying_key(),
            key_id,
            proof.checkpoint
        )
        .is_none());

        // The audit path: from the leaf of the body, the SHA-256 of the byte 0x00 and the
        // body, to the root of the checkpoint.
        let body = STANDARD.decode(read.body).unwrap();
        assert_eq!(
            hex(&leaf_hash(&body)),
            "71e978e1e0c4ac758f0172c04d09cf0474614a27312327271e625be419b7d659"
        );
        assert_eq!(
            audit_root(&body, proof.log_index, head.size, &proof.hashes),
            Some(head.root)
        );
        // Another leaf, and a tree in which the way of this leaf to the root has another
        // length: the tree that ends with the entry, and the tree of twice the size. (A path
        // alone does not say the size of its tree: a tree of one leaf more has the same way
        // for this leaf. The size counts because the log signed it with the root.)
        for (index, size) in [
            (proof.log_index + 1, head.size),
            (proof.log_index - 1, head.size),
            (proof.log_index, proof.log_index + 1),
            (proof.log_index, 2 * head.size),
        ] {
            assert_ne!(
                audit_root(&body, index, size, &proof.hashes),
                Some(head.root),
                "{index} {size}"
            );
        }
        let mut other_body = body.clone();
        other_body[0] ^= 1;
        assert_ne!(
            audit_root(&other_body, proof.log_index, head.size, &proof.hashes),
            Some(head.root)
        );

        // The body is a `hashedrekord` of version 0.0.2 under the public key of its signer,
        // in the form a node reads: the keys of an entry of the release key.
        let record: TiledBody = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            (record.api_version.as_str(), record.kind.as_str()),
            ("0.0.2", "hashedrekord")
        );
        let record = record.spec.record;
        assert_eq!(record.data.algorithm, "SHA2_256");
        assert_eq!(STANDARD.decode(&record.data.digest).unwrap().len(), 32);
        assert_eq!(
            record.signature.verifier.key_details,
            "PKIX_ECDSA_P256_SHA_256"
        );
        let signer = STANDARD
            .decode(record.signature.verifier.public_key.unwrap().raw_bytes)
            .unwrap();
        assert!(is_p256_public_key(&signer));
        assert!(STANDARD.decode(&record.signature.content).is_ok());
        // The log wrote the body as the canonical JSON of these values.
        assert_eq!(
            read.body,
            STANDARD.encode(format!(
                concat!(
                    r#"{{"apiVersion":"0.0.2","kind":"hashedrekord","spec":{{"hashedRekordV002":{{"#,
                    r#""data":{{"algorithm":"SHA2_256","digest":"{}"}},"#,
                    r#""signature":{{"content":"{}","verifier":{{"#,
                    r#""keyDetails":"PKIX_ECDSA_P256_SHA_256","publicKey":{{"rawBytes":"{}"}}}}}}}}}}}}"#
                ),
                record.data.digest,
                record.signature.content,
                STANDARD.encode(&signer),
            ))
        );

        // As the endorsement of a statement the entry passes checks 2 and 3 and fails check
        // 4: it is the record of another signer over other data.
        let statement = statement_of("v1.2.0");
        let result = verify_endorsement(
            &statement,
            &read,
            &ReleaseKeys {
                release: &TestKey::new().spki,
                logs: std::slice::from_ref(&log),
            },
            "v1.1.0",
            NOW_S,
        );
        assert_eq!(result, Err(EndorsementError::StatementHash));
    }

    #[test]
    fn every_failure_names_the_check_that_failed() {
        let checks = [
            (EndorsementError::Statement, 1),
            (EndorsementError::LogId, 2),
            (EndorsementError::EntrySignature, 3),
            (EndorsementError::Checkpoint, 3),
            (EndorsementError::InclusionProof, 3),
            (EndorsementError::EntryBody, 4),
            (EndorsementError::StatementHash, 4),
            (EndorsementError::ReleaseKey, 4),
            (EndorsementError::ReleaseSignature, 4),
            (EndorsementError::EntryTime, 5),
            (EndorsementError::ReleaseOrder, 6),
        ];
        for (failure, check) in checks {
            assert_eq!(failure.check(), check, "{failure:?}");
        }
    }
}
