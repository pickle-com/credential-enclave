//! The delegation transfer to a later release (protocol.md 10.3): the release statement, the
//! entry of the public transparency log that records its signature, the order of releases and
//! the list of predecessors.
//!
//! A node hands delegations to a node of a later release when the release key of the operator
//! signed the measurements of that release and the transparency log Rekor recorded that
//! signature. A node takes delegations from a node of a release that its own program lists as
//! a predecessor. What is decided here is whether an endorsement holds, how two releases are
//! ordered and what a list of predecessors states. Which peer a node then accepts is decided
//! where the attestation of that peer is verified (`enclave/src/attest.rs`).
//!
//! The release key and the key of the log are arguments: the node program passes the two keys
//! that are compiled into it.

use std::cmp::Ordering;
use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
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
    /// Check 2: the entry is not of the log whose key the node holds.
    LogId,
    /// Check 3: the signed entry timestamp is not the signature of the log over this entry.
    EntrySignature,
    /// Check 4: the body of the entry is not a `hashedrekord` of version 0.0.1 over a SHA-256
    /// hash.
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
        && (digits.len() == 1 || digits[0] != b'0');
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
                    match MEASUREMENT_KEYS.iter().position(|name| *name == key) {
                        Some(index) if values[index].is_some() => {
                            return Err(A::Error::duplicate_field(MEASUREMENT_KEYS[index]));
                        }
                        Some(index) => values[index] = Some(map.next_value()?),
                        None => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                let mut fields: [String; 4] = Default::default();
                for (index, value) in values.into_iter().enumerate() {
                    fields[index] =
                        value.ok_or_else(|| A::Error::missing_field(MEASUREMENT_KEYS[index]))?;
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
    let (pairs, []) = text.as_bytes().as_chunks::<2>() else {
        return None;
    };
    if pairs.len() != 48 {
        return None;
    }
    let mut value = [0u8; 48];
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

/// The identifier of a transparency log: the lower-case hexadecimal SHA-256 of the DER of its
/// public key.
pub fn log_id(log_key_der: &[u8]) -> String {
    hex(&Sha256::digest(log_key_der))
}

/// The two public keys an endorsement is verified with, each as the DER of its
/// SubjectPublicKeyInfo (ECDSA P-256).
#[derive(Clone, Copy, Debug)]
pub struct ReleaseKeys<'a> {
    /// The release key of the operator.
    pub release: &'a [u8],
    /// The key of the transparency log.
    pub log: &'a [u8],
}

/// An entry of the transparency log, as an endorsement carries it.
#[derive(Clone, Copy, Debug)]
pub struct LogEntry<'a> {
    /// The body of the entry, in standard base64, exactly as the log returned it.
    pub body: &'a str,
    /// The time at which the log took the entry, in Unix epoch seconds.
    pub integrated_time: u64,
    /// The index of the entry in the log.
    pub log_index: u64,
    /// The identifier of the log: 64 lower-case hexadecimal characters.
    pub log_id: &'a str,
    /// The signed entry timestamp: the signature of the log over the entry, in standard
    /// base64.
    pub signed_entry_timestamp: &'a str,
}

/// The bytes the log signed for an entry: the JSON object of `body`, `integratedTime`, `logID`
/// and `logIndex`, with its keys in this order and without white space. `None` when `body`
/// holds a character outside the base64 alphabet: such a character could end the string of
/// the body and state other values for the keys that follow it.
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

/// Check 4 of [`verify_endorsement`]: the body of the entry is a `hashedrekord` of version
/// 0.0.1 that holds the SHA-256 of `statement`, the release key and a signature of that key
/// over `statement`.
fn verify_body(
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

/// Check 5 of [`verify_endorsement`]: an entry counts when its time lies at most 300 seconds
/// after the clock of the node and, with a notice period, when the entry is at least as old
/// as that period by the clock of the node. The 300 seconds allow for a clock of the node that
/// is behind the clock of the log. They do not shorten a notice period.
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
/// | 2 | `log_id` of the entry is the identifier of the log key | `LogId` |
/// | 3 | `body` holds only characters of the base64 alphabet, and the signed entry timestamp is a signature of the log key over the entry | `EntrySignature` |
/// | 4 | `body` is a `hashedrekord` of version 0.0.1 with the SHA-256 of `statement`, with the release key, and with a signature of the release key over `statement` | `EntryBody`, `StatementHash`, `ReleaseKey`, `ReleaseSignature` |
/// | 5 | the time of the entry lies at most 300 seconds after `now_s`, and the notice period has passed | `EntryTime` |
/// | 6 | the release of the statement is later than `own_release` | `ReleaseOrder` |
///
/// Both signatures are ECDSA P-256 with SHA-256 in ASN.1 DER. A key of `keys` that is not the
/// SubjectPublicKeyInfo of an ECDSA P-256 public key verifies nothing.
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
    let log_id = log_id(keys.log);
    if entry.log_id != log_id {
        return Err(EndorsementError::LogId);
    }
    // 3
    let signed = signed_entry(entry.body, entry.integrated_time, &log_id, entry.log_index)
        .ok_or(EndorsementError::EntrySignature)?;
    let timestamp = STANDARD
        .decode(entry.signed_entry_timestamp)
        .map_err(|_| EndorsementError::EntrySignature)?;
    if !p256_verifies(keys.log, signed.as_bytes(), &timestamp) {
        return Err(EndorsementError::EntrySignature);
    }
    // 4
    verify_body(entry.body, statement, keys.release)?;
    // 5
    if !entry_time_counts(entry.integrated_time, now_s, limits::RELEASE_NOTICE_SECONDS) {
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

        fn verify(
            &self,
            own_release: &str,
            now_s: u64,
        ) -> Result<ReleaseMeasurement, EndorsementError> {
            verify_endorsement(
                &self.statement,
                &LogEntry {
                    body: &self.body,
                    integrated_time: self.integrated_time,
                    log_index: self.log_index,
                    log_id: &self.log_id,
                    signed_entry_timestamp: &self.signed_entry_timestamp,
                },
                &ReleaseKeys {
                    release: &self.release_key.spki,
                    log: &self.log_key.spki,
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
            &LogEntry {
                body,
                integrated_time,
                log_index,
                log_id: entry["log_id"].as_str().unwrap(),
                signed_entry_timestamp: entry["signed_entry_timestamp"].as_str().unwrap(),
            },
            &ReleaseKeys {
                release: &TestKey::new().spki,
                log: &log_key,
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
        let mut endorsement = Endorsement::of("v1.2.0");
        endorsement.log_key.spki[26] = 0x02;
        endorsement.log_id = log_id(&endorsement.log_key.spki);
        assert_eq!(endorsement.result(), Err(EndorsementError::EntrySignature));
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
}
