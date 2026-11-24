//! The release proofs (protocol.md section 9): the public build proof of a measurement, and
//! its verification.
//!
//! Release proofs show that a measurement is the one of an enclave image file that the build
//! workflow of the public repository built from the commit of a public tag. They are
//! `{"statement": b64u(release statement), "attestation": Sigstore bundle}`: the release
//! statement names the release, its commit and its measurement, and the bundle is the
//! attestation of that statement by the job that built the release. The bundle holds the
//! certificate the certificate authority of Sigstore (Fulcio) issued to the workflow run, the
//! signature of the key of that certificate over the statement, and the entry of the
//! transparency log that records both.
//!
//! The proofs are public values: whoever carries them, the verdict is the one of
//! [`verify_release_proofs`]. The certificates of the certificate authority, the keys of the
//! transparency logs, the repository and the build workflows a verifier takes are arguments
//! ([`ProofTrust`]): the node program passes the values that are compiled into it. Nothing
//! here sends a request or reads a clock: the time a certificate is valid at is the time the
//! log states for the entry.
//!
//! The secure program of the app makes the same verdict (`proveRelease` of
//! `secure-program/secure-program.js`). Where a value could be read in more than one way, it
//! is refused: release proofs that hold and are refused keep a release from receiving
//! delegations, and release proofs that do not hold and are accepted hand user keys to an
//! enclave nobody can read the source of.

use std::fmt;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rustls_pki_types::{CertificateDer, UnixTime};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use webpki::{anchor_from_trusted_cert, EndEntityCert};

use crate::attestation::AnyKeyPurpose;
use crate::certificate::Certificate;
use crate::encoding::b64u_decode;
use crate::limits;
use crate::release::{
    audit_root, hex, hex_bytes, is_sound_json, leaf_hash, pem_der, read_json, read_statement,
    ReleaseStatement, TransparencyLog,
};

/// The issuer of the tokens of GitHub Actions: the certificate of an attestation that a
/// workflow run of GitHub made names it.
pub const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The payload type of the envelope of an attestation.
const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// The predicate type of the in-toto statement of the attestation of a release statement.
const PREDICATE_TYPE: &str = "https://pickle.com/credential-enclave/release/v1";

/// The largest integer every reader of JSON holds exactly: 2^53 - 1. The times and the indexes
/// of an attestation are at most this.
const LARGEST_COUNT: u64 = 9_007_199_254_740_991;

/// The public repository whose tags are the releases, as the certificate of an attestation
/// names it: by its address and by the identifiers GitHub gave it and its owner. The
/// identifiers do not change and are not given to another repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repository {
    /// The address of the repository: `https://github.com/{owner}/{name}`.
    pub address: String,
    /// The identifier of the repository, in decimal.
    pub id: String,
    /// The identifier of the owner of the repository, in decimal.
    pub owner_id: String,
}

impl Repository {
    /// The repository of this source: `pickle-com/credential-enclave`.
    pub fn of_this_source() -> Repository {
        Repository {
            address: "https://github.com/pickle-com/credential-enclave".to_string(),
            id: "1400118248".to_string(),
            owner_id: "151645824".to_string(),
        }
    }
}

/// The identity of a build workflow: the path of its workflow file in the repository and the
/// commit of that file. The job of that file at that commit does what the file of that commit
/// states, whatever the commit of a tag holds.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Builder {
    workflow: String,
    commit: String,
}

impl Builder {
    /// The build workflow with the file `workflow` at the commit `commit`. `None` when
    /// `workflow` is empty or holds a character outside `!` to `~` or an `@`, and when
    /// `commit` is not 40 lower-case hexadecimal characters.
    pub fn new(workflow: &str, commit: &str) -> Option<Builder> {
        let path = !workflow.is_empty()
            && workflow
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'@');
        hex_bytes::<20>(commit)?;
        path.then(|| Builder {
            workflow: workflow.to_string(),
            commit: commit.to_string(),
        })
    }

    /// The path of the workflow file.
    pub fn workflow(&self) -> &str {
        &self.workflow
    }

    /// The commit of the workflow file.
    pub fn commit(&self) -> &str {
        &self.commit
    }
}

/// Reads a list of build workflows: a JSON array of
/// `{"workflow":"<path of the workflow file>","commit":"<40 hex>"}`. `None` when the list does
/// not have that form, when an element is not a build workflow by [`Builder::new`], and when
/// the list names one build workflow twice.
pub fn read_builders(list: &[u8]) -> Option<Vec<Builder>> {
    let stated: Vec<Builder> = serde_json::from_slice(list).ok()?;
    let mut builders: Vec<Builder> = Vec::with_capacity(stated.len());
    for builder in stated {
        let builder = Builder::new(&builder.workflow, &builder.commit)?;
        if builders.contains(&builder) {
            return None;
        }
        builders.push(builder);
    }
    Some(builders)
}

/// Why values are not what release proofs are verified with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrustError {
    /// The two certificates are not the root certificate and the intermediate certificate of
    /// a certificate authority, or the transparency logs are none or one log twice.
    Certificates,
    /// The key of a transparency log is not an ECDSA P-256 public key.
    LogKey,
    /// The list of build workflows is malformed or names one build workflow twice.
    Builders,
}

impl fmt::Display for TrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            TrustError::Certificates => {
                "the certificates of the certificate authority are not the root certificate and the intermediate certificate it issued, or the transparency logs are none or one log twice"
            }
            TrustError::LogKey => "a transparency log key is not an ECDSA P-256 public key",
            TrustError::Builders => {
                "the list of build workflows is malformed or names a build workflow twice"
            }
        })
    }
}

impl std::error::Error for TrustError {}

/// What release proofs are verified with.
#[derive(Clone, Debug)]
pub struct ProofTrust {
    /// The root certificate of the certificate authority, and its DER.
    root: Certificate,
    root_der: Vec<u8>,
    /// The intermediate certificate of the certificate authority, and its DER.
    intermediate: Certificate,
    intermediate_der: Vec<u8>,
    /// The transparency logs whose entries count.
    logs: Vec<TransparencyLog>,
    /// The repository whose tags are the releases.
    repository: Repository,
    /// The build workflows whose attestations count.
    builders: Vec<Builder>,
}

impl ProofTrust {
    /// What release proofs of the releases of `repository` are verified with: the root
    /// certificate and the intermediate certificate of the certificate authority (DER), the
    /// transparency logs and the build workflows.
    ///
    /// `None` when one of the two certificates is not a certificate [`Certificate::read`]
    /// reads or not the certificate of a certificate authority, when the root did not issue
    /// the intermediate, when the root is no trust anchor of an X.509 path, when there is no
    /// log, and when two logs have one identifier. The list of build workflows may be empty:
    /// no release proofs hold then.
    pub fn new(
        root_der: &[u8],
        intermediate_der: &[u8],
        logs: Vec<TransparencyLog>,
        repository: Repository,
        builders: Vec<Builder>,
    ) -> Option<ProofTrust> {
        let root = Certificate::read(root_der)?;
        let intermediate = Certificate::read(intermediate_der)?;
        if !root.is_authority() || !intermediate.is_authority() || !intermediate.is_issued_by(&root)
        {
            return None;
        }
        anchor_from_trusted_cert(&CertificateDer::from(root_der)).ok()?;
        let distinct = logs.iter().enumerate().all(|(index, log)| {
            logs.iter()
                .skip(index + 1)
                .all(|other| other.id() != log.id())
        });
        if logs.is_empty() || !distinct {
            return None;
        }
        Some(ProofTrust {
            root,
            root_der: root_der.to_vec(),
            intermediate,
            intermediate_der: intermediate_der.to_vec(),
            logs,
            repository,
            builders,
        })
    }

    /// Reads what release proofs are verified with from the files a program compiles in: the
    /// root certificate and the intermediate certificate of the certificate authority (PEM
    /// `CERTIFICATE`), the keys of the transparency logs (PEM `PUBLIC KEY`, ECDSA P-256) and
    /// the list of build workflows (JSON, [`read_builders`]), for the releases of
    /// `repository`. The rules are those of [`ProofTrust::new`].
    pub fn read(
        root_pem: &str,
        intermediate_pem: &str,
        log_keys_pem: &[&str],
        repository: Repository,
        builders: &[u8],
    ) -> Result<ProofTrust, TrustError> {
        let root = pem_der(root_pem, "CERTIFICATE").ok_or(TrustError::Certificates)?;
        let intermediate =
            pem_der(intermediate_pem, "CERTIFICATE").ok_or(TrustError::Certificates)?;
        let logs = log_keys_pem
            .iter()
            .map(|pem| {
                pem_der(pem, "PUBLIC KEY")
                    .and_then(|der| TransparencyLog::rekor_v1(&der))
                    .ok_or(TrustError::LogKey)
            })
            .collect::<Result<Vec<TransparencyLog>, TrustError>>()?;
        let builders = read_builders(builders).ok_or(TrustError::Builders)?;
        ProofTrust::new(&root, &intermediate, logs, repository, builders)
            .ok_or(TrustError::Certificates)
    }

    /// The transparency logs whose entries count.
    pub fn logs(&self) -> &[TransparencyLog] {
        &self.logs
    }

    /// The build workflows whose attestations count.
    pub fn builders(&self) -> &[Builder] {
        &self.builders
    }

    /// The repository whose tags are the releases.
    pub fn repository(&self) -> &Repository {
        &self.repository
    }
}

/// Why release proofs were not accepted. A node answers every one of them with
/// `peer_unverified`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProofError {
    /// The value is no release proofs: it is not a JSON object with a text `statement` and
    /// an object `attestation`, or it holds more than 32 arrays and objects inside one
    /// another.
    Form,
    /// V1: `statement` is not the base64url of a release statement.
    Statement,
    /// V1: the measurement of the statement is not the measurement asked for.
    Measurement,
    /// V2: `attestation` is not an object with one certificate, one envelope with one
    /// signature and one log entry.
    Bundle,
    /// V2: `attestation` is longer than 65,536 bytes as JSON without white space.
    BundleSize,
    /// V2: the envelope does not hold an in-toto statement.
    Payload,
    /// V3: the certificate of the bundle is not read.
    Certificate,
    /// V3: a certificate of the chain is not valid at the time of the entry of the log.
    CertificateValidity,
    /// V3: the certificate of the bundle is the certificate of a certificate authority.
    CertificateAuthority,
    /// V3: the intermediate certificate did not issue the certificate of the bundle.
    CertificateIssuer,
    /// V3: the X.509 path from the certificate of the bundle over the intermediate certificate
    /// to the root certificate does not validate.
    CertificatePath,
    /// V6: the certificate does not state the value asked for in its extension
    /// `1.3.6.1.4.1.57264.1.{number}`.
    Identity(u8),
    /// V5: the signature of the envelope is not the signature of the key of the certificate.
    Signature,
    /// V4: the entry of the log states no time.
    LogEntryTime,
    /// V4: the entry is of no transparency log of the verifier.
    Log,
    /// V4: the body of the entry is not the record of this envelope and this certificate.
    LogEntry,
    /// V4: the signed entry timestamp is not the signature of the log over this entry.
    SignedEntryTimestamp,
    /// V4: the audit path does not lead from this entry to the root hash of the proof.
    InclusionProof,
    /// V4: the checkpoint is not the note of that tree head that the log signed.
    Checkpoint,
    /// V7: the predicate of the in-toto statement is not the release statement.
    Predicate,
}

impl ProofError {
    /// The number of the check of protocol.md section 9 that failed, 1 to 7, and 0 for a value
    /// that is no release proofs.
    pub fn check(&self) -> u8 {
        match self {
            ProofError::Form => 0,
            ProofError::Statement | ProofError::Measurement => 1,
            ProofError::Bundle | ProofError::BundleSize | ProofError::Payload => 2,
            ProofError::Certificate
            | ProofError::CertificateValidity
            | ProofError::CertificateAuthority
            | ProofError::CertificateIssuer
            | ProofError::CertificatePath => 3,
            ProofError::LogEntryTime
            | ProofError::Log
            | ProofError::LogEntry
            | ProofError::SignedEntryTimestamp
            | ProofError::InclusionProof
            | ProofError::Checkpoint => 4,
            ProofError::Signature => 5,
            ProofError::Identity(_) => 6,
            ProofError::Predicate => 7,
        }
    }
}

impl fmt::Display for ProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            ProofError::Form => {
                "the value is not a JSON object of a statement and an attestation, of at most 32 levels"
            }
            ProofError::Statement => "the statement is not a release statement",
            ProofError::Measurement => {
                "the measurement of the statement is not the measurement asked for"
            }
            ProofError::Bundle => {
                "the attestation does not hold one certificate, one envelope with one signature and one log entry"
            }
            ProofError::BundleSize => "the attestation is longer than 65,536 bytes",
            ProofError::Payload => "the envelope does not hold an in-toto statement",
            ProofError::Certificate => "the certificate is not read",
            ProofError::CertificateValidity => {
                "a certificate of the chain is not valid at the time of the log entry"
            }
            ProofError::CertificateAuthority => {
                "the certificate is the certificate of a certificate authority"
            }
            ProofError::CertificateIssuer => {
                "the intermediate certificate did not issue the certificate"
            }
            ProofError::CertificatePath => {
                "the path from the certificate to the root certificate does not validate"
            }
            ProofError::Identity(number) => {
                return write!(
                    formatter,
                    "the certificate does not state the value asked for in its extension 1.3.6.1.4.1.57264.1.{number}"
                );
            }
            ProofError::Signature => {
                "the signature of the envelope is not the signature of the key of the certificate"
            }
            ProofError::LogEntryTime => "the log entry states no time",
            ProofError::Log => "the log entry is of no transparency log of the verifier",
            ProofError::LogEntry => {
                "the log entry is not the record of this envelope and this certificate"
            }
            ProofError::SignedEntryTimestamp => {
                "the signed entry timestamp is not the signature of the log over this entry"
            }
            ProofError::InclusionProof => {
                "the audit path does not lead from the entry to the root hash of its proof"
            }
            ProofError::Checkpoint => "the checkpoint is not the note of that tree head that the log signed",
            ProofError::Predicate => "the predicate of the attestation is not the release statement",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for ProofError {}

/// The member `key` of a JSON object. `None` when `value` is not an object or has no such
/// member.
fn member<'a>(value: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    value?.as_object()?.get(key)
}

/// The text of the member `key` of a JSON object.
fn text<'a>(value: Option<&'a Value>, key: &str) -> Option<&'a str> {
    member(value, key)?.as_str()
}

/// The bytes of the member `key` of a JSON object, a text of standard base64 with its
/// padding.
fn bytes(value: Option<&Value>, key: &str) -> Option<Vec<u8>> {
    STANDARD.decode(text(value, key)?).ok()
}

/// A count of an attestation: a non-negative integer of at most 2^53 - 1, as a JSON number
/// or as a text of decimal digits without a leading zero (a lone `0` is one). The bundle of
/// an attestation writes its times and indexes as such texts.
///
/// A JSON number counts by its value: `5.0` and `5e0` are 5, as for every reader that holds a
/// JSON number as a double. The zero with a sign, a fraction and a negative number are no
/// count.
fn count(value: Option<&Value>) -> Option<u64> {
    let number = match value? {
        Value::String(text) => {
            let digits = text.as_bytes();
            let plain = (1..=16).contains(&digits.len())
                && digits.iter().all(u8::is_ascii_digit)
                && (digits.len() == 1 || digits.first() != Some(&b'0'));
            if !plain {
                return None;
            }
            text.parse::<u64>().ok()?
        }
        Value::Number(number) => match (number.as_u64(), number.as_f64()) {
            (Some(count), _) => count,
            (None, Some(float))
                if float >= 0.0
                    && !float.is_sign_negative()
                    && float.fract() == 0.0
                    && float <= LARGEST_COUNT as f64 =>
            {
                float as u64
            }
            _ => return None,
        },
        _ => return None,
    };
    (number <= LARGEST_COUNT).then_some(number)
}

/// The length of the text ECMAScript writes for a number (Number::toString): the shortest
/// decimal digits that name the double, without an exponent from 1e-6 up to 1e21 and with one
/// outside.
fn number_text_bytes(number: &serde_json::Number) -> usize {
    // The double nearest to the number: what a reader that holds a JSON number as a double
    // makes of an integer beyond 2^53.
    let value = match (number.as_u64(), number.as_i64()) {
        (Some(unsigned), _) => unsigned as f64,
        (None, Some(signed)) => signed as f64,
        (None, None) => number.as_f64().unwrap_or(0.0),
    };
    if value == 0.0 {
        return 1;
    }
    let sign = usize::from(value < 0.0);
    // The digits and the exponent of the shortest form: `d.ddde-x`.
    let written = format!("{:e}", value.abs());
    let (mantissa, exponent) = written.split_once('e').unwrap_or((written.as_str(), "0"));
    let digits = mantissa.bytes().filter(u8::is_ascii_digit).count() as i64;
    let point = exponent.parse::<i64>().unwrap_or(0) + 1;
    let length = if digits <= point && point <= 21 {
        point
    } else if 0 < point && point <= 21 {
        digits + 1
    } else if -6 < point && point <= 0 {
        2 - point + digits
    } else {
        let exponent_digits = (point - 1).unsigned_abs().to_string().len() as i64;
        let mantissa = if digits == 1 { 1 } else { digits + 1 };
        mantissa + 2 + exponent_digits
    };
    sign + usize::try_from(length).unwrap_or(usize::MAX)
}

/// The length of a text as a string of JSON: the two quotation marks, two bytes for a
/// quotation mark, a backslash and the control characters with a short escape, six bytes for
/// every other control character, and the UTF-8 bytes of every other character.
fn string_text_bytes(text: &str) -> usize {
    2 + text
        .chars()
        .map(|character| match character {
            '"' | '\\' | '\u{08}' | '\u{0c}' | '\n' | '\r' | '\t' => 2,
            control if (control as u32) < 0x20 => 6,
            other => other.len_utf8(),
        })
        .sum::<usize>()
}

/// The length of a JSON value as JSON without white space, in bytes of UTF-8, a number
/// written as ECMAScript writes it: the length every reader of JSON agrees on.
fn compact_json_bytes(value: &Value) -> usize {
    match value {
        Value::Null | Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(number) => number_text_bytes(number),
        Value::String(text) => string_text_bytes(text),
        Value::Array(items) => {
            2 + items.len().saturating_sub(1) + items.iter().map(compact_json_bytes).sum::<usize>()
        }
        Value::Object(members) => {
            2 + members.len().saturating_sub(1)
                + members
                    .iter()
                    .map(|(key, item)| string_text_bytes(key) + 1 + compact_json_bytes(item))
                    .sum::<usize>()
        }
    }
}

/// The bytes the signature of a DSSE envelope covers (its pre-authentication encoding):
/// `DSSEv1`, a space, the length of the payload type, a space, the payload type, a space, the
/// length of the payload, a space and the payload.
fn pre_authentication(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut encoded = format!(
        "DSSEv1 {} {payload_type} {} ",
        payload_type.len(),
        payload.len()
    )
    .into_bytes();
    encoded.extend_from_slice(payload);
    encoded
}

/// V3, by the X.509 path validation the node program verifies the certificates of TLS and of
/// a Nitro attestation document with: the certificate `leaf_der` chains over the intermediate
/// certificate to the root certificate of `trust` at `time_s`. Every extended key usage is
/// accepted, and no revocation list is read.
fn path_validates(leaf_der: &[u8], trust: &ProofTrust, time_s: u64) -> bool {
    let root = CertificateDer::from(trust.root_der.as_slice());
    let Ok(anchor) = anchor_from_trusted_cert(&root) else {
        return false;
    };
    let leaf = CertificateDer::from(leaf_der);
    let Ok(leaf) = EndEntityCert::try_from(&leaf) else {
        return false;
    };
    let intermediates = [CertificateDer::from(trust.intermediate_der.as_slice())];
    leaf.verify_for_usage(
        &[
            webpki::ring::ECDSA_P256_SHA256,
            webpki::ring::ECDSA_P256_SHA384,
            webpki::ring::ECDSA_P384_SHA256,
            webpki::ring::ECDSA_P384_SHA384,
        ],
        &[anchor],
        &intermediates,
        UnixTime::since_unix_epoch(Duration::from_secs(time_s)),
        AnyKeyPurpose,
        None,
        None,
    )
    .is_ok()
}

/// V6: the certificate `leaf` states the identity of the job of a build workflow of `trust`
/// in a run that the push of the tag of the release of `stated` started at the commit of
/// `stated`, by the values of its extensions `1.3.6.1.4.1.57264.1.{number}`:
///
/// | Number | What it states | Value |
/// | --- | --- | --- |
/// | 8 | the issuer of the token the certificate was issued for | the issuer of GitHub Actions |
/// | 9 | the workflow of the job that signed | the address of the repository, `/`, the path of a build workflow, `@` and a ref that is not empty. The ref is what the calling workflow wrote and is not judged |
/// | 10 | the commit of the file of that workflow | the commit of that build workflow |
/// | 11 | the runner | `github-hosted` |
/// | 12 | the repository the run took place in | the address of the repository |
/// | 13 | the commit that started the run | the `git_commit` of the statement |
/// | 14 | the ref of the run | `refs/tags/` and the `release` of the statement |
/// | 15 | the identifier of that repository | the identifier of the repository |
/// | 17 | the identifier of the owner of that repository | the identifier of its owner |
/// | 20 | what started the run | `push` |
/// | 22 | the visibility of the repository when the certificate was issued | `public` |
///
/// The workflow that called the build workflow (the extension 18) is not judged: its file is
/// one of the commit of the tag.
fn identity(
    leaf: &Certificate,
    stated: &ReleaseStatement,
    trust: &ProofTrust,
) -> Result<(), ProofError> {
    let states = |number: u8, value: &str| {
        (leaf.fulcio_text(number) == Some(value))
            .then_some(())
            .ok_or(ProofError::Identity(number))
    };
    let repository = &trust.repository;
    states(8, GITHUB_ACTIONS_ISSUER)?;
    // The text before the last `@` of the extension 9 names the file of the workflow, and
    // the text behind it the ref the caller wrote, which is not empty.
    let signer = leaf
        .fulcio_text(9)
        .and_then(|signer| signer.rsplit_once('@'))
        .filter(|(_, reference)| !reference.is_empty())
        .map(|(file, _)| file);
    let of_file: Vec<&Builder> = trust
        .builders
        .iter()
        .filter(|builder| {
            signer == Some(format!("{}/{}", repository.address, builder.workflow).as_str())
        })
        .collect();
    if of_file.is_empty() {
        return Err(ProofError::Identity(9));
    }
    let commit = leaf.fulcio_text(10);
    if !of_file
        .iter()
        .any(|builder| commit == Some(builder.commit.as_str()))
    {
        return Err(ProofError::Identity(10));
    }
    states(11, "github-hosted")?;
    states(12, &repository.address)?;
    states(13, &stated.git_commit)?;
    states(14, &format!("refs/tags/{}", stated.release))?;
    states(15, &repository.id)?;
    states(17, &repository.owner_id)?;
    states(20, "push")?;
    states(22, "public")
}

/// V2 to V6: verifies the Sigstore bundle `attestation` as the attestation of the release
/// statement `stated` and returns the in-toto statement of its envelope.
fn attested_statement(
    attestation: &Value,
    stated: &ReleaseStatement,
    trust: &ProofTrust,
) -> Result<Value, ProofError> {
    // V2: the parts of the bundle.
    let attestation = Some(attestation);
    let material = member(attestation, "verificationMaterial");
    let envelope = member(attestation, "dsseEnvelope");
    let certificate_text = text(member(material, "certificate"), "rawBytes");
    let entries = member(material, "tlogEntries").and_then(Value::as_array);
    let signatures = member(envelope, "signatures").and_then(Value::as_array);
    let (
        Some(certificate_text),
        Some([entry]),
        Some(payload_text),
        Some(payload_type),
        Some([signature]),
    ) = (
        certificate_text,
        entries.map(Vec::as_slice),
        text(envelope, "payload"),
        text(envelope, "payloadType"),
        signatures.map(Vec::as_slice),
    )
    else {
        return Err(ProofError::Bundle);
    };
    let Some(signature_text) = text(Some(signature), "sig") else {
        return Err(ProofError::Bundle);
    };
    if !entry.is_object() {
        return Err(ProofError::Bundle);
    }
    if attestation.map_or(0, compact_json_bytes) > limits::RELEASE_ATTESTATION_BYTES {
        return Err(ProofError::BundleSize);
    }
    let entry = Some(entry);

    let payload = STANDARD
        .decode(payload_text)
        .map_err(|_| ProofError::Payload)?;
    let in_toto = read_json(&payload)
        .filter(Value::is_object)
        .ok_or(ProofError::Payload)?;
    if payload_type != PAYLOAD_TYPE {
        return Err(ProofError::Payload);
    }

    // V3: the certificate, at the time the log states for the entry.
    let integrated_time = count(member(entry, "integratedTime")).ok_or(ProofError::LogEntryTime)?;
    let leaf_der = STANDARD
        .decode(certificate_text)
        .map_err(|_| ProofError::Certificate)?;
    let leaf = Certificate::read(&leaf_der).ok_or(ProofError::Certificate)?;
    if [&leaf, &trust.intermediate, &trust.root]
        .iter()
        .any(|certificate| !certificate.is_valid_at(integrated_time))
    {
        return Err(ProofError::CertificateValidity);
    }
    if leaf.is_authority() {
        return Err(ProofError::CertificateAuthority);
    }
    if !leaf.is_issued_by(&trust.intermediate) {
        return Err(ProofError::CertificateIssuer);
    }
    if !path_validates(&leaf_der, trust, integrated_time) {
        return Err(ProofError::CertificatePath);
    }

    // V6
    identity(&leaf, stated, trust)?;

    // V5
    let signature = STANDARD
        .decode(signature_text)
        .map_err(|_| ProofError::Signature)?;
    if !leaf.signed_with_p256(&pre_authentication(payload_type, &payload), &signature) {
        return Err(ProofError::Signature);
    }

    // V4: the entry of the log.
    let log = bytes(member(entry, "logId"), "keyId")
        .and_then(|key_id| trust.logs.iter().find(|log| log.has_id(&key_id)))
        .ok_or(ProofError::Log)?;
    let body_text = text(entry, "canonicalizedBody").ok_or(ProofError::LogEntry)?;
    let body = STANDARD
        .decode(body_text)
        .map_err(|_| ProofError::LogEntry)?;
    let record = read_json(&body).ok_or(ProofError::LogEntry)?;
    let record = Some(&record);
    if text(record, "kind") != Some("dsse") || text(record, "apiVersion") != Some("0.0.1") {
        return Err(ProofError::LogEntry);
    }
    let spec = member(record, "spec");
    let payload_hash = member(spec, "payloadHash");
    if text(payload_hash, "algorithm") != Some("sha256")
        || text(payload_hash, "value") != Some(hex(&Sha256::digest(&payload)).as_str())
    {
        return Err(ProofError::LogEntry);
    }
    let logged = match member(spec, "signatures").and_then(Value::as_array) {
        Some(logged) => match logged.as_slice() {
            [logged] => Some(logged),
            _ => None,
        },
        None => None,
    };
    if bytes(logged, "signature").as_deref() != Some(signature.as_slice()) {
        return Err(ProofError::LogEntry);
    }
    let logged_certificate = bytes(logged, "verifier")
        .and_then(|verifier| String::from_utf8(verifier).ok())
        .and_then(|verifier| pem_der(&verifier, "CERTIFICATE"));
    if logged_certificate.as_deref() != Some(leaf_der.as_slice()) {
        return Err(ProofError::LogEntry);
    }
    let promised = count(member(entry, "logIndex"))
        .zip(bytes(
            member(entry, "inclusionPromise"),
            "signedEntryTimestamp",
        ))
        .is_some_and(|(log_index, timestamp)| {
            log.promised(body_text, integrated_time, log_index, &timestamp)
        });
    if !promised {
        return Err(ProofError::SignedEntryTimestamp);
    }
    let proof = member(entry, "inclusionProof");
    let root_hash = bytes(proof, "rootHash").and_then(|root| <[u8; 32]>::try_from(root).ok());
    let path = member(proof, "hashes")
        .and_then(Value::as_array)
        .filter(|hashes| hashes.len() <= limits::RELEASE_PROOF_HASHES)
        .and_then(|hashes| {
            hashes
                .iter()
                .map(|hash| {
                    let hash = STANDARD.decode(hash.as_str()?).ok()?;
                    <[u8; 32]>::try_from(hash).ok()
                })
                .collect::<Option<Vec<[u8; 32]>>>()
        });
    let (Some(leaf_index), Some(tree_size), Some(root_hash), Some(path)) = (
        count(member(proof, "logIndex")),
        count(member(proof, "treeSize")),
        root_hash,
        path,
    ) else {
        return Err(ProofError::InclusionProof);
    };
    if audit_root(leaf_hash(&body), leaf_index, tree_size, &path) != Some(root_hash) {
        return Err(ProofError::InclusionProof);
    }
    let signed = text(member(proof, "checkpoint"), "envelope")
        .is_some_and(|checkpoint| log.signed_tree_head(checkpoint, tree_size, &root_hash));
    if !signed {
        return Err(ProofError::Checkpoint);
    }
    Ok(in_toto)
}

/// Verifies release proofs for the measurement `measurement` (PCR0, PCR1 and PCR2) and returns
/// what their release statement states (protocol.md section 9). Every check must hold:
///
/// | Check | Rule | Failure |
/// | --- | --- | --- |
/// | V1 | `statement` is the base64url of a release statement by [`read_statement`], and its three PCRs are those of `measurement` | `Statement`, `Measurement` |
/// | V2 | `attestation` is at most 65,536 bytes as JSON without white space and holds one certificate, one envelope with one signature and one log entry. The payload type of the envelope is `application/vnd.in-toto+json` and its payload a JSON object | `Bundle`, `BundleSize`, `Payload` |
/// | V3 | the certificate of the bundle, the intermediate certificate and the root certificate of `trust` are valid at the time the log states for the entry. The certificate of the bundle is not one of a certificate authority, the intermediate certificate issued it, and the X.509 path from it over the intermediate certificate to the root certificate validates | `Certificate`, `CertificateValidity`, `CertificateAuthority`, `CertificateIssuer`, `CertificatePath` |
/// | V4 | the entry states its time and is of a transparency log of `trust`. Its body is the `dsse` record of version 0.0.1 of this payload, this signature and this certificate. Its signed entry timestamp is the signature of the log over the entry, its audit path leads from the entry to the root hash of the proof, and its checkpoint is the note of that tree head that the log signed | `LogEntryTime`, `Log`, `LogEntry`, `SignedEntryTimestamp`, `InclusionProof`, `Checkpoint` |
/// | V5 | the signature of the envelope is the ECDSA P-256 SHA-256 signature of the key of the certificate over the pre-authentication encoding of the payload | `Signature` |
/// | V6 | the certificate states the identity of the job of a build workflow of `trust`, in a run of the repository of `trust` that the push of the tag `release` of the statement started at the commit `git_commit` of the statement, on a runner GitHub hosts, while the repository was public | `Identity` |
/// | V7 | the in-toto statement of the envelope has the predicate type of a release statement, and its predicate states the `release`, the `git_commit` and the three PCRs of the statement | `Predicate` |
///
/// A value that is not a JSON object with a text `statement` (of at most twice 16,384 UTF-16
/// code units) and an object `attestation`, or that holds more than 32 arrays and objects
/// inside one another, is no release proofs (`Form`). The other members of the proofs, of the
/// statement and of the bundle are not read.
///
/// The measurement is the one of a verified attestation document, and the caller compares
/// the release this function returns with the release the binding of that document names.
pub fn verify_release_proofs(
    proofs: &Value,
    measurement: &[[u8; 48]; 3],
    trust: &ProofTrust,
) -> Result<ReleaseStatement, ProofError> {
    // The form. The text of a statement of 16,384 bytes is shorter than twice that number.
    let of_proofs = Some(proofs);
    let statement = text(of_proofs, "statement").filter(|statement| {
        statement.encode_utf16().count() <= 2 * limits::RELEASE_STATEMENT_BYTES
    });
    let attestation =
        member(of_proofs, "attestation").filter(|attestation| attestation.is_object());
    let (Some(statement), Some(attestation), true) =
        (statement, attestation, is_sound_json(proofs))
    else {
        return Err(ProofError::Form);
    };
    // V1
    let stated = b64u_decode(statement)
        .ok()
        .and_then(|statement| read_statement(&statement))
        .ok_or(ProofError::Statement)?;
    if stated.pcrs != *measurement {
        return Err(ProofError::Measurement);
    }
    // V2 to V6
    let in_toto = attested_statement(attestation, &stated, trust)?;
    // V7
    let in_toto = Some(&in_toto);
    let predicate = member(in_toto, "predicate");
    let [pcr0, pcr1, pcr2] = stated.pcrs.map(|pcr| hex(&pcr));
    let same = text(in_toto, "predicateType") == Some(PREDICATE_TYPE)
        && [
            ("release", stated.release.as_str()),
            ("git_commit", stated.git_commit.as_str()),
            ("pcr0", pcr0.as_str()),
            ("pcr1", pcr1.as_str()),
            ("pcr2", pcr2.as_str()),
        ]
        .into_iter()
        .all(|(name, value)| text(predicate, name) == Some(value));
    if !same {
        return Err(ProofError::Predicate);
    }
    Ok(stated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_count_is_a_non_negative_integer_below_2_to_the_53_as_a_number_or_as_digits() {
        let read = |text: &str| count(Some(&serde_json::from_str::<Value>(text).unwrap()));
        for (text, value) in [
            ("0", 0),
            ("7", 7),
            ("4083792535", 4_083_792_535),
            ("9007199254740991", LARGEST_COUNT),
            ("\"0\"", 0),
            ("\"7\"", 7),
            ("\"4083792535\"", 4_083_792_535),
            ("\"9007199254740991\"", LARGEST_COUNT),
            // A number counts by its value.
            ("5.0", 5),
            ("5e0", 5),
            ("0.5e1", 5),
            ("0.0", 0),
            ("1e3", 1000),
        ] {
            assert_eq!(read(text), Some(value), "{text}");
        }
        for text in [
            "-1",
            "-0",
            "-0.0",
            "0.5",
            "1.5",
            "9007199254740992",
            "9007199254740993",
            "18446744073709551615",
            "18446744073709551616",
            "1e16",
            "1e300",
            "\"\"",
            "\"00\"",
            "\"07\"",
            "\"-1\"",
            "\"+1\"",
            "\"1.0\"",
            "\"1e3\"",
            "\" 1\"",
            "\"1 \"",
            "\"9007199254740992\"",
            "\"9999999999999999\"",
            "\"10000000000000000\"",
            "\"１\"",
            "null",
            "true",
            "[1]",
            "{}",
        ] {
            assert_eq!(read(text), None, "{text}");
        }
        assert_eq!(count(None), None);
    }

    #[test]
    fn the_length_of_a_value_is_the_length_of_its_json_without_white_space() {
        let length = |text: &str| compact_json_bytes(&serde_json::from_str::<Value>(text).unwrap());
        // (the text, the text ECMAScript writes for its value)
        for (text, written) in [
            ("null", "null"),
            ("true", "true"),
            ("false", "false"),
            ("[]", "[]"),
            ("{}", "{}"),
            (" [ 1 , 2 ] ", "[1,2]"),
            (
                "{ \"a\" : [ ] , \"b\" : { \"c\" : null } }",
                r#"{"a":[],"b":{"c":null}}"#,
            ),
            ("\"\"", "\"\""),
            ("\"a/b\"", "\"a/b\""),
            (r#""a\"b\\c""#, r#""a\"b\\c""#),
            (r#""\b\f\n\r\t""#, r#""\b\f\n\r\t""#),
            (r#""\u0000\u001f""#, r#""\u0000\u001f""#),
            (r#""\u007f""#, "\"\u{7f}\""),
            (r#""é€""#, "\"é€\""),
            (r#""😀""#, "\"😀\""),
            ("\"\u{2028}\"", "\"\u{2028}\""),
            // A key an object states twice is one member: the last value stands.
            (r#"{"a":"long text","a":1}"#, r#"{"a":1}"#),
            // Numbers, as ECMAScript writes them.
            ("0", "0"),
            ("-0", "0"),
            ("0.0", "0"),
            ("7", "7"),
            ("-7", "-7"),
            ("4083792535", "4083792535"),
            ("9007199254740991", "9007199254740991"),
            ("9007199254740993", "9007199254740992"),
            ("18446744073709551615", "18446744073709552000"),
            ("-9223372036854775808", "-9223372036854776000"),
            ("123456789012345678901", "123456789012345680000"),
            ("1e21", "1e+21"),
            ("1e22", "1e+22"),
            ("1.5e300", "1.5e+300"),
            ("5.0", "5"),
            ("5e0", "5"),
            ("1e3", "1000"),
            ("1.5", "1.5"),
            ("-1.5", "-1.5"),
            ("123.456", "123.456"),
            ("0.1", "0.1"),
            ("0.000001", "0.000001"),
            ("0.0000001", "1e-7"),
            ("1.23e-18", "1.23e-18"),
            ("5e-324", "5e-324"),
            ("1.7976931348623157e308", "1.7976931348623157e+308"),
            ("100000000000000000000", "100000000000000000000"),
            ("1000000000000000000000", "1e+21"),
        ] {
            assert_eq!(length(text), written.len(), "{text}");
        }
    }

    #[test]
    fn a_list_of_build_workflows_names_files_and_commits() {
        let commit = "3f84e8368fcdf1f89e42ca629670bfe0989b6f13";
        let other = "4c21e0083064aec5300f6f8472a796607e83d9f3";
        let file = ".github/workflows/enclave-build.yml";
        let list = |value: Value| read_builders(value.to_string().as_bytes());
        assert_eq!(read_builders(b"[]"), Some(Vec::new()));
        let builders = list(json!([
            {"workflow": file, "commit": commit},
            {"workflow": file, "commit": other},
            {"workflow": ".github/workflows/other.yml", "commit": commit, "note": "not read"},
        ]))
        .unwrap();
        assert_eq!(builders.len(), 3);
        assert_eq!(
            (builders[0].workflow(), builders[0].commit()),
            (file, commit)
        );
        for refused in [
            json!({}),
            json!("text"),
            json!([file]),
            json!([{"workflow": file}]),
            json!([{"commit": commit}]),
            json!([{"workflow": 7, "commit": commit}]),
            json!([{"workflow": "", "commit": commit}]),
            json!([{"workflow": format!("{file}@main"), "commit": commit}]),
            json!([{"workflow": "a file.yml", "commit": commit}]),
            json!([{"workflow": "é.yml", "commit": commit}]),
            json!([{"workflow": file, "commit": &commit[1..]}]),
            json!([{"workflow": file, "commit": commit.to_uppercase()}]),
            json!([{"workflow": file, "commit": "main"}]),
            // One build workflow twice.
            json!([{"workflow": file, "commit": commit}, {"workflow": file, "commit": commit}]),
        ] {
            assert_eq!(list(refused.clone()), None, "{refused}");
        }
        for list in [&b""[..], b"[", b"[]x", b"not json"] {
            assert_eq!(read_builders(list), None);
        }
        assert!(Builder::new(file, commit).is_some());
        assert!(Builder::new(file, "").is_none());
    }

    #[test]
    fn the_signature_of_an_envelope_covers_its_pre_authentication_encoding() {
        assert_eq!(
            pre_authentication("application/vnd.in-toto+json", b"{\"a\":1}"),
            b"DSSEv1 28 application/vnd.in-toto+json 7 {\"a\":1}"
        );
        assert_eq!(pre_authentication("t", b""), b"DSSEv1 1 t 0 ");
    }

    /// The values the node program compiles in.
    fn source_trust() -> ProofTrust {
        ProofTrust::read(
            include_str!("../../enclave/release/fulcio-root.pem"),
            include_str!("../../enclave/release/fulcio-intermediate.pem"),
            &[include_str!("../../enclave/release/rekor-key.pem")],
            Repository::of_this_source(),
            include_bytes!("../../enclave/release/builders.json"),
        )
        .unwrap()
    }

    /// A certificate of a test: valid from 2026-09-01 to 2026-10-01 for a workflow run, and
    /// from 2026-01-01 to 2036-01-01 for a certificate authority.
    fn certificate(name: &str, authority: bool) -> rcgen::CertificateParams {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        if authority {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ];
            params.not_before = rcgen::date_time_ymd(2026, 1, 1);
            params.not_after = rcgen::date_time_ymd(2036, 1, 1);
        } else {
            params.is_ca = rcgen::IsCa::ExplicitNoCa;
            params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
            params.not_before = rcgen::date_time_ymd(2026, 9, 1);
            params.not_after = rcgen::date_time_ymd(2026, 10, 1);
        }
        params
    }

    #[test]
    fn the_certificate_of_a_published_release_chains_to_the_root_of_sigstore_at_its_time() {
        // The certificate Fulcio issued to the job that built release v2.4.0-rc.1, valid from
        // 2026-11-24T17:48:31Z for ten minutes.
        let leaf = include_bytes!("../tests/fixtures/fulcio-certificate-v2.4.0-rc.1.der");
        let trust = source_trust();
        assert!(path_validates(leaf, &trust, 1_795_542_511));
        assert!(path_validates(leaf, &trust, 1_795_543_111));
        assert!(!path_validates(leaf, &trust, 1_795_542_510));
        assert!(!path_validates(leaf, &trust, 1_795_543_112));
        // Bytes that are no certificate, and a changed certificate.
        assert!(!path_validates(b"certificate", &trust, 1_795_542_511));
        let mut changed = leaf.to_vec();
        changed[20] ^= 1;
        assert!(!path_validates(&changed, &trust, 1_795_542_511));
    }

    #[test]
    fn a_certificate_is_taken_by_its_reading_and_by_the_validation_of_its_path() {
        let key = |algorithm| rcgen::KeyPair::generate_for(algorithm).unwrap();
        let root_key = key(&rcgen::PKCS_ECDSA_P384_SHA384);
        let root = certificate("test root", true)
            .self_signed(&root_key)
            .unwrap();
        let intermediate_key = key(&rcgen::PKCS_ECDSA_P384_SHA384);
        let intermediate = certificate("test intermediate", true)
            .signed_by(&intermediate_key, &root, &root_key)
            .unwrap();
        let log = pem_der(
            include_str!("../../enclave/release/rekor-key.pem"),
            "PUBLIC KEY",
        )
        .and_then(|key| TransparencyLog::rekor_v1(&key))
        .unwrap();
        let trust = ProofTrust::new(
            root.der(),
            intermediate.der(),
            vec![log],
            Repository::of_this_source(),
            Vec::new(),
        )
        .unwrap();
        let read = |der: &[u8]| Certificate::read(der).unwrap();
        // 2026-09-15: inside the validity of the certificates of these workflow runs.
        let time_s = 1_789_430_400;
        let issued = |leaf: &rcgen::Certificate| {
            (
                read(leaf.der()).is_issued_by(&trust.intermediate),
                path_validates(leaf.der(), &trust, time_s),
            )
        };

        // A certificate the intermediate issued: both take it, inside its validity.
        let leaf_key = key(&rcgen::PKCS_ECDSA_P256_SHA256);
        let leaf = certificate("test run", false)
            .signed_by(&leaf_key, &intermediate, &intermediate_key)
            .unwrap();
        assert_eq!(issued(&leaf), (true, true));
        assert!(read(leaf.der()).is_valid_at(time_s));
        // 2026-09-01T00:00:00Z and 2026-10-01T00:00:00Z are the two ends of that validity.
        for (time_s, valid) in [
            (1_788_220_799, false),
            (1_788_220_800, true),
            (1_790_812_800, true),
            (1_790_812_801, false),
        ] {
            assert_eq!(read(leaf.der()).is_valid_at(time_s), valid, "{time_s}");
            assert_eq!(
                path_validates(leaf.der(), &trust, time_s),
                valid,
                "{time_s}"
            );
        }

        // A certificate the root issued: its path validates, and the intermediate did not
        // issue it. The reading refuses it.
        let direct = certificate("test run under the root", false)
            .signed_by(&leaf_key, &root, &root_key)
            .unwrap();
        assert_eq!(issued(&direct), (false, true));

        // A certificate with a critical extension no verifier knows: the intermediate issued
        // it, and its path does not validate. The validation refuses it.
        let mut marked = certificate("test run with a mark", false);
        let mut mark =
            rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 57264, 99], vec![5, 0]);
        mark.set_criticality(true);
        marked.custom_extensions.push(mark);
        let marked = marked
            .signed_by(&leaf_key, &intermediate, &intermediate_key)
            .unwrap();
        assert_eq!(issued(&marked), (true, false));
        // The same extension without the mark of a critical one is not read by either.
        let mut plain = certificate("test run with an extension", false);
        plain
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 57264, 99],
                vec![5, 0],
            ));
        let plain = plain
            .signed_by(&leaf_key, &intermediate, &intermediate_key)
            .unwrap();
        assert_eq!(issued(&plain), (true, true));

        // A certificate of a certificate authority in the place of the one of a workflow run.
        let authority = certificate("test authority below", true)
            .signed_by(&leaf_key, &intermediate, &intermediate_key)
            .unwrap();
        assert!(read(authority.der()).is_authority());
        assert!(!path_validates(authority.der(), &trust, time_s));

        // A certificate of another authority of the same names.
        let other_key = key(&rcgen::PKCS_ECDSA_P384_SHA384);
        let other = certificate("test intermediate", true)
            .signed_by(&other_key, &root, &root_key)
            .unwrap();
        let foreign = certificate("test run", false)
            .signed_by(&leaf_key, &other, &other_key)
            .unwrap();
        assert_eq!(issued(&foreign), (false, false));

        // What is no trust: the two certificates in the place of each other, an intermediate
        // of another root, a certificate of a workflow run as the intermediate, no log, and
        // one log twice.
        let log = || trust.logs.clone();
        let stranger_key = key(&rcgen::PKCS_ECDSA_P384_SHA384);
        let stranger = certificate("test root", true)
            .self_signed(&stranger_key)
            .unwrap();
        let trust_of = |root: &[u8], intermediate: &[u8], logs: Vec<TransparencyLog>| {
            ProofTrust::new(
                root,
                intermediate,
                logs,
                Repository::of_this_source(),
                Vec::new(),
            )
        };
        assert!(trust_of(root.der(), intermediate.der(), log()).is_some());
        assert!(trust_of(intermediate.der(), root.der(), log()).is_none());
        assert!(trust_of(stranger.der(), intermediate.der(), log()).is_none());
        assert!(trust_of(root.der(), leaf.der(), log()).is_none());
        assert!(trust_of(root.der(), b"certificate", log()).is_none());
        assert!(trust_of(root.der(), intermediate.der(), Vec::new()).is_none());
        assert!(trust_of(root.der(), intermediate.der(), [log(), log()].concat()).is_none());
    }

    #[test]
    fn the_failures_name_the_check_of_their_rule() {
        for (failure, check) in [
            (ProofError::Form, 0),
            (ProofError::Statement, 1),
            (ProofError::Measurement, 1),
            (ProofError::Bundle, 2),
            (ProofError::BundleSize, 2),
            (ProofError::Payload, 2),
            (ProofError::Certificate, 3),
            (ProofError::CertificateValidity, 3),
            (ProofError::CertificateAuthority, 3),
            (ProofError::CertificateIssuer, 3),
            (ProofError::CertificatePath, 3),
            (ProofError::LogEntryTime, 4),
            (ProofError::Log, 4),
            (ProofError::LogEntry, 4),
            (ProofError::SignedEntryTimestamp, 4),
            (ProofError::InclusionProof, 4),
            (ProofError::Checkpoint, 4),
            (ProofError::Signature, 5),
            (ProofError::Identity(9), 6),
            (ProofError::Predicate, 7),
        ] {
            assert_eq!(failure.check(), check, "{failure}");
            assert!(!failure.to_string().is_empty());
        }
        assert!(ProofError::Identity(14).to_string().ends_with("57264.1.14"));
    }
}
