//! The subcommand `program`: verifies the release proof of the secure program (docs/protocol.md,
//! "The secure program release"). The checks are the ten steps an app runs before it loads a
//! served program, with the same failure codes, so the tool shows a reader what the apps accept.
//!
//! The cryptography is what the tool already carries for the attestation check: the `ring`
//! provider of rustls verifies the ECDSA P-256 SHA-256 signatures, and the protocol crate reads
//! PEM keys and hashes with SHA-256. Nothing is added to `Cargo.lock`, so the measured node
//! program is untouched.

use credential_enclave_protocol::encoding::b64u_decode;
use credential_enclave_protocol::release::{is_p256_public_key, log_id, public_key_der};
use rustls::pki_types::alg_id;
use serde_json::Value;

use crate::arguments::hex_decode;
use crate::render::{EXIT_FAILED, EXIT_PASSED};
use crate::End;

/// The release key of the operator, compiled in: `enclave/release/release-key.pem`.
pub const RELEASE_KEY_PEM: &str = include_str!("../../enclave/release/release-key.pem");
/// The key of the transparency log, compiled in: `enclave/release/rekor-key.pem`.
pub const LOG_KEY_PEM: &str = include_str!("../../enclave/release/rekor-key.pem");

/// The kind, the tag prefix and the size limit of a release statement.
pub const STATEMENT_KIND: &str = "secure-program";
pub const RELEASE_TAG_PREFIX: &str = "secure-program-v";
pub const STATEMENT_BYTES: usize = 16_384;

/// The arguments of `program`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramArguments {
    /// `--source`: the program file.
    pub source: String,
    /// `--release`: the release proof file (`secure-program.release.json`).
    pub release: String,
    /// `--release-key`: a PEM file in place of the compiled-in release key.
    pub release_key: Option<String>,
    /// `--log-key`: PEM files in place of the compiled-in log key table.
    pub log_keys: Vec<String>,
}

/// The ten steps of the verification, in order; the first one that fails ends the verification.
/// The text of each code is what the apps log and what the backend assembly reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    ProofShape,
    StatementShape,
    SourceHash,
    VersionMismatch,
    UnknownLog,
    EntryShape,
    ReleaseSignature,
    LogSignature,
    InclusionProof,
    Checkpoint,
}

impl Failure {
    pub fn code(self) -> &'static str {
        match self {
            Failure::ProofShape => "proof_shape",
            Failure::StatementShape => "statement_shape",
            Failure::SourceHash => "source_hash",
            Failure::VersionMismatch => "version_mismatch",
            Failure::UnknownLog => "unknown_log",
            Failure::EntryShape => "entry_shape",
            Failure::ReleaseSignature => "release_signature",
            Failure::LogSignature => "log_signature",
            Failure::InclusionProof => "inclusion_proof",
            Failure::Checkpoint => "checkpoint",
        }
    }
}

/// A failed step and what was found.
pub type Refusal = (Failure, String);

/// The fields of a release statement the verification reads (step 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub release: String,
    pub version: u64,
    pub sha256: String,
    pub git_commit: String,
}

/// The outcome of a verification that passed: the statement and the global index of the entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub statement: Statement,
    pub log_index: u64,
}

/// A log key: the log identifier and the DER of the key.
pub type LogKey = (String, Vec<u8>);

/// Runs the subcommand: reads the files and the keys, verifies, and renders the result.
pub fn run(arguments: &ProgramArguments) -> End {
    let read = |path: &str| std::fs::read(path).map_err(|error| format!("{path}: {error}"));
    let source = match read(&arguments.source) {
        Ok(bytes) => bytes,
        Err(message) => return End::no_result(&message),
    };
    let proof: Value = match read(&arguments.release).and_then(|bytes| {
        serde_json::from_slice(&bytes).map_err(|_| format!("{}: not JSON", arguments.release))
    }) {
        Ok(value) => value,
        Err(message) => return End::no_result(&message),
    };
    let release_key = match &arguments.release_key {
        None => match public_key_der(RELEASE_KEY_PEM) {
            Some(der) => der,
            None => return End::no_result("the compiled-in release key is not a PEM public key"),
        },
        Some(path) => match read(path).map(|bytes| String::from_utf8_lossy(&bytes).into_owned()) {
            Ok(pem) => match public_key_der(&pem) {
                Some(der) => der,
                None => return End::no_result(&format!("{path}: not a PEM public key")),
            },
            Err(message) => return End::no_result(&message),
        },
    };
    let mut log_keys = Vec::new();
    if arguments.log_keys.is_empty() {
        match public_key_der(LOG_KEY_PEM) {
            Some(der) => log_keys.push((log_id(&der), der)),
            None => return End::no_result("the compiled-in log key is not a PEM public key"),
        }
    }
    for path in &arguments.log_keys {
        let pem = match read(path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(message) => return End::no_result(&message),
        };
        match public_key_der(&pem) {
            Some(der) => log_keys.push((log_id(&der), der)),
            None => return End::no_result(&format!("{path}: not a PEM public key")),
        }
    }
    match verify_release_proof(
        &source,
        declared_version(&source),
        &proof,
        &release_key,
        &log_keys,
    ) {
        Ok(verified) => End {
            status: EXIT_PASSED,
            output: format!(
                "program release {}: version {}, sha256 {}, log index {}: ok\n",
                verified.statement.release,
                verified.statement.version,
                verified.statement.sha256,
                verified.log_index
            ),
            error: String::new(),
        },
        Err((failure, detail)) => End {
            status: EXIT_FAILED,
            output: format!("program release: failed: {}: {detail}\n", failure.code()),
            error: String::new(),
        },
    }
}

/// The version the program declares: the `const VERSION = N;` line (the first one), 0 when absent.
pub fn declared_version(source: &[u8]) -> u64 {
    let text = String::from_utf8_lossy(source);
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("const VERSION = ") {
            if let Some(digits) = rest.strip_suffix(';') {
                if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
                    return digits.parse().unwrap_or(0);
                }
            }
        }
    }
    0
}

/// Steps 1 to 10 (docs/protocol.md, "The secure program release").
pub fn verify_release_proof(
    source: &[u8],
    declared_version: u64,
    proof: &Value,
    release_key_der: &[u8],
    log_keys: &[LogKey],
) -> Result<Verified, Refusal> {
    // 1
    let object = proof.as_object().ok_or_else(|| {
        (
            Failure::ProofShape,
            "the proof is not an object".to_string(),
        )
    })?;
    let statement_text = object
        .get("statement")
        .and_then(Value::as_str)
        .ok_or_else(|| (Failure::ProofShape, "statement is not a string".to_string()))?;
    let entry = object
        .get("entry")
        .filter(|value| value.is_object())
        .ok_or_else(|| (Failure::ProofShape, "entry is not an object".to_string()))?;
    // 2
    let statement_bytes = b64u_decode(statement_text).map_err(|_| {
        (
            Failure::StatementShape,
            "statement is not base64url".to_string(),
        )
    })?;
    let statement = parse_statement(&statement_bytes)?;
    // 3
    if sha256_hex(source) != statement.sha256 {
        return Err((
            Failure::SourceHash,
            "the source is not the subject of the statement".to_string(),
        ));
    }
    // 4
    if declared_version != statement.version {
        return Err((
            Failure::VersionMismatch,
            format!(
                "the source declares version {declared_version}, the statement {}",
                statement.version
            ),
        ));
    }
    let log_index = verify_log_entry(entry, &statement_bytes, release_key_der, log_keys)?;
    Ok(Verified {
        statement,
        log_index,
    })
}

/// Step 2: the statement is at most 16,384 bytes of UTF-8 JSON, an object whose kind is
/// `secure-program`, whose version is an integer below 2^31, whose sha256 is 64 lower-case hex
/// characters and whose release is `secure-program-v` followed by the version. Other keys are
/// not read.
pub fn parse_statement(bytes: &[u8]) -> Result<Statement, Refusal> {
    let shape = |detail: &str| (Failure::StatementShape, detail.to_string());
    if bytes.is_empty() || bytes.len() > STATEMENT_BYTES {
        return Err(shape(&format!("statement is {} bytes", bytes.len())));
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| shape("statement is not JSON"))?;
    let object = value
        .as_object()
        .ok_or_else(|| shape("statement is not an object"))?;
    if object.get("kind").and_then(Value::as_str) != Some(STATEMENT_KIND) {
        return Err(shape("kind is not secure-program"));
    }
    let version = object
        .get("version")
        .and_then(Value::as_u64)
        .filter(|version| *version < 1 << 31)
        .ok_or_else(|| shape("version is not an integer below 2^31"))?;
    let sha256 = object
        .get("sha256")
        .and_then(Value::as_str)
        .filter(|text| is_lower_hex(text, 64))
        .ok_or_else(|| shape("sha256 is not 64 lower-case hex characters"))?;
    let release = object.get("release").and_then(Value::as_str);
    if release != Some(format!("{RELEASE_TAG_PREFIX}{version}").as_str()) {
        return Err(shape(&format!(
            "release is not {RELEASE_TAG_PREFIX}{version}"
        )));
    }
    Ok(Statement {
        release: format!("{RELEASE_TAG_PREFIX}{version}"),
        version,
        sha256: sha256.to_string(),
        git_commit: object
            .get("git_commit")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    })
}

/// Steps 5 to 10: the log key, the form of the hashedrekord body and the release key, the
/// signature of the release key over the statement, the signed entry timestamp, the inclusion
/// proof and the checkpoint. Returns the global index of the entry.
pub fn verify_log_entry(
    entry: &Value,
    statement: &[u8],
    release_key_der: &[u8],
    log_keys: &[LogKey],
) -> Result<u64, Refusal> {
    // 5
    let log_id_text = entry.get("log_id").and_then(Value::as_str).unwrap_or("");
    let log_key = log_keys
        .iter()
        .find(|(id, _)| id == log_id_text)
        .map(|(_, der)| der.as_slice())
        .ok_or_else(|| {
            (
                Failure::UnknownLog,
                format!("log id {log_id_text:?} is not a pinned log"),
            )
        })?;
    // 6
    let shape = |detail: &str| (Failure::EntryShape, detail.to_string());
    let body_text = entry
        .get("body")
        .and_then(Value::as_str)
        .ok_or_else(|| shape("body is not a string"))?;
    let body_bytes =
        standard_base64_decode(body_text).ok_or_else(|| shape("body is not standard base64"))?;
    let body: Value =
        serde_json::from_slice(&body_bytes).map_err(|_| shape("body is not a JSON object"))?;
    let text = |path: &[&str]| {
        path.iter()
            .try_fold(&body, |value, key| value.get(key))
            .and_then(Value::as_str)
    };
    if !body.is_object()
        || text(&["apiVersion"]) != Some("0.0.1")
        || text(&["kind"]) != Some("hashedrekord")
        || text(&["spec", "data", "hash", "algorithm"]) != Some("sha256")
        || text(&["spec", "data", "hash", "value"]) != Some(sha256_hex(statement).as_str())
    {
        return Err(shape("body is not a hashedrekord 0.0.1 of the statement"));
    }
    let logged_key = text(&["spec", "signature", "publicKey", "content"])
        .and_then(standard_base64_decode)
        .and_then(|pem| public_key_der(&String::from_utf8_lossy(&pem)));
    if logged_key.as_deref() != Some(release_key_der) {
        return Err(shape("the public key of the body is not the release key"));
    }
    let signature_text = text(&["spec", "signature", "content"])
        .ok_or_else(|| shape("the signature of the body is incomplete"))?;
    let integrated_time = entry
        .get("integrated_time")
        .and_then(Value::as_u64)
        .ok_or_else(|| shape("integrated_time is not an integer"))?;
    let log_index = entry
        .get("log_index")
        .and_then(Value::as_u64)
        .ok_or_else(|| shape("log_index is not an integer"))?;
    // 7
    let release_signature = standard_base64_decode(signature_text).unwrap_or_default();
    if !p256_verifies(release_key_der, statement, &release_signature) {
        return Err((
            Failure::ReleaseSignature,
            "the release key did not sign the statement".to_string(),
        ));
    }
    // 8
    let signed_entry = format!(
        "{{\"body\":\"{body_text}\",\"integratedTime\":{integrated_time},\"logID\":\"{log_id_text}\",\"logIndex\":{log_index}}}"
    );
    let timestamp = entry
        .get("signed_entry_timestamp")
        .and_then(Value::as_str)
        .and_then(standard_base64_decode)
        .unwrap_or_default();
    if !p256_verifies(log_key, signed_entry.as_bytes(), &timestamp) {
        return Err((
            Failure::LogSignature,
            "the signed entry timestamp does not verify".to_string(),
        ));
    }
    // 9
    let inclusion = entry
        .get("inclusion_proof")
        .filter(|value| value.is_object())
        .ok_or_else(|| {
            (
                Failure::InclusionProof,
                "inclusion_proof is missing".to_string(),
            )
        })?;
    let leaf_index = inclusion.get("log_index").and_then(Value::as_u64);
    let tree_size = inclusion.get("tree_size").and_then(Value::as_u64);
    let root_hash = inclusion
        .get("root_hash")
        .and_then(Value::as_str)
        .filter(|text| is_lower_hex(text, 64));
    let hashes = inclusion
        .get("hashes")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    item.as_str()
                        .filter(|text| is_lower_hex(text, 64))
                        .and_then(hex_decode)
                })
                .collect::<Option<Vec<Vec<u8>>>>()
        });
    let (leaf_index, tree_size, root_hash, hashes) =
        match (leaf_index, tree_size, root_hash, hashes) {
            (Some(leaf_index), Some(tree_size), Some(root_hash), Some(Some(hashes)))
                if tree_size >= 1 =>
            {
                (leaf_index, tree_size, root_hash, hashes)
            }
            _ => {
                return Err((
                    Failure::InclusionProof,
                    "inclusion_proof has the wrong shape".to_string(),
                ))
            }
        };
    let mut leaf_input = vec![0u8];
    leaf_input.extend_from_slice(&body_bytes);
    let root = merkle_root(&sha256(&leaf_input), leaf_index, tree_size, &hashes);
    if root.as_deref().map(hex) != Some(root_hash.to_string()) {
        return Err((
            Failure::InclusionProof,
            "the inclusion proof does not reach root_hash".to_string(),
        ));
    }
    // 10
    let checkpoint = inclusion
        .get("checkpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| (Failure::Checkpoint, "checkpoint is missing".to_string()))?;
    let (note_text, signatures_text) = checkpoint.split_once("\n\n").ok_or_else(|| {
        (
            Failure::Checkpoint,
            "checkpoint has no signature block".to_string(),
        )
    })?;
    let lines: Vec<&str> = note_text.split('\n').collect();
    let root_bytes = hex_decode(root_hash).unwrap_or_default();
    if lines.len() < 3
        || lines[0].is_empty()
        || lines[1] != tree_size.to_string()
        || standard_base64_decode(lines[2]).as_deref() != Some(root_bytes.as_slice())
    {
        return Err((
            Failure::Checkpoint,
            "the checkpoint note is not of this tree head".to_string(),
        ));
    }
    let note = format!("{note_text}\n");
    let key_hint = &sha256(log_key)[..4];
    for line in signatures_text.split('\n') {
        let Some(rest) = line.strip_prefix("\u{2014} ") else {
            continue;
        };
        let Some((name, signature_text)) = rest.split_once(' ') else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let Some(raw) = standard_base64_decode(signature_text) else {
            continue;
        };
        if raw.len() <= 4 || raw[..4] != *key_hint {
            continue;
        }
        if p256_verifies(log_key, note.as_bytes(), &raw[4..]) {
            return Ok(log_index);
        }
    }
    Err((
        Failure::Checkpoint,
        "no checkpoint signature of the log key verifies".to_string(),
    ))
}

/// The path computation of RFC 6962 section 2.1.1. `None` when the path ends before the root.
pub fn merkle_root(
    leaf: &[u8],
    leaf_index: u64,
    tree_size: u64,
    path: &[Vec<u8>],
) -> Option<Vec<u8>> {
    let mut fn_ = leaf_index;
    let mut sn = tree_size - 1;
    let mut result = leaf.to_vec();
    for node in path {
        if sn == 0 {
            return None;
        }
        let mut input = vec![1u8];
        if fn_ % 2 == 1 || fn_ == sn {
            input.extend_from_slice(node);
            input.extend_from_slice(&result);
            result = sha256(&input);
            while !(fn_ % 2 == 1 || fn_ == 0) {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            input.extend_from_slice(&result);
            input.extend_from_slice(node);
            result = sha256(&input);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    (sn == 0).then_some(result)
}

/// True when `signature_der` is an ASN.1 DER ECDSA P-256 SHA-256 signature of the key
/// `spki_der` over `message`. The verification is the `ring` provider of rustls, which the tool
/// already carries for TLS.
pub fn p256_verifies(spki_der: &[u8], message: &[u8], signature_der: &[u8]) -> bool {
    if !is_p256_public_key(spki_der) {
        return false;
    }
    let point = &spki_der[spki_der.len() - 65..];
    let provider = rustls::crypto::ring::default_provider();
    provider
        .signature_verification_algorithms
        .all
        .iter()
        .find(|algorithm| {
            algorithm.public_key_alg_id() == alg_id::ECDSA_P256
                && algorithm.signature_alg_id() == alg_id::ECDSA_SHA256
        })
        .is_some_and(|algorithm| {
            algorithm
                .verify_signature(point, message, signature_der)
                .is_ok()
        })
}

/// SHA-256 of `bytes`: the protocol crate exposes it as the hex of a log identifier.
fn sha256(bytes: &[u8]) -> Vec<u8> {
    hex_decode(&log_id(bytes)).unwrap_or_default()
}

fn sha256_hex(bytes: &[u8]) -> String {
    log_id(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_lower_hex(text: &str, count: usize) -> bool {
    text.len() == count
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Decodes standard base64 (the alphabet `A-Z a-z 0-9 + / =`): the text is translated to the
/// url-safe alphabet without padding and decoded with the decoder of the protocol crate, which
/// rejects characters outside the alphabet and non-canonical trailing bits.
pub fn standard_base64_decode(text: &str) -> Option<Vec<u8>> {
    if !text
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return None;
    }
    let url_safe: String = text
        .trim_end_matches('=')
        .chars()
        .map(|character| match character {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    b64u_decode(&url_safe).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry of the real Rekor log at index 3267788759 (the endorsement of the enclave release
    /// v1.5.2), as `GET /api/v1/log/entries?logIndex=3267788759` returned it, and the statement of
    /// that endorsement (the bytes of the `measurements.json` of v1.5.2, base64url).
    const REKOR_ENTRY: &str = include_str!("../tests/fixtures/rekor-entry-3267788759.json");
    const STATEMENT_B64U: &str =
        include_str!("../tests/fixtures/endorsement-v1.5.2-statement.b64u");

    fn pinned_log_keys() -> Vec<LogKey> {
        let der = public_key_der(LOG_KEY_PEM).expect("the compiled-in log key is PEM");
        vec![(log_id(&der), der)]
    }

    /// The entry of the fixture in the form of a release proof entry.
    fn proof_entry() -> Value {
        let response: Value = serde_json::from_str(REKOR_ENTRY).expect("the fixture is JSON");
        let (_, entry) = response
            .as_object()
            .and_then(|map| map.iter().next())
            .expect("one entry");
        let inclusion = &entry["verification"]["inclusionProof"];
        serde_json::json!({
            "body": entry["body"],
            "integrated_time": entry["integratedTime"],
            "log_index": entry["logIndex"],
            "log_id": entry["logID"],
            "signed_entry_timestamp": entry["verification"]["signedEntryTimestamp"],
            "inclusion_proof": {
                "log_index": inclusion["logIndex"],
                "tree_size": inclusion["treeSize"],
                "root_hash": inclusion["rootHash"],
                "hashes": inclusion["hashes"],
                "checkpoint": inclusion["checkpoint"],
            },
        })
    }

    #[test]
    fn the_real_entry_verifies_with_the_pinned_keys() {
        let statement = b64u_decode(STATEMENT_B64U.trim()).expect("the statement is base64url");
        let release_key = public_key_der(RELEASE_KEY_PEM).expect("the release key is PEM");
        let entry = proof_entry();
        assert_eq!(
            verify_log_entry(&entry, &statement, &release_key, &pinned_log_keys()),
            Ok(3267788759)
        );
        // Another statement: the body is not of it.
        let other = verify_log_entry(&entry, b"{}\n", &release_key, &pinned_log_keys());
        assert_eq!(
            other.map_err(|(failure, _)| failure),
            Err(Failure::EntryShape)
        );
        // Another log: unknown.
        let unknown = verify_log_entry(&entry, &statement, &release_key, &[]);
        assert_eq!(
            unknown.map_err(|(failure, _)| failure),
            Err(Failure::UnknownLog)
        );
        // A changed root hash: the inclusion proof fails.
        let mut tampered = entry.clone();
        let root = tampered["inclusion_proof"]["root_hash"]
            .as_str()
            .unwrap()
            .to_string();
        let flipped = format!(
            "{}{}",
            &root[..63],
            if root.ends_with('0') { "1" } else { "0" }
        );
        tampered["inclusion_proof"]["root_hash"] = Value::String(flipped);
        let proof = verify_log_entry(&tampered, &statement, &release_key, &pinned_log_keys());
        assert_eq!(
            proof.map_err(|(failure, _)| failure),
            Err(Failure::InclusionProof)
        );
    }

    #[test]
    fn the_declared_version_is_the_version_line() {
        assert_eq!(
            declared_version(b"(function () {\n  const VERSION = 27;\n})();\n"),
            27
        );
        assert_eq!(
            declared_version(b"const VERSION = 2;\nconst VERSION = 3;\n"),
            2
        );
        assert_eq!(
            declared_version(b"// const VERSION = 1;\nconst VERSION = x;\n"),
            0
        );
        assert_eq!(declared_version(b""), 0);
    }

    #[test]
    fn the_statement_shape_is_checked() {
        let bytes = b"{\"kind\":\"secure-program\",\"release\":\"secure-program-v27\",\"version\":27,\"sha256\":\"ab\",\"git_commit\":\"\",\"repository\":\"r\",\"path\":\"p\"}\n";
        assert_eq!(
            parse_statement(bytes).map_err(|(failure, _)| failure),
            Err(Failure::StatementShape)
        );
        let good = format!(
            "{{\"kind\":\"secure-program\",\"release\":\"secure-program-v27\",\"version\":27,\"sha256\":\"{}\",\"git_commit\":\"{}\",\"repository\":\"pickle-com/credential-enclave\",\"path\":\"secure-program/secure-program.js\"}}\n",
            "a".repeat(64),
            "b".repeat(40)
        );
        let statement = parse_statement(good.as_bytes()).expect("a well-formed statement");
        assert_eq!(statement.version, 27);
        assert_eq!(statement.release, "secure-program-v27");
        assert_eq!(statement.git_commit, "b".repeat(40));
        let wrong_release = good.replace("secure-program-v27", "secure-program-v28");
        assert_eq!(
            parse_statement(wrong_release.as_bytes()).map_err(|(failure, _)| failure),
            Err(Failure::StatementShape)
        );
    }

    #[test]
    fn merkle_root_follows_rfc_6962() {
        // A tree of one leaf has the leaf as its root, and a path that is too long fails.
        let leaf = sha256(b"\x00leaf");
        assert_eq!(merkle_root(&leaf, 0, 1, &[]), Some(leaf.clone()));
        assert_eq!(merkle_root(&leaf, 0, 1, &[vec![0; 32]]), None);
        // A tree of two leaves: the root is SHA-256(0x01 || left || right).
        let right = sha256(b"\x00right");
        let mut input = vec![1u8];
        input.extend_from_slice(&leaf);
        input.extend_from_slice(&right);
        assert_eq!(
            merkle_root(&leaf, 0, 2, std::slice::from_ref(&right)),
            Some(sha256(&input))
        );
        assert_eq!(
            merkle_root(&right, 1, 2, std::slice::from_ref(&leaf)),
            Some(sha256(&input))
        );
    }
}
