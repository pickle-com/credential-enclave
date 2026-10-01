//! The checks on one node.
//!
//! Every check on an attestation document is the code of the protocol crate
//! (`protocol/src/attestation.rs`), which a node also runs when it verifies a peer. This
//! module decides nothing about the form of a document, its certificates or its signature. It
//! calls that code, compares the measurements it returns with the expected ones, and records
//! each check with its outcome.

use credential_enclave_protocol::attestation::{
    read_binding, read_local_document, verify_nitro_document, AttestationError, NodeBinding,
    AWS_NITRO_ROOT_G1,
};
use credential_enclave_protocol::encoding::b64u_decode;
use credential_enclave_protocol::keys::{node_id, LogStoreId};
use serde_json::Value;

use crate::arguments::{hex, Measurements};

/// Check: the entry of the response has the members the tool reads.
pub const ENTRY: &str = "response entry";
/// Check: the platform of the node has an attestation.
pub const ATTESTATION: &str = "attestation";
/// Check: the document has the form of an attestation document.
pub const FORM: &str = "document form";
/// Check: the certificate chain of the document leads to the trust root.
pub const CHAIN: &str = "certificate chain";
/// Check: the signature of the document verifies.
pub const SIGNATURE: &str = "signature";
/// Check: the document carries the nonce that was asked for.
pub const NONCE: &str = "nonce";
/// Check: the measurement is not that of a debug-mode enclave.
pub const PRODUCTION_MODE: &str = "production mode";
/// Checks: PCR0, PCR1 and PCR2 equal the expected values.
pub const PCR: [&str; 3] = ["pcr0", "pcr1", "pcr2"];
/// Check: the user data of the document is a binding.
pub const BINDING: &str = "binding";
/// Check: the signing key of the binding is the node the response names.
pub const NODE_KEY: &str = "node key";

/// How one check ended. The text says what the check established, why it failed, or why it
/// did not run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Pass(String),
    Fail(String),
    /// The check did not run: an earlier check failed, or there was nothing to compare with.
    NotRun(String),
}

/// One check on a node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub outcome: Outcome,
}

fn pass(name: &'static str, established: &str) -> Check {
    Check {
        name,
        outcome: Outcome::Pass(established.to_string()),
    }
}

fn fail(name: &'static str, reason: impl Into<String>) -> Check {
    Check {
        name,
        outcome: Outcome::Fail(reason.into()),
    }
}

fn not_run(name: &'static str, reason: &str) -> Check {
    Check {
        name,
        outcome: Outcome::NotRun(reason.to_string()),
    }
}

/// What the response says about a node outside its document. Nothing verifies these values:
/// the node is compared with the binding of the document, the rest is printed as it came.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claimed {
    pub node: String,
    pub release: Option<String>,
    pub platform: String,
}

/// What the document of a node states: a Nitro document whose certificate chain and signature
/// verified, or a local document, which is unsigned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stated {
    /// The time of the document in Unix epoch milliseconds: the time the Nitro Secure Module
    /// created it, or the system time of a node on the local platform.
    pub time_ms: u64,
    /// `module_id` of a Nitro document.
    pub module_id: Option<String>,
    /// PCR0, PCR1 and PCR2 of a Nitro document.
    pub pcrs: Option<[[u8; 48]; 3]>,
    /// The node identifier of the signing key of the binding, when the document carries one.
    pub node: Option<String>,
    /// The release of the binding, when the document carries one.
    pub release: Option<String>,
    /// The log store the binding names: the bucket the node writes its log entries to before
    /// it acts, and the region of that bucket. `None` when the binding names none, and when
    /// the document carries no binding.
    pub log_store: Option<LogStoreId>,
}

/// The checks on one node and what was read on the way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeReport {
    /// `None` for a stored document, and for an entry of the response that could not be read.
    pub claimed: Option<Claimed>,
    /// `None` when nothing the document states is known.
    pub stated: Option<Stated>,
    pub checks: Vec<Check>,
}

impl NodeReport {
    /// True when no check failed. A check that did not run is not a failure of its own: it
    /// either follows a check that failed, or it had nothing to compare with.
    pub fn passed(&self) -> bool {
        !self
            .checks
            .iter()
            .any(|check| matches!(check.outcome, Outcome::Fail(_)))
    }
}

/// The entries of the response of the attestation route: the array `nodes` of the response,
/// or the response itself when it is an array. A response without an entry is no result.
pub fn entries_of_response(body: &[u8]) -> Result<Vec<Value>, String> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| "the response is not JSON".to_string())?;
    let entries = match value {
        Value::Array(entries) => entries,
        Value::Object(mut members) => match members.remove("nodes") {
            Some(Value::Array(entries)) => entries,
            _ => return Err("the response has no array \"nodes\"".to_string()),
        },
        _ => return Err("the response is neither an object nor an array".to_string()),
    };
    if entries.is_empty() {
        return Err("the response lists no node: there is nothing to verify".to_string());
    }
    Ok(entries)
}

/// Evaluates one entry of the response:
/// `{"v":1,"platform":"nitro","document":"<base64url>","node":"<node id>","release":"..."}`.
pub fn evaluate_entry(
    entry: &Value,
    nonce: &[u8],
    expected: Option<&Measurements>,
    allow_local: bool,
) -> NodeReport {
    let (claimed, document) = match read_entry(entry) {
        Ok(read) => read,
        Err(reason) => {
            return NodeReport {
                claimed: None,
                stated: None,
                checks: vec![fail(ENTRY, reason)],
            }
        }
    };
    let (stated, checks) = match claimed.platform.as_str() {
        "nitro" => nitro(&document, nonce, expected, Some(&claimed.node)),
        "local" => local(&document, nonce, &claimed.node, allow_local),
        _ => (
            None,
            vec![fail(
                ATTESTATION,
                "the platform is neither nitro nor local: nothing verifies this node",
            )],
        ),
    };
    let mut all = vec![pass(
        ENTRY,
        "version 1 with a platform, a document and a node",
    )];
    all.extend(checks);
    NodeReport {
        claimed: Some(claimed),
        stated,
        checks: all,
    }
}

/// Evaluates one stored Nitro attestation document (raw CBOR bytes). There is no response
/// around it, so the node of its binding is compared with nothing.
pub fn evaluate_document(
    document: &[u8],
    nonce: &[u8],
    expected: Option<&Measurements>,
) -> NodeReport {
    let (stated, checks) = nitro(document, nonce, expected, None);
    NodeReport {
        claimed: None,
        stated,
        checks,
    }
}

fn read_entry(entry: &Value) -> Result<(Claimed, Vec<u8>), String> {
    let text = |name: &str| {
        entry
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("the entry has no text \"{name}\""))
    };
    if entry.get("v").and_then(Value::as_u64) != Some(1) {
        return Err("the entry is not of version 1 (\"v\":1)".to_string());
    }
    let platform = text("platform")?;
    let node = text("node")?;
    let document = b64u_decode(text("document")?)
        .map_err(|_| "\"document\" of the entry is not base64url without padding".to_string())?;
    let claimed = Claimed {
        node: node.to_string(),
        release: entry
            .get("release")
            .and_then(Value::as_str)
            .map(str::to_string),
        platform: platform.to_string(),
    };
    Ok((claimed, document))
}

/// The checks on a Nitro attestation document (protocol.md 4.3).
///
/// Steps 1 to 6 are `verify_nitro_document` with the pinned AWS Nitro Enclaves Root-G1 and the
/// nonce that was asked for. That function runs the steps in order and returns the first one
/// that failed, so the checks after it did not run. The certificate chain is validated at the
/// time of the document, not at the time of this machine: the nonce is what shows that the
/// document was made for this request.
///
/// Steps 7 and 8 are here: no PCR is all zero, PCR0, PCR1 and PCR2 equal the expected values,
/// the user data is a binding, and the signing key of the binding is `claimed_node`.
fn nitro(
    document: &[u8],
    nonce: &[u8],
    expected: Option<&Measurements>,
    claimed_node: Option<&str>,
) -> (Option<Stated>, Vec<Check>) {
    let verified = verify_nitro_document(document, AWS_NITRO_ROOT_G1, Some(nonce));
    let steps = [
        (
            FORM,
            AttestationError::Malformed,
            "a COSE_Sign1 structure with the ES384 header around an attestation payload",
        ),
        (
            CHAIN,
            AttestationError::Untrusted,
            "leads to the AWS Nitro Enclaves Root-G1 at the time of the document",
        ),
        (
            SIGNATURE,
            AttestationError::Forged,
            "verifies under the key of the certificate of the document",
        ),
        (
            NONCE,
            AttestationError::NonceMismatch,
            "the document carries the nonce that was asked for",
        ),
    ];
    // The step that failed. Without a wildcard: an error this tool does not know is not read
    // as a pass.
    let failed_step = match verified {
        Ok(_) => None,
        Err(AttestationError::Malformed) => Some(0),
        Err(AttestationError::Untrusted) => Some(1),
        Err(AttestationError::Forged) => Some(2),
        Err(AttestationError::NonceMismatch) => Some(3),
    };
    let mut checks = Vec::new();
    for (index, (name, error, established)) in steps.into_iter().enumerate() {
        checks.push(match failed_step {
            Some(failed) if failed == index => fail(name, error.to_string()),
            Some(failed) if failed < index => {
                not_run(name, "not evaluated: an earlier check failed")
            }
            _ => pass(name, established),
        });
    }

    // What a document states is known once its certificate chain and its signature verified.
    // A document with another nonce is still a statement of a Nitro Secure Module, so the
    // remaining checks are reported for it: the same verification without the nonce check
    // returns what it states.
    let document = match verified {
        Ok(document) => Some(document),
        Err(AttestationError::NonceMismatch) => {
            verify_nitro_document(document, AWS_NITRO_ROOT_G1, None).ok()
        }
        Err(_) => None,
    };
    let Some(document) = document else {
        let reason = "not evaluated: the document did not verify";
        checks.push(not_run(PRODUCTION_MODE, reason));
        checks.extend(PCR.map(|name| not_run(name, reason)));
        checks.push(not_run(BINDING, reason));
        if claimed_node.is_some() {
            checks.push(not_run(NODE_KEY, reason));
        }
        return (None, checks);
    };

    checks.push(if document.is_debug_mode() {
        fail(
            PRODUCTION_MODE,
            "PCR0, PCR1 or PCR2 is all zero: the measurement of a debug-mode enclave, whose \
             memory the parent instance can read",
        )
    } else {
        pass(PRODUCTION_MODE, "none of PCR0, PCR1 and PCR2 is all zero")
    });
    let pcrs = [document.pcr0, document.pcr1, document.pcr2];
    for (index, name) in PCR.into_iter().enumerate() {
        checks.push(match expected {
            None => not_run(name, "not compared: no expected value was given"),
            Some(expected) if expected.pcrs[index] == pcrs[index] => {
                pass(name, "equals the expected value")
            }
            Some(expected) => fail(
                name,
                format!("is not the expected value {}", hex(&expected.pcrs[index])),
            ),
        });
    }
    let binding = match document.user_data.as_deref() {
        None => Err("the document carries no user data"),
        Some(user_data) => {
            read_binding(user_data).map_err(|_| "the user data of the document is not a binding")
        }
    };
    checks.extend(binding_checks(&binding, claimed_node));

    let binding = binding.ok();
    let stated = Stated {
        time_ms: document.timestamp_ms,
        module_id: Some(document.module_id),
        pcrs: Some(pcrs),
        node: binding
            .as_ref()
            .map(|binding| node_id(&binding.sign_public)),
        log_store: binding.as_ref().and_then(|binding| binding.log.clone()),
        release: binding.map(|binding| binding.release),
    };
    (Some(stated), checks)
}

/// The checks on the document of a node on the local platform (protocol.md 4.2). The document
/// is unsigned: it is read, and no attestation verifies the node. Such a node is a failure
/// unless `allow_local` is set.
fn local(
    document: &[u8],
    nonce: &[u8],
    claimed_node: &str,
    allow_local: bool,
) -> (Option<Stated>, Vec<Check>) {
    let none = "none: no attestation verifies a node of the local platform";
    let mut checks = vec![if allow_local {
        not_run(ATTESTATION, &format!("{none} (accepted by --allow-local)"))
    } else {
        fail(ATTESTATION, none)
    }];
    let Ok(document) = read_local_document(document) else {
        let reason = "not evaluated: the document could not be read";
        checks.push(fail(FORM, "the document is not a local document"));
        checks.push(not_run(NONCE, reason));
        checks.push(not_run(BINDING, reason));
        checks.push(not_run(NODE_KEY, reason));
        return (None, checks);
    };
    checks.push(pass(FORM, "an unsigned local document"));
    checks.push(if document.nonce == nonce {
        pass(NONCE, "the document carries the nonce that was asked for")
    } else {
        fail(NONCE, AttestationError::NonceMismatch.to_string())
    });
    let binding =
        read_binding(&document.binding).map_err(|_| "the binding of the document is not a binding");
    checks.extend(binding_checks(&binding, Some(claimed_node)));

    let binding = binding.ok();
    let stated = Stated {
        time_ms: document.time_ms,
        module_id: None,
        pcrs: None,
        node: binding
            .as_ref()
            .map(|binding| node_id(&binding.sign_public)),
        log_store: binding.as_ref().and_then(|binding| binding.log.clone()),
        release: binding.map(|binding| binding.release),
    };
    (Some(stated), checks)
}

/// The check that the document carries a binding and, when the response names a node, the
/// check that the signing key of the binding is that node (`node` is the base64url form of
/// the 32 bytes of the signing public key).
fn binding_checks(binding: &Result<NodeBinding, &str>, claimed_node: Option<&str>) -> Vec<Check> {
    let mut checks = vec![match binding {
        Ok(_) => pass(BINDING, "a signing key, a sealing key and a release"),
        Err(reason) => fail(BINDING, *reason),
    }];
    if let Some(claimed_node) = claimed_node {
        checks.push(match binding {
            Ok(binding) if node_id(&binding.sign_public) == claimed_node => pass(
                NODE_KEY,
                "the signing key of the binding is the node of the response",
            ),
            Ok(_) => fail(
                NODE_KEY,
                "the signing key of the binding is not the node of the response",
            ),
            Err(_) => not_run(NODE_KEY, "not evaluated: there is no binding"),
        });
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arguments::hex_decode;
    use credential_enclave_protocol::attestation::read_unverified_nitro_document;
    use credential_enclave_protocol::encoding::b64u;
    use serde_json::json;

    /// The attestation document of a node of release v1.0.0 in a production-mode enclave, and
    /// the nonce it was requested with (see `tests/fixtures/README.md`).
    const RELEASE_DOCUMENT: &[u8] =
        include_bytes!("../tests/fixtures/nitro-attestation-alpha-prerelease.cbor");
    const RELEASE_NONCE: &[u8] =
        include_bytes!("../tests/fixtures/nitro-attestation-alpha-prerelease.cbor.nonce");
    const RELEASE_NODE: &str = "Vpgk3Ygj_gz6Sy-9R8y7wgparrJ8ZseizfJiB8ZLmRE";
    const RELEASE_SEAL: &str = "cEbNoWZTb6WqyPag8n54ID4bUEtXYamfPmsVlxReUBo";
    /// The `measurements.json` of the GitHub release v1.0.0.
    const RELEASE_MEASUREMENTS: &[u8] =
        include_bytes!("../tests/fixtures/measurements-prerelease.json");
    /// The attestation document of a diagnostic build in a production-mode enclave, with its
    /// nonce: a program with other measurements (see `protocol/tests/fixtures/README.md`).
    const OTHER_BUILD_DOCUMENT: &[u8] =
        include_bytes!("../../protocol/tests/fixtures/nitro-attestation-document-operational.cbor");
    const OTHER_BUILD_NONCE: &str =
        "ccaba542c08b40eece75fa9c337500d56d5670def7168bd932b358fe9552df4b";
    /// A document a debug-mode enclave received from its Nitro Secure Module at boot: the PCRs
    /// are all zero, user data and nonce are null.
    const DEBUG_BOOT_DOCUMENT: &[u8] =
        include_bytes!("../../protocol/tests/fixtures/nitro-attestation-document-boot.cbor");
    /// A document of a debug-mode enclave of another program, with a nonce and with user data
    /// that is not a binding.
    const DEBUG_DOCUMENT: &[u8] =
        include_bytes!("../../protocol/tests/fixtures/nitro-attestation-document.cbor");

    fn release_measurements() -> Measurements {
        Measurements::of_file("measurements.json", RELEASE_MEASUREMENTS).unwrap()
    }

    fn outcome<'a>(report: &'a NodeReport, name: &str) -> &'a Outcome {
        &report
            .checks
            .iter()
            .find(|check| check.name == name)
            .unwrap_or_else(|| panic!("no check {name}"))
            .outcome
    }

    fn names(report: &NodeReport) -> Vec<&'static str> {
        report.checks.iter().map(|check| check.name).collect()
    }

    /// The names of the checks that failed.
    fn failed(report: &NodeReport) -> Vec<&'static str> {
        report
            .checks
            .iter()
            .filter(|check| matches!(check.outcome, Outcome::Fail(_)))
            .map(|check| check.name)
            .collect()
    }

    /// The names of the checks that did not run.
    fn skipped(report: &NodeReport) -> Vec<&'static str> {
        report
            .checks
            .iter()
            .filter(|check| matches!(check.outcome, Outcome::NotRun(_)))
            .map(|check| check.name)
            .collect()
    }

    fn release_entry() -> Value {
        json!({
            "v": 1, "platform": "nitro", "document": b64u(RELEASE_DOCUMENT),
            "node": RELEASE_NODE, "release": "v1.0.0",
        })
    }

    #[test]
    fn the_document_of_the_release_passes_against_the_measurements_of_the_release() {
        let expected = release_measurements();
        let report = evaluate_document(RELEASE_DOCUMENT, RELEASE_NONCE, Some(&expected));
        assert!(report.passed());
        assert_eq!(
            names(&report),
            [
                FORM,
                CHAIN,
                SIGNATURE,
                NONCE,
                PRODUCTION_MODE,
                "pcr0",
                "pcr1",
                "pcr2",
                BINDING
            ]
        );
        assert!(report
            .checks
            .iter()
            .all(|check| matches!(check.outcome, Outcome::Pass(_))));
        assert_eq!(report.claimed, None);
        assert_eq!(
            report.stated,
            Some(Stated {
                time_ms: 1_790_828_790_930,
                module_id: Some("i-00e27c4213a488340-enc01a0f5b621ecd411".to_string()),
                pcrs: Some(expected.pcrs),
                node: Some(RELEASE_NODE.to_string()),
                release: Some("v1.0.0".to_string()),
                log_store: None,
            })
        );
    }

    #[test]
    fn the_entry_of_the_release_passes_and_its_node_is_the_key_of_the_binding() {
        let expected = release_measurements();
        let report = evaluate_entry(&release_entry(), RELEASE_NONCE, Some(&expected), false);
        assert!(report.passed());
        assert_eq!(
            names(&report),
            [
                ENTRY,
                FORM,
                CHAIN,
                SIGNATURE,
                NONCE,
                PRODUCTION_MODE,
                "pcr0",
                "pcr1",
                "pcr2",
                BINDING,
                NODE_KEY
            ]
        );
        assert_eq!(
            report.claimed,
            Some(Claimed {
                node: RELEASE_NODE.to_string(),
                release: Some("v1.0.0".to_string()),
                platform: "nitro".to_string(),
            })
        );
        assert_eq!(report.stated.unwrap().node.as_deref(), Some(RELEASE_NODE));

        // The response names another node than the key the document binds.
        let mut entry = release_entry();
        entry["node"] = json!("QkJRkEKP6EwK2iiQQnQaoqfydMV9RvHVsA3t2zJEkHo");
        let report = evaluate_entry(&entry, RELEASE_NONCE, Some(&expected), false);
        assert!(!report.passed());
        assert_eq!(failed(&report), [NODE_KEY]);
    }

    #[test]
    fn a_document_with_other_measurements_fails() {
        // A real document of another build: everything about the document verifies, and its
        // PCR0 and PCR2 are not those of the release. PCR1 (the kernel and the boot ramdisk)
        // is the same in both builds.
        let nonce = hex_decode(OTHER_BUILD_NONCE).unwrap();
        let expected = release_measurements();
        let report = evaluate_document(OTHER_BUILD_DOCUMENT, &nonce, Some(&expected));
        assert!(!report.passed());
        assert_eq!(failed(&report), ["pcr0", "pcr2"]);
        assert_eq!(skipped(&report), [""; 0]);
        assert_eq!(
            outcome(&report, "pcr0"),
            &Outcome::Fail(format!(
                "is not the expected value {}",
                hex(&expected.pcrs[0])
            ))
        );
        let stated = report.stated.unwrap();
        assert_eq!(stated.release.as_deref(), Some("v0.0.0-diag.local"));
        assert_eq!(
            hex(&stated.pcrs.unwrap()[0]),
            "904d4e19f2cece358d8c0bcfdb278573decfcc739ce320c587c59d9ee73f5db594cd0c8e73539a087138e069223d8f47"
        );

        // The document of the release against one changed expected value.
        let mut changed = release_measurements();
        changed.pcrs[1][47] ^= 1;
        let report = evaluate_document(RELEASE_DOCUMENT, RELEASE_NONCE, Some(&changed));
        assert_eq!(failed(&report), ["pcr1"]);
    }

    #[test]
    fn a_document_with_another_nonce_fails() {
        let expected = release_measurements();
        let mut nonce = RELEASE_NONCE.to_vec();
        nonce[31] ^= 1;
        let report = evaluate_document(RELEASE_DOCUMENT, &nonce, Some(&expected));
        assert!(!report.passed());
        assert_eq!(failed(&report), [NONCE]);
        assert_eq!(
            outcome(&report, NONCE),
            &Outcome::Fail("the nonce of the document is not the nonce that was asked for".into())
        );
        // The chain and the signature verified, so what the document states is reported and
        // compared.
        assert_eq!(skipped(&report), [""; 0]);
        assert_eq!(report.stated.unwrap().release.as_deref(), Some("v1.0.0"));

        // The nonce of another request.
        let other = hex_decode(OTHER_BUILD_NONCE).unwrap();
        let report = evaluate_document(RELEASE_DOCUMENT, &other, Some(&expected));
        assert_eq!(failed(&report), [NONCE]);
    }

    #[test]
    fn a_tampered_document_fails_and_nothing_it_states_is_reported() {
        let expected = release_measurements();
        let position = |needle: &[u8]| {
            RELEASE_DOCUMENT
                .windows(needle.len())
                .position(|window| window == needle)
                .unwrap()
        };
        let changed = |position: usize| {
            let mut document = RELEASE_DOCUMENT.to_vec();
            document[position] ^= 1;
            document
        };
        let after_the_failure = [PRODUCTION_MODE, "pcr0", "pcr1", "pcr2", BINDING];

        // One changed bit in what the signature covers (the release of the binding, PCR0) and
        // in the signature itself.
        for position in [
            position(b"\"release\":\"v1.0.0\"") + 12,
            position(&expected.pcrs[0]),
            RELEASE_DOCUMENT.len() - 1,
        ] {
            let report = evaluate_document(&changed(position), RELEASE_NONCE, Some(&expected));
            assert!(!report.passed(), "{position}");
            assert_eq!(failed(&report), [SIGNATURE], "{position}");
            assert_eq!(
                skipped(&report),
                [&[NONCE][..], &after_the_failure[..]].concat(),
                "{position}"
            );
            assert_eq!(report.stated, None, "{position}");
        }

        // One changed bit in the certificate of the document.
        let certificate = position(b"kcertificate") + 12 + 3 + 200;
        let report = evaluate_document(&changed(certificate), RELEASE_NONCE, Some(&expected));
        assert_eq!(failed(&report), [CHAIN]);
        assert_eq!(
            skipped(&report),
            [&[SIGNATURE, NONCE][..], &after_the_failure[..]].concat()
        );
        assert_eq!(report.stated, None);

        // A cut document, and bytes that are no document.
        for document in [&RELEASE_DOCUMENT[..RELEASE_DOCUMENT.len() - 1], b"{}"] {
            let report = evaluate_document(document, RELEASE_NONCE, Some(&expected));
            assert_eq!(failed(&report), [FORM]);
            assert_eq!(
                skipped(&report),
                [&[CHAIN, SIGNATURE, NONCE][..], &after_the_failure[..]].concat()
            );
            assert_eq!(report.stated, None);
        }

        // The same holds for an entry of the response: the node key check did not run.
        let mut entry = release_entry();
        entry["document"] = json!(b64u(&changed(RELEASE_DOCUMENT.len() - 1)));
        let report = evaluate_entry(&entry, RELEASE_NONCE, Some(&expected), false);
        assert_eq!(failed(&report), [SIGNATURE]);
        assert_eq!(skipped(&report).last(), Some(&NODE_KEY));
    }

    #[test]
    fn a_document_of_a_debug_mode_enclave_fails() {
        // The document a debug-mode enclave got at boot: all PCRs zero, no nonce, no user
        // data.
        let expected = release_measurements();
        let report = evaluate_document(DEBUG_BOOT_DOCUMENT, RELEASE_NONCE, Some(&expected));
        assert!(!report.passed());
        assert_eq!(
            failed(&report),
            [NONCE, PRODUCTION_MODE, "pcr0", "pcr1", "pcr2", BINDING]
        );
        assert_eq!(report.stated.unwrap().pcrs, Some([[0; 48]; 3]));

        // A document of a debug-mode enclave with a nonce. All zero is a failure whatever the
        // expected values are: here they are all zero as well, so the three comparisons pass,
        // and without expected values nothing is compared.
        let nonce = read_unverified_nitro_document(DEBUG_DOCUMENT)
            .unwrap()
            .nonce
            .unwrap();
        let zero = Measurements::of_command_line([[0; 48]; 3]);
        let report = evaluate_document(DEBUG_DOCUMENT, &nonce, Some(&zero));
        assert!(!report.passed());
        assert_eq!(failed(&report), [PRODUCTION_MODE, BINDING]);
        assert_eq!(
            outcome(&report, "pcr0"),
            &Outcome::Pass("equals the expected value".into())
        );
        let report = evaluate_document(DEBUG_DOCUMENT, &nonce, None);
        assert!(!report.passed());
        assert_eq!(failed(&report), [PRODUCTION_MODE, BINDING]);
    }

    #[test]
    fn without_expected_values_nothing_is_compared() {
        let report = evaluate_document(RELEASE_DOCUMENT, RELEASE_NONCE, None);
        assert!(report.passed());
        assert_eq!(skipped(&report), ["pcr0", "pcr1", "pcr2"]);
        assert_eq!(
            outcome(&report, "pcr0"),
            &Outcome::NotRun("not compared: no expected value was given".into())
        );
        assert_eq!(failed(&report), [""; 0]);
    }

    /// The entry of a node on the local platform, with the keys of the binding of the release
    /// document.
    fn local_entry(nonce: &[u8]) -> Value {
        let binding = json!({"v": 1, "sign": RELEASE_NODE, "seal": RELEASE_SEAL, "release": "dev"});
        let document = json!({
            "v": 1, "platform": "local", "binding": b64u(binding.to_string().as_bytes()),
            "nonce": b64u(nonce), "time_ms": 1_790_828_465_207u64,
        });
        json!({
            "v": 1, "platform": "local", "document": b64u(document.to_string().as_bytes()),
            "node": RELEASE_NODE, "release": "dev",
        })
    }

    #[test]
    fn the_log_store_of_a_binding_is_read() {
        // The binding of a node with a log store names it after the release.
        let binding = json!({
            "v": 1, "sign": RELEASE_NODE, "seal": RELEASE_SEAL, "release": "v1.0.0",
            "log": {"bucket": "character-credential-log-prod-1", "region": "us-west-2"},
        });
        let entry = |binding: &Value| {
            let document = json!({
                "v": 1, "platform": "local", "binding": b64u(binding.to_string().as_bytes()),
                "nonce": b64u(RELEASE_NONCE), "time_ms": 1_790_828_465_207u64,
            });
            json!({
                "v": 1, "platform": "local", "document": b64u(document.to_string().as_bytes()),
                "node": RELEASE_NODE, "release": "v1.0.0",
            })
        };
        let report = evaluate_entry(&entry(&binding), RELEASE_NONCE, None, true);
        assert!(report.passed());
        assert_eq!(
            report.stated.unwrap().log_store,
            LogStoreId::parse("character-credential-log-prod-1", "us-west-2")
        );
        // A `log` that is not a bucket name and a region name: the user data is no binding.
        let mut other = binding.clone();
        other["log"]["region"] = json!("us-west-2.example");
        let report = evaluate_entry(&entry(&other), RELEASE_NONCE, None, true);
        assert_eq!(failed(&report), [BINDING]);
        assert_eq!(report.stated.unwrap().log_store, None);
    }

    #[test]
    fn a_node_of_the_local_platform_fails_unless_it_is_allowed() {
        let expected = release_measurements();
        let entry = local_entry(RELEASE_NONCE);
        let report = evaluate_entry(&entry, RELEASE_NONCE, Some(&expected), false);
        assert!(!report.passed());
        assert_eq!(
            names(&report),
            [ENTRY, ATTESTATION, FORM, NONCE, BINDING, NODE_KEY]
        );
        assert_eq!(failed(&report), [ATTESTATION]);
        assert_eq!(
            outcome(&report, ATTESTATION),
            &Outcome::Fail("none: no attestation verifies a node of the local platform".into())
        );
        assert_eq!(
            report.stated,
            Some(Stated {
                time_ms: 1_790_828_465_207,
                module_id: None,
                pcrs: None,
                node: Some(RELEASE_NODE.to_string()),
                release: Some("dev".to_string()),
                log_store: None,
            })
        );

        let report = evaluate_entry(&entry, RELEASE_NONCE, Some(&expected), true);
        assert!(report.passed());
        assert_eq!(skipped(&report), [ATTESTATION]);

        // Allowed, a local node still answers this request and binds the node it names.
        let report = evaluate_entry(&local_entry(b"another nonce"), RELEASE_NONCE, None, true);
        assert_eq!(failed(&report), [NONCE]);
        let mut renamed = entry.clone();
        renamed["node"] = json!("QkJRkEKP6EwK2iiQQnQaoqfydMV9RvHVsA3t2zJEkHo");
        let report = evaluate_entry(&renamed, RELEASE_NONCE, None, true);
        assert_eq!(failed(&report), [NODE_KEY]);
        let mut unreadable = entry.clone();
        unreadable["document"] = json!(b64u(b"{}"));
        let report = evaluate_entry(&unreadable, RELEASE_NONCE, None, true);
        assert_eq!(failed(&report), [FORM]);
        assert_eq!(report.stated, None);

        // A Nitro document under the platform name local is not a local document, and a local
        // document under the platform name nitro is not a Nitro document.
        let mut renamed = release_entry();
        renamed["platform"] = json!("local");
        let report = evaluate_entry(&renamed, RELEASE_NONCE, Some(&expected), true);
        assert_eq!(failed(&report), [FORM]);
        let mut renamed = entry;
        renamed["platform"] = json!("nitro");
        let report = evaluate_entry(&renamed, RELEASE_NONCE, Some(&expected), true);
        assert_eq!(failed(&report), [FORM]);
    }

    #[test]
    fn an_entry_that_cannot_be_read_and_an_unknown_platform_fail() {
        let without = |name: &str| {
            let mut entry = release_entry();
            entry.as_object_mut().unwrap().remove(name);
            entry
        };
        let with = |name: &str, value: Value| {
            let mut entry = release_entry();
            entry[name] = value;
            entry
        };
        for entry in [
            without("v"),
            without("platform"),
            without("document"),
            without("node"),
            with("v", json!(2)),
            with("v", json!("1")),
            with("document", json!("not base64url!")),
            with("document", json!(format!("{}=", b64u(b"padded")))),
            with("node", json!(7)),
            json!("an entry"),
            json!(null),
        ] {
            let report = evaluate_entry(&entry, RELEASE_NONCE, None, true);
            assert!(!report.passed(), "{entry}");
            assert_eq!(failed(&report), [ENTRY], "{entry}");
            assert_eq!(names(&report), [ENTRY], "{entry}");
            assert_eq!((report.claimed, report.stated), (None, None), "{entry}");
        }

        // The release of the response is printed and compared with nothing: it may be absent.
        let report = evaluate_entry(&without("release"), RELEASE_NONCE, None, false);
        assert!(report.passed());
        assert_eq!(report.claimed.unwrap().release, None);

        let report = evaluate_entry(&with("platform", json!("sev")), RELEASE_NONCE, None, true);
        assert!(!report.passed());
        assert_eq!(names(&report), [ENTRY, ATTESTATION]);
        assert_eq!(failed(&report), [ATTESTATION]);
    }

    #[test]
    fn the_entries_of_a_response() {
        let entry = release_entry();
        let entries = vec![entry.clone(), entry.clone()];
        assert_eq!(
            entries_of_response(json!({"nodes": entries}).to_string().as_bytes()),
            Ok(entries.clone())
        );
        // The bare array.
        assert_eq!(
            entries_of_response(json!(entries).to_string().as_bytes()),
            Ok(entries)
        );
        for body in [
            "",
            "not JSON",
            "{}",
            "{\"nodes\":{}}",
            "{\"nodes\":null}",
            "\"nodes\"",
            // No node is no result, not a pass.
            "{\"nodes\":[]}",
            "[]",
        ] {
            assert!(entries_of_response(body.as_bytes()).is_err(), "{body}");
        }
    }
}
