//! The subcommand `release-proofs`: verifies the release proofs of a release (docs/protocol.md
//! section 9), the public build proof of its measurement, as a node does before it hands
//! delegations to a node of another release or takes them from one.
//!
//! The verdict is the one of `verify_release_proofs` of the protocol crate, the function the
//! node program calls, with the values the node program compiles in (`enclave/release/`): the
//! two certificates of the certificate authority of Sigstore, the key of the transparency log
//! and the list of build workflows, for the repository of this source. So a release whose
//! proofs this tool takes at a commit is a release the nodes of that commit take.
//!
//! The release workflow of this repository runs the tool on the proofs of the release it
//! builds, and makes no release whose proofs the tool of its own commit refuses (enclave.md
//! 11.2).

use credential_enclave_protocol::encoding::b64u_decode;
use credential_enclave_protocol::release::read_statement;
use credential_enclave_protocol::release_proofs::{verify_release_proofs, ProofTrust, Repository};
use serde_json::Value;

use crate::arguments::{hex, Expected, Measurements};
use crate::render::{EXIT_FAILED, EXIT_PASSED};
use crate::End;

/// The root certificate of the certificate authority of Sigstore, compiled in:
/// `enclave/release/fulcio-root.pem`.
const FULCIO_ROOT_PEM: &str = include_str!("../../enclave/release/fulcio-root.pem");
/// Its intermediate certificate, compiled in: `enclave/release/fulcio-intermediate.pem`.
const FULCIO_INTERMEDIATE_PEM: &str = include_str!("../../enclave/release/fulcio-intermediate.pem");
/// The key of the transparency log, compiled in: `enclave/release/rekor-key.pem`.
const LOG_KEY_PEM: &str = include_str!("../../enclave/release/rekor-key.pem");
/// The list of build workflows, compiled in: `enclave/release/builders.json`.
const BUILDERS: &str = include_str!("../../enclave/release/builders.json");

/// The arguments of `release-proofs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofsArguments {
    /// The file of the release proofs: `{"statement": ..., "attestation": ...}`.
    pub proofs: String,
    /// The measurement the proofs are verified for. Without it the measurement is the one the
    /// statement of the proofs states.
    pub expected: Expected,
}

/// What release proofs are verified with: the values the node program compiles in.
pub fn source_trust() -> Result<ProofTrust, String> {
    ProofTrust::read(
        FULCIO_ROOT_PEM,
        FULCIO_INTERMEDIATE_PEM,
        &[LOG_KEY_PEM],
        Repository::of_this_source(),
        BUILDERS.as_bytes(),
    )
    .map_err(|error| format!("the values compiled into the tool are not a trust: {error}"))
}

/// Runs the subcommand: reads the files, verifies, and renders the result.
pub fn run(arguments: &ProofsArguments) -> End {
    let read = |path: &str| std::fs::read(path).map_err(|error| format!("{path}: {error}"));
    let path = &arguments.proofs;
    let proofs: Value = match read(path)
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|_| format!("{path}: not JSON")))
    {
        Ok(value) => value,
        Err(message) => return End::no_result(&message),
    };
    let expected = match &arguments.expected {
        Expected::Nothing => None,
        Expected::File(path) => {
            match read(path).and_then(|content| Measurements::of_file(path, &content)) {
                Ok(measurements) => Some(measurements),
                Err(message) => return End::no_result(&message),
            }
        }
        Expected::Values(pcrs) => Some(Measurements::of_command_line(*pcrs)),
    };
    let trust = match source_trust() {
        Ok(trust) => trust,
        Err(message) => return End::no_result(&message),
    };
    judge(&proofs, expected.as_ref(), &trust)
}

/// The verdict on `proofs` under `trust`, for the measurement `expected` or, without it, for
/// the measurement the statement of the proofs states.
pub fn judge(proofs: &Value, expected: Option<&Measurements>, trust: &ProofTrust) -> End {
    let failed = |check: &str, detail: &str| End {
        status: EXIT_FAILED,
        output: format!("release proofs: failed: {check}: {detail}\n"),
        error: String::new(),
    };
    let (pcrs, origin) = match expected {
        Some(measurements) => (measurements.pcrs, measurements.origin.clone()),
        // The measurement the statement states: the proofs are verified as the proofs of the
        // release they name. Proofs without a statement that reads are verified for the
        // measurement of no enclave, and fail at their form or at their statement.
        None => {
            let stated = proofs
                .get("statement")
                .and_then(Value::as_str)
                .and_then(|statement| b64u_decode(statement).ok())
                .and_then(|statement| read_statement(&statement));
            (
                stated.map_or([[0u8; 48]; 3], |stated| stated.pcrs),
                "the statement of the proofs".to_string(),
            )
        }
    };
    match verify_release_proofs(proofs, &pcrs, trust) {
        Ok(stated) => {
            let [pcr0, pcr1, pcr2] = stated.pcrs.map(|pcr| hex(&pcr));
            End {
                status: EXIT_PASSED,
                output: format!(
                    "release proofs: release {}, commit {}, pcr0 {pcr0}, pcr1 {pcr1}, pcr2 {pcr2}, the measurement of {origin}: ok\n",
                    stated.release, stated.git_commit
                ),
                error: String::new(),
            }
        }
        Err(failure) => {
            let check = match failure.check() {
                0 => "form".to_string(),
                check => format!("V{check}"),
            };
            failed(&check, &failure.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The release statement and the bundle of the attestation of release v2.4.0-rc.1, as its
    /// GitHub release holds them.
    const STATEMENT: &[u8] =
        include_bytes!("../../protocol/vectors/published/v2.4.0-rc.1/measurements.json");
    const BUNDLE: &str = include_str!(
        "../../protocol/vectors/published/v2.4.0-rc.1/release-statement.sigstore.json"
    );

    fn published() -> Value {
        serde_json::json!({
            "statement": credential_enclave_protocol::encoding::b64u(STATEMENT),
            "attestation": serde_json::from_str::<Value>(BUNDLE).unwrap(),
        })
    }

    /// The values of the node program with, in the place of its list of build workflows, the
    /// build workflow at the commit whose job attested release v2.4.0-rc.1. The node program of
    /// that tag hands delegations on by a signature of the operator, and the list of this
    /// source does not name that commit.
    fn attested_by() -> ProofTrust {
        ProofTrust::read(
            FULCIO_ROOT_PEM,
            FULCIO_INTERMEDIATE_PEM,
            &[LOG_KEY_PEM],
            Repository::of_this_source(),
            br#"[{"workflow":".github/workflows/enclave-build.yml","commit":"3f84e8368fcdf1f89e42ca629670bfe0989b6f13"}]"#,
        )
        .unwrap()
    }

    #[test]
    fn the_published_proofs_of_a_release_candidate_hold_for_the_build_workflow_that_attested_them()
    {
        let trust = attested_by();
        let end = judge(&published(), None, &trust);
        assert_eq!(
            (end.status, end.output.as_str(), end.error.as_str()),
            (
                EXIT_PASSED,
                concat!(
                    "release proofs: release v2.4.0-rc.1, ",
                    "commit 4c21e0083064aec5300f6f8472a796607e83d9f3, ",
                    "pcr0 ccb312bc5ffd17f119379cea45ad9c2d647390cb6ea9b2f9cb0239621e938f9ede34073cc8983ad28baac458ac38bb7e, ",
                    "pcr1 4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493, ",
                    "pcr2 cb62dcc4e9a2ac5e5a04d409527dc4e1db989dbc5781f7708ed4688f882e238af25dc011a195ce5693a460c0cb03c3d9, ",
                    "the measurement of the statement of the proofs: ok\n"
                ),
                ""
            )
        );
        // The same for the measurement of that release, given beside the proofs.
        let measurements = Measurements::of_file("measurements.json", STATEMENT).unwrap();
        let end = judge(&published(), Some(&measurements), &trust);
        assert_eq!(end.status, EXIT_PASSED);
        assert!(end
            .output
            .ends_with("the measurement of measurements.json: ok\n"));
        // With the values of the node program the proofs fail: its list of build workflows
        // names another commit of the build workflow file.
        let end = judge(&published(), None, &source_trust().unwrap());
        assert_eq!(
            (end.status, end.output.as_str(), end.error.as_str()),
            (
                EXIT_FAILED,
                "release proofs: failed: V6: the certificate does not state the value asked for in its extension 1.3.6.1.4.1.57264.1.10\n",
                ""
            )
        );
    }

    #[test]
    fn proofs_that_do_not_hold_fail_with_the_check_they_break() {
        let trust = attested_by();
        let failed = |proofs: &Value, expected: Option<&Measurements>| {
            let end = judge(proofs, expected, &trust);
            assert_eq!((end.status, end.error.as_str()), (EXIT_FAILED, ""));
            end.output
        };
        // The measurement of another enclave.
        let mut other = Measurements::of_file("measurements.json", STATEMENT).unwrap();
        other.pcrs[2][0] ^= 1;
        assert_eq!(
            failed(&published(), Some(&other)),
            "release proofs: failed: V1: the measurement of the statement is not the measurement asked for\n"
        );
        // No statement, a value that is no proofs, and a statement that is none.
        const FORM: &str = "release proofs: failed: form: the value is not a JSON object of a statement and an attestation, of at most 32 levels\n";
        let mut proofs = published();
        proofs.as_object_mut().unwrap().remove("statement");
        assert_eq!(failed(&proofs, None), FORM);
        assert_eq!(failed(&serde_json::json!("proofs"), None), FORM);
        let mut proofs = published();
        proofs["statement"] = Value::from("e30");
        assert_eq!(
            failed(&proofs, None),
            "release proofs: failed: V1: the statement is not a release statement\n"
        );
        // A statement of another release: the certificate of the attestation names the tag.
        let mut proofs = published();
        let renamed = String::from_utf8(STATEMENT.to_vec())
            .unwrap()
            .replace("\"v2.4.0-rc.1\"", "\"v2.4.0\"");
        proofs["statement"] = Value::from(credential_enclave_protocol::encoding::b64u(
            renamed.as_bytes(),
        ));
        assert_eq!(
            failed(&proofs, None),
            "release proofs: failed: V6: the certificate does not state the value asked for in its extension 1.3.6.1.4.1.57264.1.14\n"
        );
        // A bundle without its log entry.
        let mut proofs = published();
        proofs["attestation"]["verificationMaterial"]["tlogEntries"] = serde_json::json!([]);
        assert_eq!(
            failed(&proofs, None),
            "release proofs: failed: V2: the attestation does not hold one certificate, one envelope with one signature and one log entry\n"
        );
    }
}
