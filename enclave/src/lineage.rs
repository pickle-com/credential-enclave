//! What a node knows of the other releases of its program (protocol.md section 9 and 10.3,
//! enclave.md 5.13): the values it verifies the release proofs of another release with, and
//! the old releases it takes delegations from.
//!
//! These files of `enclave/release/` are compiled into the program, so they are part of its
//! measurement:
//!
//! | File | What it is |
//! | --- | --- |
//! | `fulcio-root.pem`, `fulcio-intermediate.pem` | the root certificate and the intermediate certificate of the certificate authority of the public instance of Sigstore (Fulcio), which issues the certificate of an attestation |
//! | `rekor-key.pem` | the public key of the transparency log Rekor of `rekor.sigstore.dev`, a log of the form Rekor v1 |
//! | `builders.json` | the build workflows whose attestation of a release statement a node takes: the path of each workflow file in the repository and the commit of that file |
//! | `predecessors.json` | the old releases, the ones built before the build workflow existed: the releases without release proofs whose nodes a receiving node takes delegations from, each with its measurement |
//!
//! The repository whose tags are the releases is the one of this source
//! ([`Repository::of_this_source`]).
//!
//! None of these values is a value of one release: a release is built, tagged and deployed
//! without a change to them. They change when the certificate authority or the log of Sigstore
//! does, and when the build workflow does (protocol.md section 9).
//!
//! `release-key.pem` of that directory is not compiled into the program. It is the public half
//! of the release key of the operator, which the monitor of this repository and the tool
//! `credential-enclave-verify program` read. A node of this source asks for no signature of
//! that key.
//!
//! A program whose certificates, whose log keys or whose lists do not have their form does not
//! start.

use credential_enclave_protocol::release::{read_predecessors, ReleaseMeasurement};
use credential_enclave_protocol::release_proofs::{ProofTrust, Repository, TrustError};

use crate::platform::PlatformError;

/// The root certificate of the certificate authority of Sigstore (X.509, PEM).
pub const FULCIO_ROOT_PEM: &str = include_str!("../release/fulcio-root.pem");
/// The intermediate certificate of the certificate authority of Sigstore (X.509, PEM).
pub const FULCIO_INTERMEDIATE_PEM: &str = include_str!("../release/fulcio-intermediate.pem");
/// The keys of the transparency logs of this source (SubjectPublicKeyInfo PEM, ECDSA P-256):
/// `rekor.sigstore.dev`, the one log of the form Rekor v1 that the trusted root of the public
/// instance of Sigstore names.
pub const LOG_KEYS_PEM: [&str; 1] = [include_str!("../release/rekor-key.pem")];
/// The list of build workflows of this source.
pub const BUILDERS: &str = include_str!("../release/builders.json");
/// The list of old releases of this source.
const PREDECESSORS: &str = include_str!("../release/predecessors.json");

/// What a node knows about the other releases of its program.
pub struct Lineage {
    /// What the release proofs of another release are verified with.
    pub proofs: ProofTrust,
    /// The old releases this node takes delegations from, each with its measurement.
    pub predecessors: Vec<ReleaseMeasurement>,
}

impl Lineage {
    /// The certificates, the log keys and the lists that are compiled into this program.
    pub fn embedded() -> Result<Lineage, PlatformError> {
        Lineage::read(
            FULCIO_ROOT_PEM,
            FULCIO_INTERMEDIATE_PEM,
            &LOG_KEYS_PEM,
            BUILDERS.as_bytes(),
            PREDECESSORS.as_bytes(),
        )
    }

    /// Reads the two certificates of the certificate authority and the keys of the logs from
    /// their PEM, and the list of build workflows and the list of old releases from their
    /// JSON.
    ///
    /// The certificates are refused when one of them is not an X.509 certificate of a
    /// certificate authority and when the root did not issue the intermediate. The keys are
    /// refused when there is none, when one is not an ECDSA P-256 public key, and when two of
    /// them are one key. The list of build workflows is refused when it is malformed or names
    /// one build workflow twice, and the list of old releases when it is malformed
    /// (`credential_enclave_protocol::release_proofs`, `credential_enclave_protocol::release`).
    pub fn read(
        root_pem: &str,
        intermediate_pem: &str,
        log_keys_pem: &[&str],
        builders: &[u8],
        predecessors: &[u8],
    ) -> Result<Lineage, PlatformError> {
        let proofs = ProofTrust::read(
            root_pem,
            intermediate_pem,
            log_keys_pem,
            Repository::of_this_source(),
            builders,
        )
        .map_err(|error| {
            PlatformError(match error {
                TrustError::Certificates => {
                    "the certificates of the certificate authority of this build are not the root certificate and the intermediate certificate it issued, or the transparency logs of this build are none or one log twice"
                }
                TrustError::LogKey => {
                    "a transparency log key of this build is not an ECDSA P-256 public key"
                }
                TrustError::Builders => {
                    "the list of build workflows of this build is malformed or names a build workflow twice"
                }
            })
        })?;
        Ok(Lineage {
            proofs,
            predecessors: read_predecessors(predecessors).ok_or(PlatformError(
                "the list of old releases of this build is malformed",
            ))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    use credential_enclave_protocol::release::{pem_der, TransparencyLog};

    use super::*;

    const PCR: &str = "904d4e19f2cece358d8c0bcfdb278573decfcc739ce320c587c59d9ee73f5db594cd0c8e73539a087138e069223d8f47";

    /// `targets/trusted_root.json` of the repository of the trusted root of the public
    /// instance of Sigstore, as its TUF repository distributed it on 2026-11-23.
    const TRUSTED_ROOT: &str =
        include_str!("../../protocol/tests/fixtures/sigstore-trusted-root.json");

    /// The key of the log of the form Rekor v2 that the trusted root names,
    /// `log2025-1.rekor.sigstore.dev`. This source has no key for it: the attestation of a
    /// release statement is recorded in the log of the form Rekor v1, which the monitor of
    /// this repository reads.
    const LOG2025_1_KEY_PEM: &str =
        include_str!("../../protocol/tests/fixtures/rekor-log2025-1-key.pem");

    fn refused(result: Result<Lineage, PlatformError>) -> bool {
        result.is_err()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn embedded() -> Lineage {
        Lineage::embedded().unwrap_or_else(|PlatformError(reason)| panic!("{reason}"))
    }

    #[test]
    fn the_values_of_this_source_are_those_of_sigstore_and_of_this_repository() {
        let lineage = embedded();
        // The identifier of the log, as the log itself states it in every entry: the hash of
        // its key.
        let logs: Vec<String> = lineage
            .proofs
            .logs()
            .iter()
            .map(TransparencyLog::id)
            .collect();
        assert_eq!(
            logs,
            ["c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"]
        );
        // The two certificates, by the SHA-256 of their DER.
        let digest = |pem: &str| hex(&Sha256::digest(pem_der(pem, "CERTIFICATE").unwrap()));
        assert_eq!(
            digest(FULCIO_ROOT_PEM),
            "3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1"
        );
        assert_eq!(
            digest(FULCIO_INTERMEDIATE_PEM),
            "15d795348226b4649f750f5802592c393bee7cc53c3b86982175b7ad087efe47"
        );
        assert_eq!(*lineage.proofs.repository(), Repository::of_this_source());
        assert_eq!(
            lineage.proofs.repository().address,
            "https://github.com/pickle-com/credential-enclave"
        );
        // The build workflow of this repository, at the commit of its file.
        let builders: Vec<(&str, &str)> = lineage
            .proofs
            .builders()
            .iter()
            .map(|builder| (builder.workflow(), builder.commit()))
            .collect();
        assert_eq!(
            builders,
            [(
                ".github/workflows/enclave-build.yml",
                "3f84e8368fcdf1f89e42ca629670bfe0989b6f13"
            )]
        );
    }

    #[test]
    fn the_list_of_old_releases_holds_the_releases_built_before_the_build_workflow() {
        // The list is the one of the releases that have no release proofs. It gains no
        // element: a release built by the build workflow is accepted by its proofs.
        let lineage = embedded();
        let releases: Vec<&str> = lineage
            .predecessors
            .iter()
            .map(|predecessor| predecessor.release.as_str())
            .collect();
        assert_eq!(
            releases,
            ["v1.5.2", "v2.0.0", "v2.0.1", "v2.1.0", "v2.2.0", "v2.3.0"]
        );
    }

    #[test]
    fn the_values_of_this_source_are_those_of_the_trusted_root_of_sigstore() {
        // Every transparency log the trusted root names is a log of this source or the one
        // log this source has no key for, and the identifier of a log of this source is the
        // log identifier the trusted root states. A trusted root that names a further log
        // fails this test until this source holds its key or states it here as a log without
        // one, and this source holds no key beyond the logs of the trusted root.
        let root: serde_json::Value = serde_json::from_str(TRUSTED_ROOT).unwrap();
        let tlogs = root["tlogs"].as_array().unwrap();
        assert_eq!(tlogs.len(), LOG_KEYS_PEM.len() + 1);
        let mut without_a_key = Vec::new();
        for tlog in tlogs {
            let address = tlog["baseUrl"].as_str().unwrap();
            let key = STANDARD
                .decode(tlog["publicKey"]["rawBytes"].as_str().unwrap())
                .unwrap();
            let stated = STANDARD
                .decode(tlog["logId"]["keyId"].as_str().unwrap())
                .unwrap();
            let own = LOG_KEYS_PEM
                .iter()
                .any(|pem| pem_der(pem, "PUBLIC KEY").as_deref() == Some(&key[..]));
            if !own {
                assert_eq!(
                    pem_der(LOG2025_1_KEY_PEM, "PUBLIC KEY").as_deref(),
                    Some(&key[..]),
                    "{address}: this source has no key for the log and does not state it"
                );
                without_a_key.push(address);
                continue;
            }
            assert_eq!(
                tlog["publicKey"]["keyDetails"], "PKIX_ECDSA_P256_SHA_256",
                "{address}"
            );
            let log = TransparencyLog::rekor_v1(&key).unwrap();
            assert_eq!(log.id(), hex(&stated), "{address}");
        }
        assert_eq!(without_a_key, ["https://log2025-1.rekor.sigstore.dev"]);

        // The two certificates of this source are the chain of the one certificate authority
        // of the trusted root that has no end: the intermediate certificate first, then the
        // root certificate.
        let authorities: Vec<&serde_json::Value> = root["certificateAuthorities"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|authority| authority["validFor"].get("end").is_none())
            .collect();
        assert_eq!(authorities.len(), 1);
        assert_eq!(authorities[0]["uri"], "https://fulcio.sigstore.dev");
        let chain: Vec<Vec<u8>> = authorities[0]["certChain"]["certificates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|certificate| {
                STANDARD
                    .decode(certificate["rawBytes"].as_str().unwrap())
                    .unwrap()
            })
            .collect();
        assert_eq!(
            chain,
            [
                pem_der(FULCIO_INTERMEDIATE_PEM, "CERTIFICATE").unwrap(),
                pem_der(FULCIO_ROOT_PEM, "CERTIFICATE").unwrap(),
            ]
        );
    }

    #[test]
    fn a_node_does_not_start_with_malformed_certificates_keys_or_lists() {
        let [log_key] = LOG_KEYS_PEM;
        let read = |root: &str, intermediate: &str, keys: &[&str], builders: &str, list: &str| {
            Lineage::read(
                root,
                intermediate,
                keys,
                builders.as_bytes(),
                list.as_bytes(),
            )
        };
        let element = |release: &str| {
            format!(r#"{{"release":"{release}","pcr0":"{PCR}","pcr1":"{PCR}","pcr2":"{PCR}"}}"#)
        };
        let list = format!("[{},{}]", element("v1.0.0"), element("v9.0.0"));
        let builder = r#"[{"workflow":".github/workflows/build.yml","commit":"0123456789abcdef0123456789abcdef01234567"}]"#;

        let lineage = read(
            FULCIO_ROOT_PEM,
            FULCIO_INTERMEDIATE_PEM,
            &[log_key],
            builder,
            &list,
        )
        .unwrap_or_else(|PlatformError(reason)| panic!("{reason}"));
        // The list of old releases is read as it is: no release of it is compared with
        // another one, or with the release of the node.
        assert_eq!(lineage.predecessors.len(), 2);
        assert_eq!(lineage.predecessors[1].release, "v9.0.0");
        assert_eq!(lineage.proofs.builders().len(), 1);
        assert_eq!(lineage.proofs.logs().len(), 1);
        // A node with no build workflow and no old release starts: it accepts the nodes of
        // its own measurement alone.
        let alone = read(
            FULCIO_ROOT_PEM,
            FULCIO_INTERMEDIATE_PEM,
            &[log_key],
            "[]",
            "[]",
        );
        assert!(!refused(alone));

        // Certificates that are not a root and an intermediate it issued: the two in the
        // place of each other, the intermediate twice, a text that is no PEM, the PEM of a
        // key.
        for (root, intermediate) in [
            (FULCIO_INTERMEDIATE_PEM, FULCIO_ROOT_PEM),
            (FULCIO_INTERMEDIATE_PEM, FULCIO_INTERMEDIATE_PEM),
            ("", FULCIO_INTERMEDIATE_PEM),
            (FULCIO_ROOT_PEM, "not a certificate"),
            (log_key, FULCIO_INTERMEDIATE_PEM),
        ] {
            assert!(refused(read(root, intermediate, &[log_key], "[]", "[]")));
        }
        // No log, a key that is not a P-256 key, and one log twice.
        for keys in [
            &[][..],
            &[LOG2025_1_KEY_PEM],
            &["not a key"],
            &[FULCIO_ROOT_PEM],
            &[log_key, log_key],
        ] {
            assert!(
                refused(read(
                    FULCIO_ROOT_PEM,
                    FULCIO_INTERMEDIATE_PEM,
                    keys,
                    "[]",
                    "[]"
                )),
                "{} keys",
                keys.len()
            );
        }
        // A list of build workflows that is not a list, with a malformed element, and with
        // one build workflow twice.
        for builders in [
            "",
            "{}",
            r#"[{"workflow":".github/workflows/build.yml"}]"#,
            r#"[{"workflow":".github/workflows/build.yml","commit":"main"}]"#,
            &format!("[{0},{0}]", &builder[1..builder.len() - 1]),
        ] {
            assert!(
                refused(read(
                    FULCIO_ROOT_PEM,
                    FULCIO_INTERMEDIATE_PEM,
                    &[log_key],
                    builders,
                    "[]"
                )),
                "{builders}"
            );
        }
        // A list of old releases that is not a list, and one with a malformed element.
        for list in [
            "",
            "{}",
            r#"[{"release":"v1.0.0"}]"#,
            &format!("[{}]", element("dev")),
        ] {
            assert!(
                refused(read(
                    FULCIO_ROOT_PEM,
                    FULCIO_INTERMEDIATE_PEM,
                    &[log_key],
                    "[]",
                    list
                )),
                "{list}"
            );
        }
    }
}
