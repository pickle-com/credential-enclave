//! The other releases of this program that a node exchanges delegations with (protocol.md 10.3,
//! enclave.md 5.13): the later releases it hands delegations to, and the earlier releases it
//! takes them from.
//!
//! The files of `enclave/release/` are compiled into the program, so they are part of its
//! measurement:
//!
//! | File | What it is |
//! | --- | --- |
//! | `release-key.pem` | the release key of the operator: the public key whose signature over the measurements of a later release a giving node asks for |
//! | `rekor-key.pem` | the public key of the transparency log Rekor of `rekor.sigstore.dev`, a log of the form Rekor v1 |
//! | `rekor-log2025-1-key.pem` | the public key of the transparency log `log2025-1.rekor.sigstore.dev`, a log of the form Rekor v2 |
//! | `predecessors.json` | the releases whose nodes a receiving node takes delegations from, each with its measurement |
//!
//! The two log keys are the rows of the table of transparency logs ([`LOGS`]): a giving node
//! asks for an entry of one of these logs that records the signature of the release key, with
//! what the log returned to show that it holds the entry. The table is the transparency logs
//! of the trusted root of the public instance of Sigstore at the time this source was written
//! (protocol.md 10.3). A release adds the row of a further log.
//!
//! A program whose release key, whose table or whose list of predecessors does not have its
//! form does not start.

use credential_enclave_protocol::release::{
    is_p256_public_key, public_key_der, read_predecessors, LogForm, ReleaseKeys,
    ReleaseMeasurement, TransparencyLog,
};

use crate::platform::PlatformError;

/// The release key of the operator (ECDSA P-256, SubjectPublicKeyInfo PEM).
pub const RELEASE_KEY_PEM: &str = include_str!("../release/release-key.pem");
/// The list of predecessors of this source.
const PREDECESSORS: &str = include_str!("../release/predecessors.json");

/// A row of the table of transparency logs, as the source states it.
pub struct LogSource {
    /// The form of the log.
    pub form: LogForm,
    /// The origin of a log of the form Rekor v2: the first line of its checkpoints and the
    /// name of its key on them. A log of the form Rekor v1 is named by its key alone, and its
    /// row states the empty string.
    pub origin: &'static str,
    /// The public key of the log (SubjectPublicKeyInfo PEM): ECDSA P-256 for the form Rekor
    /// v1, Ed25519 for the form Rekor v2.
    pub key_pem: &'static str,
}

/// The table of transparency logs of this source: the two logs of the public instance of
/// Sigstore.
pub const LOGS: [LogSource; 2] = [
    LogSource {
        form: LogForm::RekorV1,
        origin: "",
        key_pem: include_str!("../release/rekor-key.pem"),
    },
    LogSource {
        form: LogForm::RekorV2,
        origin: "log2025-1.rekor.sigstore.dev",
        key_pem: include_str!("../release/rekor-log2025-1-key.pem"),
    },
];

/// What a node knows about the other releases of its program.
pub struct Lineage {
    /// The DER of the release key.
    release_key: Vec<u8>,
    /// The transparency logs whose entries this node accepts.
    logs: Vec<TransparencyLog>,
    /// The releases this node takes delegations from, each with its measurement.
    pub predecessors: Vec<ReleaseMeasurement>,
}

impl Lineage {
    /// The key, the table of logs and the list of predecessors that are compiled into this
    /// program, for a node of the release `release`.
    pub fn embedded(release: &str) -> Result<Lineage, PlatformError> {
        Lineage::read(RELEASE_KEY_PEM, &LOGS, PREDECESSORS.as_bytes(), release)
    }

    /// Reads the release key from its PEM, the table of logs from its rows and the list of
    /// predecessors from its JSON, for a node of the release `release`.
    ///
    /// A release key that is not an ECDSA P-256 public key is refused. The table is refused
    /// when it has no row, when the key of a row is not a key of the form of that row, when a
    /// row of the form Rekor v2 states no origin or a row of the form Rekor v1 states one, and
    /// when two rows have the same identifier. The list is refused when it is malformed and
    /// when it names a release that is not earlier than `release`. A node whose own release is
    /// not a release tag (`dev`) starts with the empty list only.
    pub fn read(
        release_key_pem: &str,
        logs: &[LogSource],
        predecessors: &[u8],
        release: &str,
    ) -> Result<Lineage, PlatformError> {
        const TABLE: PlatformError = PlatformError(
            "the table of transparency logs of this build is empty, names a log twice or holds a row whose key or origin is not of the form of its log",
        );
        let release_key = public_key_der(release_key_pem)
            .filter(|der| is_p256_public_key(der))
            .ok_or(PlatformError(
                "the release key of this build is not an ECDSA P-256 public key",
            ))?;
        let mut table: Vec<TransparencyLog> = Vec::with_capacity(logs.len());
        for source in logs {
            let log = public_key_der(source.key_pem)
                .and_then(|der| match source.form {
                    LogForm::RekorV1 if source.origin.is_empty() => TransparencyLog::rekor_v1(&der),
                    LogForm::RekorV1 => None,
                    LogForm::RekorV2 => TransparencyLog::rekor_v2(source.origin, &der),
                })
                .filter(|log| table.iter().all(|other| other.id() != log.id()))
                .ok_or(TABLE)?;
            table.push(log);
        }
        if table.is_empty() {
            return Err(TABLE);
        }
        Ok(Lineage {
            release_key,
            logs: table,
            predecessors: read_predecessors(predecessors, release).ok_or(PlatformError(
                "the predecessor list of this build is malformed or names a release that is not earlier than this one",
            ))?,
        })
    }

    /// The release key and the table of logs an endorsement is verified with.
    pub fn keys(&self) -> ReleaseKeys<'_> {
        ReleaseKeys {
            release: &self.release_key,
            logs: &self.logs,
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use credential_enclave_protocol::release::{verify_endorsement, LogEntry};

    use super::*;

    const PCR: &str = "904d4e19f2cece358d8c0bcfdb278573decfcc739ce320c587c59d9ee73f5db594cd0c8e73539a087138e069223d8f47";

    /// `targets/trusted_root.json` of the repository of the trusted root of the public
    /// instance of Sigstore, as its TUF repository distributed it on 2026-11-23.
    const TRUSTED_ROOT: &str =
        include_str!("../../protocol/tests/fixtures/sigstore-trusted-root.json");

    fn refused(result: Result<Lineage, PlatformError>) -> bool {
        result.is_err()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn the_release_key_of_this_source_is_a_p256_key_and_its_logs_are_the_two_of_sigstore() {
        // The release of this source is the version of the crate: its list of predecessors
        // is valid for that release.
        let release = concat!("v", env!("CARGO_PKG_VERSION"));
        let lineage =
            Lineage::embedded(release).unwrap_or_else(|PlatformError(reason)| panic!("{reason}"));
        assert_eq!(lineage.release_key.len(), 91);
        assert_eq!(lineage.keys().release, &lineage.release_key[..]);
        // The identifier of each log, as the log itself states it in every entry: the hash of
        // the key for the form Rekor v1, the key ID of the checkpoint signatures for the form
        // Rekor v2.
        let logs: Vec<(LogForm, Option<&str>, String)> = lineage
            .keys()
            .logs
            .iter()
            .map(|log| (log.form(), log.origin(), log.id()))
            .collect();
        assert_eq!(
            logs,
            [
                (
                    LogForm::RekorV1,
                    None,
                    "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d".to_string()
                ),
                (
                    LogForm::RekorV2,
                    Some("log2025-1.rekor.sigstore.dev"),
                    "cf1199155bddd051268d1f16ac5c0c75c009f6fb5a63f4177f8e18d7051e3fa0".to_string()
                ),
            ]
        );
        for predecessor in &lineage.predecessors {
            assert_ne!(predecessor.release, release);
        }
    }

    #[test]
    fn the_endorsement_of_a_release_of_this_program_holds_under_the_keys_of_this_source() {
        // The endorsement of release v1.5.2: the statement of that release, and the entry of
        // Rekor that records the signature of the release key over it, as the log returned
        // it. A node of this source reads it as the nodes of the releases before it did.
        let statement = credential_enclave_protocol::encoding::b64u_decode(
            include_str!("../../verify/tests/fixtures/endorsement-v1.5.2-statement.b64u").trim(),
        )
        .unwrap();
        let logged: serde_json::Value = serde_json::from_str(include_str!(
            "../../verify/tests/fixtures/rekor-entry-3267788759.json"
        ))
        .unwrap();
        let logged = logged.as_object().unwrap().values().next().unwrap();
        let entry = serde_json::json!({
            "log_id": logged["logID"],
            "body": logged["body"],
            "integrated_time": logged["integratedTime"],
            "log_index": logged["logIndex"],
            "signed_entry_timestamp": logged["verification"]["signedEntryTimestamp"],
        });
        let integrated_time = logged["integratedTime"].as_u64().unwrap();
        // The release key and the table of logs of this source, for a node of release v1.5.1
        // (the list of predecessors of this source names releases after that one).
        let lineage = Lineage::read(RELEASE_KEY_PEM, &LOGS, b"[]", "v1.5.1")
            .unwrap_or_else(|PlatformError(reason)| panic!("{reason}"));
        let verify = |own_release: &str, now_s: u64| {
            verify_endorsement(
                &statement,
                &LogEntry::read(&entry).unwrap(),
                &lineage.keys(),
                own_release,
                now_s,
            )
        };
        let later = verify("v1.5.1", integrated_time + 3_600).unwrap();
        assert_eq!(later.release, "v1.5.2");
        assert_eq!(
            hex(&later.pcrs[0]),
            "edf5a93aec5f096f0bcd6717a2ffcf4265404cf121c1c0a40be66682e7d5f6e0d1a54b841e96e0f91d6ec806aa861143"
        );
        // A node of that release or of a later one hands nothing to it, and a clock that is
        // more than 300 seconds behind the time of the entry does not count it.
        assert!(verify("v1.5.2", integrated_time + 3_600).is_err());
        assert!(verify("v2.4.0", integrated_time + 3_600).is_err());
        assert!(verify("v1.5.1", integrated_time - 301).is_err());
        assert!(verify("v1.5.1", integrated_time - 300).is_ok());
    }

    #[test]
    fn the_table_of_logs_is_the_transparency_logs_of_the_trusted_root_of_sigstore() {
        // Every transparency log the trusted root names has a row with its key, and the
        // identifier of that row is the log identifier the trusted root states. A trusted root
        // that names a further log fails this test until the table has its row, and the table
        // has no row beyond the logs of the trusted root.
        let root: serde_json::Value = serde_json::from_str(TRUSTED_ROOT).unwrap();
        let tlogs = root["tlogs"].as_array().unwrap();
        assert_eq!(tlogs.len(), LOGS.len());
        for tlog in tlogs {
            let address = tlog["baseUrl"].as_str().unwrap();
            let key = STANDARD
                .decode(tlog["publicKey"]["rawBytes"].as_str().unwrap())
                .unwrap();
            let stated = STANDARD
                .decode(tlog["logId"]["keyId"].as_str().unwrap())
                .unwrap();
            let source = LOGS
                .iter()
                .find(|source| public_key_der(source.key_pem).as_deref() == Some(&key[..]))
                .unwrap_or_else(|| panic!("{address}: the table has no row with the key"));
            let (form, origin) = match tlog["publicKey"]["keyDetails"].as_str().unwrap() {
                "PKIX_ECDSA_P256_SHA_256" => (LogForm::RekorV1, ""),
                // The origin of a log of the form Rekor v2 is its address without the scheme.
                "PKIX_ED25519" => (LogForm::RekorV2, address.strip_prefix("https://").unwrap()),
                other => panic!("{address}: a key of the kind {other}"),
            };
            assert_eq!((source.form, source.origin), (form, origin), "{address}");
            let log = match form {
                LogForm::RekorV1 => TransparencyLog::rekor_v1(&key),
                LogForm::RekorV2 => TransparencyLog::rekor_v2(origin, &key),
            }
            .unwrap();
            assert_eq!(log.id(), hex(&stated), "{address}");
        }
    }

    #[test]
    fn a_node_does_not_start_with_a_malformed_key_table_or_list() {
        let read = |release_key: &str, list: &str, release: &str| {
            Lineage::read(release_key, &LOGS, list.as_bytes(), release)
        };
        let element = |release: &str| {
            format!(r#"{{"release":"{release}","pcr0":"{PCR}","pcr1":"{PCR}","pcr2":"{PCR}"}}"#)
        };
        let list = format!("[{}]", element("v1.0.0"));

        let lineage = read(RELEASE_KEY_PEM, &list, "v1.1.0")
            .unwrap_or_else(|PlatformError(reason)| panic!("{reason}"));
        assert_eq!(lineage.predecessors.len(), 1);
        assert_eq!(lineage.predecessors[0].release, "v1.0.0");
        assert_eq!(lineage.keys().logs.len(), 2);
        assert!(!refused(read(RELEASE_KEY_PEM, "[]", "dev")));

        // A release key that is not a PEM public key, or not a P-256 key.
        let [p256, ed25519] = LOGS.map(|source| source.key_pem);
        let origin = LOGS[1].origin;
        for key in ["", "not a key", ed25519] {
            assert!(refused(read(key, "[]", "v1.1.0")), "{key}");
        }

        // A table without a row, with a key that is not of the form of its row, with a log of
        // the form Rekor v2 that states no origin, with a log of the form Rekor v1 that states
        // one, and with one log in two rows.
        let table = |rows: &[(LogForm, &'static str, &'static str)]| {
            let rows: Vec<LogSource> = rows
                .iter()
                .map(|(form, origin, key_pem)| LogSource {
                    form: *form,
                    origin,
                    key_pem,
                })
                .collect();
            Lineage::read(RELEASE_KEY_PEM, &rows, b"[]", "v1.1.0")
        };
        assert!(!refused(table(&[(LogForm::RekorV1, "", p256)])));
        assert!(!refused(table(&[(LogForm::RekorV2, origin, ed25519)])));
        assert!(!refused(table(&[
            (LogForm::RekorV2, origin, ed25519),
            (LogForm::RekorV1, "", p256),
        ])));
        // One key under two origins is two logs.
        assert!(!refused(table(&[
            (LogForm::RekorV2, origin, ed25519),
            (LogForm::RekorV2, "log2026-1.rekor.sigstore.dev", ed25519),
        ])));
        for rows in [
            &[][..],
            &[(LogForm::RekorV1, "", ed25519)],
            &[(LogForm::RekorV2, origin, p256)],
            &[(LogForm::RekorV1, "", "not a key")],
            &[(LogForm::RekorV2, "", ed25519)],
            &[(LogForm::RekorV2, "an origin", ed25519)],
            &[(LogForm::RekorV1, origin, p256)],
            &[(LogForm::RekorV1, "", p256), (LogForm::RekorV1, "", p256)],
            &[
                (LogForm::RekorV2, origin, ed25519),
                (LogForm::RekorV1, "", p256),
                (LogForm::RekorV2, origin, ed25519),
            ],
        ] {
            assert!(refused(table(rows)), "{} rows", rows.len());
        }

        // A list that is not a list, an element that is malformed, an element whose release
        // is not earlier than the release of the node, and a list for a node whose release is
        // not a release tag.
        for (list, release) in [
            ("", "v1.1.0"),
            ("{}", "v1.1.0"),
            (r#"[{"release":"v1.0.0"}]"#, "v1.1.0"),
            (&format!("[{}]", element("v1.1.0")), "v1.1.0"),
            (&format!("[{}]", element("v1.2.0")), "v1.1.0"),
            (
                &format!("[{},{}]", element("v1.0.0"), element("v1.1.0")),
                "v1.1.0",
            ),
            (&list, "dev"),
            (&list, "v1.0.0"),
        ] {
            assert!(
                refused(read(RELEASE_KEY_PEM, list, release)),
                "{list} {release}"
            );
        }
    }
}
