//! The other releases of this program that a node exchanges delegations with (protocol.md 10.3,
//! enclave.md 5.13): the later releases it hands delegations to, and the earlier releases it
//! takes them from.
//!
//! Three files of `enclave/release/` are compiled into the program, so they are part of its
//! measurement:
//!
//! | File | What it is |
//! | --- | --- |
//! | `release-key.pem` | the release key of the operator: the public key whose signature over the measurements of a later release a giving node asks for |
//! | `rekor-key.pem` | the public key of the transparency log Rekor of rekor.sigstore.dev: a giving node asks for the signature of this key over the entry that records the signature of the release key |
//! | `predecessors.json` | the releases whose nodes a receiving node takes delegations from, each with its measurement |
//!
//! A program whose keys or whose list of predecessors do not have their form does not start.

use credential_enclave_protocol::release::{
    is_p256_public_key, public_key_der, read_predecessors, ReleaseKeys, ReleaseMeasurement,
};

use crate::platform::PlatformError;

/// The release key of the operator (ECDSA P-256, SubjectPublicKeyInfo PEM).
pub const RELEASE_KEY_PEM: &str = include_str!("../release/release-key.pem");
/// The public key of the transparency log (ECDSA P-256, SubjectPublicKeyInfo PEM).
pub const LOG_KEY_PEM: &str = include_str!("../release/rekor-key.pem");
/// The list of predecessors of this source.
const PREDECESSORS: &str = include_str!("../release/predecessors.json");

/// What a node knows about the other releases of its program.
pub struct Lineage {
    /// The DER of the release key.
    release_key: Vec<u8>,
    /// The DER of the key of the transparency log.
    log_key: Vec<u8>,
    /// The releases this node takes delegations from, each with its measurement.
    pub predecessors: Vec<ReleaseMeasurement>,
}

impl Lineage {
    /// The keys and the list of predecessors that are compiled into this program, for a node
    /// of the release `release`.
    pub fn embedded(release: &str) -> Result<Lineage, PlatformError> {
        Lineage::read(
            RELEASE_KEY_PEM,
            LOG_KEY_PEM,
            PREDECESSORS.as_bytes(),
            release,
        )
    }

    /// Reads the two keys from their PEM and the list of predecessors from its JSON, for a
    /// node of the release `release`.
    ///
    /// A key that is not an ECDSA P-256 public key is refused. The list is refused when it is
    /// malformed and when it names a release that is not earlier than `release`. A node whose
    /// own release is not a release tag (`dev`) starts with the empty list only.
    pub fn read(
        release_key_pem: &str,
        log_key_pem: &str,
        predecessors: &[u8],
        release: &str,
    ) -> Result<Lineage, PlatformError> {
        let key = |pem: &str, reason: &'static str| {
            public_key_der(pem)
                .filter(|der| is_p256_public_key(der))
                .ok_or(PlatformError(reason))
        };
        Ok(Lineage {
            release_key: key(
                release_key_pem,
                "the release key of this build is not an ECDSA P-256 public key",
            )?,
            log_key: key(
                log_key_pem,
                "the transparency log key of this build is not an ECDSA P-256 public key",
            )?,
            predecessors: read_predecessors(predecessors, release).ok_or(PlatformError(
                "the predecessor list of this build is malformed or names a release that is not earlier than this one",
            ))?,
        })
    }

    /// The two keys an endorsement is verified with.
    pub fn keys(&self) -> ReleaseKeys<'_> {
        ReleaseKeys {
            release: &self.release_key,
            log: &self.log_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credential_enclave_protocol::release::log_id;

    const PCR: &str = "904d4e19f2cece358d8c0bcfdb278573decfcc739ce320c587c59d9ee73f5db594cd0c8e73539a087138e069223d8f47";

    fn refused(result: Result<Lineage, PlatformError>) -> bool {
        result.is_err()
    }

    #[test]
    fn the_keys_of_this_source_are_p256_keys_and_the_log_key_is_the_key_of_rekor() {
        // The release of this source is the version of the crate: its list of predecessors
        // is valid for that release.
        let release = concat!("v", env!("CARGO_PKG_VERSION"));
        let lineage =
            Lineage::embedded(release).unwrap_or_else(|PlatformError(reason)| panic!("{reason}"));
        assert_eq!(lineage.release_key.len(), 91);
        assert_eq!(lineage.log_key.len(), 91);
        assert_ne!(lineage.release_key, lineage.log_key);
        // The identifier of the log, as the log itself states it in every entry.
        assert_eq!(
            log_id(lineage.keys().log),
            "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
        );
        assert_eq!(lineage.keys().release, &lineage.release_key[..]);
        for predecessor in &lineage.predecessors {
            assert_ne!(predecessor.release, release);
        }
    }

    #[test]
    fn a_node_does_not_start_with_a_malformed_key_or_list() {
        let read = |release_key: &str, log_key: &str, list: &str, release: &str| {
            Lineage::read(release_key, log_key, list.as_bytes(), release)
        };
        let element = |release: &str| {
            format!(r#"{{"release":"{release}","pcr0":"{PCR}","pcr1":"{PCR}","pcr2":"{PCR}"}}"#)
        };
        let list = format!("[{}]", element("v1.0.0"));

        let lineage = read(RELEASE_KEY_PEM, LOG_KEY_PEM, &list, "v1.1.0")
            .unwrap_or_else(|PlatformError(reason)| panic!("{reason}"));
        assert_eq!(lineage.predecessors.len(), 1);
        assert_eq!(lineage.predecessors[0].release, "v1.0.0");
        assert!(!refused(read(RELEASE_KEY_PEM, LOG_KEY_PEM, "[]", "dev")));

        // A key that is not a PEM public key, or not a P-256 key.
        let not_p256 = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n";
        for key in ["", "not a key", not_p256] {
            assert!(refused(read(key, LOG_KEY_PEM, "[]", "v1.1.0")), "{key}");
            assert!(refused(read(RELEASE_KEY_PEM, key, "[]", "v1.1.0")), "{key}");
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
                refused(read(RELEASE_KEY_PEM, LOG_KEY_PEM, list, release)),
                "{list} {release}"
            );
        }
    }
}
