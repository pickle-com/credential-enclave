//! Verification of the attestation response of a peer node (protocol.md 10.1, enclave.md
//! 5.13).
//!
//! A node hands delegations to another node, and takes them from one, only after it verified
//! that node's attestation: the peer runs on the same platform and, on nitro, has the same
//! measurement, which means it is the same program. The operator domain carries the responses
//! and the envelopes between the nodes and is not trusted with either.
//!
//! The documents are read and verified by the attestation module of the protocol crate, the
//! one reader that every verifier of a node uses. What is decided here is which peer this
//! node accepts.
//!
//! The verifier does not look at the nonce or the age of a peer's document. The document proves
//! that the private half of the sealing key in its binding was created inside an enclave of that
//! measurement, and that fact does not change with time. A transfer sealed to the key of a node
//! that is gone can be opened by nobody.

use credential_enclave_protocol::attestation::{
    read_binding, read_local_document, verify_nitro_document, NitroDocument, AWS_NITRO_ROOT_G1,
};
use credential_enclave_protocol::encoding::b64u_decode;
use credential_enclave_protocol::envelope::{
    open_transfer, seal_transfer, Transfer, TransferEnvelope, TransferGrant,
};
use credential_enclave_protocol::keys::{node_id, LogStoreId, NodeKeys};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::ProtocolError;

use crate::platform::Measurement;

/// The keys of a peer, read from the binding inside its verified attestation document. Only
/// [`verify_peer`] creates one, so a `Peer` is a node this node accepted: the same platform
/// and, on nitro, the same measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    sign_public: [u8; 32],
    seal_public: [u8; 32],
}

impl Peer {
    /// The node identifier of the peer.
    pub fn node(&self) -> String {
        node_id(&self.sign_public)
    }

    /// The signing public key of the peer.
    pub fn sign_public(&self) -> [u8; 32] {
        self.sign_public
    }

    /// Hands delegations to this peer: signs the transfer and seals it to the sealing key of
    /// the peer (sink K2 of the egress policy). The user keys leave this node inside that seal
    /// only, and the seal is made to a verified peer only: this is the one call of the node to
    /// the sealing function.
    pub fn seal_transfer(
        &self,
        keys: &NodeKeys,
        time_ms: u64,
        grants: &[TransferGrant],
        hpke_seed: &Secret<[u8; 32]>,
    ) -> Result<TransferEnvelope, ProtocolError> {
        seal_transfer(
            keys,
            &self.sign_public,
            &self.seal_public,
            time_ms,
            grants,
            hpke_seed,
        )
    }

    /// Opens a transfer this peer made for this node and verifies its signature.
    pub fn open_transfer(
        &self,
        keys: &NodeKeys,
        envelope: &TransferEnvelope,
    ) -> Result<Transfer, ProtocolError> {
        open_transfer(keys, &self.sign_public, envelope)
    }
}

/// Verifies the attestation response of a peer for a node that runs on `platform` with
/// `measurement` and writes to the log store `log` (protocol.md 10.1, steps 1 to 3). Every
/// failure is `peer_unverified`.
///
/// | Step | Rule |
/// | --- | --- |
/// | 1 | the response verifies: platform `nitro` by protocol.md 4.3 without the nonce check, against the AWS Nitro Enclaves Root-G1 compiled into the binary, platform `local` by reading the binding of the local document |
/// | 2 | the platform of the peer is the platform of this node |
/// | 3 | on nitro, PCR0, PCR1 and PCR2 of the peer equal those of this node, and none of them is all zero |
/// | 3 | the log store the binding of the peer names is the log store of this node: the same bucket and region, or none on both sides |
pub fn verify_peer(
    platform: &str,
    measurement: Option<&Measurement>,
    log: Option<&LogStoreId>,
    response: &serde_json::Value,
) -> Result<Peer, ProtocolError> {
    read_peer(platform, measurement, log, response).ok_or(ProtocolError::PeerUnverified)
}

fn read_peer(
    platform: &str,
    measurement: Option<&Measurement>,
    log: Option<&LogStoreId>,
    response: &serde_json::Value,
) -> Option<Peer> {
    if response.get("v")?.as_u64()? != 1 {
        return None;
    }
    // A node of another platform holds user keys of another custody: nothing moves there.
    if response.get("platform")?.as_str()? != platform {
        return None;
    }
    let document = b64u_decode(response.get("document")?.as_str()?).ok()?;
    let binding = match platform {
        "nitro" => nitro_binding(
            measurement?,
            verify_nitro_document(&document, AWS_NITRO_ROOT_G1, None).ok()?,
        )?,
        "local" => read_local_document(&document).ok()?.binding,
        _ => return None,
    };
    let binding = read_binding(&binding).ok()?;
    // A delegation stays among nodes that write to the same log store: the entries of the
    // receiving node are then where the app of the account looks for them.
    if binding.log.as_ref() != log {
        return None;
    }
    Some(Peer {
        sign_public: binding.sign_public,
        seal_public: binding.seal_public,
    })
}

/// The binding of a nitro peer whose document verified, when this node accepts that peer:
///
/// - PCR0, PCR1 and PCR2 of the document are those of this node, and none of them is all
///   zero. An all-zero PCR is the measurement of a debug-mode enclave, whose memory the parent
///   instance can read: it is never accepted, whatever this node's own measurement says.
/// - the document carries a nonce and user data, as the document of an attestation call
///   does. A document without them (the kind a node requests from its own NSM to read the
///   time) is not the attestation of a peer.
fn nitro_binding(own: &Measurement, document: NitroDocument) -> Option<Vec<u8>> {
    if document.is_debug_mode() || own.pcrs != [document.pcr0, document.pcr1, document.pcr2] {
        return None;
    }
    document.nonce.as_ref()?;
    document.user_data
}

#[cfg(test)]
mod tests {
    use super::*;
    use credential_enclave_protocol::attestation::read_unverified_nitro_document;
    use credential_enclave_protocol::encoding::{b64u, b64u_decode_array, to_json};
    use credential_enclave_protocol::keys::{binding, NodeKeys};
    use serde_json::json;

    /// A real attestation document of a production-mode enclave (2026-10-01), the answer to
    /// an attestation call: its user data is the binding of that node.
    const OPERATIONAL_DOCUMENT: &[u8] =
        include_bytes!("../../protocol/tests/fixtures/nitro-attestation-document-operational.cbor");
    /// PCR0, PCR1 and PCR2 of that enclave.
    const OPERATIONAL_PCRS: [&str; 3] = [
        "904d4e19f2cece358d8c0bcfdb278573decfcc739ce320c587c59d9ee73f5db594cd0c8e73539a087138e069223d8f47",
        "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
        "a1952bc63a9e80a3a46eda48bb60236dfcb030d50bf81f02b5c50d20d42a905d1db7c82d3f1d4c4d5649b20697889d44",
    ];
    /// A real document of a debug-mode enclave as a node receives it at boot (2026-10-01):
    /// PCR0, PCR1 and PCR2 are zero, user data and nonce are null.
    const BOOT_DOCUMENT: &[u8] =
        include_bytes!("../../protocol/tests/fixtures/nitro-attestation-document-boot.cbor");
    /// A real document of a debug-mode enclave of another program (2023-09-18), with user
    /// data and a nonce.
    const SAMPLE_DOCUMENT: &[u8] =
        include_bytes!("../../protocol/tests/fixtures/nitro-attestation-document.cbor");

    fn pcr(text: &str) -> [u8; 48] {
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    fn operational_measurement() -> Measurement {
        Measurement {
            pcrs: [
                pcr(OPERATIONAL_PCRS[0]),
                pcr(OPERATIONAL_PCRS[1]),
                pcr(OPERATIONAL_PCRS[2]),
            ],
        }
    }

    fn response(platform: &str, document: &[u8]) -> serde_json::Value {
        // `node` and `release` are copies for convenience: a verifier does not read them.
        json!({
            "v": 1, "platform": platform, "document": b64u(document),
            "node": "not-the-node", "challenge": "c", "release": "not-the-release",
        })
    }

    #[test]
    fn a_real_nitro_peer_of_the_same_measurement_verifies() {
        // A node whose own measurement is the measurement of the document: the same program.
        let peer = verify_peer(
            "nitro",
            Some(&operational_measurement()),
            None,
            &response("nitro", OPERATIONAL_DOCUMENT),
        )
        .expect("the document verifies against the AWS root and has this measurement");
        // The keys are those of the binding inside the document.
        assert_eq!(
            peer,
            Peer {
                sign_public: b64u_decode_array("QkJRkEKP6EwK2iiQQnQaoqfydMV9RvHVsA3t2zJEkHo")
                    .unwrap(),
                seal_public: b64u_decode_array("2iI8u-awqrbr0Wt2kz4rzQ3-FHkGxVv8IjicSsHqUl4")
                    .unwrap(),
            }
        );
        assert_eq!(peer.node(), "QkJRkEKP6EwK2iiQQnQaoqfydMV9RvHVsA3t2zJEkHo");
    }

    #[test]
    fn a_real_nitro_peer_of_another_measurement_or_with_a_changed_document_is_refused() {
        let own = operational_measurement();
        let verify = |measurement: Option<&Measurement>, document: &[u8]| {
            verify_peer("nitro", measurement, None, &response("nitro", document))
        };
        assert!(verify(Some(&own), OPERATIONAL_DOCUMENT).is_ok());

        // Each of the three PCRs decides: a node of another build is not a peer.
        for index in 0..3 {
            let mut other = own;
            other.pcrs[index][47] ^= 1;
            assert_eq!(
                verify(Some(&other), OPERATIONAL_DOCUMENT),
                Err(ProtocolError::PeerUnverified),
                "PCR{index}"
            );
        }
        // A node without a measurement takes no nitro peer.
        assert_eq!(
            verify(None, OPERATIONAL_DOCUMENT),
            Err(ProtocolError::PeerUnverified)
        );

        // A changed document: one bit of the sealing key in the binding, of a PCR, of the
        // signature. The measurement this node compares with is the one the changed document
        // states, so only the verification of the document refuses it.
        let position = |needle: &[u8]| {
            OPERATIONAL_DOCUMENT
                .windows(needle.len())
                .position(|window| window == needle)
                .unwrap()
        };
        for at in [
            position(b"2iI8u-awqrbr0Wt2"),
            position(&pcr(OPERATIONAL_PCRS[1])) + 5,
            OPERATIONAL_DOCUMENT.len() - 1,
        ] {
            let mut changed = OPERATIONAL_DOCUMENT.to_vec();
            changed[at] ^= 1;
            let stated = read_unverified_nitro_document(&changed).unwrap();
            let measurement = Measurement {
                pcrs: [stated.pcr0, stated.pcr1, stated.pcr2],
            };
            assert_eq!(
                verify(Some(&measurement), &changed),
                Err(ProtocolError::PeerUnverified),
                "{at}"
            );
        }
        // Not a document.
        assert_eq!(
            verify(Some(&own), b"not a document"),
            Err(ProtocolError::PeerUnverified)
        );
    }

    #[test]
    fn a_real_document_of_a_debug_enclave_is_never_a_peer() {
        // Both documents verify as documents: their chains lead to the AWS root.
        for document in [BOOT_DOCUMENT, SAMPLE_DOCUMENT] {
            let verified = verify_nitro_document(document, AWS_NITRO_ROOT_G1, None).unwrap();
            assert!(verified.is_debug_mode());
            // Their PCRs are all zero. Even a node whose own measurement were those zeros does
            // not take them, and a node of any other measurement does not either.
            for measurement in [
                Measurement {
                    pcrs: [[0u8; 48]; 3],
                },
                operational_measurement(),
            ] {
                assert_eq!(
                    verify_peer(
                        "nitro",
                        Some(&measurement),
                        None,
                        &response("nitro", document)
                    ),
                    Err(ProtocolError::PeerUnverified)
                );
            }
        }
    }

    #[test]
    fn the_rule_of_a_nitro_peer_holds_for_each_of_its_parts() {
        let own = Measurement {
            pcrs: [[0xa0; 48], [0xa1; 48], [0xa2; 48]],
        };
        let document = || NitroDocument {
            module_id: "i-0123456789abcdef0-enc0123456789abcdef".to_string(),
            timestamp_ms: 1_790_000_000_000,
            pcr0: [0xa0; 48],
            pcr1: [0xa1; 48],
            pcr2: [0xa2; 48],
            user_data: Some(b"binding".to_vec()),
            nonce: Some(vec![0x5a; 32]),
        };
        assert_eq!(nitro_binding(&own, document()), Some(b"binding".to_vec()));

        // Another value in one of the three PCRs.
        let changes: [fn(&mut NitroDocument); 3] = [
            |document| document.pcr0[0] ^= 1,
            |document| document.pcr1[47] ^= 1,
            |document| document.pcr2[20] ^= 1,
        ];
        for (index, change) in changes.into_iter().enumerate() {
            let mut other = document();
            change(&mut other);
            assert_eq!(nitro_binding(&own, other), None, "PCR{index}");
        }
        // A PCR that is all zero, in the document and in the measurement of this node alike:
        // only the debug-mode rule refuses it.
        for index in 0..3 {
            let mut debug = document();
            let mut own = own;
            own.pcrs[index] = [0; 48];
            match index {
                0 => debug.pcr0 = [0; 48],
                1 => debug.pcr1 = [0; 48],
                _ => debug.pcr2 = [0; 48],
            }
            assert_eq!(own.pcrs, [debug.pcr0, debug.pcr1, debug.pcr2], "PCR{index}");
            assert_eq!(nitro_binding(&own, debug), None, "PCR{index}");
        }
        // A document without a nonce, and one without user data: not the answer to an
        // attestation call.
        let mut no_nonce = document();
        no_nonce.nonce = None;
        assert_eq!(nitro_binding(&own, no_nonce), None);
        let mut no_user_data = document();
        no_user_data.user_data = None;
        assert_eq!(nitro_binding(&own, no_user_data), None);
    }

    fn local_document(binding: &[u8]) -> Vec<u8> {
        crate::platform::local::local_document(binding, &[0x5a; 32], 1_790_000_000_000)
    }

    #[test]
    fn a_local_peer_is_read_from_its_unsigned_document() {
        let keys = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
        let document = local_document(&binding(&keys, "v1.0.0", None));
        let peer = verify_peer("local", None, None, &response("local", &document)).unwrap();
        assert_eq!(peer.sign_public, keys.sign_public());
        assert_eq!(peer.seal_public, keys.seal_public());
        assert_eq!(peer.node(), keys.node());

        let refused = |response: serde_json::Value| {
            verify_peer("local", None, None, &response) == Err(ProtocolError::PeerUnverified)
        };
        // A response of another version, without a document, or with a document that is not
        // a local document of version 1.
        let mut version_2 = response("local", &document);
        version_2["v"] = json!(2);
        assert!(refused(version_2));
        let mut no_document = response("local", &document);
        no_document.as_object_mut().unwrap().remove("document");
        assert!(refused(no_document));
        let mut garbled = response("local", &document);
        garbled["document"] = json!("not base64url!");
        assert!(refused(garbled));
        assert!(refused(response("local", b"not json")));
        let mut other_version: serde_json::Value = serde_json::from_slice(&document).unwrap();
        other_version["v"] = json!(2);
        assert!(refused(response("local", &to_json(&other_version))));

        // A binding of another version, with everything else in place, and a binding whose
        // sealing key cannot be sealed to.
        let binding_with = |change: fn(&mut serde_json::Value)| {
            let keys = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
            let mut value: serde_json::Value =
                serde_json::from_slice(&binding(&keys, "v1.0.0", None)).unwrap();
            change(&mut value);
            response("local", &local_document(&to_json(&value)))
        };
        assert!(!refused(binding_with(|_| {})));
        assert!(refused(binding_with(|binding| binding["v"] = json!(2))));
        assert!(refused(binding_with(
            |binding| binding["seal"] = json!(b64u(&[0u8; 32]))
        )));
        assert!(refused(json!("text")));
        assert!(refused(json!({})));
    }

    #[test]
    fn a_peer_of_another_platform_is_refused() {
        let keys = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
        let local = local_document(&binding(&keys, "v1.0.0", None));
        let own = operational_measurement();

        // A nitro node and a local peer: the peer would hold keys of custody `enclave` as an
        // ordinary process. The real document under the name of the local platform fares no
        // better.
        for document in [&local[..], OPERATIONAL_DOCUMENT] {
            assert_eq!(
                verify_peer("nitro", Some(&own), None, &response("local", document)),
                Err(ProtocolError::PeerUnverified)
            );
        }
        // A local document under the name of the nitro platform is not a COSE structure.
        assert_eq!(
            verify_peer("nitro", Some(&own), None, &response("nitro", &local)),
            Err(ProtocolError::PeerUnverified)
        );
        // A local node and a nitro peer, whatever the document.
        for document in [&local[..], OPERATIONAL_DOCUMENT] {
            assert_eq!(
                verify_peer("local", None, None, &response("nitro", document)),
                Err(ProtocolError::PeerUnverified)
            );
        }
        // A local node does not read a Nitro document as a local one.
        assert_eq!(
            verify_peer(
                "local",
                None,
                None,
                &response("local", OPERATIONAL_DOCUMENT)
            ),
            Err(ProtocolError::PeerUnverified)
        );
        // A platform this program does not know.
        assert_eq!(
            verify_peer("sev", None, None, &response("sev", &local)),
            Err(ProtocolError::PeerUnverified)
        );
    }
}
