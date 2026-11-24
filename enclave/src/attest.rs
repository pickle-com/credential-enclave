//! Verification of the attestation response of another node (protocol.md 10.1 and 10.5,
//! enclave.md 5.13 and 5.9c).
//!
//! A node hands delegations to another node, and takes them from one, only after it verified
//! that node's attestation: the peer runs on the same platform and, on nitro, has a
//! measurement the call accepts. That is the measurement of this node, which means the same
//! program, or a measurement that the release proofs of the call show: the measurement of an
//! enclave image file that the build workflow of the public repository built from a public
//! tag (protocol.md section 9). For a receiving node it is also the measurement of an old
//! release that this program lists (protocol.md 10.3). The operator domain carries the
//! responses, the proofs and the envelopes between the nodes and is trusted with none of
//! them.
//!
//! A node hands the value of a vault secret, for one request, to a node of the forward role
//! only after it verified that node's attestation as well ([`ForwardNodes::verify`]): the
//! same platform, the measurement of this node and no other one, and a binding that names
//! the forward role. The peer of a delegation transfer is a node that holds delegations (its
//! binding names no role, or the role `reserve`) and the receiver of a secret use a node of
//! the forward role, so neither rule accepts a node the other one accepts.
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
    read_binding, read_local_document, verify_nitro_document, NitroDocument, NodeBinding,
    AWS_NITRO_ROOT_G1,
};
use credential_enclave_protocol::encoding::b64u_decode;
use credential_enclave_protocol::envelope::{
    open_transfer, seal_transfer, Transfer, TransferEnvelope, TransferGrant,
};
use std::collections::HashMap;
use std::sync::MutexGuard;

use credential_enclave_protocol::keys::{node_id, LogStoreId, NodeKeys, Role};
use credential_enclave_protocol::release::ReleaseMeasurement;
use credential_enclave_protocol::release_proofs::{verify_release_proofs, ProofTrust};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::secret_use::{seal_secret_use, BoundRequest, SecretUseEnvelope};
use credential_enclave_protocol::ProtocolError;
use sha2::{Digest, Sha256};

use crate::faults::{lock, NodeLock};
use crate::platform::Measurement;

/// The keys of a peer, read from the binding inside its verified attestation document. Only
/// [`verify_peer`] creates one, so a `Peer` is a node this node accepted: the same platform
/// and, on nitro, a measurement that the rule of the call ([`Accepted`]) names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    sign_public: [u8; 32],
    seal_public: [u8; 32],
    program: Program,
}

/// The program an accepted peer runs, as the rule of the call found it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Program {
    /// The program of this node: on nitro the measurement of the peer is the measurement of
    /// this node, and on the local platform, which has no measurement, the peer is a local
    /// node. A transfer between two such nodes moves a user key between two instances of one
    /// source, and neither of them creates an entry for it (protocol.md 10.1).
    Same,
    /// The program of another release: a release whose measurement the release proofs of the
    /// call show, or a listed old release. The measurement is the one of the verified
    /// attestation document of the peer, and the release the one its binding names.
    Release(ReleaseMeasurement),
}

impl Peer {
    /// The node identifier of the peer.
    pub fn node(&self) -> String {
        node_id(&self.sign_public)
    }

    /// The program the peer runs.
    pub fn program(&self) -> &Program {
        &self.program
    }

    /// A peer with the keys of `keys` that runs `program`, for the tests of what a node does
    /// with an accepted peer: no attestation response was verified to make it.
    #[cfg(test)]
    pub fn accepted_for_tests(keys: &NodeKeys, program: Program) -> Peer {
        Peer {
            sign_public: keys.sign_public(),
            seal_public: keys.seal_public(),
            program,
        }
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

/// Release proofs a call carries for its peer, with what this node verifies them with.
#[derive(Clone, Copy, Debug)]
pub struct Proofs<'a> {
    /// The value of the key `release_proofs` of the call.
    pub value: &'a serde_json::Value,
    /// The certificates, the log keys, the repository and the build workflows of this node.
    pub trust: &'a ProofTrust,
}

/// The peers a call accepts: the rule the caller of [`verify_peer`] states.
///
/// On the local platform there is no measurement, and the peer is a local node. On nitro the
/// measurement of the peer is one of three, looked at in this order:
///
/// 1. `measurement`, the measurement of this node: the same program. A node without a
///    measurement accepts no nitro peer.
/// 2. The measurement of an element of `predecessors`, when the binding of the peer names
///    the release of that element. `peer/export` passes no element: a node hands nothing to
///    an old release.
/// 3. A measurement that `proofs` show (protocol.md section 9), when the binding of the peer
///    names the release their statement names.
///
/// The measurement of this node is accepted whatever the call carries beside it: release
/// proofs are not read for a peer of the same program.
#[derive(Clone, Copy, Debug)]
pub struct Accepted<'a> {
    /// The measurement of this node, `None` on the local platform.
    pub measurement: Option<&'a Measurement>,
    /// The old releases whose nodes the call takes.
    pub predecessors: &'a [ReleaseMeasurement],
    /// The release proofs the call carries, when it carries any.
    pub proofs: Option<Proofs<'a>>,
}

impl Accepted<'_> {
    /// The program of a nitro peer with the measurement `pcrs` whose binding names the release
    /// `release`, when the rule accepts that peer, and `None` when it does not.
    fn takes_nitro(&self, pcrs: &[[u8; 48]; 3], release: &str) -> Option<Program> {
        let own = self.measurement?;
        if own.pcrs == *pcrs {
            return Some(Program::Same);
        }
        let other = || {
            Program::Release(ReleaseMeasurement {
                release: release.to_string(),
                pcrs: *pcrs,
            })
        };
        let listed = self
            .predecessors
            .iter()
            .any(|earlier| earlier.pcrs == *pcrs && earlier.release == release);
        if listed {
            return Some(other());
        }
        let proofs = self.proofs?;
        let stated = verify_release_proofs(proofs.value, pcrs, proofs.trust).ok()?;
        (stated.release == release).then(other)
    }
}

/// Verifies the attestation response of a peer for a node that runs on `platform`, accepts
/// the peers of `accepted` and writes to the log store `log` (protocol.md 10.1, steps 1 to 3b,
/// and 10.3). Every failure is `peer_unverified`.
///
/// | Step | Rule |
/// | --- | --- |
/// | 1 | the response verifies: platform `nitro` by protocol.md 4.3 without the nonce check, against the AWS Nitro Enclaves Root-G1 compiled into the binary, platform `local` by reading the binding of the local document |
/// | 2 | the platform of the peer is the platform of this node |
/// | 3 | on nitro, PCR0, PCR1 and PCR2 of the peer are a measurement that `accepted` names, with the release of the binding where the rule names one, and none of them is all zero |
/// | 3a | the log store the binding of the peer names is the log store of this node: the same bucket and region, or none on both sides |
/// | 3b | the binding of the peer names no role or the role `reserve`: the peer is a node that holds delegations. A node of the forward role holds no delegation and takes none |
pub fn verify_peer(
    platform: &str,
    accepted: Accepted<'_>,
    log: Option<&LogStoreId>,
    response: &serde_json::Value,
) -> Result<Peer, ProtocolError> {
    read_peer(platform, accepted, log, response).ok_or(ProtocolError::PeerUnverified)
}

fn read_peer(
    platform: &str,
    accepted: Accepted<'_>,
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
    let (binding, program) = match platform {
        "nitro" => nitro_binding(
            accepted,
            verify_nitro_document(&document, AWS_NITRO_ROOT_G1, None).ok()?,
        )?,
        // A local document states no measurement: release proofs show nothing of its node.
        "local" => (
            read_binding(&read_local_document(&document).ok()?.binding).ok()?,
            Program::Same,
        ),
        _ => return None,
    };
    // A delegation stays among nodes that write to the same log store: the entries of the
    // receiving node are then where the app of the account looks for them.
    if binding.log.as_ref() != log {
        return None;
    }
    // And it stays among nodes that hold delegations: a node whose binding names no role, and
    // a node of the reserve role. A node of the forward role takes none, and a binding that
    // names any other role is no binding (`read_binding`).
    if !binding.role.holds_delegations() {
        return None;
    }
    Some(Peer {
        sign_public: binding.sign_public,
        seal_public: binding.seal_public,
        program,
    })
}

/// The binding of a nitro peer whose document verified, when the call accepts that peer:
///
/// - none of PCR0, PCR1 and PCR2 of the document is all zero. An all-zero PCR is the
///   measurement of a debug-mode enclave, whose memory the parent instance can read: it is
///   never accepted, whatever measurement the rule of the call names.
/// - the document carries a nonce and user data, as the document of an attestation call
///   does. A document without them (the kind a node requests from its own NSM to read the
///   time) is not the attestation of a peer.
/// - the user data is a binding, and `accepted` names the measurement of the document with
///   the release of that binding.
fn nitro_binding(
    accepted: Accepted<'_>,
    document: NitroDocument,
) -> Option<(NodeBinding, Program)> {
    if document.is_debug_mode() {
        return None;
    }
    document.nonce.as_ref()?;
    let binding = read_binding(document.user_data.as_deref()?).ok()?;
    let program = accepted.takes_nitro(
        &[document.pcr0, document.pcr1, document.pcr2],
        &binding.release,
    )?;
    Some((binding, program))
}

/// The keys of a node of the forward role, read from the binding inside its verified
/// attestation document. Only [`ForwardNodes::verify`] creates one, so a `ForwardNode` is a
/// node this node accepted as the receiver of a secret use: the same platform, on nitro the
/// measurement of this node, and a binding that names the forward role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardNode {
    sign_public: [u8; 32],
    seal_public: [u8; 32],
}

impl ForwardNode {
    /// The node identifier of the node.
    pub fn node(&self) -> String {
        node_id(&self.sign_public)
    }

    /// Hands one use of a vault secret to this node: signs the value and the one request it
    /// is for, and seals both to the sealing key of the node (sink K8 of the egress policy).
    /// The value leaves the node that opened its record inside that seal only, and the seal
    /// is made to a verified node of the forward role only: this is the one call of the node
    /// to the sealing function.
    #[allow(clippy::too_many_arguments)]
    pub fn seal_secret_use(
        &self,
        keys: &NodeKeys,
        time_ms: u64,
        nonce: &[u8; 16],
        user_id: &str,
        record_id: &str,
        value: &Secret<String>,
        request: &BoundRequest,
        hpke_seed: &Secret<[u8; 32]>,
    ) -> Result<SecretUseEnvelope, ProtocolError> {
        seal_secret_use(
            keys,
            &self.sign_public,
            &self.seal_public,
            time_ms,
            nonce,
            user_id,
            record_id,
            value,
            request,
            hpke_seed,
        )
    }
}

/// The attestation document of a response of version 1 that names `platform`, the platform
/// of this node. `None` for a response of another version, of another platform, or without a
/// document.
fn forward_document(platform: &str, response: &serde_json::Value) -> Option<Vec<u8>> {
    if response.get("v")?.as_u64()? != 1 {
        return None;
    }
    // A node of another platform holds user keys of another custody: no value of an account
    // of this node goes there.
    if response.get("platform")?.as_str()? != platform {
        return None;
    }
    b64u_decode(response.get("document")?.as_str()?).ok()
}

/// The node of the forward role whose attestation document `document` is, for a node that
/// runs on `platform` with `measurement` (protocol.md 10.5):
///
/// | Step | Rule |
/// | --- | --- |
/// | 1 | the document verifies: platform `nitro` by protocol.md 4.3 without the nonce check, against the AWS Nitro Enclaves Root-G1 compiled into the binary, platform `local` by reading the binding of the local document |
/// | 2 | on nitro, PCR0, PCR1 and PCR2 of the document are those of this node, and none of them is all zero: the node runs the program of this node. No other measurement is accepted, neither one that release proofs show nor that of an old release: what a node of the forward role does with a value is what this source says |
/// | 3 | the binding of the document names the role `forward`: the node holds no user key and takes none, and it sends the request of an envelope it opens. A value sealed to a node of the delegation role would be readable in a node that sends no request for it |
///
/// The verdict depends on the bytes of the document, on the platform and on the measurement,
/// and on nothing else: the verification reads neither a clock nor a nonce.
fn forward_node_of(
    platform: &str,
    measurement: Option<&Measurement>,
    document: &[u8],
) -> Option<ForwardNode> {
    // The rule that takes a node of the program of this node and of no other release.
    let same_program = Accepted {
        measurement,
        predecessors: &[],
        proofs: None,
    };
    let binding = match platform {
        "nitro" => match nitro_binding(
            same_program,
            verify_nitro_document(document, AWS_NITRO_ROOT_G1, None).ok()?,
        )? {
            (binding, Program::Same) => binding,
            // The rule names no other release, and a node of one is not taken either way.
            (_, Program::Release(_)) => return None,
        },
        "local" => read_binding(&read_local_document(document).ok()?.binding).ok()?,
        _ => return None,
    };
    (binding.role == Role::Forward).then_some(ForwardNode {
        sign_public: binding.sign_public,
        seal_public: binding.seal_public,
    })
}

/// The verifier of the nodes of the forward role for one node, with the nodes it verified:
/// each under the SHA-256 of its attestation document.
///
/// Whether a document is that of a node of the forward role this node accepts depends on the
/// bytes of the document, on the platform of this node and on its measurement
/// ([`forward_node_of`]). The platform and the measurement of a node do not change while it
/// lives: a store is made for one node and holds both. The verification reads no clock and no
/// nonce. So a document that verified once verifies whenever it is presented again, and a
/// node reads the keys of such a document from what it kept: the verification of a Nitro
/// document is a certificate chain and a signature of P-384, and a caller presents the
/// document of the same node with every use it hands over.
///
/// A document that does not verify is not kept. The store holds [`ForwardNodes::KEPT`]
/// documents: a further one empties it first, and a document in use is then verified once
/// more.
pub struct ForwardNodes {
    /// The platform of the node this store belongs to.
    platform: &'static str,
    /// The measurement of that node, `None` on the local platform.
    measurement: Option<Measurement>,
    verified: NodeLock<HashMap<[u8; 32], ForwardNode>>,
}

impl ForwardNodes {
    /// The documents the store keeps at the same time.
    pub const KEPT: usize = 1_024;

    /// The verifier of a node that runs on `platform` with `measurement`.
    pub fn of(platform: &'static str, measurement: Option<Measurement>) -> ForwardNodes {
        ForwardNodes {
            platform,
            measurement,
            verified: NodeLock::new(HashMap::new()),
        }
    }

    /// Verifies the attestation response of the node a secret use is handed to. The response
    /// is one of version 1 that names the platform of this node, and its document passes the
    /// three steps of [`forward_node_of`]. Every failure is `peer_unverified`.
    pub fn verify(&self, response: &serde_json::Value) -> Result<ForwardNode, ProtocolError> {
        let document =
            forward_document(self.platform, response).ok_or(ProtocolError::PeerUnverified)?;
        let digest: [u8; 32] = Sha256::digest(&document).into();
        if let Some(known) = self.kept().get(&digest) {
            return Ok(known.clone());
        }
        let node = forward_node_of(self.platform, self.measurement.as_ref(), &document)
            .ok_or(ProtocolError::PeerUnverified)?;
        let mut kept = self.kept();
        if kept.len() >= ForwardNodes::KEPT {
            kept.clear();
        }
        kept.insert(digest, node.clone());
        Ok(node)
    }

    fn kept(&self) -> MutexGuard<'_, HashMap<[u8; 32], ForwardNode>> {
        lock(&self.verified)
    }

    /// The documents the store keeps at this moment.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.kept().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credential_enclave_protocol::attestation::read_unverified_nitro_document;
    use credential_enclave_protocol::encoding::{b64u, b64u_decode_array, to_json};
    use credential_enclave_protocol::keys::{binding, NodeKeys};
    use serde_json::json;

    use crate::testing::{proof_case, ProofCase};

    /// The release that the binding of the operational document names.
    const OPERATIONAL_RELEASE: &str = "v0.0.0-diag.local";

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

    /// The rule of a transfer among nodes of one program: the measurement of this node, no
    /// old release and no release proofs.
    fn own(measurement: Option<&Measurement>) -> Accepted<'_> {
        Accepted {
            measurement,
            predecessors: &[],
            proofs: None,
        }
    }

    /// The rule of a call that carries the release proofs of `case`, for a node of
    /// `measurement` without an old release.
    fn with_proofs<'a>(measurement: Option<&'a Measurement>, case: &'a ProofCase) -> Accepted<'a> {
        Accepted {
            measurement,
            predecessors: &[],
            proofs: Some(Proofs {
                value: &case.proofs,
                trust: &case.trust,
            }),
        }
    }

    /// The rule of a call that lists old releases, for a node of `measurement`.
    fn with_list<'a>(
        measurement: Option<&'a Measurement>,
        predecessors: &'a [ReleaseMeasurement],
    ) -> Accepted<'a> {
        Accepted {
            measurement,
            predecessors,
            proofs: None,
        }
    }

    /// The release and the measurement of the operational document, as an element of a list
    /// of old releases states them.
    fn operational_release() -> ReleaseMeasurement {
        ReleaseMeasurement {
            release: OPERATIONAL_RELEASE.to_string(),
            pcrs: operational_measurement().pcrs,
        }
    }

    /// The measurement of another program.
    fn other_measurement() -> Measurement {
        Measurement {
            pcrs: [[0xa0; 48], [0xa1; 48], [0xa2; 48]],
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
            own(Some(&operational_measurement())),
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
                // The measurement of the peer is the measurement of this node.
                program: Program::Same,
            }
        );
        assert_eq!(peer.node(), "QkJRkEKP6EwK2iiQQnQaoqfydMV9RvHVsA3t2zJEkHo");
    }

    #[test]
    fn a_real_nitro_peer_of_another_measurement_or_with_a_changed_document_is_refused() {
        let this_node = operational_measurement();
        let verify = |measurement: Option<&Measurement>, document: &[u8]| {
            verify_peer(
                "nitro",
                own(measurement),
                None,
                &response("nitro", document),
            )
        };
        assert!(verify(Some(&this_node), OPERATIONAL_DOCUMENT).is_ok());

        // Each of the three PCRs decides: a node of another build is not a peer.
        for index in 0..3 {
            let mut other = this_node;
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
            verify(Some(&this_node), b"not a document"),
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
                        own(Some(&measurement)),
                        None,
                        &response("nitro", document)
                    ),
                    Err(ProtocolError::PeerUnverified)
                );
                // The same under a list of old releases with the zeros of the document.
                let stated = ReleaseMeasurement {
                    release: "v1.2.0".to_string(),
                    pcrs: [[0u8; 48]; 3],
                };
                assert_eq!(
                    verify_peer(
                        "nitro",
                        with_list(Some(&measurement), std::slice::from_ref(&stated)),
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
        let own_measurement = other_measurement();
        let keys = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
        let document = || NitroDocument {
            module_id: "i-0123456789abcdef0-enc0123456789abcdef".to_string(),
            timestamp_ms: 1_790_000_000_000,
            pcr0: [0xa0; 48],
            pcr1: [0xa1; 48],
            pcr2: [0xa2; 48],
            user_data: Some(binding(&keys, "v1.1.0", None)),
            nonce: Some(vec![0x5a; 32]),
        };
        let (accepted, program) = nitro_binding(own(Some(&own_measurement)), document()).unwrap();
        assert_eq!(accepted.sign_public, keys.sign_public());
        assert_eq!(accepted.seal_public, keys.seal_public());
        assert_eq!(accepted.release, "v1.1.0");
        assert_eq!(program, Program::Same);

        // Another value in one of the three PCRs.
        let changes: [fn(&mut NitroDocument); 3] = [
            |document| document.pcr0[0] ^= 1,
            |document| document.pcr1[47] ^= 1,
            |document| document.pcr2[20] ^= 1,
        ];
        for (index, change) in changes.into_iter().enumerate() {
            let mut other = document();
            change(&mut other);
            assert_eq!(
                nitro_binding(own(Some(&own_measurement)), other),
                None,
                "PCR{index}"
            );
        }
        // A PCR that is all zero, in the document and in the measurement of this node alike:
        // only the debug-mode rule refuses it.
        for index in 0..3 {
            let mut debug = document();
            let mut zeroed = own_measurement;
            zeroed.pcrs[index] = [0; 48];
            match index {
                0 => debug.pcr0 = [0; 48],
                1 => debug.pcr1 = [0; 48],
                _ => debug.pcr2 = [0; 48],
            }
            assert_eq!(
                zeroed.pcrs,
                [debug.pcr0, debug.pcr1, debug.pcr2],
                "PCR{index}"
            );
            assert_eq!(
                nitro_binding(own(Some(&zeroed)), debug.clone()),
                None,
                "PCR{index}"
            );
            // The same PCRs in a list of old releases, with the release of the binding.
            let stated = ReleaseMeasurement {
                release: "v1.1.0".to_string(),
                pcrs: zeroed.pcrs,
            };
            assert_eq!(
                nitro_binding(
                    with_list(Some(&own_measurement), std::slice::from_ref(&stated)),
                    debug
                ),
                None,
                "PCR{index}"
            );
        }
        // A document without a nonce, one without user data, and one whose user data is not
        // a binding: not the answer to an attestation call of a node.
        let mut no_nonce = document();
        no_nonce.nonce = None;
        assert_eq!(nitro_binding(own(Some(&own_measurement)), no_nonce), None);
        let mut no_user_data = document();
        no_user_data.user_data = None;
        assert_eq!(
            nitro_binding(own(Some(&own_measurement)), no_user_data),
            None
        );
        let mut no_binding = document();
        no_binding.user_data = Some(b"binding".to_vec());
        assert_eq!(nitro_binding(own(Some(&own_measurement)), no_binding), None);
    }

    #[test]
    fn the_rule_of_an_old_release_names_the_measurement_and_the_release() {
        let keys = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
        let document = |release: &str| NitroDocument {
            module_id: "i-0123456789abcdef0-enc0123456789abcdef".to_string(),
            timestamp_ms: 1_790_000_000_000,
            pcr0: [0xb0; 48],
            pcr1: [0xb1; 48],
            pcr2: [0xb2; 48],
            user_data: Some(binding(&keys, release, None)),
            nonce: Some(vec![0x5a; 32]),
        };
        let stated = |release: &str| ReleaseMeasurement {
            release: release.to_string(),
            pcrs: [[0xb0; 48], [0xb1; 48], [0xb2; 48]],
        };
        let this_node = other_measurement();
        let taken = |accepted: Accepted<'_>, document: NitroDocument| {
            nitro_binding(accepted, document).map(|(_, program)| program)
        };

        // A receiving node with the old releases v1.0.0 and v1.1.0: the measurement of an
        // element and the release of that element in the binding. The list is in no order,
        // and the release of an element is not compared with the release of the node.
        let mut first = stated("v1.0.0");
        first.pcrs[0] = [0xc0; 48];
        let predecessors = [stated("v1.1.0"), first];
        let listed = with_list(Some(&this_node), &predecessors);
        assert_eq!(
            taken(listed, document("v1.1.0")),
            Some(Program::Release(stated("v1.1.0")))
        );
        // The release of another element of the list, and a release of no element.
        assert_eq!(taken(listed, document("v1.0.0")), None);
        assert_eq!(taken(listed, document("v1.2.0")), None);
        // The other element is accepted with its own measurement and release only.
        let mut of_first = document("v1.0.0");
        of_first.pcr0 = [0xc0; 48];
        assert!(taken(listed, of_first.clone()).is_some());
        of_first.user_data = Some(binding(&keys, "v1.1.0", None));
        assert_eq!(taken(listed, of_first), None);
        // The measurement of the node itself is accepted with every release in the binding:
        // a node of that measurement is the same program.
        let mut same_program = document("anything");
        [same_program.pcr0, same_program.pcr1, same_program.pcr2] = this_node.pcrs;
        assert_eq!(taken(listed, same_program), Some(Program::Same));
        // A node without a measurement accepts no nitro peer, also not a listed one.
        assert_eq!(
            taken(with_list(None, &predecessors), document("v1.1.0")),
            None
        );
        // An empty list accepts no other measurement.
        assert_eq!(taken(own(Some(&this_node)), document("v1.1.0")), None);
    }

    #[test]
    fn the_rule_of_release_proofs_names_the_measurement_they_show_and_the_release_they_name() {
        // Release proofs that hold for the measurement and the release `v9.9.0` of the case,
        // under the certificates, the log key and the build workflows of the case.
        let case = proof_case("proofs that hold");
        assert_eq!(case.release, "v9.9.0");
        let keys = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
        let document = |pcrs: [[u8; 48]; 3], release: &str| NitroDocument {
            module_id: "i-0123456789abcdef0-enc0123456789abcdef".to_string(),
            timestamp_ms: 1_790_000_000_000,
            pcr0: pcrs[0],
            pcr1: pcrs[1],
            pcr2: pcrs[2],
            user_data: Some(binding(&keys, release, None)),
            nonce: Some(vec![0x5a; 32]),
        };
        let this_node = other_measurement();
        let taken = |accepted: Accepted<'_>, document: NitroDocument| {
            nitro_binding(accepted, document).map(|(_, program)| program)
        };
        let shown = Program::Release(ReleaseMeasurement {
            release: "v9.9.0".to_string(),
            pcrs: case.pcrs,
        });

        // The peer has the measurement the proofs show, and its binding names the release
        // of their statement.
        let proven = with_proofs(Some(&this_node), &case);
        assert_eq!(
            taken(proven, document(case.pcrs, "v9.9.0")),
            Some(shown.clone())
        );
        // A binding that names another release, also the release of a candidate of it.
        for release in ["v9.9.1", "v9.9.0-rc.1", "v9.9", "dev", ""] {
            assert_eq!(
                taken(proven, document(case.pcrs, release)),
                None,
                "{release}"
            );
        }
        // Another value in one PCR of the peer: the proofs are those of another measurement.
        for index in 0..3 {
            let mut other = case.pcrs;
            other[index][7] ^= 1;
            assert_eq!(taken(proven, document(other, "v9.9.0")), None, "PCR{index}");
        }
        // Without the proofs the node of that release is not accepted, and neither with a
        // value that is no proofs or with the proofs of another measurement.
        assert_eq!(
            taken(own(Some(&this_node)), document(case.pcrs, "v9.9.0")),
            None
        );
        for value in [json!(null), json!("proofs"), json!({}), json!([])] {
            let other = ProofCase {
                proofs: value,
                ..proof_case("proofs that hold")
            };
            assert_eq!(
                taken(
                    with_proofs(Some(&this_node), &other),
                    document(case.pcrs, "v9.9.0")
                ),
                None
            );
        }
        let recorded =
            proof_case("the proofs of the measurement of a recorded attestation document");
        assert_eq!(
            taken(
                with_proofs(Some(&this_node), &recorded),
                document(case.pcrs, "v9.9.0")
            ),
            None
        );
        // Proofs that do not hold show nothing: here the certificate was issued to the job
        // of a workflow that is no build workflow of the node.
        let refused = proof_case(
            "the attestation of a job of the release workflow itself, which no workflow called",
        );
        assert_eq!(refused.pcrs, case.pcrs);
        assert_eq!(
            taken(
                with_proofs(Some(&this_node), &refused),
                document(case.pcrs, "v9.9.0")
            ),
            None
        );
        // And so do proofs that hold for a node whose own values do not take them: the
        // build workflows of this source are not those of the case.
        let source = crate::lineage::Lineage::embedded()
            .unwrap_or_else(|crate::platform::PlatformError(reason)| panic!("{reason}"));
        let by_source = Accepted {
            measurement: Some(&this_node),
            predecessors: &[],
            proofs: Some(Proofs {
                value: &case.proofs,
                trust: &source.proofs,
            }),
        };
        assert_eq!(taken(by_source, document(case.pcrs, "v9.9.0")), None);

        // The measurement of the node itself is the same program, whatever proofs the call
        // carries and whatever release the binding names: no proofs are read for it.
        let own_peer = document(this_node.pcrs, "anything");
        assert_eq!(taken(proven, own_peer.clone()), Some(Program::Same));
        let garbage = ProofCase {
            proofs: json!("not proofs"),
            ..proof_case("proofs that hold")
        };
        assert_eq!(
            taken(with_proofs(Some(&this_node), &garbage), own_peer),
            Some(Program::Same)
        );
        // A node whose measurement is the one the proofs show takes the peer as the same
        // program as well.
        let same = Measurement { pcrs: case.pcrs };
        assert_eq!(
            taken(
                with_proofs(Some(&same), &case),
                document(case.pcrs, "v9.9.0")
            ),
            Some(Program::Same)
        );
        // A node without a measurement accepts no nitro peer, also not a proven one.
        assert_eq!(
            taken(with_proofs(None, &case), document(case.pcrs, "v9.9.0")),
            None
        );
        // A listed old release is taken by the list, with or without proofs beside it.
        let listed = [ReleaseMeasurement {
            release: "v1.1.0".to_string(),
            pcrs: case.pcrs,
        }];
        let both = Accepted {
            measurement: Some(&this_node),
            predecessors: &listed,
            proofs: Some(Proofs {
                value: &case.proofs,
                trust: &case.trust,
            }),
        };
        assert_eq!(
            taken(both, document(case.pcrs, "v1.1.0")),
            Some(Program::Release(listed[0].clone()))
        );
        assert_eq!(taken(both, document(case.pcrs, "v9.9.0")), Some(shown));
        // A debug-mode measurement is never accepted, whatever the proofs say of it.
        let mut debug = case.pcrs;
        debug[1] = [0; 48];
        assert_eq!(taken(proven, document(debug, "v9.9.0")), None);
    }

    #[test]
    fn a_real_nitro_peer_of_another_release_verifies_under_the_release_proofs_of_its_measurement() {
        // The node is another program. The proofs show the measurement of the real document
        // and name the release its binding names.
        let case = proof_case("the proofs of the measurement of a recorded attestation document");
        assert_eq!(case.pcrs, operational_measurement().pcrs);
        assert_eq!(case.release, OPERATIONAL_RELEASE);
        let this_node = other_measurement();
        let verify = |accepted: Accepted<'_>| {
            verify_peer(
                "nitro",
                accepted,
                None,
                &response("nitro", OPERATIONAL_DOCUMENT),
            )
        };
        let peer = verify(with_proofs(Some(&this_node), &case))
            .expect("the document has the measurement the proofs show and names their release");
        assert_eq!(peer.node(), "QkJRkEKP6EwK2iiQQnQaoqfydMV9RvHVsA3t2zJEkHo");
        assert_eq!(peer.program(), &Program::Release(operational_release()));
        // Without the proofs the node does not accept that peer, and neither with the proofs
        // of another measurement.
        assert_eq!(
            verify(own(Some(&this_node))),
            Err(ProtocolError::PeerUnverified)
        );
        let other = proof_case("proofs that hold");
        assert_eq!(
            verify(with_proofs(Some(&this_node), &other)),
            Err(ProtocolError::PeerUnverified)
        );
        // The binding of the peer names no log store: a node that has one refuses it.
        let log = LogStoreId::parse("credential-log-test-1", "us-west-2").unwrap();
        assert_eq!(
            verify_peer(
                "nitro",
                with_proofs(Some(&this_node), &case),
                Some(&log),
                &response("nitro", OPERATIONAL_DOCUMENT),
            ),
            Err(ProtocolError::PeerUnverified)
        );
        // A changed document under the measurement it states.
        let mut changed = OPERATIONAL_DOCUMENT.to_vec();
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(
            verify_peer(
                "nitro",
                with_proofs(Some(&this_node), &case),
                None,
                &response("nitro", &changed)
            ),
            Err(ProtocolError::PeerUnverified)
        );
    }

    #[test]
    fn a_node_of_the_local_platform_reads_no_release_proofs() {
        // A local document states no measurement. A local node takes a local peer as a node
        // of its own program, with or without proofs beside it, and takes no nitro peer.
        let case = proof_case("the proofs of the measurement of a recorded attestation document");
        let keys = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
        let local = local_document(&binding(&keys, OPERATIONAL_RELEASE, None));
        for accepted in [own(None), with_proofs(None, &case)] {
            let peer = verify_peer("local", accepted, None, &response("local", &local)).unwrap();
            assert_eq!(peer.program(), &Program::Same);
            // The real document of the proofs does not make a local node accept it, under
            // the name of either platform.
            for platform in ["local", "nitro"] {
                assert_eq!(
                    verify_peer(
                        "local",
                        accepted,
                        None,
                        &response(platform, OPERATIONAL_DOCUMENT)
                    ),
                    Err(ProtocolError::PeerUnverified),
                    "{platform}"
                );
            }
        }
        // A nitro node takes no local peer, with or without proofs.
        let this_node = other_measurement();
        for accepted in [own(Some(&this_node)), with_proofs(Some(&this_node), &case)] {
            assert_eq!(
                verify_peer("nitro", accepted, None, &response("local", &local)),
                Err(ProtocolError::PeerUnverified)
            );
        }
    }

    #[test]
    fn a_real_nitro_peer_of_a_listed_old_release_verifies() {
        // The receiving node is another program that lists the release of the real document.
        let this_node = other_measurement();
        let verify = |predecessors: &[ReleaseMeasurement]| {
            verify_peer(
                "nitro",
                with_list(Some(&this_node), predecessors),
                None,
                &response("nitro", OPERATIONAL_DOCUMENT),
            )
        };
        let peer = verify(&[operational_release()])
            .expect("the document has the measurement and the release of an element");
        assert_eq!(peer.node(), "QkJRkEKP6EwK2iiQQnQaoqfydMV9RvHVsA3t2zJEkHo");
        assert_eq!(peer.program(), &Program::Release(operational_release()));
        // The element is found among others.
        let mut unrelated = operational_release();
        unrelated.pcrs[1] = [0xee; 48];
        assert!(verify(&[unrelated.clone(), operational_release()]).is_ok());

        // No list, a list without that measurement, and an element with that measurement
        // whose release is not the release of the binding.
        assert_eq!(verify(&[]), Err(ProtocolError::PeerUnverified));
        assert_eq!(verify(&[unrelated]), Err(ProtocolError::PeerUnverified));
        let mut other_release = operational_release();
        other_release.release = "v0.0.0-diag.other".to_string();
        assert_eq!(verify(&[other_release]), Err(ProtocolError::PeerUnverified));
        for index in 0..3 {
            let mut other = operational_release();
            other.pcrs[index][0] ^= 1;
            assert_eq!(
                verify(&[other]),
                Err(ProtocolError::PeerUnverified),
                "PCR{index}"
            );
        }
        // A node without a measurement accepts no nitro peer.
        assert_eq!(
            verify_peer(
                "nitro",
                with_list(None, &[operational_release()]),
                None,
                &response("nitro", OPERATIONAL_DOCUMENT),
            ),
            Err(ProtocolError::PeerUnverified)
        );
    }

    #[test]
    fn the_old_releases_of_this_source_are_taken_by_their_measurement_and_their_release() {
        // Every element of the list of this source is the rule of one release: a peer with
        // the measurement of the element whose binding names its release.
        let lineage = crate::lineage::Lineage::embedded()
            .unwrap_or_else(|crate::platform::PlatformError(reason)| panic!("{reason}"));
        let keys = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
        let this_node = other_measurement();
        assert_eq!(lineage.predecessors.len(), 6);
        for element in &lineage.predecessors {
            let document = |release: &str| NitroDocument {
                module_id: "i-0123456789abcdef0-enc0123456789abcdef".to_string(),
                timestamp_ms: 1_790_000_000_000,
                pcr0: element.pcrs[0],
                pcr1: element.pcrs[1],
                pcr2: element.pcrs[2],
                user_data: Some(binding(&keys, release, None)),
                nonce: Some(vec![0x5a; 32]),
            };
            let receiving = Accepted {
                measurement: Some(&this_node),
                predecessors: &lineage.predecessors,
                proofs: None,
            };
            assert_eq!(
                nitro_binding(receiving, document(&element.release)).map(|(_, program)| program),
                Some(Program::Release(element.clone())),
                "{}",
                element.release
            );
            assert_eq!(nitro_binding(receiving, document("v2.4.0")), None);
            // A giving node passes no old release: it hands nothing to one.
            assert_eq!(
                nitro_binding(own(Some(&this_node)), document(&element.release)),
                None
            );
        }
    }

    fn local_document(binding: &[u8]) -> Vec<u8> {
        crate::platform::local::local_document(binding, &[0x5a; 32], 1_790_000_000_000)
    }

    #[test]
    fn a_local_peer_is_read_from_its_unsigned_document() {
        let keys = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
        let document = local_document(&binding(&keys, "v1.0.0", None));
        let peer = verify_peer("local", own(None), None, &response("local", &document)).unwrap();
        assert_eq!(peer.sign_public, keys.sign_public());
        assert_eq!(peer.seal_public, keys.seal_public());
        assert_eq!(peer.node(), keys.node());

        let refused = |response: serde_json::Value| {
            verify_peer("local", own(None), None, &response) == Err(ProtocolError::PeerUnverified)
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
        // A delegation goes to a node that holds delegations: one whose binding names no
        // role, and one of the reserve role. It goes to no node of the forward role, and a
        // binding that names any other role is no binding.
        assert!(!refused(binding_with(
            |binding| binding["role"] = json!("reserve")
        )));
        for role in ["forward", "delegation", "Reserve", "witness", ""] {
            let keys = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
            let mut value: serde_json::Value =
                serde_json::from_slice(&binding(&keys, "v1.0.0", None)).unwrap();
            value["role"] = json!(role);
            assert!(
                refused(response("local", &local_document(&to_json(&value)))),
                "{role:?}"
            );
        }
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
        let this_node = operational_measurement();

        // A nitro node and a local peer: the peer would hold keys of custody `enclave` as an
        // ordinary process. The real document under the name of the local platform fares no
        // better.
        for document in [&local[..], OPERATIONAL_DOCUMENT] {
            assert_eq!(
                verify_peer(
                    "nitro",
                    own(Some(&this_node)),
                    None,
                    &response("local", document)
                ),
                Err(ProtocolError::PeerUnverified)
            );
        }
        // A local document under the name of the nitro platform is not a COSE structure.
        assert_eq!(
            verify_peer(
                "nitro",
                own(Some(&this_node)),
                None,
                &response("nitro", &local)
            ),
            Err(ProtocolError::PeerUnverified)
        );
        // A local node and a nitro peer, whatever the document.
        for document in [&local[..], OPERATIONAL_DOCUMENT] {
            assert_eq!(
                verify_peer("local", own(None), None, &response("nitro", document)),
                Err(ProtocolError::PeerUnverified)
            );
        }
        // A local node does not read a Nitro document as a local one.
        assert_eq!(
            verify_peer(
                "local",
                own(None),
                None,
                &response("local", OPERATIONAL_DOCUMENT)
            ),
            Err(ProtocolError::PeerUnverified)
        );
        // A platform this program does not know.
        assert_eq!(
            verify_peer("sev", own(None), None, &response("sev", &local)),
            Err(ProtocolError::PeerUnverified)
        );
    }
}
