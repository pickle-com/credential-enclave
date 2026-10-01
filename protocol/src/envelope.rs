//! The command envelope an app sends to a node, the command inside it and the signed reply
//! (protocol.md section 5), and the envelope in which a node hands delegations to another node
//! (protocol.md 10.1). This module also holds the single-shot HPKE seal and open that the
//! envelopes and the log entry use (protocol.md section 2).

use std::fmt;

use ed25519_dalek::Signer;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::rand_core::{CryptoRng, RngCore};
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::encoding::{b64u, b64u_decode, b64u_decode_array, to_json, verify_detached};
use crate::encoding::{wipe_json, Signed};
use crate::keys::{node_id, Custody, NodeKeys};
use crate::log::Head;
use crate::secret::Secret;
use crate::{is_valid_name, limits, purpose, ProtocolError};

/// `envelope` = `JSON {"v":1,"node":<node>,"enc":b64u,"ct":b64u}` (5.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u8,
    pub node: String,
    pub enc: String,
    pub ct: String,
}

impl Envelope {
    /// Reads an envelope from parsed JSON. A `v` other than the integer 1 is
    /// `unsupported_version`. A missing or non-string `node`, `enc` or `ct` is
    /// `invalid_request`. Keys the protocol does not define are ignored.
    pub fn from_value(value: &serde_json::Value) -> Result<Envelope, ProtocolError> {
        let object = value.as_object().ok_or(ProtocolError::InvalidRequest)?;
        if object.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
            return Err(ProtocolError::UnsupportedVersion);
        }
        let text = |key: &str| {
            object
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .ok_or(ProtocolError::InvalidRequest)
        };
        Ok(Envelope {
            v: 1,
            node: text("node")?,
            enc: text("enc")?,
            ct: text("ct")?,
        })
    }
}

/// A verified command (5.2). `oauth_code` is a stage 4 command and is not represented.
pub enum Command {
    Grant(Grant),
    Revoke(Revoke),
}

/// The `grant` command: the app hands the user key of `custody` to the node until
/// `not_after_ms`.
pub struct Grant {
    pub user_id: String,
    pub node: String,
    pub challenge: String,
    pub sign_pk: [u8; 32],
    pub log_pk: [u8; 32],
    pub custody: Custody,
    pub user_key: Secret<[u8; 32]>,
    pub not_after_ms: u64,
}

/// The `revoke` command: the app withdraws the delegation.
pub struct Revoke {
    pub user_id: String,
    pub node: String,
    pub challenge: String,
    pub sign_pk: [u8; 32],
}

impl fmt::Debug for Grant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Grant")
            .field("user_id", &self.user_id)
            .field("node", &self.node)
            .field("challenge", &self.challenge)
            .field("sign_pk", &b64u(&self.sign_pk))
            .field("log_pk", &b64u(&self.log_pk))
            .field("custody", &self.custody.as_str())
            .field("user_key", &"<redacted>")
            .field("not_after_ms", &self.not_after_ms)
            .finish()
    }
}

impl fmt::Debug for Revoke {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Revoke")
            .field("user_id", &self.user_id)
            .field("node", &self.node)
            .field("challenge", &self.challenge)
            .field("sign_pk", &b64u(&self.sign_pk))
            .finish()
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Grant(grant) => grant.fmt(formatter),
            Command::Revoke(revoke) => revoke.fmt(formatter),
        }
    }
}

/// Opens a command envelope and verifies the command inside it.
///
/// Performs the checks 1 to 9 of protocol.md 5.3, the ones that need nothing but the node
/// keys, in the order of that table: 1 (`envelope.v`, `envelope.node`), 2 (HPKE open), 3 (JSON),
/// 4 (`payload.v`), 5 (`type`, `sign_pk`), 6 (signature by `payload.sign_pk`), 7
/// (`payload.node`), 8 (the form of the fields) and 9 (`policy`). The node checks the rest
/// against its own platform, state and clock: 10 (`custody`), 11 (`user_id` of the call), 12
/// (challenge) and 13 (`not_after_ms`).
pub fn open_command(keys: &NodeKeys, envelope: &Envelope) -> Result<Command, ProtocolError> {
    // 1
    if envelope.v != 1 {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let node = keys.node();
    if envelope.node != node {
        return Err(ProtocolError::WrongNode);
    }
    // 2
    let enc = b64u_decode(&envelope.enc).map_err(|_| ProtocolError::OpenFailed)?;
    let ct = b64u_decode(&envelope.ct).map_err(|_| ProtocolError::OpenFailed)?;
    let signed = keys
        .open(&enc, purpose::MESSAGE.as_bytes(), node.as_bytes(), &ct)
        .map_err(|_| ProtocolError::OpenFailed)?;
    // 3: the opened envelope holds the user key, so its parsed form is a secret as well.
    let outer = Secret::new(
        serde_json::from_slice::<serde_json::Value>(signed.expose_secret())
            .map_err(|_| ProtocolError::InvalidRequest)?,
    );
    open_signed_command(&node, outer.expose_secret())
}

fn open_signed_command(node: &str, outer: &serde_json::Value) -> Result<Command, ProtocolError> {
    let payload_text = text_field(outer, "payload")?;
    let signature_text = text_field(outer, "sig")?;
    let payload = Zeroizing::new(b64u_decode(payload_text)?);
    let signature = b64u_decode(signature_text)?;
    let mut command: serde_json::Value =
        serde_json::from_slice(&payload).map_err(|_| ProtocolError::InvalidRequest)?;
    let result = verify_command(node, &payload, &signature, &command);
    wipe_json(&mut command);
    result
}

fn verify_command(
    node: &str,
    payload: &[u8],
    signature: &[u8],
    command: &serde_json::Value,
) -> Result<Command, ProtocolError> {
    if !command.is_object() {
        return Err(ProtocolError::InvalidRequest);
    }
    // 4
    if command.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(ProtocolError::UnsupportedVersion);
    }
    // 5
    let kind = text_field(command, "type")?;
    if kind != "grant" && kind != "revoke" {
        return Err(ProtocolError::InvalidRequest);
    }
    let sign_pk: [u8; 32] = b64u_decode_array(text_field(command, "sign_pk")?)?;
    // 6
    verify_detached(&sign_pk, purpose::COMMAND, payload, signature)?;
    // 7
    let payload_node = text_field(command, "node")?;
    if payload_node != node {
        return Err(ProtocolError::WrongNode);
    }
    // 8
    let user_id = text_field(command, "user_id")?;
    if !is_valid_name(user_id) {
        return Err(ProtocolError::InvalidRequest);
    }
    let challenge = text_field(command, "challenge")?;
    if kind == "revoke" {
        return Ok(Command::Revoke(Revoke {
            user_id: user_id.to_string(),
            node: payload_node.to_string(),
            challenge: challenge.to_string(),
            sign_pk,
        }));
    }
    let log_pk: [u8; 32] = b64u_decode_array(text_field(command, "log_pk")?)?;
    if !is_usable_seal_key(&log_pk) {
        return Err(ProtocolError::InvalidRequest);
    }
    let user_key = Secret::new(b64u_decode_array::<32>(text_field(command, "user_key")?)?);
    let not_after_ms = command
        .get("not_after_ms")
        .and_then(serde_json::Value::as_u64)
        .ok_or(ProtocolError::InvalidRequest)?;
    let policy = command
        .get("policy")
        .and_then(serde_json::Value::as_object)
        .ok_or(ProtocolError::InvalidRequest)?;
    let custody =
        Custody::parse(text_field(command, "custody")?).ok_or(ProtocolError::InvalidRequest)?;
    // 9
    if !policy.is_empty() {
        return Err(ProtocolError::UnsupportedPolicy);
    }
    Ok(Command::Grant(Grant {
        user_id: user_id.to_string(),
        node: payload_node.to_string(),
        challenge: challenge.to_string(),
        sign_pk,
        log_pk,
        custody,
        user_key,
        not_after_ms,
    }))
}

fn text_field<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str, ProtocolError> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or(ProtocolError::InvalidRequest)
}

/// The `{seq, hash}` pair a reply carries: the end of the (node, account) chain at reply time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyHead {
    pub seq: u64,
    pub hash: String,
}

impl From<&Head> for ReplyHead {
    fn from(head: &Head) -> Self {
        ReplyHead {
            seq: head.seq,
            hash: b64u(&head.hash),
        }
    }
}

/// The body of a command reply (5.5). `kind` is `grant_reply` or `revoke_reply`. A failure has
/// `ok` false and the failure code in `code`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyBody {
    pub v: u8,
    #[serde(rename = "type")]
    pub kind: String,
    pub ok: bool,
    pub code: String,
    pub node: String,
    pub user_id: String,
    pub challenge: String,
    pub key_id: String,
    pub not_after_ms: u64,
    pub head: ReplyHead,
    pub time_ms: u64,
}

/// Signs a reply body with the node signing key under the context `pickle.secure.v1.reply\n`.
pub fn reply(keys: &NodeKeys, body: &ReplyBody) -> Signed {
    keys.sign(purpose::REPLY, &to_json(body))
}

/// `envelope` = `JSON {"v":1,"from":<giving node>,"to":<receiving node>,"enc":b64u,"ct":b64u}`
/// (10.1): a delegation transfer, sealed to the sealing key of the receiving node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferEnvelope {
    pub v: u8,
    pub from: String,
    pub to: String,
    pub enc: String,
    pub ct: String,
}

impl TransferEnvelope {
    /// Reads a transfer envelope from parsed JSON. A `v` other than the integer 1 is
    /// `unsupported_version`. A missing or non-string `from`, `to`, `enc` or `ct` is
    /// `invalid_request`. Keys the protocol does not define are ignored.
    pub fn from_value(value: &serde_json::Value) -> Result<TransferEnvelope, ProtocolError> {
        let object = value.as_object().ok_or(ProtocolError::InvalidRequest)?;
        if object.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
            return Err(ProtocolError::UnsupportedVersion);
        }
        let text = |key: &str| {
            object
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .ok_or(ProtocolError::InvalidRequest)
        };
        Ok(TransferEnvelope {
            v: 1,
            from: text("from")?,
            to: text("to")?,
            enc: text("enc")?,
            ct: text("ct")?,
        })
    }
}

/// One delegation inside a transfer: what a node holds of an accepted grant.
#[derive(Clone)]
pub struct TransferGrant {
    pub user_id: String,
    pub sign_pk: [u8; 32],
    pub log_pk: [u8; 32],
    pub custody: Custody,
    pub user_key: Secret<[u8; 32]>,
    pub not_after_ms: u64,
}

impl fmt::Debug for TransferGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransferGrant")
            .field("user_id", &self.user_id)
            .field("sign_pk", &b64u(&self.sign_pk))
            .field("log_pk", &b64u(&self.log_pk))
            .field("custody", &self.custody.as_str())
            .field("user_key", &"<redacted>")
            .field("not_after_ms", &self.not_after_ms)
            .finish()
    }
}

/// A transfer that a receiving node opened and verified.
#[derive(Debug)]
pub struct Transfer {
    /// The node time of the giving node when it made the transfer.
    pub time_ms: u64,
    pub grants: Vec<TransferGrant>,
}

#[derive(Serialize)]
struct TransferGrantBody<'a> {
    user_id: &'a str,
    sign_pk: String,
    log_pk: String,
    custody: &'static str,
    user_key: &'a str,
    not_after_ms: u64,
}

#[derive(Serialize)]
struct TransferBody<'a> {
    v: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    from: &'a str,
    to: &'a str,
    time_ms: u64,
    grants: Vec<TransferGrantBody<'a>>,
}

#[derive(Serialize)]
struct SignedTransfer<'a> {
    payload: &'a str,
    sig: &'a str,
}

/// The HPKE AAD of a transfer: `UTF-8(from + "\n" + to)`.
pub fn transfer_aad(from: &str, to: &str) -> Vec<u8> {
    format!("{from}\n{to}").into_bytes()
}

/// The payload of a transfer (10.1):
/// `UTF-8(JSON {"v":1,"type":"transfer","from":..,"to":..,"time_ms":..,"grants":[..]})`.
///
/// The payload holds the user keys of the grants, so it is a secret. It leaves a node inside
/// the seal of [`seal_transfer`] only.
pub fn transfer_payload(
    from: &str,
    to: &str,
    time_ms: u64,
    grants: &[TransferGrant],
) -> Secret<Vec<u8>> {
    let user_keys: Vec<Zeroizing<String>> = grants
        .iter()
        .map(|grant| Zeroizing::new(b64u(grant.user_key.expose_secret())))
        .collect();
    Secret::new(to_json(&TransferBody {
        v: 1,
        kind: "transfer",
        from,
        to,
        time_ms,
        grants: grants
            .iter()
            .zip(&user_keys)
            .map(|(grant, user_key)| TransferGrantBody {
                user_id: &grant.user_id,
                sign_pk: b64u(&grant.sign_pk),
                log_pk: b64u(&grant.log_pk),
                custody: grant.custody.as_str(),
                user_key,
                not_after_ms: grant.not_after_ms,
            })
            .collect(),
    }))
}

/// `signed` = `UTF-8(JSON {"payload": b64u(payload), "sig": b64u(Ed25519(signing key,
/// "pickle.secure.v1.peer\n" || payload))})`: a payload signed with a signing key the caller
/// holds. The vector generator and the tests use it. A node signs with
/// [`NodeKeys::sign_detached`] inside [`seal_transfer`].
pub fn sign_transfer(sign: &ed25519_dalek::SigningKey, payload: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut message = Zeroizing::new(Vec::with_capacity(purpose::PEER.len() + payload.len()));
    message.extend_from_slice(purpose::PEER.as_bytes());
    message.extend_from_slice(payload);
    let signature = sign.sign(&message);
    Zeroizing::new(signed_transfer(payload, &signature.to_bytes()))
}

fn signed_transfer(payload: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let payload_text = Zeroizing::new(b64u(payload));
    to_json(&SignedTransfer {
        payload: &payload_text,
        sig: &b64u(signature),
    })
}

/// Signs a transfer of `grants` with the signing key of the giving node and seals it to the
/// receiving node (10.1): HPKE info `pickle.secure.v1.peer`, AAD [`transfer_aad`].
///
/// `to_sign_public` and `to_seal_public` are the keys of the receiving node, read from its
/// verified attestation. `hpke_seed` is the input keying material of the ephemeral key pair: a
/// node passes 32 fresh random bytes. More than 1,000 grants and a sealing key HPKE cannot seal
/// to are `invalid_request`.
///
/// This function is sink K2 of the egress policy: user keys leave the node inside this seal.
/// The caller verified the attestation of the receiving node before it calls this.
pub fn seal_transfer(
    keys: &NodeKeys,
    to_sign_public: &[u8; 32],
    to_seal_public: &[u8; 32],
    time_ms: u64,
    grants: &[TransferGrant],
    hpke_seed: &Secret<[u8; 32]>,
) -> Result<TransferEnvelope, ProtocolError> {
    if grants.len() > limits::TRANSFER_GRANTS {
        return Err(ProtocolError::InvalidRequest);
    }
    let from = keys.node();
    let to = node_id(to_sign_public);
    let payload = transfer_payload(&from, &to, time_ms, grants);
    let signature = keys.sign_detached(purpose::PEER, payload.expose_secret());
    let signed = Secret::new(signed_transfer(payload.expose_secret(), &signature));
    let (enc, ct) = hpke_seal(
        to_seal_public,
        purpose::PEER_SEAL.as_bytes(),
        &transfer_aad(&from, &to),
        signed.expose_secret(),
        hpke_seed.expose_secret(),
    )?;
    Ok(TransferEnvelope {
        v: 1,
        from,
        to,
        enc: b64u(&enc),
        ct: b64u(&ct),
    })
}

/// Opens a transfer envelope as the receiving node and verifies the transfer inside it.
///
/// `from_sign_public` is the signing key of the giving node, read from its verified
/// attestation. The checks, in this order (10.1, receiving node, step 2):
///
/// | Check | Failure |
/// | --- | --- |
/// | `envelope.v` is 1 | `unsupported_version` |
/// | `envelope.to` is this node and `envelope.from` is the giving node | `wrong_node` |
/// | `enc` and `ct` are base64url and the HPKE open succeeds | `open_failed` |
/// | `signed` is JSON with base64url `payload` and `sig` | `invalid_request` |
/// | `sig` verifies under the signing key of the giving node | `bad_signature` |
/// | `payload` is a JSON object | `invalid_request` |
/// | `payload.v` is 1 | `unsupported_version` |
/// | `payload.type` is `transfer` | `invalid_request` |
/// | `payload.from` and `payload.to` equal those of the envelope | `wrong_node` |
/// | `time_ms`, at most 1,000 grants, the form of every grant | `invalid_request` |
///
/// The signature is verified over the payload bytes as carried, before they are parsed. A
/// grant has the form of protocol.md 5.3 step 8: a valid `user_id`, 32-byte keys, a `log_pk`
/// HPKE can seal to, a known `custody` and an unsigned `not_after_ms`.
pub fn open_transfer(
    keys: &NodeKeys,
    from_sign_public: &[u8; 32],
    envelope: &TransferEnvelope,
) -> Result<Transfer, ProtocolError> {
    if envelope.v != 1 {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let node = keys.node();
    let from = node_id(from_sign_public);
    if envelope.to != node || envelope.from != from {
        return Err(ProtocolError::WrongNode);
    }
    let enc = b64u_decode(&envelope.enc).map_err(|_| ProtocolError::OpenFailed)?;
    let ct = b64u_decode(&envelope.ct).map_err(|_| ProtocolError::OpenFailed)?;
    let signed = keys
        .open(
            &enc,
            purpose::PEER_SEAL.as_bytes(),
            &transfer_aad(&from, &node),
            &ct,
        )
        .map_err(|_| ProtocolError::OpenFailed)?;
    // The opened envelope holds user keys, so its parsed form is a secret as well.
    let outer = Secret::new(
        serde_json::from_slice::<serde_json::Value>(signed.expose_secret())
            .map_err(|_| ProtocolError::InvalidRequest)?,
    );
    open_signed_transfer(from_sign_public, &from, &node, outer.expose_secret())
}

fn open_signed_transfer(
    from_sign_public: &[u8; 32],
    from: &str,
    to: &str,
    outer: &serde_json::Value,
) -> Result<Transfer, ProtocolError> {
    let payload = Zeroizing::new(b64u_decode(text_field(outer, "payload")?)?);
    let signature = b64u_decode(text_field(outer, "sig")?)?;
    verify_detached(from_sign_public, purpose::PEER, &payload, &signature)?;
    let mut body: serde_json::Value =
        serde_json::from_slice(&payload).map_err(|_| ProtocolError::InvalidRequest)?;
    let result = read_transfer(from, to, &body);
    wipe_json(&mut body);
    result
}

fn read_transfer(
    from: &str,
    to: &str,
    body: &serde_json::Value,
) -> Result<Transfer, ProtocolError> {
    if !body.is_object() {
        return Err(ProtocolError::InvalidRequest);
    }
    if body.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(ProtocolError::UnsupportedVersion);
    }
    if text_field(body, "type")? != "transfer" {
        return Err(ProtocolError::InvalidRequest);
    }
    if text_field(body, "from")? != from || text_field(body, "to")? != to {
        return Err(ProtocolError::WrongNode);
    }
    let time_ms = body
        .get("time_ms")
        .and_then(serde_json::Value::as_u64)
        .ok_or(ProtocolError::InvalidRequest)?;
    let items = body
        .get("grants")
        .and_then(serde_json::Value::as_array)
        .ok_or(ProtocolError::InvalidRequest)?;
    if items.len() > limits::TRANSFER_GRANTS {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut grants = Vec::with_capacity(items.len());
    for item in items {
        let user_id = text_field(item, "user_id")?;
        if !is_valid_name(user_id) {
            return Err(ProtocolError::InvalidRequest);
        }
        let log_pk: [u8; 32] = b64u_decode_array(text_field(item, "log_pk")?)?;
        if !is_usable_seal_key(&log_pk) {
            return Err(ProtocolError::InvalidRequest);
        }
        grants.push(TransferGrant {
            user_id: user_id.to_string(),
            sign_pk: b64u_decode_array(text_field(item, "sign_pk")?)?,
            log_pk,
            custody: Custody::parse(text_field(item, "custody")?)
                .ok_or(ProtocolError::InvalidRequest)?,
            user_key: Secret::new(b64u_decode_array::<32>(text_field(item, "user_key")?)?),
            not_after_ms: item
                .get("not_after_ms")
                .and_then(serde_json::Value::as_u64)
                .ok_or(ProtocolError::InvalidRequest)?,
        });
    }
    Ok(Transfer { time_ms, grants })
}

/// True when HPKE can seal to `public_key`: the X25519 function does not map it to the all-zero
/// output. RFC 9180 section 7.1.4 requires a sender to abort on an all-zero shared secret, so a
/// node could not write log entries for a `log_pk` that fails this check.
pub fn is_usable_seal_key(public_key: &[u8; 32]) -> bool {
    // The shared secret is all zero exactly when the point has small order, for every clamped
    // scalar. One fixed scalar decides it.
    let probe = StaticSecret::from([0x42u8; 32]);
    probe
        .diffie_hellman(&PublicKey::from(*public_key))
        .was_contributory()
}

/// A random source that yields one fixed 32-byte value. The HPKE sender reads exactly 32 bytes
/// to derive its ephemeral key pair, so the ephemeral key pair becomes
/// `DeriveKeyPair(seed)` of RFC 9180 section 7.1.3.
struct SeedSource {
    seed: Zeroizing<[u8; 32]>,
    used: bool,
}

impl RngCore for SeedSource {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        self.try_fill_bytes(destination)
            .expect("the HPKE sender reads its 32-byte key material exactly once");
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), hpke::rand_core::Error> {
        if self.used || destination.len() != self.seed.len() {
            return Err(hpke::rand_core::Error::from(
                core::num::NonZeroU32::new(hpke::rand_core::Error::CUSTOM_START)
                    .expect("CUSTOM_START is not zero"),
            ));
        }
        destination.copy_from_slice(self.seed.as_slice());
        self.used = true;
        Ok(())
    }
}

impl CryptoRng for SeedSource {}

type SealKem = X25519HkdfSha256;
type SealKdf = HkdfSha256;
type SealAead = ChaCha20Poly1305;

/// Single-shot HPKE seal in base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
/// ChaCha20-Poly1305. Returns `enc` (32 bytes) and `ct` (ciphertext followed by the 16-byte
/// tag).
///
/// `seed` is the input keying material of the ephemeral key pair: the pair is
/// `DeriveKeyPair(seed)` (RFC 9180 section 7.1.3). A caller outside of tests and vector
/// generation passes 32 fresh random bytes.
pub fn hpke_seal(
    recipient_public: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    seed: &[u8; 32],
) -> Result<([u8; 32], Vec<u8>), ProtocolError> {
    let recipient = <SealKem as Kem>::PublicKey::from_bytes(recipient_public)
        .map_err(|_| ProtocolError::InvalidRequest)?;
    let mut source = SeedSource {
        seed: Zeroizing::new(*seed),
        used: false,
    };
    let (enc, ct) = hpke::single_shot_seal::<SealAead, SealKdf, SealKem, _>(
        &OpModeS::Base,
        &recipient,
        info,
        plaintext,
        aad,
        &mut source,
    )
    .map_err(|_| ProtocolError::InvalidRequest)?;
    let mut enc_bytes = [0u8; 32];
    enc_bytes.copy_from_slice(&enc.to_bytes());
    Ok((enc_bytes, ct))
}

/// Single-shot HPKE open, the inverse of [`hpke_seal`]. Every failure is `open_failed`.
pub fn hpke_open(
    recipient_private: &StaticSecret,
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let mut private_bytes = recipient_private.to_bytes();
    let private = <SealKem as Kem>::PrivateKey::from_bytes(&private_bytes);
    private_bytes.zeroize();
    let private = private.map_err(|_| ProtocolError::OpenFailed)?;
    let enc =
        <SealKem as Kem>::EncappedKey::from_bytes(enc).map_err(|_| ProtocolError::OpenFailed)?;
    hpke::single_shot_open::<SealAead, SealKdf, SealKem>(
        &OpModeR::Base,
        &private,
        &enc,
        info,
        ct,
        aad,
    )
    .map(Zeroizing::new)
    .map_err(|_| ProtocolError::OpenFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{self, AccountKeys};
    use ed25519_dalek::SigningKey;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }

    fn array(text: &str) -> [u8; 32] {
        <[u8; 32]>::try_from(hex(text).as_slice()).unwrap()
    }

    #[test]
    fn hpke_matches_rfc_9180_appendix_a_2_1() {
        // RFC 9180 A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, base mode.
        let ikm_e = array("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b");
        let pk_e = array("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        let ikm_r = hex("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df");
        let sk_r = array("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        let pk_r = array("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
        let info = hex("4f6465206f6e2061204772656369616e2055726e");
        let plaintext = hex("4265617574792069732074727574682c20747275746820626561757479");
        let aad = hex("436f756e742d30");
        let expected_ct = hex(concat!(
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db",
            "21993c62ce81883d2dd1b51a28"
        ));

        let (derived_private, derived_public) = <SealKem as Kem>::derive_keypair(&ikm_r);
        assert_eq!(derived_private.to_bytes().as_slice(), sk_r.as_slice());
        assert_eq!(derived_public.to_bytes().as_slice(), pk_r.as_slice());

        let (enc, ct) = hpke_seal(&pk_r, &info, &aad, &plaintext, &ikm_e).unwrap();
        assert_eq!(enc, pk_e);
        assert_eq!(ct, expected_ct);

        let opened = hpke_open(&StaticSecret::from(sk_r), &enc, &info, &aad, &ct).unwrap();
        assert_eq!(opened.as_slice(), plaintext.as_slice());
        assert_eq!(
            hpke_open(&StaticSecret::from(sk_r), &enc, &info, b"Count-1", &ct).map(|_| ()),
            Err(ProtocolError::OpenFailed)
        );
    }

    #[test]
    fn small_order_public_keys_cannot_be_sealed_to() {
        assert!(!is_usable_seal_key(&[0u8; 32]));
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(!is_usable_seal_key(&one));
        let usable = PublicKey::from(&StaticSecret::from([5u8; 32])).to_bytes();
        assert!(is_usable_seal_key(&usable));
        assert_eq!(
            hpke_seal(&[0u8; 32], b"info", b"aad", b"text", &[1u8; 32]).map(|_| ()),
            Err(ProtocolError::InvalidRequest)
        );
    }

    struct Fixture {
        node: NodeKeys,
        account: AccountKeys,
    }

    fn fixture() -> Fixture {
        Fixture {
            node: NodeKeys::from_random(&[0x11; 32], &[0x22; 32]),
            account: app::derive_account_keys(&[0x33; 32]),
        }
    }

    fn grant_value(fixture: &Fixture) -> serde_json::Value {
        serde_json::json!({
            "v": 1,
            "type": "grant",
            "user_id": "user-1",
            "node": fixture.node.node(),
            "challenge": b64u(&[0x44; 16]),
            "sign_pk": b64u(&fixture.account.sign_pk()),
            "log_pk": b64u(&fixture.account.log_pk()),
            "custody": "enclave",
            "user_key": b64u(fixture.account.user_key.as_slice()),
            "not_after_ms": 1_800_000_000_000u64,
            "policy": {},
        })
    }

    fn seal(fixture: &Fixture, payload: &serde_json::Value) -> Envelope {
        app::seal_command(
            &fixture.account.sign,
            &fixture.node.seal_public(),
            &fixture.node.node(),
            &to_json(payload),
            &[0x55; 32],
        )
        .unwrap()
    }

    fn open_error(fixture: &Fixture, envelope: &Envelope) -> ProtocolError {
        match open_command(&fixture.node, envelope) {
            Ok(_) => panic!("the command must be rejected"),
            Err(error) => error,
        }
    }

    #[test]
    fn a_grant_opens_to_its_fields() {
        let fixture = fixture();
        let envelope = seal(&fixture, &grant_value(&fixture));
        let Command::Grant(grant) = open_command(&fixture.node, &envelope).unwrap() else {
            panic!("expected a grant");
        };
        assert_eq!(grant.user_id, "user-1");
        assert_eq!(grant.node, fixture.node.node());
        assert_eq!(grant.challenge, b64u(&[0x44; 16]));
        assert_eq!(grant.sign_pk, fixture.account.sign_pk());
        assert_eq!(grant.log_pk, fixture.account.log_pk());
        assert_eq!(grant.custody, Custody::Enclave);
        assert_eq!(
            grant.user_key.expose_secret(),
            fixture.account.user_key.as_slice()
        );
        assert_eq!(grant.not_after_ms, 1_800_000_000_000);
        let debug = format!("{grant:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&b64u(fixture.account.user_key.as_slice())));
    }

    #[test]
    fn a_revoke_opens_to_its_fields() {
        let fixture = fixture();
        let payload = serde_json::json!({
            "v": 1,
            "type": "revoke",
            "user_id": "user-1",
            "node": fixture.node.node(),
            "challenge": b64u(&[0x44; 16]),
            "sign_pk": b64u(&fixture.account.sign_pk()),
        });
        let envelope = seal(&fixture, &payload);
        let Command::Revoke(revoke) = open_command(&fixture.node, &envelope).unwrap() else {
            panic!("expected a revoke");
        };
        assert_eq!(revoke.user_id, "user-1");
        assert_eq!(revoke.sign_pk, fixture.account.sign_pk());
    }

    #[test]
    fn step_1_rejects_other_versions_and_other_nodes() {
        let fixture = fixture();
        let mut envelope = seal(&fixture, &grant_value(&fixture));
        envelope.v = 2;
        assert_eq!(
            open_error(&fixture, &envelope),
            ProtocolError::UnsupportedVersion
        );

        let other = NodeKeys::from_random(&[0x66; 32], &[0x77; 32]);
        let mut envelope = seal(&fixture, &grant_value(&fixture));
        envelope.node = other.node();
        assert_eq!(open_error(&fixture, &envelope), ProtocolError::WrongNode);

        assert_eq!(
            Envelope::from_value(&serde_json::json!({"v": 2, "node": "n", "enc": "", "ct": ""})),
            Err(ProtocolError::UnsupportedVersion)
        );
        assert_eq!(
            Envelope::from_value(&serde_json::json!({"node": "n", "enc": "", "ct": ""})),
            Err(ProtocolError::UnsupportedVersion)
        );
        assert_eq!(
            Envelope::from_value(&serde_json::json!({"v": 1, "node": "n", "enc": ""})),
            Err(ProtocolError::InvalidRequest)
        );
        let parsed = Envelope::from_value(
            &serde_json::json!({"v": 1, "node": "n", "enc": "e", "ct": "c", "extra": true}),
        )
        .unwrap();
        assert_eq!(parsed.node, "n");
    }

    #[test]
    fn step_2_rejects_an_envelope_sealed_for_another_key_or_another_node_name() {
        let fixture = fixture();
        let envelope = seal(&fixture, &grant_value(&fixture));

        let mut flipped = envelope.clone();
        let mut ct = b64u_decode(&flipped.ct).unwrap();
        ct[0] ^= 1;
        flipped.ct = b64u(&ct);
        assert_eq!(open_error(&fixture, &flipped), ProtocolError::OpenFailed);

        let mut garbled = envelope.clone();
        garbled.enc = "***".to_string();
        assert_eq!(open_error(&fixture, &garbled), ProtocolError::OpenFailed);

        // Sealed with another node name as AAD: the node name is bound into the seal.
        let other_aad = app::seal_command(
            &fixture.account.sign,
            &fixture.node.seal_public(),
            "another-node",
            &to_json(&grant_value(&fixture)),
            &[0x55; 32],
        )
        .unwrap();
        let replayed = Envelope {
            node: fixture.node.node(),
            ..other_aad
        };
        assert_eq!(open_error(&fixture, &replayed), ProtocolError::OpenFailed);
    }

    #[test]
    fn step_4_rejects_a_command_of_another_version() {
        let fixture = fixture();
        let mut wrong_version = grant_value(&fixture);
        wrong_version["v"] = serde_json::json!(2);
        assert_eq!(
            open_error(&fixture, &seal(&fixture, &wrong_version)),
            ProtocolError::UnsupportedVersion
        );
        let mut no_version = grant_value(&fixture);
        no_version.as_object_mut().unwrap().remove("v");
        assert_eq!(
            open_error(&fixture, &seal(&fixture, &no_version)),
            ProtocolError::UnsupportedVersion
        );
        // The version is read before the type: a command of another version may be of a type
        // this version does not know.
        let mut both = grant_value(&fixture);
        both["v"] = serde_json::json!(2);
        both["type"] = serde_json::json!("oauth_code");
        assert_eq!(
            open_error(&fixture, &seal(&fixture, &both)),
            ProtocolError::UnsupportedVersion
        );
    }

    #[test]
    fn steps_3_and_5_reject_malformed_commands_and_the_stage_4_command() {
        let fixture = fixture();
        let mut stage_4 = grant_value(&fixture);
        stage_4["type"] = serde_json::json!("oauth_code");
        assert_eq!(
            open_error(&fixture, &seal(&fixture, &stage_4)),
            ProtocolError::InvalidRequest
        );

        let not_json = app::seal_command(
            &fixture.account.sign,
            &fixture.node.seal_public(),
            &fixture.node.node(),
            b"not json",
            &[0x55; 32],
        )
        .unwrap();
        assert_eq!(
            open_error(&fixture, &not_json),
            ProtocolError::InvalidRequest
        );

        let not_an_object = app::seal_command(
            &fixture.account.sign,
            &fixture.node.seal_public(),
            &fixture.node.node(),
            b"[1]",
            &[0x55; 32],
        )
        .unwrap();
        assert_eq!(
            open_error(&fixture, &not_an_object),
            ProtocolError::InvalidRequest
        );

        let mut short_key = grant_value(&fixture);
        short_key["sign_pk"] = serde_json::json!(b64u(&[1u8; 31]));
        assert_eq!(
            open_error(&fixture, &seal(&fixture, &short_key)),
            ProtocolError::InvalidRequest
        );
    }

    #[test]
    fn step_6_rejects_a_command_signed_by_another_key() {
        let fixture = fixture();
        let other = app::derive_account_keys(&[0x99; 32]);
        let envelope = app::seal_command(
            &other.sign,
            &fixture.node.seal_public(),
            &fixture.node.node(),
            &to_json(&grant_value(&fixture)),
            &[0x55; 32],
        )
        .unwrap();
        assert_eq!(open_error(&fixture, &envelope), ProtocolError::BadSignature);
    }

    #[test]
    fn step_7_rejects_a_command_addressed_to_another_node() {
        let fixture = fixture();
        let mut payload = grant_value(&fixture);
        payload["node"] = serde_json::json!(NodeKeys::from_random(&[1; 32], &[2; 32]).node());
        assert_eq!(
            open_error(&fixture, &seal(&fixture, &payload)),
            ProtocolError::WrongNode
        );
    }

    #[test]
    fn step_8_rejects_fields_of_the_wrong_form() {
        let fixture = fixture();
        for key in ["log_pk", "user_key"] {
            let mut payload = grant_value(&fixture);
            payload[key] = serde_json::json!(b64u(&[1u8; 31]));
            assert_eq!(
                open_error(&fixture, &seal(&fixture, &payload)),
                ProtocolError::InvalidRequest,
                "{key}"
            );
        }
        let mut small_order = grant_value(&fixture);
        small_order["log_pk"] = serde_json::json!(b64u(&[0u8; 32]));
        assert_eq!(
            open_error(&fixture, &seal(&fixture, &small_order)),
            ProtocolError::InvalidRequest
        );
        let mut no_expiry = grant_value(&fixture);
        no_expiry["not_after_ms"] = serde_json::json!("soon");
        assert_eq!(
            open_error(&fixture, &seal(&fixture, &no_expiry)),
            ProtocolError::InvalidRequest
        );
        let mut negative_expiry = grant_value(&fixture);
        negative_expiry["not_after_ms"] = serde_json::json!(-1);
        assert_eq!(
            open_error(&fixture, &seal(&fixture, &negative_expiry)),
            ProtocolError::InvalidRequest
        );
        let mut long_user = grant_value(&fixture);
        long_user["user_id"] = serde_json::json!("u".repeat(129));
        assert_eq!(
            open_error(&fixture, &seal(&fixture, &long_user)),
            ProtocolError::InvalidRequest
        );
        let mut no_challenge = grant_value(&fixture);
        no_challenge["challenge"] = serde_json::json!(7);
        assert_eq!(
            open_error(&fixture, &seal(&fixture, &no_challenge)),
            ProtocolError::InvalidRequest
        );
    }

    #[test]
    fn step_8_reads_the_custody_of_a_grant() {
        let fixture = fixture();
        let mut operator = grant_value(&fixture);
        operator["custody"] = serde_json::json!("operator");
        let Command::Grant(grant) =
            open_command(&fixture.node, &seal(&fixture, &operator)).unwrap()
        else {
            panic!("expected a grant");
        };
        assert_eq!(grant.custody, Custody::Operator);

        for other in [
            serde_json::json!("hsm"),
            serde_json::json!(""),
            serde_json::json!(1),
        ] {
            let mut payload = grant_value(&fixture);
            payload["custody"] = other.clone();
            assert_eq!(
                open_error(&fixture, &seal(&fixture, &payload)),
                ProtocolError::InvalidRequest,
                "{other}"
            );
        }
        let mut missing = grant_value(&fixture);
        missing.as_object_mut().unwrap().remove("custody");
        assert_eq!(
            open_error(&fixture, &seal(&fixture, &missing)),
            ProtocolError::InvalidRequest
        );
        // A revoke carries no custody.
        let revoke = serde_json::json!({
            "v": 1,
            "type": "revoke",
            "user_id": "user-1",
            "node": fixture.node.node(),
            "challenge": b64u(&[0x44; 16]),
            "sign_pk": b64u(&fixture.account.sign_pk()),
        });
        assert!(matches!(
            open_command(&fixture.node, &seal(&fixture, &revoke)),
            Ok(Command::Revoke(_))
        ));
    }

    #[test]
    fn step_9_rejects_any_policy_key() {
        let fixture = fixture();
        let mut payload = grant_value(&fixture);
        payload["policy"] = serde_json::json!({"approve": true});
        assert_eq!(
            open_error(&fixture, &seal(&fixture, &payload)),
            ProtocolError::UnsupportedPolicy
        );
        let mut missing = grant_value(&fixture);
        missing.as_object_mut().unwrap().remove("policy");
        assert_eq!(
            open_error(&fixture, &seal(&fixture, &missing)),
            ProtocolError::InvalidRequest
        );
    }

    #[test]
    fn unknown_command_keys_are_ignored() {
        let fixture = fixture();
        let mut payload = grant_value(&fixture);
        payload["future"] = serde_json::json!({"x": 1});
        assert!(open_command(&fixture.node, &seal(&fixture, &payload)).is_ok());
    }

    fn transfer_grants() -> Vec<TransferGrant> {
        ["user-a", "user-b"]
            .iter()
            .enumerate()
            .map(|(index, user_id)| {
                let account = app::derive_account_keys(&[0x40 + index as u8; 32]);
                TransferGrant {
                    user_id: user_id.to_string(),
                    sign_pk: account.sign_pk(),
                    log_pk: account.log_pk(),
                    custody: Custody::Enclave,
                    user_key: Secret::new(*account.user_key),
                    not_after_ms: 1_800_000_000_000 + index as u64,
                }
            })
            .collect()
    }

    struct Peers {
        giving: NodeKeys,
        receiving: NodeKeys,
    }

    fn peers() -> Peers {
        Peers {
            giving: NodeKeys::from_random(&[0x11; 32], &[0x22; 32]),
            receiving: NodeKeys::from_random(&[0x33; 32], &[0x44; 32]),
        }
    }

    /// The signing key of the giving node of [`peers`], for the tests that sign a transfer the
    /// node itself would not make.
    fn giving_sign() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    /// Seals arbitrary `signed` bytes the way a giving node seals a transfer.
    fn seal_signed(peers: &Peers, signed: &[u8]) -> TransferEnvelope {
        let from = peers.giving.node();
        let to = peers.receiving.node();
        let (enc, ct) = hpke_seal(
            &peers.receiving.seal_public(),
            purpose::PEER_SEAL.as_bytes(),
            &transfer_aad(&from, &to),
            signed,
            &[0x55; 32],
        )
        .unwrap();
        TransferEnvelope {
            v: 1,
            from,
            to,
            enc: b64u(&enc),
            ct: b64u(&ct),
        }
    }

    /// A transfer whose payload is `change` applied to a well-formed payload, signed by the
    /// giving node.
    fn changed_transfer(peers: &Peers, change: fn(&mut serde_json::Value)) -> TransferEnvelope {
        let payload = transfer_payload(
            &peers.giving.node(),
            &peers.receiving.node(),
            7,
            &transfer_grants(),
        );
        let mut value: serde_json::Value = serde_json::from_slice(payload.expose_secret()).unwrap();
        change(&mut value);
        seal_signed(peers, &sign_transfer(&giving_sign(), &to_json(&value)))
    }

    fn transfer_error(peers: &Peers, envelope: &TransferEnvelope) -> ProtocolError {
        open_transfer(&peers.receiving, &peers.giving.sign_public(), envelope)
            .map(|_| ())
            .unwrap_err()
    }

    #[test]
    fn a_transfer_opens_to_its_grants() {
        let peers = peers();
        let grants = transfer_grants();
        let envelope = seal_transfer(
            &peers.giving,
            &peers.receiving.sign_public(),
            &peers.receiving.seal_public(),
            1_790_000_000_000,
            &grants,
            &Secret::new([0x55; 32]),
        )
        .unwrap();
        assert_eq!(envelope.v, 1);
        assert_eq!(envelope.from, peers.giving.node());
        assert_eq!(envelope.to, peers.receiving.node());
        let transfer =
            open_transfer(&peers.receiving, &peers.giving.sign_public(), &envelope).unwrap();
        assert_eq!(transfer.time_ms, 1_790_000_000_000);
        assert_eq!(transfer.grants.len(), 2);
        for (opened, sent) in transfer.grants.iter().zip(&grants) {
            assert_eq!(opened.user_id, sent.user_id);
            assert_eq!(opened.sign_pk, sent.sign_pk);
            assert_eq!(opened.log_pk, sent.log_pk);
            assert_eq!(opened.custody, sent.custody);
            assert_eq!(
                opened.user_key.expose_secret(),
                sent.user_key.expose_secret()
            );
            assert_eq!(opened.not_after_ms, sent.not_after_ms);
        }
        let debug = format!("{:?}", transfer.grants[0]);
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&b64u(grants[0].user_key.expose_secret())));

        // An empty transfer is a transfer.
        let empty = seal_transfer(
            &peers.giving,
            &peers.receiving.sign_public(),
            &peers.receiving.seal_public(),
            5,
            &[],
            &Secret::new([0x56; 32]),
        )
        .unwrap();
        assert!(
            open_transfer(&peers.receiving, &peers.giving.sign_public(), &empty)
                .unwrap()
                .grants
                .is_empty()
        );
    }

    #[test]
    fn a_transfer_payload_has_the_key_order_of_section_10_1() {
        let grants = transfer_grants();
        let payload = transfer_payload("FROM", "TO", 42, &grants[..1]);
        assert_eq!(
            String::from_utf8(payload.expose_secret().clone()).unwrap(),
            format!(
                concat!(
                    "{{\"v\":1,\"type\":\"transfer\",\"from\":\"FROM\",\"to\":\"TO\",\"time_ms\":42,",
                    "\"grants\":[{{\"user_id\":\"user-a\",\"sign_pk\":\"{}\",\"log_pk\":\"{}\",",
                    "\"custody\":\"enclave\",\"user_key\":\"{}\",\"not_after_ms\":1800000000000}}]}}"
                ),
                b64u(&grants[0].sign_pk),
                b64u(&grants[0].log_pk),
                b64u(grants[0].user_key.expose_secret())
            )
        );
        assert_eq!(transfer_aad("FROM", "TO"), b"FROM\nTO");
        let envelope = TransferEnvelope {
            v: 1,
            from: "F".to_string(),
            to: "T".to_string(),
            enc: "E".to_string(),
            ct: "C".to_string(),
        };
        assert_eq!(
            String::from_utf8(to_json(&envelope)).unwrap(),
            "{\"v\":1,\"from\":\"F\",\"to\":\"T\",\"enc\":\"E\",\"ct\":\"C\"}"
        );
        let value = serde_json::to_value(&envelope).unwrap();
        assert_eq!(TransferEnvelope::from_value(&value).unwrap(), envelope);
        assert_eq!(
            TransferEnvelope::from_value(&serde_json::json!({"v": 2, "from": "F"})),
            Err(ProtocolError::UnsupportedVersion)
        );
        assert_eq!(
            TransferEnvelope::from_value(&serde_json::json!({"v": 1, "from": "F", "to": "T"})),
            Err(ProtocolError::InvalidRequest)
        );
    }

    #[test]
    fn a_transfer_is_bound_to_both_nodes() {
        let peers = peers();
        let other = NodeKeys::from_random(&[0x66; 32], &[0x77; 32]);
        let envelope = seal_transfer(
            &peers.giving,
            &peers.receiving.sign_public(),
            &peers.receiving.seal_public(),
            7,
            &transfer_grants(),
            &Secret::new([0x55; 32]),
        )
        .unwrap();

        // Another node cannot take it: the envelope names its receiver.
        assert_eq!(
            open_transfer(&other, &peers.giving.sign_public(), &envelope)
                .map(|_| ())
                .unwrap_err(),
            ProtocolError::WrongNode
        );
        // The receiver expects it from the node whose attestation it verified.
        assert_eq!(
            open_transfer(&peers.receiving, &other.sign_public(), &envelope)
                .map(|_| ())
                .unwrap_err(),
            ProtocolError::WrongNode
        );
        let mut version_2 = envelope.clone();
        version_2.v = 2;
        assert_eq!(
            transfer_error(&peers, &version_2),
            ProtocolError::UnsupportedVersion
        );

        // A changed ciphertext, and an envelope renamed after it was sealed: both names are
        // bound into the seal.
        let mut flipped = envelope.clone();
        let mut ct = b64u_decode(&flipped.ct).unwrap();
        ct[0] ^= 1;
        flipped.ct = b64u(&ct);
        assert_eq!(transfer_error(&peers, &flipped), ProtocolError::OpenFailed);
        let mut garbled = envelope.clone();
        garbled.enc = "***".to_string();
        assert_eq!(transfer_error(&peers, &garbled), ProtocolError::OpenFailed);

        let for_other = seal_transfer(
            &other,
            &peers.receiving.sign_public(),
            &peers.receiving.seal_public(),
            7,
            &transfer_grants(),
            &Secret::new([0x55; 32]),
        )
        .unwrap();
        let renamed = TransferEnvelope {
            from: peers.giving.node(),
            ..for_other
        };
        assert_eq!(transfer_error(&peers, &renamed), ProtocolError::OpenFailed);
    }

    #[test]
    fn a_transfer_is_signed_by_the_giving_node() {
        let peers = peers();
        let other = SigningKey::from_bytes(&[0x66; 32]);
        let payload = transfer_payload(
            &peers.giving.node(),
            &peers.receiving.node(),
            7,
            &transfer_grants(),
        );
        // Anyone can seal to the receiver. Only the giving node can sign.
        let forged = seal_signed(&peers, &sign_transfer(&other, payload.expose_secret()));
        assert_eq!(transfer_error(&peers, &forged), ProtocolError::BadSignature);

        // The signature covers the payload bytes: a transfer signed for the command context
        // is not a transfer.
        let mut message = purpose::COMMAND.as_bytes().to_vec();
        message.extend_from_slice(payload.expose_secret());
        let wrong_context = to_json(&serde_json::json!({
            "payload": b64u(payload.expose_secret()),
            "sig": b64u(&giving_sign().sign(&message).to_bytes()),
        }));
        assert_eq!(
            transfer_error(&peers, &seal_signed(&peers, &wrong_context)),
            ProtocolError::BadSignature
        );

        assert_eq!(
            transfer_error(&peers, &seal_signed(&peers, b"not json")),
            ProtocolError::InvalidRequest
        );
        assert_eq!(
            transfer_error(&peers, &seal_signed(&peers, b"{\"payload\":\"AA\"}")),
            ProtocolError::InvalidRequest
        );
    }

    #[test]
    fn a_malformed_transfer_is_refused_as_a_whole() {
        let peers = peers();
        assert!(open_transfer(
            &peers.receiving,
            &peers.giving.sign_public(),
            &changed_transfer(&peers, |_| {})
        )
        .is_ok());

        type Change = fn(&mut serde_json::Value);
        let cases: [(Change, ProtocolError); 13] = [
            (
                |body| body["v"] = serde_json::json!(2),
                ProtocolError::UnsupportedVersion,
            ),
            (
                |body| body["type"] = serde_json::json!("witness_request"),
                ProtocolError::InvalidRequest,
            ),
            (
                |body| body["to"] = serde_json::json!("another-node"),
                ProtocolError::WrongNode,
            ),
            (
                |body| body["from"] = serde_json::json!("another-node"),
                ProtocolError::WrongNode,
            ),
            (
                |body| body["time_ms"] = serde_json::json!("now"),
                ProtocolError::InvalidRequest,
            ),
            (
                |body| body["grants"] = serde_json::json!({}),
                ProtocolError::InvalidRequest,
            ),
            (
                |body| body["grants"][1] = serde_json::json!("grant"),
                ProtocolError::InvalidRequest,
            ),
            (
                |body| body["grants"][0]["user_id"] = serde_json::json!(""),
                ProtocolError::InvalidRequest,
            ),
            (
                |body| body["grants"][0]["sign_pk"] = serde_json::json!(b64u(&[1u8; 31])),
                ProtocolError::InvalidRequest,
            ),
            (
                |body| body["grants"][0]["log_pk"] = serde_json::json!(b64u(&[0u8; 32])),
                ProtocolError::InvalidRequest,
            ),
            (
                |body| body["grants"][1]["custody"] = serde_json::json!("hsm"),
                ProtocolError::InvalidRequest,
            ),
            (
                |body| body["grants"][1]["user_key"] = serde_json::json!(b64u(&[1u8; 33])),
                ProtocolError::InvalidRequest,
            ),
            (
                |body| body["grants"][1]["not_after_ms"] = serde_json::json!(-5),
                ProtocolError::InvalidRequest,
            ),
        ];
        for (index, (change, expected)) in cases.into_iter().enumerate() {
            assert_eq!(
                transfer_error(&peers, &changed_transfer(&peers, change)),
                expected,
                "case {index}"
            );
        }
        // The version is read before the type.
        assert_eq!(
            transfer_error(
                &peers,
                &changed_transfer(&peers, |body| {
                    body["v"] = serde_json::json!(2);
                    body["type"] = serde_json::json!("other");
                })
            ),
            ProtocolError::UnsupportedVersion
        );
        // A payload that is not an object.
        let array = seal_signed(&peers, &sign_transfer(&giving_sign(), b"[1]"));
        assert_eq!(
            transfer_error(&peers, &array),
            ProtocolError::InvalidRequest
        );
    }

    #[test]
    fn a_transfer_holds_at_most_1000_grants() {
        let peers = peers();
        let one = transfer_grants().remove(0);
        let full: Vec<TransferGrant> = (0..limits::TRANSFER_GRANTS)
            .map(|index| TransferGrant {
                user_id: format!("user-{index:04}"),
                ..one.clone()
            })
            .collect();
        let envelope = seal_transfer(
            &peers.giving,
            &peers.receiving.sign_public(),
            &peers.receiving.seal_public(),
            7,
            &full,
            &Secret::new([0x55; 32]),
        )
        .unwrap();
        let opened =
            open_transfer(&peers.receiving, &peers.giving.sign_public(), &envelope).unwrap();
        assert_eq!(opened.grants.len(), 1_000);
        assert_eq!(opened.grants[999].user_id, "user-0999");

        let mut over = full.clone();
        over.push(one);
        assert_eq!(
            seal_transfer(
                &peers.giving,
                &peers.receiving.sign_public(),
                &peers.receiving.seal_public(),
                7,
                &over,
                &Secret::new([0x55; 32]),
            )
            .map(|_| ()),
            Err(ProtocolError::InvalidRequest)
        );
        // A receiver refuses a longer transfer even when it is signed and sealed correctly.
        let payload = transfer_payload(&peers.giving.node(), &peers.receiving.node(), 7, &over);
        let long = seal_signed(
            &peers,
            &sign_transfer(&giving_sign(), payload.expose_secret()),
        );
        assert_eq!(transfer_error(&peers, &long), ProtocolError::InvalidRequest);

        // A node that cannot be sealed to.
        assert_eq!(
            seal_transfer(
                &peers.giving,
                &peers.receiving.sign_public(),
                &[0u8; 32],
                7,
                &full[..1],
                &Secret::new([0x55; 32]),
            )
            .map(|_| ()),
            Err(ProtocolError::InvalidRequest)
        );
    }

    #[test]
    fn reply_body_has_the_key_order_of_section_5_5() {
        let fixture = fixture();
        let body = ReplyBody {
            v: 1,
            kind: "grant_reply".to_string(),
            ok: true,
            code: String::new(),
            node: "N".to_string(),
            user_id: "U".to_string(),
            challenge: "C".to_string(),
            key_id: "K".to_string(),
            not_after_ms: 5,
            head: ReplyHead::from(&Head {
                seq: 1,
                hash: [0u8; 32],
            }),
            time_ms: 7,
        };
        let signed = reply(&fixture.node, &body);
        let bytes =
            crate::encoding::verify(&fixture.node.sign_public(), purpose::REPLY, &signed).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            format!(
                concat!(
                    "{{\"v\":1,\"type\":\"grant_reply\",\"ok\":true,\"code\":\"\",\"node\":\"N\",",
                    "\"user_id\":\"U\",\"challenge\":\"C\",\"key_id\":\"K\",\"not_after_ms\":5,",
                    "\"head\":{{\"seq\":1,\"hash\":\"{}\"}},\"time_ms\":7}}"
                ),
                b64u(&[0u8; 32])
            )
        );
    }
}
