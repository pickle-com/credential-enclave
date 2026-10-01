//! Attestation documents (protocol.md section 4): the Nitro attestation document, the binding
//! a node puts into it, and the unsigned document of the local platform.
//!
//! Everything that reads an attestation document reads it here: an app or a tool that verifies
//! a running node, a node that verifies a peer before a delegation transfer, and a node that
//! reads the time and its own measurement from the documents of its own Nitro Secure Module
//! (NSM). There is one reader of the document form, so a property of real documents is handled
//! in one place.
//!
//! This module returns what a document states and judges nothing about the measurement:
//! which PCR values are acceptable is the decision of the caller. A node compares them with
//! its own, a verifier of a release with the measurements of that release.

use std::fmt;
use std::time::Duration;

use rustls_pki_types::{CertificateDer, UnixTime};
use webpki::{
    anchor_from_trusted_cert, EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter,
};

use crate::encoding::{b64u_decode, b64u_decode_array};
use crate::envelope::is_usable_seal_key;
use crate::keys::LogStoreId;
use crate::limits;

/// The AWS Nitro Enclaves Root-G1 certificate (DER): the trust anchor of Nitro attestation
/// documents. SHA-256 of these bytes:
/// `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b` (protocol.md 4.3).
pub const AWS_NITRO_ROOT_G1: &[u8] = include_bytes!("aws-nitro-enclaves-root-g1.der");

/// Why an attestation document was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttestationError {
    /// The bytes do not have the form of the document: the COSE_Sign1 structure with the ES384
    /// header and the fields of an attestation payload (protocol.md 4.3 steps 1 to 3), a
    /// binding (4.1) or a local document (4.2).
    Malformed,
    /// The certificate chain does not lead from the certificate of the document to the trust
    /// root at the time of the document (4.3 step 4).
    Untrusted,
    /// The signature does not verify under the key of the certificate of the document (4.3
    /// step 5).
    Forged,
    /// The nonce of the document is not the nonce the verifier asked for (4.3 step 6).
    NonceMismatch,
}

impl fmt::Display for AttestationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            AttestationError::Malformed => "the document does not have the expected form",
            AttestationError::Untrusted => {
                "the certificate chain of the document does not lead to the trust root"
            }
            AttestationError::Forged => "the signature of the document does not verify",
            AttestationError::NonceMismatch => {
                "the nonce of the document is not the nonce that was asked for"
            }
        })
    }
}

impl std::error::Error for AttestationError {}

/// What a Nitro attestation document states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NitroDocument {
    /// `module_id`: the identifier of the enclave.
    pub module_id: String,
    /// `timestamp`: the time the NSM created the document, in Unix epoch milliseconds.
    pub timestamp_ms: u64,
    /// PCR0: the measurement of the enclave image file.
    pub pcr0: [u8; 48],
    /// PCR1: the measurement of the kernel and the boot ramdisk.
    pub pcr1: [u8; 48],
    /// PCR2: the measurement of the application.
    pub pcr2: [u8; 48],
    /// `user_data`: the binding of a node (4.1). `None` when the document was requested
    /// without user data (it then holds null).
    pub user_data: Option<Vec<u8>>,
    /// `nonce`. `None` when the document was requested without a nonce (it then holds null).
    pub nonce: Option<Vec<u8>>,
}

impl NitroDocument {
    /// True when PCR0, PCR1 or PCR2 is all zero: the measurement of a debug-mode enclave,
    /// whose memory the parent instance can read. No verifier accepts such a measurement
    /// (4.3 step 7).
    pub fn is_debug_mode(&self) -> bool {
        [&self.pcr0, &self.pcr1, &self.pcr2]
            .iter()
            .any(|pcr| pcr.iter().all(|byte| *byte == 0))
    }
}

/// Verifies a Nitro attestation document (protocol.md 4.3 steps 1 to 6) and returns what it
/// states.
///
/// | Step | Check | Failure |
/// | --- | --- | --- |
/// | 1 to 3 | the COSE_Sign1 structure, the ES384 header, a signature of 96 bytes, the fields of the payload | `Malformed` |
/// | 4 | the certificate chain from the certificate of the document over the certificates of `cabundle` after its first one to `root_der`, at the time of the document, without revocation lists | `Untrusted` |
/// | 5 | the ECDSA P-384 SHA-384 signature of the certificate key over the header and payload bytes as the document carries them | `Forged` |
/// | 6 | when `nonce` is given: the nonce of the document equals it | `NonceMismatch` |
///
/// `root_der` is the only trust anchor: the copy of the root that the document carries as the
/// first certificate of `cabundle` is not read. The time of the verifier is not looked at. A
/// verifier that sent a nonce passes it and gets freshness from it. A node that verifies a
/// peer passes `None`.
///
/// Steps 7 and 8 are the caller's: compare `pcr0`, `pcr1` and `pcr2` with the measurements it
/// accepts (never a debug-mode measurement, see [`NitroDocument::is_debug_mode`]) and read the
/// binding from `user_data` with [`read_binding`].
pub fn verify_nitro_document(
    document: &[u8],
    root_der: &[u8],
    nonce: Option<&[u8]>,
) -> Result<NitroDocument, AttestationError> {
    // 1 to 3
    let (cose, payload) = parse_nitro_document(document)?;

    // 4
    let root = CertificateDer::from(root_der);
    let anchor = anchor_from_trusted_cert(&root).map_err(|_| AttestationError::Untrusted)?;
    let leaf = CertificateDer::from(payload.certificate);
    let leaf = EndEntityCert::try_from(&leaf).map_err(|_| AttestationError::Untrusted)?;
    let intermediates: Vec<CertificateDer<'_>> = payload
        .cabundle
        .iter()
        .skip(1)
        .map(|certificate| CertificateDer::from(*certificate))
        .collect();
    let time = UnixTime::since_unix_epoch(Duration::from_secs(payload.timestamp_ms / 1000));
    leaf.verify_for_usage(
        &[webpki::ring::ECDSA_P384_SHA384],
        &[anchor],
        &intermediates,
        time,
        AnyKeyPurpose,
        None,
        None,
    )
    .map_err(|_| AttestationError::Untrusted)?;

    // 5
    let message = sig_structure(cose.protected, cose.payload);
    let signature = ecdsa_der(cose.signature).ok_or(AttestationError::Malformed)?;
    leaf.verify_signature(webpki::ring::ECDSA_P384_SHA384, &message, &signature)
        .map_err(|_| AttestationError::Forged)?;

    // 6
    if nonce.is_some() && nonce != payload.nonce {
        return Err(AttestationError::NonceMismatch);
    }
    Ok(payload.document())
}

/// Reads a Nitro attestation document without verifying its certificate chain and its
/// signature: what [`verify_nitro_document`] reads in its steps 1 to 3, with the same reader.
///
/// This is for a node that reads documents it received from its own NSM (the time, its own
/// measurement). Nothing a document from anywhere else states is known before
/// [`verify_nitro_document`] accepted it.
pub fn read_unverified_nitro_document(document: &[u8]) -> Result<NitroDocument, AttestationError> {
    let (_, payload) = parse_nitro_document(document)?;
    Ok(payload.document())
}

/// The values a node binds to its attestation (protocol.md 4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeBinding {
    /// The node signing public key (Ed25519). Its base64url form is the node identifier.
    pub sign_public: [u8; 32],
    /// The node sealing public key (X25519).
    pub seal_public: [u8; 32],
    /// The release tag the node was built from.
    pub release: String,
    /// The log store the node writes its entries to before it acts, when it has one.
    pub log: Option<LogStoreId>,
}

/// Reads a binding document (protocol.md 4.1):
/// `{"v":1,"sign":b64u(32 bytes),"seal":b64u(32 bytes),"release":"..."}` of at most 512 bytes,
/// with the key `"log":{"bucket":"...","region":"..."}` when the node has a log store.
/// A sealing key HPKE cannot seal to (a small-order point) is refused, so whatever is sealed
/// for the keys of a binding this function returned can be sealed. A `log` that is not a bucket
/// name and a region name is refused: a binding states its log store or none.
pub fn read_binding(binding: &[u8]) -> Result<NodeBinding, AttestationError> {
    binding_of(binding).ok_or(AttestationError::Malformed)
}

fn binding_of(binding: &[u8]) -> Option<NodeBinding> {
    if binding.len() > limits::BINDING_BYTES {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(binding).ok()?;
    if value.get("v")?.as_u64()? != 1 {
        return None;
    }
    let sign_public = b64u_decode_array::<32>(value.get("sign")?.as_str()?).ok()?;
    let seal_public = b64u_decode_array::<32>(value.get("seal")?.as_str()?).ok()?;
    if !is_usable_seal_key(&seal_public) {
        return None;
    }
    let log = match value.get("log") {
        None => None,
        Some(log) => Some(LogStoreId::parse(
            log.get("bucket")?.as_str()?,
            log.get("region")?.as_str()?,
        )?),
    };
    Some(NodeBinding {
        sign_public,
        seal_public,
        release: value.get("release")?.as_str()?.to_string(),
        log,
    })
}

/// What the document of a node on the local platform states (protocol.md 4.2). The document
/// is unsigned: it proves nothing, it is only read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalDocument {
    /// The binding of the node (4.1), to be read with [`read_binding`].
    pub binding: Vec<u8>,
    /// The nonce of the requester.
    pub nonce: Vec<u8>,
    /// The system time of the node, in Unix epoch milliseconds.
    pub time_ms: u64,
}

/// Reads a local document (protocol.md 4.2):
/// `{"v":1,"platform":"local","binding":b64u(binding),"nonce":b64u,"time_ms":n}`.
pub fn read_local_document(document: &[u8]) -> Result<LocalDocument, AttestationError> {
    local_document_of(document).ok_or(AttestationError::Malformed)
}

fn local_document_of(document: &[u8]) -> Option<LocalDocument> {
    let value: serde_json::Value = serde_json::from_slice(document).ok()?;
    if value.get("v")?.as_u64()? != 1 || value.get("platform")?.as_str()? != "local" {
        return None;
    }
    Some(LocalDocument {
        binding: b64u_decode(value.get("binding")?.as_str()?).ok()?,
        nonce: b64u_decode(value.get("nonce")?.as_str()?).ok()?,
        time_ms: value.get("time_ms")?.as_u64()?,
    })
}

/// Steps 1 to 3 of protocol.md 4.3: the COSE_Sign1 structure with the ES384 header and a
/// signature of 96 bytes, and the fields of its payload.
fn parse_nitro_document(
    document: &[u8],
) -> Result<(CoseSign1<'_>, NitroPayload<'_>), AttestationError> {
    let cose = CoseSign1::parse(document).map_err(|_| AttestationError::Malformed)?;
    if !is_es384_header(cose.protected) || cose.signature.len() != ECDSA_P384_SIGNATURE_BYTES {
        return Err(AttestationError::Malformed);
    }
    let payload = NitroPayload::parse(cose.payload).map_err(|_| AttestationError::Malformed)?;
    Ok((cose, payload))
}

/// The certificates of an attestation document are not TLS certificates, and protocol.md 4.3
/// names no extended key usage: every purpose is accepted. A malformed extension is not.
struct AnyKeyPurpose;

impl ExtendedKeyUsageValidator for AnyKeyPurpose {
    fn validate(&self, purposes: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        for purpose in purposes {
            purpose?;
        }
        Ok(())
    }
}

/// Length of an ECDSA P-384 signature as COSE carries it: `r` and `s`, 48 bytes each.
const ECDSA_P384_SIGNATURE_BYTES: usize = 96;

/// The DER form (`SEQUENCE { INTEGER r, INTEGER s }`) of a raw ECDSA P-384 signature. The
/// certificate verifier takes signatures in this form. This is a change of encoding, not a
/// computation on the values.
fn ecdsa_der(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() != ECDSA_P384_SIGNATURE_BYTES {
        return None;
    }
    let mut body = Vec::with_capacity(ECDSA_P384_SIGNATURE_BYTES + 6);
    for half in raw.chunks(ECDSA_P384_SIGNATURE_BYTES / 2) {
        // A DER integer is the shortest two's complement form: no leading zero bytes, and one
        // zero byte in front of a value whose first bit is set.
        let start = half
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(half.len() - 1);
        let digits = &half[start..];
        let pad = digits[0] & 0x80 != 0;
        body.push(0x02);
        body.push(u8::try_from(digits.len() + usize::from(pad)).ok()?);
        if pad {
            body.push(0x00);
        }
        body.extend_from_slice(digits);
    }
    // Two integers of at most 49 bytes with their headers: at most 102 bytes, a short length.
    let mut der = vec![0x30, u8::try_from(body.len()).ok()?];
    der.extend_from_slice(&body);
    Some(der)
}

/// The message a COSE_Sign1 signature covers: the CBOR encoding of the array
/// `["Signature1", protected, h'', payload]`, with `protected` and `payload` as the byte
/// strings the document carries and an empty byte string as the external data.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(protected.len() + payload.len() + 32);
    message.push(0x84);
    message.push(0x6a);
    message.extend_from_slice(b"Signature1");
    push_bytes(&mut message, protected);
    push_bytes(&mut message, &[]);
    push_bytes(&mut message, payload);
    message
}

/// Appends a CBOR byte string with the shortest form of its length.
fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let length = bytes.len() as u64;
    let major = CBOR_BYTES << 5;
    if length < 24 {
        out.push(major | length as u8);
    } else if let Ok(short) = u8::try_from(length) {
        out.extend_from_slice(&[major | 24, short]);
    } else if let Ok(short) = u16::try_from(length) {
        out.push(major | 25);
        out.extend_from_slice(&short.to_be_bytes());
    } else if let Ok(short) = u32::try_from(length) {
        out.push(major | 26);
        out.extend_from_slice(&short.to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&length.to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

/// True when `protected` is the CBOR map `{1: -35}`: the algorithm ES384 and nothing else.
fn is_es384_header(protected: &[u8]) -> bool {
    let mut reader = CborReader::new(protected);
    let Ok(mut pairs) = reader.map() else {
        return false;
    };
    reader.has_next(&mut pairs) == Ok(true)
        && reader.head() == Ok((CBOR_UNSIGNED, 1))
        // The negative integer -35 has the argument 34.
        && reader.head() == Ok((CBOR_NEGATIVE, 34))
        && reader.has_next(&mut pairs) == Ok(false)
        && reader.is_end()
}

/// A CBOR item that is not what the reader expects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Malformed;

const CBOR_UNSIGNED: u8 = 0;
const CBOR_NEGATIVE: u8 = 1;
const CBOR_BYTES: u8 = 2;
const CBOR_TEXT: u8 = 3;
const CBOR_ARRAY: u8 = 4;
const CBOR_MAP: u8 = 5;
const CBOR_TAG: u8 = 6;
/// The additional information of an initial byte that announces an indefinite length.
const CBOR_INDEFINITE: u8 = 31;
/// The byte that ends an indefinite-length array or map.
const CBOR_BREAK: u8 = 0xff;
/// The simple value null.
const CBOR_NULL: u8 = 0xf6;
const CBOR_NESTING_LIMIT: u32 = 16;

/// What is left to read of an array (items) or of a map (pairs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Items {
    /// A definite-length container: this many are left.
    Left(u64),
    /// An indefinite-length container: it ends with a break.
    UntilBreak,
}

/// Reads CBOR items. Every read is bounds-checked: the input can come from anywhere.
///
/// Arrays and maps are read in both of their forms, with a definite and with an indefinite
/// length: the Nitro Secure Module writes the payload of an attestation document as an
/// indefinite-length map (`0xbf` ... `0xff`). Indefinite-length byte and text strings do not
/// occur in attestation documents and are malformed here.
struct CborReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> CborReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        CborReader { data, position: 0 }
    }

    /// True when every byte was read.
    fn is_end(&self) -> bool {
        self.position == self.data.len()
    }

    /// The next byte, without reading it.
    fn peek(&self) -> Result<u8, Malformed> {
        self.data.get(self.position).copied().ok_or(Malformed)
    }

    fn take(&mut self, length: u64) -> Result<&'a [u8], Malformed> {
        let length = usize::try_from(length).map_err(|_| Malformed)?;
        let end = self.position.checked_add(length).ok_or(Malformed)?;
        let slice = self.data.get(self.position..end).ok_or(Malformed)?;
        self.position = end;
        Ok(slice)
    }

    /// Reads the head of the next item: its major type and its argument. An indefinite length
    /// is malformed here: [`CborReader::array`] and [`CborReader::map`] read the two items that
    /// may have one. A break outside of such a container is malformed as well.
    fn head(&mut self) -> Result<(u8, u64), Malformed> {
        let initial = self.take(1)?[0];
        let major = initial >> 5;
        let argument = match initial & 0x1f {
            small @ 0..=23 => u64::from(small),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(
                self.take(2)?.try_into().map_err(|_| Malformed)?,
            )),
            26 => u64::from(u32::from_be_bytes(
                self.take(4)?.try_into().map_err(|_| Malformed)?,
            )),
            27 => u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| Malformed)?),
            _ => return Err(Malformed),
        };
        Ok((major, argument))
    }

    /// Reads the head of an item of the major type `major` and returns its argument.
    fn expect(&mut self, major: u8) -> Result<u64, Malformed> {
        match self.head()? {
            (found, argument) if found == major => Ok(argument),
            _ => Err(Malformed),
        }
    }

    /// Reads a byte string.
    fn bytes(&mut self) -> Result<&'a [u8], Malformed> {
        let length = self.expect(CBOR_BYTES)?;
        self.take(length)
    }

    /// Reads a byte string, or the null that stands in the place of an absent one.
    fn bytes_or_null(&mut self) -> Result<Option<&'a [u8]>, Malformed> {
        if self.peek()? == CBOR_NULL {
            self.position += 1;
            return Ok(None);
        }
        self.bytes().map(Some)
    }

    /// Reads a text string.
    fn text(&mut self) -> Result<&'a str, Malformed> {
        let length = self.expect(CBOR_TEXT)?;
        std::str::from_utf8(self.take(length)?).map_err(|_| Malformed)
    }

    /// Reads the head of an array, of a definite or an indefinite length. Its items are read
    /// while [`CborReader::has_next`] says there is one.
    fn array(&mut self) -> Result<Items, Malformed> {
        self.container(CBOR_ARRAY)
    }

    /// Reads the head of a map, of a definite or an indefinite length. Its pairs are read
    /// while [`CborReader::has_next`] says there is one.
    fn map(&mut self) -> Result<Items, Malformed> {
        self.container(CBOR_MAP)
    }

    fn container(&mut self, major: u8) -> Result<Items, Malformed> {
        if self.peek()? == (major << 5) | CBOR_INDEFINITE {
            self.position += 1;
            return Ok(Items::UntilBreak);
        }
        Ok(Items::Left(self.expect(major)?))
    }

    /// True when the container has a further item (a map: a further pair). At the end of an
    /// indefinite-length container this reads its break.
    fn has_next(&mut self, items: &mut Items) -> Result<bool, Malformed> {
        match items {
            Items::Left(0) => Ok(false),
            Items::Left(left) => {
                *left -= 1;
                Ok(true)
            }
            Items::UntilBreak => {
                if self.peek()? == CBOR_BREAK {
                    self.position += 1;
                    return Ok(false);
                }
                Ok(true)
            }
        }
    }

    /// Like [`CborReader::has_next`], for a place where a further item must follow.
    fn item(&mut self, items: &mut Items) -> Result<(), Malformed> {
        if self.has_next(items)? {
            return Ok(());
        }
        Err(Malformed)
    }

    /// Skips one item with everything nested inside it.
    fn skip(&mut self, depth: u32) -> Result<(), Malformed> {
        if depth > CBOR_NESTING_LIMIT {
            return Err(Malformed);
        }
        match self.peek()? >> 5 {
            CBOR_ARRAY => {
                let mut items = self.array()?;
                while self.has_next(&mut items)? {
                    self.skip(depth + 1)?;
                }
            }
            CBOR_MAP => {
                let mut pairs = self.map()?;
                while self.has_next(&mut pairs)? {
                    self.skip(depth + 1)?;
                    self.skip(depth + 1)?;
                }
            }
            _ => {
                let (major, argument) = self.head()?;
                match major {
                    CBOR_BYTES | CBOR_TEXT => {
                        self.take(argument)?;
                    }
                    CBOR_TAG => self.skip(depth + 1)?,
                    // Integers, simple values and floats end with their head.
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

/// The parts of a COSE_Sign1 structure: the array
/// `[protected(bstr), unprotected(map), payload(bstr), signature(bstr)]`, with or without the
/// tag 18. `protected` and `payload` are the bytes inside their byte strings, exactly as the
/// document carries them: the signature covers these bytes and nothing re-encodes them.
struct CoseSign1<'a> {
    protected: &'a [u8],
    payload: &'a [u8],
    signature: &'a [u8],
}

impl<'a> CoseSign1<'a> {
    fn parse(document: &'a [u8]) -> Result<Self, Malformed> {
        let mut reader = CborReader::new(document);
        if reader.peek()? >> 5 == CBOR_TAG && reader.expect(CBOR_TAG)? != 18 {
            return Err(Malformed);
        }
        let mut items = reader.array()?;
        reader.item(&mut items)?;
        let protected = reader.bytes()?;
        reader.item(&mut items)?;
        let mut pairs = reader.map()?;
        while reader.has_next(&mut pairs)? {
            reader.skip(1)?;
            reader.skip(1)?;
        }
        reader.item(&mut items)?;
        let payload = reader.bytes()?;
        reader.item(&mut items)?;
        let signature = reader.bytes()?;
        if reader.has_next(&mut items)? || !reader.is_end() {
            return Err(Malformed);
        }
        Ok(CoseSign1 {
            protected,
            payload,
            signature,
        })
    }
}

/// Reads the `pcrs` map of an attestation payload (uint to a byte string of 48 bytes) and
/// returns PCR0, PCR1 and PCR2.
fn read_pcrs(reader: &mut CborReader<'_>) -> Result<[[u8; 48]; 3], Malformed> {
    let mut entries = reader.map()?;
    let mut pcrs: [Option<[u8; 48]>; 3] = [None; 3];
    while reader.has_next(&mut entries)? {
        let index = reader.expect(CBOR_UNSIGNED)?;
        let value: [u8; 48] = reader.bytes()?.try_into().map_err(|_| Malformed)?;
        if let Some(slot) = usize::try_from(index)
            .ok()
            .and_then(|index| pcrs.get_mut(index))
        {
            if slot.replace(value).is_some() {
                return Err(Malformed);
            }
        }
    }
    match pcrs {
        [Some(pcr0), Some(pcr1), Some(pcr2)] => Ok([pcr0, pcr1, pcr2]),
        _ => Err(Malformed),
    }
}

/// The fields of an attestation payload (protocol.md 4.3 step 3).
struct NitroPayload<'a> {
    module_id: &'a str,
    timestamp_ms: u64,
    pcrs: [[u8; 48]; 3],
    certificate: &'a [u8],
    cabundle: Vec<&'a [u8]>,
    /// `None` when the document was requested without user data: it then holds null.
    user_data: Option<&'a [u8]>,
    /// `None` when the document was requested without a nonce: it then holds null.
    nonce: Option<&'a [u8]>,
}

impl<'a> NitroPayload<'a> {
    /// Reads the payload map. Each of `module_id` (text), `digest` (the text `SHA384`),
    /// `timestamp` (uint), `pcrs`, `certificate` (bstr), `cabundle` (an array of at least one
    /// bstr), `user_data` (bstr or null) and `nonce` (bstr or null) is present exactly once
    /// with that type. Other keys are skipped.
    fn parse(payload: &'a [u8]) -> Result<Self, Malformed> {
        let mut reader = CborReader::new(payload);
        let mut pairs = reader.map()?;
        let mut module_id = None;
        let mut digest = None;
        let mut timestamp_ms = None;
        let mut pcrs = None;
        let mut certificate = None;
        let mut cabundle = None;
        let mut user_data = None;
        let mut nonce = None;
        fn once<T>(slot: &mut Option<T>, value: T) -> Result<(), Malformed> {
            match slot.replace(value) {
                None => Ok(()),
                Some(_) => Err(Malformed),
            }
        }
        while reader.has_next(&mut pairs)? {
            match reader.text()? {
                "module_id" => once(&mut module_id, reader.text()?)?,
                "digest" => once(&mut digest, reader.text()?)?,
                "timestamp" => once(&mut timestamp_ms, reader.expect(CBOR_UNSIGNED)?)?,
                "pcrs" => once(&mut pcrs, read_pcrs(&mut reader)?)?,
                "certificate" => once(&mut certificate, reader.bytes()?)?,
                "cabundle" => {
                    let mut items = reader.array()?;
                    let mut certificates = Vec::new();
                    while reader.has_next(&mut items)? {
                        certificates.push(reader.bytes()?);
                    }
                    if certificates.is_empty() {
                        return Err(Malformed);
                    }
                    once(&mut cabundle, certificates)?;
                }
                "user_data" => once(&mut user_data, reader.bytes_or_null()?)?,
                "nonce" => once(&mut nonce, reader.bytes_or_null()?)?,
                _ => reader.skip(1)?,
            }
        }
        if !reader.is_end() || digest != Some("SHA384") {
            return Err(Malformed);
        }
        Ok(NitroPayload {
            module_id: module_id.ok_or(Malformed)?,
            timestamp_ms: timestamp_ms.ok_or(Malformed)?,
            pcrs: pcrs.ok_or(Malformed)?,
            certificate: certificate.ok_or(Malformed)?,
            cabundle: cabundle.ok_or(Malformed)?,
            user_data: user_data.ok_or(Malformed)?,
            nonce: nonce.ok_or(Malformed)?,
        })
    }

    /// What the payload states, without the certificates.
    fn document(&self) -> NitroDocument {
        let [pcr0, pcr1, pcr2] = self.pcrs;
        NitroDocument {
            module_id: self.module_id.to_string(),
            timestamp_ms: self.timestamp_ms,
            pcr0,
            pcr1,
            pcr2,
            user_data: self.user_data.map(<[u8]>::to_vec),
            nonce: self.nonce.map(<[u8]>::to_vec),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{b64u, to_json};
    use crate::keys::{binding, NodeKeys};
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_FIXED_SIGNING};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    /// A real attestation document of a production-mode enclave, issued on 2026-10-01 in
    /// answer to an attestation call: its user data is the binding of the node and its nonce
    /// is [`OPERATIONAL_NONCE`]. Its payload is an indefinite-length map (`0xbf` ... `0xff`),
    /// the form the NSM writes.
    const OPERATIONAL_DOCUMENT: &[u8] =
        include_bytes!("../tests/fixtures/nitro-attestation-document-operational.cbor");
    const OPERATIONAL_NONCE: &str =
        "ccaba542c08b40eece75fa9c337500d56d5670def7168bd932b358fe9552df4b";
    /// PCR0, PCR1 and PCR2 of that enclave (a diagnostic build).
    const OPERATIONAL_PCRS: [&str; 3] = [
        "904d4e19f2cece358d8c0bcfdb278573decfcc739ce320c587c59d9ee73f5db594cd0c8e73539a087138e069223d8f47",
        "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
        "a1952bc63a9e80a3a46eda48bb60236dfcb030d50bf81f02b5c50d20d42a905d1db7c82d3f1d4c4d5649b20697889d44",
    ];
    /// A real attestation document as a node receives it from its own NSM at boot, issued on
    /// 2026-10-01 to a debug-mode enclave: PCR0, PCR1 and PCR2 are zero, user data and nonce
    /// are null. Its payload is an indefinite-length map.
    const BOOT_DOCUMENT: &[u8] =
        include_bytes!("../tests/fixtures/nitro-attestation-document-boot.cbor");
    /// A real attestation document of a debug-mode enclave of another program, issued on
    /// 2023-09-18, with user data and a nonce. Its payload is a definite-length map.
    const SAMPLE_DOCUMENT: &[u8] =
        include_bytes!("../tests/fixtures/nitro-attestation-document.cbor");
    /// A self-signed root that has nothing to do with the chain of any of these documents.
    const UNRELATED_ROOT: &[u8] = include_bytes!("../tests/fixtures/unrelated-root.der");

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }

    fn pcr(text: &str) -> [u8; 48] {
        hex(text).try_into().unwrap()
    }

    /// The position of `needle` in `haystack`.
    fn find(haystack: &[u8], needle: &[u8]) -> usize {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap()
    }

    #[test]
    fn the_embedded_root_is_the_aws_nitro_enclaves_root_g1() {
        let digest: String = Sha256::digest(AWS_NITRO_ROOT_G1)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            digest,
            "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
        );
    }

    #[test]
    fn a_real_document_of_a_production_enclave_verifies() {
        let nonce = hex(OPERATIONAL_NONCE);
        let verified = verify_nitro_document(OPERATIONAL_DOCUMENT, AWS_NITRO_ROOT_G1, Some(&nonce))
            .expect("the chain, the signature and the nonce of the real document verify");
        assert_eq!(
            verified.module_id,
            "i-00e27c4213a488340-enc01a0f59ef3fce7ac"
        );
        assert_eq!(verified.timestamp_ms, 1_790_827_255_513);
        assert_eq!(verified.pcr0, pcr(OPERATIONAL_PCRS[0]));
        assert_eq!(verified.pcr1, pcr(OPERATIONAL_PCRS[1]));
        assert_eq!(verified.pcr2, pcr(OPERATIONAL_PCRS[2]));
        assert!(!verified.is_debug_mode());
        assert_eq!(verified.nonce.as_deref(), Some(nonce.as_slice()));

        // The user data is the binding of the node: its keys and its release.
        let user_data = verified.user_data.clone().expect("user data");
        assert_eq!(
            String::from_utf8(user_data.clone()).unwrap(),
            concat!(
                "{\"v\":1,\"sign\":\"QkJRkEKP6EwK2iiQQnQaoqfydMV9RvHVsA3t2zJEkHo\",",
                "\"seal\":\"2iI8u-awqrbr0Wt2kz4rzQ3-FHkGxVv8IjicSsHqUl4\",",
                "\"release\":\"v0.0.0-diag.local\"}"
            )
        );
        let bound = read_binding(&user_data).unwrap();
        assert_eq!(
            b64u(&bound.sign_public),
            "QkJRkEKP6EwK2iiQQnQaoqfydMV9RvHVsA3t2zJEkHo"
        );
        assert_eq!(
            b64u(&bound.seal_public),
            "2iI8u-awqrbr0Wt2kz4rzQ3-FHkGxVv8IjicSsHqUl4"
        );
        assert_eq!(bound.release, "v0.0.0-diag.local");

        // A verifier that sent no nonce (a node that verifies a peer) skips the nonce check.
        assert_eq!(
            verify_nitro_document(OPERATIONAL_DOCUMENT, AWS_NITRO_ROOT_G1, None),
            Ok(verified.clone())
        );
        // A verifier that sent another nonce does not accept the document.
        let mut other = nonce.clone();
        other[0] ^= 1;
        assert_eq!(
            verify_nitro_document(OPERATIONAL_DOCUMENT, AWS_NITRO_ROOT_G1, Some(&other)),
            Err(AttestationError::NonceMismatch)
        );
        assert_eq!(
            verify_nitro_document(OPERATIONAL_DOCUMENT, AWS_NITRO_ROOT_G1, Some(&[])),
            Err(AttestationError::NonceMismatch)
        );

        // The reading without the verification is the same reading.
        assert_eq!(
            read_unverified_nitro_document(OPERATIONAL_DOCUMENT),
            Ok(verified.clone())
        );
        // The same document under the COSE_Sign1 tag.
        let mut tagged = vec![0xd2];
        tagged.extend_from_slice(OPERATIONAL_DOCUMENT);
        assert_eq!(
            verify_nitro_document(&tagged, AWS_NITRO_ROOT_G1, Some(&nonce)),
            Ok(verified)
        );
    }

    #[test]
    fn a_real_document_is_refused_under_another_root_and_after_a_change() {
        let verify = |document: &[u8]| verify_nitro_document(document, AWS_NITRO_ROOT_G1, None);
        let changed = |position: usize| {
            let mut document = OPERATIONAL_DOCUMENT.to_vec();
            document[position] ^= 1;
            document
        };
        assert!(verify(OPERATIONAL_DOCUMENT).is_ok());

        // The chain leads to the fixed root only. The document carries its own copy of the
        // AWS root, which is not a ground for trust.
        assert_eq!(
            verify_nitro_document(OPERATIONAL_DOCUMENT, UNRELATED_ROOT, None),
            Err(AttestationError::Untrusted)
        );
        assert_eq!(
            verify_nitro_document(OPERATIONAL_DOCUMENT, b"not a certificate", None),
            Err(AttestationError::Untrusted)
        );

        // One changed bit in what the signature covers: the release of the binding, a sealing
        // key character, the nonce, a PCR, the module id, the last digit of the timestamp. And
        // in the signature itself.
        let release = find(OPERATIONAL_DOCUMENT, b"v0.0.0-diag.local");
        let seal = find(OPERATIONAL_DOCUMENT, b"2iI8u-awqrbr0Wt2");
        let nonce = find(OPERATIONAL_DOCUMENT, &hex(OPERATIONAL_NONCE));
        let pcr0 = find(OPERATIONAL_DOCUMENT, &hex(OPERATIONAL_PCRS[0]));
        let module_id = find(OPERATIONAL_DOCUMENT, b"enc01a0f59ef3fce7ac");
        let timestamp = find(OPERATIONAL_DOCUMENT, b"itimestamp") + 10;
        assert_eq!(OPERATIONAL_DOCUMENT[timestamp], 0x1b);
        for position in [
            release + 1,
            seal,
            nonce + 31,
            pcr0 + 47,
            module_id,
            timestamp + 8,
            OPERATIONAL_DOCUMENT.len() - 1,
            OPERATIONAL_DOCUMENT.len() - 96,
        ] {
            assert_eq!(
                verify(&changed(position)),
                Err(AttestationError::Forged),
                "{position}"
            );
        }
        // A changed certificate, and a changed intermediate certificate.
        let certificate = find(OPERATIONAL_DOCUMENT, b"kcertificate") + 12 + 3;
        let cabundle = find(OPERATIONAL_DOCUMENT, b"hcabundle");
        for position in [certificate + 200, cabundle + 600] {
            assert_eq!(
                verify(&changed(position)),
                Err(AttestationError::Untrusted),
                "{position}"
            );
        }

        // The chain is verified at the time of the document: the certificate of a document
        // lives for three hours. A document dated a day later carries a certificate that is
        // over at that time, and the time of the verifier plays no part (this test passes at
        // any time).
        let mut later = OPERATIONAL_DOCUMENT.to_vec();
        let dated = 1_790_827_255_513u64 + 86_400_000;
        later[timestamp + 1..timestamp + 9].copy_from_slice(&dated.to_be_bytes());
        assert_eq!(verify(&later), Err(AttestationError::Untrusted));

        // A cut document, a document with a byte after it, and no document.
        assert_eq!(
            verify(&OPERATIONAL_DOCUMENT[..OPERATIONAL_DOCUMENT.len() - 1]),
            Err(AttestationError::Malformed)
        );
        let mut longer = OPERATIONAL_DOCUMENT.to_vec();
        longer.push(0);
        assert_eq!(verify(&longer), Err(AttestationError::Malformed));
        assert_eq!(verify(&[]), Err(AttestationError::Malformed));
    }

    /// The payload of a real document with an indefinite-length payload map, and that document
    /// with `payload` in the place of its payload (the byte string length is written anew).
    fn with_payload(document: &[u8], payload: &[u8]) -> Vec<u8> {
        let cose = CoseSign1::parse(document).unwrap();
        let mut out = head(CBOR_ARRAY, 4);
        out.extend(cbor_bytes(cose.protected));
        out.extend(head(CBOR_MAP, 0));
        out.extend(cbor_bytes(payload));
        out.extend(cbor_bytes(cose.signature));
        out
    }

    #[test]
    fn the_payload_of_a_real_document_is_an_indefinite_length_map() {
        let cose = CoseSign1::parse(OPERATIONAL_DOCUMENT).unwrap();
        assert_eq!(cose.payload.first(), Some(&0xbf));
        assert_eq!(cose.payload.last(), Some(&0xff));
        assert_eq!(cose.protected, [0xa1, 0x01, 0x38, 0x22]);
        assert_eq!(cose.signature.len(), 96);
        // Rebuilt from its parts, the document is the document.
        assert_eq!(
            with_payload(OPERATIONAL_DOCUMENT, cose.payload),
            OPERATIONAL_DOCUMENT
        );

        // The same map written with a definite length has the same fields, and it is another
        // byte string: the signature does not cover it.
        let pairs = &cose.payload[1..cose.payload.len() - 1];
        let mut definite = vec![0xa9];
        definite.extend_from_slice(pairs);
        let rewritten = with_payload(OPERATIONAL_DOCUMENT, &definite);
        assert_eq!(
            read_unverified_nitro_document(&rewritten),
            read_unverified_nitro_document(OPERATIONAL_DOCUMENT)
        );
        assert_eq!(
            verify_nitro_document(&rewritten, AWS_NITRO_ROOT_G1, None),
            Err(AttestationError::Forged)
        );

        // The map without its break is not a map.
        let unterminated = with_payload(
            OPERATIONAL_DOCUMENT,
            &cose.payload[..cose.payload.len() - 1],
        );
        assert_eq!(
            read_unverified_nitro_document(&unterminated),
            Err(AttestationError::Malformed)
        );
        assert_eq!(
            verify_nitro_document(&unterminated, AWS_NITRO_ROOT_G1, None),
            Err(AttestationError::Malformed)
        );
    }

    #[test]
    fn a_real_boot_document_of_a_debug_enclave_is_read_and_verifies() {
        // What a node reads from the documents of its own NSM: the time and the measurement.
        let read = read_unverified_nitro_document(BOOT_DOCUMENT).unwrap();
        assert_eq!(
            read,
            NitroDocument {
                module_id: "i-00e27c4213a488340-enc01a0f58c05ad8fe0".to_string(),
                timestamp_ms: 1_790_825_991_147,
                pcr0: [0; 48],
                pcr1: [0; 48],
                pcr2: [0; 48],
                user_data: None,
                nonce: None,
            }
        );
        // The three PCRs are all zero: a debug-mode enclave.
        assert!(read.is_debug_mode());
        assert_eq!(&BOOT_DOCUMENT[..11], &hex("8444a1013822a0591101bf")[..]);

        // Its chain and its signature verify like those of any document.
        assert_eq!(
            verify_nitro_document(BOOT_DOCUMENT, AWS_NITRO_ROOT_G1, None),
            Ok(read)
        );
        assert_eq!(
            verify_nitro_document(BOOT_DOCUMENT, UNRELATED_ROOT, None),
            Err(AttestationError::Untrusted)
        );
        // It carries no nonce, so it answers no verifier that sent one.
        assert_eq!(
            verify_nitro_document(BOOT_DOCUMENT, AWS_NITRO_ROOT_G1, Some(&[0u8; 32])),
            Err(AttestationError::NonceMismatch)
        );
    }

    #[test]
    fn a_real_document_with_a_definite_length_payload_verifies() {
        let cose = CoseSign1::parse(SAMPLE_DOCUMENT).unwrap();
        assert_eq!(cose.payload.first(), Some(&0xa9));
        let read = read_unverified_nitro_document(SAMPLE_DOCUMENT).unwrap();
        assert_eq!(read.module_id, "i-0918f6c55e3b61d89-enc018aa8b8e2285d13");
        assert_eq!(read.timestamp_ms, 1_695_049_410_860);
        assert!(read.is_debug_mode());
        // Its user data is not a binding: a public key of another program.
        let user_data = read.user_data.clone().unwrap();
        assert_eq!(user_data.len(), 91);
        assert_eq!(read_binding(&user_data), Err(AttestationError::Malformed));
        let nonce = read.nonce.clone().unwrap();
        assert_eq!(nonce.len(), 256);
        assert_eq!(
            verify_nitro_document(SAMPLE_DOCUMENT, AWS_NITRO_ROOT_G1, Some(&nonce)),
            Ok(read)
        );
        assert_eq!(
            verify_nitro_document(SAMPLE_DOCUMENT, UNRELATED_ROOT, Some(&nonce)),
            Err(AttestationError::Untrusted)
        );
        let mut changed = SAMPLE_DOCUMENT.to_vec();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert_eq!(
            verify_nitro_document(&changed, AWS_NITRO_ROOT_G1, Some(&nonce)),
            Err(AttestationError::Forged)
        );
    }

    // CBOR writers for the documents the tests build.

    fn head(major: u8, argument: u64) -> Vec<u8> {
        let major = major << 5;
        if argument < 24 {
            vec![major | argument as u8]
        } else if argument <= 0xff {
            vec![major | 24, argument as u8]
        } else if argument <= 0xffff {
            let mut out = vec![major | 25];
            out.extend_from_slice(&(argument as u16).to_be_bytes());
            out
        } else if argument <= 0xffff_ffff {
            let mut out = vec![major | 26];
            out.extend_from_slice(&(argument as u32).to_be_bytes());
            out
        } else {
            let mut out = vec![major | 27];
            out.extend_from_slice(&argument.to_be_bytes());
            out
        }
    }

    fn cbor_text(text: &str) -> Vec<u8> {
        let mut out = head(CBOR_TEXT, text.len() as u64);
        out.extend_from_slice(text.as_bytes());
        out
    }

    fn cbor_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut out = head(CBOR_BYTES, bytes.len() as u64);
        out.extend_from_slice(bytes);
        out
    }

    /// A certificate authority shaped like the one of Nitro attestation: a P-384 root, one
    /// intermediate and a leaf whose key signs documents. `direct_leaf` is a second leaf that
    /// the root issued itself.
    struct Authority {
        root: Vec<u8>,
        intermediate: Vec<u8>,
        intermediate_key: EcdsaKeyPair,
        leaf: Vec<u8>,
        leaf_key: EcdsaKeyPair,
        direct_leaf: Vec<u8>,
        direct_leaf_key: EcdsaKeyPair,
    }

    /// The time of the documents the tests build: 2026-09-21, inside the validity of the
    /// test leaves (2026-09-01 to 2026-10-01).
    const DOCUMENT_TIME_MS: u64 = 1_790_000_000_000;

    fn authority() -> Authority {
        let certificate = |name: &str, ca: bool| {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, name);
            if ca {
                params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                params.key_usages = vec![
                    rcgen::KeyUsagePurpose::KeyCertSign,
                    rcgen::KeyUsagePurpose::CrlSign,
                    rcgen::KeyUsagePurpose::DigitalSignature,
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
        };
        let key = || rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let signer = |key: &rcgen::KeyPair| {
            EcdsaKeyPair::from_pkcs8(
                &ECDSA_P384_SHA384_FIXED_SIGNING,
                &key.serialize_der(),
                &SystemRandom::new(),
            )
            .unwrap()
        };
        let root_key = key();
        let root = certificate("test attestation root", true)
            .self_signed(&root_key)
            .unwrap();
        let intermediate_key = key();
        let intermediate = certificate("test attestation zone", true)
            .signed_by(&intermediate_key, &root, &root_key)
            .unwrap();
        let leaf_key = key();
        let leaf = certificate("test enclave", false)
            .signed_by(&leaf_key, &intermediate, &intermediate_key)
            .unwrap();
        let direct_leaf_key = key();
        let direct_leaf = certificate("test enclave under the root", false)
            .signed_by(&direct_leaf_key, &root, &root_key)
            .unwrap();
        Authority {
            root: root.der().to_vec(),
            intermediate: intermediate.der().to_vec(),
            intermediate_key: signer(&intermediate_key),
            leaf: leaf.der().to_vec(),
            leaf_key: signer(&leaf_key),
            direct_leaf: direct_leaf.der().to_vec(),
            direct_leaf_key: signer(&direct_leaf_key),
        }
    }

    /// The parts of a document the tests build. `payload_pairs` are the encoded key and value
    /// pairs of the payload map, in order. `indefinite` writes the payload map with an
    /// indefinite length, as the NSM does.
    #[derive(Clone)]
    struct Parts {
        protected: Vec<u8>,
        payload_pairs: Vec<(&'static str, Vec<u8>)>,
        indefinite: bool,
        tagged: bool,
    }

    const PCRS: [[u8; 48]; 3] = [[0xa0; 48], [0xa1; 48], [0xa2; 48]];

    fn pcrs_value(pcrs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut out = head(CBOR_MAP, pcrs.len() as u64);
        for (index, value) in pcrs {
            out.extend(head(CBOR_UNSIGNED, *index));
            out.extend(cbor_bytes(value));
        }
        out
    }

    /// The sixteen PCRs of a document whose first three are `pcrs`.
    fn sixteen(pcrs: &[[u8; 48]; 3]) -> Vec<(u64, Vec<u8>)> {
        let mut all: Vec<(u64, Vec<u8>)> = pcrs
            .iter()
            .enumerate()
            .map(|(index, pcr)| (index as u64, pcr.to_vec()))
            .collect();
        all.extend((3..16).map(|index| (index, vec![0u8; 48])));
        all
    }

    fn cabundle_value(certificates: &[&[u8]]) -> Vec<u8> {
        let mut out = head(CBOR_ARRAY, certificates.len() as u64);
        for certificate in certificates {
            out.extend(cbor_bytes(certificate));
        }
        out
    }

    const NONCE: [u8; 32] = [0x5a; 32];

    /// The parts of a document of an enclave with the PCRs [`PCRS`] whose user data is
    /// `user_data` and whose nonce is [`NONCE`], in the key order of a real document.
    fn parts(authority: &Authority, user_data: &[u8]) -> Parts {
        Parts {
            protected: vec![0xa1, 0x01, 0x38, 0x22],
            payload_pairs: vec![
                (
                    "module_id",
                    cbor_text("i-0123456789abcdef0-enc0123456789abcdef"),
                ),
                ("digest", cbor_text("SHA384")),
                ("timestamp", head(CBOR_UNSIGNED, DOCUMENT_TIME_MS)),
                ("pcrs", pcrs_value(&sixteen(&PCRS))),
                ("certificate", cbor_bytes(&authority.leaf)),
                (
                    "cabundle",
                    cabundle_value(&[&authority.root, &authority.intermediate]),
                ),
                ("public_key", vec![0xf6]),
                ("user_data", cbor_bytes(user_data)),
                ("nonce", cbor_bytes(&NONCE)),
            ],
            indefinite: true,
            tagged: false,
        }
    }

    impl Parts {
        fn set(mut self, key: &'static str, value: Vec<u8>) -> Parts {
            let pair = self
                .payload_pairs
                .iter_mut()
                .find(|(name, _)| *name == key)
                .unwrap();
            pair.1 = value;
            self
        }

        fn without(mut self, key: &str) -> Parts {
            self.payload_pairs.retain(|(name, _)| *name != key);
            self
        }

        fn payload(&self) -> Vec<u8> {
            let mut out = if self.indefinite {
                vec![0xbf]
            } else {
                head(CBOR_MAP, self.payload_pairs.len() as u64)
            };
            for (key, value) in &self.payload_pairs {
                out.extend(cbor_text(key));
                out.extend_from_slice(value);
            }
            if self.indefinite {
                out.push(0xff);
            }
            out
        }

        /// The document, signed by `key` over the Sig_structure of its parts.
        fn signed_by(&self, key: &EcdsaKeyPair) -> Vec<u8> {
            let payload = self.payload();
            self.assemble(&payload, &sign(key, &self.protected, &payload))
        }

        fn assemble(&self, payload: &[u8], signature: &[u8]) -> Vec<u8> {
            let mut out = if self.tagged { vec![0xd2] } else { Vec::new() };
            out.extend(head(CBOR_ARRAY, 4));
            out.extend(cbor_bytes(&self.protected));
            out.extend(head(CBOR_MAP, 0));
            out.extend(cbor_bytes(payload));
            out.extend(cbor_bytes(signature));
            out
        }
    }

    /// The raw signature of `key` over the Sig_structure of a header and a payload.
    fn sign(key: &EcdsaKeyPair, protected: &[u8], payload: &[u8]) -> Vec<u8> {
        key.sign(&SystemRandom::new(), &sig_structure(protected, payload))
            .unwrap()
            .as_ref()
            .to_vec()
    }

    fn node_keys() -> NodeKeys {
        NodeKeys::from_random(&[0x11; 32], &[0x22; 32])
    }

    #[test]
    fn a_document_under_the_trust_root_verifies_in_every_form() {
        let authority = authority();
        let keys = node_keys();
        let bound = binding(&keys, "v1.0.0", None);
        let parts = parts(&authority, &bound);
        let verify = |document: &[u8], nonce: Option<&[u8]>| {
            verify_nitro_document(document, &authority.root, nonce)
        };
        let document = parts.signed_by(&authority.leaf_key);
        let verified = verify(&document, Some(&NONCE)).unwrap();
        assert_eq!(
            verified,
            NitroDocument {
                module_id: "i-0123456789abcdef0-enc0123456789abcdef".to_string(),
                timestamp_ms: DOCUMENT_TIME_MS,
                pcr0: PCRS[0],
                pcr1: PCRS[1],
                pcr2: PCRS[2],
                user_data: Some(bound.clone()),
                nonce: Some(NONCE.to_vec()),
            }
        );
        assert!(!verified.is_debug_mode());
        assert_eq!(
            read_binding(&bound),
            Ok(NodeBinding {
                sign_public: keys.sign_public(),
                seal_public: keys.seal_public(),
                release: "v1.0.0".to_string(),
                log: None,
            })
        );
        assert_eq!(verify(&document, None), Ok(verified.clone()));
        assert_eq!(
            verify(&document, Some(&[0x5b; 32])),
            Err(AttestationError::NonceMismatch)
        );

        // With the COSE_Sign1 tag, and with the payload as a definite-length map instead of
        // the indefinite-length one.
        let tagged = Parts {
            tagged: true,
            ..parts.clone()
        };
        assert_eq!(
            verify(&tagged.signed_by(&authority.leaf_key), None),
            Ok(verified.clone())
        );
        let definite = Parts {
            indefinite: false,
            ..parts.clone()
        };
        assert_eq!(definite.payload()[0], 0xa9);
        assert_eq!(parts.payload()[0], 0xbf);
        assert_eq!(
            verify(&definite.signed_by(&authority.leaf_key), None),
            Ok(verified.clone())
        );

        // The copy of the root that the document carries is not read: any bytes in its place
        // change nothing, and the trust root decides.
        let other_first = parts.clone().set(
            "cabundle",
            cabundle_value(&[b"not a certificate", &authority.intermediate]),
        );
        assert_eq!(
            verify(&other_first.signed_by(&authority.leaf_key), None),
            Ok(verified)
        );

        // A document requested without user data and nonce holds null in their place.
        let bare = parts
            .clone()
            .set("user_data", vec![0xf6])
            .set("nonce", vec![0xf6])
            .signed_by(&authority.leaf_key);
        let read = verify(&bare, None).unwrap();
        assert_eq!((read.user_data, read.nonce), (None, None));
        assert_eq!(
            verify(&bare, Some(&NONCE)),
            Err(AttestationError::NonceMismatch)
        );

        // A PCR that is all zero marks a debug-mode enclave. The verification returns it: the
        // caller refuses it.
        for index in 0..3 {
            let mut pcrs = PCRS;
            pcrs[index] = [0; 48];
            let debug = parts
                .clone()
                .set("pcrs", pcrs_value(&sixteen(&pcrs)))
                .signed_by(&authority.leaf_key);
            assert!(verify(&debug, None).unwrap().is_debug_mode(), "PCR{index}");
        }
    }

    #[test]
    fn the_chain_leads_to_the_trust_root_at_the_time_of_the_document() {
        let authority = authority();
        let parts = parts(&authority, &binding(&node_keys(), "v1.0.0", None));
        let document = parts.signed_by(&authority.leaf_key);
        let verify =
            |document: &[u8]| verify_nitro_document(document, &authority.root, None).map(|_| ());
        assert_eq!(verify(&document), Ok(()));

        // Another root: the same chain shape under an authority the verifier does not trust.
        let other = self::authority();
        assert_eq!(
            verify_nitro_document(&document, &other.root, None).map(|_| ()),
            Err(AttestationError::Untrusted)
        );
        assert_eq!(
            verify_nitro_document(&document, AWS_NITRO_ROOT_G1, None).map(|_| ()),
            Err(AttestationError::Untrusted)
        );

        // A document dated after the validity of its certificate, and one dated before it.
        // The time of the verifier is not looked at: the timestamp is part of what is signed.
        for timestamp_ms in [
            DOCUMENT_TIME_MS + 11 * 86_400_000,
            DOCUMENT_TIME_MS - 30 * 86_400_000,
        ] {
            let dated = parts
                .clone()
                .set("timestamp", head(CBOR_UNSIGNED, timestamp_ms));
            assert_eq!(
                verify(&dated.signed_by(&authority.leaf_key)),
                Err(AttestationError::Untrusted),
                "{timestamp_ms}"
            );
        }

        // Without the intermediate certificate the chain does not reach the root.
        let short = parts
            .clone()
            .set("cabundle", cabundle_value(&[&authority.root]));
        assert_eq!(
            verify(&short.signed_by(&authority.leaf_key)),
            Err(AttestationError::Untrusted)
        );
        // A certificate authority as the certificate of the document. The document is signed
        // with the key of that certificate, so only the chain rule refuses it.
        let issuer_as_leaf = parts
            .clone()
            .set("certificate", cbor_bytes(&authority.intermediate))
            .set("cabundle", cabundle_value(&[&authority.root]));
        assert_eq!(
            verify(&issuer_as_leaf.signed_by(&authority.intermediate_key)),
            Err(AttestationError::Untrusted)
        );
        let not_a_certificate = parts
            .clone()
            .set("certificate", cbor_bytes(b"not a certificate"));
        assert_eq!(
            verify(&not_a_certificate.signed_by(&authority.leaf_key)),
            Err(AttestationError::Untrusted)
        );

        // A certificate the root issued itself needs no intermediate: `cabundle` holds the
        // root alone. The array still has at least one element.
        let direct = parts
            .clone()
            .set("certificate", cbor_bytes(&authority.direct_leaf))
            .set("cabundle", cabundle_value(&[&authority.root]));
        assert_eq!(
            verify(&direct.signed_by(&authority.direct_leaf_key)),
            Ok(())
        );
        let empty = direct.set("cabundle", cabundle_value(&[]));
        assert_eq!(
            verify(&empty.signed_by(&authority.direct_leaf_key)),
            Err(AttestationError::Malformed)
        );
    }

    #[test]
    fn the_signature_of_the_certificate_key_covers_the_header_and_the_payload() {
        let authority = authority();
        let parts = parts(&authority, &binding(&node_keys(), "v1.0.0", None));
        let payload = parts.payload();
        let verify =
            |document: &[u8]| verify_nitro_document(document, &authority.root, None).map(|_| ());
        assert_eq!(verify(&parts.signed_by(&authority.leaf_key)), Ok(()));

        // Signed by a key that is not the key of the certificate.
        let other = self::authority();
        assert_eq!(
            verify(&parts.signed_by(&other.leaf_key)),
            Err(AttestationError::Forged)
        );
        assert_eq!(
            verify(&parts.signed_by(&authority.intermediate_key)),
            Err(AttestationError::Forged)
        );

        // The payload changed after it was signed: the binding of another node in its place.
        let signature = sign(&authority.leaf_key, &parts.protected, &payload);
        let swapped = parts.clone().set(
            "user_data",
            cbor_bytes(&binding(
                &NodeKeys::from_random(&[0x77; 32], &[0x88; 32]),
                "v1.0.0",
                None,
            )),
        );
        assert_eq!(
            verify(&swapped.assemble(&swapped.payload(), &signature)),
            Err(AttestationError::Forged)
        );
        // A signature of 96 bytes that is not one.
        assert_eq!(
            verify(&parts.assemble(&payload, &[0u8; 96])),
            Err(AttestationError::Forged)
        );
        assert_eq!(
            verify(&parts.assemble(&payload, &[0xffu8; 96])),
            Err(AttestationError::Forged)
        );
        // A signature that is not 96 bytes.
        for signature in [&signature[..95], &[0xffu8; 97][..], &[][..]] {
            assert_eq!(
                verify(&parts.assemble(&payload, signature)),
                Err(AttestationError::Malformed)
            );
        }

        // A header that names another algorithm, or more than the algorithm. Each document is
        // signed over its own header, so only the header rule refuses it.
        for protected in [
            vec![0xa1, 0x01, 0x26],                   // {1: -7}
            vec![0xa1, 0x01, 0x38, 0x23],             // {1: -36}
            vec![0xa2, 0x01, 0x38, 0x22, 0x04, 0x40], // {1: -35, 4: h''}
            vec![0xa0],                               // {}
            vec![],
        ] {
            let other_header = Parts {
                protected: protected.clone(),
                ..parts.clone()
            };
            assert_eq!(
                verify(&other_header.signed_by(&authority.leaf_key)),
                Err(AttestationError::Malformed),
                "{protected:?}"
            );
        }
    }

    #[test]
    fn every_field_of_the_payload_is_required_with_its_type() {
        let authority = authority();
        let parts = parts(&authority, &binding(&node_keys(), "v1.0.0", None));
        // Every document here is signed as it is, so only the form of its payload decides.
        let outcome = |changed: Parts| {
            verify_nitro_document(
                &changed.signed_by(&authority.leaf_key),
                &authority.root,
                None,
            )
            .map(|_| ())
        };
        assert_eq!(outcome(parts.clone()), Ok(()));
        for key in [
            "module_id",
            "digest",
            "timestamp",
            "pcrs",
            "certificate",
            "cabundle",
            "user_data",
            "nonce",
        ] {
            assert_eq!(
                outcome(parts.clone().without(key)),
                Err(AttestationError::Malformed),
                "without {key}"
            );
        }
        // `public_key` is not one of them.
        assert_eq!(outcome(parts.clone().without("public_key")), Ok(()));

        let two_pcrs: Vec<(u64, Vec<u8>)> = sixteen(&PCRS).into_iter().take(2).collect();
        let mut short_pcr = sixteen(&PCRS);
        short_pcr[5].1 = vec![0u8; 32];
        let mut twice = sixteen(&PCRS);
        twice.push((0, PCRS[0].to_vec()));
        let changes: Vec<(&str, Vec<u8>)> = vec![
            ("module_id", cbor_bytes(b"id")),
            ("digest", cbor_text("SHA256")),
            ("digest", cbor_bytes(b"SHA384")),
            ("timestamp", cbor_text("now")),
            ("timestamp", vec![0x20]),
            ("pcrs", pcrs_value(&two_pcrs)),
            ("pcrs", pcrs_value(&short_pcr)),
            ("pcrs", pcrs_value(&twice)),
            ("pcrs", cbor_bytes(&[0u8; 48])),
            ("certificate", vec![0xf6]),
            ("cabundle", cbor_bytes(&authority.intermediate)),
            (
                "cabundle",
                head(CBOR_ARRAY, 1).into_iter().chain([0xf6]).collect(),
            ),
            ("user_data", cbor_text("text")),
            ("nonce", head(CBOR_UNSIGNED, 7)),
        ];
        for (key, value) in changes {
            assert_eq!(
                outcome(parts.clone().set(key, value.clone())),
                Err(AttestationError::Malformed),
                "{key} {value:02x?}"
            );
        }
        // A key that appears twice.
        for key in ["user_data", "timestamp", "module_id"] {
            let mut doubled = parts.clone();
            let again = doubled
                .payload_pairs
                .iter()
                .find(|(name, _)| *name == key)
                .unwrap()
                .clone();
            doubled.payload_pairs.push(again);
            assert_eq!(outcome(doubled), Err(AttestationError::Malformed), "{key}");
        }
        // Bytes after the payload map.
        let payload = [parts.payload(), vec![0x00]].concat();
        let signature = sign(&authority.leaf_key, &parts.protected, &payload);
        assert_eq!(
            verify_nitro_document(&parts.assemble(&payload, &signature), &authority.root, None),
            Err(AttestationError::Malformed)
        );
    }

    #[test]
    fn maps_and_arrays_are_read_with_a_definite_or_an_indefinite_length() {
        let authority = authority();
        let parts = parts(&authority, &binding(&node_keys(), "v1.0.0", None));
        let verify =
            |document: &[u8]| verify_nitro_document(document, &authority.root, None).map(|_| ());

        // The inner map and array in their indefinite-length form.
        let mut pcrs = vec![0xbf];
        for (index, value) in sixteen(&PCRS) {
            pcrs.extend(head(CBOR_UNSIGNED, index));
            pcrs.extend(cbor_bytes(&value));
        }
        pcrs.push(0xff);
        let mut cabundle = vec![0x9f];
        cabundle.extend(cbor_bytes(&authority.root));
        cabundle.extend(cbor_bytes(&authority.intermediate));
        cabundle.push(0xff);
        let inner = parts
            .clone()
            .set("pcrs", pcrs.clone())
            .set("cabundle", cabundle.clone());
        assert_eq!(verify(&inner.signed_by(&authority.leaf_key)), Ok(()));

        // The outer array and the unprotected map in their indefinite-length form, and the
        // header as the indefinite-length map {1: -35}.
        let payload = parts.payload();
        let outer = |protected: &[u8]| {
            let mut out = vec![0x9f];
            out.extend(cbor_bytes(protected));
            out.extend_from_slice(&[0xbf, 0xff]);
            out.extend(cbor_bytes(&payload));
            out.extend(cbor_bytes(&sign(&authority.leaf_key, protected, &payload)));
            out.push(0xff);
            out
        };
        let good = outer(&parts.protected);
        assert_eq!(verify(&good), Ok(()));
        assert_eq!(verify(&outer(&[0xbf, 0x01, 0x38, 0x22, 0xff])), Ok(()));

        // An indefinite-length array without its break, with a fifth item, or followed by a
        // byte.
        assert_eq!(
            verify(&good[..good.len() - 1]),
            Err(AttestationError::Malformed)
        );
        let mut five = good[..good.len() - 1].to_vec();
        five.extend_from_slice(&[0x00, 0xff]);
        assert_eq!(verify(&five), Err(AttestationError::Malformed));
        let mut trailing = good.clone();
        trailing.push(0x00);
        assert_eq!(verify(&trailing), Err(AttestationError::Malformed));

        // Each of the following payloads is signed as it is, so only its form refuses it.
        let outcome = |payload: Vec<u8>| {
            let signature = sign(&authority.leaf_key, &parts.protected, &payload);
            verify(&parts.assemble(&payload, &signature))
        };
        assert_eq!(outcome(parts.payload()), Ok(()));
        // A payload map without its break, with a key that has no value before the break, and
        // a break after a definite-length map.
        let whole = parts.payload();
        assert_eq!(
            outcome(whole[..whole.len() - 1].to_vec()),
            Err(AttestationError::Malformed)
        );
        let mut dangling = whole[..whole.len() - 1].to_vec();
        dangling.extend(cbor_text("extra"));
        dangling.push(0xff);
        assert_eq!(outcome(dangling), Err(AttestationError::Malformed));
        let mut definite = Parts {
            indefinite: false,
            ..parts.clone()
        }
        .payload();
        definite.push(0xff);
        assert_eq!(outcome(definite), Err(AttestationError::Malformed));
        // An inner map or array without its break.
        assert_eq!(
            outcome(
                parts
                    .clone()
                    .set("pcrs", pcrs[..pcrs.len() - 1].to_vec())
                    .payload()
            ),
            Err(AttestationError::Malformed)
        );
        assert_eq!(
            outcome(
                parts
                    .clone()
                    .set("cabundle", cabundle[..cabundle.len() - 1].to_vec())
                    .payload()
            ),
            Err(AttestationError::Malformed)
        );

        // Indefinite-length strings are not read: a byte string in chunks as the user data, and
        // a text string in chunks as a value that would only be skipped.
        let bound = binding(&node_keys(), "v1.0.0", None);
        let mut chunked = vec![0x5f];
        chunked.extend(cbor_bytes(&bound[..10]));
        chunked.extend(cbor_bytes(&bound[10..]));
        chunked.push(0xff);
        assert_eq!(
            outcome(parts.clone().set("user_data", chunked).payload()),
            Err(AttestationError::Malformed)
        );
        assert_eq!(
            outcome(
                parts
                    .clone()
                    .set("public_key", vec![0x7f, 0x61, b'a', 0xff])
                    .payload()
            ),
            Err(AttestationError::Malformed)
        );
    }

    #[test]
    fn nested_items_are_skipped_up_to_the_nesting_limit() {
        let skip = |bytes: &[u8]| {
            let mut reader = CborReader::new(bytes);
            reader.skip(0).map(|()| reader.is_end())
        };
        // Definite and indefinite containers inside each other, with null, an integer, a
        // float and a tagged value.
        assert_eq!(
            skip(&[
                0x9f, 0xa1, 0x61, b'k', 0xbf, 0x01, 0x82, 0xf6, 0xfb, 0, 0, 0, 0, 0, 0, 0, 0, 0xff,
                0xc1, 0x1a, 0, 0, 0, 1, 0x40, 0xff,
            ]),
            Ok(true)
        );
        assert_eq!(skip(&[0x9f, 0xff]), Ok(true));
        assert_eq!(skip(&[0xbf, 0xff]), Ok(true));
        // A container that never ends, a pair without its value, a break out of place.
        assert_eq!(skip(&[0x9f, 0x01]), Err(Malformed));
        assert_eq!(skip(&[0xbf, 0x01, 0xff]), Err(Malformed));
        assert_eq!(skip(&[0xff]), Err(Malformed));
        assert_eq!(skip(&[0x82, 0x01, 0xff]), Err(Malformed));
        // Strings of an indefinite length.
        assert_eq!(skip(&[0x5f, 0x41, 0x00, 0xff]), Err(Malformed));
        assert_eq!(skip(&[0x7f, 0x61, b'a', 0xff]), Err(Malformed));
        // A definite length beyond the input.
        assert_eq!(
            skip(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Err(Malformed)
        );
        assert_eq!(
            skip(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Err(Malformed)
        );

        // An item may sit sixteen containers deep, in either form, and not deeper.
        for (open, close) in [(0x81u8, None), (0x9f, Some(0xffu8))] {
            let nested = |levels: usize| {
                let mut bytes = vec![open; levels];
                bytes.push(0x00);
                if let Some(close) = close {
                    bytes.extend(std::iter::repeat_n(close, levels));
                }
                bytes
            };
            assert_eq!(skip(&nested(16)), Ok(true), "{open:#x}");
            assert_eq!(skip(&nested(17)), Err(Malformed), "{open:#x}");
        }
    }

    #[test]
    fn a_binding_is_read_strictly() {
        let keys = node_keys();
        let value = |change: fn(&mut serde_json::Value)| {
            let mut value = json!({
                "v": 1,
                "sign": b64u(&NodeKeys::from_random(&[1; 32], &[2; 32]).sign_public()),
                "seal": b64u(&NodeKeys::from_random(&[1; 32], &[2; 32]).seal_public()),
                "release": "v1.0.0",
            });
            change(&mut value);
            to_json(&value)
        };
        assert!(read_binding(&binding(&keys, "v1.0.0", None)).is_ok());
        assert!(read_binding(&value(|_| {})).is_ok());
        // Keys the protocol does not define are ignored.
        assert!(read_binding(&value(|binding| binding["future"] = json!(true))).is_ok());
        // A binding states its log store, or none.
        assert_eq!(read_binding(&value(|_| {})).unwrap().log, None);
        let log = LogStoreId::parse("character-credential-log-prod-1", "us-west-2").unwrap();
        assert_eq!(
            read_binding(&binding(&keys, "v1.0.0", Some(&log)))
                .unwrap()
                .log,
            Some(log.clone())
        );
        let stated = read_binding(&value(
            |binding| binding["log"] = json!({"bucket": "character-credential-log-prod-1", "region": "us-west-2", "future": 1}),
        ));
        assert_eq!(stated.unwrap().log, Some(log));

        let changes: [fn(&mut serde_json::Value); 16] = [
            // A log store that is not a bucket name and a region name.
            |binding| binding["log"] = json!(null),
            |binding| binding["log"] = json!("character-credential-log-prod-1"),
            |binding| binding["log"] = json!({"bucket": "character-credential-log-prod-1"}),
            |binding| binding["log"] = json!({"region": "us-west-2"}),
            |binding| binding["log"] = json!({"bucket": "Bucket", "region": "us-west-2"}),
            |binding| binding["log"] = json!({"bucket": "bucket", "region": "us-west-2.example"}),
            // Another version with everything else in place.
            |binding| binding["v"] = json!(2),
            |binding| binding["v"] = json!("1"),
            |binding| binding["sign"] = json!(b64u(&[0x31; 31])),
            |binding| binding["seal"] = json!(b64u(&[0x31; 33])),
            // A sealing key HPKE cannot seal to.
            |binding| binding["seal"] = json!(b64u(&[0u8; 32])),
            |binding| binding["release"] = json!(1),
            |binding| {
                binding.as_object_mut().unwrap().remove("sign");
            },
            |binding| {
                binding.as_object_mut().unwrap().remove("seal");
            },
            |binding| {
                binding.as_object_mut().unwrap().remove("release");
            },
            // A binding of more than 512 bytes.
            |binding| binding["release"] = json!("r".repeat(512)),
        ];
        for (index, change) in changes.into_iter().enumerate() {
            assert_eq!(
                read_binding(&value(change)),
                Err(AttestationError::Malformed),
                "change {index}"
            );
        }
        for other in [&b"not json"[..], b"", b"[]", b"1"] {
            assert_eq!(read_binding(other), Err(AttestationError::Malformed));
        }
        // 512 bytes are a binding, 513 are not.
        let fits = |release_length: usize| {
            to_json(&json!({
                "v": 1,
                "sign": b64u(&keys.sign_public()),
                "seal": b64u(&keys.seal_public()),
                "release": "r".repeat(release_length),
            }))
        };
        let frame = fits(0).len();
        assert_eq!(fits(512 - frame).len(), 512);
        assert!(read_binding(&fits(512 - frame)).is_ok());
        assert_eq!(
            read_binding(&fits(513 - frame)),
            Err(AttestationError::Malformed)
        );
    }

    #[test]
    fn a_local_document_is_read_strictly() {
        let keys = node_keys();
        let bound = binding(&keys, "v1.0.0", None);
        let document = |change: fn(&mut serde_json::Value)| {
            let mut value = json!({
                "v": 1, "platform": "local", "binding": b64u(&binding(&node_keys(), "v1.0.0", None)),
                "nonce": b64u(&NONCE), "time_ms": DOCUMENT_TIME_MS,
            });
            change(&mut value);
            to_json(&value)
        };
        let read = read_local_document(&document(|_| {})).unwrap();
        assert_eq!(
            read,
            LocalDocument {
                binding: bound.clone(),
                nonce: NONCE.to_vec(),
                time_ms: DOCUMENT_TIME_MS,
            }
        );
        assert_eq!(
            read_binding(&read.binding).unwrap().sign_public,
            keys.sign_public()
        );

        let changes: [fn(&mut serde_json::Value); 9] = [
            |document| document["v"] = json!(2),
            |document| document["platform"] = json!("nitro"),
            |document| document["binding"] = json!(7),
            |document| document["binding"] = json!("not base64url!"),
            |document| document["nonce"] = json!(7),
            |document| document["time_ms"] = json!("now"),
            |document| {
                document.as_object_mut().unwrap().remove("binding");
            },
            |document| {
                document.as_object_mut().unwrap().remove("nonce");
            },
            |document| {
                document.as_object_mut().unwrap().remove("time_ms");
            },
        ];
        for (index, change) in changes.into_iter().enumerate() {
            assert_eq!(
                read_local_document(&document(change)),
                Err(AttestationError::Malformed),
                "change {index}"
            );
        }
        for other in [&b"not json"[..], b"", b"[]"] {
            assert_eq!(read_local_document(other), Err(AttestationError::Malformed));
        }
        // A Nitro document is not a local document, and the reverse.
        assert_eq!(
            read_local_document(OPERATIONAL_DOCUMENT),
            Err(AttestationError::Malformed)
        );
        assert_eq!(
            read_unverified_nitro_document(&document(|_| {})),
            Err(AttestationError::Malformed)
        );
    }

    #[test]
    fn a_raw_ecdsa_signature_becomes_its_der_form() {
        // r starts with a set bit and gets a zero byte in front, s has leading zero bytes
        // that are dropped.
        let mut raw = [0u8; 96];
        raw[0] = 0x80;
        raw[47] = 0x01;
        raw[48 + 46] = 0x7f;
        raw[48 + 47] = 0x02;
        let der = ecdsa_der(&raw).unwrap();
        let mut expected = vec![0x30, 2 + 49 + 2 + 2, 0x02, 49, 0x00, 0x80];
        expected.extend_from_slice(&[0u8; 46]);
        expected.push(0x01);
        expected.extend_from_slice(&[0x02, 2, 0x7f, 0x02]);
        assert_eq!(der, expected);
        // A zero is the integer 0.
        assert_eq!(
            ecdsa_der(&[0u8; 96]).unwrap(),
            [0x30, 6, 0x02, 1, 0x00, 0x02, 1, 0x00]
        );
        assert_eq!(ecdsa_der(&[1u8; 95]), None);
        assert_eq!(ecdsa_der(&[1u8; 97]), None);
    }

    #[test]
    fn the_signed_message_is_the_cose_signature1_array() {
        let message = sig_structure(&[0xa1, 0x01, 0x38, 0x22], &[0xaa; 300]);
        let mut expected = vec![0x84, 0x6a];
        expected.extend_from_slice(b"Signature1");
        expected.extend_from_slice(&[0x44, 0xa1, 0x01, 0x38, 0x22, 0x40, 0x59, 0x01, 0x2c]);
        expected.extend_from_slice(&[0xaa; 300]);
        assert_eq!(message, expected);
        // The lengths use the shortest form.
        let mut out = Vec::new();
        push_bytes(&mut out, &[1u8; 23]);
        assert_eq!(out[0], 0x57);
        let mut out = Vec::new();
        push_bytes(&mut out, &[1u8; 24]);
        assert_eq!(&out[..2], &[0x58, 24]);
        let mut out = Vec::new();
        push_bytes(&mut out, &vec![1u8; 70_000]);
        assert_eq!(&out[..5], &[0x5a, 0x00, 0x01, 0x11, 0x70]);
    }

    #[test]
    fn the_es384_header_is_the_map_of_the_algorithm_alone() {
        assert!(is_es384_header(&[0xa1, 0x01, 0x38, 0x22]));
        // The same map with an indefinite length.
        assert!(is_es384_header(&[0xbf, 0x01, 0x38, 0x22, 0xff]));
        for other in [
            &[0xbf, 0x01, 0x38, 0x22][..],
            &[0xbf, 0x01, 0x38, 0x22, 0x04, 0x40, 0xff],
            &[0xbf, 0xff],
            &[0xa1, 0x01, 0x38, 0x22, 0x00],
            &[0xa1, 0x01, 0x18, 0x22],
            &[0xa1, 0x02, 0x38, 0x22],
            &[0x81, 0x01],
            &[],
        ] {
            assert!(!is_es384_header(other), "{other:?}");
        }
    }
}
