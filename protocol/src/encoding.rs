//! Encodings of protocol.md section 1: base64url without padding, the JSON serialization rule
//! and the `{body, sig}` carriage of signed values.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::ProtocolError;

/// base64url without padding (RFC 4648 section 5).
pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url without padding. Padding characters, characters outside the alphabet and
/// non-canonical trailing bits are rejected with `invalid_request`.
pub fn b64u_decode(text: &str) -> Result<Vec<u8>, ProtocolError> {
    URL_SAFE_NO_PAD
        .decode(text.as_bytes())
        .map_err(|_| ProtocolError::InvalidRequest)
}

/// Decodes base64url into an array of exactly `N` bytes.
pub fn b64u_decode_array<const N: usize>(text: &str) -> Result<[u8; N], ProtocolError> {
    let mut bytes = b64u_decode(text)?;
    let result = <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| ProtocolError::InvalidRequest);
    bytes.zeroize();
    result
}

/// Serializes a value by the rule of protocol.md section 1: no whitespace, separators `,` and
/// `:`, keys in the order the type declares them, integers without an exponent, UTF-8 without a
/// byte order mark.
///
/// Types passed here are structs whose field order is the order the protocol writes, or
/// `serde_json::Value` built with the `preserve_order` feature.
pub fn to_json<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).expect("protocol values serialize to JSON")
}

/// Overwrites every string inside a JSON value with zeros. Used for parsed plaintexts that hold
/// keys or tokens.
pub fn wipe_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(items) => items.iter_mut().for_each(wipe_json),
        serde_json::Value::Object(map) => map.iter_mut().for_each(|(_, item)| wipe_json(item)),
        _ => {}
    }
}

/// A signed JSON value as it is carried: `{"body": b64u(body bytes), "sig": b64u(signature)}`.
///
/// The signature covers the body bytes exactly as carried. A verifier checks the signature over
/// the received bytes and parses the body afterwards. Re-serializing the parsed body before
/// verifying is not allowed by the protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub body: String,
    pub sig: String,
}

/// Signs `body` with Ed25519. The signature input is the purpose string `context` (ASCII, ends
/// with a line feed) followed by the body bytes.
pub fn sign(key: &SigningKey, context: &str, body: &[u8]) -> Signed {
    let mut message = Vec::with_capacity(context.len() + body.len());
    message.extend_from_slice(context.as_bytes());
    message.extend_from_slice(body);
    let signature = key.sign(&message);
    Signed {
        body: b64u(body),
        sig: b64u(&signature.to_bytes()),
    }
}

/// Verifies a signed value over its received body bytes and returns those bytes.
///
/// A `body` or `sig` that is not base64url is `invalid_request`. A signature that does not
/// verify, a signature of the wrong length and a public key that is not a valid Ed25519 key are
/// `bad_signature`.
pub fn verify(
    public_key: &[u8; 32],
    context: &str,
    signed: &Signed,
) -> Result<Vec<u8>, ProtocolError> {
    let body = b64u_decode(&signed.body)?;
    let signature = b64u_decode(&signed.sig)?;
    verify_detached(public_key, context, &body, &signature)?;
    Ok(body)
}

/// Verifies an Ed25519 signature over `context || message`.
pub fn verify_detached(
    public_key: &[u8; 32],
    context: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), ProtocolError> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| ProtocolError::BadSignature)?;
    let signature = Signature::from_slice(signature).map_err(|_| ProtocolError::BadSignature)?;
    let mut input = Vec::with_capacity(context.len() + message.len());
    input.extend_from_slice(context.as_bytes());
    input.extend_from_slice(message);
    let result = key
        .verify_strict(&input, &signature)
        .map_err(|_| ProtocolError::BadSignature);
    input.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::purpose;

    #[test]
    fn b64u_has_no_padding_and_uses_the_url_alphabet() {
        assert_eq!(b64u(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64u(&[]), "");
        assert_eq!(b64u(&[0u8; 16]).len(), 22);
        assert_eq!(b64u(&[0u8; 32]).len(), 43);
        assert_eq!(b64u_decode("-_8").unwrap(), vec![0xfb, 0xff]);
    }

    #[test]
    fn b64u_decode_rejects_padding_other_alphabets_and_trailing_bits() {
        assert_eq!(b64u_decode("-_8="), Err(ProtocolError::InvalidRequest));
        assert_eq!(b64u_decode("+/8"), Err(ProtocolError::InvalidRequest));
        assert_eq!(b64u_decode("a b"), Err(ProtocolError::InvalidRequest));
        // "-_9" carries non-zero trailing bits: not the canonical encoding of any byte string.
        assert_eq!(b64u_decode("-_9"), Err(ProtocolError::InvalidRequest));
        assert_eq!(
            b64u_decode_array::<32>(&b64u(&[1u8; 31])),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(b64u_decode_array::<4>("AQIDBA").unwrap(), [1, 2, 3, 4]);
    }

    #[test]
    fn json_is_compact_ordered_and_utf8() {
        #[derive(Serialize)]
        struct Sample {
            v: u8,
            name: &'static str,
            big: u64,
            flag: bool,
        }
        let bytes = to_json(&Sample {
            v: 1,
            name: "사용자/1",
            big: 1_759_190_400_000,
            flag: false,
        });
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\"v\":1,\"name\":\"사용자/1\",\"big\":1759190400000,\"flag\":false}"
        );
        let value = serde_json::json!({"t": "x", "b": 1, "a": 2});
        assert_eq!(
            String::from_utf8(to_json(&value)).unwrap(),
            "{\"t\":\"x\",\"b\":1,\"a\":2}"
        );
    }

    #[test]
    fn sign_and_verify_cover_context_and_received_bytes() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let public = key.verifying_key().to_bytes();
        // The body is not canonical JSON on purpose: verification is over the carried bytes.
        let body = b"{ \"v\" : 1 }";
        let signed = sign(&key, purpose::REPLY, body);
        assert_eq!(verify(&public, purpose::REPLY, &signed).unwrap(), body);
        assert_eq!(
            verify(&public, purpose::STATEMENT, &signed),
            Err(ProtocolError::BadSignature)
        );
        let mut tampered = signed.clone();
        tampered.body = b64u(b"{\"v\":1}");
        assert_eq!(
            verify(&public, purpose::REPLY, &tampered),
            Err(ProtocolError::BadSignature)
        );
        let other = SigningKey::from_bytes(&[8u8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(
            verify(&other, purpose::REPLY, &signed),
            Err(ProtocolError::BadSignature)
        );
        let mut short = signed.clone();
        short.sig = b64u(&[0u8; 63]);
        assert_eq!(
            verify(&public, purpose::REPLY, &short),
            Err(ProtocolError::BadSignature)
        );
        let mut garbled = signed;
        garbled.sig = "not base64url!".to_string();
        assert_eq!(
            verify(&public, purpose::REPLY, &garbled),
            Err(ProtocolError::InvalidRequest)
        );
    }

    #[test]
    fn signature_matches_rfc_8032_test_vector() {
        // RFC 8032 section 7.1, TEST 2: one-byte message 0x72. With an empty context the
        // signature input is the message itself.
        let seed = hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb").unwrap();
        let key = SigningKey::from_bytes(&<[u8; 32]>::try_from(seed.as_slice()).unwrap());
        assert_eq!(
            key.verifying_key().to_bytes().to_vec(),
            hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c").unwrap()
        );
        let signed = sign(&key, "", &[0x72]);
        assert_eq!(
            b64u_decode(&signed.sig).unwrap(),
            hex(concat!(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            ))
            .unwrap()
        );
    }

    #[test]
    fn wipe_json_clears_every_string() {
        let mut value = serde_json::json!({"a": "secret", "b": ["x", {"c": "y"}], "n": 1});
        wipe_json(&mut value);
        assert_eq!(
            value,
            serde_json::json!({"a": "", "b": ["", {"c": ""}], "n": 1})
        );
    }

    fn hex(text: &str) -> Option<Vec<u8>> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(text.get(index..index + 2)?, 16).ok())
            .collect()
    }
}
