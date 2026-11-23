//! A vault value that `release` hands out sealed (enclave.md 5.9): the value, sealed to a
//! public key the caller of `release` named for that one call.
//!
//! A call of `release` may carry `seal_to`, an X25519 public key. The node then answers with
//! the value under a single-shot HPKE seal to that key in the place of the value itself, so
//! the bytes of the response do not hold the value: whoever carries the response between the
//! node and the holder of the private key (the host program, a gateway, the network between
//! them) carries a ciphertext.
//!
//! The seal changes where the value is in the clear on its way. It does not change who can
//! read it: the caller chose the key, the caller is the operator domain, and the holder of the
//! private key reads the value. A sealed value is a released value, with the log entry of a
//! release.

use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::encoding::{b64u, b64u_decode, b64u_decode_array};
use crate::envelope::{hpke_open, hpke_seal, is_usable_seal_key};
use crate::secret::Secret;
use crate::{purpose, ProtocolError};

/// The public key a call of `release` names with `seal_to`: an X25519 public key HPKE can
/// seal to. Only [`SealTo::parse`] creates one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealTo([u8; 32]);

impl SealTo {
    /// Reads `seal_to`: b64u of 32 bytes that are a key HPKE can seal to (not a point of small
    /// order, for which the X25519 output is all zero: RFC 9180 7.1.4). `None` for every other
    /// text.
    pub fn parse(text: &str) -> Option<SealTo> {
        b64u_decode_array::<32>(text)
            .ok()
            .filter(is_usable_seal_key)
            .map(SealTo)
    }

    /// The 32 bytes of the key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A vault value under the seal of [`seal_released`]: `{"enc": b64u(32 bytes), "ct": b64u}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedValue {
    pub enc: String,
    pub ct: String,
}

/// The HPKE AAD of a sealed vault value:
/// `UTF-8(user_id + "\n" + record id + "\n" + field + "\n" + origin)`. It binds the ciphertext
/// to the release it answers: the account, the record, the field and the origin of the call,
/// as the log entry of that release names them.
pub fn released_aad(user_id: &str, record_id: &str, field: &str, origin: &str) -> Vec<u8> {
    format!("{user_id}\n{record_id}\n{field}\n{origin}").into_bytes()
}

/// Seals a vault value to the key the caller of `release` named: single-shot HPKE (protocol.md
/// section 2), HPKE info `pickle.secure.v3.release`, AAD [`released_aad`], plaintext the UTF-8
/// bytes of the value. `hpke_seed` is the input keying material of the ephemeral key pair: a
/// node passes 32 fresh random bytes.
///
/// The result holds the value under a key the operator domain chose, so it is a released
/// value: the caller of this function holds the `log` object of the release, as for a value
/// that leaves in the clear.
pub fn seal_released(
    to: &SealTo,
    user_id: &str,
    record_id: &str,
    field: &str,
    origin: &str,
    value: &Secret<String>,
    hpke_seed: &Secret<[u8; 32]>,
) -> Result<SealedValue, ProtocolError> {
    let (enc, ct) = hpke_seal(
        to.public_key(),
        purpose::RELEASE_SEAL.as_bytes(),
        &released_aad(user_id, record_id, field, origin),
        value.expose_secret().as_bytes(),
        hpke_seed.expose_secret(),
    )?;
    Ok(SealedValue {
        enc: b64u(&enc),
        ct: b64u(&ct),
    })
}

/// The receiver of a sealed vault value: the X25519 key pair the caller of `release` makes for
/// one call. It names the public key with `seal_to` and opens `sealed` of the response with
/// the private key.
///
/// A node does not call this type: it holds the private key of no caller. The generator of the
/// test vectors and the tests use it in the place of the caller.
pub struct Receiver(StaticSecret);

impl Receiver {
    /// The key pair whose private key is these 32 bytes (the X25519 implementation does the
    /// clamping). A caller passes 32 fresh random bytes for every call.
    pub fn from_random(private: &[u8; 32]) -> Receiver {
        Receiver(StaticSecret::from(*private))
    }

    /// `seal_to` of the call: b64u of the public key.
    pub fn seal_to(&self) -> String {
        b64u(&PublicKey::from(&self.0).to_bytes())
    }

    /// Opens `sealed` of the response to the call that asked for `field` of the record
    /// `record_id` of `user_id` at `origin`: the UTF-8 bytes of the value. Every failure is
    /// `open_failed`: a ciphertext that was sealed to another key, or for another account,
    /// record, field or origin, does not open.
    pub fn open(
        &self,
        user_id: &str,
        record_id: &str,
        field: &str,
        origin: &str,
        sealed: &SealedValue,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let enc = b64u_decode(&sealed.enc).map_err(|_| ProtocolError::OpenFailed)?;
        let ct = b64u_decode(&sealed.ct).map_err(|_| ProtocolError::OpenFailed)?;
        hpke_open(
            &self.0,
            &enc,
            purpose::RELEASE_SEAL.as_bytes(),
            &released_aad(user_id, record_id, field, origin),
            &ct,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::to_json;

    const USER_ID: &str = "user-1";
    const RECORD_ID: &str = "MTExMTExMTExMTExMTExMQ";
    const ORIGIN: &str = "https://shop.example";

    fn receiver() -> Receiver {
        Receiver::from_random(&[0x41u8; 32])
    }

    fn sealed(value: &str) -> SealedValue {
        seal_released(
            &SealTo::parse(&receiver().seal_to()).unwrap(),
            USER_ID,
            RECORD_ID,
            "password",
            ORIGIN,
            &Secret::new(value.to_string()),
            &Secret::new([0x33; 32]),
        )
        .unwrap()
    }

    #[test]
    fn a_sealed_value_opens_under_the_named_key_and_the_values_of_its_release() {
        let sealed = sealed("hunter2 값");
        assert_eq!(b64u_decode(&sealed.enc).unwrap().len(), 32);
        // The ciphertext is the value and the tag of 16 bytes.
        assert_eq!(
            b64u_decode(&sealed.ct).unwrap().len(),
            "hunter2 값".len() + 16
        );
        assert_eq!(
            receiver()
                .open(USER_ID, RECORD_ID, "password", ORIGIN, &sealed)
                .unwrap()
                .as_slice(),
            "hunter2 값".as_bytes()
        );
        // The two keys in their order, and the type reads what it writes.
        let text = String::from_utf8(to_json(&sealed)).unwrap();
        assert_eq!(
            text,
            format!("{{\"enc\":\"{}\",\"ct\":\"{}\"}}", sealed.enc, sealed.ct)
        );
        assert_eq!(serde_json::from_str::<SealedValue>(&text).unwrap(), sealed);
        // The same input gives the same bytes.
        assert_eq!(sealed, self::sealed("hunter2 값"));
    }

    #[test]
    fn a_sealed_value_opens_for_no_other_release_and_no_other_key() {
        let sealed = sealed("hunter2");
        for (user_id, record_id, field, origin) in [
            ("user-2", RECORD_ID, "password", ORIGIN),
            (USER_ID, "MjIyMjIyMjIyMjIyMjIyMg", "password", ORIGIN),
            (USER_ID, RECORD_ID, "value", ORIGIN),
            (USER_ID, RECORD_ID, "password", "https://other.example"),
        ] {
            assert_eq!(
                receiver()
                    .open(user_id, record_id, field, origin, &sealed)
                    .map(|_| ()),
                Err(ProtocolError::OpenFailed),
                "{user_id} {record_id} {field} {origin}"
            );
        }
        // Another private key.
        assert_eq!(
            Receiver::from_random(&[0x42u8; 32])
                .open(USER_ID, RECORD_ID, "password", ORIGIN, &sealed)
                .map(|_| ()),
            Err(ProtocolError::OpenFailed)
        );
        // A changed ciphertext, and text that is no base64url.
        let mut changed = sealed.clone();
        changed.ct = format!("A{}", &sealed.ct[1..]);
        let mut malformed = sealed.clone();
        malformed.enc = "not base64url!".to_string();
        for other in [changed, malformed] {
            assert_eq!(
                receiver()
                    .open(USER_ID, RECORD_ID, "password", ORIGIN, &other)
                    .map(|_| ()),
                Err(ProtocolError::OpenFailed)
            );
        }
        // Another purpose string: the seal of a command, of a transfer or of a secret use does
        // not open as a released value.
        let private = StaticSecret::from([0x41u8; 32]);
        for info in [
            purpose::MESSAGE,
            purpose::PEER_SEAL,
            purpose::SECRET_USE_SEAL,
        ] {
            assert!(hpke_open(
                &private,
                &b64u_decode(&sealed.enc).unwrap(),
                info.as_bytes(),
                &released_aad(USER_ID, RECORD_ID, "password", ORIGIN),
                &b64u_decode(&sealed.ct).unwrap(),
            )
            .is_err());
        }
        assert!(hpke_open(
            &private,
            &b64u_decode(&sealed.enc).unwrap(),
            b"pickle.secure.v3.release",
            &released_aad(USER_ID, RECORD_ID, "password", ORIGIN),
            &b64u_decode(&sealed.ct).unwrap(),
        )
        .is_ok());
    }

    #[test]
    fn seal_to_is_a_key_hpke_can_seal_to() {
        let seal_to = receiver().seal_to();
        let to = SealTo::parse(&seal_to).unwrap();
        assert_eq!(b64u(to.public_key()), seal_to);
        for other in [
            String::new(),
            b64u(&[0x51; 31]),
            b64u(&[0x51; 33]),
            // A point of small order: the shared secret would be all zero.
            b64u(&[0u8; 32]),
            // Text that is no base64url, and base64 with its padding.
            "not base64url!".to_string(),
            format!("{seal_to}="),
        ] {
            assert_eq!(SealTo::parse(&other), None, "{other:?}");
        }
    }

    #[test]
    fn the_aad_is_the_four_values_of_the_release_each_on_a_line() {
        assert_eq!(
            released_aad("U", "R", "card_cvc", "https://a.example:8443"),
            b"U\nR\ncard_cvc\nhttps://a.example:8443"
        );
    }
}
