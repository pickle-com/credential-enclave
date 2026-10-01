//! The types that hold a secret of the node (section 2.1 of `docs/egress-policy.md`): the two
//! private keys of a node, user keys, the plaintext of a record, the response of a token
//! address, PKCE verifiers and the key material of an HPKE seal. Two kinds of values of the
//! operator are held in these types as well: the client secrets of the providers and the
//! credentials for the log store.
//!
//! Rule E1 of the egress policy is enforced here. A secret lives in a type of this module and
//! the fields of these types are private to it. The types implement neither `Serialize` nor
//! `Display`, their `Debug` output is a fixed string, and their bytes are overwritten with
//! zeros when they are dropped. The body of a response is built from types that implement
//! `Serialize`, so a secret cannot be a field of a response: such a program does not compile.
//!
//! Rule E2 starts here. The bytes of a [`Secret`] are read through [`Secret::expose_secret`]
//! and through nothing else. `scripts/secret-access.sh` lists every function of the node
//! source that calls it and compares the list with `egress/secret-access.tsv`, which states
//! for each function what it does with the bytes: one of the five sinks (K1 to K5), an
//! operation that stays inside the node, or a declared declassification. The `check` workflow
//! fails when the two differ.
//!
//! The private keys of a node are not a [`Secret`]: [`NodeKeys`] offers the operations that
//! use them (sign, open) and no function that returns them.

use std::fmt;

use ed25519_dalek::{Signer, SigningKey};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::encoding::{b64u, wipe_json, Signed};
use crate::envelope::hpke_open;
use crate::ProtocolError;

/// A value that can be overwritten with zeros in place.
pub trait Wipe {
    fn wipe(&mut self);
}

impl<const N: usize> Wipe for [u8; N] {
    fn wipe(&mut self) {
        self.zeroize();
    }
}

impl Wipe for Vec<u8> {
    fn wipe(&mut self) {
        self.zeroize();
    }
}

impl Wipe for String {
    fn wipe(&mut self) {
        self.zeroize();
    }
}

impl Wipe for serde_json::Value {
    fn wipe(&mut self) {
        wipe_json(self);
    }
}

/// A secret value.
///
/// The value is read through [`Secret::expose_secret`] only. The type implements none of the
/// traits that turn a value into output or let it be read implicitly: no `Serialize`, no
/// `Display`, no `Deref`, no `AsRef`, no `PartialEq`. The lines below compile:
///
/// ```
/// use credential_enclave_protocol::secret::Secret;
/// let secret = Secret::new(String::from("ya29.token"));
/// assert_eq!(format!("{secret:?}"), "Secret(..)");
/// assert_eq!(secret.expose_secret(), "ya29.token");
/// ```
///
/// A secret cannot be serialized:
///
/// ```compile_fail
/// use credential_enclave_protocol::secret::Secret;
/// let secret = Secret::new(String::from("ya29.token"));
/// let _ = serde_json::to_string(&secret);
/// ```
///
/// A struct that holds a secret cannot derive `Serialize`:
///
/// ```compile_fail
/// use credential_enclave_protocol::secret::Secret;
/// #[derive(serde::Serialize)]
/// struct Response {
///     value: Secret<String>,
/// }
/// ```
///
/// A secret cannot be formatted with `{}` or turned into a string:
///
/// ```compile_fail
/// use credential_enclave_protocol::secret::Secret;
/// let secret = Secret::new(String::from("ya29.token"));
/// let _ = format!("{secret}");
/// ```
///
/// ```compile_fail
/// use credential_enclave_protocol::secret::Secret;
/// let secret = Secret::new(String::from("ya29.token"));
/// let _ = secret.to_string();
/// ```
///
/// A secret is not read as its inner value without the accessor:
///
/// ```compile_fail
/// use credential_enclave_protocol::secret::Secret;
/// let secret = Secret::new(String::from("ya29.token"));
/// let _: &str = &secret;
/// ```
///
/// ```compile_fail
/// use credential_enclave_protocol::secret::Secret;
/// let secret = Secret::new(vec![1u8, 2, 3]);
/// let _ = secret.len();
/// ```
pub struct Secret<T: Wipe>(T);

impl<T: Wipe> Secret<T> {
    /// Takes a value into the secret domain.
    pub fn new(value: T) -> Secret<T> {
        Secret(value)
    }

    /// The value. Every function of the node source that calls this is listed in
    /// `egress/secret-access.tsv`.
    pub fn expose_secret(&self) -> &T {
        &self.0
    }
}

impl<const N: usize> Secret<[u8; N]> {
    /// Creates a secret of `N` bytes in place: `fill` writes the bytes, so no copy of them
    /// exists outside the secret.
    pub fn try_from_fn<E>(
        fill: impl FnOnce(&mut [u8; N]) -> Result<(), E>,
    ) -> Result<Secret<[u8; N]>, E> {
        let mut secret = Secret([0u8; N]);
        fill(&mut secret.0)?;
        Ok(secret)
    }
}

/// A key is copied where a delegation is: into the view a call takes of a grant, and into a
/// delegation transfer. Other secrets have no `Clone`.
impl<const N: usize> Clone for Secret<[u8; N]> {
    fn clone(&self) -> Self {
        Secret(self.0)
    }
}

impl<T: Wipe> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.wipe();
    }
}

impl<T: Wipe> fmt::Debug for Secret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret(..)")
    }
}

/// The two key pairs a node creates at boot: an Ed25519 signing key and an X25519 sealing key.
/// Both live as long as the node process.
///
/// The private keys are used by [`NodeKeys::sign`], [`NodeKeys::sign_detached`] and
/// [`NodeKeys::open`]. No function returns them.
///
/// ```compile_fail
/// use credential_enclave_protocol::secret::NodeKeys;
/// let keys = NodeKeys::from_random(&[1u8; 32], &[2u8; 32]);
/// let _ = keys.sign.to_bytes();
/// ```
///
/// ```compile_fail
/// use credential_enclave_protocol::secret::NodeKeys;
/// let keys = NodeKeys::from_random(&[1u8; 32], &[2u8; 32]);
/// let _ = keys.seal.to_bytes();
/// ```
pub struct NodeKeys {
    sign: SigningKey,
    seal: StaticSecret,
}

impl NodeKeys {
    /// Builds the node keys from two 32-byte random values: the Ed25519 seed and the X25519
    /// private key (used as is: clamping is done by the X25519 function).
    pub fn from_random(sign_seed: &[u8; 32], seal_private: &[u8; 32]) -> NodeKeys {
        NodeKeys {
            sign: SigningKey::from_bytes(sign_seed),
            seal: StaticSecret::from(*seal_private),
        }
    }

    /// The Ed25519 public key.
    pub fn sign_public(&self) -> [u8; 32] {
        self.sign.verifying_key().to_bytes()
    }

    /// The X25519 public key.
    pub fn seal_public(&self) -> [u8; 32] {
        PublicKey::from(&self.seal).to_bytes()
    }

    /// The node identifier: `b64u(signing public key)`.
    pub fn node(&self) -> String {
        b64u(&self.sign_public())
    }

    /// Signs `body` with the node signing key and carries it as `{body, sig}`. The signature
    /// input is the purpose string `context` followed by the body bytes.
    pub fn sign(&self, context: &str, body: &[u8]) -> Signed {
        crate::encoding::sign(&self.sign, context, body)
    }

    /// The Ed25519 signature of the node over `context || message`.
    pub fn sign_detached(&self, context: &str, message: &[u8]) -> [u8; 64] {
        let mut input = Vec::with_capacity(context.len() + message.len());
        input.extend_from_slice(context.as_bytes());
        input.extend_from_slice(message);
        let signature = self.sign.sign(&input).to_bytes();
        input.zeroize();
        signature
    }

    /// Opens a single-shot HPKE seal made to the sealing key of this node. Every failure is
    /// `open_failed`.
    pub fn open(
        &self,
        enc: &[u8],
        info: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Secret<Vec<u8>>, ProtocolError> {
        let mut opened = hpke_open(&self.seal, enc, info, aad, ct)?;
        Ok(Secret::new(std::mem::take(&mut *opened)))
    }
}

impl fmt::Debug for NodeKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NodeKeys(..)")
    }
}

/// Fails to compile when `$type` implements one of the traits: the two blanket
/// implementations below then both apply, and the inference of `_` is ambiguous.
macro_rules! assert_not_implemented {
    ($type:ty: $($trait:path),+ $(,)?) => {
        const _: fn() = || {
            trait AmbiguousIfImplemented<A> {
                fn check() {}
            }
            impl<T: ?Sized> AmbiguousIfImplemented<()> for T {}
            $({
                #[allow(dead_code)]
                struct Implemented;
                impl<T: ?Sized + $trait> AmbiguousIfImplemented<Implemented> for T {}
            })+
            let _ = <$type as AmbiguousIfImplemented<_>>::check;
        };
    };
}

assert_not_implemented!(Secret<String>: serde::Serialize, fmt::Display, AsRef<str>, AsRef<[u8]>, Copy, Clone);
assert_not_implemented!(Secret<Vec<u8>>: serde::Serialize, fmt::Display, AsRef<[u8]>, Copy, Clone);
assert_not_implemented!(Secret<[u8; 32]>: serde::Serialize, fmt::Display, AsRef<[u8]>, Copy);
assert_not_implemented!(Secret<serde_json::Value>: serde::Serialize, fmt::Display, Copy, Clone);
assert_not_implemented!(NodeKeys: serde::Serialize, fmt::Display, Copy, Clone);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::verify;
    use crate::envelope::hpke_seal;

    #[test]
    fn the_debug_output_of_a_secret_is_a_fixed_string() {
        let marker = "5f1d0c7a-secret-marker";
        assert_eq!(
            format!("{:?}", Secret::new(marker.to_string())),
            "Secret(..)"
        );
        assert_eq!(
            format!("{:?}", Secret::new(marker.as_bytes().to_vec())),
            "Secret(..)"
        );
        assert_eq!(format!("{:?}", Secret::new([0x5fu8; 32])), "Secret(..)");
        assert_eq!(
            format!("{:#?}", Secret::new(serde_json::json!({"token": marker}))),
            "Secret(..)"
        );
        let keys = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
        assert_eq!(format!("{keys:?}"), "NodeKeys(..)");
        // A structure that derives `Debug` over a secret prints the fixed string as well.
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            name: &'static str,
            value: Secret<String>,
        }
        let printed = format!(
            "{:?}",
            Holder {
                name: "n",
                value: Secret::new(marker.to_string())
            }
        );
        assert!(!printed.contains(marker), "{printed}");
    }

    #[test]
    fn a_secret_is_created_in_place_and_copied_only_as_a_key() {
        let secret = Secret::<[u8; 4]>::try_from_fn(|bytes| {
            bytes.copy_from_slice(&[1, 2, 3, 4]);
            Ok::<(), ()>(())
        })
        .unwrap();
        assert_eq!(secret.expose_secret(), &[1, 2, 3, 4]);
        assert_eq!(secret.clone().expose_secret(), &[1, 2, 3, 4]);
        assert!(Secret::<[u8; 4]>::try_from_fn(|_| Err("no random source")).is_err());
    }

    #[test]
    fn wiping_overwrites_every_byte_and_every_string() {
        let mut bytes = [7u8; 8];
        bytes.wipe();
        assert_eq!(bytes, [0u8; 8]);
        let mut text = String::from("secret");
        text.wipe();
        assert!(text.is_empty());
        let mut value = serde_json::json!({"a": "secret", "b": ["x", {"c": "y"}], "n": 1});
        value.wipe();
        assert_eq!(
            value,
            serde_json::json!({"a": "", "b": ["", {"c": ""}], "n": 1})
        );
    }

    #[test]
    fn node_keys_sign_and_open_without_handing_out_the_private_keys() {
        let keys = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
        let signed = keys.sign(crate::purpose::REPLY, b"{\"v\":1}");
        assert_eq!(
            verify(&keys.sign_public(), crate::purpose::REPLY, &signed).unwrap(),
            b"{\"v\":1}"
        );
        let signature = keys.sign_detached(crate::purpose::PEER, b"payload");
        crate::encoding::verify_detached(
            &keys.sign_public(),
            crate::purpose::PEER,
            b"payload",
            &signature,
        )
        .unwrap();
        let (enc, ct) =
            hpke_seal(&keys.seal_public(), b"info", b"aad", b"plain", &[9u8; 32]).unwrap();
        let opened = keys.open(&enc, b"info", b"aad", &ct).unwrap();
        assert_eq!(opened.expose_secret().as_slice(), b"plain");
        assert_eq!(
            keys.open(&enc, b"info", b"other", &ct).map(|_| ()),
            Err(ProtocolError::OpenFailed)
        );
        assert_eq!(keys.node(), b64u(&keys.sign_public()));
    }
}
