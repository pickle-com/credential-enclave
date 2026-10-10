//! The vault kinds of a record (protocol.md section 6): values an account entered on its
//! device and encrypted there. The node opens them for `release` only.
//!
//! This module owns the types that hold a vault plaintext. A value leaves it in one way: as a
//! [`ReleasedValue`], created by [`Selected::hand_out`] (sink K4 of the egress policy,
//! `docs/egress-policy.md`). The seed of a `vault_totp` record has no way out: the only value
//! this module makes of it is the 6-digit code.

use std::fmt;

use credential_enclave_protocol::encoding::Signed;
use credential_enclave_protocol::record::{Kind, Record};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::totp::totp;
use credential_enclave_protocol::ProtocolError;
use serde::{Serialize, Serializer};
use serde_json::Value;
use zeroize::Zeroize;

use crate::state::{open_for, GrantView};

/// The opened plaintext of a vault record, before a field is taken from it. Only
/// [`open_record`] creates one.
pub struct VaultRecord {
    kind: Kind,
    plaintext: Secret<Vec<u8>>,
}

/// Step 6 of the common front for `release`: opens a record and takes it as a vault record. A
/// record of kind `oauth` or `oauth_imported` is `not_allowed`: no call hands out the
/// plaintext of a token.
pub fn open_record(
    grant: &GrantView,
    user_id: &str,
    record: &Record,
) -> Result<VaultRecord, ProtocolError> {
    match open_for(grant, user_id, record)? {
        (kind @ (Kind::VaultPassword | Kind::VaultTotp | Kind::VaultCard), plaintext) => {
            Ok(VaultRecord { kind, plaintext })
        }
        (Kind::Oauth | Kind::OauthImported | Kind::AppPassword, _) => {
            Err(ProtocolError::NotAllowed)
        }
    }
}

/// The value `release` is about to hand out, still a secret.
pub struct Selected {
    value: Secret<String>,
    kind: Kind,
    is_totp: bool,
}

impl VaultRecord {
    /// Takes the value of `field` (enclave.md 5.9). The pair of kind and field decides:
    ///
    /// | kind | field | value |
    /// | --- | --- | --- |
    /// | `vault_password` | `password` | the `value` of the plaintext |
    /// | `vault_totp` | `totp` | the 6-digit code of the seed at `now_ms` |
    /// | `vault_card` | `card_number`, `card_cvc` | `number` or `cvc` of the plaintext |
    ///
    /// Any other pair is `not_allowed`. A plaintext without the field, and a seed that is not
    /// base32, are `record_invalid`.
    pub fn select(&self, field: &str, now_ms: u64) -> Result<Selected, ProtocolError> {
        let (key, is_totp) = match (self.kind, field) {
            (Kind::VaultPassword, "password") => ("value", false),
            (Kind::VaultTotp, "totp") => ("value", true),
            (Kind::VaultCard, "card_number") => ("number", false),
            (Kind::VaultCard, "card_cvc") => ("cvc", false),
            _ => return Err(ProtocolError::NotAllowed),
        };
        let parsed = Secret::new(
            serde_json::from_slice::<Value>(self.plaintext.expose_secret())
                .map_err(|_| ProtocolError::RecordInvalid)?,
        );
        let stored = parsed
            .expose_secret()
            .get(key)
            .and_then(Value::as_str)
            .ok_or(ProtocolError::RecordInvalid)?;
        let value = if is_totp {
            totp(stored, now_ms)?
        } else {
            stored.to_string()
        };
        Ok(Selected {
            value: Secret::new(value),
            kind: self.kind,
            is_totp,
        })
    }
}

impl Selected {
    /// The kind of the record the value comes from.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// True when the value is a TOTP code. The log entry of such a release is `totp_issued`.
    pub fn is_totp(&self) -> bool {
        self.is_totp
    }

    /// Hands the value out. This is sink K4 of the egress policy: the one place where a vault
    /// value becomes part of a response. `entry` is the log entry of this release, which is on
    /// the chain of the account before the value leaves.
    pub fn hand_out(self, _entry: &Signed) -> ReleasedValue {
        ReleasedValue(self.value.expose_secret().clone())
    }
}

/// A vault value in the response of `release` (class V of the egress policy). Only
/// [`Selected::hand_out`] creates one. The copy is overwritten with zeros when the response was
/// written.
pub struct ReleasedValue(String);

impl Serialize for ReleasedValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl Drop for ReleasedValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for ReleasedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReleasedValue(..)")
    }
}
