//! The credential record (protocol.md section 6): one secret, encrypted under a key derived
//! from the user key of one custody and bound to its own `id`.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::encoding::{b64u, b64u_decode};
use crate::keys::{record_key, Custody};
use crate::secret::Secret;
use crate::{is_valid_name, purpose, ProtocolError};

/// How a credential is used (rule E6 of the egress policy).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UseMode {
    /// The node uses the value itself. The value never leaves the node.
    EnclaveUse,
    /// The node hands the value to the caller, after the log entry of that release is on the
    /// chain.
    Release,
}

/// The kinds of a record (protocol.md section 6). The kind is part of the AAD of a record, so
/// a record that opens has the kind it names.
///
/// The kind says where the plaintext was made and how it is used:
///
/// | kind | the plaintext was made by | use mode | opened by |
/// | --- | --- | --- | --- |
/// | `oauth` | the node, from the response of a token address | enclave-use | `forward`, `refresh`, `revoke-token`, `oauth/merge` |
/// | `oauth_imported` | the device of the account, from a token the operator domain held before it used this node | enclave-use | `forward`, `refresh`, `revoke-token` |
/// | `vault_password` | the device of the account | release | `release` (field `password`) |
/// | `vault_totp` | the device of the account | enclave-use (the seed stays, the code leaves) | `release` (field `totp`) |
/// | `vault_card` | the device of the account | release | `release` (fields `card_number`, `card_cvc`) |
///
/// No call takes a plaintext from the caller and makes a record of it. A node creates a
/// record of kind `oauth` from a token response it received itself, and writes an existing
/// record of kind `oauth` or `oauth_imported` again after a refresh, under the same kind.
/// The token of an `oauth_imported` record was known to the operator domain before the
/// device encrypted it: such a record does not say that its token never left a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Oauth,
    OauthImported,
    AppPassword,
    VaultPassword,
    VaultTotp,
    VaultCard,
}

impl Kind {
    /// Every kind.
    pub const ALL: [Kind; 6] = [
        Kind::Oauth,
        Kind::OauthImported,
        Kind::AppPassword,
        Kind::VaultPassword,
        Kind::VaultTotp,
        Kind::VaultCard,
    ];

    /// The name the protocol writes.
    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::Oauth => "oauth",
            Kind::OauthImported => "oauth_imported",
            Kind::AppPassword => "app_password",
            Kind::VaultPassword => "vault_password",
            Kind::VaultTotp => "vault_totp",
            Kind::VaultCard => "vault_card",
        }
    }

    /// Reads a kind name. Any other string is `None`.
    pub fn parse(text: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.as_str() == text)
    }

    /// How a record of this kind is used.
    pub const fn use_mode(self) -> UseMode {
        match self {
            Kind::Oauth | Kind::OauthImported | Kind::AppPassword | Kind::VaultTotp => {
                UseMode::EnclaveUse
            }
            Kind::VaultPassword | Kind::VaultCard => UseMode::Release,
        }
    }
}

/// `record` = `JSON {"v":1,"id":<id>,"user_id":"...","key_id":"...","custody":"...",
/// "kind":"...","provider":"...","nonce":b64u(12),"ct":b64u}`. `custody` names the custody of
/// the user key that encrypted the record: `enclave` or `operator`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub v: u8,
    pub id: String,
    pub user_id: String,
    pub key_id: String,
    pub custody: String,
    pub kind: String,
    pub provider: String,
    pub nonce: String,
    pub ct: String,
}

impl Record {
    /// Reads a record from parsed JSON. A `v` other than the integer 1 is
    /// `unsupported_version`. A missing or non-string field is `record_invalid`. Keys the
    /// protocol does not define are ignored.
    pub fn from_value(value: &serde_json::Value) -> Result<Record, ProtocolError> {
        let object = value.as_object().ok_or(ProtocolError::RecordInvalid)?;
        if object.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
            return Err(ProtocolError::UnsupportedVersion);
        }
        let text = |key: &str| {
            object
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .ok_or(ProtocolError::RecordInvalid)
        };
        Ok(Record {
            v: 1,
            id: text("id")?,
            user_id: text("user_id")?,
            key_id: text("key_id")?,
            custody: text("custody")?,
            kind: text("kind")?,
            provider: text("provider")?,
            nonce: text("nonce")?,
            ct: text("ct")?,
        })
    }

    /// The 16 bytes of the record `id`.
    pub fn id_bytes(&self) -> Result<[u8; 16], ProtocolError> {
        let bytes = b64u_decode(&self.id).map_err(|_| ProtocolError::RecordInvalid)?;
        <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| ProtocolError::RecordInvalid)
    }
}

/// `aad` = `UTF-8("pickle.secure.v1.record\n1\n" + id + "\n" + user_id + "\n" + key_id + "\n" +
/// custody + "\n" + kind + "\n" + provider)`.
pub fn record_aad(
    id: &str,
    user_id: &str,
    key_id: &str,
    custody: &str,
    kind: &str,
    provider: &str,
) -> Vec<u8> {
    format!(
        "{}\n1\n{id}\n{user_id}\n{key_id}\n{custody}\n{kind}\n{provider}",
        purpose::RECORD
    )
    .into_bytes()
}

fn is_key_id(text: &str) -> bool {
    text.len() == 16
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Opens a record with the user key of its custody and returns its plaintext.
///
/// Checks `v`, the form of every field and the AEAD tag. A `v` other than 1 is
/// `unsupported_version`. Every other failure is `record_invalid`. The caller compares
/// `user_id` with the account of the call, and `key_id` and `custody` with those of that
/// account's grant, before calling this function (protocol.md section 6).
pub fn open_record(
    user_key: &[u8; 32],
    record: &Record,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    if record.v != 1 {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let id = record.id_bytes()?;
    if !is_valid_name(&record.user_id)
        || !is_valid_name(&record.kind)
        || !is_valid_name(&record.provider)
        || !is_key_id(&record.key_id)
        || Custody::parse(&record.custody).is_none()
    {
        return Err(ProtocolError::RecordInvalid);
    }
    let nonce = b64u_decode(&record.nonce).map_err(|_| ProtocolError::RecordInvalid)?;
    if nonce.len() != 12 {
        return Err(ProtocolError::RecordInvalid);
    }
    let ct = b64u_decode(&record.ct).map_err(|_| ProtocolError::RecordInvalid)?;
    let key = record_key(user_key, &id);
    let aad = record_aad(
        &record.id,
        &record.user_id,
        &record.key_id,
        &record.custody,
        &record.kind,
        &record.provider,
    );
    ChaCha20Poly1305::new(Key::from_slice(key.as_slice()))
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ct,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| ProtocolError::RecordInvalid)
}

/// Creates a record: `ct` = `ChaCha20-Poly1305(record key, nonce, aad, plaintext)`, the
/// ciphertext followed by the 16-byte tag. `user_key` is the user key of `custody`. `id` and
/// `nonce` are fresh random bytes. Writing the same `id` again (a token refresh) uses a new
/// nonce and keeps `id`, `kind` and `provider`.
#[allow(clippy::too_many_arguments)]
pub fn seal_record(
    user_key: &[u8; 32],
    id: &[u8; 16],
    nonce: &[u8; 12],
    user_id: &str,
    key_id: &str,
    custody: Custody,
    kind: &str,
    provider: &str,
    plaintext: &[u8],
) -> Record {
    let id_text = b64u(id);
    let key = record_key(user_key, id);
    let aad = record_aad(&id_text, user_id, key_id, custody.as_str(), kind, provider);
    let ct = ChaCha20Poly1305::new(Key::from_slice(key.as_slice()))
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("a record plaintext is far below the ChaCha20-Poly1305 length limit");
    Record {
        v: 1,
        id: id_text,
        user_id: user_id.to_string(),
        key_id: key_id.to_string(),
        custody: custody.as_str().to_string(),
        kind: kind.to_string(),
        provider: provider.to_string(),
        nonce: b64u(nonce),
        ct: b64u(&ct),
    }
}

/// Opens a record with a user key the node holds. The plaintext is a secret.
///
/// The checks and the failures are those of [`open_record`].
pub fn open(
    user_key: &Secret<[u8; 32]>,
    record: &Record,
) -> Result<Secret<Vec<u8>>, ProtocolError> {
    let mut plaintext = open_record(user_key.expose_secret(), record)?;
    Ok(Secret::new(std::mem::take(&mut *plaintext)))
}

/// Creates a record from a secret plaintext with a user key the node holds.
///
/// This function is sink K1 of the egress policy: a secret leaves the node as the ciphertext
/// of a record, encrypted under a key derived from the user key, with an AAD that binds `id`,
/// `user_id`, `key_id`, `custody`, `kind` and `provider`.
#[allow(clippy::too_many_arguments)]
pub fn seal(
    user_key: &Secret<[u8; 32]>,
    id: &[u8; 16],
    nonce: &[u8; 12],
    user_id: &str,
    key_id: &str,
    custody: Custody,
    kind: Kind,
    provider: &str,
    plaintext: &Secret<Vec<u8>>,
) -> Record {
    seal_record(
        user_key.expose_secret(),
        id,
        nonce,
        user_id,
        key_id,
        custody,
        kind.as_str(),
        provider,
        plaintext.expose_secret(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::to_json;

    const USER_KEY: [u8; 32] = [0x21; 32];
    const KEY_ID: &str = "0123456789abcdef";

    fn sample() -> Record {
        seal_record(
            &USER_KEY,
            &[0x31; 16],
            &[0x41; 12],
            "user-1",
            KEY_ID,
            Custody::Enclave,
            "vault_password",
            "vault",
            b"{\"value\":\"hunter2\"}",
        )
    }

    #[test]
    fn a_record_round_trips() {
        let record = sample();
        assert_eq!(record.id.len(), 22);
        assert_eq!(record.nonce.len(), 16);
        assert_eq!(
            open_record(&USER_KEY, &record).unwrap().as_slice(),
            b"{\"value\":\"hunter2\"}"
        );
        assert_eq!(
            b64u_decode(&record.ct).unwrap().len(),
            "{\"value\":\"hunter2\"}".len() + 16
        );
    }

    #[test]
    fn a_record_serializes_in_the_key_order_of_section_6() {
        let record = sample();
        let text = String::from_utf8(to_json(&record)).unwrap();
        assert_eq!(
            text,
            format!(
                concat!(
                    "{{\"v\":1,\"id\":\"{}\",\"user_id\":\"user-1\",\"key_id\":\"{}\",",
                    "\"custody\":\"enclave\",\"kind\":\"vault_password\",\"provider\":\"vault\",",
                    "\"nonce\":\"{}\",\"ct\":\"{}\"}}"
                ),
                record.id, KEY_ID, record.nonce, record.ct
            )
        );
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(Record::from_value(&value).unwrap(), record);
    }

    #[test]
    fn the_aad_is_the_eight_lines_of_section_6() {
        assert_eq!(
            record_aad("ID", "U", "K", "enclave", "oauth", "slack"),
            b"pickle.secure.v1.record\n1\nID\nU\nK\nenclave\noauth\nslack"
        );
    }

    #[test]
    fn a_record_names_the_custody_of_its_user_key() {
        let build = |custody: Custody| {
            seal_record(
                &USER_KEY,
                &[0x31; 16],
                &[0x41; 12],
                "user-1",
                KEY_ID,
                custody,
                "oauth",
                "google_workspace",
                b"{\"token\":{\"access_token\":\"t\"},\"obtained_ms\":1}",
            )
        };
        let enclave = build(Custody::Enclave);
        let operator = build(Custody::Operator);
        assert_eq!(enclave.custody, "enclave");
        assert_eq!(operator.custody, "operator");
        // The custody is part of the AAD: the same key, id and nonce give another tag.
        assert_ne!(enclave.ct, operator.ct);
        assert!(open_record(&USER_KEY, &operator).is_ok());
        let mut relabelled = operator.clone();
        relabelled.custody = "enclave".to_string();
        assert_eq!(
            open_record(&USER_KEY, &relabelled).map(|_| ()),
            Err(ProtocolError::RecordInvalid)
        );
    }

    #[test]
    fn another_user_key_does_not_open_the_record() {
        assert_eq!(
            open_record(&[0x22; 32], &sample()).map(|_| ()),
            Err(ProtocolError::RecordInvalid)
        );
    }

    #[test]
    fn every_tampered_aad_field_fails_to_open() {
        type Change = fn(&mut Record);
        let tamper: [(&str, Change); 6] = [
            ("id", |record| record.id = b64u(&[0x32; 16])),
            ("user_id", |record| record.user_id = "user-2".to_string()),
            ("key_id", |record| {
                record.key_id = "fedcba9876543210".to_string()
            }),
            ("custody", |record| record.custody = "operator".to_string()),
            ("kind", |record| record.kind = "vault_totp".to_string()),
            ("provider", |record| record.provider = "other".to_string()),
        ];
        for (field, change) in tamper {
            let mut record = sample();
            change(&mut record);
            assert_eq!(
                open_record(&USER_KEY, &record).map(|_| ()),
                Err(ProtocolError::RecordInvalid),
                "{field}"
            );
        }
    }

    #[test]
    fn a_tampered_nonce_or_ciphertext_fails_to_open() {
        let mut record = sample();
        record.nonce = b64u(&[0x42; 12]);
        assert_eq!(
            open_record(&USER_KEY, &record).map(|_| ()),
            Err(ProtocolError::RecordInvalid)
        );
        let mut record = sample();
        let mut ct = b64u_decode(&record.ct).unwrap();
        ct[0] ^= 0x80;
        record.ct = b64u(&ct);
        assert_eq!(
            open_record(&USER_KEY, &record).map(|_| ()),
            Err(ProtocolError::RecordInvalid)
        );
    }

    #[test]
    fn malformed_fields_are_rejected_before_decryption() {
        let mut record = sample();
        record.v = 2;
        assert_eq!(
            open_record(&USER_KEY, &record).map(|_| ()),
            Err(ProtocolError::UnsupportedVersion)
        );
        let changes: [fn(&mut Record); 8] = [
            |record| record.id = b64u(&[0x31; 15]),
            |record| record.nonce = b64u(&[0x41; 11]),
            |record| record.key_id = "0123456789ABCDEF".to_string(),
            |record| record.custody = "hsm".to_string(),
            |record| record.custody = "enclave\nvault_password".to_string(),
            |record| record.kind = String::new(),
            |record| record.provider = "a\nb".to_string(),
            |record| record.ct = "%%%".to_string(),
        ];
        for change in changes {
            let mut record = sample();
            change(&mut record);
            assert_eq!(
                open_record(&USER_KEY, &record).map(|_| ()),
                Err(ProtocolError::RecordInvalid)
            );
        }
        assert_eq!(
            Record::from_value(&serde_json::json!({"v": 2})),
            Err(ProtocolError::UnsupportedVersion)
        );
        assert_eq!(
            Record::from_value(&serde_json::json!({"v": 1, "id": "x"})),
            Err(ProtocolError::RecordInvalid)
        );
        assert_eq!(
            Record::from_value(&serde_json::json!("text")),
            Err(ProtocolError::RecordInvalid)
        );
    }

    #[test]
    fn kinds_have_the_names_and_use_modes_of_the_egress_policy() {
        let table = [
            (Kind::Oauth, "oauth", UseMode::EnclaveUse),
            (Kind::OauthImported, "oauth_imported", UseMode::EnclaveUse),
            (Kind::AppPassword, "app_password", UseMode::EnclaveUse),
            (Kind::VaultPassword, "vault_password", UseMode::Release),
            (Kind::VaultTotp, "vault_totp", UseMode::EnclaveUse),
            (Kind::VaultCard, "vault_card", UseMode::Release),
        ];
        assert_eq!(table.len(), Kind::ALL.len());
        for (kind, name, use_mode) in table {
            assert_eq!(kind.as_str(), name);
            assert_eq!(Kind::parse(name), Some(kind));
            assert_eq!(kind.use_mode(), use_mode);
        }
        for other in ["", "oauth_operator", "api_key", "OAuth", "oauth ", "vault"] {
            assert_eq!(Kind::parse(other), None, "{other:?}");
        }
    }

    #[test]
    fn the_node_functions_seal_and_open_the_same_records() {
        let user_key = Secret::new(USER_KEY);
        let plaintext = Secret::new(b"{\"value\":\"hunter2\"}".to_vec());
        let record = seal(
            &user_key,
            &[0x31; 16],
            &[0x41; 12],
            "user-1",
            KEY_ID,
            Custody::Enclave,
            Kind::VaultPassword,
            "vault",
            &plaintext,
        );
        assert_eq!(record, sample());
        assert_eq!(
            open(&user_key, &record).unwrap().expose_secret().as_slice(),
            b"{\"value\":\"hunter2\"}"
        );
        assert_eq!(
            open(&Secret::new([0x22; 32]), &record).map(|_| ()),
            Err(ProtocolError::RecordInvalid)
        );
    }

    #[test]
    fn rewriting_the_same_id_with_a_new_nonce_changes_the_ciphertext() {
        let first = sample();
        let second = seal_record(
            &USER_KEY,
            &[0x31; 16],
            &[0x43; 12],
            "user-1",
            KEY_ID,
            Custody::Enclave,
            "vault_password",
            "vault",
            b"{\"value\":\"hunter2\"}",
        );
        assert_eq!(first.id, second.id);
        assert_ne!(first.ct, second.ct);
        assert!(open_record(&USER_KEY, &second).is_ok());
    }
}
