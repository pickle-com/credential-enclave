//! Node keys, identifiers, the custody mode and the record key derivation (protocol.md sections
//! 1, 3 and 4.1).

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::encoding::{b64u, to_json};
use crate::purpose;
pub use crate::secret::NodeKeys;

/// The custody mode of a user key (protocol.md section 3): the kind of node that holds it. An
/// app derives one user key per custody and hands a node the key of that node's custody only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Custody {
    /// A node on the `nitro` platform, whose attestation the app verified.
    Enclave,
    /// A node on the `local` platform: an ordinary process that no attestation verifies.
    Operator,
}

impl Custody {
    /// The name the protocol writes: `enclave` or `operator`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Custody::Enclave => "enclave",
            Custody::Operator => "operator",
        }
    }

    /// Reads a custody name. Any other string is `None`.
    pub fn parse(text: &str) -> Option<Custody> {
        match text {
            "enclave" => Some(Custody::Enclave),
            "operator" => Some(Custody::Operator),
            _ => None,
        }
    }
}

/// `node` = `b64u(node signing public key)`: 43 characters.
pub fn node_id(sign_public: &[u8; 32]) -> String {
    b64u(sign_public)
}

/// `key_id` = lowercase hex of the first 8 bytes of `SHA-256(account signing public key)`:
/// 16 characters.
pub fn key_id(sign_pk: &[u8; 32]) -> String {
    let digest = Sha256::digest(sign_pk);
    let mut text = String::with_capacity(16);
    for byte in &digest[..8] {
        text.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble"));
        text.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("nibble"));
    }
    text
}

/// HKDF-SHA256 with a 32-byte output (RFC 5869). An empty `salt` is the zero-length salt.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &str) -> Zeroizing<[u8; 32]> {
    let mut output = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info.as_bytes(), output.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    output
}

/// record key = `HKDF(ikm = the user key of the custody of the record, salt = the 16 bytes of
/// the record id, info = "pickle.secure.v1.record", 32)`.
pub fn record_key(user_key: &[u8; 32], record_id: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    hkdf_sha256(user_key, record_id, purpose::RECORD)
}

/// The log store of a node (protocol.md 4.1 and 7.6): the Amazon S3 bucket that the node writes
/// every log entry to before the act the entry describes, and the region of that bucket.
///
/// A value of this type holds a bucket name and a region name of the forms below, so the host
/// name made of them is always a name under `amazonaws.com`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "LogStoreFields")]
pub struct LogStoreId {
    bucket: String,
    region: String,
}

/// A log store as JSON carries it, before its two names are checked.
#[derive(Deserialize)]
struct LogStoreFields {
    bucket: String,
    region: String,
}

impl TryFrom<LogStoreFields> for LogStoreId {
    type Error = &'static str;

    fn try_from(fields: LogStoreFields) -> Result<LogStoreId, &'static str> {
        LogStoreId::parse(&fields.bucket, &fields.region)
            .ok_or("not a bucket name and a region name")
    }
}

impl LogStoreId {
    /// Reads a bucket name and a region name. Any other pair of strings is `None`.
    ///
    /// | Name | Form |
    /// | --- | --- |
    /// | bucket | 3 to 63 characters: lower-case letters, digits and `-`, and neither the first nor the last character is `-` |
    /// | region | the form of an AWS region name: parts joined by `-`, at least three. The first part is two lower-case letters, the last part is one or two digits, and every part between them is lower-case letters |
    pub fn parse(bucket: &str, region: &str) -> Option<LogStoreId> {
        let bucket_named = (3..=63).contains(&bucket.len())
            && bucket
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !bucket.starts_with('-')
            && !bucket.ends_with('-');
        let parts: Vec<&str> = region.split('-').collect();
        let letters =
            |part: &&str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_lowercase());
        let region_named = match parts.as_slice() {
            [first, between @ .., last] => {
                first.len() == 2
                    && letters(first)
                    && !between.is_empty()
                    && between.iter().all(letters)
                    && (1..=2).contains(&last.len())
                    && last.bytes().all(|byte| byte.is_ascii_digit())
            }
            _ => false,
        };
        (bucket_named && region_named).then(|| LogStoreId {
            bucket: bucket.to_string(),
            region: region.to_string(),
        })
    }

    /// The name of the bucket.
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// The region of the bucket.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// The host a node writes to: `{bucket}.s3.{region}.amazonaws.com`.
    pub fn host(&self) -> String {
        format!("{}.s3.{}.amazonaws.com", self.bucket, self.region)
    }
}

/// The binding document of protocol.md section 4.1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub v: u8,
    pub sign: String,
    pub seal: String,
    pub release: String,
    /// The log store of the node. A node without one writes no `log` key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<LogStoreId>,
}

/// `binding` = `UTF-8(JSON {"v":1,"sign":b64u(node signing public key),
/// "seal":b64u(node sealing public key),"release":<release>})`, and for a node with a log store
/// the key `"log":{"bucket":"...","region":"..."}` after them. The platform attestation carries
/// these bytes as its user data.
pub fn binding(keys: &NodeKeys, release: &str, log: Option<&LogStoreId>) -> Vec<u8> {
    to_json(&Binding {
        v: 1,
        sign: b64u(&keys.sign_public()),
        seal: b64u(&keys.seal_public()),
        release: release.to_string(),
        log: log.cloned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits;

    #[test]
    fn identifiers_have_the_lengths_of_section_1() {
        let keys = NodeKeys::from_random(&[1u8; 32], &[2u8; 32]);
        assert_eq!(keys.node().len(), 43);
        assert_eq!(keys.node(), node_id(&keys.sign_public()));
        let id = key_id(&keys.sign_public());
        assert_eq!(id.len(), 16);
        assert!(id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }

    #[test]
    fn key_id_is_the_first_eight_bytes_of_the_sha256() {
        // SHA-256 of 32 zero bytes starts with 66687aadf862bd77.
        assert_eq!(key_id(&[0u8; 32]), "66687aadf862bd77");
    }

    #[test]
    fn custody_names_are_enclave_and_operator() {
        for custody in [Custody::Enclave, Custody::Operator] {
            assert_eq!(Custody::parse(custody.as_str()), Some(custody));
        }
        assert_eq!(Custody::Enclave.as_str(), "enclave");
        assert_eq!(Custody::Operator.as_str(), "operator");
        for other in [
            "",
            "Enclave",
            "enclave ",
            "nitro",
            "local",
            "enclave\noperator",
        ] {
            assert_eq!(Custody::parse(other), None, "{other:?}");
        }
    }

    #[test]
    fn hkdf_matches_rfc_5869_test_case_3() {
        // RFC 5869 A.3: SHA-256, zero-length salt and info. The first 32 bytes of the OKM.
        let ikm = [0x0bu8; 22];
        let okm = hkdf_sha256(&ikm, &[], "");
        assert_eq!(
            okm.as_slice(),
            [
                0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
                0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
                0x3c, 0x73, 0x8d, 0x2d,
            ]
        );
    }

    #[test]
    fn record_key_depends_on_the_record_id() {
        let user_key = [9u8; 32];
        let first = record_key(&user_key, &[1u8; 16]);
        let second = record_key(&user_key, &[2u8; 16]);
        assert_ne!(first.as_slice(), second.as_slice());
        assert_eq!(
            first.as_slice(),
            hkdf_sha256(&user_key, &[1u8; 16], "pickle.secure.v1.record").as_slice()
        );
    }

    #[test]
    fn binding_has_the_key_order_of_section_4_1() {
        let keys = NodeKeys::from_random(&[1u8; 32], &[2u8; 32]);
        let bytes = binding(&keys, "v1.0.0", None);
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert_eq!(
            text,
            format!(
                "{{\"v\":1,\"sign\":\"{}\",\"seal\":\"{}\",\"release\":\"v1.0.0\"}}",
                b64u(&keys.sign_public()),
                b64u(&keys.seal_public())
            )
        );
        assert!(bytes.len() <= limits::BINDING_BYTES);

        // A node with a log store names it after the release.
        let log = LogStoreId::parse("character-credential-log-prod-1", "us-west-2").unwrap();
        let bytes = binding(&keys, "v1.0.0", Some(&log));
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            format!(
                concat!(
                    "{{\"v\":1,\"sign\":\"{}\",\"seal\":\"{}\",\"release\":\"v1.0.0\",",
                    "\"log\":{{\"bucket\":\"character-credential-log-prod-1\",\"region\":\"us-west-2\"}}}}"
                ),
                b64u(&keys.sign_public()),
                b64u(&keys.seal_public())
            )
        );
        // The longest names fit the limit of a binding.
        let longest = LogStoreId::parse(&"b".repeat(63), "ap-southeast-99").unwrap();
        assert!(binding(&keys, "v1.0.0", Some(&longest)).len() <= limits::BINDING_BYTES);
        // The type reads what it writes, and nothing that is not a log store.
        let read: Binding = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(read.log, Some(log));
        let other = text.replace('}', r#","log":{"bucket":"B","region":"us-west-2"}}"#);
        assert!(serde_json::from_str::<Binding>(&other).is_err());
        assert_eq!(serde_json::from_str::<Binding>(&text).unwrap().log, None);
    }

    #[test]
    fn a_log_store_is_a_bucket_name_and_a_region_name() {
        let log = LogStoreId::parse("character-credential-log-dev-1", "us-west-2").unwrap();
        assert_eq!(log.bucket(), "character-credential-log-dev-1");
        assert_eq!(log.region(), "us-west-2");
        assert_eq!(
            log.host(),
            "character-credential-log-dev-1.s3.us-west-2.amazonaws.com"
        );
        for (bucket, region) in [
            ("abc", "us-west-2"),
            ("a-1", "eu-central-1"),
            ("0bucket9", "ap-southeast-3"),
            ("bucket", "us-gov-east-1"),
            (&"b".repeat(63)[..], "ap-northeast-12"),
        ] {
            assert!(
                LogStoreId::parse(bucket, region).is_some(),
                "{bucket} {region}"
            );
        }
        for (bucket, region) in [
            // A bucket name of another length, or with a character outside the three kinds.
            ("ab", "us-west-2"),
            (&"b".repeat(64)[..], "us-west-2"),
            ("Bucket", "us-west-2"),
            ("my.bucket", "us-west-2"),
            ("my_bucket", "us-west-2"),
            ("bucket/x", "us-west-2"),
            ("-bucket", "us-west-2"),
            ("bucket-", "us-west-2"),
            ("bucket\n", "us-west-2"),
            // A region that is not of the form of a region name: the host would leave S3.
            ("bucket", ""),
            ("bucket", "us-west"),
            ("bucket", "us-2"),
            ("bucket", "US-west-2"),
            ("bucket", "usa-west-2"),
            ("bucket", "us-west-222"),
            ("bucket", "us--2"),
            ("bucket", "us-west-2.evil.example"),
            ("bucket", "us-west-2/"),
            ("bucket", "us-west-2 "),
            ("bucket", "us-we5t-2"),
        ] {
            assert!(
                LogStoreId::parse(bucket, region).is_none(),
                "{bucket} {region}"
            );
        }
    }
}
