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
    for byte in digest.iter().take(8) {
        for half in [byte >> 4, byte & 0x0f] {
            text.extend(char::from_digit(u32::from(half), 16));
        }
    }
    text
}

/// HKDF-SHA256 with a 32-byte output (RFC 5869). An empty `salt` is the zero-length salt.
#[expect(
    clippy::expect_used,
    reason = "HKDF-SHA256 refuses an output of more than 8,160 bytes and nothing else: the \
              output here is the 32 bytes of the array, whatever the three arguments are"
)]
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

    /// The host of the bucket that the binding names: `{bucket}.s3.{region}.amazonaws.com`. The
    /// entries of format 1 and of format 2 are in that bucket, and a reader lists them there.
    pub fn host(&self) -> String {
        format!("{}.s3.{}.amazonaws.com", self.bucket, self.region)
    }

    /// The host a node of format 3 connects to: the endpoint of Amazon S3 in the region of the
    /// log store, `s3.{region}.amazonaws.com`. Every bucket of the log store is written over
    /// connections to this one host, with the bucket as the first part of the path.
    pub fn regional_host(&self) -> String {
        format!("s3.{}.amazonaws.com", self.region)
    }

    /// The number of buckets that hold the entries of format 3 of this log store (protocol.md
    /// 7.6). It is a constant of the name of the log store: a reader computes the bucket of an
    /// account from the name its program holds, and a node from the name of its binding.
    pub fn shards(&self) -> u16 {
        LOG_STORE_SHARDS
            .iter()
            .find(|(bucket, _)| *bucket == self.bucket)
            .map_or(LOG_STORE_SHARDS_DEFAULT, |(_, shards)| *shards)
    }

    /// The bucket that holds the objects of format 3 of the owner with the hash `owner`
    /// ([`shard_hash`] of a `user_id` for the entries of an account, of a node identifier for a
    /// node document): bucket number `owner mod shards`.
    ///
    /// `None` when the name of the log store is too long for the names of its buckets to be
    /// bucket names (more than [`LOG_STORE_NAME_CHARS`] characters): such a log store has no
    /// bucket of format 3, and a node does not take it.
    pub fn shard_of(&self, owner: u16) -> Option<String> {
        self.shard_bucket(owner % self.shards())
    }

    /// The name of bucket number `index` of this log store (protocol.md 7.6):
    /// `{h8}-{bucket}-{index}`, where `index` is written as four decimal digits and `h8` is the
    /// first 8 characters of the lower-case hexadecimal SHA-256 of `{bucket}-{index}`. The
    /// hash in front spreads the names of the buckets of one log store over the name space of
    /// the store. `None` for an index at or above [`LogStoreId::shards`] and for a log store
    /// whose name is longer than [`LOG_STORE_NAME_CHARS`] characters.
    pub fn shard_bucket(&self, index: u16) -> Option<String> {
        if index >= self.shards() || self.bucket.len() > LOG_STORE_NAME_CHARS {
            return None;
        }
        let tail = format!("{}-{index:04}", self.bucket);
        let digest = Sha256::digest(tail.as_bytes());
        let mut name = String::with_capacity(9 + tail.len());
        for byte in digest.iter().take(4) {
            for half in [byte >> 4, byte & 0x0f] {
                name.extend(char::from_digit(u32::from(half), 16));
            }
        }
        name.push('-');
        name.push_str(&tail);
        Some(name)
    }
}

/// The log stores whose number of buckets of format 3 is not the default, by the bucket name of
/// their binding (protocol.md 7.6). Every number is a power of two.
const LOG_STORE_SHARDS: [(&str, u16); 2] = [
    ("character-credential-log-prod-1", 1024),
    ("character-credential-log-local-1", 4),
];

/// The number of buckets of format 3 of every other log store.
const LOG_STORE_SHARDS_DEFAULT: u16 = 32;

/// Longest bucket name of a binding whose buckets of format 3 have bucket names: the 63
/// characters of a bucket name without the hash, the two `-` and the four digits around it.
pub const LOG_STORE_NAME_CHARS: usize = 49;

/// The hash that places the objects of an owner in a bucket of a log store (protocol.md 7.6):
/// the first two bytes of `SHA-256(UTF-8(owner))` as a big-endian unsigned integer. `owner` is
/// the `user_id` of an account or the identifier of a node.
pub fn shard_hash(owner: &str) -> u16 {
    let digest = Sha256::digest(owner.as_bytes());
    let mut first = [0u8; 2];
    for (byte, digest_byte) in first.iter_mut().zip(digest.iter()) {
        *byte = *digest_byte;
    }
    u16::from_be_bytes(first)
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
    /// The role of the node: `reserve` or `forward`. A node of the delegation role writes no
    /// `role` key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// `binding` = `UTF-8(JSON {"v":1,"sign":b64u(node signing public key),
/// "seal":b64u(node sealing public key),"release":<release>})`, and for a node with a log store
/// the key `"log":{"bucket":"...","region":"..."}` after them. The platform attestation carries
/// these bytes as its user data. This is the binding of a node of the delegation role: it has
/// no `role` key.
pub fn binding(keys: &NodeKeys, release: &str, log: Option<&LogStoreId>) -> Vec<u8> {
    role_binding(keys, release, log, Role::Delegation)
}

/// The binding of a node of `role`: the keys of [`binding`], and behind them the key `role`
/// when the role is one a binding names ([`Role::binding_value`]).
pub fn role_binding(
    keys: &NodeKeys,
    release: &str,
    log: Option<&LogStoreId>,
    role: Role,
) -> Vec<u8> {
    to_json(&Binding {
        v: 1,
        sign: b64u(&keys.sign_public()),
        seal: b64u(&keys.seal_public()),
        release: release.to_string(),
        log: log.cloned(),
        role: role.binding_value().map(str::to_string),
    })
}

/// The role of a node, as its binding states it (protocol.md 4.1). A node takes its role
/// once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// The node holds the delegations of accounts: user keys, and with them every record. It
    /// connects to the addresses of its provider definitions and to its log store only.
    Delegation,
    /// The node holds the delegations of accounts as well, and gives and takes delegation
    /// transfers: its binding names the role `reserve`. A node that hands a delegation on
    /// tells such a node from a node of the forward role by that value.
    Reserve,
    /// The node holds no delegation and opens no record. It takes one vault value at a time,
    /// sealed to it by a node of the delegation role together with the one request the value
    /// is for, and sends that request to the host the request names (protocol.md 10.5).
    Forward,
}

impl Role {
    /// The value of the key `role` of a binding: `reserve` for the reserve role, `forward` for
    /// the forward role. A node of the delegation role writes no such key.
    pub const fn binding_value(self) -> Option<&'static str> {
        match self {
            Role::Delegation => None,
            Role::Reserve => Some("reserve"),
            Role::Forward => Some("forward"),
        }
    }

    /// The role a binding states with its key `role`: the delegation role without the key, the
    /// reserve role with the value `reserve`, the forward role with the value `forward`. Any
    /// other value names no role this release knows.
    pub fn of_binding(value: Option<&str>) -> Option<Role> {
        match value {
            None => Some(Role::Delegation),
            Some("reserve") => Some(Role::Reserve),
            Some("forward") => Some(Role::Forward),
            Some(_) => None,
        }
    }

    /// True for a role under which a node holds delegations: a node hands a delegation to a
    /// node of such a role, and to no other node (protocol.md 10.1).
    pub const fn holds_delegations(self) -> bool {
        match self {
            Role::Delegation | Role::Reserve => true,
            Role::Forward => false,
        }
    }
}

/// The binding of a node of the forward role: the keys of [`binding`] and `"role":"forward"`
/// after the release. A node of the forward role writes no log entry and has no log store, so
/// its binding has no `log` key.
pub fn forward_binding(keys: &NodeKeys, release: &str) -> Vec<u8> {
    role_binding(keys, release, None, Role::Forward)
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

    #[test]
    fn a_log_store_has_its_buckets_of_format_3() {
        let store = |bucket: &str| LogStoreId::parse(bucket, "us-west-2").unwrap();
        let prod = store("character-credential-log-prod-1");
        assert_eq!(
            prod.host(),
            "character-credential-log-prod-1.s3.us-west-2.amazonaws.com"
        );
        assert_eq!(prod.regional_host(), "s3.us-west-2.amazonaws.com");
        // The number of buckets is a constant of the name: a power of two.
        assert_eq!(prod.shards(), 1024);
        assert_eq!(store("character-credential-log-local-1").shards(), 4);
        for other in [
            "character-credential-log-dev-1",
            "character-credential-log-alpha-1",
            "character-credential-log-yolo-3",
            "character-credential-log-prod-2",
            "another-bucket",
        ] {
            assert_eq!(store(other).shards(), 32, "{other}");
        }
        // The name of a bucket: the first 8 hexadecimal characters of the SHA-256 of the name
        // of the log store and the number, in front of them.
        let name = prod.shard_bucket(7).unwrap();
        let tail = "character-credential-log-prod-1-0007";
        let digest = Sha256::digest(tail.as_bytes());
        let hash: String = digest[..4]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(name, format!("{hash}-{tail}"));
        assert_eq!(prod.shard_bucket(1023).unwrap().len(), 8 + 1 + tail.len());
        assert_eq!(prod.shard_bucket(1024), None);
        // The names of the buckets of one store start apart, and two stores share no bucket.
        let starts: std::collections::BTreeSet<String> = (0..1024)
            .map(|index| prod.shard_bucket(index).unwrap()[..4].to_string())
            .collect();
        assert!(starts.len() > 900, "{}", starts.len());
        let dev = store("character-credential-log-dev-1");
        assert_ne!(prod.shard_bucket(0), dev.shard_bucket(0));

        // The bucket of an owner: the first two bytes of the SHA-256 of its name, modulo the
        // number of buckets.
        let digest = Sha256::digest("user-1".as_bytes());
        let hash = u16::from_be_bytes([digest[0], digest[1]]);
        assert_eq!(shard_hash("user-1"), hash);
        assert_eq!(prod.shard_of(hash), prod.shard_bucket(hash % 1024));
        assert_eq!(dev.shard_of(hash), dev.shard_bucket(hash % 32));
        // A log store whose name leaves no room for the hash and the number has no bucket.
        assert!(store(&"b".repeat(LOG_STORE_NAME_CHARS))
            .shard_bucket(0)
            .is_some());
        assert_eq!(
            store(&"b".repeat(LOG_STORE_NAME_CHARS + 1)).shard_bucket(0),
            None
        );
        assert_eq!(store(&"b".repeat(63)).shard_of(hash), None);
    }

    #[test]
    fn the_binding_of_the_forward_role_names_the_role_and_no_log_store() {
        let keys = NodeKeys::from_random(&[1u8; 32], &[2u8; 32]);
        let bytes = forward_binding(&keys, "v1.0.0");
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            format!(
                "{{\"v\":1,\"sign\":\"{}\",\"seal\":\"{}\",\"release\":\"v1.0.0\",\"role\":\"forward\"}}",
                b64u(&keys.sign_public()),
                b64u(&keys.seal_public())
            )
        );
        assert!(bytes.len() <= limits::BINDING_BYTES);
        let read: Binding = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(read.role.as_deref(), Some("forward"));
        assert_eq!(read.log, None);
        // The binding of a node of the delegation role has no such key.
        let delegation: Binding = serde_json::from_slice(&binding(&keys, "v1.0.0", None)).unwrap();
        assert_eq!(delegation.role, None);

        assert_eq!(Role::Delegation.binding_value(), None);
        assert_eq!(Role::Reserve.binding_value(), Some("reserve"));
        assert_eq!(Role::Forward.binding_value(), Some("forward"));
        assert_eq!(Role::of_binding(None), Some(Role::Delegation));
        assert_eq!(Role::of_binding(Some("reserve")), Some(Role::Reserve));
        assert_eq!(Role::of_binding(Some("forward")), Some(Role::Forward));
        // A binding names the reserve role behind its log store.
        let log = LogStoreId::parse("log-bucket", "us-west-2").unwrap();
        let reserve: Binding =
            serde_json::from_slice(&role_binding(&keys, "v1.0.0", Some(&log), Role::Reserve))
                .unwrap();
        assert_eq!(
            (reserve.role.as_deref(), reserve.log),
            (Some("reserve"), Some(log))
        );
        // A node hands a delegation to a node that holds delegations, and to no other one.
        assert!(Role::Delegation.holds_delegations() && Role::Reserve.holds_delegations());
        assert!(!Role::Forward.holds_delegations());
        for other in ["", "Forward", "delegation", "forward ", "witness"] {
            assert_eq!(Role::of_binding(Some(other)), None, "{other:?}");
        }
    }
}
