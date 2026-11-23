//! The canary tests of the egress policy (egress-policy.md section 3).
//!
//! Every secret a node holds in these tests carries a marker: bytes of high entropy that occur
//! nowhere else. A stand-in plays every provider and the log store, and breaks the contract of
//! a provider where a test says so. The tests then read the channels a node writes to:
//!
//! - C1, the responses to the operator domain. No marker occurs in the status, in a header or
//!   in the body of any response, in any encoding the scan knows. The one exception is the
//!   value a successful `release` call was asked for.
//! - C2 and C4, the connections to providers and to the log store. A node asks for
//!   connections to the hosts of the definitions and to the host of its log store only. A
//!   credential occurs only in requests to the addresses that the definition of its provider
//!   names for that use, and a write to the log store carries no secret of an account.
//! - C5, the connections of a node of the forward role. Such a node asks for connections to
//!   the site of the vault secret whose use it was handed, and to no other host. The value of
//!   that secret occurs in the request to that site, and in no response of the node. That
//!   holds for a value a node of the delegation role read from a record and handed over
//!   (`vault/handoff`) as well: it occurs in no response of that node either.
//! - A node of the reserve role holds the user key of an account and uses no credential. It
//!   asks for connections to the host of its log store and to no other host, and no marker
//!   occurs in a response of it.
//!
//! The tests reach a node through its router only. Every call goes through the fixture, which
//! keeps every response for the verdict on C1: the node under test is a private field of the
//! fixture module, so no test can call it another way.

use std::collections::BTreeSet;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use credential_enclave_protocol::encoding::{b64u, b64u_decode, to_json};
use credential_enclave_protocol::keys::NodeKeys;
use credential_enclave_protocol::totp::totp;
use serde_json::{json, Value};

use self::fixture::{
    at, field, node_keys, Canary, Role, FORWARD, FORWARD_NODE, LOG_STORE, NODES, RESERVE,
    RESERVE_NODE, SITE,
};
use crate::testing::{Forwarded, Reply, Seen};

/// The routes of the router, as method and path: the list the router itself is built from, so
/// a route that is added to the router is a route the walk has to call.
fn routes() -> BTreeSet<(String, String)> {
    let named = |(method, path): (axum::http::Method, &str)| (method.to_string(), path.to_string());
    crate::api::route_list().into_iter().map(named).collect()
}

/// The routes that read nothing of a request and so have no failure of their own. Their
/// failure case is the method they do not accept.
const ROUTES_WITHOUT_A_FAILURE: [(&str, &str); 2] = [("GET", "/v1/health"), ("POST", "/v1/close")];

/// The kinds of events a node writes to a log (protocol.md 7.2).
const EVENTS: [&str; 10] = [
    "grant_accepted",
    "grant_revoked",
    "connection_created",
    "credential_refreshed",
    "connection_removed",
    "grant_transferred_out",
    "grant_transferred_in",
    "provider_request",
    "secret_released",
    "totp_issued",
];

/// The closed vocabulary of `provider_error` (egress-policy.md E5). Beside these words a
/// failure body carries `other` for any other string of the provider, and the empty string
/// when the provider sent none.
const PROVIDER_ERRORS: [&str; 41] = [
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    "access_denied",
    "server_error",
    "temporarily_unavailable",
    "invalid_target",
    "interaction_required",
    "login_required",
    "consent_required",
    "invalid_resource",
    "invalid_refresh_token",
    "token_revoked",
    "token_expired",
    "invalid_auth",
    "account_inactive",
    "invalid_code",
    "code_already_used",
    "bad_client_secret",
    "invalid_client_id",
    "bad_redirect_uri",
    "invalid_grant_type",
    "ratelimited",
    "request_timeout",
    "fatal_error",
    "internal_error",
    "service_unavailable",
    "rate_limit_exceeded",
    "unauthorized",
    "internal_server_error",
    "rate_limited",
    "validation_error",
    "restricted_resource",
    "object_not_found",
    "bad_refresh_token",
    "bad_verification_code",
    "incorrect_client_credentials",
    "refresh_token not found",
];

/// The type of a public field and, for a string, its limit in UTF-8 bytes.
#[derive(Clone, Copy, Debug)]
enum Leaf {
    Text(usize),
    Integer,
    Boolean,
}

type Leaves = &'static [(&'static str, Leaf)];

const OAUTH_LEAVES: Leaves = &[
    ("scope", Leaf::Text(8192)),
    ("expires_in", Leaf::Integer),
    ("token_type", Leaf::Text(32)),
];

/// The public fields of github: the common leaves and the lifetime of the refresh token.
const GITHUB_LEAVES: Leaves = &[
    ("scope", Leaf::Text(8192)),
    ("expires_in", Leaf::Integer),
    ("refresh_token_expires_in", Leaf::Integer),
    ("token_type", Leaf::Text(32)),
];

/// The public fields of every provider (egress-policy.md section 4): the leaves of the token
/// object by their paths, then the claims of the `id_token`. Nothing else of a token response
/// leaves a node.
const PUBLIC: [(&str, Leaves, Leaves); 9] = [
    (
        "google_workspace",
        OAUTH_LEAVES,
        &[
            ("sub", Leaf::Text(255)),
            ("email", Leaf::Text(320)),
            ("email_verified", Leaf::Boolean),
            ("hd", Leaf::Text(255)),
            ("name", Leaf::Text(256)),
            ("picture", Leaf::Text(2048)),
        ],
    ),
    (
        "microsoft",
        &[
            ("scope", Leaf::Text(8192)),
            ("expires_in", Leaf::Integer),
            ("ext_expires_in", Leaf::Integer),
            ("token_type", Leaf::Text(32)),
        ],
        &[
            ("tid", Leaf::Text(64)),
            ("oid", Leaf::Text(64)),
            ("preferred_username", Leaf::Text(320)),
        ],
    ),
    (
        "slack",
        &[
            ("team.id", Leaf::Text(32)),
            ("team.name", Leaf::Text(256)),
            ("enterprise.id", Leaf::Text(32)),
            ("enterprise.name", Leaf::Text(256)),
            ("app_id", Leaf::Text(32)),
            ("is_enterprise_install", Leaf::Boolean),
            ("authed_user.id", Leaf::Text(32)),
            ("authed_user.scope", Leaf::Text(8192)),
            ("authed_user.expires_in", Leaf::Integer),
            ("authed_user.token_type", Leaf::Text(32)),
        ],
        &[],
    ),
    (
        "notion",
        &[
            ("workspace_id", Leaf::Text(64)),
            ("workspace_name", Leaf::Text(256)),
            ("workspace_icon", Leaf::Text(2048)),
            ("bot_id", Leaf::Text(64)),
            ("duplicated_template_id", Leaf::Text(64)),
            ("owner.type", Leaf::Text(32)),
            ("owner.user.id", Leaf::Text(64)),
            ("owner.user.name", Leaf::Text(256)),
            ("owner.user.avatar_url", Leaf::Text(2048)),
            ("owner.user.type", Leaf::Text(32)),
            ("owner.user.person.email", Leaf::Text(320)),
        ],
        &[],
    ),
    ("x", OAUTH_LEAVES, &[]),
    ("link", OAUTH_LEAVES, &[]),
    ("granola", OAUTH_LEAVES, &[]),
    ("mercury", OAUTH_LEAVES, &[]),
    ("github", GITHUB_LEAVES, &[]),
];

impl Leaf {
    /// The value a provider that keeps its contract sends at `path`.
    fn sample(self, path: &str) -> Value {
        match self {
            Leaf::Text(_) => json!(format!("public {path}")),
            Leaf::Integer => json!(3600),
            Leaf::Boolean => json!(true),
        }
    }

    /// True when a value has this type and, for a string, fits the limit. A value that does
    /// not is dropped: it is not a failure of the call.
    fn admits(self, value: &Value) -> bool {
        match (self, value) {
            (Leaf::Text(limit), Value::String(text)) => text.len() <= limit,
            (Leaf::Integer, Value::Number(number)) => number.is_i64() || number.is_u64(),
            (Leaf::Integer, Value::String(text)) => {
                (1..=20).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_digit())
            }
            (Leaf::Boolean, Value::Bool(_)) => true,
            _ => false,
        }
    }
}

/// The public leaves and the public claims of a provider.
fn public_leaves(provider: &str) -> (Leaves, Leaves) {
    PUBLIC
        .iter()
        .find(|(name, _, _)| *name == provider)
        .map(|(_, leaves, claims)| (*leaves, *claims))
        .unwrap_or_else(|| panic!("{provider} has no row in the table of public fields"))
}

/// The value at a path of object keys joined by `.`.
fn lookup<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .try_fold(value, |current, key| current.as_object()?.get(key))
}

/// Writes a value at a path of object keys joined by `.` and creates the objects on the way.
fn set(value: &mut Value, path: &str, leaf: Value) {
    let mut place = value;
    for key in path.split('.') {
        if !place.is_object() {
            *place = json!({});
        }
        place = place
            .as_object_mut()
            .expect("the place is an object")
            .entry(key)
            .or_insert(Value::Null);
    }
    *place = leaf;
}

/// An `id_token` in the form of a JWT. A node reads the claims of the body and verifies no
/// signature, so the third part is free to carry a marker.
fn id_token(claims: &Value, signature: &str) -> String {
    format!(
        "{}.{}.{signature}",
        b64u(br#"{"alg":"RS256","typ":"JWT"}"#),
        b64u(&to_json(claims))
    )
}

/// The claims of the `id_token` of a token object. `null` when it has none.
fn claims_of(token: &Value) -> Value {
    token["id_token"]
        .as_str()
        .and_then(|jwt| jwt.split('.').nth(1))
        .map(|body| serde_json::from_slice(&b64u_decode(body).unwrap()).unwrap())
        .unwrap_or(Value::Null)
}

/// Drops the objects without a key from a JSON value. A node may carry the parent of dropped
/// leaves as an empty object or leave it out: both carry nothing.
fn without_empty_objects(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), without_empty_objects(item)))
                .filter(|(_, item)| item.as_object().is_none_or(|object| !object.is_empty()))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Checks the `public` of a response against the token object it was made from: the listed
/// leaves and the listed claims whose values have the listed type and size, the time of the
/// node, and whether the record holds a refresh token. Nothing else is public.
fn assert_public(provider: &str, token: &Value, public: &Value, has_refresh_token: bool) {
    let (leaves, claims) = public_leaves(provider);
    let mut listed = json!({});
    for (path, leaf) in leaves {
        if let Some(value) = lookup(token, path).filter(|value| leaf.admits(value)) {
            set(&mut listed, path, value.clone());
        }
    }
    let body = claims_of(token);
    let mut claimed = json!({});
    for (claim, leaf) in claims {
        if let Some(value) = body.get(claim).filter(|value| leaf.admits(value)) {
            set(&mut claimed, claim, value.clone());
        }
    }
    let mut public = public.clone();
    public["token"] = without_empty_objects(&public["token"]);
    let obtained_ms = public
        .as_object_mut()
        .and_then(|fields| fields.shift_remove("obtained_ms"));
    assert!(
        obtained_ms.is_some_and(|time| time.is_u64()),
        "{provider}: obtained_ms"
    );
    assert_eq!(
        public,
        json!({
            "token": listed, "id_token_claims": claimed, "has_refresh_token": has_refresh_token,
        }),
        "{provider}"
    );
}

/// The status and the failure code of a JSON answer.
fn code(outcome: &(u16, Value)) -> (u16, &str) {
    (outcome.0, outcome.1["code"].as_str().unwrap_or_default())
}

/// The failure of a `forward` call that must not hand out a provider response.
fn refused(outcome: Result<Forwarded, (u16, Value)>, case: &str) -> (u16, Value) {
    match outcome {
        Ok(forwarded) => panic!(
            "{case}: forward handed out a provider response of status {}",
            forwarded.status
        ),
        Err(failure) => failure,
    }
}

/// Percent-encodes bytes: every byte, or the bytes outside the unreserved characters of RFC
/// 3986 only, with hex digits of the given case.
fn percent_encoded(bytes: &[u8], every_byte: bool, upper: bool) -> String {
    let mut text = String::new();
    for byte in bytes {
        let unreserved = byte.is_ascii_alphanumeric() || b"-._~".contains(byte);
        match (unreserved && !every_byte, upper) {
            (true, _) => text.push(char::from(*byte)),
            (false, true) => text.push_str(&format!("%{byte:02X}")),
            (false, false) => text.push_str(&format!("%{byte:02x}")),
        }
    }
    text
}

/// The scan for markers: the forms a marker takes in bytes that left a node, and the search
/// for them.
mod scan {
    use std::collections::{BTreeMap, HashMap, HashSet};

    use base64::engine::general_purpose::{GeneralPurpose, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    use base64::Engine;
    use credential_enclave_protocol::encoding::to_json;
    use hyper::body::Bytes;
    use serde_json::Value;

    use crate::frame;

    /// Shortest marker, in bytes. A marker of this length does not occur by chance, and every
    /// form of it is longer than the index key of a scanner.
    pub const MARKER_BYTES_MIN: usize = 16;

    /// The leading bytes of a form that a scanner files it under.
    const INDEX_BYTES: usize = 8;

    /// The forms of a marker that the scan searches as they are: the bytes themselves, base64
    /// and base64url at each of the three byte alignments, and hex in lower and upper case.
    ///
    /// A percent-encoded marker has no form of its own: the scan decodes every percent escape
    /// of what it reads ([`layers`]) and finds the marker in the result, whichever bytes were
    /// escaped and whichever case the hex digits have.
    pub fn forms(marker: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut forms = vec![("as it is".to_string(), marker.to_vec())];
        for (name, engine) in [
            ("base64", &STANDARD_NO_PAD),
            ("base64url", &URL_SAFE_NO_PAD),
        ] {
            for front in 0..3 {
                let form = format!("{name} behind {front} bytes");
                forms.push((form, aligned(engine, marker, front)));
            }
        }
        forms.push(("hex".to_string(), hex(marker, false)));
        forms.push(("upper case hex".to_string(), hex(marker, true)));
        forms
    }

    /// The base64 characters that the marker alone decides when `front` bytes (modulo 3)
    /// stand in front of it inside a longer value: the encoding without the characters that
    /// share bits with the bytes in front, and without a last character that shares bits with
    /// the bytes behind.
    fn aligned(engine: &GeneralPurpose, marker: &[u8], front: usize) -> Vec<u8> {
        let mut value = vec![0u8; front];
        value.extend_from_slice(marker);
        let text = engine.encode(&value).into_bytes();
        let shared_front = [0, 2, 3][front];
        let shared_behind = usize::from(!value.len().is_multiple_of(3));
        text[shared_front..text.len() - shared_behind].to_vec()
    }

    /// The hex digits of bytes, in lower or in upper case.
    pub fn hex(bytes: &[u8], upper: bool) -> Vec<u8> {
        let digits: &[u8; 16] = match upper {
            true => b"0123456789ABCDEF",
            false => b"0123456789abcdef",
        };
        bytes
            .iter()
            .flat_map(|byte| {
                [
                    digits[usize::from(byte >> 4)],
                    digits[usize::from(byte & 15)],
                ]
            })
            .collect()
    }

    /// The bytes with every `%` and two hex digits replaced by the byte they name. `None` when
    /// there is no such escape.
    fn percent_decoded(bytes: &[u8]) -> Option<Vec<u8>> {
        let digit = |index: usize| {
            bytes
                .get(index)
                .and_then(|byte| char::from(*byte).to_digit(16))
        };
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            match (bytes[index], digit(index + 1), digit(index + 2)) {
                (b'%', Some(high), Some(low)) => {
                    decoded.push((high * 16 + low) as u8);
                    index += 3;
                }
                (byte, _, _) => {
                    decoded.push(byte);
                    index += 1;
                }
            }
        }
        (decoded.len() < bytes.len()).then_some(decoded)
    }

    /// The runs of base64 or base64url characters that are long enough to hold a marker.
    fn base64_runs(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
        bytes
            .split(|byte| !(byte.is_ascii_alphanumeric() || b"+/-_".contains(byte)))
            .filter(|run| run.len() >= (MARKER_BYTES_MIN * 4).div_ceil(3))
    }

    /// The bytes a string of JSON stands for: its UTF-8 bytes and, when every character is
    /// below U+0100, one byte per character (the way a node carries a header value that is
    /// not UTF-8).
    fn text_layers(text: &str, trail: &str, layers: &mut Vec<(String, Vec<u8>)>) {
        layers.push((trail.to_string(), text.as_bytes().to_vec()));
        if !text.is_ascii() {
            let bytes: Option<Vec<u8>> = text
                .chars()
                .map(|character| u8::try_from(u32::from(character)).ok())
                .collect();
            layers.extend(bytes.map(|bytes| (format!("{trail} characters as bytes"), bytes)));
        }
    }

    /// The strings of a JSON value, keys included, and its arrays of byte values (the form
    /// serde gives a byte array).
    fn json_layers(value: &Value, trail: &str, layers: &mut Vec<(String, Vec<u8>)>) {
        match value {
            Value::String(text) => text_layers(text, trail, layers),
            Value::Array(items) => {
                let bytes: Option<Vec<u8>> = items
                    .iter()
                    .map(|item| item.as_u64().and_then(|byte| u8::try_from(byte).ok()))
                    .collect();
                layers.extend(
                    bytes
                        .filter(|bytes| bytes.len() >= MARKER_BYTES_MIN)
                        .map(|bytes| (format!("{trail} array of bytes"), bytes)),
                );
                for item in items {
                    json_layers(item, trail, layers);
                }
            }
            Value::Object(map) => {
                for (key, item) in map {
                    text_layers(key, trail, layers);
                    json_layers(item, trail, layers);
                }
            }
            _ => {}
        }
    }

    /// The three things a `vault/send` stream holds (enclave.md 5.16), when `bytes` are such a
    /// stream as a whole: its meta, the bytes of its parts one after another, and its end
    /// record. A marker that lies across two parts is in neither of them, and it is in the
    /// bytes of the parts together.
    fn stream(bytes: &[u8]) -> Option<[Vec<u8>; 3]> {
        let length = |at: usize| {
            let prefix: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
            Some(u32::from_be_bytes(prefix) as usize)
        };
        let meta_length = length(0)?;
        let meta = bytes.get(4..4 + meta_length)?;
        serde_json::from_slice::<Value>(meta)
            .ok()
            .filter(Value::is_object)?;
        let mut at = 4 + meta_length;
        let mut body = Vec::new();
        loop {
            let part_length = length(at)?;
            at += 4;
            if part_length == 0 {
                let end = bytes.get(at..)?;
                let record = serde_json::from_slice::<Value>(end).ok()?;
                record.get("complete")?.as_bool()?;
                return Some([meta.to_vec(), body, end.to_vec()]);
            }
            body.extend_from_slice(bytes.get(at..at + part_length)?);
            at += part_length;
        }
    }

    /// Every byte string the scan searches for the bytes it was given: the bytes themselves
    /// and, again and again, what is under an encoding that wraps them: percent escapes, the
    /// strings and byte arrays of JSON, the two parts of a `forward` frame, the meta, the body
    /// and the end record of a `vault/send` stream, and base64 or base64url text. Each layer
    /// names the encodings above it.
    ///
    /// A node signs and seals JSON whose fields are base64url, and carries the result as
    /// base64url again. A key written into such a field is base64url two or three levels deep,
    /// where no single form of the key occurs in the response bytes.
    pub fn layers(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut done = Vec::new();
        let mut known = HashSet::new();
        let mut waiting = vec![(String::new(), bytes.to_vec())];
        // Every layer under an encoding is shorter than the layer it came from, so this ends.
        while let Some((trail, layer)) = waiting.pop() {
            if !known.insert(layer.clone()) {
                continue;
            }
            let under = |encoding: &str| match trail.is_empty() {
                true => encoding.to_string(),
                false => format!("{trail}, {encoding}"),
            };
            if let Some(decoded) = percent_decoded(&layer) {
                waiting.push((under("percent"), decoded));
            }
            if let Ok(value) = serde_json::from_slice::<Value>(&layer) {
                json_layers(&value, &under("JSON"), &mut waiting);
            }
            if let Ok((meta, payload)) = frame::decode(&Bytes::copy_from_slice(&layer)) {
                waiting.push((under("frame"), to_json(&meta)));
                waiting.push((under("frame"), payload.to_vec()));
            }
            if let Some(held) = stream(&layer) {
                waiting.extend(held.map(|bytes| (under("stream"), bytes)));
            }
            for run in base64_runs(&layer) {
                for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
                    if let Ok(decoded) = engine.decode(run) {
                        waiting.push((under("base64"), decoded));
                    }
                }
            }
            done.push((trail, layer));
        }
        done
    }

    struct Needle {
        marker: String,
        form: String,
        bytes: Vec<u8>,
    }

    /// The search for a set of markers.
    pub struct Scanner {
        needles: Vec<Needle>,
        /// The first bytes of a needle to the needles that start with them.
        index: HashMap<[u8; INDEX_BYTES], Vec<usize>>,
    }

    impl Scanner {
        /// A scanner for markers, each with the name a finding reports.
        pub fn new(markers: &[(String, Vec<u8>)]) -> Scanner {
            let mut scanner = Scanner {
                needles: Vec::new(),
                index: HashMap::new(),
            };
            for (name, marker) in markers {
                assert!(
                    marker.len() >= MARKER_BYTES_MIN,
                    "{name}: a marker has at least {MARKER_BYTES_MIN} bytes"
                );
                for (form, bytes) in forms(marker) {
                    let start: [u8; INDEX_BYTES] = bytes[..INDEX_BYTES].try_into().unwrap();
                    let position = scanner.needles.len();
                    scanner.index.entry(start).or_default().push(position);
                    scanner.needles.push(Needle {
                        marker: name.clone(),
                        form,
                        bytes,
                    });
                }
            }
            scanner
        }

        /// The markers that occur in `haystack` or under its encodings, by name, each with
        /// the form it has there. Of several forms of one marker the shortest description is
        /// kept.
        pub fn find(&self, haystack: &[u8]) -> BTreeMap<String, String> {
            let mut findings = BTreeMap::<String, String>::new();
            for (trail, layer) in layers(haystack) {
                for start in 0..layer.len().saturating_sub(INDEX_BYTES - 1) {
                    let key: [u8; INDEX_BYTES] =
                        layer[start..start + INDEX_BYTES].try_into().unwrap();
                    for position in self.index.get(&key).into_iter().flatten() {
                        let needle = &self.needles[*position];
                        if !layer[start..].starts_with(&needle.bytes) {
                            continue;
                        }
                        let form = match trail.is_empty() {
                            true => needle.form.clone(),
                            false => format!("{} under {trail}", needle.form),
                        };
                        let known = findings
                            .entry(needle.marker.clone())
                            .or_insert(form.clone());
                        if form.len() < known.len() {
                            *known = form;
                        }
                    }
                }
            }
            findings
        }
    }

    mod tests {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE};
        use credential_enclave_protocol::encoding::b64u;
        use serde_json::json;

        use super::super::percent_encoded;
        use super::*;

        /// A marker of text with characters that percent-encoding and JSON change, and a
        /// marker of bytes outside UTF-8.
        fn markers() -> [Vec<u8>; 2] {
            [
                b"p7/Qx+2m\"K9-_L\\r4Zt0=wYh8Vn".to_vec(),
                (0u8..24)
                    .map(|index| index.wrapping_mul(89).wrapping_add(131))
                    .collect(),
            ]
        }

        fn found(marker: &[u8], haystack: &[u8]) -> bool {
            let scanner = Scanner::new(&[("marker".to_string(), marker.to_vec())]);
            !scanner.find(haystack).is_empty()
        }

        /// The form of a marker inside other bytes that are not part of its encoding.
        fn embedded(form: &[u8]) -> Vec<u8> {
            [b"{\"field\":\"lead ".as_slice(), form, b" tail\"}"].concat()
        }

        fn percent(bytes: &[u8], every_byte: bool, upper: bool) -> Vec<u8> {
            percent_encoded(bytes, every_byte, upper).into_bytes()
        }

        /// A percent-encoded form with `/` left as it is, the way some encoders write it.
        fn unescaped(form: Vec<u8>) -> Vec<u8> {
            String::from_utf8(form)
                .unwrap()
                .replace("%2F", "/")
                .into_bytes()
        }

        #[test]
        fn a_marker_is_found_in_every_form() {
            for marker in markers() {
                let forms = [
                    ("as it is", marker.clone()),
                    ("percent, every byte, upper", percent(&marker, true, true)),
                    ("percent, every byte, lower", percent(&marker, true, false)),
                    ("percent, reserved, upper", percent(&marker, false, true)),
                    ("percent, reserved, lower", percent(&marker, false, false)),
                    (
                        "percent, reserved but `/`",
                        unescaped(percent(&marker, false, true)),
                    ),
                    ("base64", STANDARD.encode(&marker).into_bytes()),
                    (
                        "base64, no padding",
                        STANDARD_NO_PAD.encode(&marker).into_bytes(),
                    ),
                    ("base64url", URL_SAFE.encode(&marker).into_bytes()),
                    ("base64url, no padding", b64u(&marker).into_bytes()),
                    ("hex", hex(&marker, false)),
                    ("upper case hex", hex(&marker, true)),
                ];
                for (name, form) in forms {
                    assert!(found(&marker, &form), "{name}");
                    assert!(found(&marker, &embedded(&form)), "{name}, embedded");
                }
            }
        }

        #[test]
        fn a_marker_is_found_at_each_base64_alignment_inside_a_longer_value() {
            for marker in markers() {
                for front in 0..3 {
                    for behind in 0..3 {
                        let value = [&b"abc"[..front], &marker, &b"xyz"[..behind]].concat();
                        for text in [STANDARD.encode(&value), b64u(&value)] {
                            // Between other base64 characters the text does not decode at the
                            // alignment it was encoded at: the characters themselves are found.
                            for (lead, tail) in [("", ""), ("\"", "\""), ("Q", "w9"), ("a=", "&b")]
                            {
                                assert!(
                                    found(&marker, format!("{lead}{text}{tail}").as_bytes()),
                                    "{front} bytes in front, {behind} behind, in {lead}..{tail}"
                                );
                            }
                        }
                    }
                }
            }
        }

        #[test]
        fn a_marker_is_found_under_nested_encodings() {
            for marker in markers() {
                // The shape of an attestation response with a key in the place of a public
                // key: base64url three levels deep.
                let binding = json!({"v": 1, "seal": b64u(&marker)});
                let document = json!({"binding": b64u(&to_json(&binding)), "time_ms": 1});
                let response = json!({"document": b64u(&to_json(&document))});
                assert!(found(&marker, &to_json(&response)), "nested base64url");

                // The form serde gives a byte array.
                assert!(found(&marker, &to_json(&json!({"key": marker}))), "array");

                // base64 with its `+`, `/` and `=` percent-encoded, as in an address.
                let address = [
                    b"https://collector.example/?v=".as_slice(),
                    &percent(STANDARD.encode(&marker).as_bytes(), false, true),
                ]
                .concat();
                assert!(found(&marker, &address), "percent-encoded base64");

                // Hex inside base64.
                let wrapped = STANDARD.encode(hex(&marker, false));
                assert!(found(&marker, wrapped.as_bytes()), "hex inside base64");

                // The meta of a `forward` frame, which is not JSON as a whole.
                let meta = json!({"status": 200, "headers": [["x-echo", b64u(&marker)]]});
                let mut response = frame::encode_head(&meta);
                response.extend_from_slice(b"payload");
                assert!(found(&marker, &response), "frame meta");
                let mut response = frame::encode_head(&json!({"status": 200}));
                response.extend_from_slice(&marker);
                assert!(found(&marker, &response), "frame payload");

                // A JSON string: with escapes, and with one character per byte.
                let characters: String = marker.iter().map(|byte| char::from(*byte)).collect();
                assert!(
                    found(
                        &marker,
                        &to_json(&json!({"headers": [["x-echo", characters]]}))
                    ),
                    "characters as bytes"
                );
            }
        }

        #[test]
        fn bytes_that_only_resemble_a_marker_are_not_found() {
            for marker in markers() {
                let mut other = marker.clone();
                other[7] ^= 1;
                let forms = [
                    other.clone(),
                    percent(&other, true, true),
                    STANDARD.encode(&other).into_bytes(),
                    b64u(&[b"ab", other.as_slice()].concat()).into_bytes(),
                    hex(&other, false),
                    to_json(&json!({"key": other, "wrapped": b64u(b64u(&other).as_bytes())})),
                ];
                for form in forms {
                    assert!(!found(&marker, &embedded(&form)));
                }
                // The two halves of the marker, apart.
                let (head, tail) = marker.split_at(marker.len() / 2);
                assert!(!found(&marker, &[head, b" and ", tail].concat()));
                assert!(!found(&marker, b""));
            }
        }
    }
}

/// The fixture of the canary tests: the planted secrets, the provider stand-in, two nodes and
/// the record of everything the nodes answered.
mod fixture {
    use std::collections::{BTreeSet, HashMap};
    use std::sync::{Arc, Mutex};

    use axum::http::Method;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use credential_enclave_protocol::encoding::{b64u, b64u_decode, to_json};
    use credential_enclave_protocol::keys::{record_key, Binding, NodeKeys};
    use credential_enclave_protocol::record::Record;
    use credential_enclave_protocol::secret::Secret as Sealed;
    use credential_enclave_protocol::secret_use::{seal_secret_use, BoundRequest};
    use credential_enclave_protocol::{limits, purpose};
    use hyper::body::Bytes;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256, Sha512};

    use super::scan::Scanner;
    use super::{id_token, public_leaves, set, EVENTS, PROVIDER_ERRORS};
    use crate::frame;
    use crate::providers::{endpoint, ClientKind, Definitions};
    use crate::testing::{
        decode_batch, read_stream, Answer, App, Attested, BatchOutcome, Forwarded, Harness,
        Provider, Reply, Seen, Streamed, LOG_BUCKET, LOG_HOST, LOG_REGION,
    };
    use crate::tests::{provider_and_log_store, provider_hosts};

    /// What a provider address is for in the definition of its provider.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Role {
        /// The token address: exchange and refresh.
        Token,
        /// The revocation address.
        Revocation,
        /// An address of the `api` rules: `forward`.
        Api,
        /// The log store of the node: the object of a log entry.
        LogStore,
        /// The site of a vault secret: the host a use of the secret names (`vault/send`).
        Site,
    }

    /// The name the place of the log store carries where a place names a provider.
    pub const LOG_STORE: &str = "the log store";

    /// The host of the site of the vault secret of a fixture. No provider definition names
    /// it. The place of the site carries this name where a place names a provider.
    pub const SITE: &str = "api.vault-site.example";

    /// The text that stands in a request of a test where the value of the vault secret goes.
    pub const PLACEHOLDER: &str = "CANARY_PLACEHOLDER_0123456789";

    /// The addresses of one role of one provider.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Place {
        pub role: Role,
        pub provider: String,
    }

    pub fn at(role: Role, provider: &str) -> Place {
        Place {
            role,
            provider: provider.to_string(),
        }
    }

    /// A planted secret. Its bytes are a marker of both verdicts.
    #[derive(Clone)]
    pub struct Secret {
        pub name: String,
        pub bytes: Vec<u8>,
        /// The places a request may carry it to on C2. Empty for a secret that no request
        /// carries.
        pub reach: Vec<Place>,
    }

    /// The secrets of one test. A test and its stand-in take every secret value from here, so
    /// every value they plant is a marker of the verdicts.
    #[derive(Default)]
    pub struct Secrets {
        planted: Mutex<Vec<Secret>>,
    }

    /// 32 bytes that depend on the name alone. They stand for the output of a random source:
    /// two names share no run of bytes that a scan could take for the other.
    fn entropy(name: &str) -> [u8; 32] {
        Sha256::digest(format!("canary of the credential enclave\n{name}")).into()
    }

    /// RFC 4648 base32 without padding.
    pub fn base32(bytes: &[u8]) -> String {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut text = String::new();
        let (mut buffer, mut bits) = (0u32, 0u32);
        for byte in bytes {
            buffer = (buffer << 8) | u32::from(*byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                text.push(char::from(alphabet[(buffer >> bits) as usize & 31]));
            }
        }
        if bits > 0 {
            text.push(char::from(alphabet[(buffer << (5 - bits)) as usize & 31]));
        }
        text
    }

    impl Secrets {
        /// Plants a secret. A name stands for one value.
        pub fn add(&self, name: &str, bytes: &[u8], reach: &[Place]) {
            let mut planted = self.planted.lock().unwrap();
            match planted.iter().find(|secret| secret.name == name) {
                Some(known) => assert!(known.bytes == bytes, "{name} names two values"),
                None => planted.push(Secret {
                    name: name.to_string(),
                    bytes: bytes.to_vec(),
                    reach: reach.to_vec(),
                }),
            }
        }

        /// A secret of 32 bytes that no request carries.
        pub fn bytes(&self, name: &str) -> [u8; 32] {
            let bytes = entropy(name);
            self.add(name, &bytes, &[]);
            bytes
        }

        /// A secret of 45 characters. It holds `/` and `+`, which percent-encoding and
        /// base64url write differently, and no character that JSON or a header escapes.
        pub fn text(&self, name: &str, reach: &[Place]) -> String {
            let bytes = entropy(name);
            let (head, middle, tail) = (&bytes[..12], &bytes[12..24], &bytes[24..]);
            let text = format!("{}/{}+{}", b64u(head), b64u(middle), b64u(tail));
            self.add(name, text.as_bytes(), reach);
            text
        }

        /// A secret of 43 base64url characters that no request carries.
        pub fn word(&self, name: &str) -> String {
            let text = b64u(&entropy(name));
            self.add(name, text.as_bytes(), &[]);
            text
        }

        /// A secret of `length` decimal digits that no request carries.
        pub fn digits(&self, name: &str, length: usize) -> String {
            let digit = |byte: &u8| char::from(b'0' + byte % 10);
            let text: String = entropy(name)[..length].iter().map(digit).collect();
            self.add(name, text.as_bytes(), &[]);
            text
        }

        /// A TOTP seed as the base32 text a vault record holds. The text, the text in lower
        /// case (a node reads both cases) and the 20 bytes it decodes to are secrets.
        pub fn totp_seed(&self, name: &str) -> String {
            let bytes = &entropy(name)[..20];
            let text = base32(bytes);
            let lower = text.to_lowercase();
            self.add(&format!("{name} (bytes)"), bytes, &[]);
            self.add(&format!("{name} (base32)"), text.as_bytes(), &[]);
            self.add(
                &format!("{name} (base32, lower case)"),
                lower.as_bytes(),
                &[],
            );
            text
        }

        fn all(&self) -> Vec<Secret> {
            self.planted.lock().unwrap().clone()
        }
    }

    /// The names of the two nodes of the delegation role of a fixture.
    pub const NODES: [&str; 2] = ["node", "peer node"];

    /// The name of the node of the forward role of a fixture, and the number the calls of a
    /// test name it by: the number behind those of the two nodes of the delegation role.
    pub const FORWARD_NODE: &str = "forward node";
    pub const FORWARD: usize = NODES.len();

    /// The name of the node of the reserve role of a fixture, and the number the calls of a
    /// test name it by: the number behind that of the node of the forward role.
    pub const RESERVE_NODE: &str = "reserve node";
    pub const RESERVE: usize = FORWARD + 1;

    /// The name of a node by its number.
    fn name_of(node: usize) -> &'static str {
        match node {
            FORWARD => FORWARD_NODE,
            RESERVE => RESERVE_NODE,
            _ => NODES.get(node).copied().unwrap_or(RESERVE_NODE),
        }
    }

    /// Plants the two private keys of a node and returns them: the signing seed and the
    /// sealing private key.
    ///
    /// What the curves compute from the keys is as secret as the keys. Ed25519 signs with the
    /// two halves of the SHA-512 of its seed, and X25519 clears and sets bits of the first and
    /// of the last byte of its key. The bytes in between are planted under names of their own.
    pub fn node_keys(secrets: &Secrets, node: &str) -> ([u8; 32], [u8; 32]) {
        let sign_seed = secrets.bytes(&format!("signing seed of the {node}"));
        let seal_private = secrets.bytes(&format!("sealing private key of the {node}"));
        let expanded = Sha512::digest(sign_seed);
        let derived = [
            ("signing scalar", &expanded[1..31]),
            ("signing prefix", &expanded[32..]),
            ("sealing scalar", &seal_private[1..31]),
        ];
        for (name, bytes) in derived {
            secrets.add(&format!("{name} of the {node}"), bytes, &[]);
        }
        (sign_seed, seal_private)
    }

    /// A field of a token or revocation request: of its JSON body, or of its form.
    pub fn field(seen: &Seen, key: &str) -> Option<String> {
        match serde_json::from_slice::<Value>(&seen.body) {
            Ok(Value::Object(body)) => body.get(key).and_then(Value::as_str).map(str::to_string),
            _ => seen.form_value(key),
        }
    }

    type Scripted = Box<dyn FnOnce(&Seen) -> Reply + Send>;

    /// The stand-in for every provider. It answers the way a provider that keeps its contract
    /// does, unless a test scripted the answer to the next request of a role.
    pub struct StandIn {
        secrets: Arc<Secrets>,
        definitions: Definitions,
        /// The number of token objects issued per provider.
        issued: Mutex<HashMap<String, usize>>,
        scripted: Mutex<Vec<(Role, Scripted)>>,
    }

    impl StandIn {
        /// The provider names of the definitions, in lexical order.
        pub fn providers(&self) -> Vec<String> {
            self.definitions.names().map(str::to_string).collect()
        }

        /// The places an address belongs to: the roles it has in the definitions. An `api`
        /// rule covers its exact paths, the paths under its prefixes, where a prefix that
        /// does not end with `/` ends at a segment boundary, and the paths that end with one
        /// of its suffixes with at least one segment in front (enclave.md section 7).
        pub fn places(&self, server_name: &str, target: &str) -> Vec<Place> {
            let path = target.split('?').next().unwrap_or_default();
            // Every address of the site of the vault secret: the record of a secret names a
            // host, and a use names its path.
            if server_name == SITE {
                return vec![at(Role::Site, SITE)];
            }
            // The objects of the log store: the keys of protocol.md 7.6 and 7.7, each after the
            // bucket that is the first part of the path.
            if server_name == LOG_HOST {
                let key = target
                    .strip_prefix('/')
                    .and_then(|path| path.split_once('/'))
                    .map(|(_, key)| key)
                    .unwrap_or_default();
                return match key.starts_with("a3/") || key.starts_with("n3/") {
                    true => vec![at(Role::LogStore, LOG_STORE)],
                    false => Vec::new(),
                };
            }
            let is = |address: &str| {
                let address = endpoint(address).unwrap();
                address.host == server_name && address.path == path
            };
            let under = |prefix: &String| {
                let rest = path.strip_prefix(prefix.as_str());
                let at_a_boundary = |rest: &str| rest.is_empty() || rest.starts_with('/');
                rest.is_some_and(|rest| prefix.ends_with('/') || at_a_boundary(rest))
            };
            let mut places = Vec::new();
            for name in self.definitions.names() {
                let definition = self.definitions.get(name).unwrap();
                let revocation = definition.revoke.as_ref();
                let mut rules = definition
                    .api
                    .iter()
                    .filter(|rule| rule.host == server_name);
                if is(&definition.token.url) {
                    places.push(at(Role::Token, name));
                }
                if revocation.is_some_and(|revoke| is(&revoke.url)) {
                    places.push(at(Role::Revocation, name));
                }
                let ends_with =
                    |suffix: &String| path.len() > suffix.len() && path.ends_with(suffix.as_str());
                if rules.any(|rule| {
                    rule.exact.iter().any(|exact| exact == path)
                        || rule.prefixes.iter().any(under)
                        || rule.suffixes.iter().any(ends_with)
                }) {
                    places.push(at(Role::Api, name));
                }
            }
            places
        }

        /// One address per `api` rule of a provider.
        pub fn api_addresses(&self, provider: &str) -> Vec<String> {
            let rules = &self.definitions.get(provider).unwrap().api;
            rules
                .iter()
                .map(|rule| {
                    let path = match (
                        rule.exact.first(),
                        rule.prefixes.first(),
                        rule.suffixes.first(),
                    ) {
                        (Some(exact), _, _) => exact.clone(),
                        (None, Some(prefix), _) if prefix.ends_with('/') => {
                            format!("{prefix}canary")
                        }
                        (None, Some(prefix), _) => prefix.clone(),
                        (None, None, Some(suffix)) => format!("/canary/canary{suffix}"),
                        (None, None, None) => unreachable!("a rule has a path"),
                    };
                    format!("https://{}{path}", rule.host)
                })
                .collect()
        }

        /// The first of the `api` addresses of a provider.
        pub fn api_address(&self, provider: &str) -> String {
            self.api_addresses(provider).remove(0)
        }

        /// True when the caller of `oauth/begin` names the client of the provider.
        pub fn has_dynamic_client(&self, provider: &str) -> bool {
            let definition = self.definitions.get(provider);
            definition.is_some_and(|definition| definition.client == ClientKind::Dynamic)
        }

        /// True when the definition of the provider has a revocation address.
        pub fn has_revocation(&self, provider: &str) -> bool {
            self.definitions.get(provider).unwrap().revoke.is_some()
        }

        /// Answers the next request of `role` with `answer`.
        pub fn next(&self, role: Role, answer: impl FnOnce(&Seen) -> Reply + Send + 'static) {
            self.scripted.lock().unwrap().push((role, Box::new(answer)));
        }

        /// Answers the next token request with 200 and the given token object.
        pub fn next_tokens(&self, tokens: &Value) {
            let tokens = tokens.clone();
            self.next(Role::Token, move |_| Reply::json(200, &tokens));
        }

        /// A token object of `provider` the way a provider that keeps its contract answers:
        /// every public field with a value of its type, a new access token and a new refresh
        /// token where the definition expects them, an `id_token` when the provider has public
        /// claims, and fields and a claim that the definition does not list.
        pub fn token_response(&self, provider: &str) -> Value {
            let serial = {
                let mut issued = self.issued.lock().unwrap();
                let count = issued.entry(provider.to_string()).or_insert(0);
                *count += 1;
                *count
            };
            let name = |what: &str| format!("{what} {serial} of {provider}");
            let container = &self.definitions.get(provider).unwrap().token_container;
            let beside_the_tokens = |key: &str| match container.is_empty() {
                true => key.to_string(),
                false => format!("{container}.{key}"),
            };
            let (token, revocation) = (at(Role::Token, provider), at(Role::Revocation, provider));
            let access_reach = [at(Role::Api, provider), revocation.clone()];
            let access_token = self.secrets.text(&name("access token"), &access_reach);
            let refresh_token = self
                .secrets
                .text(&name("refresh token"), &[token, revocation]);

            let (leaves, claims) = public_leaves(provider);
            let mut response = json!({"ok": true});
            for (path, leaf) in leaves {
                set(&mut response, path, leaf.sample(path));
            }
            set(
                &mut response,
                &beside_the_tokens("access_token"),
                json!(access_token),
            );
            set(
                &mut response,
                &beside_the_tokens("refresh_token"),
                json!(refresh_token),
            );
            let unlisted = self.secrets.text(&name("unlisted field"), &[]);
            set(&mut response, "unlisted", json!(unlisted));
            if !container.is_empty() {
                let unlisted = self
                    .secrets
                    .text(&name("unlisted field beside the tokens"), &[]);
                set(
                    &mut response,
                    &beside_the_tokens("unlisted"),
                    json!(unlisted),
                );
            }
            if !claims.is_empty() {
                let unlisted = self.secrets.word(&name("unlisted claim of the id_token"));
                let mut body = json!({"iss": "https://issuer.example", "at_hash": unlisted});
                for (claim, leaf) in claims {
                    set(&mut body, claim, leaf.sample(claim));
                }
                let signature = self.secrets.word(&name("signature of the id_token"));
                set(
                    &mut response,
                    "id_token",
                    json!(id_token(&body, &signature)),
                );
            }
            response
        }

        fn answer(&self, seen: &Seen) -> Reply {
            let places = self.places(&seen.server_name, &seen.target);
            let Some(place) = places.first() else {
                return Reply::json(404, &json!({"error": "no such address"}));
            };
            let scripted = {
                let mut scripted = self.scripted.lock().unwrap();
                let next = scripted.iter().position(|(role, _)| *role == place.role);
                next.map(|index| scripted.remove(index).1)
            };
            match (scripted, place.role) {
                (Some(answer), _) => answer(seen),
                (None, Role::Token) => Reply::json(200, &self.token_response(&place.provider)),
                (None, Role::Revocation) => Reply::json(200, &json!({})),
                (None, Role::Api) => Reply::json(200, &json!({"ok": true})),
                // The log store confirms every write.
                (None, Role::LogStore) => Reply::with_body(200, &[], b""),
                (None, Role::Site) => Reply::json(200, &json!({"ok": true})),
            }
        }
    }

    /// One call of a test and everything the node answered.
    struct Call {
        node: usize,
        method: String,
        path: String,
        /// False for a call to a path or with a method the router has no route for.
        route: bool,
        answer: Answer,
        /// The vault value this response may carry: the value a successful `release` call was
        /// asked for.
        released: Option<String>,
    }

    /// The fixture: a node whose private keys are planted, a second node for the delegation
    /// transfer, a node of the forward role with the site of one vault secret, a node of the
    /// reserve role, the app of one account and the provider stand-in.
    pub struct Canary {
        pub secrets: Arc<Secrets>,
        pub stand_in: Arc<StandIn>,
        pub app: App,
        provider: Provider,
        nodes: [Harness; 2],
        /// The stand-in for the site of the vault secret: the one host the node of the
        /// forward role reaches.
        site: Provider,
        /// The node of the forward role. Its platform reaches the site and no provider.
        forward: Harness,
        /// The node of the reserve role. Its platform reaches every host the two nodes of
        /// the delegation role reach: what keeps it from a provider is the node itself.
        reserve: Harness,
        calls: Mutex<Vec<Call>>,
        /// The S256 challenge of every authorization a test began, with its provider.
        challenges: Mutex<Vec<(String, String)>>,
        /// The number of authorization codes the tests handed to `oauth/complete`.
        codes: Mutex<usize>,
    }

    fn json_of(answer: Answer) -> (u16, Value) {
        (answer.status, serde_json::from_slice(&answer.body).unwrap())
    }

    impl Canary {
        /// Two nodes without an operator configuration and without a grant.
        ///
        /// A node draws its signing seed and then its sealing private key from the random
        /// source of its platform when it starts. The platform of a fixture answers these two
        /// draws with planted values. `the_private_keys_of_a_node_are_the_planted_markers`
        /// shows that the keys of the node are these values.
        pub async fn start() -> Canary {
            let secrets = Arc::new(Secrets::default());
            let stand_in = Arc::new(StandIn {
                secrets: secrets.clone(),
                definitions: Definitions::embedded(),
                issued: Mutex::default(),
                scripted: Mutex::default(),
            });
            let (answering, storing) = (stand_in.clone(), stand_in.clone());
            let provider = provider_and_log_store(
                move |seen| answering.answer(seen),
                move |seen| storing.answer(seen),
            )
            .await;
            let nodes = NODES.map(|node| {
                let (sign_seed, seal_private) = node_keys(&secrets, node);
                Harness::with_draws(&provider, &[&sign_seed, &seal_private])
            });
            let siting = stand_in.clone();
            let site = Provider::start(&[SITE], move |seen| siting.answer(seen)).await;
            let (sign_seed, seal_private) = node_keys(&secrets, FORWARD_NODE);
            let forward = Harness::with_draws(&site, &[&sign_seed, &seal_private]);
            let (sign_seed, seal_private) = node_keys(&secrets, RESERVE_NODE);
            let reserve = Harness::with_draws(&provider, &[&sign_seed, &seal_private]);
            let app = App::new("canary-user", 0xc5);
            let user_key = app.keys.user_key_of(app.custody);
            secrets.add("user key", user_key.as_slice(), &[]);
            Canary {
                secrets,
                stand_in,
                app,
                provider,
                nodes,
                site,
                forward,
                reserve,
                calls: Mutex::default(),
                challenges: Mutex::default(),
                codes: Mutex::default(),
            }
        }

        /// A fixture whose first node has the operator configuration and a grant.
        pub async fn ready() -> Canary {
            let canary = Canary::start().await;
            canary.configure().await;
            canary.grant().await;
            canary
        }

        /// A node by its number: one of the two nodes of the delegation role, the node of
        /// the forward role, or the node of the reserve role.
        fn node(&self, node: usize) -> &Harness {
            match node {
                FORWARD => &self.forward,
                RESERVE => &self.reserve,
                _ => self.nodes.get(node).unwrap_or(&self.reserve),
            }
        }

        /// The one way to a node: sends a request to its router and keeps the answer.
        async fn exchange(
            &self,
            node: usize,
            route: bool,
            method: &str,
            path: &str,
            body: Vec<u8>,
        ) -> Answer {
            let sent = Method::from_bytes(method.as_bytes()).unwrap();
            let answer = self.node(node).call(sent, path, body).await;
            self.calls.lock().unwrap().push(Call {
                node,
                method: method.to_string(),
                path: path.to_string(),
                route,
                answer: answer.clone(),
                released: None,
            });
            answer
        }

        /// A JSON call of a route of the first node.
        pub async fn post(&self, path: &str, body: Value) -> (u16, Value) {
            self.post_on(0, path, body).await
        }

        /// A JSON call of a route of one of the two nodes.
        pub async fn post_on(&self, node: usize, path: &str, body: Value) -> (u16, Value) {
            json_of(
                self.exchange(node, true, "POST", path, to_json(&body))
                    .await,
            )
        }

        /// A call of a route of the first node with a body that is not JSON.
        pub async fn post_bytes(&self, path: &str, body: &[u8]) -> (u16, Value) {
            json_of(self.exchange(0, true, "POST", path, body.to_vec()).await)
        }

        /// A call the router has no route for: an unknown path, or a method the path does not
        /// accept. The response is kept for the verdict on C1 like any other.
        pub async fn probe(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
            json_of(self.exchange(0, false, method, path, to_json(&body)).await)
        }

        /// `GET /v1/health` of one of the nodes.
        pub async fn health(&self, node: usize) -> Value {
            let health = self.exchange(node, true, "GET", "/v1/health", Vec::new());
            let (status, health) = json_of(health.await);
            assert_eq!(status, 200, "{health}");
            health
        }

        /// A `forward` call of the first node. `Err` carries the status and the failure body.
        pub async fn forward(
            &self,
            record: &Value,
            method: &str,
            address: &str,
            headers: Value,
            payload: &[u8],
        ) -> Result<Forwarded, (u16, Value)> {
            let mut request = frame::encode_head(&json!({
                "user_id": self.app.user_id, "record": record, "method": method, "url": address,
                "headers": headers, "context": "canary", "timeout_ms": 5000,
            }));
            request.extend_from_slice(payload);
            let answer = self.exchange(0, true, "POST", "/v1/forward", request).await;
            if answer.status != 200 {
                return Err(json_of(answer));
            }
            let (meta, body) = frame::decode(&Bytes::from(answer.body)).unwrap();
            let text = |value: &Value| value.as_str().unwrap().to_string();
            let headers = meta["headers"].as_array().unwrap().iter();
            Ok(Forwarded {
                status: meta["status"].as_u64().unwrap() as u16,
                headers: headers
                    .map(|pair| (text(&pair[0]), text(&pair[1])))
                    .collect(),
                log: meta["log"].clone(),
                body: body.to_vec(),
            })
        }

        /// A `forward` call with the method GET, without headers of the caller.
        pub async fn get(&self, record: &Value, address: &str) -> Result<Forwarded, (u16, Value)> {
            self.forward(record, "GET", address, json!([]), b"").await
        }

        /// A `forward` call of the first node with the method GET that asks for its response
        /// as a stream. `Err` carries the status and the failure body of a call that handed
        /// no response of the provider on.
        pub async fn get_stream(
            &self,
            record: &Value,
            address: &str,
        ) -> Result<Streamed, (u16, Value)> {
            let request = frame::encode_head(&json!({
                "user_id": self.app.user_id, "record": record, "method": "GET", "url": address,
                "headers": [], "context": "canary", "timeout_ms": 5000, "stream": true,
            }));
            let answer = self.exchange(0, true, "POST", "/v1/forward", request).await;
            match answer.status {
                200 => Ok(read_stream(&answer.body)),
                _ => Err(json_of(answer)),
            }
        }

        /// A `forward/batch` call of the first node: one GET request without a body per
        /// address. `Err` carries the status and the failure body.
        pub async fn forward_batch(
            &self,
            record: &Value,
            addresses: &[String],
        ) -> Result<Vec<BatchOutcome>, (u16, Value)> {
            let requests: Vec<Value> = addresses
                .iter()
                .map(|address| {
                    json!({"method": "GET", "url": address, "headers": [], "body_bytes": 0})
                })
                .collect();
            let request = frame::encode_head(&json!({
                "user_id": self.app.user_id, "record": record, "context": "canary",
                "timeout_ms": 5000, "requests": requests,
            }));
            let answer = self
                .exchange(0, true, "POST", "/v1/forward/batch", request)
                .await;
            if answer.status != 200 {
                return Err(json_of(answer));
            }
            let (meta, body) = frame::decode(&Bytes::from(answer.body)).unwrap();
            Ok(decode_batch(&meta, &body))
        }

        /// Gives the node of the reserve role its role, with the log store of the tests and
        /// credentials for it: the node writes its node document and takes delegations.
        pub async fn take_the_reserve_role(&self) {
            let log_store = json!({"bucket": LOG_BUCKET, "region": LOG_REGION});
            let config = json!({"role": "reserve", "log_store": log_store});
            let (status, response) = self.post_on(RESERVE, "/v1/config", config).await;
            assert_eq!(status, 200, "{response}");
            let body = self.log_store_credentials("ASIACANARY");
            let (status, response) = self
                .post_on(RESERVE, "/v1/log-store/credentials", body)
                .await;
            assert_eq!(status, 200, "{response}");
            assert!(response["node_document_ms"].as_u64().unwrap() > 0);
        }

        /// The hosts the node of the reserve role asked its platform for a connection to.
        pub fn reserve_connections(&self) -> Vec<(String, u16)> {
            self.reserve.platform.connections()
        }

        /// Gives the node of the forward role its role: the operator configuration that
        /// names it.
        pub async fn take_the_forward_role(&self) {
            let outcome = self
                .post_on(FORWARD, "/v1/config", json!({"role": "forward"}))
                .await;
            // A node of the forward role has no log store, and no node document in one.
            assert_eq!(
                outcome,
                (200, json!({"configured": true, "node_document_ms": 0}))
            );
        }

        /// The envelope of one use of a vault secret of the account, sealed to the node of
        /// the forward role: `value` for a `GET` request to `path` of the site with the query
        /// `query`, the value inside the header `Authorization`. The keys that sign it stand
        /// for a node of the delegation role, which seals a use after its log entry.
        pub fn secret_use(&self, path: &str, query: &str, value: &str, nonce: u8) -> Value {
            self.secret_use_at("header:authorization", path, query, value, nonce)
        }

        /// [`Canary::secret_use`] for the slot `slot`: the header `Authorization`, or one
        /// half of the credentials of HTTP Basic inside it (`basic:user`, `basic:password`).
        pub fn secret_use_at(
            &self,
            slot: &str,
            path: &str,
            query: &str,
            value: &str,
            nonce: u8,
        ) -> Value {
            let request = json!({
                "method": "GET", "host": SITE, "path": path, "query": query,
                "slot": slot, "placeholder": PLACEHOLDER,
                "body_bytes": 0, "body_sha256": "",
            });
            let giving = NodeKeys::from_random(&[0x67; 32], &[0x68; 32]);
            let keys = &self.forward.node.keys;
            let envelope = seal_secret_use(
                &giving,
                &keys.sign_public(),
                &keys.seal_public(),
                self.forward.node.now_ms(),
                &[nonce; 16],
                &self.app.user_id,
                &b64u(&[0x31; 16]),
                &Sealed::new(value.to_string()),
                &BoundRequest::from_value(&request).unwrap(),
                &Sealed::new([nonce; 32]),
            )
            .unwrap();
            serde_json::to_value(envelope).unwrap()
        }

        /// A `vault/handoff` call of the first node: the value of `record` for a `GET`
        /// request to `path` of the site with the query `query`, the value inside the header
        /// `Authorization`, handed to the node of the forward role under its attestation.
        pub async fn handoff(&self, record: &Value, path: &str, query: &str) -> (u16, Value) {
            self.handoff_at(record, "header:authorization", path, query)
                .await
        }

        /// [`Canary::handoff`] for the slot `slot`.
        pub async fn handoff_at(
            &self,
            record: &Value,
            slot: &str,
            path: &str,
            query: &str,
        ) -> (u16, Value) {
            let request = json!({
                "method": "GET", "host": SITE, "path": path, "query": query,
                "slot": slot, "placeholder": PLACEHOLDER,
                "body_bytes": 0, "body_sha256": "",
            });
            let peer = self.attestation(FORWARD).await;
            let body = json!({
                "user_id": self.app.user_id, "record": record, "peer": peer,
                "request": request, "context": "canary",
            });
            self.post("/v1/vault/handoff", body).await
        }

        /// A `vault/send` call of one of the nodes with an envelope of
        /// [`Canary::secret_use`] or of [`Canary::handoff`]. `Err` carries the status and the
        /// failure body of a call that handed no response of the site on.
        pub async fn vault_send(
            &self,
            node: usize,
            envelope: &Value,
        ) -> Result<Streamed, (u16, Value)> {
            self.vault_send_with(node, envelope, &format!("Bearer {PLACEHOLDER}"))
                .await
        }

        /// [`Canary::vault_send`] with `authorization` as the `Authorization` header of the
        /// caller: the placeholder behind a scheme, or credentials of HTTP Basic that hold
        /// it ([`Canary::basic`]).
        pub async fn vault_send_with(
            &self,
            node: usize,
            envelope: &Value,
            authorization: &str,
        ) -> Result<Streamed, (u16, Value)> {
            let request = frame::encode_head(&json!({
                "envelope": envelope, "timeout_ms": 5000,
                "headers": [["Authorization", authorization]],
            }));
            let answer = self
                .exchange(node, true, "POST", "/v1/vault/send", request)
                .await;
            match answer.status {
                200 => Ok(read_stream(&answer.body)),
                _ => Err(json_of(answer)),
            }
        }

        /// The value of an `Authorization` header with `user_id` as the user-id of
        /// credentials of HTTP Basic and an empty password: `Basic`, a space, and the base64
        /// text of `user_id:`.
        pub fn basic(user_id: &str) -> String {
            format!("Basic {}", STANDARD.encode(format!("{user_id}:")))
        }

        /// That header as a caller of `vault/send` writes it: with the placeholder for the
        /// user-id.
        pub fn basic_with_the_placeholder() -> String {
            Canary::basic(PLACEHOLDER)
        }

        /// The attestation response of one of the nodes.
        pub async fn attestation(&self, node: usize) -> Value {
            let nonce = json!({"nonce": b64u(&[0x5a; 32])});
            let (status, response) = self.post_on(node, "/v1/attestation", nonce).await;
            assert_eq!(status, 200, "{response}");
            response
        }

        /// The keys and the challenge an app reads from an attestation response of the local
        /// platform (protocol.md 4.4): the binding inside the document names the node keys.
        pub fn attested(response: &Value) -> Attested {
            let text = |value: &Value| b64u_decode(value.as_str().unwrap()).unwrap();
            let document: Value = serde_json::from_slice(&text(&response["document"])).unwrap();
            let binding: Binding = serde_json::from_slice(&text(&document["binding"])).unwrap();
            Attested {
                seal_public: b64u_decode(&binding.seal).unwrap().try_into().unwrap(),
                node: binding.sign,
                challenge: response["challenge"].as_str().unwrap().to_string(),
            }
        }

        /// The operator configuration of the tests: every provider of the definitions, each
        /// with a client secret of its own.
        pub fn operator_config(&self) -> Value {
            let mut providers = json!({});
            for name in self.stand_in.providers() {
                let reach = [at(Role::Token, &name), at(Role::Revocation, &name)];
                let secret = self
                    .secrets
                    .text(&format!("client secret of {name}"), &reach);
                providers[&name] = json!({
                    "client_id": format!("{name}-client"),
                    "client_secret": secret,
                    "redirect_uri": format!("https://api.example/integrations/{name}/callback"),
                    "publishable_key": format!("pk_test_{name}"),
                });
            }
            json!({"providers": providers})
        }

        /// Gives the first node the operator configuration, and names the log store of the
        /// tests, with credentials for it, in the configuration of both nodes. From then on a
        /// node acts only after the stand-in confirmed the entry of the act, and the chain of
        /// the account is read from the objects the stand-in received.
        pub async fn configure(&self) {
            let mut first = self.operator_config();
            first["log_store"] = json!({"bucket": LOG_BUCKET, "region": LOG_REGION});
            let (status, response) = self.post("/v1/config", first).await;
            assert_eq!(status, 200, "{response}");
            self.configure_log_store_of(1).await;
            self.give_log_store_credentials().await;
        }

        /// Names the log store of the tests, with credentials for it, in the configuration of
        /// both nodes, without a provider.
        pub async fn configure_log_store(&self) {
            for node in 0..NODES.len() {
                self.configure_log_store_of(node).await;
            }
            self.give_log_store_credentials().await;
        }

        async fn configure_log_store_of(&self, node: usize) {
            let log_store = json!({"bucket": LOG_BUCKET, "region": LOG_REGION});
            let config = json!({"providers": {}, "log_store": log_store});
            let (status, response) = self.post_on(node, "/v1/config", config).await;
            assert_eq!(status, 200, "{response}");
        }

        /// The credentials of the operator for the log store. The session token reaches the
        /// log store and nothing else, and the secret access key reaches nothing.
        pub fn log_store_credentials(&self, access_key_id: &str) -> Value {
            let store = [at(Role::LogStore, LOG_STORE)];
            json!({
                "access_key_id": access_key_id,
                "secret_access_key": self
                    .secrets
                    .text("secret access key for the log store", &[]),
                "session_token": self
                    .secrets
                    .text("session token for the log store", &store),
                "expires_ms": 4_102_444_800_000u64,
            })
        }

        async fn give_log_store_credentials(&self) {
            for node in 0..NODES.len() {
                let body = self.log_store_credentials("ASIACANARY");
                let (status, response) =
                    self.post_on(node, "/v1/log-store/credentials", body).await;
                assert_eq!(status, 200, "{response}");
            }
        }

        /// The envelope of a grant of the account for the first node, for 30 days.
        pub async fn grant_envelope(&self) -> Value {
            let attested = Canary::attested(&self.attestation(0).await);
            let time_ms = self.health(0).await["time_ms"].as_u64().unwrap();
            self.app
                .grant_envelope(&attested, time_ms + limits::GRANT_MAX_MS)
        }

        /// The envelope of a revoke of the account for the first node.
        pub async fn revoke_envelope(&self) -> Value {
            let attested = Canary::attested(&self.attestation(0).await);
            self.app.revoke_envelope(&attested)
        }

        /// Sends a command envelope of the account to the first node.
        pub async fn send(&self, envelope: &Value) -> (u16, Value) {
            let body = json!({"user_id": self.app.user_id, "envelope": envelope});
            self.post("/v1/messages", body).await
        }

        /// The verified reply inside a response of `messages`.
        pub fn reply(&self, response: &Value) -> Value {
            self.nodes[0].verified(purpose::REPLY, &response["reply"])
        }

        /// Grants and asserts that the first node accepted.
        pub async fn grant(&self) {
            let envelope = self.grant_envelope().await;
            let (status, response) = self.send(&envelope).await;
            assert_eq!(status, 200, "{response}");
            assert_eq!(self.reply(&response)["ok"], true, "{response}");
        }

        /// Creates a record the way the app of the account does, and plants its record key.
        pub fn record(&self, kind: &str, provider: &str, plaintext: &Value) -> Value {
            let record = self.app.record(kind, provider, plaintext);
            self.plant_record_key(&record);
            record
        }

        /// The record key is derived from the user key and is a secret like it.
        fn plant_record_key(&self, record: &Value) {
            let record = Record::from_value(record).unwrap();
            let user_key = self.app.keys.user_key_of(self.app.custody);
            let key = record_key(user_key, &record.id_bytes().unwrap());
            let name = format!("record key of {}", record.id);
            self.secrets.add(&name, key.as_slice(), &[]);
        }

        /// `oauth/begin` for a provider, without parameters of the caller.
        pub async fn begin(&self, provider: &str) -> (u16, Value) {
            let client_id = match self.stand_in.has_dynamic_client(provider) {
                true => "canary-client",
                false => "",
            };
            let body = json!({
                "user_id": self.app.user_id, "provider": provider, "operator_state": "canary",
                "params": {}, "client_id": client_id,
            });
            let outcome = self.post("/v1/oauth/begin", body).await;
            let address = outcome.1["authorization_url"].as_str();
            let address = address.map(|address| url::Url::parse(address).unwrap());
            let challenge = address.and_then(|address| {
                let mut query = address.query_pairs();
                let challenge = query.find(|(key, _)| key == "code_challenge");
                challenge.map(|(_, challenge)| challenge.into_owned())
            });
            if let Some(challenge) = challenge {
                let mut challenges = self.challenges.lock().unwrap();
                challenges.push((challenge, provider.to_string()));
            }
            outcome
        }

        /// `oauth/complete` with a new authorization code, which is a secret that only the
        /// token address of the provider may receive.
        pub async fn complete(&self, provider: &str, state: &str) -> (u16, Value) {
            let serial = {
                let mut codes = self.codes.lock().unwrap();
                *codes += 1;
                *codes
            };
            let name = format!("authorization code {serial} of {provider}");
            let code = self.secrets.text(&name, &[at(Role::Token, provider)]);
            let body = json!({"user_id": self.app.user_id, "state": state, "code": code});
            let outcome = self.post("/v1/oauth/complete", body).await;
            if outcome.0 == 200 {
                self.plant_record_key(&outcome.1["record"]);
            }
            outcome
        }

        /// An authorization from `oauth/begin` to `oauth/complete`, where `answer` is what the
        /// token address answers to the exchange.
        pub async fn connect_with(
            &self,
            provider: &str,
            answer: impl FnOnce(&Seen) -> Reply + Send + 'static,
        ) -> (u16, Value) {
            let (status, begun) = self.begin(provider).await;
            assert_eq!(status, 200, "{provider}: {begun}");
            self.stand_in.next(Role::Token, answer);
            let state = begun["state"].as_str().unwrap();
            self.complete(provider, state).await
        }

        /// An authorization whose exchange the token address answers with the given token
        /// object.
        pub async fn connect_to(&self, provider: &str, tokens: &Value) -> (u16, Value) {
            let tokens = tokens.clone();
            let answer = move |_: &Seen| Reply::json(200, &tokens);
            self.connect_with(provider, answer).await
        }

        /// An authorization with a provider that keeps its contract. Returns the token object
        /// the token address answered with and the response of `oauth/complete`.
        pub async fn connect(&self, provider: &str) -> (Value, Value) {
            let tokens = self.stand_in.token_response(provider);
            let (status, connected) = self.connect_to(provider, &tokens).await;
            assert_eq!(status, 200, "{provider}: {connected}");
            (tokens, connected)
        }

        /// The body of the calls that take a record and a context.
        fn with_record(&self, record: &Value) -> Value {
            json!({"user_id": self.app.user_id, "record": record, "context": "canary"})
        }

        /// A `refresh` call of the first node.
        pub async fn refresh(&self, record: &Value) -> (u16, Value) {
            self.post("/v1/refresh", self.with_record(record)).await
        }

        /// A `revoke-token` call of the first node.
        pub async fn revoke_token(&self, record: &Value) -> (u16, Value) {
            self.post("/v1/revoke-token", self.with_record(record))
                .await
        }

        /// An `oauth/merge` call of the first node.
        pub async fn merge(&self, record: &Value, previous: &Value) -> (u16, Value) {
            let user_id = &self.app.user_id;
            let body = json!({"user_id": user_id, "record": record, "previous": previous});
            self.post("/v1/oauth/merge", body).await
        }

        /// A `release` call of one of the two nodes. `carries` is the planted value a
        /// successful call answers with: the verdict on C1 lets this one value pass in this
        /// one response. A release of a TOTP code names none: the code is no marker, and the
        /// seed has no exception.
        pub async fn release(
            &self,
            node: usize,
            record: &Value,
            field: &str,
            carries: Option<&str>,
        ) -> (u16, Value) {
            let body = json!({
                "user_id": self.app.user_id, "record": record, "field": field,
                "origin": "https://shop.example", "context": "canary",
            });
            let outcome = self.post_on(node, "/v1/release", body).await;
            if outcome.0 == 200 {
                let mut calls = self.calls.lock().unwrap();
                calls.last_mut().unwrap().released = carries.map(str::to_string);
            }
            outcome
        }

        /// A `vault/store` call of the first node for a value under `name`. The record key
        /// of a record the call returns is planted: it is derived from the user key like the
        /// key of a record the app made.
        pub async fn store(
            &self,
            name: &str,
            sites: Value,
            slots: Value,
            value: &str,
        ) -> (u16, Value) {
            let body = json!({
                "user_id": self.app.user_id, "name": name, "sites": sites, "slots": slots,
                "value": value, "context": "canary",
            });
            let outcome = self.post("/v1/vault/store", body).await;
            if outcome.0 == 200 {
                self.plant_record_key(&outcome.1["record"]);
            }
            outcome
        }

        /// The event a `log` object names on one of the two nodes, read from the object the
        /// log store stand-in received: the node signature verifies and the log key of the
        /// account opens it. Its kind is a kind that this release writes.
        pub fn logged(&self, node: usize, log: &Value) -> Value {
            let event = self.app.logged(&self.nodes[node], &self.provider, log);
            let kind = event["t"].as_str().unwrap_or_default();
            assert!(EVENTS.contains(&kind), "an event of the kind {kind:?}");
            event
        }

        /// The kinds of the events of the chain of the account on the first node, in the
        /// order of the chain, read from the objects the log store stand-in received, and the
        /// `seq` of the end of the chain.
        pub fn logged_kinds(&self) -> (Vec<String>, u64) {
            let node = &self.nodes[0];
            let kinds = self
                .provider
                .chain(&self.app.user_id, &node.node.node)
                .iter()
                .flat_map(|stored| self.app.events(node, &stored.entry))
                .map(|event| {
                    let kind = event["t"].as_str().unwrap_or_default().to_string();
                    assert!(
                        EVENTS.contains(&kind.as_str()),
                        "an event of the kind {kind:?}"
                    );
                    kind
                })
                .collect();
            (kinds, node.last_seq(&self.app.user_id))
        }

        /// The requests the stand-ins received so far: those of the providers, the writes to
        /// the log store, and those of the site of the vault secret.
        pub fn seen(&self) -> Vec<Seen> {
            [self.provider.seen(), self.site.seen()].concat()
        }

        /// The requests the site of the vault secret received so far.
        pub fn site_requests(&self) -> Vec<Seen> {
            self.site.seen()
        }

        /// The requests of the providers the stand-in received so far.
        pub fn requests(&self) -> Vec<Seen> {
            self.provider.requests()
        }

        /// The routes the tests called and that answered with a status `with` accepts.
        pub fn routes_called(&self, with: impl Fn(u16) -> bool) -> BTreeSet<(String, String)> {
            let calls = self.calls.lock().unwrap();
            let chosen = calls
                .iter()
                .filter(|call| call.route && with(call.answer.status));
            chosen
                .map(|call| (call.method.clone(), call.path.clone()))
                .collect()
        }

        /// Every secret of the test. The PKCE verifiers are read from the requests the token
        /// addresses received: a verifier is created inside a node and leaves it no other way.
        /// Its provider is the provider of the authorization whose address carried its S256
        /// challenge.
        fn every_secret(&self) -> Vec<Secret> {
            for request in self.seen() {
                let Some(verifier) = field(&request, "code_verifier") else {
                    continue;
                };
                let challenge = b64u(&Sha256::digest(verifier.as_bytes()));
                let challenges = self.challenges.lock().unwrap();
                let begun = challenges.iter().find(|(known, _)| *known == challenge);
                let (_, provider) = begun.expect("a verifier of an authorization the test began");
                let name = format!("PKCE verifier of {provider} for the challenge {challenge}");
                let reach = [at(Role::Token, provider)];
                self.secrets.add(&name, verifier.as_bytes(), &reach);
            }
            self.secrets.all()
        }

        fn scanner(secrets: &[Secret]) -> Scanner {
            let marker = |secret: &Secret| (secret.name.clone(), secret.bytes.clone());
            Scanner::new(&secrets.iter().map(marker).collect::<Vec<_>>())
        }

        /// True when the body of a failure is a code and a message and, for a refusal of a
        /// provider, its status and a word of the closed vocabulary. Nothing a provider wrote
        /// is in such a body.
        fn is_a_failure_body(body: &[u8]) -> bool {
            let Ok(Value::Object(body)) = serde_json::from_slice(body) else {
                return false;
            };
            let keys: Vec<&str> = body.keys().map(String::as_str).collect();
            let of_a_provider = ["code", "message", "provider_status", "provider_error"];
            let word = body.get("provider_error").and_then(Value::as_str);
            let in_the_vocabulary =
                |word| ["", "other"].contains(&word) || PROVIDER_ERRORS.contains(&word);
            keys == of_a_provider[..2]
                || (keys == of_a_provider && word.is_some_and(in_the_vocabulary))
        }

        /// The verdict on C1: no response of either node carries a marker in its status, in a
        /// header or in its body. The response of a successful `release` call carries the
        /// value it was asked for as its `value` and nowhere else. A failure carries a body of
        /// the one form of failures.
        pub fn verdict_c1(&self) {
            let scanner = Canary::scanner(&self.every_secret());
            let mut leaks = Vec::new();
            for call in self.calls.lock().unwrap().iter() {
                let answer = &call.answer;
                let call_of_node = format!(
                    "{} {} of the {}",
                    call.method,
                    call.path,
                    name_of(call.node)
                );
                if answer.status != 200 && !Canary::is_a_failure_body(&answer.body) {
                    let status = answer.status;
                    leaks.push(format!(
                        "{call_of_node} answered {status} with a body that is no failure body"
                    ));
                }
                let status = answer.status.to_string().into_bytes();
                let mut parts = vec![("status".to_string(), status)];
                for (name, value) in &answer.headers {
                    let header = [name.as_bytes(), b": ", value].concat();
                    parts.push((format!("header {name}"), header));
                }
                let body = match &call.released {
                    None => answer.body.clone(),
                    Some(value) => {
                        let mut body: Value = serde_json::from_slice(&answer.body).unwrap();
                        assert_eq!(body["value"], value.as_str(), "the value of a release");
                        body["value"] = Value::Null;
                        to_json(&body)
                    }
                };
                parts.push(("body".to_string(), body));
                for (part, bytes) in parts {
                    for (marker, form) in scanner.find(&bytes) {
                        let status = answer.status;
                        leaks.push(format!(
                            "{call_of_node} answered {status} with the {marker} ({form}) in its {part}"
                        ));
                    }
                }
            }
            assert!(leaks.is_empty(), "markers on C1:\n{}", leaks.join("\n"));
        }

        /// The verdict on C2: every connection a node of the delegation role asked its
        /// platform for went to port 443 of a host of the definitions or of the log store,
        /// every connection the node of the reserve role asked for went to port 443 of the
        /// host of the log store, every connection the node of the forward role asked for
        /// went to port 443 of the site of the vault secret, and each carried one request
        /// that a stand-in received.
        /// Every request went to an address that a definition names, to an object of the log
        /// store or to the site, under the TLS server name of its `Host` header, and a secret
        /// occurs only in requests to the places within its reach. Returns the secrets that
        /// were seen, each with the place of the request that carried it.
        pub fn verdict_c2(&self) -> Vec<(String, Place)> {
            let secrets = self.every_secret();
            let scanner = Canary::scanner(&secrets);
            let mut carried = Vec::new();
            let mut leaks = Vec::new();
            let hosts = provider_hosts();
            let connections = self
                .nodes
                .iter()
                .flat_map(|node| node.platform.connections());
            let mut connections: Vec<(String, u16)> = connections.collect();
            for (host, port) in &connections {
                // Whoever carries the bytes of a node sees the destination of a connection.
                if *port != 443 || !(hosts.contains(host) || host == LOG_HOST) {
                    leaks.push(format!("{host}:{port} is the host of no definition"));
                }
            }
            // A node of the reserve role uses no credential: the one host it reaches is
            // its log store.
            for (host, port) in self.reserve.platform.connections() {
                if port != 443 || host != LOG_HOST {
                    leaks.push(format!(
                        "{host}:{port} is not the log store, and the {RESERVE_NODE} asked for it"
                    ));
                }
                connections.push((host, port));
            }
            // A node of the forward role holds no credential of a provider and writes no
            // entry: the one host it reaches is the site of the use it was handed.
            for (host, port) in self.forward.platform.connections() {
                if port != 443 || host != SITE {
                    leaks.push(format!(
                        "{host}:{port} is not the site of the vault secret, and the {FORWARD_NODE} asked for it"
                    ));
                }
                connections.push((host, port));
            }
            for (host, _) in &connections {
                for (marker, form) in scanner.find(host.as_bytes()) {
                    leaks.push(format!(
                        "the host name {host} carried the {marker} ({form})"
                    ));
                }
            }
            // A node reuses its connections to the log store and to a provider host: the
            // stand-in receives at least one request over every connection.
            if connections.len() > self.seen().len() {
                leaks.push("a connection without a request that the stand-in received".into());
            }
            for request in self.seen() {
                let (host, target) = (&request.server_name, &request.target);
                let address = format!("{} https://{host}{target}", request.method);
                let places = self.stand_in.places(host, target);
                if places.is_empty() {
                    leaks.push(format!("{address} is an address of no definition"));
                }
                if request.header("host") != Some(host.as_str()) {
                    leaks.push(format!("{address} names another host in its Host header"));
                }
                let mut wire = format!("{} {target}\n", request.method).into_bytes();
                for (name, value) in &request.headers {
                    wire.extend_from_slice(format!("{name}: {value}\n").as_bytes());
                }
                wire.extend_from_slice(&request.body);
                for (marker, form) in scanner.find(&wire) {
                    let secret = secrets.iter().find(|secret| secret.name == marker).unwrap();
                    match places.iter().find(|place| secret.reach.contains(place)) {
                        Some(place) => carried.push((marker, place.clone())),
                        None => leaks.push(format!("{address} carried the {marker} ({form})")),
                    }
                }
            }
            assert!(leaks.is_empty(), "requests on C2:\n{}", leaks.join("\n"));
            // An answer a test scripted and no request asked for stands for a provider call
            // the test expected and the node did not make.
            let unasked = self.stand_in.scripted.lock().unwrap().len();
            assert_eq!(unasked, 0, "scripted answers that no request asked for");
            carried
        }

        /// Both verdicts.
        pub fn verdict(&self) {
            self.verdict_c1();
            self.verdict_c2();
        }
    }
}

/// The vault values of a test and the records the app made of them.
struct Vault {
    password: String,
    password_record: Value,
    totp_seed: String,
    totp_record: Value,
    card_number: String,
    card_cvc: String,
    card_record: Value,
    /// A named value for a field of a page of the origin the walk asks for.
    named_value: String,
    named_record: Value,
    /// A named value for a request: its record has no slot `field`, so no call hands it out.
    request_record: Value,
}

impl Vault {
    fn plant(canary: &Canary) -> Vault {
        let password = canary.secrets.text("vault password", &[]);
        let totp_seed = canary.secrets.totp_seed("TOTP seed");
        let card_number = canary.secrets.digits("card number", 19);
        let card_cvc = canary.secrets.text("card verification code", &[]);
        let card = json!({"number": card_number, "cvc": card_cvc});
        let named_value = canary.secrets.text("named value", &[]);
        let request_value = canary
            .secrets
            .text("named value without the slot field", &[]);
        let named = json!({
            "value": named_value, "name": "PAYMENT_PIN", "sites": ["shop.example"],
            "slots": ["field"], "source": "device",
        });
        let request = json!({
            "value": request_value, "name": "OPENAI_API_KEY", "sites": ["shop.example"],
            "slots": ["header:authorization"], "source": "device",
        });
        Vault {
            password_record: canary.record("vault_password", "vault", &json!({"value": password})),
            totp_record: canary.record("vault_totp", "vault", &json!({"value": totp_seed})),
            card_record: canary.record("vault_card", "vault", &card),
            named_record: canary.record("vault_secret", "vault", &named),
            request_record: canary.record("vault_secret", "vault", &request),
            password,
            totp_seed,
            card_number,
            card_cvc,
            named_value,
        }
    }
}

/// Releases every vault value once on one of the two nodes, then asks for pairs of kind and
/// field that no record releases.
async fn release_the_vault(canary: &Canary, node: usize, vault: &Vault) {
    for (record, field, value) in [
        (&vault.password_record, "password", &vault.password),
        (&vault.card_record, "card_number", &vault.card_number),
        (&vault.card_record, "card_cvc", &vault.card_cvc),
        (&vault.named_record, "value", &vault.named_value),
    ] {
        let carries = Some(value.as_str());
        let (status, released) = canary.release(node, record, field, carries).await;
        assert_eq!(
            (status, released["value"].as_str()),
            (200, carries),
            "{field}"
        );
    }

    // Of a TOTP record the code of the seed at node time leaves, and the seed does not.
    let before = canary.health(node).await["time_ms"].as_u64().unwrap();
    let (status, released) = canary.release(node, &vault.totp_record, "totp", None).await;
    let after = canary.health(node).await["time_ms"].as_u64().unwrap();
    assert_eq!(status, 200, "{released}");
    let codes = [before, after].map(|time_ms| totp(&vault.totp_seed, time_ms).unwrap());
    assert!(codes.iter().any(|code| released["value"] == code.as_str()));

    for (record, field) in [
        (&vault.totp_record, "password"),
        (&vault.totp_record, "card_number"),
        (&vault.totp_record, "card_cvc"),
        (&vault.totp_record, "value"),
        (&vault.password_record, "totp"),
        (&vault.password_record, "card_cvc"),
        (&vault.card_record, "password"),
        (&vault.card_record, "totp"),
        (&vault.named_record, "password"),
        // A named value whose record has no slot `field` is handed out by no call, also not
        // for a host of its sites.
        (&vault.request_record, "value"),
        (&vault.request_record, "header:authorization"),
    ] {
        let outcome = canary.release(node, record, field, None).await;
        assert_eq!(code(&outcome), (403, "not_allowed"), "{field}");
    }
}

/// Begins an authorization and returns its state.
async fn pending_state(canary: &Canary, provider: &str) -> String {
    let (status, begun) = canary.begin(provider).await;
    assert_eq!(status, 200, "{begun}");
    begun["state"].as_str().unwrap().to_string()
}

/// Calls every route of a node whose providers keep their contracts, each in a success case
/// and in a failure case, and returns the fixture with everything the nodes answered and
/// sent.
async fn walk() -> Canary {
    let canary = Canary::start().await;
    let user = canary.app.user_id.clone();
    let stand_in = &canary.stand_in;

    // The calls that need neither the operator configuration nor a grant.
    canary.health(0).await;
    let wrong_method = canary.probe("POST", "/v1/health", json!({})).await;
    assert_eq!(code(&wrong_method), (405, "invalid_request"));
    let short_nonce = json!({"nonce": b64u(b"short")});
    let outcome = canary.post("/v1/attestation", short_nonce).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    let no_account = json!({"nonce": b64u(b"canary")});
    let outcome = canary.post("/v1/status", no_account).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));

    // Without the configuration no authorization begins, and without a grant no record opens.
    let vault = Vault::plant(&canary);
    let outcome = canary.begin("google_workspace").await;
    assert_eq!(code(&outcome), (503, "not_configured"));
    let outcome = canary
        .release(0, &vault.password_record, "password", None)
        .await;
    assert_eq!(code(&outcome), (409, "grant_required"));

    // The operator configuration: a provider without a definition is refused, and the secret
    // that came with it stays where it was sent.
    let mut unknown = canary.operator_config();
    let stray = canary
        .secrets
        .text("client secret of a provider without a definition", &[]);
    unknown["providers"]["dropbox"] = json!({
        "client_id": "dropbox-client", "client_secret": stray,
        "redirect_uri": "https://api.example/integrations/dropbox/callback",
    });
    let outcome = canary.post("/v1/config", unknown).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    canary.configure().await;

    // The credentials for the log store of both nodes: values of another form are refused.
    // The session token reaches the log store and nothing else, the secret access key
    // reaches nothing, and neither comes back, in this response or in a later one.
    let outcome = canary
        .post(
            "/v1/log-store/credentials",
            canary.log_store_credentials("no access key"),
        )
        .await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    for node in 0..NODES.len() {
        let body = canary.log_store_credentials("ASIACANARY");
        let (status, stored) = canary
            .post_on(node, "/v1/log-store/credentials", body)
            .await;
        // The call wrote the node document of that node, with the credentials it gave.
        assert_eq!(
            (status, &stored["credentials_expires_ms"]),
            (200, &json!(4_102_444_800_000u64))
        );
        assert!(stored["node_document_ms"].as_u64().unwrap() > 0, "{stored}");
        assert_eq!(stored.as_object().unwrap().len(), 2);
    }

    // The commands of the app. An envelope that is sent again is answered with 200 and a
    // signed refusal: its challenge was used.
    let outcome = canary.post("/v1/messages", json!({"user_id": user})).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    let envelope = canary.grant_envelope().await;
    let (status, granted) = canary.send(&envelope).await;
    assert_eq!((status, &canary.reply(&granted)["ok"]), (200, &json!(true)));
    let (status, again) = canary.send(&envelope).await;
    let refusal = &canary.reply(&again)["code"];
    assert_eq!((status, refusal), (200, &json!("bad_challenge")));
    let nonce = json!({"user_id": user, "nonce": b64u(b"canary")});
    let (status, state) = canary.post("/v1/status", nonce).await;
    assert_eq!((status, &state["grant"]["state"]), (200, &json!("active")));

    // Every provider of the definitions: an authorization, a request to each host of its
    // `api` rules, a refresh, a request with the refreshed record, and a revocation.
    let mut records = std::collections::BTreeMap::new();
    for provider in stand_in.providers() {
        let (tokens, connected) = canary.connect(&provider).await;
        assert_public(&provider, &tokens, &connected["public"], true);
        for address in stand_in.api_addresses(&provider) {
            let forwarded = canary.get(&connected["record"], &address).await;
            assert_eq!(
                forwarded.map(|forwarded| forwarded.status),
                Ok(200),
                "{address}"
            );
        }
        // The same addresses in one batch: one entry names them all, and every request is
        // answered.
        let addresses = stand_in.api_addresses(&provider);
        let outcomes = canary
            .forward_batch(&connected["record"], &addresses)
            .await
            .unwrap_or_else(|failure| panic!("{provider}: {failure:?}"));
        assert_eq!(outcomes.len(), addresses.len(), "{provider}");
        assert!(
            outcomes.iter().all(|outcome| outcome.status == Some(200)),
            "{provider}: {outcomes:?}"
        );
        // One of them again, with its response as a stream: the head, the body in parts and
        // the end record are a response of the node like the frame.
        let address = stand_in.api_address(&provider);
        let streamed = canary
            .get_stream(&connected["record"], &address)
            .await
            .unwrap_or_else(|failure| panic!("{provider}: {failure:?}"));
        assert_eq!(
            (streamed.status, &streamed.end),
            (200, &json!({"complete": true})),
            "{provider}"
        );

        let tokens = stand_in.token_response(&provider);
        stand_in.next_tokens(&tokens);
        let (status, refreshed) = canary.refresh(&connected["record"]).await;
        assert_eq!(status, 200, "{provider}: {refreshed}");
        assert_public(&provider, &tokens, &refreshed["public"], true);
        let record = &refreshed["record"];
        let address = stand_in.api_address(&provider);
        let headers = json!([["Content-Type", "application/json"]]);
        let forwarded = canary
            .forward(record, "POST", &address, headers, b"{}")
            .await;
        assert_eq!(
            forwarded.map(|forwarded| forwarded.status),
            Ok(200),
            "{provider}"
        );

        let (status, revoked) = canary.revoke_token(record).await;
        let expected = Some(stand_in.has_revocation(&provider));
        assert_eq!(
            (status, revoked["revoked"].as_bool()),
            (200, expected),
            "{provider}"
        );
        records.insert(provider, record.clone());
    }
    let google = &records["google_workspace"];

    // A reconnect whose token object has no refresh token takes the one of the record before.
    let mut tokens = stand_in.token_response("google_workspace");
    tokens
        .as_object_mut()
        .unwrap()
        .shift_remove("refresh_token");
    let (status, reconnected) = canary.connect_to("google_workspace", &tokens).await;
    assert_eq!(status, 200, "{reconnected}");
    assert_public("google_workspace", &tokens, &reconnected["public"], false);
    let (status, merged) = canary.merge(&reconnected["record"], google).await;
    assert_eq!(status, 200, "{merged}");
    assert_public("google_workspace", &tokens, &merged["public"], true);
    let outcome = canary.merge(google, &records["slack"]).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));

    // The calls that use an OAuth record refuse a vault record, an authorization needs a
    // provider and a state the node knows, and `forward` needs a frame and an address of the
    // definition.
    let outcome = canary.refresh(&vault.password_record).await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    let outcome = canary.revoke_token(&vault.password_record).await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    let address = stand_in.api_address("google_workspace");
    let outcome = canary.get(&vault.password_record, &address).await;
    let outcome = refused(outcome, "a vault record");
    assert_eq!(code(&outcome), (403, "not_allowed"));
    let outcome = canary.release(0, google, "password", None).await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    let outcome = canary.begin("dropbox").await;
    assert_eq!(code(&outcome), (404, "provider_unknown"));
    let unknown_state = "AAAAAAAAAAAAAAAAAAAAAA.canary";
    let outcome = canary.complete("google_workspace", unknown_state).await;
    assert_eq!(code(&outcome), (404, "state_unknown"));
    let outcome = canary
        .get(google, "https://collector.example/gmail/v1/canary")
        .await;
    let outcome = refused(outcome, "an address of no definition");
    assert_eq!(code(&outcome), (403, "not_allowed"));
    let outcome = canary.post_bytes("/v1/forward", b"no frame").await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    let outcome = canary.post_bytes("/v1/forward/batch", b"no frame").await;
    assert_eq!(code(&outcome), (400, "invalid_request"));

    release_the_vault(&canary, 0, &vault).await;
    let no_https = json!({
        "user_id": user, "record": vault.password_record, "field": "password",
        "origin": "http://shop.example", "context": "canary",
    });
    let outcome = canary.post("/v1/release", no_https).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));

    // A value the operator domain gives to the node comes back as a record, and no response
    // carries it in the clear before `release` hands it out for a field. A value for a
    // request comes back as a record that no call hands out.
    let given = canary.secrets.text("value given to vault/store", &[]);
    let field = (json!(["shop.example"]), json!(["field"]));
    let (status, stored) = canary
        .store("SIGNUP_PASSWORD", field.0.clone(), field.1.clone(), &given)
        .await;
    assert_eq!(status, 200, "{stored}");
    let logged = canary.logged(0, &stored["log"]);
    assert_eq!(
        (&logged["t"], &logged["provider"], &logged["kind"]),
        (
            &json!("connection_created"),
            &json!("vault"),
            &json!("vault_secret")
        )
    );
    let carries = Some(given.as_str());
    let (status, released) = canary.release(0, &stored["record"], "value", carries).await;
    assert_eq!((status, released["value"].as_str()), (200, carries));
    let for_a_request = canary
        .secrets
        .text("value given to vault/store for a request", &[]);
    let header = json!(["header:authorization"]);
    let (status, stored) = canary
        .store("OPENAI_API_KEY", field.0.clone(), header, &for_a_request)
        .await;
    assert_eq!(status, 200, "{stored}");
    let outcome = canary.release(0, &stored["record"], "value", None).await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    let outcome = canary
        .store("signup_password", field.0.clone(), field.1.clone(), &given)
        .await;
    assert_eq!(code(&outcome), (400, "invalid_request"));

    // The two calls of the releases before v2.0.0 that handed the log of an account out do
    // not exist: the log store is the one place an entry is read from.
    for path in ["/v1/log/entries", "/v1/log/ack"] {
        let outcome = canary.probe("POST", path, json!({"user_id": user})).await;
        assert_eq!(code(&outcome), (404, "invalid_request"), "{path}");
    }

    // One use of a vault secret in a request to its site. The node of the forward role sends
    // the request of an envelope once. It answers no call of the delegation role, and a node
    // of the delegation role sends nothing.
    canary.take_the_forward_role().await;
    let secret = canary
        .secrets
        .text("vault secret value", &[at(Role::Site, SITE)]);
    let used = canary.secret_use("/v1/models", "page=1", &secret, 1);
    let sent = canary
        .vault_send(FORWARD, &used)
        .await
        .unwrap_or_else(|failure| panic!("{failure:?}"));
    assert_eq!((sent.status, &sent.end), (200, &json!({"complete": true})));
    let received = canary.site_requests().pop().unwrap();
    let carried = format!("Bearer {secret}");
    assert_eq!(received.target, "/v1/models?page=1");
    assert_eq!(received.header("authorization"), Some(carried.as_str()));
    let again = canary.vault_send(FORWARD, &used).await.unwrap_err();
    assert_eq!(code(&again), (400, "bad_challenge"));
    let outcome = canary.vault_send(0, &used).await.unwrap_err();
    assert_eq!(code(&outcome), (403, "not_allowed"));
    let nonce = json!({"user_id": user, "nonce": b64u(b"canary")});
    let outcome = canary.post_on(FORWARD, "/v1/status", nonce).await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    let released = json!({
        "user_id": user, "record": vault.password_record, "field": "password",
        "origin": "https://shop.example", "context": "canary",
    });
    let outcome = canary.post_on(FORWARD, "/v1/release", released).await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    assert_eq!(canary.site_requests().len(), 1);

    // The same use with both nodes: the first node opens a record the device made for the
    // site, records the use, and hands the value to the node of the forward role inside a
    // seal. That node sends the request. The record has no slot `field`: its value is in the
    // request to the site, and in no response of either node.
    let handed_value = canary
        .secrets
        .text("vault secret value of a record", &[at(Role::Site, SITE)]);
    let for_the_site = json!({
        "value": handed_value, "name": "SITE_API_KEY", "sites": [SITE],
        "slots": ["header:authorization"], "source": "device",
    });
    let for_the_site = canary.record("vault_secret", "vault", &for_the_site);
    let (status, handed) = canary.handoff(&for_the_site, "/v1/models", "page=3").await;
    assert_eq!(status, 200, "{handed}");
    let logged = canary.logged(0, &handed["log"]);
    assert_eq!(
        (&logged["t"], &logged["provider"], &logged["to"]),
        (
            &json!("provider_request"),
            &json!("vault"),
            &handed["envelope"]["to"]
        )
    );
    let sent = canary
        .vault_send(FORWARD, &handed["envelope"])
        .await
        .unwrap_or_else(|failure| panic!("{failure:?}"));
    assert_eq!((sent.status, &sent.end), (200, &json!({"complete": true})));
    let received = canary.site_requests().pop().unwrap();
    let carried = format!("Bearer {handed_value}");
    assert_eq!(received.target, "/v1/models?page=3");
    assert_eq!(received.header("authorization"), Some(carried.as_str()));
    // A record whose sites do not hold the site is handed to no request to it, and the
    // value of the record for the site is handed out by no call.
    let outcome = canary
        .handoff(&vault.request_record, "/v1/models", "")
        .await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    let outcome = canary.release(0, &for_the_site, "value", None).await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    assert_eq!(canary.site_requests().len(), 2);

    // A value that is one half of the credentials of HTTP Basic: the user-id, as its record
    // says. The caller writes the credentials with the placeholder for the user-id, and the
    // node of the forward role writes the header anew with the value: the value reaches the
    // site inside the base64 text of that header, and is in no response of either node. A
    // record of the header itself is handed to no use in the credentials, and a record of
    // one half of them to no use as the other half.
    let basic_value = canary
        .secrets
        .text("vault secret value of HTTP Basic", &[at(Role::Site, SITE)]);
    let for_basic = json!({
        "value": basic_value, "name": "SITE_BASIC_KEY", "sites": [SITE],
        "slots": ["basic:user"], "source": "device",
    });
    let for_basic = canary.record("vault_secret", "vault", &for_basic);
    let outcome = canary
        .handoff_at(&for_basic, "basic:password", "/v1/charges", "limit=1")
        .await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    let (status, handed) = canary
        .handoff_at(&for_basic, "basic:user", "/v1/charges", "limit=1")
        .await;
    assert_eq!(status, 200, "{handed}");
    assert_eq!(canary.logged(0, &handed["log"])["slot"], "basic:user");
    let sent = canary
        .vault_send_with(
            FORWARD,
            &handed["envelope"],
            &Canary::basic_with_the_placeholder(),
        )
        .await
        .unwrap_or_else(|failure| panic!("{failure:?}"));
    assert_eq!((sent.status, &sent.end), (200, &json!({"complete": true})));
    let received = canary.site_requests().pop().unwrap();
    assert_eq!(received.target, "/v1/charges?limit=1");
    assert_eq!(
        received.header("authorization"),
        Some(Canary::basic(&basic_value).as_str())
    );
    for half in ["basic:user", "basic:password"] {
        let outcome = canary
            .handoff_at(&for_the_site, half, "/v1/charges", "")
            .await;
        assert_eq!(code(&outcome), (403, "not_allowed"), "{half}");
    }
    let outcome = canary.release(0, &for_basic, "value", None).await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    assert_eq!(canary.site_requests().len(), 3);

    // The delegation moves to the second node and that node uses it. A node hands nothing to
    // itself and takes no transfer that was sealed for another node.
    let (this, peer) = (canary.attestation(0).await, canary.attestation(1).await);
    let export_to = |peer: &Value| json!({"peer": peer, "after": "", "limit": 1000});
    let import_from = |peer: &Value, envelope: &Value| json!({"peer": peer, "envelope": envelope});
    let outcome = canary.post("/v1/peer/export", export_to(&this)).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    let (status, exported) = canary.post("/v1/peer/export", export_to(&peer)).await;
    assert_eq!(status, 200, "{exported}");
    // The two nodes run one program: the transfer has no entry on either of them.
    let envelope = &exported["envelope"];
    assert_eq!(exported["logs"], json!([]));
    let outcome = canary
        .post("/v1/peer/import", import_from(&peer, envelope))
        .await;
    assert_eq!(code(&outcome), (400, "wrong_node"));
    let (status, imported) = canary
        .post_on(1, "/v1/peer/import", import_from(&this, envelope))
        .await;
    assert_eq!(
        (status, &imported["imported"]),
        (200, &json!(1)),
        "{imported}"
    );
    // The second node names the account whose grant it took, and the release that follows on
    // that node is its first entry for the account.
    assert_eq!(imported["accounts"], json!([user]));
    assert_eq!(imported["logs"], json!([]));
    release_the_vault(&canary, 1, &vault).await;
    assert_eq!(
        canary.logged(1, &json!({"seq": 1, "index": 0}))["t"],
        "secret_released"
    );
    let (status, back) = canary.post_on(1, "/v1/peer/export", export_to(&this)).await;
    assert_eq!(status, 200, "{back}");
    let returned = import_from(&peer, &back["envelope"]);
    let (status, known) = canary.post("/v1/peer/import", returned.clone()).await;
    assert_eq!((status, &known["imported"]), (200, &json!(0)), "{known}");

    // The operator reduces the nodes that hold the key of the account to one of two: the
    // second node is outside the subset of the account and drops its grant, with no entry and
    // no use. A subset outside its bounds is refused.
    let outcome = canary
        .post(
            "/v1/grants/prune",
            json!({"subset": {"pods": 0, "pod": 0, "copies": 1}}),
        )
        .await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    let outside = (0..2u32)
        .find(|pod| !super::assign(&user, 2, 1).contains(pod))
        .unwrap();
    let prune =
        json!({"subset": {"pods": 2, "pod": outside, "copies": 1}, "after": "", "limit": 1000});
    let (status, pruned) = canary.post_on(1, "/v1/grants/prune", prune.clone()).await;
    assert_eq!(status, 200, "{pruned}");
    assert_eq!(pruned["pruned"], json!([user]));
    let (status, again) = canary.post_on(1, "/v1/grants/prune", prune).await;
    assert_eq!((status, &again["pruned"]), (200, &json!([])), "{again}");

    // The calls that use a record of the account, for the two states that refuse them all.
    let until_revoked = pending_state(&canary, "google_workspace").await;
    let until_closed = pending_state(&canary, "slack").await;
    let refusals = |expected: (u16, &'static str), pending: String| {
        let (canary, google, vault, address) = (&canary, google, &vault, &address);
        async move {
            let begun = canary.begin("x").await;
            assert_eq!(code(&begun), expected, "oauth/begin");
            let completed = canary.complete("google_workspace", &pending).await;
            assert_eq!(code(&completed), expected, "oauth/complete");
            let merged = canary.merge(google, google).await;
            assert_eq!(code(&merged), expected, "oauth/merge");
            let refreshed = canary.refresh(google).await;
            assert_eq!(code(&refreshed), expected, "refresh");
            let revoked = canary.revoke_token(google).await;
            assert_eq!(code(&revoked), expected, "revoke-token");
            let forwarded = refused(canary.get(google, address).await, "forward");
            assert_eq!(code(&forwarded), expected, "forward");
            let released = canary
                .release(0, &vault.password_record, "password", None)
                .await;
            assert_eq!(code(&released), expected, "release");
            let stored = canary
                .store("PAYMENT_PIN", json!("any"), json!(["field"]), "493817")
                .await;
            assert_eq!(code(&stored), expected, "vault/store");
            let handed = canary
                .handoff(&vault.request_record, "/v1/models", "")
                .await;
            assert_eq!(code(&handed), expected, "vault/handoff");
        }
    };

    // The account withdraws its delegation.
    let (status, revoked) = canary.send(&canary.revoke_envelope().await).await;
    assert_eq!((status, &canary.reply(&revoked)["ok"]), (200, &json!(true)));
    refusals((409, "grant_revoked"), until_revoked).await;

    // The orderly shutdown: a closing node takes no command and no transfer.
    assert_eq!(canary.post("/v1/close", json!({})).await.0, 200);
    let wrong_method = canary.probe("GET", "/v1/close", json!({})).await;
    assert_eq!(code(&wrong_method), (405, "invalid_request"));
    refusals((503, "closing"), until_closed).await;
    let outcome = canary.send(&canary.grant_envelope().await).await;
    assert_eq!(code(&outcome), (503, "closing"));
    let outcome = canary.post("/v1/peer/import", returned).await;
    assert_eq!(code(&outcome), (503, "closing"));
    canary.health(0).await;

    // The node of the forward role closes as well: it sends nothing for an envelope that
    // reaches it afterwards, and its answer holds nothing of the envelope.
    let sent_before = canary.site_requests().len();
    assert_eq!(canary.post_on(FORWARD, "/v1/close", json!({})).await.0, 200);
    let unused = canary.secret_use("/v1/models", "page=2", &secret, 2);
    let outcome = canary.vault_send(FORWARD, &unused).await.unwrap_err();
    assert_eq!(code(&outcome), (503, "closing"));
    assert_eq!(canary.site_requests().len(), sent_before);
    canary.health(FORWARD).await;
    canary
}

#[tokio::test]
async fn the_private_keys_of_a_node_are_the_planted_markers() {
    let canary = Canary::start().await;
    for (node, name) in NODES
        .iter()
        .chain([&FORWARD_NODE, &RESERVE_NODE])
        .enumerate()
    {
        // The same names give the same values as the ones the fixture planted.
        let (sign_seed, seal_private) = node_keys(&canary.secrets, name);
        let keys = NodeKeys::from_random(&sign_seed, &seal_private);

        // The node identifier is the signing public key of the planted seed, and the binding
        // inside the attestation document carries the public keys of both planted values.
        assert_eq!(canary.health(node).await["node"], b64u(&keys.sign_public()));
        let response = canary.attestation(node).await;
        assert_eq!(response["node"], b64u(&keys.sign_public()));
        let attested = Canary::attested(&response);
        assert_eq!(attested.node, b64u(&keys.sign_public()));
        assert_eq!(attested.seal_public, keys.seal_public());
    }
    canary.verdict();
}

#[tokio::test]
async fn a_node_of_the_reserve_role_holds_the_user_key_and_uses_no_credential() {
    let canary = Canary::ready().await;
    let user = canary.app.user_id.clone();
    let vault = Vault::plant(&canary);
    let (_, connected) = canary.connect("google_workspace").await;
    let google = connected["record"].clone();
    canary.take_the_reserve_role().await;

    // The delegation of the account moves from the first node to the node of the reserve
    // role: that node holds the user key from here on, and neither node created an entry.
    let (this, reserve) = (
        canary.attestation(0).await,
        canary.attestation(RESERVE).await,
    );
    let (status, exported) = canary
        .post("/v1/peer/export", json!({"peer": reserve}))
        .await;
    assert_eq!(status, 200, "{exported}");
    assert_eq!(exported["logs"], json!([]));
    let import = json!({"peer": this, "envelope": exported["envelope"]});
    let (status, imported) = canary.post_on(RESERVE, "/v1/peer/import", import).await;
    assert_eq!(
        (status, &imported["accounts"]),
        (200, &json!([user])),
        "{imported}"
    );
    let (status, state) = canary
        .post_on(RESERVE, "/v1/status", json!({"user_id": user}))
        .await;
    assert_eq!((status, &state["grant"]["state"]), (200, &json!("active")));
    let health = canary.health(RESERVE).await;
    assert_eq!(
        (&health["role"], &health["grants"]),
        (&json!("reserve"), &json!(1))
    );

    // Every call that uses a credential is refused by the role of the node, with the
    // records of the account in its body: the node opens none of them and calls no
    // provider.
    let requests_before = canary.requests().len();
    for (record, field) in [
        (&vault.password_record, "password"),
        (&vault.totp_record, "totp"),
        (&vault.card_record, "number"),
        (&vault.named_record, "value"),
    ] {
        let outcome = canary.release(RESERVE, record, field, None).await;
        assert_eq!(code(&outcome), (403, "not_allowed"), "{field}");
    }
    let with_record = |record: &Value| {
        json!({
            "user_id": user, "record": record, "previous": record, "context": "canary",
            "provider": "google_workspace", "state": "state", "code": "code",
        })
    };
    for path in [
        "/v1/refresh",
        "/v1/revoke-token",
        "/v1/oauth/merge",
        "/v1/oauth/begin",
        "/v1/oauth/complete",
        "/v1/forward",
        "/v1/forward/batch",
        "/v1/mail/verify",
        "/v1/mail/read",
        "/v1/mail/submit",
        "/v1/vault/handoff",
    ] {
        let outcome = canary.post_on(RESERVE, path, with_record(&google)).await;
        assert_eq!(code(&outcome), (403, "not_allowed"), "{path}");
    }
    let store = json!({
        "user_id": user, "name": "PAYMENT_PIN", "sites": "any", "slots": ["field"],
        "value": canary.secrets.text("value for a node of the reserve role", &[]),
        "context": "canary",
    });
    let outcome = canary.post_on(RESERVE, "/v1/vault/store", store).await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    assert_eq!(canary.requests().len(), requests_before);
    let health = canary.health(RESERVE).await;
    assert_eq!(
        (
            &health["log"]["entries"],
            &health["log"]["events"],
            &health["grants"]
        ),
        (&json!(0), &json!(0), &json!(1))
    );
    // The node asked for connections to the host of its log store, for its node document,
    // and to no other host.
    let connections = canary.reserve_connections();
    assert!(!connections.is_empty());
    assert!(connections
        .iter()
        .all(|(host, port)| host == "s3.us-west-2.amazonaws.com" && *port == 443));

    // The node hands the delegation on to the second node, which uses it.
    let peer = canary.attestation(1).await;
    let (status, exported) = canary
        .post_on(RESERVE, "/v1/peer/export", json!({"peer": peer}))
        .await;
    assert_eq!(status, 200, "{exported}");
    let import = json!({"peer": reserve, "envelope": exported["envelope"]});
    let (status, imported) = canary.post_on(1, "/v1/peer/import", import).await;
    assert_eq!(
        (status, &imported["accounts"]),
        (200, &json!([user])),
        "{imported}"
    );
    release_the_vault(&canary, 1, &vault).await;
    canary.verdict();
}

#[tokio::test]
async fn the_walk_calls_every_route_in_a_success_case_and_in_a_failure_case() {
    let canary = walk().await;
    let set_of = |routes: &[(&str, &str)]| -> BTreeSet<(String, String)> {
        let owned = |(method, path): &(&str, &str)| (method.to_string(), path.to_string());
        routes.iter().map(owned).collect()
    };
    let routes = routes();
    assert_eq!(routes.len(), 24);
    let (mail_success, mail_failure) = super::mail::canary_routes().await;
    let mut called = canary.routes_called(|_| true);
    called.extend(mail_success.clone());
    called.extend(mail_failure.clone());
    assert_eq!(called, routes);
    let mut succeeded = canary.routes_called(|status| status == 200);
    succeeded.extend(mail_success);
    assert_eq!(succeeded, routes);
    let without_a_failure = set_of(&ROUTES_WITHOUT_A_FAILURE);
    let failing: BTreeSet<_> = routes.difference(&without_a_failure).cloned().collect();
    let mut refused = canary.routes_called(|status| status != 200);
    refused.extend(mail_failure);
    assert_eq!(refused, failing);
}

#[tokio::test]
async fn no_marker_appears_in_a_response_of_any_route() {
    walk().await.verdict_c1();
    super::mail::canary_routes().await;
}

#[tokio::test]
async fn a_credential_reaches_only_the_addresses_of_its_own_provider() {
    let canary = walk().await;
    let carried = canary.verdict_c2();

    // The verdict judges requests that happened: every provider received its authorization
    // code and its tokens, and the providers below their client secret and a PKCE verifier.
    let saw = |what: &str, role: Role, provider: &str| {
        let of_the_provider = format!(" of {provider}");
        let named = |name: &str| name.starts_with(what) && name.contains(&of_the_provider);
        let place = at(role, provider);
        carried.iter().any(|(name, at)| named(name) && *at == place)
    };
    for provider in canary.stand_in.providers() {
        assert!(
            saw("authorization code", Role::Token, &provider),
            "{provider}"
        );
        assert!(saw("access token", Role::Api, &provider), "{provider}");
        assert!(saw("refresh token", Role::Token, &provider), "{provider}");
        let revokes = canary.stand_in.has_revocation(&provider);
        assert_eq!(
            saw("refresh token", Role::Revocation, &provider),
            revokes,
            "{provider}"
        );
    }
    // A client secret in a form, and one in HTTP Basic.
    assert!(saw("client secret", Role::Token, "google_workspace"));
    assert!(saw("client secret", Role::Token, "x"));
    assert!(saw("PKCE verifier", Role::Token, "google_workspace"));
    // The three values of the vault secrets reached their site, each in the one request of
    // its use: the value of an envelope the test sealed, the value the first node read from
    // a record and sealed for the node of the forward role, and the value that node sealed
    // for the credentials of HTTP Basic, which the site received as base64 text.
    let site = at(Role::Site, SITE);
    let to_the_site: Vec<&String> = carried
        .iter()
        .filter(|(_, place)| *place == site)
        .map(|(name, _)| name)
        .collect();
    assert_eq!(
        to_the_site,
        [
            "vault secret value",
            "vault secret value of a record",
            "vault secret value of HTTP Basic"
        ]
    );
    // The log store received the session token of the operator with the entries of both
    // nodes, and nothing else that is a secret: not the secret access key that signed the
    // writes, and no secret of the account.
    let store = at(Role::LogStore, LOG_STORE);
    let stored: Vec<&String> = carried
        .iter()
        .filter(|(_, place)| *place == store)
        .map(|(name, _)| name)
        .collect();
    // Every provider had at least its connection, its refresh and its revocation written.
    assert!(stored.len() >= 3 * canary.stand_in.providers().len());
    assert!(stored
        .iter()
        .all(|name| *name == "session token for the log store"));
    let writes = canary.seen();
    let writes = writes
        .iter()
        .filter(|request| request.server_name == crate::testing::LOG_HOST);
    assert_eq!(writes.count(), stored.len());
}

#[tokio::test]
async fn a_release_carries_the_one_value_it_was_asked_for_and_never_a_totp_seed() {
    // `release` needs no provider in the operator configuration: the node has its log store
    // and nothing else.
    let canary = Canary::start().await;
    canary.configure_log_store().await;
    canary.grant().await;
    let vault = Vault::plant(&canary);
    release_the_vault(&canary, 0, &vault).await;

    // One event per value that left, and none for a refusal.
    let (kinds, _) = canary.logged_kinds();
    let released = ["secret_released"; 4];
    assert_eq!(kinds[..1], ["grant_accepted"]);
    assert_eq!(kinds[1..5], released);
    assert_eq!(kinds[5..], ["totp_issued"]);
    assert!(
        canary.requests().is_empty(),
        "no provider received a request"
    );
    canary.verdict();
}

#[tokio::test]
async fn the_answer_of_a_revocation_address_leaves_as_one_bit() {
    let canary = Canary::ready().await;
    // The revocation address hands back the token it received, in its body and in a header,
    // with a status inside and outside 2xx.
    for (status, revoked) in [(200, true), (204, true), (400, false), (503, false)] {
        let (_, connected) = canary.connect("google_workspace").await;
        canary.stand_in.next(Role::Revocation, move |seen| {
            let token = field(seen, "token").unwrap_or_default();
            let body = json!({"error": token, "error_description": token, "token": token});
            let headers = [
                ("content-type", "application/json"),
                ("x-token", token.as_str()),
            ];
            Reply::with_body(status, &headers, &to_json(&body))
        });
        let (answered, outcome) = canary.revoke_token(&connected["record"]).await;
        assert_eq!(answered, 200, "{status}: {outcome}");
        let keys: Vec<&String> = outcome.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["revoked", "log"], "{status}");
        assert_eq!(outcome["revoked"], revoked, "{status}");
    }
    canary.verdict();
}

#[tokio::test]
async fn a_redirect_to_another_host_is_returned_and_not_followed() {
    let canary = Canary::ready().await;
    let (_, connected) = canary.connect("google_workspace").await;
    let address = canary.stand_in.api_address("google_workspace");
    let exchanged = canary.requests().len();

    // A node that followed one of these redirects would hand the token of one provider to
    // another, to a token address, or to a host of no definition. The stand-in answers for the
    // hosts of every provider, and the platform of the fixture keeps every connection a node
    // asks for.
    let targets = [
        "https://graph.microsoft.com/v1.0/me",
        "https://oauth2.googleapis.com/token",
        "https://slack.com/api/auth.test",
        "https://collector.example/gmail/v1/canary",
    ];
    let statuses = [301, 302, 303, 307, 308];
    for (request, status) in statuses.into_iter().enumerate() {
        let target = targets[request % targets.len()];
        canary.stand_in.next(Role::Api, move |_| {
            Reply::with_body(status, &[("location", target)], b"moved")
        });
        let record = &connected["record"];
        let forwarded = canary
            .forward(record, "POST", &address, json!([]), b"{}")
            .await
            .unwrap();
        assert_eq!(forwarded.status, status);
        assert_eq!(forwarded.header("location"), Some(target), "{status}");
        assert_eq!(forwarded.body, b"moved", "{status}");
    }
    assert_eq!(canary.requests().len(), exchanged + statuses.len());
    canary.verdict();
}

#[test]
fn the_base32_of_the_fixture_is_the_base32_of_rfc_4648() {
    // The test vectors of RFC 4648 section 10, and the seed of RFC 6238 appendix B.
    assert_eq!(fixture::base32(b"f"), "MY");
    assert_eq!(fixture::base32(b"foobar"), "MZXW6YTBOI");
    let seed = fixture::base32(b"12345678901234567890");
    assert_eq!(seed, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
}

#[tokio::test]
async fn seal_and_open_are_not_routes() {
    let canary = Canary::ready().await;
    let user = &canary.app.user_id;
    let token = json!({
        "access_token": canary.secrets.text("access token the operator domain obtained", &[]),
        "refresh_token": canary.secrets.text("refresh token the operator domain obtained", &[]),
    });

    // A node takes no plaintext to make a record of it, and hands out no plaintext of one.
    let seal = json!({
        "user_id": user, "kind": "oauth_operator", "provider": "google_workspace", "id": "",
        "plaintext": b64u(&to_json(&token)), "context": "canary",
    });
    let outcome = canary.probe("POST", "/v1/seal", seal).await;
    assert_eq!(code(&outcome), (404, "invalid_request"), "{}", outcome.1);
    let record = canary.record("oauth_operator", "google_workspace", &token);
    let open = json!({"user_id": user, "record": record, "context": "canary"});
    let outcome = canary.probe("POST", "/v1/open", open).await;
    assert_eq!(code(&outcome), (404, "invalid_request"), "{}", outcome.1);
    canary.verdict();
}

#[tokio::test]
async fn records_of_the_kinds_oauth_operator_and_api_key_are_used_by_no_call() {
    let canary = Canary::ready().await;
    let address = canary.stand_in.api_address("google_workspace");
    // A record of such a kind has no use: the call is not allowed, or the record is no record
    // of this release.
    let unused = |outcome: &(u16, Value), call: &str| {
        let refusal = code(outcome);
        let refused = refusal == (403, "not_allowed") || refusal == (422, "record_invalid");
        assert!(refused, "{call}: {} {}", outcome.0, outcome.1);
    };

    for kind in ["oauth_operator", "api_key"] {
        // A plaintext with a credential in every place a call reads one from.
        let name = format!("credential of a record of kind {kind}");
        let credential = canary.secrets.text(&name, &[]);
        let plaintext = json!({
            "api_key": credential, "value": credential, "number": credential, "cvc": credential,
            "token": {"access_token": credential, "refresh_token": credential}, "obtained_ms": 1,
        });
        let record = canary.record(kind, "google_workspace", &plaintext);
        let forwarded = refused(canary.get(&record, &address).await, kind);
        unused(&forwarded, &format!("forward, {kind}"));
        unused(&canary.refresh(&record).await, &format!("refresh, {kind}"));
        unused(
            &canary.revoke_token(&record).await,
            &format!("revoke-token, {kind}"),
        );
        unused(
            &canary.merge(&record, &record).await,
            &format!("oauth/merge, {kind}"),
        );
        for field in ["password", "totp", "card_number", "card_cvc"] {
            let released = canary.release(0, &record, field, None).await;
            unused(&released, &format!("release of {field}, {kind}"));
        }
    }
    assert!(
        canary.requests().is_empty(),
        "no provider received a request"
    );
    canary.verdict();
}

#[tokio::test]
async fn a_token_the_device_imported_is_used_inside_the_node_and_handed_out_by_no_call() {
    let canary = Canary::ready().await;
    for provider in canary.stand_in.providers() {
        // A record of kind `oauth_imported` is made by the device of the account, of a token
        // the operator domain held before. Its plaintext has the shape of a record of kind
        // `oauth`. No call of a node makes one.
        let tokens = canary.stand_in.token_response(&provider);
        let mut plaintext = json!({"token": tokens, "obtained_ms": 1});
        if canary.stand_in.has_dynamic_client(&provider) {
            plaintext["client_id"] = json!("canary-client");
        }
        let imported = canary.record("oauth_imported", &provider, &plaintext);

        // The node uses it the way it uses a token it was issued: in a request to an address
        // of the provider, and in a refresh, whose record is of the same kind.
        let address = canary.stand_in.api_address(&provider);
        let forwarded = canary.get(&imported, &address).await;
        assert_eq!(
            forwarded.map(|forwarded| forwarded.status),
            Ok(200),
            "{provider}"
        );
        let tokens = canary.stand_in.token_response(&provider);
        canary.stand_in.next_tokens(&tokens);
        let (status, refreshed) = canary.refresh(&imported).await;
        assert_eq!(status, 200, "{provider}: {refreshed}");
        assert_eq!(refreshed["record"]["kind"], "oauth_imported", "{provider}");
        assert_eq!(refreshed["record"]["id"], imported["id"], "{provider}");
        assert_public(&provider, &tokens, &refreshed["public"], true);

        // No call hands the token out, and none moves it into a record of kind `oauth`: a
        // merge refuses an imported record in either place.
        let (_, connected) = canary.connect(&provider).await;
        let issued = &connected["record"];
        for record in [&imported, &refreshed["record"]] {
            for (record, previous) in [(record, issued), (issued, record), (record, record)] {
                let outcome = canary.merge(record, previous).await;
                assert_eq!(code(&outcome), (403, "not_allowed"), "{provider}");
            }
            for field in ["password", "totp", "card_number", "card_cvc"] {
                let outcome = canary.release(0, record, field, None).await;
                assert_eq!(code(&outcome), (403, "not_allowed"), "{provider}, {field}");
            }
        }

        let (status, revoked) = canary.revoke_token(&refreshed["record"]).await;
        let expected = Some(canary.stand_in.has_revocation(&provider));
        assert_eq!(
            (status, revoked["revoked"].as_bool()),
            (200, expected),
            "{provider}"
        );
    }
    canary.verdict();
}

/// Replaces the claims of the `id_token` of a token object and keeps its other two parts.
fn set_claims(token: &mut Value, claims: &Value) {
    let jwt = token["id_token"].as_str().unwrap().to_string();
    let signature = jwt.rsplit('.').next().unwrap();
    token["id_token"] = json!(id_token(claims, signature));
}

/// The value a test puts in the place of a public field.
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// A value of the listed type. A string has exactly as many UTF-8 bytes as its limit and
    /// fewer characters.
    AtTheLimit,
    /// A value of another type, with a marker inside.
    OfAnotherType,
    /// A string with a marker that has more UTF-8 bytes than its limit and, where the limit
    /// leaves room for that, no more characters than the limit. An integer of 21 digits.
    AboveTheLimit,
}

impl Shape {
    fn value(self, canary: &Canary, provider: &str, path: &str, leaf: Leaf) -> Value {
        let marker = || {
            let name = format!("{self:?} value of {path} of {provider}");
            canary.secrets.text(&name, &[])
        };
        match (self, leaf) {
            (Shape::AtTheLimit, Leaf::Text(limit)) => {
                json!(format!(
                    "{}{}",
                    "가".repeat(limit / 3),
                    "x".repeat(limit % 3)
                ))
            }
            (Shape::AtTheLimit, Leaf::Integer) => json!(3600),
            (Shape::AtTheLimit, Leaf::Boolean) => json!(false),
            (Shape::OfAnotherType, Leaf::Text(_)) => json!({"nested": marker()}),
            (Shape::OfAnotherType, Leaf::Integer | Leaf::Boolean) => json!(marker()),
            (Shape::AboveTheLimit, Leaf::Text(limit)) => {
                let marker = marker();
                let filler = "가".repeat(limit.saturating_sub(marker.len()) / 3 + 1);
                json!(format!("{marker}{filler}"))
            }
            (Shape::AboveTheLimit, Leaf::Integer) => {
                let name = format!("integer of 21 digits at {path} of {provider}");
                json!(canary.secrets.digits(&name, 21))
            }
            (Shape::AboveTheLimit, Leaf::Boolean) => json!(true),
        }
    }
}

#[tokio::test]
async fn public_fields_are_the_listed_leaves_of_the_listed_type_and_size() {
    let canary = Canary::ready().await;
    let shapes = [
        Shape::AtTheLimit,
        Shape::OfAnotherType,
        Shape::AboveTheLimit,
    ];
    for provider in canary.stand_in.providers() {
        let (leaves, claims) = public_leaves(&provider);
        for shape in shapes {
            let mut tokens = canary.stand_in.token_response(&provider);
            for (path, leaf) in leaves {
                set(
                    &mut tokens,
                    path,
                    shape.value(&canary, &provider, path, *leaf),
                );
                // Beside every public leaf of an object, a key that the definition does not
                // list: the object is not public, its listed leaves are.
                if let Some((object, _)) = path.rsplit_once('.') {
                    let name = format!("unlisted key of {object} of {provider}, {shape:?}");
                    let unlisted = json!(canary.secrets.text(&name, &[]));
                    set(&mut tokens, &format!("{object}.unlisted"), unlisted);
                }
            }
            if !claims.is_empty() {
                let mut body = claims_of(&tokens);
                for (claim, leaf) in claims {
                    body[*claim] = shape.value(&canary, &provider, claim, *leaf);
                }
                set_claims(&mut tokens, &body);
            }

            // A value of the wrong type or size is left out. It does not fail the call.
            let (status, connected) = canary.connect_to(&provider, &tokens).await;
            assert_eq!(status, 200, "{provider}, {shape:?}: {connected}");
            assert_public(&provider, &tokens, &connected["public"], true);
        }
    }
    canary.verdict();
}

/// A call that failed because a provider response did not pass a check of the egress policy:
/// 502 with the code `response_withheld` and a message, and nothing of the provider response.
fn assert_withheld(outcome: &(u16, Value), case: &str) {
    assert_eq!(
        code(outcome),
        (502, "response_withheld"),
        "{case}: {}",
        outcome.1
    );
    let keys: Vec<&str> = outcome
        .1
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["code", "message"], "{case}");
}

/// The place of a token object that carries a token it must not carry.
#[derive(Clone, Copy, Debug)]
enum Carrier {
    /// A public field of the token object, by its path.
    Field(&'static str),
    /// A public claim of the `id_token`.
    Claim(&'static str),
}

impl Carrier {
    fn carry(self, tokens: &mut Value, value: String) {
        match self {
            Carrier::Field(path) => set(tokens, path, json!(value)),
            Carrier::Claim(claim) => {
                let mut body = claims_of(tokens);
                body[claim] = json!(value);
                set_claims(tokens, &body);
            }
        }
    }
}

#[tokio::test]
async fn a_token_response_with_a_token_inside_a_public_field_or_claim_is_withheld() {
    use Carrier::{Claim, Field};
    let canary = Canary::ready().await;
    let stand_in = &canary.stand_in;

    // An exchange. The token is the whole value of the public field or claim, or a part of it.
    let cases = [
        ("google_workspace", Field("scope"), "access_token"),
        ("google_workspace", Field("scope"), "refresh_token"),
        ("google_workspace", Field("scope"), "id_token"),
        ("google_workspace", Claim("email"), "access_token"),
        ("google_workspace", Claim("name"), "refresh_token"),
        ("google_workspace", Claim("picture"), "access_token"),
        ("microsoft", Claim("preferred_username"), "refresh_token"),
        ("slack", Field("team.name"), "authed_user.access_token"),
        (
            "slack",
            Field("authed_user.scope"),
            "authed_user.refresh_token",
        ),
        ("notion", Field("owner.user.name"), "access_token"),
        ("x", Field("scope"), "refresh_token"),
    ];
    for (index, (provider, carrier, token)) in cases.into_iter().enumerate() {
        let mut tokens = stand_in.token_response(provider);
        let carried = lookup(&tokens, token).and_then(Value::as_str).unwrap();
        let value = match index % 2 {
            0 => carried.to_string(),
            _ => format!("in front {carried} behind"),
        };
        carrier.carry(&mut tokens, value);
        let outcome = canary.connect_to(provider, &tokens).await;
        assert_withheld(&outcome, &format!("{provider}: {token} in {carrier:?}"));
    }

    // A provider with a token container: a token at the top level counts as well.
    let mut tokens = stand_in.token_response("slack");
    let bot_token = canary
        .secrets
        .text("access token at the top level of slack", &[]);
    set(&mut tokens, "access_token", json!(bot_token));
    set(&mut tokens, "team.name", json!(format!("team {bot_token}")));
    let outcome = canary.connect_to("slack", &tokens).await;
    assert_withheld(&outcome, "slack: the top level access_token in team.name");

    // A refresh. The tokens of the merged token object count: the response has no refresh
    // token, so the record keeps the one it holds, and that one is inside a public field.
    let (first, connected) = canary.connect("google_workspace").await;
    let mut tokens = stand_in.token_response("google_workspace");
    tokens
        .as_object_mut()
        .unwrap()
        .shift_remove("refresh_token");
    let held = first["refresh_token"].as_str().unwrap();
    set(&mut tokens, "scope", json!(format!("openid {held}")));
    stand_in.next_tokens(&tokens);
    let outcome = canary.refresh(&connected["record"]).await;
    assert_withheld(
        &outcome,
        "refresh: the refresh token of the record in scope",
    );

    // A refresh whose response carries its own new access token in a public claim.
    let mut tokens = stand_in.token_response("google_workspace");
    let issued = tokens["access_token"].as_str().unwrap().to_string();
    Claim("email").carry(&mut tokens, format!("{issued}@example.com"));
    stand_in.next_tokens(&tokens);
    let outcome = canary.refresh(&connected["record"]).await;
    assert_withheld(&outcome, "refresh: the new access token in the claim email");

    // A merge. The refresh token that moves in from the previous record is inside a public
    // field of the new one.
    let secret = |name: &str| canary.secrets.text(&format!("{name} of a merge"), &[]);
    let moved = secret("refresh token of the previous record");
    let previous = json!({
        "access_token": secret("access token of the previous record"), "refresh_token": moved,
    });
    let new = json!({
        "access_token": secret("access token of the new record"), "token_type": "Bearer",
        "scope": format!("openid {moved}"),
    });
    let record = |token: Value| {
        let plaintext = json!({"token": token, "obtained_ms": 1});
        canary.record("oauth", "google_workspace", &plaintext)
    };
    let outcome = canary.merge(&record(new), &record(previous)).await;
    assert_withheld(
        &outcome,
        "merge: the refresh token of the previous record in scope",
    );
    canary.verdict();
}

#[tokio::test]
async fn a_refused_token_request_answers_with_a_word_of_the_closed_vocabulary() {
    let canary = Canary::ready().await;
    // A refusal of a provider leaves as its status and one word, and as nothing else.
    let assert_refusal = |outcome: &(u16, Value), failure: &str, status: u16, word: &str| {
        let case = format!("{failure}, {status}, {word:?}");
        assert_eq!(code(outcome), (502, failure), "{case}");
        let expected = json!({
            "code": failure, "message": outcome.1["message"], "provider_status": status,
            "provider_error": word,
        });
        assert_eq!(outcome.1, expected, "{case}");
    };

    // A word of the vocabulary comes back as it is, and what the provider wrote beside it
    // does not come back.
    for word in PROVIDER_ERRORS {
        let detail = canary.secrets.text("error description of a provider", &[]);
        let answer = json!({"error": word, "error_description": detail, "error_uri": detail});
        let refusal = move |_: &Seen| Reply::json(400, &answer);
        let outcome = canary.connect_with("google_workspace", refusal).await;
        assert_refusal(&outcome, "exchange_failed", 400, word);
    }

    // A refused exchange that hands back what the node sent: the PKCE verifier as the error
    // code, the client secret and the authorization code beside it.
    let refusal = |seen: &Seen| {
        let sent = |key: &str| field(seen, key).unwrap_or_default();
        let answer = json!({
            "error": sent("code_verifier"), "error_description": sent("client_secret"),
            "code": sent("code"),
        });
        Reply::json(400, &answer)
    };
    let outcome = canary.connect_with("google_workspace", refusal).await;
    assert_refusal(&outcome, "exchange_failed", 400, "other");

    // A provider that says `ok: false` with 200 and hands back the authorization code.
    let refusal = |seen: &Seen| {
        let answer = json!({"ok": false, "error": field(seen, "code").unwrap_or_default()});
        Reply::json(200, &answer)
    };
    let outcome = canary.connect_with("slack", refusal).await;
    assert_refusal(&outcome, "exchange_failed", 200, "other");

    // Refused refreshes of one record. Each failure response of the token address carries the
    // refresh token it received: in the places a node reads an error string from, and in
    // places it does not read.
    type Refusal = fn(&str) -> Value;
    let json_refusals: [(u16, Refusal, &str); 9] = [
        (
            400,
            |token| json!({"error": token, "error_description": token}),
            "other",
        ),
        (
            401,
            |token| json!({"error": {"code": token, "message": token}}),
            "other",
        ),
        (403, |token| json!({"error": {"message": token}}), "other"),
        (500, |token| json!({"code": token}), "other"),
        (
            400,
            |token| json!({"error": "invalid_grant", "error_description": token}),
            "invalid_grant",
        ),
        // The comparison with the vocabulary is by bytes.
        (
            400,
            |token| json!({"error": "Invalid_Grant", "hint": token}),
            "other",
        ),
        (
            400,
            |token| json!({"error": "invalid_grant ", "hint": token}),
            "other",
        ),
        // No error string in a place a node reads: the empty string.
        (
            400,
            |token| json!({"error_description": token, "errors": [token]}),
            "",
        ),
        // A 200 that is no token response.
        (
            200,
            |token| json!({"detail": token, "token_type": "Bearer"}),
            "",
        ),
    ];
    let (_, connected) = canary.connect("google_workspace").await;
    for (status, answer, word) in json_refusals {
        canary.stand_in.next(Role::Token, move |seen| {
            let token = field(seen, "refresh_token").unwrap_or_default();
            Reply::json(status, &answer(&token))
        });
        let outcome = canary.refresh(&connected["record"]).await;
        assert_refusal(&outcome, "refresh_failed", status, word);
    }
    // A failure response that is not JSON.
    canary.stand_in.next(Role::Token, |seen| {
        let page = format!(
            "<p>{}</p>",
            field(seen, "refresh_token").unwrap_or_default()
        );
        Reply::with_body(503, &[("content-type", "text/html")], page.as_bytes())
    });
    let outcome = canary.refresh(&connected["record"]).await;
    assert_refusal(&outcome, "refresh_failed", 503, "");
    // A connection that ends without a response: the status is 0.
    canary
        .stand_in
        .next(Role::Token, |_| Reply::Raw(Vec::new()));
    let outcome = canary.refresh(&connected["record"]).await;
    assert_refusal(&outcome, "refresh_failed", 0, "");
    canary.verdict();
}

#[tokio::test]
async fn a_repeated_refresh_of_one_record_is_answered_from_memory() {
    let canary = Canary::ready().await;
    let (_, connected) = canary.connect("google_workspace").await;
    let (status, first) = canary.refresh(&connected["record"]).await;
    assert_eq!(status, 200, "{first}");
    let logged = canary.logged_kinds();

    // The same record again: the node answers with the response it kept. It asks the provider
    // nothing and writes no entry.
    let (status, second) = canary.refresh(&connected["record"]).await;
    assert_eq!((status, &second), (200, &first));
    let seen = canary.seen();
    let is_a_refresh =
        |request: &&Seen| field(request, "grant_type").as_deref() == Some("refresh_token");
    assert_eq!(
        seen.iter().filter(is_a_refresh).count(),
        1,
        "token requests of a refresh"
    );
    assert_eq!(canary.logged_kinds(), logged);
    canary.verdict();
}

/// What a provider makes of the value of a request header before it hands it back.
type Echo = fn(&str) -> String;

/// The ways a provider hands the value of a request header back. The value of the
/// `Authorization` header is `Bearer` and a space in front of the token, so the base64 forms
/// put the token at each of the three alignments.
///
/// Encoders do not agree on the bytes they escape: one escapes every byte outside the
/// unreserved characters, one leaves `/` as it is, and nothing keeps one from escaping every
/// byte. Each of these is the percent-encoding of the same value. Writers of JSON do not
/// agree either: one writes `/` behind a backslash, another a character of markup as its code
/// unit.
const ECHOES: [(&str, Echo); 16] = [
    ("as it is", |value| value.to_string()),
    ("percent, every byte, upper case", |value| {
        percent_encoded(value.as_bytes(), true, true)
    }),
    ("percent, every byte, lower case", |value| {
        percent_encoded(value.as_bytes(), true, false)
    }),
    ("percent, reserved bytes, upper case", |value| {
        percent_encoded(value.as_bytes(), false, true)
    }),
    ("percent, reserved bytes, lower case", |value| {
        percent_encoded(value.as_bytes(), false, false)
    }),
    ("percent, reserved bytes but `/`", |value| {
        percent_encoded(value.as_bytes(), false, true).replace("%2F", "/")
    }),
    ("base64", |value| STANDARD.encode(value)),
    ("base64 behind one byte", |value| {
        STANDARD.encode(format!("-{value}"))
    }),
    ("base64 behind two bytes", |value| {
        STANDARD.encode(format!("--{value}"))
    }),
    ("base64url", |value| {
        URL_SAFE_NO_PAD.encode(format!("{value}\n"))
    }),
    ("base64url behind one byte", |value| {
        URL_SAFE_NO_PAD.encode(format!("-{value}\n"))
    }),
    ("base64url behind two bytes", |value| {
        URL_SAFE_NO_PAD.encode(format!("--{value}\n"))
    }),
    ("hex", |value| {
        String::from_utf8(scan::hex(value.as_bytes(), false)).unwrap()
    }),
    ("upper case hex", |value| {
        String::from_utf8(scan::hex(value.as_bytes(), true)).unwrap()
    }),
    // Inside a JSON string, as two writers of JSON escape it.
    ("JSON, the slash escaped", |value| value.replace('/', "\\/")),
    ("JSON, code units", |value| {
        let unit = |character: char| match character {
            '/' | '+' | '=' | ' ' => format!("{}u{:04x}", '\\', u32::from(character)),
            other => other.to_string(),
        };
        value.chars().map(unit).collect()
    }),
];

#[tokio::test]
async fn a_provider_response_that_reflects_the_injected_credential_is_withheld() {
    let canary = Canary::ready().await;
    let (_, connected) = canary.connect("google_workspace").await;
    let record = &connected["record"];
    let address = canary.stand_in.api_address("google_workspace");
    let sent = |seen: &Seen| seen.header("authorization").unwrap_or_default().to_string();

    // A response that reflects nothing comes back.
    let plain = canary.get(record, &address).await;
    assert_eq!(plain.map(|forwarded| forwarded.status), Ok(200));
    let mut requests = 1;

    // The value of the `Authorization` header of the request, in the body and in a header of
    // the response, in every form.
    for in_a_header in [false, true] {
        for (form, echo) in ECHOES {
            canary.stand_in.next(Role::Api, move |seen| {
                let echoed = echo(&sent(seen));
                match in_a_header {
                    true => Reply::with_body(200, &[("x-request-echo", echoed.as_str())], b"{}"),
                    false => Reply::with_body(200, &[], echoed.as_bytes()),
                }
            });
            requests += 1;
            let numbered = format!("{address}?request={requests}");
            let case = format!("{form}, in a header: {in_a_header}");
            let outcome = refused(canary.get(record, &numbered).await, &case);
            assert_withheld(&outcome, &case);
        }
    }

    // The value in two chunks of a chunked body: the check reads the body, not its chunks.
    canary.stand_in.next(Role::Api, move |seen| {
        let value = sent(seen);
        let (head, tail) = value.split_at(value.len() / 2);
        let chunked = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{head}\r\n{:x}\r\n{tail}\r\n0\r\n\r\n",
            head.len(),
            tail.len()
        );
        Reply::Raw(chunked.into_bytes())
    });
    requests += 1;
    let numbered = format!("{address}?request={requests}");
    let case = "a value in two chunks";
    assert_withheld(&refused(canary.get(record, &numbered).await, case), case);

    // A redirect is returned as it is only when it reflects nothing: an address that carries
    // the credential is withheld like any other header.
    canary.stand_in.next(Role::Api, move |seen| {
        let echoed = percent_encoded(sent(seen).as_bytes(), false, true);
        let location = format!("https://collector.example/?authorization={echoed}");
        Reply::with_body(302, &[("location", location.as_str())], b"")
    });
    requests += 1;
    let numbered = format!("{address}?request={requests}");
    let case = "a redirect to an address that carries the credential";
    assert_withheld(&refused(canary.get(record, &numbered).await, case), case);

    // Each request went out, so each is on the log, although its response was withheld.
    assert_eq!(canary.requests().len(), 1 + requests);
    let (kinds, _) = canary.logged_kinds();
    let recorded = kinds.iter().filter(|kind| *kind == "provider_request");
    assert_eq!(recorded.count(), requests);
    canary.verdict();
}

#[tokio::test]
async fn a_streamed_provider_response_that_reflects_the_injected_credential_is_cut() {
    let canary = Canary::ready().await;
    let (_, connected) = canary.connect("google_workspace").await;
    let record = &connected["record"];
    let address = canary.stand_in.api_address("google_workspace");
    let sent = |seen: &Seen| seen.header("authorization").unwrap_or_default().to_string();

    // A response that reflects nothing comes back whole, as a stream.
    let plain = canary
        .get_stream(record, &address)
        .await
        .unwrap_or_else(|failure| panic!("{failure:?}"));
    assert_eq!(
        (plain.status, &plain.end),
        (200, &json!({"complete": true}))
    );
    assert_eq!(plain.log["created"], true);
    let mut requests = 1;

    // The value of the `Authorization` header of the request in a header of the response, in
    // every form: the call fails, and no part of the response is handed on.
    for (form, echo) in ECHOES {
        canary.stand_in.next(Role::Api, move |seen| {
            let echoed = echo(&sent(seen));
            Reply::with_body(200, &[("x-request-echo", echoed.as_str())], b"{}")
        });
        requests += 1;
        let numbered = format!("{address}?request={requests}");
        let failure = canary.get_stream(record, &numbered).await.expect_err(form);
        assert_withheld(&failure, form);
    }
    // The same in the body, behind bytes that hold nothing of the credential, more of them
    // than the search holds back: the head is handed on, and the body is cut in front of the
    // credential.
    let lead = "0123456789".repeat(4_000);
    for (form, echo) in ECHOES {
        let front = lead.clone();
        canary.stand_in.next(Role::Api, move |seen| {
            let body = format!("{front}{} and more", echo(&sent(seen)));
            Reply::with_body(200, &[], body.as_bytes())
        });
        requests += 1;
        let numbered = format!("{address}?request={requests}");
        let cut = canary
            .get_stream(record, &numbered)
            .await
            .unwrap_or_else(|failure| panic!("{form}: {failure:?}"));
        assert_eq!(cut.status, 200, "{form}");
        assert_eq!(cut.end["complete"], false, "{form}");
        assert_eq!(cut.end["code"], "response_withheld", "{form}");
        assert!(lead.as_bytes().starts_with(&cut.body()), "{form}");
    }
    // The value in two chunks of a chunked body that arrive apart: the search reads the body
    // across its pieces, and what was handed on before the second chunk came holds no part
    // of the credential.
    let lead_bytes = lead.clone();
    canary.stand_in.next(Role::Api, move |seen| {
        let value = sent(seen);
        let (head, tail) = value.split_at(value.len() / 2);
        let first = format!("{lead_bytes}{head}");
        let pause = std::time::Duration::from_millis(50);
        Reply::chunked(200, &[], &[first.as_bytes(), tail.as_bytes()], pause)
    });
    requests += 1;
    let numbered = format!("{address}?request={requests}");
    let cut = canary.get_stream(record, &numbered).await.unwrap();
    assert_eq!(cut.end["code"], "response_withheld");
    assert!(!cut.body().is_empty());
    assert!(lead.as_bytes().starts_with(&cut.body()));

    // Each request went out, so each is on the log, although its response was cut or
    // withheld.
    assert_eq!(canary.requests().len(), 1 + requests);
    let (kinds, _) = canary.logged_kinds();
    let recorded = kinds.iter().filter(|kind| *kind == "provider_request");
    assert_eq!(recorded.count(), requests);
    canary.verdict();
}

#[tokio::test]
async fn a_site_response_that_reflects_the_value_of_a_vault_secret_is_not_handed_on() {
    let canary = Canary::start().await;
    canary.take_the_forward_role().await;
    let secret = canary
        .secrets
        .text("vault secret value", &[at(Role::Site, SITE)]);
    let sent = |seen: &Seen| seen.header("authorization").unwrap_or_default().to_string();
    let mut uses = 0u8;
    let mut used = || {
        uses += 1;
        let envelope = canary.secret_use("/v1/echo", &format!("use={uses}"), &secret, uses);
        let canary = &canary;
        async move { canary.vault_send(FORWARD, &envelope).await }
    };
    let withheld = |outcome: Result<crate::testing::Streamed, (u16, Value)>, case: &str| {
        let failure = outcome.expect_err(case);
        assert_eq!(code(&failure), (502, "response_withheld"), "{case}");
    };

    // A response that reflects nothing comes back whole.
    let plain = used().await.unwrap();
    assert_eq!(
        (plain.status, &plain.end),
        (200, &json!({"complete": true}))
    );
    assert_eq!(plain.body(), b"{\"ok\":true}");

    // The value of the `Authorization` header of the request in a header of the response, in
    // every form: no part of the response is handed on.
    for (form, echo) in ECHOES {
        canary.stand_in.next(Role::Site, move |seen| {
            let echoed = echo(&sent(seen));
            Reply::with_body(200, &[("x-request-echo", echoed.as_str())], b"{}")
        });
        withheld(used().await, form);
    }
    // The same in the body, behind bytes that hold nothing of the value, more of them than
    // the search holds back: the head is handed on, and the body is cut in front of the
    // value.
    let lead = "0123456789".repeat(4_000);
    for (form, echo) in ECHOES {
        let front = lead.clone();
        canary.stand_in.next(Role::Site, move |seen| {
            let body = format!("{front}{} and more", echo(&sent(seen)));
            Reply::with_body(200, &[], body.as_bytes())
        });
        let cut = used()
            .await
            .unwrap_or_else(|failure| panic!("{form}: {failure:?}"));
        assert_eq!(cut.status, 200, "{form}");
        assert_eq!(cut.end["complete"], false, "{form}");
        assert_eq!(cut.end["code"], "response_withheld", "{form}");
        assert!(lead.as_bytes().starts_with(&cut.body()), "{form}");
    }

    // The value in two chunks of a chunked body that arrive apart: the search reads the
    // body across its pieces, and what was handed on before the second chunk came holds no
    // part of the value.
    let lead_bytes = lead.clone();
    canary.stand_in.next(Role::Site, move |seen| {
        let value = sent(seen);
        let (head, tail) = value.split_at(value.len() / 2);
        let first = format!("{lead_bytes}{head}");
        let pause = std::time::Duration::from_millis(50);
        Reply::chunked(200, &[], &[first.as_bytes(), tail.as_bytes()], pause)
    });
    let cut = used().await.unwrap();
    assert_eq!(cut.end["code"], "response_withheld");
    assert!(!cut.body().is_empty());
    assert!(lead.as_bytes().starts_with(&cut.body()));

    // A redirect whose address carries the value, and the answers a node does not search: a
    // content coding, and a transfer coding it does not remove.
    canary.stand_in.next(Role::Site, move |seen| {
        let echoed = percent_encoded(sent(seen).as_bytes(), false, true);
        let location = format!("https://collector.example/?authorization={echoed}");
        Reply::with_body(302, &[("location", location.as_str())], b"")
    });
    withheld(
        used().await,
        "a redirect to an address that carries the value",
    );
    for (name, value) in [
        ("content-encoding", "gzip"),
        ("transfer-encoding", "gzip, chunked"),
    ] {
        canary.stand_in.next(Role::Site, move |_| {
            Reply::with_body(200, &[(name, value)], b"\x1f\x8b coded")
        });
        withheld(used().await, name);
    }

    // A redirect to another host comes back as it is, and the node follows none: it asked
    // its platform for the site alone. A cookie of the site is not handed on.
    canary.stand_in.next(Role::Site, |_| {
        let headers = [
            ("location", "https://collector.example/next"),
            ("set-cookie", "session=canary"),
        ];
        Reply::with_body(302, &headers, b"")
    });
    let redirect = used().await.unwrap();
    assert_eq!(redirect.status, 302);
    assert_eq!(
        redirect.header("location"),
        Some("https://collector.example/next")
    );
    assert_eq!(redirect.header("set-cookie"), None);

    // Every request of these uses reached the site, with the value in its header.
    let received = canary.site_requests();
    assert_eq!(received.len(), usize::from(uses));
    let carried = format!("Bearer {secret}");
    assert!(received
        .iter()
        .all(|request| request.header("authorization") == Some(carried.as_str())));

    // The value as one half of the credentials of HTTP Basic. The site sends back the
    // header it received, the base64 text of the credentials with the value in it, in a
    // header and in its body: neither is handed on.
    let basic_use = |nonce: u8| {
        let query = format!("use={nonce}");
        canary.secret_use_at("basic:user", "/v1/echo", &query, &secret, nonce)
    };
    let authorization = Canary::basic_with_the_placeholder();
    canary.stand_in.next(Role::Site, move |seen| {
        Reply::with_body(401, &[("x-request-echo", sent(seen).as_str())], b"{}")
    });
    let outcome = canary
        .vault_send_with(FORWARD, &basic_use(200), &authorization)
        .await;
    withheld(outcome, "the credentials of HTTP Basic in a header");
    let front = lead.clone();
    canary.stand_in.next(Role::Site, move |seen| {
        let body = format!("{front}{} and more", sent(seen));
        Reply::with_body(401, &[], body.as_bytes())
    });
    let cut = canary
        .vault_send_with(FORWARD, &basic_use(201), &authorization)
        .await
        .unwrap_or_else(|failure| panic!("{failure:?}"));
    assert_eq!(cut.end["code"], "response_withheld");
    assert!(lead.as_bytes().starts_with(&cut.body()));
    // Both requests reached the site, with the value in the credentials of their header.
    let received = canary.site_requests();
    assert_eq!(received.len(), usize::from(uses) + 2);
    let carried = Canary::basic(&secret);
    assert!(received[usize::from(uses)..]
        .iter()
        .all(|request| request.header("authorization") == Some(carried.as_str())));
    canary.verdict();
}

#[tokio::test]
async fn forward_asks_for_the_identity_coding_and_withholds_a_coded_response() {
    let canary = Canary::ready().await;
    let (_, connected) = canary.connect("google_workspace").await;
    let record = &connected["record"];
    let address = canary.stand_in.api_address("google_workspace");

    // Whatever the caller asks for, the node asks the provider for `identity`.
    let asked = [
        json!([]),
        json!([["Accept-Encoding", "gzip, deflate, br"]]),
        json!([
            ["accept-encoding", "gzip"],
            ["ACCEPT-ENCODING", "zstd"],
            ["Accept", "*/*"]
        ]),
    ];
    for (request, headers) in asked.into_iter().enumerate() {
        let numbered = format!("{address}?asked={request}");
        let forwarded = canary.forward(record, "GET", &numbered, headers, b"").await;
        assert_eq!(forwarded.map(|forwarded| forwarded.status), Ok(200));
        let sent = canary.requests().pop().unwrap();
        let is_coding = |(name, _): &&(String, String)| name == "accept-encoding";
        let codings: Vec<&str> = sent
            .headers
            .iter()
            .filter(is_coding)
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(codings, ["identity"], "request {request}");
    }

    // A body the node cannot read is withheld on its header alone. These bytes carry no
    // credential in any form.
    let coded: &[u8] = &[0x1f, 0x8b, 0x08, 0x00, 0xff, 0x00, 0x80, 0x7f];
    let answered: [&[&str]; 5] = [
        &["gzip"],
        &["br"],
        &["deflate"],
        &["gzip, identity"],
        &["identity", "gzip"],
    ];
    for (response, codings) in answered.into_iter().enumerate() {
        canary.stand_in.next(Role::Api, move |_| {
            let header = |coding: &&'static str| ("content-encoding", *coding);
            let headers: Vec<(&str, &str)> = codings.iter().map(header).collect();
            Reply::with_body(200, &headers, coded)
        });
        let numbered = format!("{address}?coded={response}");
        let case = format!("Content-Encoding: {codings:?}");
        let outcome = refused(canary.get(record, &numbered).await, &case);
        assert_withheld(&outcome, &case);
    }

    // The same holds for a transfer coding. A node sends no `TE` header, so `chunked` is the
    // one transfer coding it removes: under any other the body would leave still coded, and
    // without the header that says so.
    for (response, codings) in ["gzip, chunked", "gzip", "chunked, gzip", "identity", ""]
        .into_iter()
        .enumerate()
    {
        canary.stand_in.next(Role::Api, move |_| {
            let mut chunked = format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: {codings}\r\n\r\n{:x}\r\n",
                coded.len()
            )
            .into_bytes();
            chunked.extend_from_slice(coded);
            chunked.extend_from_slice(b"\r\n0\r\n\r\n");
            Reply::Raw(chunked)
        });
        let numbered = format!("{address}?transfer={response}");
        let case = format!("Transfer-Encoding: {codings:?}");
        let outcome = refused(canary.get(record, &numbered).await, &case);
        assert_withheld(&outcome, &case);
    }

    // The coding `identity` says that the body is not coded.
    canary.stand_in.next(Role::Api, |_| {
        Reply::with_body(200, &[("content-encoding", "identity")], b"as it is")
    });
    let numbered = format!("{address}?coded=identity");
    let forwarded = canary.get(record, &numbered).await.unwrap();
    assert_eq!(
        (forwarded.status, forwarded.body.as_slice()),
        (200, b"as it is".as_slice())
    );
    canary.verdict();
}

#[tokio::test]
async fn forward_returns_no_cookie_of_the_provider() {
    let canary = Canary::ready().await;
    let (_, connected) = canary.connect("google_workspace").await;
    let address = canary.stand_in.api_address("google_workspace");

    // A cookie is access to the provider that outlasts the call and that no entry records.
    let cookie = canary.secrets.text("cookie of the provider", &[]);
    canary.stand_in.next(Role::Api, move |_| {
        let response = format!(
            concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: application/json\r\n",
                "Set-Cookie: session={cookie}; Secure; HttpOnly\r\n",
                "set-cookie: second={cookie}\r\n",
                "Set-Cookie2: legacy={cookie}\r\n",
                "X-Kept: yes\r\n",
                "Content-Length: 2\r\n",
                "\r\n",
                "{{}}",
            ),
            cookie = cookie
        );
        Reply::Raw(response.into_bytes())
    });
    let forwarded = canary.get(&connected["record"], &address).await.unwrap();
    assert_eq!(
        (forwarded.status, forwarded.body.as_slice()),
        (200, b"{}".as_slice())
    );
    let names: Vec<&str> = forwarded
        .headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(names, ["content-type", "x-kept", "content-length"]);
    canary.verdict();
}
