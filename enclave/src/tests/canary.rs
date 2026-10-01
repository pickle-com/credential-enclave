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

use self::fixture::{at, field, node_keys, Canary, Role, LOG_STORE, NODES};
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
const PROVIDER_ERRORS: [&str; 38] = [
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

/// The public fields of every provider (egress-policy.md section 4): the leaves of the token
/// object by their paths, then the claims of the `id_token`. Nothing else of a token response
/// leaves a node.
const PUBLIC: [(&str, Leaves, Leaves); 7] = [
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

    /// Every byte string the scan searches for the bytes it was given: the bytes themselves
    /// and, again and again, what is under an encoding that wraps them: percent escapes, the
    /// strings and byte arrays of JSON, the two parts of a `forward` frame, and base64 or
    /// base64url text. Each layer names the encodings above it.
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
    use credential_enclave_protocol::encoding::{b64u, b64u_decode, to_json};
    use credential_enclave_protocol::keys::{record_key, Binding};
    use credential_enclave_protocol::record::Record;
    use credential_enclave_protocol::{limits, purpose};
    use hyper::body::Bytes;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256, Sha512};

    use super::scan::Scanner;
    use super::{id_token, public_leaves, set, EVENTS, PROVIDER_ERRORS};
    use crate::frame;
    use crate::providers::{endpoint, ClientKind, Definitions};
    use crate::testing::{
        Answer, App, Attested, Forwarded, Harness, Provider, Reply, Seen, LOG_BUCKET, LOG_HOST,
        LOG_REGION,
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
    }

    /// The name the place of the log store carries where a place names a provider.
    pub const LOG_STORE: &str = "the log store";

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

    /// The names of the two nodes of a fixture.
    pub const NODES: [&str; 2] = ["node", "peer node"];

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
        /// rule covers its exact paths and the paths under its prefixes, where a prefix that
        /// does not end with `/` ends at a segment boundary (enclave.md section 7).
        pub fn places(&self, server_name: &str, target: &str) -> Vec<Place> {
            let path = target.split('?').next().unwrap_or_default();
            // The objects of the log store: the keys of protocol.md 7.6.
            if server_name == LOG_HOST {
                return match target.starts_with("/v1/accounts/") {
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
                if rules.any(|rule| {
                    rule.exact.iter().any(|exact| exact == path) || rule.prefixes.iter().any(under)
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
                    let path = match (rule.exact.first(), rule.prefixes.first()) {
                        (Some(exact), _) => exact.clone(),
                        (None, Some(prefix)) if prefix.ends_with('/') => format!("{prefix}canary"),
                        (None, Some(prefix)) => prefix.clone(),
                        (None, None) => unreachable!("a rule has a path"),
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
    /// transfer, the app of one account and the provider stand-in.
    pub struct Canary {
        pub secrets: Arc<Secrets>,
        pub stand_in: Arc<StandIn>,
        pub app: App,
        provider: Provider,
        nodes: [Harness; 2],
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
            let app = App::new("canary-user", 0xc5);
            let user_key = app.keys.user_key_of(app.custody);
            secrets.add("user key", user_key.as_slice(), &[]);
            Canary {
                secrets,
                stand_in,
                app,
                provider,
                nodes,
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
            let answer = self.nodes[node].call(sent, path, body).await;
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

        /// `GET /v1/health` of one of the two nodes.
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
                entry: meta["entry"].clone(),
                body: body.to_vec(),
            })
        }

        /// A `forward` call with the method GET, without headers of the caller.
        pub async fn get(&self, record: &Value, address: &str) -> Result<Forwarded, (u16, Value)> {
            self.forward(record, "GET", address, json!([]), b"").await
        }

        /// The attestation response of one of the two nodes.
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

        /// Gives the first node the operator configuration.
        pub async fn configure(&self) {
            let (status, response) = self.post("/v1/config", self.operator_config()).await;
            assert_eq!(status, 200, "{response}");
        }

        /// Names the log store of the tests in the configuration of both nodes. From then on
        /// a node acts only after the stand-in confirmed the entry of the act.
        pub async fn configure_log_store(&self) {
            let log_store = json!({"bucket": LOG_BUCKET, "region": LOG_REGION});
            let mut first = self.operator_config();
            first["log_store"] = log_store.clone();
            let second = json!({"providers": {}, "log_store": log_store});
            for (node, config) in [first, second].into_iter().enumerate() {
                let (status, response) = self.post_on(node, "/v1/config", config).await;
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

        /// The event of an entry that one of the two nodes created for the account: the node
        /// signature verifies and the log key of the account opens it. Its kind is a kind
        /// that this release writes.
        pub fn event(&self, node: usize, entry: &Value) -> Value {
            let event = self.app.event(&self.nodes[node], entry);
            let kind = event["t"].as_str().unwrap_or_default();
            assert!(EVENTS.contains(&kind), "an event of the kind {kind:?}");
            event
        }

        /// Fetches the entries of the account that wait on the first node, acknowledges them
        /// and returns the kinds of their events and the `seq` of the end of the chain.
        pub async fn drain_log(&self) -> (Vec<String>, u64) {
            let user_id = &self.app.user_id;
            let waiting = json!({"user_id": user_id, "after_seq": 0});
            let (status, listed) = self.post("/v1/log/entries", waiting).await;
            assert_eq!(status, 200, "{listed}");
            let entries = listed["entries"].as_array().unwrap().iter();
            let kind = |entry| self.event(0, entry)["t"].as_str().unwrap().to_string();
            let kinds = entries.map(kind).collect();
            let seq = listed["head"]["seq"].as_u64().unwrap();
            let stored = json!({"user_id": user_id, "seq": seq});
            let (status, acknowledged) = self.post("/v1/log/ack", stored).await;
            assert_eq!((status, &acknowledged["unacked"]), (200, &json!(0)));
            (kinds, seq)
        }

        /// The requests the stand-in received so far.
        pub fn seen(&self) -> Vec<Seen> {
            self.provider.seen()
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
                let call_of_node =
                    format!("{} {} of the {}", call.method, call.path, NODES[call.node]);
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

        /// The verdict on C2: every connection a node asked its platform for went to port 443
        /// of a host of the definitions or of the log store, and carried one request that the
        /// stand-in received. Every request went to an address that a definition names or to
        /// an object of the log store, under the TLS server name of its `Host` header, and a
        /// secret occurs only in requests to the places within its reach. Returns the secrets
        /// that were seen, each with the place of the request that carried it.
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
            let connections: Vec<(String, u16)> = connections.collect();
            for (host, port) in &connections {
                // Whoever carries the bytes of a node sees the destination of a connection.
                if *port != 443 || !(hosts.contains(host) || host == LOG_HOST) {
                    leaks.push(format!("{host}:{port} is the host of no definition"));
                }
                for (marker, form) in scanner.find(host.as_bytes()) {
                    leaks.push(format!(
                        "the host name {host} carried the {marker} ({form})"
                    ));
                }
            }
            if connections.len() != self.seen().len() {
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
}

impl Vault {
    fn plant(canary: &Canary) -> Vault {
        let password = canary.secrets.text("vault password", &[]);
        let totp_seed = canary.secrets.totp_seed("TOTP seed");
        let card_number = canary.secrets.digits("card number", 19);
        let card_cvc = canary.secrets.text("card verification code", &[]);
        let card = json!({"number": card_number, "cvc": card_cvc});
        Vault {
            password_record: canary.record("vault_password", "vault", &json!({"value": password})),
            totp_record: canary.record("vault_totp", "vault", &json!({"value": totp_seed})),
            card_record: canary.record("vault_card", "vault", &card),
            password,
            totp_seed,
            card_number,
            card_cvc,
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
    let empty_nonce = json!({"user_id": user, "nonce": ""});
    let outcome = canary.post("/v1/status", empty_nonce).await;
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

    // The log store of both nodes, and the credentials for it: values of another form are
    // refused. The session token reaches the log store and nothing else, the secret access
    // key reaches nothing, and neither comes back, in this response or in a later one.
    canary.configure_log_store().await;
    let credentials = |access_key_id: &str| {
        let (secrets, store) = (&canary.secrets, [at(Role::LogStore, LOG_STORE)]);
        json!({
            "access_key_id": access_key_id,
            "secret_access_key": secrets.text("secret access key for the log store", &[]),
            "session_token": secrets.text("session token for the log store", &store),
            "expires_ms": 4_102_444_800_000u64,
        })
    };
    let outcome = canary
        .post("/v1/log-store/credentials", credentials("no access key"))
        .await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    let stored = json!({"credentials_expires_ms": 4_102_444_800_000u64});
    for node in 0..NODES.len() {
        let body = credentials("ASIACANARY");
        let outcome = canary
            .post_on(node, "/v1/log-store/credentials", body)
            .await;
        assert_eq!(outcome, (200, stored.clone()));
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
        canary.drain_log().await;
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

    release_the_vault(&canary, 0, &vault).await;
    let no_https = json!({
        "user_id": user, "record": vault.password_record, "field": "password",
        "origin": "http://shop.example", "context": "canary",
    });
    let outcome = canary.post("/v1/release", no_https).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));

    // The log of the account.
    for path in ["/v1/log/entries", "/v1/log/ack"] {
        let outcome = canary.post(path, json!({"user_id": user})).await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{path}");
    }
    canary.drain_log().await;

    // The delegation moves to the second node and that node uses it. A node hands nothing to
    // itself and takes no transfer that was sealed for another node.
    let (this, peer) = (canary.attestation(0).await, canary.attestation(1).await);
    let export_to = |peer: &Value| json!({"peer": peer, "after": "", "limit": 1000});
    let import_from = |peer: &Value, envelope: &Value| json!({"peer": peer, "envelope": envelope});
    let outcome = canary.post("/v1/peer/export", export_to(&this)).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    let (status, exported) = canary.post("/v1/peer/export", export_to(&peer)).await;
    assert_eq!(status, 200, "{exported}");
    let (envelope, entry) = (&exported["envelope"], &exported["entries"][0]);
    assert_eq!(canary.event(0, entry)["t"], "grant_transferred_out");
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
    assert_eq!(
        canary.event(1, &imported["entries"][0])["t"],
        "grant_transferred_in"
    );
    release_the_vault(&canary, 1, &vault).await;
    let (status, back) = canary.post_on(1, "/v1/peer/export", export_to(&this)).await;
    assert_eq!(status, 200, "{back}");
    let returned = import_from(&peer, &back["envelope"]);
    let (status, known) = canary.post("/v1/peer/import", returned.clone()).await;
    assert_eq!((status, &known["imported"]), (200, &json!(0)), "{known}");

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
        }
    };

    // The account withdraws its delegation.
    let (status, revoked) = canary.send(&canary.revoke_envelope().await).await;
    assert_eq!((status, &canary.reply(&revoked)["ok"]), (200, &json!(true)));
    refusals((409, "grant_revoked"), until_revoked).await;
    canary.drain_log().await;

    // The orderly shutdown. Final heads exist only after `close`, and a closing node takes
    // no command and no transfer.
    let page = json!({"cursor": "", "limit": 1000});
    let outcome = canary.post("/v1/close/heads", page.clone()).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    assert_eq!(canary.post("/v1/close", json!({})).await.0, 200);
    let wrong_method = canary.probe("GET", "/v1/close", json!({})).await;
    assert_eq!(code(&wrong_method), (405, "invalid_request"));
    refusals((503, "closing"), until_closed).await;
    let outcome = canary.send(&canary.grant_envelope().await).await;
    assert_eq!(code(&outcome), (503, "closing"));
    let outcome = canary.post("/v1/peer/import", returned).await;
    assert_eq!(code(&outcome), (503, "closing"));
    let (status, heads) = canary.post("/v1/close/heads", page).await;
    assert_eq!(
        (status, heads["heads"].as_array().map(Vec::len)),
        (200, Some(1))
    );
    canary.health(0).await;
    canary
}

#[tokio::test]
async fn the_private_keys_of_a_node_are_the_planted_markers() {
    let canary = Canary::start().await;
    for (node, name) in NODES.iter().enumerate() {
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
async fn the_walk_calls_every_route_in_a_success_case_and_in_a_failure_case() {
    let canary = walk().await;
    let set_of = |routes: &[(&str, &str)]| -> BTreeSet<(String, String)> {
        let owned = |(method, path): &(&str, &str)| (method.to_string(), path.to_string());
        routes.iter().map(owned).collect()
    };
    let routes = routes();
    assert_eq!(routes.len(), 19);
    assert_eq!(canary.routes_called(|_| true), routes);
    assert_eq!(canary.routes_called(|status| status == 200), routes);
    let without_a_failure = set_of(&ROUTES_WITHOUT_A_FAILURE);
    let failing: BTreeSet<_> = routes.difference(&without_a_failure).cloned().collect();
    assert_eq!(canary.routes_called(|status| status != 200), failing);
}

#[tokio::test]
async fn no_marker_appears_in_a_response_of_any_route() {
    walk().await.verdict_c1();
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
    // `release` needs no operator configuration.
    let canary = Canary::start().await;
    canary.grant().await;
    let vault = Vault::plant(&canary);
    release_the_vault(&canary, 0, &vault).await;

    // One entry per value that left, and none for a refusal.
    let (kinds, _) = canary.drain_log().await;
    let released = ["secret_released"; 3];
    assert_eq!(kinds[..1], ["grant_accepted"]);
    assert_eq!(kinds[1..4], released);
    assert_eq!(kinds[4..], ["totp_issued"]);
    assert!(canary.seen().is_empty(), "no provider received a request");
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
        assert_eq!(keys, ["revoked", "entry"], "{status}");
        assert_eq!(outcome["revoked"], revoked, "{status}");
    }
    canary.verdict();
}

#[tokio::test]
async fn a_redirect_to_another_host_is_returned_and_not_followed() {
    let canary = Canary::ready().await;
    let (_, connected) = canary.connect("google_workspace").await;
    let address = canary.stand_in.api_address("google_workspace");
    let exchanged = canary.seen().len();

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
    assert_eq!(canary.seen().len(), exchanged + statuses.len());
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
    assert!(canary.seen().is_empty(), "no provider received a request");
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
        canary.drain_log().await;
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
        canary.drain_log().await;
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
    let (_, seq) = canary.drain_log().await;

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
    assert_eq!(canary.drain_log().await, (Vec::new(), seq));
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
/// byte. Each of these is the percent-encoding of the same value.
const ECHOES: [(&str, Echo); 14] = [
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
    assert_eq!(canary.seen().len(), 1 + requests);
    let (kinds, _) = canary.drain_log().await;
    let recorded = kinds.iter().filter(|kind| *kind == "provider_request");
    assert_eq!(recorded.count(), requests);
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
        let sent = canary.seen().pop().unwrap();
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
