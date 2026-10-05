//! Provider definitions (enclave.md section 6) and the address check of `forward`
//! (enclave.md section 7).
//!
//! The definitions are compiled into the binary, so they are part of the measurement of a
//! release. The operator configuration can change client identifiers and callback addresses
//! only: the addresses a credential may be sent to, and the token addresses, are fixed here.

use std::collections::{BTreeMap, HashSet};

use credential_enclave_protocol::{is_valid_name, limits, ProtocolError};
use serde::Deserialize;

use crate::egress::is_token;

/// The definitions compiled into the binary.
const EMBEDDED: &str = include_str!("definitions.json");

/// Longest address `forward` accepts, in bytes.
const ADDRESS_LIMIT_BYTES: usize = 8192;

// An event `provider_request` holds this many bytes of a path and of a query, so the entry of
// a request carries both whole (protocol.md 7.2).
const _: () = assert!(ADDRESS_LIMIT_BYTES <= limits::EVENT_ADDRESS_BYTES);

/// How many times the comparison with the denied paths of a rule decodes the percent escapes
/// of a path: it reads a path that was encoded up to three times.
const DENIED_DECODINGS: usize = 3;

/// Where the client identifier of a provider comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientKind {
    /// The operator configuration holds the client identifier and secret.
    Static,
    /// A public client without a secret: the caller passes the `client_id`.
    Dynamic,
}

/// PKCE of the authorization request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub enum Pkce {
    S256,
    #[serde(rename = "none")]
    None,
}

/// How a client authenticates to the token address or the revocation address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientAuth {
    /// `client_id` and `client_secret` in the body.
    Body,
    /// HTTP Basic.
    Basic,
    /// `client_id` only, in the body.
    None,
}

/// The body format of a token request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BodyFormat {
    Form,
    Json,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorize {
    pub url: String,
    /// `[name, value]` pairs that are always part of the authorization address.
    pub fixed: Vec<(String, String)>,
    /// Parameter names a caller may choose.
    pub allowed: Vec<String>,
    /// Parameter name that carries the operator's `publishable_key`. Empty when unused.
    pub key_param: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    pub url: String,
    pub client_auth: ClientAuth,
    pub body: BodyFormat,
    /// `[name, value]` header pairs of a token request.
    pub headers: Vec<(String, String)>,
    /// `publishable_key` adds `Authorization: Bearer {publishable_key}`. Empty when unused.
    pub bearer: String,
    /// `[name, value]` pairs that are always part of an exchange and a refresh body.
    pub fixed: Vec<(String, String)>,
    /// When not empty, a 200 response whose field of this name is `false` is a failure.
    pub ok_field: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revoke {
    pub url: String,
    pub client_auth: ClientAuth,
    pub bearer: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inject {
    pub header: String,
    pub prefix: String,
    /// Dot-joined key paths into the token object. The first path that exists is used.
    pub paths: Vec<String>,
}

/// The type of a public field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    /// A JSON string of at most `max` bytes.
    String,
    /// A JSON integer, or a string of 1 to 20 ASCII digits.
    Integer,
    /// A JSON boolean.
    Boolean,
}

/// One value of a token response that leaves the node in the clear (rule E4 of the egress
/// policy): the path of a leaf, its type and, for a string, its longest length in bytes.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicField {
    /// Object keys joined by `.`. For a claim of the `id_token` it is the claim name.
    pub path: String,
    #[serde(rename = "type")]
    pub kind: FieldType,
    /// Longest value of a `string` field, in bytes of UTF-8. Absent for the other types.
    #[serde(default)]
    pub max: Option<usize>,
}

/// The keys of a token object that hold a token. A definition cannot list them as public.
pub const TOKEN_KEYS: [&str; 3] = ["access_token", "refresh_token", "id_token"];

/// The paths of one host a credential may be sent to.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiRule {
    pub host: String,
    pub prefixes: Vec<String>,
    pub exact: Vec<String>,
    /// True when a path of this host may carry an encoded `/` (`%2F`, `%2f`). The host of
    /// such a rule takes a value with a `/` in it as one path segment.
    #[serde(default)]
    pub encoded_slash: bool,
    /// Paths under a prefix of this rule that are refused all the same: an address that
    /// carries other requests in its body, which the entry of the call would not describe.
    #[serde(default)]
    pub denied: Vec<String>,
}

impl ApiRule {
    /// True when `path` equals an exact path or lies under a prefix.
    pub fn allows(&self, path: &str) -> bool {
        self.exact.iter().any(|exact| exact == path) || self.under_prefix(path)
    }

    /// True when `path` lies under a prefix. A prefix that does not end with `/` matches at a
    /// segment boundary only: the path equals the prefix or continues with `/`.
    fn under_prefix(&self, path: &str) -> bool {
        self.prefixes.iter().any(|prefix| {
            path.starts_with(prefix.as_str())
                && (prefix.ends_with('/')
                    || path.len() == prefix.len()
                    || path.as_bytes()[prefix.len()] == b'/')
        })
    }

    /// True when a path is a denied path of this rule or continues one with `/`. `decoded` is
    /// the path with its percent escapes decoded once.
    ///
    /// A list of refusals holds only when no other spelling of a denied path passes. So the
    /// comparison does not read the path as it was received. It reads the path with its
    /// escapes decoded once, twice and three times, and each of these with every segment cut
    /// at its first `;` and with its letters in lower case ([`lenient_path`]): the spellings
    /// that a server may take for the same address.
    fn denies(&self, decoded: &[u8]) -> bool {
        if self.denied.is_empty() {
            return false;
        }
        let mut reading = decoded.to_vec();
        for _ in 0..DENIED_DECODINGS {
            let lenient = lenient_path(&reading);
            let denied = self.denied.iter().any(|denied| {
                lenient.starts_with(denied.as_bytes())
                    && (lenient.len() == denied.len() || lenient[denied.len()] == b'/')
            });
            if denied {
                return true;
            }
            reading = decode_escapes(&reading);
        }
        false
    }
}

/// One provider definition (enclave.md 6.1).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    pub client: ClientKind,
    pub authorize: Authorize,
    pub scope_param: String,
    pub scope_delimiter: String,
    /// Optional list of scope values a caller may request.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    pub pkce: Pkce,
    pub token: Token,
    /// When not empty, the access token, the refresh token and `expires_in` are inside the
    /// object of this name in a token response.
    pub token_container: String,
    pub revoke: Option<Revoke>,
    pub inject: Inject,
    /// The leaves of a token response that leave the node as public fields.
    pub public: Vec<PublicField>,
    /// The claims of the `id_token` that leave the node as public fields.
    pub id_token_claims: Vec<PublicField>,
    /// Every address a credential of this provider may be sent to.
    pub api: Vec<ApiRule>,
    /// The token address and the revocation address as destinations. They are set when the
    /// definitions document was validated ([`Definitions`]): a definition that did not come
    /// from there has none, and no token request can be made for it.
    #[serde(skip)]
    token_destination: Option<Destination>,
    #[serde(skip)]
    revoke_destination: Option<Destination>,
}

/// The host and the request target of a request to a provider.
///
/// A request that carries a secret is addressed to a `Destination` and to nothing else (sink
/// K3 of the egress policy), and only this module creates one, from an address of a validated
/// provider definition: an address that passed the check of `forward`
/// ([`Target::destination`]), the token address ([`Definition::token_destination`]) and the
/// revocation address ([`Definition::revoke_destination`]). No other code of the node can
/// name the host a credential is sent to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    host: String,
    request_target: String,
}

impl Destination {
    /// The provider host: the TLS server name and the `Host` header.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The request target in origin form: the path, with `?` and the query when present.
    pub fn request_target(&self) -> &str {
        &self.request_target
    }

    fn of(endpoint: Endpoint) -> Destination {
        Destination {
            host: endpoint.host,
            request_target: endpoint.path,
        }
    }

    /// A destination for the tests of the TLS client.
    #[cfg(test)]
    pub fn for_test(host: &str, request_target: &str) -> Destination {
        Destination {
            host: host.to_string(),
            request_target: request_target.to_string(),
        }
    }
}

/// An address that passed the check, split the way it is sent. Only
/// [`Definition::check_address`] creates one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// The host, lowercase.
    host: String,
    /// The path exactly as received.
    path: String,
    /// The query exactly as received, without the `?`. Empty when there is none.
    query: String,
    /// The request target: the path, and `?` with the query when the address has a `?`.
    request_target: String,
}

impl Target {
    /// The host, lowercase.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The path exactly as received.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The query exactly as received, without the `?`. Empty when there is none.
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Where the request of `forward` goes: the checked host and the request target as
    /// received.
    pub fn destination(&self) -> Destination {
        Destination {
            host: self.host.clone(),
            request_target: self.request_target.clone(),
        }
    }
}

/// The host and path of a definition address (authorization, token, revocation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub path: String,
}

/// Splits an `https://host/path` address of a definition. Such an address has no user
/// information, port, query or fragment.
pub fn endpoint(address: &str) -> Result<Endpoint, String> {
    let parsed = url::Url::parse(address).map_err(|_| format!("{address}: not an address"))?;
    let host = match parsed.host() {
        Some(url::Host::Domain(host)) => host.to_string(),
        _ => return Err(format!("{address}: the host is not a DNS name")),
    };
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !is_host_name(&host)
        || format!("https://{host}{}", parsed.path()) != address
    {
        return Err(format!("{address}: not a plain https address"));
    }
    Ok(Endpoint {
        host,
        path: parsed.path().to_string(),
    })
}

/// True for a lowercase DNS name without a trailing dot that is not an IP literal.
fn is_host_name(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
        })
        && !is_ip_literal(host)
}

/// True when a host would be read as an IPv4 address: its last label is a number (decimal, or
/// hexadecimal with a `0x` prefix). IPv6 literals never reach this function: `[` is rejected
/// before.
fn is_ip_literal(host: &str) -> bool {
    let last = host.rsplit('.').next().unwrap_or(host);
    if last.is_empty() {
        return false;
    }
    if last.bytes().all(|byte| byte.is_ascii_digit()) {
        return true;
    }
    match last.strip_prefix("0x") {
        Some(hex) => hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        None => false,
    }
}

/// True when every `%` of `text` starts a two-digit hexadecimal escape.
fn has_valid_escapes(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let valid = bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit);
            if !valid {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

/// The bytes of a path with every percent escape decoded once.
///
/// This is the path as a server reads it after decoding: a dot may be written `%2e`, and on a
/// host whose rule takes an encoded `/` a segment boundary may be written `%2F`.
fn decode_escapes(bytes: &[u8]) -> Vec<u8> {
    let hex = |byte: Option<&u8>| byte.and_then(|byte| char::from(*byte).to_digit(16));
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let escape = match (
            bytes[index],
            hex(bytes.get(index + 1)),
            hex(bytes.get(index + 2)),
        ) {
            (b'%', Some(high), Some(low)) => u8::try_from(high * 16 + low).ok(),
            _ => None,
        };
        match escape {
            Some(byte) => {
                decoded.push(byte);
                index += 3;
            }
            None => {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
    }
    decoded
}

/// True when the path holds `%25` in front of `2e`, `2f` or `5c`, in either case of the
/// letters: the escape of `.`, of `/` or of `\` with its `%` encoded once more. A server that
/// decodes a path twice reads a dot or a separator there.
fn has_twice_encoded_separator(path: &str) -> bool {
    path.as_bytes().windows(5).any(|window| {
        window[..3] == *b"%25"
            && matches!(
                (window[3], window[4].to_ascii_lowercase()),
                (b'2', b'e') | (b'2', b'f') | (b'5', b'c')
            )
    })
}

/// A segment of a decoded path up to its first `;`. What follows a `;` is a path parameter
/// to a server that takes them, and such a server reads the segment without it.
fn without_parameters(segment: &[u8]) -> &[u8] {
    segment
        .split(|byte| *byte == b';')
        .next()
        .unwrap_or(segment)
}

/// True when the decoded path has a segment that is `.` or `..` up to its first `;`: `..`,
/// `..;` and `..;x` alike. A path whose decoded form has no such segment stays below the
/// prefix it was compared with, also on a server that leaves path parameters out.
fn has_dot_segment(decoded: &[u8]) -> bool {
    decoded
        .split(|byte| *byte == b'/')
        .map(without_parameters)
        .any(|segment| segment == b"." || segment == b"..")
}

/// A decoded path in the form the denied paths of a rule are compared with: every segment ends
/// at its first `;` (what follows it is a path parameter), and the ASCII letters are in lower
/// case.
fn lenient_path(decoded: &[u8]) -> Vec<u8> {
    let mut lenient = Vec::with_capacity(decoded.len());
    for (index, segment) in decoded.split(|byte| *byte == b'/').enumerate() {
        if index > 0 {
            lenient.push(b'/');
        }
        lenient.extend(
            without_parameters(segment)
                .iter()
                .map(u8::to_ascii_lowercase),
        );
    }
    lenient
}

impl Definition {
    /// The address check of enclave.md section 7. Every violation is `not_allowed`.
    ///
    /// The check reads the address as the raw string it received: nothing is normalized, and
    /// the path and query are later sent exactly as they were checked.
    pub fn check_address(&self, address: &str) -> Result<Target, ProtocolError> {
        const DENIED: ProtocolError = ProtocolError::NotAllowed;
        if address.len() > ADDRESS_LIMIT_BYTES
            || !address.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(DENIED);
        }
        let rest = address.strip_prefix("https://").ok_or(DENIED)?;
        if rest.contains('#') {
            return Err(DENIED);
        }
        let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(authority_end);
        if authority.contains(['@', '[', ']', '\\']) {
            return Err(DENIED);
        }
        let raw_host = match authority.rsplit_once(':') {
            Some((host, "443")) => host,
            Some(_) => return Err(DENIED),
            None => authority,
        };
        if raw_host.contains(':') {
            return Err(DENIED);
        }
        let host = raw_host.to_ascii_lowercase();
        if !is_host_name(&host) {
            return Err(DENIED);
        }
        let (path, query, has_query) = match tail.split_once('?') {
            Some((path, query)) => (path, query, true),
            None => (tail, "", false),
        };
        if !path.starts_with('/') {
            return Err(DENIED);
        }
        let rule = self
            .api
            .iter()
            .find(|rule| rule.host == host)
            .ok_or(DENIED)?;
        // An encoded `/` is refused unless the rule of the host takes it. The prefix comparison
        // below reads the path as received either way: an encoded `/` is not a segment
        // boundary there.
        let encoded_slash = path.contains("%2f") || path.contains("%2F");
        if (encoded_slash && !rule.encoded_slash)
            || ["%5c", "%5C", "\\", "//"]
                .iter()
                .any(|pattern| path.contains(pattern))
            || !has_valid_escapes(path)
            || has_twice_encoded_separator(path)
        {
            return Err(DENIED);
        }
        let decoded = decode_escapes(path.as_bytes());
        if has_dot_segment(&decoded) {
            return Err(DENIED);
        }
        if !rule.allows(path) || rule.denies(&decoded) {
            return Err(DENIED);
        }
        // A second reading with a WHATWG URL parser must see the same host, port and path.
        // An address that two parsers read differently is not sent anywhere.
        let parsed = url::Url::parse(address).map_err(|_| DENIED)?;
        if parsed.scheme() != "https"
            || parsed.host_str() != Some(host.as_str())
            || parsed.port_or_known_default() != Some(443)
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != path
        {
            return Err(DENIED);
        }
        let mut request_target = path.to_string();
        if has_query {
            request_target.push('?');
            request_target.push_str(query);
        }
        Ok(Target {
            host,
            path: path.to_string(),
            query: query.to_string(),
            request_target,
        })
    }

    /// Where a token request goes: the token address of the definition.
    pub fn token_destination(&self) -> Result<Destination, ProtocolError> {
        self.token_destination
            .clone()
            .ok_or(ProtocolError::NotAllowed)
    }

    /// Where a revocation request goes: the revocation address of the definition, when it has
    /// one.
    pub fn revoke_destination(&self) -> Option<Destination> {
        self.revoke_destination.clone()
    }

    /// True when the address `host` + `path` is one a credential may be sent to.
    pub fn allows(&self, host: &str, path: &str) -> bool {
        self.api
            .iter()
            .any(|rule| rule.host == host && rule.allows(path))
    }

    fn validate(&self, name: &str) -> Result<(), String> {
        let fail = |what: &str| Err(format!("{name}: {what}"));
        if !is_valid_name(name) {
            return fail("the provider name is not a valid name");
        }
        let authorize = endpoint(&self.authorize.url)?;
        let token = endpoint(&self.token.url)?;
        if authorize.path.is_empty() || token.path.is_empty() {
            return fail("an address has no path");
        }
        // The token address and the revocation address return or accept tokens: forward must
        // not be able to reach them (enclave.md section 7).
        if self.allows(&token.host, &token.path) {
            return fail("the token address is reachable by forward");
        }
        if let Some(revoke) = &self.revoke {
            let address = endpoint(&revoke.url)?;
            if self.allows(&address.host, &address.path) {
                return fail("the revocation address is reachable by forward");
            }
            if !matches!(revoke.bearer.as_str(), "" | "publishable_key") {
                return fail("unknown revoke.bearer");
            }
        }
        if !matches!(self.token.bearer.as_str(), "" | "publishable_key") {
            return fail("unknown token.bearer");
        }
        let pairs = self.authorize.fixed.iter().chain(self.token.fixed.iter());
        for (key, _) in pairs {
            if key.is_empty() {
                return fail("an empty fixed parameter name");
            }
        }
        let reserved = [
            "response_type",
            "client_id",
            "redirect_uri",
            "state",
            "code_challenge",
            "code_challenge_method",
        ];
        let fixed: HashSet<&str> = self
            .authorize
            .fixed
            .iter()
            .map(|(key, _)| key.as_str())
            .collect();
        for allowed in &self.authorize.allowed {
            if allowed.is_empty()
                || reserved.contains(&allowed.as_str())
                || fixed.contains(allowed.as_str())
                || *allowed == self.authorize.key_param
            {
                return fail("an allowed parameter collides with a parameter the node sets");
            }
        }
        if !self.scope_param.is_empty() && !self.authorize.allowed.contains(&self.scope_param) {
            return fail("scope_param is not an allowed parameter");
        }
        if self.scopes.is_some() && (self.scope_param.is_empty() || self.scope_delimiter.is_empty())
        {
            return fail("scopes needs scope_param and scope_delimiter");
        }
        for (header, value) in &self.token.headers {
            if !is_token(header) || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
                return fail("an invalid token header");
            }
        }
        if !is_token(&self.inject.header) || self.inject.paths.is_empty() {
            return fail("an invalid inject rule");
        }
        // The public fields are leaves with a type and a limit (rule E4 of the egress policy).
        // A path that names a token, a path the node injects as a credential, a path listed
        // twice and a path that is the parent of another one (an object) are refused.
        for (fields, nested) in [(&self.public, true), (&self.id_token_claims, false)] {
            let mut seen = HashSet::new();
            for field in fields {
                let segments: Vec<&str> = if nested {
                    field.path.split('.').collect()
                } else {
                    vec![field.path.as_str()]
                };
                let valid_limit = match field.kind {
                    FieldType::String => field.max.is_some_and(|max| max >= 1),
                    FieldType::Integer | FieldType::Boolean => field.max.is_none(),
                };
                if segments.iter().any(|segment| segment.is_empty())
                    || !valid_limit
                    || !seen.insert(field.path.as_str())
                    || segments
                        .last()
                        .is_some_and(|last| TOKEN_KEYS.contains(last))
                    || self.inject.paths.contains(&field.path)
                {
                    return fail("an invalid public field");
                }
            }
            for field in fields {
                let parent = format!("{}.", field.path);
                if nested && fields.iter().any(|other| other.path.starts_with(&parent)) {
                    return fail("a public field is the parent of another public field");
                }
            }
        }
        if self.api.is_empty() {
            return fail("no api rule");
        }
        let mut hosts = HashSet::new();
        for rule in &self.api {
            if !is_host_name(&rule.host) || !hosts.insert(rule.host.as_str()) {
                return fail("an invalid or repeated api host");
            }
            if rule.prefixes.is_empty() && rule.exact.is_empty() {
                return fail("an api host without paths");
            }
            let paths = rule.prefixes.iter().chain(&rule.exact).chain(&rule.denied);
            for path in paths {
                if !path.starts_with('/') || path.contains("//") || path.contains(['?', '#', '%']) {
                    return fail("an invalid api path");
                }
            }
            // A denied path takes something away from a prefix of the same rule, and it is
            // written in the form it is compared in: lower case, without a path parameter.
            for denied in &rule.denied {
                if !rule.under_prefix(denied)
                    || denied.contains(';')
                    || denied.bytes().any(|byte| byte.is_ascii_uppercase())
                {
                    return fail("an invalid denied path");
                }
            }
        }
        Ok(())
    }
}

/// The provider definitions of a node.
#[derive(Clone, Debug)]
pub struct Definitions {
    providers: BTreeMap<String, Definition>,
}

impl Definitions {
    /// The definitions compiled into the binary.
    ///
    /// # Panics
    ///
    /// Panics when the embedded file is invalid. A test of this module parses the embedded
    /// file, so a release build never carries an invalid one.
    pub fn embedded() -> Definitions {
        Definitions::parse(EMBEDDED).expect("the embedded provider definitions are valid")
    }

    /// Parses and validates a definitions document. The node program calls it for the document
    /// compiled into the binary only.
    fn parse(text: &str) -> Result<Definitions, String> {
        let mut providers: BTreeMap<String, Definition> =
            serde_json::from_str(text).map_err(|error| error.to_string())?;
        for (name, definition) in &mut providers {
            definition.validate(name)?;
            definition.token_destination = Some(Destination::of(endpoint(&definition.token.url)?));
            definition.revoke_destination = match &definition.revoke {
                Some(revoke) => Some(Destination::of(endpoint(&revoke.url)?)),
                None => None,
            };
        }
        Ok(Definitions { providers })
    }

    /// The definition of a provider.
    pub fn get(&self, provider: &str) -> Option<&Definition> {
        self.providers.get(provider)
    }

    /// The provider names, in lexical order.
    #[cfg(test)]
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.providers.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn embedded() -> Definitions {
        Definitions::embedded()
    }

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    /// One row of the table of enclave.md 6.2.
    struct Row {
        name: &'static str,
        client: ClientKind,
        authorize_url: &'static str,
        authorize_fixed: &'static [(&'static str, &'static str)],
        allowed: &'static [&'static str],
        key_param: &'static str,
        scope_param: &'static str,
        scope_delimiter: &'static str,
        pkce: Pkce,
        token_url: &'static str,
        client_auth: ClientAuth,
        body: BodyFormat,
        token_headers: &'static [(&'static str, &'static str)],
        token_bearer: &'static str,
        token_fixed: &'static [(&'static str, &'static str)],
        ok_field: &'static str,
        token_container: &'static str,
        revoke: Option<(&'static str, ClientAuth, &'static str)>,
        inject_paths: &'static [&'static str],
        public: &'static [Leaf],
        id_token_claims: &'static [Leaf],
    }

    /// A public field of the table: its path, its type and its byte limit.
    type Leaf = (&'static str, FieldType, Option<usize>);

    const fn text(path: &'static str, max: usize) -> Leaf {
        (path, FieldType::String, Some(max))
    }

    const fn integer(path: &'static str) -> Leaf {
        (path, FieldType::Integer, None)
    }

    const fn boolean(path: &'static str) -> Leaf {
        (path, FieldType::Boolean, None)
    }

    const COMMON: &[Leaf] = &[
        text("scope", 8192),
        integer("expires_in"),
        text("token_type", 32),
    ];

    fn leaves(fields: &[PublicField]) -> Vec<(String, FieldType, Option<usize>)> {
        fields
            .iter()
            .map(|field| (field.path.clone(), field.kind, field.max))
            .collect()
    }

    fn listed(row: &[Leaf]) -> Vec<(String, FieldType, Option<usize>)> {
        row.iter()
            .map(|(path, kind, max)| (path.to_string(), *kind, *max))
            .collect()
    }

    const ROWS: [Row; 8] = [
        Row {
            name: "google_workspace",
            client: ClientKind::Static,
            authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
            authorize_fixed: &[],
            allowed: &[
                "scope",
                "access_type",
                "prompt",
                "include_granted_scopes",
                "login_hint",
            ],
            key_param: "",
            scope_param: "scope",
            scope_delimiter: " ",
            pkce: Pkce::S256,
            token_url: "https://oauth2.googleapis.com/token",
            client_auth: ClientAuth::Body,
            body: BodyFormat::Form,
            token_headers: &[],
            token_bearer: "",
            token_fixed: &[],
            ok_field: "",
            token_container: "",
            revoke: Some(("https://oauth2.googleapis.com/revoke", ClientAuth::None, "")),
            inject_paths: &["access_token"],
            public: COMMON,
            id_token_claims: &[
                text("sub", 255),
                text("email", 320),
                boolean("email_verified"),
                text("hd", 255),
                text("name", 256),
                text("picture", 2048),
            ],
        },
        Row {
            name: "microsoft",
            client: ClientKind::Static,
            authorize_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            authorize_fixed: &[],
            allowed: &["scope", "prompt", "login_hint"],
            key_param: "",
            scope_param: "scope",
            scope_delimiter: " ",
            pkce: Pkce::S256,
            token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            client_auth: ClientAuth::Body,
            body: BodyFormat::Form,
            token_headers: &[],
            token_bearer: "",
            token_fixed: &[],
            ok_field: "",
            token_container: "",
            revoke: None,
            inject_paths: &["access_token"],
            public: &[
                text("scope", 8192),
                integer("expires_in"),
                integer("ext_expires_in"),
                text("token_type", 32),
            ],
            id_token_claims: &[
                text("tid", 64),
                text("oid", 64),
                text("preferred_username", 320),
            ],
        },
        Row {
            name: "slack",
            client: ClientKind::Static,
            authorize_url: "https://slack.com/oauth/v2/authorize",
            authorize_fixed: &[],
            allowed: &["user_scope"],
            key_param: "",
            scope_param: "user_scope",
            scope_delimiter: ",",
            pkce: Pkce::None,
            token_url: "https://slack.com/api/oauth.v2.access",
            client_auth: ClientAuth::Body,
            body: BodyFormat::Form,
            token_headers: &[],
            token_bearer: "",
            token_fixed: &[],
            ok_field: "ok",
            token_container: "authed_user",
            revoke: None,
            inject_paths: &["authed_user.access_token", "access_token"],
            public: &[
                text("team.id", 32),
                text("team.name", 256),
                text("enterprise.id", 32),
                text("enterprise.name", 256),
                text("app_id", 32),
                boolean("is_enterprise_install"),
                text("authed_user.id", 32),
                text("authed_user.scope", 8192),
                integer("authed_user.expires_in"),
                text("authed_user.token_type", 32),
            ],
            id_token_claims: &[],
        },
        Row {
            name: "notion",
            client: ClientKind::Static,
            authorize_url: "https://api.notion.com/v1/oauth/authorize",
            authorize_fixed: &[("owner", "user")],
            allowed: &[],
            key_param: "",
            scope_param: "",
            scope_delimiter: "",
            pkce: Pkce::None,
            token_url: "https://api.notion.com/v1/oauth/token",
            client_auth: ClientAuth::Basic,
            body: BodyFormat::Json,
            token_headers: &[("Notion-Version", "2025-09-03")],
            token_bearer: "",
            token_fixed: &[],
            ok_field: "",
            token_container: "",
            revoke: None,
            inject_paths: &["access_token"],
            public: &[
                text("workspace_id", 64),
                text("workspace_name", 256),
                text("workspace_icon", 2048),
                text("bot_id", 64),
                text("duplicated_template_id", 64),
                text("owner.type", 32),
                text("owner.user.id", 64),
                text("owner.user.name", 256),
                text("owner.user.avatar_url", 2048),
                text("owner.user.type", 32),
                text("owner.user.person.email", 320),
            ],
            id_token_claims: &[],
        },
        Row {
            name: "x",
            client: ClientKind::Static,
            authorize_url: "https://x.com/i/oauth2/authorize",
            authorize_fixed: &[],
            allowed: &["scope"],
            key_param: "",
            scope_param: "scope",
            scope_delimiter: " ",
            pkce: Pkce::S256,
            token_url: "https://api.x.com/2/oauth2/token",
            client_auth: ClientAuth::Basic,
            body: BodyFormat::Form,
            token_headers: &[],
            token_bearer: "",
            token_fixed: &[],
            ok_field: "",
            token_container: "",
            revoke: Some(("https://api.x.com/2/oauth2/revoke", ClientAuth::Basic, "")),
            inject_paths: &["access_token"],
            public: COMMON,
            id_token_claims: &[],
        },
        Row {
            name: "link",
            client: ClientKind::Static,
            authorize_url: "https://login.link.com/auth",
            authorize_fixed: &[],
            allowed: &["scope"],
            key_param: "key",
            scope_param: "scope",
            scope_delimiter: " ",
            pkce: Pkce::S256,
            token_url: "https://login.link.com/auth/token",
            client_auth: ClientAuth::Body,
            body: BodyFormat::Form,
            token_headers: &[],
            token_bearer: "publishable_key",
            token_fixed: &[],
            ok_field: "",
            token_container: "",
            revoke: Some((
                "https://login.link.com/auth/revoke",
                ClientAuth::Body,
                "publishable_key",
            )),
            inject_paths: &["access_token"],
            public: COMMON,
            id_token_claims: &[],
        },
        Row {
            name: "granola",
            client: ClientKind::Dynamic,
            authorize_url: "https://mcp-auth.granola.ai/oauth2/authorize",
            authorize_fixed: &[("resource", "https://mcp.granola.ai/mcp")],
            allowed: &["scope"],
            key_param: "",
            scope_param: "scope",
            scope_delimiter: " ",
            pkce: Pkce::S256,
            token_url: "https://mcp-auth.granola.ai/oauth2/token",
            client_auth: ClientAuth::None,
            body: BodyFormat::Form,
            token_headers: &[],
            token_bearer: "",
            token_fixed: &[("resource", "https://mcp.granola.ai/mcp")],
            ok_field: "",
            token_container: "",
            revoke: None,
            inject_paths: &["access_token"],
            public: COMMON,
            id_token_claims: &[],
        },
        Row {
            name: "mercury",
            client: ClientKind::Dynamic,
            authorize_url: "https://mcp.mercury.com/authorize",
            authorize_fixed: &[("resource", "https://mcp.mercury.com/mcp")],
            allowed: &["scope"],
            key_param: "",
            scope_param: "scope",
            scope_delimiter: " ",
            pkce: Pkce::S256,
            token_url: "https://mcp.mercury.com/token",
            client_auth: ClientAuth::None,
            body: BodyFormat::Form,
            token_headers: &[],
            token_bearer: "",
            token_fixed: &[("resource", "https://mcp.mercury.com/mcp")],
            ok_field: "",
            token_container: "",
            revoke: None,
            inject_paths: &["access_token"],
            public: COMMON,
            id_token_claims: &[],
        },
    ];

    #[test]
    fn the_embedded_definitions_are_the_table_of_section_6_2() {
        let definitions = embedded();
        let mut names: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
        names.sort_unstable();
        assert_eq!(definitions.names().collect::<Vec<_>>(), names);
        for row in &ROWS {
            let name = row.name;
            let definition = definitions.get(name).unwrap();
            assert_eq!(definition.client, row.client, "{name}");
            assert_eq!(definition.authorize.url, row.authorize_url, "{name}");
            assert_eq!(
                definition.authorize.fixed,
                pairs(row.authorize_fixed),
                "{name}"
            );
            assert_eq!(definition.authorize.allowed, row.allowed, "{name}");
            assert_eq!(definition.authorize.key_param, row.key_param, "{name}");
            assert_eq!(definition.scope_param, row.scope_param, "{name}");
            assert_eq!(definition.scope_delimiter, row.scope_delimiter, "{name}");
            assert_eq!(definition.scopes, None, "{name}");
            assert_eq!(definition.pkce, row.pkce, "{name}");
            assert_eq!(definition.token.url, row.token_url, "{name}");
            assert_eq!(definition.token.client_auth, row.client_auth, "{name}");
            assert_eq!(definition.token.body, row.body, "{name}");
            assert_eq!(definition.token.headers, pairs(row.token_headers), "{name}");
            assert_eq!(definition.token.bearer, row.token_bearer, "{name}");
            assert_eq!(definition.token.fixed, pairs(row.token_fixed), "{name}");
            assert_eq!(definition.token.ok_field, row.ok_field, "{name}");
            assert_eq!(definition.token_container, row.token_container, "{name}");
            let revoke = definition.revoke.as_ref().map(|revoke| {
                (
                    revoke.url.as_str(),
                    revoke.client_auth,
                    revoke.bearer.as_str(),
                )
            });
            assert_eq!(revoke, row.revoke, "{name}");
            assert_eq!(definition.inject.header, "Authorization", "{name}");
            assert_eq!(definition.inject.prefix, "Bearer ", "{name}");
            assert_eq!(definition.inject.paths, row.inject_paths, "{name}");
            assert_eq!(leaves(&definition.public), listed(row.public), "{name}");
            assert_eq!(
                leaves(&definition.id_token_claims),
                listed(row.id_token_claims),
                "{name}"
            );
        }
    }

    /// The table of enclave.md section 7: provider, host, prefixes, exact paths.
    const ADDRESSES: [(&str, &str, &[&str], &[&str]); 16] = [
        (
            "google_workspace",
            "gmail.googleapis.com",
            &["/gmail/v1/", "/upload/gmail/v1/"],
            &[],
        ),
        (
            "google_workspace",
            "www.googleapis.com",
            &[
                "/calendar/v3/",
                "/drive/v3/",
                "/upload/drive/v3/",
                "/download/drive/v3/",
            ],
            &["/oauth2/v3/userinfo"],
        ),
        (
            "google_workspace",
            "docs.googleapis.com",
            &["/v1/documents"],
            &[],
        ),
        (
            "google_workspace",
            "sheets.googleapis.com",
            &["/v4/spreadsheets"],
            &[],
        ),
        (
            "google_workspace",
            "slides.googleapis.com",
            &["/v1/presentations"],
            &[],
        ),
        (
            "google_workspace",
            "forms.googleapis.com",
            &["/v1/forms"],
            &[],
        ),
        (
            "google_workspace",
            "tasks.googleapis.com",
            &["/tasks/v1/"],
            &[],
        ),
        ("google_workspace", "meet.googleapis.com", &["/v2/"], &[]),
        ("microsoft", "graph.microsoft.com", &["/v1.0/"], &[]),
        (
            "slack",
            "slack.com",
            &[],
            &[
                "/api/conversations.list",
                "/api/conversations.history",
                "/api/conversations.replies",
                "/api/conversations.info",
                "/api/auth.test",
                "/api/search.messages",
                "/api/users.list",
                "/api/users.info",
                "/api/files.info",
                "/api/chat.postMessage",
                "/api/files.getUploadURLExternal",
                "/api/files.completeUploadExternal",
            ],
        ),
        ("slack", "files.slack.com", &["/files-pri/"], &[]),
        (
            "notion",
            "api.notion.com",
            &[
                "/v1/pages",
                "/v1/blocks/",
                "/v1/databases/",
                "/v1/data_sources/",
            ],
            &["/v1/search"],
        ),
        (
            "x",
            "api.x.com",
            &["/2/users", "/2/tweets", "/2/dm_events"],
            &[],
        ),
        (
            "link",
            "api.link.com",
            &["/spend_requests"],
            &["/userinfo", "/payment-details", "/shipping_addresses"],
        ),
        ("granola", "mcp.granola.ai", &[], &["/mcp"]),
        ("mercury", "mcp.mercury.com", &[], &["/mcp"]),
    ];

    #[test]
    fn the_embedded_api_rules_are_the_table_of_section_7() {
        let definitions = embedded();
        let mut counted: BTreeMap<&str, usize> = BTreeMap::new();
        for (provider, host, prefixes, exact) in &ADDRESSES {
            let definition = definitions.get(provider).unwrap();
            let rule = definition
                .api
                .iter()
                .find(|rule| rule.host == *host)
                .unwrap_or_else(|| panic!("{provider} {host}"));
            assert_eq!(rule.prefixes, *prefixes, "{provider} {host}");
            assert_eq!(rule.exact, *exact, "{provider} {host}");
            // One host takes an encoded `/` in a path: the values address of Google Sheets
            // carries a range, which may hold the `/` of a tab name, as one segment.
            assert_eq!(
                rule.encoded_slash,
                (*provider, *host) == ("google_workspace", "sheets.googleapis.com"),
                "{provider} {host}"
            );
            // One rule denies a path under its prefix: the batch address of Microsoft Graph
            // carries up to 20 requests in its body.
            let denied: &[&str] = match (*provider, *host) {
                ("microsoft", "graph.microsoft.com") => &["/v1.0/$batch"],
                _ => &[],
            };
            assert_eq!(rule.denied, denied, "{provider} {host}");
            *counted.entry(provider).or_default() += 1;
        }
        for name in definitions.names() {
            assert_eq!(
                definitions.get(name).unwrap().api.len(),
                counted[name],
                "{name}"
            );
        }
    }

    #[test]
    fn token_and_revocation_addresses_are_not_reachable_by_forward() {
        let definitions = embedded();
        for name in definitions.names() {
            let definition = definitions.get(name).unwrap();
            assert!(
                definition.check_address(&definition.token.url).is_err(),
                "{name}"
            );
            if let Some(revoke) = &definition.revoke {
                assert!(definition.check_address(&revoke.url).is_err(), "{name}");
            }
            assert!(
                definition.check_address(&definition.authorize.url).is_err(),
                "{name}"
            );
        }
    }

    fn google() -> Definition {
        embedded().get("google_workspace").unwrap().clone()
    }

    #[test]
    fn allowed_addresses_pass_and_keep_their_raw_form() {
        let google = google();
        let target = google
            .check_address("https://gmail.googleapis.com/gmail/v1/users/me/messages?q=from%3Aa%40b.c&maxResults=5")
            .unwrap();
        assert_eq!(target.host, "gmail.googleapis.com");
        assert_eq!(target.path, "/gmail/v1/users/me/messages");
        assert_eq!(target.query, "q=from%3Aa%40b.c&maxResults=5");
        assert_eq!(
            target.request_target,
            "/gmail/v1/users/me/messages?q=from%3Aa%40b.c&maxResults=5"
        );
        // Explicit port 443 and an uppercase host are the same address.
        let target = google
            .check_address("https://GMAIL.googleapis.com:443/gmail/v1/users/me/profile")
            .unwrap();
        assert_eq!(target.host, "gmail.googleapis.com");
        assert_eq!(target.query, "");
        assert_eq!(target.request_target, "/gmail/v1/users/me/profile");
        // A `?` without a query is kept.
        let target = google
            .check_address("https://www.googleapis.com/oauth2/v3/userinfo?")
            .unwrap();
        assert_eq!(target.request_target, "/oauth2/v3/userinfo?");
        // Exact paths and prefixes at a segment boundary.
        for address in [
            "https://www.googleapis.com/oauth2/v3/userinfo",
            "https://docs.googleapis.com/v1/documents",
            "https://docs.googleapis.com/v1/documents/abc:batchUpdate",
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart",
            "https://sheets.googleapis.com/v4/spreadsheets/1a/values/A1%3AB2",
            "https://meet.googleapis.com/v2/spaces",
        ] {
            assert!(google.check_address(address).is_ok(), "{address}");
        }
    }

    #[test]
    fn an_encoded_slash_passes_on_the_host_whose_rule_takes_it_and_nowhere_else() {
        let google = google();
        // A range of a tab whose name has a `/`, in both cases of the hex digits. The path is
        // sent as it was received.
        for path in [
            "/v4/spreadsheets/abc/values/Q1%2FQ2%21A1%3AB2",
            "/v4/spreadsheets/abc/values/Q1%2fQ2%21A1%3AB2",
            "/v4/spreadsheets/abc/values/2026%2F09%2F30!A1:append",
        ] {
            let address = format!("https://sheets.googleapis.com{path}?majorDimension=ROWS");
            let target = google.check_address(&address).unwrap();
            assert_eq!(target.path, path);
            assert_eq!(target.request_target, format!("{path}?majorDimension=ROWS"));
        }
        let denied = [
            // The decoded path has a dot segment: it would leave the prefix on a server that
            // decodes before it resolves.
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/x%2F..%2F..%2Fy",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/x%2f%2e%2e%2fy",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/..%2Fy",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/x%2F..",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/x%2F.%2Fy",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/x%2F.",
            "https://sheets.googleapis.com/v4/spreadsheets/%2E%2E%2Fy",
            // An encoded `/` is not a segment boundary for the prefix comparison.
            "https://sheets.googleapis.com/v4/spreadsheets%2Fabc",
            "https://sheets.googleapis.com/v4%2Fspreadsheets/abc",
            "https://sheets.googleapis.com/%2Fv4/spreadsheets/abc",
            // The other refusals hold on this host too.
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/x%5Cy",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/x%5cy",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/x\\y",
            "https://sheets.googleapis.com/v4/spreadsheets/abc//values/x%2Fy",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/x%2Fy%2",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/x%2Fy%zz",
            // Every other host refuses an encoded `/`.
            "https://docs.googleapis.com/v1/documents/abc%2Fdef",
            "https://www.googleapis.com/drive/v3/files/abc%2Fdef",
            "https://gmail.googleapis.com/gmail/v1/users/me%2Fprofile",
            "https://slides.googleapis.com/v1/presentations/abc%2fdef",
        ];
        for address in denied {
            assert_eq!(
                google.check_address(address),
                Err(ProtocolError::NotAllowed),
                "{address}"
            );
        }
        // No other provider has a host that takes one.
        let definitions = embedded();
        for name in definitions.names() {
            let definition = definitions.get(name).unwrap();
            for rule in &definition.api {
                if (name, rule.host.as_str()) == ("google_workspace", "sheets.googleapis.com") {
                    continue;
                }
                let path = rule
                    .prefixes
                    .first()
                    .or(rule.exact.first())
                    .unwrap()
                    .trim_end_matches('/');
                let address = format!("https://{}{path}/a%2Fb", rule.host);
                assert_eq!(
                    definition.check_address(&address),
                    Err(ProtocolError::NotAllowed),
                    "{address}"
                );
            }
        }
    }

    #[test]
    fn every_rejection_of_section_7() {
        let google = google();
        let denied = [
            // Another scheme.
            "http://gmail.googleapis.com/gmail/v1/users/me/profile",
            "HTTPS://gmail.googleapis.com/gmail/v1/users/me/profile",
            "gmail.googleapis.com/gmail/v1/users/me/profile",
            // Another host.
            "https://evil.example/gmail/v1/users/me/profile",
            "https://gmail.googleapis.com.evil.example/gmail/v1/users/me/profile",
            "https://xgmail.googleapis.com/gmail/v1/users/me/profile",
            "https://googleapis.com/gmail/v1/users/me/profile",
            // The token address and the revocation address of the same provider.
            "https://oauth2.googleapis.com/token",
            "https://oauth2.googleapis.com/revoke",
            // A host of another provider.
            "https://graph.microsoft.com/v1.0/me",
            // A path outside the allowed ones.
            "https://gmail.googleapis.com/",
            "https://gmail.googleapis.com",
            "https://gmail.googleapis.com?x=1",
            "https://gmail.googleapis.com/gmail/v2/users/me/profile",
            "https://gmail.googleapis.com/gmail/v1",
            "https://www.googleapis.com/oauth2/v3/userinfo/extra",
            "https://www.googleapis.com/oauth2/v3/tokeninfo",
            "https://www.googleapis.com/oauth2/v4/token",
            // A prefix that does not end with `/` matches at a segment boundary only.
            "https://docs.googleapis.com/v1/documentsX",
            "https://docs.googleapis.com/v1/documents.evil",
            "https://sheets.googleapis.com/v4/spreadsheetsandmore/1",
            // Dot segments, plain and percent-encoded.
            "https://gmail.googleapis.com/gmail/v1/../../token",
            "https://gmail.googleapis.com/gmail/v1/./users",
            "https://gmail.googleapis.com/gmail/v1/users/..",
            "https://gmail.googleapis.com/gmail/v1/%2e%2e/token",
            "https://gmail.googleapis.com/gmail/v1/%2E%2E/token",
            "https://gmail.googleapis.com/gmail/v1/.%2e/token",
            "https://gmail.googleapis.com/gmail/v1/%2e./token",
            "https://gmail.googleapis.com/gmail/v1/%2e/token",
            // Encoded separators, backslashes and empty segments.
            "https://gmail.googleapis.com/gmail/v1/users%2fme",
            "https://gmail.googleapis.com/gmail/v1/users%2Fme",
            "https://gmail.googleapis.com/gmail/v1/users%5cme",
            "https://gmail.googleapis.com/gmail/v1/users%5Cme",
            "https://gmail.googleapis.com/gmail/v1/users\\me",
            "https://gmail.googleapis.com/gmail/v1//users",
            "https://gmail.googleapis.com//gmail/v1/users",
            // Ports.
            "https://gmail.googleapis.com:8443/gmail/v1/users/me/profile",
            "https://gmail.googleapis.com:80/gmail/v1/users/me/profile",
            "https://gmail.googleapis.com:/gmail/v1/users/me/profile",
            "https://gmail.googleapis.com:0443/gmail/v1/users/me/profile",
            // User information.
            "https://user@gmail.googleapis.com/gmail/v1/users/me/profile",
            "https://user:pass@gmail.googleapis.com/gmail/v1/users/me/profile",
            "https://gmail.googleapis.com@evil.example/gmail/v1/users/me/profile",
            // IP literals and a host with a trailing dot.
            "https://127.0.0.1/gmail/v1/users/me/profile",
            "https://[::1]/gmail/v1/users/me/profile",
            "https://2130706433/gmail/v1/users/me/profile",
            "https://0x7f.0.0.1/gmail/v1/users/me/profile",
            "https://gmail.googleapis.com./gmail/v1/users/me/profile",
            // A fragment, whitespace, control characters, other bytes, a broken escape.
            "https://gmail.googleapis.com/gmail/v1/users/me/profile#fragment",
            "https://gmail.googleapis.com/gmail/v1/users/me/pro file",
            "https://gmail.googleapis.com/gmail/v1/users/me/profile\r\nHost: evil.example",
            "https://gmail.googleapis.com/gmail/v1/users/me/pro\tfile",
            "https://gmail.googleapis.com/gmail/v1/users/mé/profile",
            "https://gmail.googleapis.com/gmail/v1/users/me/%zzprofile",
            "https://gmail.googleapis.com/gmail/v1/users/me/profile%2",
            "",
        ];
        for address in denied {
            assert_eq!(
                google.check_address(address),
                Err(ProtocolError::NotAllowed),
                "{address:?}"
            );
        }
    }

    #[test]
    fn path_parameters_and_escapes_that_are_encoded_twice_hide_no_dot_segment() {
        let google = google();
        let denied = [
            // A dot segment in front of a path parameter. A server that leaves the parameter
            // out reads `..`.
            "https://gmail.googleapis.com/gmail/v1/..;/token",
            "https://gmail.googleapis.com/gmail/v1/..;x/token",
            "https://gmail.googleapis.com/gmail/v1/..;x=1;y=2/..;/token",
            "https://gmail.googleapis.com/gmail/v1/users/..;",
            "https://gmail.googleapis.com/gmail/v1/users/..;x",
            "https://gmail.googleapis.com/gmail/v1/.;/users",
            "https://gmail.googleapis.com/gmail/v1/.;x/users",
            // The same with the dots or the `;` as escapes.
            "https://gmail.googleapis.com/gmail/v1/%2e%2e;/token",
            "https://gmail.googleapis.com/gmail/v1/%2E.;x/token",
            "https://gmail.googleapis.com/gmail/v1/..%3b/token",
            "https://gmail.googleapis.com/gmail/v1/..%3Bx/token",
            // The escape of `.`, of `/` and of `\\` with its `%` encoded once more. A server
            // that decodes twice reads a dot segment or a separator.
            "https://gmail.googleapis.com/gmail/v1/%252e%252e/token",
            "https://gmail.googleapis.com/gmail/v1/%252E%252E/token",
            "https://gmail.googleapis.com/gmail/v1/%252e/users",
            "https://gmail.googleapis.com/gmail/v1/users%252fme",
            "https://gmail.googleapis.com/gmail/v1/users%252Fme",
            "https://gmail.googleapis.com/gmail/v1/users%255cme",
            "https://gmail.googleapis.com/gmail/v1/users%255Cme",
            "https://gmail.googleapis.com/gmail/v1/a%252e%252e%252fb",
            // The host that takes an encoded `/` refuses all of these as well.
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/..;/y",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/x%2F..;%2Fy",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/x%2F..;z%2Fy",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/x%252Fy",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/x%252fy",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/%252e%252e%2Fy",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/x%255Cy",
        ];
        for address in denied {
            assert_eq!(
                google.check_address(address),
                Err(ProtocolError::NotAllowed),
                "{address}"
            );
        }
        let allowed = [
            // A `;` inside a longer segment is part of a name.
            "https://gmail.googleapis.com/gmail/v1/users/me;v=1/messages",
            "https://gmail.googleapis.com/gmail/v1/users/a;b",
            "https://gmail.googleapis.com/gmail/v1/users/...;x",
            "https://gmail.googleapis.com/gmail/v1/users/..a;x",
            "https://gmail.googleapis.com/gmail/v1/users/;x",
            "https://docs.googleapis.com/v1/documents/doc;1:batchUpdate",
            // A range of Google Sheets with the `/` of a tab name, and with a `;`.
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/Q1%2FQ2%21A1%3AB2",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/2026%2F09%2F30!A1:append",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/a;b%2Fc!A1",
            // An encoded `%` in front of other characters is a `%` of a name.
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/100%25!A1",
            "https://sheets.googleapis.com/v4/spreadsheets/abc/values/a%2520b!A1",
            "https://gmail.googleapis.com/gmail/v1/users/me/labels/50%25",
            "https://gmail.googleapis.com/gmail/v1/users/me/labels/%2525",
        ];
        for address in allowed {
            let target = google
                .check_address(address)
                .unwrap_or_else(|_| panic!("{address}"));
            // The path is sent as it was received.
            assert_eq!(format!("https://{}{}", target.host, target.path), address);
        }
    }

    #[test]
    fn every_provider_reaches_only_its_own_hosts() {
        let definitions = embedded();
        let samples = [
            (
                "google_workspace",
                "https://tasks.googleapis.com/tasks/v1/users/@me/lists",
            ),
            ("microsoft", "https://graph.microsoft.com/v1.0/me/messages"),
            ("slack", "https://slack.com/api/chat.postMessage"),
            (
                "slack",
                "https://files.slack.com/files-pri/T1-F1/report.pdf",
            ),
            ("notion", "https://api.notion.com/v1/pages"),
            ("notion", "https://api.notion.com/v1/blocks/abc/children"),
            ("notion", "https://api.notion.com/v1/search"),
            ("x", "https://api.x.com/2/users/me?user.fields=username"),
            ("link", "https://api.link.com/spend_requests/lsrq_1"),
            ("link", "https://api.link.com/userinfo"),
            ("granola", "https://mcp.granola.ai/mcp"),
            ("mercury", "https://mcp.mercury.com/mcp"),
        ];
        for (provider, address) in samples {
            for name in definitions.names() {
                let outcome = definitions.get(name).unwrap().check_address(address);
                assert_eq!(outcome.is_ok(), name == provider, "{name} {address}");
            }
        }
        let denied = [
            ("slack", "https://slack.com/api/oauth.v2.access"),
            ("slack", "https://slack.com/api/chat.postMessageX"),
            ("slack", "https://slack.com/api/admin.users.list"),
            ("notion", "https://api.notion.com/v1/oauth/token"),
            ("notion", "https://api.notion.com/v1/blocks"),
            ("notion", "https://api.notion.com/v1/search/more"),
            ("x", "https://api.x.com/2/oauth2/token"),
            ("x", "https://api.x.com/2/usersearch"),
            ("link", "https://login.link.com/auth/token"),
            ("link", "https://api.link.com/userinfo2"),
            ("granola", "https://mcp.granola.ai/mcp/other"),
            ("granola", "https://mcp-auth.granola.ai/oauth2/token"),
            ("mercury", "https://mcp.mercury.com/mcp/other"),
            ("mercury", "https://mcp.mercury.com/token"),
            ("mercury", "https://mcp.mercury.com/register"),
            ("microsoft", "https://graph.microsoft.com/beta/me"),
            (
                "microsoft",
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            ),
        ];
        for (provider, address) in denied {
            assert!(
                definitions
                    .get(provider)
                    .unwrap()
                    .check_address(address)
                    .is_err(),
                "{provider} {address}"
            );
        }
    }

    #[test]
    fn a_denied_path_is_refused_in_every_spelling_a_server_may_take_for_it() {
        let definitions = embedded();
        let microsoft = definitions.get("microsoft").unwrap();
        let denied = [
            "https://graph.microsoft.com/v1.0/$batch",
            "https://graph.microsoft.com/v1.0/$batch?x=1",
            "https://GRAPH.microsoft.com:443/v1.0/$batch",
            // The `$` as an escape, in both cases of the digits, and other characters of the
            // path as escapes.
            "https://graph.microsoft.com/v1.0/%24batch",
            "https://graph.microsoft.com/v1.0/%24%62atch",
            "https://graph.microsoft.com/v1.0/$%42atch",
            // Other cases of the letters.
            "https://graph.microsoft.com/v1.0/$Batch",
            "https://graph.microsoft.com/v1.0/$BATCH",
            // What continues the path, and a path parameter.
            "https://graph.microsoft.com/v1.0/$batch/",
            "https://graph.microsoft.com/v1.0/$batch/more",
            "https://graph.microsoft.com/v1.0/$batch;x",
            "https://graph.microsoft.com/v1.0/$batch;x=1/more",
            "https://graph.microsoft.com/v1.0/%24BATCH%3bx",
            // A path that was encoded twice and three times.
            "https://graph.microsoft.com/v1.0/%2524batch",
            "https://graph.microsoft.com/v1.0/%252524batch",
            "https://graph.microsoft.com/v1.0/%2524Batch%253Bx",
        ];
        for address in denied {
            assert_eq!(
                microsoft.check_address(address),
                Err(ProtocolError::NotAllowed),
                "{address}"
            );
        }
        // The other addresses under the prefix pass, also those that begin like the denied
        // path or hold it at another place.
        for address in [
            "https://graph.microsoft.com/v1.0/me/messages",
            "https://graph.microsoft.com/v1.0/me/messages?$top=5",
            "https://graph.microsoft.com/v1.0/users/$count",
            "https://graph.microsoft.com/v1.0/me/photo/$value",
            "https://graph.microsoft.com/v1.0/$batches",
            "https://graph.microsoft.com/v1.0/me/$batch",
        ] {
            assert!(microsoft.check_address(address).is_ok(), "{address}");
        }
    }

    const MINIMAL: &str = r#"{
        "client": "static",
        "authorize": {"url": "https://auth.provider.test/authorize", "fixed": [], "allowed": ["scope"], "key_param": ""},
        "scope_param": "scope",
        "scope_delimiter": " ",
        "pkce": "S256",
        "token": {"url": "https://auth.provider.test/token", "client_auth": "body", "body": "form", "headers": [], "bearer": "", "fixed": [], "ok_field": ""},
        "token_container": "",
        "revoke": null,
        "inject": {"header": "Authorization", "prefix": "Bearer ", "paths": ["access_token"]},
        "public": [{"path": "scope", "type": "string", "max": 8192}],
        "id_token_claims": [],
        "api": [{"host": "api.provider.test", "prefixes": ["/v1/"], "exact": []}]
    }"#;

    fn with(change: impl Fn(&mut serde_json::Value)) -> Result<Definitions, String> {
        let mut definition: serde_json::Value = serde_json::from_str(MINIMAL).unwrap();
        change(&mut definition);
        Definitions::parse(&serde_json::json!({"sample": definition}).to_string())
    }

    #[test]
    fn public_fields_are_typed_leaves_that_name_no_token() {
        let public = |fields: serde_json::Value| with(|d| d["public"] = fields.clone());
        let claims = |fields: serde_json::Value| with(|d| d["id_token_claims"] = fields.clone());
        use serde_json::json;
        assert!(public(json!([
            {"path": "scope", "type": "string", "max": 8192},
            {"path": "expires_in", "type": "integer"},
            {"path": "team.id", "type": "string", "max": 32},
            {"path": "is_enterprise_install", "type": "boolean"},
        ]))
        .is_ok());
        assert!(claims(json!([{"path": "email", "type": "string", "max": 320}])).is_ok());
        // The form of v1.0.0: a bare path.
        assert!(public(json!(["scope"])).is_err());
        // A string without a limit, a limit of zero, a limit on another type.
        assert!(public(json!([{"path": "scope", "type": "string"}])).is_err());
        assert!(public(json!([{"path": "scope", "type": "string", "max": 0}])).is_err());
        assert!(public(json!([{"path": "expires_in", "type": "integer", "max": 5}])).is_err());
        assert!(public(json!([{"path": "ok", "type": "boolean", "max": 5}])).is_err());
        // An unknown type, an unknown key, an empty path or segment.
        assert!(public(json!([{"path": "team", "type": "object"}])).is_err());
        assert!(public(json!([{"path": "scope", "type": "string", "max": 1, "x": 1}])).is_err());
        assert!(public(json!([{"path": "", "type": "boolean"}])).is_err());
        assert!(public(json!([{"path": "team..id", "type": "boolean"}])).is_err());
        // A path listed twice, and a path that is the parent of another one.
        assert!(public(json!([
            {"path": "scope", "type": "string", "max": 1},
            {"path": "scope", "type": "string", "max": 2},
        ]))
        .is_err());
        assert!(public(json!([
            {"path": "team", "type": "string", "max": 1},
            {"path": "team.id", "type": "string", "max": 2},
        ]))
        .is_err());
        // A path that names a token, at any depth, and the path the node injects.
        for path in [
            "access_token",
            "refresh_token",
            "id_token",
            "authed_user.access_token",
            "authed_user.refresh_token",
        ] {
            assert!(
                public(json!([{"path": path, "type": "string", "max": 4096}])).is_err(),
                "{path}"
            );
        }
        assert!(claims(json!([{"path": "id_token", "type": "string", "max": 4096}])).is_err());
        assert!(with(|d| {
            d["inject"]["paths"] = json!(["bot.key"]);
            d["public"] = json!([{"path": "bot.key", "type": "string", "max": 64}]);
        })
        .is_err());
    }

    #[test]
    fn a_definitions_document_is_validated() {
        assert!(with(|_| {}).is_ok());
        // The token address must not be reachable by forward.
        assert!(with(|d| {
            d["api"][0]["host"] = "auth.provider.test".into();
            d["api"][0]["prefixes"] = serde_json::json!(["/"]);
        })
        .is_err());
        assert!(with(|d| d["token"]["url"] = "http://auth.provider.test/token".into()).is_err());
        assert!(with(|d| d["token"]["url"] = "https://127.0.0.1/token".into()).is_err());
        assert!(
            with(|d| d["token"]["url"] = "https://auth.provider.test:8443/token".into()).is_err()
        );
        assert!(with(|d| d["token"]["url"] = "https://u@auth.provider.test/token".into()).is_err());
        assert!(
            with(|d| d["token"]["url"] = "https://auth.provider.test/token?x=1".into()).is_err()
        );
        assert!(with(|d| d["token"]["bearer"] = "client_secret".into()).is_err());
        assert!(with(|d| d["token"]["client_auth"] = "mtls".into()).is_err());
        assert!(with(|d| d["pkce"] = "plain".into()).is_err());
        assert!(with(|d| d["api"] = serde_json::json!([])).is_err());
        assert!(with(|d| d["api"][0]["host"] = "API.provider.test".into()).is_err());
        assert!(with(|d| d["api"][0]["host"] = "10.0.0.1".into()).is_err());
        assert!(with(|d| d["api"][0]["prefixes"] = serde_json::json!(["v1/"])).is_err());
        assert!(with(|d| d["authorize"]["allowed"] = serde_json::json!(["state"])).is_err());
        assert!(with(|d| d["scope_param"] = "other".into()).is_err());
        assert!(with(|d| d["inject"]["paths"] = serde_json::json!([])).is_err());
        assert!(with(|d| d["unknown_key"] = true.into()).is_err());
        assert!(Definitions::parse("[]").is_err());
    }

    #[test]
    fn a_denied_path_lies_under_a_prefix_of_its_rule() {
        use serde_json::json;
        let denied = |paths: serde_json::Value| with(|d| d["api"][0]["denied"] = paths.clone());
        // A rule without the key denies nothing.
        let definitions = with(|_| {}).unwrap();
        assert!(definitions.get("sample").unwrap().api[0].denied.is_empty());
        let definitions = denied(json!(["/v1/$batch", "/v1/admin"])).unwrap();
        let sample = definitions.get("sample").unwrap();
        for (address, allowed) in [
            ("https://api.provider.test/v1/items", true),
            ("https://api.provider.test/v1/administrators", true),
            ("https://api.provider.test/v1/$batch", false),
            ("https://api.provider.test/v1/admin", false),
            ("https://api.provider.test/v1/admin/users", false),
            ("https://api.provider.test/v1/Admin", false),
        ] {
            assert_eq!(sample.check_address(address).is_ok(), allowed, "{address}");
        }
        // A path outside every prefix of the rule, also when it is an exact path of the rule.
        assert!(denied(json!(["/v2/$batch"])).is_err());
        assert!(denied(json!(["/v1"])).is_err());
        assert!(with(|d| {
            d["api"][0]["exact"] = json!(["/me"]);
            d["api"][0]["denied"] = json!(["/me"]);
        })
        .is_err());
        // The form of a path of the definitions, and the form of the comparison: lower case
        // and no path parameter.
        assert!(denied(json!(["v1/$batch"])).is_err());
        assert!(denied(json!(["/v1//batch"])).is_err());
        assert!(denied(json!(["/v1/%24batch"])).is_err());
        assert!(denied(json!(["/v1/batch?x"])).is_err());
        assert!(denied(json!(["/v1/$Batch"])).is_err());
        assert!(denied(json!(["/v1/$batch;x"])).is_err());
        assert!(denied(json!("/v1/$batch")).is_err());
        assert!(denied(json!([5])).is_err());
    }
}
