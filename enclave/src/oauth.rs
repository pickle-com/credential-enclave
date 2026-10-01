//! OAuth inside the node (enclave.md sections 5.5 to 5.7 and 6): the authorization address,
//! the token address call, the merge rules of protocol.md 8.3 and the public fields.
//!
//! Tokens are issued to the node and stay in it. This module owns the types that hold them:
//! the response of a token address ([`TokenResponse`]), the plaintext of a record of kind
//! `oauth` or `oauth_imported` ([`OauthRecord`], [`OauthPlaintext`]), the credential of a
//! request ([`Credential`]) and the PKCE verifier ([`PkceVerifier`]). Their fields are private
//! to this module and are secrets of the protocol crate, so no other module of the node can
//! read a token.
//!
//! The kind of a record says where its token came from (rule E6 of the egress policy). A
//! record of kind `oauth` holds a token this node, or another node that held the user key of
//! the account, received from the token address itself. A record of kind `oauth_imported` holds a token the operator
//! domain had before the device of the account encrypted it. The node keeps the two apart: a
//! plaintext carries its kind from the record it was opened from to the record it is sealed
//! into, a token response becomes kind `oauth` only, and `oauth/merge` takes kind `oauth`
//! only.
//!
//! What leaves this module, and in which form (the egress policy, `docs/egress-policy.md`):
//!
//! - a record, encrypted under the user key (sink K1: [`OauthPlaintext::seal`]);
//! - a request to the token address or the revocation address of the provider, and the
//!   credential of a `forward` request, as secrets that only the TLS client reads (sink K3);
//! - the public fields: the leaves the definition lists, each checked for its type and its
//!   length, and refused as a whole when one of them contains a token (rule E4:
//!   [`OauthPlaintext::public_fields`]);
//! - one bit: whether the token object holds a refresh token;
//! - the S256 challenge of a PKCE verifier;
//! - of a refused token request: the HTTP status and a word of a closed vocabulary (rule E5:
//!   [`ProviderError`]).

use std::collections::BTreeMap;
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use credential_enclave_protocol::encoding::{b64u, to_json};
use credential_enclave_protocol::record::{self, Kind, Record};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::ProtocolError;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::egress::{OutboundBody, OutboundHeader, OutboundRequest};
use crate::provider_response::Forms;
use crate::providers::{
    BodyFormat, ClientAuth, Definition, Destination, FieldType, PublicField, Revoke, TOKEN_KEYS,
};
use crate::state::{open_for, GrantView, Node};

/// Time limit of a token address call.
pub const TOKEN_TIMEOUT: Duration = Duration::from_secs(15);
/// Time limit of a revocation address call.
pub const REVOKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest token response a node reads: 1 MiB.
const TOKEN_RESPONSE_LIMIT_BYTES: usize = 1024 * 1024;
/// Longest value of an authorization parameter, in characters.
const PARAM_VALUE_CHARS: usize = 1024;

/// The successful response of a token address: a JSON object with an access token in the
/// token place. The whole response is a secret. Only [`call_token_address`] creates one.
pub struct TokenResponse(Secret<Value>);

/// The opened plaintext of a record of kind `oauth` or `oauth_imported`, before it is parsed.
/// Only [`open_record`] and [`open_records`] create one, so the bytes are those of a record
/// that opened under the grant of the account and names that kind in its AAD.
pub struct OauthRecord {
    kind: TokenKind,
    plaintext: Secret<Vec<u8>>,
}

/// The two kinds of a record that holds a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenKind {
    /// The node received the token from the token address.
    Issued,
    /// The device of the account encrypted a token the operator domain held.
    Imported,
}

impl TokenKind {
    fn of(kind: Kind) -> Option<TokenKind> {
        match kind {
            Kind::Oauth => Some(TokenKind::Issued),
            Kind::OauthImported => Some(TokenKind::Imported),
            Kind::VaultPassword | Kind::VaultTotp | Kind::VaultCard => None,
        }
    }

    fn kind(self) -> Kind {
        match self {
            TokenKind::Issued => Kind::Oauth,
            TokenKind::Imported => Kind::OauthImported,
        }
    }
}

/// The plaintext of a record of kind `oauth` or `oauth_imported` (protocol.md section 6):
/// `{"token": {...}, "obtained_ms": n}`, with `"client_id"` for a dynamically registered
/// client.
///
/// A value of this type comes from one of three places and from nowhere else: the response of
/// a token address ([`TokenResponse::into_plaintext`]), an opened record
/// ([`OauthRecord::parse`]), or the merge rules applied to those ([`OauthPlaintext::refreshed`],
/// [`OauthPlaintext::with_refresh_token_of`]). No call of the node turns a value of its caller
/// into one. The value keeps the kind of where it came from, and [`OauthPlaintext::seal`]
/// writes a record of that kind.
pub struct OauthPlaintext {
    kind: TokenKind,
    plaintext: Secret<Value>,
}

/// The credential `forward` injects: the token of an `oauth` record, and the header value made
/// of the prefix of the definition and that token.
pub struct Credential {
    token: Secret<String>,
    header: Secret<String>,
}

impl Credential {
    /// The header value for the TLS client, and the token for the check of the response.
    pub fn into_parts(self) -> (Secret<String>, Secret<String>) {
        (self.header, self.token)
    }
}

/// The PKCE verifier of an authorization in progress. It reaches the token address of the
/// provider and nothing else. Its S256 challenge is public.
pub struct PkceVerifier(Secret<String>);

impl PkceVerifier {
    /// The verifier of 32 random bytes: their base64url text, 43 characters.
    pub fn new(random: &Secret<[u8; 32]>) -> PkceVerifier {
        PkceVerifier(Secret::new(b64u(random.expose_secret())))
    }

    /// The S256 challenge: `b64u(SHA-256(verifier))`. It is part of the authorization address.
    pub fn challenge(&self) -> String {
        b64u(&Sha256::digest(self.0.expose_secret().as_bytes()))
    }
}

/// A provider response that the node does not hand on, because a value it would return
/// contains a token (rule E4 of the egress policy). The call fails with `response_withheld`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Withheld;

impl From<Withheld> for ProtocolError {
    fn from(_: Withheld) -> Self {
        ProtocolError::ResponseWithheld
    }
}

/// Step 6 of the common front for the calls that use a token (`forward`, `refresh`,
/// `revoke-token`): opens a record and takes it as a token record. The kinds `oauth` and
/// `oauth_imported` are taken. A vault kind is `not_allowed`.
pub fn open_record(
    grant: &GrantView,
    user_id: &str,
    record: &Record,
) -> Result<OauthRecord, ProtocolError> {
    let (kind, plaintext) = open_for(grant, user_id, record)?;
    let kind = TokenKind::of(kind).ok_or(ProtocolError::NotAllowed)?;
    Ok(OauthRecord { kind, plaintext })
}

/// Opens the two records of `oauth/merge`. Both are of kind `oauth`: the refresh token of an
/// imported record is not moved into a record the node issued. Both are opened before the
/// kind of either is judged, so a record that does not open fails with its own code first.
pub fn open_records(
    grant: &GrantView,
    user_id: &str,
    record: &Record,
    previous: &Record,
) -> Result<(OauthRecord, OauthRecord), ProtocolError> {
    let new = open_for(grant, user_id, record)?;
    let old = open_for(grant, user_id, previous)?;
    match (new, old) {
        ((Kind::Oauth, new), (Kind::Oauth, old)) => Ok((
            OauthRecord {
                kind: TokenKind::Issued,
                plaintext: new,
            },
            OauthRecord {
                kind: TokenKind::Issued,
                plaintext: old,
            },
        )),
        _ => Err(ProtocolError::NotAllowed),
    }
}

impl OauthRecord {
    /// Parses the plaintext. A plaintext that is not a JSON object with a `token` object is
    /// `record_invalid`.
    pub fn parse(&self) -> Result<OauthPlaintext, ProtocolError> {
        let parsed = Secret::new(
            serde_json::from_slice::<Value>(self.plaintext.expose_secret())
                .map_err(|_| ProtocolError::RecordInvalid)?,
        );
        if !parsed
            .expose_secret()
            .get("token")
            .is_some_and(Value::is_object)
        {
            return Err(ProtocolError::RecordInvalid);
        }
        Ok(OauthPlaintext {
            kind: self.kind,
            plaintext: parsed,
        })
    }
}

impl TokenResponse {
    /// The plaintext of the record of a first exchange: the response as the token object, the
    /// node time, and the client identifier of a dynamically registered client. The node
    /// received this token itself, so the record is of kind `oauth`.
    pub fn into_plaintext(self, obtained_ms: u64, client_id: Option<&str>) -> OauthPlaintext {
        let token = object_of(self.0.expose_secret()).clone();
        OauthPlaintext::from_parts(TokenKind::Issued, token, obtained_ms, client_id)
    }
}

impl OauthPlaintext {
    /// `{"token": .., "obtained_ms": .., "client_id": ..}`, in this key order.
    fn from_parts(
        kind: TokenKind,
        token: Map<String, Value>,
        obtained_ms: u64,
        client_id: Option<&str>,
    ) -> OauthPlaintext {
        let mut plaintext = Map::new();
        plaintext.insert("token".to_string(), Value::Object(token));
        plaintext.insert("obtained_ms".to_string(), Value::from(obtained_ms));
        if let Some(client_id) = client_id {
            plaintext.insert(
                "client_id".to_string(),
                Value::String(client_id.to_string()),
            );
        }
        OauthPlaintext {
            kind,
            plaintext: Secret::new(Value::Object(plaintext)),
        }
    }

    /// The plaintext after a refresh (protocol.md 8.3): the token of this plaintext with the
    /// response written over it, obtained at `obtained_ms`. It keeps the kind of this
    /// plaintext: the refreshed token of an imported record is still an imported one.
    pub fn refreshed(
        &self,
        response: &TokenResponse,
        container: &str,
        obtained_ms: u64,
    ) -> OauthPlaintext {
        let old = self.plaintext.expose_secret();
        let merged = merge_refresh(
            token_of(old),
            object_of(response.0.expose_secret()),
            container,
        );
        OauthPlaintext::from_parts(self.kind, merged, obtained_ms, client_id_of(old))
    }

    /// The plaintext of a reconnect (protocol.md 8.3): this plaintext, with the refresh token
    /// of `previous` when this one holds none.
    pub fn with_refresh_token_of(
        &self,
        previous: &OauthPlaintext,
        container: &str,
    ) -> OauthPlaintext {
        let new = self.plaintext.expose_secret();
        let mut token = token_of(new).clone();
        merge_reconnect(
            &mut token,
            token_of(previous.plaintext.expose_secret()),
            container,
        );
        OauthPlaintext::from_parts(self.kind, token, obtained_ms_of(new), client_id_of(new))
    }

    /// The refresh token: in the token place first, then at the top level.
    pub fn refresh_token(&self, container: &str) -> Option<Secret<String>> {
        refresh_token_of(token_of(self.plaintext.expose_secret()), container)
            .map(|token| Secret::new(token.to_string()))
    }

    /// The token a revocation request names and its `token_type_hint`: the refresh token when
    /// the record has one, else the access token.
    pub fn revocation_token(&self, container: &str) -> Option<(Secret<String>, &'static str)> {
        let token = token_of(self.plaintext.expose_secret());
        match refresh_token_of(token, container) {
            Some(refresh) => Some((Secret::new(refresh.to_string()), "refresh_token")),
            None => access_token_of(token, container)
                .map(|access| (Secret::new(access.to_string()), "access_token")),
        }
    }

    /// The credential `forward` injects: the token at the first path of the definition that
    /// holds a non-empty string, and the header value made of the prefix and that token.
    pub fn credential(&self, definition: &Definition) -> Option<Credential> {
        let token = inject_token(definition, token_of(self.plaintext.expose_secret()))?;
        Some(Credential {
            header: Secret::new(format!("{}{}", definition.inject.prefix, token)),
            token: Secret::new(token.to_string()),
        })
    }

    /// The client identifier of a dynamically registered client. It goes into the requests to
    /// the token address and the revocation address.
    pub fn client_id(&self) -> Option<Secret<String>> {
        client_id_of(self.plaintext.expose_secret())
            .map(|client_id| Secret::new(client_id.to_string()))
    }

    /// The public fields of the token (enclave.md 6.4, rule E4 of the egress policy).
    ///
    /// `response` is the token response this plaintext was made from, when the call received
    /// one. When a value the node would return holds the string at `access_token`,
    /// `refresh_token` or `id_token` of the token object or of that response (at the top level
    /// and in the token place), nothing is returned: the call fails with `response_withheld`.
    /// A value holds a token when it contains the token as it is, or one of its encoded forms
    /// the search of a provider response knows ([`Forms`]).
    pub fn public_fields(
        &self,
        definition: &Definition,
        response: Option<&TokenResponse>,
    ) -> Result<PublicFields, Withheld> {
        let plaintext = self.plaintext.expose_secret();
        let token = token_of(plaintext);
        let container = definition.token_container.as_str();
        let fields = PublicFields {
            token: public_token(&definition.public, token),
            id_token_claims: public_claims(&definition.id_token_claims, token),
            obtained_ms: obtained_ms_of(plaintext),
            has_refresh_token: refresh_token_of(token, container).is_some(),
        };
        let mut tokens = Vec::new();
        token_strings(token, container, &mut tokens);
        if let Some(response) = response {
            token_strings(
                object_of(response.0.expose_secret()),
                container,
                &mut tokens,
            );
        }
        let secrets: Vec<Secret<String>> = tokens
            .iter()
            .map(|token| Secret::new((*token).to_string()))
            .collect();
        let forms = Forms::of(&secrets);
        if carries_any(&fields.token, &tokens, &forms)
            || carries_any(&fields.id_token_claims, &tokens, &forms)
        {
            return Err(Withheld);
        }
        Ok(fields)
    }

    /// Creates the record of this plaintext under the user key of the grant, with the kind this
    /// plaintext came from. This is the one place where a token leaves this module as a record
    /// (sink K1).
    pub fn seal(
        &self,
        grant: &GrantView,
        id: &[u8; 16],
        nonce: &[u8; 12],
        user_id: &str,
        provider: &str,
    ) -> Record {
        let plaintext = Secret::new(to_json(self.plaintext.expose_secret()));
        record::seal(
            &grant.user_key,
            id,
            nonce,
            user_id,
            &grant.key_id,
            grant.custody,
            self.kind.kind(),
            provider,
            &plaintext,
        )
    }
}

/// The public fields of enclave.md 6.4:
/// `{"token": {the listed leaves}, "id_token_claims": {the listed claims}, "obtained_ms": n,
/// "has_refresh_token": bool}`. Only [`OauthPlaintext::public_fields`] creates one, so every
/// value in it passed rule E4.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicFields {
    token: Map<String, Value>,
    id_token_claims: Map<String, Value>,
    obtained_ms: u64,
    has_refresh_token: bool,
}

impl PublicFields {
    /// The scope string among the public fields: the `scope` of the token place, else the
    /// `scope` of the top level. Empty when the definition lists neither or the provider
    /// returned none.
    pub fn scope(&self, definition: &Definition) -> &str {
        let nested = self
            .token
            .get(&definition.token_container)
            .and_then(|place| place.get("scope"))
            .and_then(Value::as_str)
            .filter(|scope| !scope.is_empty());
        nested
            .or_else(|| self.token.get("scope").and_then(Value::as_str))
            .unwrap_or_default()
    }
}

fn object_of(value: &Value) -> &Map<String, Value> {
    value
        .as_object()
        .expect("a token response is created from a JSON object")
}

fn token_of(plaintext: &Value) -> &Map<String, Value> {
    plaintext
        .get("token")
        .and_then(Value::as_object)
        .expect("an oauth plaintext is created with a token object")
}

fn obtained_ms_of(plaintext: &Value) -> u64 {
    plaintext
        .get("obtained_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn client_id_of(plaintext: &Value) -> Option<&str> {
    plaintext.get("client_id").and_then(Value::as_str)
}

/// Percent-encodes by RFC 3986: every byte outside the unreserved characters becomes `%XX`. A
/// space is `%20`.
pub fn percent_encode(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    push_percent_encoded(&mut encoded, text);
    encoded
}

/// Appends the percent-encoding of `text` to `output`.
fn push_percent_encoded(output: &mut String, text: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

/// A value of a token request or a revocation request.
enum Field<'a> {
    Plain(&'a str),
    Secret(&'a Secret<String>),
}

impl Field<'_> {
    /// The length of the value in bytes.
    fn len(&self) -> usize {
        match self {
            Field::Plain(text) => text.len(),
            Field::Secret(text) => text.expose_secret().len(),
        }
    }
}

/// The form body of a token or revocation request. The body is a secret as a whole. It is
/// written into one buffer of its final size, so no copy of a part of it stays behind.
fn form_body(pairs: &[(&str, Field<'_>)]) -> Secret<Vec<u8>> {
    let capacity = pairs
        .iter()
        .map(|(key, value)| 3 * (key.len() + value.len()) + 2)
        .sum();
    let mut body = String::with_capacity(capacity);
    for (index, (key, value)) in pairs.iter().enumerate() {
        if index > 0 {
            body.push('&');
        }
        push_percent_encoded(&mut body, key);
        body.push('=');
        match value {
            Field::Plain(text) => push_percent_encoded(&mut body, text),
            Field::Secret(text) => push_percent_encoded(&mut body, text.expose_secret()),
        }
    }
    Secret::new(body.into_bytes())
}

/// The JSON body of a token request. The body is a secret as a whole.
fn json_body(pairs: &[(&str, Field<'_>)]) -> Secret<Vec<u8>> {
    let mut object = Map::new();
    for (key, value) in pairs {
        let text = match value {
            Field::Plain(text) => (*text).to_string(),
            Field::Secret(text) => text.expose_secret().clone(),
        };
        object.insert((*key).to_string(), Value::String(text));
    }
    let object = Secret::new(Value::Object(object));
    Secret::new(to_json(object.expose_secret()))
}

/// Checks the authorization parameters a caller chose (enclave.md 5.5 step 2): every key is in
/// `authorize.allowed`, every value is a string of at most 1,024 characters without control
/// characters, and when the definition lists `scopes`, every requested scope is in that list.
/// A violation is `not_allowed`.
pub fn check_params(
    definition: &Definition,
    params: &Map<String, Value>,
) -> Result<BTreeMap<String, String>, ProtocolError> {
    let mut checked = BTreeMap::new();
    for (key, value) in params {
        if !definition.authorize.allowed.contains(key) {
            return Err(ProtocolError::NotAllowed);
        }
        let text = value.as_str().ok_or(ProtocolError::NotAllowed)?;
        if text.chars().count() > PARAM_VALUE_CHARS || text.chars().any(char::is_control) {
            return Err(ProtocolError::NotAllowed);
        }
        checked.insert(key.clone(), text.to_string());
    }
    if let Some(allowed_scopes) = &definition.scopes {
        if let Some(requested) = checked.get(&definition.scope_param) {
            let all_listed = requested
                .split(definition.scope_delimiter.as_str())
                .filter(|scope| !scope.is_empty())
                .all(|scope| allowed_scopes.iter().any(|allowed| allowed == scope));
            if !all_listed {
                return Err(ProtocolError::NotAllowed);
            }
        }
    }
    Ok(checked)
}

/// Assembles the authorization address (enclave.md 5.5 step 5). The query parameters are in
/// this fixed order: `response_type=code`, `client_id`, `redirect_uri`, `state`, the PKCE
/// challenge with `code_challenge_method=S256`, the fixed pairs of the definition, the
/// `publishable_key` under `key_param`, and the caller's parameters sorted by key.
pub fn authorization_url(
    definition: &Definition,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    code_challenge: Option<&str>,
    publishable_key: &str,
    params: &BTreeMap<String, String>,
) -> String {
    let mut pairs: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("state", state),
    ];
    if let Some(challenge) = code_challenge {
        pairs.push(("code_challenge", challenge));
        pairs.push(("code_challenge_method", "S256"));
    }
    for (key, value) in &definition.authorize.fixed {
        pairs.push((key, value));
    }
    if !definition.authorize.key_param.is_empty() {
        pairs.push((&definition.authorize.key_param, publishable_key));
    }
    for (key, value) in params {
        pairs.push((key, value));
    }
    let query: Vec<String> = pairs
        .iter()
        .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
        .collect();
    format!("{}?{}", definition.authorize.url, query.join("&"))
}

/// The client identifier of a token or revocation request.
pub enum ClientId<'a> {
    /// The identifier of the operator configuration, or the one the caller of `oauth/begin`
    /// gave for a dynamically registered client.
    Configured(&'a str),
    /// The identifier a record holds for a dynamically registered client.
    Recorded(&'a Secret<String>),
}

impl ClientId<'_> {
    fn field(&self) -> Field<'_> {
        match self {
            ClientId::Configured(client_id) => Field::Plain(client_id),
            ClientId::Recorded(client_id) => Field::Secret(client_id),
        }
    }
}

/// The client values a token or revocation request authenticates with.
pub struct ClientValues<'a> {
    pub client_id: ClientId<'a>,
    pub client_secret: &'a Secret<String>,
    pub publishable_key: &'a str,
}

/// What a token request asks for.
pub enum TokenGrant<'a> {
    Exchange {
        code: &'a str,
        redirect_uri: &'a str,
        code_verifier: Option<&'a PkceVerifier>,
    },
    Refresh {
        refresh_token: &'a Secret<String>,
    },
}

/// The value of the HTTP Basic header of a token or revocation request: a secret.
fn basic_credentials(client: &ClientValues<'_>) -> Secret<String> {
    let client_id = match &client.client_id {
        ClientId::Configured(client_id) => client_id,
        ClientId::Recorded(client_id) => client_id.expose_secret().as_str(),
    };
    let pair = Secret::new(format!(
        "{client_id}:{}",
        client.client_secret.expose_secret()
    ));
    let encoded = Secret::new(STANDARD.encode(pair.expose_secret().as_bytes()));
    Secret::new(format!("Basic {}", encoded.expose_secret()))
}

fn outbound(
    destination: Destination,
    headers: Vec<OutboundHeader>,
    body: Secret<Vec<u8>>,
) -> OutboundRequest {
    OutboundRequest::new(destination, "POST", headers, OutboundBody::Secret(body))
}

/// Builds the token address request of enclave.md 6.3. The request goes to the token address
/// of the definition and to no other address.
///
/// Exchange body: `grant_type=authorization_code`, `code`, `redirect_uri`, the `code_verifier`
/// when PKCE is used, the client authentication values, the fixed pairs. Refresh body:
/// `grant_type=refresh_token`, `refresh_token`, the client authentication values, the fixed
/// pairs.
pub fn token_request(
    definition: &Definition,
    client: &ClientValues<'_>,
    grant: &TokenGrant<'_>,
) -> Result<OutboundRequest, ProtocolError> {
    let mut pairs: Vec<(&str, Field<'_>)> = Vec::new();
    match grant {
        TokenGrant::Exchange {
            code,
            redirect_uri,
            code_verifier,
        } => {
            pairs.push(("grant_type", Field::Plain("authorization_code")));
            pairs.push(("code", Field::Plain(code)));
            pairs.push(("redirect_uri", Field::Plain(redirect_uri)));
            if let Some(verifier) = code_verifier {
                pairs.push(("code_verifier", Field::Secret(&verifier.0)));
            }
        }
        TokenGrant::Refresh { refresh_token } => {
            pairs.push(("grant_type", Field::Plain("refresh_token")));
            pairs.push(("refresh_token", Field::Secret(refresh_token)));
        }
    }
    let mut headers = vec![
        OutboundHeader::plain("accept", "application/json"),
        OutboundHeader::plain("user-agent", "credential-enclave"),
    ];
    match definition.token.client_auth {
        ClientAuth::Body => {
            pairs.push(("client_id", client.client_id.field()));
            pairs.push(("client_secret", Field::Secret(client.client_secret)));
        }
        ClientAuth::None => pairs.push(("client_id", client.client_id.field())),
        ClientAuth::Basic => {}
    }
    for (key, value) in &definition.token.fixed {
        pairs.push((key, Field::Plain(value)));
    }
    for (name, value) in &definition.token.headers {
        headers.push(OutboundHeader::plain(name, value));
    }
    // The publishable key as a bearer takes precedence over HTTP Basic.
    if definition.token.bearer == "publishable_key" {
        headers.push(OutboundHeader::secret(
            "authorization",
            Secret::new(format!("Bearer {}", client.publishable_key)),
        ));
    } else if definition.token.client_auth == ClientAuth::Basic {
        headers.push(OutboundHeader::secret(
            "authorization",
            basic_credentials(client),
        ));
    }
    let body = match definition.token.body {
        BodyFormat::Form => {
            headers.push(OutboundHeader::plain(
                "content-type",
                "application/x-www-form-urlencoded",
            ));
            form_body(&pairs)
        }
        BodyFormat::Json => {
            headers.push(OutboundHeader::plain("content-type", "application/json"));
            json_body(&pairs)
        }
    };
    Ok(outbound(definition.token_destination()?, headers, body))
}

/// Builds the revocation address request (enclave.md 5.7): a form body with `token` and
/// `token_type_hint`, and the client authentication of the definition. `destination` is the
/// revocation address of the definition ([`Definition::revoke_destination`]): the request goes
/// there and to no other address.
pub fn revoke_request(
    revoke: &Revoke,
    destination: Destination,
    client: &ClientValues<'_>,
    token: &Secret<String>,
    token_type_hint: &str,
) -> OutboundRequest {
    let mut pairs: Vec<(&str, Field<'_>)> = vec![
        ("token", Field::Secret(token)),
        ("token_type_hint", Field::Plain(token_type_hint)),
    ];
    let mut headers = vec![
        OutboundHeader::plain("accept", "application/json"),
        OutboundHeader::plain("user-agent", "credential-enclave"),
        OutboundHeader::plain("content-type", "application/x-www-form-urlencoded"),
    ];
    if revoke.client_auth == ClientAuth::Body {
        pairs.push(("client_id", client.client_id.field()));
        pairs.push(("client_secret", Field::Secret(client.client_secret)));
    }
    if revoke.bearer == "publishable_key" {
        headers.push(OutboundHeader::secret(
            "authorization",
            Secret::new(format!("Bearer {}", client.publishable_key)),
        ));
    } else if revoke.client_auth == ClientAuth::Basic {
        headers.push(OutboundHeader::secret(
            "authorization",
            basic_credentials(client),
        ));
    }
    outbound(destination, headers, form_body(&pairs))
}

/// The error word of a refused token request (rule E5 of the egress policy).
///
/// The node reads the error string of the provider response and compares it with the list
/// below. The value that leaves the node is an element of the list, `other` for a string that
/// is not in it, or the empty string when the response has none. Each of them is a constant of
/// this source: no byte of a refused response leaves the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderError(&'static str);

impl ProviderError {
    /// The response carried no error string, or there was no response.
    pub const NONE: ProviderError = ProviderError("");
    /// The response carried an error string that the list does not hold.
    pub const OTHER: ProviderError = ProviderError("other");

    /// The words a node hands on. The last one is a sentence with a space: the error text of
    /// the token address of Link.
    pub const VOCABULARY: [&'static str; 38] = [
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

    /// The word for an error string of a provider.
    fn of(text: &str) -> ProviderError {
        if text.is_empty() {
            return ProviderError::NONE;
        }
        ProviderError::VOCABULARY
            .iter()
            .copied()
            .find(|word| *word == text)
            .map_or(ProviderError::OTHER, ProviderError)
    }

    /// The word as it is written into a failure response.
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// A refused or failed token address call: the HTTP status of the provider (0 for a transport
/// failure or a timeout) and the error word of its response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenFailure {
    pub status: u16,
    pub error: ProviderError,
}

/// The error word of a provider response (enclave.md 5.7): when the response is a JSON object,
/// a string `error`; when `error` is an object, its string `code`, else its string `message`;
/// without a usable `error`, the top-level string `code`. That string is mapped to the closed
/// vocabulary of [`ProviderError`].
fn provider_error(response: &Value) -> ProviderError {
    let Some(object) = response.as_object() else {
        return ProviderError::NONE;
    };
    let mut code = match object.get("error") {
        Some(Value::String(text)) => Some(text.as_str()),
        Some(Value::Object(nested)) => match nested.get("code").and_then(Value::as_str) {
            Some(text) if !text.is_empty() => Some(text),
            _ => nested.get("message").and_then(Value::as_str),
        },
        _ => None,
    };
    if code.is_none_or(str::is_empty) {
        code = object.get("code").and_then(Value::as_str);
    }
    ProviderError::of(code.unwrap_or_default())
}

/// The object that holds the tokens: the `token_container` object when the definition names
/// one and the value has it, else the value itself.
fn token_place<'a>(token: &'a Map<String, Value>, container: &str) -> &'a Map<String, Value> {
    if container.is_empty() {
        return token;
    }
    token
        .get(container)
        .and_then(Value::as_object)
        .unwrap_or(token)
}

fn text_at<'a>(token: &'a Map<String, Value>, container: &str, key: &str) -> Option<&'a str> {
    let nested = token_place(token, container)
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty());
    nested.or_else(|| {
        token
            .get(key)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
    })
}

/// The refresh token of a token object: in the token place first, then at the top level.
fn refresh_token_of<'a>(token: &'a Map<String, Value>, container: &str) -> Option<&'a str> {
    text_at(token, container, "refresh_token")
}

/// The access token of a token object: in the token place first, then at the top level.
fn access_token_of<'a>(token: &'a Map<String, Value>, container: &str) -> Option<&'a str> {
    text_at(token, container, "access_token")
}

fn lookup<'a>(token: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut keys = path.split('.');
    let first = token.get(keys.next()?)?;
    keys.try_fold(first, |current, key| current.as_object()?.get(key))
}

/// The token `forward` injects for an `oauth` record: the non-empty string at the first of the
/// paths of the definition.
fn inject_token<'a>(definition: &Definition, token: &'a Map<String, Value>) -> Option<&'a str> {
    definition.inject.paths.iter().find_map(|path| {
        lookup(token, path)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
    })
}

/// Calls the token address and judges the response (enclave.md 6.3): success is status 200, a
/// JSON object, a passed `ok_field` check and an `access_token` string in the token place.
///
/// The response body is a secret from the moment it was read. Of a refused call, only the
/// status and the error word leave this function.
pub async fn call_token_address(
    node: &Node,
    definition: &Definition,
    request: OutboundRequest,
) -> Result<TokenResponse, TokenFailure> {
    let transport = TokenFailure {
        status: 0,
        error: ProviderError::NONE,
    };
    let exchange = tokio::time::timeout(TOKEN_TIMEOUT, async {
        let exchange = node
            .egress
            .send_to_provider(node.platform.as_ref(), request)
            .await
            .map_err(|_| transport)?;
        let status = exchange.status;
        let body = exchange
            .read_body(TOKEN_RESPONSE_LIMIT_BYTES)
            .await
            .map(Secret::new)
            .map_err(|_| transport)?;
        Ok::<_, TokenFailure>((status, body))
    })
    .await;
    let (status, body) = match exchange {
        Ok(outcome) => outcome?,
        Err(_) => return Err(transport),
    };
    judge_token_response(definition, status, &body)
}

fn judge_token_response(
    definition: &Definition,
    status: u16,
    body: &Secret<Vec<u8>>,
) -> Result<TokenResponse, TokenFailure> {
    let Ok(parsed) = serde_json::from_slice::<Value>(body.expose_secret()) else {
        return Err(TokenFailure {
            status,
            error: ProviderError::NONE,
        });
    };
    let response = Secret::new(parsed);
    let failure = TokenFailure {
        status,
        error: provider_error(response.expose_secret()),
    };
    let Some(object) = response.expose_secret().as_object() else {
        return Err(failure);
    };
    let ok_field = &definition.token.ok_field;
    let refused = !ok_field.is_empty() && object.get(ok_field) == Some(&Value::Bool(false));
    if status != 200 || refused || access_token_of(object, &definition.token_container).is_none() {
        return Err(failure);
    }
    Ok(TokenResponse(response))
}

/// The refresh rule of protocol.md 8.3: the old token with the keys of the response written
/// over it. A response without `scope` keeps the old value, and a response without
/// `expires_in` removes that key. For a provider with a `token_container`, the `access_token`,
/// `refresh_token` and `expires_in` of the response are written into that place.
fn merge_refresh(
    old: &Map<String, Value>,
    response: &Map<String, Value>,
    container: &str,
) -> Map<String, Value> {
    let mut merged = old.clone();
    for (key, value) in response {
        if key == container && !container.is_empty() {
            continue;
        }
        merged.insert(key.clone(), value.clone());
    }
    let has_scope = response
        .get("scope")
        .and_then(Value::as_str)
        .is_some_and(|scope| !scope.is_empty());
    if !has_scope {
        match old.get("scope") {
            Some(scope) => merged.insert("scope".to_string(), scope.clone()),
            None => merged.shift_remove("scope"),
        };
    }
    if !response.contains_key("expires_in") {
        merged.shift_remove("expires_in");
    }
    if !container.is_empty() {
        let mut place = old
            .get(container)
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let nested = response.get(container).and_then(Value::as_object);
        if let Some(nested) = nested {
            for (key, value) in nested {
                place.insert(key.clone(), value.clone());
            }
        }
        let mut has_expiry = false;
        for key in ["access_token", "refresh_token", "expires_in"] {
            let value = nested
                .and_then(|nested| nested.get(key))
                .or_else(|| response.get(key));
            if let Some(value) = value {
                place.insert(key.to_string(), value.clone());
                has_expiry |= key == "expires_in";
            }
        }
        if !has_expiry {
            place.shift_remove("expires_in");
        }
        merged.insert(container.to_string(), Value::Object(place));
    }
    merged
}

/// The reconnect rule of protocol.md 8.3: a new token without a `refresh_token` takes the
/// `refresh_token` of the previous record, in the token place.
fn merge_reconnect(new: &mut Map<String, Value>, previous: &Map<String, Value>, container: &str) {
    if refresh_token_of(new, container).is_some() {
        return;
    }
    let Some(refresh_token) = refresh_token_of(previous, container) else {
        return;
    };
    let value = Value::String(refresh_token.to_string());
    let nested = if container.is_empty() {
        None
    } else {
        new.get_mut(container).and_then(Value::as_object_mut)
    };
    match nested {
        Some(place) => place.insert("refresh_token".to_string(), value),
        None => new.insert("refresh_token".to_string(), value),
    };
}

/// The value of a public field, when the response holds a value of its type within its limit
/// (rule E4). A value of another type, an object, an array and a longer string are left out.
fn public_leaf(field: &PublicField, value: &Value) -> Option<Value> {
    let fits = match (field.kind, value) {
        (FieldType::String, Value::String(text)) => field.max.is_some_and(|max| text.len() <= max),
        (FieldType::Integer, Value::Number(number)) => number.is_u64() || number.is_i64(),
        (FieldType::Integer, Value::String(text)) => {
            (1..=20).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_digit())
        }
        (FieldType::Boolean, Value::Bool(_)) => true,
        _ => false,
    };
    fits.then(|| value.clone())
}

/// The listed leaves of a token object, each at its own path in the same nested shape.
fn public_token(fields: &[PublicField], token: &Map<String, Value>) -> Map<String, Value> {
    let mut output = Map::new();
    for field in fields {
        if let Some(value) = lookup(token, &field.path).and_then(|value| public_leaf(field, value))
        {
            let keys: Vec<&str> = field.path.split('.').collect();
            insert_at(&mut output, &keys, value);
        }
    }
    output
}

/// Writes `value` at the path `keys` of `output`, creating the objects on the way.
fn insert_at(output: &mut Map<String, Value>, keys: &[&str], value: Value) {
    match keys {
        [] => {}
        [last] => {
            output.insert((*last).to_string(), value);
        }
        [first, rest @ ..] => {
            let nested = output
                .entry((*first).to_string())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(nested) = nested {
                insert_at(nested, rest, value);
            }
        }
    }
}

/// The listed claims of the `id_token` of a token object.
fn public_claims(fields: &[PublicField], token: &Map<String, Value>) -> Map<String, Value> {
    let mut claims = Map::new();
    if fields.is_empty() {
        return claims;
    }
    // The body of the JWT is read without verifying its signature: the TLS connection to the
    // token address vouches for where it came from.
    let body = token
        .get("id_token")
        .and_then(Value::as_str)
        .and_then(|jwt| jwt.split('.').nth(1))
        .and_then(|part| URL_SAFE_NO_PAD.decode(part.trim_end_matches('=')).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    if let Some(Value::Object(body)) = body {
        for field in fields {
            if let Some(value) = body
                .get(&field.path)
                .and_then(|value| public_leaf(field, value))
            {
                claims.insert(field.path.clone(), value);
            }
        }
    }
    claims
}

/// Collects the strings at `access_token`, `refresh_token` and `id_token` of a token object,
/// at the top level and in the token place.
fn token_strings<'a>(token: &'a Map<String, Value>, container: &str, tokens: &mut Vec<&'a str>) {
    let nested = if container.is_empty() {
        None
    } else {
        token.get(container).and_then(Value::as_object)
    };
    for place in std::iter::once(token).chain(nested) {
        for key in TOKEN_KEYS {
            if let Some(Value::String(text)) = place.get(key) {
                if !text.is_empty() {
                    tokens.push(text);
                }
            }
        }
    }
}

/// True when a string value of `fields`, at any depth, contains one of `tokens`.
fn carries_any(fields: &Map<String, Value>, tokens: &[&str], forms: &Forms) -> bool {
    fields.values().any(|value| match value {
        Value::String(text) => {
            tokens.iter().any(|token| text.contains(token)) || forms.found_in(text.as_bytes())
        }
        Value::Object(nested) => carries_any(nested, tokens, forms),
        _ => false,
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::egress::HeaderText;
    use crate::providers::Definitions;
    use serde_json::json;

    fn definition(name: &str) -> Definition {
        Definitions::embedded().get(name).unwrap().clone()
    }

    fn object(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    fn client_secret() -> Secret<String> {
        Secret::new("s3cr&t".to_string())
    }

    fn client(secret: &Secret<String>) -> ClientValues<'_> {
        ClientValues {
            client_id: ClientId::Configured("client id"),
            client_secret: secret,
            publishable_key: "pk_live_1",
        }
    }

    fn header(request: &OutboundRequest, name: &str) -> Option<String> {
        request
            .headers()
            .iter()
            .find(|header| header.name == name)
            .map(|header| match &header.value {
                HeaderText::Plain(text) => text.clone(),
                HeaderText::Secret(text) => text.expose_secret().clone(),
            })
    }

    fn body(request: &OutboundRequest) -> String {
        match request.body() {
            OutboundBody::Plain(bytes) => String::from_utf8(bytes.to_vec()).unwrap(),
            OutboundBody::Secret(bytes) => {
                String::from_utf8(bytes.expose_secret().clone()).unwrap()
            }
        }
    }

    /// A plaintext of kind `oauth` with the given token object, obtained at 77.
    fn issued(token: Value) -> OauthPlaintext {
        OauthPlaintext::from_parts(TokenKind::Issued, object(token), 77, None)
    }

    /// Public fields without a value, for the tests of other modules that need the type.
    pub fn empty_public_fields() -> PublicFields {
        PublicFields {
            token: Map::new(),
            id_token_claims: Map::new(),
            obtained_ms: 0,
            has_refresh_token: false,
        }
    }

    fn public(definition: &Definition, token: Value) -> Value {
        serde_json::to_value(issued(token).public_fields(definition, None).unwrap()).unwrap()
    }

    #[test]
    fn percent_encoding_keeps_unreserved_characters_only() {
        assert_eq!(percent_encode("AZaz09-._~"), "AZaz09-._~");
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("a+b&c=d/e?f#g"), "a%2Bb%26c%3Dd%2Fe%3Ff%23g");
        assert_eq!(percent_encode("한"), "%ED%95%9C");
        assert_eq!(
            percent_encode("https://a.example/cb"),
            "https%3A%2F%2Fa.example%2Fcb"
        );
    }

    #[test]
    fn the_authorization_address_has_the_fixed_parameter_order() {
        let google = definition("google_workspace");
        let params = check_params(
            &google,
            &object(json!({
                "scope": "openid https://www.googleapis.com/auth/gmail.readonly",
                "prompt": "consent select_account",
                "access_type": "offline",
                "include_granted_scopes": "true",
            })),
        )
        .unwrap();
        let url = authorization_url(
            &google,
            "client.apps.example",
            "https://api.example/api/integrations/google_workspace/oauth/callback",
            "bm9kZQ.operator-state",
            Some("challenge-value"),
            "",
            &params,
        );
        assert_eq!(
            url,
            concat!(
                "https://accounts.google.com/o/oauth2/v2/auth",
                "?response_type=code",
                "&client_id=client.apps.example",
                "&redirect_uri=https%3A%2F%2Fapi.example%2Fapi%2Fintegrations%2Fgoogle_workspace%2Foauth%2Fcallback",
                "&state=bm9kZQ.operator-state",
                "&code_challenge=challenge-value",
                "&code_challenge_method=S256",
                "&access_type=offline",
                "&include_granted_scopes=true",
                "&prompt=consent%20select_account",
                "&scope=openid%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.readonly"
            )
        );
    }

    #[test]
    fn fixed_pairs_and_the_publishable_key_come_before_the_caller_parameters() {
        let notion = definition("notion");
        let url = authorization_url(
            &notion,
            "c",
            "https://a/cb",
            "s.o",
            None,
            "",
            &BTreeMap::new(),
        );
        assert_eq!(
            url,
            "https://api.notion.com/v1/oauth/authorize?response_type=code&client_id=c&redirect_uri=https%3A%2F%2Fa%2Fcb&state=s.o&owner=user"
        );
        let link = definition("link");
        let params = check_params(&link, &object(json!({"scope": "a b"}))).unwrap();
        let url = authorization_url(
            &link,
            "c",
            "https://a/cb",
            "s.o",
            Some("ch"),
            "pk_1",
            &params,
        );
        assert!(url.ends_with("&code_challenge=ch&code_challenge_method=S256&key=pk_1&scope=a%20b"));
        let granola = definition("granola");
        let url = authorization_url(
            &granola,
            "dyn",
            "https://a/cb",
            "s.o",
            Some("ch"),
            "",
            &BTreeMap::new(),
        );
        assert!(url
            .ends_with("&code_challenge_method=S256&resource=https%3A%2F%2Fmcp.granola.ai%2Fmcp"));
    }

    #[test]
    fn parameters_outside_the_definition_are_not_allowed() {
        let google = definition("google_workspace");
        let denied = [
            json!({"redirect_uri": "https://evil.example"}),
            json!({"state": "x"}),
            json!({"client_id": "x"}),
            json!({"response_type": "token"}),
            json!({"hd": "example.com"}),
            json!({"scope": 5}),
            json!({"scope": "a\nb"}),
            json!({"scope": "s".repeat(1025)}),
        ];
        for params in denied {
            assert_eq!(
                check_params(&google, &object(params.clone())),
                Err(ProtocolError::NotAllowed),
                "{params}"
            );
        }
        assert!(check_params(&google, &object(json!({"scope": "s".repeat(1024)}))).is_ok());
        assert!(check_params(&definition("notion"), &object(json!({}))).is_ok());
        assert_eq!(
            check_params(
                &definition("notion"),
                &object(json!({"owner": "workspace"}))
            ),
            Err(ProtocolError::NotAllowed)
        );
    }

    #[test]
    fn a_definition_with_scopes_limits_the_requested_scopes() {
        let mut slack = definition("slack");
        slack.scopes = Some(vec!["chat:write".to_string(), "users:read".to_string()]);
        assert!(check_params(
            &slack,
            &object(json!({"user_scope": "chat:write,users:read"}))
        )
        .is_ok());
        assert_eq!(
            check_params(&slack, &object(json!({"user_scope": "chat:write,admin"}))),
            Err(ProtocolError::NotAllowed)
        );
    }

    #[test]
    fn the_challenge_of_a_verifier_is_its_s256_hash() {
        let verifier = PkceVerifier::new(&Secret::new([0x5a; 32]));
        let text = b64u(&[0x5a; 32]);
        assert_eq!(text.len(), 43);
        assert_eq!(verifier.challenge(), b64u(&Sha256::digest(text.as_bytes())));
        // The verifier reaches the token request and nothing else.
        let secret = client_secret();
        let request = token_request(
            &definition("google_workspace"),
            &client(&secret),
            &TokenGrant::Exchange {
                code: "c",
                redirect_uri: "https://a.example/cb",
                code_verifier: Some(&verifier),
            },
        )
        .unwrap();
        assert!(body(&request).contains(&format!("&code_verifier={text}&")));
    }

    #[test]
    fn a_form_exchange_carries_the_client_values_in_the_body() {
        let google = definition("google_workspace");
        let secret = client_secret();
        let verifier = PkceVerifier::new(&Secret::new([0x01; 32]));
        let request = token_request(
            &google,
            &client(&secret),
            &TokenGrant::Exchange {
                code: "4/code",
                redirect_uri: "https://a.example/cb",
                code_verifier: Some(&verifier),
            },
        )
        .unwrap();
        assert_eq!(request.host(), "oauth2.googleapis.com");
        assert_eq!(request.method(), "POST");
        assert_eq!(request.target(), "/token");
        assert_eq!(
            body(&request),
            format!(
                concat!(
                    "grant_type=authorization_code&code=4%2Fcode",
                    "&redirect_uri=https%3A%2F%2Fa.example%2Fcb&code_verifier={}",
                    "&client_id=client%20id&client_secret=s3cr%26t"
                ),
                b64u(&[0x01; 32])
            )
        );
        assert!(matches!(request.body(), OutboundBody::Secret(_)));
        assert_eq!(
            header(&request, "content-type").as_deref(),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(header(&request, "authorization"), None);
    }

    #[test]
    fn basic_json_and_bearer_variants_follow_the_definition() {
        let secret = client_secret();
        let refresh_token = Secret::new("r".to_string());
        let notion = definition("notion");
        let request = token_request(
            &notion,
            &client(&secret),
            &TokenGrant::Exchange {
                code: "c",
                redirect_uri: "https://a.example/cb",
                code_verifier: None,
            },
        )
        .unwrap();
        assert_eq!(
            body(&request),
            r#"{"grant_type":"authorization_code","code":"c","redirect_uri":"https://a.example/cb"}"#
        );
        assert_eq!(
            header(&request, "content-type").as_deref(),
            Some("application/json")
        );
        assert_eq!(
            header(&request, "Notion-Version").as_deref(),
            Some("2025-09-03")
        );
        assert_eq!(
            header(&request, "authorization"),
            Some(format!("Basic {}", STANDARD.encode("client id:s3cr&t")))
        );
        // A header that carries the client secret is a secret of the request.
        assert!(request.headers().iter().any(|header| {
            header.name == "authorization" && matches!(header.value, HeaderText::Secret(_))
        }));

        let x = definition("x");
        let request = token_request(
            &x,
            &client(&secret),
            &TokenGrant::Refresh {
                refresh_token: &refresh_token,
            },
        )
        .unwrap();
        assert_eq!(body(&request), "grant_type=refresh_token&refresh_token=r");
        assert!(header(&request, "authorization")
            .unwrap()
            .starts_with("Basic "));

        let link = definition("link");
        let request = token_request(
            &link,
            &client(&secret),
            &TokenGrant::Refresh {
                refresh_token: &refresh_token,
            },
        )
        .unwrap();
        assert_eq!(
            body(&request),
            "grant_type=refresh_token&refresh_token=r&client_id=client%20id&client_secret=s3cr%26t"
        );
        assert_eq!(
            header(&request, "authorization").as_deref(),
            Some("Bearer pk_live_1")
        );

        // A dynamically registered client refreshes with the client id its record holds.
        let granola = definition("granola");
        let recorded = Secret::new("recorded client".to_string());
        let request = token_request(
            &granola,
            &ClientValues {
                client_id: ClientId::Recorded(&recorded),
                client_secret: &secret,
                publishable_key: "",
            },
            &TokenGrant::Refresh {
                refresh_token: &refresh_token,
            },
        )
        .unwrap();
        assert_eq!(
            body(&request),
            "grant_type=refresh_token&refresh_token=r&client_id=recorded%20client&resource=https%3A%2F%2Fmcp.granola.ai%2Fmcp"
        );
        assert_eq!(header(&request, "authorization"), None);
    }

    #[test]
    fn revocation_requests_follow_the_definition() {
        let secret = client_secret();
        let token = Secret::new("tok".to_string());
        let google = definition("google_workspace");
        let request = revoke_request(
            google.revoke.as_ref().unwrap(),
            google.revoke_destination().unwrap(),
            &client(&secret),
            &token,
            "refresh_token",
        );
        assert_eq!(request.host(), "oauth2.googleapis.com");
        assert_eq!(request.target(), "/revoke");
        assert_eq!(body(&request), "token=tok&token_type_hint=refresh_token");
        assert_eq!(header(&request, "authorization"), None);

        let x = definition("x");
        let request = revoke_request(
            x.revoke.as_ref().unwrap(),
            x.revoke_destination().unwrap(),
            &client(&secret),
            &token,
            "access_token",
        );
        assert_eq!(body(&request), "token=tok&token_type_hint=access_token");
        assert!(header(&request, "authorization")
            .unwrap()
            .starts_with("Basic "));

        let link = definition("link");
        let request = revoke_request(
            link.revoke.as_ref().unwrap(),
            link.revoke_destination().unwrap(),
            &client(&secret),
            &token,
            "refresh_token",
        );
        assert_eq!(
            body(&request),
            "token=tok&token_type_hint=refresh_token&client_id=client%20id&client_secret=s3cr%26t"
        );
        assert_eq!(
            header(&request, "authorization").as_deref(),
            Some("Bearer pk_live_1")
        );
    }

    #[test]
    fn the_provider_error_is_a_word_of_the_closed_vocabulary() {
        let word = |response: Value| provider_error(&response).as_str();
        // The error string is read by the rule of enclave.md 5.7.
        assert_eq!(
            word(json!({"error": "invalid_grant", "error_description": "x"})),
            "invalid_grant"
        );
        assert_eq!(
            word(json!({"error": {"code": "token_expired", "message": "m"}})),
            "token_expired"
        );
        assert_eq!(
            word(json!({"error": {"message": "refresh_token not found"}})),
            "refresh_token not found"
        );
        assert_eq!(
            word(json!({"object": "error", "code": "unauthorized", "message": "m"})),
            "unauthorized"
        );
        assert_eq!(
            word(json!({"ok": false, "error": "invalid_auth"})),
            "invalid_auth"
        );
        // A string that is not in the list leaves as `other`, whatever it holds.
        assert_eq!(
            word(json!({"error": {"code": "", "message": "m"}})),
            "other"
        );
        assert_eq!(word(json!({"error": "", "code": "fallback"})), "other");
        assert_eq!(word(json!({"error": "invalid_grant "})), "other");
        assert_eq!(word(json!({"error": "INVALID_GRANT"})), "other");
        assert_eq!(
            word(json!({"error": "1//refresh-token-in-the-error-field"})),
            "other"
        );
        // No error string: the empty word.
        assert_eq!(word(json!({"error": 5})), "");
        assert_eq!(word(json!({"message": "only a message"})), "");
        assert_eq!(word(json!(["error"])), "");
        assert_eq!(word(json!("error")), "");
        // Every word of the vocabulary maps to itself, and the two special words are not in it.
        for listed in ProviderError::VOCABULARY {
            assert_eq!(word(json!({"error": listed})), listed);
            assert!(!listed.is_empty() && listed != "other");
        }
        assert_eq!(ProviderError::VOCABULARY.len(), 38);
        assert_eq!(ProviderError::NONE.as_str(), "");
        assert_eq!(ProviderError::OTHER.as_str(), "other");
    }

    #[test]
    fn a_refused_token_response_gives_its_status_and_word_only() {
        let google = definition("google_workspace");
        let judge = |status: u16, text: &str| {
            judge_token_response(&google, status, &Secret::new(text.as_bytes().to_vec()))
                .map(|_| ())
        };
        assert_eq!(
            judge(
                400,
                r#"{"error":"invalid_grant","error_description":"1//refresh-token"}"#
            ),
            Err(TokenFailure {
                status: 400,
                error: ProviderError("invalid_grant"),
            })
        );
        assert_eq!(
            judge(400, r#"{"error":"1//refresh-token"}"#),
            Err(TokenFailure {
                status: 400,
                error: ProviderError::OTHER,
            })
        );
        assert_eq!(
            judge(502, "<html>bad gateway</html>"),
            Err(TokenFailure {
                status: 502,
                error: ProviderError::NONE,
            })
        );
        // A 200 response without an access token is a failure.
        assert_eq!(
            judge(200, r#"{"token_type":"Bearer"}"#),
            Err(TokenFailure {
                status: 200,
                error: ProviderError::NONE,
            })
        );
        assert_eq!(judge(200, r#"{"access_token":"ya29.a"}"#), Ok(()));
        // Slack answers a refusal with status 200 and `ok: false`.
        let slack = definition("slack");
        assert_eq!(
            judge_token_response(
                &slack,
                200,
                &Secret::new(br#"{"ok":false,"error":"invalid_code"}"#.to_vec())
            )
            .map(|_| ()),
            Err(TokenFailure {
                status: 200,
                error: ProviderError("invalid_code"),
            })
        );
    }

    #[test]
    fn a_refresh_overlays_the_response_and_applies_the_scope_and_expiry_rules() {
        let old = object(json!({
            "access_token": "old-access",
            "refresh_token": "old-refresh",
            "expires_in": 3600,
            "scope": "a b",
            "token_type": "Bearer",
            "id_token": "old.id.token",
        }));
        // A response with a new expiry, without scope and without refresh token.
        let merged = merge_refresh(
            &old,
            &object(
                json!({"access_token": "new-access", "expires_in": 1800, "token_type": "Bearer"}),
            ),
            "",
        );
        assert_eq!(
            Value::Object(merged),
            json!({
                "access_token": "new-access",
                "refresh_token": "old-refresh",
                "expires_in": 1800,
                "scope": "a b",
                "token_type": "Bearer",
                "id_token": "old.id.token",
            })
        );
        // A response without expires_in removes the key. A rotated refresh token and a new
        // scope replace the old values. An empty scope counts as absent.
        let merged = merge_refresh(
            &old,
            &object(json!({"access_token": "n", "refresh_token": "rotated", "scope": "a"})),
            "",
        );
        assert_eq!(merged.get("expires_in"), None);
        assert_eq!(merged["refresh_token"], "rotated");
        assert_eq!(merged["scope"], "a");
        let merged = merge_refresh(&old, &object(json!({"access_token": "n", "scope": ""})), "");
        assert_eq!(merged["scope"], "a b");
    }

    #[test]
    fn a_refresh_of_a_nested_token_writes_into_the_container() {
        let old = object(json!({
            "ok": true,
            "app_id": "A1",
            "team": {"id": "T1", "name": "Team"},
            "authed_user": {
                "id": "U1",
                "scope": "chat:write",
                "access_token": "xoxe.xoxp-old",
                "refresh_token": "xoxe-1-old",
                "expires_in": 43200,
                "token_type": "user",
            },
        }));
        // Slack answers a refresh with a flat object.
        let response = object(json!({
            "ok": true,
            "access_token": "xoxe.xoxp-new",
            "refresh_token": "xoxe-1-new",
            "expires_in": 43000,
            "token_type": "user",
        }));
        let merged = merge_refresh(&old, &response, "authed_user");
        assert_eq!(
            merged["authed_user"],
            json!({
                "id": "U1",
                "scope": "chat:write",
                "access_token": "xoxe.xoxp-new",
                "refresh_token": "xoxe-1-new",
                "expires_in": 43000,
                "token_type": "user",
            })
        );
        assert_eq!(merged["team"], json!({"id": "T1", "name": "Team"}));
        let slack = definition("slack");
        assert_eq!(inject_token(&slack, &merged), Some("xoxe.xoxp-new"));
        // A response that nests the tokens itself is merged into the same place, and a
        // response without expires_in removes the key from the container.
        let nested = object(
            json!({"ok": true, "authed_user": {"access_token": "a2", "refresh_token": "r2"}}),
        );
        let merged = merge_refresh(&old, &nested, "authed_user");
        assert_eq!(merged["authed_user"]["access_token"], "a2");
        assert_eq!(merged["authed_user"]["id"], "U1");
        assert_eq!(merged["authed_user"].get("expires_in"), None);
    }

    #[test]
    fn a_reconnect_without_a_refresh_token_takes_the_previous_one() {
        let previous = object(json!({"access_token": "a1", "refresh_token": "r1"}));
        let mut new = object(json!({"access_token": "a2"}));
        merge_reconnect(&mut new, &previous, "");
        assert_eq!(new["refresh_token"], "r1");
        assert_eq!(new["access_token"], "a2");
        // A new refresh token is kept.
        let mut new = object(json!({"access_token": "a2", "refresh_token": "r2"}));
        merge_reconnect(&mut new, &previous, "");
        assert_eq!(new["refresh_token"], "r2");
        // Nested place.
        let previous =
            object(json!({"authed_user": {"access_token": "a1", "refresh_token": "r1"}}));
        let mut new = object(json!({"authed_user": {"access_token": "a2"}}));
        merge_reconnect(&mut new, &previous, "authed_user");
        assert_eq!(new["authed_user"]["refresh_token"], "r1");
        assert_eq!(new.get("refresh_token"), None);
        // Nothing to take.
        let mut new = object(json!({"access_token": "a2"}));
        merge_reconnect(&mut new, &object(json!({"access_token": "a1"})), "");
        assert_eq!(new.get("refresh_token"), None);
    }

    fn jwt(claims: Value) -> String {
        format!(
            "{}.{}.signature",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    }

    #[test]
    fn public_fields_carry_only_the_listed_leaves() {
        let google = definition("google_workspace");
        let token = json!({
            "access_token": "ya29.secret-access",
            "refresh_token": "1//secret-refresh",
            "expires_in": 3599,
            "scope": "openid email",
            "token_type": "Bearer",
            "id_token": jwt(json!({
                "sub": "1", "email": "a@example.com", "email_verified": true,
                "at_hash": "hash", "aud": "client", "name": "A",
            })),
            "unexpected": "value",
        });
        let public = public(&google, token);
        assert_eq!(
            public,
            json!({
                "token": {"scope": "openid email", "expires_in": 3599, "token_type": "Bearer"},
                "id_token_claims": {"sub": "1", "email": "a@example.com", "email_verified": true, "name": "A"},
                "obtained_ms": 77,
                "has_refresh_token": true,
            })
        );
        let text = public.to_string();
        for secret in [
            "ya29.secret-access",
            "1//secret-refresh",
            "at_hash",
            "unexpected",
            "id_token\"",
        ] {
            assert!(!text.contains(secret), "{secret}");
        }
        assert_eq!(
            text,
            concat!(
                r#"{"token":{"scope":"openid email","expires_in":3599,"token_type":"Bearer"},"#,
                r#""id_token_claims":{"sub":"1","email":"a@example.com","email_verified":true,"name":"A"},"#,
                r#""obtained_ms":77,"has_refresh_token":true}"#
            )
        );
    }

    #[test]
    fn nested_public_leaves_keep_their_place_and_objects_do_not_leave() {
        let slack = definition("slack");
        let token = json!({
            "ok": true,
            "app_id": "A1",
            "team": {"id": "T1", "name": "Team", "internal": "not listed"},
            "enterprise": null,
            "is_enterprise_install": false,
            "authed_user": {
                "id": "U1", "scope": "chat:write", "access_token": "xoxp-secret-access",
                "refresh_token": "xoxe-secret-refresh", "expires_in": 43200, "token_type": "user",
            },
            "access_token": "xoxb-secret-bot",
            "scope": "bot:scope",
        });
        let fields = issued(token).public_fields(&slack, None).unwrap();
        assert_eq!(fields.scope(&slack), "chat:write");
        let public = serde_json::to_value(&fields).unwrap();
        assert_eq!(
            public["token"],
            json!({
                "team": {"id": "T1", "name": "Team"},
                "app_id": "A1",
                "is_enterprise_install": false,
                "authed_user": {"id": "U1", "scope": "chat:write", "expires_in": 43200, "token_type": "user"},
            })
        );
        assert_eq!(public["id_token_claims"], json!({}));
        assert_eq!(public["has_refresh_token"], true);
        assert!(!public.to_string().contains("secret"));

        // Notion: the leaves under `owner` are listed one by one.
        let notion = definition("notion");
        let public = self::public(
            &notion,
            json!({
                "access_token": "ntn_secret-access",
                "workspace_id": "W1",
                "workspace_name": "Space",
                "bot_id": "B1",
                "owner": {
                    "type": "user",
                    "user": {
                        "object": "user", "id": "N1", "name": "N", "type": "person",
                        "person": {"email": "n@example.com"},
                        "access_token": "ntn_nested-secret",
                    },
                },
            }),
        );
        assert_eq!(
            public["token"],
            json!({
                "workspace_id": "W1",
                "workspace_name": "Space",
                "bot_id": "B1",
                "owner": {
                    "type": "user",
                    "user": {"id": "N1", "name": "N", "type": "person", "person": {"email": "n@example.com"}},
                },
            })
        );
        assert!(!public.to_string().contains("secret"));
    }

    #[test]
    fn a_public_leaf_of_another_type_or_above_its_limit_is_left_out() {
        let google = definition("google_workspace");
        // A string field that holds an object, an array or a number, and a string above its
        // limit, are left out. The call does not fail.
        for scope in [
            json!({"nested": "x"}),
            json!(["a", "b"]),
            json!(5),
            json!(null),
            json!("s".repeat(8193)),
        ] {
            let public = public(
                &google,
                json!({"access_token": "ya29.long-access", "scope": scope, "token_type": "Bearer"}),
            );
            assert_eq!(public["token"], json!({"token_type": "Bearer"}), "{scope}");
        }
        let public = self::public(
            &google,
            json!({"access_token": "ya29.long-access", "scope": "s".repeat(8192)}),
        );
        assert_eq!(public["token"]["scope"].as_str().unwrap().len(), 8192);
        // An integer is a JSON integer or a string of 1 to 20 digits.
        for (expires_in, kept) in [
            (json!(3599), true),
            (json!("3599"), true),
            (json!("1".repeat(20)), true),
            (json!(0), true),
            (json!(3599.5), false),
            (json!("3599s"), false),
            (json!(""), false),
            (json!("1".repeat(21)), false),
            (json!(true), false),
            (json!({"n": 1}), false),
        ] {
            let public = self::public(
                &google,
                json!({"access_token": "ya29.long-access", "expires_in": expires_in}),
            );
            assert_eq!(
                public["token"].get("expires_in").is_some(),
                kept,
                "{expires_in}"
            );
        }
        // A boolean claim is a JSON boolean.
        let claims = |email_verified: Value| {
            self::public(
                &google,
                json!({
                    "access_token": "ya29.long-access",
                    "id_token": jwt(json!({"sub": "1", "email_verified": email_verified})),
                }),
            )["id_token_claims"]
                .clone()
        };
        assert_eq!(
            claims(json!(true)),
            json!({"sub": "1", "email_verified": true})
        );
        assert_eq!(claims(json!("true")), json!({"sub": "1"}));
        assert_eq!(claims(json!({"x": 1})), json!({"sub": "1"}));
    }

    #[test]
    fn public_fields_that_contain_a_token_are_withheld() {
        let google = definition("google_workspace");
        let withheld = |token: Value| issued(token).public_fields(&google, None) == Err(Withheld);
        // The provider put a token into a listed field.
        assert!(withheld(json!({
            "access_token": "ya29.access-token-value",
            "scope": "openid ya29.access-token-value",
        })));
        assert!(withheld(json!({
            "access_token": "ya29.access-token-value",
            "refresh_token": "1//refresh-token-value",
            "token_type": "1//refresh-token-value",
        })));
        // The provider put a token into a listed claim.
        assert!(withheld(json!({
            "access_token": "ya29.access-token-value",
            "refresh_token": "1//refresh-token-value",
            "id_token": jwt(json!({"sub": "1", "email": "x 1//refresh-token-value y"})),
        })));
        // The raw id_token inside a listed field.
        let id_token = jwt(json!({"sub": "1"}));
        assert!(withheld(json!({
            "access_token": "ya29.access-token-value",
            "id_token": id_token,
            "scope": id_token,
        })));
        // A token of the token place of a nested provider.
        let slack = definition("slack");
        assert_eq!(
            issued(json!({
                "ok": true,
                "team": {"id": "T1", "name": "xoxp-user-token-value"},
                "authed_user": {"id": "U1", "access_token": "xoxp-user-token-value"},
            }))
            .public_fields(&slack, None),
            Err(Withheld)
        );
        // A response without such a field passes.
        assert!(!withheld(json!({
            "access_token": "ya29.access-token-value",
            "refresh_token": "1//refresh-token-value",
            "scope": "openid email",
            "token_type": "Bearer",
        })));
        // A refresh: the tokens of the response count as well as those of the merged object.
        let old = issued(json!({
            "access_token": "ya29.old-access",
            "refresh_token": "1//old-refresh",
            "scope": "openid",
        }));
        let response = TokenResponse(Secret::new(json!({
            "access_token": "ya29.new-access",
            "refresh_token": "1//rotated-refresh",
            "scope": "openid 1//rotated-refresh",
        })));
        let renewed = old.refreshed(&response, "", 78);
        assert_eq!(
            renewed.public_fields(&google, Some(&response)),
            Err(Withheld)
        );
    }

    #[test]
    fn a_missing_or_broken_id_token_gives_no_claims() {
        let google = definition("google_workspace");
        for token in [
            json!({"access_token": "ya29.long-access"}),
            json!({"access_token": "ya29.long-access", "id_token": "not-a-jwt"}),
            json!({"access_token": "ya29.long-access", "id_token": "a.%%%.c"}),
            json!({"access_token": "ya29.long-access", "id_token": 5}),
        ] {
            let public = public(&google, token);
            assert_eq!(public["id_token_claims"], json!({}));
            assert_eq!(public["has_refresh_token"], false);
        }
    }

    #[test]
    fn the_injected_token_is_at_the_first_path_that_exists() {
        let slack = definition("slack");
        assert_eq!(
            inject_token(&slack, &object(json!({"access_token": "xoxb"}))),
            Some("xoxb")
        );
        assert_eq!(
            inject_token(
                &slack,
                &object(json!({"authed_user": {"access_token": "xoxp"}, "access_token": "xoxb"}))
            ),
            Some("xoxp")
        );
        assert_eq!(
            inject_token(&slack, &object(json!({"authed_user": {"id": "U1"}}))),
            None
        );
        assert_eq!(
            inject_token(&slack, &object(json!({"access_token": ""}))),
            None
        );
        // The credential is the token, and the header value is the prefix and the token.
        let (header, token) = issued(json!({"access_token": "xoxb-token"}))
            .credential(&slack)
            .unwrap()
            .into_parts();
        assert_eq!(header.expose_secret(), "Bearer xoxb-token");
        assert_eq!(token.expose_secret(), "xoxb-token");
        assert!(issued(json!({"token_type": "Bearer"}))
            .credential(&slack)
            .is_none());
    }

    #[test]
    fn a_plaintext_keeps_its_kind_and_its_key_order() {
        // A token response becomes a plaintext of kind `oauth`, with `client_id` for a
        // dynamically registered client.
        let response = TokenResponse(Secret::new(json!({"access_token": "ya29.long-access"})));
        let plaintext = response.into_plaintext(5, Some("dyn-client"));
        assert_eq!(plaintext.kind, TokenKind::Issued);
        assert_eq!(
            String::from_utf8(to_json(plaintext.plaintext.expose_secret())).unwrap(),
            r#"{"token":{"access_token":"ya29.long-access"},"obtained_ms":5,"client_id":"dyn-client"}"#
        );
        assert_eq!(plaintext.client_id().unwrap().expose_secret(), "dyn-client");
        // An imported plaintext stays imported through a refresh.
        let imported = OauthPlaintext::from_parts(
            TokenKind::Imported,
            object(json!({"access_token": "ya29.old-access", "refresh_token": "1//old-refresh"})),
            1,
            None,
        );
        let response = TokenResponse(Secret::new(json!({"access_token": "ya29.new-access"})));
        let renewed = imported.refreshed(&response, "", 9);
        assert_eq!(renewed.kind, TokenKind::Imported);
        assert_eq!(TokenKind::Imported.kind(), Kind::OauthImported);
        assert_eq!(TokenKind::Issued.kind(), Kind::Oauth);
        assert_eq!(
            renewed.refresh_token("").unwrap().expose_secret(),
            "1//old-refresh"
        );
        let (token, hint) = renewed.revocation_token("").unwrap();
        assert_eq!(
            (token.expose_secret().as_str(), hint),
            ("1//old-refresh", "refresh_token")
        );
        let (token, hint) = issued(json!({"access_token": "ya29.only-access"}))
            .revocation_token("")
            .unwrap();
        assert_eq!(
            (token.expose_secret().as_str(), hint),
            ("ya29.only-access", "access_token")
        );
        for kind in [Kind::VaultPassword, Kind::VaultTotp, Kind::VaultCard] {
            assert_eq!(TokenKind::of(kind), None);
        }
    }
}
