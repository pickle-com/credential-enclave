//! The call surface of a node (enclave.md sections 4 and 5): the router, the failure
//! responses and the helpers every call shares.
//!
//! The caller is the operator domain and is not trusted. A call succeeds with 200. A failure
//! is a status of the table in enclave.md section 4 with the body
//! `{"code": "<code of protocol.md section 11>", "message": "..."}`.

use std::pin::Pin;
use std::sync::Arc;

use axum::extract::Request;
use axum::http::header::CONTENT_LENGTH;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{on, MethodFilter, MethodRouter};
use axum::Router;
use credential_enclave_protocol::encoding::wipe_json;
use credential_enclave_protocol::{is_valid_name, limits, ProtocolError};
use hyper::body::Body as HttpBody;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use zeroize::Zeroizing;

use crate::oauth::{ProviderError, Withheld};
use crate::platform::{Listener, PlatformError};
use crate::providers::{ClientKind, Definition};
use crate::state::{Node, OperatorConfig, ProviderCredentials};
use credential_enclave_protocol::record::Record;

mod attestation;
mod close;
mod config;
mod forward;
mod health;
mod log;
mod log_store;
mod mail;
mod messages;
mod oauth;
mod peer;
mod refresh;
mod release;
pub mod responses;
mod revoke;
mod status;

pub use responses::json_ok;
use responses::{json_error, ErrorBody};

/// Body limit of a call whose body is JSON: 1 MiB.
const JSON_BODY_LIMIT_BYTES: usize = 1024 * 1024;

type Route = (Method, &'static str, MethodRouter<Arc<Node>>);

fn route<H, T>(method: Method, path: &'static str, handler: H) -> Route
where
    H: axum::handler::Handler<T, Arc<Node>>,
    T: 'static,
{
    let filter = MethodFilter::try_from(method.clone()).expect("a route method is GET or POST");
    (method, path, on(filter, handler))
}

/// Every call of a node: its method, its path and its handler. The router is built from this
/// table, and so is the list a test compares with the table of `docs/egress-policy.md`.
fn routes() -> Vec<Route> {
    vec![
        route(Method::GET, "/v1/health", health::health),
        route(Method::POST, "/v1/config", config::config),
        route(Method::POST, "/v1/attestation", attestation::attestation),
        route(Method::POST, "/v1/messages", messages::messages),
        route(Method::POST, "/v1/status", status::status),
        route(Method::POST, "/v1/oauth/begin", oauth::begin),
        route(Method::POST, "/v1/oauth/complete", oauth::complete),
        route(Method::POST, "/v1/oauth/merge", oauth::merge),
        route(Method::POST, "/v1/refresh", refresh::refresh),
        route(Method::POST, "/v1/revoke-token", revoke::revoke_token),
        route(Method::POST, "/v1/forward", forward::forward),
        route(Method::POST, "/v1/mail/verify", mail::verify),
        route(Method::POST, "/v1/mail/read", mail::read),
        route(Method::POST, "/v1/mail/submit", mail::submit),
        route(Method::POST, "/v1/release", release::release),
        route(Method::POST, "/v1/log/entries", log::entries),
        route(Method::POST, "/v1/log/ack", log::ack),
        route(Method::POST, "/v1/close", close::close),
        route(Method::POST, "/v1/close/heads", close::heads),
        route(Method::POST, "/v1/peer/export", peer::export),
        route(Method::POST, "/v1/peer/import", peer::import),
        route(
            Method::POST,
            "/v1/log-store/credentials",
            log_store::credentials,
        ),
    ]
}

/// The method and the path of every call, in the order of [`routes`]. The tests compare it
/// with the table of `docs/egress-policy.md` and with the calls the canary tests make.
#[cfg(test)]
pub fn route_list() -> Vec<(Method, &'static str)> {
    routes()
        .into_iter()
        .map(|(method, path, _)| (method, path))
        .collect()
}

/// The router of every call.
pub fn router(node: Arc<Node>) -> Router {
    let mut router = Router::new();
    for (_, path, handler) in routes() {
        router = router.route(path, handler);
    }
    router
        .fallback(unknown_route)
        .method_not_allowed_fallback(unknown_method)
        .with_state(node)
}

async fn unknown_route() -> Response {
    ApiError {
        status: StatusCode::NOT_FOUND,
        code: ProtocolError::InvalidRequest.code(),
        message: "no such call",
        provider: None,
    }
    .into_response()
}

async fn unknown_method() -> Response {
    ApiError {
        status: StatusCode::METHOD_NOT_ALLOWED,
        code: ProtocolError::InvalidRequest.code(),
        message: "the call does not accept this method",
        provider: None,
    }
    .into_response()
}

/// Serves HTTP/1.1 on every connection of the listener. A call in progress runs to its end:
/// nothing here cancels a connection.
pub async fn serve(listener: Listener, router: Router) {
    loop {
        let stream = match listener.accept().await {
            Ok(stream) => stream,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let service = TowerToHyperService::new(router.clone());
        tokio::spawn(async move {
            // No `Date` header: it would be the only value a node takes from the system
            // clock instead of its own clock.
            let _ = hyper::server::conn::http1::Builder::new()
                .auto_date_header(false)
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

/// A failed call (rule E5 of the egress policy). The code is one of the closed list of
/// protocol.md section 11, the message is a fixed string of this source, and what a provider
/// said is reduced to its HTTP status and a word of a closed vocabulary. A failure never
/// carries a credential, a key, a body or the query string of an address.
#[derive(Debug, PartialEq, Eq)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: &'static str,
    /// `provider_status` and `provider_error` of `exchange_failed` and `refresh_failed`.
    pub provider: Option<(u16, ProviderError)>,
}

/// The status of a failure code (enclave.md section 4).
pub fn status_of(error: ProtocolError) -> StatusCode {
    use ProtocolError::*;
    match error {
        InvalidRequest | UnsupportedVersion | BadChallenge | BadSignature | UserMismatch
        | WrongNode | OpenFailed | BadExpiry | UnsupportedPolicy | CustodyMismatch => {
            StatusCode::BAD_REQUEST
        }
        NotAllowed | PeerUnverified => StatusCode::FORBIDDEN,
        ProviderUnknown | StateUnknown => StatusCode::NOT_FOUND,
        GrantRequired | GrantRevoked | GrantExpired | KeyMismatch => StatusCode::CONFLICT,
        TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        RecordInvalid => StatusCode::UNPROCESSABLE_ENTITY,
        LogBacklog => StatusCode::TOO_MANY_REQUESTS,
        Internal => StatusCode::INTERNAL_SERVER_ERROR,
        ExchangeFailed | RefreshFailed | ProviderUnreachable | ResponseWithheld => {
            StatusCode::BAD_GATEWAY
        }
        NotConfigured | Closing | LogStoreUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        Timeout => StatusCode::GATEWAY_TIMEOUT,
    }
}

fn message_of(error: ProtocolError) -> &'static str {
    use ProtocolError::*;
    match error {
        InvalidRequest => "the request is malformed",
        UnsupportedVersion => "the version is not 1",
        WrongNode => "the command names another node",
        OpenFailed => "the envelope cannot be opened",
        BadSignature => "the signature does not verify",
        UserMismatch => "the user does not match the call",
        BadChallenge => "the challenge is unknown, expired or used",
        BadExpiry => "the expiry is not after the node time",
        UnsupportedPolicy => "the policy is not empty",
        CustodyMismatch => "the custody of the grant is not the custody of this node",
        PeerUnverified => "the attestation of the peer does not verify against this node",
        Internal => "the platform failed",
        NotConfigured => "the operator configuration is missing",
        Closing => "the node is closing",
        GrantRequired => "the account has no grant on this node",
        GrantRevoked => "the account revoked its grant",
        GrantExpired => "the grant expired",
        KeyMismatch => "the key or the custody is not that of the grant",
        RecordInvalid => "the record cannot be opened",
        ProviderUnknown => "the provider has no definition",
        NotAllowed => "the provider definition does not allow this",
        StateUnknown => "no pending authorization for this state",
        ExchangeFailed => "the provider refused the code exchange",
        RefreshFailed => "the provider refused the refresh",
        ProviderUnreachable => "the provider cannot be reached",
        Timeout => "the provider call timed out",
        ResponseWithheld => "the provider response was withheld by the egress policy",
        TooLarge => "a body is above the limit",
        LogBacklog => "too many log entries wait for a storage acknowledgement",
        LogStoreUnavailable => "the log store did not confirm the entry of this call",
    }
}

impl From<ProtocolError> for ApiError {
    fn from(error: ProtocolError) -> Self {
        ApiError {
            status: status_of(error),
            code: error.code(),
            message: message_of(error),
            provider: None,
        }
    }
}

impl From<PlatformError> for ApiError {
    fn from(_: PlatformError) -> Self {
        ApiError::internal()
    }
}

impl From<Withheld> for ApiError {
    fn from(withheld: Withheld) -> Self {
        ApiError::from(ProtocolError::from(withheld))
    }
}

impl ApiError {
    /// A failure of the platform under the node (random source, attestation device): the
    /// code `internal`.
    pub fn internal() -> ApiError {
        ApiError::from(ProtocolError::Internal)
    }

    /// `exchange_failed` or `refresh_failed` with the status of the provider (0 for a transport
    /// failure) and the error word of its response.
    pub fn provider(error: ProtocolError, status: u16, provider_error: ProviderError) -> ApiError {
        ApiError {
            provider: Some((status, provider_error)),
            ..ApiError::from(error)
        }
    }

    /// A failure with a message that says which part of the request is wrong.
    pub fn with_message(error: ProtocolError, message: &'static str) -> ApiError {
        ApiError {
            message,
            ..ApiError::from(error)
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        json_error(
            self.status,
            &ErrorBody {
                code: self.code,
                message: self.message,
                provider_status: self.provider.map(|(status, _)| status),
                provider_error: self.provider.map(|(_, error)| error.as_str()),
            },
        )
    }
}

/// Turns the outcome of a call into its response.
pub fn respond(outcome: Result<Response, ApiError>) -> Response {
    outcome.unwrap_or_else(IntoResponse::into_response)
}

/// Reads a request body up to `limit` bytes. A longer body is `too_large`.
pub async fn read_body(request: Request, limit: usize) -> Result<Vec<u8>, ApiError> {
    let declared = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > limit as u64) {
        return Err(ProtocolError::TooLarge.into());
    }
    let mut body = request.into_body();
    let mut collected = Vec::with_capacity(declared.unwrap_or(0) as usize);
    loop {
        let frame = std::future::poll_fn(|context| Pin::new(&mut body).poll_frame(context)).await;
        match frame {
            None => return Ok(collected),
            Some(Err(_)) => {
                return Err(ApiError::with_message(
                    ProtocolError::InvalidRequest,
                    "the request body could not be read",
                ))
            }
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    if collected.len() + data.len() > limit {
                        return Err(ProtocolError::TooLarge.into());
                    }
                    collected.extend_from_slice(&data);
                }
            }
        }
    }
}

/// A parsed JSON request body. Its strings are overwritten with zeros when it is dropped: a
/// body can carry an authorization code or a client secret.
pub struct JsonBody(serde_json::Value);

impl Drop for JsonBody {
    fn drop(&mut self) {
        wipe_json(&mut self.0);
    }
}

impl JsonBody {
    /// Reads and parses the body of a call. The body is a JSON object.
    pub async fn read(request: Request) -> Result<JsonBody, ApiError> {
        let bytes = Zeroizing::new(read_body(request, JSON_BODY_LIMIT_BYTES).await?);
        JsonBody::parse(&bytes)
    }

    /// Parses a JSON object.
    pub fn parse(bytes: &[u8]) -> Result<JsonBody, ApiError> {
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| {
            ApiError::with_message(ProtocolError::InvalidRequest, "the body is not JSON")
        })?;
        JsonBody::from_value(value)
    }

    /// Wraps a parsed JSON object.
    pub fn from_value(value: serde_json::Value) -> Result<JsonBody, ApiError> {
        let body = JsonBody(value);
        if !body.0.is_object() {
            return Err(ApiError::with_message(
                ProtocolError::InvalidRequest,
                "the body is not a JSON object",
            ));
        }
        Ok(body)
    }

    /// The value of a key, when present and not `null`.
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.0.get(key).filter(|value| !value.is_null())
    }

    /// A required string.
    pub fn text(&self, key: &str) -> Result<&str, ApiError> {
        self.get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| missing(key))
    }

    /// An optional string: an absent key is the empty string.
    pub fn text_or_empty(&self, key: &str) -> Result<&str, ApiError> {
        match self.get(key) {
            None => Ok(""),
            Some(value) => value.as_str().ok_or_else(|| missing(key)),
        }
    }

    /// A required unsigned integer.
    pub fn number(&self, key: &str) -> Result<u64, ApiError> {
        self.get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| missing(key))
    }

    /// A required JSON object.
    pub fn object(&self, key: &str) -> Result<&serde_json::Value, ApiError> {
        self.get(key)
            .filter(|value| value.is_object())
            .ok_or_else(|| missing(key))
    }

    /// The `user_id` of a call: 1 to 128 characters without control characters.
    pub fn user_id(&self) -> Result<&str, ApiError> {
        let user_id = self.text("user_id")?;
        if !is_valid_name(user_id) {
            return Err(missing("user_id"));
        }
        Ok(user_id)
    }

    /// The `context` of a call: a string of at most 256 characters that the node copies into
    /// log entries without checking it. An absent key is the empty string.
    pub fn context(&self) -> Result<&str, ApiError> {
        let context = self.text_or_empty("context")?;
        if context.chars().count() > limits::CONTEXT_CHARS {
            return Err(missing("context"));
        }
        Ok(context)
    }
}

fn missing(key: &str) -> ApiError {
    let message = match key {
        "user_id" => "user_id is missing or invalid",
        "envelope" => "envelope is missing or invalid",
        "peer" => "peer is missing or invalid",
        "endorsement" => "endorsement is missing or invalid",
        "after" => "after is missing or invalid",
        "nonce" => "nonce is missing or invalid",
        "record" => "record is missing or invalid",
        "previous" => "previous is missing or invalid",
        "context" => "context is missing or invalid",
        "provider" => "provider is missing or invalid",
        "providers" => "providers is missing or invalid",
        "log_store" => "log_store is missing or invalid",
        "access_key_id" => "access_key_id is missing or invalid",
        "secret_access_key" => "secret_access_key is missing or invalid",
        "session_token" => "session_token is missing or invalid",
        "expires_ms" => "expires_ms is missing or invalid",
        "operator_state" => "operator_state is missing or invalid",
        "params" => "params is missing or invalid",
        "client_id" => "client_id is missing or invalid",
        "state" => "state is missing or invalid",
        "code" => "code is missing or invalid",
        "field" => "field is missing or invalid",
        "origin" => "origin is missing or invalid",
        "method" => "method is missing or invalid",
        "url" => "url is missing or invalid",
        "headers" => "headers is missing or invalid",
        "timeout_ms" => "timeout_ms is missing or invalid",
        "after_seq" => "after_seq is missing or invalid",
        "seq" => "seq is missing or invalid",
        "cursor" => "cursor is missing or invalid",
        "limit" => "limit is missing or invalid",
        _ => "a field is missing or invalid",
    };
    ApiError::with_message(ProtocolError::InvalidRequest, message)
}

/// The record of a call.
pub fn record_of(body: &JsonBody, key: &str) -> Result<Record, ApiError> {
    Ok(Record::from_value(body.object(key)?)?)
}

/// The client values of a provider from the operator configuration. A provider the
/// configuration does not list, and a `static` provider with an empty `client_id`, are
/// `not_configured` (enclave.md 5.1).
pub fn provider_credentials<'a>(
    definition: &Definition,
    config: &'a OperatorConfig,
    provider: &str,
) -> Result<&'a ProviderCredentials, ProtocolError> {
    let credentials = config
        .providers
        .get(provider)
        .ok_or(ProtocolError::NotConfigured)?;
    if definition.client == ClientKind::Static && credentials.client_id.is_empty() {
        return Err(ProtocolError::NotConfigured);
    }
    Ok(credentials)
}

/// `invalid_request` for a named field.
pub fn invalid(key: &str) -> ApiError {
    missing(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_the_status_of_section_4() {
        let table: [(u16, &[&str]); 11] = [
            (
                400,
                &[
                    "invalid_request",
                    "unsupported_version",
                    "bad_challenge",
                    "bad_signature",
                    "user_mismatch",
                    "wrong_node",
                    "open_failed",
                    "bad_expiry",
                    "unsupported_policy",
                    "custody_mismatch",
                ],
            ),
            (403, &["not_allowed", "peer_unverified"]),
            (404, &["provider_unknown", "state_unknown"]),
            (
                409,
                &[
                    "grant_required",
                    "grant_revoked",
                    "grant_expired",
                    "key_mismatch",
                ],
            ),
            (413, &["too_large"]),
            (422, &["record_invalid"]),
            (429, &["log_backlog"]),
            (500, &["internal"]),
            (
                502,
                &[
                    "exchange_failed",
                    "refresh_failed",
                    "provider_unreachable",
                    "response_withheld",
                ],
            ),
            (503, &["not_configured", "closing", "log_store_unavailable"]),
            (504, &["timeout"]),
        ];
        let mut seen = 0;
        for (status, codes) in table {
            for code in codes {
                let error = ProtocolError::ALL
                    .iter()
                    .find(|error| error.code() == *code)
                    .unwrap_or_else(|| panic!("{code}"));
                assert_eq!(status_of(*error).as_u16(), status, "{code}");
                seen += 1;
            }
        }
        assert_eq!(seen, ProtocolError::ALL.len());
    }

    #[tokio::test]
    async fn a_failure_body_has_code_and_message_and_provider_fields_only_when_set() {
        let response = ApiError::from(ProtocolError::GrantRequired).into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            "application/json"
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            body.as_ref(),
            b"{\"code\":\"grant_required\",\"message\":\"the account has no grant on this node\"}"
        );

        let response = ApiError::provider(ProtocolError::RefreshFailed, 400, ProviderError::OTHER)
            .into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            body.as_ref(),
            concat!(
                "{\"code\":\"refresh_failed\",\"message\":\"the provider refused the refresh\",",
                "\"provider_status\":400,\"provider_error\":\"other\"}"
            )
            .as_bytes()
        );
    }

    #[test]
    fn a_json_body_is_an_object_and_is_wiped_on_drop() {
        assert!(JsonBody::parse(b"[]").is_err());
        assert!(JsonBody::parse(b"not json").is_err());
        let body = JsonBody::parse(br#"{"user_id":"u","n":5,"o":{},"z":null}"#).unwrap();
        assert_eq!(body.user_id().unwrap(), "u");
        assert_eq!(body.number("n").unwrap(), 5);
        assert!(body.object("o").is_ok());
        assert!(body.text("z").is_err());
        assert_eq!(body.text_or_empty("z").unwrap(), "");
        assert_eq!(body.text_or_empty("absent").unwrap(), "");
        assert!(body.text("n").is_err());
        assert!(JsonBody::parse(br#"{"user_id":""}"#)
            .unwrap()
            .user_id()
            .is_err());
        assert!(JsonBody::parse(br#"{"user_id":"a\nb"}"#)
            .unwrap()
            .user_id()
            .is_err());
        let long = format!("{{\"context\":\"{}\"}}", "c".repeat(257));
        assert!(JsonBody::parse(long.as_bytes()).unwrap().context().is_err());
        let fits = format!("{{\"context\":\"{}\"}}", "c".repeat(256));
        assert!(JsonBody::parse(fits.as_bytes()).unwrap().context().is_ok());
    }
}
