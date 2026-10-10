//! Outbound calls to providers: TLS that ends inside the node (rustls) and one HTTP/1.1
//! exchange per connection.
//!
//! The byte pipe comes from the platform (a direct TCP connection on local, the egress relay of
//! the parent on nitro). Whoever carries the bytes sees TLS records only. Certificates are
//! verified against the roots compiled into the binary, at the time of the node clock.
//! Redirects are never followed and responses are returned without decompression.
//!
//! The connection itself ([`Egress::open`]) is also the way of the node to its log store. What
//! is written to the log store, and when, is `crate::log_store`: no request of that module is
//! built here and no provider definition is read there.
//!
//! This module is sink K3 of the egress policy: [`build_request`] is the one place where a
//! credential, a token request or a revocation request is written into a request that goes to
//! a provider. A request is addressed to a [`Destination`], which only the provider
//! definitions create: the host of a request is one that passed the address check of
//! `forward`, or the host of the token address or of the revocation address of a definition.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use credential_enclave_protocol::secret::Secret;
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::client::conn::http1::SendRequest;
use hyper::header::{HeaderName, HeaderValue, CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use hyper::{Method, Request, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::clock::{Clock, TlsTime};
use crate::platform::DynPlatform;
use crate::providers::Destination;

/// The port of every provider address and of the log store.
pub const PROVIDER_PORT: u16 = 443;

/// Response headers that are not passed on: the headers that describe one connection
/// (RFC 9110 7.6.1), and the cookie headers. A node drops the `Cookie` header of every request,
/// so no cookie is in use, and a cookie handed to the caller would be an access to the provider
/// that no log entry records.
const DROPPED_RESPONSE_HEADERS: [&str; 10] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "set-cookie",
    "set-cookie2",
];

/// True when `text` is an HTTP token (RFC 9110 5.6.2): the characters of a header name.
pub fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Why an outbound call failed. No variant carries bytes of the exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressError {
    /// The request could not be expressed as an HTTP/1.1 request (target or header).
    Invalid,
    /// Connecting, the TLS handshake or the HTTP exchange failed.
    Unreachable,
    /// The response body is above the limit.
    TooLarge,
    /// The response body is under a transfer coding other than `chunked`: the node cannot read
    /// it.
    Coded,
}

/// One outbound request. Its host and its request target are those of its [`Destination`].
pub struct OutboundRequest {
    destination: Destination,
    method: String,
    /// Headers after `Host` and `Content-Length`.
    headers: Vec<OutboundHeader>,
    body: OutboundBody,
}

impl OutboundRequest {
    /// A request to a destination of the provider definitions.
    pub fn new(
        destination: Destination,
        method: &str,
        headers: Vec<OutboundHeader>,
        body: OutboundBody,
    ) -> OutboundRequest {
        OutboundRequest {
            destination,
            method: method.to_string(),
            headers,
            body,
        }
    }

    /// The provider host: the TLS server name and the `Host` header.
    pub fn host(&self) -> &str {
        self.destination.host()
    }

    /// The request method.
    #[cfg(test)]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The request target in origin form.
    #[cfg(test)]
    pub fn target(&self) -> &str {
        self.destination.request_target()
    }

    /// The headers after `Host` and `Content-Length`.
    #[cfg(test)]
    pub fn headers(&self) -> &[OutboundHeader] {
        &self.headers
    }

    /// The body.
    #[cfg(test)]
    pub fn body(&self) -> &OutboundBody {
        &self.body
    }
}

/// The body of an outbound request.
pub enum OutboundBody {
    /// A body the caller of `forward` gave.
    Plain(Bytes),
    /// A body the node assembled around a secret: a token request or a revocation request.
    Secret(Secret<Vec<u8>>),
}

impl OutboundBody {
    /// The length of the body in bytes.
    pub fn len(&self) -> usize {
        match self {
            OutboundBody::Plain(bytes) => bytes.len(),
            OutboundBody::Secret(bytes) => bytes.expose_secret().len(),
        }
    }
}

/// The value of an outbound header.
pub enum HeaderText {
    /// A value of the caller or of the definition.
    Plain(String),
    /// A value that carries a credential or a client secret.
    Secret(Secret<String>),
}

/// One header of an outbound request.
pub struct OutboundHeader {
    pub name: String,
    pub value: HeaderText,
}

impl OutboundHeader {
    pub fn plain(name: &str, value: &str) -> OutboundHeader {
        OutboundHeader {
            name: name.to_string(),
            value: HeaderText::Plain(value.to_string()),
        }
    }

    pub fn secret(name: &str, value: Secret<String>) -> OutboundHeader {
        OutboundHeader {
            name: name.to_string(),
            value: HeaderText::Secret(value),
        }
    }
}

/// A request body that is sent as one chunk.
pub(crate) struct OnceBody(Option<Bytes>);

impl OnceBody {
    /// A body of these bytes. No bytes are no body.
    pub(crate) fn new(bytes: Bytes) -> OnceBody {
        OnceBody((!bytes.is_empty()).then_some(bytes))
    }
}

impl Body for OnceBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.0.take().map(|bytes| Ok(Frame::data(bytes))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.0.as_ref().map_or(0, |bytes| bytes.len() as u64))
    }
}

/// The head of a provider response. The body is read with [`Exchange::read_body`].
pub struct Exchange {
    pub status: u16,
    /// Response headers in the order received, without the headers of
    /// [`DROPPED_RESPONSE_HEADERS`].
    pub headers: Vec<(String, String)>,
    /// The declared body length, when the response declares one.
    pub content_length: Option<u64>,
    body: Incoming,
    // The connection stays open while the body is read.
    _sender: SendRequest<OnceBody>,
}

impl Exchange {
    /// Reads the response body. `Transfer-Encoding: chunked` is already decoded. A body above
    /// `limit` bytes is [`EgressError::TooLarge`].
    pub async fn read_body(mut self, limit: usize) -> Result<Vec<u8>, EgressError> {
        if self
            .content_length
            .is_some_and(|length| length > limit as u64)
        {
            return Err(EgressError::TooLarge);
        }
        let capacity = self
            .content_length
            .map_or(0, |length| length.min(limit as u64) as usize);
        let mut collected = Vec::with_capacity(capacity);
        loop {
            let frame =
                std::future::poll_fn(|context| Pin::new(&mut self.body).poll_frame(context)).await;
            match frame {
                None => return Ok(collected),
                Some(Err(_)) => return Err(EgressError::Unreachable),
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        if collected.len() + data.len() > limit {
                            return Err(EgressError::TooLarge);
                        }
                        collected.extend_from_slice(&data);
                    }
                }
            }
        }
    }
}

/// The TLS client of a node.
pub struct Egress {
    connector: TlsConnector,
    mail_connector: TlsConnector,
}

impl Egress {
    /// The TLS client of a running node: the trust roots are the `webpki-roots` compiled into
    /// the binary.
    pub fn new(clock: Arc<Clock>) -> Egress {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Egress::build(clock, roots)
    }

    /// A TLS client that trusts the given roots only. Tests use it to trust the certificate
    /// authority of their provider stand-in. The node binary does not contain this function.
    #[cfg(test)]
    pub fn with_test_roots(clock: Arc<Clock>, roots: RootCertStore) -> Egress {
        Egress::build(clock, roots)
    }

    fn build(clock: Arc<Clock>, roots: RootCertStore) -> Egress {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_details(provider, Arc::new(TlsTime(clock)))
            .with_safe_default_protocol_versions()
            .expect("the ring provider supports the default TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mail_connector = TlsConnector::from(Arc::new(config.clone()));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Egress {
            connector: TlsConnector::from(Arc::new(config)),
            mail_connector,
        }
    }

    /// Opens a connection to port 443 of `host` and returns its HTTP/1.1 sender: the byte pipe
    /// of the platform, TLS that ends inside the node with a certificate verified against the
    /// trust roots of this client at the time of the node clock, then HTTP/1.1.
    ///
    /// This is the way of every outbound connection of a node: to a provider
    /// ([`Egress::send_to_provider`]) and to the log store (`crate::log_store`).
    pub(crate) async fn open(
        &self,
        platform: &dyn DynPlatform,
        host: &str,
    ) -> Result<SendRequest<OnceBody>, EgressError> {
        let server_name =
            ServerName::try_from(host.to_string()).map_err(|_| EgressError::Invalid)?;
        let stream = platform
            .connect(host, PROVIDER_PORT)
            .await
            .map_err(|_| EgressError::Unreachable)?;
        let tls = self
            .connector
            .connect(server_name, stream)
            .await
            .map_err(|_| EgressError::Unreachable)?;
        let (sender, connection) =
            hyper::client::conn::http1::handshake::<_, OnceBody>(TokioIo::new(tls))
                .await
                .map_err(|_| EgressError::Unreachable)?;
        tokio::spawn(async move {
            // The connection ends when its sender is dropped or the other side closes it.
            let _ = connection.await;
        });
        Ok(sender)
    }

    /// Fixed mail destinations. TLS and its trusted clock stay inside the node.
    pub(crate) async fn open_mail(
        &self,
        platform: &dyn DynPlatform,
        host: &str,
        port: u16,
    ) -> Result<crate::platform::Stream, EgressError> {
        if !matches!(
            (host, port),
            ("imap.naver.com", 993) | ("smtp.naver.com", 465)
        ) {
            return Err(EgressError::Invalid);
        }
        let name = ServerName::try_from(host.to_string()).map_err(|_| EgressError::Invalid)?;
        let stream = platform
            .connect(host, port)
            .await
            .map_err(|_| EgressError::Unreachable)?;
        let tls = self
            .mail_connector
            .connect(name, stream)
            .await
            .map_err(|_| EgressError::Unreachable)?;
        Ok(Box::new(tls))
    }

    /// Connects to the provider, sends the request and returns the response head.
    ///
    /// The request carries `Host`, then `Content-Length` when it has a body or its method is
    /// `POST`, `PUT` or `PATCH`, then the given headers, then `Connection: close`.
    pub async fn send_to_provider(
        &self,
        platform: &dyn DynPlatform,
        outbound: OutboundRequest,
    ) -> Result<Exchange, EgressError> {
        let request = build_request(&outbound)?;
        let mut sender = self.open(platform, outbound.host()).await?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| EgressError::Unreachable)?;
        let (parts, body) = response.into_parts();

        // A node sends no `TE` header, so the one transfer coding a provider may apply is
        // `chunked`, which the HTTP client removes. A body under another transfer coding
        // (`gzip, chunked`) would reach the caller still coded and without the header that
        // says so, and the node could not search it.
        let coded = parts
            .headers
            .get_all(TRANSFER_ENCODING)
            .iter()
            .any(|value| {
                value.to_str().map_or(true, |codings| {
                    codings
                        .split(',')
                        .any(|coding| !coding.trim().eq_ignore_ascii_case("chunked"))
                })
            });
        if coded {
            return Err(EgressError::Coded);
        }

        let mut dropped: Vec<String> = DROPPED_RESPONSE_HEADERS
            .iter()
            .map(|name| name.to_string())
            .collect();
        for value in parts.headers.get_all(CONNECTION) {
            if let Ok(listed) = value.to_str() {
                dropped.extend(
                    listed
                        .split(',')
                        .map(|name| name.trim().to_ascii_lowercase()),
                );
            }
        }
        let mut content_length = None;
        let mut headers = Vec::with_capacity(parts.headers.len());
        for (name, value) in &parts.headers {
            if dropped.iter().any(|hop| hop == name.as_str()) {
                continue;
            }
            let text = match std::str::from_utf8(value.as_bytes()) {
                Ok(text) => text.to_string(),
                // Bytes outside UTF-8 are read as ISO 8859-1, one character per byte.
                Err(_) => value
                    .as_bytes()
                    .iter()
                    .map(|byte| char::from(*byte))
                    .collect(),
            };
            if name == CONTENT_LENGTH {
                content_length = text.trim().parse::<u64>().ok();
            }
            headers.push((name.as_str().to_string(), text));
        }
        Ok(Exchange {
            status: parts.status.as_u16(),
            headers,
            content_length,
            body,
            _sender: sender,
        })
    }
}

/// Checks that a request can be expressed as an HTTP/1.1 request, without sending it.
pub fn check(outbound: &OutboundRequest) -> Result<(), EgressError> {
    build_request(outbound).map(|_| ())
}

fn build_request(outbound: &OutboundRequest) -> Result<Request<OnceBody>, EgressError> {
    let method =
        Method::from_bytes(outbound.method.as_bytes()).map_err(|_| EgressError::Invalid)?;
    let target: Uri = outbound
        .destination
        .request_target()
        .parse()
        .map_err(|_| EgressError::Invalid)?;
    if target.scheme().is_some() || target.authority().is_some() || target.path().is_empty() {
        return Err(EgressError::Invalid);
    }
    let body_length = outbound.body.len();
    let sends_length =
        body_length > 0 || matches!(method, Method::POST | Method::PUT | Method::PATCH);
    let mut builder = Request::builder().method(method).uri(target).header(
        HOST,
        HeaderValue::from_str(outbound.host()).map_err(|_| EgressError::Invalid)?,
    );
    if sends_length {
        builder = builder.header(CONTENT_LENGTH, body_length);
    }
    for header in &outbound.headers {
        let name =
            HeaderName::from_bytes(header.name.as_bytes()).map_err(|_| EgressError::Invalid)?;
        // A value may hold bytes above ASCII (sent as UTF-8). Control characters are not
        // accepted: a value cannot end its line.
        let value = match &header.value {
            HeaderText::Plain(text) => {
                HeaderValue::from_bytes(text.as_bytes()).map_err(|_| EgressError::Invalid)?
            }
            HeaderText::Secret(text) => {
                let mut value = HeaderValue::from_bytes(text.expose_secret().as_bytes())
                    .map_err(|_| EgressError::Invalid)?;
                value.set_sensitive(true);
                value
            }
        };
        builder = builder.header(name, value);
    }
    builder = builder.header(CONNECTION, HeaderValue::from_static("close"));
    let body = match &outbound.body {
        _ if body_length == 0 => OnceBody(None),
        OutboundBody::Plain(bytes) => OnceBody(Some(bytes.clone())),
        OutboundBody::Secret(bytes) => {
            OnceBody(Some(Bytes::copy_from_slice(bytes.expose_secret())))
        }
    };
    builder.body(body).map_err(|_| EgressError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_names_are_tokens() {
        for name in [
            "Accept",
            "x-goog-api-client",
            "X_Custom.Header",
            "a!#$%&'*+-.^_`|~1",
        ] {
            assert!(is_token(name), "{name}");
        }
        for name in [
            "", "a b", "a:b", "a\r\nb", "a(b)", "a/b", "héader", "a=b", "a,b",
        ] {
            assert!(!is_token(name), "{name}");
        }
    }

    fn request(method: &str, target: &str, body: &'static [u8]) -> OutboundRequest {
        OutboundRequest::new(
            Destination::for_test("api.provider.test", target),
            method,
            vec![
                OutboundHeader::secret("Authorization", Secret::new("Bearer token".to_string())),
                OutboundHeader::plain("accept", "application/json"),
            ],
            OutboundBody::Plain(Bytes::from_static(body)),
        )
    }

    #[test]
    fn a_request_carries_host_length_headers_and_connection_close() {
        let built = build_request(&request("POST", "/v1/items?a=1", b"{}")).unwrap();
        assert_eq!(built.method(), Method::POST);
        assert_eq!(built.uri().to_string(), "/v1/items?a=1");
        let names: Vec<&str> = built.headers().keys().map(HeaderName::as_str).collect();
        assert_eq!(
            names,
            [
                "host",
                "content-length",
                "authorization",
                "accept",
                "connection"
            ]
        );
        assert_eq!(built.headers()[HOST], "api.provider.test");
        assert_eq!(built.headers()[CONTENT_LENGTH], "2");
        assert!(built.headers()["authorization"].is_sensitive());
        assert!(!format!("{:?}", built.headers()).contains("Bearer token"));
        assert_eq!(built.headers()[CONNECTION], "close");
    }

    #[test]
    fn a_get_without_a_body_has_no_content_length_and_an_empty_post_has_zero() {
        let get = build_request(&request("GET", "/v1/items", b"")).unwrap();
        assert!(!get.headers().contains_key(CONTENT_LENGTH));
        let post = build_request(&request("POST", "/v1/items", b"")).unwrap();
        assert_eq!(post.headers()[CONTENT_LENGTH], "0");
        let delete = build_request(&request("DELETE", "/v1/items/1", b"")).unwrap();
        assert!(!delete.headers().contains_key(CONTENT_LENGTH));
    }

    #[test]
    fn requests_that_are_not_http_are_rejected() {
        assert_eq!(
            build_request(&request("GET", "https://other.example/v1", b"")).err(),
            Some(EgressError::Invalid)
        );
        assert_eq!(
            build_request(&request("GET", "/v1/<items>", b"")).err(),
            Some(EgressError::Invalid)
        );
        assert_eq!(
            build_request(&request("G ET", "/v1", b"")).err(),
            Some(EgressError::Invalid)
        );
        let mut injected = request("GET", "/v1", b"");
        injected
            .headers
            .push(OutboundHeader::plain("x-a", "1\r\nx-b: 2"));
        assert_eq!(build_request(&injected).err(), Some(EgressError::Invalid));
    }
}
