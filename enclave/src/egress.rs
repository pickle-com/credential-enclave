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

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use credential_enclave_protocol::limits;
use credential_enclave_protocol::secret::Secret;
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::client::conn::http1::SendRequest;
use hyper::header::{HeaderName, HeaderValue, CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use hyper::{Method, Request, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsConnector;

use crate::clock::{Clock, TlsTime};
use crate::platform::{ConnectError, DynPlatform};
use crate::providers::Destination;
use crate::state::lock;

/// The port of every provider address and of the log store.
pub const PROVIDER_PORT: u16 = 443;

/// Caller headers the HTTP calls drop (enclave.md 5.8 step 4): the credential header is the
/// node's, `Accept-Encoding` is set by the node, and the rest describe the connection or the
/// body framing. The `verify` request of an application password definition cannot name one.
pub const DROPPED_REQUEST_HEADERS: [&str; 13] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "expect",
    "accept-encoding",
];

/// Caller headers that ask a provider to treat a request as one of another method than the
/// method it is sent with. A call that carries one is refused: the event `provider_request`
/// names the method of the request, and the request that leaves is of that method. The `verify`
/// request of an application password definition cannot name one either.
pub const REFUSED_REQUEST_HEADERS: [&str; 3] = [
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

/// Open connections to providers in total that carry no request, over every account.
const IDLE_PROVIDER_CONNECTIONS_TOTAL: usize = 1024;

/// Outbound connections a node opens at the same time (enclave.md section 8): the default of
/// `Limits::open_concurrency`. A quarter of the backlog of the egress relay of the host
/// program, so a burst of opens waits in the node and not in a queue the kernel resets.
pub const OPEN_CONCURRENCY: usize = 256;
/// Attempts to open one outbound connection ([`Egress::open_at`]).
const OPEN_ATTEMPTS: u32 = 3;
/// The base of the full jitter backoff between two attempts to open a connection.
const OPEN_BACKOFF_BASE: Duration = Duration::from_millis(50);
/// The cap of that backoff.
const OPEN_BACKOFF_CAP: Duration = Duration::from_millis(400);

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

/// Why an attempt to open an outbound connection failed (enclave.md 5.14). Every variant is a
/// failure before any request byte left the node, so an attempt of every kind is repeated. No
/// variant carries bytes of the exchange, and the four names are the closed vocabulary of
/// `open_failures` of health.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The platform could not open the byte pipe: the vsock connection to the egress relay of
    /// the parent on nitro, the TCP connection on local.
    Transport,
    /// The egress relay of the parent refused the host and the port (nitro).
    RelayRefused,
    /// The TLS handshake failed: the certificate, the protocol, or the connection during it.
    /// A host that is not a server name fails here as well.
    Tls,
    /// The HTTP/1.1 handshake failed.
    Http,
}

impl From<ConnectError> for OpenError {
    fn from(error: ConnectError) -> OpenError {
        match error {
            ConnectError::Transport(_) => OpenError::Transport,
            ConnectError::RelayRefused(_) => OpenError::RelayRefused,
        }
    }
}

impl From<OpenError> for EgressError {
    fn from(_: OpenError) -> EgressError {
        EgressError::Unreachable
    }
}

/// The counts of `egress` of `GET /v1/health` (enclave.md 5.1), since the node started.
#[derive(Default)]
pub struct EgressCounters {
    /// Outbound connections that were opened: the byte pipe, the TLS handshake and, for a
    /// connection to a provider or to the log store, the HTTP/1.1 handshake.
    pub opens: AtomicU64,
    /// Attempts to open a connection that failed, by cause.
    pub open_failures: OpenFailureCounters,
    /// Attempts that followed a failed attempt.
    pub open_retries: AtomicU64,
    /// Requests that went over an idle connection instead of a new one.
    pub idle_reuses: IdleReuseCounters,
}

/// The failed attempts to open a connection, by cause ([`OpenError`]).
#[derive(Default)]
pub struct OpenFailureCounters {
    pub transport: AtomicU64,
    pub relay_refused: AtomicU64,
    pub tls: AtomicU64,
    pub http: AtomicU64,
}

impl OpenFailureCounters {
    fn count(&self, error: OpenError) {
        let counter = match error {
            OpenError::Transport => &self.transport,
            OpenError::RelayRefused => &self.relay_refused,
            OpenError::Tls => &self.tls,
            OpenError::Http => &self.http,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// The requests that went over an idle connection, by peer: a provider (enclave.md 5.8 step
/// 8) or the log store (5.14).
#[derive(Default)]
pub struct IdleReuseCounters {
    pub provider: AtomicU64,
    pub log_store: AtomicU64,
}

/// A full jitter backoff: a random time between zero and the smaller of `cap` and `base`
/// doubled for every attempt after the first. The randomness comes from the random source of
/// the platform; when that source fails, the backoff is the upper bound.
pub(crate) fn full_jitter(
    platform: &dyn DynPlatform,
    attempt: u32,
    base: Duration,
    cap: Duration,
) -> Duration {
    let doublings = attempt.saturating_sub(1).min(16);
    let upper = base.saturating_mul(1u32 << doublings).min(cap);
    let mut bytes = [0u8; 8];
    if platform.fill_random(&mut bytes).is_err() {
        return upper;
    }
    let upper_ms = u64::try_from(upper.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(u64::from_le_bytes(bytes) % upper_ms.saturating_add(1))
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

/// Where the connection of an exchange goes back to when its response has ended: the idle
/// connections of one account and host.
struct Keep {
    pool: Arc<ProviderConnections>,
    user_id: String,
    host: String,
    now_ms: u64,
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
    /// The connection stays open while the body is read. When the body has ended and the
    /// provider did not close the connection, it goes back to the idle connections of its
    /// account and host.
    sender: Option<SendRequest<OnceBody>>,
    keep: Option<Keep>,
    /// The share of the node-wide bound of provider requests in flight. Held until the
    /// exchange is dropped.
    _inflight: OwnedSemaphorePermit,
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
                None => {
                    self.keep_connection();
                    return Ok(collected);
                }
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

    /// Puts the connection among the idle connections of its account and host, when the
    /// response has ended on an open connection.
    fn keep_connection(&mut self) {
        if let (Some(keep), Some(sender)) = (self.keep.take(), self.sender.take()) {
            if !sender.is_closed() {
                keep.pool
                    .put(&keep.user_id, &keep.host, sender, keep.now_ms);
            }
        }
    }
}

/// The open connections to providers that carry no request, by account and host (enclave.md
/// 5.8 step 8): at most [`limits::PROVIDER_IDLE_CONNECTIONS`] per account and host, each kept
/// for at most [`limits::PROVIDER_IDLE_MS`], and at most [`IDLE_PROVIDER_CONNECTIONS_TOTAL`] in
/// all. No connection carries the requests of two accounts.
#[derive(Default)]
pub struct ProviderConnections(Mutex<HashMap<(String, String), IdleSenders>>);

/// The idle connections of one (account, host) pair, each with the node time it became idle,
/// the most recently used last.
type IdleSenders = Vec<(SendRequest<OnceBody>, u64)>;

impl ProviderConnections {
    /// The most recently used open connection of `user_id` to `host`, once it is ready for a
    /// request. Connections idle for longer than the idle time are dropped.
    async fn take(&self, user_id: &str, host: &str, now_ms: u64) -> Option<SendRequest<OnceBody>> {
        loop {
            let candidate = {
                let mut pools = lock(&self.0);
                let key = (user_id.to_string(), host.to_string());
                let idle = pools.get_mut(&key)?;
                idle.retain(|(sender, since_ms)| {
                    !sender.is_closed()
                        && now_ms < since_ms.saturating_add(limits::PROVIDER_IDLE_MS)
                });
                let candidate = idle.pop();
                if idle.is_empty() {
                    pools.remove(&key);
                }
                candidate
            };
            let (mut sender, _) = candidate?;
            if sender.ready().await.is_ok() {
                return Some(sender);
            }
        }
    }

    /// Keeps a connection of `user_id` to `host` whose response has ended. The oldest idle
    /// connection of the pair leaves when the pair has its limit, and the oldest of all when
    /// the node has its total.
    fn put(&self, user_id: &str, host: &str, sender: SendRequest<OnceBody>, now_ms: u64) {
        let mut pools = lock(&self.0);
        pools.retain(|_, idle| {
            idle.retain(|(sender, since_ms)| {
                !sender.is_closed() && now_ms < since_ms.saturating_add(limits::PROVIDER_IDLE_MS)
            });
            !idle.is_empty()
        });
        let total: usize = pools.values().map(Vec::len).sum();
        if total >= IDLE_PROVIDER_CONNECTIONS_TOTAL {
            let oldest = pools
                .iter()
                .filter_map(|(key, idle)| idle.first().map(|(_, since)| (*since, key.clone())))
                .min()
                .map(|(_, key)| key);
            if let Some(key) = oldest {
                if let Some(idle) = pools.get_mut(&key) {
                    idle.remove(0);
                    if idle.is_empty() {
                        pools.remove(&key);
                    }
                }
            }
        }
        let idle = pools
            .entry((user_id.to_string(), host.to_string()))
            .or_default();
        if idle.len() >= limits::PROVIDER_IDLE_CONNECTIONS {
            idle.remove(0);
        }
        idle.push((sender, now_ms));
    }

    /// The number of idle connections of `user_id` to `host`.
    #[cfg(test)]
    pub fn idle_count(&self, user_id: &str, host: &str) -> usize {
        lock(&self.0)
            .get(&(user_id.to_string(), host.to_string()))
            .map_or(0, Vec::len)
    }

    /// The number of idle connections over every account and host, as they are kept at this
    /// moment (`provider` of `idle_connections` of health).
    pub fn idle_total(&self) -> usize {
        lock(&self.0).values().map(Vec::len).sum()
    }
}

/// The TLS client of a node.
pub struct Egress {
    connector: TlsConnector,
    mail_connector: TlsConnector,
    /// The idle connections to providers.
    pub provider_idle: Arc<ProviderConnections>,
    /// The node-wide bound of provider requests in flight (enclave.md section 8).
    inflight: Arc<Semaphore>,
    /// The node-wide bound of outbound connections being opened (enclave.md section 8): a
    /// place is held from the first attempt to the open connection or the last failure.
    opens: Arc<Semaphore>,
    /// The size of that bound.
    open_concurrency: usize,
    /// The counts of `egress` of health.
    pub counters: EgressCounters,
}

impl Egress {
    /// The TLS client of a running node: the trust roots are the `webpki-roots` compiled into
    /// the binary. `open_concurrency` is the bound of connections being opened at the same
    /// time (`Limits::open_concurrency`).
    pub fn new(clock: Arc<Clock>, open_concurrency: usize) -> Egress {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Egress::build(clock, roots, open_concurrency)
    }

    /// A TLS client that trusts the given roots only. Tests use it to trust the certificate
    /// authority of their provider stand-in. The node binary does not contain this function.
    #[cfg(test)]
    pub fn with_test_roots(
        clock: Arc<Clock>,
        roots: RootCertStore,
        open_concurrency: usize,
    ) -> Egress {
        Egress::build(clock, roots, open_concurrency)
    }

    /// The provider requests in flight at this moment: the places of the node-wide bound that
    /// are taken.
    pub fn provider_inflight(&self) -> usize {
        limits::PROVIDER_INFLIGHT.saturating_sub(self.inflight.available_permits())
    }

    /// The outbound connections being opened at this moment: the places of the bound of
    /// `open_concurrency` that are taken, the attempts and the backoffs between them included.
    pub fn open_inflight(&self) -> usize {
        self.open_concurrency
            .saturating_sub(self.opens.available_permits())
    }

    fn build(clock: Arc<Clock>, roots: RootCertStore, open_concurrency: usize) -> Egress {
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
            provider_idle: Arc::new(ProviderConnections::default()),
            inflight: Arc::new(Semaphore::new(limits::PROVIDER_INFLIGHT)),
            opens: Arc::new(Semaphore::new(open_concurrency)),
            open_concurrency,
            counters: EgressCounters::default(),
        }
    }

    /// Opens a connection to port 443 of `host` and returns its HTTP/1.1 sender: the byte pipe
    /// of the platform, TLS that ends inside the node with a certificate verified against the
    /// trust roots of this client at the time of the node clock, then HTTP/1.1. `budget` is
    /// the time limit of the call the connection is for: a failed attempt is repeated within
    /// half of it ([`Egress::open_at`]).
    ///
    /// This is the way of every outbound connection of a node: to a provider
    /// ([`Egress::send_to_provider`]) and to the log store (`crate::log_store`).
    pub(crate) async fn open(
        &self,
        platform: &dyn DynPlatform,
        host: &str,
        budget: Duration,
    ) -> Result<SendRequest<OnceBody>, OpenError> {
        self.open_at(platform, host, PROVIDER_PORT, true, budget)
            .await
    }

    /// [`Egress::open`] to `host:port`, with TLS or, for the log store endpoint of a node of
    /// the local platform only (enclave.md 5.14), over the plain byte pipe.
    ///
    /// An attempt that fails before any request byte left the node (the byte pipe, the
    /// refusal of the egress relay, the TLS handshake, the HTTP/1.1 handshake) is repeated: at
    /// most [`OPEN_ATTEMPTS`] attempts, with a full jitter backoff between them, as long as the
    /// attempts and the backoff stay within half of `budget`. The attempts of one open take one
    /// place of the bound of connections being opened; a further open waits for a place.
    pub(crate) async fn open_at(
        &self,
        platform: &dyn DynPlatform,
        host: &str,
        port: u16,
        tls: bool,
        budget: Duration,
    ) -> Result<SendRequest<OnceBody>, OpenError> {
        let server_name = match tls {
            true => match ServerName::try_from(host.to_string()) {
                Ok(name) => Some(name),
                Err(_) => {
                    self.counters.open_failures.count(OpenError::Tls);
                    return Err(OpenError::Tls);
                }
            },
            false => None,
        };
        self.with_attempts(platform, budget, move || {
            self.open_once(platform, host, port, server_name.clone())
        })
        .await
    }

    /// One attempt of [`Egress::open_at`].
    async fn open_once(
        &self,
        platform: &dyn DynPlatform,
        host: &str,
        port: u16,
        server_name: Option<ServerName<'static>>,
    ) -> Result<SendRequest<OnceBody>, OpenError> {
        let stream = platform.connect(host, port).await?;
        match server_name {
            None => Egress::handshake(stream).await,
            Some(name) => {
                let tls = self
                    .connector
                    .connect(name, stream)
                    .await
                    .map_err(|_| OpenError::Tls)?;
                Egress::handshake(tls).await
            }
        }
    }

    /// Runs `attempt` until it succeeds, at most [`OPEN_ATTEMPTS`] times, within one place of
    /// the bound of connections being opened. Between two attempts the node waits a full
    /// jitter backoff (base [`OPEN_BACKOFF_BASE`], cap [`OPEN_BACKOFF_CAP`]); an attempt is
    /// repeated only when it and the backoff before it stay within half of `budget`, counted
    /// from the moment the place was asked for, so the open never takes the whole time limit
    /// of its call. Every attempt and every repetition is counted.
    async fn with_attempts<T, F, Fut>(
        &self,
        platform: &dyn DynPlatform,
        budget: Duration,
        mut attempt: F,
    ) -> Result<T, OpenError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, OpenError>>,
    {
        let started = Instant::now();
        let _place = self
            .opens
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| OpenError::Transport)?;
        let mut attempts = 0;
        loop {
            match attempt().await {
                Ok(opened) => {
                    self.counters.opens.fetch_add(1, Ordering::Relaxed);
                    return Ok(opened);
                }
                Err(error) => {
                    self.counters.open_failures.count(error);
                    attempts += 1;
                    let backoff =
                        full_jitter(platform, attempts, OPEN_BACKOFF_BASE, OPEN_BACKOFF_CAP);
                    if attempts >= OPEN_ATTEMPTS || started.elapsed() + backoff > budget / 2 {
                        return Err(error);
                    }
                    self.counters.open_retries.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    /// The HTTP/1.1 handshake over an open byte stream: returns the sender of requests and
    /// drives the connection on a task of its own until the sender is dropped or the other
    /// side closes it.
    async fn handshake<IO>(io: IO) -> Result<SendRequest<OnceBody>, OpenError>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (sender, connection) =
            hyper::client::conn::http1::handshake::<_, OnceBody>(TokioIo::new(io))
                .await
                .map_err(|_| OpenError::Http)?;
        tokio::spawn(async move {
            // The connection ends when its sender is dropped or the other side closes it.
            let _ = connection.await;
        });
        Ok(sender)
    }

    /// Fixed mail destinations. TLS and its trusted clock stay inside the node. A failed
    /// attempt to open the connection is repeated by the rule of [`Egress::open_at`], within
    /// half of `budget`.
    pub(crate) async fn open_mail(
        &self,
        platform: &dyn DynPlatform,
        host: &str,
        port: u16,
        budget: Duration,
    ) -> Result<crate::platform::Stream, EgressError> {
        if !matches!(
            (host, port),
            ("imap.naver.com", 993) | ("smtp.naver.com", 465)
        ) {
            return Err(EgressError::Invalid);
        }
        let name = ServerName::try_from(host.to_string()).map_err(|_| EgressError::Invalid)?;
        let tls = self
            .with_attempts(platform, budget, move || {
                let name = name.clone();
                async move {
                    let stream = platform.connect(host, port).await?;
                    self.mail_connector
                        .connect(name, stream)
                        .await
                        .map_err(|_| OpenError::Tls)
                }
            })
            .await?;
        Ok(Box::new(tls))
    }

    /// Sends the request to the provider and returns the response head.
    ///
    /// The request carries `Host`, then `Content-Length` when it has a body or its method is
    /// `POST`, `PUT` or `PATCH`, then the given headers, then `Connection: keep-alive`.
    ///
    /// With `account`, the request goes over an idle connection of that account to the host
    /// when there is one, and its connection goes back to those idle connections when the
    /// response has ended (enclave.md 5.8 step 8). A request over an idle connection that ends
    /// without a response goes once more over a new connection when its method is `GET` or
    /// `HEAD`; a request of another method is not repeated, because whether the provider
    /// received it is unknown. Without `account` (the token address and the revocation
    /// address) every request opens its own connection.
    ///
    /// Every request takes a share of the node-wide bound of provider requests in flight and
    /// holds it until the exchange is dropped. `budget` is the time limit of the call: the
    /// opening of a new connection repeats a failed attempt within half of it
    /// ([`Egress::open_at`]).
    pub async fn send_to_provider(
        &self,
        platform: &dyn DynPlatform,
        account: Option<&str>,
        outbound: OutboundRequest,
        now_ms: u64,
        budget: Duration,
    ) -> Result<Exchange, EgressError> {
        let inflight = self
            .inflight
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| EgressError::Unreachable)?;
        let host = outbound.host().to_string();
        let idle = match account {
            Some(user_id) => self.provider_idle.take(user_id, &host, now_ms).await,
            None => None,
        };
        if idle.is_some() {
            self.counters
                .idle_reuses
                .provider
                .fetch_add(1, Ordering::Relaxed);
        }
        let repeatable = matches!(outbound.method.as_str(), "GET" | "HEAD");
        let (sender, response) = match idle {
            Some(mut sender) => match sender.send_request(build_request(&outbound)?).await {
                Ok(response) => (sender, response),
                Err(_) if repeatable => {
                    let mut fresh = self.open(platform, &host, budget).await?;
                    let response = fresh
                        .send_request(build_request(&outbound)?)
                        .await
                        .map_err(|_| EgressError::Unreachable)?;
                    (fresh, response)
                }
                Err(_) => return Err(EgressError::Unreachable),
            },
            None => {
                let mut fresh = self.open(platform, &host, budget).await?;
                let response = fresh
                    .send_request(build_request(&outbound)?)
                    .await
                    .map_err(|_| EgressError::Unreachable)?;
                (fresh, response)
            }
        };
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
        let mut provider_closes = false;
        for value in parts.headers.get_all(CONNECTION) {
            if let Ok(listed) = value.to_str() {
                let names: Vec<String> = listed
                    .split(',')
                    .map(|name| name.trim().to_ascii_lowercase())
                    .collect();
                provider_closes |= names.iter().any(|name| name == "close");
                dropped.extend(names);
            }
        }
        // A connection the provider closes after this response is not kept: the sender is
        // dropped with the exchange and the connection ends.
        let keep = match account {
            Some(user_id) if !provider_closes => Some(Keep {
                pool: self.provider_idle.clone(),
                user_id: user_id.to_string(),
                host: host.clone(),
                now_ms,
            }),
            _ => None,
        };
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
            sender: Some(sender),
            keep,
            _inflight: inflight,
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
    builder = builder.header(CONNECTION, HeaderValue::from_static("keep-alive"));
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
    fn a_request_carries_host_length_headers_and_connection_keep_alive() {
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
        assert_eq!(built.headers()[CONNECTION], "keep-alive");
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
