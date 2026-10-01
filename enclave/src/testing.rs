//! Test support. Compiled for tests only.
//!
//! The tests run a whole node against a provider stand-in: a TLS server on the loopback
//! interface. Two seams make that possible without changing what the node program does:
//!
//! - the platform: [`TestPlatform`] opens the byte pipe to the stand-in for every provider
//!   host, so the node still connects to `host:443` by name and still rejects IP literals and
//!   other ports in the address check;
//! - the trust roots: the node's TLS client trusts the certificate authority of the stand-in
//!   instead of the public roots.
//!
//! The same stand-in plays the log store when a test gives it a certificate for [`LOG_HOST`]:
//! a node of these tests reaches Amazon S3 as it reaches a provider.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use credential_enclave_protocol::app::{self, AccountKeys};
use credential_enclave_protocol::encoding::{b64u, b64u_decode, to_json, verify, Signed};
use credential_enclave_protocol::keys::{Binding, Custody};
use credential_enclave_protocol::record::{open_record, seal_record, Record};
use credential_enclave_protocol::{limits, purpose};
use hyper::body::Bytes;
use hyper::service::Service;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::api;
use crate::clock::Clock;
use crate::egress::Egress;
use crate::frame;
use crate::platform::local::{kernel_random, local_document, system_time_ms};
use crate::platform::{Listener, Measurement, Platform, PlatformError, Stream};
use crate::providers::Definitions;
use crate::state::{lock, Limits, Node};

/// A platform for tests: the local attestation document, and provider connections that end at
/// the stand-in registered for the host.
///
/// By default it stands for the local platform. [`TestPlatform::measured`] stands for the
/// nitro platform in what the rest of the program reads from a platform: its name, its custody
/// and its measurement. Its attestation document stays the unsigned local document, which is
/// enough for an app of these tests to read the node keys from.
#[derive(Default)]
pub struct TestPlatform {
    routes: Mutex<HashMap<String, SocketAddr>>,
    measurement: Option<Measurement>,
    /// Values the random source hands out before it reads the kernel, one per draw.
    draws: Mutex<std::collections::VecDeque<Vec<u8>>>,
    /// The host and the port of every provider connection the node asked for.
    connections: Mutex<Vec<(String, u16)>>,
}

impl TestPlatform {
    /// A platform that reports the name `nitro`, the custody `enclave` and `measurement`.
    pub fn measured(measurement: Measurement) -> TestPlatform {
        TestPlatform {
            measurement: Some(measurement),
            ..TestPlatform::default()
        }
    }

    /// A local platform whose random source answers its first draws with `draws`, in this
    /// order, and with kernel randomness after them. A draw of another length than the value
    /// at its turn fails.
    pub fn with_draws(draws: &[&[u8]]) -> TestPlatform {
        TestPlatform {
            draws: Mutex::new(draws.iter().map(|draw| draw.to_vec()).collect()),
            ..TestPlatform::default()
        }
    }

    /// Sends the connections to `host` to the stand-in at `address`.
    pub fn route(&self, host: &str, address: SocketAddr) {
        lock(&self.routes).insert(host.to_string(), address);
    }

    /// The host and the port of every provider connection the node asked for so far, in
    /// order, whether the connection was opened or not. Whoever carries the bytes of a node
    /// sees these destinations.
    pub fn connections(&self) -> Vec<(String, u16)> {
        lock(&self.connections).clone()
    }
}

impl Platform for TestPlatform {
    fn name(&self) -> &'static str {
        match self.measurement {
            Some(_) => "nitro",
            None => "local",
        }
    }

    fn custody(&self) -> &'static str {
        match self.measurement {
            Some(_) => "enclave",
            None => "operator",
        }
    }

    fn measurement(&self) -> Option<Measurement> {
        self.measurement
    }

    fn attestation(&self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, PlatformError> {
        Ok(local_document(user_data, nonce, system_time_ms()?))
    }

    fn fill_random(&self, out: &mut [u8]) -> Result<(), PlatformError> {
        if let Some(draw) = lock(&self.draws).pop_front() {
            if draw.len() != out.len() {
                return Err(PlatformError("a scripted draw has another length"));
            }
            out.copy_from_slice(&draw);
            return Ok(());
        }
        kernel_random(out)
    }

    fn trusted_time_ms(&self) -> Result<u64, PlatformError> {
        system_time_ms()
    }

    async fn listen(&self) -> Result<Listener, PlatformError> {
        TcpListener::bind("127.0.0.1:0")
            .await
            .map(Listener::Tcp)
            .map_err(|_| PlatformError("cannot listen"))
    }

    async fn connect(&self, host: &str, port: u16) -> Result<Stream, PlatformError> {
        lock(&self.connections).push((host.to_string(), port));
        if port != 443 {
            return Err(PlatformError("a provider connection goes to port 443"));
        }
        let address = lock(&self.routes)
            .get(host)
            .copied()
            .ok_or(PlatformError("no stand-in for this host"))?;
        let stream = TcpStream::connect(address)
            .await
            .map_err(|_| PlatformError("the stand-in refused the connection"))?;
        Ok(Box::new(stream))
    }
}

/// A request the provider stand-in received.
#[derive(Clone, Debug)]
pub struct Seen {
    /// The TLS server name the node asked for.
    pub server_name: String,
    pub method: String,
    pub target: String,
    /// Header names in lowercase, in the order received.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    /// The value of a header, by lowercase name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }

    /// The header names in the order received.
    pub fn header_names(&self) -> Vec<&str> {
        self.headers.iter().map(|(name, _)| name.as_str()).collect()
    }

    /// The body as form fields.
    pub fn form(&self) -> Vec<(String, String)> {
        url::form_urlencoded::parse(&self.body)
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect()
    }

    /// The value of a form field.
    pub fn form_value(&self, key: &str) -> Option<String> {
        self.form()
            .into_iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }
}

/// What the stand-in answers.
pub enum Reply {
    /// The raw bytes of an HTTP/1.1 response.
    Raw(Vec<u8>),
    /// The raw bytes of an HTTP/1.1 response, sent after a pause.
    Late(Duration, Vec<u8>),
    /// No answer: the connection stays open and silent.
    Hang,
}

impl Reply {
    /// A response with a JSON body and a `Content-Length`.
    pub fn json(status: u16, body: &Value) -> Reply {
        Reply::with_body(
            status,
            &[("content-type", "application/json")],
            body.to_string().as_bytes(),
        )
    }

    /// The same response, sent after `pause`.
    pub fn after(self, pause: Duration) -> Reply {
        match self {
            Reply::Raw(bytes) | Reply::Late(_, bytes) => Reply::Late(pause, bytes),
            Reply::Hang => Reply::Hang,
        }
    }

    /// A response with the given headers, a body and its `Content-Length`.
    pub fn with_body(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Reply {
        let mut response = format!("HTTP/1.1 {status} Status\r\n").into_bytes();
        for (name, value) in headers {
            response.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        response.extend_from_slice(format!("content-length: {}\r\n\r\n", body.len()).as_bytes());
        response.extend_from_slice(body);
        Reply::Raw(response)
    }
}

type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

/// A provider stand-in: a TLS server on the loopback interface with a certificate for the
/// given host names, signed by its own certificate authority.
pub struct Provider {
    pub address: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    authority: CertificateDer<'static>,
    hosts: Vec<String>,
}

impl Provider {
    /// Starts a stand-in for `hosts`. `handler` answers each request.
    pub async fn start(
        hosts: &[&str],
        handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static,
    ) -> Provider {
        let authority_key = rcgen::KeyPair::generate().unwrap();
        let mut authority_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        authority_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        authority_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "provider stand-in authority");
        authority_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let authority = authority_params.self_signed(&authority_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let names: Vec<String> = hosts.iter().map(|host| host.to_string()).collect();
        let mut leaf_params = rcgen::CertificateParams::new(names.clone()).unwrap();
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf_params
            .signed_by(&leaf_key, &authority, &authority_key)
            .unwrap();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handler: Handler = Arc::new(handler);
        let recorded = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let handler = handler.clone();
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let _ = serve_one(acceptor, stream, handler, recorded).await;
                });
            }
        });
        Provider {
            address,
            seen,
            authority: authority.der().clone(),
            hosts: names,
        }
    }

    /// The trust roots that accept this stand-in only.
    pub fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.authority.clone()).unwrap();
        roots
    }

    /// The requests received so far.
    pub fn seen(&self) -> Vec<Seen> {
        lock(&self.seen).clone()
    }

    /// The only request received so far.
    pub fn only(&self) -> Seen {
        let seen = self.seen();
        assert_eq!(seen.len(), 1, "expected exactly one provider request");
        seen[0].clone()
    }

    /// Routes the hosts of this stand-in to it.
    pub fn route(&self, platform: &TestPlatform) {
        for host in &self.hosts {
            platform.route(host, self.address);
        }
    }
}

async fn serve_one(
    acceptor: TlsAcceptor,
    stream: TcpStream,
    handler: Handler,
    recorded: Arc<Mutex<Vec<Seen>>>,
) -> std::io::Result<()> {
    let mut tls = acceptor.accept(stream).await?;
    let server_name = tls
        .get_ref()
        .1
        .server_name()
        .unwrap_or_default()
        .to_string();
    let mut buffer = Vec::new();
    let head_end = loop {
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        let mut chunk = [0u8; 4096];
        let read = tls.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default().to_string();
    let target = request_line.next().unwrap_or_default().to_string();
    let headers: Vec<(String, String)> = lines
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buffer[head_end..].to_vec();
    while body.len() < length {
        let mut chunk = vec![0u8; 65536];
        let read = tls.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    let seen = Seen {
        server_name,
        method,
        target,
        headers,
        body,
    };
    lock(&recorded).push(seen.clone());
    match handler(&seen) {
        Reply::Raw(bytes) => {
            tls.write_all(&bytes).await?;
            tls.shutdown().await?;
        }
        Reply::Late(pause, bytes) => {
            tokio::time::sleep(pause).await;
            tls.write_all(&bytes).await?;
            tls.shutdown().await?;
        }
        Reply::Hang => tokio::time::sleep(Duration::from_secs(3600)).await,
    }
    Ok(())
}

/// The bucket of the log store the tests name in the configuration of a node.
pub const LOG_BUCKET: &str = "credential-log-test-1";
/// The region of that bucket.
pub const LOG_REGION: &str = "us-west-2";
/// The host a node with that log store writes to.
pub const LOG_HOST: &str = "credential-log-test-1.s3.us-west-2.amazonaws.com";
/// The session token of the credentials the tests give a node for its log store.
pub const LOG_SESSION_TOKEN: &str = "test/session+token/of+the/log/store==";
/// The secret access key of those credentials.
pub const LOG_SECRET_ACCESS_KEY: &str = "test/secret+access/key/of+the/log/store";

/// Credentials for the log store that end at `expires_ms`.
pub fn log_credentials(expires_ms: u64) -> Value {
    json!({
        "access_key_id": "ASIATESTACCESSKEYID",
        "secret_access_key": LOG_SECRET_ACCESS_KEY,
        "session_token": LOG_SESSION_TOKEN,
        "expires_ms": expires_ms,
    })
}

/// The operator configuration the tests give a node: every provider of the definitions, with
/// the callback address of its name.
pub fn operator_config(definitions: &Definitions) -> Value {
    let mut providers = serde_json::Map::new();
    for name in definitions.names() {
        providers.insert(
            name.to_string(),
            json!({
                "client_id": format!("{name}-client"),
                "client_secret": format!("{name}-secret"),
                "redirect_uri": format!("https://api.example/api/integrations/{name}/oauth/callback"),
                "publishable_key": "pk_test_1",
            }),
        );
    }
    json!({"providers": providers})
}

/// The outcome of a `forward` call.
pub struct Forwarded {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub entry: Value,
    pub body: Vec<u8>,
}

impl Forwarded {
    /// The value of a provider response header.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }
}

/// A node under test.
pub struct Harness {
    pub node: Arc<Node>,
    pub platform: Arc<TestPlatform>,
    router: Router,
}

impl Harness {
    /// A node with the embedded definitions and the default limits that reaches the given
    /// stand-in for every host the stand-in has a certificate for. The operator configuration
    /// is not set.
    pub fn new(provider: &Provider) -> Harness {
        Harness::with(provider, Definitions::embedded(), Limits::default())
    }

    /// A node with the given definitions and limits.
    pub fn with(provider: &Provider, definitions: Definitions, limits: Limits) -> Harness {
        Harness::on(TestPlatform::default(), provider, definitions, limits)
    }

    /// A node of custody `enclave`: its platform reports the name `nitro` and `measurement`.
    pub fn measured(provider: &Provider, measurement: Measurement) -> Harness {
        Harness::on(
            TestPlatform::measured(measurement),
            provider,
            Definitions::embedded(),
            Limits::default(),
        )
    }

    fn on(
        platform: TestPlatform,
        provider: &Provider,
        definitions: Definitions,
        limits: Limits,
    ) -> Harness {
        let platform = Arc::new(platform);
        provider.route(&platform);
        let clock = Arc::new(Clock::start(platform.as_ref()).unwrap());
        let egress = Egress::with_test_roots(clock.clone(), provider.roots());
        let node = Arc::new(
            Node::start(
                platform.clone(),
                clock,
                definitions,
                egress,
                "v0.0.0-test",
                limits,
            )
            .unwrap(),
        );
        Harness {
            router: api::router(node.clone()),
            node,
            platform,
        }
    }

    /// A configured node.
    pub async fn configured(provider: &Provider) -> Harness {
        let harness = Harness::new(provider);
        let (status, _) = harness
            .post("/v1/config", operator_config(&harness.node.definitions))
            .await;
        assert_eq!(status, 200);
        harness
    }

    /// Gives the node the operator configuration with the log store of the tests, and
    /// credentials for it that end in 12 hours.
    pub async fn use_log_store(&self) {
        let mut config = operator_config(&self.node.definitions);
        config["log_store"] = json!({"bucket": LOG_BUCKET, "region": LOG_REGION});
        let (status, response) = self.post("/v1/config", config).await;
        assert_eq!(status, 200, "{response}");
        let expires_ms = self.node.now_ms() + 12 * 60 * 60 * 1000;
        let (status, response) = self
            .post("/v1/log-store/credentials", log_credentials(expires_ms))
            .await;
        assert_eq!(status, 200, "{response}");
    }

    /// Sends one request to the router and returns the status, the content type and the body.
    pub async fn send(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
    ) -> (StatusCode, String, Bytes) {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-length", body.len())
            .body(Body::from(body))
            .unwrap();
        let response = TowerToHyperService::new(self.router.clone())
            .call(request)
            .await
            .unwrap();
        let status = response.status();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, content_type, bytes)
    }

    /// A JSON call. Returns the status and the JSON body.
    pub async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let (status, content_type, bytes) = self.send(Method::POST, path, to_json(&body)).await;
        assert_eq!(content_type, "application/json", "{path}");
        (status.as_u16(), serde_json::from_slice(&bytes).unwrap())
    }

    /// `GET /v1/health`.
    pub async fn health(&self) -> Value {
        let (status, _, bytes) = self.send(Method::GET, "/v1/health", Vec::new()).await;
        assert_eq!(status, StatusCode::OK);
        serde_json::from_slice(&bytes).unwrap()
    }

    /// A `forward` call. `Err` carries the status and the failure body.
    pub async fn forward(&self, meta: Value, payload: &[u8]) -> Result<Forwarded, (u16, Value)> {
        let mut request = frame::encode_head(&meta);
        request.extend_from_slice(payload);
        let (status, content_type, bytes) = self.send(Method::POST, "/v1/forward", request).await;
        if status != StatusCode::OK {
            assert_eq!(content_type, "application/json");
            return Err((status.as_u16(), serde_json::from_slice(&bytes).unwrap()));
        }
        assert_eq!(content_type, frame::CONTENT_TYPE);
        let (meta, body) = frame::decode(&bytes).unwrap();
        let headers = meta["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| {
                (
                    pair[0].as_str().unwrap().to_string(),
                    pair[1].as_str().unwrap().to_string(),
                )
            })
            .collect();
        Ok(Forwarded {
            status: meta["status"].as_u64().unwrap() as u16,
            headers,
            entry: meta["entry"].clone(),
            body: body.to_vec(),
        })
    }

    /// The node signing public key.
    pub fn node_public(&self) -> [u8; 32] {
        self.node.keys.sign_public()
    }

    /// Verifies a signed value of this node and returns its body as JSON.
    pub fn verified(&self, context: &str, signed: &Value) -> Value {
        let signed: Signed = serde_json::from_value(signed.clone()).unwrap();
        let body = verify(&self.node_public(), context, &signed).unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    /// The `seq` of the end of the chain of an account.
    pub fn head_seq(&self, user_id: &str) -> u64 {
        self.node
            .account(user_id)
            .map_or(0, |account| lock(&account).head.seq)
    }
}

/// Everything a node answered to one call.
#[derive(Clone, Debug)]
pub struct Answer {
    pub status: u16,
    /// Header names in lowercase with the bytes of their values, in the order of the response.
    /// Trailers of the body follow the headers.
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

impl Harness {
    /// A node with the embedded definitions and the default limits on a platform whose random
    /// source answers its first draws with `draws` ([`TestPlatform::with_draws`]).
    pub fn with_draws(provider: &Provider, draws: &[&[u8]]) -> Harness {
        Harness::on(
            TestPlatform::with_draws(draws),
            provider,
            Definitions::embedded(),
            Limits::default(),
        )
    }

    /// Sends one request to the router and returns everything the node answered: the status,
    /// every header, the whole body and the trailers of the body.
    pub async fn call(&self, method: Method, path: &str, body: Vec<u8>) -> Answer {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-length", body.len())
            .body(Body::from(body))
            .unwrap();
        let response = TowerToHyperService::new(self.router.clone())
            .call(request)
            .await
            .unwrap();
        let (parts, mut frames) = response.into_parts();
        let owned = |map: &axum::http::HeaderMap| -> Vec<(String, Vec<u8>)> {
            map.iter()
                .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
                .collect()
        };
        let mut headers = owned(&parts.headers);
        let mut body = Vec::new();
        loop {
            let next = std::future::poll_fn(|context| {
                hyper::body::Body::poll_frame(std::pin::Pin::new(&mut frames), context)
            });
            let Some(frame) = next.await else {
                break;
            };
            match frame.unwrap().into_data() {
                Ok(data) => body.extend_from_slice(&data),
                Err(frame) => headers.extend(frame.trailers_ref().map(owned).unwrap_or_default()),
            }
        }
        Answer {
            status: parts.status.as_u16(),
            headers,
            body,
        }
    }
}

/// The app of one account: its keys and the commands it sends.
pub struct App {
    pub user_id: String,
    pub keys: AccountKeys,
    /// The custody of the node this app talks to. The test platform is a `local` platform, so
    /// an app hands out the user key of custody `operator` unless a test changes this field.
    pub custody: Custody,
}

/// What an attestation call gave an app.
pub struct Attested {
    pub node: String,
    pub seal_public: [u8; 32],
    pub challenge: String,
}

impl App {
    /// An app whose master key is 32 times `seed`.
    pub fn new(user_id: &str, seed: u8) -> App {
        App {
            user_id: user_id.to_string(),
            keys: app::derive_account_keys(&[seed; 32]),
            custody: Custody::Operator,
        }
    }

    /// Fetches an attestation and reads the node keys from the binding inside the document
    /// (protocol.md 4.4): the nonce matches, the binding parses, and the challenge statement
    /// binds the challenge of the response to the nonce of this request.
    pub async fn attest(&self, harness: &Harness) -> Attested {
        let nonce = [0x5au8; 32];
        let (status, response) = harness
            .post("/v1/attestation", json!({"nonce": b64u(&nonce)}))
            .await;
        assert_eq!(status, 200);
        assert_eq!(response["platform"], harness.node.platform.name());
        let document: Value =
            serde_json::from_slice(&b64u_decode(response["document"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(document["nonce"], b64u(&nonce));
        let binding: Binding =
            serde_json::from_slice(&b64u_decode(document["binding"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(binding.v, 1);
        assert_eq!(binding.sign, response["node"].as_str().unwrap());
        let sign_public: [u8; 32] = b64u_decode(&binding.sign).unwrap().try_into().unwrap();
        let challenge = response["challenge"].as_str().unwrap().to_string();
        let statement: Signed =
            serde_json::from_value(response["challenge_statement"].clone()).unwrap();
        app::verify_challenge_statement(&sign_public, &statement, &nonce, &challenge).unwrap();
        Attested {
            node: binding.sign,
            seal_public: b64u_decode(&binding.seal).unwrap().try_into().unwrap(),
            challenge,
        }
    }

    /// The envelope of a grant that ends at `not_after_ms`. It carries the user key of the
    /// custody of this app.
    pub fn grant_envelope(&self, attested: &Attested, not_after_ms: u64) -> Value {
        let payload = app::grant_payload(
            &self.keys,
            &self.user_id,
            &attested.node,
            &attested.challenge,
            self.custody,
            not_after_ms,
        );
        self.envelope(attested, &payload)
    }

    /// The envelope of a revoke.
    pub fn revoke_envelope(&self, attested: &Attested) -> Value {
        let payload = app::revoke_payload(
            &self.keys,
            &self.user_id,
            &attested.node,
            &attested.challenge,
        );
        self.envelope(attested, &payload)
    }

    /// Signs and seals a command payload for the attested node.
    pub fn envelope(&self, attested: &Attested, payload: &[u8]) -> Value {
        let mut seed = [0u8; 32];
        kernel_random(&mut seed).unwrap();
        let envelope = app::seal_command(
            &self.keys.sign,
            &attested.seal_public,
            &attested.node,
            payload,
            &seed,
        )
        .unwrap();
        serde_json::to_value(envelope).unwrap()
    }

    /// Sends an envelope and returns the whole response of `messages`.
    pub async fn send(&self, harness: &Harness, envelope: Value) -> Value {
        let (status, response) = harness
            .post(
                "/v1/messages",
                json!({"user_id": self.user_id, "envelope": envelope}),
            )
            .await;
        assert_eq!(status, 200, "{response}");
        response
    }

    /// Grants for 30 days and asserts that the node accepted. Returns the response.
    pub async fn grant(&self, harness: &Harness) -> Value {
        let attested = self.attest(harness).await;
        let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
        let response = self
            .send(harness, self.grant_envelope(&attested, not_after_ms))
            .await;
        let reply = harness.verified(purpose::REPLY, &response["reply"]);
        assert_eq!(reply["ok"], true, "{reply}");
        assert_eq!(reply["challenge"], attested.challenge.as_str());
        response
    }

    /// Revokes and returns the response.
    pub async fn revoke(&self, harness: &Harness) -> Value {
        let attested = self.attest(harness).await;
        self.send(harness, self.revoke_envelope(&attested)).await
    }

    /// Creates a record the way an app does (protocol.md section 6).
    pub fn record(&self, kind: &str, provider: &str, plaintext: &Value) -> Value {
        let mut id = [0u8; 16];
        let mut nonce = [0u8; 12];
        kernel_random(&mut id).unwrap();
        kernel_random(&mut nonce).unwrap();
        let record = seal_record(
            self.keys.user_key_of(self.custody),
            &id,
            &nonce,
            &self.user_id,
            &self.keys.key_id(),
            self.custody,
            kind,
            provider,
            &to_json(plaintext),
        );
        serde_json::to_value(record).unwrap()
    }

    /// Opens a record with the user key of the custody the record names.
    pub fn open(&self, record: &Value) -> Value {
        let record = Record::from_value(record).unwrap();
        let custody = Custody::parse(&record.custody).unwrap();
        let plaintext = open_record(self.keys.user_key_of(custody), &record).unwrap();
        serde_json::from_slice(&plaintext).unwrap()
    }

    /// Verifies the node signature of an entry and opens its event with the log key.
    pub fn event(&self, harness: &Harness, entry: &Value) -> Value {
        let signed: Signed = serde_json::from_value(entry.clone()).unwrap();
        let body = verify(&harness.node_public(), purpose::LOG_ENTRY, &signed).unwrap();
        serde_json::from_slice(&app::open_entry(&self.keys.log, &body).unwrap()).unwrap()
    }

    /// The body of an entry.
    pub fn entry_body(&self, harness: &Harness, entry: &Value) -> Value {
        harness.verified(purpose::LOG_ENTRY, entry)
    }
}
