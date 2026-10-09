//! The egress relay (enclave.md section 9): the way of the node to the providers.
//!
//! An enclave has no network. The node opens a vsock connection to port 8443 of the parent
//! instance and sends one line, `CONNECT {host}:{port}\n`. The relay answers `OK\n` and moves
//! the bytes between the node and a TCP connection to that host, or it answers `ERR\n` and
//! closes. TLS ends inside the node: the relay sees ciphertext only.
//!
//! The relay connects to port 443 of the hosts the provider definitions name, to the host of
//! the log store when the environment names one, and the two fixed Naver mail endpoints.
//! This list is a second
//! line: the node itself sends credentials only to the addresses of its definitions, which are
//! part of the measured binary, and log entries only to its log store.

use std::collections::BTreeSet;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpSocket;

use crate::relay::{self, BoxFuture, Stream, VsockListener};

/// The vsock port of the egress relay.
pub const EGRESS_PORT: u32 = 8443;
/// The port of the HTTP provider endpoints.
pub const PROVIDER_PORT: u16 = 443;

/// Longest DNS name.
const HOST_LIMIT_BYTES: usize = 253;
/// Longest first line without its line end: `CONNECT `, a DNS name, `:` and a port.
const CONNECT_LINE_LIMIT_BYTES: usize = 8 + HOST_LIMIT_BYTES + 1 + 5;
/// Longest wait for the first line.
const CONNECT_LINE_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest wait for the name lookup and the TCP connection to a provider.
const PROVIDER_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const REPLY_OK: &[u8] = b"OK\n";
const REPLY_ERR: &[u8] = b"ERR\n";

/// True for a DNS name in the form the definitions and the node use: lowercase letters, digits,
/// `-` and `.`, with no empty label.
fn is_host_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= HOST_LIMIT_BYTES
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
        })
}

/// The host of an `https://host/path` address of a definition.
fn host_of(address: &str) -> Option<&str> {
    let rest = address.strip_prefix("https://")?;
    let host = rest.split('/').next()?;
    is_host_name(host).then_some(host)
}

/// The hosts the relay connects to.
#[derive(Debug, PartialEq, Eq)]
pub struct Allowlist {
    hosts: BTreeSet<String>,
}

impl Allowlist {
    /// Computes the list from the provider definitions of the node
    /// (`enclave/src/providers/definitions.json`): the hosts of `api`, the host of the token
    /// address and the host of the revocation address of every provider. The host of the
    /// authorization address is not in the list: the node never connects to it.
    pub fn from_definitions(text: &str) -> Result<Allowlist, String> {
        let definitions: serde_json::Map<String, Value> = serde_json::from_str(text)
            .map_err(|_| "the provider definitions are not a JSON object".to_string())?;
        let mut hosts = BTreeSet::new();
        for (provider, definition) in &definitions {
            let rules = definition
                .get("api")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{provider}: api is not a list"))?;
            for rule in rules {
                let host = rule
                    .get("host")
                    .and_then(Value::as_str)
                    .filter(|host| is_host_name(host))
                    .ok_or_else(|| format!("{provider}: an api host is not a DNS name"))?;
                hosts.insert(host.to_string());
            }
            let token = definition
                .pointer("/token/url")
                .and_then(Value::as_str)
                .and_then(host_of)
                .ok_or_else(|| format!("{provider}: the token address is not an https address"))?;
            hosts.insert(token.to_string());
            match definition.get("revoke") {
                None | Some(Value::Null) => {}
                Some(revoke) => {
                    let host = revoke
                        .get("url")
                        .and_then(Value::as_str)
                        .and_then(host_of)
                        .ok_or_else(|| {
                            format!("{provider}: the revocation address is not an https address")
                        })?;
                    hosts.insert(host.to_string());
                }
            }
        }
        Ok(Allowlist { hosts })
    }

    /// The list with the host of the log store of the node added:
    /// `{bucket}.s3.{region}.amazonaws.com`.
    pub fn with_log_store(mut self, host: String) -> Allowlist {
        self.hosts.insert(host);
        self
    }

    /// True when the relay connects to `host:port`.
    pub fn allows(&self, host: &str, port: u16) -> bool {
        (port == PROVIDER_PORT && self.hosts.contains(host))
            || matches!(
                (host, port),
                ("imap.naver.com", 993) | ("smtp.naver.com", 465)
            )
    }

    /// The number of HTTP hosts, excluding the two fixed mail endpoints.
    pub fn len(&self) -> usize {
        self.hosts.len()
    }
}

/// Reads the target of a first line (without its line end). The line is exactly
/// `CONNECT {host}:{port}`: one space, a DNS name in lowercase, a decimal port without sign or
/// padding.
pub fn parse_connect(line: &[u8]) -> Option<(&str, u16)> {
    let line = std::str::from_utf8(line).ok()?;
    let target = line.strip_prefix("CONNECT ")?;
    let (host, port) = target.rsplit_once(':')?;
    if !is_host_name(host) {
        return None;
    }
    let canonical = !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && (port == "0" || !port.starts_with('0'));
    if !canonical {
        return None;
    }
    Some((host, port.parse().ok()?))
}

/// Opens connections to providers.
pub trait Outbound: Send + Sync + 'static {
    /// Opens a byte pipe to `host:port`.
    fn connect<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<Stream>>;
}

/// TCP connections with the name lookup of the parent instance.
pub struct TcpOutbound;

impl Outbound for TcpOutbound {
    fn connect<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            let mut last_error = io::Error::from(io::ErrorKind::NotFound);
            for address in tokio::net::lookup_host((host, port)).await? {
                let socket = if address.is_ipv4() {
                    TcpSocket::new_v4()
                } else {
                    TcpSocket::new_v6()
                };
                let connected = match socket {
                    Ok(socket) => match socket.set_keepalive(true) {
                        Ok(()) => socket.connect(address).await,
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error),
                };
                match connected {
                    Ok(stream) => {
                        let _ = stream.set_nodelay(true);
                        return Ok(Box::new(stream) as Stream);
                    }
                    Err(error) => last_error = error,
                }
            }
            Err(last_error)
        })
    }
}

/// What the relay did with one connection of the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The bytes were relayed until both sides ended.
    Relayed,
    /// The first line was not a `CONNECT` line, was too long or did not arrive in time.
    Malformed,
    /// The target is not port 443 of a host of the list.
    NotAllowed(String),
    /// The provider could not be reached: the host and the failure of the name lookup or of the
    /// connection.
    Unreachable(String, String),
}

/// Reads the first line, one byte at a time: the bytes after the line belong to the provider
/// connection and stay in the stream.
async fn read_connect_line<S>(stream: &mut S) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut line = Vec::with_capacity(64);
    loop {
        let byte = stream.read_u8().await.ok()?;
        if byte == b'\n' {
            return Some(line);
        }
        if line.len() == CONNECT_LINE_LIMIT_BYTES {
            return None;
        }
        line.push(byte);
    }
}

async fn refuse<S>(mut inbound: S, outcome: Outcome) -> Outcome
where
    S: AsyncWrite + Unpin,
{
    let _ = inbound.write_all(REPLY_ERR).await;
    let _ = inbound.shutdown().await;
    outcome
}

/// Serves one connection of the node: reads the `CONNECT` line, checks the target against the
/// list, opens the provider connection, answers and relays.
pub async fn relay<S>(mut inbound: S, allowlist: &Allowlist, outbound: &dyn Outbound) -> Outcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let line = tokio::time::timeout(CONNECT_LINE_TIMEOUT, read_connect_line(&mut inbound)).await;
    let Ok(Some(line)) = line else {
        return refuse(inbound, Outcome::Malformed).await;
    };
    let Some((host, port)) = parse_connect(&line) else {
        return refuse(inbound, Outcome::Malformed).await;
    };
    if !allowlist.allows(host, port) {
        return refuse(inbound, Outcome::NotAllowed(format!("{host}:{port}"))).await;
    }
    let provider =
        tokio::time::timeout(PROVIDER_CONNECT_TIMEOUT, outbound.connect(host, port)).await;
    let provider = match provider {
        Ok(Ok(provider)) => provider,
        Ok(Err(error)) => {
            let outcome = Outcome::Unreachable(host.to_string(), error.to_string());
            return refuse(inbound, outcome).await;
        }
        Err(_) => {
            let outcome = Outcome::Unreachable(host.to_string(), "no connection in time".into());
            return refuse(inbound, outcome).await;
        }
    };
    if inbound.write_all(REPLY_OK).await.is_err() || inbound.flush().await.is_err() {
        return Outcome::Relayed;
    }
    relay::pipe(inbound, provider).await;
    Outcome::Relayed
}

/// The egress relay: serves every connection of `listener`. A refused connection leaves one
/// line in the output of the host program.
pub async fn serve(
    listener: VsockListener,
    allowlist: Arc<Allowlist>,
    outbound: Arc<dyn Outbound>,
) {
    loop {
        let Ok(inbound) = listener.accept().await else {
            relay::pause_after_failed_accept().await;
            continue;
        };
        let allowlist = allowlist.clone();
        let outbound = outbound.clone();
        tokio::spawn(async move {
            match relay(inbound, &allowlist, outbound.as_ref()).await {
                Outcome::Relayed => {}
                Outcome::Malformed => {
                    crate::log("egress: refused a connection without a valid CONNECT line");
                }
                Outcome::NotAllowed(target) => {
                    crate::log(&format!("egress: refused {target}: not a host of the list"));
                }
                Outcome::Unreachable(host, reason) => {
                    crate::log(&format!("egress: cannot reach {host}: {reason}"));
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tokio::io::DuplexStream;

    use super::*;

    const DEFINITIONS: &str = r#"{
        "first": {
            "authorize": {"url": "https://accounts.first.example/authorize"},
            "token": {"url": "https://token.first.example/oauth/token"},
            "revoke": {"url": "https://revoke.first.example/oauth/revoke"},
            "api": [
                {"host": "api.first.example", "prefixes": ["/v1/"], "exact": []},
                {"host": "files.first.example", "prefixes": ["/files/"], "exact": []}
            ]
        },
        "second": {
            "authorize": {"url": "https://second.example/authorize"},
            "token": {"url": "https://second.example/token"},
            "revoke": null,
            "api": [{"host": "api.second.example", "prefixes": [], "exact": ["/me"]}]
        }
    }"#;

    fn allowlist() -> Allowlist {
        Allowlist::from_definitions(DEFINITIONS).unwrap()
    }

    /// A provider stand-in: every connection is one end of an in-memory pipe, and the test
    /// holds the other end.
    #[derive(Default)]
    struct Providers {
        reachable: bool,
        dialed: Mutex<Vec<(String, u16)>>,
        far_ends: Mutex<Vec<DuplexStream>>,
    }

    impl Providers {
        fn reachable() -> Providers {
            Providers {
                reachable: true,
                ..Providers::default()
            }
        }

        fn dialed(&self) -> Vec<(String, u16)> {
            self.dialed.lock().unwrap().clone()
        }

        fn take_far_end(&self) -> DuplexStream {
            self.far_ends.lock().unwrap().remove(0)
        }
    }

    impl Outbound for Providers {
        fn connect<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<Stream>> {
            Box::pin(async move {
                self.dialed.lock().unwrap().push((host.to_string(), port));
                if !self.reachable {
                    return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
                }
                let (near, far) = tokio::io::duplex(1024);
                self.far_ends.lock().unwrap().push(far);
                Ok(Box::new(near) as Stream)
            })
        }
    }

    /// Reads up to the end of the stream.
    async fn read_all(stream: &mut DuplexStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        bytes
    }

    /// Sends `first_bytes` as the node would and returns what the relay answered and did.
    async fn refused(first_bytes: &[u8], providers: &Providers) -> (Vec<u8>, Outcome) {
        let (mut node, inbound) = tokio::io::duplex(1024);
        node.write_all(first_bytes).await.unwrap();
        let outcome = relay(inbound, &allowlist(), providers).await;
        (read_all(&mut node).await, outcome)
    }

    #[test]
    fn the_list_holds_the_api_token_and_revocation_hosts() {
        let list = allowlist();
        let expected: BTreeSet<String> = [
            "api.first.example",
            "files.first.example",
            "token.first.example",
            "revoke.first.example",
            "api.second.example",
            "second.example",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(list.hosts, expected);
        assert_eq!(list.len(), 6);

        assert!(list.allows("api.first.example", 443));
        assert!(list.allows("token.first.example", 443));
        assert!(list.allows("revoke.first.example", 443));
        // The authorization address is opened by the browser of the user, never by the node.
        assert!(!list.allows("accounts.first.example", 443));
        // Port 443 only, exact names only.
        assert!(!list.allows("api.first.example", 80));
        assert!(!list.allows("api.first.example", 8443));
        assert!(!list.allows("first.example", 443));
        assert!(!list.allows("evil.api.first.example", 443));
        assert!(!list.allows("api.first.example.evil.test", 443));
        assert!(!list.allows("", 443));
    }

    #[test]
    fn the_host_of_the_log_store_is_added_to_the_list() {
        let host = "character-credential-log-dev-1.s3.us-west-2.amazonaws.com";
        assert!(!allowlist().allows(host, 443));
        let list = allowlist().with_log_store(host.to_string());
        assert_eq!(list.len(), 7);
        assert!(list.allows(host, 443));
        assert!(list.allows("api.first.example", 443));
        // That host only: no other bucket, no other region, no other port.
        assert!(!list.allows("another-bucket.s3.us-west-2.amazonaws.com", 443));
        assert!(!list.allows(
            "character-credential-log-dev-1.s3.eu-west-1.amazonaws.com",
            443
        ));
        assert!(!list.allows("s3.us-west-2.amazonaws.com", 443));
        assert!(!list.allows(host, 80));
    }

    #[test]
    fn the_list_of_the_embedded_definitions_is_the_list_of_the_node() {
        let list = Allowlist::from_definitions(crate::DEFINITIONS).unwrap();
        // One host of each kind of the definitions the node is built with.
        assert!(list.allows("gmail.googleapis.com", 443));
        assert!(list.allows("oauth2.googleapis.com", 443));
        assert!(list.allows("login.microsoftonline.com", 443));
        assert!(list.allows("graph.microsoft.com", 443));
        assert!(!list.allows("accounts.google.com", 443));
        assert!(!list.allows("example.com", 443));
    }

    #[test]
    fn definitions_that_cannot_be_read_give_no_list() {
        for text in [
            "",
            "[]",
            r#"{"p": {"token": {"url": "https://t.example/token"}, "revoke": null}}"#,
            r#"{"p": {"api": [{"host": "API.example"}], "token": {"url": "https://t.example/t"}}}"#,
            r#"{"p": {"api": [], "token": {"url": "http://t.example/token"}, "revoke": null}}"#,
            r#"{"p": {"api": [], "token": {"url": "https://t.example:8443/token"}}}"#,
            r#"{"p": {"api": [], "token": {"url": "https://t.example/t"}, "revoke": {"url": 1}}}"#,
            r#"{"p": {"api": [], "token": {}}}"#,
        ] {
            assert!(Allowlist::from_definitions(text).is_err(), "{text}");
        }
    }

    #[test]
    fn a_connect_line_names_one_host_and_one_port() {
        assert_eq!(
            parse_connect(b"CONNECT oauth2.googleapis.com:443"),
            Some(("oauth2.googleapis.com", 443))
        );
        assert_eq!(
            parse_connect(b"CONNECT a-b.c9.example:8443"),
            Some(("a-b.c9.example", 8443))
        );
        assert_eq!(parse_connect(b"CONNECT host:0"), Some(("host", 0)));

        for line in [
            &b""[..],
            b"CONNECT",
            b"CONNECT ",
            b"CONNECT host",
            b"CONNECT host:",
            b"CONNECT :443",
            b"connect host:443",
            b"GET / HTTP/1.1",
            b"CONNECT  host:443",
            b"CONNECT host:443 ",
            b"CONNECT host:443\r",
            b"CONNECT host:443 HTTP/1.1",
            b"CONNECT Host:443",
            b"CONNECT ho st:443",
            b"CONNECT host:+443",
            b"CONNECT host:0443",
            b"CONNECT host:443x",
            b"CONNECT host:65536",
            b"CONNECT host:123456",
            b"CONNECT .host:443",
            b"CONNECT host.:443",
            b"CONNECT a..b:443",
            b"CONNECT [::1]:443",
            b"CONNECT user@host:443",
            b"CONNECT host/path:443",
            b"CONNECT h\xc3\xb6st:443",
            b"CONNECT host\0:443",
        ] {
            assert_eq!(
                parse_connect(line),
                None,
                "{:?}",
                String::from_utf8_lossy(line)
            );
        }
        let long = format!("CONNECT {}:443", "a".repeat(HOST_LIMIT_BYTES + 1));
        assert_eq!(parse_connect(long.as_bytes()), None);
    }

    #[tokio::test]
    async fn an_allowed_target_is_answered_ok_and_relayed_in_both_directions() {
        let providers = Arc::new(Providers::reachable());
        let (mut node, inbound) = tokio::io::duplex(1024);
        let relayed = {
            let providers = providers.clone();
            tokio::spawn(async move { relay(inbound, &allowlist(), providers.as_ref()).await })
        };

        // The node sends the line and, right behind it, the first bytes for the provider.
        node.write_all(b"CONNECT api.first.example:443\nclient hello")
            .await
            .unwrap();
        let mut reply = [0u8; 3];
        node.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"OK\n");
        assert_eq!(providers.dialed(), [("api.first.example".to_string(), 443)]);

        // The relay took the line only: the provider receives every byte after it.
        let mut provider = providers.take_far_end();
        let mut buffer = [0u8; 12];
        provider.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"client hello");

        provider.write_all(b"server hello").await.unwrap();
        node.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"server hello");

        // The provider ends the exchange, then the node closes: the relay is done.
        provider.shutdown().await.unwrap();
        assert_eq!(node.read(&mut buffer).await.unwrap(), 0);
        node.shutdown().await.unwrap();
        assert_eq!(read_all(&mut provider).await, b"");
        assert_eq!(relayed.await.unwrap(), Outcome::Relayed);
    }

    #[tokio::test]
    async fn a_target_outside_the_list_is_answered_err_and_never_dialed() {
        let providers = Providers::reachable();
        for (line, target) in [
            ("CONNECT evil.example:443\n", "evil.example:443"),
            (
                "CONNECT accounts.first.example:443\n",
                "accounts.first.example:443",
            ),
            ("CONNECT api.first.example:80\n", "api.first.example:80"),
            ("CONNECT api.first.example:8443\n", "api.first.example:8443"),
            ("CONNECT 169.254.169.254:443\n", "169.254.169.254:443"),
            ("CONNECT localhost:443\n", "localhost:443"),
        ] {
            let (reply, outcome) = refused(line.as_bytes(), &providers).await;
            assert_eq!(reply, b"ERR\n", "{line}");
            assert_eq!(outcome, Outcome::NotAllowed(target.to_string()), "{line}");
        }
        assert!(providers.dialed().is_empty());
    }

    #[tokio::test]
    async fn a_line_that_is_not_a_connect_line_is_answered_err() {
        let providers = Providers::reachable();
        for line in [
            &b"GET / HTTP/1.1\r\n\r\n"[..],
            b"CONNECT api.first.example:443\r\n",
            b"CONNECT API.FIRST.EXAMPLE:443\n",
            b"CONNECT api.first.example\n",
            b"\n",
        ] {
            let (reply, outcome) = refused(line, &providers).await;
            assert_eq!(reply, b"ERR\n", "{:?}", String::from_utf8_lossy(line));
            assert_eq!(outcome, Outcome::Malformed);
        }
        // A line that never ends is cut at the limit.
        let endless = vec![b'a'; CONNECT_LINE_LIMIT_BYTES + 1];
        let (reply, outcome) = refused(&endless, &providers).await;
        assert_eq!(reply, b"ERR\n");
        assert_eq!(outcome, Outcome::Malformed);
        assert!(providers.dialed().is_empty());
    }

    #[tokio::test]
    async fn the_longest_host_name_fits_the_line_limit() {
        let host = format!("{}.example", "a".repeat(HOST_LIMIT_BYTES - 8));
        assert_eq!(host.len(), HOST_LIMIT_BYTES);
        let line = format!("CONNECT {host}:65535\n");
        assert_eq!(line.len() - 1, CONNECT_LINE_LIMIT_BYTES);
        let (reply, outcome) = refused(line.as_bytes(), &Providers::reachable()).await;
        assert_eq!(reply, b"ERR\n");
        assert_eq!(outcome, Outcome::NotAllowed(format!("{host}:65535")));
    }

    #[tokio::test]
    async fn a_connection_that_closes_before_its_line_ends_is_dropped() {
        let providers = Providers::reachable();
        let (mut node, inbound) = tokio::io::duplex(1024);
        node.write_all(b"CONNECT api.first.exam").await.unwrap();
        node.shutdown().await.unwrap();
        assert_eq!(
            relay(inbound, &allowlist(), &providers).await,
            Outcome::Malformed
        );
        assert!(providers.dialed().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_that_sends_no_line_is_answered_err_after_the_time_limit() {
        let providers = Providers::reachable();
        let (mut node, inbound) = tokio::io::duplex(1024);
        node.write_all(b"CONNECT api.first.example:443")
            .await
            .unwrap();
        let outcome = relay(inbound, &allowlist(), &providers).await;
        assert_eq!(outcome, Outcome::Malformed);
        assert_eq!(read_all(&mut node).await, b"ERR\n");
    }

    #[tokio::test]
    async fn a_provider_that_cannot_be_reached_is_answered_err() {
        let providers = Providers::default();
        let (reply, outcome) = refused(b"CONNECT api.first.example:443\n", &providers).await;
        assert_eq!(reply, b"ERR\n");
        assert_eq!(
            outcome,
            Outcome::Unreachable(
                "api.first.example".to_string(),
                io::Error::from(io::ErrorKind::ConnectionRefused).to_string()
            )
        );
        assert_eq!(providers.dialed(), [("api.first.example".to_string(), 443)]);
    }

    /// A provider stand-in whose connections never open.
    struct Hanging;

    impl Outbound for Hanging {
        fn connect<'a>(&'a self, _host: &'a str, _port: u16) -> BoxFuture<'a, io::Result<Stream>> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_provider_connection_that_does_not_open_in_time_is_answered_err() {
        let (mut node, inbound) = tokio::io::duplex(1024);
        node.write_all(b"CONNECT api.first.example:443\n")
            .await
            .unwrap();
        let started = tokio::time::Instant::now();
        let outcome = relay(inbound, &allowlist(), &Hanging).await;
        assert!(started.elapsed() >= PROVIDER_CONNECT_TIMEOUT);
        assert_eq!(
            outcome,
            Outcome::Unreachable(
                "api.first.example".to_string(),
                "no connection in time".to_string()
            )
        );
        assert_eq!(read_all(&mut node).await, b"ERR\n");
    }

    #[tokio::test]
    async fn the_tcp_outbound_connects_by_name() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"hello").await.unwrap();
        });
        let mut stream = TcpOutbound.connect("localhost", port).await.unwrap();
        let mut buffer = [0u8; 5];
        stream.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"hello");
        accepted.await.unwrap();
    }
}
