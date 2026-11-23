//! The egress relay (enclave.md section 9): the way of the node to the providers.
//!
//! An enclave has no network. The node opens a vsock connection to port 8443 of the parent
//! instance and sends one line, `CONNECT {host}:{port}\n`. The relay answers `OK\n` and moves
//! the bytes between the node and a TCP connection to that host, or it answers `ERR\n` and
//! closes. TLS ends inside the node: the relay sees ciphertext only.
//!
//! What the relay connects to depends on the role of the node of its pod ([`Reach`]).
//!
//! For a node of the delegation role the relay connects to port 443 of the hosts the provider
//! definitions name, to the host of the log store when the environment names one, and the two
//! fixed Naver mail endpoints. This list is a second line: the node itself sends credentials
//! only to the addresses of its definitions, which are part of the measured binary, and log
//! entries only to its log store.
//!
//! For a node of the forward role the relay connects to port 443 of any host, at a public
//! IPv4 address only. Such a node sends the value of a vault secret to the site the record of
//! the secret names, a host the account chose, so no list names it. What the relay keeps the
//! node from is the network of the operator: a name that resolves to a loopback, private,
//! link local or otherwise special address (the addresses of the cluster, of the VPC and of
//! the instance metadata service among them) is refused, and the relay connects to the
//! address it checked.
//!
//! The relay holds at most [`relay::EGRESS_PIPES`] connections of the node at once: a
//! connection above that is answered `ERR\n` without a provider connection. A connection it
//! holds ends within the limits of a pipe ([`relay::pipe`]).

use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpSocket;

use crate::relay::{self, AcceptFailure, BoxFuture, Pipes, Stream, VsockListener};

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

/// What the relay connects to (enclave.md section 9). The role of the node of the pod decides
/// it, and it does not change while the host program runs.
#[derive(Debug, PartialEq, Eq)]
pub enum Reach {
    /// The relay of a node of the delegation role: port 443 of the hosts of the list, and the
    /// two mail endpoints.
    Listed(Allowlist),
    /// The relay of a node of the forward role: port 443 of any host, at a public IPv4
    /// address.
    PublicHosts,
}

/// Which addresses of a host the relay connects to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Addresses {
    /// Every address the name of a listed host resolves to.
    Any,
    /// The public IPv4 addresses the name resolves to ([`is_public`]), and no other one.
    Public,
}

impl Reach {
    /// Whether the relay connects to `host:port`, and to which of its addresses. `None` for
    /// a target the relay refuses before it looks the name up.
    ///
    /// The relay of a node of the forward role takes port 443 of a DNS name of two labels or
    /// more whose last label begins with a letter, the form a node gives the host of a site
    /// (protocol.md section 6): a text in the form of an IP address, in any notation of its
    /// numbers, is no name of a site, and a name of one label is a name of the network of the
    /// pod.
    pub fn of(&self, host: &str, port: u16) -> Option<Addresses> {
        match self {
            Reach::Listed(allowlist) => allowlist.allows(host, port).then_some(Addresses::Any),
            Reach::PublicHosts => {
                let last = host.rsplit('.').next().unwrap_or_default();
                let named = host.contains('.')
                    && last
                        .bytes()
                        .next()
                        .is_some_and(|byte| byte.is_ascii_lowercase());
                (port == PROVIDER_PORT && named).then_some(Addresses::Public)
            }
        }
    }

    /// Why a target is refused, for the line of the log.
    fn refusal(&self) -> &'static str {
        match self {
            Reach::Listed(_) => "not a host of the list",
            Reach::PublicHosts => "not port 443 of a host at a public address",
        }
    }
}

/// True for an IPv4 address of the public internet: an address outside the ranges the IANA
/// special-purpose registry reserves.
fn is_public_v4(address: Ipv4Addr) -> bool {
    let [first, second, third, _] = address.octets();
    let special = match first {
        // "This network", private use, loopback.
        0 | 10 | 127 => true,
        // Shared address space of carrier-grade NAT, 100.64.0.0/10.
        100 => (64..=127).contains(&second),
        // Link local, 169.254.0.0/16: the instance metadata service is here.
        169 => second == 254,
        // Private use, 172.16.0.0/12.
        172 => (16..=31).contains(&second),
        // 192.0.0.0/24 protocol assignments, 192.0.2.0/24 documentation, 192.88.99.0/24 the
        // former 6to4 relays, 192.168.0.0/16 private use.
        192 => matches!((second, third), (0, 0) | (0, 2) | (88, 99)) || second == 168,
        // 198.18.0.0/15 benchmarking, 198.51.100.0/24 documentation.
        198 => matches!(second, 18 | 19) || (second, third) == (51, 100),
        // 203.0.113.0/24 documentation.
        203 => (second, third) == (0, 113),
        // Multicast, reserved, broadcast.
        224..=255 => true,
        _ => false,
    };
    !special
}

/// True for an address the relay of a node of the forward role connects to: a public IPv4
/// address.
///
/// The relay connects to no IPv6 address. A global IPv6 address may be an address of the
/// network of the operator itself (the IPv6 range of a VPC is a range of global addresses),
/// and nothing in an address tells the two apart.
pub fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(_) => false,
    }
}

/// The addresses of `resolved` the relay connects to, in their order.
fn chosen(resolved: impl Iterator<Item = SocketAddr>, addresses: Addresses) -> Vec<SocketAddr> {
    resolved
        .filter(|address| addresses == Addresses::Any || is_public(address.ip()))
        .collect()
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

/// Why no connection to a host was opened.
#[derive(Debug)]
pub enum ConnectFailure {
    /// The name resolved, and none of its addresses is one the relay connects to: every one
    /// of them is outside the public internet.
    NotPublic,
    /// The name lookup or the connection failed.
    Io(io::Error),
}

impl From<io::Error> for ConnectFailure {
    fn from(error: io::Error) -> ConnectFailure {
        ConnectFailure::Io(error)
    }
}

/// Opens connections to providers and to sites.
pub trait Outbound: Send + Sync + 'static {
    /// Opens a byte pipe to `host:port`, at one of the addresses `addresses` admits.
    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        addresses: Addresses,
    ) -> BoxFuture<'a, Result<Stream, ConnectFailure>>;
}

/// TCP connections with the name lookup of the parent instance.
pub struct TcpOutbound;

impl Outbound for TcpOutbound {
    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        addresses: Addresses,
    ) -> BoxFuture<'a, Result<Stream, ConnectFailure>> {
        Box::pin(async move {
            // The name of a site is looked up as the name it is, from the root: the search
            // list of the pod would try it as a name inside the cluster first.
            let resolved: Vec<SocketAddr> = match addresses {
                Addresses::Any => tokio::net::lookup_host((host, port)).await?.collect(),
                Addresses::Public => tokio::net::lookup_host((format!("{host}."), port))
                    .await?
                    .collect(),
            };
            // The relay connects to an address it checked: the name is not looked up again.
            let admitted = chosen(resolved.iter().copied(), addresses);
            if admitted.is_empty() && !resolved.is_empty() {
                return Err(ConnectFailure::NotPublic);
            }
            let mut last_error = io::Error::from(io::ErrorKind::NotFound);
            for address in admitted {
                let socket = if address.is_ipv4() {
                    TcpSocket::new_v4()
                } else {
                    TcpSocket::new_v6()
                };
                let connected = match socket {
                    Ok(socket) => socket.connect(address).await,
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
            Err(ConnectFailure::Io(last_error))
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
    /// The relay does not connect to the target: it is not port 443 of a host of the list
    /// or, for the relay of a node of the forward role, not port 443 of a host at a public
    /// address.
    NotAllowed(String),
    /// The provider could not be reached: the host and the failure of the name lookup or of the
    /// connection.
    Unreachable(String, String),
    /// The relay held [`relay::EGRESS_PIPES`] connections of the node: the target is on the
    /// list and was not dialed.
    OverLimit,
}

impl Outcome {
    /// The values of the `outcome` label of `credential_enclave_host_egress_relays_total`, in
    /// the order of the variants.
    pub const LABELS: [&'static str; 5] = [
        "relayed",
        "malformed",
        "not_allowed",
        "unreachable",
        "over_limit",
    ];

    /// The position of the outcome in [`Outcome::LABELS`].
    fn index(&self) -> usize {
        match self {
            Outcome::Relayed => 0,
            Outcome::Malformed => 1,
            Outcome::NotAllowed(_) => 2,
            Outcome::Unreachable(..) => 3,
            Outcome::OverLimit => 4,
        }
    }
}

/// The counts of the egress relay since the host program started, and the connections it
/// holds. The relay writes them and the status surface reads them for `/metrics` (enclave.md
/// section 9).
#[derive(Debug)]
pub struct EgressCounters {
    /// Failed accepts by class, in the order of [`AcceptFailure::ALL`].
    accept_errors: [AtomicU64; 3],
    /// Served connections of the node by outcome, in the order of [`Outcome::LABELS`].
    relays: [AtomicU64; 5],
    /// The connections of the node the relay holds, at most [`relay::EGRESS_PIPES`]: those it
    /// opens a provider connection for and those whose bytes it moves.
    pipes: Arc<Pipes>,
}

impl Default for EgressCounters {
    fn default() -> EgressCounters {
        EgressCounters::holding(relay::EGRESS_PIPES)
    }
}

impl EgressCounters {
    /// The counts of a relay that holds at most `limit` connections of the node at once.
    pub fn holding(limit: usize) -> EgressCounters {
        EgressCounters {
            accept_errors: Default::default(),
            relays: Default::default(),
            pipes: Pipes::new(limit),
        }
    }

    fn count_accept_error(&self, failure: AcceptFailure) {
        // One counter per class, in the order of the classes.
        if let Some(count) = self.accept_errors.get(failure as usize) {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn count_relay(&self, outcome: &Outcome) {
        // One counter per outcome, in the order of the labels.
        if let Some(count) = self.relays.get(outcome.index()) {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The failed accepts by class: the value of the `cause` label and the count.
    pub fn accept_errors(&self) -> [(&'static str, u64); 3] {
        let mut classes = AcceptFailure::ALL.iter().zip(&self.accept_errors);
        std::array::from_fn(|_| {
            classes.next().map_or(("", 0), |(class, count)| {
                (class.label(), count.load(Ordering::Relaxed))
            })
        })
    }

    /// The served connections by outcome: the value of the `outcome` label and the count.
    pub fn relays(&self) -> [(&'static str, u64); 5] {
        let mut outcomes = Outcome::LABELS.iter().zip(&self.relays);
        std::array::from_fn(|_| {
            outcomes.next().map_or(("", 0), |(label, count)| {
                (*label, count.load(Ordering::Relaxed))
            })
        })
    }

    /// The connections of the node the relay holds, and how its pipes ended.
    pub fn pipes(&self) -> &Pipes {
        &self.pipes
    }
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

/// Serves one connection of the node: reads the `CONNECT` line, checks the target against
/// what the relay connects to, takes a place among the connections the relay holds, opens the
/// connection, answers and relays. The outcome is counted, and the connection holds its place
/// from the check of its target until its pipe has ended.
pub async fn relay<S>(
    inbound: S,
    reach: &Reach,
    outbound: &dyn Outbound,
    counters: &EgressCounters,
) -> Outcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let outcome = serve_connection(inbound, reach, outbound, counters).await;
    counters.count_relay(&outcome);
    outcome
}

async fn serve_connection<S>(
    mut inbound: S,
    reach: &Reach,
    outbound: &dyn Outbound,
    counters: &EgressCounters,
) -> Outcome
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
    let Some(addresses) = reach.of(host, port) else {
        return refuse(inbound, Outcome::NotAllowed(format!("{host}:{port}"))).await;
    };
    let Some(place) = counters.pipes.admit() else {
        return refuse(inbound, Outcome::OverLimit).await;
    };
    let provider = tokio::time::timeout(
        PROVIDER_CONNECT_TIMEOUT,
        outbound.connect(host, port, addresses),
    )
    .await;
    let provider = match provider {
        Ok(Ok(provider)) => provider,
        Ok(Err(ConnectFailure::NotPublic)) => {
            return refuse(inbound, Outcome::NotAllowed(format!("{host}:{port}"))).await;
        }
        Ok(Err(ConnectFailure::Io(error))) => {
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
    // What the node still sends to a provider that closed stays unread: the node learns of
    // the close from the end of the connection, and nobody waits for a reply to those bytes.
    relay::pipe(inbound, provider, &place, relay::Relay::Egress).await;
    Outcome::Relayed
}

/// The egress relay: serves every connection of `listener`. A connection refused for its
/// line, its target or its provider leaves one line in the output of the host program; a
/// connection refused because the relay holds its limit is counted only. A failed accept is
/// counted by its class, and the next accept follows at once or after a pause as the class
/// asks (`relay::AcceptFailure`).
pub async fn serve(
    listener: VsockListener,
    reach: Arc<Reach>,
    outbound: Arc<dyn Outbound>,
    counters: Arc<EgressCounters>,
) {
    loop {
        let inbound = match listener.accept().await {
            Ok(inbound) => inbound,
            Err(error) => {
                let failure = AcceptFailure::of(&error);
                counters.count_accept_error(failure);
                relay::pause_after_failed_accept(failure).await;
                continue;
            }
        };
        let reach = reach.clone();
        let outbound = outbound.clone();
        let counters = counters.clone();
        tokio::spawn(async move {
            match relay(inbound, &reach, outbound.as_ref(), &counters).await {
                Outcome::Relayed | Outcome::OverLimit => {}
                Outcome::Malformed => {
                    crate::log("egress: refused a connection without a valid CONNECT line");
                }
                Outcome::NotAllowed(target) => {
                    crate::log(&format!("egress: refused {target}: {}", reach.refusal()));
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

    /// The reach of the relay of a node of the delegation role.
    fn listed() -> Reach {
        Reach::Listed(allowlist())
    }

    /// A provider stand-in: every connection is one end of an in-memory pipe, and the test
    /// holds the other end.
    #[derive(Default)]
    struct Providers {
        reachable: bool,
        /// The hosts whose names resolve to addresses outside the public internet.
        private: Vec<&'static str>,
        dialed: Mutex<Vec<(String, u16)>>,
        /// The addresses the relay asked for, per connection.
        asked: Mutex<Vec<Addresses>>,
        far_ends: Mutex<Vec<DuplexStream>>,
    }

    impl Providers {
        fn reachable() -> Providers {
            Providers {
                reachable: true,
                ..Providers::default()
            }
        }

        /// Reachable hosts, of which `private` resolve to addresses of a private network.
        fn with_private(private: &[&'static str]) -> Providers {
            Providers {
                reachable: true,
                private: private.to_vec(),
                ..Providers::default()
            }
        }

        fn asked(&self) -> Vec<Addresses> {
            self.asked.lock().unwrap().clone()
        }

        fn dialed(&self) -> Vec<(String, u16)> {
            self.dialed.lock().unwrap().clone()
        }

        fn take_far_end(&self) -> DuplexStream {
            self.far_ends.lock().unwrap().remove(0)
        }
    }

    impl Outbound for Providers {
        fn connect<'a>(
            &'a self,
            host: &'a str,
            port: u16,
            addresses: Addresses,
        ) -> BoxFuture<'a, Result<Stream, ConnectFailure>> {
            Box::pin(async move {
                self.dialed.lock().unwrap().push((host.to_string(), port));
                self.asked.lock().unwrap().push(addresses);
                if addresses == Addresses::Public && self.private.contains(&host) {
                    return Err(ConnectFailure::NotPublic);
                }
                if !self.reachable {
                    return Err(io::Error::from(io::ErrorKind::ConnectionRefused).into());
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
        let outcome = relay(inbound, &listed(), providers, &EgressCounters::default()).await;
        (read_all(&mut node).await, outcome)
    }

    /// The same for the relay of a node of the forward role.
    async fn refused_in_the_open(first_bytes: &[u8], providers: &Providers) -> (Vec<u8>, Outcome) {
        let (mut node, inbound) = tokio::io::duplex(1024);
        node.write_all(first_bytes).await.unwrap();
        let counters = EgressCounters::default();
        let outcome = relay(inbound, &Reach::PublicHosts, providers, &counters).await;
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
        let counters = Arc::new(EgressCounters::default());
        let (mut node, inbound) = tokio::io::duplex(1024);
        let relayed = {
            let (providers, counters) = (providers.clone(), counters.clone());
            tokio::spawn(
                async move { relay(inbound, &listed(), providers.as_ref(), &counters).await },
            )
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
        // The bytes move: the connection holds one place of the relay, and the outcome is not
        // counted yet.
        assert_eq!(counters.pipes().held(), 1);
        assert_eq!(counters.relays().map(|(_, count)| count), [0, 0, 0, 0, 0]);

        provider.write_all(b"server hello").await.unwrap();
        node.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"server hello");

        // The provider ends the exchange, then the node closes: the relay is done.
        provider.shutdown().await.unwrap();
        assert_eq!(node.read(&mut buffer).await.unwrap(), 0);
        node.shutdown().await.unwrap();
        assert_eq!(read_all(&mut provider).await, b"");
        assert_eq!(relayed.await.unwrap(), Outcome::Relayed);
        assert_eq!(counters.pipes().held(), 0);
        assert_eq!(
            counters.relays(),
            [
                ("relayed", 1),
                ("malformed", 0),
                ("not_allowed", 0),
                ("unreachable", 0),
                ("over_limit", 0)
            ]
        );
        assert_eq!(
            counters.pipes().ended(),
            [
                ("closed", 1),
                ("failed", 0),
                ("idle", 0),
                ("half_closed", 0)
            ]
        );
    }

    #[tokio::test]
    async fn a_connection_above_the_limit_of_the_relay_is_answered_err_and_never_dialed() {
        let providers = Arc::new(Providers::reachable());
        let counters = Arc::new(EgressCounters::holding(1));
        let (mut node, inbound) = tokio::io::duplex(1024);
        let relayed = {
            let (providers, counters) = (providers.clone(), counters.clone());
            tokio::spawn(
                async move { relay(inbound, &listed(), providers.as_ref(), &counters).await },
            )
        };
        node.write_all(b"CONNECT api.first.example:443\n")
            .await
            .unwrap();
        let mut reply = [0u8; 3];
        node.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"OK\n");
        assert_eq!(counters.pipes().held(), 1);

        // The relay holds its one connection: the next one is refused with the answer of a
        // target the relay does not connect to, and no provider is dialed for it.
        let (mut second, inbound) = tokio::io::duplex(1024);
        second
            .write_all(b"CONNECT api.second.example:443\n")
            .await
            .unwrap();
        let outcome = relay(inbound, &listed(), providers.as_ref(), &counters).await;
        assert_eq!(outcome, Outcome::OverLimit);
        assert_eq!(read_all(&mut second).await, b"ERR\n");
        assert_eq!(providers.dialed(), [("api.first.example".to_string(), 443)]);
        assert_eq!(counters.pipes().held(), 1);

        // The first connection ends: its place is free.
        let mut provider = providers.take_far_end();
        provider.shutdown().await.unwrap();
        node.shutdown().await.unwrap();
        assert_eq!(relayed.await.unwrap(), Outcome::Relayed);
        assert_eq!(counters.pipes().held(), 0);
        let (mut third, inbound) = tokio::io::duplex(1024);
        third
            .write_all(b"CONNECT api.second.example:443\n")
            .await
            .unwrap();
        let relayed = {
            let (providers, counters) = (providers.clone(), counters.clone());
            tokio::spawn(
                async move { relay(inbound, &listed(), providers.as_ref(), &counters).await },
            )
        };
        third.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"OK\n");
        drop((third, providers.take_far_end()));
        assert_eq!(relayed.await.unwrap(), Outcome::Relayed);
        assert_eq!(
            counters.relays(),
            [
                ("relayed", 2),
                ("malformed", 0),
                ("not_allowed", 0),
                ("unreachable", 0),
                ("over_limit", 1)
            ]
        );
    }

    #[tokio::test]
    async fn the_counters_count_every_outcome_once() {
        let counters = EgressCounters::default();
        let reachable = Providers::reachable();
        let unreachable = Providers::default();
        for (line, providers) in [
            (&b"GET / HTTP/1.1\r\n\r\n"[..], &reachable),
            (b"CONNECT evil.example:443\n", &reachable),
            (b"CONNECT api.first.example:80\n", &reachable),
            (b"CONNECT api.first.example:443\n", &unreachable),
            (b"CONNECT api.second.example:443\n", &unreachable),
            (b"CONNECT api.second.example:443\n", &unreachable),
        ] {
            let (mut node, inbound) = tokio::io::duplex(1024);
            node.write_all(line).await.unwrap();
            relay(inbound, &listed(), providers, &counters).await;
        }
        assert_eq!(
            counters.relays(),
            [
                ("relayed", 0),
                ("malformed", 1),
                ("not_allowed", 2),
                ("unreachable", 3),
                ("over_limit", 0)
            ]
        );
        assert_eq!(counters.pipes().held(), 0);
        assert_eq!(
            counters.accept_errors(),
            [("aborted", 0), ("resources", 0), ("other", 0)]
        );
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
            relay(inbound, &listed(), &providers, &EgressCounters::default()).await,
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
        let outcome = relay(inbound, &listed(), &providers, &EgressCounters::default()).await;
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
        fn connect<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
            _addresses: Addresses,
        ) -> BoxFuture<'a, Result<Stream, ConnectFailure>> {
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
        let outcome = relay(inbound, &listed(), &Hanging, &EgressCounters::default()).await;
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

    #[test]
    fn the_relay_of_a_forward_node_takes_port_443_of_a_named_host() {
        let reach = Reach::PublicHosts;
        for host in [
            "api.openai.com",
            "example.com",
            "a-b.c9.example",
            // A name is judged by the addresses it resolves to, when the relay looks it up.
            "metadata.google.internal",
            "kubernetes.default.svc.cluster.local",
        ] {
            assert_eq!(reach.of(host, 443), Some(Addresses::Public), "{host}");
        }
        for (host, port) in [
            // Port 443 only: no other port of a site, and no mail endpoint.
            ("example.com", 80),
            ("example.com", 8443),
            ("example.com", 0),
            ("imap.naver.com", 993),
            ("smtp.naver.com", 465),
            // No name of one label, and no IP address.
            ("localhost", 443),
            ("kubernetes", 443),
            ("169.254.169.254", 443),
            ("10.0.0.1", 443),
            ("127.0.0.1", 443),
            ("1.1.1.1", 443),
            ("example.123", 443),
        ] {
            assert_eq!(reach.of(host, port), None, "{host}:{port}");
        }
        // The relay of a node of the delegation role takes the hosts of its list, at every
        // address their names resolve to, and the two mail endpoints.
        assert_eq!(listed().of("api.first.example", 443), Some(Addresses::Any));
        assert_eq!(listed().of("imap.naver.com", 993), Some(Addresses::Any));
        assert_eq!(listed().of("example.com", 443), None);
    }

    #[test]
    fn a_public_address_is_an_ipv4_address_outside_the_special_ranges() {
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "52.94.236.248",
            "100.63.255.255",
            "100.128.0.0",
            "169.253.255.255",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.1",
            "192.167.255.255",
            "198.17.255.255",
            "198.20.0.0",
            "203.0.112.255",
            "223.255.255.255",
        ] {
            assert!(is_public(address.parse().unwrap()), "{address}");
        }
        for address in [
            // Loopback and "this network".
            "127.0.0.1",
            "127.255.255.254",
            "0.0.0.0",
            "0.1.2.3",
            // Private use: the addresses of a cluster and of a VPC.
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.20.0.10",
            "172.31.255.255",
            "192.168.0.1",
            // The shared address space of carrier-grade NAT.
            "100.64.0.1",
            "100.127.255.255",
            // Link local: the instance metadata service and the resolver of a VPC.
            "169.254.169.254",
            "169.254.169.253",
            "169.254.170.2",
            // Protocol assignments, documentation, benchmarking, the former 6to4 relays.
            "192.0.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "198.19.255.255",
            "192.88.99.1",
            // Multicast, reserved, broadcast.
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            // No IPv6 address: a global one may be an address of the network of the operator,
            // and the others are no addresses of a site.
            "2606:4700:4700::1111",
            "2a00:1450:4001:81b::200e",
            "::1",
            "::",
            "fe80::1",
            "fd00:ec2::254",
            "::ffff:8.8.8.8",
            "::ffff:10.0.0.1",
            "64:ff9b::808:808",
            "ff02::1",
        ] {
            assert!(!is_public(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn of_the_addresses_of_a_name_the_public_ones_are_chosen() {
        let resolved: Vec<SocketAddr> = [
            "10.0.0.5:443",
            "93.184.216.34:443",
            "[fd00:ec2::254]:443",
            "[2606:2800:220:1::1]:443",
            "169.254.169.254:443",
            "151.101.1.69:443",
        ]
        .iter()
        .map(|address| address.parse().unwrap())
        .collect();
        let public: Vec<String> = chosen(resolved.iter().copied(), Addresses::Public)
            .iter()
            .map(SocketAddr::to_string)
            .collect();
        assert_eq!(public, ["93.184.216.34:443", "151.101.1.69:443"]);
        assert_eq!(chosen(resolved.iter().copied(), Addresses::Any), resolved);
        // A name that resolves to no public address has no address the relay connects to.
        let private = resolved.iter().copied().filter(|a| !is_public(a.ip()));
        assert!(chosen(private, Addresses::Public).is_empty());
    }

    #[tokio::test]
    async fn the_relay_of_a_forward_node_connects_to_a_site_at_a_public_address() {
        let providers = Arc::new(Providers::with_private(&["intranet.example"]));
        let counters = Arc::new(EgressCounters::default());
        let (mut node, inbound) = tokio::io::duplex(1024);
        let relayed = {
            let (providers, counters) = (providers.clone(), counters.clone());
            tokio::spawn(async move {
                relay(inbound, &Reach::PublicHosts, providers.as_ref(), &counters).await
            })
        };
        // A host no list names: the site of a vault secret.
        node.write_all(b"CONNECT api.site.example:443\nclient hello")
            .await
            .unwrap();
        let mut reply = [0u8; 3];
        node.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"OK\n");
        assert_eq!(providers.dialed(), [("api.site.example".to_string(), 443)]);
        // The relay asked for a public address of the name.
        assert_eq!(providers.asked(), [Addresses::Public]);
        let mut site = providers.take_far_end();
        let mut buffer = [0u8; 12];
        site.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"client hello");
        site.shutdown().await.unwrap();
        node.shutdown().await.unwrap();
        assert_eq!(relayed.await.unwrap(), Outcome::Relayed);
    }

    #[tokio::test]
    async fn the_relay_of_a_forward_node_refuses_what_is_not_a_site_at_a_public_address() {
        let providers = Providers::with_private(&["intranet.example", "metadata.internal"]);
        // A name that resolves to addresses of a private network: the relay looked it up and
        // connected to none of them.
        for host in ["intranet.example", "metadata.internal"] {
            let line = format!("CONNECT {host}:443\n");
            let (reply, outcome) = refused_in_the_open(line.as_bytes(), &providers).await;
            assert_eq!(reply, b"ERR\n", "{host}");
            assert_eq!(outcome, Outcome::NotAllowed(format!("{host}:443")));
        }
        assert_eq!(providers.dialed().len(), 2);
        assert!(providers.far_ends.lock().unwrap().is_empty());
        // A target the relay refuses before it looks a name up: another port, a mail
        // endpoint, a name of one label, an IP address in any notation of its numbers, and a
        // name whose last label does not begin with a letter.
        for target in [
            "api.site.example:80",
            "api.site.example:8443",
            "imap.naver.com:993",
            "localhost:443",
            "169.254.169.254:443",
            "10.0.0.1:443",
            "1.1.1.1:443",
            "127.1:443",
            "0x7f.0x0.0x0.0x1:443",
            "0177.0.0.01:443",
            "api.site.3xample:443",
            "api.site.-example:443",
        ] {
            let line = format!("CONNECT {target}\n");
            let (reply, outcome) = refused_in_the_open(line.as_bytes(), &providers).await;
            assert_eq!(reply, b"ERR\n", "{target}");
            assert_eq!(outcome, Outcome::NotAllowed(target.to_string()), "{target}");
        }
        assert_eq!(providers.dialed().len(), 2);
        // The relay of a node of the delegation role keeps its list: a site is no host of it.
        let (reply, outcome) = refused(b"CONNECT api.site.example:443\n", &providers).await;
        assert_eq!(reply, b"ERR\n");
        assert_eq!(
            outcome,
            Outcome::NotAllowed("api.site.example:443".to_string())
        );
        assert_eq!(providers.dialed().len(), 2);
    }

    #[tokio::test]
    async fn the_tcp_outbound_connects_by_name() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"hello").await.unwrap();
        });
        let mut stream = TcpOutbound
            .connect("localhost", port, Addresses::Any)
            .await
            .unwrap();
        let mut buffer = [0u8; 5];
        stream.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"hello");
        accepted.await.unwrap();
    }
}
