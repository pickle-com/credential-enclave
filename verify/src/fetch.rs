//! The one request of the tool: `GET {url}/api/credential-enclave/attestation?nonce={nonce}`.
//!
//! The request carries no credential, follows no redirect and reads no proxy setting: the
//! address that is asked is the address of `--url`. What the response says is not trusted
//! because of the connection it came over. Each document in it is verified on its own
//! (`evaluate`), and the nonce shows that it was made for this request.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use credential_enclave_protocol::encoding::b64u;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// The route that returns the attestation documents of the running nodes.
pub const ROUTE: &str = "/api/credential-enclave/attestation";
/// The length of the nonce of a request, in bytes.
pub const NONCE_BYTES: usize = 32;

/// How long the connection to the service may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the request may take in all.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// The largest response the tool reads. An entry with a Nitro document is about 7000 bytes.
const RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

/// A fresh nonce: 32 bytes from the random source of the operating system.
pub fn fresh_nonce() -> Result<[u8; NONCE_BYTES], String> {
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::getrandom(&mut nonce)
        .map_err(|_| "the random source of the operating system failed".to_string())?;
    Ok(nonce)
}

/// The address of the attestation route of the service at `url` (without a trailing slash).
pub fn route_address(url: &str) -> String {
    format!("{url}{ROUTE}")
}

/// The address of the request: the route with the nonce in base64url without padding.
pub fn request_address(url: &str, nonce: &[u8]) -> String {
    format!("{}?nonce={}", route_address(url), b64u(nonce))
}

/// Sends `GET {address}` and returns the body of the response when its status is 200.
pub fn get(address: &str) -> Result<Vec<u8>, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirects(0)
        .try_proxy_from_env(false)
        .user_agent(concat!(
            "credential-enclave-verify/",
            env!("CARGO_PKG_VERSION")
        ))
        .tls_connector(Arc::new(Tls::new()?))
        .build();
    let response = match agent.get(address).set("accept", "application/json").call() {
        Ok(response) => response,
        Err(ureq::Error::Status(status, _)) => return Err(status_error(status)),
        Err(ureq::Error::Transport(transport)) => {
            return Err(format!("the request failed: {transport}"))
        }
    };
    // A redirect that is not followed arrives here as a response.
    if response.status() != 200 {
        return Err(status_error(response.status()));
    }
    let mut body = Vec::new();
    response
        .into_reader()
        .take(RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|error| format!("the response could not be read: {error}"))?;
    if body.len() as u64 > RESPONSE_BYTES {
        return Err(format!(
            "the response is longer than {RESPONSE_BYTES} bytes"
        ));
    }
    Ok(body)
}

fn status_error(status: u16) -> String {
    format!("the service answered with the HTTP status {status}")
}

/// The TLS of an `https` address: rustls with the `ring` provider, TLS 1.2 and TLS 1.3, and
/// the certificate authorities of the `webpki-roots` crate as the trust anchors. The node
/// program builds the TLS of its connections to the providers from the same parts.
struct Tls(Arc<ClientConfig>);

impl Tls {
    fn new() -> Result<Tls, String> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| format!("the TLS configuration could not be built: {error}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Tls(Arc::new(config)))
    }
}

impl ureq::TlsConnector for Tls {
    fn connect(
        &self,
        dns_name: &str,
        mut io: Box<dyn ureq::ReadWrite>,
    ) -> Result<Box<dyn ureq::ReadWrite>, ureq::Error> {
        // An IPv6 address arrives in brackets, which the name of a server does not have.
        let name = dns_name
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(dns_name);
        let name = ServerName::try_from(name.to_string()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the host of the address is not the name of a server",
            )
        })?;
        let mut connection =
            ClientConnection::new(self.0.clone(), name).map_err(io::Error::other)?;
        // The handshake runs here, so a certificate that does not verify fails the request
        // before anything is sent.
        connection.complete_io(&mut io)?;
        Ok(Box::new(TlsStream(StreamOwned::new(connection, io))))
    }
}

/// A TLS connection in the form the HTTP client reads and writes.
struct TlsStream(StreamOwned<ClientConnection, Box<dyn ureq::ReadWrite>>);

impl Read for TlsStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.read(buffer)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl fmt::Debug for TlsStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TlsStream")
    }
}

impl ureq::ReadWrite for TlsStream {
    fn socket(&self) -> Option<&TcpStream> {
        self.0.get_ref().socket()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_of_the_request() {
        assert_eq!(
            route_address("https://api.example.com"),
            "https://api.example.com/api/credential-enclave/attestation"
        );
        // 32 bytes are 43 characters of base64url without padding, and the alphabet needs no
        // escaping in a query.
        assert_eq!(
            request_address("https://api.example.com", &[0xfb; 32]),
            "https://api.example.com/api/credential-enclave/attestation?nonce=-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s"
        );
    }

    #[test]
    fn a_nonce_is_32_bytes_and_not_the_one_before() {
        let first = fresh_nonce().unwrap();
        let second = fresh_nonce().unwrap();
        assert_eq!(first.len(), 32);
        assert_ne!(first, second);
    }

    #[test]
    fn the_tls_configuration_is_built() {
        assert!(Tls::new().is_ok());
    }
}
