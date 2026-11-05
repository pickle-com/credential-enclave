//! The shutdown collection call (enclave.md section 9).
//!
//! A node keeps its state in memory, so the backend collects what must outlive the node before
//! the enclave ends: it calls `close`, `log/entries` and `close/heads` of the node. The host
//! program starts this by one request when it receives the termination signal:
//!
//! ```text
//! POST {CREDENTIAL_ENCLAVE_DRAIN_URL}
//! Authorization: Bearer {CREDENTIAL_ENCLAVE_DRAIN_TOKEN}
//! Content-Type: application/json
//!
//! {"pod": "{CREDENTIAL_ENCLAVE_POD_NAME}"}
//! ```
//!
//! The backend makes its calls to the node inside that request, through the inbound relay of
//! this host program, and the host program waits for the response for a time that grows with
//! the accounts of the node ([`response_timeout`]): the backend hands the delegations over and
//! collects the final heads page by page, 1,000 accounts a page, so the collection of a node
//! takes a time proportional to its pages. Without one of the three variables the host
//! program ends the enclave without the call.

use std::future::Future;
use std::io;
use std::time::Duration;

use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::Method;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::http;

pub const URL_VARIABLE: &str = "CREDENTIAL_ENCLAVE_DRAIN_URL";
pub const TOKEN_VARIABLE: &str = "CREDENTIAL_ENCLAVE_DRAIN_TOKEN";
pub const POD_VARIABLE: &str = "CREDENTIAL_ENCLAVE_POD_NAME";

/// The accounts of one page of the collection: `peer/export` and `close/heads` of the node
/// page by 1,000 accounts (enclave.md 5.11 and 5.13).
pub const ACCOUNTS_PER_PAGE: u64 = 1_000;
/// The wait for the response of the backend, from the start of the connection, for a node
/// without accounts: the base of [`response_timeout`].
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(100);
/// What the wait grows by for every page of accounts of the node: the pages of the two
/// stages that go page by page (the handover of the delegations, measured at about 2 seconds
/// a page, and the final heads, measured at about 1 second a page), with room.
pub const RESPONSE_TIMEOUT_PER_PAGE: Duration = Duration::from_secs(4);
/// The longest wait. The `terminationGracePeriodSeconds` of the pod covers this wait twice
/// (the subcommand of the pre-stop hook and the signal path) with a margin.
pub const RESPONSE_TIMEOUT_MAX: Duration = Duration::from_secs(600);
/// Longest response body the host program reads.
const REPLY_LIMIT_BYTES: usize = 1024 * 1024;

/// The wait for the response of the backend for a node of `accounts` accounts (the
/// `accounts` of its `health` call, `None` when the call gave none): the base plus
/// [`RESPONSE_TIMEOUT_PER_PAGE`] for every started page of [`ACCOUNTS_PER_PAGE`] accounts, at
/// most [`RESPONSE_TIMEOUT_MAX`].
pub fn response_timeout(accounts: Option<u64>) -> Duration {
    let pages = accounts
        .unwrap_or(0)
        .div_ceil(ACCOUNTS_PER_PAGE)
        .min(u64::from(u32::MAX));
    (RESPONSE_TIMEOUT + RESPONSE_TIMEOUT_PER_PAGE * (pages as u32)).min(RESPONSE_TIMEOUT_MAX)
}

/// The parts of an `http://host[:port]/path` address.
#[derive(Clone, Debug, PartialEq, Eq)]
struct HttpAddress {
    host: String,
    port: u16,
    /// The value of the `Host` header: the host, with the port when the address names one.
    authority: String,
    /// The path with its query.
    path: String,
}

/// Splits a plain `http` address. The route of the backend is an address inside the cluster,
/// so `https` is not an accepted scheme.
fn parse_address(address: &str) -> Result<HttpAddress, &'static str> {
    let rest = address
        .strip_prefix("http://")
        .ok_or("the address does not start with http://")?;
    let (authority, path) = match rest.find('/') {
        Some(index) => rest.split_at(index),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            let canonical = !port.is_empty()
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && !port.starts_with('0');
            let port = port.parse::<u16>().ok().filter(|_| canonical);
            (host, port.ok_or("the port of the address is not a number")?)
        }
        None => (authority, 80),
    };
    let valid_host = !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-');
    if !valid_host {
        return Err("the host of the address is not a DNS name or an IPv4 address");
    }
    let valid_path = path
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'#');
    if !valid_path {
        return Err("the path of the address holds a character outside printable ASCII");
    }
    Ok(HttpAddress {
        host: host.to_string(),
        port,
        authority: authority.to_string(),
        path: path.to_string(),
    })
}

/// The shutdown collection call of this pod.
#[derive(PartialEq, Eq)]
pub struct Drain {
    address: HttpAddress,
    token: String,
    pod: String,
}

/// The token is a secret of the operator: the debug form leaves it out.
impl std::fmt::Debug for Drain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Drain")
            .field("address", &self.address)
            .field("pod", &self.pod)
            .finish_non_exhaustive()
    }
}

impl Drain {
    /// Reads the three variables (`variable` reads one). `Ok(None)` when one of them is not
    /// set: the host program then ends the enclave without the call. `Err` when the address
    /// cannot be used.
    pub fn from_variables(
        variable: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<Drain>, &'static str> {
        let (Some(address), Some(token), Some(pod)) = (
            variable(URL_VARIABLE),
            variable(TOKEN_VARIABLE),
            variable(POD_VARIABLE),
        ) else {
            return Ok(None);
        };
        Ok(Some(Drain {
            address: parse_address(&address)?,
            token,
            pod,
        }))
    }

    /// Sends the request over `stream` and returns the status of the response.
    async fn call_over<S>(&self, stream: S) -> Result<u16, &'static str>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let request = http::request(
            Method::POST,
            &self.address.authority,
            &self.address.path,
            &[
                (AUTHORIZATION, &format!("Bearer {}", self.token)),
                (CONTENT_TYPE, "application/json"),
            ],
            json!({ "pod": self.pod }).to_string().into_bytes(),
        )
        .map_err(|_| "the request cannot be written: the token is not a header value")?;
        match http::exchange(stream, request, REPLY_LIMIT_BYTES).await {
            Ok(reply) => Ok(reply.status),
            Err(http::ExchangeError::TooLarge) => Err("the response is longer than 1 MiB"),
            Err(_) => Err("the connection ended without a response"),
        }
    }

    /// Makes the call over the connection that `connection` opens. The time limit `wait`
    /// covers the opening of the connection and the whole response.
    async fn call_through<S>(
        &self,
        connection: impl Future<Output = io::Result<S>>,
        wait: Duration,
    ) -> Result<u16, &'static str>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let call = async {
            let stream = connection
                .await
                .map_err(|_| "cannot connect to the backend")?;
            self.call_over(stream).await
        };
        tokio::time::timeout(wait, call)
            .await
            .unwrap_or(Err("no response within the wait"))
    }

    /// Calls the backend and waits for its response, for at most [`response_timeout`] of the
    /// accounts of the node in total. Returns the status of the response.
    pub async fn call(&self, accounts: Option<u64>) -> Result<u16, &'static str> {
        let target = (self.address.host.as_str(), self.address.port);
        self.call_through(TcpStream::connect(target), response_timeout(accounts))
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn environment(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let values: HashMap<String, String> = pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        move |name: &str| values.get(name).filter(|value| !value.is_empty()).cloned()
    }

    const FULL: [(&str, &str); 3] = [
        (
            URL_VARIABLE,
            "http://character-api.character.svc.cluster.local/api/credential-enclave/drain",
        ),
        (TOKEN_VARIABLE, "0123abcd"),
        (POD_VARIABLE, "credential-enclave-1"),
    ];

    #[test]
    fn an_http_address_splits_into_host_port_and_path() {
        assert_eq!(
            parse_address(
                "http://character-api.character.svc.cluster.local/api/credential-enclave/drain"
            ),
            Ok(HttpAddress {
                host: "character-api.character.svc.cluster.local".to_string(),
                port: 80,
                authority: "character-api.character.svc.cluster.local".to_string(),
                path: "/api/credential-enclave/drain".to_string(),
            })
        );
        assert_eq!(
            parse_address("http://127.0.0.1:8000/drain?source=host"),
            Ok(HttpAddress {
                host: "127.0.0.1".to_string(),
                port: 8000,
                authority: "127.0.0.1:8000".to_string(),
                path: "/drain?source=host".to_string(),
            })
        );
        assert_eq!(parse_address("http://backend").unwrap().path, "/");

        for address in [
            "",
            "https://backend.example/drain",
            "backend.example/drain",
            "http:///drain",
            "http://user@backend.example/drain",
            "http://backend.example:/drain",
            "http://backend.example:0x50/drain",
            "http://backend.example:080/drain",
            "http://backend.example:65536/drain",
            "http://[::1]:8000/drain",
            "http://backend.example/dr ain",
            "http://backend.example/drain#part",
            "http://backend.example/drain\r\nx-injected: 1",
        ] {
            assert!(parse_address(address).is_err(), "{address:?}");
        }
    }

    #[test]
    fn the_call_exists_only_with_all_three_variables() {
        let drain = Drain::from_variables(&environment(&FULL)).unwrap().unwrap();
        assert_eq!(
            drain.address.host,
            "character-api.character.svc.cluster.local"
        );
        assert_eq!(drain.token, "0123abcd");
        assert_eq!(drain.pod, "credential-enclave-1");

        for missing in [URL_VARIABLE, TOKEN_VARIABLE, POD_VARIABLE] {
            let pairs: Vec<(&str, &str)> = FULL
                .iter()
                .copied()
                .filter(|(name, _)| *name != missing)
                .collect();
            assert_eq!(
                Drain::from_variables(&environment(&pairs)),
                Ok(None),
                "{missing}"
            );
            // An empty value is a missing value.
            let mut emptied = pairs.clone();
            emptied.push((missing, ""));
            assert_eq!(
                Drain::from_variables(&environment(&emptied)),
                Ok(None),
                "{missing}"
            );
        }

        let mut pairs = FULL.to_vec();
        pairs[0] = (URL_VARIABLE, "https://backend.example/drain");
        assert!(Drain::from_variables(&environment(&pairs)).is_err());
    }

    /// Reads one request: its head and a body of the length its head announces.
    async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> String {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(stream.read_u8().await.unwrap());
        }
        let head = String::from_utf8(bytes).unwrap().to_ascii_lowercase();
        let length: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .map(|value| value.parse().unwrap())
            .unwrap_or(0);
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).await.unwrap();
        head + std::str::from_utf8(&body).unwrap()
    }

    #[tokio::test]
    async fn the_call_names_the_pod_and_carries_the_bearer_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let backend = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 17\r\n\r\n{\"complete\":true}")
                .await
                .unwrap();
            request
        });
        let address = format!("http://127.0.0.1:{port}/api/credential-enclave/drain");
        let drain = Drain::from_variables(&environment(&[
            (URL_VARIABLE, &address),
            (TOKEN_VARIABLE, "0123abcd"),
            (POD_VARIABLE, "credential-enclave-1"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(drain.call(Some(3)).await, Ok(200));

        let request = backend.await.unwrap();
        assert!(
            request.starts_with("post /api/credential-enclave/drain http/1.1\r\n"),
            "{request}"
        );
        for line in [
            format!("\r\nhost: 127.0.0.1:{port}\r\n"),
            "\r\nauthorization: bearer 0123abcd\r\n".to_string(),
            "\r\ncontent-type: application/json\r\n".to_string(),
        ] {
            assert!(request.contains(&line), "{line:?} in {request}");
        }
        assert!(
            request.ends_with("\r\n\r\n{\"pod\":\"credential-enclave-1\"}"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn the_status_of_a_failure_response_is_returned() {
        let drain = Drain::from_variables(&environment(&FULL)).unwrap().unwrap();
        let (near, mut far) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            read_request(&mut far).await;
            far.write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n")
                .await
                .unwrap();
            far
        });
        assert_eq!(drain.call_over(near).await, Ok(401));
    }

    #[tokio::test]
    async fn a_backend_that_cannot_be_reached_fails_the_call() {
        // A port nothing listens on.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let address = format!("http://127.0.0.1:{port}/drain");
        let drain = Drain::from_variables(&environment(&[
            (URL_VARIABLE, &address),
            (TOKEN_VARIABLE, "t"),
            (POD_VARIABLE, "p"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(drain.call(None).await, Err("cannot connect to the backend"));

        // A backend that closes without a response.
        let (near, far) = tokio::io::duplex(4096);
        drop(far);
        assert_eq!(
            drain.call_over(near).await,
            Err("the connection ended without a response")
        );
    }

    #[test]
    fn the_wait_grows_with_the_pages_of_the_node_up_to_the_longest_wait() {
        // No accounts, or no health answer: the base.
        assert_eq!(response_timeout(None), Duration::from_secs(100));
        assert_eq!(response_timeout(Some(0)), Duration::from_secs(100));
        // A started page counts as a page.
        assert_eq!(response_timeout(Some(1)), Duration::from_secs(104));
        assert_eq!(response_timeout(Some(1_000)), Duration::from_secs(104));
        assert_eq!(response_timeout(Some(1_001)), Duration::from_secs(108));
        // The node of 2026-11-05 with 46,167 accounts: 47 pages.
        assert_eq!(response_timeout(Some(46_167)), Duration::from_secs(288));
        // 125 pages reach the longest wait, and more pages do not pass it.
        assert_eq!(response_timeout(Some(125_000)), RESPONSE_TIMEOUT_MAX);
        assert_eq!(response_timeout(Some(1_000_000)), RESPONSE_TIMEOUT_MAX);
        assert_eq!(response_timeout(Some(u64::MAX)), RESPONSE_TIMEOUT_MAX);
    }

    #[tokio::test(start_paused = true)]
    async fn the_wait_for_the_response_ends_after_the_wait_of_the_accounts() {
        let drain = Drain::from_variables(&environment(&FULL)).unwrap().unwrap();
        // The backend accepts the connection and never answers. A node of 2,500 accounts
        // (three pages) gets the base and three pages.
        let (near, _far) = tokio::io::duplex(4096);
        let started = tokio::time::Instant::now();
        let wait = response_timeout(Some(2_500));
        assert_eq!(wait, Duration::from_secs(112));
        assert_eq!(
            drain.call_through(async { Ok(near) }, wait).await,
            Err("no response within the wait")
        );
        let waited = started.elapsed();
        assert!(waited >= wait && waited < wait + Duration::from_secs(1));
    }

    #[tokio::test]
    async fn a_token_with_a_line_break_is_never_written() {
        let drain = Drain {
            address: parse_address("http://backend.example/drain").unwrap(),
            token: "a\r\nx-injected: 1".to_string(),
            pod: "p".to_string(),
        };
        let (near, _far) = tokio::io::duplex(64);
        assert_eq!(
            drain.call_over(near).await,
            Err("the request cannot be written: the token is not a header value")
        );
    }

    #[test]
    fn the_debug_form_leaves_the_token_out() {
        let drain = Drain::from_variables(&environment(&FULL)).unwrap().unwrap();
        let text = format!("{drain:?}");
        assert!(text.contains("credential-enclave-1"), "{text}");
        assert!(!text.contains("0123abcd"), "{text}");
    }
}
