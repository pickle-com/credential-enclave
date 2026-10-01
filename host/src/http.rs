//! One HTTP/1.1 exchange over a byte pipe: the client side of the calls the host program makes
//! (the health call and the configuration call to the node, the shutdown call to the backend).

use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Bytes;
use hyper::header::{HeaderName, HeaderValue, CONNECTION, HOST};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;

/// The `Host` header of a call to the node. The node does not read it.
pub const NODE_HOST: &str = "credential-enclave";

/// A request of the host program.
pub type HostRequest = Request<Full<Bytes>>;

/// The response of an exchange.
#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Why an exchange gave no response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExchangeError {
    /// The request cannot be written: its path or a header value is not valid HTTP.
    Invalid,
    /// The connection failed or the peer did not answer with HTTP/1.1.
    Failed,
    /// The response body is longer than the limit.
    TooLarge,
}

/// Builds a request with `Host`, `Connection: close` and the given headers.
pub fn request(
    method: Method,
    host: &str,
    path: &str,
    headers: &[(HeaderName, &str)],
    body: Vec<u8>,
) -> Result<HostRequest, ExchangeError> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, host)
        .header(CONNECTION, "close");
    for (name, value) in headers {
        let value = HeaderValue::from_str(value).map_err(|_| ExchangeError::Invalid)?;
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| ExchangeError::Invalid)
}

/// Ends the task that drives a connection when the exchange ends or is dropped.
struct Driver(JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Sends `request` over `stream` and reads the whole response. The stream is closed afterwards.
/// The caller sets the time limit.
pub async fn exchange<S>(
    stream: S,
    request: HostRequest,
    body_limit: usize,
) -> Result<Reply, ExchangeError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| ExchangeError::Failed)?;
    let _driver = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| ExchangeError::Failed)?;
    let status = response.status().as_u16();
    let body = Limited::new(response.into_body(), body_limit)
        .collect()
        .await
        .map_err(|error| {
            if error.downcast_ref::<LengthLimitError>().is_some() {
                ExchangeError::TooLarge
            } else {
                ExchangeError::Failed
            }
        })?;
    Ok(Reply {
        status,
        body: body.to_bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// Reads a request up to the end of its head and of a body of `body_length` bytes.
    async fn read_request(stream: &mut tokio::io::DuplexStream, body_length: usize) -> String {
        let mut bytes = Vec::new();
        loop {
            let byte = stream.read_u8().await.unwrap();
            bytes.push(byte);
            if bytes.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let mut body = vec![0u8; body_length];
        stream.read_exact(&mut body).await.unwrap();
        bytes.extend_from_slice(&body);
        String::from_utf8(bytes).unwrap()
    }

    #[tokio::test]
    async fn an_exchange_writes_the_request_and_reads_the_response() {
        let (near, mut far) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            let request = read_request(&mut far, 13).await;
            far.write_all(b"HTTP/1.1 201 Created\r\ncontent-length: 5\r\n\r\nhello")
                .await
                .unwrap();
            request
        });
        let request = request(
            Method::POST,
            "backend.example",
            "/api/drain?x=1",
            &[
                (AUTHORIZATION, "Bearer token-value"),
                (CONTENT_TYPE, "application/json"),
            ],
            br#"{"pod":"p-0"}"#.to_vec(),
        )
        .unwrap();
        let reply = exchange(near, request, 1024).await.unwrap();
        assert_eq!(
            reply,
            Reply {
                status: 201,
                body: b"hello".to_vec()
            }
        );

        let written = peer.await.unwrap().to_ascii_lowercase();
        assert!(
            written.starts_with("post /api/drain?x=1 http/1.1\r\n"),
            "{written}"
        );
        for line in [
            "\r\nhost: backend.example\r\n",
            "\r\nconnection: close\r\n",
            "\r\nauthorization: bearer token-value\r\n",
            "\r\ncontent-type: application/json\r\n",
            "\r\ncontent-length: 13\r\n",
        ] {
            assert!(written.contains(line), "{line:?} in {written}");
        }
        assert!(written.ends_with("\r\n\r\n{\"pod\":\"p-0\"}"), "{written}");
    }

    #[tokio::test]
    async fn a_chunked_response_is_read_to_its_end() {
        let (near, mut far) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            read_request(&mut far, 0).await;
            far.write_all(
                b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
            )
            .await
            .unwrap();
            far
        });
        let request = request(Method::GET, NODE_HOST, "/v1/health", &[], Vec::new()).unwrap();
        let reply = exchange(near, request, 1024).await.unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, b"abcde");
    }

    #[tokio::test]
    async fn a_response_body_above_the_limit_is_too_large() {
        let (near, mut far) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            read_request(&mut far, 0).await;
            far.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 9\r\n\r\n123456789")
                .await
                .unwrap();
            far
        });
        let request = request(Method::GET, NODE_HOST, "/v1/health", &[], Vec::new()).unwrap();
        assert_eq!(
            exchange(near, request, 8).await,
            Err(ExchangeError::TooLarge)
        );
    }

    #[tokio::test]
    async fn a_peer_that_does_not_speak_http_fails_the_exchange() {
        let (near, mut far) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            read_request(&mut far, 0).await;
            far.write_all(b"not http\r\n\r\n").await.unwrap();
            far
        });
        let request = request(Method::GET, NODE_HOST, "/v1/health", &[], Vec::new()).unwrap();
        assert_eq!(
            exchange(near, request, 1024).await,
            Err(ExchangeError::Failed)
        );

        // A peer that closes without an answer.
        let (near, far) = tokio::io::duplex(4096);
        drop(far);
        let request = request_for_health();
        assert_eq!(
            exchange(near, request, 1024).await,
            Err(ExchangeError::Failed)
        );
    }

    fn request_for_health() -> HostRequest {
        request(Method::GET, NODE_HOST, "/v1/health", &[], Vec::new()).unwrap()
    }

    #[test]
    fn a_header_value_with_a_line_break_is_not_written() {
        let outcome = request(
            Method::POST,
            "backend.example",
            "/drain",
            &[(AUTHORIZATION, "Bearer a\r\nx-injected: 1")],
            Vec::new(),
        );
        assert_eq!(outcome.err(), Some(ExchangeError::Invalid));
        assert_eq!(
            request(Method::GET, "backend.example", "no slash", &[], Vec::new()).err(),
            Some(ExchangeError::Invalid)
        );
    }
}
