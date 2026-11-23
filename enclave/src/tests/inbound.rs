//! The connections from the backend (enclave.md section 8): a node waits for the peer of a
//! connection for `inbound_idle` and no longer, whatever the peer and the kernel do, and a
//! connection holds a bounded read buffer.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::{provider_with_log_store, quiet_provider};
use crate::api;
use crate::frame;
use crate::inbound::{BLOCKED_WRITE_RETRY, READ_BUFFER_BYTES};
use crate::platform::{Attempted, Platform};
use crate::state::INBOUND_IDLE;
use crate::testing::{App, Harness, Reply};

const HEALTH: &[u8] = b"GET /v1/health HTTP/1.1\r\nHost: node\r\n\r\n";

/// Serves the calls of the node of `harness` on `stream`, as the node serves an accepted
/// connection. The task ends when the node ended the connection.
fn served<S>(harness: &Harness, stream: S) -> JoinHandle<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(api::serve_connection(
        stream,
        api::router(harness.node.clone()),
        harness.node.limits.inbound_idle,
    ))
}

/// Lets the tasks that are ready run, without moving the clock.
async fn settle() {
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
}

/// Reads one response with a `content-length`: its status and its body.
async fn response<S: AsyncRead + Unpin>(stream: &mut S) -> (u16, Vec<u8>) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
    let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
    let status = head[9..12].parse().unwrap();
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .map_or(0, |length| length.parse().unwrap());
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.unwrap();
    (status, body)
}

#[tokio::test(start_paused = true)]
async fn a_connection_whose_peer_takes_no_byte_of_a_response_ends_at_the_limit() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    // The connection of the peer has room for 256 bytes, and the peer reads nothing.
    let (near, mut far) = tokio::io::duplex(256);
    let served = served(&harness, near);
    far.write_all(HEALTH).await.unwrap();
    let asked = Instant::now();

    // The response of `health` is longer than 256 bytes: the node waits for the peer to take
    // the rest, for the limit, and then ends the connection.
    served.await.unwrap();
    assert_eq!(asked.elapsed(), INBOUND_IDLE);
    let mut received = Vec::new();
    far.read_to_end(&mut received).await.unwrap();
    assert_eq!(received.len(), 256);
    assert!(received.starts_with(b"HTTP/1.1 200 OK\r\n"));
}

#[tokio::test(start_paused = true)]
async fn a_peer_that_takes_bytes_of_a_response_before_the_limit_keeps_its_connection() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let (near, mut far) = tokio::io::duplex(256);
    let served = served(&harness, near);
    far.write_all(HEALTH).await.unwrap();
    let asked = Instant::now();

    // The peer takes what its connection holds, at most 256 bytes, a second before the
    // limit, again and again: every byte it takes starts the wait of the node anew, and the
    // whole response arrives. The last part is in the connection when the node has written
    // it, so the peer has it a second before the node ends the idle connection.
    let mut received = Vec::new();
    let length = loop {
        tokio::time::sleep(INBOUND_IDLE - Duration::from_secs(1)).await;
        let mut part = [0u8; 256];
        let count = far.read(&mut part).await.unwrap();
        received.extend_from_slice(&part[..count]);
        if let Some(end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&received[..end]).to_ascii_lowercase();
            let length: usize = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .unwrap()
                .parse()
                .unwrap();
            if received.len() >= end + 4 + length {
                break length;
            }
        }
    };
    assert!(asked.elapsed() > 2 * INBOUND_IDLE);
    let body = &received[received.len() - length..];
    let health: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(health["node"], harness.node.node.as_str());
    assert!(!served.is_finished());

    // The connection is idle since the node wrote the last byte of the response, and ends
    // after the idle time as every idle one does.
    let answered = Instant::now();
    served.await.unwrap();
    assert!(answered.elapsed() <= INBOUND_IDLE);
}

/// A stream stand-in for a vsock connection in the kernel of an enclave, whose peer takes
/// some bytes and then none: a write that waits for the stream is never woken, also when the
/// peer closes. A read gives the bytes the peer sent and then waits without an end. The
/// stream has the write that returns at once (`io::Write`): it takes bytes while the peer has
/// room, answers `WouldBlock` when it has none, and fails with a broken pipe once the peer is
/// gone.
#[derive(Clone, Default)]
struct Quiet(Arc<Mutex<QuietPeer>>);

#[derive(Default)]
struct QuietPeer {
    /// Bytes the peer sent and the stream has not read yet.
    sent: Vec<u8>,
    /// Bytes the peer still has room for.
    room: usize,
    /// The peer is gone: an attempted write fails.
    gone: bool,
    /// Bytes the peer took.
    taken: Vec<u8>,
    /// Writes that were attempted.
    attempts: u64,
    /// The task that waits for a read.
    reader: Option<Waker>,
}

impl Quiet {
    /// A peer that sent `sent` and has room for `room` bytes.
    fn with(sent: &[u8], room: usize) -> Quiet {
        let quiet = Quiet::default();
        {
            let mut peer = quiet.peer();
            peer.sent = sent.to_vec();
            peer.room = room;
        }
        quiet
    }

    fn peer(&self) -> MutexGuard<'_, QuietPeer> {
        self.0.lock().unwrap()
    }
}

impl AsyncRead for Quiet {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut peer = self.peer();
        if peer.sent.is_empty() {
            peer.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let count = peer.sent.len().min(buffer.remaining());
        buffer.put_slice(&peer.sent[..count]);
        peer.sent.drain(..count);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Quiet {
    /// The write that waits for the stream: nothing ever wakes it.
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl io::Write for Quiet {
    /// The write that returns at once.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut peer = self.peer();
        peer.attempts += 1;
        if peer.gone {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        let count = bytes.len().min(peer.room);
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        peer.room -= count;
        peer.taken.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn a_peer_that_closed_without_an_event_ends_its_connection_within_a_second() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    // The peer sent three requests in a row and takes 100 bytes of the first response. The
    // node holds the two further requests in front of it, so it reads nothing from the
    // connection while it writes: nothing would tell it that the peer closed.
    let requests = [HEALTH, HEALTH, HEALTH].concat();
    let quiet = Quiet::with(&requests, 100);
    let served = served(&harness, Attempted(quiet.clone()));
    settle().await;
    assert_eq!(quiet.peer().taken.len(), 100);
    let attempts_at_once = quiet.peer().attempts;

    // The write that waits is attempted again every second, without an event.
    tokio::time::sleep(10 * BLOCKED_WRITE_RETRY + Duration::from_millis(500)).await;
    assert_eq!(quiet.peer().attempts, attempts_at_once + 10);
    assert!(!served.is_finished());

    // The peer closes, and no task of the node is woken for it. The next attempt of the
    // write fails, and the node ends the connection.
    quiet.peer().gone = true;
    let gone = Instant::now();
    served.await.unwrap();
    assert!(gone.elapsed() <= BLOCKED_WRITE_RETRY);
    assert_eq!(quiet.peer().taken.len(), 100);
}

#[tokio::test(start_paused = true)]
async fn a_stream_that_never_takes_a_write_and_never_fails_is_cut_at_the_limit() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    // Without the attempted write the stream is one that only waits: a write is asked of it
    // every second and never answered, also after its peer is gone.
    let quiet = Quiet::with(HEALTH, 0);
    let served = served(&harness, quiet.clone());
    let asked = Instant::now();
    tokio::time::sleep(Duration::from_secs(10)).await;
    quiet.peer().gone = true;
    served.await.unwrap();
    assert_eq!(asked.elapsed(), INBOUND_IDLE);
    assert!(quiet.peer().taken.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_request_body_that_stops_arriving_fails_its_call_at_the_limit() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let (near, mut far) = tokio::io::duplex(64 * 1024);
    let served = served(&harness, near);

    // The head of a `forward` call that declares 1,000 bytes, and 10 of them.
    far.write_all(b"POST /v1/forward HTTP/1.1\r\nHost: node\r\nContent-Length: 1000\r\n\r\n")
        .await
        .unwrap();
    far.write_all(&[0u8; 10]).await.unwrap();
    let sent = Instant::now();
    settle().await;
    // The call holds one of the places of the forward calls while it reads its body.
    assert_eq!(harness.node.forward_calls(), 1);

    // No further byte arrives. The call fails after the limit, gives its place back, and
    // the node closes the connection after the response: the rest of the body would be read
    // as the next request.
    let (status, body) = response(&mut far).await;
    assert_eq!(sent.elapsed(), INBOUND_IDLE);
    let failure: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status, 400);
    assert_eq!(failure["code"], "invalid_request");
    assert_eq!(
        failure["message"],
        "the request body did not arrive within the time limit"
    );
    assert_eq!(harness.node.forward_calls(), 0);
    assert_eq!(far.read(&mut [0u8; 8]).await.unwrap(), 0);
    served.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_request_body_that_arrives_in_parts_before_the_limit_is_read() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let (near, mut far) = tokio::io::duplex(64 * 1024);
    let served = served(&harness, near);

    // The body of a `status` call in three parts, each a second before the limit: every
    // byte starts the wait of the node anew.
    let body = br#"{"user_id":"nobody","nonce":"bm9uY2U"}"#;
    let head = format!(
        "POST /v1/status HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    far.write_all(head.as_bytes()).await.unwrap();
    let sent = Instant::now();
    for part in body.chunks(body.len() / 3 + 1) {
        tokio::time::sleep(INBOUND_IDLE - Duration::from_secs(1)).await;
        far.write_all(part).await.unwrap();
    }
    let (status, body) = response(&mut far).await;
    assert!(sent.elapsed() > 2 * INBOUND_IDLE);
    assert_eq!(status, 200);
    let state: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(state["grant"]["state"], "none");
    assert!(!served.is_finished());
}

#[tokio::test(start_paused = true)]
async fn a_request_head_above_the_read_buffer_is_refused() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let (near, mut far) = tokio::io::duplex(4 * READ_BUFFER_BYTES);
    let served = served(&harness, near);

    // A head the read buffer holds is read whole.
    let padding = "x".repeat(READ_BUFFER_BYTES - 64);
    let head = format!("GET /v1/health HTTP/1.1\r\nHost: node\r\nX-Padding: {padding}\r\n\r\n");
    assert!(head.len() <= READ_BUFFER_BYTES);
    far.write_all(head.as_bytes()).await.unwrap();
    assert_eq!(response(&mut far).await.0, 200);

    // A head of three times the read buffer has no end the node could find in what it
    // reads: the node refuses it and closes the connection.
    let padding = "x".repeat(3 * READ_BUFFER_BYTES);
    let head = format!("GET /v1/health HTTP/1.1\r\nHost: node\r\nX-Padding: {padding}\r\n\r\n");
    far.write_all(head.as_bytes()).await.unwrap();
    let mut received = Vec::new();
    far.read_to_end(&mut received).await.unwrap();
    assert!(
        received.starts_with(b"HTTP/1.1 431 "),
        "{}",
        String::from_utf8_lossy(&received)
    );
    served.await.unwrap();
}

/// The share of the body budget a response body occupies is held until the peer took the
/// response: a peer that takes nothing holds memory the budget counts, and the budget is free
/// when the peer has read the response.
#[tokio::test]
async fn the_share_of_a_response_body_is_held_until_the_peer_took_the_response() {
    // More bytes than the buffers of a TCP connection hold.
    const BODY_BYTES: usize = 32 * 1024 * 1024;
    let provider = provider_with_log_store(|_| {
        Reply::with_body(
            200,
            &[("content-type", "application/octet-stream")],
            &vec![7u8; BODY_BYTES],
        )
    })
    .await;
    let harness = Harness::new(&provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let record = app.record(
        "oauth",
        "google_workspace",
        &json!({
            "token": {"access_token": "ya29.injected", "refresh_token": "1//refresh"},
            "obtained_ms": 1,
        }),
    );
    let listener = Platform::listen(harness.platform.as_ref(), 16)
        .await
        .unwrap();
    let address = listener.tcp_addr().unwrap();
    tokio::spawn(api::serve(
        listener,
        api::router(harness.node.clone()),
        harness.node.clone(),
    ));
    let budget = harness.node.limits.body_budget_bytes;
    let free = || harness.node.body_budget.available_permits();

    // A `forward` call over a connection of its own. The caller reads nothing.
    let meta = json!({
        "user_id": app.user_id, "record": record, "method": "GET",
        "url": "https://gmail.googleapis.com/gmail/v1/users/me/profile",
        "headers": [], "context": "", "timeout_ms": 20000,
    });
    let request_frame = frame::encode_head(&meta);
    let mut caller = TcpStream::connect(address).await.unwrap();
    let head = format!(
        "POST /v1/forward HTTP/1.1\r\nHost: node\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n",
        frame::CONTENT_TYPE,
        request_frame.len()
    );
    caller.write_all(head.as_bytes()).await.unwrap();
    caller.write_all(&request_frame).await.unwrap();

    // The node has the response of the provider and writes it to a caller that takes
    // nothing: the share of the body stays taken.
    let mut first = [0u8; 16];
    caller.read_exact(&mut first).await.unwrap();
    assert!(first.starts_with(b"HTTP/1.1 200 OK"));
    for _ in 0..20 {
        assert_eq!(budget - free(), BODY_BYTES);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The caller reads the response to its end: the share is free.
    let mut received = first.len();
    let mut buffer = vec![0u8; 1024 * 1024];
    while received < BODY_BYTES {
        let count = caller.read(&mut buffer).await.unwrap();
        assert!(count > 0, "the response ended after {received} bytes");
        received += count;
    }
    for _ in 0..400 {
        if free() == budget {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(free(), budget);
}
