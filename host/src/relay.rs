//! Byte pipes: the stream type of the host program, the vsock endpoints of the parent instance
//! and the inbound relay (enclave.md section 9).
//!
//! The inbound relay listens on TCP `0.0.0.0:8080`. For every connection it opens a vsock
//! connection to the listener of the node (CID 16, port 8080) and moves the bytes in both
//! directions. The relay does not read the bytes: the call surface of the node ends inside the
//! enclave.
//!
//! vsock exists on Linux only. Everything else in this crate works on a stream type and on the
//! [`NodeConnector`] trait, so the tests run without vsock.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpSocket};

/// The vsock context id the host program gives the enclave.
pub const ENCLAVE_CID: u32 = 16;
/// The vsock port the node listens on for backend calls.
pub const NODE_PORT: u32 = 8080;

/// Longest wait for a vsock connection to the node.
const NODE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Size of the buffer of each direction of a pipe.
const PIPE_BUFFER_BYTES: usize = 64 * 1024;
/// Pause after a failed accept of a class that asks for one, so a persistent failure does not
/// spin.
const ACCEPT_RETRY_PAUSE: Duration = Duration::from_millis(50);
/// Length of the queue of connections that wait for accept, on the two TCP listeners and on the
/// vsock listener of the egress relay.
const LISTEN_BACKLOG: u32 = 1024;

/// The class of a failed accept. The class decides whether the next accept runs at once or
/// after a pause, and it is the `cause` label of
/// `credential_enclave_host_egress_accept_errors_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptFailure {
    /// The connection was gone before accept returned it (`ECONNABORTED`, `EPROTO`), or the
    /// call was interrupted or found no connection (`EINTR`, `EAGAIN`): the next accept runs at
    /// once.
    Aborted,
    /// The process or the kernel is out of descriptors or memory (`EMFILE`, `ENFILE`,
    /// `ENOBUFS`, `ENOMEM`): the next accept runs after a pause of 50 milliseconds.
    Resources,
    /// Any other failure: the next accept runs after a pause of 50 milliseconds.
    Other,
}

impl AcceptFailure {
    /// The three classes, in the order of the label values of the metrics.
    pub const ALL: [AcceptFailure; 3] = [
        AcceptFailure::Aborted,
        AcceptFailure::Resources,
        AcceptFailure::Other,
    ];

    /// Classifies the error of a failed accept: by its OS error number when it has one, by its
    /// kind otherwise.
    pub fn of(error: &io::Error) -> AcceptFailure {
        match error.raw_os_error() {
            Some(libc::ECONNABORTED | libc::EINTR | libc::EAGAIN | libc::EPROTO) => {
                AcceptFailure::Aborted
            }
            Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM) => {
                AcceptFailure::Resources
            }
            Some(_) => AcceptFailure::Other,
            None => match error.kind() {
                io::ErrorKind::ConnectionAborted
                | io::ErrorKind::Interrupted
                | io::ErrorKind::WouldBlock => AcceptFailure::Aborted,
                io::ErrorKind::OutOfMemory => AcceptFailure::Resources,
                _ => AcceptFailure::Other,
            },
        }
    }

    /// The value of the `cause` label.
    pub fn label(self) -> &'static str {
        match self {
            AcceptFailure::Aborted => "aborted",
            AcceptFailure::Resources => "resources",
            AcceptFailure::Other => "other",
        }
    }
}

/// A bidirectional byte pipe.
pub trait ByteStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> ByteStream for T {}

/// A connection of the host program: accepted from a caller or opened towards the node or a
/// provider.
pub type Stream = Box<dyn ByteStream>;

/// A boxed future, for the traits that open connections.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The way to the listener of the node.
pub trait NodeConnector: Send + Sync + 'static {
    /// Opens one connection to the listener of the node.
    fn connect(&self) -> BoxFuture<'_, io::Result<Stream>>;
}

/// The node of this parent instance: vsock CID 16, port 8080.
pub struct VsockNode;

impl NodeConnector for VsockNode {
    fn connect(&self) -> BoxFuture<'_, io::Result<Stream>> {
        Box::pin(async {
            match tokio::time::timeout(NODE_CONNECT_TIMEOUT, vsock_connect(ENCLAVE_CID, NODE_PORT))
                .await
            {
                Ok(outcome) => outcome,
                Err(_) => Err(io::Error::from(io::ErrorKind::TimedOut)),
            }
        })
    }
}

#[cfg(target_os = "linux")]
async fn vsock_connect(cid: u32, port: u32) -> io::Result<Stream> {
    let stream = tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(cid, port)).await?;
    Ok(Box::new(stream))
}

#[cfg(not(target_os = "linux"))]
async fn vsock_connect(_cid: u32, _port: u32) -> io::Result<Stream> {
    Err(vsock_unsupported())
}

#[cfg(not(target_os = "linux"))]
fn vsock_unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "vsock exists on Linux only")
}

/// A vsock listener of the parent instance. It accepts connections from every context id: the
/// only vsock peer of a parent instance is its enclave.
pub struct VsockListener {
    #[cfg(target_os = "linux")]
    inner: tokio_vsock::VsockListener,
}

impl VsockListener {
    /// Listens on `port`. The queue of connections that wait for accept has the length the
    /// library sets, 128, until [`VsockListener::widen_backlog`] runs.
    #[cfg(target_os = "linux")]
    pub fn bind(port: u32) -> io::Result<VsockListener> {
        let address = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, port);
        tokio_vsock::VsockListener::bind(address).map(|inner| VsockListener { inner })
    }

    /// Listens on `port`.
    #[cfg(not(target_os = "linux"))]
    pub fn bind(_port: u32) -> io::Result<VsockListener> {
        Err(vsock_unsupported())
    }

    /// Sets the queue of connections that wait for accept to `LISTEN_BACKLOG` with a second
    /// `listen` call on the bound socket, and returns that length. The kernel of the parent
    /// instance resets a connection request that finds the queue full, so the queue holds the
    /// connections the node opens at once. When the call fails the queue keeps the length of
    /// `bind`, and the listener works as before.
    #[cfg(target_os = "linux")]
    pub fn widen_backlog(&self) -> io::Result<u32> {
        let backlog = i32::try_from(LISTEN_BACKLOG)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        socket2::SockRef::from(&self.inner).listen(backlog)?;
        Ok(LISTEN_BACKLOG)
    }

    /// Sets the queue of connections that wait for accept to `LISTEN_BACKLOG`.
    #[cfg(not(target_os = "linux"))]
    pub fn widen_backlog(&self) -> io::Result<u32> {
        Err(vsock_unsupported())
    }

    /// Waits for the next connection.
    #[cfg(target_os = "linux")]
    pub async fn accept(&self) -> io::Result<Stream> {
        let (stream, _) = self.inner.accept().await?;
        Ok(Box::new(stream))
    }

    /// Waits for the next connection.
    #[cfg(not(target_os = "linux"))]
    pub async fn accept(&self) -> io::Result<Stream> {
        Err(vsock_unsupported())
    }
}

/// Opens a TCP listener. Its connections have TCP keepalive on, so a peer that disappears
/// without closing does not hold a pipe forever (Linux hands the option of the listening socket
/// to the accepted sockets).
pub fn listen_tcp(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.set_keepalive(true)?;
    socket.bind(address)?;
    socket.listen(LISTEN_BACKLOG)
}

/// Moves bytes between `a` and `b` in both directions until both directions have ended. The end
/// of one direction closes the write side of the other stream, and the pipe stays open for the
/// bytes of the other direction. A failure of either stream ends the pipe.
pub async fn pipe<A, B>(mut a: A, mut b: B)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let _ = tokio::io::copy_bidirectional_with_sizes(
        &mut a,
        &mut b,
        PIPE_BUFFER_BYTES,
        PIPE_BUFFER_BYTES,
    )
    .await;
}

/// Pauses after a failed accept of the class `failure` when that class asks for one: a
/// persistent failure does not spin, and a connection that was gone before accept returned it
/// costs no wait.
pub async fn pause_after_failed_accept(failure: AcceptFailure) {
    if failure != AcceptFailure::Aborted {
        tokio::time::sleep(ACCEPT_RETRY_PAUSE).await;
    }
}

/// The counts of the inbound relay since the host program started. The relay writes them and
/// the status surface reads them for `/metrics` (enclave.md section 9).
#[derive(Debug, Default)]
pub struct InboundCounters {
    /// Connections of callers for which the connection to the node could not be opened.
    node_connect_failures: AtomicU64,
}

impl InboundCounters {
    /// The connections of callers for which the vsock connection to the node failed or did not
    /// open within its time limit: the value of
    /// `credential_enclave_host_inbound_node_connect_failures_total`.
    pub fn node_connect_failures(&self) -> u64 {
        self.node_connect_failures.load(Ordering::Relaxed)
    }
}

/// The inbound relay: pipes every connection of `listener` to a new connection to the node. A
/// connection whose node connection cannot be opened is closed and counted.
pub async fn serve(
    listener: TcpListener,
    node: Arc<dyn NodeConnector>,
    counters: Arc<InboundCounters>,
) {
    loop {
        let (caller, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                pause_after_failed_accept(AcceptFailure::of(&error)).await;
                continue;
            }
        };
        let _ = caller.set_nodelay(true);
        let node = node.clone();
        let counters = counters.clone();
        tokio::spawn(async move {
            match node.connect().await {
                Ok(stream) => pipe(caller, stream).await,
                Err(_) => {
                    counters
                        .node_connect_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;

    /// A node stand-in whose connections echo every byte, or that cannot be reached.
    struct EchoNode {
        reachable: bool,
    }

    impl NodeConnector for EchoNode {
        fn connect(&self) -> BoxFuture<'_, io::Result<Stream>> {
            Box::pin(async move {
                if !self.reachable {
                    return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
                }
                let (near, mut far) = tokio::io::duplex(1024);
                tokio::spawn(async move {
                    let mut buffer = [0u8; 256];
                    while let Ok(count) = far.read(&mut buffer).await {
                        if count == 0 || far.write_all(&buffer[..count]).await.is_err() {
                            break;
                        }
                    }
                });
                Ok(Box::new(near) as Stream)
            })
        }
    }

    async fn relay_with(node: EchoNode) -> (SocketAddr, Arc<InboundCounters>) {
        let listener = listen_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let counters = Arc::new(InboundCounters::default());
        tokio::spawn(serve(listener, Arc::new(node), counters.clone()));
        (address, counters)
    }

    #[tokio::test]
    async fn a_pipe_moves_bytes_in_both_directions_and_carries_the_end_of_a_direction() {
        let (mut left, left_inner) = tokio::io::duplex(64);
        let (right_inner, mut right) = tokio::io::duplex(64);
        let piped = tokio::spawn(pipe(left_inner, right_inner));

        left.write_all(b"to the right").await.unwrap();
        let mut buffer = [0u8; 12];
        right.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"to the right");

        right.write_all(b"to the left").await.unwrap();
        let mut buffer = [0u8; 11];
        left.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"to the left");

        // The left side ends its direction. The right side sees the end and can still answer.
        left.shutdown().await.unwrap();
        assert_eq!(right.read(&mut [0u8; 8]).await.unwrap(), 0);
        right.write_all(b"late").await.unwrap();
        let mut buffer = [0u8; 4];
        left.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"late");

        // The end of the second direction ends the pipe.
        right.shutdown().await.unwrap();
        assert_eq!(left.read(&mut [0u8; 8]).await.unwrap(), 0);
        piped.await.unwrap();
    }

    #[tokio::test]
    async fn a_pipe_carries_more_bytes_than_its_buffers_hold() {
        let (mut left, left_inner) = tokio::io::duplex(1024);
        let (right_inner, mut right) = tokio::io::duplex(1024);
        tokio::spawn(pipe(left_inner, right_inner));

        let sent: Vec<u8> = (0..1_000_000u32).map(|index| (index % 251) as u8).collect();
        let expected = sent.clone();
        let writer = tokio::spawn(async move {
            left.write_all(&sent).await.unwrap();
            left.shutdown().await.unwrap();
            left
        });
        let mut received = Vec::new();
        right.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, expected);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn the_inbound_relay_pipes_a_tcp_connection_to_the_node() {
        let (address, counters) = relay_with(EchoNode { reachable: true }).await;
        let mut first = TcpStream::connect(address).await.unwrap();
        let mut second = TcpStream::connect(address).await.unwrap();

        // Two connections are two pipes: each one gets its own bytes back.
        first.write_all(b"first call").await.unwrap();
        second.write_all(b"second call").await.unwrap();
        let mut buffer = [0u8; 10];
        first.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"first call");
        let mut buffer = [0u8; 11];
        second.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"second call");

        // The caller closes: the node side ends and the relay closes the connection. Every
        // connection to the node opened.
        first.shutdown().await.unwrap();
        assert_eq!(first.read(&mut [0u8; 8]).await.unwrap(), 0);
        assert_eq!(counters.node_connect_failures(), 0);
    }

    /// The vsock endpoints against the loopback transport of the kernel (context id 1). The
    /// test needs a kernel with `vsock_loopback` and a process that may open vsock sockets, so
    /// it runs on request only: `cargo test -p credential-enclave-host -- --ignored`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "needs the vsock loopback transport of the kernel"]
    async fn the_vsock_endpoints_carry_bytes_over_the_loopback_transport() {
        const LOOPBACK_CID: u32 = 1;
        const PORT: u32 = 18_443;
        // More connections than the queue of `bind` holds: the kernel resets the 130th
        // connection request of a queue of 128.
        const WAITING: usize = 300;
        let listener = VsockListener::bind(PORT).unwrap();
        assert_eq!(listener.widen_backlog().unwrap(), LISTEN_BACKLOG);

        // Every connection opens before the first accept: the widened queue holds them all.
        let mut waiting: Vec<Stream> = Vec::with_capacity(WAITING);
        for index in 0..WAITING {
            match vsock_connect(LOOPBACK_CID, PORT).await {
                Ok(stream) => waiting.push(stream),
                Err(error) => panic!("connection {index} did not enter the queue: {error}"),
            }
        }
        assert_eq!(waiting.len(), WAITING);

        // The first connection of the queue carries bytes in both directions.
        let accepted = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4];
            stream.read_exact(&mut buffer).await.unwrap();
            stream.write_all(&buffer).await.unwrap();
            stream.write_all(b" back").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut stream = waiting.remove(0);
        stream.write_all(b"ping").await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"ping back");
        accepted.await.unwrap();
    }

    #[test]
    fn a_failed_accept_is_classified_by_its_os_error_number_or_its_kind() {
        for code in [libc::ECONNABORTED, libc::EINTR, libc::EAGAIN, libc::EPROTO] {
            let error = io::Error::from_raw_os_error(code);
            assert_eq!(AcceptFailure::of(&error), AcceptFailure::Aborted, "{error}");
        }
        for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            let error = io::Error::from_raw_os_error(code);
            assert_eq!(
                AcceptFailure::of(&error),
                AcceptFailure::Resources,
                "{error}"
            );
        }
        for code in [libc::EBADF, libc::EINVAL, libc::ENOTSOCK, libc::EOPNOTSUPP] {
            let error = io::Error::from_raw_os_error(code);
            assert_eq!(AcceptFailure::of(&error), AcceptFailure::Other, "{error}");
        }

        // An error without an OS error number is classified by its kind.
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::Interrupted,
            io::ErrorKind::WouldBlock,
        ] {
            assert_eq!(
                AcceptFailure::of(&io::Error::from(kind)),
                AcceptFailure::Aborted,
                "{kind:?}"
            );
        }
        assert_eq!(
            AcceptFailure::of(&io::Error::from(io::ErrorKind::OutOfMemory)),
            AcceptFailure::Resources
        );
        for kind in [
            io::ErrorKind::Other,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::Unsupported,
        ] {
            assert_eq!(
                AcceptFailure::of(&io::Error::from(kind)),
                AcceptFailure::Other,
                "{kind:?}"
            );
        }

        assert_eq!(
            AcceptFailure::ALL.map(AcceptFailure::label),
            ["aborted", "resources", "other"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn only_an_aborted_accept_is_followed_by_the_next_accept_at_once() {
        let slack = Duration::from_millis(10);
        let started = tokio::time::Instant::now();
        pause_after_failed_accept(AcceptFailure::Aborted).await;
        assert_eq!(started.elapsed(), Duration::ZERO);
        pause_after_failed_accept(AcceptFailure::Resources).await;
        let waited = started.elapsed();
        assert!(waited >= ACCEPT_RETRY_PAUSE && waited < ACCEPT_RETRY_PAUSE + slack);
        pause_after_failed_accept(AcceptFailure::Other).await;
        let waited = started.elapsed();
        assert!(waited >= 2 * ACCEPT_RETRY_PAUSE && waited < 2 * ACCEPT_RETRY_PAUSE + slack);
    }

    #[tokio::test]
    async fn the_inbound_relay_closes_a_connection_when_the_node_cannot_be_reached() {
        let (address, counters) = relay_with(EchoNode { reachable: false }).await;
        for expected in 1..=3u64 {
            let mut caller = TcpStream::connect(address).await.unwrap();
            // The connection ends without a byte: with an orderly close or with a reset.
            let mut buffer = [0u8; 8];
            assert!(matches!(caller.read(&mut buffer).await, Ok(0) | Err(_)));
            // Every connection whose node connection failed is counted.
            for _ in 0..200 {
                if counters.node_connect_failures() == expected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(counters.node_connect_failures(), expected);
        }
    }
}
