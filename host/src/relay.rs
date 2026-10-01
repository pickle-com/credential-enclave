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
/// Pause after a failed accept, so a persistent failure does not spin.
const ACCEPT_RETRY_PAUSE: Duration = Duration::from_millis(50);
/// Length of the queue of connections that wait for accept.
const LISTEN_BACKLOG: u32 = 1024;

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
    /// Listens on `port`.
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

/// Pauses after a failed accept.
pub async fn pause_after_failed_accept() {
    tokio::time::sleep(ACCEPT_RETRY_PAUSE).await;
}

/// The inbound relay: pipes every connection of `listener` to a new connection to the node. A
/// connection whose node connection cannot be opened is closed.
pub async fn serve(listener: TcpListener, node: Arc<dyn NodeConnector>) {
    loop {
        let Ok((caller, _)) = listener.accept().await else {
            pause_after_failed_accept().await;
            continue;
        };
        let _ = caller.set_nodelay(true);
        let node = node.clone();
        tokio::spawn(async move {
            if let Ok(stream) = node.connect().await {
                pipe(caller, stream).await;
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

    async fn relay_with(node: EchoNode) -> SocketAddr {
        let listener = listen_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::new(node)));
        address
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
        let address = relay_with(EchoNode { reachable: true }).await;
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

        // The caller closes: the node side ends and the relay closes the connection.
        first.shutdown().await.unwrap();
        assert_eq!(first.read(&mut [0u8; 8]).await.unwrap(), 0);
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
        let listener = VsockListener::bind(PORT).unwrap();
        let accepted = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4];
            stream.read_exact(&mut buffer).await.unwrap();
            stream.write_all(&buffer).await.unwrap();
            stream.write_all(b" back").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut stream = vsock_connect(LOOPBACK_CID, PORT).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"ping back");
        accepted.await.unwrap();
    }

    #[tokio::test]
    async fn the_inbound_relay_closes_a_connection_when_the_node_cannot_be_reached() {
        let address = relay_with(EchoNode { reachable: false }).await;
        let mut caller = TcpStream::connect(address).await.unwrap();
        // The connection ends without a byte: with an orderly close or with a reset.
        let mut buffer = [0u8; 8];
        assert!(matches!(caller.read(&mut buffer).await, Ok(0) | Err(_)));
    }
}
