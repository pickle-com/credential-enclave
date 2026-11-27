//! The platform layer (enclave.md section 2): attestation, randomness, trusted time, the
//! listener for backend calls and the outbound byte pipe to providers.
//!
//! Code outside this module does not know which platform it runs on. It holds a
//! [`SharedPlatform`] and calls its operations.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

// The vsock connections of a node, which only the nitro platform has.
#[cfg(any(target_os = "linux", test))]
mod lingering;
pub mod local;
// The platform inside this module is compiled on Linux only. Its pure helpers are also
// compiled for tests on other systems.
#[cfg(any(target_os = "linux", test))]
pub mod nitro;

#[cfg(target_os = "linux")]
pub use lingering::{Lingerers, Lingering};

/// The port a node listens on: vsock 8080 on nitro, TCP 8080 on local.
pub const LISTEN_PORT: u16 = 8080;

/// A platform failure. The message is a fixed string: it never carries key material, request
/// bodies or addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformError(pub &'static str);

impl std::fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for PlatformError {}

/// Why the platform could not open a byte pipe to a provider or to the log store. Each variant
/// carries a fixed string of the source: it never carries key material, request bodies or
/// addresses. The two kinds are counted apart by `egress` of `GET /v1/health` (enclave.md
/// 5.1), and both are repeated by the node before any request byte left it (enclave.md 5.14).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectError {
    /// The pipe itself could not be opened: on nitro the vsock connection to the egress relay
    /// of the parent, on local the TCP connection to the host.
    Transport(&'static str),
    /// The egress relay of the parent took the connection and did not answer the `CONNECT`
    /// line with `OK`. The nitro platform, which is compiled on Linux only, is the one that
    /// creates it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    RelayRefused(&'static str),
}

/// The measurement of an enclave image: PCR0, PCR1 and PCR2 of its attestation documents. Two
/// enclaves with the same measurement run the same program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Measurement {
    pub pcrs: [[u8; 48]; 3],
}

/// A bidirectional byte pipe.
pub trait ByteStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> ByteStream for T {}

/// A connection accepted from the backend or opened towards a provider.
pub type Stream = Box<dyn ByteStream>;

/// A stream whose writes are attempted each time they are asked for, not only after the stream
/// reported that it takes bytes. `io::Write` of the inner stream is a write that returns at
/// once: it answers `WouldBlock` when the stream takes no byte now.
///
/// The vsock connections a node accepts are streams of this kind. The kernel of an enclave
/// gives a writer that waits no event when the peer of its vsock connection closes: the
/// event that says a socket takes bytes comes while the connection is open and its peer has
/// room, and a close of the peer changes neither. A write that waits for that event waits
/// without an end. An attempted write to a connection whose peer closed fails at once, and
/// what holds the stream asks for a write that waits again at its own pace
/// (`crate::inbound::TimedStream`).
///
/// The stream writes several buffers in one write (`is_write_vectored`): the HTTP connection
/// of a caller then keeps the body of a response as it is until the stream took it, and does
/// not copy it into a buffer of its own first.
#[cfg(any(target_os = "linux", test))]
pub struct Attempted<S>(pub S);

#[cfg(any(target_os = "linux", test))]
impl<S: AsyncRead + Unpin> AsyncRead for Attempted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buffer)
    }
}

#[cfg(any(target_os = "linux", test))]
impl<S: AsyncWrite + std::io::Write + Unpin> AsyncWrite for Attempted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::io::ErrorKind::{Interrupted, WouldBlock};
        loop {
            match std::io::Write::write(&mut self.0, bytes) {
                Err(error) if error.kind() == Interrupted => {}
                // The stream takes no byte now: its own write registers the task for the
                // event that says it does.
                Err(error) if error.kind() == WouldBlock => {
                    return Pin::new(&mut self.0).poll_write(cx, bytes);
                }
                outcome => return std::task::Poll::Ready(outcome),
            }
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        slices: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::io::ErrorKind::{Interrupted, WouldBlock};
        loop {
            match std::io::Write::write_vectored(&mut self.0, slices) {
                Err(error) if error.kind() == Interrupted => {}
                Err(error) if error.kind() == WouldBlock => {
                    let first = slices
                        .iter()
                        .find(|slice| !slice.is_empty())
                        .map_or(&[][..], |slice| &**slice);
                    return Pin::new(&mut self.0).poll_write(cx, first);
                }
                outcome => return std::task::Poll::Ready(outcome),
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// A vsock connection as [`Attempted`] writes to it: the write that returns at once, of one
/// buffer and of several buffers in one message.
#[cfg(target_os = "linux")]
pub struct VsockConnection(tokio_vsock::VsockStream);

#[cfg(target_os = "linux")]
impl std::io::Write for VsockConnection {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.0, bytes)
    }

    fn write_vectored(&mut self, slices: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
        socket2::SockRef::from(&self.0).send_vectored(slices)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl AsyncRead for VsockConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buffer)
    }
}

#[cfg(target_os = "linux")]
impl AsyncWrite for VsockConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, bytes)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// The place where backend calls arrive.
pub enum Listener {
    Tcp(TcpListener),
    /// A vsock listener, and the connections of the node that wait for the end of their
    /// peer.
    #[cfg(target_os = "linux")]
    Vsock(tokio_vsock::VsockListener, Arc<Lingerers>),
}

impl Listener {
    /// Waits for the next connection. A vsock connection is a stream whose writes are
    /// attempted each time they are asked for ([`Attempted`]) and that is closed only after
    /// its peer reported the end of its bytes ([`Lingering`]).
    pub async fn accept(&self) -> std::io::Result<Stream> {
        match self {
            Listener::Tcp(listener) => {
                let (stream, _) = listener.accept().await?;
                stream.set_nodelay(true)?;
                Ok(Box::new(stream))
            }
            #[cfg(target_os = "linux")]
            Listener::Vsock(listener, lingerers) => {
                let (stream, _) = listener.accept().await?;
                Ok(Box::new(Lingering::new(
                    Attempted(VsockConnection(stream)),
                    lingerers.clone(),
                )))
            }
        }
    }

    /// The local TCP address, when the listener is a TCP listener.
    #[cfg(test)]
    pub fn tcp_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            Listener::Tcp(listener) => listener.local_addr().ok(),
            #[cfg(target_os = "linux")]
            Listener::Vsock(..) => None,
        }
    }
}

/// The operations a platform provides (enclave.md section 2).
pub trait Platform: Send + Sync + 'static {
    /// `"nitro"` or `"local"`.
    fn name(&self) -> &'static str;
    /// The custody of the user keys a node on this platform holds (protocol.md section 3):
    /// `"enclave"` on nitro, `"operator"` on local.
    fn custody(&self) -> &'static str;
    /// The measurement of this node: its own PCR0, PCR1 and PCR2 on nitro, `None` on local.
    fn measurement(&self) -> Option<Measurement>;
    /// The platform attestation document over `user_data` and `nonce`.
    fn attestation(&self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, PlatformError>;
    /// Fills `out` with kernel randomness.
    fn fill_random(&self, out: &mut [u8]) -> Result<(), PlatformError>;
    /// The time the hypervisor gives, in Unix epoch milliseconds.
    fn trusted_time_ms(&self) -> Result<u64, PlatformError>;
    /// Opens the listener for backend calls of a node that holds `connections` connections
    /// from the backend at once (enclave.md section 8). On nitro the queue of the listener
    /// holds as many connections that wait for accept, so the kernel refuses no connection
    /// the node has a place for. The local platform leaves the queue of its TCP listener as
    /// the library sets it.
    fn listen(
        &self,
        connections: usize,
    ) -> impl Future<Output = Result<Listener, PlatformError>> + Send;
    /// Opens a byte pipe to `host:port` of a provider or of the log store.
    fn connect(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = Result<Stream, ConnectError>> + Send;
    /// The connections the node is done with that wait for the end of their peer at this
    /// moment, and the connections it closed before their peer had reported its end since it
    /// started (`lingering_connections` and `lingering_cut` of `load` of health). `None` on a
    /// platform that closes a connection when the node is done with it: only the vsock
    /// connections of nitro wait.
    fn lingering(&self) -> Option<(usize, u64)> {
        None
    }
}

/// A boxed future, for the object-safe form of [`Platform`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The object-safe form of [`Platform`]. Every platform has it through the blanket
/// implementation below.
pub trait DynPlatform: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn custody(&self) -> &'static str;
    fn measurement(&self) -> Option<Measurement>;
    fn attestation(&self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, PlatformError>;
    fn fill_random(&self, out: &mut [u8]) -> Result<(), PlatformError>;
    fn trusted_time_ms(&self) -> Result<u64, PlatformError>;
    fn listen(&self, connections: usize) -> BoxFuture<'_, Result<Listener, PlatformError>>;
    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, Result<Stream, ConnectError>>;
    fn lingering(&self) -> Option<(usize, u64)>;
}

impl<P: Platform> DynPlatform for P {
    fn name(&self) -> &'static str {
        Platform::name(self)
    }

    fn custody(&self) -> &'static str {
        Platform::custody(self)
    }

    fn measurement(&self) -> Option<Measurement> {
        Platform::measurement(self)
    }

    fn attestation(&self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, PlatformError> {
        Platform::attestation(self, user_data, nonce)
    }

    fn fill_random(&self, out: &mut [u8]) -> Result<(), PlatformError> {
        Platform::fill_random(self, out)
    }

    fn trusted_time_ms(&self) -> Result<u64, PlatformError> {
        Platform::trusted_time_ms(self)
    }

    fn listen(&self, connections: usize) -> BoxFuture<'_, Result<Listener, PlatformError>> {
        Box::pin(Platform::listen(self, connections))
    }

    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, Result<Stream, ConnectError>> {
        Box::pin(Platform::connect(self, host, port))
    }

    fn lingering(&self) -> Option<(usize, u64)> {
        Platform::lingering(self)
    }
}

/// The platform a node runs on, shared by every part of the program.
pub type SharedPlatform = Arc<dyn DynPlatform>;

/// Selects the platform named by the `--platform` argument.
pub fn select(name: &str) -> Result<SharedPlatform, PlatformError> {
    match name {
        "local" => Ok(Arc::new(local::LocalPlatform)),
        #[cfg(target_os = "linux")]
        "nitro" => Ok(Arc::new(nitro::NitroPlatform::open()?)),
        #[cfg(not(target_os = "linux"))]
        "nitro" => Err(PlatformError("the nitro platform exists on Linux only")),
        _ => Err(PlatformError("unknown platform: expected nitro or local")),
    }
}
