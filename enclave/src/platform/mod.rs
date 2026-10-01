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

pub mod local;
// The platform inside this module is compiled on Linux only. Its pure helpers are also
// compiled for tests on other systems.
#[cfg(any(target_os = "linux", test))]
pub mod nitro;

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

/// The place where backend calls arrive.
pub enum Listener {
    Tcp(TcpListener),
    #[cfg(target_os = "linux")]
    Vsock(tokio_vsock::VsockListener),
}

impl Listener {
    /// Waits for the next connection.
    pub async fn accept(&self) -> std::io::Result<Stream> {
        match self {
            Listener::Tcp(listener) => {
                let (stream, _) = listener.accept().await?;
                stream.set_nodelay(true)?;
                Ok(Box::new(stream))
            }
            #[cfg(target_os = "linux")]
            Listener::Vsock(listener) => {
                let (stream, _) = listener.accept().await?;
                Ok(Box::new(stream))
            }
        }
    }

    /// The local TCP address, when the listener is a TCP listener.
    #[cfg(test)]
    pub fn tcp_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            Listener::Tcp(listener) => listener.local_addr().ok(),
            #[cfg(target_os = "linux")]
            Listener::Vsock(_) => None,
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
    /// Opens the listener for backend calls.
    fn listen(&self) -> impl Future<Output = Result<Listener, PlatformError>> + Send;
    /// Opens a byte pipe to `host:port` of a provider.
    fn connect(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = Result<Stream, PlatformError>> + Send;
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
    fn listen(&self) -> BoxFuture<'_, Result<Listener, PlatformError>>;
    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, Result<Stream, PlatformError>>;
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

    fn listen(&self) -> BoxFuture<'_, Result<Listener, PlatformError>> {
        Box::pin(Platform::listen(self))
    }

    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, Result<Stream, PlatformError>> {
        Box::pin(Platform::connect(self, host, port))
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
