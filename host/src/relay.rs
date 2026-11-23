//! Byte pipes: the stream type of the host program, the vsock endpoints of the parent instance,
//! the pipe of the two relays with its limits and its counts, and the inbound relay (enclave.md
//! section 9).
//!
//! The inbound relay listens on TCP `0.0.0.0:8080`. For every connection it opens a vsock
//! connection to the listener of the node (CID 16, port 8080) and moves the bytes in both
//! directions. The relay does not read the bytes: the call surface of the node ends inside the
//! enclave.
//!
//! A pipe ends within a fixed time whatever its two ends do ([`pipe`]): no byte for
//! [`PIPE_IDLE_LIMIT`] ends it, no byte for [`PIPE_HALF_CLOSED_LIMIT`] after one of its
//! directions ended ends it, and a write a stream did not take is attempted again every
//! [`BLOCKED_WRITE_RETRY`] without an event of the kernel. A relay holds a fixed number of
//! connections and of large buffers ([`Pipes`]), so the memory of the host program has a bound
//! (enclave.md 9.2).
//!
//! A pipe has a side that asks and a side that answers: a caller and the node for the inbound
//! relay, the node and a provider for the egress relay ([`Relay`]). The side that answers can
//! close while bytes for it are on the way, and it does not take its answer with it: the pipe
//! moves what it sent last and its end to the side that asks before it ends. The inbound relay
//! also reads and drops what a caller still sends to a node that closed, so a caller that was
//! sending the body of its request when the node answered reads the whole answer and closes
//! its connection itself. When the side that asks is gone, nobody waits for anything, and the
//! pipe ends at once.
//!
//! The inbound relay takes connections until the shutdown of the pod closes its door
//! ([`InboundDoor`]). It then takes the connections that wait in the queue of its listener,
//! closes the listener, and holds its pipes until they end: a caller that connects from then
//! on is refused by the kernel, which is a connection that did not open, and no connection the
//! relay took is left without the node behind it (`crate::calls`).
//!
//! One of the two streams of a pipe is the node, and the end of its bytes says more than the
//! end of a direction: a node that closed its write side is done with the connection. It
//! keeps the connection open only until its peer ended too, because the kernel of an enclave
//! does not give back the bytes that reach a vsock socket it closed (enclave.md section 8).
//! So a pipe that read the end of the bytes of the node closes the write side of its
//! connection to the node at once and moves nothing more to it.
//!
//! vsock exists on Linux only. Everything else in this crate works on a stream type and on the
//! [`NodeConnector`] trait, so the tests run without vsock.

use std::collections::BTreeMap;
use std::future::{poll_fn, Future};
use std::io;
use std::net::SocketAddr;
use std::ops::Range;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::watch;
use tokio::time::Instant;

/// The vsock context id the host program gives the enclave.
pub const ENCLAVE_CID: u32 = 16;
/// The vsock port the node listens on for backend calls.
pub const NODE_PORT: u32 = 8080;

/// Longest wait for a vsock connection to the node.
const NODE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Size of the buffer every direction of a pipe has.
pub const SMALL_BUFFER_BYTES: usize = 4 * 1024;
/// Size of the buffer a direction takes while it moves many bytes: the largest packet of the
/// vsock transport, so one write of a full buffer to the node is one packet.
pub const LARGE_BUFFER_BYTES: usize = 64 * 1024;
/// Large buffers the directions of the pipes of one relay hold at once.
pub const LARGE_BUFFERS: usize = 2_048;
/// Time after which a direction gives its large buffer back when it has not held
/// [`SMALL_BUFFER_BYTES`] or more at once.
pub const LARGE_BUFFER_IDLE: Duration = Duration::from_secs(1);
/// Longest time a pipe with both directions open stays open while no byte moves in either
/// direction. It is above every silence of a connection in use: the relay allows one call 600
/// seconds between two bytes, no time limit of the node is above that (enclave.md section 8:
/// the longest is that of a `vault/send` call, at most 600 seconds), and the 300 seconds
/// between the two numbers are the room for what a caller adds to the time limit of a call.
pub const PIPE_IDLE_LIMIT: Duration = Duration::from_secs(900);
/// Longest time a pipe stays open while no byte moves after one of its streams reported the
/// end of its bytes: the time the side that is still open has to read what the pipe carried
/// and to close.
pub const PIPE_HALF_CLOSED_LIMIT: Duration = Duration::from_secs(60);
/// Pause between two attempts of a write that a stream did not take.
pub const BLOCKED_WRITE_RETRY: Duration = Duration::from_secs(1);
/// The most connections of callers the inbound relay holds at once: the most connections from
/// the backend a node holds at once, whatever its memory (enclave.md section 8). The relay
/// holds this many until the node says how many connections it holds ([`inbound_pipes_for`]).
pub const INBOUND_PIPES: usize = 16_384;
/// Connections the node keeps for the calls the host program itself makes to it, past the
/// inbound relay: the `health` calls of the probes of the pod, of the metrics and of the
/// watch of the enclave. The inbound relay holds this many connections fewer than the node,
/// so a node whose callers hold every place of the relay still answers the host program.
pub const HOST_CALLS: usize = 8;

/// The connections of callers the inbound relay holds at once in front of a node that holds
/// `node_connections` connections from the backend at once (`inbound_limit` of `load` of its
/// `health` call): that number less [`HOST_CALLS`], at least 1 and at most [`INBOUND_PIPES`].
pub fn inbound_pipes_for(node_connections: u64) -> usize {
    usize::try_from(node_connections)
        .unwrap_or(INBOUND_PIPES)
        .saturating_sub(HOST_CALLS)
        .clamp(1, INBOUND_PIPES)
}
/// Connections of the node the egress relay holds at once.
pub const EGRESS_PIPES: usize = 8_192;
/// Reads a direction of a pipe makes before the task of the pipe lets other tasks run.
const READS_PER_TURN: u32 = 16;
/// Pause after a failed accept of a class that asks for one, so a persistent failure does not
/// spin.
const ACCEPT_RETRY_PAUSE: Duration = Duration::from_millis(50);
/// Length of the queue of connections that wait for accept, on the TCP listener of the status
/// surface and on the vsock listener of the egress relay.
pub const LISTEN_BACKLOG: u32 = 1024;
/// Length of the queue of connections that wait for accept on the TCP listener of the inbound
/// relay: the most connections of callers the relay holds at once ([`INBOUND_PIPES`]). A
/// connection the relay has a place for must not be turned away because the relay has not
/// accepted it yet, so the relay asks for a queue as long as its places, in front of a node
/// of any size. The kernel caps the queue of every listener at `net.core.somaxconn` of the
/// network namespace of the pod, whose default is 4,096: more than the 1,494 places of a
/// relay in front of a node in an enclave of 4,096 MiB (enclave.md section 8).
pub const INBOUND_LISTEN_BACKLOG: u32 = INBOUND_PIPES as u32;

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

/// A stream whose writes are attempted each time they are asked for, not only after the stream
/// reported that it takes bytes. `io::Write::write` of the inner stream is a write that returns
/// at once: it answers `WouldBlock` when the stream takes no byte now.
///
/// The vsock connections of the host program are streams of this kind. The kernel of the
/// parent instance does not report every end of a vsock peer to a writer that waits: a socket
/// that holds unread bytes when its peer closes gets no event that says it can be written or
/// that it failed, and a write that waits for such an event waits without an end. An attempted
/// write fails at once on such a socket, and a pipe asks for its write again every
/// [`BLOCKED_WRITE_RETRY`] while the stream does not take it ([`pipe`]).
#[cfg(any(target_os = "linux", test))]
pub struct Attempting<S>(pub S);

#[cfg(any(target_os = "linux", test))]
impl<S: AsyncRead + Unpin> AsyncRead for Attempting<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buffer)
    }
}

#[cfg(any(target_os = "linux", test))]
impl<S: AsyncWrite + io::Write + Unpin> AsyncWrite for Attempting<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match io::Write::write(&mut self.0, bytes) {
                Ok(written) => return Poll::Ready(Ok(written)),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                // The stream takes no byte now: its own write registers the task for the event
                // that says it does.
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Pin::new(&mut self.0).poll_write(cx, bytes);
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(target_os = "linux")]
async fn vsock_connect(cid: u32, port: u32) -> io::Result<Stream> {
    let stream = tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(cid, port)).await?;
    Ok(Box::new(Attempting(stream)))
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
        Ok(Box::new(Attempting(stream)))
    }

    /// Waits for the next connection.
    #[cfg(not(target_os = "linux"))]
    pub async fn accept(&self) -> io::Result<Stream> {
        Err(vsock_unsupported())
    }
}

/// Opens a TCP listener whose queue of connections that wait for accept has the length
/// `backlog`, or the length the kernel caps it at. A peer that disappears without closing does
/// not hold a connection of the listener: a pipe ends at its limits ([`pipe`]), and the status
/// surface ends a connection that sends no request.
pub fn listen_tcp(address: SocketAddr, backlog: u32) -> io::Result<TcpListener> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(backlog)
}

/// How a pipe ended. It is the `cause` label of
/// `credential_enclave_host_egress_relays_ended_total` and of
/// `credential_enclave_host_inbound_relays_ended_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeEnd {
    /// Both directions ended: each stream reported the end of its bytes and the other took
    /// every byte before it, or a stream took no further byte after it had reported the end
    /// of its bytes, or after the pipe had moved what it sent last (it had closed, and the
    /// bytes for it had nowhere to go).
    Closed,
    /// A read of a stream failed, or a write to the stream that asks before that stream had
    /// reported the end of its bytes.
    Failed,
    /// No byte moved for [`PIPE_IDLE_LIMIT`] while both directions were open.
    Idle,
    /// No byte moved for [`PIPE_HALF_CLOSED_LIMIT`] after a stream had reported the end of its
    /// bytes or the sink of a direction had closed.
    HalfClosed,
}

impl PipeEnd {
    /// The four ends, in the order of the label values of the metrics.
    pub const ALL: [PipeEnd; 4] = [
        PipeEnd::Closed,
        PipeEnd::Failed,
        PipeEnd::Idle,
        PipeEnd::HalfClosed,
    ];

    /// The value of the `cause` label.
    pub fn label(self) -> &'static str {
        match self {
            PipeEnd::Closed => "closed",
            PipeEnd::Failed => "failed",
            PipeEnd::Idle => "idle",
            PipeEnd::HalfClosed => "half_closed",
        }
    }
}

/// The relay a pipe belongs to: which of its two streams asks, which answers, and which of
/// them is the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relay {
    /// The inbound relay: a caller asks and the node answers.
    Inbound,
    /// The egress relay: the node asks, and a provider or the log store answers.
    Egress,
}

/// What a direction does with the bytes of its source once its sink takes no more: the sink
/// closed (a write to it failed), or the sink is the node and reported the end of its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Leftover {
    /// The direction does not read them, and the stream that sends them is cut off when the
    /// pipe ends. What the node still sends to a provider that closed, and what a provider
    /// still sends to a node that is done, is of use to nobody.
    Unread,
    /// The direction reads them and drops them until the stream reports the end of its
    /// bytes. A caller of the inbound relay that is still sending its request when the node
    /// answers and is done (a node answers some calls before it has read their body) is not
    /// cut off: it sends the rest of its request, reads the answer and closes first. A
    /// connection that is closed while its peer is still sending is reset, and a caller
    /// whose connection is reset can lose an answer it has not read yet.
    Dropped,
}

/// The two times of an open pipe, in milliseconds since the relay started.
#[derive(Debug)]
struct PipeTimes {
    /// When the relay took the connection.
    opened_ms: u64,
    /// When a byte last moved, or the connection was taken when none moved yet.
    moved_ms: AtomicU64,
}

/// The pipes of one relay: the connections the relay holds at this moment, at most `limit` of
/// them, the large buffers their directions hold, at most `large_limit` of them, and how the
/// pipes that ended did end. The relay writes it and the status surface reads it for
/// `/metrics` (enclave.md section 9).
#[derive(Debug)]
pub struct Pipes {
    /// The most connections the relay holds at once. The inbound relay sets it again when
    /// the node says how many connections it holds ([`Pipes::set_limit`]).
    limit: AtomicUsize,
    large_limit: usize,
    /// The instant the times of the pipes count from.
    started: Instant,
    /// The connections the relay holds, by the order in which it took them.
    open: Mutex<BTreeMap<u64, Arc<PipeTimes>>>,
    /// The number of the next connection.
    next: AtomicU64,
    /// The large buffers the directions of the pipes hold.
    large_held: AtomicUsize,
    /// Ended pipes by end, in the order of [`PipeEnd::ALL`].
    ended: [AtomicU64; 4],
}

/// A buffer of [`LARGE_BUFFER_BYTES`] that a direction of a pipe holds while it moves many
/// bytes. Dropping it gives it back to the pipes of its relay.
struct LargeBuffer {
    bytes: Box<[u8]>,
    pipes: Arc<Pipes>,
}

impl Drop for LargeBuffer {
    fn drop(&mut self) {
        self.pipes.large_held.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Pipes {
    /// The pipes of a relay that holds at most `limit` connections and [`LARGE_BUFFERS`] large
    /// buffers at once.
    pub fn new(limit: usize) -> Arc<Pipes> {
        Pipes::with_large_buffers(limit, LARGE_BUFFERS)
    }

    /// The pipes of a relay that holds at most `limit` connections and `large_limit` large
    /// buffers at once.
    pub fn with_large_buffers(limit: usize, large_limit: usize) -> Arc<Pipes> {
        Arc::new(Pipes {
            limit: AtomicUsize::new(limit),
            large_limit,
            started: Instant::now(),
            open: Mutex::new(BTreeMap::new()),
            next: AtomicU64::new(0),
            large_held: AtomicUsize::new(0),
            ended: Default::default(),
        })
    }

    /// Takes a large buffer, or `None` when the directions of the relay hold `large_limit`.
    fn take_large(self: &Arc<Pipes>) -> Option<LargeBuffer> {
        self.large_held
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                (held < self.large_limit).then_some(held + 1)
            })
            .ok()?;
        Some(LargeBuffer {
            bytes: vec![0; LARGE_BUFFER_BYTES].into_boxed_slice(),
            pipes: self.clone(),
        })
    }

    /// The large buffers the directions of the pipes hold at this moment.
    pub fn large_buffers_held(&self) -> usize {
        self.large_held.load(Ordering::Relaxed)
    }

    fn open(&self) -> MutexGuard<'_, BTreeMap<u64, Arc<PipeTimes>>> {
        // The map holds plain values: a panic of another task leaves it as it was.
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ms_since_start(&self, instant: Instant) -> u64 {
        u64::try_from(instant.saturating_duration_since(self.started).as_millis())
            .unwrap_or(u64::MAX)
    }

    /// Takes a place for one connection, or `None` when the relay holds `limit` connections.
    /// The place is held until it is dropped.
    pub fn admit(self: &Arc<Pipes>) -> Option<Place> {
        let now_ms = self.ms_since_start(Instant::now());
        let times = Arc::new(PipeTimes {
            opened_ms: now_ms,
            moved_ms: AtomicU64::new(now_ms),
        });
        let mut open = self.open();
        if open.len() >= self.limit() {
            return None;
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        open.insert(id, times.clone());
        Some(Place {
            pipes: self.clone(),
            id,
            times,
        })
    }

    /// The most connections the relay holds at once.
    pub fn limit(&self) -> usize {
        self.limit.load(Ordering::Relaxed)
    }

    /// Sets the most connections the relay holds at once. The connections it holds at that
    /// moment stay: a lower limit is reached as they end.
    pub fn set_limit(&self, limit: usize) {
        self.limit.store(limit, Ordering::Relaxed);
    }

    /// The connections the relay holds at this moment.
    pub fn held(&self) -> usize {
        self.open().len()
    }

    /// The age of the connection the relay has held longest, and the longest time one of its
    /// connections has moved no byte, in milliseconds. Both are 0 when the relay holds no
    /// connection.
    pub fn oldest_and_idlest_ms(&self) -> (u64, u64) {
        let now_ms = self.ms_since_start(Instant::now());
        let open = self.open();
        let oldest = open
            .values()
            .next()
            .map_or(0, |times| now_ms.saturating_sub(times.opened_ms));
        let idlest = open
            .values()
            .map(|times| now_ms.saturating_sub(times.moved_ms.load(Ordering::Relaxed)))
            .max()
            .unwrap_or(0);
        (oldest, idlest)
    }

    /// The ended pipes by end: the value of the `cause` label and the count.
    pub fn ended(&self) -> [(&'static str, u64); 4] {
        let mut ends = PipeEnd::ALL.iter().zip(&self.ended);
        std::array::from_fn(|_| {
            ends.next().map_or(("", 0), |(end, count)| {
                (end.label(), count.load(Ordering::Relaxed))
            })
        })
    }
}

/// The place of one connection among the connections a relay holds. Dropping it frees the
/// place.
#[derive(Debug)]
pub struct Place {
    pipes: Arc<Pipes>,
    id: u64,
    times: Arc<PipeTimes>,
}

impl Place {
    /// Records that a byte of the pipe moved at `instant`.
    fn moved(&self, instant: Instant) {
        let moved_ms = self.pipes.ms_since_start(instant);
        self.times.moved_ms.store(moved_ms, Ordering::Relaxed);
    }

    /// Counts the end of the pipe.
    fn ended(&self, end: PipeEnd) {
        // One counter per end, in the order of the ends.
        if let Some(count) = self.pipes.ended.get(end as usize) {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        self.pipes.open().remove(&self.id);
    }
}

/// Where one direction of a pipe stands.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// The direction reads from its source and writes to its sink.
    Moving,
    /// The source reported its end: the direction writes what it still holds and closes the
    /// write side of its sink.
    Ending,
    /// The sink takes no more and the bytes of the source are [`Leftover::Dropped`]: the
    /// direction reads its source and drops the bytes until the source reports its end.
    Dropping,
    /// The direction is over: the write side of the sink is closed, or the sink takes no
    /// more.
    Ended,
}

/// The stream of a direction that failed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Broken {
    /// A read of the source failed.
    Source,
    /// A write to the sink failed, or its flush or the close of its write side.
    Sink,
}

/// One direction of a pipe: its buffers, the bytes it read and has not written yet, and where
/// it stands.
///
/// A direction always has a buffer of [`SMALL_BUFFER_BYTES`]. When that buffer is full to its
/// end, the direction moves many bytes: it takes a buffer of [`LARGE_BUFFER_BYTES`] from the
/// pipes of its relay and goes on in that one, until it has not held [`SMALL_BUFFER_BYTES`] or
/// more at once for [`LARGE_BUFFER_IDLE`], or it has ended. While the relay has no large
/// buffer to give, the direction goes on with the small one.
struct Direction {
    small: Box<[u8]>,
    large: Option<LargeBuffer>,
    /// The bytes the sink has not taken yet: a part of the large buffer when the direction
    /// holds one, of the small buffer otherwise.
    unwritten: Range<usize>,
    stage: Stage,
    /// The source reported the end of its bytes.
    source_over: bool,
    /// The write side of the sink is still to be closed: the sink is the node and is done
    /// with the pipe ([`Direction::sink_done`]).
    close_sink: bool,
    /// The sink did not take the last write that was asked of it.
    blocked: bool,
    /// The sink took bytes that it was not asked to flush yet.
    unflushed: bool,
    /// A byte was read or written, or the direction ended, since the pipe last looked.
    moved: bool,
    /// The direction held [`SMALL_BUFFER_BYTES`] or more at once since the pipe last looked.
    held_much: bool,
    /// When the pipe last saw that.
    held_much_at: Instant,
}

impl Direction {
    fn new(now: Instant) -> Direction {
        Direction {
            small: vec![0; SMALL_BUFFER_BYTES].into_boxed_slice(),
            large: None,
            unwritten: 0..0,
            stage: Stage::Moving,
            source_over: false,
            close_sink: false,
            blocked: false,
            unflushed: false,
            moved: false,
            held_much: false,
            held_much_at: now,
        }
    }

    fn ended(&self) -> bool {
        self.stage == Stage::Ended && !self.close_sink
    }

    /// True once the source reported the end of its bytes.
    fn source_ended(&self) -> bool {
        matches!(self.stage, Stage::Ending | Stage::Ended)
    }

    /// True once the direction moves no further byte to its sink: it has ended, or its sink
    /// closed.
    fn done_moving(&self) -> bool {
        matches!(self.stage, Stage::Dropping | Stage::Ended)
    }

    /// The sink closed: a write to it failed, or its flush or the close of its write side.
    /// The direction drops what it holds for the sink and moves nothing more. What its source
    /// still sends is dealt with as `leftover` says: the direction is over when the source
    /// has reported its end or its bytes stay unread, and reads and drops them otherwise.
    fn sink_closed(&mut self, leftover: Leftover) {
        self.stage = match (self.stage, leftover) {
            (Stage::Moving, Leftover::Dropped) => Stage::Dropping,
            _ => Stage::Ended,
        };
        self.unwritten = 0..0;
        self.large = None;
        self.blocked = false;
        self.unflushed = false;
        self.moved = true;
    }

    /// The sink is the node, and it reported the end of its bytes: it is done with the pipe
    /// and reads on only to learn that nothing more comes. The direction drops what it holds
    /// for the node, moves nothing more, and closes the write side of the node with its next
    /// poll. What its source still sends is dealt with as `leftover` says. A direction that
    /// moves nothing to its sink any more stays as it is.
    fn sink_done(&mut self, leftover: Leftover) {
        if self.done_moving() {
            return;
        }
        self.sink_closed(leftover);
        self.close_sink = true;
    }

    /// Reads `source` and drops the bytes until it is not ready, it reports its end (the
    /// direction is over then) or the direction made [`READS_PER_TURN`] reads (the task is
    /// then woken again at once). The bytes are not counted as moved: a stream cannot keep a
    /// pipe open with bytes that go nowhere.
    fn poll_dropping<R>(&mut self, cx: &mut Context<'_>, source: &mut R) -> Poll<Result<(), Broken>>
    where
        R: AsyncRead + Unpin,
    {
        for _ in 0..READS_PER_TURN {
            let mut read = ReadBuf::new(&mut self.small[..]);
            match Pin::new(&mut *source).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) if read.filled().is_empty() => {
                    self.stage = Stage::Ended;
                    self.source_over = true;
                    self.moved = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(_)) => return Poll::Ready(Err(Broken::Source)),
                Poll::Pending => return Poll::Pending,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// Records at `now` what the direction did since the pipe last looked, and gives the large
    /// buffer back when the direction holds no byte and has not held [`SMALL_BUFFER_BYTES`] or
    /// more at once for [`LARGE_BUFFER_IDLE`]. Returns whether a byte moved or the direction
    /// ended.
    fn settle(&mut self, now: Instant) -> bool {
        if std::mem::take(&mut self.held_much) {
            self.held_much_at = now;
        }
        if self.release_due().is_some_and(|due| now >= due) {
            self.large = None;
        }
        std::mem::take(&mut self.moved)
    }

    /// When the pipe has to look at the direction again to give its large buffer back: `None`
    /// while it holds none, or holds bytes that the sink has not taken.
    fn release_due(&self) -> Option<Instant> {
        (self.large.is_some() && self.unwritten.is_empty())
            .then(|| self.held_much_at + LARGE_BUFFER_IDLE)
    }

    /// Moves bytes from `source` to `sink` until one of them is not ready, the direction has
    /// ended, or it made [`READS_PER_TURN`] reads (the task is then woken again at once). It
    /// reads while its buffer has room, also while the sink takes no byte, and then writes
    /// what it holds, so a sink that is slower than the source gets its bytes in writes of the
    /// size of the buffer. Every call asks the sink again for a write it did not take. A
    /// failure names the stream that failed. A direction whose sink takes no more
    /// ([`Direction::sink_closed`], [`Direction::sink_done`]) asks nothing more of the sink
    /// but the close of its write side when the sink is done.
    fn poll<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        source: &mut R,
        sink: &mut W,
        pipes: &Arc<Pipes>,
    ) -> Poll<Result<(), Broken>>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let sink_failed = |_: io::Error| Broken::Sink;
        if self.close_sink {
            // The node learns from the close of its write side that nothing more comes. A
            // close that fails is the close of a node that is gone.
            let _ = std::task::ready!(Pin::new(&mut *sink).poll_shutdown(cx));
            self.close_sink = false;
        }
        let mut reads = 0;
        let mut sink_waits = false;
        loop {
            match self.stage {
                Stage::Ended => return Poll::Ready(Ok(())),
                Stage::Dropping => return self.poll_dropping(cx, source),
                Stage::Moving | Stage::Ending => {}
            }
            let mut source_waits = false;
            let mut turn_over = false;
            while self.stage == Stage::Moving {
                if self.large.is_none() && self.unwritten.end == SMALL_BUFFER_BYTES {
                    // The small buffer is full to its end: the direction goes on in a large
                    // buffer, with the bytes it holds, when the relay has one to give.
                    if let Some(mut large) = pipes.take_large() {
                        // The bytes the small buffer holds lie in it, and the large buffer
                        // has room for all of them.
                        let held = self.small.get(self.unwritten.clone()).unwrap_or_default();
                        if let Some(room) = large.bytes.get_mut(..held.len()) {
                            room.copy_from_slice(held);
                            self.unwritten = 0..held.len();
                            self.large = Some(large);
                        }
                    }
                }
                let buffer = match &mut self.large {
                    Some(large) => &mut large.bytes[..],
                    None => &mut self.small[..],
                };
                if self.unwritten.end == buffer.len() {
                    break;
                }
                if reads == READS_PER_TURN {
                    turn_over = true;
                    break;
                }
                reads += 1;
                // The buffer has room behind the bytes it holds: the loop ended above when
                // it had none.
                let Some(room) = buffer.get_mut(self.unwritten.end..) else {
                    break;
                };
                let mut read = ReadBuf::new(room);
                match Pin::new(&mut *source).poll_read(cx, &mut read) {
                    Poll::Ready(Ok(())) => match read.filled().len() {
                        0 => {
                            self.stage = Stage::Ending;
                            self.source_over = true;
                        }
                        count => {
                            self.unwritten.end += count;
                            self.held_much |= self.unwritten.len() >= SMALL_BUFFER_BYTES;
                            self.moved = true;
                        }
                    },
                    Poll::Ready(Err(_)) => return Poll::Ready(Err(Broken::Source)),
                    Poll::Pending => {
                        source_waits = true;
                        break;
                    }
                }
            }
            if sink_waits {
                return Poll::Pending;
            }
            while !self.unwritten.is_empty() {
                let buffer = match &self.large {
                    Some(large) => &large.bytes[..],
                    None => &self.small[..],
                };
                // The bytes the sink has not taken lie in the buffer.
                let bytes = buffer.get(self.unwritten.clone()).unwrap_or_default();
                match Pin::new(&mut *sink).poll_write(cx, bytes) {
                    Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => {
                        return Poll::Ready(Err(Broken::Sink));
                    }
                    Poll::Ready(Ok(count)) => {
                        self.unwritten.start += count;
                        self.blocked = false;
                        self.unflushed = true;
                        self.moved = true;
                    }
                    Poll::Pending => {
                        self.blocked = true;
                        sink_waits = true;
                        break;
                    }
                }
            }
            if sink_waits {
                // The sink takes no byte now. The direction reads once more into the room its
                // buffer has left, so the bytes for the next write are there when the sink
                // takes it.
                continue;
            }
            self.unwritten = 0..0;
            if self.stage == Stage::Ending {
                std::task::ready!(Pin::new(&mut *sink).poll_flush(cx)).map_err(sink_failed)?;
                std::task::ready!(Pin::new(&mut *sink).poll_shutdown(cx)).map_err(sink_failed)?;
                self.stage = Stage::Ended;
                self.large = None;
                self.moved = true;
                return Poll::Ready(Ok(()));
            }
            if turn_over {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if source_waits {
                // The source has no byte now: the sink sends on what it took.
                if self.unflushed {
                    std::task::ready!(Pin::new(&mut *sink).poll_flush(cx)).map_err(sink_failed)?;
                    self.unflushed = false;
                }
                return Poll::Pending;
            }
        }
    }
}

/// Moves bytes between `a` and `b` in both directions and returns how the pipe ended. The end
/// is counted in the pipes of `place`, and every byte that moves is recorded there.
///
/// `a` is the stream that asks and `b` the stream that answers: a caller and the node for
/// the inbound relay, the node and a provider for the egress relay (`relay`).
///
/// The end of one direction (its stream reports the end of its bytes) closes the write side of
/// the other stream, and the pipe stays open for the bytes of the other direction.
///
/// The end of the bytes of the node is more than the end of a direction: the node is done
/// with the connection and keeps it open only until its peer ended too. The pipe closes the
/// write side of its connection to the node at once, without the bytes it still held for
/// the node, and moves nothing more to it.
///
/// - The inbound relay moves the last bytes of the node, its answer, to the caller, and
///   reads and drops what the caller still sends until the caller reports its end.
/// - The egress relay moves the last bytes of the node to the provider and ends: nobody
///   waits for what the provider still sends.
///
/// A write to a stream that fails is the close of that stream.
///
/// - When `b` closed, the direction that writes to it moves nothing more, and the pipe stays
///   open for the answer: the other direction goes on until it has moved what `b` sent last
///   and its end. What `a` sends from then on has nowhere to go: the inbound relay reads it
///   and drops it, and the egress relay leaves it unread.
/// - When `a` closed, nobody waits for an answer. The pipe reads once more what `a` sent last
///   and its end, and ends.
///
/// The pipe ends
///
/// - when both directions have ended, when a write to `a` fails after `a` reported the end of
///   its bytes, and when the node of the egress relay reported the end of its bytes and the
///   last of them are with the provider ([`PipeEnd::Closed`]);
/// - when a read of a stream fails, or a write to `a` before it reported the end of its bytes
///   ([`PipeEnd::Failed`]);
/// - when no byte moved for [`PIPE_IDLE_LIMIT`] while both directions were open
///   ([`PipeEnd::Idle`]);
/// - when no byte moved for [`PIPE_HALF_CLOSED_LIMIT`] since a stream reported the end of
///   its bytes, `b` closed or the node reported the end of its bytes
///   ([`PipeEnd::HalfClosed`]). The limit holds from the moment a stream reported its end,
///   also while the other stream has not taken the bytes that were sent in front of that
///   end: a stream that takes no byte of them for the limit is not reading, and the stream
///   that sent them sends nothing more. A byte the pipe drops is not a byte that moved.
///
/// A write that a stream does not take is asked of it again every [`BLOCKED_WRITE_RETRY`], and
/// at once when the other direction ends: a pipe does not rely on the stream to report that it
/// takes bytes again or that it failed. The two limits are measured by the clock of the
/// runtime, so no state of the two streams keeps a pipe open beyond them.
pub async fn pipe<A, B>(mut a: A, mut b: B, place: &Place, relay: Relay) -> PipeEnd
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let pipes = &place.pipes;
    let leftover_of_a = match relay {
        Relay::Inbound => Leftover::Dropped,
        Relay::Egress => Leftover::Unread,
    };
    let mut moved_at = Instant::now();
    let mut a_to_b = Direction::new(moved_at);
    let mut b_to_a = Direction::new(moved_at);
    let timer = tokio::time::sleep_until(moved_at + PIPE_IDLE_LIMIT);
    tokio::pin!(timer);
    let end = poll_fn(|cx| loop {
        let done_before = u8::from(a_to_b.done_moving()) + u8::from(b_to_a.done_moving());
        match a_to_b.poll(cx, &mut a, &mut b, pipes) {
            Poll::Ready(Err(Broken::Source)) => return Poll::Ready(PipeEnd::Failed),
            // `b` closed: the pipe stays open for what it sent last.
            Poll::Ready(Err(Broken::Sink)) => a_to_b.sink_closed(leftover_of_a),
            Poll::Ready(Ok(())) | Poll::Pending => {}
        }
        match b_to_a.poll(cx, &mut b, &mut a, pipes) {
            Poll::Ready(Err(Broken::Source)) => return Poll::Ready(PipeEnd::Failed),
            Poll::Ready(Err(Broken::Sink)) => {
                // `a` closed: nobody waits for an answer. The direction that reads from `a`
                // is asked once more for what `a` sent last and for its end.
                let _ = a_to_b.poll(cx, &mut a, &mut b, pipes);
                return Poll::Ready(match a_to_b.source_ended() {
                    true => PipeEnd::Closed,
                    false => PipeEnd::Failed,
                });
            }
            Poll::Ready(Ok(())) | Poll::Pending => {}
        }
        match relay {
            // The node answers. Once it reported the end of its bytes, the pipe closes the
            // write side of the node and drops what the caller still sends.
            Relay::Inbound if b_to_a.source_over => a_to_b.sink_done(leftover_of_a),
            // The node asks. Once it reported the end of its bytes, the pipe closes the
            // write side of the node and leaves what the provider still sends unread, and
            // it ends when the last bytes of the node are with the provider.
            Relay::Egress if a_to_b.source_over => {
                if a_to_b.ended() {
                    return Poll::Ready(PipeEnd::Closed);
                }
                b_to_a.sink_done(Leftover::Unread);
            }
            Relay::Inbound | Relay::Egress => {}
        }
        if a_to_b.ended() && b_to_a.ended() {
            return Poll::Ready(PipeEnd::Closed);
        }
        let now = Instant::now();
        // Both directions are settled: `|` does not skip the second.
        if a_to_b.settle(now) | b_to_a.settle(now) {
            moved_at = now;
            place.moved(now);
        }
        let done = u8::from(a_to_b.done_moving()) + u8::from(b_to_a.done_moving());
        if done > done_before {
            // A direction ended, `b` closed or the node is done in this turn. The pipe looks
            // at both directions again at once: the write of the other direction that its
            // stream did not take is asked of it again, the direction that reads from `b`
            // moves what `b` sent last, the write side of a node that is done is closed, and
            // a direction that drops the bytes of `a` from now on begins to read them.
            continue;
        }
        // A stream that reported the end of its bytes sends nothing more: from then on the
        // other stream has the half-closed limit to take what was sent in front of that end.
        let half_closed = done > 0 || a_to_b.source_over || b_to_a.source_over;
        let (limit, end) = match half_closed {
            false => (PIPE_IDLE_LIMIT, PipeEnd::Idle),
            true => (PIPE_HALF_CLOSED_LIMIT, PipeEnd::HalfClosed),
        };
        let deadline = moved_at + limit;
        if now >= deadline {
            return Poll::Ready(end);
        }
        // The pipe looks again at its limit, when a write that was not taken is due again,
        // and when a direction is due to give its large buffer back.
        let mut wake_at = deadline;
        if a_to_b.blocked || b_to_a.blocked {
            wake_at = wake_at.min(now + BLOCKED_WRITE_RETRY);
        }
        for due in [a_to_b.release_due(), b_to_a.release_due()]
            .into_iter()
            .flatten()
        {
            wake_at = wake_at.min(due);
        }
        // The timer is set again only when it has to fire earlier than it would, or after it
        // fired: a pipe that moves bytes does not set it for every byte.
        if timer.is_elapsed() || wake_at < timer.deadline() {
            timer.as_mut().reset(wake_at);
        }
        if timer.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
    })
    .await;
    place.ended(end);
    end
}

/// Pauses after a failed accept of the class `failure` when that class asks for one: a
/// persistent failure does not spin, and a connection that was gone before accept returned it
/// costs no wait.
pub async fn pause_after_failed_accept(failure: AcceptFailure) {
    if failure != AcceptFailure::Aborted {
        tokio::time::sleep(ACCEPT_RETRY_PAUSE).await;
    }
}

/// The counts of the inbound relay since the host program started, and the connections it
/// holds. The relay writes them and the status surface reads them for `/metrics` (enclave.md
/// section 9).
#[derive(Debug)]
pub struct InboundCounters {
    /// Connections of callers for which the connection to the node could not be opened.
    node_connect_failures: AtomicU64,
    /// Connections of callers closed without a byte because the relay held its limit.
    refused: AtomicU64,
    /// The connections of callers the relay holds, at most [`INBOUND_PIPES`].
    pipes: Arc<Pipes>,
}

impl Default for InboundCounters {
    fn default() -> InboundCounters {
        InboundCounters::holding(INBOUND_PIPES)
    }
}

impl InboundCounters {
    /// The counts of a relay that holds at most `limit` connections of callers at once.
    pub fn holding(limit: usize) -> InboundCounters {
        InboundCounters {
            node_connect_failures: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            pipes: Pipes::new(limit),
        }
    }

    /// The connections of callers for which the vsock connection to the node failed or did not
    /// open within its time limit: the value of
    /// `credential_enclave_host_inbound_node_connect_failures_total`.
    pub fn node_connect_failures(&self) -> u64 {
        self.node_connect_failures.load(Ordering::Relaxed)
    }

    /// The connections of callers the relay closed without a byte because it held its limit:
    /// the value of `credential_enclave_host_inbound_refused_total`.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// The connections of callers the relay holds, and how its pipes ended.
    pub fn pipes(&self) -> &Pipes {
        &self.pipes
    }
}

/// The door of an inbound relay, open until the shutdown of the pod closes it: the half the
/// shutdown holds, and the half the relay holds ([`serve`]).
///
/// An enclave that is ending answers nothing, so a connection the relay took then would end
/// without a response, and its caller could not tell whether the node had acted on its
/// request. A connection the kernel refuses did not open, and its caller takes any call to
/// another node. So the relay stops taking connections before the enclave ends, and the
/// shutdown waits for the connections it holds (`crate::calls`).
pub fn inbound_door() -> (InboundDoor, DoorOrder) {
    let (order, told) = watch::channel(false);
    (InboundDoor(order), DoorOrder(told))
}

/// The half of the door of an inbound relay that the shutdown holds ([`inbound_door`]).
#[derive(Debug)]
pub struct InboundDoor(watch::Sender<bool>);

impl InboundDoor {
    /// Tells the relay to take no further connection, and resolves when the relay has closed
    /// its listener: the connections it holds then ([`Pipes::held`]) are all the connections
    /// of callers it will ever hold. It resolves at once when the door is closed already, and
    /// when no relay holds the other half. True when this call is the one that closed the
    /// door.
    pub async fn close(&self) -> bool {
        let closed_before = self.0.send_replace(true);
        // The relay drops its half after it closed its listener.
        self.0.closed().await;
        !closed_before
    }
}

/// The half of the door of an inbound relay that the relay holds ([`inbound_door`]).
#[derive(Debug)]
pub struct DoorOrder(watch::Receiver<bool>);

impl DoorOrder {
    /// Resolves when the shutdown closes the door. It does not resolve when the other half is
    /// gone without having closed it: a relay whose door nobody holds stays open.
    pub(crate) async fn told_to_close(&mut self) {
        if self.0.wait_for(|close| *close).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// The inbound relay: pipes every connection of `listener` to a new connection to the node. It
/// holds at most the connections of its counts at once: a connection accepted while it holds
/// that many is closed without a byte and counted, as the node does with a connection above
/// its own limit. A connection whose node connection cannot be opened is closed and counted.
///
/// What a caller still sends after the node answered and was done with its connection is
/// read and dropped ([`Relay::Inbound`]): the node answers some calls before it has read
/// their body (a call it refuses because it is closing, a body above a limit, a path it does
/// not have), and the caller of such a call gets the answer whole, whenever the rest of its
/// request arrives.
///
/// The relay returns when the shutdown closes `door`: it takes the connections that wait in
/// the queue of the listener, closes the listener, and drops its half of the door
/// ([`close_listener`]). The pipes it started go on until they end.
pub async fn serve(
    listener: TcpListener,
    node: Arc<dyn NodeConnector>,
    counters: Arc<InboundCounters>,
    mut door: DoorOrder,
) {
    loop {
        let accepted = tokio::select! {
            biased;
            () = door.told_to_close() => break,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((caller, _)) => take(caller, &node, &counters),
            Err(error) => pause_after_failed_accept(AcceptFailure::of(&error)).await,
        }
    }
    close_listener(listener, &node, &counters);
}

/// Takes one connection of a caller: a place of the relay and a pipe to a new connection to
/// the node, on a task of its own.
fn take(caller: TcpStream, node: &Arc<dyn NodeConnector>, counters: &Arc<InboundCounters>) {
    let Some(place) = counters.pipes.admit() else {
        counters.refused.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let _ = caller.set_nodelay(true);
    let node = node.clone();
    let counters = counters.clone();
    tokio::spawn(async move {
        match node.connect().await {
            Ok(stream) => {
                pipe(caller, stream, &place, Relay::Inbound).await;
            }
            Err(_) => {
                counters
                    .node_connect_failures
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    });
}

/// Closes the listener of the inbound relay. The kernel resets every connection that waits in
/// the queue of a listener when the listener is closed, and the caller of such a connection
/// reads a connection that opened and ended without a response. So the relay first takes the
/// connections of the queue, as it took every connection before, and closes the listener when
/// an accept finds none: the node behind them is alive (the shutdown ends the enclave only
/// after the relay holds no connection, `crate::calls`). A connection whose handshake the
/// kernel completes between that accept and the close is still reset: nothing a program can
/// call closes that gap, which is the time between two system calls.
fn close_listener(
    listener: TcpListener,
    node: &Arc<dyn NodeConnector>,
    counters: &Arc<InboundCounters>,
) {
    // The listener leaves the runtime: an accept on it from here on answers at once, with a
    // connection of the queue or with the answer that the queue holds none. A listener that
    // does not leave the runtime is closed as it is.
    let Ok(listener) = listener.into_std() else {
        return;
    };
    // The queue holds at most the connections the listener was opened for.
    for _ in 0..INBOUND_LISTEN_BACKLOG {
        match listener.accept() {
            Ok((caller, _)) => {
                // An accepted connection does not take the mode of its listener on Linux.
                if caller.set_nonblocking(true).is_ok() {
                    if let Ok(caller) = TcpStream::from_std(caller) {
                        take(caller, node, counters);
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            // The connection was gone before accept returned it: the next one is asked for.
            Err(error) if AcceptFailure::of(&error) == AcceptFailure::Aborted => {}
            Err(_) => break,
        }
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
        relay_holding(node, INBOUND_PIPES).await
    }

    /// An inbound relay that holds at most `limit` connections of callers at once. Nobody
    /// holds the other half of its door: it stays open.
    async fn relay_holding(node: EchoNode, limit: usize) -> (SocketAddr, Arc<InboundCounters>) {
        let listener =
            listen_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), LISTEN_BACKLOG).unwrap();
        let address = listener.local_addr().unwrap();
        let counters = Arc::new(InboundCounters::holding(limit));
        let (_, door) = inbound_door();
        tokio::spawn(serve(listener, Arc::new(node), counters.clone(), door));
        (address, counters)
    }

    /// An inbound relay in front of a node that echoes, and the half of its door that the
    /// shutdown holds.
    async fn relay_with_door() -> (SocketAddr, Arc<InboundCounters>, InboundDoor) {
        let listener =
            listen_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), LISTEN_BACKLOG).unwrap();
        let address = listener.local_addr().unwrap();
        let counters = Arc::new(InboundCounters::default());
        let (door, order) = inbound_door();
        tokio::spawn(serve(
            listener,
            Arc::new(EchoNode { reachable: true }),
            counters.clone(),
            order,
        ));
        (address, counters, door)
    }

    /// Runs a pipe of the egress relay between the node `a` and the provider `b` as its own
    /// task, with a place among `pipes`.
    fn piped<A, B>(a: A, b: B, pipes: &Arc<Pipes>) -> tokio::task::JoinHandle<PipeEnd>
    where
        A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        piped_with(a, b, pipes, Relay::Egress)
    }

    /// Runs a pipe of `relay` between `a`, which asks, and `b`, which answers, as its own
    /// task, with a place among `pipes`.
    fn piped_with<A, B>(
        a: A,
        b: B,
        pipes: &Arc<Pipes>,
        relay: Relay,
    ) -> tokio::task::JoinHandle<PipeEnd>
    where
        A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let place = pipes.admit().unwrap();
        tokio::spawn(async move { pipe(a, b, &place, relay).await })
    }

    /// The ended pipes of `pipes` in the order closed, failed, idle, half closed.
    fn ended(pipes: &Pipes) -> [u64; 4] {
        pipes.ended().map(|(_, count)| count)
    }

    /// Lets the tasks that are ready run, without moving the clock.
    async fn settle() {
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
    }

    /// A stream stand-in for a socket whose peer takes no byte and whose kernel reports
    /// nothing to a writer: a write that waits for the stream is never woken. A read gives the
    /// bytes the peer sent and then waits, until the peer closes. The stream also has the
    /// write that returns at once (`io::Write`), which fails with a broken pipe once the peer
    /// is gone, as a write of the kernel to a peer that closed does.
    #[derive(Clone, Default)]
    struct Silent(Arc<Mutex<SilentPeer>>);

    #[derive(Default)]
    struct SilentPeer {
        /// Bytes the peer sent and the stream has not read yet.
        sent: Vec<u8>,
        /// The peer ended its direction: a read gives the end after `sent`.
        ended: bool,
        /// The peer is gone: an attempted write fails.
        gone: bool,
        /// The peer takes every byte of an attempted write.
        takes: bool,
        /// Bytes the peer took.
        taken: Vec<u8>,
        /// Writes that were asked of the stream, attempted or not.
        writes_asked: u64,
        /// The task that waits for a read.
        reader: Option<std::task::Waker>,
    }

    impl Silent {
        fn peer(&self) -> MutexGuard<'_, SilentPeer> {
            self.0.lock().unwrap()
        }

        /// The peer writes `bytes`, ends its direction and closes: what a peer does that
        /// writes a last message and closes its socket.
        fn close_after(&self, bytes: &[u8]) {
            let mut peer = self.peer();
            peer.sent.extend_from_slice(bytes);
            peer.ended = true;
            peer.gone = true;
            if let Some(reader) = peer.reader.take() {
                reader.wake();
            }
        }
    }

    impl AsyncRead for Silent {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut peer = self.peer();
            if !peer.sent.is_empty() {
                let count = peer.sent.len().min(buffer.remaining());
                buffer.put_slice(&peer.sent[..count]);
                peer.sent.drain(..count);
                return Poll::Ready(Ok(()));
            }
            if peer.ended {
                return Poll::Ready(Ok(()));
            }
            peer.reader = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    impl AsyncWrite for Silent {
        /// The write that waits for the stream: nothing ever wakes it.
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.peer().writes_asked += 1;
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl io::Write for Silent {
        /// The write that returns at once.
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut peer = self.peer();
            if peer.gone {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            if !peer.takes {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            peer.taken.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_pipe_moves_bytes_in_both_directions_and_carries_the_end_of_a_direction() {
        let pipes = Pipes::new(8);
        let (mut left, left_inner) = tokio::io::duplex(64);
        let (right_inner, mut right) = tokio::io::duplex(64);
        // A caller on the left, the node on the right.
        let piped = piped_with(left_inner, right_inner, &pipes, Relay::Inbound);

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
        assert_eq!(pipes.held(), 1);
        assert_eq!(ended(&pipes), [0, 0, 0, 0]);

        // The end of the second direction ends the pipe, and the pipe is counted as closed.
        right.shutdown().await.unwrap();
        assert_eq!(left.read(&mut [0u8; 8]).await.unwrap(), 0);
        assert_eq!(piped.await.unwrap(), PipeEnd::Closed);
        assert_eq!(pipes.held(), 0);
        assert_eq!(ended(&pipes), [1, 0, 0, 0]);
    }

    #[tokio::test]
    async fn a_pipe_carries_more_bytes_than_its_buffers_hold() {
        let pipes = Pipes::new(8);
        let (mut left, left_inner) = tokio::io::duplex(1024);
        let (right_inner, mut right) = tokio::io::duplex(1024);
        let piped = piped(left_inner, right_inner, &pipes);

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
        let mut left = writer.await.unwrap();
        right.shutdown().await.unwrap();
        assert_eq!(left.read(&mut [0u8; 8]).await.unwrap(), 0);
        assert_eq!(piped.await.unwrap(), PipeEnd::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn a_pipe_that_moves_no_byte_for_the_idle_limit_ends() {
        let pipes = Pipes::new(8);
        let (mut left, left_inner) = tokio::io::duplex(64);
        let (right_inner, mut right) = tokio::io::duplex(64);
        let started = Instant::now();
        let piped = piped(left_inner, right_inner, &pipes);

        // A byte after 800 seconds: the limit counts from that byte.
        tokio::time::sleep(Duration::from_secs(800)).await;
        left.write_all(b"x").await.unwrap();
        assert_eq!(right.read(&mut [0u8; 8]).await.unwrap(), 1);
        let moved = Instant::now();

        // Both ends stay open and silent: the pipe ends at the limit and closes both.
        assert_eq!(piped.await.unwrap(), PipeEnd::Idle);
        assert_eq!(moved.elapsed(), PIPE_IDLE_LIMIT);
        assert_eq!(
            started.elapsed(),
            Duration::from_secs(800) + PIPE_IDLE_LIMIT
        );
        assert_eq!(left.read(&mut [0u8; 8]).await.unwrap(), 0);
        assert_eq!(right.read(&mut [0u8; 8]).await.unwrap(), 0);
        assert_eq!(pipes.held(), 0);
        assert_eq!(ended(&pipes), [0, 0, 1, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_pipe_that_is_used_again_before_the_idle_limit_stays_open() {
        let pipes = Pipes::new(8);
        let (mut left, left_inner) = tokio::io::duplex(64);
        let (right_inner, mut right) = tokio::io::duplex(64);
        let started = Instant::now();
        let piped = piped(left_inner, right_inner, &pipes);

        // Four exchanges, each after a silence one second short of the limit.
        let mut buffer = [0u8; 8];
        for _ in 0..4 {
            tokio::time::sleep(PIPE_IDLE_LIMIT - Duration::from_secs(1)).await;
            left.write_all(b"request").await.unwrap();
            right.read_exact(&mut buffer[..7]).await.unwrap();
            assert_eq!(&buffer[..7], b"request");
            right.write_all(b"response").await.unwrap();
            left.read_exact(&mut buffer).await.unwrap();
            assert_eq!(&buffer, b"response");
        }
        assert!(started.elapsed() > 3 * PIPE_IDLE_LIMIT);
        assert_eq!(pipes.held(), 1);

        left.shutdown().await.unwrap();
        right.shutdown().await.unwrap();
        assert_eq!(piped.await.unwrap(), PipeEnd::Closed);
        assert_eq!(ended(&pipes), [1, 0, 0, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_transfer_that_lasts_longer_than_the_limits_is_carried_in_both_directions() {
        const BYTES: usize = 600_000;
        const CHUNK: usize = 4096;
        let pipes = Pipes::new(8);
        let (left, left_inner) = tokio::io::duplex(1024);
        let (right_inner, right) = tokio::io::duplex(1024);
        let started = Instant::now();
        // A caller on the left, the node on the right.
        let piped = piped_with(left_inner, right_inner, &pipes, Relay::Inbound);

        // Each end sends its bytes at once and reads the bytes of the other end slowly: one
        // chunk every 10 seconds, so both directions move bytes for 1,470 seconds. The
        // caller ends its direction when it has sent its bytes. The node ends its own when
        // it has read the end of the caller: a node that ends its direction is done.
        async fn exchange(end: tokio::io::DuplexStream, seed: u32, node: bool) -> Vec<u8> {
            let (mut reader, mut writer) = tokio::io::split(end);
            let sending = tokio::spawn(async move {
                let sent: Vec<u8> = (0..BYTES as u32)
                    .map(|index| ((index + seed) % 251) as u8)
                    .collect();
                writer.write_all(&sent).await.unwrap();
                if !node {
                    writer.shutdown().await.unwrap();
                }
                writer
            });
            let mut received = Vec::new();
            let mut chunk = [0u8; CHUNK];
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let mut filled = 0;
                while filled < CHUNK {
                    match reader.read(&mut chunk[filled..]).await.unwrap() {
                        0 => break,
                        count => filled += count,
                    }
                }
                received.extend_from_slice(&chunk[..filled]);
                if filled < CHUNK {
                    break;
                }
            }
            let mut writer = sending.await.unwrap();
            if node {
                writer.shutdown().await.unwrap();
            }
            received
        }
        let left_side = tokio::spawn(exchange(left, 0, false));
        let right_side = tokio::spawn(exchange(right, 7, true));
        let from_right = left_side.await.unwrap();
        let from_left = right_side.await.unwrap();

        let expected = |seed: u32| -> Vec<u8> {
            (0..BYTES as u32)
                .map(|index| ((index + seed) % 251) as u8)
                .collect()
        };
        assert_eq!(from_left, expected(0));
        assert_eq!(from_right, expected(7));
        assert!(started.elapsed() > PIPE_IDLE_LIMIT + PIPE_HALF_CLOSED_LIMIT);
        assert_eq!(piped.await.unwrap(), PipeEnd::Closed);
        assert_eq!(ended(&pipes), [1, 0, 0, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_half_closed_pipe_stays_open_while_its_other_direction_moves_bytes() {
        let pipes = Pipes::new(8);
        let (mut left, left_inner) = tokio::io::duplex(64);
        let (right_inner, mut right) = tokio::io::duplex(64);
        // A caller on the left, the node on the right.
        let piped = piped_with(left_inner, right_inner, &pipes, Relay::Inbound);

        // The left side sends its request and ends its direction; the right side answers in
        // parts, each one second before the half-closed limit would end the pipe.
        left.write_all(b"request").await.unwrap();
        left.shutdown().await.unwrap();
        let mut buffer = [0u8; 8];
        right.read_exact(&mut buffer[..7]).await.unwrap();
        assert_eq!(right.read(&mut buffer).await.unwrap(), 0);
        let half_closed = Instant::now();
        for _ in 0..5 {
            tokio::time::sleep(PIPE_HALF_CLOSED_LIMIT - Duration::from_secs(1)).await;
            right.write_all(b"part").await.unwrap();
            left.read_exact(&mut buffer[..4]).await.unwrap();
            assert_eq!(&buffer[..4], b"part");
        }
        assert!(half_closed.elapsed() > 4 * PIPE_HALF_CLOSED_LIMIT);
        assert_eq!(pipes.held(), 1);

        // The right side ends its direction too: an orderly end.
        right.shutdown().await.unwrap();
        assert_eq!(left.read(&mut buffer).await.unwrap(), 0);
        assert_eq!(piped.await.unwrap(), PipeEnd::Closed);
        assert_eq!(ended(&pipes), [1, 0, 0, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_half_closed_pipe_ends_when_its_other_direction_moves_no_byte_for_the_limit() {
        let pipes = Pipes::new(8);
        let (mut left, left_inner) = tokio::io::duplex(64);
        let (right_inner, mut right) = tokio::io::duplex(64);
        // A caller on the left, the node on the right.
        let piped = piped_with(left_inner, right_inner, &pipes, Relay::Inbound);

        // The left side ends its direction after 100 seconds. The right side reads the end,
        // answers once 20 seconds later and then neither writes nor closes.
        tokio::time::sleep(Duration::from_secs(100)).await;
        left.shutdown().await.unwrap();
        let mut buffer = [0u8; 8];
        assert_eq!(right.read(&mut buffer).await.unwrap(), 0);
        tokio::time::sleep(Duration::from_secs(20)).await;
        right.write_all(b"late").await.unwrap();
        left.read_exact(&mut buffer[..4]).await.unwrap();
        let moved = Instant::now();

        // The limit counts from the last byte: the pipe ends and closes both sides.
        assert_eq!(piped.await.unwrap(), PipeEnd::HalfClosed);
        assert_eq!(moved.elapsed(), PIPE_HALF_CLOSED_LIMIT);
        assert_eq!(left.read(&mut buffer).await.unwrap(), 0);
        assert_eq!(pipes.held(), 0);
        assert_eq!(ended(&pipes), [0, 0, 0, 1]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_that_is_not_taken_is_attempted_again_every_second_without_an_event() {
        let pipes = Pipes::new(8);
        let silent = Silent::default();
        let (right_inner, mut right) = tokio::io::duplex(64);
        let piped = piped(Attempting(silent.clone()), right_inner, &pipes);

        // The right side sends bytes for a peer that takes none and reports nothing: the pipe
        // attempts the write when it gets the bytes and once every second after that.
        right.write_all(b"for the silent peer").await.unwrap();
        settle().await;
        let attempts_at_once = silent.peer().writes_asked;
        assert!(attempts_at_once >= 1);
        tokio::time::sleep(BLOCKED_WRITE_RETRY * 10 + Duration::from_millis(500)).await;
        assert_eq!(silent.peer().writes_asked, attempts_at_once + 10);
        assert!(!piped.is_finished());

        // The peer starts to take bytes, still without an event: the next attempt, within a
        // second, moves them.
        silent.peer().takes = true;
        tokio::time::sleep(BLOCKED_WRITE_RETRY).await;
        assert_eq!(silent.peer().taken, b"for the silent peer");
        assert!(!piped.is_finished());
        assert_eq!(pipes.held(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_to_a_peer_that_closed_fails_within_a_second_without_an_event() {
        let pipes = Pipes::new(8);
        let silent = Silent::default();
        let (right_inner, mut right) = tokio::io::duplex(64);
        let piped = piped(Attempting(silent.clone()), right_inner, &pipes);

        right.write_all(b"for the silent peer").await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert!(!piped.is_finished());

        // The peer closes and nothing reports it: no task of the pipe is woken, neither the
        // one that reads nor the one that writes. The next attempt of the write fails: the
        // stream closed. The pipe then reads the end of the stream and ends, as closed.
        {
            let mut peer = silent.peer();
            peer.ended = true;
            peer.gone = true;
        }
        let gone = Instant::now();
        assert_eq!(piped.await.unwrap(), PipeEnd::Closed);
        assert!(gone.elapsed() <= BLOCKED_WRITE_RETRY);
        assert_eq!(right.read(&mut [0u8; 8]).await.unwrap(), 0);
        assert_eq!(pipes.held(), 0);
        assert_eq!(ended(&pipes), [1, 0, 0, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_to_the_side_that_asks_fails_and_ends_the_pipe_within_a_second() {
        let pipes = Pipes::new(8);
        let silent = Silent::default();
        let (right_inner, mut right) = tokio::io::duplex(64);
        let piped = piped(Attempting(silent.clone()), right_inner, &pipes);

        right.write_all(b"for the silent peer").await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert!(!piped.is_finished());

        // The side that asks goes away and nothing reports it: no end of its bytes, no event
        // for the writer. The next attempt of the write fails and ends the pipe, as failed:
        // the stream had not reported the end of its bytes, and nobody waits for an answer.
        silent.peer().gone = true;
        let gone = Instant::now();
        assert_eq!(piped.await.unwrap(), PipeEnd::Failed);
        assert!(gone.elapsed() <= BLOCKED_WRITE_RETRY);
        assert_eq!(right.read(&mut [0u8; 8]).await.unwrap(), 0);
        assert_eq!(pipes.held(), 0);
        assert_eq!(ended(&pipes), [0, 1, 0, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_side_that_answers_fails_a_write_and_reports_no_end_is_cut_at_the_half_closed_limit()
    {
        let pipes = Pipes::new(8);
        let silent = Silent::default();
        let (mut left, left_inner) = tokio::io::duplex(64);
        let piped = piped(left_inner, Attempting(silent.clone()), &pipes);

        left.write_all(b"for the silent peer").await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert!(!piped.is_finished());

        // The side that answers takes no write any more and never reports the end of its
        // own bytes. The failed write is its close: the pipe waits for what it sent last, for
        // the half-closed limit and no longer.
        silent.peer().gone = true;
        let gone = Instant::now();
        assert_eq!(piped.await.unwrap(), PipeEnd::HalfClosed);
        assert!(gone.elapsed() >= PIPE_HALF_CLOSED_LIMIT);
        assert!(gone.elapsed() <= PIPE_HALF_CLOSED_LIMIT + BLOCKED_WRITE_RETRY);
        assert_eq!(left.read(&mut [0u8; 8]).await.unwrap(), 0);
        assert_eq!(pipes.held(), 0);
        assert_eq!(ended(&pipes), [0, 0, 0, 1]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_caller_that_is_gone_ends_the_pipe_at_once_also_while_the_node_takes_no_byte() {
        let pipes = Pipes::new(8);
        // The node sent an answer of more bytes than the caller, which reads nothing, has
        // room for, and takes no byte itself.
        let silent = Silent::default();
        silent.peer().sent = vec![3u8; 100_000];
        let (mut caller, caller_inner) = tokio::io::duplex(1024);
        let piped = piped_with(
            caller_inner,
            Attempting(silent.clone()),
            &pipes,
            Relay::Inbound,
        );

        // The caller sends more than the pipe can hand to the node: both directions wait,
        // each with bytes its stream does not take.
        let sending = tokio::spawn(async move {
            let _ = caller.write_all(&[5u8; 200_000]).await;
        });
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!piped.is_finished());

        // The caller goes away. The write of the answer to it fails, and the pipe ends at
        // once: it does not wait for the node, which would go on holding its connection, or
        // for a limit.
        sending.abort();
        let gone = Instant::now();
        assert_eq!(piped.await.unwrap(), PipeEnd::Failed);
        assert_eq!(gone.elapsed(), Duration::ZERO);
        assert_eq!(pipes.held(), 0);
        assert_eq!(ended(&pipes), [0, 1, 0, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_caller_that_ended_behind_bytes_the_node_does_not_take_is_cut_at_the_half_closed_limit(
    ) {
        let pipes = Pipes::new(8);
        // The node takes no byte and sends none: a call that waits for its place.
        let silent = Silent::default();
        let (mut caller, caller_inner) = tokio::io::duplex(8192);
        let piped = piped_with(
            caller_inner,
            Attempting(silent.clone()),
            &pipes,
            Relay::Inbound,
        );

        // Fewer bytes than the buffer of the direction holds, and the end of the caller: the
        // pipe reads both, and the node takes none of the bytes. The caller sends nothing
        // more, so the node has the half-closed limit to take a byte, and not the idle
        // limit of a pipe whose two streams may still send.
        caller.write_all(&[5u8; 3_000]).await.unwrap();
        caller.shutdown().await.unwrap();
        let ended_at = Instant::now();
        assert_eq!(piped.await.unwrap(), PipeEnd::HalfClosed);
        assert_eq!(ended_at.elapsed(), PIPE_HALF_CLOSED_LIMIT);
        assert_eq!(ended(&pipes), [0, 0, 0, 1]);
        assert_eq!(silent.peer().taken, b"");
    }

    #[tokio::test(start_paused = true)]
    async fn the_end_of_a_caller_is_carried_to_a_node_that_takes_its_bytes() {
        let pipes = Pipes::new(8);
        // The node takes every byte: the pipe holds none it did not take, and the end of
        // the caller reaches the node behind the bytes, as the end of a direction. The pipe
        // stays open for the answer of the node.
        let silent = Silent::default();
        silent.peer().takes = true;
        let (mut caller, caller_inner) = tokio::io::duplex(8192);
        let piped = piped_with(
            caller_inner,
            Attempting(silent.clone()),
            &pipes,
            Relay::Inbound,
        );
        caller.write_all(&[5u8; 3_000]).await.unwrap();
        caller.shutdown().await.unwrap();
        settle().await;
        assert!(!piped.is_finished());
        assert_eq!(silent.peer().taken.len(), 3_000);
        // The node says nothing: the pipe ends at the half-closed limit.
        assert_eq!(piped.await.unwrap(), PipeEnd::HalfClosed);
    }

    #[tokio::test(start_paused = true)]
    async fn a_caller_that_is_still_sending_reads_the_whole_answer_of_a_peer_that_closed() {
        // An answer of more bytes than one turn of a direction moves.
        const ANSWER: usize = 3_000_000;
        const LATE: usize = 500_000;
        let pipes = Pipes::new(8);
        let (caller, caller_inner) = tokio::io::duplex(1024);
        let (node_inner, mut node) = tokio::io::duplex(ANSWER + 1024);
        let piped = piped_with(caller_inner, node_inner, &pipes, Relay::Inbound);
        let (mut caller_reader, mut caller_writer) = tokio::io::split(caller);

        // The caller sends the head of its request. The node reads it, answers before the
        // rest of the request arrived, and closes its connection.
        caller_writer.write_all(b"head").await.unwrap();
        let mut head = [0u8; 4];
        node.read_exact(&mut head).await.unwrap();
        let answer: Vec<u8> = (0..ANSWER).map(|index| (index % 241) as u8).collect();
        node.write_all(&answer).await.unwrap();
        drop(node);
        settle().await;

        // The rest of the request arrives while most of the answer is still on its way: the
        // caller has read none of it. The pipe drops those bytes and goes on with the answer.
        let sending = tokio::spawn(async move {
            caller_writer.write_all(&vec![7u8; LATE]).await.unwrap();
            caller_writer
        });
        let mut received = vec![0u8; ANSWER];
        caller_reader.read_exact(&mut received).await.unwrap();
        assert!(received == answer, "the answer arrived changed");
        assert_eq!(caller_reader.read(&mut [0u8; 8]).await.unwrap(), 0);
        let mut caller_writer = sending.await.unwrap();

        // The pipe stays open for the caller, which closes first: nothing cuts it off.
        settle().await;
        assert!(!piped.is_finished());
        assert_eq!(pipes.held(), 1);
        caller_writer.shutdown().await.unwrap();
        assert_eq!(piped.await.unwrap(), PipeEnd::Closed);
        assert_eq!(ended(&pipes), [1, 0, 0, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_caller_that_keeps_sending_to_a_peer_that_closed_is_cut_at_the_half_closed_limit() {
        let pipes = Pipes::new(8);
        let (caller, caller_inner) = tokio::io::duplex(1024);
        let (node_inner, mut node) = tokio::io::duplex(1024);
        let piped = piped_with(caller_inner, node_inner, &pipes, Relay::Inbound);
        let (mut caller_reader, mut caller_writer) = tokio::io::split(caller);

        caller_writer.write_all(b"head").await.unwrap();
        let mut head = [0u8; 4];
        node.read_exact(&mut head).await.unwrap();
        node.write_all(b"answer").await.unwrap();
        drop(node);
        let mut answer = [0u8; 6];
        caller_reader.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"answer");
        assert_eq!(caller_reader.read(&mut [0u8; 8]).await.unwrap(), 0);
        let answered = Instant::now();

        // The caller sends a byte every 10 seconds and never closes. The bytes are dropped
        // and are no bytes that moved: the pipe ends at the half-closed limit, counted from
        // the end of the answer.
        let trickle = tokio::spawn(async move {
            while caller_writer.write_all(b"x").await.is_ok() {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
        assert_eq!(piped.await.unwrap(), PipeEnd::HalfClosed);
        assert_eq!(answered.elapsed(), PIPE_HALF_CLOSED_LIMIT);
        trickle.await.unwrap();
        assert_eq!(ended(&pipes), [0, 0, 0, 1]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_answer_of_a_provider_that_closed_reaches_the_node_that_is_still_sending() {
        // An answer of more bytes than one turn of a direction moves.
        const ANSWER: usize = 300_000;
        let pipes = Pipes::new(8);
        let (node, node_inner) = tokio::io::duplex(1024);
        let (provider_inner, mut provider) = tokio::io::duplex(ANSWER + 1024);
        let piped = piped(node_inner, provider_inner, &pipes);
        let (mut node_reader, mut node_writer) = tokio::io::split(node);

        // The node sends more than the provider, which reads nothing, has room for: the write
        // of the pipe to the provider blocks.
        let sending = tokio::spawn(async move { node_writer.write_all(&[7u8; 2_000_000]).await });
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!piped.is_finished());
        assert!(!sending.is_finished());

        // The provider answers before it has read the request, and closes.
        let answer: Vec<u8> = (0..ANSWER).map(|index| (index % 233) as u8).collect();
        provider.write_all(&answer).await.unwrap();
        drop(provider);
        let closed = Instant::now();

        // The node gets the whole answer and the end of the provider. What it still sends
        // stays unread, and the pipe ends when the answer has moved: no limit is waited for.
        let mut received = Vec::new();
        node_reader.read_to_end(&mut received).await.unwrap();
        assert!(received == answer, "the answer arrived changed");
        assert_eq!(piped.await.unwrap(), PipeEnd::Closed);
        assert_eq!(closed.elapsed(), Duration::ZERO);
        assert!(sending.await.unwrap().is_err());
        assert_eq!(pipes.held(), 0);
        assert_eq!(ended(&pipes), [1, 0, 0, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_that_closed_its_connection_cuts_the_provider_off_at_once() {
        let pipes = Pipes::new(8);
        let (mut node, node_inner) = tokio::io::duplex(1024);
        let (provider_inner, provider) = tokio::io::duplex(1024);
        let piped = piped(node_inner, provider_inner, &pipes);
        let (mut provider_reader, mut provider_writer) = tokio::io::split(provider);

        // The provider sends more than the node, which reads nothing, has room for: the write
        // of the pipe to the node blocks.
        let flood = tokio::spawn(async move { provider_writer.write_all(&[7u8; 2_000_000]).await });
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!piped.is_finished());
        assert!(!flood.is_finished());

        // The node gives the response up: it writes its last 24 bytes and closes while the
        // provider goes on sending.
        node.write_all(&[9u8; 24]).await.unwrap();
        drop(node);
        let closed = Instant::now();

        // The provider gets the 24 bytes and the end of the node, and the pipe ends at once:
        // its close cuts the provider off.
        let mut received = Vec::new();
        provider_reader.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, [9u8; 24]);
        assert_eq!(piped.await.unwrap(), PipeEnd::Closed);
        assert_eq!(closed.elapsed(), Duration::ZERO);
        assert!(flood.await.unwrap().is_err());
        assert_eq!(pipes.held(), 0);
        assert_eq!(ended(&pipes), [1, 0, 0, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_that_is_done_learns_at_once_that_its_caller_sends_nothing_more() {
        let pipes = Pipes::new(8);
        let (caller, caller_inner) = tokio::io::duplex(1024);
        let (node_inner, node) = tokio::io::duplex(1024);
        let piped = piped_with(caller_inner, node_inner, &pipes, Relay::Inbound);
        let (mut caller_reader, mut caller_writer) = tokio::io::split(caller);
        let (mut node_reader, mut node_writer) = tokio::io::split(node);

        // The caller sends the head of its request. The node reads it, answers before the
        // rest of the request arrived and is done: it closes its write side and reads on
        // until its peer ends.
        caller_writer.write_all(b"head").await.unwrap();
        let mut head = [0u8; 4];
        node_reader.read_exact(&mut head).await.unwrap();
        node_writer.write_all(b"answer").await.unwrap();
        node_writer.shutdown().await.unwrap();
        let done = Instant::now();

        // The pipe closes its write side to the node at once: the node reads the end of its
        // peer while the caller has neither read the answer nor ended, and closes.
        let mut rest = Vec::new();
        node_reader.read_to_end(&mut rest).await.unwrap();
        assert_eq!(done.elapsed(), Duration::ZERO);
        assert!(rest.is_empty());
        drop((node_reader, node_writer));

        // The caller reads the whole answer and the end of the node. What it still sends is
        // dropped, and the pipe stays open until the caller ends.
        let mut answer = Vec::new();
        caller_reader.read_to_end(&mut answer).await.unwrap();
        assert_eq!(answer, b"answer");
        caller_writer.write_all(&vec![7u8; 500_000]).await.unwrap();
        settle().await;
        assert!(!piped.is_finished());
        caller_writer.shutdown().await.unwrap();
        assert_eq!(piped.await.unwrap(), PipeEnd::Closed);
        assert_eq!(ended(&pipes), [1, 0, 0, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_that_is_done_ends_the_pipe_to_a_provider_that_is_still_sending() {
        let pipes = Pipes::new(8);
        let (node, node_inner) = tokio::io::duplex(1024);
        let (provider_inner, provider) = tokio::io::duplex(1024);
        let piped = piped(node_inner, provider_inner, &pipes);
        let (mut node_reader, mut node_writer) = tokio::io::split(node);
        let (mut provider_reader, mut provider_writer) = tokio::io::split(provider);

        // The provider is in the middle of a response, and the node reads it.
        let flood = tokio::spawn(async move { provider_writer.write_all(&[7u8; 2_000_000]).await });
        let mut part = [0u8; 4096];
        node_reader.read_exact(&mut part).await.unwrap();

        // The node gives the response up: it writes its last 24 bytes, closes its write side
        // and reads on until its peer ends.
        node_writer.write_all(&[9u8; 24]).await.unwrap();
        node_writer.shutdown().await.unwrap();
        let done = Instant::now();

        // The provider gets the 24 bytes and the end of the node, and the pipe ends at once.
        // The node reads the end of its peer after what was on its way, no more than its
        // connection held, and the close of the pipe cuts the provider off.
        let mut received = Vec::new();
        provider_reader.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, [9u8; 24]);
        assert_eq!(piped.await.unwrap(), PipeEnd::Closed);
        let mut rest = Vec::new();
        node_reader.read_to_end(&mut rest).await.unwrap();
        assert_eq!(done.elapsed(), Duration::ZERO);
        assert!(rest.len() <= 1024, "{} bytes", rest.len());
        assert!(flood.await.unwrap().is_err());
        assert_eq!(pipes.held(), 0);
        assert_eq!(ended(&pipes), [1, 0, 0, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_that_is_done_does_not_wait_for_a_provider_that_takes_its_last_bytes_late() {
        let pipes = Pipes::new(8);
        let (node, node_inner) = tokio::io::duplex(1024);
        let (provider_inner, mut provider) = tokio::io::duplex(64);
        let piped = piped(node_inner, provider_inner, &pipes);
        let (mut node_reader, mut node_writer) = tokio::io::split(node);

        // The node sends more than the provider, which reads nothing, has room for, and is
        // done.
        node_writer.write_all(&[9u8; 300]).await.unwrap();
        node_writer.shutdown().await.unwrap();
        let done = Instant::now();

        // The pipe still holds bytes of the node for the provider. It closes its write side
        // to the node all the same, at once: the node reads the end of its peer and closes.
        let mut rest = Vec::new();
        node_reader.read_to_end(&mut rest).await.unwrap();
        assert_eq!(done.elapsed(), Duration::ZERO);
        assert!(rest.is_empty());
        drop((node_reader, node_writer));

        // The pipe stays open for the last bytes of the node. The provider takes them 30
        // seconds later, with the end of the node, and the pipe ends then.
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert!(!piped.is_finished());
        let mut received = Vec::new();
        provider.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, [9u8; 300]);
        assert_eq!(piped.await.unwrap(), PipeEnd::Closed);
        assert_eq!(done.elapsed(), Duration::from_secs(30));
        assert_eq!(ended(&pipes), [1, 0, 0, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_end_of_one_direction_attempts_the_blocked_write_of_the_other_at_once() {
        let pipes = Pipes::new(8);
        let silent = Silent::default();
        let (right_inner, mut right) = tokio::io::duplex(64);
        let piped = piped(Attempting(silent.clone()), right_inner, &pipes);

        // The right side sends more than the pipe can hand to a peer that reads nothing.
        let flood = tokio::spawn(async move {
            let _ = right.write_all(&[7u8; 200_000]).await;
            right
        });
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!piped.is_finished());

        // The silent peer writes a last message, ends its direction and closes, while the
        // write to it is blocked and no event will wake that write. The pipe carries the
        // message, reads the end and attempts the blocked write in the same turn. The write
        // fails on a stream that reported the end of its bytes: the stream closed, and so
        // does the pipe.
        silent.close_after(b"goodbye");
        let closed = Instant::now();
        assert_eq!(piped.await.unwrap(), PipeEnd::Closed);
        assert_eq!(closed.elapsed(), Duration::ZERO);
        assert_eq!(pipes.held(), 0);
        assert_eq!(ended(&pipes), [1, 0, 0, 0]);

        // The other side got the last message of the peer before the pipe closed it.
        let mut right = flood.await.unwrap();
        let mut received = Vec::new();
        right.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"goodbye");
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_that_never_takes_a_write_and_never_fails_is_cut_at_the_limits() {
        // Without the attempted write the stream is one that only waits: a write is asked of
        // it every second and never answered.
        let pipes = Pipes::new(8);

        // Both directions open, bytes waiting for the silent side: the idle limit ends it.
        let silent = Silent::default();
        let (right_inner, mut right) = tokio::io::duplex(64);
        let started = Instant::now();
        let piped_open = piped(silent.clone(), right_inner, &pipes);
        right.write_all(b"never taken").await.unwrap();
        assert_eq!(piped_open.await.unwrap(), PipeEnd::Idle);
        assert_eq!(started.elapsed(), PIPE_IDLE_LIMIT);
        assert!(silent.peer().writes_asked >= PIPE_IDLE_LIMIT.as_secs());

        // The silent side is a caller that ended its direction, bytes of the node waiting
        // for it: the half-closed limit ends it.
        let silent = Silent::default();
        silent.peer().ended = true;
        let (right_inner, mut right) = tokio::io::duplex(64);
        let started = Instant::now();
        let piped_half = piped_with(silent.clone(), right_inner, &pipes, Relay::Inbound);
        right.write_all(b"never taken").await.unwrap();
        assert_eq!(right.read(&mut [0u8; 8]).await.unwrap(), 0);
        assert_eq!(piped_half.await.unwrap(), PipeEnd::HalfClosed);
        assert_eq!(started.elapsed(), PIPE_HALF_CLOSED_LIMIT);
        assert_eq!(ended(&pipes), [0, 0, 1, 1]);
    }

    /// Sends `bytes` into `from` and reads them out of `to`.
    async fn carry(
        from: &mut tokio::io::DuplexStream,
        to: &mut tokio::io::DuplexStream,
        bytes: usize,
    ) {
        let sent: Vec<u8> = (0..bytes).map(|index| (index % 239) as u8).collect();
        let (wrote, received) = tokio::join!(from.write_all(&sent), async {
            let mut received = vec![0u8; bytes];
            to.read_exact(&mut received).await.unwrap();
            received
        });
        wrote.unwrap();
        assert!(received == sent, "{bytes} bytes arrived changed");
    }

    #[tokio::test(start_paused = true)]
    async fn a_direction_takes_a_large_buffer_while_it_moves_many_bytes() {
        let pipes = Pipes::with_large_buffers(8, 4);
        let (mut left, left_inner) = tokio::io::duplex(256 * 1024);
        let (right_inner, mut right) = tokio::io::duplex(256 * 1024);
        let piped = piped(left_inner, right_inner, &pipes);

        // Messages below the size of the small buffer are moved with it.
        for _ in 0..3 {
            carry(&mut left, &mut right, SMALL_BUFFER_BYTES - 1).await;
            carry(&mut right, &mut left, 100).await;
            assert_eq!(pipes.large_buffers_held(), 0);
            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        // A message that fills the small buffer: the direction that carries it takes a large
        // buffer, the other direction takes none.
        carry(&mut left, &mut right, 300_000).await;
        assert_eq!(pipes.large_buffers_held(), 1);
        carry(&mut right, &mut left, 100).await;
        assert_eq!(pipes.large_buffers_held(), 1);

        // Small messages go on: the direction gives the buffer back a second after its last
        // read of the size of the small buffer or more, whether or not bytes still move.
        tokio::time::sleep(LARGE_BUFFER_IDLE / 2).await;
        carry(&mut left, &mut right, 100).await;
        assert_eq!(pipes.large_buffers_held(), 1);
        tokio::time::sleep(LARGE_BUFFER_IDLE / 2 + Duration::from_millis(1)).await;
        assert_eq!(pipes.large_buffers_held(), 0);
        carry(&mut left, &mut right, 100).await;
        assert_eq!(pipes.large_buffers_held(), 0);

        // Both directions carry many bytes: each holds one, and both give them back when the
        // pipe ends.
        carry(&mut left, &mut right, 300_000).await;
        carry(&mut right, &mut left, 300_000).await;
        assert_eq!(pipes.large_buffers_held(), 2);
        left.shutdown().await.unwrap();
        right.shutdown().await.unwrap();
        assert_eq!(piped.await.unwrap(), PipeEnd::Closed);
        assert_eq!(pipes.large_buffers_held(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_relay_without_a_free_large_buffer_moves_the_bytes_with_the_small_buffers() {
        // One large buffer for two pipes that carry many bytes at the same time.
        let pipes = Pipes::with_large_buffers(8, 1);
        let (mut first, first_inner) = tokio::io::duplex(256 * 1024);
        let (first_far_inner, mut first_far) = tokio::io::duplex(256 * 1024);
        let first_pipe = piped(first_inner, first_far_inner, &pipes);
        let (mut second, second_inner) = tokio::io::duplex(256 * 1024);
        let (second_far_inner, mut second_far) = tokio::io::duplex(256 * 1024);
        let second_pipe = piped(second_inner, second_far_inner, &pipes);

        carry(&mut first, &mut first_far, 300_000).await;
        assert_eq!(pipes.large_buffers_held(), 1);
        // The second pipe finds no large buffer and still carries every byte, in both
        // directions.
        carry(&mut second, &mut second_far, 300_000).await;
        carry(&mut second_far, &mut second, 300_000).await;
        assert_eq!(pipes.large_buffers_held(), 1);

        // The first pipe gives its buffer back: a direction of the second takes it with its
        // next bytes.
        tokio::time::sleep(LARGE_BUFFER_IDLE + Duration::from_millis(1)).await;
        assert_eq!(pipes.large_buffers_held(), 0);
        carry(&mut second, &mut second_far, 300_000).await;
        assert_eq!(pipes.large_buffers_held(), 1);

        drop((first, first_far, second, second_far));
        assert_eq!(first_pipe.await.unwrap(), PipeEnd::Closed);
        assert_eq!(second_pipe.await.unwrap(), PipeEnd::Closed);
        assert_eq!(pipes.large_buffers_held(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_relay_holds_its_limit_of_connections_and_reports_their_ages() {
        let pipes = Pipes::new(2);
        assert_eq!(pipes.limit(), 2);
        assert_eq!(pipes.held(), 0);
        assert_eq!(pipes.oldest_and_idlest_ms(), (0, 0));

        let (mut first, first_inner) = tokio::io::duplex(64);
        let (first_far_inner, mut first_far) = tokio::io::duplex(64);
        let first_pipe = piped(first_inner, first_far_inner, &pipes);
        tokio::time::sleep(Duration::from_secs(40)).await;
        let (second, second_inner) = tokio::io::duplex(64);
        let (second_far_inner, second_far) = tokio::io::duplex(64);
        let second_pipe = piped(second_inner, second_far_inner, &pipes);
        tokio::time::sleep(Duration::from_secs(60)).await;

        // Two connections are held: a third gets no place.
        assert_eq!(pipes.held(), 2);
        assert!(pipes.admit().is_none());
        // The first is 100 seconds old and has moved no byte for as long.
        assert_eq!(pipes.oldest_and_idlest_ms(), (100_000, 100_000));

        // A byte on the first connection: it is still the oldest, and the second is now the
        // one that has moved no byte for the longest time.
        first.write_all(b"x").await.unwrap();
        assert_eq!(first_far.read(&mut [0u8; 8]).await.unwrap(), 1);
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(pipes.oldest_and_idlest_ms(), (105_000, 65_000));

        // The first connection ends: its place is free, and the second is the oldest.
        first.shutdown().await.unwrap();
        first_far.shutdown().await.unwrap();
        assert_eq!(first_pipe.await.unwrap(), PipeEnd::Closed);
        assert_eq!(pipes.held(), 1);
        assert_eq!(pipes.oldest_and_idlest_ms(), (65_000, 65_000));
        let place = pipes.admit().unwrap();
        assert_eq!(pipes.held(), 2);
        drop(place);
        assert_eq!(pipes.held(), 1);

        drop((second, second_far));
        assert_eq!(second_pipe.await.unwrap(), PipeEnd::Closed);
        assert_eq!(pipes.oldest_and_idlest_ms(), (0, 0));
        assert_eq!(
            pipes.ended(),
            [
                ("closed", 2),
                ("failed", 0),
                ("idle", 0),
                ("half_closed", 0)
            ]
        );
    }

    #[test]
    fn the_inbound_relay_holds_the_connections_of_the_node_less_those_of_the_host_program() {
        // A node in an enclave of 4,096 MiB holds 1,502 connections from the backend.
        assert_eq!(inbound_pipes_for(1_502), 1_494);
        assert_eq!(inbound_pipes_for(64), 56);
        assert_eq!(inbound_pipes_for(16_384), 16_376);
        // Never more than the relay has descriptors and memory for, and never none.
        assert_eq!(inbound_pipes_for(1_000_000), INBOUND_PIPES);
        assert_eq!(inbound_pipes_for(u64::MAX), INBOUND_PIPES);
        assert_eq!(inbound_pipes_for(8), 1);
        assert_eq!(inbound_pipes_for(0), 1);
    }

    #[tokio::test]
    async fn a_relay_whose_limit_is_lowered_takes_no_connection_until_it_holds_fewer() {
        let pipes = Pipes::new(4);
        let first = pipes.admit().unwrap();
        let second = pipes.admit().unwrap();
        let third = pipes.admit().unwrap();

        // The limit falls below what the relay holds: the connections it holds stay, and it
        // takes no further one until it holds fewer than the new limit.
        pipes.set_limit(2);
        assert_eq!(pipes.limit(), 2);
        assert_eq!(pipes.held(), 3);
        assert!(pipes.admit().is_none());
        drop(first);
        assert!(pipes.admit().is_none());
        drop(second);
        let fourth = pipes.admit().unwrap();
        assert!(pipes.admit().is_none());

        // A higher limit takes effect at once.
        pipes.set_limit(3);
        let fifth = pipes.admit().unwrap();
        assert!(pipes.admit().is_none());
        drop((third, fourth, fifth));
        assert_eq!(pipes.held(), 0);
    }

    #[tokio::test]
    async fn the_inbound_relay_closes_a_connection_above_its_limit_without_a_byte() {
        let (address, counters) = relay_holding(EchoNode { reachable: true }, 1).await;
        let mut first = TcpStream::connect(address).await.unwrap();
        first.write_all(b"held").await.unwrap();
        let mut buffer = [0u8; 4];
        first.read_exact(&mut buffer).await.unwrap();
        assert_eq!(counters.pipes().held(), 1);

        // The relay holds its one connection: the next one ends without a byte and is counted.
        let mut second = TcpStream::connect(address).await.unwrap();
        assert!(matches!(second.read(&mut buffer).await, Ok(0) | Err(_)));
        assert_eq!(counters.refused(), 1);
        assert_eq!(counters.pipes().held(), 1);
        assert_eq!(counters.node_connect_failures(), 0);

        // The first connection ends: its place is free for the next caller.
        first.shutdown().await.unwrap();
        assert_eq!(first.read(&mut buffer).await.unwrap(), 0);
        for _ in 0..200 {
            if counters.pipes().held() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let mut third = TcpStream::connect(address).await.unwrap();
        third.write_all(b"next").await.unwrap();
        third.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"next");
        assert_eq!(counters.refused(), 1);
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

    /// A node stand-in that answers a request when it has read the head of the request,
    /// without reading the body: what a node does with a call it refuses before it reads the
    /// request (enclave.md section 4). Like a node, it is done then: it closes its write side,
    /// reads and drops what still comes until its peer ends, and closes. It counts the bytes
    /// that reached it after its answer.
    struct EarlyNode {
        answer: Vec<u8>,
        after_answer: Arc<AtomicUsize>,
    }

    impl NodeConnector for EarlyNode {
        fn connect(&self) -> BoxFuture<'_, io::Result<Stream>> {
            Box::pin(async move {
                // The stand-in writes its whole answer at once, as a node whose answer fits
                // the buffers of its connection does.
                let (near, mut far) = tokio::io::duplex(self.answer.len() + 1024);
                let answer = self.answer.clone();
                let after_answer = self.after_answer.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        match far.read_u8().await {
                            Ok(byte) => head.push(byte),
                            Err(_) => return,
                        }
                    }
                    let _ = far.write_all(&answer).await;
                    let _ = far.shutdown().await;
                    let mut dropped = [0u8; 4096];
                    while let Ok(count) = far.read(&mut dropped).await {
                        if count == 0 {
                            break;
                        }
                        after_answer.fetch_add(count, Ordering::Relaxed);
                    }
                });
                Ok(Box::new(near) as Stream)
            })
        }
    }

    /// An inbound relay in front of a node that answers with `answer` before the body, and
    /// the bytes that reached the node after its answers.
    async fn relay_with_early_node(
        answer: &[u8],
    ) -> (SocketAddr, Arc<InboundCounters>, Arc<AtomicUsize>) {
        let listener =
            listen_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), LISTEN_BACKLOG).unwrap();
        let address = listener.local_addr().unwrap();
        let counters = Arc::new(InboundCounters::default());
        let after_answer = Arc::new(AtomicUsize::new(0));
        let node = EarlyNode {
            answer: answer.to_vec(),
            after_answer: after_answer.clone(),
        };
        let (_, door) = inbound_door();
        tokio::spawn(serve(listener, Arc::new(node), counters.clone(), door));
        (address, counters, after_answer)
    }

    /// Waits until the relay counted `closed` pipes that ended as closed and holds none.
    async fn closed_pipes(counters: &InboundCounters, closed: u64) {
        for _ in 0..400 {
            if counters.pipes().held() == 0 && ended(counters.pipes()) == [closed, 0, 0, 0] {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!(
            "the relay holds {} pipes, ended {:?}",
            counters.pipes().held(),
            ended(counters.pipes())
        );
    }

    #[tokio::test]
    async fn the_inbound_relay_carries_the_answer_of_a_node_that_was_done_before_the_body_arrived()
    {
        const HEAD: &[u8] = b"POST /v1/close HTTP/1.1\r\ncontent-length: 2\r\n\r\n";
        let answer = b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 2\r\n\r\n{}";
        let (address, counters, after_answer) = relay_with_early_node(answer).await;

        // The head and the body of a request arrive apart: the node has answered and is done
        // when the body reaches the relay. The relay has told the node that nothing more
        // comes, and drops the body. The caller reads the whole answer and the end of the
        // connection, on a connection nothing reset, and no byte of a body reaches the node.
        for round in 1..=20u64 {
            let mut caller = TcpStream::connect(address).await.unwrap();
            caller.set_nodelay(true).unwrap();
            caller.write_all(HEAD).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            caller.write_all(b"{}").await.unwrap();
            let mut received = Vec::new();
            caller.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, answer, "round {round}");
            drop(caller);
            closed_pipes(&counters, round).await;
        }
        assert_eq!(after_answer.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn the_inbound_relay_does_not_cut_off_a_caller_that_sends_a_body_the_node_did_not_read() {
        // More bytes than the buffers of a TCP connection hold, in each direction.
        const ANSWER_BYTES: usize = 24 * 1024 * 1024;
        const BODY_BYTES: usize = 24 * 1024 * 1024;
        let answer: Vec<u8> = (0..ANSWER_BYTES).map(|index| (index % 239) as u8).collect();
        let (address, counters, _) = relay_with_early_node(&answer).await;

        let mut caller = TcpStream::connect(address).await.unwrap();
        caller
            .write_all(b"POST /v1/forward HTTP/1.1\r\ncontent-length: 25165824\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The caller sends its whole body before it reads a byte of the answer, as an HTTP
        // client does. The node was done long ago: what the relay cannot hand to the node it
        // drops, so every write of the caller succeeds, and the answer waits for the caller.
        let chunk = vec![5u8; 64 * 1024];
        for _ in 0..BODY_BYTES / chunk.len() {
            caller.write_all(&chunk).await.unwrap();
        }
        let mut received = Vec::with_capacity(ANSWER_BYTES);
        caller.read_to_end(&mut received).await.unwrap();
        assert!(received == answer, "{} bytes of the answer", received.len());

        // The relay closes the connection when the caller did, and counts an orderly end.
        drop(caller);
        closed_pipes(&counters, 1).await;
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

    /// A pipe whose vsock peer writes a last message and closes while the write of the pipe to
    /// it is blocked, against the loopback transport of the kernel. The kernel gives the
    /// socket of the pipe no event for that end when the socket was accepted and holds unread
    /// bytes, so the test shows that the pipe ends without one. It needs what the test of the
    /// endpoints needs and runs on request only.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "needs the vsock loopback transport of the kernel"]
    async fn a_pipe_ends_when_its_vsock_peer_closes_while_the_write_to_it_is_blocked() {
        const LOOPBACK_CID: u32 = 1;
        const PORT: u32 = 18_444;
        let listener = VsockListener::bind(PORT).unwrap();
        let mut peer = vsock_connect(LOOPBACK_CID, PORT).await.unwrap();
        let accepted = listener.accept().await.unwrap();

        // The other side of the pipe sends more than the vsock peer, which reads nothing,
        // has room for: the write of the pipe to the peer blocks.
        let pipes = Pipes::new(8);
        let (other_inner, other) = tokio::io::duplex(64 * 1024);
        let piped = piped(accepted, other_inner, &pipes);
        let (mut other_reader, mut other_writer) = tokio::io::split(other);
        let flood = tokio::spawn(async move {
            let _ = other_writer.write_all(&vec![7u8; 4 * 1024 * 1024]).await;
        });
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(!piped.is_finished());
        assert!(!flood.is_finished());

        // The peer writes 24 bytes, ends its direction and closes its socket.
        peer.write_all(&[9u8; 24]).await.unwrap();
        peer.shutdown().await.unwrap();
        drop(peer);
        let closed = std::time::Instant::now();

        // The pipe carries the 24 bytes and ends within the pause between two attempts of the
        // blocked write and a margin.
        let end = tokio::time::timeout(BLOCKED_WRITE_RETRY * 3, piped)
            .await
            .expect("the pipe did not end")
            .unwrap();
        assert_eq!(end, PipeEnd::Closed);
        assert!(closed.elapsed() < BLOCKED_WRITE_RETRY * 3);
        let mut received = Vec::new();
        other_reader.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, [9u8; 24]);
        flood.await.unwrap();
        assert_eq!(pipes.held(), 0);
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
    async fn an_inbound_relay_whose_door_is_closed_refuses_a_caller_and_keeps_its_pipes() {
        let (address, counters, door) = relay_with_door().await;
        let mut held = TcpStream::connect(address).await.unwrap();
        held.write_all(b"before").await.unwrap();
        let mut buffer = [0u8; 6];
        held.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"before");

        // The shutdown closes the door: when the call returns the listener is closed.
        assert!(tokio::time::timeout(Duration::from_secs(5), door.close())
            .await
            .unwrap());
        // A caller that connects now is refused: its connection does not open.
        for _ in 0..3 {
            let refused = TcpStream::connect(address).await.unwrap_err();
            assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
        }
        // The connection the relay held goes on: its node is still behind it.
        assert_eq!(counters.pipes().held(), 1);
        held.write_all(b"after!").await.unwrap();
        held.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"after!");
        held.shutdown().await.unwrap();
        assert_eq!(held.read(&mut buffer).await.unwrap(), 0);
        closed_pipes(&counters, 1).await;
        assert_eq!(counters.refused(), 0);
        assert_eq!(counters.node_connect_failures(), 0);

        // A door that is closed is closed: the second call returns at once, and says that it
        // was not the one that closed the door.
        assert!(!tokio::time::timeout(Duration::from_secs(5), door.close())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn an_inbound_relay_takes_the_connections_that_wait_when_its_door_closes() {
        let listener =
            listen_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), LISTEN_BACKLOG).unwrap();
        let address = listener.local_addr().unwrap();
        let counters = Arc::new(InboundCounters::default());
        let (door, order) = inbound_door();

        // Three callers connect while nothing accepts: the kernel completes their
        // connections, which wait in the queue of the listener, and takes their requests.
        let mut waiting = Vec::new();
        for number in 0..3u8 {
            let mut caller = TcpStream::connect(address).await.unwrap();
            caller.write_all(&[b'a' + number; 5]).await.unwrap();
            waiting.push(caller);
        }

        // The door is closed before the relay accepted once: the relay takes the three
        // connections of the queue, and only then closes the listener.
        let closing = tokio::spawn(async move {
            door.close().await;
            door
        });
        tokio::spawn(serve(
            listener,
            Arc::new(EchoNode { reachable: true }),
            counters.clone(),
            order,
        ));
        let _door = tokio::time::timeout(Duration::from_secs(5), closing)
            .await
            .unwrap()
            .unwrap();

        // None of the three was reset: each reads the answer of the node.
        for (number, caller) in waiting.iter_mut().enumerate() {
            let mut buffer = [0u8; 5];
            caller.read_exact(&mut buffer).await.unwrap();
            assert_eq!(buffer, [b'a' + number as u8; 5]);
        }
        assert_eq!(counters.pipes().held(), 3);
        assert_eq!(counters.refused(), 0);
        // A caller that connects after the door closed is refused.
        let refused = TcpStream::connect(address).await.unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
        for caller in &mut waiting {
            caller.shutdown().await.unwrap();
        }
        closed_pipes(&counters, 3).await;
    }

    #[tokio::test]
    async fn an_inbound_relay_whose_door_nobody_holds_stays_open() {
        // The half of the shutdown is dropped without a close: the relay goes on.
        let (address, counters, door) = relay_with_door().await;
        drop(door);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut caller = TcpStream::connect(address).await.unwrap();
        caller.write_all(b"open").await.unwrap();
        let mut buffer = [0u8; 4];
        caller.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"open");
        assert_eq!(counters.pipes().held(), 1);

        // A door no relay holds is closed at once.
        let (door, order) = inbound_door();
        drop(order);
        assert!(tokio::time::timeout(Duration::from_secs(5), door.close())
            .await
            .unwrap());
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
