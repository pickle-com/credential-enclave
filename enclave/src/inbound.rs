//! The connections from the backend (enclave.md section 8): how many of them a node holds at
//! once, and how long a node waits for the peer of one.
//!
//! A connection from the backend ends within a fixed time whatever its peer does. A node
//! waits for the peer of a connection at three places, and at each of them for `inbound_idle`
//! at the longest:
//!
//! - for the head of the next request: the first request of the connection, and every request
//!   after a response (`crate::api::serve_connection`);
//! - for the next bytes of the body of a request ([`TimedBody`]);
//! - for the peer to take bytes of a response ([`TimedStream`]).
//!
//! While a node works on a call it waits for nobody on the connection of that call, and the
//! call has the time limits of its own steps.
//!
//! The number of connections a node holds at once is computed from the memory of the kernel
//! it runs in ([`connections_for`]): a connection can hold memory that no other bound of the
//! node covers, and the node gives the connections a fixed share of its memory.

use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::BoxError;
use hyper::body::{Body as HttpBody, Bytes, Frame, SizeHint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// The most connections from the backend a node holds at once, whatever its memory: every
/// connection holds a descriptor, and this bound keeps the connections of the callers from
/// taking the descriptors of the writes to the log store and of the provider requests
/// (`crate::descriptors`).
pub const CONNECTIONS_MAX: usize = 16_384;
/// The fewest connections from the backend a node holds at once, whatever its memory.
pub const CONNECTIONS_MIN: usize = 64;
/// The part of the memory of its kernel a node gives the connections from the backend: one
/// eighth.
pub const MEMORY_SHARE: u64 = 8;
/// What one connection from the backend can hold that no other bound of the node covers:
///
/// - the bytes its peer sent and the node has not read yet, in the receive queue of the
///   socket: the kernel takes 262,144 bytes for a vsock connection before the peer has to
///   wait;
/// - the bytes the node read and has not parsed or handed to a call yet, in the read buffer
///   of the HTTP connection: twice [`READ_BUFFER_BYTES`];
/// - the socket, the task and the state of the connection: 16 KiB.
///
/// The body of a request a call has read, and the body of a response, are not part of it:
/// they are in memory under the body budget of the node or within the limit of a JSON body.
///
/// Measured in an enclave of 4,096 MiB (enclave.md section 8): a connection that sent
/// nothing took 14.3 KiB, and a connection whose peer had filled its receive queue and took
/// nothing of a response took 314 KiB.
pub const CONNECTION_BYTES: u64 = 262_144 + 2 * READ_BUFFER_BYTES as u64 + 16 * 1024;
/// The bytes the HTTP connection of a caller holds in its read buffer before it stops
/// reading: it reads on while the buffer holds less, so a request head of this size or less
/// is always read, and the buffer grows to at most twice this size. A head the buffer cannot
/// hold is refused with the status 431 before any call sees it. A body is read in parts of
/// at most this size.
pub const READ_BUFFER_BYTES: usize = 32 * 1024;
/// Pause between two attempts of a write that the peer of a connection did not take.
pub const BLOCKED_WRITE_RETRY: Duration = Duration::from_secs(1);

/// The connections from the backend a node holds at once in a kernel with `memory_total`
/// bytes of memory (`MemTotal` of `/proc/meminfo`): the share of the connections,
/// `memory_total / MEMORY_SHARE`, divided by what one connection can hold,
/// [`CONNECTION_BYTES`], and at least [`CONNECTIONS_MIN`] and at most [`CONNECTIONS_MAX`]. A
/// kernel that exposes no memory size (a development machine that is not Linux) gives
/// [`CONNECTIONS_MAX`].
///
/// With the 4,096 MiB of an enclave the kernel has 3,943 MiB, and the node holds 1,502
/// connections.
pub fn connections_for(memory_total: Option<u64>) -> usize {
    let Some(memory_total) = memory_total else {
        return CONNECTIONS_MAX;
    };
    let connections = memory_total / MEMORY_SHARE / CONNECTION_BYTES;
    usize::try_from(connections)
        .unwrap_or(CONNECTIONS_MAX)
        .clamp(CONNECTIONS_MIN, CONNECTIONS_MAX)
}

/// The stream of a connection from the backend, with the time limit of its writes.
///
/// A write the peer does not take waits, and the node does not rely on the kernel to end that
/// wait: the write is asked of the stream again every [`BLOCKED_WRITE_RETRY`], and it fails
/// with a timeout when the peer took no byte for `limit`. The HTTP connection that gets the
/// failure ends, which frees the place of the connection, its descriptor and what it holds
/// of a response.
///
/// The kernel of an enclave gives a writer that waits no event when the peer of its vsock
/// connection closes. An HTTP connection that reads while it writes learns of the close from
/// the end of the bytes of its peer. One that does not read (it has bytes of a further
/// request in front of it, or it answered before the end of a request body) would wait for a
/// peer that is gone without an end. The stream of a vsock connection attempts a write each
/// time it is asked for it (`crate::platform::Attempted`), so the attempt after the close
/// fails, within a second.
pub struct TimedStream<S> {
    stream: S,
    /// Longest time a write waits for the peer to take a byte.
    limit: Duration,
    /// When the write that waits now began to wait. `None` while no write waits.
    waiting_since: Option<Instant>,
    /// Wakes the task of the connection for the next attempt of a write that waits, and at
    /// the limit.
    timer: Pin<Box<Sleep>>,
}

impl<S> TimedStream<S> {
    /// The stream of a connection whose peer has `limit` to take a byte of a write.
    pub fn new(stream: S, limit: Duration) -> TimedStream<S> {
        TimedStream {
            stream,
            limit,
            waiting_since: None,
            timer: Box::pin(tokio::time::sleep(limit)),
        }
    }

    /// The outcome of a write that was asked of the stream. A write the stream took, or
    /// failed, ends the wait. A write that waits fails when it has waited for the limit;
    /// before that, the task is woken for the next attempt.
    fn waited<T>(
        &mut self,
        cx: &mut Context<'_>,
        outcome: Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        if outcome.is_ready() {
            self.waiting_since = None;
            return outcome;
        }
        let now = Instant::now();
        let deadline = *self.waiting_since.get_or_insert(now) + self.limit;
        if now >= deadline {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the peer took no byte of a response within the time limit",
            )));
        }
        self.timer
            .as_mut()
            .reset(deadline.min(now + BLOCKED_WRITE_RETRY));
        // The timer lies ahead: polling it registers the task of the connection with it.
        let _ = self.timer.as_mut().poll(cx);
        Poll::Pending
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TimedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TimedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let outcome = Pin::new(&mut self.stream).poll_write(cx, bytes);
        self.waited(cx, outcome)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        slices: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let outcome = Pin::new(&mut self.stream).poll_write_vectored(cx, slices);
        self.waited(cx, outcome)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Why a read of a request body failed: no byte of the body arrived for the time limit of
/// [`TimedBody`].
#[derive(Debug)]
pub struct BodyIdle;

impl std::fmt::Display for BodyIdle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("no byte of the request body arrived within the time limit")
    }
}

impl std::error::Error for BodyIdle {}

/// The body of a request, with the time limit of its bytes: a read that gets no byte of the
/// body for `limit` fails with [`BodyIdle`]. A call that reads its body holds what it took
/// before (a place among the calls of its kind, a share of the body budget), and a caller
/// that stops sending must not hold those for longer.
pub struct TimedBody {
    body: Body,
    limit: Duration,
    /// True while a read waits for the next bytes: the timer is set for that read.
    waiting: bool,
    timer: Pin<Box<Sleep>>,
}

impl TimedBody {
    fn new(body: Body, limit: Duration) -> TimedBody {
        TimedBody {
            body,
            limit,
            waiting: false,
            timer: Box::pin(tokio::time::sleep(limit)),
        }
    }
}

impl HttpBody for TimedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if let Poll::Ready(frame) = Pin::new(&mut self.body).poll_frame(cx) {
            self.waiting = false;
            return Poll::Ready(frame.map(|frame| frame.map_err(BoxError::from)));
        }
        if !self.waiting {
            self.waiting = true;
            let deadline = Instant::now() + self.limit;
            self.timer.as_mut().reset(deadline);
        }
        match self.timer.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Some(Err(BodyIdle.into()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// The request with its body under the time limit of [`TimedBody`].
pub fn timed(request: Request, limit: Duration) -> Request {
    request.map(|body| Body::new(TimedBody::new(body, limit)))
}

/// True when `error` is the failure of a read of a request body that waited for its bytes
/// for the time limit.
pub fn is_body_idle(error: axum::Error) -> bool {
    error.into_inner().downcast_ref::<BodyIdle>().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn the_connections_of_a_node_are_a_share_of_its_memory() {
        // The kernel of an enclave of 4,096 MiB has 3,943 MiB (`MemTotal`).
        assert_eq!(connections_for(Some(4_134_662_144)), 1_502);
        // One connection is 336 KiB, and the connections together get one eighth.
        assert_eq!(CONNECTION_BYTES, 344_064);
        assert_eq!(connections_for(Some(8 * 1000 * CONNECTION_BYTES)), 1_000);
        // More memory, more connections, up to the bound of the descriptors.
        assert_eq!(connections_for(Some(8_192 * MIB)), 3_120);
        assert_eq!(connections_for(Some(64 * 1024 * MIB)), CONNECTIONS_MAX);
        assert_eq!(connections_for(Some(u64::MAX)), CONNECTIONS_MAX);
        // A kernel with little memory still takes calls.
        assert_eq!(connections_for(Some(64 * MIB)), CONNECTIONS_MIN);
        assert_eq!(connections_for(Some(0)), CONNECTIONS_MIN);
        // A kernel that exposes no memory size.
        assert_eq!(connections_for(None), CONNECTIONS_MAX);
    }
}
