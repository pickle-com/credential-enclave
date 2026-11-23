//! The connections a node closes only after their peer reported the end of its bytes: the vsock
//! connections of the nitro platform (enclave.md section 8).

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::ByteStream;

/// Longest time a connection the node is done with waits for the end of its peer
/// ([`Lingering`]). A relay that learns the node is done ends its side at once (enclave.md
/// 9.1), so the wait is a round trip to the parent instance; the limit is for a peer that
/// does not answer.
pub const LINGER_LIMIT: Duration = Duration::from_secs(10);
/// The most connections the node is done with that wait for the end of their peer at once
/// ([`Lingering`]). Each holds a descriptor and nothing else: what its peer sends is read and
/// dropped. The nitro platform, which is compiled on Linux only, is the one that has such
/// connections.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const LINGERING_CONNECTIONS: usize = 1_024;

/// The connections the node is done with and has not closed yet ([`Lingering`]): how many
/// there are, their bound and their time limit, and how many the node closed before their
/// peer had reported its end.
#[derive(Debug)]
pub struct Lingerers {
    /// Longest time one connection waits for the end of its peer.
    limit: Duration,
    /// The most connections that wait at once.
    most: usize,
    /// The connections that wait at this moment.
    waiting: AtomicUsize,
    /// The connections closed before their peer had reported its end, since the node started:
    /// a connection whose peer had not reported its end when it was dropped while `most`
    /// were waiting or outside a runtime, and a connection whose peer had not reported its
    /// end after `limit`. A connection whose peer reported its end before the node was done
    /// with it is not one of them: nothing reaches it after its close.
    cut: AtomicU64,
}

impl Lingerers {
    /// The connections of a node: at most [`LINGERING_CONNECTIONS`] wait at once, each for
    /// [`LINGER_LIMIT`] at the longest.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn new() -> Arc<Lingerers> {
        Lingerers::holding(LINGERING_CONNECTIONS, LINGER_LIMIT)
    }

    /// Connections of which at most `most` wait at once, each for `limit` at the longest.
    pub fn holding(most: usize, limit: Duration) -> Arc<Lingerers> {
        Arc::new(Lingerers {
            limit,
            most,
            waiting: AtomicUsize::new(0),
            cut: AtomicU64::new(0),
        })
    }

    /// The connections that wait for the end of their peer at this moment.
    pub fn waiting(&self) -> usize {
        self.waiting.load(Ordering::Relaxed)
    }

    /// The connections closed before their peer had reported its end, since the node started.
    pub fn cut(&self) -> u64 {
        self.cut.load(Ordering::Relaxed)
    }

    /// Takes a place among the connections that wait, or `None` when `most` wait.
    fn admit(self: &Arc<Lingerers>) -> Option<LingerPlace> {
        self.waiting
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |waiting| {
                (waiting < self.most).then_some(waiting + 1)
            })
            .ok()?;
        Some(LingerPlace(self.clone()))
    }
}

/// The place of one connection among the connections that wait for the end of their peer.
/// Dropping it frees the place.
struct LingerPlace(Arc<Lingerers>);

impl Drop for LingerPlace {
    fn drop(&mut self) {
        self.0.waiting.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A connection that is closed only after its peer reported the end of its bytes.
///
/// The vsock connections of a node are connections of this kind. The kernel of an enclave
/// keeps what reaches a vsock socket after the node closed it: the buffers of those bytes
/// stay taken for as long as the enclave runs, and reading the socket empty before the close
/// does not help while the peer goes on sending (enclave.md section 8 has the
/// measurements). A node is done with a connection while its peer is still sending in
/// several places: a connection above its bound, a call it answered before the end of the
/// request body, a response of a provider it gave up on. Each such close would cost the node
/// the memory of those bytes for good.
///
/// So the node does not close a connection it is done with. When the connection is dropped,
/// its write side is closed, which tells the peer that the node is done, and a task reads
/// and drops what the peer still sends until the peer reports the end of its bytes
/// ([`end_after_peer`]). The connection is closed then: its receive queue is empty and its
/// peer sends nothing more. The two relays of the host program end their side at once when
/// the node closes its write side (enclave.md 9.1), so the wait is short.
///
/// A connection whose peer reported the end of its bytes before the node was done with it
/// has nothing to wait for: a read of the connection gave the end (a caller that closed
/// after its answer), or failed (a peer that is gone). Nothing reaches such a connection
/// after its close, so it is closed when it is dropped, without a wait and without a count.
///
/// The wait has two bounds ([`Lingerers`]). A connection whose peer has not reported its end
/// after the time limit is closed, and a connection dropped while the bound of waiting
/// connections is reached, or outside a runtime, is closed at once. Both are counted: each
/// is a close before the end of the peer, the one kind of close that can cost the kernel
/// memory.
pub struct Lingering<S: ByteStream> {
    /// The connection. `None` once the connection was dropped and handed to its wait.
    stream: Option<S>,
    /// True once the write side of the connection was closed: what held the connection
    /// closed it when it was done, and the wait does not close it a second time.
    write_closed: bool,
    /// True once a read of the connection gave the end of the bytes of its peer, or failed:
    /// the peer sends nothing more.
    peer_ended: bool,
    lingerers: Arc<Lingerers>,
}

impl<S: ByteStream> Lingering<S> {
    /// `stream` as a connection that waits for the end of its peer among `lingerers` when
    /// it is dropped.
    pub fn new(stream: S, lingerers: Arc<Lingerers>) -> Lingering<S> {
        Lingering {
            stream: Some(stream),
            write_closed: false,
            peer_ended: false,
            lingerers,
        }
    }

    fn stream(self: Pin<&mut Self>) -> std::io::Result<Pin<&mut S>> {
        // The stream is there until the connection is dropped.
        match self.get_mut().stream.as_mut() {
            Some(stream) => Ok(Pin::new(stream)),
            None => Err(std::io::Error::from(std::io::ErrorKind::NotConnected)),
        }
    }
}

impl<S: ByteStream> Drop for Lingering<S> {
    fn drop(&mut self) {
        let Some(mut stream) = self.stream.take() else {
            return;
        };
        if self.peer_ended {
            // The peer sends nothing more: the connection is closed here, and no byte can
            // reach it afterwards.
            return;
        }
        let lingerers = self.lingerers.clone();
        let write_closed = self.write_closed;
        let place = lingerers.admit();
        let runtime = tokio::runtime::Handle::try_current();
        let (Some(place), Ok(runtime)) = (place, runtime) else {
            // No place or no runtime for the wait: the connection is closed here.
            lingerers.cut.fetch_add(1, Ordering::Relaxed);
            return;
        };
        runtime.spawn(async move {
            // The place is held until the connection is closed.
            let _place = place;
            if !end_after_peer(&mut stream, write_closed, lingerers.limit).await {
                lingerers.cut.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
}

/// Ends a connection the node is done with: closes its write side unless it is closed
/// already (`write_closed`), then reads and drops what the peer still sends until the peer
/// reports the end of its bytes or a read fails (the peer is gone). Returns false when
/// neither happened within `limit`.
///
/// A close of the write side that fails is the close of a connection whose peer is gone:
/// the reads say so. Most connections end with a peer that has ended already, so the first
/// read is a small one, and the buffer for a peer that goes on sending is taken after it.
pub async fn end_after_peer<S>(stream: &mut S, write_closed: bool, limit: Duration) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ended = async {
        if !write_closed {
            let _ = stream.shutdown().await;
        }
        let mut first = [0u8; 256];
        if !matches!(stream.read(&mut first).await, Ok(count) if count > 0) {
            return;
        }
        let mut dropped = vec![0u8; 16 * 1024];
        while matches!(stream.read(&mut dropped).await, Ok(count) if count > 0) {}
    };
    tokio::time::timeout(limit, ended).await.is_ok()
}

impl<S: ByteStream> AsyncRead for Lingering<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let Some(stream) = this.stream.as_mut() else {
            return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)));
        };
        let room = buffer.remaining();
        let outcome = std::task::ready!(Pin::new(stream).poll_read(cx, buffer));
        // A read that had room and gave no byte is the end of the bytes of the peer, and a
        // read that failed is a peer that is gone: either way the peer sends nothing more.
        this.peer_ended |= match &outcome {
            Ok(()) => room > 0 && buffer.remaining() == room,
            Err(_) => true,
        };
        Poll::Ready(outcome)
    }
}

impl<S: ByteStream> AsyncWrite for Lingering<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.stream() {
            Ok(stream) => stream.poll_write(cx, bytes),
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        slices: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match self.stream() {
            Ok(stream) => stream.poll_write_vectored(cx, slices),
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.as_ref().is_some_and(S::is_write_vectored)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.stream() {
            Ok(stream) => stream.poll_flush(cx),
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let Some(stream) = this.stream.as_mut() else {
            return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)));
        };
        let closed = std::task::ready!(Pin::new(stream).poll_shutdown(cx));
        this.write_closed |= closed.is_ok();
        Poll::Ready(closed)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::{Lingerers, Lingering, LINGER_LIMIT};

    /// A connection of the node and its peer. The pipe between them holds 64 bytes: a write
    /// of more than that is taken only while the other end reads.
    fn connection(
        lingerers: &std::sync::Arc<Lingerers>,
    ) -> (Lingering<DuplexStream>, DuplexStream) {
        let (near, far) = tokio::io::duplex(64);
        (Lingering::new(near, lingerers.clone()), far)
    }

    /// Lets the tasks that are ready run, without moving the clock.
    async fn settle() {
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_the_node_is_done_with_is_closed_after_its_peer_reported_its_end() {
        let lingerers = Lingerers::holding(4, LINGER_LIMIT);
        let (mut node, mut peer) = connection(&lingerers);
        node.write_all(b"answer").await.unwrap();
        // The peer is in the middle of a body when the node is done with the connection.
        peer.write_all(&[7u8; 32]).await.unwrap();
        drop(node);
        settle().await;
        assert_eq!((lingerers.waiting(), lingerers.cut()), (1, 0));

        // The peer reads the answer and the end of the bytes of the node: the node closed
        // its write side.
        let mut answer = Vec::new();
        peer.read_to_end(&mut answer).await.unwrap();
        assert_eq!(answer, b"answer");
        // The connection is still open: it takes what the peer sends, far more than the
        // pipe holds, and drops it.
        peer.write_all(&[7u8; 100_000]).await.unwrap();
        assert_eq!(lingerers.waiting(), 1);

        // The peer ends its bytes: the connection is closed, and it was not cut.
        peer.shutdown().await.unwrap();
        settle().await;
        assert_eq!((lingerers.waiting(), lingerers.cut()), (0, 0));
        assert!(peer.write_all(b"late").await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_whose_peer_is_gone_is_closed_at_once() {
        let lingerers = Lingerers::holding(4, LINGER_LIMIT);
        let (node, peer) = connection(&lingerers);
        drop(peer);
        drop(node);
        settle().await;
        assert_eq!((lingerers.waiting(), lingerers.cut()), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_that_does_not_report_its_end_is_cut_at_the_time_limit() {
        let lingerers = Lingerers::holding(4, Duration::from_secs(10));
        let (node, mut peer) = connection(&lingerers);
        drop(node);
        // The peer goes on sending and does not end: the connection reads on.
        for _ in 0..9 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            peer.write_all(&[7u8; 1000]).await.unwrap();
        }
        assert_eq!((lingerers.waiting(), lingerers.cut()), (1, 0));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        settle().await;
        assert_eq!((lingerers.waiting(), lingerers.cut()), (0, 1));
        assert!(peer.write_all(&[7u8; 1000]).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_dropped_above_the_bound_of_waiting_connections_is_closed_at_once() {
        let lingerers = Lingerers::holding(1, LINGER_LIMIT);
        let (first, mut first_peer) = connection(&lingerers);
        let (second, mut second_peer) = connection(&lingerers);
        drop(first);
        drop(second);
        settle().await;
        assert_eq!((lingerers.waiting(), lingerers.cut()), (1, 1));
        // The first waits for its peer, the second is closed.
        first_peer.write_all(&[7u8; 1000]).await.unwrap();
        assert!(second_peer.write_all(&[7u8; 1000]).await.is_err());

        // A place that is free again is taken by the next connection.
        first_peer.shutdown().await.unwrap();
        settle().await;
        let (third, mut third_peer) = connection(&lingerers);
        drop(third);
        settle().await;
        assert_eq!((lingerers.waiting(), lingerers.cut()), (1, 1));
        third_peer.write_all(&[7u8; 1000]).await.unwrap();
    }

    /// A stream that counts the closes of its write side.
    struct Counted {
        stream: DuplexStream,
        closes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl tokio::io::AsyncRead for Counted {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.stream).poll_read(cx, buffer)
        }
    }

    impl tokio::io::AsyncWrite for Counted {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.stream).poll_write(cx, bytes)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.stream).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.closes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_write_side_of_a_connection_is_closed_once() {
        let lingerers = Lingerers::holding(4, LINGER_LIMIT);
        let closes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = |stream| Counted {
            stream,
            closes: closes.clone(),
        };
        let closed = || closes.load(std::sync::atomic::Ordering::Relaxed);

        // What held the connection closed its write side when it was done: the wait reads
        // the end of the peer and does not close the write side again.
        let (near, mut peer) = tokio::io::duplex(64);
        let mut node = Lingering::new(counted(near), lingerers.clone());
        node.shutdown().await.unwrap();
        drop(node);
        settle().await;
        assert_eq!((closed(), lingerers.waiting()), (1, 1));
        peer.shutdown().await.unwrap();
        settle().await;
        assert_eq!((closed(), lingerers.waiting(), lingerers.cut()), (1, 0, 0));

        // A connection that was dropped as it was: the wait closes its write side.
        let (near, mut peer) = tokio::io::duplex(64);
        drop(Lingering::new(counted(near), lingerers.clone()));
        settle().await;
        assert_eq!(peer.read(&mut [0u8; 8]).await.unwrap(), 0);
        assert_eq!((closed(), lingerers.waiting()), (2, 1));
        peer.shutdown().await.unwrap();
        settle().await;
        assert_eq!((closed(), lingerers.waiting(), lingerers.cut()), (2, 0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_whose_peer_reported_its_end_is_closed_without_a_wait_and_a_count() {
        // No place for a wait: a connection that had to wait would be closed and counted.
        let lingerers = Lingerers::holding(0, LINGER_LIMIT);
        let (mut node, mut peer) = connection(&lingerers);
        peer.write_all(b"request").await.unwrap();
        peer.shutdown().await.unwrap();
        // The node reads the request and the end of the bytes of its peer, and answers.
        let mut request = Vec::new();
        node.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        node.write_all(b"answer").await.unwrap();
        drop(node);
        // The connection is closed with the drop: the peer reads the answer and the end,
        // and nothing was counted, because nothing can reach the connection any more.
        let mut answer = Vec::new();
        peer.read_to_end(&mut answer).await.unwrap();
        assert_eq!(answer, b"answer");
        assert_eq!((lingerers.waiting(), lingerers.cut()), (0, 0));

        // The same connection whose peer has not ended is closed before that end, and
        // counted.
        let (mut node, mut peer) = connection(&lingerers);
        peer.write_all(b"request").await.unwrap();
        let mut request = [0u8; 7];
        node.read_exact(&mut request).await.unwrap();
        drop(node);
        assert_eq!((lingerers.waiting(), lingerers.cut()), (0, 1));

        // A peer that is gone: the read gives its end.
        let (mut node, peer) = connection(&lingerers);
        drop(peer);
        assert_eq!(node.read(&mut [0u8; 8]).await.unwrap(), 0);
        drop(node);
        assert_eq!((lingerers.waiting(), lingerers.cut()), (0, 1));
    }

    #[test]
    fn a_connection_dropped_outside_a_runtime_is_closed_at_once() {
        let lingerers = Lingerers::holding(4, LINGER_LIMIT);
        let (node, _peer) = connection(&lingerers);
        drop(node);
        assert_eq!((lingerers.waiting(), lingerers.cut()), (0, 1));
    }
}
