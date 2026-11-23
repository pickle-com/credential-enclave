//! The calls in progress of a node at the shutdown of its pod (enclave.md section 9).
//!
//! A call the node is in the middle of when its enclave ends is cut: its caller reads a
//! connection that ended without a response or in the middle of one, and does not know
//! whether the request of the call reached the provider or the site. A `vault/send` call
//! carries the one request of an envelope, which is not sent a second time, and the request of
//! a `forward` call may have written at its provider. So the host program lets the calls in
//! progress end before it ends the enclave. On the termination signal it
//!
//! 1. calls `POST /v1/close` of the node, without a body ([`Wait::begin`]). A closed node
//!    begins no use of a credential and no request: a call that reaches it ends with
//!    `closing`, and its caller takes it to another node;
//! 2. waits until the node holds no place of a forward call (`forward_calls` of `load` of its
//!    `health` call). The calls that hold a place are the ones that carry a request to a
//!    provider or to a site and hand its response on: `forward`, `forward/batch` and the mail
//!    calls on a node of the delegation role, `vault/send` on a node of the forward role. A
//!    call holds its place from before it reads the closing flag to the end of its response
//!    body. So a closed node that holds no place has no such request in progress and begins
//!    none;
//! 3. closes the door of the inbound relay ([`InboundDoor::close`]): the relay takes its
//!    listener off the network of the pod, takes the connections that wait in the queue of
//!    the listener and those whose handshake the kernel had answered, and closes the listener
//!    (`crate::relay::HANDSHAKE_GRACE` later). A caller that connects from then on is refused
//!    by the kernel. A connection the relay took while
//!    the enclave ended would end without a response, and its caller could not tell whether
//!    the node had acted on its request: a refused connection did not open, and its caller
//!    takes any call to another node, as it does with the answer `closing`;
//! 4. waits until the inbound relay holds no connection of a caller: the last part of a
//!    response and the end record of its stream may still be on their way to the caller, a
//!    call that holds no place (`refresh`, `oauth/complete`, `release`, a command of an app)
//!    ends within the time of this wait, and a call that reached the closed node last gets
//!    its answer `closing`.
//!
//! In a pod of the delegation role or of the reserve role the shutdown collection call
//! (`drain`) runs between step 1 and step 2: the backend moves the delegations of the node
//! while its calls in progress end. A node of the reserve role answers none of the calls of
//! step 2 and holds no place. The wait of step 2 counts from the termination signal in
//! every role.
//!
//! Each of the two waits has a limit ([`CALLS_WAIT`], [`CALLERS_WAIT`]), and the enclave ends
//! after them whatever the node said. A node that does not answer is asked again until the
//! limit: its calls may be going on all the same. The door of the relay is closed before the
//! enclave ends however the waits ended (`main.rs`).

use std::time::Duration;

use hyper::Method;
use tokio::time::Instant;

use crate::health::node_health;
use crate::http;
use crate::log;
use crate::relay::{InboundDoor, NodeConnector, Pipes};
use crate::watch::EnclaveWatch;

/// The longest wait for the node to hold no place of a forward call, from the termination
/// signal: 660 seconds. 600 of them are the longest time limit of one call that holds a place:
/// that of a `forward` call that asked for its response as a stream (`timeout_ms`, enclave.md
/// 5.8: the time from the confirmation of its entry to the end of the body of the provider)
/// and that of a `vault/send` call (enclave.md 5.16: the time from the moment its request
/// leaves to the end of its response body). The other 60 are the time within which a call
/// that held its place when the node was closed begins its request. A call of the delegation
/// role has its entry confirmed first, and the node waits for the log store for at most
/// twice the time of a write, 10 seconds, at each of its two steps (enclave.md 5.14). A
/// `vault/send` call sends the request of an envelope before the end of that envelope, and
/// the node takes no envelope whose end lies more than 60 seconds ahead (protocol.md 10.5).
/// A place that is held after that time is the place of no request to a provider or a site.
pub const CALLS_WAIT: Duration = Duration::from_secs(660);
/// The longest wait for the connections of the callers, from the moment the node holds no
/// place and the inbound relay takes no further connection: 60 seconds, the time for which
/// the node itself waits for a caller to take bytes of a response (`inbound_idle`, enclave.md
/// section 8). The calls that hold no place end within it as well: the time limit of a token
/// address call is 15 seconds (enclave.md 6.3).
pub const CALLERS_WAIT: Duration = Duration::from_secs(60);
/// The longest time from the termination signal to the end of the two waits. The
/// `terminationGracePeriodSeconds` of a pod covers it with a margin (enclave.md section 9).
pub const WAIT_LONGEST: Duration = Duration::from_secs(720);
const _: () = assert!(WAIT_LONGEST.as_secs() == CALLS_WAIT.as_secs() + CALLERS_WAIT.as_secs());

/// Pause between two looks at the node.
const POLL_PAUSE: Duration = Duration::from_millis(500);
/// Pause between two looks at the connections of the callers. The relay takes no further
/// connection then, and the connections it holds end within milliseconds when nothing but
/// answers `closing` is on its way: the enclave ends as soon as they have ended.
const CALLERS_POLL_PAUSE: Duration = Duration::from_millis(20);
/// Longest round trip of the `close` call.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest response body of the `close` call the host program reads.
const CLOSE_REPLY_LIMIT_BYTES: usize = 4096;

/// How the wait for the calls of a node ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The node is closed and holds no place of a forward call, the inbound relay takes no
    /// further connection, and every connection of a caller it held has ended.
    Finished,
    /// The node did not say within [`CALLS_WAIT`] that it holds no place.
    CallsLeft {
        /// Whether the node took the `close` call.
        closed: bool,
        /// The places of forward calls the node held at its last answer, `None` when it gave
        /// no answer after the close.
        calls: Option<u64>,
    },
    /// The node holds no place, and connections of callers the inbound relay held when it
    /// closed its listener are still open [`CALLERS_WAIT`] later.
    CallersLeft {
        /// The number of these connections.
        callers: usize,
    },
    /// The watch of the enclave confirmed that the enclave ended on its own: no call is in
    /// progress in an enclave that is gone.
    EnclaveEnded,
}

impl Outcome {
    /// The line of the log that names the outcome.
    pub fn line(&self) -> String {
        match self {
            Outcome::Finished => "calls: every response has left".to_string(),
            Outcome::CallsLeft { closed, calls } => format!(
                "calls: the wait ended at its limit of {} s: the node {}, {}",
                CALLS_WAIT.as_secs(),
                match closed {
                    true => "is closed",
                    false => "did not take the close call",
                },
                match calls {
                    Some(calls) => format!("{calls} calls in progress at its last answer"),
                    None => "no answer about its calls".to_string(),
                },
            ),
            Outcome::CallersLeft { callers } => format!(
                "calls: {callers} connections of callers are still open {} s after the last \
                 call ended",
                CALLERS_WAIT.as_secs()
            ),
            Outcome::EnclaveEnded => {
                "calls: the enclave ended on its own, nothing is left to wait for".to_string()
            }
        }
    }
}

/// Calls `POST /v1/close` of the node, without a body: a node answers the call before it
/// reads a body, and the answer to a call that is still sending can be lost on its way.
/// True when the node answered with the status 200.
async fn close(node: &dyn NodeConnector) -> bool {
    let call = async {
        let stream = node.connect().await.ok()?;
        let request =
            http::request(Method::POST, http::NODE_HOST, "/v1/close", &[], Vec::new()).ok()?;
        http::exchange(stream, request, CLOSE_REPLY_LIMIT_BYTES)
            .await
            .ok()
    };
    matches!(
        tokio::time::timeout(CLOSE_TIMEOUT, call).await,
        Ok(Some(reply)) if reply.status == 200
    )
}

/// The places of forward calls the node holds at this moment (`forward_calls` of `load` of
/// its `health` call), `None` when the node gives no such answer.
async fn calls_in_progress(node: &dyn NodeConnector) -> Option<u64> {
    let health = node_health(node).await?;
    Some(health.load?.forward_calls)
}

/// The wait of one shutdown for the calls in progress of the node (the four steps of the
/// module). It begins with the termination signal, and its limits count from there.
pub struct Wait<'a> {
    node: &'a dyn NodeConnector,
    callers: &'a Pipes,
    /// The door of the inbound relay that holds `callers`.
    door: &'a InboundDoor,
    /// The moment of the termination signal.
    started: Instant,
    /// Whether the node took the `close` call.
    closed: bool,
}

impl<'a> Wait<'a> {
    /// Step 1, at the termination signal: closes the node, in one attempt. A node that does
    /// not take the call is asked again by [`Wait::finish`]. One line of the log names the
    /// limits of the wait, and one the close.
    pub async fn begin(
        node: &'a dyn NodeConnector,
        callers: &'a Pipes,
        door: &'a InboundDoor,
    ) -> Wait<'a> {
        let started = Instant::now();
        log(&format!(
            "calls: closing the node, then waiting {} s at the most for its calls in progress \
             and {} s for their callers",
            CALLS_WAIT.as_secs(),
            CALLERS_WAIT.as_secs()
        ));
        let mut wait = Wait {
            node,
            callers,
            door,
            started,
            closed: false,
        };
        wait.close().await;
        wait
    }

    fn elapsed_ms(&self) -> u128 {
        self.started.elapsed().as_millis()
    }

    /// One attempt to close a node that is not closed yet, within the limit of the calls.
    async fn close(&mut self) {
        self.closed = tokio::time::timeout_at(self.started + CALLS_WAIT, close(self.node))
            .await
            .unwrap_or(false);
        if self.closed {
            log(&format!(
                "calls: the node is closed after {} ms, it begins no request",
                self.elapsed_ms()
            ));
        }
    }

    /// Steps 2 to 4: waits for the calls in progress of the node, for [`CALLS_WAIT`] at the
    /// most from the termination signal until the node holds no place, then closes the door
    /// of the inbound relay and waits for the connections the relay holds, for
    /// [`CALLERS_WAIT`] at the most. One line of the log names each step that is done, with
    /// the milliseconds since the signal.
    pub async fn finish(mut self) -> Outcome {
        let mut calls: Option<u64> = None;
        // Set when the closed node first holds no place and the relay has closed its
        // listener: the limit of the wait for the connections of callers the relay holds.
        let mut ended: Option<Instant> = None;
        loop {
            // The limit of the wait that is going on. No call to the node outlasts it.
            let limit = ended.unwrap_or(self.started + CALLS_WAIT);
            if !self.closed {
                self.close().await;
            }
            // A closed node that held no place once holds none later: it is not asked again.
            if self.closed && ended.is_none() {
                let answer = tokio::time::timeout_at(limit, calls_in_progress(self.node))
                    .await
                    .unwrap_or(None);
                match answer {
                    Some(0) => {
                        // The relay closes its listener within the wait for the handshakes
                        // the kernel had answered. A relay that does not is not waited for
                        // past the limit of the calls.
                        let _ = tokio::time::timeout_at(limit, self.door.close()).await;
                        ended = Some(Instant::now() + CALLERS_WAIT);
                        log(&format!(
                            "calls: none in progress after {} ms, the inbound relay takes no \
                             further connection, {} connections of callers are open",
                            self.elapsed_ms(),
                            self.callers.held()
                        ));
                    }
                    Some(count) if calls != Some(count) => log(&format!(
                        "calls: {count} in progress after {} ms",
                        self.elapsed_ms()
                    )),
                    _ => {}
                }
                calls = answer.or(calls);
            }
            let now = Instant::now();
            match ended {
                Some(limit) => {
                    let left = self.callers.held();
                    if left == 0 {
                        log(&format!(
                            "calls: the connections of the callers have ended after {} ms",
                            self.elapsed_ms()
                        ));
                        return Outcome::Finished;
                    }
                    if now >= limit {
                        return Outcome::CallersLeft { callers: left };
                    }
                    tokio::time::sleep_until((now + CALLERS_POLL_PAUSE).min(limit)).await;
                }
                None => {
                    if now >= limit {
                        return Outcome::CallsLeft {
                            closed: self.closed,
                            calls,
                        };
                    }
                    tokio::time::sleep_until((now + POLL_PAUSE).min(limit)).await;
                }
            }
        }
    }

    /// [`Wait::finish`], unless the watch of the enclave confirms first that the enclave ended
    /// on its own: an enclave that is gone holds no call, and nothing is left to wait for.
    pub async fn finish_unless_ended(self, watch: &EnclaveWatch) -> Outcome {
        tokio::select! {
            outcome = self.finish() => outcome,
            _ = watch.wait_ended() => Outcome::EnclaveEnded,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::relay::inbound_door;
    use crate::testing::{health_body_with_limit, Behavior, Call, FakeNode};

    /// The answers of a node: `close` is answered with 200, and `health` says that `calls`
    /// forward calls hold a place.
    fn answers(calls: Arc<AtomicU64>) -> Behavior {
        Behavior::Answer(Arc::new(move |call: &Call| match call.path.as_str() {
            "/v1/close" => (200, r#"{"accounts":0}"#.to_string()),
            "/v1/health" => {
                let health = health_body_with_limit(true, 0, 1).replace(
                    r#""forward_calls":5"#,
                    &format!(r#""forward_calls":{}"#, calls.load(Ordering::SeqCst)),
                );
                (200, health)
            }
            _ => (404, "{}".to_string()),
        }))
    }

    fn close_calls(node: &FakeNode) -> usize {
        node.calls()
            .iter()
            .filter(|call| call.path == "/v1/close")
            .count()
    }

    /// The whole wait of a pod whose shutdown has nothing between the close and the wait. No
    /// relay holds the other half of the door: it is closed at once when the wait closes it.
    async fn finish(node: &FakeNode, callers: &Pipes) -> Outcome {
        let (door, _) = inbound_door();
        Wait::begin(node, callers, &door).await.finish().await
    }

    #[tokio::test(start_paused = true)]
    async fn the_shutdown_closes_the_node_and_waits_for_its_calls_and_for_their_callers() {
        let calls = Arc::new(AtomicU64::new(2));
        let node = FakeNode::new(answers(calls.clone()));
        let callers = Pipes::new(16);
        // The connection of the caller of a call in progress.
        let caller = callers.admit().unwrap();
        let waiting = {
            let (node, callers) = (node.clone(), callers.clone());
            tokio::spawn(async move { finish(node.as_ref(), &callers).await })
        };

        // Two calls are in progress: the wait goes on. The first call the node received is
        // the close, without a body, and every call after it reads its health.
        tokio::time::sleep(Duration::from_secs(120)).await;
        assert!(!waiting.is_finished());
        let received = node.calls();
        assert_eq!(
            received.first(),
            Some(&Call {
                method: "POST".to_string(),
                path: "/v1/close".to_string(),
                body: Vec::new(),
            })
        );
        assert!(received.len() > 100, "{}", received.len());
        assert!(received
            .iter()
            .skip(1)
            .all(|call| call.method == "GET" && call.path == "/v1/health"));

        // The calls ended. The connection of their caller is still open: the end of a
        // response may be on its way through it.
        calls.store(0, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!waiting.is_finished());
        // A closed node that held no place is not asked again.
        let asked = node.calls().len();
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(node.calls().len(), asked);

        // The wait ends when the relay holds no connection of a caller.
        drop(caller);
        assert_eq!(waiting.await.unwrap(), Outcome::Finished);
        assert_eq!(callers.held(), 0);
        assert_eq!(close_calls(&node), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_relay_closes_its_door_when_the_node_holds_no_place_and_is_waited_for() {
        let calls = Arc::new(AtomicU64::new(1));
        let node = FakeNode::new(answers(calls.clone()));
        let callers = Pipes::new(16);
        // The connection of the caller of the call in progress, and the connection of a
        // caller that reached the closed node and is reading its answer `closing`.
        let caller = callers.admit().unwrap();
        let refused = callers.admit().unwrap();
        let (door, mut order) = inbound_door();
        let started = Instant::now();
        // The relay: it closes its listener when it is told, 300 milliseconds after the
        // order in this test, and says when the order came.
        let relay = tokio::spawn(async move {
            order.told_to_close().await;
            let told = Instant::now();
            tokio::time::sleep(Duration::from_millis(300)).await;
            told
        });
        let waiting = {
            let (node, callers) = (node.clone(), callers.clone());
            tokio::spawn(async move {
                Wait::begin(node.as_ref(), &callers, &door)
                    .await
                    .finish()
                    .await
            })
        };

        // A call holds its place: the backend may still be calling the node through the
        // relay, and the door stays open.
        tokio::time::sleep(Duration::from_secs(100)).await;
        assert!(!relay.is_finished());
        assert!(!waiting.is_finished());

        // The node holds no place: the relay is told at the next look at the node, and the
        // wait goes on only after the relay has closed its listener.
        calls.store(0, Ordering::SeqCst);
        let told = relay.await.unwrap();
        let waited = told - started;
        assert!(
            waited >= Duration::from_secs(100) && waited <= Duration::from_secs(100) + POLL_PAUSE,
            "{waited:?}"
        );
        assert!(!waiting.is_finished());

        // Every connection the relay holds is waited for: the one of the call that was in
        // progress, and the one that reached the closed node last. The wait ends within one
        // look at the connections after the last of them ended.
        drop(caller);
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!waiting.is_finished());
        let ended = Instant::now();
        drop(refused);
        assert_eq!(waiting.await.unwrap(), Outcome::Finished);
        assert!(
            ended.elapsed() <= CALLERS_POLL_PAUSE,
            "{:?}",
            ended.elapsed()
        );
        assert_eq!(callers.held(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_without_a_call_in_progress_ends_at_once() {
        let node = FakeNode::new(answers(Arc::new(AtomicU64::new(0))));
        let callers = Pipes::new(16);
        let started = Instant::now();
        assert_eq!(finish(node.as_ref(), &callers).await, Outcome::Finished);
        assert_eq!(started.elapsed(), Duration::ZERO);
        let paths: Vec<String> = node.calls().into_iter().map(|call| call.path).collect();
        assert_eq!(paths, ["/v1/close", "/v1/health"]);
    }

    #[tokio::test(start_paused = true)]
    async fn each_of_the_two_waits_ends_at_its_limit() {
        assert_eq!(CALLS_WAIT, Duration::from_secs(660));
        assert_eq!(CALLERS_WAIT, Duration::from_secs(60));
        assert_eq!(WAIT_LONGEST, Duration::from_secs(720));

        // A place that is held for longer than a call can last.
        let node = FakeNode::new(answers(Arc::new(AtomicU64::new(1))));
        let callers = Pipes::new(16);
        let started = Instant::now();
        assert_eq!(
            finish(node.as_ref(), &callers).await,
            Outcome::CallsLeft {
                closed: true,
                calls: Some(1),
            }
        );
        assert_eq!(started.elapsed(), CALLS_WAIT);

        // A caller that does not take the end of its response: the last call ended 100
        // seconds after the signal, and the connection of the caller stays open.
        let calls = Arc::new(AtomicU64::new(1));
        let node = FakeNode::new(answers(calls.clone()));
        let _caller = callers.admit().unwrap();
        let started = Instant::now();
        let waiting = {
            let (node, callers) = (node.clone(), callers.clone());
            tokio::spawn(async move { finish(node.as_ref(), &callers).await })
        };
        tokio::time::sleep(Duration::from_secs(100)).await;
        calls.store(0, Ordering::SeqCst);
        assert_eq!(waiting.await.unwrap(), Outcome::CallersLeft { callers: 1 });
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_secs(100) + CALLERS_WAIT
                && waited <= Duration::from_secs(100) + CALLERS_WAIT + POLL_PAUSE,
            "{waited:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_wait_counts_from_the_signal_across_what_runs_after_the_close() {
        // A pod of the delegation role: the node is closed at the signal, the shutdown
        // collection call takes its time, and only then the host program looks at the calls.
        let calls = Arc::new(AtomicU64::new(3));
        let node = FakeNode::new(answers(calls.clone()));
        let callers = Pipes::new(16);
        let (door, _) = inbound_door();
        let started = Instant::now();
        let wait = Wait::begin(node.as_ref(), &callers, &door).await;
        // The node is closed before anything else happens: one call, the close.
        assert_eq!(started.elapsed(), Duration::ZERO);
        let paths: Vec<String> = node.calls().into_iter().map(|call| call.path).collect();
        assert_eq!(paths, ["/v1/close"]);

        // The collection takes 600 seconds, its longest wait. A call that is still in
        // progress then has the 60 seconds that are left of the 660 since the signal, not
        // 660 seconds more.
        tokio::time::sleep(Duration::from_secs(600)).await;
        assert_eq!(
            wait.finish().await,
            Outcome::CallsLeft {
                closed: true,
                calls: Some(3),
            }
        );
        assert_eq!(started.elapsed(), CALLS_WAIT);
        // The node that took the close at the signal is not closed a second time.
        assert_eq!(close_calls(&node), 1);

        // The calls that were in progress at the signal ended while the collection ran: the
        // wait ends at its first look, and the connection of a caller that is open then has
        // its 60 seconds from that look.
        let calls = Arc::new(AtomicU64::new(1));
        let node = FakeNode::new(answers(calls.clone()));
        let caller = callers.admit().unwrap();
        let started = Instant::now();
        let wait = Wait::begin(node.as_ref(), &callers, &door).await;
        tokio::time::sleep(Duration::from_secs(20)).await;
        calls.store(0, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(280)).await;
        let waiting = tokio::spawn({
            let callers = callers.clone();
            async move {
                tokio::time::sleep(Duration::from_secs(7)).await;
                drop(caller);
                callers.held()
            }
        });
        assert_eq!(wait.finish().await, Outcome::Finished);
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_secs(307) && waited <= Duration::from_secs(307) + POLL_PAUSE,
            "{waited:?}"
        );
        assert_eq!(waiting.await.unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_that_does_not_take_the_close_call_is_asked_again() {
        let node = FakeNode::new(Behavior::Unreachable);
        let callers = Pipes::new(16);
        let waiting = {
            let (node, callers) = (node.clone(), callers.clone());
            tokio::spawn(async move { finish(node.as_ref(), &callers).await })
        };
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(!waiting.is_finished());
        assert!(node.calls().is_empty());

        // A node that answers the close with another status is not closed: its health is
        // not read, and the close is repeated.
        node.set(Behavior::Answer(Arc::new(|_: &Call| {
            (503, "{}".to_string())
        })));
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(!waiting.is_finished());
        let received = node.calls();
        assert!(received.len() > 1 && received.iter().all(|call| call.path == "/v1/close"));

        node.set(answers(Arc::new(AtomicU64::new(0))));
        assert_eq!(waiting.await.unwrap(), Outcome::Finished);

        // A node that never answers: the wait ends at the limit of the calls.
        let node = FakeNode::new(Behavior::Silent);
        let started = Instant::now();
        assert_eq!(
            finish(node.as_ref(), &callers).await,
            Outcome::CallsLeft {
                closed: false,
                calls: None,
            }
        );
        assert_eq!(started.elapsed(), CALLS_WAIT);

        // A node that did not take the close at the signal takes it after the collection.
        let node = FakeNode::new(Behavior::Unreachable);
        let (door, _) = inbound_door();
        let wait = Wait::begin(node.as_ref(), &callers, &door).await;
        assert!(node.calls().is_empty());
        node.set(answers(Arc::new(AtomicU64::new(0))));
        assert_eq!(wait.finish().await, Outcome::Finished);
        assert_eq!(close_calls(&node), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn an_enclave_that_ended_on_its_own_is_not_waited_for() {
        // A call in progress, as the node last said, and then the enclave is gone.
        let node = FakeNode::new(answers(Arc::new(AtomicU64::new(1))));
        let callers = Pipes::new(16);
        let watch = EnclaveWatch::new();
        let waiting = {
            let (node, callers, watch) = (node.clone(), callers.clone(), watch.clone());
            tokio::spawn(async move {
                let (door, _) = inbound_door();
                Wait::begin(node.as_ref(), &callers, &door)
                    .await
                    .finish_unless_ended(&watch)
                    .await
            })
        };
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert!(!waiting.is_finished());
        for _ in 0..crate::watch::GONE_POLLS {
            watch.observe(Some(false));
        }
        assert_eq!(waiting.await.unwrap(), Outcome::EnclaveEnded);

        // Without the end of the enclave the outcome is that of the wait.
        let node = FakeNode::new(answers(Arc::new(AtomicU64::new(0))));
        let watch = EnclaveWatch::new();
        let (door, _) = inbound_door();
        assert_eq!(
            Wait::begin(node.as_ref(), &callers, &door)
                .await
                .finish_unless_ended(&watch)
                .await,
            Outcome::Finished
        );
    }

    #[test]
    fn the_line_of_an_outcome_names_what_was_left() {
        assert_eq!(Outcome::Finished.line(), "calls: every response has left");
        assert_eq!(
            Outcome::CallsLeft {
                closed: true,
                calls: Some(2),
            }
            .line(),
            "calls: the wait ended at its limit of 660 s: the node is closed, 2 calls in \
             progress at its last answer"
        );
        assert_eq!(
            Outcome::CallsLeft {
                closed: false,
                calls: None,
            }
            .line(),
            "calls: the wait ended at its limit of 660 s: the node did not take the close \
             call, no answer about its calls"
        );
        assert_eq!(
            Outcome::CallersLeft { callers: 3 }.line(),
            "calls: 3 connections of callers are still open 60 s after the last call ended"
        );
    }
}
