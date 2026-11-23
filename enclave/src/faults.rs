//! What a fault of the node program ends (enclave.md 3.1).
//!
//! A panic is a fault: a place of this program, or of a library it is built with, that met a
//! state it has no answer for. A node that ends takes the delegations it holds with it, so the
//! program is built to unwind on a panic (the release profile), and a panic ends the smallest
//! part of the node that it can have left in doubt:
//!
//! - **One call.** The work of a call runs on the task of its connection and on tasks that
//!   call started. A panic there ends the call: its connection ends without a response, and
//!   what the call held (its place among the connections, a place among the forward calls, a
//!   share of the body budget, the entries it was writing) is given back by the values that
//!   hold it, as when the caller closes the connection. A call that waits for a task it
//!   started takes a panic of that task as its own ([`joined`]).
//! - **One account.** A panic while the lock of the state of an account was held can have left
//!   that state half changed. The node gives the state up: the account is halted on this node
//!   (`crate::state::AccountLock`).
//! - **The process.** A panic while a lock of the state of the whole node was held
//!   ([`NodeLock`], [`NodeRwLock`]), and a panic of a task the node cannot do without
//!   ([`vital`]), end the process: the node could no longer say that it keeps its rules.
//!
//! A panic of a value that is dropped while another panic unwinds ends the process as well:
//! the standard library does not unwind out of such a drop. It writes one line of its own to
//! the standard error then, a fixed string that holds nothing of either panic.
//!
//! No panic writes anything ([`silence`]: rule E5 of the egress policy). The panics of the
//! process are counted ([`panics`]), and `health` reports the count: a panic that was counted
//! and did not end the process is a fault the node contained.

use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::task::{Context, Poll};

use tokio::task::JoinHandle;

/// The panics of this process since it started.
static PANICS: AtomicU64 = AtomicU64::new(0);

/// Counts one panic. The panic hook of the node calls it ([`silence`]).
pub fn count_panic() {
    PANICS.fetch_add(1, Ordering::Relaxed);
}

/// The panics of this process since it started (`contained_panics` of `load` of health): each
/// of them ended a call or halted an account, and none of them ended the process, which
/// answers the call that reads the count.
pub fn panics() -> u64 {
    PANICS.load(Ordering::Relaxed)
}

/// Makes a panic of this process silent: the panic hook writes nothing and counts the panic.
/// The message of a panic can hold a value of the call it happened in, and the node writes no
/// output of its own making (rule E5 of the egress policy). The node calls this before it
/// starts anything else.
pub fn silence() {
    std::panic::set_hook(Box::new(|_| count_panic()));
}

/// Ends the process at once: nothing is unwound and nothing is written. An enclave ends with
/// its node program, and the delegations of the node are gone with it.
fn end_process() -> ! {
    std::process::abort()
}

/// A task the node cannot do without: when `task` panics, the process ends. A task that
/// returns, and a task that is dropped when the runtime ends, end nothing.
///
/// The node runs three tasks this way (`main.rs`): the task that starts the node and accepts
/// its connections, the task that corrects the clock and the task of the sweep. Without the
/// first the node answers nothing, without the second its time is the time of its last
/// correction, and without the third a grant whose time passed keeps its user key in memory
/// and a pending entry stays out of the store: a node that went on without one of them would
/// break a rule in silence.
pub fn vital<F: Future>(task: F) -> Vital<F> {
    Vital(Box::pin(task))
}

/// The future of [`vital`].
pub struct Vital<F>(Pin<Box<F>>);

impl<F: Future> Future for Vital<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<F::Output> {
        // A task that panicked is not polled again: the process ends here.
        match catch_unwind(AssertUnwindSafe(|| self.0.as_mut().poll(context))) {
            Ok(poll) => poll,
            Err(_) => end_process(),
        }
    }
}

/// The output of a task that a call started and waits for: `None` when the task was ended
/// before it had one. A panic of the task goes on in the call that waits: the work of a call
/// is one piece, and a call whose task panicked ends as a call that panicked itself does,
/// without a response. The call has no answer to give for such a task: an act of the call
/// may lie behind the task (the request to a provider whose response the task was reading),
/// and a failure response would say that the call can be repeated.
pub async fn joined<T>(task: &mut JoinHandle<T>) -> Option<T> {
    match task.await {
        Ok(output) => Some(output),
        Err(error) => match error.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            Err(_) => None,
        },
    }
}

/// A lock of the node. The kind of a lock says what a panic under it ends:
///
/// | Lock | What it guards | A panic while it was held |
/// | --- | --- | --- |
/// | `crate::state::AccountLock` | The state of one account | Halts that account on this node |
/// | [`NodeLock`], [`NodeRwLock`] | State of the whole node | Ends the process |
///
/// A lock is held around changes of the state it guards and around nothing else: no call
/// waits, and no byte of a provider is read, under one.
pub trait Lock {
    /// The state the lock guards.
    type State;

    /// Waits for the lock and returns its state.
    fn acquire(&self) -> MutexGuard<'_, Self::State>;
}

impl<L: Lock + ?Sized> Lock for Arc<L> {
    type State = L::State;

    fn acquire(&self) -> MutexGuard<'_, L::State> {
        (**self).acquire()
    }
}

impl<L: Lock + ?Sized> Lock for &L {
    type State = L::State;

    fn acquire(&self) -> MutexGuard<'_, L::State> {
        (**self).acquire()
    }
}

/// Waits for a lock of the node and returns the state it guards. What the call does when a
/// panic began while the lock was held is the rule of the kind of the lock ([`Lock`]).
pub fn lock<L: Lock + ?Sized>(lock: &L) -> MutexGuard<'_, L::State> {
    lock.acquire()
}

/// A lock that guards state of the whole node: the challenges it issued, the authorizations
/// in progress, its idle connections.
///
/// A panic while it was held ends the process, at the next call that asks for the lock: the
/// state it guards may be half changed, every account of the node depends on it, and the node
/// has no smaller part to give up.
#[derive(Default)]
pub struct NodeLock<T>(Mutex<T>);

impl<T> NodeLock<T> {
    /// A lock around `state`.
    pub fn new(state: T) -> NodeLock<T> {
        NodeLock(Mutex::new(state))
    }
}

impl<T> Lock for NodeLock<T> {
    type State = T;

    fn acquire(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap_or_else(|_| end_process())
    }
}

/// A lock that guards state of the whole node which is read far more often than it changes:
/// the index of the accounts, the operator configuration, the credentials for the log store.
/// A panic while a writer held it ends the process, as for a [`NodeLock`].
#[derive(Default)]
pub struct NodeRwLock<T>(RwLock<T>);

impl<T> NodeRwLock<T> {
    /// A lock around `state`.
    pub fn new(state: T) -> NodeRwLock<T> {
        NodeRwLock(RwLock::new(state))
    }

    /// Waits for the lock and returns its state for reading.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        self.0.read().unwrap_or_else(|_| end_process())
    }

    /// Waits for the lock and returns its state for a change.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.0.write().unwrap_or_else(|_| end_process())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::testing::{in_own_process, quiet_panics, ScriptedFault, OWN_PROCESS};

    /// Poisons `lock`: a thread takes it and panics.
    fn poison<L: Lock + Send + Sync + 'static>(lock: &Arc<L>) {
        let held = lock.clone();
        let panicked = std::thread::spawn(move || {
            let _state = held.acquire();
            std::panic::panic_any(ScriptedFault);
        })
        .join();
        assert!(panicked.is_err());
    }

    #[test]
    fn a_panic_under_a_lock_of_the_node_ends_the_process_at_the_next_lock() {
        if std::env::var(OWN_PROCESS).as_deref() == Ok("mutex") {
            quiet_panics();
            let state = Arc::new(NodeLock::new(0u32));
            *lock(&state) += 1;
            poison(&state);
            // The process ends here: the line after it is not reached.
            drop(lock(&state));
            std::process::exit(0);
        }
        if std::env::var(OWN_PROCESS).as_deref() == Ok("rwlock") {
            quiet_panics();
            let state = Arc::new(NodeRwLock::new(0u32));
            *state.write() += 1;
            let held = state.clone();
            let panicked = std::thread::spawn(move || {
                let _state = held.write();
                std::panic::panic_any(ScriptedFault);
            })
            .join();
            assert!(panicked.is_err());
            drop(state.read());
            std::process::exit(0);
        }
        for kind in ["mutex", "rwlock"] {
            let ended = in_own_process(
                "faults::tests::a_panic_under_a_lock_of_the_node_ends_the_process_at_the_next_lock",
                kind,
            );
            assert!(ended.aborted(), "{kind}: {ended:?}");
        }
    }

    #[test]
    fn a_panic_of_a_task_the_node_cannot_do_without_ends_the_process() {
        if std::env::var(OWN_PROCESS).as_deref() == Ok("vital") {
            quiet_panics();
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let task = tokio::spawn(vital(async {
                    tokio::task::yield_now().await;
                    std::panic::panic_any(ScriptedFault);
                }));
                // The process ends inside the task: the line after it is not reached.
                let _ = task.await;
            });
            std::process::exit(0);
        }
        if std::env::var(OWN_PROCESS).as_deref() == Ok("other") {
            quiet_panics();
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            // Another task that panics ends alone, a task the node cannot do without that
            // returns ends nothing, and neither does one the runtime drops at its end.
            let outcome = runtime.block_on(async {
                let alone = tokio::spawn(async {
                    std::panic::panic_any(ScriptedFault);
                });
                let returned = tokio::spawn(vital(async { 5 }));
                tokio::spawn(vital(std::future::pending::<()>()));
                (alone.await.is_err(), returned.await.ok())
            });
            drop(runtime);
            std::process::exit(if outcome == (true, Some(5)) { 7 } else { 1 });
        }
        let name = "faults::tests::a_panic_of_a_task_the_node_cannot_do_without_ends_the_process";
        let ended = in_own_process(name, "vital");
        assert!(ended.aborted(), "{ended:?}");
        let ended = in_own_process(name, "other");
        assert_eq!(ended.code, Some(7), "{ended:?}");
    }

    #[test]
    fn a_panic_of_the_node_writes_nothing_and_is_counted() {
        if std::env::var(OWN_PROCESS).as_deref() == Ok("silent") {
            // The hook of the node program, as its `main` installs it.
            silence();
            let before = panics();
            let panicked = std::thread::spawn(|| {
                let secret = "a value of a call";
                panic!("{secret}");
            })
            .join();
            let counted = panics() - before;
            std::process::exit(if panicked.is_err() && counted == 1 {
                7
            } else {
                1
            });
        }
        let ended = in_own_process(
            "faults::tests::a_panic_of_the_node_writes_nothing_and_is_counted",
            "silent",
        );
        assert_eq!(ended.code, Some(7), "{ended:?}");
        // Nothing of the panic is on the standard error: no message, no place, no thread.
        assert!(!ended.stderr.contains("a value of a call"), "{ended:?}");
        assert!(!ended.stderr.contains("panicked"), "{ended:?}");
    }

    #[test]
    fn a_second_panic_while_a_first_unwinds_ends_the_process_and_writes_no_value() {
        /// A value that panics when it is dropped.
        struct Held;

        impl Drop for Held {
            fn drop(&mut self) {
                let value = "a value of a destructor";
                panic!("{value}");
            }
        }

        if std::env::var(OWN_PROCESS).as_deref() == Ok("second") {
            // The hook of the node program, as its `main` installs it.
            silence();
            let _ = std::thread::spawn(|| {
                let _held = Held;
                let value = "a value of a call";
                panic!("{value}");
            })
            .join();
            // The process ends while the thread unwinds: this line is not reached.
            std::process::exit(0);
        }
        let ended = in_own_process(
            "faults::tests::a_second_panic_while_a_first_unwinds_ends_the_process_and_writes_no_value",
            "second",
        );
        assert!(ended.aborted(), "{ended:?}");
        // The standard library ends the process and says so in a line of its own. Nothing of
        // the two panics is on the standard error: no message and no place.
        assert!(!ended.stderr.contains("a value of"), "{ended:?}");
        assert!(!ended.stderr.contains("faults.rs"), "{ended:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_call_takes_the_panic_of_a_task_it_waits_for_as_its_own() {
        quiet_panics();
        // A task that returns gives its output, and a task that was ended gives none.
        let mut done = tokio::spawn(async { 5 });
        assert_eq!(joined(&mut done).await, Some(5));
        let mut ended = tokio::spawn(std::future::pending::<u8>());
        ended.abort();
        assert_eq!(joined(&mut ended).await, None);
        // A task that panicked: the call that waits for it panics with the same value.
        let call = tokio::spawn(async {
            let mut task = tokio::task::spawn_blocking(|| -> u8 {
                std::panic::panic_any(ScriptedFault);
            });
            joined(&mut task).await
        });
        let panic = call.await.unwrap_err().into_panic();
        assert!(panic.is::<ScriptedFault>());
    }
}
