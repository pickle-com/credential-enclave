//! What a panic of the host program ends (enclave.md section 9, the Faults row).
//!
//! The enclave ends with the host program: the end of the first process of the container ends
//! `nitro-cli` and the enclave with it, and the delegations the node held are gone. So the
//! host program is built to unwind on a panic (the release profile), and a panic ends the
//! smallest part of the program that it can:
//!
//! - **One connection.** Every connection of the two relays and of the status surface is
//!   served on a task of its own. A panic there ends that task: its two streams are closed,
//!   and what the task held (a place of its relay, a buffer) is given back by the values that
//!   hold it. The node and the caller see a connection that failed.
//! - **The process.** A panic of a task the host program cannot do without ([`vital`]) ends
//!   the process, and the container starts again with a new enclave.
//!
//! The one lock of the host program guards the times of the open pipes, which its metrics
//! read (`crate::relay`). It is used as it is after a panic under it: no connection depends
//! on those times.
//!
//! A panic is logged with the place it happened at and without its message ([`report`]): a
//! message can hold a value of the environment. The panics of the process are counted
//! ([`panics`]), and `/metrics` reports the count.

use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

/// The panics of this process since it started.
static PANICS: AtomicU64 = AtomicU64::new(0);

/// The panics of this process since it started
/// (`credential_enclave_host_contained_panics_total`): each of them ended one connection, and
/// none of them ended the process, which answers the request that reads the count.
pub fn panics() -> u64 {
    PANICS.load(Ordering::Relaxed)
}

/// Makes the panic hook of this process count a panic and log one line with the place of the
/// panic. The host program calls this before it starts anything else.
pub fn report() {
    std::panic::set_hook(Box::new(|panic| {
        PANICS.fetch_add(1, Ordering::Relaxed);
        match panic.location() {
            Some(place) => crate::log(&format!(
                "panic at {}:{}:{}",
                place.file(),
                place.line(),
                place.column()
            )),
            None => crate::log("panic at an unknown place"),
        }
    }));
}

/// A task the host program cannot do without: when `task` panics, the process ends. A task
/// that returns, and a task that is dropped when the runtime ends, end nothing.
///
/// The host program runs these tasks this way (`main.rs`): its main task, the three tasks
/// that accept connections (the two relays and the status surface), the watch of the enclave
/// and the task that sends the operator configuration. Without one of them the pod would go
/// on with a node nobody reaches, a node that reaches nothing, an enclave whose end nobody
/// notices, or a node without its configuration.
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
            Err(_) => std::process::abort(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;

    use super::*;

    /// The environment variable that tells a test of this module that it runs in a process of
    /// its own, and which part of the test that process is to run.
    const OWN_PROCESS: &str = "CREDENTIAL_ENCLAVE_HOST_TEST_OWN_PROCESS";

    /// Runs the test `test` of this test program alone, in a process of its own, with
    /// [`OWN_PROCESS`] set to `part`: the exit status, the signal that ended the process and
    /// what it wrote to its standard output.
    fn in_own_process(test: &str, part: &str) -> (Option<i32>, Option<i32>, String) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([test, "--exact", "--nocapture", "--test-threads=1"])
            .env(OWN_PROCESS, part)
            .output()
            .unwrap();
        (
            output.status.code(),
            output.status.signal(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn a_panic_of_a_task_the_host_program_cannot_do_without_ends_the_process() {
        let name =
            "faults::tests::a_panic_of_a_task_the_host_program_cannot_do_without_ends_the_process";
        match std::env::var(OWN_PROCESS).as_deref() {
            Ok("vital") => {
                report();
                runtime().block_on(async {
                    let task = tokio::spawn(vital(async {
                        tokio::task::yield_now().await;
                        panic!("a value of the environment");
                    }));
                    // The process ends inside the task: the line after it is not reached.
                    let _ = task.await;
                });
                std::process::exit(0);
            }
            Ok("connection") => {
                report();
                // The task of one connection panics: it ends alone, the panic is counted,
                // and a task the program cannot do without that returns ends nothing.
                let outcome = runtime().block_on(async {
                    let connection = tokio::spawn(async {
                        panic!("a value of the environment");
                    });
                    let returned = tokio::spawn(vital(async { 5 }));
                    (connection.await.is_err(), returned.await.ok(), panics())
                });
                std::process::exit(if outcome == (true, Some(5), 1) { 7 } else { 1 });
            }
            _ => {}
        }
        // SIGABRT is signal 6.
        let (code, signal, output) = in_own_process(name, "vital");
        assert_eq!((code, signal), (None, Some(6)), "{output}");
        let (code, signal, output) = in_own_process(name, "connection");
        assert_eq!((code, signal), (Some(7), None), "{output}");
        // The line of a panic names its place, and nothing of its message.
        assert!(
            output.contains("credential-enclave-host: panic at host/src/faults.rs:"),
            "{output}"
        );
        assert!(!output.contains("a value of the environment"), "{output}");
    }
}
