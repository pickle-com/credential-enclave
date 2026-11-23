//! The credential enclave node program.
//!
//! ```text
//! credential-enclave --platform {nitro|local}
//! ```
//!
//! The platform is the only argument. The operator configuration arrives through
//! `POST /v1/config`. The node keeps its whole state in memory and writes nothing to disk or to
//! standard output.

#![forbid(unsafe_code)]
// A node that ends takes the delegations it holds with it, and a panic ends a call, halts an
// account or ends the node (`faults`). So:
// No input makes the program panic. Its code (not the code of its tests) holds no `unwrap`,
// no `expect`, no `panic!`, and no index or slice expression that can fail. A place that
// keeps one of them says, where it stands, why no input reaches its failure
// (`#[expect(clippy::.., reason = "..")]`).
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::get_unwrap
    )
)]
// Rule E5 of the egress policy: the node writes no output of its own making. The one exception
// is `diagnostic`, which takes a fixed string.
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

mod api;
mod attest;
mod bound;
mod clock;
mod descriptors;
mod egress;
mod faults;
mod frame;
mod imap;
mod inbound;
mod lineage;
mod load;
mod log_store;
mod mail;
mod mail_sessions;
mod oauth;
mod platform;
mod provider_response;
mod providers;
mod role;
mod state;
#[cfg(test)]
mod testing;
#[cfg(test)]
mod tests;
mod vault;

use std::process::ExitCode;
use std::sync::Arc;

use clock::{Clock, CALIBRATION_INTERVAL};
use egress::Egress;
use faults::vital;
use lineage::Lineage;
use platform::{PlatformError, SharedPlatform};
use providers::Definitions;
use state::{Limits, Node};

/// The release tag of this build: the value of `CREDENTIAL_ENCLAVE_RELEASE` at compile time
/// (the build passes the git tag), or `dev`. It is part of the binding that the attestation
/// carries, and it is the release that the order of releases compares with (protocol.md
/// 10.3).
const RELEASE: &str = match option_env!("CREDENTIAL_ENCLAVE_RELEASE") {
    Some(tag) if !tag.is_empty() => tag,
    _ => "dev",
};

const USAGE: &str = "usage: credential-enclave --platform {nitro|local}";

/// Reads the platform name from the arguments.
fn platform_argument(mut arguments: impl Iterator<Item = String>) -> Option<String> {
    let first = arguments.next()?;
    let name = match first.strip_prefix("--platform=") {
        Some(name) => name.to_string(),
        None if first == "--platform" => arguments.next()?,
        None => return None,
    };
    if arguments.next().is_some() {
        return None;
    }
    Some(name)
}

/// Takes a new clock correction every 60 seconds. A failed read keeps the last correction,
/// and so does a read that panicked: each correction runs on a thread of its own, and the
/// clock takes a correction in one step, at its end.
async fn keep_calibrating(platform: SharedPlatform, clock: Arc<Clock>) {
    loop {
        tokio::time::sleep(CALIBRATION_INTERVAL).await;
        let platform = platform.clone();
        let clock = clock.clone();
        let _ = tokio::task::spawn_blocking(move || clock.calibrate(platform.as_ref())).await;
    }
}

/// Resolves when the process is asked to end. An enclave is ended by its parent, so this only
/// matters for the local platform, where the process is the first process of a container.
async fn terminated() {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut terminate), Ok(mut interrupt)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        return std::future::pending().await;
    };
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
}

/// Starts the node and serves its calls until the process is asked to end. The node cannot
/// do without this task, nor without the two tasks it starts: the correction of the clock and
/// the sweep (`faults::vital`).
async fn run(platform_name: &str) -> Result<(), PlatformError> {
    // The limit of open descriptors is raised before any connection exists (enclave.md
    // section 8). The outcome is not logged (rule E5): `health` reports the limit in force.
    let _ = descriptors::raise_limit();
    let platform = platform::select(platform_name)?;
    let clock = Arc::new(Clock::start(platform.as_ref())?);
    // The connections from the backend the node holds at once are a share of the memory of
    // the kernel it runs in (enclave.md section 8). `health` reports the bound in force.
    let limits = Limits {
        inbound_connections: inbound::connections_for(
            load::read_memory().map(|memory| memory.total),
        ),
        ..Limits::default()
    };
    let node = Arc::new(Node::start(
        platform.clone(),
        clock.clone(),
        Definitions::embedded(),
        Egress::new(clock.clone(), limits.open_concurrency),
        RELEASE,
        Lineage::embedded(RELEASE)?,
        limits,
    )?);
    let listener = platform.listen(node.limits.inbound_connections).await?;
    tokio::spawn(vital(keep_calibrating(platform, clock)));
    tokio::spawn(vital(log_store::keep_sweeping(node.clone())));
    tokio::select! {
        _ = api::serve(listener, api::router(node.clone()), node) => {}
        _ = terminated() => {}
    }
    Ok(())
}

/// Writes a startup diagnostic to the standard error. This is the only output of the node
/// program besides its responses. The text is a fixed string of the source: a console exists
/// in a debug-mode enclave only, and no value of a call can reach it.
#[allow(clippy::print_stderr)]
fn diagnostic(text: &'static str) {
    eprintln!("credential-enclave: {text}");
}

fn main() -> ExitCode {
    // No panic of the node writes anything (rule E5): from here on a panic is counted.
    faults::silence();
    let Some(platform_name) = platform_argument(std::env::args().skip(1)) else {
        diagnostic(USAGE);
        return ExitCode::from(2);
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            diagnostic("cannot start the runtime");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(vital(run(&platform_name))) {
        Ok(()) => ExitCode::SUCCESS,
        Err(PlatformError(reason)) => {
            diagnostic(reason);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod calibration_tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::{keep_calibrating, CALIBRATION_INTERVAL};
    use crate::clock::Clock;
    use crate::faults;
    use crate::platform::{
        ConnectError, Listener, Measurement, Platform, PlatformError, SharedPlatform, Stream,
    };
    use crate::testing::{quiet_panics, ScriptedFault};

    /// A platform whose trusted time is a value of the test, and whose read of that time
    /// panics while the test says so.
    struct Timed {
        trusted_ms: AtomicU64,
        faulty: AtomicBool,
    }

    impl Platform for Timed {
        fn name(&self) -> &'static str {
            "local"
        }

        fn custody(&self) -> &'static str {
            "operator"
        }

        fn measurement(&self) -> Option<Measurement> {
            None
        }

        fn attestation(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, PlatformError> {
            Err(PlatformError("unused"))
        }

        fn fill_random(&self, _: &mut [u8]) -> Result<(), PlatformError> {
            Err(PlatformError("unused"))
        }

        fn trusted_time_ms(&self) -> Result<u64, PlatformError> {
            if self.faulty.load(Ordering::SeqCst) {
                std::panic::panic_any(ScriptedFault);
            }
            Ok(self.trusted_ms.load(Ordering::SeqCst))
        }

        async fn listen(&self, _: usize) -> Result<Listener, PlatformError> {
            Err(PlatformError("unused"))
        }

        async fn connect(&self, _: &str, _: u16) -> Result<Stream, ConnectError> {
            Err(ConnectError::Transport("unused"))
        }
    }

    #[tokio::test]
    async fn a_correction_that_panicked_is_followed_by_the_next_correction() {
        quiet_panics();
        const START_MS: u64 = 1_790_000_000_000;
        const HOUR_MS: u64 = 3_600_000;
        let platform = Arc::new(Timed {
            trusted_ms: AtomicU64::new(START_MS),
            faulty: AtomicBool::new(false),
        });
        let clock = Arc::new(Clock::start(platform.as_ref()).unwrap());
        // The task of the corrections, as a running node starts it. A correction starts every
        // 60 seconds: once the task waits for its next one, the clock of the runtime is moved
        // past that time by hand.
        let shared: SharedPlatform = platform.clone();
        let correcting = tokio::spawn(keep_calibrating(shared, clock.clone()));
        let next_correction = || async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            tokio::time::pause();
            tokio::time::advance(CALIBRATION_INTERVAL + Duration::from_millis(1)).await;
            tokio::time::resume();
        };

        // The trusted time is an hour further, and the read of it panics: that correction
        // ends, and the clock keeps the correction before it.
        platform
            .trusted_ms
            .store(START_MS + HOUR_MS, Ordering::SeqCst);
        platform.faulty.store(true, Ordering::SeqCst);
        let panics = faults::panics();
        next_correction().await;
        for _ in 0..1000 {
            if faults::panics() > panics {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(faults::panics() > panics);
        assert!(clock.now_ms() < START_MS + HOUR_MS);

        // The task goes on: the next correction takes the trusted time.
        platform.faulty.store(false, Ordering::SeqCst);
        next_correction().await;
        for _ in 0..1000 {
            if clock.now_ms() >= START_MS + HOUR_MS {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(clock.now_ms() >= START_MS + HOUR_MS);
        assert!(!correcting.is_finished());
    }
}

#[cfg(test)]
mod argument_tests {
    use super::platform_argument;

    fn parse(arguments: &[&str]) -> Option<String> {
        platform_argument(arguments.iter().map(|argument| argument.to_string()))
    }

    #[test]
    fn the_platform_is_the_only_argument() {
        assert_eq!(parse(&["--platform", "local"]).as_deref(), Some("local"));
        assert_eq!(parse(&["--platform=nitro"]).as_deref(), Some("nitro"));
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&["--platform"]), None);
        assert_eq!(parse(&["local"]), None);
        assert_eq!(parse(&["--platform", "local", "--port", "9"]), None);
    }
}
