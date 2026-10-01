//! Node time (enclave.md section 8).
//!
//! Every time the node uses (`time_ms` values, expiry checks, TOTP, TLS certificate
//! verification) is the monotonic clock plus a correction taken from the platform's trusted
//! time. The node does not read a time the parent instance could set.
//!
//! Node time never decreases. A new correction can be smaller than the one before it (the
//! samples differ by their round trips), and the clock then holds the largest time it already
//! returned until the corrected time passes it. So the `time_ms` values of one chain do not
//! decrease with `seq`, and an expiry that passed does not come back into force.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;

use crate::platform::{DynPlatform, PlatformError};

/// The interval between two corrections.
pub const CALIBRATION_INTERVAL: Duration = Duration::from_secs(60);

/// Samples read for one correction. The sample with the shortest round trip is used.
const CALIBRATION_SAMPLES: usize = 3;

/// The node clock.
#[derive(Debug)]
pub struct Clock {
    origin: Instant,
    /// The trusted time, in Unix epoch milliseconds, at `origin`.
    base_ms: AtomicU64,
    /// The largest time this clock returned.
    latest_ms: AtomicU64,
}

impl Clock {
    /// Starts the clock with a first correction.
    pub fn start(platform: &dyn DynPlatform) -> Result<Clock, PlatformError> {
        let clock = Clock {
            origin: Instant::now(),
            base_ms: AtomicU64::new(0),
            latest_ms: AtomicU64::new(0),
        };
        clock.calibrate(platform)?;
        Ok(clock)
    }

    /// Takes a new correction: reads the trusted time three times in a row and keeps the sample
    /// whose round trip was the shortest.
    pub fn calibrate(&self, platform: &dyn DynPlatform) -> Result<(), PlatformError> {
        let mut best: Option<(Duration, u64)> = None;
        for _ in 0..CALIBRATION_SAMPLES {
            let before = self.origin.elapsed();
            let trusted_ms = platform.trusted_time_ms()?;
            let after = self.origin.elapsed();
            let round_trip = after.saturating_sub(before);
            let midpoint_ms = u64::try_from(((before + after) / 2).as_millis())
                .map_err(|_| PlatformError("the monotonic clock is out of range"))?;
            let base_ms = trusted_ms.saturating_sub(midpoint_ms);
            if best.is_none_or(|(shortest, _)| round_trip < shortest) {
                best = Some((round_trip, base_ms));
            }
        }
        if let Some((_, base_ms)) = best {
            self.base_ms.store(base_ms, Ordering::SeqCst);
        }
        Ok(())
    }

    /// The node time in Unix epoch milliseconds: the corrected time, or the largest time this
    /// function already returned when that one is larger.
    pub fn now_ms(&self) -> u64 {
        let elapsed_ms = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        let corrected_ms = self
            .base_ms
            .load(Ordering::SeqCst)
            .saturating_add(elapsed_ms);
        self.latest_ms
            .fetch_max(corrected_ms, Ordering::SeqCst)
            .max(corrected_ms)
    }

    /// Moves the clock forward. Tests use it to cross expiry boundaries.
    #[cfg(test)]
    pub fn advance(&self, milliseconds: u64) {
        self.base_ms.fetch_add(milliseconds, Ordering::SeqCst);
    }
}

/// The node clock as the time source of TLS certificate verification.
#[derive(Debug)]
pub struct TlsTime(pub Arc<Clock>);

impl TimeProvider for TlsTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_millis(
            self.0.now_ms(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{Listener, Measurement, Platform, Stream};
    use std::sync::atomic::AtomicUsize;

    /// A platform whose trusted time is a script: each read takes a given delay and returns a
    /// given value.
    struct Scripted {
        samples: Vec<(Duration, u64)>,
        next: AtomicUsize,
    }

    impl Platform for Scripted {
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
            let index = self.next.fetch_add(1, Ordering::SeqCst);
            let (delay, value) = self.samples[index % self.samples.len()];
            std::thread::sleep(delay);
            Ok(value)
        }

        async fn listen(&self) -> Result<Listener, PlatformError> {
            Err(PlatformError("unused"))
        }

        async fn connect(&self, _: &str, _: u16) -> Result<Stream, PlatformError> {
            Err(PlatformError("unused"))
        }
    }

    #[test]
    fn the_clock_follows_the_trusted_time_and_then_the_monotonic_clock() {
        let platform = Scripted {
            samples: vec![(Duration::ZERO, 1_790_000_000_000)],
            next: AtomicUsize::new(0),
        };
        let clock = Clock::start(&platform).unwrap();
        let first = clock.now_ms();
        assert!((1_790_000_000_000..1_790_000_000_500).contains(&first));
        std::thread::sleep(Duration::from_millis(20));
        let second = clock.now_ms();
        assert!(second >= first + 20);
        clock.advance(5_000);
        assert!(clock.now_ms() >= second + 5_000);
    }

    #[test]
    fn the_sample_with_the_shortest_round_trip_wins() {
        // The slow samples carry a time that is an hour off. The fast one is the one to keep.
        let platform = Scripted {
            samples: vec![
                (Duration::from_millis(40), 1_790_003_600_000),
                (Duration::from_millis(1), 1_790_000_000_000),
                (Duration::from_millis(40), 1_790_003_600_000),
            ],
            next: AtomicUsize::new(0),
        };
        let clock = Clock::start(&platform).unwrap();
        let now = clock.now_ms();
        assert!(
            (1_790_000_000_000..1_790_000_001_000).contains(&now),
            "{now}"
        );
    }

    #[test]
    fn node_time_does_not_decrease_when_a_correction_moves_back() {
        // The first correction reads T, the second one reads an hour before T.
        let platform = Scripted {
            samples: vec![
                (Duration::ZERO, 1_790_003_600_000),
                (Duration::ZERO, 1_790_003_600_000),
                (Duration::ZERO, 1_790_003_600_000),
                (Duration::ZERO, 1_790_000_000_000),
            ],
            next: AtomicUsize::new(0),
        };
        let clock = Clock::start(&platform).unwrap();
        let before = clock.now_ms();
        assert!(before >= 1_790_003_600_000);
        // The three samples of the second correction: an hour back, then twice the old time
        // again. The sample with the shortest round trip decides, and whichever it is, the
        // clock does not go back.
        clock.calibrate(&platform).unwrap();
        let held = clock.now_ms();
        assert!(held >= before, "{held} < {before}");

        // A correction that is an hour back in all of its samples.
        let back = Scripted {
            samples: vec![(Duration::ZERO, 1_790_000_000_000)],
            next: AtomicUsize::new(0),
        };
        clock.calibrate(&back).unwrap();
        let after = clock.now_ms();
        assert_eq!(after, held, "the clock holds the largest time it returned");
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(clock.now_ms(), held);

        // Once the corrected time passes the held time, the clock moves again.
        clock.advance(3_600_000 + 60_000);
        let resumed = clock.now_ms();
        assert!(resumed > held);
        std::thread::sleep(Duration::from_millis(5));
        assert!(clock.now_ms() > resumed);
    }

    #[test]
    fn tls_verification_reads_the_node_clock() {
        let platform = Scripted {
            samples: vec![(Duration::ZERO, 1_790_000_000_000)],
            next: AtomicUsize::new(0),
        };
        let clock = Arc::new(Clock::start(&platform).unwrap());
        let time = TlsTime(clock.clone()).current_time().unwrap();
        assert_eq!(time.as_secs(), 1_790_000_000);
        clock.advance(10_000);
        assert_eq!(
            TlsTime(clock).current_time().unwrap().as_secs(),
            1_790_000_010
        );
    }
}
