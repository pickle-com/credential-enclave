//! The open file descriptors of the host program (enclave.md section 9): the limit it raises
//! at its start and the two gauges of `/metrics`.
//!
//! Every connection of the two relays holds two descriptors of the host program (the socket
//! of the caller or of the provider, and the vsock socket to the node). The container runtime
//! gives the process the limit of the service it runs under; at its start the host program
//! raises the soft limit of `RLIMIT_NOFILE` to [`DESCRIPTOR_LIMIT`], or to the hard limit
//! when the target is above it (the container does not hold `CAP_SYS_RESOURCE`, so the hard
//! limit cannot be raised). `/metrics` reports the limit in force and the number of open
//! descriptors.

use std::fs;

use rlimit::Resource;

/// The open descriptors the host program asks the kernel for at its start.
pub const DESCRIPTOR_LIMIT: u64 = 65_536;

/// The directory whose entries are the open descriptors of this process.
const DESCRIPTOR_DIRECTORY: &str = "/proc/self/fd";

/// The limits of open descriptors of this process: the soft limit and the hard limit. `None`
/// when the platform has no such limit.
pub fn limits() -> Option<(u64, u64)> {
    Resource::NOFILE.get().ok()
}

/// Raises the soft limit of open descriptors to [`DESCRIPTOR_LIMIT`], or to the hard limit
/// when the target is above it. Returns the limits in force after the call.
pub fn raise_limit() -> Option<(u64, u64)> {
    let (soft, hard) = limits()?;
    if soft >= DESCRIPTOR_LIMIT {
        return Some((soft, hard));
    }
    if Resource::NOFILE
        .set(DESCRIPTOR_LIMIT, hard.max(DESCRIPTOR_LIMIT))
        .is_ok()
    {
        return limits();
    }
    if soft < hard {
        let _ = Resource::NOFILE.set(hard, hard);
    }
    limits()
}

/// The soft limit of open descriptors in force.
pub fn soft_limit() -> Option<u64> {
    limits().map(|(soft, _)| soft)
}

/// The number of open descriptors of this process: the entries of `/proc/self/fd` without the
/// one that the reading itself holds open. `None` when the directory cannot be read (a kernel
/// without procfs).
pub fn open_count() -> Option<u64> {
    let entries = fs::read_dir(DESCRIPTOR_DIRECTORY)
        .ok()?
        .filter(|entry| entry.is_ok())
        .count();
    Some(u64::try_from(entries).ok()?.saturating_sub(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limit_is_raised_or_kept_and_never_lowered() {
        let before = limits().expect("a Unix kernel has a limit of open descriptors");
        let after = raise_limit().expect("the limits can be read after the call");
        assert!(after.0 >= before.0, "{after:?} < {before:?}");
        assert!(after.0 <= after.1, "{after:?}");
        assert_eq!(soft_limit(), Some(after.0));
        assert_eq!(raise_limit(), Some(after));
    }

    #[test]
    fn the_open_count_follows_the_descriptors_the_process_holds() {
        if !cfg!(target_os = "linux") {
            return;
        }
        // The count is that of the whole process, and the other tests of the crate run in
        // threads at the same time: the test holds many descriptors and asserts the direction
        // of the change, not its exact size.
        let before = open_count().expect("a Linux kernel exposes /proc/self/fd");
        let held: Vec<fs::File> = (0..32)
            .map(|_| fs::File::open("/proc/self/stat").unwrap())
            .collect();
        let during = open_count().unwrap();
        assert!(during > before, "{during} <= {before}");
        drop(held);
        let after = open_count().unwrap();
        assert!(after < during, "{after} >= {during}");
    }
}
