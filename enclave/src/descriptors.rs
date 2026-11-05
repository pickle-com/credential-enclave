//! The open file descriptors of the node process (enclave.md section 8): the limit the node
//! raises at its start and the two values that `load` of `GET /v1/health` reports.
//!
//! Every connection the node accepts from the backend and every connection it opens to a
//! provider or to the log store holds one descriptor. The kernel of the enclave starts its
//! first process with the default limit of a Linux kernel, 1,024 open descriptors (the soft
//! limit of `RLIMIT_NOFILE`; the hard limit is 4,096), and nothing in the enclave image raises
//! it. Under that limit a node that holds about a thousand connections can neither open the
//! connection of a write to the log store or of a provider request (every call that uses a
//! credential then fails with `log_store_unavailable` or `provider_unreachable`) nor accept the
//! connection of a `health` call (the host program then reports the node as not answering).
//!
//! At its start the node asks the kernel for [`DESCRIPTOR_LIMIT`] open descriptors: it raises
//! the soft limit, and the hard limit as well when that is below the target (the node is the
//! first process of the enclave, runs as root and holds `CAP_SYS_RESOURCE`). When the kernel
//! refuses the target, the node raises the soft limit to the hard limit; when the kernel
//! refuses that too, the limits stay as they are. `health` reports the soft limit in force and
//! the number of open descriptors, so the operator domain sees a node whose limit is below the
//! target and a node that approaches its limit.

use std::fs;

use rlimit::Resource;

/// The open descriptors the node asks the kernel for at its start. The connections of a node
/// are bounded by the limits of section 8 of enclave.md: 16,384 accepted connections
/// (`inbound_connections`), 1,024 idle connections to the providers, 32 idle connections to
/// the log store, 512 provider requests in flight, 256 connections being opened, and the
/// writes to the log store of the calls in progress. The target leaves room above their sum.
pub const DESCRIPTOR_LIMIT: u64 = 65_536;

/// The directory whose entries are the open descriptors of this process.
const DESCRIPTOR_DIRECTORY: &str = "/proc/self/fd";

/// The limits of open descriptors of this process: the soft limit and the hard limit. `None`
/// when the platform has no such limit.
pub fn limits() -> Option<(u64, u64)> {
    Resource::NOFILE.get().ok()
}

/// Raises the limit of open descriptors of this process to [`DESCRIPTOR_LIMIT`]: the soft
/// limit, and the hard limit when it is below the target. When the kernel refuses the target,
/// the soft limit is raised to the hard limit. Returns the limits in force after the call,
/// `None` when the platform has no such limit.
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

/// The soft limit of open descriptors in force: `descriptors_limit` of `load` of health.
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
        assert!(after.1 >= before.1, "{after:?} < {before:?}");
        assert!(after.0 <= after.1, "{after:?}");
        assert_eq!(soft_limit(), Some(after.0));
        // A second call changes nothing.
        assert_eq!(raise_limit(), Some(after));
    }

    #[test]
    fn the_open_count_follows_the_descriptors_the_process_holds() {
        if !cfg!(target_os = "linux") {
            // Only a Linux kernel exposes /proc/self/fd.
            return;
        }
        let before = open_count().expect("a Linux kernel exposes /proc/self/fd");
        let held = fs::File::open("/proc/self/stat").unwrap();
        let during = open_count().unwrap();
        assert_eq!(during, before + 1);
        drop(held);
        assert_eq!(open_count().unwrap(), before);
    }
}
