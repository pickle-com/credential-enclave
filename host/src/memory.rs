//! The memory of the parent container (enclave.md 9.2): the gauge of its socket buffers.
//!
//! The kernel charges the receive queues and the send queues of the TCP sockets of the host
//! program to the memory of its container. That memory is no memory of the process: it is the
//! bytes the pipes of the two relays have not read yet or the peers have not taken yet, and it
//! is the part of the memory of the container the limits of the host program do not bound by
//! themselves (the kernel of the parent instance bounds it for all TCP sockets together).
//! `/metrics` reports it from the memory statistics of the cgroup of the container.

use std::fs;

/// The memory statistics of the cgroup of this process, as a container sees its own cgroup
/// (cgroup version 2).
const MEMORY_STATISTICS: &str = "/sys/fs/cgroup/memory.stat";

/// The bytes of socket buffers charged to the container of this process: the value `sock` of
/// its memory statistics. `None` when the statistics cannot be read or hold no such value (a
/// kernel without cgroup version 2).
pub fn socket_bytes() -> Option<u64> {
    socket_bytes_of(&fs::read_to_string(MEMORY_STATISTICS).ok()?)
}

/// The value `sock` of the text of a `memory.stat` file: lines of a name, one space and a
/// decimal number.
fn socket_bytes_of(statistics: &str) -> Option<u64> {
    statistics
        .lines()
        .find_map(|line| line.strip_prefix("sock "))?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::socket_bytes_of;

    #[test]
    fn the_socket_memory_is_the_sock_line_of_the_memory_statistics() {
        let statistics = "anon 6340608\nfile 58335232\nkernel 1769472\nkernel_stack 131072\n\
                          pagetables 200704\nsec_pagetables 0\npercpu 0\nsock 102285312\n\
                          vmalloc 0\nshmem 0\nslab 1426104\n";
        assert_eq!(socket_bytes_of(statistics), Some(102_285_312));
        assert_eq!(socket_bytes_of("anon 1\nsock 0\n"), Some(0));
        // Other names that hold the word, a file without the line, and a value that is no
        // number give nothing.
        assert_eq!(socket_bytes_of("sock_other 5\nunsock 6\n"), None);
        assert_eq!(socket_bytes_of("anon 1\nfile 2\n"), None);
        assert_eq!(socket_bytes_of("sock many\n"), None);
        assert_eq!(socket_bytes_of(""), None);
    }
}
