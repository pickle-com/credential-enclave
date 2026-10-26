//! The values of the kernel in `load` of `GET /v1/health` (enclave.md 5.1): the CPU time and
//! the memory of the kernel the node runs in, read from procfs.
//!
//! The kernel exposes the CPU time of all its processors together, since it booted, in the
//! first line of `/proc/stat`, in clock ticks, and its memory sizes in `/proc/meminfo`. The
//! number of clock ticks per second is the entry `AT_CLKTCK` of the auxiliary vector of the
//! process, which the kernel exposes as `/proc/self/auxv`. The crate forbids `unsafe` code, so
//! the node reads the auxiliary vector as a file in the place of `sysconf(_SC_CLK_TCK)` of
//! the C library. A kernel without procfs (a development machine that is not Linux) gives no
//! value: the fields of the response are null then.

use std::fs;

/// The CPU time of the kernel since it booted, in milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuMs {
    /// Time in user mode: `user` and `nice` of `/proc/stat`.
    pub user: u64,
    /// Time in kernel mode: `system`, `irq`, `softirq` and `steal` of `/proc/stat`.
    pub system: u64,
    /// Idle time: `idle` and `iowait` of `/proc/stat`.
    pub idle: u64,
}

/// The memory of the kernel, in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryBytes {
    /// `MemTotal` of `/proc/meminfo`.
    pub total: u64,
    /// `MemAvailable` of `/proc/meminfo`: what the kernel estimates it can give out without
    /// swapping.
    pub available: u64,
}

/// The type of the entry of the auxiliary vector that holds the clock ticks per second.
const AT_CLKTCK: usize = 17;
/// The type of the entry that ends the auxiliary vector.
const AT_NULL: usize = 0;

/// The CPU time of the kernel: the first line of `/proc/stat` at the clock ticks per second
/// of `/proc/self/auxv`. `None` when one of the two cannot be read or parsed.
pub fn read_cpu() -> Option<CpuMs> {
    let clk_tck = parse_auxv(&fs::read("/proc/self/auxv").ok()?)?;
    parse_proc_stat(&fs::read_to_string("/proc/stat").ok()?, clk_tck)
}

/// The memory of the kernel from `/proc/meminfo`. `None` when the file cannot be read or
/// parsed.
pub fn read_memory() -> Option<MemoryBytes> {
    parse_meminfo(&fs::read_to_string("/proc/meminfo").ok()?)
}

/// The clock ticks per second of an auxiliary vector: pairs of machine words (the type, then
/// the value) in the byte order of the machine, ended by a pair of type `AT_NULL`. `None` when
/// the vector has no `AT_CLKTCK` entry before its end or the entry holds 0.
pub fn parse_auxv(bytes: &[u8]) -> Option<u64> {
    const WORD: usize = std::mem::size_of::<usize>();
    let (pairs, _) = bytes.as_chunks::<{ 2 * WORD }>();
    for pair in pairs {
        let (kind, value) = pair.split_at(WORD);
        let kind = usize::from_ne_bytes(kind.try_into().ok()?);
        let value = usize::from_ne_bytes(value.try_into().ok()?);
        match kind {
            AT_NULL => return None,
            AT_CLKTCK => return u64::try_from(value).ok().filter(|ticks| *ticks > 0),
            _ => {}
        }
    }
    None
}

/// The CPU time of the first line of `/proc/stat`, `cpu user nice system idle iowait irq
/// softirq steal guest guest_nice` in clock ticks, as milliseconds at `clk_tck` ticks per
/// second. The first four columns are required; a column after them that the kernel does not
/// write counts 0. `None` when the first line does not start with `cpu`, a column is not a
/// number, `clk_tck` is 0, or a conversion overflows.
pub fn parse_proc_stat(text: &str, clk_tck: u64) -> Option<CpuMs> {
    if clk_tck == 0 {
        return None;
    }
    let mut columns = text.lines().next()?.split_ascii_whitespace();
    if columns.next()? != "cpu" {
        return None;
    }
    let mut ticks = [0u64; 8];
    for (index, slot) in ticks.iter_mut().enumerate() {
        match columns.next() {
            Some(column) => *slot = column.parse().ok()?,
            None if index < 4 => return None,
            None => break,
        }
    }
    let [user, nice, system, idle, iowait, irq, softirq, steal] = ticks;
    let ms = |parts: [u64; 4]| {
        let sum = parts
            .iter()
            .try_fold(0u64, |sum, part| sum.checked_add(*part))?;
        Some(sum.checked_mul(1000)? / clk_tck)
    };
    Some(CpuMs {
        user: ms([user, nice, 0, 0])?,
        system: ms([system, irq, softirq, steal])?,
        idle: ms([idle, iowait, 0, 0])?,
    })
}

/// `MemTotal` and `MemAvailable` of `/proc/meminfo` (lines of the form `MemTotal:  16384 kB`),
/// in bytes. `None` when one of the two lines is absent, its value is not a number in kB, or a
/// conversion overflows.
pub fn parse_meminfo(text: &str) -> Option<MemoryBytes> {
    let mut total = None;
    let mut available = None;
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let slot = match name {
            "MemTotal" => &mut total,
            "MemAvailable" => &mut available,
            _ => continue,
        };
        let mut parts = rest.split_ascii_whitespace();
        let kilobytes: u64 = parts.next()?.parse().ok()?;
        if parts.next() != Some("kB") || parts.next().is_some() {
            return None;
        }
        *slot = Some(kilobytes.checked_mul(1024)?);
        if total.is_some() && available.is_some() {
            break;
        }
    }
    Some(MemoryBytes {
        total: total?,
        available: available?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_STAT: &str = "cpu  4705 150 1120 1048576 230 0 45 8 0 0\n\
                             cpu0 2000 100 600 524288 115 0 20 4 0 0\n\
                             cpu1 2705 50 520 524288 115 0 25 4 0 0\n\
                             intr 123456 0 0 0\n\
                             ctxt 987654\n\
                             btime 1790000000\n";

    #[test]
    fn the_cpu_time_is_the_sum_of_the_columns_of_each_mode_in_milliseconds() {
        // At 100 ticks per second one tick is 10 ms.
        assert_eq!(
            parse_proc_stat(PROC_STAT, 100),
            Some(CpuMs {
                user: (4705 + 150) * 10,
                system: (1120 + 45 + 8) * 10,
                idle: (1048576 + 230) * 10,
            })
        );
        // At 250 ticks per second one tick is 4 ms, and the division rounds down.
        assert_eq!(
            parse_proc_stat("cpu 7 0 1 2 0 0 0 0 0 0\n", 250),
            Some(CpuMs {
                user: 28,
                system: 4,
                idle: 8,
            })
        );
        // At 1000 ticks per second one tick is 1 ms.
        assert_eq!(
            parse_proc_stat("cpu 1 1 1 1\n", 1000),
            Some(CpuMs {
                user: 2,
                system: 1,
                idle: 1,
            })
        );
    }

    #[test]
    fn a_line_with_fewer_columns_counts_the_missing_columns_as_zero() {
        // The four columns of a kernel of the 2.4 series.
        assert_eq!(
            parse_proc_stat("cpu 10 20 30 40\n", 100),
            Some(CpuMs {
                user: 300,
                system: 300,
                idle: 400,
            })
        );
        // Seven columns: without steal and the two guest columns.
        assert_eq!(
            parse_proc_stat("cpu 10 20 30 40 50 60 70\n", 100),
            Some(CpuMs {
                user: 300,
                system: 1600,
                idle: 900,
            })
        );
        // Fewer than four columns is not a cpu line.
        assert_eq!(parse_proc_stat("cpu 10 20 30\n", 100), None);
    }

    #[test]
    fn a_malformed_stat_gives_no_cpu_time() {
        for text in [
            "",
            "\n",
            "intr 123\ncpu 1 2 3 4\n",
            "cpu0 1 2 3 4\n",
            "cpu 1 2 x 4\n",
            "cpu 1 2 -3 4\n",
            "cpu 1 2 3 18446744073709551615\n",
        ] {
            assert_eq!(parse_proc_stat(text, 100), None, "{text:?}");
        }
        assert_eq!(parse_proc_stat(PROC_STAT, 0), None);
    }

    #[test]
    fn the_memory_sizes_are_the_two_lines_in_bytes() {
        let text = "MemTotal:        4030444 kB\n\
                    MemFree:         3120000 kB\n\
                    MemAvailable:    3652088 kB\n\
                    Buffers:           12345 kB\n\
                    HugePages_Total:       0\n";
        assert_eq!(
            parse_meminfo(text),
            Some(MemoryBytes {
                total: 4030444 * 1024,
                available: 3652088 * 1024,
            })
        );
        for text in [
            "",
            "MemTotal:        4030444 kB\n",
            "MemAvailable:    3652088 kB\n",
            "MemTotal:        4030444\nMemAvailable:    3652088 kB\n",
            "MemTotal:        4030444 MB\nMemAvailable:    3652088 kB\n",
            "MemTotal:        x kB\nMemAvailable:    3652088 kB\n",
            "MemTotal 4030444 kB\nMemAvailable:    3652088 kB\n",
            "MemTotal:        18014398509481984 kB\nMemAvailable:    3652088 kB\n",
        ] {
            assert_eq!(parse_meminfo(text), None, "{text:?}");
        }
    }

    #[test]
    fn the_clock_ticks_are_the_at_clktck_entry_of_the_auxiliary_vector() {
        let vector = |entries: &[(usize, usize)]| {
            let mut bytes = Vec::new();
            for (kind, value) in entries {
                bytes.extend_from_slice(&kind.to_ne_bytes());
                bytes.extend_from_slice(&value.to_ne_bytes());
            }
            bytes
        };
        // AT_PAGESZ 6, AT_CLKTCK 17, AT_PHDR 3, AT_NULL 0.
        assert_eq!(
            parse_auxv(&vector(&[(6, 4096), (17, 100), (3, 0x4000_0040), (0, 0)])),
            Some(100)
        );
        // The entry after the end of the vector does not count, and neither does a value of 0.
        assert_eq!(parse_auxv(&vector(&[(6, 4096), (0, 0), (17, 100)])), None);
        assert_eq!(parse_auxv(&vector(&[(17, 0), (0, 0)])), None);
        assert_eq!(parse_auxv(&vector(&[(6, 4096), (0, 0)])), None);
        assert_eq!(parse_auxv(&[]), None);
        // A vector that ends inside a pair gives the entries before it.
        let mut cut = vector(&[(17, 250), (6, 4096)]);
        cut.truncate(cut.len() - 1);
        assert_eq!(parse_auxv(&cut), Some(250));
    }

    #[test]
    fn a_linux_kernel_gives_every_value() {
        if cfg!(target_os = "linux") {
            let cpu = read_cpu().expect("a Linux kernel exposes /proc/stat and the clock ticks");
            assert!(cpu.user + cpu.system + cpu.idle > 0);
            let memory = read_memory().expect("a Linux kernel exposes /proc/meminfo");
            assert!(memory.total >= memory.available && memory.total > 0);
        }
    }
}
