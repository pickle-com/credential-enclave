//! The start, the description and the end of the enclave (enclave.md section 9), all through
//! `nitro-cli`.
//!
//! ```text
//! nitro-cli run-enclave --eif-path /opt/credential-enclave/enclave.eif \
//!     --cpu-count 2 --memory {CREDENTIAL_ENCLAVE_MEMORY_MIB, default 4096} --enclave-cid 16
//! nitro-cli describe-enclaves
//! nitro-cli terminate-enclave --all
//! ```
//!
//! The arguments are constants of the host program, except the memory, which the environment
//! variable `CREDENTIAL_ENCLAVE_MEMORY_MIB` gives. `nitro-cli` writes to the standard output
//! and the standard error of the host program, so its messages and error codes are part of the
//! container log.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

use crate::relay::ENCLAVE_CID;

/// The program that starts and ends enclaves, found through `PATH`.
const NITRO_CLI: &str = "nitro-cli";
/// The enclave image file of the host image.
pub const EIF_PATH: &str = "/opt/credential-enclave/enclave.eif";
/// The measurements of that enclave image file.
pub const MEASUREMENTS_PATH: &str = "/opt/credential-enclave/measurements.json";
/// The vCPUs of the enclave.
const CPU_COUNT: u32 = 2;
/// The variable that gives the memory of the enclave, in MiB.
pub const MEMORY_VARIABLE: &str = "CREDENTIAL_ENCLAVE_MEMORY_MIB";
/// The memory of the enclave when the variable is not set, in MiB.
pub const DEFAULT_MEMORY_MIB: u32 = 4096;
/// Longest output of `describe-enclaves` the host program puts into its log line.
const DESCRIBE_LINE_BYTES: usize = 4096;

/// Reads the memory of the enclave from the environment (`variable` reads one variable): the
/// default when the variable is not set, else its value as a positive integer of MiB. A value
/// that is not a positive integer is an error, and the host program does not start.
pub fn memory_mib(variable: &dyn Fn(&str) -> Option<String>) -> Result<u32, String> {
    let Some(value) = variable(MEMORY_VARIABLE) else {
        return Ok(DEFAULT_MEMORY_MIB);
    };
    let canonical = value.bytes().all(|byte| byte.is_ascii_digit()) && !value.starts_with('0');
    value
        .parse::<u32>()
        .ok()
        .filter(|_| canonical)
        .ok_or_else(|| format!("{MEMORY_VARIABLE} is not a positive integer: {value:?}"))
}

/// Where `nitro-cli` keeps the socket of a running enclave.
const SOCKET_DIRECTORY: &str = "/run/nitro_enclaves";
/// Where `nitro-cli` writes its log and the details of its errors.
const LOG_DIRECTORY: &str = "/var/log/nitro_enclaves";
/// How much of the end of each `nitro-cli` log file is printed after a failed start.
const LOG_TAIL_BYTES: usize = 16 * 1024;

/// The arguments of the start, with the memory of the enclave in MiB.
fn run_enclave_arguments(memory_mib: u32) -> Vec<String> {
    [
        "run-enclave",
        "--eif-path",
        EIF_PATH,
        "--cpu-count",
        &CPU_COUNT.to_string(),
        "--memory",
        &memory_mib.to_string(),
        "--enclave-cid",
        &ENCLAVE_CID.to_string(),
    ]
    .map(str::to_string)
    .to_vec()
}

/// The arguments of the end: every enclave of this container, which is the one enclave the
/// host program started.
fn terminate_enclave_arguments() -> Vec<String> {
    ["terminate-enclave", "--all"].map(str::to_string).to_vec()
}

/// The arguments of the description: the running enclaves of this container, a JSON list.
fn describe_enclaves_arguments() -> Vec<String> {
    ["describe-enclaves"].map(str::to_string).to_vec()
}

/// The standard output of a program that ran to its end, as one line: every run of whitespace
/// is one space, and the text is cut at [`DESCRIBE_LINE_BYTES`].
fn output_line(program: &str, arguments: &[String]) -> Result<String, String> {
    let output = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("cannot start {program}: {error}"))?;
    if !output.status.success() {
        let action = arguments.first().map(String::as_str).unwrap_or_default();
        return Err(format!("{program} {action} ended with {}", output.status));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if line.len() > DESCRIBE_LINE_BYTES {
        let mut end = DESCRIBE_LINE_BYTES;
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        line.truncate(end);
    }
    Ok(line)
}

/// Runs a program to its end with the output streams of the host program.
fn run(program: &str, arguments: &[String]) -> Result<(), String> {
    let status = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| format!("cannot start {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        let action = arguments.first().map(String::as_str).unwrap_or_default();
        Err(format!("{program} {action} ended with {status}"))
    }
}

/// The end of every `.log` file of a directory, in the order of the file names.
fn log_tails(directory: &Path) -> Vec<(PathBuf, String)> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "log"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| {
            let bytes = std::fs::read(&path).ok()?;
            let tail = &bytes[bytes.len().saturating_sub(LOG_TAIL_BYTES)..];
            let text = String::from_utf8_lossy(tail).into_owned();
            Some((path, text))
        })
        .collect()
}

/// Starts the enclave with `memory_mib` MiB of memory and waits until `nitro-cli` reports the
/// start. This call blocks.
///
/// After a failure the log files of `nitro-cli` are printed to the standard error: the files
/// are gone when the container restarts, and the container log is what remains.
pub fn run_enclave(memory_mib: u32) -> Result<(), String> {
    for directory in [SOCKET_DIRECTORY, LOG_DIRECTORY] {
        let _ = std::fs::create_dir_all(directory);
    }
    let outcome = run(NITRO_CLI, &run_enclave_arguments(memory_mib));
    if outcome.is_err() {
        for (path, text) in log_tails(Path::new(LOG_DIRECTORY)) {
            eprintln!("---- {} ----\n{}", path.display(), text.trim_end());
        }
    }
    outcome
}

/// The running enclaves of this container as `nitro-cli` describes them, on one line: the
/// JSON list of enclave objects, `[]` when none runs. This call blocks.
pub fn describe_enclaves() -> Result<String, String> {
    output_line(NITRO_CLI, &describe_enclaves_arguments())
}

/// Ends the enclave. This call blocks.
pub fn terminate_enclave() -> Result<(), String> {
    run(NITRO_CLI, &terminate_enclave_arguments())
}

/// One line that names the release of the enclave image file, from the measurements file next
/// to it (`release`, `git_commit`, `pcr0`, `pcr1`, `pcr2`).
pub fn release_line(measurements: &Path) -> String {
    let values = std::fs::read(measurements)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let Some(values) = values else {
        return format!(
            "enclave image: no measurements at {}",
            measurements.display()
        );
    };
    let field = |name: &str| -> String {
        values
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or("?")
            .chars()
            .filter(char::is_ascii_graphic)
            .take(128)
            .collect()
    };
    format!(
        "enclave image: release {}, commit {}, pcr0 {}, pcr1 {}, pcr2 {}",
        field("release"),
        field("git_commit"),
        field("pcr0"),
        field("pcr1"),
        field("pcr2")
    )
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    /// A new empty directory for one test.
    fn test_directory(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "credential-enclave-host-{name}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn the_enclave_starts_with_the_fixed_arguments_and_the_memory_of_the_environment() {
        assert_eq!(
            run_enclave_arguments(DEFAULT_MEMORY_MIB).join(" "),
            "run-enclave --eif-path /opt/credential-enclave/enclave.eif --cpu-count 2 \
             --memory 4096 --enclave-cid 16"
        );
        assert_eq!(
            run_enclave_arguments(8192).join(" "),
            "run-enclave --eif-path /opt/credential-enclave/enclave.eif --cpu-count 2 \
             --memory 8192 --enclave-cid 16"
        );
        assert_eq!(
            terminate_enclave_arguments().join(" "),
            "terminate-enclave --all"
        );
        assert_eq!(describe_enclaves_arguments(), ["describe-enclaves"]);
    }

    #[test]
    fn the_memory_is_the_variable_or_the_default_and_refuses_other_values() {
        let environment = |value: Option<&'static str>| {
            move |name: &str| {
                assert_eq!(name, MEMORY_VARIABLE);
                value.filter(|value| !value.is_empty()).map(str::to_string)
            }
        };
        assert_eq!(memory_mib(&environment(None)), Ok(4096));
        assert_eq!(memory_mib(&environment(Some(""))), Ok(4096));
        assert_eq!(memory_mib(&environment(Some("4096"))), Ok(4096));
        assert_eq!(memory_mib(&environment(Some("8192"))), Ok(8192));
        assert_eq!(memory_mib(&environment(Some("1"))), Ok(1));
        for value in [
            "0",
            "-1",
            "4096.5",
            "4 GiB",
            "0x1000",
            "04096",
            "4294967296",
            "abc",
        ] {
            assert_eq!(
                memory_mib(&environment(Some(value))),
                Err(format!(
                    "CREDENTIAL_ENCLAVE_MEMORY_MIB is not a positive integer: {value:?}"
                )),
                "{value}"
            );
        }
    }

    #[test]
    fn a_program_that_fails_or_is_missing_is_an_error() {
        let arguments = ["run-enclave".to_string()];
        assert_eq!(run("true", &arguments), Ok(()));
        let failure = run("false", &arguments).unwrap_err();
        assert!(
            failure.starts_with("false run-enclave ended with exit"),
            "{failure}"
        );
        let missing = run("/nonexistent/nitro-cli", &arguments).unwrap_err();
        assert!(
            missing.starts_with("cannot start /nonexistent/nitro-cli: "),
            "{missing}"
        );
    }

    #[test]
    fn the_output_of_a_program_is_one_line() {
        let arguments = [
            "[\n  {\n    \"EnclaveID\": \"i-0\",\n    \"State\": \"RUNNING\"\n  }\n]\n".to_string(),
        ];
        assert_eq!(
            output_line("echo", &arguments),
            Ok("[ { \"EnclaveID\": \"i-0\", \"State\": \"RUNNING\" } ]".to_string())
        );
        assert_eq!(
            output_line("echo", &["[]".to_string()]),
            Ok("[]".to_string())
        );
        assert_eq!(output_line("true", &[]), Ok(String::new()));
        let failure = output_line("false", &["describe-enclaves".to_string()]).unwrap_err();
        assert!(
            failure.starts_with("false describe-enclaves ended with exit"),
            "{failure}"
        );
        let missing = output_line("/nonexistent/nitro-cli", &[]).unwrap_err();
        assert!(
            missing.starts_with("cannot start /nonexistent/nitro-cli: "),
            "{missing}"
        );
        // A long output is cut at the limit of the line.
        let long = "x".repeat(DESCRIBE_LINE_BYTES + 100);
        let line = output_line("echo", &[long]).unwrap();
        assert_eq!(line.len(), DESCRIBE_LINE_BYTES);
    }

    #[test]
    fn the_ends_of_the_log_files_are_collected() {
        let directory = test_directory("logs");
        std::fs::write(directory.join("nitro_enclaves.log"), "second file\n").unwrap();
        std::fs::write(directory.join("err2026.log"), "first file\n").unwrap();
        std::fs::write(directory.join("other.txt"), "not a log\n").unwrap();
        let long = "x".repeat(LOG_TAIL_BYTES) + "the end";
        std::fs::write(directory.join("z.log"), &long).unwrap();

        let tails = log_tails(&directory);
        let names: Vec<&str> = tails
            .iter()
            .map(|(path, _)| path.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, ["err2026.log", "nitro_enclaves.log", "z.log"]);
        assert_eq!(tails[0].1, "first file\n");
        assert_eq!(tails[1].1, "second file\n");
        assert_eq!(tails[2].1.len(), LOG_TAIL_BYTES);
        assert!(tails[2].1.ends_with("the end"));

        assert!(log_tails(&directory.join("missing")).is_empty());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn the_release_line_repeats_the_measurements_file() {
        let directory = test_directory("measurements");
        let path = directory.join("measurements.json");
        std::fs::write(
            &path,
            r#"{"release":"v1.0.0","git_commit":"0123abc","pcr0":"aa","pcr1":"bb","pcr2":"cc","inputs":{}}"#,
        )
        .unwrap();
        assert_eq!(
            release_line(&path),
            "enclave image: release v1.0.0, commit 0123abc, pcr0 aa, pcr1 bb, pcr2 cc"
        );

        std::fs::write(&path, r#"{"release":"v1\nforged line","pcr0":7}"#).unwrap();
        assert_eq!(
            release_line(&path),
            "enclave image: release v1forgedline, commit ?, pcr0 ?, pcr1 ?, pcr2 ?"
        );

        let missing = directory.join("missing.json");
        assert_eq!(
            release_line(&missing),
            format!("enclave image: no measurements at {}", missing.display())
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
