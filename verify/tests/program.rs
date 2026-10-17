//! Runs the built tool with `program` on the synthetic release proof of
//! `tests/fixtures/secure-program/`: the exit status and the output of a proof that holds, of
//! each tampering (the code of the check that fails), and of arguments without a result. No
//! request is sent.

use std::path::PathBuf;
use std::process::Command;

use credential_enclave_protocol::encoding::{b64u, b64u_decode};
use serde_json::Value;

/// The SHA-256 of `source.js`, the `sha256` of both statements of the fixtures.
const SHA256_OF_SOURCE: &str = "a4610f0a732e639bb818fadc7a51b373c6629d42e4d603333c4949f0bf7d52d0";

/// What a run of the tool gave.
struct Run {
    status: Option<i32>,
    output: String,
    error: String,
}

fn run(arguments: &[&str]) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_credential-enclave-verify"))
        .args(arguments)
        .output()
        .expect("the tool runs");
    Run {
        status: output.status.code(),
        output: String::from_utf8(output.stdout).expect("the standard output is UTF-8"),
        error: String::from_utf8(output.stderr).expect("the standard error is UTF-8"),
    }
}

fn fixture(name: &str) -> String {
    format!(
        "{}/tests/fixtures/secure-program/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// A directory for the tampered copies of the fixtures, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let directory = std::env::temp_dir().join(format!(
            "credential-enclave-verify-program-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).expect("the scratch directory is created");
        Scratch(directory)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).expect("the file is written");
        path.to_string_lossy().into_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Standard base64 (`+`, `/`, padding), through the url-safe decoder and encoder of the
/// protocol crate.
fn standard_decode(text: &str) -> Vec<u8> {
    let url_safe = text
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_");
    b64u_decode(&url_safe).expect("standard base64")
}

fn standard_encode(bytes: &[u8]) -> String {
    let mut text = b64u(bytes).replace('-', "+").replace('_', "/");
    while !text.len().is_multiple_of(4) {
        text.push('=');
    }
    text
}

/// `text` (ASCII) with the character at `index` replaced by `character`.
fn replaced(text: &str, index: usize, character: char) -> String {
    let mut characters: Vec<char> = text.chars().collect();
    characters[index] = character;
    characters.into_iter().collect()
}

/// A base64 text with one character changed to another character of the alphabet.
fn flipped_base64(text: &str, index: usize) -> String {
    let other = if text.as_bytes()[index] == b'A' {
        'B'
    } else {
        'A'
    };
    replaced(text, index, other)
}

/// A hexadecimal text with one character changed to another hexadecimal character.
fn flipped_hex(text: &str, index: usize) -> String {
    let other = if text.as_bytes()[index] == b'0' {
        '1'
    } else {
        '0'
    };
    replaced(text, index, other)
}

fn text_of(value: &Value) -> String {
    value.as_str().expect("a string").to_string()
}

#[test]
fn a_proof_that_holds() {
    let source = fixture("source.js");
    let release = fixture("release.json");
    let release_key = fixture("release-key.pem");
    let log_key = fixture("log-key.pem");

    // 0: the ten checks pass under the two keys of the fixtures.
    let passed = run(&[
        "program",
        "--source",
        source.as_str(),
        "--release",
        release.as_str(),
        "--release-key",
        release_key.as_str(),
        "--log-key",
        log_key.as_str(),
    ]);
    assert_eq!(passed.status, Some(0));
    assert_eq!(
        passed.output,
        format!(
            "program release secure-program-v27: version 27, sha256 {SHA256_OF_SOURCE}, log index 42: ok\n"
        )
    );
    assert_eq!(passed.error, "");

    // `--name=value`, and several log keys: the table holds every one of them.
    let several = run(&[
        "program",
        format!("--source={source}").as_str(),
        format!("--release={release}").as_str(),
        format!("--release-key={release_key}").as_str(),
        "--log-key",
        release_key.as_str(),
        "--log-key",
        log_key.as_str(),
    ]);
    assert_eq!(several.status, Some(0));
    assert_eq!(several.output, passed.output);
}

#[test]
fn the_compiled_in_keys_are_the_default() {
    let source = fixture("source.js");
    let release = fixture("release.json");

    // 1: without --log-key the log of the synthetic proof is not the pinned log.
    let no_log_key = run(&[
        "program",
        "--source",
        source.as_str(),
        "--release",
        release.as_str(),
        "--release-key",
        fixture("release-key.pem").as_str(),
    ]);
    assert_eq!(no_log_key.status, Some(1));
    assert!(no_log_key
        .output
        .starts_with("program release: failed: unknown_log: "));
    assert_eq!(no_log_key.error, "");

    // 1: without --release-key the body of the entry is not signed by the release key of the
    // operator.
    let no_release_key = run(&[
        "program",
        "--source",
        source.as_str(),
        "--release",
        release.as_str(),
        "--log-key",
        fixture("log-key.pem").as_str(),
    ]);
    assert_eq!(no_release_key.status, Some(1));
    assert_eq!(
        no_release_key.output,
        "program release: failed: entry_shape: the public key of the body is not the release key\n"
    );
}

#[test]
fn each_tampering_fails_with_the_code_of_its_check() {
    let scratch = Scratch::new("tampering");
    let source = fixture("source.js");
    let release_key = fixture("release-key.pem");
    let log_key = fixture("log-key.pem");
    let keys: [&str; 4] = [
        "--release-key",
        release_key.as_str(),
        "--log-key",
        log_key.as_str(),
    ];
    let proof: Value = serde_json::from_slice(
        &std::fs::read(fixture("release.json")).expect("the fixture is read"),
    )
    .expect("the fixture is JSON");
    let statement = String::from_utf8(
        b64u_decode(&text_of(&proof["statement"])).expect("the statement is base64url"),
    )
    .expect("the statement is UTF-8");
    let body_text = text_of(&proof["entry"]["body"]);
    let body: Value =
        serde_json::from_slice(&standard_decode(&body_text)).expect("the body is JSON");
    let with_body = |body: &Value| -> Value {
        let mut tampered = proof.clone();
        tampered["entry"]["body"] = Value::String(standard_encode(
            serde_json::to_string(body).expect("JSON").as_bytes(),
        ));
        tampered
    };

    let mut cases: Vec<(&str, Value)> = Vec::new();
    // 1: no statement; an entry that is not an object.
    let mut tampered = proof.clone();
    tampered
        .as_object_mut()
        .expect("an object")
        .remove("statement");
    cases.push(("proof_shape", tampered));
    let mut tampered = proof.clone();
    tampered["entry"] = Value::String("entry".to_string());
    cases.push(("proof_shape", tampered));
    // 2: another kind.
    let mut tampered = proof.clone();
    tampered["statement"] = Value::String(b64u(
        statement
            .replace("\"kind\":\"secure-program\"", "\"kind\":\"program\"")
            .as_bytes(),
    ));
    cases.push(("statement_shape", tampered));
    // 5: another log identifier.
    let mut tampered = proof.clone();
    let log_id = text_of(&proof["entry"]["log_id"]);
    tampered["entry"]["log_id"] = Value::String(flipped_hex(&log_id, 63));
    cases.push(("unknown_log", tampered));
    // 6: a body of another version.
    let mut other_version = body.clone();
    other_version["apiVersion"] = Value::String("0.0.2".to_string());
    cases.push(("entry_shape", with_body(&other_version)));
    // 7: a changed signature of the release key.
    let mut other_signature = body.clone();
    let signature = text_of(&body["spec"]["signature"]["content"]);
    other_signature["spec"]["signature"]["content"] = Value::String(flipped_base64(&signature, 20));
    cases.push(("release_signature", with_body(&other_signature)));
    // 8: a changed signed entry timestamp.
    let mut tampered = proof.clone();
    let timestamp = text_of(&proof["entry"]["signed_entry_timestamp"]);
    tampered["entry"]["signed_entry_timestamp"] = Value::String(flipped_base64(&timestamp, 20));
    cases.push(("log_signature", tampered));
    // 9: a changed root hash.
    let mut tampered = proof.clone();
    let root_hash = text_of(&proof["entry"]["inclusion_proof"]["root_hash"]);
    tampered["entry"]["inclusion_proof"]["root_hash"] = Value::String(flipped_hex(&root_hash, 63));
    cases.push(("inclusion_proof", tampered));
    // 10: a changed signature of the checkpoint.
    let mut tampered = proof.clone();
    let checkpoint = text_of(&proof["entry"]["inclusion_proof"]["checkpoint"]);
    let (note, signatures) = checkpoint
        .split_once("\n\n")
        .expect("the checkpoint has a signature block");
    let (head, signature) = signatures
        .trim_end_matches('\n')
        .rsplit_once(' ')
        .expect("a signature line");
    tampered["entry"]["inclusion_proof"]["checkpoint"] = Value::String(format!(
        "{note}\n\n{head} {}\n",
        flipped_base64(signature, 20)
    ));
    cases.push(("checkpoint", tampered));

    for (index, (code, tampered)) in cases.iter().enumerate() {
        let path = scratch.write(
            &format!("{index}-{code}.json"),
            serde_json::to_string(tampered).expect("JSON").as_bytes(),
        );
        let failed = run(&[
            &[
                "program",
                "--source",
                source.as_str(),
                "--release",
                path.as_str(),
            ][..],
            &keys[..],
        ]
        .concat());
        assert_eq!(failed.status, Some(1), "{code}");
        assert!(
            failed
                .output
                .starts_with(&format!("program release: failed: {code}: ")),
            "{code}: {}",
            failed.output
        );
        assert_eq!(failed.error, "", "{code}");
    }

    // 3: another program (one more byte) under the same proof.
    let mut other_source = std::fs::read(source.as_str()).expect("the source is read");
    other_source.push(b'\n');
    let other_source = scratch.write("source.js", &other_source);
    let failed = run(&[
        &[
            "program",
            "--source",
            other_source.as_str(),
            "--release",
            fixture("release.json").as_str(),
        ][..],
        &keys[..],
    ]
    .concat());
    assert_eq!(failed.status, Some(1));
    assert!(failed
        .output
        .starts_with("program release: failed: source_hash: "));

    // 4: a statement of version 28 over a program that declares 27.
    let failed = run(&[
        &[
            "program",
            "--source",
            source.as_str(),
            "--release",
            fixture("release-version-28.json").as_str(),
        ][..],
        &keys[..],
    ]
    .concat());
    assert_eq!(failed.status, Some(1));
    assert_eq!(
        failed.output,
        "program release: failed: version_mismatch: the source declares version 27, the statement 28\n"
    );
}

#[test]
fn arguments_without_a_result() {
    let source = fixture("source.js");
    let release = fixture("release.json");
    let missing = fixture("no-such-file.json");

    // 2: a file that does not exist, a release file that is not JSON, a key file that is not a
    // PEM public key, a missing argument, a missing value, an argument twice, an argument that
    // is not understood. Nothing goes to the standard output.
    for arguments in [
        &[
            "program",
            "--source",
            missing.as_str(),
            "--release",
            release.as_str(),
        ][..],
        &[
            "program",
            "--source",
            source.as_str(),
            "--release",
            missing.as_str(),
        ],
        &[
            "program",
            "--source",
            source.as_str(),
            "--release",
            source.as_str(),
        ],
        &[
            "program",
            "--source",
            source.as_str(),
            "--release",
            release.as_str(),
            "--release-key",
            source.as_str(),
        ],
        &[
            "program",
            "--source",
            source.as_str(),
            "--release",
            release.as_str(),
            "--log-key",
            missing.as_str(),
        ],
        &["program", "--source", source.as_str()],
        &["program", "--release", release.as_str()],
        &["program", "--source", source.as_str(), "--release"],
        &[
            "program",
            "--source",
            source.as_str(),
            "--release",
            release.as_str(),
            "--source",
            source.as_str(),
        ],
        &[
            "program",
            "--source",
            source.as_str(),
            "--release",
            release.as_str(),
            "--url",
            "x",
        ],
        &["program"],
    ] {
        let refused = run(arguments);
        assert_eq!(refused.status, Some(2), "{arguments:?}");
        assert_eq!(refused.output, "", "{arguments:?}");
        assert!(
            refused.error.starts_with("credential-enclave-verify: "),
            "{arguments:?}"
        );
    }

    // --help prints the usage.
    let help = run(&["program", "--help"]);
    assert_eq!(help.status, Some(0));
    assert!(help.output.starts_with("usage:\n"));
    assert!(help.output.contains("\n  --release {file}"));
    assert_eq!(help.error, "");
}
