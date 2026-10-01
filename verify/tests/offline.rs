//! Runs the built tool on a stored document (`--document`): the exit status, the last line of
//! the report and the standard error. No request is sent.

use std::process::Command;

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
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn the_exit_status_of_a_stored_document() {
    // The document of a node of release v1.0.0, the nonce it was requested with, and the
    // measurements of that release.
    let document = fixture("nitro-attestation-alpha-prerelease.cbor");
    let nonce: String = std::fs::read(fixture("nitro-attestation-alpha-prerelease.cbor.nonce"))
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let measurements = fixture("measurements-prerelease.json");
    let stored = ["--document", document.as_str(), "--nonce", nonce.as_str()];

    // 0: every check passes.
    let passed = run(&[&stored[..], &["--measurements", measurements.as_str()]].concat());
    assert_eq!(passed.status, Some(0));
    assert!(passed.output.contains("\n    release   v1.0.0\n"));
    assert!(passed
        .output
        .ends_with("\n  result: pass\n\nsummary: 1 node: 1 passed, 0 failed.\n"));
    assert_eq!(passed.error, "");

    // 0, and the report says that nothing was compared.
    let uncompared = run(&stored);
    assert_eq!(uncompared.status, Some(0));
    assert!(uncompared.output.ends_with(
        "\nsummary: 1 node: 1 passed, 0 failed. No measurement was compared: no expected values were given.\n"
    ));

    // 1: another expected PCR2, and another nonce.
    let zero = "00".repeat(48);
    let pcr0 = "d11eea49deb3a47dd60db99c7017435722ea4aa13678097839054c00e330ada12c83412710f923b45167068e12aeaba7";
    let pcr1 = "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493";
    let other_pcr2 = [
        &stored[..],
        &["--pcr0", pcr0, "--pcr1", pcr1, "--pcr2", zero.as_str()],
    ]
    .concat();
    let failed = run(&other_pcr2);
    assert_eq!(failed.status, Some(1));
    assert!(failed
        .output
        .contains("\n    pass  pcr1: equals the expected value\n"));
    assert!(failed.output.contains(&format!(
        "\n    FAIL  pcr2: is not the expected value {zero}\n"
    )));
    assert!(failed
        .output
        .ends_with("\n  result: FAIL\n\nsummary: 1 node: 0 passed, 1 failed.\n"));
    assert_eq!(failed.error, "");

    let other_nonce = run(&[
        "--document",
        document.as_str(),
        "--nonce",
        "00",
        "--measurements",
        measurements.as_str(),
    ]);
    assert_eq!(other_nonce.status, Some(1));
    assert!(other_nonce.output.contains(
        "\n    FAIL  nonce: the nonce of the document is not the nonce that was asked for\n"
    ));

    // 2: no result. A file that does not exist, a measurements file that is not one, and
    // arguments that are not understood. Nothing goes to the standard output.
    let missing = fixture("no-such-document.cbor");
    for arguments in [
        &["--document", missing.as_str(), "--nonce", nonce.as_str()][..],
        &[&stored[..], &["--measurements", missing.as_str()]].concat(),
        &[&stored[..], &["--measurements", document.as_str()]].concat(),
        &["--document", document.as_str()],
        &[&stored[..], &["--pcr0", pcr0]].concat(),
        &[],
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
    let help = run(&["--help"]);
    assert_eq!(help.status, Some(0));
    assert!(help.output.starts_with("usage:\n"));
    assert_eq!(help.error, "");
}
