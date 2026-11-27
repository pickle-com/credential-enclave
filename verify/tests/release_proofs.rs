//! Runs the built tool with `release-proofs` on the published release proofs of
//! `protocol/vectors/published/`: the exit status and the output for the proofs of a release
//! the build workflow of this source attested, for the proofs of releases it did not attest
//! and for proofs with one value changed (the check that fails), and for arguments without a
//! result. No request is sent.

use std::path::PathBuf;
use std::process::Command;

use credential_enclave_protocol::encoding::b64u;
use serde_json::{json, Value};

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

/// A file of `protocol/vectors/published/{release}/`.
fn published(release: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../protocol/vectors/published")
        .join(release)
        .join(name)
}

/// The release proofs of a published release, as its release workflow writes them: the
/// statement in base64url beside the bundle of its attestation.
fn proofs_of(release: &str) -> Value {
    let statement = std::fs::read(published(release, "measurements.json")).unwrap();
    let bundle: Value = serde_json::from_slice(
        &std::fs::read(published(release, "release-statement.sigstore.json")).unwrap(),
    )
    .unwrap();
    json!({"statement": b64u(&statement), "attestation": bundle})
}

/// A directory for the files of a test, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let directory = std::env::temp_dir().join(format!(
            "credential-enclave-verify-release-proofs-{}-{name}",
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

const RC2: &str = "release proofs: release v2.4.0-rc.2, \
commit ebf4358294a6a1e92db804ab3286684b232f8981, \
pcr0 0d92c7d5c9e00f526eaff129a548e33ce6324330b8b3c3e655dcac9a3d05978cff0f7d4c92fc39bc99a9123a15a2658e, \
pcr1 4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493, \
pcr2 de865be1108c177b010827f6cbf983366d5bc375ece626473ff3d05002840ae453606f68c385370701b2ae4148e8b3ed, \
the measurement of ";

#[test]
fn the_published_proofs_of_a_release_built_by_the_build_workflow_hold() {
    let scratch = Scratch::new("hold");
    let proofs = scratch.write(
        "release-proofs.json",
        proofs_of("v2.4.0-rc.2").to_string().as_bytes(),
    );
    let ran = run(&["release-proofs", &proofs]);
    assert_eq!(
        (ran.status, ran.output.as_str(), ran.error.as_str()),
        (
            Some(0),
            format!("{RC2}the statement of the proofs: ok\n").as_str(),
            ""
        )
    );
    // The same against the measurements.json of the release, and against its three values.
    let measurements = published("v2.4.0-rc.2", "measurements.json");
    let measurements = measurements.to_str().unwrap();
    let ran = run(&["release-proofs", &proofs, "--measurements", measurements]);
    assert_eq!(ran.status, Some(0), "{}{}", ran.output, ran.error);
    assert_eq!(ran.output, format!("{RC2}{measurements}: ok\n"));
    let stated: Value = serde_json::from_slice(&std::fs::read(measurements).unwrap()).unwrap();
    let pcr = |name: &str| stated[name].as_str().unwrap().to_string();
    let ran = run(&[
        "release-proofs",
        &proofs,
        "--pcr0",
        &pcr("pcr0"),
        "--pcr1",
        &pcr("pcr1"),
        "--pcr2",
        &pcr("pcr2"),
    ]);
    assert_eq!(ran.status, Some(0), "{}{}", ran.output, ran.error);
    assert_eq!(ran.output, format!("{RC2}--pcr0, --pcr1 and --pcr2: ok\n"));
}

#[test]
fn the_proofs_of_a_release_candidate_an_earlier_build_workflow_attested_fail() {
    // The job of the build workflow attested release v2.4.0-rc.1 at an earlier commit of that
    // file, and the node program of that tag hands delegations on by a signature of the
    // operator. The list of build workflows of this source does not name that commit, so the
    // tool and the nodes of this source do not take those proofs.
    let scratch = Scratch::new("earlier");
    let proofs = scratch.write(
        "release-proofs.json",
        proofs_of("v2.4.0-rc.1").to_string().as_bytes(),
    );
    let ran = run(&["release-proofs", &proofs]);
    assert_eq!(
        (ran.status, ran.output.as_str(), ran.error.as_str()),
        (
            Some(1),
            "release proofs: failed: V6: the certificate does not state the value asked for in its extension 1.3.6.1.4.1.57264.1.10\n",
            ""
        )
    );
}

#[test]
fn proofs_that_do_not_hold_end_with_the_status_1_and_the_check_they_fail() {
    let scratch = Scratch::new("fail");
    let failed = |name: &str, proofs: &Value, more: &[&str]| {
        let path = scratch.write(name, proofs.to_string().as_bytes());
        let ran = run(&[&["release-proofs", path.as_str()], more].concat());
        assert_eq!((ran.status, ran.error.as_str()), (Some(1), ""), "{name}");
        ran.output
    };
    // The proofs of release v2.3.0: a job of the release workflow of that tag made the
    // attestation, before the build workflow existed. No node takes them.
    assert_eq!(
        failed("v2.3.0.json", &proofs_of("v2.3.0"), &[]),
        "release proofs: failed: V6: the certificate does not state the value asked for in its extension 1.3.6.1.4.1.57264.1.9\n"
    );
    // The proofs of one release for the measurement of another.
    let other = published("v2.3.0", "measurements.json");
    assert_eq!(
        failed(
            "other-measurement.json",
            &proofs_of("v2.4.0-rc.2"),
            &["--measurements", other.to_str().unwrap()]
        ),
        "release proofs: failed: V1: the measurement of the statement is not the measurement asked for\n"
    );
    // The statement of one release with the attestation of another.
    let mut mixed = proofs_of("v2.4.0-rc.2");
    mixed["statement"] = proofs_of("v2.3.0")["statement"].clone();
    assert_eq!(
        failed("mixed.json", &mixed, &[]),
        "release proofs: failed: V6: the certificate does not state the value asked for in its extension 1.3.6.1.4.1.57264.1.13\n"
    );
    // A changed time of the log entry, a missing inclusion proof, and a value that is no
    // proofs.
    let mut later = proofs_of("v2.4.0-rc.2");
    let entry = &mut later["attestation"]["verificationMaterial"]["tlogEntries"][0];
    let time: u64 = entry["integratedTime"].as_str().unwrap().parse().unwrap();
    entry["integratedTime"] = json!((time + 1).to_string());
    assert_eq!(
        failed("later.json", &later, &[]),
        "release proofs: failed: V4: the signed entry timestamp is not the signature of the log over this entry\n"
    );
    let mut unproven = proofs_of("v2.4.0-rc.2");
    unproven["attestation"]["verificationMaterial"]["tlogEntries"][0]
        .as_object_mut()
        .unwrap()
        .remove("inclusionProof");
    assert_eq!(
        failed("unproven.json", &unproven, &[]),
        "release proofs: failed: V4: the audit path does not lead from the entry to the root hash of its proof\n"
    );
    assert_eq!(
        failed("array.json", &json!([proofs_of("v2.4.0-rc.2")]), &[]),
        "release proofs: failed: form: the value is not a JSON object of a statement and an attestation, of at most 32 levels\n"
    );
}

#[test]
fn arguments_and_files_without_a_result_end_with_the_status_2() {
    let scratch = Scratch::new("no-result");
    let missing = scratch.0.join("missing.json");
    let ran = run(&["release-proofs", missing.to_str().unwrap()]);
    assert_eq!((ran.status, ran.output.as_str()), (Some(2), ""));
    assert!(
        ran.error.starts_with("credential-enclave-verify: "),
        "{}",
        ran.error
    );

    let text = scratch.write("text.json", b"not json");
    let ran = run(&["release-proofs", &text]);
    assert_eq!((ran.status, ran.output.as_str()), (Some(2), ""));
    assert!(ran.error.ends_with(": not JSON\n"), "{}", ran.error);

    let proofs = scratch.write(
        "release-proofs.json",
        proofs_of("v2.4.0-rc.1").to_string().as_bytes(),
    );
    let ran = run(&["release-proofs", &proofs, "--measurements", &text]);
    assert_eq!((ran.status, ran.output.as_str()), (Some(2), ""));
    let ran = run(&["release-proofs"]);
    assert_eq!((ran.status, ran.output.as_str()), (Some(2), ""));
    assert!(ran.error.contains("usage:"), "{}", ran.error);
}
