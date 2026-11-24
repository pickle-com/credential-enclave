//! The release proofs of `protocol/vectors/release-proofs.json` (protocol.md section 9): the
//! verdict of this implementation on every case is the verdict the file states.
//!
//! The file is made by `protocol/vectors/release_proofs.py`, which shares no code with this
//! crate, and the secure program of the app must give the same verdicts (`proveRelease` of
//! `secure-program/secure-program.js`). A case names what its proofs are verified with: a
//! trust of the file, or `source`, the values the node program compiles in
//! (`enclave/release/`).

use std::collections::BTreeMap;

use credential_enclave_protocol::encoding::b64u_decode;
use credential_enclave_protocol::release::{pem_der, TransparencyLog};
use credential_enclave_protocol::release_proofs::{
    read_builders, verify_release_proofs, Builder, ProofTrust, Repository, GITHUB_ACTIONS_ISSUER,
};
use serde_json::Value;

const VECTORS: &str = include_str!("../vectors/release-proofs.json");

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is a text"))
}

fn bytes(value: &Value) -> Vec<u8> {
    b64u_decode(value.as_str().unwrap()).unwrap()
}

/// The values the node program compiles in: the certificates of the certificate authority of
/// Sigstore, the key of Rekor, the repository of this source and its build workflows.
fn source() -> ProofTrust {
    let certificate = |pem: &str| pem_der(pem, "CERTIFICATE").unwrap();
    let key = pem_der(
        include_str!("../../enclave/release/rekor-key.pem"),
        "PUBLIC KEY",
    )
    .unwrap();
    ProofTrust::new(
        &certificate(include_str!("../../enclave/release/fulcio-root.pem")),
        &certificate(include_str!(
            "../../enclave/release/fulcio-intermediate.pem"
        )),
        vec![TransparencyLog::rekor_v1(&key).unwrap()],
        Repository::of_this_source(),
        read_builders(include_bytes!("../../enclave/release/builders.json")).unwrap(),
    )
    .unwrap()
}

/// A trust of the file. `None` for values no verifier takes as a trust: the root did not
/// issue the intermediate, or one of the two is not the certificate of a certificate
/// authority. No proofs hold under such values.
fn trust_of(stated: &Value) -> Option<ProofTrust> {
    assert_eq!(text(stated, "issuer"), GITHUB_ACTIONS_ISSUER);
    let logs = stated["log_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| TransparencyLog::rekor_v1(&bytes(key)).unwrap())
        .collect();
    let builders = stated["builders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|builder| Builder::new(text(builder, "workflow"), text(builder, "commit")).unwrap())
        .collect();
    ProofTrust::new(
        &bytes(&stated["fulcio_root"]),
        &bytes(&stated["fulcio_intermediate"]),
        logs,
        Repository {
            address: text(stated, "repository").to_string(),
            id: text(stated, "repository_id").to_string(),
            owner_id: text(stated, "owner_id").to_string(),
        },
        builders,
    )
}

fn pcr(text: &str) -> [u8; 48] {
    let digits: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect();
    digits.try_into().unwrap()
}

#[test]
fn the_verdict_on_every_case_is_the_verdict_of_the_file() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let mut trusts: BTreeMap<&str, Option<ProofTrust>> = vectors["trusts"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, stated)| (name.as_str(), trust_of(stated)))
        .collect();
    assert!(!trusts.contains_key("source"));
    trusts.insert("source", Some(source()));

    let cases = vectors["cases"].as_array().unwrap();
    let mut verdicts: BTreeMap<String, usize> = BTreeMap::new();
    let mut names = std::collections::BTreeSet::new();
    for case in cases {
        let name = text(case, "name");
        assert!(names.insert(name), "{name}: two cases of one name");
        let measurement = ["pcr0", "pcr1", "pcr2"].map(|key| pcr(text(&case["measurement"], key)));
        let trust = trusts
            .get(text(case, "trust"))
            .unwrap_or_else(|| panic!("{name}: no trust of that name"));
        // The text is parsed as the JSON body of a call is: a text that is no JSON is no
        // release proofs. A trust no verifier takes refuses at the certificates.
        let verdict = match (
            serde_json::from_str::<Value>(text(case, "release_proofs_text")),
            trust,
        ) {
            (Err(_), _) => Err("form".to_string()),
            (Ok(_), None) => Err("V3".to_string()),
            (Ok(proofs), Some(trust)) => verify_release_proofs(&proofs, &measurement, trust)
                .map(|stated| stated.release)
                .map_err(|failure| match failure.check() {
                    0 => "form".to_string(),
                    check => format!("V{check}"),
                }),
        };
        let stated = match case["accepted"].as_bool().unwrap() {
            true => Ok(text(case, "release").to_string()),
            false => Err(text(case, "rule").to_string()),
        };
        assert_eq!(verdict, stated, "{name}");
        *verdicts
            .entry(verdict.err().unwrap_or_else(|| "accepted".to_string()))
            .or_default() += 1;
    }
    // Proofs that hold, and proofs that every rule refuses.
    for verdict in ["accepted", "form", "V1", "V2", "V3", "V4", "V5", "V6", "V7"] {
        assert!(
            verdicts.get(verdict).is_some_and(|count| *count >= 5),
            "{verdict}"
        );
    }
}

#[test]
fn the_published_proofs_of_a_release_candidate_hold_for_the_build_workflow_that_attested_them() {
    // The release statement and the bundle of the attestation of release v2.4.0-rc.1, as its
    // GitHub release holds them. The job of the build workflow made the attestation at an
    // earlier commit of that file, and the node program of that tag hands delegations on by a
    // signature of the operator. The list of build workflows of this source does not name
    // that commit: the proofs hold for a trust that names it, and not for this source.
    let statement = include_bytes!("../vectors/published/v2.4.0-rc.1/measurements.json");
    let bundle: Value = serde_json::from_str(include_str!(
        "../vectors/published/v2.4.0-rc.1/release-statement.sigstore.json"
    ))
    .unwrap();
    let stated: Value = serde_json::from_slice(statement).unwrap();
    let measurement = ["pcr0", "pcr1", "pcr2"].map(|key| pcr(text(&stated, key)));
    let proofs = serde_json::json!({
        "statement": credential_enclave_protocol::encoding::b64u(statement),
        "attestation": bundle,
    });
    let vectors: Value =
        serde_json::from_str(include_str!("../vectors/release-proofs.json")).unwrap();
    let attested_by = trust_of(&vectors["trusts"]["sigstore-build-workflow-v2.4.0-rc.1"]).unwrap();
    let release = verify_release_proofs(&proofs, &measurement, &attested_by).unwrap();
    assert_eq!(release.release, "v2.4.0-rc.1");
    assert_eq!(
        release.git_commit,
        "4c21e0083064aec5300f6f8472a796607e83d9f3"
    );
    assert_eq!(release.pcrs, measurement);
    assert_eq!(release.measurement().pcrs, measurement);

    let refused = verify_release_proofs(&proofs, &measurement, &source()).unwrap_err();
    assert_eq!(refused.check(), 6, "{refused}");
}
