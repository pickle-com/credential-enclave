//! Endorsements made by an independent implementation (Python with the `cryptography`
//! package, test keys): one that holds for each accepted case, and one per check that does
//! not. The file `fixtures/endorsement-vectors.json` holds the test release key, the test log
//! key and, per case, the endorsement, the release of the node, its clock and the verdict.

use credential_enclave_protocol::encoding::b64u_decode;
use credential_enclave_protocol::release::{
    public_key_der, verify_endorsement, LogEntry, ReleaseKeys,
};

#[test]
fn the_verdicts_of_an_independent_implementation_are_the_verdicts_of_this_one() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/endorsement-vectors.json")).unwrap();
    let text = |value: &serde_json::Value| value.as_str().unwrap().to_owned();
    let release_key = public_key_der(&text(&vectors["release_key_pem"])).unwrap();
    let log_key = public_key_der(&text(&vectors["log_key_pem"])).unwrap();
    let keys = ReleaseKeys {
        release: &release_key,
        log: &log_key,
    };
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() >= 20);
    for case in cases {
        let name = text(&case["name"]);
        let endorsement = &case["endorsement"];
        let entry = &endorsement["entry"];
        let statement = b64u_decode(&text(&endorsement["statement"])).unwrap();
        let (body, log_id, timestamp) = (
            text(&entry["body"]),
            text(&entry["log_id"]),
            text(&entry["signed_entry_timestamp"]),
        );
        let verdict = verify_endorsement(
            &statement,
            &LogEntry {
                body: &body,
                integrated_time: entry["integrated_time"].as_u64().unwrap(),
                log_index: entry["log_index"].as_u64().unwrap(),
                log_id: &log_id,
                signed_entry_timestamp: &timestamp,
            },
            &keys,
            &text(&case["own_release"]),
            case["now"].as_u64().unwrap(),
        );
        assert_eq!(verdict.is_ok(), case["ok"].as_bool().unwrap(), "{name}");
    }
}
