//! Endorsements made by an independent implementation (Python with the `cryptography`
//! package, test keys): ones that hold, and one per rule that does not. The verdicts of that
//! implementation are the verdicts of this one.
//!
//! `fixtures/endorsement-vectors.json` holds endorsements whose entry is in a log of the form
//! Rekor v1, with the test release key and the test log key.
//! `fixtures/endorsement-vectors-rekor-v2.json` holds endorsements whose entry is in a log of
//! the form Rekor v2, with the test release key and the origin and the key of the test log.
//! Each case names the endorsement, the release of the node, its clock and the verdict.

use credential_enclave_protocol::encoding::b64u_decode;
use credential_enclave_protocol::release::{
    public_key_der, verify_endorsement, LogEntry, LogForm, ReleaseKeys, TransparencyLog,
};

fn text(value: &serde_json::Value) -> String {
    value.as_str().unwrap().to_owned()
}

/// Compares the verdict of this implementation on every case of `vectors` with the verdict
/// the file states. Returns the number of cases that hold and of cases that do not.
fn compare(vectors: &serde_json::Value, logs: &[TransparencyLog]) -> (usize, usize) {
    let release_key = public_key_der(&text(&vectors["release_key_pem"])).unwrap();
    let keys = ReleaseKeys {
        release: &release_key,
        logs,
    };
    let (mut held, mut refused) = (0, 0);
    for case in vectors["cases"].as_array().unwrap() {
        let name = text(&case["name"]);
        let endorsement = &case["endorsement"];
        // An endorsement that lacks a value or holds one of another type does not hold: a node
        // answers it like a check that fails.
        let verdict = endorsement["statement"]
            .as_str()
            .and_then(|statement| b64u_decode(statement).ok())
            .zip(LogEntry::read(&endorsement["entry"]))
            .is_some_and(|(statement, entry)| {
                verify_endorsement(
                    &statement,
                    &entry,
                    &keys,
                    &text(&case["own_release"]),
                    case["now"].as_u64().unwrap(),
                )
                .is_ok()
            });
        assert_eq!(verdict, case["ok"].as_bool().unwrap(), "{name}");
        match verdict {
            true => held += 1,
            false => refused += 1,
        }
    }
    (held, refused)
}

#[test]
fn the_verdicts_of_an_independent_implementation_are_the_verdicts_of_this_one() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/endorsement-vectors.json")).unwrap();
    let log_key = public_key_der(&text(&vectors["log_key_pem"])).unwrap();
    let log = TransparencyLog::rekor_v1(&log_key).unwrap();
    assert_eq!(log.form(), LogForm::RekorV1);
    let (held, refused) = compare(&vectors, &[log]);
    assert!(held >= 4 && refused >= 16, "{held} {refused}");
}

#[test]
fn the_verdicts_of_an_independent_implementation_on_the_entries_of_a_tiled_log() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/endorsement-vectors-rekor-v2.json")).unwrap();
    let log_key = public_key_der(&text(&vectors["log_key_pem"])).unwrap();
    let log = TransparencyLog::rekor_v2(&text(&vectors["log_origin"]), &log_key).unwrap();
    assert_eq!(log.form(), LogForm::RekorV2);
    assert_eq!(log.id(), text(&vectors["log_id"]));
    // The node of these cases knows a log of the other form as well: the entry of a tiled log
    // is not taken for an entry of that log, and the other way round.
    let other_key = public_key_der(&text(&vectors["rekor_v1_log_key_pem"])).unwrap();
    let other = TransparencyLog::rekor_v1(&other_key).unwrap();
    let (held, refused) = compare(&vectors, &[other, log]);
    assert!(held >= 8 && refused >= 30, "{held} {refused}");
}
