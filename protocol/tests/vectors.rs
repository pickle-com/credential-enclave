//! The committed `vectors.json` equals a fresh run of the generator, and the library passes
//! every vector of protocol.md section 13 that it contains.

use std::process::Command;

use credential_enclave_protocol::app::{self, ChainError};
use credential_enclave_protocol::attestation::{read_binding, read_local_document, NodeBinding};
use credential_enclave_protocol::encoding::{b64u, b64u_decode, verify, Signed};
use credential_enclave_protocol::envelope::{self, Envelope, TransferEnvelope, TransferGrant};
use credential_enclave_protocol::keys::{self, Custody, NodeKeys};
use credential_enclave_protocol::log::{self, Head};
use credential_enclave_protocol::record::{open_record, record_aad, seal_record, Record};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::totp::totp;
use ed25519_dalek::SigningKey;
use serde_json::Value;
use x25519_dalek::StaticSecret;

const COMMITTED: &str = include_str!("../vectors.json");

fn vectors() -> Value {
    serde_json::from_str(COMMITTED).expect("vectors.json is JSON")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is a string"))
}

fn bytes(value: &Value, key: &str) -> Vec<u8> {
    b64u_decode(text(value, key)).unwrap_or_else(|_| panic!("{key} is base64url"))
}

fn array<const N: usize>(value: &Value, key: &str) -> [u8; N] {
    bytes(value, key)
        .try_into()
        .unwrap_or_else(|_| panic!("{key} has {N} bytes"))
}

fn signed(value: &Value) -> Signed {
    Signed {
        body: text(value, "body").to_string(),
        sig: text(value, "sig").to_string(),
    }
}

#[test]
fn the_committed_file_equals_a_fresh_run() {
    let output = Command::new(env!("CARGO_BIN_EXE_vectors"))
        .arg("--stdout")
        .output()
        .expect("the generator runs");
    assert!(output.status.success());
    assert!(
        output.stdout == COMMITTED.as_bytes(),
        "protocol/vectors.json is stale: run `cargo run -p credential-enclave-protocol --bin vectors`"
    );
}

#[test]
fn key_derivation() {
    let vector = &vectors()["key_derivation"];
    let keys = app::derive_account_keys(&array(vector, "master_key"));
    assert_eq!(b64u(&keys.sign.to_bytes()), text(vector, "sign_seed"));
    assert_eq!(b64u(&keys.sign_pk()), text(vector, "sign_pk"));
    assert_eq!(b64u(&keys.log.to_bytes()), text(vector, "log_private"));
    assert_eq!(b64u(&keys.log_pk()), text(vector, "log_pk"));
    assert_eq!(b64u(keys.user_key.as_slice()), text(vector, "user_key"));
    assert_eq!(
        b64u(keys.user_key_operator.as_slice()),
        text(vector, "user_key_operator")
    );
    assert_ne!(text(vector, "user_key"), text(vector, "user_key_operator"));
    assert_eq!(keys.key_id(), text(vector, "key_id"));
}

#[test]
fn record() {
    let vector = &vectors()["record"];
    let user_key: [u8; 32] = array(vector, "user_key");
    let id: [u8; 16] = array(vector, "id");
    let custody = Custody::parse(text(vector, "custody")).expect("custody");
    // The record vector is encrypted under the user key of its custody.
    assert_eq!(
        text(vector, "user_key"),
        match custody {
            Custody::Enclave => text(&vectors()["key_derivation"], "user_key").to_string(),
            Custody::Operator =>
                text(&vectors()["key_derivation"], "user_key_operator").to_string(),
        }
    );
    let expected: Record = serde_json::from_value(vector["record"].clone()).unwrap();
    assert_eq!(expected.custody, custody.as_str());
    let plaintext = bytes(vector, "plaintext");
    assert_eq!(plaintext, text(vector, "plaintext_text").as_bytes());
    assert_eq!(
        b64u(keys::record_key(&user_key, &id).as_slice()),
        text(vector, "record_key")
    );
    assert_eq!(
        record_aad(
            text(vector, "id"),
            text(vector, "user_id"),
            text(vector, "key_id"),
            text(vector, "custody"),
            text(vector, "kind"),
            text(vector, "provider"),
        ),
        text(vector, "aad_text").as_bytes()
    );
    let sealed = seal_record(
        &user_key,
        &id,
        &array(vector, "nonce"),
        text(vector, "user_id"),
        text(vector, "key_id"),
        custody,
        text(vector, "kind"),
        text(vector, "provider"),
        &plaintext,
    );
    assert_eq!(sealed, expected);
    assert_eq!(
        open_record(&user_key, &expected).unwrap().as_slice(),
        plaintext.as_slice()
    );
    // The record of kind `oauth_imported` is made with the same key, user and custody.
    let imported = &vector["imported"];
    assert_eq!(text(imported, "kind"), "oauth_imported");
    let imported_id: [u8; 16] = array(imported, "id");
    let imported_plaintext = bytes(imported, "plaintext");
    assert_eq!(
        imported_plaintext,
        text(imported, "plaintext_text").as_bytes()
    );
    assert_eq!(
        b64u(keys::record_key(&user_key, &imported_id).as_slice()),
        text(imported, "record_key")
    );
    assert_eq!(
        record_aad(
            text(imported, "id"),
            text(vector, "user_id"),
            text(vector, "key_id"),
            text(vector, "custody"),
            text(imported, "kind"),
            text(imported, "provider"),
        ),
        text(imported, "aad_text").as_bytes()
    );
    let expected_imported: Record = serde_json::from_value(imported["record"].clone()).unwrap();
    assert_eq!(
        seal_record(
            &user_key,
            &imported_id,
            &array(imported, "nonce"),
            text(vector, "user_id"),
            text(vector, "key_id"),
            custody,
            text(imported, "kind"),
            text(imported, "provider"),
            &imported_plaintext,
        ),
        expected_imported
    );
    assert_eq!(
        open_record(&user_key, &expected_imported)
            .unwrap()
            .as_slice(),
        imported_plaintext.as_slice()
    );
    let tampered = vector["tampered"].as_array().unwrap();
    let fields: Vec<&str> = tampered.iter().map(|case| text(case, "field")).collect();
    assert_eq!(
        fields,
        ["id", "user_id", "key_id", "custody", "kind", "provider"]
    );
    for case in tampered {
        let record = Record::from_value(&case["record"]).unwrap();
        assert_eq!(
            open_record(&user_key, &record).is_ok(),
            case["opens"].as_bool().unwrap(),
            "{}",
            text(case, "field")
        );
    }
}

#[test]
fn command_envelopes() {
    let vector = &vectors()["command"];
    let node = NodeKeys::from_random(
        &array(vector, "node_sign_seed"),
        &array(vector, "node_seal_private"),
    );
    assert_eq!(node.node(), text(vector, "node"));
    assert_eq!(b64u(&node.sign_public()), text(vector, "node_sign_pk"));
    assert_eq!(b64u(&node.seal_public()), text(vector, "node_seal_pk"));
    let cases = vector["cases"].as_array().unwrap();
    let mut results = Vec::new();
    for case in cases {
        let name = text(case, "name");
        let outcome = match Envelope::from_value(&case["envelope"]) {
            Ok(envelope) => envelope::open_command(&node, &envelope),
            Err(error) => Err(error),
        };
        let result = match &outcome {
            Ok(_) => "ok",
            Err(error) => error.code(),
        };
        assert_eq!(result, text(case, "result"), "{name}");
        results.push(result);
        if let Ok(command) = outcome {
            let payload: Value =
                serde_json::from_slice(&bytes(case, "payload")).expect("payload is JSON");
            match command {
                envelope::Command::Grant(grant) => {
                    assert_eq!(text(&payload, "type"), "grant");
                    assert_eq!(grant.user_id, text(&payload, "user_id"));
                    assert_eq!(grant.node, text(&payload, "node"));
                    assert_eq!(grant.challenge, text(&payload, "challenge"));
                    assert_eq!(b64u(&grant.sign_pk), text(&payload, "sign_pk"));
                    assert_eq!(b64u(&grant.log_pk), text(&payload, "log_pk"));
                    assert_eq!(grant.custody.as_str(), text(&payload, "custody"));
                    assert_eq!(
                        b64u(grant.user_key.expose_secret()),
                        text(&payload, "user_key")
                    );
                    assert_eq!(
                        grant.not_after_ms,
                        payload["not_after_ms"].as_u64().unwrap()
                    );
                }
                envelope::Command::Revoke(revoke) => {
                    assert_eq!(text(&payload, "type"), "revoke");
                    assert_eq!(revoke.user_id, text(&payload, "user_id"));
                    assert_eq!(revoke.challenge, text(&payload, "challenge"));
                    assert_eq!(b64u(&revoke.sign_pk), text(&payload, "sign_pk"));
                }
            }
            assert_eq!(case["signature_valid"], Value::Bool(true), "{name}");
        }
    }
    assert_eq!(
        results,
        [
            "ok",
            "ok",
            "ok",
            "bad_signature",
            "wrong_node",
            "unsupported_version",
            "open_failed",
            "wrong_node",
            "unsupported_policy",
            "unsupported_version",
            "invalid_request",
            "invalid_request",
        ]
    );
    // The two grants carry the user key of their custody.
    let derived = &vectors()["key_derivation"];
    for (name, custody, user_key) in [
        ("grant", "enclave", "user_key"),
        ("grant_custody_operator", "operator", "user_key_operator"),
    ] {
        let case = cases
            .iter()
            .find(|case| text(case, "name") == name)
            .unwrap_or_else(|| panic!("{name}"));
        let payload: Value = serde_json::from_slice(&bytes(case, "payload")).unwrap();
        assert_eq!(text(&payload, "custody"), custody, "{name}");
        assert_eq!(
            text(&payload, "user_key"),
            text(derived, user_key),
            "{name}"
        );
    }
}

#[test]
fn replies_statements_and_heads() {
    let vector = &vectors()["signed"];
    let cases = vector["cases"].as_array().unwrap();
    let mut valid = 0;
    let mut invalid = 0;
    for case in cases {
        let outcome = verify(
            &array(case, "public_key"),
            text(case, "context_text"),
            &signed(case),
        );
        let expected = case["valid"].as_bool().unwrap();
        assert_eq!(outcome.is_ok(), expected, "{}", text(case, "name"));
        if let Ok(body) = outcome {
            assert_eq!(body, text(case, "body_text").as_bytes());
            valid += 1;
        } else {
            invalid += 1;
        }
    }
    assert_eq!((valid, invalid), (8, 4));
}

#[test]
fn log_chain() {
    let vector = &vectors()["log"];
    let node_public: [u8; 32] = array(vector, "node_sign_pk");
    let log_private = StaticSecret::from(array::<32>(vector, "log_private"));
    let user_id = text(vector, "user_id");
    let checkpoint = Head {
        seq: vector["checkpoint"]["seq"].as_u64().unwrap(),
        hash: array(&vector["checkpoint"], "hash"),
    };
    let entries = vector["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    let mut stored = Vec::new();
    for entry in entries {
        let carried = signed(&entry["entry"]);
        let body = verify(
            &node_public,
            credential_enclave_protocol::purpose::LOG_ENTRY,
            &carried,
        )
        .unwrap();
        assert_eq!(body, text(entry, "body_text").as_bytes());
        assert_eq!(b64u(&log::entry_hash(&body)), text(entry, "entry_hash"));
        assert_eq!(
            app::open_entry(&log_private, &body).unwrap(),
            text(entry, "event_text").as_bytes()
        );
        stored.push(carried);
    }
    let head = signed(&vector["head"]);
    let nonce = text(vector, "head_nonce");
    let verified = app::verify_chain(
        &node_public,
        user_id,
        &checkpoint,
        &stored,
        &head,
        Some(nonce),
    );
    assert_eq!(verified.is_ok(), vector["chain_valid"].as_bool().unwrap());
    let end = verified.unwrap();
    assert_eq!(end.seq, 3);
    assert_eq!(b64u(&end.hash), text(&entries[2], "entry_hash"));
    assert_eq!(
        app::verify_chain(
            &node_public,
            user_id,
            &checkpoint,
            &stored,
            &signed(&vector["final_head"]),
            None
        ),
        Ok(end)
    );

    let without_middle: Vec<Signed> = vector["missing_middle"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(signed)
        .collect();
    assert_eq!(without_middle.len(), 2);
    assert!(!vector["missing_middle"]["chain_valid"].as_bool().unwrap());
    assert_eq!(
        app::verify_chain(
            &node_public,
            user_id,
            &checkpoint,
            &without_middle,
            &head,
            Some(nonce)
        ),
        Err(ChainError::Broken)
    );
}

#[test]
fn log_entries_are_reproducible_from_their_seeds() {
    let all = vectors();
    let vector = &all["log"];
    let command = &all["command"];
    let node = NodeKeys::from_random(
        &array(command, "node_sign_seed"),
        &array(command, "node_seal_private"),
    );
    let mut head = Head::EMPTY;
    for entry in vector["entries"].as_array().unwrap() {
        let event: Value = serde_json::from_str(text(entry, "event_text")).unwrap();
        let (created, next) = log::append(
            &node,
            &head,
            text(vector, "user_id"),
            text(vector, "key_id"),
            &array(vector, "log_pk"),
            entry["time_ms"].as_u64().unwrap(),
            &event,
            &Secret::new(array(entry, "hpke_seed")),
        );
        assert_eq!(created, signed(&entry["entry"]));
        assert_eq!(next.seq, entry["seq"].as_u64().unwrap());
        head = next;
    }
}

/// The acceptance rule of protocol.md 4.4 for a `local` document: the nonce matches, the
/// binding parses with `v` 1, and the challenge statement is the statement of the node of the
/// binding for this nonce and the challenge of the response.
fn accept_local(response: &Value, nonce: &str) -> Option<NodeBinding> {
    if response["v"].as_u64() != Some(1) || response["platform"].as_str() != Some("local") {
        return None;
    }
    let document = read_local_document(&bytes(response, "document")).ok()?;
    if b64u(&document.nonce) != nonce {
        return None;
    }
    let binding = read_binding(&document.binding).ok()?;
    let statement: Signed = serde_json::from_value(response["challenge_statement"].clone()).ok()?;
    app::verify_challenge_statement(
        &binding.sign_public,
        &statement,
        &document.nonce,
        response["challenge"].as_str()?,
    )
    .ok()?;
    Some(binding)
}

#[test]
fn local_attestation() {
    let all = vectors();
    let vector = &all["attestation"]["local"];
    let binding = accept_local(&vector["response"], text(vector, "nonce")).expect("accepted");
    assert_eq!(b64u(&binding.sign_public), text(vector, "sign_pk"));
    assert_eq!(b64u(&binding.seal_public), text(vector, "seal_pk"));
    assert_eq!(binding.release, text(vector, "release"));
    assert_eq!(
        b64u(&binding.sign_public),
        text(&vector["response"], "node")
    );
    let node = NodeKeys::from_random(
        &array(&all["command"], "node_sign_seed"),
        &array(&all["command"], "node_seal_private"),
    );
    assert_eq!(
        keys::binding(&node, text(vector, "release"), None),
        bytes(vector, "binding")
    );
    assert_eq!(
        text(vector, "challenge_statement_text").as_bytes(),
        bytes(&vector["response"]["challenge_statement"], "body")
    );
    let rejected = vector["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 6);
    for case in rejected {
        assert!(
            accept_local(&case["response"], text(case, "nonce")).is_none(),
            "{}",
            text(case, "name")
        );
    }
    // The last four are refused for the challenge statement alone: the document and the
    // binding of each are those of the accepted response.
    for case in &rejected[2..] {
        assert_eq!(case["nonce"], vector["nonce"], "{}", text(case, "name"));
        assert_eq!(
            case["response"]["document"],
            vector["response"]["document"],
            "{}",
            text(case, "name")
        );
    }
    assert_eq!(all["attestation"]["nitro"]["included"], Value::Bool(false));
}

#[test]
fn delegation_transfer() {
    let vector = &vectors()["transfer"];
    let giving_public: [u8; 32] = array(vector, "from_sign_pk");
    let giving = NodeKeys::from_random(&array(vector, "from_sign_seed"), &[0u8; 32]);
    assert_eq!(giving.sign_public(), giving_public);
    assert_eq!(giving.node(), text(vector, "from"));
    let receiving = NodeKeys::from_random(
        &array(vector, "to_sign_seed"),
        &array(vector, "to_seal_private"),
    );
    assert_eq!(receiving.node(), text(vector, "to"));
    assert_eq!(b64u(&receiving.sign_public()), text(vector, "to_sign_pk"));
    assert_eq!(b64u(&receiving.seal_public()), text(vector, "to_seal_pk"));
    assert_eq!(
        envelope::transfer_aad(text(vector, "from"), text(vector, "to")),
        text(vector, "hpke_aad_text").as_bytes()
    );

    // The receiving node opens the envelope to the grants of the vector.
    let expected = vector["grants"].as_array().unwrap();
    let envelope = TransferEnvelope::from_value(&vector["envelope"]).unwrap();
    let opened = envelope::open_transfer(&receiving, &giving_public, &envelope).unwrap();
    assert_eq!(opened.time_ms, vector["time_ms"].as_u64().unwrap());
    assert_eq!(opened.grants.len(), expected.len());
    assert_eq!(expected.len(), 2);
    for (grant, expected) in opened.grants.iter().zip(expected) {
        assert_eq!(grant.user_id, text(expected, "user_id"));
        assert_eq!(b64u(&grant.sign_pk), text(expected, "sign_pk"));
        assert_eq!(b64u(&grant.log_pk), text(expected, "log_pk"));
        assert_eq!(grant.custody.as_str(), text(expected, "custody"));
        assert_eq!(
            b64u(grant.user_key.expose_secret()),
            text(expected, "user_key")
        );
        assert_eq!(
            grant.not_after_ms,
            expected["not_after_ms"].as_u64().unwrap()
        );
    }

    // The giving node makes the same envelope from the same grants and the same seed.
    let grants: Vec<TransferGrant> = opened.grants.clone();
    let sealed = envelope::seal_transfer(
        &giving,
        &receiving.sign_public(),
        &receiving.seal_public(),
        opened.time_ms,
        &grants,
        &Secret::new(array(vector, "hpke_seed")),
    )
    .unwrap();
    assert_eq!(sealed, envelope);
    assert_eq!(
        envelope::transfer_payload(
            text(vector, "from"),
            text(vector, "to"),
            opened.time_ms,
            &grants
        )
        .expose_secret()
        .as_slice(),
        text(vector, "payload_text").as_bytes()
    );
    assert_eq!(
        envelope::sign_transfer(
            &SigningKey::from_bytes(&array(vector, "from_sign_seed")),
            text(vector, "payload_text").as_bytes()
        )
        .as_slice(),
        bytes(vector, "signed").as_slice()
    );

    let mut results = Vec::new();
    for case in vector["cases"].as_array().unwrap() {
        let name = text(case, "name");
        let outcome = TransferEnvelope::from_value(&case["envelope"])
            .and_then(|envelope| envelope::open_transfer(&receiving, &giving_public, &envelope));
        let result = match &outcome {
            Ok(_) => "ok",
            Err(error) => error.code(),
        };
        assert_eq!(result, text(case, "result"), "{name}");
        results.push((
            name,
            result,
            case.get("opens").and_then(Value::as_bool),
            case.get("signature_valid").and_then(Value::as_bool),
        ));
    }
    assert_eq!(
        results,
        [
            ("transfer", "ok", Some(true), Some(true)),
            ("tampered_ciphertext", "open_failed", Some(false), None),
            (
                "signed_by_another_node",
                "bad_signature",
                Some(true),
                Some(false)
            ),
            ("envelope_for_another_node", "wrong_node", None, None),
        ]
    );
    assert_eq!(vector["cases"][0]["envelope"], vector["envelope"]);
}

#[test]
fn totp_codes() {
    for case in vectors()["totp"].as_array().unwrap() {
        assert_eq!(
            totp(text(case, "seed_base32"), case["time_ms"].as_u64().unwrap()).unwrap(),
            text(case, "code")
        );
    }
}
