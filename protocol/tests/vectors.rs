//! The committed `vectors.json` equals a fresh run of the generator, and the library passes
//! every vector of protocol.md section 13 that it contains.

use std::process::Command;

use credential_enclave_protocol::app::{self, ChainError, EntryError, IndexError};
use credential_enclave_protocol::attestation::{
    read_binding, read_local_document, NodeBinding, AWS_NITRO_ROOT_G1,
};
use credential_enclave_protocol::encoding::{b64u, b64u_decode, verify, Signed};
use credential_enclave_protocol::envelope::{self, Envelope, TransferEnvelope, TransferGrant};
use credential_enclave_protocol::keys::{self, Custody, LogStoreId, NodeKeys};
use credential_enclave_protocol::log::{self, EntryKind, EntryParts, Head, Last, ParsedKey};
use credential_enclave_protocol::purpose;
use credential_enclave_protocol::record::{open_record, record_aad, seal_record, Record};
use credential_enclave_protocol::release::{
    public_key_der, verify_endorsement, LogEntry, LogForm, ReleaseKeys, TransparencyLog,
};
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

/// The parts of the keys of a listing of the vector `log`, read back by their shape under the
/// prefix of the chain.
fn parsed_keys(vector: &Value, keys: &Value) -> Vec<EntryParts> {
    let prefix = text(vector, "key_prefix");
    keys.as_array()
        .unwrap()
        .iter()
        .map(
            |key| match log::parse_object_key(key.as_str().unwrap(), prefix) {
                Some(ParsedKey::V2(parts)) => parts,
                other => panic!("a key of format 2: {other:?}"),
            },
        )
        .collect()
}

#[test]
fn log_chain() {
    let vector = &vectors()["log"];
    let node_public: [u8; 32] = array(vector, "node_sign_pk");
    let log_private = StaticSecret::from(array::<32>(vector, "log_private"));
    let user_id = text(vector, "user_id");
    assert_eq!(
        text(vector, "key_prefix"),
        log::chain_prefix(user_id, text(vector, "node"))
    );
    assert_eq!(text(vector, "chain_prefix_text"), purpose::LOG_CHAIN_V2);
    let checkpoint = Head {
        seq: vector["checkpoint"]["seq"].as_u64().unwrap(),
        hash: array(&vector["checkpoint"], "hash"),
    };
    let entries = vector["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);

    // Content verification: every object verifies against its key and its predecessor, its
    // key is the key the parts give, and it opens to its events.
    let mut keys = Vec::new();
    let mut cursor = checkpoint;
    for entry in entries {
        let carried = signed(&entry["entry"]);
        let parts = parsed_keys(vector, &Value::Array(vec![entry["key"].clone()])).remove(0);
        assert_eq!(parts.seq, entry["seq"].as_u64().unwrap());
        assert_eq!(parts.time_ms, entry["time_ms"].as_u64().unwrap());
        assert_eq!(parts.kind.letter().to_string(), text(entry, "kind"));
        assert_eq!(u64::from(parts.count), entry["count"].as_u64().unwrap());
        assert_eq!(parts.key_id, text(vector, "key_id"));
        assert_eq!(b64u(&parts.body_hash), text(entry, "body_hash"));
        assert_eq!(b64u(&parts.entry_hash), text(entry, "entry_hash"));
        let body =
            app::verify_entry_v2(&node_public, user_id, &parts, Some(&cursor), &carried).unwrap();
        let body_bytes = verify(&node_public, purpose::LOG_ENTRY_V2, &carried).unwrap();
        assert_eq!(body_bytes, text(entry, "body_text").as_bytes());
        assert_eq!(log::body_hash(&body_bytes), parts.body_hash);
        assert_eq!(
            log::entry_hash_v2(&cursor.hash, &parts.body_hash, &parts.fields()),
            parts.entry_hash
        );
        // The key of the vector writes the five parts of the hash input first.
        assert!(text(entry, "key").contains(&format!("/{}-", parts.fields())));
        let events = app::open_entry_v2(&log_private, &body_bytes).unwrap();
        assert_eq!(events.len(), body.count as usize);
        assert_eq!(
            serde_json::to_string(&Value::Array(events)).unwrap(),
            text(entry, "events_text")
        );
        cursor = Head {
            seq: parts.seq,
            hash: parts.entry_hash,
        };
        keys.push(parts);
    }
    assert!(vector["content_valid"].as_bool().unwrap());
    let kinds: Vec<EntryKind> = keys.iter().map(|parts| parts.kind).collect();
    assert_eq!(kinds, [EntryKind::Control, EntryKind::Use, EntryKind::Use]);
    let counts: Vec<u32> = keys.iter().map(|parts| parts.count).collect();
    assert_eq!(counts, [1, 3, 1]);

    // Index verification: the keys alone reach the hash of the head, and of the final head.
    let head = signed(&vector["head"]);
    let nonce = text(vector, "head_nonce");
    let verified = app::verify_index(
        &node_public,
        user_id,
        &checkpoint,
        &keys,
        &head,
        Some(nonce),
    );
    assert_eq!(verified.is_ok(), vector["index_valid"].as_bool().unwrap());
    let end = verified.unwrap();
    assert_eq!(end.seq, 3);
    assert_eq!(b64u(&end.hash), text(&entries[2], "entry_hash"));
    assert_eq!(
        app::verify_index(
            &node_public,
            user_id,
            &checkpoint,
            &keys,
            &signed(&vector["final_head"]),
            None
        ),
        Ok(end)
    );

    // Without the key of the middle entry the listing has a gap.
    let missing = &vector["missing_middle"];
    let without_middle = parsed_keys(vector, &missing["keys"]);
    assert_eq!(without_middle.len(), 2);
    assert!(!missing["index_valid"].as_bool().unwrap());
    assert_eq!(
        app::verify_index(
            &node_public,
            user_id,
            &checkpoint,
            &without_middle,
            &head,
            Some(nonce)
        ),
        Err(IndexError::Gap {
            seq: missing["gap_seq"].as_u64().unwrap()
        })
    );

    // A forged key next to the genuine one of seq 2 (another body hash and a chain hash that
    // is consistent with it): the keys alone cannot tell them apart, and the objects decide.
    let forged = &vector["forged_key"];
    let with_forged = parsed_keys(vector, &forged["keys"]);
    assert_eq!(with_forged.len(), 4);
    assert!(!forged["index_valid"].as_bool().unwrap());
    let ambiguous = forged["ambiguous_seq"].as_u64().unwrap();
    assert_eq!(
        app::verify_index(
            &node_public,
            user_id,
            &checkpoint,
            &with_forged,
            &head,
            Some(nonce)
        ),
        Err(IndexError::Ambiguous { seq: ambiguous })
    );
    let cursor = Head {
        seq: 1,
        hash: keys[0].entry_hash,
    };
    let object = signed(&entries[1]["entry"]);
    let candidates: Vec<&EntryParts> = with_forged
        .iter()
        .filter(|parts| parts.seq == ambiguous)
        .collect();
    assert_eq!(candidates.len(), 2);
    for candidate in candidates {
        let verifies =
            app::verify_entry_v2(&node_public, user_id, candidate, Some(&cursor), &object).is_ok();
        let genuine = candidate.body_hash == keys[1].body_hash;
        assert_eq!(verifies, genuine);
    }
    assert!(forged["genuine_object_verifies"].as_bool().unwrap());
    assert!(!forged["forged_key_object_verifies"].as_bool().unwrap());
}

#[test]
fn log_chain_of_format_1() {
    let vector = &vectors()["log_v1"];
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
        let body = verify(&node_public, purpose::LOG_ENTRY, &carried).unwrap();
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
fn log_of_format_3() {
    let vector = &vectors()["log_v3"];
    let log_private = StaticSecret::from(array::<32>(vector, "log_private"));
    let user_id = text(vector, "user_id");
    assert_eq!(text(vector, "hpke_info_text"), purpose::LOG_ENTRY_SEAL_V3);
    assert_eq!(
        text(vector, "signature_context_text"),
        purpose::LOG_ENTRY_V3
    );
    assert_eq!(
        text(vector, "control_prefix"),
        log::entry_prefix_v3(user_id, EntryKind::Control)
    );
    assert_eq!(
        text(vector, "use_prefix"),
        log::entry_prefix_v3(user_id, EntryKind::Use)
    );
    let entries = vector["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 4);
    assert_eq!(vector["verifies"], true);

    // Every object verifies against the parts of its key, which its key gives back, and opens
    // to its events. The body of an entry carries the hash of the body before it.
    let mut prev = b64u(&[0u8; 32]);
    let mut listed: Vec<Vec<String>> = vec![Vec::new(), Vec::new()];
    for entry in entries {
        let key = log::parse_object_key_v3(text(entry, "key"), user_id).expect("a key");
        assert_eq!(log::object_key_v3(user_id, &key), text(entry, "key"));
        assert_eq!(key.node, text(vector, "node"));
        assert_eq!(key.key_id, text(vector, "key_id"));
        assert_eq!(key.seq, entry["seq"].as_u64().unwrap());
        assert_eq!(key.time_ms, entry["time_ms"].as_u64().unwrap());
        assert_eq!(key.kind().letter().to_string(), text(entry, "kind"));
        assert_eq!(u64::from(key.count()), entry["count"].as_u64().unwrap());
        assert_eq!(b64u(&key.body_hash), text(entry, "body_hash"));
        let (body, body_bytes) =
            app::verify_entry_v3(user_id, &key, &signed(&entry["entry"])).unwrap();
        assert_eq!(body_bytes, text(entry, "body_text").as_bytes());
        assert_eq!((body.v, &body.prev), (3, &prev));
        let events = app::open_entry_v3(&log_private, &body_bytes).unwrap();
        let expected: Vec<Value> = serde_json::from_str(text(entry, "events_text")).unwrap();
        assert_eq!(events, expected);
        // The event name of a control key is the `t` of its one event.
        if let log::EntryLabel::Control(event) = &key.label {
            assert_eq!(events[0]["t"], event.as_str());
        }
        prev = b64u(&key.body_hash);
        listed[usize::from(key.kind() == EntryKind::Use)].push(text(entry, "key").to_string());
    }
    // A listing returns the keys of a prefix in the order of their bytes: the latest first.
    for (keys, name) in listed.iter_mut().zip(["control_listing", "use_listing"]) {
        keys.sort();
        let expected: Vec<&str> = vector[name]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key.as_str().unwrap())
            .collect();
        assert_eq!(keys, &expected);
        let times: Vec<u64> = keys
            .iter()
            .map(|key| log::parse_object_key_v3(key, user_id).unwrap().time_ms)
            .collect();
        assert!(times.windows(2).all(|pair| pair[0] > pair[1]), "{times:?}");
    }

    // An object that is not the entry of its key.
    let rejected = vector["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 3);
    for case in rejected {
        let key = log::parse_object_key_v3(text(case, "key"), user_id).expect("a key");
        let outcome = match app::verify_entry_v3(user_id, &key, &signed(&case["entry"])) {
            Ok(_) => "ok",
            Err(EntryError::Body) => "body",
            Err(EntryError::Signature) => "signature",
            Err(EntryError::Fields) => "fields",
        };
        assert_eq!(outcome, text(case, "result"), "{}", text(case, "name"));
        assert_ne!(outcome, "ok");
    }
    // Strings that are not keys of the account.
    assert_eq!(vector["a_key_of_not_keys_parses"], false);
    for key in vector["not_keys"].as_array().unwrap() {
        let key = key.as_str().unwrap();
        assert!(log::parse_object_key_v3(key, user_id).is_none(), "{key}");
    }

    // The node document: its key, its bucket, its nonce, and what a reader accepts.
    let document = &vector["node_document"];
    let node = text(vector, "node");
    let node_public: [u8; 32] = array(vector, "node_sign_pk");
    assert_eq!(text(document, "key"), log::node_document_key(node));
    assert_eq!(text(document, "nonce_prefix_text"), purpose::NODE_DOCUMENT);
    assert_eq!(
        array::<32>(document, "nonce"),
        log::node_document_nonce(&node_public)
    );
    let facts = app::read_node_document(
        text(document, "object_text").as_bytes(),
        node,
        AWS_NITRO_ROOT_G1,
    )
    .unwrap();
    assert_eq!(document["accepted"], true);
    assert_eq!((facts.platform.as_str(), facts.pcrs), ("local", None));
    assert_eq!(facts.binding.sign_public, node_public);
    let store = facts.binding.log.expect("the binding names the log store");
    assert_eq!(
        store.shard_of(keys::shard_hash(node)).as_deref(),
        Some(text(document, "bucket"))
    );
    for case in document["rejected"].as_array().unwrap() {
        let accepted = app::read_node_document(
            text(case, "object_text").as_bytes(),
            text(case, "node"),
            AWS_NITRO_ROOT_G1,
        )
        .is_ok();
        assert!(!accepted, "{}", text(case, "name"));
        assert_eq!(case["accepted"], false);
    }
}

#[test]
fn log_store_buckets() {
    let vector = &vectors()["log_store"];
    let stores = vector["stores"].as_array().unwrap();
    assert_eq!(stores.len(), 5);
    let mut counts = Vec::new();
    for case in stores {
        let store = LogStoreId::parse(text(case, "bucket"), text(case, "region")).unwrap();
        let shards = store.shards();
        assert_eq!(u64::from(shards), case["shards"].as_u64().unwrap());
        assert!(shards.is_power_of_two());
        assert_eq!(store.regional_host(), text(case, "host"));
        assert_eq!(
            store.shard_bucket(0).as_deref(),
            Some(text(case, "first_bucket"))
        );
        assert_eq!(
            store.shard_bucket(shards - 1).as_deref(),
            Some(text(case, "last_bucket"))
        );
        assert_eq!(store.shard_bucket(shards), None);
        for owner in case["owners"].as_array().unwrap() {
            let hash = keys::shard_hash(text(owner, "owner"));
            assert_eq!(u64::from(hash), owner["hash"].as_u64().unwrap());
            assert_eq!(u64::from(hash % shards), owner["index"].as_u64().unwrap());
            assert_eq!(store.shard_of(hash).as_deref(), Some(text(owner, "bucket")));
        }
        // Every bucket of a store has a bucket name of its own.
        let names: std::collections::BTreeSet<String> = (0..shards)
            .map(|index| store.shard_bucket(index).unwrap())
            .collect();
        assert_eq!(names.len(), usize::from(shards));
        assert!(names
            .iter()
            .all(|name| LogStoreId::parse(name, "us-west-2").is_some()));
        counts.push(shards);
    }
    assert_eq!(counts, [1024, 32, 32, 4, 32]);
    // The longest name of a log store that has buckets, and a name one character longer.
    let longest = &vector["longest_name"];
    assert_eq!(text(longest, "bucket").len(), keys::LOG_STORE_NAME_CHARS);
    assert_eq!(text(longest, "first_bucket").len(), 63);
    assert_eq!(vector["name_without_buckets"]["first_bucket"], Value::Null);
}

#[test]
fn log_entries_are_reproducible_from_their_seeds() {
    let all = vectors();
    let command = &all["command"];
    let node = NodeKeys::from_random(
        &array(command, "node_sign_seed"),
        &array(command, "node_seal_private"),
    );

    // Format 3: the entry and its key follow from the events, the seed and the entry before.
    let vector = &all["log_v3"];
    assert_eq!(text(vector, "node"), node.node());
    let mut last = Last::NONE;
    for entry in vector["entries"].as_array().unwrap() {
        let events: Vec<Value> = serde_json::from_str(text(entry, "events_text")).unwrap();
        let kind = EntryKind::parse(text(entry, "kind").chars().next().unwrap()).unwrap();
        let (created, next, key) = log::append_v3(
            &node,
            &last,
            text(vector, "user_id"),
            text(vector, "key_id"),
            &array(vector, "log_pk"),
            entry["time_ms"].as_u64().unwrap(),
            kind,
            &events,
            &Secret::new(array(entry, "hpke_seed")),
        )
        .unwrap();
        assert_eq!(created, signed(&entry["entry"]));
        assert_eq!(next.seq, entry["seq"].as_u64().unwrap());
        assert_eq!(
            log::object_key_v3(text(vector, "user_id"), &key),
            text(entry, "key")
        );
        last = next;
    }

    // Format 2: the entry and its key follow from the events, the seed and the chain before.
    let vector = &all["log"];
    assert_eq!(text(vector, "node"), node.node());
    let mut head = Head::EMPTY;
    for entry in vector["entries"].as_array().unwrap() {
        let events: Vec<Value> = serde_json::from_str(text(entry, "events_text")).unwrap();
        let kind = EntryKind::parse(text(entry, "kind").chars().next().unwrap()).unwrap();
        let (created, next, parts) = log::append_batch(
            &node,
            &head,
            text(vector, "user_id"),
            text(vector, "key_id"),
            &array(vector, "log_pk"),
            entry["time_ms"].as_u64().unwrap(),
            kind,
            &events,
            &Secret::new(array(entry, "hpke_seed")),
        );
        assert_eq!(created, signed(&entry["entry"]));
        assert_eq!(next.seq, entry["seq"].as_u64().unwrap());
        assert_eq!(
            log::object_key_v2(text(vector, "user_id"), &node.node(), &parts),
            text(entry, "key")
        );
        head = next;
    }

    // Format 1: the entry of the releases before v2.0.0 follows from the event and the seed.
    let vector = &all["log_v1"];
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

#[test]
fn endorsements() {
    let vector = &vectors()["endorsement"];
    let release_key = public_key_der(text(vector, "release_key_pem")).unwrap();
    // The table of the giving node: one log of each form.
    let logs: Vec<TransparencyLog> = vector["logs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let key = public_key_der(text(row, "key_pem")).unwrap();
            let log = match text(row, "form") {
                "rekor_v1" => TransparencyLog::rekor_v1(&key),
                "rekor_v2" => TransparencyLog::rekor_v2(text(row, "origin"), &key),
                other => panic!("a log of the form {other}"),
            }
            .unwrap();
            assert_eq!(log.id(), text(row, "log_id"));
            log
        })
        .collect();
    assert_eq!(
        logs.iter().map(TransparencyLog::form).collect::<Vec<_>>(),
        [LogForm::RekorV1, LogForm::RekorV2]
    );
    let keys = ReleaseKeys {
        release: &release_key,
        logs: &logs,
    };
    let cases = vector["cases"].as_array().unwrap();
    // An entry of each form holds, and every check has a case that fails it.
    let mut failed = std::collections::BTreeSet::new();
    let mut accepted = std::collections::BTreeSet::new();
    for case in cases {
        let name = text(case, "name");
        let endorsement = &case["endorsement"];
        let entry = LogEntry::read(&endorsement["entry"]).unwrap();
        let statement = bytes(endorsement, "statement");
        let verdict = verify_endorsement(
            &statement,
            &entry,
            &keys,
            text(case, "own_release"),
            case["now_s"].as_u64().unwrap(),
        );
        assert_eq!(
            verdict.is_ok(),
            case["accepted"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            verdict
                .as_ref()
                .err()
                .map(|failure| u64::from(failure.check())),
            case["check"].as_u64(),
            "{name}"
        );
        match verdict {
            Ok(later) => {
                assert_eq!(later.release, text(vector, "release"), "{name}");
                assert_eq!(statement, text(vector, "statement_text").as_bytes());
                accepted.insert(text(&endorsement["entry"], "log_id"));
            }
            Err(failure) => {
                failed.insert(failure.check());
            }
        }
    }
    assert_eq!(failed.into_iter().collect::<Vec<_>>(), [1, 2, 3, 4, 5, 6]);
    assert_eq!(accepted.len(), 2);
}
