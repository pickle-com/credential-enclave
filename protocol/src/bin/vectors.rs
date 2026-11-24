//! Generates `protocol/vectors.json`, the test vectors of protocol.md section 13.
//!
//! Every input that a node or an app would draw from a random source is derived here from a
//! fixed label, so a fresh run always produces the committed file.
//!
//! ```text
//! cargo run -p credential-enclave-protocol --bin vectors            # writes protocol/vectors.json
//! cargo run -p credential-enclave-protocol --bin vectors -- --check # fails when the file differs
//! cargo run -p credential-enclave-protocol --bin vectors -- --stdout
//! ```

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine;
use credential_enclave_protocol::app::{self, AccountKeys};
use credential_enclave_protocol::attestation::AWS_NITRO_ROOT_G1;
use credential_enclave_protocol::encoding::{
    b64u, b64u_decode, to_json, verify, verify_detached, Signed,
};
use credential_enclave_protocol::envelope::{
    self, Envelope, ReplyBody, TransferEnvelope, TransferGrant,
};
use credential_enclave_protocol::keys::{self, Custody, LogStoreId, NodeKeys};
use credential_enclave_protocol::log::{self, EntryKey, EntryKind, EntryParts, Head, Last};
use credential_enclave_protocol::record::{record_aad, seal_record, Kind};
use credential_enclave_protocol::released::{released_aad, seal_released, Receiver, SealTo};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::secret_use::{
    is_placed_in_header, is_site_host, BasicCredentials, BasicPart, Slot, DROPPED_HEADERS,
    REFUSED_HEADERS, REFUSED_SCHEMES,
};
use credential_enclave_protocol::vault_secret::{self, Reach};
use credential_enclave_protocol::{purpose, statement, subset, totp};
use ed25519_dalek::SigningKey;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use x25519_dalek::StaticSecret;

const RELEASE: &str = "v1.0.0";
const USER_ID: &str = "user-7f3a";
const TIME_MS: u64 = 1_790_000_000_000;

/// A fixed 32-byte value for a label.
fn fixed(label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"credential-enclave vectors v1\n");
    hasher.update(label.as_bytes());
    hasher.finalize().into()
}

fn fixed_prefix<const N: usize>(label: &str) -> [u8; N] {
    let mut output = [0u8; N];
    output.copy_from_slice(&fixed(label)[..N]);
    output
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("vector texts are UTF-8")
}

fn signed_value(signed: &Signed) -> Value {
    json!({"body": signed.body, "sig": signed.sig})
}

fn envelope_value(envelope: &Envelope) -> Value {
    json!({"v": envelope.v, "node": envelope.node, "enc": envelope.enc, "ct": envelope.ct})
}

fn node_keys() -> NodeKeys {
    NodeKeys::from_random(&fixed("node sign seed"), &fixed("node seal private"))
}

fn account_keys() -> AccountKeys {
    app::derive_account_keys(&fixed("master key"))
}

fn key_derivation() -> Value {
    let master_key = fixed("master key");
    let keys = app::derive_account_keys(&master_key);
    json!({
        "master_key": b64u(&master_key),
        "sign_seed": b64u(&keys.sign.to_bytes()),
        "sign_pk": b64u(&keys.sign_pk()),
        "log_private": b64u(&keys.log.to_bytes()),
        "log_pk": b64u(&keys.log_pk()),
        "user_key": b64u(keys.user_key.as_slice()),
        "user_key_operator": b64u(keys.user_key_operator.as_slice()),
        "key_id": keys.key_id(),
    })
}

fn record() -> Value {
    let keys = account_keys();
    let id: [u8; 16] = fixed_prefix("record id");
    let nonce: [u8; 12] = fixed_prefix("record nonce");
    let plaintext = br#"{"number":"4242424242424242","cvc":"123"}"#;
    let key_id = keys.key_id();
    let record = seal_record(
        &keys.user_key,
        &id,
        &nonce,
        USER_ID,
        &key_id,
        Custody::Enclave,
        "vault_card",
        "vault",
        plaintext,
    );
    let tampered: Vec<Value> = [
        ("id", b64u(&fixed_prefix::<16>("another record id"))),
        ("user_id", "user-0000".to_string()),
        ("key_id", "0000000000000000".to_string()),
        ("custody", Custody::Operator.as_str().to_string()),
        ("kind", "vault_password".to_string()),
        ("provider", "other".to_string()),
    ]
    .into_iter()
    .map(|(field, value)| {
        let mut changed = serde_json::to_value(&record).expect("record");
        changed[field] = Value::String(value);
        json!({"field": field, "record": changed, "opens": false})
    })
    .collect();
    // A record of kind `oauth_imported`: a device encrypts a token that the operator domain
    // held before it used a node. It is made with the user key, `user_id`, `key_id` and
    // custody of the record above. Its plaintext has the form of a record of kind `oauth`.
    let imported_id: [u8; 16] = fixed_prefix("imported record id");
    let imported_nonce: [u8; 12] = fixed_prefix("imported record nonce");
    let imported_plaintext = concat!(
        r#"{"token":{"access_token":"ya29.imported-access-token","expires_in":3599,"#,
        r#""refresh_token":"1//imported-refresh-token","scope":"openid email","#,
        r#""token_type":"Bearer"},"obtained_ms":1790000000000}"#
    )
    .as_bytes();
    let imported = seal_record(
        &keys.user_key,
        &imported_id,
        &imported_nonce,
        USER_ID,
        &key_id,
        Custody::Enclave,
        "oauth_imported",
        "google_workspace",
        imported_plaintext,
    );
    json!({
        "user_key": b64u(keys.user_key.as_slice()),
        "id": b64u(&id),
        "nonce": b64u(&nonce),
        "user_id": USER_ID,
        "key_id": key_id,
        "custody": Custody::Enclave.as_str(),
        "kind": "vault_card",
        "provider": "vault",
        "plaintext_text": text(plaintext),
        "plaintext": b64u(plaintext),
        "aad_text": text(&record_aad(
            &b64u(&id),
            USER_ID,
            &key_id,
            Custody::Enclave.as_str(),
            "vault_card",
            "vault",
        )),
        "record_key": b64u(keys::record_key(&keys.user_key, &id).as_slice()),
        "record": record,
        "tampered": tampered,
        "imported": {
            "id": b64u(&imported_id),
            "nonce": b64u(&imported_nonce),
            "kind": "oauth_imported",
            "provider": "google_workspace",
            "plaintext_text": text(imported_plaintext),
            "plaintext": b64u(imported_plaintext),
            "aad_text": text(&record_aad(
                &b64u(&imported_id),
                USER_ID,
                &key_id,
                Custody::Enclave.as_str(),
                "oauth_imported",
                "google_workspace",
            )),
            "record_key": b64u(keys::record_key(&keys.user_key, &imported_id).as_slice()),
            "record": imported,
        },
    })
}

/// One command vector. `result` is the outcome of the checks 1 to 9 of protocol.md 5.3, the
/// ones a node makes with its keys alone: `ok` or the failure code. When the envelope passes
/// step 1, `opens` tells whether the HPKE open of step 2 succeeds. When it opens, `payload` is
/// the command inside and `signature_valid` is the outcome of verifying `sig` with the
/// `sign_pk` of that command (step 6).
fn command_case(node: &NodeKeys, name: &str, envelope: &Envelope) -> Value {
    let mut case = Map::new();
    case.insert("name".to_string(), json!(name));
    case.insert("envelope".to_string(), envelope_value(envelope));
    case.insert(
        "result".to_string(),
        json!(match envelope::open_command(node, envelope) {
            Ok(_) => "ok",
            Err(error) => error.code(),
        }),
    );
    if envelope.v != 1 || envelope.node != node.node() {
        return Value::Object(case);
    }
    let opened = b64u_decode(&envelope.enc)
        .and_then(|enc| Ok((enc, b64u_decode(&envelope.ct)?)))
        .and_then(|(enc, ct)| {
            envelope::hpke_open(
                &StaticSecret::from(fixed("node seal private")),
                &enc,
                purpose::MESSAGE.as_bytes(),
                node.node().as_bytes(),
                &ct,
            )
        });
    case.insert("opens".to_string(), json!(opened.is_ok()));
    let Ok(signed) = opened else {
        return Value::Object(case);
    };
    let outer: Value = serde_json::from_slice(&signed).expect("vector commands are JSON");
    let payload = b64u_decode(outer["payload"].as_str().expect("payload")).expect("payload");
    let signature = b64u_decode(outer["sig"].as_str().expect("sig")).expect("sig");
    let command: Value = serde_json::from_slice(&payload).expect("vector payloads are JSON");
    let sign_pk: [u8; 32] = b64u_decode(command["sign_pk"].as_str().expect("sign_pk"))
        .expect("sign_pk")
        .try_into()
        .expect("sign_pk is 32 bytes");
    case.insert("payload_text".to_string(), json!(text(&payload)));
    case.insert("payload".to_string(), json!(b64u(&payload)));
    case.insert("sig".to_string(), json!(b64u(&signature)));
    case.insert(
        "signature_valid".to_string(),
        json!(verify_detached(&sign_pk, purpose::COMMAND, &payload, &signature).is_ok()),
    );
    Value::Object(case)
}

fn command() -> Value {
    let node = node_keys();
    let node_id = node.node();
    let account = account_keys();
    let other_account = app::derive_account_keys(&fixed("another master key"));
    let other_node = NodeKeys::from_random(
        &fixed("another node sign seed"),
        &fixed("another node seal private"),
    );
    let challenge = b64u(&fixed_prefix::<16>("challenge"));
    let not_after_ms = TIME_MS + 30 * 24 * 60 * 60 * 1000;
    let seal = |sign_with: &AccountKeys, payload: &[u8], label: &str| {
        app::seal_command(
            &sign_with.sign,
            &node.seal_public(),
            &node_id,
            payload,
            &fixed(label),
        )
        .expect("the node sealing key is usable")
    };

    let mut cases = Vec::new();

    let grant = app::grant_payload(
        &account,
        USER_ID,
        &node_id,
        &challenge,
        Custody::Enclave,
        not_after_ms,
    );
    let grant_envelope = seal(&account, &grant, "grant hpke seed");
    cases.push(command_case(&node, "grant", &grant_envelope));

    // The same account for a node of custody `operator`: the other user key.
    let operator_grant = app::grant_payload(
        &account,
        USER_ID,
        &node_id,
        &challenge,
        Custody::Operator,
        not_after_ms,
    );
    cases.push(command_case(
        &node,
        "grant_custody_operator",
        &seal(&account, &operator_grant, "operator grant hpke seed"),
    ));

    let revoke = app::revoke_payload(&account, USER_ID, &node_id, &challenge);
    cases.push(command_case(
        &node,
        "revoke",
        &seal(&account, &revoke, "revoke hpke seed"),
    ));

    cases.push(command_case(
        &node,
        "signed_by_another_key",
        &seal(&other_account, &grant, "bad signature hpke seed"),
    ));

    let mut wrong_envelope_node = grant_envelope.clone();
    wrong_envelope_node.node = other_node.node();
    cases.push(command_case(
        &node,
        "envelope_names_another_node",
        &wrong_envelope_node,
    ));

    let mut wrong_version = grant_envelope.clone();
    wrong_version.v = 2;
    cases.push(command_case(&node, "envelope_version_2", &wrong_version));

    let mut tampered = grant_envelope.clone();
    let mut ct = b64u_decode(&tampered.ct).expect("ct");
    ct[0] ^= 0x01;
    tampered.ct = b64u(&ct);
    cases.push(command_case(&node, "tampered_ciphertext", &tampered));

    let for_other_node = app::grant_payload(
        &account,
        USER_ID,
        &other_node.node(),
        &challenge,
        Custody::Enclave,
        not_after_ms,
    );
    cases.push(command_case(
        &node,
        "command_names_another_node",
        &seal(&account, &for_other_node, "wrong node hpke seed"),
    ));

    let mut with_policy: Value = serde_json::from_slice(&grant).expect("grant payload");
    with_policy["policy"] = json!({"approve_each_request": true});
    let with_policy = to_json(&with_policy);
    cases.push(command_case(
        &node,
        "policy_not_empty",
        &seal(&account, &with_policy, "policy hpke seed"),
    ));

    let mut version_2: Value = serde_json::from_slice(&grant).expect("grant payload");
    version_2["v"] = json!(2);
    let version_2 = to_json(&version_2);
    cases.push(command_case(
        &node,
        "command_version_2",
        &seal(&account, &version_2, "command version hpke seed"),
    ));

    let mut unknown_custody: Value = serde_json::from_slice(&grant).expect("grant payload");
    unknown_custody["custody"] = json!("hsm");
    let unknown_custody = to_json(&unknown_custody);
    cases.push(command_case(
        &node,
        "custody_unknown",
        &seal(&account, &unknown_custody, "custody hpke seed"),
    ));

    let stage_4 = to_json(&json!({
        "v": 1,
        "type": "oauth_code",
        "user_id": USER_ID,
        "node": node_id,
        "challenge": challenge,
        "sign_pk": b64u(&account.sign_pk()),
        "state": "c3RhdGU.operator",
        "code": "authorization-code",
    }));
    cases.push(command_case(
        &node,
        "stage_4_command",
        &seal(&account, &stage_4, "stage 4 hpke seed"),
    ));

    json!({
        "node_sign_seed": b64u(&fixed("node sign seed")),
        "node_sign_pk": b64u(&node.sign_public()),
        "node_seal_private": b64u(&fixed("node seal private")),
        "node_seal_pk": b64u(&node.seal_public()),
        "node": node_id,
        "hpke_info_text": purpose::MESSAGE,
        "hpke_aad_text": node.node(),
        "signature_context_text": purpose::COMMAND,
        "cases": cases,
    })
}

fn signed_case(name: &str, context: &str, public_key: &[u8; 32], signed: &Signed) -> Value {
    let valid = verify(public_key, context, signed).is_ok();
    json!({
        "name": name,
        "context_text": context,
        "public_key": b64u(public_key),
        "body": signed.body,
        "sig": signed.sig,
        "body_text": text(&b64u_decode(&signed.body).expect("body")),
        "valid": valid,
    })
}

fn signed() -> Value {
    let node = node_keys();
    let public = node.sign_public();
    let other = NodeKeys::from_random(
        &fixed("another node sign seed"),
        &fixed("another node seal private"),
    );
    let account = account_keys();
    let key_id = account.key_id();
    let sign_pk = account.sign_pk();
    let challenge = b64u(&fixed_prefix::<16>("challenge"));
    let head = Head {
        seq: 3,
        hash: fixed("head hash"),
    };
    let reply_body = |kind: &str, ok: bool, code: &str, not_after_ms: u64| ReplyBody {
        v: 1,
        kind: kind.to_string(),
        ok,
        code: code.to_string(),
        node: node.node(),
        user_id: USER_ID.to_string(),
        challenge: challenge.clone(),
        key_id: key_id.clone(),
        not_after_ms,
        time_ms: TIME_MS,
    };
    let grant_reply = envelope::reply(
        &node,
        &reply_body("grant_reply", true, "", TIME_MS + 2_592_000_000),
    );
    let failed_reply =
        envelope::reply(&node, &reply_body("grant_reply", false, "bad_challenge", 0));
    let revoke_reply = envelope::reply(&node, &reply_body("revoke_reply", true, "", 0));
    let state = format!("{}.operator-state", b64u(&fixed_prefix::<16>("node state")));
    let url = "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=client";
    let begin = statement::oauth_begin(
        &node,
        USER_ID,
        &key_id,
        &sign_pk,
        "google_workspace",
        &state,
        url,
        TIME_MS,
    );
    let complete = statement::oauth_complete(
        &node,
        USER_ID,
        &key_id,
        &sign_pk,
        "google_workspace",
        &state,
        &b64u(&fixed_prefix::<16>("record id")),
        TIME_MS,
    );
    let challenge_statement = statement::challenge(
        &node,
        &fixed("attestation nonce"),
        &fixed_prefix::<16>("challenge"),
        TIME_MS,
    );
    let nonce = b64u(&fixed_prefix::<16>("head nonce"));
    let live_head = log::signed_head(&node, USER_ID, &head, &nonce, TIME_MS, false);
    let final_head = log::signed_head(&node, USER_ID, &head, "", TIME_MS, true);

    let mut tampered_reply = grant_reply.clone();
    let mut body = b64u_decode(&tampered_reply.body).expect("body");
    let position = body
        .windows(4)
        .position(|window| window == b"true")
        .expect("ok is true");
    body.splice(position..position + 4, b"false".iter().copied());
    tampered_reply.body = b64u(&body);

    let forged_head = log::signed_head(&other, USER_ID, &head, &nonce, TIME_MS, false);

    json!({
        "authorization_url_text": url,
        "cases": [
            signed_case("grant_reply", purpose::REPLY, &public, &grant_reply),
            signed_case("grant_reply_failure", purpose::REPLY, &public, &failed_reply),
            signed_case("revoke_reply", purpose::REPLY, &public, &revoke_reply),
            signed_case("oauth_begin", purpose::STATEMENT, &public, &begin),
            signed_case("oauth_complete", purpose::STATEMENT, &public, &complete),
            signed_case("head", purpose::HEAD, &public, &live_head),
            signed_case("final_head", purpose::HEAD, &public, &final_head),
            signed_case("reply_with_changed_body", purpose::REPLY, &public, &tampered_reply),
            signed_case("statement_under_the_reply_context", purpose::REPLY, &public, &begin),
            signed_case("head_signed_by_another_node", purpose::HEAD, &public, &forged_head),
            signed_case("challenge", purpose::CHALLENGE, &public, &challenge_statement),
            signed_case("reply_under_the_challenge_context", purpose::CHALLENGE, &public, &revoke_reply),
        ],
    })
}

/// The vector `log`: a chain of format 2 (protocol.md 7.1) of three entries, the keys of its
/// objects, and the outcomes of the index verification over the keys and of the content
/// verification over the objects.
fn log_chain() -> Value {
    let node = node_keys();
    let account = account_keys();
    let key_id = account.key_id();
    let record_id = b64u(&fixed_prefix::<16>("record id"));
    let batches: [(EntryKind, Vec<Value>); 3] = [
        (
            EntryKind::Control,
            vec![json!({
                "t": "grant_accepted",
                "time_ms": TIME_MS + 1_000,
                "not_after_ms": TIME_MS + 2_592_000_000,
                "custody": Custody::Enclave.as_str(),
            })],
        ),
        (
            EntryKind::Use,
            (0..3u64)
                .map(|index| {
                    json!({
                        "t": "provider_request",
                        "time_ms": TIME_MS + 1_900 + index,
                        "record_id": record_id,
                        "provider": "google_workspace",
                        "method": "GET",
                        "host": "gmail.googleapis.com",
                        "path": format!("/gmail/v1/users/me/threads/thread-{index}"),
                        "query": "format=metadata",
                        "body_bytes": 0,
                        "body_sha256": "",
                        "context": "cli:gog",
                        "window_s": 300,
                    })
                })
                .collect(),
        ),
        (
            EntryKind::Use,
            vec![json!({
                "t": "secret_released",
                "time_ms": TIME_MS + 3_000,
                "record_id": record_id,
                "kind": "vault_card",
                "field": "card_number",
                "origin": "https://shop.example",
                "context": "browser:fill",
            })],
        ),
    ];
    let prefix = log::chain_prefix(USER_ID, &node.node());
    let mut head = Head::EMPTY;
    let mut entries = Vec::new();
    let mut signed_entries = Vec::new();
    let mut parts: Vec<EntryParts> = Vec::new();
    for (index, (kind, events)) in batches.iter().enumerate() {
        let seed = fixed(&format!("log entry {} hpke seed", index + 1));
        let time_ms = TIME_MS + 1_000 * (index as u64 + 1);
        let (entry, next, key) = log::append_batch(
            &node,
            &head,
            USER_ID,
            &key_id,
            &account.log_pk(),
            time_ms,
            *kind,
            events,
            &Secret::new(seed),
        );
        let body = b64u_decode(&entry.body).expect("entry body");
        entries.push(json!({
            "seq": next.seq,
            "hpke_seed": b64u(&seed),
            "time_ms": time_ms,
            "kind": kind.letter().to_string(),
            "count": events.len(),
            "events_text": text(&to_json(&Value::Array(events.clone()))),
            "entry": signed_value(&entry),
            "body_text": text(&body),
            "body_hash": b64u(&key.body_hash),
            "entry_hash": b64u(&key.entry_hash),
            "key": log::object_key_v2(USER_ID, &node.node(), &key),
        }));
        signed_entries.push(entry);
        parts.push(key);
        head = next;
    }
    let nonce = b64u(&fixed_prefix::<16>("chain head nonce"));
    let signed_head = log::signed_head(&node, USER_ID, &head, &nonce, TIME_MS + 4_000, false);
    let final_head = log::signed_head(&node, USER_ID, &head, "", TIME_MS + 5_000, true);
    let public = node.sign_public();
    let index_of = |keys: &[EntryParts]| {
        app::verify_index(
            &public,
            USER_ID,
            &Head::EMPTY,
            keys,
            &signed_head,
            Some(&nonce),
        )
    };
    let content_valid = signed_entries.iter().enumerate().all(|(index, entry)| {
        let cursor = match index {
            0 => Head::EMPTY,
            _ => Head {
                seq: parts[index - 1].seq,
                hash: parts[index - 1].entry_hash,
            },
        };
        match app::verify_entry_v2(&public, USER_ID, &parts[index], Some(&cursor), entry) {
            Ok(body) => {
                let bytes = b64u_decode(&entry.body).expect("entry body");
                body.count as usize == batches[index].1.len()
                    && app::open_entry_v2(&account.log, &bytes).as_deref()
                        == Ok(batches[index].1.as_slice())
            }
            Err(_) => false,
        }
    });
    let keys_of = |list: &[EntryParts]| -> Vec<Value> {
        list.iter()
            .map(|key| Value::String(log::object_key_v2(USER_ID, &node.node(), key)))
            .collect()
    };
    let without_middle = [parts[0].clone(), parts[2].clone()];
    let mut forged = parts[1].clone();
    forged.body_hash = log::body_hash(b"not the body of the entry");
    forged.entry_hash =
        log::entry_hash_v2(&parts[0].entry_hash, &forged.body_hash, &forged.fields());
    let with_forged = [
        parts[0].clone(),
        parts[1].clone(),
        forged.clone(),
        parts[2].clone(),
    ];
    let cursor = Head {
        seq: 1,
        hash: parts[0].entry_hash,
    };
    json!({
        "node_sign_pk": b64u(&public),
        "node": node.node(),
        "user_id": USER_ID,
        "key_id": key_id,
        "log_private": b64u(&account.log.to_bytes()),
        "log_pk": b64u(&account.log_pk()),
        "hpke_info_text": purpose::LOG_ENTRY_SEAL_V2,
        "signature_context_text": purpose::LOG_ENTRY_V2,
        "chain_prefix_text": purpose::LOG_CHAIN_V2,
        "key_prefix": prefix,
        "checkpoint": {"seq": 0, "hash": b64u(&Head::EMPTY.hash), "time_ms": 0},
        "entries": entries,
        "head_nonce": nonce,
        "head": signed_value(&signed_head),
        "head_text": text(&b64u_decode(&signed_head.body).expect("head body")),
        "final_head": signed_value(&final_head),
        "index_valid": index_of(&parts).is_ok(),
        "content_valid": content_valid,
        "missing_middle": {
            "keys": keys_of(&without_middle),
            "index_valid": index_of(&without_middle).is_ok(),
            "gap_seq": 2,
        },
        "forged_key": {
            "keys": keys_of(&with_forged),
            "index_valid": index_of(&with_forged).is_ok(),
            "ambiguous_seq": 2,
            "genuine_object_verifies": app::verify_entry_v2(
                &public, USER_ID, &parts[1], Some(&cursor), &signed_entries[1]
            ).is_ok(),
            "forged_key_object_verifies": app::verify_entry_v2(
                &public, USER_ID, &forged, Some(&cursor), &signed_entries[1]
            ).is_ok(),
        },
    })
}

/// The log store of the vectors `log_v3` and `log_store`.
fn log_store_id() -> LogStoreId {
    LogStoreId::parse("character-credential-log-dev-1", "us-west-2").expect("a log store name")
}

/// The vector `log_v3`: four entries of format 3 (protocol.md 7.1) of one node for one account,
/// the keys of their objects, the outcome of the verification of every object against its key,
/// objects that are not the entry of their key, strings that are not keys, and the node
/// document of the node.
fn log_v3() -> Value {
    let node = node_keys();
    let other = NodeKeys::from_random(
        &fixed("another node sign seed"),
        &fixed("another node seal private"),
    );
    let account = account_keys();
    let key_id = account.key_id();
    let record_id = b64u(&fixed_prefix::<16>("record id"));
    let batches: [(EntryKind, Vec<Value>); 4] = [
        (
            EntryKind::Control,
            vec![json!({
                "t": "grant_accepted",
                "time_ms": TIME_MS + 1_000,
                "not_after_ms": TIME_MS + 2_592_000_000,
                "custody": Custody::Enclave.as_str(),
            })],
        ),
        (
            EntryKind::Use,
            (0..3u64)
                .map(|index| {
                    json!({
                        "t": "provider_request",
                        "time_ms": TIME_MS + 1_900 + index,
                        "record_id": record_id,
                        "provider": "google_workspace",
                        "method": "GET",
                        "host": "gmail.googleapis.com",
                        "path": format!("/gmail/v1/users/me/threads/thread-{index}"),
                        "query": "format=metadata",
                        "body_bytes": 0,
                        "body_sha256": "",
                        "context": "cli:gog",
                        "window_s": 300,
                    })
                })
                .collect(),
        ),
        (
            EntryKind::Use,
            vec![json!({
                "t": "secret_released",
                "time_ms": TIME_MS + 3_000,
                "record_id": record_id,
                "kind": "vault_card",
                "field": "card_number",
                "origin": "https://shop.example",
                "context": "browser:fill",
            })],
        ),
        (
            EntryKind::Control,
            vec![json!({
                "t": "grant_transferred_out",
                "time_ms": TIME_MS + 4_000,
                "to": other.node(),
                "release": "v9.0.0",
                "pcr0": "11".repeat(48),
                "pcr1": "22".repeat(48),
                "pcr2": "33".repeat(48),
            })],
        ),
    ];
    let mut last = Last::NONE;
    let mut entries = Vec::new();
    let mut signed_entries = Vec::new();
    let mut keys: Vec<EntryKey> = Vec::new();
    let mut verifies = true;
    for (index, (kind, events)) in batches.iter().enumerate() {
        let seed = fixed(&format!("log v3 entry {} hpke seed", index + 1));
        let time_ms = TIME_MS + 1_000 * (index as u64 + 1);
        let (entry, next, key) = log::append_v3(
            &node,
            &last,
            USER_ID,
            &key_id,
            &account.log_pk(),
            time_ms,
            *kind,
            events,
            &Secret::new(seed),
        )
        .expect("an entry of the vector");
        let object_key = log::object_key_v3(USER_ID, &key);
        verifies &= log::parse_object_key_v3(&object_key, USER_ID).as_ref() == Some(&key)
            && match app::verify_entry_v3(USER_ID, &key, &entry) {
                Ok((_, body)) => {
                    app::open_entry_v3(&account.log, &body).as_deref() == Ok(events.as_slice())
                }
                Err(_) => false,
            };
        entries.push(json!({
            "seq": next.seq,
            "hpke_seed": b64u(&seed),
            "time_ms": time_ms,
            "kind": kind.letter().to_string(),
            "count": events.len(),
            "events_text": text(&to_json(&Value::Array(events.clone()))),
            "entry": signed_value(&entry),
            "body_text": text(&b64u_decode(&entry.body).expect("entry body")),
            "body_hash": b64u(&key.body_hash),
            "key": object_key,
        }));
        signed_entries.push(entry);
        keys.push(key);
        last = next;
    }
    // The keys of each prefix in the order a listing returns them: the order of their bytes,
    // which is the latest entry first.
    let listing = |kind: EntryKind| -> Vec<Value> {
        let mut listed: Vec<String> = keys
            .iter()
            .filter(|key| key.kind() == kind)
            .map(|key| log::object_key_v3(USER_ID, key))
            .collect();
        listed.sort();
        listed.into_iter().map(Value::String).collect()
    };
    let outcome = |key: &EntryKey, entry: &Signed| match app::verify_entry_v3(USER_ID, key, entry) {
        Ok(_) => "ok",
        Err(app::EntryError::Body) => "body",
        Err(app::EntryError::Signature) => "signature",
        Err(app::EntryError::Fields) => "fields",
    };
    // The body of entry 3 under the key of entry 2: not the body that key names.
    let other_body = (keys[1].clone(), signed_entries[2].clone());
    // The body of entry 2 with the signature of another node over it.
    let second_body = b64u_decode(&signed_entries[1].body).expect("entry body");
    let other_signature = (
        keys[1].clone(),
        Signed {
            body: signed_entries[1].body.clone(),
            sig: other.sign(purpose::LOG_ENTRY_V3, &second_body).sig,
        },
    );
    // The object of entry 2 under a key that names another `seq` beside the same hash.
    let mut another_seq = keys[1].clone();
    another_seq.seq = 7;
    let other_seq = (another_seq, signed_entries[1].clone());
    let rejected: Vec<Value> = [
        ("the_body_of_another_entry", &other_body),
        ("the_signature_of_another_node", &other_signature),
        ("a_key_of_another_seq", &other_seq),
    ]
    .iter()
    .map(|(name, (key, entry))| {
        json!({
            "name": name,
            "key": log::object_key_v3(USER_ID, key),
            "entry": signed_value(entry),
            "result": outcome(key, entry),
        })
    })
    .collect();
    let genuine = log::object_key_v3(USER_ID, &keys[0]);
    let not_keys: Vec<String> = vec![
        // The key of another account.
        genuine.replacen(USER_ID, "user-0000", 1),
        // A `seq` with a zero in front.
        genuine.replacen(".1.grant_accepted.", ".01.grant_accepted.", 1),
        // A use entry of 129 events.
        log::object_key_v3(USER_ID, &keys[2]).replacen(".3.1.", ".3.129.", 1),
        // An event name with an upper-case letter.
        genuine.replacen("grant_accepted", "Grant_accepted", 1),
        // A key of format 2.
        log::object_key_v2(
            USER_ID,
            &node.node(),
            &EntryParts {
                seq: 1,
                time_ms: TIME_MS,
                kind: EntryKind::Control,
                count: 1,
                key_id: key_id.clone(),
                body_hash: keys[0].body_hash,
                entry_hash: keys[0].body_hash,
            },
        ),
    ];
    let a_key_parses = not_keys
        .iter()
        .any(|key| log::parse_object_key_v3(key, USER_ID).is_some());

    // The node document of the node, on the local platform: the vectors hold no Nitro document.
    let store = log_store_id();
    let binding = keys::binding(&node, RELEASE, Some(&store));
    let nonce = log::node_document_nonce(&node.sign_public());
    let document = local_document(&binding, &nonce, TIME_MS);
    let object = log::node_document("local", &document, &node.node(), RELEASE);
    let reads = |object: &[u8], of: &NodeKeys| {
        app::read_node_document(object, &of.node(), AWS_NITRO_ROOT_G1).is_ok()
    };
    let with_another_nonce = log::node_document(
        "local",
        &local_document(&binding, &fixed("attestation nonce"), TIME_MS),
        &node.node(),
        RELEASE,
    );
    let with_another_release = log::node_document("local", &document, &node.node(), "v9.0.0");
    json!({
        "node_sign_pk": b64u(&node.sign_public()),
        "node": node.node(),
        "user_id": USER_ID,
        "key_id": key_id,
        "log_private": b64u(&account.log.to_bytes()),
        "log_pk": b64u(&account.log_pk()),
        "hpke_info_text": purpose::LOG_ENTRY_SEAL_V3,
        "signature_context_text": purpose::LOG_ENTRY_V3,
        "control_prefix": log::entry_prefix_v3(USER_ID, EntryKind::Control),
        "use_prefix": log::entry_prefix_v3(USER_ID, EntryKind::Use),
        "entries": entries,
        "control_listing": listing(EntryKind::Control),
        "use_listing": listing(EntryKind::Use),
        "verifies": verifies,
        "rejected": rejected,
        "not_keys": not_keys,
        "a_key_of_not_keys_parses": a_key_parses,
        "node_document": {
            "key": log::node_document_key(&node.node()),
            "bucket": store.shard_of(keys::shard_hash(&node.node())).expect("a bucket"),
            "nonce_prefix_text": purpose::NODE_DOCUMENT,
            "nonce": b64u(&nonce),
            "binding_text": text(&binding),
            "document_text": text(&document),
            "object_text": text(&object),
            "accepted": reads(&object, &node),
            "rejected": [
                {"name": "another_nonce", "node": node.node(),
                 "object_text": text(&with_another_nonce),
                 "accepted": reads(&with_another_nonce, &node)},
                {"name": "another_release", "node": node.node(),
                 "object_text": text(&with_another_release),
                 "accepted": reads(&with_another_release, &node)},
                {"name": "the_document_of_another_node", "node": other.node(),
                 "object_text": text(&object),
                 "accepted": reads(&object, &other)},
            ],
        },
    })
}

/// The vector `log_store`: the buckets of format 3 of five log stores (protocol.md 7.6), and the
/// bucket of four owners in each of them.
fn log_store() -> Value {
    let node = node_keys();
    let owners = [
        USER_ID.to_string(),
        "00000000-0000-4000-8000-000000000007".to_string(),
        "사용자 1".to_string(),
        node.node(),
    ];
    let stores: Vec<Value> = [
        "character-credential-log-prod-1",
        "character-credential-log-dev-1",
        "character-credential-log-alpha-1",
        "character-credential-log-local-1",
        "character-credential-log-yolo-3",
    ]
    .iter()
    .map(|bucket| {
        let store = LogStoreId::parse(bucket, "us-west-2").expect("a log store name");
        let shards = store.shards();
        let placed: Vec<Value> = owners
            .iter()
            .map(|owner| {
                let hash = keys::shard_hash(owner);
                json!({
                    "owner": owner,
                    "hash": hash,
                    "index": hash % shards,
                    "bucket": store.shard_of(hash).expect("a bucket"),
                })
            })
            .collect();
        json!({
            "bucket": bucket,
            "region": store.region(),
            "host": store.regional_host(),
            "shards": shards,
            "first_bucket": store.shard_bucket(0).expect("a bucket"),
            "last_bucket": store.shard_bucket(shards - 1).expect("a bucket"),
            "owners": placed,
        })
    })
    .collect();
    let longest = LogStoreId::parse(&"b".repeat(keys::LOG_STORE_NAME_CHARS), "us-west-2")
        .expect("a log store name");
    let too_long = LogStoreId::parse(&"b".repeat(keys::LOG_STORE_NAME_CHARS + 1), "us-west-2")
        .expect("a log store name");
    json!({
        "stores": stores,
        "longest_name": {
            "bucket": longest.bucket(),
            "first_bucket": longest.shard_bucket(0),
        },
        "name_without_buckets": {
            "bucket": too_long.bucket(),
            "first_bucket": too_long.shard_bucket(0),
        },
    })
}

/// The vector `log_v1`: a chain of format 1 (protocol.md 7.1, "Format 1") as the releases
/// before v2.0.0 wrote it.
fn log_chain_v1() -> Value {
    let node = node_keys();
    let account = account_keys();
    let key_id = account.key_id();
    let record_id = b64u(&fixed_prefix::<16>("record id"));
    let events = [
        json!({
            "t": "grant_accepted",
            "not_after_ms": TIME_MS + 2_592_000_000,
            "custody": Custody::Enclave.as_str(),
        }),
        json!({
            "t": "provider_request",
            "record_id": record_id,
            "provider": "google_workspace",
            "method": "GET",
            "host": "gmail.googleapis.com",
            "path": "/gmail/v1/users/me/messages",
            "query": "maxResults=10",
            "body_bytes": 0,
            "body_sha256": "",
            "context": "cli:gog",
            "window_s": 300,
        }),
        json!({
            "t": "secret_released",
            "record_id": record_id,
            "kind": "vault_card",
            "field": "card_number",
            "origin": "https://shop.example",
            "context": "browser:fill",
        }),
    ];
    let mut head = Head::EMPTY;
    let mut entries = Vec::new();
    let mut signed_entries = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let seed = fixed(&format!("log entry {} hpke seed", index + 1));
        let time_ms = TIME_MS + 1_000 * (index as u64 + 1);
        let (entry, next) = log::append(
            &node,
            &head,
            USER_ID,
            &key_id,
            &account.log_pk(),
            time_ms,
            event,
            &Secret::new(seed),
        );
        let body = b64u_decode(&entry.body).expect("entry body");
        entries.push(json!({
            "seq": next.seq,
            "hpke_seed": b64u(&seed),
            "time_ms": time_ms,
            "event_text": text(&to_json(event)),
            "entry": signed_value(&entry),
            "body_text": text(&body),
            "entry_hash": b64u(&next.hash),
        }));
        signed_entries.push(entry);
        head = next;
    }
    let nonce = b64u(&fixed_prefix::<16>("chain head nonce"));
    let signed_head = log::signed_head(&node, USER_ID, &head, &nonce, TIME_MS + 4_000, false);
    let final_head = log::signed_head(&node, USER_ID, &head, "", TIME_MS + 5_000, true);
    let verifies = |list: &[Signed]| {
        app::verify_chain(
            &node.sign_public(),
            USER_ID,
            &Head::EMPTY,
            list,
            &signed_head,
            Some(&nonce),
        )
        .is_ok()
    };
    let without_middle = [signed_entries[0].clone(), signed_entries[2].clone()];
    json!({
        "node_sign_pk": b64u(&node.sign_public()),
        "node": node.node(),
        "user_id": USER_ID,
        "key_id": key_id,
        "log_private": b64u(&account.log.to_bytes()),
        "log_pk": b64u(&account.log_pk()),
        "hpke_info_text": purpose::LOG_ENTRY_SEAL,
        "checkpoint": {"seq": 0, "hash": b64u(&Head::EMPTY.hash)},
        "entries": entries,
        "head_nonce": nonce,
        "head": signed_value(&signed_head),
        "head_text": text(&b64u_decode(&signed_head.body).expect("head body")),
        "final_head": signed_value(&final_head),
        "chain_valid": verifies(&signed_entries),
        "missing_middle": {
            "entries": [signed_value(&without_middle[0]), signed_value(&without_middle[1])],
            "chain_valid": verifies(&without_middle),
        },
    })
}

fn local_document(binding: &[u8], nonce: &[u8], time_ms: u64) -> Vec<u8> {
    to_json(&json!({
        "v": 1,
        "platform": "local",
        "binding": b64u(binding),
        "nonce": b64u(nonce),
        "time_ms": time_ms,
    }))
}

fn attestation() -> Value {
    let node = node_keys();
    let other = NodeKeys::from_random(
        &fixed("another node sign seed"),
        &fixed("another node seal private"),
    );
    let binding = keys::binding(&node, RELEASE, None);
    let nonce = fixed("attestation nonce");
    let another_nonce = fixed("another attestation nonce");
    let challenge = fixed_prefix::<16>("challenge");
    let another_challenge = fixed_prefix::<16>("another challenge");
    let response = |document: &[u8], statement: Option<&Signed>| {
        let mut response = json!({
            "v": 1,
            "platform": "local",
            "document": b64u(document),
            "node": node.node(),
            "challenge": b64u(&challenge),
            "release": RELEASE,
        });
        if let Some(statement) = statement {
            response["challenge_statement"] = signed_value(statement);
        }
        response
    };
    let document = local_document(&binding, &nonce, TIME_MS);
    let statement = statement::challenge(&node, &nonce, &challenge, TIME_MS);
    let other_binding = to_json(&json!({
        "v": 2,
        "sign": b64u(&node.sign_public()),
        "seal": b64u(&node.seal_public()),
        "release": RELEASE,
    }));
    let other_version = local_document(&other_binding, &nonce, TIME_MS);
    // The statements a relay could offer in place of the one this request is owed.
    let of_another_request = statement::challenge(&node, &another_nonce, &challenge, TIME_MS);
    let of_another_challenge = statement::challenge(&node, &nonce, &another_challenge, TIME_MS);
    let of_another_node = statement::challenge(&other, &nonce, &challenge, TIME_MS);
    json!({
        "local": {
            "nonce": b64u(&nonce),
            "response": response(&document, Some(&statement)),
            "document_text": text(&document),
            "binding_text": text(&binding),
            "binding": b64u(&binding),
            "sign_pk": b64u(&node.sign_public()),
            "seal_pk": b64u(&node.seal_public()),
            "release": RELEASE,
            "challenge_statement_text": text(&b64u_decode(&statement.body).expect("body")),
            "accepted": true,
            "rejected": [
                {
                    "name": "another_nonce",
                    "nonce": b64u(&another_nonce),
                    "response": response(&document, Some(&statement)),
                },
                {
                    "name": "binding_version_2",
                    "nonce": b64u(&nonce),
                    "response": response(&other_version, Some(&statement)),
                },
                {
                    "name": "challenge_statement_missing",
                    "nonce": b64u(&nonce),
                    "response": response(&document, None),
                },
                {
                    "name": "challenge_statement_of_another_request",
                    "nonce": b64u(&nonce),
                    "response": response(&document, Some(&of_another_request)),
                },
                {
                    "name": "challenge_statement_of_another_challenge",
                    "nonce": b64u(&nonce),
                    "response": response(&document, Some(&of_another_challenge)),
                },
                {
                    "name": "challenge_statement_of_another_node",
                    "nonce": b64u(&nonce),
                    "response": response(&document, Some(&of_another_node)),
                },
            ],
        },
        "nitro": {
            "included": false,
            "note": concat!(
                "A real Nitro attestation document is not part of this file yet. It is added, ",
                "with its nonce and the AWS Nitro Enclaves Root-G1 certificate, from the first ",
                "enclave booted from a release image. Its expected binding: user_data is the ",
                "binding bytes, nonce is the 32 request bytes, public_key is absent."
            ),
        },
    })
}

/// One transfer vector. `result` is what the receiving node finds when it opens the envelope
/// with the giving node's signing key from the attestation: `ok` or the failure code of
/// protocol.md 10.1. When the envelope names this receiver and that giver, `opens` tells
/// whether the HPKE open succeeds. When it opens, `signature_valid` is the outcome of
/// verifying `sig` over `payload` with the giving node's signing key.
fn transfer_case(
    giving: &NodeKeys,
    receiving: &NodeKeys,
    name: &str,
    envelope: &TransferEnvelope,
) -> Value {
    let mut case = Map::new();
    case.insert("name".to_string(), json!(name));
    case.insert(
        "envelope".to_string(),
        serde_json::to_value(envelope).expect("envelope"),
    );
    case.insert(
        "result".to_string(),
        json!(
            match envelope::open_transfer(receiving, &giving.sign_public(), envelope) {
                Ok(_) => "ok",
                Err(error) => error.code(),
            }
        ),
    );
    if envelope.v != 1 || envelope.to != receiving.node() || envelope.from != giving.node() {
        return Value::Object(case);
    }
    let opened = b64u_decode(&envelope.enc)
        .and_then(|enc| Ok((enc, b64u_decode(&envelope.ct)?)))
        .and_then(|(enc, ct)| {
            envelope::hpke_open(
                &StaticSecret::from(fixed("receiving node seal private")),
                &enc,
                purpose::PEER_SEAL.as_bytes(),
                &envelope::transfer_aad(&envelope.from, &envelope.to),
                &ct,
            )
        });
    case.insert("opens".to_string(), json!(opened.is_ok()));
    let Ok(signed) = opened else {
        return Value::Object(case);
    };
    let outer: Value = serde_json::from_slice(&signed).expect("vector transfers are JSON");
    let payload = b64u_decode(outer["payload"].as_str().expect("payload")).expect("payload");
    let signature = b64u_decode(outer["sig"].as_str().expect("sig")).expect("sig");
    case.insert("signed_text".to_string(), json!(text(&signed)));
    case.insert("signed".to_string(), json!(b64u(&signed)));
    case.insert("payload_text".to_string(), json!(text(&payload)));
    case.insert("payload".to_string(), json!(b64u(&payload)));
    case.insert("sig".to_string(), json!(b64u(&signature)));
    case.insert(
        "signature_valid".to_string(),
        json!(verify_detached(&giving.sign_public(), purpose::PEER, &payload, &signature).is_ok()),
    );
    Value::Object(case)
}

fn transfer() -> Value {
    let giving = node_keys();
    let receiving = NodeKeys::from_random(
        &fixed("receiving node sign seed"),
        &fixed("receiving node seal private"),
    );
    let other = NodeKeys::from_random(
        &fixed("another node sign seed"),
        &fixed("another node seal private"),
    );
    let first = account_keys();
    let second = app::derive_account_keys(&fixed("another master key"));
    let not_after_ms = TIME_MS + 30 * 24 * 60 * 60 * 1000;
    let grants = [
        TransferGrant {
            user_id: USER_ID.to_string(),
            sign_pk: first.sign_pk(),
            log_pk: first.log_pk(),
            custody: Custody::Enclave,
            user_key: Secret::new(*first.user_key),
            not_after_ms,
        },
        TransferGrant {
            user_id: "user-9c1e".to_string(),
            sign_pk: second.sign_pk(),
            log_pk: second.log_pk(),
            custody: Custody::Enclave,
            user_key: Secret::new(*second.user_key),
            not_after_ms: not_after_ms - 86_400_000,
        },
    ];
    let hpke_seed = fixed("transfer hpke seed");
    let envelope = envelope::seal_transfer(
        &giving,
        &receiving.sign_public(),
        &receiving.seal_public(),
        TIME_MS,
        &grants,
        &Secret::new(hpke_seed),
    )
    .expect("the receiving node can be sealed to");
    let good = transfer_case(&giving, &receiving, "transfer", &envelope);

    let mut tampered = envelope.clone();
    let mut ct = b64u_decode(&tampered.ct).expect("ct");
    ct[0] ^= 0x01;
    tampered.ct = b64u(&ct);

    // The same payload signed by a node that is not the giving node, sealed as the giving
    // node would seal it.
    let payload = envelope::transfer_payload(&giving.node(), &receiving.node(), TIME_MS, &grants);
    let forged_signed = envelope::sign_transfer(
        &SigningKey::from_bytes(&fixed("another node sign seed")),
        payload.expose_secret(),
    );
    let (enc, ct) = envelope::hpke_seal(
        &receiving.seal_public(),
        purpose::PEER_SEAL.as_bytes(),
        &envelope::transfer_aad(&giving.node(), &receiving.node()),
        &forged_signed,
        &fixed("forged transfer hpke seed"),
    )
    .expect("the receiving node can be sealed to");
    let forged = TransferEnvelope {
        v: 1,
        from: giving.node(),
        to: receiving.node(),
        enc: b64u(&enc),
        ct: b64u(&ct),
    };

    let for_another_node = envelope::seal_transfer(
        &giving,
        &other.sign_public(),
        &other.seal_public(),
        TIME_MS,
        &grants,
        &Secret::new(fixed("another transfer hpke seed")),
    )
    .expect("the other node can be sealed to");

    json!({
        "from_sign_seed": b64u(&fixed("node sign seed")),
        "from_sign_pk": b64u(&giving.sign_public()),
        "from": giving.node(),
        "to_sign_seed": b64u(&fixed("receiving node sign seed")),
        "to_sign_pk": b64u(&receiving.sign_public()),
        "to_seal_private": b64u(&fixed("receiving node seal private")),
        "to_seal_pk": b64u(&receiving.seal_public()),
        "to": receiving.node(),
        "hpke_info_text": purpose::PEER_SEAL,
        "hpke_aad_text": text(&envelope::transfer_aad(&giving.node(), &receiving.node())),
        "signature_context_text": purpose::PEER,
        "hpke_seed": b64u(&hpke_seed),
        "time_ms": TIME_MS,
        "payload_text": good["payload_text"],
        "signed": good["signed"],
        "envelope": good["envelope"],
        "grants": grants
            .iter()
            .map(|grant| json!({
                "user_id": grant.user_id,
                "sign_pk": b64u(&grant.sign_pk),
                "log_pk": b64u(&grant.log_pk),
                "custody": grant.custody.as_str(),
                "user_key": b64u(grant.user_key.expose_secret()),
                "not_after_ms": grant.not_after_ms,
            }))
            .collect::<Vec<Value>>(),
        "cases": [
            good,
            transfer_case(&giving, &receiving, "tampered_ciphertext", &tampered),
            transfer_case(&giving, &receiving, "signed_by_another_node", &forged),
            transfer_case(&giving, &receiving, "envelope_for_another_node", &for_another_node),
        ],
    })
}

fn totp_vectors() -> Value {
    let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let cases: Vec<Value> = [59_000u64, 1_111_111_109_000, 1_234_567_890_000, TIME_MS]
        .into_iter()
        .map(|time_ms| {
            json!({
                "seed_base32": seed,
                "time_ms": time_ms,
                "code": totp::totp(seed, time_ms).expect("seed"),
            })
        })
        .collect();
    Value::Array(cases)
}

/// The form of the plaintext of a record of kind `vault_secret` (protocol.md section 6): a
/// record a device made, and strings and reaches with the verdict of the form rules on each.
/// The verdicts are written here by hand, and the generator stops when the library gives
/// another one. The one list that is not written by hand is `reserved_headers`: the header
/// names no slot names, from the two lists of the library, each with the verdict that the slot
/// of that header is no slot.
fn vault_secret_forms() -> Value {
    let keys = account_keys();
    let id: [u8; 16] = fixed_prefix("vault secret record id");
    let nonce: [u8; 12] = fixed_prefix("vault secret record nonce");
    let plaintext = concat!(
        r#"{"value":"sk-example-0123456789abcdef","name":"OPENAI_API_KEY","#,
        r#""sites":["api.openai.com"],"slots":["header:authorization"],"source":"device"}"#
    )
    .as_bytes();
    let key_id = keys.key_id();
    let kind = Kind::VaultSecret.as_str();
    let record = seal_record(
        &keys.user_key,
        &id,
        &nonce,
        USER_ID,
        &key_id,
        Custody::Enclave,
        kind,
        "vault",
        plaintext,
    );

    let verdicts = |cases: &[(&str, bool)], rule: &dyn Fn(&str) -> bool| -> Vec<Value> {
        let verdict = |(text, valid): &(&str, bool)| {
            assert_eq!(rule(text), *valid, "the verdict on {text:?}");
            json!({"text": text, "valid": valid})
        };
        cases.iter().map(verdict).collect()
    };
    let name_of_64 = format!("A{}", "9".repeat(63));
    let name_of_65 = format!("A{}", "9".repeat(64));
    let names = verdicts(
        &[
            ("A", true),
            ("OPENAI_API_KEY", true),
            ("K2_", true),
            (&name_of_64, true),
            ("", false),
            ("a", false),
            ("openai_api_key", false),
            ("Openai", false),
            ("1KEY", false),
            ("_KEY", false),
            ("API-KEY", false),
            ("API KEY", false),
            ("ÅPI", false),
            (&name_of_65, false),
        ],
        &vault_secret::is_name,
    );
    let label_of_63 = format!("{}.example", "a".repeat(63));
    let label_of_64 = format!("{}.example", "a".repeat(64));
    let host_of_253 = [63, 63, 63, 61].map(|length| "h".repeat(length)).join(".");
    let host_of_254 = [63, 63, 63, 62].map(|length| "h".repeat(length)).join(".");
    let hosts = verdicts(
        &[
            ("api.openai.com", true),
            ("a.b", true),
            ("xn--9n2bp8q.example", true),
            ("my-shop.co.kr", true),
            ("1.example", true),
            ("3com.example", true),
            ("a-b.example", true),
            ("a--b.example", true),
            (&label_of_63, true),
            (&host_of_253, true),
            ("", false),
            ("localhost", false),
            ("Shop.example", false),
            ("shop.example.", false),
            (".shop.example", false),
            ("shop..example", false),
            ("shop_1.example", false),
            ("shop.example:443", false),
            ("shop.example/login", false),
            ("https://shop.example", false),
            ("*.example", false),
            ("상점.example", false),
            ("10.0.0.1", false),
            ("example.0x1f", false),
            ("shop.1example", false),
            // No label begins or ends with `-`.
            ("-a.example", false),
            ("a-.example", false),
            ("-a-.example", false),
            ("shop.-example", false),
            ("shop.example-", false),
            (&label_of_64, false),
            (&host_of_254, false),
        ],
        &is_site_host,
    );
    let header_of_64 = format!("header:{}", "n".repeat(64));
    let header_of_65 = format!("header:{}", "n".repeat(65));
    let query_of_64 = format!("query:{}", "q".repeat(64));
    let query_of_65 = format!("query:{}", "q".repeat(65));
    let form_of_64 = format!("form:{}", "f".repeat(64));
    let form_of_65 = format!("form:{}", "f".repeat(65));
    let json_of_63 = format!("json:{}", "가".repeat(21));
    let json_of_64 = format!("json:{}a", "가".repeat(21));
    let json_of_65 = format!("json:{}ab", "가".repeat(21));
    let json_of_66 = format!("json:{}", "가".repeat(22));
    let slots = verdicts(
        &[
            ("field", true),
            ("path", true),
            // The two halves of the credentials of HTTP Basic in the `Authorization` header:
            // one slot each.
            ("basic:user", true),
            ("basic:password", true),
            ("header:authorization", true),
            ("header:x-api-key", true),
            ("query:key", true),
            ("form:client_secret", true),
            ("json:apiKey", true),
            // The name of a JSON slot is object keys joined by `.`.
            ("json:auth.token", true),
            ("json:a.b.c", true),
            // A header no node of the forward role drops or refuses.
            ("header:cookie", true),
            ("header:content-type", true),
            ("header:x-forwarded-for", true),
            // The name of a query or form slot: the characters a query writes without an
            // escape.
            ("query:serviceKey", true),
            ("query:a-b.c_d~e", true),
            ("form:API_KEY", true),
            ("form:0", true),
            (&header_of_64, true),
            (&query_of_64, true),
            (&form_of_64, true),
            // The name of a JSON slot: a colon, a character outside ASCII, and characters that
            // are neither control characters nor white space (U+200B, U+FEFF). Its length is
            // counted in bytes.
            ("json:a:b", true),
            ("json:비밀번호", true),
            (&json_of_63, true),
            (&json_of_64, true),
            ("json:a\u{200b}b", true),
            ("json:a\u{feff}b", true),
            ("", false),
            ("Field", false),
            ("field:", false),
            ("field:name", false),
            ("path:/v1", false),
            // A slot of HTTP Basic names its half with one of two words.
            ("basic", false),
            ("Basic", false),
            ("basic:", false),
            ("basic:User", false),
            ("basic:user-id", false),
            ("basic:username", false),
            ("basic:pass", false),
            ("basic:user:password", false),
            ("Basic:password", false),
            ("header", false),
            ("header:", false),
            ("header:Authorization", false),
            ("header:x_api_key", false),
            // A header a node of the forward role drops, and one it refuses (the whole list is
            // `reserved_headers`).
            ("header:host", false),
            ("header:content-length", false),
            ("header:x-http-method-override", false),
            ("header:x-forwarded-host", false),
            // No key of the name of a JSON slot is empty.
            ("json:a..b", false),
            ("json:.a", false),
            ("json:a.", false),
            ("json:.", false),
            ("query:", false),
            ("query:a b", false),
            ("form:a\tb", false),
            // A character a query or a form body writes with an escape, or that parts a name
            // from its value or one pair from the next.
            ("query:a:b", false),
            ("query:a%20b", false),
            ("query:a+b", false),
            ("query:a&b", false),
            ("query:a=b", false),
            ("query:a[0]", false),
            ("query:키", false),
            ("query:a\u{200b}b", false),
            ("form:비밀번호", false),
            ("form:a:b", false),
            ("form:a%3Db", false),
            ("form:a/b", false),
            ("json:a\u{1f}b", false),
            ("json:a\u{7f}", false),
            ("json:a\u{85}", false),
            ("json:a\u{9f}b", false),
            ("json:a\u{a0}b", false),
            ("json:a\u{1680}b", false),
            ("json:a\u{2000}b", false),
            ("json:a\u{200a}b", false),
            ("json:a\u{2028}b", false),
            ("json:a\u{2029}b", false),
            ("json:a\u{202f}b", false),
            ("json:a\u{205f}b", false),
            ("json:a\u{3000}b", false),
            ("cookie:session", false),
            ("body", false),
            (&header_of_65, false),
            (&query_of_65, false),
            (&form_of_65, false),
            (&json_of_65, false),
            (&json_of_66, false),
        ],
        &|text| Slot::parse(text).is_some(),
    );
    let nine_hosts: Vec<String> = (0..9).map(|index| format!("h{index}.example")).collect();
    let reaches: Vec<Value> = [
        (
            json!(["api.openai.com"]),
            json!(["header:authorization"]),
            true,
        ),
        (
            json!(["shop.example", "pay.example"]),
            json!(["field"]),
            true,
        ),
        // A reach names at least one slot.
        (json!(["shop.example"]), json!([]), false),
        // The slots of a record are the slot `field` alone, or slots of a request: a value
        // that is typed into a page is in the hands of whoever fills the page, and a value
        // that goes into requests leaves a node in no other way.
        (
            json!(["shop.example"]),
            json!(["field", "path", "query:key", "json:key"]),
            false,
        ),
        (json!(["shop.example"]), json!(["field", "path"]), false),
        (
            json!(["shop.example"]),
            json!(["path", "query:key", "json:key", "form:key"]),
            true,
        ),
        (
            json!(["shop.example"]),
            json!(["query:key", "query:token"]),
            true,
        ),
        // A list names a host once, and a slot once.
        (json!(["a.example", "a.example"]), json!(["field"]), false),
        (json!(["api.example.com"]), json!(["basic:password"]), true),
        (json!(["api.example.com"]), json!(["basic:user"]), true),
        // The two halves of the credentials of HTTP Basic are two slots, and a record may
        // list both.
        (
            json!(["api.example.com"]),
            json!(["basic:user", "basic:password"]),
            true,
        ),
        (
            json!(["api.example.com"]),
            json!(["basic:password", "header:authorization"]),
            true,
        ),
        (
            json!(["api.example.com"]),
            json!(["basic:password", "basic:password"]),
            false,
        ),
        (json!(["api.example.com"]), json!(["basic"]), false),
        (json!("any"), json!(["basic:password"]), false),
        (json!("any"), json!(["field"]), true),
        (json!([]), json!(["field"]), false),
        (json!(nine_hosts), json!(["field"]), false),
        (json!("all"), json!(["field"]), false),
        (json!(["Shop.example"]), json!(["field"]), false),
        (json!(["shop.example"]), json!(["field", "field"]), false),
        (
            json!(["shop.example"]),
            json!(["field", "path", "query:a", "form:a", "json:a"]),
            false,
        ),
        (json!(["shop.example"]), json!(["cookie:session"]), false),
        (json!(["shop.example"]), json!(["json:auth.token"]), true),
        (json!(["shop.example"]), json!(["json:auth..token"]), false),
        (json!(["shop.example"]), json!(["header:host"]), false),
        (
            json!(["shop.example"]),
            json!(["field", "header:x-forwarded-host"]),
            false,
        ),
        (json!(["shop-.example"]), json!(["field"]), false),
        (
            json!(["shop.example", "-pay.example"]),
            json!(["field"]),
            false,
        ),
        (json!(["shop.example"]), json!("field"), false),
        (json!("any"), json!([]), false),
        (json!("any"), json!(["header:authorization"]), false),
        (
            json!("any"),
            json!(["field", "header:authorization"]),
            false,
        ),
    ]
    .into_iter()
    .map(|(sites, slots, valid)| {
        let read = Reach::from_values(&sites, &slots).is_some();
        assert_eq!(read, valid, "the verdict on {sites} {slots}");
        json!({"sites": sites, "slots": slots, "valid": valid})
    })
    .collect();
    let reserved_headers: Vec<Value> = DROPPED_HEADERS
        .iter()
        .chain(&REFUSED_HEADERS)
        .map(|name| {
            let slot = format!("header:{name}");
            assert!(Slot::parse(&slot).is_none(), "the verdict on {slot}");
            json!({"text": slot, "valid": false})
        })
        .collect();

    json!({
        "id": b64u(&id),
        "nonce": b64u(&nonce),
        "kind": kind,
        "provider": "vault",
        "plaintext_text": text(plaintext),
        "plaintext": b64u(plaintext),
        "aad_text": text(&record_aad(
            &b64u(&id),
            USER_ID,
            &key_id,
            Custody::Enclave.as_str(),
            kind,
            "vault",
        )),
        "record_key": b64u(keys::record_key(&keys.user_key, &id).as_slice()),
        "record": record,
        "names": names,
        "hosts": hosts,
        "slots": slots,
        "reserved_headers": reserved_headers,
        "reaches": reaches,
    })
}

/// The credentials of HTTP Basic of a request whose slot is `basic:user` or `basic:password`
/// (protocol.md 10.5): values of an `Authorization` header, each with the slot of the half of
/// the credentials the placeholder stands for, or with none, and for a value that names a
/// half the header a node writes with the value in the place of the placeholder. A node
/// sends a request with such a header under the slot of that half, and under no other one.
/// The verdicts are written here by hand, and the generator stops when the library gives
/// another one.
fn basic_credentials() -> Value {
    const PLACEHOLDER: &str = "PLACEHOLDER_0123456789abcdef";
    const VALUE: &str = "example-value-0123456789";
    let text_of = |credentials: &[u8]| STANDARD.encode(credentials);
    let header = |credentials: &str| format!("Basic {}", text_of(credentials.as_bytes()));
    let of_user_id = format!("{PLACEHOLDER}:");
    let of_password = format!("user:{PLACEHOLDER}");
    // The credentials whose base64 text ends with one padding character and with two, and
    // credentials whose text holds `+` and `/`.
    let one_pad = text_of(of_user_id.as_bytes());
    let two_pads = text_of(format!("us:{PLACEHOLDER}").as_bytes());
    assert!(one_pad.ends_with('=') && !one_pad.ends_with("=="));
    assert!(two_pads.ends_with("=="));
    let signs = format!("???>>>:{PLACEHOLDER}");
    assert!(header(&signs).contains('+') && header(&signs).contains('/'));
    // The second character of a last group of one byte holds four bits that are zero: the
    // character behind it in the alphabet sets the lowest of them.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let at = two_pads.len() - 3;
    let index = alphabet
        .iter()
        .position(|byte| *byte == two_pads.as_bytes()[at])
        .expect("a character of the alphabet");
    let loose = format!("{}{}==", &two_pads[..at], char::from(alphabet[index + 1]));
    let latin = [b"caf\xe9:".as_slice(), PLACEHOLDER.as_bytes()].concat();

    let user_id = Some(BasicPart::UserId);
    let password = Some(BasicPart::Password);
    let cases: Vec<(&str, String, Option<BasicPart>)> = vec![
        (
            "the placeholder is the user-id, and the password is empty",
            header(&of_user_id),
            user_id,
        ),
        (
            "the placeholder is the user-id",
            header(&format!("{PLACEHOLDER}:password")),
            user_id,
        ),
        (
            "the placeholder is the user-id, and the password holds colons",
            header(&format!("{PLACEHOLDER}:a:b:")),
            user_id,
        ),
        (
            "the placeholder is the password",
            header(&of_password),
            password,
        ),
        (
            "the placeholder is the password, and the user-id is empty",
            header(&format!(":{PLACEHOLDER}")),
            password,
        ),
        (
            "the placeholder is the password, and the user-id holds characters outside ASCII",
            header(&format!("사용자:{PLACEHOLDER}")),
            password,
        ),
        ("the base64 text holds + and /", header(&signs), password),
        (
            "the base64 text ends with two padding characters",
            format!("Basic {two_pads}"),
            password,
        ),
        (
            "the credentials do not hold the placeholder",
            header("user:password"),
            None,
        ),
        (
            "the placeholder is a part of the user-id",
            header(&format!("x{PLACEHOLDER}:")),
            None,
        ),
        (
            "the placeholder is a part of the password",
            header(&format!("user:{PLACEHOLDER}x")),
            None,
        ),
        (
            "the placeholder is both halves",
            header(&format!("{PLACEHOLDER}:{PLACEHOLDER}")),
            None,
        ),
        (
            "the placeholder is the user-id and a part of the password",
            header(&format!("{PLACEHOLDER}:x{PLACEHOLDER}")),
            None,
        ),
        (
            "the placeholder stands behind a second colon",
            header(&format!("user:pass:{PLACEHOLDER}")),
            None,
        ),
        ("the credentials hold no colon", header(PLACEHOLDER), None),
        (
            "the credentials are not UTF-8",
            format!("Basic {}", text_of(&latin)),
            None,
        ),
        ("the scheme in lower case", format!("basic {one_pad}"), None),
        ("the scheme in upper case", format!("BASIC {one_pad}"), None),
        (
            "two spaces behind the scheme",
            format!("Basic  {one_pad}"),
            None,
        ),
        (
            "a space behind the base64 text",
            format!("Basic {one_pad} "),
            None,
        ),
        (
            "the base64 text without its padding",
            format!("Basic {}", one_pad.trim_end_matches('=')),
            None,
        ),
        (
            "base64url in the place of base64",
            format!("Basic {}", URL_SAFE.encode(signs.as_bytes())),
            None,
        ),
        (
            "a bit set behind the last byte of the base64 text",
            format!("Basic {loose}"),
            None,
        ),
        (
            "a text behind the credentials",
            format!("Basic {one_pad}, Bearer token"),
            None,
        ),
        ("another scheme", format!("Bearer {one_pad}"), None),
        ("no scheme", one_pad.clone(), None),
        (
            "the placeholder as it stands behind the scheme",
            format!("Basic {PLACEHOLDER}"),
            None,
        ),
    ];
    let value = Secret::new(VALUE.to_string());
    let cases: Vec<Value> = cases
        .into_iter()
        .map(|(name, authorization, part)| {
            let read = BasicCredentials::read(&authorization, PLACEHOLDER);
            assert_eq!(
                read.as_ref().map(BasicCredentials::part),
                part,
                "the verdict on {name}"
            );
            let mut case = Map::new();
            case.insert("name".into(), json!(name));
            case.insert("authorization_text".into(), json!(authorization));
            let slot = part.map(|part| Slot::Basic(part).to_string());
            if let Some(slot) = &slot {
                assert!(Slot::parse(slot).is_some(), "the slot of {name}");
            }
            case.insert("slot".into(), json!(slot));
            if let Some(credentials) = read {
                let written = credentials.written(&value);
                case.insert("written_text".into(), json!(written.expose_secret()));
            }
            Value::Object(case)
        })
        .collect();
    json!({
        "placeholder_text": PLACEHOLDER,
        "value_text": VALUE,
        "cases": cases,
    })
}

/// The value of the header of a request whose slot is `header:<name>` (protocol.md 10.5):
/// header values with a placeholder, each with the verdict on whether a node of the forward
/// role puts a value in the place of that placeholder. The verdicts are written here by
/// hand, and the generator stops when the library gives another one.
fn header_values() -> Value {
    const PLACEHOLDER: &str = "PLACEHOLDER_0123456789abcdef";
    let cases: Vec<(&str, &str, &str, bool)> = vec![
        (
            "the placeholder is the whole value",
            "X-Api-Key",
            "{}",
            true,
        ),
        (
            "the placeholder behind the scheme Bearer",
            "Authorization",
            "Bearer {}",
            true,
        ),
        (
            "the placeholder behind a scheme of the site",
            "authorization",
            "KakaoAK {}",
            true,
        ),
        (
            "the placeholder as a parameter of a scheme of the site",
            "Authorization",
            "Token token=\"{}\"",
            true,
        ),
        (
            "the placeholder as the value of a cookie",
            "Cookie",
            "theme=dark; session={}; lang=ko",
            true,
        ),
        (
            "the name of a refused scheme behind the placeholder",
            "Authorization",
            "Token token=\"{}\", name=\"basic\"",
            true,
        ),
        (
            "the name of a refused scheme in a header no server reads credentials from",
            "Cookie",
            "plan=basic; session={}",
            true,
        ),
        (
            "a refused scheme in a header no server reads credentials from",
            "X-Note",
            "Basic {}",
            true,
        ),
        (
            "a character outside ASCII in a header no server reads credentials from",
            "X-Note",
            "\u{d55c}: {}",
            true,
        ),
        ("no placeholder", "Authorization", "Bearer token", false),
        ("the placeholder twice", "Authorization", "{} {}", false),
        (
            "the placeholder behind a letter",
            "Authorization",
            "Bearer{}",
            false,
        ),
        (
            "the placeholder behind a tab",
            "Authorization",
            "Bearer\t{}",
            false,
        ),
        (
            "the placeholder behind the beginning of a percent escape",
            "X-Api-Key",
            "key=%4{}",
            false,
        ),
        (
            "the placeholder behind the beginning of a code unit escape",
            "X-Api-Key",
            "{\"key\":\"\\u004{}\"}",
            false,
        ),
        (
            "the placeholder behind the scheme Basic",
            "Authorization",
            "Basic {}",
            false,
        ),
        (
            "the scheme Basic in lower case",
            "authorization",
            "basic {}",
            false,
        ),
        (
            "the scheme Basic in upper case, and two spaces",
            "AUTHORIZATION",
            "BASIC  {}",
            false,
        ),
        (
            "a space in front of the scheme Basic",
            "Authorization",
            " Basic {}",
            false,
        ),
        (
            "the scheme Basic and = in front of the placeholder",
            "Authorization",
            "Basic={}",
            false,
        ),
        (
            "a base64 text between the scheme Basic and the placeholder",
            "Authorization",
            "Basic dXNlcjo= {}",
            false,
        ),
        (
            "the scheme Basic behind another scheme",
            "Authorization",
            "Bearer token, Basic {}",
            false,
        ),
        (
            "the name of the scheme Basic as a part of a word",
            "Authorization",
            "xBasic {}",
            false,
        ),
        (
            "the placeholder as the user name of the scheme Digest",
            "Authorization",
            "Digest username=\"{}\"",
            false,
        ),
        (
            "the placeholder behind the scheme Negotiate",
            "Authorization",
            "Negotiate {}",
            false,
        ),
        (
            "the placeholder behind the scheme NTLM",
            "Authorization",
            "NTLM {}",
            false,
        ),
        (
            "the scheme Basic in a header named after Authorization",
            "X-Authorization",
            "Basic {}",
            false,
        ),
        (
            "the scheme Basic in a header named after Authorization, written with _",
            "X_Forwarded_Authorization",
            "basic {}",
            false,
        ),
        (
            "a character outside ASCII in the place of a letter of the scheme Basic",
            "Authorization",
            "Ba\u{17f}ic {}",
            false,
        ),
        (
            "a character outside ASCII in front of a scheme",
            "Authorization",
            "\u{a0}Bearer {}",
            false,
        ),
    ];
    let cases: Vec<Value> = cases
        .into_iter()
        .map(|(name, header, value, valid)| {
            let value = value.replace("{}", PLACEHOLDER);
            assert_eq!(
                is_placed_in_header(header, &value, PLACEHOLDER),
                valid,
                "the verdict on {name}"
            );
            json!({"name": name, "header": header, "value_text": value, "valid": valid})
        })
        .collect();
    json!({
        "placeholder_text": PLACEHOLDER,
        "refused_schemes": REFUSED_SCHEMES,
        "cases": cases,
    })
}

/// A vault value that `release` hands out under the seal of a key its caller named
/// (protocol.md section 6): the key pair of the caller, the call, and the `sealed` object of
/// the response.
fn sealed_release() -> Value {
    let private = fixed("release receiver private key");
    let receiver = Receiver::from_random(&private);
    let seal_to = receiver.seal_to();
    let hpke_seed = fixed("release hpke seed");
    let record_id = b64u(&fixed_prefix::<16>("released record id"));
    let (field, origin) = ("value", "https://pay.shop.example");
    let value = "correct horse battery staple";
    let to = SealTo::parse(&seal_to).expect("the public key of a key pair is a key to seal to");
    let sealed = seal_released(
        &to,
        USER_ID,
        &record_id,
        field,
        origin,
        &Secret::new(value.to_string()),
        &Secret::new(hpke_seed),
    )
    .expect("a value seals to a key");
    let opened = receiver
        .open(USER_ID, &record_id, field, origin, &sealed)
        .expect("the receiver opens what was sealed to it");
    assert_eq!(opened.as_slice(), value.as_bytes());
    json!({
        "receiver_private": b64u(&private),
        "seal_to": seal_to,
        "hpke_seed": b64u(&hpke_seed),
        "user_id": USER_ID,
        "record_id": record_id,
        "field": field,
        "origin": origin,
        "info_text": purpose::RELEASE_SEAL,
        "aad_text": text(&released_aad(USER_ID, &record_id, field, origin)),
        "value_text": value,
        "sealed": sealed,
    })
}

/// The delegation subset (protocol.md 10.4): the nodes of an account in a pool, without
/// `groups` and with them, two pools that place an account in three groups, and `subset`
/// objects with the verdict of their form. The verdicts are written here by hand, and the
/// generator stops when the library gives another one.
fn subset_vectors() -> Value {
    let uuid = "00000000-0000-4000-8000-000000000007";
    let (a, b, c) = ("us-west-2a", "us-west-2b", "us-west-2c");
    let round: Vec<&str> = (0..15).map(|ordinal| [a, b, c][ordinal % 3]).collect();
    // The cases of one account whose groups have the same names are the pools of one fleet:
    // a pool of the delegation role (`copies` 2, `skip` 0) and a pool of the reserve role
    // (`copies` 1, `skip` 2).
    let cases: Vec<(&str, u32, Option<Vec<&str>>, u32)> = vec![
        ("user-1", 2, None, 0),
        (uuid, 2, None, 0),
        ("alice", 3, None, 0),
        ("bob", 1, None, 0),
        ("사용자 1", 2, None, 0),
        ("carol", 5, None, 0),
        ("alice", 3, None, 2),
        ("user-1", 2, Some(vec![a, b, c, a, b, c]), 0),
        ("user-1", 1, Some(vec![a, b, c]), 2),
        (uuid, 2, Some(round.clone()), 0),
        (uuid, 1, Some(vec![c, a, b]), 2),
        ("alice", 2, Some(vec![a, a, a, b, b, c, c]), 0),
        ("alice", 1, Some(vec![b, c, a, b]), 2),
        ("사용자 1", 3, Some(vec![c, c, b, b, a, a]), 0),
        (
            "bob",
            1,
            Some(vec!["zone_1.a", "Zone-2", "zone_1.a", "Zone-2"]),
            1,
        ),
        ("carol", 1, Some(vec!["a", "a"]), 0),
    ];
    let pods_of = |user_id: &str, groups: &Option<Vec<&str>>| -> u32 {
        match (groups, user_id) {
            (Some(groups), _) => u32::try_from(groups.len()).expect("a pool of some nodes"),
            (None, "user-1") => 3,
            (None, "alice") => 5,
            (None, "bob") => 4,
            (None, "사용자 1") => 6,
            (None, "carol") => 2,
            (None, _) => 12,
        }
    };
    let cases: Vec<Value> = cases
        .into_iter()
        .map(|(user_id, copies, groups, skip)| {
            let pods = pods_of(user_id, &groups);
            let placement = subset::Placement::new(pods, copies, groups.as_deref(), skip)
                .expect("the values of a case are a placement");
            let mut case = Map::new();
            case.insert("user_id".to_string(), json!(user_id));
            case.insert("pods".to_string(), json!(pods));
            case.insert("copies".to_string(), json!(copies));
            case.insert("skip".to_string(), json!(skip));
            match &groups {
                Some(groups) => {
                    let order = placement.group_order(user_id);
                    let ranked: Vec<Vec<u32>> = order
                        .iter()
                        .map(|group| placement.ranked(user_id, Some(group)))
                        .collect();
                    case.insert("groups".to_string(), json!(groups));
                    case.insert("group_order".to_string(), json!(order));
                    case.insert("group_ranked".to_string(), json!(ranked));
                }
                None => {
                    case.insert("ranked".to_string(), json!(placement.ranked(user_id, None)));
                }
            }
            let assigned = placement.assign(user_id);
            for pod in 0..pods {
                assert_eq!(placement.holds(user_id, pod), assigned.contains(&pod));
            }
            case.insert("assign".to_string(), json!(assigned));
            Value::Object(case)
        })
        .collect();

    // Two pools of one fleet whose nodes run in the same three groups: the two nodes of an
    // account in the pool of the delegation role and its node in the pool of the reserve
    // role lie in three different groups.
    let calls_groups = vec![a, b, c, b, a, c, a];
    let reserve_groups = vec![c, a, b, c];
    let calls = subset::Placement::new(7, 2, Some(&calls_groups), 0).expect("a placement");
    let reserve = subset::Placement::new(4, 1, Some(&reserve_groups), 2).expect("a placement");
    let accounts: Vec<Value> = ["user-1", uuid, "alice", "bob", "사용자 1", "carol"]
        .into_iter()
        .map(|user_id| {
            let (of_calls, of_reserve) = (calls.assign(user_id), reserve.assign(user_id));
            let group_of = |groups: &[&str], ordinal: &u32| -> String {
                let index = usize::try_from(*ordinal).expect("an ordinal");
                groups[index].to_string()
            };
            let mut groups: Vec<String> = of_calls
                .iter()
                .map(|ordinal| group_of(&calls_groups, ordinal))
                .collect();
            groups.extend(
                of_reserve
                    .iter()
                    .map(|ordinal| group_of(&reserve_groups, ordinal)),
            );
            assert_eq!(groups, calls.group_order(user_id), "{user_id}");
            assert_eq!(groups, reserve.group_order(user_id), "{user_id}");
            json!({"user_id": user_id, "calls": of_calls, "reserve": of_reserve, "groups": groups})
        })
        .collect();
    let pools = json!({
        "calls": {"pods": 7, "copies": 2, "skip": 0, "groups": calls_groups},
        "reserve": {"pods": 4, "copies": 1, "skip": 2, "groups": reserve_groups},
        "accounts": accounts,
    });

    let objects = [
        (json!({"pods": 3, "pod": 1, "copies": 2}), true),
        (json!({"pods": 1024, "pod": 1023, "copies": 1}), true),
        (json!({"pods": 2, "pod": 0, "copies": 5}), true),
        (
            json!({"pods": 3, "pod": 1, "copies": 2, "groups": null, "skip": null}),
            true,
        ),
        (json!({"pods": 3, "pod": 1, "copies": 2, "skip": 2}), true),
        (
            json!({"pods": 3, "pod": 1, "copies": 2, "other": "not read"}),
            true,
        ),
        (
            json!({"pods": 3, "pod": 0, "copies": 2, "groups": [a, b, c]}),
            true,
        ),
        (
            json!({"pods": 3, "pod": 0, "copies": 3, "groups": [a, b, c], "skip": 0}),
            true,
        ),
        (
            json!({"pods": 3, "pod": 2, "copies": 1, "groups": [a, b, c], "skip": 2}),
            true,
        ),
        (
            json!({"pods": 4, "pod": 3, "copies": 1, "groups": [a, a, b, b], "skip": 1}),
            true,
        ),
        (
            json!({"pods": 2, "pod": 0, "copies": 1, "groups": ["Zone_1.a-b", "z".repeat(63)]}),
            true,
        ),
        (json!({"pods": 0, "pod": 0, "copies": 1}), false),
        (json!({"pods": 1025, "pod": 0, "copies": 1}), false),
        (json!({"pods": 3, "pod": 3, "copies": 1}), false),
        (json!({"pods": 3, "pod": 0, "copies": 0}), false),
        (json!({"pods": 3, "pod": 0}), false),
        (json!({"pods": "3", "pod": 0, "copies": 1}), false),
        (json!({"pods": 3.5, "pod": 0, "copies": 1}), false),
        (json!({"pods": -3, "pod": 0, "copies": 1}), false),
        (json!({"pods": 3, "pod": 0, "copies": 4294967296u64}), false),
        (json!([3, 0, 1]), false),
        (
            json!({"pods": 3, "pod": 0, "copies": 1, "skip": "2"}),
            false,
        ),
        (json!({"pods": 3, "pod": 0, "copies": 1, "skip": -1}), false),
        (
            json!({"pods": 3, "pod": 0, "copies": 1, "skip": 4294967296u64}),
            false,
        ),
        (
            json!({"pods": 3, "pod": 0, "copies": 1, "groups": [a, b]}),
            false,
        ),
        (
            json!({"pods": 3, "pod": 0, "copies": 1, "groups": [a, b, c, a]}),
            false,
        ),
        (
            json!({"pods": 3, "pod": 0, "copies": 1, "groups": [0, 1, 2]}),
            false,
        ),
        (
            json!({"pods": 3, "pod": 0, "copies": 1, "groups": [a, null, c]}),
            false,
        ),
        (
            json!({"pods": 3, "pod": 0, "copies": 1, "groups": "abc"}),
            false,
        ),
        (
            json!({"pods": 2, "pod": 0, "copies": 1, "groups": ["", b]}),
            false,
        ),
        (
            json!({"pods": 2, "pod": 0, "copies": 1, "groups": ["us west", b]}),
            false,
        ),
        (
            json!({"pods": 2, "pod": 0, "copies": 1, "groups": ["a\nzone\nb", b]}),
            false,
        ),
        (
            json!({"pods": 2, "pod": 0, "copies": 1, "groups": ["영역", b]}),
            false,
        ),
        (
            json!({"pods": 2, "pod": 0, "copies": 1, "groups": ["z".repeat(64), b]}),
            false,
        ),
        (
            json!({"pods": 3, "pod": 0, "copies": 4, "groups": [a, b, c]}),
            false,
        ),
        (
            json!({"pods": 3, "pod": 0, "copies": 2, "groups": [a, b, c], "skip": 2}),
            false,
        ),
        (
            json!({"pods": 3, "pod": 0, "copies": 1, "groups": [a, b, c], "skip": 3}),
            false,
        ),
        (
            json!({"pods": 3, "pod": 0, "copies": 2, "groups": [a, a, a]}),
            false,
        ),
    ];
    let objects: Vec<Value> = objects
        .into_iter()
        .map(|(object, valid)| {
            assert_eq!(
                subset::Subset::from_value(&object).is_some(),
                valid,
                "{object}"
            );
            json!({"subset": object, "valid": valid})
        })
        .collect();
    json!({"cases": cases, "pools": pools, "objects": objects, "spans": span_vectors()})
}

/// The spans of the delegation subset (protocol.md 10.4): the span number of an account,
/// `subset` objects with a `span` and whether they hold an account, a fleet of three pools
/// whose spans divide the numbers, and `span` values with the verdict of their form. The
/// verdicts are written here by hand, and the generator stops when the library gives another
/// one.
fn span_vectors() -> Value {
    let uuid = "00000000-0000-4000-8000-000000000007";
    let users = ["user-1", uuid, "alice", "bob", "사용자 1", "carol"];
    let numbers: Vec<Value> = users
        .into_iter()
        .map(|user_id| json!({"user_id": user_id, "number": subset::span_number(user_id)}))
        .collect();

    // `contains`: whether the node of `pod` holds the account under the object. The first
    // six pairs are one pool with the lower half and with the upper half of the numbers.
    let lower = json!([0, 2147483647]);
    let upper = json!([2147483648u32, 4294967295u32]);
    let pool = |pod: u32, span: Value| json!({"pods": 3, "pod": pod, "copies": 2, "span": span});
    let grouped = |span: Value| {
        json!({
            "pods": 6, "pod": 2, "copies": 2, "skip": 0, "span": span,
            "groups": ["us-west-2a", "us-west-2b", "us-west-2c", "us-west-2a", "us-west-2b", "us-west-2c"],
        })
    };
    let contains = [
        // The assignment of `user-1` among three nodes is {0, 1}, and its number lies in
        // the upper half.
        (pool(1, upper.clone()), "user-1", true),
        (pool(1, lower.clone()), "user-1", false),
        (pool(2, upper.clone()), "user-1", false),
        // The number of `bob` lies in the lower half, and its assignment is {1, 0}.
        (pool(0, lower.clone()), "bob", true),
        (pool(0, upper.clone()), "bob", false),
        (pool(2, lower.clone()), "bob", false),
        // Both ends belong to a span.
        (
            pool(1, json!([2518581323u32, 2518581323u32])),
            "user-1",
            true,
        ),
        (
            pool(1, json!([2518581324u32, 4294967295u32])),
            "user-1",
            false,
        ),
        (pool(1, json!([0, 2518581322u32])), "user-1", false),
        (pool(1, json!([0, 4294967295u32])), "user-1", true),
        // A pool with groups: the assignment of `user-1` there is the ordinals 2 and 0.
        (grouped(upper.clone()), "user-1", true),
        (grouped(lower.clone()), "user-1", false),
        // An object without the key, and one whose value is null, hold every account of the
        // assignment.
        (json!({"pods": 3, "pod": 1, "copies": 2}), "user-1", true),
        (
            json!({"pods": 3, "pod": 1, "copies": 2, "span": null}),
            "user-1",
            true,
        ),
    ];
    let contains: Vec<Value> = contains
        .into_iter()
        .map(|(object, user_id, held)| {
            let read = subset::Subset::from_value(&object).expect("a subset object");
            assert_eq!(read.contains(user_id), held, "{object} {user_id}");
            json!({"subset": object, "user_id": user_id, "contains": held})
        })
        .collect();

    // A fleet of three pools whose spans divide the numbers: every account is an account of
    // exactly one of them.
    let spans = [
        ("first", json!([0, 1431655764])),
        ("second", json!([1431655765, 2863311529u32])),
        ("third", json!([2863311530u32, 4294967295u32])),
    ];
    let pool_of: Vec<Value> = users
        .into_iter()
        .map(|user_id| {
            let holding: Vec<&str> = spans
                .iter()
                .filter(|(_, span)| {
                    let ends = span.as_array().expect("a span of two numbers");
                    let end = |index: usize| {
                        u32::try_from(ends[index].as_u64().expect("a number")).expect("a number")
                    };
                    subset::Span::new(end(0), end(1))
                        .expect("a span")
                        .holds(user_id)
                })
                .map(|(name, _)| *name)
                .collect();
            assert_eq!(holding.len(), 1, "{user_id}");
            json!({"user_id": user_id, "pool": holding[0]})
        })
        .collect();
    let fleet: Map<String, Value> = spans
        .iter()
        .map(|(name, span)| ((*name).to_string(), span.clone()))
        .collect();

    let objects = [
        (json!([0, 0]), true),
        (json!([0, 4294967295u32]), true),
        (json!([4294967295u32, 4294967295u32]), true),
        (json!([1431655765, 2863311529u32]), true),
        (json!(null), true),
        (json!([]), false),
        (json!([0]), false),
        (json!([0, 1, 2]), false),
        (json!([6, 5]), false),
        (json!([0, 4294967296u64]), false),
        (json!([-1, 5]), false),
        (json!([0.5, 5]), false),
        (json!(["0", "5"]), false),
        (json!([null, 5]), false),
        (json!({"first": 0, "last": 5}), false),
        (json!("0-5"), false),
        (json!(5), false),
    ];
    let objects: Vec<Value> = objects
        .into_iter()
        .map(|(span, valid)| {
            let object = json!({"pods": 3, "pod": 1, "copies": 2, "span": span});
            assert_eq!(
                subset::Subset::from_value(&object).is_some(),
                valid,
                "{object}"
            );
            json!({"subset": object, "valid": valid})
        })
        .collect();
    json!({
        "numbers": numbers,
        "contains": contains,
        "fleet": {"pools": fleet, "accounts": pool_of},
        "objects": objects,
    })
}

fn generate() -> String {
    let document = json!({
        "v": 1,
        "description": concat!(
            "Test vectors of the protocol (protocol.md section 13). Generated by ",
            "`cargo run -p credential-enclave-protocol --bin vectors` from fixed inputs. ",
            "Byte values are base64url without padding. A key ending in `_text` holds the same ",
            "bytes as UTF-8 text. An `hpke_seed` is the input keying material of the HPKE ",
            "ephemeral key pair: the pair is DeriveKeyPair(hpke_seed) of RFC 9180 section 7.1.3. ",
            "`log_v3` is the credential log of format 3 (the releases from v2.4.0 on: the key of ",
            "an object carries the time, the node and the body_hash of its entry) with the node ",
            "document of its node, `log_store` the buckets of format 3 of a log store, `log` the ",
            "log of format 2 (the releases from v2.0.0 to v2.3.0: the key carries body_hash and ",
            "entry_hash, and the node signed heads) and `log_v1` the log of format 1 (one entry ",
            "holds one event). ",
            "`vault_secret` holds a record of that kind and the verdicts of the form rules of ",
            "its plaintext: `valid` says whether a string is a name, a host or a slot, and ",
            "whether `sites` and `slots` together are a reach. A host and a slot of the request ",
            "of a secret use have the same form rules. `reserved_headers` lists the slot of ",
            "every header no slot names. `sealed_release` holds a `release` call that named a ",
            "key to seal the value to: `receiver_private` is the X25519 private key of the ",
            "caller, `seal_to` its public key, and `sealed` the object of the response, which ",
            "opens to `value_text` under the HPKE info `info_text` and the AAD `aad_text`. ",
            "`basic_credentials` holds values of an ",
            "`Authorization` header of a request whose slot is one of the two of HTTP Basic: ",
            "`slot` is the slot of the half of the credentials the placeholder ",
            "`placeholder_text` stands for (`basic:user` or `basic:password`), the one slot a ",
            "node of the forward role sends the request under, or is null for a value it sends ",
            "under neither, and `written_text` is the header that node writes for the value ",
            "`value_text`. `header_values` holds values of the header of a request whose slot ",
            "is `header:<name>`, with the placeholder `placeholder_text` in them: `valid` says ",
            "whether a node of the forward role puts a value in the place of the placeholder, ",
            "and `refused_schemes` lists the names of the authentication schemes behind which ",
            "it puts none. ",
            "`subset` holds the delegation subset (protocol.md 10.4). A case of ",
            "`cases` is a pool of `pods` nodes with `copies` nodes per account, with the group ",
            "of every ordinal in `groups` or without groups, and `skip` groups passed over: ",
            "`assign` lists the ordinals that hold the delegation of `user_id` in the order the ",
            "account takes them. Without `groups`, `ranked` lists every ordinal in the order of ",
            "its rank. With `groups`, `group_order` lists the groups in the order of the ",
            "account and `group_ranked` the ordinals of each of them, in the same order, by ",
            "their rank. `pools` holds two pools whose nodes run in the same groups, and for ",
            "each account its nodes in both and the three groups those nodes run in. `objects` ",
            "holds `subset` objects of a request: `valid` says whether a node reads the object ",
            "or answers `invalid_request`. `spans` holds the spans of a `subset`: `numbers` the ",
            "span number of an account, `contains` `subset` objects with a `user_id` and whether ",
            "the node of their `pod` holds that account (`contains`), `fleet` three pools whose ",
            "spans divide the numbers (`pools`) with the pool of each account (`accounts`), and ",
            "`objects` `subset` objects whose `span` a node reads or answers `invalid_request` ",
            "for (`valid`)."
        ),
        "key_derivation": key_derivation(),
        "record": record(),
        "command": command(),
        "signed": signed(),
        "log_v3": log_v3(),
        "log_store": log_store(),
        "log": log_chain(),
        "log_v1": log_chain_v1(),
        "attestation": attestation(),
        "totp": totp_vectors(),
        "transfer": transfer(),
        "subset": subset_vectors(),
        "vault_secret": vault_secret_forms(),
        "sealed_release": sealed_release(),
        "basic_credentials": basic_credentials(),
        "header_values": header_values(),
    });
    let mut output = serde_json::to_string_pretty(&document).expect("vectors serialize");
    output.push('\n');
    output
}

fn main() -> ExitCode {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors.json");
    let generated = generate();
    match std::env::args().nth(1).as_deref() {
        None => match std::fs::write(&path, &generated) {
            Ok(()) => {
                println!("wrote {}", path.display());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("cannot write {}: {error}", path.display());
                ExitCode::FAILURE
            }
        },
        Some("--stdout") => {
            print!("{generated}");
            ExitCode::SUCCESS
        }
        Some("--check") => match std::fs::read_to_string(&path) {
            Ok(committed) if committed == generated => {
                println!("{} is up to date", path.display());
                ExitCode::SUCCESS
            }
            Ok(_) => {
                eprintln!("{} differs from a fresh run", path.display());
                ExitCode::FAILURE
            }
            Err(error) => {
                eprintln!("cannot read {}: {error}", path.display());
                ExitCode::FAILURE
            }
        },
        Some(other) => {
            eprintln!("unknown argument {other}: expected --check or --stdout");
            ExitCode::FAILURE
        }
    }
}
