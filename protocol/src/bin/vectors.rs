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

use credential_enclave_protocol::app::{self, AccountKeys};
use credential_enclave_protocol::encoding::{
    b64u, b64u_decode, to_json, verify, verify_detached, Signed,
};
use credential_enclave_protocol::envelope::{
    self, Envelope, ReplyBody, ReplyHead, TransferEnvelope, TransferGrant,
};
use credential_enclave_protocol::keys::{self, Custody, NodeKeys};
use credential_enclave_protocol::log::{self, Head};
use credential_enclave_protocol::record::{record_aad, seal_record};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::{purpose, statement, totp};
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
        head: ReplyHead::from(&head),
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

fn log_chain() -> Value {
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

fn generate() -> String {
    let document = json!({
        "v": 1,
        "description": concat!(
            "Test vectors of protocol v1 (protocol.md section 13). Generated by ",
            "`cargo run -p credential-enclave-protocol --bin vectors` from fixed inputs. ",
            "Byte values are base64url without padding. A key ending in `_text` holds the same ",
            "bytes as UTF-8 text. An `hpke_seed` is the input keying material of the HPKE ",
            "ephemeral key pair: the pair is DeriveKeyPair(hpke_seed) of RFC 9180 section 7.1.3."
        ),
        "key_derivation": key_derivation(),
        "record": record(),
        "command": command(),
        "signed": signed(),
        "log": log_chain(),
        "attestation": attestation(),
        "totp": totp_vectors(),
        "transfer": transfer(),
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
