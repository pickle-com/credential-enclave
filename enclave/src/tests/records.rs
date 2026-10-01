//! Records (protocol.md section 6) as `release` opens them: a record opens only for its own
//! account, under the key and the custody of the grant, with every field of its AAD intact.

use credential_enclave_protocol::encoding::b64u;
use credential_enclave_protocol::keys::Custody;
use credential_enclave_protocol::totp::totp;
use serde_json::{json, Value};

use super::quiet_provider;
use crate::testing::{App, Harness};

async fn release(harness: &Harness, user_id: &str, record: &Value, field: &str) -> (u16, Value) {
    harness
        .post(
            "/v1/release",
            json!({
                "user_id": user_id,
                "record": record,
                "field": field,
                "origin": "https://site.example",
                "context": "browser:fill",
            }),
        )
        .await
}

fn code(outcome: &(u16, Value)) -> (u16, &str) {
    (outcome.0, outcome.1["code"].as_str().unwrap_or_default())
}

#[tokio::test]
async fn a_record_of_another_account_does_not_open() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let alice = App::new("alice", 1);
    let bob = App::new("bob", 2);
    alice.grant(&harness).await;
    let bobs = bob.record("vault_password", "vault", &json!({"value": "bob-secret"}));

    // Bob has no grant on this node.
    assert_eq!(
        code(&release(&harness, "bob", &bobs, "password").await),
        (409, "grant_required")
    );
    // Bob's record under Alice's name: the record names another account.
    assert_eq!(
        code(&release(&harness, "alice", &bobs, "password").await),
        (400, "user_mismatch")
    );

    // With both grants in place the records still open for their own account only.
    bob.grant(&harness).await;
    let alices = alice.record("vault_password", "vault", &json!({"value": "alice-secret"}));
    assert_eq!(
        release(&harness, "alice", &alices, "password").await.1["value"],
        "alice-secret"
    );
    assert_eq!(
        release(&harness, "bob", &bobs, "password").await.1["value"],
        "bob-secret"
    );
    assert_eq!(
        code(&release(&harness, "bob", &alices, "password").await),
        (400, "user_mismatch")
    );

    // A record rewritten to name the other account: the key of the grant differs.
    let mut renamed = alices.clone();
    renamed["user_id"] = json!("bob");
    assert_eq!(
        code(&release(&harness, "bob", &renamed, "password").await),
        (409, "key_mismatch")
    );
    // With the key_id rewritten as well, the AEAD check fails: the user key is another one.
    renamed["key_id"] = json!(bob.keys.key_id());
    assert_eq!(
        code(&release(&harness, "bob", &renamed, "password").await),
        (422, "record_invalid")
    );
}

#[tokio::test]
async fn a_record_of_another_key_does_not_open() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let current = App::new("user-1", 1);
    let former = App::new("user-1", 2);
    current.grant(&harness).await;
    let old = former.record("vault_password", "vault", &json!({"value": "old"}));
    assert_eq!(
        code(&release(&harness, "user-1", &old, "password").await),
        (409, "key_mismatch")
    );
}

#[tokio::test]
async fn a_record_of_another_custody_does_not_open() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&harness).await;

    // The same account made this record for a node of custody `enclave`, under the user key
    // of that custody. This node holds the user key of custody `operator` only.
    let mut enclave_app = App::new("user-1", 1);
    enclave_app.custody = Custody::Enclave;
    let record = enclave_app.record("vault_password", "vault", &json!({"value": "hunter2"}));
    assert_eq!(record["custody"], "enclave");
    assert_eq!(record["key_id"], app.keys.key_id().as_str());
    assert_eq!(
        code(&release(&harness, "user-1", &record, "password").await),
        (409, "key_mismatch")
    );
    // Relabelled as a record of this node's custody, it reaches the AEAD check and fails
    // there: the user key is another one and the custody is part of the AAD.
    let mut relabelled = record.clone();
    relabelled["custody"] = json!("operator");
    assert_eq!(
        code(&release(&harness, "user-1", &relabelled, "password").await),
        (422, "record_invalid")
    );
    // A record without a custody is not a record of this protocol version.
    let mut without = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
    without.as_object_mut().unwrap().remove("custody");
    assert_eq!(
        code(&release(&harness, "user-1", &without, "password").await),
        (422, "record_invalid")
    );
    // Only the grant left an entry.
    assert_eq!(harness.head_seq("user-1"), 1);
}

#[tokio::test]
async fn every_tampered_field_of_a_record_fails_to_open() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let record = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
    assert_eq!(
        release(&harness, "user-1", &record, "password").await.0,
        200
    );

    let changes: [(&str, Value, &str, (u16, &str)); 10] = [
        (
            "id",
            json!(b64u(&[3u8; 16])),
            "password",
            (422, "record_invalid"),
        ),
        (
            "user_id",
            json!("user-2"),
            "password",
            (400, "user_mismatch"),
        ),
        (
            "key_id",
            json!("0000000000000000"),
            "password",
            (409, "key_mismatch"),
        ),
        // The custody of the record is compared with the custody of the grant before the
        // record is decrypted.
        (
            "custody",
            json!("enclave"),
            "password",
            (409, "key_mismatch"),
        ),
        ("custody", json!("hsm"), "password", (409, "key_mismatch")),
        // The kind decides which field may be asked for, and it is part of the AAD.
        ("kind", json!("vault_totp"), "totp", (422, "record_invalid")),
        (
            "provider",
            json!("other"),
            "password",
            (422, "record_invalid"),
        ),
        (
            "nonce",
            json!(b64u(&[4u8; 12])),
            "password",
            (422, "record_invalid"),
        ),
        (
            "ct",
            json!(b64u(&[5u8; 40])),
            "password",
            (422, "record_invalid"),
        ),
        ("v", json!(2), "password", (400, "unsupported_version")),
    ];
    for (field, value, asked, expected) in changes {
        let mut changed = record.clone();
        changed[field] = value;
        assert_eq!(
            code(&release(&harness, "user-1", &changed, asked).await),
            expected,
            "{field}"
        );
    }
    // A record that is not a record.
    assert_eq!(
        code(&release(&harness, "user-1", &json!({"v": 1, "id": "x"}), "password").await),
        (422, "record_invalid")
    );
    // No refused call left an entry behind: grant and the one successful release.
    assert_eq!(harness.head_seq("user-1"), 2);
}

#[tokio::test]
async fn the_kind_of_a_record_decides_the_fields_it_releases() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let password = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
    let seed = app.record("vault_totp", "vault", &json!({"value": "JBSWY3DPEHPK3PXP"}));
    let card = app.record(
        "vault_card",
        "vault",
        &json!({"number": "4242424242424242", "cvc": "123"}),
    );
    let token = app.record(
        "oauth",
        "slack",
        &json!({"token": {"access_token": "xoxp"}, "obtained_ms": 1}),
    );

    // password
    let (status, released) = release(&harness, "user-1", &password, "password").await;
    assert_eq!(status, 200);
    assert_eq!(released["value"], "hunter2");
    assert_eq!(
        app.event(&harness, &released["entry"]),
        json!({
            "t": "secret_released", "record_id": password["id"], "kind": "vault_password",
            "field": "password", "origin": "https://site.example", "context": "browser:fill",
        })
    );

    // totp: the code leaves, the seed does not.
    let before = harness.node.now_ms();
    let (status, released) = release(&harness, "user-1", &seed, "totp").await;
    let after = harness.node.now_ms();
    assert_eq!(status, 200);
    let value = released["value"].as_str().unwrap();
    assert_eq!(value.len(), 6);
    assert!(
        value == totp("JBSWY3DPEHPK3PXP", before).unwrap()
            || value == totp("JBSWY3DPEHPK3PXP", after).unwrap()
    );
    assert!(!released.to_string().contains("JBSWY3DPEHPK3PXP"));
    assert_eq!(
        app.event(&harness, &released["entry"]),
        json!({
            "t": "totp_issued", "record_id": seed["id"],
            "origin": "https://site.example", "context": "browser:fill",
        })
    );

    // card: one field per call.
    let (_, number) = release(&harness, "user-1", &card, "card_number").await;
    assert_eq!(number["value"], "4242424242424242");
    let (_, cvc) = release(&harness, "user-1", &card, "card_cvc").await;
    assert_eq!(cvc["value"], "123");
    assert_eq!(app.event(&harness, &cvc["entry"])["field"], "card_cvc");
    assert_eq!(app.event(&harness, &cvc["entry"])["kind"], "vault_card");

    // Every other pair of kind and field is refused, and nothing is recorded for it.
    let seq = harness.head_seq("user-1");
    for (record, field) in [
        (&password, "totp"),
        (&password, "card_number"),
        (&seed, "password"),
        (&card, "password"),
        (&card, "totp"),
        (&token, "password"),
        (&password, "value"),
    ] {
        assert_eq!(
            code(&release(&harness, "user-1", record, field).await),
            (403, "not_allowed"),
            "{field}"
        );
    }
    assert_eq!(harness.head_seq("user-1"), seq);

    // A plaintext that lacks the value, and a seed that is not base32.
    let empty = app.record("vault_password", "vault", &json!({"other": "x"}));
    assert_eq!(
        code(&release(&harness, "user-1", &empty, "password").await),
        (422, "record_invalid")
    );
    let broken = app.record("vault_totp", "vault", &json!({"value": "not base32!"}));
    assert_eq!(
        code(&release(&harness, "user-1", &broken, "totp").await),
        (422, "record_invalid")
    );
    assert_eq!(harness.head_seq("user-1"), seq);
}

#[tokio::test]
async fn release_checks_its_arguments_and_needs_no_operator_configuration() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    assert_eq!(harness.health().await["configured"], false);
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let record = app.record("vault_password", "vault", &json!({"value": "hunter2"}));

    for (origin, context) in [
        ("http://site.example", "c".to_string()),
        ("site.example", "c".to_string()),
        ("https://site.example/login", "c".to_string()),
        ("https://site.example", "c".repeat(257)),
    ] {
        let outcome = harness
            .post(
                "/v1/release",
                json!({
                    "user_id": "user-1", "record": record, "field": "password",
                    "origin": origin, "context": context,
                }),
            )
            .await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{origin}");
    }
    assert_eq!(
        release(&harness, "user-1", &record, "password").await.0,
        200
    );

    // The provider stand-in saw nothing: release calls no provider.
    assert!(provider.seen().is_empty());
}
