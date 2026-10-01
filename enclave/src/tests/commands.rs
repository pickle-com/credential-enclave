//! Command processing (protocol.md 5.3 and 5.4): the state transitions of grant and revoke
//! sequences.

use credential_enclave_protocol::app;
use credential_enclave_protocol::encoding::{b64u, b64u_decode};
use credential_enclave_protocol::keys::{Custody, NodeKeys};
use credential_enclave_protocol::log::entry_hash;
use credential_enclave_protocol::{limits, purpose};
use serde_json::{json, Value};

use super::{quiet_provider, quiet_provider_and_log_store};
use crate::platform::Measurement;
use crate::state::{lock, GrantState};
use crate::testing::{App, Attested, Harness};

fn reply(harness: &Harness, response: &Value) -> Value {
    harness.verified(purpose::REPLY, &response["reply"])
}

async fn release(harness: &Harness, app: &App, record: &Value) -> (u16, Value) {
    harness
        .post(
            "/v1/release",
            json!({
                "user_id": app.user_id,
                "record": record,
                "field": "password",
                "origin": "https://site.example",
                "context": "browser:fill",
            }),
        )
        .await
}

fn password(app: &App) -> Value {
    app.record("vault_password", "vault", &json!({"value": "hunter2"}))
}

#[tokio::test]
async fn a_grant_is_accepted_recorded_and_answered_with_a_signed_reply() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    let attested = app.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let response = app
        .send(&harness, app.grant_envelope(&attested, not_after_ms))
        .await;

    let reply = reply(&harness, &response);
    assert_eq!(reply["v"], 1);
    assert_eq!(reply["type"], "grant_reply");
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["code"], "");
    assert_eq!(reply["node"], harness.node.node.as_str());
    assert_eq!(reply["user_id"], "user-1");
    assert_eq!(reply["challenge"], attested.challenge.as_str());
    assert_eq!(reply["key_id"], app.keys.key_id().as_str());
    assert_eq!(reply["not_after_ms"], not_after_ms);
    assert_eq!(reply["head"]["seq"], 1);

    // The entry is the first of the chain and only the account can read it.
    let entry = app.entry_body(&harness, &response["entry"]);
    assert_eq!(entry["seq"], 1);
    assert_eq!(entry["prev"], b64u(&[0u8; 32]));
    assert_eq!(entry["node"], harness.node.node.as_str());
    assert_eq!(entry["user_id"], "user-1");
    assert_eq!(entry["key_id"], app.keys.key_id().as_str());
    assert_eq!(
        app.event(&harness, &response["entry"]),
        json!({"t": "grant_accepted", "not_after_ms": not_after_ms, "custody": "operator"})
    );
    let body = b64u_decode(response["entry"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(reply["head"]["hash"], b64u(&entry_hash(&body)));

    // The plaintext copy for the caller, the health count and the status call agree.
    assert_eq!(
        response["grant"],
        json!({
            "state": "active", "key_id": app.keys.key_id(), "custody": "operator",
            "not_after_ms": not_after_ms,
        })
    );
    let health = harness.health().await;
    assert_eq!(
        (&health["accounts"], &health["grants"]),
        (&json!(1), &json!(1))
    );
    let (status, state) = harness
        .post(
            "/v1/status",
            json!({"user_id": "user-1", "nonce": "bm9uY2U"}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(state["grant"], response["grant"]);
    let head = harness.verified(purpose::HEAD, &state["head"]);
    assert_eq!(head["type"], "head");
    assert_eq!(head["seq"], 1);
    assert_eq!(head["hash"], reply["head"]["hash"]);
    assert_eq!(head["nonce"], "bm9uY2U");
    assert_eq!(head["final"], false);

    // The user key works: a record of the account opens.
    let (status, released) = release(&harness, &app, &password(&app)).await;
    assert_eq!(status, 200);
    assert_eq!(released["value"], "hunter2");
}

#[tokio::test]
async fn a_challenge_is_accepted_once_and_for_300_seconds() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);

    // The same envelope a second time: the challenge was used.
    let attested = app.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let envelope = app.grant_envelope(&attested, not_after_ms);
    assert_eq!(
        reply(&harness, &app.send(&harness, envelope.clone()).await)["ok"],
        true
    );
    let replayed = app.send(&harness, envelope).await;
    let body = reply(&harness, &replayed);
    assert_eq!(body["ok"], false);
    assert_eq!(body["code"], "bad_challenge");
    assert_eq!(body["challenge"], attested.challenge.as_str());
    assert_eq!(body["key_id"], app.keys.key_id().as_str());
    assert_eq!(body["head"]["seq"], 1);
    assert_eq!(replayed["entry"], Value::Null);
    assert_eq!(replayed["grant"]["state"], "active");
    assert_eq!(harness.head_seq("user-1"), 1);

    // A challenge of another kind of origin: never issued by this node.
    let invented = Attested {
        node: attested.node.clone(),
        seal_public: attested.seal_public,
        challenge: b64u(&[7u8; 16]),
    };
    let response = app
        .send(&harness, app.grant_envelope(&invented, not_after_ms))
        .await;
    assert_eq!(reply(&harness, &response)["code"], "bad_challenge");

    // A challenge older than 300 seconds.
    let late = app.attest(&harness).await;
    harness.node.clock.advance(limits::CHALLENGE_MS + 1_000);
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let response = app
        .send(&harness, app.grant_envelope(&late, not_after_ms))
        .await;
    assert_eq!(reply(&harness, &response)["code"], "bad_challenge");

    // A challenge used within its 300 seconds.
    let in_time = app.attest(&harness).await;
    harness.node.clock.advance(limits::CHALLENGE_MS - 5_000);
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let response = app
        .send(&harness, app.grant_envelope(&in_time, not_after_ms))
        .await;
    assert_eq!(reply(&harness, &response)["ok"], true);
}

#[tokio::test]
async fn a_command_for_another_node_is_refused() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    let attested = app.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let other = NodeKeys::from_random(&[8u8; 32], &[9u8; 32]);

    // An envelope made for another node: refused before it is opened, so the reply names no
    // user, challenge or key.
    let for_other = Attested {
        node: other.node(),
        seal_public: other.seal_public(),
        challenge: attested.challenge.clone(),
    };
    let response = app
        .send(&harness, app.grant_envelope(&for_other, not_after_ms))
        .await;
    let body = reply(&harness, &response);
    assert_eq!(body["ok"], false);
    assert_eq!(body["code"], "wrong_node");
    assert_eq!(body["type"], "grant_reply");
    assert_eq!(body["user_id"], "");
    assert_eq!(body["challenge"], "");
    assert_eq!(body["key_id"], "");
    assert_eq!(body["head"], json!({"seq": 0, "hash": b64u(&[0u8; 32])}));
    assert_eq!(response["grant"]["state"], "none");

    // An envelope sealed for this node whose command names another node.
    let payload = app::grant_payload(
        &app.keys,
        "user-1",
        &other.node(),
        &attested.challenge,
        Custody::Operator,
        not_after_ms,
    );
    let response = app.send(&harness, app.envelope(&attested, &payload)).await;
    assert_eq!(reply(&harness, &response)["code"], "wrong_node");

    // An envelope sealed for another node's key under this node's name cannot be opened.
    let sealed_for_other = Attested {
        node: attested.node.clone(),
        seal_public: other.seal_public(),
        challenge: attested.challenge.clone(),
    };
    let response = app
        .send(
            &harness,
            app.grant_envelope(&sealed_for_other, not_after_ms),
        )
        .await;
    assert_eq!(reply(&harness, &response)["code"], "open_failed");

    // None of the refusals used the challenge: the right command still passes.
    let response = app
        .send(&harness, app.grant_envelope(&attested, not_after_ms))
        .await;
    assert_eq!(reply(&harness, &response)["ok"], true);
}

#[tokio::test]
async fn a_command_of_another_user_is_refused() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    let attested = app.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let envelope = app.grant_envelope(&attested, not_after_ms);

    // The caller says user-2, the command says user-1.
    let (status, response) = harness
        .post(
            "/v1/messages",
            json!({"user_id": "user-2", "envelope": envelope}),
        )
        .await;
    assert_eq!(status, 200);
    let body = reply(&harness, &response);
    assert_eq!(body["ok"], false);
    assert_eq!(body["code"], "user_mismatch");
    assert_eq!(body["user_id"], "user-1");
    assert_eq!(body["challenge"], attested.challenge.as_str());
    assert_eq!(response["grant"]["state"], "none");
    assert_eq!(response["entry"], Value::Null);
    assert!(harness.node.account("user-1").is_none());
    assert!(harness.node.account("user-2").is_none());

    // The challenge was not used by the refusal.
    let response = app.send(&harness, envelope).await;
    assert_eq!(reply(&harness, &response)["ok"], true);
}

#[tokio::test]
async fn a_grant_that_ended_is_refused_and_a_longer_one_is_shortened_to_30_days() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);

    // An end that is not after the node time: refused.
    for offset_ms in [-1_000i64, 0] {
        let attested = app.attest(&harness).await;
        let not_after_ms = (harness.node.now_ms() as i64 + offset_ms) as u64;
        let envelope = app.grant_envelope(&attested, not_after_ms);
        let response = app.send(&harness, envelope.clone()).await;
        let body = reply(&harness, &response);
        assert_eq!(body["code"], "bad_expiry", "{offset_ms}");
        assert_eq!(body["not_after_ms"], 0);
        assert_eq!(body["challenge"], attested.challenge.as_str());
        assert_eq!(body["key_id"], app.keys.key_id().as_str());
        assert_eq!(response["grant"]["state"], "none");
        assert_eq!(response["entry"], Value::Null);
        // The challenge was used in step 12, before the expiry was checked in step 13.
        let again = app.send(&harness, envelope).await;
        assert_eq!(reply(&harness, &again)["code"], "bad_challenge");
    }
    assert_eq!(harness.head_seq("user-1"), 0);

    // An end within 30 days is taken as it is.
    let attested = app.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + 60_000;
    let response = app
        .send(&harness, app.grant_envelope(&attested, not_after_ms))
        .await;
    let body = reply(&harness, &response);
    assert_eq!(body["ok"], true);
    assert_eq!(body["not_after_ms"], not_after_ms);

    // An end beyond 30 days of node time is not refused: the node moves it to 30 days from
    // its own time, and the reply, the entry and the plaintext copy carry the accepted end.
    // (An app whose device clock is far ahead still delegates.)
    for beyond_ms in [1u64, 60_000, 365 * 24 * 60 * 60 * 1000] {
        let attested = app.attest(&harness).await;
        let before = harness.node.now_ms();
        let asked = before + limits::GRANT_MAX_MS + 5_000 + beyond_ms;
        let response = app
            .send(&harness, app.grant_envelope(&attested, asked))
            .await;
        let after = harness.node.now_ms();
        let body = reply(&harness, &response);
        assert_eq!(body["ok"], true, "{beyond_ms}");
        let accepted = body["not_after_ms"].as_u64().unwrap();
        assert!(accepted < asked, "{beyond_ms}");
        assert!(
            (before + limits::GRANT_MAX_MS..=after + limits::GRANT_MAX_MS).contains(&accepted),
            "{beyond_ms}"
        );
        assert_eq!(
            app.event(&harness, &response["entry"]),
            json!({"t": "grant_accepted", "not_after_ms": accepted, "custody": "operator"})
        );
        assert_eq!(response["grant"]["not_after_ms"], accepted);
    }
    // The largest u64 is an unsigned integer like any other.
    let attested = app.attest(&harness).await;
    let response = app
        .send(&harness, app.grant_envelope(&attested, u64::MAX))
        .await;
    let body = reply(&harness, &response);
    assert_eq!(body["ok"], true);
    assert!(body["not_after_ms"].as_u64().unwrap() <= harness.node.now_ms() + limits::GRANT_MAX_MS);
}

#[tokio::test]
async fn a_grant_of_another_custody_is_refused() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    // The node runs on the local platform: its custody is `operator`.
    assert_eq!(harness.node.custody, Custody::Operator);
    let mut app = App::new("user-1", 1);
    let attested = app.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;

    // A grant that carries the user key of custody `enclave`.
    app.custody = Custody::Enclave;
    let response = app
        .send(&harness, app.grant_envelope(&attested, not_after_ms))
        .await;
    let body = reply(&harness, &response);
    assert_eq!(body["ok"], false);
    assert_eq!(body["code"], "custody_mismatch");
    // The node cannot take the command: the reply names no user, challenge or key.
    assert_eq!(body["type"], "grant_reply");
    assert_eq!(body["user_id"], "");
    assert_eq!(body["challenge"], "");
    assert_eq!(body["key_id"], "");
    assert_eq!(body["not_after_ms"], 0);
    assert_eq!(body["head"], json!({"seq": 0, "hash": b64u(&[0u8; 32])}));
    assert_eq!(response["entry"], Value::Null);
    assert_eq!(response["grant"]["state"], "none");
    assert!(harness.node.account("user-1").is_none());

    // The custody is checked before the user of the call: the code is the one of the
    // earlier check.
    let (status, response) = harness
        .post(
            "/v1/messages",
            json!({"user_id": "user-2", "envelope": app.grant_envelope(&attested, not_after_ms)}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(reply(&harness, &response)["code"], "custody_mismatch");

    // The refusal did not use the challenge: the grant of this node's custody passes with it.
    app.custody = Custody::Operator;
    let response = app
        .send(&harness, app.grant_envelope(&attested, not_after_ms))
        .await;
    assert_eq!(reply(&harness, &response)["ok"], true);
    assert_eq!(response["grant"]["custody"], "operator");
    assert_eq!(harness.health().await["custody"], "operator");
}

#[tokio::test]
async fn a_node_of_custody_enclave_takes_the_user_key_of_that_custody_only() {
    // A node of the nitro platform does not act without a log store: this one has one that
    // confirms every write.
    let provider = quiet_provider_and_log_store().await;
    let measurement = Measurement {
        pcrs: [[0xa0; 48], [0xa1; 48], [0xa2; 48]],
    };
    let harness = Harness::measured(&provider, measurement);
    harness.use_log_store().await;
    assert_eq!(harness.node.custody, Custody::Enclave);
    let health = harness.health().await;
    assert_eq!(
        (&health["platform"], &health["custody"]),
        (&json!("nitro"), &json!("enclave"))
    );

    // The user key of custody `operator` is refused here.
    let operator_app = App::new("user-1", 1);
    let attested = operator_app.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let response = operator_app
        .send(
            &harness,
            operator_app.grant_envelope(&attested, not_after_ms),
        )
        .await;
    assert_eq!(reply(&harness, &response)["code"], "custody_mismatch");
    assert_eq!(harness.health().await["grants"], 0);

    // The user key of custody `enclave` is taken, and what the node makes with it says so.
    let mut app = App::new("user-1", 1);
    app.custody = Custody::Enclave;
    let response = app
        .send(&harness, app.grant_envelope(&attested, not_after_ms))
        .await;
    assert_eq!(reply(&harness, &response)["ok"], true);
    assert_eq!(
        response["grant"],
        json!({
            "state": "active", "key_id": app.keys.key_id(), "custody": "enclave",
            "not_after_ms": not_after_ms,
        })
    );
    assert_eq!(
        app.event(&harness, &response["entry"]),
        json!({"t": "grant_accepted", "not_after_ms": not_after_ms, "custody": "enclave"})
    );
    // Records under the two user keys of the same account: only the one of custody `enclave`
    // opens here.
    assert_eq!(release(&harness, &app, &password(&app)).await.0, 200);
    let (status, failure) = release(&harness, &operator_app, &password(&operator_app)).await;
    assert_eq!(
        (status, failure["code"].as_str()),
        (409, Some("key_mismatch"))
    );

    // A node of the local platform is not a peer of this node, and neither is a document
    // that is not a Nitro attestation document under the name of the nitro platform.
    let local = Harness::new(&provider);
    let (_, local_response) = local
        .post("/v1/attestation", json!({"nonce": b64u(&[9u8; 32])}))
        .await;
    let mut renamed = local_response.clone();
    renamed["platform"] = json!("nitro");
    for peer in [local_response, renamed] {
        let (status, failure) = harness.post("/v1/peer/export", json!({"peer": peer})).await;
        assert_eq!(
            (status, failure["code"].as_str()),
            (403, Some("peer_unverified"))
        );
    }
    // No refused export left an entry: grant and one release.
    assert_eq!(harness.head_seq("user-1"), 2);
}

#[tokio::test]
async fn a_revoke_ends_the_delegation_and_an_old_envelope_does_not_bring_it_back() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    let attested = app.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let grant_envelope = app.grant_envelope(&attested, not_after_ms);
    app.send(&harness, grant_envelope.clone()).await;
    let record = password(&app);
    assert_eq!(release(&harness, &app, &record).await.0, 200);

    let response = app.revoke(&harness).await;
    let body = reply(&harness, &response);
    assert_eq!(body["type"], "revoke_reply");
    assert_eq!(body["ok"], true);
    assert_eq!(body["key_id"], app.keys.key_id().as_str());
    assert_eq!(body["not_after_ms"], 0);
    assert_eq!(body["head"]["seq"], 3);
    assert_eq!(
        response["grant"],
        json!({"state": "revoked", "key_id": app.keys.key_id(), "custody": "", "not_after_ms": 0})
    );
    assert_eq!(harness.health().await["grants"], 0);
    // The entry is sealed to the log key of the grant that ended.
    assert_eq!(
        app.event(&harness, &response["entry"]),
        json!({"t": "grant_revoked"})
    );
    assert_eq!(app.entry_body(&harness, &response["entry"])["seq"], 3);

    // The user key is gone: nothing opens any more.
    let (status, failure) = release(&harness, &app, &record).await;
    assert_eq!(
        (status, failure["code"].as_str()),
        (409, Some("grant_revoked"))
    );
    let (_, state) = harness
        .post(
            "/v1/status",
            json!({"user_id": "user-1", "nonce": "bm9uY2U"}),
        )
        .await;
    assert_eq!(state["grant"]["state"], "revoked");

    // The grant envelope from before the revoke is refused: its challenge was used.
    let replayed = app.send(&harness, grant_envelope).await;
    assert_eq!(reply(&harness, &replayed)["code"], "bad_challenge");
    assert_eq!(replayed["grant"]["state"], "revoked");
    assert_eq!(release(&harness, &app, &record).await.0, 409);

    // A second revoke is idempotent and creates no entry.
    let again = app.revoke(&harness).await;
    assert_eq!(reply(&harness, &again)["ok"], true);
    assert_eq!(again["entry"], Value::Null);
    assert_eq!(harness.head_seq("user-1"), 3);

    // A new grant replaces the revocation marker.
    let response = app.grant(&harness).await;
    assert_eq!(response["grant"]["state"], "active");
    assert_eq!(release(&harness, &app, &record).await.0, 200);
}

#[tokio::test]
async fn a_grant_that_was_held_back_is_refused_after_a_revoke_of_the_account() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let record = password(&app);
    assert_eq!(release(&harness, &app, &record).await.0, 200);

    // The app seals a grant with a challenge of the node. Whoever carries the envelope keeps
    // it instead of delivering it.
    let held = app.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let held_envelope = app.grant_envelope(&held, not_after_ms);

    // The app revokes with a later challenge. The revoke is delivered, and the app receives
    // the signed reply.
    let revoked = app.revoke(&harness).await;
    let body = reply(&harness, &revoked);
    assert_eq!(
        (&body["type"], &body["ok"]),
        (&json!("revoke_reply"), &json!(true))
    );
    assert_eq!(body["head"]["seq"], 3);

    // The kept grant arrives within the 300 seconds of its challenge, which was never used.
    // The node issued that challenge before the revoke: the grant is refused.
    let late = app.send(&harness, held_envelope.clone()).await;
    let body = reply(&harness, &late);
    assert_eq!(body["type"], "grant_reply");
    assert_eq!(body["ok"], false);
    assert_eq!(body["code"], "bad_challenge");
    assert_eq!(body["user_id"], "user-1");
    assert_eq!(body["challenge"], held.challenge.as_str());
    assert_eq!(body["key_id"], app.keys.key_id().as_str());
    assert_eq!(body["not_after_ms"], 0);
    assert_eq!(body["head"]["seq"], 3);
    // No entry, and the account is as the revoke left it.
    assert_eq!(late["entry"], Value::Null);
    assert_eq!(
        late["grant"],
        json!({"state": "revoked", "key_id": app.keys.key_id(), "custody": "", "not_after_ms": 0})
    );
    assert_eq!(harness.head_seq("user-1"), 3);
    assert_eq!(harness.health().await["grants"], 0);
    let (_, state) = harness
        .post(
            "/v1/status",
            json!({"user_id": "user-1", "nonce": "bm9uY2U"}),
        )
        .await;
    assert_eq!(state["grant"]["state"], "revoked");
    let (status, failure) = release(&harness, &app, &record).await;
    assert_eq!(
        (status, failure["code"].as_str()),
        (409, Some("grant_revoked"))
    );
    // The refusal used the challenge up.
    let again = app.send(&harness, held_envelope).await;
    assert_eq!(reply(&harness, &again)["code"], "bad_challenge");
    assert_eq!(again["grant"]["state"], "revoked");

    // The same holds when the revoke met no grant: it leaves the marker, and a grant from
    // before it stays out. The account has no chain, so the reply carries the empty head.
    let fresh = App::new("user-2", 2);
    let held = fresh.attest(&harness).await;
    let held_envelope = fresh.grant_envelope(&held, not_after_ms);
    let revoked = fresh.revoke(&harness).await;
    assert_eq!(reply(&harness, &revoked)["ok"], true);
    assert_eq!(revoked["entry"], Value::Null);
    let late = fresh.send(&harness, held_envelope).await;
    let body = reply(&harness, &late);
    assert_eq!(body["code"], "bad_challenge");
    assert_eq!(body["head"], json!({"seq": 0, "hash": b64u(&[0u8; 32])}));
    assert_eq!(late["entry"], Value::Null);
    assert_eq!(late["grant"]["state"], "revoked");
    assert_eq!(harness.head_seq("user-2"), 0);

    // It also holds after a grant replaced the revocation marker: what a revoke ended, only
    // a grant made after it brings back.
    let held = app.attest(&harness).await;
    let held_envelope = app.grant_envelope(&held, not_after_ms);
    app.revoke(&harness).await;
    assert_eq!(app.grant(&harness).await["grant"]["state"], "active");
    let seq = harness.head_seq("user-1");
    let late = app.send(&harness, held_envelope).await;
    assert_eq!(reply(&harness, &late)["code"], "bad_challenge");
    assert_eq!(late["entry"], Value::Null);
    // The grant in force is the one the app made after the revoke.
    assert_eq!(late["grant"]["state"], "active");
    assert_eq!(harness.head_seq("user-1"), seq);
    assert_eq!(release(&harness, &app, &record).await.0, 200);
}

#[tokio::test]
async fn a_grant_with_a_challenge_from_after_a_revoke_is_accepted() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let record = password(&app);

    // The challenge of this grant is issued after the node accepted the revoke.
    assert_eq!(reply(&harness, &app.revoke(&harness).await)["ok"], true);
    let attested = app.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let response = app
        .send(&harness, app.grant_envelope(&attested, not_after_ms))
        .await;
    let body = reply(&harness, &response);
    assert_eq!(body["ok"], true);
    assert_eq!(body["challenge"], attested.challenge.as_str());
    assert_eq!(response["grant"]["state"], "active");
    assert_eq!(
        app.event(&harness, &response["entry"])["t"],
        "grant_accepted"
    );
    // grant, revoke, grant.
    assert_eq!(harness.head_seq("user-1"), 3);
    assert_eq!(release(&harness, &app, &record).await.0, 200);
}

#[tokio::test]
async fn a_revoke_of_one_account_does_not_touch_the_grants_of_another() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let alice = App::new("alice", 1);
    let bob = App::new("bob", 2);
    alice.grant(&harness).await;

    // Bob seals a grant, and its delivery is delayed. In between, alice revokes: the
    // challenge of bob's grant is older than her revoke.
    let attested = bob.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let envelope = bob.grant_envelope(&attested, not_after_ms);
    assert_eq!(reply(&harness, &alice.revoke(&harness).await)["ok"], true);

    // Bob never revoked: his grant is taken as before.
    let response = bob.send(&harness, envelope).await;
    assert_eq!(reply(&harness, &response)["ok"], true);
    assert_eq!(response["grant"]["state"], "active");
    assert_eq!(release(&harness, &bob, &password(&bob)).await.0, 200);

    // An account that never revoked renews with a challenge of any age within its 300
    // seconds.
    let attested = bob.attest(&harness).await;
    harness.node.clock.advance(limits::CHALLENGE_MS - 5_000);
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let response = bob
        .send(&harness, bob.grant_envelope(&attested, not_after_ms))
        .await;
    assert_eq!(reply(&harness, &response)["ok"], true);
}

#[tokio::test]
async fn a_revoke_is_signed_by_the_key_of_the_grant() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&harness).await;

    // Another key cannot end the delegation of user-1.
    let stranger = App::new("user-1", 2);
    let response = stranger.revoke(&harness).await;
    let body = reply(&harness, &response);
    assert_eq!(body["ok"], false);
    assert_eq!(body["code"], "bad_signature");
    assert_eq!(response["entry"], Value::Null);
    assert_eq!(response["grant"]["state"], "active");
    assert_eq!(release(&harness, &app, &password(&app)).await.0, 200);

    // A revoke for an account without a grant passes and leaves a marker without an entry.
    let fresh = App::new("user-9", 9);
    let response = fresh.revoke(&harness).await;
    assert_eq!(reply(&harness, &response)["ok"], true);
    assert_eq!(response["entry"], Value::Null);
    assert_eq!(
        response["grant"],
        json!({"state": "revoked", "key_id": fresh.keys.key_id(), "custody": "", "not_after_ms": 0})
    );
    assert_eq!(harness.head_seq("user-9"), 0);
    // An account without a chain is not counted.
    assert_eq!(harness.health().await["accounts"], 1);
}

#[tokio::test]
async fn a_new_grant_replaces_the_grant_before_it() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let first = App::new("user-1", 1);
    first.grant(&harness).await;
    let old_record = password(&first);
    assert_eq!(release(&harness, &first, &old_record).await.0, 200);

    // The same account with a new master key (after reset_key).
    let second = App::new("user-1", 2);
    let response = second.grant(&harness).await;
    assert_eq!(response["grant"]["key_id"], second.keys.key_id().as_str());
    // The chain continues: the entry of the new grant follows the entries before it.
    assert_eq!(second.entry_body(&harness, &response["entry"])["seq"], 3);
    assert_eq!(
        second.entry_body(&harness, &response["entry"])["key_id"],
        second.keys.key_id().as_str()
    );

    // Records of the old key no longer open, records of the new key do.
    let (status, failure) = release(&harness, &first, &old_record).await;
    assert_eq!(
        (status, failure["code"].as_str()),
        (409, Some("key_mismatch"))
    );
    assert_eq!(release(&harness, &second, &password(&second)).await.0, 200);

    // A renewal with the same key keeps the key_id and moves the expiry.
    let before = response["grant"]["not_after_ms"].as_u64().unwrap();
    harness.node.clock.advance(3_600_000);
    let renewed = second.grant(&harness).await;
    assert_eq!(renewed["grant"]["key_id"], second.keys.key_id().as_str());
    assert!(renewed["grant"]["not_after_ms"].as_u64().unwrap() > before);
}

#[tokio::test]
async fn an_expired_grant_is_refused_and_reported() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    let attested = app.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + 120_000;
    app.send(&harness, app.grant_envelope(&attested, not_after_ms))
        .await;
    let record = password(&app);
    assert_eq!(release(&harness, &app, &record).await.0, 200);

    harness.node.clock.advance(121_000);
    let (status, failure) = release(&harness, &app, &record).await;
    assert_eq!(
        (status, failure["code"].as_str()),
        (409, Some("grant_expired"))
    );
    // The refusal stays `grant_expired` on later uses.
    assert_eq!(
        release(&harness, &app, &record).await.1["code"],
        "grant_expired"
    );
    let (_, state) = harness
        .post(
            "/v1/status",
            json!({"user_id": "user-1", "nonce": "bm9uY2U"}),
        )
        .await;
    assert_eq!(
        state["grant"],
        json!({
            "state": "expired", "key_id": app.keys.key_id(), "custody": "",
            "not_after_ms": not_after_ms,
        })
    );
    assert_eq!(harness.health().await["grants"], 0);

    // A new grant brings the delegation back.
    app.grant(&harness).await;
    assert_eq!(release(&harness, &app, &record).await.0, 200);
}

#[tokio::test]
async fn an_expired_grant_counts_as_no_grant_in_commands() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    let attested = app.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + 120_000;
    app.send(&harness, app.grant_envelope(&attested, not_after_ms))
        .await;
    harness.node.clock.advance(121_000);

    // The plaintext copy of `messages` reports an expired grant as `none`.
    let replayed = app
        .send(&harness, app.grant_envelope(&attested, not_after_ms))
        .await;
    assert_eq!(reply(&harness, &replayed)["code"], "bad_challenge");
    assert_eq!(
        replayed["grant"],
        json!({"state": "none", "key_id": "", "custody": "", "not_after_ms": 0})
    );
    // Reading the state ended the grant: the account holds no user key any more.
    {
        let account = harness.node.account("user-1").unwrap();
        assert!(matches!(
            lock(&account).grant,
            GrantState::Expired { not_after_ms: end, .. } if end == not_after_ms
        ));
    }

    // A revoke after the expiry meets no grant: it is not compared with the key of the grant
    // that ended, creates no entry and leaves the marker of the key that sent it.
    let stranger = App::new("user-1", 2);
    let response = stranger.revoke(&harness).await;
    let body = reply(&harness, &response);
    assert_eq!(body["ok"], true);
    assert_eq!(body["type"], "revoke_reply");
    assert_eq!(response["entry"], Value::Null);
    assert_eq!(harness.head_seq("user-1"), 1);
    assert_eq!(
        response["grant"],
        json!({"state": "revoked", "key_id": stranger.keys.key_id(), "custody": "", "not_after_ms": 0})
    );
    let record = password(&app);
    assert_eq!(
        release(&harness, &app, &record).await.1["code"],
        "grant_revoked"
    );

    // A new grant replaces the marker.
    app.grant(&harness).await;
    assert_eq!(release(&harness, &app, &record).await.0, 200);
}

#[tokio::test]
async fn commands_outside_stage_1_and_policies_are_refused() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    let attested = app.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;

    let mut with_policy: Value = serde_json::from_slice(&app::grant_payload(
        &app.keys,
        "user-1",
        &attested.node,
        &attested.challenge,
        Custody::Operator,
        not_after_ms,
    ))
    .unwrap();
    with_policy["policy"] = json!({"approve": true});
    let response = app
        .send(
            &harness,
            app.envelope(&attested, with_policy.to_string().as_bytes()),
        )
        .await;
    assert_eq!(reply(&harness, &response)["code"], "unsupported_policy");

    let stage_4 = json!({
        "v": 1, "type": "oauth_code", "user_id": "user-1", "node": attested.node,
        "challenge": attested.challenge, "sign_pk": b64u(&app.keys.sign_pk()),
        "state": "s.o", "code": "c",
    });
    let response = app
        .send(
            &harness,
            app.envelope(&attested, stage_4.to_string().as_bytes()),
        )
        .await;
    assert_eq!(reply(&harness, &response)["code"], "invalid_request");

    let mut version_2 = app.grant_envelope(&attested, not_after_ms);
    version_2["v"] = json!(2);
    let response = app.send(&harness, version_2).await;
    assert_eq!(reply(&harness, &response)["code"], "unsupported_version");

    // A command of another version inside an envelope of version 1.
    let mut command_version_2: Value = serde_json::from_slice(&app::grant_payload(
        &app.keys,
        "user-1",
        &attested.node,
        &attested.challenge,
        Custody::Operator,
        not_after_ms,
    ))
    .unwrap();
    command_version_2["v"] = json!(2);
    let response = app
        .send(
            &harness,
            app.envelope(&attested, command_version_2.to_string().as_bytes()),
        )
        .await;
    let body = reply(&harness, &response);
    assert_eq!(body["code"], "unsupported_version");
    assert_eq!(body["user_id"], "");
    assert!(harness.node.account("user-1").is_none());

    // None of these used the challenge.
    let response = app
        .send(&harness, app.grant_envelope(&attested, not_after_ms))
        .await;
    assert_eq!(reply(&harness, &response)["ok"], true);
}

#[tokio::test]
async fn a_malformed_call_and_a_closing_node_answer_with_a_failure_status() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);

    for body in [
        json!({}),
        json!({"user_id": "user-1"}),
        json!({"user_id": "", "envelope": {}}),
        json!({"user_id": "user-1", "envelope": "text"}),
        json!({"user_id": 5, "envelope": {}}),
    ] {
        let (status, failure) = harness.post("/v1/messages", body.clone()).await;
        assert_eq!(
            (status, failure["code"].as_str()),
            (400, Some("invalid_request")),
            "{body}"
        );
    }

    let attested = app.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let envelope = app.grant_envelope(&attested, not_after_ms);
    assert_eq!(harness.post("/v1/close", json!({})).await.0, 200);
    let (status, failure) = harness
        .post(
            "/v1/messages",
            json!({"user_id": "user-1", "envelope": envelope}),
        )
        .await;
    assert_eq!((status, failure["code"].as_str()), (503, Some("closing")));
}
