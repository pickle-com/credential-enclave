//! Delegation transfer between two nodes (enclave.md 5.13, protocol.md 10.1): `peer/export`
//! on the node that holds the delegations and `peer/import` on the node that takes them. Both
//! nodes of these tests run on the local platform, so their custody is `operator`.

use credential_enclave_protocol::encoding::{b64u, b64u_decode, to_json, verify, Signed};
use credential_enclave_protocol::envelope::{
    hpke_seal, sign_transfer, transfer_aad, transfer_payload, TransferGrant,
};
use credential_enclave_protocol::keys::{key_id, Custody};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::{app, limits, purpose};
use serde_json::{json, Value};

use super::quiet_provider;
use crate::state::{lock, ActiveGrant, GrantState};
use crate::testing::{App, Harness};

/// The attestation response of a node, as the operator domain fetches it for the other node.
async fn attestation(harness: &Harness) -> Value {
    let (status, response) = harness
        .post("/v1/attestation", json!({"nonce": b64u(&[9u8; 32])}))
        .await;
    assert_eq!(status, 200);
    response
}

async fn export(giving: &Harness, peer: &Value, after: &str, limit: u64) -> (u16, Value) {
    giving
        .post(
            "/v1/peer/export",
            json!({"peer": peer, "after": after, "limit": limit}),
        )
        .await
}

async fn import(receiving: &Harness, peer: &Value, envelope: &Value) -> (u16, Value) {
    receiving
        .post(
            "/v1/peer/import",
            json!({"peer": peer, "envelope": envelope}),
        )
        .await
}

/// Moves every delegation of `giving` to `receiving`, page by page, and returns the entries
/// of both nodes.
async fn transfer(giving: &Harness, receiving: &Harness, limit: u64) -> (Vec<Value>, Vec<Value>) {
    let to = attestation(receiving).await;
    let from = attestation(giving).await;
    let mut out = Vec::new();
    let mut into = Vec::new();
    let mut after = String::new();
    loop {
        let (status, page) = export(giving, &to, &after, limit).await;
        assert_eq!(status, 200, "{page}");
        out.extend(page["entries"].as_array().unwrap().iter().cloned());
        if page["envelope"].is_null() {
            assert!(page["entries"].as_array().unwrap().is_empty());
        } else {
            let (status, imported) = import(receiving, &from, &page["envelope"]).await;
            assert_eq!(status, 200, "{imported}");
            assert_eq!(
                imported["imported"].as_u64().unwrap() as usize,
                imported["entries"].as_array().unwrap().len()
            );
            into.extend(imported["entries"].as_array().unwrap().iter().cloned());
        }
        after = page["next"].as_str().unwrap().to_string();
        if after.is_empty() {
            return (out, into);
        }
    }
}

async fn grant_state(harness: &Harness, user_id: &str) -> Value {
    harness
        .post(
            "/v1/status",
            json!({"user_id": user_id, "nonce": "bm9uY2U"}),
        )
        .await
        .1["grant"]
        .clone()
}

async fn release(harness: &Harness, app: &App, record: &Value) -> (u16, Value) {
    harness
        .post(
            "/v1/release",
            json!({
                "user_id": app.user_id, "record": record, "field": "password",
                "origin": "https://site.example", "context": "browser:fill",
            }),
        )
        .await
}

/// The end of the grant of an account on a node.
async fn end_of(harness: &Harness, user_id: &str) -> u64 {
    grant_state(harness, user_id).await["not_after_ms"]
        .as_u64()
        .unwrap()
}

/// Grants on a node with the given end.
async fn grant_until(app: &App, harness: &Harness, not_after_ms: u64) -> Value {
    let attested = app.attest(harness).await;
    app.send(harness, app.grant_envelope(&attested, not_after_ms))
        .await
}

fn code(outcome: &(u16, Value)) -> (u16, &str) {
    (outcome.0, outcome.1["code"].as_str().unwrap_or_default())
}

/// The `user_id` in the body of an entry. The body is readable without a key.
fn entry_user(entry: &Value) -> String {
    let body = b64u_decode(entry["body"].as_str().unwrap()).unwrap();
    serde_json::from_slice::<Value>(&body).unwrap()["user_id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn a_delegation_moves_to_a_peer_and_both_nodes_record_it() {
    let provider = quiet_provider().await;
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    let alice = App::new("alice", 1);
    let bob = App::new("bob", 2);
    let granted = alice.grant(&old).await;
    bob.grant(&old).await;
    let record = alice.record("vault_password", "vault", &json!({"value": "hunter2"}));
    assert_eq!(release(&old, &alice, &record).await.0, 200);
    assert_eq!(
        code(&release(&new, &alice, &record).await),
        (409, "grant_required")
    );
    assert_eq!(new.health().await["grants"], 0);

    // The node that holds the delegations seals them for the new node.
    let to = attestation(&new).await;
    let (status, exported) = export(&old, &to, "", 1000).await;
    assert_eq!(status, 200, "{exported}");
    assert_eq!(exported["next"], "");
    let envelope = &exported["envelope"];
    let keys: Vec<&String> = envelope.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["v", "from", "to", "enc", "ct"]);
    assert_eq!(envelope["v"], 1);
    assert_eq!(envelope["from"], old.node.node.as_str());
    assert_eq!(envelope["to"], new.node.node.as_str());
    // Nothing of the user keys is readable on the way.
    for user_key in [&alice.keys.user_key_operator, &bob.keys.user_key_operator] {
        assert!(!exported.to_string().contains(&b64u(user_key.as_slice())));
    }

    // One entry per account, on the chain of the giving node, before the grant left.
    let out = exported["entries"].as_array().unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(entry_user(&out[0]), "alice");
    assert_eq!(entry_user(&out[1]), "bob");
    // alice: grant, release, transfer.
    assert_eq!(alice.entry_body(&old, &out[0])["seq"], 3);
    assert_eq!(
        alice.entry_body(&old, &out[0])["key_id"],
        alice.keys.key_id().as_str()
    );
    let event = alice.event(&old, &out[0]);
    assert_eq!(
        event,
        json!({"t": "grant_transferred_out", "to": new.node.node})
    );
    assert_eq!(bob.entry_body(&old, &out[1])["seq"], 2);
    assert_eq!(old.head_seq("alice"), 3);

    // The new node takes them after it verified the giving node.
    let from = attestation(&old).await;
    let (status, imported) = import(&new, &from, envelope).await;
    assert_eq!(status, 200, "{imported}");
    assert_eq!(imported["imported"], 2);
    let into = imported["entries"].as_array().unwrap();
    assert_eq!(into.len(), 2);
    let accepted = granted["grant"]["not_after_ms"].as_u64().unwrap();
    assert_eq!(
        alice.event(&new, &into[0]),
        json!({
            "t": "grant_transferred_in", "from": old.node.node, "not_after_ms": accepted,
            "custody": "operator",
        })
    );
    let body = alice.entry_body(&new, &into[0]);
    assert_eq!(body["seq"], 1);
    assert_eq!(body["node"], new.node.node.as_str());
    assert_eq!(body["user_id"], "alice");
    assert_eq!(body["key_id"], alice.keys.key_id().as_str());
    // The `to` of the entry on the old node is the signing key of the new node: the account
    // verifies the entries of the new node with it, without asking anyone who that node is.
    let new_public: [u8; 32] = b64u_decode(event["to"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let carried: Signed = serde_json::from_value(into[0].clone()).unwrap();
    assert!(verify(&new_public, purpose::LOG_ENTRY, &carried).is_ok());

    // The delegation is in force on the new node, with the key, the custody and the end it
    // had, and the old node keeps its own.
    assert_eq!(
        grant_state(&new, "alice").await,
        json!({
            "state": "active", "key_id": alice.keys.key_id(), "custody": "operator",
            "not_after_ms": accepted,
        })
    );
    assert_eq!(new.health().await["grants"], 2);
    assert_eq!(new.health().await["accounts"], 2);
    assert_eq!(old.health().await["grants"], 2);
    let (status, released) = release(&new, &alice, &record).await;
    assert_eq!(status, 200);
    assert_eq!(released["value"], "hunter2");
    assert_eq!(alice.entry_body(&new, &released["entry"])["seq"], 2);
    assert_eq!(release(&old, &alice, &record).await.0, 200);

    // The same envelope again changes nothing: the grants are there.
    let (status, again) = import(&new, &from, envelope).await;
    assert_eq!(
        (status, again),
        (200, json!({"imported": 0, "entries": []}))
    );
    assert_eq!(new.head_seq("alice"), 2);

    // The provider stand-in saw nothing, and neither node has an operator configuration.
    assert!(provider.seen().is_empty());
}

#[tokio::test]
async fn export_pages_through_the_accounts_that_have_a_grant() {
    let provider = quiet_provider().await;
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    // a, c, e and f hold a grant. b revoked, d expired, g only revoked and has no chain.
    for (index, user_id) in ["a", "b", "c", "e", "f"].iter().enumerate() {
        App::new(user_id, index as u8 + 1).grant(&old).await;
    }
    App::new("b", 2).revoke(&old).await;
    App::new("g", 9).revoke(&old).await;
    grant_until(&App::new("d", 7), &old, old.node.now_ms() + 60_000).await;
    old.node.clock.advance(61_000);
    assert_eq!(old.health().await["grants"], 4);

    let to = attestation(&new).await;
    let users = |page: &Value| -> Vec<String> {
        page["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(entry_user)
            .collect()
    };
    // A page holds `limit` grants. `next` is the last account the page looked at.
    let (_, first) = export(&old, &to, "", 2).await;
    assert_eq!(users(&first), ["a", "c"]);
    assert_eq!(first["next"], "c");
    let (_, second) = export(&old, &to, "c", 2).await;
    assert_eq!(users(&second), ["e", "f"]);
    // g follows f: the listing goes on, and its last page is empty.
    assert_eq!(second["next"], "f");
    let (status, third) = export(&old, &to, "f", 2).await;
    assert_eq!(
        (status, third),
        (200, json!({"envelope": null, "entries": [], "next": ""}))
    );
    // Accounts without a grant got no entry: b has grant and revoke, d has its grant.
    assert_eq!(old.head_seq("b"), 2);
    assert_eq!(old.head_seq("d"), 1);
    assert_eq!(old.head_seq("g"), 0);

    // A limit above 1,000 is read as 1,000, and an absent limit and `after` are the defaults.
    // Each of the two listings goes to a node that was handed nothing yet, so the entries
    // name the accounts of the page.
    let to_second = attestation(&Harness::new(&provider)).await;
    let (status, all) = export(&old, &to_second, "", 5000).await;
    assert_eq!(status, 200);
    assert_eq!(users(&all), ["a", "c", "e", "f"]);
    assert_eq!(all["next"], "");
    let to_third = attestation(&Harness::new(&provider)).await;
    let (status, defaults) = old.post("/v1/peer/export", json!({"peer": to_third})).await;
    assert_eq!(status, 200);
    assert_eq!(users(&defaults), ["a", "c", "e", "f"]);
    for limit in [json!(0), json!(-1), json!("many"), json!(1.5)] {
        let outcome = old
            .post("/v1/peer/export", json!({"peer": to, "limit": limit}))
            .await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{limit}");
    }

    // The whole listing arrives on the new node, page by page. The envelopes of the first
    // pages above were never delivered, so the transfer to the new node is made again: the
    // grants are carried again, and the chains of the old node, which hold the entry of that
    // transfer already, get no further one.
    let seq: Vec<u64> = ["a", "c", "e", "f"]
        .iter()
        .map(|user_id| old.head_seq(user_id))
        .collect();
    assert_eq!(seq, [4, 4, 4, 4]);
    let (out, into) = transfer(&old, &new, 3).await;
    assert!(out.is_empty());
    assert_eq!(
        ["a", "c", "e", "f"].map(|user_id| old.head_seq(user_id)),
        [4, 4, 4, 4]
    );
    assert_eq!(
        into.iter().map(entry_user).collect::<Vec<String>>(),
        ["a", "c", "e", "f"]
    );
    assert_eq!(new.health().await["grants"], 4);
    for user_id in ["b", "d", "g"] {
        assert_eq!(
            grant_state(&new, user_id).await["state"],
            "none",
            "{user_id}"
        );
    }
}

#[tokio::test]
async fn an_import_never_replaces_what_the_app_of_the_account_put_in_place() {
    let provider = quiet_provider().await;
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    // On the old node every account has a grant of 30 days.
    let fresh = App::new("fresh", 1);
    let revoked = App::new("revoked", 2);
    let rekeyed_old = App::new("rekeyed", 3);
    let shorter = App::new("shorter", 4);
    let longer = App::new("longer", 5);
    let expired = App::new("expired", 6);
    for app in [&fresh, &revoked, &rekeyed_old, &shorter, &longer, &expired] {
        app.grant(&old).await;
    }
    // On the new node:
    // - `revoked` withdrew its delegation,
    revoked.revoke(&new).await;
    // - `rekeyed` granted with a new master key (after a key reset),
    let rekeyed_new = App::new("rekeyed", 33);
    rekeyed_new.grant(&new).await;
    // - `shorter` has the same key with an end in one hour,
    grant_until(&shorter, &new, new.node.now_ms() + 3_600_000).await;
    // - `expired` has the same key with an end that passed,
    grant_until(&expired, &new, new.node.now_ms() + 60_000).await;
    // - `longer` granted on the new node two minutes after the old one: its end here is the
    //   later one. The two minutes also end the grant of `expired`.
    new.node.clock.advance(120_000);
    grant_until(&longer, &new, new.node.now_ms() + limits::GRANT_MAX_MS).await;
    let longer_end = end_of(&new, "longer").await;
    assert!(longer_end > end_of(&old, "longer").await);
    assert_eq!(grant_state(&new, "expired").await["state"], "expired");
    let seq_before: Vec<u64> = ["revoked", "rekeyed", "shorter", "longer", "expired"]
        .iter()
        .map(|user_id| new.head_seq(user_id))
        .collect();

    let (out, into) = transfer(&old, &new, 1000).await;
    assert_eq!(out.len(), 6);
    // Only the accounts without a grant in force and without a marker got an entry.
    assert_eq!(
        into.iter().map(entry_user).collect::<Vec<String>>(),
        ["expired", "fresh"]
    );

    // No grant here: taken.
    assert_eq!(grant_state(&new, "fresh").await["state"], "active");
    assert_eq!(end_of(&new, "fresh").await, end_of(&old, "fresh").await);
    // An expired grant is no grant: taken, with an entry after the entry of the old grant.
    assert_eq!(grant_state(&new, "expired").await["state"], "active");
    assert_eq!(expired.event(&new, &into[0])["t"], "grant_transferred_in");
    assert_eq!(expired.entry_body(&new, &into[0])["seq"], 2);
    // A revocation marker stays.
    assert_eq!(
        grant_state(&new, "revoked").await,
        json!({"state": "revoked", "key_id": revoked.keys.key_id(), "custody": "", "not_after_ms": 0})
    );
    // A grant of another signing key stays: the transfer does not bring the old key back.
    assert_eq!(
        grant_state(&new, "rekeyed").await["key_id"],
        rekeyed_new.keys.key_id().as_str()
    );
    let new_record = rekeyed_new.record("vault_password", "vault", &json!({"value": "new"}));
    assert_eq!(release(&new, &rekeyed_new, &new_record).await.0, 200);
    let old_record = rekeyed_old.record("vault_password", "vault", &json!({"value": "old"}));
    assert_eq!(
        code(&release(&new, &rekeyed_old, &old_record).await),
        (409, "key_mismatch")
    );
    // The same signing key: the later end stays, without an entry.
    assert_eq!(end_of(&new, "shorter").await, end_of(&old, "shorter").await);
    assert_eq!(end_of(&new, "longer").await, longer_end);
    let seq_after: Vec<u64> = ["revoked", "rekeyed", "shorter", "longer", "expired"]
        .iter()
        .map(|user_id| new.head_seq(user_id))
        .collect();
    // One release for `rekeyed`, one entry for `expired`, nothing else.
    assert_eq!(
        seq_after
            .iter()
            .zip(&seq_before)
            .map(|(after, before)| after - before)
            .collect::<Vec<u64>>(),
        [0, 1, 0, 0, 1]
    );
}

#[tokio::test]
async fn an_import_reads_the_end_of_a_grant_against_its_own_clock() {
    let provider = quiet_provider().await;

    // The clock of the giving node is 10 days ahead: the end it accepted lies 40 days from the
    // time of the receiving node, which takes it with the end at its own 30 days.
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    old.node.clock.advance(10 * 86_400_000);
    let app = App::new("user-1", 1);
    let granted = app.grant(&old).await;
    let given_end = granted["grant"]["not_after_ms"].as_u64().unwrap();
    let before = new.node.now_ms();
    let (_, into) = transfer(&old, &new, 1000).await;
    let after = new.node.now_ms();
    assert_eq!(into.len(), 1);
    let taken_end = app.event(&new, &into[0])["not_after_ms"].as_u64().unwrap();
    assert!(taken_end < given_end);
    assert!((before + limits::GRANT_MAX_MS..=after + limits::GRANT_MAX_MS).contains(&taken_end));
    assert_eq!(grant_state(&new, "user-1").await["not_after_ms"], taken_end);

    // The clock of the receiving node is ahead of the end of a grant: that grant is over
    // there and is not taken.
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    grant_until(&app, &old, old.node.now_ms() + 3_600_000).await;
    new.node.clock.advance(2 * 3_600_000);
    let (out, into) = transfer(&old, &new, 1000).await;
    assert_eq!((out.len(), into.len()), (1, 0));
    assert_eq!(grant_state(&new, "user-1").await["state"], "none");
    assert!(new.node.account("user-1").is_none());
}

#[tokio::test]
async fn a_transfer_is_bound_to_the_two_nodes_that_verified_each_other() {
    let provider = quiet_provider().await;
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    let third = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&old).await;
    let old_response = attestation(&old).await;
    let new_response = attestation(&new).await;
    let third_response = attestation(&third).await;

    // A node does not export to itself.
    assert_eq!(
        code(&export(&old, &old_response, "", 1000).await),
        (400, "invalid_request")
    );
    // A peer that is not verified: another platform, a document that is not a document, a
    // binding of another version, a response of another version.
    let changed = |change: fn(&mut Value)| {
        let mut response = new_response.clone();
        change(&mut response);
        response
    };
    for peer in [
        changed(|response| response["platform"] = json!("nitro")),
        changed(|response| response["document"] = json!(b64u(b"not a document"))),
        changed(|response| response["document"] = json!("not base64url!")),
        changed(|response| response["v"] = json!(2)),
        // The binding of the node with another version and everything else in place.
        changed(|response| {
            let mut document: Value = serde_json::from_slice(
                &b64u_decode(response["document"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            let mut binding: Value = serde_json::from_slice(
                &b64u_decode(document["binding"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            binding["v"] = json!(2);
            document["binding"] = json!(b64u(&to_json(&binding)));
            response["document"] = json!(b64u(&to_json(&document)));
        }),
        json!({}),
    ] {
        assert_eq!(
            code(&export(&old, &peer, "", 1000).await),
            (403, "peer_unverified"),
            "{peer}"
        );
        assert_eq!(
            code(
                &import(
                    &new,
                    &peer,
                    &json!({"v": 1, "from": "", "to": "", "enc": "", "ct": ""})
                )
                .await
            ),
            (403, "peer_unverified"),
            "{peer}"
        );
    }
    // A call without a peer or without an envelope.
    for body in [json!({}), json!({"peer": "text"}), json!({"peer": []})] {
        assert_eq!(
            code(&old.post("/v1/peer/export", body.clone()).await),
            (400, "invalid_request"),
            "{body}"
        );
        assert_eq!(
            code(&new.post("/v1/peer/import", body.clone()).await),
            (400, "invalid_request"),
            "{body}"
        );
    }
    assert_eq!(
        code(
            &new.post("/v1/peer/import", json!({"peer": old_response}))
                .await
        ),
        (400, "invalid_request")
    );
    // No refused export left an entry.
    assert_eq!(old.head_seq("user-1"), 1);

    let (_, exported) = export(&old, &new_response, "", 1000).await;
    let envelope = exported["envelope"].clone();
    assert_eq!(old.head_seq("user-1"), 2);

    // The envelope was made for `new`: another node does not take it.
    assert_eq!(
        code(&import(&third, &old_response, &envelope).await),
        (400, "wrong_node")
    );
    // The receiver expects it from the node whose attestation the call carries.
    assert_eq!(
        code(&import(&new, &third_response, &envelope).await),
        (400, "wrong_node")
    );
    // A changed envelope.
    let mut tampered = envelope.clone();
    let mut ct = b64u_decode(tampered["ct"].as_str().unwrap()).unwrap();
    ct[10] ^= 1;
    tampered["ct"] = json!(b64u(&ct));
    assert_eq!(
        code(&import(&new, &old_response, &tampered).await),
        (400, "open_failed")
    );
    let mut renamed = envelope.clone();
    renamed["from"] = json!(third.node.node);
    assert_eq!(
        code(&import(&new, &third_response, &renamed).await),
        (400, "open_failed")
    );
    let mut version_2 = envelope.clone();
    version_2["v"] = json!(2);
    assert_eq!(
        code(&import(&new, &old_response, &version_2).await),
        (400, "unsupported_version")
    );
    let mut incomplete = envelope.clone();
    incomplete.as_object_mut().unwrap().remove("enc");
    assert_eq!(
        code(&import(&new, &old_response, &incomplete).await),
        (400, "invalid_request")
    );

    // A transfer that someone else signed and sealed to the new node under the name of the
    // old node. The sealing key of a node is public, its signing key is not.
    let forger = app::derive_account_keys(&[0x61; 32]).sign;
    let stolen = App::new("user-1", 99);
    let grants = [TransferGrant {
        user_id: "user-1".to_string(),
        sign_pk: stolen.keys.sign_pk(),
        log_pk: stolen.keys.log_pk(),
        custody: Custody::Operator,
        user_key: Secret::new([0x63; 32]),
        not_after_ms: new.node.now_ms() + 3_600_000,
    }];
    let payload = transfer_payload(&old.node.node, &new.node.node, new.node.now_ms(), &grants);
    let (enc, ct) = hpke_seal(
        &new.node.keys.seal_public(),
        purpose::PEER_SEAL.as_bytes(),
        &transfer_aad(&old.node.node, &new.node.node),
        &sign_transfer(&forger, payload.expose_secret()),
        &[0x64; 32],
    )
    .unwrap();
    let forged = json!({
        "v": 1, "from": old.node.node, "to": new.node.node, "enc": b64u(&enc), "ct": b64u(&ct),
    });
    assert_eq!(
        code(&import(&new, &old_response, &forged).await),
        (400, "bad_signature")
    );

    // None of the refused imports changed the new node.
    assert_eq!(new.health().await["grants"], 0);
    assert!(new.node.account("user-1").is_none());
    assert!(third.node.account("user-1").is_none());

    // The untouched envelope still arrives.
    let (status, imported) = import(&new, &old_response, &envelope).await;
    assert_eq!((status, imported["imported"].as_u64()), (200, Some(1)));
}

#[tokio::test]
async fn a_revoke_on_a_node_is_not_undone_by_a_transfer() {
    let provider = quiet_provider().await;
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&old).await;
    let record = app.record("vault_password", "vault", &json!({"value": "hunter2"}));

    // The delegation moved to the new node. Whoever carried the envelope of that transfer
    // can keep it.
    let to = attestation(&new).await;
    let from = attestation(&old).await;
    let (_, exported) = export(&old, &to, "", 1000).await;
    let envelope = exported["envelope"].clone();
    let (_, imported) = import(&new, &from, &envelope).await;
    assert_eq!(imported["imported"], 1);
    assert_eq!(release(&new, &app, &record).await.0, 200);

    // The account revokes on the new node. The kept envelope does not bring the delegation
    // back.
    app.revoke(&new).await;
    assert_eq!(
        code(&release(&new, &app, &record).await),
        (409, "grant_revoked")
    );
    let (status, again) = import(&new, &from, &envelope).await;
    assert_eq!(
        (status, again),
        (200, json!({"imported": 0, "entries": []}))
    );
    assert_eq!(grant_state(&new, "user-1").await["state"], "revoked");

    // A grant of a foreign key for the same user id replaces the revocation marker (a node
    // knows no account registration: protocol.md 5.2), and it ends at once.
    let foreign = App::new("user-1", 66);
    grant_until(&foreign, &new, new.node.now_ms() + 1_000).await;
    assert_eq!(
        grant_state(&new, "user-1").await["key_id"],
        foreign.keys.key_id().as_str()
    );
    new.node.clock.advance(2_000);
    assert_eq!(grant_state(&new, "user-1").await["state"], "expired");
    // The marker is gone, and the account still revoked here: neither the kept envelope nor
    // a new transfer from the old node, which still holds the delegation, is taken.
    let seq = new.head_seq("user-1");
    let (status, again) = import(&new, &from, &envelope).await;
    assert_eq!(
        (status, again),
        (200, json!({"imported": 0, "entries": []}))
    );
    // The old node hands the grant to the new node once more. Its chain holds the entry of
    // that transfer already, and the new node takes nothing.
    let (out, into) = transfer(&old, &new, 1000).await;
    assert_eq!((out.len(), into.len()), (0, 0));
    assert_eq!(new.head_seq("user-1"), seq);
    assert_eq!(
        code(&release(&new, &app, &record).await),
        (409, "grant_expired")
    );

    // What a revoke ended, a grant command of the app brings back.
    app.grant(&new).await;
    assert_eq!(release(&new, &app, &record).await.0, 200);
}

#[tokio::test]
async fn a_repeated_export_to_the_same_peer_carries_the_grant_again_without_an_entry() {
    let provider = quiet_provider().await;
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    let third = Harness::new(&provider);
    let alice = App::new("alice", 1);
    let bob = App::new("bob", 2);
    alice.grant(&old).await;
    let to = attestation(&new).await;
    let from = attestation(&old).await;

    // The first transfer of the grant to the new node: one entry.
    let (status, first) = export(&old, &to, "", 1000).await;
    assert_eq!(status, 200);
    assert_eq!(first["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        alice.event(&old, &first["entries"][0]),
        json!({"t": "grant_transferred_out", "to": new.node.node})
    );
    assert_eq!(old.head_seq("alice"), 2);

    // The same call again, as often as the caller likes: the envelope carries the grant
    // again, and the chain does not grow. The response has the same shape.
    for _ in 0..5 {
        let (status, again) = export(&old, &to, "", 1000).await;
        assert_eq!(status, 200);
        let keys: Vec<&String> = again.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["envelope", "entries", "next"]);
        assert!(again["envelope"].is_object());
        assert_eq!(again["entries"], json!([]));
        assert_eq!(again["next"], "");
    }
    assert_eq!(old.head_seq("alice"), 2);
    let (_, listed) = old
        .post(
            "/v1/log/entries",
            json!({"user_id": "alice", "after_seq": 0}),
        )
        .await;
    assert_eq!(listed["entries"].as_array().unwrap().len(), 2);

    // A transfer whose envelope was lost is made again: the envelope of a later call arrives.
    let (_, retried) = export(&old, &to, "", 1000).await;
    let (status, imported) = import(&new, &from, &retried["envelope"]).await;
    assert_eq!((status, imported["imported"].as_u64()), (200, Some(1)));
    assert_eq!(grant_state(&new, "alice").await["state"], "active");

    // An account that was not handed to this peer yet gets its entry, in the same call that
    // carries the other grant again.
    bob.grant(&old).await;
    let (_, mixed) = export(&old, &to, "", 1000).await;
    let entries = mixed["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entry_user(&entries[0]), "bob");
    let (_, imported) = import(&new, &from, &mixed["envelope"]).await;
    assert_eq!(imported["imported"], 1);
    assert_eq!(new.health().await["grants"], 2);
    // A grant that a node took from a transfer was handed on by that node to no one yet: the
    // node that took the two grants hands them on with entries on its own chains.
    let to_third = attestation(&third).await;
    let (_, onward) = export(&new, &to_third, "", 1000).await;
    assert_eq!(onward["entries"].as_array().unwrap().len(), 2);
    let (_, onward) = export(&new, &to_third, "", 1000).await;
    assert_eq!(onward["entries"], json!([]));
    // The pages count grants, whether a grant gets an entry or not.
    let (_, page) = export(&old, &to, "", 1).await;
    assert!(page["envelope"].is_object());
    assert_eq!(
        (&page["entries"], &page["next"]),
        (&json!([]), &json!("alice"))
    );
    let (_, page) = export(&old, &to, "alice", 1).await;
    assert!(page["envelope"].is_object());
    assert_eq!((&page["entries"], &page["next"]), (&json!([]), &json!("")));

    // Another peer is another transfer: one entry that names it.
    let (_, other) = export(&old, &to_third, "", 1000).await;
    let entries = other["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        alice.event(&old, &entries[0]),
        json!({"t": "grant_transferred_out", "to": third.node.node})
    );
    assert_eq!(old.head_seq("alice"), 3);
    let (_, again) = export(&old, &to_third, "", 1000).await;
    assert_eq!(again["entries"], json!([]));

    // A new grant command of the app puts a new grant in place, which was handed to no node:
    // its transfer to the same peer has its entry again.
    alice.grant(&old).await;
    assert_eq!(old.head_seq("alice"), 4);
    let (_, renewed) = export(&old, &to, "", 1000).await;
    let entries = renewed["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entry_user(&entries[0]), "alice");
    assert_eq!(old.head_seq("alice"), 5);
    let (_, again) = export(&old, &to, "", 1000).await;
    assert_eq!(again["entries"], json!([]));
    assert_eq!(old.head_seq("alice"), 5);
}

#[tokio::test]
async fn a_grant_is_handed_to_at_most_64_peers() {
    let provider = quiet_provider().await;
    let old = Harness::new(&provider);
    let alice = App::new("alice", 1);
    let bob = App::new("bob", 2);
    alice.grant(&old).await;
    assert_eq!(limits::TRANSFER_PEERS, 64);

    // 64 peers: each gets the grant, with one entry on the chain of the giving node.
    let mut peers = Vec::new();
    for index in 0..64u64 {
        let to = attestation(&Harness::new(&provider)).await;
        let (status, exported) = export(&old, &to, "", 1000).await;
        assert_eq!(status, 200);
        assert!(exported["envelope"].is_object(), "{index}");
        assert_eq!(exported["entries"].as_array().unwrap().len(), 1, "{index}");
        assert_eq!(old.head_seq("alice"), 2 + index);
        peers.push(to);
    }
    assert_eq!(old.head_seq("alice"), 65);

    // A 65th peer gets nothing of this grant: the account is left out, and no entry is made.
    let late = Harness::new(&provider);
    let to_late = attestation(&late).await;
    for _ in 0..3 {
        let (status, exported) = export(&old, &to_late, "", 1000).await;
        assert_eq!(
            (status, exported),
            (200, json!({"envelope": null, "entries": [], "next": ""}))
        );
    }
    assert_eq!(old.head_seq("alice"), 65);
    // The peers of the list still get it again, without an entry.
    for to in [&peers[0], &peers[63]] {
        let (_, again) = export(&old, to, "", 1000).await;
        assert!(again["envelope"].is_object());
        assert_eq!(again["entries"], json!([]));
    }
    assert_eq!(old.head_seq("alice"), 65);

    // An account that is left out does not fill a page: the page of one grant holds the
    // grant of the next account.
    bob.grant(&old).await;
    let (_, page) = export(&old, &to_late, "", 1).await;
    let entries = page["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entry_user(&entries[0]), "bob");
    assert_eq!(page["next"], "");
    let from = attestation(&old).await;
    let (_, imported) = import(&late, &from, &page["envelope"]).await;
    assert_eq!(imported["imported"], 1);
    assert_eq!(grant_state(&late, "alice").await["state"], "none");
    assert_eq!(grant_state(&late, "bob").await["state"], "active");

    // A new grant command of the app starts a new list: the 65th peer gets the new grant.
    alice.grant(&old).await;
    let (_, exported) = export(&old, &to_late, "", 1000).await;
    let entries = exported["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        alice.event(&old, &entries[0]),
        json!({"t": "grant_transferred_out", "to": late.node.node})
    );
    // 1 grant, 64 transfers, 1 grant, 1 transfer.
    assert_eq!(old.head_seq("alice"), 67);
}

#[tokio::test]
async fn a_closing_node_exports_until_its_final_heads_and_imports_nothing() {
    let provider = quiet_provider().await;
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    let alice = App::new("alice", 1);
    let bob = App::new("bob", 2);
    alice.grant(&old).await;
    bob.grant(&old).await;
    let to = attestation(&new).await;
    let from = attestation(&old).await;

    // The orderly shutdown: close, then hand the delegations on.
    assert_eq!(old.post("/v1/close", json!({})).await.0, 200);
    let (status, exported) = export(&old, &to, "", 1).await;
    assert_eq!(status, 200, "{exported}");
    assert_eq!(exported["next"], "alice");
    assert_eq!(
        alice.event(&old, &exported["entries"][0])["t"],
        "grant_transferred_out"
    );
    let (status, imported) = import(&new, &from, &exported["envelope"]).await;
    assert_eq!((status, imported["imported"].as_u64()), (200, Some(1)));

    // The final heads are signed: no entry follows them, so the accounts that were not yet
    // handed on stay where they are. Their apps delegate again at their next sync.
    let (status, heads) = old
        .post("/v1/close/heads", json!({"cursor": "", "limit": 1000}))
        .await;
    assert_eq!(status, 200);
    let finals: Vec<Value> = heads["heads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|head| old.verified(purpose::HEAD, head))
        .collect();
    assert_eq!(
        finals
            .iter()
            .map(|head| (
                head["user_id"].as_str().unwrap(),
                head["seq"].as_u64().unwrap()
            ))
            .collect::<Vec<(&str, u64)>>(),
        [("alice", 2), ("bob", 1)]
    );
    let (status, late) = export(&old, &to, "alice", 1).await;
    assert_eq!(
        (status, late),
        (200, json!({"envelope": null, "entries": [], "next": ""}))
    );
    assert_eq!(old.head_seq("bob"), 1);
    assert_eq!(old.head_seq("alice"), 2);

    // A closing node takes no delegation.
    assert_eq!(new.post("/v1/close", json!({})).await.0, 200);
    let other = Harness::new(&provider);
    bob.grant(&other).await;
    let (_, exported) = export(&other, &to, "", 1000).await;
    let other_response = attestation(&other).await;
    assert_eq!(
        code(&import(&new, &other_response, &exported["envelope"]).await),
        (503, "closing")
    );
    assert_eq!(grant_state(&new, "bob").await["state"], "none");
}

#[tokio::test]
async fn a_full_page_of_1000_grants_fits_one_import_call() {
    let provider = quiet_provider().await;
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    // 1,005 accounts with a grant, put in place directly: a grant command for each of them
    // would only slow this test down. The user ids have the length of a UUID.
    let keys = app::derive_account_keys(&[0x21; 32]);
    let not_after_ms = old.node.now_ms() + limits::GRANT_MAX_MS;
    for index in 0..1005 {
        let user_id = format!("00000000-0000-4000-8000-{index:012}");
        let account = old.node.account_or_create(&user_id);
        lock(&account).grant = GrantState::Active(ActiveGrant {
            key_id: key_id(&keys.sign_pk()),
            sign_pk: keys.sign_pk(),
            log_pk: keys.log_pk(),
            custody: Custody::Operator,
            user_key: Secret::new(*keys.user_key_operator),
            not_after_ms,
            exported_to: Vec::new(),
        });
    }
    assert_eq!(old.health().await["grants"], 1005);

    let to = attestation(&new).await;
    let from = attestation(&old).await;
    // A limit above 1,000 is read as 1,000.
    let (status, first) = export(&old, &to, "", 5000).await;
    assert_eq!(status, 200);
    assert_eq!(first["entries"].as_array().unwrap().len(), 1000);
    assert_eq!(first["next"], "00000000-0000-4000-8000-000000000999");
    // The import call carries the envelope and the attestation response in a JSON body of at
    // most 1 MiB.
    let body = to_json(&json!({"peer": from, "envelope": first["envelope"]}));
    assert!(body.len() < 1024 * 1024, "{}", body.len());
    let (status, imported) = import(&new, &from, &first["envelope"]).await;
    assert_eq!((status, imported["imported"].as_u64()), (200, Some(1000)));

    let (_, second) = export(&old, &to, first["next"].as_str().unwrap(), 5000).await;
    assert_eq!(second["entries"].as_array().unwrap().len(), 5);
    assert_eq!(second["next"], "");
    let (_, imported) = import(&new, &from, &second["envelope"]).await;
    assert_eq!(imported["imported"], 5);
    assert_eq!(new.health().await["grants"], 1005);
}
