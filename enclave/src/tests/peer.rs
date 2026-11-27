//! Delegation transfer between two nodes (enclave.md 5.13, protocol.md 10.1 and 10.3):
//! `peer/export` on the node that holds the delegations and `peer/import` on the node that
//! takes them. The nodes of most of these tests run on the local platform, so their custody
//! is `operator`, and two of them are two nodes of one program: a transfer between them
//! creates no entry. What a node does with a peer of another release (the entries of the
//! transfer, the list of the peers a grant was handed to) is tested with a peer the test
//! states as accepted: which peer a node accepts is tested with the attestation documents
//! (`crate::attest`), and at the two calls with a recorded document of a real enclave.

use credential_enclave_protocol::encoding::{b64u, b64u_decode, to_json};
use credential_enclave_protocol::envelope::{
    hpke_seal, sign_transfer, transfer_aad, transfer_payload, TransferGrant,
};
use credential_enclave_protocol::keys::{key_id, Custody, NodeKeys};
use credential_enclave_protocol::release::ReleaseMeasurement;
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::{app, limits, purpose};
use serde_json::{json, Value};

use super::{quiet_provider, quiet_provider_and_log_store};
use crate::api::peer::{export_to, import_from};
use crate::attest::{Peer, Program};
use crate::platform::Measurement;
use crate::state::{lock, ActiveGrant, GrantState};
use crate::testing::{proof_case, App, Harness, Provider};

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

/// The accounts an import call names: the accounts whose grant of the transfer the node
/// holds when the call ends.
fn accounts_of(imported: &Value) -> Vec<String> {
    imported["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|user_id| user_id.as_str().unwrap().to_string())
        .collect()
}

/// Moves every delegation of `giving` to `receiving`, page by page, and returns what the
/// import calls answered: the number of grants they put in place, and the accounts they
/// named (the accounts whose grant of the transfer the receiving node holds afterwards: it
/// took the grant, or it held the grant of the same signing key already). The two nodes run
/// one program: neither call creates an entry.
async fn transfer(giving: &Harness, receiving: &Harness, limit: u64) -> (usize, Vec<String>) {
    let to = attestation(receiving).await;
    let from = attestation(giving).await;
    let mut placed = 0;
    let mut named = Vec::new();
    let mut after = String::new();
    loop {
        let (status, page) = export(giving, &to, &after, limit).await;
        assert_eq!(status, 200, "{page}");
        assert_eq!(page["logs"], json!([]));
        if !page["envelope"].is_null() {
            let (status, imported) = import(receiving, &from, &page["envelope"]).await;
            assert_eq!(status, 200, "{imported}");
            assert_eq!(imported["logs"], json!([]));
            placed += imported["imported"].as_u64().unwrap() as usize;
            named.extend(accounts_of(&imported));
        }
        after = page["next"].as_str().unwrap().to_string();
        if after.is_empty() {
            return (placed, named);
        }
    }
}

/// The release `release` with the measurement the tests state for a node of another release.
fn other_release(release: &str) -> ReleaseMeasurement {
    ReleaseMeasurement {
        release: release.to_string(),
        pcrs: [[0x11; 48], [0x22; 48], [0x33; 48]],
    }
}

/// The node of `harness` as a peer that runs the program of the release `release`, with the
/// measurement of [`other_release`].
fn peer_of(harness: &Harness, release: &str) -> Peer {
    Peer::accepted_for_tests(&harness.node.keys, Program::Release(other_release(release)))
}

/// One page of the delegations of `giving` for `peer`, a node of another release: the part
/// of `peer/export` after the peer verified by the release proofs of its measurement.
async fn export_later(
    giving: &Harness,
    peer: &Peer,
    after: &str,
    limit: usize,
) -> Result<Value, (u16, &'static str)> {
    export_to(&giving.node, peer, after, limit, None)
        .await
        .map(|exported| serde_json::to_value(&exported).unwrap())
        .map_err(|error| (error.status.as_u16(), error.code))
}

/// Takes the transfer `envelope` that `peer`, a node of another release, made for
/// `receiving`: the part of `peer/import` after the peer verified.
async fn import_earlier(
    receiving: &Harness,
    peer: &Peer,
    envelope: &Value,
) -> Result<Value, (u16, &'static str)> {
    import_from(&receiving.node, peer, envelope, None)
        .await
        .map(|imported| serde_json::to_value(&imported).unwrap())
        .map_err(|error| (error.status.as_u16(), error.code))
}

async fn grant_state(harness: &Harness, user_id: &str) -> Value {
    harness
        .post("/v1/status", json!({"user_id": user_id}))
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

/// An event without its `time_ms`, the node time of its creation.
fn without_time(mut event: Value) -> Value {
    assert!(event["time_ms"].as_u64().is_some(), "{event}");
    event.as_object_mut().unwrap().shift_remove("time_ms");
    event
}

/// The one event of the control entry that a `{"user_id", "seq"}` object of `peer/export` or
/// `peer/import` names on the node of `harness`, read from the log store stand-in and without
/// its `time_ms`.
fn logged(app: &App, harness: &Harness, provider: &Provider, log: &Value) -> Value {
    assert_eq!(log["user_id"], app.user_id.as_str());
    without_time(app.logged(harness, provider, &json!({"seq": log["seq"], "index": 0})))
}

#[tokio::test]
async fn a_delegation_moves_to_a_node_of_the_same_program_without_an_entry() {
    let provider = quiet_provider_and_log_store().await;
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    old.use_log_store().await;
    new.use_log_store().await;
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
    let written = provider.stored().len();

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
    // The two nodes run one program: the transfer has no entry on the giving node.
    assert_eq!(exported["logs"], json!([]));
    assert_eq!((old.last_seq("alice"), old.last_seq("bob")), (2, 1));

    // The new node takes them after it verified the giving node, names the accounts it took,
    // and creates no entry either. Neither call wrote to the log store.
    let from = attestation(&old).await;
    let (status, imported) = import(&new, &from, envelope).await;
    assert_eq!(status, 200, "{imported}");
    assert_eq!(
        imported,
        json!({"imported": 2, "accounts": ["alice", "bob"], "logs": []})
    );
    assert_eq!((new.last_seq("alice"), new.last_seq("bob")), (0, 0));
    assert_eq!(provider.stored().len(), written);
    assert_eq!(new.health().await["log_store"]["pending"], 0);

    // The delegation is in force on the new node, with the key, the custody and the end it
    // had, and the old node keeps its own.
    let accepted = granted["grant"]["not_after_ms"].as_u64().unwrap();
    assert_eq!(
        grant_state(&new, "alice").await,
        json!({
            "state": "active", "key_id": alice.keys.key_id(), "custody": "operator",
            "not_after_ms": accepted,
        })
    );
    assert_eq!(new.health().await["grants"], 2);
    assert_eq!(new.health().await["accounts"], 0);
    assert_eq!(old.health().await["grants"], 2);
    // The first entry of the new node for the account is the entry of its first act there.
    // The store holds the document of the new node, which says which program wrote it.
    let (status, released) = release(&new, &alice, &record).await;
    assert_eq!(status, 200);
    assert_eq!(released["value"], "hunter2");
    assert_eq!(
        released["log"],
        json!({"seq": 1, "index": 0, "created": true})
    );
    assert_eq!(new.health().await["accounts"], 1);
    assert_eq!(provider.chain("alice", &new.node.node).len(), 1);
    assert!(provider
        .documents()
        .iter()
        .any(|document| document.node == new.node.node));
    assert_eq!(release(&old, &alice, &record).await.0, 200);

    // The same envelope again changes nothing: the grants are there. The call puts no grant
    // in place and names the two accounts, whose grant of this transfer the node holds.
    let (status, again) = import(&new, &from, envelope).await;
    assert_eq!(
        (status, again),
        (
            200,
            json!({"imported": 0, "accounts": ["alice", "bob"], "logs": []})
        )
    );
    assert_eq!(new.last_seq("alice"), 1);

    // The provider stand-in saw no provider request: a transfer calls no provider.
    assert!(provider.requests().is_empty());
}

#[tokio::test]
async fn a_delegation_moves_to_another_release_and_both_nodes_record_it() {
    let provider = quiet_provider_and_log_store().await;
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    old.use_log_store().await;
    new.use_log_store().await;
    let alice = App::new("alice", 1);
    let bob = App::new("bob", 2);
    let granted = alice.grant(&old).await;
    bob.grant(&old).await;
    let record = alice.record("vault_password", "vault", &json!({"value": "hunter2"}));
    assert_eq!(release(&old, &alice, &record).await.0, 200);

    // The giving node hands its delegations to a node of another release. One entry per
    // account, in the store before the grant left: alice has grant, release, transfer, and
    // bob grant, transfer.
    let exported = export_later(&old, &peer_of(&new, "v9.0.0"), "", 1000)
        .await
        .unwrap();
    assert_eq!(
        exported["logs"],
        json!([{"user_id": "alice", "seq": 3}, {"user_id": "bob", "seq": 2}])
    );
    let out = provider.chain("alice", &old.node.node);
    assert_eq!(out.len(), 3);
    let body = alice.entry_body(&old, &out[2].entry);
    assert_eq!(body["seq"], 3);
    assert_eq!(body["key_id"], alice.keys.key_id().as_str());
    assert_eq!((&body["kind"], &body["count"]), (&json!("c"), &json!(1)));
    assert!(out[2].key.contains(".3.grant_transferred_out."));
    // The event names the node the key went to, and the release and the measurement of that
    // node: the account reads from its own log which program holds its key from here on.
    assert_eq!(
        logged(&alice, &old, &provider, &exported["logs"][0]),
        json!({
            "t": "grant_transferred_out", "to": new.node.node, "release": "v9.0.0",
            "pcr0": "11".repeat(48), "pcr1": "22".repeat(48), "pcr2": "33".repeat(48),
        })
    );
    assert_eq!(
        logged(&bob, &old, &provider, &exported["logs"][1])["t"],
        "grant_transferred_out"
    );
    assert_eq!((old.last_seq("alice"), old.last_seq("bob")), (3, 2));

    // The receiving node takes them from a node of another release, and writes the entries
    // of the import in one round: the store holds the first entry of each account on the new
    // node before any of them acts there.
    let envelope = &exported["envelope"];
    let imported = import_earlier(&new, &peer_of(&old, "v2.3.0"), envelope)
        .await
        .unwrap();
    assert_eq!(
        imported,
        json!({
            "imported": 2, "accounts": ["alice", "bob"],
            "logs": [{"user_id": "alice", "seq": 1}, {"user_id": "bob", "seq": 1}],
        })
    );
    assert_eq!(provider.chain("alice", &new.node.node).len(), 1);
    assert_eq!(provider.chain("bob", &new.node.node).len(), 1);
    assert_eq!(new.health().await["log_store"]["pending"], 0);
    let accepted = granted["grant"]["not_after_ms"].as_u64().unwrap();
    assert_eq!(
        logged(&alice, &new, &provider, &imported["logs"][0]),
        json!({
            "t": "grant_transferred_in", "from": old.node.node, "release": "v2.3.0",
            "not_after_ms": accepted, "custody": "operator",
        })
    );
    assert_eq!(new.health().await["grants"], 2);
    let (status, released) = release(&new, &alice, &record).await;
    assert_eq!(status, 200);
    assert_eq!(
        released["log"],
        json!({"seq": 2, "index": 0, "created": true})
    );

    // The same envelope again changes nothing: the grants are there. The call creates no
    // entry and names the two accounts, whose grant of this transfer the node holds.
    let again = import_earlier(&new, &peer_of(&old, "v2.3.0"), envelope)
        .await
        .unwrap();
    assert_eq!(
        again,
        json!({"imported": 0, "accounts": ["alice", "bob"], "logs": []})
    );
    assert_eq!(new.last_seq("alice"), 2);
}

#[tokio::test]
async fn export_pages_through_the_accounts_that_have_a_grant() {
    let provider = quiet_provider().await;
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    // a, c, e and f hold a grant. b revoked, d expired, g only revoked and has no entry.
    for (index, user_id) in ["a", "b", "c", "e", "f"].iter().enumerate() {
        App::new(user_id, index as u8 + 1).grant(&old).await;
    }
    App::new("b", 2).revoke(&old).await;
    App::new("g", 9).revoke(&old).await;
    grant_until(&App::new("d", 7), &old, old.node.now_ms() + 60_000).await;
    old.node.clock.advance(61_000);
    // The end of the grant of d is read by a status call: a grant whose time passed ends at
    // the first read of the account, or in the sweep of the node.
    assert_eq!(grant_state(&old, "d").await["state"], "expired");
    assert_eq!(old.health().await["grants"], 4);

    let to = attestation(&new).await;
    let from = attestation(&old).await;
    // A page holds `limit` grants. `next` is the last account the page looked at. The
    // receiving node names the accounts of the page it took.
    let (_, first) = export(&old, &to, "", 2).await;
    assert_eq!(first["next"], "c");
    let (_, taken) = import(&new, &from, &first["envelope"]).await;
    assert_eq!(accounts_of(&taken), ["a", "c"]);
    let (_, second) = export(&old, &to, "c", 2).await;
    // g follows f: the listing goes on, and its last page is empty.
    assert_eq!(second["next"], "f");
    let (_, taken) = import(&new, &from, &second["envelope"]).await;
    assert_eq!(accounts_of(&taken), ["e", "f"]);
    let (status, third) = export(&old, &to, "f", 2).await;
    assert_eq!(
        (status, third),
        (200, json!({"envelope": null, "logs": [], "next": ""}))
    );
    // No export created an entry: a and c have their grant, b has grant and revoke, d has
    // its grant.
    assert_eq!(
        ["a", "b", "c", "d", "g"].map(|user_id| old.last_seq(user_id)),
        [1, 2, 1, 1, 0]
    );

    // A limit above 1,000 is read as 1,000, and an absent limit and `after` are the defaults.
    let second_node = Harness::new(&provider);
    let (status, all) = export(&old, &attestation(&second_node).await, "", 5000).await;
    assert_eq!(status, 200);
    assert_eq!(all["next"], "");
    let (_, taken) = import(&second_node, &from, &all["envelope"]).await;
    assert_eq!(accounts_of(&taken), ["a", "c", "e", "f"]);
    let third_node = Harness::new(&provider);
    let to_third = attestation(&third_node).await;
    let (status, defaults) = old.post("/v1/peer/export", json!({"peer": to_third})).await;
    assert_eq!(status, 200);
    let (_, taken) = import(&third_node, &from, &defaults["envelope"]).await;
    assert_eq!(accounts_of(&taken), ["a", "c", "e", "f"]);
    for limit in [json!(0), json!(-1), json!("many"), json!(1.5)] {
        let outcome = old
            .post("/v1/peer/export", json!({"peer": to, "limit": limit}))
            .await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{limit}");
    }

    // The whole listing once more to the node that holds every grant already: the grants are
    // carried again, and the receiving node puts none in place and names the accounts of all
    // of them.
    let held = ["a", "c", "e", "f"].map(String::from).to_vec();
    assert_eq!(transfer(&old, &new, 3).await, (0, held));
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
        .map(|user_id| new.last_seq(user_id))
        .collect();

    // Only the accounts without a grant in force and without a marker were taken: two
    // grants. The answer names them and the two accounts that had the grant of the same
    // signing key here already, and neither the account that revoked here nor the account
    // whose grant here is of another key.
    let named = ["expired", "fresh", "longer", "shorter"].map(String::from);
    assert_eq!(transfer(&old, &new, 1000).await, (2, named.to_vec()));

    // No grant here: taken.
    assert_eq!(grant_state(&new, "fresh").await["state"], "active");
    assert_eq!(end_of(&new, "fresh").await, end_of(&old, "fresh").await);
    // An expired grant is no grant: taken.
    assert_eq!(grant_state(&new, "expired").await["state"], "active");
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
    // The same signing key: the later end stays.
    assert_eq!(end_of(&new, "shorter").await, end_of(&old, "shorter").await);
    assert_eq!(end_of(&new, "longer").await, longer_end);
    let seq_after: Vec<u64> = ["revoked", "rekeyed", "shorter", "longer", "expired"]
        .iter()
        .map(|user_id| new.last_seq(user_id))
        .collect();
    // One release for `rekeyed`, and nothing else: the transfer created no entry.
    assert_eq!(
        seq_after
            .iter()
            .zip(&seq_before)
            .map(|(after, before)| after - before)
            .collect::<Vec<u64>>(),
        [0, 1, 0, 0, 0]
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
    assert_eq!(
        transfer(&old, &new, 1000).await,
        (1, vec!["user-1".to_string()])
    );
    let after = new.node.now_ms();
    assert_eq!(grant_state(&new, "user-1").await["state"], "active");
    let taken_end = end_of(&new, "user-1").await;
    assert!(taken_end < given_end);
    assert!((before + limits::GRANT_MAX_MS..=after + limits::GRANT_MAX_MS).contains(&taken_end));

    // The clock of the receiving node is ahead of the end of a grant: that grant is over
    // there and is not taken.
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    grant_until(&app, &old, old.node.now_ms() + 3_600_000).await;
    new.node.clock.advance(2 * 3_600_000);
    assert_eq!(transfer(&old, &new, 1000).await, (0, Vec::new()));
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

    let (_, exported) = export(&old, &new_response, "", 1000).await;
    let envelope = exported["envelope"].clone();
    // Neither a refused export nor the one that was made left an entry.
    assert_eq!(old.last_seq("user-1"), 1);

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
    let nothing = json!({"imported": 0, "accounts": [], "logs": []});
    let (status, again) = import(&new, &from, &envelope).await;
    assert_eq!((status, &again), (200, &nothing));
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
    let seq = new.last_seq("user-1");
    let (status, again) = import(&new, &from, &envelope).await;
    assert_eq!((status, &again), (200, &nothing));
    assert_eq!(transfer(&old, &new, 1000).await, (0, Vec::new()));
    assert_eq!(new.last_seq("user-1"), seq);
    assert_eq!(
        code(&release(&new, &app, &record).await),
        (409, "grant_expired")
    );

    // What a revoke ended, a grant command of the app brings back.
    app.grant(&new).await;
    assert_eq!(release(&new, &app, &record).await.0, 200);
}

#[tokio::test]
async fn a_repeated_export_to_another_release_carries_the_grant_again_without_an_entry() {
    let provider = quiet_provider_and_log_store().await;
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    let third = Harness::new(&provider);
    for harness in [&old, &new, &third] {
        harness.use_log_store().await;
    }
    let alice = App::new("alice", 1);
    let bob = App::new("bob", 2);
    alice.grant(&old).await;
    let to = peer_of(&new, "v9.0.0");
    let from = peer_of(&old, "v2.3.0");

    // The first transfer of the grant to the node of the other release: one entry.
    let first = export_later(&old, &to, "", 1000).await.unwrap();
    assert_eq!(first["logs"], json!([{"user_id": "alice", "seq": 2}]));
    assert_eq!(
        logged(&alice, &old, &provider, &first["logs"][0])["to"],
        new.node.node
    );
    assert_eq!(old.last_seq("alice"), 2);

    // The same call again, as often as the caller likes: the envelope carries the grant
    // again, and the node creates no entry. The response has the same shape.
    for _ in 0..5 {
        let again = export_later(&old, &to, "", 1000).await.unwrap();
        let keys: Vec<&String> = again.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["envelope", "logs", "next"]);
        assert!(again["envelope"].is_object());
        assert_eq!(again["logs"], json!([]));
        assert_eq!(again["next"], "");
    }
    assert_eq!(old.last_seq("alice"), 2);
    assert_eq!(provider.chain("alice", &old.node.node).len(), 2);

    // A transfer whose envelope was lost is made again: the envelope of a later call arrives.
    let retried = export_later(&old, &to, "", 1000).await.unwrap();
    let imported = import_earlier(&new, &from, &retried["envelope"])
        .await
        .unwrap();
    assert_eq!(imported["imported"], 1);
    assert_eq!(grant_state(&new, "alice").await["state"], "active");

    // An account that was not handed to this peer yet gets its entry, in the same call that
    // carries the other grant again.
    bob.grant(&old).await;
    let mixed = export_later(&old, &to, "", 1000).await.unwrap();
    assert_eq!(mixed["logs"], json!([{"user_id": "bob", "seq": 2}]));
    let imported = import_earlier(&new, &from, &mixed["envelope"])
        .await
        .unwrap();
    // One grant is put in place, and the answer names both accounts: the node holds the
    // grant of alice from the transfer before.
    assert_eq!(imported["imported"], 1);
    assert_eq!(accounts_of(&imported), ["alice", "bob"]);
    assert_eq!(new.health().await["grants"], 2);
    // The pages count grants, whether a grant gets an entry or not.
    let page = export_later(&old, &to, "", 1).await.unwrap();
    assert!(page["envelope"].is_object());
    assert_eq!(
        (&page["logs"], &page["next"]),
        (&json!([]), &json!("alice"))
    );
    let page = export_later(&old, &to, "alice", 1).await.unwrap();
    assert!(page["envelope"].is_object());
    assert_eq!((&page["logs"], &page["next"]), (&json!([]), &json!("")));

    // Another peer of the other release is another transfer: one entry that names it.
    let other = export_later(&old, &peer_of(&third, "v9.0.0"), "", 1000)
        .await
        .unwrap();
    assert_eq!(
        other["logs"],
        json!([{"user_id": "alice", "seq": 3}, {"user_id": "bob", "seq": 3}])
    );
    assert_eq!(
        logged(&alice, &old, &provider, &other["logs"][0])["to"],
        third.node.node
    );
    assert_eq!(old.last_seq("alice"), 3);

    // A grant command of the app for the grant in force renews it and keeps what the node
    // knows of it: the peers it was handed to. A transfer to one of them has no further entry.
    alice.grant(&old).await;
    assert_eq!(old.last_seq("alice"), 3);
    let again = export_later(&old, &to, "", 1000).await.unwrap();
    assert_eq!(again["logs"], json!([]));

    // A grant that follows a revoke is a new grant, which was handed to no node: its transfer
    // to the same peer has its entry again. Grant, two transfers, revoke, grant, transfer.
    alice.revoke(&old).await;
    alice.grant(&old).await;
    assert_eq!(old.last_seq("alice"), 5);
    let renewed = export_later(&old, &to, "", 1000).await.unwrap();
    assert_eq!(renewed["logs"], json!([{"user_id": "alice", "seq": 6}]));
    let again = export_later(&old, &to, "", 1000).await.unwrap();
    assert_eq!(again["logs"], json!([]));
    assert_eq!(old.last_seq("alice"), 6);

    // A transfer to a node of the same program creates no entry, however often it is made.
    let same = attestation(&third).await;
    for _ in 0..2 {
        let (status, page) = export(&old, &same, "", 1000).await;
        assert_eq!(status, 200);
        assert!(page["envelope"].is_object());
        assert_eq!(page["logs"], json!([]));
    }
    assert_eq!((old.last_seq("alice"), old.last_seq("bob")), (6, 3));
}

#[tokio::test]
async fn a_grant_is_handed_to_at_most_64_peers_of_another_release() {
    let provider = quiet_provider_and_log_store().await;
    let old = Harness::new(&provider);
    old.use_log_store().await;
    let alice = App::new("alice", 1);
    let bob = App::new("bob", 2);
    alice.grant(&old).await;
    assert_eq!(limits::TRANSFER_PEERS, 64);
    let later = |index: u8| {
        Peer::accepted_for_tests(
            &NodeKeys::from_random(&[index; 32], &[index.wrapping_add(100); 32]),
            Program::Release(other_release("v9.0.0")),
        )
    };

    // 64 peers: each gets the grant, with one entry of the giving node.
    for index in 0..64u8 {
        let exported = export_later(&old, &later(index), "", 1000).await.unwrap();
        assert!(exported["envelope"].is_object(), "{index}");
        assert_eq!(
            exported["logs"],
            json!([{"user_id": "alice", "seq": 2 + u64::from(index)}]),
            "{index}"
        );
    }
    assert_eq!(old.last_seq("alice"), 65);

    // A 65th peer gets nothing of this grant: the account is left out, and no entry is made.
    let late = later(64);
    for _ in 0..3 {
        let exported = export_later(&old, &late, "", 1000).await.unwrap();
        assert_eq!(exported, json!({"envelope": null, "logs": [], "next": ""}));
    }
    assert_eq!(old.last_seq("alice"), 65);
    // The peers of the list still get it again, without an entry.
    for index in [0, 63] {
        let again = export_later(&old, &later(index), "", 1000).await.unwrap();
        assert!(again["envelope"].is_object());
        assert_eq!(again["logs"], json!([]));
    }
    assert_eq!(old.last_seq("alice"), 65);

    // An account that is left out does not fill a page: the page of one grant holds the
    // grant of the next account.
    bob.grant(&old).await;
    let page = export_later(&old, &late, "", 1).await.unwrap();
    assert_eq!(page["logs"], json!([{"user_id": "bob", "seq": 2}]));
    assert_eq!(page["next"], "");

    // The list counts the entries of a grant, so it does not stop a transfer that has none:
    // a node of the same program takes the grant of both accounts.
    let same = Harness::new(&provider);
    same.use_log_store().await;
    let both = ["alice", "bob"].map(String::from).to_vec();
    assert_eq!(transfer(&old, &same, 1000).await, (2, both));
    assert_eq!(old.last_seq("alice"), 65);

    // A grant that follows a revoke starts a new list: the 65th peer gets the new grant, with
    // an entry that names it. 1 grant, 64 transfers, 1 revoke, 1 grant, 1 transfer.
    alice.revoke(&old).await;
    alice.grant(&old).await;
    let exported = export_later(&old, &late, "", 1000).await.unwrap();
    assert_eq!(exported["logs"], json!([{"user_id": "alice", "seq": 68}]));
    assert_eq!(old.last_seq("alice"), 68);
}

#[tokio::test]
async fn a_closing_node_exports_and_imports_nothing() {
    let provider = quiet_provider().await;
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    let alice = App::new("alice", 1);
    let bob = App::new("bob", 2);
    alice.grant(&old).await;
    bob.grant(&old).await;
    let to = attestation(&new).await;
    let from = attestation(&old).await;

    // The orderly shutdown: close, then hand the delegations on, page by page.
    assert_eq!(old.post("/v1/close", json!({})).await.0, 200);
    let (status, exported) = export(&old, &to, "", 1).await;
    assert_eq!(status, 200, "{exported}");
    assert_eq!(exported["next"], "alice");
    let (status, imported) = import(&new, &from, &exported["envelope"]).await;
    assert_eq!(
        (status, accounts_of(&imported)),
        (200, vec!["alice".to_string()])
    );
    let (status, exported) = export(&old, &to, "alice", 1).await;
    assert_eq!((status, &exported["next"]), (200, &json!("")));
    let (_, imported) = import(&new, &from, &exported["envelope"]).await;
    assert_eq!(accounts_of(&imported), ["bob"]);
    // The closing node created no entry and signed nothing.
    assert_eq!((old.last_seq("alice"), old.last_seq("bob")), (1, 1));

    // A closing node takes no delegation.
    assert_eq!(new.post("/v1/close", json!({})).await.0, 200);
    let other = Harness::new(&provider);
    let carol = App::new("carol", 3);
    carol.grant(&other).await;
    let (_, exported) = export(&other, &to, "", 1000).await;
    let other_response = attestation(&other).await;
    assert_eq!(
        code(&import(&new, &other_response, &exported["envelope"]).await),
        (503, "closing")
    );
    assert_eq!(grant_state(&new, "carol").await["state"], "none");
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
        lock(&account).set_grant(GrantState::Active(ActiveGrant {
            key_id: key_id(&keys.sign_pk()),
            sign_pk: keys.sign_pk(),
            log_pk: keys.log_pk(),
            custody: Custody::Operator,
            user_key: Secret::new(*keys.user_key_operator),
            not_after_ms,
            exported_to: Vec::new(),
        }));
    }
    assert_eq!(old.health().await["grants"], 1005);

    let to = attestation(&new).await;
    let from = attestation(&old).await;
    // A limit above 1,000 is read as 1,000.
    let (status, first) = export(&old, &to, "", 5000).await;
    assert_eq!(status, 200);
    assert_eq!(first["next"], "00000000-0000-4000-8000-000000000999");
    // The import call carries the envelope, the attestation response and the release proofs
    // of the giving node in a JSON body of at most 1 MiB, also with the longest proofs: a
    // statement of 16,384 bytes and an attestation of 65,536 bytes.
    let longest = json!({
        "statement": proof_case("a statement of 16,384 bytes").proofs["statement"],
        "attestation": proof_case("an attestation of 65,536 bytes").proofs["attestation"],
    });
    assert_eq!(longest["statement"].as_str().unwrap().len(), 21_846);
    assert_eq!(to_json(&longest["attestation"]).len(), 65_536);
    let body = json!({"peer": from, "envelope": first["envelope"], "release_proofs": longest});
    let length = to_json(&body).len();
    assert!(length < 1024 * 1024, "{length}");
    let (status, imported) = new.post("/v1/peer/import", body).await;
    assert_eq!((status, imported["imported"].as_u64()), (200, Some(1000)));
    assert_eq!(accounts_of(&imported).len(), 1000);

    let (_, second) = export(&old, &to, first["next"].as_str().unwrap(), 5000).await;
    assert_eq!(second["next"], "");
    let (_, imported) = import(&new, &from, &second["envelope"]).await;
    assert_eq!(imported["imported"], 5);
    assert_eq!(new.health().await["grants"], 1005);
}

/// The accounts of `user_ids` that ordinal `pod` holds under the subset, in order.
fn share(user_ids: &[&str], pods: u32, pod: u32, copies: u32) -> Vec<String> {
    user_ids
        .iter()
        .filter(|user_id| super::assign(user_id, pods, copies).contains(&pod))
        .map(|user_id| user_id.to_string())
        .collect()
}

#[tokio::test]
async fn an_export_with_a_subset_hands_over_the_share_of_the_peer_and_an_import_keeps_its_own() {
    let provider = quiet_provider().await;
    let old = Harness::new(&provider);
    let holders = ["a", "b", "c", "d", "e", "f", "g", "h"];
    for (index, user_id) in holders.iter().enumerate() {
        App::new(user_id, index as u8 + 1).grant(&old).await;
    }

    // The peer is pod 1 of 3 nodes with 2 copies per account: the page holds the accounts of
    // its share alone, and nothing else enters the envelope.
    let new = Harness::new(&provider);
    let to = attestation(&new).await;
    let from = attestation(&old).await;
    let subset = json!({"pods": 3, "pod": 1, "copies": 2});
    let expected = share(&holders, 3, 1, 2);
    assert!(
        expected.len() >= 2 && expected.len() < holders.len(),
        "{expected:?}"
    );
    let (status, exported) = old
        .post(
            "/v1/peer/export",
            json!({"peer": to, "after": "", "limit": 1000, "subset": subset}),
        )
        .await;
    assert_eq!(status, 200, "{exported}");
    assert_eq!(exported["next"], "");
    let (status, imported) = import(&new, &from, &exported["envelope"]).await;
    assert_eq!(status, 200, "{imported}");
    assert_eq!(accounts_of(&imported), expected);
    for user_id in holders {
        let in_share = expected.iter().any(|share| share == user_id);
        assert_eq!(
            grant_state(&new, user_id).await["state"],
            if in_share { "active" } else { "none" },
            "{user_id}"
        );
    }

    // The pages count the selected grants, and `next` is the last account looked at.
    let third = Harness::new(&provider);
    let to_third = attestation(&third).await;
    let (_, first) = old
        .post(
            "/v1/peer/export",
            json!({"peer": to_third, "after": "", "limit": 1, "subset": subset}),
        )
        .await;
    assert_eq!(first["next"], expected[0]);
    let (_, taken) = import(&third, &from, &first["envelope"]).await;
    assert_eq!(accounts_of(&taken), expected[..1]);
    let (_, rest) = old
        .post(
            "/v1/peer/export",
            json!({"peer": to_third, "after": expected[0], "limit": 1000, "subset": subset}),
        )
        .await;
    let (_, taken) = import(&third, &from, &rest["envelope"]).await;
    assert_eq!(accounts_of(&taken), expected[1..]);

    // A giving node without the subset rule hands every account over: the receiving node keeps
    // its own share and leaves the rest out, with no count for them.
    let fourth = Harness::new(&provider);
    let to_fourth = attestation(&fourth).await;
    let (_, everything) = export(&old, &to_fourth, "", 1000).await;
    let own = json!({"pods": 3, "pod": 2, "copies": 2});
    let expected = share(&holders, 3, 2, 2);
    let (status, imported) = fourth
        .post(
            "/v1/peer/import",
            json!({"peer": from, "envelope": everything["envelope"], "subset": own}),
        )
        .await;
    assert_eq!(status, 200, "{imported}");
    assert_eq!(accounts_of(&imported), expected);
    assert_eq!(
        imported["imported"].as_u64().unwrap() as usize,
        expected.len()
    );
    assert_eq!(fourth.health().await["grants"], expected.len());
    // The same envelope again without a subset takes the rest.
    let (_, imported) = import(&fourth, &from, &everything["envelope"]).await;
    assert_eq!(
        imported["imported"].as_u64().unwrap() as usize,
        holders.len() - expected.len()
    );

    // `copies` at or above `pods` gives every account to every node, and `null` is a call
    // without a subset.
    let fifth = Harness::new(&provider);
    let to_fifth = attestation(&fifth).await;
    let (_, all) = old
        .post(
            "/v1/peer/export",
            json!({"peer": to_fifth, "subset": {"pods": 2, "pod": 0, "copies": 2}}),
        )
        .await;
    let (_, taken) = import(&fifth, &from, &all["envelope"]).await;
    assert_eq!(accounts_of(&taken).len(), holders.len());
    let (status, none) = old
        .post("/v1/peer/export", json!({"peer": to_fifth, "subset": null}))
        .await;
    assert_eq!(status, 200);
    assert!(none["envelope"].is_object());
    // No transfer of this test created an entry: every account has its grant alone.
    assert!(holders.iter().all(|user_id| old.last_seq(user_id) == 1));
    assert!(holders.iter().all(|user_id| fourth.last_seq(user_id) == 0));

    // A subset outside its bounds is refused by both calls, and nothing changes.
    let sixth = Harness::new(&provider);
    let to_sixth = attestation(&sixth).await;
    for subset in [
        json!({"pods": 0, "pod": 0, "copies": 1}),
        json!({"pods": 3, "pod": 3, "copies": 1}),
        json!({"pods": 3, "pod": 0, "copies": 0}),
        json!({"pods": 3, "pod": 0}),
        json!("3"),
    ] {
        let outcome = old
            .post(
                "/v1/peer/export",
                json!({"peer": to_sixth, "subset": subset}),
            )
            .await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{subset}");
        let outcome = sixth
            .post(
                "/v1/peer/import",
                json!({"peer": from, "envelope": everything["envelope"], "subset": subset}),
            )
            .await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{subset}");
    }
    assert_eq!(sixth.health().await["grants"], 0);
}

/// A real attestation document of a production-mode enclave (2026-10-01), the answer to an
/// attestation call: its user data is the binding of that node, which names the release
/// `v0.0.0-diag.local` and no log store.
const RECORDED_DOCUMENT: &[u8] =
    include_bytes!("../../../protocol/tests/fixtures/nitro-attestation-document-operational.cbor");

/// The attestation response that carries the recorded document.
fn recorded_peer() -> Value {
    json!({"v": 1, "platform": "nitro", "document": b64u(RECORDED_DOCUMENT)})
}

/// A measurement of no document of these tests.
fn measurement_of_this_node() -> Measurement {
    Measurement {
        pcrs: [[0xa0; 48], [0xa1; 48], [0xa2; 48]],
    }
}

#[tokio::test]
async fn an_export_goes_to_a_node_of_another_measurement_only_under_the_release_proofs_of_it() {
    let provider = quiet_provider().await;
    // Release proofs that hold for the measurement of the recorded document and name the
    // release of its binding, and what the node of this test verifies them with.
    let case = proof_case("the proofs of the measurement of a recorded attestation document");
    let recorded = Measurement { pcrs: case.pcrs };
    let other = proof_case("proofs that hold");
    let old = Harness::measured_with(
        &provider,
        measurement_of_this_node(),
        case.trust.clone(),
        Vec::new(),
    );
    let peer = recorded_peer();

    // Without release proofs the node of another measurement is no peer, and neither with a
    // value that is no proofs, with the proofs of another measurement, or with what a node
    // of an old release asks for: an endorsement is not read.
    for body in [
        json!({"peer": peer}),
        json!({"peer": peer, "release_proofs": null}),
        json!({"peer": peer, "release_proofs": "proofs"}),
        json!({"peer": peer, "release_proofs": []}),
        json!({"peer": peer, "release_proofs": {}}),
        json!({"peer": peer, "release_proofs": {"statement": case.proofs["statement"]}}),
        json!({"peer": peer, "release_proofs": other.proofs}),
        json!({"peer": peer, "endorsement": case.proofs}),
        json!({"peer": peer, "endorsement": {"statement": case.proofs["statement"], "entry": {}}}),
    ] {
        assert_eq!(
            code(&old.post("/v1/peer/export", body.clone()).await),
            (403, "peer_unverified"),
            "{body}"
        );
    }
    // With the proofs of its measurement it is a peer of another release. A transfer to it
    // has an entry, and this node has no log store to write one to: the call ends there,
    // after the peer verified.
    let body = json!({"peer": peer, "release_proofs": case.proofs});
    assert_eq!(
        code(&old.post("/v1/peer/export", body.clone()).await),
        (503, "log_store_unavailable")
    );
    // A node whose own values do not take those proofs refuses the same call: the build
    // workflows of the source are not those of the case.
    let by_source = Harness::measured(&provider, measurement_of_this_node());
    assert_eq!(
        code(&by_source.post("/v1/peer/export", body.clone()).await),
        (403, "peer_unverified")
    );
    // A node hands nothing to an old release: a list that names the measurement of the peer
    // is the rule of `peer/import` alone.
    let listing = Harness::measured_with(
        &provider,
        measurement_of_this_node(),
        other.trust.clone(),
        vec![ReleaseMeasurement {
            release: "v0.0.0-diag.local".to_string(),
            pcrs: case.pcrs,
        }],
    );
    assert_eq!(
        code(&listing.post("/v1/peer/export", json!({"peer": peer})).await),
        (403, "peer_unverified")
    );

    // A node of the measurement of the peer is a node of the same program: the call needs no
    // proofs and reads none, creates no entry and writes nothing, also without a log store.
    let same = Harness::measured(&provider, recorded);
    for body in [
        json!({"peer": peer}),
        json!({"peer": peer, "release_proofs": "not proofs"}),
        json!({"peer": peer, "release_proofs": other.proofs}),
        json!({"peer": peer, "release_proofs": case.proofs}),
    ] {
        let (status, page) = same.post("/v1/peer/export", body.clone()).await;
        assert_eq!(
            (status, page),
            (200, json!({"envelope": null, "logs": [], "next": ""})),
            "{body}"
        );
    }
}

#[tokio::test]
async fn an_import_comes_from_a_node_of_another_measurement_under_its_release_proofs_or_the_list() {
    let provider = quiet_provider().await;
    let case = proof_case("the proofs of the measurement of a recorded attestation document");
    let other = proof_case("proofs that hold");
    let new = Harness::measured_with(
        &provider,
        measurement_of_this_node(),
        case.trust.clone(),
        Vec::new(),
    );
    let peer = recorded_peer();
    let envelope = json!({"v": 1, "from": "a", "to": "b", "enc": "", "ct": ""});

    // Without release proofs the node of another measurement is no peer, and neither with
    // the proofs of another measurement.
    for body in [
        json!({"peer": peer, "envelope": envelope}),
        json!({"peer": peer, "envelope": envelope, "release_proofs": "proofs"}),
        json!({"peer": peer, "envelope": envelope, "release_proofs": other.proofs}),
    ] {
        assert_eq!(
            code(&new.post("/v1/peer/import", body.clone()).await),
            (403, "peer_unverified"),
            "{body}"
        );
    }
    // With the proofs of its measurement the giving node is a peer of another release. This
    // node has no log store that holds its node document, and takes no user key without one:
    // the call ends there, after the peer verified.
    let body = json!({"peer": peer, "envelope": envelope, "release_proofs": case.proofs});
    assert_eq!(
        code(&new.post("/v1/peer/import", body).await),
        (503, "log_store_unavailable")
    );
    // A node that lists the release of the peer as an old release takes it without proofs,
    // and with any value in their place.
    let listing = Harness::measured_with(
        &provider,
        measurement_of_this_node(),
        other.trust.clone(),
        vec![ReleaseMeasurement {
            release: "v0.0.0-diag.local".to_string(),
            pcrs: case.pcrs,
        }],
    );
    for body in [
        json!({"peer": peer, "envelope": envelope}),
        json!({"peer": peer, "envelope": envelope, "release_proofs": "proofs"}),
    ] {
        assert_eq!(
            code(&listing.post("/v1/peer/import", body.clone()).await),
            (503, "log_store_unavailable"),
            "{body}"
        );
    }
    // The element of the list names the release of the binding of the peer: under another
    // release that measurement is listed for no node.
    let renamed = Harness::measured_with(
        &provider,
        measurement_of_this_node(),
        other.trust.clone(),
        vec![ReleaseMeasurement {
            release: "v0.0.0-diag.other".to_string(),
            pcrs: case.pcrs,
        }],
    );
    assert_eq!(
        code(
            &renamed
                .post(
                    "/v1/peer/import",
                    json!({"peer": peer, "envelope": envelope})
                )
                .await
        ),
        (403, "peer_unverified")
    );
}

#[tokio::test]
async fn a_node_of_the_local_platform_reads_no_release_proofs() {
    let provider = quiet_provider().await;
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&old).await;
    let to = attestation(&new).await;
    let from = attestation(&old).await;
    let case = proof_case("proofs that hold");

    // Two nodes of the local platform are two nodes of one program, whatever value the call
    // carries as release proofs or as the endorsement a node of an old release asks for: the
    // transfer has no entry.
    for extra in [
        json!({"release_proofs": "not proofs"}),
        json!({"release_proofs": {}}),
        json!({"release_proofs": case.proofs}),
        json!({"endorsement": "not read"}),
        json!({"release_proofs": null, "endorsement": null}),
    ] {
        let mut body = json!({"peer": to});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let (status, page) = old.post("/v1/peer/export", body.clone()).await;
        assert_eq!(status, 200, "{body}");
        assert!(page["envelope"].is_object(), "{body}");
        assert_eq!(page["logs"], json!([]));

        let mut body = json!({"peer": from, "envelope": page["envelope"]});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let (status, imported) = new.post("/v1/peer/import", body).await;
        assert_eq!(status, 200, "{imported}");
        assert_eq!(imported["accounts"], json!(["user-1"]));
        assert_eq!(imported["logs"], json!([]));
    }
    assert_eq!((old.last_seq("user-1"), new.last_seq("user-1")), (1, 0));
}
