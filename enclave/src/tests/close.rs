//! The final head of the orderly shutdown (enclave.md 5.11, protocol.md 7.3): it stands at the
//! last entry the log store confirmed. Pending entries that are the tail of a chain and that the
//! store is known not to hold are dropped and the head moves below them; an entry the store may
//! hold (a request that left and got no answer, a 5xx answer, a call that ended while the store
//! held its request) and a confirmed entry above a pending one leave the account without a head
//! until the store confirms the entry or the gap closes.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use credential_enclave_protocol::app::verify_index;
use credential_enclave_protocol::encoding::{b64u, Signed};
use credential_enclave_protocol::log::{EntryParts, Head};
use credential_enclave_protocol::purpose;
use serde_json::{json, Value};

use super::provider_and_log_store;
use crate::state::{lock, Limits};
use crate::testing::{App, Harness, Provider, Reply};

/// What the log store stand-in does with a write: it refuses every write with `status` when
/// `status` is not 0, and the writes of the entry `seq` alone (with `status`, or 403 when
/// `status` is 0) when `seq` is set; it reads `lost` writes and closes the connection without a
/// response; it reads every write without answering while `hang` is set. `confirmed` holds the
/// request targets of the writes it answered with 200: the objects the store holds (a write
/// refused with a 4xx status stores nothing; a write answered with a 5xx status, a lost write and
/// a hanging write may or may not have been stored, as far as the node can tell).
#[derive(Default)]
struct Refusal {
    status: u16,
    seq: Option<u64>,
    lost: usize,
    hang: bool,
    confirmed: Vec<String>,
}

type Store = Arc<Mutex<Refusal>>;

/// A stand-in for the providers and for the log store. The store confirms a write unless the
/// refusal says otherwise.
async fn refusing_store() -> (Provider, Store) {
    let store: Store = Arc::default();
    let script = store.clone();
    let provider = provider_and_log_store(
        |_| Reply::json(200, &json!({"ok": true})),
        move |seen| {
            let mut refusal = lock(&script);
            if refusal.lost > 0 {
                refusal.lost -= 1;
                return Reply::Raw(Vec::new());
            }
            if refusal.hang {
                return Reply::Hang;
            }
            let of_seq = refusal
                .seq
                .is_some_and(|seq| seen.target.contains(&format!("/{seq:020}-")));
            let refused = of_seq || (refusal.seq.is_none() && refusal.status != 0);
            match refused {
                true => Reply::with_body(
                    match refusal.status {
                        0 => 403,
                        status => status,
                    },
                    &[],
                    b"<Error></Error>",
                ),
                false => {
                    refusal.confirmed.push(seen.target.clone());
                    Reply::with_body(200, &[("etag", "\"0\"")], b"")
                }
            }
        },
    )
    .await;
    (provider, store)
}

/// A node with the log store of the tests whose writes are not repeated (a time limit below
/// the margin of a repeated attempt), and the app of an account that granted on it.
async fn node_with_log_store(provider: &Provider) -> (Harness, App) {
    let limits = Limits {
        log_write: Duration::from_millis(450),
        ..Limits::default()
    };
    let harness = Harness::with(provider, crate::providers::Definitions::embedded(), limits);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    (harness, app)
}

async fn release(harness: &Harness, app: &App) -> (u16, Value) {
    let record = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
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

async fn heads(harness: &Harness) -> Value {
    let (status, page) = harness
        .post("/v1/close/heads", json!({"cursor": "", "limit": 1000}))
        .await;
    assert_eq!(status, 200, "{page}");
    page
}

/// The parts of the keys of the chain of `user_id` that the store holds, in `seq` order: the
/// writes the stand-in confirmed. A refused write is a request the stand-in saw and no object.
fn keys_of(
    provider: &Provider,
    store: &Store,
    harness: &Harness,
    user_id: &str,
) -> Vec<EntryParts> {
    let confirmed = lock(store).confirmed.clone();
    provider
        .chain(user_id, &harness.node.node)
        .iter()
        .filter(|stored| confirmed.contains(&format!("/{}", stored.key)))
        .map(|stored| stored.parts().clone())
        .collect()
}

/// The end of the chain that the keys of the store and the final head give, verified by the
/// rule of the app.
fn verified_end(
    provider: &Provider,
    store: &Store,
    harness: &Harness,
    user_id: &str,
    head: &Value,
) -> Head {
    let signed: Signed = serde_json::from_value(head.clone()).unwrap();
    verify_index(
        &harness.node_public(),
        user_id,
        &Head::EMPTY,
        &keys_of(provider, store, harness, user_id),
        &signed,
        None,
    )
    .unwrap()
}

#[tokio::test]
async fn a_pending_tail_is_dropped_and_the_final_head_stands_at_the_last_confirmed_entry() {
    let (provider, store) = refusing_store().await;
    let (harness, app) = node_with_log_store(&provider).await;
    // Entry 1 (the grant) and entry 2 (a release) are in the store. Then the store refuses
    // with a 4xx status (the object is known not to be there): two releases fail and leave
    // entries 3 and 4 pending.
    assert_eq!(release(&harness, &app).await.0, 200);
    lock(&store).status = 403;
    for _ in 0..2 {
        assert_eq!(
            release(&harness, &app).await.1["code"],
            "log_store_unavailable"
        );
    }
    assert_eq!(harness.head_seq("user-1"), 4);
    let health = harness.health().await;
    assert_eq!(health["log_store"]["pending"], 1);
    assert_eq!(health["state"]["pending_entries"], 2);
    let hash_of_2 = b64u(&keys_of(&provider, &store, &harness, "user-1")[1].entry_hash);

    // The orderly shutdown while the store still refuses: the write round of the page fails,
    // the two pending entries are the tail of the chain, and the final head is signed at
    // entry 2, the last entry the store confirmed. The tail is gone from the chain and from
    // the entries the store has not confirmed.
    assert_eq!(harness.post("/v1/close", json!({})).await.0, 200);
    let page = heads(&harness).await;
    assert_eq!(
        (&page["truncated"], &page["skipped"]),
        (&json!(1), &json!(0))
    );
    assert_eq!(page["next"], "");
    let head = harness.verified(purpose::HEAD, &page["heads"][0]);
    assert_eq!(head["user_id"], "user-1");
    assert_eq!((&head["seq"], &head["final"]), (&json!(2), &json!(true)));
    assert_eq!(head["hash"], hash_of_2);
    assert_eq!(harness.head_seq("user-1"), 2);
    let account = harness.node.account("user-1").unwrap();
    assert!(lock(&account).unconfirmed().is_empty());
    let health = harness.health().await;
    assert_eq!(health["accounts"], 1);
    assert_eq!(health["log_store"]["pending"], 0);
    assert_eq!(health["state"]["pending_entries"], 0);

    // The store takes writes again. The round of a repeated call has no entry left to write
    // (the sweep ended with `close`, and the rounds of `close/heads` are the writer after it):
    // the store holds entries 1 and 2 and nothing above the head, and the keys of the store
    // reach the hash of the final head.
    lock(&store).status = 0;
    let writes = provider.stored().len();
    heads(&harness).await;
    assert_eq!(provider.stored().len(), writes);
    assert_eq!(keys_of(&provider, &store, &harness, "user-1").len(), 2);
    let end = verified_end(&provider, &store, &harness, "user-1", &page["heads"][0]);
    assert_eq!(end.seq, 2);

    // A repeated call returns the same head and moves nothing.
    let again = heads(&harness).await;
    assert_eq!(again["heads"], page["heads"]);
    assert_eq!(
        (&again["truncated"], &again["skipped"]),
        (&json!(0), &json!(0))
    );
}

#[tokio::test]
async fn a_tail_whose_write_may_have_reached_the_store_leaves_the_account_without_a_head() {
    let (provider, store) = refusing_store().await;
    let (harness, app) = node_with_log_store(&provider).await;
    assert_eq!(release(&harness, &app).await.0, 200);
    // Entry 3: the store reads the write and closes the connection without a response. Entry
    // 4: the store reads the writes of 3 and 4 and never answers. In both cases the request
    // may have reached the store.
    lock(&store).lost = 1;
    assert_eq!(
        release(&harness, &app).await.1["code"],
        "log_store_unavailable"
    );
    lock(&store).hang = true;
    assert_eq!(
        release(&harness, &app).await.1["code"],
        "log_store_unavailable"
    );
    assert_eq!(harness.head_seq("user-1"), 4);
    let health = harness.health().await;
    assert_eq!(health["log"]["write_attempt_failures"]["closed"], 1);
    assert!(
        health["log"]["write_attempt_failures"]["timeout"]
            .as_u64()
            .unwrap()
            >= 2
    );
    assert_eq!(health["state"]["pending_entries"], 2);

    // The shutdown while the store refuses with a 4xx status: the entries are known not to be
    // stored by that round, and still the earlier attempts may have stored them. The account
    // gets no final head, nothing is dropped, and the sweep keeps the entries pending.
    lock(&store).hang = false;
    lock(&store).status = 403;
    assert_eq!(harness.post("/v1/close", json!({})).await.0, 200);
    let page = heads(&harness).await;
    assert_eq!(
        (&page["heads"], &page["truncated"], &page["skipped"]),
        (&json!([]), &json!(0), &json!(1))
    );
    assert_eq!(harness.head_seq("user-1"), 4);
    let account = harness.node.account("user-1").unwrap();
    assert_eq!(lock(&account).unconfirmed().len(), 2);
    assert_eq!(harness.health().await["log_store"]["pending"], 1);

    // The store takes the entries again: the round of the repeated call writes them, and the
    // call signs the head at the end of the chain, which the keys the store holds reach.
    lock(&store).status = 0;
    let page = heads(&harness).await;
    assert!(lock(&account).unconfirmed().is_empty());
    assert_eq!(
        (&page["truncated"], &page["skipped"]),
        (&json!(0), &json!(0))
    );
    let head = harness.verified(purpose::HEAD, &page["heads"][0]);
    assert_eq!((&head["seq"], &head["final"]), (&json!(4), &json!(true)));
    let end = verified_end(&provider, &store, &harness, "user-1", &page["heads"][0]);
    assert_eq!(end.seq, 4);
}

#[tokio::test]
async fn a_tail_whose_writes_never_left_the_node_is_dropped() {
    let (provider, store) = refusing_store().await;
    let (harness, app) = node_with_log_store(&provider).await;
    assert_eq!(release(&harness, &app).await.0, 200);
    // Every connection to the store is refused: no request byte leaves the node for entries 3
    // and 4.
    harness.platform.refuse_connections(1_000);
    for _ in 0..2 {
        assert_eq!(
            release(&harness, &app).await.1["code"],
            "log_store_unavailable"
        );
    }
    let health = harness.health().await;
    assert!(
        health["log"]["write_attempt_failures"]["connect"]
            .as_u64()
            .unwrap()
            >= 2
    );
    assert_eq!(health["log"]["write_attempt_failures"]["closed"], 0);
    assert_eq!(health["log"]["write_attempt_failures"]["timeout"], 0);
    assert_eq!(harness.head_seq("user-1"), 4);

    // The shutdown: the two entries are known not to be in the store, so the tail is dropped
    // and the final head stands at entry 2.
    assert_eq!(harness.post("/v1/close", json!({})).await.0, 200);
    let page = heads(&harness).await;
    assert_eq!(
        (&page["truncated"], &page["skipped"]),
        (&json!(1), &json!(0))
    );
    let head = harness.verified(purpose::HEAD, &page["heads"][0]);
    assert_eq!((&head["seq"], &head["final"]), (&json!(2), &json!(true)));
    assert_eq!(harness.head_seq("user-1"), 2);
    // With the store reachable again, a repeated call writes nothing: the dropped entries are
    // gone, and the head is the same.
    harness.platform.refuse_connections(0);
    let writes = provider.stored().len();
    let again = heads(&harness).await;
    assert_eq!(again["heads"], page["heads"]);
    assert_eq!(provider.stored().len(), writes);
    assert_eq!(keys_of(&provider, &store, &harness, "user-1").len(), 2);
    let end = verified_end(&provider, &store, &harness, "user-1", &page["heads"][0]);
    assert_eq!(end.seq, 2);
}

#[tokio::test]
async fn a_tail_the_store_answered_with_a_5xx_status_leaves_the_account_without_a_head() {
    let (provider, store) = refusing_store().await;
    let (harness, app) = node_with_log_store(&provider).await;
    assert_eq!(release(&harness, &app).await.0, 200);
    // The store answers the writes of entries 3 and 4 with 503: S3 promises nothing about the
    // object of such an answer, so the entries may be in the store.
    lock(&store).status = 503;
    for _ in 0..2 {
        assert_eq!(
            release(&harness, &app).await.1["code"],
            "log_store_unavailable"
        );
    }
    assert_eq!(harness.head_seq("user-1"), 4);
    let health = harness.health().await;
    assert!(
        health["log"]["write_attempt_failures"]["status_5xx"]
            .as_u64()
            .unwrap()
            >= 2
    );

    // The shutdown while the store keeps answering 503: no final head, nothing dropped.
    assert_eq!(harness.post("/v1/close", json!({})).await.0, 200);
    let page = heads(&harness).await;
    assert_eq!(
        (&page["heads"], &page["truncated"], &page["skipped"]),
        (&json!([]), &json!(0), &json!(1))
    );
    assert_eq!(harness.head_seq("user-1"), 4);
    let account = harness.node.account("user-1").unwrap();
    assert_eq!(lock(&account).unconfirmed().len(), 2);

    // The store takes the entries: the round of the repeated call writes them and the head
    // stands at the end of the chain.
    lock(&store).status = 0;
    let page = heads(&harness).await;
    assert!(lock(&account).unconfirmed().is_empty());
    let head = harness.verified(purpose::HEAD, &page["heads"][0]);
    assert_eq!((&head["seq"], &head["final"]), (&json!(4), &json!(true)));
    let end = verified_end(&provider, &store, &harness, "user-1", &page["heads"][0]);
    assert_eq!(end.seq, 4);
}

#[tokio::test]
async fn a_write_a_call_abandoned_while_the_store_held_its_request_leaves_the_account_without_a_head(
) {
    let (provider, store) = refusing_store().await;
    let (harness, app) = node_with_log_store(&provider).await;
    assert_eq!(release(&harness, &app).await.0, 200);
    // Entry 3: the store reads the write and never answers, and the caller gives up before the
    // time limit of the attempt. The request was with the store when the call ended, so the
    // node knows nothing about the object.
    lock(&store).hang = true;
    let call = release(&harness, &app);
    assert!(tokio::time::timeout(Duration::from_millis(300), call)
        .await
        .is_err());
    assert_eq!(harness.head_seq("user-1"), 3);
    let account = harness.node.account("user-1").unwrap();
    assert_eq!(lock(&account).unconfirmed().len(), 1);

    // The shutdown while the store refuses with a 4xx status: the round of the page fails
    // definitely, and still the account gets no final head, because the abandoned request
    // may have stored the object.
    lock(&store).hang = false;
    lock(&store).status = 403;
    assert_eq!(harness.post("/v1/close", json!({})).await.0, 200);
    let page = heads(&harness).await;
    assert_eq!(
        (&page["heads"], &page["truncated"], &page["skipped"]),
        (&json!([]), &json!(0), &json!(1))
    );
    assert_eq!(harness.head_seq("user-1"), 3);
    assert_eq!(lock(&account).unconfirmed().len(), 1);

    // The store takes the entry: the repeated call writes it and signs the head at entry 3.
    lock(&store).status = 0;
    let page = heads(&harness).await;
    assert!(lock(&account).unconfirmed().is_empty());
    let head = harness.verified(purpose::HEAD, &page["heads"][0]);
    assert_eq!((&head["seq"], &head["final"]), (&json!(3), &json!(true)));
    let end = verified_end(&provider, &store, &harness, "user-1", &page["heads"][0]);
    assert_eq!(end.seq, 3);
}

#[tokio::test]
async fn a_chain_whose_every_entry_is_pending_ends_at_seq_zero() {
    // The receiving node of a transfer creates entry 1 (`grant_transferred_in`) as a pending
    // entry; its store refuses the round of the import.
    let (provider, store) = refusing_store().await;
    let (old, app) = node_with_log_store(&provider).await;
    let new = Harness::new(&provider);
    new.use_log_store().await;
    lock(&store).status = 403;
    let to = new
        .post("/v1/attestation", json!({"nonce": b64u(&[9u8; 32])}))
        .await
        .1;
    let from = old
        .post("/v1/attestation", json!({"nonce": b64u(&[9u8; 32])}))
        .await
        .1;
    // The giving node cannot write its entry: it hands nothing over while the store refuses.
    let (status, failure) = old
        .post("/v1/peer/export", json!({"peer": to, "limit": 1000}))
        .await;
    assert_eq!(
        (status, failure["code"].as_str()),
        (503, Some("log_store_unavailable"))
    );
    lock(&store).status = 0;
    let (_, exported) = old
        .post("/v1/peer/export", json!({"peer": to, "limit": 1000}))
        .await;
    lock(&store).status = 403;
    let (status, imported) = new
        .post(
            "/v1/peer/import",
            json!({"peer": from, "envelope": exported["envelope"]}),
        )
        .await;
    assert_eq!((status, imported["imported"].as_u64()), (200, Some(1)));
    assert_eq!(new.head_seq(&app.user_id), 1);
    assert_eq!(new.health().await["accounts"], 1);

    // The shutdown of the receiving node: entry 1 is the whole chain and pending, so the
    // final head stands at the empty chain, and the node has no chain for the account.
    assert_eq!(new.post("/v1/close", json!({})).await.0, 200);
    let page = heads(&new).await;
    assert_eq!(
        (&page["truncated"], &page["skipped"]),
        (&json!(1), &json!(0))
    );
    let head = new.verified(purpose::HEAD, &page["heads"][0]);
    assert_eq!(head["seq"], 0);
    assert_eq!(head["hash"], b64u(&[0u8; 32]));
    assert_eq!(head["final"], true);
    assert_eq!(new.head_seq(&app.user_id), 0);
    assert_eq!(new.health().await["accounts"], 0);
    assert!(keys_of(&provider, &store, &new, &app.user_id).is_empty());

    // The account stays listed with its head: a later page returns the same head.
    let again = heads(&new).await;
    assert_eq!(again["heads"], page["heads"]);
    assert_eq!(again["truncated"], 0);
}

#[tokio::test]
async fn a_confirmed_entry_above_a_pending_one_leaves_the_account_without_a_head_until_the_gap_closes(
) {
    let (provider, store) = refusing_store().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let bob = App::new("bob", 2);
    bob.grant(&harness).await;
    // The store refuses the writes of entry 2 of user-1 alone: the release that creates it
    // fails and leaves it pending. The next release creates entry 3 and writes 2 and 3: 2 is
    // refused again, 3 is confirmed, and the call succeeds. Entry 3 stands above a gap.
    lock(&store).seq = Some(2);
    assert_eq!(
        release(&harness, &app).await.1["code"],
        "log_store_unavailable"
    );
    let (status, released) = release(&harness, &app).await;
    assert_eq!(status, 200, "{released}");
    assert_eq!(released["log"]["seq"], 3);
    let account = harness.node.account("user-1").unwrap();
    assert_eq!(
        lock(&account)
            .unconfirmed()
            .iter()
            .map(|entry| entry.seq)
            .collect::<Vec<u64>>(),
        [2]
    );

    // The shutdown while entry 2 is still refused: bob gets his head, user-1 gets none in this
    // call. Nothing of user-1 is dropped, and the listing goes on past the account.
    assert_eq!(harness.post("/v1/close", json!({})).await.0, 200);
    let page = heads(&harness).await;
    assert_eq!(
        (&page["truncated"], &page["skipped"]),
        (&json!(0), &json!(1))
    );
    assert_eq!(page["heads"].as_array().unwrap().len(), 1);
    assert_eq!(
        harness.verified(purpose::HEAD, &page["heads"][0])["user_id"],
        "bob"
    );
    assert_eq!(page["next"], "");
    assert_eq!(harness.head_seq("user-1"), 3);
    assert_eq!(lock(&account).unconfirmed().len(), 1);
    assert_eq!(harness.health().await["log_store"]["pending"], 1);
    let (_, cursor_page) = harness
        .post("/v1/close/heads", json!({"cursor": "bob", "limit": 1}))
        .await;
    assert_eq!(
        (&cursor_page["heads"], &cursor_page["skipped"]),
        (&json!([]), &json!(1))
    );

    // The store takes entry 2: the repeated call writes it in its round and signs the head at
    // the end of the chain.
    lock(&store).seq = None;
    let page = heads(&harness).await;
    assert_eq!(
        (&page["truncated"], &page["skipped"]),
        (&json!(0), &json!(0))
    );
    assert_eq!(page["heads"].as_array().unwrap().len(), 2);
    let head = harness.verified(purpose::HEAD, &page["heads"][1]);
    assert_eq!(
        (&head["user_id"], &head["seq"]),
        (&json!("user-1"), &json!(3))
    );
    assert!(lock(&account).unconfirmed().is_empty());
    let end = verified_end(&provider, &store, &harness, "user-1", &page["heads"][1]);
    assert_eq!(end.seq, 3);
    assert_eq!(harness.health().await["log_store"]["pending"], 0);
}
