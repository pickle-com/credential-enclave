//! The credential log as a node writes it (protocol.md section 7, enclave.md 5.8 and 5.11):
//! an entry precedes the act it records, the events that arrive during a write form the next
//! entry (the group commit), identical GET requests share one event, a control event stands in
//! an entry of its own, the chain verifies from the keys of the store, and the orderly shutdown
//! ends every chain with a `final` head that covers an open batch.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use credential_enclave_protocol::app::{open_entry_v2, verify_entry_v2, verify_index, IndexError};
use credential_enclave_protocol::encoding::{to_json, verify, Signed};
use credential_enclave_protocol::log::{
    chain_prefix, parse_object_key, EntryKind, EntryParts, Head, ParsedKey,
};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::{limits, purpose};
use serde_json::{json, Value};

use super::{provider, provider_and_log_store, quiet_provider_and_log_store};
use crate::state::{lock, Account, Node};
use crate::testing::{App, Harness, Provider, Reply, Seen, LOG_HOST};

const MESSAGES: &str = "https://gmail.googleapis.com/gmail/v1/users/me/messages";

fn google_record(app: &App) -> Value {
    app.record(
        "oauth",
        "google_workspace",
        &json!({
            "token": {"access_token": "ya29.access", "refresh_token": "1//refresh", "expires_in": 3599},
            "obtained_ms": 1,
        }),
    )
}

fn get(app: &App, record: &Value, url: &str) -> Value {
    json!({
        "user_id": app.user_id, "record": record, "method": "GET", "url": url,
        "headers": [], "context": "cli:gog", "timeout_ms": 5000,
    })
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

/// A stand-in for the providers and the log store whose store answers every write after the
/// pause the test sets: a write in progress is the time in which other calls join the open
/// batch of the account.
async fn paused_store() -> (Provider, Arc<Mutex<Duration>>) {
    let pause = Arc::new(Mutex::new(Duration::ZERO));
    let script = pause.clone();
    let provider = provider_and_log_store(
        |_| Reply::json(200, &json!({"ok": true})),
        move |_| {
            let pause = *lock(&script);
            Reply::with_body(200, &[("etag", "\"0\"")], b"")
                .keep_alive()
                .after(pause)
        },
    )
    .await;
    (provider, pause)
}

/// A node with the log store of the tests and the app of an account that granted on it.
async fn node_with_log_store(provider: &Provider) -> (Harness, App) {
    let harness = Harness::new(provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    (harness, app)
}

/// The parts of the keys of the chain of `user_id` on the node under test, in `seq` order.
fn keys_of(provider: &Provider, harness: &Harness, user_id: &str) -> Vec<EntryParts> {
    provider
        .chain(user_id, &harness.node.node)
        .iter()
        .map(|stored| stored.parts().clone())
        .collect()
}

/// The head of the chain of `user_id` for a nonce, as `status` hands it out.
async fn head_of(harness: &Harness, user_id: &str, nonce: &str) -> Signed {
    let (status, state) = harness
        .post("/v1/status", json!({"user_id": user_id, "nonce": nonce}))
        .await;
    assert_eq!(status, 200);
    serde_json::from_value(state["head"].clone()).unwrap()
}

/// The position of the write of the entry `seq` of `user_id` and the positions of the
/// provider requests whose target ends with one of `targets`, in the order the stand-in saw
/// them.
fn positions(seen: &[Seen], user_id: &str, seq: u64, targets: &[&str]) -> (usize, Vec<usize>) {
    let name = format!("/{seq:020}-");
    let write = seen
        .iter()
        .position(|seen| {
            seen.server_name == LOG_HOST
                && seen.target.contains(&format!("/accounts/{user_id}/"))
                && seen.target.contains(&name)
        })
        .expect("the entry was written");
    let requests = targets
        .iter()
        .map(|target| {
            seen.iter()
                .position(|seen| seen.server_name != LOG_HOST && seen.target.ends_with(target))
                .unwrap_or_else(|| panic!("the request {target} reached the provider"))
        })
        .collect();
    (write, requests)
}

#[tokio::test]
async fn the_entry_is_on_the_chain_before_the_provider_is_called() {
    // The stand-in looks at the chain of the account at the moment a request reaches it.
    let node_slot: Arc<Mutex<Option<Arc<Node>>>> = Arc::new(Mutex::new(None));
    let observed: Arc<Mutex<Vec<(String, u64, bool)>>> = Arc::new(Mutex::new(Vec::new()));
    let provider = provider({
        let node_slot = node_slot.clone();
        let observed = observed.clone();
        move |seen| {
            let node = lock(&node_slot).clone().expect("the node is running");
            let account = node.account("user-1").expect("the account has a grant");
            let account = lock(&account);
            lock(&observed).push((
                seen.target.clone(),
                account.head.seq,
                account.has_open_events(),
            ));
            // Not a token response: a refresh that reaches this stand-in is refused.
            Reply::json(200, &json!({"ok": true}))
        }
    })
    .await;
    let harness = Harness::configured(&provider).await;
    *lock(&node_slot) = Some(harness.node.clone());
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let record = google_record(&app);

    // forward: entry 2 exists, and no event waits in the open batch, when the request arrives.
    let forwarded = harness
        .forward(get(&app, &record, MESSAGES), b"")
        .await
        .unwrap();
    assert_eq!(
        forwarded.log,
        json!({"seq": 2, "index": 0, "created": true})
    );
    assert_eq!(
        lock(&observed).last().unwrap(),
        &("/gmail/v1/users/me/messages".to_string(), 2, false)
    );

    // refresh: entry 3 exists when the token address is called, and it stays although the
    // provider refuses the refresh.
    let (status, failure) = harness
        .post(
            "/v1/refresh",
            json!({"user_id": "user-1", "record": record, "context": "refresh:scheduled"}),
        )
        .await;
    assert_eq!(
        (status, failure["code"].as_str()),
        (502, Some("refresh_failed"))
    );
    assert_eq!(
        lock(&observed).last().unwrap(),
        &("/token".to_string(), 3, false)
    );
    assert_eq!(harness.head_seq("user-1"), 3);

    // revoke-token: entry 4 exists when the revocation address is called.
    let (status, revoked) = harness
        .post(
            "/v1/revoke-token",
            json!({"user_id": "user-1", "record": record, "context": "disconnect"}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        lock(&observed).last().unwrap(),
        &("/revoke".to_string(), 4, false)
    );
    assert_eq!(
        revoked["log"],
        json!({"seq": 4, "index": 0, "created": true})
    );
}

#[tokio::test]
async fn a_request_under_a_new_grant_does_not_merge_into_an_event_of_the_grant_before() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let record = google_record(&app);
    let address = format!("{MESSAGES}?maxResults=5");
    let first = harness
        .forward(get(&app, &record, &address), b"")
        .await
        .unwrap();
    assert_eq!(first.log, json!({"seq": 2, "index": 0, "created": true}));

    // The grant ends and a new one takes its place within the 300 seconds: the same request
    // has an event of its own under the new grant.
    app.revoke(&harness).await;
    app.grant(&harness).await;
    assert_eq!(harness.head_seq("user-1"), 4);
    let again = harness
        .forward(get(&app, &record, &address), b"")
        .await
        .unwrap();
    assert_eq!(again.log, json!({"seq": 5, "index": 0, "created": true}));
    assert_eq!(
        app.stored_events(&harness, &provider)
            .iter()
            .flat_map(|events| events.iter())
            .map(|event| event["t"].as_str().unwrap().to_string())
            .collect::<Vec<_>>(),
        [
            "grant_accepted",
            "provider_request",
            "grant_revoked",
            "grant_accepted",
            "provider_request",
        ]
    );
}

#[tokio::test]
async fn identical_get_requests_within_300_seconds_share_one_event() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let record = google_record(&app);
    let address = format!("{MESSAGES}?maxResults=5");

    let before_ms = harness.node.now_ms();
    let first = harness
        .forward(get(&app, &record, &address), b"")
        .await
        .unwrap();
    assert_eq!(first.log, json!({"seq": 2, "index": 0, "created": true}));
    let event = app.logged(&harness, &provider, &first.log);
    let time_ms = event["time_ms"].as_u64().unwrap();
    assert!((before_ms..=harness.node.now_ms()).contains(&time_ms));
    assert_eq!(
        event,
        json!({
            "t": "provider_request", "time_ms": time_ms, "record_id": record["id"],
            "provider": "google_workspace", "method": "GET", "host": "gmail.googleapis.com",
            "path": "/gmail/v1/users/me/messages", "query": "maxResults=5",
            "body_bytes": 0, "body_sha256": "", "context": "cli:gog", "window_s": 300,
        })
    );

    // The same request again: sent, and it names the event of the first one.
    let second = harness
        .forward(get(&app, &record, &address), b"")
        .await
        .unwrap();
    assert_eq!(second.status, 200);
    assert_eq!(second.log, json!({"seq": 2, "index": 0, "created": false}));
    assert_eq!(
        provider
            .seen()
            .iter()
            .filter(|seen| seen.server_name != LOG_HOST)
            .count(),
        2
    );
    assert_eq!(harness.head_seq("user-1"), 2);

    // Another query, another path and another record are other requests.
    for (url, seq) in [
        (format!("{MESSAGES}?maxResults=6"), 3),
        (format!("{MESSAGES}/m1?maxResults=5"), 4),
    ] {
        let other = harness
            .forward(get(&app, &record, &url), b"")
            .await
            .unwrap();
        assert_eq!(
            other.log,
            json!({"seq": seq, "index": 0, "created": true}),
            "{url}"
        );
    }
    let second_record = google_record(&app);
    let other = harness
        .forward(get(&app, &second_record, &address), b"")
        .await
        .unwrap();
    assert_eq!(other.log, json!({"seq": 5, "index": 0, "created": true}));

    // Requests with another method are never merged and carry no window.
    let mut post = get(&app, &record, &address);
    post["method"] = json!("POST");
    for seq in [6, 7] {
        let sent = harness.forward(post.clone(), b"{}").await.unwrap();
        assert_eq!(sent.log, json!({"seq": seq, "index": 0, "created": true}));
        let event = app.logged(&harness, &provider, &sent.log);
        assert_eq!(event["method"], "POST");
        assert_eq!(event["body_bytes"], 2);
        assert!(event.get("window_s").is_none());
    }

    // Still inside the window: merged. After 300 seconds: a new event.
    harness
        .node
        .clock
        .advance(limits::MERGE_WINDOW_S * 1000 - 5_000);
    let inside = harness
        .forward(get(&app, &record, &address), b"")
        .await
        .unwrap();
    assert_eq!(inside.log, json!({"seq": 2, "index": 0, "created": false}));
    harness.node.clock.advance(6_000);
    let outside = harness
        .forward(get(&app, &record, &address), b"")
        .await
        .unwrap();
    assert_eq!(outside.log, json!({"seq": 8, "index": 0, "created": true}));

    // Another account has its own chain and its own window.
    let other_app = App::new("user-2", 2);
    other_app.grant(&harness).await;
    let other_record = google_record(&other_app);
    let theirs = harness
        .forward(get(&other_app, &other_record, &address), b"")
        .await
        .unwrap();
    assert_eq!(theirs.log, json!({"seq": 2, "index": 0, "created": true}));
}

#[tokio::test]
async fn events_that_arrive_during_a_write_form_the_next_entry() {
    let (provider, pause) = paused_store().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let record = google_record(&app);
    *lock(&pause) = Duration::from_millis(400);

    // The first request writes its own entry. While the store holds that write, three more
    // requests of the account arrive: their events go into the open batch, and they wait.
    let first = harness.forward(get(&app, &record, &format!("{MESSAGES}?q=a")), b"");
    let rest = async {
        provider.until_written(2).await;
        tokio::join!(
            harness.forward(get(&app, &record, &format!("{MESSAGES}?q=b")), b""),
            harness.forward(get(&app, &record, &format!("{MESSAGES}?q=c")), b""),
            harness.forward(get(&app, &record, &format!("{MESSAGES}?q=d")), b""),
        )
    };
    let (first, (second, third, fourth)) = tokio::join!(first, rest);
    let first = first.unwrap();
    assert_eq!(first.log, json!({"seq": 2, "index": 0, "created": true}));

    // The three form entry 3 together, each named by its index in it, and every one of them
    // reached the provider after the store confirmed that entry.
    let mut indices = Vec::new();
    for outcome in [second, third, fourth] {
        let outcome = outcome.unwrap();
        assert_eq!(outcome.status, 200);
        assert_eq!(outcome.log["seq"], 3);
        assert_eq!(outcome.log["created"], true);
        indices.push(outcome.log["index"].as_u64().unwrap());
    }
    indices.sort();
    assert_eq!(indices, [0, 1, 2]);
    let chain = provider.chain("user-1", &harness.node.node);
    let seqs: Vec<u64> = chain.iter().map(|stored| stored.seq()).collect();
    assert_eq!(seqs, [1, 2, 3]);
    assert_eq!(
        (chain[2].parts().kind, chain[2].parts().count),
        (EntryKind::Use, 3)
    );
    let mut queries: Vec<String> = app
        .events(&harness, &chain[2].entry)
        .iter()
        .map(|event| event["query"].as_str().unwrap().to_string())
        .collect();
    queries.sort();
    assert_eq!(queries, ["q=b", "q=c", "q=d"]);
    let (write, requests) = positions(&provider.seen(), "user-1", 3, &["?q=b", "?q=c", "?q=d"]);
    assert!(requests.iter().all(|request| *request > write));

    // The counts of health: three entries, five events, three writes, none failed, no open
    // batch left.
    let log = harness.health().await["log"].clone();
    assert_eq!(
        log,
        json!({
            "entries": 3, "events": 5, "writes": 3, "write_failures": 0, "open_batches": 0,
            "batch_calls": 0, "batch_requests": 0,
        })
    );
}

#[tokio::test]
async fn a_merged_get_waits_for_the_entry_of_the_event_it_shares() {
    let (provider, pause) = paused_store().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let record = google_record(&app);
    *lock(&pause) = Duration::from_millis(400);

    // The same GET arrives while the entry of the first one is being written: it shares the
    // event and waits for that write.
    let first = harness.forward(get(&app, &record, MESSAGES), b"");
    let second = async {
        provider.until_written(2).await;
        harness.forward(get(&app, &record, MESSAGES), b"").await
    };
    let (first, second) = tokio::join!(first, second);
    assert_eq!(
        first.unwrap().log,
        json!({"seq": 2, "index": 0, "created": true})
    );
    assert_eq!(
        second.unwrap().log,
        json!({"seq": 2, "index": 0, "created": false})
    );
    let seen = provider.seen();
    let writes = seen
        .iter()
        .filter(|seen| seen.server_name == LOG_HOST)
        .count();
    assert_eq!(writes, 2);
    let (write, requests) = positions(&seen, "user-1", 2, &["/messages", "/messages"]);
    assert!(requests[0] > write);
    assert_eq!(harness.head_seq("user-1"), 2);

    // The same GET after the write shares the confirmed event and writes nothing.
    *lock(&pause) = Duration::ZERO;
    let third = harness
        .forward(get(&app, &record, MESSAGES), b"")
        .await
        .unwrap();
    assert_eq!(third.log, json!({"seq": 2, "index": 0, "created": false}));
    assert_eq!(provider.stored().len(), 2);
}

#[tokio::test]
async fn a_control_event_closes_the_open_batch_and_stands_alone() {
    let (provider, pause) = paused_store().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let record = google_record(&app);
    *lock(&pause) = Duration::from_millis(400);

    // A release writes entry 2. A forward joins the open batch while that write runs, and
    // then a grant command arrives: the control event closes the batch (entry 3, the event of
    // the forward) and forms entry 4 of its own.
    let password = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
    let released = release(&harness, &app, &password);
    let rest = async {
        provider.until_written(2).await;
        let forwarded = harness.forward(get(&app, &record, MESSAGES), b"");
        let granted = async {
            tokio::time::sleep(Duration::from_millis(60)).await;
            app.grant(&harness).await
        };
        tokio::join!(forwarded, granted)
    };
    let ((status, released), (forwarded, granted)) = tokio::join!(released, rest);
    assert_eq!(status, 200);
    assert_eq!(
        released["log"],
        json!({"seq": 2, "index": 0, "created": true})
    );
    assert_eq!(
        forwarded.unwrap().log,
        json!({"seq": 3, "index": 0, "created": true})
    );
    assert_eq!(
        granted["log"],
        json!({"seq": 4, "index": 0, "created": true})
    );

    let chain = provider.chain("user-1", &harness.node.node);
    let shape: Vec<(u64, EntryKind, u32)> = chain
        .iter()
        .map(|stored| {
            let parts = stored.parts();
            (parts.seq, parts.kind, parts.count)
        })
        .collect();
    assert_eq!(
        shape,
        [
            (1, EntryKind::Control, 1),
            (2, EntryKind::Use, 1),
            (3, EntryKind::Use, 1),
            (4, EntryKind::Control, 1),
        ]
    );
    assert_eq!(app.event(&harness, &chain[3].entry)["t"], "grant_accepted");
    assert_eq!(
        app.event(&harness, &chain[2].entry)["t"],
        "provider_request"
    );
}

/// An account of the node under test with the key of `app`, for the tests that create events
/// without a call.
fn account_of(harness: &Harness, app: &App) -> Arc<Mutex<Account>> {
    let account = harness.node.account_or_create(&app.user_id);
    let mut guard = lock(&account);
    guard.open.key_id = app.keys.key_id();
    guard.open.log_pk = app.keys.log_pk();
    drop(guard);
    account
}

/// Creates one use event on the chain of `app`, outside a call.
fn create_use_event(harness: &Harness, account: &Mutex<Account>, app: &App, event: Value) {
    harness
        .node
        .create_event(
            &mut lock(account),
            &app.user_id,
            &app.keys.key_id(),
            &app.keys.log_pk(),
            harness.node.now_ms(),
            EntryKind::Use,
            event,
        )
        .unwrap();
}

/// The parts of the keys of the unconfirmed entries of an account, in order.
fn unconfirmed_parts(
    harness: &Harness,
    account: &Mutex<Account>,
    user_id: &str,
) -> Vec<EntryParts> {
    lock(account)
        .unconfirmed
        .iter()
        .map(|entry| {
            match parse_object_key(&entry.key, &chain_prefix(user_id, &harness.node.node)) {
                Some(ParsedKey::V2(parts)) => parts,
                other => panic!("a key of format 2: {other:?}"),
            }
        })
        .collect()
}

#[tokio::test]
async fn an_entry_holds_at_most_128_events() {
    let provider = quiet_provider_and_log_store().await;
    let harness = Harness::new(&provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    let account = account_of(&harness, &app);

    // The 129th event closes the batch of the 128 before it.
    for index in 0..limits::ENTRY_EVENTS + 1 {
        let event = json!({"t": "secret_released", "record_id": format!("r{index}")});
        create_use_event(&harness, &account, &app, event);
    }
    let parts = unconfirmed_parts(&harness, &account, "user-1");
    assert_eq!(parts.len(), 1);
    assert_eq!(
        (parts[0].seq, parts[0].kind, parts[0].count as usize),
        (1, EntryKind::Use, limits::ENTRY_EVENTS)
    );
    assert_eq!(lock(&account).open.events.len(), 1);
    assert_eq!(harness.head_seq("user-1"), 1);

    // The one event that is left forms the next entry when the batch is closed.
    let seq = harness
        .node
        .close_batch(&mut lock(&account), "user-1", harness.node.now_ms())
        .unwrap();
    assert_eq!(seq, Some(2));
    let parts = unconfirmed_parts(&harness, &account, "user-1");
    assert_eq!((parts[1].seq, parts[1].count), (2, 1));
    assert!(!lock(&account).has_open_events());
    assert_eq!(
        harness
            .node
            .close_batch(&mut lock(&account), "user-1", harness.node.now_ms())
            .unwrap(),
        None
    );
    let log = harness.health().await["log"].clone();
    assert_eq!((&log["entries"], &log["events"]), (&json!(2), &json!(129)));
    // The events of the first entry open in the order of their creation.
    let entry = serde_json::to_value(&lock(&account).unconfirmed[0].entry).unwrap();
    let events = app.events(&harness, &entry);
    assert_eq!(events.len(), limits::ENTRY_EVENTS);
    assert_eq!(events[0]["record_id"], "r0");
    assert_eq!(events[127]["record_id"], "r127");
}

#[tokio::test]
async fn an_entry_plaintext_stays_under_the_byte_limit() {
    let provider = quiet_provider_and_log_store().await;
    let harness = Harness::new(&provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    let account = account_of(&harness, &app);

    // Events of about 300 KB: three fit under 1,048,576 bytes of plaintext, the fourth closes
    // the batch before it.
    let large =
        |index: usize| json!({"t": "secret_released", "context": "x".repeat(300_000), "i": index});
    for index in 0..4 {
        create_use_event(&harness, &account, &app, large(index));
    }
    let parts = unconfirmed_parts(&harness, &account, "user-1");
    assert_eq!(parts.len(), 1);
    assert_eq!((parts[0].seq, parts[0].count), (1, 3));
    assert_eq!(lock(&account).open.events.len(), 1);
    let entry = serde_json::to_value(&lock(&account).unconfirmed[0].entry).unwrap();
    let events = app.events(&harness, &entry);
    let plaintext = to_json(&Value::Array(events.clone()));
    assert!(plaintext.len() <= limits::ENTRY_PLAINTEXT_BYTES);
    let four = to_json(&Value::Array((0..4).map(large).collect()));
    assert!(four.len() > limits::ENTRY_PLAINTEXT_BYTES);
    assert_eq!(events[2]["i"], 2);
}

#[tokio::test]
async fn event_and_entry_times_do_not_decrease() {
    let provider = quiet_provider_and_log_store().await;
    let harness = Harness::new(&provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    let account = account_of(&harness, &app);
    let times_of = |entry: &Signed| -> (u64, u64, Vec<u64>) {
        let entry = serde_json::to_value(entry).unwrap();
        let body = app.entry_body(&harness, &entry);
        let events = app.events(&harness, &entry);
        (
            body["seq"].as_u64().unwrap(),
            body["time_ms"].as_u64().unwrap(),
            events
                .iter()
                .map(|event| event["time_ms"].as_u64().unwrap())
                .collect(),
        )
    };

    // A caller may read the node time before it takes the account lock. Whatever time it
    // then hands over, the times of the chain do not decrease with `seq`, and an event is
    // never dated after its entry.
    for time_ms in [5_000u64, 3_000, 5_000, 7_000, 6_999] {
        harness
            .node
            .create_event_seeded(
                &mut lock(&account),
                "user-1",
                &app.keys.key_id(),
                &app.keys.log_pk(),
                time_ms,
                EntryKind::Control,
                json!({"t": "grant_revoked"}),
                &Secret::new([7; 32]),
            )
            .unwrap();
    }
    let written: Vec<(u64, u64, Vec<u64>)> = lock(&account)
        .unconfirmed
        .iter()
        .map(|entry| times_of(&entry.entry))
        .collect();
    assert_eq!(
        written,
        [
            (1, 5_000, vec![5_000]),
            (2, 5_000, vec![5_000]),
            (3, 5_000, vec![5_000]),
            (4, 7_000, vec![7_000]),
            (5, 7_000, vec![7_000]),
        ]
    );

    // Use events that join a batch: the second one carries a stale time and gets the time of
    // the first; the batch is closed with an even older time and the entry gets the time of
    // its latest event.
    for time_ms in [9_000u64, 8_000] {
        harness
            .node
            .create_event_seeded(
                &mut lock(&account),
                "user-1",
                &app.keys.key_id(),
                &app.keys.log_pk(),
                time_ms,
                EntryKind::Use,
                json!({"t": "secret_released"}),
                &Secret::new([7; 32]),
            )
            .unwrap();
    }
    harness
        .node
        .close_batch(&mut lock(&account), "user-1", 8_500)
        .unwrap();
    let last = times_of(&lock(&account).unconfirmed[5].entry);
    assert_eq!(last, (6, 9_000, vec![9_000, 9_000]));
}

#[tokio::test]
async fn the_chain_a_node_wrote_verifies_from_the_keys_of_the_store_and_its_head() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let record = google_record(&app);
    let password = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
    harness
        .forward(get(&app, &record, MESSAGES), b"")
        .await
        .unwrap();
    assert_eq!(release(&harness, &app, &password).await.0, 200);
    app.revoke(&harness).await;

    // The index verification: the keys alone reach the hash of the head.
    let keys = keys_of(&provider, &harness, "user-1");
    assert_eq!(keys.len(), 4);
    let kinds: Vec<EntryKind> = keys.iter().map(|parts| parts.kind).collect();
    assert_eq!(
        kinds,
        [
            EntryKind::Control,
            EntryKind::Use,
            EntryKind::Use,
            EntryKind::Control
        ]
    );
    let head = head_of(&harness, "user-1", "bm9uY2U").await;
    let end = verify_index(
        &harness.node_public(),
        "user-1",
        &Head::EMPTY,
        &keys,
        &head,
        Some("bm9uY2U"),
    )
    .unwrap();
    assert_eq!(end.seq, 4);

    // The content verification: every object verifies against its key and its predecessor,
    // and opens to its events.
    let mut cursor = Head::EMPTY;
    let mut kinds = Vec::new();
    for stored in provider.chain("user-1", &harness.node.node) {
        let entry: Signed = serde_json::from_value(stored.entry.clone()).unwrap();
        let body = verify_entry_v2(
            &harness.node_public(),
            "user-1",
            stored.parts(),
            Some(&cursor),
            &entry,
        )
        .unwrap();
        let body_bytes = verify(&harness.node_public(), purpose::LOG_ENTRY_V2, &entry).unwrap();
        let events = open_entry_v2(&app.keys.log, &body_bytes).unwrap();
        assert_eq!(events.len(), body.count as usize);
        kinds.push(events[0]["t"].as_str().unwrap().to_string());
        cursor = Head {
            seq: stored.seq(),
            hash: stored.parts().entry_hash,
        };
    }
    assert_eq!(
        kinds,
        [
            "grant_accepted",
            "provider_request",
            "secret_released",
            "grant_revoked"
        ]
    );
    assert_eq!(cursor.seq, 4);

    // Without the key of the middle entry the index has a gap, and a key whose body hash was
    // changed breaks the chain at its `seq`.
    let mut missing = keys.clone();
    missing.remove(1);
    assert_eq!(
        verify_index(
            &harness.node_public(),
            "user-1",
            &Head::EMPTY,
            &missing,
            &head,
            Some("bm9uY2U"),
        ),
        Err(IndexError::Gap { seq: 2 })
    );
    let mut changed = keys.clone();
    changed[2].body_hash[0] ^= 1;
    assert_eq!(
        verify_index(
            &harness.node_public(),
            "user-1",
            &Head::EMPTY,
            &changed,
            &head,
            Some("bm9uY2U"),
        ),
        Err(IndexError::Broken { seq: 3 })
    );
}

#[tokio::test]
async fn close_ends_every_chain_with_a_final_head() {
    let provider = quiet_provider_and_log_store().await;
    let harness = Harness::new(&provider);
    harness.use_log_store().await;
    let alice = App::new("alice", 1);
    let bob = App::new("bob", 2);
    let carol = App::new("carol", 3);
    alice.grant(&harness).await;
    bob.grant(&harness).await;
    // Carol only revoked: she has a marker and no chain.
    carol.revoke(&harness).await;
    let password = alice.record("vault_password", "vault", &json!({"value": "hunter2"}));
    release(&harness, &alice, &password).await;
    let token = google_record(&alice);

    // Final heads exist only after close.
    let (status, failure) = harness
        .post("/v1/close/heads", json!({"cursor": "", "limit": 1000}))
        .await;
    assert_eq!(
        (status, failure["code"].as_str()),
        (400, Some("invalid_request"))
    );

    let (status, closed) = harness.post("/v1/close", json!({})).await;
    assert_eq!((status, closed["accounts"].as_u64()), (200, Some(2)));
    let health = harness.health().await;
    assert_eq!(health["closing"], true);
    assert_eq!(health["accounts"], 2);

    // From now on commands and every call that uses a credential are refused.
    let provider_requests_before = provider
        .seen()
        .iter()
        .filter(|seen| seen.server_name != LOG_HOST)
        .count();
    assert_eq!(
        release(&harness, &alice, &password).await.1["code"],
        "closing"
    );
    let refused = harness
        .forward(get(&alice, &token, MESSAGES), b"")
        .await
        .err()
        .unwrap();
    assert_eq!(
        (refused.0, refused.1["code"].as_str()),
        (503, Some("closing"))
    );
    for (path, body) in [
        (
            "/v1/refresh",
            json!({"user_id": "alice", "record": token, "context": "c"}),
        ),
        (
            "/v1/revoke-token",
            json!({"user_id": "alice", "record": token, "context": "c"}),
        ),
        (
            "/v1/oauth/merge",
            json!({"user_id": "alice", "record": token, "previous": token}),
        ),
        (
            "/v1/oauth/begin",
            json!({"user_id": "alice", "provider": "slack", "operator_state": "o", "params": {}, "client_id": ""}),
        ),
    ] {
        let (status, failure) = harness.post(path, body).await;
        assert_eq!(
            (status, failure["code"].as_str()),
            (503, Some("closing")),
            "{path}"
        );
    }
    let attested = alice.attest(&harness).await;
    let envelope = alice.revoke_envelope(&attested);
    let (status, failure) = harness
        .post(
            "/v1/messages",
            json!({"user_id": "alice", "envelope": envelope}),
        )
        .await;
    assert_eq!((status, failure["code"].as_str()), (503, Some("closing")));
    assert_eq!(
        provider
            .seen()
            .iter()
            .filter(|seen| seen.server_name != LOG_HOST)
            .count(),
        provider_requests_before
    );

    // One final head per account with a chain, in user_id order, page by page.
    let (status, first) = harness
        .post("/v1/close/heads", json!({"cursor": "", "limit": 1}))
        .await;
    assert_eq!(status, 200);
    assert_eq!(first["heads"].as_array().unwrap().len(), 1);
    assert_eq!(first["next"], "alice");
    let (_, second) = harness
        .post("/v1/close/heads", json!({"cursor": "alice", "limit": 1}))
        .await;
    assert_eq!(second["heads"].as_array().unwrap().len(), 1);
    assert_eq!(second["next"], "");
    let alice_head = harness.verified(purpose::HEAD, &first["heads"][0]);
    assert_eq!(alice_head["user_id"], "alice");
    assert_eq!(alice_head["seq"], 2);
    assert_eq!(alice_head["nonce"], "");
    assert_eq!(alice_head["final"], true);
    assert_eq!(
        harness.verified(purpose::HEAD, &second["heads"][0])["user_id"],
        "bob"
    );

    // The final head closes the stored chain: the keys of the store reach its hash.
    let head: Signed = serde_json::from_value(first["heads"][0].clone()).unwrap();
    let end = verify_index(
        &harness.node_public(),
        "alice",
        &Head::EMPTY,
        &keys_of(&provider, &harness, "alice"),
        &head,
        None,
    )
    .unwrap();
    assert_eq!(end.seq, 2);

    // A node creates one final head per account: asking again returns the same heads.
    let (_, all) = harness
        .post("/v1/close/heads", json!({"cursor": "", "limit": 1000}))
        .await;
    assert_eq!(all["heads"], json!([first["heads"][0], second["heads"][0]]));
    assert_eq!(all["next"], "");
    let (_, past) = harness
        .post("/v1/close/heads", json!({"cursor": "bob", "limit": 10}))
        .await;
    assert_eq!(past, json!({"heads": [], "next": ""}));
    assert_eq!(harness.head_seq("alice"), 2);
}

#[tokio::test]
async fn final_heads_cover_an_open_batch() {
    let (provider, pause) = paused_store().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let record = google_record(&app);
    let password = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
    *lock(&pause) = Duration::from_millis(400);

    // A release writes entry 2. A forward joins the open batch while that write runs. The
    // orderly shutdown starts in that time: `close/heads` closes the open batch into entry 3,
    // writes it, and signs a final head that covers it.
    let released = release(&harness, &app, &password);
    let rest = async {
        provider.until_written(2).await;
        let forwarded = harness.forward(get(&app, &record, MESSAGES), b"");
        let closed = async {
            tokio::time::sleep(Duration::from_millis(60)).await;
            let (status, _) = harness.post("/v1/close", json!({})).await;
            assert_eq!(status, 200);
            harness
                .post("/v1/close/heads", json!({"cursor": "", "limit": 10}))
                .await
        };
        tokio::join!(forwarded, closed)
    };
    let ((status, released), (forwarded, (heads_status, heads))) = tokio::join!(released, rest);
    assert_eq!(status, 200);
    assert_eq!(released["log"]["seq"], 2);
    // The forward passed the common front before the shutdown: its entry is on the chain and
    // the request leaves after the store confirmed it.
    let forwarded = forwarded.unwrap();
    assert_eq!(
        forwarded.log,
        json!({"seq": 3, "index": 0, "created": true})
    );
    assert_eq!(heads_status, 200);
    let head = harness.verified(purpose::HEAD, &heads["heads"][0]);
    assert_eq!((&head["seq"], &head["final"]), (&json!(3), &json!(true)));

    let keys = keys_of(&provider, &harness, "user-1");
    assert_eq!(keys.len(), 3);
    assert_eq!((keys[2].kind, keys[2].count), (EntryKind::Use, 1));
    let signed: Signed = serde_json::from_value(heads["heads"][0].clone()).unwrap();
    let end = verify_index(
        &harness.node_public(),
        "user-1",
        &Head::EMPTY,
        &keys,
        &signed,
        None,
    )
    .unwrap();
    assert_eq!(end.seq, 3);
    assert!(!lock(&harness.node.account("user-1").unwrap()).has_open_events());
}
