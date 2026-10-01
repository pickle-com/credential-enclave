//! The credential log as a node writes it (protocol.md section 7, enclave.md 5.10 and 5.11):
//! an entry precedes the action it records, identical GET requests share an entry, entries wait
//! for their storage acknowledgement, and the orderly shutdown ends every chain with a `final`
//! head.

use std::sync::{Arc, Mutex};

use credential_enclave_protocol::app::verify_chain;
use credential_enclave_protocol::encoding::Signed;
use credential_enclave_protocol::log::Head;
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::{limits, purpose};
use serde_json::{json, Value};

use super::{provider, quiet_provider};
use crate::state::{lock, Node};
use crate::testing::{App, Harness, Reply};

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

#[tokio::test]
async fn the_entry_is_on_the_chain_before_the_provider_is_called() {
    // The stand-in looks at the chain of the account at the moment a request reaches it.
    let node_slot: Arc<Mutex<Option<Arc<Node>>>> = Arc::new(Mutex::new(None));
    let observed: Arc<Mutex<Vec<(String, u64, usize)>>> = Arc::new(Mutex::new(Vec::new()));
    let provider = provider({
        let node_slot = node_slot.clone();
        let observed = observed.clone();
        move |seen| {
            let node = lock(&node_slot).clone().expect("the node is running");
            let account = node.account("user-1").expect("the account has a grant");
            let account = lock(&account);
            lock(&observed).push((seen.target.clone(), account.head.seq, account.unacked.len()));
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

    // forward: entry 2 exists when the request arrives.
    let forwarded = harness
        .forward(get(&app, &record, MESSAGES), b"")
        .await
        .unwrap();
    assert_eq!(app.entry_body(&harness, &forwarded.entry)["seq"], 2);
    assert_eq!(
        lock(&observed).last().unwrap(),
        &("/gmail/v1/users/me/messages".to_string(), 2, 2)
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
        &("/token".to_string(), 3, 3)
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
        &("/revoke".to_string(), 4, 4)
    );
    assert_eq!(app.entry_body(&harness, &revoked["entry"])["seq"], 4);

    // The entry of the refused refresh was not in a response. The caller fetches it.
    let (_, listed) = harness
        .post(
            "/v1/log/entries",
            json!({"user_id": "user-1", "after_seq": 2}),
        )
        .await;
    let events: Vec<Value> = listed["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| app.event(&harness, entry))
        .collect();
    assert_eq!(events[0]["t"], "credential_refreshed");
    assert_eq!(events[0]["record_id"], record["id"]);
    assert_eq!(events[1]["t"], "connection_removed");
    assert_eq!(listed["head"]["seq"], 4);
}

#[tokio::test]
async fn identical_get_requests_within_300_seconds_share_one_entry() {
    let provider = quiet_provider().await;
    let harness = Harness::configured(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let record = google_record(&app);
    let address = format!("{MESSAGES}?maxResults=5");

    let first = harness
        .forward(get(&app, &record, &address), b"")
        .await
        .unwrap();
    let event = app.event(&harness, &first.entry);
    assert_eq!(
        event,
        json!({
            "t": "provider_request", "record_id": record["id"], "provider": "google_workspace",
            "method": "GET", "host": "gmail.googleapis.com",
            "path": "/gmail/v1/users/me/messages", "query": "maxResults=5",
            "body_bytes": 0, "body_sha256": "", "context": "cli:gog", "window_s": 300,
        })
    );

    // The same request again: sent, but without a new entry.
    let second = harness
        .forward(get(&app, &record, &address), b"")
        .await
        .unwrap();
    assert_eq!(second.status, 200);
    assert_eq!(second.entry, Value::Null);
    assert_eq!(provider.seen().len(), 2);
    assert_eq!(harness.head_seq("user-1"), 2);

    // Another query, another path and another record are other requests.
    for url in [
        format!("{MESSAGES}?maxResults=6"),
        format!("{MESSAGES}/m1?maxResults=5"),
    ] {
        let other = harness
            .forward(get(&app, &record, &url), b"")
            .await
            .unwrap();
        assert_ne!(other.entry, Value::Null, "{url}");
    }
    let second_record = google_record(&app);
    let other = harness
        .forward(get(&app, &second_record, &address), b"")
        .await
        .unwrap();
    assert_ne!(other.entry, Value::Null);
    assert_eq!(harness.head_seq("user-1"), 5);

    // Requests with another method are never merged and carry no window.
    let mut post = get(&app, &record, &address);
    post["method"] = json!("POST");
    for _ in 0..2 {
        let sent = harness.forward(post.clone(), b"{}").await.unwrap();
        let event = app.event(&harness, &sent.entry);
        assert_eq!(event["method"], "POST");
        assert_eq!(event["body_bytes"], 2);
        assert!(event.get("window_s").is_none());
    }
    assert_eq!(harness.head_seq("user-1"), 7);

    // Still inside the window: merged. After 300 seconds: a new entry.
    harness
        .node
        .clock
        .advance(limits::MERGE_WINDOW_S * 1000 - 5_000);
    let inside = harness
        .forward(get(&app, &record, &address), b"")
        .await
        .unwrap();
    assert_eq!(inside.entry, Value::Null);
    harness.node.clock.advance(6_000);
    let outside = harness
        .forward(get(&app, &record, &address), b"")
        .await
        .unwrap();
    assert_eq!(app.entry_body(&harness, &outside.entry)["seq"], 8);

    // Another account has its own chain and its own window.
    let other_app = App::new("user-2", 2);
    other_app.grant(&harness).await;
    let other_record = google_record(&other_app);
    let theirs = harness
        .forward(get(&other_app, &other_record, &address), b"")
        .await
        .unwrap();
    assert_eq!(other_app.entry_body(&harness, &theirs.entry)["seq"], 2);
}

#[tokio::test]
async fn sixty_four_unacknowledged_entries_stop_the_use_of_credentials() {
    let provider = quiet_provider().await;
    let harness = Harness::configured(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let password = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
    let token = google_record(&app);

    // The grant made entry 1. 63 releases fill the rest.
    for _ in 0..63 {
        assert_eq!(release(&harness, &app, &password).await.0, 200);
    }
    assert_eq!(harness.head_seq("user-1"), 64);

    // Every call that uses a credential is refused now, and nothing is sent or recorded.
    let (status, failure) = release(&harness, &app, &password).await;
    assert_eq!(
        (status, failure["code"].as_str()),
        (429, Some("log_backlog"))
    );
    let refused = harness
        .forward(get(&app, &token, MESSAGES), b"")
        .await
        .err()
        .unwrap();
    assert_eq!(
        (refused.0, refused.1["code"].as_str()),
        (429, Some("log_backlog"))
    );
    for path in ["/v1/refresh", "/v1/revoke-token"] {
        let (status, failure) = harness
            .post(
                path,
                json!({"user_id": "user-1", "record": token, "context": "c"}),
            )
            .await;
        assert_eq!(
            (status, failure["code"].as_str()),
            (429, Some("log_backlog")),
            "{path}"
        );
    }
    assert!(provider.seen().is_empty());
    assert_eq!(harness.head_seq("user-1"), 64);

    // Another account is not affected.
    let other = App::new("user-2", 2);
    other.grant(&harness).await;
    let theirs = other.record("vault_password", "vault", &json!({"value": "x"}));
    assert_eq!(release(&harness, &other, &theirs).await.0, 200);

    // The caller fetches what it missed.
    let (_, all) = harness
        .post(
            "/v1/log/entries",
            json!({"user_id": "user-1", "after_seq": 0}),
        )
        .await;
    assert_eq!(all["entries"].as_array().unwrap().len(), 64);
    assert_eq!(all["head"]["seq"], 64);
    let (_, tail) = harness
        .post(
            "/v1/log/entries",
            json!({"user_id": "user-1", "after_seq": 60}),
        )
        .await;
    let tail = tail["entries"].as_array().unwrap().clone();
    assert_eq!(tail.len(), 4);
    assert_eq!(app.entry_body(&harness, &tail[0])["seq"], 61);

    // An acknowledgement drops the entries up to its seq and frees room.
    let (status, acknowledged) = harness
        .post("/v1/log/ack", json!({"user_id": "user-1", "seq": 10}))
        .await;
    assert_eq!((status, acknowledged["unacked"].as_u64()), (200, Some(54)));
    assert_eq!(release(&harness, &app, &password).await.0, 200);
    let (_, rest) = harness
        .post(
            "/v1/log/entries",
            json!({"user_id": "user-1", "after_seq": 0}),
        )
        .await;
    assert_eq!(app.entry_body(&harness, &rest["entries"][0])["seq"], 11);
    let (_, acknowledged) = harness
        .post("/v1/log/ack", json!({"user_id": "user-1", "seq": 1000}))
        .await;
    assert_eq!(acknowledged["unacked"], 0);

    // An account the node does not know has no entries.
    let (status, none) = harness
        .post(
            "/v1/log/entries",
            json!({"user_id": "nobody", "after_seq": 0}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(none["entries"], json!([]));
    assert_eq!(none["head"]["seq"], 0);
    let (_, acknowledged) = harness
        .post("/v1/log/ack", json!({"user_id": "nobody", "seq": 5}))
        .await;
    assert_eq!(acknowledged["unacked"], 0);
}

#[tokio::test]
async fn a_backlog_does_not_stop_commands() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let password = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
    for _ in 0..63 {
        release(&harness, &app, &password).await;
    }
    assert_eq!(release(&harness, &app, &password).await.0, 429);

    // A revoke must always be possible, and a grant stays possible as well.
    let response = app.revoke(&harness).await;
    assert_eq!(
        harness.verified(purpose::REPLY, &response["reply"])["ok"],
        true
    );
    assert_eq!(app.entry_body(&harness, &response["entry"])["seq"], 65);
    let response = app.grant(&harness).await;
    assert_eq!(app.entry_body(&harness, &response["entry"])["seq"], 66);
}

#[tokio::test]
async fn the_chain_a_node_wrote_verifies_from_its_entries_and_its_head() {
    let provider = quiet_provider().await;
    let harness = Harness::configured(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let record = google_record(&app);
    let password = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
    harness
        .forward(get(&app, &record, MESSAGES), b"")
        .await
        .unwrap();
    release(&harness, &app, &password).await;
    app.revoke(&harness).await;

    let (_, listed) = harness
        .post(
            "/v1/log/entries",
            json!({"user_id": "user-1", "after_seq": 0}),
        )
        .await;
    let entries: Vec<Signed> = serde_json::from_value(listed["entries"].clone()).unwrap();
    assert_eq!(entries.len(), 4);
    let (_, state) = harness
        .post(
            "/v1/status",
            json!({"user_id": "user-1", "nonce": "bm9uY2U"}),
        )
        .await;
    let head: Signed = serde_json::from_value(state["head"].clone()).unwrap();
    let end = verify_chain(
        &harness.node_public(),
        "user-1",
        &Head::EMPTY,
        &entries,
        &head,
        Some("bm9uY2U"),
    )
    .unwrap();
    assert_eq!(end.seq, 4);
    let kinds: Vec<Value> = listed["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| app.event(&harness, entry)["t"].clone())
        .collect();
    assert_eq!(
        kinds,
        [
            "grant_accepted",
            "provider_request",
            "secret_released",
            "grant_revoked"
        ]
    );

    // With an entry withheld, the verification fails.
    let mut withheld = entries.clone();
    withheld.remove(1);
    assert!(verify_chain(
        &harness.node_public(),
        "user-1",
        &Head::EMPTY,
        &withheld,
        &head,
        Some("bm9uY2U"),
    )
    .is_err());
}

#[tokio::test]
async fn close_ends_every_chain_with_a_final_head() {
    let provider = quiet_provider().await;
    let harness = Harness::configured(&provider).await;
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
    assert!(provider.seen().is_empty());

    // The entries that wait are still handed out, and acknowledged.
    let (_, listed) = harness
        .post(
            "/v1/log/entries",
            json!({"user_id": "alice", "after_seq": 0}),
        )
        .await;
    let entries: Vec<Signed> = serde_json::from_value(listed["entries"].clone()).unwrap();
    assert_eq!(entries.len(), 2);

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

    // The final head closes the stored chain.
    let head: Signed = serde_json::from_value(first["heads"][0].clone()).unwrap();
    let end = verify_chain(
        &harness.node_public(),
        "alice",
        &Head::EMPTY,
        &entries,
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
async fn the_time_of_an_entry_is_never_before_the_time_of_the_entry_in_front_of_it() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    let account = harness.node.account_or_create("user-1");
    // A caller may read the node time before it takes the account lock. Whatever time it
    // then hands over, the times of the chain do not decrease with `seq`.
    let written: Vec<(u64, u64)> = [5_000u64, 3_000, 5_000, 7_000, 6_999]
        .into_iter()
        .map(|time_ms| {
            let entry = harness.node.append_entry_seeded(
                &mut lock(&account),
                "user-1",
                &app.keys.key_id(),
                &app.keys.log_pk(),
                time_ms,
                &json!({"t": "grant_revoked"}),
                &Secret::new([7; 32]),
            );
            let body = app.entry_body(&harness, &serde_json::to_value(entry).unwrap());
            (
                body["seq"].as_u64().unwrap(),
                body["time_ms"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        written,
        [(1, 5_000), (2, 5_000), (3, 5_000), (4, 7_000), (5, 7_000)]
    );
}
