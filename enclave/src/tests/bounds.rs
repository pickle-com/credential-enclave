//! The bounds of what a node holds of a call (enclave.md section 8): the share of the body
//! budget of a request, the longest record and the longest token a node handles, the room of
//! a token object, what a call that waits for a token address holds, and the connections a
//! node keeps.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::Method;
use credential_enclave_protocol::{limits, purpose};
use serde_json::{json, Value};

use super::{provider_and_log_store, provider_with_log_store};
use crate::api::{
    credential_share, COMMAND_SHARE_LIMIT_BYTES, REQUEST_SHARE_LIMIT_BYTES, REQUEST_WAIT,
};
use crate::frame;
use crate::oauth::{
    refresh_share, REFRESH_SHARE_BYTES, TOKEN_OBJECT_ROOM_BYTES, TOKEN_RESPONSE_SHARE_BYTES,
};
use crate::providers::Definitions;
use crate::room::Marks;
use crate::state::Limits;
use crate::testing::{request_share, App, Forwarded, Harness, Provider, Reply, Seen};

const PROFILE: &str = "https://gmail.googleapis.com/gmail/v1/users/me/profile";

/// The message of a call whose request would take a larger share than its budget gives one
/// request.
const NO_ROOM: &str = "the request takes more room than a node gives one request";

/// The message of a call whose record is above what a node reads.
const ABOVE: &str = "the plaintext of the record is above what a node reads; nothing was sent";

/// A node with the log store of the tests and the app of an account that granted on it.
async fn ready(provider: &Provider) -> (Harness, App) {
    let harness = Harness::new(provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    (harness, app)
}

/// A Google record of kind `oauth` with the given token object.
fn google_record(app: &App, token: Value) -> Value {
    let plaintext = json!({"token": token, "obtained_ms": 1});
    app.record("oauth", "google_workspace", &plaintext)
}

/// A token object with `count` arrays of one element beside its tokens: many values in a
/// text of few bytes.
fn of_many_values(count: usize) -> Value {
    json!({
        "access_token": "ya29.access", "refresh_token": "1//refresh",
        "more": vec![json!([0]); count],
    })
}

fn forward_meta(app: &App, record: &Value, method: &str, url: &str, headers: Value) -> Value {
    json!({
        "user_id": app.user_id, "record": record, "method": method, "url": url,
        "headers": headers, "context": "cli:gog", "timeout_ms": 5000,
    })
}

fn refresh_body(app: &App, record: &Value) -> Value {
    json!({"user_id": app.user_id, "record": record, "context": "refresh:scheduled"})
}

fn code(outcome: &(u16, Value)) -> (u16, &str) {
    (outcome.0, outcome.1["code"].as_str().unwrap_or_default())
}

fn failure(outcome: Result<Forwarded, (u16, Value)>) -> (u16, Value) {
    outcome.err().expect("the call must fail")
}

/// What the calls of the node hold of its body budget at this moment.
fn held(harness: &Harness) -> usize {
    harness.node.limits.body_budget_bytes - harness.node.body_budget.available_permits()
}

/// Takes all of the body budget of the node but `left` bytes, until the returned value is
/// dropped.
fn leave(harness: &Harness, left: usize) -> tokio::sync::OwnedSemaphorePermit {
    let taken = u32::try_from(harness.node.limits.body_budget_bytes - left).unwrap();
    harness
        .node
        .body_budget
        .clone()
        .try_acquire_many_owned(taken)
        .unwrap()
}

/// Runs `call` until `reached` says so. The call does not end before that.
async fn until<T>(call: &mut (impl Future<Output = T> + Unpin), reached: impl Fn() -> bool) {
    for _ in 0..4_000 {
        if reached() {
            return;
        }
        tokio::select! {
            _ = &mut *call => panic!("the call ended before what the test waited for"),
            () = tokio::time::sleep(Duration::from_millis(5)) => {}
        }
    }
    panic!("what the test waited for did not happen");
}

/// Runs `call` until the calls of the node hold `bytes` of its body budget. The call does
/// not end before that.
async fn until_held<T>(
    harness: &Harness,
    call: &mut (impl Future<Output = T> + Unpin),
    bytes: usize,
) {
    until(call, || held(harness) == bytes).await;
}

/// Waits until the calls of the node hold nothing of its body budget.
async fn until_free(harness: &Harness) {
    for _ in 0..4_000 {
        if held(harness) == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(held(harness), 0);
}

#[tokio::test]
async fn a_call_with_a_json_body_holds_the_share_of_its_request_until_it_ends() {
    // The log store confirms a write after 800 milliseconds while the test says so: a call
    // that waits for the confirmation of its entry holds what it holds for that long.
    let slow = Arc::new(AtomicBool::new(false));
    let quiet = |_: &Seen| Reply::json(200, &json!({"ok": true}));
    let store = {
        let slow = slow.clone();
        move |seen: &Seen| match slow.load(Ordering::SeqCst) {
            true => quiet(seen).after(Duration::from_millis(800)),
            false => quiet(seen),
        }
    };
    let provider = provider_and_log_store(quiet, store).await;
    let (harness, app) = ready(&provider).await;
    let record = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
    let release = |context: &str| {
        json!({
            "user_id": app.user_id, "record": record, "field": "password",
            "origin": "https://shop.example", "context": context,
        })
    };
    assert_eq!(held(&harness), 0);

    // The call waits for the log store: it holds the share of its request, a bound of its
    // parsed body and of what it makes of it, and nothing else. The share is computed from
    // the bytes of the body: ten times its bytes, and the room of its two objects and its
    // twelve commas four times.
    let body = release("fill:1");
    let share = request_share(&body);
    let text = serde_json::to_vec(&body).unwrap();
    assert_eq!(share, 10 * text.len() + 4 * (2 * 512 + 12 * 448) + 4096);
    slow.store(true, Ordering::SeqCst);
    {
        let call = harness.post("/v1/release", body);
        tokio::pin!(call);
        until_held(&harness, &mut call, share).await;
        let (status, released) = call.await;
        assert_eq!((status, &released["value"]), (200, &json!("hunter2")));
    }
    // The call has ended: the share is free.
    assert_eq!(held(&harness), 0);
    slow.store(false, Ordering::SeqCst);

    // A call that does not get the share of its request within the time of its admission
    // ends: it parsed nothing, created no entry and wrote nothing to the log store. The body
    // budget has room for the bytes of its body and for nothing else.
    let (entries, written) = (harness.last_seq("user-1"), provider.stored().len());
    let body = release("fill:2");
    let rest = leave(&harness, serde_json::to_vec(&body).unwrap().len());
    let started = Instant::now();
    let outcome = harness.post("/v1/release", body).await;
    assert_eq!(code(&outcome), (503, "capacity_unavailable"));
    assert!(started.elapsed() >= REQUEST_WAIT);
    assert_eq!(harness.last_seq("user-1"), entries);
    assert_eq!(provider.stored().len(), written);
    drop(rest);
    // A call that does not get the share of its body reads nothing of it.
    let rest = leave(&harness, 16);
    let started = Instant::now();
    let outcome = harness.post("/v1/release", release("fill:3")).await;
    assert_eq!(code(&outcome), (503, "capacity_unavailable"));
    assert!(started.elapsed() >= REQUEST_WAIT);
    assert_eq!(harness.last_seq("user-1"), entries);
    drop(rest);
    assert_eq!(held(&harness), 0);

    // With the budget free the same call passes.
    let (status, released) = harness.post("/v1/release", release("fill:4")).await;
    assert_eq!((status, &released["value"]), (200, &json!("hunter2")));
    assert_eq!(held(&harness), 0);
}

#[tokio::test]
async fn a_request_of_more_values_than_a_node_takes_is_not_parsed() {
    let provider = provider_with_log_store(|_| Reply::json(200, &json!({"ok": true}))).await;
    let (harness, app) = ready(&provider).await;
    let record = google_record(&app, json!({"access_token": "ya29.injected"}));

    // 20,000 empty arrays in 60 KB of a JSON body: the share of that request would be above
    // the share of the largest body.
    let many = vec![json!([]); 20_000];
    let body = json!({"user_id": app.user_id, "more": many});
    assert!(serde_json::to_vec(&body).unwrap().len() < 64 * 1024);
    assert!(request_share(&body) > REQUEST_SHARE_LIMIT_BYTES);
    let entries = harness.last_seq("user-1");
    for path in ["/v1/status", "/v1/release", "/v1/refresh"] {
        let (status, refused) = harness.post(path, body.clone()).await;
        assert_eq!(
            (status, &refused["code"]),
            (413, &json!("too_large")),
            "{path}"
        );
        assert_eq!(refused["message"], NO_ROOM, "{path}");
    }
    // The meta of a frame of that many values: of `forward`, of `forward/batch`, of
    // `vault/send` and of a mail call.
    let mut meta = forward_meta(&app, &record, "GET", PROFILE, json!([]));
    meta["more"] = json!(many);
    let (status, refused) = failure(harness.forward(meta.clone(), b"").await);
    assert_eq!((status, &refused["code"]), (413, &json!("too_large")));
    assert_eq!(refused["message"], NO_ROOM);
    meta["requests"] = json!([{"method": "GET", "url": PROFILE}]);
    let (status, refused) = harness
        .forward_batch(meta.clone(), b"")
        .await
        .err()
        .unwrap();
    assert_eq!((status, &refused["code"]), (413, &json!("too_large")));
    assert_eq!(refused["message"], NO_ROOM);
    let forward = Harness::new(&provider);
    let (status, _) = forward.post("/v1/config", json!({"role": "forward"})).await;
    assert_eq!(status, 200);
    let (status, refused) = forward.vault_send(meta.clone(), b"").await.err().unwrap();
    assert_eq!((status, &refused["code"]), (413, &json!("too_large")));
    assert_eq!(refused["message"], NO_ROOM);
    assert_eq!(held(&forward), 0);
    let (status, _, refused) = harness
        .send(Method::POST, "/v1/mail/read", frame::encode_head(&meta))
        .await;
    let refused: Value = serde_json::from_slice(&refused).unwrap();
    assert_eq!(
        (status.as_u16(), &refused["code"]),
        (413, &json!("too_large"))
    );
    assert_eq!(refused["message"], NO_ROOM);
    // The node parsed none of them: it created no entry and sent nothing.
    assert_eq!(harness.last_seq("user-1"), entries);
    assert!(provider.requests().is_empty());
    assert_eq!(held(&harness), 0);

    // A request below that bound is parsed, whatever it holds: 5,000 empty arrays are a body
    // a call takes, and the call holds the share of them while it runs.
    let fewer = vec![json!([]); 5_000];
    let body = json!({"user_id": app.user_id, "more": fewer});
    assert!(request_share(&body) < REQUEST_SHARE_LIMIT_BYTES);
    assert!(request_share(&body) > 100 * serde_json::to_vec(&body).unwrap().len());
    let (status, answered) = harness.post("/v1/status", body).await;
    assert_eq!(
        (status, &answered["grant"]["state"]),
        (200, &json!("active"))
    );
    assert_eq!(held(&harness), 0);
}

#[tokio::test]
async fn a_record_of_a_longer_ciphertext_than_a_node_reads_is_refused_before_it_is_opened() {
    let provider = provider_with_log_store(|_| Reply::json(200, &json!({"ok": true}))).await;
    let (harness, app) = ready(&provider).await;
    // The plaintext of a record is at most 65,536 bytes, and its `ct` at most 87,403
    // characters. A string of the token object that is no token fills the plaintext.
    let of_bytes = |bytes: usize| {
        let empty =
            json!({"token": {"access_token": "ya29.injected", "icon": ""}, "obtained_ms": 1});
        let filler = bytes - serde_json::to_vec(&empty).unwrap().len();
        google_record(
            &app,
            json!({"access_token": "ya29.injected", "icon": "i".repeat(filler)}),
        )
    };
    let longest = of_bytes(limits::RECORD_PLAINTEXT_BYTES);
    let longer = of_bytes(limits::RECORD_PLAINTEXT_BYTES + 1);
    assert_eq!(
        longest["ct"].as_str().unwrap().len(),
        limits::RECORD_CT_CHARS
    );
    assert_eq!(
        longer["ct"].as_str().unwrap().len(),
        limits::RECORD_CT_CHARS + 1
    );

    // The longest record is opened and used.
    let forwarded = harness
        .forward(forward_meta(&app, &longest, "GET", PROFILE, json!([])), b"")
        .await
        .unwrap();
    assert_eq!(forwarded.status, 200);
    assert_eq!(
        provider.only().header("authorization"),
        Some("Bearer ya29.injected")
    );

    // A record of one character more is `record_invalid` in every call that carries one,
    // whatever its kind says: the node does not open it, creates no entry and sends nothing.
    let (entries, written) = (harness.last_seq("user-1"), provider.stored().len());
    let invalid = (422, json!("record_invalid"));
    let meta = forward_meta(&app, &longer, "GET", PROFILE, json!([]));
    let refused = failure(harness.forward(meta.clone(), b"").await);
    assert_eq!((refused.0, refused.1["code"].clone()), invalid);
    let mut batch = meta.clone();
    batch["requests"] = json!([{"method": "GET", "url": PROFILE}]);
    let refused = harness.forward_batch(batch, b"").await.err().unwrap();
    assert_eq!((refused.0, refused.1["code"].clone()), invalid);
    let with_kind = |kind: &str, provider: &str| {
        let mut record = longer.clone();
        record["kind"] = json!(kind);
        record["provider"] = json!(provider);
        record
    };
    for (path, body) in [
        ("/v1/refresh", refresh_body(&app, &longer)),
        ("/v1/revoke-token", refresh_body(&app, &longer)),
        (
            "/v1/oauth/merge",
            json!({"user_id": app.user_id, "record": longer, "previous": longest}),
        ),
        (
            "/v1/oauth/merge",
            json!({"user_id": app.user_id, "record": longest, "previous": longer}),
        ),
        (
            "/v1/release",
            json!({
                "user_id": app.user_id, "record": with_kind("vault_password", "vault"),
                "field": "password", "origin": "https://shop.example",
            }),
        ),
    ] {
        let (status, refused) = harness.post(path, body).await;
        assert_eq!((status, refused["code"].clone()), invalid, "{path}");
    }
    let mail_meta = json!({
        "user_id": app.user_id, "record": with_kind("app_password", "naver_mail"),
        "context": "cli:naver-mail", "request": {"action": "folders"},
    });
    let (status, _, refused) = harness
        .send(
            Method::POST,
            "/v1/mail/read",
            frame::encode_head(&mail_meta),
        )
        .await;
    let refused: Value = serde_json::from_slice(&refused).unwrap();
    assert_eq!((status.as_u16(), refused["code"].clone()), invalid);
    assert_eq!(harness.last_seq("user-1"), entries);
    assert_eq!(provider.stored().len(), written);
    assert_eq!(provider.requests().len(), 1);
    assert_eq!(held(&harness), 0);
}

#[tokio::test]
async fn a_token_longer_than_a_node_handles_is_refused_after_the_entry_of_its_call() {
    let provider = provider_with_log_store(|_| Reply::json(200, &json!({"ok": true}))).await;
    let (harness, app) = ready(&provider).await;
    let of_bytes = |bytes: usize| "t".repeat(bytes);
    let longest = google_record(
        &app,
        json!({"access_token": of_bytes(limits::TOKEN_BYTES), "refresh_token": "1//refresh"}),
    );
    let longer = google_record(
        &app,
        json!({"access_token": of_bytes(limits::TOKEN_BYTES + 1), "refresh_token": "1//refresh"}),
    );

    // A token of 16,384 bytes is injected.
    let forwarded = harness
        .forward(forward_meta(&app, &longest, "GET", PROFILE, json!([])), b"")
        .await
        .unwrap();
    assert_eq!(forwarded.status, 200);
    let bearer = format!("Bearer {}", of_bytes(limits::TOKEN_BYTES));
    assert_eq!(
        provider.only().header("authorization"),
        Some(bearer.as_str())
    );

    // A token of one byte more: the call creates its entry, the log store confirms it, and
    // the call ends with `record_invalid`. Nothing is sent. The judgement depends on the
    // content of the plaintext, so it has an entry.
    let entries = harness.last_seq("user-1");
    let url = format!("{PROFILE}?n=1");
    let refused = failure(
        harness
            .forward(forward_meta(&app, &longer, "GET", &url, json!([])), b"")
            .await,
    );
    assert_eq!(
        (refused.0, &refused.1["code"]),
        (422, &json!("record_invalid"))
    );
    assert_eq!(refused.1["message"], ABOVE);
    assert_eq!(harness.last_seq("user-1"), entries + 1);
    let chain = provider.chain("user-1", &harness.node.node);
    let event = app.event(&harness, &chain.last().unwrap().entry);
    assert_eq!(
        (&event["t"], &event["query"]),
        (&json!("provider_request"), &json!("n=1"))
    );
    assert_eq!(provider.requests().len(), 1);

    // The same for a call that asks for a stream and for every request of a batch.
    let mut streamed = forward_meta(&app, &longer, "GET", &format!("{PROFILE}?n=2"), json!([]));
    streamed["stream"] = json!(true);
    let refused = harness.forward_stream(streamed, b"").await.err().unwrap();
    assert_eq!((refused.0, &refused.1["message"]), (422, &json!(ABOVE)));
    let mut batch = forward_meta(&app, &longer, "GET", PROFILE, json!([]));
    batch["requests"] = json!([
        {"method": "GET", "url": format!("{PROFILE}?n=3")},
        {"method": "POST", "url": format!("{PROFILE}?n=4"), "body_bytes": 2},
    ]);
    let refused = harness.forward_batch(batch, b"{}").await.err().unwrap();
    assert_eq!((refused.0, &refused.1["message"]), (422, &json!(ABOVE)));
    assert_eq!(refused.1.get("index"), None);
    assert_eq!(harness.last_seq("user-1"), entries + 3);
    assert_eq!(provider.requests().len(), 1);
    assert_eq!(held(&harness), 0);

    // Before its record is open, such a call takes the share of the longest token a node
    // handles, not of the longest string its record could hold: with room for its frame,
    // for the share of its request and for that share of its credential, the call goes on
    // to its entry.
    let meta = forward_meta(&app, &longer, "GET", &format!("{PROFILE}?n=5"), json!([]));
    let rest = leave(
        &harness,
        frame::encode_head(&meta).len()
            + request_share(&meta)
            + credential_share(limits::TOKEN_BYTES, 1, 1),
    );
    let refused = failure(harness.forward(meta, b"").await);
    assert_eq!((refused.0, &refused.1["message"]), (422, &json!(ABOVE)));
    drop(rest);
    assert_eq!(held(&harness), 0);
}

#[tokio::test]
async fn a_record_a_node_does_not_read_is_no_token_for_refresh_revoke_and_merge() {
    let provider = provider_with_log_store(|_| Reply::json(200, &json!({"ok": true}))).await;
    let (harness, app) = ready(&provider).await;
    let longer = "t".repeat(limits::TOKEN_BYTES + 1);
    let plain = google_record(
        &app,
        json!({"access_token": "ya29.access", "refresh_token": "1//refresh"}),
    );
    // A refresh token that is too long, an access token that is too long beside a refresh
    // token that is not, and a plaintext whose parsed form would take more room than a token
    // object may take.
    let above = [
        google_record(
            &app,
            json!({"access_token": "ya29.access", "refresh_token": longer}),
        ),
        google_record(
            &app,
            json!({"access_token": longer, "refresh_token": "1//refresh"}),
        ),
        google_record(&app, of_many_values(400)),
    ];
    let within = google_record(&app, of_many_values(200));

    for record in &above {
        // `refresh`: the entry of the call, then `record_invalid`, and no call of the token
        // address.
        let entries = harness.last_seq("user-1");
        let outcome = harness
            .post("/v1/refresh", refresh_body(&app, record))
            .await;
        assert_eq!(code(&outcome), (422, "record_invalid"));
        assert_eq!(outcome.1["message"], ABOVE);
        assert_eq!(harness.last_seq("user-1"), entries + 1);
        let chain = provider.chain("user-1", &harness.node.node);
        let event = app.event(&harness, &chain.last().unwrap().entry);
        assert_eq!(event["t"], "credential_refreshed");

        // `revoke-token`: the node sends no token of such a record, and the entry says so.
        let (status, revoked) = harness
            .post("/v1/revoke-token", refresh_body(&app, record))
            .await;
        assert_eq!((status, &revoked["revoked"]), (200, &json!(false)));
        let event = app.logged(&harness, &provider, &revoked["log"]);
        assert_eq!(
            (&event["t"], &event["provider_revoke"]),
            (&json!("connection_removed"), &json!(false))
        );

        // `oauth/merge` creates no entry: it refuses such a record as either of its two.
        let entries = harness.last_seq("user-1");
        for (record, previous) in [(record, &plain), (&plain, record)] {
            let body = json!({"user_id": app.user_id, "record": record, "previous": previous});
            let outcome = harness.post("/v1/oauth/merge", body).await;
            assert_eq!(code(&outcome), (422, "record_invalid"));
        }
        assert_eq!(harness.last_seq("user-1"), entries);
    }
    assert!(provider.requests().is_empty());

    // A plaintext of many values within the room of a token object is read: the refresh
    // calls the token address.
    let outcome = harness
        .post("/v1/refresh", refresh_body(&app, &within))
        .await;
    assert_eq!(outcome.0, 502, "{outcome:?}");
    assert_eq!(provider.requests().len(), 1);
    // A call of `forward` with a plaintext above that room ends after its entry as well.
    let entries = harness.last_seq("user-1");
    let meta = forward_meta(&app, &above[2], "GET", PROFILE, json!([]));
    let refused = failure(harness.forward(meta, b"").await);
    assert_eq!((refused.0, &refused.1["message"]), (422, &json!(ABOVE)));
    assert_eq!(harness.last_seq("user-1"), entries + 1);
    assert_eq!(provider.requests().len(), 1);
    assert_eq!(held(&harness), 0);
}

/// A configured node with the log store of the tests whose `refresh` waits 600 milliseconds
/// for the token address and keeps receiving a late response for 6 seconds.
async fn late_node(provider: &Provider) -> Harness {
    let harness = Harness::with(
        provider,
        Definitions::embedded(),
        Limits {
            token_timeout: Duration::from_millis(600),
            token_late_limit: Duration::from_secs(6),
            ..Limits::default()
        },
    );
    harness.use_log_store().await;
    harness
}

#[tokio::test]
async fn a_refresh_holds_the_share_of_its_plaintext_and_of_the_token_response() {
    // The token address answers a refresh after 1,500 milliseconds: after the time limit of
    // the call, before the late limit.
    let provider = provider_with_log_store(|_| {
        let renewed = json!({"access_token": "ya29.renewed", "expires_in": 3599});
        Reply::json(200, &renewed).after(Duration::from_millis(1500))
    })
    .await;
    let harness = late_node(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let token = json!({"access_token": "ya29.access", "refresh_token": "1//refresh"});
    let record_of = |obtained_ms: u64| {
        let plaintext = json!({"token": token, "obtained_ms": obtained_ms});
        let room = Marks::of(&serde_json::to_vec(&plaintext).unwrap()).value_room();
        (app.record("oauth", "google_workspace", &plaintext), room)
    };
    assert_eq!(REFRESH_SHARE_BYTES, TOKEN_OBJECT_ROOM_BYTES + 3 * 65_536);
    assert_eq!(TOKEN_RESPONSE_SHARE_BYTES, 3 * 65_536);

    // The call waits for the token address. It holds the share of its request, and the
    // share of what it holds while it waits: its parsed plaintext, and the response while
    // it arrives. What it took for the largest plaintext a node parses is free again.
    let (record, room) = record_of(1);
    let body = refresh_body(&app, &record);
    let of_the_request = request_share(&body);
    assert!(room < 4096, "{room}");
    {
        let call = harness.post("/v1/refresh", body);
        tokio::pin!(call);
        until_held(&harness, &mut call, of_the_request + refresh_share(room)).await;
        // The call gives up at its time limit, and its exchange goes on: the share of the
        // request is free, and the exchange holds its share until it has ended.
        let outcome = call.await;
        assert_eq!(code(&outcome), (502, "refresh_failed"));
        assert_eq!(outcome.1["provider_status"], 0);
    }
    assert_eq!(held(&harness), refresh_share(room));
    assert_eq!(harness.health().await["refresh"]["late_inflight"], 1);
    until_free(&harness).await;
    assert_eq!(provider.requests().len(), 1);

    // A call whose caller goes away after the token address received its request ends its
    // exchange: it holds nothing.
    let (record, room) = record_of(2);
    let body = refresh_body(&app, &record);
    let of_the_request = request_share(&body);
    {
        let call = harness.post("/v1/refresh", body);
        tokio::pin!(call);
        until_held(&harness, &mut call, of_the_request + refresh_share(room)).await;
        until(&mut call, || provider.requests().len() == 2).await;
    }
    until_free(&harness).await;

    // A call that does not get that share within the time of its admission ends: it created
    // no event (none in an entry, and none in the open batch of the account) and called no
    // provider. The body budget has room for its body and for the share of its request, and
    // for less than the share of a refresh.
    let entries = harness.last_seq("user-1");
    let log = super::seven_counts(&harness.health().await["log"]);
    assert_eq!(log["open_batches"], 0);
    let (record, _) = record_of(3);
    let body = refresh_body(&app, &record);
    let rest = leave(&harness, request_share(&body) + REFRESH_SHARE_BYTES - 1);
    let started = Instant::now();
    let outcome = harness.post("/v1/refresh", body.clone()).await;
    assert_eq!(code(&outcome), (503, "capacity_unavailable"));
    assert!(started.elapsed() >= REQUEST_WAIT);
    assert_eq!(harness.last_seq("user-1"), entries);
    assert_eq!(super::seven_counts(&harness.health().await["log"]), log);
    assert_eq!(provider.requests().len(), 2);
    drop(rest);
    // With exactly that share free the call goes on to its entry and to the token address.
    let rest = leave(&harness, request_share(&body) + REFRESH_SHARE_BYTES);
    let outcome = harness.post("/v1/refresh", body).await;
    assert_eq!(code(&outcome), (502, "refresh_failed"));
    assert_eq!(harness.last_seq("user-1"), entries + 1);
    drop(rest);
    until_free(&harness).await;
    assert_eq!(provider.requests().len(), 3);
}

/// Begins an authorization of `google_workspace` and returns its state.
async fn begun(harness: &Harness, app: &App) -> String {
    let (status, begun) = harness
        .post(
            "/v1/oauth/begin",
            json!({
                "user_id": app.user_id, "provider": "google_workspace",
                "operator_state": "operator.state_1-x", "params": {}, "client_id": "",
            }),
        )
        .await;
    assert_eq!(status, 200, "{begun}");
    begun["state"].as_str().unwrap().to_string()
}

fn complete_body(app: &App, state: &str) -> Value {
    json!({"user_id": app.user_id, "state": state, "code": "4/authorization-code"})
}

#[tokio::test]
async fn an_exchange_holds_the_share_of_the_token_response() {
    // The token address answers after 600 milliseconds.
    let provider = provider_with_log_store(|_| {
        let issued = json!({"access_token": "ya29.first", "refresh_token": "1//first"});
        Reply::json(200, &issued).after(Duration::from_millis(600))
    })
    .await;
    let (harness, app) = ready(&provider).await;

    // The call waits for the token address: it holds the share of its request and the share
    // of the token response.
    let state = begun(&harness, &app).await;
    let body = complete_body(&app, &state);
    let of_the_request = request_share(&body);
    {
        let call = harness.post("/v1/oauth/complete", body);
        tokio::pin!(call);
        until_held(
            &harness,
            &mut call,
            of_the_request + TOKEN_RESPONSE_SHARE_BYTES,
        )
        .await;
        let (status, issued) = call.await;
        assert_eq!(status, 200, "{issued}");
        assert_eq!(issued["record"]["kind"], "oauth");
    }
    assert_eq!(held(&harness), 0);

    // A call that does not get the share of the token response within the time of its
    // admission ends: it called no provider, and it did not use its pending authorization
    // up. The same call passes once the node has room.
    let calls = provider.requests().len();
    let state = begun(&harness, &app).await;
    let body = complete_body(&app, &state);
    let rest = leave(
        &harness,
        request_share(&body) + TOKEN_RESPONSE_SHARE_BYTES - 1,
    );
    let started = Instant::now();
    let outcome = harness.post("/v1/oauth/complete", body.clone()).await;
    assert_eq!(code(&outcome), (503, "capacity_unavailable"));
    assert!(started.elapsed() >= REQUEST_WAIT);
    assert_eq!(provider.requests().len(), calls);
    drop(rest);
    let (status, issued) = harness.post("/v1/oauth/complete", body).await;
    assert_eq!(status, 200, "{issued}");
    assert_eq!(provider.requests().len(), calls + 1);
    assert_eq!(held(&harness), 0);
}

#[tokio::test]
async fn a_token_response_above_the_bounds_of_a_node_makes_no_record() {
    // The token address answers with the response the test set last.
    let answer = Arc::new(std::sync::Mutex::new(json!({})));
    let provider = {
        let answer = answer.clone();
        provider_with_log_store(move |_| Reply::json(200, &answer.lock().unwrap())).await
    };
    let (harness, app) = ready(&provider).await;
    let set = |response: Value| *answer.lock().unwrap() = response;
    let longest = "t".repeat(limits::TOKEN_BYTES);
    let longer = format!("{longest}t");
    let not_taken = |outcome: &(u16, Value), code: &str, status: u16| {
        assert_eq!(outcome.0, 502, "{outcome:?}");
        assert_eq!(outcome.1["code"], code, "{outcome:?}");
        assert_eq!(outcome.1["provider_status"], status, "{outcome:?}");
        assert_eq!(outcome.1["provider_error"], "", "{outcome:?}");
    };

    // An exchange. A response within the bounds becomes a record: tokens of 16,384 bytes,
    // and a long string that is no token.
    set(json!({"access_token": longest, "refresh_token": longest, "icon": "i".repeat(20_000)}));
    let state = begun(&harness, &app).await;
    let (status, issued) = harness
        .post("/v1/oauth/complete", complete_body(&app, &state))
        .await;
    assert_eq!(status, 200, "{issued}");
    let record = issued["record"].clone();
    let entries = harness.last_seq("user-1");
    // A token of one byte more, a response whose parsed form would take more room than a
    // token object may take, and a response of more bytes than a node reads: the exchange
    // fails, and the node creates no record and no entry.
    for (response, status) in [
        (json!({"access_token": longer}), 200),
        (
            json!({"access_token": "ya29.a", "refresh_token": longer}),
            200,
        ),
        (json!({"access_token": "ya29.a", "id_token": longer}), 200),
        (of_many_values(400), 200),
        (
            json!({"access_token": "ya29.a", "icon": "i".repeat(70_000)}),
            0,
        ),
    ] {
        set(response);
        let state = begun(&harness, &app).await;
        let outcome = harness
            .post("/v1/oauth/complete", complete_body(&app, &state))
            .await;
        not_taken(&outcome, "exchange_failed", status);
    }
    assert_eq!(harness.last_seq("user-1"), entries);

    // A refresh: the entry of the call is on the chain, and a response above the bounds
    // gives no record.
    for (response, status) in [
        (json!({"access_token": longer}), 200),
        (
            json!({"access_token": "ya29.a", "refresh_token": longer}),
            200,
        ),
        (of_many_values(400), 200),
        (
            json!({"access_token": "ya29.a", "icon": "i".repeat(70_000)}),
            0,
        ),
    ] {
        set(response);
        let entries = harness.last_seq("user-1");
        let outcome = harness
            .post("/v1/refresh", refresh_body(&app, &record))
            .await;
        not_taken(&outcome, "refresh_failed", status);
        assert_eq!(harness.last_seq("user-1"), entries + 1);
    }
    // A response within the bounds whose merge with the token of the record is a plaintext
    // above them: the record holds 20,000 bytes that are no token, and the response adds
    // 30,000 under another key.
    set(json!({"access_token": "ya29.renewed", "other": "o".repeat(30_000)}));
    let outcome = harness
        .post("/v1/refresh", refresh_body(&app, &record))
        .await;
    not_taken(&outcome, "refresh_failed", 200);
    // The same record with a response that fits is renewed.
    set(json!({"access_token": "ya29.renewed", "expires_in": 3599}));
    let (status, renewed) = harness
        .post("/v1/refresh", refresh_body(&app, &record))
        .await;
    assert_eq!(status, 200, "{renewed}");
    assert_eq!(renewed["record"]["id"], record["id"]);
    assert_eq!(held(&harness), 0);
}

#[tokio::test]
async fn a_connection_that_carried_a_long_head_is_not_kept() {
    let provider =
        provider_with_log_store(|_| Reply::json(200, &json!({"ok": true})).keep_alive()).await;
    let (harness, app) = ready(&provider).await;
    let record = google_record(&app, json!({"access_token": "ya29.injected"}));
    let idle = || {
        harness
            .node
            .egress
            .provider_idle
            .idle_count("user-1", "gmail.googleapis.com")
    };
    // The connections the node asked its platform for to the host of the requests.
    let opened = || {
        harness
            .platform
            .connections()
            .iter()
            .filter(|(host, _)| host == "gmail.googleapis.com")
            .count()
    };
    let call = |query: &str, header_bytes: usize| {
        let headers = json!([["x-note", "n".repeat(header_bytes)]]);
        let url = format!("{PROFILE}?{query}");
        harness.forward(forward_meta(&app, &record, "POST", &url, headers), b"{}")
    };

    // A request with a head of common length: its connection is kept for the next request
    // of the account and the host.
    assert_eq!(call("n=1", 100).await.unwrap().status, 200);
    assert_eq!((opened(), idle()), (1, 1));
    // A request whose head is longer than 32 KiB goes over that connection, and the
    // connection is closed when its response has ended: the buffer the head was written
    // from belongs to the connection.
    assert_eq!(call("n=2", 40_000).await.unwrap().status, 200);
    assert_eq!((opened(), idle()), (1, 0));
    assert_eq!(
        provider.requests()[1].header("x-note").map(str::len),
        Some(40_000)
    );
    assert_eq!(
        harness.health().await["egress"]["idle_reuses"]["provider"],
        1
    );
    // The next request opens a connection, which is kept again. A head below the bound
    // keeps its connection.
    assert_eq!(call("n=3", 100).await.unwrap().status, 200);
    assert_eq!((opened(), idle()), (2, 1));
    assert_eq!(call("n=4", 31_000).await.unwrap().status, 200);
    assert_eq!((opened(), idle()), (2, 1));
    assert_eq!(
        harness.health().await["egress"]["idle_reuses"]["provider"],
        2
    );
    assert_eq!(held(&harness), 0);
}

#[tokio::test]
async fn a_command_does_not_wait_for_the_body_budget() {
    // The whole body budget of the node is taken, as the bodies of the calls that use a
    // credential take it. A call whose request is held under that budget waits and ends
    // with `capacity_unavailable`.
    let provider = provider_with_log_store(|_| Reply::json(200, &json!({"ok": true}))).await;
    let (harness, app) = ready(&provider).await;
    let status = || harness.post("/v1/status", json!({"user_id": "user-1"}));
    let rest = leave(&harness, 0);
    let started = Instant::now();
    assert_eq!(code(&status().await), (503, "capacity_unavailable"));
    assert!(started.elapsed() >= REQUEST_WAIT);

    // `health` reads no body and is answered. The two calls of a command are answered as
    // well, since their requests are held under the command budget: the app gets a
    // challenge and the node takes its revoke, and after that its grant.
    assert_eq!(harness.health().await["configured"], true);
    let revoked = app.revoke(&harness).await;
    let reply = harness.verified(purpose::REPLY, &revoked["reply"]);
    assert_eq!(
        (&reply["type"], &reply["ok"]),
        (&json!("revoke_reply"), &json!(true))
    );
    assert_eq!(revoked["grant"]["state"], "revoked");
    app.grant(&harness).await;
    assert_eq!(code(&status().await), (503, "capacity_unavailable"));

    drop(rest);
    let (status, answered) = status().await;
    assert_eq!(
        (status, &answered["grant"]["state"]),
        (200, &json!("active"))
    );
    assert_eq!(held(&harness), 0);
}

#[tokio::test]
async fn a_command_holds_the_share_of_its_request_of_the_command_budget() {
    // The log store confirms a write after 800 milliseconds while the test says so: a grant
    // waits for the confirmation of its entry.
    let slow = Arc::new(AtomicBool::new(false));
    let quiet = |_: &Seen| Reply::json(200, &json!({"ok": true}));
    let store = {
        let slow = slow.clone();
        move |seen: &Seen| match slow.load(Ordering::SeqCst) {
            true => quiet(seen).after(Duration::from_millis(800)),
            false => quiet(seen),
        }
    };
    let provider = provider_and_log_store(quiet, store).await;
    let harness = Harness::new(&provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    let budget = harness.node.limits.command_budget_bytes;
    assert_eq!(budget, 32 * 1024 * 1024);
    let of_commands = || budget - harness.node.command_budget.available_permits();
    let command = |envelope: Value| json!({"user_id": app.user_id, "envelope": envelope});
    let answered = |outcome: &(u16, Value), kind: &str| {
        assert_eq!(outcome.0, 200, "{outcome:?}");
        let reply = harness.verified(purpose::REPLY, &outcome.1["reply"]);
        assert_eq!((&reply["type"], &reply["ok"]), (&json!(kind), &json!(true)));
    };

    // A grant waits for the log store. It holds the share of its request of the command
    // budget, and nothing of the body budget. A grant in its envelope is a body of about
    // 1 KB, and its share is some tens of kibibytes.
    let attested = app.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let body = command(app.grant_envelope(&attested, not_after_ms));
    let bytes = serde_json::to_vec(&body).unwrap().len();
    assert!((768..1536).contains(&bytes), "{bytes}");
    let share = request_share(&body);
    assert!((16 * 1024..64 * 1024).contains(&share), "{share}");
    assert_eq!((of_commands(), held(&harness)), (0, 0));
    slow.store(true, Ordering::SeqCst);
    {
        let call = harness.post("/v1/messages", body);
        tokio::pin!(call);
        until(&mut call, || of_commands() == share).await;
        assert_eq!(held(&harness), 0);
        answered(&call.await, "grant_reply");
    }
    slow.store(false, Ordering::SeqCst);
    assert_eq!((of_commands(), held(&harness)), (0, 0));

    // A command that does not get the share of its request within the time of its
    // admission ends: the node parsed nothing of it, so its challenge is not used, and the
    // same command passes once the node has room.
    let attested = app.attest(&harness).await;
    let body = command(app.revoke_envelope(&attested));
    let left = request_share(&body) - 1;
    let rest = harness
        .node
        .command_budget
        .clone()
        .try_acquire_many_owned(u32::try_from(budget - left).unwrap())
        .unwrap();
    let started = Instant::now();
    let outcome = harness.post("/v1/messages", body.clone()).await;
    assert_eq!(code(&outcome), (503, "capacity_unavailable"));
    assert!(started.elapsed() >= REQUEST_WAIT);
    drop(rest);
    let outcome = harness.post("/v1/messages", body).await;
    answered(&outcome, "revoke_reply");
    assert_eq!(outcome.1["grant"]["state"], "revoked");
    assert_eq!(of_commands(), 0);

    // The share of one request of a command is at most 256 KiB: a longer request, and a
    // request of more values than that share holds, is not parsed.
    let long = command(json!({"v": 1, "node": "n", "enc": "e", "ct": "c".repeat(30_000)}));
    let many = json!({"user_id": app.user_id, "more": vec![json!([]); 200]});
    let nonce = json!({"nonce": "n".repeat(30_000)});
    assert!(serde_json::to_vec(&many).unwrap().len() < 1024);
    for (path, body) in [
        ("/v1/messages", long),
        ("/v1/messages", many.clone()),
        ("/v1/attestation", nonce),
        ("/v1/attestation", many),
    ] {
        assert!(request_share(&body) > COMMAND_SHARE_LIMIT_BYTES, "{path}");
        let (status, refused) = harness.post(path, body).await;
        assert_eq!(
            (status, &refused["code"]),
            (413, &json!("too_large")),
            "{path}"
        );
        assert_eq!(refused["message"], NO_ROOM, "{path}");
    }
    assert_eq!((of_commands(), held(&harness)), (0, 0));
}
