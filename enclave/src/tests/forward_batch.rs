//! `forward/batch` (enclave.md 5.8b): one entry names every request of the batch before any
//! of them leaves, the requests leave a few at a time over the connections of the account, a
//! request that fails the address check refuses the whole call with its index, identical GET
//! requests inside a batch share one event, the open batch splits a batch at its cap, one
//! failed request leaves the other results intact, and the bodies of the results together stay
//! under the body limit.

use std::time::{Duration, Instant};

use credential_enclave_protocol::limits;
use credential_enclave_protocol::log::EntryKind;
use serde_json::{json, Value};

use super::{provider_with_log_store, quiet_provider_and_log_store};
use crate::providers::Definitions;
use crate::state::{lock, Limits};
use crate::testing::{App, BatchOutcome, Harness, Provider, Reply, LOG_HOST};

const MESSAGES: &str = "https://gmail.googleapis.com/gmail/v1/users/me/messages";

fn google_record(app: &App) -> Value {
    app.record(
        "oauth",
        "google_workspace",
        &json!({
            "token": {"access_token": "ya29.injected", "refresh_token": "1//refresh"},
            "obtained_ms": 1,
        }),
    )
}

/// The meta of a batch of GET requests without bodies.
fn batch(app: &App, record: &Value, urls: &[String]) -> Value {
    let requests: Vec<Value> = urls
        .iter()
        .map(|url| json!({"method": "GET", "url": url, "headers": [], "body_bytes": 0}))
        .collect();
    json!({
        "user_id": app.user_id, "record": record, "context": "cli:gog", "timeout_ms": 5000,
        "requests": requests,
    })
}

/// `count` addresses of messages: `.../messages/m0`, `.../messages/m1`, ...
fn messages(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("{MESSAGES}/m{index}"))
        .collect()
}

async fn node_with_log_store(provider: &Provider) -> (Harness, App, Value) {
    let harness = Harness::new(provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let record = google_record(&app);
    (harness, app, record)
}

fn logs_of(outcomes: &[BatchOutcome]) -> Vec<Value> {
    outcomes.iter().map(|outcome| outcome.log.clone()).collect()
}

/// The provider requests the stand-in saw, in order.
fn provider_targets(provider: &Provider) -> Vec<String> {
    provider
        .seen()
        .into_iter()
        .filter(|seen| seen.server_name != LOG_HOST)
        .map(|seen| seen.target)
        .collect()
}

/// True when every write to the store came before every provider request, in the order the
/// stand-in saw them.
fn writes_precede_requests(provider: &Provider, writes_after: usize) -> bool {
    let seen = provider.seen();
    let last_write = seen
        .iter()
        .rposition(|seen| seen.server_name == LOG_HOST)
        .unwrap();
    let first_request = seen
        .iter()
        .skip(writes_after)
        .position(|seen| seen.server_name != LOG_HOST)
        .map(|at| at + writes_after);
    first_request.is_none_or(|first| first > last_write)
}

#[tokio::test]
async fn one_entry_names_every_request_before_any_leaves() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app, record) = node_with_log_store(&provider).await;
    let urls = messages(limits::FORWARD_BATCH_REQUESTS);
    let before = provider.seen().len();

    let outcomes = harness
        .forward_batch(batch(&app, &record, &urls), b"")
        .await
        .unwrap();
    assert_eq!(outcomes.len(), limits::FORWARD_BATCH_REQUESTS);
    // One result per request, in order, each 200 and each named by its index in entry 2.
    for (index, outcome) in outcomes.iter().enumerate() {
        assert_eq!(outcome.status, Some(200), "{index}");
        assert_eq!(outcome.error, None);
        assert_eq!(
            outcome.log,
            json!({"seq": 2, "index": index, "created": true})
        );
        assert_eq!(outcome.body, br#"{"ok":true}"#);
    }
    // Entry 2 holds the hundred events in the order of the requests, and the store confirmed
    // it before the first request reached the provider.
    let chain = provider.chain("user-1", &harness.node.node);
    assert_eq!(chain.len(), 2);
    assert_eq!(
        (chain[1].parts().kind, chain[1].parts().count as usize),
        (EntryKind::Use, limits::FORWARD_BATCH_REQUESTS)
    );
    let events = app.events(&harness, &chain[1].entry);
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event["t"], "provider_request");
        assert_eq!(
            event["path"],
            format!("/gmail/v1/users/me/messages/m{index}")
        );
        assert_eq!(event["window_s"], 300);
    }
    assert!(writes_precede_requests(&provider, before));
    let mut targets = provider_targets(&provider);
    targets.sort();
    let mut expected: Vec<String> = (0..limits::FORWARD_BATCH_REQUESTS)
        .map(|index| format!("/gmail/v1/users/me/messages/m{index}"))
        .collect();
    expected.sort();
    assert_eq!(targets, expected);
    assert_eq!(harness.head_seq("user-1"), 2);

    let log = harness.health().await["log"].clone();
    assert_eq!(
        log,
        json!({
            "entries": 2, "events": 101, "writes": 2, "write_failures": 0, "open_batches": 0,
            "batch_calls": 1, "batch_requests": 100,
        })
    );
    // The call took one forward slot and gave it back.
    assert_eq!(
        harness.node.forward_slots.available_permits(),
        harness.node.limits.forward_concurrency
    );
    assert_eq!(
        harness.node.body_budget.available_permits(),
        harness.node.limits.body_budget_bytes
    );
}

#[tokio::test]
async fn six_requests_are_in_flight_at_once() {
    let provider = provider_with_log_store(|_| {
        Reply::json(200, &json!({"ok": true})).after(Duration::from_millis(100))
    })
    .await;
    let (harness, app, record) = node_with_log_store(&provider).await;
    let urls = messages(24);

    let started = Instant::now();
    let outcomes = harness
        .forward_batch(batch(&app, &record, &urls), b"")
        .await
        .unwrap();
    let elapsed = started.elapsed();
    assert!(outcomes.iter().all(|outcome| outcome.status == Some(200)));
    // 24 requests of 100 ms each, 6 at a time: four rounds.
    assert_eq!(provider.most_in_flight(), limits::FORWARD_BATCH_CONCURRENCY);
    assert!(
        elapsed >= Duration::from_millis(400) && elapsed < Duration::from_millis(1_500),
        "{elapsed:?}"
    );
}

#[tokio::test]
async fn a_request_that_fails_the_address_check_refuses_the_call_with_its_index() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app, record) = node_with_log_store(&provider).await;
    let writes = provider.stored().len();

    // An address outside the definition at index 3: not_allowed, and the index of the
    // request. No event is created and nothing is written or sent.
    let mut urls = messages(5);
    urls[3] = "https://evil.example/gmail/v1/users/me/messages".to_string();
    let (status, failure) = harness
        .forward_batch(batch(&app, &record, &urls), b"")
        .await
        .err()
        .unwrap();
    assert_eq!(status, 403);
    assert_eq!(failure["code"], "not_allowed");
    assert_eq!(failure["index"], 3);
    // A method the node does not send, at index 1.
    let mut meta = batch(&app, &record, &messages(3));
    meta["requests"][1]["method"] = json!("TRACE");
    let (status, failure) = harness.forward_batch(meta, b"").await.err().unwrap();
    assert_eq!(
        (status, &failure["code"], &failure["index"]),
        (403, &json!("not_allowed"), &json!(1))
    );
    // A request object without an address, at index 2.
    let mut meta = batch(&app, &record, &messages(3));
    meta["requests"][2]["url"] = json!(5);
    let (status, failure) = harness.forward_batch(meta, b"").await.err().unwrap();
    assert_eq!(
        (status, &failure["code"], &failure["index"]),
        (400, &json!("invalid_request"), &json!(2))
    );
    assert_eq!(provider.stored().len(), writes);
    assert!(provider_targets(&provider).is_empty());
    assert_eq!(harness.head_seq("user-1"), 1);
    assert_eq!(harness.health().await["log"]["batch_calls"], 0);
}

#[tokio::test]
async fn a_merged_request_inside_a_batch_shares_the_event() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app, record) = node_with_log_store(&provider).await;
    let urls = vec![
        format!("{MESSAGES}/m1"),
        format!("{MESSAGES}/m2"),
        format!("{MESSAGES}/m1"),
    ];
    let outcomes = harness
        .forward_batch(batch(&app, &record, &urls), b"")
        .await
        .unwrap();
    assert_eq!(
        logs_of(&outcomes),
        [
            json!({"seq": 2, "index": 0, "created": true}),
            json!({"seq": 2, "index": 1, "created": true}),
            json!({"seq": 2, "index": 0, "created": false}),
        ]
    );
    // Two events, three requests sent.
    let chain = provider.chain("user-1", &harness.node.node);
    assert_eq!(chain[1].parts().count, 2);
    assert_eq!(provider_targets(&provider).len(), 3);

    // A later batch with the same request shares the event of the entry that is on the chain.
    let outcomes = harness
        .forward_batch(batch(&app, &record, &urls[..1]), b"")
        .await
        .unwrap();
    assert_eq!(
        logs_of(&outcomes),
        [json!({"seq": 2, "index": 0, "created": false})]
    );
    assert_eq!(harness.head_seq("user-1"), 2);
}

#[tokio::test]
async fn two_entries_when_the_open_batch_reaches_its_cap() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app, record) = node_with_log_store(&provider).await;
    let account = harness.node.account("user-1").unwrap();

    // Sixty events already wait in the open batch of the account (events of calls that wait
    // for a writer). A batch of a hundred fills the entry to 128 events and puts the rest into
    // the next one; the call waits for both.
    for index in 0..60 {
        harness
            .node
            .create_event(
                &mut lock(&account),
                "user-1",
                &app.keys.key_id(),
                &app.keys.log_pk(),
                harness.node.now_ms(),
                EntryKind::Use,
                json!({"t": "secret_released", "record_id": format!("r{index}")}),
            )
            .unwrap();
    }
    let before = provider.seen().len();
    let urls = messages(limits::FORWARD_BATCH_REQUESTS);
    let outcomes = harness
        .forward_batch(batch(&app, &record, &urls), b"")
        .await
        .unwrap();
    for (index, outcome) in outcomes.iter().enumerate() {
        assert_eq!(outcome.status, Some(200), "{index}");
        let expected = match index < limits::ENTRY_EVENTS - 60 {
            true => json!({"seq": 2, "index": 60 + index, "created": true}),
            false => {
                json!({"seq": 3, "index": index - (limits::ENTRY_EVENTS - 60), "created": true})
            }
        };
        assert_eq!(outcome.log, expected, "{index}");
    }
    let chain = provider.chain("user-1", &harness.node.node);
    let shape: Vec<(u64, u32)> = chain
        .iter()
        .map(|stored| (stored.seq(), stored.parts().count))
        .collect();
    assert_eq!(shape, [(1, 1), (2, 128), (3, 32)]);
    assert!(writes_precede_requests(&provider, before));
    assert_eq!(harness.health().await["log"]["open_batches"], 0);
}

#[tokio::test]
async fn one_failed_request_leaves_the_others_intact() {
    // The stand-in closes the connection of the seventh message without a response.
    let provider = provider_with_log_store(|seen| match seen.target.ends_with("/m7") {
        true => Reply::Raw(Vec::new()),
        false => Reply::json(200, &json!({"ok": true})),
    })
    .await;
    let (harness, app, record) = node_with_log_store(&provider).await;
    let outcomes = harness
        .forward_batch(batch(&app, &record, &messages(10)), b"")
        .await
        .unwrap();
    for (index, outcome) in outcomes.iter().enumerate() {
        assert_eq!(
            outcome.log,
            json!({"seq": 2, "index": index, "created": true})
        );
        if index == 7 {
            assert_eq!(outcome.status, None);
            assert_eq!(outcome.error.as_deref(), Some("provider_unreachable"));
            assert!(outcome.body.is_empty());
            assert!(outcome.headers.is_empty());
        } else {
            assert_eq!(outcome.status, Some(200), "{index}");
            assert_eq!(outcome.body, br#"{"ok":true}"#);
        }
    }
    // The entry names all ten.
    assert_eq!(
        provider.chain("user-1", &harness.node.node)[1]
            .parts()
            .count,
        10
    );
}

#[tokio::test]
async fn the_bodies_of_the_results_together_stay_under_the_body_limit() {
    let body = "b".repeat(400);
    let provider = provider_with_log_store(move |_| {
        Reply::with_body(200, &[("content-type", "text/plain")], body.as_bytes())
    })
    .await;
    let harness = Harness::with(
        &provider,
        Definitions::embedded(),
        Limits {
            body_bytes: 1_000,
            ..Limits::default()
        },
    );
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let record = google_record(&app);

    // Three responses of 400 bytes: two fit under 1,000 bytes, the third is too_large and its
    // body is not handed on. Every result names its event.
    let outcomes = harness
        .forward_batch(batch(&app, &record, &messages(3)), b"")
        .await
        .unwrap();
    let too_large: Vec<usize> = outcomes
        .iter()
        .enumerate()
        .filter(|(_, outcome)| outcome.error.as_deref() == Some("too_large"))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(too_large.len(), 1, "{outcomes:?}");
    let handed: usize = outcomes
        .iter()
        .filter(|outcome| outcome.status == Some(200))
        .map(|outcome| outcome.body.len())
        .sum();
    assert_eq!(handed, 800);
    assert_eq!(
        logs_of(&outcomes),
        [
            json!({"seq": 2, "index": 0, "created": true}),
            json!({"seq": 2, "index": 1, "created": true}),
            json!({"seq": 2, "index": 2, "created": true}),
        ]
    );
    assert_eq!(
        harness.node.body_budget.available_permits(),
        harness.node.limits.body_budget_bytes
    );
}

#[tokio::test]
async fn results_keep_the_order_of_the_requests() {
    // The first message answers last; every answer names its message.
    let provider = provider_with_log_store(|seen| {
        let name = seen.target.rsplit('/').next().unwrap().to_string();
        let reply = Reply::with_body(200, &[], name.as_bytes());
        match name == "m0" {
            true => reply.after(Duration::from_millis(200)),
            false => reply,
        }
    })
    .await;
    let (harness, app, record) = node_with_log_store(&provider).await;
    let outcomes = harness
        .forward_batch(batch(&app, &record, &messages(8)), b"")
        .await
        .unwrap();
    let bodies: Vec<String> = outcomes
        .iter()
        .map(|outcome| String::from_utf8(outcome.body.clone()).unwrap())
        .collect();
    assert_eq!(bodies, ["m0", "m1", "m2", "m3", "m4", "m5", "m6", "m7"]);
    assert_eq!(provider_targets(&provider).len(), 8);
}

#[tokio::test]
async fn bodies_are_split_by_body_bytes() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app, record) = node_with_log_store(&provider).await;
    let meta = json!({
        "user_id": app.user_id, "record": record, "context": "cli:gog", "timeout_ms": 5000,
        "requests": [
            {"method": "POST", "url": format!("{MESSAGES}/send"), "headers": [["content-type", "application/json"]], "body_bytes": 2},
            {"method": "GET", "url": format!("{MESSAGES}/m1"), "headers": [], "body_bytes": 0},
            {"method": "POST", "url": format!("{MESSAGES}/send"), "headers": [], "body_bytes": 3},
        ],
    });
    let outcomes = harness.forward_batch(meta.clone(), b"abcde").await.unwrap();
    assert_eq!(outcomes.len(), 3);
    // Two POST requests of the same address have their own events, which carry the hash of
    // their body.
    assert_eq!(
        logs_of(&outcomes),
        [
            json!({"seq": 2, "index": 0, "created": true}),
            json!({"seq": 2, "index": 1, "created": true}),
            json!({"seq": 2, "index": 2, "created": true}),
        ]
    );
    let events = app.events(
        &harness,
        &provider.chain("user-1", &harness.node.node)[1].entry,
    );
    assert_eq!(events[0]["body_bytes"], 2);
    assert_eq!(events[2]["body_bytes"], 3);
    assert_ne!(events[0]["body_sha256"], events[2]["body_sha256"]);
    let mut bodies: Vec<Vec<u8>> = provider
        .seen()
        .into_iter()
        .filter(|seen| seen.server_name != LOG_HOST && seen.method == "POST")
        .map(|seen| seen.body)
        .collect();
    bodies.sort();
    assert_eq!(bodies, [b"ab".to_vec(), b"cde".to_vec()]);

    // A payload that is not the sum of the declared bodies is invalid, and so is a count out
    // of the declared bodies.
    let (status, failure) = harness
        .forward_batch(meta.clone(), b"abcd")
        .await
        .err()
        .unwrap();
    assert_eq!((status, &failure["code"]), (400, &json!("invalid_request")));
    let (status, _) = harness
        .forward_batch(meta.clone(), b"abcdef")
        .await
        .err()
        .unwrap();
    assert_eq!(status, 400);
    // A declared length near the limit of the integer is invalid like any other past the
    // payload: the node answers instead of failing on the arithmetic.
    let mut huge = meta;
    huge["requests"][2]["body_bytes"] = json!(u64::MAX);
    let (status, failure) = harness.forward_batch(huge, b"ab").await.err().unwrap();
    assert_eq!((status, &failure["code"]), (400, &json!("invalid_request")));
    assert_eq!(harness.head_seq("user-1"), 2);
}

#[tokio::test]
async fn a_batch_of_zero_or_101_requests_is_invalid() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app, record) = node_with_log_store(&provider).await;
    for urls in [messages(0), messages(limits::FORWARD_BATCH_REQUESTS + 1)] {
        let (status, failure) = harness
            .forward_batch(batch(&app, &record, &urls), b"")
            .await
            .err()
            .unwrap();
        assert_eq!(
            (status, &failure["code"]),
            (400, &json!("invalid_request")),
            "{}",
            urls.len()
        );
    }
    let mut meta = batch(&app, &record, &messages(1));
    meta.as_object_mut().unwrap().remove("requests");
    let (status, _) = harness.forward_batch(meta, b"").await.err().unwrap();
    assert_eq!(status, 400);
    assert_eq!(harness.head_seq("user-1"), 1);

    // The front conditions hold for the call as a whole: an account without a grant.
    let stranger = App::new("user-2", 2);
    let (status, failure) = harness
        .forward_batch(
            batch(&stranger, &google_record(&stranger), &messages(2)),
            b"",
        )
        .await
        .err()
        .unwrap();
    assert_eq!((status, &failure["code"]), (409, &json!("grant_required")));
}
