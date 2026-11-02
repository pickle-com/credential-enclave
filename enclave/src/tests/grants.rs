//! `POST /v1/grants/prune` (enclave.md 5.15) and the counts of health (5.1): a node drops the
//! grants outside its share of the delegation subset, and every count the node keeps with the
//! state of its accounts equals a scan of the accounts.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use credential_enclave_protocol::encoding::b64u;
use serde_json::{json, Value};

use super::{provider_and_log_store, quiet_provider};
use crate::state::{lock, GrantState, Limits, Node};
use crate::subset::assign;
use crate::testing::{App, Harness, Provider, Reply};

const MESSAGES: &str = "https://gmail.googleapis.com/gmail/v1/users/me/messages";

async fn grant_state(harness: &Harness, user_id: &str) -> String {
    harness
        .post(
            "/v1/status",
            json!({"user_id": user_id, "nonce": "bm9uY2U"}),
        )
        .await
        .1["grant"]["state"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn prune(harness: &Harness, subset: Value, after: &str, limit: u64) -> (u16, Value) {
    harness
        .post(
            "/v1/grants/prune",
            json!({"subset": subset, "after": after, "limit": limit}),
        )
        .await
}

/// The accounts of `user_ids` that the node of ordinal `pod` does not hold under the subset.
fn outside(user_ids: &[&str], pods: u32, pod: u32, copies: u32) -> Vec<String> {
    user_ids
        .iter()
        .filter(|user_id| !assign(user_id, pods, copies).contains(&pod))
        .map(|user_id| user_id.to_string())
        .collect()
}

#[tokio::test]
async fn prune_drops_the_grants_outside_the_subset_page_by_page() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    // Eight accounts with a grant, one that revoked, one whose grant expired.
    let holders = ["a", "b", "c", "d", "e", "f", "g", "h"];
    for (index, user_id) in holders.iter().enumerate() {
        App::new(user_id, index as u8 + 1).grant(&harness).await;
    }
    App::new("revoked", 20).revoke(&harness).await;
    let expired = App::new("expired", 21);
    let attested = expired.attest(&harness).await;
    expired
        .send(
            &harness,
            expired.grant_envelope(&attested, harness.node.now_ms() + 1_000),
        )
        .await;
    harness.node.clock.advance(2_000);
    assert_eq!(grant_state(&harness, "expired").await, "expired");
    assert_eq!(harness.health().await["grants"], 8);
    let heads_before: Vec<u64> = holders
        .iter()
        .map(|user_id| harness.head_seq(user_id))
        .collect();

    // The node is pod 1 of 3 with 2 copies per account: the accounts whose two nodes do not
    // include ordinal 1 are pruned, the expired grant among them (an expired grant is a grant
    // the node still remembers). Pages of two, in `user_id` order; `next` is the last
    // account looked at.
    let subset = json!({"pods": 3, "pod": 1, "copies": 2});
    let mut expected = outside(&holders, 3, 1, 2);
    if !assign("expired", 3, 2).contains(&1) {
        expected.push("expired".to_string());
    }
    expected.sort();
    assert!(expected.len() >= 2, "{expected:?}");
    let mut pruned = Vec::new();
    let mut after = String::new();
    let mut pages = 0;
    loop {
        let (status, page) = prune(&harness, subset.clone(), &after, 2).await;
        assert_eq!(status, 200, "{page}");
        let listed: Vec<String> = page["pruned"]
            .as_array()
            .unwrap()
            .iter()
            .map(|user_id| user_id.as_str().unwrap().to_string())
            .collect();
        assert!(listed.len() <= 2);
        pruned.extend(listed);
        pages += 1;
        after = page["next"].as_str().unwrap().to_string();
        if after.is_empty() {
            break;
        }
        assert!(
            pruned.last().is_none_or(|last| last <= &after),
            "{pruned:?} {after}"
        );
    }
    assert_eq!(pruned, expected);
    assert!(pages >= expected.len().div_ceil(2), "{pages}");

    // The pruned accounts have no grant and no chain was touched; the accounts of the share
    // keep their grant, the revocation marker stays.
    for user_id in &pruned {
        assert_eq!(grant_state(&harness, user_id).await, "none", "{user_id}");
    }
    for user_id in holders {
        let kept = !pruned.iter().any(|pruned| pruned == user_id);
        assert_eq!(
            grant_state(&harness, user_id).await,
            if kept { "active" } else { "none" },
            "{user_id}"
        );
    }
    assert_eq!(grant_state(&harness, "revoked").await, "revoked");
    assert_eq!(
        holders
            .iter()
            .map(|user_id| harness.head_seq(user_id))
            .collect::<Vec<u64>>(),
        heads_before
    );
    let in_share = holders.len() - outside(&holders, 3, 1, 2).len();
    assert_eq!(harness.health().await["grants"], in_share);

    // A repeated walk prunes nothing more. The call works on a closing node too.
    let (status, again) = prune(&harness, subset.clone(), "", 1000).await;
    assert_eq!((status, again), (200, json!({"pruned": [], "next": ""})));
    assert_eq!(harness.post("/v1/close", json!({})).await.0, 200);
    let (status, closing) = prune(&harness, subset, "", 1000).await;
    assert_eq!(
        (status, closing["pruned"].as_array().map(Vec::len)),
        (200, Some(0))
    );

    // The subset is required and has bounds; a limit is at least 1.
    for body in [
        json!({}),
        json!({"subset": null}),
        json!({"subset": {"pods": 3, "pod": 3, "copies": 1}}),
        json!({"subset": {"pods": 1025, "pod": 0, "copies": 1}}),
        json!({"subset": {"pods": 3, "pod": 0, "copies": 0}}),
        json!({"subset": {"pods": 3, "pod": 0, "copies": 1}, "limit": 0}),
    ] {
        let (status, failure) = harness.post("/v1/grants/prune", body.clone()).await;
        assert_eq!(
            (status, failure["code"].as_str()),
            (400, Some("invalid_request")),
            "{body}"
        );
    }
}

/// A stand-in for the providers and for the log store. The providers answer a token request
/// with a token response and every other request with `200 {"ok":true}`; the store confirms a
/// write unless `refusing` is set.
async fn stand_in() -> (Provider, Arc<Mutex<bool>>) {
    let refusing = Arc::new(Mutex::new(false));
    let script = refusing.clone();
    let provider = provider_and_log_store(
        |seen| match seen.target.as_str() {
            "/token" => Reply::json(
                200,
                &json!({
                    "access_token": "ya29.second-access", "expires_in": 3599,
                    "token_type": "Bearer", "refresh_token": "1//second-refresh",
                }),
            ),
            _ => Reply::json(200, &json!({"ok": true})),
        },
        move |_| match *lock(&script) {
            true => Reply::with_body(503, &[], b"<Error></Error>"),
            false => Reply::with_body(200, &[("etag", "\"0\"")], b""),
        },
    )
    .await;
    (provider, refusing)
}

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

/// The counts of the node that a scan of its accounts gives, in the order of
/// [`counts_of_health`].
fn scan(node: &Node) -> [usize; 7] {
    let mut counts = [0usize; 7];
    for (_, account) in node.accounts_after("") {
        let account = lock(&account);
        counts[0] += usize::from(account.head.seq > 0);
        counts[1] += usize::from(matches!(account.grant(), GrantState::Active(_)));
        counts[2] += usize::from(!account.unconfirmed().is_empty());
        counts[3] += account.unconfirmed().len();
        counts[4] += account.kept_refresh_count();
        counts[5] += account.merge_key_count();
        counts[6] += usize::from(account.has_open_events());
    }
    counts
}

/// The same counts as health reports them: `accounts`, `grants`, `pending` of the log store,
/// and `pending_entries`, `kept_refreshes`, `merge_keys` of `state`, `open_batches` of `log`.
fn counts_of_health(health: &Value) -> [usize; 7] {
    let count = |value: &Value| value.as_u64().unwrap() as usize;
    [
        count(&health["accounts"]),
        count(&health["grants"]),
        count(&health["log_store"]["pending"]),
        count(&health["state"]["pending_entries"]),
        count(&health["state"]["kept_refreshes"]),
        count(&health["state"]["merge_keys"]),
        count(&health["log"]["open_batches"]),
    ]
}

#[tokio::test]
async fn the_counts_of_health_equal_a_scan_of_the_accounts_after_every_change() {
    let (provider, refusing) = stand_in().await;
    let limits = Limits {
        log_write: Duration::from_millis(450),
        ..Limits::default()
    };
    let harness = Harness::with(&provider, crate::providers::Definitions::embedded(), limits);
    harness.use_log_store().await;
    let old = Harness::new(&provider);
    old.use_log_store().await;
    let check = |step: &'static str| {
        let harness = &harness;
        async move {
            let health = harness.health().await;
            assert_eq!(counts_of_health(&health), scan(&harness.node), "{step}");
            health
        }
    };
    check("empty").await;

    // Grants.
    let apps: Vec<App> = ["a", "b", "c", "d"]
        .iter()
        .enumerate()
        .map(|(index, user_id)| App::new(user_id, index as u8 + 1))
        .collect();
    for app in &apps {
        app.grant(&harness).await;
    }
    let health = check("grants").await;
    assert_eq!(
        (&health["accounts"], &health["grants"]),
        (&json!(4), &json!(4))
    );

    // A refresh keeps its response; two identical GET requests share one merge key.
    let (status, _) = harness
        .post(
            "/v1/refresh",
            json!({"user_id": "a", "record": google_record(&apps[0]), "context": "c"}),
        )
        .await;
    assert_eq!(status, 200);
    let record = google_record(&apps[1]);
    for _ in 0..2 {
        let forwarded = harness
            .forward(
                json!({
                    "user_id": "b", "record": record, "method": "GET", "url": MESSAGES,
                    "headers": [], "context": "cli:gog", "timeout_ms": 5000,
                }),
                b"",
            )
            .await
            .unwrap();
        assert_eq!(forwarded.status, 200);
    }
    let health = check("refresh and forward").await;
    assert_eq!(health["state"]["kept_refreshes"], 1);
    assert_eq!(health["state"]["merge_keys"], 1);

    // The store refuses: two releases of c and one of a leave three pending entries.
    *lock(&refusing) = true;
    for app in [&apps[2], &apps[2], &apps[0]] {
        let record = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
        let (status, failure) = harness
            .post(
                "/v1/release",
                json!({
                    "user_id": app.user_id, "record": record, "field": "password",
                    "origin": "https://site.example", "context": "browser:fill",
                }),
            )
            .await;
        assert_eq!(
            (status, failure["code"].as_str()),
            (503, Some("log_store_unavailable"))
        );
    }
    let health = check("pending").await;
    assert_eq!(health["log_store"]["pending"], 2);
    assert_eq!(health["state"]["pending_entries"], 3);

    // A grant that ends: its expiry is read by a status call. A revoke.
    let short = App::new("e", 9);
    let attested = short.attest(&harness).await;
    *lock(&refusing) = false;
    short
        .send(
            &harness,
            short.grant_envelope(&attested, harness.node.now_ms() + 1_000),
        )
        .await;
    check("short grant").await;
    harness.node.clock.advance(2_000);
    assert_eq!(grant_state(&harness, "e").await, "expired");
    apps[3].revoke(&harness).await;
    let health = check("expiry and revoke").await;
    assert_eq!(health["grants"], 3);

    // An import from another node puts a grant in place with a pending entry (the store
    // refuses the round of the import).
    let newcomer = App::new("f", 10);
    newcomer.grant(&old).await;
    let to = harness
        .post("/v1/attestation", json!({"nonce": b64u(&[9u8; 32])}))
        .await
        .1;
    let from = old
        .post("/v1/attestation", json!({"nonce": b64u(&[9u8; 32])}))
        .await
        .1;
    let (_, exported) = old
        .post("/v1/peer/export", json!({"peer": to, "limit": 1000}))
        .await;
    *lock(&refusing) = true;
    let (status, imported) = harness
        .post(
            "/v1/peer/import",
            json!({"peer": from, "envelope": exported["envelope"]}),
        )
        .await;
    assert_eq!((status, imported["imported"].as_u64()), (200, Some(1)));
    let health = check("import").await;
    assert_eq!(health["grants"], 4);
    assert_eq!(health["log_store"]["pending"], 3);

    // A prune drops the grants outside the share of the node.
    let (status, pruned) = prune(
        &harness,
        json!({"pods": 2, "pod": 0, "copies": 1}),
        "",
        1000,
    )
    .await;
    assert_eq!(status, 200, "{pruned}");
    assert!(!pruned["pruned"].as_array().unwrap().is_empty());
    check("prune").await;

    // The store confirms again: the sweep writes the pending entries. After the merge window
    // and the time of a kept response passed, the sweep drops both.
    *lock(&refusing) = false;
    harness.node.clock.advance(30_000);
    crate::log_store::sweep(&harness.node).await;
    let health = check("sweep").await;
    assert_eq!(health["log_store"]["pending"], 0);
    assert_eq!(health["state"]["pending_entries"], 0);
    harness.node.clock.advance(3_600_000);
    crate::log_store::sweep(&harness.node).await;
    let health = check("sweep after the windows").await;
    assert_eq!(health["state"]["kept_refreshes"], 0);
    assert_eq!(health["state"]["merge_keys"], 0);

    // The shutdown: the final heads of every account, none pending.
    assert_eq!(harness.post("/v1/close", json!({})).await.0, 200);
    let (status, heads) = harness
        .post("/v1/close/heads", json!({"cursor": "", "limit": 1000}))
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        (&heads["truncated"], &heads["skipped"]),
        (&json!(0), &json!(0))
    );
    check("closed").await;
}
