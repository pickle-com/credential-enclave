//! `forward` against a provider stand-in (enclave.md 5.8 and section 7): header removal, the
//! injected credential, redirects that are not followed, chunked responses, the body limit and
//! the time limit.

use std::time::{Duration, Instant};

use credential_enclave_protocol::encoding::b64u;
use credential_enclave_protocol::limits;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{provider_with_log_store, quiet_provider, quiet_provider_and_log_store};
use crate::providers::Definitions;
use crate::state::Limits;
use crate::testing::{App, Harness, Reply};

const PROFILE: &str = "https://gmail.googleapis.com/gmail/v1/users/me/profile";

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

fn meta(app: &App, record: &Value, method: &str, url: &str, headers: Value) -> Value {
    json!({
        "user_id": app.user_id, "record": record, "method": method, "url": url,
        "headers": headers, "context": "cli:gog", "timeout_ms": 5000,
    })
}

/// A node with the log store of the tests (the stand-in confirms every write), the app of an
/// account that granted on it and a Google record of that account.
async fn ready(provider: &crate::testing::Provider) -> (Harness, App, Value) {
    let harness = Harness::new(provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let record = google_record(&app);
    (harness, app, record)
}

/// An event without its `time_ms`, the node time of its creation.
fn without_time(mut event: Value) -> Value {
    assert!(event["time_ms"].as_u64().is_some(), "{event}");
    event.as_object_mut().unwrap().remove("time_ms");
    event
}

fn failure(outcome: Result<crate::testing::Forwarded, (u16, Value)>) -> (u16, String) {
    let (status, body) = outcome.err().expect("the call must fail");
    (
        status,
        body["code"].as_str().unwrap_or_default().to_string(),
    )
}

fn assert_budget_is_free(harness: &Harness) {
    assert_eq!(
        harness.node.body_budget.available_permits(),
        harness.node.limits.body_budget_bytes
    );
    assert_eq!(
        harness.node.forward_slots.available_permits(),
        harness.node.limits.forward_concurrency
    );
}

#[tokio::test]
async fn the_node_sets_the_credential_and_drops_the_headers_it_owns() {
    let provider = provider_with_log_store(|_| {
        Reply::with_body(
            200,
            &[("content-type", "application/json")],
            br#"{"emailAddress":"a@example.com"}"#,
        )
    })
    .await;
    let (harness, app, record) = ready(&provider).await;
    let headers = json!([
        ["Authorization", "Bearer placeholder-from-the-caller"],
        ["Proxy-Authorization", "Basic eDp5"],
        ["Cookie", "session=1"],
        ["Host", "evil.example"],
        ["Content-Length", "999"],
        ["Transfer-Encoding", "chunked"],
        ["Connection", "keep-alive, x-hop"],
        ["Keep-Alive", "timeout=5"],
        ["Upgrade", "h2c"],
        ["TE", "trailers"],
        ["Trailer", "x-checksum"],
        ["Expect", "100-continue"],
        ["Accept", "application/json"],
        ["Accept-Encoding", "gzip"],
        ["User-Agent", "python-httpx/0.28"],
        ["X-Goog-Api-Client", "gog/0.38.1"],
        ["X-Upload-Name", "보고서.pdf"],
    ]);
    let body = br#"{"raw":"bWVzc2FnZQ"}"#;
    let address = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send?alt=json";
    let forwarded = harness
        .forward(meta(&app, &record, "POST", address, headers), body)
        .await
        .unwrap();
    assert_eq!(forwarded.status, 200);
    assert_eq!(forwarded.body, br#"{"emailAddress":"a@example.com"}"#);
    assert_eq!(forwarded.header("content-type"), Some("application/json"));

    let seen = provider.only();
    assert_eq!(seen.server_name, "gmail.googleapis.com");
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.target, "/gmail/v1/users/me/messages/send?alt=json");
    assert_eq!(seen.body, body);
    assert_eq!(
        seen.header_names(),
        [
            "host",
            "content-length",
            "authorization",
            "accept-encoding",
            "accept",
            "user-agent",
            "x-goog-api-client",
            "x-upload-name",
            "connection",
        ]
    );
    // A value above ASCII is sent as UTF-8.
    assert_eq!(seen.header("x-upload-name"), Some("보고서.pdf"));
    assert_eq!(seen.header("host"), Some("gmail.googleapis.com"));
    assert_eq!(
        seen.header("content-length"),
        Some(body.len().to_string().as_str())
    );
    assert_eq!(seen.header("authorization"), Some("Bearer ya29.injected"));
    // The connection stays open for the next request of this account to this host.
    assert_eq!(seen.header("connection"), Some("keep-alive"));
    // The node asks for an unencoded response, whatever the caller asked for: it searches the
    // response for the credential before it hands it on.
    assert_eq!(seen.header("accept-encoding"), Some("identity"));

    // The event describes the request and never holds the credential.
    assert_eq!(
        forwarded.log,
        json!({"seq": 2, "index": 0, "created": true})
    );
    let event = without_time(app.logged(&harness, &provider, &forwarded.log));
    assert_eq!(
        event,
        json!({
            "t": "provider_request", "record_id": record["id"], "provider": "google_workspace",
            "method": "POST", "host": "gmail.googleapis.com",
            "path": "/gmail/v1/users/me/messages/send", "query": "alt=json",
            "body_bytes": body.len(), "body_sha256": b64u(&Sha256::digest(body)),
            "context": "cli:gog",
        })
    );
    assert_budget_is_free(&harness);
}

#[tokio::test]
async fn github_takes_basic_on_its_git_addresses_and_token_on_its_api() {
    let provider = provider_with_log_store(|_| Reply::json(200, &json!({"ok": true}))).await;
    let harness = Harness::new(&provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let record = app.record(
        "oauth",
        "github",
        &json!({"token": {"access_token": "ghu_injected", "refresh_token": "ghr_1"}, "obtained_ms": 1}),
    );
    let git =
        "https://github.com/pickle-com/interactive-character.git/info/refs?service=git-upload-pack";
    harness
        .forward(meta(&app, &record, "GET", git, json!([])), b"")
        .await
        .unwrap();
    let api = "https://api.github.com/repos/pickle-com/interactive-character/pulls/1771";
    harness
        .forward(
            meta(
                &app,
                &record,
                "GET",
                api,
                json!([["Authorization", "token placeholder"]]),
            ),
            b"",
        )
        .await
        .unwrap();
    let seen = provider.requests();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].server_name, "github.com");
    assert_eq!(
        seen[0].target,
        "/pickle-com/interactive-character.git/info/refs?service=git-upload-pack"
    );
    // base64("x-access-token:ghu_injected")
    assert_eq!(
        seen[0].header("authorization"),
        Some("Basic eC1hY2Nlc3MtdG9rZW46Z2h1X2luamVjdGVk")
    );
    assert_eq!(seen[1].server_name, "api.github.com");
    assert_eq!(seen[1].header("authorization"), Some("token ghu_injected"));
    // The git address that pushes is reachable too, and the token address is not.
    let push = "https://github.com/pickle-com/interactive-character/git-receive-pack";
    assert!(harness
        .forward(meta(&app, &record, "POST", push, json!([])), b"0000")
        .await
        .is_ok());
    let (status, code) = failure(
        harness
            .forward(
                meta(
                    &app,
                    &record,
                    "POST",
                    "https://github.com/login/oauth/access_token",
                    json!([]),
                ),
                b"",
            )
            .await,
    );
    assert_eq!((status, code.as_str()), (403, "not_allowed"));
}

#[tokio::test]
async fn every_method_of_the_list_is_sent_and_no_other() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app, record) = ready(&provider).await;
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
        let forwarded = harness
            .forward(meta(&app, &record, method, PROFILE, json!([])), b"")
            .await
            .unwrap();
        assert_eq!(forwarded.status, 200, "{method}");
        let seen = provider.requests().last().unwrap().clone();
        assert_eq!(seen.method, method);
        // A request without a body declares a length only for the methods that carry one.
        let expected = matches!(method, "POST" | "PUT" | "PATCH").then_some("0");
        assert_eq!(seen.header("content-length"), expected, "{method}");
    }
    let sent = provider.requests().len();
    let seq = harness.head_seq("user-1");
    for method in ["HEAD", "OPTIONS", "CONNECT", "TRACE", "get", "QUERY"] {
        assert_eq!(
            failure(
                harness
                    .forward(meta(&app, &record, method, PROFILE, json!([])), b"")
                    .await
            ),
            (403, "not_allowed".to_string()),
            "{method}"
        );
    }
    assert_eq!(provider.requests().len(), sent);
    assert_eq!(harness.head_seq("user-1"), seq);
}

#[tokio::test]
async fn an_address_outside_the_definition_is_refused_before_anything_is_recorded_or_sent() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app, record) = ready(&provider).await;
    for address in [
        "https://oauth2.googleapis.com/token",
        "https://oauth2.googleapis.com/revoke",
        "https://graph.microsoft.com/v1.0/me",
        "https://gmail.googleapis.com/gmail/v1/../../token",
        "https://gmail.googleapis.com/gmail/v1/..;/token",
        "https://gmail.googleapis.com/gmail/v1/%252e%252e/token",
        "https://gmail.googleapis.com/gmail/v1/users%2Fme",
        "https://gmail.googleapis.com/gmail/v1/users%252Fme",
        "https://gmail.googleapis.com:8443/gmail/v1/users/me/profile",
        "https://user@gmail.googleapis.com/gmail/v1/users/me/profile",
        "https://127.0.0.1/gmail/v1/users/me/profile",
        "http://gmail.googleapis.com/gmail/v1/users/me/profile",
        "https://gmail.googleapis.com/gmail/v1/users/me/profile#fragment",
    ] {
        assert_eq!(
            failure(
                harness
                    .forward(meta(&app, &record, "GET", address, json!([])), b"")
                    .await
            ),
            (403, "not_allowed".to_string()),
            "{address}"
        );
    }
    // A record of another provider cannot borrow the hosts of this one.
    let slack = app.record(
        "oauth",
        "slack",
        &json!({"token": {"access_token": "xoxp"}, "obtained_ms": 1}),
    );
    assert_eq!(
        failure(
            harness
                .forward(meta(&app, &slack, "GET", PROFILE, json!([])), b"")
                .await
        ),
        (403, "not_allowed".to_string())
    );
    // A vault record is never forwarded.
    let vault = app.record("vault_password", "vault", &json!({"value": "x"}));
    assert_eq!(
        failure(
            harness
                .forward(meta(&app, &vault, "GET", PROFILE, json!([])), b"")
                .await
        ),
        (403, "not_allowed".to_string())
    );
    assert!(provider.requests().is_empty());
    assert_eq!(harness.head_seq("user-1"), 1);
    assert_budget_is_free(&harness);
}

#[tokio::test]
async fn malformed_headers_and_arguments_are_refused() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app, record) = ready(&provider).await;
    for headers in [
        json!([["X Bad", "1"]]),
        json!([["X-Ok", "line\r\nX-Injected: 1"]]),
        json!([["X-Ok", "line\nbreak"]]),
        json!([["X-Ok", "nul\u{0}byte"]]),
        json!([["X-Ok"]]),
        json!([["X-Ok", 5]]),
        json!({"x-ok": "1"}),
        json!([["", "1"]]),
    ] {
        assert_eq!(
            failure(
                harness
                    .forward(meta(&app, &record, "GET", PROFILE, headers.clone()), b"")
                    .await
            ),
            (400, "invalid_request".to_string()),
            "{headers}"
        );
    }
    for timeout_ms in [json!(999), json!(120_001), json!("soon")] {
        let mut request = meta(&app, &record, "GET", PROFILE, json!([]));
        request["timeout_ms"] = timeout_ms;
        assert_eq!(
            failure(harness.forward(request, b"").await),
            (400, "invalid_request".to_string())
        );
    }
    let mut long_context = meta(&app, &record, "GET", PROFILE, json!([]));
    long_context["context"] = json!("c".repeat(257));
    assert_eq!(
        failure(harness.forward(long_context, b"").await),
        (400, "invalid_request".to_string())
    );
    // A body that is not a frame.
    let (status, _, bytes) = harness
        .send(
            axum::http::Method::POST,
            "/v1/forward",
            b"\x00\x00".to_vec(),
        )
        .await;
    assert_eq!(status.as_u16(), 400);
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["code"],
        "invalid_request"
    );
    assert!(provider.requests().is_empty());
    assert_eq!(harness.head_seq("user-1"), 1);

    // The time limit is optional and the bounds are inclusive.
    for timeout_ms in [Value::Null, json!(1000), json!(120_000)] {
        let mut request = meta(&app, &record, "GET", PROFILE, json!([]));
        request["timeout_ms"] = timeout_ms;
        assert!(harness.forward(request, b"").await.is_ok());
    }
}

#[tokio::test]
async fn a_header_that_overrides_the_method_is_refused() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app, record) = ready(&provider).await;
    // A provider that reads such a header would carry out another method than the method of
    // the entry. The call is refused, whatever the case of the name and wherever it stands.
    for name in [
        "X-HTTP-Method-Override",
        "x-http-method-override",
        "X-HTTP-Method",
        "X-Method-Override",
        "x-METHOD-override",
    ] {
        for headers in [
            json!([[name, "DELETE"]]),
            json!([
                ["Accept", "application/json"],
                [name, "PATCH"],
                ["X-Other", "1"]
            ]),
        ] {
            for method in ["POST", "GET"] {
                assert_eq!(
                    failure(
                        harness
                            .forward(meta(&app, &record, method, PROFILE, headers.clone()), b"")
                            .await
                    ),
                    (403, "not_allowed".to_string()),
                    "{name} {method}"
                );
            }
        }
    }
    // Nothing was sent and no entry was created.
    assert!(provider.requests().is_empty());
    assert_eq!(harness.head_seq("user-1"), 1);
    assert_budget_is_free(&harness);

    // A header whose name is not one of the three is a header like any other.
    let headers = json!([["X-HTTP-Method-Overrides", "DELETE"]]);
    let forwarded = harness
        .forward(meta(&app, &record, "POST", PROFILE, headers), b"{}")
        .await
        .unwrap();
    let seen = provider.only();
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.header("x-http-method-overrides"), Some("DELETE"));
    assert_eq!(
        app.logged(&harness, &provider, &forwarded.log)["method"],
        "POST"
    );
}

#[tokio::test]
async fn the_batch_address_of_microsoft_graph_is_refused() {
    let provider = quiet_provider_and_log_store().await;
    let harness = Harness::new(&provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let record = app.record(
        "oauth",
        "microsoft",
        &json!({"token": {"access_token": "EwB4A8l6.graph"}, "obtained_ms": 1}),
    );
    // One call to this address would carry up to 20 requests in its body, and its entry
    // would name none of them.
    let batch = br#"{"requests":[{"id":"1","method":"DELETE","url":"/me/messages/AAMkAD"}]}"#;
    let headers = json!([["Content-Type", "application/json"]]);
    for address in [
        "https://graph.microsoft.com/v1.0/$batch",
        "https://graph.microsoft.com/v1.0/%24batch",
        "https://graph.microsoft.com/v1.0/$Batch",
        "https://graph.microsoft.com/v1.0/$batch/",
        "https://graph.microsoft.com/v1.0/$batch;x",
        "https://graph.microsoft.com/v1.0/$batch?x=1",
    ] {
        assert_eq!(
            failure(
                harness
                    .forward(meta(&app, &record, "POST", address, headers.clone()), batch)
                    .await
            ),
            (403, "not_allowed".to_string()),
            "{address}"
        );
    }
    assert!(provider.requests().is_empty());
    assert_eq!(harness.head_seq("user-1"), 1);
    assert_budget_is_free(&harness);

    // The same request on its own address is sent, and its event names it.
    let address = "https://graph.microsoft.com/v1.0/me/messages/AAMkAD";
    let forwarded = harness
        .forward(meta(&app, &record, "DELETE", address, json!([])), b"")
        .await
        .unwrap();
    let event = app.logged(&harness, &provider, &forwarded.log);
    assert_eq!(
        (&event["method"], &event["host"], &event["path"]),
        (
            &json!("DELETE"),
            &json!("graph.microsoft.com"),
            &json!("/v1.0/me/messages/AAMkAD")
        )
    );
    assert_eq!(provider.only().target, "/v1.0/me/messages/AAMkAD");
}

#[tokio::test]
async fn a_get_request_with_a_body_always_has_its_own_event() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app, record) = ready(&provider).await;
    let address = format!("{PROFILE}?fields=emailAddress");
    let get = |payload: &'static [u8]| {
        let request = meta(&app, &record, "GET", &address, json!([]));
        let harness = &harness;
        async move { harness.forward(request, payload).await.unwrap() }
    };

    // A GET without a body: its event can be the target of a merge.
    let first = get(b"").await;
    assert_eq!(first.log, json!({"seq": 2, "index": 0, "created": true}));
    assert_eq!(app.logged(&harness, &provider, &first.log)["window_s"], 300);

    // The same address with a body, inside the window. The merge key holds the address
    // only, so such a request is never merged: its event carries the size and the hash of
    // the body, and no window.
    let body: &[u8] = br#"{"query":"from:alice"}"#;
    let with_body = get(body).await;
    assert_eq!(with_body.log["created"], true);
    let event = without_time(app.logged(&harness, &provider, &with_body.log));
    assert_eq!(
        event,
        json!({
            "t": "provider_request", "record_id": record["id"], "provider": "google_workspace",
            "method": "GET", "host": "gmail.googleapis.com",
            "path": "/gmail/v1/users/me/profile", "query": "fields=emailAddress",
            "body_bytes": body.len(), "body_sha256": b64u(&Sha256::digest(body)),
            "context": "cli:gog",
        })
    );
    let seen = provider.requests().last().unwrap().clone();
    assert_eq!((seen.method.as_str(), seen.body.as_slice()), ("GET", body));

    // The same body again, and another body: an event each.
    let again = get(body).await;
    assert_eq!(again.log["created"], true);
    assert_eq!(
        app.logged(&harness, &provider, &again.log)["body_sha256"],
        event["body_sha256"]
    );
    let other: &[u8] = br#"{"query":"from:bob"}"#;
    let changed = get(other).await;
    assert_eq!(
        app.logged(&harness, &provider, &changed.log)["body_sha256"],
        b64u(&Sha256::digest(other))
    );
    // The grant, the first GET and the three requests with a body.
    assert_eq!(harness.head_seq("user-1"), 5);

    // A GET without a body still shares the event of the first one, and a request with a
    // body opened no window for it.
    assert_eq!(
        get(b"").await.log,
        json!({"seq": 2, "index": 0, "created": false})
    );
    assert_eq!(harness.head_seq("user-1"), 5);
    assert_eq!(provider.requests().len(), 5);
    let fresh = format!("{PROFILE}?fields=messagesTotal");
    let request = meta(&app, &record, "GET", &fresh, json!([]));
    assert_eq!(
        harness.forward(request.clone(), body).await.unwrap().log["created"],
        true
    );
    let unmerged = harness.forward(request, b"").await.unwrap();
    assert_eq!(unmerged.log["created"], true);
    assert_eq!(
        app.logged(&harness, &provider, &unmerged.log)["window_s"],
        300
    );
}

#[tokio::test]
async fn an_event_carries_the_whole_path_and_the_whole_query() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app, record) = ready(&provider).await;
    // An address of 8,192 bytes, the longest that passes the address check.
    let front = "https://gmail.googleapis.com";
    let path = format!("/gmail/v1/users/me/messages/{}", "m".repeat(3000));
    let query = format!(
        "q={}",
        "x".repeat(8192 - front.len() - path.len() - "?q=".len())
    );
    let address = format!("{front}{path}?{query}");
    assert_eq!(address.len(), 8192);
    assert!(path.len() > 2048 && query.len() > 2048);
    let forwarded = harness
        .forward(meta(&app, &record, "POST", &address, json!([])), b"{}")
        .await
        .unwrap();

    // The event names the request that was sent: nothing of the path or the query is cut.
    let event = app.logged(&harness, &provider, &forwarded.log);
    assert_eq!(event["path"], path.as_str());
    assert_eq!(event["query"], query.as_str());
    assert_eq!(provider.only().target, format!("{path}?{query}"));

    // The largest event of a request: the query fills the address with a byte that JSON
    // writes as two, and the context holds 256 control characters, which JSON writes as six
    // bytes each. Fifty events of this size fit in the plaintext of one entry; a batch of
    // more such requests is split at the cap of the open batch (two entries).
    let query = "\\".repeat(8192 - PROFILE.len() - 1);
    let mut request = meta(
        &app,
        &record,
        "POST",
        &format!("{PROFILE}?{query}"),
        json!([]),
    );
    request["context"] = json!("\u{1}".repeat(256));
    let largest = harness.forward(request, b"{}").await.unwrap();
    let event = app.logged(&harness, &provider, &largest.log);
    assert_eq!(event["query"], query.as_str());
    assert_eq!(event["context"], "\u{1}".repeat(256));
    let event_bytes = event.to_string().len();
    assert!(event_bytes < 20_000, "{event_bytes}");
    assert!(event_bytes * 50 < limits::ENTRY_PLAINTEXT_BYTES);

    // One byte more is no address of `forward`: nothing is sent and nothing is recorded.
    assert_eq!(
        failure(
            harness
                .forward(
                    meta(&app, &record, "POST", &format!("{address}x"), json!([])),
                    b"{}"
                )
                .await
        ),
        (403, "not_allowed".to_string())
    );
    assert_eq!(provider.requests().len(), 2);
    assert_eq!(harness.head_seq("user-1"), 3);
}

#[tokio::test]
async fn a_redirect_is_returned_and_not_followed() {
    let provider = provider_with_log_store(|_| {
        Reply::with_body(
            302,
            &[
                ("location", "https://oauth2.googleapis.com/token"),
                ("content-type", "text/html"),
            ],
            b"moved",
        )
    })
    .await;
    let (harness, app, record) = ready(&provider).await;
    let forwarded = harness
        .forward(meta(&app, &record, "GET", PROFILE, json!([])), b"")
        .await
        .unwrap();
    assert_eq!(forwarded.status, 302);
    assert_eq!(
        forwarded.header("location"),
        Some("https://oauth2.googleapis.com/token")
    );
    assert_eq!(forwarded.body, b"moved");
    // One request only: the credential did not follow the redirect.
    assert_eq!(provider.requests().len(), 1);
}

#[tokio::test]
async fn provider_answers_come_back_as_they_are() {
    let chunked = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Content-Type: application/json\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Connection: keep-alive, x-session\r\n",
        "Keep-Alive: timeout=5\r\n",
        "X-Session: hop\r\n",
        "Set-Cookie: a=1\r\n",
        "Set-Cookie: b=2\r\n",
        "\r\n",
        "7\r\n{\"ok\":t\r\n",
        "4\r\nrue}\r\n",
        "0\r\n\r\n",
    );
    let compressed: &[u8] = &[0x1f, 0x8b, 0x08, 0x00, 0xff, 0x00, 0x80, 0x7f];
    let answers = std::sync::Mutex::new(vec![
        Reply::Raw(chunked.as_bytes().to_vec()),
        Reply::with_body(200, &[("content-encoding", "gzip")], compressed),
        Reply::json(
            401,
            &json!({"error": {"code": 401, "status": "UNAUTHENTICATED"}}),
        ),
        Reply::Raw(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()),
    ]);
    let provider = provider_with_log_store(move |_| answers.lock().unwrap().remove(0)).await;
    let (harness, app, record) = ready(&provider).await;
    let call = |query: &'static str| {
        let request = meta(
            &app,
            &record,
            "GET",
            &format!("{PROFILE}?{query}"),
            json!([]),
        );
        let harness = &harness;
        async move { harness.forward(request, b"").await.unwrap() }
    };

    // A chunked response is decoded. The headers of the connection and the cookies are left
    // out: a cookie would be an access to the provider that no entry records.
    let forwarded = call("n=1").await;
    assert_eq!(forwarded.status, 200);
    assert_eq!(forwarded.body, br#"{"ok":true}"#);
    let names: Vec<&str> = forwarded
        .headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(names, ["content-type"]);

    // A compressed body is one the node cannot search: nothing of it is handed on. The
    // request went to the provider, and its entry is on the chain.
    let before = harness.head_seq("user-1");
    let withheld = harness
        .forward(
            meta(&app, &record, "GET", &format!("{PROFILE}?n=2"), json!([])),
            b"",
        )
        .await
        .err()
        .unwrap();
    assert_eq!(withheld.0, 502);
    assert_eq!(withheld.1["code"], "response_withheld");
    assert!(withheld.1.get("log").is_none());
    assert_eq!(harness.head_seq("user-1"), before + 1);
    assert_budget_is_free(&harness);

    // An authentication failure is the provider's answer, not a failure of the call.
    let forwarded = call("n=3").await;
    assert_eq!(forwarded.status, 401);
    assert_eq!(
        serde_json::from_slice::<Value>(&forwarded.body).unwrap()["error"]["status"],
        "UNAUTHENTICATED"
    );
    // The node did not refresh and did not retry.
    assert_eq!(provider.requests().len(), 3);

    let forwarded = call("n=4").await;
    assert_eq!(forwarded.status, 204);
    assert!(forwarded.body.is_empty());
    assert_budget_is_free(&harness);
}

#[tokio::test]
async fn bodies_above_the_limit_are_too_large() {
    assert_eq!(Limits::default().body_bytes, 67_108_864);
    assert_eq!(limits::BODY_BYTES, 64 * 1024 * 1024);

    const SMALL: usize = 64 * 1024;
    let oversized_chunked = {
        let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for _ in 0..5 {
            response.extend_from_slice(format!("{:x}\r\n", 16 * 1024).as_bytes());
            response.extend_from_slice(&vec![b'a'; 16 * 1024]);
            response.extend_from_slice(b"\r\n");
        }
        response.extend_from_slice(b"0\r\n\r\n");
        response
    };
    let answers = std::sync::Mutex::new(vec![
        // A declared length above the limit: refused without reading the body.
        Reply::Raw(
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", SMALL + 1).into_bytes(),
        ),
        // A chunked body that grows above the limit.
        Reply::Raw(oversized_chunked),
        // A body of exactly the limit.
        Reply::with_body(200, &[], &vec![b'b'; SMALL]),
        Reply::json(200, &json!({})),
    ]);
    let provider = provider_with_log_store(move |_| answers.lock().unwrap().remove(0)).await;
    let harness = Harness::with(
        &provider,
        Definitions::embedded(),
        Limits {
            body_bytes: SMALL,
            ..Limits::default()
        },
    );
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let record = google_record(&app);
    let post = |query: &str| {
        meta(
            &app,
            &record,
            "POST",
            &format!("{PROFILE}?{query}"),
            json!([]),
        )
    };

    assert_eq!(
        failure(harness.forward(post("n=1"), b"").await),
        (413, "too_large".to_string())
    );
    assert_eq!(
        failure(harness.forward(post("n=2"), b"").await),
        (413, "too_large".to_string())
    );
    let forwarded = harness.forward(post("n=3"), b"").await.unwrap();
    assert_eq!(forwarded.body.len(), SMALL);

    // A request body of exactly the limit is sent. One byte more is refused before the
    // provider is called and before an entry is made.
    let forwarded = harness
        .forward(post("n=4"), &vec![b'c'; SMALL])
        .await
        .unwrap();
    assert_eq!(forwarded.status, 200);
    assert_eq!(provider.requests().last().unwrap().body.len(), SMALL);
    let sent = provider.requests().len();
    let seq = harness.head_seq("user-1");
    assert_eq!(
        failure(harness.forward(post("n=5"), &vec![b'c'; SMALL + 1]).await),
        (413, "too_large".to_string())
    );
    assert_eq!(provider.requests().len(), sent);
    assert_eq!(harness.head_seq("user-1"), seq);
    assert_budget_is_free(&harness);
}

#[tokio::test]
async fn a_provider_that_does_not_answer_ends_in_a_timeout() {
    let provider = provider_with_log_store(|_| Reply::Hang).await;
    let (harness, app, record) = ready(&provider).await;
    let mut request = meta(&app, &record, "POST", PROFILE, json!([]));
    request["timeout_ms"] = json!(1000);
    let started = Instant::now();
    assert_eq!(
        failure(harness.forward(request, b"{}").await),
        (504, "timeout".to_string())
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1000) && elapsed < Duration::from_secs(4),
        "{elapsed:?}"
    );

    // The request left the node, so its entry is on the chain and in the store.
    assert_eq!(provider.requests().len(), 1);
    assert_eq!(harness.head_seq("user-1"), 2);
    let events = app.stored_events(&harness, &provider);
    assert_eq!(events.len(), 2);
    assert_eq!(events[1][0]["t"], "provider_request");
    assert_budget_is_free(&harness);
}

#[tokio::test]
async fn a_provider_that_cannot_be_reached_is_unreachable() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app, record) = ready(&provider).await;
    // Nothing listens at this address.
    harness
        .platform
        .route("gmail.googleapis.com", "127.0.0.1:1".parse().unwrap());
    assert_eq!(
        failure(
            harness
                .forward(meta(&app, &record, "GET", PROFILE, json!([])), b"")
                .await
        ),
        (502, "provider_unreachable".to_string())
    );

    // A stand-in whose certificate the node does not trust is unreachable as well.
    let stranger = quiet_provider().await;
    harness
        .platform
        .route("gmail.googleapis.com", stranger.address);
    assert_eq!(
        failure(
            harness
                .forward(
                    meta(&app, &record, "GET", &format!("{PROFILE}?n=2"), json!([])),
                    b""
                )
                .await
        ),
        (502, "provider_unreachable".to_string())
    );
    assert!(stranger.seen().is_empty());
    assert_budget_is_free(&harness);
}

#[tokio::test]
async fn forward_needs_the_front_conditions() {
    let provider = quiet_provider_and_log_store().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    let record = google_record(&app);
    let request = meta(&app, &record, "GET", PROFILE, json!([]));

    // Without the operator configuration, then without a grant.
    app.grant(&harness).await;
    assert_eq!(
        failure(harness.forward(request.clone(), b"").await),
        (503, "not_configured".to_string())
    );
    harness.use_log_store().await;
    let stranger = App::new("user-2", 2);
    let theirs = google_record(&stranger);
    assert_eq!(
        failure(
            harness
                .forward(meta(&stranger, &theirs, "GET", PROFILE, json!([])), b"")
                .await
        ),
        (409, "grant_required".to_string())
    );

    // A record whose token object holds no access token.
    let empty = app.record(
        "oauth",
        "google_workspace",
        &json!({"token": {"refresh_token": "r"}, "obtained_ms": 1}),
    );
    assert_eq!(
        failure(
            harness
                .forward(meta(&app, &empty, "GET", PROFILE, json!([])), b"")
                .await
        ),
        (422, "record_invalid".to_string())
    );
    // A record of a provider without a definition.
    let unknown = app.record(
        "oauth",
        "dropbox",
        &json!({"token": {"access_token": "a"}, "obtained_ms": 1}),
    );
    assert_eq!(
        failure(
            harness
                .forward(meta(&app, &unknown, "GET", PROFILE, json!([])), b"")
                .await
        ),
        (404, "provider_unknown".to_string())
    );
    assert!(provider.requests().is_empty());

    // The kinds of release v1.0.0 that this release does not know are not allowed.
    for (kind, plaintext) in [
        ("api_key", json!({"api_key": "secret_key_1"})),
        ("oauth_operator", json!({"access_token": "ya29.operator"})),
    ] {
        let old = app.record(kind, "notion", &plaintext);
        assert_eq!(
            failure(
                harness
                    .forward(
                        meta(
                            &app,
                            &old,
                            "POST",
                            "https://api.notion.com/v1/search",
                            json!([])
                        ),
                        b"{}"
                    )
                    .await
            ),
            (403, "not_allowed".to_string()),
            "{kind}"
        );
    }
    assert!(provider.requests().is_empty());

    // A record of kind `oauth_imported` (a token the device of the account encrypted) is used
    // by the same rules as a record of kind `oauth`.
    let imported = app.record(
        "oauth_imported",
        "notion",
        &json!({"token": {"access_token": "ntn_imported-access"}, "obtained_ms": 1}),
    );
    let forwarded = harness
        .forward(
            meta(
                &app,
                &imported,
                "POST",
                "https://api.notion.com/v1/search",
                json!([]),
            ),
            b"{}",
        )
        .await
        .unwrap();
    assert_eq!(forwarded.status, 200);
    assert_eq!(
        provider.only().header("authorization"),
        Some("Bearer ntn_imported-access")
    );
    assert_eq!(
        app.logged(&harness, &provider, &forwarded.log)["provider"],
        "notion"
    );
}

#[tokio::test]
async fn a_response_that_reflects_the_credential_is_withheld() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    // The stand-in breaks the contract of an API: it sends the `Authorization` value of the
    // request back, in the body or in a header, as it is or encoded.
    let provider = provider_with_log_store(|seen| {
        let authorization = seen.header("authorization").unwrap_or_default().to_string();
        let token = authorization.trim_start_matches("Bearer ").to_string();
        match seen.target.rsplit('=').next().unwrap_or_default() {
            "body" => Reply::json(200, &json!({"headers": {"Authorization": authorization}})),
            "base64" => Reply::json(
                200,
                &json!({"debug": STANDARD.encode(format!("auth: {authorization}"))}),
            ),
            "hex" => Reply::json(
                200,
                &json!({"debug": token.bytes().map(|byte| format!("{byte:02x}")).collect::<String>()}),
            ),
            "header" => Reply::with_body(200, &[("x-echo", authorization.as_str())], b"{}"),
            "error" => Reply::json(500, &json!({"error": format!("bad token {token}")})),
            _ => Reply::json(200, &json!({"ok": true})),
        }
    })
    .await;
    let harness = Harness::new(&provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let record = app.record(
        "oauth",
        "google_workspace",
        &json!({
            "token": {"access_token": "ya29.a0Af-reflected/token+value=1234567890"},
            "obtained_ms": 1,
        }),
    );
    for (index, case) in ["body", "base64", "hex", "header", "error"]
        .into_iter()
        .enumerate()
    {
        let before = harness.head_seq("user-1");
        let outcome = harness
            .forward(
                meta(
                    &app,
                    &record,
                    "POST",
                    &format!("{PROFILE}?case={case}"),
                    json!([]),
                ),
                b"{}",
            )
            .await;
        let (status, body) = outcome.err().expect("the response must be withheld");
        assert_eq!(status, 502, "{case}");
        assert_eq!(
            body,
            json!({
                "code": "response_withheld",
                "message": "the provider response was withheld by the egress policy",
            }),
            "{case}"
        );
        // The request went out, and its entry is on the chain.
        assert_eq!(provider.requests().len(), index + 1);
        assert_eq!(harness.head_seq("user-1"), before + 1);
    }
    // A response without the credential comes back.
    let forwarded = harness
        .forward(
            meta(
                &app,
                &record,
                "POST",
                &format!("{PROFILE}?case=clean"),
                json!([]),
            ),
            b"{}",
        )
        .await
        .unwrap();
    assert_eq!(forwarded.body, br#"{"ok":true}"#);
    assert_budget_is_free(&harness);
}

/// The connections of the node to the host of `PROFILE`, in the order they were opened.
#[tokio::test]
async fn two_calls_whose_responses_have_no_length_do_not_wait_for_each_other() {
    // Each response declares no length, so each reserves the whole body limit of 1,000 bytes.
    // The budget holds two request frames and one such response but not two frames and two
    // responses: a call must give its frame back before its response asks for its share, or
    // the two calls hold their frames and wait for each other until the time limit.
    let provider = provider_with_log_store(|_| {
        Reply::Raw(
            b"HTTP/1.1 200 Status\r\ncontent-type: text/plain\r\ntransfer-encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"
                .to_vec(),
        )
        .after(Duration::from_millis(300))
    })
    .await;
    let app = App::new("user-1", 1);
    let record = google_record(&app);
    let first = meta(&app, &record, "GET", PROFILE, json!([]));
    let second = meta(
        &app,
        &record,
        "GET",
        "https://gmail.googleapis.com/gmail/v1/users/me/messages",
        json!([]),
    );
    let frame = crate::frame::encode_head(&first).len();
    let harness = Harness::with(
        &provider,
        Definitions::embedded(),
        Limits {
            body_bytes: 1_000,
            body_budget_bytes: 2 * frame + 1_000 - 1,
            ..Limits::default()
        },
    );
    harness.use_log_store().await;
    app.grant(&harness).await;
    let started = Instant::now();
    let (one, two) = tokio::join!(harness.forward(first, b""), harness.forward(second, b""));
    assert_eq!(one.unwrap().status, 200);
    assert_eq!(two.unwrap().status, 200);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_budget_is_free(&harness);
}

fn gmail_connections(harness: &Harness) -> usize {
    harness
        .platform
        .connections()
        .iter()
        .filter(|(host, _)| host == "gmail.googleapis.com")
        .count()
}

#[tokio::test]
async fn requests_of_one_account_to_one_host_share_a_connection_and_accounts_do_not() {
    let provider =
        provider_with_log_store(|_| Reply::json(200, &json!({"ok": true})).keep_alive()).await;
    let (harness, app, record) = ready(&provider).await;
    let idle = |user_id: &str| {
        harness
            .node
            .egress
            .provider_idle
            .idle_count(user_id, "gmail.googleapis.com")
    };

    // Three requests of one account in a row: one connection, kept idle between them.
    for query in ["n=1", "n=2", "n=3"] {
        let request = meta(
            &app,
            &record,
            "GET",
            &format!("{PROFILE}?{query}"),
            json!([]),
        );
        assert_eq!(harness.forward(request, b"").await.unwrap().status, 200);
    }
    assert_eq!(gmail_connections(&harness), 1);
    assert_eq!(idle("user-1"), 1);

    // Another account to the same host: its own connection. The first account's connection
    // stays idle for the first account.
    let other = App::new("user-2", 2);
    other.grant(&harness).await;
    let theirs = google_record(&other);
    let request = meta(&other, &theirs, "GET", &format!("{PROFILE}?n=4"), json!([]));
    assert_eq!(harness.forward(request, b"").await.unwrap().status, 200);
    assert_eq!(gmail_connections(&harness), 2);
    assert_eq!((idle("user-1"), idle("user-2")), (1, 1));

    // A connection idle for longer than 30 seconds is not used again.
    harness.node.clock.advance(limits::PROVIDER_IDLE_MS + 1);
    let request = meta(&app, &record, "GET", &format!("{PROFILE}?n=5"), json!([]));
    assert_eq!(harness.forward(request, b"").await.unwrap().status, 200);
    assert_eq!(gmail_connections(&harness), 3);
    assert_eq!(idle("user-1"), 1);

    // A response with `Connection: close` ends the connection: the next request opens one.
    assert_eq!(provider.requests().len(), 5);
    assert_budget_is_free(&harness);
}

#[tokio::test]
async fn a_get_over_an_idle_connection_that_ends_without_a_response_is_sent_once_more() {
    // The stand-in keeps the connection after the first answer, closes it without a response
    // when the second request arrives over it, and answers every later request.
    let answers = std::sync::Mutex::new(vec![
        Reply::json(200, &json!({"n": 1})).keep_alive(),
        Reply::Raw(Vec::new()),
        Reply::json(200, &json!({"n": 3})).keep_alive(),
        Reply::Raw(Vec::new()),
    ]);
    let provider = provider_with_log_store(move |_| {
        let mut answers = answers.lock().unwrap();
        match answers.is_empty() {
            true => Reply::json(200, &json!({"ok": true})).keep_alive(),
            false => answers.remove(0),
        }
    })
    .await;
    let (harness, app, record) = ready(&provider).await;

    // The first GET opens the connection; the second goes over it, gets no response, and is
    // sent once more over a new connection: the caller sees the answer of the third try.
    let first = meta(&app, &record, "GET", &format!("{PROFILE}?n=1"), json!([]));
    assert_eq!(
        harness.forward(first, b"").await.unwrap().body,
        br#"{"n":1}"#
    );
    let second = meta(&app, &record, "GET", &format!("{PROFILE}?n=2"), json!([]));
    let forwarded = harness.forward(second, b"").await.unwrap();
    assert_eq!(forwarded.body, br#"{"n":3}"#);
    assert_eq!(gmail_connections(&harness), 2);
    assert_eq!(provider.requests().len(), 3);
    // Both tries are the same request, which one event names.
    assert_eq!(forwarded.log["created"], true);
    assert_eq!(harness.head_seq("user-1"), 3);

    // A POST over an idle connection that ends without a response is not sent again: whether
    // the provider received it is unknown.
    let post = meta(&app, &record, "POST", &format!("{PROFILE}?n=4"), json!([]));
    assert_eq!(
        failure(harness.forward(post, b"{}").await),
        (502, "provider_unreachable".to_string())
    );
    assert_eq!(gmail_connections(&harness), 2);
    assert_eq!(provider.requests().len(), 4);
    assert_eq!(harness.head_seq("user-1"), 4);
    assert_budget_is_free(&harness);
}
