//! The HTTP calls with an application password (enclave.md 5.8, 5.8b and 5.8c): `forward` and
//! `forward/batch` with a record of kind `app_password` of a provider of the application
//! password definitions, and `app-password/verify`, against a stand-in for the CalDAV host of
//! NAVER Calendar.

use std::collections::BTreeSet;

use axum::http::Method;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use credential_enclave_protocol::encoding::b64u;
use credential_enclave_protocol::purpose;
use hyper::body::Bytes;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::provider_with_log_store;
use crate::frame;
use crate::testing::{App, Forwarded, Harness, Provider, Reply, Seen, LOG_HOST};

const PASSWORD: &str = "calendar-secret-marker-5b1d9f0c7a3e";
const HOST: &str = "caldav.calendar.naver.com";
const ROOT: &str = "https://caldav.calendar.naver.com/";
const CALENDARS: &str = "https://caldav.calendar.naver.com/calendars/tester/";
/// The request body of the definition (enclave.md 6.5).
const PROPFIND: &[u8] = concat!(
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
    "<d:propfind xmlns:d=\"DAV:\"><d:prop><d:current-user-principal/></d:prop></d:propfind>"
)
.as_bytes();
const MULTISTATUS: &[u8] = concat!(
    "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\"><d:response><d:href>/</d:href>",
    "<d:propstat><d:prop><d:current-user-principal><d:href>/principals/tester/</d:href>",
    "</d:current-user-principal></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>",
    "</d:response></d:multistatus>"
)
.as_bytes();

/// The HTTP Basic value of `login` and the password of the tests.
fn basic(login: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{login}:{PASSWORD}")))
}

/// A stand-in for the CalDAV host that accepts the password of the account `tester`: it
/// answers 207 with a multistatus body to a request with that credential and 401 to any
/// other. Every other host answers 200.
fn caldav(seen: &Seen) -> Reply {
    if seen.server_name != HOST {
        return Reply::json(200, &json!({"ok": true}));
    }
    match seen.header("authorization") {
        Some(value) if value == basic("tester") => Reply::with_body(
            207,
            &[
                ("content-type", "application/xml; charset=utf-8"),
                ("etag", "\"1\""),
            ],
            MULTISTATUS,
        ),
        _ => Reply::with_body(
            401,
            &[("www-authenticate", "basic realm=\"Naver Calendar\"")],
            b"",
        ),
    }
}

fn calendar_record(app: &App, username: &str) -> Value {
    app.record(
        "app_password",
        "naver_calendar",
        &json!({"username": username, "password": PASSWORD}),
    )
}

fn google_record(app: &App) -> Value {
    app.record(
        "oauth",
        "google_workspace",
        &json!({"token": {"access_token": "ya29.injected"}, "obtained_ms": 1}),
    )
}

/// A node with the log store of the tests (the stand-in confirms every write), the app of an
/// account that granted on it, and a NAVER Calendar record of that account whose account name
/// carries the domain, in upper case.
async fn ready(provider: &Provider) -> (Harness, App, Value) {
    let harness = Harness::new(provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let record = calendar_record(&app, "Tester@Naver.com");
    (harness, app, record)
}

fn meta(app: &App, record: &Value, method: &str, url: &str, headers: Value) -> Value {
    json!({
        "user_id": app.user_id, "record": record, "method": method, "url": url,
        "headers": headers, "context": "cli:naver-calendar", "timeout_ms": 5000,
    })
}

fn failure(outcome: Result<Forwarded, (u16, Value)>) -> (u16, String) {
    let (status, body) = outcome.err().expect("the call must fail");
    (
        status,
        body["code"].as_str().unwrap_or_default().to_string(),
    )
}

/// Fails when `bytes` hold the password: as it is, in base64, or inside the base64 of the
/// credential header.
fn assert_without_password(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    assert!(!text.contains(PASSWORD));
    assert!(!text.contains(&STANDARD.encode(PASSWORD)));
    assert!(!text.contains(&STANDARD.encode(format!("tester:{PASSWORD}"))));
}

/// A verify call. `Ok` is the status of the frame, its meta and its JSON body; `Err` the
/// status and the failure body of a refused call.
async fn verify(
    harness: &Harness,
    app: &App,
    record: &Value,
    request: Option<Value>,
    payload: &[u8],
) -> Result<(u16, Value, Value), (u16, Value)> {
    let mut meta = json!({
        "user_id": app.user_id, "record": record, "context": "connect:naver_calendar",
    });
    if let Some(request) = request {
        meta["request"] = request;
    }
    let mut wire = frame::encode_head(&meta);
    wire.extend_from_slice(payload);
    let answer = harness
        .call(Method::POST, "/v1/app-password/verify", wire)
        .await;
    assert_without_password(&answer.body);
    if answer.status != 200 {
        return Err((answer.status, serde_json::from_slice(&answer.body).unwrap()));
    }
    let (meta, body) = frame::decode(&Bytes::from(answer.body)).unwrap();
    let status = meta["status"].as_u64().unwrap() as u16;
    Ok((status, meta, serde_json::from_slice(&body).unwrap()))
}

#[tokio::test]
async fn forward_sends_the_password_as_http_basic_and_logs_the_request() {
    let provider = provider_with_log_store(caldav).await;
    let (harness, app, record) = ready(&provider).await;
    let headers = json!([
        ["Depth", "0"],
        ["Content-Type", "application/xml; charset=utf-8"],
        ["Authorization", "Basic from-the-caller"],
        ["Accept-Encoding", "gzip"],
    ]);
    let forwarded = harness
        .forward(meta(&app, &record, "PROPFIND", ROOT, headers), PROPFIND)
        .await
        .unwrap();
    assert_eq!(forwarded.status, 207);
    assert_eq!(forwarded.body, MULTISTATUS);
    assert_eq!(forwarded.header("etag"), Some("\"1\""));
    assert_without_password(&forwarded.body);

    // The login is the account name without its domain, in lower case. The credential
    // header of the caller is dropped and the node's takes its place.
    let seen = provider.only();
    assert_eq!(
        (
            seen.server_name.as_str(),
            seen.method.as_str(),
            seen.target.as_str()
        ),
        (HOST, "PROPFIND", "/")
    );
    assert_eq!(seen.body, PROPFIND);
    assert_eq!(seen.header("authorization"), Some(basic("tester").as_str()));
    assert_eq!(seen.header("accept-encoding"), Some("identity"));
    assert_eq!(
        seen.header_names(),
        [
            "host",
            "content-length",
            "authorization",
            "accept-encoding",
            "depth",
            "content-type",
            "connection",
        ]
    );

    // The event is the `provider_request` of the record, as for a token record.
    assert_eq!(forwarded.log["created"], true);
    let mut event = app.logged(&harness, &provider, &forwarded.log);
    assert!(event["time_ms"].as_u64().is_some());
    event.as_object_mut().unwrap().remove("time_ms");
    assert_eq!(
        event,
        json!({
            "t": "provider_request", "record_id": record["id"], "provider": "naver_calendar",
            "method": "PROPFIND", "host": HOST, "path": "/", "query": "",
            "body_bytes": PROPFIND.len(), "body_sha256": b64u(&Sha256::digest(PROPFIND)),
            "context": "cli:naver-calendar",
        })
    );
}

#[tokio::test]
async fn the_headers_of_the_caller_pass_in_their_case_and_a_repeated_get_shares_its_event() {
    let provider = provider_with_log_store(caldav).await;
    let (harness, app, record) = ready(&provider).await;
    // The headers of a conditional write, as the backend sends them, and a credential header
    // in lower case, which is dropped like the one in canonical case.
    let headers = json!([
        ["DEPTH", "1"],
        ["If-None-Match", "*"],
        ["Prefer", "return=minimal"],
        ["authorization", "Basic from-the-caller"],
    ]);
    let item = "https://caldav.calendar.naver.com/calendars/tester/default/a.ics";
    let forwarded = harness
        .forward(
            meta(&app, &record, "PUT", item, headers),
            b"BEGIN:VCALENDAR\r\n",
        )
        .await
        .unwrap();
    assert_eq!(forwarded.status, 207);
    let seen = provider.only();
    assert_eq!(seen.header("depth"), Some("1"));
    assert_eq!(seen.header("if-none-match"), Some("*"));
    assert_eq!(seen.header("prefer"), Some("return=minimal"));
    assert_eq!(seen.header("authorization"), Some(basic("tester").as_str()));

    // Two identical GET requests without a body within 300 seconds share one event, as with
    // a token record. A third one for another path has its own.
    let first = harness
        .forward(meta(&app, &record, "GET", CALENDARS, json!([])), b"")
        .await
        .unwrap();
    let second = harness
        .forward(meta(&app, &record, "GET", CALENDARS, json!([])), b"")
        .await
        .unwrap();
    assert_eq!(first.log["created"], true);
    assert_eq!(second.log["created"], false);
    assert_eq!(second.log["seq"], first.log["seq"]);
    assert_eq!(second.log["index"], first.log["index"]);
    let other = harness
        .forward(meta(&app, &record, "GET", ROOT, json!([])), b"")
        .await
        .unwrap();
    assert_eq!(other.log["created"], true);
    assert_eq!(provider.requests().len(), 4);
}

#[tokio::test]
async fn a_batch_sends_every_request_with_the_password_after_one_entry() {
    let provider = provider_with_log_store(caldav).await;
    let (harness, app, record) = ready(&provider).await;
    let requests = json!([
        {"method": "PROPFIND", "url": ROOT, "headers": [["Depth", "0"]], "body_bytes": PROPFIND.len()},
        {"method": "GET", "url": CALENDARS, "headers": [], "body_bytes": 0},
    ]);
    let batch = json!({
        "user_id": app.user_id, "record": record, "context": "cli:naver-calendar",
        "timeout_ms": 5000, "requests": requests,
    });
    let outcomes = harness.forward_batch(batch, PROPFIND).await.unwrap();
    assert_eq!(outcomes.len(), 2);
    for outcome in &outcomes {
        assert_eq!(outcome.status, Some(207), "{:?}", outcome.error);
        assert_eq!(outcome.body, MULTISTATUS);
        assert_eq!(outcome.log["created"], true);
        assert_without_password(&outcome.body);
    }
    assert_eq!(outcomes[0].log["seq"], outcomes[1].log["seq"]);
    let seen = provider.requests();
    assert_eq!(seen.len(), 2);
    for request in &seen {
        assert_eq!(request.server_name, HOST);
        assert_eq!(
            request.header("authorization"),
            Some(basic("tester").as_str())
        );
    }
    let methods: BTreeSet<&str> = seen.iter().map(|seen| seen.method.as_str()).collect();
    assert_eq!(methods, BTreeSet::from(["PROPFIND", "GET"]));
    // A method the definition does not list refuses the whole batch with its index.
    let refused = json!({
        "user_id": app.user_id, "record": record, "context": "cli:naver-calendar",
        "requests": [
            {"method": "GET", "url": ROOT, "headers": [], "body_bytes": 0},
            {"method": "PATCH", "url": ROOT, "headers": [], "body_bytes": 0},
        ],
    });
    let (status, body) = harness.forward_batch(refused, b"").await.unwrap_err();
    assert_eq!((status, body["code"].as_str()), (403, Some("not_allowed")));
    assert_eq!(body["index"], 1);
    assert_eq!(provider.requests().len(), 2);
}

#[tokio::test]
async fn the_definition_bounds_the_methods_and_the_hosts_the_password_reaches() {
    let provider = provider_with_log_store(caldav).await;
    let (harness, app, record) = ready(&provider).await;
    let item = "https://caldav.calendar.naver.com/calendars/tester/default/a.ics";
    for method in ["PROPFIND", "REPORT", "GET", "PUT", "DELETE"] {
        let forwarded = harness
            .forward(meta(&app, &record, method, item, json!([])), b"")
            .await
            .unwrap_or_else(|failure| panic!("{method}: {failure:?}"));
        assert_eq!(forwarded.status, 207, "{method}");
    }
    assert_eq!(provider.requests().len(), 5);
    // A method the definition does not list, and an address outside it.
    for (method, url) in [
        ("PATCH", ROOT),
        ("POST", ROOT),
        ("MKCALENDAR", ROOT),
        ("propfind", ROOT),
        ("PROPFIND", "https://caldav.calendar.naver.com:8443/"),
        ("PROPFIND", "https://calendar.naver.com/"),
        (
            "PROPFIND",
            "https://gmail.googleapis.com/gmail/v1/users/me/profile",
        ),
        ("PROPFIND", "http://caldav.calendar.naver.com/"),
    ] {
        assert_eq!(
            failure(
                harness
                    .forward(meta(&app, &record, method, url, json!([])), b"")
                    .await
            ),
            (403, "not_allowed".to_string()),
            "{method} {url}"
        );
    }
    // A token of another provider does not reach the CalDAV host.
    assert_eq!(
        failure(
            harness
                .forward(
                    meta(&app, &google_record(&app), "GET", ROOT, json!([])),
                    b""
                )
                .await
        ),
        (403, "not_allowed".to_string())
    );
    assert_eq!(provider.requests().len(), 5);
}

#[tokio::test]
async fn records_of_another_kind_or_provider_are_not_taken_by_the_http_calls() {
    let provider = provider_with_log_store(caldav).await;
    let (harness, app, _) = ready(&provider).await;
    let not_allowed = |status: u16, body: &Value| {
        assert_eq!((status, body["code"].as_str()), (403, Some("not_allowed")));
    };
    // The password of NAVER Mail is used by the mail calls only, a vault record by `release`
    // only, and a password of a provider that has an OAuth definition exists for no call.
    let mail = app.record(
        "app_password",
        "naver_mail",
        &json!({"username": "tester@naver.com", "password": PASSWORD}),
    );
    let vault = app.record("vault_password", "vault", &json!({"value": PASSWORD}));
    let misnamed = app.record(
        "app_password",
        "google_workspace",
        &json!({"username": "tester", "password": PASSWORD}),
    );
    for record in [&mail, &vault, &misnamed] {
        let (status, body) = harness
            .forward(meta(&app, record, "PROPFIND", ROOT, json!([])), PROPFIND)
            .await
            .err()
            .expect("the call must fail");
        not_allowed(status, &body);
        let (status, body) = verify(&harness, &app, record, Some(json!({})), b"")
            .await
            .unwrap_err();
        not_allowed(status, &body);
    }
    // A token record has no verification, whatever its provider: the call refuses it by its
    // kind before it reads the plaintext, where `forward` would look for the OAuth definition
    // (`provider_unknown` for a provider that has none).
    let google = google_record(&app);
    let token_named_calendar = app.record(
        "oauth",
        "naver_calendar",
        &json!({"token": {"access_token": "ya29.injected"}, "obtained_ms": 1}),
    );
    for record in [&google, &token_named_calendar] {
        let (status, body) = verify(&harness, &app, record, None, b"").await.unwrap_err();
        assert_eq!(
            (status, body),
            (
                403,
                json!({
                    "code": "not_allowed",
                    "message": "the provider definition does not allow this",
                })
            )
        );
    }
    assert_eq!(
        failure(
            harness
                .forward(
                    meta(&app, &token_named_calendar, "GET", ROOT, json!([])),
                    b""
                )
                .await
        ),
        (404, "provider_unknown".to_string())
    );
    assert!(provider.requests().is_empty());
}

#[tokio::test]
async fn verify_sends_the_request_of_the_definition_and_states_the_identity() {
    let provider = provider_with_log_store(caldav).await;
    let (harness, app, record) = ready(&provider).await;
    let (status, meta, body) = verify(&harness, &app, &record, Some(json!({})), b"")
        .await
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(
        meta["headers"],
        json!([["content-type", "application/json"]])
    );
    assert_eq!(meta["log"]["created"], true);
    // The response of the provider stays inside the node: the body is the identity, the node
    // and the statement.
    assert_eq!(
        body.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["identity", "node", "statement"]
    );
    assert_eq!(body["identity"], "tester@naver.com");
    assert_eq!(body["node"], harness.node.node.as_str());
    let statement = harness.verified(purpose::STATEMENT, &body["statement"]);
    assert_eq!(statement["v"], 1);
    assert_eq!(statement["type"], "app_password_verified");
    assert_eq!(statement["node"], harness.node.node.as_str());
    assert_eq!(statement["user_id"], "user-1");
    assert_eq!(statement["provider"], "naver_calendar");
    assert_eq!(statement["record_id"], record["id"]);
    assert_eq!(statement["key_id"], app.keys.key_id());
    assert_eq!(statement["sign_pk"], b64u(&app.keys.sign_pk()));
    assert_eq!(
        statement["ciphertext_sha256"],
        b64u(&Sha256::digest(record["ct"].as_str().unwrap().as_bytes()))
    );
    assert_eq!(statement["identity"], "tester@naver.com");
    assert!(statement["time_ms"].as_u64().is_some());

    // The request is the one of the definition: PROPFIND of the root with its headers and its
    // body, under the credential of the record.
    let seen = provider.only();
    assert_eq!(
        (seen.method.as_str(), seen.target.as_str()),
        ("PROPFIND", "/")
    );
    assert_eq!(seen.header("authorization"), Some(basic("tester").as_str()));
    assert_eq!(seen.header("depth"), Some("0"));
    assert_eq!(
        seen.header("content-type"),
        Some("application/xml; charset=utf-8")
    );
    assert_eq!(seen.body, PROPFIND);
    // The event is the `provider_request` of that request.
    let event = app.logged(&harness, &provider, &meta["log"]);
    assert_eq!(event["t"], "provider_request");
    assert_eq!(event["provider"], "naver_calendar");
    assert_eq!(event["method"], "PROPFIND");
    assert_eq!(event["path"], "/");
    assert_eq!(event["body_bytes"], PROPFIND.len());
    assert_eq!(event["context"], "connect:naver_calendar");

    // Without `request`, or with `null`, the call is the same. A request of its own, or a
    // payload, is refused before anything is opened.
    assert_eq!(
        verify(&harness, &app, &record, None, b"").await.unwrap().0,
        200
    );
    assert_eq!(
        verify(&harness, &app, &record, Some(Value::Null), b"")
            .await
            .unwrap()
            .0,
        200
    );
    assert_eq!(
        verify(&harness, &app, &record, Some(json!({"action": "x"})), b"")
            .await
            .unwrap_err()
            .0,
        400
    );
    assert_eq!(
        verify(&harness, &app, &record, Some(json!({})), b"x")
            .await
            .unwrap_err()
            .0,
        400
    );
    assert_eq!(provider.requests().len(), 3);
}

#[tokio::test]
async fn verify_reports_a_refused_password_and_every_other_answer_as_not_verified() {
    let provider = provider_with_log_store(caldav).await;
    let (harness, app, _) = ready(&provider).await;
    // The stand-in accepts the password of `tester` only.
    let other = calendar_record(&app, "someone.else");
    let (status, _, body) = verify(&harness, &app, &other, None, b"").await.unwrap();
    assert_eq!(
        (status, body),
        (401, json!({"code": "authentication_failed"}))
    );
    assert_eq!(
        provider.only().header("authorization"),
        Some(basic("someone.else").as_str())
    );

    // Any other answer is the fixed frame status 502 with the status of the provider in the
    // body: a 200 of a page that is not the provider accepting the password (the definition
    // accepts 207 only), a redirect, which is not followed, and a failure of the provider.
    for (answer, status) in [
        (
            Reply::with_body(
                200,
                &[("content-type", "text/html")],
                b"<html>maintenance</html>",
            ),
            200,
        ),
        (
            Reply::with_body(
                302,
                &[("location", "https://caldav.calendar.naver.com/dav/")],
                b"",
            ),
            302,
        ),
        (Reply::json(503, &json!({"error": "busy"})), 503),
    ] {
        let answered = std::sync::Mutex::new(Some(answer));
        let provider = provider_with_log_store(move |seen: &Seen| match seen.target.as_str() {
            "/" => answered
                .lock()
                .unwrap()
                .take()
                .expect("the probe is sent once"),
            _ => Reply::json(200, &json!({"ok": true})),
        })
        .await;
        let (harness, app, record) = ready(&provider).await;
        let (frame_status, _, body) = verify(&harness, &app, &record, None, b"").await.unwrap();
        assert_eq!(
            (frame_status, body),
            (
                502,
                json!({"code": "verification_failed", "status": status})
            ),
            "{status}"
        );
        assert_eq!(provider.requests().len(), 1, "{status}");
    }
}

#[tokio::test]
async fn a_response_that_reflects_the_password_is_withheld() {
    // The stand-in breaks its contract: it sends the credential header back in its body.
    let provider = provider_with_log_store(|seen: &Seen| {
        let echoed = seen.header("authorization").unwrap_or_default().to_string();
        Reply::with_body(207, &[("content-type", "text/plain")], echoed.as_bytes())
    })
    .await;
    let (harness, app, record) = ready(&provider).await;
    assert_eq!(
        failure(
            harness
                .forward(meta(&app, &record, "PROPFIND", ROOT, json!([])), PROPFIND)
                .await
        ),
        (502, "response_withheld".to_string())
    );
    assert_eq!(
        verify(&harness, &app, &record, None, b"")
            .await
            .unwrap_err(),
        (
            502,
            json!({
                "code": "response_withheld",
                "message": "the provider response was withheld by the egress policy",
            })
        )
    );
    // Both requests went out: their entries are on the chain before the responses came back.
    assert_eq!(provider.requests().len(), 2);
}

/// The two cases of the route of the canary test: a verification that passes, and a refused
/// record (a vault record is `not_allowed`). The password reaches the CalDAV host only, and no
/// response of the walk holds it.
pub async fn canary_routes() -> (BTreeSet<(String, String)>, BTreeSet<(String, String)>) {
    let provider = provider_with_log_store(caldav).await;
    let (harness, app, record) = ready(&provider).await;
    let route = ("POST".to_string(), "/v1/app-password/verify".to_string());
    let (status, _, body) = verify(&harness, &app, &record, Some(json!({})), b"")
        .await
        .unwrap();
    assert_eq!(
        (status, body["identity"].as_str()),
        (200, Some("tester@naver.com"))
    );
    let vault = app.record("vault_password", "vault", &json!({"value": PASSWORD}));
    assert_eq!(
        verify(&harness, &app, &vault, Some(json!({})), b"")
            .await
            .unwrap_err()
            .0,
        403
    );
    let forwarded = harness
        .forward(meta(&app, &record, "GET", CALENDARS, json!([])), b"")
        .await
        .unwrap();
    assert_without_password(&forwarded.body);
    for (name, value) in &forwarded.headers {
        assert_without_password(name.as_bytes());
        assert_without_password(value.as_bytes());
    }
    for (host, port) in harness.platform.connections() {
        assert!(host == LOG_HOST || host == HOST, "{host}");
        assert_eq!(port, 443);
    }
    for seen in provider.requests() {
        assert_eq!(seen.server_name, HOST);
        assert_eq!(seen.header("authorization"), Some(basic("tester").as_str()));
    }
    (BTreeSet::from([route.clone()]), BTreeSet::from([route]))
}

#[tokio::test]
async fn the_route_passes_and_fails_without_a_password_in_a_response() {
    canary_routes().await;
}
