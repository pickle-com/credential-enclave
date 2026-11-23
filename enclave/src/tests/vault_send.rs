//! `POST /v1/vault/send` (enclave.md 5.16): a node of the forward role sends the one request
//! of a secret use, with the value at its slot, and hands the response on while it arrives.
//!
//! The envelopes of these tests are sealed by keys the tests hold, in the place of a node of
//! the delegation role: a node of the forward role opens what is sealed to it and signed by
//! the node the envelope names. The tests of `vault/handoff` make the envelope with a node.

use std::time::{Duration, Instant};

use axum::http::Method;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use credential_enclave_protocol::encoding::b64u;
use credential_enclave_protocol::keys::NodeKeys;
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::secret_use::{seal_secret_use, BoundRequest};
use hyper::body::Body as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::quiet_provider;
use crate::frame;
use crate::provider_response::{Forms, StreamCheck, ESCAPED_BYTE_SPAN};
use crate::state::lock;
use crate::testing::{operator_config, read_stream, Harness, Provider, Reply, Seen, Streamed};

/// The host of the site of the secret.
const SITE: &str = "api.site.example";
const USER: &str = "user-1";
const PLACEHOLDER: &str = "PLACEHOLDER_0123456789abcdef";
/// A value with characters a path, a query and a form write as escapes.
const VALUE: &str = "sk-live_4f9A/b+c=d~0123456789";
const RECORD_ID: &str = "MTExMTExMTExMTExMTExMQ";

/// A stand-in for the site.
async fn site(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Provider {
    Provider::start(&[SITE], handler).await
}

/// A stand-in for the site that answers every request with `200 {"ok":true}` and keeps its
/// connections open for the next request.
async fn quiet_site() -> Provider {
    site(|_| Reply::json(200, &json!({"ok": true})).keep_alive()).await
}

/// A node that took the forward role.
async fn forward_node(provider: &Provider) -> Harness {
    let harness = Harness::new(provider);
    let (status, _) = harness.post("/v1/config", json!({"role": "forward"})).await;
    assert_eq!(status, 200);
    harness
}

/// The keys that stand for a node of the delegation role.
fn giving() -> NodeKeys {
    NodeKeys::from_random(&[0x61; 32], &[0x62; 32])
}

/// The request object of a use.
fn request_of(method: &str, path: &str, query: &str, slot: &str, body: &[u8]) -> Value {
    let body_sha256 = match body.is_empty() {
        true => String::new(),
        false => b64u(&Sha256::digest(body)),
    };
    json!({
        "method": method, "host": SITE, "path": path, "query": query, "slot": slot,
        "placeholder": PLACEHOLDER, "body_bytes": body.len(), "body_sha256": body_sha256,
    })
}

/// An envelope of the account `user_id` for `forward` that was made `age_ms` before the node
/// time of that node (or after it, for a negative age), with the number `nonce` 16 times.
fn envelope_of(
    forward: &Harness,
    user_id: &str,
    request: &Value,
    value: &str,
    nonce: u8,
    age_ms: i64,
) -> Value {
    let time_ms = forward.node.now_ms().saturating_add_signed(-age_ms);
    let envelope = seal_secret_use(
        &giving(),
        &forward.node.keys.sign_public(),
        &forward.node.keys.seal_public(),
        time_ms,
        &[nonce; 16],
        user_id,
        RECORD_ID,
        &Secret::new(value.to_string()),
        &BoundRequest::from_value(request).unwrap(),
        &Secret::new([nonce; 32]),
    )
    .unwrap();
    serde_json::to_value(envelope).unwrap()
}

/// An envelope of the account of these tests for `forward` that was made `age_ms` before the
/// node time of that node.
fn envelope_aged(forward: &Harness, request: &Value, value: &str, nonce: u8, age_ms: i64) -> Value {
    envelope_of(forward, USER, request, value, nonce, age_ms)
}

/// An envelope for `forward` that was made now.
fn envelope(forward: &Harness, request: &Value, value: &str, nonce: u8) -> Value {
    envelope_aged(forward, request, value, nonce, 0)
}

fn code(outcome: &Result<Streamed, (u16, Value)>) -> (u16, String) {
    match outcome {
        Ok(sent) => panic!("the call handed a response of status {} on", sent.status),
        Err((status, failure)) => (
            *status,
            failure["code"].as_str().unwrap_or_default().to_string(),
        ),
    }
}

fn percent(text: &str) -> String {
    let mut encoded = String::new();
    for byte in text.bytes() {
        match byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            true => encoded.push(char::from(byte)),
            false => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// One use of a secret in a test: the request of its envelope, the headers and the body of
/// the caller, and the value.
struct Use<'a> {
    method: &'a str,
    path: &'a str,
    query: &'a str,
    slot: &'a str,
    headers: Value,
    body: &'a [u8],
    value: &'a str,
}

#[tokio::test]
async fn the_value_goes_to_the_slot_of_the_envelope_in_the_form_of_its_place() {
    let provider = site(|_| {
        Reply::with_body(
            201,
            &[
                ("content-type", "application/json"),
                ("x-request-id", "r-1"),
            ],
            b"{\"ok\":true}",
        )
        .keep_alive()
    })
    .await;
    let forward = forward_node(&provider).await;
    let json_body = format!("{{\"auth\":{{\"token\":\"{PLACEHOLDER}\",\"user\":\"u\"}},\"n\":1}}");
    let form_body = format!("grant_type=x&client_secret={PLACEHOLDER}&scope=s");
    let bearer = format!("Bearer {PLACEHOLDER}");
    let query = format!("a=1&key={PLACEHOLDER}&b=2");
    let path = format!("/bot{PLACEHOLDER}/send");
    let quoted = "sk-\"quoted\"\\back\nline";
    let uses = [
        Use {
            method: "POST",
            path: "/v1/items",
            query: "page=2",
            slot: "header:authorization",
            headers: json!([["Authorization", bearer], ["Accept", "application/json"]]),
            body: b"{\"a\":1}",
            value: VALUE,
        },
        Use {
            method: "GET",
            path: "/v1/items",
            query: "page=2",
            slot: "header:x-api-key",
            headers: json!([["X-Api-Key", PLACEHOLDER]]),
            body: b"",
            value: VALUE,
        },
        Use {
            method: "GET",
            path: "/v1/items",
            query: &query,
            slot: "query:key",
            headers: json!([]),
            body: b"",
            value: VALUE,
        },
        Use {
            method: "DELETE",
            path: &path,
            query: "",
            slot: "path",
            headers: json!([]),
            body: b"",
            value: VALUE,
        },
        Use {
            method: "POST",
            path: "/oauth/token",
            query: "",
            slot: "form:client_secret",
            headers: json!([["Content-Type", "application/x-www-form-urlencoded"]]),
            body: form_body.as_bytes(),
            value: VALUE,
        },
        Use {
            method: "PUT",
            path: "/v1/session",
            query: "",
            slot: "json:auth.token",
            headers: json!([["Content-Type", "application/json"]]),
            body: json_body.as_bytes(),
            value: quoted,
        },
    ];
    for (index, used) in uses.into_iter().enumerate() {
        let Use {
            method,
            path,
            query,
            slot,
            headers,
            body,
            value,
        } = used;
        let request = request_of(method, path, query, slot, body);
        let meta = json!({
            "envelope": envelope(&forward, &request, value, index as u8),
            "headers": headers, "timeout_ms": 5000,
        });
        let sent = forward
            .vault_send(meta, body)
            .await
            .unwrap_or_else(|failure| panic!("{slot}: {failure:?}"));
        // The response of the site, and the end of a body that ended as the site ended it.
        assert_eq!(sent.status, 201, "{slot}");
        assert_eq!(sent.header("x-request-id"), Some("r-1"), "{slot}");
        assert_eq!(sent.body(), b"{\"ok\":true}", "{slot}");
        assert_eq!(sent.end, json!({"complete": true}), "{slot}");

        let seen = provider.seen().pop().unwrap();
        assert_eq!(provider.seen().len(), index + 1, "{slot}");
        assert_eq!(seen.server_name, SITE);
        assert_eq!(seen.header("host"), Some(SITE));
        assert_eq!(seen.method, method);
        assert_eq!(seen.header("accept-encoding"), Some("identity"));
        // The placeholder is gone, and the value stands at the slot and nowhere else.
        let wire = format!(
            "{} {:?} {}",
            seen.target,
            seen.headers,
            String::from_utf8_lossy(&seen.body)
        );
        assert!(!wire.contains(PLACEHOLDER), "{slot}: {wire}");
        match slot {
            "header:authorization" => {
                assert_eq!(seen.target, "/v1/items?page=2");
                assert_eq!(
                    seen.header("authorization"),
                    Some(format!("Bearer {VALUE}").as_str())
                );
                assert_eq!(seen.header("accept"), Some("application/json"));
                assert_eq!(seen.body, body);
            }
            "header:x-api-key" => {
                assert_eq!(seen.header("x-api-key"), Some(VALUE));
                assert_eq!(seen.header("content-length"), None);
            }
            "query:key" => {
                assert_eq!(
                    seen.target,
                    format!("/v1/items?a=1&key={}&b=2", percent(VALUE))
                );
                assert_eq!(percent(VALUE), "sk-live_4f9A%2Fb%2Bc%3Dd~0123456789");
            }
            "path" => assert_eq!(seen.target, format!("/bot{}/send", percent(VALUE))),
            "form:client_secret" => {
                assert_eq!(
                    seen.body,
                    format!("grant_type=x&client_secret={}&scope=s", percent(VALUE)).as_bytes()
                );
                assert_eq!(seen.form_value("client_secret").as_deref(), Some(VALUE));
                let length = seen.body.len().to_string();
                assert_eq!(seen.header("content-length"), Some(length.as_str()));
            }
            _ => {
                let body: Value = serde_json::from_slice(&seen.body).unwrap();
                assert_eq!(
                    body,
                    json!({"auth": {"token": quoted, "user": "u"}, "n": 1})
                );
            }
        }
    }
    // Every request went to port 443 of the site.
    assert!(forward
        .platform
        .connections()
        .iter()
        .all(|(host, port)| host == SITE && *port == 443));
}

#[tokio::test]
async fn a_value_stands_in_a_header_behind_every_text_that_names_no_refused_scheme() {
    let provider = quiet_site().await;
    let forward = forward_node(&provider).await;
    // The slot, the header of the caller, and its value with `{}` for the placeholder.
    let uses = [
        ("header:authorization", "Authorization", "Bearer {}"),
        ("header:authorization", "authorization", "KakaoAK {}"),
        ("header:authorization", "Authorization", "{}"),
        // The name of a refused scheme behind the placeholder says nothing of the value.
        (
            "header:authorization",
            "Authorization",
            "Token token=\"{}\", name=\"basic\"",
        ),
        // A header no server reads credentials from holds any text in front of the value.
        ("header:x-note", "X-Note", "Basic {}"),
        ("header:cookie", "Cookie", "plan=basic; session={}; a=1"),
    ];
    for (index, (slot, name, text)) in uses.into_iter().enumerate() {
        let request = request_of("GET", "/v1/me", "", slot, b"");
        let meta = json!({
            "envelope": envelope(&forward, &request, VALUE, index as u8),
            "headers": [[name, text.replace("{}", PLACEHOLDER)]],
            "timeout_ms": 5000,
        });
        let sent = forward
            .vault_send(meta, b"")
            .await
            .unwrap_or_else(|failure| panic!("{text}: {failure:?}"));
        assert_eq!(sent.status, 200, "{text}");
        let seen = provider.seen().pop().unwrap();
        assert_eq!(
            seen.header(&name.to_ascii_lowercase()),
            Some(text.replace("{}", VALUE).as_str()),
            "{text}"
        );
    }
}

#[tokio::test]
async fn a_body_whose_type_states_utf8_is_the_body_of_that_type() {
    let provider = quiet_site().await;
    let forward = forward_node(&provider).await;
    let form = format!("a=1&secret={PLACEHOLDER}");
    let document = format!("{{\"n\":\"\u{d55c}\",\"secret\":\"{PLACEHOLDER}\"}}");
    let uses = [
        ("form:secret", "application/x-www-form-urlencoded", &form),
        ("json:secret", "application/json", &document),
    ];
    let mut nonce = 0u8;
    for (slot, own, body) in uses {
        // UTF-8 is the encoding the node writes a value in: a type that states it, in
        // either spelling and with or without quotes, is the type.
        for parameters in [
            "",
            "; charset=utf-8",
            ";charset=\"UTF-8\"",
            "; charset=utf8",
        ] {
            nonce += 1;
            let request = request_of("POST", "/v1/items", "", slot, body.as_bytes());
            let meta = json!({
                "envelope": envelope(&forward, &request, VALUE, nonce),
                "headers": [["Content-Type", format!("{own}{parameters}")]],
            });
            let sent = forward.vault_send(meta, body.as_bytes()).await;
            assert_eq!(sent.unwrap().status, 200, "{slot} {parameters}");
            let seen = provider.seen().pop().unwrap();
            assert!(!seen
                .body
                .windows(PLACEHOLDER.len())
                .any(|w| w == PLACEHOLDER.as_bytes()));
        }
    }
    assert_eq!(provider.seen().len(), 8);
}

/// The value of an `Authorization` header that carries `credentials` as HTTP Basic.
fn basic(credentials: &str) -> String {
    format!("Basic {}", STANDARD.encode(credentials))
}

#[tokio::test]
async fn the_value_becomes_one_half_of_the_credentials_of_http_basic() {
    let provider = quiet_site().await;
    let forward = forward_node(&provider).await;
    // A value with a colon is a password like any other.
    let with_colon = "tok:en/with+a=colon~0123";
    let uses = [
        // The value as the user-id, in front of an empty password and of one with colons.
        (
            "basic:user",
            format!("{PLACEHOLDER}:"),
            VALUE,
            format!("{VALUE}:"),
        ),
        (
            "basic:user",
            format!("{PLACEHOLDER}:x:y"),
            VALUE,
            format!("{VALUE}:x:y"),
        ),
        // The value as the password, behind a user-id and behind an empty one.
        (
            "basic:password",
            format!("AC0123:{PLACEHOLDER}"),
            VALUE,
            format!("AC0123:{VALUE}"),
        ),
        (
            "basic:password",
            format!("user@example.com:{PLACEHOLDER}"),
            with_colon,
            format!("user@example.com:{with_colon}"),
        ),
        (
            "basic:password",
            format!(":{PLACEHOLDER}"),
            VALUE,
            format!(":{VALUE}"),
        ),
    ];
    for (index, (slot, credentials, value, expected)) in uses.into_iter().enumerate() {
        let request = request_of("GET", "/v1/charges", "limit=3", slot, b"");
        let meta = json!({
            "envelope": envelope(&forward, &request, value, index as u8),
            "headers": [["Accept", "application/json"], ["Authorization", basic(&credentials)]],
            "timeout_ms": 5000,
        });
        let sent = forward
            .vault_send(meta, b"")
            .await
            .unwrap_or_else(|failure| panic!("{credentials}: {failure:?}"));
        assert_eq!(sent.status, 200, "{credentials}");
        assert_eq!(sent.end, json!({"complete": true}), "{credentials}");

        let seen = provider.seen().pop().unwrap();
        assert_eq!(provider.seen().len(), index + 1, "{credentials}");
        assert_eq!(seen.target, "/v1/charges?limit=3");
        assert_eq!(seen.header("accept"), Some("application/json"));
        // The header the site receives is the header of the caller but for the half the
        // value stands for: `Basic`, a space, and the base64 text with its padding.
        assert_eq!(
            seen.header("authorization"),
            Some(basic(&expected).as_str()),
            "{credentials}"
        );
        // What a server reads of it: the first colon parts the user-id from the password.
        let text = seen
            .header("authorization")
            .and_then(|header| header.strip_prefix("Basic "))
            .unwrap();
        let read = String::from_utf8(STANDARD.decode(text).unwrap()).unwrap();
        assert_eq!(read.split_once(':'), expected.split_once(':'));
        let wire = format!("{} {:?}", seen.target, seen.headers);
        assert!(!wire.contains(PLACEHOLDER), "{credentials}: {wire}");
        assert!(!read.contains(PLACEHOLDER), "{credentials}");
    }
}

#[tokio::test]
async fn credentials_of_http_basic_without_the_placeholder_as_one_half_are_not_sent() {
    let provider = quiet_site().await;
    let forward = forward_node(&provider).await;
    let request = request_of("POST", "/v1/charges", "", "basic:user", b"amount=1");
    let of_password = request_of("POST", "/v1/charges", "", "basic:password", b"amount=1");
    let good = basic(&format!("{PLACEHOLDER}:"));
    let mut nonce = 0u8;
    let mut attempt = |request: &Value, headers: Value, value: &str, body: &[u8]| {
        nonce += 1;
        let meta = json!({
            "envelope": envelope(&forward, request, value, nonce), "headers": headers,
        });
        let (forward, body) = (&forward, body.to_vec());
        async move { forward.vault_send(meta, &body).await }
    };
    let invalid = (400, "invalid_request".to_string());
    let text_of = |credentials: &str| STANDARD.encode(credentials);
    let user_id = text_of(&format!("{PLACEHOLDER}:"));

    for headers in [
        // No `Authorization` header, and two of them.
        json!([]),
        json!([["X-Authorization", good]]),
        json!([["Authorization", good], ["authorization", good]]),
        json!([["Authorization", good], ["AUTHORIZATION", "Bearer token"]]),
        // The header in another form than the one the node writes: the scheme in another
        // case, two spaces, no padding, base64url, a text behind the credentials.
        json!([["Authorization", format!("basic {user_id}")]]),
        json!([["Authorization", format!("BASIC {user_id}")]]),
        json!([["Authorization", format!("Basic  {user_id}")]]),
        json!([[
            "Authorization",
            format!("Basic {}", user_id.trim_end_matches('='))
        ]]),
        json!([[
            "Authorization",
            format!(
                "Basic {}",
                URL_SAFE_NO_PAD.encode(format!("{PLACEHOLDER}:"))
            )
        ]]),
        json!([["Authorization", format!("Basic {user_id}, Bearer token")]]),
        json!([["Authorization", format!("Bearer {user_id}")]]),
        json!([["Authorization", user_id]]),
        // The placeholder is not the whole of one half: a part of a half, in both halves,
        // behind a second colon, without a colon, and not there.
        json!([["Authorization", basic(&format!("x{PLACEHOLDER}:"))]]),
        json!([["Authorization", basic(&format!("user:{PLACEHOLDER}x"))]]),
        json!([[
            "Authorization",
            basic(&format!("{PLACEHOLDER}:{PLACEHOLDER}"))
        ]]),
        json!([["Authorization", basic(&format!("user:pass:{PLACEHOLDER}"))]]),
        json!([["Authorization", basic(PLACEHOLDER)]]),
        json!([["Authorization", basic("user:password")]]),
        // The placeholder in the request as it stands: in the header itself, in another
        // header, in a header the node does not send.
        json!([["Authorization", format!("Basic {PLACEHOLDER}")]]),
        json!([["Authorization", format!("Bearer {PLACEHOLDER}")]]),
        json!([["Authorization", good], ["X-Api-Key", PLACEHOLDER]]),
        json!([["Authorization", good], [PLACEHOLDER, "x"]]),
        json!([
            ["Authorization", good],
            ["Proxy-Authorization", PLACEHOLDER]
        ]),
    ] {
        let outcome = attempt(&request, headers.clone(), VALUE, b"amount=1").await;
        assert_eq!(code(&outcome), invalid, "{headers}");
    }
    // The placeholder as the other half than the slot names: the caller of a use does not
    // choose the half, so a value its record holds as a password is not sent as a user-id,
    // and the other way round.
    let password = basic(&format!("user:{PLACEHOLDER}"));
    for (request, header) in [
        (&request, &password),
        (&request, &basic(&format!(":{PLACEHOLDER}"))),
        (&of_password, &good),
        (&of_password, &basic(&format!("{PLACEHOLDER}:password"))),
    ] {
        let headers = json!([["Authorization", header]]);
        let outcome = attempt(request, headers, VALUE, b"amount=1").await;
        assert_eq!(code(&outcome), invalid, "{} {header}", request["slot"]);
    }
    // The placeholder in the address or in the body of a request whose slot is one of HTTP
    // Basic: the request object of such an envelope has no placeholder in its address, and a
    // body that holds it is not the body of a request of this slot.
    let in_body = format!("key={PLACEHOLDER}");
    let other = request_of("POST", "/v1/charges", "", "basic:user", in_body.as_bytes());
    let outcome = attempt(
        &other,
        json!([["Authorization", good]]),
        VALUE,
        in_body.as_bytes(),
    );
    assert_eq!(code(&outcome.await), invalid);
    // Credentials of HTTP Basic under the slot of the header itself: the placeholder is not
    // in the request as it stands, and that slot reads no base64 text.
    let header_slot = request_of(
        "POST",
        "/v1/charges",
        "",
        "header:authorization",
        b"amount=1",
    );
    let outcome = attempt(
        &header_slot,
        json!([["Authorization", good]]),
        VALUE,
        b"amount=1",
    );
    assert_eq!(code(&outcome.await), invalid);

    // A value the credentials cannot hold: a control character in either half, and a colon
    // in the user-id, which ends at its first colon.
    for (request, header, value) in [
        (&request, &good, "line\nbreak-0123"),
        (&of_password, &password, "line\r\nbreak-0123"),
        (&request, &good, "tab\tinside-0123"),
        (&of_password, &password, "delete\u{7f}-0123"),
        (&request, &good, "user:pass-0123"),
        (&request, &good, ":leading-0123"),
    ] {
        let headers = json!([["Authorization", header]]);
        let outcome = attempt(request, headers, value, b"amount=1").await;
        assert_eq!(code(&outcome), invalid, "{value:?}");
    }
    assert!(provider.seen().is_empty());
    assert!(forward.platform.connections().is_empty());

    // A request that was refused left its envelope unused: the same envelope sends the
    // request of the caller once that is the request of the envelope.
    let unused = envelope(&forward, &request, VALUE, 200);
    let meta = |headers: Value| json!({"envelope": unused, "headers": headers});
    let refused = forward
        .vault_send(
            meta(json!([["Authorization", basic("user:password")]])),
            b"amount=1",
        )
        .await;
    assert_eq!(code(&refused), invalid);
    let sent = forward
        .vault_send(meta(json!([["Authorization", good]])), b"amount=1")
        .await
        .unwrap();
    assert_eq!(sent.status, 200);
    assert_eq!(
        provider.only().header("authorization"),
        Some(basic(&format!("{VALUE}:")).as_str())
    );
}

#[tokio::test]
async fn a_site_that_reflects_credentials_of_http_basic_gets_none_of_the_value_handed_on() {
    // The site sends back what it received: the header as it stands, the text of the
    // credentials, or one half of them, in the body or in a header. The value stands in
    // the base64 text at each of the three places of a group, by the length of the user-id.
    for user_id in ["", "u", "us", "user"] {
        let credentials = format!("{user_id}:{PLACEHOLDER}");
        for echo in ["header", "credentials", "password", "in a header"] {
            let provider = site(move |seen| {
                let received = seen.header("authorization").unwrap_or_default().to_string();
                let text = received.strip_prefix("Basic ").unwrap_or_default();
                let decoded = String::from_utf8(STANDARD.decode(text).unwrap_or_default())
                    .unwrap_or_default();
                let password = decoded.split_once(':').map_or("", |(_, password)| password);
                let lead = "0123456789".repeat(40);
                match echo {
                    "header" => Reply::json(401, &json!({"lead": lead, "received": received})),
                    "credentials" => Reply::json(401, &json!({"lead": lead, "user": decoded})),
                    "password" => Reply::json(401, &json!({"lead": lead, "tried": password})),
                    _ => Reply::with_body(401, &[("x-received", received.as_str())], b"denied"),
                }
            })
            .await;
            let forward = forward_node(&provider).await;
            let request = request_of("GET", "/v1/me", "", "basic:password", b"");
            let meta = json!({
                "envelope": envelope(&forward, &request, VALUE, 1),
                "headers": [["Authorization", basic(&credentials)]],
            });
            let outcome = forward.vault_send(meta, b"").await;
            assert_eq!(provider.seen().len(), 1, "{user_id:?} {echo}");
            match (echo, outcome) {
                ("in a header", outcome) => assert_eq!(
                    code(&outcome),
                    (502, "response_withheld".to_string()),
                    "{user_id:?}"
                ),
                (_, Ok(sent)) => {
                    assert_eq!(sent.end["code"], "response_withheld", "{user_id:?} {echo}");
                    let body = sent.body();
                    assert!(
                        !Forms::of(&[Secret::new(VALUE.to_string())]).found_in(&body),
                        "{user_id:?} {echo}"
                    );
                    assert!(body.len() < 400, "{user_id:?} {echo}: {}", body.len());
                }
                (_, Err(failure)) => panic!("{user_id:?} {echo}: {failure:?}"),
            }
        }
    }
}

#[tokio::test]
async fn one_envelope_sends_one_request_within_its_time() {
    let provider = quiet_site().await;
    let forward = forward_node(&provider).await;
    let request = request_of("GET", "/v1/me", "", "header:authorization", b"");
    let headers = json!([["authorization", format!("Bearer {PLACEHOLDER}")]]);
    let meta = |envelope: &Value| json!({"envelope": envelope, "headers": headers});

    // The same envelope a second time sends nothing.
    let once = envelope(&forward, &request, VALUE, 1);
    assert_eq!(
        forward.vault_send(meta(&once), b"").await.unwrap().status,
        200
    );
    let again = forward.vault_send(meta(&once), b"").await;
    assert_eq!(code(&again), (400, "bad_challenge".to_string()));
    assert_eq!(provider.seen().len(), 1);

    // An envelope whose 30 seconds passed, and one whose end lies further ahead of the clock
    // of the node than twice the life of an envelope.
    for age_ms in [30_000, 30_001, 3_600_000, -31_000, -3_600_000] {
        let stale = envelope_aged(&forward, &request, VALUE, 2, age_ms);
        let outcome = forward.vault_send(meta(&stale), b"").await;
        assert_eq!(code(&outcome), (400, "bad_expiry".to_string()), "{age_ms}");
    }
    assert_eq!(provider.seen().len(), 1);
    // Within its time an envelope is used: near its end, and when the clock of the node that
    // made it is ahead of the clock of this node.
    for (nonce, age_ms) in [(3, 25_000), (4, -25_000)] {
        let near = envelope_aged(&forward, &request, VALUE, nonce, age_ms);
        assert_eq!(
            forward.vault_send(meta(&near), b"").await.unwrap().status,
            200
        );
    }
    assert_eq!(provider.seen().len(), 3);

    // A request that is refused before it is sent leaves its envelope unused.
    let unused = envelope(&forward, &request, VALUE, 5);
    let wrong_body = forward.vault_send(meta(&unused), b"other").await;
    assert_eq!(code(&wrong_body), (400, "invalid_request".to_string()));
    assert_eq!(
        forward.vault_send(meta(&unused), b"").await.unwrap().status,
        200
    );
    assert_eq!(provider.seen().len(), 4);

    // A request that failed on its way used its envelope. The account of this envelope has
    // no connection to the site yet, and the platform opens none.
    let failed = envelope_of(&forward, "user-2", &request, VALUE, 6, 0);
    let meta_failed = json!({"envelope": failed, "headers": headers, "timeout_ms": 1000});
    forward.platform.refuse_connections(8);
    let outcome = forward.vault_send(meta_failed.clone(), b"").await;
    assert_eq!(code(&outcome), (502, "provider_unreachable".to_string()));
    forward.platform.refuse_connections(0);
    let outcome = forward.vault_send(meta_failed, b"").await;
    assert_eq!(code(&outcome), (400, "bad_challenge".to_string()));
    assert_eq!(provider.seen().len(), 4);
    // The numbers of the five envelopes that were used are kept.
    assert_eq!(lock(&forward.node.used_nonces).len(), 5);
}

#[tokio::test]
async fn a_request_that_is_not_the_request_of_its_envelope_is_not_sent() {
    let provider = quiet_site().await;
    let forward = forward_node(&provider).await;
    let body = b"{\"note\":\"hello\"}".as_slice();
    let request = request_of("POST", "/v1/items", "a=1", "header:authorization", body);
    let bearer = format!("Bearer {PLACEHOLDER}");
    let with_placeholder = format!("{{\"note\":\"{PLACEHOLDER}\"}}");
    let mut nonce = 0u8;
    let mut attempt = |headers: Value, body: &[u8]| {
        nonce += 1;
        let meta =
            json!({"envelope": envelope(&forward, &request, VALUE, nonce), "headers": headers});
        let (forward, body) = (&forward, body.to_vec());
        async move { forward.vault_send(meta, &body).await }
    };
    let invalid = (400, "invalid_request".to_string());

    // Another body than the envelope names: other bytes of the same length, more, none.
    let good = json!([["authorization", bearer]]);
    for other in [&b"{\"note\":\"HELLO\"}"[..], b"{\"note\":\"hello\"} ", b""] {
        assert_eq!(code(&attempt(good.clone(), other).await), invalid);
    }
    // The placeholder is not once in the request, or not at the slot.
    for headers in [
        json!([]),
        json!([["authorization", "Bearer token"]]),
        json!([["authorization", format!("{PLACEHOLDER} {PLACEHOLDER}")]]),
        json!([["authorization", bearer], ["x-copy", PLACEHOLDER]]),
        json!([["x-api-key", PLACEHOLDER]]),
        json!([[PLACEHOLDER, "Bearer token"]]),
        json!([["authorization", bearer], ["authorization", bearer]]),
        // The header of the slot is stated once: a server joins two headers of one name
        // into one value, or reads one of them, by a rule of its own.
        json!([["authorization", bearer], ["Authorization", "Basic"]]),
        json!([["authorization", "Basic"], ["AUTHORIZATION", PLACEHOLDER]]),
        json!([["authorization", bearer], ["authorization", ""]]),
        // A header the node does not send carries nothing.
        json!([
            ["authorization", bearer],
            ["proxy-authorization", PLACEHOLDER]
        ]),
        json!("authorization"),
        json!([["authorization"]]),
        json!([["author ization", bearer]]),
        json!([["authorization", format!("{bearer}\r\nx-injected: 1")]]),
    ] {
        let outcome = attempt(headers.clone(), body).await;
        assert_eq!(code(&outcome), invalid, "{headers}");
    }
    // A header that asks the site for another method, another host or another path than the
    // entry names, also when it is written with `_` in the place of `-`.
    for refused in [
        "X-HTTP-Method-Override",
        "X_HTTP_Method_Override",
        "x-method-override",
        "X-Original-URL",
        "X-Rewrite-Url",
        "X-Forwarded-Host",
        "x_forwarded_host",
        "Forwarded",
    ] {
        let headers = json!([["authorization", bearer], [refused, "DELETE"]]);
        let outcome = attempt(headers, body).await;
        assert_eq!(
            code(&outcome),
            (403, "not_allowed".to_string()),
            "{refused}"
        );
    }
    // An `Accept` header that asks the site for its response in another character encoding
    // than UTF-8: the node searches the bytes of a response, and in UTF-16 the bytes of the
    // value are not the bytes it searches for.
    for accept in [
        "application/json; charset=utf-16",
        "text/plain;charset=UTF-16LE, */*",
        "*/*; charset=\"ibm037\"",
        "application/json; charset=utf-8, text/html; charset=utf-32",
    ] {
        for name in ["Accept", "accept", "ACCEPT"] {
            let headers = json!([["authorization", bearer], [name, accept]]);
            let outcome = attempt(headers, body).await;
            assert_eq!(
                code(&outcome),
                (403, "not_allowed".to_string()),
                "{name}: {accept}"
            );
        }
    }
    // In a header the placeholder begins the value or follows a space, `=`, `:` or `"`: a
    // text that ends with the beginning of an escape would take the first characters of the
    // value for the rest of it.
    let backslash = '\\';
    for front in [
        "Bearer%4".to_string(),
        "Bearer %".to_string(),
        "a=%4".to_string(),
        format!("{{\"t\":\"{backslash}u004"),
        "&#x4".to_string(),
        "Bearer".to_string(),
        "x".to_string(),
    ] {
        let headers = json!([["authorization", format!("{front}{PLACEHOLDER}")]]);
        let outcome = attempt(headers, body).await;
        assert_eq!(code(&outcome), invalid, "{front}");
    }

    // In the header `Authorization` the placeholder stands behind no scheme whose
    // credentials a server decodes or reads a user name from: the value of a record of this
    // header would be read as another text there. The name of such a scheme is found in any
    // case of its letters and at any place in front of the placeholder, and a text with a
    // character outside ASCII is refused with it.
    for front in [
        "Basic ",
        "basic ",
        "BASIC  ",
        " Basic ",
        "Basic\t ",
        "Basic=",
        "Basic:",
        "Basic dXNlcjo= ",
        "Bearer x, Basic ",
        "xBasic ",
        "Digest username=\"",
        "Negotiate ",
        "NTLM ",
        "Ba\u{17f}ic ",
        "\u{a0}Bearer ",
    ] {
        let headers = json!([["Authorization", format!("{front}{PLACEHOLDER}")]]);
        let outcome = attempt(headers, body).await;
        assert_eq!(code(&outcome), invalid, "{front:?}");
    }
    assert!(provider.seen().is_empty());

    // The placeholder in the body of a request whose slot is a header: the envelope names
    // that body, and the value does not go there.
    let other = request_of(
        "POST",
        "/v1/items",
        "",
        "header:authorization",
        with_placeholder.as_bytes(),
    );
    for headers in [json!([]), good.clone()] {
        let meta = json!({"envelope": envelope(&forward, &other, VALUE, 90), "headers": headers});
        let outcome = forward.vault_send(meta, with_placeholder.as_bytes()).await;
        assert_eq!(code(&outcome), invalid, "{headers}");
    }
    // A slot of the body without the placeholder at its place, in a body of the type its
    // header states.
    let form = json!([["Content-Type", "application/x-www-form-urlencoded"]]);
    let document = json!([["Content-Type", "application/json"]]);
    for (slot, headers, sent_body) in [
        ("form:secret", &form, format!("secret=x{PLACEHOLDER}")),
        ("form:secret", &form, format!("other={PLACEHOLDER}")),
        (
            "form:secret",
            &form,
            format!("secret={PLACEHOLDER}&copy={PLACEHOLDER}"),
        ),
        // A body that is no form: the bytes of another syntax around the field.
        (
            "form:secret",
            &form,
            format!("{{\"comment\":\"x&secret={PLACEHOLDER}&y\"}}"),
        ),
        (
            "form:secret",
            &form,
            format!("POST /notes HTTP/1.1\r\n\r\nnote=x&secret={PLACEHOLDER}"),
        ),
        (
            "json:secret",
            &document,
            format!("{{\"other\":\"{PLACEHOLDER}\"}}"),
        ),
        (
            "json:secret",
            &document,
            format!("{{\"secret\":\"x{PLACEHOLDER}\"}}"),
        ),
        (
            "json:secret",
            &document,
            format!("{{\"secret\":[\"{PLACEHOLDER}\"]}}"),
        ),
        (
            "json:secret",
            &document,
            format!("{{\"secret\":\"{PLACEHOLDER}\",\"secret\":\"x\"}}"),
        ),
        ("json:secret", &document, format!("secret={PLACEHOLDER}")),
    ] {
        let request = request_of("POST", "/v1/items", "", slot, sent_body.as_bytes());
        let meta = json!({"envelope": envelope(&forward, &request, VALUE, 91), "headers": headers});
        let outcome = forward.vault_send(meta, sent_body.as_bytes()).await;
        assert_eq!(code(&outcome), invalid, "{slot} {sent_body}");
    }
    // A body with the placeholder at its place under a header that states another type, no
    // type or two types: a site reads a body by its `Content-Type`, so the field the value
    // is written into is the field of that type.
    let placed = [
        ("form:secret", format!("a=1&secret={PLACEHOLDER}")),
        (
            "json:secret",
            format!("{{\"junk\":\"&note=\",\"secret\":\"{PLACEHOLDER}\"}}"),
        ),
    ];
    for (slot, sent_body) in &placed {
        let (own, other) = match *slot {
            "form:secret" => ("application/x-www-form-urlencoded", "application/json"),
            _ => ("application/json", "application/x-www-form-urlencoded"),
        };
        for headers in [
            json!([]),
            json!([["Content-Type", other]]),
            json!([["Content-Type", "text/plain"]]),
            json!([["Content-Type", "multipart/form-data; boundary=b"]]),
            json!([["Content-Type", own], ["content-type", own]]),
            json!([["Content-Type", own], ["Content_Type", other]]),
            json!([["Content_Type", own]]),
            // A character encoding other than UTF-8, and a coding of the body: a site that
            // reads the body by either reads other characters than the node judged, and the
            // bytes of the value as another text.
            json!([["Content-Type", format!("{own}; charset=utf-16")]]),
            json!([["Content-Type", format!("{own};charset=\"UTF-16LE\"")]]),
            json!([["Content-Type", format!("{own}; charset=iso-8859-1")]]),
            json!([[
                "Content-Type",
                format!("{own}; charset=utf-8; charset=utf-32")
            ]]),
            json!([["Content-Type", own], ["Content-Encoding", "gzip"]]),
            json!([["Content-Type", own], ["Content_Encoding", "deflate"]]),
        ] {
            let request = request_of("POST", "/v1/items", "", slot, sent_body.as_bytes());
            let meta =
                json!({"envelope": envelope(&forward, &request, VALUE, 96), "headers": headers});
            let outcome = forward.vault_send(meta, sent_body.as_bytes()).await;
            assert_eq!(code(&outcome), invalid, "{slot} {headers}");
        }
    }
    // A JSON body with bytes outside UTF-8 in a string beside the member of the slot.
    let odd = [
        b"{\"junk\":\"\xff\",\"secret\":\"".as_slice(),
        PLACEHOLDER.as_bytes(),
        b"\"}",
    ]
    .concat();
    let request = request_of("POST", "/v1/items", "", "json:secret", &odd);
    let meta = json!({"envelope": envelope(&forward, &request, VALUE, 97), "headers": document});
    assert_eq!(code(&forward.vault_send(meta, &odd).await), invalid);

    // An envelope that is not for this node, a changed one, and none.
    let elsewhere = Harness::new(&provider);
    let meta = json!({"envelope": envelope(&elsewhere, &request, VALUE, 92), "headers": good});
    let outcome = forward.vault_send(meta, body).await;
    assert_eq!(code(&outcome), (400, "wrong_node".to_string()));
    let mut changed = envelope(&forward, &request, VALUE, 93);
    changed["ct"] = json!(b64u(b"another ciphertext of some length"));
    let meta = json!({"envelope": changed, "headers": good});
    assert_eq!(
        code(&forward.vault_send(meta, body).await),
        (400, "open_failed".to_string())
    );
    let mut version = envelope(&forward, &request, VALUE, 94);
    version["v"] = json!(2);
    let meta = json!({"envelope": version, "headers": good});
    assert_eq!(
        code(&forward.vault_send(meta, body).await),
        (400, "unsupported_version".to_string())
    );
    assert_eq!(
        code(&forward.vault_send(json!({"headers": good}), body).await),
        invalid
    );
    for timeout_ms in [json!(999), json!(600_001), json!("soon")] {
        let meta = json!({
            "envelope": envelope(&forward, &request, VALUE, 95), "headers": good,
            "timeout_ms": timeout_ms,
        });
        assert_eq!(
            code(&forward.vault_send(meta, body).await),
            invalid,
            "{timeout_ms}"
        );
    }
    let (status, _, _) = forward
        .send(Method::POST, "/v1/vault/send", b"no frame".to_vec())
        .await;
    assert_eq!(status.as_u16(), 400);

    // None of these requests reached the site, and the node asked for no connection.
    assert!(provider.seen().is_empty());
    assert!(forward.platform.connections().is_empty());
}

#[tokio::test]
async fn a_value_cannot_add_a_header_or_leave_its_place() {
    let provider = quiet_site().await;
    let forward = forward_node(&provider).await;
    let hostile = "v\r\nx-injected: 1\r\n\r\nGET /other&admin=1#f\"}";

    // Inside a header a value with a line end is not sent.
    let request = request_of("GET", "/v1/me", "", "header:authorization", b"");
    let meta = json!({
        "envelope": envelope(&forward, &request, hostile, 1),
        "headers": [["authorization", format!("Bearer {PLACEHOLDER}")]],
    });
    let outcome = forward.vault_send(meta, b"").await;
    assert_eq!(code(&outcome), (400, "invalid_request".to_string()));
    assert!(provider.seen().is_empty());

    // In every other place the value is written in the form of the place: it is one
    // parameter, one segment, one field, one string, whatever bytes it holds.
    let query = format!("key={PLACEHOLDER}&b=2");
    let path = format!("/v1/{PLACEHOLDER}/items");
    let form = format!("a=1&secret={PLACEHOLDER}");
    let document = format!("{{\"secret\":\"{PLACEHOLDER}\",\"b\":2}}");
    let uses: [(&str, &str, &str, &str, &str); 4] = [
        ("query:key", "/v1/me", &query, "", "text/plain"),
        ("path", &path, "", "", "text/plain"),
        (
            "form:secret",
            "/v1/me",
            "",
            &form,
            "application/x-www-form-urlencoded",
        ),
        (
            "json:secret",
            "/v1/me",
            "",
            &document,
            "application/json; charset=utf-8",
        ),
    ];
    for (index, (slot, path, query, body, media_type)) in uses.into_iter().enumerate() {
        let request = request_of("POST", path, query, slot, body.as_bytes());
        let meta = json!({
            "envelope": envelope(&forward, &request, hostile, 2 + index as u8),
            "headers": [["Content-Type", media_type]],
        });
        let sent = forward.vault_send(meta, body.as_bytes()).await.unwrap();
        assert_eq!(sent.status, 200, "{slot}");
        let seen = provider.seen().pop().unwrap();
        assert_eq!(provider.seen().len(), index + 1, "{slot}");
        assert_eq!(seen.header("x-injected"), None, "{slot}");
        assert_eq!(seen.method, "POST", "{slot}");
        match slot {
            "query:key" => assert_eq!(
                seen.target,
                format!("/v1/me?key={}&b=2", percent(hostile)),
                "{slot}"
            ),
            "path" => assert_eq!(seen.target, format!("/v1/{}/items", percent(hostile))),
            "form:secret" => {
                assert_eq!(
                    seen.form(),
                    [
                        ("a".to_string(), "1".to_string()),
                        ("secret".to_string(), hostile.to_string())
                    ]
                );
            }
            _ => {
                let body: Value = serde_json::from_slice(&seen.body).unwrap();
                assert_eq!(body, json!({"secret": hostile, "b": 2}));
            }
        }
    }
}

/// The forms a site may reflect a value in, each under a name.
pub(super) fn reflections(value: &str) -> Vec<(String, Vec<u8>)> {
    let bytes = value.as_bytes();
    let hex = |upper: bool| -> Vec<u8> {
        bytes
            .iter()
            .flat_map(|byte| match upper {
                true => format!("{byte:02X}").into_bytes(),
                false => format!("{byte:02x}").into_bytes(),
            })
            .collect()
    };
    let mut forms = vec![
        ("as it is".to_string(), bytes.to_vec()),
        ("percent-encoded".to_string(), percent(value).into_bytes()),
        (
            "percent-encoded twice".to_string(),
            percent(&percent(value)).into_bytes(),
        ),
        ("hexadecimal".to_string(), hex(false)),
        ("upper case hexadecimal".to_string(), hex(true)),
        // Inside a JSON string, as two writers of JSON escape it: one writes `/` with a
        // backslash, another every character of markup as its code unit.
        (
            "JSON, the slash escaped".to_string(),
            value.replace('/', "\\/").into_bytes(),
        ),
        (
            "JSON, code units".to_string(),
            bytes
                .iter()
                .map(|byte| match byte {
                    b'/' | b'+' | b'=' => format!("{}u{byte:04x}", '\\'),
                    _ => char::from(*byte).to_string(),
                })
                .collect::<String>()
                .into_bytes(),
        ),
    ];
    for front in ["", "x", "xy"] {
        let around = [front.as_bytes(), bytes, b" and more"].concat();
        forms.push((
            format!("base64 behind {} bytes", front.len()),
            STANDARD_NO_PAD.encode(&around).into_bytes(),
        ));
        forms.push((
            format!("base64url behind {} bytes", front.len()),
            URL_SAFE_NO_PAD.encode(&around).into_bytes(),
        ));
    }
    forms
}

#[tokio::test]
async fn a_streamed_response_that_reflects_the_value_is_cut_in_front_of_the_reflection() {
    let forms = Forms::of(&[Secret::new(VALUE.to_string())]);
    for (name, form) in reflections(VALUE) {
        // The lead is longer than what the search holds back.
        let lead =
            format!("{{\"lead\":\"{}\",\"echo\":\"", "0123456789".repeat(1_000)).into_bytes();
        assert!(lead.len() > HELD_BACK + GATHER);
        let whole = [lead.as_slice(), &form, b"\",\"tail\":true}"].concat();
        // The body arrives in pieces that end inside the reflection: after its first byte, in
        // its middle, and one byte before its end.
        for inside in [1, form.len() / 2, form.len() - 1] {
            let cut = lead.len() + inside;
            let reply_pieces = [whole[..cut].to_vec(), whole[cut..].to_vec()];
            let provider = site(move |_| {
                let pieces: Vec<&[u8]> = reply_pieces.iter().map(Vec::as_slice).collect();
                Reply::chunked(200, &[], &pieces, Duration::from_millis(30))
            })
            .await;
            let forward = forward_node(&provider).await;
            let request = request_of("GET", "/v1/echo", "", "header:authorization", b"");
            let meta = json!({
                "envelope": envelope(&forward, &request, VALUE, 1),
                "headers": [["authorization", format!("Bearer {PLACEHOLDER}")]],
            });
            let sent = forward.vault_send(meta, b"").await.unwrap();
            // The head was handed on, and of the body a part of what stands in front of the
            // reflection: no byte of the reflection, and not the byte in front of it.
            assert_eq!(sent.status, 200, "{name}");
            assert_eq!(sent.end["complete"], false, "{name}");
            assert_eq!(sent.end["code"], "response_withheld", "{name}");
            let body = sent.body();
            // Of a first piece that holds a part of a form, the bytes in front of what the
            // search holds back were handed on before the second piece came. A first piece
            // that holds a whole form of the value already (the text of a base64 reflection
            // is longer than the form the search finds in it) is cut where the search read
            // that form. Either way what was handed on ends in front of what the search held
            // back when it found the form, which the reflection lies in.
            if !forms.found_in(&whole[..cut]) {
                assert!(!body.is_empty(), "{name} at {inside}");
            }
            assert!(
                body.len() + HELD_BACK <= whole.len() && body.len() < lead.len(),
                "{name} at {inside}: {}",
                body.len()
            );
            assert_eq!(body, whole[..body.len()], "{name}");
            assert!(!forms.found_in(&body), "{name}");
            assert_eq!(provider.seen().len(), 1);
        }
    }
}

#[tokio::test]
async fn a_response_the_node_cannot_search_or_whose_head_holds_the_value_is_not_handed_on() {
    let encoded = STANDARD_NO_PAD.encode(format!("Bearer {VALUE}"));
    let location = format!("https://elsewhere.example/?key={}", percent(VALUE));
    let replies: Vec<(&str, Vec<(String, String)>)> = vec![
        (
            "the value in a header",
            vec![("x-echo".into(), VALUE.into())],
        ),
        (
            "the value in a header, base64",
            vec![("x-debug".into(), encoded)],
        ),
        (
            "the value in a redirect",
            vec![("location".into(), location)],
        ),
        (
            "a content coding",
            vec![("content-encoding".into(), "gzip".into())],
        ),
        (
            "a content coding",
            vec![("content-encoding".into(), "br".into())],
        ),
        (
            "a transfer coding",
            vec![("transfer-encoding".into(), "gzip, chunked".into())],
        ),
        // A content coding the response names among the headers of its connection: the node
        // leaves such headers out of what it hands on, and judges the coding all the same.
        (
            "a content coding listed in the connection header",
            vec![
                ("content-encoding".into(), "gzip".into()),
                ("connection".into(), "content-encoding".into()),
            ],
        ),
        // An instance manipulation (RFC 3229), which a caller may ask a server for.
        (
            "an instance manipulation",
            vec![("im".into(), "gzip".into())],
        ),
    ];
    for (index, (name, headers)) in replies.into_iter().enumerate() {
        let provider = site(move |_| {
            let headers: Vec<(&str, &str)> = headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            Reply::with_body(302, &headers, b"\x1f\x8b body")
        })
        .await;
        let forward = forward_node(&provider).await;
        let request = request_of("GET", "/v1/echo", "", "header:authorization", b"");
        let meta = json!({
            "envelope": envelope(&forward, &request, VALUE, index as u8),
            "headers": [["authorization", PLACEHOLDER]],
        });
        let outcome = forward.vault_send(meta, b"").await;
        assert_eq!(
            code(&outcome),
            (502, "response_withheld".to_string()),
            "{name}"
        );
        assert_eq!(provider.seen().len(), 1, "{name}");
    }
}

/// `body` under one layer of the transfer coding `chunked`, in chunks of `size` bytes.
fn chunked_once(body: &[u8], size: usize) -> Vec<u8> {
    let mut coded = Vec::new();
    for chunk in body.chunks(size) {
        coded.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        coded.extend_from_slice(chunk);
        coded.extend_from_slice(b"\r\n");
    }
    coded.extend_from_slice(b"0\r\n\r\n");
    coded
}

#[tokio::test]
async fn a_body_under_the_chunked_coding_more_than_once_is_not_handed_on() {
    // A site that states the transfer coding `chunked` twice, in one header or in two, and
    // sends the value back in a body that is chunked twice. The HTTP client of the node
    // removes one layer of that coding: what it reads is a body that is still chunked, whose
    // inner chunks part the value, under no header that says so.
    for stated in [
        "chunked, chunked",
        "chunked,chunked",
        "Chunked , CHUNKED",
        "chunked\r\ntransfer-encoding: chunked",
        "chunked, chunked, chunked",
    ] {
        let provider = site(move |seen| {
            let echoed = seen.header("x-api-key").unwrap_or_default();
            let inner = chunked_once(format!("{{\"echo\":\"{echoed}\"}}").as_bytes(), 13);
            let mut reply =
                format!("HTTP/1.1 200 OK\r\ntransfer-encoding: {stated}\r\n\r\n").into_bytes();
            reply.extend_from_slice(&chunked_once(&inner, 4096));
            Reply::Raw(reply)
        })
        .await;
        let forward = forward_node(&provider).await;
        let request = request_of("GET", "/v1/echo", "", "header:x-api-key", b"");
        let meta = json!({
            "envelope": envelope(&forward, &request, VALUE, 1),
            "headers": [["X-Api-Key", PLACEHOLDER]],
        });
        let outcome = forward.vault_send(meta, b"").await;
        assert_eq!(provider.only().header("x-api-key"), Some(VALUE), "{stated}");
        assert_eq!(
            code(&outcome),
            (502, "response_withheld".to_string()),
            "{stated}"
        );
    }

    // The coding once is the coding the node removes: a body under it is handed on as the
    // site wrote it.
    let provider = site(|_| {
        let mut reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n".to_vec();
        reply.extend_from_slice(&chunked_once(b"{\"ok\":true}", 4));
        Reply::Raw(reply)
    })
    .await;
    let forward = forward_node(&provider).await;
    let request = request_of("GET", "/v1/echo", "", "header:x-api-key", b"");
    let meta = json!({
        "envelope": envelope(&forward, &request, VALUE, 1),
        "headers": [["X-Api-Key", PLACEHOLDER]],
    });
    let sent = forward.vault_send(meta, b"").await.unwrap();
    assert_eq!(sent.body(), b"{\"ok\":true}");
    assert_eq!(sent.end, json!({"complete": true}));
}

#[tokio::test]
async fn a_value_with_white_space_at_its_ends_is_found_without_it() {
    // A value that was stored with white space at its ends, as one that was copied with a
    // space or a line end behind it. A server reads the value of a header without the white
    // space around it, and a server that reads a parameter often strips it: what such a site
    // sends back is the value without that white space, which is the value a server takes.
    let spaced = [
        format!("{VALUE} "),
        format!(" {VALUE}"),
        format!("  {VALUE}  "),
        format!("{VALUE}\n"),
        format!("\u{a0}{VALUE}\u{3000}"),
    ];
    for (index, value) in spaced.iter().enumerate() {
        let in_a_line = !value.contains('\n');
        for echo in ["body", "header"] {
            // The site sends back what it read of the header, or of the query parameter.
            let provider = site(move |seen| {
                let read = match in_a_line {
                    true => seen.header("x-api-key").unwrap_or_default().to_string(),
                    false => url::form_urlencoded::parse(
                        seen.target
                            .split_once('?')
                            .map_or("", |(_, query)| query)
                            .as_bytes(),
                    )
                    .find(|(name, _)| name == "key")
                    .map(|(_, value)| value.into_owned())
                    .unwrap_or_default(),
                };
                let read = read.trim().to_string();
                let lead = "0123456789".repeat(1_000);
                match echo {
                    "body" => Reply::json(400, &json!({"lead": lead, "unknown key": read})),
                    _ => Reply::with_body(400, &[("x-unknown-key", read.as_str())], b"{}"),
                }
            })
            .await;
            let forward = forward_node(&provider).await;
            let query = format!("key={PLACEHOLDER}");
            let (request, headers) = match in_a_line {
                true => (
                    request_of("GET", "/v1/me", "", "header:x-api-key", b""),
                    json!([["X-Api-Key", PLACEHOLDER]]),
                ),
                false => (
                    request_of("GET", "/v1/me", &query, "query:key", b""),
                    json!([]),
                ),
            };
            let meta = json!({
                "envelope": envelope(&forward, &request, value, index as u8),
                "headers": headers,
            });
            let outcome = forward.vault_send(meta, b"").await;
            assert_eq!(provider.seen().len(), 1, "{value:?} {echo}");
            match (echo, outcome) {
                ("body", Ok(sent)) => {
                    assert_eq!(sent.end["code"], "response_withheld", "{value:?}");
                    let body = String::from_utf8(sent.body()).unwrap();
                    assert!(!body.contains(VALUE), "{value:?}");
                }
                (_, outcome) => assert_eq!(
                    code(&outcome),
                    (502, "response_withheld".to_string()),
                    "{value:?} {echo}"
                ),
            }
        }
    }
}

#[tokio::test]
async fn a_value_a_site_sends_back_in_a_header_that_is_not_utf8_is_not_handed_on() {
    // A value with characters outside ASCII. The site sends it back in a header, beside a
    // byte that is no UTF-8: the node hands such a header on with one character per byte,
    // and a reader of that text reads the bytes of the value back from it.
    let value = "\u{be44}\u{bc00}-\u{ac12}-0123456789";
    for beside in [&b"caf\xe9 "[..], b"\xff", b""] {
        let provider = site(move |seen| {
            let echoed = seen.header("x-api-key").unwrap_or_default();
            let mut reply = b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 2\r\nx-echo: ".to_vec();
            reply.extend_from_slice(beside);
            reply.extend_from_slice(echoed.as_bytes());
            reply.extend_from_slice(b"\r\n\r\n{}");
            Reply::Raw(reply)
        })
        .await;
        let forward = forward_node(&provider).await;
        let request = request_of("GET", "/v1/me", "", "header:x-api-key", b"");
        let meta = json!({
            "envelope": envelope(&forward, &request, value, 1),
            "headers": [["X-Api-Key", PLACEHOLDER]],
        });
        let outcome = forward.vault_send(meta, b"").await;
        // The site received the value as it is.
        assert_eq!(provider.only().header("x-api-key"), Some(value));
        assert_eq!(
            code(&outcome),
            (502, "response_withheld".to_string()),
            "{beside:?}"
        );
    }
}

#[tokio::test]
async fn a_value_a_site_sends_back_as_a_header_name_is_not_handed_on() {
    // A value of characters a header name can hold, with upper case letters. The site names
    // a header of its response after it. The HTTP client of the node hands a header name on
    // in lower case, so the name the caller would receive is the value but for the case of
    // its letters.
    let value = "Sk-Live_4f9A.bCd~0123456789";
    for front in ["", "X-Unknown-Key-"] {
        let provider = site(move |seen| {
            let echoed = seen.header("x-api-key").unwrap_or_default();
            let reply = format!(
                "HTTP/1.1 401 Unauthorized\r\n{front}{echoed}: 1\r\ncontent-length: 2\r\n\r\n{{}}"
            );
            Reply::Raw(reply.into_bytes())
        })
        .await;
        let forward = forward_node(&provider).await;
        let request = request_of("GET", "/v1/me", "", "header:x-api-key", b"");
        let meta = json!({
            "envelope": envelope(&forward, &request, value, 1),
            "headers": [["X-Api-Key", PLACEHOLDER]],
        });
        let outcome = forward.vault_send(meta, b"").await;
        assert_eq!(provider.only().header("x-api-key"), Some(value));
        assert_eq!(
            code(&outcome),
            (502, "response_withheld".to_string()),
            "{front:?}"
        );
    }
}

/// The length of the longest form of `VALUE`, the hexadecimal one.
const LONGEST: usize = 2 * VALUE.len();

/// The new bytes a search of a streamed body waits for, for a value of this length.
const GATHER: usize = 4 * 1024;

/// How many of its last bytes the search of a streamed body holds back for `VALUE`: the bytes
/// that one byte more than its longest form can take.
const HELD_BACK: usize = (LONGEST + 1) * ESCAPED_BYTE_SPAN;

/// The bytes of the body in the parts of a stream that arrived whole so far.
fn body_bytes_so_far(stream: &[u8]) -> usize {
    let length = |at: usize| {
        stream
            .get(at..at + 4)
            .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()) as usize)
    };
    let Some(meta_length) = length(0) else {
        return 0;
    };
    let (mut at, mut body) = (4 + meta_length, 0);
    while let Some(part_length) = length(at).filter(|part| *part > 0) {
        if at + 4 + part_length > stream.len() {
            break;
        }
        body += part_length;
        at += 4 + part_length;
    }
    body
}

/// Asserts that `handed_on` is what a search hands on of a body that was cut behind `part`:
/// the bytes of `part` in front of the ones the search held back, but for the bytes that
/// still waited for a search.
fn assert_cut_behind(handed_on: &[u8], part: &[u8]) {
    let most = part.len() - HELD_BACK;
    assert!(
        handed_on.len() <= most && handed_on.len() + GATHER > most,
        "{} of {}",
        handed_on.len(),
        part.len()
    );
    assert_eq!(handed_on, &part[..handed_on.len()]);
}

#[tokio::test]
async fn a_response_is_handed_on_while_it_arrives() {
    // The site sends the head and the first events at once and the last event 600 ms later.
    // The first events are more bytes than the search holds back.
    let first = b"data: 0123456789\n\n".repeat(1_000);
    assert!(first.len() > HELD_BACK + 2 * GATHER);
    let last = b"data: done\n\n".to_vec();
    let chunks = [first.clone(), last.clone()];
    let provider = site(move |_| {
        Reply::chunked(
            200,
            &[("content-type", "text/event-stream")],
            &[&chunks[0], &chunks[1]],
            Duration::from_millis(600),
        )
    })
    .await;
    let forward = forward_node(&provider).await;
    let request = request_of("GET", "/v1/events", "", "header:authorization", b"");
    let meta = json!({
        "envelope": envelope(&forward, &request, VALUE, 1),
        "headers": [["authorization", PLACEHOLDER]],
    });
    let started = Instant::now();
    let response = forward
        .respond(Method::POST, "/v1/vault/send", frame::encode_head(&meta))
        .await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.headers()["content-type"],
        frame::STREAM_CONTENT_TYPE
    );
    let mut body = response.into_body();
    let mut received = Vec::new();
    // What the caller holds of the first events before the last one came: all of them but
    // the bytes the search holds back, and but the bytes that still wait for a search.
    let early = first.len() - HELD_BACK;
    let mut early_after = None;
    loop {
        let frame =
            std::future::poll_fn(|context| std::pin::Pin::new(&mut body).poll_frame(context)).await;
        let Some(frame) = frame else { break };
        received.extend_from_slice(&frame.unwrap().into_data().unwrap());
        let so_far = body_bytes_so_far(&received);
        if started.elapsed() < Duration::from_millis(550) {
            // The bytes the search holds back did not leave before the site went on.
            assert!(so_far <= early, "{so_far}");
        }
        if early_after.is_none() && so_far + GATHER > early {
            early_after = Some(started.elapsed());
        }
    }
    // The first events were in the hands of the caller before the site sent the last one.
    let early_after = early_after.expect("the first events came before the last one");
    assert!(early_after < Duration::from_millis(450), "{early_after:?}");
    assert!(started.elapsed() >= Duration::from_millis(600));
    let sent = read_stream(&received);
    assert_eq!(sent.header("content-type"), Some("text/event-stream"));
    assert_eq!(sent.body(), [first, last].concat());
    assert_eq!(sent.end, json!({"complete": true}));
}

#[tokio::test]
async fn a_body_that_ends_early_or_not_in_time_is_cut_with_its_reason() {
    let request = request_of("GET", "/v1/items", "", "header:authorization", b"");
    let headers = json!([["authorization", PLACEHOLDER]]);
    let meta = |forward: &Harness| {
        json!({
            "envelope": envelope(forward, &request, VALUE, 1), "headers": headers,
            "timeout_ms": 1000,
        })
    };
    // A response that announces 100,000 bytes and sends 40,000 of them: more than the search
    // holds back.
    let part = b"0123456789".repeat(4_000);
    assert!(part.len() > HELD_BACK + GATHER);
    let partial = [
        b"HTTP/1.1 200 OK\r\ncontent-length: 100000\r\n\r\n".as_slice(),
        &part,
    ]
    .concat();
    // Of a body that is cut, the bytes the search held back are not handed on: they may be
    // the beginning of a reflection the rest of the body would have completed.

    // The site closes the connection before the body it announced is whole.
    let reply = partial.clone();
    let provider = site(move |_| Reply::Raw(reply.clone())).await;
    let forward = forward_node(&provider).await;
    let sent = forward.vault_send(meta(&forward), b"").await.unwrap();
    assert_eq!(sent.status, 200);
    assert_cut_behind(&sent.body(), &part);
    assert_eq!(sent.end["complete"], false);
    assert_eq!(sent.end["code"], "provider_unreachable");
    assert!(sent.end["message"]
        .as_str()
        .is_some_and(|text| !text.is_empty()));

    // The body does not end within the time limit of the call.
    let reply = partial.clone();
    let provider = site(move |_| Reply::Pieces(vec![(Duration::ZERO, reply.clone())], false)).await;
    let forward = forward_node(&provider).await;
    let started = Instant::now();
    let sent = forward.vault_send(meta(&forward), b"").await.unwrap();
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert_cut_behind(&sent.body(), &part);
    assert_eq!(sent.end["complete"], false);
    assert_eq!(sent.end["code"], "timeout");

    // A body whose end is the end of its connection. With the closing alert of TLS the site
    // ended it. Without the alert the connection was cut at a place its carrier chose, and
    // the bytes the search kept back are not handed on.
    let unframed = [b"HTTP/1.1 200 OK\r\n\r\n".as_slice(), &part].concat();
    let reply = unframed.clone();
    let provider = site(move |_| Reply::Raw(reply.clone())).await;
    let forward = forward_node(&provider).await;
    let sent = forward.vault_send(meta(&forward), b"").await.unwrap();
    assert_eq!(sent.body(), part);
    assert_eq!(sent.end, json!({"complete": true}));
    let provider = site(move |_| Reply::Abrupt(unframed.clone())).await;
    let forward = forward_node(&provider).await;
    let sent = forward.vault_send(meta(&forward), b"").await.unwrap();
    assert_cut_behind(&sent.body(), &part);
    assert_eq!(sent.end["complete"], false);
    assert_eq!(sent.end["code"], "provider_unreachable");

    // No head within the time limit: nothing of a response is handed on.
    let provider = site(|_| Reply::Hang).await;
    let forward = forward_node(&provider).await;
    let outcome = forward.vault_send(meta(&forward), b"").await;
    assert_eq!(code(&outcome), (504, "timeout".to_string()));

    // The site cannot be reached.
    let provider = quiet_site().await;
    let forward = forward_node(&provider).await;
    forward.platform.refuse_connections(8);
    let outcome = forward.vault_send(meta(&forward), b"").await;
    assert_eq!(code(&outcome), (502, "provider_unreachable".to_string()));
    assert!(provider.seen().is_empty());
}

#[tokio::test]
async fn the_headers_of_a_request_and_of_a_response_are_cleaned_and_no_redirect_is_followed() {
    let provider = site(|_| {
        Reply::with_body(
            302,
            &[
                ("location", "https://elsewhere.example/next"),
                ("set-cookie", "session=1"),
                ("set-cookie2", "session=2"),
                ("x-kept", "yes"),
                ("connection", "close"),
            ],
            b"moved",
        )
    })
    .await;
    let forward = forward_node(&provider).await;
    let request = request_of("POST", "/v1/items", "", "header:cookie", b"body");
    let meta = json!({
        "envelope": envelope(&forward, &request, VALUE, 1),
        "headers": [
            ["Cookie", format!("theme=dark; session={PLACEHOLDER}")],
            ["Authorization", "Bearer token-of-the-caller"],
            ["Host", "elsewhere.example"],
            ["Content-Length", "9999"],
            ["Transfer-Encoding", "chunked"],
            ["Connection", "close"],
            ["Accept-Encoding", "gzip"],
            ["Proxy-Authorization", "Basic abc"],
            ["Expect", "100-continue"],
            ["Range", "bytes=0-10"],
            ["If-Range", "\"etag\""],
            ["Accept-Charset", "utf-16, utf-8;q=0.5"],
            ["Content_Length", "0"],
            ["Transfer_Encoding", "chunked"],
            // An `Accept` header that names UTF-8 is a header like any other.
            ["Accept", "application/json; charset=utf-8"],
            ["X-Custom", "kept"],
        ],
    });
    let sent = forward.vault_send(meta, b"body").await.unwrap();
    // The redirect comes back as it is: the node asked the site alone.
    assert_eq!(sent.status, 302);
    assert_eq!(
        sent.header("location"),
        Some("https://elsewhere.example/next")
    );
    assert_eq!(sent.header("x-kept"), Some("yes"));
    assert_eq!(sent.header("set-cookie"), None);
    assert_eq!(sent.header("set-cookie2"), None);
    assert_eq!(sent.header("connection"), None);
    assert_eq!(sent.body(), b"moved");
    assert_eq!(forward.platform.connections(), [(SITE.to_string(), 443)]);

    let seen = provider.seen().pop().unwrap();
    assert_eq!(
        seen.header_names(),
        [
            "host",
            "content-length",
            "accept-encoding",
            "cookie",
            "authorization",
            "accept",
            "x-custom",
            "connection"
        ]
    );
    assert_eq!(seen.header("host"), Some(SITE));
    assert_eq!(seen.header("content-length"), Some("4"));
    assert_eq!(seen.header("accept-encoding"), Some("identity"));
    assert_eq!(
        seen.header("cookie"),
        Some(format!("theme=dark; session={VALUE}").as_str())
    );
    assert_eq!(
        seen.header("authorization"),
        Some("Bearer token-of-the-caller")
    );
    // The connection carries this one request.
    assert_eq!(seen.header("connection"), Some("close"));
}

/// A `vault/send` call with an envelope that is sealed to `harness` and within its time: the
/// node refuses it as a call of a role it has not.
async fn refused_by_its_role(harness: &Harness) {
    let request = request_of("GET", "/v1/me", "", "header:authorization", b"");
    let meta = json!({
        "envelope": envelope(harness, &request, VALUE, 1),
        "headers": [["authorization", PLACEHOLDER]],
    });
    let outcome = harness.vault_send(meta, b"").await;
    assert_eq!(code(&outcome), (403, "not_allowed".to_string()));
}

#[tokio::test]
async fn only_a_node_of_the_forward_role_sends() {
    let provider = quiet_provider().await;
    // A node of the delegation role, with or without a configuration.
    refused_by_its_role(&Harness::configured(&provider).await).await;
    let delegation = Harness::new(&provider);
    let status = json!({"user_id": USER, "nonce": b64u(b"nonce")});
    assert_eq!(delegation.post("/v1/status", status).await.0, 200);
    refused_by_its_role(&delegation).await;
    // A node without a role refuses the call and stays without a role: the operator
    // configuration still gives it one.
    let unset = Harness::new(&provider);
    refused_by_its_role(&unset).await;
    assert_eq!(unset.health().await["role"], Value::Null);
    let (status, _) = unset
        .post("/v1/config", operator_config(&unset.node.definitions))
        .await;
    assert_eq!(status, 200);
    refused_by_its_role(&unset).await;
    assert!(provider.seen().is_empty());
}

#[tokio::test]
async fn every_request_goes_over_a_connection_of_its_own() {
    let provider = site(|_| Reply::json(200, &json!({"ok": true})).keep_alive()).await;
    let forward = forward_node(&provider).await;
    let request = request_of("GET", "/v1/me", "", "header:authorization", b"");
    for nonce in 1..=3 {
        let meta = json!({
            "envelope": envelope(&forward, &request, VALUE, nonce),
            "headers": [["authorization", PLACEHOLDER]],
        });
        let sent = forward.vault_send(meta, b"").await.unwrap();
        assert_eq!(sent.end, json!({"complete": true}));
    }
    // The site keeps its connections open, and the node uses none of them again: a request
    // that carries a value follows no other request on its connection.
    let seen = provider.seen();
    assert_eq!(seen.len(), 3);
    assert!(seen
        .iter()
        .all(|request| request.header("connection") == Some("close")));
    assert_eq!(forward.platform.connections().len(), 3);
    let health = forward.health().await;
    assert_eq!(health["egress"]["idle_reuses"]["provider"], 0);
    assert_eq!(health["state"]["idle_connections"]["provider"], 0);
    assert_eq!(forward.node.egress.provider_idle.idle_total(), 0);
}

#[tokio::test]
async fn the_shares_of_a_request_are_held_until_its_response_has_ended() {
    // The site answers with the head and a part of the body, and then stays silent.
    let provider = site(|_| {
        let head = b"HTTP/1.1 200 OK\r\ncontent-length: 1000\r\n\r\n".to_vec();
        let part = b"0123456789".repeat(40);
        Reply::Pieces(vec![(Duration::ZERO, [head, part].concat())], false)
    })
    .await;
    let forward = forward_node(&provider).await;
    let body = vec![b'x'; 300_000];
    let request = request_of("POST", "/v1/upload", "", "header:authorization", &body);
    let meta = json!({
        "envelope": envelope(&forward, &request, VALUE, 1),
        "headers": [["authorization", PLACEHOLDER]], "timeout_ms": 600_000,
    });
    let mut frame_bytes = frame::encode_head(&meta);
    frame_bytes.extend_from_slice(&body);
    let (frame_length, whole) = (frame_bytes.len(), forward.node.limits.body_budget_bytes);
    let response = forward
        .respond(Method::POST, "/v1/vault/send", frame_bytes)
        .await;
    assert_eq!(response.status().as_u16(), 200);
    // The response goes on: the call holds the share of its request body, the share the
    // search of its response can hold, and its place.
    let mut stream = response.into_body();
    let first =
        std::future::poll_fn(|context| std::pin::Pin::new(&mut stream).poll_frame(context)).await;
    assert!(first.is_some());
    assert_eq!(
        forward.node.body_budget.available_permits(),
        whole - frame_length - StreamCheck::memory_bound(VALUE.len())
    );
    assert_eq!(forward.health().await["load"]["forward_calls"], 1);
    // The caller goes away: the task of the stream drops the response of the site, and all
    // of it is free.
    drop(stream);
    for _ in 0..200 {
        if forward.node.body_budget.available_permits() == whole {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(forward.node.body_budget.available_permits(), whole);
    assert_eq!(forward.health().await["load"]["forward_calls"], 0);
    assert_eq!(forward.health().await["load"]["provider_inflight"], 0);
}

#[tokio::test]
async fn a_closing_node_begins_no_request_and_ends_the_one_it_had_begun() {
    // The site sends the head and the first part at once and the rest 400 ms later.
    let parts = [b"first ".repeat(64), b"last".to_vec()];
    let chunks = parts.clone();
    let provider = site(move |_| {
        Reply::chunked(
            200,
            &[("content-type", "text/plain")],
            &[&chunks[0], &chunks[1]],
            Duration::from_millis(400),
        )
    })
    .await;
    let forward = forward_node(&provider).await;
    let request = request_of("GET", "/v1/events", "", "header:authorization", b"");
    let meta = |nonce: u8| {
        json!({
            "envelope": envelope(&forward, &request, VALUE, nonce),
            "headers": [["authorization", PLACEHOLDER]],
        })
    };

    // A call the node took before it closes: its request is on the wire and its response
    // has begun.
    let response = forward
        .respond(Method::POST, "/v1/vault/send", frame::encode_head(&meta(1)))
        .await;
    assert_eq!(response.status().as_u16(), 200);
    let health = forward.health().await;
    assert_eq!(
        (&health["closing"], &health["load"]["forward_calls"]),
        (&json!(false), &json!(1))
    );

    // `close` is a call of either role: the node of the forward role takes it, and says so.
    let (status, closed) = forward.post("/v1/close", json!({})).await;
    assert_eq!((status, closed), (200, json!({"accounts": 0})));
    let health = forward.health().await;
    assert_eq!(
        (&health["closing"], &health["load"]["forward_calls"]),
        (&json!(true), &json!(1))
    );

    // A further call is refused before the node reads its frame: nothing goes to the site,
    // the number of its envelope is not marked, and no place stays held for it. A frame the
    // node would refuse for its form is refused for the closing all the same.
    let refused = forward.vault_send(meta(2), b"").await;
    assert_eq!(code(&refused), (503, "closing".to_string()));
    let (status, _, bytes) = forward
        .send(Method::POST, "/v1/vault/send", b"no frame".to_vec())
        .await;
    let failure: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        (status.as_u16(), &failure["code"]),
        (503, &json!("closing"))
    );
    assert_eq!(provider.seen().len(), 1);
    assert_eq!(lock(&forward.node.used_nonces).len(), 1);
    assert_eq!(forward.health().await["load"]["forward_calls"], 1);

    // The call the node had taken runs to the end of its response.
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let sent = read_stream(&bytes);
    assert_eq!(sent.body(), parts.concat());
    assert_eq!(sent.end, json!({"complete": true}));
    // The node holds no call any more: whoever closed it may end it without cutting one.
    assert_eq!(forward.health().await["load"]["forward_calls"], 0);

    // The other calls of a node of the forward role answer as before.
    let nonce = json!({"nonce": b64u(&[0x5a; 32])});
    assert_eq!(forward.post("/v1/attestation", nonce).await.0, 200);
    assert_eq!(forward.post("/v1/close", json!({})).await.0, 200);
}
