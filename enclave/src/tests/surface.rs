//! The call surface itself (enclave.md sections 4, 5.1 and 5.2): health, the operator
//! configuration, attestation, failure bodies, and HTTP/1.1 over a real connection.

use credential_enclave_protocol::app::verify_challenge_statement;
use credential_enclave_protocol::encoding::{b64u, b64u_decode, Signed};
use credential_enclave_protocol::keys::{binding, Binding};
use credential_enclave_protocol::{purpose, ProtocolError};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::quiet_provider;
use crate::api;
use crate::platform::Platform;
use crate::testing::{operator_config, App, Harness};

#[tokio::test]
async fn health_reports_the_node_in_the_key_order_of_5_1() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let (status, content_type, bytes) = harness
        .send(axum::http::Method::GET, "/v1/health", Vec::new())
        .await;
    assert_eq!(status.as_u16(), 200);
    assert_eq!(content_type, "application/json");
    let health: Value = serde_json::from_slice(&bytes).unwrap();
    let started_ms = health["started_ms"].as_u64().unwrap();
    let time_ms = health["time_ms"].as_u64().unwrap();
    assert_eq!(
        String::from_utf8(bytes.to_vec()).unwrap(),
        format!(
            concat!(
                "{{\"node\":\"{}\",\"release\":\"v0.0.0-test\",\"platform\":\"local\",",
                "\"custody\":\"operator\",\"started_ms\":{},\"time_ms\":{},",
                "\"configured\":false,\"closing\":false,\"accounts\":0,\"grants\":0,",
                "\"mail_providers\":[\"naver_mail\"],\"log_store\":null}}"
            ),
            harness.node.node, started_ms, time_ms
        )
    );
    assert_eq!(harness.node.node.len(), 43);
    assert!(time_ms >= started_ms && started_ms > 1_700_000_000_000);

    harness
        .post("/v1/config", operator_config(&harness.node.definitions))
        .await;
    App::new("user-1", 1).grant(&harness).await;
    let health = harness.health().await;
    assert_eq!(health["configured"], true);
    assert_eq!(health["accounts"], 1);
    assert_eq!(health["grants"], 1);
}

#[tokio::test]
async fn the_operator_configuration_is_validated_and_replaced_as_a_whole() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let entry = |redirect_uri: &str| json!({"client_id": "c", "client_secret": "s", "redirect_uri": redirect_uri, "publishable_key": ""});

    for body in [
        json!({}),
        json!({"providers": []}),
        json!({"providers": {"dropbox": entry("https://api.example/cb")}}),
        json!({"providers": {"slack": entry("http://api.example/cb")}}),
        json!({"providers": {"slack": entry("ftp://api.example/cb")}}),
        json!({"providers": {"slack": entry("")}}),
        json!({"providers": {"slack": entry("https://api.example/c b")}}),
        json!({"providers": {"slack": "text"}}),
        json!({"providers": {"slack": {"client_id": 5, "redirect_uri": "https://api.example/cb"}}}),
    ] {
        let (status, failure) = harness.post("/v1/config", body.clone()).await;
        assert_eq!(
            (status, failure["code"].as_str()),
            (400, Some("invalid_request")),
            "{body}"
        );
    }
    assert_eq!(harness.health().await["configured"], false);

    // The local platform also accepts a callback on http://localhost.
    let (status, configured) = harness
        .post(
            "/v1/config",
            json!({"providers": {
                "slack": entry("http://localhost:8000/api/integrations/slack/oauth/callback"),
                "notion": {"redirect_uri": "https://api.example/api/integrations/notion/oauth/callback"},
            }}),
        )
        .await;
    assert_eq!((status, configured), (200, json!({"configured": true})));

    // A second configuration replaces the first one as a whole.
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let begin = |provider: &'static str| {
        let harness = &harness;
        async move {
            harness
                .post(
                    "/v1/oauth/begin",
                    json!({"user_id": "user-1", "provider": provider, "operator_state": "o", "params": {}}),
                )
                .await
        }
    };
    assert_eq!(begin("slack").await.0, 200);
    // notion is configured without a client id.
    assert_eq!(begin("notion").await.1["code"], "not_configured");
    let (status, _) = harness
        .post(
            "/v1/config",
            json!({"providers": {"notion": entry("https://api.example/cb")}}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(begin("notion").await.0, 200);
    assert_eq!(begin("slack").await.1["code"], "not_configured");

    // The client secret is not echoed by any call.
    assert!(!harness.health().await.to_string().contains("\"s\""));
}

#[tokio::test]
async fn attestation_binds_the_node_keys_to_the_nonce_and_issues_a_challenge() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let nonce = [0x11u8; 32];
    let (status, response) = harness
        .post("/v1/attestation", json!({"nonce": b64u(&nonce)}))
        .await;
    assert_eq!(status, 200);
    let keys: Vec<&str> = response
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "v",
            "platform",
            "document",
            "node",
            "challenge",
            "release",
            "challenge_statement"
        ]
    );
    assert_eq!(response["v"], 1);
    assert_eq!(response["platform"], "local");
    assert_eq!(response["node"], harness.node.node.as_str());
    assert_eq!(response["release"], "v0.0.0-test");
    assert_eq!(
        b64u_decode(response["challenge"].as_str().unwrap())
            .unwrap()
            .len(),
        16
    );

    // The document carries the binding of the node keys and the nonce of the requester.
    let document: Value =
        serde_json::from_slice(&b64u_decode(response["document"].as_str().unwrap()).unwrap())
            .unwrap();
    assert_eq!(document["platform"], "local");
    assert_eq!(document["nonce"], b64u(&nonce));
    let carried = b64u_decode(document["binding"].as_str().unwrap()).unwrap();
    assert_eq!(carried, binding(&harness.node.keys, "v0.0.0-test", None));
    let parsed: Binding = serde_json::from_slice(&carried).unwrap();
    assert_eq!(parsed.sign, b64u(&harness.node.keys.sign_public()));
    assert_eq!(parsed.seal, b64u(&harness.node.keys.seal_public()));
    assert_eq!(parsed.release, "v0.0.0-test");

    // Every call issues a new challenge.
    let (_, second) = harness
        .post("/v1/attestation", json!({"nonce": b64u(&nonce)}))
        .await;
    assert_ne!(second["challenge"], response["challenge"]);

    // The nonce is 16 to 64 bytes of base64url.
    for length in [16, 64] {
        let (status, _) = harness
            .post(
                "/v1/attestation",
                json!({"nonce": b64u(&vec![1u8; length])}),
            )
            .await;
        assert_eq!(status, 200, "{length}");
    }
    for nonce in [
        json!(b64u(&[1u8; 15])),
        json!(b64u(&[1u8; 65])),
        json!("not base64url!"),
        json!(5),
        Value::Null,
    ] {
        let (status, failure) = harness
            .post("/v1/attestation", json!({"nonce": nonce}))
            .await;
        assert_eq!(
            (status, failure["code"].as_str()),
            (400, Some("invalid_request"))
        );
    }
}

fn challenge_statement(response: &Value) -> Signed {
    serde_json::from_value(response["challenge_statement"].clone()).unwrap()
}

#[tokio::test]
async fn the_challenge_statement_binds_a_challenge_to_the_nonce_of_its_request() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let public = harness.node_public();
    let nonce = [0x11u8; 32];
    let before_ms = harness.node.now_ms();
    let (status, response) = harness
        .post("/v1/attestation", json!({"nonce": b64u(&nonce)}))
        .await;
    let after_ms = harness.node.now_ms();
    assert_eq!(status, 200);
    let challenge = response["challenge"].as_str().unwrap();

    // The body, in the key order of protocol.md 4.2, signed under its own context.
    let body = harness.verified(purpose::CHALLENGE, &response["challenge_statement"]);
    let keys: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["v", "type", "node", "nonce", "challenge", "time_ms"]);
    assert_eq!(body["v"], 1);
    assert_eq!(body["type"], "challenge");
    assert_eq!(body["node"], harness.node.node.as_str());
    assert_eq!(body["nonce"], b64u(&nonce));
    assert_eq!(body["challenge"], challenge);
    assert!((before_ms..=after_ms).contains(&body["time_ms"].as_u64().unwrap()));
    let statement = challenge_statement(&response);
    assert_eq!(
        verify_challenge_statement(&public, &statement, &nonce, challenge),
        Ok(())
    );

    // A later request, with another nonce or with the same one, gets another challenge, and
    // the statement of one request is not the statement of the challenge of another. What a
    // relay kept from an earlier request therefore fails for the nonce an app just chose.
    for later_nonce in [[0x22u8; 32], nonce] {
        let (_, later) = harness
            .post("/v1/attestation", json!({"nonce": b64u(&later_nonce)}))
            .await;
        let later_challenge = later["challenge"].as_str().unwrap();
        assert_ne!(later_challenge, challenge);
        assert_eq!(
            verify_challenge_statement(
                &public,
                &challenge_statement(&later),
                &later_nonce,
                later_challenge
            ),
            Ok(())
        );
        assert_eq!(
            verify_challenge_statement(&public, &statement, &later_nonce, later_challenge),
            Err(ProtocolError::BadChallenge)
        );
        assert_eq!(
            verify_challenge_statement(&public, &challenge_statement(&later), &nonce, challenge),
            Err(ProtocolError::BadChallenge)
        );
    }

    // The nonce is in the statement as the node read it, at every length it accepts.
    for length in [16, 64] {
        let nonce = vec![7u8; length];
        let (_, response) = harness
            .post("/v1/attestation", json!({"nonce": b64u(&nonce)}))
            .await;
        assert_eq!(
            verify_challenge_statement(
                &public,
                &challenge_statement(&response),
                &nonce,
                response["challenge"].as_str().unwrap()
            ),
            Ok(()),
            "{length}"
        );
    }
}

#[tokio::test]
async fn a_node_keeps_at_most_its_limit_of_challenges() {
    let provider = quiet_provider().await;
    let harness = Harness::with(
        &provider,
        crate::providers::Definitions::embedded(),
        crate::state::Limits {
            challenges: 3,
            ..crate::state::Limits::default()
        },
    );
    let app = App::new("user-1", 1);
    let first = app.attest(&harness).await;
    for _ in 0..3 {
        app.attest(&harness).await;
    }
    // The oldest challenge gave way to the fourth one.
    let not_after_ms = harness.node.now_ms() + 60_000;
    let response = app
        .send(&harness, app.grant_envelope(&first, not_after_ms))
        .await;
    let reply = harness.verified(
        credential_enclave_protocol::purpose::REPLY,
        &response["reply"],
    );
    assert_eq!(reply["code"], "bad_challenge");
    // The newest one is accepted.
    app.grant(&harness).await;
}

#[tokio::test]
async fn the_router_serves_the_calls_of_the_route_list_and_no_other() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let routes = crate::api::route_list();
    let listed: Vec<String> = routes
        .iter()
        .map(|(method, path)| format!("{method} {path}"))
        .collect();
    assert_eq!(
        listed,
        [
            "GET /v1/health",
            "POST /v1/config",
            "POST /v1/attestation",
            "POST /v1/messages",
            "POST /v1/status",
            "POST /v1/oauth/begin",
            "POST /v1/oauth/complete",
            "POST /v1/oauth/merge",
            "POST /v1/refresh",
            "POST /v1/revoke-token",
            "POST /v1/forward",
            "POST /v1/mail/verify",
            "POST /v1/mail/read",
            "POST /v1/mail/submit",
            "POST /v1/release",
            "POST /v1/log/entries",
            "POST /v1/log/ack",
            "POST /v1/close",
            "POST /v1/close/heads",
            "POST /v1/peer/export",
            "POST /v1/peer/import",
            "POST /v1/log-store/credentials",
        ]
    );
    // Every listed call is routed: none answers with the code of an unknown call or of a
    // method the call does not accept.
    for (method, path) in routes {
        let (status, _, _) = harness.send(method.clone(), path, b"{}".to_vec()).await;
        assert!(
            status != 404 && status != 405,
            "{method} {path} answered {status}"
        );
        // The other method of the pair is not accepted.
        let other = if method == axum::http::Method::GET {
            axum::http::Method::POST
        } else {
            axum::http::Method::GET
        };
        let (status, _, _) = harness.send(other, path, Vec::new()).await;
        assert_eq!(status, 405, "{path}");
    }
    // The two calls of release v1.0.0 that took and handed out a plaintext do not exist.
    for path in ["/v1/seal", "/v1/open"] {
        let (status, body) = harness.post(path, json!({"user_id": "user-1"})).await;
        assert_eq!(
            (status, body["code"].as_str()),
            (404, Some("invalid_request")),
            "{path}"
        );
    }
}

#[test]
fn the_calls_of_the_egress_policy_document_are_the_calls_of_the_router() {
    // Rule E3: the table of section 4 of docs/egress-policy.md classifies the response of
    // every call. A call that is added to the router without a row there fails this test.
    let document = include_str!("../../../docs/egress-policy.md");
    let section = document
        .split("## 4. The calls")
        .nth(1)
        .and_then(|rest| rest.split("\n## 5.").next())
        .expect("the document has section 4");
    let documented: Vec<String> = section
        .lines()
        .filter_map(|line| line.strip_prefix("| `")?.split('`').next())
        .filter(|call| call.starts_with("GET /v1/") || call.starts_with("POST /v1/"))
        .map(str::to_string)
        .collect();
    let routed: Vec<String> = crate::api::route_list()
        .iter()
        .map(|(method, path)| format!("{method} {path}"))
        .collect();
    assert_eq!(documented, routed);
}

#[tokio::test]
async fn failures_of_the_surface_have_a_code_and_a_message() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let failure = |status: u16, bytes: &[u8]| {
        let body: Value = serde_json::from_slice(bytes).unwrap();
        assert!(body["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
        (status, body["code"].as_str().unwrap().to_string())
    };

    let (status, _, bytes) = harness
        .send(axum::http::Method::GET, "/v1/unknown", Vec::new())
        .await;
    assert_eq!(
        failure(status.as_u16(), &bytes),
        (404, "invalid_request".to_string())
    );
    let (status, _, bytes) = harness
        .send(axum::http::Method::GET, "/v1/status", Vec::new())
        .await;
    assert_eq!(
        failure(status.as_u16(), &bytes),
        (405, "invalid_request".to_string())
    );
    let (status, _, bytes) = harness
        .send(axum::http::Method::POST, "/v1/status", b"not json".to_vec())
        .await;
    assert_eq!(
        failure(status.as_u16(), &bytes),
        (400, "invalid_request".to_string())
    );
    let (status, _, bytes) = harness
        .send(axum::http::Method::POST, "/v1/status", b"[1,2]".to_vec())
        .await;
    assert_eq!(
        failure(status.as_u16(), &bytes),
        (400, "invalid_request".to_string())
    );
    // A JSON body above 1 MiB.
    let large = format!("{{\"user_id\":\"{}\"}}", "u".repeat(1024 * 1024));
    let (status, _, bytes) = harness
        .send(axum::http::Method::POST, "/v1/status", large.into_bytes())
        .await;
    assert_eq!(
        failure(status.as_u16(), &bytes),
        (413, "too_large".to_string())
    );
    // A status nonce that is not base64url, or empty.
    for nonce in ["", "not base64url!"] {
        let (status, body) = harness
            .post("/v1/status", json!({"user_id": "user-1", "nonce": nonce}))
            .await;
        assert_eq!(
            (status, body["code"].as_str()),
            (400, Some("invalid_request"))
        );
    }
    // An account the node does not know has an empty chain and no grant.
    let (status, state) = harness
        .post(
            "/v1/status",
            json!({"user_id": "nobody", "nonce": "bm9uY2U"}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        state["grant"],
        json!({"state": "none", "key_id": "", "custody": "", "not_after_ms": 0})
    );
    let head = harness.verified(credential_enclave_protocol::purpose::HEAD, &state["head"]);
    assert_eq!(head["seq"], 0);
    assert_eq!(head["hash"], b64u(&[0u8; 32]));
}

async fn exchange(stream: &mut TcpStream, request: &str) -> (u16, Value) {
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buffer = Vec::new();
    let (head_end, length) = loop {
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await.unwrap();
        assert!(read > 0, "the connection closed before a full response");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..position]).to_ascii_lowercase();
            let length: usize = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .unwrap()
                .parse()
                .unwrap();
            break (position + 4, length);
        }
    };
    while buffer.len() < head_end + length {
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await.unwrap();
        buffer.extend_from_slice(&chunk[..read]);
    }
    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
    assert!(head.starts_with("HTTP/1.1 "));
    // The node does not stamp responses with the system time.
    assert!(!head.to_ascii_lowercase().contains("\r\ndate:"));
    let status = head[9..12].parse().unwrap();
    (
        status,
        serde_json::from_slice(&buffer[head_end..head_end + length]).unwrap(),
    )
}

#[tokio::test]
async fn the_node_serves_http_1_1_on_the_listener_of_its_platform() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let listener = Platform::listen(harness.platform.as_ref()).await.unwrap();
    let address = listener.tcp_addr().unwrap();
    tokio::spawn(api::serve(listener, api::router(harness.node.clone())));

    // Two calls on one connection, then a second connection.
    let mut stream = TcpStream::connect(address).await.unwrap();
    let (status, health) =
        exchange(&mut stream, "GET /v1/health HTTP/1.1\r\nHost: node\r\n\r\n").await;
    assert_eq!(status, 200);
    assert_eq!(health["node"], harness.node.node.as_str());
    let body = json!({"nonce": b64u(&[3u8; 32])}).to_string();
    let request = format!(
        "POST /v1/attestation HTTP/1.1\r\nHost: node\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (status, attestation) = exchange(&mut stream, &request).await;
    assert_eq!(status, 200);
    assert_eq!(attestation["node"], harness.node.node.as_str());

    let mut second = TcpStream::connect(address).await.unwrap();
    let (status, failure) = exchange(
        &mut second,
        "GET /v1/nothing HTTP/1.1\r\nHost: node\r\n\r\n",
    )
    .await;
    assert_eq!(
        (status, failure["code"].as_str()),
        (404, Some("invalid_request"))
    );
}
