//! `POST /v1/vault/handoff` (enclave.md 5.9c, protocol.md 10.5): a node of the delegation role
//! hands the value of a vault secret, for one request to its site, to a node of the forward
//! role, and `vault/send` of that node sends the request.
//!
//! These tests run both nodes: a node that holds the grant of an account and writes to the log
//! store, a node that took the forward role, and a stand-in for the site. The envelope a test
//! sends is the one the first node made.

use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use credential_enclave_protocol::app::{open_entry_v3, verify_entry_v3};
use credential_enclave_protocol::encoding::{b64u, Signed};
use credential_enclave_protocol::keys::shard_hash;
use credential_enclave_protocol::log::{object_key_v3, EntryLabel};
use credential_enclave_protocol::secret_use::{open_secret_use, BoundRequest, SecretUseEnvelope};
use credential_enclave_protocol::{limits, ProtocolError};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::platform::Measurement;
use crate::providers::Definitions;
use crate::state::{lock, Limits};
use crate::testing::{App, Harness, Provider, Reply, Seen, Streamed, LOG_HOST};

/// The host of the site of the secret.
const SITE: &str = "api.site.example";
const USER: &str = "user-1";
const NAME: &str = "OPENAI_API_KEY";
const PLACEHOLDER: &str = "vault-placeholder-not-the-value-OPENAI_API_KEY-0123456789abcdefghijkl";
/// A value with characters a path, a query and a form write as escapes.
const VALUE: &str = "sk-live_4f9A/b+c=d~0123456789";
const CONTEXT: &str = "shell:curl";

/// A stand-in for the site and for the log store: `handler` answers a request to the site,
/// and the store confirms every write.
async fn site_and_log_store(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Provider {
    Provider::start(&[SITE, LOG_HOST], move |seen| {
        match seen.server_name == LOG_HOST {
            true => Reply::json(200, &json!({"ok": true})),
            false => handler(seen),
        }
    })
    .await
}

/// A stand-in whose site answers every request with `200 {"ok":true}`.
async fn quiet_site() -> Provider {
    site_and_log_store(|_| Reply::json(200, &json!({"ok": true}))).await
}

/// A node of the delegation role with the log store of the tests, and the app of an account
/// that granted on it.
async fn giving_node(provider: &Provider) -> (Harness, App) {
    let harness = Harness::new(provider);
    harness.use_log_store().await;
    let app = App::new(USER, 1);
    app.grant(&harness).await;
    (harness, app)
}

/// A node that took the forward role.
async fn forward_node(provider: &Provider) -> Harness {
    let harness = Harness::new(provider);
    let (status, _) = harness.post("/v1/config", json!({"role": "forward"})).await;
    assert_eq!(status, 200);
    harness
}

/// The attestation response of a node: what a caller of `vault/handoff` passes as `peer`.
async fn attestation(harness: &Harness) -> Value {
    let nonce = json!({"nonce": b64u(&[0x5a; 32])});
    let (status, response) = harness.post("/v1/attestation", nonce).await;
    assert_eq!(status, 200, "{response}");
    response
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

/// A `GET` request without a body whose value goes into the header `Authorization`.
fn bearer_request() -> Value {
    request_of("GET", "/v1/models", "", "header:authorization", b"")
}

/// A `GET` request without a body whose value is the half of the credentials of HTTP Basic
/// that `slot` names: `basic:user` or `basic:password`.
fn basic_request(slot: &str) -> Value {
    request_of("GET", "/v1/charges", "", slot, b"")
}

/// The value of an `Authorization` header that carries `credentials` as HTTP Basic.
fn basic(credentials: &str) -> String {
    format!("Basic {}", STANDARD.encode(credentials))
}

/// The plaintext of a record of kind `vault_secret` as the device of an account writes it.
fn plaintext(sites: Value, slots: Value, value: &str) -> Value {
    json!({"value": value, "name": NAME, "sites": sites, "slots": slots, "source": "device"})
}

/// A record of kind `vault_secret` the device of the account made.
fn named(app: &App, sites: Value, slots: Value, value: &str) -> Value {
    app.record("vault_secret", "vault", &plaintext(sites, slots, value))
}

/// A record whose value may go into the header `Authorization` of a request to the site.
fn bearer_record(app: &App, value: &str) -> Value {
    named(app, json!([SITE]), json!(["header:authorization"]), value)
}

fn body_of(record: &Value, peer: &Value, request: &Value) -> Value {
    json!({
        "user_id": USER, "record": record, "peer": peer, "request": request,
        "context": CONTEXT,
    })
}

async fn handoff(giving: &Harness, record: &Value, peer: &Value, request: &Value) -> (u16, Value) {
    giving
        .post("/v1/vault/handoff", body_of(record, peer, request))
        .await
}

fn code(outcome: &(u16, Value)) -> (u16, &str) {
    (outcome.0, outcome.1["code"].as_str().unwrap_or_default())
}

fn sent_code(outcome: &Result<Streamed, (u16, Value)>) -> (u16, String) {
    match outcome {
        Ok(sent) => panic!("the call handed a response of status {} on", sent.status),
        Err((status, failure)) => (
            *status,
            failure["code"].as_str().unwrap_or_default().to_string(),
        ),
    }
}

/// The keys of an event in their order, and the event without its `time_ms`.
fn keys_and_event(mut event: Value) -> (Vec<String>, Value) {
    assert!(event["time_ms"].as_u64().is_some(), "{event}");
    let keys = event.as_object().unwrap().keys().cloned().collect();
    event.as_object_mut().unwrap().remove("time_ms");
    (keys, event)
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

#[tokio::test]
async fn a_value_goes_from_its_record_to_its_site_through_the_two_nodes() {
    let provider = quiet_site().await;
    let (giving, app) = giving_node(&provider).await;
    let forward = forward_node(&provider).await;
    let peer = attestation(&forward).await;
    let record = bearer_record(&app, VALUE);
    let body = b"{\"model\":\"m\",\"input\":\"hello\"}";
    let request = request_of(
        "POST",
        "/v1/chat/completions",
        "stream=false",
        "header:authorization",
        body,
    );

    // The node of the delegation role records the use and answers with the envelope: no
    // value, and nothing of the record but its place on the chain.
    let (status, handed) = handoff(&giving, &record, &peer, &request).await;
    assert_eq!(status, 200, "{handed}");
    assert_eq!(
        handed.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["envelope", "log"]
    );
    assert_eq!(
        handed["log"],
        json!({"seq": 2, "index": 0, "created": true})
    );
    let envelope = &handed["envelope"];
    assert_eq!(
        envelope.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["v", "from", "to", "enc", "ct"]
    );
    assert_eq!(envelope["v"], 1);
    assert_eq!(envelope["from"], giving.node.node.as_str());
    assert_eq!(envelope["to"], forward.node.node.as_str());
    assert!(!handed.to_string().contains(VALUE));

    // The event of the use is on the chain of the account, in the store: a `provider_request`
    // with the request as the caller stated it, the name of the record, the slot and the
    // node the value was sealed to. It carries no `window_s`.
    let (keys, event) = keys_and_event(app.logged(&giving, &provider, &handed["log"]));
    assert_eq!(
        keys,
        [
            "t",
            "time_ms",
            "record_id",
            "provider",
            "method",
            "host",
            "path",
            "query",
            "body_bytes",
            "body_sha256",
            "context",
            "name",
            "slot",
            "to"
        ]
    );
    assert_eq!(
        event,
        json!({
            "t": "provider_request", "record_id": record["id"], "provider": "vault",
            "method": "POST", "host": SITE, "path": "/v1/chat/completions",
            "query": "stream=false", "body_bytes": body.len(),
            "body_sha256": b64u(&Sha256::digest(body)), "context": CONTEXT, "name": NAME,
            "slot": "header:authorization", "to": forward.node.node,
        })
    );
    // Nothing went to the site yet: the node of the delegation role connects to its log
    // store and to no site.
    assert!(provider.requests().is_empty());
    assert!(giving
        .platform
        .connections()
        .iter()
        .all(|(host, port)| host == LOG_HOST && *port == 443));

    // The node of the forward role sends the request of the envelope, with the value at its
    // slot.
    let meta = json!({
        "envelope": envelope, "timeout_ms": 5000,
        "headers": [
            ["Authorization", format!("Bearer {PLACEHOLDER}")],
            ["Content-Type", "application/json"],
        ],
    });
    let sent = forward
        .vault_send(meta.clone(), body)
        .await
        .unwrap_or_else(|failure| panic!("{failure:?}"));
    assert_eq!((sent.status, &sent.end), (200, &json!({"complete": true})));
    let seen = provider.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].server_name.as_str(), seen[0].method.as_str()),
        (SITE, "POST")
    );
    assert_eq!(seen[0].target, "/v1/chat/completions?stream=false");
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {VALUE}").as_str())
    );
    assert_eq!(seen[0].body, body);
    assert!(forward
        .platform
        .connections()
        .iter()
        .all(|(host, port)| host == SITE && *port == 443));

    // One envelope, one request: the same envelope sends nothing a second time, and the
    // chain of the account holds the one event of the one use.
    let again = forward.vault_send(meta, body).await;
    assert_eq!(sent_code(&again), (400, "bad_challenge".to_string()));
    assert_eq!(provider.requests().len(), 1);
    let chain = app.stored_events(&giving, &provider);
    assert_eq!(chain.len(), 2);
    assert_eq!(
        (&chain[0][0]["t"], chain[1].len(), &chain[1][0]["t"]),
        (&json!("grant_accepted"), 1, &json!("provider_request"))
    );
    assert_eq!(giving.last_seq(USER), 2);
}

#[tokio::test]
async fn the_value_goes_to_every_slot_of_a_request_its_record_lists() {
    let provider = quiet_site().await;
    let (giving, app) = giving_node(&provider).await;
    let forward = forward_node(&provider).await;
    let peer = attestation(&forward).await;
    let in_the_address = named(
        &app,
        json!(["other.example", SITE]),
        json!(["query:key", "path", "json:auth.token", "header:x-api-key"]),
        VALUE,
    );
    let in_a_form = named(
        &app,
        json!([SITE]),
        json!(["form:client_secret", "basic:user", "basic:password"]),
        VALUE,
    );
    let json_body = format!("{{\"auth\":{{\"token\":\"{PLACEHOLDER}\"}},\"n\":1}}");
    let form_body = format!("grant_type=x&client_secret={PLACEHOLDER}&scope=s");
    let query = format!("a=1&key={PLACEHOLDER}");
    let path = format!("/bot{PLACEHOLDER}/send");
    // The record, the request object, the headers of the caller and the body.
    let uses: [(&Value, Value, Value, &[u8]); 7] = [
        (
            &in_a_form,
            basic_request("basic:user"),
            json!([["Authorization", basic(&format!("{PLACEHOLDER}:"))]]),
            b"",
        ),
        (
            &in_a_form,
            basic_request("basic:password"),
            json!([["Authorization", basic(&format!("AC0123:{PLACEHOLDER}"))]]),
            b"",
        ),
        (
            &in_the_address,
            request_of("GET", "/v1/items", &query, "query:key", b""),
            json!([]),
            b"",
        ),
        (
            &in_the_address,
            request_of("DELETE", &path, "", "path", b""),
            json!([]),
            b"",
        ),
        (
            &in_the_address,
            request_of(
                "PUT",
                "/v1/session",
                "",
                "json:auth.token",
                json_body.as_bytes(),
            ),
            json!([["Content-Type", "application/json"]]),
            json_body.as_bytes(),
        ),
        (
            &in_the_address,
            request_of("GET", "/v1/items", "", "header:x-api-key", b""),
            json!([["X-Api-Key", PLACEHOLDER]]),
            b"",
        ),
        (
            &in_a_form,
            request_of(
                "POST",
                "/oauth/token",
                "",
                "form:client_secret",
                form_body.as_bytes(),
            ),
            json!([["Content-Type", "application/x-www-form-urlencoded"]]),
            form_body.as_bytes(),
        ),
    ];
    for (index, (record, request, headers, body)) in uses.into_iter().enumerate() {
        let slot = request["slot"].as_str().unwrap().to_string();
        let (status, handed) = handoff(&giving, record, &peer, &request).await;
        assert_eq!(status, 200, "{slot}: {handed}");
        let event = app.logged(&giving, &provider, &handed["log"]);
        assert_eq!(
            (&event["slot"], &event["path"], &event["query"]),
            (&request["slot"], &request["path"], &request["query"]),
            "{slot}"
        );
        // The path and the query of the event hold the placeholder where the value goes:
        // no part of the value is on the chain.
        assert!(!event.to_string().contains(VALUE), "{slot}");
        let meta = json!({
            "envelope": handed["envelope"], "headers": headers, "timeout_ms": 5000,
        });
        let sent = forward
            .vault_send(meta, body)
            .await
            .unwrap_or_else(|failure| panic!("{slot}: {failure:?}"));
        assert_eq!(sent.status, 200, "{slot}");
        let seen = provider.requests();
        assert_eq!(seen.len(), index + 1, "{slot}");
        let seen = seen.last().unwrap();
        let wire = format!(
            "{} {:?} {}",
            seen.target,
            seen.headers,
            String::from_utf8_lossy(&seen.body)
        );
        assert!(!wire.contains(PLACEHOLDER), "{slot}: {wire}");
        match slot.as_str() {
            "query:key" => assert_eq!(seen.target, format!("/v1/items?a=1&key={}", percent(VALUE))),
            "path" => assert_eq!(seen.target, format!("/bot{}/send", percent(VALUE))),
            "json:auth.token" => assert_eq!(
                serde_json::from_slice::<Value>(&seen.body).unwrap(),
                json!({"auth": {"token": VALUE}, "n": 1})
            ),
            "header:x-api-key" => assert_eq!(seen.header("x-api-key"), Some(VALUE)),
            // The value as the user-id of the credentials, in front of an empty password, and
            // as the password, behind the user-id of the caller.
            "basic:user" => assert_eq!(
                seen.header("authorization"),
                Some(basic(&format!("{VALUE}:")).as_str())
            ),
            "basic:password" => assert_eq!(
                seen.header("authorization"),
                Some(basic(&format!("AC0123:{VALUE}")).as_str())
            ),
            _ => assert_eq!(seen.form_value("client_secret").as_deref(), Some(VALUE)),
        }
    }
    assert_eq!(giving.last_seq(USER), 8);
}

#[tokio::test]
async fn the_envelope_opens_for_the_node_it_was_sealed_to_and_names_the_use() {
    let provider = quiet_site().await;
    let (giving, app) = giving_node(&provider).await;
    let forward = forward_node(&provider).await;
    let other = forward_node(&provider).await;
    let record = bearer_record(&app, VALUE);
    let request = bearer_request();

    let before_ms = giving.node.now_ms();
    let (status, handed) = handoff(&giving, &record, &attestation(&forward).await, &request).await;
    assert_eq!(status, 200, "{handed}");
    let after_ms = giving.node.now_ms();
    let envelope = SecretUseEnvelope::from_value(&handed["envelope"]).unwrap();

    let opened = open_secret_use(&forward.node.keys, &envelope).unwrap();
    assert_eq!(opened.from(), giving.node.node);
    assert_eq!(opened.user_id(), USER);
    assert_eq!(opened.record_id(), record["id"].as_str().unwrap());
    assert_eq!(opened.value().expose_secret(), VALUE);
    assert_eq!(
        opened.request(),
        &BoundRequest::from_value(&request).unwrap()
    );
    // The envelope lives 30 seconds from the node time at which it was made, which is after
    // the entry of the use was confirmed.
    assert!((before_ms..=after_ms).contains(&opened.time_ms()));
    assert_eq!(
        opened.not_after_ms(),
        opened.time_ms() + limits::SECRET_USE_MS
    );
    let event = app.logged(&giving, &provider, &handed["log"]);
    assert!(event["time_ms"].as_u64().unwrap() <= opened.time_ms());

    // Another node of the forward role does not open it, and neither does the node that made
    // it: the value is readable in the one node the entry names.
    for keys in [&other.node.keys, &giving.node.keys] {
        assert_eq!(
            open_secret_use(keys, &envelope).map(|_| ()),
            Err(ProtocolError::WrongNode)
        );
    }
    let meta = json!({
        "envelope": handed["envelope"],
        "headers": [["authorization", format!("Bearer {PLACEHOLDER}")]],
    });
    let outcome = other.vault_send(meta, b"").await;
    assert_eq!(sent_code(&outcome), (400, "wrong_node".to_string()));
    assert!(provider.requests().is_empty());

    // Every call draws its own number and its own seal: two envelopes of one use differ, and
    // each sends its request once.
    let (_, second) = handoff(&giving, &record, &attestation(&forward).await, &request).await;
    let second_envelope = SecretUseEnvelope::from_value(&second["envelope"]).unwrap();
    assert_ne!(second_envelope.ct, envelope.ct);
    let reopened = open_secret_use(&forward.node.keys, &second_envelope).unwrap();
    assert_ne!(reopened.nonce(), opened.nonce());
}

#[tokio::test]
async fn every_handoff_has_an_event_of_its_own() {
    let provider = quiet_site().await;
    let (giving, app) = giving_node(&provider).await;
    let forward = forward_node(&provider).await;
    let peer = attestation(&forward).await;
    let record = bearer_record(&app, VALUE);
    // Three times the same `GET` request without a body: `forward` would give such requests
    // one event of 300 seconds. A use of a vault secret is not merged.
    let request = bearer_request();
    let mut logs = Vec::new();
    for _ in 0..3 {
        let (status, handed) = handoff(&giving, &record, &peer, &request).await;
        assert_eq!(status, 200, "{handed}");
        logs.push(handed["log"].clone());
    }
    assert_eq!(
        logs,
        [2, 3, 4].map(|seq| json!({"seq": seq, "index": 0, "created": true}))
    );
    for log in &logs {
        let event = app.logged(&giving, &provider, log);
        assert_eq!(event["t"], "provider_request");
        assert_eq!(event["body_bytes"], 0);
        assert_eq!(event["body_sha256"], "");
        assert!(event.get("window_s").is_none(), "{event}");
    }
    assert_eq!(giving.health().await["state"]["merge_keys"], 0);

    // Calls that arrive together share entries, and each has its own event in them.
    let together = (0..8).map(|_| handoff(&giving, &record, &peer, &request));
    let outcomes = crate::log_store::join_all(together).await;
    let mut places = std::collections::BTreeSet::new();
    for (status, handed) in &outcomes {
        assert_eq!(*status, 200, "{handed}");
        assert_eq!(handed["log"]["created"], true);
        let place = (
            handed["log"]["seq"].as_u64().unwrap(),
            handed["log"]["index"].as_u64().unwrap(),
        );
        assert!(places.insert(place), "{place:?} names two uses");
    }
    let events: usize = app
        .stored_events(&giving, &provider)
        .iter()
        .map(Vec::len)
        .sum();
    assert_eq!(events, 1 + 3 + 8);
}

#[tokio::test]
async fn a_use_outside_the_reach_of_its_record_is_refused_and_creates_no_entry() {
    let provider = quiet_site().await;
    let (giving, app) = giving_node(&provider).await;
    let forward = forward_node(&provider).await;
    let peer = attestation(&forward).await;
    let bearer = bearer_request();
    let query = format!("key={PLACEHOLDER}");
    let with_key = request_of("GET", "/v1/items", &query, "query:key", b"");

    let other_site = named(
        &app,
        json!(["api.other.example", "site.example", "www.api.site.example"]),
        json!(["header:authorization"]),
        VALUE,
    );
    let other_slots = named(
        &app,
        json!([SITE]),
        json!([
            "header:x-api-key",
            "query:authorization",
            "form:key",
            "path"
        ]),
        VALUE,
    );
    let other_name = named(&app, json!([SITE]), json!(["query:Key"]), VALUE);
    let field_only = named(&app, json!([SITE]), json!(["field"]), VALUE);
    // A value that may be typed into a page of every host goes into no request.
    let anywhere = named(&app, json!("any"), json!(["field"]), VALUE);
    // The header `Authorization` and the credentials of HTTP Basic inside it are two places.
    let of_the_header = bearer_record(&app, VALUE);
    // So are the two halves of those credentials: a record that holds a password lists the
    // slot of the password, and admits no use of its value as a user-id.
    let of_password = named(&app, json!([SITE]), json!(["basic:password"]), VALUE);
    let of_user_id = named(&app, json!([SITE]), json!(["basic:user"]), VALUE);
    let as_user_id = basic_request("basic:user");
    let as_password = basic_request("basic:password");
    let refused = [
        ("a host that is not one of the sites", &other_site, &bearer),
        ("a slot the record does not list", &other_slots, &bearer),
        (
            "a user-id of HTTP Basic for a record of the header",
            &of_the_header,
            &as_user_id,
        ),
        (
            "a password of HTTP Basic for a record of the header",
            &of_the_header,
            &as_password,
        ),
        (
            "the header for a record of HTTP Basic",
            &of_password,
            &bearer,
        ),
        (
            "a user-id of HTTP Basic for a record of a password",
            &of_password,
            &as_user_id,
        ),
        (
            "a password of HTTP Basic for a record of a user-id",
            &of_user_id,
            &as_password,
        ),
        ("a query slot of another spelling", &other_name, &with_key),
        ("a record for a field of a page", &field_only, &bearer),
        ("a record of every host", &anywhere, &bearer),
    ];
    for (case, record, request) in refused {
        let outcome = handoff(&giving, record, &peer, request).await;
        assert_eq!(code(&outcome), (403, "not_allowed"), "{case}");
        assert_eq!(outcome.1.as_object().unwrap().len(), 2, "{case}");
    }

    // A record of another kind holds no value for a request: the three other vault kinds,
    // and a token.
    let fixed = [
        ("vault_password", "vault", json!({"value": VALUE})),
        ("vault_totp", "vault", json!({"value": "JBSWY3DPEHPK3PXP"})),
        (
            "vault_card",
            "vault",
            json!({"number": "4242", "cvc": "123"}),
        ),
        (
            "oauth",
            "google_workspace",
            json!({"token": {"access_token": VALUE}, "obtained_ms": 1}),
        ),
    ];
    for (kind, record_provider, plaintext) in fixed {
        let record = app.record(kind, record_provider, &plaintext);
        let outcome = handoff(&giving, &record, &peer, &bearer).await;
        assert_eq!(code(&outcome), (403, "not_allowed"), "{kind}");
    }
    // A plaintext of the kind that states no reach does not open, as for `release`: one
    // without the members of a reach, one without a slot, and one that lists the slot `field`
    // next to a slot of a request.
    let stateless = app.record("vault_secret", "vault", &json!({"value": VALUE}));
    let no_slot = named(&app, json!([SITE]), json!([]), VALUE);
    let typed_too = named(
        &app,
        json!([SITE]),
        json!(["header:authorization", "field"]),
        VALUE,
    );
    for record in [&stateless, &no_slot, &typed_too] {
        let outcome = handoff(&giving, record, &peer, &bearer).await;
        assert_eq!(code(&outcome), (422, "record_invalid"));
    }

    // What a refusal before the entry says does not depend on the value of the record: a
    // plaintext whose value no call can use is refused outside its reach like any other.
    for value in [json!(7), Value::Null, json!("short")] {
        let mut odd = plaintext(json!(["api.other.example"]), json!(["path"]), VALUE);
        odd["value"] = value.clone();
        let record = app.record("vault_secret", "vault", &odd);
        let outcome = handoff(&giving, &record, &peer, &bearer).await;
        assert_eq!(code(&outcome), (403, "not_allowed"), "{value}");
    }

    // Only the grant left an entry, the store received nothing after it, and nothing was
    // sealed: the node of the forward role has nothing to send.
    assert_eq!(giving.last_seq(USER), 1);
    assert_eq!(app.stored_events(&giving, &provider).len(), 1);
    assert!(provider.requests().is_empty());
}

#[tokio::test]
async fn the_value_of_a_use_is_judged_after_its_entry() {
    let provider = quiet_site().await;
    let (giving, app) = giving_node(&provider).await;
    let forward = forward_node(&provider).await;
    let peer = attestation(&forward).await;
    let slots = json!([
        "header:authorization",
        "query:key",
        "basic:user",
        "basic:password"
    ]);
    let bearer = bearer_request();
    let as_user_id = basic_request("basic:user");
    let as_password = basic_request("basic:password");
    let query = format!("key={PLACEHOLDER}");
    let with_key = request_of("GET", "/v1/items", &query, "query:key", b"");
    let record_of = |value: Value| {
        let mut stated = plaintext(json!([SITE]), slots.clone(), VALUE);
        match value {
            Value::Null => {
                stated.as_object_mut().unwrap().shift_remove("value");
            }
            value => stated["value"] = value,
        }
        app.record("vault_secret", "vault", &stated)
    };

    // Values no envelope carries: a member that is missing or no string, a value of fewer
    // than 8 bytes or of more than 12,000, for a header and for either half of the
    // credentials of HTTP Basic a value with a control character, and for the user-id of
    // those credentials a value with a colon.
    // Each call passes the checks before its entry like a call for a usable value, its entry
    // is confirmed, and only then the node reads the value: no envelope leaves, and the entry
    // stays.
    let line_break = format!("{VALUE}\r\nx-injected: 1");
    let unusable = [
        ("no value", record_of(Value::Null), &bearer),
        ("a number", record_of(json!(12345678)), &bearer),
        ("an object", record_of(json!({"value": VALUE})), &bearer),
        ("the empty string", record_of(json!("")), &bearer),
        ("7 bytes", record_of(json!("1234567")), &bearer),
        (
            "7 bytes for a query",
            record_of(json!("1234567")),
            &with_key,
        ),
        (
            "12,001 bytes",
            record_of(json!("v".repeat(12_001))),
            &with_key,
        ),
        (
            "a line break in a header",
            record_of(json!(line_break)),
            &bearer,
        ),
        (
            "a tab in a header",
            record_of(json!("sk-live\t0123456789")),
            &bearer,
        ),
        (
            "a line break in a user-id of HTTP Basic",
            record_of(json!(line_break)),
            &as_user_id,
        ),
        (
            "a line break in a password of HTTP Basic",
            record_of(json!(line_break)),
            &as_password,
        ),
        (
            "a tab in a password of HTTP Basic",
            record_of(json!("sk-live\t0123456789")),
            &as_password,
        ),
        (
            "7 bytes for the credentials of HTTP Basic",
            record_of(json!("1234567")),
            &as_user_id,
        ),
        // The first colon of the credentials ends the user-id: a server would read a
        // user-id with a colon up to that colon.
        (
            "a colon in a user-id of HTTP Basic",
            record_of(json!("user:pass-0123456789")),
            &as_user_id,
        ),
    ];
    let mut seq = 1;
    for (case, record, request) in &unusable {
        let outcome = handoff(&giving, record, &peer, request).await;
        assert_eq!(code(&outcome), (422, "record_invalid"), "{case}");
        assert_eq!(outcome.1.as_object().unwrap().len(), 2, "{case}");
        seq += 1;
        assert_eq!(giving.last_seq(USER), seq, "{case}");
        let event = app.logged(&giving, &provider, &json!({"seq": seq, "index": 0}));
        assert_eq!(
            (&event["t"], &event["record_id"], &event["slot"]),
            (&json!("provider_request"), &record["id"], &request["slot"]),
            "{case}"
        );
    }

    // The values at the two ends of the length, a value with a control character where the
    // slot is no header (the node of the forward role writes it there as an escape), and a
    // value with a colon for the password of the credentials of HTTP Basic: a colon is a
    // character of a password like any other.
    let usable = [
        ("8 bytes", record_of(json!("12345678")), &bearer),
        (
            "a colon in a password of HTTP Basic",
            record_of(json!("user:pass-0123456789")),
            &as_password,
        ),
        (
            "12,000 bytes",
            record_of(json!("v".repeat(12_000))),
            &with_key,
        ),
        (
            "a line break in a query",
            record_of(json!(line_break)),
            &with_key,
        ),
    ];
    for (case, record, request) in &usable {
        let (status, handed) = handoff(&giving, record, &peer, request).await;
        assert_eq!(status, 200, "{case}: {handed}");
        seq += 1;
        assert_eq!(handed["log"]["seq"], seq, "{case}");
    }
    assert!(provider.requests().is_empty());
}

#[tokio::test]
async fn a_value_goes_into_the_half_of_http_basic_its_record_names_and_not_into_the_other() {
    let provider = quiet_site().await;
    let (giving, app) = giving_node(&provider).await;
    let forward = forward_node(&provider).await;
    let peer = attestation(&forward).await;
    let as_user_id = basic(&format!("{PLACEHOLDER}:x"));
    let as_password = basic(&format!("x:{PLACEHOLDER}"));
    // The record, the slot of its use, the credentials a caller writes to move the value
    // into the other half, and the credentials of the half the record names.
    let cases = [
        ("basic:password", &as_user_id, &as_password, "x", VALUE),
        ("basic:user", &as_password, &as_user_id, VALUE, "x"),
    ];
    for (index, (slot, moved, placed, user_id, password)) in cases.into_iter().enumerate() {
        let record = named(&app, json!([SITE]), json!([slot]), VALUE);
        // The request object names the half, and so does the event of the use.
        let (status, handed) = handoff(&giving, &record, &peer, &basic_request(slot)).await;
        assert_eq!(status, 200, "{slot}: {handed}");
        let event = app.logged(&giving, &provider, &handed["log"]);
        assert_eq!(event["slot"], slot);
        // The caller of `vault/send` writes the placeholder as the other half: nothing is
        // sent, whatever else the request holds.
        let meta = |authorization: &str| {
            json!({
                "envelope": handed["envelope"],
                "headers": [["Authorization", authorization]],
                "timeout_ms": 5000,
            })
        };
        let refused = forward.vault_send(meta(moved), b"").await;
        assert_eq!(
            sent_code(&refused),
            (400, "invalid_request".to_string()),
            "{slot}"
        );
        assert_eq!(provider.requests().len(), index, "{slot}");
        // The envelope stayed unused, and sends the request with the value as the half the
        // record names.
        let sent = forward.vault_send(meta(placed), b"").await.unwrap();
        assert_eq!(sent.status, 200, "{slot}");
        let seen = provider.requests();
        let seen = seen.last().unwrap();
        let text = seen
            .header("authorization")
            .and_then(|header| header.strip_prefix("Basic "))
            .unwrap();
        let read = String::from_utf8(STANDARD.decode(text).unwrap()).unwrap();
        assert_eq!(read.split_once(':'), Some((user_id, password)), "{slot}");
    }
    // A request object that names no half is no request object: no record lists such a
    // slot, and none is sealed for one.
    let record = named(&app, json!([SITE]), json!(["basic:password"]), VALUE);
    let outcome = handoff(&giving, &record, &peer, &basic_request("basic")).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
}

#[tokio::test]
async fn the_receiving_node_is_a_node_of_the_forward_role_of_this_program() {
    let provider = quiet_site().await;
    let (giving, app) = giving_node(&provider).await;
    let forward = forward_node(&provider).await;
    let record = bearer_record(&app, VALUE);
    let request = bearer_request();
    let of_a_forward_node = attestation(&forward).await;

    // A node of the delegation role and a node that took no role: their bindings name no
    // role, and a value sealed to such a node would be readable in a node that sends nothing
    // for it. This node itself is one of them.
    let delegation = Harness::new(&provider);
    App::new("user-2", 2).grant(&delegation).await;
    let without_a_role = Harness::new(&provider);
    for (case, node) in [
        ("a node of the delegation role", &delegation),
        ("a node without a role", &without_a_role),
        ("this node", &giving),
    ] {
        let peer = attestation(node).await;
        let outcome = handoff(&giving, &record, &peer, &request).await;
        assert_eq!(code(&outcome), (403, "peer_unverified"), "{case}");
    }

    // A response that is no attestation response, or one whose document was changed.
    let mut other_version = of_a_forward_node.clone();
    other_version["v"] = json!(2);
    let mut other_platform = of_a_forward_node.clone();
    other_platform["platform"] = json!("nitro");
    let mut no_document = of_a_forward_node.clone();
    no_document.as_object_mut().unwrap().remove("document");
    let mut garbled = of_a_forward_node.clone();
    garbled["document"] = json!(b64u(b"not a document"));
    for (case, peer) in [
        ("another version", other_version),
        ("another platform", other_platform),
        ("no document", no_document),
        ("a document that is none", garbled),
        ("an empty object", json!({})),
    ] {
        let outcome = handoff(&giving, &record, &peer, &request).await;
        assert_eq!(code(&outcome), (403, "peer_unverified"), "{case}");
    }
    // A `peer` that is no object is a body of another form.
    for peer in [json!("node"), json!([]), Value::Null] {
        let outcome = handoff(&giving, &record, &peer, &request).await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{peer}");
    }

    // A node of another platform: a node inside an enclave seals no value to a node that
    // runs as an ordinary process.
    let measured = Harness::measured(
        &provider,
        Measurement {
            pcrs: [[0xa0; 48], [0xa1; 48], [0xa2; 48]],
        },
    );
    let outcome = handoff(&measured, &record, &of_a_forward_node, &request).await;
    assert_eq!(code(&outcome), (403, "peer_unverified"));

    // None of these calls created an entry or sealed a value.
    assert_eq!(giving.last_seq(USER), 1);
    assert_eq!(app.stored_events(&giving, &provider).len(), 1);

    // The same call with the response of the node of the forward role is taken, also when
    // the response is presented a second time and with keys a verifier does not read.
    let mut presented = of_a_forward_node.clone();
    presented["node"] = json!("not-the-node");
    presented["challenge"] = json!("not-the-challenge");
    for peer in [&of_a_forward_node, &presented, &of_a_forward_node] {
        let (status, handed) = handoff(&giving, &record, peer, &request).await;
        assert_eq!(status, 200, "{handed}");
        assert_eq!(handed["envelope"]["to"], forward.node.node.as_str());
    }
    // The node keeps what it verified under the hash of the document: the one document of
    // these three calls.
    assert_eq!(giving.node.forward_nodes.len(), 1);
    let (status, _) = handoff(&giving, &record, &attestation(&forward).await, &request).await;
    assert_eq!(status, 200);
    assert_eq!(giving.node.forward_nodes.len(), 2);
}

#[tokio::test]
async fn a_body_that_has_not_the_form_of_vault_handoff_is_refused_and_creates_no_entry() {
    let provider = quiet_site().await;
    let (giving, app) = giving_node(&provider).await;
    let forward = forward_node(&provider).await;
    let peer = attestation(&forward).await;
    let record = named(
        &app,
        json!([SITE]),
        json!(["header:authorization", "query:key", "path"]),
        VALUE,
    );
    let valid = || body_of(&record, &peer, &bearer_request());
    let without = |key: &str| {
        let mut body = valid();
        body.as_object_mut().unwrap().shift_remove(key);
        body
    };
    let with = |key: &str, value: Value| {
        let mut body = valid();
        body[key] = value;
        body
    };
    let with_request = |key: &str, value: Value| {
        let mut body = valid();
        body["request"][key] = value;
        body
    };
    let query = format!("key={PLACEHOLDER}");
    let bodies = [
        ("no user_id", without("user_id")),
        ("a user_id that is no name", with("user_id", json!("a\nb"))),
        ("no record", without("record")),
        (
            "a record that is no object",
            with("record", json!("record")),
        ),
        ("no request", without("request")),
        (
            "a request that is no object",
            with("request", json!("GET /")),
        ),
        ("no peer", without("peer")),
        (
            "a context of 257 characters",
            with("context", json!("c".repeat(257))),
        ),
        ("a method no use has", with_request("method", json!("HEAD"))),
        (
            "a host with a capital",
            with_request("host", json!("API.site.example")),
        ),
        (
            "an address for a host",
            with_request("host", json!("169.254.169.254")),
        ),
        (
            "a host of one label",
            with_request("host", json!("localhost")),
        ),
        ("a path without /", with_request("path", json!("v1/models"))),
        (
            "a path with a query",
            with_request("path", json!("/v1/models?a=1")),
        ),
        ("a query with #", with_request("query", json!("a=1#top"))),
        // A slot that is no place of a request, a slot of no form, and a slot whose name a
        // query writes with an escape.
        ("the slot field", with_request("slot", json!("field"))),
        ("a slot of no form", with_request("slot", json!("body"))),
        (
            "the slot of a header a node of the forward role writes",
            with_request("slot", json!("header:host")),
        ),
        (
            "a query slot with a colon in its name",
            with_request("slot", json!("query:a:b")),
        ),
        // The placeholder and the address do not agree with the slot.
        (
            "a path slot without the placeholder in the path",
            with_request("slot", json!("path")),
        ),
        (
            "a query slot without the placeholder in the query",
            with_request("slot", json!("query:key")),
        ),
        (
            "a header slot with the placeholder in the query",
            with_request("query", json!(query)),
        ),
        (
            "a placeholder of 15 characters",
            with_request("placeholder", json!("p".repeat(15))),
        ),
        (
            "a body without its hash",
            with_request("body_bytes", json!(5)),
        ),
        (
            "a hash without a body",
            with_request("body_sha256", json!(b64u(&[7u8; 32]))),
        ),
        ("no body_bytes", {
            let mut body = valid();
            let request = body["request"].as_object_mut().unwrap();
            request.shift_remove("body_bytes");
            body
        }),
    ];
    for (case, body) in bodies {
        let outcome = giving.post("/v1/vault/handoff", body).await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{case}");
    }
    // A body above the limit of a request.
    let mut large = valid();
    large["request"]["body_bytes"] = json!(limits::BODY_BYTES + 1);
    large["request"]["body_sha256"] = json!(b64u(&[7u8; 32]));
    let outcome = giving.post("/v1/vault/handoff", large).await;
    assert_eq!(code(&outcome), (413, "too_large"));
    // A record of another account, of another version, and one that does not open.
    let mut of_another = record.clone();
    of_another["user_id"] = json!("user-2");
    let outcome = giving
        .post("/v1/vault/handoff", with("record", of_another))
        .await;
    assert_eq!(code(&outcome), (400, "user_mismatch"));
    let mut version = record.clone();
    version["v"] = json!(2);
    let outcome = giving
        .post("/v1/vault/handoff", with("record", version))
        .await;
    assert_eq!(code(&outcome), (400, "unsupported_version"));
    let mut relabelled = record.clone();
    relabelled["kind"] = json!("vault_password");
    let outcome = giving
        .post("/v1/vault/handoff", with("record", relabelled))
        .await;
    assert_eq!(code(&outcome), (422, "record_invalid"));
    assert_eq!(giving.last_seq(USER), 1);

    // The context is optional, and keys the call does not define are passed over.
    let mut body = without("context");
    body["future"] = json!(1);
    body["request"]["future"] = json!(1);
    let (status, handed) = giving.post("/v1/vault/handoff", body).await;
    assert_eq!(status, 200, "{handed}");
    let event = app.logged(&giving, &provider, &handed["log"]);
    assert_eq!(event["context"], "");
    assert!(event.get("future").is_none());
}

#[tokio::test]
async fn a_handoff_passes_the_common_front_before_its_event() {
    let provider = quiet_site().await;
    let forward = forward_node(&provider).await;
    let peer = attestation(&forward).await;
    let request = bearer_request();

    // An account without a grant on the node, and one that withdrew its grant.
    let (giving, app) = giving_node(&provider).await;
    let record = bearer_record(&app, VALUE);
    let stranger = App::new("user-2", 2);
    let mut body = body_of(&bearer_record(&stranger, VALUE), &peer, &request);
    body["user_id"] = json!("user-2");
    let outcome = giving.post("/v1/vault/handoff", body).await;
    assert_eq!(code(&outcome), (409, "grant_required"));
    // A record under the key of another grant.
    let rekeyed = App::new(USER, 9);
    let outcome = handoff(&giving, &bearer_record(&rekeyed, VALUE), &peer, &request).await;
    assert_eq!(code(&outcome), (409, "key_mismatch"));
    app.revoke(&giving).await;
    let outcome = handoff(&giving, &record, &peer, &request).await;
    assert_eq!(code(&outcome), (409, "grant_revoked"));
    assert_eq!(giving.last_seq(USER), 2);

    // A closing node hands nothing over.
    let (closing, app) = giving_node(&provider).await;
    let record = bearer_record(&app, VALUE);
    assert_eq!(closing.post("/v1/close", json!({})).await.0, 200);
    let outcome = handoff(&closing, &record, &peer, &request).await;
    assert_eq!(code(&outcome), (503, "closing"));
    assert_eq!(closing.last_seq(USER), 1);

    // The call works without the client values of a provider: a node whose configuration
    // names its log store and nothing else.
    let bare = Harness::new(&provider);
    let config = json!({
        "providers": {},
        "log_store": {"bucket": crate::testing::LOG_BUCKET, "region": crate::testing::LOG_REGION},
    });
    assert_eq!(bare.post("/v1/config", config).await.0, 200);
    let expires_ms = bare.node.now_ms() + 3_600_000;
    let credentials = crate::testing::log_credentials(expires_ms);
    assert_eq!(
        bare.post("/v1/log-store/credentials", credentials).await.0,
        200
    );
    let app = App::new(USER, 1);
    app.grant(&bare).await;
    let (status, handed) = handoff(&bare, &bearer_record(&app, VALUE), &peer, &request).await;
    assert_eq!(status, 200, "{handed}");

    // A node of the forward role answers no call of the delegation role, this one included.
    let outcome = handoff(&forward, &record, &peer, &request).await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
}

#[tokio::test]
async fn no_envelope_leaves_before_the_log_store_confirmed_the_entry_of_the_use() {
    // The store answers every write with the status the cell holds, 200 when it is 0.
    let status = Arc::new(AtomicU16::new(0));
    let answered = status.clone();
    let provider = Provider::start(&[SITE, LOG_HOST], move |seen| {
        match (
            seen.server_name == LOG_HOST,
            answered.load(Ordering::SeqCst),
        ) {
            (false, _) => Reply::json(200, &json!({"ok": true})),
            (true, 0) => Reply::with_body(200, &[("etag", "\"0\""), ("connection", "close")], b""),
            (true, status) => {
                Reply::with_body(status, &[("connection", "close")], b"<Error></Error>")
            }
        }
    })
    .await;
    // A node that writes every entry once: a time limit of a write below the margin of a
    // repeated attempt.
    let limits = Limits {
        log_write: Duration::from_millis(450),
        ..Limits::default()
    };
    let giving = Harness::with(&provider, Definitions::embedded(), limits);
    giving.use_log_store().await;
    let app = App::new(USER, 1);
    app.grant(&giving).await;
    let forward = forward_node(&provider).await;
    let peer = attestation(&forward).await;
    let record = bearer_record(&app, VALUE);
    let request = bearer_request();

    // The store refuses the write: the call ends without an envelope, and the event stays on
    // the chain as the event of a use that did not take place.
    status.store(503, Ordering::SeqCst);
    let outcome = handoff(&giving, &record, &peer, &request).await;
    assert_eq!(code(&outcome), (503, "log_store_unavailable"));
    assert_eq!(outcome.1.as_object().unwrap().len(), 2);
    assert_eq!(giving.last_seq(USER), 2);
    let account = giving.node.account(USER).unwrap();
    assert_eq!(lock(&account).pending_entries(), 1);

    // The store confirms again: the next call writes the entry that waited and its own, in
    // their order, and hands its envelope over.
    status.store(0, Ordering::SeqCst);
    let (status_code, handed) = handoff(&giving, &record, &peer, &request).await;
    assert_eq!(status_code, 200, "{handed}");
    assert_eq!(handed["log"]["seq"], 3);
    assert_eq!(lock(&account).pending_entries(), 0);
    let chain = app.stored_events(&giving, &provider);
    assert_eq!(chain.len(), 3);
    assert!(chain[1..]
        .iter()
        .all(|events| events.len() == 1 && events[0]["t"] == "provider_request"));
}

#[tokio::test]
async fn the_entries_of_the_vault_calls_verify_against_their_keys_in_the_bucket_of_the_account() {
    let provider = quiet_site().await;
    let (giving, app) = giving_node(&provider).await;
    let forward = forward_node(&provider).await;
    let peer = attestation(&forward).await;

    // The three calls of the vault that create an event, each once: `vault/store` makes a
    // record, `release` hands its value out, and `vault/handoff` seals the value of a record
    // of the device for one request.
    let stored = json!({
        "user_id": USER, "name": "SIGNUP_PASSWORD", "sites": ["shop.example"],
        "slots": ["field"], "value": "tr0ub4dor&3", "context": "agent:signup",
    });
    let (status, made) = giving.post("/v1/vault/store", stored).await;
    assert_eq!(status, 200, "{made}");
    let release = json!({
        "user_id": USER, "record": made["record"], "field": "value",
        "origin": "https://shop.example", "context": "browser:fill",
    });
    let (status, released) = giving.post("/v1/release", release).await;
    assert_eq!((status, &released["value"]), (200, &json!("tr0ub4dor&3")));
    let record = bearer_record(&app, VALUE);
    let (status, handed) = handoff(&giving, &record, &peer, &bearer_request()).await;
    assert_eq!(status, 200, "{handed}");
    assert_eq!(
        (
            &made["log"]["seq"],
            &released["log"]["seq"],
            &handed["log"]["seq"]
        ),
        (&json!(2), &json!(3), &json!(4))
    );

    // The store holds one object per entry, in the bucket of the account. A control entry is
    // under the prefix of the control entries and its key names its event, and a use entry is
    // under the prefix of the use entries and its key carries the number of its events.
    let chain = provider.chain(USER, &giving.node.node);
    let labels: Vec<EntryLabel> = chain
        .iter()
        .map(|stored| stored.parts().label.clone())
        .collect();
    assert_eq!(
        labels,
        [
            EntryLabel::Control("grant_accepted".to_string()),
            EntryLabel::Control("connection_created".to_string()),
            EntryLabel::Use(1),
            EntryLabel::Use(1),
        ]
    );
    let bucket = giving
        .node
        .log_store
        .id()
        .unwrap()
        .shard_of(shard_hash(USER))
        .unwrap();
    let mut prev = b64u(&[0u8; 32]);
    let mut events = Vec::new();
    for stored in &chain {
        let prefix = match stored.parts().label {
            EntryLabel::Control(_) => format!("a3/{USER}/c/"),
            EntryLabel::Use(_) => format!("a3/{USER}/u/"),
        };
        assert!(stored.key.starts_with(&prefix), "{}", stored.key);
        assert_eq!(stored.key, object_key_v3(USER, stored.parts()));
        assert_eq!(stored.bucket, bucket);
        // The object is the entry its key names, signed by the node of the key, and it opens
        // with the log key of the account. Its body carries the hash of the body before it.
        let entry: Signed = serde_json::from_value(stored.entry.clone()).unwrap();
        let (body, body_bytes) = verify_entry_v3(USER, stored.parts(), &entry).unwrap();
        assert_eq!((body.v, &body.prev), (3, &prev));
        let opened = open_entry_v3(&app.keys.log, &body_bytes).unwrap();
        assert_eq!(opened.len(), 1);
        events.push(opened[0].clone());
        prev = b64u(&stored.parts().body_hash);
    }
    let named = |event: &Value| {
        (
            event["t"].as_str().unwrap().to_string(),
            event["name"].as_str().unwrap_or_default().to_string(),
        )
    };
    assert_eq!(
        events.iter().map(named).collect::<Vec<_>>(),
        [
            ("grant_accepted".to_string(), String::new()),
            (
                "connection_created".to_string(),
                "SIGNUP_PASSWORD".to_string()
            ),
            ("secret_released".to_string(), "SIGNUP_PASSWORD".to_string()),
            ("provider_request".to_string(), NAME.to_string()),
        ]
    );
    assert_eq!(
        (&events[3]["slot"], &events[3]["to"]),
        (
            &json!("header:authorization"),
            &json!(forward.node.node.as_str())
        )
    );

    // The store holds the node document of the node that wrote the entries, and none of the
    // node of the forward role: that node has no log store and wrote nothing to one.
    let documents: Vec<String> = provider
        .documents()
        .into_iter()
        .map(|document| document.node)
        .collect();
    assert_eq!(documents, std::slice::from_ref(&giving.node.node));
    assert!(forward
        .platform
        .connections()
        .iter()
        .all(|(host, _)| host != LOG_HOST));
}

#[tokio::test]
async fn the_vault_calls_create_no_entry_while_the_store_holds_no_node_document_for_it() {
    /// One day in milliseconds.
    const DAY_MS: u64 = 24 * 60 * 60 * 1000;
    // The store confirms every write but, while the cell is set, the write of a node document.
    let documents_refused = Arc::new(AtomicBool::new(false));
    let refused = documents_refused.clone();
    let provider = Provider::start(&[SITE, LOG_HOST], move |seen| {
        let of_a_document = seen.server_name == LOG_HOST && seen.target.contains("/n3/");
        match of_a_document && refused.load(Ordering::SeqCst) {
            true => Reply::with_body(403, &[("connection", "close")], b"<Error></Error>"),
            false => Reply::json(200, &json!({"ok": true})),
        }
    })
    .await;
    let (giving, app) = giving_node(&provider).await;
    let forward = forward_node(&provider).await;
    let peer = attestation(&forward).await;
    let record = bearer_record(&app, VALUE);
    let for_a_field = named(&app, json!(["shop.example"]), json!(["field"]), VALUE);
    let stored = json!({
        "user_id": USER, "name": NAME, "sites": [SITE], "slots": ["header:authorization"],
        "value": VALUE, "context": CONTEXT,
    });
    let release = json!({
        "user_id": USER, "record": for_a_field, "field": "value",
        "origin": "https://shop.example", "context": CONTEXT,
    });

    // 29 days after the node wrote its node document the account renews its grant, which
    // then outlives the time the node acts on that document. From here on the store refuses
    // the document.
    documents_refused.store(true, Ordering::SeqCst);
    giving.node.clock.advance(29 * DAY_MS);
    giving.use_log_store().await;
    app.grant(&giving).await;

    // 31 days after that write the store holds no version of the document that outlives an
    // entry written now. The grant is in force, and each of the three calls ends with
    // `log_store_unavailable` before it creates an event: no record, no value and no
    // envelope leaves, and the account has the one entry of its grant.
    giving.node.clock.advance(2 * DAY_MS);
    giving.use_log_store().await;
    let status = json!({"user_id": USER});
    assert_eq!(
        giving.post("/v1/status", status).await.1["grant"]["state"],
        "active"
    );
    let outcomes = [
        giving.post("/v1/vault/store", stored.clone()).await,
        giving.post("/v1/release", release.clone()).await,
        handoff(&giving, &record, &peer, &bearer_request()).await,
    ];
    for outcome in &outcomes {
        assert_eq!(code(outcome), (503, "log_store_unavailable"));
        assert_eq!(outcome.1.as_object().unwrap().len(), 2);
    }
    assert_eq!(giving.last_seq(USER), 1);
    let account = giving.node.account(USER).unwrap();
    assert_eq!(lock(&account).pending_entries(), 0);
    assert_eq!(provider.stored().len(), 1);

    // The store takes the document again and the sweep of the node writes it: the three calls
    // create their events and act.
    documents_refused.store(false, Ordering::SeqCst);
    crate::log_store::sweep(&giving.node).await;
    let (status, made) = giving.post("/v1/vault/store", stored).await;
    assert_eq!((status, &made["log"]["seq"]), (200, &json!(2)), "{made}");
    let (status, released) = giving.post("/v1/release", release).await;
    assert_eq!((status, &released["value"]), (200, &json!(VALUE)));
    let (status, handed) = handoff(&giving, &record, &peer, &bearer_request()).await;
    assert_eq!(
        (status, &handed["log"]["seq"]),
        (200, &json!(4)),
        "{handed}"
    );
    assert_eq!(provider.stored().len(), 4);
}

/// The time of one `vault/handoff` call and of its parts, as the nodes of these tests take it:
/// the calls go to the router of a node in the same process, and the log store and the site
/// are stand-ins on the loopback interface, so no time of a network is in the numbers. The
/// test asserts nothing about them. Run it with
/// `cargo test --release -p credential-enclave -- --ignored vault_handoff_timing --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "timing probe of vault/handoff: prints the time of a call and of its parts"]
#[expect(
    clippy::print_stdout,
    reason = "The opt-in probe emits only fixture timings"
)]
async fn vault_handoff_timing_probe() {
    use std::time::Instant;

    use credential_enclave_protocol::keys::NodeKeys;
    use credential_enclave_protocol::record::{open_record, Record};
    use credential_enclave_protocol::secret::Secret;
    use credential_enclave_protocol::secret_use::seal_secret_use;

    const ROUNDS: usize = 2_000;
    const WARM_UP: usize = 200;

    /// The median, the 90th and the 99th percentile and the mean of `times`, in microseconds.
    fn summary(mut times: Vec<Duration>) -> Value {
        times.sort();
        let micros = |time: Duration| (time.as_nanos() as f64 / 100.0).round() / 10.0;
        let at = |percent: usize| micros(times[(times.len() * percent / 100).min(times.len() - 1)]);
        let mean = times.iter().sum::<Duration>() / times.len() as u32;
        json!({"p50_us": at(50), "p90_us": at(90), "p99_us": at(99), "mean_us": micros(mean)})
    }

    // The store and the site keep their connections open, as Amazon S3 does: the node writes
    // every entry over a connection it holds.
    let provider = Provider::start(&[SITE, LOG_HOST], |_| {
        Reply::json(200, &json!({"ok": true})).keep_alive()
    })
    .await;
    let forward = forward_node(&provider).await;
    let peer = attestation(&forward).await;
    let request = bearer_request();
    let mut report = serde_json::Map::new();

    // One call after another for one account, on a node with the log store and on a node
    // that runs without one: the difference is the write of the entry and its confirmation.
    let (with_store, app) = giving_node(&provider).await;
    let without_store = Harness::new(&provider);
    app.grant(&without_store).await;
    let record = bearer_record(&app, VALUE);
    for (name, giving) in [
        (
            "handoff, entry confirmed by the log store stand-in",
            &with_store,
        ),
        ("handoff, node without a log store", &without_store),
    ] {
        let mut times = Vec::with_capacity(ROUNDS);
        for round in 0..WARM_UP + ROUNDS {
            let started = Instant::now();
            let (status, handed) = handoff(giving, &record, &peer, &request).await;
            let elapsed = started.elapsed();
            assert_eq!(status, 200, "{handed}");
            if round >= WARM_UP {
                times.push(elapsed);
            }
        }
        report.insert(name.to_string(), summary(times));
    }

    // `release` of a value of the same account on the same node, for comparison: the same
    // front, one event and one confirmed entry, and no seal.
    let for_a_field = named(&app, json!([SITE]), json!(["field"]), VALUE);
    let release = json!({
        "user_id": USER, "record": for_a_field, "field": "value",
        "origin": format!("https://{SITE}"), "context": CONTEXT,
    });
    let mut times = Vec::with_capacity(ROUNDS);
    for round in 0..WARM_UP + ROUNDS {
        let started = Instant::now();
        let (status, released) = with_store.post("/v1/release", release.clone()).await;
        let elapsed = started.elapsed();
        assert_eq!(status, 200, "{released}");
        if round >= WARM_UP {
            times.push(elapsed);
        }
    }
    report.insert(
        "release, entry confirmed by the log store stand-in".to_string(),
        summary(times),
    );

    // The two calls of one use, one after the other: the handoff, and the request the node
    // of the forward role sends over a connection of its own, without a body.
    let (mut handoffs, mut sends) = (Vec::new(), Vec::new());
    for round in 0..WARM_UP + ROUNDS {
        let started = Instant::now();
        let (status, handed) = handoff(&with_store, &record, &peer, &request).await;
        let handed_after = started.elapsed();
        assert_eq!(status, 200, "{handed}");
        let meta = json!({
            "envelope": handed["envelope"],
            "headers": [["authorization", format!("Bearer {PLACEHOLDER}")]],
        });
        let started = Instant::now();
        let sent = forward.vault_send(meta, b"").await;
        let sent_after = started.elapsed();
        assert_eq!(sent.map(|sent| sent.status), Ok(200));
        if round >= WARM_UP {
            handoffs.push(handed_after);
            sends.push(sent_after);
        }
    }
    report.insert("one use: handoff".to_string(), summary(handoffs));
    report.insert("one use: send, no body".to_string(), summary(sends));

    // Calls of 32 accounts at the same time, each account one call after another: the calls
    // of one node that do not wait for each other.
    let accounts: Vec<(App, Value)> = (0..32u8)
        .map(|index| {
            let app = App::new(&format!("probe-{index}"), 100 + index);
            let record = bearer_record(&app, VALUE);
            (app, record)
        })
        .collect();
    for (app, _) in &accounts {
        app.grant(&with_store).await;
    }
    let started = Instant::now();
    let each = 200;
    let runs = accounts.iter().map(|(app, record)| {
        let (giving, peer, request) = (&with_store, &peer, &request);
        async move {
            for _ in 0..each {
                let mut body = body_of(record, peer, request);
                body["user_id"] = json!(app.user_id);
                let (status, handed) = giving.post("/v1/vault/handoff", body).await;
                assert_eq!(status, 200, "{handed}");
            }
        }
    });
    crate::log_store::join_all(runs).await;
    let elapsed = started.elapsed();
    let calls = (accounts.len() * each) as f64;
    report.insert(
        "32 accounts at once".to_string(),
        json!({
            "calls": calls,
            "calls_per_second": (calls / elapsed.as_secs_f64()).round(),
            "mean_us_per_call": (elapsed.as_micros() as f64 / calls * 10.0).round() / 10.0,
        }),
    );

    // The parts that are the same on every platform, each alone: the opening of the record
    // and the signed seal of the envelope.
    let opened_record = Record::from_value(&record).unwrap();
    let user_key = app.keys.user_key_of(app.custody);
    let started = Instant::now();
    for _ in 0..ROUNDS {
        open_record(user_key, &opened_record).unwrap();
    }
    let open_us = started.elapsed().as_micros() as f64 / ROUNDS as f64;
    let (giving_keys, receiving_keys) = (
        NodeKeys::from_random(&[0x11; 32], &[0x12; 32]),
        NodeKeys::from_random(&[0x21; 32], &[0x22; 32]),
    );
    let bound = BoundRequest::from_value(&request).unwrap();
    let value = Secret::new(VALUE.to_string());
    let started = Instant::now();
    for round in 0..ROUNDS {
        seal_secret_use(
            &giving_keys,
            &receiving_keys.sign_public(),
            &receiving_keys.seal_public(),
            1_800_000_000_000,
            &[round as u8; 16],
            USER,
            opened_record.id.as_str(),
            &value,
            &bound,
            &Secret::new([round as u8; 32]),
        )
        .unwrap();
    }
    let seal_us = started.elapsed().as_micros() as f64 / ROUNDS as f64;
    report.insert(
        "parts alone".to_string(),
        json!({
            "open the record, mean_us": (open_us * 10.0).round() / 10.0,
            "sign and seal the envelope, mean_us": (seal_us * 10.0).round() / 10.0,
        }),
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&Value::Object(report)).unwrap()
    );
}
