//! The log store (protocol.md 7.6, enclave.md 5.14): a node writes an entry to the store before
//! the act the entry describes, and acts only after the store confirmed it.
//!
//! A stand-in plays Amazon S3 for the host of the log store, next to the providers: the same
//! TLS server, so the order in which its requests arrived is the order in which the node made
//! them.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use credential_enclave_protocol::encoding::{b64u, b64u_decode, to_json};
use credential_enclave_protocol::keys::Custody;
use credential_enclave_protocol::log::entry_hash;
use credential_enclave_protocol::{limits, purpose};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::provider_and_log_store;
use crate::log_store::PENDING_ENTRIES;
use crate::platform::Measurement;
use crate::providers::Definitions;
use crate::state::{lock, Limits};
use crate::testing::{
    log_credentials, operator_config, App, Harness, Provider, Reply, Seen, LOG_BUCKET, LOG_HOST,
    LOG_REGION, LOG_SECRET_ACCESS_KEY, LOG_SESSION_TOKEN,
};

const MESSAGES: &str = "https://gmail.googleapis.com/gmail/v1/users/me/messages";

/// What the stand-in of the log store does with a write.
#[derive(Default)]
struct Script {
    /// The status of every answer, 200 when it is 0.
    status: u16,
    /// Parts of request targets: a write whose target holds one of them is answered with 503.
    refused: Vec<String>,
    /// The stand-in answers no write.
    silent: bool,
    /// The stand-in answers a write after this pause.
    pause: Duration,
}

type Store = Arc<Mutex<Script>>;

fn refuse(store: &Store, status: u16) {
    lock(store).status = status;
}

fn confirm(store: &Store) {
    *lock(store) = Script::default();
}

/// The part of the key of the entry `seq` that names it.
fn seq_part(seq: u64) -> String {
    format!("/{seq:020}-")
}

/// The token response of the stand-in.
fn tokens() -> Value {
    json!({
        "access_token": "ya29.second-access", "expires_in": 3599, "token_type": "Bearer",
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
        "refresh_token": "1//second-refresh",
    })
}

/// A stand-in for the providers and for the log store. The providers answer a token request
/// with [`tokens`] and every other request with `200 {"ok":true}`. The log store confirms a
/// write unless its script says otherwise.
async fn stand_in() -> (Provider, Store) {
    let store: Store = Arc::default();
    let script = store.clone();
    let provider = provider_and_log_store(
        |seen| match seen.target.as_str() {
            "/token" => Reply::json(200, &tokens()),
            _ => Reply::json(200, &json!({"ok": true})),
        },
        move |seen| {
            let script = lock(&script);
            if script.silent {
                return Reply::Hang;
            }
            let refused = script.refused.iter().any(|part| seen.target.contains(part));
            let reply = match (refused, script.status) {
                (true, _) => Reply::with_body(503, &[], b"<Error><Code>SlowDown</Code></Error>"),
                (false, 0 | 200) => Reply::with_body(
                    200,
                    &[("etag", "\"0\""), ("x-amz-version-id", "version")],
                    b"",
                ),
                (false, status) => Reply::with_body(status, &[], b"<Error></Error>"),
            };
            match script.pause.is_zero() {
                true => reply,
                false => reply.after(script.pause),
            }
        },
    )
    .await;
    (provider, store)
}

/// A node of the local platform with the log store of the tests, and the app of an account
/// that granted on it.
async fn node_with_log_store(provider: &Provider) -> (Harness, App) {
    let harness = Harness::new(provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    (harness, app)
}

/// The writes the log store received, in the order they arrived.
fn writes(provider: &Provider) -> Vec<Seen> {
    let to_the_store = |seen: &Seen| seen.server_name == LOG_HOST;
    provider.seen().into_iter().filter(to_the_store).collect()
}

/// The requests the providers received, in the order they arrived.
fn provider_requests(provider: &Provider) -> Vec<Seen> {
    let to_a_provider = |seen: &Seen| seen.server_name != LOG_HOST;
    provider.seen().into_iter().filter(to_a_provider).collect()
}

/// The request target of the object of an entry: the key of protocol.md 7.6, read from the
/// body of the entry.
fn target_of(harness: &Harness, entry: &Value) -> String {
    let body = b64u_decode(entry["body"].as_str().unwrap()).unwrap();
    let fields: Value = serde_json::from_slice(&body).unwrap();
    format!(
        "/v1/accounts/{}/{}/{:020}-{}",
        fields["user_id"].as_str().unwrap(),
        harness.node.node,
        fields["seq"].as_u64().unwrap(),
        b64u(&entry_hash(&body))
    )
}

/// The `seq` in the target of a write.
fn seq_of(write: &Seen) -> u64 {
    let name = write.target.rsplit('/').next().unwrap();
    name.split('-').next().unwrap().parse().unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// The signature the request should carry, computed from the request as it arrived: AWS
/// Signature Version 4 over the method, the target, the headers its `Authorization` header
/// names and the hash of its body, with the secret access key of the tests.
fn signature_of(write: &Seen) -> String {
    let authorization = write.header("authorization").unwrap();
    let named = authorization.split("SignedHeaders=").nth(1).unwrap();
    let names = named.split(',').next().unwrap();
    let mut canonical = format!("{}\n{}\n\n", write.method, write.target);
    for name in names.split(';') {
        canonical.push_str(&format!("{name}:{}\n", write.header(name).unwrap()));
    }
    canonical.push_str(&format!("\n{names}\n{}", hex(&Sha256::digest(&write.body))));
    let amz_date = write.header("x-amz-date").unwrap();
    let date = &amz_date[..8];
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{date}/{LOG_REGION}/s3/aws4_request\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let mut key = hmac(
        format!("AWS4{LOG_SECRET_ACCESS_KEY}").as_bytes(),
        date.as_bytes(),
    );
    for part in [LOG_REGION, "s3", "aws4_request"] {
        key = hmac(&key, part.as_bytes());
    }
    hex(&hmac(&key, to_sign.as_bytes()))
}

/// Asserts that `write` is the write of `entry` in the form of protocol.md 7.6.
fn assert_write_of(harness: &Harness, write: &Seen, entry: &Value) {
    assert_eq!(write.method, "PUT");
    assert_eq!(write.server_name, LOG_HOST);
    assert_eq!(write.target, target_of(harness, entry));
    // The object is the entry as the response of the call carries it.
    assert_eq!(write.body, to_json(entry));
    let digest = Sha256::digest(&write.body);
    assert_eq!(
        write.header_names(),
        [
            "content-length",
            "content-type",
            "host",
            "x-amz-checksum-sha256",
            "x-amz-content-sha256",
            "x-amz-date",
            "x-amz-object-lock-mode",
            "x-amz-object-lock-retain-until-date",
            "x-amz-security-token",
            "authorization",
            "connection",
        ]
    );
    assert_eq!(write.header("content-type"), Some("application/json"));
    assert_eq!(write.header("host"), Some(LOG_HOST));
    assert_eq!(
        write.header("x-amz-checksum-sha256"),
        Some(STANDARD.encode(digest).as_str())
    );
    assert_eq!(
        write.header("x-amz-content-sha256"),
        Some(hex(&digest).as_str())
    );
    assert_eq!(write.header("x-amz-object-lock-mode"), Some("COMPLIANCE"));
    assert_eq!(
        write.header("x-amz-security-token"),
        Some(LOG_SESSION_TOKEN)
    );
    assert_eq!(write.header("connection"), Some("close"));
    // The retention ends 365 days after the write: the same day and time one year later,
    // or the day before it when a leap day lies in between.
    let amz_date = write.header("x-amz-date").unwrap();
    let until = write.header("x-amz-object-lock-retain-until-date").unwrap();
    assert_eq!((amz_date.len(), until.len()), (16, 20));
    let year: u32 = amz_date[..4].parse().unwrap();
    assert_eq!(until[..4].parse::<u32>().unwrap(), year + 1);
    assert_eq!(
        &until[11..],
        format!(
            "{}:{}:{}Z",
            &amz_date[9..11],
            &amz_date[11..13],
            &amz_date[13..15]
        )
    );
    // The request is signed with the credentials the node was given, over every header it
    // carries but the length of its body and the header of the connection.
    let authorization = write.header("authorization").unwrap();
    assert_eq!(
        authorization,
        format!(
            concat!(
                "AWS4-HMAC-SHA256 Credential=ASIATESTACCESSKEYID/{}/{}/s3/aws4_request,",
                "SignedHeaders=content-type;host;x-amz-checksum-sha256;x-amz-content-sha256;",
                "x-amz-date;x-amz-object-lock-mode;x-amz-object-lock-retain-until-date;",
                "x-amz-security-token,Signature={}"
            ),
            &amz_date[..8],
            LOG_REGION,
            signature_of(write)
        )
    );
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

fn get(app: &App, record: &Value, url: &str) -> Value {
    json!({
        "user_id": app.user_id, "record": record, "method": "GET", "url": url,
        "headers": [], "context": "cli:gog", "timeout_ms": 5000,
    })
}

async fn refresh(harness: &Harness, app: &App, record: &Value) -> (u16, Value) {
    let body = json!({"user_id": app.user_id, "record": record, "context": "refresh:scheduled"});
    harness.post("/v1/refresh", body).await
}

async fn revoke_token(harness: &Harness, app: &App, record: &Value) -> (u16, Value) {
    let body = json!({"user_id": app.user_id, "record": record, "context": "disconnect"});
    harness.post("/v1/revoke-token", body).await
}

async fn release(harness: &Harness, app: &App, record: &Value) -> (u16, Value) {
    let body = json!({
        "user_id": app.user_id, "record": record, "field": "password",
        "origin": "https://site.example", "context": "browser:fill",
    });
    harness.post("/v1/release", body).await
}

fn password(app: &App) -> Value {
    app.record("vault_password", "vault", &json!({"value": "hunter2"}))
}

/// Begins an authorization of `google_workspace` and returns its state.
async fn begin(harness: &Harness, app: &App) -> String {
    let body = json!({
        "user_id": app.user_id, "provider": "google_workspace", "operator_state": "o",
        "params": {"scope": "https://www.googleapis.com/auth/gmail.readonly"},
    });
    let (status, begun) = harness.post("/v1/oauth/begin", body).await;
    assert_eq!(status, 200, "{begun}");
    begun["state"].as_str().unwrap().to_string()
}

async fn complete(harness: &Harness, app: &App, state: &str) -> (u16, Value) {
    let body = json!({"user_id": app.user_id, "state": state, "code": "4/authorization-code"});
    harness.post("/v1/oauth/complete", body).await
}

fn code(outcome: &(u16, Value)) -> (u16, &str) {
    (outcome.0, outcome.1["code"].as_str().unwrap_or_default())
}

fn unavailable(outcome: &(u16, Value)) {
    assert_eq!(
        code(outcome),
        (503, "log_store_unavailable"),
        "{}",
        outcome.1
    );
}

/// The entries of an account that wait for their storage acknowledgement, after `after_seq`.
async fn entries_after(harness: &Harness, user_id: &str, after_seq: u64) -> Vec<Value> {
    let body = json!({"user_id": user_id, "after_seq": after_seq});
    let (status, listed) = harness.post("/v1/log/entries", body).await;
    assert_eq!(status, 200);
    listed["entries"].as_array().unwrap().clone()
}

/// The attestation response of a node, as the operator domain fetches it for another node.
async fn attestation(harness: &Harness) -> Value {
    let (status, response) = harness
        .post("/v1/attestation", json!({"nonce": b64u(&[9u8; 32])}))
        .await;
    assert_eq!(status, 200);
    response
}

async fn export(giving: &Harness, peer: &Value) -> (u16, Value) {
    giving.post("/v1/peer/export", json!({"peer": peer})).await
}

async fn import(receiving: &Harness, peer: &Value, envelope: &Value) -> (u16, Value) {
    let body = json!({"peer": peer, "envelope": envelope});
    receiving.post("/v1/peer/import", body).await
}

#[tokio::test]
async fn the_log_store_confirms_the_entry_before_the_provider_is_called() {
    let (provider, _store) = stand_in().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let record = google_record(&app);

    // The grant: its entry is in the store before the node answers.
    let granted = entries_after(&harness, "user-1", 0).await;
    assert_eq!(writes(&provider).len(), 1);
    assert_write_of(&harness, &writes(&provider)[0], &granted[0]);
    assert!(provider_requests(&provider).is_empty());

    // forward: the write of the entry arrives, then the request to the provider.
    let forwarded = harness
        .forward(get(&app, &record, MESSAGES), b"")
        .await
        .unwrap();
    let seen = provider.seen();
    assert_eq!(seen.len(), 3);
    assert_write_of(&harness, &seen[1], &forwarded.entry);
    assert_eq!(seen[2].server_name, "gmail.googleapis.com");
    assert_eq!(seen[2].target, "/gmail/v1/users/me/messages");

    // refresh: the write, then the call of the token address.
    let (status, refreshed) = refresh(&harness, &app, &record).await;
    assert_eq!(status, 200, "{refreshed}");
    let seen = provider.seen();
    assert_eq!(seen.len(), 5);
    assert_write_of(&harness, &seen[3], &refreshed["entry"]);
    assert_eq!(
        (seen[4].server_name.as_str(), seen[4].target.as_str()),
        ("oauth2.googleapis.com", "/token")
    );

    // revoke-token: the write, then the call of the revocation address.
    let (status, revoked) = revoke_token(&harness, &app, &record).await;
    assert_eq!((status, &revoked["revoked"]), (200, &json!(true)));
    let seen = provider.seen();
    assert_eq!(seen.len(), 7);
    assert_write_of(&harness, &seen[5], &revoked["entry"]);
    assert_eq!(seen[6].target, "/revoke");

    // release: the write, then the value in the response.
    let (status, released) = release(&harness, &app, &password(&app)).await;
    assert_eq!((status, &released["value"]), (200, &json!("hunter2")));
    let seen = provider.seen();
    assert_eq!(seen.len(), 8);
    assert_write_of(&harness, &seen[7], &released["entry"]);

    // oauth/complete: the code is exchanged first, then the entry is written, and the record
    // leaves after that.
    let state = begin(&harness, &app).await;
    let (status, completed) = complete(&harness, &app, &state).await;
    assert_eq!(status, 200, "{completed}");
    let seen = provider.seen();
    assert_eq!(seen.len(), 10);
    assert_eq!(seen[8].target, "/token");
    assert_write_of(&harness, &seen[9], &completed["entry"]);
    assert_eq!(
        app.open(&completed["record"])["token"]["access_token"],
        "ya29.second-access"
    );

    // Every entry of the chain is in the store, each once, under the key of its `seq`.
    let seqs: Vec<u64> = writes(&provider).iter().map(seq_of).collect();
    assert_eq!(seqs, [1, 2, 3, 4, 5, 6]);
    assert_eq!(harness.head_seq("user-1"), 6);
    let health = harness.health().await;
    assert_eq!(health["log_store"]["pending"], 0);
    // The credentials reached the store and nothing else.
    for request in provider_requests(&provider) {
        let wire = format!(
            "{:?} {:?}",
            request.headers,
            String::from_utf8_lossy(&request.body)
        );
        assert!(!wire.contains(LOG_SESSION_TOKEN) && !wire.contains(LOG_SECRET_ACCESS_KEY));
    }
    for write in writes(&provider) {
        let wire = format!(
            "{:?} {:?}",
            write.headers,
            String::from_utf8_lossy(&write.body)
        );
        assert!(!wire.contains(LOG_SECRET_ACCESS_KEY));
    }
}

#[tokio::test]
async fn a_write_the_store_does_not_confirm_stops_the_act() {
    let (provider, store) = stand_in().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let record = google_record(&app);
    let state = begin(&harness, &app).await;
    refuse(&store, 500);

    // forward: no request reaches the provider.
    let outcome = harness.forward(get(&app, &record, MESSAGES), b"").await;
    unavailable(&outcome.err().unwrap());
    // refresh and revoke-token: the token address and the revocation address are not called.
    unavailable(&refresh(&harness, &app, &record).await);
    unavailable(&revoke_token(&harness, &app, &record).await);
    assert!(provider_requests(&provider).is_empty());
    // release: the value does not leave.
    let outcome = release(&harness, &app, &password(&app)).await;
    unavailable(&outcome);
    assert!(!outcome.1.to_string().contains("hunter2"));
    // oauth/complete: the code was exchanged, and the record does not leave.
    let outcome = complete(&harness, &app, &state).await;
    unavailable(&outcome);
    assert_eq!(outcome.1.as_object().unwrap().len(), 2);
    let exchanged = provider_requests(&provider);
    assert_eq!(exchanged.len(), 1);
    assert_eq!(exchanged[0].target, "/token");

    // Each call left its entry on the chain: the caller fetches them, and they wait for the
    // store.
    assert_eq!(harness.head_seq("user-1"), 6);
    let kinds: Vec<Value> = entries_after(&harness, "user-1", 1)
        .await
        .iter()
        .map(|entry| app.event(&harness, entry)["t"].clone())
        .collect();
    assert_eq!(
        kinds,
        [
            "provider_request",
            "credential_refreshed",
            "connection_removed",
            "secret_released",
            "connection_created"
        ]
    );
    let health = harness.health().await;
    assert_eq!(health["log_store"]["pending"], 1);
    let account = harness.node.account("user-1").unwrap();
    assert_eq!(lock(&account).pending_entries(), 5);

    // A status that says that an object of the key exists is no confirmation either: the
    // node does not ask for it, and it does not take it.
    refuse(&store, 412);
    let outcome = harness.forward(get(&app, &record, MESSAGES), b"").await;
    unavailable(&outcome.err().unwrap());
    for write in writes(&provider) {
        assert_eq!(write.header("if-none-match"), None);
    }
    for status in [201, 204, 301, 403, 409] {
        refuse(&store, status);
        unavailable(&release(&harness, &app, &password(&app)).await);
    }
    assert!(provider_requests(&provider).len() == 1);
}

#[tokio::test]
async fn a_store_that_cannot_be_reached_or_does_not_answer_stops_the_act() {
    // A stand-in for the providers only: the platform has no way to the host of the log
    // store, as when the host program or the network refuses the connection.
    let provider = super::quiet_provider().await;
    let harness = Harness::new(&provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    let attested = app.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let response = app
        .send(&harness, app.grant_envelope(&attested, not_after_ms))
        .await;
    let reply = harness.verified(purpose::REPLY, &response["reply"]);
    assert_eq!(reply["code"], "log_store_unavailable");
    assert_eq!(
        harness.platform.connections(),
        [(LOG_HOST.to_string(), 443)]
    );

    // A store that takes the connection and never answers: the write ends at its time limit.
    let (provider, store) = stand_in().await;
    let harness = Harness::with(
        &provider,
        Definitions::embedded(),
        Limits {
            log_write: Duration::from_millis(300),
            ..Limits::default()
        },
    );
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    lock(&store).silent = true;
    let started = std::time::Instant::now();
    unavailable(&release(&harness, &app, &password(&app)).await);
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(300) && waited < Duration::from_secs(3));
    assert!(provider_requests(&provider).is_empty());
}

#[tokio::test]
async fn a_pending_entry_is_written_again_with_the_next_write_of_the_account() {
    let (provider, store) = stand_in().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let vault = password(&app);

    // Two releases fail: entries 2 and 3 are pending.
    refuse(&store, 500);
    unavailable(&release(&harness, &app, &vault).await);
    unavailable(&release(&harness, &app, &vault).await);
    assert_eq!(harness.health().await["log_store"]["pending"], 1);
    let before = writes(&provider).len();

    // The next call writes its own entry and the two pending ones, and all three are
    // confirmed.
    confirm(&store);
    let (status, released) = release(&harness, &app, &vault).await;
    assert_eq!(status, 200);
    assert_eq!(app.entry_body(&harness, &released["entry"])["seq"], 4);
    let written = writes(&provider)[before..].to_vec();
    let mut seqs: Vec<u64> = written.iter().map(seq_of).collect();
    seqs.sort();
    assert_eq!(seqs, [2, 3, 4]);
    // What is written again is the entry that was created then, under its own key.
    let pending = entries_after(&harness, "user-1", 1).await;
    for write in &written {
        let entry = &pending[seq_of(write) as usize - 2];
        assert_write_of(&harness, write, entry);
    }
    assert_eq!(harness.health().await["log_store"]["pending"], 0);
    let account = harness.node.account("user-1").unwrap();
    assert!(lock(&account).unconfirmed.is_empty());

    // A pending entry that the store still refuses does not fail the call that took it along.
    refuse(&store, 500);
    unavailable(&release(&harness, &app, &vault).await);
    *lock(&store) = Script {
        refused: vec![seq_part(5)],
        ..Script::default()
    };
    let (status, released) = release(&harness, &app, &vault).await;
    assert_eq!((status, &released["value"]), (200, &json!("hunter2")));
    assert_eq!(lock(&account).pending_entries(), 1);
    assert_eq!(lock(&account).unconfirmed[0].seq, 5);
    // It is taken along again by the write after that.
    confirm(&store);
    assert_eq!(release(&harness, &app, &vault).await.0, 200);
    assert!(lock(&account).unconfirmed.is_empty());
    let all: Vec<u64> = writes(&provider).iter().map(seq_of).collect();
    assert_eq!(all.iter().filter(|seq| **seq == 5).count(), 3);
}

#[tokio::test]
async fn a_request_that_shares_an_entry_waits_for_the_store_to_confirm_that_entry() {
    let (provider, store) = stand_in().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let record = google_record(&app);

    // The first request fails at the store: its entry, 2, is on the chain and pending.
    refuse(&store, 500);
    let outcome = harness.forward(get(&app, &record, MESSAGES), b"").await;
    unavailable(&outcome.err().unwrap());
    assert_eq!(harness.head_seq("user-1"), 2);

    // The same request again shares that entry. It is not sent while the store refuses the
    // entry, and no second entry is created.
    let outcome = harness.forward(get(&app, &record, MESSAGES), b"").await;
    unavailable(&outcome.err().unwrap());
    assert_eq!(harness.head_seq("user-1"), 2);
    assert!(provider_requests(&provider).is_empty());

    // Once the store takes the entry, the request is sent, without an entry of its own.
    confirm(&store);
    let before = writes(&provider).len();
    let sent = harness
        .forward(get(&app, &record, MESSAGES), b"")
        .await
        .unwrap();
    assert_eq!((sent.status, &sent.entry), (200, &Value::Null));
    assert_eq!(harness.head_seq("user-1"), 2);
    let written = writes(&provider)[before..].to_vec();
    assert_eq!(written.len(), 1);
    assert_write_of(
        &harness,
        &written[0],
        &entries_after(&harness, "user-1", 1).await[0],
    );
    let seen = provider.seen();
    assert_eq!(seen[seen.len() - 2].server_name, LOG_HOST);
    assert_eq!(seen[seen.len() - 1].server_name, "gmail.googleapis.com");

    // A request that shares a confirmed entry writes nothing.
    let before = writes(&provider).len();
    let again = harness
        .forward(get(&app, &record, MESSAGES), b"")
        .await
        .unwrap();
    assert_eq!(again.entry, Value::Null);
    assert_eq!(writes(&provider).len(), before);
    assert_eq!(provider_requests(&provider).len(), 2);
}

#[tokio::test]
async fn a_grant_is_put_in_place_only_after_the_store_confirmed_its_entry() {
    let (provider, store) = stand_in().await;
    let harness = Harness::new(&provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;

    // The store refuses the entry: the reply is a signed refusal, and the node holds no key.
    refuse(&store, 500);
    let attested = app.attest(&harness).await;
    let envelope = app.grant_envelope(&attested, not_after_ms);
    let response = app.send(&harness, envelope.clone()).await;
    let reply = harness.verified(purpose::REPLY, &response["reply"]);
    assert_eq!(
        (&reply["type"], &reply["ok"], &reply["code"]),
        (
            &json!("grant_reply"),
            &json!(false),
            &json!("log_store_unavailable")
        )
    );
    assert_eq!(reply["user_id"], "user-1");
    assert_eq!(reply["challenge"], attested.challenge.as_str());
    assert_eq!(reply["key_id"], app.keys.key_id().as_str());
    assert_eq!(reply["not_after_ms"], 0);
    assert_eq!(response["entry"], Value::Null);
    assert_eq!(response["grant"]["state"], "none");
    assert_eq!(harness.health().await["grants"], 0);
    assert_eq!(
        code(&release(&harness, &app, &password(&app)).await),
        (409, "grant_required")
    );
    // The entry is on the chain, where the reply says the chain ends, and it waits.
    assert_eq!(reply["head"]["seq"], 1);
    let waiting = entries_after(&harness, "user-1", 0).await;
    assert_eq!(app.event(&harness, &waiting[0])["t"], "grant_accepted");
    assert_eq!(harness.health().await["log_store"]["pending"], 1);
    // The challenge of that command is used.
    confirm(&store);
    let response = app.send(&harness, envelope).await;
    let reply = harness.verified(purpose::REPLY, &response["reply"]);
    assert_eq!(reply["code"], "bad_challenge");

    // A grant with a new challenge passes, and the entry that waited is written with it.
    let before = writes(&provider).len();
    let response = app.grant(&harness).await;
    assert_eq!(response["grant"]["state"], "active");
    assert_eq!(app.entry_body(&harness, &response["entry"])["seq"], 2);
    let mut seqs: Vec<u64> = writes(&provider)[before..].iter().map(seq_of).collect();
    seqs.sort();
    assert_eq!(seqs, [1, 2]);
    assert_eq!(harness.health().await["log_store"]["pending"], 0);
}

#[tokio::test]
async fn a_revoke_erases_the_key_whatever_the_store_answers() {
    let (provider, store) = stand_in().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let vault = password(&app);
    assert_eq!(release(&harness, &app, &vault).await.0, 200);

    refuse(&store, 500);
    let response = app.revoke(&harness).await;
    let reply = harness.verified(purpose::REPLY, &response["reply"]);
    assert_eq!(
        (&reply["type"], &reply["ok"], &reply["code"]),
        (&json!("revoke_reply"), &json!(true), &json!(""))
    );
    assert_eq!(
        app.event(&harness, &response["entry"])["t"],
        "grant_revoked"
    );
    assert_eq!(response["grant"]["state"], "revoked");
    assert_eq!(harness.health().await["grants"], 0);
    assert_eq!(
        code(&release(&harness, &app, &vault).await),
        (409, "grant_revoked")
    );
    // The node tried to write the entry, and it waits.
    assert_eq!(seq_of(writes(&provider).last().unwrap()), 3);
    let account = harness.node.account("user-1").unwrap();
    assert_eq!(lock(&account).pending_entries(), 1);
    assert_eq!(harness.health().await["log_store"]["pending"], 1);

    // The next write of the account takes it along: here the entry of a new grant.
    confirm(&store);
    app.grant(&harness).await;
    assert!(lock(&account).unconfirmed.is_empty());
    let last: Vec<u64> = writes(&provider).iter().rev().take(2).map(seq_of).collect();
    assert!(last.contains(&3) && last.contains(&4), "{last:?}");

    // A node without credentials for its log store takes a revoke as well.
    let (status, _) = harness
        .post("/v1/log-store/credentials", log_credentials(1))
        .await;
    assert_eq!(status, 200);
    let before = writes(&provider).len();
    let response = app.revoke(&harness).await;
    let reply = harness.verified(purpose::REPLY, &response["reply"]);
    assert_eq!(reply["ok"], true);
    assert_eq!(response["grant"]["state"], "revoked");
    assert_eq!(writes(&provider).len(), before);
    assert_eq!(lock(&account).pending_entries(), 1);
}

#[tokio::test]
async fn an_export_hands_a_grant_over_only_after_the_store_confirmed_its_entry() {
    let (provider, store) = stand_in().await;
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    old.use_log_store().await;
    new.use_log_store().await;
    let alice = App::new("alice", 1);
    let bob = App::new("bob", 2);
    alice.grant(&old).await;
    bob.grant(&old).await;
    let to = attestation(&new).await;
    let from = attestation(&old).await;

    // The store refuses the entry of bob (his second entry) and takes the one of alice: the
    // call hands no grant over, also not the one of alice.
    lock(&store).refused = vec![format!("/bob/{}{}", old.node.node, seq_part(2))];
    let outcome = export(&old, &to).await;
    unavailable(&outcome);
    assert_eq!(outcome.1.as_object().unwrap().len(), 2);
    assert_eq!((old.head_seq("alice"), old.head_seq("bob")), (2, 2));
    let pending = |user_id: &str| {
        let account = old.node.account(user_id).unwrap();
        let pending = lock(&account).pending_entries();
        pending
    };
    assert_eq!((pending("alice"), pending("bob")), (0, 1));
    assert_eq!(old.health().await["log_store"]["pending"], 1);
    // The entries are on the chains: the caller fetches them.
    let waiting = entries_after(&old, "bob", 1).await;
    assert_eq!(
        bob.event(&old, &waiting[0]),
        json!({"t": "grant_transferred_out", "to": new.node.node})
    );

    // The same call while the store still refuses: no further entry, and no grant.
    unavailable(&export(&old, &to).await);
    assert_eq!((old.head_seq("alice"), old.head_seq("bob")), (2, 2));

    // The next call for the same peer creates no entry: it writes the one that waits again
    // and hands both grants over.
    confirm(&store);
    let before = writes(&provider).len();
    let (status, exported) = export(&old, &to).await;
    assert_eq!(status, 200, "{exported}");
    assert_eq!(exported["entries"], json!([]));
    assert_eq!((old.head_seq("alice"), old.head_seq("bob")), (2, 2));
    let written = writes(&provider)[before..].to_vec();
    assert_eq!(written.len(), 1);
    assert_write_of(&old, &written[0], &waiting[0]);
    assert_eq!(pending("bob"), 0);

    // The receiving node takes both grants. Their entries wait there: it writes them with
    // the next write of each account.
    let before = writes(&provider).len();
    let (status, imported) = import(&new, &from, &exported["envelope"]).await;
    assert_eq!(
        (status, &imported["imported"]),
        (200, &json!(2)),
        "{imported}"
    );
    assert_eq!(writes(&provider).len(), before);
    assert_eq!(new.health().await["log_store"]["pending"], 2);
    let (status, released) = release(&new, &alice, &password(&alice)).await;
    assert_eq!(status, 200, "{released}");
    let written = writes(&provider)[before..].to_vec();
    let mut seqs: Vec<u64> = written.iter().map(seq_of).collect();
    seqs.sort();
    assert_eq!(seqs, [1, 2]);
    for write in &written {
        assert!(write
            .target
            .starts_with(&format!("/v1/accounts/alice/{}/", new.node.node)));
    }
    assert_eq!(new.health().await["log_store"]["pending"], 1);

    // A grant that took the place of the one an entry was made for is not handed over under
    // that entry: the new grant gets its own.
    let third = Harness::new(&provider);
    third.use_log_store().await;
    let to_third = attestation(&third).await;
    refuse(&store, 500);
    unavailable(&export(&old, &to_third).await);
    assert_eq!((old.head_seq("alice"), old.head_seq("bob")), (3, 3));
    confirm(&store);
    alice.grant(&old).await;
    let (status, exported) = export(&old, &to_third).await;
    assert_eq!(status, 200, "{exported}");
    let entries = exported["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(alice.entry_body(&old, &entries[0])["seq"], 5);
    assert_eq!((old.head_seq("alice"), old.head_seq("bob")), (5, 3));

    // A node whose credentials for the log store ended hands nothing over, before an entry
    // is created.
    let fourth = Harness::new(&provider);
    fourth.use_log_store().await;
    let expired = log_credentials(old.node.now_ms());
    assert_eq!(old.post("/v1/log-store/credentials", expired).await.0, 200);
    unavailable(&export(&old, &attestation(&fourth).await).await);
    assert_eq!((old.head_seq("alice"), old.head_seq("bob")), (5, 3));
}

#[tokio::test]
async fn a_peer_that_names_another_log_store_is_no_peer() {
    let (provider, _store) = stand_in().await;
    let with = Harness::new(&provider);
    with.use_log_store().await;
    let without = Harness::new(&provider);
    let other = Harness::new(&provider);
    let mut config = operator_config(&other.node.definitions);
    config["log_store"] = json!({"bucket": "another-bucket", "region": LOG_REGION});
    assert_eq!(other.post("/v1/config", config).await.0, 200);
    let app = App::new("user-1", 1);
    app.grant(&with).await;
    app.grant(&without).await;

    // A node hands nothing to a node that writes elsewhere or nowhere, and takes nothing
    // from one.
    for peer in [&without, &other] {
        let named = attestation(peer).await;
        assert_eq!(code(&export(&with, &named).await), (403, "peer_unverified"));
    }
    assert_eq!(
        code(&export(&without, &attestation(&with).await).await),
        (403, "peer_unverified")
    );
    assert_eq!(with.head_seq("user-1"), 1);
    assert_eq!(without.head_seq("user-1"), 1);
    // The same holds for a transfer a node is offered: the node that made it is judged by
    // its binding.
    let second = Harness::new(&provider);
    let (status, from_without) = export(&without, &attestation(&second).await).await;
    assert_eq!(status, 200, "{from_without}");
    let made_by = attestation(&without).await;
    let outcome = import(&with, &made_by, &from_without["envelope"]).await;
    assert_eq!(code(&outcome), (403, "peer_unverified"));

    // Two nodes of the same log store are peers, and so are two nodes without one.
    let same = Harness::new(&provider);
    same.use_log_store().await;
    let (status, from_with) = export(&with, &attestation(&same).await).await;
    assert_eq!(status, 200, "{from_with}");
    let outcome = import(&same, &attestation(&with).await, &from_with["envelope"]).await;
    assert_eq!((outcome.0, &outcome.1["imported"]), (200, &json!(1)));
    let outcome = import(&second, &made_by, &from_without["envelope"]).await;
    assert_eq!((outcome.0, &outcome.1["imported"]), (200, &json!(1)));
}

#[tokio::test]
async fn a_node_of_the_nitro_platform_does_not_act_without_its_log_store() {
    let (provider, _store) = stand_in().await;
    let measurement = Measurement {
        pcrs: [[0xa0; 48], [0xa1; 48], [0xa2; 48]],
    };
    let harness = Harness::measured(&provider, measurement);
    let (status, _) = harness
        .post("/v1/config", operator_config(&harness.node.definitions))
        .await;
    assert_eq!(status, 200);
    assert_eq!(harness.health().await["log_store"], Value::Null);
    let mut app = App::new("user-1", 1);
    app.custody = Custody::Enclave;
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;

    // Without a log store in its configuration the node takes no grant. The refusal does
    // not use the challenge.
    let attested = app.attest(&harness).await;
    let envelope = app.grant_envelope(&attested, not_after_ms);
    let refused = |response: &Value| {
        let reply = harness.verified(purpose::REPLY, &response["reply"]);
        assert_eq!(
            (&reply["ok"], &reply["code"], &reply["head"]["seq"]),
            (&json!(false), &json!("log_store_unavailable"), &json!(0))
        );
        assert_eq!(response["grant"]["state"], "none");
    };
    refused(&app.send(&harness, envelope.clone()).await);
    // With the log store and without credentials for it: the same.
    let mut config = operator_config(&harness.node.definitions);
    config["log_store"] = json!({"bucket": LOG_BUCKET, "region": LOG_REGION});
    assert_eq!(harness.post("/v1/config", config).await.0, 200);
    refused(&app.send(&harness, envelope.clone()).await);
    // With credentials whose time has passed: the same.
    let now_ms = harness.node.now_ms();
    let credentials = |expires_ms: u64| {
        let harness = &harness;
        async move {
            let body = log_credentials(expires_ms);
            let outcome = harness.post("/v1/log-store/credentials", body).await;
            assert_eq!(
                outcome,
                (200, json!({"credentials_expires_ms": expires_ms}))
            );
        }
    };
    credentials(now_ms).await;
    refused(&app.send(&harness, envelope.clone()).await);
    assert!(writes(&provider).is_empty());
    assert_eq!(harness.head_seq("user-1"), 0);

    // With credentials within their time the same command passes.
    credentials(now_ms + 60_000).await;
    let response = app.send(&harness, envelope).await;
    let reply = harness.verified(purpose::REPLY, &response["reply"]);
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(writes(&provider).len(), 1);
    let record = app.record(
        "oauth",
        "google_workspace",
        &json!({"token": {"access_token": "ya29.access", "refresh_token": "1//refresh"}, "obtained_ms": 1}),
    );
    let vault = password(&app);
    let state = begin(&harness, &app).await;
    assert_eq!(release(&harness, &app, &vault).await.0, 200);

    // When the credentials end, every act of the node ends with them, before an entry is
    // created and before a provider is called.
    harness.node.clock.advance(60_000);
    let seq = harness.head_seq("user-1");
    let outcome = harness.forward(get(&app, &record, MESSAGES), b"").await;
    unavailable(&outcome.err().unwrap());
    unavailable(&refresh(&harness, &app, &record).await);
    unavailable(&revoke_token(&harness, &app, &record).await);
    unavailable(&release(&harness, &app, &vault).await);
    unavailable(&complete(&harness, &app, &state).await);
    let peer = Harness::measured(&provider, measurement);
    let mut config = operator_config(&peer.node.definitions);
    config["log_store"] = json!({"bucket": LOG_BUCKET, "region": LOG_REGION});
    assert_eq!(peer.post("/v1/config", config).await.0, 200);
    // The stand-in of the nitro platform signs no document, so no node of these tests is a
    // peer of this one: the refusal of the peer comes first.
    assert_eq!(
        code(&export(&harness, &attestation(&peer).await).await),
        (403, "peer_unverified")
    );
    assert_eq!(harness.head_seq("user-1"), seq);
    assert!(provider_requests(&provider).is_empty());
    assert_eq!(writes(&provider).len(), 2);
    // The calls that create no entry go on.
    begin(&harness, &app).await;

    // The refused completion did not use its pending authorization up: with credentials
    // within their time the same call passes.
    credentials(harness.node.now_ms() + 60_000).await;
    let (status, completed) = complete(&harness, &app, &state).await;
    assert_eq!(status, 200, "{completed}");
    assert_eq!(writes(&provider).len(), 3);
    let nonce = json!({"user_id": "user-1", "nonce": "bm9uY2U"});
    assert_eq!(harness.post("/v1/status", nonce).await.0, 200);
}

#[tokio::test]
async fn a_node_takes_one_log_store_and_names_it_in_its_binding() {
    let (provider, _store) = stand_in().await;
    let harness = Harness::new(&provider);
    let providers = operator_config(&harness.node.definitions)["providers"].clone();
    let config = |log_store: Value| json!({"providers": providers, "log_store": log_store});
    let binding_of = |response: &Value| -> Value {
        let document = b64u_decode(response["document"].as_str().unwrap()).unwrap();
        let document: Value = serde_json::from_slice(&document).unwrap();
        let binding = b64u_decode(document["binding"].as_str().unwrap()).unwrap();
        serde_json::from_slice(&binding).unwrap()
    };

    // A node without a log store: its binding has no `log` key.
    let binding = binding_of(&attestation(&harness).await);
    let keys: Vec<&String> = binding.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["v", "sign", "seal", "release"]);

    // A log store that is not a bucket name and a region name is refused, and so is the
    // configuration that carries it.
    for log_store in [
        json!("credential-log-test-1"),
        json!({}),
        json!({"bucket": LOG_BUCKET}),
        json!({"region": LOG_REGION}),
        json!({"bucket": "Bucket", "region": LOG_REGION}),
        json!({"bucket": "my.bucket", "region": LOG_REGION}),
        json!({"bucket": LOG_BUCKET, "region": "us-west-2.example.com"}),
        json!({"bucket": LOG_BUCKET, "region": 2}),
    ] {
        let outcome = harness.post("/v1/config", config(log_store.clone())).await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{log_store}");
    }
    let health = harness.health().await;
    assert_eq!(
        (&health["configured"], &health["log_store"]),
        (&json!(false), &Value::Null)
    );

    // The node takes the log store, and its health and its binding name it from then on.
    let named = json!({"bucket": LOG_BUCKET, "region": LOG_REGION});
    assert_eq!(
        harness.post("/v1/config", config(named.clone())).await.0,
        200
    );
    assert_eq!(
        harness.health().await["log_store"],
        json!({
            "bucket": LOG_BUCKET, "region": LOG_REGION, "credentials_expires_ms": 0, "pending": 0,
        })
    );
    let binding = binding_of(&attestation(&harness).await);
    let keys: Vec<&String> = binding.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["v", "sign", "seal", "release", "log"]);
    assert_eq!(binding["log"], named);

    // The same log store again, and a configuration that names none, leave it in place.
    assert_eq!(
        harness.post("/v1/config", config(named.clone())).await.0,
        200
    );
    let without = json!({"providers": providers});
    assert_eq!(harness.post("/v1/config", without).await.0, 200);
    assert_eq!(harness.health().await["log_store"]["bucket"], LOG_BUCKET);
    // Another log store is refused, and the configuration that names it changes nothing.
    let other =
        json!({"providers": {}, "log_store": {"bucket": "another-bucket", "region": LOG_REGION}});
    let outcome = harness.post("/v1/config", other).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    let other = json!({"bucket": LOG_BUCKET, "region": "eu-central-1"});
    let outcome = harness.post("/v1/config", config(other)).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    assert_eq!(binding_of(&attestation(&harness).await)["log"], named);
    let app = App::new("user-1", 1);
    let expires_ms = harness.node.now_ms() + 60_000;
    let credentials = log_credentials(expires_ms);
    assert_eq!(
        harness
            .post("/v1/log-store/credentials", credentials)
            .await
            .0,
        200
    );
    app.grant(&harness).await;
    let begun = harness
        .post(
            "/v1/oauth/begin",
            json!({"user_id": "user-1", "provider": "slack", "operator_state": "o", "params": {}}),
        )
        .await;
    assert_eq!(
        begun.0, 200,
        "the providers of the last accepted configuration"
    );

    // The credentials: the health says when they end, and no response holds their secrets.
    let health = harness.health().await;
    assert_eq!(health["log_store"]["credentials_expires_ms"], expires_ms);
    assert!(!health.to_string().contains(LOG_SESSION_TOKEN));
    for (field, value) in [
        ("access_key_id", json!("")),
        ("access_key_id", json!("not an access key")),
        ("access_key_id", json!(5)),
        ("secret_access_key", json!("")),
        ("secret_access_key", json!("line\nbreak")),
        ("secret_access_key", Value::Null),
        ("session_token", json!("line\r\nbreak")),
        ("session_token", json!(5)),
        ("expires_ms", json!("soon")),
        ("expires_ms", json!(-1)),
        ("expires_ms", Value::Null),
    ] {
        let mut body = log_credentials(expires_ms + 1);
        body[field] = value.clone();
        let outcome = harness.post("/v1/log-store/credentials", body).await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{field} {value}");
        assert!(!outcome.1.to_string().contains(LOG_SECRET_ACCESS_KEY));
    }
    assert_eq!(
        harness.health().await["log_store"]["credentials_expires_ms"],
        expires_ms
    );
    // Credentials without a session are taken: their requests carry no token header.
    let mut body = log_credentials(expires_ms);
    body.as_object_mut().unwrap().remove("session_token");
    assert_eq!(harness.post("/v1/log-store/credentials", body).await.0, 200);
    assert_eq!(release(&harness, &app, &password(&app)).await.0, 200);
    let write = writes(&provider).pop().unwrap();
    assert_eq!(write.header("x-amz-security-token"), None);
    assert!(write.header("authorization").unwrap().contains(concat!(
        "SignedHeaders=content-type;host;x-amz-checksum-sha256;x-amz-content-sha256;",
        "x-amz-date;x-amz-object-lock-mode;x-amz-object-lock-retain-until-date,"
    )));
    assert!(write
        .header("authorization")
        .unwrap()
        .ends_with(&signature_of(&write)));
}

#[tokio::test]
async fn an_account_collects_at_most_64_pending_entries_of_calls_that_use_a_credential() {
    let (provider, store) = stand_in().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let vault = password(&app);
    let account = harness.node.account("user-1").unwrap();
    let acknowledge = || {
        let harness = &harness;
        async move {
            let seq = harness.head_seq("user-1");
            let body = json!({"user_id": "user-1", "seq": seq});
            assert_eq!(harness.post("/v1/log/ack", body).await.0, 200);
        }
    };

    // The store refuses every write. The caller stores the entries of the failed calls, so
    // the limit of entries without a storage acknowledgement does not stop it.
    refuse(&store, 500);
    for _ in 0..PENDING_ENTRIES {
        unavailable(&release(&harness, &app, &vault).await);
        acknowledge().await;
    }
    assert_eq!(lock(&account).pending_entries(), PENDING_ENTRIES);
    assert_eq!(harness.head_seq("user-1"), 1 + PENDING_ENTRIES as u64);

    // The next call creates no entry: it writes the pending ones again, and they still wait.
    let before = writes(&provider).len();
    unavailable(&release(&harness, &app, &vault).await);
    assert_eq!(harness.head_seq("user-1"), 1 + PENDING_ENTRIES as u64);
    assert_eq!(lock(&account).pending_entries(), PENDING_ENTRIES);
    assert!(writes(&provider).len() > before);
    // A command is not stopped by this limit, and its entry waits with the others.
    let response = app.revoke(&harness).await;
    assert_eq!(response["grant"]["state"], "revoked");
    assert_eq!(lock(&account).pending_entries(), PENDING_ENTRIES + 1);

    // Once the store takes writes again, a call makes room and goes on: a grant, here, and
    // the release after it.
    confirm(&store);
    app.grant(&harness).await;
    assert!(lock(&account).unconfirmed.is_empty());
    let (status, released) = release(&harness, &app, &vault).await;
    assert_eq!((status, &released["value"]), (200, &json!("hunter2")));
    // Every entry of the chain is in the store.
    let mut seqs: Vec<u64> = writes(&provider).iter().map(seq_of).collect();
    seqs.sort();
    seqs.dedup();
    let all: Vec<u64> = (1..=harness.head_seq("user-1")).collect();
    assert_eq!(seqs, all);
}

#[tokio::test]
async fn a_call_at_the_limit_of_pending_entries_goes_on_once_the_store_made_room() {
    let (provider, store) = stand_in().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let vault = password(&app);
    let account = harness.node.account("user-1").unwrap();
    refuse(&store, 500);
    for _ in 0..PENDING_ENTRIES {
        unavailable(&release(&harness, &app, &vault).await);
        let body = json!({"user_id": "user-1", "seq": harness.head_seq("user-1")});
        assert_eq!(harness.post("/v1/log/ack", body).await.0, 200);
    }
    confirm(&store);
    let (status, released) = release(&harness, &app, &vault).await;
    assert_eq!((status, &released["value"]), (200, &json!("hunter2")));
    assert_eq!(
        app.entry_body(&harness, &released["entry"])["seq"],
        2 + PENDING_ENTRIES as u64
    );
    assert!(lock(&account).unconfirmed.is_empty());
    // The call wrote the 64 pending entries first, and its own entry after the store took
    // them.
    let seqs: Vec<u64> = writes(&provider).iter().map(seq_of).collect();
    let (pending, own) = seqs[seqs.len() - 1 - PENDING_ENTRIES..].split_at(PENDING_ENTRIES);
    let mut pending = pending.to_vec();
    pending.sort();
    let waited: Vec<u64> = (2..2 + PENDING_ENTRIES as u64).collect();
    assert_eq!(pending, waited);
    assert_eq!(own, [2 + PENDING_ENTRIES as u64]);
}

#[tokio::test]
async fn a_call_that_ends_before_its_write_leaves_its_entry_pending() {
    let (provider, store) = stand_in().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let vault = password(&app);
    let account = harness.node.account("user-1").unwrap();

    // The caller gives up while the node waits for the store: the call ends there.
    lock(&store).silent = true;
    let call = release(&harness, &app, &vault);
    assert!(tokio::time::timeout(Duration::from_millis(300), call)
        .await
        .is_err());
    // Its entry is on the chain and no call writes it: it is a pending entry.
    assert_eq!(harness.head_seq("user-1"), 2);
    assert_eq!(lock(&account).unconfirmed.len(), 1);
    assert_eq!(lock(&account).pending_entries(), 1);

    // The next write of the account takes it along.
    confirm(&store);
    assert_eq!(release(&harness, &app, &vault).await.0, 200);
    assert!(lock(&account).unconfirmed.is_empty());
}

#[tokio::test]
async fn a_node_without_a_log_store_writes_nowhere() {
    let (provider, _store) = stand_in().await;
    let harness = Harness::configured(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    // Credentials alone name no place to write to.
    let expires_ms = harness.node.now_ms() + 60_000;
    let credentials = log_credentials(expires_ms);
    assert_eq!(
        harness
            .post("/v1/log-store/credentials", credentials)
            .await
            .0,
        200
    );
    assert_eq!(release(&harness, &app, &password(&app)).await.0, 200);
    let sent = harness
        .forward(get(&app, &google_record(&app), MESSAGES), b"")
        .await
        .unwrap();
    assert_eq!(sent.status, 200);
    app.revoke(&harness).await;
    assert!(writes(&provider).is_empty());
    assert_eq!(harness.health().await["log_store"], Value::Null);
    let account = harness.node.account("user-1").unwrap();
    assert!(lock(&account).unconfirmed.is_empty());
    assert_eq!(
        harness.platform.connections(),
        [("gmail.googleapis.com".to_string(), 443)]
    );
}

/// Waits until the log store received `count` writes.
async fn until_written(provider: &Provider, count: usize) {
    for _ in 0..500 {
        if writes(provider).len() >= count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the log store did not receive {count} writes");
}

#[tokio::test]
async fn a_revoke_that_is_accepted_while_a_grant_waits_for_the_store_stands() {
    let (provider, store) = stand_in().await;
    let harness = Harness::new(&provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let for_the_grant = app.attest(&harness).await;
    let for_the_revoke = app.attest(&harness).await;

    // The store takes its time with the entry of the grant. In that time the node accepts
    // a revoke of the account, with a challenge that was issued after the one of the grant.
    lock(&store).pause = Duration::from_millis(400);
    let grant = app.send(&harness, app.grant_envelope(&for_the_grant, not_after_ms));
    let revoke = async {
        until_written(&provider, 1).await;
        let response = app
            .send(&harness, app.revoke_envelope(&for_the_revoke))
            .await;
        let reply = harness.verified(purpose::REPLY, &response["reply"]);
        assert_eq!(
            (&reply["type"], &reply["ok"]),
            (&json!("revoke_reply"), &json!(true))
        );
        // There was no grant to end: no entry, and nothing to write.
        assert_eq!(response["entry"], Value::Null);
    };
    let (response, ()) = tokio::join!(grant, revoke);

    // The store confirmed the entry of the grant, and the node did not put the key in place:
    // the revoke came after the challenge of the grant.
    let reply = harness.verified(purpose::REPLY, &response["reply"]);
    assert_eq!(
        (&reply["type"], &reply["ok"], &reply["code"]),
        (
            &json!("grant_reply"),
            &json!(false),
            &json!("bad_challenge")
        )
    );
    assert_eq!(response["entry"], Value::Null);
    assert_eq!(response["grant"]["state"], "revoked");
    assert_eq!(harness.health().await["grants"], 0);
    assert_eq!(
        code(&release(&harness, &app, &password(&app)).await),
        (409, "grant_revoked")
    );
    assert_eq!(writes(&provider).len(), 1);
    let account = harness.node.account("user-1").unwrap();
    assert!(lock(&account).unconfirmed.is_empty());
    assert_eq!(harness.head_seq("user-1"), 1);
}

#[tokio::test]
async fn a_revoke_that_is_accepted_while_an_export_waits_for_the_store_leaves_no_transfer() {
    let (provider, store) = stand_in().await;
    let old = Harness::new(&provider);
    let new = Harness::new(&provider);
    old.use_log_store().await;
    new.use_log_store().await;
    let alice = App::new("alice", 1);
    let bob = App::new("bob", 2);
    alice.grant(&old).await;
    bob.grant(&old).await;
    let to = attestation(&new).await;
    let for_the_revoke = alice.attest(&old).await;
    let before = writes(&provider).len();

    lock(&store).pause = Duration::from_millis(400);
    let revoke = async {
        until_written(&provider, before + 2).await;
        let envelope = alice.revoke_envelope(&for_the_revoke);
        let response = alice.send(&old, envelope).await;
        assert_eq!(response["grant"]["state"], "revoked");
    };
    let ((status, exported), ()) = tokio::join!(export(&old, &to), revoke);

    // The store confirmed both entries, and the transfer carries the grant of bob alone.
    assert_eq!(status, 200, "{exported}");
    assert_eq!(exported["entries"].as_array().unwrap().len(), 2);
    confirm(&store);
    let (status, imported) = import(&new, &attestation(&old).await, &exported["envelope"]).await;
    assert_eq!(
        (status, &imported["imported"]),
        (200, &json!(1)),
        "{imported}"
    );
    assert_eq!(new.health().await["grants"], 1);
    assert_eq!(
        code(&release(&new, &alice, &password(&alice)).await),
        (409, "grant_required")
    );
    assert_eq!(release(&new, &bob, &password(&bob)).await.0, 200);
}

#[tokio::test]
async fn calls_that_run_at_the_same_time_write_each_entry_once() {
    let (provider, store) = stand_in().await;
    let (harness, app) = node_with_log_store(&provider).await;
    let vault = password(&app);
    lock(&store).pause = Duration::from_millis(200);

    // Four releases of one account at the same time: each call writes the entry it created
    // and leaves the entries the others are writing to them.
    let call = || release(&harness, &app, &vault);
    let outcomes = tokio::join!(call(), call(), call(), call());
    for outcome in [outcomes.0, outcomes.1, outcomes.2, outcomes.3] {
        assert_eq!((outcome.0, &outcome.1["value"]), (200, &json!("hunter2")));
    }
    let mut seqs: Vec<u64> = writes(&provider).iter().map(seq_of).collect();
    seqs.sort();
    assert_eq!(seqs, [1, 2, 3, 4, 5]);
    let account = harness.node.account("user-1").unwrap();
    assert!(lock(&account).unconfirmed.is_empty());
}
