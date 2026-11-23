//! What a panic of the node program ends (enclave.md 3.1, `crate::faults`): a call, an
//! account on this node, or a sweep, and never the calls and the accounts beside it.
//!
//! The node of these tests takes its calls from a listener, as a running node does: every
//! connection is served on a task of its own, and a call whose task panics is a connection
//! that ends without a response. The panics are scripted on the test platform
//! (`TestPlatform::fault_at_draw`, `TestPlatform::fault_attestation`): the node program holds
//! no place that panics for a test. What ends the process (a panic under a lock of the whole
//! node, a panic of a task the node cannot do without) is tested in `crate::faults`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use credential_enclave_protocol::encoding::{b64u, to_json};
use credential_enclave_protocol::{limits, purpose};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::provider_and_log_store;
use crate::api;
use crate::faults;
use crate::log_store::{self, SWEEP_INTERVAL};
use crate::platform::Platform;
use crate::state::{lock, GrantState};
use crate::testing::{quiet_panics, App, Harness, Provider, Reply};
use credential_enclave_protocol::subset::Subset;

/// What the log store stand-in does with the write of an entry: it answers it after `pause`,
/// with `status` when `status` is not 0 and with a confirmation otherwise. The script is read
/// when the write arrives. The write of a node document is confirmed at once. Every answer
/// ends its connection.
#[derive(Default)]
struct Script {
    status: u16,
    pause: Duration,
}

type Store = Arc<Mutex<Script>>;

/// A stand-in for the providers and for the log store.
async fn scripted_store() -> (Provider, Store) {
    let store: Store = Arc::default();
    let script = store.clone();
    let provider = provider_and_log_store(
        |_| Reply::json(200, &json!({"ok": true})),
        move |seen| {
            let script = lock(&script);
            let entry = seen.target.contains("/a3/");
            if entry && script.status != 0 {
                return Reply::with_body(
                    script.status,
                    &[("connection", "close")],
                    b"<Error></Error>",
                )
                .after(script.pause);
            }
            let confirmed =
                Reply::with_body(200, &[("etag", "\"0\""), ("connection", "close")], b"");
            match entry {
                true => confirmed.after(script.pause),
                false => confirmed,
            }
        },
    )
    .await;
    (provider, store)
}

/// A node with the log store of the tests.
async fn node_with_log_store(provider: &Provider) -> Harness {
    let harness = Harness::new(provider);
    harness.use_log_store().await;
    harness
}

/// Serves the calls of the node on a listener of its platform and returns its address.
pub(super) async fn serve(harness: &Harness) -> SocketAddr {
    let listener = Platform::listen(harness.platform.as_ref(), 64)
        .await
        .unwrap();
    let address = listener.tcp_addr().unwrap();
    tokio::spawn(api::serve(
        listener,
        api::router(harness.node.clone()),
        harness.node.clone(),
    ));
    address
}

/// One call over a connection of its own: the status and the body of the response, or `None`
/// when the node ended the connection without a response.
pub(super) async fn call(
    node: SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
) -> Option<(u16, Vec<u8>)> {
    let mut stream = TcpStream::connect(node).await.unwrap();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: node\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut response = Vec::new();
    // A connection the node ended gives the end of its bytes, or a reset.
    let _ = stream.read_to_end(&mut response).await;
    let head_end = response.windows(4).position(|bytes| bytes == b"\r\n\r\n")?;
    let status = std::str::from_utf8(response.get(9..12)?)
        .ok()?
        .parse()
        .ok()?;
    Some((status, response[head_end + 4..].to_vec()))
}

/// A JSON call over a connection of its own.
async fn post(node: SocketAddr, path: &str, body: &Value) -> Option<(u16, Value)> {
    let (status, body) = call(node, "POST", path, &to_json(body)).await?;
    Some((status, serde_json::from_slice(&body).unwrap()))
}

/// `GET /v1/health` over a connection of its own, once the node holds no other connection:
/// the node gives the place of a connection back when the task of that connection ended,
/// which is a moment after its peer read the end of its bytes.
pub(super) async fn health(node: SocketAddr) -> Value {
    let mut health = Value::Null;
    for _ in 0..200 {
        let (status, body) = call(node, "GET", "/v1/health", b"").await.unwrap();
        assert_eq!(status, 200);
        health = serde_json::from_slice(&body).unwrap();
        if health["load"]["inbound_connections"] == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    health
}

/// The attestation response of a node, as the operator domain fetches it for a peer.
async fn attestation_of(harness: &Harness) -> Value {
    let (status, response) = harness.post("/v1/attestation", attestation_body()).await;
    assert_eq!(status, 200);
    response
}

fn attestation_body() -> Value {
    json!({"nonce": b64u(&[7u8; 32])})
}

/// The body of a `release` call of `app` for a password record.
fn release_body(app: &App) -> Value {
    let record = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
    json!({
        "user_id": app.user_id, "record": record, "field": "password",
        "origin": "https://site.example", "context": "browser:fill",
    })
}

/// The status and the failure code of a response.
fn code(response: &(u16, Value)) -> (u16, &str) {
    (response.0, response.1["code"].as_str().unwrap_or_default())
}

/// The writes of the entry `seq` of `user_id` the log store stand-in received, confirmed or
/// not.
fn writes_of(provider: &Provider, user_id: &str, seq: u64) -> usize {
    provider
        .stored()
        .iter()
        .filter(|stored| stored.user_id == user_id && stored.seq() == seq)
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panic_in_a_call_ends_that_call_and_no_other() {
    quiet_panics();
    let (provider, store) = scripted_store().await;
    let harness = node_with_log_store(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let node = serve(&harness).await;
    let before = health(node).await;
    assert_eq!(before["load"]["halted_accounts"], 0);

    // A call in progress: a release whose entry the store takes its time to confirm.
    lock(&store).pause = Duration::from_millis(700);
    let written = provider.stored().len();
    let body = release_body(&app);
    let in_progress = tokio::spawn(async move { post(node, "/v1/release", &body).await });
    provider.until_written(written + 1).await;

    // The first draw of an attestation call is its challenge, outside every lock. It panics:
    // the connection of that call ends without a response.
    harness.platform.fault_at_draw(0);
    assert_eq!(
        post(node, "/v1/attestation", &attestation_body()).await,
        None
    );
    // A panic of a task the call waits for (the request to the attestation device) is a panic
    // of the call.
    harness.platform.fault_attestation(true);
    assert_eq!(
        post(node, "/v1/attestation", &attestation_body()).await,
        None
    );
    harness.platform.fault_attestation(false);

    // The call that was in progress runs to its end, and the next calls are answered.
    let (status, released) = in_progress.await.unwrap().unwrap();
    assert_eq!((status, released["value"].as_str()), (200, Some("hunter2")));
    let (status, attested) = post(node, "/v1/attestation", &attestation_body())
        .await
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(attested["node"], harness.node.node.as_str());
    lock(&store).pause = Duration::ZERO;
    assert_eq!(
        post(node, "/v1/release", &release_body(&app))
            .await
            .unwrap()
            .0,
        200
    );

    // The two panics are counted. Nothing of the two calls is held: the one connection the
    // node holds is the one of this health call, no account was halted, and the grant stands.
    let after = health(node).await;
    let counted = |health: &Value| health["load"]["contained_panics"].as_u64().unwrap();
    assert!(counted(&after) >= counted(&before) + 2, "{after}");
    assert_eq!(after["load"]["inbound_connections"], 1);
    assert_eq!(after["load"]["forward_calls"], 0);
    assert_eq!(after["load"]["halted_accounts"], 0);
    assert_eq!(after["grants"], 1);
    assert_eq!(after["log_store"]["pending"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_that_panics_while_it_writes_leaves_its_entry_pending_and_the_account_free() {
    quiet_panics();
    let (provider, store) = scripted_store().await;
    let harness = node_with_log_store(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let node = serve(&harness).await;
    let before = health(node).await;

    // The writer: a release whose entry (seq 2) the store refuses after a pause. A refusal
    // with a 5xx status is followed by a backoff, and the backoff draws from the random
    // source: the next draw of the node is that one, outside every lock, while the call is
    // the writer of its account and holds its entry.
    {
        let mut script = lock(&store);
        script.status = 500;
        script.pause = Duration::from_millis(700);
    }
    let written = provider.stored().len();
    let body = release_body(&app);
    let writer = tokio::spawn(async move { post(node, "/v1/release", &body).await });
    provider.until_written(written + 1).await;
    // The store confirms what arrives from here on.
    *lock(&store) = Script::default();
    // A second release of the account: its event is in the open batch, and the call waits
    // for the writer.
    let body = release_body(&app);
    let waiting = tokio::spawn(async move { post(node, "/v1/release", &body).await });
    let account = harness.node.account("user-1").unwrap();
    for _ in 0..1000 {
        if lock(&account).has_open_events() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(lock(&account).has_open_events() && lock(&account).writer);

    // The backoff of the writer panics: its connection ends without a response, and no value
    // left the node for it.
    harness.platform.fault_at_draw(0);
    assert_eq!(writer.await.unwrap(), None);

    // What the writer held is given back as when its caller goes away: the account has no
    // writer, and the entry the store did not confirm is a pending entry. The call that
    // waited becomes the writer, writes its own entry (seq 3) and the pending one with it,
    // and acts: the store confirmed its entry.
    let (status, released) = waiting.await.unwrap().unwrap();
    assert_eq!((status, released["value"].as_str()), (200, Some("hunter2")));
    assert_eq!(released["log"]["seq"], 3);
    {
        let account = lock(&account);
        assert!(!account.is_halted() && !account.writer && !account.has_open_events());
        assert_eq!(account.pending_entries(), 0);
        assert_eq!([2, 3].map(|seq| account.is_confirmed(seq)), [true, true]);
    }
    // The store received the entry of the call that panicked twice: the write it refused,
    // and the write of the next writer.
    assert_eq!(writes_of(&provider, "user-1", 2), 2);
    assert_eq!(writes_of(&provider, "user-1", 3), 1);

    // The panic is counted, no account was halted, and the node holds nothing for the call.
    let after = health(node).await;
    let counted = |health: &Value| health["load"]["contained_panics"].as_u64().unwrap();
    assert!(counted(&after) > counted(&before), "{after}");
    assert_eq!(after["load"]["halted_accounts"], 0);
    assert_eq!(after["load"]["inbound_connections"], 1);
    assert_eq!(after["grants"], 1);
    assert_eq!(after["log"]["open_batches"], 0);
    assert_eq!(after["log_store"]["pending"], 0);
    assert_eq!(after["state"]["pending_entries"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panic_under_the_lock_of_an_account_halts_that_account_on_the_node() {
    quiet_panics();
    let (provider, store) = scripted_store().await;
    let harness = node_with_log_store(&provider).await;
    let (halted, other) = (App::new("user-1", 1), App::new("user-2", 2));
    halted.grant(&harness).await;
    other.grant(&harness).await;
    // The entries of `user-1`: 1 the grant, 2 a release the store confirmed, 3 a release the
    // store refused. Entry 3 is a pending entry.
    assert_eq!(
        harness.post("/v1/release", release_body(&halted)).await.0,
        200
    );
    lock(&store).status = 403;
    assert_eq!(
        code(&harness.post("/v1/release", release_body(&halted)).await),
        (503, "log_store_unavailable")
    );
    lock(&store).status = 0;
    let before = harness.health().await;
    assert_eq!(before["grants"], 2);
    assert_eq!(before["log_store"]["pending"], 1);
    assert_eq!(before["state"]["pending_entries"], 1);
    assert_eq!(before["load"]["halted_accounts"], 0);

    // The first draw of a call that creates an event is the seed of its entry, drawn inside
    // the lock of the account. It panics: the call ends without a response.
    let node = serve(&harness).await;
    harness.platform.fault_at_draw(0);
    assert_eq!(
        post(node, "/v1/release", &release_body(&halted)).await,
        None
    );

    // From here on a call that names the account ends with `internal`: the calls that use a
    // credential, the grant command of the app and `status`.
    let token = halted.record(
        "oauth",
        "google_workspace",
        &json!({"token": {"access_token": "ya29.token", "refresh_token": "1//refresh"}, "obtained_ms": 1}),
    );
    let requests = provider.requests().len();
    let written = provider.stored().len();
    for (path, body) in [
        ("/v1/release", release_body(&halted)),
        ("/v1/status", json!({"user_id": "user-1"})),
        (
            "/v1/oauth/begin",
            json!({"user_id": "user-1", "provider": "google_workspace", "operator_state": "s", "params": {}}),
        ),
        (
            "/v1/refresh",
            json!({"user_id": "user-1", "record": token, "context": ""}),
        ),
        (
            "/v1/revoke-token",
            json!({"user_id": "user-1", "record": token, "context": ""}),
        ),
    ] {
        assert_eq!(
            code(&harness.post(path, body).await),
            (500, "internal"),
            "{path}"
        );
    }
    let forwarded = harness
        .forward(
            json!({
                "user_id": "user-1", "record": token, "method": "GET",
                "url": "https://gmail.googleapis.com/gmail/v1/users/me/profile", "context": "",
            }),
            b"",
        )
        .await;
    assert_eq!(forwarded.err().map(|(status, _)| status), Some(500));
    let attested = halted.attest(&harness).await;
    let not_after_ms = harness.node.now_ms() + limits::GRANT_MAX_MS;
    let grant = halted.grant_envelope(&attested, not_after_ms);
    let command = json!({"user_id": "user-1", "envelope": grant});
    assert_eq!(
        code(&harness.post("/v1/messages", command).await),
        (500, "internal")
    );

    // A revoke is answered with the signed reply of a revoke: the node holds no user key of
    // the account and takes none, which is what a revoke asks of it. The reply is that of an
    // account without a grant: no entry, and the state the caller reads is `none`.
    let revoked = halted.revoke(&harness).await;
    let reply = harness.verified(purpose::REPLY, &revoked["reply"]);
    assert_eq!(
        (&reply["type"], &reply["ok"], &reply["user_id"]),
        (&json!("revoke_reply"), &json!(true), &json!("user-1"))
    );
    assert_eq!(revoked["log"], Value::Null);
    assert_eq!(revoked["grant"]["state"], "none");
    // The account stays halted after it: a grant that follows the revoke is not taken.
    let attested = halted.attest(&harness).await;
    let grant = halted.grant_envelope(&attested, not_after_ms);
    assert_eq!(
        code(
            &harness
                .post(
                    "/v1/messages",
                    json!({"user_id": "user-1", "envelope": grant})
                )
                .await
        ),
        (500, "internal")
    );
    // None of these calls reached a provider or wrote an entry.
    assert_eq!(provider.requests().len(), requests);
    assert_eq!(provider.stored().len(), written);

    // The node gave the state of the account up: the grant is gone with its user key, no
    // entry of the account counts as confirmed, and the pending entry is gone.
    {
        let account = harness.node.account("user-1").unwrap();
        let account = lock(&account);
        assert!(account.is_halted());
        assert!(matches!(account.grant(), GrantState::None));
        assert_eq!(
            [1, 2, 3, 4].map(|seq| account.is_confirmed(seq)),
            [false; 4]
        );
        assert_eq!(account.pending_entries(), 0);
    }
    let after = harness.health().await;
    assert_eq!(after["grants"], 1);
    assert_eq!(after["log_store"]["pending"], 0);
    assert_eq!(after["state"]["pending_entries"], 0);
    assert_eq!(after["load"]["halted_accounts"], 1);
    let counted = |health: &Value| health["load"]["contained_panics"].as_u64().unwrap();
    assert!(counted(&after) > counted(&before), "{after}");

    // The other account of the node is served as before.
    assert_eq!(
        harness.post("/v1/release", release_body(&other)).await.0,
        200
    );

    // The sweep writes nothing of the account: the entry that was pending is gone as it is
    // gone with a node that ends.
    let pending_writes = writes_of(&provider, "user-1", 3);
    harness.node.clock.advance(60_000);
    log_store::sweep(&harness.node).await;
    assert_eq!(writes_of(&provider, "user-1", 3), pending_writes);
    assert_eq!(harness.health().await["load"]["halted_accounts"], 1);

    // A transfer hands the delegation of the other account on, and not that of this one.
    let receiving = node_with_log_store(&provider).await;
    let (status, page) = harness
        .post(
            "/v1/peer/export",
            json!({"peer": attestation_of(&receiving).await, "after": "", "limit": 1000}),
        )
        .await;
    assert_eq!((status, page["next"].as_str()), (200, Some("")));
    let (status, imported) = receiving
        .post(
            "/v1/peer/import",
            json!({"peer": attestation_of(&harness).await, "envelope": page["envelope"]}),
        )
        .await;
    assert_eq!((status, &imported["accounts"]), (200, &json!(["user-2"])));

    // No transfer brings it back: a node that holds the delegation of the account hands it
    // over, and this node takes nothing.
    let giving = node_with_log_store(&provider).await;
    halted.grant(&giving).await;
    let (status, page) = giving
        .post(
            "/v1/peer/export",
            json!({"peer": attestation_of(&harness).await, "after": "", "limit": 1000}),
        )
        .await;
    assert_eq!(status, 200);
    assert!(page["envelope"].is_object());
    let (status, imported) = harness
        .post(
            "/v1/peer/import",
            json!({"peer": attestation_of(&giving).await, "envelope": page["envelope"]}),
        )
        .await;
    assert_eq!(
        (status, &imported["imported"], &imported["accounts"]),
        (200, &json!(0), &json!([]))
    );
    assert_eq!(harness.health().await["grants"], 1);

    // A prune walks past it: of the two accounts outside the share, the one with a grant is
    // pruned.
    let outside = (0..3)
        .map(|pod| json!({"pods": 3, "pod": pod, "copies": 1}))
        .find(|subset| {
            let subset = Subset::from_value(subset).unwrap();
            !subset.contains("user-1") && !subset.contains("user-2")
        })
        .unwrap();
    let (status, pruned) = harness
        .post("/v1/grants/prune", json!({"subset": outside}))
        .await;
    assert_eq!((status, &pruned["pruned"]), (200, &json!(["user-2"])));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_calls_of_an_account_that_is_halted_while_they_write_or_wait_do_not_act() {
    quiet_panics();
    let (provider, store) = scripted_store().await;
    let harness = node_with_log_store(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let node = serve(&harness).await;

    // The writer: a release whose entry the store confirms after a pause. The call waits for
    // the confirmation, and its value has not left.
    lock(&store).pause = Duration::from_millis(800);
    let written = provider.stored().len();
    let body = release_body(&app);
    let writer = tokio::spawn(async move { post(node, "/v1/release", &body).await });
    provider.until_written(written + 1).await;
    // A second release: its event is in the open batch, and the call waits for the writer.
    let body = release_body(&app);
    let waiting = tokio::spawn(async move { post(node, "/v1/release", &body).await });
    let account = harness.node.account("user-1").unwrap();
    for _ in 0..1000 {
        if lock(&account).has_open_events() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(lock(&account).has_open_events());

    // A third call of the account panics inside the lock of the account.
    harness.platform.fault_at_draw(0);
    assert_eq!(post(node, "/v1/release", &release_body(&app)).await, None);

    // The store confirms the entry of the writer. The node gave up what it knew of the
    // entries of the account, so the writer does not act: its value does not leave. The call
    // that waited is woken at the end of that write and finds the account halted: its event
    // never became an entry.
    let wrote = writer.await.unwrap().unwrap();
    assert_eq!(code(&wrote), (500, "internal"));
    assert!(wrote.1.get("value").is_none());
    let waited = waiting.await.unwrap().unwrap();
    assert_eq!(code(&waited), (500, "internal"));
    assert!(waited.1.get("value").is_none());
    assert_eq!(provider.stored().len(), written + 1);

    // The account has no writer and no grant, and the node holds nothing for the three calls.
    {
        let account = lock(&account);
        assert!(account.is_halted() && !account.writer && !account.has_open_events());
    }
    let after = health(node).await;
    assert_eq!(after["grants"], 0);
    assert_eq!(after["log"]["open_batches"], 0);
    assert_eq!(after["log_store"]["pending"], 0);
    assert_eq!(after["load"]["halted_accounts"], 1);
    assert_eq!(after["load"]["inbound_connections"], 1);
}

#[tokio::test]
async fn a_sweep_that_panicked_is_followed_by_the_next_sweep() {
    quiet_panics();
    let (provider, store) = scripted_store().await;
    let harness = node_with_log_store(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    // A pending entry: a release the store refused. The sweep draws a jitter for the account
    // before it writes the entry again.
    lock(&store).status = 403;
    assert_eq!(
        code(&harness.post("/v1/release", release_body(&app)).await),
        (503, "log_store_unavailable")
    );
    lock(&store).status = 0;
    harness.node.clock.advance(60_000);
    let refused = writes_of(&provider, "user-1", 2);

    // The task of the sweep, as a running node starts it. A sweep starts every 30 seconds:
    // once the task waits for its next sweep, the clock of the runtime is moved past that
    // time by hand.
    let sweeping = tokio::spawn(log_store::keep_sweeping(harness.node.clone()));
    let next_sweep = || async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::time::pause();
        tokio::time::advance(SWEEP_INTERVAL + Duration::from_millis(1)).await;
        tokio::time::resume();
    };

    // The first sweep panics at its first draw, outside every lock: that sweep ends, and the
    // entry stays pending.
    let panics = faults::panics();
    harness.platform.fault_at_draw(0);
    next_sweep().await;
    for _ in 0..1000 {
        if faults::panics() > panics {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(faults::panics() > panics);
    assert_eq!(writes_of(&provider, "user-1", 2), refused);
    assert_eq!(harness.health().await["log_store"]["pending"], 1);

    // The task goes on: the next sweep writes the entry.
    next_sweep().await;
    for _ in 0..1000 {
        if harness.health().await["log_store"]["pending"] == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(harness.health().await["log_store"]["pending"], 0);
    assert_eq!(writes_of(&provider, "user-1", 2), refused + 1);
    assert!(!sweeping.is_finished());
    let after = harness.health().await;
    assert_eq!(after["load"]["halted_accounts"], 0);
    assert_eq!(after["grants"], 1);
}
