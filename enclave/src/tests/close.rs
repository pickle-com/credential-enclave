//! The entries the log store did not confirm, and the orderly shutdown (enclave.md 5.11 and
//! 5.14, protocol.md 7.6): an entry counts as confirmed by an answer of the store alone, an
//! unconfirmed entry stays in the memory of the node and is never dropped, the act of a call
//! that waited for it does not take place, and `close` signs nothing.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use super::{is_write_of, provider_and_log_store};
use crate::state::{lock, Limits};
use crate::testing::{App, Harness, Provider, Reply};

/// What the log store stand-in does with the write of an entry: it refuses every write with
/// `status` when `status` is not 0, and it reads every write without answering while `hang` is
/// set. `confirmed` holds the request targets of the writes it answered with 200: the objects
/// the store holds. The write of a node document is always confirmed.
#[derive(Default)]
struct Refusal {
    status: u16,
    hang: bool,
    confirmed: Vec<String>,
}

type Store = Arc<Mutex<Refusal>>;

/// A stand-in for the providers and for the log store. The store confirms a write unless the
/// refusal says otherwise.
async fn refusing_store() -> (Provider, Store) {
    let store: Store = Arc::default();
    let script = store.clone();
    let provider = provider_and_log_store(
        |_| Reply::json(200, &json!({"ok": true})),
        move |seen| {
            let mut refusal = lock(&script);
            let entry = seen.target.contains("/a3/");
            if entry && refusal.hang {
                return Reply::Hang;
            }
            match entry && refusal.status != 0 {
                true => Reply::with_body(refusal.status, &[], b"<Error></Error>"),
                false => {
                    refusal.confirmed.push(seen.target.clone());
                    Reply::with_body(200, &[("etag", "\"0\"")], b"")
                }
            }
        },
    )
    .await;
    (provider, store)
}

/// A node with the log store of the tests whose writes are not repeated (a time limit below
/// the margin of a repeated attempt), and the app of an account that granted on it.
async fn node_with_log_store(provider: &Provider) -> (Harness, App) {
    let limits = Limits {
        log_write: Duration::from_millis(450),
        ..Limits::default()
    };
    let harness = Harness::with(provider, crate::providers::Definitions::embedded(), limits);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    (harness, app)
}

async fn release(harness: &Harness, app: &App) -> (u16, Value) {
    let record = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
    harness
        .post(
            "/v1/release",
            json!({
                "user_id": app.user_id, "record": record, "field": "password",
                "origin": "https://site.example", "context": "browser:fill",
            }),
        )
        .await
}

/// The `seq` of the entries of `user_id` that the store holds: the writes it confirmed.
fn held(provider: &Provider, store: &Store, harness: &Harness, user_id: &str) -> Vec<u64> {
    let confirmed = lock(store).confirmed.clone();
    provider
        .chain(user_id, &harness.node.node)
        .iter()
        .filter(|stored| confirmed.iter().any(|target| target.ends_with(&stored.key)))
        .map(|stored| stored.seq())
        .collect()
}

#[tokio::test]
async fn an_entry_the_store_did_not_confirm_stays_with_the_node_through_the_shutdown() {
    let (provider, store) = refusing_store().await;
    let (harness, app) = node_with_log_store(&provider).await;
    // Entry 1 (the grant) and entry 2 (a release) are in the store. Then the store refuses:
    // two releases fail, hand no value out and leave entries 3 and 4 unconfirmed.
    assert_eq!(release(&harness, &app).await.0, 200);
    lock(&store).status = 403;
    for _ in 0..2 {
        let (status, failure) = release(&harness, &app).await;
        assert_eq!(
            (status, failure["code"].as_str()),
            (503, Some("log_store_unavailable"))
        );
        assert!(failure.get("value").is_none());
    }
    assert_eq!(harness.last_seq("user-1"), 4);
    let account = harness.node.account("user-1").unwrap();
    {
        let account = lock(&account);
        // Confirmed is what the store answered with 200, and nothing else: not an entry that
        // waits, and not a `seq` the node never created.
        assert_eq!(
            [1, 2, 3, 4, 5, 0].map(|seq| account.is_confirmed(seq)),
            [true, true, false, false, false, false]
        );
        assert_eq!(account.pending_entries(), 2);
    }

    // The orderly shutdown while the store still refuses. Nothing is signed and nothing is
    // dropped: the node holds the two entries as before, and the store holds entries 1 and 2.
    assert_eq!(harness.post("/v1/close", json!({})).await.0, 200);
    assert_eq!(harness.last_seq("user-1"), 4);
    {
        let account = lock(&account);
        assert_eq!(
            account
                .unconfirmed()
                .iter()
                .map(|entry| entry.seq)
                .collect::<Vec<_>>(),
            [3, 4]
        );
        assert!(!account.is_confirmed(3) && !account.is_confirmed(4));
    }
    let health = harness.health().await;
    assert_eq!(health["accounts"], 1);
    assert_eq!(health["log_store"]["pending"], 1);
    assert_eq!(health["state"]["pending_entries"], 2);
    assert_eq!(held(&provider, &store, &harness, "user-1"), [1, 2]);
    // The acts of the two entries did not take place, and a reader of the store finds no
    // object of them: that absence is the record of it.
    let (status, failure) = release(&harness, &app).await;
    assert_eq!((status, failure["code"].as_str()), (503, Some("closing")));
}

#[tokio::test]
async fn a_call_that_waited_for_an_entry_the_store_never_confirmed_hands_no_value_out() {
    let (provider, store) = refusing_store().await;
    let (harness, app) = node_with_log_store(&provider).await;
    assert_eq!(release(&harness, &app).await.0, 200);
    let writes_before = provider.stored().len();

    // The store reads the writes and does not answer. A first release is the writer of entry
    // 3. A second release joins the open batch while that write runs and waits for the entry
    // that will hold its event. The node closes in that time.
    lock(&store).hang = true;
    let first = release(&harness, &app);
    let rest = async {
        for _ in 0..1000 {
            if provider.stored().len() > writes_before {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let second = release(&harness, &app);
        let closed = async {
            tokio::time::sleep(Duration::from_millis(60)).await;
            harness.post("/v1/close", json!({})).await
        };
        tokio::join!(second, closed)
    };
    let (first, (second, (closed, _))) = tokio::join!(first, rest);
    assert_eq!(closed, 200);
    // Neither call hands a value out: the writer was not confirmed, and the call that waited
    // found its entry unconfirmed.
    for (status, body) in [&first, &second] {
        assert_eq!(*status, 503, "{body}");
        assert!(
            matches!(
                body["code"].as_str(),
                Some("log_store_unavailable" | "closing")
            ),
            "{body}"
        );
        assert!(body.get("value").is_none());
    }
    assert_eq!(first.1["code"], "log_store_unavailable");

    // The store confirmed neither entry: it holds entries 1 and 2, the node holds every entry
    // above them as unconfirmed, and no entry of the account is written by a call any more.
    assert_eq!(held(&provider, &store, &harness, "user-1"), [1, 2]);
    let account = harness.node.account("user-1").unwrap();
    let account = lock(&account);
    assert!(account.last.seq >= 3);
    for seq in 3..=account.last.seq {
        assert!(!account.is_confirmed(seq), "{seq}");
    }
    assert_eq!(
        account.pending_entries(),
        account.unconfirmed().len(),
        "no call writes an entry after both calls ended"
    );
    // The first of the unconfirmed entries left the node at least once and was never answered.
    assert!(provider
        .seen()
        .iter()
        .any(|seen| is_write_of(seen, "user-1", 3)));
}

#[tokio::test]
async fn an_entry_two_calls_write_is_pending_only_when_both_ended() {
    let (provider, store) = refusing_store().await;
    let (harness, app) = node_with_log_store(&provider).await;
    lock(&store).status = 403;
    assert_eq!(release(&harness, &app).await.0, 503);
    let account = harness.node.account("user-1").unwrap();
    assert_eq!(lock(&account).pending_entries(), 1);

    // Two calls take the same entry: the first as a pending entry it takes along, the second
    // because its act waits for it. The entry is written by both, and it is a pending entry
    // again only when the second of them ended.
    let seq = lock(&account).last.seq;
    let awaited = [seq];
    lock(&store).hang = true;
    let sweep = crate::log_store::confirm(&harness.node, &account, &[]);
    let waiting = crate::log_store::confirm(&harness.node, &account, &awaited);
    let watch = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let guard = lock(&account);
        (guard.unconfirmed()[0].writers, guard.pending_entries())
    };
    let (swept, waited, (writers, pending)) = tokio::join!(sweep, waiting, watch);
    assert_eq!((writers, pending), (2, 0));
    // The call that named no entry does not fail for a pending entry, and the call whose act
    // waits for the entry does.
    assert_eq!(swept, Ok(()));
    assert_eq!(
        waited,
        Err(credential_enclave_protocol::ProtocolError::LogStoreUnavailable)
    );
    let account = lock(&account);
    assert_eq!(account.unconfirmed()[0].writers, 0);
    assert_eq!(account.pending_entries(), 1);
    assert!(!account.is_confirmed(seq));
}
