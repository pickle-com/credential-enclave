//! The named values of the vault (protocol.md section 6, enclave.md 5.9 and 5.9b): a record
//! of kind `vault_secret` states in its plaintext where its value may go, and `release` hands
//! the value out for the slot `field` on a site of the record or on a host below one. What a
//! call answers before its entry exists is the same for every value a record can hold.
//! `vault/store` makes such a record, or the record of a password, of a value its caller gave,
//! and hands it out after the entry that records it. A call of `release` that names a key gets
//! its value under the seal of that key.

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::http::Method;
use credential_enclave_protocol::encoding::{b64u, b64u_decode, to_json};
use credential_enclave_protocol::log::EntryLabel;
use credential_enclave_protocol::released::{Receiver, SealedValue};
use credential_enclave_protocol::totp::totp;
use credential_enclave_protocol::vault_secret::{device_plaintext, Reach};
use serde_json::{json, Value};

use super::{provider_and_log_store, quiet_provider, quiet_provider_and_log_store};
use crate::frame;
use crate::providers::Definitions;
use crate::state::{lock, Limits};
use crate::testing::{App, Harness, Provider, Reply};

const NAME: &str = "PAYMENT_PIN";

/// A node with the log store of the tests and the app of an account that granted on it.
async fn node(provider: &Provider) -> (Harness, App) {
    let harness = Harness::new(provider);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    (harness, app)
}

/// A stand-in for the providers and for the log store. The store answers every write with the
/// status the cell holds, 200 when it is 0, and closes the connection after each answer.
async fn store_with_status() -> (Provider, Arc<AtomicU16>) {
    let status = Arc::new(AtomicU16::new(0));
    let answered = status.clone();
    let provider = provider_and_log_store(
        |_| Reply::json(200, &json!({"ok": true})),
        move |_| match answered.load(Ordering::SeqCst) {
            0 => Reply::with_body(200, &[("etag", "\"0\""), ("connection", "close")], b""),
            status => Reply::with_body(status, &[("connection", "close")], b"<Error></Error>"),
        },
    )
    .await;
    (provider, status)
}

/// A node that writes every entry once (a time limit of a write below the margin of a repeated
/// attempt), for the tests in which the store refuses writes.
async fn node_without_repeated_writes(provider: &Provider) -> (Harness, App) {
    let limits = Limits {
        log_write: Duration::from_millis(450),
        ..Limits::default()
    };
    let harness = Harness::with(provider, Definitions::embedded(), limits);
    harness.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    (harness, app)
}

/// The plaintext of a record of kind `vault_secret` as the device of an account writes it.
fn plaintext(sites: Value, slots: Value, value: &str) -> Value {
    json!({"value": value, "name": NAME, "sites": sites, "slots": slots, "source": "device"})
}

/// A record of kind `vault_secret` the device of the account made.
fn named(app: &App, sites: Value, slots: Value, value: &str) -> Value {
    app.record("vault_secret", "vault", &plaintext(sites, slots, value))
}

async fn release(harness: &Harness, record: &Value, field: &str, origin: &str) -> (u16, Value) {
    harness
        .post(
            "/v1/release",
            json!({
                "user_id": "user-1", "record": record, "field": field, "origin": origin,
                "context": "browser:fill",
            }),
        )
        .await
}

fn code(outcome: &(u16, Value)) -> (u16, &str) {
    (outcome.0, outcome.1["code"].as_str().unwrap_or_default())
}

/// The keys of an event in their order, and the event without its `time_ms`.
fn keys_and_event(mut event: Value) -> (Vec<String>, Value) {
    assert!(event["time_ms"].as_u64().is_some(), "{event}");
    let keys = event.as_object().unwrap().keys().cloned().collect();
    event.as_object_mut().unwrap().remove("time_ms");
    (keys, event)
}

#[tokio::test]
async fn a_named_value_is_released_for_the_slot_field_on_a_site_of_its_record() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app) = node(&provider).await;
    let record = named(
        &app,
        json!(["shop.example", "pay.example"]),
        json!(["field"]),
        "493817",
    );

    let (status, released) = release(&harness, &record, "value", "https://shop.example").await;
    assert_eq!(status, 200, "{released}");
    assert_eq!(released["value"], "493817");
    // A call without `seal_to` is answered as a node of release v2.3.0 answers it.
    let keys: Vec<&String> = released.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["value", "log"]);
    assert_eq!(
        released["log"],
        json!({"seq": 2, "index": 0, "created": true})
    );
    // The event names the record, the origin and the name the record states.
    let (keys, event) = keys_and_event(app.logged(&harness, &provider, &released["log"]));
    assert_eq!(
        keys,
        [
            "t",
            "time_ms",
            "record_id",
            "kind",
            "field",
            "origin",
            "context",
            "name"
        ]
    );
    assert_eq!(
        event,
        json!({
            "t": "secret_released", "record_id": record["id"], "kind": "vault_secret",
            "field": "value", "origin": "https://shop.example", "context": "browser:fill",
            "name": NAME,
        })
    );

    // The host of the origin is compared in lower case and without the port, and every host
    // of the sites is admitted, with the hosts below it: the document a value is typed into is
    // often one of a host below the site (the payment frame of a shop). The event carries the
    // origin as the caller wrote it.
    let origins = [
        "https://SHOP.example:8443",
        "https://pay.example",
        "https://www.shop.example",
        "https://frame.checkout.pay.example:8443",
        "https://WWW.Shop.Example",
    ];
    for origin in origins {
        let (status, released) = release(&harness, &record, "value", origin).await;
        assert_eq!(
            (status, &released["value"]),
            (200, &json!("493817")),
            "{origin}"
        );
        let event = app.logged(&harness, &provider, &released["log"]);
        assert_eq!(event["origin"], origin);
    }
    assert_eq!(harness.last_seq("user-1"), 2 + origins.len() as u64);
}

#[tokio::test]
async fn a_record_the_device_padded_is_released_like_one_without_padding() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app) = node(&provider).await;
    // The plaintext as the device of an account writes it: the members of a named value and
    // `pad`, at one of the seven lengths.
    let reach = Reach::from_values(&json!(["shop.example"]), &json!(["field"])).unwrap();
    let plaintext = device_plaintext("493817", NAME, &reach).unwrap();
    assert_eq!(plaintext.len(), 256);
    let plaintext: Value = serde_json::from_slice(&plaintext).unwrap();
    assert!(plaintext["pad"].as_str().unwrap().len() > 100);
    let record = app.record("vault_secret", "vault", &plaintext);
    let (status, released) = release(&harness, &record, "value", "https://shop.example").await;
    assert_eq!((status, &released["value"]), (200, &json!("493817")));
    let event = app.logged(&harness, &provider, &released["log"]);
    assert_eq!(event["name"], NAME);
}

#[tokio::test]
async fn a_named_value_is_not_released_outside_its_reach_and_no_entry_is_created() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app) = node(&provider).await;
    let field = named(&app, json!(["shop.example"]), json!(["field"]), "493817");
    // A value for a request: the record has no slot `field`.
    let request_only = named(
        &app,
        json!(["api.openai.com"]),
        json!(["header:authorization", "query:key"]),
        "sk-live-value",
    );
    // A site that is a host below another name: the value goes neither to that name nor to
    // its other hosts.
    let below = named(
        &app,
        json!(["pay.shop.example"]),
        json!(["field"]),
        "493817",
    );

    let refused = [
        // A host that is neither one of the sites nor below one: another name, a name above
        // a site, a name that only ends like a site, the site as a part of another name, an
        // address, and a text in front of the site that is no label.
        (&field, "value", "https://other.example"),
        (&field, "value", "https://example"),
        (&field, "value", "https://myshop.example"),
        (&field, "value", "https://shop.example.other.example"),
        (&field, "value", "https://[2001:db8::1]"),
        (&field, "value", "https://.shop.example"),
        (&field, "value", "https://a..shop.example"),
        (&field, "value", "https://-.shop.example"),
        (&below, "value", "https://shop.example"),
        (&below, "value", "https://www.shop.example"),
        // An origin in which a colon is followed by something that is no port has no host,
        // also when it begins with a site.
        (&field, "value", "https://shop.example:other.example"),
        (&field, "value", "https://shop.example:"),
        (&field, "value", "https://shop.example:443:8443"),
        // Another field than `value`.
        (&field, "password", "https://shop.example"),
        (&field, "totp", "https://shop.example"),
        (&field, "card_number", "https://shop.example"),
        (&field, "name", "https://shop.example"),
        // No slot `field`, on a host of the sites.
        (&request_only, "value", "https://api.openai.com"),
        (
            &request_only,
            "header:authorization",
            "https://api.openai.com",
        ),
        // A value for a request is typed into no page, also not one of a host below its site.
        (&request_only, "value", "https://eu.api.openai.com"),
    ];
    for (record, asked, origin) in refused {
        let outcome = release(&harness, record, asked, origin).await;
        assert_eq!(code(&outcome), (403, "not_allowed"), "{asked} {origin}");
        assert_eq!(outcome.1.as_object().unwrap().len(), 2);
    }
    // Only the grant left an entry, and the store received nothing after it.
    assert_eq!(harness.last_seq("user-1"), 1);
    assert_eq!(app.stored_events(&harness, &provider).len(), 1);
}

#[tokio::test]
async fn a_named_value_of_every_host_is_released_for_any_origin() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app) = node(&provider).await;
    let anywhere = named(&app, json!("any"), json!(["field"]), "900101-1234567");
    for origin in ["https://shop.example", "https://gov.example:8443"] {
        let (status, released) = release(&harness, &anywhere, "value", origin).await;
        assert_eq!(
            (status, &released["value"]),
            (200, &json!("900101-1234567")),
            "{origin}"
        );
    }

    // An origin whose host is no name is an origin all the same: a value of every host is
    // compared with none.
    let (status, released) = release(&harness, &anywhere, "value", "https://10.0.0.1").await;
    assert_eq!(
        (status, &released["value"]),
        (200, &json!("900101-1234567"))
    );

    // A record of every host states the one slot `field`: with another slot, with a second
    // slot or with none, its plaintext has not the form of a record and it does not open.
    for slots in [
        json!(["header:authorization"]),
        json!(["field", "header:authorization"]),
        json!([]),
    ] {
        let record = named(&app, json!("any"), slots.clone(), "sk-live-value");
        let outcome = release(&harness, &record, "value", "https://shop.example").await;
        assert_eq!(code(&outcome), (422, "record_invalid"), "{slots}");
    }
    assert_eq!(harness.last_seq("user-1"), 4);
}

#[tokio::test]
async fn a_record_that_does_not_state_a_name_and_a_reach_does_not_open() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app) = node(&provider).await;
    let stated = || plaintext(json!(["shop.example"]), json!(["field"]), "493817");
    let without = |key: &str| {
        let mut plaintext = stated();
        plaintext.as_object_mut().unwrap().shift_remove(key);
        plaintext
    };
    let with = |key: &str, value: Value| {
        let mut plaintext = stated();
        plaintext[key] = value;
        plaintext
    };
    let plaintexts = [
        without("name"),
        without("sites"),
        without("slots"),
        without("source"),
        with("name", json!("payment pin")),
        with("name", json!(7)),
        with("sites", json!([])),
        with("sites", json!(["Shop.example"])),
        with("sites", json!(["shop.example/login"])),
        with("sites", json!("everywhere")),
        // A host twice.
        with("sites", json!(["shop.example", "shop.example"])),
        with("slots", json!(["field", "field"])),
        with("slots", json!(["cookie:session"])),
        with(
            "slots",
            json!(["header:a", "path", "query:a", "form:a", "json:a"]),
        ),
        with("slots", json!("field")),
        // No slot, and the slot `field` next to a slot of a request: a record is typed into
        // pages or put into requests, and not both.
        with("slots", json!([])),
        with("slots", json!(["field", "header:authorization"])),
        with("slots", json!(["query:key", "field"])),
        // What the reader of a host and the reader of a slot refuse: a label that ends with
        // `-`, a header a node of the forward role writes itself, a JSON slot with an empty
        // key.
        with("sites", json!(["shop-.example"])),
        with("slots", json!(["field", "header:content-length"])),
        with("slots", json!(["field", "json:.token"])),
        with("source", json!("node")),
        json!(["PAYMENT_PIN", ["shop.example"], ["field"], "device"]),
        json!("493817"),
    ];
    for plaintext in plaintexts {
        let record = app.record("vault_secret", "vault", &plaintext);
        let outcome = release(&harness, &record, "value", "https://shop.example").await;
        assert_eq!(code(&outcome), (422, "record_invalid"), "{plaintext}");
    }
    // The form of a plaintext is judged before an entry is created.
    assert_eq!(harness.last_seq("user-1"), 1);

    // A member the release does not define is passed over.
    let record = app.record(
        "vault_secret",
        "vault",
        &with("note", json!({"created_ms": 1})),
    );
    let (status, released) = release(&harness, &record, "value", "https://shop.example").await;
    assert_eq!((status, &released["value"]), (200, &json!("493817")));

    // A record of another vault kind is not read as a named value, and a named value is not
    // read as a record of another kind: the kind is part of the AAD.
    let password = app.record("vault_password", "vault", &stated());
    let outcome = release(&harness, &password, "value", "https://shop.example").await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    let mut relabelled = named(&app, json!(["shop.example"]), json!(["field"]), "493817");
    relabelled["kind"] = json!("vault_password");
    let outcome = release(&harness, &relabelled, "password", "https://shop.example").await;
    assert_eq!(code(&outcome), (422, "record_invalid"));
}

#[tokio::test]
async fn the_value_of_a_named_value_is_judged_after_its_entry() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app) = node(&provider).await;
    let stated = plaintext(json!(["shop.example"]), json!(["field"]), "493817");
    let mut no_value = stated.clone();
    no_value.as_object_mut().unwrap().shift_remove("value");
    let mut no_string = stated.clone();
    no_string["value"] = json!(493817);
    let mut null = stated.clone();
    null["value"] = Value::Null;

    // A plaintext whose `value` cannot be handed out is refused like every other plaintext
    // where the reach refuses it, without an entry: the answer says nothing of the value.
    for plaintext in [&no_value, &no_string, &null] {
        let record = app.record("vault_secret", "vault", plaintext);
        let outcome = release(&harness, &record, "value", "https://other.example").await;
        assert_eq!(code(&outcome), (403, "not_allowed"), "{plaintext}");
    }
    assert_eq!(harness.last_seq("user-1"), 1);

    // Within the reach the call creates its entry, the store confirms it, and only then the
    // node reads the value: the call fails, nothing leaves, and the entry stays.
    for (index, plaintext) in [&no_value, &no_string, &null].into_iter().enumerate() {
        let record = app.record("vault_secret", "vault", plaintext);
        let outcome = release(&harness, &record, "value", "https://shop.example").await;
        assert_eq!(code(&outcome), (422, "record_invalid"), "{plaintext}");
        assert_eq!(outcome.1.as_object().unwrap().len(), 2);
        let seq = 2 + index as u64;
        assert_eq!(harness.last_seq("user-1"), seq);
        let event = app.logged(&harness, &provider, &json!({"seq": seq, "index": 0}));
        assert_eq!(
            (&event["t"], &event["record_id"], &event["name"]),
            (&json!("secret_released"), &record["id"], &json!(NAME))
        );
    }
    let account = harness.node.account("user-1").unwrap();
    assert_eq!(lock(&account).pending_entries(), 0);
}

#[tokio::test]
async fn a_named_value_does_not_leave_before_the_store_confirmed_its_entry() {
    let (provider, status) = store_with_status().await;
    let (harness, app) = node_without_repeated_writes(&provider).await;
    let record = named(&app, json!(["shop.example"]), json!(["field"]), "493817");

    status.store(403, Ordering::SeqCst);
    let outcome = release(&harness, &record, "value", "https://shop.example").await;
    assert_eq!(code(&outcome), (503, "log_store_unavailable"));
    assert!(!outcome.1.to_string().contains("493817"));
    // The entry is on the chain and waits for the store.
    assert_eq!(harness.last_seq("user-1"), 2);
    let account = harness.node.account("user-1").unwrap();
    assert_eq!(lock(&account).pending_entries(), 1);

    // The next call writes the pending entry along with its own and hands the value out.
    status.store(0, Ordering::SeqCst);
    let (status, released) = release(&harness, &record, "value", "https://shop.example").await;
    assert_eq!((status, &released["value"]), (200, &json!("493817")));
    assert_eq!(released["log"]["seq"], 3);
    assert_eq!(lock(&account).pending_entries(), 0);
}

/// The body of a `vault/store` call for the account of the tests.
fn stored(name: &str, sites: Value, slots: Value, value: &str) -> Value {
    json!({
        "user_id": "user-1", "name": name, "sites": sites, "slots": slots, "value": value,
        "context": "agent:signup",
    })
}

async fn store(harness: &Harness, body: Value) -> (u16, Value) {
    harness.post("/v1/vault/store", body).await
}

#[tokio::test]
async fn a_value_the_caller_gave_comes_back_as_a_record_that_release_opens() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app) = node(&provider).await;
    let body = stored(
        "SIGNUP_PASSWORD",
        json!(["shop.example"]),
        json!(["field"]),
        "tr0ub4dor&3",
    );
    let (status, response) = store(&harness, body).await;
    assert_eq!(status, 200, "{response}");
    let keys: Vec<&String> = response.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["record", "log"]);
    assert_eq!(
        response["log"],
        json!({"seq": 2, "index": 0, "created": true})
    );

    // The record is a record of the account under the key and the custody of its grant, of
    // kind `vault_secret`, with an `id` of 16 bytes and a nonce of 12 bytes.
    let record = &response["record"];
    assert_eq!(
        (&record["v"], &record["user_id"], &record["custody"]),
        (&json!(1), &json!("user-1"), &json!("operator"))
    );
    assert_eq!(record["key_id"], app.keys.key_id().as_str());
    assert_eq!(
        (&record["kind"], &record["provider"]),
        (&json!("vault_secret"), &json!("vault"))
    );
    assert_eq!(
        b64u_decode(record["id"].as_str().unwrap()).unwrap().len(),
        16
    );
    assert_eq!(
        b64u_decode(record["nonce"].as_str().unwrap())
            .unwrap()
            .len(),
        12
    );
    // Its plaintext is what the node wrote: the values of the call and the source `operator`.
    assert_eq!(
        app.open(record).to_string(),
        concat!(
            r#"{"value":"tr0ub4dor&3","name":"SIGNUP_PASSWORD","sites":["shop.example"],"#,
            r#""slots":["field"],"source":"operator"}"#
        )
    );
    assert!(!response.to_string().contains("tr0ub4dor"));

    // The event is a `connection_created` event, as `oauth/complete` creates one for the
    // record it hands out: the same five keys first, with the provider of a vault record and
    // the empty scope, then the kind, the name and the context. It says nothing of the value.
    let (keys, event) = keys_and_event(app.logged(&harness, &provider, &response["log"]));
    assert_eq!(
        keys,
        [
            "t",
            "time_ms",
            "record_id",
            "provider",
            "scope",
            "kind",
            "name",
            "context"
        ]
    );
    assert_eq!(
        event,
        json!({
            "t": "connection_created", "record_id": record["id"], "provider": "vault",
            "scope": "", "kind": "vault_secret", "name": "SIGNUP_PASSWORD",
            "context": "agent:signup",
        })
    );
    // Its entry is a control entry: it holds this one event, and its key names the event
    // under the prefix of the control entries of the account.
    let chain = provider.chain("user-1", &harness.node.node);
    let entry = chain.iter().find(|stored| stored.seq() == 2).unwrap();
    assert_eq!(
        entry.parts().label,
        EntryLabel::Control("connection_created".to_string())
    );
    assert!(entry.key.starts_with("a3/user-1/c/"), "{}", entry.key);

    // The same node opens the record: `release` hands the value out within its reach.
    let (status, released) = release(&harness, record, "value", "https://shop.example").await;
    assert_eq!((status, &released["value"]), (200, &json!("tr0ub4dor&3")));
    let event = app.logged(&harness, &provider, &released["log"]);
    assert_eq!(
        (&event["t"], &event["record_id"], &event["name"]),
        (
            &json!("secret_released"),
            &record["id"],
            &json!("SIGNUP_PASSWORD")
        )
    );
    let outcome = release(&harness, record, "value", "https://other.example").await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    assert_eq!(harness.last_seq("user-1"), 3);
}

#[tokio::test]
async fn the_node_chooses_the_id_and_the_nonce_of_a_stored_record() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let body = || {
        stored(
            "OPENAI_API_KEY",
            json!(["api.openai.com"]),
            json!(["header:authorization"]),
            "sk-live-value",
        )
    };

    // A body that names an `id` or a `nonce` is refused, whatever it names: the caller gives
    // neither.
    let named = [
        ("id", json!(b64u(&[7u8; 16]))),
        ("id", Value::Null),
        ("id", json!("")),
        ("nonce", json!(b64u(&[9u8; 12]))),
        ("nonce", Value::Null),
    ];
    for (key, value) in named {
        let mut body = body();
        body[key] = value.clone();
        let outcome = store(&harness, body).await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{key} {value}");
    }
    assert_eq!(harness.last_seq("user-1"), 1);

    // Two calls with the same body give two records, each with an `id` and a nonce of its
    // own and so with another ciphertext, that hold the same plaintext.
    let (status, first) = store(&harness, body()).await;
    assert_eq!(status, 200, "{first}");
    let (status, second) = store(&harness, body()).await;
    assert_eq!(status, 200, "{second}");
    let (first, second) = (&first["record"], &second["record"]);
    for key in ["id", "nonce", "ct"] {
        assert_ne!(first[key], second[key], "{key}");
    }
    assert_eq!(app.open(first), app.open(second));
    assert_eq!(harness.last_seq("user-1"), 3);

    // The node writes the provider, the custody and the source of the record, whatever the
    // body names for them.
    let mut body = body();
    for (key, value) in [
        ("source", json!("device")),
        ("kind", json!("vault_secret")),
        ("provider", json!("google_workspace")),
        ("custody", json!("enclave")),
        ("record", json!({"v": 1})),
    ] {
        body[key] = value;
    }
    let (status, response) = store(&harness, body).await;
    assert_eq!(status, 200, "{response}");
    let record = &response["record"];
    assert_eq!(
        (&record["kind"], &record["provider"], &record["custody"]),
        (&json!("vault_secret"), &json!("vault"), &json!("operator"))
    );
    assert_eq!(app.open(record), app.open(first));
    assert_eq!(app.open(record)["source"], "operator");
}

#[tokio::test]
async fn a_stored_record_lists_the_hosts_and_the_slots_of_the_call_as_they_were_given() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    // A slot is written as the string it was read from, a JSON slot with its keys joined by
    // `.` among them, and a host whose labels hold `-` inside is a host.
    let sites = json!(["api.my-shop.example", "xn--9n2bp8q.example"]);
    let slots = json!([
        "json:auth.token",
        "header:x-api-key",
        "query:service_Key",
        "path"
    ]);
    let body = stored(NAME, sites.clone(), slots.clone(), "sk-live-value");
    let (status, response) = store(&harness, body).await;
    assert_eq!(status, 200, "{response}");
    let plaintext = app.open(&response["record"]);
    assert_eq!((&plaintext["sites"], &plaintext["slots"]), (&sites, &slots));
}

#[tokio::test]
async fn a_body_that_has_not_the_form_of_vault_store_is_refused_and_creates_no_entry() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let valid = || stored(NAME, json!(["shop.example"]), json!(["field"]), "493817");
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
    let nine: Vec<String> = (0..9).map(|index| format!("h{index}.example")).collect();
    let five = json!(["header:a", "path", "query:a", "form:a", "json:a"]);
    let bodies = [
        ("no user_id", without("user_id")),
        ("no name", without("name")),
        ("a name in lower case", with("name", json!("payment_pin"))),
        (
            "a name that begins with a digit",
            with("name", json!("1PIN")),
        ),
        (
            "a name of 65 characters",
            with("name", json!(format!("P{}", "I".repeat(64)))),
        ),
        ("a name that is no string", with("name", json!(7))),
        ("no sites", without("sites")),
        ("sites that is null", with("sites", Value::Null)),
        ("no host", with("sites", json!([]))),
        ("nine hosts", with("sites", json!(nine))),
        (
            "a host with a capital",
            with("sites", json!(["Shop.example"])),
        ),
        (
            "a host with a path",
            with("sites", json!(["shop.example/login"])),
        ),
        (
            "a host with a port",
            with("sites", json!(["shop.example:443"])),
        ),
        ("an address for a host", with("sites", json!(["10.0.0.1"]))),
        ("a host of one label", with("sites", json!(["localhost"]))),
        (
            "a host whose label begins with -",
            with("sites", json!(["-shop.example"])),
        ),
        (
            "a host whose label ends with -",
            with("sites", json!(["shop.example", "pay-.example"])),
        ),
        (
            "a host whose last label begins with a digit",
            with("sites", json!(["shop.1example"])),
        ),
        ("another word than any", with("sites", json!("all"))),
        ("no slots", without("slots")),
        (
            "a slot of no form",
            with("slots", json!(["cookie:session"])),
        ),
        (
            "a header name with a capital",
            with("slots", json!(["header:Authorization"])),
        ),
        (
            "the slot of a header a node of the forward role writes itself",
            with("slots", json!(["header:host"])),
        ),
        (
            "the slot of a header a node of the forward role refuses",
            with("slots", json!(["field", "header:x-forwarded-host"])),
        ),
        (
            "a JSON slot with an empty key",
            with("slots", json!(["json:auth..token"])),
        ),
        (
            "a query slot whose name a query writes with an escape",
            with("slots", json!(["query:a:b"])),
        ),
        (
            "a form slot whose name a form writes with an escape",
            with("slots", json!(["field", "form:비밀번호"])),
        ),
        ("a slot twice", with("slots", json!(["field", "field"]))),
        ("five slots", with("slots", five)),
        ("no slot", with("slots", json!([]))),
        (
            "the slot field next to a slot of a request",
            with("slots", json!(["field", "header:authorization"])),
        ),
        (
            "a host twice",
            with("sites", json!(["shop.example", "shop.example"])),
        ),
        (
            "a kind the call does not make",
            with("kind", json!("vault_totp")),
        ),
        ("the kind of a token", with("kind", json!("oauth"))),
        ("a kind that is no kind", with("kind", json!("secret"))),
        ("a kind that is no string", with("kind", json!(7))),
        ("the empty kind", with("kind", json!(""))),
        (
            "the site of a password for a named value",
            with("site", json!("shop.example")),
        ),
        ("slots that is no array", with("slots", json!("field"))),
        ("no value", without("value")),
        ("an empty value", with("value", json!(""))),
        ("a value that is no string", with("value", json!(493817))),
        (
            "a value with the character U+0000",
            with("value", json!("49\u{0}3817")),
        ),
        (
            "a value of 12,001 bytes",
            with("value", json!("v".repeat(12_001))),
        ),
        (
            "a context of 257 characters",
            with("context", json!("c".repeat(257))),
        ),
    ];
    for (case, body) in bodies {
        let outcome = store(&harness, body).await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{case}");
        assert_eq!(outcome.1.as_object().unwrap().len(), 2, "{case}");
    }
    // A value for every host is a value for a field of a page and for nothing else.
    for slots in [
        json!(["header:authorization"]),
        json!(["field", "header:authorization"]),
        json!([]),
    ] {
        let body = stored(NAME, json!("any"), slots.clone(), "493817");
        let outcome = store(&harness, body).await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{slots}");
    }
    assert_eq!(harness.last_seq("user-1"), 1);

    // The plaintext of a record is at most 12,272 bytes, the value counted as its JSON
    // string. The plaintext of this body is 78 bytes and the JSON string of the value: a
    // line feed is two bytes of it.
    let sized = |line_feeds: usize| {
        let value = format!(
            "{}{}",
            "\n".repeat(line_feeds),
            "v".repeat(12_000 - line_feeds)
        );
        stored("K", json!(["a.io"]), json!(["field"]), &value)
    };
    let (status, largest) = store(&harness, sized(194)).await;
    assert_eq!(status, 200, "{largest}");
    let record = &largest["record"];
    assert_eq!(to_json(&app.open(record)).len(), 12_272);
    assert_eq!(record["ct"].as_str().unwrap().len(), 16_384);
    let outcome = store(&harness, sized(195)).await;
    assert_eq!(code(&outcome), (413, "too_large"));
    assert_eq!(
        outcome.1["message"],
        "the plaintext of the record is longer than 12,272 bytes"
    );
    let outcome = store(&harness, sized(12_000)).await;
    assert_eq!(code(&outcome), (413, "too_large"));
    // No refused call created an entry: the grant and the one record.
    assert_eq!(harness.last_seq("user-1"), 2);
}

#[tokio::test]
async fn a_stored_record_does_not_leave_before_the_store_confirmed_its_entry() {
    let (provider, status) = store_with_status().await;
    let (harness, app) = node_without_repeated_writes(&provider).await;
    let body = || stored(NAME, json!(["shop.example"]), json!(["field"]), "493817");

    status.store(403, Ordering::SeqCst);
    let outcome = store(&harness, body()).await;
    assert_eq!(code(&outcome), (503, "log_store_unavailable"));
    // The failure carries its code and its message, and no record.
    let keys: Vec<&String> = outcome.1.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["code", "message"]);
    // The entry is on the chain and waits for the store. The record it names was dropped
    // inside the node.
    assert_eq!(harness.last_seq("user-1"), 2);
    let account = harness.node.account("user-1").unwrap();
    assert_eq!(lock(&account).pending_entries(), 1);

    // The next call makes another record. Its write takes the pending entry along.
    status.store(0, Ordering::SeqCst);
    let (status, response) = store(&harness, body()).await;
    assert_eq!(status, 200, "{response}");
    assert_eq!(response["log"]["seq"], 3);
    assert_eq!(lock(&account).pending_entries(), 0);
    let events = app.stored_events(&harness, &provider);
    let stored: Vec<(&Value, &Value)> = events[1..]
        .iter()
        .map(|events| (&events[0]["t"], &events[0]["record_id"]))
        .collect();
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0].0, "connection_created");
    assert_ne!(stored[0].1, &response["record"]["id"]);
    assert_eq!(
        stored[1],
        (&json!("connection_created"), &response["record"]["id"])
    );
}

#[tokio::test]
async fn vault_store_passes_the_common_front_and_needs_no_operator_configuration() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    assert_eq!(harness.health().await["configured"], false);
    let body = || stored(NAME, json!(["shop.example"]), json!(["field"]), "493817");

    // An account without a grant on this node.
    assert_eq!(
        code(&store(&harness, body()).await),
        (409, "grant_required")
    );
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let (status, response) = store(&harness, body()).await;
    assert_eq!(status, 200, "{response}");
    // The call makes a record for the account it names, under the grant of that account.
    let mut other = body();
    other["user_id"] = json!("user-2");
    assert_eq!(code(&store(&harness, other).await), (409, "grant_required"));

    // After a revoke the node makes no record, and the record it made opens for no call.
    app.revoke(&harness).await;
    assert_eq!(code(&store(&harness, body()).await), (409, "grant_revoked"));
    let outcome = release(
        &harness,
        &response["record"],
        "value",
        "https://shop.example",
    )
    .await;
    assert_eq!(code(&outcome), (409, "grant_revoked"));

    // A closing node makes no record.
    assert_eq!(harness.post("/v1/close", json!({})).await.0, 200);
    assert_eq!(code(&store(&harness, body()).await), (503, "closing"));
    // The call reaches no provider.
    assert!(provider.seen().is_empty());
}

#[tokio::test]
async fn a_stored_record_without_the_slot_field_is_handed_out_by_no_call() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app) = node(&provider).await;
    let body = stored(
        "OPENAI_API_KEY",
        json!(["api.openai.com"]),
        json!(["header:authorization", "query:key"]),
        "sk-live-value",
    );
    let (status, response) = store(&harness, body).await;
    assert_eq!(status, 200, "{response}");
    let record = &response["record"];
    assert_eq!(
        app.open(record)["slots"],
        json!(["header:authorization", "query:key"])
    );

    for (field, origin) in [
        ("value", "https://api.openai.com"),
        ("header:authorization", "https://api.openai.com"),
        ("password", "https://api.openai.com"),
        ("value", "https://shop.example"),
    ] {
        let outcome = release(&harness, record, field, origin).await;
        assert_eq!(code(&outcome), (403, "not_allowed"), "{field} {origin}");
    }
    // The calls that use a token do not take the kind.
    let user = json!({"user_id": "user-1", "record": record, "context": "c"});
    for path in ["/v1/refresh", "/v1/revoke-token"] {
        let outcome = harness.post(path, user.clone()).await;
        assert_eq!(code(&outcome), (403, "not_allowed"), "{path}");
    }
    let merge = json!({"user_id": "user-1", "record": record, "previous": record});
    let outcome = harness.post("/v1/oauth/merge", merge).await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    let forward = json!({
        "user_id": "user-1", "record": record, "method": "GET",
        "url": "https://api.openai.com/v1/models", "headers": [], "context": "c",
        "timeout_ms": 5000,
    });
    let outcome = harness.forward(forward, b"").await.err().unwrap();
    assert_eq!(code(&outcome), (403, "not_allowed"));
    let batch = json!({
        "user_id": "user-1", "record": record, "context": "c", "timeout_ms": 5000,
        "requests": [{
            "method": "GET", "url": "https://api.openai.com/v1/models", "headers": [],
            "body_bytes": 0,
        }],
    });
    let outcome = harness.forward_batch(batch, b"").await.err().unwrap();
    assert_eq!(code(&outcome), (403, "not_allowed"));
    // The mail calls take an application password and no other kind.
    let message = &b"From: user@naver.com\r\nTo: friend@naver.com\r\n\r\ntext\r\n"[..];
    for (operation, request, payload) in [
        ("verify", json!({}), &b""[..]),
        ("read", json!({"action": "folders"}), &b""[..]),
        (
            "submit",
            json!({"recipients": ["friend@naver.com"]}),
            message,
        ),
    ] {
        let mut call = frame::encode_head(&json!({
            "user_id": "user-1", "record": record, "context": "c", "request": request,
        }));
        call.extend_from_slice(payload);
        let path = format!("/v1/mail/{operation}");
        let (status, _, body) = harness.send(Method::POST, &path, call).await;
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            (status.as_u16(), body["code"].as_str()),
            (403, Some("not_allowed")),
            "{operation}"
        );
    }
    // The grant and the entry of the record: no refused call left an entry, and no provider
    // received a request.
    assert_eq!(harness.last_seq("user-1"), 2);
    assert!(provider.requests().is_empty());
}

#[tokio::test]
async fn a_value_stored_for_every_host_is_released_for_any_origin() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let body = stored(
        "RESIDENT_NUMBER",
        json!("any"),
        json!(["field"]),
        "900101-1234567",
    );
    let (status, response) = store(&harness, body).await;
    assert_eq!(status, 200, "{response}");
    let record = &response["record"];
    assert_eq!(app.open(record)["sites"], "any");
    for origin in ["https://shop.example", "https://gov.example:8443"] {
        let (status, released) = release(&harness, record, "value", origin).await;
        assert_eq!(
            (status, &released["value"]),
            (200, &json!("900101-1234567")),
            "{origin}"
        );
    }
}

#[tokio::test]
async fn a_value_is_not_judged_while_the_store_has_not_confirmed_the_entry() {
    let (provider, status) = store_with_status().await;
    let (harness, app) = node_without_repeated_writes(&provider).await;
    // Two plaintexts a value cannot be taken from: a named value without its `value`, and a
    // seed that is not base32.
    let mut no_value = plaintext(json!(["shop.example"]), json!(["field"]), "493817");
    no_value.as_object_mut().unwrap().shift_remove("value");
    let calls = [
        (app.record("vault_secret", "vault", &no_value), "value"),
        (
            app.record("vault_totp", "vault", &json!({"value": "not base32!"})),
            "totp",
        ),
    ];

    // While the store does not confirm the entry of a call, the call says that and nothing
    // of the value: the plaintext is not read for it.
    status.store(403, Ordering::SeqCst);
    for (record, field) in &calls {
        let outcome = release(&harness, record, field, "https://shop.example").await;
        assert_eq!(code(&outcome), (503, "log_store_unavailable"), "{field}");
    }
    // Once the store confirms the entries, the same calls are judged by the value.
    status.store(0, Ordering::SeqCst);
    for (record, field) in &calls {
        let outcome = release(&harness, record, field, "https://shop.example").await;
        assert_eq!(code(&outcome), (422, "record_invalid"), "{field}");
    }
    assert_eq!(harness.last_seq("user-1"), 5);
    let account = harness.node.account("user-1").unwrap();
    assert_eq!(lock(&account).pending_entries(), 0);
}

/// The body of a `vault/store` call that asks for the record of a password.
fn stored_password(site: &str, value: &str) -> Value {
    json!({
        "user_id": "user-1", "kind": "vault_password", "site": site, "value": value,
        "context": "vault:generate-password",
    })
}

#[tokio::test]
async fn a_password_the_caller_gave_comes_back_as_a_record_that_says_who_made_it() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app) = node(&provider).await;
    let (status, response) =
        store(&harness, stored_password("shop.example", "c0rrect horse")).await;
    assert_eq!(status, 200, "{response}");
    let keys: Vec<&String> = response.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["record", "log"]);
    let record = &response["record"];
    assert_eq!(
        (&record["kind"], &record["provider"], &record["user_id"]),
        (&json!("vault_password"), &json!("vault"), &json!("user-1"))
    );
    // The plaintext is the value and the source `operator`: a record of this kind the device
    // of an account made has the one member `value`.
    assert_eq!(
        app.open(record).to_string(),
        r#"{"value":"c0rrect horse","source":"operator"}"#
    );
    assert!(!response.to_string().contains("c0rrect"));

    // The event is the `connection_created` event of a stored record, with the site the call
    // stated in the place of a name.
    let (keys, event) = keys_and_event(app.logged(&harness, &provider, &response["log"]));
    assert_eq!(
        keys,
        [
            "t",
            "time_ms",
            "record_id",
            "provider",
            "scope",
            "kind",
            "site",
            "context"
        ]
    );
    assert_eq!(
        event,
        json!({
            "t": "connection_created", "record_id": record["id"], "provider": "vault",
            "scope": "", "kind": "vault_password", "site": "shop.example",
            "context": "vault:generate-password",
        })
    );
    let chain = provider.chain("user-1", &harness.node.node);
    let entry = chain.iter().find(|stored| stored.seq() == 2).unwrap();
    assert_eq!(
        entry.parts().label,
        EntryLabel::Control("connection_created".to_string())
    );
    assert!(entry.key.starts_with("a3/user-1/c/"), "{}", entry.key);

    // `release` hands the value out as it hands out a password the user entered: the field
    // `password`, and no comparison of a host.
    for origin in ["https://shop.example", "https://login.other.example"] {
        let (status, released) = release(&harness, record, "password", origin).await;
        assert_eq!(
            (status, &released["value"]),
            (200, &json!("c0rrect horse")),
            "{origin}"
        );
        let event = app.logged(&harness, &provider, &released["log"]);
        assert_eq!(
            (&event["t"], &event["kind"], &event["field"]),
            (
                &json!("secret_released"),
                &json!("vault_password"),
                &json!("password")
            )
        );
        // The event of a record of this kind carries no name.
        assert!(event.get("name").is_none());
    }
    let outcome = release(&harness, record, "value", "https://shop.example").await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
}

#[tokio::test]
async fn a_body_that_has_not_the_form_of_a_stored_password_is_refused_and_creates_no_entry() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let valid = || stored_password("shop.example", "c0rrect horse");
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
    let bodies = [
        ("no site", without("site")),
        ("a site that is no string", with("site", json!(7))),
        ("a site that is null", with("site", Value::Null)),
        ("a site with a capital", with("site", json!("Shop.example"))),
        ("a site of one label", with("site", json!("localhost"))),
        ("an address for a site", with("site", json!("10.0.0.1"))),
        (
            "an origin for a site",
            with("site", json!("https://shop.example")),
        ),
        (
            "a site with a port",
            with("site", json!("shop.example:443")),
        ),
        ("a list of sites", with("site", json!(["shop.example"]))),
        // The keys of a named value: a password has a site and no reach of its own.
        ("a name", with("name", json!("SIGNUP_PASSWORD"))),
        ("a name that is null", with("name", Value::Null)),
        ("sites", with("sites", json!(["shop.example"]))),
        ("slots", with("slots", json!(["field"]))),
        ("an id", with("id", json!(b64u(&[7u8; 16])))),
        ("a nonce", with("nonce", json!(b64u(&[9u8; 12])))),
        ("no value", without("value")),
        ("an empty value", with("value", json!(""))),
        (
            "a value with the character U+0000",
            with("value", json!("c0rrect\u{0}horse")),
        ),
        (
            "a value of 12,001 bytes",
            with("value", json!("v".repeat(12_001))),
        ),
    ];
    for (case, body) in bodies {
        let outcome = store(&harness, body).await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{case}");
    }
    // The plaintext of a record is at most 12,272 bytes, the value counted as its JSON
    // string: the plaintext of a password is 32 bytes and that string.
    let sized = |quotes: usize| {
        let value = format!("{}{}", "\"".repeat(quotes), "v".repeat(12_000 - quotes));
        stored_password("shop.example", &value)
    };
    let (status, largest) = store(&harness, sized(240)).await;
    assert_eq!(status, 200, "{largest}");
    assert_eq!(to_json(&app.open(&largest["record"])).len(), 12_272);
    assert_eq!(code(&store(&harness, sized(241)).await), (413, "too_large"));
    // The grant and the one record: no refused call created an entry.
    assert_eq!(harness.last_seq("user-1"), 2);
}

/// The key pair a caller of `release` makes for one call, and its `seal_to`.
fn receiver(seed: u8) -> (Receiver, String) {
    let receiver = Receiver::from_random(&[seed; 32]);
    let seal_to = receiver.seal_to();
    (receiver, seal_to)
}

async fn release_sealed(
    harness: &Harness,
    record: &Value,
    field: &str,
    origin: &str,
    seal_to: &str,
) -> (u16, Value) {
    harness
        .post(
            "/v1/release",
            json!({
                "user_id": "user-1", "record": record, "field": field, "origin": origin,
                "seal_to": seal_to, "context": "browser:fill",
            }),
        )
        .await
}

/// Opens `sealed` of a response as the holder of the private key does, for the release of
/// `field` of `record` at `origin`.
fn opened(
    receiver: &Receiver,
    sealed: &Value,
    record: &Value,
    field: &str,
    origin: &str,
) -> Option<String> {
    let sealed: SealedValue = serde_json::from_value(sealed.clone()).unwrap();
    receiver
        .open(
            "user-1",
            record["id"].as_str().unwrap(),
            field,
            origin,
            &sealed,
        )
        .ok()
        .map(|plaintext| String::from_utf8(plaintext.to_vec()).unwrap())
}

#[tokio::test]
async fn a_release_that_names_a_key_hands_the_value_out_under_the_seal_of_that_key() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app) = node(&provider).await;
    let (private, seal_to) = receiver(0x41);
    let seed = "JBSWY3DPEHPK3PXP";
    let records = [
        (
            app.record("vault_password", "vault", &json!({"value": "hunter2 값"})),
            "password",
            "hunter2 값".to_string(),
        ),
        (
            app.record(
                "vault_card",
                "vault",
                &json!({"number": "4111111111111111", "cvc": "737"}),
            ),
            "card_number",
            "4111111111111111".to_string(),
        ),
        (
            app.record(
                "vault_card",
                "vault",
                &json!({"number": "4111111111111111", "cvc": "737"}),
            ),
            "card_cvc",
            "737".to_string(),
        ),
        (
            named(&app, json!(["shop.example"]), json!(["field"]), "493817"),
            "value",
            "493817".to_string(),
        ),
    ];
    let origin = "https://shop.example";
    for (record, field, value) in &records {
        let (status, released) = release_sealed(&harness, record, field, origin, &seal_to).await;
        assert_eq!(status, 200, "{released}");
        // The response carries `sealed` in the place of `value`, and the value is in none of
        // its bytes.
        let keys: Vec<&String> = released.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["sealed", "log"], "{field}");
        let sealed_keys: Vec<&String> = released["sealed"].as_object().unwrap().keys().collect();
        assert_eq!(sealed_keys, ["enc", "ct"]);
        assert!(!released.to_string().contains(value.as_str()), "{field}");
        // The holder of the private key opens it with the account, the record, the field and
        // the origin of the call, and with no other of them.
        assert_eq!(
            opened(&private, &released["sealed"], record, field, origin).as_deref(),
            Some(value.as_str()),
            "{field}"
        );
        assert_eq!(
            opened(
                &private,
                &released["sealed"],
                record,
                field,
                "https://other.example"
            ),
            None
        );
        assert_eq!(
            opened(&private, &released["sealed"], record, "other", origin),
            None
        );
        assert_eq!(
            opened(
                &receiver(0x42).0,
                &released["sealed"],
                record,
                field,
                origin
            ),
            None
        );
        // The entry of the release is the entry of a release without a key: the event says
        // nothing of the seal.
        let event = app.logged(&harness, &provider, &released["log"]);
        assert_eq!(
            (&event["t"], &event["field"], &event["origin"]),
            (&json!("secret_released"), &json!(field), &json!(origin))
        );
        assert!(event.get("seal_to").is_none());
    }

    // The code of a TOTP seed leaves under the seal as well, and the seed does not leave.
    let record = app.record("vault_totp", "vault", &json!({"value": seed}));
    let before_ms = harness.node.now_ms();
    let (status, released) = release_sealed(&harness, &record, "totp", origin, &seal_to).await;
    assert_eq!(status, 200, "{released}");
    let after_ms = harness.node.now_ms();
    let code = opened(&private, &released["sealed"], &record, "totp", origin).unwrap();
    assert!(
        [before_ms, after_ms]
            .iter()
            .any(|time_ms| totp(seed, *time_ms).unwrap() == code),
        "{code}"
    );
    assert!(!released.to_string().contains(seed));
    let event = app.logged(&harness, &provider, &released["log"]);
    assert_eq!(event["t"], "totp_issued");

    // Two releases of one value under one key are two ciphertexts.
    let (record, field, _) = &records[0];
    let (_, first) = release_sealed(&harness, record, field, origin, &seal_to).await;
    let (_, second) = release_sealed(&harness, record, field, origin, &seal_to).await;
    assert_ne!(first["sealed"]["enc"], second["sealed"]["enc"]);
    assert_ne!(first["sealed"]["ct"], second["sealed"]["ct"]);
}

#[tokio::test]
async fn a_release_with_a_key_that_is_no_key_is_refused_and_creates_no_entry() {
    let provider = quiet_provider_and_log_store().await;
    let (harness, app) = node(&provider).await;
    let record = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
    let (_, seal_to) = receiver(0x41);
    let not_keys = [
        json!(""),
        json!(b64u(&[0x51; 31])),
        json!(b64u(&[0x51; 33])),
        // A point of small order: HPKE cannot seal to it.
        json!(b64u(&[0u8; 32])),
        json!(format!("{seal_to}=")),
        json!("not base64url!"),
        json!(7),
        json!([seal_to]),
        json!({"key": seal_to}),
    ];
    for seal_to in not_keys {
        let outcome = harness
            .post(
                "/v1/release",
                json!({
                    "user_id": "user-1", "record": record, "field": "password",
                    "origin": "https://shop.example", "seal_to": seal_to, "context": "c",
                }),
            )
            .await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{seal_to}");
        assert_eq!(
            outcome.1["message"],
            "seal_to is invalid: base64url of an X25519 public key of 32 bytes"
        );
    }
    assert_eq!(harness.last_seq("user-1"), 1);

    // A key that is null is a call without a key.
    let (status, released) = harness
        .post(
            "/v1/release",
            json!({
                "user_id": "user-1", "record": record, "field": "password",
                "origin": "https://shop.example", "seal_to": null, "context": "c",
            }),
        )
        .await;
    assert_eq!((status, &released["value"]), (200, &json!("hunter2")));

    // What a call is refused for without a key it is refused for with one, and a value its
    // plaintext does not hold fails after the entry all the same.
    let (_, seal_to) = receiver(0x41);
    let outcome = release_sealed(&harness, &record, "totp", "https://shop.example", &seal_to).await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    assert_eq!(harness.last_seq("user-1"), 2);
    let empty = app.record("vault_password", "vault", &json!({"other": "x"}));
    let outcome = release_sealed(
        &harness,
        &empty,
        "password",
        "https://shop.example",
        &seal_to,
    )
    .await;
    assert_eq!(code(&outcome), (422, "record_invalid"));
    assert_eq!(outcome.1.as_object().unwrap().len(), 2);
    assert_eq!(harness.last_seq("user-1"), 3);
}

#[tokio::test]
async fn a_sealed_value_does_not_leave_before_the_store_confirmed_its_entry() {
    let (provider, status) = store_with_status().await;
    let (harness, app) = node_without_repeated_writes(&provider).await;
    let record = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
    let (private, seal_to) = receiver(0x41);
    let origin = "https://shop.example";

    status.store(403, Ordering::SeqCst);
    let outcome = release_sealed(&harness, &record, "password", origin, &seal_to).await;
    assert_eq!(code(&outcome), (503, "log_store_unavailable"));
    let keys: Vec<&String> = outcome.1.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["code", "message"]);

    status.store(0, Ordering::SeqCst);
    let (status, released) = release_sealed(&harness, &record, "password", origin, &seal_to).await;
    assert_eq!(status, 200, "{released}");
    assert_eq!(
        opened(&private, &released["sealed"], &record, "password", origin).as_deref(),
        Some("hunter2")
    );
}
