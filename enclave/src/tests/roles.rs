//! The three roles of a node (protocol.md 4.1, enclave.md section 4): a node takes its role
//! once. A node of the forward role answers no call of a node that holds delegations, and no
//! delegation moves to it. A node of the reserve role holds delegations, takes the commands
//! of the apps and gives and takes delegation transfers, and answers no call that uses a
//! credential.

use axum::http::Method;
use credential_enclave_protocol::app::read_node_document;
use credential_enclave_protocol::encoding::{b64u, b64u_decode, to_json};
use credential_enclave_protocol::envelope::{seal_transfer, TransferGrant};
use credential_enclave_protocol::keys::{
    binding, forward_binding, role_binding, Custody, LogStoreId, Role,
};
use credential_enclave_protocol::log::EntryLabel;
use credential_enclave_protocol::release::ReleaseMeasurement;
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::{limits, purpose};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

use super::{quiet_provider, quiet_provider_and_log_store};
use crate::api;
use crate::api::peer::{export_to, import_from};
use crate::attest::{Peer, Program};
use crate::log_store::sweep;
use crate::testing::{
    log_credentials, operator_config, App, Harness, Provider, LOG_BUCKET, LOG_HOST, LOG_REGION,
};

/// What a node of the forward role says to a call of a node that holds delegations and to a
/// call that uses a credential.
const FORWARD_REFUSAL: &str =
    "the node has the forward role: it holds no delegation and uses no credential";

/// The calls a node of the forward role answers: the four calls of every role, and the one
/// call of its own role.
const CALLS_OF_A_FORWARD_NODE: [&str; 5] = [
    "/v1/health",
    "/v1/config",
    "/v1/attestation",
    "/v1/close",
    "/v1/vault/send",
];

/// A node that took the forward role from its operator configuration.
async fn forward_node(provider: &Provider) -> Harness {
    let harness = Harness::new(provider);
    let (status, configured) = harness.post("/v1/config", json!({"role": "forward"})).await;
    assert_eq!((status, configured), (200, forward_configured()));
    harness
}

/// The answer to the configuration of a node of the forward role: the node has no log store,
/// so the store confirmed no node document of it.
fn forward_configured() -> Value {
    json!({"configured": true, "node_document_ms": 0})
}

/// The attestation response of a node.
async fn attestation(harness: &Harness) -> Value {
    let nonce = json!({"nonce": b64u(&[0x5a; 32])});
    let (status, response) = harness.post("/v1/attestation", nonce).await;
    assert_eq!(status, 200, "{response}");
    response
}

/// The binding inside the document of an attestation response of the local platform.
fn binding_of(response: &Value) -> Vec<u8> {
    let text = |value: &Value| b64u_decode(value.as_str().unwrap()).unwrap();
    let document: Value = serde_json::from_slice(&text(&response["document"])).unwrap();
    text(&document["binding"])
}

fn code(outcome: &(u16, Value)) -> (u16, &str) {
    (outcome.0, outcome.1["code"].as_str().unwrap_or_default())
}

#[tokio::test]
async fn a_node_takes_the_forward_role_once_and_names_it_in_its_binding() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let keys = &harness.node.keys;

    // A node that has no role yet: its binding is that of a node of the delegation role.
    assert_eq!(harness.health().await["role"], Value::Null);
    assert_eq!(
        binding_of(&attestation(&harness).await),
        binding(keys, "v0.0.0-test", None)
    );

    // A configuration names the role `reserve` or the role `forward`, and a node of the
    // forward role takes no provider and no log store. A refused configuration changes
    // nothing.
    for body in [
        json!({"role": "delegation"}),
        json!({"role": "Forward"}),
        json!({"role": ""}),
        json!({"role": 1}),
        json!({"role": ["forward"]}),
        json!({"role": "forward", "providers": operator_config(&harness.node.definitions)["providers"]}),
        json!({"role": "forward", "providers": []}),
        json!({"role": "forward", "log_store": {"bucket": "credential-log-test-1", "region": "us-west-2"}}),
    ] {
        let outcome = harness.post("/v1/config", body.clone()).await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{body}");
    }
    let health = harness.health().await;
    assert_eq!(
        (&health["role"], &health["configured"]),
        (&Value::Null, &json!(false))
    );

    let (status, configured) = harness.post("/v1/config", json!({"role": "forward"})).await;
    assert_eq!((status, configured), (200, forward_configured()));
    let health = harness.health().await;
    assert_eq!(health["role"], "forward");
    assert_eq!(health["configured"], true);
    assert_eq!(health["log_store"], Value::Null);
    // From that call on the binding of the node names the role, and no log store.
    let response = attestation(&harness).await;
    assert_eq!(binding_of(&response), forward_binding(keys, "v0.0.0-test"));
    assert_eq!(
        String::from_utf8(binding_of(&response)).unwrap(),
        format!(
            "{{\"v\":1,\"sign\":\"{}\",\"seal\":\"{}\",\"release\":\"v0.0.0-test\",\"role\":\"forward\"}}",
            b64u(&keys.sign_public()),
            b64u(&keys.seal_public())
        )
    );

    // The same configuration again leaves the node as it is. A configuration of the
    // delegation role or of the reserve role is refused: the role does not change.
    for body in [
        json!({"role": "forward"}),
        json!({"role": "forward", "providers": {}}),
    ] {
        assert_eq!(harness.post("/v1/config", body).await.0, 200);
    }
    let mut with_log_store = operator_config(&harness.node.definitions);
    with_log_store["log_store"] = json!({"bucket": "credential-log-test-1", "region": "us-west-2"});
    for body in [
        operator_config(&harness.node.definitions),
        json!({"providers": {}}),
        with_log_store,
        json!({"role": "reserve"}),
        json!({"role": "reserve", "log_store": {"bucket": LOG_BUCKET, "region": LOG_REGION}}),
    ] {
        let outcome = harness.post("/v1/config", body.clone()).await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{body}");
        assert_eq!(outcome.1["message"], "the node has the forward role");
    }
    assert_eq!(harness.health().await["role"], "forward");
    assert_eq!(harness.health().await["log_store"], Value::Null);
    assert_eq!(
        binding_of(&attestation(&harness).await),
        forward_binding(keys, "v0.0.0-test")
    );
}

#[tokio::test]
async fn a_node_of_the_forward_role_answers_no_call_of_a_node_that_holds_delegations() {
    let provider = quiet_provider().await;
    let forward = forward_node(&provider).await;

    // An app that ignores the role in the binding seals a grant to the keys of the node. The
    // node refuses the call before it opens the envelope: it holds no user key afterwards and
    // no state of the account.
    let app = App::new("user-1", 1);
    let attested = app.attest(&forward).await;
    let not_after_ms = forward.node.now_ms() + limits::GRANT_MAX_MS;
    let envelope = app.grant_envelope(&attested, not_after_ms);
    let outcome = forward
        .post(
            "/v1/messages",
            json!({"user_id": "user-1", "envelope": envelope}),
        )
        .await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    assert!(forward.node.account("user-1").is_none());

    // A transfer that is sealed to the keys of the node, with the signature of a node that
    // holds the grant of an account: the node does not open it either.
    let giving = Harness::new(&provider);
    App::new("user-2", 2).grant(&giving).await;
    let grant = TransferGrant {
        user_id: "user-2".to_string(),
        sign_pk: [3u8; 32],
        log_pk: App::new("user-2", 2).keys.log_pk(),
        custody: Custody::Operator,
        user_key: Secret::new([4u8; 32]),
        not_after_ms,
    };
    let transfer = seal_transfer(
        &giving.node.keys,
        &forward.node.keys.sign_public(),
        &forward.node.keys.seal_public(),
        giving.node.now_ms(),
        &[grant],
        &Secret::new([5u8; 32]),
    )
    .unwrap();
    let import = json!({"peer": attestation(&giving).await, "envelope": transfer});
    let outcome = forward.post("/v1/peer/import", import).await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    assert!(forward.node.account("user-2").is_none());

    // Every call of a node that holds delegations, and every call that uses a credential,
    // is refused the same way, whatever it carries. A method a path does not accept is the
    // failure it is on every node.
    let mut refused = 0;
    for (method, path) in crate::api::route_list() {
        if CALLS_OF_A_FORWARD_NODE.contains(&path) {
            continue;
        }
        let (status, _, bytes) = forward
            .send(method.clone(), path, to_json(&json!({"user_id": "user-1"})))
            .await;
        let failure: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            (status.as_u16(), failure["code"].as_str()),
            (403, Some("not_allowed")),
            "{method} {path}"
        );
        assert_eq!(failure["message"], FORWARD_REFUSAL);
        refused += 1;
    }
    assert_eq!(
        refused,
        crate::api::route_list().len() - CALLS_OF_A_FORWARD_NODE.len()
    );
    let (status, _, bytes) = forward.send(Method::GET, "/v1/status", Vec::new()).await;
    let failure: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        (status.as_u16(), failure["code"].as_str()),
        (405, Some("invalid_request"))
    );

    // The node holds nothing of an account, and none of the refused calls closed it: `close`
    // was not among them.
    let health = forward.health().await;
    assert_eq!(
        (&health["accounts"], &health["grants"], &health["closing"]),
        (&json!(0), &json!(0), &json!(false))
    );
    assert_eq!(health["log_store"], Value::Null);
}

#[tokio::test]
async fn a_node_that_took_a_call_of_the_delegation_role_does_not_take_the_forward_role() {
    let provider = quiet_provider().await;
    let forward_role = json!({"role": "forward"});

    // A call of a node that holds delegations gives a node without a role the delegation
    // role, also a call that changes nothing.
    let harness = Harness::new(&provider);
    let status = json!({"user_id": "user-1", "nonce": b64u(b"nonce")});
    assert_eq!(harness.post("/v1/status", status).await.0, 200);
    let outcome = harness.post("/v1/config", forward_role.clone()).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    assert_eq!(outcome.1["message"], "the node has the delegation role");

    // A node that holds the grant of an account.
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let outcome = harness.post("/v1/config", forward_role.clone()).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));

    // A node that took an operator configuration without a role.
    let harness = Harness::configured(&provider).await;
    let outcome = harness.post("/v1/config", forward_role).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));

    // Each of them is a node of the delegation role as before: its binding names no role, it
    // takes a grant, and the configuration of its own role is taken again.
    assert_eq!(harness.health().await["role"], Value::Null);
    assert_eq!(
        binding_of(&attestation(&harness).await),
        binding(&harness.node.keys, "v0.0.0-test", None)
    );
    app.grant(&harness).await;
    assert_eq!(harness.health().await["grants"], 1);
    let (status, _) = harness
        .post("/v1/config", operator_config(&harness.node.definitions))
        .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn a_node_of_the_delegation_role_hands_no_delegation_to_a_node_of_the_forward_role() {
    let provider = quiet_provider().await;
    let giving = Harness::new(&provider);
    let forward = forward_node(&provider).await;
    let other = Harness::new(&provider);
    App::new("user-1", 1).grant(&giving).await;
    assert_eq!(giving.last_seq("user-1"), 1);

    // The binding of the receiving node names the forward role: the export is refused before
    // an entry is created, with a subset as without one.
    let peer = attestation(&forward).await;
    for body in [
        json!({"peer": peer, "after": "", "limit": 1000}),
        json!({"peer": peer, "subset": {"pods": 1, "pod": 0, "copies": 1}}),
    ] {
        let outcome = giving.post("/v1/peer/export", body).await;
        assert_eq!(code(&outcome), (403, "peer_unverified"));
    }
    assert_eq!(giving.last_seq("user-1"), 1);

    // A node of the delegation role takes no transfer under the attestation of a node of the
    // forward role either.
    let (status, exported) = giving
        .post(
            "/v1/peer/export",
            json!({"peer": attestation(&other).await}),
        )
        .await;
    assert_eq!(status, 200, "{exported}");
    let import = json!({"peer": peer, "envelope": exported["envelope"]});
    let outcome = other.post("/v1/peer/import", import).await;
    assert_eq!(code(&outcome), (403, "peer_unverified"));
    assert_eq!(other.health().await["grants"], 0);
}

#[tokio::test]
async fn a_node_of_the_forward_role_has_no_log_store_and_writes_nothing_to_one() {
    // The stand-in answers for the host of the log store of the tests: a write of the node
    // would arrive there.
    let provider = quiet_provider_and_log_store().await;
    let forward = forward_node(&provider).await;

    // The node takes no credentials for a log store: the call is one of a node that holds
    // delegations.
    let expires_ms = forward.node.now_ms() + 60 * 60 * 1000;
    let outcome = forward
        .post("/v1/log-store/credentials", log_credentials(expires_ms))
        .await;
    assert_eq!(code(&outcome), (403, "not_allowed"));

    // Neither its configuration nor the sweep of the node writes a node document: the node
    // has no log store, its binding names none, and its health says so.
    sweep(&forward.node).await;
    let (status, configured) = forward.post("/v1/config", json!({"role": "forward"})).await;
    assert_eq!((status, configured), (200, forward_configured()));
    sweep(&forward.node).await;
    assert!(provider.seen().is_empty());
    assert!(forward
        .platform
        .connections()
        .iter()
        .all(|(host, _)| host != LOG_HOST));
    let health = forward.health().await;
    assert_eq!(health["log_store"], Value::Null);
    assert_eq!(
        (&health["log"]["writes"], &health["log"]["entries"]),
        (&json!(0), &json!(0))
    );
    assert_eq!(
        binding_of(&attestation(&forward).await),
        forward_binding(&forward.node.keys, "v0.0.0-test")
    );
}

#[tokio::test]
async fn a_transfer_without_an_entry_goes_to_no_node_of_the_forward_role() {
    // Two nodes of one program that write to the same log store, and a node of the forward
    // role of that program. A transfer between the first two creates no entry and writes
    // nothing to the store, so no entry stands between a delegation and a peer: the rule that
    // keeps a delegation from a node of the forward role is the reading of its binding.
    let provider = quiet_provider_and_log_store().await;
    let giving = Harness::new(&provider);
    let receiving = Harness::new(&provider);
    giving.use_log_store().await;
    receiving.use_log_store().await;
    let forward = forward_node(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&giving).await;
    assert_eq!(giving.last_seq("user-1"), 1);
    provider.until_written(1).await;

    // The node of the forward role: its binding names the role and no log store, and the
    // giving node has one. Each of the two refuses it as a peer (protocol.md 10.1, steps 3a
    // and 3b), and nothing was written for the refusal.
    let outcome = giving
        .post(
            "/v1/peer/export",
            json!({"peer": attestation(&forward).await}),
        )
        .await;
    assert_eq!(code(&outcome), (403, "peer_unverified"));

    // The node of the delegation role with the same log store takes the delegation, and
    // neither node creates an entry for it.
    let (status, exported) = giving
        .post(
            "/v1/peer/export",
            json!({"peer": attestation(&receiving).await}),
        )
        .await;
    assert_eq!(status, 200, "{exported}");
    assert_eq!(exported["logs"], json!([]));
    let import = json!({"peer": attestation(&giving).await, "envelope": exported["envelope"]});
    let (status, imported) = receiving.post("/v1/peer/import", import.clone()).await;
    assert_eq!(status, 200, "{imported}");
    assert_eq!(imported["accounts"], json!(["user-1"]));
    assert_eq!(imported["logs"], json!([]));
    assert_eq!(
        (giving.last_seq("user-1"), receiving.last_seq("user-1")),
        (1, 0)
    );
    assert_eq!(provider.stored().len(), 1);

    // The same envelope is nothing a node of the forward role opens: the call is refused by
    // the role of the node before the envelope is read.
    let outcome = forward.post("/v1/peer/import", import).await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    assert_eq!(forward.health().await["grants"], 0);
}

// ---------------------------------------------------------------------------------------
// The reserve role.

/// The calls a node of the reserve role answers: the four calls of every role and the six
/// calls of a node that holds delegations.
const CALLS_OF_A_RESERVE_NODE: [&str; 10] = [
    "/v1/health",
    "/v1/config",
    "/v1/attestation",
    "/v1/close",
    "/v1/messages",
    "/v1/status",
    "/v1/peer/export",
    "/v1/peer/import",
    "/v1/grants/prune",
    "/v1/log-store/credentials",
];

/// The calls that use a credential: the calls a node of the reserve role refuses, without
/// `vault/send`, which only a node of the forward role answers.
const CALLS_THAT_USE_A_CREDENTIAL: [&str; 13] = [
    "/v1/oauth/begin",
    "/v1/oauth/complete",
    "/v1/oauth/merge",
    "/v1/refresh",
    "/v1/revoke-token",
    "/v1/forward",
    "/v1/forward/batch",
    "/v1/mail/verify",
    "/v1/mail/read",
    "/v1/mail/submit",
    "/v1/release",
    "/v1/vault/store",
    "/v1/vault/handoff",
];

const RESERVE_REFUSAL: &str =
    "the node has the reserve role: it holds delegations and uses no credential";

/// The configuration of a node of the reserve role with the log store of the tests.
fn reserve_config() -> Value {
    json!({"role": "reserve", "log_store": {"bucket": LOG_BUCKET, "region": LOG_REGION}})
}

/// A node that took the reserve role from its operator configuration, without a log store.
async fn reserve_node(provider: &Provider) -> Harness {
    let harness = Harness::new(provider);
    let (status, configured) = harness.post("/v1/config", json!({"role": "reserve"})).await;
    assert_eq!(
        (status, configured),
        (200, json!({"configured": true, "node_document_ms": 0}))
    );
    harness
}

/// A node of the reserve role with the log store of the tests and credentials for it: the
/// call that gives the credentials writes the node document, so the node takes grants.
async fn reserve_node_with_log_store(provider: &Provider) -> Harness {
    let harness = Harness::new(provider);
    let (status, configured) = harness.post("/v1/config", reserve_config()).await;
    assert_eq!(
        (status, configured),
        (200, json!({"configured": true, "node_document_ms": 0}))
    );
    let expires_ms = harness.node.now_ms() + 12 * 60 * 60 * 1000;
    let (status, credentials) = harness
        .post("/v1/log-store/credentials", log_credentials(expires_ms))
        .await;
    assert_eq!(status, 200, "{credentials}");
    assert!(credentials["node_document_ms"].as_u64().unwrap() > 0);
    harness
}

/// The binding of a node of the reserve role with the log store of the tests.
fn reserve_binding(harness: &Harness) -> Vec<u8> {
    let log = LogStoreId::parse(LOG_BUCKET, LOG_REGION).unwrap();
    role_binding(&harness.node.keys, "v0.0.0-test", Some(&log), Role::Reserve)
}

async fn grant_state(harness: &Harness, user_id: &str) -> String {
    let (status, response) = harness
        .post("/v1/status", json!({"user_id": user_id}))
        .await;
    assert_eq!(status, 200, "{response}");
    response["grant"]["state"].as_str().unwrap().to_string()
}

/// Moves the delegations of `giving` to `receiving` in one page and returns the accounts the
/// import names: the accounts whose grant of the transfer the receiving node holds
/// afterwards. The two nodes run one program: neither call creates an entry.
async fn transfer(giving: &Harness, receiving: &Harness) -> Vec<String> {
    let (status, exported) = giving
        .post(
            "/v1/peer/export",
            json!({"peer": attestation(receiving).await}),
        )
        .await;
    assert_eq!(status, 200, "{exported}");
    assert_eq!(exported["logs"], json!([]));
    let import = json!({"peer": attestation(giving).await, "envelope": exported["envelope"]});
    let (status, imported) = receiving.post("/v1/peer/import", import).await;
    assert_eq!(status, 200, "{imported}");
    assert_eq!(imported["logs"], json!([]));
    let accounts = imported["accounts"].as_array().unwrap().iter();
    accounts
        .map(|user_id| user_id.as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn a_node_takes_the_reserve_role_once_and_names_it_in_its_binding() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let keys = &harness.node.keys;
    let providers = operator_config(&harness.node.definitions)["providers"].clone();

    // A configuration of the reserve role names the role and a log store, and no client
    // value of a provider. A refused configuration changes nothing: the node has no role
    // and no log store afterwards.
    for body in [
        json!({"role": "Reserve"}),
        json!({"role": "reserve "}),
        json!({"role": ["reserve"]}),
        json!({"role": "reserve", "providers": providers}),
        json!({"role": "reserve", "providers": []}),
        json!({"role": "reserve", "providers": "none"}),
        json!({"role": "reserve", "log_store": {"bucket": "B", "region": LOG_REGION}}),
        json!({"role": "reserve", "log_store": {"bucket": LOG_BUCKET}}),
        json!({"role": "reserve", "log_store": {"bucket": "b".repeat(50), "region": LOG_REGION}}),
        json!({"role": "reserve", "log_store": {
            "bucket": LOG_BUCKET, "region": LOG_REGION, "endpoint": "not an origin",
        }}),
    ] {
        let outcome = harness.post("/v1/config", body.clone()).await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{body}");
    }
    let health = harness.health().await;
    assert_eq!(
        (&health["role"], &health["configured"], &health["log_store"]),
        (&Value::Null, &json!(false), &Value::Null)
    );
    assert_eq!(
        binding_of(&attestation(&harness).await),
        binding(keys, "v0.0.0-test", None)
    );

    // The node takes the role with its log store. It holds no credentials for the store
    // yet, so the store confirmed no node document.
    let (status, configured) = harness.post("/v1/config", reserve_config()).await;
    assert_eq!(
        (status, configured),
        (200, json!({"configured": true, "node_document_ms": 0}))
    );
    let health = harness.health().await;
    assert_eq!(health["role"], "reserve");
    assert_eq!(health["configured"], true);
    assert_eq!(health["log_store"]["bucket"], LOG_BUCKET);
    // From that call on the binding names the log store and, behind it, the role.
    let response = attestation(&harness).await;
    assert_eq!(binding_of(&response), reserve_binding(&harness));
    assert_eq!(
        String::from_utf8(binding_of(&response)).unwrap(),
        format!(
            concat!(
                "{{\"v\":1,\"sign\":\"{}\",\"seal\":\"{}\",\"release\":\"v0.0.0-test\",",
                "\"log\":{{\"bucket\":\"credential-log-test-1\",\"region\":\"us-west-2\"}},",
                "\"role\":\"reserve\"}}"
            ),
            b64u(&keys.sign_public()),
            b64u(&keys.seal_public())
        )
    );

    // The same configuration again, and one that names the role alone, leave the node as it
    // is. Another log store is refused, and so is the configuration of another role: neither
    // the role nor the log store changes.
    for body in [
        reserve_config(),
        json!({"role": "reserve"}),
        json!({"role": "reserve", "providers": {}}),
    ] {
        assert_eq!(harness.post("/v1/config", body).await.0, 200);
    }
    let other_store =
        json!({"role": "reserve", "log_store": {"bucket": "another-log-1", "region": LOG_REGION}});
    let outcome = harness.post("/v1/config", other_store).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    assert_eq!(outcome.1["message"], "the node has another log store");
    for body in [
        operator_config(&harness.node.definitions),
        json!({"providers": {}}),
        json!({"role": "forward"}),
    ] {
        let outcome = harness.post("/v1/config", body.clone()).await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{body}");
        assert_eq!(outcome.1["message"], "the node has the reserve role");
    }
    assert_eq!(harness.health().await["role"], "reserve");
    assert_eq!(
        binding_of(&attestation(&harness).await),
        reserve_binding(&harness)
    );

    // A node of the reserve role without a log store: its binding ends with the role.
    let bare = reserve_node(&provider).await;
    assert_eq!(
        String::from_utf8(binding_of(&attestation(&bare).await)).unwrap(),
        format!(
            "{{\"v\":1,\"sign\":\"{}\",\"seal\":\"{}\",\"release\":\"v0.0.0-test\",\"role\":\"reserve\"}}",
            b64u(&bare.node.keys.sign_public()),
            b64u(&bare.node.keys.seal_public())
        )
    );
    assert_eq!(bare.health().await["log_store"], Value::Null);
}

#[tokio::test]
async fn the_first_call_that_only_a_node_that_holds_delegations_answers_decides_the_role() {
    let provider = quiet_provider().await;
    let reserve_role = json!({"role": "reserve"});

    // A call of a node that holds delegations, and a call that uses a credential, give a
    // node without a role the delegation role, also a call that fails or changes nothing.
    // Such a node takes neither the reserve role nor the forward role afterwards.
    for (path, body) in [
        ("/v1/status", json!({"user_id": "user-1"})),
        ("/v1/log-store/credentials", json!({})),
        ("/v1/grants/prune", json!({})),
        ("/v1/release", json!({"user_id": "user-1"})),
        ("/v1/oauth/begin", json!({})),
    ] {
        let harness = Harness::new(&provider);
        let _ = harness.post(path, body).await;
        for role in ["reserve", "forward"] {
            let outcome = harness.post("/v1/config", json!({"role": role})).await;
            assert_eq!(code(&outcome), (400, "invalid_request"), "{path} {role}");
            assert_eq!(
                outcome.1["message"], "the node has the delegation role",
                "{path} {role}"
            );
        }
        assert_eq!(harness.health().await["role"], Value::Null, "{path}");
    }
    // So does a node that took an operator configuration without a role, and a node that
    // holds the grant of an account.
    let configured = Harness::configured(&provider).await;
    let outcome = configured.post("/v1/config", reserve_role.clone()).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    let granted = Harness::new(&provider);
    App::new("user-1", 1).grant(&granted).await;
    let outcome = granted.post("/v1/config", reserve_role.clone()).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    assert_eq!(granted.health().await["grants"], 1);

    // A node of the forward role does not become a node of the reserve role.
    let forward = forward_node(&provider).await;
    let outcome = forward.post("/v1/config", reserve_role.clone()).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    assert_eq!(outcome.1["message"], "the node has the forward role");
    assert_eq!(forward.health().await["role"], "forward");

    // The calls of every role, and the call of the forward role that a node without that
    // role refuses, give a node no role: it takes the reserve role after them.
    let harness = Harness::new(&provider);
    harness.health().await;
    attestation(&harness).await;
    let outcome = harness.vault_send(json!({}), b"").await.unwrap_err();
    assert_eq!(code(&outcome), (403, "not_allowed"));
    let outcome = harness.post("/v1/config", json!({"role": "witness"})).await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    assert_eq!(harness.post("/v1/config", reserve_role).await.0, 200);
    assert_eq!(harness.health().await["role"], "reserve");
}

#[tokio::test]
async fn a_node_of_the_reserve_role_answers_no_call_that_uses_a_credential() {
    let provider = quiet_provider().await;
    let reserve = reserve_node(&provider).await;

    // The router has the calls of a node of the reserve role, the calls that use a
    // credential and the call of the forward role, and no other one.
    let routes = crate::api::route_list();
    let mut listed: Vec<&str> = CALLS_OF_A_RESERVE_NODE.to_vec();
    listed.extend(CALLS_THAT_USE_A_CREDENTIAL);
    listed.push("/v1/vault/send");
    listed.sort_unstable();
    let mut paths: Vec<&str> = routes.iter().map(|(_, path)| *path).collect();
    paths.sort_unstable();
    assert_eq!(paths, listed);

    let body = to_json(&json!({"user_id": "user-1"}));
    for (method, path) in routes {
        // The node closes with this call: it is the last one below.
        if path == "/v1/close" {
            continue;
        }
        let (status, _, bytes) = reserve.send(method.clone(), path, body.clone()).await;
        let answer: Value = serde_json::from_slice(&bytes).unwrap();
        let refused_by_role =
            (status.as_u16(), answer["code"].as_str()) == (403, Some("not_allowed"));
        match path {
            _ if CALLS_OF_A_RESERVE_NODE.contains(&path) => {
                assert!(!refused_by_role, "{method} {path}: {answer}");
            }
            // A call that uses a credential is refused before the node reads the request.
            _ if CALLS_THAT_USE_A_CREDENTIAL.contains(&path) => {
                assert!(refused_by_role, "{method} {path}: {answer}");
                assert_eq!(answer["message"], RESERVE_REFUSAL, "{path}");
            }
            // The call of the forward role.
            _ => {
                assert!(refused_by_role, "{method} {path}: {answer}");
                assert_eq!(
                    answer["message"],
                    "the call is a call of the forward role, and the node has not that role"
                );
            }
        }
    }
    // None of the refused calls left a state of the account behind, and the node took what
    // the other calls gave it: it answers `status`, and it closes.
    assert!(reserve.node.account("user-1").is_none());
    assert_eq!(grant_state(&reserve, "user-1").await, "none");
    let health = reserve.health().await;
    assert_eq!(
        (&health["role"], &health["closing"], &health["grants"]),
        (&json!("reserve"), &json!(false), &json!(0))
    );
    assert_eq!(reserve.post("/v1/close", json!({})).await.0, 200);
    assert_eq!(reserve.health().await["closing"], true);
    // No call made the node ask for a connection.
    assert!(reserve.platform.connections().is_empty());
    assert!(provider.seen().is_empty());
}

#[tokio::test]
async fn a_node_of_the_delegation_role_answers_every_call_but_the_call_of_the_forward_role() {
    let provider = quiet_provider().await;
    let harness = Harness::configured(&provider).await;
    let body = to_json(&json!({"user_id": "user-1"}));
    for (method, path) in crate::api::route_list() {
        // The node closes with this call.
        if path == "/v1/close" {
            continue;
        }
        let (status, _, bytes) = harness.send(method.clone(), path, body.clone()).await;
        let answer: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let refused_by_role =
            (status.as_u16(), answer["code"].as_str()) == (403, Some("not_allowed"));
        assert_eq!(
            refused_by_role,
            path == "/v1/vault/send",
            "{method} {path}: {answer}"
        );
    }
    assert_eq!(harness.health().await["role"], Value::Null);
}

#[tokio::test]
async fn a_node_of_the_reserve_role_takes_the_commands_of_an_app_and_writes_control_entries() {
    let provider = quiet_provider_and_log_store().await;
    let reserve = reserve_node_with_log_store(&provider).await;
    let node = reserve.node.node.clone();

    // The node document the store holds attests the binding of the node: the log store and
    // the role `reserve`.
    let documents = provider.documents();
    assert_eq!(documents.len(), 1);
    let facts = read_node_document(&to_json(&documents[0].document), &node, &[]).unwrap();
    assert_eq!(facts.binding.role, Role::Reserve);
    assert_eq!(
        facts.binding.log,
        Some(LogStoreId::parse(LOG_BUCKET, LOG_REGION).unwrap())
    );
    assert_eq!(documents[0].node, node);

    // The grant command of an app: the node holds the delegation, and the entry of the
    // command is in the store.
    let app = App::new("user-1", 1);
    let granted = app.grant(&reserve).await;
    assert_eq!(
        granted["log"],
        json!({"seq": 1, "index": 0, "created": true})
    );
    assert_eq!(grant_state(&reserve, "user-1").await, "active");
    assert_eq!(reserve.health().await["grants"], 1);
    assert_eq!(
        app.logged(&reserve, &provider, &granted["log"])["t"],
        "grant_accepted"
    );

    // The revoke command: the node drops the user key and writes the entry of the revoke.
    let revoked = app.revoke(&reserve).await;
    let reply = reserve.verified(purpose::REPLY, &revoked["reply"]);
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(grant_state(&reserve, "user-1").await, "revoked");
    assert_eq!(
        app.logged(&reserve, &provider, &revoked["log"])["t"],
        "grant_revoked"
    );
    assert_eq!(reserve.health().await["grants"], 0);

    // What the node wrote to its log store: its node document and two control entries.
    let stored = provider.chain("user-1", &node);
    let labels: Vec<EntryLabel> = stored
        .iter()
        .map(|entry| entry.parts().label.clone())
        .collect();
    assert_eq!(
        labels,
        [
            EntryLabel::Control("grant_accepted".to_string()),
            EntryLabel::Control("grant_revoked".to_string()),
        ]
    );
    let health = reserve.health().await;
    assert_eq!(
        (
            &health["log"]["entries"],
            &health["log"]["events"],
            &health["log"]["writes"]
        ),
        (&json!(2), &json!(2), &json!(3))
    );
    // Every connection the node asked for went to its log store.
    let connections = reserve.platform.connections();
    assert!(!connections.is_empty());
    assert!(connections
        .iter()
        .all(|(host, port)| host == LOG_HOST && *port == 443));
}

#[tokio::test(start_paused = true)]
async fn a_node_of_the_reserve_role_answers_a_call_that_uses_a_credential_before_its_body() {
    let provider = quiet_provider().await;
    let reserve = reserve_node(&provider).await;
    let delegation = Harness::new(&provider);

    // The head of a `forward` call that announces a body of the body limit, 64 MiB, on a
    // connection the node serves as it serves an accepted one. No byte of the body follows.
    let head = b"POST /v1/forward HTTP/1.1\r\nHost: node\r\nContent-Length: 67108864\r\n\r\n";
    let answer = |harness: &Harness| {
        let (near, mut far) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn(api::serve_connection(
            near,
            api::router(harness.node.clone()),
            harness.node.limits.inbound_idle,
        ));
        async move {
            far.write_all(head).await.unwrap();
            let asked = Instant::now();
            let mut response = Vec::new();
            while !response.ends_with(b"\r\n\r\n") {
                response.push(far.read_u8().await.unwrap());
            }
            let head = String::from_utf8(response).unwrap();
            let status: u16 = head[9..12].parse().unwrap();
            drop(far);
            served.await.unwrap();
            (status, asked.elapsed())
        }
    };

    // The node of the reserve role refuses the call at once: it waits for no byte of the
    // body, so what a caller sends as the body of a call that uses a credential is nothing
    // the node reads.
    let (status, waited) = answer(&reserve).await;
    assert_eq!(status, 403);
    assert_eq!(waited, std::time::Duration::ZERO);
    // A node of the delegation role reads the frame of the call: it waits for the body for
    // the time limit of the bytes of a body, and then fails the call.
    let (status, waited) = answer(&delegation).await;
    assert_eq!(status, 400);
    assert_eq!(waited, delegation.node.limits.inbound_idle);
}

#[tokio::test]
async fn a_node_of_the_reserve_role_creates_no_event_for_a_call_that_uses_a_credential() {
    let provider = quiet_provider_and_log_store().await;
    let calls = Harness::new(&provider);
    calls.use_log_store().await;
    let reserve = reserve_node_with_log_store(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&calls).await;
    // The node of the reserve role takes the delegation from the node of the delegation
    // role: it holds the user key of the account, and it created no entry for it.
    assert_eq!(transfer(&calls, &reserve).await, ["user-1"]);
    assert_eq!(grant_state(&reserve, "user-1").await, "active");
    assert_eq!(
        (calls.last_seq("user-1"), reserve.last_seq("user-1")),
        (1, 0)
    );

    // A record of the account that a node of the delegation role opens: the release of its
    // value is an event on the log of the account.
    let record = app.record("vault_password", "vault", &json!({"value": "hunter2"}));
    let release = json!({
        "user_id": "user-1", "record": record, "field": "password",
        "origin": "https://site.example", "context": "browser:fill",
    });
    let (status, released) = calls.post("/v1/release", release.clone()).await;
    assert_eq!((status, &released["value"]), (200, &json!("hunter2")));
    assert_eq!(calls.last_seq("user-1"), 2);

    // The node of the reserve role holds the same user key and refuses the same call. It
    // creates no event and writes nothing, and the account is as it was.
    let writes_before = provider.seen().len();
    let health_before = reserve.health().await;
    let outcome = reserve.post("/v1/release", release.clone()).await;
    assert_eq!(code(&outcome), (403, "not_allowed"));
    assert_eq!(outcome.1["message"], RESERVE_REFUSAL);
    // Every other call that uses a credential, with the record and the names a call of its
    // kind carries.
    let body = json!({
        "user_id": "user-1", "record": record, "previous": record, "field": "password",
        "origin": "https://site.example", "provider": "google_workspace", "state": "state",
        "code": "code", "name": "API_KEY", "sites": "any", "slots": ["field"], "value": "v",
        "context": "context",
    });
    for path in CALLS_THAT_USE_A_CREDENTIAL {
        let (status, _, bytes) = reserve.send(Method::POST, path, to_json(&body)).await;
        let failure: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            (status.as_u16(), failure["code"].as_str()),
            (403, Some("not_allowed")),
            "{path}"
        );
    }
    // A frame of `forward`, as a node of the delegation role takes it.
    let meta = json!({
        "user_id": "user-1", "record": record, "method": "GET",
        "url": "https://gmail.googleapis.com/gmail/v1/users/me/messages", "headers": [],
        "context": "context", "timeout_ms": 5000,
    });
    let outcome = reserve.forward(meta, b"").await.err();
    assert_eq!(outcome.as_ref().map(code), Some((403, "not_allowed")));

    let health = reserve.health().await;
    for key in ["log", "state", "egress", "refresh"] {
        assert_eq!(health[key], health_before[key], "{key}");
    }
    assert_eq!(
        (&health["log"]["entries"], &health["log"]["events"]),
        (&json!(0), &json!(0))
    );
    assert_eq!(health["log_store"]["pending"], 0);
    assert_eq!(
        (&health["grants"], &health["accounts"]),
        (&json!(1), &json!(0))
    );
    assert_eq!(reserve.last_seq("user-1"), 0);
    assert_eq!(provider.seen().len(), writes_before);
    assert!(provider.chain("user-1", &reserve.node.node).is_empty());
    // The one host the node asked for a connection to is its log store, for its node
    // document.
    assert!(reserve
        .platform
        .connections()
        .iter()
        .all(|(host, port)| host == LOG_HOST && *port == 443));
    // The delegation is still there: the node hands it back to a node that uses it.
    let other = Harness::new(&provider);
    other.use_log_store().await;
    assert_eq!(transfer(&reserve, &other).await, ["user-1"]);
    let (status, released) = other.post("/v1/release", release).await;
    assert_eq!((status, &released["value"]), (200, &json!("hunter2")));
}

#[tokio::test]
async fn delegations_move_among_the_nodes_that_hold_them_and_to_no_node_of_the_forward_role() {
    let provider = quiet_provider().await;
    let calls = [Harness::new(&provider), Harness::new(&provider)];
    let reserve = [reserve_node(&provider).await, reserve_node(&provider).await];
    let forward = forward_node(&provider).await;

    // An account granted on a node of the delegation role moves to a node of the reserve
    // role, from there to another node of the reserve role, from there to a node of the
    // delegation role, and each of them holds it afterwards.
    let app = App::new("user-1", 1);
    app.grant(&calls[0]).await;
    for (giving, receiving) in [
        (&calls[0], &reserve[0]),
        (&reserve[0], &reserve[1]),
        (&reserve[1], &calls[1]),
    ] {
        assert_eq!(transfer(giving, receiving).await, ["user-1"]);
        assert_eq!(grant_state(receiving, "user-1").await, "active");
    }
    // An account that granted on a node of the reserve role moves to a node of the
    // delegation role the same way.
    // The receiving node holds the grant of user-1 already: the answer names both accounts.
    App::new("user-2", 2).grant(&reserve[0]).await;
    assert_eq!(transfer(&reserve[0], &calls[0]).await, ["user-1", "user-2"]);
    for node in calls.iter().chain(&reserve) {
        assert_eq!(grant_state(node, "user-1").await, "active");
    }

    // No node that holds delegations hands one to a node of the forward role, and none
    // takes a transfer under the attestation of such a node.
    let to_forward = attestation(&forward).await;
    for giving in [&calls[0], &reserve[0]] {
        let outcome = giving
            .post("/v1/peer/export", json!({"peer": to_forward}))
            .await;
        assert_eq!(code(&outcome), (403, "peer_unverified"));
        let (status, exported) = giving
            .post(
                "/v1/peer/export",
                json!({"peer": attestation(&reserve[1]).await}),
            )
            .await;
        assert_eq!(status, 200, "{exported}");
        let import = json!({"peer": to_forward, "envelope": exported["envelope"]});
        for receiving in [&calls[1], &reserve[1]] {
            let outcome = receiving.post("/v1/peer/import", import.clone()).await;
            assert_eq!(code(&outcome), (403, "peer_unverified"));
        }
        // The node of the forward role refuses the call by its role.
        let import = json!({"peer": attestation(giving).await, "envelope": exported["envelope"]});
        let outcome = forward.post("/v1/peer/import", import).await;
        assert_eq!(code(&outcome), (403, "not_allowed"));
    }
    assert_eq!(forward.health().await["grants"], 0);
    assert!(forward.node.account("user-1").is_none());
}

#[tokio::test]
async fn a_node_of_the_reserve_role_takes_and_gives_the_transfers_of_another_release() {
    let provider = quiet_provider_and_log_store().await;
    let earlier = Harness::new(&provider);
    earlier.use_log_store().await;
    let reserve = reserve_node_with_log_store(&provider).await;
    let later = Harness::new(&provider);
    later.use_log_store().await;
    let app = App::new("user-1", 1);
    app.grant(&earlier).await;
    let release = |release: &str, pcr: u8| ReleaseMeasurement {
        release: release.to_string(),
        pcrs: [[pcr; 48], [pcr + 1; 48], [pcr + 2; 48]],
    };
    let as_release = |harness: &Harness, release: &str| {
        Peer::accepted_for_tests(&harness.node.keys, Program::Release(release.to_string()))
    };

    // A node of an earlier release hands the delegation to the node of the reserve role
    // under the statement of its release: the transfer is on the log of the account on both
    // nodes, and the entry of the node of the reserve role is a control entry.
    let statement = release("v9.0.0", 0x11);
    let exported = export_to(
        &earlier.node,
        &as_release(&reserve, "v9.0.0"),
        Some(&statement),
        "",
        1000,
        None,
    )
    .await
    .unwrap();
    let envelope = serde_json::to_value(&exported.envelope).unwrap();
    let imported = import_from(
        &reserve.node,
        &as_release(&earlier, "v2.3.0"),
        &envelope,
        None,
    )
    .await
    .unwrap();
    assert_eq!(imported.accounts, ["user-1"]);
    assert_eq!(grant_state(&reserve, "user-1").await, "active");
    let taken = app.logged(&reserve, &provider, &json!({"seq": 1, "index": 0}));
    assert_eq!(
        (&taken["t"], &taken["from"], &taken["release"]),
        (
            &json!("grant_transferred_in"),
            &json!(earlier.node.node),
            &json!("v2.3.0")
        )
    );

    // The node of the reserve role hands the delegation on to a node of a later release:
    // the entry that names that node, its release and its measurement is in the store
    // before the grant leaves.
    let statement = release("v9.1.0", 0x21);
    let exported = export_to(
        &reserve.node,
        &as_release(&later, "v9.1.0"),
        Some(&statement),
        "",
        1000,
        None,
    )
    .await
    .unwrap();
    assert!(exported.envelope.is_some());
    let given = app.logged(&reserve, &provider, &json!({"seq": 2, "index": 0}));
    assert_eq!(
        (&given["t"], &given["to"], &given["release"]),
        (
            &json!("grant_transferred_out"),
            &json!(later.node.node),
            &json!("v9.1.0")
        )
    );
    // Both entries of the node of the reserve role are control entries.
    let labels: Vec<EntryLabel> = provider
        .chain("user-1", &reserve.node.node)
        .iter()
        .map(|entry| entry.parts().label.clone())
        .collect();
    assert_eq!(
        labels,
        [
            EntryLabel::Control("grant_transferred_in".to_string()),
            EntryLabel::Control("grant_transferred_out".to_string()),
        ]
    );
}
