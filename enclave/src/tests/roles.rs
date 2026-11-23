//! The two roles of a node (protocol.md 4.1, enclave.md section 4): a node takes its role
//! once, a node of the forward role answers no call of the delegation role, and no delegation
//! moves to a node of the forward role.

use axum::http::Method;
use credential_enclave_protocol::encoding::{b64u, b64u_decode, to_json};
use credential_enclave_protocol::envelope::{seal_transfer, TransferGrant};
use credential_enclave_protocol::keys::{binding, forward_binding, Custody};
use credential_enclave_protocol::limits;
use credential_enclave_protocol::secret::Secret;
use serde_json::{json, Value};

use super::quiet_provider;
use crate::testing::{operator_config, App, Harness, Provider};

/// The calls a node of the forward role answers: the four calls of either role, and the one
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
    assert_eq!((status, configured), (200, json!({"configured": true})));
    harness
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

    // The one role a configuration names is `forward`, and a node of that role takes no
    // provider and no log store. A refused configuration changes nothing.
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
    assert_eq!((status, configured), (200, json!({"configured": true})));
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
    // delegation role is refused: the role does not change.
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
    ] {
        let outcome = harness.post("/v1/config", body.clone()).await;
        assert_eq!(code(&outcome), (400, "invalid_request"), "{body}");
    }
    assert_eq!(harness.health().await["role"], "forward");
    assert_eq!(harness.health().await["log_store"], Value::Null);
    assert_eq!(
        binding_of(&attestation(&harness).await),
        forward_binding(keys, "v0.0.0-test")
    );
}

#[tokio::test]
async fn a_node_of_the_forward_role_answers_no_call_of_the_delegation_role() {
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

    // Every call of the delegation role is refused the same way, whatever it carries. A
    // method a path does not accept is the failure it is on every node.
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
        assert_eq!(
            failure["message"],
            "the node has the forward role and takes no call of the delegation role"
        );
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

    // The node holds nothing of an account, and none of the refused calls closed it:
    // `close/heads` is a call of the delegation role, and `close` was not among them.
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

    // A call of the delegation role gives a node without a role the delegation role, also a
    // call that changes nothing.
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
    assert_eq!(giving.head_seq("user-1"), 1);

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
    assert_eq!(giving.head_seq("user-1"), 1);

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
