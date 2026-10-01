//! OAuth against a provider stand-in (enclave.md 5.5 to 5.7 and section 6): exchange, refresh,
//! reconnect merge, the nested token place of slack with its `ok: false`, and the public
//! fields.

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use credential_enclave_protocol::encoding::b64u;
use credential_enclave_protocol::keys::Custody;
use credential_enclave_protocol::{limits, purpose};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{provider, quiet_provider};
use crate::state::{lock, ActiveGrant, GrantState};
use crate::testing::{operator_config, App, Harness, Reply, Seen};

fn jwt(claims: &Value) -> String {
    format!(
        "{}.{}.signature",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

fn google_token() -> Value {
    json!({
        "access_token": "ya29.first-access",
        "expires_in": 3599,
        "refresh_token": "1//first-refresh",
        "scope": "openid https://www.googleapis.com/auth/gmail.readonly",
        "token_type": "Bearer",
        "id_token": jwt(&json!({
            "iss": "https://accounts.google.com", "sub": "1099", "email": "a@example.com",
            "email_verified": true, "at_hash": "hash-value", "name": "A", "picture": "https://p/x",
        })),
        "refresh_token_expires_in": 604799,
    })
}

async fn begin(
    harness: &Harness,
    user_id: &str,
    provider: &str,
    params: Value,
    client_id: &str,
) -> (u16, Value) {
    harness
        .post(
            "/v1/oauth/begin",
            json!({
                "user_id": user_id, "provider": provider, "operator_state": "operator.state_1-x",
                "params": params, "client_id": client_id,
            }),
        )
        .await
}

async fn complete(harness: &Harness, user_id: &str, state: &str) -> (u16, Value) {
    harness
        .post(
            "/v1/oauth/complete",
            json!({"user_id": user_id, "state": state, "code": "4/authorization-code"}),
        )
        .await
}

fn query(url: &str) -> Vec<(String, String)> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn query_value(url: &str, key: &str) -> Option<String> {
    query(url)
        .into_iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

fn code(outcome: &(u16, Value)) -> (u16, &str) {
    (outcome.0, outcome.1["code"].as_str().unwrap_or_default())
}

#[tokio::test]
async fn a_google_connection_is_issued_inside_the_node_with_pkce() {
    let provider = provider(|seen| match seen.target.as_str() {
        "/token" => Reply::json(200, &google_token()),
        _ => Reply::json(404, &json!({})),
    })
    .await;
    let harness = Harness::configured(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;

    let now_ms = harness.node.now_ms();
    let (status, started) = begin(
        &harness,
        "user-1",
        "google_workspace",
        json!({"scope": "openid https://www.googleapis.com/auth/gmail.readonly", "access_type": "offline", "prompt": "consent select_account"}),
        "",
    )
    .await;
    assert_eq!(status, 200, "{started}");
    let url = started["authorization_url"].as_str().unwrap();
    let state = started["state"].as_str().unwrap();
    let (node_state, operator_state) = state.split_once('.').unwrap();
    assert_eq!(node_state.len(), 22);
    assert_eq!(operator_state, "operator.state_1-x");
    let names: Vec<String> = query(url).into_iter().map(|(name, _)| name).collect();
    assert_eq!(
        names,
        [
            "response_type",
            "client_id",
            "redirect_uri",
            "state",
            "code_challenge",
            "code_challenge_method",
            "access_type",
            "prompt",
            "scope",
        ]
    );
    assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=google_workspace-client&redirect_uri=https%3A%2F%2Fapi.example%2Fapi%2Fintegrations%2Fgoogle_workspace%2Foauth%2Fcallback&state="));
    assert!(url.ends_with("&code_challenge_method=S256&access_type=offline&prompt=consent%20select_account&scope=openid%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.readonly"));
    assert_eq!(query_value(url, "state").as_deref(), Some(state));
    let expires_ms = started["expires_ms"].as_u64().unwrap();
    assert!(
        (now_ms + limits::PENDING_AUTH_MS..now_ms + limits::PENDING_AUTH_MS + 5_000)
            .contains(&expires_ms)
    );

    // The statement binds the address to the node, the account key and the state.
    let statement = harness.verified(purpose::STATEMENT, &started["statement"]);
    assert_eq!(statement["type"], "oauth_begin");
    assert_eq!(statement["node"], harness.node.node.as_str());
    assert_eq!(statement["user_id"], "user-1");
    assert_eq!(statement["key_id"], app.keys.key_id().as_str());
    assert_eq!(statement["sign_pk"], b64u(&app.keys.sign_pk()));
    assert_eq!(statement["provider"], "google_workspace");
    assert_eq!(statement["state"], state);
    assert_eq!(
        statement["url_sha256"],
        b64u(&Sha256::digest(url.as_bytes()))
    );

    // The exchange: the node sends the verifier that matches the challenge of the address.
    let (status, issued) = complete(&harness, "user-1", state).await;
    assert_eq!(status, 200, "{issued}");
    let exchange = provider.only();
    assert_eq!(exchange.server_name, "oauth2.googleapis.com");
    assert_eq!(
        (exchange.method.as_str(), exchange.target.as_str()),
        ("POST", "/token")
    );
    assert_eq!(exchange.header("host"), Some("oauth2.googleapis.com"));
    assert_eq!(
        exchange.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(exchange.header("authorization"), None);
    let fields: Vec<String> = exchange.form().into_iter().map(|(name, _)| name).collect();
    assert_eq!(
        fields,
        [
            "grant_type",
            "code",
            "redirect_uri",
            "code_verifier",
            "client_id",
            "client_secret"
        ]
    );
    assert_eq!(
        exchange.form_value("grant_type").as_deref(),
        Some("authorization_code")
    );
    assert_eq!(
        exchange.form_value("code").as_deref(),
        Some("4/authorization-code")
    );
    assert_eq!(
        exchange.form_value("redirect_uri").as_deref(),
        Some("https://api.example/api/integrations/google_workspace/oauth/callback")
    );
    assert_eq!(
        exchange.form_value("client_id").as_deref(),
        Some("google_workspace-client")
    );
    assert_eq!(
        exchange.form_value("client_secret").as_deref(),
        Some("google_workspace-secret")
    );
    let verifier = exchange.form_value("code_verifier").unwrap();
    assert_eq!(verifier.len(), 43);
    assert_eq!(
        query_value(url, "code_challenge").unwrap(),
        b64u(&Sha256::digest(verifier.as_bytes()))
    );

    // The record holds the whole token response, under the user key.
    let record = &issued["record"];
    assert_eq!(record["v"], 1);
    assert_eq!(record["user_id"], "user-1");
    assert_eq!(record["key_id"], app.keys.key_id().as_str());
    assert_eq!(record["custody"], "operator");
    assert_eq!(record["kind"], "oauth");
    assert_eq!(record["provider"], "google_workspace");
    assert_eq!(record["id"].as_str().unwrap().len(), 22);
    let plaintext = app.open(record);
    assert_eq!(plaintext["token"], google_token());
    let obtained_ms = plaintext["obtained_ms"].as_u64().unwrap();
    assert!(obtained_ms >= now_ms);
    assert!(plaintext.get("client_id").is_none());

    // The public fields carry the listed values and nothing else.
    assert_eq!(
        issued["public"],
        json!({
            "token": {
                "scope": "openid https://www.googleapis.com/auth/gmail.readonly",
                "expires_in": 3599,
                "token_type": "Bearer",
            },
            "id_token_claims": {
                "sub": "1099", "email": "a@example.com", "email_verified": true,
                "name": "A", "picture": "https://p/x",
            },
            "obtained_ms": obtained_ms,
            "has_refresh_token": true,
        })
    );
    let whole = issued.to_string();
    for secret in [
        "ya29.first-access",
        "1//first-refresh",
        "hash-value",
        "refresh_token_expires_in",
        "signature",
        verifier.as_str(),
        "google_workspace-secret",
        "4/authorization-code",
    ] {
        assert!(!whole.contains(secret), "{secret}");
    }
    assert!(!started.to_string().contains(&verifier));

    // The completion statement and the entry name the record.
    let statement = harness.verified(purpose::STATEMENT, &issued["statement"]);
    assert_eq!(statement["type"], "oauth_complete");
    assert_eq!(statement["state"], state);
    assert_eq!(statement["record_id"], record["id"]);
    assert_eq!(statement["key_id"], app.keys.key_id().as_str());
    assert_eq!(statement["sign_pk"], b64u(&app.keys.sign_pk()));
    let keys: Vec<&String> = statement.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "v",
            "type",
            "node",
            "user_id",
            "key_id",
            "sign_pk",
            "provider",
            "state",
            "record_id",
            "time_ms"
        ]
    );
    assert_eq!(
        app.event(&harness, &issued["entry"]),
        json!({
            "t": "connection_created", "record_id": record["id"], "provider": "google_workspace",
            "scope": "openid https://www.googleapis.com/auth/gmail.readonly",
        })
    );
    assert_eq!(app.entry_body(&harness, &issued["entry"])["seq"], 2);

    // A state is used once.
    assert_eq!(
        code(&complete(&harness, "user-1", state).await),
        (404, "state_unknown")
    );
    assert_eq!(provider.seen().len(), 1);
}

#[tokio::test]
async fn a_pending_authorization_is_bound_to_its_state_user_key_and_time() {
    let provider = provider(|_| Reply::json(200, &google_token())).await;
    let harness = Harness::configured(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let start = || {
        begin(
            &harness,
            "user-1",
            "google_workspace",
            json!({"scope": "openid"}),
            "",
        )
    };

    // A state the node never issued, and a state without the separator.
    assert_eq!(
        code(&complete(&harness, "user-1", "AAAAAAAAAAAAAAAAAAAAAA.operator").await),
        (404, "state_unknown")
    );
    assert_eq!(
        code(&complete(&harness, "user-1", "no-separator").await),
        (404, "state_unknown")
    );

    // The operator part of the state was changed on the way.
    let state = start().await.1["state"].as_str().unwrap().to_string();
    let node_state = state.split('.').next().unwrap();
    assert_eq!(
        code(&complete(&harness, "user-1", &format!("{node_state}.other")).await),
        (404, "state_unknown")
    );
    // The attempt used the pending authorization up.
    assert_eq!(
        code(&complete(&harness, "user-1", &state).await),
        (404, "state_unknown")
    );

    // Another user presents the state.
    let other = App::new("user-2", 2);
    other.grant(&harness).await;
    let state = start().await.1["state"].as_str().unwrap().to_string();
    assert_eq!(
        code(&complete(&harness, "user-2", &state).await),
        (400, "user_mismatch")
    );
    assert_eq!(
        code(&complete(&harness, "user-1", &state).await),
        (404, "state_unknown")
    );

    // 600 seconds passed.
    let state = start().await.1["state"].as_str().unwrap().to_string();
    harness.node.clock.advance(limits::PENDING_AUTH_MS + 1_000);
    assert_eq!(
        code(&complete(&harness, "user-1", &state).await),
        (404, "state_unknown")
    );

    // The account key changed between begin and complete.
    let state = start().await.1["state"].as_str().unwrap().to_string();
    App::new("user-1", 7).grant(&harness).await;
    assert_eq!(
        code(&complete(&harness, "user-1", &state).await),
        (409, "key_mismatch")
    );

    // A grant of another signing key whose key_id has the same 8 bytes: the completion
    // compares the whole signing public key, so the 64-bit match does not pass. Such a grant
    // cannot be made by a test (it takes 2^64 key generations to find one), so the state of
    // the account is set as that grant would leave it.
    let state = start().await.1["state"].as_str().unwrap().to_string();
    {
        let account = harness.node.account("user-1").unwrap();
        let mut account = lock(&account);
        let GrantState::Active(grant) = &account.grant else {
            panic!("user-1 has a grant");
        };
        let colliding = ActiveGrant {
            key_id: grant.key_id.clone(),
            sign_pk: [0xee; 32],
            log_pk: grant.log_pk,
            custody: Custody::Operator,
            user_key: grant.user_key.clone(),
            not_after_ms: grant.not_after_ms,
            exported_to: Vec::new(),
        };
        account.grant = GrantState::Active(colliding);
    }
    assert_eq!(
        code(&complete(&harness, "user-1", &state).await),
        (409, "key_mismatch")
    );

    // The delegation was revoked between begin and complete.
    let renewed = App::new("user-1", 7);
    renewed.grant(&harness).await;
    let state = start().await.1["state"].as_str().unwrap().to_string();
    renewed.revoke(&harness).await;
    assert_eq!(
        code(&complete(&harness, "user-1", &state).await),
        (409, "grant_revoked")
    );

    // No exchange reached the provider in any of these cases.
    assert!(provider.seen().is_empty());
}

#[tokio::test]
async fn a_refused_exchange_returns_only_the_status_and_the_error_code() {
    let answers: Arc<Mutex<Vec<Reply>>> = Arc::new(Mutex::new(vec![
        Reply::json(
            400,
            &json!({"error": "invalid_grant", "error_description": "Bad Request detail"}),
        ),
        Reply::with_body(
            200,
            &[("content-type", "text/html")],
            b"<html>proxy page</html>",
        ),
        Reply::json(
            200,
            &json!({"token_type": "Bearer", "detail": "no access token here"}),
        ),
        Reply::json(
            500,
            &json!({"error": {"code": "backend_error", "message": "m"}}),
        ),
    ]));
    let provider = provider({
        let answers = answers.clone();
        move |_| lock(&answers).remove(0)
    })
    .await;
    let harness = Harness::configured(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;

    // The error word is one of the closed vocabulary. A string of the provider that is not in
    // it leaves as `other`.
    for (provider_status, provider_error) in
        [(400, "invalid_grant"), (200, ""), (200, ""), (500, "other")]
    {
        let state = begin(&harness, "user-1", "google_workspace", json!({}), "")
            .await
            .1["state"]
            .as_str()
            .unwrap()
            .to_string();
        let (status, failure) = complete(&harness, "user-1", &state).await;
        assert_eq!(status, 502);
        assert_eq!(failure["code"], "exchange_failed");
        assert_eq!(failure["provider_status"], provider_status);
        assert_eq!(failure["provider_error"], provider_error);
        let text = failure.to_string();
        for leaked in [
            "Bad Request detail",
            "proxy page",
            "no access token here",
            "backend_error",
        ] {
            assert!(!text.contains(leaked));
        }
    }
    // A transport failure: the provider cannot be reached.
    let unrouted = Harness::configured(&quiet_provider().await).await;
    let lonely = App::new("user-1", 1);
    lonely.grant(&unrouted).await;
    // The node reaches no stand-in for the token host of this node.
    unrouted
        .platform
        .route("oauth2.googleapis.com", "127.0.0.1:1".parse().unwrap());
    let state = begin(&unrouted, "user-1", "google_workspace", json!({}), "")
        .await
        .1["state"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, failure) = complete(&unrouted, "user-1", &state).await;
    assert_eq!(
        (status, failure["code"].as_str()),
        (502, Some("exchange_failed"))
    );
    assert_eq!(failure["provider_status"], 0);
    assert_eq!(failure["provider_error"], "");

    // A refused exchange leaves no record and no entry: only the grant is on the chain.
    assert_eq!(harness.head_seq("user-1"), 1);
}

#[tokio::test]
async fn a_refresh_merges_the_response_into_the_same_record() {
    let refreshed =
        json!({"access_token": "ya29.second-access", "expires_in": 1800, "token_type": "Bearer"});
    let answers: Arc<Mutex<Vec<Reply>>> = Arc::new(Mutex::new(vec![
        Reply::json(200, &google_token()),
        Reply::json(200, &refreshed),
        Reply::json(
            200,
            &json!({"access_token": "ya29.third-access", "refresh_token": "1//rotated", "scope": "openid"}),
        ),
        Reply::json(
            400,
            &json!({"error": "invalid_grant", "error_description": "Token has been revoked."}),
        ),
    ]));
    let provider = provider({
        let answers = answers.clone();
        move |_| lock(&answers).remove(0)
    })
    .await;
    let harness = Harness::configured(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let state = begin(&harness, "user-1", "google_workspace", json!({}), "")
        .await
        .1["state"]
        .as_str()
        .unwrap()
        .to_string();
    let issued = complete(&harness, "user-1", &state).await.1;
    let record = issued["record"].clone();

    // A response without refresh token and scope: the old values stay.
    let (status, renewed) = harness
        .post(
            "/v1/refresh",
            json!({"user_id": "user-1", "record": record, "context": "refresh:scheduled"}),
        )
        .await;
    assert_eq!(status, 200, "{renewed}");
    let call = &provider.seen()[1];
    assert_eq!(call.target, "/token");
    assert_eq!(
        call.form(),
        [
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), "1//first-refresh".to_string()),
            (
                "client_id".to_string(),
                "google_workspace-client".to_string()
            ),
            (
                "client_secret".to_string(),
                "google_workspace-secret".to_string()
            ),
        ]
    );
    let new_record = &renewed["record"];
    assert_eq!(new_record["id"], record["id"]);
    assert_eq!(new_record["kind"], "oauth");
    assert_eq!(new_record["provider"], "google_workspace");
    assert_ne!(new_record["nonce"], record["nonce"]);
    assert_ne!(new_record["ct"], record["ct"]);
    let token = app.open(new_record)["token"].clone();
    assert_eq!(token["access_token"], "ya29.second-access");
    assert_eq!(token["refresh_token"], "1//first-refresh");
    assert_eq!(token["expires_in"], 1800);
    assert_eq!(token["scope"], google_token()["scope"]);
    assert_eq!(token["id_token"], google_token()["id_token"]);
    assert_eq!(renewed["public"]["token"]["expires_in"], 1800);
    assert_eq!(renewed["public"]["has_refresh_token"], true);
    assert_eq!(
        renewed["public"]["id_token_claims"]["email"],
        "a@example.com"
    );
    assert!(!renewed.to_string().contains("ya29.second-access"));
    assert_eq!(
        app.event(&harness, &renewed["entry"]),
        json!({"t": "credential_refreshed", "record_id": record["id"], "provider": "google_workspace"})
    );

    // A response without expires_in removes the key. A rotated refresh token and a new scope
    // replace the old values.
    let (_, rotated) = harness
        .post(
            "/v1/refresh",
            json!({"user_id": "user-1", "record": new_record, "context": "refresh:auth_failure"}),
        )
        .await;
    let token = app.open(&rotated["record"])["token"].clone();
    assert_eq!(token["access_token"], "ya29.third-access");
    assert_eq!(token["refresh_token"], "1//rotated");
    assert_eq!(token["scope"], "openid");
    assert!(token.get("expires_in").is_none());
    assert!(rotated["public"]["token"].get("expires_in").is_none());
    assert_eq!(
        provider.seen()[2].form_value("refresh_token").as_deref(),
        Some("1//first-refresh")
    );

    // A refused refresh: only the status and the error code come back, and the entry stays.
    let before = harness.head_seq("user-1");
    let (status, failure) = harness
        .post(
            "/v1/refresh",
            json!({"user_id": "user-1", "record": rotated["record"], "context": "refresh:scheduled"}),
        )
        .await;
    assert_eq!(status, 502);
    assert_eq!(
        failure,
        json!({
            "code": "refresh_failed", "message": "the provider refused the refresh",
            "provider_status": 400, "provider_error": "invalid_grant",
        })
    );
    assert_eq!(harness.head_seq("user-1"), before + 1);
}

#[tokio::test]
async fn a_refresh_needs_an_oauth_record_with_a_refresh_token() {
    let provider = quiet_provider().await;
    let harness = Harness::configured(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let refresh = |record: Value| {
        let harness = &harness;
        async move {
            harness
                .post(
                    "/v1/refresh",
                    json!({"user_id": "user-1", "record": record, "context": "c"}),
                )
                .await
        }
    };

    let without = app.record(
        "oauth",
        "slack",
        &json!({"token": {"authed_user": {"access_token": "xoxp"}}, "obtained_ms": 1}),
    );
    assert_eq!(code(&refresh(without).await), (422, "record_invalid"));
    let vault = app.record("vault_password", "vault", &json!({"value": "x"}));
    assert_eq!(code(&refresh(vault).await), (403, "not_allowed"));
    let unknown = app.record(
        "oauth",
        "unknown_provider",
        &json!({"token": {"refresh_token": "r"}, "obtained_ms": 1}),
    );
    assert_eq!(code(&refresh(unknown).await), (404, "provider_unknown"));
    let shapeless = app.record("oauth", "slack", &json!({"access_token": "xoxp"}));
    assert_eq!(code(&refresh(shapeless).await), (422, "record_invalid"));

    // None of these created an entry or reached a provider.
    assert_eq!(harness.head_seq("user-1"), 1);
    assert!(provider.seen().is_empty());
}

fn slack_token() -> Value {
    json!({
        "ok": true,
        "app_id": "A0123",
        "authed_user": {
            "id": "U0123", "scope": "channels:history,chat:write",
            "access_token": "xoxe.xoxp-first", "refresh_token": "xoxe-1-first",
            "expires_in": 43200, "token_type": "user",
        },
        "team": {"id": "T0123", "name": "Team"},
        "enterprise": null,
        "is_enterprise_install": false,
    })
}

#[tokio::test]
async fn slack_tokens_live_in_the_nested_place_and_ok_false_is_a_refusal() {
    let answers: Arc<Mutex<Vec<Reply>>> = Arc::new(Mutex::new(vec![
        // A refusal that still carries a token: `ok: false` alone decides.
        Reply::json(
            200,
            &json!({"ok": false, "error": "invalid_code", "authed_user": {"access_token": "xoxp-ignored"}}),
        ),
        Reply::json(200, &slack_token()),
        Reply::json(
            200,
            &json!({
                "ok": true, "access_token": "xoxe.xoxp-second", "refresh_token": "xoxe-1-second",
                "expires_in": 43000, "token_type": "user",
            }),
        ),
        Reply::json(200, &json!({"ok": false, "error": "invalid_refresh_token"})),
    ]));
    let provider = provider({
        let answers = answers.clone();
        move |seen| match seen.target.as_str() {
            "/api/oauth.v2.access" => lock(&answers).remove(0),
            _ => Reply::json(200, &json!({"ok": true})),
        }
    })
    .await;
    let harness = Harness::configured(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let start = || {
        begin(
            &harness,
            "user-1",
            "slack",
            json!({"user_scope": "channels:history,chat:write"}),
            "",
        )
    };

    // No PKCE for slack: the address has no challenge.
    let started = start().await.1;
    let url = started["authorization_url"].as_str().unwrap();
    assert!(url.starts_with(
        "https://slack.com/oauth/v2/authorize?response_type=code&client_id=slack-client&"
    ));
    assert!(url.ends_with("&user_scope=channels%3Ahistory%2Cchat%3Awrite"));
    assert!(query_value(url, "code_challenge").is_none());

    // HTTP 200 with ok false is a refused exchange.
    let (status, failure) = complete(&harness, "user-1", started["state"].as_str().unwrap()).await;
    assert_eq!(status, 502);
    assert_eq!(failure["code"], "exchange_failed");
    assert_eq!(failure["provider_status"], 200);
    assert_eq!(failure["provider_error"], "invalid_code");
    assert_eq!(provider.seen()[0].server_name, "slack.com");
    assert!(provider.seen()[0].form_value("code_verifier").is_none());

    // A successful exchange: the scope of the entry and the public fields come from the
    // nested place, and no token value is public.
    let started = start().await.1;
    let (status, issued) = complete(&harness, "user-1", started["state"].as_str().unwrap()).await;
    assert_eq!(status, 200, "{issued}");
    assert_eq!(app.open(&issued["record"])["token"], slack_token());
    assert_eq!(
        issued["public"]["token"],
        json!({
            "team": {"id": "T0123", "name": "Team"},
            "app_id": "A0123",
            "is_enterprise_install": false,
            "authed_user": {
                "id": "U0123", "scope": "channels:history,chat:write",
                "expires_in": 43200, "token_type": "user",
            },
        })
    );
    assert_eq!(issued["public"]["has_refresh_token"], true);
    assert_eq!(issued["public"]["id_token_claims"], json!({}));
    assert!(!issued.to_string().contains("xoxe"));
    assert_eq!(
        app.event(&harness, &issued["entry"])["scope"],
        "channels:history,chat:write"
    );

    // A refresh answers with a flat object: its tokens are written into the nested place.
    let (status, renewed) = harness
        .post(
            "/v1/refresh",
            json!({"user_id": "user-1", "record": issued["record"], "context": "refresh:auth_failure"}),
        )
        .await;
    assert_eq!(status, 200, "{renewed}");
    assert_eq!(
        provider.seen()[2].form_value("refresh_token").as_deref(),
        Some("xoxe-1-first")
    );
    let token = app.open(&renewed["record"])["token"].clone();
    assert_eq!(
        token["authed_user"],
        json!({
            "id": "U0123", "scope": "channels:history,chat:write",
            "access_token": "xoxe.xoxp-second", "refresh_token": "xoxe-1-second",
            "expires_in": 43000, "token_type": "user",
        })
    );
    assert_eq!(token["team"], json!({"id": "T0123", "name": "Team"}));
    assert_eq!(
        renewed["public"]["token"]["authed_user"]["expires_in"],
        43000
    );
    assert!(!renewed.to_string().contains("xoxe"));

    // forward injects the token of the nested place.
    let forwarded = harness
        .forward(
            json!({
                "user_id": "user-1", "record": renewed["record"], "method": "POST",
                "url": "https://slack.com/api/auth.test", "headers": [], "context": "cli:slack",
            }),
            b"",
        )
        .await
        .unwrap();
    assert_eq!(forwarded.status, 200);
    assert_eq!(
        provider.seen().last().unwrap().header("authorization"),
        Some("Bearer xoxe.xoxp-second")
    );

    // HTTP 200 with ok false on a refresh is refresh_failed with provider_status 200.
    let (status, failure) = harness
        .post(
            "/v1/refresh",
            json!({"user_id": "user-1", "record": renewed["record"], "context": "refresh:auth_failure"}),
        )
        .await;
    assert_eq!(status, 502);
    assert_eq!(failure["code"], "refresh_failed");
    assert_eq!(failure["provider_status"], 200);
    assert_eq!(failure["provider_error"], "invalid_refresh_token");
}

#[tokio::test]
async fn notion_link_and_granola_authenticate_the_way_their_definitions_say() {
    let provider = provider(|seen| match seen.server_name.as_str() {
        "api.notion.com" => Reply::json(
            200,
            &json!({
                "access_token": "ntn_secret", "token_type": "bearer", "bot_id": "b-1",
                "workspace_id": "w-1", "workspace_name": "Space", "workspace_icon": null,
                "owner": {"type": "user", "user": {"id": "u-1"}}, "duplicated_template_id": null,
                "request_id": "r-1",
            }),
        ),
        "login.link.com" => Reply::json(
            200,
            &json!({
                "access_token": "link_access", "refresh_token": "link_refresh",
                "expires_in": 3600, "scope": "userinfo:read", "token_type": "Bearer",
            }),
        ),
        _ => Reply::json(
            200,
            &json!({
                "access_token": "granola_access", "refresh_token": "granola_refresh",
                "expires_in": 3600, "scope": "mcp offline_access", "token_type": "Bearer",
            }),
        ),
    })
    .await;
    let harness = Harness::configured(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;

    // notion: HTTP Basic, a JSON body, a version header, the fixed owner parameter.
    let (status, started) = begin(&harness, "user-1", "notion", json!({}), "").await;
    assert_eq!(status, 200);
    let url = started["authorization_url"].as_str().unwrap();
    assert!(url.ends_with("&owner=user"));
    assert!(query_value(url, "code_challenge").is_none());
    let issued = complete(&harness, "user-1", started["state"].as_str().unwrap())
        .await
        .1;
    let call = provider.seen().last().unwrap().clone();
    assert_eq!(
        (call.server_name.as_str(), call.target.as_str()),
        ("api.notion.com", "/v1/oauth/token")
    );
    assert_eq!(call.header("content-type"), Some("application/json"));
    assert_eq!(call.header("notion-version"), Some("2025-09-03"));
    assert_eq!(
        call.header("authorization"),
        Some(format!("Basic {}", STANDARD.encode("notion-client:notion-secret")).as_str())
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&call.body).unwrap(),
        json!({
            "grant_type": "authorization_code", "code": "4/authorization-code",
            "redirect_uri": "https://api.example/api/integrations/notion/oauth/callback",
        })
    );
    assert_eq!(
        issued["public"]["token"],
        json!({
            "workspace_id": "w-1", "workspace_name": "Space",
            "bot_id": "b-1", "owner": {"type": "user", "user": {"id": "u-1"}},
        })
    );
    assert_eq!(issued["public"]["has_refresh_token"], false);
    assert_eq!(app.event(&harness, &issued["entry"])["scope"], "");

    // link: the publishable key in the address and as the bearer of the token call, the
    // client values in the body.
    let (_, started) = begin(
        &harness,
        "user-1",
        "link",
        json!({"scope": "userinfo:read"}),
        "",
    )
    .await;
    let url = started["authorization_url"].as_str().unwrap();
    assert!(url.ends_with("&code_challenge_method=S256&key=pk_test_1&scope=userinfo%3Aread"));
    complete(&harness, "user-1", started["state"].as_str().unwrap()).await;
    let call = provider.seen().last().unwrap().clone();
    assert_eq!(
        (call.server_name.as_str(), call.target.as_str()),
        ("login.link.com", "/auth/token")
    );
    assert_eq!(call.header("authorization"), Some("Bearer pk_test_1"));
    assert_eq!(call.form_value("client_id").as_deref(), Some("link-client"));
    assert_eq!(
        call.form_value("client_secret").as_deref(),
        Some("link-secret")
    );
    assert!(call.form_value("code_verifier").is_some());

    // granola: a public client whose id comes with the call, and a fixed resource.
    let outcome = begin(
        &harness,
        "user-1",
        "granola",
        json!({"scope": "mcp offline_access"}),
        "",
    )
    .await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
    let (status, started) = begin(
        &harness,
        "user-1",
        "granola",
        json!({"scope": "mcp offline_access"}),
        "dyn-client-1",
    )
    .await;
    assert_eq!(status, 200);
    let url = started["authorization_url"].as_str().unwrap();
    assert_eq!(
        query_value(url, "client_id").as_deref(),
        Some("dyn-client-1")
    );
    assert_eq!(
        query_value(url, "resource").as_deref(),
        Some("https://mcp.granola.ai/mcp")
    );
    let issued = complete(&harness, "user-1", started["state"].as_str().unwrap())
        .await
        .1;
    let call = provider.seen().last().unwrap().clone();
    assert_eq!(call.server_name, "mcp-auth.granola.ai");
    let fields: Vec<String> = call.form().into_iter().map(|(name, _)| name).collect();
    assert_eq!(
        fields,
        [
            "grant_type",
            "code",
            "redirect_uri",
            "code_verifier",
            "client_id",
            "resource"
        ]
    );
    assert_eq!(
        call.form_value("client_id").as_deref(),
        Some("dyn-client-1")
    );
    assert_eq!(call.header("authorization"), None);
    // The record remembers the client id, and the refresh uses it.
    assert_eq!(app.open(&issued["record"])["client_id"], "dyn-client-1");
    let (status, renewed) = harness
        .post(
            "/v1/refresh",
            json!({"user_id": "user-1", "record": issued["record"], "context": "c"}),
        )
        .await;
    assert_eq!(status, 200);
    let call = provider.seen().last().unwrap().clone();
    assert_eq!(
        call.form(),
        [
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), "granola_refresh".to_string()),
            ("client_id".to_string(), "dyn-client-1".to_string()),
            (
                "resource".to_string(),
                "https://mcp.granola.ai/mcp".to_string()
            ),
        ]
    );
    assert_eq!(app.open(&renewed["record"])["client_id"], "dyn-client-1");

    // A client id for a static provider is refused.
    let outcome = begin(&harness, "user-1", "notion", json!({}), "my-own-client").await;
    assert_eq!(code(&outcome), (400, "invalid_request"));
}

#[tokio::test]
async fn begin_checks_the_front_the_provider_and_the_parameters() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);

    // Without the operator configuration.
    assert_eq!(
        code(&begin(&harness, "user-1", "slack", json!({}), "").await),
        (503, "not_configured")
    );
    let mut config = operator_config(&harness.node.definitions);
    config["providers"]["x"]["client_id"] = json!("");
    config["providers"].as_object_mut().unwrap().remove("link");
    assert_eq!(harness.post("/v1/config", config).await.0, 200);

    // Without a grant.
    assert_eq!(
        code(&begin(&harness, "user-1", "slack", json!({}), "").await),
        (409, "grant_required")
    );
    app.grant(&harness).await;

    // A provider without a definition, without a client id, and one the configuration lacks.
    assert_eq!(
        code(&begin(&harness, "user-1", "dropbox", json!({}), "").await),
        (404, "provider_unknown")
    );
    assert_eq!(
        code(&begin(&harness, "user-1", "x", json!({"scope": "a"}), "").await),
        (503, "not_configured")
    );
    assert_eq!(
        code(&begin(&harness, "user-1", "link", json!({"scope": "a"}), "").await),
        (503, "not_configured")
    );

    // Parameters the definition does not allow.
    for params in [
        json!({"redirect_uri": "https://evil.example/cb"}),
        json!({"scope": "a"}),
        json!({"user_scope": 5}),
        json!({"user_scope": "a\u{0}b"}),
    ] {
        assert_eq!(
            code(&begin(&harness, "user-1", "slack", params.clone(), "").await),
            (403, "not_allowed"),
            "{params}"
        );
    }

    // A malformed call.
    for body in [
        json!({"user_id": "user-1", "provider": "slack", "operator_state": "", "params": {}}),
        json!({"user_id": "user-1", "provider": "slack", "operator_state": "has space", "params": {}}),
        json!({"user_id": "user-1", "provider": "slack", "operator_state": "o".repeat(1025), "params": {}}),
        json!({"user_id": "user-1", "provider": "slack", "operator_state": "o", "params": []}),
        json!({"user_id": "user-1", "operator_state": "o", "params": {}}),
    ] {
        assert_eq!(
            code(&harness.post("/v1/oauth/begin", body).await),
            (400, "invalid_request")
        );
    }

    // An operator_state of the longest form passes.
    let (status, started) = harness
        .post(
            "/v1/oauth/begin",
            json!({"user_id": "user-1", "provider": "slack", "operator_state": "o".repeat(1024)}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(started["state"].as_str().unwrap().len(), 22 + 1 + 1024);
}

#[tokio::test]
async fn a_reconnect_without_a_refresh_token_keeps_the_previous_one() {
    let provider = quiet_provider().await;
    let harness = Harness::new(&provider);
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let previous = app.record(
        "oauth",
        "google_workspace",
        &json!({"token": {"access_token": "old-access", "refresh_token": "kept-refresh", "scope": "a"}, "obtained_ms": 10}),
    );
    let new = app.record(
        "oauth",
        "google_workspace",
        &json!({"token": {"access_token": "new-access", "expires_in": 3599, "scope": "a b", "token_type": "Bearer"}, "obtained_ms": 20}),
    );
    let merge = |record: Value, previous: Value| {
        let harness = &harness;
        async move {
            harness
                .post(
                    "/v1/oauth/merge",
                    json!({"user_id": "user-1", "record": record, "previous": previous}),
                )
                .await
        }
    };

    // Works without the operator configuration, creates no entry and calls no provider.
    let (status, merged) = merge(new.clone(), previous.clone()).await;
    assert_eq!(status, 200, "{merged}");
    assert_eq!(merged["record"]["id"], new["id"]);
    assert_ne!(merged["record"]["nonce"], new["nonce"]);
    assert_eq!(
        app.open(&merged["record"]),
        json!({
            "token": {
                "access_token": "new-access", "expires_in": 3599, "scope": "a b",
                "token_type": "Bearer", "refresh_token": "kept-refresh",
            },
            "obtained_ms": 20,
        })
    );
    assert_eq!(
        merged["public"],
        json!({
            "token": {"scope": "a b", "expires_in": 3599, "token_type": "Bearer"},
            "id_token_claims": {},
            "obtained_ms": 20,
            "has_refresh_token": true,
        })
    );
    assert!(merged.get("entry").is_none());
    assert_eq!(harness.head_seq("user-1"), 1);
    assert!(provider.seen().is_empty());

    // A new record with its own refresh token keeps it.
    let (_, kept) = merge(previous.clone(), new.clone()).await;
    assert_eq!(
        app.open(&kept["record"])["token"]["refresh_token"],
        "kept-refresh"
    );
    assert_eq!(kept["record"]["id"], previous["id"]);

    // Records of different providers, records that are not OAuth, and a previous record of a
    // former key.
    let other_provider = app.record(
        "oauth",
        "microsoft",
        &json!({"token": {"access_token": "m"}, "obtained_ms": 1}),
    );
    assert_eq!(
        code(&merge(new.clone(), other_provider).await),
        (400, "invalid_request")
    );
    let vault = app.record("vault_password", "vault", &json!({"value": "x"}));
    assert_eq!(
        code(&merge(vault.clone(), vault).await),
        (403, "not_allowed")
    );
    let former = App::new("user-1", 9).record(
        "oauth",
        "google_workspace",
        &json!({"token": {"refresh_token": "former"}, "obtained_ms": 1}),
    );
    assert_eq!(
        code(&merge(new.clone(), former).await),
        (409, "key_mismatch")
    );
    let mut broken = previous.clone();
    broken["ct"] = json!(b64u(&[1u8; 40]));
    assert_eq!(code(&merge(new, broken).await), (422, "record_invalid"));
}

#[tokio::test]
async fn revoke_token_sends_the_refresh_token_to_the_revocation_address() {
    let provider =
        provider(
            |seen: &Seen| match (seen.server_name.as_str(), seen.target.as_str()) {
                ("api.x.com", "/2/oauth2/revoke") => {
                    Reply::json(400, &json!({"error": "invalid_request"}))
                }
                _ => Reply::json(200, &json!({})),
            },
        )
        .await;
    let harness = Harness::configured(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let revoke = |record: Value| {
        let harness = &harness;
        async move {
            harness
                .post(
                    "/v1/revoke-token",
                    json!({"user_id": "user-1", "record": record, "context": "disconnect"}),
                )
                .await
        }
    };

    // google: the refresh token, without client authentication.
    let google = app.record(
        "oauth",
        "google_workspace",
        &json!({"token": {"access_token": "g-access", "refresh_token": "g-refresh"}, "obtained_ms": 1}),
    );
    let (status, revoked) = revoke(google.clone()).await;
    assert_eq!(status, 200);
    assert_eq!(revoked["revoked"], true);
    let call = provider.seen().last().unwrap().clone();
    assert_eq!(
        (call.server_name.as_str(), call.target.as_str()),
        ("oauth2.googleapis.com", "/revoke")
    );
    assert_eq!(
        call.form(),
        [
            ("token".to_string(), "g-refresh".to_string()),
            ("token_type_hint".to_string(), "refresh_token".to_string()),
        ]
    );
    assert_eq!(call.header("authorization"), None);
    assert_eq!(
        app.event(&harness, &revoked["entry"]),
        json!({"t": "connection_removed", "record_id": google["id"], "provider": "google_workspace", "provider_revoke": true})
    );

    // link: the access token when there is no refresh token, client values in the body and
    // the publishable key as bearer.
    let link = app.record(
        "oauth",
        "link",
        &json!({"token": {"access_token": "l-access"}, "obtained_ms": 1}),
    );
    assert_eq!(revoke(link).await.1["revoked"], true);
    let call = provider.seen().last().unwrap().clone();
    assert_eq!(
        (call.server_name.as_str(), call.target.as_str()),
        ("login.link.com", "/auth/revoke")
    );
    assert_eq!(
        call.form(),
        [
            ("token".to_string(), "l-access".to_string()),
            ("token_type_hint".to_string(), "access_token".to_string()),
            ("client_id".to_string(), "link-client".to_string()),
            ("client_secret".to_string(), "link-secret".to_string()),
        ]
    );
    assert_eq!(call.header("authorization"), Some("Bearer pk_test_1"));

    // x: HTTP Basic. The provider refuses: not an error, revoked is false.
    let x = app.record("oauth", "x", &json!({"token": {"access_token": "x-access", "refresh_token": "x-refresh"}, "obtained_ms": 1}));
    let (status, refused) = revoke(x.clone()).await;
    assert_eq!((status, refused["revoked"].as_bool()), (200, Some(false)));
    let call = provider.seen().last().unwrap().clone();
    assert_eq!(
        call.header("authorization"),
        Some(format!("Basic {}", STANDARD.encode("x-client:x-secret")).as_str())
    );
    // The entry was created before the call: it says that the node calls the revocation
    // address, not what the provider answered.
    assert_eq!(
        app.event(&harness, &refused["entry"]),
        json!({"t": "connection_removed", "record_id": x["id"], "provider": "x", "provider_revoke": true})
    );

    // microsoft has no revocation address: the entry is written and no provider is called.
    let calls = provider.seen().len();
    let microsoft = app.record(
        "oauth",
        "microsoft",
        &json!({"token": {"access_token": "m", "refresh_token": "r"}, "obtained_ms": 1}),
    );
    let (status, skipped) = revoke(microsoft.clone()).await;
    assert_eq!((status, skipped["revoked"].as_bool()), (200, Some(false)));
    assert_eq!(
        app.event(&harness, &skipped["entry"]),
        json!({"t": "connection_removed", "record_id": microsoft["id"], "provider": "microsoft", "provider_revoke": false})
    );
    assert_eq!(provider.seen().len(), calls);

    // A record that is not OAuth.
    let vault = app.record("vault_password", "vault", &json!({"value": "x"}));
    assert_eq!(code(&revoke(vault).await), (403, "not_allowed"));
}

/// A stand-in whose token address answers the exchange with the first Google token and every
/// refresh with a new access token and a rotated refresh token.
async fn rotating_provider() -> crate::testing::Provider {
    let refreshes = Arc::new(Mutex::new(0u32));
    provider(move |seen: &Seen| {
        if seen.form_value("grant_type").as_deref() == Some("authorization_code") {
            return Reply::json(200, &google_token());
        }
        let mut count = lock(&refreshes);
        *count += 1;
        Reply::json(
            200,
            &json!({
                "access_token": format!("ya29.refreshed-access-{count}"),
                "refresh_token": format!("1//rotated-refresh-{count}"),
                "expires_in": 3599,
                "token_type": "Bearer",
            }),
        )
    })
    .await
}

async fn refresh(harness: &Harness, user_id: &str, record: &Value) -> (u16, Value) {
    harness
        .post(
            "/v1/refresh",
            json!({"user_id": user_id, "record": record, "context": "refresh:scheduled"}),
        )
        .await
}

#[tokio::test]
async fn a_repeated_refresh_of_the_same_record_gets_the_kept_response() {
    let provider = rotating_provider().await;
    let harness = Harness::configured(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let state = begin(&harness, "user-1", "google_workspace", json!({}), "")
        .await
        .1["state"]
        .as_str()
        .unwrap()
        .to_string();
    let record = complete(&harness, "user-1", &state).await.1["record"].clone();

    // The first refresh calls the provider. The provider rotated the refresh token: the old
    // one, which the record that was sent still holds, is no longer valid there.
    let (status, first) = refresh(&harness, "user-1", &record).await;
    assert_eq!(status, 200, "{first}");
    assert_eq!(provider.seen().len(), 2);
    assert_eq!(
        app.open(&first["record"])["token"]["refresh_token"],
        "1//rotated-refresh-1"
    );
    let seq = harness.head_seq("user-1");

    // The response did not reach its caller, and the caller sends the same record again: the
    // node answers with the response it kept. No provider call, no new entry.
    for _ in 0..3 {
        let (status, again) = refresh(&harness, "user-1", &record).await;
        assert_eq!(status, 200);
        assert_eq!(again, first);
    }
    assert_eq!(provider.seen().len(), 2);
    assert_eq!(harness.head_seq("user-1"), seq);

    // The kept response belongs to the account: another account does not get it, and the
    // record of this account does not open for it.
    let other = App::new("user-2", 2);
    other.grant(&harness).await;
    assert_eq!(
        code(&refresh(&harness, "user-2", &record).await),
        (400, "user_mismatch")
    );
    assert_eq!(provider.seen().len(), 2);

    // The record the refresh returned is another record: its refresh is a provider call.
    let (status, second) = refresh(&harness, "user-1", &first["record"]).await;
    assert_eq!(status, 200);
    assert_eq!(provider.seen().len(), 3);
    assert_eq!(
        provider.seen()[2].form_value("refresh_token").as_deref(),
        Some("1//rotated-refresh-1")
    );
    assert_ne!(second["record"]["ct"], first["record"]["ct"]);

    // One millisecond before 3,600 seconds the response is still kept. At 3,600 seconds it is
    // gone, and the same record is a provider call again.
    harness.node.clock.advance(3_600_000 - 2_000);
    assert_eq!(refresh(&harness, "user-1", &record).await.1, first);
    assert_eq!(provider.seen().len(), 3);
    harness.node.clock.advance(2_000);
    let (status, late) = refresh(&harness, "user-1", &record).await;
    assert_eq!(status, 200);
    assert_eq!(provider.seen().len(), 4);
    assert_ne!(late["record"]["ct"], first["record"]["ct"]);
    assert_eq!(
        provider.seen()[3].form_value("refresh_token").as_deref(),
        Some("1//first-refresh")
    );
}

#[tokio::test]
async fn a_revoke_drops_the_kept_refresh_responses() {
    let provider = rotating_provider().await;
    let harness = Harness::configured(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let state = begin(&harness, "user-1", "google_workspace", json!({}), "")
        .await
        .1["state"]
        .as_str()
        .unwrap()
        .to_string();
    let record = complete(&harness, "user-1", &state).await.1["record"].clone();
    let (_, first) = refresh(&harness, "user-1", &record).await;
    assert_eq!(refresh(&harness, "user-1", &record).await.1, first);
    assert_eq!(provider.seen().len(), 2);

    // After a revoke the account gets nothing, the kept response included.
    app.revoke(&harness).await;
    assert_eq!(
        code(&refresh(&harness, "user-1", &record).await),
        (409, "grant_revoked")
    );
    // A new grant does not bring the kept response back: the same record is a provider call.
    app.grant(&harness).await;
    let (status, after) = refresh(&harness, "user-1", &record).await;
    assert_eq!(status, 200);
    assert_ne!(after, first);
    assert_eq!(provider.seen().len(), 3);

    // An expired grant drops them as well.
    assert_eq!(refresh(&harness, "user-1", &record).await.1, after);
    harness.node.clock.advance(limits::GRANT_MAX_MS);
    assert_eq!(
        code(&refresh(&harness, "user-1", &record).await),
        (409, "grant_expired")
    );
    app.grant(&harness).await;
    assert_eq!(refresh(&harness, "user-1", &record).await.0, 200);
    assert_eq!(provider.seen().len(), 4);
}

#[tokio::test]
async fn an_imported_record_is_used_like_an_oauth_record_and_stays_imported() {
    let provider = provider(|seen: &Seen| match seen.target.as_str() {
        "/token" => Reply::json(
            200,
            &json!({"access_token": "ya29.refreshed-imported", "expires_in": 3599}),
        ),
        _ => Reply::json(200, &json!({})),
    })
    .await;
    let harness = Harness::configured(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    // The device of the account encrypted a token the operator domain held.
    let imported = app.record(
        "oauth_imported",
        "google_workspace",
        &json!({
            "token": {
                "access_token": "ya29.imported-access", "refresh_token": "1//imported-refresh",
                "scope": "openid email", "token_type": "Bearer",
            },
            "obtained_ms": 10,
        }),
    );

    // A refresh writes the same record again, under the same kind.
    let (status, renewed) = refresh(&harness, "user-1", &imported).await;
    assert_eq!(status, 200, "{renewed}");
    assert_eq!(renewed["record"]["id"], imported["id"]);
    assert_eq!(renewed["record"]["kind"], "oauth_imported");
    let token = app.open(&renewed["record"])["token"].clone();
    assert_eq!(token["access_token"], "ya29.refreshed-imported");
    assert_eq!(token["refresh_token"], "1//imported-refresh");
    assert_eq!(
        renewed["public"]["token"],
        json!({"scope": "openid email", "expires_in": 3599, "token_type": "Bearer"})
    );
    assert_eq!(
        provider.only().form_value("refresh_token").as_deref(),
        Some("1//imported-refresh")
    );

    // The refresh token of an imported record is not moved into a record the node issued,
    // and an imported record takes none.
    let issued = app.record(
        "oauth",
        "google_workspace",
        &json!({"token": {"access_token": "ya29.issued-access"}, "obtained_ms": 20}),
    );
    for (record, previous) in [(&issued, &imported), (&imported, &issued)] {
        let outcome = harness
            .post(
                "/v1/oauth/merge",
                json!({"user_id": "user-1", "record": record, "previous": previous}),
            )
            .await;
        assert_eq!(code(&outcome), (403, "not_allowed"));
    }

    // No call hands its plaintext out.
    let outcome = harness
        .post(
            "/v1/release",
            json!({
                "user_id": "user-1", "record": imported, "field": "password",
                "origin": "https://accounts.example", "context": "c",
            }),
        )
        .await;
    assert_eq!(code(&outcome), (403, "not_allowed"));

    // A revoke sends its refresh token to the revocation address of the provider.
    let (status, revoked) = harness
        .post(
            "/v1/revoke-token",
            json!({"user_id": "user-1", "record": renewed["record"], "context": "disconnect"}),
        )
        .await;
    assert_eq!((status, &revoked["revoked"]), (200, &json!(true)));
    let call = provider.seen().last().unwrap().clone();
    assert_eq!(call.target, "/revoke");
    assert_eq!(
        call.form_value("token").as_deref(),
        Some("1//imported-refresh")
    );
}

#[tokio::test]
async fn a_token_response_with_a_token_in_a_public_field_is_withheld() {
    let answers: Arc<Mutex<Vec<Reply>>> = Arc::new(Mutex::new(vec![
        // An exchange whose listed `scope` field carries the access token.
        Reply::json(
            200,
            &json!({
                "access_token": "ya29.leaked-access-token", "refresh_token": "1//kept-refresh",
                "scope": "openid ya29.leaked-access-token", "token_type": "Bearer",
            }),
        ),
        // An exchange whose listed `email` claim carries the refresh token.
        Reply::json(
            200,
            &json!({
                "access_token": "ya29.second-access-token", "refresh_token": "1//leaked-refresh",
                "id_token": jwt(&json!({"sub": "1", "email": "1//leaked-refresh"})),
            }),
        ),
        // A clean exchange.
        Reply::json(200, &google_token()),
        // A refresh whose listed `token_type` field carries the rotated refresh token.
        Reply::json(
            200,
            &json!({
                "access_token": "ya29.third-access-token", "refresh_token": "1//rotated-leaked",
                "token_type": "Bearer 1//rotated-leaked",
            }),
        ),
    ]));
    let provider = provider({
        let answers = answers.clone();
        move |_| lock(&answers).remove(0)
    })
    .await;
    let harness = Harness::configured(&provider).await;
    let app = App::new("user-1", 1);
    app.grant(&harness).await;
    let start = || async {
        begin(&harness, "user-1", "google_workspace", json!({}), "")
            .await
            .1["state"]
            .as_str()
            .unwrap()
            .to_string()
    };

    // Nothing of the two responses leaves: no record, no public field, no entry.
    for leaked in ["ya29.leaked-access-token", "1//leaked-refresh"] {
        let state = start().await;
        let before = harness.head_seq("user-1");
        let (status, failure) = complete(&harness, "user-1", &state).await;
        assert_eq!(status, 502);
        assert_eq!(
            failure,
            json!({
                "code": "response_withheld",
                "message": "the provider response was withheld by the egress policy",
            })
        );
        assert!(!failure.to_string().contains(leaked));
        assert_eq!(harness.head_seq("user-1"), before);
        // The authorization was used: the same state completes nothing.
        assert_eq!(
            code(&complete(&harness, "user-1", &state).await),
            (404, "state_unknown")
        );
    }

    // A refresh: the entry of the refresh is on the chain, the response is withheld, and
    // nothing is kept for a repeated call.
    let state = start().await;
    let record = complete(&harness, "user-1", &state).await.1["record"].clone();
    let before = harness.head_seq("user-1");
    let (status, failure) = refresh(&harness, "user-1", &record).await;
    assert_eq!(
        (status, failure["code"].as_str()),
        (502, Some("response_withheld"))
    );
    assert!(!failure.to_string().contains("1//rotated-leaked"));
    assert_eq!(harness.head_seq("user-1"), before + 1);
    assert_eq!(provider.seen().len(), 4);
}
