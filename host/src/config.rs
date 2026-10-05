//! The operator configuration (enclave.md section 9 and 5.1).
//!
//! The host program reads the OAuth client values of the operator from its environment and
//! sends them to the node with `POST /v1/config`, once, as soon as the `health` call of the
//! node succeeds. The configuration names every provider of the definitions: the callback
//! address is always set, and a value without an environment variable is the empty string.
//!
//! The configuration also names the log store of the node, when the environment names one:
//! the bucket the node writes its log entries to, and the region of that bucket.
//!
//! The client values are secrets of the operator. They are never part of a log line.

use std::time::Duration;

use hyper::header::CONTENT_TYPE;
use hyper::Method;
use serde_json::{json, Map, Value};

use crate::health;
use crate::http;
use crate::relay::NodeConnector;

/// The variable with the front of the callback addresses: the callback address of a provider is
/// `{value}/api/integrations/{provider}/oauth/callback`.
pub const BASE_URL_VARIABLE: &str = "CHARACTER_API_BASE_URL";

/// The variable with the bucket of the log store of the node.
pub const LOG_BUCKET_VARIABLE: &str = "CREDENTIAL_ENCLAVE_LOG_BUCKET";
/// The variable with the region of that bucket.
pub const LOG_REGION_VARIABLE: &str = "CREDENTIAL_ENCLAVE_LOG_REGION";

/// The log store the environment names (enclave.md 5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogStore {
    pub bucket: String,
    pub region: String,
}

impl LogStore {
    /// Reads the log store from the environment. `Ok(None)` when neither variable is set. An
    /// error when one of the two is missing, or when a value has not the form the node takes:
    /// a bucket name of 3 to 63 lower-case letters, digits and `-` that neither starts nor
    /// ends with `-`, and a region name such as `us-west-2` (two letters, then parts of
    /// letters, then one or two digits, joined by `-`).
    pub fn from_variables(
        variable: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<LogStore>, String> {
        let (bucket, region) = match (variable(LOG_BUCKET_VARIABLE), variable(LOG_REGION_VARIABLE))
        {
            (None, None) => return Ok(None),
            (Some(bucket), Some(region)) => (bucket, region),
            (Some(_), None) => return Err(format!("{LOG_REGION_VARIABLE} is not set")),
            (None, Some(_)) => return Err(format!("{LOG_BUCKET_VARIABLE} is not set")),
        };
        let bucket_named = (3..=63).contains(&bucket.len())
            && bucket
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !bucket.starts_with('-')
            && !bucket.ends_with('-');
        if !bucket_named {
            return Err(format!("{LOG_BUCKET_VARIABLE} is not a bucket name"));
        }
        let parts: Vec<&str> = region.split('-').collect();
        let letters =
            |part: &&str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_lowercase());
        let region_named = match parts.as_slice() {
            [first, between @ .., last] => {
                first.len() == 2
                    && letters(first)
                    && !between.is_empty()
                    && between.iter().all(letters)
                    && (1..=2).contains(&last.len())
                    && last.bytes().all(|byte| byte.is_ascii_digit())
            }
            _ => false,
        };
        if !region_named {
            return Err(format!("{LOG_REGION_VARIABLE} is not a region name"));
        }
        Ok(Some(LogStore { bucket, region }))
    }

    /// The host the node writes to: `{bucket}.s3.{region}.amazonaws.com`.
    pub fn host(&self) -> String {
        format!("{}.s3.{}.amazonaws.com", self.bucket, self.region)
    }
}

/// The environment variables of one provider.
struct ClientVariables {
    provider: &'static str,
    client_id: &'static str,
    client_secret: &'static str,
    publishable_key: Option<&'static str>,
}

/// The variables the host program reads, per provider of the definitions. A provider without a
/// row has no client values of the operator (its clients are registered dynamically).
const CLIENT_VARIABLES: [ClientVariables; 6] = [
    ClientVariables {
        provider: "google_workspace",
        client_id: "GOOGLE_CLIENT_ID",
        client_secret: "GOOGLE_CLIENT_SECRET",
        publishable_key: None,
    },
    ClientVariables {
        provider: "microsoft",
        client_id: "OUTLOOK_CLIENT_ID",
        client_secret: "OUTLOOK_CLIENT_SECRET",
        publishable_key: None,
    },
    ClientVariables {
        provider: "slack",
        client_id: "SLACK_CLIENT_ID",
        client_secret: "SLACK_CLIENT_SECRET",
        publishable_key: None,
    },
    ClientVariables {
        provider: "notion",
        client_id: "NOTION_CLIENT_ID",
        client_secret: "NOTION_CLIENT_SECRET",
        publishable_key: None,
    },
    ClientVariables {
        provider: "x",
        client_id: "X_CLIENT_ID",
        client_secret: "X_CLIENT_SECRET",
        publishable_key: None,
    },
    ClientVariables {
        provider: "link",
        client_id: "LINK_CLIENT_ID",
        client_secret: "LINK_CLIENT_SECRET",
        publishable_key: Some("STRIPE_PUBLISHABLE_KEY"),
    },
];

/// Pause between two `health` calls while the node does not answer yet.
const HEALTH_POLL_PAUSE: Duration = Duration::from_millis(500);
/// Pause after a configuration call that failed without a refusal.
const RETRY_PAUSE: Duration = Duration::from_secs(1);
/// Longest configuration call.
const CONFIG_CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest response body of the configuration call the host program reads.
const CONFIG_REPLY_LIMIT_BYTES: usize = 64 * 1024;
/// A failed attempt is logged the first time and then once in this many attempts.
const FAILURE_LOG_PERIOD: u64 = 60;

/// The names of the providers of the definitions, in the order of the file.
pub fn provider_names(definitions: &str) -> Result<Vec<String>, String> {
    let definitions: Map<String, Value> = serde_json::from_str(definitions)
        .map_err(|_| "the provider definitions are not a JSON object".to_string())?;
    Ok(definitions.keys().cloned().collect())
}

/// Why no configuration can be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// `CHARACTER_API_BASE_URL` is not set: there is no callback address.
    NoBaseUrl,
}

/// Builds the body of `POST /v1/config` for `providers` from the environment (`variable` reads
/// one variable). With a log store, the body names it as `log_store`.
pub fn operator_config(
    providers: &[String],
    variable: &dyn Fn(&str) -> Option<String>,
    log_store: Option<&LogStore>,
) -> Result<Vec<u8>, ConfigError> {
    let base = variable(BASE_URL_VARIABLE).unwrap_or_default();
    let base = base.trim_end_matches('/');
    if base.is_empty() {
        return Err(ConfigError::NoBaseUrl);
    }
    let read = |name: Option<&str>| name.and_then(variable).unwrap_or_default();
    let mut entries = Map::new();
    for provider in providers {
        let variables = CLIENT_VARIABLES
            .iter()
            .find(|variables| variables.provider == provider);
        entries.insert(
            provider.clone(),
            json!({
                "client_id": read(variables.map(|variables| variables.client_id)),
                "client_secret": read(variables.map(|variables| variables.client_secret)),
                "redirect_uri": format!("{base}/api/integrations/{provider}/oauth/callback"),
                "publishable_key": read(variables.and_then(|variables| variables.publishable_key)),
            }),
        );
    }
    let mut body = json!({ "providers": entries });
    if let Some(log_store) = log_store {
        body["log_store"] = json!({"bucket": log_store.bucket, "region": log_store.region});
    }
    Ok(body.to_string().into_bytes())
}

/// Says which providers have a client id in the environment, by name. The line holds no value.
pub fn summary(providers: &[String], variable: &dyn Fn(&str) -> Option<String>) -> String {
    let has_client = |provider: &String| {
        CLIENT_VARIABLES
            .iter()
            .find(|variables| variables.provider == provider)
            .is_some_and(|variables| variable(variables.client_id).is_some())
    };
    let (with, without): (Vec<&String>, Vec<&String>) =
        providers.iter().partition(|provider| has_client(provider));
    let list = |names: Vec<&String>| match names.is_empty() {
        true => "none".to_string(),
        false => names
            .iter()
            .map(|name| name.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    };
    format!(
        "operator configuration: client id set for {}; not set for {}",
        list(with),
        list(without)
    )
}

/// How the node answered the configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Injection {
    /// The node holds the configuration.
    Accepted,
    /// The node refused the configuration (a 4xx status). `code` is the code of its response.
    /// The same body would be refused again, so the host program does not repeat the call.
    Rejected { status: u16, code: String },
}

/// The `code` of a failure response of the node, when it is a short lowercase word.
fn failure_code(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("code")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .filter(|code| {
            code.len() <= 64
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        })
        .unwrap_or_default()
}

async fn send(node: &dyn NodeConnector, body: &[u8]) -> Option<http::Reply> {
    let call = async {
        let stream = node.connect().await.ok()?;
        let request = http::request(
            Method::POST,
            http::NODE_HOST,
            "/v1/config",
            &[(CONTENT_TYPE, "application/json")],
            body.to_vec(),
        )
        .ok()?;
        http::exchange(stream, request, CONFIG_REPLY_LIMIT_BYTES)
            .await
            .ok()
    };
    tokio::time::timeout(CONFIG_CALL_TIMEOUT, call)
        .await
        .ok()
        .flatten()
}

/// Waits until the `health` call of the node succeeds, then sends the configuration. A call
/// that fails without a refusal (no connection, no response, a status outside 200 and 4xx) is
/// repeated until the node accepts or refuses.
pub async fn inject(node: &dyn NodeConnector, body: &[u8]) -> Injection {
    let mut failures: u64 = 0;
    loop {
        if health::node_health(node).await.is_none() {
            tokio::time::sleep(HEALTH_POLL_PAUSE).await;
            continue;
        }
        let status = match send(node, body).await {
            Some(reply) if reply.status == 200 => return Injection::Accepted,
            Some(reply) if (400..500).contains(&reply.status) => {
                return Injection::Rejected {
                    status: reply.status,
                    code: failure_code(&reply.body),
                };
            }
            Some(reply) => reply.status,
            None => 0,
        };
        if failures.is_multiple_of(FAILURE_LOG_PERIOD) {
            crate::log(&match status {
                0 => "operator configuration: the call got no response, repeating".to_string(),
                status => format!("operator configuration: status {status}, repeating"),
            });
        }
        failures += 1;
        tokio::time::sleep(RETRY_PAUSE).await;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::testing::{health_body, Behavior, Call, FakeNode};

    fn environment(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let values: HashMap<String, String> = pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        move |name: &str| values.get(name).filter(|value| !value.is_empty()).cloned()
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn the_provider_names_are_those_of_the_definitions_in_file_order() {
        assert_eq!(
            provider_names(crate::DEFINITIONS).unwrap(),
            names(&[
                "google_workspace",
                "microsoft",
                "slack",
                "notion",
                "x",
                "link",
                "granola",
                "mercury"
            ])
        );
        assert!(provider_names("[]").is_err());
    }

    #[test]
    fn every_row_of_the_variable_table_names_a_provider_of_the_definitions() {
        let providers = provider_names(crate::DEFINITIONS).unwrap();
        for variables in &CLIENT_VARIABLES {
            assert!(providers.iter().any(|name| name == variables.provider));
        }
    }

    #[test]
    fn the_configuration_names_every_provider_and_fills_missing_values_with_empty_strings() {
        let variable = environment(&[
            ("CHARACTER_API_BASE_URL", "https://api.example.test"),
            ("GOOGLE_CLIENT_ID", "google-id"),
            ("GOOGLE_CLIENT_SECRET", "google-secret"),
            ("OUTLOOK_CLIENT_ID", "outlook-id"),
            ("OUTLOOK_CLIENT_SECRET", "outlook-secret"),
            ("SLACK_CLIENT_ID", "slack-id"),
            ("NOTION_CLIENT_SECRET", ""),
            ("X_CLIENT_ID", "x-id"),
            ("X_CLIENT_SECRET", "x-secret"),
            ("LINK_CLIENT_ID", "link-id"),
            ("LINK_CLIENT_SECRET", "link-secret"),
            ("STRIPE_PUBLISHABLE_KEY", "pk_test_1"),
        ]);
        let providers = provider_names(crate::DEFINITIONS).unwrap();
        let body = operator_config(&providers, &variable, None).unwrap();
        let expected = json!({
            "providers": {
                "google_workspace": {
                    "client_id": "google-id",
                    "client_secret": "google-secret",
                    "redirect_uri": "https://api.example.test/api/integrations/google_workspace/oauth/callback",
                    "publishable_key": "",
                },
                "microsoft": {
                    "client_id": "outlook-id",
                    "client_secret": "outlook-secret",
                    "redirect_uri": "https://api.example.test/api/integrations/microsoft/oauth/callback",
                    "publishable_key": "",
                },
                "slack": {
                    "client_id": "slack-id",
                    "client_secret": "",
                    "redirect_uri": "https://api.example.test/api/integrations/slack/oauth/callback",
                    "publishable_key": "",
                },
                "notion": {
                    "client_id": "",
                    "client_secret": "",
                    "redirect_uri": "https://api.example.test/api/integrations/notion/oauth/callback",
                    "publishable_key": "",
                },
                "x": {
                    "client_id": "x-id",
                    "client_secret": "x-secret",
                    "redirect_uri": "https://api.example.test/api/integrations/x/oauth/callback",
                    "publishable_key": "",
                },
                "link": {
                    "client_id": "link-id",
                    "client_secret": "link-secret",
                    "redirect_uri": "https://api.example.test/api/integrations/link/oauth/callback",
                    "publishable_key": "pk_test_1",
                },
                "granola": {
                    "client_id": "",
                    "client_secret": "",
                    "redirect_uri": "https://api.example.test/api/integrations/granola/oauth/callback",
                    "publishable_key": "",
                },
                "mercury": {
                    "client_id": "",
                    "client_secret": "",
                    "redirect_uri": "https://api.example.test/api/integrations/mercury/oauth/callback",
                    "publishable_key": "",
                },
            }
        });
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), expected);
    }

    #[test]
    fn the_callback_address_joins_the_base_address_without_a_double_slash() {
        let variable = environment(&[("CHARACTER_API_BASE_URL", "https://api.example.test/")]);
        let body = operator_config(&names(&["slack"]), &variable, None).unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value["providers"]["slack"]["redirect_uri"],
            "https://api.example.test/api/integrations/slack/oauth/callback"
        );
    }

    #[test]
    fn a_provider_outside_the_variable_table_gets_its_callback_address_only() {
        let variable = environment(&[("CHARACTER_API_BASE_URL", "https://api.example.test")]);
        let body = operator_config(&names(&["later_provider"]), &variable, None).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"providers": {"later_provider": {
                "client_id": "",
                "client_secret": "",
                "redirect_uri": "https://api.example.test/api/integrations/later_provider/oauth/callback",
                "publishable_key": "",
            }}})
        );
    }

    #[test]
    fn the_configuration_names_the_log_store_of_the_environment() {
        let variable = environment(&[
            ("CHARACTER_API_BASE_URL", "https://api.example.test"),
            (
                "CREDENTIAL_ENCLAVE_LOG_BUCKET",
                "character-credential-log-dev-1",
            ),
            ("CREDENTIAL_ENCLAVE_LOG_REGION", "us-west-2"),
        ]);
        let log_store = LogStore::from_variables(&variable).unwrap().unwrap();
        assert_eq!(
            log_store.host(),
            "character-credential-log-dev-1.s3.us-west-2.amazonaws.com"
        );
        let body = operator_config(&names(&["slack"]), &variable, Some(&log_store)).unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value["log_store"],
            json!({"bucket": "character-credential-log-dev-1", "region": "us-west-2"})
        );
        // Without the two variables the configuration has no such key.
        let variable = environment(&[("CHARACTER_API_BASE_URL", "https://api.example.test")]);
        assert_eq!(LogStore::from_variables(&variable), Ok(None));
        let body = operator_config(&names(&["slack"]), &variable, None).unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert!(value.get("log_store").is_none());
    }

    #[test]
    fn a_log_store_is_a_bucket_name_and_a_region_name() {
        let read = |bucket: &str, region: &str| {
            LogStore::from_variables(&environment(&[
                ("CREDENTIAL_ENCLAVE_LOG_BUCKET", bucket),
                ("CREDENTIAL_ENCLAVE_LOG_REGION", region),
            ]))
        };
        for (bucket, region) in [
            ("abc", "us-west-2"),
            ("character-credential-log-prod-1", "us-west-2"),
            ("0bucket9", "ap-southeast-3"),
            ("bucket", "us-gov-east-1"),
        ] {
            assert!(read(bucket, region).unwrap().is_some(), "{bucket} {region}");
        }
        // One variable without the other.
        assert_eq!(
            read("bucket", ""),
            Err("CREDENTIAL_ENCLAVE_LOG_REGION is not set".to_string())
        );
        assert_eq!(
            read("", "us-west-2"),
            Err("CREDENTIAL_ENCLAVE_LOG_BUCKET is not set".to_string())
        );
        // A name of another form: the host of the allow list would not be a bucket of S3.
        for bucket in [
            "ab",
            "Bucket",
            "my.bucket",
            "bucket/x",
            "-bucket",
            "bucket-",
        ] {
            assert_eq!(
                read(bucket, "us-west-2"),
                Err("CREDENTIAL_ENCLAVE_LOG_BUCKET is not a bucket name".to_string()),
                "{bucket}"
            );
        }
        assert!(read(&"b".repeat(64), "us-west-2").is_err());
        for region in [
            "us-west",
            "us-2",
            "US-west-2",
            "usa-west-2",
            "us-west-222",
            "us-west-2.evil.example",
            "us-west-2/",
        ] {
            assert_eq!(
                read("bucket", region),
                Err("CREDENTIAL_ENCLAVE_LOG_REGION is not a region name".to_string()),
                "{region}"
            );
        }
    }

    #[test]
    fn there_is_no_configuration_without_the_base_address() {
        let providers = names(&["slack"]);
        let missing = environment(&[("SLACK_CLIENT_ID", "slack-id")]);
        assert_eq!(
            operator_config(&providers, &missing, None),
            Err(ConfigError::NoBaseUrl)
        );
        let empty = environment(&[("CHARACTER_API_BASE_URL", "")]);
        assert_eq!(
            operator_config(&providers, &empty, None),
            Err(ConfigError::NoBaseUrl)
        );
        let slash = environment(&[("CHARACTER_API_BASE_URL", "/")]);
        assert_eq!(
            operator_config(&providers, &slash, None),
            Err(ConfigError::NoBaseUrl)
        );
    }

    #[test]
    fn the_summary_names_providers_and_holds_no_value() {
        let variable = environment(&[
            ("GOOGLE_CLIENT_ID", "google-id-value"),
            ("GOOGLE_CLIENT_SECRET", "google-secret-value"),
            ("LINK_CLIENT_ID", "link-id-value"),
        ]);
        let providers = provider_names(crate::DEFINITIONS).unwrap();
        let line = summary(&providers, &variable);
        assert_eq!(
            line,
            "operator configuration: client id set for google_workspace, link; \
             not set for microsoft, slack, notion, x, granola, mercury"
        );
        assert_eq!(
            summary(&names(&["slack"]), &environment(&[])),
            "operator configuration: client id set for none; not set for slack"
        );
    }

    fn config_calls(node: &FakeNode) -> Vec<Call> {
        node.calls()
            .into_iter()
            .filter(|call| call.path == "/v1/config")
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn the_configuration_is_sent_once_the_health_call_succeeds() {
        let node = FakeNode::new(Behavior::Unreachable);
        let injection = {
            let node = node.clone();
            tokio::spawn(async move { inject(node.as_ref(), b"{\"providers\":{}}").await })
        };
        // The node is still booting.
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!injection.is_finished());
        assert!(node.calls().is_empty());

        node.set(Behavior::Answer(Arc::new(|call: &Call| {
            match call.path.as_str() {
                "/v1/health" => (200, health_body(false, 0, 1_790_000_000_000)),
                _ => (200, r#"{"configured":true}"#.to_string()),
            }
        })));
        assert_eq!(injection.await.unwrap(), Injection::Accepted);

        let calls = node.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            (calls[0].method.as_str(), calls[0].path.as_str()),
            ("GET", "/v1/health")
        );
        assert_eq!(
            calls[1],
            Call {
                method: "POST".to_string(),
                path: "/v1/config".to_string(),
                body: b"{\"providers\":{}}".to_vec(),
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_configuration_is_not_sent_again() {
        let node = FakeNode::answering(|call| match call.path.as_str() {
            "/v1/health" => (200, health_body(false, 0, 1)),
            _ => (
                400,
                r#"{"code":"invalid_request","message":"a redirect_uri is not an https address"}"#
                    .to_string(),
            ),
        });
        assert_eq!(
            inject(node.as_ref(), b"{}").await,
            Injection::Rejected {
                status: 400,
                code: "invalid_request".to_string()
            }
        );
        assert_eq!(config_calls(&node).len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_configuration_call_is_repeated_until_the_node_answers() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let node = {
            let attempts = attempts.clone();
            FakeNode::answering(move |call| match call.path.as_str() {
                "/v1/health" => (200, health_body(false, 0, 1)),
                _ => match attempts.fetch_add(1, Ordering::SeqCst) {
                    0 | 1 => (500, r#"{"code":"internal","message":"x"}"#.to_string()),
                    _ => (200, r#"{"configured":true}"#.to_string()),
                },
            })
        };
        assert_eq!(inject(node.as_ref(), b"{}").await, Injection::Accepted);
        assert_eq!(config_calls(&node).len(), 3);
    }

    #[test]
    fn the_failure_code_is_read_only_when_it_is_a_plain_word() {
        assert_eq!(
            failure_code(br#"{"code":"invalid_request","message":"m"}"#),
            "invalid_request"
        );
        assert_eq!(failure_code(br#"{"code":"Not A Code\n"}"#), "");
        assert_eq!(failure_code(br#"{"message":"m"}"#), "");
        assert_eq!(failure_code(b"not json"), "");
    }
}
