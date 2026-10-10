//! Tests of the whole node (enclave.md section 12): a node built from the embedded provider
//! definitions, driven through its router, with a TLS stand-in in the place of every provider.

use std::collections::BTreeSet;

use serde_json::json;

use crate::providers::{endpoint, Definitions};
use crate::testing::{Provider, Reply, Seen, LOG_HOST};

mod canary;
mod commands;
mod forward;
mod log;
mod log_store;
mod mail;
mod oauth;
mod peer;
mod records;
mod surface;

/// Every host a node can connect to with the embedded definitions: the token addresses, the
/// revocation addresses and the hosts of the `api` rules.
fn provider_hosts() -> Vec<String> {
    let definitions = Definitions::embedded();
    let mut hosts = BTreeSet::new();
    for name in definitions.names() {
        let definition = definitions.get(name).unwrap();
        hosts.insert(endpoint(&definition.token.url).unwrap().host);
        if let Some(revoke) = &definition.revoke {
            hosts.insert(endpoint(&revoke.url).unwrap().host);
        }
        for rule in &definition.api {
            hosts.insert(rule.host.clone());
        }
    }
    hosts.into_iter().collect()
}

/// A stand-in for every provider host that answers with `handler`.
async fn provider(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Provider {
    let hosts = provider_hosts();
    let hosts: Vec<&str> = hosts.iter().map(String::as_str).collect();
    Provider::start(&hosts, handler).await
}

/// A stand-in that answers every request with `200 {"ok":true}`.
async fn quiet_provider() -> Provider {
    provider(|_| Reply::json(200, &json!({"ok": true}))).await
}

/// A stand-in for the providers and for the log store that answers every request with
/// `200 {"ok":true}`: the log store confirms every write.
async fn quiet_provider_and_log_store() -> Provider {
    let quiet = |_: &Seen| Reply::json(200, &json!({"ok": true}));
    provider_and_log_store(quiet, quiet).await
}

/// A stand-in for every provider host and for the log store of the tests. `handler` answers
/// a request to a provider and `store` a write to the log store. The stand-in keeps the
/// requests of both in the order they arrived.
async fn provider_and_log_store(
    handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static,
    store: impl Fn(&Seen) -> Reply + Send + Sync + 'static,
) -> Provider {
    let mut hosts = provider_hosts();
    hosts.push(LOG_HOST.to_string());
    let hosts: Vec<&str> = hosts.iter().map(String::as_str).collect();
    Provider::start(&hosts, move |seen| match seen.server_name == LOG_HOST {
        true => store(seen),
        false => handler(seen),
    })
    .await
}
