//! `POST /v1/vault/store` (enclave.md 5.9b): takes a value the operator domain holds and hands
//! it back as a record of the vault, and records that it did.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::log::EntryKind;
use credential_enclave_protocol::record::Kind;
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::secret_use::is_site_host;
use credential_enclave_protocol::vault_secret::{self, Reach, Sites};
use credential_enclave_protocol::{limits, ProtocolError};
use serde_json::Value;

use super::responses::Stored;
use super::{invalid, json_ok, respond, ApiError, JsonBody};
use crate::log_store;
use crate::state::{lock, Node};
use crate::vault::{self, OperatorValue};

/// The two values of a record that a node draws from its random source. The call takes
/// neither from its caller.
const DRAWN_BY_THE_NODE: [&str; 2] = ["id", "nonce"];

/// The keys of a body that asks for a record of kind `vault_secret`. A body that asks for a
/// record of kind `vault_password` carries none of them.
const OF_A_NAMED_VALUE: [&str; 3] = ["name", "sites", "slots"];

pub async fn store(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run_store(&node, request).await)
}

/// True for a value the call takes: 1 to 12,000 bytes of UTF-8 without U+0000.
fn is_value(value: &str) -> bool {
    (1..=limits::VAULT_SECRET_VALUE_BYTES).contains(&value.len()) && !value.contains('\0')
}

/// What a body asks a record for, next to the value: the kind of the record, and what the
/// event of the call names.
enum Asked {
    /// A record of kind `vault_secret`: the name and the reach of the body.
    Named { name: String, reach: Reach },
    /// A record of kind `vault_password`: the host of the login the password belongs to.
    Password { site: String },
}

/// Reads what the body asks for. `kind` is `vault_secret` (also when the key is absent) or
/// `vault_password`: every other value is `invalid_request`.
///
/// | kind | keys | form |
/// | --- | --- | --- |
/// | `vault_secret` | `name`, `sites`, `slots` | a name (`[A-Z][A-Z0-9_]{0,63}`) and a reach of protocol.md section 6. The body carries no `site` |
/// | `vault_password` | `site` | the host of a site (protocol.md section 6). The body carries no `name`, `sites` or `slots` |
fn asked_of(body: &JsonBody) -> Result<Asked, ApiError> {
    let stated = |key: &str| body.as_value().get(key).is_some();
    let kind = match body.get("kind") {
        None => Kind::VaultSecret,
        Some(kind) => kind
            .as_str()
            .and_then(Kind::parse)
            .filter(|kind| matches!(kind, Kind::VaultSecret | Kind::VaultPassword))
            .ok_or_else(|| invalid("kind"))?,
    };
    match kind {
        Kind::VaultPassword => {
            if OF_A_NAMED_VALUE.iter().any(|key| stated(key)) {
                return Err(ApiError::with_message(
                    ProtocolError::InvalidRequest,
                    "a record of kind vault_password takes no name, sites or slots",
                ));
            }
            let site = body.text("site")?;
            if !is_site_host(site) {
                return Err(invalid("site"));
            }
            Ok(Asked::Password {
                site: site.to_string(),
            })
        }
        _ => {
            if stated("site") {
                return Err(ApiError::with_message(
                    ProtocolError::InvalidRequest,
                    "a record of kind vault_secret takes sites, and no site",
                ));
            }
            let name = body.text("name")?;
            if !vault_secret::is_name(name) {
                return Err(invalid("name"));
            }
            let sites: &Value = body.get("sites").ok_or_else(|| invalid("sites"))?;
            if Sites::from_value(sites).is_none() {
                return Err(invalid("sites"));
            }
            let reach = body
                .get("slots")
                .and_then(|slots| Reach::from_values(sites, slots))
                .ok_or_else(|| invalid("slots"))?;
            Ok(Asked::Named {
                name: name.to_string(),
                reach,
            })
        }
    }
}

/// Works without the operator configuration. The call checks the form of its body, passes the
/// common front, makes the record under the user key of the grant, and creates the control
/// event `connection_created` of that record, with its kind and its name or its site
/// (`vault::events`). The record leaves only after the log store confirmed the entry that
/// holds the event: when it does not, the record is dropped here and the value with it.
///
/// The plaintext of the record is written by the node: the value of the body, for a record of
/// kind `vault_secret` the name, the sites and the slots of the body, and the source
/// `operator`. The `id` and the nonce of the record are node randomness. A body that names an
/// `id` or a `nonce` is `invalid_request`: the node does not encrypt a value of its caller
/// under the record key of a record that exists.
async fn run_store(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let user_id = body.user_id()?;
    if DRAWN_BY_THE_NODE
        .iter()
        .any(|key| body.as_value().get(key).is_some())
    {
        return Err(ApiError::with_message(
            ProtocolError::InvalidRequest,
            "the node chooses the id and the nonce of the record",
        ));
    }
    let asked = asked_of(&body)?;
    let value = body.text("value")?;
    if !is_value(value) {
        return Err(invalid("value"));
    }
    let context = body.context()?;
    // From here on the value is a secret of the node: it leaves as the ciphertext of the
    // record and in no other form.
    let value = Secret::new(value.to_string());
    let value = match &asked {
        Asked::Named { name, reach } => OperatorValue::named(name, reach, &value),
        Asked::Password { .. } => OperatorValue::password(&value),
    }
    .ok_or(ApiError::with_message(
        ProtocolError::TooLarge,
        "the plaintext of the record is longer than 12,272 bytes",
    ))?;

    node.ensure_open()?;
    let account = node.account(user_id).ok_or(ProtocolError::GrantRequired)?;
    log_store::admit(node, &account).await?;
    let id = node.random_public::<16>()?;
    let nonce = node.random_public::<12>()?;
    // The record and its event are created under the account lock.
    let (record, place) = {
        let mut account = lock(&account);
        node.ensure_open()?;
        let now_ms = node.now_ms();
        let grant = account.active(now_ms)?;
        let record = value.seal(&grant, &id, &nonce, user_id);
        let event = match &asked {
            Asked::Named { name, .. } => vault::events::secret_stored(&record.id, name, context),
            Asked::Password { site } => vault::events::password_stored(&record.id, site, context),
        };
        let place = node.create_event(
            &mut account,
            user_id,
            &grant.key_id,
            &grant.log_pk,
            now_ms,
            EntryKind::Control,
            event,
        )?;
        (record, place)
    };
    // The record leaves only after the log store confirmed the entry that holds the event.
    let log = log_store::commit(node, user_id, &account, &[(place, true)])
        .await?
        .into_iter()
        .next()
        .ok_or_else(ApiError::internal)?;
    Ok(json_ok(&Stored { record, log }))
}

#[cfg(test)]
mod tests {
    use super::is_value;

    #[test]
    fn a_value_is_1_to_12000_bytes_without_the_character_zero() {
        for value in ["x", "sk-live", "값", "a b\n\tc", &"v".repeat(12_000)] {
            assert!(is_value(value), "{} bytes", value.len());
        }
        // 4,000 characters of three bytes each.
        assert!(is_value(&"값".repeat(4_000)));
        for value in ["", "a\0b", "\0", &"v".repeat(12_001), &"값".repeat(4_001)] {
            assert!(!is_value(value), "{} bytes", value.len());
        }
    }
}
