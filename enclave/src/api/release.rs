//! `POST /v1/release` (enclave.md 5.9): hands one vault value to the worker right before it
//! fills a form, and records it.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::ProtocolError;

use super::responses::Released;
use super::{invalid, json_ok, record_of, respond, ApiError, JsonBody};
use crate::log_store;
use crate::state::{events, lock, Node};
use crate::vault;

/// Longest `origin`, in bytes.
const ORIGIN_LIMIT_BYTES: usize = 512;

pub async fn release(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// True for an origin string `https://host` or `https://host:port`. The node checks the form
/// only: whether the origin is the site of the vault item is decided by the caller, and the
/// node writes the value it received into the entry.
fn is_https_origin(origin: &str) -> bool {
    let Some(rest) = origin.strip_prefix("https://") else {
        return false;
    };
    !rest.is_empty()
        && origin.len() <= ORIGIN_LIMIT_BYTES
        && rest.chars().all(|character| {
            !character.is_control()
                && !character.is_whitespace()
                && !matches!(character, '/' | '?' | '#' | '@' | '\\')
        })
}

/// Works without the operator configuration. The pair of record kind and field decides the
/// value and the entry:
///
/// | kind | field | value | entry |
/// | --- | --- | --- | --- |
/// | `vault_password` | `password` | the `value` of the plaintext | `secret_released` |
/// | `vault_totp` | `totp` | the 6-digit code of the seed at node time | `totp_issued` |
/// | `vault_card` | `card_number`, `card_cvc` | `number` or `cvc` of the plaintext | `secret_released` |
///
/// Any other pair is `not_allowed`, and so is a record of kind `oauth`: this call opens vault
/// kinds only. A TOTP seed never leaves the node. The value leaves only after the log store
/// confirmed the entry.
async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let user_id = body.user_id()?;
    let record = record_of(&body, "record")?;
    let field = body.text("field")?;
    let origin = body.text("origin")?;
    if !is_https_origin(origin) {
        return Err(invalid("origin"));
    }
    let context = body.context()?;

    node.ensure_open()?;
    let account = node.account(user_id).ok_or(ProtocolError::GrantRequired)?;
    log_store::admit(node, user_id, &account).await?;
    let (selected, entry, seq) = {
        let mut account = lock(&account);
        node.ensure_open()?;
        let now_ms = node.now_ms();
        let grant = account.active(now_ms)?;
        account.ensure_capacity()?;
        let selected = vault::open_record(&grant, user_id, &record)?.select(field, now_ms)?;
        let event = if selected.is_totp() {
            events::totp_issued(&record.id, origin, context)
        } else {
            events::secret_released(&record.id, selected.kind().as_str(), field, origin, context)
        };
        // The entry raises the end of the chain before the value leaves the node.
        let entry = node.append_entry(
            &mut account,
            user_id,
            &grant.key_id,
            &grant.log_pk,
            now_ms,
            &event,
        )?;
        (selected, entry, account.head.seq)
    };
    // The value leaves only after the log store confirmed the entry.
    log_store::confirm(node, user_id, &account, &[seq]).await?;
    Ok(json_ok(&Released {
        value: selected.hand_out(&entry),
        entry,
    }))
}

#[cfg(test)]
mod tests {
    use super::is_https_origin;

    #[test]
    fn an_origin_is_https_with_a_host_and_an_optional_port() {
        for origin in [
            "https://shop.example",
            "https://shop.example:8443",
            "https://xn--9n2bp8q.example",
        ] {
            assert!(is_https_origin(origin), "{origin}");
        }
        for origin in [
            "",
            "https://",
            "http://shop.example",
            "shop.example",
            "https://shop.example/",
            "https://shop.example/path",
            "https://user@shop.example",
            "https://shop.example?x",
            "https://shop.example#x",
            "https://shop .example",
            "https://shop.example\n",
        ] {
            assert!(!is_https_origin(origin), "{origin:?}");
        }
        assert!(!is_https_origin(&format!("https://{}", "a".repeat(600))));
    }
}
