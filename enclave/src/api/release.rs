//! `POST /v1/release` (enclave.md 5.9): hands one vault value to the worker right before it
//! fills a form, and records it.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::log::EntryKind;
use credential_enclave_protocol::released::SealTo;
use credential_enclave_protocol::ProtocolError;

use super::responses::Released;
use super::{invalid, json_ok, record_of, respond, ApiError, JsonBody};
use crate::log_store;
use crate::state::{events, lock, Node};
use crate::vault::{self, Sealing};

/// Longest `origin`, in bytes.
const ORIGIN_LIMIT_BYTES: usize = 512;

/// The scheme of an origin.
const SCHEME: &str = "https://";

pub async fn release(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// True for an origin string `https://host` or `https://host:port`. The node checks the form
/// only: whether the browser is at that origin is known to the caller alone, and the node
/// writes the value it received into the entry.
fn is_https_origin(origin: &str) -> bool {
    let Some(rest) = origin.strip_prefix(SCHEME) else {
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

/// The host of an origin [`is_https_origin`] accepts, for the comparison with the `sites` of a
/// record of kind `vault_secret`: what stands between the scheme and the port, in lower case.
/// An origin in which a colon is followed by anything but a port of 1 to 5 digits has no host:
/// the empty string, which no list of hosts admits.
fn host_of(origin: &str) -> String {
    let rest = origin.strip_prefix(SCHEME).unwrap_or_default();
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    let is_port = |port: &str| {
        (1..=5).contains(&port.len()) && port.bytes().all(|byte| byte.is_ascii_digit())
    };
    match port {
        Some(port) if !is_port(port) => String::new(),
        _ => host.to_ascii_lowercase(),
    }
}

/// The optional `seal_to` of the call: the public key the value is sealed to. An absent key
/// is a call that takes the value as it is. A value that is no key HPKE can seal to is
/// `invalid_request`.
fn seal_to_of(body: &JsonBody) -> Result<Option<SealTo>, ApiError> {
    match body.get("seal_to") {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .and_then(SealTo::parse)
            .map(Some)
            .ok_or_else(|| invalid("seal_to")),
    }
}

/// Works without the operator configuration. The pair of record kind and field decides the
/// value and the entry:
///
/// | kind | field | value | entry |
/// | --- | --- | --- | --- |
/// | `vault_password` | `password` | the `value` of the plaintext | `secret_released` |
/// | `vault_totp` | `totp` | the 6-digit code of the seed at node time | `totp_issued` |
/// | `vault_card` | `card_number`, `card_cvc` | `number` or `cvc` of the plaintext | `secret_released` |
/// | `vault_secret` | `value` | the `value` of the plaintext | `secret_released`, with the `name` of the record |
///
/// Any other pair is `not_allowed`, and so is a record of kind `oauth`: this call opens vault
/// kinds only. A record of kind `vault_secret` says itself where its value may go: the call
/// is `not_allowed` when its `slots` are not the slot `field`, or when its `sites` hold
/// neither the host of `origin` nor a host that host lies below. A call that is refused up to
/// here creates no entry. A TOTP seed never leaves the node.
///
/// The plaintext is read for the value after the log store confirmed the entry, and the value
/// leaves then. A plaintext that does not hold the value, and a seed that is not base32, are
/// `record_invalid` at that point: the response carries no value and the entry stays. So no
/// answer of this call depends on the content of a value unless an entry records the call.
///
/// With `seal_to`, the value leaves under the seal of that key (`sealed` of the response) and
/// not as it is: whoever carries the response to the holder of the key carries a ciphertext.
async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(node, request).await?;
    let user_id = body.user_id()?;
    let record = record_of(&body, "record")?;
    let field = body.text("field")?;
    let origin = body.text("origin")?;
    if !is_https_origin(origin) {
        return Err(invalid("origin"));
    }
    let host = host_of(origin);
    let seal_to = seal_to_of(&body)?;
    let context = body.context()?;

    node.ensure_open()?;
    let account = node.account(user_id).ok_or(ProtocolError::GrantRequired)?;
    log_store::admit(node, &account).await?;
    // The key material of the seal is drawn before the chain grows: a failure of the random
    // source leaves no entry of a release without a value.
    let seed = match seal_to {
        Some(_) => Some(node.random_secret::<32>()?),
        None => None,
    };
    let (selected, place) = {
        let mut account = lock(&account);
        node.ensure_open()?;
        let now_ms = node.now_ms();
        let grant = account.active(now_ms)?;
        let selected = vault::open_record(&grant, user_id, &record)?.select(field, &host)?;
        let event = if selected.is_totp() {
            events::totp_issued(&record.id, origin, context)
        } else {
            vault::events::released(
                &record.id,
                selected.kind(),
                field,
                origin,
                context,
                selected.name(),
            )
        };
        // The event is on the chain before the value leaves the node.
        let place = node.create_event(
            &mut account,
            user_id,
            &grant.key_id,
            &grant.log_pk,
            now_ms,
            EntryKind::Use,
            event,
        )?;
        (selected, place)
    };
    // The plaintext is read for the value, and the value leaves, only after the log store
    // confirmed the entry that holds the event.
    let log = log_store::commit(node, user_id, &account, &[(place, true)])
        .await?
        .into_iter()
        .next()
        .ok_or_else(ApiError::internal)?;
    let sealing = match (&seal_to, &seed) {
        (Some(to), Some(hpke_seed)) => Some(Sealing {
            to,
            user_id,
            record_id: &record.id,
            field,
            origin,
            hpke_seed,
        }),
        _ => None,
    };
    Ok(json_ok(&Released {
        handed_out: selected.hand_out(&log, node.now_ms(), sealing)?,
        log,
    }))
}

#[cfg(test)]
mod tests {
    use super::{host_of, is_https_origin};

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

    #[test]
    fn the_host_of_an_origin_is_its_name_in_lower_case_without_the_port() {
        for (origin, host) in [
            ("https://shop.example", "shop.example"),
            ("https://shop.example:8443", "shop.example"),
            ("https://Shop.EXAMPLE", "shop.example"),
            ("https://xn--9n2bp8q.example:443", "xn--9n2bp8q.example"),
            ("https://shop.example:65535", "shop.example"),
            // What follows the colon is no port: the origin has no host.
            ("https://shop.example:evil.example", ""),
            ("https://shop.example:", ""),
            ("https://shop.example:443:8443", ""),
            ("https://shop.example:123456", ""),
            ("https://shop.example:44a", ""),
            // An address in brackets is the host of no record: `sites` holds names.
            ("https://[2001:db8::1]:8443", ""),
            // No name in front of the port.
            ("https://:443", ""),
        ] {
            assert!(is_https_origin(origin), "{origin}");
            assert_eq!(host_of(origin), host, "{origin}");
        }
    }
}
