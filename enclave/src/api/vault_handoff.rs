//! `POST /v1/vault/handoff` (enclave.md 5.9c, protocol.md 10.5): hands the value of a vault
//! secret, for one request to its site, to a node of the forward role, and records it.
//!
//! The site of a vault secret is a host an account chose, and a node of the delegation role
//! connects to the addresses of its provider definitions and to its log store only. So this
//! node does not send the request in which the value is used. It opens the record, holds the
//! request to the reach of the record, records the use, and seals the value, with that one
//! request, to the sealing key of a node of the forward role it verified. The caller carries
//! the envelope to that node, whose call `vault/send` sends the request (enclave.md 5.16).
//!
//! What the call answers is the envelope, a ciphertext only the node it names can open, and
//! the place of the event on the chain of the account. The value is in no response of this
//! node: of a record without the slot `field` it is in the clear in the memory of this node
//! while the call runs, in the memory of the node of the forward role while that node sends
//! the request, and inside the TLS connection to the site.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Response;
use credential_enclave_protocol::log::EntryKind;
use credential_enclave_protocol::secret_use::BoundRequest;
use credential_enclave_protocol::ProtocolError;

use super::responses::HandedOff;
use super::{json_ok, record_of, respond, ApiError, JsonBody};
use crate::log_store;
use crate::state::{lock, Node};
use crate::vault;

pub async fn handoff(State(node): State<Arc<Node>>, request: Request) -> Response {
    respond(run(&node, request).await)
}

/// Works without the operator configuration. The order of the judgements:
///
/// 1. The form of the body: `user_id`, `record`, `request` (the request object of protocol.md
///    10.5, read by [`BoundRequest::from_value`], the reader the node of the forward role reads
///    it with), `peer` (an attestation response) and `context`.
/// 2. The receiving node: `peer` is the attestation response of a node of the forward role of
///    the platform and the measurement of this node (`ForwardNodes::verify`). Otherwise
///    `peer_unverified`.
/// 3. The common front: the node is not closing, it can write to its log store, and the grant
///    of the account is Active.
/// 4. The record: it opens under the user key of the grant, it is of kind `vault_secret`, and
///    its reach admits the request. The host of the request is one of its `sites` and the
///    slot of the request one of its `slots`. Otherwise `not_allowed`.
/// 5. The use event `provider_request` of the use (`vault::events::use_requested`): the
///    request as the caller stated it, the name of the record, the slot and the receiving
///    node.
///
/// A call that is refused up to here creates no entry, and none of these judgements reads the
/// value of the record: what the call answers without an entry is the same for every value a
/// record can hold.
///
/// The plaintext is read for the value after the log store confirmed the entry that holds the
/// event, and the value is sealed then (`ForRequest::hand_off`). A value no envelope carries
/// (no string, more than 12,000 bytes, fewer than 8 bytes without the white space at its ends,
/// a control character for a header slot
/// or for a slot of HTTP Basic, a colon for the slot `basic:user`) is `record_invalid` at
/// that point: the response carries no envelope and the entry stays.
async fn run(node: &Node, request: Request) -> Result<Response, ApiError> {
    let body = JsonBody::read(request).await?;
    let user_id = body.user_id()?;
    let record = record_of(&body, "record")?;
    let bound = BoundRequest::from_value(body.object("request")?)?;
    let peer = body.object("peer")?;
    let context = body.context()?;

    // The value is sealed to a node of the forward role of the program of this node, and to
    // no other node.
    let to = node.forward_nodes.verify(peer)?;

    node.ensure_open()?;
    let account = node.account(user_id).ok_or(ProtocolError::GrantRequired)?;
    log_store::admit(node, &account).await?;
    // The number of the use and the key material of its seal are drawn before the chain
    // grows: a failure of the random source leaves no entry of a use without an envelope.
    let nonce = node.random_public::<16>()?;
    let seed = node.random_secret::<32>()?;
    let (chosen, place) = {
        let mut account = lock(&account);
        node.ensure_open()?;
        let now_ms = node.now_ms();
        let grant = account.active(now_ms)?;
        let chosen = vault::open_record(&grant, user_id, &record)?.select_for_request(&bound)?;
        let event =
            vault::events::use_requested(&record.id, &bound, context, chosen.name(), &to.node());
        // The event is on the chain before the value is sealed for another node.
        let place = node.create_event(
            &mut account,
            user_id,
            &grant.key_id,
            &grant.log_pk,
            now_ms,
            EntryKind::Use,
            event,
        )?;
        (chosen, place)
    };
    // The plaintext is read for the value, and the value is sealed, only after the log store
    // confirmed the entry that holds the event.
    let log = log_store::commit(node, user_id, &account, &[(place, true)])
        .await?
        .into_iter()
        .next()
        .ok_or_else(ApiError::internal)?;
    let envelope = chosen.hand_off(
        &log,
        &to,
        &node.keys,
        node.now_ms(),
        &nonce,
        user_id,
        &record.id,
        &bound,
        &seed,
    )?;
    Ok(json_ok(&HandedOff { envelope, log }))
}
