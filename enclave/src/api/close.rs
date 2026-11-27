//! `POST /v1/close` (enclave.md 5.11): the orderly shutdown.
//!
//! `close` raises the closing flag. From then on every command and every call that uses a
//! credential is refused with `closing`, and the node creates no further entry for a call. A
//! call that was in progress runs to its end. `peer/export` keeps working: the caller hands the
//! delegations of the node on before the node ends.
//!
//! The shutdown signs nothing and drops nothing. An entry the log store confirmed is in the
//! store, and its act may have taken place. An entry the store did not confirm is in the
//! memory of the node and is gone with it: its act did not take place, and the absence of its
//! object from the store says so.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;

use super::json_ok;
use super::responses::Closed;
use crate::state::Node;

/// Starts the orderly shutdown. `accounts` is the number of accounts this node created an
/// entry for.
pub async fn close(State(node): State<Arc<Node>>) -> Response {
    node.closing.store(true, Ordering::SeqCst);
    json_ok(&Closed {
        accounts: node.account_count(),
    })
}
