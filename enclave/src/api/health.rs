//! `GET /v1/health` (enclave.md 5.1).

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;

use super::json_ok;
use super::responses::{Health, LogCounts, LogStoreState};
use crate::state::Node;

/// The diagnostic values of a node. `accounts` counts the accounts that have a chain on this
/// node and `grants` the accounts that have a grant within its time (the operator domain reads
/// it to see that a delegation transfer arrived). `log_store` is null on a node without a log
/// store. Otherwise it names the bucket and its region, the end of the credentials the node
/// holds (0 when it holds none) and the number of accounts that have a pending entry. `log`
/// counts the entries, events, writes and batch calls since the node started.
pub async fn health(State(node): State<Arc<Node>>) -> Response {
    let counters = &node.log_counters;
    json_ok(&Health {
        node: &node.node,
        release: node.release,
        platform: node.platform.name(),
        custody: node.custody.as_str(),
        started_ms: node.started_ms,
        time_ms: node.now_ms(),
        configured: node.is_configured(),
        closing: node.closing.load(Ordering::SeqCst),
        accounts: node.account_count(),
        grants: node.grant_count(),
        mail_providers: &["naver_mail"],
        log_store: node.log_store.id().map(|id| LogStoreState {
            bucket: id.bucket(),
            region: id.region(),
            credentials_expires_ms: node.log_store.credentials_expires_ms(),
            pending: node.pending_count(),
        }),
        log: LogCounts {
            entries: counters.entries.load(Ordering::Relaxed),
            events: counters.events.load(Ordering::Relaxed),
            writes: counters.writes.load(Ordering::Relaxed),
            write_failures: counters.write_failures.load(Ordering::Relaxed),
            open_batches: node.open_batch_count(),
            batch_calls: counters.batch_calls.load(Ordering::Relaxed),
            batch_requests: counters.batch_requests.load(Ordering::Relaxed),
        },
    })
}
