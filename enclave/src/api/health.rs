//! `GET /v1/health` (enclave.md 5.1).

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;

use super::json_ok;
use super::responses::{
    EgressCounts, Health, IdleConnectionCounts, IdleReuseCounts, LateRefreshCounts, Load,
    LogCounts, LogStoreState, OpenFailureCounts, RefreshCounts, StateCounts,
    WriteAttemptFailureCounts, WriteMsBuckets,
};
use crate::descriptors;
use crate::load;
use crate::state::Node;

/// The diagnostic values of a node. `accounts` counts the accounts that have a chain on this
/// node and `grants` the accounts that have a grant within its time (the operator domain reads
/// it to see that a delegation transfer arrived). `log_store` is null on a node without a log
/// store. Otherwise it names the bucket and its region, the end of the credentials the node
/// holds (0 when it holds none), the number of accounts that have an entry the store has not
/// confirmed and the age of the oldest pending entry as the last sweep of the node found it.
/// `log` counts the entries, events, write attempts (confirmed, failed by cause, repeated, and
/// the time to confirmation of the confirmed ones) and batch calls since the node started.
/// `load` is the load at the moment of the call: the provider requests in flight, the calls
/// that hold a forward slot, the connections from the backend open now and the ones refused
/// at accept since the start, the CPU time and the memory of the kernel the node runs in,
/// read from procfs (`crate::load`), null where the kernel exposes no value, and the open
/// file descriptors of the node process and their limit (`crate::descriptors`). `egress` counts
/// the outbound connections (opened, failed by cause, repeated, being opened, and the requests
/// that reused an idle connection), `refresh` the token address calls of `refresh` the node
/// continued after their time limit, by outcome and in progress, and `state` the sizes of the
/// variable state of the accounts (kept `refresh` responses, merge keys, unconfirmed entries)
/// and the idle connections by peer.
///
/// Every count of the accounts is a count the node keeps with the state it counts
/// (`crate::state::StateCounters`): the call walks no account, so its time does not grow with
/// the number of accounts.
pub async fn health(State(node): State<Arc<Node>>) -> Response {
    let counters = &node.log_counters;
    let egress = &node.egress.counters;
    let refresh = &node.refresh_counters;
    let state = &node.counters;
    let cpu = load::read_cpu();
    let memory = load::read_memory();
    let read = |counter: &std::sync::atomic::AtomicU64| counter.load(Ordering::Relaxed);
    let count = |counter: &std::sync::atomic::AtomicUsize| counter.load(Ordering::Relaxed);
    let buckets = &counters.write_ms_buckets;
    let app_password_providers = node.definitions.app_password_names();
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
        grants: count(&state.grants),
        mail_providers: &["naver_mail"],
        app_password_providers: &app_password_providers,
        log_store: node.log_store.id().map(|id| LogStoreState {
            bucket: id.bucket(),
            region: id.region(),
            credentials_expires_ms: node.log_store.credentials_expires_ms(),
            pending: count(&state.pending_accounts),
            pending_oldest_ms: node.pending_oldest_ms(),
        }),
        log: LogCounts {
            entries: read(&counters.entries),
            events: read(&counters.events),
            writes: read(&counters.writes),
            write_failures: read(&counters.write_failures),
            open_batches: count(&state.open_batches),
            batch_calls: read(&counters.batch_calls),
            batch_requests: read(&counters.batch_requests),
            write_attempt_failures: WriteAttemptFailureCounts {
                connect: read(&counters.write_attempt_failures.connect),
                tls: read(&counters.write_attempt_failures.tls),
                closed: read(&counters.write_attempt_failures.closed),
                timeout: read(&counters.write_attempt_failures.timeout),
                status_4xx: read(&counters.write_attempt_failures.status_4xx),
                status_5xx: read(&counters.write_attempt_failures.status_5xx),
            },
            write_retries: read(&counters.write_retries),
            write_ms_buckets: WriteMsBuckets {
                le_25: read(&buckets[0]),
                le_50: read(&buckets[1]),
                le_100: read(&buckets[2]),
                le_250: read(&buckets[3]),
                le_500: read(&buckets[4]),
                le_1000: read(&buckets[5]),
                le_2500: read(&buckets[6]),
                le_5000: read(&buckets[7]),
            },
            write_ms_sum: read(&counters.write_ms_sum),
            write_count: read(&counters.write_count),
        },
        load: Load {
            provider_inflight: node.egress.provider_inflight(),
            forward_calls: node.forward_calls(),
            inbound_connections: node.inbound.open(),
            inbound_refused: node.inbound.refused(),
            cpu_user_ms: cpu.map(|cpu| cpu.user),
            cpu_system_ms: cpu.map(|cpu| cpu.system),
            cpu_idle_ms: cpu.map(|cpu| cpu.idle),
            memory_total_bytes: memory.map(|memory| memory.total),
            memory_available_bytes: memory.map(|memory| memory.available),
            descriptors_open: descriptors::open_count(),
            descriptors_limit: descriptors::soft_limit(),
        },
        egress: EgressCounts {
            opens: read(&egress.opens),
            open_failures: OpenFailureCounts {
                transport: read(&egress.open_failures.transport),
                relay_refused: read(&egress.open_failures.relay_refused),
                tls: read(&egress.open_failures.tls),
                http: read(&egress.open_failures.http),
            },
            open_retries: read(&egress.open_retries),
            open_inflight: node.egress.open_inflight(),
            idle_reuses: IdleReuseCounts {
                provider: read(&egress.idle_reuses.provider),
                log_store: read(&egress.idle_reuses.log_store),
            },
        },
        refresh: RefreshCounts {
            late: LateRefreshCounts {
                kept: read(&refresh.late_kept),
                dropped: read(&refresh.late_dropped),
                failed: read(&refresh.late_failed),
                abandoned: read(&refresh.late_abandoned),
            },
            late_inflight: node.late_refreshes_inflight(),
        },
        state: StateCounts {
            kept_refreshes: count(&state.kept_refreshes),
            merge_keys: count(&state.merge_keys),
            pending_entries: count(&state.pending_entries),
            idle_connections: IdleConnectionCounts {
                provider: node.egress.provider_idle.idle_total(),
                log_store: node.log_store.idle_connections(),
            },
        },
    })
}
