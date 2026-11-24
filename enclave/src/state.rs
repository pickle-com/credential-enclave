//! The state of a node (enclave.md section 3). Everything lives in memory: a node writes
//! nothing to disk and shares no state with other nodes.

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use credential_enclave_protocol::encoding::{b64u, b64u_decode, to_json, Signed};
use credential_enclave_protocol::keys::{
    binding, role_binding, shard_hash, Custody, LogStoreId, NodeKeys, Role,
};
use credential_enclave_protocol::log::{self, EntryKind, Last};
use credential_enclave_protocol::record::{self, Kind, Record};
use credential_enclave_protocol::release::ReleaseMeasurement;
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::{limits, ProtocolError};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, Semaphore};

use crate::api::responses::RefreshedBody;
use crate::api::ApiError;
use crate::attest::ForwardNodes;
use crate::clock::Clock;
use crate::egress::Egress;
pub use crate::faults::lock;
use crate::faults::{Lock, NodeLock, NodeRwLock};
use crate::lineage::Lineage;
use crate::log_store::{LogStore, WriteFailure};
use crate::oauth::PkceVerifier;
use crate::platform::{PlatformError, SharedPlatform};
use crate::providers::Definitions;
use crate::role::{RoleCell, UsedNonces};

/// How long a node keeps the response of a successful `refresh` for a repeated call with the
/// same record: 3,600 seconds.
pub const REFRESH_KEPT_MS: u64 = 3_600 * 1000;
/// The responses of `refresh` a node keeps per account: the most recent 16.
pub const REFRESH_KEPT_ENTRIES: usize = 16;
/// The sum a node keeps `refresh` responses up to, over every account (enclave.md 5.7): the
/// default of `Limits::kept_refresh_bytes`, 512 MiB of the bytes it counts for them
/// ([`kept_refresh_bytes`]). Above it the node drops the responses it kept first.
pub const REFRESH_KEPT_BYTES: usize = 512 * 1024 * 1024;
/// The bytes a node counts for a kept `refresh` response beside its body and the `user_id`
/// of its account: its place among the kept responses of its account and in the order of the
/// node.
pub const REFRESH_KEPT_ENTRY_BYTES: usize = 384;

/// The bytes a node counts for one kept `refresh` response: the bytes of its body and of the
/// `user_id` of its account, a quarter more (an allocation is up to a quarter larger than
/// what it holds, as `crate::room` states), and [`REFRESH_KEPT_ENTRY_BYTES`].
pub fn kept_refresh_bytes(user_id: &str, body: &RefreshedBody) -> usize {
    let held = body.bytes().saturating_add(user_id.len());
    held.saturating_add(held / 4)
        .saturating_add(REFRESH_KEPT_ENTRY_BYTES)
}
/// Time limit of a token address call (enclave.md 6.3): the default of
/// `Limits::token_timeout`.
pub const TOKEN_TIMEOUT: Duration = Duration::from_secs(15);
/// Longest time a node keeps receiving the response of a token address call of `refresh`
/// after the time limit of the call passed, counted from the start of the call (enclave.md
/// 5.7): the default of `Limits::token_late_limit`.
pub const TOKEN_LATE_LIMIT: Duration = Duration::from_secs(120);
/// Token address calls of `refresh` that a node continues after their time limit at the same
/// time (enclave.md 5.7): the default of `Limits::refresh_late_tasks`.
pub const REFRESH_LATE_TASKS: usize = 128;
/// The budget of the requests of the two calls of a command, `attestation` and `messages`
/// (enclave.md section 8): the default of `Limits::command_budget_bytes`, 32 MiB. A grant
/// and a revoke are those two calls. Their requests are held under this budget and not under
/// the body budget of the node, so a command does not wait behind the bodies of the calls
/// that use a credential.
pub const COMMAND_BUDGET_BYTES: usize = 32 * 1024 * 1024;

/// The capacities of a node (enclave.md sections 3 and 8).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Body limit of a provider request and of a provider response.
    pub body_bytes: usize,
    /// Sum of the bodies that may be in memory at the same time. A call that would exceed it
    /// waits.
    pub body_budget_bytes: usize,
    /// Sum of the shares the calls of a command (`attestation`, `messages`) hold for their
    /// requests at the same time. A call that would exceed it waits.
    pub command_budget_bytes: usize,
    /// `forward` and `forward/batch` calls that run at the same time. The bodies in memory are
    /// bounded by `body_budget_bytes` and the provider requests in flight by
    /// `limits::PROVIDER_INFLIGHT`, so a call that waits for a slot holds nothing but its frame
    /// reservation.
    pub forward_concurrency: usize,
    /// Challenges a node keeps.
    pub challenges: usize,
    /// Pending authorizations a node keeps.
    pub pending: usize,
    /// Longest attempt to write one entry to the log store: the connection, the TLS handshake
    /// and the exchange. An attempt over an idle connection gets half of it, and the attempts
    /// of one entry share a budget of twice it (enclave.md 5.14).
    pub log_write: Duration,
    /// Time limit of a token address call: the whole of `oauth/complete`'s call, and the time
    /// `refresh` waits for its call before the call fails (enclave.md 5.7).
    pub token_timeout: Duration,
    /// Longest time a node keeps receiving the response of a token address call of `refresh`
    /// whose time limit passed, counted from the start of the call.
    pub token_late_limit: Duration,
    /// Token address calls of `refresh` the node continues after their time limit at the same
    /// time. A call that finds no place ends with its time limit.
    pub refresh_late_tasks: usize,
    /// Outbound connections the node opens at the same time: the connections to providers and
    /// to the log store that are being opened (enclave.md section 8). A further open waits.
    pub open_concurrency: usize,
    /// Entries the sweep of the node writes per second, over every account (enclave.md
    /// section 3).
    pub sweep_write_rate: u32,
    /// Connections from the backend the node holds open at the same time (enclave.md section
    /// 8). A connection accepted above this bound is closed without a byte and counted as
    /// refused: every open connection holds a descriptor, and the bound keeps the connections
    /// of the callers from taking the descriptors of the writes to the log store and of the
    /// provider requests.
    pub inbound_connections: usize,
    /// Longest time an accepted connection waits for the head of its next request: the time
    /// before the first request, and the idle time between two requests of a connection the
    /// caller keeps open (enclave.md section 8). A connection that passes it is closed.
    pub inbound_idle: Duration,
    /// Events of GET requests without a body the node remembers for one account at one time
    /// (protocol.md 7.2). A request beyond it has an event of its own that no later request
    /// shares, so the table of one account has a bounded size whatever the account sends.
    pub merge_keys: usize,
    /// Sum of the bytes the node counts for its kept `refresh` responses, over every account
    /// (enclave.md 5.7). Above it the node drops the responses it kept first.
    pub kept_refresh_bytes: usize,
}

/// The connections from the backend the node holds open at the same time.
pub const INBOUND_CONNECTIONS: usize = 16_384;
/// The idle time after which the node closes a connection from the backend.
pub const INBOUND_IDLE: Duration = Duration::from_secs(60);

impl Default for Limits {
    fn default() -> Self {
        Limits {
            body_bytes: limits::BODY_BYTES,
            body_budget_bytes: 2 * 1024 * 1024 * 1024,
            command_budget_bytes: COMMAND_BUDGET_BYTES,
            forward_concurrency: 512,
            challenges: 100_000,
            pending: 100_000,
            log_write: Duration::from_secs(5),
            token_timeout: TOKEN_TIMEOUT,
            token_late_limit: TOKEN_LATE_LIMIT,
            refresh_late_tasks: REFRESH_LATE_TASKS,
            open_concurrency: crate::egress::OPEN_CONCURRENCY,
            sweep_write_rate: crate::log_store::SWEEP_WRITE_RATE,
            inbound_connections: INBOUND_CONNECTIONS,
            inbound_idle: INBOUND_IDLE,
            merge_keys: limits::MERGE_KEYS,
            kept_refresh_bytes: REFRESH_KEPT_BYTES,
        }
    }
}

/// The counts of the connections from the backend (`inbound_connections` and
/// `inbound_refused` of `load` of `GET /v1/health`): the connections open at this moment, and
/// the connections closed at accept because the bound `inbound_connections` of [`Limits`] was
/// reached, since the node started. The accept loop of the call surface moves them
/// (`crate::api::serve`).
#[derive(Debug, Default)]
pub struct InboundCounters {
    /// Connections open at this moment.
    pub connections: AtomicUsize,
    /// Connections closed at accept because the bound was reached, since the node started.
    pub refused: AtomicU64,
}

impl InboundCounters {
    /// Admits one accepted connection under `bound`: `Some` with the guard that holds its
    /// place until the connection ends, `None` when the bound is reached (the connection is
    /// counted as refused).
    pub fn admit(self: &Arc<Self>, bound: usize) -> Option<InboundConnection> {
        let open = self.connections.fetch_add(1, Ordering::SeqCst) + 1;
        if open > bound {
            self.connections.fetch_sub(1, Ordering::SeqCst);
            self.refused.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(InboundConnection(self.clone()))
    }

    /// The connections open at this moment.
    pub fn open(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// The connections refused since the node started.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }
}

/// The place of one accepted connection: dropped when the connection ends.
pub struct InboundConnection(Arc<InboundCounters>);

impl Drop for InboundConnection {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The client values of one provider, from the operator configuration.
///
/// The client secret is a value the operator domain gave, so it is no secret from it. It is
/// held as a secret all the same: it reaches the token address and the revocation address of
/// its provider and appears in no response.
pub struct ProviderCredentials {
    pub client_id: String,
    pub client_secret: Secret<String>,
    pub redirect_uri: String,
    pub publishable_key: String,
}

/// The operator configuration (enclave.md 5.1). It can change client identifiers and callback
/// addresses only.
pub struct OperatorConfig {
    pub providers: HashMap<String, ProviderCredentials>,
}

/// A delegation in force: the account handed the user key of `custody` to this node until
/// `not_after_ms`.
pub struct ActiveGrant {
    pub key_id: String,
    pub sign_pk: [u8; 32],
    pub log_pk: [u8; 32],
    pub custody: Custody,
    pub user_key: Secret<[u8; 32]>,
    pub not_after_ms: u64,
    /// The nodes of another release this grant was handed to (`peer/export` to a node whose
    /// measurement release proofs show), at most 64. The node created the entry
    /// `grant_transferred_out` that names
    /// a node of this list, so a repeated transfer to it creates none. A grant command that
    /// puts a grant in place where none of that key was in force, a revoke, the end of the
    /// grant and a transfer this node takes put a new state in place, and a new grant state
    /// starts with an empty list (protocol.md 10.1). A transfer to a node of the measurement
    /// of this node creates no entry and is not on the list.
    pub exported_to: Vec<Handover>,
}

/// One node of another release a grant was handed to, and the entry that says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handover {
    /// The signing public key of the receiving node.
    pub peer: [u8; 32],
    /// The `seq` of the entry `grant_transferred_out` that names it. The grant enters a
    /// transfer to that node only when the log store confirmed this entry.
    pub seq: u64,
}

impl ActiveGrant {
    /// The entry that says that this grant was handed to the node `peer` of another release,
    /// when it was.
    pub fn handed_to(&self, peer: &[u8; 32]) -> Option<u64> {
        self.exported_to
            .iter()
            .find(|handover| &handover.peer == peer)
            .map(|handover| handover.seq)
    }
}

/// The delegation state of an account.
pub enum GrantState {
    None,
    /// A grant within its time. [`Account::expire`] turns it into `Expired` at the first read
    /// after `not_after_ms`, so an `Active` state never holds a user key that was overwritten.
    Active(ActiveGrant),
    /// The time of the grant passed. Its user key is gone: only what `status` reports remains.
    /// In every call an expired grant counts as no grant (protocol.md 5.4).
    Expired {
        key_id: String,
        not_after_ms: u64,
    },
    /// The account withdrew its delegation. The marker names the key that did it.
    Revoked {
        key_id: String,
        /// Part of the revocation marker of protocol.md 5.4. The calls read the `key_id` only.
        #[allow(dead_code)]
        sign_pk: [u8; 32],
    },
}

/// What a call needs from a delegation in force. The user key copy is overwritten with zeros
/// when the value is dropped.
pub struct GrantView {
    pub key_id: String,
    pub sign_pk: [u8; 32],
    pub log_pk: [u8; 32],
    pub custody: Custody,
    pub user_key: Secret<[u8; 32]>,
    /// The revoke serial of the account when the view was taken: a revoke accepted after it
    /// draws a larger one, so a grant of the same key made after that revoke is told apart from
    /// the grant the view was taken under.
    pub revoke_serial: u64,
}

/// The plaintext copy of the delegation state that a caller reads (enclave.md 5.3 and 5.4).
/// `key_id`, `custody` and `not_after_ms` have values in the state `active`. `expired` carries
/// `key_id` and `not_after_ms`, `revoked` carries `key_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GrantStatus {
    pub state: &'static str,
    pub key_id: String,
    pub custody: &'static str,
    pub not_after_ms: u64,
}

/// A log entry that the log store has not confirmed (protocol.md 7.6).
pub struct Unconfirmed {
    pub seq: u64,
    /// The key of the object of the entry in the log store (protocol.md 7.6).
    pub key: String,
    /// The hash that names the bucket of the object among the buckets of the log store: the
    /// hash of the `user_id` of the account (protocol.md 7.6).
    pub shard: u16,
    pub entry: Signed,
    /// The calls that write the entry at this moment: the call that created it, and every
    /// call that took it along. An entry no call writes (the count is 0) is a pending entry:
    /// the next write of the account takes it along. The count is kept per call, so the end
    /// of one call does not say that an entry which another call still writes is pending.
    pub writers: u32,
    /// The node time at which the entry was created: the time since which the store has not
    /// confirmed it. The sweep writes the pending entries of an account only after a part of
    /// its interval passed since this time, and `pending_oldest_ms` of health is the age of the
    /// oldest pending entry (enclave.md 5.1).
    pub pending_since_ms: u64,
}

/// The `seq` of the entry an open batch became, set when the batch is closed. Every call
/// whose event joined the batch holds the same cell, so it finds its entry without any
/// bookkeeping of the account.
pub type BatchSeq = Arc<OnceLock<u64>>;

/// Where the event of a call is (protocol.md 7.1): in an open batch of the account, named by
/// the cell of that batch and the index of the event in it, or in an entry, named by the
/// `seq` of the entry and the index of the event in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventPlace {
    Open { batch: BatchSeq, index: u32 },
    Entry { seq: u64, index: u32 },
}

impl EventPlace {
    /// The `seq` of the entry that holds the event, when that entry exists: an event of an
    /// open batch has none until the batch is closed. The place of a control event always has
    /// one.
    pub fn seq(&self) -> Option<u64> {
        match self {
            EventPlace::Entry { seq, .. } => Some(*seq),
            EventPlace::Open { batch, .. } => batch.get().copied(),
        }
    }

    /// The index of the event in its entry.
    pub fn index(&self) -> u32 {
        match self {
            EventPlace::Open { index, .. } | EventPlace::Entry { index, .. } => *index,
        }
    }
}

/// The event of an identical GET request that later ones share (protocol.md 7.2).
#[derive(Clone)]
pub struct Recent {
    /// The time of the event.
    pub entry_ms: u64,
    /// Where the event is. A request shares it only once the log store confirmed the entry
    /// that holds it.
    pub target: EventPlace,
}

/// The use events of an account whose entry does not exist yet (protocol.md 7.1). The call
/// that finds no writer closes it into an entry; the writer closes it when its write ends.
pub struct OpenBatch {
    /// The events in the order of their creation.
    pub events: Vec<Value>,
    /// The length of the JSON array of the events so far: the bound of the plaintext.
    pub bytes: usize,
    /// The cell that receives the `seq` of the entry when this batch is closed. A new cell
    /// starts with the next batch.
    pub seq: BatchSeq,
    /// The key the events were created under: the entry is sealed to its log public key.
    pub key_id: String,
    pub log_pk: [u8; 32],
}

impl OpenBatch {
    fn new() -> OpenBatch {
        OpenBatch {
            events: Vec::new(),
            bytes: 2,
            seq: Arc::new(OnceLock::new()),
            key_id: String::new(),
            log_pk: [0u8; 32],
        }
    }

    /// True when `event_bytes` more bytes, or one more event, would take the batch over the
    /// caps of protocol.md 7.1.
    fn full_for(&self, event_bytes: usize) -> bool {
        !self.events.is_empty()
            && (self.events.len() >= limits::ENTRY_EVENTS
                || self.bytes + event_bytes + 1 > limits::ENTRY_PLAINTEXT_BYTES)
    }
}

/// The upper bounds, in milliseconds, of the cumulative buckets of the time to confirmation of
/// a write to the log store (`write_ms_buckets` of health, enclave.md 5.1).
pub const WRITE_MS_BOUNDS: [u64; 8] = [25, 50, 100, 250, 500, 1000, 2500, 5000];

/// The counts of `log` of `GET /v1/health` (enclave.md 5.1), since the node started.
#[derive(Default)]
pub struct LogCounters {
    pub entries: AtomicU64,
    pub events: AtomicU64,
    /// Attempts to write an entry to the log store, confirmed or not.
    pub writes: AtomicU64,
    /// Entries the store did not confirm within the budget of their attempts.
    pub write_failures: AtomicU64,
    pub batch_calls: AtomicU64,
    pub batch_requests: AtomicU64,
    /// Attempts the store did not confirm, by cause.
    pub write_attempt_failures: WriteAttemptFailures,
    /// Attempts that followed an attempt the store did not confirm.
    pub write_retries: AtomicU64,
    /// Confirmed attempts whose time to confirmation was at most the bound of
    /// [`WRITE_MS_BOUNDS`] at the same index: cumulative buckets.
    pub write_ms_buckets: [AtomicU64; WRITE_MS_BOUNDS.len()],
    /// The sum of the times to confirmation of the confirmed attempts, in milliseconds.
    pub write_ms_sum: AtomicU64,
    /// Confirmed attempts.
    pub write_count: AtomicU64,
}

impl LogCounters {
    /// Records a confirmed attempt that took `elapsed_ms` from its start to the status 200.
    pub fn record_confirmed(&self, elapsed_ms: u64) {
        for (bucket, bound) in self.write_ms_buckets.iter().zip(WRITE_MS_BOUNDS) {
            if elapsed_ms <= bound {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.write_ms_sum.fetch_add(elapsed_ms, Ordering::Relaxed);
        self.write_count.fetch_add(1, Ordering::Relaxed);
    }
}

/// The attempts to write an entry that the log store did not confirm, by cause
/// (`write_attempt_failures` of health). The causes are those of
/// [`crate::log_store::WriteFailure`].
#[derive(Default)]
pub struct WriteAttemptFailures {
    pub connect: AtomicU64,
    pub tls: AtomicU64,
    pub closed: AtomicU64,
    pub timeout: AtomicU64,
    pub status_4xx: AtomicU64,
    pub status_5xx: AtomicU64,
}

impl WriteAttemptFailures {
    pub fn count(&self, cause: WriteFailure) {
        let counter = match cause {
            WriteFailure::Connect => &self.connect,
            WriteFailure::Tls => &self.tls,
            WriteFailure::Closed => &self.closed,
            WriteFailure::Timeout => &self.timeout,
            WriteFailure::Status4xx => &self.status_4xx,
            WriteFailure::Status5xx => &self.status_5xx,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// The counts of `refresh` of `GET /v1/health` (enclave.md 5.1): the outcomes of the token
/// address calls of `refresh` that the node continued after their time limit (5.7).
#[derive(Default)]
pub struct RefreshCounters {
    /// Late calls whose success became the kept response of the record.
    pub late_kept: AtomicU64,
    /// Late calls whose success was not kept: the grant had ended, a revoke or a grant of
    /// another key arrived, or the node was closing.
    pub late_dropped: AtomicU64,
    /// Late calls that ended with a refusal of the provider, a transport failure or the late
    /// limit.
    pub late_failed: AtomicU64,
    /// Calls that found no place among the late calls at their time limit and ended there.
    pub late_abandoned: AtomicU64,
}

/// The counts of the state of the accounts that `GET /v1/health` reports (enclave.md 5.1):
/// `grants`, `pending` of `log_store`, `open_batches` of `log` and the `state` object. Every
/// count is changed by the method of [`Account`] that changes the state it counts, so a health
/// call reads the counts and walks no account.
#[derive(Default)]
pub struct StateCounters {
    /// Accounts that have a grant within its time.
    pub grants: AtomicUsize,
    /// Accounts that have an entry the log store has not confirmed.
    pub pending_accounts: AtomicUsize,
    /// Entries the log store has not confirmed, over every account.
    pub pending_entries: AtomicUsize,
    /// Kept `refresh` responses, over every account.
    pub kept_refreshes: AtomicUsize,
    /// The kept `refresh` responses of every account in the order the node kept them, with
    /// the bytes it counts for each and their sum.
    pub kept_order: NodeLock<KeptOrder>,
    /// Kept `refresh` responses the node dropped before their time because the sum of its
    /// kept responses was above its bound ([`Node::bound_kept_refreshes`]), since it started.
    pub kept_refreshes_dropped: AtomicU64,
    /// Merge keys, over every account.
    pub merge_keys: AtomicUsize,
    /// Accounts whose open batch holds events.
    pub open_batches: AtomicUsize,
    /// The `pending_since_ms` of the oldest pending entry the last sweep of the node found, 0
    /// when it found none ([`crate::log_store::sweep`]). The age it gives is at most one sweep
    /// interval behind the state of the accounts.
    pub pending_oldest_since_ms: AtomicU64,
    /// Accounts the node halted ([`Account::halt`]), since it started.
    pub halted: AtomicUsize,
}

/// Moves a count from `before` to `after`.
fn adjust(counter: &AtomicUsize, before: usize, after: usize) {
    if after > before {
        counter.fetch_add(after - before, Ordering::Relaxed);
    } else if before > after {
        counter.fetch_sub(before - after, Ordering::Relaxed);
    }
}

/// Takes `count` off a count, down to zero at the lowest: the count of a state that a panic
/// may have left half changed ([`Account::halt`]).
fn lower(counter: &AtomicUsize, count: usize) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_sub(count))
    });
}

/// The kept `refresh` responses of a node over every account, in the order the node kept
/// them: for each its account and the bytes the node counts for it ([`kept_refresh_bytes`]),
/// and the sum of those bytes (`kept_refresh_bytes` of `state` of health).
///
/// An account changes the order under its own lock with every response it keeps and every
/// response it drops, so the sum is that of the responses the accounts hold. The lock of the
/// order is taken inside the lock of an account and never around one.
#[derive(Default)]
pub struct KeptOrder {
    /// The serial of the response kept last. A serial is given once.
    last: u64,
    /// The sum of the bytes of the responses of `kept`.
    bytes: usize,
    /// Serial to the account of the response and the bytes counted for it. The smallest
    /// serial is the response kept first.
    kept: BTreeMap<u64, (String, usize)>,
}

impl KeptOrder {
    /// Takes in a response of the account `user_id` that counts `bytes`, and returns its
    /// serial.
    fn add(&mut self, user_id: &str, bytes: usize) -> u64 {
        self.last = self.last.saturating_add(1);
        self.kept.insert(self.last, (user_id.to_string(), bytes));
        self.bytes = self.bytes.saturating_add(bytes);
        self.last
    }

    /// Takes the response with this serial out. Nothing changes when the order holds none.
    fn remove(&mut self, serial: u64) {
        if let Some((_, bytes)) = self.kept.remove(&serial) {
            self.bytes = self.bytes.saturating_sub(bytes);
        }
    }

    /// The sum of the bytes of the kept responses.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// The serial and the account of the response kept first, while the sum is above `bound`.
    fn first_above(&self, bound: usize) -> Option<(u64, String)> {
        if self.bytes <= bound {
            return None;
        }
        self.kept
            .first_key_value()
            .map(|(serial, (user_id, _))| (*serial, user_id.clone()))
    }
}

/// The response of a successful `refresh`, kept for a repeated call with the same record: the
/// body of the response as the node sent it, which holds a record (ciphertext), public fields
/// and a log entry.
struct KeptRefresh {
    /// The hash of the `ct` of the record the call sent.
    key: [u8; 32],
    kept_ms: u64,
    /// The serial of the response in the order of the node ([`KeptOrder`]).
    serial: u64,
    body: RefreshedBody,
}

/// The key under which the response of a `refresh` is kept: `SHA-256(the ct of the record that
/// was sent)`.
pub fn refresh_key(record: &Record) -> [u8; 32] {
    Sha256::digest(record.ct.as_bytes()).into()
}

/// The state of one account on this node.
///
/// The delegation state, the unconfirmed entries, the merge keys, the kept `refresh` responses
/// and the open batch are changed through the methods of this type, which keep the counts of
/// [`StateCounters`] of the node in step with them.
///
/// The state is reached through its lock ([`AccountLock`]). A panic while that lock was held
/// halts the account on this node ([`Account::halt`]).
pub struct Account {
    /// The delegation state. Changed through [`Account::set_grant`] and [`Account::expire`].
    grant: GrantState,
    /// The last entry this node created for the account: its `seq` and the hash of its body,
    /// which the next entry carries as `prev`.
    pub last: Last,
    /// The use events whose entry does not exist yet. Its events are added and taken by
    /// [`Node::create_event_seeded`] and [`Node::close_batch`].
    pub open: OpenBatch,
    /// True while a call of this account writes to the log store: the writer of the group
    /// commit (protocol.md 7.1).
    pub writer: bool,
    /// Woken when a write of this account ended: the waiting calls look at their entries
    /// again.
    pub notify: Arc<Notify>,
    /// Entries the log store has not confirmed, in the order of their `seq`. Empty on a node
    /// that runs without a log store. An entry leaves this list in one way: the store answered
    /// a write of it with the status 200 ([`Account::store_confirmed`]). The list holds memory
    /// for the entries it has.
    unconfirmed: Vec<Unconfirmed>,
    /// Merge key to its event: identical GET requests of `forward` that have no body. Kept
    /// for 300 seconds, at most `Limits::merge_keys` at one time. The table holds memory for
    /// the keys it has: it gives back the memory of the keys it drops
    /// ([`Account::prune_recent`], [`Account::clear_recent`]).
    recent: HashMap<[u8; 32], Recent>,
    /// The responses of the successful `refresh` calls of the last 3,600 seconds, at most 16,
    /// in the order they were kept. A revoke, an expiry and a grant of another key drop them,
    /// and the bound of the node drops those the node kept first
    /// ([`Node::bound_kept_refreshes`]). The list holds room for the responses it has and no
    /// more, and none once the last of them left.
    kept_refreshes: Vec<KeptRefresh>,
    /// The counts of the node this account is part of.
    counters: Arc<StateCounters>,
    /// The `time_ms` of the last entry of the chain. An entry is never dated before the entry
    /// in front of it.
    last_entry_ms: u64,
    /// The `time_ms` of the last event created. The times of the events of a chain do not
    /// decrease with (seq, index).
    last_event_ms: u64,
    /// True once this node accepted a revoke command of the account. From then on the
    /// delegation of the account comes from its app alone: no delegation transfer is taken
    /// for it. A revocation marker can be replaced by the grant of any key (protocol.md 5.3
    /// step 14), so without this memory a grant of a foreign key that ends at once, followed
    /// by a transfer made before the revoke, would bring the revoked delegation back.
    pub revoked_here: bool,
    /// The serial this node drew when it last accepted a revoke command of the account
    /// ([`Node::next_serial`]), 0 when it never did. It only grows. A grant whose challenge
    /// has a smaller serial was issued before that revoke and is refused (protocol.md 5.3
    /// step 12): a carrier that kept a sealed grant cannot deliver it after the revoke.
    pub revoke_serial: u64,
    /// True once the node halted the account ([`Account::halt`]). It stays true for as long as
    /// the node lives.
    halted: bool,
}

impl Account {
    fn new(counters: Arc<StateCounters>) -> Account {
        Account {
            grant: GrantState::None,
            last: Last::NONE,
            open: OpenBatch::new(),
            writer: false,
            notify: Arc::new(Notify::new()),
            unconfirmed: Vec::new(),
            recent: HashMap::new(),
            kept_refreshes: Vec::new(),
            counters,
            last_entry_ms: 0,
            last_event_ms: 0,
            revoked_here: false,
            revoke_serial: 0,
            halted: false,
        }
    }

    /// Halts the account on this node (enclave.md 3.1). A panic began while the lock of
    /// this state was held, so the state may be half changed: the step that panicked may have
    /// left an entry counted as written that the store never confirmed, or a grant in place
    /// that a command was taking away. The node does not judge which. It gives the state up:
    ///
    /// - the grant goes, and its user key is overwritten with zeros;
    /// - the unconfirmed entries, the events of the open batch, the merge keys and the kept
    ///   `refresh` responses go. An entry the store did not confirm is gone as it is gone with
    ///   a node that ends: its act did not take place (protocol.md 7.6). The cell of the open
    ///   batch receives 0, the `seq` of no entry, so the calls whose events were in it find no
    ///   entry;
    /// - from here on the account takes no grant ([`Account::set_grant`]), the node creates no
    ///   entry for it ([`Node::create_event`]), none of its entries counts as confirmed
    ///   ([`Account::is_confirmed`]), and a call that needs its state ends with `internal`
    ///   ([`Account::ensure_usable`]). So no act follows on this state.
    ///
    /// The other nodes that hold the delegation of the account serve it. This node holds it
    /// again only as another node: after its enclave was replaced.
    ///
    /// What the account knows of its chain (the last entry, the times) stays as it is: the
    /// node reads none of it again. The calls that wait for a write of the account are woken
    /// and find the account halted. The counts of the node follow, each down to zero at the
    /// lowest.
    fn halt(&mut self) {
        if self.halted {
            return;
        }
        self.halted = true;
        let granted = usize::from(matches!(self.grant, GrantState::Active(_)));
        self.grant = GrantState::None;
        lower(&self.counters.grants, granted);
        let entries = std::mem::take(&mut self.unconfirmed).len();
        lower(&self.counters.pending_entries, entries);
        lower(&self.counters.pending_accounts, usize::from(entries > 0));
        let open = std::mem::replace(&mut self.open, OpenBatch::new());
        lower(
            &self.counters.open_batches,
            usize::from(!open.events.is_empty()),
        );
        let _ = open.seq.set(0);
        lower(
            &self.counters.merge_keys,
            std::mem::take(&mut self.recent).len(),
        );
        let kept = std::mem::take(&mut self.kept_refreshes);
        {
            let mut order = lock(&self.counters.kept_order);
            for kept in &kept {
                order.remove(kept.serial);
            }
        }
        lower(&self.counters.kept_refreshes, kept.len());
        self.writer = false;
        self.counters.halted.fetch_add(1, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    /// True once the node halted the account ([`Account::halt`]).
    pub fn is_halted(&self) -> bool {
        self.halted
    }

    /// `internal` for a halted account: the node performs no act for the account, and the
    /// call that reads this has changed nothing. A call that needs the grant of the account
    /// passes this check in [`Account::active`]; a call that reads or changes the state
    /// without the grant (a grant command, `status`) makes the check itself. The one call the
    /// node answers for a halted account is a revoke command, which asks for what halting
    /// did: the node holds no user key of the account (`crate::api::messages`).
    pub fn ensure_usable(&self) -> Result<(), ProtocolError> {
        match self.halted {
            true => Err(ProtocolError::Internal),
            false => Ok(()),
        }
    }

    /// The delegation state.
    pub fn grant(&self) -> &GrantState {
        &self.grant
    }

    /// The delegation state, to change a value of a grant in force (its end, the nodes it was
    /// handed to). A change of the state itself goes through [`Account::set_grant`].
    pub fn grant_mut(&mut self) -> &mut GrantState {
        &mut self.grant
    }

    /// Puts a delegation state in place. Dropping an `Active` state overwrites its user key
    /// with zeros. The count of the accounts with a grant within its time follows. A halted
    /// account takes no state: the value is dropped, and a grant in it loses its user key.
    pub fn set_grant(&mut self, grant: GrantState) {
        if self.halted {
            return;
        }
        let before = usize::from(matches!(self.grant, GrantState::Active(_)));
        let after = usize::from(matches!(grant, GrantState::Active(_)));
        self.grant = grant;
        adjust(&self.counters.grants, before, after);
    }

    /// Ends a grant whose time passed: the state becomes `Expired` and the user key is
    /// overwritten with zeros. Every place that reads the delegation state calls this first
    /// (enclave.md section 3), and node time does not decrease, so a grant that expired stays
    /// expired.
    pub fn expire(&mut self, now_ms: u64) {
        let expired = match &self.grant {
            GrantState::Active(grant) if now_ms >= grant.not_after_ms => GrantState::Expired {
                key_id: grant.key_id.clone(),
                not_after_ms: grant.not_after_ms,
            },
            _ => return,
        };
        // Replacing the state drops the grant, which overwrites its user key with zeros. The
        // merge window of the grant ends with it: no request merges into an event made under
        // a grant that is over.
        self.set_grant(expired);
        self.forget_refreshes();
        self.clear_recent();
    }

    /// Drops the grant of the account, within its time or expired, as the end of its time
    /// does: the state becomes `None`, the user key is overwritten with zeros, and the kept
    /// `refresh` responses and the merge keys go with it (`grants/prune`, enclave.md 5.15). A
    /// revocation marker stays. True when a grant was dropped.
    pub fn drop_grant(&mut self) -> bool {
        if !matches!(
            self.grant,
            GrantState::Active(_) | GrantState::Expired { .. }
        ) {
            return false;
        }
        self.set_grant(GrantState::None);
        self.forget_refreshes();
        self.clear_recent();
        true
    }

    /// The kept response of a `refresh` of the record with this key, when it was kept less
    /// than 3,600 seconds ago.
    pub fn kept_refresh(&mut self, key: &[u8; 32], now_ms: u64) -> Option<&RefreshedBody> {
        self.prune_refreshes(now_ms);
        self.kept_refreshes
            .iter()
            .find(|kept| &kept.key == key)
            .map(|kept| &kept.body)
    }

    /// Drops the kept `refresh` responses whose 3,600 seconds passed. A `refresh` of the
    /// account drops them on its way, and the sweep of the node drops them for an account
    /// that makes no call.
    pub fn prune_refreshes(&mut self, now_ms: u64) {
        self.unkeep(|kept| now_ms >= kept.kept_ms.saturating_add(REFRESH_KEPT_MS));
    }

    /// Drops the kept `refresh` responses that `dropped` names and returns their number. The
    /// order of the node and its count follow, and the list gives back the room of the
    /// responses that left: an account lives as long as the node, and without a kept response
    /// it holds no memory for one.
    fn unkeep(&mut self, dropped: impl Fn(&KeptRefresh) -> bool) -> usize {
        if !self.kept_refreshes.iter().any(&dropped) {
            return 0;
        }
        let before = self.kept_refreshes.len();
        {
            let mut order = lock(&self.counters.kept_order);
            self.kept_refreshes.retain(|kept| {
                let leaves = dropped(kept);
                if leaves {
                    order.remove(kept.serial);
                }
                !leaves
            });
        }
        self.kept_refreshes.shrink_to_fit();
        let after = self.kept_refreshes.len();
        adjust(&self.counters.kept_refreshes, before, after);
        before.saturating_sub(after)
    }

    /// Keeps the body of the response of a successful `refresh` that ran under `grant` for
    /// the account `user_id`, and returns true. Nothing is kept, and false is returned, when
    /// that grant is no longer in force: a revoke that was answered while the provider call
    /// ran leaves no kept response behind it, also when a grant of the same key followed that
    /// revoke (the revoke serial of the view is then behind the one of the account).
    ///
    /// The response takes its place in the order of the node. The caller holds the node
    /// within its bound afterwards, outside the lock of this account
    /// ([`Node::bound_kept_refreshes`]).
    pub fn keep_refresh(
        &mut self,
        grant: &GrantView,
        user_id: &str,
        key: [u8; 32],
        now_ms: u64,
        body: RefreshedBody,
    ) -> bool {
        self.expire(now_ms);
        let in_force = self.revoke_serial == grant.revoke_serial
            && matches!(
                &self.grant,
                GrantState::Active(active) if active.sign_pk == grant.sign_pk
            );
        if !in_force {
            return false;
        }
        self.unkeep(|kept| kept.key == key);
        // The list is in the order of keeping: its first response is the one kept first.
        while self.kept_refreshes.len() >= REFRESH_KEPT_ENTRIES {
            let first = self.kept_refreshes.first().map(|kept| kept.serial);
            if self.unkeep(|kept| Some(kept.serial) == first) == 0 {
                break;
            }
        }
        let serial =
            lock(&self.counters.kept_order).add(user_id, kept_refresh_bytes(user_id, &body));
        self.kept_refreshes.reserve_exact(1);
        self.kept_refreshes.push(KeptRefresh {
            key,
            kept_ms: now_ms,
            serial,
            body,
        });
        self.counters.kept_refreshes.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Drops the kept `refresh` responses, and the memory of their list: the delegation they
    /// were made under ended.
    pub fn forget_refreshes(&mut self) {
        self.unkeep(|_| true);
    }

    /// Drops the kept `refresh` response with this serial, for the bound of the node
    /// ([`Node::bound_kept_refreshes`]). True when the account held it.
    fn drop_kept_refresh(&mut self, serial: u64) -> bool {
        self.unkeep(|kept| kept.serial == serial) > 0
    }

    /// The event an identical GET request of the last 300 seconds created, when there is one
    /// under this merge key (protocol.md 7.2).
    pub fn shared_event(&self, key: &[u8; 32]) -> Option<Recent> {
        self.recent.get(key).cloned()
    }

    /// True when the account remembers fewer than `bound` events of GET requests: the event of
    /// a further request is remembered, so that an identical request shares it. At the bound a
    /// request has an event of its own that no later request shares (protocol.md 7.2).
    pub fn remembers_more(&self, bound: usize) -> bool {
        self.recent.len() < bound
    }

    /// Remembers the event of a GET request under its merge key for the next 300 seconds. A
    /// halted account remembers none.
    pub fn remember_event(&mut self, key: [u8; 32], recent: Recent) {
        if self.halted {
            return;
        }
        let before = self.recent.len();
        self.recent.insert(key, recent);
        adjust(&self.counters.merge_keys, before, self.recent.len());
    }

    /// Drops every merge key, and the memory of the table with them: the grant the events
    /// were made under ended, or another one took its place.
    pub fn clear_recent(&mut self) {
        let before = self.recent.len();
        self.recent = HashMap::new();
        adjust(&self.counters.merge_keys, before, 0);
    }

    /// The entries the log store has not confirmed, in the order of their `seq`.
    #[cfg(test)]
    pub fn unconfirmed(&self) -> &[Unconfirmed] {
        &self.unconfirmed
    }

    /// The same entries, for a call that marks the ones it writes.
    pub fn unconfirmed_mut(&mut self) -> impl Iterator<Item = &mut Unconfirmed> {
        self.unconfirmed.iter_mut()
    }

    /// Adds the entry the node just created to the entries the store has not confirmed.
    fn push_unconfirmed(&mut self, entry: Unconfirmed) {
        if self.unconfirmed.is_empty() {
            self.counters
                .pending_accounts
                .fetch_add(1, Ordering::Relaxed);
        }
        self.unconfirmed.push(entry);
        self.counters
            .pending_entries
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records that the log store answered a write of the entry `seq` with the status 200: the
    /// entry leaves the entries the store has not confirmed. This is the one place an entry
    /// leaves that list, and its one caller is the end of the write that received that status
    /// (`crate::log_store`). So "the store confirmed the entry" is said by an answer of the
    /// store and by nothing else.
    pub fn store_confirmed(&mut self, seq: u64) {
        let before = self.unconfirmed.len();
        self.unconfirmed.retain(|entry| entry.seq != seq);
        if self.unconfirmed.is_empty() && before > 0 {
            // The list of an account lives as long as the node: without an entry it holds no
            // memory.
            self.unconfirmed = Vec::new();
        }
        self.unconfirmed_changed(before);
    }

    /// Moves the two counts of the unconfirmed entries after their number went from `before`
    /// to the number now.
    fn unconfirmed_changed(&mut self, before: usize) {
        let after = self.unconfirmed.len();
        adjust(&self.counters.pending_entries, before, after);
        adjust(
            &self.counters.pending_accounts,
            usize::from(before > 0),
            usize::from(after > 0),
        );
    }

    /// Step 4 of the common front: the grant is active and within its time. A halted account
    /// is `internal` ([`Account::ensure_usable`]).
    pub fn active(&mut self, now_ms: u64) -> Result<GrantView, ProtocolError> {
        self.ensure_usable()?;
        self.expire(now_ms);
        match &self.grant {
            GrantState::None => Err(ProtocolError::GrantRequired),
            GrantState::Revoked { .. } => Err(ProtocolError::GrantRevoked),
            GrantState::Expired { .. } => Err(ProtocolError::GrantExpired),
            GrantState::Active(grant) => Ok(GrantView {
                key_id: grant.key_id.clone(),
                sign_pk: grant.sign_pk,
                log_pk: grant.log_pk,
                custody: grant.custody,
                user_key: grant.user_key.clone(),
                revoke_serial: self.revoke_serial,
            }),
        }
    }

    /// True when the log store confirmed the entry `seq`: the node created an entry of that
    /// `seq` for the account, and the entry left the unconfirmed entries, which it does by an
    /// answer of the store alone ([`Account::store_confirmed`]). A `seq` the node never
    /// created is not confirmed. On a node that runs without a log store every entry it
    /// created counts as confirmed: such a node keeps no account of it. No entry of a halted
    /// account counts as confirmed: the node gave up what it knew of them ([`Account::halt`]).
    pub fn is_confirmed(&self, seq: u64) -> bool {
        !self.halted
            && (1..=self.last.seq).contains(&seq)
            && !self.unconfirmed.iter().any(|entry| entry.seq == seq)
    }

    /// True when the open batch holds events.
    pub fn has_open_events(&self) -> bool {
        !self.open.events.is_empty()
    }

    /// Drops the merge keys whose window of 300 seconds passed (protocol.md 7.2), and the
    /// memory the table held for them. A call that creates events drops them on its way, and
    /// the sweep of the node drops them for an account that makes no call, so an idle account
    /// holds the keys of its last 300 seconds at most, and no memory of a table once they are
    /// gone.
    ///
    /// The state of an account lives as long as the node, and a table keeps the room of the
    /// largest number of keys it ever held unless it is asked to give it back. So when keys
    /// leave, a table without a key is replaced by one without memory, and a table with more
    /// room than twice its keys need shrinks to that room: the room that is left keeps the
    /// keys of an account that come and go around one number from resizing the table at every
    /// change.
    pub fn prune_recent(&mut self, now_ms: u64) {
        let window_ms = limits::MERGE_WINDOW_S * 1000;
        let before = self.recent.len();
        self.recent
            .retain(|_, recent| now_ms < recent.entry_ms.saturating_add(window_ms));
        match self.recent.len() {
            keys if keys == before => {}
            0 => self.recent = HashMap::new(),
            keys => self.recent.shrink_to(2 * keys),
        }
        adjust(&self.counters.merge_keys, before, self.recent.len());
    }

    /// The number of pending entries: entries that the log store has not confirmed and that
    /// no call writes at this moment.
    pub fn pending_entries(&self) -> usize {
        self.unconfirmed
            .iter()
            .filter(|entry| entry.writers == 0)
            .count()
    }

    /// The `pending_since_ms` of the oldest pending entry, `None` when the account has none.
    pub fn oldest_pending_since_ms(&self) -> Option<u64> {
        self.unconfirmed
            .iter()
            .filter(|entry| entry.writers == 0)
            .map(|entry| entry.pending_since_ms)
            .min()
    }

    /// The delegation state as `status` reports it: `active`, `none`, `revoked` or `expired`.
    pub fn status(&mut self, now_ms: u64) -> GrantStatus {
        self.expire(now_ms);
        match &self.grant {
            GrantState::None => GrantStatus::none(),
            GrantState::Revoked { key_id, .. } => GrantStatus {
                state: "revoked",
                key_id: key_id.clone(),
                custody: "",
                not_after_ms: 0,
            },
            GrantState::Expired {
                key_id,
                not_after_ms,
            } => GrantStatus {
                state: "expired",
                key_id: key_id.clone(),
                custody: "",
                not_after_ms: *not_after_ms,
            },
            GrantState::Active(grant) => GrantStatus {
                state: "active",
                key_id: grant.key_id.clone(),
                custody: grant.custody.as_str(),
                not_after_ms: grant.not_after_ms,
            },
        }
    }

    /// True when the account has a grant within its time.
    pub fn has_grant(&mut self, now_ms: u64) -> bool {
        self.expire(now_ms);
        matches!(self.grant, GrantState::Active(_))
    }

    /// The kept `refresh` responses of the account, for the tests that compare the counts of
    /// the node with a scan of its accounts.
    #[cfg(test)]
    pub fn kept_refresh_count(&self) -> usize {
        self.kept_refreshes.len()
    }

    /// The merge keys of the account, for the same tests.
    #[cfg(test)]
    pub fn merge_key_count(&self) -> usize {
        self.recent.len()
    }

    /// The numbers of merge keys, of kept `refresh` responses and of unconfirmed entries the
    /// account holds memory for, for the tests of that memory.
    #[cfg(test)]
    pub fn rooms(&self) -> (usize, usize, usize) {
        (
            self.recent.capacity(),
            self.kept_refreshes.capacity(),
            self.unconfirmed.capacity(),
        )
    }
}

impl GrantStatus {
    /// The state of an account without a delegation.
    pub fn none() -> GrantStatus {
        GrantStatus {
            state: "none",
            key_id: String::new(),
            custody: "",
            not_after_ms: 0,
        }
    }

    /// The state as `messages` reports it: `active`, `none` or `revoked`. An expired grant is
    /// reported as `none`.
    pub fn for_messages(self) -> GrantStatus {
        if self.state == "expired" {
            return GrantStatus::none();
        }
        self
    }
}

/// An authorization in progress (enclave.md 5.5), kept for 600 seconds and used once.
pub struct PendingAuth {
    pub user_id: String,
    pub key_id: String,
    /// The account signing public key of the grant under which the authorization started.
    /// The completion compares all 32 bytes with the grant then in force (protocol.md 8.2).
    pub sign_pk: [u8; 32],
    pub provider: String,
    pub code_verifier: Option<PkceVerifier>,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub expires_ms: u64,
}

/// A bounded store of values that expire and are used once.
///
/// When the store is full, entries past their time are dropped. When it is full of live
/// entries, the entry that was inserted first gives way to the new one.
struct Expiring<K, V> {
    slots: HashMap<K, Slot<V>>,
    next_serial: u64,
}

struct Slot<V> {
    value: V,
    expires_ms: u64,
    serial: u64,
}

impl<K: std::hash::Hash + Eq + Clone, V> Expiring<K, V> {
    fn new() -> Self {
        Expiring {
            slots: HashMap::new(),
            next_serial: 0,
        }
    }

    fn insert(&mut self, key: K, value: V, expires_ms: u64, now_ms: u64, capacity: usize) {
        if self.slots.len() >= capacity {
            self.slots.retain(|_, slot| now_ms < slot.expires_ms);
        }
        if self.slots.len() >= capacity {
            let first = self
                .slots
                .iter()
                .min_by_key(|(_, slot)| slot.serial)
                .map(|(key, _)| key.clone());
            if let Some(first) = first {
                self.slots.remove(&first);
            }
        }
        let serial = self.next_serial;
        self.next_serial += 1;
        self.slots.insert(
            key,
            Slot {
                value,
                expires_ms,
                serial,
            },
        );
    }

    /// Removes an entry and returns its value when its time has not passed.
    fn take<Q>(&mut self, key: &Q, now_ms: u64) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        self.slots
            .remove(key)
            .filter(|slot| now_ms < slot.expires_ms)
            .map(|slot| slot.value)
    }
}

/// A node.
pub struct Node {
    /// The signing key and the sealing key, created at boot.
    pub keys: NodeKeys,
    /// `b64u(signing public key)`.
    pub node: String,
    /// The custody of the user keys this node holds: the custody of its platform.
    pub custody: Custody,
    /// The release tag compiled into the binary.
    pub release: &'static str,
    /// What this node verifies the release proofs of another release with, and the old
    /// releases it takes delegations from (`crate::lineage`).
    pub lineage: Lineage,
    pub started_ms: u64,
    pub closing: AtomicBool,
    /// The role of this node, taken once (protocol.md 4.1).
    pub role: RoleCell,
    pub config: NodeRwLock<Option<Arc<OperatorConfig>>>,
    /// The log store of this node and the credentials for it (`crate::log_store`).
    pub log_store: LogStore,
    /// The challenges this node issued, each with the serial it was issued under. Removed
    /// after 300 seconds or on use.
    challenges: NodeLock<Expiring<[u8; 16], u64>>,
    /// The next serial of this node: one count, starting at 1, for the challenges the node
    /// issues and the revoke commands it accepts. It says which of the two came first.
    serials: AtomicU64,
    /// `user_id` to account state, in the order of `user_id`: a page of accounts after a
    /// `user_id` is a range of this map. Each account has its own lock.
    accounts: NodeRwLock<BTreeMap<String, Arc<AccountLock>>>,
    /// `node_state` to the authorization in progress. Removed after 600 seconds or on use.
    pending: NodeLock<Expiring<String, PendingAuth>>,
    /// The number of accounts that have a chain.
    chains: AtomicUsize,
    /// The counts of the state of the accounts, kept by the methods of [`Account`].
    pub counters: Arc<StateCounters>,
    pub platform: SharedPlatform,
    pub clock: Arc<Clock>,
    pub definitions: Definitions,
    pub egress: Egress,
    pub limits: Limits,
    pub forward_slots: Arc<Semaphore>,
    pub body_budget: Arc<Semaphore>,
    /// The budget of the requests of the calls of a command
    /// (`Limits::command_budget_bytes`).
    pub command_budget: Arc<Semaphore>,
    /// The numbers of the secret uses this node sent (`vault/send`): a node of the forward
    /// role sends the request of one number once.
    pub used_nonces: NodeLock<UsedNonces>,
    /// The verifier of the nodes of the forward role for this node, with the nodes it
    /// verified (`crate::attest`): a node of the delegation role seals a secret use to one of
    /// them (`vault/handoff`).
    pub forward_nodes: ForwardNodes,
    /// The places of the token address calls of `refresh` that the node continues after their
    /// time limit (enclave.md 5.7): `limits.refresh_late_tasks` of them.
    pub late_refreshes: Arc<Semaphore>,
    /// The counts of `log` of `GET /v1/health`.
    pub log_counters: LogCounters,
    /// The counts of `refresh` of `GET /v1/health`.
    pub refresh_counters: RefreshCounters,
    /// The counts of the connections from the backend (`load` of `GET /v1/health`), moved by
    /// the accept loop of the call surface.
    pub inbound: Arc<InboundCounters>,
}

/// The accounts of a node whose `user_id` sorts after a value, in `user_id` order, read from
/// the sorted index in chunks of [`WALK_CHUNK`] accounts: the index is locked for one chunk at
/// a time, so a walk over every account of the node (the sweep, a page of `peer/export` or of
/// `grants/prune`) never holds the index for long.
pub struct AccountWalk<'a> {
    node: &'a Node,
    /// The `user_id` the next chunk starts after.
    after: String,
    chunk: std::collections::VecDeque<(String, Arc<AccountLock>)>,
    /// True once a chunk came back shorter than [`WALK_CHUNK`]: the index has no further
    /// account.
    exhausted: bool,
}

/// The accounts one range read of the sorted index returns.
pub const WALK_CHUNK: usize = 1_000;

impl Iterator for AccountWalk<'_> {
    type Item = (String, Arc<AccountLock>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.chunk.is_empty() && !self.exhausted {
            let chunk = self.node.accounts_from(&self.after, WALK_CHUNK);
            self.exhausted = chunk.len() < WALK_CHUNK;
            if let Some((last, _)) = chunk.last() {
                self.after = last.clone();
            }
            self.chunk = chunk.into();
        }
        self.chunk.pop_front()
    }
}

/// The state of one account behind its lock: `lock(&account)` waits for the lock and returns
/// the state.
///
/// A panic that began while the lock was held leaves the lock poisoned. The next call that
/// asks for the lock, of the account or of the sweep of the node (within 30 seconds), finds it
/// so and halts the account before it reads anything of the state ([`Account::halt`]). The
/// lock of one account is never held across a wait, and no lock of another account is taken
/// under it, so a panic under it leaves the state of no other account in doubt.
pub struct AccountLock(Mutex<Account>);

impl AccountLock {
    fn new(account: Account) -> AccountLock {
        AccountLock(Mutex::new(account))
    }
}

impl Lock for AccountLock {
    type State = Account;

    fn acquire(&self) -> MutexGuard<'_, Account> {
        match self.0.lock() {
            Ok(account) => account,
            Err(poisoned) => {
                let mut account = poisoned.into_inner();
                account.halt();
                account
            }
        }
    }
}

impl Node {
    /// Creates the node keys and an empty state.
    pub fn start(
        platform: SharedPlatform,
        clock: Arc<Clock>,
        definitions: Definitions,
        egress: Egress,
        release: &'static str,
        lineage: Lineage,
        limits: Limits,
    ) -> Result<Node, PlatformError> {
        // The signing seed is drawn first, then the sealing private key.
        let sign_seed = Secret::<[u8; 32]>::try_from_fn(|bytes| platform.fill_random(bytes))?;
        let seal_private = Secret::<[u8; 32]>::try_from_fn(|bytes| platform.fill_random(bytes))?;
        let keys = NodeKeys::from_random(sign_seed.expose_secret(), seal_private.expose_secret());
        // The binding of a node with the longest log store name fits the limit of a binding.
        let longest = LogStoreId::parse(&"b".repeat(63), "ap-southeast-99");
        if binding(&keys, release, longest.as_ref()).len()
            > credential_enclave_protocol::limits::BINDING_BYTES
        {
            return Err(PlatformError("the release tag is too long for the binding"));
        }
        let custody = Custody::parse(platform.custody())
            .ok_or(PlatformError("the platform names an unknown custody"))?;
        let forward_nodes = ForwardNodes::of(platform.name(), platform.measurement());
        Ok(Node {
            node: keys.node(),
            keys,
            custody,
            release,
            lineage,
            started_ms: clock.now_ms(),
            closing: AtomicBool::new(false),
            role: RoleCell::default(),
            config: NodeRwLock::new(None),
            // A node of the nitro platform does not act without a log store.
            log_store: LogStore::new(platform.name() == "nitro"),
            challenges: NodeLock::new(Expiring::new()),
            serials: AtomicU64::new(1),
            accounts: NodeRwLock::new(BTreeMap::new()),
            pending: NodeLock::new(Expiring::new()),
            chains: AtomicUsize::new(0),
            counters: Arc::new(StateCounters::default()),
            platform,
            clock,
            definitions,
            egress,
            forward_slots: Arc::new(Semaphore::new(limits.forward_concurrency)),
            body_budget: Arc::new(Semaphore::new(limits.body_budget_bytes)),
            command_budget: Arc::new(Semaphore::new(limits.command_budget_bytes)),
            used_nonces: NodeLock::new(UsedNonces::default()),
            forward_nodes,
            late_refreshes: Arc::new(Semaphore::new(limits.refresh_late_tasks)),
            limits,
            log_counters: LogCounters::default(),
            refresh_counters: RefreshCounters::default(),
            inbound: Arc::new(InboundCounters::default()),
        })
    }

    /// The node time in Unix epoch milliseconds.
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// The calls that hold one of the places of the bound of concurrent `forward` and
    /// `forward/batch` calls at this moment (`forward`, `forward/batch` and the mail calls take
    /// one each).
    pub fn forward_calls(&self) -> usize {
        self.limits
            .forward_concurrency
            .saturating_sub(self.forward_slots.available_permits())
    }

    /// The token address calls of `refresh` the node continues after their time limit at this
    /// moment (enclave.md 5.7).
    pub fn late_refreshes_inflight(&self) -> usize {
        self.limits
            .refresh_late_tasks
            .saturating_sub(self.late_refreshes.available_permits())
    }

    /// Holds the kept `refresh` responses of the node within their bound (enclave.md 5.7).
    /// While the sum of the bytes the node counts for them is above
    /// `Limits::kept_refresh_bytes`, the response the node kept first is dropped, whichever
    /// account holds it, and counted (`kept_refreshes_dropped` of `load` of health). The call
    /// that kept a response calls this, and holds the lock of no account when it does.
    pub fn bound_kept_refreshes(&self) {
        loop {
            // The lock of the order is given back before the lock of an account is taken.
            let first = lock(&self.counters.kept_order).first_above(self.limits.kept_refresh_bytes);
            let Some((serial, user_id)) = first else {
                return;
            };
            let dropped = self
                .account(&user_id)
                .is_some_and(|account| lock(&account).drop_kept_refresh(serial));
            if dropped {
                self.counters
                    .kept_refreshes_dropped
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                // No account holds this response any more: its place in the order goes.
                lock(&self.counters.kept_order).remove(serial);
            }
        }
    }

    /// The bytes the node counts for its kept `refresh` responses at this moment
    /// (`kept_refresh_bytes` of `state` of health).
    pub fn kept_refresh_bytes(&self) -> usize {
        lock(&self.counters.kept_order).bytes()
    }

    /// The kept `refresh` responses the node dropped for their bound since it started
    /// (`kept_refreshes_dropped` of `load` of health).
    pub fn kept_refreshes_dropped(&self) -> u64 {
        self.counters.kept_refreshes_dropped.load(Ordering::Relaxed)
    }

    /// `N` random bytes that may appear in a response: a challenge, the node part of a state,
    /// the `id` and the nonce of a record. Every random value of a response comes from this
    /// function, and it reads nothing but the random source of the platform.
    pub fn random_public<const N: usize>(&self) -> Result<[u8; N], ApiError> {
        let mut bytes = [0u8; N];
        self.platform.fill_random(&mut bytes)?;
        Ok(bytes)
    }

    /// `N` random bytes that stay inside the node: the key material of an HPKE seal and a PKCE
    /// verifier.
    pub fn random_secret<const N: usize>(&self) -> Result<Secret<[u8; N]>, ApiError> {
        Ok(Secret::try_from_fn(|bytes| {
            self.platform.fill_random(bytes)
        })?)
    }

    /// Step 1 of the common front: the orderly shutdown has not started.
    pub fn ensure_open(&self) -> Result<(), ProtocolError> {
        if self.closing.load(Ordering::SeqCst) {
            return Err(ProtocolError::Closing);
        }
        Ok(())
    }

    /// Step 2 of the common front: the operator configuration is present.
    pub fn operator_config(&self) -> Result<Arc<OperatorConfig>, ProtocolError> {
        self.config
            .read()
            .clone()
            .ok_or(ProtocolError::NotConfigured)
    }

    /// True when the operator configuration is present.
    pub fn is_configured(&self) -> bool {
        self.config.read().is_some()
    }

    /// Replaces the operator configuration.
    pub fn set_config(&self, config: OperatorConfig) {
        *self.config.write() = Some(Arc::new(config));
    }

    /// True when the platform accepts a callback address on `http://localhost` (enclave.md
    /// 5.1): the local platform only.
    pub fn accepts_localhost_redirect(&self) -> bool {
        self.platform.name() == "local"
    }

    /// The state of an account, when it has one.
    pub fn account(&self, user_id: &str) -> Option<Arc<AccountLock>> {
        self.accounts.read().get(user_id).cloned()
    }

    /// The state of an account, created when it has none.
    pub fn account_or_create(&self, user_id: &str) -> Arc<AccountLock> {
        if let Some(account) = self.account(user_id) {
            return account;
        }
        self.accounts
            .write()
            .entry(user_id.to_string())
            .or_insert_with(|| Arc::new(AccountLock::new(Account::new(self.counters.clone()))))
            .clone()
    }

    /// The first `count` accounts whose `user_id` sorts after `after`, in `user_id` order: one
    /// range read of the sorted index. An empty `after` starts at the first account.
    pub fn accounts_from(&self, after: &str, count: usize) -> Vec<(String, Arc<AccountLock>)> {
        let start = match after.is_empty() {
            true => Bound::Unbounded,
            false => Bound::Excluded(after.to_string()),
        };
        self.accounts
            .read()
            .range((start, Bound::Unbounded))
            .take(count)
            .map(|(user_id, account)| (user_id.clone(), account.clone()))
            .collect()
    }

    /// The accounts whose `user_id` sorts after `after`, in `user_id` order, read from the
    /// sorted index one chunk at a time. An empty `after` walks every account.
    pub fn accounts_after(&self, after: &str) -> AccountWalk<'_> {
        AccountWalk {
            node: self,
            after: after.to_string(),
            chunk: std::collections::VecDeque::new(),
            exhausted: false,
        }
    }

    /// The number of accounts that have a chain.
    pub fn account_count(&self) -> usize {
        self.chains.load(Ordering::SeqCst)
    }

    /// The number of accounts this node halted since it started (`halted_accounts` of `load`
    /// of health): an account stays halted for as long as the node lives.
    pub fn halted_accounts(&self) -> usize {
        self.counters.halted.load(Ordering::Relaxed)
    }

    /// The binding of this node (protocol.md 4.1): its two public keys, its release, its log
    /// store when it has one, and its role when that is one a binding names. A node of the
    /// forward role has no log store. A node that has taken no role yet states none, as a
    /// node of the delegation role does: it is one with the first call that only a node
    /// that holds delegations answers.
    pub fn binding(&self) -> Vec<u8> {
        let role = self.role.get().unwrap_or(Role::Delegation);
        let log = match role {
            Role::Forward => None,
            Role::Delegation | Role::Reserve => self.log_store.id(),
        };
        role_binding(&self.keys, self.release, log, role)
    }

    /// The age of the oldest pending entry in milliseconds of node time, as the last sweep of
    /// the node found it (`pending_oldest_ms` of `log_store` of health): 0 when that sweep
    /// found no pending entry or no sweep ran yet.
    pub fn pending_oldest_ms(&self) -> u64 {
        match self
            .counters
            .pending_oldest_since_ms
            .load(Ordering::Relaxed)
        {
            0 => 0,
            since_ms => self.now_ms().saturating_sub(since_ms),
        }
    }

    /// The next serial of this node. Every call returns a larger value than the calls before
    /// it, starting at 1. A challenge gets one when it is issued, and an account gets one
    /// when this node accepts a revoke command of it.
    pub fn next_serial(&self) -> u64 {
        self.serials.fetch_add(1, Ordering::SeqCst)
    }

    /// Issues a one-time challenge (protocol.md 4.2). Step 12 of protocol.md 5.3 consumes it.
    pub fn issue_challenge(&self) -> Result<[u8; 16], ApiError> {
        let challenge = self.random_public::<16>()?;
        let now_ms = self.now_ms();
        lock(&self.challenges).insert(
            challenge,
            self.next_serial(),
            now_ms.saturating_add(limits::CHALLENGE_MS),
            now_ms,
            self.limits.challenges,
        );
        Ok(challenge)
    }

    /// Consumes a challenge and returns the serial it was issued under. `None` when this node
    /// did not issue it, when its 300 seconds passed, and when it was used before.
    pub fn take_challenge(&self, challenge: &str) -> Option<u64> {
        let bytes = b64u_decode(challenge).ok()?;
        let key = <[u8; 16]>::try_from(bytes.as_slice()).ok()?;
        let now_ms = self.now_ms();
        lock(&self.challenges).take(&key, now_ms)
    }

    /// Keeps an authorization in progress under its `node_state`.
    pub fn insert_pending(&self, node_state: String, pending: PendingAuth) {
        let now_ms = self.now_ms();
        let expires_ms = pending.expires_ms;
        lock(&self.pending).insert(node_state, pending, expires_ms, now_ms, self.limits.pending);
    }

    /// Removes and returns the authorization in progress of a `node_state`. `None` when there
    /// is none or its 600 seconds passed.
    pub fn take_pending(&self, node_state: &str) -> Option<PendingAuth> {
        let now_ms = self.now_ms();
        lock(&self.pending).take(node_state, now_ms)
    }

    /// Creates an event of an account (protocol.md 7.1) and returns where it is. The caller
    /// holds the account lock, so the entries of one account are created one after the other.
    /// `key_id` and `log_pk` are those of the grant in force at this moment, `now_ms` the node
    /// time the caller read.
    ///
    /// A use event goes into the open batch of the account; when the batch is full for it, or
    /// was opened under another key, the batch is closed into an entry first. A control event
    /// closes the open batch, when it holds events, and forms an entry of its own. An entry
    /// starts as an unconfirmed entry that no call writes yet: the call confirms it with
    /// `log_store::commit` before the act the event describes, or leaves it to the next write
    /// of the account (`peer/import`).
    ///
    /// The `time_ms` of the event is `now_ms`, or the time of the event before it when that
    /// one is later: a caller may have read the node time before it took the account lock,
    /// and the times of the events of one node for one account do not decrease with
    /// (seq, index).
    ///
    /// An event whose JSON alone is longer than the plaintext of an entry may be is refused
    /// with `too_large` before anything changes: no entry could hold it.
    #[allow(clippy::too_many_arguments)]
    pub fn create_event(
        &self,
        account: &mut Account,
        user_id: &str,
        key_id: &str,
        log_pk: &[u8; 32],
        now_ms: u64,
        kind: EntryKind,
        event: Value,
    ) -> Result<EventPlace, ApiError> {
        let seed = self.random_secret::<32>()?;
        self.create_event_seeded(account, user_id, key_id, log_pk, now_ms, kind, event, &seed)
    }

    /// [`Node::create_event`] with the HPKE seed drawn by the caller. A call that creates
    /// events on several chains draws every seed first, so a failure of the random source
    /// leaves every chain as it was. The seed is used when this call closes a batch or forms a
    /// control entry; a use event that joins an open batch does not use it (the close of that
    /// batch draws its own).
    #[allow(clippy::too_many_arguments)]
    pub fn create_event_seeded(
        &self,
        account: &mut Account,
        user_id: &str,
        key_id: &str,
        log_pk: &[u8; 32],
        now_ms: u64,
        kind: EntryKind,
        mut event: Value,
        seed: &Secret<[u8; 32]>,
    ) -> Result<EventPlace, ApiError> {
        // The node creates no event for a halted account.
        account.ensure_usable()?;
        let time_ms = now_ms.max(account.last_event_ms);
        // An event is a JSON object (`events`): its `time_ms` key takes the time. A value of
        // another form is no event.
        let Some(keys) = event.as_object_mut() else {
            return Err(ApiError::internal());
        };
        keys.insert("time_ms".to_string(), Value::from(time_ms));
        // The array of one event is the event and its two brackets.
        let event_bytes = to_json(&event).len();
        if event_bytes + 2 > limits::ENTRY_PLAINTEXT_BYTES {
            return Err(ProtocolError::TooLarge.into());
        }
        account.last_event_ms = time_ms;
        match kind {
            EntryKind::Control => {
                if account.has_open_events() {
                    self.close_batch(account, user_id, time_ms)?;
                }
                let seq = self.append_closed(
                    account,
                    user_id,
                    key_id,
                    log_pk,
                    time_ms,
                    kind,
                    vec![event],
                    seed,
                )?;
                Ok(EventPlace::Entry { seq, index: 0 })
            }
            EntryKind::Use => {
                let other_key = account.has_open_events() && account.open.key_id != key_id;
                if other_key || account.open.full_for(event_bytes) {
                    self.close_batch_seeded(account, user_id, time_ms, seed)?;
                }
                if account.open.events.is_empty() {
                    account.open.key_id = key_id.to_string();
                    account.open.log_pk = *log_pk;
                    account.open.bytes = 2;
                    self.counters.open_batches.fetch_add(1, Ordering::Relaxed);
                } else {
                    account.open.bytes += 1;
                }
                account.open.bytes += event_bytes;
                account.open.events.push(event);
                Ok(EventPlace::Open {
                    batch: account.open.seq.clone(),
                    index: (account.open.events.len() - 1) as u32,
                })
            }
        }
    }

    /// Creates the use events of a `forward/batch` call in one step, in the order given.
    /// `events` pairs each event with its merge key when the request is a GET without a body.
    /// A request that matches an event of the open batch or of an entry created less than
    /// 300 seconds before shares that event (protocol.md 7.2), also inside the batch. Returns
    /// where every event is and whether this call created it.
    ///
    /// The node remembers at most `Limits::merge_keys` events of one account at one time. A
    /// GET request without a body that finds no event to share while its account has that
    /// many has an event of its own that the node does not remember: no later request shares
    /// it, and the event carries no `window_s`, the key that says that the same request may
    /// have happened again in the 300 seconds after it.
    pub fn create_events(
        &self,
        account: &mut Account,
        user_id: &str,
        key_id: &str,
        log_pk: &[u8; 32],
        now_ms: u64,
        events: Vec<(Option<[u8; 32]>, Value)>,
    ) -> Result<Vec<(EventPlace, bool)>, ApiError> {
        account.prune_recent(now_ms);
        let mut places = Vec::with_capacity(events.len());
        for (merge_key, mut event) in events {
            if let Some(shared) = merge_key.and_then(|key| account.shared_event(&key)) {
                places.push((shared.target, false));
                continue;
            }
            let remembered = merge_key.filter(|_| account.remembers_more(self.limits.merge_keys));
            if merge_key.is_some() && remembered.is_none() {
                if let Some(keys) = event.as_object_mut() {
                    keys.shift_remove("window_s");
                }
            }
            let place = self.create_event(
                account,
                user_id,
                key_id,
                log_pk,
                now_ms,
                EntryKind::Use,
                event,
            )?;
            if let Some(key) = remembered {
                account.remember_event(
                    key,
                    Recent {
                        entry_ms: now_ms,
                        target: place.clone(),
                    },
                );
            }
            places.push((place, true));
        }
        Ok(places)
    }

    /// Closes the open batch of an account into an entry (protocol.md 7.1) and returns the
    /// `seq` of that entry, `None` when the batch holds no event. The caller holds the account
    /// lock. The entry is an unconfirmed entry that no call writes yet.
    pub fn close_batch(
        &self,
        account: &mut Account,
        user_id: &str,
        now_ms: u64,
    ) -> Result<Option<u64>, ApiError> {
        if !account.has_open_events() {
            return Ok(None);
        }
        let seed = self.random_secret::<32>()?;
        Ok(Some(
            self.close_batch_seeded(account, user_id, now_ms, &seed)?,
        ))
    }

    /// [`Node::close_batch`] with the seed drawn by the caller, for a batch that holds events.
    fn close_batch_seeded(
        &self,
        account: &mut Account,
        user_id: &str,
        now_ms: u64,
        seed: &Secret<[u8; 32]>,
    ) -> Result<u64, ApiError> {
        let events = std::mem::take(&mut account.open.events);
        let (key_id, log_pk) = (account.open.key_id.clone(), account.open.log_pk);
        let batch = std::mem::replace(&mut account.open.seq, Arc::new(OnceLock::new()));
        account.open.bytes = 2;
        self.counters.open_batches.fetch_sub(1, Ordering::Relaxed);
        let appended = self.append_closed(
            account,
            user_id,
            &key_id,
            &log_pk,
            now_ms,
            EntryKind::Use,
            events,
            seed,
        );
        // Every call whose event joined the batch, and every `recent` that points into it,
        // now finds the entry through the cell. When no entry could be made of the batch, the
        // cell receives 0, the `seq` of no entry: no entry of that `seq` is ever confirmed, so
        // the acts of those calls do not take place.
        let _ = batch.set(*appended.as_ref().unwrap_or(&0));
        appended
    }

    /// Creates the next entry of the node for the account from `events`. The `time_ms` of the
    /// entry is `now_ms`, or the time of the entry before it, or the time of the latest event,
    /// whichever is largest: the times of the entries of one node for one account do not
    /// decrease, and no event is dated after its entry.
    ///
    /// When no entry can be made of the events (`log::append_v3` names the cases, none of
    /// which a batch the node filled reaches), the call ends with an internal failure and the
    /// account keeps the entry it had as its last one.
    #[allow(clippy::too_many_arguments)]
    fn append_closed(
        &self,
        account: &mut Account,
        user_id: &str,
        key_id: &str,
        log_pk: &[u8; 32],
        now_ms: u64,
        kind: EntryKind,
        events: Vec<Value>,
        seed: &Secret<[u8; 32]>,
    ) -> Result<u64, ApiError> {
        // The one place the chain of an account grows: it does not grow for a halted account.
        account.ensure_usable()?;
        let time_ms = now_ms.max(account.last_entry_ms).max(account.last_event_ms);
        let count = events.len() as u64;
        let (signed, last, key) = log::append_v3(
            &self.keys,
            &account.last,
            user_id,
            key_id,
            log_pk,
            time_ms,
            kind,
            &events,
            seed,
        )
        .ok_or_else(ApiError::internal)?;
        account.last_entry_ms = time_ms;
        if account.last.seq == 0 {
            self.chains.fetch_add(1, Ordering::SeqCst);
        }
        account.last = last;
        self.log_counters.entries.fetch_add(1, Ordering::Relaxed);
        self.log_counters.events.fetch_add(count, Ordering::Relaxed);
        if self.log_store.tracks() {
            account.push_unconfirmed(Unconfirmed {
                seq: last.seq,
                key: log::object_key_v3(user_id, &key),
                shard: shard_hash(user_id),
                entry: signed,
                writers: 0,
                pending_since_ms: time_ms,
            });
        }
        Ok(last.seq)
    }
}

/// Step 6 of the common front: opens a record for the account of the call (protocol.md
/// section 6) and reads its kind. A record of another account is `user_mismatch`, a record of
/// another key or of another custody is `key_mismatch`, a record that does not decrypt is
/// `record_invalid`, and a record whose kind this release does not know is `not_allowed`.
///
/// The kind is part of the AAD of the record, so a record that opened has the kind it names.
/// The two callers turn the plaintext into the type of their call family and refuse the kinds
/// of the other one: [`crate::oauth::open_record`] for the calls that use a token inside the
/// node, [`crate::vault::open_record`] for `release`.
pub fn open_for(
    grant: &GrantView,
    user_id: &str,
    record: &Record,
) -> Result<(Kind, Secret<Vec<u8>>), ProtocolError> {
    if record.v != 1 {
        return Err(ProtocolError::UnsupportedVersion);
    }
    if record.user_id != user_id {
        return Err(ProtocolError::UserMismatch);
    }
    if record.key_id != grant.key_id || record.custody != grant.custody.as_str() {
        return Err(ProtocolError::KeyMismatch);
    }
    let plaintext = record::open(&grant.user_key, record)?;
    let kind = Kind::parse(&record.kind).ok_or(ProtocolError::NotAllowed)?;
    Ok((kind, plaintext))
}

/// The merge key of a GET request: the hash of the record id and the address. Identical GET
/// requests of one account within 300 seconds share one entry when they have no body
/// (protocol.md 7.2). A GET request with a body is never merged, so the key holds no body.
pub fn merge_key(record_id: &[u8; 16], host: &str, path: &str, query: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(record_id);
    hasher.update(host.as_bytes());
    hasher.update(b"\n");
    hasher.update(path.as_bytes());
    hasher.update(b"\n");
    hasher.update(query.as_bytes());
    hasher.finalize().into()
}

/// The events of protocol.md 7.2. Each function returns the event with its keys in the order
/// of that table: `t` first, then `time_ms` (the value [`Node::create_event`] sets to the node
/// time of the creation), then the other keys.
///
/// An event holds no secret. Its values are identifiers, addresses, the hash of a request body
/// and the context string of the caller, and a scope string that passed the public field rule.
/// No function here takes a secret type.
pub mod events {
    use super::{b64u, limits, Custody, Digest, ReleaseMeasurement, Sha256};
    use serde_json::{json, Value};

    /// The `time_ms` key every event carries after `t`. [`super::Node::create_event`] writes
    /// the node time into it.
    const TIME_MS: u64 = 0;

    /// Copies at most 8,192 bytes of an address part and marks a cut with `…` (U+2026). No
    /// address of `forward` is longer than that, so the path and the query of a request are
    /// carried whole: this bound never cuts one.
    fn clip(text: &str) -> String {
        if text.len() <= limits::EVENT_ADDRESS_BYTES {
            return text.to_string();
        }
        let mut end = limits::EVENT_ADDRESS_BYTES;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}\u{2026}", text.get(..end).unwrap_or_default())
    }

    /// `not_after_ms` is the expiry the node accepted, which can be earlier than the one the
    /// command asked for.
    pub fn grant_accepted(not_after_ms: u64, custody: Custody) -> Value {
        json!({
            "t": "grant_accepted",
            "time_ms": TIME_MS,
            "not_after_ms": not_after_ms,
            "custody": custody.as_str(),
        })
    }

    pub fn grant_revoked() -> Value {
        json!({"t": "grant_revoked", "time_ms": TIME_MS})
    }

    pub fn connection_created(record_id: &str, provider: &str, scope: &str) -> Value {
        json!({
            "t": "connection_created",
            "time_ms": TIME_MS,
            "record_id": record_id,
            "provider": provider,
            "scope": scope,
        })
    }

    pub fn credential_refreshed(record_id: &str, provider: &str) -> Value {
        json!({
            "t": "credential_refreshed",
            "time_ms": TIME_MS,
            "record_id": record_id,
            "provider": provider,
        })
    }

    /// `provider_revoke` says whether the node calls the revocation address of the provider
    /// after this entry. The entry is created before that call, so it cannot carry its outcome.
    pub fn connection_removed(record_id: &str, provider: &str, provider_revoke: bool) -> Value {
        json!({
            "t": "connection_removed",
            "time_ms": TIME_MS,
            "record_id": record_id,
            "provider": provider,
            "provider_revoke": provider_revoke,
        })
    }

    /// The event of a transfer to a node of another release (protocol.md 10.3). `to` is the
    /// node the delegation was sealed for, and `other` the release and the measurement of
    /// that node: the measurement of its verified attestation document, which the release
    /// proofs of the call show, and the release its binding names. With them the account
    /// reads from its log which program received its key. A transfer to a node of the
    /// measurement of this node creates no event.
    pub fn grant_transferred_out(to: &str, other: &ReleaseMeasurement) -> Value {
        let [pcr0, pcr1, pcr2] = other.pcrs.map(|pcr| hex(&pcr));
        json!({
            "t": "grant_transferred_out",
            "time_ms": TIME_MS,
            "to": to,
            "release": other.release,
            "pcr0": pcr0,
            "pcr1": pcr1,
            "pcr2": pcr2,
        })
    }

    /// The event of a transfer this node took from a node of another release (protocol.md
    /// 10.3). `from` is the node that gave the delegation and `release` the release of that
    /// node, as its binding names it. `not_after_ms` is the end the receiving node accepted.
    pub fn grant_transferred_in(
        from: &str,
        release: &str,
        not_after_ms: u64,
        custody: Custody,
    ) -> Value {
        json!({
            "t": "grant_transferred_in",
            "time_ms": TIME_MS,
            "from": from,
            "release": release,
            "not_after_ms": not_after_ms,
            "custody": custody.as_str(),
        })
    }

    /// Lower-case hexadecimal.
    fn hex(bytes: &[u8]) -> String {
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            for half in [byte >> 4, byte & 0x0f] {
                text.extend(char::from_digit(u32::from(half), 16));
            }
        }
        text
    }

    /// The event of a mail call: `operation` is `verify`, `read` or `submit` and `request` the
    /// parameters of the call.
    pub fn mail_request(
        record_id: &str,
        operation: &str,
        request: &Value,
        body: &[u8],
        context: &str,
    ) -> Value {
        json!({
            "t": "mail_request",
            "time_ms": TIME_MS,
            "record_id": record_id,
            "provider": "naver_mail",
            "operation": operation,
            "request": request,
            "body_bytes": body.len(),
            "body_sha256": b64u(&Sha256::digest(body)),
            "context": context,
        })
    }

    /// `mergeable` is true for a GET request without a body: such an entry carries
    /// `window_s: 300`, which says that the same request may have happened any number of
    /// times in the 300 seconds after it.
    #[allow(clippy::too_many_arguments)]
    pub fn provider_request(
        record_id: &str,
        provider: &str,
        method: &str,
        host: &str,
        path: &str,
        query: &str,
        body: &[u8],
        context: &str,
        mergeable: bool,
    ) -> Value {
        let body_sha256 = if body.is_empty() {
            String::new()
        } else {
            b64u(&Sha256::digest(body))
        };
        let mut event = json!({
            "t": "provider_request",
            "time_ms": TIME_MS,
            "record_id": record_id,
            "provider": provider,
            "method": method,
            "host": host,
            "path": clip(path),
            "query": clip(query),
            "body_bytes": body.len(),
            "body_sha256": body_sha256,
            "context": context,
        });
        if let (true, Some(keys)) = (mergeable, event.as_object_mut()) {
            keys.insert("window_s".to_string(), json!(limits::MERGE_WINDOW_S));
        }
        event
    }

    pub fn secret_released(
        record_id: &str,
        kind: &str,
        field: &str,
        origin: &str,
        context: &str,
    ) -> Value {
        json!({
            "t": "secret_released",
            "time_ms": TIME_MS,
            "record_id": record_id,
            "kind": kind,
            "field": field,
            "origin": origin,
            "context": context,
        })
    }

    pub fn totp_issued(record_id: &str, origin: &str, context: &str) -> Value {
        json!({
            "t": "totp_issued",
            "time_ms": TIME_MS,
            "record_id": record_id,
            "origin": origin,
            "context": context,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use credential_enclave_protocol::encoding::to_json;

        fn text(value: &Value) -> String {
            String::from_utf8(to_json(value)).unwrap()
        }

        #[test]
        fn events_have_the_key_order_of_protocol_7_2() {
            assert_eq!(
                text(&grant_accepted(9, Custody::Enclave)),
                r#"{"t":"grant_accepted","time_ms":0,"not_after_ms":9,"custody":"enclave"}"#
            );
            assert_eq!(
                text(&grant_accepted(9, Custody::Operator)),
                r#"{"t":"grant_accepted","time_ms":0,"not_after_ms":9,"custody":"operator"}"#
            );
            assert_eq!(
                text(&grant_revoked()),
                r#"{"t":"grant_revoked","time_ms":0}"#
            );
            assert_eq!(
                text(&connection_created("r", "slack", "chat:write")),
                r#"{"t":"connection_created","time_ms":0,"record_id":"r","provider":"slack","scope":"chat:write"}"#
            );
            assert_eq!(
                text(&credential_refreshed("r", "x")),
                r#"{"t":"credential_refreshed","time_ms":0,"record_id":"r","provider":"x"}"#
            );
            assert_eq!(
                text(&connection_removed("r", "x", true)),
                r#"{"t":"connection_removed","time_ms":0,"record_id":"r","provider":"x","provider_revoke":true}"#
            );
            assert_eq!(
                text(&secret_released(
                    "r",
                    "vault_card",
                    "card_cvc",
                    "https://a.example",
                    "browser:fill"
                )),
                concat!(
                    r#"{"t":"secret_released","time_ms":0,"record_id":"r","kind":"vault_card","#,
                    r#""field":"card_cvc","origin":"https://a.example","context":"browser:fill"}"#
                )
            );
            assert_eq!(
                text(&totp_issued("r", "https://a.example", "browser:fill")),
                r#"{"t":"totp_issued","time_ms":0,"record_id":"r","origin":"https://a.example","context":"browser:fill"}"#
            );
            let later = ReleaseMeasurement {
                release: "v9.0.0".to_string(),
                pcrs: [[0x0a; 48], [0x1b; 48], [0xf2; 48]],
            };
            assert_eq!(
                text(&grant_transferred_out("NODE-B", &later)),
                format!(
                    concat!(
                        r#"{{"t":"grant_transferred_out","time_ms":0,"to":"NODE-B","#,
                        r#""release":"v9.0.0","pcr0":"{}","pcr1":"{}","pcr2":"{}"}}"#
                    ),
                    "0a".repeat(48),
                    "1b".repeat(48),
                    "f2".repeat(48)
                )
            );
            assert_eq!(
                text(&grant_transferred_in(
                    "NODE-A",
                    "v2.3.0",
                    9,
                    Custody::Enclave
                )),
                concat!(
                    r#"{"t":"grant_transferred_in","time_ms":0,"from":"NODE-A","#,
                    r#""release":"v2.3.0","not_after_ms":9,"custody":"enclave"}"#
                )
            );
            assert_eq!(
                text(&mail_request(
                    "r",
                    "read",
                    &json!({"action": "folders"}),
                    b"",
                    "cli:naver-mail"
                )),
                concat!(
                    r#"{"t":"mail_request","time_ms":0,"record_id":"r","provider":"naver_mail","operation":"read","#,
                    r#""request":{"action":"folders"},"body_bytes":0,"#,
                    r#""body_sha256":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","context":"cli:naver-mail"}"#
                )
            );
        }

        #[test]
        fn a_get_request_carries_the_merge_window_and_other_methods_do_not() {
            assert_eq!(
                text(&provider_request(
                    "r",
                    "x",
                    "GET",
                    "api.x.com",
                    "/2/users/me",
                    "a=1",
                    b"",
                    "cli:x",
                    true
                )),
                concat!(
                    r#"{"t":"provider_request","time_ms":0,"record_id":"r","provider":"x","method":"GET","#,
                    r#""host":"api.x.com","path":"/2/users/me","query":"a=1","body_bytes":0,"#,
                    r#""body_sha256":"","context":"cli:x","window_s":300}"#
                )
            );
            let post = provider_request(
                "r",
                "x",
                "POST",
                "api.x.com",
                "/2/tweets",
                "",
                b"{}",
                "cli:x",
                false,
            );
            assert_eq!(post["body_bytes"], 2);
            assert_eq!(post["body_sha256"], b64u(&Sha256::digest(b"{}")));
            assert!(post.get("window_s").is_none());
        }

        #[test]
        fn a_path_and_a_query_of_the_length_of_an_address_are_carried_whole() {
            // The longest address of `forward` is 8,192 bytes: no path and no query of a
            // request is longer, and the event holds each of them whole.
            assert_eq!(limits::EVENT_ADDRESS_BYTES, 8192);
            let path = format!("/{}", "a".repeat(8191));
            let query = "q".repeat(8192);
            let event = provider_request("r", "x", "GET", "h", &path, &query, b"", "", true);
            assert_eq!(event["path"].as_str().unwrap(), path);
            assert_eq!(event["query"].as_str().unwrap(), query);
            // The bound of the event itself: a longer value, which no request has, is cut and
            // marked. A cut never splits a character.
            let long = "a".repeat(9000);
            let event = provider_request("r", "x", "GET", "h", &long, "", b"", "", true);
            let cut = event["path"].as_str().unwrap();
            assert_eq!(cut.len(), 8192 + "\u{2026}".len());
            assert!(cut.ends_with('\u{2026}'));
            let wide = "é".repeat(5000);
            let event = provider_request("r", "x", "GET", "h", "/", &wide, b"", "", true);
            let cut = event["query"].as_str().unwrap();
            assert!(cut.ends_with('\u{2026}'));
            assert_eq!(cut.len(), 8192 + 3);
            // Here byte 8,192 lies inside a character of two bytes: the cut is before it.
            let shifted = format!("a{wide}");
            let event = provider_request("r", "x", "GET", "h", "/", &shifted, b"", "", true);
            let cut = event["query"].as_str().unwrap();
            assert_eq!(cut.len(), 8191 + 3);
            assert_eq!(cut, format!("a{}\u{2026}", "é".repeat(4095)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_store_drops_expired_entries_first_and_then_the_first_inserted() {
        let mut store: Expiring<&str, u32> = Expiring::new();
        // Three entries in the same millisecond: insertion order decides.
        store.insert("a", 1, 100, 0, 3);
        store.insert("b", 2, 100, 0, 3);
        store.insert("c", 3, 100, 0, 3);
        store.insert("d", 4, 100, 0, 3);
        assert_eq!(store.take("a", 0), None);
        assert_eq!(store.take("b", 0), Some(2));
        // A value is used once.
        assert_eq!(store.take("b", 0), None);
        // An entry past its time is not returned.
        assert_eq!(store.take("c", 100), None);
        assert_eq!(store.take("d", 99), Some(4));

        // Expired entries make room before any live entry is dropped.
        let mut store: Expiring<&str, u32> = Expiring::new();
        store.insert("live", 1, 1_000, 0, 2);
        store.insert("stale", 2, 10, 0, 2);
        store.insert("new", 3, 1_000, 50, 2);
        assert_eq!(store.take("live", 60), Some(1));
        assert_eq!(store.take("new", 60), Some(3));
        assert_eq!(store.take("stale", 5), None);
    }

    #[test]
    fn an_expired_grant_loses_its_key_and_stays_expired() {
        let counters = Arc::new(StateCounters::default());
        let mut account = Account::new(counters.clone());
        account.set_grant(GrantState::Active(ActiveGrant {
            key_id: "0123456789abcdef".to_string(),
            sign_pk: [1; 32],
            log_pk: [2; 32],
            custody: Custody::Operator,
            user_key: Secret::new([3; 32]),
            not_after_ms: 1_000,
            exported_to: Vec::new(),
        }));
        assert_eq!(counters.grants.load(Ordering::Relaxed), 1);
        // Within its time the grant is handed out.
        let view = account.active(999).unwrap();
        assert_eq!(view.user_key.expose_secret(), &[3u8; 32]);
        assert_eq!(view.custody, Custody::Operator);
        assert!(account.has_grant(999));
        assert_eq!(account.status(999).state, "active");
        assert_eq!(account.status(999).custody, "operator");

        // At `not_after_ms` the grant ends: the state keeps the key_id and the expiry only,
        // and the count of the grants within their time goes down.
        assert_eq!(
            account.active(1_000).map(|_| ()),
            Err(ProtocolError::GrantExpired)
        );
        assert!(matches!(
            account.grant(),
            GrantState::Expired { key_id, not_after_ms: 1_000 } if key_id == "0123456789abcdef"
        ));
        assert_eq!(counters.grants.load(Ordering::Relaxed), 0);
        // A reading before the expiry does not bring it back (node time does not decrease, and
        // the user key is gone in any case).
        assert_eq!(
            account.active(500).map(|_| ()),
            Err(ProtocolError::GrantExpired)
        );
        assert!(!account.has_grant(500));
        let status = account.status(500);
        assert_eq!(
            (status.state, status.custody, status.not_after_ms),
            ("expired", "", 1_000)
        );
        assert_eq!(status.for_messages(), GrantStatus::none());

        // Dropping the grant (`grants/prune`) leaves no state of it; a revocation marker stays.
        assert!(account.drop_grant());
        assert!(matches!(account.grant(), GrantState::None));
        assert!(!account.drop_grant());
        account.set_grant(GrantState::Revoked {
            key_id: "0123456789abcdef".to_string(),
            sign_pk: [1; 32],
        });
        assert!(!account.drop_grant());
        assert!(matches!(account.grant(), GrantState::Revoked { .. }));
        assert_eq!(counters.grants.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn an_account_keeps_the_sixteen_most_recent_refresh_responses_of_its_grant() {
        use credential_enclave_protocol::record;
        let user_key = Secret::new([3; 32]);
        let grant = |sign_pk: [u8; 32]| GrantView {
            key_id: "0123456789abcdef".to_string(),
            sign_pk,
            log_pk: [2; 32],
            custody: Custody::Operator,
            user_key: user_key.clone(),
            revoke_serial: 0,
        };
        let counters = Arc::new(StateCounters::default());
        let mut account = Account::new(counters.clone());
        account.set_grant(GrantState::Active(ActiveGrant {
            key_id: "0123456789abcdef".to_string(),
            sign_pk: [1; 32],
            log_pk: [2; 32],
            custody: Custody::Operator,
            user_key: user_key.clone(),
            not_after_ms: 10_000_000,
            exported_to: Vec::new(),
        }));
        let response = |index: u8| {
            let sealed = record::seal(
                &user_key,
                &[index; 16],
                &[index; 12],
                "user-1",
                "0123456789abcdef",
                Custody::Operator,
                Kind::Oauth,
                "x",
                &Secret::new(b"{}".to_vec()),
            );
            (refresh_key(&sealed), sealed)
        };
        let log = crate::api::responses::LogRef {
            seq: 1,
            index: 0,
            created: true,
        };
        let body = |sealed: Record| {
            crate::api::responses::Refreshed {
                record: sealed,
                public: crate::oauth::tests::empty_public_fields(),
                log,
            }
            .body()
        };
        // Every body of this test has the same length: the bytes the node counts for one.
        let counted = kept_refresh_bytes("user-1", &body(response(0).1));
        assert_eq!(
            counted,
            (body(response(0).1).bytes() + 6) * 5 / 4 + REFRESH_KEPT_ENTRY_BYTES
        );
        let sum = || lock(&counters.kept_order).bytes();
        let keys: Vec<[u8; 32]> = (0..17u8)
            .map(|index| {
                let (key, sealed) = response(index);
                assert!(account.keep_refresh(
                    &grant([1; 32]),
                    "user-1",
                    key,
                    1_000 + u64::from(index),
                    body(sealed),
                ));
                // The list of the account holds room for the responses it has and no more,
                // and the order of the node holds their sum.
                let kept = usize::from(index + 1).min(REFRESH_KEPT_ENTRIES);
                assert_eq!(account.rooms().1, kept);
                assert_eq!(sum(), kept * counted);
                key
            })
            .collect();
        // The first of seventeen made room for the last, and the count of the node follows.
        assert_eq!(counters.kept_refreshes.load(Ordering::Relaxed), 16);
        assert!(account.kept_refresh(&keys[0], 2_000).is_none());
        for key in &keys[1..] {
            assert!(account.kept_refresh(key, 2_000).is_some());
        }
        // The response of a record that is kept again takes the place of the earlier one.
        let (key, sealed) = response(5);
        assert!(account.keep_refresh(&grant([1; 32]), "user-1", key, 1_005, body(sealed)));
        assert_eq!(counters.kept_refreshes.load(Ordering::Relaxed), 16);
        assert_eq!(sum(), 16 * counted);
        // A response is kept for 3,600 seconds.
        assert!(account
            .kept_refresh(&keys[1], 1_001 + REFRESH_KEPT_MS - 1)
            .is_some());
        assert!(account
            .kept_refresh(&keys[1], 1_001 + REFRESH_KEPT_MS)
            .is_none());
        assert!(account
            .kept_refresh(&keys[16], 1_001 + REFRESH_KEPT_MS)
            .is_some());
        assert_eq!(counters.kept_refreshes.load(Ordering::Relaxed), 15);
        assert_eq!((account.rooms().1, sum()), (15, 15 * counted));
        // A response of a grant that is no longer in force is not kept.
        let (key, sealed) = response(40);
        assert!(!account.keep_refresh(&grant([9; 32]), "user-1", key, 3_000, body(sealed)));
        assert!(account.kept_refresh(&key, 3_000).is_none());
        assert_eq!(sum(), 15 * counted);
        // The end of the grant drops what was kept.
        account.expire(10_000_000);
        assert!(account.kept_refresh(&keys[16], 3_000).is_none());
        assert_eq!(counters.kept_refreshes.load(Ordering::Relaxed), 0);
        assert_eq!((account.rooms().1, sum()), (0, 0));
    }

    #[test]
    fn the_merge_keys_of_an_account_are_dropped_when_their_window_passed() {
        let counters = Arc::new(StateCounters::default());
        let mut account = Account::new(counters.clone());
        let place = |index: u32| EventPlace::Entry { seq: 1, index };
        account.remember_event(
            [1u8; 32],
            Recent {
                entry_ms: 1_000,
                target: place(0),
            },
        );
        account.remember_event(
            [2u8; 32],
            Recent {
                entry_ms: 200_000,
                target: place(1),
            },
        );
        assert_eq!(counters.merge_keys.load(Ordering::Relaxed), 2);
        // At the end of the window of the first key it is dropped and the second one stays.
        account.prune_recent(1_000 + limits::MERGE_WINDOW_S * 1000);
        assert!(account.shared_event(&[1u8; 32]).is_none());
        assert!(account.shared_event(&[2u8; 32]).is_some());
        assert_eq!(counters.merge_keys.load(Ordering::Relaxed), 1);
        account.prune_recent(200_000 + limits::MERGE_WINDOW_S * 1000 - 1);
        assert!(account.shared_event(&[2u8; 32]).is_some());
        account.prune_recent(200_000 + limits::MERGE_WINDOW_S * 1000);
        assert!(account.shared_event(&[2u8; 32]).is_none());
        assert_eq!(account.merge_key_count(), 0);
        assert_eq!(counters.merge_keys.load(Ordering::Relaxed), 0);
    }

    /// Remembers the merge key number `index`, of an event created at `entry_ms`.
    fn remember(account: &mut Account, index: u32, entry_ms: u64) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(&index.to_le_bytes());
        account.remember_event(
            key,
            Recent {
                entry_ms,
                target: EventPlace::Entry { seq: 1, index },
            },
        );
        key
    }

    #[test]
    fn the_merge_key_table_gives_back_the_memory_of_the_keys_it_drops() {
        let window_ms = limits::MERGE_WINDOW_S * 1000;
        let counters = Arc::new(StateCounters::default());
        let mut account = Account::new(counters.clone());
        let room = |account: &Account| account.rooms().0;
        // An account without a merge key holds no table.
        assert_eq!(room(&account), 0);

        // 4,096 keys of one moment, and eight keys one second later.
        for index in 0..4_096 {
            remember(&mut account, index, 1_000);
        }
        let late: Vec<[u8; 32]> = (4_096..4_104)
            .map(|index| remember(&mut account, index, 2_000))
            .collect();
        let grown = room(&account);
        assert!(grown >= 4_104, "{grown}");
        assert!(account.remembers_more(4_105) && !account.remembers_more(4_104));
        // A look that drops no key moves no memory.
        account.prune_recent(1_000 + window_ms - 1);
        assert_eq!((account.merge_key_count(), room(&account)), (4_104, grown));

        // The window of the 4,096 keys passed: the table keeps the eight others, and shrinks
        // to room for twice their number and for little more. Before this rule the table kept
        // the room of the 4,104 keys for as long as the node lived.
        account.prune_recent(1_000 + window_ms);
        assert_eq!(account.merge_key_count(), 8);
        let kept = room(&account);
        assert!((16..=64).contains(&kept), "{kept}");
        for key in &late {
            assert!(account.shared_event(key).is_some());
        }
        assert_eq!(counters.merge_keys.load(Ordering::Relaxed), 8);

        // The window of the last keys passed: the table holds no memory.
        account.prune_recent(2_000 + window_ms);
        assert_eq!((account.merge_key_count(), room(&account)), (0, 0));
        assert_eq!(counters.merge_keys.load(Ordering::Relaxed), 0);

        // The keys of a grant that ended go with their memory, before their window passed.
        for index in 0..4_096 {
            remember(&mut account, index, 3_000);
        }
        assert!(room(&account) >= 4_096);
        account.clear_recent();
        assert_eq!((account.merge_key_count(), room(&account)), (0, 0));
        assert_eq!(counters.merge_keys.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn the_merge_key_separates_the_parts_of_an_address() {
        let id = [1u8; 16];
        assert_ne!(
            merge_key(&id, "h", "/a", "b"),
            merge_key(&id, "h", "/ab", "")
        );
        assert_ne!(merge_key(&id, "h", "/a", ""), merge_key(&id, "h/a", "", ""));
        assert_ne!(
            merge_key(&id, "h", "/a", "b"),
            merge_key(&[2u8; 16], "h", "/a", "b")
        );
        assert_eq!(
            merge_key(&id, "h", "/a", "b"),
            merge_key(&id, "h", "/a", "b")
        );
    }

    #[test]
    fn a_panic_under_the_lock_of_an_account_halts_it_at_the_next_lock() {
        use crate::testing::{quiet_panics, ScriptedFault};
        quiet_panics();
        let grant = || {
            GrantState::Active(ActiveGrant {
                key_id: "0123456789abcdef".to_string(),
                sign_pk: [1; 32],
                log_pk: [2; 32],
                custody: Custody::Operator,
                user_key: Secret::new([3; 32]),
                not_after_ms: 10_000,
                exported_to: Vec::new(),
            })
        };
        let counters = Arc::new(StateCounters::default());
        let account = Arc::new(AccountLock::new(Account::new(counters.clone())));
        // An account with everything a call leaves in its state: a grant, an entry the store
        // has not confirmed, an event in the open batch, a merge key.
        let batch = {
            let mut state = lock(&account);
            state.set_grant(grant());
            state.last = Last {
                seq: 2,
                body_hash: [7; 32],
            };
            state.push_unconfirmed(Unconfirmed {
                seq: 2,
                key: "a3/user-1/u/key".to_string(),
                shard: 0,
                entry: Signed {
                    body: String::new(),
                    sig: String::new(),
                },
                writers: 0,
                pending_since_ms: 5,
            });
            state
                .open
                .events
                .push(serde_json::json!({"t": "provider_request"}));
            counters.open_batches.fetch_add(1, Ordering::Relaxed);
            state.remember_event(
                [4; 32],
                Recent {
                    entry_ms: 5,
                    target: EventPlace::Entry { seq: 2, index: 0 },
                },
            );
            state.writer = true;
            assert!(state.is_confirmed(1) && !state.is_confirmed(2));
            assert_eq!(state.active(9).map(|_| ()), Ok(()));
            state.open.seq.clone()
        };
        let count = |counter: &AtomicUsize| counter.load(Ordering::Relaxed);
        assert_eq!(
            [
                &counters.grants,
                &counters.pending_accounts,
                &counters.pending_entries,
                &counters.open_batches,
                &counters.merge_keys,
                &counters.halted,
            ]
            .map(count),
            [1, 1, 1, 1, 1, 0]
        );

        // A thread panics while it holds the lock of the account.
        let held = account.clone();
        let panicked = std::thread::spawn(move || {
            let _state = lock(&held);
            std::panic::panic_any(ScriptedFault);
        })
        .join();
        assert!(panicked.is_err());

        // The next lock finds the account halted: the grant and its key are gone, no entry
        // counts as confirmed, the batch of the events that waited names no entry, and the
        // counts of the node follow.
        let mut state = lock(&account);
        assert!(state.is_halted());
        assert!(matches!(state.grant(), GrantState::None));
        assert_eq!(
            [1, 2, 3].map(|seq| state.is_confirmed(seq)),
            [false, false, false]
        );
        assert_eq!(batch.get(), Some(&0));
        assert!(!state.writer && !state.has_open_events());
        assert_eq!((state.pending_entries(), state.merge_key_count()), (0, 0));
        assert_eq!(
            [
                &counters.grants,
                &counters.pending_accounts,
                &counters.pending_entries,
                &counters.open_batches,
                &counters.merge_keys,
                &counters.halted,
            ]
            .map(count),
            [0, 0, 0, 0, 0, 1]
        );
        // What the node created for the account stays as it was: the node reads none of it.
        assert_eq!(state.last.seq, 2);

        // A call that needs the state ends with `internal`, and the account takes no grant.
        assert_eq!(state.ensure_usable(), Err(ProtocolError::Internal));
        assert_eq!(state.active(9).map(|_| ()), Err(ProtocolError::Internal));
        state.set_grant(grant());
        assert!(matches!(state.grant(), GrantState::None));
        assert!(!state.has_grant(9));
        assert_eq!(state.status(9), GrantStatus::none());
        assert_eq!(count(&counters.grants), 0);
        drop(state);
        // An account is halted once.
        assert!(lock(&account).is_halted());
        assert_eq!(count(&counters.halted), 1);
    }
}
