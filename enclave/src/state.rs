//! The state of a node (enclave.md section 3). Everything lives in memory: a node writes
//! nothing to disk and shares no state with other nodes.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Duration;

use credential_enclave_protocol::encoding::{b64u, b64u_decode, Signed};
use credential_enclave_protocol::keys::{binding, Custody, LogStoreId, NodeKeys};
use credential_enclave_protocol::log::{self, Head};
use credential_enclave_protocol::record::{self, Kind, Record};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::{limits, ProtocolError};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::api::responses::Refreshed;
use crate::api::ApiError;
use crate::clock::Clock;
use crate::egress::Egress;
use crate::log_store::LogStore;
use crate::oauth::PkceVerifier;
use crate::platform::{PlatformError, SharedPlatform};
use crate::providers::Definitions;

/// How long a node keeps the response of a successful `refresh` for a repeated call with the
/// same record: 3,600 seconds.
pub const REFRESH_KEPT_MS: u64 = 3_600 * 1000;
/// The responses of `refresh` a node keeps per account: the most recent 16.
pub const REFRESH_KEPT_ENTRIES: usize = 16;

/// The capacities of a node (enclave.md sections 3 and 8).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Body limit of a provider request and of a provider response.
    pub body_bytes: usize,
    /// Sum of the bodies that may be in memory at the same time. A call that would exceed it
    /// waits.
    pub body_budget_bytes: usize,
    /// `forward` calls that run at the same time.
    pub forward_concurrency: usize,
    /// Challenges a node keeps.
    pub challenges: usize,
    /// Pending authorizations a node keeps.
    pub pending: usize,
    /// Longest write of one entry to the log store: the connection, the TLS handshake and
    /// the exchange.
    pub log_write: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            body_bytes: limits::BODY_BYTES,
            body_budget_bytes: 2 * 1024 * 1024 * 1024,
            forward_concurrency: 64,
            challenges: 100_000,
            pending: 100_000,
            log_write: Duration::from_secs(5),
        }
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
    /// The nodes this grant was handed to (`peer/export`), at most 64. The entry
    /// `grant_transferred_out` that names a node of this list is on the chain, so a repeated
    /// transfer to it creates none. A grant command, a revoke, the end of the grant and a
    /// transfer this node takes put a new state in place, and a new grant state starts with
    /// an empty list (protocol.md 10.1).
    pub exported_to: Vec<Handover>,
}

/// One node a grant was handed to, and the entry that says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handover {
    /// The signing public key of the receiving node.
    pub peer: [u8; 32],
    /// The `seq` of the entry `grant_transferred_out` that names it. The grant enters a
    /// transfer to that node only when the log store confirmed this entry.
    pub seq: u64,
}

impl ActiveGrant {
    /// The entry that says that this grant was handed to `peer`, when it was.
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

/// A log entry that waits for its storage acknowledgement.
pub struct Entry {
    pub seq: u64,
    pub signed: Signed,
}

/// A log entry that the log store has not confirmed (protocol.md 7.6).
pub struct Unconfirmed {
    pub seq: u64,
    /// The chain hash of the entry: the last part of its key in the log store.
    pub hash: [u8; 32],
    pub entry: Signed,
    /// True while a call writes the entry: the call that created it, or a later call that
    /// took it along. An entry no call writes is a pending entry: the next write of the
    /// account takes it along.
    pub writing: bool,
}

/// The entry of an identical GET request that later ones share (protocol.md 7.2).
#[derive(Clone, Copy)]
pub struct Recent {
    /// The time of the entry.
    pub entry_ms: u64,
    /// The `seq` of the entry. A request shares the entry only once the log store confirmed
    /// it.
    pub seq: u64,
}

/// The response of a successful `refresh`, kept for a repeated call with the same record. It
/// holds what the response held: a record (ciphertext), public fields and a log entry.
struct KeptRefresh {
    /// The hash of the `ct` of the record the call sent.
    key: [u8; 32],
    kept_ms: u64,
    response: Refreshed,
}

/// The key under which the response of a `refresh` is kept: `SHA-256(the ct of the record that
/// was sent)`.
pub fn refresh_key(record: &Record) -> [u8; 32] {
    Sha256::digest(record.ct.as_bytes()).into()
}

/// The state of one account on this node.
pub struct Account {
    pub grant: GrantState,
    /// The end of the (node, account) chain.
    pub head: Head,
    /// Entries without a storage acknowledgement.
    pub unacked: VecDeque<Entry>,
    /// Entries the log store has not confirmed, in the order of their `seq`. Empty on a node
    /// that runs without a log store.
    pub unconfirmed: Vec<Unconfirmed>,
    /// Merge key to its entry: identical GET requests of `forward` that have no body. Kept
    /// for 300 seconds.
    pub recent: HashMap<[u8; 32], Recent>,
    /// The `final` head, once the orderly shutdown created it.
    pub final_head: Option<Signed>,
    /// The responses of the successful `refresh` calls of the last 3,600 seconds, at most 16.
    /// A revoke, an expiry and a grant of another key drop them.
    kept_refreshes: VecDeque<KeptRefresh>,
    /// The `time_ms` of the last entry of the chain. An entry is never dated before the entry
    /// in front of it.
    last_entry_ms: u64,
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
}

impl Account {
    fn new() -> Account {
        Account {
            grant: GrantState::None,
            head: Head::EMPTY,
            unacked: VecDeque::new(),
            unconfirmed: Vec::new(),
            recent: HashMap::new(),
            final_head: None,
            kept_refreshes: VecDeque::new(),
            last_entry_ms: 0,
            revoked_here: false,
            revoke_serial: 0,
        }
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
        // Replacing the state drops the grant, which overwrites its user key with zeros.
        self.grant = expired;
        self.kept_refreshes.clear();
    }

    /// The kept response of a `refresh` of the record with this key, when it was kept less
    /// than 3,600 seconds ago.
    pub fn kept_refresh(&mut self, key: &[u8; 32], now_ms: u64) -> Option<&Refreshed> {
        self.kept_refreshes
            .retain(|kept| now_ms < kept.kept_ms.saturating_add(REFRESH_KEPT_MS));
        self.kept_refreshes
            .iter()
            .find(|kept| &kept.key == key)
            .map(|kept| &kept.response)
    }

    /// Keeps the response of a successful `refresh` that ran under `grant`. Nothing is kept
    /// when that grant is no longer in force: a revoke that was answered while the provider
    /// call ran leaves no kept response behind it.
    pub fn keep_refresh(
        &mut self,
        grant: &GrantView,
        key: [u8; 32],
        now_ms: u64,
        response: Refreshed,
    ) {
        self.expire(now_ms);
        let in_force = matches!(
            &self.grant,
            GrantState::Active(active) if active.sign_pk == grant.sign_pk
        );
        if !in_force {
            return;
        }
        self.kept_refreshes.retain(|kept| kept.key != key);
        while self.kept_refreshes.len() >= REFRESH_KEPT_ENTRIES {
            self.kept_refreshes.pop_front();
        }
        self.kept_refreshes.push_back(KeptRefresh {
            key,
            kept_ms: now_ms,
            response,
        });
    }

    /// Drops the kept `refresh` responses: the delegation they were made under ended.
    pub fn forget_refreshes(&mut self) {
        self.kept_refreshes.clear();
    }

    /// Step 4 of the common front: the grant is active and within its time.
    pub fn active(&mut self, now_ms: u64) -> Result<GrantView, ProtocolError> {
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
            }),
        }
    }

    /// Step 5 of the common front: fewer than 64 entries wait for an acknowledgement.
    pub fn ensure_capacity(&self) -> Result<(), ProtocolError> {
        if self.unacked.len() >= limits::UNACKED_ENTRIES {
            return Err(ProtocolError::LogBacklog);
        }
        Ok(())
    }

    /// True when the log store confirmed the entry `seq`. On a node that runs without a log
    /// store every entry counts as confirmed: such a node keeps no account of it.
    pub fn is_confirmed(&self, seq: u64) -> bool {
        !self.unconfirmed.iter().any(|entry| entry.seq == seq)
    }

    /// The number of pending entries: entries that the log store has not confirmed and that
    /// no call writes at this moment.
    pub fn pending_entries(&self) -> usize {
        self.unconfirmed
            .iter()
            .filter(|entry| !entry.writing)
            .count()
    }

    /// Leaves the entry `seq` to the next write of the account: the call that created it does
    /// not write it itself (`peer/import`).
    pub fn leave_pending(&mut self, seq: u64) {
        if let Some(entry) = self.unconfirmed.iter_mut().find(|entry| entry.seq == seq) {
            entry.writing = false;
        }
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
    pub started_ms: u64,
    pub closing: AtomicBool,
    pub config: RwLock<Option<Arc<OperatorConfig>>>,
    /// The log store of this node and the credentials for it (`crate::log_store`).
    pub log_store: LogStore,
    /// The challenges this node issued, each with the serial it was issued under. Removed
    /// after 300 seconds or on use.
    challenges: Mutex<Expiring<[u8; 16], u64>>,
    /// The next serial of this node: one count, starting at 1, for the challenges the node
    /// issues and the revoke commands it accepts. It says which of the two came first.
    serials: AtomicU64,
    /// `user_id` to account state. Each account has its own lock.
    accounts: RwLock<HashMap<String, Arc<Mutex<Account>>>>,
    /// `node_state` to the authorization in progress. Removed after 600 seconds or on use.
    pending: Mutex<Expiring<String, PendingAuth>>,
    /// The number of accounts that have a chain.
    chains: AtomicUsize,
    pub platform: SharedPlatform,
    pub clock: Arc<Clock>,
    pub definitions: Definitions,
    pub egress: Egress,
    pub limits: Limits,
    pub forward_slots: Semaphore,
    pub body_budget: Arc<Semaphore>,
}

/// Locks a mutex. A poisoned lock is used as it is: the release build aborts on a panic, so a
/// poisoned lock exists in tests only.
pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Node {
    /// Creates the node keys and an empty state.
    pub fn start(
        platform: SharedPlatform,
        clock: Arc<Clock>,
        definitions: Definitions,
        egress: Egress,
        release: &'static str,
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
        Ok(Node {
            node: keys.node(),
            keys,
            custody,
            release,
            started_ms: clock.now_ms(),
            closing: AtomicBool::new(false),
            config: RwLock::new(None),
            // A node of the nitro platform does not act without a log store.
            log_store: LogStore::new(platform.name() == "nitro"),
            challenges: Mutex::new(Expiring::new()),
            serials: AtomicU64::new(1),
            accounts: RwLock::new(HashMap::new()),
            pending: Mutex::new(Expiring::new()),
            chains: AtomicUsize::new(0),
            platform,
            clock,
            definitions,
            egress,
            forward_slots: Semaphore::new(limits.forward_concurrency),
            body_budget: Arc::new(Semaphore::new(limits.body_budget_bytes)),
            limits,
        })
    }

    /// The node time in Unix epoch milliseconds.
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
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
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or(ProtocolError::NotConfigured)
    }

    /// True when the operator configuration is present.
    pub fn is_configured(&self) -> bool {
        self.config
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Replaces the operator configuration.
    pub fn set_config(&self, config: OperatorConfig) {
        *self.config.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(config));
    }

    /// True when the platform accepts a callback address on `http://localhost` (enclave.md
    /// 5.1): the local platform only.
    pub fn accepts_localhost_redirect(&self) -> bool {
        self.platform.name() == "local"
    }

    /// The state of an account, when it has one.
    pub fn account(&self, user_id: &str) -> Option<Arc<Mutex<Account>>> {
        self.accounts
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(user_id)
            .cloned()
    }

    /// The state of an account, created when it has none.
    pub fn account_or_create(&self, user_id: &str) -> Arc<Mutex<Account>> {
        if let Some(account) = self.account(user_id) {
            return account;
        }
        self.accounts
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(user_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(Account::new())))
            .clone()
    }

    /// The accounts that have a chain, sorted by `user_id`.
    pub fn accounts_with_chain(&self) -> Vec<(String, Arc<Mutex<Account>>)> {
        let mut accounts: Vec<(String, Arc<Mutex<Account>>)> = self
            .accounts
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(_, account)| lock(account).head.seq > 0)
            .map(|(user_id, account)| (user_id.clone(), account.clone()))
            .collect();
        accounts.sort_by(|left, right| left.0.cmp(&right.0));
        accounts
    }

    /// The accounts whose `user_id` sorts after `after`, sorted by `user_id`. An empty `after`
    /// selects every account.
    pub fn accounts_after(&self, after: &str) -> Vec<(String, Arc<Mutex<Account>>)> {
        let mut accounts: Vec<(String, Arc<Mutex<Account>>)> = self
            .accounts
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(user_id, _)| after.is_empty() || user_id.as_str() > after)
            .map(|(user_id, account)| (user_id.clone(), account.clone()))
            .collect();
        accounts.sort_by(|left, right| left.0.cmp(&right.0));
        accounts
    }

    /// The number of accounts that have a chain.
    pub fn account_count(&self) -> usize {
        self.chains.load(Ordering::SeqCst)
    }

    /// The binding of this node (protocol.md 4.1): its two public keys, its release and, when
    /// it has one, its log store.
    pub fn binding(&self) -> Vec<u8> {
        binding(&self.keys, self.release, self.log_store.id())
    }

    /// The number of accounts that have a pending entry: an entry the log store has not
    /// confirmed and no call writes at this moment.
    pub fn pending_count(&self) -> usize {
        let accounts: Vec<Arc<Mutex<Account>>> = self
            .accounts
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        accounts
            .iter()
            .filter(|account| lock(account).pending_entries() > 0)
            .count()
    }

    /// The number of accounts that have a grant within its time. Reading the state of an
    /// account ends a grant whose time passed.
    pub fn grant_count(&self) -> usize {
        let accounts: Vec<Arc<Mutex<Account>>> = self
            .accounts
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        let now_ms = self.now_ms();
        accounts
            .iter()
            .filter(|account| lock(account).has_grant(now_ms))
            .count()
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

    /// Creates the next entry of an account chain and raises the end of the chain. The caller
    /// holds the account lock, so one chain never forks. `key_id` and `log_pk` are those of the
    /// grant in force at this moment.
    ///
    /// On a node with a log store the entry starts as one its call writes: the call confirms
    /// it with `log_store::confirm` before the act the entry describes, or leaves it to the
    /// next write of the account ([`Account::leave_pending`]). The `seq` of the entry is the
    /// `seq` of the end of the chain when this function returns.
    pub fn append_entry(
        &self,
        account: &mut Account,
        user_id: &str,
        key_id: &str,
        log_pk: &[u8; 32],
        time_ms: u64,
        event: &serde_json::Value,
    ) -> Result<Signed, ApiError> {
        let seed = self.random_secret::<32>()?;
        Ok(self.append_entry_seeded(account, user_id, key_id, log_pk, time_ms, event, &seed))
    }

    /// [`Node::append_entry`] with the HPKE seed of the entry drawn by the caller. A call that
    /// creates entries on several chains draws every seed first, so a failure of the random
    /// source leaves every chain as it was.
    ///
    /// The `time_ms` of the entry is `time_ms`, or the time of the entry in front of it when
    /// that one is later: a caller may have read the node time before it took the account
    /// lock, and the times of one chain do not decrease with `seq` (enclave.md section 8).
    #[allow(clippy::too_many_arguments)]
    pub fn append_entry_seeded(
        &self,
        account: &mut Account,
        user_id: &str,
        key_id: &str,
        log_pk: &[u8; 32],
        time_ms: u64,
        event: &serde_json::Value,
        seed: &Secret<[u8; 32]>,
    ) -> Signed {
        let time_ms = time_ms.max(account.last_entry_ms);
        account.last_entry_ms = time_ms;
        let (signed, head) = log::append(
            &self.keys,
            &account.head,
            user_id,
            key_id,
            log_pk,
            time_ms,
            event,
            seed,
        );
        if account.head.seq == 0 {
            self.chains.fetch_add(1, Ordering::SeqCst);
        }
        account.head = head;
        account.unacked.push_back(Entry {
            seq: head.seq,
            signed: signed.clone(),
        });
        if self.log_store.tracks() {
            account.unconfirmed.push(Unconfirmed {
                seq: head.seq,
                hash: head.hash,
                entry: signed.clone(),
                writing: true,
            });
        }
        signed
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
/// of that table.
///
/// An event holds no secret. Its values are identifiers, addresses, the hash of a request body
/// and the context string of the caller, and a scope string that passed the public field rule.
/// No function here takes a secret type.
pub mod events {
    use super::{b64u, limits, Custody, Digest, Sha256};
    use serde_json::{json, Value};

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
        format!("{}\u{2026}", &text[..end])
    }

    /// `not_after_ms` is the expiry the node accepted, which can be earlier than the one the
    /// command asked for.
    pub fn grant_accepted(not_after_ms: u64, custody: Custody) -> Value {
        json!({
            "t": "grant_accepted",
            "not_after_ms": not_after_ms,
            "custody": custody.as_str(),
        })
    }

    pub fn grant_revoked() -> Value {
        json!({"t": "grant_revoked"})
    }

    pub fn connection_created(record_id: &str, provider: &str, scope: &str) -> Value {
        json!({
            "t": "connection_created",
            "record_id": record_id,
            "provider": provider,
            "scope": scope,
        })
    }

    pub fn credential_refreshed(record_id: &str, provider: &str) -> Value {
        json!({"t": "credential_refreshed", "record_id": record_id, "provider": provider})
    }

    /// `provider_revoke` says whether the node calls the revocation address of the provider
    /// after this entry. The entry is created before that call, so it cannot carry its outcome.
    pub fn connection_removed(record_id: &str, provider: &str, provider_revoke: bool) -> Value {
        json!({
            "t": "connection_removed",
            "record_id": record_id,
            "provider": provider,
            "provider_revoke": provider_revoke,
        })
    }

    /// `to` is the node the delegation was sealed for. A node identifier is that node's
    /// signing public key, so the account can verify the entries of the receiving node with
    /// this value.
    pub fn grant_transferred_out(to: &str) -> Value {
        json!({"t": "grant_transferred_out", "to": to})
    }

    /// `from` is the node that gave the delegation. `not_after_ms` is the end the receiving
    /// node accepted.
    pub fn grant_transferred_in(from: &str, not_after_ms: u64, custody: Custody) -> Value {
        json!({
            "t": "grant_transferred_in",
            "from": from,
            "not_after_ms": not_after_ms,
            "custody": custody.as_str(),
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
        if mergeable {
            event["window_s"] = json!(limits::MERGE_WINDOW_S);
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
                r#"{"t":"grant_accepted","not_after_ms":9,"custody":"enclave"}"#
            );
            assert_eq!(
                text(&grant_accepted(9, Custody::Operator)),
                r#"{"t":"grant_accepted","not_after_ms":9,"custody":"operator"}"#
            );
            assert_eq!(text(&grant_revoked()), r#"{"t":"grant_revoked"}"#);
            assert_eq!(
                text(&connection_created("r", "slack", "chat:write")),
                r#"{"t":"connection_created","record_id":"r","provider":"slack","scope":"chat:write"}"#
            );
            assert_eq!(
                text(&credential_refreshed("r", "x")),
                r#"{"t":"credential_refreshed","record_id":"r","provider":"x"}"#
            );
            assert_eq!(
                text(&connection_removed("r", "x", true)),
                r#"{"t":"connection_removed","record_id":"r","provider":"x","provider_revoke":true}"#
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
                    r#"{"t":"secret_released","record_id":"r","kind":"vault_card","field":"card_cvc","#,
                    r#""origin":"https://a.example","context":"browser:fill"}"#
                )
            );
            assert_eq!(
                text(&totp_issued("r", "https://a.example", "browser:fill")),
                r#"{"t":"totp_issued","record_id":"r","origin":"https://a.example","context":"browser:fill"}"#
            );
            assert_eq!(
                text(&grant_transferred_out("NODE-B")),
                r#"{"t":"grant_transferred_out","to":"NODE-B"}"#
            );
            assert_eq!(
                text(&grant_transferred_in("NODE-A", 9, Custody::Enclave)),
                r#"{"t":"grant_transferred_in","from":"NODE-A","not_after_ms":9,"custody":"enclave"}"#
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
                    r#"{"t":"provider_request","record_id":"r","provider":"x","method":"GET","#,
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
        let mut account = Account::new();
        account.grant = GrantState::Active(ActiveGrant {
            key_id: "0123456789abcdef".to_string(),
            sign_pk: [1; 32],
            log_pk: [2; 32],
            custody: Custody::Operator,
            user_key: Secret::new([3; 32]),
            not_after_ms: 1_000,
            exported_to: Vec::new(),
        });
        // Within its time the grant is handed out.
        let view = account.active(999).unwrap();
        assert_eq!(view.user_key.expose_secret(), &[3u8; 32]);
        assert_eq!(view.custody, Custody::Operator);
        assert!(account.has_grant(999));
        assert_eq!(account.status(999).state, "active");
        assert_eq!(account.status(999).custody, "operator");

        // At `not_after_ms` the grant ends: the state keeps the key_id and the expiry only.
        assert_eq!(
            account.active(1_000).map(|_| ()),
            Err(ProtocolError::GrantExpired)
        );
        assert!(matches!(
            &account.grant,
            GrantState::Expired { key_id, not_after_ms: 1_000 } if key_id == "0123456789abcdef"
        ));
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
        };
        let mut account = Account::new();
        account.grant = GrantState::Active(ActiveGrant {
            key_id: "0123456789abcdef".to_string(),
            sign_pk: [1; 32],
            log_pk: [2; 32],
            custody: Custody::Operator,
            user_key: user_key.clone(),
            not_after_ms: 10_000_000,
            exported_to: Vec::new(),
        });
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
        let keys: Vec<[u8; 32]> = (0..17u8)
            .map(|index| {
                let (key, sealed) = response(index);
                let entry = Signed {
                    body: String::new(),
                    sig: String::new(),
                };
                let public = crate::oauth::tests::empty_public_fields();
                account.keep_refresh(
                    &grant([1; 32]),
                    key,
                    1_000 + u64::from(index),
                    Refreshed {
                        record: sealed,
                        public,
                        entry,
                    },
                );
                key
            })
            .collect();
        // The first of seventeen made room for the last.
        assert!(account.kept_refresh(&keys[0], 2_000).is_none());
        for key in &keys[1..] {
            assert!(account.kept_refresh(key, 2_000).is_some());
        }
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
        // A response of a grant that is no longer in force is not kept.
        let (key, sealed) = response(40);
        account.keep_refresh(
            &grant([9; 32]),
            key,
            3_000,
            Refreshed {
                record: sealed,
                public: crate::oauth::tests::empty_public_fields(),
                entry: Signed {
                    body: String::new(),
                    sig: String::new(),
                },
            },
        );
        assert!(account.kept_refresh(&key, 3_000).is_none());
        // The end of the grant drops what was kept.
        account.expire(10_000_000);
        assert!(account.kept_refresh(&keys[16], 3_000).is_none());
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
}
