//! The authenticated IMAP sessions a node keeps between the reads of a record (enclave.md,
//! "Mail call surface").
//!
//! A read of a mailbox opens a connection to the IMAP server and logs in with the application
//! password of its record. When the read ends, the node keeps that session for the next read
//! of the same record, which then neither opens a connection nor logs in. What is kept is the
//! TLS connection the server accepted the password for: a kept session holds no byte of the
//! password.
//!
//! The sessions are kept here, beside the idle connections to the providers
//! (`Egress::mail_sessions`), and not in the state of an account: the state of an account
//! and the orderly shutdown do not know them. Three rules stand in for that knowledge.
//!
//! - A session is kept under the record it was authenticated with ([`SessionKey`]: the
//!   account, the `id` of the record and the SHA-256 of its ciphertext) and under the
//!   delegation its call ran under ([`Delegation`]: the signing public key of the grant and
//!   the revoke serial of the account). It is handed to a call of that record and of that
//!   delegation, and to no other: a call after a revoke runs under a larger revoke serial,
//!   and a call under the grant of another key under another signing public key.
//! - The call that takes a session, and the call that gives one back, look at the account at
//!   that moment (`api::mail`): a session is taken and kept only while the delegation is in
//!   force and the node is not closing.
//! - A session that carries no call ends [`SESSION_IDLE_MS`] after its last call, and
//!   [`SESSION_LOGIN_MS`] after its login at the latest, whether a call asks for it or not:
//!   a task of its own ends it. So a session of an account whose grant ended, which revoked,
//!   or whose node is closing, is held for the idle time at the longest and is used by no
//!   call in it.
//!
//! No session is taken before the log store confirmed the entry of the call that takes it:
//! the handover is a step of the act of that call (`api::mail`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use credential_enclave_protocol::record::Record;
use sha2::{Digest, Sha256};

use crate::api::responses::LogRef;
use crate::mail::ImapSession;
use crate::state::{lock, GrantView};

/// How long a session that carries no call is kept: 30 seconds, the idle time of a connection
/// to a provider.
pub(crate) const SESSION_IDLE_MS: u64 = 30_000;

/// How long after its login a session is handed to a call: 300 seconds. The server accepted
/// the application password of a call at most that long before the call, so a password the
/// account withdrew at the provider is of no use to the node after that time, also while
/// calls follow each other closely enough to keep the session from being idle.
pub(crate) const SESSION_LOGIN_MS: u64 = 300_000;

/// The sessions a node keeps at the same time. At the bound, the session that has carried no
/// call for the longest time ends for the one that comes. Every kept session holds one
/// descriptor of the node (`crate::descriptors`).
pub(crate) const KEPT_SESSIONS: usize = 1_024;

/// The record a session was authenticated with: the account, the `id` of the record, and the
/// SHA-256 of its `ct`. A record that opens under the user key of the account has the
/// plaintext its ciphertext holds, so two calls with the same key carry the same application
/// password.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SessionKey {
    user_id: String,
    record_id: String,
    ciphertext: [u8; 32],
}

impl SessionKey {
    /// The key of the record `record` of the account `user_id`.
    pub(crate) fn of(user_id: &str, record: &Record) -> SessionKey {
        SessionKey {
            user_id: user_id.to_string(),
            record_id: record.id.clone(),
            ciphertext: Sha256::digest(record.ct.as_bytes()).into(),
        }
    }
}

/// The delegation a call runs under: the signing public key of the grant in force when the
/// call created its event, and the revoke serial of the account at that moment. A revoke the
/// node accepts after it draws a larger serial, so a grant of the same key made after that
/// revoke is told apart from the grant the call ran under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Delegation {
    pub(crate) sign_pk: [u8; 32],
    pub(crate) revoke_serial: u64,
}

impl Delegation {
    /// The delegation of the grant view of a call.
    pub(crate) fn of(grant: &GrantView) -> Delegation {
        Delegation {
            sign_pk: grant.sign_pk,
            revoke_serial: grant.revoke_serial,
        }
    }
}

/// A session that carries no call.
struct Kept {
    /// The name of this stay of the session: the task that ends an idle session ends the
    /// stay it was started for and no later one.
    id: u64,
    session: ImapSession,
    delegation: Delegation,
    /// The node time at which the session came back from its last call.
    idle_ms: u64,
}

/// The sessions a node keeps, by the record of each. A record has at most one kept session.
pub(crate) struct MailSessions {
    kept: Mutex<HashMap<SessionKey, Kept>>,
    ids: AtomicU64,
    /// [`SESSION_IDLE_MS`] and [`SESSION_LOGIN_MS`]. A test shortens them.
    idle_limit_ms: AtomicU64,
    login_limit_ms: AtomicU64,
}

impl Default for MailSessions {
    fn default() -> MailSessions {
        MailSessions {
            kept: Mutex::default(),
            ids: AtomicU64::new(1),
            idle_limit_ms: AtomicU64::new(SESSION_IDLE_MS),
            login_limit_ms: AtomicU64::new(SESSION_LOGIN_MS),
        }
    }
}

impl MailSessions {
    /// True when a session that came back at `idle_ms` and logged in at `login_ms` can carry
    /// a call at `now_ms`.
    fn carries(&self, idle_ms: u64, login_ms: u64, now_ms: u64) -> bool {
        now_ms < idle_ms.saturating_add(self.idle_limit_ms.load(Ordering::Relaxed))
            && now_ms < login_ms.saturating_add(self.login_limit_ms.load(Ordering::Relaxed))
    }

    /// Takes the kept session of the record `key` for a call that runs under `delegation`.
    /// The caller holds the `log` object of that call (`_entry`): the log store confirmed the
    /// entry that names the call before a command of the call goes over the session. The
    /// session leaves the kept ones in every case. `None`, and the session ends, when it was
    /// kept under another delegation, when its idle time passed, or when its login is older
    /// than the time a login carries calls.
    pub(crate) fn take(
        &self,
        _entry: &LogRef,
        key: &SessionKey,
        delegation: &Delegation,
        now_ms: u64,
    ) -> Option<ImapSession> {
        let kept = lock(&self.kept).remove(key)?;
        let usable = kept.delegation == *delegation
            && self.carries(kept.idle_ms, kept.session.login_ms(), now_ms);
        usable.then_some(kept.session)
    }

    /// Keeps the session a call gives back, for the next call of the record `key` under
    /// `delegation`. A session whose login is older than the time a login carries calls is
    /// not kept. A session the record already keeps (two calls of the record ran at the same
    /// time) stays when its login is the later one; otherwise it ends for the one that comes.
    ///
    /// The session ends without a further call when its idle time passed or its login became
    /// too old: a task started here ends this stay then.
    pub(crate) fn keep(
        self: &Arc<Self>,
        key: SessionKey,
        delegation: Delegation,
        session: ImapSession,
        now_ms: u64,
    ) {
        let login_ms = session.login_ms();
        if !self.carries(now_ms, login_ms, now_ms) {
            return;
        }
        let id = self.ids.fetch_add(1, Ordering::Relaxed);
        // The sessions that end here are dropped after the lock is free.
        let mut ended = Vec::new();
        let mut not_kept = None;
        {
            let mut kept = lock(&self.kept);
            let other_stays = kept.get(&key).is_some_and(|other| {
                other.delegation == delegation && other.session.login_ms() >= login_ms
            });
            if other_stays {
                not_kept = Some(session);
            } else {
                if kept.len() >= KEPT_SESSIONS && !kept.contains_key(&key) {
                    let longest_idle = kept
                        .iter()
                        .min_by_key(|(_, other)| other.idle_ms)
                        .map(|(key, _)| key.clone());
                    ended.extend(longest_idle.and_then(|key| kept.remove(&key)));
                }
                ended.extend(kept.insert(
                    key.clone(),
                    Kept {
                        id,
                        session,
                        delegation,
                        idle_ms: now_ms,
                    },
                ));
            }
        }
        drop(ended);
        if not_kept.is_some() {
            return;
        }
        let idle = self.idle_limit_ms.load(Ordering::Relaxed);
        let login_left = login_ms
            .saturating_add(self.login_limit_ms.load(Ordering::Relaxed))
            .saturating_sub(now_ms);
        let sessions = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(idle.min(login_left))).await;
            sessions.end_stay(&key, id);
        });
    }

    /// Ends the stay `id` of the session of `key`, when the session still is in that stay: no
    /// call took it since.
    fn end_stay(&self, key: &SessionKey, id: u64) {
        let ended = {
            let mut kept = lock(&self.kept);
            match kept.get(key) {
                Some(stay) if stay.id == id => kept.remove(key),
                _ => None,
            }
        };
        drop(ended);
    }

    /// Ends the kept session of the record `key`, when there is one: the delegation it was
    /// kept under is not in force, or the server refused the application password of the
    /// record.
    pub(crate) fn end(&self, key: &SessionKey) {
        let ended = lock(&self.kept).remove(key);
        drop(ended);
    }

    /// The sessions the node keeps at this moment (`mail` of `idle_connections` of health).
    pub(crate) fn count(&self) -> usize {
        lock(&self.kept).len()
    }

    /// Sets the idle time and the time a login carries calls. Tests cross them in
    /// milliseconds.
    #[cfg(test)]
    pub(crate) fn set_limits(&self, idle_ms: u64, login_ms: u64) {
        self.idle_limit_ms.store(idle_ms, Ordering::Relaxed);
        self.login_limit_ms.store(login_ms, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, DuplexStream};

    use super::*;

    /// The `log` object of a call whose entry the log store confirmed.
    const ENTRY: LogRef = LogRef {
        seq: 1,
        index: 0,
        created: true,
    };

    fn key(user_id: &str, id: &str, ct: &str) -> SessionKey {
        SessionKey::of(
            user_id,
            &Record {
                v: 1,
                id: id.to_string(),
                user_id: user_id.to_string(),
                key_id: "key".to_string(),
                custody: "enclave".to_string(),
                kind: "app_password".to_string(),
                provider: "naver_mail".to_string(),
                nonce: "nonce".to_string(),
                ct: ct.to_string(),
            },
        )
    }

    fn delegation(sign_pk: u8, revoke_serial: u64) -> Delegation {
        Delegation {
            sign_pk: [sign_pk; 32],
            revoke_serial,
        }
    }

    /// A session whose login was at `login_ms`, and the other end of its connection.
    fn session(login_ms: u64) -> (ImapSession, DuplexStream) {
        let (near, far) = tokio::io::duplex(64);
        (ImapSession::for_test(Box::new(near), login_ms), far)
    }

    /// True when the connection whose other end is `far` ended.
    async fn ended(far: &mut DuplexStream) -> bool {
        let read = tokio::time::timeout(Duration::from_millis(20), far.read(&mut [0u8; 1])).await;
        matches!(read, Ok(Ok(0)))
    }

    #[tokio::test(start_paused = true)]
    async fn a_session_is_handed_to_a_call_of_its_record_and_of_its_delegation() {
        let sessions = Arc::new(MailSessions::default());
        let (record, grant) = (key("user", "r1", "ct1"), delegation(1, 5));

        // Another record, another ciphertext of the record and another account find nothing,
        // and the session stays.
        let (kept, mut far) = session(1_000);
        sessions.keep(record.clone(), grant, kept, 1_000);
        for other in [
            key("user", "r2", "ct1"),
            key("user", "r1", "ct2"),
            key("other", "r1", "ct1"),
        ] {
            assert!(sessions.take(&ENTRY, &other, &grant, 1_001).is_none());
        }
        assert_eq!(sessions.count(), 1);
        assert!(!ended(&mut far).await);
        // A call of the record under the delegation takes it, and the record keeps none.
        let taken = sessions.take(&ENTRY, &record, &grant, 1_001).unwrap();
        assert_eq!(sessions.count(), 0);
        assert!(sessions.take(&ENTRY, &record, &grant, 1_001).is_none());
        assert!(!ended(&mut far).await);

        // A call after a revoke, and a call under the grant of another key, get no session:
        // the session ends.
        for stranger in [delegation(1, 6), delegation(2, 5)] {
            let (kept, mut far) = session(1_000);
            sessions.keep(record.clone(), grant, kept, 1_000);
            assert!(sessions.take(&ENTRY, &record, &stranger, 1_001).is_none());
            assert_eq!(sessions.count(), 0);
            assert!(ended(&mut far).await);
        }

        // The idle time and the time a login carries calls, by node time.
        sessions.keep(record.clone(), grant, taken, 2_000);
        assert!(sessions
            .take(&ENTRY, &record, &grant, 2_000 + SESSION_IDLE_MS)
            .is_none());
        assert!(ended(&mut far).await);
        let (kept, mut far) = session(10_000);
        sessions.keep(record.clone(), grant, kept, 10_000 + SESSION_LOGIN_MS - 2);
        let taken = sessions
            .take(&ENTRY, &record, &grant, 10_000 + SESSION_LOGIN_MS - 1)
            .unwrap();
        // A session that old is not kept, and one a call asks for at that age is not
        // handed over.
        sessions.keep(record.clone(), grant, taken, 10_000 + SESSION_LOGIN_MS);
        assert_eq!(sessions.count(), 0);
        assert!(ended(&mut far).await);
        let (kept, mut far) = session(10_000);
        sessions.keep(record.clone(), grant, kept, 10_000 + SESSION_LOGIN_MS - 1);
        assert!(sessions
            .take(&ENTRY, &record, &grant, 10_000 + SESSION_LOGIN_MS)
            .is_none());
        assert!(ended(&mut far).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_record_keeps_one_session_and_a_node_keeps_a_bounded_number() {
        let sessions = Arc::new(MailSessions::default());
        let (record, grant) = (key("user", "r1", "ct1"), delegation(1, 0));

        // Two sessions of one record: the one of the later login stays.
        let (older, mut far_older) = session(1_000);
        let (newer, mut far_newer) = session(2_000);
        sessions.keep(record.clone(), grant, newer, 3_000);
        sessions.keep(record.clone(), grant, older, 3_000);
        assert_eq!(sessions.count(), 1);
        assert!(ended(&mut far_older).await);
        assert!(!ended(&mut far_newer).await);
        let (newest, mut far_newest) = session(2_500);
        sessions.keep(record.clone(), grant, newest, 3_000);
        assert_eq!(sessions.count(), 1);
        assert!(ended(&mut far_newer).await);
        assert!(!ended(&mut far_newest).await);
        // A session of another delegation gives way whatever its login.
        let (other, mut far_other) = session(100);
        sessions.keep(record.clone(), delegation(1, 1), other, 3_000);
        assert!(ended(&mut far_newest).await);
        assert!(!ended(&mut far_other).await);
        sessions.end(&record);
        assert_eq!(sessions.count(), 0);
        assert!(ended(&mut far_other).await);

        // At the bound, the session that has carried no call for the longest time ends for
        // the one that comes.
        let mut far_ends = Vec::new();
        for number in 0..KEPT_SESSIONS + 1 {
            let (kept, far) = session(5_000);
            far_ends.push(far);
            let record = key("user", &format!("record {number}"), "ct");
            // The second session came back first.
            let idle_ms = if number == 1 {
                5_000
            } else {
                5_001 + number as u64
            };
            sessions.keep(record, grant, kept, idle_ms);
        }
        assert_eq!(sessions.count(), KEPT_SESSIONS);
        assert!(ended(&mut far_ends[1]).await);
        assert!(!ended(&mut far_ends[0]).await);
        assert!(!ended(&mut far_ends[KEPT_SESSIONS]).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_session_that_carries_no_call_ends_at_its_idle_time() {
        let sessions = Arc::new(MailSessions::default());
        let (record, grant) = (key("user", "r1", "ct1"), delegation(1, 0));
        sessions.set_limits(60, 10_000);

        // No call asks for the session: its stay ends by itself.
        let (kept, mut far) = session(0);
        sessions.keep(record.clone(), grant, kept, 0);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(sessions.count(), 0);
        assert!(ended(&mut far).await);

        // A session a call took and gave back is in a new stay: the end of the stay before
        // it does not end it. The first stay ends 60 milliseconds after it began, the second
        // stay begins 30 milliseconds after the first, and the test looks 65 milliseconds
        // after the first began.
        let (kept, mut far) = session(0);
        sessions.keep(record.clone(), grant, kept, 0);
        tokio::time::sleep(Duration::from_millis(30)).await;
        let taken = sessions.take(&ENTRY, &record, &grant, 30).unwrap();
        sessions.keep(record.clone(), grant, taken, 30);
        tokio::time::sleep(Duration::from_millis(35)).await;
        assert_eq!(sessions.count(), 1);
        assert!(!ended(&mut far).await);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(sessions.count(), 0);
        assert!(ended(&mut far).await);

        // The time a login carries calls ends a stay as well, before the idle time does.
        sessions.set_limits(10_000, 60);
        let (kept, mut far) = session(0);
        sessions.keep(record.clone(), grant, kept, 20);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(sessions.count(), 0);
        assert!(ended(&mut far).await);
    }
}
