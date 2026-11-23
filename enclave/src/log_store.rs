//! The log store (protocol.md 7.6, enclave.md 5.14): the place outside the node where an entry
//! is written before the act it describes.
//!
//! A node writes every entry to Amazon S3 buckets whose objects are locked in compliance
//! mode: until its retention ends, nobody can delete an object version or shorten its
//! retention. The node acts only after the store confirmed the entry of the act. TLS ends
//! inside the node, so whoever carries the bytes cannot answer in the place of the store.
//!
//! The log store of a node is a set of buckets that follows from the one bucket name of its
//! binding (`LogStoreId::shard_bucket`). The entries of one account are all in one of them,
//! the bucket of the hash of its `user_id`. Every bucket is written over connections to one
//! host, the endpoint of Amazon S3 in the region of the store, with the bucket as the first
//! part of the path: the idle connections of the node carry the writes of every bucket.
//!
//! What this module holds:
//!
//! - [`LogStore`]: which log store the node writes to (set once, part of the binding of the
//!   attestation), the credentials of the operator for it, and when the store last confirmed
//!   the node document;
//! - [`write_node_document`]: the node writes its own attestation document to the store
//!   before it takes a user key, and again every 30 days (protocol.md 7.7);
//! - [`admit`], [`confirm`] and [`confirm_each`]: the steps a call takes before it acts;
//! - `send_to_log_store`, sink K5 of the egress policy: the one function that writes to the
//!   store. What it writes is a signed entry, whose content is sealed to the log public key
//!   of the account, or the node document, which holds public values; the request is signed
//!   with the credentials of the operator. No function here takes a user key, the plaintext
//!   of a record or a token of a provider.
//!
//! A write is confirmed by the status 200 of the store and by nothing else. The node does not
//! ask the store whether an object of that key exists: the operator domain can write to the
//! same buckets with the same credentials. An answer "this key exists" would say nothing
//! about who wrote the object, what it holds and how long it is kept. A write that is
//! repeated (the answer of the first one was lost) adds a second version of the same object.
//! An entry the store does not confirm stays in the memory of the node, is written again, and
//! is gone with the node: its act did not take place.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::task::Poll;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use credential_enclave_protocol::encoding::to_json;
use credential_enclave_protocol::keys::{shard_hash, LogStoreId};
use credential_enclave_protocol::log::{node_document, node_document_key, node_document_nonce};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::{limits, ProtocolError};
use hmac::{Hmac, Mac};
use hyper::body::{Body, Bytes};
use hyper::client::conn::http1::SendRequest;
use hyper::header::{HeaderValue, AUTHORIZATION, CONTENT_LENGTH};
use hyper::{Method, Request, StatusCode};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::api::responses::LogRef;
use crate::egress::{full_jitter, OnceBody, OpenError};
use crate::platform::DynPlatform;
use crate::state::{lock, Account, EventPlace, Node};

/// Writes of one call that run at the same time.
const WRITE_CONCURRENCY: usize = 32;
/// The interval of the sweep of the node ([`keep_sweeping`]).
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// Entries the sweep writes per second over the whole node ([`sweep`]): the default of
/// `Limits::sweep_write_rate`. The class of the peak write rate of a node, so the recovery
/// after an outage of the store does not more than double the live load on it.
pub const SWEEP_WRITE_RATE: u32 = 64;
/// Open connections to the log store that carry no write ([`IdleConnections`]).
const IDLE_CONNECTIONS: usize = 32;
/// Pending entries of one account at which a call that uses a credential creates no further
/// entry before the store confirmed some of them ([`admit`]).
pub const PENDING_ENTRIES: usize = 64;
/// The base of the full jitter backoff between two attempts to write one entry
/// ([`send_to_log_store`]).
const WRITE_BACKOFF_BASE: Duration = Duration::from_millis(100);
/// The cap of that backoff.
const WRITE_BACKOFF_CAP: Duration = Duration::from_secs(1);
/// The time a repeated attempt needs to have left in the budget of its entry: an attempt is
/// repeated only when the time passed, the backoff and this margin fit in the budget.
const WRITE_RETRY_MARGIN: Duration = Duration::from_secs(1);
/// One day in milliseconds.
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// Longest access key identifier, in characters.
const ACCESS_KEY_ID_CHARS: usize = 128;
/// Longest secret access key, in bytes.
const SECRET_ACCESS_KEY_BYTES: usize = 256;
/// Longest session token, in bytes.
const SESSION_TOKEN_BYTES: usize = 8192;

/// The credentials of the operator for the log store: temporary credentials of AWS.
///
/// They are values the operator domain gave, so they are no secrets from it. The secret access
/// key and the session token are held as secrets all the same (rule E1 of the egress policy):
/// they reach the log store and appear in no response.
pub struct Credentials {
    access_key_id: String,
    secret_access_key: Secret<String>,
    session_token: Secret<String>,
    expires_ms: u64,
}

impl Credentials {
    /// Reads credentials. `None` when a value has not the form of its kind: the access key
    /// identifier is 1 to 128 letters and digits, the secret access key is 1 to 256 printable
    /// ASCII characters, and the session token is at most 8,192 printable ASCII characters
    /// (the empty string for credentials without a session).
    pub fn new(
        access_key_id: &str,
        secret_access_key: &str,
        session_token: &str,
        expires_ms: u64,
    ) -> Option<Credentials> {
        let printable = |text: &str| text.bytes().all(|byte| (0x21..=0x7e).contains(&byte));
        let valid = (1..=ACCESS_KEY_ID_CHARS).contains(&access_key_id.len())
            && access_key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
            && (1..=SECRET_ACCESS_KEY_BYTES).contains(&secret_access_key.len())
            && printable(secret_access_key)
            && session_token.len() <= SESSION_TOKEN_BYTES
            && printable(session_token);
        valid.then(|| Credentials {
            access_key_id: access_key_id.to_string(),
            secret_access_key: Secret::new(secret_access_key.to_string()),
            session_token: Secret::new(session_token.to_string()),
            expires_ms,
        })
    }

    /// The value of the `Authorization` header of AWS Signature Version 4 for a request to S3
    /// in `region`: the method, the path as it is sent (each part of the key percent-encoded
    /// once), no query, the given headers and the session token as signed headers, and the
    /// SHA-256 of the body.
    ///
    /// `headers` are lower-case names with their values. `amz_date` is the value of the
    /// header `x-amz-date`.
    fn authorization(
        &self,
        region: &str,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        payload_sha256: &str,
        amz_date: &str,
    ) -> String {
        // The signed headers, in the order of their names.
        let token = self.session_token.expose_secret();
        let mut signed: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        if !token.is_empty() {
            signed.push((SECURITY_TOKEN, token));
        }
        signed.sort_by(|left, right| left.0.cmp(right.0));
        let names = signed
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(";");

        // The canonical request holds the session token: it is written into one buffer of its
        // final size, which is overwritten with zeros when it is dropped.
        let size = method.len()
            + path.len()
            + names.len()
            + payload_sha256.len()
            + signed
                .iter()
                .map(|(name, value)| name.len() + value.len() + 2)
                .sum::<usize>()
            + 8;
        let mut canonical = Zeroizing::new(String::with_capacity(size));
        canonical.push_str(method);
        canonical.push('\n');
        canonical.push_str(path);
        canonical.push_str("\n\n");
        for (name, value) in &signed {
            canonical.push_str(name);
            canonical.push(':');
            canonical.push_str(value.trim());
            canonical.push('\n');
        }
        canonical.push('\n');
        canonical.push_str(&names);
        canonical.push('\n');
        canonical.push_str(payload_sha256);

        let date = &amz_date[..amz_date.len().min(8)];
        let scope = format!("{date}/{region}/s3/aws4_request");
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex(&Sha256::digest(canonical.as_bytes()))
        );

        // The signing key: a chain of HMAC-SHA256 from the secret access key.
        let secret = self.secret_access_key.expose_secret();
        let mut first = Zeroizing::new(Vec::with_capacity(4 + secret.len()));
        first.extend_from_slice(b"AWS4");
        first.extend_from_slice(secret.as_bytes());
        let mut key = hmac_sha256(&first, date.as_bytes());
        for part in [region, "s3", "aws4_request"] {
            key = hmac_sha256(key.as_slice(), part.as_bytes());
        }
        let signature = hmac_sha256(key.as_slice(), to_sign.as_bytes());
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope},SignedHeaders={names},Signature={}",
            self.access_key_id,
            hex(signature.as_slice())
        )
    }
}

/// The name of the header that carries the session token.
const SECURITY_TOKEN: &str = "x-amz-security-token";

fn hmac_sha256(key: &[u8], message: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 takes a key of any length");
    mac.update(message);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// Lower-case hexadecimal.
fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble"));
        text.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("nibble"));
    }
    text
}

/// The parts of a time in UTC: year, month, day, hour, minute, second.
fn utc(time_ms: u64) -> [u64; 6] {
    let seconds = time_ms / 1000;
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    // The date of a count of days since 1970-01-01 in the Gregorian calendar. The count is
    // moved to start at 0000-03-01, the first day after a leap day in a cycle of 400 years.
    let shifted = days + 719_468;
    let (era, day_of_era) = (shifted / 146_097, shifted % 146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    [year, month, day, rest / 3600, rest % 3600 / 60, rest % 60]
}

/// The value of `x-amz-date`: `YYYYMMDDTHHMMSSZ`.
fn amz_date(time_ms: u64) -> String {
    let [year, month, day, hour, minute, second] = utc(time_ms);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

/// The value of `x-amz-object-lock-retain-until-date`: `YYYY-MM-DDTHH:MM:SSZ`.
fn retain_until(time_ms: u64) -> String {
    let [year, month, day, hour, minute, second] = utc(time_ms);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// The request target of an object: `/` and the key, in which every byte is percent-encoded
/// except the unreserved characters of RFC 3986 and `/`. This is the canonical path of
/// Signature Version 4 for S3, so the path that is sent is the path that is signed.
fn object_path(key: &str) -> String {
    let mut path = String::with_capacity(1 + key.len());
    path.push('/');
    for byte in key.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            path.push(char::from(byte));
        } else {
            path.push('%');
            for nibble in [byte >> 4, byte & 0x0f] {
                let digit = char::from_digit(u32::from(nibble), 16).expect("nibble");
                path.push(digit.to_ascii_uppercase());
            }
        }
    }
    path
}

/// The endpoint of the log store of a node of the local platform (enclave.md 5.14): the S3
/// stand-in of the local stack, written to in path-style with the `Host` header of the
/// endpoint and, when its scheme is `http`, without TLS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogStoreEndpoint {
    pub tls: bool,
    pub host: String,
    pub port: u16,
}

impl LogStoreEndpoint {
    /// Reads an `http://host:port` or `https://host:port` origin: a scheme, a host of letters,
    /// digits, `.` and `-`, and an optional port. A path, a query, a fragment and user
    /// information are `None`.
    pub fn parse(text: &str) -> Option<LogStoreEndpoint> {
        let (tls, rest) = match (text.strip_prefix("http://"), text.strip_prefix("https://")) {
            (Some(rest), _) => (false, rest),
            (_, Some(rest)) => (true, rest),
            _ => return None,
        };
        let (host, port) = match rest.split_once(':') {
            Some((host, port)) => (host, port.parse::<u16>().ok().filter(|port| *port != 0)?),
            None => (rest, if tls { 443 } else { 80 }),
        };
        let valid_host = !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
        valid_host.then(|| LogStoreEndpoint {
            tls,
            host: host.to_string(),
            port,
        })
    }

    /// The value of the `Host` header: the host, with the port when it is not the default of
    /// the scheme.
    pub fn authority(&self) -> String {
        match (self.tls, self.port) {
            (true, 443) | (false, 80) => self.host.clone(),
            _ => format!("{}:{}", self.host, self.port),
        }
    }
}

/// Where a write goes and what signs it.
struct Writer {
    id: LogStoreId,
    credentials: Arc<Credentials>,
    endpoint: Option<LogStoreEndpoint>,
}

/// The log store of a node and the credentials for it.
pub struct LogStore {
    /// True on a platform whose nodes do not act without a log store: `nitro`.
    required: bool,
    /// The bucket name of the binding and its region. Set once: the binding of the attestation
    /// names it, and what a verifier read there holds for as long as the node lives. The
    /// buckets the node writes to follow from this name (`LogStoreId::shard_bucket`).
    id: OnceLock<LogStoreId>,
    /// The endpoint of a node of the local platform, set once with the log store.
    endpoint: OnceLock<Option<LogStoreEndpoint>>,
    credentials: RwLock<Option<Arc<Credentials>>>,
    idle: IdleConnections,
    /// The node time of the latest write of the node document that the store confirmed, 0
    /// while it confirmed none (protocol.md 7.7). It only grows.
    document_ms: AtomicU64,
    /// Held by the one call that writes the node document at a time.
    document_writer: tokio::sync::Mutex<()>,
}

/// The open HTTP/1.1 connections to the log store that carry no write, the most recently used
/// last.
#[derive(Default)]
struct IdleConnections(Mutex<Vec<SendRequest<OnceBody>>>);

impl IdleConnections {
    /// The most recently used connection that is still open, once it is ready for a request.
    async fn take(&self) -> Option<SendRequest<OnceBody>> {
        loop {
            let mut sender = lock(&self.0).pop()?;
            if sender.ready().await.is_ok() {
                return Some(sender);
            }
        }
    }

    /// Keeps a connection whose response has ended, while fewer than [`IDLE_CONNECTIONS`] are
    /// kept.
    fn put(&self, sender: SendRequest<OnceBody>) {
        let mut connections = lock(&self.0);
        connections.retain(|sender| !sender.is_closed());
        if connections.len() < IDLE_CONNECTIONS {
            connections.push(sender);
        }
    }
}

impl LogStore {
    /// The state of a node that starts: no log store and no credentials. With `required`, the
    /// node refuses every act of the table of protocol.md 7.6 until it has both.
    pub fn new(required: bool) -> LogStore {
        LogStore {
            required,
            id: OnceLock::new(),
            endpoint: OnceLock::new(),
            credentials: RwLock::new(None),
            idle: IdleConnections::default(),
            document_ms: AtomicU64::new(0),
            document_writer: tokio::sync::Mutex::new(()),
        }
    }

    /// The log store of this node, when the operator configuration named one.
    pub fn id(&self) -> Option<&LogStoreId> {
        self.id.get()
    }

    /// Names the log store of this node. False when the node has another one (a log store
    /// does not change), and when the name is too long for the names of its buckets to be
    /// bucket names: a node takes a log store it can write to only.
    pub fn set_id(&self, id: LogStoreId) -> bool {
        if id.shard_bucket(0).is_none() {
            return false;
        }
        self.id.get_or_init(|| id.clone()) == &id
    }

    /// The node time of the latest write of the node document that the store confirmed, 0
    /// while it confirmed none.
    pub fn document_ms(&self) -> u64 {
        self.document_ms.load(Ordering::SeqCst)
    }

    /// True while the store holds a version of the node document that outlives an entry
    /// written now: the store confirmed a write of the document less than 31 days ago
    /// (protocol.md 7.7). The retention of that version ends 400 days after its write, and the
    /// retention of an entry 365 days after the write of the entry.
    fn document_covers(&self, now_ms: u64) -> bool {
        let written_ms = self.document_ms();
        written_ms != 0
            && now_ms < written_ms.saturating_add(limits::NODE_DOCUMENT_VALID_DAYS * DAY_MS)
    }

    /// True when the node document is due: the store confirmed no write of it, or the latest
    /// one it confirmed is 30 days old.
    fn document_due(&self, now_ms: u64) -> bool {
        let written_ms = self.document_ms();
        written_ms == 0
            || now_ms >= written_ms.saturating_add(limits::NODE_DOCUMENT_RENEW_DAYS * DAY_MS)
    }

    /// Sets the endpoint of the log store (`None` for the host of the bucket). False when the
    /// node has another one: the endpoint is set once, with the log store.
    pub fn set_endpoint(&self, endpoint: Option<LogStoreEndpoint>) -> bool {
        self.endpoint.get_or_init(|| endpoint.clone()) == &endpoint
    }

    /// Replaces the credentials.
    pub fn set_credentials(&self, credentials: Credentials) {
        *self
            .credentials
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(credentials));
    }

    /// The end of the credentials the node holds, 0 when it holds none.
    pub fn credentials_expires_ms(&self) -> u64 {
        self.credentials
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map_or(0, |credentials| credentials.expires_ms)
    }

    /// True when the node keeps account of which entries the log store confirmed: it has a log
    /// store, or its platform requires one.
    pub fn tracks(&self) -> bool {
        self.required || self.id.get().is_some()
    }

    /// Where a write goes and what signs it. `Ok(None)` for a node that runs without a log
    /// store (the local platform without one in its configuration). `log_store_unavailable`
    /// when the node lacks the configuration or credentials within their time.
    fn target(&self, now_ms: u64) -> Result<Option<Writer>, ProtocolError> {
        let Some(id) = self.id.get() else {
            return match self.required {
                true => Err(ProtocolError::LogStoreUnavailable),
                false => Ok(None),
            };
        };
        let credentials = self
            .credentials
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .filter(|credentials| now_ms < credentials.expires_ms)
            .ok_or(ProtocolError::LogStoreUnavailable)?;
        Ok(Some(Writer {
            id: id.clone(),
            credentials,
            endpoint: self.endpoint.get().cloned().flatten(),
        }))
    }

    /// What the write of an entry needs: [`LogStore::target`], and a node document in the
    /// store that outlives the entry (protocol.md 7.7). `log_store_unavailable` without one:
    /// a node writes no entry that a reader could not trace to an attested node.
    fn writer(&self, now_ms: u64) -> Result<Option<Writer>, ProtocolError> {
        let writer = self.target(now_ms)?;
        if writer.is_some() && !self.document_covers(now_ms) {
            return Err(ProtocolError::LogStoreUnavailable);
        }
        Ok(writer)
    }

    /// The node can write an entry to its log store now, or it runs without one: it has a log
    /// store, credentials within their time, and its node document in the store.
    pub fn ensure_ready(&self, now_ms: u64) -> Result<(), ProtocolError> {
        self.writer(now_ms).map(|_| ())
    }

    /// The log store holds the node document of this node, with a retention that outlives an
    /// entry written now, or the node runs without a log store. `log_store_unavailable`
    /// otherwise: a node that has no log store on a platform that requires one, and a node
    /// whose document the store did not confirm in the last 31 days. A node takes a user key
    /// from another node under this condition (`peer/import`), which asks for no credentials:
    /// the transfer of a node of the same measurement writes nothing.
    pub fn ensure_documented(&self, now_ms: u64) -> Result<(), ProtocolError> {
        let documented = match self.id.get() {
            Some(_) => self.document_covers(now_ms),
            None => !self.required,
        };
        match documented {
            true => Ok(()),
            false => Err(ProtocolError::LogStoreUnavailable),
        }
    }

    /// The idle connections to the log store at this moment (`log_store` of
    /// `idle_connections` of health).
    pub fn idle_connections(&self) -> usize {
        lock(&self.idle.0).len()
    }
}

/// One object a node writes to its log store: an entry or the node document.
struct StoreObject {
    /// The hash that names the bucket of the object among the buckets of the log store
    /// (protocol.md 7.6): the hash of the `user_id` for an entry, of the node identifier for
    /// the node document.
    shard: u16,
    /// The key of the object.
    key: String,
    /// The bytes of the object.
    body: Bytes,
    /// The days of the retention of the object, from the write.
    retention_days: u64,
}

/// One entry in the hands of a call.
struct Write {
    seq: u64,
    /// The object of the entry (protocol.md 7.6).
    object: StoreObject,
    /// True for an entry an act of the call waits for.
    required: bool,
    /// True once the store answered a write of the entry by this call with the status 200.
    confirmed: bool,
}

/// The entries of one account that a call writes: the entries the call names and the pending
/// entries of the account. While the claim lives, no other call takes the pending ones along.
/// When it is dropped, the entries the store confirmed leave the account, and the others are
/// no longer written by this call: also when the call ends before its writes do.
struct Claim<'a> {
    account: &'a Mutex<Account>,
    writes: Vec<Write>,
}

impl<'a> Claim<'a> {
    fn take(account: &'a Mutex<Account>, seqs: &[u64]) -> Claim<'a> {
        let mut writes = Vec::new();
        for entry in lock(account).unconfirmed_mut() {
            let required = seqs.contains(&entry.seq);
            // An entry another call writes is left to that call, unless an act of this call
            // waits for it: then both write it, and the store keeps two versions of it.
            if required || entry.writers == 0 {
                entry.writers += 1;
                writes.push(Write {
                    seq: entry.seq,
                    object: StoreObject {
                        shard: entry.shard,
                        key: entry.key.clone(),
                        body: Bytes::from(to_json(&entry.entry)),
                        retention_days: limits::LOG_RETENTION_DAYS,
                    },
                    required,
                    confirmed: false,
                });
            }
        }
        Claim { account, writes }
    }
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        let mut account = lock(self.account);
        for write in &self.writes {
            if write.confirmed {
                // The one place an entry becomes a confirmed entry: the store answered this
                // write of it with the status 200.
                account.store_confirmed(write.seq);
            } else if let Some(entry) = account
                .unconfirmed_mut()
                .find(|entry| entry.seq == write.seq)
            {
                // This call no longer writes the entry. It is a pending entry once no other
                // call writes it either.
                entry.writers = entry.writers.saturating_sub(1);
            }
        }
    }
}

/// Runs futures at the same time, on the task of the caller, and returns their outputs in the
/// order of the futures.
pub(crate) async fn join_all<F: Future>(futures: impl Iterator<Item = F>) -> Vec<F::Output> {
    let mut futures: Vec<Pin<Box<F>>> = futures.map(Box::pin).collect();
    let mut outputs: Vec<Option<F::Output>> = futures.iter().map(|_| None).collect();
    std::future::poll_fn(|context| {
        let mut waiting = false;
        for (future, output) in futures.iter_mut().zip(outputs.iter_mut()) {
            if output.is_none() {
                match future.as_mut().poll(context) {
                    Poll::Ready(value) => *output = Some(value),
                    Poll::Pending => waiting = true,
                }
            }
        }
        match waiting {
            true => Poll::Pending,
            false => Poll::Ready(()),
        }
    })
    .await;
    outputs
        .into_iter()
        .map(|output| output.expect("every future ended"))
        .collect()
}

/// Writes the entries of the claims: the entries an act waits for first, at most 32 writes at
/// the same time. After a round in which a write failed, no further round starts: the entries
/// that were not written stay with their accounts. Nothing is written while the node cannot
/// write an entry ([`LogStore::ensure_ready`]).
async fn write_claims(node: &Node, claims: &mut [Claim<'_>]) {
    let mut order: Vec<(usize, usize)> = Vec::new();
    for required in [true, false] {
        for (at, claim) in claims.iter().enumerate() {
            for (index, write) in claim.writes.iter().enumerate() {
                if write.required == required {
                    order.push((at, index));
                }
            }
        }
    }
    if order.is_empty() {
        return;
    }
    let Ok(Some(writer)) = node.log_store.writer(node.now_ms()) else {
        return;
    };
    for round in order.chunks(WRITE_CONCURRENCY) {
        let outcomes = join_all(round.iter().filter_map(|(at, index)| {
            let write = claims.get(*at)?.writes.get(*index)?;
            Some(send_to_log_store(node, &writer, &write.object))
        }))
        .await;
        let failed = outcomes.iter().filter(|confirmed| !**confirmed).count();
        node.log_counters
            .write_failures
            .fetch_add(failed as u64, Ordering::Relaxed);
        for ((at, index), confirmed) in round.iter().zip(&outcomes) {
            if let Some(write) = claims
                .get_mut(*at)
                .and_then(|claim| claim.writes.get_mut(*index))
            {
                write.confirmed = *confirmed;
            }
        }
        if failed > 0 {
            return;
        }
    }
}

/// How an attempt to write an entry ended without a confirmation (enclave.md 5.14): the cause
/// under which `write_attempt_failures` of health counts it. The six names are a closed
/// vocabulary of the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteFailure {
    /// The byte pipe, the egress relay or the HTTP/1.1 handshake failed, or the request could
    /// not be built.
    Connect,
    /// The TLS handshake failed.
    Tls,
    /// The connection closed without a response.
    Closed,
    /// The attempt passed its time limit.
    Timeout,
    /// A status other than 200 that is neither 5xx nor 429: a 4xx status (the signature, the
    /// credentials or the configuration of the bucket), and the statuses of the other classes
    /// that the store does not answer a `PUT` with.
    Status4xx,
    /// A status 5xx, or 429.
    Status5xx,
}

/// The failure of one attempt: its cause, and whether the attempt is repeated over a new
/// connection when the budget of the entry permits.
type AttemptFailure = (WriteFailure, bool);

/// The failure of a status other than 200: a 5xx status and 429 are repeated, every other
/// status is not.
fn status_failure(status: StatusCode) -> AttemptFailure {
    match status.as_u16() {
        429 => (WriteFailure::Status4xx, true),
        500..=599 => (WriteFailure::Status5xx, true),
        _ => (WriteFailure::Status4xx, false),
    }
}

/// Sink K5 of the egress policy: writes one object to the log store and returns whether the
/// store confirmed the write.
///
/// What leaves is a signed entry (its content is sealed to the log public key of the account)
/// or the node document (public values), under its key in the bucket of its owner (protocol.md
/// 7.6 and 7.7), with a retention in compliance mode from now, and the request is signed with
/// the credentials of the operator. The connection goes to the endpoint of Amazon S3 in the
/// region of the log store, `s3.{region}.amazonaws.com`: TLS ends inside the node and the
/// certificate is verified against the trust roots of the binary. The bucket is the first part
/// of the path, so one connection carries the writes of every bucket of the store.
///
/// The attempts of one object share a budget of twice the time limit of a write. The first
/// attempt goes over an idle connection when there is one, with half the time limit; every
/// later attempt, and the first when there is no idle connection, opens a new connection
/// (`Egress::open`, which repeats a failed open itself) with the whole time limit. An attempt
/// that ends without a confirmation because the connection failed, closed without a response,
/// passed its time limit or was answered with a 5xx status or 429 is repeated after a full
/// jitter backoff, as long as the time passed, the backoff and a margin of one second fit in
/// the budget; a 4xx status other than 429 ends the write at once. A `PUT` is idempotent (RFC
/// 9110 9.2.2), and a repeated attempt adds a version of the same object with the same body:
/// `put_request` renews the date and the signature only.
///
/// The one confirmation is the status 200. Every other status, a failure of the connection
/// and an attempt that takes longer than its time limit are no confirmation. Every attempt is
/// counted as a write of `log` of health, every failed attempt under its cause, every repeated
/// attempt as a retry, and the time to the confirmation of a confirmed attempt in the buckets.
async fn send_to_log_store(node: &Node, writer: &Writer, object: &StoreObject) -> bool {
    let counters = &node.log_counters;
    let limit = node.limits.log_write;
    let budget = 2 * limit;
    let started = Instant::now();
    let mut attempts: u32 = 0;
    loop {
        attempts += 1;
        counters.writes.fetch_add(1, Ordering::Relaxed);
        let attempt_started = Instant::now();
        let remaining = budget.saturating_sub(started.elapsed());
        match write_once(node, writer, object, attempts == 1, limit.min(remaining)).await {
            Ok(()) => {
                let elapsed_ms =
                    u64::try_from(attempt_started.elapsed().as_millis()).unwrap_or(u64::MAX);
                counters.record_confirmed(elapsed_ms);
                return true;
            }
            Err((cause, repeated)) => {
                counters.write_attempt_failures.count(cause);
                if !repeated {
                    return false;
                }
                let backoff = full_jitter(
                    node.platform.as_ref(),
                    attempts,
                    WRITE_BACKOFF_BASE,
                    WRITE_BACKOFF_CAP,
                );
                if started.elapsed() + backoff + WRITE_RETRY_MARGIN > budget {
                    return false;
                }
                counters.write_retries.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

/// One attempt of [`send_to_log_store`]: one `PUT` of the object, over an idle connection when
/// `first` and there is one (with half of `limit`), else over a new connection (with `limit`,
/// which also bounds the open). `Ok` is the status 200.
async fn write_once(
    node: &Node,
    writer: &Writer,
    object: &StoreObject,
    first: bool,
    limit: Duration,
) -> Result<(), AttemptFailure> {
    let idle = match first {
        true => node.log_store.idle.take().await,
        false => None,
    };
    let attempt_limit = match idle.is_some() {
        true => limit / 2,
        false => limit,
    };
    let exchange = async {
        let mut sender = match idle {
            Some(sender) => {
                node.egress
                    .counters
                    .idle_reuses
                    .log_store
                    .fetch_add(1, Ordering::Relaxed);
                sender
            }
            None => open_log_connection(node, writer, attempt_limit).await?,
        };
        let request =
            put_request(writer, object, node.now_ms()).ok_or((WriteFailure::Connect, false))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| (WriteFailure::Closed, true))?;
        if response.body().is_end_stream() {
            node.log_store.idle.put(sender);
        }
        match response.status() {
            StatusCode::OK => Ok(()),
            status => Err(status_failure(status)),
        }
    };
    match tokio::time::timeout(attempt_limit, exchange).await {
        Ok(outcome) => outcome,
        Err(_) => Err((WriteFailure::Timeout, true)),
    }
}

/// A new connection to the log store: to the endpoint of Amazon S3 in the region of the store,
/// or to the endpoint of a node of the local platform (enclave.md 5.14). `budget` is the time
/// limit of the attempt.
async fn open_log_connection(
    node: &Node,
    writer: &Writer,
    budget: Duration,
) -> Result<SendRequest<OnceBody>, AttemptFailure> {
    let opened = match &writer.endpoint {
        None => {
            node.egress
                .open(node.platform.as_ref(), &writer.id.regional_host(), budget)
                .await
        }
        Some(endpoint) => {
            node.egress
                .open_at(
                    node.platform.as_ref(),
                    &endpoint.host,
                    endpoint.port,
                    endpoint.tls,
                    budget,
                )
                .await
        }
    };
    opened.map_err(|error| match error {
        OpenError::Tls => (WriteFailure::Tls, true),
        OpenError::Transport | OpenError::RelayRefused | OpenError::Http => {
            (WriteFailure::Connect, true)
        }
    })
}

/// The request that writes one object (protocol.md 7.6): `PUT` of the bytes of the object under
/// its key in its bucket, with the retention of the object, the checksum S3 requires of a
/// request that sets one, and the encryption of the object under a key the store manages
/// (`AES256`). The request target is path-style, `/{bucket}/{key}`, and the `Host` is the
/// endpoint of Amazon S3 in the region of the store, or the endpoint of a node of the local
/// platform. `None` when the log store has no bucket for the object.
///
/// The request names the encryption itself, and a header of the request comes before the
/// default encryption of the bucket. So no key that someone can disable or delete stands
/// between a reader and an object of the store: a bucket whose default names a key of the key
/// management service does not put that key on the objects of a node.
fn put_request(writer: &Writer, object: &StoreObject, now_ms: u64) -> Option<Request<OnceBody>> {
    let bucket = writer.id.shard_of(object.shard)?;
    let path = format!("/{bucket}{}", object_path(&object.key));
    let host = match &writer.endpoint {
        None => writer.id.regional_host(),
        Some(endpoint) => endpoint.authority(),
    };
    let digest = Sha256::digest(&object.body);
    let payload_sha256 = hex(&digest);
    let amz_date = amz_date(now_ms);
    let retention_ms = object.retention_days.saturating_mul(DAY_MS);
    // The headers of the request, in the order of their names. All of them are signed.
    let headers = [
        ("content-type", "application/json".to_string()),
        ("host", host),
        ("x-amz-checksum-sha256", STANDARD.encode(digest)),
        ("x-amz-content-sha256", payload_sha256.clone()),
        ("x-amz-date", amz_date.clone()),
        ("x-amz-object-lock-mode", "COMPLIANCE".to_string()),
        (
            "x-amz-object-lock-retain-until-date",
            retain_until(now_ms.saturating_add(retention_ms)),
        ),
        ("x-amz-server-side-encryption", "AES256".to_string()),
    ];
    let authorization = writer.credentials.authorization(
        writer.id.region(),
        "PUT",
        &path,
        &headers,
        &payload_sha256,
        &amz_date,
    );
    let mut builder = Request::builder()
        .method(Method::PUT)
        .uri(path)
        .header(CONTENT_LENGTH, object.body.len());
    for (name, value) in &headers {
        builder = builder.header(*name, value);
    }
    let token = writer.credentials.session_token.expose_secret();
    if !token.is_empty() {
        let mut value = HeaderValue::from_str(token).ok()?;
        value.set_sensitive(true);
        builder = builder.header(SECURITY_TOKEN, value);
    }
    builder
        .header(AUTHORIZATION, authorization)
        .body(OnceBody::new(object.body.clone()))
        .ok()
}

/// Writes the node document of this node to its log store when it is due (protocol.md 7.7):
/// the store confirmed no write of it yet, or the latest write it confirmed is 30 days old.
/// Returns the node time of the latest confirmed write, 0 while there is none.
///
/// The object is the attestation document of the platform over the binding of the node (with
/// its `log`) and the nonce [`node_document_nonce`], under the key `n3/{node}` in the bucket of
/// the hash of the node identifier, with a retention of 400 days from the write. Its values
/// are public: the binding and the measurement of the node. A node takes no user key and
/// writes no entry before the store confirmed this object ([`LogStore::ensure_ready`]), so a
/// reader of the store finds, for every entry, the document that says which program holds the
/// signing key of the entry; the retention of the version a node relies on ends after the
/// retention of the entries it writes.
///
/// Nothing is written on a node without a log store, without credentials within their time,
/// or while the document is not due. One call at a time writes the document: a call that
/// finds another one writing waits for it and looks again. The call that names the log store
/// (`config`), the call that gives the credentials (`log-store/credentials`) and the sweep of
/// the node make this call.
pub async fn write_node_document(node: &Node) -> u64 {
    let store = &node.log_store;
    let _writing = store.document_writer.lock().await;
    let now_ms = node.now_ms();
    if !store.document_due(now_ms) {
        return store.document_ms();
    }
    let Ok(Some(writer)) = store.target(now_ms) else {
        return store.document_ms();
    };
    let nonce = node_document_nonce(&node.keys.sign_public());
    let Ok(document) = node.platform.attestation(&node.binding(), &nonce) else {
        return store.document_ms();
    };
    let object = StoreObject {
        shard: shard_hash(&node.node),
        key: node_document_key(&node.node),
        body: Bytes::from(node_document(
            node.platform.name(),
            &document,
            &node.node,
            node.release,
        )),
        retention_days: limits::NODE_DOCUMENT_RETENTION_DAYS,
    };
    if send_to_log_store(node, &writer, &object).await {
        // The time read before the write: the retention of the version the store holds ends
        // no earlier than 400 days after it.
        store.document_ms.fetch_max(now_ms, Ordering::SeqCst);
    } else {
        node.log_counters
            .write_failures
            .fetch_add(1, Ordering::Relaxed);
    }
    store.document_ms()
}

/// The sweep of the node (enclave.md section 3): every [`SWEEP_INTERVAL`], for every account, a
/// grant whose time passed is ended, the merge keys whose window passed and the kept `refresh`
/// responses whose time passed are dropped, and the pending entries are written again. A pending
/// entry is otherwise written again with the next write of its account only, so without the sweep
/// an account that makes no further call would leave a gap in the store for as long as it is
/// idle, and a reader of the store would take that gap for an omission. The task ends when the
/// orderly shutdown of the node starts.
pub async fn keep_sweeping(node: Arc<Node>) {
    loop {
        tokio::time::sleep(SWEEP_INTERVAL).await;
        if node.ensure_open().is_err() {
            return;
        }
        sweep(&node).await;
    }
}

/// One sweep ([`keep_sweeping`]), in three passes.
///
/// The first pass visits every account of the node once, in the order of the sorted index,
/// one chunk of the index at a time: it ends a grant whose time passed (as every read of the
/// state of an account does), drops the merge keys whose window passed and the kept `refresh`
/// responses whose time passed, and collects the accounts that have a pending entry.
///
/// The second pass visits the collected accounts one at a time, in an order the random source
/// of the platform shuffles. The pending entries of an account are written with the rules of
/// [`confirm`] (at most 32 at the same time, over the idle connections) when the oldest of
/// them has been pending for longer than a jitter drawn in `[0, SWEEP_INTERVAL)` for that
/// account; otherwise they wait for the next sweep. Over the whole node the sweep writes at
/// most `Limits::sweep_write_rate` entries per second (a token bucket with a burst of one
/// second), and the pass ends when the next sweep is due: the accounts it did not reach wait
/// for that sweep. The calls of an account whose entries were written look at their entries
/// again. An entry the store does not confirm stays pending for the next sweep.
///
/// The third pass reads the oldest pending entry of the collected accounts again and keeps its
/// `pending_since_ms` in the counts of the node (0 when none is left): `pending_oldest_ms` of
/// health is computed from it until the next sweep.
///
/// The random order and the jitter spread the writes of the accounts whose entries became
/// pending at one moment (an outage of the store) over two sweeps instead of one burst, and
/// the rate keeps the recovery from more than doubling the live load on the store.
pub async fn sweep(node: &Node) {
    // The node document first: a node whose document the store has not confirmed, or whose
    // latest confirmed write is 30 days old, writes it here when no call did (protocol.md 7.7).
    write_node_document(node).await;
    let now_ms = node.now_ms();
    let platform = node.platform.as_ref();
    let mut random = RandomDraws::new(platform);
    let mut pending_accounts: Vec<(String, Arc<Mutex<Account>>)> = Vec::new();
    for (user_id, account) in node.accounts_after("") {
        let mut guard = lock(&account);
        guard.expire(now_ms);
        guard.prune_recent(now_ms);
        guard.prune_refreshes(now_ms);
        if guard.oldest_pending_since_ms().is_some() {
            drop(guard);
            pending_accounts.push((user_id, account));
        }
    }
    shuffle(&mut pending_accounts, &mut random);
    let deadline = Instant::now() + SWEEP_INTERVAL;
    let mut bucket = TokenBucket::new(node.limits.sweep_write_rate);
    let interval_ms = u64::try_from(SWEEP_INTERVAL.as_millis()).unwrap_or(u64::MAX);
    for (_, account) in &pending_accounts {
        let waiting = {
            let guard = lock(account);
            guard
                .oldest_pending_since_ms()
                .map(|since_ms| (guard.pending_entries(), now_ms.saturating_sub(since_ms)))
        };
        let Some((pending, age_ms)) = waiting else {
            continue;
        };
        if node.ensure_open().is_err() {
            break;
        }
        if age_ms < random.next() % interval_ms {
            continue;
        }
        if !bucket.take(pending, deadline).await {
            break;
        }
        let _ = confirm(node, account, &[]).await;
        let notify = lock(account).notify.clone();
        notify.notify_waiters();
    }
    let oldest_since_ms = pending_accounts
        .iter()
        .filter_map(|(_, account)| lock(account).oldest_pending_since_ms())
        .min()
        .unwrap_or(0);
    node.counters
        .pending_oldest_since_ms
        .store(oldest_since_ms, Ordering::Relaxed);
}

/// Random values from the random source of the platform, read 512 bytes at a time. When the
/// source fails, every value is 0: the sweep then visits the accounts in one fixed order and
/// writes every pending entry without a jitter.
struct RandomDraws<'a> {
    platform: &'a dyn DynPlatform,
    buffer: [u8; 512],
    at: usize,
}

impl<'a> RandomDraws<'a> {
    fn new(platform: &'a dyn DynPlatform) -> RandomDraws<'a> {
        RandomDraws {
            platform,
            buffer: [0u8; 512],
            at: 512,
        }
    }

    fn next(&mut self) -> u64 {
        if self.at + 8 > self.buffer.len() {
            if self.platform.fill_random(&mut self.buffer).is_err() {
                return 0;
            }
            self.at = 0;
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.buffer[self.at..self.at + 8]);
        self.at += 8;
        u64::from_le_bytes(bytes)
    }
}

/// Puts `items` in a random order (Fisher-Yates).
fn shuffle<T>(items: &mut [T], random: &mut RandomDraws<'_>) {
    for remaining in (2..=items.len()).rev() {
        let chosen = usize::try_from(random.next() % remaining as u64).unwrap_or(0);
        items.swap(remaining - 1, chosen);
    }
}

/// The pace of the writes of the sweep: `rate` entries per second, with a burst of one second
/// of them. The tokens are counted in thousandths, and the count goes below zero when an
/// account has more entries than one second of the rate: that debt is paid before the next
/// account is written.
struct TokenBucket {
    rate: i64,
    tokens: i64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate: u32) -> TokenBucket {
        let rate = i64::from(rate.max(1));
        TokenBucket {
            rate,
            tokens: rate * 1000,
            last: Instant::now(),
        }
    }

    /// Takes the tokens of `count` entries, waiting for them to accrue, and returns false when
    /// they would accrue after `deadline`.
    async fn take(&mut self, count: usize, deadline: Instant) -> bool {
        let now = Instant::now();
        let accrued = i64::try_from(now.duration_since(self.last).as_millis()).unwrap_or(i64::MAX);
        let capacity = self.rate * 1000;
        self.tokens = self
            .tokens
            .saturating_add(accrued.saturating_mul(self.rate))
            .min(capacity);
        self.last = now;
        let needed = i64::try_from(count)
            .unwrap_or(i64::MAX)
            .saturating_mul(1000);
        let target = needed.min(capacity);
        if self.tokens < target {
            // The ceiling of the division: both values are positive here.
            let wait_ms = (target - self.tokens + self.rate - 1) / self.rate;
            let wait = Duration::from_millis(u64::try_from(wait_ms).unwrap_or(u64::MAX));
            if now + wait > deadline {
                return false;
            }
            tokio::time::sleep(wait).await;
            self.tokens = target;
            self.last = Instant::now();
        }
        self.tokens = self.tokens.saturating_sub(needed);
        true
    }
}

/// Step 3 of the common front, for a call that uses a credential: the node can write to its
/// log store, and the account has room for one more pending entry.
///
/// An account whose pending entries reached 64 gets no further entry from such a call before
/// the store confirmed some of them. The call writes the pending entries again here. When
/// they still wait after that, it ends with `log_store_unavailable` and creates no entry: an
/// account does not collect entries of acts that never took place without a bound.
pub async fn admit(node: &Node, account: &Mutex<Account>) -> Result<(), ProtocolError> {
    node.log_store.ensure_ready(node.now_ms())?;
    if lock(account).pending_entries() < PENDING_ENTRIES {
        return Ok(());
    }
    let _ = confirm(node, account, &[]).await;
    let (admitted, notify) = {
        let account = lock(account);
        (
            account.pending_entries() < PENDING_ENTRIES,
            account.notify.clone(),
        )
    };
    // A call that waits for one of the entries this round confirmed goes on now.
    notify.notify_waiters();
    match admitted {
        true => Ok(()),
        false => Err(ProtocolError::LogStoreUnavailable),
    }
}

/// Writes the entries `seqs` of an account and, with them, its pending entries. `Ok` when the
/// log store confirmed every entry of `seqs`: the act these entries describe may follow. An
/// entry of `seqs` that the store confirmed before is not written again.
///
/// A pending entry that is not confirmed does not fail the call. On a node that runs without
/// a log store nothing is written and the answer is `Ok`.
pub async fn confirm(
    node: &Node,
    account: &Mutex<Account>,
    seqs: &[u64],
) -> Result<(), ProtocolError> {
    if !node.log_store.tracks() {
        return Ok(());
    }
    let mut claim = [Claim::take(account, seqs)];
    write_claims(node, &mut claim).await;
    // The end of the claim records the answers of the store with the account, and the answer
    // of this call is read from the account: an entry is confirmed when the store said so,
    // to this call or to another one that wrote it.
    drop(claim);
    let account = lock(account);
    match seqs.iter().all(|seq| account.is_confirmed(*seq)) {
        true => Ok(()),
        false => Err(ProtocolError::LogStoreUnavailable),
    }
}

/// [`confirm`] for one entry of each of several accounts, with the writes of all of them
/// sharing the limit of 32 at the same time. `Ok` when the store confirmed every one of
/// these entries. After a failure, the entries the store confirmed stay confirmed. The round
/// runs beside the group commit of [`commit`]: a call of one of these accounts that writes in
/// the same time takes no entry this round is writing, except one its own act waits for, and
/// the waiting calls of these accounts look at their entries again when the round ends.
pub async fn confirm_each(
    node: &Node,
    entries: &[(&Mutex<Account>, u64)],
) -> Result<(), ProtocolError> {
    if !node.log_store.tracks() {
        return Ok(());
    }
    let mut claims: Vec<Claim<'_>> = entries
        .iter()
        .map(|(account, seq)| Claim::take(account, &[*seq]))
        .collect();
    write_claims(node, &mut claims).await;
    drop(claims);
    let mut outcome = true;
    for (account, seq) in entries {
        let (confirmed, notify) = {
            let account = lock(account);
            (account.is_confirmed(*seq), account.notify.clone())
        };
        outcome &= confirmed;
        notify.notify_waiters();
    }
    match outcome {
        true => Ok(()),
        false => Err(ProtocolError::LogStoreUnavailable),
    }
}

/// The group commit of one account for one call (protocol.md 7.1): writes the entries that
/// hold the events of the call and returns the place of every event.
///
/// `places` are where the events of the call are (one for a single call, up to
/// [`limits::FORWARD_BATCH_REQUESTS`] for a `forward/batch` call), each with whether this call
/// created the event. The call returns `Ok` when the store confirmed every entry that holds
/// one of its events: when no write of the account is in progress the call closes the open
/// batch, when its events are in it, and writes (it is the writer); while a write of the
/// account is in progress the call waits for its end and looks again. `Err(log_store_unavailable)`
/// when a write of an entry of the call was not confirmed or when the call waited for
/// twice the time of a write; `Err(closing)` when the node started its orderly shutdown while
/// the call waited.
///
/// On a node that runs without a log store the open batch is closed and every entry counts as
/// confirmed.
pub async fn commit(
    node: &Node,
    user_id: &str,
    account: &Arc<Mutex<Account>>,
    places: &[(EventPlace, bool)],
) -> Result<Vec<LogRef>, ProtocolError> {
    if !node.log_store.tracks() {
        let mut account = lock(account);
        node.close_batch(&mut account, user_id, node.now_ms())
            .map_err(|_| ProtocolError::Internal)?;
        return resolved(&account, places).ok_or(ProtocolError::Internal);
    }
    let deadline = tokio::time::Instant::now() + 2 * node.limits.log_write;
    let notify = lock(account).notify.clone();
    loop {
        enum Role {
            Done(Vec<LogRef>),
            Write(Vec<u64>),
            Wait,
        }
        // The notification is taken before the state is read: a write that ends between the
        // reading and the waiting wakes this call all the same.
        let notified = notify.notified();
        let role = {
            let mut account = lock(account);
            if let Some(refs) = resolved(&account, places) {
                Role::Done(refs)
            } else if account.writer {
                Role::Wait
            } else {
                let open = places.iter().any(|(place, _)| place.seq().is_none());
                if open {
                    node.close_batch(&mut account, user_id, node.now_ms())
                        .map_err(|_| ProtocolError::Internal)?;
                }
                let seqs: Vec<u64> = places
                    .iter()
                    .filter_map(|(place, _)| place.seq())
                    .filter(|seq| !account.is_confirmed(*seq))
                    .collect();
                account.writer = true;
                Role::Write(seqs)
            }
        };
        match role {
            Role::Done(refs) => return Ok(refs),
            Role::Write(seqs) => {
                let mut guard = WriterGuard {
                    node,
                    user_id,
                    account,
                    armed: true,
                };
                let outcome = confirm(node, account, &seqs).await;
                guard.armed = false;
                let refs = end_write(node, user_id, account, places);
                outcome?;
                return refs.ok_or(ProtocolError::LogStoreUnavailable);
            }
            Role::Wait => {
                node.ensure_open()?;
                if tokio::time::timeout_at(deadline, notified).await.is_err() {
                    return Err(ProtocolError::LogStoreUnavailable);
                }
            }
        }
    }
}

/// The `log` objects of `places` when every entry that holds one of them exists and the store
/// confirmed it, `None` while one of them is in an open batch or in an unconfirmed entry.
fn resolved(account: &Account, places: &[(EventPlace, bool)]) -> Option<Vec<LogRef>> {
    places
        .iter()
        .map(|(place, created)| {
            let seq = place.seq()?;
            account.is_confirmed(seq).then_some(LogRef {
                seq,
                index: place.index(),
                created: *created,
            })
        })
        .collect()
}

/// Ends the write of the writer of an account: the account has no writer, the events that
/// arrived while the write ran form the next entry (which the next writer writes), and the
/// waiting calls look at their entries again. Returns [`resolved`] for `places`.
fn end_write(
    node: &Node,
    user_id: &str,
    account: &Mutex<Account>,
    places: &[(EventPlace, bool)],
) -> Option<Vec<LogRef>> {
    let (notify, refs) = {
        let mut account = lock(account);
        account.writer = false;
        if account.has_open_events() {
            let _ = node.close_batch(&mut account, user_id, node.now_ms());
        }
        (account.notify.clone(), resolved(&account, places))
    };
    notify.notify_waiters();
    refs
}

/// Ends the write of a call whose future is dropped before its write ended (its caller went
/// away): without it the account would keep a writer that never ends, and every later call of
/// the account would wait for it. The entries of the write stay pending (`Claim`).
struct WriterGuard<'a> {
    node: &'a Node,
    user_id: &'a str,
    account: &'a Mutex<Account>,
    armed: bool,
}

impl Drop for WriterGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            end_write(self.node, self.user_id, self.account, &[]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credential_enclave_protocol::log::{object_key_v3, EntryKey, EntryLabel};

    /// The object of a use entry of two events of the account `user 1`, created at
    /// 2026-10-01T12:10:45.000Z by the node whose signing public key is 32 bytes of 0x4e.
    fn entry_object() -> StoreObject {
        let key = EntryKey {
            time_ms: 1_790_856_645_000,
            node: credential_enclave_protocol::encoding::b64u(&[0x4e; 32]),
            seq: 7,
            label: EntryLabel::Use(2),
            key_id: "0123456789abcdef".to_string(),
            body_hash: [0xfb; 32],
        };
        StoreObject {
            shard: shard_hash("user 1"),
            key: object_key_v3("user 1", &key),
            body: Bytes::from_static(br#"{"body":"Ym9keQ","sig":"c2ln"}"#),
            retention_days: limits::LOG_RETENTION_DAYS,
        }
    }

    fn credentials(session_token: &str) -> Credentials {
        Credentials::new(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token,
            u64::MAX,
        )
        .unwrap()
    }

    /// The example "PUT Object" of the Amazon S3 API reference, "Signature Calculations for
    /// the Authorization Header: Transferring Payload in a Single Chunk (AWS Signature
    /// Version 4)": the request `PUT /test$file.text` to `examplebucket.s3.amazonaws.com` in
    /// `us-east-1` on 2013-05-24 with the body `Welcome to Amazon S3.`.
    #[test]
    fn the_signature_is_the_one_of_the_put_object_example_of_aws() {
        let payload_sha256 = hex(&Sha256::digest(b"Welcome to Amazon S3."));
        assert_eq!(
            payload_sha256,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        let path = object_path("test$file.text");
        assert_eq!(path, "/test%24file.text");
        let headers = [
            ("date", "Fri, 24 May 2013 00:00:00 GMT".to_string()),
            ("host", "examplebucket.s3.amazonaws.com".to_string()),
            ("x-amz-content-sha256", payload_sha256.clone()),
            ("x-amz-date", "20130524T000000Z".to_string()),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY".to_string()),
        ];
        assert_eq!(
            credentials("").authorization(
                "us-east-1",
                "PUT",
                &path,
                &headers,
                &payload_sha256,
                "20130524T000000Z"
            ),
            concat!(
                "AWS4-HMAC-SHA256 ",
                "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,",
                "SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,",
                "Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
            )
        );
    }

    /// The example "GET Object" of the same page: a request without a body, whose headers
    /// are given here in another order than the order of their names.
    #[test]
    fn the_signature_is_the_one_of_the_get_object_example_of_aws() {
        let empty = hex(&Sha256::digest(b""));
        let headers = [
            ("x-amz-date", "20130524T000000Z".to_string()),
            ("range", "bytes=0-9".to_string()),
            ("x-amz-content-sha256", empty.clone()),
            ("host", "examplebucket.s3.amazonaws.com".to_string()),
        ];
        let authorization = credentials("").authorization(
            "us-east-1",
            "GET",
            "/test.txt",
            &headers,
            &empty,
            "20130524T000000Z",
        );
        assert!(authorization.ends_with(concat!(
            "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,",
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        )));
    }

    /// The example of "Deriving a signing key" of the AWS general reference: the key of
    /// 2012-02-15 for the service `iam` in `us-east-1`.
    #[test]
    fn the_signing_key_is_a_chain_of_hmac_sha256() {
        let mut key = hmac_sha256(b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", b"20120215");
        for part in ["us-east-1", "iam", "aws4_request"] {
            key = hmac_sha256(key.as_slice(), part.as_bytes());
        }
        assert_eq!(
            hex(key.as_slice()),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    #[test]
    fn a_session_token_is_a_signed_header() {
        let headers = [
            ("host", "bucket.s3.us-west-2.amazonaws.com".to_string()),
            ("x-amz-date", "20261001T120000Z".to_string()),
        ];
        let sign = |token: &str| {
            credentials(token).authorization(
                "us-west-2",
                "PUT",
                "/v1/x",
                &headers,
                "00",
                "20261001T120000Z",
            )
        };
        let without = sign("");
        assert!(without.contains(",SignedHeaders=host;x-amz-date,"));
        let with = sign("TOKEN");
        assert!(with.contains(",SignedHeaders=host;x-amz-date;x-amz-security-token,"));
        assert!(
            with.contains("Credential=AKIAIOSFODNN7EXAMPLE/20261001/us-west-2/s3/aws4_request,")
        );
        // The signature covers the value of the token, and no part of the header value is
        // the token or the secret access key.
        assert_ne!(sign("TOKEN"), sign("OTHER"));
        assert!(!with.contains("TOKEN") && !with.contains("wJalrXUtnFEMI"));
    }

    #[test]
    fn the_write_of_an_entry_is_a_put_with_a_retention_in_compliance_mode() {
        let id = LogStoreId::parse("character-credential-log-dev-1", "us-west-2").unwrap();
        let writer = Writer {
            id,
            credentials: Arc::new(credentials("TOKEN")),
            endpoint: None,
        };
        let object = entry_object();
        // 2026-10-01T12:10:45.123Z.
        let request = put_request(&writer, &object, 1_790_856_645_123).unwrap();
        let body = br#"{"body":"Ym9keQ","sig":"c2ln"}"#;
        let digest = Sha256::digest(body);
        // The bucket of the account among the 32 buckets of the log store, as the first part
        // of the path, and the key with its space percent-encoded.
        let path = concat!(
            "/BUCKET/a3/user%201/u/8209143354999.",
            "Tk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk4.7.2.0123456789abcdef.",
            "-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s"
        )
        .replace("BUCKET", ENTRY_BUCKET);
        assert_eq!(
            writer.id.shard_of(shard_hash("user 1")).as_deref(),
            Some(ENTRY_BUCKET)
        );
        assert_eq!(request.method(), Method::PUT);
        assert_eq!(request.uri().to_string(), path);
        assert_eq!(
            hyper::body::Body::size_hint(request.body()).exact(),
            Some(body.len() as u64)
        );
        let headers: Vec<(&str, &str)> = request
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str(), value.to_str().unwrap()))
            .collect();
        let authorization = request.headers()[AUTHORIZATION].to_str().unwrap();
        assert_eq!(
            headers,
            [
                ("content-length", "30"),
                ("content-type", "application/json"),
                // The endpoint of Amazon S3 in the region: one host for every bucket.
                ("host", "s3.us-west-2.amazonaws.com"),
                ("x-amz-checksum-sha256", STANDARD.encode(digest).as_str()),
                ("x-amz-content-sha256", hex(&digest).as_str()),
                ("x-amz-date", "20261001T121045Z"),
                ("x-amz-object-lock-mode", "COMPLIANCE"),
                // 365 days after the write.
                (
                    "x-amz-object-lock-retain-until-date",
                    "2027-10-01T12:10:45Z"
                ),
                // The object is encrypted under a key the store manages, whatever the
                // default encryption of the bucket names.
                ("x-amz-server-side-encryption", "AES256"),
                ("x-amz-security-token", "TOKEN"),
                ("authorization", authorization),
            ]
        );
        // The request asks for no condition on the key: the store answers 200 only when it
        // stored this object with this retention.
        assert!(!request.headers().contains_key("if-none-match"));
        assert!(request.headers()[SECURITY_TOKEN].is_sensitive());
        assert!(!format!("{:?}", request.headers()).contains("TOKEN"));
        // Every header but the length of the body is
        // signed: signing the headers of the request again gives its `Authorization`.
        let signed: Vec<(&str, String)> = headers[1..9]
            .iter()
            .map(|(name, value)| (*name, value.to_string()))
            .collect();
        assert_eq!(
            authorization,
            writer.credentials.authorization(
                "us-west-2",
                "PUT",
                &path,
                &signed,
                &hex(&digest),
                "20261001T121045Z"
            )
        );
        // The signature is the one the AWS SDK for Python computes for this request
        // (botocore 1.44, `S3SigV4Auth`, with the payload signed): the same credentials, the same
        // time, the same address, headers and body.
        assert_eq!(
            authorization,
            concat!(
                "AWS4-HMAC-SHA256 ",
                "Credential=AKIAIOSFODNN7EXAMPLE/20261001/us-west-2/s3/aws4_request,",
                "SignedHeaders=content-type;host;x-amz-checksum-sha256;x-amz-content-sha256;",
                "x-amz-date;x-amz-object-lock-mode;x-amz-object-lock-retain-until-date;",
                "x-amz-security-token;x-amz-server-side-encryption,",
                "Signature=a40d27e2808e59e841bb30d9a9c2b1261ff6eb15a132b947782dfce5caf7bd4f"
            )
        );

        // The same request with credentials that have no session, and the request for a key
        // whose `user_id` holds characters that are percent-encoded: both signatures are
        // those of the same SDK.
        let without_session = Writer {
            id: writer.id.clone(),
            credentials: Arc::new(credentials("")),
            endpoint: None,
        };
        let request = put_request(&without_session, &object, 1_790_856_645_123).unwrap();
        assert!(!request.headers().contains_key(SECURITY_TOKEN));
        let authorization = request.headers()[AUTHORIZATION].to_str().unwrap();
        assert!(authorization.ends_with(concat!(
            "x-amz-object-lock-retain-until-date;x-amz-server-side-encryption,",
            "Signature=b1c37459bc9dced671f44841f26bfcb24fd7f6c172847c42bd750b27ef7bacae"
        )));
        let path = format!("/{ENTRY_BUCKET}{}", object_path("a3/a b/ü$%+=&?#:@/c/1.x"));
        assert_eq!(
            path,
            format!("/{ENTRY_BUCKET}/a3/a%20b/%C3%BC%24%25%2B%3D%26%3F%23%3A%40/c/1.x")
        );
        let authorization = writer.credentials.authorization(
            "us-west-2",
            "PUT",
            &path,
            &signed,
            &hex(&digest),
            "20261001T121045Z",
        );
        assert!(authorization.ends_with(
            "Signature=7764384b5f0539846979686ac42b61cebc9f055f1365f140db82aca56329ee71"
        ));
    }

    /// The bucket of the account `user 1` among the buckets of the log store
    /// `character-credential-log-dev-1`.
    const ENTRY_BUCKET: &str = "785f2d9e-character-credential-log-dev-1-0021";

    #[test]
    fn the_node_document_is_written_with_a_retention_of_400_days() {
        let id = LogStoreId::parse("character-credential-log-dev-1", "us-west-2").unwrap();
        let writer = Writer {
            id,
            credentials: Arc::new(credentials("")),
            endpoint: None,
        };
        let node = credential_enclave_protocol::encoding::b64u(&[0x4e; 32]);
        let object = StoreObject {
            shard: shard_hash(&node),
            key: node_document_key(&node),
            body: Bytes::from(node_document("nitro", b"document", &node, "v2.4.0")),
            retention_days: limits::NODE_DOCUMENT_RETENTION_DAYS,
        };
        let request = put_request(&writer, &object, 1_790_856_645_123).unwrap();
        // The bucket of the node, not of an account.
        let bucket = writer.id.shard_of(shard_hash(&node)).unwrap();
        assert_eq!(request.uri().to_string(), format!("/{bucket}/n3/{node}"));
        assert_eq!(
            request.headers()["x-amz-object-lock-retain-until-date"],
            "2027-11-05T12:10:45Z"
        );
        assert_eq!(request.headers()["x-amz-object-lock-mode"], "COMPLIANCE");
        assert_eq!(request.headers()["x-amz-server-side-encryption"], "AES256");
    }

    #[test]
    fn a_log_store_without_a_bucket_for_the_object_gives_no_request() {
        // The name is too long for the names of its buckets to be bucket names.
        let id = LogStoreId::parse(&"b".repeat(50), "us-west-2").unwrap();
        let writer = Writer {
            id,
            credentials: Arc::new(credentials("")),
            endpoint: None,
        };
        assert!(put_request(&writer, &entry_object(), 1_790_856_645_123).is_none());
    }

    #[test]
    fn a_local_endpoint_is_written_in_path_style_with_its_own_host() {
        let id = LogStoreId::parse("character-credential-log-local-1", "us-west-2").unwrap();
        let endpoint =
            LogStoreEndpoint::parse("http://minio.character.svc.cluster.local:9000").unwrap();
        assert_eq!(
            endpoint,
            LogStoreEndpoint {
                tls: false,
                host: "minio.character.svc.cluster.local".to_string(),
                port: 9000,
            }
        );
        assert_eq!(
            endpoint.authority(),
            "minio.character.svc.cluster.local:9000"
        );
        assert_eq!(
            LogStoreEndpoint::parse("https://s3.local")
                .unwrap()
                .authority(),
            "s3.local"
        );
        for text in [
            "minio:9000",
            "ftp://minio:9000",
            "http://minio:9000/bucket",
            "http://user@minio:9000",
            "http://minio:0",
            "http://mi nio",
            "http://",
        ] {
            assert_eq!(LogStoreEndpoint::parse(text), None, "{text}");
        }
        let writer = Writer {
            id,
            credentials: Arc::new(credentials("")),
            endpoint: Some(endpoint),
        };
        let object = entry_object();
        let request = put_request(&writer, &object, 1_790_856_645_123).unwrap();
        // The same path as for Amazon S3, with the bucket of the account among the four
        // buckets of this log store.
        let bucket = writer.id.shard_of(shard_hash("user 1")).unwrap();
        assert!(
            bucket.ends_with("-character-credential-log-local-1-0001"),
            "{bucket}"
        );
        assert_eq!(
            request.uri().to_string(),
            format!(
                concat!(
                    "/{}/a3/user%201/u/8209143354999.",
                    "Tk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk4.7.2.0123456789abcdef.",
                    "-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s"
                ),
                bucket
            )
        );
        assert_eq!(
            request.headers()["host"],
            "minio.character.svc.cluster.local:9000"
        );
        // The signature covers the path-style target and the host of the endpoint.
        let authorization = request.headers()[AUTHORIZATION].to_str().unwrap();
        assert!(authorization
            .contains("Credential=AKIAIOSFODNN7EXAMPLE/20261001/us-west-2/s3/aws4_request,"));
    }

    #[test]
    fn times_are_written_in_utc() {
        for (time_ms, date, until) in [
            (0, "19700101T000000Z", "1970-01-01T00:00:00Z"),
            (
                1_369_353_600_000,
                "20130524T000000Z",
                "2013-05-24T00:00:00Z",
            ),
            (951_782_399_999, "20000228T235959Z", "2000-02-28T23:59:59Z"),
            (951_782_400_000, "20000229T000000Z", "2000-02-29T00:00:00Z"),
            (
                1_709_251_199_000,
                "20240229T235959Z",
                "2024-02-29T23:59:59Z",
            ),
            (
                1_790_856_645_123,
                "20261001T121045Z",
                "2026-10-01T12:10:45Z",
            ),
            (
                1_798_761_599_000,
                "20261231T235959Z",
                "2026-12-31T23:59:59Z",
            ),
            (
                1_798_761_600_000,
                "20270101T000000Z",
                "2027-01-01T00:00:00Z",
            ),
            // 2100 is no leap year.
            (
                4_107_542_400_000,
                "21000301T000000Z",
                "2100-03-01T00:00:00Z",
            ),
        ] {
            assert_eq!(amz_date(time_ms), date, "{time_ms}");
            assert_eq!(retain_until(time_ms), until, "{time_ms}");
        }
    }

    #[test]
    fn the_path_of_an_object_is_its_key_with_every_part_encoded_once() {
        // A key of format 3 of an account whose `user_id` is letters, digits and `-` has no
        // character that is encoded: its parts are digits, letters, `-`, `_` and `.`.
        let key = EntryKey {
            time_ms: 1_790_000_000_000,
            node: credential_enclave_protocol::encoding::b64u(&[0x4e; 32]),
            seq: 2,
            label: EntryLabel::Control("grant_accepted".to_string()),
            key_id: "0123456789abcdef".to_string(),
            body_hash: [0xfb; 32],
        };
        let key = object_key_v3("user-1", &key);
        assert_eq!(object_path(&key), format!("/{key}"));
        let node = credential_enclave_protocol::encoding::b64u(&[0x4e; 32]);
        assert_eq!(
            object_path(&node_document_key(&node)),
            format!("/n3/{node}")
        );
        // Every part of a key is encoded once, and `/` stays.
        assert_eq!(
            object_path("a3/a b/ü$%+=&?#:@/c/1.x"),
            "/a3/a%20b/%C3%BC%24%25%2B%3D%26%3F%23%3A%40/c/1.x"
        );
        assert_eq!(object_path("A-Za-z0-9-._~"), "/A-Za-z0-9-._~");
    }

    #[test]
    fn credentials_have_the_form_of_their_kind() {
        assert!(Credentials::new("ASIAEXAMPLE", "secret/+=", "token/+=", 1).is_some());
        assert!(Credentials::new("ASIAEXAMPLE", "secret", "", 1).is_some());
        let long = "t".repeat(SESSION_TOKEN_BYTES);
        assert!(Credentials::new("ASIAEXAMPLE", "secret", &long, 1).is_some());
        for (access_key_id, secret_access_key, session_token) in [
            ("", "secret", "token"),
            ("ASIA EXAMPLE", "secret", "token"),
            ("ASIA/EXAMPLE", "secret", "token"),
            (&"A".repeat(129)[..], "secret", "token"),
            ("ASIAEXAMPLE", "", "token"),
            ("ASIAEXAMPLE", "sec ret", "token"),
            ("ASIAEXAMPLE", "secret\r\nx-amz-acl: public-read", "token"),
            ("ASIAEXAMPLE", &"s".repeat(257)[..], "token"),
            ("ASIAEXAMPLE", "secret", "to ken"),
            ("ASIAEXAMPLE", "secret", "token\r\nx-amz-acl: public-read"),
            ("ASIAEXAMPLE", "secret", "tokén"),
            ("ASIAEXAMPLE", "secret", &format!("{long}t")[..]),
        ] {
            assert!(
                Credentials::new(access_key_id, secret_access_key, session_token, 1).is_none(),
                "{access_key_id:?} {session_token:?}"
            );
        }
    }

    #[test]
    fn a_log_store_is_named_once_and_its_credentials_end() {
        let first = LogStoreId::parse("bucket-one", "us-west-2").unwrap();
        let second = LogStoreId::parse("bucket-two", "us-west-2").unwrap();

        // A node that runs without a log store: nothing to write, and that is no failure.
        let optional = LogStore::new(false);
        assert!(!optional.tracks());
        assert!(optional.writer(5).unwrap().is_none());
        assert_eq!(optional.ensure_ready(5), Ok(()));
        assert_eq!(optional.ensure_documented(5), Ok(()));
        // With a log store it needs credentials within their time, and its node document in
        // the store.
        assert!(optional.set_id(first.clone()));
        assert!(optional.tracks());
        assert_eq!(optional.id(), Some(&first));
        assert_eq!(optional.credentials_expires_ms(), 0);
        assert_eq!(
            optional.ensure_ready(5),
            Err(ProtocolError::LogStoreUnavailable)
        );
        optional.set_credentials(Credentials::new("ASIAEXAMPLE", "secret", "token", 10).unwrap());
        assert_eq!(optional.credentials_expires_ms(), 10);
        // The node can sign a write, and writes no entry before its node document.
        assert!(optional.target(9).unwrap().is_some());
        assert_eq!(
            optional.ensure_ready(9),
            Err(ProtocolError::LogStoreUnavailable)
        );
        assert_eq!(
            optional.ensure_documented(9),
            Err(ProtocolError::LogStoreUnavailable)
        );
        optional.document_ms.store(4, Ordering::SeqCst);
        assert_eq!(optional.ensure_ready(9), Ok(()));
        assert_eq!(optional.ensure_documented(9), Ok(()));
        assert_eq!(
            optional.ensure_ready(10),
            Err(ProtocolError::LogStoreUnavailable)
        );
        // The document covers a transfer without credentials within their time.
        assert_eq!(optional.ensure_documented(10), Ok(()));
        // The same log store again is taken, another one is not.
        assert!(optional.set_id(first.clone()));
        assert!(!optional.set_id(second));
        assert_eq!(optional.id(), Some(&first));

        // A node whose platform requires a log store does not run without one.
        let required = LogStore::new(true);
        assert!(required.tracks());
        assert_eq!(
            required.ensure_ready(5),
            Err(ProtocolError::LogStoreUnavailable)
        );
        assert_eq!(
            required.ensure_documented(5),
            Err(ProtocolError::LogStoreUnavailable)
        );
        required.set_credentials(Credentials::new("ASIAEXAMPLE", "secret", "token", 10).unwrap());
        assert_eq!(
            required.ensure_ready(5),
            Err(ProtocolError::LogStoreUnavailable)
        );
        assert!(required.set_id(first));
        assert_eq!(
            required.ensure_ready(5),
            Err(ProtocolError::LogStoreUnavailable)
        );
        required.document_ms.store(4, Ordering::SeqCst);
        assert_eq!(required.ensure_ready(5), Ok(()));

        // A log store whose name is too long for the names of its buckets is not taken.
        let unnamed = LogStore::new(true);
        assert!(!unnamed.set_id(LogStoreId::parse(&"b".repeat(50), "us-west-2").unwrap()));
        assert_eq!(unnamed.id(), None);
        assert!(unnamed.set_id(LogStoreId::parse(&"b".repeat(49), "us-west-2").unwrap()));
    }

    #[test]
    fn the_node_document_covers_31_days_and_is_due_after_30() {
        let store = LogStore::new(true);
        // No write confirmed: due, and it covers nothing.
        assert!(store.document_due(1_000));
        assert!(!store.document_covers(1_000));
        let written_ms = 1_790_000_000_000;
        store.document_ms.store(written_ms, Ordering::SeqCst);
        let renew_ms = written_ms + 30 * DAY_MS;
        let end_ms = written_ms + 31 * DAY_MS;
        assert!(!store.document_due(renew_ms - 1));
        assert!(store.document_due(renew_ms));
        assert!(store.document_covers(end_ms - 1));
        assert!(!store.document_covers(end_ms));
        // An entry written inside the 31 days is unlocked before the version of the document
        // the node relied on: its retention ends 365 days after its write, the retention of
        // the document 400 days after the write of the document.
        let entry_unlocked_ms = (end_ms - 1) + limits::LOG_RETENTION_DAYS * DAY_MS;
        let document_unlocked_ms = written_ms + limits::NODE_DOCUMENT_RETENTION_DAYS * DAY_MS;
        assert!(entry_unlocked_ms < document_unlocked_ms);
    }

    #[tokio::test]
    async fn futures_run_together_and_answer_in_their_order() {
        // The first future ends only after the second one ran, and the third only after the
        // second: the three run at the same time, and the outputs keep their order.
        let (first, third) = (tokio::sync::Notify::new(), tokio::sync::Notify::new());
        let step = |index: u8| {
            let (first, third) = (&first, &third);
            async move {
                match index {
                    1 => first.notified().await,
                    3 => third.notified().await,
                    _ => {
                        first.notify_one();
                        third.notify_one();
                    }
                }
                index
            }
        };
        assert_eq!(join_all([1, 2, 3].into_iter().map(step)).await, [1, 2, 3]);
        let none = join_all(std::iter::empty::<std::future::Ready<u8>>()).await;
        assert!(none.is_empty());
    }
}
