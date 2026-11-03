//! The log store (protocol.md 7.6, enclave.md 5.14): the place outside the node where an entry
//! is written before the act it describes.
//!
//! A node writes every entry of a chain to an Amazon S3 bucket whose objects are locked in
//! compliance mode: until its retention ends, nobody can delete an object version or shorten
//! its retention. The node acts only after the store confirmed the entry of the act. TLS ends
//! inside the node, so whoever carries the bytes cannot answer in the place of the store.
//!
//! What this module holds:
//!
//! - [`LogStore`]: which bucket the node writes to (set once, part of the binding of the
//!   attestation) and the credentials of the operator for it;
//! - [`admit`], [`confirm`] and [`confirm_each`]: the steps a call takes before it acts;
//! - `send_to_log_store`, sink K5 of the egress policy: the one function that writes to the
//!   store. What it writes is a signed entry, whose content is sealed to the log public key
//!   of the account, signed with the credentials of the operator. No function here takes a
//!   user key, the plaintext of a record or a token of a provider.
//!
//! A write is confirmed by the status 200 of the store and by nothing else. The node does not
//! ask the store whether an object of that key exists: the operator domain can write to the
//! same bucket with the same credentials, and it knows the key of an entry from the head of
//! the chain as soon as the entry exists. An answer "this key exists" would say nothing about
//! who wrote the object, what it holds and how long it is kept. A write that is repeated
//! (the answer of the first one was lost) adds a second version of the same object.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::task::Poll;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use credential_enclave_protocol::encoding::{to_json, Signed};
use credential_enclave_protocol::keys::LogStoreId;
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
    /// The bucket and its region. Set once: the binding of the attestation names it, and what
    /// a verifier read there holds for as long as the node lives.
    id: OnceLock<LogStoreId>,
    /// The endpoint of a node of the local platform, set once with the log store.
    endpoint: OnceLock<Option<LogStoreEndpoint>>,
    credentials: RwLock<Option<Arc<Credentials>>>,
    idle: IdleConnections,
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
        }
    }

    /// The log store of this node, when the operator configuration named one.
    pub fn id(&self) -> Option<&LogStoreId> {
        self.id.get()
    }

    /// Names the log store of this node. False when the node has another one: a log store
    /// does not change.
    pub fn set_id(&self, id: LogStoreId) -> bool {
        self.id.get_or_init(|| id.clone()) == &id
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

    /// What a write needs. `Ok(None)` for a node that runs without a log store (the local
    /// platform without one in its configuration). `log_store_unavailable` when the node
    /// lacks the configuration or credentials within their time.
    fn writer(&self, now_ms: u64) -> Result<Option<Writer>, ProtocolError> {
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

    /// The node can write to its log store now, or it runs without one.
    pub fn ensure_ready(&self, now_ms: u64) -> Result<(), ProtocolError> {
        self.writer(now_ms).map(|_| ())
    }

    /// The idle connections to the log store at this moment (`log_store` of
    /// `idle_connections` of health).
    pub fn idle_connections(&self) -> usize {
        lock(&self.idle.0).len()
    }
}

/// One entry in the hands of a call.
struct Write {
    seq: u64,
    /// The key of the object of the entry (protocol.md 7.6).
    key: String,
    entry: Signed,
    /// True for an entry an act of the call waits for.
    required: bool,
    confirmed: bool,
    /// True when an attempt of this call may have reached the store without a confirmation
    /// ([`WriteOutcome::outcome_unknown`]). Copied from the attempts after a round.
    outcome_unknown: bool,
    /// Set by an attempt just before its request leaves, cleared when the store answered it
    /// with a status: while it is set, the request may be with the store. It is read when the
    /// call that owns the write ends before its round ends (`Claim::drop`), where the round
    /// has not copied its outcome yet.
    in_flight: AtomicBool,
    /// Set by an attempt that ended with the connection closed without a response, passed its
    /// time limit after the request left, or was answered with a 5xx status: the store may hold
    /// the object. Never cleared: a later attempt that failed before a byte left changes
    /// nothing about the earlier one.
    may_be_stored: AtomicBool,
}

impl Write {
    /// True when some attempt of this call may have reached the store without a confirmation:
    /// an attempt left its request and got no answer yet, or an earlier attempt ended in a
    /// state where the store may hold the object.
    fn may_have_reached_the_store(&self) -> bool {
        self.in_flight.load(Ordering::Relaxed) || self.may_be_stored.load(Ordering::Relaxed)
    }
}

/// The end of the attempts of one entry ([`send_to_log_store`]).
#[derive(Clone, Copy)]
struct WriteOutcome {
    /// The store confirmed the entry.
    confirmed: bool,
    /// Not confirmed, and an attempt may have reached the store all the same: the connection
    /// closed without a response, or the attempt passed its time limit after the request may
    /// have been sent. An attempt that failed before any request byte left the node (the
    /// connection, the TLS handshake) and an attempt the store answered with a status other
    /// than 200 did not store the object.
    outcome_unknown: bool,
}

/// The entries of one account that a call writes: the entries the call names and the pending
/// entries of the account. While the claim lives, no other call takes the pending ones along.
/// When it is dropped, the entries the store confirmed leave the account, and the others
/// become pending entries: also when the call ends before its writes do.
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
            if required || !entry.writing {
                entry.writing = true;
                writes.push(Write {
                    seq: entry.seq,
                    key: entry.key.clone(),
                    entry: entry.entry.clone(),
                    required,
                    confirmed: false,
                    outcome_unknown: false,
                    in_flight: AtomicBool::new(false),
                    may_be_stored: AtomicBool::new(false),
                });
            }
        }
        Claim { account, writes }
    }

    /// True when the store confirmed every entry that an act waits for. An entry that was
    /// confirmed before is not among the writes.
    fn holds(&self) -> bool {
        self.writes
            .iter()
            .all(|write| write.confirmed || !write.required)
    }
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        let mut account = lock(self.account);
        for write in &self.writes {
            if write.confirmed {
                account.confirm_entry(write.seq);
            } else if let Some(entry) = account
                .unconfirmed_mut()
                .find(|entry| entry.seq == write.seq)
            {
                entry.writing = false;
                entry.outcome_unknown |=
                    write.outcome_unknown || write.may_have_reached_the_store();
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
/// that were not written stay with their accounts.
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
        let outcomes = join_all(round.iter().map(|(at, index)| {
            let claim = &claims[*at];
            send_to_log_store(node, &writer, &claim.writes[*index])
        }))
        .await;
        let failed = outcomes.iter().filter(|outcome| !outcome.confirmed).count();
        node.log_counters
            .write_failures
            .fetch_add(failed as u64, Ordering::Relaxed);
        for ((at, index), outcome) in round.iter().zip(&outcomes) {
            let write = &mut claims[*at].writes[*index];
            write.confirmed = outcome.confirmed;
            write.outcome_unknown |= outcome.outcome_unknown;
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

/// Sink K5 of the egress policy: writes one entry to the log store and returns whether the
/// store confirmed the write and, when it did not, whether an attempt may have reached the store
/// (its request left and the connection closed or the time limit passed without an answer, or
/// the store answered with a 5xx status: the orderly shutdown drops no such entry, enclave.md
/// 5.11).
///
/// What leaves is the signed entry (its content is sealed to the log public key of the
/// account) under the key of protocol.md 7.6 ([`object_key`]), with a retention in compliance
/// mode until 365 days from now, and the request is signed with the credentials of the
/// operator. The connection goes to `{bucket}.s3.{region}.amazonaws.com`: TLS ends inside the
/// node and the certificate is verified against the trust roots of the binary.
///
/// The attempts of one entry share a budget of twice the time limit of a write. The first
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
async fn send_to_log_store(node: &Node, writer: &Writer, write: &Write) -> WriteOutcome {
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
        match write_once(node, writer, write, attempts == 1, limit.min(remaining)).await {
            Ok(()) => {
                let elapsed_ms =
                    u64::try_from(attempt_started.elapsed().as_millis()).unwrap_or(u64::MAX);
                counters.record_confirmed(elapsed_ms);
                return WriteOutcome {
                    confirmed: true,
                    outcome_unknown: false,
                };
            }
            Err((cause, repeated)) => {
                counters.write_attempt_failures.count(cause);
                // The request may have reached the store when it left (the connection closed
                // without a response, or the time limit passed after it left) and when the
                // store answered with a 5xx status (S3 promises nothing about the object of
                // such an answer). A time limit that passed while the connection opened, and
                // every failure before a byte left, say the object is not there.
                if write.in_flight.load(Ordering::Relaxed)
                    || matches!(cause, WriteFailure::Status5xx)
                {
                    write.may_be_stored.store(true, Ordering::Relaxed);
                }
                write.in_flight.store(false, Ordering::Relaxed);
                let failed = WriteOutcome {
                    confirmed: false,
                    outcome_unknown: write.may_be_stored.load(Ordering::Relaxed),
                };
                if !repeated {
                    return failed;
                }
                let backoff = full_jitter(
                    node.platform.as_ref(),
                    attempts,
                    WRITE_BACKOFF_BASE,
                    WRITE_BACKOFF_CAP,
                );
                if started.elapsed() + backoff + WRITE_RETRY_MARGIN > budget {
                    return failed;
                }
                counters.write_retries.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

/// One attempt of [`send_to_log_store`]: one `PUT` of the entry, over an idle connection when
/// `first` and there is one (with half of `limit`), else over a new connection (with `limit`,
/// which also bounds the open). `Ok` is the status 200.
async fn write_once(
    node: &Node,
    writer: &Writer,
    write: &Write,
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
            put_request(writer, write, node.now_ms()).ok_or((WriteFailure::Connect, false))?;
        // From here the request may be with the store, until the store answered it. A call
        // that ends during the wait leaves the flag set.
        write.in_flight.store(true, Ordering::Relaxed);
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| (WriteFailure::Closed, true))?;
        write.in_flight.store(false, Ordering::Relaxed);
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

/// A new connection to the log store: to the host of the bucket, or to the endpoint of a node
/// of the local platform (enclave.md 5.14). `budget` is the time limit of the attempt.
async fn open_log_connection(
    node: &Node,
    writer: &Writer,
    budget: Duration,
) -> Result<SendRequest<OnceBody>, AttemptFailure> {
    let opened = match &writer.endpoint {
        None => {
            node.egress
                .open(node.platform.as_ref(), &writer.id.host(), budget)
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

/// The request that writes one entry (protocol.md 7.6): `PUT` of the signed entry as the node
/// carries it in a response, `{"body":"...","sig":"..."}`, under the key of the entry, with
/// the retention of the object and the checksum S3 requires of a request that sets one. With an
/// endpoint (a node of the local platform) the request target is path-style:
/// `/{bucket}/{key}` with the `Host` of the endpoint.
fn put_request(writer: &Writer, write: &Write, now_ms: u64) -> Option<Request<OnceBody>> {
    let (path, host) = match &writer.endpoint {
        None => (object_path(&write.key), writer.id.host()),
        Some(endpoint) => (
            format!("/{}{}", writer.id.bucket(), object_path(&write.key)),
            endpoint.authority(),
        ),
    };
    let body = to_json(&write.entry);
    let digest = Sha256::digest(&body);
    let payload_sha256 = hex(&digest);
    let amz_date = amz_date(now_ms);
    let retention_ms = limits::LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;
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
        .header(CONTENT_LENGTH, body.len());
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
        .body(OnceBody::new(Bytes::from(body)))
        .ok()
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
    match claim[0].holds() {
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
    let outcome = claims.iter().all(Claim::holds);
    drop(claims);
    for (account, _) in entries {
        let notify = lock(account).notify.clone();
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
    use credential_enclave_protocol::log::object_key;

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
        let write = Write {
            seq: 7,
            key: object_key("user 1", "NODE", 7, &[0xfb; 32]),
            entry: Signed {
                body: "Ym9keQ".to_string(),
                sig: "c2ln".to_string(),
            },
            required: true,
            confirmed: false,
            outcome_unknown: false,
            in_flight: AtomicBool::new(false),
            may_be_stored: AtomicBool::new(false),
        };
        // 2026-10-01T12:10:45.123Z.
        let request = put_request(&writer, &write, 1_790_856_645_123).unwrap();
        let body = br#"{"body":"Ym9keQ","sig":"c2ln"}"#;
        let digest = Sha256::digest(body);
        let path = concat!(
            "/v1/accounts/user%201/NODE/",
            "00000000000000000007--_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s"
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
                (
                    "host",
                    "character-credential-log-dev-1.s3.us-west-2.amazonaws.com"
                ),
                ("x-amz-checksum-sha256", STANDARD.encode(digest).as_str()),
                ("x-amz-content-sha256", hex(&digest).as_str()),
                ("x-amz-date", "20261001T121045Z"),
                ("x-amz-object-lock-mode", "COMPLIANCE"),
                // 365 days after the write.
                (
                    "x-amz-object-lock-retain-until-date",
                    "2027-10-01T12:10:45Z"
                ),
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
        let signed: Vec<(&str, String)> = headers[1..8]
            .iter()
            .map(|(name, value)| (*name, value.to_string()))
            .collect();
        assert_eq!(
            authorization,
            writer.credentials.authorization(
                "us-west-2",
                "PUT",
                path,
                &signed,
                &hex(&digest),
                "20261001T121045Z"
            )
        );
        // The signature is the one the AWS SDK for Python computes for this request
        // (botocore 1.43, `S3SigV4Auth`, with the payload signed): the same credentials, the
        // same time, the same address, headers and body.
        assert_eq!(
            authorization,
            concat!(
                "AWS4-HMAC-SHA256 ",
                "Credential=AKIAIOSFODNN7EXAMPLE/20261001/us-west-2/s3/aws4_request,",
                "SignedHeaders=content-type;host;x-amz-checksum-sha256;x-amz-content-sha256;",
                "x-amz-date;x-amz-object-lock-mode;x-amz-object-lock-retain-until-date;",
                "x-amz-security-token,",
                "Signature=8d7747bae7303ef63b4a453ccdbe239070a6a64c50ffb586afb916df2cd3f828"
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
        let request = put_request(&without_session, &write, 1_790_856_645_123).unwrap();
        assert!(!request.headers().contains_key(SECURITY_TOKEN));
        let authorization = request.headers()[AUTHORIZATION].to_str().unwrap();
        assert!(authorization.ends_with(concat!(
            "x-amz-object-lock-retain-until-date,",
            "Signature=ab38f4ec0f6b975bab74ebf0437982cbbb9f87de54d2703dc04c51d9b51d8735"
        )));
        let path = object_path("v1/accounts/a b/ü$%+=&?#:@/N/1-x");
        assert_eq!(
            path,
            "/v1/accounts/a%20b/%C3%BC%24%25%2B%3D%26%3F%23%3A%40/N/1-x"
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
            "Signature=4158355ad822130ed2a001d7f5b2be44e92c716e10bc40539237ff032b19eac8"
        ));
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
        let write = Write {
            seq: 7,
            key: object_key("user 1", "NODE", 7, &[0xfb; 32]),
            entry: Signed {
                body: "Ym9keQ".to_string(),
                sig: "c2ln".to_string(),
            },
            required: true,
            confirmed: false,
            outcome_unknown: false,
            in_flight: AtomicBool::new(false),
            may_be_stored: AtomicBool::new(false),
        };
        let request = put_request(&writer, &write, 1_790_856_645_123).unwrap();
        assert_eq!(
            request.uri().to_string(),
            concat!(
                "/character-credential-log-local-1/v1/accounts/user%201/NODE/",
                "00000000000000000007--_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s"
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
        let key = object_key("user-1", "NODE", 7, &[0xfb; 32]);
        assert_eq!(object_path(&key), format!("/{key}"));
        // A key of format 2 has no character that is encoded: its parts are digits, letters,
        // `-` and `_`.
        let parts = credential_enclave_protocol::log::EntryParts {
            seq: 2,
            time_ms: 1_790_000_000_000,
            kind: credential_enclave_protocol::log::EntryKind::Use,
            count: 3,
            key_id: "0123456789abcdef".to_string(),
            body_hash: [0xfb; 32],
            entry_hash: [0x3f; 32],
        };
        let key = credential_enclave_protocol::log::object_key_v2("user-1", "NODE", &parts);
        assert_eq!(object_path(&key), format!("/{key}"));
        // Every part of a key is encoded once, and `/` stays.
        assert_eq!(
            object_path("v1/accounts/a b/ü$%+=&?#:@/N/1-x"),
            "/v1/accounts/a%20b/%C3%BC%24%25%2B%3D%26%3F%23%3A%40/N/1-x"
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
        // With a log store it needs credentials within their time.
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
        assert_eq!(optional.ensure_ready(9), Ok(()));
        assert_eq!(
            optional.ensure_ready(10),
            Err(ProtocolError::LogStoreUnavailable)
        );
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
        required.set_credentials(Credentials::new("ASIAEXAMPLE", "secret", "token", 10).unwrap());
        assert_eq!(
            required.ensure_ready(5),
            Err(ProtocolError::LogStoreUnavailable)
        );
        assert!(required.set_id(first));
        assert_eq!(required.ensure_ready(5), Ok(()));
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
