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
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::task::Poll;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use credential_enclave_protocol::encoding::{to_json, Signed};
use credential_enclave_protocol::keys::LogStoreId;
use credential_enclave_protocol::log::object_key;
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::{limits, ProtocolError};
use hmac::{Hmac, Mac};
use hyper::body::Bytes;
use hyper::header::{HeaderValue, AUTHORIZATION, CONNECTION, CONTENT_LENGTH};
use hyper::{Method, Request, StatusCode};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::egress::OnceBody;
use crate::state::{lock, Account, Node};

/// Writes of one call that run at the same time.
const WRITE_CONCURRENCY: usize = 32;
/// Pending entries of one account at which a call that uses a credential creates no further
/// entry before the store confirmed some of them ([`admit`]).
pub const PENDING_ENTRIES: usize = 64;

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

/// Where a write goes and what signs it.
struct Writer {
    id: LogStoreId,
    credentials: Arc<Credentials>,
}

/// The log store of a node and the credentials for it.
pub struct LogStore {
    /// True on a platform whose nodes do not act without a log store: `nitro`.
    required: bool,
    /// The bucket and its region. Set once: the binding of the attestation names it, and what
    /// a verifier read there holds for as long as the node lives.
    id: OnceLock<LogStoreId>,
    credentials: RwLock<Option<Arc<Credentials>>>,
}

impl LogStore {
    /// The state of a node that starts: no log store and no credentials. With `required`, the
    /// node refuses every act of the table of protocol.md 7.6 until it has both.
    pub fn new(required: bool) -> LogStore {
        LogStore {
            required,
            id: OnceLock::new(),
            credentials: RwLock::new(None),
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
        }))
    }

    /// The node can write to its log store now, or it runs without one.
    pub fn ensure_ready(&self, now_ms: u64) -> Result<(), ProtocolError> {
        self.writer(now_ms).map(|_| ())
    }
}

/// One entry in the hands of a call.
struct Write {
    seq: u64,
    hash: [u8; 32],
    entry: Signed,
    /// True for an entry an act of the call waits for.
    required: bool,
    confirmed: bool,
}

/// The entries of one account that a call writes: the entries the call names and the pending
/// entries of the account. While the claim lives, no other call takes the pending ones along.
/// When it is dropped, the entries the store confirmed leave the account, and the others
/// become pending entries: also when the call ends before its writes do.
struct Claim<'a> {
    user_id: &'a str,
    account: &'a Mutex<Account>,
    writes: Vec<Write>,
}

impl<'a> Claim<'a> {
    fn take(user_id: &'a str, account: &'a Mutex<Account>, seqs: &[u64]) -> Claim<'a> {
        let mut writes = Vec::new();
        for entry in lock(account).unconfirmed.iter_mut() {
            let required = seqs.contains(&entry.seq);
            // An entry another call writes is left to that call, unless an act of this call
            // waits for it: then both write it, and the store keeps two versions of it.
            if required || !entry.writing {
                entry.writing = true;
                writes.push(Write {
                    seq: entry.seq,
                    hash: entry.hash,
                    entry: entry.entry.clone(),
                    required,
                    confirmed: false,
                });
            }
        }
        Claim {
            user_id,
            account,
            writes,
        }
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
                account.unconfirmed.retain(|entry| entry.seq != write.seq);
            } else if let Some(entry) = account
                .unconfirmed
                .iter_mut()
                .find(|entry| entry.seq == write.seq)
            {
                entry.writing = false;
            }
        }
    }
}

/// Runs futures at the same time, on the task of the caller, and returns their outputs in the
/// order of the futures.
async fn join_all<F: Future>(futures: impl Iterator<Item = F>) -> Vec<F::Output> {
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
            send_to_log_store(node, &writer, claim.user_id, &claim.writes[*index])
        }))
        .await;
        for ((at, index), confirmed) in round.iter().zip(&outcomes) {
            claims[*at].writes[*index].confirmed = *confirmed;
        }
        if outcomes.contains(&false) {
            return;
        }
    }
}

/// Sink K5 of the egress policy: writes one entry to the log store and returns true when the
/// store confirmed the write.
///
/// What leaves is the signed entry (its content is sealed to the log public key of the
/// account) under the key of protocol.md 7.6 ([`object_key`]), with a retention in compliance
/// mode until 365 days from now, and the request is signed with the credentials of the
/// operator. The connection goes to `{bucket}.s3.{region}.amazonaws.com`: TLS ends inside the
/// node and the certificate is verified against the trust roots of the binary.
///
/// The one confirmation is the status 200. Every other status, a failure of the connection
/// and a write that takes longer than its time limit (5 seconds) are no confirmation.
async fn send_to_log_store(node: &Node, writer: &Writer, user_id: &str, write: &Write) -> bool {
    let exchange = async {
        let request = put_request(writer, &node.node, user_id, write, node.now_ms())?;
        let mut sender = node
            .egress
            .open(node.platform.as_ref(), &writer.id.host())
            .await
            .ok()?;
        let response = sender.send_request(request).await.ok()?;
        Some(response.status() == StatusCode::OK)
    };
    matches!(
        tokio::time::timeout(node.limits.log_write, exchange).await,
        Ok(Some(true))
    )
}

/// The request that writes one entry (protocol.md 7.6): `PUT` of the signed entry as the node
/// carries it in a response, `{"body":"...","sig":"..."}`, with the retention of the object
/// and the checksum S3 requires of a request that sets one.
fn put_request(
    writer: &Writer,
    node: &str,
    user_id: &str,
    write: &Write,
    now_ms: u64,
) -> Option<Request<OnceBody>> {
    let path = object_path(&object_key(user_id, node, write.seq, &write.hash));
    let body = to_json(&write.entry);
    let digest = Sha256::digest(&body);
    let payload_sha256 = hex(&digest);
    let amz_date = amz_date(now_ms);
    let retention_ms = limits::LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;
    // The headers of the request, in the order of their names. All of them are signed.
    let headers = [
        ("content-type", "application/json".to_string()),
        ("host", writer.id.host()),
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
        .header(CONNECTION, HeaderValue::from_static("close"))
        .body(OnceBody::new(Bytes::from(body)))
        .ok()
}

/// Step 3 of the common front, for a call that uses a credential: the node can write to its
/// log store, and the account has room for one more pending entry.
///
/// An account whose pending entries reached 64 gets no further entry from such a call before
/// the store confirmed some of them. The call writes the pending entries again here. When
/// they still wait after that, it ends with `log_store_unavailable` and creates no entry: an
/// account does not collect entries of acts that never took place without a bound.
pub async fn admit(
    node: &Node,
    user_id: &str,
    account: &Mutex<Account>,
) -> Result<(), ProtocolError> {
    node.log_store.ensure_ready(node.now_ms())?;
    if lock(account).pending_entries() < PENDING_ENTRIES {
        return Ok(());
    }
    let _ = confirm(node, user_id, account, &[]).await;
    match lock(account).pending_entries() < PENDING_ENTRIES {
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
    user_id: &str,
    account: &Mutex<Account>,
    seqs: &[u64],
) -> Result<(), ProtocolError> {
    if !node.log_store.tracks() {
        return Ok(());
    }
    let mut claim = [Claim::take(user_id, account, seqs)];
    write_claims(node, &mut claim).await;
    match claim[0].holds() {
        true => Ok(()),
        false => Err(ProtocolError::LogStoreUnavailable),
    }
}

/// [`confirm`] for one entry of each of several accounts, with the writes of all of them
/// sharing the limit of 32 at the same time. `Ok` when the store confirmed every one of
/// these entries. After a failure, the entries the store confirmed stay confirmed.
pub async fn confirm_each(
    node: &Node,
    entries: &[(&str, &Mutex<Account>, u64)],
) -> Result<(), ProtocolError> {
    if !node.log_store.tracks() {
        return Ok(());
    }
    let mut claims: Vec<Claim<'_>> = entries
        .iter()
        .map(|(user_id, account, seq)| Claim::take(user_id, account, &[*seq]))
        .collect();
    write_claims(node, &mut claims).await;
    match claims.iter().all(Claim::holds) {
        true => Ok(()),
        false => Err(ProtocolError::LogStoreUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        let write = Write {
            seq: 7,
            hash: [0xfb; 32],
            entry: Signed {
                body: "Ym9keQ".to_string(),
                sig: "c2ln".to_string(),
            },
            required: true,
            confirmed: false,
        };
        // 2026-10-01T12:10:45.123Z.
        let request = put_request(&writer, "NODE", "user 1", &write, 1_790_856_645_123).unwrap();
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
                ("connection", "close"),
            ]
        );
        // The request asks for no condition on the key: the store answers 200 only when it
        // stored this object with this retention.
        assert!(!request.headers().contains_key("if-none-match"));
        assert!(request.headers()[SECURITY_TOKEN].is_sensitive());
        assert!(!format!("{:?}", request.headers()).contains("TOKEN"));
        // Every header but the length of the body and the header of the connection is
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
        };
        let request = put_request(
            &without_session,
            "NODE",
            "user 1",
            &write,
            1_790_856_645_123,
        )
        .unwrap();
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
