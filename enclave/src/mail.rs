//! Fixed Naver IMAP/SMTP operations. Authentication bytes only reach in-node TLS streams.
//!
//! The responses of the IMAP server are read by the reader of this program (`crate::imap`),
//! which reads what the commands of a mail call need and passes over the rest. This module
//! sends those commands and decides what a response is to the command it answers.

use std::{
    collections::BTreeMap,
    fmt, io,
    pin::Pin,
    sync::atomic::Ordering,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine};
use credential_enclave_protocol::encoding::to_json;
use credential_enclave_protocol::record::{Kind, Record};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::ProtocolError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter,
    ReadBuf,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::imap::{self, Code, Condition, Fetched, Response, Status, Step};
use crate::platform::Stream;
use crate::provider_response::{self, CheckedResponse};
use crate::state::{lock, open_for, GrantView, Limits, Node};

/// Protocol input the IMAP connection of a folder listing or of a search accepts: 4 MiB. A
/// UID set or headers above it end the connection; the search must be narrowed.
pub(crate) const LISTING_INPUT_BYTES: usize = 4 * 1024 * 1024;

/// The end-to-end time limit of a mail call, its admission included (`api::mail`). It is also
/// the budget of the opening of a mail connection: a failed attempt is repeated within half of
/// it (`Egress::open_mail`).
pub(crate) const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Protocol input a raw message read accepts: the body limit plus 1 MiB of protocol overhead.
/// The returned message itself still has the body limit.
pub(crate) fn message_input_bytes(limits: &Limits) -> usize {
    limits.body_bytes + 1024 * 1024
}

/// Protocol input the IMAP connection of a verification accepts: the greeting of the server
/// and its answer to the login. A call that verifies reserves these bytes before it reads its
/// request frame.
pub(crate) const LOGIN_INPUT_BYTES: usize = 64 * 1024;

/// Protocol input an SMTP connection accepts. A call that opens one reserves these bytes
/// before it reads its request frame.
pub(crate) const SMTP_INPUT_BYTES: usize = 64 * 1024;

/// What a mail call holds besides its request frame and the mail it reads: its parsed
/// request, the read buffer of its IMAP connection and the head of its response frame.
/// Reserved with the frame, before the call reads it.
pub(crate) const CALL_BYTES: usize = 64 * 1024;

/// The step in which the share of a mail call follows its protocol input.
pub(crate) const SHARE_STEP_BYTES: usize = 64 * 1024;

/// What a folder listing or a search holds at once per byte of its protocol input. The
/// responses are read one at a time, and what a call keeps of them is the names of the
/// folders, the UIDs of the search and the header blocks of at most 50 messages. At its peak
/// a call holds the bytes it keeps (at most one per byte of input, and three for a number of
/// the search: the digits of the response and the number), the text it makes of them (the
/// base64 of a header is 4/3 of its bytes; the JSON of a name is at most twice its bytes), and
/// the copy the check of the response makes of that text. Six covers each of these sums.
pub(crate) const LISTING_HELD_PER_BYTE: usize = 6;

/// What a raw message read holds at once per byte of its protocol input: the message, and the
/// copy the check of the response makes of it.
pub(crate) const MESSAGE_HELD_PER_BYTE: usize = 2;

/// The most bytes a connection to the IMAP server takes from its stream in one read.
const IMAP_READ_BYTES: usize = 16 * 1024;

/// The share of the body budget of the node that one mail call holds (the budget of
/// `Limits::body_budget_bytes`, which `forward` reserves its bodies from).
///
/// A call takes its share without waiting, in two parts. The first is taken before the call
/// reads its request frame: the frame, [`CALL_BYTES`], and the input bound of every connection
/// whose input the call does not follow ([`LOGIN_INPUT_BYTES`], [`SMTP_INPUT_BYTES`]). The
/// second follows the protocol input of a read ([`Allowance`]): for every byte the call takes
/// from its IMAP connection, and for every octet of a literal the server declares, the share
/// grows by what the call holds per byte of input, before the reader of the responses takes
/// the byte. So the share of a call is what the call read, and the shares of the calls of a
/// node add up to the mail the node holds, not to the largest mail each call could have read.
/// When the budget has no room for a step, the input of the call ends there
/// ([`MailError::Capacity`]).
pub(crate) struct Share {
    budget: Arc<Semaphore>,
    held: Mutex<Held>,
}

struct Held {
    /// The bytes of the budget the call holds. `None` once its response frame took them.
    permit: Option<OwnedSemaphorePermit>,
    /// The part of the share that does not follow the input.
    base: usize,
}

/// Takes `bytes` of the budget without waiting. `None` when they are not free.
fn take_bytes(budget: &Arc<Semaphore>, bytes: usize) -> Option<OwnedSemaphorePermit> {
    let permits = u32::try_from(bytes).ok()?;
    budget.clone().try_acquire_many_owned(permits).ok()
}

impl Share {
    /// The share of a call that starts: `bytes` of the budget, taken without waiting. `None`
    /// when they are not free.
    pub(crate) fn admit(budget: &Arc<Semaphore>, bytes: usize) -> Option<Arc<Share>> {
        let permit = take_bytes(budget, bytes)?;
        Some(Arc::new(Share {
            budget: budget.clone(),
            held: Mutex::new(Held {
                permit: Some(permit),
                base: bytes,
            }),
        }))
    }

    /// Makes the share `bytes`: more is taken without waiting, less is given back. False
    /// when the budget has no room for more, and for a share its response frame took.
    fn resize(&self, held: &mut Held, bytes: usize) -> bool {
        let Some(permit) = held.permit.as_mut() else {
            return false;
        };
        let now = permit.num_permits();
        if bytes > now {
            match take_bytes(&self.budget, bytes.saturating_sub(now)) {
                Some(more) => permit.merge(more),
                None => return false,
            }
        } else if let Some(freed) = permit.split(now.saturating_sub(bytes)) {
            drop(freed);
        }
        true
    }

    /// Makes `bytes` the part of the share that does not follow the input, and the share
    /// that size: the call knows the length of its request frame now.
    pub(crate) fn rebase(&self, bytes: usize) -> bool {
        let mut held = lock(&self.held);
        held.base = bytes;
        self.resize(&mut held, bytes)
    }

    /// Raises the share to its base plus `input_share` bytes, in whole steps of
    /// [`SHARE_STEP_BYTES`]. A share that is that large already stays as it is. False when
    /// the budget has no room.
    fn cover(&self, input_share: usize) -> bool {
        let mut held = lock(&self.held);
        let steps = input_share.div_ceil(SHARE_STEP_BYTES);
        let needed = held
            .base
            .saturating_add(steps.saturating_mul(SHARE_STEP_BYTES));
        let covered = held
            .permit
            .as_ref()
            .is_some_and(|permit| permit.num_permits() >= needed);
        covered || self.resize(&mut held, needed)
    }

    /// Ends the share at what the response frame of the call holds, `bytes` at the most,
    /// and hands the permit to that frame: a share is never raised here. `None` for a share
    /// that was handed over before.
    pub(crate) fn settle(&self, bytes: usize) -> Option<OwnedSemaphorePermit> {
        let mut held = lock(&self.held);
        let now = held.permit.as_ref()?.num_permits();
        self.resize(&mut held, bytes.min(now));
        held.permit.take()
    }
}

/// Whether a `NO` reply to `LOGIN` says that the server refused the credentials. Two forms
/// count: the RFC 5530 response code `AUTHENTICATIONFAILED`, and the information
/// `Authentication failed` that imap.naver.com sends with its own response code `[AUTH]`
/// (`NO [AUTH] "name": Authentication failed. (Please check your username, password)`). Any
/// other `NO` is a provider failure.
fn credentials_refused(status: &Status) -> bool {
    status.mentions(b"authenticationfailed") || status.mentions(b"authentication failed")
}

/// A record of kind `app_password` that opened under the grant of its account. Its plaintext
/// is not read yet: [`MailRecord::credentials`] reads it, after the log store confirmed the
/// entry of the call.
pub struct MailRecord {
    plaintext: Secret<Vec<u8>>,
}

/// The account name and the application password of a record. Only a mail call reads them.
/// Neither field implements response serialization.
pub struct AppPassword {
    identity: String,
    password: Secret<String>,
}

/// Closed protocol failures, never a provider transcript.
pub enum MailError {
    Auth,
    Invalid,
    Unavailable,
    TooLarge,
    MailboxChanged,
    Missing,
    /// The body budget of the node has no room for the input of the call: the input ended
    /// there.
    Capacity,
}

/// Opens the record of a mail call for the account of the call, before the event of the call
/// is created. What is judged here is the same for every value the record can hold: the
/// grant, the AEAD verification, and the kind and the provider of the record. The plaintext
/// is not read.
pub fn open_record(
    grant: &GrantView,
    user: &str,
    record: &Record,
) -> Result<MailRecord, ProtocolError> {
    let (kind, plaintext) = open_for(grant, user, record)?;
    if kind != Kind::AppPassword || record.provider != "naver_mail" {
        return Err(ProtocolError::NotAllowed);
    }
    Ok(MailRecord { plaintext })
}

impl MailRecord {
    /// Reads the plaintext of the record. A mail call does this after the log store confirmed
    /// the entry that holds its event, so every answer that depends on the content of the
    /// plaintext has an entry. A plaintext that is no JSON object, a `username` that is no
    /// NAVER account name, and a `password` that is shorter than 8 bytes, longer than 256
    /// bytes or holds a control character are `record_invalid` at that point: nothing goes
    /// to the provider, and the entry stays on the chain as the entry of a mail call that did
    /// not take place.
    pub fn credentials(&self) -> Result<AppPassword, ProtocolError> {
        let value = Secret::new(
            serde_json::from_slice::<Value>(self.plaintext.expose_secret())
                .map_err(|_| ProtocolError::RecordInvalid)?,
        );
        let value = value.expose_secret();
        let name = value
            .get("username")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::RecordInvalid)?;
        let lower = name.trim().to_ascii_lowercase();
        let id = lower.strip_suffix("@naver.com").unwrap_or(&lower);
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
        {
            return Err(ProtocolError::RecordInvalid);
        }
        let password = value
            .get("password")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::RecordInvalid)?;
        if password.len() < 8 || password.len() > 256 || password.chars().any(char::is_control) {
            return Err(ProtocolError::RecordInvalid);
        }
        Ok(AppPassword {
            identity: format!("{id}@naver.com"),
            password: Secret::new(password.to_string()),
        })
    }
}

impl AppPassword {
    /// D: identity is returned by the verify call only after both authentications succeed.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// E4 applies to every response, including public identity and fixed status results.
    pub fn check(
        &self,
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<CheckedResponse, ProtocolError> {
        provider_response::check(&self.password, status, headers, body)
            .map_err(|_| ProtocolError::ResponseWithheld)
    }

    /// Opens a connection to imap.naver.com and authenticates: sink K6 of the egress policy.
    /// The connection delivers its protocol input within `allowance`.
    async fn imap(&self, node: &Node, allowance: Allowance) -> Result<ImapSession, MailError> {
        let stream = node
            .egress
            .open_mail(node.platform.as_ref(), "imap.naver.com", 993, CALL_TIMEOUT)
            .await
            .map_err(|_| MailError::Unavailable)?;
        let mut connection = ImapConnection::new(stream, allowance);
        // The greeting of the server: a connection it refuses, or ends, carries no login.
        match connection.response().await? {
            Response::Untagged(status)
                if matches!(status.condition, Condition::Ok | Condition::Preauth) => {}
            _ => return Err(MailError::Unavailable),
        }
        let login = self
            .identity
            .strip_suffix("@naver.com")
            .ok_or(MailError::Invalid)?;
        connection
            .login(login, self.password.expose_secret())
            .await?;
        Ok(ImapSession {
            connection,
            in_step: true,
            answered: false,
            login_ms: node.now_ms(),
        })
    }

    async fn smtp(&self, node: &Node) -> Result<Smtp, MailError> {
        let stream = node
            .egress
            .open_mail(node.platform.as_ref(), "smtp.naver.com", 465, CALL_TIMEOUT)
            .await
            .map_err(|_| MailError::Unavailable)?;
        let mut smtp = Smtp {
            io: BufReader::new(BufWriter::new(MailStream::bounded(
                stream,
                SMTP_INPUT_BYTES,
            ))),
            size: None,
        };
        if smtp.reply().await?.0 != 220 {
            return Err(MailError::Unavailable);
        }
        let (code, lines) = smtp.command(b"EHLO pickle.com\r\n").await?;
        if code != 250 {
            return Err(MailError::Unavailable);
        }
        for line in lines {
            if let Some(value) = line.get(4..).and_then(|s| s.strip_prefix("SIZE ")) {
                smtp.size = value.trim().parse::<usize>().ok();
            }
        }
        if smtp.command(b"AUTH LOGIN\r\n").await?.0 != 334 {
            return Err(MailError::Unavailable);
        }
        let login = self
            .identity
            .strip_suffix("@naver.com")
            .ok_or(MailError::Invalid)?;
        match smtp
            .command(format!("{}\r\n", STANDARD.encode(login)).as_bytes())
            .await?
            .0
        {
            334 => {}
            535 => return Err(MailError::Auth),
            _ => return Err(MailError::Unavailable),
        }
        let mut auth = Zeroizing::new(STANDARD.encode(self.password.expose_secret()));
        auth.push_str("\r\n");
        match smtp.command(auth.as_bytes()).await?.0 {
            235 => Ok(smtp),
            535 => Err(MailError::Auth),
            _ => Err(MailError::Unavailable),
        }
    }

    pub async fn verify(&self, node: &Node) -> Result<(), MailError> {
        drop(
            self.imap(node, Allowance::reserved(LOGIN_INPUT_BYTES))
                .await?,
        );
        drop(self.smtp(node).await?);
        Ok(())
    }

    /// Reads mail for one call, and returns the session of the call when it can carry the
    /// next one. The share of the call follows the input of its connection (`share`).
    ///
    /// `kept` is the session the node kept for this record from an earlier call, when it
    /// kept one (`crate::mail_sessions`). The call goes over it and neither opens a
    /// connection nor authenticates: the server accepted the application password of this
    /// record for that connection. A kept session that ends before the server completed a
    /// command of this call had ended while it carried no call: the call starts once more
    /// over a new connection, with a login. Every command of a read examines, lists, searches
    /// or fetches and changes nothing in the mailbox, so the second start repeats no act.
    ///
    /// The session comes back when the call left it in step with the server: every command
    /// the call sent got its completion, and the connection holds no byte of a further
    /// response. A call that ended at a failure of the connection, at the input bound or at
    /// the end of its share of the body budget returns none, and the connection ends with
    /// the call.
    pub async fn read(
        &self,
        node: &Node,
        request: &ReadMail,
        kept: Option<ImapSession>,
        share: &Arc<Share>,
    ) -> (Result<MailData, MailError>, Option<ImapSession>) {
        if let Err(error) = request.validate() {
            return (Err(error), kept);
        }
        // A UID search can expand into a large set before pagination. Bound listing and
        // header input separately from a raw message, whose content has the frame limit.
        let allowance = || match request.action.as_str() {
            "read" => Allowance::charged(
                message_input_bytes(&node.limits),
                MESSAGE_HELD_PER_BYTE,
                share,
            ),
            _ => Allowance::charged(LISTING_INPUT_BYTES, LISTING_HELD_PER_BYTE, share),
        };
        let (mut session, mut reused) = match kept {
            Some(mut session) => {
                session.serve(allowance());
                (session, true)
            }
            None => match self.imap(node, allowance()).await {
                Ok(session) => (session, false),
                Err(error) => return (Err(error), None),
            },
        };
        let mut data = session.read(request, &node.limits).await;
        if reused && session.ended_unanswered() {
            reused = false;
            session = match self.imap(node, allowance()).await {
                Ok(session) => session,
                Err(error) => return (Err(error), None),
            };
            data = session.read(request, &node.limits).await;
        }
        if reused {
            node.egress
                .counters
                .idle_reuses
                .mail
                .fetch_add(1, Ordering::Relaxed);
        }
        let session = session.rest().then_some(session);
        (data, session)
    }

    /// A single authenticated SMTP transaction through K7. No retry follows DATA.
    pub async fn submit(
        &self,
        node: &Node,
        recipients: &[String],
        body: &[u8],
    ) -> Result<MailData, MailError> {
        // The sender of the message is the account of the record. This judgement depends on
        // the content of the record: the call makes it here, after its entry, and not with
        // the form of the submission before it.
        if submission_sender(recipients, body)? != self.identity {
            return Err(MailError::Invalid);
        }
        let mut smtp = self.smtp(node).await?;
        if smtp
            .size
            .is_some_and(|limit| limit > 0 && body.len() > limit)
        {
            return Err(MailError::TooLarge);
        }
        let from = format!("MAIL FROM:<{}> SIZE={}\r\n", self.identity, body.len());
        let code = smtp.command(from.as_bytes()).await?.0;
        if code != 250 {
            return Ok(rejected(code));
        }
        for recipient in recipients {
            let code = smtp
                .command(format!("RCPT TO:<{recipient}>\r\n").as_bytes())
                .await?
                .0;
            if code != 250 && code != 251 {
                return Ok(rejected(code));
            }
        }
        let code = smtp.command(b"DATA\r\n").await?.0;
        if code != 354 {
            return Ok(rejected(code));
        }
        for line in body.split_inclusive(|byte| *byte == b'\n') {
            if line.starts_with(b".") {
                smtp.io
                    .get_mut()
                    .write_all(b".")
                    .await
                    .map_err(|_| MailError::Unavailable)?;
            }
            smtp.io
                .get_mut()
                .write_all(line)
                .await
                .map_err(|_| MailError::Unavailable)?;
        }
        let code = smtp.command(b".\r\n").await?.0;
        match code {
            250 => Ok(MailData::Json(to_json(
                &json!({"status": "accepted", "smtp_code": code}),
            ))),
            400..=599 => Ok(rejected(code)),
            _ => Err(MailError::Unavailable),
        }
    }
}

fn rejected(code: u16) -> MailData {
    MailData::Json(to_json(&json!({"status": "rejected", "smtp_code": code})))
}

/// What a mail call answers with.
pub enum MailData {
    /// A JSON document, serialized.
    Json(Vec<u8>),
    /// A message as the server holds it.
    Raw(Vec<u8>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadMail {
    pub action: String,
    #[serde(default = "inbox")]
    pub mailbox: String,
    pub uid_validity: Option<u32>,
    pub uid: Option<u32>,
    pub before_uid: Option<u32>,
    pub from: Option<String>,
    pub subject: Option<String>,
    pub since: Option<String>,
    #[serde(default = "page_size")]
    pub limit: usize,
}
fn inbox() -> String {
    "INBOX".into()
}
fn page_size() -> usize {
    20
}

impl ReadMail {
    pub(crate) fn validate(&self) -> Result<(), MailError> {
        if !matches!(self.action.as_str(), "folders" | "search" | "read")
            || !(1..=50).contains(&self.limit)
            || self.mailbox.is_empty()
            || self.mailbox.len() > imap::FOLDER_NAME_BYTES
            || self.mailbox.chars().any(char::is_control)
        {
            return Err(MailError::Invalid);
        }
        if self.action == "search" {
            self.query(1)?;
        }
        if self.action == "read" && (self.uid.unwrap_or(0) == 0 || self.uid_validity.is_none()) {
            return Err(MailError::Invalid);
        }
        Ok(())
    }
    fn query(&self, upper: u32) -> Result<Vec<String>, MailError> {
        let mut command = format!("UID SEARCH CHARSET UTF-8 UID 1:{upper}");
        if let Some(since) = &self.since {
            command.push_str(&format!(" SINCE {}", imap_date(since)?));
        }
        let mut pieces = Vec::new();
        for (name, value) in [("FROM", &self.from), ("SUBJECT", &self.subject)] {
            if let Some(value) = value {
                if value.len() > 1024 || value.chars().any(char::is_control) {
                    return Err(MailError::Invalid);
                }
                // RFC 3501 4.3: quoted strings are 7-bit. UTF-8 uses a literal with
                // a byte count, sent only after the server's continuation response.
                command.push_str(&format!(" {name} {{{}}}", value.len()));
                pieces.push(command);
                command = value.clone();
            }
        }
        pieces.push(command);
        Ok(pieces)
    }
}

/// The folders of an account, as a folder listing answers.
#[derive(Serialize)]
struct Folders<'a> {
    folders: Vec<Folder<'a>>,
}

#[derive(Serialize)]
struct Folder<'a> {
    name: &'a str,
}

/// One page of a search, as a search answers.
#[derive(Serialize)]
struct Page {
    uid_validity: u32,
    messages: Vec<Listed>,
    next_uid: Option<u32>,
}

/// One message of a page: its UID, its size, and its header block in base64.
#[derive(Serialize)]
struct Listed {
    uid: u32,
    size: Option<u64>,
    headers_b64: String,
}

/// An authenticated connection to imap.naver.com: the session of one login with the
/// application password of one record.
///
/// A node keeps the session of a read for the next read of the same record
/// (`crate::mail_sessions`). The session holds no byte of the application password: what it
/// holds is the TLS connection the server accepted the password for.
pub(crate) struct ImapSession {
    connection: ImapConnection,
    /// True while every command the node sent got its tagged completion: the next command
    /// starts an exchange of its own. False from the moment a command is sent to the moment
    /// its completion was read, and for good once the connection failed in between.
    in_step: bool,
    /// True once the server completed a command of the call the session carries.
    answered: bool,
    /// The node time of the login.
    login_ms: u64,
}

/// What a response is to the command with a tag.
enum Turn {
    /// The tagged completion of the command, and whether its condition is `OK`.
    Completed(bool),
    /// The server ends the connection (`BYE`), or completes a command the node did not send.
    Ended,
    /// Data, of the command or unsolicited. An untagged `NO` or `BAD` is a warning (RFC 3501
    /// sections 7.1.2 and 7.1.3): the completion of the command says how the command ended.
    Data,
}

fn turn(response: &Response, tag: &str) -> Turn {
    match response {
        Response::Tagged(completed, status) if completed == tag.as_bytes() => {
            Turn::Completed(status.condition == Condition::Ok)
        }
        Response::Tagged(..) => Turn::Ended,
        Response::Untagged(status) if status.condition == Condition::Bye => Turn::Ended,
        _ => Turn::Data,
    }
}

impl ImapSession {
    /// The node time of the login of the session.
    pub(crate) fn login_ms(&self) -> u64 {
        self.login_ms
    }

    /// Gives the session to a call: the call takes the input of the connection from here on,
    /// within its allowance.
    fn serve(&mut self, allowance: Allowance) {
        self.answered = false;
        self.connection.serve(allowance);
    }

    /// Takes the session from its call, and with it the hold of the call on its share of the
    /// body budget. True when the session can carry a further call: it is in step with the
    /// server, and its connection holds no byte of a further response.
    fn rest(&mut self) -> bool {
        let at_rest = self.connection.rest();
        self.in_step && at_rest
    }

    /// True when the connection ended and the server completed no command of the call the
    /// session carries: a session that was kept had ended while it carried no call.
    fn ended_unanswered(&self) -> bool {
        self.connection.lost && !self.answered
    }

    /// Sends a command and returns its tag. The session is out of step until the completion
    /// of the command was read.
    async fn send(&mut self, command: String) -> Result<String, MailError> {
        self.in_step = false;
        self.connection.command(&command).await
    }

    /// Ends a command at its completion: the session is in step again, and the command
    /// succeeded when its condition is `OK`.
    fn completed<T>(&mut self, ok: bool, value: T) -> Result<T, MailError> {
        self.in_step = true;
        self.answered = true;
        match ok {
            true => Ok(value),
            false => Err(MailError::Unavailable),
        }
    }

    /// The commands of one read, and what the read answers with.
    async fn read(&mut self, request: &ReadMail, limits: &Limits) -> Result<MailData, MailError> {
        if request.action == "folders" {
            let names = self.list_folders().await?;
            let folders = names
                .iter()
                .map(|name| Folder {
                    name: name.as_str(),
                })
                .collect();
            return Ok(MailData::Json(to_json(&Folders { folders })));
        }
        let (validity, uid_next) = self.examine(&request.mailbox).await?;
        if request
            .uid_validity
            .is_some_and(|expected| expected != validity)
        {
            return Err(MailError::MailboxChanged);
        }
        if request.action == "search" {
            let upper = request
                .before_uid
                .unwrap_or(uid_next.unwrap_or(u32::MAX))
                .saturating_sub(1);
            let mut page = Page {
                uid_validity: validity,
                messages: Vec::new(),
                next_uid: None,
            };
            if upper == 0 {
                return Ok(MailData::Json(to_json(&page)));
            }
            let mut uids = self.search_uids(request.query(upper)?).await?;
            uids.sort_unstable_by(|a, b| b.cmp(a));
            uids.dedup();
            let more = uids.len() > request.limit;
            uids.truncate(request.limit);
            // The numbers of the page stay: the room of the others is given back.
            uids.shrink_to_fit();
            page.next_uid = if more { uids.last().copied() } else { None };
            if !uids.is_empty() {
                let set = uids
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                let mut rows = self
                    .uid_fetch(&set, "(UID RFC822.SIZE BODY.PEEK[HEADER])", &uids)
                    .await?;
                for uid in &uids {
                    // The header of a message leaves the rows when its text is made: a
                    // page holds each header once, in one of the two forms.
                    if let Some(row) = rows.remove(uid) {
                        page.messages.push(Listed {
                            uid: *uid,
                            size: row.size,
                            headers_b64: STANDARD.encode(row.header.unwrap_or_default()),
                        });
                    }
                }
            }
            return Ok(MailData::Json(to_json(&page)));
        }
        let uid = request.uid.ok_or(MailError::Invalid)?;
        let uid_set = uid.to_string();
        let size = self
            .uid_fetch(&uid_set, "(UID RFC822.SIZE)", &[uid])
            .await?
            .remove(&uid)
            .and_then(|row| row.size)
            .ok_or(MailError::Missing)?;
        if size > limits.body_bytes as u64 {
            return Err(MailError::TooLarge);
        }
        let body = self
            .uid_fetch(&uid_set, "(UID BODY.PEEK[])", &[uid])
            .await?
            .remove(&uid)
            .and_then(|row| row.body)
            .ok_or(MailError::Missing)?;
        if body.len() > limits.body_bytes {
            return Err(MailError::TooLarge);
        }
        Ok(MailData::Raw(body))
    }

    /// `LIST "" "*"`: the names of the folders of the account.
    async fn list_folders(&mut self) -> Result<Vec<String>, MailError> {
        let tag = self.send("LIST \"\" \"*\"".to_string()).await?;
        let mut folders = Vec::new();
        loop {
            let response = self.connection.response().await?;
            match turn(&response, &tag) {
                Turn::Completed(ok) => return self.completed(ok, folders),
                Turn::Ended => return Err(MailError::Unavailable),
                Turn::Data => {
                    if let Response::List(name) = response {
                        folders.push(name);
                    }
                }
            }
        }
    }

    /// `EXAMINE`: opens a mailbox for reading and returns its generation (`UIDVALIDITY`) and
    /// the UID its next message gets (`UIDNEXT`), when the server names one. A mailbox the
    /// server does not open, and one whose generation it does not name, fail the read.
    async fn examine(&mut self, mailbox: &str) -> Result<(u32, Option<u32>), MailError> {
        let tag = self
            .send(format!("EXAMINE {}", imap::quoted(mailbox)))
            .await?;
        let (mut validity, mut uid_next) = (None, None);
        loop {
            let response = self.connection.response().await?;
            match turn(&response, &tag) {
                Turn::Completed(ok) => {
                    let validity = self.completed(ok, validity)?;
                    return Ok((validity.ok_or(MailError::Unavailable)?, uid_next));
                }
                Turn::Ended => return Err(MailError::Unavailable),
                Turn::Data => {
                    if let Response::Untagged(status) = response {
                        match (status.condition, status.code) {
                            (Condition::Ok, Code::UidValidity(value)) => validity = Some(value),
                            (Condition::Ok, Code::UidNext(value)) => uid_next = Some(value),
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    /// `UID FETCH set items`: the messages of `wanted` the server answers with, by UID. The
    /// items of one message can arrive in more than one response: they are put together. A
    /// response about another message (an unsolicited one, or one without a UID) is dropped
    /// when it was read, so the rows hold the messages the read asked for and no more.
    async fn uid_fetch(
        &mut self,
        set: &str,
        items: &str,
        wanted: &[u32],
    ) -> Result<BTreeMap<u32, Fetched>, MailError> {
        let tag = self.send(format!("UID FETCH {set} {items}")).await?;
        let mut rows: BTreeMap<u32, Fetched> = BTreeMap::new();
        loop {
            let response = self.connection.response().await?;
            match turn(&response, &tag) {
                Turn::Completed(ok) => return self.completed(ok, rows),
                Turn::Ended => return Err(MailError::Unavailable),
                Turn::Data => {
                    let Response::Fetch(fetched) = response else {
                        continue;
                    };
                    let Some(uid) = fetched.uid.filter(|uid| wanted.contains(uid)) else {
                        continue;
                    };
                    let row = rows.entry(uid).or_default();
                    row.uid = Some(uid);
                    row.size = fetched.size.or(row.size);
                    if fetched.header.is_some() {
                        row.header = fetched.header;
                    }
                    if fetched.body.is_some() {
                        row.body = fetched.body;
                    }
                }
            }
        }
    }

    /// `UID SEARCH`: the UIDs the server answers with. Every piece after the first is the
    /// octets of a literal, sent after the continuation request of the server.
    async fn search_uids(&mut self, pieces: Vec<String>) -> Result<Vec<u32>, MailError> {
        let mut pieces = pieces.into_iter();
        let tag = self.send(pieces.next().ok_or(MailError::Invalid)?).await?;
        for piece in pieces {
            loop {
                let response = self.connection.response().await?;
                match turn(&response, &tag) {
                    // The server completed the command where the node expected to go on.
                    Turn::Completed(_) => return self.completed(false, Vec::new()),
                    Turn::Ended => return Err(MailError::Unavailable),
                    Turn::Data => {
                        if response == Response::Continue {
                            break;
                        }
                    }
                }
            }
            self.connection.line(&piece).await?;
        }
        let mut uids = Vec::new();
        loop {
            let response = self.connection.response().await?;
            match turn(&response, &tag) {
                Turn::Completed(ok) => return self.completed(ok, uids),
                Turn::Ended => return Err(MailError::Unavailable),
                Turn::Data => {
                    if let Response::Search(values) = response {
                        uids.extend(values);
                    }
                }
            }
        }
    }
}

fn imap_date(date: &str) -> Result<String, MailError> {
    let parts: Vec<_> = date.split('-').collect();
    let [year, month, day] = parts.as_slice() else {
        return Err(MailError::Invalid);
    };
    if year.len() != 4
        || month.len() != 2
        || day.len() != 2
        || parts
            .iter()
            .any(|part| !part.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(MailError::Invalid);
    }
    let year: u32 = year.parse().map_err(|_| MailError::Invalid)?;
    let month: usize = month.parse().map_err(|_| MailError::Invalid)?;
    let day: u32 = day.parse().map_err(|_| MailError::Invalid)?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    // The month is 1 to 12, or it names no place of the two tables.
    let place = month.checked_sub(1).ok_or(MailError::Invalid)?;
    let days_of_month = *days.get(place).ok_or(MailError::Invalid)?;
    if year == 0 || day == 0 || day > days_of_month {
        return Err(MailError::Invalid);
    }
    let names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let name = names.get(place).ok_or(MailError::Invalid)?;
    Ok(format!("{day}-{name}-{year}"))
}

fn email(value: &str) -> bool {
    value.len() <= 254
        && value
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"<>(),;:\\\"".contains(&b))
        && value.split('@').count() == 2
        && !value.starts_with('@')
        && !value.ends_with('@')
}

/// The form of a submission, which a call judges before it creates its event: one to 50
/// recipients that are addresses, and a message of ASCII lines that end in CRLF whose header
/// block holds exactly one `From` field. Returns the value of that field. Whether it names
/// the account of the record is judged after the entry of the call ([`AppPassword::submit`]):
/// that answer depends on the content of the record.
pub(crate) fn submission_sender<'a>(
    recipients: &[String],
    body: &'a [u8],
) -> Result<&'a str, MailError> {
    if recipients.is_empty() || recipients.len() > 50 || recipients.iter().any(|v| !email(v)) {
        return Err(MailError::Invalid);
    }
    if !body.is_ascii()
        || !body.ends_with(b"\r\n")
        || body.windows(2).any(|pair| match pair {
            [first, second] => {
                (*first == b'\r' && *second != b'\n') || (*second == b'\n' && *first != b'\r')
            }
            _ => false,
        })
    {
        return Err(MailError::Invalid);
    }
    let text = std::str::from_utf8(body).map_err(|_| MailError::Invalid)?;
    let (headers, _) = text.split_once("\r\n\r\n").ok_or(MailError::Invalid)?;
    let from: Vec<_> = headers
        .split("\r\n")
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("from").then_some(value.trim())
        })
        .collect();
    match from.as_slice() {
        [sender] => Ok(sender),
        _ => Err(MailError::Invalid),
    }
}

struct Smtp {
    io: BufReader<BufWriter<MailStream>>,
    size: Option<usize>,
}
impl Smtp {
    async fn command(&mut self, bytes: &[u8]) -> Result<(u16, Vec<String>), MailError> {
        self.io
            .get_mut()
            .write_all(bytes)
            .await
            .map_err(|_| MailError::Unavailable)?;
        self.io
            .get_mut()
            .flush()
            .await
            .map_err(|_| MailError::Unavailable)?;
        self.reply().await
    }
    async fn reply(&mut self) -> Result<(u16, Vec<String>), MailError> {
        let mut lines = Vec::new();
        let mut expected = None;
        loop {
            let mut line = String::new();
            if self
                .io
                .read_line(&mut line)
                .await
                .map_err(|_| MailError::Unavailable)?
                == 0
                || line.len() > 4096
                || lines.len() >= 100
            {
                return Err(MailError::Unavailable);
            }
            let code = line
                .get(..3)
                .and_then(|s| s.parse::<u16>().ok())
                .ok_or(MailError::Unavailable)?;
            if expected.is_some_and(|other| other != code) {
                return Err(MailError::Unavailable);
            }
            expected = Some(code);
            let separator = line
                .as_bytes()
                .get(3)
                .copied()
                .ok_or(MailError::Unavailable)?;
            lines.push(line);
            match separator {
                b' ' => return Ok((code, lines)),
                b'-' => {}
                _ => return Err(MailError::Unavailable),
            }
        }
    }
}

/// What one call may take from an IMAP connection, and what that costs the call.
///
/// `left` bounds the protocol input: the connection delivers no byte above it. `accounted` is
/// what the call holds of its input: the bytes it took, and the octets still to come of a
/// literal the server declared. The buffer of a literal has the length of the literal from
/// the moment the literal is admitted, so a declaration alone commits that memory. Two rules
/// keep it inside the share of the call. A declaration above what is left of the input bound
/// ends the input: its octets could not arrive under the bound. And the share of the call is
/// raised to `accounted` times what the call holds per byte ([`Share`]) before the buffer of
/// a literal is made and before a byte that was taken is read. So what a connection holds of
/// its input never exceeds its input bound, whatever length a server declares, and the call
/// holds a share of the body budget for all of it.
pub(crate) struct Allowance {
    /// Bytes the call may still take from the connection.
    left: usize,
    /// Bytes the call took, and the octets still to come of a declared literal.
    accounted: usize,
    /// The octets of declared literals that are accounted and were not taken yet.
    outstanding: usize,
    /// What the call holds at once per byte of `accounted`, and the share that covers it.
    /// `None` for a connection whose whole input bound the call reserved before it opened
    /// the connection.
    charge: Option<(usize, Arc<Share>)>,
}

impl Allowance {
    /// `bound` bytes of input, for each of which the call holds `held_per_byte` bytes at once
    /// and takes them into its share as the input arrives.
    pub(crate) fn charged(bound: usize, held_per_byte: usize, share: &Arc<Share>) -> Allowance {
        Allowance {
            left: bound,
            accounted: 0,
            outstanding: 0,
            charge: Some((held_per_byte, share.clone())),
        }
    }

    /// `bound` bytes of input that the call reserved before it opened the connection.
    pub(crate) fn reserved(bound: usize) -> Allowance {
        Allowance {
            left: bound,
            accounted: 0,
            outstanding: 0,
            charge: None,
        }
    }

    /// Raises the share of the call to what it holds of its input now.
    fn cover(&self) -> Result<(), MailError> {
        match &self.charge {
            Some((held_per_byte, share))
                if !share.cover(self.accounted.saturating_mul(*held_per_byte)) =>
            {
                Err(MailError::Capacity)
            }
            _ => Ok(()),
        }
    }

    /// Counts `bytes` bytes the connection just delivered. The octets of a declared literal
    /// among them were accounted when they were declared.
    fn take(&mut self, bytes: usize) -> Result<(), MailError> {
        self.left = self.left.saturating_sub(bytes);
        let declared = bytes.min(self.outstanding);
        self.outstanding = self.outstanding.saturating_sub(declared);
        self.accounted = self
            .accounted
            .saturating_add(bytes.saturating_sub(declared));
        self.cover()
    }

    /// Accounts the `missing` octets of a literal the server declared that the connection
    /// has not delivered yet. They arrive within what is left of the bound, or not at all:
    /// a declaration above it is [`MailError::Unavailable`].
    fn declare(&mut self, missing: u64) -> Result<(), MailError> {
        let missing = usize::try_from(missing)
            .ok()
            .filter(|missing| *missing <= self.left)
            .ok_or(MailError::Unavailable)?;
        self.outstanding = self.outstanding.saturating_add(missing);
        self.accounted = self.accounted.saturating_add(missing);
        self.cover()
    }
}

/// A connection to the IMAP server: the byte pipe with TLS that ends inside the node, the
/// reader of its responses ([`crate::imap`]) and the input its call may take from it. Every
/// byte the server sends passes the [`Allowance`] of the call before the reader takes it: the
/// input bound, and the share of the body budget. The reader is the one place that says where
/// the octets of a literal are, so the octets the allowance counts are the octets a response
/// holds.
pub(crate) struct ImapConnection {
    stream: Stream,
    reader: imap::Reader,
    /// Bytes the stream delivered. The reader took the first `taken` of them.
    buffer: Vec<u8>,
    taken: usize,
    /// What the call of the connection may take from it. `None` for a connection that
    /// carries no call (a kept session): it takes no input.
    allowance: Option<Allowance>,
    /// The number of the last tag.
    tags: u64,
    /// True once the stream ended or failed, or the server said that it ends the connection
    /// (`BYE`).
    lost: bool,
}

impl ImapConnection {
    fn new(stream: Stream, allowance: Allowance) -> ImapConnection {
        ImapConnection {
            stream,
            reader: imap::Reader::default(),
            buffer: Vec::new(),
            taken: 0,
            allowance: Some(allowance),
            tags: 0,
            lost: false,
        }
    }

    /// Gives the connection to a call: the call takes its input, within this allowance.
    fn serve(&mut self, allowance: Allowance) {
        self.allowance = Some(allowance);
    }

    /// Takes the connection from its call, with the hold of the call on its share of the
    /// body budget, and gives back the room of its buffer. True when the connection can
    /// carry a further call: its stream has not ended, the reader stands between two
    /// responses, and the connection holds no byte of a further one.
    fn rest(&mut self) -> bool {
        self.allowance = None;
        let at_rest = !self.lost && self.taken >= self.buffer.len() && self.reader.at_rest();
        self.buffer = Vec::new();
        self.taken = 0;
        at_rest
    }

    /// Writes bytes of a command.
    async fn write(&mut self, bytes: &[u8]) -> Result<(), MailError> {
        let written = async {
            self.stream.write_all(bytes).await?;
            self.stream.flush().await
        };
        written.await.map_err(|_| {
            self.lost = true;
            MailError::Unavailable
        })
    }

    /// Writes one line of a command.
    async fn line(&mut self, text: &str) -> Result<(), MailError> {
        let mut line = Vec::with_capacity(text.len().saturating_add(2));
        line.extend_from_slice(text.as_bytes());
        line.extend_from_slice(b"\r\n");
        self.write(&line).await
    }

    /// The tag of the next command.
    fn next_tag(&mut self) -> String {
        self.tags = self.tags.saturating_add(1);
        format!("a{}", self.tags)
    }

    /// Sends a command under a new tag and returns the tag.
    async fn command(&mut self, command: &str) -> Result<String, MailError> {
        let tag = self.next_tag();
        self.line(&format!("{tag} {command}")).await?;
        Ok(tag)
    }

    /// `LOGIN` with the account name and the application password, each as a quoted string.
    /// The line that holds the password is overwritten when it was written. A `NO` that says
    /// the server refused the credentials is [`MailError::Auth`].
    async fn login(&mut self, user: &str, password: &str) -> Result<(), MailError> {
        let tag = self.next_tag();
        // Room for the whole line, every character escaped: no shorter buffer with a part
        // of the password is left behind by a growth.
        let mut line = Zeroizing::new(String::with_capacity(
            tag.len()
                .saturating_add(16)
                .saturating_add(user.len().saturating_add(password.len()).saturating_mul(2)),
        ));
        line.push_str(&tag);
        line.push_str(" LOGIN ");
        for (text, behind) in [(user, " "), (password, "\r\n")] {
            line.push('"');
            for character in text.chars() {
                if matches!(character, '"' | '\\') {
                    line.push('\\');
                }
                line.push(character);
            }
            line.push('"');
            line.push_str(behind);
        }
        self.write(line.as_bytes()).await?;
        loop {
            let response = self.response().await?;
            match turn(&response, &tag) {
                Turn::Completed(true) => return Ok(()),
                Turn::Completed(false) => {
                    return match response {
                        Response::Tagged(_, status)
                            if status.condition == Condition::No
                                && credentials_refused(&status) =>
                        {
                            Err(MailError::Auth)
                        }
                        _ => Err(MailError::Unavailable),
                    };
                }
                Turn::Ended => return Err(MailError::Unavailable),
                Turn::Data => {}
            }
        }
    }

    /// The next response of the server. The end of the connection, the end of the input the
    /// call may take, and bytes that are no response are [`MailError::Unavailable`]; a body
    /// budget without room for the input is [`MailError::Capacity`].
    async fn response(&mut self) -> Result<Response, MailError> {
        loop {
            let ahead = self.buffer.get(self.taken..).unwrap_or_default();
            let (taken, step) = self.reader.feed(ahead);
            self.taken = self.taken.saturating_add(taken);
            if self.taken >= self.buffer.len() {
                self.buffer.clear();
                self.taken = 0;
            }
            match step {
                Step::Response(raw) => {
                    let response = imap::parse(raw).ok_or(MailError::Unavailable)?;
                    if matches!(&response, Response::Untagged(status) if status.condition == Condition::Bye)
                    {
                        self.lost = true;
                    }
                    return Ok(response);
                }
                Step::Malformed => return Err(MailError::Unavailable),
                Step::Literal(octets) => {
                    // The octets the stream has not delivered yet are accounted, and held
                    // against the input bound, before the buffer of the literal is made.
                    let ahead = self.buffer.len().saturating_sub(self.taken) as u64;
                    self.allowance
                        .as_mut()
                        .ok_or(MailError::Unavailable)?
                        .declare(octets.saturating_sub(ahead))?;
                    self.reader.admit();
                }
                Step::More => self.fill().await?,
            }
        }
    }

    /// Takes the next bytes from the stream, within the allowance of the call. The reader
    /// took every byte the buffer held: the buffer is empty. Without a call, and at the input
    /// bound of its call, the connection takes no further byte.
    async fn fill(&mut self) -> Result<(), MailError> {
        let allowance = self.allowance.as_mut().ok_or(MailError::Unavailable)?;
        let window = IMAP_READ_BYTES.min(allowance.left);
        if window == 0 {
            return Err(MailError::Unavailable);
        }
        self.buffer.reserve(window);
        let read = (&mut self.stream)
            .take(window as u64)
            .read_buf(&mut self.buffer)
            .await;
        match read {
            Ok(read) if read > 0 => allowance.take(read),
            _ => {
                self.lost = true;
                Err(MailError::Unavailable)
            }
        }
    }
}

/// The connection to the SMTP server: the byte pipe with TLS that ends inside the node, and
/// the bound of its input. At its bound the connection delivers no further byte.
///
/// Debug never includes transport buffers or authentication bytes.
struct MailStream {
    inner: Stream,
    /// Bytes the connection may still deliver.
    left: usize,
}

impl MailStream {
    fn bounded(inner: Stream, input_bytes: usize) -> MailStream {
        MailStream {
            inner,
            left: input_bytes,
        }
    }
}

impl fmt::Debug for MailStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MailStream(..)")
    }
}

impl AsyncRead for MailStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let window = buf.remaining().min(this.left);
        if window == 0 {
            // The end of the input.
            return Poll::Ready(Ok(()));
        }
        let read = {
            let mut within = ReadBuf::new(buf.initialize_unfilled_to(window));
            std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut within))?;
            within.filled().len()
        };
        buf.advance(read);
        this.left = this.left.saturating_sub(read);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MailStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
impl ImapSession {
    /// A session over `stream` whose login was at `login_ms`, that carries no call.
    pub(crate) fn for_test(stream: Stream, login_ms: u64) -> ImapSession {
        let mut connection = ImapConnection::new(stream, Allowance::reserved(0));
        connection.rest();
        ImapSession {
            connection,
            in_step: true,
            answered: false,
            login_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_input_of_a_connection_ends_at_a_literal_that_cannot_arrive_within_its_bound() {
        // The bound leaves room for the 40 octets of a declared literal: they are accounted
        // when they are declared, and not again when they arrive.
        let mut allowance = Allowance::reserved(64);
        assert!(allowance.take(24).is_ok());
        assert!(allowance.declare(40).is_ok());
        assert_eq!((allowance.accounted, allowance.left), (64, 40));
        assert!(allowance.take(40).is_ok());
        assert_eq!((allowance.accounted, allowance.left), (64, 0));
        // One byte less of the bound, and the literal cannot arrive: the input ends at the
        // declaration.
        let mut allowance = Allowance::reserved(63);
        assert!(allowance.take(24).is_ok());
        assert!(matches!(allowance.declare(40), Err(MailError::Unavailable)));
        assert!(matches!(
            allowance.declare(u64::MAX),
            Err(MailError::Unavailable)
        ));
    }

    #[test]
    fn the_share_of_a_call_follows_its_input_and_ends_where_the_budget_does() {
        let step = SHARE_STEP_BYTES;
        let budget = Arc::new(Semaphore::new(4 * step));
        let held = |budget: &Arc<Semaphore>| 4 * step - budget.available_permits();
        let share = Share::admit(&budget, 1_000).unwrap();
        assert_eq!(held(&budget), 1_000);
        let mut allowance = Allowance::charged(1 << 20, 2, &share);

        // Ten bytes of text, of which the call holds twenty: one step.
        assert!(allowance.take(10).is_ok());
        assert_eq!(held(&budget), 1_000 + step);
        // A declared literal of one step: the call takes what it will hold of it, twice its
        // length, before an octet arrived. With the text that is three steps.
        assert!(allowance.take(30).is_ok());
        assert!(allowance.declare(step as u64).is_ok());
        assert_eq!(held(&budget), 1_000 + 3 * step);
        // The octets arrive: nothing more is taken.
        assert!(allowance.take(step).is_ok());
        assert_eq!(held(&budget), 1_000 + 3 * step);

        // A second literal of that length needs five steps in all, and the budget has four:
        // the input ends, and the call keeps what it held.
        assert!(matches!(
            allowance.declare(step as u64),
            Err(MailError::Capacity)
        ));
        assert_eq!(held(&budget), 1_000 + 3 * step);

        // The response frame takes the share of what it holds and gives it back with
        // itself. It never takes more than the call held.
        let frame = share.settle(500).unwrap();
        assert_eq!(held(&budget), 500);
        assert!(share.settle(500).is_none());
        drop(frame);
        assert_eq!(held(&budget), 0);
        let share = Share::admit(&budget, 100).unwrap();
        let frame = share.settle(4 * step).unwrap();
        assert_eq!(held(&budget), 100);
        drop(frame);

        // A share is taken without waiting: none when the bytes are not free.
        let all = Share::admit(&budget, 4 * step).unwrap();
        assert!(Share::admit(&budget, 1).is_none());
        assert!(all.rebase(step));
        assert_eq!(held(&budget), step);
    }
}
