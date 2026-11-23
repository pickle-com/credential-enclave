//! Fixed Naver IMAP/SMTP operations. Authentication bytes only reach in-node TLS streams.
//!
//! The responses of the IMAP server are read by the reader of this program (`crate::imap`),
//! which reads what the commands of a mail call need and passes over the rest. This module
//! sends those commands and decides what a response is to the command it answers.

use std::{
    collections::BTreeMap,
    fmt, io,
    pin::Pin,
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
use zeroize::Zeroizing;

use crate::imap::{self, Code, Condition, Fetched, Response, Status, Step};
use crate::platform::Stream;
use crate::provider_response::{self, CheckedResponse};
use crate::state::{open_for, GrantView, Limits, Node};

/// Protocol input a verify, folder listing or search connection accepts: 4 MiB. A UID set or
/// headers above it end the connection; the search must be narrowed.
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

/// Protocol input an SMTP connection accepts.
pub(crate) const SMTP_INPUT_BYTES: usize = 64 * 1024;

/// The most bytes a connection to the IMAP server takes from its stream in one read.
const IMAP_READ_BYTES: usize = 16 * 1024;

/// Whether a `NO` reply to `LOGIN` says that the server refused the credentials. Two forms
/// count: the RFC 5530 response code `AUTHENTICATIONFAILED`, and the information
/// `Authentication failed` that imap.naver.com sends with its own response code `[AUTH]`
/// (`NO [AUTH] "name": Authentication failed. (Please check your username, password)`). Any
/// other `NO` is a provider failure.
fn credentials_refused(status: &Status) -> bool {
    status.mentions(b"authenticationfailed") || status.mentions(b"authentication failed")
}

/// Only the mail call opens this kind. Neither field implements response serialization.
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
}

impl AppPassword {
    pub fn open(grant: &GrantView, user: &str, record: &Record) -> Result<Self, ProtocolError> {
        let (kind, bytes) = open_for(grant, user, record)?;
        if kind != Kind::AppPassword || record.provider != "naver_mail" {
            return Err(ProtocolError::NotAllowed);
        }
        let value = Secret::new(
            serde_json::from_slice::<Value>(bytes.expose_secret())
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
        Ok(Self {
            identity: format!("{id}@naver.com"),
            password: Secret::new(password.to_string()),
        })
    }

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
    /// The connection delivers at most `input_bytes` of protocol input.
    async fn imap(&self, node: &Node, input_bytes: usize) -> Result<ImapSession, MailError> {
        let stream = node
            .egress
            .open_mail(node.platform.as_ref(), "imap.naver.com", 993, CALL_TIMEOUT)
            .await
            .map_err(|_| MailError::Unavailable)?;
        let mut connection = ImapConnection::new(stream, input_bytes);
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
        drop(self.imap(node, LISTING_INPUT_BYTES).await?);
        drop(self.smtp(node).await?);
        Ok(())
    }

    pub async fn read(&self, node: &Node, request: &ReadMail) -> Result<MailData, MailError> {
        request.validate()?;
        // A UID search can expand into a large set before pagination. Bound listing and
        // header input separately from a raw message, whose content has the frame limit.
        let input_bytes = if request.action == "read" {
            message_input_bytes(&node.limits)
        } else {
            LISTING_INPUT_BYTES
        };
        let mut session = self.imap(node, input_bytes).await?;
        session.read(request, &node.limits).await
    }

    pub(crate) fn validate_submission(
        &self,
        recipients: &[String],
        body: &[u8],
    ) -> Result<(), MailError> {
        if recipients.is_empty() || recipients.len() > 50 || recipients.iter().any(|v| !email(v)) {
            return Err(MailError::Invalid);
        }
        validate_message(body, &self.identity)
    }

    /// A single authenticated SMTP transaction through K7. No retry follows DATA.
    pub async fn submit(
        &self,
        node: &Node,
        recipients: &[String],
        body: &[u8],
    ) -> Result<MailData, MailError> {
        self.validate_submission(recipients, body)?;
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
pub(crate) struct ImapSession {
    connection: ImapConnection,
    /// True while every command the node sent got its tagged completion: the next command
    /// starts an exchange of its own. False from the moment a command is sent to the moment
    /// its completion was read, and for good once the connection failed in between.
    in_step: bool,
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

fn validate_message(body: &[u8], identity: &str) -> Result<(), MailError> {
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
    if from != [identity] {
        return Err(MailError::Invalid);
    }
    Ok(())
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

/// A connection to the IMAP server: the byte pipe with TLS that ends inside the node, the
/// reader of its responses ([`crate::imap`]) and the bound of its protocol input.
///
/// The connection takes at most `left` further bytes from its stream. A literal the server
/// declares is held against that bound when it is declared: a declaration above what is left
/// of the bound ends the input before the buffer of the literal is made, because its octets
/// could not arrive under the bound. So what a connection holds of its input never exceeds
/// its input bound, whatever length a server declares.
pub(crate) struct ImapConnection {
    stream: Stream,
    reader: imap::Reader,
    /// Bytes the stream delivered. The reader took the first `taken` of them.
    buffer: Vec<u8>,
    taken: usize,
    /// Bytes the connection may still take from its stream.
    left: usize,
    /// The number of the last tag.
    tags: u64,
}

impl ImapConnection {
    fn new(stream: Stream, input_bytes: usize) -> ImapConnection {
        ImapConnection {
            stream,
            reader: imap::Reader::default(),
            buffer: Vec::new(),
            taken: 0,
            left: input_bytes,
            tags: 0,
        }
    }

    /// Writes one line of a command.
    async fn line(&mut self, text: &str) -> Result<(), MailError> {
        let written = async {
            self.stream.write_all(text.as_bytes()).await?;
            self.stream.write_all(b"\r\n").await?;
            self.stream.flush().await
        };
        written.await.map_err(|_| MailError::Unavailable)
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
        let written = async {
            self.stream.write_all(line.as_bytes()).await?;
            self.stream.flush().await
        };
        written.await.map_err(|_| MailError::Unavailable)?;
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
    /// connection may take, and bytes that are no response are [`MailError::Unavailable`].
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
                Step::Response(raw) => return imap::parse(raw).ok_or(MailError::Unavailable),
                Step::Malformed => return Err(MailError::Unavailable),
                Step::Literal(octets) => {
                    // The octets the stream has not delivered yet arrive within what is
                    // left of the bound, or the input ends here.
                    let ahead = self.buffer.len().saturating_sub(self.taken) as u64;
                    if octets.saturating_sub(ahead) > self.left as u64 {
                        return Err(MailError::Unavailable);
                    }
                    self.reader.admit();
                }
                Step::More => self.fill().await?,
            }
        }
    }

    /// Takes the next bytes from the stream, within the bound of the connection. The reader
    /// took every byte the buffer held: the buffer is empty.
    async fn fill(&mut self) -> Result<(), MailError> {
        let window = IMAP_READ_BYTES.min(self.left);
        if window == 0 {
            return Err(MailError::Unavailable);
        }
        self.buffer.reserve(window);
        let read = (&mut self.stream)
            .take(window as u64)
            .read_buf(&mut self.buffer)
            .await
            .map_err(|_| MailError::Unavailable)?;
        if read == 0 {
            return Err(MailError::Unavailable);
        }
        self.left = self.left.saturating_sub(read);
        Ok(())
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
