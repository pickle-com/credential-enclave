//! Fixed Naver IMAP/SMTP operations. Authentication bytes only reach in-node TLS streams.

use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};

use async_imap::imap_proto::{
    AttributeValue, MailboxDatum, MessageSection, Response, SectionPath, Status,
};
use async_imap::{Client, Session};
use base64::{engine::general_purpose::STANDARD, Engine};
use credential_enclave_protocol::record::{Kind, Record};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::ProtocolError;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter,
    ReadBuf,
};
use zeroize::Zeroizing;

use crate::platform::Stream;
use crate::provider_response::{self, CheckedResponse};
use crate::state::{open_for, GrantView, Limits, Node};

/// Protocol input a verify, folder listing or search connection accepts: 4 MiB. A UID set or
/// headers above it end the connection; the search must be narrowed.
pub(crate) const LISTING_INPUT_BYTES: usize = 4 * 1024 * 1024;

/// Protocol input a raw message read accepts: the body limit plus 1 MiB of protocol overhead.
/// The returned message itself still has the body limit.
pub(crate) fn message_input_bytes(limits: &Limits) -> usize {
    limits.body_bytes + 1024 * 1024
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

    async fn imap(
        &self,
        node: &Node,
        response_bytes: usize,
    ) -> Result<Session<MailStream>, MailError> {
        let stream = node
            .egress
            .open_mail(node.platform.as_ref(), "imap.naver.com", 993)
            .await
            .map_err(|_| MailError::Unavailable)?;
        let mut client = Client::new(limited(stream, response_bytes));
        client
            .read_response()
            .await
            .map_err(|_| MailError::Unavailable)?
            .ok_or(MailError::Unavailable)?;
        let login = self
            .identity
            .strip_suffix("@naver.com")
            .ok_or(MailError::Invalid)?;
        client
            .login(login, self.password.expose_secret())
            .await
            .map_err(|(error, _)| match error {
                async_imap::error::Error::No(text)
                    if text.to_ascii_lowercase().contains("authenticationfailed") =>
                {
                    MailError::Auth
                }
                _ => MailError::Unavailable,
            })
    }

    async fn smtp(&self, node: &Node) -> Result<Smtp, MailError> {
        let stream = node
            .egress
            .open_mail(node.platform.as_ref(), "smtp.naver.com", 465)
            .await
            .map_err(|_| MailError::Unavailable)?;
        let mut smtp = Smtp {
            io: BufReader::new(BufWriter::new(limited(stream, 65536))),
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
        let response_bytes = if request.action == "read" {
            message_input_bytes(&node.limits)
        } else {
            LISTING_INPUT_BYTES
        };
        let mut session = self.imap(node, response_bytes).await?;
        if request.action == "folders" {
            let folders = list_folders(&mut session).await?;
            return Ok(MailData::Json(json!({"folders": folders})));
        }
        let mailbox = session
            .examine(&request.mailbox)
            .await
            .map_err(|_| MailError::Unavailable)?;
        let validity = mailbox.uid_validity.ok_or(MailError::Unavailable)?;
        if request
            .uid_validity
            .is_some_and(|expected| expected != validity)
        {
            return Err(MailError::MailboxChanged);
        }
        if request.action == "search" {
            let upper = request
                .before_uid
                .unwrap_or(mailbox.uid_next.unwrap_or(u32::MAX))
                .saturating_sub(1);
            if upper == 0 {
                return Ok(MailData::Json(
                    json!({"uid_validity": validity, "messages": [], "next_uid": null}),
                ));
            }
            let mut uids = search_uids(&mut session, request.query(upper)?).await?;
            uids.sort_unstable_by(|a, b| b.cmp(a));
            uids.dedup();
            let more = uids.len() > request.limit;
            uids.truncate(request.limit);
            let next = if more { uids.last().copied() } else { None };
            let mut messages = Vec::new();
            if !uids.is_empty() {
                let set = uids
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                let rows =
                    uid_fetch(&mut session, &set, "(UID RFC822.SIZE BODY.PEEK[HEADER])").await?;
                for row in rows {
                    let uid = row.uid.ok_or(MailError::Unavailable)?;
                    if !uids.contains(&uid) {
                        return Err(MailError::Unavailable);
                    }
                    messages.push(json!({"uid": uid, "size": row.size, "headers_b64": STANDARD.encode(row.header.as_deref().unwrap_or_default())}));
                }
                messages
                    .sort_by_key(|row| std::cmp::Reverse(row["uid"].as_u64().unwrap_or_default()));
            }
            return Ok(MailData::Json(
                json!({"uid_validity": validity, "messages": messages, "next_uid": next}),
            ));
        }
        let uid = request.uid.ok_or(MailError::Invalid)?;
        let uid_set = uid.to_string();
        let sizes = uid_fetch(&mut session, &uid_set, "(UID RFC822.SIZE)").await?;
        let size = sizes
            .iter()
            .find(|row| row.uid == Some(uid))
            .and_then(|row| row.size)
            .ok_or(MailError::Missing)?;
        if size as usize > node.limits.body_bytes {
            return Err(MailError::TooLarge);
        }
        let rows = uid_fetch(&mut session, &uid_set, "(UID BODY.PEEK[])").await?;
        let body = rows
            .into_iter()
            .find(|row| row.uid == Some(uid))
            .and_then(|row| row.body)
            .ok_or(MailError::Missing)?;
        if body.len() > node.limits.body_bytes {
            return Err(MailError::TooLarge);
        }
        Ok(MailData::Raw(body))
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
            250 => Ok(MailData::Json(
                json!({"status": "accepted", "smtp_code": code}),
            )),
            400..=599 => Ok(rejected(code)),
            _ => Err(MailError::Unavailable),
        }
    }
}

fn rejected(code: u16) -> MailData {
    MailData::Json(json!({"status": "rejected", "smtp_code": code}))
}

pub enum MailData {
    Json(Value),
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
            || self.mailbox.len() > 1024
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

async fn list_folders(session: &mut Session<MailStream>) -> Result<Vec<Value>, MailError> {
    let tag = session
        .run_command("LIST \"\" \"*\"")
        .await
        .map_err(|_| MailError::Unavailable)?;
    let mut folders = Vec::new();
    loop {
        let response = session
            .read_response()
            .await
            .map_err(|_| MailError::Unavailable)?
            .ok_or(MailError::Unavailable)?;
        match response.parsed() {
            Response::MailboxData(MailboxDatum::List(data)) => {
                folders.push(json!({"name": data.name.as_ref()}));
            }
            Response::Done {
                tag: response_tag,
                status: Status::Ok,
                ..
            } if *response_tag == tag => return Ok(folders),
            Response::Done { .. }
            | Response::Data {
                status: Status::Bye,
                ..
            } => return Err(MailError::Unavailable),
            _ => {}
        }
    }
}

struct FetchedMessage {
    uid: Option<u32>,
    size: Option<u32>,
    header: Option<Vec<u8>>,
    body: Option<Vec<u8>>,
}

async fn uid_fetch(
    session: &mut Session<MailStream>,
    set: &str,
    items: &str,
) -> Result<Vec<FetchedMessage>, MailError> {
    let tag = session
        .run_command(format!("UID FETCH {set} {items}"))
        .await
        .map_err(|_| MailError::Unavailable)?;
    let mut rows = Vec::new();
    loop {
        let response = session
            .read_response()
            .await
            .map_err(|_| MailError::Unavailable)?
            .ok_or(MailError::Unavailable)?;
        match response.parsed() {
            Response::Fetch(_, attrs) => {
                let mut row = FetchedMessage {
                    uid: None,
                    size: None,
                    header: None,
                    body: None,
                };
                for attr in attrs {
                    match attr {
                        AttributeValue::Uid(uid) => row.uid = Some(*uid),
                        AttributeValue::Rfc822Size(size) => row.size = Some(*size),
                        AttributeValue::BodySection {
                            section: Some(SectionPath::Full(MessageSection::Header)),
                            data: Some(header),
                            ..
                        }
                        | AttributeValue::Rfc822Header(Some(header)) => {
                            row.header = Some(header.to_vec());
                        }
                        AttributeValue::BodySection {
                            section: None,
                            data: Some(body),
                            ..
                        }
                        | AttributeValue::Rfc822(Some(body)) => {
                            row.body = Some(body.to_vec());
                        }
                        _ => {}
                    }
                }
                rows.push(row);
            }
            Response::Done {
                tag: response_tag,
                status: Status::Ok,
                ..
            } if *response_tag == tag => return Ok(rows),
            Response::Done { .. }
            | Response::Data {
                status: Status::Bye,
                ..
            } => return Err(MailError::Unavailable),
            _ => {}
        }
    }
}

async fn search_uids(
    session: &mut Session<MailStream>,
    pieces: Vec<String>,
) -> Result<Vec<u32>, MailError> {
    let mut pieces = pieces.into_iter();
    let tag = session
        .run_command(pieces.next().ok_or(MailError::Invalid)?)
        .await
        .map_err(|_| MailError::Unavailable)?;
    for piece in pieces {
        loop {
            let response = session
                .read_response()
                .await
                .map_err(|_| MailError::Unavailable)?
                .ok_or(MailError::Unavailable)?;
            match response.parsed() {
                Response::Continue(_) => break,
                Response::Done { .. }
                | Response::Data {
                    status: Status::Bye,
                    ..
                } => return Err(MailError::Unavailable),
                _ => {}
            }
        }
        session
            .run_command_untagged(piece)
            .await
            .map_err(|_| MailError::Unavailable)?;
    }
    let mut uids = Vec::new();
    loop {
        let response = session
            .read_response()
            .await
            .map_err(|_| MailError::Unavailable)?
            .ok_or(MailError::Unavailable)?;
        match response.parsed() {
            Response::MailboxData(MailboxDatum::Search(values)) => {
                uids.extend(values.iter().copied())
            }
            Response::Done {
                tag: response_tag,
                status: Status::Ok,
                ..
            } if *response_tag == tag => return Ok(uids),
            Response::Done { .. }
            | Response::Data {
                status: Status::Bye,
                ..
            } => return Err(MailError::Unavailable),
            _ => {}
        }
    }
}

fn imap_date(date: &str) -> Result<String, MailError> {
    let parts: Vec<_> = date.split('-').collect();
    if parts.len() != 3
        || parts[0].len() != 4
        || parts[1].len() != 2
        || parts[2].len() != 2
        || parts
            .iter()
            .any(|part| !part.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(MailError::Invalid);
    }
    let year: u32 = parts[0].parse().map_err(|_| MailError::Invalid)?;
    let month: usize = parts[1].parse().map_err(|_| MailError::Invalid)?;
    let day: u32 = parts[2].parse().map_err(|_| MailError::Invalid)?;
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
    if year == 0 || !(1..=12).contains(&month) || day == 0 || day > days[month - 1] {
        return Err(MailError::Invalid);
    }
    let names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    Ok(format!("{day}-{}-{year}", names[month - 1]))
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
        || body
            .windows(2)
            .any(|w| (w[0] == b'\r' && w[1] != b'\n') || (w[1] == b'\n' && w[0] != b'\r'))
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

/// Caps bytes delivered to the protocol client at `limit`, and refuses a literal declaration
/// above `limit` before the client's parser reads it. async-imap 0.12 grows its parser buffer
/// to a declared literal length with a zero-filled allocation (at most 512 MiB) before the
/// octets arrive, so without the guard a server's declaration alone would commit that memory.
/// With it, the parser buffer never exceeds `limit` plus one block, and the API reserves
/// memory by `limit` instead of the parser maximum.
fn limited(stream: Stream, limit: usize) -> MailStream {
    let (read, write) = tokio::io::split(stream);
    let read = LiteralGuard {
        inner: read.take(limit as u64),
        bound: limit,
        scan: LiteralScan::Text,
    };
    MailStream(Box::new(tokio::io::join(read, write)))
}

/// Where a scan of server bytes stands between literal declarations. RFC 3501 section 4.3:
/// a literal is `{` digits `}` CRLF followed by that many octets, and a quoted string holds
/// no CR or LF, so a declaration is recognized without tracking quoted strings. A line of
/// text that ends in `{digits}` is read as a declaration here and by the protocol parser
/// alike, so the two never disagree about where the octets are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LiteralScan {
    /// Outside a declaration.
    Text,
    /// After `{`: the digits read so far.
    Digits(u64),
    /// After `}`: the declared length, expecting CR.
    Closed(u64),
    /// After CR: the declared length, expecting LF.
    Cr(u64),
    /// Inside the octets of a literal: those still to come.
    Octets(u64),
}

impl LiteralScan {
    /// Advances over `bytes`. `Err(length)` is a declaration above `bound`; the scan does not
    /// continue past it.
    pub(crate) fn feed(&mut self, bytes: &[u8], bound: usize) -> Result<(), u64> {
        for &byte in bytes {
            *self = match (*self, byte) {
                (Self::Octets(remaining), _) if remaining > 1 => Self::Octets(remaining - 1),
                (Self::Octets(_), _) => Self::Text,
                (Self::Text, b'{') => Self::Digits(0),
                (Self::Text, _) => Self::Text,
                (Self::Digits(length), b'0'..=b'9') => Self::Digits(
                    length
                        .saturating_mul(10)
                        .saturating_add(u64::from(byte - b'0')),
                ),
                (Self::Digits(length), b'}') => Self::Closed(length),
                (Self::Closed(length), b'\r') => Self::Cr(length),
                (Self::Cr(length), b'\n') => {
                    if length > bound as u64 {
                        return Err(length);
                    }
                    if length == 0 {
                        Self::Text
                    } else {
                        Self::Octets(length)
                    }
                }
                (Self::Digits(_) | Self::Closed(_) | Self::Cr(_), b'{') => Self::Digits(0),
                (Self::Digits(_) | Self::Closed(_) | Self::Cr(_), _) => Self::Text,
            };
        }
        Ok(())
    }
}

/// The read half of a mail connection: every byte passes the literal scan before the
/// protocol client sees it.
struct LiteralGuard<R> {
    inner: R,
    bound: usize,
    scan: LiteralScan,
}

impl<R: AsyncRead + Unpin> AsyncRead for LiteralGuard<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled = buf.filled().len();
        std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        if this.scan.feed(&buf.filled()[filled..], this.bound).is_err() {
            return Poll::Ready(Err(io::Error::other(
                "a literal declaration above the response bound",
            )));
        }
        Poll::Ready(Ok(()))
    }
}

/// Debug never includes transport buffers or authentication bytes.
struct MailStream(Stream);
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
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}
impl AsyncWrite for MailStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}
