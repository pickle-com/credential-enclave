//! Fixed Naver IMAP/SMTP operations. Authentication bytes only reach in-node TLS streams.

use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};

use async_imap::{Client, Session};
use base64::{engine::general_purpose::STANDARD, Engine};
use credential_enclave_protocol::record::{Kind, Record};
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::ProtocolError;
use futures_util::TryStreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter,
    ReadBuf,
};
use zeroize::Zeroizing;

use crate::platform::Stream;
use crate::provider_response::{self, CheckedResponse};
use crate::state::{open_for, GrantView, Node};

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
        drop(self.imap(node, 4 * 1024 * 1024).await?);
        drop(self.smtp(node).await?);
        Ok(())
    }

    pub async fn read(&self, node: &Node, request: &ReadMail) -> Result<MailData, MailError> {
        request.validate()?;
        // A UID search can expand into a large set before pagination. Bound listing and
        // header input separately from a raw message, whose content has the frame limit.
        let response_bytes = if request.action == "read" {
            node.limits.body_bytes + 1024 * 1024
        } else {
            4 * 1024 * 1024
        };
        let mut session = self.imap(node, response_bytes).await?;
        if request.action == "folders" {
            let names: Vec<_> = session
                .list(None, Some("\"*\""))
                .await
                .map_err(|_| MailError::Unavailable)?
                .try_collect()
                .await
                .map_err(|_| MailError::Unavailable)?;
            return Ok(MailData::Json(
                json!({"folders": names.iter().map(|name| json!({"name": name.name()})).collect::<Vec<_>>()}),
            ));
        }
        let mailbox = session
            .examine(&request.mailbox)
            .await
            .map_err(|_| MailError::Unavailable)?;
        let validity = mailbox
            .uid_validity
            .filter(|v| *v > 0)
            .ok_or(MailError::Unavailable)?;
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
            let query = request.query(upper)?;
            let mut uids: Vec<_> = session
                .uid_search(query)
                .await
                .map_err(|_| MailError::Unavailable)?
                .into_iter()
                .collect();
            uids.sort_unstable_by(|a, b| b.cmp(a));
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
                let rows: Vec<_> = session
                    .uid_fetch(set, "UID RFC822.SIZE BODY.PEEK[HEADER]")
                    .await
                    .map_err(|_| MailError::Unavailable)?
                    .try_collect()
                    .await
                    .map_err(|_| MailError::Unavailable)?;
                for row in rows {
                    let uid = row.uid.ok_or(MailError::Unavailable)?;
                    if !uids.contains(&uid) {
                        return Err(MailError::Unavailable);
                    }
                    messages.push(json!({"uid": uid, "size": row.size, "headers_b64": STANDARD.encode(row.header().unwrap_or_default())}));
                }
                messages
                    .sort_by_key(|row| std::cmp::Reverse(row["uid"].as_u64().unwrap_or_default()));
            }
            return Ok(MailData::Json(
                json!({"uid_validity": validity, "messages": messages, "next_uid": next}),
            ));
        }
        let uid = request.uid.ok_or(MailError::Invalid)?;
        let sizes: Vec<_> = session
            .uid_fetch(uid.to_string(), "UID RFC822.SIZE")
            .await
            .map_err(|_| MailError::Unavailable)?
            .try_collect()
            .await
            .map_err(|_| MailError::Unavailable)?;
        let size = sizes
            .iter()
            .find(|row| row.uid == Some(uid))
            .and_then(|row| row.size)
            .ok_or(MailError::Missing)?;
        if size as usize > node.limits.body_bytes {
            return Err(MailError::TooLarge);
        }
        let rows: Vec<_> = session
            .uid_fetch(uid.to_string(), "UID BODY.PEEK[]")
            .await
            .map_err(|_| MailError::Unavailable)?
            .try_collect()
            .await
            .map_err(|_| MailError::Unavailable)?;
        let body = rows
            .iter()
            .find(|row| row.uid == Some(uid))
            .and_then(|row| row.body())
            .ok_or(MailError::Missing)?;
        if body.len() > node.limits.body_bytes {
            return Err(MailError::TooLarge);
        }
        Ok(MailData::Raw(body.to_vec()))
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
        if self.action == "read"
            && (self.uid.unwrap_or(0) == 0 || self.uid_validity.unwrap_or(0) == 0)
        {
            return Err(MailError::Invalid);
        }
        Ok(())
    }
    fn query(&self, upper: u32) -> Result<String, MailError> {
        let mut query = format!("CHARSET UTF-8 UID 1:{upper}");
        for (name, value) in [("FROM", &self.from), ("SUBJECT", &self.subject)] {
            if let Some(value) = value {
                if value.len() > 1024 || value.chars().any(char::is_control) {
                    return Err(MailError::Invalid);
                }
                query.push_str(&format!(
                    " {name} \"{}\"",
                    value.replace('\\', "\\\\").replace('"', "\\\"")
                ));
            }
        }
        if let Some(since) = &self.since {
            query.push_str(&format!(" SINCE {}", imap_date(since)?));
        }
        Ok(query)
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

/// Caps total bytes read, including IMAP literals, before the protocol client buffers them.
fn limited(stream: Stream, limit: usize) -> MailStream {
    let (read, write) = tokio::io::split(stream);
    MailStream(Box::new(tokio::io::join(read.take(limit as u64), write)))
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
