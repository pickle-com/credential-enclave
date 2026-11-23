//! The use of a vault secret in a request to its site (protocol.md 10.5): the request a secret
//! is bound to, and the envelope in which a node of the delegation role hands the value, with
//! that one request, to a node of the forward role.
//!
//! A node of the delegation role holds user keys and connects to the addresses of its provider
//! definitions and to its log store only. The site of a vault secret is a host the account
//! chose, so that node does not connect to it. It writes the event of the use first, a
//! `provider_request` that names the request, the name of the secret, its place and the node
//! of the forward role (protocol.md 7.2), and after the log store confirmed the entry it
//! seals the value to the sealing key of that node, together with the one request the value
//! may be used in: the method, the host, the path and the query, the place of the value, and
//! the size and the hash of the body. The node of the forward role opens the envelope, puts
//! the value at that place and sends that request to that host. It holds no user key and
//! opens no record: what it learns of an account is one value for one request.
//!
//! The envelope has a purpose string of its own for its signature and for its seal. A node
//! opens a delegation transfer (protocol.md 10.1) under another one, so the node of the
//! forward role has no operation that opens a transfer, and a node of the delegation role has
//! none that opens this envelope.
//!
//! This module holds the one reader of each of the two forms a record of a vault secret and a
//! request share (protocol.md section 6): a place a value may go to ([`Slot::parse`]) and the
//! host of a site ([`is_site_host`]). The plaintext of a record ([`crate::vault_secret`]: what
//! `vault/store` writes and what `release` reads), the request object of a use
//! ([`BoundRequest::from_value`]) and the node that sends the request read a slot and a host
//! with these two functions, so no two of them give different verdicts on one string.

use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::encoding::{b64u, b64u_decode, b64u_decode_array, to_json, verify_detached, wipe_json};
use crate::envelope::{hpke_seal, transfer_aad};
use crate::keys::{node_id, NodeKeys};
use crate::secret::Secret;
use crate::{is_valid_name, limits, purpose, ProtocolError};

/// The methods of a request a vault secret is used in.
pub const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/// The request headers a node of the forward role does not send for its caller: it writes
/// the host, the framing of the body and the state of the connection itself, it asks for the
/// coding `identity`, for the whole of a response and for no character encoding of it (it
/// searches the bytes of the response: a part of a response is no response it can search,
/// and under UTF-16 the bytes of a value are not the bytes it searches for), and it is no
/// proxy.
pub const DROPPED_HEADERS: [&str; 15] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "upgrade",
    "te",
    "trailer",
    "expect",
    "accept-encoding",
    "proxy-authorization",
    "range",
    "if-range",
    "accept-charset",
];

/// The request headers a node of the forward role refuses a call for: a header that asks a
/// server to treat a request as one of another method, or as one to another host or another
/// path, than the method, the host and the path it is sent with. The entry of a use names
/// those three, and the request that leaves is the request of the entry.
pub const REFUSED_HEADERS: [&str; 14] = [
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
    "forwarded",
    "x-forwarded-host",
    "x-forwarded-server",
    "x-forwarded-uri",
    "x-forwarded-prefix",
    "x-original-url",
    "x-original-uri",
    "x-original-host",
    "x-rewrite-url",
    "x-host",
    "x-http-host-override",
];

/// A header name as it is compared with the two lists above: in lower case, with `-` for
/// every `_`. Some servers read the two characters as one, so `Content_Length` is the header
/// `content-length` here.
pub fn header_key(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

/// True for a header of [`DROPPED_HEADERS`] or of [`REFUSED_HEADERS`]: no slot names such a
/// header ([`Slot::parse`]). A value in a header that frames a request, or that makes a server
/// take a request for another one, would make the request another request than the one its
/// entry names.
pub fn is_reserved_header(name: &str) -> bool {
    let key = header_key(name);
    DROPPED_HEADERS.contains(&key.as_str()) || REFUSED_HEADERS.contains(&key.as_str())
}

/// How often a text is read with its percent escapes decoded when a rule asks what a server
/// may make of it: a server that decodes a path more than once is not rare.
const ESCAPE_LAYERS: usize = 3;

/// True when `front`, the text in front of a placeholder, leaves the value behind it to
/// itself: it does not end with the beginning of a percent escape (`%`, or `%` and one
/// hexadecimal digit), neither as it stands nor with its percent escapes decoded, up to three
/// times.
///
/// A value is written percent-encoded where this rule applies, so a `%` of the caller in
/// front of it would take the first characters of the value for the digits of its escape: the
/// server would read another text than the value, and an answer that names that text would
/// not be an answer that holds the value.
pub fn leaves_the_value_alone(front: &[u8]) -> bool {
    let digit = |byte: Option<&u8>| byte.and_then(|byte| char::from(*byte).to_digit(16));
    let begins_escape = |text: &[u8]| match text {
        [.., b'%'] => true,
        [.., b'%', last] => last.is_ascii_hexdigit(),
        _ => false,
    };
    let mut text = front.to_vec();
    for _ in 0..=ESCAPE_LAYERS {
        if begins_escape(&text) {
            return false;
        }
        let mut decoded = Vec::with_capacity(text.len());
        let mut index = 0;
        while let Some(literal) = text.get(index).copied() {
            match (
                literal,
                digit(text.get(index + 1)),
                digit(text.get(index + 2)),
            ) {
                (b'%', Some(high), Some(low)) => {
                    decoded.push((high * 16 + low) as u8);
                    index += 3;
                }
                (byte, _, _) => {
                    decoded.push(byte);
                    index += 1;
                }
            }
        }
        if decoded.len() == text.len() {
            break;
        }
        text = decoded;
    }
    true
}

/// A place the value of a vault secret may go to (protocol.md section 6): the record of the
/// secret lists its places (`slots`). `field` is an input of a web page, where `release` hands
/// the value to the caller. The other seven are places inside an HTTPS request, where a node
/// of the forward role puts the value (protocol.md 10.5), and a request names one of them.
///
/// [`Slot::parse`] is the one reader of a slot: a slot that was read has the form of the table
/// there, and it writes ([`fmt::Display`]) the string it was read from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Slot {
    /// `field`: an input of a web page.
    Field,
    /// `header:<name>`: inside the value of the request header of that name.
    Header(String),
    /// `query:<name>`: the whole value of the query parameter of that name.
    Query(String),
    /// `form:<name>`: the whole value of the field of that name of a form body
    /// (`application/x-www-form-urlencoded`).
    Form(String),
    /// `json:<name>`: the whole string at that place of a JSON body. The name is object keys
    /// joined by `.`: one key names a member of the body, more keys a member of a nested
    /// object.
    Json(Vec<String>),
    /// `path`: inside the path of the address.
    Path,
    /// `basic:user` and `basic:password`: the whole user-id, or the whole password, of the
    /// credentials of HTTP Basic (RFC 7617) in the `Authorization` header. The credentials
    /// stand in that header as the base64 text of `user-id:password`, so the text of a
    /// placeholder is not in the header as it stands, and the slot `header:authorization`
    /// cannot name this place ([`BasicCredentials`]).
    ///
    /// The two halves are two slots. A server treats them differently: it may name the
    /// user-id it received in what it answers, in a form of its own, and it does not name a
    /// password. So a record says which half its value is, and a value its record holds as a
    /// password is written as a password and never as a user-id.
    Basic(BasicPart),
}

impl Slot {
    /// Reads a slot. `None` for a text that is not one of the eight forms.
    ///
    /// | Form | Name |
    /// | --- | --- |
    /// | `field`, `path` | none |
    /// | `basic:user`, `basic:password` | one of the two words. `basic` alone names no half and is no slot, and neither is `basic:` with another word |
    /// | `header:<name>` | 1 to 64 characters of `a` to `z`, `0` to `9` and `-`, and no header a node of the forward role drops or refuses ([`is_reserved_header`]) |
    /// | `query:<name>`, `form:<name>` | 1 to 64 characters that a query and a form body write without a percent escape: `A` to `Z`, `a` to `z`, `0` to `9`, `-`, `.`, `_` and `~` (the unreserved characters of RFC 3986) |
    /// | `json:<name>` | 1 to 64 bytes without a control character (U+0000 to U+001F, U+007F to U+009F) and without a white space character (the Unicode property White_Space), and the name is object keys joined by `.`: no key between two `.`, in front of the first or behind the last is empty |
    ///
    /// The name is what follows the first colon, so the name of a JSON slot may hold a colon
    /// itself.
    ///
    /// The name of a query or form slot is compared with the bytes of a query and of a form
    /// body as they stand ([`is_the_value_of`]): the node that sends a request decodes no
    /// escape of a parameter name. A name with a character outside the unreserved ones is
    /// written in a request with an escape or not at all, so no request could name such a
    /// slot, and the reader takes none.
    pub fn parse(text: &str) -> Option<Slot> {
        match text {
            "field" => return Some(Slot::Field),
            "path" => return Some(Slot::Path),
            _ => {}
        }
        let (kind, name) = text.split_once(':')?;
        let sized = (1..=limits::SLOT_NAME_BYTES).contains(&name.len());
        let plain = name
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace());
        let unreserved = name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte));
        match kind {
            "basic" => BasicPart::of_name(name).map(Slot::Basic),
            "header" => (sized
                && name.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                })
                && !is_reserved_header(name))
            .then(|| Slot::Header(name.to_string())),
            "query" => (sized && unreserved).then(|| Slot::Query(name.to_string())),
            "form" => (sized && unreserved).then(|| Slot::Form(name.to_string())),
            "json" => {
                let keys: Vec<String> = name.split('.').map(str::to_string).collect();
                (sized && plain && keys.iter().all(|key| !key.is_empty()))
                    .then_some(Slot::Json(keys))
            }
            _ => None,
        }
    }
}

/// A slot as a record and a request write it: the string [`Slot::parse`] reads.
impl fmt::Display for Slot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Slot::Field => formatter.write_str("field"),
            Slot::Path => formatter.write_str("path"),
            Slot::Basic(part) => write!(formatter, "basic:{}", part.name()),
            Slot::Header(name) => write!(formatter, "header:{name}"),
            Slot::Query(name) => write!(formatter, "query:{name}"),
            Slot::Form(name) => write!(formatter, "form:{name}"),
            Slot::Json(keys) => write!(formatter, "json:{}", keys.join(".")),
        }
    }
}

/// True for the host of a site (protocol.md section 6): a DNS name in lower case of at most
/// 253 bytes with two or more labels, each label 1 to 63 characters of `a` to `z`, `0` to `9`
/// and `-` that neither begins nor ends with `-`, whose last label begins with a letter.
///
/// The rule on the last label keeps an IPv4 address in any of its spellings out (`10.0.0.1`,
/// `2130706433.1`, `host.0x7f`): a host is a name. A name of one label is a name of the
/// network a node runs in, and no site.
///
/// This is the one reader of a host: the `sites` of a record and the `host` of a request are
/// read with it.
pub fn is_site_host(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    let label = |label: &&str| {
        (1..=limits::HOST_LABEL_BYTES).contains(&label.len())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    host.len() <= limits::HOST_BYTES
        && labels.len() >= 2
        && labels.iter().all(label)
        && labels
            .last()
            .and_then(|last| last.bytes().next())
            .is_some_and(|first| first.is_ascii_lowercase())
}

/// True for a placeholder: 16 to 128 characters of `A` to `Z`, `a` to `z`, `0` to `9`, `_`
/// and `-`. No encoding of a request changes such a text, so it is found where it stands.
pub fn is_placeholder(text: &str) -> bool {
    (limits::PLACEHOLDER_CHARS_MIN..=limits::PLACEHOLDER_CHARS_MAX).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// True for a value that can stand inside the value of a request header: it holds no control
/// character (U+0000 to U+001F and U+007F to U+009F). Inside a header a value is written as
/// it is, so a value with a line end would end the line of its header and begin another one.
///
/// A node of the delegation role makes this check for a slot `header:<name>` before it seals
/// a value (after the entry of the use: the check reads the value), and a node of the forward
/// role makes it before it writes one.
pub fn fits_header(value: &str) -> bool {
    !value.chars().any(char::is_control)
}

/// True for a character a server strips from the ends of a text it read: a white space
/// character (the Unicode property White_Space), a control character (U+0000 to U+001F and
/// U+007F to U+009F), and U+FEFF, the byte order mark.
///
/// A server strips a text with the function of its runtime, and the runtimes do not agree on
/// what that function removes. All of them remove white space. Some remove every character
/// up to U+0020 (`String.trim` of Java), and some U+FEFF (`trim` of JavaScript). This is what
/// one of them or another removes.
fn is_stripped(character: char) -> bool {
    character.is_whitespace() || character.is_control() || character == '\u{feff}'
}

/// The value of a vault secret as the search of a response looks for it (egress-policy.md,
/// rule E4): without the characters at its ends that a server strips from a text
/// ([`is_stripped`]: white space, control characters and U+FEFF).
///
/// A server reads the value of a header without the white space around it, and a server that
/// reads a parameter or a member of a body often strips it. So what a site sends back of a
/// value that was stored with a space, a line end or a byte order mark at one of its ends may
/// be the value without it, which is the value that site takes. A response that holds the
/// value with those characters holds it without them as well, in every form the search knows,
/// whichever of them a server removed.
pub fn searched_text(value: &str) -> &str {
    value.trim_matches(is_stripped)
}

/// True for a value that is used in a request (10.5): at most 12,000 bytes, of which 8 or
/// more are left without the characters a server strips at its ends ([`searched_text`]). Of a
/// shorter text no reflection is searched for in the response to its request, so no node
/// seals or sends such a value.
pub fn is_used_in_requests(value: &str) -> bool {
    value.len() <= limits::SECRET_USE_VALUE_BYTES_MAX
        && searched_text(value).len() >= limits::SECRET_USE_VALUE_BYTES_MIN
}

/// The authentication schemes whose credentials a value of a header slot does not stand in
/// ([`states_no_scheme`]): the name of each, in lower case.
///
/// - `basic` (RFC 7617), `negotiate` (RFC 4559) and `ntlm`: the credentials are one base64
///   text, and a server of the scheme decodes what follows the name of the scheme before it
///   reads it. It may name what it decoded in what it answers (the user-id of HTTP Basic),
///   and the search of a response reads the base64 text of a value as the value, not the
///   bytes a value decodes to: whoever reads such an answer encodes those bytes again.
/// - `digest` (RFC 7616): a server reads a user name from what follows the name of the
///   scheme, and may name it in what it answers in a form of its own. No stored value is
///   the credentials of this scheme: they are computed for each request.
///
/// A value that is one half of the credentials of HTTP Basic has a slot of its own
/// ([`Slot::Basic`]): a node writes those credentials itself, with the value as the half the
/// record of the value names.
pub const REFUSED_SCHEMES: [&str; 4] = ["basic", "digest", "negotiate", "ntlm"];

/// True when `text`, the value of an `Accept` or of a `Content-Type` header, names no
/// character encoding but UTF-8: wherever the word `charset` stands in it, in any case of its
/// letters, it is the parameter `charset=utf-8` (also written `utf8`), with or without
/// quotes.
///
/// A node searches the bytes of a response for a value, and it writes a value into a body
/// as UTF-8. A caller that asks a server for another character encoding of its response
/// (`Accept: application/json; charset=utf-16`), or that states one for a body
/// (`Content-Type: application/json; charset=utf-16`), would have the value sent back, or
/// read, as other bytes than the node searches for or wrote: in UTF-16 every character of a
/// value is two bytes. The header `Accept-Charset`, which asks for the same, is one of
/// [`DROPPED_HEADERS`].
pub fn names_no_other_charset(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let mut rest = lower.as_str();
    while let Some((_, behind)) = rest.split_once("charset") {
        let behind = behind.trim_start_matches([' ', '\t']);
        let Some(stated) = behind.strip_prefix('=') else {
            return false;
        };
        let stated = stated.trim_start_matches([' ', '\t']);
        let stated = stated.strip_prefix('"').unwrap_or(stated);
        let end = stated
            .find(|character: char| {
                !(character.is_ascii_alphanumeric() || "-_".contains(character))
            })
            .unwrap_or(stated.len());
        let Some((named, behind)) = stated.split_at_checked(end) else {
            return false;
        };
        if !matches!(named, "utf-8" | "utf8") {
            return false;
        }
        rest = behind;
    }
    true
}

/// True for a header a server may read the credentials of an HTTP authentication scheme
/// from: `Authorization` (RFC 9110 section 11.6.2), and every header whose name holds that
/// word (`x-authorization`, `x-forwarded-authorization`), which a server behind a gateway may
/// read the same way. The name is compared as [`header_key`] writes it.
pub fn reads_credentials(name: &str) -> bool {
    header_key(name).contains("authorization")
}

/// True when `front`, the text of a header value in front of a placeholder, leaves the value
/// to itself: it is empty, or it ends with a space, `=`, `:` or `"`. Inside a header a value
/// stands as it is, and what a server makes of a header value is its own matter: a text
/// that ends with the beginning of an escape of any syntax (`%4`, `\u004`, `&#x4`) would
/// take the first characters of the value for the rest of that escape.
pub fn stands_free(front: &str) -> bool {
    matches!(
        front.as_bytes().last(),
        None | Some(b' ' | b'=' | b':' | b'"')
    )
}

/// True when `front`, the text in front of a placeholder in the value of a header a server
/// reads credentials from ([`reads_credentials`]), names none of [`REFUSED_SCHEMES`]: it is
/// ASCII, and none of the names stands in it, in any case of its letters and at any place.
///
/// A server finds the scheme of credentials by a rule of its own: at the first word of the
/// header value, at its beginning, or wherever the name stands in it. So the name is looked
/// for in the whole text, and not as a word of it. And a server may compare a name without
/// regard to case by the rules of Unicode, under which a letter outside ASCII equals an
/// ASCII one (U+017F and `s`): a text with a character outside ASCII names no scheme a node
/// can tell.
///
/// Behind such a name a server does not read a value as it stands. A caller that could
/// write one there would move a value its record holds for the header (the token behind
/// `Bearer`) into the credentials of HTTP Basic, where a server decodes it and may send the
/// decoded bytes back: a text the search of a response does not find.
pub fn states_no_scheme(front: &str) -> bool {
    let lower = front.to_ascii_lowercase();
    front.is_ascii() && !REFUSED_SCHEMES.iter().any(|scheme| lower.contains(scheme))
}

/// True when `placeholder` stands in `value`, the value of the header `name`, where a node
/// of the forward role puts the value of a slot `header:<name>` (protocol.md 10.5): it
/// occurs once, the text in front of it leaves the value to itself ([`stands_free`]), and in
/// a header a server reads credentials from ([`reads_credentials`]) that text names no
/// scheme under which a server does not read a value as it stands ([`states_no_scheme`]).
pub fn is_placed_in_header(name: &str, value: &str, placeholder: &str) -> bool {
    let front = value.split(placeholder).next().unwrap_or_default();
    occurrences(value.as_bytes(), placeholder.as_bytes()) == 1
        && stands_free(front)
        && (!reads_credentials(name) || states_no_scheme(front))
}

/// True for a value that can be a half of the credentials of HTTP Basic (RFC 7617), the
/// user-id or the password: it holds no control character (U+0000 to U+001F and U+007F to
/// U+009F). RFC 7617 allows none in either half, and a server may refuse such credentials or
/// read them up to that character.
///
/// This is the judgement the two halves share. The judgement of one half is
/// [`BasicPart::admits`].
pub fn fits_basic(value: &str) -> bool {
    !value.chars().any(char::is_control)
}

/// The scheme of HTTP Basic and the one space behind it: how the value of an `Authorization`
/// header with such credentials begins.
const BASIC_SCHEME: &str = "Basic ";

/// A half of the credentials of HTTP Basic (RFC 7617). The credentials are the text
/// `user-id:password`, and the first colon of that text parts the two halves. A slot names
/// one of them ([`Slot::Basic`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BasicPart {
    /// The user-id: the text in front of the first colon. The slot `basic:user`.
    UserId,
    /// The password: the text behind the first colon. The slot `basic:password`.
    Password,
}

impl BasicPart {
    /// The name of the half in its slot: `user` or `password`.
    pub const fn name(self) -> &'static str {
        match self {
            BasicPart::UserId => "user",
            BasicPart::Password => "password",
        }
    }

    /// The half a slot names with `name`. `None` for every other text.
    fn of_name(name: &str) -> Option<BasicPart> {
        [BasicPart::UserId, BasicPart::Password]
            .into_iter()
            .find(|part| part.name() == name)
    }

    /// True when `value` can stand for this half: it holds no control character
    /// ([`fits_basic`]), and a user-id holds no colon. The first colon of the credentials
    /// ends the user-id, so a server would read a user-id with a colon up to that colon and
    /// take the rest of it for the beginning of the password: it would read another text
    /// than the value.
    ///
    /// A node of the delegation role makes this check before it seals a value for a slot of
    /// these credentials (after the entry of the use: the check reads the value), and a node
    /// of the forward role makes it before it writes one.
    pub fn admits(self, value: &str) -> bool {
        fits_basic(value) && (self == BasicPart::Password || !value.contains(':'))
    }
}

/// The credentials of HTTP Basic of a request in which a placeholder stands for one half:
/// which half that is, and the other half as the caller wrote it. Only
/// [`BasicCredentials::read`] creates one.
///
/// The half is read from what the caller wrote. The slot of the request names the half the
/// value may stand for, and the node that sends a request sends it only when the two are the
/// same half: the caller of a use does not choose the half.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicCredentials {
    part: BasicPart,
    other: String,
}

impl BasicCredentials {
    /// Reads the value of an `Authorization` header as credentials of HTTP Basic in which
    /// `placeholder` is the whole user-id or the whole password. `None` for every other
    /// value.
    ///
    /// - The value is `Basic`, one space, and the base64 text of the credentials, and
    ///   nothing else. The text is the one text a writer of RFC 4648 section 4 gives for its
    ///   bytes: the alphabet with `+` and `/`, the padding with `=`, and no bit set behind
    ///   the last byte.
    /// - The bytes of that text are UTF-8 and hold a colon. The first colon parts the
    ///   user-id from the password, and either half may be empty.
    /// - The placeholder occurs once in the credentials, and it is the whole of one half.
    ///
    /// So the value this function reads is the value [`BasicCredentials::written`] writes
    /// for the same credentials: the header a node sends differs from the header of its
    /// caller in the half the value stands for, and in nothing else.
    ///
    /// The scheme in another case of its letters, more than one space, base64url, a text
    /// without its padding and credentials in another character encoding are forms a server
    /// may read as well. A node reads none of them: it writes the header anew, and it reads
    /// the one form it writes.
    pub fn read(header: &str, placeholder: &str) -> Option<BasicCredentials> {
        let encoded = header.strip_prefix(BASIC_SCHEME)?;
        let decoded = STANDARD.decode(encoded).ok()?;
        if STANDARD.encode(&decoded) != encoded {
            return None;
        }
        let credentials = String::from_utf8(decoded).ok()?;
        let (user_id, password) = credentials.split_once(':')?;
        if occurrences(credentials.as_bytes(), placeholder.as_bytes()) != 1 {
            return None;
        }
        let (part, other) = match (user_id == placeholder, password == placeholder) {
            (true, false) => (BasicPart::UserId, password),
            (false, true) => (BasicPart::Password, user_id),
            _ => return None,
        };
        Some(BasicCredentials {
            part,
            other: other.to_string(),
        })
    }

    /// The half the placeholder stands for.
    pub fn part(&self) -> BasicPart {
        self.part
    }

    /// The other half, as the caller wrote it.
    pub fn other(&self) -> &str {
        &self.other
    }

    /// The value of the `Authorization` header with `value` in the place of the placeholder:
    /// `Basic`, one space, and the base64 text (RFC 4648 section 4, with its padding) of
    /// `user-id:password`. The result holds the value, so it is a secret.
    ///
    /// The caller checked that the value can stand for the half ([`BasicPart::admits`]).
    pub fn written(&self, value: &Secret<String>) -> Secret<String> {
        let value = value.expose_secret().as_str();
        let (user_id, password) = match self.part {
            BasicPart::UserId => (value, self.other.as_str()),
            BasicPart::Password => (self.other.as_str(), value),
        };
        // Both buffers have their final size: no part of the value is left behind by a
        // growth.
        let mut credentials = String::with_capacity(user_id.len() + 1 + password.len());
        credentials.push_str(user_id);
        credentials.push(':');
        credentials.push_str(password);
        let credentials = Secret::new(credentials);
        let length = credentials.expose_secret().len();
        let mut written = String::with_capacity(BASIC_SCHEME.len() + length.div_ceil(3) * 4);
        written.push_str(BASIC_SCHEME);
        STANDARD.encode_string(credentials.expose_secret().as_bytes(), &mut written);
        Secret::new(written)
    }
}

/// How often `needle` occurs in `text`, counted from every position.
pub fn occurrences(text: &[u8], needle: &[u8]) -> usize {
    match needle.is_empty() || needle.len() > text.len() {
        true => 0,
        false => text
            .windows(needle.len())
            .filter(|window| *window == needle)
            .count(),
    }
}

/// True when `placeholder` is the whole value of exactly one pair `name=placeholder` of
/// `pairs`, a text of pairs joined by `&` (a query, or a form body), and occurs nowhere else
/// in it. Other pairs of the same name are not counted: `pairs` may hold some.
pub fn is_the_value_of(pairs: &[u8], name: &str, placeholder: &str) -> bool {
    let wanted = [name.as_bytes(), b"=", placeholder.as_bytes()].concat();
    occurrences(pairs, placeholder.as_bytes()) == 1
        && pairs
            .split(|byte| *byte == b'&')
            .filter(|pair| *pair == wanted.as_slice())
            .count()
            == 1
}

/// The request the value of a vault secret is used in (protocol.md 10.5), as the caller of
/// `vault/handoff` states it, as the event `provider_request` of the use records it and as
/// the envelope carries it. The value is not part of it: `placeholder` stands where the value
/// goes.
///
/// Only [`BoundRequest::from_value`] creates one, so a value of this type has the form of the
/// table there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundRequest {
    method: String,
    host: String,
    path: String,
    query: String,
    slot: Slot,
    slot_text: String,
    placeholder: String,
    body_bytes: u64,
    body_sha256: String,
}

/// The request object in the key order the protocol writes it.
#[derive(Serialize)]
struct BoundRequestBody<'a> {
    method: &'a str,
    host: &'a str,
    path: &'a str,
    query: &'a str,
    slot: &'a str,
    placeholder: &'a str,
    body_bytes: u64,
    body_sha256: &'a str,
}

impl BoundRequest {
    /// Reads a request object. A body above 64 MiB is `too_large`. Every other violation is
    /// `invalid_request`.
    ///
    /// | Key | Form |
    /// | --- | --- |
    /// | `method` | one of [`METHODS`] |
    /// | `host` | the host of a site ([`is_site_host`]). The request goes to port 443 of it |
    /// | `path` | starts with `/`, at most 8,192 bytes of printable ASCII (0x21 to 0x7e), without `?` and `#` |
    /// | `query` | at most 8,192 bytes of printable ASCII without `#`. The empty string for a request without a query |
    /// | `slot` | a slot ([`Slot::parse`]) inside a request: not `field` |
    /// | `placeholder` | a placeholder ([`is_placeholder`]) |
    /// | `body_bytes` | the length of the body, at most 64 MiB |
    /// | `body_sha256` | b64u of the SHA-256 of the body, the empty string for a request without a body |
    ///
    /// The placeholder and the address agree with the slot: for the slot `path` the
    /// placeholder occurs once in the path and not in the query, and the path in front of it
    /// does not end with the beginning of a percent escape ([`leaves_the_value_alone`]). For a
    /// slot `query:<name>` exactly one pair of the query is the name, `=` and the placeholder
    /// ([`is_the_value_of`]: further pairs of the same name may stand beside it) and the
    /// placeholder occurs nowhere else in the address, and for every other slot it occurs
    /// neither in the path nor in the query. For the two slots of HTTP Basic it stands in no part of a request as
    /// it is: it is inside the base64 text of the `Authorization` header, which the node that
    /// sends the request reads ([`BasicCredentials::read`]).
    pub fn from_value(value: &serde_json::Value) -> Result<BoundRequest, ProtocolError> {
        const INVALID: ProtocolError = ProtocolError::InvalidRequest;
        let text = |key: &str| value.get(key).and_then(serde_json::Value::as_str);
        let method = text("method").ok_or(INVALID)?;
        let host = text("host").ok_or(INVALID)?;
        let path = text("path").ok_or(INVALID)?;
        let query = text("query").ok_or(INVALID)?;
        let slot_text = text("slot").ok_or(INVALID)?;
        let placeholder = text("placeholder").ok_or(INVALID)?;
        let body_sha256 = text("body_sha256").ok_or(INVALID)?;
        let body_bytes = value
            .get("body_bytes")
            .and_then(serde_json::Value::as_u64)
            .ok_or(INVALID)?;
        if body_bytes > limits::BODY_BYTES as u64 {
            return Err(ProtocolError::TooLarge);
        }
        let printable = |text: &str| text.bytes().all(|byte| (0x21..=0x7e).contains(&byte));
        let addressed = path.starts_with('/')
            && path.len() <= limits::EVENT_ADDRESS_BYTES
            && query.len() <= limits::EVENT_ADDRESS_BYTES
            && printable(path)
            && printable(query)
            && !path.contains(['?', '#'])
            && !query.contains('#');
        let hashed = match body_bytes {
            0 => body_sha256.is_empty(),
            _ => b64u_decode_array::<32>(body_sha256).is_ok(),
        };
        if !METHODS.contains(&method)
            || !is_site_host(host)
            || !addressed
            || !is_placeholder(placeholder)
            || !hashed
        {
            return Err(INVALID);
        }
        let slot = Slot::parse(slot_text).ok_or(INVALID)?;
        let in_path = occurrences(path.as_bytes(), placeholder.as_bytes());
        let in_query = occurrences(query.as_bytes(), placeholder.as_bytes());
        let placed = match &slot {
            // An input of a web page is no place of a request: `release` serves it.
            Slot::Field => false,
            Slot::Path => {
                let front = path.split(placeholder).next().unwrap_or_default();
                in_path == 1 && in_query == 0 && leaves_the_value_alone(front.as_bytes())
            }
            Slot::Query(name) => {
                in_path == 0 && is_the_value_of(query.as_bytes(), name, placeholder)
            }
            Slot::Header(_) | Slot::Form(_) | Slot::Json(_) | Slot::Basic(_) => {
                in_path == 0 && in_query == 0
            }
        };
        if !placed {
            return Err(INVALID);
        }
        Ok(BoundRequest {
            method: method.to_string(),
            host: host.to_string(),
            path: path.to_string(),
            query: query.to_string(),
            slot,
            slot_text: slot_text.to_string(),
            placeholder: placeholder.to_string(),
            body_bytes,
            body_sha256: body_sha256.to_string(),
        })
    }

    fn body(&self) -> BoundRequestBody<'_> {
        BoundRequestBody {
            method: &self.method,
            host: &self.host,
            path: &self.path,
            query: &self.query,
            slot: &self.slot_text,
            placeholder: &self.placeholder,
            body_bytes: self.body_bytes,
            body_sha256: &self.body_sha256,
        }
    }

    /// The request object: the eight keys in the order of the table of
    /// [`BoundRequest::from_value`].
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({
            "method": self.method,
            "host": self.host,
            "path": self.path,
            "query": self.query,
            "slot": self.slot_text,
            "placeholder": self.placeholder,
            "body_bytes": self.body_bytes,
            "body_sha256": self.body_sha256,
        })
    }

    /// The method.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The host: the request goes to port 443 of it, and to no other host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The path, with the placeholder in it when the slot is `path`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The query without its `?`, with the placeholder in it when the slot is a query
    /// parameter. Empty for a request without a query.
    pub fn query(&self) -> &str {
        &self.query
    }

    /// The place of the value.
    pub fn slot(&self) -> &Slot {
        &self.slot
    }

    /// The slot as the request names it: one of the `slots` of the record.
    pub fn slot_text(&self) -> &str {
        &self.slot_text
    }

    /// The text that stands where the value goes.
    pub fn placeholder(&self) -> &str {
        &self.placeholder
    }

    /// The length of the body.
    pub fn body_bytes(&self) -> u64 {
        self.body_bytes
    }

    /// b64u of the SHA-256 of the body, the empty string for a request without a body.
    pub fn body_sha256(&self) -> &str {
        &self.body_sha256
    }
}

/// `envelope` = `JSON {"v":1,"from":<giving node>,"to":<receiving node>,"enc":b64u,"ct":b64u}`
/// (10.5): one use of a vault secret, sealed to the sealing key of a node of the forward role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretUseEnvelope {
    pub v: u8,
    pub from: String,
    pub to: String,
    pub enc: String,
    pub ct: String,
}

impl SecretUseEnvelope {
    /// Reads an envelope from parsed JSON. A `v` other than the integer 1 is
    /// `unsupported_version`. A missing or non-string `from`, `to`, `enc` or `ct` is
    /// `invalid_request`. Keys the protocol does not define are ignored.
    pub fn from_value(value: &serde_json::Value) -> Result<SecretUseEnvelope, ProtocolError> {
        let object = value.as_object().ok_or(ProtocolError::InvalidRequest)?;
        if object.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
            return Err(ProtocolError::UnsupportedVersion);
        }
        let text = |key: &str| {
            object
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .ok_or(ProtocolError::InvalidRequest)
        };
        Ok(SecretUseEnvelope {
            v: 1,
            from: text("from")?,
            to: text("to")?,
            enc: text("enc")?,
            ct: text("ct")?,
        })
    }
}

/// One use of a vault secret, as a node of the forward role opened it: the value and the one
/// request it is for. Only [`open_secret_use`] creates one.
#[derive(Debug)]
pub struct SecretUse {
    from: String,
    time_ms: u64,
    not_after_ms: u64,
    nonce: [u8; 16],
    user_id: String,
    record_id: String,
    value: Secret<String>,
    request: BoundRequest,
}

impl SecretUse {
    /// The node that made the envelope.
    pub fn from(&self) -> &str {
        &self.from
    }

    /// The node time of the giving node when it made the envelope.
    pub fn time_ms(&self) -> u64 {
        self.time_ms
    }

    /// The end of the envelope: from this time on the receiving node begins no request for
    /// it.
    pub fn not_after_ms(&self) -> u64 {
        self.not_after_ms
    }

    /// The number of this use. A receiving node sends the request of one number once.
    pub fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }

    /// The account the secret belongs to.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// The record the value was read from.
    pub fn record_id(&self) -> &str {
        &self.record_id
    }

    /// The length of the value in bytes. The search of the response to the request holds back
    /// as many bytes as the longest form of the value can take (egress-policy.md, rule E4),
    /// and the node that sends the request reserves the memory of that search by this
    /// length.
    pub fn value_bytes(&self) -> usize {
        self.value.expose_secret().len()
    }

    /// The value.
    pub fn value(&self) -> &Secret<String> {
        &self.value
    }

    /// The request the value is for.
    pub fn request(&self) -> &BoundRequest {
        &self.request
    }
}

#[derive(Serialize)]
struct SecretUseBody<'a> {
    v: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    from: &'a str,
    to: &'a str,
    time_ms: u64,
    not_after_ms: u64,
    nonce: String,
    user_id: &'a str,
    record_id: &'a str,
    value: &'a str,
    request: BoundRequestBody<'a>,
}

#[derive(Serialize)]
struct SignedSecretUse<'a> {
    payload: &'a str,
    sig: &'a str,
}

/// The payload of a secret use (10.5):
/// `UTF-8(JSON {"v":1,"type":"secret_use","from":..,"to":..,"time_ms":..,"not_after_ms":..,
/// "nonce":b64u(16),"user_id":..,"record_id":..,"value":..,"request":{..}})`, where
/// `not_after_ms` is `time_ms` plus 30 seconds.
///
/// The payload holds the value, so it is a secret. It leaves a node inside the seal of
/// [`seal_secret_use`] only.
#[allow(clippy::too_many_arguments)]
pub fn secret_use_payload(
    from: &str,
    to: &str,
    time_ms: u64,
    nonce: &[u8; 16],
    user_id: &str,
    record_id: &str,
    value: &Secret<String>,
    request: &BoundRequest,
) -> Secret<Vec<u8>> {
    Secret::new(to_json(&SecretUseBody {
        v: 1,
        kind: "secret_use",
        from,
        to,
        time_ms,
        not_after_ms: time_ms.saturating_add(limits::SECRET_USE_MS),
        nonce: b64u(nonce),
        user_id,
        record_id,
        value: value.expose_secret(),
        request: request.body(),
    }))
}

fn signed_secret_use(payload: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let payload_text = Zeroizing::new(b64u(payload));
    to_json(&SignedSecretUse {
        payload: &payload_text,
        sig: &b64u(signature),
    })
}

/// Signs one use of a vault secret with the signing key of the giving node and seals it to
/// the receiving node (10.5): signature purpose `pickle.secure.v3.secret-use\n`, HPKE info
/// `pickle.secure.v3.secret-use`, AAD `UTF-8(from + "\n" + to)`.
///
/// `to_sign_public` and `to_seal_public` are the keys of the receiving node, read from its
/// verified attestation. `nonce` is 16 fresh random bytes and `hpke_seed` the input keying
/// material of the ephemeral key pair, 32 fresh random bytes. A sealing key HPKE cannot seal
/// to is `invalid_request`.
///
/// This function is sink K8 of the egress policy: the value of a vault secret leaves the node
/// that opened its record inside this seal. The caller verified that the receiving node is a
/// node of the forward role of its own measurement, and the log store confirmed the entry
/// that holds the event `provider_request` of this use of `request`, before it calls this.
#[allow(clippy::too_many_arguments)]
pub fn seal_secret_use(
    keys: &NodeKeys,
    to_sign_public: &[u8; 32],
    to_seal_public: &[u8; 32],
    time_ms: u64,
    nonce: &[u8; 16],
    user_id: &str,
    record_id: &str,
    value: &Secret<String>,
    request: &BoundRequest,
    hpke_seed: &Secret<[u8; 32]>,
) -> Result<SecretUseEnvelope, ProtocolError> {
    let from = keys.node();
    let to = node_id(to_sign_public);
    let payload = secret_use_payload(
        &from, &to, time_ms, nonce, user_id, record_id, value, request,
    );
    let signature = keys.sign_detached(purpose::SECRET_USE, payload.expose_secret());
    let signed = Secret::new(signed_secret_use(payload.expose_secret(), &signature));
    let (enc, ct) = hpke_seal(
        to_seal_public,
        purpose::SECRET_USE_SEAL.as_bytes(),
        &transfer_aad(&from, &to),
        signed.expose_secret(),
        hpke_seed.expose_secret(),
    )?;
    Ok(SecretUseEnvelope {
        v: 1,
        from,
        to,
        enc: b64u(&enc),
        ct: b64u(&ct),
    })
}

/// Opens the envelope of one use of a vault secret as the receiving node and verifies what is
/// inside it. The checks, in this order (10.5):
///
/// | Check | Failure |
/// | --- | --- |
/// | `envelope.v` is 1 | `unsupported_version` |
/// | `envelope.to` is this node | `wrong_node` |
/// | `enc` and `ct` are base64url and the HPKE open succeeds | `open_failed` |
/// | `signed` is JSON with base64url `payload` and `sig`, and `envelope.from` is b64u of 32 bytes | `invalid_request` |
/// | `sig` verifies under the signing key `envelope.from` names | `bad_signature` |
/// | `payload` is a JSON object | `invalid_request` |
/// | `payload.v` is 1 | `unsupported_version` |
/// | `payload.type` is `secret_use` | `invalid_request` |
/// | `payload.from` and `payload.to` equal those of the envelope | `wrong_node` |
/// | the form of the fields: the two times, a `nonce` of 16 bytes, a valid `user_id`, a `record_id` of 16 bytes, a `value` that is used in requests ([`is_used_in_requests`]), a request object ([`BoundRequest::from_value`]) | `invalid_request` (`too_large` for a body above the limit) |
///
/// The signature is verified over the payload bytes as carried, before they are parsed. It
/// shows that the holder of the signing key `from` made the payload. The receiving node does
/// not verify an attestation of that node: it holds no secret of its own, and what an
/// envelope makes it do is send the value inside the envelope to the host inside the envelope.
/// What a node of the delegation role relies on is its own verification of the receiving node
/// before it seals.
///
/// The time of the receiving node and the single use of `nonce` are the caller's to check.
pub fn open_secret_use(
    keys: &NodeKeys,
    envelope: &SecretUseEnvelope,
) -> Result<SecretUse, ProtocolError> {
    if envelope.v != 1 {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let node = keys.node();
    if envelope.to != node {
        return Err(ProtocolError::WrongNode);
    }
    let enc = b64u_decode(&envelope.enc).map_err(|_| ProtocolError::OpenFailed)?;
    let ct = b64u_decode(&envelope.ct).map_err(|_| ProtocolError::OpenFailed)?;
    let signed = keys
        .open(
            &enc,
            purpose::SECRET_USE_SEAL.as_bytes(),
            &transfer_aad(&envelope.from, &node),
            &ct,
        )
        .map_err(|_| ProtocolError::OpenFailed)?;
    // The opened envelope holds the value, so its parsed form is a secret as well.
    let outer = Secret::new(
        serde_json::from_slice::<serde_json::Value>(signed.expose_secret())
            .map_err(|_| ProtocolError::InvalidRequest)?,
    );
    open_signed_secret_use(&envelope.from, &node, outer.expose_secret())
}

fn open_signed_secret_use(
    from: &str,
    to: &str,
    outer: &serde_json::Value,
) -> Result<SecretUse, ProtocolError> {
    let text = |key: &str| {
        outer
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or(ProtocolError::InvalidRequest)
    };
    let payload = Zeroizing::new(b64u_decode(text("payload")?)?);
    let signature = b64u_decode(text("sig")?)?;
    let from_sign_public: [u8; 32] = b64u_decode_array(from)?;
    verify_detached(&from_sign_public, purpose::SECRET_USE, &payload, &signature)?;
    let mut body: serde_json::Value =
        serde_json::from_slice(&payload).map_err(|_| ProtocolError::InvalidRequest)?;
    let result = read_secret_use(from, to, &body);
    wipe_json(&mut body);
    result
}

fn read_secret_use(
    from: &str,
    to: &str,
    body: &serde_json::Value,
) -> Result<SecretUse, ProtocolError> {
    const INVALID: ProtocolError = ProtocolError::InvalidRequest;
    if !body.is_object() {
        return Err(INVALID);
    }
    if body.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let text = |key: &str| {
        body.get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or(INVALID)
    };
    let number = |key: &str| {
        body.get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or(INVALID)
    };
    if text("type")? != "secret_use" {
        return Err(INVALID);
    }
    if text("from")? != from || text("to")? != to {
        return Err(ProtocolError::WrongNode);
    }
    let user_id = text("user_id")?;
    let record_id = text("record_id")?;
    let value = text("value")?;
    let sized = is_used_in_requests(value);
    if !is_valid_name(user_id) || b64u_decode_array::<16>(record_id).is_err() || !sized {
        return Err(INVALID);
    }
    Ok(SecretUse {
        from: from.to_string(),
        time_ms: number("time_ms")?,
        not_after_ms: number("not_after_ms")?,
        nonce: b64u_decode_array(text("nonce")?)?,
        user_id: user_id.to_string(),
        record_id: record_id.to_string(),
        value: Secret::new(value.to_string()),
        request: BoundRequest::from_value(body.get("request").ok_or(INVALID)?)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{hpke_open, open_transfer, seal_transfer, TransferEnvelope};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use x25519_dalek::StaticSecret;

    const PLACEHOLDER: &str = "pk_placeholder_0123456789";
    const RECORD_ID: &str = "MTExMTExMTExMTExMTExMQ";
    const VALUE: &str = "sk-live-0123456789abcdef";

    /// One change of a JSON value that a test makes before it reads the value.
    type Change = Box<dyn Fn(&mut serde_json::Value)>;

    fn request_value() -> serde_json::Value {
        json!({
            "method": "POST", "host": "api.example.com", "path": "/v1/chat/completions",
            "query": "", "slot": "header:authorization", "placeholder": PLACEHOLDER,
            "body_bytes": 2, "body_sha256": b64u(&[7u8; 32]),
        })
    }

    fn request() -> BoundRequest {
        BoundRequest::from_value(&request_value()).unwrap()
    }

    fn giving() -> NodeKeys {
        NodeKeys::from_random(&[0x11; 32], &[0x12; 32])
    }

    fn receiving() -> NodeKeys {
        NodeKeys::from_random(&[0x21; 32], &[0x22; 32])
    }

    fn sealed() -> SecretUseEnvelope {
        seal_secret_use(
            &giving(),
            &receiving().sign_public(),
            &receiving().seal_public(),
            1_800_000_000_000,
            &[9u8; 16],
            "user-1",
            RECORD_ID,
            &Secret::new(VALUE.to_string()),
            &request(),
            &Secret::new([0x33; 32]),
        )
        .unwrap()
    }

    #[test]
    fn a_slot_has_one_of_eight_forms() {
        assert_eq!(Slot::parse("field"), Some(Slot::Field));
        assert_eq!(Slot::parse("path"), Some(Slot::Path));
        // The two halves of the credentials of HTTP Basic are two slots.
        assert_eq!(
            Slot::parse("basic:user"),
            Some(Slot::Basic(BasicPart::UserId))
        );
        assert_eq!(
            Slot::parse("basic:password"),
            Some(Slot::Basic(BasicPart::Password))
        );
        assert_ne!(Slot::parse("basic:user"), Slot::parse("basic:password"));
        assert_eq!(
            Slot::parse("header:authorization"),
            Some(Slot::Header("authorization".to_string()))
        );
        assert_eq!(
            Slot::parse("header:x-api-key"),
            Some(Slot::Header("x-api-key".to_string()))
        );
        assert_eq!(
            Slot::parse("query:api_key"),
            Some(Slot::Query("api_key".to_string()))
        );
        assert_eq!(
            Slot::parse("form:client_secret"),
            Some(Slot::Form("client_secret".to_string()))
        );
        // The name of a JSON slot is one key, or keys joined by `.`.
        assert_eq!(
            Slot::parse("json:api_key"),
            Some(Slot::Json(vec!["api_key".to_string()]))
        );
        assert_eq!(
            Slot::parse("json:auth.token"),
            Some(Slot::Json(vec!["auth".to_string(), "token".to_string()]))
        );
        assert_eq!(
            Slot::parse("json:키"),
            Some(Slot::Json(vec!["키".to_string()]))
        );
        // The name of a JSON slot is what follows the first colon: a later colon is part of
        // it.
        assert_eq!(
            Slot::parse("json:a:b"),
            Some(Slot::Json(vec!["a:b".to_string()]))
        );
        // The name of a query or form slot is written with the characters a query writes
        // without an escape, all of them: letters of both cases, digits, `-`, `.`, `_`, `~`.
        for name in ["serviceKey", "API_KEY", "a-b.c_d~e", "0", "~", "a.b"] {
            assert_eq!(
                Slot::parse(&format!("query:{name}")),
                Some(Slot::Query(name.to_string())),
                "{name}"
            );
            assert_eq!(
                Slot::parse(&format!("form:{name}")),
                Some(Slot::Form(name.to_string())),
                "{name}"
            );
        }
        for kind in ["header", "query", "form", "json"] {
            let longest = format!("{kind}:{}", "q".repeat(limits::SLOT_NAME_BYTES));
            assert!(Slot::parse(&longest).is_some(), "{kind}");
            assert_eq!(Slot::parse(&format!("{longest}q")), None, "{kind}");
            assert_eq!(Slot::parse(&format!("{kind}:")), None, "{kind}");
        }
        // The length of the name of a JSON slot is counted in bytes: 21 characters of three
        // bytes each are 63 bytes, one byte more is the longest name, and two bytes more are
        // one too many.
        assert!(Slot::parse(&format!("json:{}", "가".repeat(21))).is_some());
        assert!(Slot::parse(&format!("json:{}a", "가".repeat(21))).is_some());
        assert!(Slot::parse(&format!("json:{}ab", "가".repeat(21))).is_none());
        assert!(Slot::parse(&format!("json:{}", "가".repeat(22))).is_none());
        // In the name of a JSON slot a character that is neither a control character nor
        // white space is part of the name, also one that shows nothing: U+200B, U+FEFF.
        assert!(Slot::parse("json:a\u{200b}b").is_some());
        assert!(Slot::parse("json:a\u{feff}b").is_some());

        for other in [
            "",
            "Field",
            "field:",
            "field:name",
            "Path",
            "path:",
            "path:/v1",
            // A slot of HTTP Basic names its half, with one of two words: without a half it
            // is no slot, and the half has no other name.
            "basic",
            "Basic",
            "basic:",
            "basic:User",
            "basic:user-id",
            "basic:userid",
            "basic:username",
            "basic:pass",
            "basic:Password",
            "basic:user:password",
            "basic:user ",
            "Basic:user",
            "header",
            // The name of a header is written in lower case.
            "header:Authorization",
            "header:a b",
            "header:a:b",
            "header:a_b",
            "header:a.b",
            "query:a b",
            "query:a\tb",
            "query:a\u{7f}b",
            "form:a\nb",
            // A character a query or a form body writes with an escape, or that parts one
            // pair from the next or a name from its value: no request names such a slot.
            "query:a:b",
            "query:a%20b",
            "query:a+b",
            "query:a&b",
            "query:a=b",
            "query:a/b",
            "query:a[0]",
            "query:a*",
            "query:키",
            "query:a\u{200b}b",
            "form:a:b",
            "form:a%3Db",
            "form:a+b",
            "form:a&b",
            "form:a=b",
            "form:a@b",
            "form:비밀번호",
            "form:é",
            // No key of the name of a JSON slot is empty.
            "json:a..b",
            "json:.a",
            "json:a.",
            "json:.",
            "json:a b",
            "json:a\nb",
            // Every white space character and the ends of the two ranges of control
            // characters.
            "json:a\u{1f}b",
            "json:a\u{7f}",
            "json:a\u{85}",
            "json:a\u{9f}b",
            "json:a\u{a0}b",
            "json:a\u{1680}b",
            "json:a\u{2000}b",
            "json:a\u{200a}b",
            "json:a\u{2028}b",
            "json:a\u{2029}b",
            "json:a\u{202f}b",
            "json:a\u{205f}b",
            "json:a\u{3000}b",
            "body:token",
            "body",
            "cookie:session",
        ] {
            assert_eq!(Slot::parse(other), None, "{other:?}");
        }
    }

    #[test]
    fn a_slot_writes_the_string_it_was_read_from() {
        let long = "n".repeat(limits::SLOT_NAME_BYTES);
        for text in [
            "field".to_string(),
            "path".to_string(),
            "basic:user".to_string(),
            "basic:password".to_string(),
            "header:authorization".to_string(),
            "header:x-api-key".to_string(),
            "query:key".to_string(),
            "query:a-b.c_d~e".to_string(),
            "form:client_secret".to_string(),
            "json:apiKey".to_string(),
            "json:a:b".to_string(),
            "json:키.값".to_string(),
            "json:auth.token".to_string(),
            "json:a.b.c".to_string(),
            format!("header:{long}"),
            format!("json:{long}"),
        ] {
            let slot = Slot::parse(&text).unwrap_or_else(|| panic!("{text} is a slot"));
            assert_eq!(slot.to_string(), text);
        }
    }

    #[test]
    fn a_site_host_is_a_lower_case_dns_name_of_two_labels_or_more() {
        for host in [
            "api.example.com",
            "a.b",
            "xn--9n2bp8q.example",
            "api-1.example.co.kr",
            "my-shop.co.kr",
            // A label may begin with a digit. The last one begins with a letter.
            "1.example",
            "10.0.0.x1",
            "3com.example",
            // `-` inside a label, also twice in a row.
            "a-b.example",
            "a--b.example",
            "shop.ex-ample",
        ] {
            assert!(is_site_host(host), "{host}");
        }
        let label = "l".repeat(63);
        assert!(is_site_host(&format!("{label}.example")));
        let longest = format!("{label}.{label}.{label}.{}", "l".repeat(61));
        assert_eq!(longest.len(), 253);
        assert!(is_site_host(&longest));
        for host in [
            "",
            "localhost",
            "example",
            "API.example.com",
            "Shop.example",
            "api.example.com.",
            ".example.com",
            "api..example.com",
            "api.example.com:443",
            "api_1.example.com",
            "user@example.com",
            "example.com/path",
            "https://shop.example",
            "*.example",
            "상점.example",
            // An IPv4 address in its spellings: the last label begins with a digit.
            "169.254.169.254",
            "10.0.0.1",
            "2130706433.1",
            "host.0x7f",
            "1.2.3.04",
            "shop.1example",
            "[::1]",
            "exa mple.com",
            // No label begins or ends with `-`.
            "-a.example",
            "a-.example",
            "-a-.example",
            "-.example",
            "shop.-example",
            "shop.example-",
            "shop.-",
        ] {
            assert!(!is_site_host(host), "{host:?}");
        }
        assert!(!is_site_host(&format!("{}.example", "l".repeat(64))));
        assert!(!is_site_host(&format!("{longest}l")));
    }

    #[test]
    fn a_placeholder_is_text_no_encoding_changes() {
        assert!(is_placeholder(PLACEHOLDER));
        assert!(is_placeholder(&"p".repeat(16)));
        assert!(is_placeholder(&"P".repeat(128)));
        assert!(is_placeholder("abcDEF012_-abcDEF012"));
        for other in [
            "".to_string(),
            "p".repeat(15),
            "p".repeat(129),
            "placeholder with space".to_string(),
            "placeholder.with.dots".to_string(),
            "placeholder/with/slash".to_string(),
            "placeholder%2fescaped".to_string(),
            "placeholder=with=equal".to_string(),
            "자리표시값자리표시값자리표시값".to_string(),
        ] {
            assert!(!is_placeholder(&other), "{other:?}");
        }
    }

    #[test]
    fn a_header_a_node_writes_drops_or_refuses_is_no_slot() {
        assert_eq!(DROPPED_HEADERS.len() + REFUSED_HEADERS.len(), 29);
        for name in DROPPED_HEADERS.iter().chain(&REFUSED_HEADERS) {
            assert!(is_reserved_header(name), "{name}");
            assert!(is_reserved_header(&name.to_uppercase()), "{name}");
            // A server may read `_` as `-`: the name with either character is the header.
            assert!(is_reserved_header(&name.replace('-', "_")), "{name}");
            // The name has the letters of a header slot, and the reader of a slot refuses it:
            // no record lists such a slot, and no request names one.
            assert_eq!(Slot::parse(&format!("header:{name}")), None, "{name}");
            let mut value = request_value();
            value["slot"] = json!(format!("header:{name}"));
            assert_eq!(
                BoundRequest::from_value(&value).map(|_| ()),
                Err(ProtocolError::InvalidRequest),
                "{name}"
            );
        }
        for name in [
            "authorization",
            "cookie",
            "x-api-key",
            "content-type",
            "x-forwarded-for",
        ] {
            assert!(!is_reserved_header(name), "{name}");
            assert!(Slot::parse(&format!("header:{name}")).is_some(), "{name}");
        }
        assert_eq!(
            header_key("X_HTTP_Method-Override"),
            "x-http-method-override"
        );
    }

    #[test]
    fn a_value_with_a_control_character_does_not_fit_a_header() {
        for value in [
            "sk-live_0123456789",
            "Bearer token with spaces",
            "a\"quoted\\value%2F",
            "비밀 값 ünïcode",
        ] {
            assert!(fits_header(value), "{value:?}");
        }
        for value in [
            "line\r\nx-injected: 1",
            "line\nend",
            "carriage\rreturn",
            "null\0byte",
            "tab\tinside",
            "delete\u{7f}",
            "c1\u{85}control",
        ] {
            assert!(!fits_header(value), "{value:?}");
        }
    }

    #[test]
    fn a_value_used_in_a_request_has_eight_bytes_without_what_a_server_strips_at_its_ends() {
        for (value, searched) in [
            ("sk-live_0123456789", "sk-live_0123456789"),
            (" sk-live_0123456789\n", "sk-live_0123456789"),
            ("\t\r\n12345678 \u{a0}\u{3000}", "12345678"),
            ("1234 5678", "1234 5678"),
            // A byte order mark, as a value that was read from a file begins with one, and
            // control characters that are no white space.
            ("\u{feff}sk-live_0123456789", "sk-live_0123456789"),
            ("\u{feff} 12345678\u{1f}\u{1}", "12345678"),
            ("12345678\u{7f}\u{9c}", "12345678"),
            // Only the ends: what stands inside a value is part of it.
            ("1234\u{feff}\u{1f}5678", "1234\u{feff}\u{1f}5678"),
        ] {
            assert_eq!(searched_text(value), searched, "{value:?}");
            assert!(is_used_in_requests(value), "{value:?}");
        }
        // Fewer than 8 bytes are left: the search of a response would look for no form of
        // such a value.
        for value in [
            "1234567",
            " 1234567 ",
            "1234567\n\n\n",
            "        ",
            "\u{3000}123456",
            "\u{feff}1234567",
            "1234567\u{1f}",
            "\u{1}\u{feff} 1234567\u{7f}\u{85}",
        ] {
            assert!(!is_used_in_requests(value), "{value:?}");
        }
        // The longest value, and one byte more. What a server strips counts for the length
        // of a value and not for the text that is searched for.
        let longest = "v".repeat(limits::SECRET_USE_VALUE_BYTES_MAX);
        assert!(is_used_in_requests(&longest));
        assert!(!is_used_in_requests(&format!("{longest} ")));
    }

    #[test]
    fn a_placeholder_in_a_header_begins_the_value_or_follows_a_delimiter() {
        for front in [
            "",
            "Bearer ",
            "Basic ",
            "theme=dark; session=",
            "user:",
            "token=\"",
            "{\"token\":\"",
        ] {
            assert!(stands_free(front), "{front:?}");
        }
        // The beginning of an escape of some syntax, and every other text a value could be
        // read together with.
        for front in [
            "%",
            "%4",
            "a=%4",
            "\\",
            "\\u004",
            "{\"t\":\"\\u004",
            "&#x4",
            "&#",
            "=?",
            "Bearer",
            "Bearer\t",
            "a,",
            "a;",
            "a/",
            "a+",
            "x",
        ] {
            assert!(!stands_free(front), "{front:?}");
        }
    }

    #[test]
    fn a_header_names_no_character_encoding_but_utf8() {
        for text in [
            "",
            "*/*",
            "application/json",
            "application/json, text/plain;q=0.9, */*;q=0.8",
            "application/json; charset=utf-8",
            "application/json;charset=UTF-8",
            "text/html; charset=\"utf-8\", application/json; CHARSET = utf8",
            "application/x-www-form-urlencoded ; charset = \"UTF-8\" ; version=1",
        ] {
            assert!(names_no_other_charset(text), "{text:?}");
        }
        for text in [
            "application/json; charset=utf-16",
            "application/json;charset=UTF-16LE",
            "text/plain; charset=\"utf-16be\"",
            "text/plain;charset=utf-32",
            "text/plain;charset=utf-7",
            "text/plain;charset=ibm037",
            "text/html;charset=iso-8859-1",
            "text/html;charset=euc-kr",
            "application/json; charset=utf-8, text/plain; charset=utf-16",
            "application/json; charset=utf-8x",
            "application/json; charset=utf-80",
            "application/json; charset=",
            "application/json; charset",
            "application/json; charset*=utf-16",
            "application/json; boundary=charset",
            "application/charset",
        ] {
            assert!(!names_no_other_charset(text), "{text:?}");
        }
    }

    #[test]
    fn a_header_named_after_authorization_is_one_a_server_reads_credentials_from() {
        for name in [
            "authorization",
            "Authorization",
            "AUTHORIZATION",
            "x-authorization",
            "X-Forwarded-Authorization",
            "x_original_authorization",
            "authorization-token",
            "proxy-authorization",
        ] {
            assert!(reads_credentials(name), "{name}");
        }
        for name in [
            "cookie",
            "x-api-key",
            "x-auth-token",
            "authentication",
            "x-author",
            "authorisation",
            "",
        ] {
            assert!(!reads_credentials(name), "{name}");
        }
    }

    #[test]
    fn the_text_in_front_of_a_value_names_no_scheme_a_server_decodes() {
        assert_eq!(REFUSED_SCHEMES, ["basic", "digest", "negotiate", "ntlm"]);
        // The schemes and the forms a value stands behind as it is.
        for front in [
            "",
            "Bearer ",
            "bearer ",
            "Token ",
            "token ",
            "Token token=\"",
            "Bot ",
            "KakaoAK ",
            "Infuser ",
            "SSWS ",
            "key=",
            "PVEAPIToken=user@pam!id=",
            "OAuth ",
            "DPoP ",
            "AWS4-HMAC-SHA256 Credential=",
            "Bas ic ",
        ] {
            assert!(states_no_scheme(front), "{front:?}");
        }
        // The name of a scheme under which a server does not read a value as it stands: in
        // any case of its letters, behind white space, in front of any delimiter, as a part
        // of a longer word, behind another scheme, and inside a parameter.
        for front in [
            "Basic ",
            "basic ",
            "BASIC ",
            "bAsIc ",
            "Basic  ",
            " Basic ",
            "\tBasic ",
            "Basic\t ",
            "Basic=",
            "Basic:",
            "Basic\"",
            "Basic realm=\"x\", ",
            "Basic dXNlcjo= ",
            "Basic abc=",
            "basic-plan ",
            "Basically ",
            "xBasic ",
            "Bearer x, Basic ",
            "Bearer x Basic ",
            "Token scheme=basic, token=",
            "Digest username=\"",
            "digest username=\"u\", response=\"",
            "Negotiate ",
            "negotiate  ",
            "NTLM ",
            "ntlm ",
            "Ntlm TlRMTVNTUAAB ",
        ] {
            assert!(!states_no_scheme(front), "{front:?}");
        }
        // A character outside ASCII: a server may read it as white space in front of a
        // scheme, or as a letter of one when it compares names without regard to case.
        for front in [
            "\u{a0}Bearer ",
            "Ba\u{17f}ic ",
            "BAS\u{131}C ",
            "Bearer \u{d55c} ",
            "Token name=\"\u{e9}\", token=",
        ] {
            assert!(!states_no_scheme(front), "{front:?}");
        }
    }

    #[test]
    fn a_placeholder_stands_in_a_header_value_once_and_free_and_behind_no_refused_scheme() {
        let placed = |name: &str, value: &str| is_placed_in_header(name, value, PLACEHOLDER);
        let with = |text: &str| text.replace("{}", PLACEHOLDER);
        for (name, value) in [
            ("authorization", "Bearer {}"),
            ("Authorization", "{}"),
            ("authorization", "token {}"),
            ("authorization", "Token token=\"{}\", name=\"basic\""),
            ("x-api-key", "{}"),
            ("cookie", "theme=dark; session={}; plan=basic"),
            // A header no server reads credentials from holds any text in front of the
            // value: the name of a scheme has no meaning in it.
            ("cookie", "plan=basic; session={}"),
            ("cookie", "basic={}"),
            ("x-note", "Basic {}"),
            ("x-note", "\u{d55c}: {}"),
        ] {
            assert!(placed(name, &with(value)), "{name}: {value}");
        }
        for (name, value) in [
            // Not once, and not free.
            ("authorization", "Bearer token"),
            ("authorization", "{} {}"),
            ("authorization", "Bearer{}"),
            ("x-api-key", "key%4{}"),
            // Behind the name of a refused scheme, in a header a server reads credentials
            // from.
            ("authorization", "Basic {}"),
            ("Authorization", "basic {}"),
            ("AUTHORIZATION", "BASIC  {}"),
            ("authorization", " Basic {}"),
            ("authorization", "Basic dXNlcjo= {}"),
            ("authorization", "Bearer x, Basic {}"),
            ("authorization", "Digest username=\"{}\""),
            ("authorization", "Negotiate {}"),
            ("authorization", "NTLM {}"),
            ("x-authorization", "Basic {}"),
            ("x-forwarded-authorization", "basic {}"),
            ("authorization", "Ba\u{17f}ic {}"),
            ("authorization", "\u{a0}Bearer {}"),
        ] {
            assert!(!placed(name, &with(value)), "{name}: {value}");
        }
    }

    /// The value of an `Authorization` header that carries `credentials` as HTTP Basic.
    fn basic(credentials: &[u8]) -> String {
        format!("Basic {}", STANDARD.encode(credentials))
    }

    #[test]
    fn the_credentials_of_http_basic_hold_the_placeholder_as_one_whole_half() {
        let read = |header: &str| {
            BasicCredentials::read(header, PLACEHOLDER)
                .map(|credentials| (credentials.part(), credentials.other().to_string()))
        };
        let of = |credentials: &str| read(&basic(credentials.as_bytes()));
        let user_id = |other: &str| Some((BasicPart::UserId, other.to_string()));
        let password = |other: &str| Some((BasicPart::Password, other.to_string()));

        // The placeholder as the user-id, in front of a password that may be empty and may
        // hold colons, and as the password, behind a user-id that may be empty.
        assert_eq!(of(&format!("{PLACEHOLDER}:")), user_id(""));
        assert_eq!(of(&format!("{PLACEHOLDER}:x")), user_id("x"));
        assert_eq!(of(&format!("{PLACEHOLDER}:a:b:")), user_id("a:b:"));
        assert_eq!(of(&format!(":{PLACEHOLDER}")), password(""));
        assert_eq!(of(&format!("api:{PLACEHOLDER}")), password("api"));
        assert_eq!(
            of(&format!("user@example.com:{PLACEHOLDER}")),
            password("user@example.com")
        );
        assert_eq!(of(&format!("사용자:{PLACEHOLDER}")), password("사용자"));
        // The other half is the text of the caller as it is, also with a control character.
        assert_eq!(of(&format!("a\tb:{PLACEHOLDER}")), password("a\tb"));

        // The placeholder as a part of a half, in both halves, twice in one half, behind a
        // second colon, and in no half.
        for credentials in [
            format!("x{PLACEHOLDER}:"),
            format!("{PLACEHOLDER}x:"),
            format!(":{PLACEHOLDER}x"),
            format!("u:x{PLACEHOLDER}"),
            format!("{PLACEHOLDER}:{PLACEHOLDER}"),
            format!("{PLACEHOLDER}:x{PLACEHOLDER}"),
            format!("{PLACEHOLDER}{PLACEHOLDER}:"),
            format!("u:p:{PLACEHOLDER}"),
            "user:password".to_string(),
            ":".to_string(),
            // Credentials without a colon have no halves.
            PLACEHOLDER.to_string(),
            String::new(),
        ] {
            assert_eq!(of(&credentials), None, "{credentials:?}");
        }
        // Credentials that are not UTF-8.
        let latin = [b"caf\xe9:".as_slice(), PLACEHOLDER.as_bytes()].concat();
        assert_eq!(read(&basic(&latin)), None);

        // The header value has one form: `Basic`, one space, and the base64 text of RFC 4648
        // section 4 with its padding. The credentials of the three lengths of a last group.
        for other in ["", "x", "xy"] {
            let credentials = format!("{other}:{PLACEHOLDER}");
            let header = basic(credentials.as_bytes());
            assert_eq!(read(&header), password(other), "{header}");
            let (_, text) = header.split_once(' ').unwrap();
            let unpadded = text.trim_end_matches('=');
            for another in [
                format!("basic {text}"),
                format!("BASIC {text}"),
                format!("Basic  {text}"),
                format!("Basic\t{text}"),
                format!(" Basic {text}"),
                format!("Basic {text} "),
                format!("Basic {text}="),
                format!("Basic {text}\n"),
                format!("Basic{text}"),
                format!("Bearer {text}"),
                format!("Basic {text}, Bearer token"),
                text.to_string(),
            ] {
                assert_eq!(read(&another), None, "{another:?}");
            }
            if unpadded != text {
                assert_eq!(read(&format!("Basic {unpadded}")), None, "{other:?}");
            }
        }
        // base64url writes `-` and `_` where base64 writes `+` and `/`.
        let credentials = format!("???>>>:{PLACEHOLDER}");
        let header = basic(credentials.as_bytes());
        assert!(header.contains('+') && header.contains('/'), "{header}");
        assert_eq!(read(&header), password("???>>>"));
        let url_safe = base64::engine::general_purpose::URL_SAFE.encode(&credentials);
        assert_eq!(read(&format!("Basic {url_safe}")), None);
        // A text with a bit set behind its last byte stands for the same bytes as the text a
        // writer gives, and is not that text: `QQ==` is the one text of the byte `A`.
        let (other, canonical) = ["", "x", "xy"]
            .into_iter()
            .map(|other| (other, STANDARD.encode(format!("{other}:{PLACEHOLDER}"))))
            .find(|(_, text)| text.ends_with("=="))
            .expect("one of three lengths ends with a group of one byte");
        // The second character of the last group holds two bits of the last byte and four
        // bits that are zero: the character behind it in the alphabet sets the lowest one.
        let stem = &canonical[..canonical.len() - 3];
        let last = canonical.as_bytes()[canonical.len() - 3];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let index = alphabet.iter().position(|byte| *byte == last).unwrap();
        let loose = format!("{stem}{}==", char::from(alphabet[index + 1]));
        assert_eq!(read(&format!("Basic {canonical}")), password(other));
        assert_eq!(read(&format!("Basic {loose}")), None);
        // Characters outside the alphabet, and no text at all.
        for text in ["", "=", "====", "dTpw*A==", "dTp w"] {
            assert_eq!(read(&format!("Basic {text}")), None, "{text:?}");
        }
        assert_eq!(read(""), None);
        assert_eq!(read("Basic"), None);
    }

    #[test]
    fn the_header_a_node_writes_is_the_header_it_reads_but_for_the_value() {
        let value = Secret::new(VALUE.to_string());
        for (credentials, expected) in [
            (format!("{PLACEHOLDER}:"), format!("{VALUE}:")),
            (
                format!("{PLACEHOLDER}:pass:word"),
                format!("{VALUE}:pass:word"),
            ),
            (format!(":{PLACEHOLDER}"), format!(":{VALUE}")),
            (format!("사용자:{PLACEHOLDER}"), format!("사용자:{VALUE}")),
        ] {
            let header = basic(credentials.as_bytes());
            let read = BasicCredentials::read(&header, PLACEHOLDER).unwrap();
            let written = read.written(&value);
            assert_eq!(
                written.expose_secret(),
                &basic(expected.as_bytes()),
                "{credentials}"
            );
            // With the placeholder for a value, the node writes the header it read: the
            // form it reads is the form it writes.
            let unchanged = read.written(&Secret::new(PLACEHOLDER.to_string()));
            assert_eq!(unchanged.expose_secret(), &header, "{credentials}");
        }
        // A value of any length and of characters outside ASCII is written as its UTF-8
        // bytes, and a server that reads the credentials finds it as the half it stands for.
        for value in [
            "12345678",
            "값 with spaces and ünïcode",
            &"v".repeat(12_000),
        ] {
            for (credentials, part) in [
                (format!("{PLACEHOLDER}:other"), BasicPart::UserId),
                (format!("other:{PLACEHOLDER}"), BasicPart::Password),
            ] {
                let read = BasicCredentials::read(&basic(credentials.as_bytes()), PLACEHOLDER);
                let written = read.unwrap().written(&Secret::new(value.to_string()));
                let text = written.expose_secret().strip_prefix("Basic ").unwrap();
                let decoded = String::from_utf8(STANDARD.decode(text).unwrap()).unwrap();
                let (user_id, password) = decoded.split_once(':').unwrap();
                match part {
                    BasicPart::UserId => assert_eq!((user_id, password), (value, "other")),
                    BasicPart::Password => assert_eq!((user_id, password), ("other", value)),
                }
            }
        }
    }

    #[test]
    fn a_half_of_http_basic_holds_no_control_character_and_a_user_id_no_colon() {
        assert_eq!(BasicPart::UserId.name(), "user");
        assert_eq!(BasicPart::Password.name(), "password");
        assert_eq!(BasicPart::of_name("user"), Some(BasicPart::UserId));
        assert_eq!(BasicPart::of_name("password"), Some(BasicPart::Password));
        assert_eq!(BasicPart::of_name("user-id"), None);
        assert_eq!(BasicPart::of_name(""), None);
        for value in ["sk_live_0123456789", "a b/c+d=e", "비밀 값", "p@ss\"word\\"] {
            assert!(fits_basic(value), "{value:?}");
            assert!(BasicPart::UserId.admits(value), "{value:?}");
            assert!(BasicPart::Password.admits(value), "{value:?}");
        }
        // A colon ends a user-id, and is a character of a password like any other.
        for value in ["user:name", ":", "a:", ":a"] {
            assert!(fits_basic(value), "{value:?}");
            assert!(!BasicPart::UserId.admits(value), "{value:?}");
            assert!(BasicPart::Password.admits(value), "{value:?}");
        }
        for value in [
            "line\nend",
            "carriage\rreturn",
            "null\0byte",
            "tab\tinside",
            "delete\u{7f}",
            "c1\u{85}control",
        ] {
            assert!(!fits_basic(value), "{value:?}");
            assert!(!BasicPart::UserId.admits(value), "{value:?}");
            assert!(!BasicPart::Password.admits(value), "{value:?}");
        }
    }

    #[test]
    fn a_request_object_is_read_strictly() {
        let request = request();
        assert_eq!(request.method(), "POST");
        assert_eq!(request.host(), "api.example.com");
        assert_eq!(request.path(), "/v1/chat/completions");
        assert_eq!(request.query(), "");
        assert_eq!(request.slot(), &Slot::Header("authorization".to_string()));
        assert_eq!(request.slot_text(), "header:authorization");
        assert_eq!(request.placeholder(), PLACEHOLDER);
        assert_eq!(request.body_bytes(), 2);
        assert_eq!(request.body_sha256(), b64u(&[7u8; 32]));
        // The object is written with its eight keys in the order of the protocol, whatever
        // order and whatever other keys the caller gave.
        let mut shuffled = json!({"future": 1, "body_sha256": b64u(&[7u8; 32]), "body_bytes": 2});
        for (key, value) in request_value().as_object().unwrap() {
            shuffled[key] = value.clone();
        }
        let read = BoundRequest::from_value(&shuffled).unwrap();
        assert_eq!(read, request);
        assert_eq!(
            String::from_utf8(to_json(&read.to_value())).unwrap(),
            format!(
                concat!(
                    "{{\"method\":\"POST\",\"host\":\"api.example.com\",",
                    "\"path\":\"/v1/chat/completions\",\"query\":\"\",",
                    "\"slot\":\"header:authorization\",\"placeholder\":\"{}\",",
                    "\"body_bytes\":2,\"body_sha256\":\"{}\"}}"
                ),
                PLACEHOLDER,
                b64u(&[7u8; 32])
            )
        );

        let with = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut value = request_value();
            change(&mut value);
            BoundRequest::from_value(&value).map(|_| ())
        };
        // A request without a body states no hash.
        assert_eq!(
            with(&|request| {
                request["body_bytes"] = json!(0);
                request["body_sha256"] = json!("");
            }),
            Ok(())
        );
        assert_eq!(with(&|request| request["method"] = json!("DELETE")), Ok(()));
        assert_eq!(
            with(&|request| request["body_bytes"] = json!(limits::BODY_BYTES)),
            Ok(())
        );
        assert_eq!(
            with(&|request| request["body_bytes"] = json!(limits::BODY_BYTES + 1)),
            Err(ProtocolError::TooLarge)
        );
        let changes: Vec<Change> = vec![
            Box::new(|request| request["method"] = json!("HEAD")),
            Box::new(|request| request["method"] = json!("post")),
            Box::new(|request| request["method"] = json!("CONNECT")),
            Box::new(|request| request["host"] = json!("API.example.com")),
            Box::new(|request| request["host"] = json!("localhost")),
            Box::new(|request| request["host"] = json!("169.254.169.254")),
            Box::new(|request| request["host"] = json!("api.example.com:8443")),
            Box::new(|request| request["path"] = json!("v1/chat")),
            Box::new(|request| request["path"] = json!("")),
            Box::new(|request| request["path"] = json!("/v1/chat?a=1")),
            Box::new(|request| request["path"] = json!("/v1/chat#top")),
            Box::new(|request| request["path"] = json!("/v1/a b")),
            Box::new(|request| request["path"] = json!("/v1/\u{d55c}")),
            Box::new(|request| request["path"] = json!(format!("/{}", "a".repeat(8192)))),
            Box::new(|request| request["query"] = json!("a=1#top")),
            Box::new(|request| request["query"] = json!("a=1 2")),
            Box::new(|request| request["query"] = json!("q".repeat(8193))),
            Box::new(|request| request["slot"] = json!("header:host")),
            Box::new(|request| request["slot"] = json!("body")),
            // An input of a web page is no place of a request, and neither is a header the
            // node writes itself or one that changes the method.
            Box::new(|request| request["slot"] = json!("field")),
            Box::new(|request| request["slot"] = json!("header:content-length")),
            Box::new(|request| request["slot"] = json!("header:x-http-method-override")),
            Box::new(|request| request["placeholder"] = json!("short")),
            Box::new(|request| request["placeholder"] = json!("with space 0123456789")),
            Box::new(|request| request["body_bytes"] = json!(-1)),
            Box::new(|request| request["body_bytes"] = json!("2")),
            Box::new(|request| request["body_sha256"] = json!("")),
            Box::new(|request| request["body_sha256"] = json!(b64u(&[7u8; 31]))),
            Box::new(|request| request["body_sha256"] = json!("not base64url!")),
            Box::new(|request| {
                request["body_bytes"] = json!(0);
            }),
            Box::new(|request| {
                request.as_object_mut().unwrap().remove("query");
            }),
            Box::new(|request| {
                request.as_object_mut().unwrap().remove("slot");
            }),
            Box::new(|request| {
                request.as_object_mut().unwrap().remove("body_bytes");
            }),
        ];
        for (index, change) in changes.iter().enumerate() {
            assert_eq!(
                with(change.as_ref()),
                Err(ProtocolError::InvalidRequest),
                "change {index}"
            );
        }
        for other in [json!("text"), json!([]), json!(null), json!({})] {
            assert_eq!(
                BoundRequest::from_value(&other).map(|_| ()),
                Err(ProtocolError::InvalidRequest)
            );
        }
    }

    #[test]
    fn the_placeholder_and_the_address_agree_with_the_slot() {
        let placed = |slot: &str, path: &str, query: &str| {
            let mut value = request_value();
            value["slot"] = json!(slot);
            value["path"] = json!(path);
            value["query"] = json!(query);
            BoundRequest::from_value(&value).is_ok()
        };
        let key = format!("key={PLACEHOLDER}");

        // A slot outside the address: the placeholder is in neither part of it.
        for slot in [
            "header:authorization",
            "form:key",
            "json:key",
            "basic:user",
            "basic:password",
        ] {
            assert!(placed(slot, "/v1/items", "a=1&b=2"), "{slot}");
            assert!(!placed(slot, &format!("/v1/{PLACEHOLDER}"), ""), "{slot}");
            assert!(!placed(slot, "/v1/items", &key), "{slot}");
        }

        // The slot `path`: once in the path, as a segment or as a part of one, and not in the
        // query.
        assert!(placed("path", &format!("/bot{PLACEHOLDER}/send"), ""));
        assert!(placed("path", &format!("/v1/{PLACEHOLDER}"), "a=1"));
        assert!(!placed("path", "/v1/items", ""));
        assert!(!placed(
            "path",
            &format!("/{PLACEHOLDER}/{PLACEHOLDER}"),
            ""
        ));
        assert!(!placed("path", &format!("/v1/{PLACEHOLDER}"), &key));
        assert!(!placed("path", "/v1/items", &key));
        // The path in front of the placeholder does not end with the beginning of a percent
        // escape, as it stands or with its own escapes decoded: the first characters of the
        // value would be read as the digits of that escape.
        for front in [
            "/v1/%",
            "/v1/%4",
            "/v1/%a",
            "/v1/%25",
            "/v1/%254",
            "/v1/%25%34",
            "/v1/%2525",
            "/v1/%25252",
        ] {
            let path = format!("{front}{PLACEHOLDER}/x");
            assert!(!placed("path", &path, ""), "{path}");
        }
        for front in [
            "/v1/%41",
            "/v1/%252541",
            "/v1/100%25-",
            "/v1/%zz",
            "/v1/%4g",
            "/v1/a%20b",
            "/v1/4",
            "/%2541/",
        ] {
            let path = format!("{front}{PLACEHOLDER}/x");
            assert!(placed("path", &path, ""), "{path}");
        }

        // A slot `query:<name>`: exactly one pair of the query is the name, `=` and the
        // placeholder.
        assert!(placed("query:key", "/v1/items", &key));
        assert!(placed("query:key", "/v1/items", &format!("a=1&{key}&b=2")));
        assert!(placed("query:key", "/v1/items", &format!("{key}&key2=x")));
        // Further pairs of the same name may stand beside that pair.
        assert!(placed(
            "query:key",
            "/v1/items",
            &format!("key=other&{key}")
        ));
        assert!(placed("query:key", "/v1/items", &format!("{key}&key=&key")));
        for query in [
            "".to_string(),
            "key=other".to_string(),
            format!("key2={PLACEHOLDER}"),
            format!("xkey={PLACEHOLDER}"),
            format!("key=x{PLACEHOLDER}"),
            format!("key={PLACEHOLDER}x"),
            format!("{key}&{key}"),
            format!("{key}&other={PLACEHOLDER}"),
            format!("key=={PLACEHOLDER}"),
            PLACEHOLDER.to_string(),
            format!("{PLACEHOLDER}=key"),
        ] {
            assert!(!placed("query:key", "/v1/items", &query), "{query}");
        }
        assert!(!placed("query:key", &format!("/v1/{PLACEHOLDER}"), &key));
    }

    #[test]
    fn a_secret_use_round_trips_between_two_nodes() {
        let envelope = sealed();
        assert_eq!(envelope.v, 1);
        assert_eq!(envelope.from, giving().node());
        assert_eq!(envelope.to, receiving().node());
        // The envelope is read from JSON as it is written.
        let carried = serde_json::to_value(&envelope).unwrap();
        assert_eq!(
            carried.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["v", "from", "to", "enc", "ct"]
        );
        assert_eq!(
            SecretUseEnvelope::from_value(&carried),
            Ok(envelope.clone())
        );

        let opened = open_secret_use(&receiving(), &envelope).unwrap();
        assert_eq!(opened.from(), giving().node());
        assert_eq!(opened.time_ms(), 1_800_000_000_000);
        assert_eq!(opened.not_after_ms(), 1_800_000_030_000);
        assert_eq!(opened.nonce(), &[9u8; 16]);
        assert_eq!(opened.user_id(), "user-1");
        assert_eq!(opened.record_id(), RECORD_ID);
        assert_eq!(opened.value().expose_secret(), VALUE);
        assert_eq!(opened.request(), &request());
        // The debug output of an opened use does not hold the value.
        assert!(!format!("{opened:?}").contains(VALUE));
    }

    #[test]
    fn the_payload_has_the_key_order_of_the_protocol() {
        let payload = secret_use_payload(
            "FROM",
            "TO",
            5,
            &[9u8; 16],
            "user-1",
            RECORD_ID,
            &Secret::new(VALUE.to_string()),
            &request(),
        );
        assert_eq!(
            String::from_utf8(payload.expose_secret().clone()).unwrap(),
            format!(
                concat!(
                    "{{\"v\":1,\"type\":\"secret_use\",\"from\":\"FROM\",\"to\":\"TO\",",
                    "\"time_ms\":5,\"not_after_ms\":30005,\"nonce\":\"{}\",",
                    "\"user_id\":\"user-1\",\"record_id\":\"{}\",\"value\":\"{}\",",
                    "\"request\":{}}}"
                ),
                b64u(&[9u8; 16]),
                RECORD_ID,
                VALUE,
                String::from_utf8(to_json(&request().to_value())).unwrap()
            )
        );
    }

    #[test]
    fn an_envelope_for_another_node_or_a_changed_one_does_not_open() {
        let envelope = sealed();
        let open =
            |envelope: &SecretUseEnvelope| open_secret_use(&receiving(), envelope).map(|_| ());

        // Another node cannot open it, and this node does not open one that names another.
        let other = NodeKeys::from_random(&[0x41; 32], &[0x42; 32]);
        assert_eq!(
            open_secret_use(&other, &envelope).map(|_| ()),
            Err(ProtocolError::WrongNode)
        );
        let mut renamed = envelope.clone();
        renamed.to = other.node();
        assert_eq!(open(&renamed), Err(ProtocolError::WrongNode));
        let mut version = envelope.clone();
        version.v = 2;
        assert_eq!(open(&version), Err(ProtocolError::UnsupportedVersion));

        // The names of the two nodes are bound by the seal.
        let mut from_other = envelope.clone();
        from_other.from = other.node();
        assert_eq!(open(&from_other), Err(ProtocolError::OpenFailed));
        // One changed bit of the ciphertext or of the encapsulated key.
        for field in ["enc", "ct"] {
            let mut changed = envelope.clone();
            let text = match field {
                "enc" => &mut changed.enc,
                _ => &mut changed.ct,
            };
            let mut bytes = b64u_decode(text).unwrap();
            bytes[3] ^= 1;
            *text = b64u(&bytes);
            assert_eq!(open(&changed), Err(ProtocolError::OpenFailed), "{field}");
        }
        let mut garbled = envelope.clone();
        garbled.ct = "not base64url!".to_string();
        assert_eq!(open(&garbled), Err(ProtocolError::OpenFailed));

        for value in [
            json!({"v": 2, "from": "a", "to": "b", "enc": "c", "ct": "d"}),
            json!({"from": "a", "to": "b", "enc": "c", "ct": "d"}),
        ] {
            assert_eq!(
                SecretUseEnvelope::from_value(&value),
                Err(ProtocolError::UnsupportedVersion)
            );
        }
        for value in [
            json!({"v": 1, "from": "a", "to": "b", "enc": "c"}),
            json!({"v": 1, "from": 1, "to": "b", "enc": "c", "ct": "d"}),
            json!([]),
        ] {
            assert_eq!(
                SecretUseEnvelope::from_value(&value),
                Err(ProtocolError::InvalidRequest)
            );
        }
    }

    /// Seals `payload` to the receiving node under the signature of `signer`, with the names
    /// of the envelope `from` and the receiving node.
    fn sealed_with(signer: &SigningKey, from: &str, payload: &[u8]) -> SecretUseEnvelope {
        let mut message = purpose::SECRET_USE.as_bytes().to_vec();
        message.extend_from_slice(payload);
        let signed = signed_secret_use(payload, &signer.sign(&message).to_bytes());
        let to = receiving().node();
        let (enc, ct) = hpke_seal(
            &receiving().seal_public(),
            purpose::SECRET_USE_SEAL.as_bytes(),
            &transfer_aad(from, &to),
            &signed,
            &[0x55; 32],
        )
        .unwrap();
        SecretUseEnvelope {
            v: 1,
            from: from.to_string(),
            to,
            enc: b64u(&enc),
            ct: b64u(&ct),
        }
    }

    fn payload_value() -> serde_json::Value {
        let payload = secret_use_payload(
            &giving().node(),
            &receiving().node(),
            1_800_000_000_000,
            &[9u8; 16],
            "user-1",
            RECORD_ID,
            &Secret::new(VALUE.to_string()),
            &request(),
        );
        serde_json::from_slice(payload.expose_secret()).unwrap()
    }

    #[test]
    fn what_is_inside_an_envelope_is_verified_in_the_order_of_the_protocol() {
        let signer = SigningKey::from_bytes(&[0x11; 32]);
        let from = giving().node();
        assert_eq!(from, b64u(&signer.verifying_key().to_bytes()));
        let outcome = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut value = payload_value();
            change(&mut value);
            let envelope = sealed_with(&signer, &from, &to_json(&value));
            open_secret_use(&receiving(), &envelope).map(|_| ())
        };
        assert_eq!(outcome(&|_| {}), Ok(()));
        // Keys the protocol does not define are ignored.
        assert_eq!(outcome(&|payload| payload["future"] = json!(1)), Ok(()));

        // The signature of another key than the one the envelope names.
        let other = SigningKey::from_bytes(&[0x61; 32]);
        let forged = sealed_with(&other, &from, &to_json(&payload_value()));
        assert_eq!(
            open_secret_use(&receiving(), &forged).map(|_| ()),
            Err(ProtocolError::BadSignature)
        );
        // A `from` that is no signing key.
        let unnamed = sealed_with(&signer, "not-a-node", &to_json(&payload_value()));
        assert_eq!(
            open_secret_use(&receiving(), &unnamed).map(|_| ()),
            Err(ProtocolError::InvalidRequest)
        );
        // A payload that is not JSON, under a signature that verifies.
        let no_json = sealed_with(&signer, &from, b"not json");
        assert_eq!(
            open_secret_use(&receiving(), &no_json).map(|_| ()),
            Err(ProtocolError::InvalidRequest)
        );

        assert_eq!(
            outcome(&|payload| payload["v"] = json!(2)),
            Err(ProtocolError::UnsupportedVersion)
        );
        // The payload of a delegation transfer is not the payload of a secret use.
        assert_eq!(
            outcome(&|payload| payload["type"] = json!("transfer")),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(
            outcome(&|payload| payload["to"] = json!(giving().node())),
            Err(ProtocolError::WrongNode)
        );
        assert_eq!(
            outcome(&|payload| payload["from"] = json!(receiving().node())),
            Err(ProtocolError::WrongNode)
        );
        assert_eq!(
            outcome(&|payload| payload["request"]["body_bytes"] = json!(limits::BODY_BYTES + 1)),
            Err(ProtocolError::TooLarge)
        );
        let changes: Vec<Change> = vec![
            Box::new(|payload| payload["time_ms"] = json!("now")),
            Box::new(|payload| payload["not_after_ms"] = json!(-1)),
            Box::new(|payload| payload["nonce"] = json!(b64u(&[9u8; 15]))),
            Box::new(|payload| payload["nonce"] = json!(5)),
            Box::new(|payload| payload["user_id"] = json!("")),
            Box::new(|payload| payload["user_id"] = json!("a\nb")),
            Box::new(|payload| payload["record_id"] = json!("short")),
            Box::new(|payload| payload["value"] = json!(7)),
            // A value of fewer than 8 bytes cannot be searched for in a response.
            Box::new(|payload| payload["value"] = json!("1234567")),
            Box::new(|payload| {
                payload["value"] = json!("v".repeat(limits::SECRET_USE_VALUE_BYTES_MAX + 1));
            }),
            Box::new(|payload| payload["request"] = json!("POST /")),
            Box::new(|payload| payload["request"]["host"] = json!("localhost")),
            Box::new(|payload| payload["request"]["slot"] = json!("header:host")),
            Box::new(|payload| {
                payload.as_object_mut().unwrap().remove("request");
            }),
            Box::new(|payload| {
                payload.as_object_mut().unwrap().remove("value");
            }),
        ];
        for (index, change) in changes.iter().enumerate() {
            assert_eq!(
                outcome(change.as_ref()),
                Err(ProtocolError::InvalidRequest),
                "change {index}"
            );
        }
        assert_eq!(
            outcome(&|payload| payload["value"] = json!("12345678")),
            Ok(())
        );
        assert_eq!(
            outcome(&|payload| {
                payload["value"] = json!("v".repeat(limits::SECRET_USE_VALUE_BYTES_MAX));
            }),
            Ok(())
        );
    }

    #[test]
    fn a_secret_use_and_a_delegation_transfer_do_not_open_as_each_other() {
        // A transfer that a node of the delegation role sealed to the keys of this node: the
        // operation that opens a secret use does not open it, so no user key becomes readable
        // in the node that received it.
        let transfer = seal_transfer(
            &giving(),
            &receiving().sign_public(),
            &receiving().seal_public(),
            1_800_000_000_000,
            &[],
            &Secret::new([0x33; 32]),
        )
        .unwrap();
        let as_secret_use = SecretUseEnvelope {
            v: 1,
            from: transfer.from.clone(),
            to: transfer.to.clone(),
            enc: transfer.enc.clone(),
            ct: transfer.ct.clone(),
        };
        assert_eq!(
            open_secret_use(&receiving(), &as_secret_use).map(|_| ()),
            Err(ProtocolError::OpenFailed)
        );
        // And the other way round.
        let envelope = sealed();
        let as_transfer = TransferEnvelope {
            v: 1,
            from: envelope.from.clone(),
            to: envelope.to.clone(),
            enc: envelope.enc.clone(),
            ct: envelope.ct.clone(),
        };
        assert_eq!(
            open_transfer(&receiving(), &giving().sign_public(), &as_transfer).map(|_| ()),
            Err(ProtocolError::OpenFailed)
        );
        // The seal itself opens under the purpose string of a secret use and under no other.
        let private = StaticSecret::from([0x22; 32]);
        let (enc, ct) = (
            b64u_decode(&envelope.enc).unwrap(),
            b64u_decode(&envelope.ct).unwrap(),
        );
        let aad = transfer_aad(&envelope.from, &envelope.to);
        assert!(hpke_open(&private, &enc, b"pickle.secure.v3.secret-use", &aad, &ct).is_ok());
        assert!(hpke_open(&private, &enc, b"pickle.secure.v1.peer", &aad, &ct).is_err());
    }
}
