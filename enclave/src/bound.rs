//! The request of one use of a vault secret, as a node of the forward role sends it
//! (enclave.md 5.16, protocol.md 10.5).
//!
//! The envelope of a use names one request: its method, its host, its path and its query, the
//! place of the value (the slot), and the size and the hash of its body. The caller of
//! `vault/send` gives the rest of the request, the headers and the body, with a placeholder
//! where the value goes. This module puts the value there, and nowhere else:
//!
//! - the body is the body the envelope names, by its length and its SHA-256;
//! - the placeholder occurs once in the whole request (the names and the values of the
//!   headers, the path, the query, the body), and that one occurrence is at the slot;
//! - the value is written in the form of its place: as it is inside a header value (a value
//!   with a control character is not written there), percent-encoded in the path, in a query
//!   parameter and in a form field, and as the content of a JSON string in a JSON body;
//! - for the slots `basic:user` and `basic:password` the placeholder is one half of the
//!   credentials of HTTP Basic: the one `Authorization` header of the caller is `Basic`, a
//!   space and the base64 text of `user-id:password`, and the placeholder is the whole of the
//!   half the slot names (`BasicCredentials::read` of the protocol crate): the whole user-id
//!   for `basic:user`, the whole password for `basic:password`. It occurs nowhere in the
//!   request as it stands. The node writes that header anew, with the value for that half,
//!   in the one form it reads the header in: a value with a control character, and a value
//!   with a colon for the user-id, is not written there. The caller does not choose the
//!   half: credentials with the placeholder as the other half are not sent, so a value its
//!   record holds as a password does not leave as a user-id;
//! - what the caller wrote around the placeholder leaves the value to itself. In a header the
//!   placeholder begins the value or stands behind a space, `=`, `:` or `"`: a text of the
//!   caller that ends with the beginning of an escape would take the first characters of the
//!   value for the rest of that escape. In the path the request object keeps the same rule
//!   for percent escapes (`BoundRequest::from_value` of the protocol crate);
//! - a value of a header slot is read as it stands. The header of the slot is stated once (a
//!   server joins two headers of one name, or reads one of them, by a rule of its own), and in
//!   a header a server reads the credentials of an authentication scheme from
//!   (`Authorization`, and a header named after it) the text in front of the placeholder
//!   names no scheme under which a server decodes what follows or reads a user name from it:
//!   `Basic`, `Digest`, `Negotiate`, `NTLM` (`secret_use::states_no_scheme` of the protocol
//!   crate). A value its record holds for the header does not become such credentials: a
//!   server could send back the bytes it decoded, a text the search of the response does not
//!   find;
//! - a body that holds the value is the body its `Content-Type` says: a form for a form
//!   slot, JSON for a JSON slot. A server reads a body by that header, so the field the node
//!   wrote the value into is the field the server reads it from. For the same reason the
//!   header states no `charset` but UTF-8, the caller states no `Content-Encoding`, and a
//!   JSON body is UTF-8: under another character encoding or a coding, a server reads other
//!   characters than the bytes the node judged and wrote.
//!
//! So a request that leaves with the value is the request of the event `provider_request`
//! that the node of the delegation role wrote for this use before it sealed the value
//! (`vault/handoff`, enclave.md 5.9c): the same address, the same body but for the value, and
//! the value at the place the record of the secret allows. Only [`prepare`] creates the
//! request with the value.

use std::fmt;

use axum::http::HeaderValue;
use credential_enclave_protocol::encoding::b64u;
use credential_enclave_protocol::secret::Secret;
use credential_enclave_protocol::secret_use::{
    fits_header, header_key, is_the_value_of, names_no_other_charset, occurrences,
    reads_credentials, stands_free, states_no_scheme, BasicCredentials, SecretUse, Slot,
    DROPPED_HEADERS, REFUSED_HEADERS,
};
use credential_enclave_protocol::ProtocolError;
use hyper::body::Bytes;
use memchr::memmem;
use serde::de::{DeserializeSeed, Deserializer, Error as _, IgnoredAny, MapAccess, Visitor};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::api::ApiError;
use crate::egress::{self, BoundBody, BoundRequest, OutboundHeader};

/// `invalid_request` for a request that is not the request of its envelope.
fn mismatch(message: &'static str) -> ApiError {
    ApiError::with_message(ProtocolError::InvalidRequest, message)
}

const MISPLACED: &str = "the placeholder is not once in the request, at the slot of the envelope";

const NOT_BASIC: &str = concat!(
    "the one Authorization header is not HTTP Basic with the placeholder as the whole ",
    "user-id or the whole password, or the placeholder stands in the request as it is"
);

const NOT_ONE_HEADER: &str = "the header of the slot is not stated once, under its own name";

const IN_A_SCHEME: &str = concat!(
    "the header states credentials of a scheme a value does not stand in as it is ",
    "(Basic, Digest, Negotiate, NTLM), or holds a character outside ASCII in front of ",
    "the placeholder"
);

const OTHER_HALF: &str = concat!(
    "the placeholder is not the half of the HTTP Basic credentials the slot names: ",
    "the user-id for basic:user, the password for basic:password"
);

/// One header of the caller: its name as it was given, the key its name is compared by
/// (`secret_use::header_key`), and its value.
struct CallerHeader {
    name: String,
    key: String,
    value: String,
}

/// Reads the headers of the caller: an array of `[name, value]` pairs. A name that is not a
/// token and a value with a control character are `invalid_request`. A header of
/// `REFUSED_HEADERS` is `not_allowed`, and so is an `Accept` header that names another
/// character encoding than UTF-8 (`secret_use::names_no_other_charset`).
fn caller_headers(headers: Option<&Value>) -> Result<Vec<CallerHeader>, ApiError> {
    let invalid = || mismatch("headers is missing or invalid");
    let Some(headers) = headers.filter(|headers| !headers.is_null()) else {
        return Ok(Vec::new());
    };
    let mut pairs = Vec::new();
    for pair in headers.as_array().ok_or_else(invalid)? {
        let (name, value) = match pair.as_array().map(Vec::as_slice) {
            Some([name, value]) => (
                name.as_str().ok_or_else(invalid)?,
                value.as_str().ok_or_else(invalid)?,
            ),
            _ => return Err(invalid()),
        };
        if !egress::is_token(name) || HeaderValue::from_bytes(value.as_bytes()).is_err() {
            return Err(invalid());
        }
        let key = header_key(name);
        // A header that asks the site for another request than the request of the entry,
        // and an `Accept` header that asks it for its response in another character
        // encoding than the bytes the node searches.
        if REFUSED_HEADERS.contains(&key.as_str())
            || (key == "accept" && !names_no_other_charset(value))
        {
            return Err(ProtocolError::NotAllowed.into());
        }
        pairs.push(CallerHeader {
            name: name.to_string(),
            key,
            value: value.to_string(),
        });
    }
    Ok(pairs)
}

/// The media type of the one `Content-Type` header of the caller, in lower case and without
/// its parameters: the syntax a server reads the body in. `None` when the headers of the
/// caller do not say that a server reads the bytes of the body as the node read them:
///
/// - the caller gave no such header, more than one, or one whose name is written with `_`: a
///   server that does not read `_` as `-` would find no `Content-Type` in the request, and
///   read the body by a rule of its own;
/// - the header states a `charset` other than UTF-8. A server that reads the body in another
///   character encoding reads other characters than the node judged, and the bytes of the
///   value as another text: under UTF-16, two bytes of the value as one character;
/// - the caller states a `Content-Encoding`: a server that removes a coding from the body
///   reads another body than the bytes the node judged and wrote the value into.
fn content_type(headers: &[CallerHeader]) -> Option<String> {
    let mut stated = headers.iter().filter(|header| header.key == "content-type");
    let (first, second) = (stated.next()?, stated.next());
    let coded = headers
        .iter()
        .any(|header| header.key == "content-encoding");
    let media_type = first.value.split(';').next().unwrap_or_default();
    let in_utf8 = names_no_other_charset(&first.value);
    (second.is_none() && !coded && in_utf8 && first.name.eq_ignore_ascii_case("content-type"))
        .then(|| media_type.trim().to_ascii_lowercase())
}

/// True when every byte of `body` is one a form body is written with: a letter, a digit, or
/// one of ``-._~*!'()%+=&,:@/$;[]``. A form body holds no space, no quote, no bracket of JSON
/// or of markup and no control character, so it is the body of no other syntax.
fn is_form_text(body: &[u8]) -> bool {
    body.iter()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-._~*!'()%+=&,:@/$;[]".contains(byte))
}

/// How often `needle` occurs in `text`, counted from every position.
fn count(text: &[u8], needle: &[u8]) -> usize {
    let finder = memmem::Finder::new(needle);
    let (mut from, mut found) = (0, 0);
    while let Some(at) = text.get(from..).and_then(|rest| finder.find(rest)) {
        found += 1;
        from += at + 1;
    }
    found
}

/// The strings of the members a path of keys names in a JSON object, each borrowed from the
/// text of the document. A member that is no string, a string that is written with an escape
/// and an object that names a key of the path twice are errors: the placeholder stands in a
/// JSON body as it is, at a member a reader of the document finds in one way.
struct Members<'k>(&'k [String]);

impl<'de> DeserializeSeed<'de> for Members<'_> {
    type Value = Vec<&'de str>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Members<'_> {
    type Value = Vec<&'de str>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut found = Vec::new();
        let mut named = false;
        // The path names one key or more: a path without a key names no member.
        let Some((first, deeper)) = self.0.split_first() else {
            return Err(A::Error::custom("a path without a key"));
        };
        while let Some(key) = map.next_key::<String>()? {
            if key != *first {
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            // Readers of JSON do not agree on which of two members of one name counts.
            if std::mem::replace(&mut named, true) {
                return Err(A::Error::custom("a key of the path occurs twice"));
            }
            match deeper {
                [] => found.push(map.next_value::<&'de str>()?),
                _ => found.extend(map.next_value_seed(Members(deeper))?),
            }
        }
        Ok(found)
    }
}

/// True when `body` is a JSON document whose member at `keys` (object keys from the outside
/// in) exists and is the string `placeholder`, written without an escape. A document that
/// names a key of the path twice in one object has no such member, and neither has a
/// document whose bytes are not UTF-8: the reader below passes over a string it does not
/// return without judging its bytes, and a server that reads bytes outside UTF-8 by a rule
/// of its own may find the end of that string, and so the members of the document, at
/// another place.
fn is_the_json_string_at(body: &[u8], keys: &[String], placeholder: &str) -> bool {
    if keys.is_empty() || std::str::from_utf8(body).is_err() {
        return false;
    }
    let mut document = serde_json::Deserializer::from_slice(body);
    let Ok(found) = Members(keys).deserialize(&mut document) else {
        return false;
    };
    document.end().is_ok() && found == [placeholder]
}

/// The hexadecimal digit of `half`, one half of a byte, in a table of sixteen digits. A half
/// of a byte is below 16.
fn digit_of(digits: &[u8; 16], half: u8) -> u8 {
    digits.get(usize::from(half & 15)).copied().unwrap_or(b'0')
}

/// The value as it is written inside a header value: as it is.
fn as_it_is(value: &Secret<String>) -> Secret<Vec<u8>> {
    Secret::new(value.expose_secret().as_bytes().to_vec())
}

/// The value as it is written in a path, in a query parameter and in a form field: every byte
/// outside the unreserved characters of RFC 3986 as a percent escape. No byte of the value can
/// end the segment, the parameter or the field it is written into.
fn percent_encoded(value: &Secret<String>) -> Secret<Vec<u8>> {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let bytes = value.expose_secret().as_bytes();
    // The longest form: no buffer that holds a part of the value is left behind by a growth.
    let mut encoded = Vec::with_capacity(bytes.len() * 3);
    for byte in bytes {
        match byte.is_ascii_alphanumeric() || b"-._~".contains(byte) {
            true => encoded.push(*byte),
            false => encoded.extend_from_slice(&[
                b'%',
                digit_of(DIGITS, byte >> 4),
                digit_of(DIGITS, byte & 15),
            ]),
        }
    }
    Secret::new(encoded)
}

/// The value as the content of a JSON string: `"`, `\` and the control characters escaped. No
/// byte of the value can end the string it is written into.
fn json_escaped(value: &Secret<String>) -> Secret<Vec<u8>> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let bytes = value.expose_secret().as_bytes();
    // The longest form, as in `percent_encoded`.
    let mut escaped = Vec::with_capacity(bytes.len() * 6);
    for byte in bytes {
        match byte {
            b'"' => escaped.extend_from_slice(b"\\\""),
            b'\\' => escaped.extend_from_slice(b"\\\\"),
            0x00..=0x1f => escaped.extend_from_slice(&[
                b'\\',
                b'u',
                b'0',
                b'0',
                digit_of(DIGITS, byte >> 4),
                digit_of(DIGITS, byte & 15),
            ]),
            _ => escaped.push(*byte),
        }
    }
    Secret::new(escaped)
}

/// `body` with its one occurrence of `placeholder` replaced by `written`: the bytes of the
/// body in front of the placeholder and behind it, as parts of the body the caller sent, and
/// the value between them.
fn spliced_body(body: &Bytes, placeholder: &[u8], written: Secret<Vec<u8>>) -> BoundBody {
    match memmem::find(body, placeholder) {
        Some(at) => BoundBody::Spliced {
            before: body.slice(..at),
            written,
            after: body.slice(at + placeholder.len()..),
        },
        None => BoundBody::Plain(body.clone()),
    }
}

/// `text` with its one occurrence of `placeholder` replaced by `written`.
fn spliced(text: &[u8], placeholder: &[u8], written: &Secret<Vec<u8>>) -> Secret<Vec<u8>> {
    let written = written.expose_secret();
    let Some(at) = memmem::find(text, placeholder) else {
        return Secret::new(text.to_vec());
    };
    // The placeholder was found at `at`: it lies in the text whole.
    let before = text.get(..at).unwrap_or_default();
    let after = text.get(at + placeholder.len()..).unwrap_or_default();
    let mut result = Vec::with_capacity(before.len() + written.len() + after.len());
    result.extend_from_slice(before);
    result.extend_from_slice(written);
    result.extend_from_slice(after);
    Secret::new(result)
}

/// The bytes as text. A value is UTF-8, and so is every text it is written into here.
fn text_of(bytes: Secret<Vec<u8>>) -> Result<Secret<String>, ApiError> {
    String::from_utf8(bytes.expose_secret().clone())
        .map(Secret::new)
        .map_err(|_| ApiError::internal())
}

/// Builds the request of `secret_use` from the headers and the body of the caller, with the
/// value at the slot of the envelope. Every violation of the rules at the top of this module
/// is `invalid_request` (`not_allowed` for a header of `REFUSED_HEADERS`), and nothing is
/// sent.
pub fn prepare(
    secret_use: &SecretUse,
    headers: Option<&Value>,
    payload: &Bytes,
) -> Result<BoundRequest, ApiError> {
    let request = secret_use.request();
    let placeholder = request.placeholder().as_bytes();

    // The body is the body of the entry and of the envelope.
    let hash = match payload.is_empty() {
        true => String::new(),
        false => b64u(&Sha256::digest(payload)),
    };
    if payload.len() as u64 != request.body_bytes() || hash != request.body_sha256() {
        return Err(mismatch("the body is not the body the envelope names"));
    }

    // The placeholder occurs once in the whole request. For a slot of HTTP Basic it is inside
    // the base64 text of the credentials, and occurs nowhere in the request as it stands.
    let pairs = caller_headers(headers)?;
    let in_headers: usize = pairs
        .iter()
        .map(|header| {
            occurrences(header.name.as_bytes(), placeholder)
                + occurrences(header.value.as_bytes(), placeholder)
        })
        .sum();
    let in_address = occurrences(request.path().as_bytes(), placeholder)
        + occurrences(request.query().as_bytes(), placeholder);
    let in_body = count(payload, placeholder);
    match (request.slot(), in_headers + in_address + in_body) {
        (Slot::Basic(_), 0) => {}
        (Slot::Basic(_), _) => return Err(mismatch(NOT_BASIC)),
        (_, 1) => {}
        _ => return Err(mismatch(MISPLACED)),
    }

    // That one occurrence is at the slot, and the value takes its place there in the form of
    // the place.
    let value = secret_use.value();
    let address = match request.query().is_empty() {
        true => request.path().to_string(),
        false => format!("{}?{}", request.path(), request.query()),
    };
    let mut target = Secret::new(address.clone().into_bytes());
    let mut body = BoundBody::Plain(payload.clone());
    let mut secret_header = None;
    match request.slot() {
        // The request object of an envelope has the placeholder of these two slots at its
        // place in the address (`BoundRequest::from_value` of the protocol crate).
        Slot::Path | Slot::Query(_) if in_address == 1 => {
            target = spliced(address.as_bytes(), placeholder, &percent_encoded(value));
        }
        // The slot of a request object names no header the node drops or refuses: the reader
        // of a slot takes none (`Slot::parse` of the protocol crate).
        Slot::Header(name) if in_headers == 1 => {
            // A server reads one header of a name: with two of them, which one it reads, or
            // how it joins them into one value, is its own matter. And a name written with
            // `_` is the header for a server that reads `_` as `-`, and no header for
            // another one.
            let mut stated = pairs
                .iter()
                .enumerate()
                .filter(|(_, header)| header.key == *name);
            let (at, header) = match (stated.next(), stated.next()) {
                (Some(one), None) => one,
                _ => return Err(mismatch(NOT_ONE_HEADER)),
            };
            let text = &header.value;
            if !header.name.eq_ignore_ascii_case(name)
                || occurrences(text.as_bytes(), placeholder) != 1
            {
                return Err(mismatch(MISPLACED));
            }
            let front = text.split(request.placeholder()).next().unwrap_or_default();
            if !stands_free(front) {
                return Err(mismatch(
                    "the placeholder does not begin its header value or follow a space, =, : or \"",
                ));
            }
            // The value is not written where a server does not read it as it stands: behind
            // the name of a scheme whose credentials a server decodes or reads a user name
            // from. The record of the value lists the header, and not such credentials.
            if reads_credentials(name) && !states_no_scheme(front) {
                return Err(mismatch(IN_A_SCHEME));
            }
            // Inside a header a value stands as it is, so a value that could end the line of
            // its header is not written there.
            if !fits_header(value.expose_secret()) {
                return Err(mismatch("the value cannot stand inside a header"));
            }
            let written = spliced(text.as_bytes(), placeholder, &as_it_is(value));
            secret_header = Some((at, text_of(written)?));
        }
        Slot::Form(name) if in_body == 1 => {
            let stated = content_type(&pairs);
            let placed = stated.as_deref() == Some("application/x-www-form-urlencoded")
                && is_form_text(payload)
                && is_the_value_of(payload, name, request.placeholder());
            if !placed {
                return Err(mismatch(
                    "the body is not a form, stated as one, with the placeholder as the value of the field of the slot",
                ));
            }
            body = spliced_body(payload, placeholder, percent_encoded(value));
        }
        Slot::Json(keys) if in_body == 1 => {
            let stated = content_type(&pairs);
            let json = stated
                .as_deref()
                .is_some_and(|media| media == "application/json" || media.ends_with("+json"));
            if !json || !is_the_json_string_at(payload, keys, request.placeholder()) {
                return Err(mismatch(
                    "the body is not JSON, stated as JSON, with the placeholder as the string of the member of the slot",
                ));
            }
            body = spliced_body(payload, placeholder, json_escaped(value));
        }
        Slot::Basic(part) => {
            // A server reads the credentials of one `Authorization` header: with two of
            // them, which one it reads is its own matter.
            let mut stated = pairs
                .iter()
                .enumerate()
                .filter(|(_, header)| header.key == "authorization");
            let (at, header) = match (stated.next(), stated.next()) {
                (Some(one), None) => one,
                _ => return Err(mismatch(NOT_BASIC)),
            };
            let credentials = BasicCredentials::read(&header.value, request.placeholder())
                .ok_or_else(|| mismatch(NOT_BASIC))?;
            // The slot names the half, and the caller does not: the record of the value
            // lists this slot, so the value stands for the half its record holds it as.
            if credentials.part() != *part {
                return Err(mismatch(OTHER_HALF));
            }
            // The credentials hold no control character, and the first colon ends the
            // user-id: a value that a server would read as another text is not written.
            if !part.admits(value.expose_secret()) {
                return Err(mismatch(
                    "the value cannot be the half of HTTP Basic credentials the placeholder stands for",
                ));
            }
            secret_header = Some((at, credentials.written(value)));
        }
        _ => return Err(mismatch(MISPLACED)),
    }

    let mut sent = vec![OutboundHeader::plain("accept-encoding", "identity")];
    for (index, header) in pairs.iter().enumerate() {
        if DROPPED_HEADERS.contains(&header.key.as_str()) {
            continue;
        }
        match secret_header.take_if(|(at, _)| *at == index) {
            Some((_, written)) => sent.push(OutboundHeader::secret(&header.name, written)),
            None => sent.push(OutboundHeader::plain(&header.name, &header.value)),
        }
    }
    BoundRequest::build(secret_use, &text_of(target)?, &sent, &body)
        .map_err(|_| mismatch("the request cannot be sent as an HTTP/1.1 request"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_string_of_a_json_member_is_found_by_its_keys_and_only_when_it_is_written_plainly() {
        const PLACEHOLDER: &str = "placeholder_0123456789";
        let keys = |path: &str| -> Vec<String> { path.split('.').map(str::to_string).collect() };
        let placed = |body: &str, path: &str| {
            is_the_json_string_at(body.as_bytes(), &keys(path), PLACEHOLDER)
        };
        assert!(placed(r#"{"key":"placeholder_0123456789"}"#, "key"));
        assert!(placed(
            r#" { "a" : 1, "key" : "placeholder_0123456789" , "b":[{"key":"x"}] } "#,
            "key"
        ));
        assert!(placed(
            r#"{"auth":{"token":"placeholder_0123456789","user":"u"},"token":"other"}"#,
            "auth.token"
        ));
        for (body, path) in [
            // Another member, another depth, another value.
            (r#"{"other":"placeholder_0123456789"}"#, "key"),
            (r#"{"auth":{"key":"placeholder_0123456789"}}"#, "key"),
            (r#"{"key":"placeholder_0123456789"}"#, "auth.key"),
            (r#"{"key":"xplaceholder_0123456789"}"#, "key"),
            (r#"{"key":"placeholder_0123456789x"}"#, "key"),
            (r#"{"key":["placeholder_0123456789"]}"#, "key"),
            (r#"{"key":{"key":"placeholder_0123456789"}}"#, "key"),
            (r#"{"key":5}"#, "key"),
            (r#"{"key":null}"#, "key"),
            // The member twice, in either order, and a key of the path twice, whatever the
            // second one holds.
            (
                r#"{"key":"placeholder_0123456789","key":"placeholder_0123456789"}"#,
                "key",
            ),
            (r#"{"key":"placeholder_0123456789","key":"x"}"#, "key"),
            (r#"{"key":"x","key":"placeholder_0123456789"}"#, "key"),
            (
                r#"{"a":{"k":"placeholder_0123456789"},"a":{"k":"x"}}"#,
                "a.k",
            ),
            (r#"{"a":{"k":"placeholder_0123456789"},"a":5}"#, "a.k"),
            (r#"{"a":{"k":"placeholder_0123456789"},"a":{}}"#, "a.k"),
            (r#"{"a":{},"a":{"k":"placeholder_0123456789"}}"#, "a.k"),
            (
                r#"{"a":{"k":"placeholder_0123456789"},"a":{"other":1}}"#,
                "a.k",
            ),
            // The placeholder written with an escape: its text is not in the body.
            (r#"{"key":"\u0070laceholder_0123456789"}"#, "key"),
            // No JSON document, no object, and bytes after the document.
            (r#"{"key":"placeholder_0123456789""#, "key"),
            (r#"["placeholder_0123456789"]"#, "key"),
            (r#""placeholder_0123456789""#, "key"),
            (r#"{"key":"placeholder_0123456789"} x"#, "key"),
            ("", "key"),
        ] {
            assert!(!placed(body, path), "{body} at {path}");
        }
        // Bytes that are not UTF-8, in a string the reader passes over: a JSON text is
        // UTF-8, and a server may read such bytes by a rule of its own.
        for other in [&b"\xff"[..], b"\xc2", b"\xc0\xaf", b"\xed\xa0\x80"] {
            let body = [
                br#"{"a":""#.as_slice(),
                other,
                br#"","key":"placeholder_0123456789"}"#,
            ]
            .concat();
            assert!(
                !is_the_json_string_at(&body, &keys("key"), PLACEHOLDER),
                "{other:?}"
            );
        }
        let body = "{\"a\":\"\u{d55c}\",\"key\":\"placeholder_0123456789\"}";
        assert!(placed(body, "key"));
        // A key that is written with an escape names the member all the same.
        assert!(placed(r#"{"k\u0065y":"placeholder_0123456789"}"#, "key"));
        assert!(!is_the_json_string_at(
            br#"{"key":"placeholder_0123456789"}"#,
            &[],
            PLACEHOLDER
        ));
    }

    #[test]
    fn a_value_is_written_in_the_form_of_its_place() {
        let value = Secret::new("a b/c+d=e&f\"g\\h\n\u{1f}i%j~k.l-m_n\u{d55c}".to_string());
        assert_eq!(
            String::from_utf8(percent_encoded(&value).expose_secret().clone()).unwrap(),
            "a%20b%2Fc%2Bd%3De%26f%22g%5Ch%0A%1Fi%25j~k.l-m_n%ED%95%9C"
        );
        assert_eq!(
            String::from_utf8(json_escaped(&value).expose_secret().clone()).unwrap(),
            "a b/c+d=e&f\\\"g\\\\h\\u000a\\u001fi%j~k.l-m_n\u{d55c}"
        );
        // The content of a JSON string reads back as the value.
        let quoted = [
            b"\"".as_slice(),
            json_escaped(&value).expose_secret(),
            b"\"",
        ]
        .concat();
        assert_eq!(
            serde_json::from_slice::<String>(&quoted).unwrap(),
            *value.expose_secret()
        );
        assert_eq!(
            as_it_is(&value).expose_secret().as_slice(),
            value.expose_secret().as_bytes()
        );
        let written = spliced(b"key=PLACE&b=2", b"PLACE", &percent_encoded(&value));
        assert!(written.expose_secret().starts_with(b"key=a%20b%2Fc"));
        assert!(written.expose_secret().ends_with(b"%9C&b=2"));
    }

    #[test]
    fn a_form_body_is_written_with_the_bytes_of_a_form() {
        for body in [
            "",
            "a=1&b=2",
            "grant_type=x&client_secret=PLACEHOLDER_0123456789&scope=a+b%20c",
            "url=https://h.example/p&list[0]=a,b;c&at=u@h:1&m=$!'()*~",
        ] {
            assert!(is_form_text(body.as_bytes()), "{body}");
        }
        for body in [
            "a=1 2",
            "a=\"1\"",
            "{\"comment\":\"x&secret=P&y\"}",
            "a=1\r\nb=2",
            "a=<b>",
            "a=1\\2",
            "a=\u{d55c}",
            "a=1#b",
            "a=1?b",
        ] {
            assert!(!is_form_text(body.as_bytes()), "{body}");
        }
    }

    #[test]
    fn the_media_type_of_a_request_is_that_of_its_one_content_type_header() {
        let headers = |pairs: &[(&str, &str)]| -> Vec<CallerHeader> {
            pairs
                .iter()
                .map(|(name, value)| CallerHeader {
                    name: name.to_string(),
                    key: header_key(name),
                    value: value.to_string(),
                })
                .collect()
        };
        let stated = |pairs: &[(&str, &str)]| content_type(&headers(pairs));
        assert_eq!(
            stated(&[("Content-Type", "Application/JSON; charset=utf-8")]).as_deref(),
            Some("application/json")
        );
        assert_eq!(
            stated(&[("accept", "*/*"), ("CONTENT-TYPE", " text/plain ")]).as_deref(),
            Some("text/plain")
        );
        assert_eq!(stated(&[("accept", "*/*")]), None);
        // A name with `_` is the header for a server that reads `_` as `-`, and no header
        // for another one: it states no type, alone or beside the header itself.
        assert_eq!(stated(&[("content_type", "application/json")]), None);
        assert_eq!(
            stated(&[
                ("content-type", "application/json"),
                ("Content_Type", "text/plain")
            ]),
            None
        );
        // Two headers state two things, also when they agree.
        assert_eq!(
            stated(&[
                ("content-type", "application/json"),
                ("Content-Type", "application/json")
            ]),
            None
        );
        // The one character encoding a type states is UTF-8, in either spelling and with or
        // without quotes. Under another one a server reads the bytes of the body, and of the
        // value in it, as other characters.
        for parameters in [
            "charset=utf-8",
            " charset = UTF-8 ",
            "charset=\"utf-8\"",
            "charset=utf8",
            "profile=x; charset=UTF-8; version=1",
        ] {
            let value = format!("application/json; {parameters}");
            assert_eq!(
                stated(&[("content-type", &value)]).as_deref(),
                Some("application/json"),
                "{parameters}"
            );
        }
        for parameters in [
            "charset=utf-16",
            "charset=UTF-16LE",
            "charset=\"utf-16be\"",
            "charset=utf-32",
            "charset=iso-8859-1",
            "charset=us-ascii",
            "charset=euc-kr",
            "charset=ibm037",
            "charset=",
            "charset",
            "charset*=utf-16",
            "charset=utf-8; charset=utf-16",
            "CHARSET = UTF-7",
            "boundary=charset",
        ] {
            let value = format!("application/json; {parameters}");
            assert_eq!(stated(&[("content-type", &value)]), None, "{parameters}");
        }
        // A coding of the body: a server that removes it reads another body.
        for name in ["Content-Encoding", "content-encoding", "Content_Encoding"] {
            for coding in ["gzip", "deflate", "br", "identity", ""] {
                assert_eq!(
                    stated(&[("content-type", "application/json"), (name, coding)]),
                    None,
                    "{name}: {coding}"
                );
            }
        }
    }

    #[test]
    fn occurrences_are_counted_from_every_position() {
        assert_eq!(count(b"", b"aa"), 0);
        assert_eq!(count(b"xaax", b"aa"), 1);
        assert_eq!(count(b"aaa", b"aa"), 2);
        assert_eq!(count(b"aaxaa", b"aa"), 2);
        assert_eq!(count(b"abc", b"abcd"), 0);
    }
}
