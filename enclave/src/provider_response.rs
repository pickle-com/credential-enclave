//! The search for a credential in what a provider sent, before any of it leaves the node (rule
//! E4 of the egress policy, `docs/egress-policy.md`).
//!
//! A provider is assumed to follow its public API contract: an API does not send the token of
//! its caller back, and a token response holds its tokens at the places the definition names.
//! This module is the defense for a response that breaks that assumption.
//!
//! [`Forms`] is the search. Bytes are read as they were received, with their percent escapes
//! decoded (up to [`PERCENT_LAYERS`] times, for a value that was encoded more than once), and
//! with their JSON string escapes decoded (up to [`JSON_LAYERS`] times, for a JSON text inside
//! a JSON string). Each reading is searched for these forms of the credential: as it is,
//! base64 or base64url in each of the three byte alignments and without padding, hexadecimal
//! in lower or upper case. Decoding the escapes finds the credential under every
//! percent-encoding of it and under every way a writer of JSON escapes it: encoders do not
//! agree on the bytes they escape or on the case of the digits (one writes `/` as `\/`,
//! another `=` as `\u003d`), and all of their outputs decode to the same bytes. A form
//! shorter than [`SHORTEST_FORM_BYTES`] is not searched for: it would match unrelated data.
//! The tokens of the defined providers are longer than that in every form.
//!
//! The search has three users. The public fields of a token response are searched for the
//! tokens of that response (`OauthPlaintext::public_fields`). The response of `forward` is
//! handed on only as a [`CheckedResponse`], which only [`check`] creates. It refuses:
//!
//! - a response with a `Content-Encoding` other than `identity`. The node asked for `identity`
//!   and cannot search a body it does not decode;
//! - a response that holds the injected credential in a header name, a header value or the
//!   body.
//!
//! And the response of `vault/send` is handed on while it arrives: its head only as a
//! [`CheckedHead`], which only [`check_head`] creates and which refuses the same two things
//! for the headers, and its body through a [`StreamCheck`], which searches every piece in the
//! same readings for the same forms, together with the end of what came before the piece,
//! and hands on only what lies in front of the bytes it keeps back.

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use credential_enclave_protocol::secret::Secret;
use memchr::memmem;
use zeroize::Zeroize;

use crate::oauth::Withheld;

/// The shortest form of a credential the check searches for, in bytes.
pub const SHORTEST_FORM_BYTES: usize = 8;

/// How many times the check decodes the percent escapes of what it reads.
pub const PERCENT_LAYERS: usize = 3;

/// How many times the check decodes the JSON string escapes of what it reads.
pub const JSON_LAYERS: usize = 2;

/// A provider response that passed the check: the status, the headers and the body, as the
/// provider sent them.
pub struct CheckedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl CheckedResponse {
    /// The status, the headers and the body.
    pub fn into_parts(self) -> (u16, Vec<(String, String)>, Vec<u8>) {
        (self.status, self.headers, self.body)
    }

    /// The length of the body.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

/// Checks the response of a request that carried `credential` (the token without the prefix of
/// the definition).
pub fn check(
    credential: &Secret<String>,
    status: u16,
    mut headers: Vec<(String, String)>,
    mut body: Vec<u8>,
) -> Result<CheckedResponse, Withheld> {
    let encoded = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-encoding")
            && !value.trim().eq_ignore_ascii_case("identity")
    });
    let forms = Forms::of(std::slice::from_ref(credential));
    let reflected = forms.found_in(&body)
        || headers
            .iter()
            .any(|(name, value)| forms.found_in_header(name) || forms.found_in_header(value));
    if encoded || reflected {
        // What is withheld may hold the credential: the copy this check was given is
        // overwritten before it is dropped.
        body.zeroize();
        for (name, value) in &mut headers {
            name.zeroize();
            value.zeroize();
        }
        return Err(Withheld);
    }
    Ok(CheckedResponse {
        status,
        headers,
        body,
    })
}

/// The forms of one or more credentials that are searched for in bytes a provider sent. Each
/// form is a secret, like the credential it is made of.
pub struct Forms(Vec<Secret<Vec<u8>>>);

impl Forms {
    /// The forms of every credential of `credentials`: as it is, base64 and base64url at each
    /// byte alignment, hexadecimal in both cases. A form shorter than [`SHORTEST_FORM_BYTES`]
    /// is left out.
    pub fn of(credentials: &[Secret<String>]) -> Forms {
        let mut kept: Vec<Secret<Vec<u8>>> = Vec::new();
        for credential in credentials {
            let token = credential.expose_secret().as_bytes();
            let mut forms: Vec<Vec<u8>> = vec![token.to_vec()];
            for alignment in 0..3 {
                forms.push(base64_inside(&STANDARD_NO_PAD, token, alignment));
                forms.push(base64_inside(&URL_SAFE_NO_PAD, token, alignment));
            }
            forms.push(hex(token, b"0123456789abcdef"));
            forms.push(hex(token, b"0123456789ABCDEF"));
            for form in forms {
                let form = Secret::new(form);
                let known = kept
                    .iter()
                    .any(|other| other.expose_secret() == form.expose_secret());
                if form.expose_secret().len() >= SHORTEST_FORM_BYTES && !known {
                    kept.push(form);
                }
            }
        }
        Forms(kept)
    }

    /// The length of the longest form, 0 when there is none.
    fn longest(&self) -> usize {
        self.0
            .iter()
            .map(|form| form.expose_secret().len())
            .max()
            .unwrap_or(0)
    }

    /// True when `bytes` hold one of the forms as they are: one reading, no escape decoded.
    fn in_reading(&self, bytes: &[u8]) -> bool {
        self.0
            .iter()
            .any(|form| memmem::find(bytes, form.expose_secret()).is_some())
    }

    /// True when one of the forms ends in `fresh`, the bytes that follow `tail` in one
    /// reading: it lies in `fresh` as a whole, or it begins in `tail`. A form that lies in
    /// `tail` as a whole is not looked for: it ended before `fresh`.
    ///
    /// A form that begins in `tail` is compared at each place it can end in `fresh`, so the
    /// work for a piece of a few bytes does not grow with the length of the credential.
    fn end_in(&self, tail: &[u8], fresh: &[u8]) -> bool {
        self.0.iter().any(|form| {
            let form = form.expose_secret().as_slice();
            if fresh.len() >= form.len() && memmem::find(fresh, form).is_some() {
                return true;
            }
            // The last `in_fresh` bytes of the form are the first bytes of `fresh`, and the
            // bytes in front of them are the last bytes of `tail`.
            let least = form.len().saturating_sub(tail.len()).max(1);
            let most = fresh.len().min(form.len().saturating_sub(1));
            (least..=most).any(|in_fresh| {
                form.len()
                    .checked_sub(in_fresh)
                    .and_then(|in_tail| form.split_at_checked(in_tail))
                    .is_some_and(|(front, back)| tail.ends_with(front) && fresh.starts_with(back))
            })
        })
    }

    /// True when the name or the value of a response header holds one of the forms
    /// ([`Forms::found_in`]): in the text the node hands on, or in the bytes the sender wrote
    /// when that text is their reading as ISO 8859-1.
    ///
    /// A header whose bytes are not UTF-8 is handed on with one character per byte
    /// (`Exchange::of`). A credential with a character outside ASCII stands in such a text as
    /// other characters than its own, and whoever receives the text reads the bytes back
    /// from it. So a text whose characters all lie below U+0100 is searched as the bytes
    /// those characters stand for as well.
    pub fn found_in_header(&self, text: &str) -> bool {
        if self.found_in(text.as_bytes()) {
            return true;
        }
        if text.is_ascii() {
            return false;
        }
        let bytes: Option<Vec<u8>> = text
            .chars()
            .map(|character| u8::try_from(u32::from(character)).ok())
            .collect();
        bytes.is_some_and(|mut bytes| {
            let found = self.found_in(&bytes);
            bytes.zeroize();
            found
        })
    }

    /// True when `received` hold one of the forms: as received, under percent escapes, or
    /// under the escapes of a JSON string.
    pub fn found_in(&self, received: &[u8]) -> bool {
        if self.in_reading(received) {
            return true;
        }
        // Each layer of escapes is decoded and searched. There is one decoded copy at a time,
        // and each further layer is decoded inside it. The copy may hold the credential: it
        // is overwritten before it is dropped.
        if let Some(mut decoded) = percent_decoded(received) {
            let mut layer = 1;
            let reflected = loop {
                if self.in_reading(&decoded) {
                    break true;
                }
                if layer == PERCENT_LAYERS || !decode_in_place(&mut decoded) {
                    break false;
                }
                layer += 1;
            };
            decoded.zeroize();
            if reflected {
                return true;
            }
        }
        if memchr::memchr(b'\\', received).is_none() {
            return false;
        }
        let mut decoded = received.to_vec();
        let mut reflected = false;
        for _ in 0..JSON_LAYERS {
            if !decode_escapes_in_place(Escapes::Json, &mut decoded) {
                break;
            }
            if self.in_reading(&decoded) {
                reflected = true;
                break;
            }
        }
        decoded.zeroize();
        reflected
    }
}

/// The escapes a reading of bytes decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Escapes {
    /// `%` and two hexadecimal digits: the byte they name.
    Percent,
    /// The escapes of a JSON string: `\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`, and
    /// `\u` with four hexadecimal digits, as the UTF-8 bytes of its character (two such
    /// escapes for a character outside the basic plane).
    Json,
}

impl Escapes {
    /// How many times a reading decodes these escapes.
    fn layers(self) -> usize {
        match self {
            Escapes::Percent => PERCENT_LAYERS,
            Escapes::Json => JSON_LAYERS,
        }
    }

    /// True when `bytes` hold an escape of this kind, or begin one at their end that the bytes
    /// after them may complete: the reading with the escapes decoded then differs from
    /// `bytes`, or may come to differ.
    fn found_in(self, bytes: &[u8], end: bool) -> bool {
        let introducer = match self {
            Escapes::Percent => b'%',
            Escapes::Json => b'\\',
        };
        memchr::memchr_iter(introducer, bytes).any(|index| {
            bytes
                .get(index..)
                .is_some_and(|rest| !matches!(self.step(rest, end), Step::Literal))
        })
    }

    /// What stands at the beginning of `rest`, which is not empty. With `end`, nothing
    /// follows `rest`.
    fn step(self, rest: &[u8], end: bool) -> Step {
        match self {
            Escapes::Percent => percent_step(rest, end),
            Escapes::Json => json_step(rest, end),
        }
    }
}

/// What stands at a place of the bytes a reading decodes.
enum Step {
    /// A byte that stands for itself.
    Literal,
    /// An escape of `consumed` bytes that stands for the first `length` bytes of `decoded`.
    Decoded {
        consumed: usize,
        decoded: [u8; 4],
        length: usize,
    },
    /// The beginning of an escape that the bytes after the end may complete.
    Open,
}

fn hex_digit(byte: Option<&u8>) -> Option<u32> {
    byte.and_then(|byte| char::from(*byte).to_digit(16))
}

/// An escape that stands for one byte.
fn one_byte(consumed: usize, byte: u8) -> Step {
    Step::Decoded {
        consumed,
        decoded: [byte, 0, 0, 0],
        length: 1,
    }
}

fn percent_step(rest: &[u8], end: bool) -> Step {
    if rest.first() != Some(&b'%') {
        return Step::Literal;
    }
    match (rest.len(), hex_digit(rest.get(1)), hex_digit(rest.get(2))) {
        // Two hexadecimal digits are a value below 256.
        (_, Some(high), Some(low)) => match u8::try_from(high * 16 + low) {
            Ok(byte) => one_byte(3, byte),
            Err(_) => Step::Literal,
        },
        // `%`, or `%` and one digit, at the end of what was read so far.
        (1, _, _) | (2, Some(_), _) if !end => Step::Open,
        _ => Step::Literal,
    }
}

/// The code unit of a `\uXXXX` escape at the beginning of `rest`.
enum Unit {
    /// `rest` begins with such an escape: its sixteen bits.
    Value(u32),
    /// `rest` is the beginning of such an escape, and the bytes after it may complete it.
    Begun,
    /// `rest` begins with no such escape.
    Absent,
}

fn code_unit(rest: &[u8]) -> Unit {
    // The first two bytes, or as many as there are, are those of `\u`.
    if !b"\\u".starts_with(rest.get(..2).unwrap_or(rest)) {
        return Unit::Absent;
    }
    let mut value = 0;
    for offset in 2..6 {
        match (rest.get(offset), hex_digit(rest.get(offset))) {
            (None, _) => return Unit::Begun,
            (Some(_), Some(digit)) => value = value * 16 + digit,
            (Some(_), None) => return Unit::Absent,
        }
    }
    Unit::Value(value)
}

fn json_step(rest: &[u8], end: bool) -> Step {
    if rest.first() != Some(&b'\\') {
        return Step::Literal;
    }
    let character = |code: u32, consumed: usize| match char::from_u32(code) {
        Some(character) => {
            let mut decoded = [0u8; 4];
            let length = character.encode_utf8(&mut decoded).len();
            Step::Decoded {
                consumed,
                decoded,
                length,
            }
        }
        None => Step::Literal,
    };
    let open = match end {
        true => Step::Literal,
        false => Step::Open,
    };
    match rest.get(1) {
        None => open,
        Some(b'"') => one_byte(2, b'"'),
        Some(b'\\') => one_byte(2, b'\\'),
        Some(b'/') => one_byte(2, b'/'),
        Some(b'b') => one_byte(2, 0x08),
        Some(b'f') => one_byte(2, 0x0c),
        Some(b'n') => one_byte(2, b'\n'),
        Some(b'r') => one_byte(2, b'\r'),
        Some(b't') => one_byte(2, b'\t'),
        Some(b'u') => match code_unit(rest) {
            Unit::Begun => open,
            Unit::Absent => Step::Literal,
            // The first half of a character outside the basic plane: the second half follows
            // as an escape of its own. A half without its other half is the bytes it is.
            Unit::Value(high @ 0xd800..=0xdbff) => {
                match code_unit(rest.get(6..).unwrap_or_default()) {
                    Unit::Value(low @ 0xdc00..=0xdfff) => {
                        character(0x1_0000 + ((high - 0xd800) << 10) + (low - 0xdc00), 12)
                    }
                    Unit::Begun => open,
                    _ => Step::Literal,
                }
            }
            Unit::Value(unit) => character(unit, 6),
        },
        Some(_) => Step::Literal,
    }
}

/// Replaces every escape of `bytes` by the bytes it stands for, in place. False when `bytes`
/// hold no such escape. What an escape stands for is never longer than the escape, so the
/// result is written over the source, and the bytes behind the result are overwritten before
/// the length is cut.
fn decode_escapes_in_place(escapes: Escapes, bytes: &mut Vec<u8>) -> bool {
    let (mut read, mut write, mut any) = (0, 0, false);
    while let Some(rest) = bytes.get(read..).filter(|rest| !rest.is_empty()) {
        // The bytes the step stands for, at most four, and the bytes of `bytes` it consumed.
        let (stands_for, length, consumed) = match escapes.step(rest, true) {
            Step::Decoded {
                consumed,
                decoded,
                length,
            } => {
                any = true;
                (decoded, length, consumed)
            }
            Step::Literal | Step::Open => {
                let literal = rest.first().copied().unwrap_or_default();
                ([literal, 0, 0, 0], 1, 1)
            }
        };
        // The result is not longer than what was read, so it is written at or in front of
        // the place of the read.
        for (target, byte) in bytes
            .iter_mut()
            .skip(write)
            .zip(stands_for.iter().take(length))
        {
            *target = *byte;
        }
        read += consumed;
        write += length;
    }
    if let Some(behind) = bytes.get_mut(write..) {
        behind.zeroize();
    }
    bytes.truncate(write);
    any
}

/// The head of a response that is handed on while its body still arrives: the status and the
/// headers, after the checks [`check`] makes on them. Only [`check_head`] creates one.
pub struct CheckedHead {
    status: u16,
    headers: Vec<(String, String)>,
}

impl CheckedHead {
    /// The status and the headers.
    pub fn into_parts(self) -> (u16, Vec<(String, String)>) {
        (self.status, self.headers)
    }
}

/// Checks the head of the response of a request that carried `credential`, for a response
/// whose body is handed on piece by piece: a `Content-Encoding` other than `identity` and a
/// header name or a header value that holds the credential withhold the response, as in
/// [`check`]. Returns the head and the search every piece of the body passes before it is
/// handed on ([`StreamCheck`]).
pub fn check_head(
    credential: &Secret<String>,
    status: u16,
    mut headers: Vec<(String, String)>,
) -> Result<(CheckedHead, StreamCheck), Withheld> {
    let encoded = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-encoding")
            && !value.trim().eq_ignore_ascii_case("identity")
    });
    let forms = Forms::of(std::slice::from_ref(credential));
    let reflected = headers
        .iter()
        .any(|(name, value)| forms.found_in_header(name) || forms.found_in_header(value));
    if encoded || reflected {
        for (name, value) in &mut headers {
            name.zeroize();
            value.zeroize();
        }
        return Err(Withheld);
    }
    Ok((CheckedHead { status, headers }, StreamCheck::new(forms)))
}

/// Where each byte of a run of bytes begins in the body as it was received.
enum Starts {
    /// The bytes are the received bytes themselves, the first of them at this place.
    From(u64),
    /// One place per byte: the place of the first received byte the byte was decoded from.
    Each(Vec<u64>),
}

impl Starts {
    /// The place of the byte at `index`. A list holds one place per byte; a place it does
    /// not hold is read as the beginning of the body, so the search then keeps back
    /// everything: it never hands on a byte it should have kept.
    fn at(&self, index: usize) -> u64 {
        match self {
            Starts::From(first) => first.saturating_add(index as u64),
            Starts::Each(places) => places.get(index).copied().unwrap_or(0),
        }
    }
}

/// The bytes one piece of the body adds to one reading of it. Decoded bytes may hold the
/// credential: they are overwritten before they are dropped.
struct Fresh<'a> {
    bytes: std::borrow::Cow<'a, [u8]>,
    starts: Starts,
}

impl Drop for Fresh<'_> {
    fn drop(&mut self) {
        if let std::borrow::Cow::Owned(bytes) = &mut self.bytes {
            bytes.zeroize();
        }
    }
}

/// One reading of the body: which escapes it decodes, of which other reading, and its end.
struct Reading {
    /// The reading this one is decoded from, the escapes that are decoded, and how many
    /// readings of those escapes lie between the body as received and this one, this one
    /// counted. `None` for the body as received.
    origin: Option<(usize, Escapes, usize)>,
    /// Decodes the escapes of the reading this one is decoded from.
    decoder: Decoder,
    /// The last bytes of the reading, as many as the search keeps back, each with the place
    /// in the received body it began at.
    tail: Vec<u8>,
    starts: Vec<u64>,
}

impl Reading {
    /// A reading that begins as a copy of the end of `before`, the reading it is decoded
    /// from as that one stood in front of the piece that holds its first escape: up to there
    /// the two were the same bytes. The tail has room for the bytes it keeps, so it is never
    /// moved to another place of memory.
    fn begun(
        origin: Option<(usize, Escapes, usize)>,
        before: Option<&Reading>,
        hold: usize,
    ) -> Reading {
        let mut tail = Vec::with_capacity(hold);
        let mut starts = Vec::with_capacity(hold);
        if let Some(before) = before {
            tail.extend_from_slice(&before.tail);
            starts.extend_from_slice(&before.starts);
        }
        Reading {
            origin,
            decoder: Decoder::default(),
            tail,
            starts,
        }
    }

    /// Adds `fresh` to the reading and keeps its last `hold` bytes. True when the reading
    /// holds a form that ends in `fresh`. `hold` is longer than every form.
    fn advance(&mut self, forms: &Forms, hold: usize, fresh: &Fresh<'_>) -> bool {
        if forms.end_in(&self.tail, &fresh.bytes) {
            return true;
        }
        let kept_fresh = fresh.bytes.len().min(hold);
        let from_fresh = fresh.bytes.len().saturating_sub(kept_fresh);
        let kept_tail = hold.saturating_sub(kept_fresh).min(self.tail.len());
        let drop_tail = self.tail.len().saturating_sub(kept_tail);
        if let Some(dropped) = self.tail.get_mut(..drop_tail) {
            dropped.zeroize();
        }
        // The tail and its places have one length: each drops as many as it has of them.
        self.tail.drain(..drop_tail.min(self.tail.len()));
        self.starts.drain(..drop_tail.min(self.starts.len()));
        self.tail
            .extend_from_slice(fresh.bytes.get(from_fresh..).unwrap_or_default());
        self.starts
            .extend((from_fresh..fresh.bytes.len()).map(|index| fresh.starts.at(index)));
        false
    }

    /// The place in the received body where the first byte this reading keeps back began.
    /// `None` for a reading without a byte.
    fn kept_from(&self) -> Option<u64> {
        self.starts.first().copied()
    }
}

impl Drop for Reading {
    fn drop(&mut self) {
        self.tail.zeroize();
    }
}

/// Decodes the escapes of one reading into the next one, piece by piece. An escape that a
/// piece begins and does not end waits here for the bytes that follow.
#[derive(Default)]
struct Decoder {
    carry: Vec<u8>,
    carry_starts: Vec<u64>,
}

impl Decoder {
    /// The bytes `fresh` adds to the next reading: every escape becomes the bytes it stands
    /// for, at the place of its first byte. With `end`, nothing follows `fresh`: an escape
    /// that did not end is the bytes it is.
    fn decode(&mut self, escapes: Escapes, fresh: &Fresh<'_>, end: bool) -> Fresh<'static> {
        let mut bytes = Vec::with_capacity(self.carry.len() + fresh.bytes.len());
        bytes.extend_from_slice(&self.carry);
        bytes.extend_from_slice(&fresh.bytes);
        let mut starts = std::mem::take(&mut self.carry_starts);
        starts.extend((0..fresh.bytes.len()).map(|index| fresh.starts.at(index)));
        self.carry.zeroize();
        self.carry.clear();
        // The longest escape that waits is two escapes of a JSON string less one byte.
        self.carry.reserve_exact(12);
        // What an escape stands for is never longer than the escape.
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut places = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while let Some(rest) = bytes.get(index..).filter(|rest| !rest.is_empty()) {
            // One place per byte: a place the list does not hold is the beginning of the
            // body, which keeps back more and hands on nothing it should not.
            let place = starts.get(index).copied().unwrap_or(0);
            match escapes.step(rest, end) {
                Step::Decoded {
                    consumed,
                    decoded: stands_for,
                    length,
                } => {
                    decoded.extend(stands_for.iter().take(length));
                    places.extend(std::iter::repeat_n(place, length.min(stands_for.len())));
                    index += consumed.max(1);
                }
                Step::Literal => {
                    decoded.extend(rest.first());
                    places.push(place);
                    index += 1;
                }
                // The escape may end in the bytes that follow: it waits.
                Step::Open => {
                    self.carry.extend_from_slice(rest);
                    self.carry_starts = starts.get(index..).unwrap_or_default().to_vec();
                    break;
                }
            }
        }
        bytes.zeroize();
        Fresh {
            bytes: std::borrow::Cow::Owned(decoded),
            starts: Starts::Each(places),
        }
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        self.carry.zeroize();
    }
}

/// The search for a credential in a body that is handed on while it arrives.
///
/// The body is read in the readings [`Forms::found_in`] makes of a whole body: as received,
/// with its percent escapes decoded once, twice and three times, and with its JSON string
/// escapes decoded once and twice. A piece is searched in every reading together with the
/// end of what came before it, so a form that lies across two or more pieces is found when
/// its last byte arrives.
///
/// What is handed on lags behind what was received. Of every reading the search keeps the
/// last bytes back, as many as the longest form is long plus one, and it hands on the
/// received bytes in front of the place where the first kept byte of any reading began. So
/// when a form is found, no byte of it was handed on, in any reading, and neither was the
/// one byte in front of it: in a base64 text that character holds bits of the first byte of
/// the credential beside bits of the byte before.
///
/// How far the handed on bytes lag depends on the length of the credential and on the
/// escapes of the body, and on nothing else: no byte is handed on sooner or later because it
/// resembles the credential. A search that kept bytes back only while they begin like a form
/// would tell its caller, by the sizes of what it hands on, that the end of a piece is the
/// beginning of the credential, and a caller that can make the sender put a text of its
/// choice there would learn the credential one byte at a time. The one thing the bytes this
/// search hands on tell about the credential is whether the body held it whole.
///
/// The kept bytes are handed on by [`StreamCheck::finish`], at the end of the body as its
/// sender ended it: they hold no form. A body that is cut (the connection failed, the time
/// limit of the call passed) has no such end, and its kept bytes are not handed on: they may
/// be the beginning of a form the rest of the body would have completed, and whoever carries
/// the bytes of the connection can end it at any place.
pub struct StreamCheck {
    forms: Forms,
    /// How many of its last bytes every reading keeps back: the length of the longest form
    /// plus one.
    hold: usize,
    /// The received bytes that were not handed on yet: the first of them is at `released`
    /// in the body.
    held: Vec<u8>,
    released: u64,
    received: u64,
    /// The readings: the body as received first, and behind it each reading that decodes
    /// the escapes of a reading in front of it. A reading exists from the piece on in which
    /// the reading it is decoded from held an escape of its kind. Before that it is the same
    /// bytes as that reading.
    readings: Vec<Reading>,
}

impl StreamCheck {
    fn new(forms: Forms) -> StreamCheck {
        let hold = forms.longest() + 1;
        StreamCheck {
            forms,
            hold,
            held: Vec::new(),
            released: 0,
            received: 0,
            readings: vec![Reading::begun(None, None, hold)],
        }
    }

    /// Takes the next piece of the body and adds to `handed` the bytes that are handed on
    /// now: the received bytes up to the place the search keeps back from. `Err` when a
    /// reading of the body holds the credential: nothing more is handed on, and the bytes
    /// that were kept are overwritten.
    pub fn push(&mut self, piece: &[u8], handed: &mut Vec<u8>) -> Result<(), Withheld> {
        self.step(piece, false, handed)
    }

    /// The body has ended as its sender ended it: adds the kept bytes to `handed`. An escape
    /// that began and did not end is the bytes it is, in every reading, and `Err` when a
    /// reading holds the credential with them.
    pub fn finish(mut self, handed: &mut Vec<u8>) -> Result<(), Withheld> {
        self.step(&[], true, handed)
    }

    /// True when the reading at `index` has no reading that decodes `escapes` of it yet, and
    /// may have one: the body as received has one of each kind, and a reading that decodes
    /// escapes has one of its own kind until the layers of that kind are reached.
    fn may_begin(&self, index: usize, escapes: Escapes) -> bool {
        let Some(reading) = self.readings.get(index) else {
            return false;
        };
        let depth = match reading.origin {
            None => 0,
            Some((_, own, depth)) if own == escapes => depth,
            Some(_) => return false,
        };
        let begun = self
            .readings
            .iter()
            .any(|reading| matches!(reading.origin, Some((from, kind, _)) if from == index && kind == escapes));
        depth < escapes.layers() && !begun
    }

    fn step(&mut self, piece: &[u8], end: bool, handed: &mut Vec<u8>) -> Result<(), Withheld> {
        let first = self.received;
        self.received += piece.len() as u64;
        let mut kept_from = self.received;
        // What the piece adds to each reading, in the order of the readings: a reading
        // stands behind the reading it is decoded from.
        let mut fresh = vec![Fresh {
            bytes: std::borrow::Cow::Borrowed(piece),
            starts: Starts::From(first),
        }];
        let mut index = 0;
        while index < self.readings.len() {
            // Every reading has its place in `readings`, and what the piece adds to it has
            // the same place in `fresh`: a reading stands behind the reading it is decoded
            // from, whose bytes are in `fresh` when its turn comes. A search that finds one
            // of them missing is not in a state it can search from, and withholds the body.
            let origin = self.readings.get(index).and_then(|reading| reading.origin);
            if let Some((from, escapes, _)) = origin {
                let (Some(reading), Some(source)) = (self.readings.get_mut(index), fresh.get(from))
                else {
                    self.held.zeroize();
                    return Err(Withheld);
                };
                let decoded = reading.decoder.decode(escapes, source, end);
                fresh.push(decoded);
            }
            let Some(added) = fresh.get(index) else {
                self.held.zeroize();
                return Err(Withheld);
            };
            for escapes in [Escapes::Percent, Escapes::Json] {
                if self.may_begin(index, escapes) && escapes.found_in(&added.bytes, end) {
                    let depth = origin.map_or(1, |(_, _, depth)| depth + 1);
                    let begun = Reading::begun(
                        Some((index, escapes, depth)),
                        self.readings.get(index),
                        self.hold,
                    );
                    self.readings.push(begun);
                }
            }
            let Some(reading) = self.readings.get_mut(index) else {
                self.held.zeroize();
                return Err(Withheld);
            };
            if reading.advance(&self.forms, self.hold, added) {
                self.held.zeroize();
                return Err(Withheld);
            }
            // An escape that waits in a decoder is among the last bytes of the reading it
            // is decoded from, so the place that reading keeps back from is in front of it.
            if let Some(place) = reading.kept_from() {
                kept_from = kept_from.min(place);
            }
            index += 1;
        }
        // At the end of the body nothing follows: no form grows out of what is kept.
        let until = match end {
            true => self.received,
            false => kept_from,
        };
        // Of the kept bytes and of the piece, those in front of `until` are handed on. The
        // rest is kept in a buffer of its own size, and the buffer it leaves is overwritten.
        let count = usize::try_from(until.saturating_sub(self.released)).unwrap_or(usize::MAX);
        let from_held = count.min(self.held.len());
        let from_piece = count.saturating_sub(from_held).min(piece.len());
        // Neither place lies behind the end of its bytes. Bytes that could not be parted
        // there are kept whole: nothing of them is handed on.
        let (held_out, held_kept) = self
            .held
            .split_at_checked(from_held)
            .unwrap_or((&[], self.held.as_slice()));
        let (piece_out, piece_kept) = piece.split_at_checked(from_piece).unwrap_or((&[], piece));
        handed.extend_from_slice(held_out);
        handed.extend_from_slice(piece_out);
        let handed_on = held_out.len() + piece_out.len();
        let mut kept = Vec::with_capacity(held_kept.len() + piece_kept.len());
        kept.extend_from_slice(held_kept);
        kept.extend_from_slice(piece_kept);
        self.held.zeroize();
        self.held = kept;
        self.released = self.released.saturating_add(handed_on as u64);
        Ok(())
    }
}

impl Drop for StreamCheck {
    fn drop(&mut self) {
        self.held.zeroize();
    }
}

/// The byte a percent escape at `index` stands for: `%` and two hexadecimal digits of either
/// case.
fn escape_at(bytes: &[u8], index: usize) -> Option<u8> {
    let hex = |byte: Option<&u8>| byte.and_then(|byte| char::from(*byte).to_digit(16));
    match (
        bytes.get(index),
        hex(bytes.get(index + 1)),
        hex(bytes.get(index + 2)),
    ) {
        (Some(b'%'), Some(high), Some(low)) => u8::try_from(high * 16 + low).ok(),
        _ => None,
    }
}

/// `bytes` with every percent escape replaced by the byte it stands for. `None` when `bytes`
/// hold no escape: nothing is copied then.
fn percent_decoded(bytes: &[u8]) -> Option<Vec<u8>> {
    let first =
        memchr::memchr_iter(b'%', bytes).find(|index| escape_at(bytes, *index).is_some())?;
    let mut decoded = bytes.to_vec();
    decode_from(&mut decoded, first);
    Some(decoded)
}

/// Replaces every percent escape of `bytes` by the byte it stands for, in place. False when
/// `bytes` hold no escape.
fn decode_in_place(bytes: &mut Vec<u8>) -> bool {
    let first = memchr::memchr_iter(b'%', bytes).find(|index| escape_at(bytes, *index).is_some());
    match first {
        Some(first) => {
            decode_from(bytes, first);
            true
        }
        None => false,
    }
}

/// Decodes the escapes of `bytes` from `first` on, where `first` is the place of an escape. A
/// decoded value is never longer than its source, so the result is written over the source.
/// The bytes behind the result are overwritten before the length is cut.
fn decode_from(bytes: &mut Vec<u8>, first: usize) {
    let (mut read, mut write) = (first, first);
    while let Some(literal) = bytes.get(read).copied() {
        let (byte, consumed) = match escape_at(bytes, read) {
            Some(byte) => (byte, 3),
            None => (literal, 1),
        };
        // The result is not longer than what was read: the place of the write is at or in
        // front of the place of the read.
        if let Some(target) = bytes.get_mut(write) {
            *target = byte;
        }
        read += consumed;
        write += 1;
    }
    if let Some(behind) = bytes.get_mut(write..) {
        behind.zeroize();
    }
    bytes.truncate(write);
}

fn hex(bytes: &[u8], digits: &[u8; 16]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // A half of a byte is below 16, the length of the table.
        for half in [byte >> 4, byte & 0x0f] {
            encoded.extend(digits.get(usize::from(half)));
        }
    }
    encoded
}

/// The base64 characters that `bytes` produce wherever they stand inside a longer encoded
/// value, when `alignment` bytes (0, 1 or 2) come before them in their group of three.
///
/// The bytes are encoded behind `alignment` filler bytes. The characters at the front that
/// also depend on the bytes before (2 for one filler byte, 3 for two) and the character at the
/// end that also depends on the byte after are cut off. What remains appears in the encoding of
/// every value that holds `bytes` at that alignment.
fn base64_inside(engine: &impl Engine, bytes: &[u8], alignment: usize) -> Vec<u8> {
    let mut padded = vec![0u8; alignment];
    padded.extend_from_slice(bytes);
    let mut encoded = engine.encode(&padded).into_bytes();
    padded.iter_mut().for_each(|byte| *byte = 0);
    if !padded.len().is_multiple_of(3) {
        encoded.pop();
    }
    let front = match alignment {
        0 => 0,
        1 => 2,
        _ => 3,
    };
    let form = encoded.split_off(front.min(encoded.len()));
    encoded.iter_mut().for_each(|byte| *byte = 0);
    form
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "ya29.a0Af/Token+With=Symbols_1234567890";

    fn credential() -> Secret<String> {
        Secret::new(TOKEN.to_string())
    }

    fn outcome(headers: &[(&str, &str)], body: &[u8]) -> Result<(), Withheld> {
        let headers = headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        check(&credential(), 200, headers, body.to_vec()).map(|_| ())
    }

    #[test]
    fn a_credential_in_a_header_that_is_not_utf8_is_found_in_the_bytes_of_the_header() {
        // A credential with characters outside ASCII, and a header value of bytes that are
        // not UTF-8 around it: the node hands such a header on with one character per byte.
        let credential = Secret::new("\u{d1a0}\u{d070}-\u{be44}\u{bc00}-0123456789".to_string());
        let forms = Forms::of(std::slice::from_ref(&credential));
        let handed_on = |bytes: &[u8]| -> String {
            match std::str::from_utf8(bytes) {
                Ok(text) => text.to_string(),
                Err(_) => bytes.iter().map(|byte| char::from(*byte)).collect(),
            }
        };
        let token = credential.expose_secret().as_bytes();
        // In a header of UTF-8 bytes the credential stands as its own characters.
        let utf8 = [b"denied: ".as_slice(), token].concat();
        assert!(forms.found_in_header(&handed_on(&utf8)));
        // One byte that is no UTF-8 in front of it, behind it, and a Latin-1 word beside it.
        for other in [&b"\xff "[..], b"caf\xe9 ", b"\x80"] {
            for bytes in [[other, token].concat(), [token, other].concat()] {
                let text = handed_on(&bytes);
                assert!(!text.contains(credential.expose_secret().as_str()));
                assert!(!forms.found_in(text.as_bytes()), "{text:?}");
                assert!(forms.found_in_header(&text), "{text:?}");
                let headers = vec![("x-echo".to_string(), text.clone())];
                assert!(check(&credential, 401, headers.clone(), Vec::new()).is_err());
                assert!(check_head(&credential, 401, headers).is_err());
            }
        }
        // The same under a percent escape of the bytes of the credential.
        let escaped: String = token.iter().map(|byte| format!("%{byte:02X}")).collect();
        let text = handed_on(&[b"\xff ".as_slice(), escaped.as_bytes()].concat());
        assert!(forms.found_in_header(&text));
        // A header that holds no form of it passes, whatever its bytes.
        for bytes in [
            &b"caf\xe9"[..],
            b"\xff\xfe",
            "\u{d55c}\u{ae00}".as_bytes(),
            b"plain",
        ] {
            assert!(!forms.found_in_header(&handed_on(bytes)), "{bytes:?}");
        }
    }

    #[test]
    fn a_response_without_the_credential_passes_unchanged() {
        let headers = vec![("content-type".to_string(), "application/json".to_string())];
        let checked = check(
            &credential(),
            207,
            headers.clone(),
            b"{\"ok\":true}".to_vec(),
        );
        let (status, returned, body) = checked.unwrap().into_parts();
        assert_eq!(status, 207);
        assert_eq!(returned, headers);
        assert_eq!(body, b"{\"ok\":true}");
        assert_eq!(outcome(&[], b""), Ok(()));
        // A part of the token is not the token.
        assert_eq!(outcome(&[], &TOKEN.as_bytes()[..TOKEN.len() - 1]), Ok(()));
    }

    #[test]
    fn a_reflected_credential_is_withheld_in_every_form() {
        let token = TOKEN.as_bytes();
        let embed = |form: &[u8]| {
            let mut body = b"{\"echo\":\"prefix ".to_vec();
            body.extend_from_slice(form);
            body.extend_from_slice(b" suffix\"}");
            body
        };
        assert_eq!(outcome(&[], &embed(token)), Err(Withheld));
        // Percent-encoded. Encoders differ in the bytes they escape and in the case of the
        // digits: the reserved bytes `/`, `+` and `=`, all of them but `/`, every byte, or any
        // mix.
        let every_byte = |upper: bool| -> String {
            token
                .iter()
                .map(|byte| match upper {
                    true => format!("%{byte:02X}"),
                    false => format!("%{byte:02x}"),
                })
                .collect()
        };
        for encoded in [
            "ya29.a0Af%2FToken%2BWith%3DSymbols_1234567890".to_string(),
            "ya29.a0Af%2fToken%2bWith%3dSymbols_1234567890".to_string(),
            "ya29.a0Af/Token%2BWith%3DSymbols_1234567890".to_string(),
            "ya29%2Ea0Af%2fToken%2BWith%3dSymbols%5F1234567890".to_string(),
            every_byte(true),
            every_byte(false),
            // Encoded twice and three times, as a value inside an address inside an address.
            "ya29.a0Af%252FToken%252BWith%253DSymbols_1234567890".to_string(),
            "ya29.a0Af%25252FToken%25252BWith%25253DSymbols_1234567890".to_string(),
        ] {
            assert_eq!(
                outcome(&[], &embed(encoded.as_bytes())),
                Err(Withheld),
                "{encoded}"
            );
            assert_eq!(
                outcome(
                    &[("location", &format!("https://a.example/?t={encoded}"))],
                    b""
                ),
                Err(Withheld),
                "{encoded}"
            );
        }
        // An escape that is not one stays as it is, and a response with escapes but without
        // the credential passes.
        assert_eq!(outcome(&[], b"100%, %zz, %4, 50%25 of ya29"), Ok(()));
        // Base64 and base64url of a longer value that holds the token at each alignment.
        for prefix in ["", "x", "xy", "xyz", "Bearer "] {
            let mut value = prefix.as_bytes().to_vec();
            value.extend_from_slice(token);
            value.extend_from_slice(b" and more");
            for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
                let encoded = engine.encode(&value);
                assert_eq!(
                    outcome(&[], &embed(encoded.as_bytes())),
                    Err(Withheld),
                    "{prefix:?}"
                );
            }
            let padded = base64::engine::general_purpose::STANDARD.encode(&value);
            assert_eq!(outcome(&[], &embed(padded.as_bytes())), Err(Withheld));
            // The base64 value with its `+`, `/` and `=` escaped, as in a query.
            let escaped = padded
                .replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D");
            assert_eq!(outcome(&[], &embed(escaped.as_bytes())), Err(Withheld));
        }
        let hexadecimal: String = token.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(outcome(&[], &embed(hexadecimal.as_bytes())), Err(Withheld));
        assert_eq!(
            outcome(&[], &embed(hexadecimal.to_ascii_uppercase().as_bytes())),
            Err(Withheld)
        );
        // Inside a JSON string. Writers of JSON differ in what they escape: `/`, the
        // characters of markup, every character, and a JSON text inside a JSON string is
        // escaped twice.
        let every_unit: String = token.iter().map(|byte| format!("\\u{byte:04x}")).collect();
        for escaped in [
            r"ya29.a0Af\/Token+With=Symbols_1234567890".to_string(),
            r"ya29.a0Af/Token+With\u003dSymbols_1234567890".to_string(),
            r"ya29.a0Af\u002FToken\u002bWith\u003DSymbols_1234567890".to_string(),
            every_unit.clone(),
            every_unit.replace('\\', r"\\"),
            r"ya29.a0Af\\/Token+With=Symbols_1234567890".to_string(),
        ] {
            assert_eq!(
                outcome(&[], &embed(escaped.as_bytes())),
                Err(Withheld),
                "{escaped}"
            );
            assert_eq!(
                outcome(&[("x-echo", &escaped)], b""),
                Err(Withheld),
                "{escaped}"
            );
        }
        // An escape that is not one stays as it is, and a response with escapes but without
        // the credential passes.
        assert_eq!(
            outcome(
                &[],
                br#"{"a":"C:\\dir\n\u00e9\ud83d\ude00 \x \u12 \ud83d ya29"}"#
            ),
            Ok(())
        );
    }

    #[test]
    fn the_escapes_of_a_json_string_are_decoded_once_per_layer() {
        let decoded = |text: &str| {
            let mut bytes = text.as_bytes().to_vec();
            decode_escapes_in_place(Escapes::Json, &mut bytes)
                .then(|| String::from_utf8(bytes).unwrap())
        };
        assert_eq!(
            decoded(r#"a\"b\\c\/d\be\ff\ng\rh\ti"#).as_deref(),
            Some("a\"b\\c/d\u{8}e\u{c}f\ng\rh\ti")
        );
        assert_eq!(
            decoded(r"\u0041\u00e9\ud55c").as_deref(),
            Some("A\u{e9}\u{d55c}")
        );
        // The two halves of a character outside the basic plane are one character. A half
        // without its other half, and an escape that is none, are the bytes they are.
        assert_eq!(decoded(r"\ud83d\ude00").as_deref(), Some("\u{1f600}"));
        assert_eq!(decoded(r"\ud83d"), None);
        assert_eq!(decoded(r"\ude00\ud83d"), None);
        assert_eq!(decoded(r"\ud83d\u0041").as_deref(), Some(r"\ud83dA"));
        assert_eq!(decoded(r"no escape, \x \u12 \u12g4 \"), None);
        // One layer at a time: a backslash that an escape stood for begins no escape in the
        // same pass.
        assert_eq!(decoded(r"\\u0041").as_deref(), Some(r"\u0041"));
        assert_eq!(decoded(r"\\\\u0041").as_deref(), Some(r"\\u0041"));
    }

    #[test]
    fn a_credential_in_a_header_is_withheld() {
        assert_eq!(
            outcome(
                &[("x-echo-authorization", &format!("Bearer {TOKEN}"))],
                b"{}"
            ),
            Err(Withheld)
        );
        let encoded = STANDARD_NO_PAD.encode(format!("Bearer {TOKEN}"));
        assert_eq!(outcome(&[("x-debug", &encoded)], b"{}"), Err(Withheld));
        assert_eq!(outcome(&[("x-request-id", "abc")], b"{}"), Ok(()));
    }

    #[test]
    fn a_content_encoding_other_than_identity_is_withheld() {
        for value in ["gzip", "br", "deflate", "GZIP", "gzip, identity", ""] {
            assert_eq!(
                outcome(&[("content-encoding", value)], b"\x1f\x8b"),
                Err(Withheld),
                "{value:?}"
            );
        }
        assert_eq!(outcome(&[("Content-Encoding", "zstd")], b""), Err(Withheld));
        assert_eq!(outcome(&[("content-encoding", "identity")], b"{}"), Ok(()));
        assert_eq!(
            outcome(&[("content-encoding", " Identity ")], b"{}"),
            Ok(())
        );
    }

    #[test]
    fn forms_shorter_than_the_limit_are_not_searched() {
        // A 4-byte credential has no form of 8 bytes but its hexadecimal one.
        let short = Secret::new("abcd".to_string());
        let forms: Vec<Vec<u8>> = Forms::of(std::slice::from_ref(&short))
            .0
            .iter()
            .map(|form| form.expose_secret().clone())
            .collect();
        assert_eq!(forms, vec![b"61626364".to_vec()]);
        assert!(check(&short, 200, Vec::new(), b"abcd abcd".to_vec()).is_ok());
        // Every form of a long token is kept once.
        let forms = Forms::of(&[credential()]).0;
        // The token as it is, three base64 alignments and two hexadecimal forms. The base64url
        // forms are kept when they differ from the base64 ones.
        assert!(forms.len() >= 6, "{}", forms.len());
        for (index, form) in forms.iter().enumerate() {
            assert!(form.expose_secret().len() >= SHORTEST_FORM_BYTES);
            assert!(forms[index + 1..]
                .iter()
                .all(|other| other.expose_secret() != form.expose_secret()));
        }
        // The forms of several credentials are searched together.
        let both = Forms::of(&[credential(), Secret::new("another-token-0123".to_string())]);
        assert!(both.found_in(TOKEN.as_bytes()));
        assert!(both.found_in(b"x another-token-0123 y"));
        assert!(!both.found_in(b"neither of them"));
    }

    #[test]
    fn percent_escapes_are_decoded_once_per_layer() {
        assert_eq!(percent_decoded(b"plain text"), None);
        assert_eq!(percent_decoded(b"100% and %zz and %4"), None);
        assert_eq!(percent_decoded(b"a%2Fb%2fc%41"), Some(b"a/b/cA".to_vec()));
        assert_eq!(percent_decoded(b"%25%32%46"), Some(b"%2F".to_vec()));
        assert_eq!(percent_decoded(b"%00%ff%FF"), Some(vec![0x00, 0xff, 0xff]));
        assert_eq!(percent_decoded(b"50%25, %zz"), Some(b"50%, %zz".to_vec()));
        // Each further layer is decoded inside the copy of the first one.
        let mut layers = b"%252525zz%252541".to_vec();
        assert!(decode_in_place(&mut layers));
        assert_eq!(layers, b"%2525zz%2541");
        assert!(decode_in_place(&mut layers));
        assert_eq!(layers, b"%25zz%41");
        assert!(decode_in_place(&mut layers));
        assert_eq!(layers, b"%zzA");
        assert!(!decode_in_place(&mut layers));
        assert_eq!(layers, b"%zzA");
        // A fourth layer is not decoded.
        let token = TOKEN.as_bytes();
        let mut layered = token.to_vec();
        for _ in 0..PERCENT_LAYERS + 1 {
            layered = layered
                .iter()
                .flat_map(|byte| format!("%{byte:02X}").into_bytes())
                .collect();
        }
        assert_eq!(outcome(&[], &layered), Ok(()));
        let mut decoded = percent_decoded(&layered).unwrap();
        assert_eq!(outcome(&[], &decoded), Err(Withheld));
        for _ in 1..PERCENT_LAYERS {
            decoded = percent_decoded(&decoded).unwrap();
        }
        assert_eq!(percent_decoded(&decoded), Some(token.to_vec()));
    }

    /// The search of a streamed body for the token of these tests.
    fn stream_check() -> StreamCheck {
        StreamCheck::new(Forms::of(&[credential()]))
    }

    /// How many of its last bytes a reading keeps back for the token of these tests: its
    /// hexadecimal form is the longest one.
    const HOLD: usize = 2 * TOKEN.len() + 1;

    /// What a body gives when it is handed on in the pieces `cuts` make of it: the bytes that
    /// were handed on, and whether the search withheld the rest.
    fn streamed(body: &[u8], cuts: &[usize]) -> (Vec<u8>, bool) {
        let mut check = stream_check();
        let mut handed = Vec::new();
        let mut from = 0;
        for cut in cuts.iter().copied().chain([body.len()]) {
            if check.push(&body[from..cut], &mut handed).is_err() {
                return (handed, true);
            }
            from = cut;
        }
        match check.finish(&mut handed) {
            Ok(()) => (handed, false),
            Err(Withheld) => (handed, true),
        }
    }

    /// The forms of the token a response may reflect it in, each under a name.
    fn reflections() -> Vec<(String, Vec<u8>)> {
        let token = TOKEN.as_bytes();
        let percent = |bytes: &[u8], every: bool, upper: bool| -> Vec<u8> {
            let mut text = String::new();
            for byte in bytes {
                let plain = byte.is_ascii_alphanumeric() || b"-._~".contains(byte);
                match (plain && !every, upper) {
                    (true, _) => text.push(char::from(*byte)),
                    (false, true) => text.push_str(&format!("%{byte:02X}")),
                    (false, false) => text.push_str(&format!("%{byte:02x}")),
                }
            }
            text.into_bytes()
        };
        let mut forms = vec![
            ("as it is".to_string(), token.to_vec()),
            ("percent, reserved".to_string(), percent(token, false, true)),
            (
                "percent, every byte".to_string(),
                percent(token, true, false),
            ),
            (
                "percent twice".to_string(),
                percent(&percent(token, false, true), false, true),
            ),
            (
                "percent three times, every byte".to_string(),
                percent(
                    &percent(&percent(token, true, true), true, false),
                    true,
                    true,
                ),
            ),
            (
                "hex".to_string(),
                token
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
                    .into_bytes(),
            ),
            (
                "upper case hex".to_string(),
                token
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<String>()
                    .into_bytes(),
            ),
        ];
        let json = |bytes: &[u8], every: bool| -> Vec<u8> {
            let mut text = String::new();
            for byte in bytes {
                match (byte, every) {
                    (_, true) => text.push_str(&format!("\\u{byte:04x}")),
                    (b'/', false) => text.push_str("\\/"),
                    (b'=' | b'+', false) => text.push_str(&format!("\\u{byte:04x}")),
                    (b'\\', false) => text.push_str("\\\\"),
                    _ => text.push(char::from(*byte)),
                }
            }
            text.into_bytes()
        };
        forms.push(("JSON, some characters".to_string(), json(token, false)));
        forms.push(("JSON, every character".to_string(), json(token, true)));
        forms.push((
            "JSON inside a JSON string".to_string(),
            json(&json(token, false), false),
        ));
        for front in ["", "x", "xy"] {
            let value = [front.as_bytes(), token, b" tail"].concat();
            forms.push((
                format!("base64 behind {} bytes", front.len()),
                STANDARD_NO_PAD.encode(&value).into_bytes(),
            ));
            forms.push((
                format!("base64url behind {} bytes", front.len()),
                URL_SAFE_NO_PAD.encode(&value).into_bytes(),
            ));
            // The base64 text with its `+` and `/` escaped, as inside an address.
            let escaped = STANDARD_NO_PAD
                .encode(&value)
                .replace('+', "%2B")
                .replace('/', "%2F");
            forms.push((
                format!("percent-encoded base64 behind {} bytes", front.len()),
                escaped.into_bytes(),
            ));
        }
        forms
    }

    #[test]
    fn a_streamed_body_without_the_credential_is_handed_on_whole_behind_the_kept_bytes() {
        let body = [
            b"{\"ok\":true,\"items\":[1,2,3],\"note\":\"100% of a%2Fb, %zz\"}".as_slice(),
            &[b'.'; 300],
        ]
        .concat();
        for cuts in [vec![], vec![1], vec![10, 20, 30], (1..body.len()).collect()] {
            assert_eq!(streamed(&body, &cuts), (body.clone(), false), "{cuts:?}");
        }
        // Of a body without an escape, what was handed on after a piece is what was received
        // but for the last bytes, as many as the longest form is long plus one.
        let plain = vec![b'a'; 1000];
        let mut check = stream_check();
        let mut handed = Vec::new();
        for (received, piece) in plain.chunks(64).enumerate().map(|(index, piece)| {
            let received = (index * 64 + piece.len()).min(plain.len());
            (received, piece)
        }) {
            check.push(piece, &mut handed).unwrap();
            assert_eq!(handed.len(), received.saturating_sub(HOLD), "{received}");
        }
        check.finish(&mut handed).unwrap();
        assert_eq!(handed, plain);
        // Where escapes stand among the last bytes, the bytes one reading keeps back began
        // further in front: more is kept, and nothing is lost.
        let escaped = "%41".repeat(400).into_bytes();
        let mut check = stream_check();
        let mut handed = Vec::new();
        check.push(&escaped, &mut handed).unwrap();
        assert_eq!(handed.len(), escaped.len() - 3 * HOLD);
        check.finish(&mut handed).unwrap();
        assert_eq!(handed, escaped);
        let escaped = r"\u0041".repeat(400).into_bytes();
        let mut check = stream_check();
        let mut handed = Vec::new();
        check.push(&escaped, &mut handed).unwrap();
        assert_eq!(handed.len(), escaped.len() - 6 * HOLD);
        check.finish(&mut handed).unwrap();
        assert_eq!(handed, escaped);
    }

    #[test]
    fn a_credential_that_lies_across_pieces_is_found_before_a_byte_of_it_is_handed_on() {
        for (name, form) in reflections() {
            let body = [b"{\"echo\":\"lead ".as_slice(), &form, b" tail\"}"].concat();
            let begins = b"{\"echo\":\"lead ".len();
            // In a base64 text of a value that holds the token behind one or two bytes, the
            // first one or two characters depend on those bytes alone. Every character after
            // them holds bits of the token: none of those is handed on, the one in front of
            // the form the search finds included.
            let free = ["behind 1 bytes", "behind 2 bytes"]
                .iter()
                .position(|behind| name.ends_with(behind))
                .map_or(0, |index| index + 1);
            let mut every_cut: Vec<Vec<usize>> = vec![vec![], (1..body.len()).collect()];
            every_cut.extend((1..body.len()).map(|cut| vec![cut]));
            every_cut.extend((1..body.len() - 7).map(|cut| vec![cut, cut + 3, cut + 7]));
            for cuts in every_cut {
                let (handed, withheld) = streamed(&body, &cuts);
                assert!(withheld, "{name}, cut at {cuts:?}");
                assert!(
                    handed.len() <= begins + free,
                    "{name}, cut at {cuts:?}: {} bytes were handed on",
                    handed.len()
                );
                assert_eq!(handed, body[..handed.len()], "{name}, cut at {cuts:?}");
                // What was handed on holds no form of the token, in any reading.
                assert!(
                    !Forms::of(&[credential()]).found_in(&handed),
                    "{name}, cut at {cuts:?}"
                );
            }
        }
    }

    #[test]
    fn what_is_handed_on_does_not_depend_on_a_likeness_to_the_credential() {
        // One body, searched for two credentials of the same length. The pieces of the body
        // end with beginnings of the first credential, in several of its forms, and hold
        // nothing like the second one. After every piece the two searches handed on the same
        // bytes: nothing the caller sees while a body arrives tells it that the end of a
        // piece begins like the credential of the request.
        const OTHER: &str = "zb38-b1Bg~Uplfo*Xjui.Tzncpmt!2345678901";
        assert_eq!(OTHER.len(), TOKEN.len());
        let other = || StreamCheck::new(Forms::of(&[Secret::new(OTHER.to_string())]));
        let token = TOKEN.as_bytes();
        let filler = vec![b'.'; 400];
        let mut compared = 0;
        for (name, form) in reflections() {
            for length in [1, 2, 3, form.len() / 2, form.len() - 1] {
                let begun = &form[..length];
                let body = [&filler, begun, &filler, begun, &filler].concat();
                // The beginning of a reflection may hold a whole form of the token: such a
                // body is withheld, which is the one thing a search tells.
                if Forms::of(&[credential()]).found_in(&body) {
                    continue;
                }
                compared += 1;
                let cuts = [400 + length, 800 + 2 * length];
                let (mut check_like, mut check_unlike) = (stream_check(), other());
                let (mut handed_like, mut handed_unlike) = (Vec::new(), Vec::new());
                let mut from = 0;
                for cut in cuts.into_iter().chain([body.len()]) {
                    check_like.push(&body[from..cut], &mut handed_like).unwrap();
                    check_unlike
                        .push(&body[from..cut], &mut handed_unlike)
                        .unwrap();
                    assert_eq!(handed_like, handed_unlike, "{name} {length} at {cut}");
                    // The bytes in front of the place a reading keeps back from, and none
                    // behind it.
                    assert!(handed_like.len() <= cut - HOLD, "{name} {length} at {cut}");
                    from = cut;
                }
                // A part of the token is not the token: at the end of the body all of it is
                // handed on.
                check_like.finish(&mut handed_like).unwrap();
                assert_eq!(handed_like, body, "{name} {length}");
            }
        }
        assert!(compared > 50);
        // The whole token but for its last byte, and then the end of the body.
        let begun = [b"lead ".as_slice(), &token[..token.len() - 1]].concat();
        assert_eq!(streamed(&begun, &[5, 20]), (begun.clone(), false));
    }

    #[test]
    fn a_body_that_does_not_end_as_its_sender_ended_it_keeps_its_last_bytes_back() {
        // The bytes a search keeps are handed on by `finish` alone. A search that is dropped
        // without it, because the body was cut, hands on what it had handed on before: of a
        // token that the body began and did not complete, no byte.
        let token = TOKEN.as_bytes();
        let lead = vec![b'.'; 500];
        for cut in 1..token.len() {
            let mut check = stream_check();
            let mut handed = Vec::new();
            check.push(&lead, &mut handed).unwrap();
            check.push(&token[..cut], &mut handed).unwrap();
            assert!(handed.len() < lead.len(), "{cut}");
            assert_eq!(handed, lead[..handed.len()], "{cut}");
        }
    }

    #[test]
    fn the_search_of_a_streamed_body_agrees_with_the_search_of_the_whole_body() {
        // Bodies made of the parts a reflection is made of, in an order a fixed sequence of
        // numbers chooses, each cut at places the same sequence chooses.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % bound as u64) as usize
        };
        let token = TOKEN.as_bytes();
        let forms = reflections();
        let fragments: Vec<Vec<u8>> = vec![
            b"%".to_vec(),
            b"%2".to_vec(),
            b"%25".to_vec(),
            b"%2525".to_vec(),
            b"25".to_vec(),
            b"%zz".to_vec(),
            b"ya29".to_vec(),
            b"ya29.a0Af".to_vec(),
            b"%79a29".to_vec(),
            br"\".to_vec(),
            br"\u".to_vec(),
            br"\u00".to_vec(),
            br"\u0079a29".to_vec(),
            br"\/".to_vec(),
            br"\\".to_vec(),
            br"\ud83d".to_vec(),
            br"\ude00".to_vec(),
            b"u0079".to_vec(),
            token[..token.len() - 1].to_vec(),
            token[1..].to_vec(),
            b" ".to_vec(),
            b"\n".to_vec(),
            b"{\"k\":\"v\"}".to_vec(),
        ];
        let (mut withheld_bodies, mut passed_bodies) = (0, 0);
        for round in 0..4000 {
            let mut body = Vec::new();
            for _ in 0..1 + next(6) {
                match next(10) {
                    // Three in ten parts are a whole form of the token.
                    0..=2 => body.extend_from_slice(&forms[next(forms.len())].1),
                    _ => body.extend_from_slice(&fragments[next(fragments.len())]),
                }
            }
            let mut cuts: Vec<usize> = (0..next(5)).map(|_| next(body.len() + 1)).collect();
            cuts.sort_unstable();
            let whole = Forms::of(&[credential()]).found_in(&body);
            let (handed, withheld) = streamed(&body, &cuts);
            assert_eq!(
                withheld,
                whole,
                "round {round}: {:?}",
                String::from_utf8_lossy(&body)
            );
            assert_eq!(handed, body[..handed.len()], "round {round}");
            match withheld {
                true => {
                    withheld_bodies += 1;
                    assert!(
                        !Forms::of(&[credential()]).found_in(&handed),
                        "round {round}: {:?} was handed on",
                        String::from_utf8_lossy(&handed)
                    );
                }
                false => {
                    passed_bodies += 1;
                    assert_eq!(handed.len(), body.len(), "round {round}");
                }
            }
        }
        assert!(withheld_bodies > 500 && passed_bodies > 500);
    }

    #[test]
    fn the_head_of_a_streamed_response_passes_the_checks_of_a_whole_response() {
        let head = |headers: &[(&str, &str)]| {
            let headers = headers
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect();
            check_head(&credential(), 200, headers).map(|(head, _)| head.into_parts())
        };
        assert_eq!(
            head(&[("content-type", "text/event-stream")]).ok(),
            Some((
                200,
                vec![("content-type".to_string(), "text/event-stream".to_string())]
            ))
        );
        assert!(head(&[("content-encoding", "identity")]).is_ok());
        assert!(head(&[("content-encoding", "gzip")]).is_err());
        assert!(head(&[("x-echo", &format!("Bearer {TOKEN}"))]).is_err());
        let encoded = STANDARD_NO_PAD.encode(format!("Bearer {TOKEN}"));
        assert!(head(&[("x-debug", &encoded)]).is_err());
        let location = format!("https://a.example/?t={}", TOKEN.replace('/', "%2F"));
        assert!(head(&[("location", &location)]).is_err());
    }

    #[test]
    fn the_base64_form_is_what_every_alignment_shares() {
        let token = b"0123456789abcdef";
        for alignment in 0..3 {
            let form = base64_inside(&STANDARD_NO_PAD, token, alignment);
            for before in [vec![0xffu8; alignment], vec![0x00u8; alignment]] {
                for after in [&b""[..], b"\xff", b"\x00\x01", b"zzz"] {
                    let mut value = before.clone();
                    value.extend_from_slice(token);
                    value.extend_from_slice(after);
                    let encoded = STANDARD_NO_PAD.encode(&value).into_bytes();
                    // A value that ends with the token ends with a character that also holds
                    // padding bits: the form leaves that character out, so it is still found.
                    assert!(
                        memmem::find(&encoded, &form).is_some(),
                        "alignment {alignment}, after {after:?}"
                    );
                }
            }
        }
    }
}
