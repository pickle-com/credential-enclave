//! The search for a credential in what a provider sent, before any of it leaves the node (rule
//! E4 of the egress policy, `docs/egress-policy.md`).
//!
//! A provider is assumed to follow its public API contract: an API does not send the token of
//! its caller back, and a token response holds its tokens at the places the definition names.
//! This module is the defense for a response that breaks that assumption.
//!
//! [`Forms`] is the search. Bytes are read in six readings ([`Readings`]): as they were
//! received, with their percent escapes decoded once, twice and three times
//! ([`PERCENT_LAYERS`], for a value that was encoded more than once), and with their JSON
//! string escapes decoded once and twice ([`JSON_LAYERS`], for a JSON text inside a JSON
//! string). Each reading is searched for these
//! forms of the credential: as it is, base64 or base64url in each of the three byte alignments
//! and without padding, hexadecimal in lower or upper case. Decoding the escapes finds the
//! credential under every percent-encoding of it and under every way a writer of JSON escapes
//! it: encoders do not agree on the bytes they escape or on the case of the digits (one writes
//! `/` as `\/`, another `=` as `\u003d`), and all of their outputs decode to the same bytes. A
//! form shorter than [`SHORTEST_FORM_BYTES`] is not searched for: it would match unrelated
//! data. The tokens of the defined providers are longer than that in every form.
//!
//! The search has three users. The public fields of a token response are searched for the
//! tokens of that response (`OauthPlaintext::public_fields`). The response of `forward` is
//! handed on only as a [`CheckedResponse`], which only [`check`] creates, or as the head and
//! the parts a [`StreamCheck`] gives out. And the response of `vault/send`, the request that
//! carried the value of a vault secret, is handed on only as the head and the parts a
//! [`StreamCheck`] gives out. Both refuse:
//!
//! - a response with a `Content-Encoding` other than `identity`. The node asked for `identity`
//!   and cannot search a body it does not decode;
//! - a response that holds the credential in a header name, a header value or the body.
//!
//! [`check`] reads a whole response and hands on all of it or nothing. [`StreamCheck`] reads a
//! body while it arrives and hands on the bytes in front of the last ones it holds back, so a
//! body of any length is searched in a bounded memory. The two read a body through the same
//! readings, step by step from its first byte, so the verdict of the one on a body is the
//! verdict of the other on the same bytes, and no byte of a form a [`StreamCheck`] finds is
//! handed on: the body is cut in front of it.

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

/// The most bytes one byte of a reading can take in what a provider sent. An escape of a JSON
/// string is six bytes for one (`\u0041`), and each of the six can be such an escape of the
/// layer above it, for [`JSON_LAYERS`] layers. A percent escape is three bytes for one, for
/// [`PERCENT_LAYERS`] layers, which is less.
pub const ESCAPED_BYTE_SPAN: usize = 36;

const _: () = assert!(
    ESCAPED_BYTE_SPAN >= 6usize.pow(JSON_LAYERS as u32)
        && ESCAPED_BYTE_SPAN >= 3usize.pow(PERCENT_LAYERS as u32)
);

/// The most bytes one step of a search adds to the readings (the length of the longest form,
/// when that is longer). A reading that decodes escapes is searched for itself only in the
/// steps around an escape, so a step is short: the bytes between two escapes that lie far
/// apart are searched once, in the reading they were received in.
const SEARCH_SLICE_BYTES: usize = 1024;

/// The fewest new bytes a [`StreamCheck`] waits for before it searches them (four times the
/// length of the longest form, when that is more).
const STREAM_GATHER_BYTES: usize = 4 * 1024;

/// More bytes than an escape that waits for the bytes that follow can have: the longest one
/// is two escapes of a JSON string, the two halves of a character outside the basic plane,
/// less one byte.
const OPEN_ESCAPE_BYTES: usize = 16;

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

/// True when the headers of a response name a `Content-Encoding` other than `identity`.
fn coded(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-encoding")
            && !value.trim().eq_ignore_ascii_case("identity")
    })
}

/// Overwrites the headers of a response that is withheld: they may hold the credential.
fn overwrite(headers: &mut [(String, String)]) {
    for (name, value) in headers {
        name.zeroize();
        value.zeroize();
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
    let forms = Forms::of(std::slice::from_ref(credential));
    let search = forms.search();
    if coded(&headers) || search.found_in(&body) || search.found_in_head(&headers) {
        // What is withheld may hold the credential: the copy this check was given is
        // overwritten before it is dropped.
        body.zeroize();
        overwrite(&mut headers);
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
    ///
    /// A credential is searched for without the white space at its ends (the Unicode property
    /// White_Space). A server reads the value of a header without the white space around it,
    /// and often strips it from a parameter, so what it sends back of a credential that was
    /// stored with a space or a line end behind it may be the credential without it. Bytes
    /// that hold the credential with its white space hold it without as well, in each of
    /// these forms: the search finds both.
    pub fn of(credentials: &[Secret<String>]) -> Forms {
        let mut kept: Vec<Secret<Vec<u8>>> = Vec::new();
        for credential in credentials {
            let token = credential.expose_secret().trim().as_bytes();
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

    /// The length of the longest form in bytes, 0 when there is none.
    fn longest(&self) -> usize {
        self.0
            .iter()
            .map(|form| form.expose_secret().len())
            .max()
            .unwrap_or(0)
    }

    /// The search for these forms, made ready once for the bytes it is to read.
    fn search(&self) -> Search<'_> {
        Search {
            finders: self
                .0
                .iter()
                .map(|form| memmem::Finder::new(form.expose_secret().as_slice()))
                .collect(),
            longest: self.longest(),
        }
    }

    /// True when `received` hold one of the forms: as received, under percent escapes, or
    /// under the escapes of a JSON string.
    pub fn found_in(&self, received: &[u8]) -> bool {
        self.search().found_in(received)
    }

    /// True when the name or the value of a response header holds one of the forms
    /// ([`Forms::found_in`]): in the text the node hands on, or in the bytes the sender wrote
    /// when that text is their reading as ISO 8859-1.
    #[cfg(test)]
    pub fn found_in_header(&self, text: &str) -> bool {
        self.search().found_in_header(text)
    }
}

/// The search for the forms of a credential ([`Forms::search`]): a searcher for each form,
/// which borrows the form, and the length of the longest one.
struct Search<'a> {
    finders: Vec<memmem::Finder<'a>>,
    longest: usize,
}

impl Search<'_> {
    /// True when `bytes` hold one of the forms as they are: one reading, no escape decoded.
    fn in_reading(&self, bytes: &[u8]) -> bool {
        self.finders
            .iter()
            .any(|finder| finder.find(bytes).is_some())
    }

    /// True when `received` hold one of the forms, in one of the readings of [`Readings`].
    /// The bytes are read slice by slice: no copy of the whole of them is made.
    fn found_in(&self, received: &[u8]) -> bool {
        if self.finders.is_empty() {
            return false;
        }
        let mut readings = Readings::new(self.longest);
        received
            .chunks(slice_of(self.longest))
            .any(|slice| readings.add(self, slice, false))
            || readings.add(self, &[], true)
    }

    /// True when the name or the value of a response header holds one of the forms: in the
    /// text the node hands on, or in the bytes the sender wrote when that text is their
    /// reading as ISO 8859-1.
    ///
    /// A header whose bytes are not UTF-8 is handed on with one character per byte
    /// (`crate::egress::Exchange`). A credential with a character outside ASCII stands in
    /// such a text as other characters than its own, and whoever receives the text reads the
    /// bytes back from it. So a text whose characters all lie below U+0100 is searched as the
    /// bytes those characters stand for as well.
    fn found_in_header(&self, text: &str) -> bool {
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

    /// True when a header name or a header value of `headers` holds one of the forms.
    fn found_in_head(&self, headers: &[(String, String)]) -> bool {
        headers
            .iter()
            .any(|(name, value)| self.found_in_header(name) || self.found_in_header(value))
    }
}

/// The most bytes one step of a search adds to the readings, for a longest form of `longest`
/// bytes: [`SEARCH_SLICE_BYTES`], or the length of that form when it is longer.
const fn slice_of(longest: usize) -> usize {
    if longest > SEARCH_SLICE_BYTES {
        longest
    } else {
        SEARCH_SLICE_BYTES
    }
}

/// The escapes a reading of bytes decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Escapes {
    /// `%` and two hexadecimal digits of either case: the byte they name.
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

    /// The byte every escape of this kind begins with.
    fn first_byte(self) -> u8 {
        match self {
            Escapes::Percent => b'%',
            Escapes::Json => b'\\',
        }
    }

    /// True when `bytes` hold an escape of this kind, or, without `end`, begin one at their
    /// end that the bytes after them may complete: the reading with the escapes decoded then
    /// differs from `bytes`, or may come to differ.
    fn begin_in(self, bytes: &[u8], end: bool) -> bool {
        memchr::memchr_iter(self.first_byte(), bytes).any(|index| {
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

/// One reading of bytes that arrive in parts.
///
/// A reading that decodes escapes decodes them part by part: an escape that the bytes so far
/// begin and do not end waits for the bytes that follow. So the bytes of the reading are, at
/// every moment, the bytes of that reading of the whole body, up to the escape that waits.
///
/// A reading is searched only while it differs from the reading it is decoded from. Before
/// that reading held an escape of its kind the two are the same bytes, and they are the same
/// bytes again once as many bytes as a form can have followed the last escape: a form that
/// ends in the bytes still to come then lies in bytes the two readings share, and the search
/// of the one reading is the search of the other.
struct Reading {
    /// The reading this one is decoded from (its place among the readings) and the escapes
    /// that are decoded. `None` for the bytes as they were received.
    origin: Option<(usize, Escapes)>,
    /// True while the reading is searched for itself.
    begun: bool,
    /// The escape that waits for the bytes that follow.
    open: Vec<u8>,
    /// The last bytes of the reading, one fewer than the longest form has: a form that ends
    /// in the bytes still to come begins in them.
    tail: Vec<u8>,
    /// The bytes at the end of the reading that stand for themselves: the bytes since the
    /// last escape that was decoded.
    plain: usize,
}

impl Reading {
    fn of(origin: Option<(usize, Escapes)>) -> Reading {
        Reading {
            origin,
            begun: false,
            open: Vec::new(),
            tail: Vec::new(),
            plain: 0,
        }
    }

    /// Begins the reading with the last bytes `before` of the reading it was the same bytes
    /// as. It has room for the bytes it comes to hold: its last bytes and as many of what a
    /// step adds, both one fewer than `longest`.
    fn begin(&mut self, before: &[u8], longest: usize) {
        self.tail.clear();
        self.tail
            .reserve_exact(longest.saturating_mul(2).max(before.len()));
        self.tail.extend_from_slice(before);
        self.begun = true;
        self.plain = 0;
    }

    /// Adds to `decoded` the bytes `source` adds to this reading, where `source` is what the
    /// reading it is decoded from received: every escape becomes the bytes it stands for.
    /// With `end`, nothing follows `source`: an escape that did not end is the bytes it is.
    fn decode(&mut self, escapes: Escapes, source: &[u8], end: bool, decoded: &mut Vec<u8>) {
        let mut at = 0;
        // An escape that waited ends within the first bytes of `source`, or it is none: its
        // first byte then stands for itself, and the bytes that waited behind it are read
        // anew.
        while !self.open.is_empty() {
            let waited = self.open.len();
            let rest = source.get(at..).unwrap_or_default();
            let joined = rest.len().min(OPEN_ESCAPE_BYTES);
            self.open
                .extend_from_slice(rest.get(..joined).unwrap_or_default());
            let nothing_follows = end && joined == rest.len();
            match escapes.step(&self.open, nothing_follows) {
                // The escape holds every byte that waited for its end.
                Step::Decoded {
                    consumed,
                    decoded: stands_for,
                    length,
                } if consumed >= waited => {
                    decoded.extend(stands_for.iter().take(length));
                    self.plain = 0;
                    at += consumed - waited;
                    self.open.zeroize();
                }
                // The bytes still begin an escape, and every byte of `source` is among them.
                Step::Open if joined == rest.len() => return,
                _ => {
                    decoded.extend(self.open.first());
                    self.plain = self.plain.saturating_add(1);
                    self.open.truncate(waited);
                    self.open.drain(..1);
                }
            }
        }
        while let Some(rest) = source.get(at..).filter(|rest| !rest.is_empty()) {
            // The bytes up to the next one that can begin an escape stand for themselves.
            let plain = memchr::memchr(escapes.first_byte(), rest).unwrap_or(rest.len());
            decoded.extend_from_slice(rest.get(..plain).unwrap_or_default());
            self.plain = self.plain.saturating_add(plain);
            at += plain;
            let Some(rest) = rest.get(plain..).filter(|rest| !rest.is_empty()) else {
                break;
            };
            match escapes.step(rest, end) {
                Step::Decoded {
                    consumed,
                    decoded: stands_for,
                    length,
                } => {
                    decoded.extend(stands_for.iter().take(length));
                    self.plain = 0;
                    at += consumed.max(1);
                }
                Step::Literal => {
                    decoded.extend(rest.first());
                    self.plain = self.plain.saturating_add(1);
                    at += 1;
                }
                // The escape may end in the bytes that follow: it waits.
                Step::Open => {
                    self.open.extend_from_slice(rest);
                    return;
                }
            }
        }
    }

    /// Adds `fresh` to the reading and searches it. True when the reading holds a form that
    /// ends in `fresh`. Afterwards the reading keeps its last bytes, one fewer than the
    /// longest form has.
    fn search(&mut self, search: &Search<'_>, fresh: &[u8]) -> bool {
        let overlap = search.longest.saturating_sub(1);
        // A form that begins in the last bytes of the reading ends within as many bytes of
        // `fresh`. Every other form that ends in `fresh` lies in it whole.
        let kept = self.tail.len();
        let front = fresh.get(..overlap.min(fresh.len())).unwrap_or_default();
        self.tail.extend_from_slice(front);
        if (kept > 0 && search.in_reading(&self.tail)) || search.in_reading(fresh) {
            return true;
        }
        match fresh
            .len()
            .checked_sub(overlap)
            .and_then(|at| fresh.get(at..))
        {
            Some(last) => {
                self.tail.clear();
                self.tail.extend_from_slice(last);
            }
            // `fresh` is shorter than that: the reading keeps the end of what it has now.
            None => {
                let dropped = self.tail.len().saturating_sub(overlap);
                self.tail.drain(..dropped);
            }
        }
        false
    }

    /// Ends the search of the reading for itself when it is the same bytes as the reading it
    /// is decoded from again: no escape waits, and as many bytes as it keeps followed the
    /// last escape.
    fn rest(&mut self, longest: usize) {
        if self.origin.is_some() && self.open.is_empty() && self.plain >= longest.saturating_sub(1)
        {
            self.begun = false;
            self.tail.clear();
        }
    }
}

impl Drop for Reading {
    fn drop(&mut self) {
        self.open.zeroize();
        self.tail.zeroize();
    }
}

/// The readings of bytes a provider sent, as the search reads them step by step: the bytes
/// as they were received first, and behind them each reading that decodes the escapes of a
/// reading in front of it (the layers of each kind of escapes, each decoded from the layer
/// before it, the first from the bytes as received).
struct Readings {
    longest: usize,
    readings: Vec<Reading>,
    /// What one step adds to each reading. The buffers are kept between the steps.
    added: Vec<Vec<u8>>,
    /// For every reading, the reading whose bytes it is in this step: itself while it is
    /// searched for itself.
    same_as: Vec<usize>,
}

impl Readings {
    /// The readings of a search whose longest form has `longest` bytes.
    fn new(longest: usize) -> Readings {
        let mut received = Reading::of(None);
        received.begin(&[], longest);
        let mut readings = vec![received];
        for escapes in [Escapes::Percent, Escapes::Json] {
            let mut from = 0;
            for _ in 0..escapes.layers() {
                readings.push(Reading::of(Some((from, escapes))));
                from = readings.len() - 1;
            }
        }
        Readings {
            longest,
            added: readings.iter().map(|_| Vec::new()).collect(),
            same_as: Vec::with_capacity(readings.len()),
            readings,
        }
    }

    /// Adds `received`, at most one slice of the bytes, to every reading and searches each.
    /// True when a reading holds a form. With `end`, nothing follows `received`.
    fn add(&mut self, search: &Search<'_>, received: &[u8], end: bool) -> bool {
        self.same_as.clear();
        for index in 0..self.readings.len() {
            // A reading stands behind the reading it is decoded from, so what this step adds
            // to that one is known when its turn comes.
            let (Some((before, at)), Some((added_before, added_at))) = (
                self.readings.split_at_mut_checked(index),
                self.added.split_at_mut_checked(index),
            ) else {
                return true;
            };
            let (Some(reading), Some(added)) = (at.first_mut(), added_at.first_mut()) else {
                return true;
            };
            added.zeroize();
            let Some((from, escapes)) = reading.origin else {
                self.same_as.push(index);
                continue;
            };
            let source_of = self.same_as.get(from).copied().unwrap_or(0);
            let source = match source_of {
                0 => received,
                other => added_before
                    .get(other)
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
            };
            if !reading.begun {
                if !escapes.begin_in(source, end) {
                    self.same_as.push(source_of);
                    continue;
                }
                // The reading begins as the end of the reading it was the same bytes as, as
                // that one stood in front of these bytes.
                let last = before.get(source_of).map(|reading| reading.tail.as_slice());
                reading.begin(last.unwrap_or_default(), self.longest);
            }
            reading.decode(escapes, source, end, added);
            self.same_as.push(index);
        }
        for (index, reading) in self.readings.iter_mut().enumerate() {
            if self.same_as.get(index) != Some(&index) {
                continue;
            }
            let fresh = match index {
                0 => received,
                other => self.added.get(other).map(Vec::as_slice).unwrap_or_default(),
            };
            if reading.search(search, fresh) {
                return true;
            }
            reading.rest(self.longest);
        }
        false
    }
}

impl Drop for Readings {
    fn drop(&mut self) {
        // Decoded bytes may hold the credential: they are overwritten before they are dropped.
        for bytes in &mut self.added {
            bytes.zeroize();
        }
    }
}

/// The search of a response body that is handed on while it arrives (the stream form of
/// `forward`, enclave.md 5.8, and `vault/send`, enclave.md 5.16).
///
/// The body is read in the readings [`Forms::found_in`] makes of a whole body, each of them
/// decoded part by part ([`Reading`]) and searched together with its last bytes from the part
/// before. So a form that lies across two or more parts is found when its last byte arrives,
/// and the verdict on a body is the verdict of [`check`] on the same bytes.
///
/// The check holds the last bytes it received back and hands on the bytes in front of them
/// once a search of every reading found no form. It holds back as many received bytes as one
/// byte more than the longest form can take in a reading: [`ESCAPED_BYTE_SPAN`] bytes for
/// each of them. So when a search finds a form, no byte of it was handed on, in any reading:
/// the byte that ends a form arrived after the search before, the form begins fewer bytes in
/// front of that byte than the check holds back, and so does the one byte in front of the
/// form (in a base64 text that character holds bits of the first byte of the credential
/// beside bits of the byte before).
///
/// How far the handed on bytes lag depends on the length of the credential and on nothing
/// else: no byte is handed on sooner or later because it resembles the credential. A search
/// that held bytes back only while they begin like a form would tell its caller, by the sizes
/// of what it hands on, that the end of a part is the beginning of the credential.
///
/// The bytes held back are handed on by [`StreamCheck::end`], at the end of the body as its
/// sender ended it. A body that is cut (the connection failed, the time limit of the call
/// passed) has no such end, and its last bytes are not handed on: they may be the beginning
/// of a form the rest of the body would have completed.
///
/// The bytes the check holds are overwritten when it is dropped: they may hold the
/// credential.
pub struct StreamCheck {
    forms: Forms,
    readings: Readings,
    /// The received bytes that were not handed on yet: the bytes of `held` from `front` on.
    /// The bytes in front of `front` were handed on and are dropped once they are the larger
    /// part of the buffer.
    held: Vec<u8>,
    front: usize,
    /// The bytes at the end of `held` that no search has read yet.
    unsearched: usize,
    /// The bytes held back behind what is handed on.
    hold: usize,
    /// The bytes a search waits for.
    gather: usize,
    /// True once a search found a form: nothing more is handed on.
    withheld: bool,
}

impl StreamCheck {
    /// Begins the check of the response of a request that carried `credential` (a token
    /// without the prefix of the definition, or the value of a vault secret) with the head of
    /// that response. A response with a `Content-Encoding` other than `identity`, and a
    /// response that holds the credential in a header name or a header value, is withheld:
    /// the headers are overwritten, and no part of the response is handed on.
    pub fn begin(
        credential: &Secret<String>,
        headers: &mut Vec<(String, String)>,
    ) -> Result<StreamCheck, Withheld> {
        let forms = Forms::of(std::slice::from_ref(credential));
        if coded(headers) || forms.search().found_in_head(headers) {
            overwrite(headers);
            headers.clear();
            return Err(Withheld);
        }
        let longest = forms.longest();
        Ok(StreamCheck {
            forms,
            readings: Readings::new(longest),
            // The buffer has room for the most bytes it comes to hold, so its bytes stay at
            // one place of memory.
            held: Vec::with_capacity(Self::buffer_of(longest)),
            front: 0,
            unsearched: 0,
            hold: Self::hold_of(longest),
            gather: Self::gather_of(longest),
            withheld: false,
        })
    }

    /// The bytes a check holds back whose longest form has `longest` bytes.
    const fn hold_of(longest: usize) -> usize {
        longest.saturating_add(1).saturating_mul(ESCAPED_BYTE_SPAN)
    }

    /// The new bytes a search waits for, for a longest form of `longest` bytes:
    /// [`STREAM_GATHER_BYTES`], or four times the length of that form when that is more. A
    /// search makes its searchers ready, a work that grows with the forms, and reads the
    /// last bytes of a reading again: it waits for enough bytes to be the smaller part of
    /// both.
    const fn gather_of(longest: usize) -> usize {
        let forms = longest.saturating_mul(4);
        if forms > STREAM_GATHER_BYTES {
            forms
        } else {
            STREAM_GATHER_BYTES
        }
    }

    /// The room of the buffer of the received bytes, for a longest form of `longest` bytes:
    /// twice what is held back (the bytes that were handed on leave the buffer when they are
    /// its larger part), the bytes that wait for a search and the bytes that start one.
    const fn buffer_of(longest: usize) -> usize {
        Self::hold_of(longest)
            .saturating_mul(2)
            .saturating_add(Self::gather_of(longest).saturating_mul(2))
    }

    /// A bound of the memory the check of the response of a request holds while the body
    /// arrives, for a credential of `credential_bytes` bytes: the buffer of the received
    /// bytes, and for every reading its last bytes and what one step of a search adds to it.
    /// The longest form of a credential is its hexadecimal form, two bytes for one.
    pub const fn memory_bound(credential_bytes: usize) -> usize {
        let longest = credential_bytes.saturating_mul(2);
        // The bytes as received, and the layers of the two kinds of escapes.
        let readings = 1 + PERCENT_LAYERS + JSON_LAYERS;
        let reading = longest
            .saturating_mul(2)
            .saturating_add(slice_of(longest))
            .saturating_add(OPEN_ESCAPE_BYTES);
        Self::buffer_of(longest).saturating_add(reading.saturating_mul(readings))
    }

    /// Takes the next bytes of the body and returns the bytes that are handed on now: none
    /// until enough bytes for a search have arrived. `Err` when the body holds the
    /// credential: the bytes the check held are overwritten, and every later call fails too.
    pub fn take(&mut self, received: &[u8]) -> Result<Vec<u8>, Withheld> {
        self.advance(received, false)
    }

    /// The end of the body: returns the bytes that were still held back, after a last search.
    /// An escape that began and did not end is the bytes it is, in every reading.
    pub fn end(&mut self) -> Result<Vec<u8>, Withheld> {
        self.advance(&[], true)
    }

    /// Adds `received` to the body, searches the bytes that wait for a search once enough of
    /// them have arrived (with `end`, all of them: nothing follows), and returns the bytes
    /// that are handed on: those in front of the bytes held back (with `end`, all of them).
    fn advance(&mut self, received: &[u8], end: bool) -> Result<Vec<u8>, Withheld> {
        if self.withheld {
            return Err(Withheld);
        }
        // The searchers are made ready once for the searches of this call, when it comes to
        // one: a call that only adds bytes to the ones that wait makes none.
        let mut searchers: Option<Search<'_>> = None;
        let mut handed_on = Vec::new();
        let mut found = false;
        for bytes in received.chunks(self.gather) {
            self.held.extend_from_slice(bytes);
            self.unsearched = self.unsearched.saturating_add(bytes.len());
            if self.unsearched < self.gather {
                continue;
            }
            let search = searchers.get_or_insert_with(|| self.forms.search());
            found = Self::search(
                search,
                &mut self.readings,
                &self.held,
                self.unsearched,
                false,
            );
            if found {
                break;
            }
            self.unsearched = 0;
            Self::hand_on(&mut self.held, &mut self.front, self.hold, &mut handed_on);
        }
        if end && !found {
            let search = searchers.get_or_insert_with(|| self.forms.search());
            found = Self::search(
                search,
                &mut self.readings,
                &self.held,
                self.unsearched,
                true,
            );
            self.unsearched = 0;
            Self::hand_on(&mut self.held, &mut self.front, 0, &mut handed_on);
        }
        if found {
            // What the check held, and what this call was about to hand on, may hold the
            // credential: it is overwritten, and nothing more is handed on.
            self.withheld = true;
            self.held.zeroize();
            self.front = 0;
            handed_on.zeroize();
            return Err(Withheld);
        }
        Ok(handed_on)
    }

    /// Moves the bytes of `held` from `front` on, but the last `kept` of them, to
    /// `handed_on`.
    fn hand_on(held: &mut Vec<u8>, front: &mut usize, kept: usize, handed_on: &mut Vec<u8>) {
        let until = held.len().saturating_sub(kept).max(*front);
        handed_on.extend_from_slice(held.get(*front..until).unwrap_or_default());
        *front = until;
        // The bytes that were handed on leave the buffer once they are the larger part of
        // it: a buffer is moved as often as it halves, not with every part.
        if *front >= held.len() - *front {
            held.drain(..*front);
            *front = 0;
        }
    }

    /// Searches the last `unsearched` bytes of `held`, which no search has read yet, in every
    /// reading. With `end`, nothing follows them. True when a reading holds a form.
    fn search(
        search: &Search<'_>,
        readings: &mut Readings,
        held: &[u8],
        unsearched: usize,
        end: bool,
    ) -> bool {
        let fresh_at = held.len().saturating_sub(unsearched);
        let received = held.get(fresh_at..).unwrap_or_default();
        received
            .chunks(slice_of(search.longest))
            .any(|slice| readings.add(search, slice, false))
            || (end && readings.add(search, &[], true))
    }
}

impl Drop for StreamCheck {
    fn drop(&mut self) {
        self.held.zeroize();
    }
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
    }

    /// A generator of bytes a test can repeat: xorshift64.
    struct Noise(u64);

    impl Noise {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next() % bound as u64) as usize
        }

        /// [`Noise::bytes`] of a length below `bound`.
        fn some(&mut self, bound: usize) -> Vec<u8> {
            let length = self.below(bound);
            self.bytes(length)
        }

        /// Bytes that hold `%`, backslashes, hexadecimal digits and other characters, so
        /// that parts of them read as escapes.
        fn bytes(&mut self, length: usize) -> Vec<u8> {
            const ALPHABET: &[u8] =
                b"%%25 2541abcdefABCDEF0123456789{}\":,xyzXYZ_-./=+\\\\uuunrt00d";
            (0..length)
                .map(|_| ALPHABET[self.below(ALPHABET.len())])
                .collect()
        }
    }

    /// `bytes` under one layer of percent escapes, each byte escaped or not as `noise` says.
    fn escaped(bytes: &[u8], noise: &mut Noise, every: bool) -> Vec<u8> {
        let mut out = Vec::new();
        for byte in bytes {
            if every || *byte == b'%' || noise.below(3) == 0 {
                let digits = match noise.below(2) {
                    0 => format!("%{byte:02X}"),
                    _ => format!("%{byte:02x}"),
                };
                out.extend_from_slice(digits.as_bytes());
            } else {
                out.push(*byte);
            }
        }
        out
    }

    /// Hands `body` to a stream check in parts whose lengths `noise` chooses, and returns the
    /// bytes that were handed on and whether the body passed.
    fn streamed(body: &[u8], noise: &mut Noise, longest_part: usize) -> (Vec<u8>, bool) {
        let mut headers = Vec::new();
        let mut check = StreamCheck::begin(&credential(), &mut headers).unwrap();
        let mut handed_on = Vec::new();
        let mut at = 0;
        while at < body.len() {
            let end = (at + 1 + noise.below(longest_part)).min(body.len());
            match check.take(&body[at..end]) {
                Ok(bytes) => handed_on.extend_from_slice(&bytes),
                Err(Withheld) => {
                    assert_eq!(check.take(b"more"), Err(Withheld));
                    assert_eq!(check.end(), Err(Withheld));
                    return (handed_on, false);
                }
            }
            at = end;
        }
        match check.end() {
            Ok(bytes) => {
                handed_on.extend_from_slice(&bytes);
                (handed_on, true)
            }
            Err(Withheld) => (handed_on, false),
        }
    }

    #[test]
    fn a_stream_without_the_credential_is_handed_on_whole_whatever_its_parts() {
        let mut noise = Noise(0x9e37_79b9_7f4a_7c15);
        for round in 0..40 {
            let body = noise.some(400_000);
            assert!(!Forms::of(&[credential()]).found_in(&body));
            let longest_part = [1, 7, 4_096, 70_000, 300_000][round % 5];
            let (handed_on, passed) = streamed(&body, &mut noise, longest_part);
            assert!(passed, "round {round}");
            assert_eq!(handed_on, body, "round {round}");
        }
        // A body of no byte, and a body shorter than what the check holds back.
        assert_eq!(streamed(b"", &mut noise, 5), (Vec::new(), true));
        assert_eq!(streamed(b"short", &mut noise, 2), (b"short".to_vec(), true));
    }

    #[test]
    fn a_stream_is_cut_in_front_of_the_credential_in_every_form_and_at_every_place() {
        let mut noise = Noise(0x2545_f491_4f6c_dd1d);
        let token = TOKEN.as_bytes();
        let forms: Vec<Vec<u8>> = vec![
            token.to_vec(),
            STANDARD_NO_PAD.encode(token).into_bytes(),
            URL_SAFE_NO_PAD.encode([b"ab", token].concat()).into_bytes(),
            hex(token, b"0123456789abcdef"),
            hex(token, b"0123456789ABCDEF"),
        ];
        for round in 0..480 {
            let form = &forms[round % forms.len()];
            // The form as it is, under one, two or three layers of percent escapes, or under
            // one or two layers of the escapes of a JSON string. Some rounds escape every
            // byte in each of their layers: the longest a form can be written.
            let json = round % 3 == 0;
            let layers = match json {
                true => round % 4 % (JSON_LAYERS + 1),
                false => round % 4,
            };
            let every = round % 8 >= 6;
            let mut reflected = form.clone();
            for _ in 0..layers {
                reflected = match json {
                    true => json_escaped(&reflected, &mut noise, every),
                    false => escaped(&reflected, &mut noise, every),
                };
            }
            if every {
                let span = match json {
                    true => 6usize.pow(layers as u32),
                    false => 3usize.pow(layers as u32),
                };
                assert_eq!(reflected.len(), form.len() * span);
                assert!(span <= ESCAPED_BYTE_SPAN);
            }
            // The form stands between two quotes: the bytes in front of it then end no
            // escape inside it.
            let mut front = noise.some(250_000);
            front.push(b'"');
            let mut back = vec![b'"'];
            back.extend(noise.some(250_000));
            let body = [front.as_slice(), reflected.as_slice(), back.as_slice()].concat();
            // The verdict of the check of a whole response.
            assert_eq!(outcome(&[], &body), Err(Withheld), "round {round}");
            let longest_part = [1, 13, 1_024, 65_536, 400_000][round % 5];
            let (handed_on, passed) = streamed(&body, &mut noise, longest_part);
            assert!(!passed, "round {round}: layers {layers}");
            // What was handed on is a front part of the body that ends in front of the
            // form: no byte of the form left.
            assert!(
                handed_on.len() <= front.len(),
                "round {round}: layers {layers}"
            );
            assert_eq!(handed_on, body[..handed_on.len()], "round {round}");
        }
    }

    #[test]
    fn a_stream_and_a_whole_response_have_the_same_verdict() {
        let mut noise = Noise(0x0123_4567_89ab_cdef);
        let token = TOKEN.as_bytes();
        for round in 0..200 {
            // Bodies that hold the credential whole, a part of it, or the credential with a
            // byte changed, under escapes that begin and end at any byte.
            let mut body = noise.some(150_000);
            let mut piece = match round % 4 {
                0 => token.to_vec(),
                1 => token[..token.len() - 1].to_vec(),
                2 => {
                    let mut changed = token.to_vec();
                    changed[round % token.len()] ^= 1;
                    changed
                }
                _ => hex(token, b"0123456789abcdef"),
            };
            for _ in 0..(round % 3) {
                piece = match round % 5 < 2 {
                    true => json_escaped(&piece, &mut noise, false),
                    false => escaped(&piece, &mut noise, false),
                };
            }
            body.extend_from_slice(&piece);
            body.extend(noise.some(150_000));
            let whole = outcome(&[], &body).is_ok();
            let longest_part = [3, 500, 20_000, 200_000][round % 4];
            let (handed_on, passed) = streamed(&body, &mut noise, longest_part);
            assert_eq!(passed, whole, "round {round}");
            if passed {
                assert_eq!(handed_on, body, "round {round}");
            }
        }
    }

    #[test]
    fn a_stream_holds_back_what_the_longest_form_can_take_and_hands_on_the_rest() {
        let mut headers = Vec::new();
        let mut check = StreamCheck::begin(&credential(), &mut headers).unwrap();
        // The longest form of the token is its hexadecimal form.
        let longest = 2 * TOKEN.len();
        let hold = (longest + 1) * ESCAPED_BYTE_SPAN;
        let gather = STREAM_GATHER_BYTES;
        assert!(4 * longest < gather && hold < gather);
        // Nothing leaves before enough bytes for a search have arrived.
        assert_eq!(
            check.take(&vec![b'a'; gather - 1]).unwrap(),
            Vec::<u8>::new()
        );
        // With the next byte the search runs, and everything in front of the bytes held back
        // is handed on.
        assert_eq!(check.take(b"a").unwrap(), vec![b'a'; gather - hold]);
        // The bytes are held back whatever they are: the beginning of the credential leaves
        // as late as any other bytes.
        let begun = &TOKEN.as_bytes()[..TOKEN.len() - 1];
        let mut likeness = vec![b'c'; gather - begun.len()];
        likeness.extend_from_slice(begun);
        assert_eq!(check.take(&likeness).unwrap().len(), gather);
        // The end hands on the rest.
        assert_eq!(check.end().unwrap().len(), hold);
    }

    #[test]
    fn a_stream_with_the_credential_in_its_head_or_a_coded_body_does_not_begin() {
        for (name, value) in [
            ("x-echo", TOKEN),
            ("content-encoding", "gzip"),
            ("Content-Encoding", "br"),
        ] {
            let mut headers = vec![
                ("content-type".to_string(), "text/plain".to_string()),
                (name.to_string(), value.to_string()),
            ];
            assert!(StreamCheck::begin(&credential(), &mut headers).is_err());
            // The headers that are withheld are gone.
            assert!(headers.is_empty());
        }
        let mut headers = vec![("content-encoding".to_string(), "identity".to_string())];
        assert!(StreamCheck::begin(&credential(), &mut headers).is_ok());
        assert_eq!(headers.len(), 1);
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

    /// `bytes` with one layer of escapes decoded, `None` when they hold no escape.
    fn decoded(escapes: Escapes, bytes: &[u8]) -> Option<Vec<u8>> {
        let mut decoded = Vec::new();
        Reading::of(Some((0, escapes))).decode(escapes, bytes, true, &mut decoded);
        escapes.begin_in(bytes, true).then_some(decoded)
    }

    /// Decodes one layer of escapes of `bytes`. False when they hold no escape.
    fn decode_in_place(escapes: Escapes, bytes: &mut Vec<u8>) -> bool {
        match decoded(escapes, bytes) {
            Some(layer) => {
                *bytes = layer;
                true
            }
            None => false,
        }
    }

    /// The escape of a JSON string for one code unit: a backslash, `u` and four hexadecimal
    /// digits.
    fn unit_escape(unit: u16, upper: bool) -> String {
        match upper {
            true => format!("{}u{unit:04X}", '\\'),
            false => format!("{}u{unit:04x}", '\\'),
        }
    }

    /// `bytes` (ASCII) under one layer of the escapes of a JSON string. A backslash and a
    /// quote are escaped, as a writer of JSON has to, a `/` as some writers do, and every
    /// other byte as the escape of its code unit or not as `noise` says. With `every`, each
    /// byte is the escape of its code unit: the longest way to write it.
    fn json_escaped(bytes: &[u8], noise: &mut Noise, every: bool) -> Vec<u8> {
        let mut out = Vec::new();
        for byte in bytes {
            match byte {
                _ if every => {
                    let escape = unit_escape(u16::from(*byte), noise.below(2) == 0);
                    out.extend_from_slice(escape.as_bytes());
                }
                b'\\' | b'"' => out.extend_from_slice(&[b'\\', *byte]),
                b'/' if noise.below(2) == 0 => out.extend_from_slice(b"\\/"),
                _ if noise.below(3) == 0 => {
                    let escape = unit_escape(u16::from(*byte), noise.below(2) == 0);
                    out.extend_from_slice(escape.as_bytes());
                }
                _ => out.push(*byte),
            }
        }
        out
    }

    #[test]
    fn the_escapes_of_a_json_string_are_decoded_once_per_layer() {
        let json = |text: &str| decoded(Escapes::Json, text.as_bytes());
        assert_eq!(json("plain text, 100% and %2F"), None);
        // A backslash that begins no escape of a JSON string stays as it is.
        let no_escape = format!("a{0}x, {0}u12, {0}u12g4, {0}", '\\');
        assert_eq!(json(&no_escape), None);
        // The escapes of two characters.
        let short = format!("{0}{0} {0}/ {0}{1} {0}b{0}f{0}n{0}r{0}t", '\\', '"');
        assert_eq!(json(&short), Some(b"\\ / \" \x08\x0c\n\r\t".to_vec()));
        // The escape of a code unit, in either case of its digits, and two of them for a
        // character outside the basic plane.
        let units = [
            unit_escape(0x3d, false),
            unit_escape(0x2f, true),
            unit_escape(0xd55c, false),
            unit_escape(0xd83d, true),
            unit_escape(0xde00, false),
        ]
        .concat();
        let expected = ['=', '/', '\u{d55c}', '\u{1f600}']
            .iter()
            .collect::<String>();
        assert_eq!(json(&units), Some(expected.into_bytes()));
        // Half of such a character without its other half is the bytes it is.
        let half = format!(
            "{}x{}",
            unit_escape(0xd83d, false),
            unit_escape(0xde00, false)
        );
        assert_eq!(json(&half), None);

        // A credential a writer of JSON wrote, with `/` as an escape of two characters and
        // `=` as the escape of its code unit.
        let written = format!(
            "ya29.a0Af{0}/Token+With{1}Symbols_1234567890",
            '\\',
            unit_escape(0x3d, false)
        );
        assert_eq!(json(&written), Some(TOKEN.as_bytes().to_vec()));
        // A JSON text inside a JSON string: each layer is decoded once, and a third layer is
        // not decoded.
        let layer = |text: &str| text.replace('\\', "\\\\").replace('"', "\\\"");
        let twice = layer(&written);
        let thrice = layer(&twice);
        assert_eq!(json(&twice), Some(written.clone().into_bytes()));
        assert_eq!(outcome(&[], written.as_bytes()), Err(Withheld));
        assert_eq!(outcome(&[], twice.as_bytes()), Err(Withheld));
        assert_eq!(outcome(&[], thrice.as_bytes()), Ok(()));
        assert_eq!(JSON_LAYERS, 2);
    }

    #[test]
    fn a_credential_under_the_escapes_of_a_json_string_is_withheld_in_every_form() {
        let token = TOKEN.as_bytes();
        let mut noise = Noise(0x6a09_e667_f3bc_c908);
        let embed = |form: &[u8]| {
            let mut body = b"{\"echo\":\"prefix ".to_vec();
            body.extend_from_slice(form);
            body.extend_from_slice(b" suffix\"}");
            body
        };
        let padded = base64::engine::general_purpose::STANDARD.encode([b"x", token].concat());
        let forms: Vec<Vec<u8>> = vec![
            token.to_vec(),
            padded.into_bytes(),
            URL_SAFE_NO_PAD.encode(token).into_bytes(),
            hex(token, b"0123456789abcdef"),
        ];
        for form in &forms {
            for every in [false, true] {
                let once = json_escaped(form, &mut noise, every);
                let twice = json_escaped(&once, &mut noise, every);
                if every {
                    assert_eq!(twice.len(), form.len() * ESCAPED_BYTE_SPAN);
                }
                for written in [&once, &twice] {
                    assert_eq!(outcome(&[], &embed(written)), Err(Withheld));
                    let text = String::from_utf8(written.clone()).unwrap();
                    assert_eq!(outcome(&[("x-echo", &text)], b""), Err(Withheld));
                }
            }
        }
        // A body with escapes of a JSON string and without the credential passes.
        let other = format!("{{\"a\":\"b{0}/c{0}n{1}\"}}", '\\', unit_escape(0x3d, true));
        assert_eq!(outcome(&[], other.as_bytes()), Ok(()));
    }

    #[test]
    fn a_credential_in_a_header_that_is_not_utf8_is_found_in_the_bytes_of_the_header() {
        // A credential with characters outside ASCII, in a header whose bytes are not UTF-8.
        // The node hands such a header on with one character for each byte, and the
        // credential stands in that text as other characters than its own.
        let credential = Secret::new("p\u{e4}ss-\u{d55c}\u{ae00}-w\u{f6}rd".to_string());
        let mut sent = b"echo=".to_vec();
        sent.extend_from_slice(credential.expose_secret().as_bytes());
        sent.push(0xff);
        assert!(std::str::from_utf8(&sent).is_err());
        let handed_on: String = sent.iter().map(|byte| char::from(*byte)).collect();
        assert!(!handed_on.contains(credential.expose_secret().as_str()));
        let forms = Forms::of(std::slice::from_ref(&credential));
        assert!(!forms.found_in(handed_on.as_bytes()));
        assert!(forms.found_in_header(&handed_on));
        let headers = vec![("x-echo".to_string(), handed_on.clone())];
        assert!(check(&credential, 200, headers.clone(), Vec::new()).is_err());
        let mut headers = headers;
        assert!(StreamCheck::begin(&credential, &mut headers).is_err());
        // A text with a character above U+00FF is no such reading of bytes.
        let other = format!("{handed_on}\u{d55c}");
        assert!(!forms.found_in_header(&other));
    }

    #[test]
    fn a_run_of_backslashes_in_front_of_the_credential_does_not_hide_it_from_a_stream() {
        // A credential that begins with the letter of an escape of two characters (`r`), as
        // a writer of JSON wrote it. Behind an odd number of backslashes, a reading that
        // began at another byte than the first one of the body would take the last backslash
        // and the `r` for an escape. The readings of a stream begin at the first byte of the
        // body, whatever its parts.
        let credential = Secret::new("rk_live_abc/def+ghi=0123456789".to_string());
        let written = format!(
            "rk_live_abc{0}/def+ghi{1}0123456789",
            '\\',
            unit_escape(0x3d, false)
        );
        let forms = Forms::of(std::slice::from_ref(&credential));
        for pairs in [0usize, 1, 2, 3, 40, 41, 4_000, 4_001] {
            let mut body = b"{\"echo\":\"".to_vec();
            body.extend(std::iter::repeat_n(b'\\', 2 * pairs));
            let front = body.len();
            body.extend_from_slice(written.as_bytes());
            body.extend_from_slice(b"\"}");
            assert!(forms.found_in(&body), "{pairs}");
            for part in [1usize, 2, 3, 7, 64, 1_000, 100_000] {
                let mut headers = Vec::new();
                let mut check = StreamCheck::begin(&credential, &mut headers).unwrap();
                let mut handed_on = Vec::new();
                let mut withheld = false;
                for bytes in body.chunks(part) {
                    match check.take(bytes) {
                        Ok(bytes) => handed_on.extend_from_slice(&bytes),
                        Err(Withheld) => {
                            withheld = true;
                            break;
                        }
                    }
                }
                if !withheld {
                    withheld = check.end().is_err();
                }
                assert!(withheld, "{pairs} pairs in parts of {part}");
                assert!(handed_on.len() <= front, "{pairs} pairs in parts of {part}");
                assert_eq!(handed_on, body[..handed_on.len()]);
            }
        }
    }

    #[test]
    fn a_stream_holds_a_bounded_number_of_bytes_whatever_the_parts_of_the_body() {
        let mut noise = Noise(0xbb67_ae85_84ca_a73b);
        let mut headers = Vec::new();
        let mut check = StreamCheck::begin(&credential(), &mut headers).unwrap();
        let longest = 2 * TOKEN.len();
        let room = check.held.capacity();
        assert_eq!(room, StreamCheck::buffer_of(longest));
        let mut held = 0;
        let mut rested = false;
        for round in 0..90 {
            // Parts of a few bytes, parts far above what one search waits for, and parts
            // without an escape, behind which every reading is the bytes as received again.
            let part = match round % 4 {
                0 => noise.some(40),
                1 => noise.some(3_000),
                2 => noise.some(300_000),
                _ => vec![b'x'; 2 * STREAM_GATHER_BYTES],
            };
            let handed_on = check.take(&part).unwrap();
            held = held + part.len() - handed_on.len();
            // What is not handed on is what the check holds back and what waits for a
            // search, and the buffers stay where they are.
            assert!(held < StreamCheck::hold_of(longest) + StreamCheck::gather_of(longest));
            assert_eq!(check.held.capacity(), room);
            let readings = &check.readings.readings;
            rested |= round % 4 == 3 && readings.iter().skip(1).all(|reading| !reading.begun);
            for reading in readings.iter().filter(|reading| reading.begun) {
                assert!(reading.tail.len() < longest);
                assert!(reading.tail.capacity() <= 2 * longest);
                assert!(reading.open.len() < OPEN_ESCAPE_BYTES);
            }
            for added in &check.readings.added {
                assert!(added.capacity() <= 2 * (slice_of(longest) + OPEN_ESCAPE_BYTES));
            }
        }
        assert!(rested);
        assert_eq!(check.end().unwrap().len(), held);
        // The bound a call reserves for the check of a vault value of the longest length and
        // of a value of a common length.
        assert!(StreamCheck::memory_bound(12_000) < 3 * 1024 * 1024);
        assert!(StreamCheck::memory_bound(200) < 64 * 1024);
    }

    #[test]
    fn percent_escapes_are_decoded_once_per_layer() {
        assert_eq!(decoded(Escapes::Percent, b"plain text"), None);
        assert_eq!(decoded(Escapes::Percent, b"100% and %zz and %4"), None);
        assert_eq!(
            decoded(Escapes::Percent, b"a%2Fb%2fc%41"),
            Some(b"a/b/cA".to_vec())
        );
        assert_eq!(
            decoded(Escapes::Percent, b"%25%32%46"),
            Some(b"%2F".to_vec())
        );
        assert_eq!(
            decoded(Escapes::Percent, b"%00%ff%FF"),
            Some(vec![0x00, 0xff, 0xff])
        );
        assert_eq!(
            decoded(Escapes::Percent, b"50%25, %zz"),
            Some(b"50%, %zz".to_vec())
        );
        // Each further layer is decoded inside the copy of the first one.
        let mut layers = b"%252525zz%252541".to_vec();
        assert!(decode_in_place(Escapes::Percent, &mut layers));
        assert_eq!(layers, b"%2525zz%2541");
        assert!(decode_in_place(Escapes::Percent, &mut layers));
        assert_eq!(layers, b"%25zz%41");
        assert!(decode_in_place(Escapes::Percent, &mut layers));
        assert_eq!(layers, b"%zzA");
        assert!(!decode_in_place(Escapes::Percent, &mut layers));
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
        let mut once = decoded(Escapes::Percent, &layered).unwrap();
        assert_eq!(outcome(&[], &once), Err(Withheld));
        for _ in 1..PERCENT_LAYERS {
            once = decoded(Escapes::Percent, &once).unwrap();
        }
        assert_eq!(decoded(Escapes::Percent, &once), Some(token.to_vec()));
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
