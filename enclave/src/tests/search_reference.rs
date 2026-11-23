//! The search of rule E4 (egress-policy.md) against a plain reference.
//!
//! The search of a node reads a body step by step: it decodes each of its readings part by
//! part, keeps the last bytes of a reading between two steps, and searches a reading that
//! decodes escapes only around an escape. A stream check hands bytes on while it reads. The
//! reference of this module does none of that: it decodes a whole body in each of the eight
//! readings and searches every form of the credential in each of them.
//!
//! The two give the same verdict on every body, whatever the parts a body arrives in, and a
//! stream hands on no byte of a form the reference finds, nor the byte in front of it.

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use credential_enclave_protocol::secret::Secret;

use crate::provider_response::{Forms, StreamCheck};

/// A sequence of numbers that is the same in every run.
struct Sequence(u64);

impl Sequence {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }

    fn one_in(&mut self, of: usize) -> bool {
        self.below(of) == 0
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

fn holds(bytes: &[u8], form: &[u8]) -> bool {
    bytes.windows(form.len()).any(|window| window == form)
}

/// The base64 characters the bytes alone decide when `front` bytes stand in front of them in
/// their group of three.
fn base64_inside(url_safe: bool, bytes: &[u8], front: usize) -> Vec<u8> {
    let mut value = vec![0u8; front];
    value.extend_from_slice(bytes);
    let text = match url_safe {
        true => URL_SAFE_NO_PAD.encode(&value),
        false => STANDARD_NO_PAD.encode(&value),
    }
    .into_bytes();
    let shared_front = [0, 2, 3][front];
    let shared_behind = usize::from(!value.len().is_multiple_of(3));
    text[shared_front..text.len() - shared_behind].to_vec()
}

fn hex(bytes: &[u8], upper: bool) -> Vec<u8> {
    let text: String = bytes
        .iter()
        .map(|byte| match upper {
            true => format!("{byte:02X}"),
            false => format!("{byte:02x}"),
        })
        .collect();
    text.into_bytes()
}

/// The forms of a credential the search looks for: as it is, base64 and base64url at each
/// byte alignment, hexadecimal in both cases, for a credential with a space the credential
/// with `+` for every space, and for a credential with a character outside ASCII the text a
/// reader of ISO 8859-1 makes of its bytes.
fn forms_of(credential: &[u8]) -> Vec<Vec<u8>> {
    let mut forms = vec![credential.to_vec()];
    for front in 0..3 {
        forms.push(base64_inside(false, credential, front));
        forms.push(base64_inside(true, credential, front));
    }
    forms.push(hex(credential, false));
    forms.push(hex(credential, true));
    if credential.contains(&b' ') {
        let text = String::from_utf8(credential.to_vec()).unwrap();
        forms.push(text.replace(' ', "+").into_bytes());
    }
    if !credential.is_ascii() {
        let misread: String = credential.iter().map(|byte| char::from(*byte)).collect();
        forms.push(misread.into_bytes());
    }
    forms.retain(|form| form.len() >= 8);
    forms
}

fn digit(byte: Option<&u8>) -> Option<u32> {
    byte.and_then(|byte| char::from(*byte).to_digit(16))
}

/// The bytes with every `%` and two hexadecimal digits replaced by the byte they name.
fn percent_decoded(bytes: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match (
            bytes[at],
            digit(bytes.get(at + 1)),
            digit(bytes.get(at + 2)),
        ) {
            (b'%', Some(high), Some(low)) => {
                decoded.push((high * 16 + low) as u8);
                at += 3;
            }
            (byte, _, _) => {
                decoded.push(byte);
                at += 1;
            }
        }
    }
    decoded
}

/// The code unit of a `\uXXXX` escape at `at`.
fn code_unit(bytes: &[u8], at: usize) -> Option<u32> {
    if bytes.get(at..at + 2)? != b"\\u" {
        return None;
    }
    (2..6).try_fold(0, |value, offset| {
        Some(value * 16 + digit(bytes.get(at + offset))?)
    })
}

/// The bytes with every escape of a JSON string replaced by the bytes it stands for.
fn json_decoded(bytes: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    let character = |code: u32, decoded: &mut Vec<u8>| match char::from_u32(code) {
        Some(character) => {
            decoded.extend_from_slice(character.encode_utf8(&mut [0u8; 4]).as_bytes());
            true
        }
        None => false,
    };
    while at < bytes.len() {
        let simple = match (bytes[at], bytes.get(at + 1)) {
            (b'\\', Some(b'"')) => Some(b'"'),
            (b'\\', Some(b'\\')) => Some(b'\\'),
            (b'\\', Some(b'/')) => Some(b'/'),
            (b'\\', Some(b'b')) => Some(0x08),
            (b'\\', Some(b'f')) => Some(0x0c),
            (b'\\', Some(b'n')) => Some(b'\n'),
            (b'\\', Some(b'r')) => Some(b'\r'),
            (b'\\', Some(b't')) => Some(b'\t'),
            _ => None,
        };
        if let Some(byte) = simple {
            decoded.push(byte);
            at += 2;
            continue;
        }
        match (code_unit(bytes, at), code_unit(bytes, at + 6)) {
            (Some(high @ 0xd800..=0xdbff), Some(low @ 0xdc00..=0xdfff)) => {
                character(
                    0x1_0000 + ((high - 0xd800) << 10) + (low - 0xdc00),
                    &mut decoded,
                );
                at += 12;
            }
            (Some(unit), _) if character(unit, &mut decoded) => at += 6,
            _ => {
                decoded.push(bytes[at]);
                at += 1;
            }
        }
    }
    decoded
}

/// The character the character reference at the beginning of `rest` stands for, and the
/// length of that reference: one of the five names, or the number of a character, in decimal
/// with at most seven digits or in hexadecimal with at most six, in no more than six bytes
/// for each byte of the UTF-8 form of that character.
fn character_reference(rest: &[u8]) -> Option<(char, usize)> {
    let names = [
        ("&amp;", '&'),
        ("&lt;", '<'),
        ("&gt;", '>'),
        ("&quot;", '"'),
        ("&apos;", '\''),
    ];
    for (name, character) in names {
        if rest.starts_with(name.as_bytes()) {
            return Some((character, name.len()));
        }
    }
    // The longest reference is ten bytes: its `;` is among the first ten.
    let end = rest.iter().take(10).position(|byte| *byte == b';')?;
    let text = std::str::from_utf8(&rest[..end]).ok()?;
    let hexadecimal = text
        .strip_prefix("&#x")
        .or_else(|| text.strip_prefix("&#X"));
    let (digits, radix, most) = match hexadecimal {
        Some(digits) => (digits, 16, 6),
        None => (text.strip_prefix("&#")?, 10, 7),
    };
    let of_the_radix = digits.chars().all(|digit| digit.is_digit(radix));
    if digits.is_empty() || digits.len() > most || !of_the_radix {
        return None;
    }
    let character = char::from_u32(u32::from_str_radix(digits, radix).ok()?)?;
    let length = end + 1;
    (length <= 6 * character.len_utf8()).then_some((character, length))
}

/// The bytes with every character reference replaced by the UTF-8 bytes of its character.
fn reference_decoded(bytes: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match character_reference(&bytes[at..]) {
            Some((character, length)) => {
                decoded.extend_from_slice(character.encode_utf8(&mut [0u8; 4]).as_bytes());
                at += length;
            }
            None => {
                decoded.push(bytes[at]);
                at += 1;
            }
        }
    }
    decoded
}

/// The eight readings of `body`: as it is, with its percent escapes decoded once, twice and
/// three times, with its JSON string escapes decoded once and twice, and with its character
/// references decoded once and twice.
fn readings_of(body: &[u8]) -> Vec<Vec<u8>> {
    let mut readings = vec![body.to_vec()];
    let mut reading = body.to_vec();
    for _ in 0..3 {
        reading = percent_decoded(&reading);
        readings.push(reading.clone());
    }
    reading = body.to_vec();
    for _ in 0..2 {
        reading = json_decoded(&reading);
        readings.push(reading.clone());
    }
    reading = body.to_vec();
    for _ in 0..2 {
        reading = reference_decoded(&reading);
        readings.push(reading.clone());
    }
    readings
}

/// True when one of the eight readings of `body` holds one of `forms`.
fn found_by_the_reference(forms: &[Vec<u8>], body: &[u8]) -> bool {
    readings_of(body)
        .iter()
        .any(|reading| forms.iter().any(|form| holds(reading, form)))
}

/// True when `body` holds one of `forms` in a reading that decodes character references and
/// in none of the six other readings.
fn found_under_references_alone(forms: &[Vec<u8>], body: &[u8]) -> bool {
    let readings = readings_of(body);
    let held = |reading: &Vec<u8>| forms.iter().any(|form| holds(reading, form));
    !readings[..6].iter().any(held) && readings[6..].iter().any(held)
}

/// `bytes` percent-encoded: every byte outside the unreserved ones, and of the others one in
/// `of`.
fn percent_encoded(numbers: &mut Sequence, bytes: &[u8], of: usize) -> Vec<u8> {
    let mut encoded = Vec::new();
    for byte in bytes {
        let unreserved = byte.is_ascii_alphanumeric() || b"-._~".contains(byte);
        match (unreserved && !numbers.one_in(of), numbers.one_in(2)) {
            (true, _) => encoded.push(*byte),
            (false, true) => encoded.extend_from_slice(format!("%{byte:02X}").as_bytes()),
            (false, false) => encoded.extend_from_slice(format!("%{byte:02x}").as_bytes()),
        }
    }
    encoded
}

/// `text` as the content of a JSON string: `"`, `\` and the control characters escaped, and
/// of the other characters one in `of`.
fn json_escaped(numbers: &mut Sequence, text: &[u8], of: usize) -> Vec<u8> {
    let text = String::from_utf8(text.to_vec()).unwrap();
    let mut escaped = String::new();
    for character in text.chars() {
        let short = match character {
            '"' => Some("\\\""),
            '\\' => Some("\\\\"),
            '/' => Some("\\/"),
            '\u{8}' => Some("\\b"),
            '\u{c}' => Some("\\f"),
            '\n' => Some("\\n"),
            '\r' => Some("\\r"),
            '\t' => Some("\\t"),
            _ => None,
        };
        let must = matches!(character, '"' | '\\') || character.is_control();
        if !must && !numbers.one_in(of) {
            escaped.push(character);
            continue;
        }
        match short.filter(|_| numbers.one_in(2)) {
            Some(short) => escaped.push_str(short),
            None => {
                for unit in character.encode_utf16(&mut [0u16; 2]) {
                    match numbers.one_in(2) {
                        true => escaped.push_str(&format!("\\u{unit:04X}")),
                        false => escaped.push_str(&format!("\\u{unit:04x}")),
                    }
                }
            }
        }
    }
    escaped.into_bytes()
}

/// `text` as a writer of HTML or XML writes it: `&`, `<`, `>`, `"` and `'` as a reference, by
/// name or by number, and of the other characters one in `of` as a numeric reference. A number
/// is in decimal or in hexadecimal, and most are written without a leading zero. One in
/// eight has leading zeros up to a number of digits around the most the search decodes: some
/// of those are references the search leaves as they are.
fn reference_escaped(numbers: &mut Sequence, text: &[u8], of: usize) -> Vec<u8> {
    let text = String::from_utf8(text.to_vec()).unwrap();
    let mut escaped = String::new();
    for character in text.chars() {
        let name = match character {
            '&' => Some("&amp;"),
            '<' => Some("&lt;"),
            '>' => Some("&gt;"),
            '"' => Some("&quot;"),
            '\'' => Some("&apos;"),
            _ => None,
        };
        if name.is_none() && !numbers.one_in(of) {
            escaped.push(character);
            continue;
        }
        if let Some(name) = name.filter(|_| numbers.one_in(2)) {
            escaped.push_str(name);
            continue;
        }
        let code = u32::from(character);
        let width = match numbers.one_in(8) {
            true => *numbers.pick(&[2usize, 3, 4, 5, 6, 7, 8]),
            false => 0,
        };
        let reference = match numbers.below(4) {
            0 | 1 => format!("&#{code:0width$};"),
            2 => format!("&#x{code:0width$x};"),
            _ => format!("&#{}{code:0width$X};", numbers.pick(&['x', 'X'])),
        };
        escaped.push_str(&reference);
    }
    escaped.into_bytes()
}

/// A credential of 8 bytes or more: letters and digits, with the symbols of a token, with
/// characters that are escapes themselves, with characters outside ASCII, or with texts that
/// are character references or begin one.
fn credential(numbers: &mut Sequence) -> String {
    let plain: Vec<char> = ('a'..='z').chain('A'..='Z').chain('0'..='9').collect();
    let symbols: Vec<char> = "/+=._-~".chars().collect();
    let hostile: Vec<char> = "\"\\%&<> \n\tu0b:;'".chars().collect();
    let wide: Vec<char> = "\u{d55c}\u{ae00}\u{e9}\u{1f600}\u{10000}\u{7ff}\u{800}"
        .chars()
        .collect();
    let references = [
        "&amp;", "&lt;", "&#39;", "&#x2F;", "&", "&#", "#", ";", "&am", "&#x",
    ];
    let kind = numbers.below(5);
    loop {
        let mut text = String::new();
        for _ in 0..3 + numbers.below(30) {
            let other = match kind {
                1 => Some(&symbols),
                2 => Some(&hostile),
                3 => Some(&wide),
                _ => None,
            };
            match other.filter(|_| numbers.one_in(3)) {
                Some(set) => text.push(*numbers.pick(set)),
                None if kind == 4 && numbers.one_in(4) => text.push_str(numbers.pick(&references)),
                None => text.push(*numbers.pick(&plain)),
            }
        }
        // No white space at the ends: the tests of the calls fix how the search reads a
        // credential that has some.
        if text.len() >= 8 && text.trim() == text {
            return text;
        }
    }
}

/// Bytes that hold no form on purpose: text, the beginnings of escapes of every kind, runs of
/// the three characters an escape begins with, character references with a number of digits
/// around the most the search decodes, bytes outside UTF-8, and parts of the forms.
fn filler(numbers: &mut Sequence, length: usize, forms: &[Vec<u8>]) -> Vec<u8> {
    let common = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEF{}:,\"' \n-_/+=&#;";
    let references: [&[u8]; 36] = [
        b"&",
        b"&#",
        b"&#x",
        b"&#X",
        b"&a",
        b"&am",
        b"&amp",
        b"&quo",
        b"&apos",
        b"&#3",
        b"&#x2",
        b"&#0000039",
        b"&#x00002F",
        b"&amp;",
        b"&#38;",
        b"&#x26;",
        b"&amp;#",
        b"&amp;amp;",
        b"&#38;#38;",
        b"&lt;",
        b"&nbsp;",
        b"&AMP;",
        b"&#065;",
        b"&#0065;",
        b"&#x41;",
        b"&#x041;",
        b"&#0000233;",
        b"&#00000233;",
        b"&#x0000e9;",
        b"&#x00000e9;",
        b"&#1114111;",
        b"&#1114112;",
        b"&#x10FFFF;",
        b"&#x110000;",
        b"&#xD800;",
        b"&#;",
    ];
    let pieces: [&[u8]; 9] = [
        b"%25",
        b"%2525",
        b"\\u00",
        b"\\ud83d",
        b"\\ud83d\\ude00",
        b"\\u005c",
        b"\\\\u00",
        b"%5c%75",
        b"\\u",
    ];
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        match numbers.below(46) {
            0 => bytes.extend(std::iter::repeat_n(b'\\', 1 + numbers.below(9))),
            1 => bytes.extend(std::iter::repeat_n(b'%', 1 + numbers.below(5))),
            2..=5 => bytes.extend_from_slice(numbers.pick(&pieces)),
            40 => bytes.extend(std::iter::repeat_n(b'&', 1 + numbers.below(7))),
            41..=45 => bytes.extend_from_slice(numbers.pick(&references)),
            6 => bytes.push(0x80 + numbers.below(0x80) as u8),
            7 => {
                let form = numbers.pick(forms);
                let cut = 1 + numbers.below(form.len() - 1);
                match numbers.one_in(2) {
                    true => bytes.extend_from_slice(&form[..cut]),
                    false => bytes.extend_from_slice(&form[cut..]),
                }
                // A part of a form does not run on into the bytes behind it.
                bytes.push(b' ');
            }
            _ => bytes.push(*numbers.pick(common)),
        }
    }
    bytes
}

/// A body with up to three encoded forms in it, and the place of the first one the reference
/// finds when it stands alone.
fn body(numbers: &mut Sequence, forms: &[Vec<u8>]) -> (Vec<u8>, Option<usize>) {
    let lengths = [0usize, 5, 40, 300, 2_000, 4_096, 6_000, 12_000];
    let mut bytes = Vec::new();
    let mut first = None;
    let lead = *numbers.pick(&lengths) + numbers.below(64);
    bytes.extend(filler(numbers, lead, forms));
    for _ in 0..numbers.below(4) {
        let mut encoded = numbers.pick(forms).clone();
        let of = 1 + numbers.below(10);
        match numbers.below(12) {
            0 => {}
            1..=3 => {
                // One layer more than the search decodes, at the most.
                for _ in 0..1 + numbers.below(4) {
                    encoded = percent_encoded(numbers, &encoded, of);
                }
            }
            4..=6 => {
                for _ in 0..1 + numbers.below(3) {
                    encoded = json_escaped(numbers, &encoded, of);
                }
            }
            7..=9 => {
                for _ in 0..1 + numbers.below(3) {
                    encoded = reference_escaped(numbers, &encoded, of);
                }
            }
            _ => {
                // Escapes of two kinds one over the other: no reading decodes both.
                let first = numbers.below(3);
                let second = (first + 1 + numbers.below(2)) % 3;
                for kind in [first, second] {
                    encoded = match kind {
                        0 => percent_encoded(numbers, &encoded, of),
                        1 => json_escaped(numbers, &encoded, of),
                        _ => reference_escaped(numbers, &encoded, of),
                    };
                }
            }
        }
        // A byte that ends every escape in front of the form and behind it.
        bytes.push(b' ');
        if first.is_none() && found_by_the_reference(forms, &encoded) {
            first = Some(bytes.len());
        }
        bytes.extend_from_slice(&encoded);
        bytes.push(b' ');
        let gap = *numbers.pick(&lengths) + numbers.below(64);
        bytes.extend(filler(numbers, gap, forms));
    }
    (bytes, first)
}

/// The body in parts: of one length for the whole body, or of mixed lengths.
fn parts<'a>(numbers: &mut Sequence, body: &'a [u8]) -> Vec<&'a [u8]> {
    let longest = [3usize, 64, 2_000, 10_000];
    let style = numbers.below(longest.len() + 1);
    let mut parts = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let length = match longest.get(style) {
            Some(longest) => 1 + numbers.below(*longest),
            None => *numbers.pick(&[1usize, 16, 4_096, 9_000]),
        };
        let (part, behind) = rest.split_at(length.min(rest.len()));
        parts.push(part);
        rest = behind;
    }
    parts
}

/// What a stream check hands on of a body that arrives in `parts`, and whether it withheld
/// the body.
fn streamed(credential: &Secret<String>, parts: &[&[u8]]) -> (Vec<u8>, bool) {
    let Ok(mut check) = StreamCheck::begin(credential, &mut Vec::new()) else {
        panic!("a head without a header holds no credential");
    };
    let mut handed_on = Vec::new();
    for part in parts {
        match check.take(part) {
            Ok(bytes) => handed_on.extend(bytes),
            Err(_) => return (handed_on, true),
        }
    }
    match check.end() {
        Ok(bytes) => {
            handed_on.extend(bytes);
            (handed_on, false)
        }
        Err(_) => (handed_on, true),
    }
}

/// What a comparison counted: the bodies that hold a form, those of them of which a part was
/// handed on before the cut, and those that hold a form under character references alone.
#[derive(Debug, Default)]
struct Counts {
    found: usize,
    cut_behind_a_part: usize,
    under_references_alone: usize,
}

/// Compares the search with the plain reference on `rounds` bodies, those of the sequence of
/// numbers that begins with `seed`: the verdict on the whole body, the verdict on the body as
/// a stream, and what the stream handed on.
fn compare(seed: u64, rounds: usize) -> Counts {
    let mut numbers = Sequence(seed);
    let mut counts = Counts::default();
    for round in 0..rounds {
        let text = credential(&mut numbers);
        let forms = forms_of(text.as_bytes());
        let (body, first) = body(&mut numbers, &forms);
        let expected = found_by_the_reference(&forms, &body);
        let secret = Secret::new(text.clone());
        let case = format!("seed {seed:#x}, round {round}: {text:?}");

        // The search of a whole body.
        let whole = Forms::of(std::slice::from_ref(&secret)).found_in(&body);
        assert_eq!(whole, expected, "{case}");

        // The search of the same body as a stream.
        let (handed_on, withheld) = streamed(&secret, &parts(&mut numbers, &body));
        assert_eq!(withheld, expected, "{case}");
        assert!(body.starts_with(&handed_on), "{case}");
        if !withheld {
            assert_eq!(handed_on.len(), body.len(), "{case}");
            continue;
        }
        // Of a body that holds a form, no form was handed on, and neither was the first
        // form the body holds nor the byte in front of it.
        assert!(!found_by_the_reference(&forms, &handed_on), "{case}");
        if let Some(first) = first {
            assert!(handed_on.len() < first, "{case}");
        }
        counts.found += 1;
        counts.cut_behind_a_part += usize::from(!handed_on.is_empty());
        counts.under_references_alone += usize::from(found_under_references_alone(&forms, &body));
    }
    counts
}

#[test]
fn the_search_gives_the_verdict_of_a_plain_search_of_every_reading() {
    let counts = compare(0x9E37_79B9_7F4A_7C15, 600);
    // The bodies of this test are of both kinds. Of the ones that hold a form many are cut
    // after a part of them was handed on, and some hold it under character references alone.
    assert!((250..550).contains(&counts.found), "{counts:?}");
    assert!(counts.cut_behind_a_part > 60, "{counts:?}");
    assert!(counts.under_references_alone > 10, "{counts:?}");
}

/// The comparison of the test above for other sequences of bodies than its one. Run it with
/// `SEARCH_REFERENCE_SEEDS=1,2545F4914F6CDD1D cargo test --release -p credential-enclave --
/// --ignored --nocapture the_search_gives_that_verdict_on_the_bodies_of_other_seeds`.
#[test]
#[ignore = "the comparison with the plain reference for the seeds of an environment variable"]
#[expect(
    clippy::print_stdout,
    reason = "The opt-in comparison prints the counts of the bodies of each seed"
)]
fn the_search_gives_that_verdict_on_the_bodies_of_other_seeds() {
    // `SEARCH_REFERENCE_SEEDS` holds the seeds, numbers above 0 in hexadecimal, separated by
    // commas. `SEARCH_REFERENCE_ROUNDS` is the number of bodies of each seed, 4,000 when it
    // is not set.
    let seeds = std::env::var("SEARCH_REFERENCE_SEEDS").unwrap_or_default();
    let rounds = std::env::var("SEARCH_REFERENCE_ROUNDS")
        .map(|rounds| rounds.parse().unwrap())
        .unwrap_or(4_000);
    for seed in seeds.split(',').filter(|seed| !seed.is_empty()) {
        let seed = u64::from_str_radix(seed.trim().trim_start_matches("0x"), 16).unwrap();
        assert_ne!(seed, 0);
        let counts = compare(seed, rounds);
        println!("seed {seed:#018x}: {rounds} bodies, {counts:?}");
    }
}

/// `form` with its byte at `at` written as an escape: a percent escape (`kind` 0 and 1, upper
/// and lower case), a `\u` escape (`kind` 2) or a character reference (`kind` 3), and for every
/// further layer the first character of that escape written as an escape again.
fn with_one_escape(form: &[u8], at: usize, kind: usize, layers: usize) -> Vec<u8> {
    let byte = form[at];
    let mut escape = match kind {
        0 => format!("%{byte:02X}"),
        1 => format!("%{byte:02x}"),
        2 => format!("\\u{byte:04x}"),
        _ => format!("&#x{byte:02X};"),
    };
    for _ in 1..layers {
        escape = match kind {
            0 | 1 => escape.replace('%', "%25"),
            2 => escape.replace('\\', "\\\\"),
            _ => escape.replace('&', "&amp;"),
        };
    }
    [&form[..at], escape.as_bytes(), &form[at + 1..]].concat()
}

#[test]
fn a_form_with_one_escape_is_found_wherever_a_step_of_the_search_ends() {
    // A reading that decodes escapes is searched for itself from an escape on, until as many
    // bytes as a form can have followed it. So the place of an escape inside a form, and the
    // place of the form relative to the steps of the search, decide which reading finds it:
    // every form with one escaped byte, at every place relative to a step of 1,024 bytes (the
    // step of a search) and of 4,096 bytes (what a stream check gathers before it searches).
    let text = "Zx9-credential_0123";
    let forms = forms_of(text.as_bytes());
    let secret = Secret::new(text.to_string());
    let search = Forms::of(std::slice::from_ref(&secret));
    // The credential as it is (the shortest form), one of its base64 forms, and its
    // hexadecimal form (the longest one, whose length the search keeps its last bytes by).
    let (shortest, longest) = (forms[0].clone(), forms[forms.len() - 2].clone());
    assert_eq!(
        (shortest.len(), longest.len()),
        (text.len(), 2 * text.len())
    );
    for form in [&shortest, &forms[3], &longest] {
        for at in [0, 1, form.len() / 2, form.len() - 1] {
            for (kind, layers) in [(0, 1), (1, 3), (2, 1), (2, 2), (3, 1), (3, 2)] {
                let encoded = with_one_escape(form, at, kind, layers);
                assert!(found_by_the_reference(&forms, &encoded));
                for step in [1_024usize, 4_096] {
                    for back in 0..encoded.len() + 2 {
                        let lead = step - back;
                        let mut body = vec![b'x'; lead];
                        body.extend_from_slice(&encoded);
                        body.extend_from_slice(&[b'y'; 100]);
                        let case = format!("{form:?} {at} {kind} {layers} at {lead}");
                        assert!(search.found_in(&body), "{case}");
                        // Parts that end where a stream check searches, and one part.
                        for part in [64usize, 100_000] {
                            let parts: Vec<&[u8]> = body.chunks(part).collect();
                            let (handed_on, withheld) = streamed(&secret, &parts);
                            assert!(withheld, "{case}, parts of {part}");
                            assert!(handed_on.len() < lead, "{case}, parts of {part}");
                        }
                    }
                }
            }
        }
    }
}
