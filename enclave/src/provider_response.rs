//! The search for a credential in what a provider sent, before any of it leaves the node (rule
//! E4 of the egress policy, `docs/egress-policy.md`).
//!
//! A provider is assumed to follow its public API contract: an API does not send the token of
//! its caller back, and a token response holds its tokens at the places the definition names.
//! This module is the defense for a response that breaks that assumption.
//!
//! [`Forms`] is the search. Bytes are read as they were received and with their percent
//! escapes decoded (up to [`PERCENT_LAYERS`] times, for a value that was encoded more than
//! once), and each reading is searched for these forms of the credential: as it is, base64 or
//! base64url in each of the three byte alignments and without padding, hexadecimal in lower or
//! upper case. Decoding the escapes finds the credential under every percent-encoding of it:
//! encoders do not agree on the bytes they escape or on the case of the digits, and all of
//! their outputs decode to the same bytes. A form shorter than [`SHORTEST_FORM_BYTES`] is not
//! searched for: it would match unrelated data. The tokens of the defined providers are longer
//! than that in every form.
//!
//! The search has two users. The public fields of a token response are searched for the tokens
//! of that response (`OauthPlaintext::public_fields`). And the response of `forward` is handed
//! on only as a [`CheckedResponse`], which only [`check`] creates, or as the head and the
//! parts a [`StreamCheck`] gives out. Both refuse:
//!
//! - a response with a `Content-Encoding` other than `identity`. The node asked for `identity`
//!   and cannot search a body it does not decode;
//! - a response that holds the injected credential in a header name, a header value or the
//!   body.
//!
//! [`check`] reads a whole response and hands on all of it or nothing. [`StreamCheck`] reads a
//! body while it arrives and hands on the bytes in front of the last ones it holds back, so a
//! body of any length is searched in a bounded memory. Its verdict on a body is the verdict of
//! [`check`] on the same bytes, and no byte of a form it finds is handed on: the body is cut
//! in front of it.

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
        || headers.iter().any(|(name, value)| {
            forms.found_in(name.as_bytes()) || forms.found_in(value.as_bytes())
        });
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

/// The most bytes one byte of a form can take in what a provider sent: a percent escape is
/// three bytes for one, and each of the three can be an escape of the layer above it, for
/// [`PERCENT_LAYERS`] layers.
pub const ESCAPED_BYTE_SPAN: usize = 27;

/// The bytes at the front of a part of a body that the search can read in another way than it
/// reads them inside the whole body: a part can begin inside an escape, and the bytes of that
/// escape are then read as they are, in each of the [`PERCENT_LAYERS`] layers (2 bytes of the
/// first layer, 6 of the second, 18 of the third).
const UNALIGNED_FRONT_BYTES: usize = 32;

/// The fewest bytes a [`StreamCheck`] gathers before it searches them. A body arrives in
/// parts of a few kilobytes, and one search of the bytes held back and a part reads the bytes
/// held back again: gathering keeps the bytes a search reads below twice the bytes of the
/// body.
const STREAM_STEP_BYTES: usize = 64 * 1024;

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

    /// The length of the longest form in bytes, 0 when there is none.
    fn longest(&self) -> usize {
        self.0
            .iter()
            .map(|form| form.expose_secret().len())
            .max()
            .unwrap_or(0)
    }

    /// True when `received` hold one of the forms, as received or under percent escapes.
    pub fn found_in(&self, received: &[u8]) -> bool {
        let found = |bytes: &[u8]| {
            self.0
                .iter()
                .any(|form| memmem::find(bytes, form.expose_secret()).is_some())
        };
        if found(received) {
            return true;
        }
        // Each layer of escapes is decoded and searched. There is one decoded copy, and each
        // further layer is decoded inside it. The copy may hold the credential: it is
        // overwritten before it is dropped.
        let Some(mut decoded) = percent_decoded(received) else {
            return false;
        };
        let mut layer = 1;
        let reflected = loop {
            if found(&decoded) {
                break true;
            }
            if layer == PERCENT_LAYERS || !decode_in_place(&mut decoded) {
                break false;
            }
            layer += 1;
        };
        decoded.zeroize();
        reflected
    }
}

/// The search of a response body that is handed on while it arrives (the stream form of
/// `forward`, enclave.md 5.8).
///
/// The check holds the last bytes it received back and hands on the bytes in front of them
/// once a search of everything it holds found no form. It holds back as many bytes as the
/// longest form can take under [`PERCENT_LAYERS`] layers of escapes
/// ([`ESCAPED_BYTE_SPAN`] bytes for each of its bytes), and [`UNALIGNED_FRONT_BYTES`] more.
/// So:
///
/// - a form that ends in a byte still to come begins inside the bytes held back: none of its
///   bytes was handed on when the search that reads its end finds it;
/// - every form lies whole in the bytes of one search, behind the front of those bytes that
///   can be read in another way than inside the whole body, or in a search that began at the
///   first byte of the body. The verdict on a body is the verdict of [`check`] on the same
///   bytes.
///
/// The bytes the check holds are overwritten when it is dropped: they may hold the
/// credential.
pub struct StreamCheck {
    forms: Forms,
    /// The bytes received and not handed on yet.
    held: Vec<u8>,
    /// The bytes of `held` that no search has read yet.
    unsearched: usize,
    /// The bytes held back behind what is handed on.
    hold: usize,
    /// The unsearched bytes that start a search.
    step: usize,
    /// True once a search found a form: nothing more is handed on.
    withheld: bool,
}

impl StreamCheck {
    /// Begins the check of the response of a request that carried `credential` (the token
    /// without the prefix of the definition) with the head of that response. A response with a
    /// `Content-Encoding` other than `identity`, and a response that holds the credential in a
    /// header name or a header value, is withheld: the headers are overwritten, and no part of
    /// the response is handed on.
    pub fn begin(
        credential: &Secret<String>,
        headers: &mut Vec<(String, String)>,
    ) -> Result<StreamCheck, Withheld> {
        let encoded = headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-encoding")
                && !value.trim().eq_ignore_ascii_case("identity")
        });
        let forms = Forms::of(std::slice::from_ref(credential));
        let reflected = headers.iter().any(|(name, value)| {
            forms.found_in(name.as_bytes()) || forms.found_in(value.as_bytes())
        });
        if encoded || reflected {
            for (name, value) in headers.iter_mut() {
                name.zeroize();
                value.zeroize();
            }
            headers.clear();
            return Err(Withheld);
        }
        let hold = forms
            .longest()
            .saturating_mul(ESCAPED_BYTE_SPAN)
            .saturating_add(UNALIGNED_FRONT_BYTES);
        Ok(StreamCheck {
            forms,
            held: Vec::new(),
            unsearched: 0,
            hold,
            step: hold.max(STREAM_STEP_BYTES),
            withheld: false,
        })
    }

    /// Takes the next bytes of the body and returns the bytes that are handed on now: none
    /// until enough bytes for a search have arrived. `Err` when the body holds the
    /// credential: the bytes the check held are overwritten, and every later call fails too.
    pub fn take(&mut self, received: &[u8]) -> Result<Vec<u8>, Withheld> {
        if self.withheld {
            return Err(Withheld);
        }
        self.held.extend_from_slice(received);
        self.unsearched = self.unsearched.saturating_add(received.len());
        if self.unsearched < self.step {
            return Ok(Vec::new());
        }
        self.search()?;
        let handed_on = self.held.len().saturating_sub(self.hold);
        let rest = self.held.split_off(handed_on);
        Ok(std::mem::replace(&mut self.held, rest))
    }

    /// The end of the body: returns the bytes that were still held back, after a last search.
    pub fn end(&mut self) -> Result<Vec<u8>, Withheld> {
        if self.withheld {
            return Err(Withheld);
        }
        self.search()?;
        Ok(std::mem::take(&mut self.held))
    }

    /// Searches everything the check holds.
    fn search(&mut self) -> Result<(), Withheld> {
        self.unsearched = 0;
        if self.forms.found_in(&self.held) {
            self.withheld = true;
            self.held.zeroize();
            return Err(Withheld);
        }
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
        let (byte, taken) = match escape_at(bytes, read) {
            Some(byte) => (byte, 3),
            None => (literal, 1),
        };
        // The place that is written lies at or in front of the place that was read.
        if let Some(place) = bytes.get_mut(write) {
            *place = byte;
        }
        read += taken;
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

        /// Bytes that hold `%`, hexadecimal digits and other characters, so that parts of
        /// them read as escapes.
        fn bytes(&mut self, length: usize) -> Vec<u8> {
            const ALPHABET: &[u8] = b"%%25 2541abcdefABCDEF0123456789{}\":,xyzXYZ_-./=+";
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
        for round in 0..300 {
            let form = &forms[round % forms.len()];
            // The form as it is, or under one, two or three layers of escapes. Every eighth
            // round escapes every byte in each of its three layers: the longest form a
            // search has to hold.
            let layers = round % 4;
            let mut reflected = form.clone();
            for _ in 0..layers {
                reflected = escaped(&reflected, &mut noise, round % 8 == 7);
            }
            if round % 8 == 7 {
                assert_eq!(reflected.len(), form.len() * ESCAPED_BYTE_SPAN);
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
                piece = escaped(&piece, &mut noise, false);
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
        let hold = 2 * TOKEN.len() * ESCAPED_BYTE_SPAN + UNALIGNED_FRONT_BYTES;
        // Nothing leaves before enough bytes for a search have arrived.
        let first = vec![b'a'; STREAM_STEP_BYTES - 1];
        assert_eq!(check.take(&first).unwrap(), Vec::<u8>::new());
        // With the next byte the search runs, and everything in front of the bytes held back
        // is handed on.
        let handed_on = check.take(b"a").unwrap();
        assert_eq!(handed_on.len(), STREAM_STEP_BYTES - hold);
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
