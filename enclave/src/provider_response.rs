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
//! on only as a [`CheckedResponse`], which only [`check`] creates. It refuses:
//!
//! - a response with a `Content-Encoding` other than `identity`. The node asked for `identity`
//!   and cannot search a body it does not decode;
//! - a response that holds the injected credential in a header name, a header value or the
//!   body.

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
    while read < bytes.len() {
        match escape_at(bytes, read) {
            Some(byte) => {
                bytes[write] = byte;
                read += 3;
            }
            None => {
                bytes[write] = bytes[read];
                read += 1;
            }
        }
        write += 1;
    }
    bytes[write..].zeroize();
    bytes.truncate(write);
}

fn hex(bytes: &[u8], digits: &[u8; 16]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(digits[usize::from(byte >> 4)]);
        encoded.push(digits[usize::from(byte & 0x0f)]);
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
