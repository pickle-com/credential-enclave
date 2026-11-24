//! The certificate of a release proof (protocol.md section 9): one element of DER, an X.509
//! certificate as far as the verification of a release proof reads it, and the ECDSA
//! signature of one certificate over another.
//!
//! The reader takes a certificate in one form and refuses every other: an element of DER has
//! a tag of one byte and its shortest length form, the parts of a certificate stand in their
//! order with their tags, and a certificate holds an extension once. What it returns is the
//! bytes of each part as they are encoded. Two certificates are compared by those bytes: the
//! issuer name of one is the subject name of the other when the two encodings are equal.
//!
//! The secure program of the app reads a certificate by the same rules (`readCertificate` of
//! `secure-program/secure-program.js`), and the cases of `protocol/vectors/release-proofs.json`
//! hold both readers to the same verdicts.

use ring::signature::{
    UnparsedPublicKey, VerificationAlgorithm, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA384_ASN1,
    ECDSA_P384_SHA256_ASN1, ECDSA_P384_SHA384_ASN1,
};

/// The tag of a SEQUENCE.
const SEQUENCE: u8 = 0x30;
/// The tag of an INTEGER.
const INTEGER: u8 = 0x02;
/// The tag of a BIT STRING.
const BIT_STRING: u8 = 0x03;
/// The tag of an OCTET STRING.
const OCTET_STRING: u8 = 0x04;
/// The tag of an OBJECT IDENTIFIER.
const OBJECT_IDENTIFIER: u8 = 0x06;
/// The tag of a BOOLEAN.
const BOOLEAN: u8 = 0x01;
/// The tag of a UTF8String.
const UTF8_STRING: u8 = 0x0c;
/// The tag of a UTCTime.
const UTC_TIME: u8 = 0x17;
/// The tag of a GeneralizedTime.
const GENERALIZED_TIME: u8 = 0x18;
/// The tag of the version of a certificate: `[0]`, constructed.
const VERSION: u8 = 0xa0;
/// The tags of the two unique identifiers of a certificate: `[1]` and `[2]`, primitive.
const UNIQUE_IDENTIFIERS: [u8; 2] = [0x81, 0x82];
/// The tag of the extensions of a certificate: `[3]`, constructed.
const EXTENSIONS: u8 = 0xa3;

/// The content bytes of the object identifier of the basic constraints, 2.5.29.19.
const BASIC_CONSTRAINTS: [u8; 3] = [0x55, 0x1d, 0x13];
/// The content bytes of the object identifier 1.3.6.1.4.1.57264.1, the arc of the extensions
/// in which Fulcio states the identity a certificate was issued for. The number of an
/// extension follows them as one byte.
const FULCIO_ARC: [u8; 9] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbf, 0x30, 0x01];
/// The content bytes of the object identifier ecdsa-with-SHA256, 1.2.840.10045.4.3.2.
const ECDSA_WITH_SHA256: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// The content bytes of the object identifier ecdsa-with-SHA384, 1.2.840.10045.4.3.3.
const ECDSA_WITH_SHA384: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];

/// The first 26 bytes of the SubjectPublicKeyInfo (DER) of an ECDSA P-256 public key: the
/// algorithm `id-ecPublicKey` with the curve `prime256v1` and the header of the bit string.
/// The 65 bytes of the uncompressed point follow them.
pub(crate) const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
/// The first 23 bytes of the SubjectPublicKeyInfo (DER) of an ECDSA P-384 public key: the
/// algorithm `id-ecPublicKey` with the curve `secp384r1` and the header of the bit string.
/// The 97 bytes of the uncompressed point follow them.
const P384_SPKI_PREFIX: [u8; 23] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
];

/// One element of DER: its tag, the bytes of the whole element and the bytes of its content.
#[derive(Clone, Copy)]
struct Element<'a> {
    tag: u8,
    whole: &'a [u8],
    content: &'a [u8],
}

/// The element of DER at the start of `bytes`, and the bytes after it. `None` for bytes that
/// do not start with one element: a tag of more than one byte, a length that is not in its
/// shortest form or takes more than four bytes, an element that runs past the end.
fn element(bytes: &[u8]) -> Option<(Element<'_>, &[u8])> {
    let (tag, after_tag) = bytes.split_first()?;
    let (first, after_first) = after_tag.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (length, after_length) = if *first < 0x80 {
        (usize::from(*first), after_first)
    } else {
        let count = usize::from(first & 0x7f);
        if !(1..=4).contains(&count) {
            return None;
        }
        let (digits, after_digits) = after_first.split_at_checked(count)?;
        if digits.first() == Some(&0) {
            return None;
        }
        let length = digits.iter().try_fold(0usize, |length, digit| {
            length.checked_mul(256)?.checked_add(usize::from(*digit))
        })?;
        if length < 0x80 {
            return None;
        }
        (length, after_digits)
    };
    let (content, rest) = after_length.split_at_checked(length)?;
    let whole = bytes.get(..bytes.len().checked_sub(rest.len())?)?;
    Some((
        Element {
            tag: *tag,
            whole,
            content,
        },
        rest,
    ))
}

/// The elements of DER that fill `bytes`, in order. `None` when the bytes are not such
/// elements one after another.
fn elements(mut bytes: &[u8]) -> Option<Vec<Element<'_>>> {
    let mut found = Vec::new();
    while !bytes.is_empty() {
        let (next, rest) = element(bytes)?;
        found.push(next);
        bytes = rest;
    }
    Some(found)
}

/// The one element of DER that is all of `bytes`.
fn only(bytes: &[u8]) -> Option<Element<'_>> {
    match element(bytes)? {
        (found, []) => Some(found),
        _ => None,
    }
}

/// The value of `count` decimal digits of `text` from `start`.
fn digits(text: &[u8], start: usize, count: usize) -> Option<i64> {
    text.get(start..start.checked_add(count)?)?
        .iter()
        .try_fold(0i64, |value, digit| {
            digit
                .is_ascii_digit()
                .then(|| value * 10 + i64::from(digit - b'0'))
        })
}

/// The days of a month of the Gregorian calendar.
fn days_of(year: i64, month: i64) -> i64 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 31,
    }
}

/// The seconds since 1970-01-01T00:00:00Z that a UTCTime or a GeneralizedTime of a
/// certificate states (`YYMMDDHHMMSSZ` or `YYYYMMDDHHMMSSZ`: a two-digit year below 50 is of
/// the century 2000, the others of 1900). `None` for an element of another form, for a year
/// before 1950 and for a day no calendar has.
fn time(stated: &Element<'_>) -> Option<i64> {
    let wide = match stated.tag {
        UTC_TIME => 2,
        GENERALIZED_TIME => 4,
        _ => return None,
    };
    let text = stated.content;
    if text.len() != wide + 11 || text.last() != Some(&b'Z') {
        return None;
    }
    let mut year = digits(text, 0, wide)?;
    if wide == 2 {
        year += if year < 50 { 2000 } else { 1900 };
    }
    let month = digits(text, wide, 2)?;
    let day = digits(text, wide + 2, 2)?;
    let hour = digits(text, wide + 4, 2)?;
    let minute = digits(text, wide + 6, 2)?;
    let second = digits(text, wide + 8, 2)?;
    if year < 1950
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_of(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    // The days from 1970-01-01 to the day, by the count of the days of the 400-year cycle of
    // the calendar, with the year taken to begin in March.
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = shifted.div_euclid(400);
    let year_of_era = shifted.rem_euclid(400);
    let month_of_year = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_of_year + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// The curve of an ECDSA public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Curve {
    P256,
    P384,
}

/// The hash of an ECDSA signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hash {
    Sha256,
    Sha384,
}

/// The curve and the uncompressed point of an ECDSA public key given as the DER of its
/// SubjectPublicKeyInfo: a key on P-256 (91 bytes) or on P-384 (120 bytes) in the one form of
/// each. `None` for every other input.
fn ec_key(spki: &[u8]) -> Option<(Curve, &[u8])> {
    let forms: [(Curve, &[u8], usize); 2] = [
        (Curve::P256, &P256_SPKI_PREFIX, 65),
        (Curve::P384, &P384_SPKI_PREFIX, 97),
    ];
    forms.into_iter().find_map(|(curve, prefix, point_bytes)| {
        spki.strip_prefix(prefix)
            .filter(|point| point.len() == point_bytes && point.first() == Some(&0x04))
            .map(|point| (curve, point))
    })
}

/// True when `signature` (ASN.1 DER: two non-negative integers without unneeded bytes) is the
/// ECDSA signature of the key `spki` over `message` with the hash `hash`. The key is one of
/// the form [`ec_key`] reads. With `curve`, the key is on that curve as well.
pub(crate) fn ecdsa_verifies(
    spki: &[u8],
    curve: Option<Curve>,
    hash: Hash,
    message: &[u8],
    signature: &[u8],
) -> bool {
    let Some((of_key, point)) = ec_key(spki) else {
        return false;
    };
    if curve.is_some_and(|curve| curve != of_key) {
        return false;
    }
    let algorithm: &dyn VerificationAlgorithm = match (of_key, hash) {
        (Curve::P256, Hash::Sha256) => &ECDSA_P256_SHA256_ASN1,
        (Curve::P256, Hash::Sha384) => &ECDSA_P256_SHA384_ASN1,
        (Curve::P384, Hash::Sha256) => &ECDSA_P384_SHA256_ASN1,
        (Curve::P384, Hash::Sha384) => &ECDSA_P384_SHA384_ASN1,
    };
    UnparsedPublicKey::new(algorithm, point)
        .verify(message, signature)
        .is_ok()
}

/// An X.509 certificate, as far as the verification of a release proof reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// The signed part (TBSCertificate), as it is encoded.
    signed: Vec<u8>,
    /// The content bytes of the object identifier of the signature algorithm.
    algorithm: Vec<u8>,
    /// The signature value.
    signature: Vec<u8>,
    /// The issuer name, as it is encoded.
    issuer: Vec<u8>,
    /// The subject name, as it is encoded.
    subject: Vec<u8>,
    /// The start of the validity, in seconds since 1970.
    not_before: i64,
    /// The end of the validity, in seconds since 1970.
    not_after: i64,
    /// The SubjectPublicKeyInfo, as it is encoded.
    key: Vec<u8>,
    /// The extensions: the content bytes of the object identifier of each, and its value.
    extensions: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Certificate {
    /// Reads a certificate from its DER. `None` for bytes that are not one certificate of the
    /// form below, and for bytes behind it:
    ///
    /// - the certificate is a SEQUENCE of the signed part (a SEQUENCE), the signature
    ///   algorithm (a SEQUENCE that begins with an object identifier) and the signature (a
    ///   BIT STRING without unused bits);
    /// - the signed part holds, after a version `[0]` it may begin with: the serial number
    ///   (an INTEGER), the signature algorithm, the issuer name, the validity, the subject
    ///   name and the SubjectPublicKeyInfo (five SEQUENCEs). The signature algorithm of the
    ///   signed part is, as encoded, the one of the certificate. The validity is two times
    ///   (UTCTime or GeneralizedTime);
    /// - what follows is a unique identifier (`[1]`, `[2]`), which is not read, or the
    ///   extensions (`[3]`): one SEQUENCE of extensions, each a SEQUENCE of an object
    ///   identifier, an optional BOOLEAN and an OCTET STRING. No object identifier occurs
    ///   twice.
    pub fn read(der: &[u8]) -> Option<Certificate> {
        let outer = only(der).filter(|outer| outer.tag == SEQUENCE)?;
        let [signed, algorithm, signature] =
            <[Element<'_>; 3]>::try_from(elements(outer.content)?).ok()?;
        if signed.tag != SEQUENCE || algorithm.tag != SEQUENCE || signature.tag != BIT_STRING {
            return None;
        }
        let (unused_bits, signature_value) = signature.content.split_first()?;
        if *unused_bits != 0 {
            return None;
        }
        let identifier = elements(algorithm.content)?
            .first()
            .copied()
            .filter(|identifier| identifier.tag == OBJECT_IDENTIFIER)?;

        let fields = elements(signed.content)?;
        let mut fields = fields.iter().peekable();
        fields.next_if(|field| field.tag == VERSION);
        let mut part = |tag: u8| fields.next().filter(|field| field.tag == tag).copied();
        part(INTEGER)?;
        let inner_algorithm = part(SEQUENCE)?;
        let issuer = part(SEQUENCE)?;
        let validity = part(SEQUENCE)?;
        let subject = part(SEQUENCE)?;
        let key = part(SEQUENCE)?;
        if inner_algorithm.whole != algorithm.whole {
            return None;
        }
        let [not_before, not_after] =
            <[Element<'_>; 2]>::try_from(elements(validity.content)?).ok()?;

        let mut extensions: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for field in fields {
            if UNIQUE_IDENTIFIERS.contains(&field.tag) {
                continue;
            }
            if field.tag != EXTENSIONS {
                return None;
            }
            let list = only(field.content).filter(|list| list.tag == SEQUENCE)?;
            for extension in elements(list.content)? {
                if extension.tag != SEQUENCE {
                    return None;
                }
                let inner = elements(extension.content)?;
                let (identifier, value) = match inner.as_slice() {
                    [identifier, value] => (identifier, value),
                    [identifier, critical, value] if critical.tag == BOOLEAN => (identifier, value),
                    _ => return None,
                };
                if identifier.tag != OBJECT_IDENTIFIER || value.tag != OCTET_STRING {
                    return None;
                }
                if extensions
                    .iter()
                    .any(|(known, _)| known == identifier.content)
                {
                    return None;
                }
                extensions.push((identifier.content.to_vec(), value.content.to_vec()));
            }
        }
        Some(Certificate {
            signed: signed.whole.to_vec(),
            algorithm: identifier.content.to_vec(),
            signature: signature_value.to_vec(),
            issuer: issuer.whole.to_vec(),
            subject: subject.whole.to_vec(),
            not_before: time(&not_before)?,
            not_after: time(&not_after)?,
            key: key.whole.to_vec(),
            extensions,
        })
    }

    /// The value of the extension whose object identifier has the content bytes `identifier`.
    fn extension(&self, identifier: &[u8]) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(known, _)| known == identifier)
            .map(|(_, value)| value.as_slice())
    }

    /// True when the certificate is valid at `time_s`, in seconds since 1970: the time is
    /// neither before the start of its validity nor after its end.
    pub fn is_valid_at(&self, time_s: u64) -> bool {
        i64::try_from(time_s).is_ok_and(|time| self.not_before <= time && time <= self.not_after)
    }

    /// True when the certificate is one of a certificate authority: its basic constraints are
    /// a SEQUENCE that begins with a BOOLEAN of one byte that is not zero.
    pub fn is_authority(&self) -> bool {
        self.extension(&BASIC_CONSTRAINTS)
            .and_then(only)
            .filter(|constraints| constraints.tag == SEQUENCE)
            .and_then(|constraints| elements(constraints.content))
            .and_then(|inner| inner.first().copied())
            .is_some_and(|first| {
                first.tag == BOOLEAN && matches!(first.content, [value] if *value != 0)
            })
    }

    /// The text of the extension 1.3.6.1.4.1.57264.1.{number} of the certificate, whose value
    /// is the DER of one UTF8String. `None` when the certificate has no such extension or its
    /// value is not such a string.
    pub fn fulcio_text(&self, number: u8) -> Option<&str> {
        if number >= 0x80 {
            return None;
        }
        let mut identifier = FULCIO_ARC.to_vec();
        identifier.push(number);
        self.extension(&identifier)
            .and_then(only)
            .filter(|text| text.tag == UTF8_STRING)
            .and_then(|text| std::str::from_utf8(text.content).ok())
    }

    /// True when `issuer` issued this certificate: the issuer name of this certificate is the
    /// subject name of `issuer` as it is encoded, the signature algorithm is ECDSA with
    /// SHA-256 or with SHA-384, and the signature is the signature of the key of `issuer`, an
    /// ECDSA key on P-256 or on P-384, over the signed part.
    pub fn is_issued_by(&self, issuer: &Certificate) -> bool {
        let hash = if self.algorithm == ECDSA_WITH_SHA256 {
            Hash::Sha256
        } else if self.algorithm == ECDSA_WITH_SHA384 {
            Hash::Sha384
        } else {
            return false;
        };
        self.issuer == issuer.subject
            && ecdsa_verifies(&issuer.key, None, hash, &self.signed, &self.signature)
    }

    /// True when `signature` (ASN.1 DER) is the ECDSA P-256 SHA-256 signature of the key of
    /// this certificate over `message`. A certificate with a key of another kind signed
    /// nothing.
    pub fn signed_with_p256(&self, message: &[u8], signature: &[u8]) -> bool {
        ecdsa_verifies(
            &self.key,
            Some(Curve::P256),
            Hash::Sha256,
            message,
            signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One element of DER with the tag `tag` and the content `content`.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            length @ 0..=0x7f => out.push(length as u8),
            length @ 0x80..=0xff => out.extend([0x81, length as u8]),
            length => out.extend([0x82, (length >> 8) as u8, length as u8]),
        }
        out.extend_from_slice(content);
        out
    }

    #[test]
    fn an_element_of_der_has_a_tag_of_one_byte_and_its_shortest_length() {
        let (found, rest) = element(&[0x04, 0x02, 0xaa, 0xbb, 0xcc]).unwrap();
        assert_eq!(
            (found.tag, found.whole, found.content, rest),
            (
                0x04,
                &[0x04, 0x02, 0xaa, 0xbb][..],
                &[0xaa, 0xbb][..],
                &[0xcc][..]
            )
        );
        // The empty element, the longest short length and the two shortest long lengths.
        assert_eq!(element(&[0x05, 0x00]).unwrap().0.content, &[] as &[u8]);
        assert_eq!(
            element(&tlv(0x04, &[7; 0x7f])).unwrap().0.content.len(),
            0x7f
        );
        assert_eq!(
            element(&tlv(0x04, &[7; 0x80])).unwrap().0.content.len(),
            0x80
        );
        assert_eq!(
            element(&tlv(0x04, &[7; 0x100])).unwrap().0.content.len(),
            0x100
        );

        let long = [&[0x04, 0x81, 0x80][..], &[7; 0x80]].concat();
        assert!(element(&long).is_some());
        for refused in [
            // No bytes, a tag alone, a tag of more than one byte.
            &[][..],
            &[0x04],
            &[0x1f, 0x01, 0x00],
            &[0xbf, 0x01, 0x00],
            // A length that runs past the end.
            &[0x04, 0x02, 0xaa],
            // An indefinite length, a long form of a short length, a long form with a leading
            // zero, a long form of five bytes, a long form whose bytes are missing.
            &[0x30, 0x80, 0x00, 0x00],
            &[0x04, 0x81, 0x7f],
            &[0x04, 0x82, 0x00, 0x80],
            &[0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00],
            &[0x04, 0x82, 0x01],
        ] {
            assert!(element(refused).is_none(), "{refused:02x?}");
        }

        assert_eq!(elements(&[]).unwrap().len(), 0);
        assert_eq!(elements(&[0x05, 0x00, 0x04, 0x01, 0x09]).unwrap().len(), 2);
        assert!(elements(&[0x05, 0x00, 0x04]).is_none());
        assert!(only(&[0x05, 0x00]).is_some());
        assert!(only(&[0x05, 0x00, 0x00]).is_none());
    }

    #[test]
    fn a_time_of_a_certificate_is_read_in_its_two_forms() {
        let utc = |text: &str| time(&element(&tlv(UTC_TIME, text.as_bytes())).unwrap().0);
        let general =
            |text: &str| time(&element(&tlv(GENERALIZED_TIME, text.as_bytes())).unwrap().0);
        assert_eq!(utc("700101000000Z"), Some(0));
        assert_eq!(utc("700101000001Z"), Some(1));
        assert_eq!(utc("691231235959Z"), Some(-1));
        assert_eq!(utc("500101000000Z"), Some(-631_152_000));
        assert_eq!(utc("491231235959Z"), Some(2_524_607_999));
        assert_eq!(utc("261124174831Z"), Some(1_795_542_511));
        assert_eq!(utc("000229000000Z"), Some(951_782_400));
        assert_eq!(utc("240229120000Z"), Some(1_709_208_000));
        assert_eq!(general("20261124174831Z"), Some(1_795_542_511));
        assert_eq!(general("19700101000000Z"), Some(0));
        assert_eq!(general("19500101000000Z"), Some(-631_152_000));
        assert_eq!(general("21000301000000Z"), Some(4_107_542_400));
        assert_eq!(general("99991231235959Z"), Some(253_402_300_799));
        for refused in [
            "",
            "7001010000Z",
            "70010100000Z",
            "7001010000000Z",
            "700101000000",
            "700101000000z",
            "700101000000+",
            "70010100000aZ",
            "7001010000 0Z",
            "-00101000000Z",
            // A month and a day no calendar has, and times past the end of a day.
            "700001000000Z",
            "701301000000Z",
            "700100000000Z",
            "700132000000Z",
            "700431000000Z",
            "230229000000Z",
            "700101240000Z",
            "700101006000Z",
            "700101000060Z",
        ] {
            assert_eq!(utc(refused), None, "{refused}");
        }
        for refused in [
            "19491231235959Z",
            "00000101000000Z",
            "21000229000000Z",
            "2026112417483Z",
            "202611241748311Z",
            "20261124174831",
        ] {
            assert_eq!(general(refused), None, "{refused}");
        }
        // A time of another type.
        assert_eq!(
            time(&element(&tlv(0x0c, b"700101000000Z")).unwrap().0),
            None
        );
    }

    /// The root certificate and the intermediate certificate of the certificate authority of
    /// the public instance of Sigstore, as the node program holds them.
    fn pem_der(pem: &str) -> Vec<u8> {
        crate::release::pem_der(pem, "CERTIFICATE").unwrap()
    }

    fn fulcio() -> (Certificate, Certificate) {
        (
            Certificate::read(&pem_der(include_str!(
                "../../enclave/release/fulcio-root.pem"
            )))
            .unwrap(),
            Certificate::read(&pem_der(include_str!(
                "../../enclave/release/fulcio-intermediate.pem"
            )))
            .unwrap(),
        )
    }

    /// The certificate Fulcio issued to the job of the build workflow that built release
    /// v2.4.0-rc.1 (2026-11-24).
    const LEAF: &[u8] = include_bytes!("../tests/fixtures/fulcio-certificate-v2.4.0-rc.1.der");

    #[test]
    fn the_certificates_of_sigstore_are_read_and_chain() {
        let (root, intermediate) = fulcio();
        assert!(root.is_authority() && intermediate.is_authority());
        assert!(root.is_issued_by(&root));
        assert!(intermediate.is_issued_by(&root));
        assert!(!root.is_issued_by(&intermediate));
        assert!(!intermediate.is_issued_by(&intermediate));
        // Both are valid from their first second to 2031-10-05T13:56:58Z.
        assert_eq!(
            (root.not_before, root.not_after),
            (1_633_615_019, 1_948_975_018)
        );
        assert_eq!(
            (intermediate.not_before, intermediate.not_after),
            (1_649_880_375, 1_948_975_018)
        );
        assert!(intermediate.is_valid_at(1_649_880_375));
        assert!(!intermediate.is_valid_at(1_649_880_374));
        assert!(intermediate.is_valid_at(1_948_975_018));
        assert!(!intermediate.is_valid_at(1_948_975_019));
        assert!(!intermediate.is_valid_at(u64::MAX));

        let leaf = Certificate::read(LEAF).unwrap();
        assert!(!leaf.is_authority());
        assert!(leaf.is_issued_by(&intermediate));
        assert!(!leaf.is_issued_by(&root));
        // The certificate is valid for ten minutes.
        assert_eq!(
            (leaf.not_before, leaf.not_after),
            (1_795_542_511, 1_795_543_111)
        );
        // What it states of the run it was issued for.
        for (number, text) in [
            (8, "https://token.actions.githubusercontent.com"),
            (
                9,
                "https://github.com/pickle-com/credential-enclave/.github/workflows/enclave-build.yml@3f84e8368fcdf1f89e42ca629670bfe0989b6f13",
            ),
            (10, "3f84e8368fcdf1f89e42ca629670bfe0989b6f13"),
            (11, "github-hosted"),
            (12, "https://github.com/pickle-com/credential-enclave"),
            (13, "4c21e0083064aec5300f6f8472a796607e83d9f3"),
            (14, "refs/tags/v2.4.0-rc.1"),
            (15, "1400118248"),
            (17, "151645824"),
            (20, "push"),
            (22, "public"),
        ] {
            assert_eq!(leaf.fulcio_text(number), Some(text), "{number}");
        }
        // The extensions 1 to 6 hold a text that is no DER, and no certificate holds the
        // extension 7.
        for number in [1, 2, 3, 4, 5, 6, 7, 0x80, 0xff] {
            assert_eq!(leaf.fulcio_text(number), None, "{number}");
        }
    }

    #[test]
    fn a_changed_certificate_is_not_the_one_its_issuer_signed() {
        let (_, intermediate) = fulcio();
        // One bit of the serial number, of the key and of the signature.
        for at in [20, 180, LEAF.len() - 1] {
            let mut changed = LEAF.to_vec();
            changed[at] ^= 1;
            let read = Certificate::read(&changed);
            assert!(
                read.is_none_or(|leaf| !leaf.is_issued_by(&intermediate)),
                "{at}"
            );
        }
        // Bytes behind the certificate, and a certificate without its last byte.
        assert!(Certificate::read(&[LEAF, &[0u8]].concat()).is_none());
        assert!(Certificate::read(&LEAF[..LEAF.len() - 1]).is_none());
        assert!(Certificate::read(&[]).is_none());
        assert!(Certificate::read(b"certificate").is_none());
    }

    #[test]
    fn a_signature_is_verified_with_a_key_of_one_of_two_forms() {
        let leaf = Certificate::read(LEAF).unwrap();
        // The key of the certificate is on P-256: it has the form of that curve and no other.
        assert_eq!(ec_key(&leaf.key).map(|(curve, _)| curve), Some(Curve::P256));
        let (root, _) = fulcio();
        assert_eq!(ec_key(&root.key).map(|(curve, _)| curve), Some(Curve::P384));
        for spki in [
            &leaf.key[..leaf.key.len() - 1],
            &[&leaf.key[..], &[0u8]].concat(),
            &leaf.key[26..],
            &[],
        ] {
            assert_eq!(ec_key(spki), None);
        }
        let mut compressed = leaf.key.clone();
        compressed[26] = 0x02;
        assert_eq!(ec_key(&compressed), None);
        // A signature of a key on P-384 is none of a key that must be on P-256.
        assert!(!ecdsa_verifies(
            &root.key,
            Some(Curve::P256),
            Hash::Sha384,
            &root.signed,
            &root.signature
        ));
        assert!(ecdsa_verifies(
            &root.key,
            Some(Curve::P384),
            Hash::Sha384,
            &root.signed,
            &root.signature
        ));
        assert!(!ecdsa_verifies(
            &root.key,
            None,
            Hash::Sha256,
            &root.signed,
            &root.signature
        ));
        // Bytes behind a signature.
        let longer = [&root.signature[..], &[0u8]].concat();
        assert!(!ecdsa_verifies(
            &root.key,
            None,
            Hash::Sha384,
            &root.signed,
            &longer
        ));
    }
}
