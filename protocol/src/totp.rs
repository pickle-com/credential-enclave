//! TOTP (RFC 6238) with HMAC-SHA1, 6 digits and a 30-second step. Only the node computes it:
//! the seed never leaves a record, the code does.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::ProtocolError;

const STEP_MS: u64 = 30_000;
const DIGITS: u32 = 6;

/// Decodes RFC 4648 base32. Letters of either case are accepted, trailing `=` padding is
/// optional, and leftover bits that do not fill a byte are dropped.
fn base32_decode(text: &str) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let trimmed = text.trim_end_matches('=');
    let mut output = Zeroizing::new(Vec::with_capacity(trimmed.len() * 5 / 8));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for character in trimmed.bytes() {
        let value = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a',
            b'2'..=b'7' => character - b'2' + 26,
            _ => return Err(ProtocolError::RecordInvalid),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    if output.is_empty() {
        return Err(ProtocolError::RecordInvalid);
    }
    Ok(output)
}

/// The 6-digit TOTP code of the base32 seed at `time_ms` (Unix epoch milliseconds).
///
/// A seed that is not base32 or decodes to no bytes is `record_invalid`: the seed comes from
/// the plaintext of a `vault_totp` record.
pub fn totp(seed_base32: &str, time_ms: u64) -> Result<String, ProtocolError> {
    let seed = base32_decode(seed_base32)?;
    let counter = time_ms / STEP_MS;
    let mut mac = Hmac::<Sha1>::new_from_slice(&seed).map_err(|_| ProtocolError::RecordInvalid)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = (u32::from(digest[offset]) & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);
    Ok(format!(
        "{:0width$}",
        binary % 10u32.pow(DIGITS),
        width = DIGITS as usize
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // base32 of the ASCII seed "12345678901234567890" used by RFC 6238 appendix B.
    const RFC_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn matches_rfc_6238_appendix_b_sha1_vectors() {
        // The RFC lists 8-digit codes. The 6-digit code is their last six digits.
        for (seconds, expected) in [
            (59u64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(
                totp(RFC_SEED, seconds * 1000).unwrap(),
                expected,
                "{seconds}"
            );
        }
    }

    #[test]
    fn the_code_is_constant_within_a_step_and_changes_at_the_boundary() {
        assert_eq!(
            totp(RFC_SEED, 30_000).unwrap(),
            totp(RFC_SEED, 59_999).unwrap()
        );
        assert_ne!(
            totp(RFC_SEED, 59_999).unwrap(),
            totp(RFC_SEED, 60_000).unwrap()
        );
    }

    #[test]
    fn padding_and_case_do_not_change_the_code() {
        let reference = totp("JBSWY3DPEHPK3PXP", 1_000_000).unwrap();
        assert_eq!(totp("jbswy3dpehpk3pxp", 1_000_000).unwrap(), reference);
        assert_eq!(totp("JBSWY3DPEHPK3PXP====", 1_000_000).unwrap(), reference);
    }

    #[test]
    fn a_seed_that_is_not_base32_is_rejected() {
        assert_eq!(totp("", 0), Err(ProtocolError::RecordInvalid));
        assert_eq!(totp("====", 0), Err(ProtocolError::RecordInvalid));
        assert_eq!(totp("JBSW Y3DP", 0), Err(ProtocolError::RecordInvalid));
        assert_eq!(totp("JBSWY3DP1", 0), Err(ProtocolError::RecordInvalid));
        assert_eq!(totp("A", 0), Err(ProtocolError::RecordInvalid));
    }
}
