//! Node statements: signed values an app verifies before it relies on what the operator
//! domain relayed to it.
//!
//! The challenge statement (protocol.md section 4.2) binds the one-time challenge of an
//! attestation response to the nonce of that attestation request. The `challenge` field of the
//! response is outside the attestation document. Without the statement, a relay could hand an
//! app a challenge the node issued earlier, drop the command the app signs with it, and answer
//! with the signed reply the node gave to an earlier command that carried the same challenge.
//!
//! The statements about an OAuth authorization (section 8.2): an app opens the web
//! authentication session only after it verified the `oauth_begin` statement, and learns from
//! the `oauth_complete` statement that the token was issued inside the node.
//!
//! Both of those carry `sign_pk`, the whole account signing public key of the grant under
//! which the authorization started. The 8-byte `key_id` identifies a key for display and early
//! refusal. It does not bind a statement to a key: a node replaces the grant of a `user_id`
//! with any new grant, so a grant of another signing key with the same first 8 hash bytes
//! would pass a `key_id` comparison.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::encoding::{b64u, to_json, Signed};
use crate::keys::NodeKeys;
use crate::purpose;

/// The body of a challenge statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeBody {
    pub v: u8,
    #[serde(rename = "type")]
    pub kind: String,
    pub node: String,
    pub nonce: String,
    pub challenge: String,
    pub time_ms: u64,
}

/// Signs the statement that this node issued `challenge` in answer to the attestation request
/// that carried `nonce`. A node signs it for a challenge it drew for that request and for no
/// other value, so a valid statement for a nonce proves that the challenge is not older than
/// the nonce.
pub fn challenge(keys: &NodeKeys, nonce: &[u8], challenge: &[u8; 16], time_ms: u64) -> Signed {
    let body = to_json(&ChallengeBody {
        v: 1,
        kind: "challenge".to_string(),
        node: keys.node(),
        nonce: b64u(nonce),
        challenge: b64u(challenge),
        time_ms,
    });
    keys.sign(purpose::CHALLENGE, &body)
}

/// The body of an `oauth_begin` statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OauthBeginBody {
    pub v: u8,
    #[serde(rename = "type")]
    pub kind: String,
    pub node: String,
    pub user_id: String,
    pub key_id: String,
    pub sign_pk: String,
    pub provider: String,
    pub state: String,
    pub url_sha256: String,
    pub time_ms: u64,
}

/// The body of an `oauth_complete` statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OauthCompleteBody {
    pub v: u8,
    #[serde(rename = "type")]
    pub kind: String,
    pub node: String,
    pub user_id: String,
    pub key_id: String,
    pub sign_pk: String,
    pub provider: String,
    pub state: String,
    pub record_id: String,
    pub time_ms: u64,
}

/// Signs the statement that this node created the authorization address `authorization_url`
/// for `state`, for the account key `sign_pk`. `url_sha256` is
/// `b64u(SHA-256(UTF-8(authorization_url)))`.
#[allow(clippy::too_many_arguments)]
pub fn oauth_begin(
    keys: &NodeKeys,
    user_id: &str,
    key_id: &str,
    sign_pk: &[u8; 32],
    provider: &str,
    state: &str,
    authorization_url: &str,
    time_ms: u64,
) -> Signed {
    let body = to_json(&OauthBeginBody {
        v: 1,
        kind: "oauth_begin".to_string(),
        node: keys.node(),
        user_id: user_id.to_string(),
        key_id: key_id.to_string(),
        sign_pk: b64u(sign_pk),
        provider: provider.to_string(),
        state: state.to_string(),
        url_sha256: b64u(&Sha256::digest(authorization_url.as_bytes())),
        time_ms,
    });
    keys.sign(purpose::STATEMENT, &body)
}

/// Signs the statement that the token of `state` was issued inside this node and became the
/// record `record_id`. `sign_pk` is the account key the authorization started under.
#[allow(clippy::too_many_arguments)]
pub fn oauth_complete(
    keys: &NodeKeys,
    user_id: &str,
    key_id: &str,
    sign_pk: &[u8; 32],
    provider: &str,
    state: &str,
    record_id: &str,
    time_ms: u64,
) -> Signed {
    let body = to_json(&OauthCompleteBody {
        v: 1,
        kind: "oauth_complete".to_string(),
        node: keys.node(),
        user_id: user_id.to_string(),
        key_id: key_id.to_string(),
        sign_pk: b64u(sign_pk),
        provider: provider.to_string(),
        state: state.to_string(),
        record_id: record_id.to_string(),
        time_ms,
    });
    keys.sign(purpose::STATEMENT, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::verify;

    #[test]
    fn challenge_has_the_key_order_of_section_4_2() {
        let keys = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
        let signed = challenge(&keys, &[0x5a; 32], &[0x44; 16], 9);
        let bytes = verify(&keys.sign_public(), purpose::CHALLENGE, &signed).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            format!(
                concat!(
                    "{{\"v\":1,\"type\":\"challenge\",\"node\":\"{}\",\"nonce\":\"{}\",",
                    "\"challenge\":\"{}\",\"time_ms\":9}}"
                ),
                keys.node(),
                b64u(&[0x5a; 32]),
                b64u(&[0x44; 16])
            )
        );
        // A challenge statement is not accepted as a reply or as another statement, and a reply
        // context does not make one: the signature contexts differ.
        assert!(verify(&keys.sign_public(), purpose::REPLY, &signed).is_err());
        assert!(verify(&keys.sign_public(), purpose::STATEMENT, &signed).is_err());
    }

    #[test]
    fn oauth_begin_has_the_key_order_of_section_8_2_and_hashes_the_address() {
        let keys = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
        let url = "https://accounts.example/authorize?response_type=code&client_id=c";
        let signed = oauth_begin(
            &keys,
            "user-1",
            "0123456789abcdef",
            &[0x33; 32],
            "google_workspace",
            "s.o",
            url,
            9,
        );
        let bytes = verify(&keys.sign_public(), purpose::STATEMENT, &signed).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            format!(
                concat!(
                    "{{\"v\":1,\"type\":\"oauth_begin\",\"node\":\"{}\",\"user_id\":\"user-1\",",
                    "\"key_id\":\"0123456789abcdef\",\"sign_pk\":\"{}\",",
                    "\"provider\":\"google_workspace\",",
                    "\"state\":\"s.o\",\"url_sha256\":\"{}\",\"time_ms\":9}}"
                ),
                keys.node(),
                b64u(&[0x33; 32]),
                b64u(&Sha256::digest(url.as_bytes()))
            )
        );
    }

    #[test]
    fn oauth_complete_has_the_key_order_of_section_8_2() {
        let keys = NodeKeys::from_random(&[0x11; 32], &[0x22; 32]);
        let signed = oauth_complete(
            &keys,
            "user-1",
            "0123456789abcdef",
            &[0x33; 32],
            "slack",
            "s.o",
            "rid",
            9,
        );
        let bytes = verify(&keys.sign_public(), purpose::STATEMENT, &signed).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            format!(
                concat!(
                    "{{\"v\":1,\"type\":\"oauth_complete\",\"node\":\"{}\",\"user_id\":\"user-1\",",
                    "\"key_id\":\"0123456789abcdef\",\"sign_pk\":\"{}\",",
                    "\"provider\":\"slack\",\"state\":\"s.o\",",
                    "\"record_id\":\"rid\",\"time_ms\":9}}"
                ),
                keys.node(),
                b64u(&[0x33; 32])
            )
        );
        // A statement is not accepted as a reply: the signature contexts differ.
        assert!(verify(&keys.sign_public(), purpose::REPLY, &signed).is_err());
    }
}
