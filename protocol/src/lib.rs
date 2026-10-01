//! Formats of the credential enclave protocol (protocol v1).
//!
//! This crate holds the pure functions that the node program, the test vector generator and
//! the verifiers of a node share: encodings, key derivation, the command envelope, the
//! credential record, the credential log, the node statements and the attestation documents.
//! No function here performs I/O or reads a clock: randomness and time are arguments.
//!
//! The normative description of every format is `docs/protocol.md`. Section numbers in the
//! comments of this crate refer to that document, and `enclave.md` in a comment is
//! `docs/enclave.md`. The rules on what leaves a node are in `docs/egress-policy.md`.

#![forbid(unsafe_code)]
// Rule E5 of the egress policy: the node writes no diagnostic output of its own making.
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

pub mod app;
pub mod attestation;
pub mod encoding;
pub mod envelope;
pub mod keys;
pub mod log;
pub mod record;
pub mod release;
pub mod secret;
pub mod statement;
pub mod totp;

use std::fmt;

/// The purpose strings of protocol.md section 3. No other string is used as an HKDF info, an
/// HPKE info or a signature context.
pub mod purpose {
    /// HKDF info: master key to the account signing seed.
    pub const SIGN: &str = "pickle.secure.v1.sign";
    /// HKDF info: master key to the log decryption private key.
    pub const LOG: &str = "pickle.secure.v1.log";
    /// HKDF info: master key to the user key of custody `enclave`.
    pub const USER_KEY: &str = "pickle.secure.v1.user-key";
    /// HKDF info: master key to the user key of custody `operator`.
    pub const USER_KEY_OPERATOR: &str = "pickle.secure.v1.user-key.operator";
    /// HKDF info of the record key and the first line of the record AAD.
    pub const RECORD: &str = "pickle.secure.v1.record";
    /// HPKE info of the command envelope.
    pub const MESSAGE: &str = "pickle.secure.v1.message";
    /// Signature context of an app command.
    pub const COMMAND: &str = "pickle.secure.v1.command\n";
    /// Signature context of a node reply.
    pub const REPLY: &str = "pickle.secure.v1.reply\n";
    /// Signature context of a node statement.
    pub const STATEMENT: &str = "pickle.secure.v1.statement\n";
    /// Signature context of a challenge statement.
    pub const CHALLENGE: &str = "pickle.secure.v1.challenge\n";
    /// HPKE info of a log entry.
    pub const LOG_ENTRY_SEAL: &str = "pickle.secure.v1.log-entry";
    /// Signature context of a log entry.
    pub const LOG_ENTRY: &str = "pickle.secure.v1.log-entry\n";
    /// Prefix of the log chain hash.
    pub const LOG_CHAIN: &str = "pickle.secure.v1.log-chain\n";
    /// Signature context of a head.
    pub const HEAD: &str = "pickle.secure.v1.head\n";
    /// Signature context of the account key registration (verified by the backend).
    pub const REGISTER: &str = "pickle.secure.v1.register\n";
    /// HPKE info of a message between nodes.
    pub const PEER_SEAL: &str = "pickle.secure.v1.peer";
    /// Signature context of a message between nodes.
    pub const PEER: &str = "pickle.secure.v1.peer\n";
}

/// The constants of protocol.md section 12 and the length limits of section 1.
pub mod limits {
    /// Longest delegation: 30 days of node time. A node shortens a longer grant to this length
    /// (5.2 `not_after_ms`).
    pub const GRANT_MAX_MS: u64 = 30 * 24 * 60 * 60 * 1000;
    /// Lifetime of a challenge: 300 seconds.
    pub const CHALLENGE_MS: u64 = 300 * 1000;
    /// Lifetime of a pending authorization: 600 seconds.
    pub const PENDING_AUTH_MS: u64 = 600 * 1000;
    /// Window in which identical GET requests of `forward` share one log entry: 300 seconds.
    pub const MERGE_WINDOW_S: u64 = 300;
    /// Most accounts in one delegation transfer between nodes.
    pub const TRANSFER_GRANTS: usize = 1_000;
    /// Most nodes that one grant is handed to by the node that holds it (10.1).
    pub const TRANSFER_PEERS: usize = 64;
    /// Entries per account that may wait for a storage acknowledgement.
    pub const UNACKED_ENTRIES: usize = 64;
    /// Body limit of a provider request and of a provider response: 64 MiB.
    pub const BODY_BYTES: usize = 67_108_864;
    /// Longest `context` string, in characters.
    pub const CONTEXT_CHARS: usize = 256;
    /// Longest `user_id`, `provider` and `kind`, in characters.
    pub const NAME_CHARS: usize = 128;
    /// Longest `path` and `query` copied into a `provider_request` event, in bytes. It is the
    /// longest address `forward` takes (enclave.md section 7), so an event carries the whole
    /// path and the whole query of its request (7.2).
    pub const EVENT_ADDRESS_BYTES: usize = 8192;
    /// Longest binding document, in bytes (4.1).
    pub const BINDING_BYTES: usize = 512;
    /// How long the log store keeps an entry from the moment a node writes it: 365 days. Until
    /// then nobody can delete the object or shorten its retention (7.6).
    pub const LOG_RETENTION_DAYS: u64 = 365;
    /// Longest release statement, in bytes (10.3).
    pub const RELEASE_STATEMENT_BYTES: usize = 16_384;
    /// The notice period of a release: how old the entry of the transparency log must be, by
    /// the clock of the giving node, before the statement it records counts (10.3).
    pub const RELEASE_NOTICE_SECONDS: u64 = 0;
    /// How far the time of an entry of the transparency log may lie after the clock of the
    /// giving node: 300 seconds (10.3).
    pub const RELEASE_ENTRY_AHEAD_SECONDS: u64 = 300;
}

/// The failure codes of protocol.md section 11. The variants and the codes correspond one to
/// one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProtocolError {
    InvalidRequest,
    UnsupportedVersion,
    WrongNode,
    OpenFailed,
    BadSignature,
    BadChallenge,
    BadExpiry,
    UnsupportedPolicy,
    CustodyMismatch,
    PeerUnverified,
    UserMismatch,
    Internal,
    NotConfigured,
    Closing,
    GrantRequired,
    GrantRevoked,
    GrantExpired,
    KeyMismatch,
    RecordInvalid,
    ProviderUnknown,
    NotAllowed,
    StateUnknown,
    ExchangeFailed,
    RefreshFailed,
    ProviderUnreachable,
    Timeout,
    ResponseWithheld,
    TooLarge,
    LogBacklog,
    LogStoreUnavailable,
}

impl ProtocolError {
    /// Every variant, in the order of protocol.md section 11.
    pub const ALL: [ProtocolError; 30] = [
        ProtocolError::InvalidRequest,
        ProtocolError::UnsupportedVersion,
        ProtocolError::WrongNode,
        ProtocolError::OpenFailed,
        ProtocolError::BadSignature,
        ProtocolError::BadChallenge,
        ProtocolError::BadExpiry,
        ProtocolError::UnsupportedPolicy,
        ProtocolError::CustodyMismatch,
        ProtocolError::PeerUnverified,
        ProtocolError::UserMismatch,
        ProtocolError::Internal,
        ProtocolError::NotConfigured,
        ProtocolError::Closing,
        ProtocolError::GrantRequired,
        ProtocolError::GrantRevoked,
        ProtocolError::GrantExpired,
        ProtocolError::KeyMismatch,
        ProtocolError::RecordInvalid,
        ProtocolError::ProviderUnknown,
        ProtocolError::NotAllowed,
        ProtocolError::StateUnknown,
        ProtocolError::ExchangeFailed,
        ProtocolError::RefreshFailed,
        ProtocolError::ProviderUnreachable,
        ProtocolError::Timeout,
        ProtocolError::ResponseWithheld,
        ProtocolError::TooLarge,
        ProtocolError::LogBacklog,
        ProtocolError::LogStoreUnavailable,
    ];

    /// The code string of protocol.md section 11.
    pub fn code(&self) -> &'static str {
        match self {
            ProtocolError::InvalidRequest => "invalid_request",
            ProtocolError::UnsupportedVersion => "unsupported_version",
            ProtocolError::WrongNode => "wrong_node",
            ProtocolError::OpenFailed => "open_failed",
            ProtocolError::BadSignature => "bad_signature",
            ProtocolError::BadChallenge => "bad_challenge",
            ProtocolError::BadExpiry => "bad_expiry",
            ProtocolError::UnsupportedPolicy => "unsupported_policy",
            ProtocolError::CustodyMismatch => "custody_mismatch",
            ProtocolError::PeerUnverified => "peer_unverified",
            ProtocolError::UserMismatch => "user_mismatch",
            ProtocolError::Internal => "internal",
            ProtocolError::NotConfigured => "not_configured",
            ProtocolError::Closing => "closing",
            ProtocolError::GrantRequired => "grant_required",
            ProtocolError::GrantRevoked => "grant_revoked",
            ProtocolError::GrantExpired => "grant_expired",
            ProtocolError::KeyMismatch => "key_mismatch",
            ProtocolError::RecordInvalid => "record_invalid",
            ProtocolError::ProviderUnknown => "provider_unknown",
            ProtocolError::NotAllowed => "not_allowed",
            ProtocolError::StateUnknown => "state_unknown",
            ProtocolError::ExchangeFailed => "exchange_failed",
            ProtocolError::RefreshFailed => "refresh_failed",
            ProtocolError::ProviderUnreachable => "provider_unreachable",
            ProtocolError::Timeout => "timeout",
            ProtocolError::ResponseWithheld => "response_withheld",
            ProtocolError::TooLarge => "too_large",
            ProtocolError::LogBacklog => "log_backlog",
            ProtocolError::LogStoreUnavailable => "log_store_unavailable",
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProtocolError {}

/// True when `text` satisfies the length rule of protocol.md section 1 for `user_id`,
/// `provider` and `kind`: 1 to 128 characters, none of them a control character
/// (U+0000 to U+001F).
pub fn is_valid_name(text: &str) -> bool {
    let mut count = 0usize;
    for character in text.chars() {
        if character <= '\u{1f}' {
            return false;
        }
        count += 1;
        if count > limits::NAME_CHARS {
            return false;
        }
    }
    count >= 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn codes_are_unique_and_cover_section_11() {
        let codes: HashSet<&str> = ProtocolError::ALL
            .iter()
            .map(|error| error.code())
            .collect();
        assert_eq!(codes.len(), ProtocolError::ALL.len());
        for code in [
            "invalid_request",
            "unsupported_version",
            "wrong_node",
            "open_failed",
            "bad_signature",
            "bad_challenge",
            "bad_expiry",
            "unsupported_policy",
            "custody_mismatch",
            "peer_unverified",
            "user_mismatch",
            "internal",
            "not_configured",
            "closing",
            "grant_required",
            "grant_revoked",
            "grant_expired",
            "key_mismatch",
            "record_invalid",
            "provider_unknown",
            "not_allowed",
            "state_unknown",
            "exchange_failed",
            "refresh_failed",
            "provider_unreachable",
            "timeout",
            "response_withheld",
            "too_large",
            "log_backlog",
            "log_store_unavailable",
        ] {
            assert!(codes.contains(code), "missing code {code}");
        }
    }

    #[test]
    fn name_rule() {
        assert!(is_valid_name("u"));
        assert!(is_valid_name(&"a".repeat(128)));
        assert!(is_valid_name("사용자 1"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name(&"a".repeat(129)));
        assert!(!is_valid_name("a\nb"));
        assert!(!is_valid_name("a\u{0}b"));
    }
}
