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
// The node program calls this crate with what its callers and a peer node sent. So:
// No input ends the program. Its code (not the code of its tests) holds no `unwrap`, no
// `expect`, no `panic!`, and no index or slice expression that can fail. A place that keeps
// one of them says, where it stands, why no input reaches its failure
// (`#[expect(clippy::.., reason = "..")]`).
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::get_unwrap
    )
)]
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
pub mod released;
pub mod secret;
pub mod secret_use;
pub mod statement;
pub mod totp;
pub mod vault_secret;

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
    /// HPKE info of a log entry of format 1 (the releases before v2.0.0).
    pub const LOG_ENTRY_SEAL: &str = "pickle.secure.v1.log-entry";
    /// Signature context of a log entry of format 1.
    pub const LOG_ENTRY: &str = "pickle.secure.v1.log-entry\n";
    /// Prefix of the log chain hash of format 1.
    pub const LOG_CHAIN: &str = "pickle.secure.v1.log-chain\n";
    /// HPKE info of a log entry of format 2.
    pub const LOG_ENTRY_SEAL_V2: &str = "pickle.secure.v2.log-entry";
    /// Signature context of a log entry of format 2.
    pub const LOG_ENTRY_V2: &str = "pickle.secure.v2.log-entry\n";
    /// Prefix of the log chain hash of format 2: `SHA-256(prefix || prev || body_hash)`.
    pub const LOG_CHAIN_V2: &str = "pickle.secure.v2.log-chain\n";
    /// HPKE info of a log entry of format 3.
    pub const LOG_ENTRY_SEAL_V3: &str = "pickle.secure.v3.log-entry";
    /// Signature context of a log entry of format 3.
    pub const LOG_ENTRY_V3: &str = "pickle.secure.v3.log-entry\n";
    /// Prefix of the nonce of a node document:
    /// `SHA-256(prefix || the 32 bytes of the node signing public key)` (7.7).
    pub const NODE_DOCUMENT: &str = "pickle.secure.v3.node-document\n";
    /// Signature context of a head.
    pub const HEAD: &str = "pickle.secure.v1.head\n";
    /// Signature context of the account key registration (verified by the backend).
    pub const REGISTER: &str = "pickle.secure.v1.register\n";
    /// HPKE info of a message between nodes.
    pub const PEER_SEAL: &str = "pickle.secure.v1.peer";
    /// Signature context of a message between nodes.
    pub const PEER: &str = "pickle.secure.v1.peer\n";
    /// HPKE info of the envelope of one use of a vault secret (10.5).
    pub const SECRET_USE_SEAL: &str = "pickle.secure.v3.secret-use";
    /// Signature context of one use of a vault secret (10.5).
    pub const SECRET_USE: &str = "pickle.secure.v3.secret-use\n";
    /// HPKE info of a vault value that `release` seals to a key its caller named (enclave.md
    /// 5.9).
    pub const RELEASE_SEAL: &str = "pickle.secure.v3.release";
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
    /// Most events in one entry of format 2 or 3 (7.1). An open batch is closed before it
    /// would hold more.
    pub const ENTRY_EVENTS: usize = 128;
    /// Most bytes of the plaintext (the JSON array of the events) of one entry of format 2 or
    /// 3 (7.1).
    pub const ENTRY_PLAINTEXT_BYTES: usize = 1_048_576;
    /// Most events of GET requests without a body that a node remembers for one account at
    /// one time, so that an identical request shares one of them (7.2).
    pub const MERGE_KEYS: usize = 8_192;
    /// Most requests in one `forward/batch` call (enclave.md 5.8b).
    pub const FORWARD_BATCH_REQUESTS: usize = 100;
    /// Requests of one `forward/batch` call that are in flight at the same time (enclave.md
    /// 5.8b). The value keeps the rate at which a provider receives the requests of one
    /// account at the rate of the callers before the batch existed.
    pub const FORWARD_BATCH_CONCURRENCY: usize = 6;
    /// Provider requests of a node that are in flight at the same time, over every call
    /// (enclave.md section 8).
    pub const PROVIDER_INFLIGHT: usize = 512;
    /// Idle HTTP/1.1 connections a node keeps to its log store (enclave.md 5.14).
    pub const LOG_STORE_IDLE_CONNECTIONS: usize = 32;
    /// Idle connections a node keeps to one provider host for one account (enclave.md 5.8
    /// step 8).
    pub const PROVIDER_IDLE_CONNECTIONS: usize = 8;
    /// How long an idle connection to a provider is kept: 30 seconds.
    pub const PROVIDER_IDLE_MS: u64 = 30_000;
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
    /// The age at which the lifecycle rule of the log store removes an entry, and from which a
    /// reader treats an absent entry as expired: 400 days (7.4, 7.6).
    pub const LOG_EXPIRY_DAYS: u64 = 400;
    /// How long the log store keeps a version of a node document from the moment the node
    /// writes it: 400 days (7.7).
    pub const NODE_DOCUMENT_RETENTION_DAYS: u64 = 400;
    /// The age of the latest confirmed write of its node document at which a node writes the
    /// document again: 30 days (7.7).
    pub const NODE_DOCUMENT_RENEW_DAYS: u64 = 30;
    /// The age of the latest confirmed write of its node document up to which a node takes a
    /// user key and writes an entry: 31 days (7.7). An entry written inside this time has a
    /// retention that ends before the retention of that version of the document.
    pub const NODE_DOCUMENT_VALID_DAYS: u64 = 31;
    /// Longest release statement, in bytes (10.3).
    pub const RELEASE_STATEMENT_BYTES: usize = 16_384;
    /// The notice period of a release: how old the entry of the transparency log must be, by
    /// the clock of the giving node, before the statement it records counts (10.3).
    pub const RELEASE_NOTICE_SECONDS: u64 = 0;
    /// How far the time of an entry of the transparency log may lie after the clock of the
    /// giving node: 300 seconds (10.3).
    pub const RELEASE_ENTRY_AHEAD_SECONDS: u64 = 300;
    /// Longest `name` of a record of kind `vault_secret`, in characters (section 6).
    pub const VAULT_SECRET_NAME_CHARS: usize = 64;
    /// Most hosts in `sites` of a record of kind `vault_secret` (section 6).
    pub const VAULT_SECRET_SITES: usize = 8;
    /// Most slots in `slots` of a record of kind `vault_secret` (section 6).
    pub const VAULT_SECRET_SLOTS: usize = 4;
    /// Longest name inside a slot of a vault secret (the part after `header:`, `query:`,
    /// `form:` or `json:`), in bytes (section 6).
    pub const SLOT_NAME_BYTES: usize = 64;
    /// Longest host of a site, in bytes (section 6).
    pub const HOST_BYTES: usize = 253;
    /// Longest label of the host of a site, in bytes (section 6).
    pub const HOST_LABEL_BYTES: usize = 63;
    /// Longest `value` that `vault/store` takes, in bytes (enclave.md 5.9b).
    pub const VAULT_SECRET_VALUE_BYTES: usize = 12_000;
    /// Longest plaintext of a record that `vault/store` creates, in bytes (section 6). The
    /// `ct` of such a record is at most 16,384 characters long.
    pub const VAULT_SECRET_PLAINTEXT_BYTES: usize = 12_272;
    /// The lengths the device of an account pads the plaintext of a record of kind
    /// `vault_secret` to, in bytes (section 6): the shortest of them the plaintext fits.
    pub const VAULT_SECRET_PADDED_BYTES: [usize; 7] =
        [256, 512, 1_024, 2_048, 4_096, 8_192, 12_272];
    /// How long the envelope of one use of a vault secret can be used, from the node time of
    /// the giving node at which it was made: 30 seconds (10.5).
    pub const SECRET_USE_MS: u64 = 30_000;
    /// Shortest value of a vault secret that is used in a request, in bytes (10.5). A shorter
    /// value is not searched for in the response to the request, so no node sends one.
    pub const SECRET_USE_VALUE_BYTES_MIN: usize = 8;
    /// Longest value of a vault secret that is used in a request, in bytes (10.5).
    pub const SECRET_USE_VALUE_BYTES_MAX: usize = 12_000;
    /// Shortest placeholder of a request a vault secret is used in, in characters (10.5).
    pub const PLACEHOLDER_CHARS_MIN: usize = 16;
    /// Longest placeholder, in characters.
    pub const PLACEHOLDER_CHARS_MAX: usize = 128;
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
    LogStoreUnavailable,
    CapacityUnavailable,
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
        ProtocolError::LogStoreUnavailable,
        ProtocolError::CapacityUnavailable,
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
            ProtocolError::LogStoreUnavailable => "log_store_unavailable",
            ProtocolError::CapacityUnavailable => "capacity_unavailable",
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
            "log_store_unavailable",
            "capacity_unavailable",
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
