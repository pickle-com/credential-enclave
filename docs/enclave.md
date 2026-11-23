# The enclave node program and the host program

This document is the implementation-level specification of the two programs of this repository
that run in production: the enclave node program and its host program. The formats (keys, messages,
records, the log) are in [protocol.md](protocol.md). This document describes the programs that
implement them: their structure, the call surface of a node, the provider definitions, the build
and the release. The rules on what leaves a node are in [egress-policy.md](egress-policy.md).

The terms account, app, node, operator, operator domain and provider are defined at the top of
protocol.md. The backend is the part of the operator domain that calls a node.

---

## 1. Repository

| Item | Value |
| --- | --- |
| Name | `pickle-com/credential-enclave` |
| License | Apache-2.0 (`LICENSE`) |
| Language | Rust, edition 2021 |
| Toolchain | `rust-toolchain.toml` fixes the channel `1.98.1`. The workspace states `rust-version = "1.98"` |
| Workspace | `Cargo.toml`: the four crates `protocol`, `enclave`, `host` and `verify`, resolver 3. `Cargo.lock` fixes the version of every dependency |

```text
credential-enclave/
├── README.md
├── LICENSE
├── Cargo.toml                    # the workspace, the shared dependency versions, the release profile
├── Cargo.lock
├── rust-toolchain.toml
├── docs/
│   ├── protocol.md               # the formats
│   ├── enclave.md                # this document
│   └── egress-policy.md          # what can leave a node, and what enforces it
├── protocol/                     # crate credential-enclave-protocol (library)
│   ├── src/lib.rs                # purpose strings, constants, failure codes
│   ├── src/{encoding,secret,keys,envelope,record,log,statement,totp,attestation,release,app}.rs
│   ├── src/aws-nitro-enclaves-root-g1.der   # the trust root of Nitro attestation documents
│   ├── src/bin/vectors.rs        # the generator of the test vectors
│   ├── tests/vectors.rs          # the library passes every committed vector
│   ├── tests/fixtures/           # real Nitro attestation documents, an unrelated root certificate, a real entry of each transparency log, the trusted root of Sigstore, endorsements of an independent implementation
│   └── vectors.json              # the test vectors of protocol.md section 13
├── enclave/                      # crate credential-enclave (binary credential-enclave)
│   ├── release/{release-key.pem,rekor-key.pem,rekor-log2025-1-key.pem,predecessors.json}   # compiled into the node program (5.13, 11.1)
│   ├── src/main.rs               # the argument, the choice of the platform, the start of the server
│   ├── src/platform/mod.rs       # trait Platform (section 2)
│   ├── src/platform/nitro.rs     # NSM attestation, vsock listener, vsock egress
│   ├── src/platform/lingering.rs # a vsock connection is closed only after its peer reported its end (section 8)
│   ├── src/platform/local.rs     # unsigned document, TCP listener, direct egress
│   ├── src/state.rs              # the state of a node (section 3), the counts of health, the events of the log
│   ├── src/subset.rs             # the delegation subset: which accounts a node holds (protocol.md 10.4)
│   ├── src/clock.rs              # node time (section 8)
│   ├── src/faults.rs             # what a panic ends: a call, an account on this node, or the process (3.1)
│   ├── src/api/mod.rs            # the router, the failure responses
│   ├── src/api/responses.rs      # every response type (rule E3 of the egress policy)
│   ├── src/api/{health,config,attestation,messages,status,oauth,refresh,revoke,forward,forward_batch,mail,release,close,peer,grants,log_store}.rs
│   ├── src/attest.rs             # which peer a node accepts (same platform; same measurement, a later release with an endorsement, a predecessor)
│   ├── src/lineage.rs            # the release key, the table of transparency logs and the list of predecessors of the program (5.13)
│   ├── src/load.rs               # the CPU time and the memory of the kernel, from procfs, for `load` of health (5.1)
│   ├── src/descriptors.rs        # the limit of open descriptors the node raises at its start, and the two descriptor values of `load` of health (section 8)
│   ├── src/inbound.rs            # the connections from the backend: their number from the memory of the kernel, and the time limits of a body and of a response (section 8)
│   ├── src/providers/mod.rs      # the provider definitions: parsing, validation, the address check
│   ├── src/providers/definitions.json
│   ├── src/oauth.rs              # the authorization address, the token address call, the merge rules, the public fields
│   ├── src/vault.rs              # the vault kinds, the value `release` hands out, the value `vault/handoff` seals, the record `vault/store` makes
│   ├── src/role.rs               # the role of a node, taken once, and the numbers of the secret uses a node of the forward role sent
│   ├── src/bound.rs              # the request of one use of a vault secret, with the value at its slot (5.16)
│   ├── src/provider_response.rs  # the check of a provider response before `forward` returns it, and of the response of a site before `vault/send` does
│   ├── src/egress.rs             # the TLS client (rustls), the idle connections per (account, host), the node-wide bound of provider requests
│   ├── src/mail.rs               # the mail calls: the record of an application password, the IMAP and SMTP commands, the share of the body budget of a call
│   ├── src/imap.rs               # the reader of the responses of the IMAP server
│   ├── src/mail_sessions.rs      # the authenticated IMAP sessions a node keeps between the reads of a record
│   ├── src/log_store.rs          # the log store: the group commit, the write of an entry, its signature, the pending entries, the idle connections, the node document (5.14)
│   ├── src/frame.rs              # the frame of `forward` (5.8) and of `forward/batch` (5.8b), and the stream of `forward` and of `vault/send`
│   ├── src/testing.rs            # tests only: the provider stand-in, the test platform and clock
│   └── src/tests/                # tests only: the tests of the whole node (section 12)
├── host/                         # crate credential-enclave-host (binary credential-enclave-host)
│   └── src/{main,launch,relay,egress,config,health,watch,descriptors,memory,drain,calls,http,faults,testing}.rs
├── verify/                       # crate credential-enclave-verify (binary credential-enclave-verify)
│   ├── src/{main,arguments,evaluate,fetch,render}.rs   # the attestation check
│   ├── src/program.rs            # the subcommand program: the release proof of the secure program
│   └── tests/{offline.rs,program.rs,fixtures/}
├── secure-program/               # the secure program of the apps: protocol.md, "The secure program release"
│   ├── secure-program.js         # the program (the source of truth; pickle-com/interactive-character vendors a byte-identical copy)
│   ├── statement.py              # writes the release statement of a secure-program-v* tag
│   ├── monitor.py                # compares the entries of the release key in the transparency log with the releases
│   └── README.md
├── egress/
│   ├── secret-access.tsv         # the functions that read a secret, and what each does with it
│   └── sink-callers.tsv          # the functions that call a sink
├── scripts/secret-access.sh      # compares the source with the two lists (rule E2)
├── build/
│   ├── Dockerfile.enclave        # FROM scratch + the static node binary
│   ├── Dockerfile.eif            # a fixed amazonlinux:2023 + a fixed nitro-cli: assembles the enclave image file
│   ├── Dockerfile.host           # the host image (nitro-cli, the host binary, enclave.eif)
│   ├── Dockerfile.local          # the local platform image (the node binary as an ordinary process)
│   └── build.sh                  # the single entry point of the build (prints the measurements as JSON)
└── .github/workflows/{check.yml,release.yml,secure-program-release.yml,secure-program-monitor.yml}
```

The crates and what they depend on, as their `Cargo.toml` files state it:

| Crate | Output | Crates of this workspace | External crates |
| --- | --- | --- | --- |
| `credential-enclave-protocol` | Library `credential_enclave_protocol`, binary `vectors` | None | `base64` 0.22, `chacha20poly1305` 0.10, `ed25519-dalek` 2, `hkdf` 0.12, `hmac` 0.12, `hpke` 0.12, `ring` 0.17, `rustls-pki-types` 1, `rustls-webpki` 0.103, `serde` 1, `serde_json` 1, `sha1` 0.10, `sha2` 0.10, `x25519-dalek` 2, `zeroize` 1 |
| `credential-enclave` | Binary `credential-enclave`: the node program | `credential-enclave-protocol` | `axum` 0.8, `base64`, `getrandom` 0.2, `hmac` 0.12, `hyper` 1, `hyper-util` 0.1, `memchr` 2, `rustls` 0.23, `serde`, `serde_json`, `sha2`, `tokio` 1, `tokio-rustls` 0.26, `url` 2, `webpki-roots` 0.26, `zeroize`. On Linux: `aws-nitro-enclaves-nsm-api` 0.5, `tokio-vsock` 0.7 |
| `credential-enclave-host` | Binary `credential-enclave-host`: the host program | None | `http-body-util` 0.1, `hyper` 1, `hyper-util` 0.1, `serde`, `serde_json`, `tokio` 1. On Linux: `tokio-vsock` 0.7 |
| `credential-enclave-verify` | Binary `credential-enclave-verify`: the verification tool | `credential-enclave-protocol` | `getrandom` 0.2, `rustls` 0.23, `serde_json`, `ureq` 2.12, `webpki-roots` 0.26 |

- `serde_json` is built with the feature `preserve_order`: the key order of events and of token
  objects is kept.
- The node signs its writes to the log store with AWS Signature Version 4, which
  `enclave/src/log_store.rs` implements with `hmac` and `sha2`. No AWS SDK is part of the node
  program.
- `rustls` and `rustls-webpki` use the `ring` provider. The certificate chain and the ECDSA P-384
  SHA-384 signature of a Nitro attestation document are verified with `rustls-webpki`, the crate
  that also verifies the TLS certificates of the node. CBOR is read by code of the protocol crate.
  That reader is the only reader of attestation documents: a verifier of a node, a node that
  verifies a peer, and a node that reads the time and its own measurement from its own documents
  use it.
- The two ECDSA P-256 SHA-256 signatures of an endorsement (protocol.md 10.3) are verified with
  `ring`, the crate that `rustls` and `rustls-webpki` use as their provider. The PEM of a public
  key is read by code of the protocol crate.
- The verification tool verifies the ECDSA P-256 SHA-256 signatures of a secure program release
  proof (protocol.md, "The secure program release": the release key over the statement, the log
  key over the signed entry timestamp and over the checkpoint) with the `ring` provider of
  `rustls`, which the tool carries for TLS, and reads PEM keys and computes SHA-256 with the
  protocol crate (`verify/src/program.rs`). The subcommand adds no dependency: `Cargo.lock` is a
  build input of the measured node program.
- Dependencies of tests only: `rcgen` 0.13 (the certificates of the provider stand-in and of the
  attestation documents that tests build), and the feature `test-util` of `tokio`.
- Every crate has `#![forbid(unsafe_code)]`: the source of this repository has no `unsafe` block
  (its dependencies are outside this rule).
- A node that ends takes the delegations it holds with it, and the enclave ends with the host
  program. Two rules keep a fault of one of the two programs from ending a node. The first:
  the crates of the node program, of the host program and of the protocol deny, outside the
  code of their tests, the lints `clippy::unwrap_used`, `expect_used`, `panic`, `unreachable`,
  `todo`, `unimplemented`, `indexing_slicing`, `string_slice` and `get_unwrap`, in every
  module. A place that keeps an `expect` carries
  `#[expect(clippy::expect_used, reason = "...")]` with the reason why no input reaches its
  failure. The rule reads the code of these crates and not their dependencies. The second:
  the two programs unwind on a panic (the release profile below), and a panic ends the
  smallest part of the program that it can have left in doubt: a call, an account on this
  node, or a connection of the host program (3.1, section 9).
- The release profile is a build input of the measured binary: `opt-level = 3`, `lto = "fat"`,
  `codegen-units = 1`, `panic = "unwind"`, `strip = true`.

### 1.1 The modules of the protocol crate

The protocol crate holds the pure functions that the node program, the generator of the test
vectors and the verifiers of a node share. No function of the crate performs input or output or
reads a clock: randomness and time are arguments.

| Module | What it holds |
| --- | --- |
| `lib.rs` | The purpose strings of protocol.md section 3 (`purpose`), the constants of section 12 and the length limits (`limits`), the failure codes (`ProtocolError`: its variants and the codes of section 11 correspond one to one), the name rule of section 1 (`is_valid_name`) |
| `encoding.rs` | base64url without padding, the JSON serialization rule, the carriage of signed values `{body, sig}`, Ed25519 signing and verification over the purpose string and the body bytes |
| `secret.rs` | The types that hold a secret: `Secret<T>` and `NodeKeys` (rule E1 of the egress policy). A `Secret` is read through `expose_secret` only, implements neither `Serialize` nor `Display`, prints a fixed string as `Debug`, and is overwritten with zeros when it is dropped. `NodeKeys` offers the operations that use the two private keys of a node (sign, open) and no function that returns them |
| `keys.rs` | The custody mode, `node` and `key_id`, HKDF-SHA256, the derivation of the record key, the binding document, the name of a log store (`LogStoreId`: a bucket name and a region name of the forms of protocol.md 4.1), the buckets of a log store and the bucket of an account or of a node among them (protocol.md 7.6) |
| `envelope.rs` | The command envelope and the commands inside it (the checks 1 to 9 of protocol.md 5.3), the signed reply, the transfer envelope between nodes (protocol.md 10.1), and the single-shot HPKE seal and open |
| `record.rs` | The credential record: the kinds and their use modes, the AAD, opening and creating |
| `log.rs` | The log entry of format 3 (one entry, one or more events), the key of its object in the log store and the parsing of such a key, the node document (protocol.md 7.7). For a reader and for the test vectors: the entries of format 2 and of format 1 as the earlier releases wrote them, their two chain hashes, the head, the keys of their objects and their parsing |
| `statement.rs` | The node statements: the challenge statement of an attestation response (protocol.md 4.2), and `oauth_begin` and `oauth_complete` (protocol.md 8.2) |
| `totp.rs` | TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30 seconds) |
| `vault_secret.rs` | The plaintext of a record of kind `vault_secret` (protocol.md section 6): the name, the sites, the slots, the source and the padding, and whether a reach admits an origin or a request |
| `secret_use.rs` | The use of a vault secret in a request (protocol.md 10.5): the one reader of a slot and of the host of a site, the request object, the two lists of request headers a node of the forward role drops and refuses, the rules of a placeholder in a header and in the credentials of HTTP Basic, and the envelope between the two nodes |
| `released.rs` | A vault value `release` hands out under the seal of a key its caller named (protocol.md section 6) |
| `release.rs` | The delegation transfer to a later release (protocol.md 10.3): the release statement, a transparency log of one of the two forms with its key and its log identifier, the reader of the `entry` of an endorsement, the six checks of an endorsement (the statement, the log identifier, what the log returned with the entry: the signed entry timestamp of a log of the form Rekor v1, or the checkpoint and the audit path of a log of the form Rekor v2, the body of the entry with the release key and its signature, the time of the entry, the order of the two releases), the order of release tags, the reader of a list of predecessors, the reader of the PEM of a public key. The release key and the table of logs are arguments |
| `attestation.rs` | Reading and verifying attestation documents: the Nitro document (CBOR, COSE_Sign1, the certificate chain, the signature, the PCRs), the binding, the local document. It holds the trust root (AWS Nitro Enclaves Root-G1, DER) as a public constant. It returns what a document states and does not judge a measurement: which PCR values are acceptable is the decision of the caller |
| `app.rs` | The app side of the protocol: the derivation of the account keys, the check of a challenge statement, sealing a command, opening log entries, verifying the object of a key of format 3 against that key, reading a node document, verifying a chain of format 2 from the keys of the listing (index verification) and from its entries (content verification), verifying a chain of format 1. The node program does not call this module. The generator of the test vectors and the tests use it in the place of the app |
| `bin/vectors.rs` | The generator of `protocol/vectors.json` (fixed seeds) |

## 2. The platform layer

```rust
pub trait Platform: Send + Sync + 'static {
    fn name(&self) -> &'static str;                                   // "nitro" | "local"
    fn custody(&self) -> &'static str;                                // "enclave" on nitro, "operator" on local (protocol.md section 3)
    fn measurement(&self) -> Option<Measurement>;                     // its own PCR0, PCR1, PCR2 (nitro). None on local
    fn attestation(&self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, PlatformError>;
    fn fill_random(&self, out: &mut [u8]) -> Result<(), PlatformError>;
    fn trusted_time_ms(&self) -> Result<u64, PlatformError>;          // the time the hypervisor gives
    fn listen(&self, connections: usize) -> impl Future<Output = Result<Listener, PlatformError>> + Send;   // where the calls of the backend arrive; `connections` is the bound of section 8
    fn connect(&self, host: &str, port: u16) -> impl Future<Output = Result<Stream, PlatformError>> + Send;  // the outbound byte pipe to a provider or to the log store
    fn lingering(&self) -> Option<(usize, u64)>;                      // the connections that wait for the end of their peer, and those closed before it (section 8). None on local
}
```

| Operation | nitro | local |
| --- | --- | --- |
| `name` | `nitro`. A node of this platform does not act without a log store (5.14) | `local`. A node of this platform works without a log store when its configuration names none |
| `custody` | `enclave` | `operator` |
| `measurement` | At boot the node requests one attestation document of its own and keeps the values 0, 1 and 2 of its `pcrs`. When one of the three is all zero (debug mode), the start stops: a node does not come up in an enclave that was launched in debug mode, and one line with the reason is on the console | None |
| `attestation` | NSM `Attestation { user_data, nonce, public_key: None }` | The local document of protocol.md 4.2 |
| `fill_random` | Kernel randomness (`getrandom`). At boot the node checks that `/sys/class/misc/hw_random/rng_current` is `nsm-hwrng`, and the start stops when it is not | `getrandom` |
| `trusted_time_ms` | The node requests one NSM attestation document and reads its `timestamp` (the signature is not verified: the document comes from the node's own `/dev/nsm`) | The system time |
| `listen` | vsock, port 8080, any CID (`VMADDR_CID_ANY`), with a queue of `connections` connections that wait for accept (section 8). An accepted connection is closed only after its peer reported the end of its bytes, and a write to it is attempted each time it is asked for (section 8) | TCP `0.0.0.0:8080` |
| `connect` | The node connects to vsock port 8443 of the parent (CID 3), sends `CONNECT {host}:{port}\n` as the first line, receives `OK\n`, and uses the connection as the byte pipe from then on. The host is a DNS name: lower-case letters, digits, `.` and `-`. The hosts a node asks for are those of its provider definitions and the host of its log store. The connection is closed only after the egress relay reported the end of its bytes (section 8) | A direct TCP connection |

The program argument: `credential-enclave --platform {nitro|local}`. There is no other
configuration (the operator configuration arrives through the call of 5.1). A wrong argument ends
the program with exit status 2 and the usage line. A platform that cannot be opened ends it with
exit status 1 and one fixed line with the reason on the standard error. Code outside the platform
layer holds the platform as a `SharedPlatform` and calls its operations.

## 3. The state of a node (memory only)

```rust
struct Node {
    keys: NodeKeys,                  // the signing key (Ed25519) and the sealing key (X25519), created at boot
    node: String,                    // b64u(signing public key)
    custody: Custody,                // the custody of the platform
    release: &'static str,           // the release tag compiled into the binary
    lineage: Lineage,                // { release_key, log_key: the DER of the two public keys, predecessors: Vec<ReleaseMeasurement> } (5.13)
    started_ms: u64,
    closing: AtomicBool,
    role: RoleCell,                  // the role of the node, taken once: none yet, the delegation role or the forward role (section 4)
    used_nonces: NodeLock<UsedNonces>,  // on a node of the forward role: the numbers of the envelopes whose request it sent, each kept for 60 seconds, at most 1,048,576 (5.16)
    forward_nodes: ForwardNodes,     // on a node of the delegation role: the nodes of the forward role it verified, by the SHA-256 of their attestation documents, at most 1,024 (5.9c)
    config: NodeRwLock<Option<Arc<OperatorConfig>>>,
    log_store: LogStore,             // { required, id: OnceLock<LogStoreId>, endpoint: OnceLock<Option<LogStoreEndpoint>>, credentials: NodeRwLock<Option<Arc<Credentials>>>, idle: IdleConnections, document_ms: AtomicU64 (the node time of the latest write of the node document the store confirmed), document_writer } (5.14)
    log_counters: LogCounters,       // { entries, events, writes, write_failures, batch_calls, batch_requests, write_attempt_failures: { connect, tls, closed, timeout, status_4xx, status_5xx }, write_retries, write_ms_buckets: [u64; 8], write_ms_sum, write_count }: the counts of `log` of health (5.1)
    late_refreshes: Arc<Semaphore>,  // the places of the token address calls of refresh that go on after their time limit: 128 (5.7)
    refresh_counters: RefreshCounters,  // { late_kept, late_dropped, late_failed, late_abandoned }: the counts of `refresh` of health (5.1)
    challenges: NodeLock<Expiring<[u8; 16], u64>>,      // the issued challenges, each with its serial. Removed after 300 seconds or on use. At most 100,000
    serials: AtomicU64,                                 // the next serial: one count for the challenges the node issues and the revoke commands it accepts. It starts at 1 and only grows
    accounts: NodeRwLock<BTreeMap<String, Arc<AccountLock>>>,  // user_id -> the state of the account behind its lock, in the order of user_id: a page of accounts after a user_id is a range of the map. One lock per account (3.1)
    pending: NodeLock<Expiring<String, PendingAuth>>,   // node_state -> the pending authorization (600 seconds, used once). At most 100,000
    chains: AtomicUsize,                                // the accounts this node created an entry for: `accounts` of health (5.1)
    counters: Arc<StateCounters>,                       // { grants, pending_accounts, pending_entries, kept_refreshes, merge_keys, open_batches, pending_oldest_since_ms, halted }: the counts of health kept by the methods of Account (5.1)
    // and: the platform, the clock, the provider definitions, the TLS client (with the idle connections to the providers, 5.8, the IMAP sessions kept between the reads of a record, "Mail call surface", the bound of connections being opened and the counts of `egress` of health, 5.1), the limits of section 8
}
struct Account {
    grant: GrantState,               // None | Active { key_id, sign_pk, log_pk, custody, user_key, not_after_ms, exported_to } | Expired { key_id, not_after_ms } | Revoked { key_id, sign_pk }
    last: Last,                      // { seq, body_hash } of the last entry this node created for the account. Without entries: seq 0 and a hash of 32 zero bytes
    open: OpenBatch,                 // the use events whose entry does not exist yet: { events: Vec<Value>, bytes, seq: Arc<OnceLock<u64>> (the cell that receives the seq of the entry when the batch is closed), key_id, log_pk }
    writer: bool,                    // true while a call of this account writes to the log store (the writer of the group commit, protocol.md 7.1)
    notify: Arc<Notify>,             // woken when a write of this account ended: the waiting calls look at their entries again
    unconfirmed: Vec<Unconfirmed>,   // the entries the log store has not confirmed: { seq, key, shard, entry, writers, pending_since_ms }. Empty on a node without a log store (5.14)
    recent: HashMap<[u8; 32], Recent>,  // merge key -> { entry_ms, target: EventPlace } of its event. Removed after 300 seconds, at most 8,192 keys (the GET requests of forward that have no body)
    kept_refreshes: VecDeque<KeptRefresh>,  // the responses of the successful refresh calls of the last 3,600 seconds, at most 16 (5.7)
    counters: Arc<StateCounters>,    // the counts of the node: the methods that change grant, unconfirmed, recent, kept_refreshes and open move them
    last_entry_ms: u64,              // the time_ms of the last entry this node created for the account (section 8)
    last_event_ms: u64,              // the time_ms of the last event created (section 8)
    revoked_here: bool,              // true once this node accepted a revoke command of the account (protocol.md 10.1)
    revoke_serial: u64,              // the serial of the last revoke command of the account that this node accepted, 0 when there is none (protocol.md 5.4)
    halted: bool,                    // true once the node halted the account: a panic began while its lock was held (3.1)
}
enum EventPlace { Open { batch: Arc<OnceLock<u64>>, index: u32 }, Entry { seq: u64, index: u32 } }   // where the event of a call is: in an open batch (the cell of that batch, filled with the seq of its entry at the close), or in an entry
struct KeptRefresh { key: [u8; 32], kept_ms: u64, response: Refreshed }   // key = SHA-256(the ct of the record that was sent)
struct PendingAuth { user_id, key_id, sign_pk: [u8; 32], provider, code_verifier: Option<PkceVerifier>, client_id: String, redirect_uri: String, state: String, expires_ms }
struct OperatorConfig { providers: HashMap<String, ProviderCredentials> }
struct ProviderCredentials { client_id: String, client_secret: Secret<String>, redirect_uri: String, publishable_key: String }
struct Credentials { access_key_id: String, secret_access_key: Secret<String>, session_token: Secret<String>, expires_ms: u64 }   // of the log store
```

- A node writes nothing to disk. Nodes share no state. The one exchange between nodes is the
  delegation transfer (5.13). The witnessing of stage 2 is in section 10.
- A grant whose time has passed: every place that reads the state of an account (a call that uses
  a credential, a command, `status`, the sweep of the node) first checks `now >= not_after_ms`.
  When that is true, the node erases the user key and changes the state to
  `Expired { key_id, not_after_ms }`, and judges after that. A call that uses a credential refuses
  `Expired` with `grant_expired`. There is no case in which an `Active` state holds a user key
  that is overwritten with zeros (protocol.md 5.4). `grants/prune` (5.15) changes the state of an
  account outside the share of the node from `Active` or `Expired` to `None` and erases the user
  key the same way.
- The counts of health (5.1) are kept with the state they count: `grants` (the accounts whose
  state is `Active`), `pending` of `log_store` (the accounts whose `unconfirmed` is not empty),
  `open_batches` of `log` (the accounts whose open batch holds events) and the three counts of
  `state` (the entries of `unconfirmed`, the elements of `kept_refreshes` and the keys of `recent`
  over every account) are atomic integers of the node that the methods of `Account` move when
  they change the state (`set_grant`, `expire`, `drop_grant`, the methods of the kept responses,
  of the merge keys and of the unconfirmed entries, and the creation and the close of a batch).
  A health call reads the integers and locks no account. `grants` counts a grant whose time
  passed until the first read of the account or the sweep ends it: at most one sweep interval
  after its end.
- `exported_to` of an `Active` grant is the list of the nodes of a later release that the grant was
  handed to with `peer/export`: the signing public key of each and the `seq` of the entry
  `grant_transferred_out` that names it, at most 64 (protocol.md 10.1). A grant command that puts a
  grant in place, a revoke, the end of the grant and a transfer that puts a grant in place create a
  new state, and the list of a new grant is empty. A grant command that renews the grant in force
  keeps the grant and its list. A transfer to a node of the measurement of this node has no entry
  and is not on the list.
- The open batch of an account holds use events in the order of their creation. It is closed into
  an entry by the call that finds no writer, by the writer when its write ends and the batch is
  not empty, when the next event would exceed 128 events or 1,048,576 bytes of plaintext, when
  the next event is created under another key than the batch was opened under, and before a
  control event is created. Closing happens inside the lock of the account: the `seq`, the seal
  and the signature are assigned there, and the cell of the batch receives the `seq`. The write
  runs outside the lock.
- A call whose event is in the open batch waits on the notification of the account until the
  entry that holds its event is confirmed (it acts), or its own write was not confirmed
  (`log_store_unavailable`), or it waited for twice the time limit of a write
  (`log_store_unavailable`), or the node is closing when it looks again (`closing`). A call that
  wakes and finds no writer and its entry unconfirmed becomes the writer. A forward batch waits
  for every entry that holds one of its events. A writer whose call ends before its write does
  (the caller closed the connection) is no longer the writer: the account has no writer until the
  next call, and its entries are pending entries.
- The sweep of the node: a task that runs every 30 seconds (`log_store::keep_sweeping`). It first
  writes the node document when that is due (5.14), and then makes three passes. The first pass
  visits every account once, in the order of the sorted index and one chunk of 1,000 accounts of the
  index at a time (the index is locked for one chunk, not for the walk): it ends a grant whose time
  passed, drops the merge keys whose window of 300 seconds passed (`recent`) and the kept `refresh`
  responses whose 3,600 seconds passed, and collects the accounts that have a pending entry. The
  second pass visits the collected accounts in an order the random source of the platform shuffles
  and writes the pending entries of each again with the rules of a write (at most 32 at the same
  time, over the idle connections). It writes the pending entries of an account only when the oldest
  of them has been pending for longer than a jitter it draws for that account in `[0, 30 seconds)`;
  otherwise they wait for the next sweep. Over the whole node it writes at most 64 entries per
  second (`sweep_write_rate` of section 8: a token bucket with a burst of one second), and the pass
  ends when the next sweep is due, so the accounts it did not reach wait for that sweep. The third
  pass reads the oldest pending entry of the collected accounts again and keeps its
  `pending_since_ms` in the counts of the node (0 when none is left): `pending_oldest_ms` of health
  is computed from that value until the next sweep. Without the sweep, a pending entry of an account
  that makes no further call would stay out of the store for as long as the account is idle; the
  merge keys and the kept responses of an idle account would stay in memory until its next call; and
  the user key of an idle account whose grant ended would stay until its next call. The random
  order, the jitter and the rate spread the writes of the accounts whose entries became pending at
  one moment (an outage of the store) over two sweeps and keep the recovery from more than doubling
  the live load on the store. The sweep ends when the orderly shutdown starts.
- `unconfirmed` of an account holds the entries that the log store has not confirmed, in the order
  of their `seq`. An entry leaves the list in one way: the store answered a write of it with the
  status 200. So "the store confirmed the entry" is said by an answer of the store and by nothing
  else, and an entry of a `seq` the node never created is not confirmed. `writers` is the number of
  calls that write the entry at this moment: the call that created it, and every call that took it
  along. An entry of this list that no call writes is a pending entry (protocol.md 7.6). A call
  counts itself as a writer of the entries it writes inside the lock of the account and counts
  itself out when its writes end, also when the call ends before its writes do (the caller closed
  the connection): the end of one call does not make an entry pending that another call still
  writes. `shard` is the hash that names the bucket of the account (protocol.md 7.6).
  `pending_since_ms` is the node time at which the entry was created: the age of the oldest pending
  entry of the node, as the last sweep found it, is `pending_oldest_ms` of `log_store` of health
  (5.1). An entry of this list is gone with the node: nothing drops it before, and the orderly
  shutdown does not touch it (5.11).
- The memory of the state of an account. The state of an account lives as long as the node, and a
  table keeps the room of the largest number of elements it ever held unless it gives that room
  back. So the three collections of an account give back the memory of what leaves them: `recent`
  shrinks when merge keys leave it (to the room of twice the keys it holds, and to none when it is
  empty), and `kept_refreshes` and `unconfirmed` hold no memory once they are empty. `recent` holds
  at most 8,192 keys (`merge_keys` of section 8): a GET request beyond that has an event of its own
  that the node does not remember (protocol.md 7.2), so one account cannot grow its table without a
  bound.
- The merge key of `forward` is
  `SHA-256(the 16 bytes of the record id || host || "\n" || path || "\n" || query)`. The
  separators keep different addresses from having the same key. The key holds no body: a GET
  request with a body is never merged (protocol.md 7.2).
- `Expiring` (the store of the challenges and of the pending authorizations): when an insert finds
  the store at its limit, the values whose time has passed are dropped first. When the store is
  still full, the value that was inserted first is dropped. A take removes the value, and a value
  whose time has passed is not returned.
- `user_key`, the opened plaintext of a record, `code_verifier`, `client_secret`, and the
  `secret_access_key` and the `session_token` of the log store are values of the secret types of
  `protocol/src/secret.rs`: their memory is overwritten with zeros when they are dropped.
- The creation of an event, the close of the open batch into an entry and the update of the last
  entry of one account happen inside the lock of that account (the chain of one account does not
  fork). A provider call and a write to the log store run outside the lock.
- The kept responses of `refresh` (5.7): a kept response holds what the response held, which is a
  record (a ciphertext), the public fields and the `log` object of the entry. A revoke command,
  the expiry of the grant, and a grant of another signing key drop the kept responses of the
  account.

### 3.1 What a panic ends

A panic is a fault of the node program or of a library it is built with: a place that met a
state it has no answer for. The lints of section 1 keep the code of this repository from
panicking on an input. They do not read its dependencies, which read what a caller, a provider,
a mail server and the log store send. So the program is built to unwind on a panic (11.1), and
a panic ends the smallest part of the node that it can have left in doubt
(`enclave/src/faults.rs`):

| Where the panic happens | What ends | What follows |
| --- | --- | --- |
| In the work of one call: on the task of its connection, or on a task the call started and waits for (the search of a provider response, the request to the attestation device, the token address call of `refresh`, the check of the request of `vault/send`) | That call | Its connection ends without a response. The other calls of the node, and the next calls of the same account, are served |
| On the task that carries one outbound HTTP/1.1 connection (to a provider or to the log store) | That connection | The call that used it fails as on a connection that broke: `provider_unreachable`, or a write the store did not confirm |
| On the task that hands the body of a stream on (`forward` with `stream`, `vault/send`) | That stream | The body is cut and ends with the end record of a call whose task ended without one (`timeout`) |
| In one sweep, or in one correction of the clock | That sweep, or that correction | The next one starts at its time. A correction that panicked leaves the correction before it in force |
| On the task that ends one kept IMAP session at its time ("Mail call surface") | That task | A session whose time passed is handed to no read, whether or not its task ended it: the read that asks for a session looks at its times. The task takes the session out of the table of the kept sessions before it drops it |
| While the lock of the state of one account is held | That account on this node: the node halts it | Every later call that names the account ends with `internal` on this node. The other nodes that hold its delegation serve it |
| While a lock of state of the whole node is held, or on one of the three tasks the node cannot do without | The process | The node program ends itself without unwinding and without output, and the enclave ends with it. The delegations of the node are those of the other nodes that hold them |

- A call that panicked holds nothing afterwards. What a call holds is held by values that give
  it back when they are dropped, and a panic drops them as a caller that closes its connection
  does: the place of the connection, a place among the forward calls, the shares of the body
  budget, the place of a provider request in flight, the IMAP session a mail read went over (it
  ends with the call and is not kept), and the entries the call was writing, which are pending
  entries once no other call writes them. The account of a call that was the writer of its group
  commit has no writer afterwards, and the calls that waited for it look at their entries again.
- A panic confirms no entry and performs no act. An entry leaves the unconfirmed entries by an
  answer of the store alone (section 3), and a call acts only after it read, inside the lock
  of its account, that the store confirmed the entry of its event. So no act of a node lacks
  its entry in the store because of a panic, before it or after it.
- The connection of a call that panicked ends without a response because the node has no true
  answer for it. A failure response says what the node knows of the act of the call: that no
  request left the node (`internal`, `closing`, `capacity_unavailable`,
  `log_store_unavailable`, and the failures of the checks before the act), or how a request
  that left ended. A call that panicked knows neither: its act took place or did not, as for
  a call to a node that ended. A caller repeats such a call only when the act of the call can
  be performed twice.
- A halted account. A panic while the lock of an account was held can have left its state half
  changed: an entry counted as written that the store never confirmed, a grant in place that a
  command was taking away. The node does not judge which. The next call that asks for the
  lock, of a call or of the sweep (at most 30 seconds later), gives the state up before it
  reads anything of it: the grant goes and its user key is overwritten with zeros; the
  unconfirmed entries, the events of the open batch, the merge keys and the kept `refresh`
  responses go (an entry the store did not confirm is gone as it is gone with a node that
  ends: its act did not take place, protocol.md 7.6). From then on, for as long as the node
  lives, the account takes no grant and no transfer, the node creates no entry for it, none
  of its entries counts as confirmed, and a call that needs its state ends with `internal`:
  the calls that use a credential, a grant command of the app (`messages`) and `status`. A
  call that was writing or waiting when the account was halted ends with `internal` as well,
  also when the store confirmed its entry: its act does not take place. A revoke command is
  the one call the node answers for the account: with the signed reply of a revoke, as for
  an account without a grant, and without an entry. What a revoke asks of a node is so: the
  node holds no user key of the account and takes none. The app of the account counts its
  delegation as withdrawn when every living node answered the revoke with its signed reply,
  and without this answer it could not while this node lives. `peer/export` and
  `grants/prune` pass the account by. The delegation of the account on the other nodes is
  untouched, and this node holds it again only as another node: after its enclave was
  replaced. The lock of an account is held around changes of its state and never across a
  wait, and no lock of another account is taken under it: a panic under it leaves the state
  of no other account in doubt.
- The process ends on a panic under a lock of state of the whole node, at the next call that
  asks for that lock: the index of the accounts, the operator configuration, the credentials
  for the log store, the issued challenges, the authorizations in progress, the idle
  connections to the providers and to the log store, the IMAP sessions kept between the reads of
  a record, the numbers of the envelopes a node of the forward role used, and the nodes of the
  forward role a node verified (`NodeLock`, `NodeRwLock`). Every account depends on that state,
  and the node has no smaller part to give up. These locks are held around a change of a map or
  of a list and around nothing else: no byte of a call is read under one. The process ends at
  once on a panic of one of three tasks: the task that starts the node and accepts its
  connections, the task that corrects the clock and the task of the sweep (`faults::vital`). A
  node that went on without one of them would break a rule in silence. Each sweep and each
  correction runs on a task of its own, so a panic inside one of them is not a panic of these
  three, and the node keeps its sweep and its clock: a sweep that panicked confirmed no entry
  the store did not confirm and halted the account under whose lock it panicked, and the clock
  takes a correction in one step, at the end of the correction. A fault that makes every sweep
  or every correction panic shows as a count of `contained_panics` that grows with each of them.
  The lock around the descriptor of the attestation device guards no state, and it is used as it
  is after a panic under it.
- A second panic while a first one unwinds ends the process: a value that gives back what a
  call held panicked itself, and the standard library does not unwind out of that.
- No panic writes anything of a call (rule E5 of egress-policy.md): the panic hook of the
  node counts the panic and has no output. The one line a panic can leave is a line of the
  standard library, when a second panic ends the process: a fixed string on the standard
  error, without the message or the place of either panic. `contained_panics` of `load` of
  health is the count of the hook, and `halted_accounts` the number of accounts the node
  halted (5.1).
- What this section does not cover: a node that runs out of memory or of stack ends as before.

## 4. The common rules of the call surface

- Transport: HTTP/1.1. On nitro the node listens on vsock port 8080, on local on TCP 8080. The host
  program moves TCP 8080 inside the cluster to the vsock listener (section 9).
- The caller is the operator domain (its backend processes). A node does not trust its caller: a
  decision rests on the grant of the account, on the AEAD authentication of a record and on the
  provider definitions, and on nothing else.
- Bodies: `POST /v1/forward` and `POST /v1/forward/batch` take and return a frame (5.8), and
  `POST /v1/vault/send` takes a frame and returns a stream (5.16). Every other body is
  `application/json`.
- The role of a node. A node of this program takes one of two roles, the delegation role or the
  forward role (protocol.md 4.1), and answers the calls of its own role. `health`, `config`, `attestation` and `close` are calls of either
  role: none of them reads or changes a delegation, a record or the log of an account.
  `vault/send` is the call of the forward role. Every other call is a call of the delegation
  role. A node starts without a role and takes one once: the forward role with an operator
  configuration that names it (5.1), the delegation role with the first call of that role or
  with an operator configuration that names no role. A call of the other role than the role of
  the node is `not_allowed` (403), before the node reads anything of the request: a node of the
  forward role takes no command, no delegation transfer and no call that opens a record, so no
  call can make it hold a user key, and a node that holds delegations sends no request to a host
  that is not an address of its definitions. A node without a role refuses `vault/send` the
  same way.
- A success is 200. A failure is one of the statuses below with the body
  `{"code":"<code of protocol.md section 11>","message":"..."}`. `message` is a fixed string of the
  source. The failures `exchange_failed` and `refresh_failed` carry two more keys,
  `provider_status` and `provider_error` (5.7).

| Status | Codes |
| --- | --- |
| 400 | `invalid_request`, `unsupported_version`, `bad_challenge`, `bad_signature`, `user_mismatch`, `wrong_node`, `open_failed`, `bad_expiry`, `unsupported_policy`, `custody_mismatch` |
| 403 | `not_allowed`, `peer_unverified` |
| 404 | `provider_unknown`, `state_unknown` |
| 409 | `grant_required`, `grant_revoked`, `grant_expired`, `key_mismatch` |
| 413 | `too_large` |
| 422 | `record_invalid` |
| 500 | `internal` |
| 502 | `exchange_failed`, `refresh_failed`, `provider_unreachable`, `response_withheld` |
| 503 | `not_configured`, `closing`, `log_store_unavailable`, `capacity_unavailable` |
| 504 | `timeout` |

A path that is not defined is 404, and a method that a path does not accept is 405. Both have the
code `invalid_request`. `user_mismatch` is 400 also when the account of a record does not match
(protocol.md section 6). A JSON body is accepted up to 1 MiB, and a longer one is `too_large`. A
body whose bytes stop arriving for 60 seconds (`inbound_idle`, section 8) is `invalid_request`
with the message `the request body did not arrive within the time limit`, and the connection
ends after that response. A request head above 32 KiB is answered with the status 431 by the
HTTP connection, before a call sees it. The responses of a node carry no `Date` header (it
would be a value of the system clock). A call that ends with `internal` performed no act: the
platform failed before the act (the random source, the attestation device), or the call names
an account the node halted (3.1). A call whose connection ends without a response may have
performed its act: the node ended, or the call panicked (3.1).

- The common front of the calls that use a credential (`forward`, `forward/batch`, `refresh`,
  `revoke-token`, `release`, `vault/store`, `vault/handoff`, `oauth/complete`, the mail calls):
  (1) the node is not `closing`. (2) The operator configuration is present (`release`,
  `vault/store` and `vault/handoff` are the exceptions). (3) The node can write to
  its log store, and the account has fewer than 64 pending entries (5.14. A node of platform
  `local` without a log store passes. An account the node holds no state of fails before this
  step, with `grant_required`). (4) The grant of the account is Active and within its time. (5)
  The node opens the record (protocol.md section 6. `oauth/complete` and `vault/store` create a
  record and have no step 5). `oauth/merge` passes (1), (4) and (5) only (it creates no event and calls no provider).
  `oauth/begin` passes (1), (2) and (4).
- A command (`messages`) is not stopped by the limit of (3): a revocation must always be possible.
  The entries of commands and of delegation transfers can raise the pending entries of an account
  above 64.
- The event, the log store and the act. A call that creates an event puts it into the open batch
  of the account or into a control entry of its own (protocol.md 7.1), and performs its act only
  after the store confirmed the entry that holds the event (protocol.md 7.6 names the act of every
  call). When the store does not confirm it, the call ends with `log_store_unavailable` (503) and
  the act does not take place.
- A call that creates an event carries in its response the object `log`: `{"seq": the seq of the
  entry that holds the event, "index": the index of the event in that entry (0 based), "created":
  true}`. A call that merges into an event of the open batch or of an earlier entry carries the
  `log` object of that event with `"created": false`. A call that creates no event (`oauth/merge`,
  a revoke of an account without a grant, a refused grant) carries null. A forward batch carries
  one `log` object per request. The entry itself is not carried: the log store is the place an
  entry is read from. A failure response carries no `log` object: the entry of a call whose
  provider call failed after the event was created is on the chain all the same.
- From step (4) of the front to the creation of the event, a call runs inside the lock of the
  account. So a call either fails on the state of the grant, or its event is on the chain before
  the entry of a later revoke: a revoke that is answered before a call reaches this part leaves no
  request of that call behind it. The write to the log store and the act follow outside the lock.

## 5. The calls

### 5.1 `GET /v1/health`, `POST /v1/config`

```json
GET /v1/health -> {"node":"...","release":"v2.1.0","platform":"nitro","custody":"enclave","role":"forward"|null,"started_ms":0,"time_ms":0,"configured":true,"closing":false,"accounts":0,"grants":0,
                   "mail_providers":["naver_mail"],
                   "log_store":{"bucket":"...","region":"...","shards":32,"credentials_expires_ms":0,"node_document_ms":0,"pending":0,"pending_oldest_ms":0}|null,
                   "log":{"entries":0,"events":0,"writes":0,"write_failures":0,"open_batches":0,"batch_calls":0,"batch_requests":0,
                          "write_attempt_failures":{"connect":0,"tls":0,"closed":0,"timeout":0,"status_4xx":0,"status_5xx":0},"write_retries":0,
                          "write_ms_buckets":{"25":0,"50":0,"100":0,"250":0,"500":0,"1000":0,"2500":0,"5000":0},"write_ms_sum":0,"write_count":0},
                   "load":{"provider_inflight":0,"forward_calls":0,"inbound_connections":0,"inbound_refused":0,"inbound_limit":0,"cpu_user_ms":0|null,"cpu_system_ms":0|null,"cpu_idle_ms":0|null,"memory_total_bytes":0|null,"memory_available_bytes":0|null,"descriptors_open":0|null,"descriptors_limit":0|null,"lingering_connections":0|null,"lingering_cut":0|null,"contained_panics":0,"halted_accounts":0},
                   "egress":{"opens":0,"open_failures":{"transport":0,"relay_refused":0,"tls":0,"http":0},"open_retries":0,"open_inflight":0,"idle_reuses":{"provider":0,"log_store":0,"mail":0}},
                   "refresh":{"late":{"kept":0,"dropped":0,"failed":0,"abandoned":0},"late_inflight":0},
                   "state":{"kept_refreshes":0,"merge_keys":0,"pending_entries":0,"idle_connections":{"provider":0,"log_store":0,"mail":0}}}
POST /v1/config {"providers":{"google_workspace":{"client_id":"...","client_secret":"...","redirect_uri":"https://.../api/integrations/google_workspace/oauth/callback","publishable_key":""}, ...},
                 "log_store":{"bucket":"...","region":"...","endpoint":"http://host:port"}}
             -> {"configured":true,"node_document_ms":0}
POST /v1/config {"role":"forward"}
             -> {"configured":true,"node_document_ms":0}
```

- `role` of `health` is `forward` on a node that took the forward role, and null on every other node
  (section 4). `role` of the configuration names the role of the node: its one value is `forward`,
  and a configuration without the key is the configuration of a node of the delegation role. A node
  takes its role once. The configuration of a node of the forward role is `{"role":"forward"}` and
  nothing else: with `providers` or `log_store` beside the role it is `invalid_request`. A node of
  the forward role holds no client value of a provider, connects to no token address and has no log
  store, so its `health` reports `log_store` null, it writes no node document (protocol.md 7.7), and
  `node_document_ms` of the answer to its configuration is 0. A configuration of the other role than
  the role the node has is `invalid_request` and changes nothing: a node that took a call of the
  delegation role does not become a node of the forward role, and a node of the forward role takes
  no client value.

- `accounts` of `health` is the number of accounts this node created an entry for (a `seq` of at
  least 1). `grants` is the number of accounts that have a grant within its time (the operator
  domain reads this value to see that a delegation transfer arrived). A node that took the grant of
  an account from a node of its own measurement holds that grant before it created an entry for the
  account: `grants` counts it and `accounts` does not. Both are counts the node keeps with the state
  (section 3): a health call locks no account, and its time does not grow with the number of
  accounts. A grant whose time passed is counted until the first read of the account or the sweep
  ends it, at most one sweep interval (30 seconds) after its end.
- `log_store` of `health` is null on a node without a log store. Otherwise it names the bucket of
  the binding and its region, the number of buckets the node writes its entries to (`shards`, a
  constant of the bucket name: protocol.md 7.6), the end of the credentials the node holds
  (`credentials_expires_ms`, 0 when it holds none), the node time of the latest write of the node
  document that the store confirmed (`node_document_ms`, 0 when it confirmed none: such a node takes
  no user key, 5.14), the number of accounts that have an entry the store has not confirmed
  (`pending`, a count kept with the state) and the age of the oldest pending entry in milliseconds
  of node time (`pending_oldest_ms`). The age is computed from the oldest pending entry the last
  sweep of the node found (section 3): it grows with the node time until the next sweep, it is 0
  when that sweep found no pending entry or no sweep ran yet, and the set of entries it stands for
  is up to 30 seconds old. The endpoint of a node of the local platform is not reported.
- `state` of `health`: the sizes of the variable state of the accounts at the moment of the
  call, each a count kept with the state (section 3). `kept_refreshes` is the number of kept
  `refresh` responses over every account (5.7), `merge_keys` the number of merge keys over every
  account (protocol.md 7.2), `pending_entries` the number of entries the log store has not
  confirmed over every account, and `idle_connections` the number of idle connections the node
  keeps at this moment, to the providers over every account and host (`provider`, 5.8 step 8),
  to the log store (`log_store`, 5.14), and the authenticated IMAP sessions it keeps between
  the reads of a record (`mail`, "Mail call surface"). The operator domain reads these values
  to tell the memory of the delegation state from the memory of the variable state.
- `log` of `health`: counts since the node started. `entries` is the number of entries the node
  created, `events` the number of events in them, `writes` the number of attempts to write an
  entry or the node document to the log store (`PUT` requests, confirmed or not: an object the
  store did not confirm at the first attempt is counted once per attempt, 5.14),
  `write_failures` the number of entries, and of writes of the node document, whose attempts
  ended without a confirmation within their budget, `open_batches` the
  number of accounts whose open batch is not empty at this moment, `batch_calls` the number of
  `forward/batch` calls that passed the common front, and `batch_requests` the number of
  requests in them. `write_attempt_failures` counts the attempts the store did not confirm by
  cause: `connect` (the byte pipe, the egress relay or the HTTP/1.1 handshake failed, or the
  request could not be built), `tls` (the TLS handshake failed), `closed` (the connection closed
  without a response), `timeout` (the attempt passed its time limit), `status_5xx` (a 5xx status
  or 429) and `status_4xx` (every other status that is not 200). `write_retries` is the number
  of attempts that followed a failed attempt. `write_ms_buckets` are cumulative counts of the
  confirmed attempts by their time from the start of the attempt to the status 200: the count
  under a key is the attempts that took at most that many milliseconds, so every attempt counted
  under `25` is counted under `50` and every larger key as well. `write_ms_sum` is the sum of
  those times in milliseconds and `write_count` the number of confirmed attempts (the count of
  every bucket above the longest time). All values of `log` are integers.
- `egress` of `health`: the outbound connections of the node (5.14 for the rules of an open).
  `opens` is the number of connections that were opened since the node started, `open_failures`
  the number of failed attempts to open one, by cause (`transport`: the byte pipe of the platform
  could not be opened; `relay_refused`: the egress relay of the parent refused the host and the
  port; `tls`: the TLS handshake failed; `http`: the HTTP/1.1 handshake failed), `open_retries`
  the number of attempts that followed a failed attempt, `open_inflight` the number of
  connections being opened at this moment (the taken places of the bound of section 8), and
  `idle_reuses` the number of requests that went over an idle connection instead of a new one,
  to a provider (`provider`, 5.8 step 8) and to the log store (`log_store`, 5.14), and the
  number of mail reads that went over a kept session instead of a new connection and a login
  (`mail`, "Mail call surface").
- `refresh` of `health`: the token address calls of `refresh` the node continued after their time
  limit (5.7). `late` counts them since the node started by outcome: `kept` (the late success
  became the kept response of its record), `dropped` (the late success was not kept: the grant
  had ended, a revoke or a grant of another key arrived, or the node was closing), `failed` (the
  late call ended with a refusal of the provider, a transport failure or the late limit) and
  `abandoned` (the call found no free place at its time limit and was ended there).
  `late_inflight` is the number of late calls in progress at this moment.
- `load` of `health`: the load of the node at the moment of the call. `provider_inflight` is the
  number of provider requests in flight (the taken places of the node-wide bound of section 8), and
  `forward_calls` the number of calls that hold one of the places of the bound of concurrent
  `forward` and `forward/batch` calls (`forward`, `forward/batch`, the mail calls and, on a node of
  the forward role, `vault/send` take one each). `cpu_user_ms`, `cpu_system_ms` and `cpu_idle_ms`
  are the CPU time of the kernel the node runs in, over all its processors, since that kernel
  booted, in milliseconds: the first line of `/proc/stat` (`user` and `nice`; `system`, `irq`,
  `softirq` and `steal`; `idle` and `iowait`), at the clock ticks per second that the auxiliary
  vector of the node process states (`AT_CLKTCK` of `/proc/self/auxv`). `memory_total_bytes` and
  `memory_available_bytes` are `MemTotal` and `MemAvailable` of `/proc/meminfo`, in bytes. The node
  reads the three files at every call. Each of the five values of the kernel is null when the kernel
  exposes no procfs value (a kernel without procfs, or a development machine that is not Linux); the
  two counts are always numbers. `inbound_connections` is the number of connections from the backend
  the node holds open at this moment, `inbound_refused` the number of connections it closed at
  accept because its bound of open connections was reached, since it started, and `inbound_limit`
  that bound: the node computed it at its start from the memory of its kernel (section 8).
  `descriptors_open` is the number of open file descriptors of the node process (the entries of
  `/proc/self/fd`, null when the kernel exposes none) and `descriptors_limit` the soft limit of
  open file descriptors in force (null when the platform has no such limit): the limit the
  node raised at its start (section 8), or the limit the kernel gave it when the kernel refused
  the raise. The operator domain reads the two to see a node that approaches its limit.
  `lingering_connections` is the number of connections the node is done with and keeps open
  until their peer reported the end of its bytes, at this moment, and `lingering_cut` the
  number of connections it closed before that end, since it started (section 8). Both are
  null on the local platform, which closes a connection when the node is done with it.
  `contained_panics` is the number of panics of the node program since it started: each of
  them ended a call, a connection, a sweep or a correction of the clock, or halted an account,
  and none of them ended the node (3.1). `halted_accounts` is the number of accounts the node
  halted since it started: an account stays halted for as long as the node lives. A node whose
  `halted_accounts` is not 0 serves those accounts again after its enclave was replaced.
- `log_store` of `config` names the log store of the node (protocol.md 4.1 gives the form of the
  two names. Another form is `invalid_request`). The key is optional. A node takes a log store
  once: a later configuration that names the same log store, or none, leaves it in place, and a
  configuration that names another one is `invalid_request` and changes nothing, also not the
  client values. From the call that named it, the binding of the attestation responses of the
  node carries it as `log`. A node of the local platform also takes an optional `endpoint` in
  `log_store` (5.14): an `http://host:port` or `https://host:port` origin it writes to in
  path-style, set once with the log store. A node of the nitro platform refuses a configuration
  with `endpoint` (`invalid_request`), and a value that is not such an origin is `invalid_request`
  on both platforms. A bucket name of more than 49 characters is `invalid_request` as well: the
  buckets the node writes to carry that name between a hash and a number, and their names would
  not be bucket names (protocol.md 7.6). A node that holds credentials for its log store writes
  its node document in this call when it is due (5.14). `node_document_ms` of the response is
  the node time of the latest write of the document that the store confirmed, 0 when it
  confirmed none or the node has no log store.
- The host program sends `config` after the boot. A repeated call replaces the whole
  configuration of the client values. A provider name that has no definition (section 6) and a `redirect_uri` that is
  not https are `invalid_request`. The local platform also accepts a `redirect_uri` that starts
  with `http://localhost`. A `redirect_uri` is at most 2,048 bytes long and holds no whitespace and
  no control character. A missing `client_id`, `client_secret` or `publishable_key` is read as the
  empty string.
- When the configuration does not list a provider, or the `client_id` of a provider whose `client`
  is `static` is the empty string, the calls `oauth/begin`, `oauth/complete`, `refresh` and
  `revoke-token` of that provider are `not_configured` (`forward` and `release` do not use the
  client values of the operator configuration).
- The operator configuration is a secret of the operator, so it is not sealed. The configuration
  can change the client values and the callback address of a provider, and nothing else: the
  address lists and the token addresses are in the definitions, which are part of the measurement.

### 5.2 `POST /v1/attestation`

```json
{"nonce":"<b64u 32 bytes>"} -> the response of protocol.md 4.2
```

The nonce is 16 to 64 bytes long. Every call issues a new `challenge`. The response carries
`challenge_statement` (protocol.md 4.2): the signature of the node over that challenge and the
nonce of the call. The field is present on both platforms.

### 5.3 `POST /v1/messages`

```json
{"user_id":"...","envelope":{...}}
-> {"reply":{"body":"...","sig":"..."},"log":{"seq":1,"index":0,"created":true}|null,"grant":{"state":"active","key_id":"...","custody":"enclave","not_after_ms":0}}
```

The processing is that of protocol.md 5.3 and 5.4. A command that fails is answered with 200 as
well, and `ok` of `reply` is false (the app receives a signed failure). That includes a grant
that the node refuses with `log_store_unavailable`: before the challenge is used when the node
cannot write to its log store, and after the entry `grant_accepted` was created when the store
did not confirm it (`log` of the response is null, and the entry is a pending entry). `log` names
the control entry the command created (a grant that put a user key into the node, a revoke of an
account with a grant) and is null for a command that created none: a grant that renewed the grant
in force among them (protocol.md 5.3, step 13a). The reply carries no head (protocol.md 5.5). The
responses other than 200 are a violation
of the form of the call itself (`invalid_request`), `closing`, and `internal`: a failure of the
platform, or a grant for an account the node halted (3.1). A revoke for such an account gets
the reply of a revoke for an account without a grant, and the `grant` of the response is `none`. `grant` is the plaintext copy that the caller (the backend) reads:
the state of the account that the call named, after the processing. `state` is `active`, `none` or
`revoked`, and a grant whose time has passed is reported as `none`. `key_id`, `custody` and
`not_after_ms` have values in the state `active` only, and `revoked` has `key_id` only. `custody`
is the custody of the platform of that node.

### 5.4 `POST /v1/status`

```json
{"user_id":"..."} -> {"grant":{"state":"active|none|revoked|expired","key_id":"...","custody":"enclave","not_after_ms":0}}
```

The call reports the delegation state of the account on this node. A `user_id` without account
state receives `none`, and the call for an account the node halted ends with `internal` (3.1). The state `expired` carries `key_id` and `not_after_ms`. The call signs
nothing: a node keeps no head (protocol.md 7.3). A request can carry other keys (a caller of a
release before v2.4.0 sends `nonce`): the node does not read them.

### 5.5 `POST /v1/oauth/begin`

```json
{"user_id":"...","provider":"google_workspace","operator_state":"...","params":{"scope":"...","login_hint":"..."},"client_id":""}
-> {"authorization_url":"https://...","state":"...","statement":{"body":"...","sig":"..."},"expires_ms":0}
```

`operator_state` has the form of protocol.md 8.1 (otherwise `invalid_request`).

1. Steps (1) to (3) of the common front. The provider has a definition (`provider_unknown`) and
   client values in the operator configuration (`not_configured`).
2. Every key of `params` is in `authorize.allowed` of that definition, and every value is a string
   of at most 1,024 characters without a control character. When the definition has `scopes`,
   every value of the scope parameter (`scope_param` of the definition, split at
   `scope_delimiter`) is on that list. A violation is `not_allowed`.
3. `client_id`: when `client` of the definition is `static`, the node uses the value of the
   operator configuration, and the `client_id` of the request must be the empty string. When it is
   `dynamic`, the node uses the value of the request (1 to 256 characters without a control
   character). A violation is `invalid_request`.
4. The node creates `node_state` (16 random bytes) and, when `pkce` of the definition is `S256`,
   `code_verifier` (the b64u of 32 random bytes, 43 characters).
5. The node assembles the authorization address. The order of the query parameters is fixed as
   below, and the values are percent-encoded by RFC 3986 (every byte outside the unreserved
   characters, a space is `%20`):
   `response_type=code`, `client_id`, `redirect_uri`, `state`, (`code_challenge`,
   `code_challenge_method=S256`), `authorize.fixed` of the definition (in the order of the
   definition), `params` (in the lexical order of the keys). When the definition has
   `authorize.key_param`, the `publishable_key` of the operator configuration is added under that
   name after the fixed pairs.
6. The node keeps the pending authorization for 600 seconds. It signs the statement `oauth_begin`
   (protocol.md 8.2).

The PKCE verifier stays in the node. Of the verifier, only its S256 challenge leaves, inside the
authorization address.

### 5.6 `POST /v1/oauth/complete`, `POST /v1/oauth/merge`

```json
complete {"user_id":"...","state":"...","code":"..."}
      -> {"record":{...},"public":{...},"statement":{"body":"...","sig":"..."},"log":{"seq":1,"index":0,"created":true}}
merge    {"user_id":"...","record":{...},"previous":{...}}
      -> {"record":{...},"public":{...}}
```

complete:

1. The node finds the pending authorization by the part of `state` before the first `.`
   (`node_state`) and removes it (it is used once). When there is none, or its time has passed, the
   call fails with `state_unknown`. When the `user_id` of that authorization is not that of the
   request, it fails with `user_mismatch`. When the whole `state` of the request does not equal
   the `state` that the node issued for that authorization, it fails with `state_unknown` (the
   authorization is already removed). `code` is 1 to 4,096 bytes long (`invalid_request`).
2. The common front. The `sign_pk` of the grant must equal, in all 32 bytes, the `sign_pk` at the
   start of the authorization (otherwise `key_mismatch`. protocol.md 8.2).
3. The node calls the token address (6.3). A failure is `exchange_failed`, and the body carries
   `provider_status` (the HTTP status of the provider, 0 for a transport failure) and
   `provider_error` (the rule of 5.7).
4. The node creates the record: a new `id`, kind `oauth`, the plaintext
   `{"token": the response, "obtained_ms": now}` (with `"client_id"` for a dynamically registered
   client). The public fields (6.4) are computed first: when they fail the containment check, the
   call fails with `response_withheld`, and no record, no public field and no event leaves.
5. The node creates the control entry `connection_created` (the open batch of the account is
   closed before it) and writes it to the log store. After the store confirmed it, the node
   returns the record, the `log` object of the entry, the statement `oauth_complete` and the
   public fields (6.4). When the store does not confirm the entry, the call fails with
   `log_store_unavailable`: the record is dropped inside the node, and the pending authorization
   was used, so the connection is started again. A node that cannot write to its log store (it
   has none, or no credentials within their time) ends the call before step 1: the pending
   authorization stays and the code is not spent, so the same call passes once the node can
   write.

merge moves the `refresh_token` of the old record when, in a reconnect, the new response has none
(protocol.md 8.3). The node opens both records (both are of kind `oauth`, otherwise `not_allowed`).
Their providers must be equal (otherwise `invalid_request`). The node returns the new record,
encrypted again under the `id` of the new record, and its public fields. merge creates no event.
It works without the operator configuration and is not stopped by the limit of pending entries
(section 4).

### 5.7 `POST /v1/refresh`, `POST /v1/revoke-token`

```json
refresh      {"user_id":"...","record":{...},"context":"..."} -> {"record":{...},"public":{...},"log":{"seq":1,"index":0,"created":true}}
revoke-token {"user_id":"...","record":{...},"context":"..."} -> {"revoked":true,"log":{"seq":1,"index":0,"created":true}}
```

- Both calls take a record of kind `oauth` or `oauth_imported` (otherwise `not_allowed`).
- refresh: when the token place of the plaintext of the record has no `refresh_token`, the call
  fails with `record_invalid`, without an event and without a provider call (on this code the
  backend marks the connection as one that needs a new authorization). When there is one, the node
  creates the use event `credential_refreshed` (into the open batch of the account), waits until
  the store confirmed the entry that holds it (the group commit of section 3), calls the token
  address with `grant_type=refresh_token` after that, and creates the new record of the same `id`
  and the same kind by the merge rules (protocol.md 8.3). When the provider refuses, the call fails
  with `refresh_failed`, and the body carries `provider_status` and `provider_error`.
- `provider_error` is a word of a closed vocabulary, `other`, or the empty string. The node reads
  the error strings of the provider response, in this order: when the response is a JSON object,
  a string `error`; for an object `error` its string `code` and then its string `message`; and,
  when none of those is a non-empty string, the top-level string `code`. It compares each of them
  with the list of rule E5 of egress-policy.md. What leaves is the first element of the list that
  equals one of them, the empty string when the response has no such string, and `other`
  otherwise. Each of them is a constant of the source: no byte of a refused response leaves the
  node. The backend decides from that word whether the connection needs a new authorization.
- The time limit of the token address call of a refresh is 15 seconds (`token_timeout` of
  section 8). A call that does not answer within it fails the call with `refresh_failed` and
  `provider_status` 0, and the node keeps receiving that response for up to 120 seconds from the
  start of the call (`token_late_limit`). When the response is a success, and the grant the call
  ran under is still in force (the rule of the kept response below) and the node is not closing,
  the node keeps it as the kept response of that record: the next `refresh` of the same record
  within 3,600 seconds returns it, with the `log` object of the entry of the first call. A late
  response that is a refusal, a transport failure, or a success after a revoke, an expiry, a grant
  of another key or `close`, is dropped inside the node. At most 128 such calls go on at once
  (`refresh_late_tasks`); a call that finds no free place at its time limit ends its token
  address call there. The counts of these calls are `refresh` of health (5.1). The entry
  `credential_refreshed` of a late call is the entry of the call that started it: a late call
  creates no entry.
- The kept response of a refresh: a node keeps the response of a successful `refresh` for 3,600
  seconds, per account, the 16 most recent ones, under the SHA-256 of the `ct` of the record that
  was sent. A repeated `refresh` of the same record by the same account passes the common front
  and the opening of the record, and then returns the kept response as it is (its `log` object
  names the event of the first call): the node calls no provider and creates no event. A revoke
  command, the expiry of the grant, and a grant of another signing key drop the kept responses. A
  response is not kept when the grant under which the refresh ran is no longer in force at the
  end of the call. The reason for keeping a response: a provider that rotates refresh tokens
  invalidates the old token at the first call, so a response that never reached the caller would
  end the connection.
- revoke-token: the node creates the control entry `connection_removed` (the open batch of the
  account is closed before it) and writes it to the log store. After the store confirmed it, the
  node calls the revocation address, when the definition has `revoke` and the plaintext of the
  record has a token (`token` = the refresh token when there is one, else the access token, with
  its `token_type_hint`. The time limit is 5 seconds). `provider_revoke` of the event says whether
  the node makes that call (protocol.md 7.2), and `revoked` of the response is the outcome of the
  call: one bit, true for a 2xx status. A provider without a revocation address and a failed
  revocation call are not errors: the response says `revoked: false`.

### 5.8 `POST /v1/forward`

The frame (of the request body and of the response body):

```text
frame = meta_len (unsigned 32 bit, big-endian) || meta (UTF-8 JSON, meta_len bytes) || payload (all the rest)
Content-Type: application/vnd.pickle.frame
```

```json
request meta:  {"user_id":"...","record":{...},"method":"GET","url":"https://host/path?query","headers":[["name","value"],...],"context":"...","timeout_ms":30000}
response meta: {"status":200,"headers":[["name","value"],...],"log":{"seq":1,"index":0,"created":true}|null}
```

The payload of the request is the body to send to the provider. The payload of the response is the
body that the provider returned, as the provider sent it: the node asks for the encoding
`identity`, decodes nothing, and does not return a body of another encoding (step 10).

The response has one of two forms, and the caller chooses with `stream` of the request meta.
Without the key, and with `false` or `null`, the response is the frame above: the node reads
the whole body of the provider into memory, at most 64 MiB of it, checks the response as a
whole and answers with the meta and the body. With `"stream": true` the response is a stream:
the head of the provider response first, and its body in parts while it arrives (step 11). A
body that is handed on as a stream has no limit.

```text
stream = meta_len (unsigned 32 bit, big-endian) || meta (UTF-8 JSON, meta_len bytes) || part* || end
part   = part_len (unsigned 32 bit, big-endian, 1 to 1,048,576) || part_len bytes of the body of the provider
end    = 0 (unsigned 32 bit) || end record (UTF-8 JSON, all the rest)
Content-Type: application/vnd.pickle.stream
```

```json
stream meta: {"status":200,"headers":[["name","value"],...],"log":{"seq":1,"index":0,"created":true}}
end record:  {"complete":true} | {"complete":false,"code":"response_withheld","message":"..."}
```

A node of a release before v2.4.0 does not know the key: it passes over it and answers with a
frame. So a caller that asks for a stream reads the `Content-Type` of a 200 response to learn
which form it holds. The order of the processing:

0. The frame: meta is a JSON object of at most 1 MiB (a longer meta, and a meta that is no object,
   is `invalid_request`). A payload above 64 MiB is `too_large`. `stream` is a boolean (another
   value is `invalid_request`). A `timeout_ms` that is not an integer from 1,000 to 120,000 is
   `invalid_request` (when it is omitted, it is 30,000). For a call that asks for a stream the
   range is 1,000 to 600,000: the time limit of such a call reaches to the end of the body. The
   call takes one of the 512 places of the forward calls and the share of the body budget its
   request frame occupies before it reads the frame, and waits for the two together for at most
   30 seconds (`ADMISSION_WAIT`, section 8): a call that has not got them by then ends with
   `capacity_unavailable`, having read nothing, created no entry and sent nothing.
1. The common front. The kind of the record is `oauth` or `oauth_imported` (any other kind is
   `not_allowed`).
2. The address check (section 7). A violation is `not_allowed`.
3. The method is one of `GET`, `POST`, `PUT`, `PATCH`, `DELETE` (any other is `not_allowed`).
4. The header check: a name holds token characters only, and a value holds no control character
   (CR and LF included). A violation is `invalid_request`. A value can hold characters outside
   ASCII and is sent as UTF-8. A header name is compared in lower case and with `-` for every
   `_` (some servers read the two as one character). A call with a header named
   `x-http-method-override`, `x-http-method` or `x-method-override` is
   refused with `not_allowed`: such a header asks a provider to treat the request as one of
   another method than the method the request is sent with, which is the method the entry of
   step 6 names. The node refuses the call. It does not drop the header and send the rest. The
   node drops the names below and the name that equals `inject.header` of the definition:
   `authorization`, `proxy-authorization`, `cookie`, `host`, `content-length`,
   `transfer-encoding`, `connection`, `keep-alive`, `upgrade`, `te`, `trailer`, `expect`,
   `accept-encoding`, `range`, `if-range`, `accept-charset`. Without `Range` and `If-Range` the
   node asks for the whole of a response: the response check of step 10 reads what one
   response holds. Of a response that held the injected credential, two parts that a caller
   asked for one by one would each pass that check, and a response of several ranges
   (`multipart/byteranges`) holds its parts with other bytes between them. A provider that
   honours a range answers the request without one with the whole representation, so a
   caller that names a range receives the status 200 and the whole body, and a body of any
   length is handed on as a stream (step 11). Without `Accept-Charset` the node asks for no
   character encoding of a response: the check of step 10 reads bytes, and in UTF-16 the
   bytes of a credential are not the bytes it looks for. An `Accept` header can ask for the
   same with a `charset` parameter, so a call with an `Accept` header in which the word
   `charset` (in any case of its letters) is followed by anything but `=` and `utf-8` or
   `utf8` (with or without quotes and blanks) is refused with `not_allowed`, before an entry
   is created.
5. The merge decision (protocol.md 7.2): a GET request without a body that matches an event of
   the open batch or of an entry created less than 300 seconds before shares that event. In case
   of a merge the call continues at step 8 without an event of its own, once the log store
   confirmed the entry that holds the event: when that entry is a pending entry, the call writes
   it again, and it fails with `log_store_unavailable` when the store does not confirm it. A
   request with a body is never merged. The merge window of an account is cleared by a revoke, an
   expiry and a grant of another key (protocol.md 7.2).
6. The node creates the event `provider_request` (its `time_ms` is now) and puts it into the open
   batch of the account. The event names the request that step 8 sends: its method, its host,
   its whole path and its whole query, and the size and the SHA-256 of its body. When no writer
   is active for the account, the call closes the batch into an entry and writes it (5.14);
   otherwise it waits for the writer (section 3). The call continues when the store confirmed the
   entry that holds its event. Otherwise the call fails with `log_store_unavailable` and no
   request is sent.
7. (Stage 2) The node obtains the witness signatures.
8. The node assembles the request and sends it: `Host`, then `Content-Length` when there is a body
   or the method is `POST`, `PUT` or `PATCH`, then the credential header made by the injection
   rule of the definition, then `Accept-Encoding: identity`, then the headers of the caller, then
   `Connection: keep-alive`. The node keeps at most 8 idle connections per (account, host), each
   for at most 30 seconds, and a request of an account goes over an idle connection of that
   account and host when there is one. No connection carries requests of two accounts, and a
   connection whose response said `Connection: close` is not kept. A request over an idle
   connection that ends without a response goes once more over a new connection when its method
   is `GET` or `HEAD`; a request of another method is not repeated (`provider_unreachable`:
   whether the provider received it is unknown). Every provider request takes one of the 512
   places of the node-wide bound of provider requests in flight (section 8). The node follows no
   redirect (a 3xx response is returned as it is). A response with `Transfer-Encoding: chunked`
   is returned decoded. The node sends no `TE` header, and a response under any other transfer
   coding fails the check of step 10. The hop-by-hop headers of the response (`connection`,
   `keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`, `trailer`,
   `transfer-encoding`, `upgrade`, and the names that its `Connection` header lists),
   `Set-Cookie` and `Set-Cookie2` are left out.
9. The time limit is `timeout_ms` (`timeout`). A transport failure is `provider_unreachable`, and
   a response body above 64 MiB is `too_large`.
10. The response check (rule E4 of egress-policy.md, `enclave/src/provider_response.rs`). A
    response with a `Content-Encoding` other than `identity`, or with a transfer coding other than
    `chunked`, fails the check: the node does not hand on a body it cannot search. The two
    headers are read as they arrived, before the headers that the `Connection` header of the
    response lists are left out (step 8), and a response under an instance manipulation (RFC
    3229: the status 226, or a header `IM`) fails the check as well. A response
    fails the check when a header name, a header value or the body holds the injected credential
    (the token without the prefix of the definition). Each of the three is read as it was
    received, with its percent escapes decoded (up to three times, for a value that was
    encoded more than once) and with its JSON string escapes decoded (up to twice, for a JSON
    text inside a JSON string), and each reading is searched for the credential as it is, in
    base64 or base64url (each of the three byte alignments, without padding) and in hexadecimal
    (lower or upper case). A header whose bytes are not UTF-8 is searched as those bytes as well. A form shorter than 8 bytes is not searched for. A failed check is
    `response_withheld`: no part of the response leaves. The event `provider_request` is already
    on the chain, because the request went to the provider.
11. A call that asked for a stream. Steps 8 and 9 run up to the head of the provider response:
    a failure before it (`timeout`, `provider_unreachable`) is the failure of the call, a
    JSON failure as for a frame. The head passes the checks of step 10 before the status 200
    leaves: a response under a `Content-Encoding` other than `identity` or a transfer coding
    other than `chunked`, and a response whose header names or header values hold the
    injected credential, is `response_withheld`, and no stream begins. Then the node answers
    200 with the stream meta, and a task hands the body on: every part of the body goes
    through the search of step 10 (`provider_response::StreamCheck`) before it leaves. The
    search decodes each reading of step 10 part by part, from the first byte of the body, and
    searches it together with its last bytes from the part before. It holds back the last
    bytes it received, as many as one byte more than the longest form of the credential can
    take in a reading (36 bytes for each of them), and hands on the bytes in front of them
    once a search found no form of the credential (it searches when 4,096 new bytes have
    arrived, or four times the length of the longest form when that is more, and at the end
    of the body). A reading that decodes escapes is searched for itself only around an
    escape: where no escape was decoded for as many bytes as a form can have, it is the same
    bytes as the reading it is decoded from, and one search reads both. How far the bytes that leave lag depends
    on the length of the credential and on nothing else. Its verdict on a body is the verdict
    of step 10 on the same bytes, and a body that holds the credential is cut in front of it:
    no byte of the form leaves, and the bytes held back leave only at the end of a body as
    its sender ended it. The end record says how the body ended: `{"complete":true}`, or
    `complete` false with the `code` `response_withheld`, `provider_unreachable` (the
    connection of the provider failed or ended inside the body) or `timeout`, and the fixed
    `message` of that code. A stream that ends without an end record was cut on its way and
    is a failure for its caller. The response body of a stream takes no share of the body
    budget: the node holds the bytes held back, the bytes of one search and four elements of
    the stream. At the time limit of the call the task frees the connection to the provider
    and the place of the call among the forward calls whether or not the caller reads the
    response; it frees them as well when the connection of the caller ends. The sizes of the
    parts of a stream depend on the length of the credential (the bytes held back), which
    the size of the request to the provider shows the operator domain as well.

The value of the credential header: `inject.prefix` followed by the value at the first path of
`inject.paths` that holds a non-empty string in the token object. When there is no such value, the
call fails with `record_invalid`.

The node does not judge the expiry of a token and does not refresh. The response of the provider
(a 401 and the `ok: false` of slack included) goes back as it is, after the check of step 10.
Refreshing (`refresh`) and calling again are the work of the backend.

### 5.8b `POST /v1/forward/batch`

Sends one to 100 provider requests of one record with the credential of the record injected, after
one entry names them all. The frame is the frame of 5.8. Its meta is

```json
request meta:  {"user_id":"...","record":{...},"context":"...","timeout_ms":30000,
                "requests":[{"method":"GET","url":"https://host/path?query","headers":[["name","value"],...],"body_bytes":0}, ...]}
response meta: {"results":[{"status":200,"headers":[["name","value"],...],"body_bytes":0,"log":{"seq":1,"index":0,"created":true}}
                           | {"error":"timeout","log":{"seq":1,"index":1,"created":true}}, ...]}
```

and its payload is the bodies of the requests one after another, in order, `body_bytes` each (a
sum that is not the length of the payload is `invalid_request`). `timeout_ms` (1,000 to 120,000,
30,000 when omitted) is the time the node gives the provider calls of the batch together, from the
confirmation of the entry. `requests` holds 1 to 100 objects; another count is `invalid_request`.

1. The common front of section 4, once for the call. The call takes one forward slot (section 8).
2. For every request, in order: the method is one of the methods of 5.8 step 3, the address
   passes the check of section 7, and the headers pass the rules of 5.8 step 4. The first request
   that fails refuses the whole call: `not_allowed`, `invalid_request` or `record_invalid` with
   the body `{"code": ..., "message": ..., "index": i}`. No event is created before every request
   passed.
3. Inside the account lock: for every request, in order, the merge decision of 5.8 step 5, then
   the event `provider_request` (`time_ms` now) into the open batch when the request is not
   merged. Two identical GET requests inside the batch share one event. The open batch is closed
   when it reaches a cap (protocol.md 7.1), so the events of one batch may lie in two entries.
   The call leaves the lock with the place of every request.
4. The call waits until every entry that holds one of its events is confirmed (the group commit
   of protocol.md 7.1: the call is the writer when none is active). When a write is not
   confirmed, the call fails with `log_store_unavailable` and no request is sent.
5. The grant is checked once more (a revoke the node accepted while the entry was written
   refuses the call with `grant_revoked`: the entry stays on the chain and no request leaves).
   The requests leave over the idle connections of (account, host) of 5.8 step 8, at most 6 at a
   time (`FORWARD_BATCH_CONCURRENCY`), within the node-wide bound of 512 provider requests in
   flight, until `timeout_ms` since the confirmation. Every response passes the checks of 5.8
   step 10 one by one.
6. The response frame: `results` in the order of the requests, and the payload is the bodies of
   the results one after another. The `error` of one result is the failure code the same request
   would have had as a single `forward` (`timeout`, `provider_unreachable`, `too_large`,
   `response_withheld`); the other results are not affected, and the `log` object of a failed
   request names its event all the same (the entry is on the chain). The bodies of the results
   together stay under the body limit of 64 MiB: a response that would take their sum over it is
   `too_large` and its body is not kept. The body budget of section 8 covers the bodies of the
   batch as it covers the body of a single `forward`: the reservation of the request frame is
   split among the requests by the length of their bodies, and the share of a request is free
   once the request is on the wire, before its response body takes a share of its own.

### 5.9 `POST /v1/release`

```json
{"user_id":"...","record":{...},"field":"password|totp|card_number|card_cvc|value","origin":"https://host","seal_to":"<b64u of 32 bytes>","context":"..."}
-> {"value":"...","log":{"seq":1,"index":0,"created":true}}
-> {"sealed":{"enc":"...","ct":"..."},"log":{"seq":1,"index":0,"created":true}}
```

| Record kind | Allowed field | The value that is returned | Event |
| --- | --- | --- | --- |
| `vault_password` | `password` | `value` of the plaintext | `secret_released` |
| `vault_totp` | `totp` | The 6-digit code computed from the seed of the plaintext (RFC 6238, node time). The seed does not leave | `totp_issued` |
| `vault_card` | `card_number`, `card_cvc` | `number` or `cvc` of the plaintext | `secret_released` |
| `vault_secret` | `value` | `value` of the plaintext, the whole of it | `secret_released`, with the `name` of the record |

Any other pair of kind and field is `not_allowed`, and so is a record of kind `oauth` or
`oauth_imported`: no call hands out the plaintext of a token.

A record of kind `vault_secret` says itself where its value may go (protocol.md section 6). The
call is `not_allowed` when the slots of the record are not the slot `field`, or when its `sites`
are not `"any"` and hold neither the host of `origin` (what stands between the scheme and the
port, in lower case) nor a host that host lies below. So the value of a record with slots of a
request leaves a node through no call, and the origin an entry names for a value is an origin of
the sites of that value. A plaintext of this kind that does not state a name, sites, slots and a
source of the forms of protocol.md section 6 is `record_invalid`.

`origin` is an origin string `https://host` or `https://host:port` of at most 512 bytes (the node
checks the form only). The node cannot know whether the browser of the caller is at that origin:
the caller states it, and the node writes the value it received into the entry. For the kinds
other than `vault_secret` the backend decides whether that origin is the site of the vault item.
The call works without the operator configuration.

`seal_to` is optional: the b64u of an X25519 public key the caller made for this call. With it,
the response carries `sealed` in the place of `value`: the value under a single-shot HPKE seal to
that key (protocol.md section 6). The key material of the seal is drawn before the event is
created, so a failure of the random source leaves no entry of a release without a value. A
`seal_to` that is no key HPKE can seal to is `invalid_request`. The seal holds for every kind of
this call. A call without the key gets the value as it is.

The order of the call: the form of the body, the common front, the AEAD verification of the
record and its kind, the pair of kind and field, and for a `vault_secret` the reach. A call that
is refused up to here creates no event. Then the event, and the confirmation of the log store
for the entry that holds it. Only then does the node read the plaintext for the value, and the
value leaves. A plaintext that does not hold the field, and a seed that is not base32, are
`record_invalid` at that point: the response carries no value, and the entry stays on the chain.
So no answer of this call depends on the content of a value unless an entry records the call: a
caller that repeats the call to learn the form of a value a user entered leaves an entry for
every try.

### 5.9b `POST /v1/vault/store`

```json
{"user_id":"...","name":"OPENAI_API_KEY","sites":["api.openai.com"],"slots":["header:authorization"],"value":"...","context":"..."}
-> {"record":{...},"log":{"seq":1,"index":0,"created":true}}

{"user_id":"...","kind":"vault_password","site":"shop.example","value":"...","context":"..."}
-> {"record":{...},"log":{"seq":1,"index":0,"created":true}}
```

The call takes a value the operator domain holds and hands it back as a record of the vault under
the user key of the grant, and records that it did. It works without the operator configuration,
and it needs an active grant: without one no value is stored.

- `kind` is `vault_secret` (also when the key is absent) or `vault_password`. A body of the first
  kind carries `name`, `sites` and `slots` of the forms of protocol.md section 6 and no `site`. A
  body of the second kind carries `site`, a host of that form (the host of the login the password
  belongs to), and no `name`, `sites` or `slots`. `value` is 1 to 12,000 bytes of UTF-8 without
  U+0000. A violation is `invalid_request`. A plaintext above 12,272 bytes is `too_large`.
- The node draws the `id` (16 bytes) and the nonce of the record from its random source. A body
  with a key `id` or `nonce`, whatever its value, is `invalid_request`: the node does not encrypt
  a value of its caller under the record key of a record that exists.
- The plaintext is written by the node: `value`, `name`, `sites`, `slots` and `source`, in this
  order, for a `vault_secret`, and `value` and `source` for a `vault_password`. `source` is
  `operator`. The plaintext of a record a device makes has the source `device`, or for a
  `vault_password` no source, so a value that came in through this call cannot pass for a value
  a user entered on a device.
- The event is a control event `connection_created` (protocol.md 7.2): `record_id`, the provider
  `vault`, the empty `scope`, `kind`, `name` (of a `vault_secret`) or `site` (of a
  `vault_password`, as the caller stated it), and `context`. The record leaves only after the log
  store confirmed the entry that holds the event. When it does not, the call ends with
  `log_store_unavailable` and the record is dropped inside the node, the value with it.

### 5.9c `POST /v1/vault/handoff`

```json
{"user_id":"...","record":{...},"peer":{the attestation response of a node of the forward role},
 "request":{"method":"POST","host":"api.openai.com","path":"/v1/chat/completions","query":"",
            "slot":"header:authorization","placeholder":"...","body_bytes":0,"body_sha256":""},
 "context":"..."}
-> {"envelope":{"v":1,"from":"<node>","to":"<node>","enc":"...","ct":"..."},"log":{"seq":1,"index":0,"created":true}}
```

A node of the delegation role hands the value of a record of kind `vault_secret`, for one request
to a site of that record, to a node of the forward role (protocol.md 10.5). The call works
without the operator configuration.

1. The form of the body: `request` is a request object of protocol.md 10.5, `peer` an
   attestation response, `context` at most 256 characters.
2. The receiving node: its attestation response verifies as that of a node of the platform and
   the measurement of this node, and its binding has the `role` `forward` (protocol.md 4.1).
   Otherwise `peer_unverified`. The node keeps the nodes it verified, so the next call for the
   same node verifies no document again.
3. The common front (section 4), and the record: its kind is `vault_secret` and it opens.
4. The reach of the record: its `sites` are a list that holds `host` of the request, and its
   `slots` hold `slot` of the request. A record whose `sites` is `"any"`, and a record whose slot
   is `field`, goes into no request. A use outside the reach is `not_allowed`.
5. The event: a use event `provider_request` with the provider `vault`, the method, the host, the
   path, the query, the size and the hash of the body as the request object states them,
   `context`, `name`, `slot` and `to` (protocol.md 7.2). It is merged with no other event. A call
   that is refused up to here creates no event.
6. After the log store confirmed the entry: the value is 8 to 12,000 bytes, and for a slot of a
   header and for the two slots of HTTP Basic it holds no control character (for `basic:user`, no
   colon either). A value that fails is `record_invalid`: no envelope leaves, and the entry stays.
7. The node seals the value and the request object to the sealing key of the receiving node
   (protocol.md 10.5, sink K8 of the egress policy) and returns the envelope.

The entry of a use is on the chain before a value is sealed, and an envelope is one request
within 30 seconds: the log of an account holds one `provider_request` for every handoff that
passed step 5.

### 5.16 `POST /v1/vault/send`

The request is a frame (5.8): `meta_len || meta || payload`.

```text
meta    = {"envelope":{...},"headers":[["authorization","Bearer <placeholder>"], ...],"timeout_ms":30000}
payload = the body of the request, with the placeholder where the value goes
```

A node of the forward role sends the one request of the envelope, with the value at its slot, and
hands the response on while it arrives. `timeout_ms` is 1,000 to 600,000 (30,000 when absent): the
time from the moment the request leaves to the end of the response body.

1. The call takes one of the places of the forward calls of the node and the share of the body
   budget its frame occupies, and waits for them for 30 seconds at the most
   (`capacity_unavailable`, section 8). A closing node begins no request (`closing`): the envelope
   of such a call stays unused.
2. The envelope opens for this node, its signature verifies, and the node time is before its
   `not_after_ms` (protocol.md 10.5).
3. The call takes the share of the body budget that the search of the response can hold for a
   value of this length (rule E4, `StreamCheck`), within the same 30 seconds.
4. The request of the caller is the request of the envelope: the body has the length and the
   SHA-256 the envelope states, the placeholder occurs once and at the slot, and the headers pass
   the rules of protocol.md 10.5. A request that fails here leaves the envelope unused.
5. The node marks the number of the envelope as used and sends the request to port 443 of the
   host, on a connection of its own, with `Connection: close` (sink K9 of the egress policy). A
   failure from here on is not followed by a second request: the caller does not send the
   envelope again either, because the request may have reached the host.
6. The head of the response passes rule E4: a response under a content coding, a transfer
   coding the node does not remove or an instance manipulation, and a response with the value in
   a header name or a header value, ends the call with `response_withheld` and nothing of it is
   handed on. A redirect is returned as it is and not followed.
7. The 200 response is a stream of the form of 5.8 (`application/vnd.pickle.stream`): the meta
   `{"status":n,"headers":[[name,value],...]}`, the parts of the body, and the end record. Every
   part passes the search of rule E4 before it leaves, and a body that holds the value in a form
   the search knows is cut in front of it (`{"complete":false,"code":"response_withheld",...}`).
   A body that ends early, or not within the time limit, ends with the end record of that
   failure, and the bytes the search held back at that moment are not handed on.

The call holds its place, the share of its frame and the share of its search until the body has
ended, was cut, the time limit passed or the caller is gone. So a closing node that holds no
place of a forward call (`forward_calls` of `load` of `health`) sends no request and begins
none: the host program of its pod waits for that before it ends the enclave (section 9). The
node holds no user key and opens no record: what it learns of an account is one value for one
request.

### 5.10 `POST /v1/log/entries`, `POST /v1/log/ack`

The calls `POST /v1/log/entries` and `POST /v1/log/ack` are not part of the call surface. A node
answers them with 404 `invalid_request`, like every path that is not defined. The log store is the
one place an entry is read from (protocol.md 7.6): no call hands an entry out, and no call takes an
acknowledgement of its storage.

### 5.11 `POST /v1/close`

```json
close {} -> {"accounts":0}
```

`close` raises `closing`: from then on, the calls that use a credential and the commands are refused
with `closing`, the node creates no further entry for a call, and its sweep ends. A call that was in
progress runs to its end: its event exists, and the call acts when the store confirms the entry of
that event. `accounts` is the number of accounts this node created an entry for. `peer/export` works
in the state `closing` (5.13): the orderly shutdown of a node is `close`, then the handover of
its delegations to other nodes with `peer/export`, and the end of the calls it is in the middle
of. The host program starts this sequence when it receives the termination signal (section 9),
and the pre-stop hook of the pod starts it before the signal (section 9, `drain`). The host
program makes the `close` call itself at the termination signal, has the backend hand the
delegations on, and ends the enclave only after the calls in progress of the node ended
(section 9, "The calls in progress at a shutdown"). A node of the forward role holds no
delegation: its orderly shutdown is `close`, after which it begins no request of `vault/send`
(5.16), and the end of the requests it is sending.

The shutdown signs nothing and drops nothing. An entry the log store confirmed is in the store. An
entry the store did not confirm is in the memory of the node and is gone with it: its act did not
take place, and that the store holds no object of it says so (protocol.md 7.6). So a node that ends
without `close` (the enclave ran out of memory, the node program aborted, the parent instance was
lost) leaves in the store what a node leaves that ended with it: the entries of its acts. A reader
of the store needs nothing else of a node that is gone (protocol.md 7.4).

The call `POST /v1/close/heads` is not part of the call surface. A node answers it with 404
`invalid_request`, like every path that is not defined: a node signs no head (protocol.md 7.3).

### 5.12 `POST /v1/seal`, `POST /v1/open`

The calls `POST /v1/seal` and `POST /v1/open` are not part of the call surface. A node answers
them with 404 `invalid_request`, like every path that is not defined. No call takes a credential
in the clear, and no call hands the plaintext of a token out.

### 5.13 `POST /v1/peer/export`, `POST /v1/peer/import`

```json
export {"peer":{the attestation response of the receiving node},"after":"","limit":1000,
        "subset":{"pods":3,"pod":1,"copies":2},
        "endorsement":{"statement":"...","entry":{"log_id":"...","body":"...","integrated_time":0,"log_index":0,"signed_entry_timestamp":"..."}
                                               | {"log_id":"...","body":"...","inclusion_proof":{"log_index":0,"hashes":["..."],"checkpoint":"..."}}}}
  -> {"envelope":{...}|null,"logs":[{"user_id":"...","seq":1}],"next":""}
import {"peer":{the attestation response of the giving node},"envelope":{...},"subset":{"pods":3,"pod":2,"copies":2}}
  -> {"imported":0,"accounts":["<user_id>", ...],"logs":[{"user_id":"...","seq":1}]}
```

The rules are those of protocol.md 10.1, 10.3 and 10.4. What this document adds:

- `subset` is optional in both calls (protocol.md 10.4). In export, `pod` is the ordinal of the
  receiving node: the page selects the accounts of its share alone, and `limit` counts the
  selected grants. In import, `pod` is the ordinal of this node: a grant of an account outside its
  share is left out, not put in place, without an entry and not counted in `imported`. The key
  absent or `null` is a call without a subset. A `subset` that is not an object of three integers
  within the bounds of protocol.md 10.4 is `invalid_request`, and the call changes nothing. A node
  of release v2.0.1 does not read the key: it exports every account, and the receiving node of
  this release keeps its share.

- `peer` is the response of `POST /v1/attestation` of that peer, as it is (the nonce is a value
  that the caller chose, and the node does not look at it).
- `limit` of export is 1 to 1,000 (a larger value is read as 1,000). `after` is the `next` of the
  page before (the empty string for the first page). When a page has no grant to hand over,
  `envelope` is null and `logs` is an empty list. An empty `next` ends the listing.
- A transfer to a node of the measurement of this node (export without `endorsement`) creates no
  entry and writes nothing to the log store (protocol.md 10.1): `logs` of export and `logs` of
  import are empty lists, the export works while the node cannot write to its log store, and a grant
  is handed to any number of such nodes.
- `logs` of export with `endorsement` names the control entry `grant_transferred_out` (its `user_id`
  and `seq`) of every grant of the page that the node hands to this peer for the first time
  (protocol.md 10.1; the open batch of such an account is closed before it). A grant that the node
  handed to the same peer before is in the envelope again and has no new entry: a repeated call
  returns the envelope and an empty `logs`. An account whose grant was handed to 64 other peers of a
  later release is not selected. It is not in the envelope, it has no entry, and it does not count
  toward `limit`.
- export works in the state `closing` too: the orderly shutdown is `close`, then `peer/export`
  (5.11). import is refused with `closing` in the state `closing`, and when the shutdown starts
  during an import, the call answers with what it took until then.
- The pages of export: the node goes through the accounts in the order of `user_id`, reading its
  sorted index one chunk of 1,000 accounts at a time (section 3), until `limit` grants are
  selected, and `next` is the last `user_id` it looked at (the last page can be empty). An
  omitted `limit` is 1,000 and an omitted `after` is the empty string. `imported` of import is
  the number of grants that this call put in place, and `accounts` names their accounts (the
  `user_id` of each): the caller learns from the response which accounts this node holds a
  delegation of now. `logs` of import names the control entries `grant_transferred_in` the call
  created: one per grant it put in place from a node of an earlier release, and none for a
  transfer from a node of the measurement of this node. Within the 1 MiB limit of a JSON
  body, a page of 1,000 grants fits when a `user_id` is at most about 350 bytes long (a `user_id`
  of the length of a UUID fits).
- `attest.rs` decides which peer a node accepts: platform `nitro` by steps 1 to 5, 7, 8 and 10 of
  protocol.md 4.3 (the allowed measurements are those the call names, see the next three items,
  the trust root is the DER of AWS Nitro Enclaves Root-G1 inside the binary, and the one allowed
  log store is that of the node itself), platform `local` by parsing the `binding` of the local
  document of 4.2 and comparing its log store in the same way. A response of a platform that is
  not the platform of the node, and a response whose binding names another log store than the
  node has (or one where the node has none, or none where the node has one), is `peer_unverified`.
- export without `endorsement` (the key is absent or holds `null`): the one allowed measurement
  is that of `Platform::measurement()`.
- export with `endorsement`: the value is the endorsement of protocol.md 10.3, and the node makes
  the seven checks of that section. What it checks with are the release key and the table of
  transparency logs inside the binary: the entry of the endorsement names its log by its log
  identifier, and the node reads the entry in the form of that log (the signed entry timestamp
  of `rekor.sigstore.dev`, or the inclusion proof of `log2025-1.rekor.sigstore.dev`). The node
  sends no request to a log: the entry and its proof are bytes of the call. The release it
  compares with is the release tag inside the binary, and the time of check 5 is the node time
  (section 8) in seconds. The one allowed measurement is that of
  the statement, with the `release` of the statement in the binding of the peer. The measurement
  of the node itself is not allowed then, and a node of platform `local` accepts no peer. An
  `endorsement` that is not a JSON object is `invalid_request`. An endorsement that lacks a key,
  holds a value of another type or fails a check is `peer_unverified`: the response does not say
  which check failed. A refused call creates no entry.
- import: the allowed measurements are that of `Platform::measurement()` and those of the list of
  predecessors inside the binary (`enclave/release/predecessors.json`), each of the list with the
  `release` of its element in the binding of the peer. The call has no key for an endorsement: a
  receiving node does not look at one.
- The node reads the release key, the table of logs and the list when it starts (`lineage.rs`).
  It does not start when the release key is not an ECDSA P-256 public key, when the table fails
  the rules of protocol.md 10.3 (no row, a key or an origin that is not of the form of its row,
  one log in two rows), or when the list fails the rules of that section (a malformed list, an
  element whose release is not earlier than the release of the node, any element for a node
  whose release is not a release tag).
- export with `endorsement` and the log store: the node hands a grant over only after the log
  store confirmed the entry `grant_transferred_out` of that grant for that peer (protocol.md
  10.1, steps 4a to 5b). The entry names the peer, its release and its measurement.
  When the store does not confirm the entry of one account of the page, the call fails with
  `log_store_unavailable` and the response carries no envelope and no `logs`. The entries the
  call created are on their chains and wait for the store (pending entries). The next call for
  the same peer creates no entry for these accounts, so its `logs` are those of the grants it
  hands over for the first time only.
- A halted account (3.1) is in no transfer: export passes it by (it has no grant), and import
  leaves a grant of it out, without an entry and not counted in `imported`.
- import and the log store: a node takes a transfer only while its log store holds its node document
  (5.14, protocol.md 7.7). Without it the call is `log_store_unavailable` and the envelope is not
  opened: a node holds no user key that a reader of the store could not trace to an attested node.
  The call does not need the credentials. For a transfer from an earlier release, the grants are put
  in place first, and the call then writes the entries `grant_transferred_in` it created in one
  round (the pending entries of the same accounts along) when the node has credentials for its log
  store. Without them, and for an entry the store does not confirm, the entry is a pending entry
  that the next write of the account on this node takes along, and the call succeeds all the same.
- Both calls work without the operator configuration. On a node of platform `nitro`, the log
  store of that configuration is what makes a peer acceptable and an export possible.

### 5.14 `POST /v1/log-store/credentials`, the log store

```json
{"access_key_id":"...","secret_access_key":"...","session_token":"...","expires_ms":0}
-> {"credentials_expires_ms":0,"node_document_ms":0}
```

The call gives the node the credentials it signs its writes to the log store with: temporary
credentials of AWS that the operator domain holds. They are values of the operator domain and
no secrets of an account.

- `access_key_id` is 1 to 128 letters and digits, `secret_access_key` is 1 to 256 printable ASCII
  characters, `session_token` is at most 8,192 printable ASCII characters (an absent key or the
  empty string for credentials without a session: such a request carries no
  `x-amz-security-token`), and `expires_ms` is an unsigned integer. Any other value is
  `invalid_request`, and the credentials the node holds stay.
- The node keeps the credentials in memory. A new call replaces them. No response carries the
  secret access key or the session token: `health` reports `credentials_expires_ms` only.
- The node uses the credentials while its own clock is before `expires_ms`. After that it has no
  credentials: the node does not ask the log store.
- The call works without the operator configuration and in the state `closing`. The credentials
  say nothing about where the node writes: that is the log store of the operator configuration
  (5.1).
- With credentials the node can write its node document (the row "Node document" below). The
  call writes it before it answers, when it is due. `node_document_ms` of the response is the
  node time of the latest write of the document that the store confirmed, 0 when it confirmed
  none. The outcome of that write does not change the status of the call, which can take as
  long as the attempts of one write (twice the time limit of a write) when the store does not
  answer.

The write of an entry (`enclave/src/log_store.rs`) is the request of protocol.md 7.6:

| Item | Rule |
| --- | --- |
| Connection | The connection of every outbound call (`Egress::open`): the byte pipe of the platform to port 443 of `s3.{region}.amazonaws.com`, the endpoint of Amazon S3 in the region of the log store (one host for every bucket of the store), TLS that ends inside the node, the trust roots of `webpki-roots`, the certificate verified at node time. An attempt to open a connection that fails before any request byte left the node (the byte pipe, a refusal of the egress relay, the TLS handshake, the HTTP/1.1 handshake) is repeated: at most 3 attempts (`OPEN_ATTEMPTS`), with a full jitter backoff between them (a random time up to 50 milliseconds, doubled for every attempt after the first, at most 400 milliseconds, drawn from the random source of the platform), as long as the attempts and the backoff stay within half the time limit of the call the connection is for (for a write to the log store: half the time limit of the attempt). This rule holds for every outbound connection of the node: to a provider (5.7, 5.8, the mail hosts) and to the log store. The node opens at most 256 connections at the same time (`open_concurrency` of section 8); a further open waits for a place within the time limit of its call. The node keeps at most 32 idle HTTP/1.1 connections to its log store: open connections that carry no write. A connection carries a write to any bucket of the store. A write takes the most recently used one. A connection carries one write at a time and is idle again only when its response has ended. A connection that closed or failed, or whose write was cancelled, is not kept |
| Request | `PUT` of the object of protocol.md 7.6 to `/{bucket}/{key}` (path-style: the bucket of the account of an entry, or of the node for the node document, is the first part of the path), signed with AWS Signature Version 4 (the service `s3`, the region of the log store). Every header of the request except `Content-Length` is signed. The times of `x-amz-date` and of the retention are node time |
| Confirmation | The status 200. The node reads no response body and follows no redirect. An attempt that is not confirmed is repeated over a new connection with a full jitter backoff (a random time up to 100 milliseconds, doubled for every attempt after the first, at most 1 second) within a budget of twice the time limit of a write per entry, when the failure is a failed connection, a connection that closed without a response, the time limit of the attempt, a 5xx status or 429; a 4xx status other than 429 is not repeated, and neither is an attempt whose backoff and a margin of one second would not fit in the budget. A `PUT` is idempotent (RFC 9110 9.2.2), and a repeated attempt adds a version of the same object with the same body: the request renews the date and the signature only (protocol.md 7.6). Every attempt is a write of `log` of health, and every failed attempt is counted under its cause (5.1) |
| Local endpoint | A node of platform `local` takes an optional `endpoint` in the `log_store` of its configuration (5.1): an `http://host:port` or `https://host:port` origin. With it, the node sends the same request (the same path `/{bucket}/{key}`, with the bucket of the object among the buckets of the log store) to the endpoint, with the `Host` header of the endpoint and, when the scheme is `http`, over the plain byte pipe of the platform without TLS; the signature region is the region of the configuration and the signed headers are the same. A node of platform `nitro` refuses a configuration with `endpoint` (`invalid_request`). The binding carries the bucket and the region only |
| Time limit | 5 seconds for one attempt to write an entry: the connection, the TLS handshake and the exchange. The first attempt goes over an idle connection when there is one and gets half this time, so a connection that stalls leaves the time for an attempt over a new connection; every later attempt opens a new connection. The attempts of one entry end within twice this time. A call that waits for the write of another call waits for at most twice this time |
| Writes of one call | The entries the act of the call waits for, and the pending entries of the same accounts. At most 32 writes run at the same time, the entries an act waits for first. After a round in which a write was not confirmed, the call starts no further write. The group commit (protocol.md 7.1, section 3): one call of an account writes at a time, and the events of the calls that arrive meanwhile form the next entry |
| Sweep | The sweep of section 3 visits the accounts in a random order, writes the pending entries of an account only after a jitter of up to 30 seconds since the oldest of them became pending, and writes at most 64 entries per second over the whole node (`sweep_write_rate` of section 8). An account the sweep did not reach before the next sweep is due waits for that sweep |
| The limit of pending entries | An account whose pending entries reached 64 gets no further entry from a call that uses a credential (step 3 of the common front): the call writes the pending entries again, goes on when fewer than 64 are left, and otherwise ends with `log_store_unavailable` without an entry. A command and a delegation transfer are not stopped by this limit |
| Node document | The node writes its node document (protocol.md 7.7: its attestation document over its binding, under `n3/{node}` in the bucket of the node, with a retention of 400 days) once it has a log store and credentials: in the call that gives it the second of the two (`config`, 5.1, or `log-store/credentials`) and, while the store confirmed no write of it, in every sweep. It writes the document again in the sweep when the latest confirmed write is 30 days old. One call writes the document at a time, with the attempts of a write of this table. While the store confirmed no write of the document in the last 31 days, the node cannot write an entry: it refuses a grant command and every call that uses a credential with `log_store_unavailable` and takes no transfer (5.13). `node_document_ms` of health (5.1) is the node time of the latest confirmed write |
| Platform | A node of platform `nitro` requires a log store (protocol.md 7.6). A node of platform `local` keeps account of the entries it creates from the call of `config` that named its log store: the entries it created before are not written |

### 5.15 `POST /v1/grants/prune`

```json
prune {"subset":{"pods":3,"pod":1,"copies":2},"after":"","limit":1000} -> {"pruned":["<user_id>", ...],"next":""}
```

The rules are those of protocol.md 10.4. What this document adds:

- `subset` is required: `pod` is the ordinal of this node. A missing key or a value outside the
  bounds of protocol.md 10.4 is `invalid_request`, and the call changes nothing.
- The node walks its accounts in the order of `user_id` after `after` (an omitted `after` is the
  empty string), reading its sorted index one chunk of 1,000 accounts at a time (section 3), and
  for every account that the subset does not give to this node drops a grant within its time and
  an expired grant alike: the state becomes `None`, the user key is overwritten with zeros, and the
  kept `refresh` responses and the merge keys of the account go with the grant. A revocation
  marker stays, and so does the chain of the account. The walk ends after `limit` pruned accounts
  (1 to 1,000, a larger value is read as 1,000) or after 10,000 accounts looked at, whichever
  comes first. `pruned` lists the `user_id` of every account the call pruned, in `user_id` order,
  and `next` is the last `user_id` the walk looked at, the empty string when it reached the end;
  the caller repeats the call with `next` as `after` until `next` is empty.
- No entry is created and nothing is written to the log store: nothing is used, and the operator
  chose which nodes hold the key. The acts the chain records stand. `grants` of health follows.
- The call works without the operator configuration and in the state `closing`.

## 6. The provider definitions

### 6.1 The format (`enclave/src/providers/definitions.json`, compiled into the binary)

```json
{
  "google_workspace": {
    "client": "static",
    "authorize": {"url": "https://accounts.google.com/o/oauth2/v2/auth", "fixed": [], "allowed": ["scope", "access_type", "prompt", "include_granted_scopes", "login_hint"], "key_param": ""},
    "scope_param": "scope",
    "scope_delimiter": " ",
    "pkce": "S256",
    "token": {"url": "https://oauth2.googleapis.com/token", "client_auth": "body", "body": "form", "headers": [], "bearer": "", "fixed": [], "ok_field": ""},
    "token_container": "",
    "revoke": {"url": "https://oauth2.googleapis.com/revoke", "client_auth": "none", "bearer": ""},
    "inject": {"header": "Authorization", "prefix": "Bearer ", "paths": ["access_token"]},
    "public": [
      {"path": "scope", "type": "string", "max": 8192},
      {"path": "expires_in", "type": "integer"},
      {"path": "token_type", "type": "string", "max": 32}
    ],
    "id_token_claims": [
      {"path": "sub", "type": "string", "max": 255},
      {"path": "email", "type": "string", "max": 320},
      {"path": "email_verified", "type": "boolean"},
      {"path": "hd", "type": "string", "max": 255},
      {"path": "name", "type": "string", "max": 256},
      {"path": "picture", "type": "string", "max": 2048}
    ],
    "api": [
      {"host": "gmail.googleapis.com", "prefixes": ["/gmail/v1/", "/upload/gmail/v1/"], "exact": []},
      {"host": "sheets.googleapis.com", "prefixes": ["/v4/spreadsheets"], "exact": [], "encoded_slash": true}
    ]
  }
}
```

The example shows two of the eight `api` rules of `google_workspace` (section 7 lists all).

| Key | Meaning |
| --- | --- |
| `client` | `static`: the client values come from the operator configuration. `dynamic`: a public client, whose `client_id` comes as an argument of the call (it has no secret) |
| `authorize.url` | The authorization address |
| `authorize.fixed` | A list of `[name, value]` pairs that are always part of the authorization address |
| `authorize.allowed` | The names of the parameters that a caller may choose |
| `authorize.key_param` | The name of the parameter that carries the `publishable_key` of the operator configuration (the empty string when there is none) |
| `scope_param`, `scope_delimiter` | The name of the scope parameter and the delimiter between its values |
| `scopes` | Optional: the list of the scope values that a caller may request |
| `pkce` | `S256` or `none` |
| `token.url` | The token address |
| `token.client_auth` | `body` (`client_id` and `client_secret` in the body), `basic` (HTTP Basic), `none` (`client_id` only, in the body) |
| `token.body` | `form` or `json` |
| `token.headers` | `[name, value]` pairs that are added to a call of the token address |
| `token.bearer` | `publishable_key`: the call carries `Authorization: Bearer {publishable_key of the operator configuration}` (this takes precedence over `basic`) |
| `token.fixed` | `[name, value]` pairs that are always part of the body of an exchange and of a refresh |
| `token.ok_field` | When it is not the empty string: a 200 response whose value of that name is `false` is a failure (the `ok` of slack) |
| `token_container` | When it is not the empty string: the access token, the refresh token and `expires_in` are inside the object of that name in the response (protocol.md 8.3) |
| `revoke` | The revocation address (`url`, `client_auth`, `bearer`). `null` when the provider has none |
| `inject` | The credential header that `forward` sets: one rule as an object, or a list of rules when the hosts of `api` take the token in different forms. A rule is `{"host", "header", "prefix", "basic_user", "paths"}`: `host` (absent or the empty string = every host; else a host of `api`) is the host the rule applies to, and `forward` uses the first rule whose host is empty or equals the host of the address. The value is `prefix + token[the first path of paths that exists]`, or, when `basic_user` is not empty (`prefix` is then empty), HTTP Basic: `Basic ` and the base64 of `{basic_user}:{token}` (the git addresses of GitHub). A path is object keys joined by `.`. Every host of `api` must have a rule |
| `public`, `id_token_claims` | 6.4 |
| `api` | Section 7. A rule is `{"host", "prefixes", "exact"}`, the optional boolean `encoded_slash` (false when it is absent), the optional list `denied` (empty when it is absent) and the optional list `suffixes` (empty when it is absent: path ends that are allowed whatever comes before them, for the git addresses of GitHub whose front names a repository) |

The definitions are validated when the node loads them, and a node with an invalid definition does
not start (`Definition::validate` in `enclave/src/providers/mod.rs`). A key that the format does
not define is refused. The authorization address, the token address and the revocation address
are plain addresses `https://host/path`: a lower-case DNS name, no user information, no port, no
query, no fragment. The token address and the revocation address must not be reachable through
the `api` list of the same definition (section 7). An `allowed` parameter must not be a parameter
that the node sets itself (`response_type`, `client_id`, `redirect_uri`, `state`,
`code_challenge`, `code_challenge_method`, a `fixed` name, `key_param`). An `inject` rule must
name a valid header, at least one path, and either a prefix or a `basic_user` (a token without
`:`); a rule with a host must name a host of `api`, and every host of `api` must have a rule.
The rules for `public` and `id_token_claims` are in 6.4, the rules for `api` in section 7.

### 6.2 The values of the definitions

| | google_workspace | microsoft | slack | notion | x | link | granola | mercury | github |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| client | static | static | static | static | static | static | dynamic | dynamic | static |
| authorize url | `https://accounts.google.com/o/oauth2/v2/auth` | `https://login.microsoftonline.com/common/oauth2/v2.0/authorize` | `https://slack.com/oauth/v2/authorize` | `https://api.notion.com/v1/oauth/authorize` | `https://x.com/i/oauth2/authorize` | `https://login.link.com/auth` | `https://mcp-auth.granola.ai/oauth2/authorize` | `https://mcp.mercury.com/authorize` | `https://github.com/login/oauth/authorize` |
| authorize fixed | None | None | None | `owner=user` | None | None | `resource=https://mcp.granola.ai/mcp` | `resource=https://mcp.mercury.com/mcp` | None |
| authorize allowed | `scope`, `access_type`, `prompt`, `include_granted_scopes`, `login_hint` | `scope`, `prompt`, `login_hint` | `user_scope` | None | `scope` | `scope` | `scope` | `scope` | `prompt`, `login` |
| key_param | None | None | None | None | None | `key` | None | None | None |
| scope_param, delimiter | `scope`, space | `scope`, space | `user_scope`, `,` | None | `scope`, space | `scope`, space | `scope`, space | `scope`, space | None |
| pkce | S256 | S256 | none | none | S256 | S256 | S256 | S256 | S256 |
| token url | `https://oauth2.googleapis.com/token` | `https://login.microsoftonline.com/common/oauth2/v2.0/token` | `https://slack.com/api/oauth.v2.access` | `https://api.notion.com/v1/oauth/token` | `https://api.x.com/2/oauth2/token` | `https://login.link.com/auth/token` | `https://mcp-auth.granola.ai/oauth2/token` | `https://mcp.mercury.com/token` | `https://github.com/login/oauth/access_token` |
| token client_auth, body | body, form | body, form | body, form | basic, json | basic, form | body, form | none, form | none, form | body, form |
| token headers | None | None | None | `Notion-Version: 2025-09-03` | None | None | None | None | `Accept: application/json` |
| token bearer | None | None | None | None | None | `publishable_key` | None | None | None |
| token fixed | None | None | None | None | None | None | `resource=https://mcp.granola.ai/mcp` | `resource=https://mcp.mercury.com/mcp` | None |
| ok_field | None | None | `ok` | None | None | None | None | None | None |
| token_container | None | None | `authed_user` | None | None | None | None | None | None |
| revoke | `https://oauth2.googleapis.com/revoke`, client_auth none | None | None | None | `https://api.x.com/2/oauth2/revoke`, client_auth basic | `https://login.link.com/auth/revoke`, client_auth body, bearer `publishable_key` | None | None | None |
| inject paths | `access_token` | `access_token` | `authed_user.access_token`, `access_token` | `access_token` | `access_token` | `access_token` | `access_token` | `access_token` | `access_token` (two rules: 6.1) |

Every definition injects the header `Authorization`. The prefix is `Bearer ` everywhere but in
github: there the rules of `api.github.com` and `uploads.github.com` have the prefix `token ` and
the rule of `github.com` (the git smart HTTP addresses) is HTTP Basic with the user name
`x-access-token` (a `Bearer` or `token` header is refused there by GitHub). A rule without a host
applies to every host of the definition and must be the only rule or the last one.

The public fields of the definitions (path: type, and the limit of a string in bytes):

| Provider | `public` | `id_token_claims` |
| --- | --- | --- |
| google_workspace | `scope`: string 8192. `expires_in`: integer. `token_type`: string 32 | `sub`: string 255. `email`: string 320. `email_verified`: boolean. `hd`: string 255. `name`: string 256. `picture`: string 2048 |
| microsoft | `scope`: string 8192. `expires_in`: integer. `ext_expires_in`: integer. `token_type`: string 32 | `tid`: string 64. `oid`: string 64. `preferred_username`: string 320 |
| slack | `team.id`: string 32. `team.name`: string 256. `enterprise.id`: string 32. `enterprise.name`: string 256. `app_id`: string 32. `is_enterprise_install`: boolean. `authed_user.id`: string 32. `authed_user.scope`: string 8192. `authed_user.expires_in`: integer. `authed_user.token_type`: string 32 | None |
| notion | `workspace_id`: string 64. `workspace_name`: string 256. `workspace_icon`: string 2048. `bot_id`: string 64. `duplicated_template_id`: string 64. `owner.type`: string 32. `owner.user.id`: string 64. `owner.user.name`: string 256. `owner.user.avatar_url`: string 2048. `owner.user.type`: string 32. `owner.user.person.email`: string 320 | None |
| x, link, granola, mercury | `scope`: string 8192. `expires_in`: integer. `token_type`: string 32 | None |
| github | `scope`: string 8192. `expires_in`: integer. `refresh_token_expires_in`: integer. `token_type`: string 32 | None |

No definition has a list of allowed scopes (`scopes`): the consent page of the provider shows the
requested scopes to the user, and the `api` list bounds the addresses that a token can reach.

For a provider with `pkce` `S256`, the authorization code that passes through the callback of the
operator is of no use outside the node, because the verifier never leaves the node. This rests on
the token address of the provider: it must require the `code_verifier` of an authorization that
carried a `code_challenge` (RFC 7636 section 4.6). That is part of the contract of a provider that
section 1 of egress-policy.md assumes. The providers with `pkce` `none` (slack, notion) are a
stated limit (section 5 of egress-policy.md).

The inject rules by host (6.1): every definition but github has one rule for every host.

| Provider | host | header | form |
| --- | --- | --- | --- |
| github | `api.github.com` | `Authorization` | `token {access_token}` |
| github | `uploads.github.com` | `Authorization` | `token {access_token}` |
| github | `github.com` | `Authorization` | `Basic base64(x-access-token:{access_token})` |

### 6.3 The call of the token address

- The body of an exchange: `grant_type=authorization_code`, `code`, `redirect_uri`,
  (`code_verifier`), the client authentication values, `token.fixed`.
- The body of a refresh: `grant_type=refresh_token`, `refresh_token`, the client authentication
  values, `token.fixed`. When `client` is `dynamic`, `client_id` is the value of the plaintext of
  the record.
- The time limit is 15 seconds (`token_timeout` of section 8). The call of `oauth/complete` ends
  with it; the call of `refresh` goes on after it by the rule of 5.7. The node reads at most 1
  MiB of the response. A success is: the status is 200, the body is a JSON object, the
  `ok_field` check passes, and the token place holds an `access_token` string (reading the token
  place: protocol.md 8.3).
- The body of a revocation: `token`, `token_type_hint`, and the client authentication values that
  `client_auth` names. A revocation with `client_auth` `none` sends no client value (the `none` of
  the token address sends `client_id`).
- TLS ends inside the node. The trust roots are those of `webpki-roots`, compiled into the binary.
  The certificate is verified at the time of the node clock. The node follows no redirect.

### 6.4 The public fields

`public` in the responses of `oauth/complete`, `oauth/merge` and `refresh` is the object below. A
value that the definition does not list does not leave the node.

```json
{"token": {the listed leaves of the token object, each at its own path}, "id_token_claims": {the listed claims}, "obtained_ms": 0, "has_refresh_token": true}
```

- `public` of a definition is a list of `{path, type, max}`. `path` is object keys joined by `.`
  and names a leaf. `type` is `string`, `integer` or `boolean`. `max` is the longest `string`, in
  bytes of UTF-8 (a `string` has a `max` of at least 1, the other types have none). An `integer`
  is a JSON integer or a string of 1 to 20 ASCII digits.
- A value of another type, an object, an array and a string above its limit are left out. That is
  no failure. A listed leaf keeps its path: `token` has the nested shape of the token object, with
  the listed leaves only.
- `id_token_claims` is a list of the same form: claim name, type, limit. The claims are read from
  the body of the `id_token` (a JWT) of the token object, decoded without a verification of its
  signature (the TLS connection to the token address vouches for where the value came from).
- The validation of a definition refuses a public path that names a token (`access_token`,
  `refresh_token` or `id_token` as its last key, at any depth), the path that the node injects as
  a credential, a path that is listed twice, and a path that is the parent of another listed path
  (a path that points at an object does not exist).
- `has_refresh_token` is one bit: whether the token place of the token object holds a refresh
  token. `obtained_ms` is the node time at which the node received the token response.
- The containment check: when a string among the public fields and claims holds the string at
  `access_token`, `refresh_token` or `id_token` of the token response or of the merged token
  object (at the top level and in the token place), the call fails with `response_withheld`. No
  record and no public field leaves. A string holds a token when it contains the token as it
  is, or in one of the encoded forms that the response check of `forward` searches for (5.8).

## 7. The address check (`forward`)

| Definition | host | Allowed paths |
| --- | --- | --- |
| google_workspace | `gmail.googleapis.com` | Prefixes `/gmail/v1/`, `/upload/gmail/v1/` |
| | `www.googleapis.com` | Prefixes `/calendar/v3/`, `/drive/v3/`, `/upload/drive/v3/`, `/download/drive/v3/`, `/drive/v2/`. Exact `/oauth2/v3/userinfo` |
| | `docs.googleapis.com` | Prefix `/v1/documents` |
| | `sheets.googleapis.com` | Prefix `/v4/spreadsheets`. `encoded_slash` is true |
| | `slides.googleapis.com` | Prefix `/v1/presentations` |
| | `forms.googleapis.com` | Prefix `/v1/forms` |
| | `tasks.googleapis.com` | Prefix `/tasks/v1/` |
| | `meet.googleapis.com` | Prefix `/v2/` |
| microsoft | `graph.microsoft.com` | Prefix `/v1.0/`. Denied `/v1.0/$batch` |
| slack | `slack.com` | Exact `/api/conversations.list`, `/api/conversations.history`, `/api/conversations.replies`, `/api/conversations.info`, `/api/auth.test`, `/api/search.messages`, `/api/users.list`, `/api/users.info`, `/api/files.info`, `/api/chat.postMessage`, `/api/files.getUploadURLExternal`, `/api/files.completeUploadExternal` |
| | `files.slack.com` | Prefix `/files-pri/` |
| notion | `api.notion.com` | Prefixes `/v1/pages`, `/v1/blocks/`, `/v1/databases/`, `/v1/data_sources/`. Exact `/v1/search` |
| x | `api.x.com` | Prefixes `/2/users`, `/2/tweets`, `/2/dm_events` |
| link | `api.link.com` | Prefix `/spend_requests`. Exact `/userinfo`, `/payment-details`, `/shipping_addresses` |
| granola | `mcp.granola.ai` | Exact `/mcp` |
| mercury | `mcp.mercury.com` | Exact `/mcp` |
| github | `api.github.com` | Prefixes `/user`, `/users/`, `/repos/`, `/repositories/`, `/search/`, `/orgs/`, `/rate_limit`. Exact `/`, `/graphql`. `encoded_slash` is true |
| | `uploads.github.com` | Prefix `/repos/` (the release asset uploads `/repos/{owner}/{repo}/releases/{id}/assets`) |
| | `github.com` | Suffixes `/info/refs`, `/git-upload-pack`, `/git-receive-pack` (the git smart HTTP addresses `/{owner}/{repo}.git/info/refs`, `.../git-upload-pack`, `.../git-receive-pack`) |

The rules:

- The address is read as the string that was received (nothing is normalized). It is at most
  8,192 bytes long, every byte is printable ASCII (0x21 to 0x7e), and it has no fragment (`#`).
- The scheme is `https` and the port is 443 (no port, or `:443`). An address with a user
  information part, an IP literal and a host that ends with a dot are refused. The host is
  compared in lower case, and it must equal the host of a rule exactly.
- The path starts with `/` and is sent as the string that was received. Before the comparison with
  the lists the node refuses a path that holds one of these: `%2f` or `%2F`, `%5c` or `%5C`, `\`,
  `//`, a `%` that is not followed by two hexadecimal digits, `%25` in front of `2e`, `2f` or `5c`
  (in either case of the letters), and, after every percent escape of the path is decoded once, a
  segment that is `.` or `..` when it is read up to its first `;`.
- The last two refusals are for a server that reads a path in another way than the node does.
  `%252e`, `%252f` and `%255c` are the escapes of `.`, `/` and `\` with their `%` encoded once
  more: a server that decodes a path twice reads a dot or a separator there. `..;` and `..;x`
  are dot segments in front of a path parameter: a server that leaves path parameters out reads
  `..`. In both cases the request would reach a path outside the prefix that the node compared.
  A `;` inside a longer segment (`me;v=1`) and an encoded `%` in front of other characters
  (`100%25`, `a%2520b`) are not refused.
- `encoded_slash`: under a rule whose `encoded_slash` is true, `%2F` and `%2f` in the path are not
  refused. Two rules set it. That of `sheets.googleapis.com`: the values address of Google
  Sheets, `/v4/spreadsheets/{id}/values/{range}`, carries the range as one path segment, and the
  name of a tab that contains `/` arrives as `%2F`. That of `api.github.com`: the REST API of
  GitHub carries the name of a branch or of a tag as one path segment
  (`/repos/{owner}/{repo}/git/refs/heads%2Ffeature%2Fx`, `.../branches/{branch}`,
  `.../compare/{base}...{head}`), and a name that contains `/` arrives as `%2F`. Everything else
  holds under such a rule too. The prefix comparison stays on the path as it was received (an
  encoded `/` is no segment boundary: `/repos%2Fo%2Fr` and `/user%2Fkeys` are under no prefix),
  and the rule on dot segments reads the decoded path, so `x%2F..%2F..%2Fy` and `x%2F..;%2Fy`
  are refused. `%252F` is refused there as on every host. So a path with an encoded `/` that
  passes is, on a server that decodes a path before it resolves it, a path under the same prefix
  of the same rule: the encoded `/` reaches no address that a `/` in its place does not reach. A
  rule that sets `encoded_slash` has no `suffixes` and no `denied` list.
- The rule of `api.github.com` beyond the addresses of a resource by its name. The exact path
  `/` is the root of the API, which lists the addresses of the API and holds no value of an
  account: a client reads the scopes of a token from the head of its response. The prefix
  `/repositories/` is the repository of `/repos/{owner}/{repo}/` by its number,
  `/repositories/{id}/...`: GitHub redirects the address of a repository that was renamed or
  moved to it. The list of every public repository, `/repositories` without a `/` behind it,
  is not under the prefix.
- The prefix `/drive/v2/` of `www.googleapis.com` is the second version of the Drive API. It
  reads and writes the files and the permissions of the third version, under the same scopes.
  The upload addresses of that version (`/upload/drive/v2/`) are not part of the rule.
- `denied`: a rule can list paths under its prefixes that are refused all the same. The one
  rule with such a list is that of `graph.microsoft.com`, which denies `/v1.0/$batch`: one
  request to the batch address of Microsoft Graph carries up to 20 requests in its body, and
  the entry of the call would name none of them. A list of refusals holds only when no other
  spelling of a denied path passes, so this comparison does not read the path as it was
  received. It reads the path with its percent escapes decoded once, twice and three times, and
  each of these readings with every segment cut at its first `;` and with its ASCII letters in
  lower case. A path is refused when one of the readings equals a denied path or continues it
  with `/`: `/v1.0/%24batch`, `/v1.0/%2524batch`, `/v1.0/$Batch`, `/v1.0/$batch/` and
  `/v1.0/$batch;x` are refused like `/v1.0/$batch`.
- The same address is read a second time by a WHATWG URL parser (the crate `url`). The scheme, the
  host, the port and the path of that reading must all equal the values read above. An address
  that two parsers read differently is sent nowhere.
- The prefix comparison keeps segment boundaries: when a prefix does not end with `/`, the path
  must equal the prefix, or the character after the prefix must be `/`.
- `suffixes`: a rule can list path ends that are allowed whatever comes before them, when the
  front of the path names something the definition cannot enumerate (the repository of a git
  address). A suffix starts with `/`, so it matches at a segment boundary, and the path must be
  longer than the suffix (`/info/refs` alone does not pass). The one rule with such a list is
  that of `github.com`. Everything else of this section holds for a path that passes by a suffix:
  the refusals of the spellings above, the dot segments, the second reading by the URL parser.
- The load check of the definitions: when the token address or the revocation address of a
  definition is an address that its `api` list reaches, the node does not start. It does not
  start either when a `denied` path does not lie under a prefix of its own rule, or is not
  written in the form of its comparison (lower case, no `;`, no percent escape).
- This list is every address that a credential can be sent to through `forward`. The token
  addresses and the revocation addresses are not on it: `forward` cannot reach an address that
  returns an OAuth token of that provider in a response body. An address of the list can return
  another credential that the provider derives from the token. That is a limit which section 6
  of egress-policy.md states.
- An addition to a list is a new release of the enclave: the definitions are compiled into the
  binary and are part of the measurement.

## 8. Time, randomness, limits

- Time: at boot the node takes a correction of the monotonic clock from `trusted_time_ms`, and it
  takes a new one every 60 seconds (it reads the trusted time three times in a row and uses the
  sample with the shortest round trip). Every time of the node (`time_ms`, the expiry checks,
  TOTP, the verification of TLS certificates) is the monotonic clock plus that correction. The
  node does not use a time that the parent instance gives.
- Node time does not decrease: the function that reads the time remembers the largest value it
  returned, and when a new correction gives a smaller value, it returns that largest value. The
  `time_ms` values of the entries one node created for one account do not decrease with `seq`,
  the `time_ms` values of their events do not decrease with (`seq`, index), and no event is dated
  after its entry (the one
  place that creates an event or closes a batch never dates it before the one in front of it),
  and an expiry that has passed does not come back into force.
- Randomness: the kernel random source.
- Concurrency: at most 512 `forward`, `forward/batch` and `vault/send` calls run at the same
  time (a semaphore; a batch call takes one place, and holds it for the round trips of its
  requests, so the places are not the bound of the throughput of a node: the provider requests
  in flight and the body budget are). A `forward`, `forward/batch` or `vault/send` call waits
  for its place and for the shares of the body budget it takes before its request leaves (the
  share its request frame occupies, and for `vault/send` the share the search of its response
  can hold: about 20 KiB for a value of 30 bytes and 2.3 MiB for one of 12,000 bytes) for at
  most 30 seconds together (`ADMISSION_WAIT`)
  and ends with `capacity_unavailable` when it has not got them by then: the node reads
  nothing from the connection of a call that waits, so it does not learn that the caller of
  such a call is gone, and the wait is what bounds the time such a call holds its connection.
  At most 512 provider requests of the node are in flight at once,
  and a batch sends at most 6 of its requests at a time. The bodies of a request and of a
  response are held in memory, and each of them is `too_large` above 64 MiB (for a batch, the
  bodies of its results together). A call that would raise the sum of the bodies in memory above
  2 GiB waits until there is room. The share of the budget a response body occupies travels
  with the bytes of the response and is free when the connection wrote them: a caller that
  takes a response slowly, or not at all, holds memory the budget counts. The body of a
  response that is handed on as a stream (5.8 step 11) is not held in memory and takes no
  share.
- Connections from the backend: the node holds a bounded number of them open at the same time
  (`inbound_limit` of `load` of health). It computes the bound at its start from the memory of
  its kernel: one eighth of `MemTotal` divided by what one connection can hold that no other
  bound covers (344,064 bytes: the 262,144 bytes the kernel takes into the receive queue of a
  vsock socket before the peer has to wait, two read buffers of 32 KiB of the HTTP
  connection, and 16 KiB for the socket, the task and the state), at least 64 and at most
  16,384. An enclave of 4,096 MiB has 3,943 MiB and holds 1,502 connections; a kernel that
  exposes no memory size (a development machine that is not Linux) gives 16,384. A connection
  accepted while that many are open is closed without a byte and counted in `inbound_refused`
  of `load` of health; the caller sees a connection that ended without a response, as it does
  for a node that is gone, and what it does next follows its own retry rules (the backend of
  the operator tries another node for a call it may repeat).
- A connection from the backend ends within a fixed time whatever its peer does. The node waits
  for the peer of a connection at three places, and at each of them for 60 seconds
  (`inbound_idle`) at the longest: for the head of the next request (before the first request
  and between two requests), for the next bytes of a request body (the call ends with
  `invalid_request`, and the connection after its response), and for the peer to take bytes of
  a response (the connection ends). A write the peer does not take is attempted again every
  second: the kernel of an enclave gives a writer that waits no event when the peer of its
  vsock connection closes, so a write that waited for such an event would wait without an end.
  The HTTP connection reads at most 32 KiB ahead of what it has parsed, and a request head
  above that is answered with the status 431.
- The queue of the listener (the connections that wait for accept) holds as many connections as
  the node holds on the nitro platform. The kernel of an enclave caps the queue of every
  listener at `net.core.somaxconn`, whose default there is 128, whatever a `listen` call asks
  for: the node, the first process of the enclave, writes the bound to
  `/proc/sys/net/core/somaxconn` before it asks for the queue. A kernel that refuses one of
  the two leaves the queue shorter, and the listener works as before.
- A vsock connection the node is done with is closed only after its peer reported the end of
  its bytes. The kernel of an enclave (Linux 4.14.256, the kernel `nitro-cli` 1.5.0 puts into
  an enclave image file) keeps the bytes that reach a vsock socket after the node closed it,
  for as long as the enclave runs. A node is done with a connection while its peer is still
  sending in several places: a call it answered before the end of the request body, a
  connection above its bound, a response of a provider it gave up on. So the node does not
  close such a connection: it closes the write side, which tells the peer that the node is
  done, and a task reads and drops what the peer still sends until the peer reports the end
  of its bytes (`platform::Lingering`). The two relays of the host program end their side at
  once when the node closes its write side (9.1), so the wait is a round trip. At most 1,024
  connections wait at once, each for 10 seconds at the longest; a connection that finds no
  place, and one whose peer has not ended after the 10 seconds, is closed and counted in
  `lingering_cut` of `load` of health. The connections the node accepts and the connections
  it opens to the egress relay are both of this kind. The local platform closes a connection
  when the node is done with it.
- Descriptors: every connection the node accepts and every connection it opens holds one file
  descriptor. The kernel of the enclave starts the node with the default limit of its first
  process, 1,024 open descriptors; at its start the node raises the limit to 65,536
  (`DESCRIPTOR_LIMIT` of `descriptors.rs`: the soft limit, and the hard limit when it is below
  the target), or to its hard limit when the kernel refuses the target. `load` of health reports
  the limit in force and the open descriptors. The bounds of this section keep the descriptors
  of a node below the target: at most 16,384 connections from the backend, 1,024 idle
  connections to the providers, 1,024 kept mail sessions, 32 idle connections to the log
  store, 512 provider requests in flight, 256 connections being opened, 1,024 connections that
  wait for the end of their peer, and the writes to the log store of the calls in progress.
- The size of the enclave: 2 vCPUs (a constant of the host program) and the memory that the
  environment variable `CREDENTIAL_ENCLAVE_MEMORY_MIB` of the host program gives in MiB, 4,096
  when the variable is not set (section 9).
- Output: the node writes nothing to the standard output (a production enclave has no console).
  Diagnostic values leave through `health` and through the failure codes of the calls only. A
  failure message is a fixed string of the source: it carries no credential, no key, no body and
  no query string of an address. The one other output is a fixed line on the standard error when
  the start of the node fails (section 2). A panic writes nothing: the message of a panic can
  hold a value of the call it happened in, and the panic hook of the node counts the panic and
  has no output (3.1).

The limits, as the source states them:

| Limit | Value |
| --- | --- |
| JSON body of a call | 1 MiB |
| `meta` of a `forward` or `forward/batch` frame | 1 MiB |
| Body of a provider request and of a provider response (`forward`); the bodies of the results of a `forward/batch` call together | 64 MiB each |
| Sum of the bodies in memory | 2 GiB |
| Concurrent `forward` and `forward/batch` calls | 512 |
| Wait of a `forward` or `forward/batch` call for its place and for the share of the body budget of its request frame (`ADMISSION_WAIT`) | 30 seconds |
| Connections from the backend held open at once (`inbound_limit` of health) | One eighth of the memory of the kernel divided by 344,064 bytes, 64 to 16,384: 1,502 in an enclave of 4,096 MiB |
| Longest wait for the peer of a connection from the backend: for the head of a request, for the next bytes of a request body, for the peer to take bytes of a response (`inbound_idle`) | 60 seconds |
| Read buffer of the HTTP connection of a caller, and the longest request head | 32 KiB |
| Queue of the listener of the node (nitro platform) | The connections the node holds at once |
| Connections that wait for the end of their peer at once, and the longest wait of one (`LINGERING_CONNECTIONS`, `LINGER_LIMIT`) | 1,024, 10 seconds |
| Open descriptors the node asks the kernel for at its start (`DESCRIPTOR_LIMIT`) | 65,536 |
| Requests in one `forward/batch` call | 100 |
| Requests of one `forward/batch` call in flight at once | 6 |
| Provider requests of the node in flight at once | 512 |
| Outbound connections being opened at once (`open_concurrency`) | 256 |
| Attempts to open one outbound connection (`OPEN_ATTEMPTS`), and the backoff between them | 3, a full jitter of 50 milliseconds doubled per attempt and at most 400 milliseconds, within half the time limit of the call |
| Idle connections to one provider host for one account, and their idle time | 8, 30 seconds |
| Events in one entry | 128 |
| Plaintext of one entry | 1,048,576 bytes |
| `timeout_ms` of `forward` and `forward/batch` | 1,000 to 120,000, default 30,000 |
| `timeout_ms` of a `forward` call that asks for a stream | 1,000 to 600,000, default 30,000 |
| One part of a stream | 1,048,576 bytes |
| Bytes the search of a stream holds back | 27 bytes for each byte of the longest form of the credential, and 32 |
| Address of `forward` | 8,192 bytes |
| Response of a token address | 1 MiB, time limit 15 seconds (`token_timeout`) |
| Late response of a token address call of `refresh` (`token_late_limit`) | 120 seconds from the start of the call |
| Token address calls of `refresh` that go on after their time limit at once (`refresh_late_tasks`) | 128 |
| Call of a revocation address | Time limit 5 seconds |
| Authorization code | 4,096 bytes |
| Value of an authorization parameter | 1,024 characters |
| `client_id` of a dynamic client | 256 characters |
| `redirect_uri` of the operator configuration | 2,048 bytes |
| `origin` of `release` | 512 bytes |
| Challenges a node keeps | 100,000 |
| Pending authorizations a node keeps | 100,000 |
| One attempt to write an entry to the log store | Time limit 5 seconds (`log_write`; an attempt over an idle connection: half of it. A call that waits for the write of another call: twice that) |
| The attempts to write one entry | A budget of twice the time limit of an attempt, a full jitter backoff of 100 milliseconds doubled per attempt and at most 1 second between them, a margin of 1 second for a repeated attempt |
| Writes of one call to the log store at the same time | 32 |
| Entries the sweep writes per second (`sweep_write_rate`) | 64 |
| Idle connections to the log store | 32 |
| Pending entries of an account at which a call that uses a credential creates no further entry | 64 |
| Merge keys of one account (`merge_keys`: the events of GET requests the node remembers for it at one time, protocol.md 7.2) | 8,192 |
| The node document (protocol.md 7.7) | Written again when the latest confirmed write is 30 days old; a node takes a user key and writes an entry while that write is less than 31 days old |
| `access_key_id`, `secret_access_key`, `session_token` of the log store | 128 characters, 256 bytes, 8,192 bytes |

The constants of the protocol (the lifetime of a grant, of a challenge and of a pending
authorization, the merge window, the kept `refresh` responses, the page of a transfer, the nodes
that one grant is handed to, the caps of an entry, the retention of an object of the log store,
the longest `context`) are in protocol.md section 12.

## 9. The host program (`credential-enclave-host`)

The host program runs inside the parent pod of the enclave. It is an untrusted component: nothing
that a node guarantees depends on it. It is kept in this repository next to the node program. It
takes no argument, or the one argument `drain` (the row `drain` below), and it reads its
configuration from environment variables.

| Function | What it does |
| --- | --- |
| Start | Before the enclave, the host program raises its own limit of open descriptors to 65,536 (`descriptors.rs`), or to its hard limit when the target is above it (the container does not hold `CAP_SYS_RESOURCE`), and logs the limits in force. Then `nitro-cli run-enclave --eif-path /opt/credential-enclave/enclave.eif --cpu-count 2 --memory {memory} --enclave-cid 16`, where `{memory}` is the value of the environment variable `CREDENTIAL_ENCLAVE_MEMORY_MIB` in MiB and 4,096 when the variable is not set or empty. A value that is not a positive decimal integer (a sign, a leading zero, a fraction, letters, a value above 4,294,967,295) ends the host program before the start of the enclave with one line on the standard error that names the variable and the value, and a status that is not 0. The host program logs the memory and the vCPUs it starts the enclave with. When the start fails, the host program prints the ends of the `nitro-cli` log files and ends with a status that is not 0 |
| Inbound relay | For every connection on TCP `0.0.0.0:8080` it opens a connection to vsock `16:8080` and moves the bytes in both directions (the pipe of 9.1). It does not read the bytes: the call surface of the node ends inside the enclave. It holds a bounded number of connections of callers at once: 16,384 until the node answers its first `health` call, and from then on the bound the node reports (`inbound_limit`) less 8 places, which stay free for the calls the host program itself makes to the node (the probes of the pod, the metrics, the watch). A connection above the bound is closed without a byte and counted. It counts the connections for which the vsock connection to the node failed or did not open within its time limit of 5 seconds (the Status row): a caller whose connection the relay closes without a byte. The queue of its TCP listener is asked for 16,384 connections (the kernel caps it at `net.core.somaxconn` of the network namespace of the pod) |
| Egress relay | It listens on vsock port 8443. It reads the first line `CONNECT {host}:{port}\n`. When the host is on the allow list and the port is 443, it connects by TCP, answers `OK\n` and moves the bytes. Otherwise it sends `ERR\n` and closes. The allow list is the hosts of section 7, the hosts of the token addresses and the revocation addresses of 6.2 (the host program is built from the same definitions file), and the host of the log store, `s3.{region}.amazonaws.com` (the endpoint of Amazon S3 in the region of the store, over which the node writes every bucket of its log store: protocol.md 7.6), when the two variables of the next row name one. TLS ends inside the node, so the relay sees ciphertext only. This list is a second line: the node itself sends a credential only to the addresses of its definitions, and log entries only to the buckets of its log store. The relay sees the host of a connection and not the bucket of a request, which is inside the TLS that ends in the node: which bucket a node writes to is a rule of the node program (the name of its binding and the rule of protocol.md 7.6), not of this list. It holds at most 8,192 connections of the node at once: a connection above the bound is answered `ERR` and no provider is connected (the outcome `over_limit`). The bytes move through the pipe of 9.1. Its listener has a backlog of 1,024 connections (the queue of connections that wait for accept; the kernel of the parent instance resets a connection request that finds the queue full); when the kernel refuses to set it the host program logs one line and keeps the default. A failed accept, on this listener and on the two TCP listeners, is classified by its error: `ECONNABORTED`, `EPROTO`, `EINTR` and `EAGAIN` (the connection was gone before accept returned it, or the call was interrupted) are followed by the next accept at once; `EMFILE`, `ENFILE`, `ENOBUFS` and `ENOMEM` (the process or the kernel is out of descriptors or memory) and every other error are followed by a pause of 50 milliseconds. The egress relay counts its failed accepts by class (`aborted`, `resources`, `other`), its connections by outcome and the connections whose bytes it moves at this moment (the Status row) |
| Operator configuration | It reads the values of every provider from environment variables and calls `POST /v1/config` once the `health` call of the node answers. The variables: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `OUTLOOK_CLIENT_ID`, `OUTLOOK_CLIENT_SECRET`, `SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET`, `NOTION_CLIENT_ID`, `NOTION_CLIENT_SECRET`, `X_CLIENT_ID`, `X_CLIENT_SECRET`, `LINK_CLIENT_ID`, `LINK_CLIENT_SECRET`, `STRIPE_PUBLISHABLE_KEY`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, and `CHARACTER_API_BASE_URL` (the front of the callback address `{value}/api/integrations/{provider}/oauth/callback`). The configuration names every provider of the definitions: `redirect_uri` is always set, and a value without a variable is the empty string. `CREDENTIAL_ENCLAVE_LOG_BUCKET` and `CREDENTIAL_ENCLAVE_LOG_REGION` name the log store: when both are set and have the forms of protocol.md 4.1, the configuration carries them as `log_store`. When one is missing or has another form, the configuration carries no `log_store` and one line of the log says why. Without `CHARACTER_API_BASE_URL` no configuration is sent. A configuration that the node refuses is not sent again. The host program does not send the credentials for the log store: the backend sends them (5.14) |
| Status | TCP 9091: `GET /healthz` (200 when the round trip of the `health` call of the node succeeds within 8 seconds, 503 otherwise: the responsiveness of the node, read by the startup and readiness probes of the pod), `GET /livez` (200 while the enclave runs, 503 once the watch of the enclave (the Watch row) confirmed that it ended: the life of the enclave, read by the liveness probe of the pod. It makes no call to the node: a node that does not answer is not a dead enclave, and a pod replaced for that reason would lose the delegations of a living node) and `GET /metrics` (the Prometheus text format). Four gauges: `credential_enclave_up` (1 when the `health` round trip succeeds, 0 when it fails), `credential_enclave_configured` (1 when `configured` of `health` is true), `credential_enclave_accounts` (`accounts` of `health`), `credential_enclave_started_timestamp_seconds` (`started_ms` of `health` in seconds). From the `log` object of `health`, when the node answers with one: the counters `credential_enclave_log_entries_total` (`entries`), `credential_enclave_log_events_total` (`events`), `credential_enclave_log_store_writes_total` (`writes`), `credential_enclave_log_store_write_failures_total` (`write_failures`), `credential_enclave_forward_batch_calls_total` (`batch_calls`), `credential_enclave_forward_batch_requests_total` (`batch_requests`), and the gauge `credential_enclave_log_open_batches` (`open_batches`); and, when the object holds the write counts of 5.1: the counter `credential_enclave_log_store_write_attempt_failures_total{cause}` (`write_attempt_failures`; `cause` is `connect`, `tls`, `closed`, `timeout`, `status_4xx` or `status_5xx`), the counter `credential_enclave_log_store_write_retries_total` (`write_retries`), and the histogram `credential_enclave_log_store_write_seconds`: `_bucket{le}` for `le` `0.025`, `0.05`, `0.1`, `0.25`, `0.5`, `1`, `2.5` and `5` from the cumulative counts of `write_ms_buckets`, `_bucket{le="+Inf"}` and `_count` from `write_count`, `_sum` from `write_ms_sum` as seconds with three decimals. From the `log_store` object of `health`, when it is not null: the gauge `credential_enclave_log_store_pending_accounts` (`pending`) and, when the object holds `pending_oldest_ms`, the gauge `credential_enclave_log_store_pending_oldest_seconds` (its milliseconds as seconds with three decimals), and, when the object holds `node_document_ms` (a node of release v2.4.0 or later), the gauge `credential_enclave_log_store_node_document_timestamp_seconds` (its milliseconds as seconds with three decimals: the time of the latest write of the node document that the store confirmed, 0 when it confirmed none). From the `load` object of `health`, when the node answers with one: the gauges `credential_enclave_provider_inflight` (`provider_inflight`) and `credential_enclave_forward_calls` (`forward_calls`); when its three CPU values are not null, the counters `credential_enclave_cpu_user_seconds_total`, `credential_enclave_cpu_system_seconds_total` and `credential_enclave_cpu_idle_seconds_total` (the milliseconds of `health` as seconds with three decimals); when its two memory values are not null, the gauges `credential_enclave_memory_total_bytes` and `credential_enclave_memory_available_bytes`; when the object holds the two counts of the connections from the backend (a node of release v2.2.0 or later), the gauge `credential_enclave_inbound_connections` (`inbound_connections`) and the counter `credential_enclave_inbound_refused_total` (`inbound_refused`); when it holds the bound (a node of release v2.4.0 or later), the gauge `credential_enclave_inbound_limit` (`inbound_limit`); when it holds the value, the gauge `credential_enclave_descriptors_open` (`descriptors_open`) and the gauge `credential_enclave_descriptors_limit` (`descriptors_limit`); when it holds the two counts of the connections that wait for the end of their peer (a node of release v2.4.0 or later on the nitro platform), the gauge `credential_enclave_lingering_connections` (`lingering_connections`) and the counter `credential_enclave_lingering_cut_total` (`lingering_cut`); when it holds the two counts of the faults the node contained (a node of release v2.4.0 or later), the counter `credential_enclave_contained_panics_total` (`contained_panics`) and the gauge `credential_enclave_halted_accounts` (`halted_accounts`). From the `egress` object of `health`, when the node answers with one: the counter `credential_enclave_egress_opens_total` (`opens`), the counter `credential_enclave_egress_open_failures_total{cause}` (`open_failures`; `cause` is `transport`, `relay_refused`, `tls` or `http`), the counter `credential_enclave_egress_open_retries_total` (`open_retries`), the gauge `credential_enclave_egress_open_inflight` (`open_inflight`) and the counter `credential_enclave_egress_idle_reuses_total{peer}` (`idle_reuses`; `peer` is `provider` or `log_store`, and `mail` for a node of release v2.4.0 or later, which reports the mail reads that went over a kept session). From the `refresh` object of `health`, when the node answers with one: the counter `credential_enclave_refresh_late_total{outcome}` (`late`; `outcome` is `kept`, `dropped`, `failed` or `abandoned`) and the gauge `credential_enclave_refresh_late_inflight` (`late_inflight`). After the series of the objects, when the answer holds the value: the gauge `credential_enclave_grants` (`grants` of `health`, the accounts with a grant within its time; every release answers it). From the `state` object of `health`, when the node answers with one: the gauges `credential_enclave_kept_refreshes` (`kept_refreshes`), `credential_enclave_merge_keys` (`merge_keys`), `credential_enclave_pending_entries` (`pending_entries`) and `credential_enclave_idle_connections{peer}` (`idle_connections`; `peer` is `provider` or `log_store`, and `mail` for a node of release v2.4.0 or later, which reports the IMAP sessions it keeps). From the host program itself, with every answer, after the series of `health`: the gauge `credential_enclave_host_enclave_running` (1 while the last `describe-enclaves` of the watch listed a running enclave or none ran yet, 0 when it listed none), the gauges `credential_enclave_host_descriptors_open` and `credential_enclave_host_descriptors_limit` (the open descriptors of the host program and its limit in force, when the kernel gives both), the counter `credential_enclave_host_egress_accept_errors_total{cause}` (the failed accepts of the egress relay; `cause` is `aborted`, `resources` or `other`), the gauge `credential_enclave_host_socket_memory_bytes` (the memory of socket buffers charged to the container of the host program: the line `sock` of `memory.stat` of its cgroup, when the kernel gives it), the counter `credential_enclave_host_egress_relays_total{outcome}` (the connections of the node the egress relay served; `outcome` is `relayed`, `malformed`, `not_allowed`, `unreachable` or `over_limit`), the counter `credential_enclave_host_inbound_node_connect_failures_total` (the connections of callers for which the inbound relay could not open its connection to the node), the counter `credential_enclave_host_inbound_refused_total` (the connections of callers the inbound relay closed without a byte because it held its bound), and for each of the two relays (`{relay}` is `egress` or `inbound`) the series of its pipes (9.1): the gauge `credential_enclave_host_{relay}_relays_inflight` (the connections it holds at this moment), the gauge `credential_enclave_host_{relay}_relays_limit` (its bound), the gauges `credential_enclave_host_{relay}_relays_oldest_seconds` and `credential_enclave_host_{relay}_relays_idle_seconds` (the age of the connection it has held longest, and the longest time one of its connections has moved no byte), the gauge `credential_enclave_host_{relay}_relays_large_buffers` (the buffers of 64 KiB its pipes hold) and the counter `credential_enclave_host_{relay}_relays_ended_total{cause}` (the pipes that ended; `cause` is `closed`, `failed`, `idle` or `half_closed`), and after them the counter `credential_enclave_host_contained_panics_total` (the panics of the host program that ended one connection and did not end the program: the Faults row). A pipe that does not end shows as `_relays_idle_seconds` above 900 and as a growing count of the causes `idle` and `half_closed`; the cause `failed` counts a provider that reset its connection as well and is no sign of a fault. When the `health` call fails, the answer is `credential_enclave_up 0` and the series of the host program. A counter of the node restarts at 0 when the node restarts (the started timestamp changes), a CPU counter when the kernel of the node boots, and a counter of the host program when the host program starts |
| Sending the operator configuration again | Does not happen. The configuration is sent once at the start. To change a value, the pod is replaced |
| Watch | Every 10 seconds the host program runs `nitro-cli describe-enclaves` (in a blocking task; an answer is waited for 5 seconds, a run that takes longer is waited for at the next poll and no second run starts beside it) and reads its JSON list: an element whose `State` is `RUNNING` is a running enclave. Before the third consecutive answer without a running enclave counts, the host program makes one `health` call to the node: a node that answers is alive whatever the list said, the answer counts as a running enclave and the count starts over (a node that does not answer is judged by the list alone). Three consecutive answers without a running enclave confirm that the enclave ended on its own (the node program aborted, the enclave ran out of memory, the hypervisor ended it): the host program logs it, makes the shutdown collection call of the Shutdown row (the backend records the node as closed; the collection fails at its first stage, as the node is gone), calls `nitro-cli terminate-enclave --all` and ends with a status that is not 0, so that the container runtime starts it again with a new enclave, which takes its delegations from the living nodes. One answer without a running enclave does not confirm the end (one line of the log says that the list was empty), and a run that failed or passed its 5 seconds changes nothing: a host program that ended on a reading failure would end a living node and lose its delegations. `GET /livez` and the gauge `credential_enclave_host_enclave_running` of the Status row read the same observations |
| Shutdown | On SIGTERM (or SIGINT) the host program logs one line with the output of `nitro-cli describe-enclaves` on one line (the JSON list of the running enclaves: the enclave object while the node is alive, `[]` when the enclave ended before the signal; the line says whether the node was alive when the signal came). Then it does three things in this order, calls `nitro-cli terminate-enclave --all` and ends. First it closes the node: `POST /v1/close`, without a body, in one attempt (`host/src/calls.rs`). A closed node begins no use of a credential and no request (5.11): a call that reaches it ends with `closing`, and its caller takes it to another node. Second, in a pod of the delegation role, it calls `POST {CREDENTIAL_ENCLAVE_DRAIN_URL}` (the shutdown collection route of the backend): the body `{"pod": "<the value of CREDENTIAL_ENCLAVE_POD_NAME>"}`, the headers `Authorization: Bearer {CREDENTIAL_ENCLAVE_DRAIN_TOKEN}` and `Content-Type: application/json`. Inside that request the backend makes the calls of the orderly shutdown to the node (5.11, 5.13), through the inbound relay: it moves the delegations of the node while the calls the node is in the middle of end. Before the call the host program reads `grants` of the `health` call of the node (the delegations the node holds) and waits for the response for 100 seconds plus 4 seconds for every started page of 1,000 delegations, at most 600 seconds (`drain::response_timeout`: the backend hands the delegations over page by page, 1,000 accounts a page; a node that does not answer its `health` call gets the 100 seconds). The log names the wait and the delegations. When one of the three variables (`CREDENTIAL_ENCLAVE_DRAIN_URL`, `CREDENTIAL_ENCLAVE_DRAIN_TOKEN`, `CREDENTIAL_ENCLAVE_POD_NAME`) is missing, the collection is left out. The call of the signal path repeats the call of the `drain` subcommand when the pre-stop hook made one: the backend takes a repeated call for the same pod as the same collection. Third it waits for the calls the node is in the middle of and for the connections of their callers (the paragraph "The calls in progress at a shutdown" below): for 660 seconds at the most from the signal until the node holds no place of a forward call, and from then on for 60 seconds at the most. The collection, 600 seconds at the most, ends inside the 660 seconds, so the signal path takes 720 seconds at the most. The `terminationGracePeriodSeconds` of a pod of the delegation role must cover the longest wait of the `drain` subcommand, the signal path and a margin: 610 + 720 + 30 = 1,360 seconds. When the watch confirmed that the enclave ended on its own, the node is not closed and not waited for, and the collection call tells the backend that the node of the pod is gone |
| `drain` | `credential-enclave-host drain` makes the shutdown collection call of the Shutdown row alone (the same request, from the same three variables, after the same `health` call for the delegations of the node), waits for the response for the wait of the Shutdown row plus 10 seconds from its start (110 seconds for a node without delegations, at most 610 seconds), logs one line with the outcome (the status of the response and the elapsed milliseconds, the failure and the elapsed milliseconds, or the end of the wait) and ends with the status 0 in every case: a failed collection does not hold the end of the pod. When one of the three variables is missing, or the address cannot be used, it logs one line and ends with the status 0 without a call, and so it does in a pod of the forward role, whose node holds nothing to collect. The pre-stop hook of a pod of the delegation role runs it before the termination signal reaches the host program, while the node is alive |
| Faults | The enclave ends with the host program: the end of the first process of the container ends `nitro-cli` and the enclave with it. So the host program unwinds on a panic, as the node program does (3.1), and a panic ends the smallest part it can (`host/src/faults.rs`). Every connection of the two relays and of the status surface is served on a task of its own: a panic there ends that task, its two streams are closed, and the place and the buffers it held are given back; the node or the caller sees a connection that failed. A panic of a task the program cannot do without ends the process, and the container starts again with a new enclave: the main task, the three tasks that accept connections (the two relays, the status surface), the watch of the enclave and the task that sends the operator configuration. The one lock of the program guards the times of the open pipes, which the metrics read, and is used as it is after a panic under it. A panic is logged as one line with the place it happened at (the file, the line and the column) and without its message, which can hold a value of the environment, and it is counted (the Status row) |
| local | The node program with `--platform local` runs alone, without the host program. Whatever starts it sends the operator configuration |

The output of the host program is its log: lines on the standard output, and the output of
`nitro-cli`. The client values of the operator are never part of a line.

**The calls in progress at a shutdown.** A call the node is in the middle of when its enclave
ends is cut: its caller reads a connection that ended without a response or in the middle of
one, and does not know whether the request of the call reached the provider or the site. So the
host program of a pod of either role lets the calls in progress end before it ends the enclave
(`host/src/calls.rs`).

- The node is closed at the signal (the Shutdown row). The calls that reach it from then on end
  with `closing`, and the calls it had accepted go on.
- The host program reads `forward_calls` of `load` of the `health` call of the node every 500
  milliseconds until the value is 0. The calls that hold a place of a forward call are the ones
  that carry a request to a provider or to a site and hand its response on: `forward`,
  `forward/batch` and the mail calls on a node of the delegation role, `vault/send` on a node
  of the forward role. A call holds its place from before it reads the closing flag to the end
  of its response body. So a closed node that holds no place has no such request in progress
  and begins none. In a pod of the delegation role the first reading comes after the shutdown
  collection call: the delegations of the node move while its calls in progress end.
- Then the host program waits until every connection of a caller that the inbound relay held at
  that moment has ended: the last part of a response and the end record of its stream may
  still be on their way to the caller, and a call that holds no place (`refresh`,
  `oauth/complete`, `release`, a command of an app) ends within the time of this wait. A
  connection the relay takes after that moment is not waited for.
- The two waits have limits, and the enclave ends after them whatever the node said. The wait
  for the places of the node is 660 seconds at the most, counted from the signal: 600 seconds,
  the longest time limit of a call that holds a place (a `forward` call that asked for its
  response as a stream, 5.8, and a `vault/send` call, 5.16), and 60 seconds, within which a
  call that held its place when the node was closed begins its request. A `forward` call has
  its entry confirmed first, and the node waits for the log store for at most twice the time
  of a write at each of its two steps (5.14). A `vault/send` call sends the request of an
  envelope before the end of the envelope, and the node takes no envelope whose end lies more
  than 60 seconds ahead (protocol.md 10.5). A place that is still held then is the place of no
  request (a call whose caller is still sending its frame holds one). A node that does not
  take the `close` call, or gives no answer about its places, is asked again until that limit:
  its calls may be going on all the same. The wait for the connections of the callers is 60
  seconds at the most, counted from the moment the node held no place: the time for which the
  node itself waits for a caller to take bytes of a response (`inbound_idle`, section 8); the
  time limit of a token address call, 15 seconds (6.3), lies inside it. When the watch
  confirmed that the enclave ended on its own, before the signal or during a wait, nothing is
  waited for.
- The log names each step with the milliseconds since the signal, and how the wait ended. Its
  lines begin with `calls:`.

**The pod of a node of the forward role.** The environment variable `CREDENTIAL_ENCLAVE_ROLE`
names the role of the node of the pod: a pod that does not set it is a pod of the delegation
role, the value `forward` names the forward role, and any other value ends the host program
before it starts an enclave. In a pod of the forward role:

- The operator configuration is `{"role":"forward"}` (5.1). The host program sends it once the
  node answers, and it starts the inbound relay only after the node took the role: a call of the
  delegation role would give a node without a role that role. A node that refuses the role ends
  the host program, and the container starts again with a new enclave.
- The host program reads no client value of a provider, no log store and no address of the
  shutdown collection, and makes no shutdown collection call: the node holds nothing to collect.
- The shutdown has no collection. It closes the node and waits for its calls in progress, the
  sends of the node, as the next paragraph states. A request of `vault/send` is the one request
  of its envelope, which is not sent a second time (5.16): a node that ended in the middle of
  one would leave a caller that does not know whether its request reached the site. A closed
  node begins no request: a `vault/send` call ends with `closing`, its envelope stays unused,
  and its caller takes it to another node.
- The `terminationGracePeriodSeconds` of a pod of the forward role must cover the two waits
  and a margin for the line of `describe-enclaves` and the end of the enclave: 660 + 60 + 30 =
  750 seconds. The pod needs no pre-stop hook: nothing has to happen before the signal, and the
  subcommand `drain` makes no call in such a pod.
- The egress relay connects to port 443 of any site at a public address, and to nothing else. It
  takes a DNS name of two labels or more whose last label begins with a letter (the form of the
  host of a site, protocol.md section 6), looks the name up once as a name from the root (the
  search list of the pod is not applied), and connects to the public IPv4 addresses among the
  answers: an address outside the special-purpose ranges of IPv4 (this network, private use,
  shared address space, loopback, link local, the protocol assignments, documentation,
  benchmarking, multicast and the reserved ranges). A name whose addresses are all outside the
  public internet, every IPv6 address, another port and the two mail endpoints are refused
  (`ERR\n`). The site of a vault secret is a host an account chose, so no list names it. What
  the relay keeps the node from is the network of the operator: the addresses of the cluster, of
  the VPC and of the instance metadata service.

### 9.1 The pipe of the two relays

A pipe moves the bytes between the two connections of a relay (`host/src/relay.rs`). It has a
side that asks and a side that answers: a caller and the node for the inbound relay, the node
and a provider (or the log store) for the egress relay.

- A pipe ends within a fixed time whatever its two ends do. It ends when no byte moved in
  either direction for 900 seconds while both directions are open (the cause `idle`: 900
  seconds are above every silence of a connection in use, the longest of which is the time
  limit of a call), and when no byte moved for 60 seconds after one of its streams reported
  the end of its bytes (the cause `half_closed`). A byte the pipe drops is not a byte that
  moved.
- A pipe does not wait for the kernel to say that a write can go on. The kernel of the parent
  instance gives a writer that waits no event when the peer of its vsock connection closes
  while the socket holds unread bytes: a write that waited for such an event would wait
  without an end, and the pipe would keep its TCP socket with the bytes its peer sent. So a
  write a stream did not take is asked of it again every second and at once when the other
  direction ends, and a write to a vsock connection is attempted each time it is asked for.
- The end of the bytes of the node says that the node is done with the connection: the node
  closes its write side when it is done and keeps the connection open only until its peer
  ended too (section 8). So a pipe that read the end of the bytes of the node closes the
  write side of its connection to the node at once and moves nothing more to it. The inbound
  relay moves the answer of the node to the caller and reads and drops what the caller still
  sends, until the caller reports its end: a caller that was sending the body of its request
  when the node answered reads the whole answer and closes its connection itself. The egress
  relay moves the last bytes of the node to the provider and ends: nobody waits for what the
  provider still sends.
- When the side that asks is gone (a write to it fails), nobody waits for an answer, and the
  pipe ends at once. When the side that answers closed, the pipe stays open for what it sent
  last.
- A direction of a pipe holds a buffer of 4 KiB. While it moves many bytes it takes one of
  the 2,048 buffers of 64 KiB of its relay and gives it back when it has not held 4 KiB at
  once for one second; while the relay has none to give, the direction goes on with the small
  buffer.
- The connections of the relays set no TCP keepalive: the first probe of the kernel comes
  after 7,200 seconds, past both limits of a pipe.

The memory of the parent container: the host program holds at most 16,384 + 8,192
connections with two buffers of 4 KiB each and 2 x 2,048 buffers of 64 KiB (about 450 MiB
when every bound is reached). The receive queues of its TCP sockets are memory of the kernel
of the parent instance that is charged to the container (`sock` of `memory.stat`): the kernel
grows the receive queue of one socket up to `tcp_rmem` (32 MiB on the parent instances of
this service) and bounds all of them together at the third value of `net.ipv4.tcp_mem`.

## 10. Stages 2 and 3

This section describes calls that the current release does not implement. The delegation transfer
between nodes of the same release and to a node of a later release (5.13) is part of stage 1.

| Stage | Call | What it adds |
| --- | --- | --- |
| 2 | `POST /v1/peer/witness` | Witnessing (protocol.md 10.2). The backend carries the messages |
| 2 | Step 7 of `forward` and of the other calls that create an entry | The node obtains a witness signature for every entry and acts after that. When no peer is alive, it continues without a witness, and the entry has no witness signature (the app counts such an entry as "not witnessed") |
| 3 | `peer/export` | The node hands the delegation of an account over also when the measurement of the receiving node is neither its own nor that of an endorsed later release, if the list of allowed measurements that the grant of that account carries holds that value (the last item of protocol.md 10.1) |

## 11. Build and release

### 11.1 The reproducible build

`build/build.sh` is the single entry point. Its reference machine is Linux x86_64 with git and
Docker (with buildx), and it needs nothing else.

```bash
build/build.sh eif     # out/enclave.eif and out/measurements.json
build/build.sh host    # the host image credential-enclave-host:{release}, from the files of out/
build/build.sh         # eif, then host (the same as `all`)
```

The script builds the commit `HEAD`, not the work tree: the build context is `git archive HEAD`,
and the script stops when the work tree has uncommitted changes. It prints the measurements (the
content of `out/measurements.json`) to the standard output, or the name of the host image for
`host`. Everything else goes to the standard error.

| Row | What happens | What is fixed |
| --- | --- | --- |
| 1 | `Dockerfile.enclave`: in a fixed Rust builder image (Alpine), `cargo build --release --locked --target x86_64-unknown-linux-musl -p credential-enclave`. The result is copied into an image `FROM scratch` with `ENTRYPOINT ["/credential-enclave","--platform","nitro"]` | The digest of the builder image. The build installs no package: the builder image holds the C library headers (`musl-dev`) that the C parts of the crate `ring` need, and the Dockerfile asserts their version and the version of `rustc`. `rust-toolchain.toml`, `Cargo.lock`, the release profile (`opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "unwind"`, `strip = true`), `WORKDIR /build`, `SOURCE_DATE_EPOCH` (the time of the commit), `CARGO_INCREMENTAL=0`, `TZ=UTC`, `LC_ALL=C`, `--remap-path-prefix` |
| 2 | BuildKit creates the image with `SOURCE_DATE_EPOCH` and `--output type=docker,rewrite-timestamp=true` | The version of BuildKit (the digest of its image) |
| 3 | `Dockerfile.eif`: `amazonlinux:2023`, fixed by digest, with `aws-nitro-enclaves-cli` and `aws-nitro-enclaves-cli-devel` of a fixed version. In it, `nitro-cli build-enclave --docker-uri ... --output-file enclave.eif` | The digest of the base image, the name, version and release of the two packages, and the SHA-256 of the files that `nitro-cli` puts into every enclave image file (`bzImage`, `cmdline`, `init`, `linuxkit`, `nsm.ko`), which the build records |
| 4 | The output: `out/enclave.eif` and `out/measurements.json` (`{"release","git_commit","pcr0","pcr1","pcr2","inputs":{...}}`). `inputs` names what the three measurements were made of: the digests of the three images, the SHA-256 of `rust-toolchain.toml`, `Cargo.toml`, `Cargo.lock`, the two Dockerfiles and `build.sh`, of the five files of row 3, and of the node binary | |
| 5 | `Dockerfile.host`: the host program, built with the builder image of row 1 and linked statically, on the base image of row 3 with `nitro-cli`. Files: `/usr/local/bin/credential-enclave-host`, `/opt/credential-enclave/enclave.eif`, `/opt/credential-enclave/measurements.json`. Directories: `/run/nitro_enclaves`, `/var/log/nitro_enclaves`. `ENTRYPOINT ["/usr/local/bin/credential-enclave-host"]` (no argument). The user is root (`nitro-cli` needs it for the enclave device). The host program listens on TCP 8080 and 9091. This image is not measured | |
| 6 | `Dockerfile.local`: the node program, built with the same builder image, as the one file of an image `FROM scratch`. It builds natively on linux/amd64 and on linux/arm64: `docker build -f build/Dockerfile.local -t credential-enclave-local:dev .`. `ENTRYPOINT ["/credential-enclave","--platform","local"]`. It listens on TCP 8080. This image is for development stacks. No workflow builds or publishes it: a release consists of what the measurements cover and of the host image around it | |

- The release tag is a build input: `build.sh` passes the git tag of the commit (`v*`, or `dev`
  for a commit without a tag) as `CREDENTIAL_ENCLAVE_RELEASE`, and the node program compiles that
  value in as a constant (the `release` of `binding`).
- Four files of `enclave/release/` are build inputs: the node program compiles them in, so they
  are part of the measurement (protocol.md 10.3). `release-key.pem` is the release key of the
  operator, an ECDSA P-256 public key as a SubjectPublicKeyInfo in PEM. `rekor-key.pem` and
  `rekor-log2025-1-key.pem` are the public keys of the two rows of the table of transparency
  logs (`enclave/src/lineage.rs`), each as a SubjectPublicKeyInfo in PEM: the ECDSA P-256 key
  of Rekor of rekor.sigstore.dev, a log of the form Rekor v1, and the Ed25519 key of
  log2025-1.rekor.sigstore.dev, a log of the form Rekor v2, whose row states that name as the
  origin of the log. `predecessors.json` is the list of the releases whose nodes a node of this
  build takes delegations from: `[{"release","pcr0","pcr1","pcr2"}]`, with the values of the
  `measurements.json` of each of those releases. Every release of the list is earlier than the
  release of the build. A build without a tag (`dev`) starts with the empty list only.
- The table of transparency logs is the transparency logs of the trusted root of the public
  instance of Sigstore. `protocol/tests/fixtures/sigstore-trusted-root.json` is that file as of
  the day it was read, and a test of `enclave/src/lineage.rs` fails when the file names a log
  the table has no row for. Before a release is tagged, the file is read again from the
  repository of the trusted root (`targets/trusted_root.json` of `sigstore/root-signing`): when
  it names a further log, the release adds the key file and the row of that log (protocol.md
  10.3 states why the endorsement of a release needs a log that every release in service has).
- The endorsement of a release (protocol.md 10.3) is made outside this repository: the operator
  signs the `measurements.json` of the release with the private half of the release key and
  records the signature in a transparency log of the table of the releases in service. This
  repository holds the public half only, and no workflow of it creates an endorsement.
- The identity of a release is PCR0, PCR1 and PCR2. The hash of the enclave image file is not the
  identity: the metadata section of the file holds the build time and is not measured.
- The enclave image file is not signed (no PCR8, no certificate that expires).
- There is one architecture: x86_64.
- The test of reproducibility: two builds of the same commit on two machines give the same PCR0,
  PCR1 and PCR2. The `release` workflow builds twice, in two independent jobs, and creates a
  release only when the two results are equal.
- A machine of another architecture runs the linux/amd64 programs of the build under emulation.
  The step of row 3 (`nitro-cli` in a container) has been observed to crash under the QEMU
  emulation of Docker Desktop on an Apple Silicon Mac, so the full build is not stated to work
  there. A reader without the reference machine has two other sources for the measurements of a
  commit: the `check` workflow builds the enclave image file on every push and keeps
  `measurements.json` as an artifact of the run, and every GitHub release carries the
  `measurements.json` that two independent builds agreed on.

### 11.2 The workflows

| File | Trigger | Jobs |
| --- | --- | --- |
| `check.yml` | A push to any branch, a pull request | `check`: `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`, the vector check (`cargo run --locked -p credential-enclave-protocol --bin vectors -- --check`: the committed file equals the output of the generator), `scripts/secret-access.sh --check` (rule E2 of egress-policy.md), the tests of the secure program on the model of the bridge (`node --test secure-program/tests/program.test.js`, secure-program/README.md), and the tests of the comparison of the transparency log monitor (`python3 -m unittest discover -s secure-program/tests -p 'test_*.py'`). `measure` (on a push): `build/build.sh eif`, and `out/measurements.json` as the artifact `measurements` |
| `release.yml` | The push of a `v*` tag | `check`: the checks above and `cargo audit` (no dependency of `Cargo.lock` has a security advisory). `build-a`, `build-b`: `build/build.sh eif` each, and the release of the build is the pushed tag. `compare`: the two `measurements.json` are equal, otherwise there is no release. `publish`: the host image around the enclave image file of `build-a` to `ghcr.io/pickle-com/credential-enclave/host:{tag}`, the GitHub release with `enclave.eif` and `measurements.json`, two attestations of the enclave image file (its build provenance, and the release statement of protocol.md section 9, whose predicate is `measurements.json`), and their bundles on the GitHub release (`provenance.sigstore.json`, `release-statement.sigstore.json`) |
| `secure-program-release.yml` | The push of a `secure-program-v*` tag | `release`: `secure-program/statement.py` writes the release statement of the tag (protocol.md, "The secure program release"; the job fails when the version of `secure-program/secure-program.js` is not the N of the tag), creates the GitHub release of the tag with `secure-program.js` and `statement.json`, and attaches a build provenance attestation of the file (`secure-program-provenance.sigstore.json`). The signature of the release key and the entry of the transparency log are made outside this repository, by the operator on the machine that holds the release key, and uploaded to the same release as `secure-program.release.json` |
| `secure-program-monitor.yml` | Every hour (`17 * * * *`), and `workflow_dispatch` | `monitor`: `secure-program/monitor.py` asks Rekor for every entry of the release key (`POST /api/v1/index/retrieve`) and compares the statement hash of each with the statements of the releases of this repository: of every `secure-program-v*` tag (the statement rebuilt from the file and the commit of the tag) and of every `v*` tag (the bytes of `measurements.json` of its GitHub release, read through the API of GitHub; a request that failed for a reason that can pass is sent again, four attempts in all). The run has one of three results. Every entry is the statement of a release: the job succeeds and closes the open issues of the monitor. An entry that no release explains, or an entry of another key: the job fails and opens the issue "Transparency log: entry of the release key without a matching release" with the report, or adds the report as a comment to the open one. The comparison is not complete (the log could not be searched, an entry could not be read, or an entry matches no statement that was read while the statement of a release could not be read): the job fails without that issue, because such an entry may be the entry of the release whose statement was not read; when the five runs before it failed too, the job opens the issue "Transparency log monitor: the comparison could not be completed", or adds the report to the open one. The monitor reads `rekor.sigstore.dev` alone. It does not read the entries of `log2025-1.rekor.sigstore.dev`, the second log of the table of a node (protocol.md 10.3): that log has no search by key, and its entries are read from its tiles |

- The runner is `ubuntu-24.04`, and every action is fixed by its commit SHA. The permissions of
  `publish` are `id-token: write`, `contents: write`, `attestations: write` and
  `packages: write`. The permissions of `release` of `secure-program-release.yml` are
  `contents: write`, `id-token: write` and `attestations: write`; those of `monitor` of
  `secure-program-monitor.yml` are `contents: read`, `issues: write` and `actions: read`.
- GitHub records an attestation on the public Sigstore instance when the repository is public at
  the time of the run. An attestation of a run in a private repository is not on that public
  record. Its bundle is still attached to the GitHub release.

## 12. Tests

`cargo test --workspace --locked` runs every test below. The tests of the whole node build a node
from the embedded provider definitions, drive it through its router, and put a TLS stand-in in the
place of every provider (`enclave/src/testing.rs`).

| Subject | Where | What is tested |
| --- | --- | --- |
| Formats | `protocol/tests/vectors.rs` | Every vector of `protocol/vectors.json` (protocol.md section 13), and that the committed file equals a fresh run of the generator |
| Formats, per module | The unit tests of `protocol/src/` | Encodings, key derivation, the command envelope and its failure order, the record and its kinds, the log chain, the keys and the entries of format 3 and the node document, the buckets of a log store, the statements, TOTP, the failure codes |
| Endorsement of a later release | The unit tests of `protocol/src/release.rs`, with `protocol/tests/fixtures/rekor-entry-150000000.json` and `rekor-log2025-1-entry-200000163.json`; `protocol/tests/endorsement_vectors.rs` with the two files of endorsements of an independent implementation; the vectors `endorsement` | With keys the tests create, for a log of the form Rekor v1: an endorsement that holds, and the refusal of another log identifier, of a signed entry timestamp over another body, time or index, of a body with a character outside the base64 alphabet, of a body with the hash of another statement, with another public key or with the signature of another key, of a statement with a missing or malformed value or of more than 16,384 bytes, of an entry time more than 300 seconds ahead, and of a release that is not later than the own release (the candidates `-rc.{n}` and an own release `dev` included). For a log of the form Rekor v2: an entry at every leaf of every tree of 1 to 33 leaves and in the largest trees a size of 64 bits states, which a clock does not decide, and the refusal of a checkpoint the log did not sign for this tree (another origin, size or root, a size or a root that has not its form, the signature of another key, of another key ID or under another name, no line of the log, a second line of the log that does not verify, a checkpoint of more than 262,144 bytes), of an audit path that does not lead from the entry to the root (another index, a changed, missing or added hash, a hash of another form, another body), and of a body that is not the record of the statement under the release key (another version, kind or algorithm, another kind of key, a certificate, a key that occurs twice). A checkpoint counts by the lines of the log alone (the lines of witnesses, an extension line the log signed). An entry is read in the form of its log and of no other, and the parts of an entry are read by their form. The form of a release tag and the order of releases. The signed entry timestamp of a real entry of Rekor, and the checkpoint and the audit path of a real entry of log2025-1.rekor.sigstore.dev, verify with the keys of the node program. The list of predecessors: a valid list, malformed elements, an element that is not earlier than the own release. The verdicts of an independent implementation on 22 endorsements of the form Rekor v1 and on 108 endorsements for a node with a log of each form are the verdicts of this one |
| Keys, logs and predecessors of the program | The unit tests of `enclave/src/lineage.rs`, with `protocol/tests/fixtures/sigstore-trusted-root.json` and the endorsement of release v1.5.2 of `verify/tests/fixtures/` | The release key of `enclave/release/` is an ECDSA P-256 key, the table has the two logs with the log identifiers the logs state, every transparency log of the trusted root of Sigstore has a row with its key and its log identifier, the endorsement of a release of this program holds as Rekor returned it, the list of the source is valid for the release of the crate version, and a node does not start with a malformed key, table or list |
| Secret types | `protocol/src/secret.rs` | The `compile_fail` examples and the compile-time assertions of rule E1 (a secret cannot be serialized, formatted, dereferenced or compared, and the private keys of `NodeKeys` cannot be read), and that the `Debug` output of a secret never holds its bytes |
| Attestation documents | The unit tests of `protocol/src/attestation.rs`, `enclave/src/attest.rs` and `enclave/src/platform/nitro.rs`, with the files of `protocol/tests/fixtures/` | The certificate chain and the signature of real Nitro attestation documents, the definite and the indefinite form of the payload, the refusal of another root, of a changed document, of other PCRs and of a debug-mode enclave. A peer under the statement of a later release and a peer of a listed predecessor: accepted with the measurement and the release of the real document, refused with another release in the binding, with another PCR, with another log store, on the local platform, and as a debug-mode enclave |
| Command processing | `enclave/src/tests/commands.rs` | The state transitions of sequences of grant and revoke: a challenge is used once and for 300 seconds, a command for another node or of another user, the range of the expiry, the custody of a grant, a revoke and an old envelope after it, a grant that was held back until after a revoke, replacement, an expired grant, the renewal of the grant in force (no entry, the later end stays, refused while the node cannot write to its log store; a grant after an expiry, after a revoke or of another key has its entry) |
| Records | `enclave/src/tests/records.rs` | A record of another account, of another key or of another custody does not open, and neither does a record with a changed field of its AAD. The kind of a record decides the fields that `release` hands out |
| Log | `enclave/src/tests/log.rs` | The entry is on the chain before the provider is called (the provider stand-in looks at the last entry at the time of the call), the group commit (the events that arrive during a write form the next entry; a merged GET waits for the entry of the event it shares; a control event closes the open batch and stands alone; the caps of 128 events and 1,048,576 bytes), the bound of the GET requests a node remembers for one account, the `log` object of every response, the entries a node wrote verified against the keys of the store (every object against its key, in the bucket of the account, the `prev` of every body, the order of the keys of a prefix), `close` refuses every new call and signs nothing (`close/heads` is no call, and `status` reports the grant alone), a call in progress when the node closes runs to its end, the times of the events and entries of a node for one account |
| Orderly shutdown | `enclave/src/tests/close.rs` | Against a store that refuses or holds writes: an entry the store did not confirm stays with the node through the shutdown (nothing is signed and nothing is dropped: the node holds the entry as unconfirmed, and the store holds the confirmed entries alone); a call that waited for an entry the store never confirmed hands no value out, also when the node closes while it waits; an entry two calls write is a pending entry only when both ended |
| Log store | `enclave/src/tests/log_store.rs`, the unit tests of `enclave/src/log_store.rs` | Against a stand-in for Amazon S3 on the TLS server of the provider stand-in: the write of an entry arrives before the request to the provider, under the key of format 3 whose parts the test computes again from the body, in the bucket of the account, with the headers (the retention, the checksum, the encryption) and a signature that the test computes again from the request. A write the store does not confirm (a status other than 200, a 412 included, no connection, no answer within the time limit) stops the act of every call, the writer and the calls that waited for it. A pending entry is written again with the next write of its account, and a request that shares an event waits for its entry. The signed refusal of a grant, a revoke that erases the key whatever the store answers, the failure and the repetition of `peer/export` to a later release, the refusal of a peer of another log store, a node of the nitro platform without a log store or credentials, the limit of pending entries, calls that end before their write (the account has no writer afterwards), calls that run at the same time form one entry and write each entry once. The idle connections: one connection for writes in a row, a connection the store closed, a write whose idle connection ends without a response, the current credentials over an idle connection. The attempts of a write: a 5xx status and 429 are repeated over a new connection with the same body within the budget, a 4xx status is not, an idle connection that stalls or that closes without a response is left for a new connection, a new connection that closes without a response is repeated as well, a store that cannot be reached is asked for three connections, and the causes and the counts of health. The sweep: its rate, its random order, and the jitter before it writes the entries of an account. The local endpoint: a path-style write over plain HTTP with the host of the endpoint, refused on the nitro platform and for a value that is not an origin. The node document: a node takes no user key (a grant command, a transfer) before the store holds its document, writes it again after 30 days and acts for 31 days on one write, with a retention of 400 days. A log store whose name is too long for its buckets is not taken. The signature against the examples of the AWS documentation |
| Address check | The unit tests of `enclave/src/providers/mod.rs` | The refusals of section 7 (another host, a path outside the lists, a denied path in its spellings, dot segments, dot segments in front of a path parameter, encoded separators and separators that are encoded twice, a port, user information), the two hosts that take an encoded `/` (on each, every path of up to three parts behind every prefix, joined by `/` or by an encoded `/`: a path that passes is inside the rule as it was received and after one decoding of its escapes, and has no dot segment then), the root and the repository by number of the API of GitHub, the second version of the Drive API, and the validation of the definitions, including the rules for public fields |
| OAuth | `enclave/src/tests/oauth.rs`, the unit tests of `enclave/src/oauth.rs` | Against the provider stand-in: exchange, refresh, the merge of a reconnect, the nested token place of slack and its `ok: false`, the public fields and the containment check, the closed vocabulary of `provider_error`, the kept response of a repeated refresh, a token address call of `refresh` whose response arrives after the time limit of the call (kept for the next call with the same record; dropped after a revoke or after `close`; a late refusal and the late limit; the bound of the late calls and their counts in health), a record of kind `oauth_imported` |
| forward | `enclave/src/tests/forward.rs`, the unit tests of `enclave/src/provider_response.rs` and `enclave/src/egress.rs` | Header removal, the refusal of a header that overrides the method and of the batch address of Microsoft Graph, the injected credential, the event of a GET request with a body, the whole path and the whole query in the event of the longest address, redirects that are not followed, chunked responses, the body limit, the time limit, a response that reflects the credential (as it is, under percent escapes of up to three layers, in base64 and in hexadecimal), the idle connections per (account, host): two accounts never share one, a connection is dropped after 30 seconds idle, a GET over an idle connection that ends without a response is sent once more and a POST is not; an open that fails before a request byte left is repeated within half the time limit of the call (two refusals and then a success, three refusals, a refusal that arrives after half the time limit), the bound of connections being opened at once, and the counts of `egress` of health; a call that is not admitted within its wait ends with `capacity_unavailable` and holds nothing; the headers the node drops (`Range`, `If-Range`, `Accept-Charset`, names written with `_`), the refusal of an `Accept` header that names another character encoding than UTF-8. The stream form: a body above the body limit is handed on in parts, with a declared length and chunked; a body that holds the credential is cut in front of it; a head that holds it, or a coded body, begins no stream; the end record of a body that does not arrive and of the time limit; the place of the call is free at the time limit whether or not the caller reads, and at once when the caller is gone; `stream` and the time limit of a stream are checked. The search of a stream (`provider_response.rs`): bodies in parts of any length are handed on whole without the credential, are cut in front of every form of it at every place (as it is, base64, hexadecimal, under one to three layers of escapes, each byte escaped), and get the verdict of the check of a whole response |
| Mail calls | `enclave/src/tests/mail.rs`, `enclave/src/tests/mail_connections.rs`, the unit tests of `enclave/src/imap.rs`, `enclave/src/mail.rs` and `enclave/src/mail_sessions.rs` | Against TLS stand-ins for imap.naver.com and smtp.naver.com (`enclave/src/tests/mail_stand_in.rs` is one whose answers a test writes): the three calls authenticate over TLS that ends inside the node and return no password; a read checks the generation of its mailbox and a reflected password is withheld; a submission whose reply is lost is delivered once and not sent again, and a refused recipient sends no data; a refused login is told apart from a provider failure. The order of a call: a record of another kind and a submission of another form are refused without an entry; a plaintext the call cannot use is `record_invalid` after the entry of the call, for each of the three calls, and a submission of another sender is refused after its entry, each without a connection to the provider. The reader of the responses: the responses of a read in pieces of every length, a status line that ends in the form of a literal declaration, a declaration that is reported before an octet behind it is taken, three responses that end the parser of the crate imap-proto 0.17.0 with a panic (a character outside ASCII directly behind the response code of a tagged and of an untagged status response, and `INTERNALDATE NIL`), bytes that are no response, 60,000 responses with changed, removed and added bytes, and that the reading of a response does not depend on its pieces; inside a call: those three responses, a warning while a mailbox opens, responses about other messages, the items of one message in two responses, and the names of a folder listing (a quoted name without its escapes, a name in a literal, a name in UTF-8, names a node cannot put into a command). The share of the body budget: the fixed share of each call at its login, the share of concurrent folder listings and of a read inside its message, a read that ends where the budget has no room for its input (with its entry, and its share given back), a verification and a submission that are refused before their entry, a literal above the input bound, and that excess mail calls do not wait in front of an HTTP call. The bounds of a connection: the bytes of a search, the text of one response and the declarations of literals end a read at their bound with `provider_unreachable`, and the same responses below the bounds are read; a declaration counts as input whatever length it declares. The kept sessions: the reads of a record go over one session and each has its entry; a read sends no command over a kept session before the log store confirmed its entry (the command arrives after the answer of a store that holds the confirmation back), and a read whose entry the store refuses sends nothing and leaves the session where it was; another ciphertext has a session of its own; no read goes over a session after a revoke, after the end of its grant, after `grants/prune` dropped its grant or while the node closes, and a read in progress at a revoke or at `close` leaves none; a session ends at its idle time without a call and is handed to no call 300 seconds after its login; a read over a session that ended starts once more with a login, and one whose session fails after the server completed a command fails; a session is kept when its read left it in step; two reads at the same time leave one session; a refused login ends the kept session of its record; the bound of the kept sessions of a node. A panic (3.1), raised by the test platform on a node that takes its calls from a listener: a read that panics behind its entry, on the second start of a read whose kept session had ended, ends without a response, the session it went over ends with it and is not kept, no forward place and nothing of the body budget stays held, the account is not halted, and the next read of the record logs in and is answered; after a panic inside the lock of an account, a read of the account that was reading its mailbox is answered and leaves no session, every mail call of the account after it ends with `internal` without a command to the server, a connection or an entry, and the session the node kept for a record of the account is handed to none of them. Three tests are not part of `cargo test` (`--ignored`): two print what concurrent folder listings hold of the body budget and what consecutive reads cost in connections and logins, and one reads the mailbox of an IMAP server of another implementation and compares the result with what another client read (`enclave/src/tests/mail_probe.rs`) |
| Vault | `enclave/src/tests/vault.rs`, `vault_handoff.rs`, `vault_send.rs` and `roles.rs`, the unit tests of `enclave/src/vault.rs`, `enclave/src/bound.rs`, `enclave/src/role.rs`, `protocol/src/vault_secret.rs`, `protocol/src/secret_use.rs` and `protocol/src/released.rs` | `release` of a vault secret: the slot `field`, the hosts of the record and the hosts below them, no entry for a refused call, the value judged after its entry, the sealed value and its key. `vault/store`: the two kinds, the plaintext the node writes and its source, the `id` and the nonce of the node, no record before the store confirmed the entry. The roles: a node takes one role, a node of the forward role answers no call of the delegation role and gets no delegation. `vault/handoff` and `vault/send` with both nodes and a stand-in for the site: the value at every slot in the form of its place, the reach of the record, one event per handoff and no envelope before its entry is confirmed, one envelope one request within its time, a request that is not the request of its envelope, the two lists of headers, the two halves of HTTP Basic, a value that cannot add a header or leave its place, the stream of the response and its cut in front of a reflected value in every form, a body that ends early or not in time, a connection of its own for every request, the shares of the body budget, a closing node. The log of format 3: the entries of `vault/store`, `release` and `vault/handoff` in the store verify against their keys and open with the log key of the account, in the bucket of the account and under the prefix of their kind; the three calls create no entry while the store holds no node document that outlives it; a node of the forward role takes no credentials for a log store and writes nothing to one; a transfer among nodes of one program has no entry and goes to no node of the forward role |
| forward/batch | `enclave/src/tests/forward_batch.rs` | One entry names every request before any leaves; a batch of 100 with 6 in flight; a request that fails the address check refuses the whole call with its index and creates no event; a merged request inside a batch shares the event; two entries when the open batch reaches its cap inside a batch; one failed request leaves the other results intact and keeps its `log` object; the bodies of the results together under the body limit; the results in the order of the requests; the bodies split by `body_bytes`; a batch of 0 or 101 requests is invalid |
| Delegation transfer | `enclave/src/tests/peer.rs` | The round trip of export and import between two nodes of the local platform without an entry on either node (the `accounts` of the import, the node documents of both nodes in the store), a transfer to a later release and from an earlier release with the entries `grant_transferred_out` (the receiving node, its release and its measurement) and `grant_transferred_in` (the giving node and its release), paging, the exclusion of expired grants and of accounts that revoked, a grant of another `sign_pk` is not replaced, the refusal of a changed envelope and of an envelope for another node, a repeated export to the same peer of a later release without a new entry, the limit of 64 peers of a later release per grant, an export with an endorsement that does not hold (it hands nothing over and leaves no entry, also for a peer the call without an endorsement accepts), the `subset` of export (the share of the peer alone, and pages that count the selected grants) and of import (the share of the receiving node alone out of a transfer of every account, `copies` at or above `pods` names every account, `null` is a call without a subset, a subset outside its bounds is refused by both calls). The transfers between releases run on peers the tests accept themselves: the attestation of a peer has its own tests (the row "Attestation documents") |
| Delegation subset and pruning | `enclave/src/tests/grants.rs`, the unit tests of `enclave/src/subset.rs` | The assignment vectors of protocol.md 10.4 and the agreement of `contains` with `assign`; `grants/prune` drops the grants within their time and the expired grants outside the share page by page in `user_id` order, leaves the chains, the revocation markers and the grants of the share, prunes nothing more on a repeated walk, works in the state `closing`, and refuses a missing subset, a subset outside its bounds and a `limit` of 0; after grants, a refresh, merged GET requests, refused writes, an expiry, a revoke, an import, a prune, two sweeps and the shutdown, every count of health (`accounts`, `grants`, `pending`, `pending_entries`, `kept_refreshes`, `merge_keys`, `open_batches`) equals a scan of the accounts, and no account holds memory for merge keys, kept responses or unconfirmed entries it does not have |
| Connections from the backend | `enclave/src/tests/inbound.rs`, the unit tests of `enclave/src/inbound.rs` and `enclave/src/platform/lingering.rs` | The bound of the connections from the memory of the kernel. A request body whose bytes stop arriving ends its call with `invalid_request` after the time limit and frees its share of the body budget; a caller that takes no byte of a response is cut after the time limit and frees the share of the response body, which is held until then; a write that is not taken is attempted again without an event; a request head above the read buffer is answered with 431. A connection that is dropped closes its write side and is closed after the end of its peer, within the time limit and the bound of waiting connections, and a connection whose peer had ended is closed at once |
| Faults | `enclave/src/tests/faults.rs`, the unit tests of `enclave/src/faults.rs` and `enclave/src/state.rs` | A node that takes its calls from a listener, with panics the test platform raises at a place of a call (a draw of the random source, a request to the attestation device): a call that panics, and a call whose task panics, end without a response while a call in progress runs to its end and the next calls are answered; nothing of the call stays held, and the panic is counted in health. A call that panics while it is the writer of its account, in the backoff after a refused write: its entry is a pending entry, the account has no writer and is not halted, and the call that waited for it writes both entries and acts. A panic inside the lock of an account halts the account: every call that needs its state (the calls that use a credential, a grant command, `status`) ends with `internal` without a provider request and without an entry, a revoke command gets the signed reply of a revoke and leaves the account halted, its grant, its pending entry and its confirmed entries are given up, the counts of health follow, the sweep writes nothing of it, a transfer does not hand it on and does not bring it back, a prune passes it by, and the other account of the node is served. The writer and a waiting call of an account that is halted meanwhile end with `internal` and hand no value out, also after the store confirmed the entry of the writer. A sweep that panicked is followed by the next sweep, which writes what the first left. In a process of their own: a panic under a lock of the whole node ends the process at the next lock, a panic of a task the node cannot do without ends the process and the panic of another task does not, the panic hook of the node writes nothing and counts, and a second panic while a first one unwinds ends the process without a line that holds the message or the place of either |
| Call surface | `enclave/src/tests/surface.rs`, the unit tests of `enclave/src/load.rs` and `enclave/src/descriptors.rs` | `health` with the counts of its `log`, `egress`, `refresh` and `state` objects and the values of its `load` object (the readers of `/proc/stat`, `/proc/meminfo` and the auxiliary vector on sample text: the columns of each mode, a line with fewer columns, malformed text; the limit of open descriptors is raised or kept and never lowered, and the count of open descriptors follows the descriptors the process holds), the bound of the connections from the backend (a connection above the bound is closed without a byte and counted, an idle connection is closed after the idle time and frees its place), the operator configuration, attestation and its challenge statement, the failure bodies, HTTP/1.1 over a real connection, that `log/entries` and `log/ack` do not exist, and that the calls of the router are the calls of the table in section 4 of egress-policy.md |
| Egress policy | `enclave/src/tests/canary.rs` | The canary test of egress-policy.md: every secret carries a distinct marker, the provider stand-in breaks its contract on purpose (reflected credentials, tokens in public fields, content and transfer codings, cookies, redirects), every call of the router is made in a success and in a failure, no marker appears in a response in any of the searched encodings, and a credential reaches only the addresses of its own provider. The one exception is the requested field of a successful `release`. Both nodes of the walk have a log store: no write to it carries a secret of the account, and of the credentials for it the session token reaches the log store alone and the secret access key no request |
| Host program | The unit tests of `host/src/` | The pipe of the relays (9.1): the two limits, a transfer that lasts longer than both, a write that is not taken and is attempted again every second without an event, the end of the node (the write side of the node is closed at once, the answer reaches a caller that is still sending, the provider is cut off), a side that asks and is gone, the buffers of the two sizes, the bound of a relay and the ages of its connections, the bound the inbound relay takes from the node. The relays (the inbound relay counts the connections for which the node could not be reached, and closes a connection above its bound without a byte), the allow list of the egress relay with the host of the log store, the operator configuration with the log store of the environment, the memory of the enclave from its variable (the default, a value, the refused values), the description line of the enclaves, the one argument `drain`, the status surface (the four gauges, the seven series of the `log` object of `health`, which the answer of a node of a release before v2.0.0 does not have, the seven series of its `load` object, which the answer of a node of a release before v2.0.1 does not have and whose CPU and memory series are absent when the values are null, the series of its `egress`, `refresh` and `state` objects, the gauge of its `grants` value, and the four series of the two relays) the shutdown call and its wait (the base, the pages of the delegations of the node, the longest wait), the watch of the enclave (the reading of the answer of `describe-enclaves`, three consecutive answers without a running enclave confirm the end and one does not, a failed run does not count, a node that answers its health call keeps the end from being confirmed), `/livez` from the watch and not from the node, the series of a node of release v2.2.0 (the connections from the backend, the descriptors of the node and of the host program, the gauge of the watch), the gauge of the node document of a node of release v2.4.0, the series of the peer `mail` of such a node (the mail reads over a kept session and the kept sessions, which the answer of a node of an earlier release does not have), the two series of the faults a node of release v2.4.0 contained, the count of the panics of the host program, the limit of open descriptors of the host program, and the shutdown of a pod (the `close` call without a body before any other call, the wait while the node holds a place of a forward call, the wait for the connections of callers that were open when the last call ended and not for a later one, a node that does not take the `close` call is asked again, the limits of the two waits (660 and 60 seconds), which count from the signal across a collection that runs between the close and the wait, no wait for an enclave that ended on its own, and for a pod of the delegation role the order of the three: the node is closed, the backend is asked to collect, the calls in progress end), against a stand-in for the node over in-memory pipes and a stand-in for the backend. In a process of its own (`host/src/faults.rs`): a panic of a task the host program cannot do without ends the process, the panic of the task of a connection ends that task alone and is counted, and the line of a panic names its place and nothing of its message |
| Verification tool | The unit tests of `verify/src/`, `verify/tests/offline.rs`, with the files of `verify/tests/fixtures/` | The checks on a stored attestation document of a node of release v1.0.0 against the `measurements.json` of that release, the refusals, the report with the log store of a binding, and the exit status of the built tool |


## Mail call surface

GET /v1/health adds `mail_providers: ["naver_mail"]`. An absent field on an older release means
no mail support. POST /v1/mail/verify, /v1/mail/read and /v1/mail/submit use the forward binary
frame. Meta is `{user_id, record, context, request}`; only submit has payload bytes (ASCII SMTP
MIME with CRLF). The response is the forward frame with `status`, `headers`, `log` and body.

Verify takes an empty request and returns JSON `{identity,node,statement}`. Read takes
`action: folders|search|read`, optional `mailbox` (INBOX), `uid_validity`, `uid`, `before_uid`,
`from`, `subject`, `since` (YYYY-MM-DD), and `limit` (1..50, default 20). Search returns
`uid_validity`, messages with UID/size/base64 headers, and `next_uid`. Read requires UIDVALIDITY
and UID and returns message/rfc822 bytes. A changed UIDVALIDITY returns frame status 409;
a missing message 404; rejected authentication 401. Protocol/transport failures use fixed
existing error codes. No provider transcript appears in a diagnostic.

Submit takes `{recipients:[address,...]}` (1..50) and raw MIME as payload. Its From must equal
the record account. It authenticates with SMTP, checks every recipient before DATA, dot-stuffs
the payload, and returns JSON `{status:accepted|rejected,smtp_code}`. Accepted requires the
final 250 after DATA. A dropped connection after DATA is provider_unreachable, not rejected.
The backend owns the persistent submission intent and must never retry that unknown outcome.

These calls require a configured log store. Both protocols have fixed destinations and TLS
ends in the node. The parent egress relay additionally permits exactly those two host/port pairs.
The mail module performs no persistent mailbox synchronization and stores no message body.

The order of a mail call. Before the event `mail_request` is created, the node judges what is
the same for every value the record can hold: the form of the request (for `submit`: one to 50
recipients that are addresses, and a message of ASCII lines that end in CRLF with exactly one
`From` field; another form is `invalid_request`), the grant, the AEAD verification of the
record, and its kind and provider (`not_allowed` for a record that is not an `app_password`
record of `naver_mail`). A call that is refused up to here creates no entry. The node reads the
plaintext of the record after the log store confirmed the entry that holds the event. A
plaintext that is no JSON object, a `username` that is no NAVER account name (1 to 64
characters of ASCII letters, digits, `_`, `.` and `-`, with or without `@naver.com`), and a
`password` shorter than 8 bytes, longer than 256 bytes or with a control character are
`record_invalid` (422) at that point. A submission whose `From` field is not the account of
the record is answered then with the frame status 400 and the body
`{"code":"invalid_mail_request"}`. In both cases no connection to the provider is opened, and
the entry stays on the chain as the entry of a mail call that did not take place. So no answer
of a mail call depends on the content of a record unless an entry records the call.

The reader of the IMAP responses. The node reads what the IMAP server sends with a reader of
its own (`enclave/src/imap.rs`); no parser of another crate sees those bytes. The reader reads
the responses to the commands a mail call sends (`LOGIN`, `LIST`, `EXAMINE`, `UID SEARCH`,
`UID FETCH`) and takes from a response what those commands need: the condition of a status
response and the response codes `UIDVALIDITY` and `UIDNEXT`, the name of a folder (`LIST`), the
numbers of a search (`SEARCH`), and of a message (`FETCH`) its `UID`, its `RFC822.SIZE`, its
header (`BODY[HEADER]`) and its body (`BODY[]`). Every other part of a response is passed over
by its syntax (an atom, a quoted string, a literal, a list with everything inside it) and is
not interpreted.

- A response is one line, or a line that declares a literal (`{N}` in front of its line end),
  the N octets of the literal and the line that follows them, which can declare a further
  literal. A line declares a literal only in an untagged response that is no status response.
  The text of a status response (`OK`, `NO`, `BAD`, `BYE`, `PREAUTH`, with a tag or without)
  and of a continuation request reaches to the end of its line: a server can put a text of the
  caller there (the name of a refused login, the name of a folder that does not exist), and a
  line such as `NO Mailbox doesn't exist: x{100000}` is one line.
- No byte a server sends ends the node. The reader indexes nothing without a check, follows a
  list inside a list by a count and not by a call, makes no text of the bytes of a status
  response, and allocates for a literal only after the connection held its declared length
  against the input bound and the share of the body budget of the call (below). Bytes that are
  no response the reader reads (a tag without a condition behind it, a `LIST` or `FETCH`
  response in another form than its syntax, a declaration whose digits are no unsigned number
  of 64 bits) end the connection, and the call ends with `provider_unreachable`.
- The completion of a command says how the command ended. An untagged `NO` or `BAD` is a
  warning (RFC 3501 sections 7.1.2 and 7.1.3) and decides nothing. An untagged `BYE`, and the
  completion of a command the node did not send, end the connection.
- `EXAMINE` gives the generation of a mailbox (`UIDVALIDITY`, also when it is 0: imap.naver.com
  answers `INBOX` with 0) and the UID of its next message (`UIDNEXT`, when the server names
  one). A mailbox the server does not open, and one whose generation it does not name, fail
  the read with `provider_unreachable`.
- A folder listing hands on the names a read can put into a command: 1 to 1,024 bytes of UTF-8
  without a control character, as the server means them (a quoted name without its escapes,
  the octets of a literal, an atom). A folder with another name is left out. The name `INBOX`
  in any case of its letters is `INBOX`.
- A search and a read take the messages they asked for by UID. The items of one message can
  arrive in more than one `FETCH` response and are put together; a response about another
  message (an unsolicited one, or one without a UID) is dropped when it was read.
  `RFC822.SIZE` is read as a number of 64 bits, and a message above the body limit is
  `too_large` before its body is asked for.
- A `NO` reply to `LOGIN` says that the server refused the application password only when it
  carries the RFC 5530 response code `AUTHENTICATIONFAILED` or the information `Authentication
  failed`, which imap.naver.com sends with its own response code `[AUTH]`; any other failure of
  the login is a provider failure. The line of `LOGIN` that holds the password is overwritten
  when it was written.

The input of a connection. The protocol input an IMAP connection delivers to one call has a
bound: 4 MiB for a folder listing or a search (headers included), the body limit plus 1 MiB
for the read of one message (the returned message itself still has the body limit), and 64 KiB
for the connection of a verification, which reads the greeting and the answer to the login. An
SMTP connection delivers 64 KiB. A search whose UID set or headers exceed the bound must be
narrowed. Three rules keep what an IMAP connection holds of its input inside that bound,
whatever a server sends:

- A literal the server declares above what is left of the bound ends the input when it is
  declared, before a buffer is made for it.
- The declaration of a literal counts as 96 bytes of the input (`LITERAL_INPUT_BYTES`), beside
  the octets it declares. The reader keeps a place for every literal of the response it stands
  in, whatever the length of the literal, and a server can declare a literal without an octet
  in 4 bytes of a line: with this count the literals of a connection are bounded like its
  bytes, and the share of the body budget of the call covers what the reader keeps for them.
- The text of one response (its lines, without the octets of its literals) is at most 4 MiB
  (`RESPONSE_TEXT_BYTES`) on every connection. That is the input bound of a search, whose line
  of numbers is the longest response a node reads. The connection of the read of one message
  has a larger input bound, for the literal of the message: a response whose text passes
  4 MiB ends that connection.

The share of the body budget. A mail call holds a share of the body budget of the node (section
8: the 2 GiB that also admit the bodies of `forward`) for what it holds in memory, and takes it
in two parts.

| Call | Taken before the request frame is read | Taken while the protocol input arrives |
| --- | --- | --- |
| `mail/verify` | The frame, 64 KiB (`CALL_BYTES`), the 64 KiB of its IMAP connection, the 64 KiB of its SMTP connection | Nothing |
| `mail/read`: `folders`, `search` | The frame, 64 KiB | 6 bytes per byte of IMAP input |
| `mail/read`: `read` | The frame, 64 KiB | 2 bytes per byte of IMAP input |
| `mail/submit` | The frame (the payload is part of it), 64 KiB, the 64 KiB of its SMTP connection | Nothing |

- The frame is taken by its declared length (the frame limit when none is declared) and by its
  length once it was read. The 64 KiB are what a call holds beside its frame and its mail: its
  parsed request, the read buffer of its connection and the head of its response frame.
- The second part follows the input of a read in steps of 64 KiB: for every byte the read takes
  from its connection, for every octet of a literal when the server declares it, and for the
  96 bytes each declaration counts as, the share grows before the reader takes the byte. Six
  bytes per byte cover what a folder listing or a search holds at its peak, whatever the
  server sends: the text of the response it reads (a buffer that grows by doubling), and what
  it keeps of the responses before. A folder listing keeps the JSON document it answers with,
  written as the names arrive, and no list of the names beside it. A search keeps the numbers
  of its `SEARCH` responses (four bytes for a number of at least two bytes of text, in a list
  made with the room for the numbers of a response), then the header blocks of at most 50
  messages, each once (as the octets of its literal or as its base64, 4/3 of them), and the
  JSON document it makes of them. The check of the response makes one copy of the document.
  Two bytes per byte cover a message and the copy the check makes of it.
  So the share of a read is what the read took, and the shares of the reads of a node add up
  to the mail the node holds: a folder listing whose server sends 3,750 bytes holds its frame
  and 128 KiB, and the 512 forward places bound the number of such calls before the budget
  does.
- A mail call takes its forward place and every part of its share without waiting: no mail
  call stands in the queue of the body budget. When the place or the first part is not free,
  the call ends with HTTP 503 `capacity_unavailable` before its entry is created: no credential
  was opened and no provider was called. When the budget has no room for a step of a read, the
  input of the read ends there, and the call ends with `capacity_unavailable` and the message
  `the node has no room for the mail the call reads; the call changed nothing`: the entry of
  the call is on the chain, the call read from the mailbox and changed nothing in it, and
  nothing of what it read leaves. A verification and a submission take the whole of their
  share before their entry, so `capacity_unavailable` of one of them says that nothing was
  sent.
- The response frame keeps the share of its body and 64 KiB until the connection wrote it; the
  rest of the share is given back when the frame is made. A call that ends without a frame
  gives all of it back. Admitted calls retain the 30-second deadline, their admission included.

The sessions of the reads. The reads of a record go over one authenticated IMAP session
(`enclave/src/mail_sessions.rs`). The first read opens a connection and logs in with the
application password of its record. When it ends, the node keeps the session, and the next
read of the record sends its commands over it: that read neither opens a connection nor logs
in. What is kept is the TLS connection the server accepted the password for; a kept session
holds no byte of the password and nothing of the body budget.

- Every read has its entry. A read takes a kept session only after the log store confirmed the
  entry that holds its event, as a read that logs in sends its login only then. A kept session
  is no way to reach a mailbox without an entry.
- A session is kept under the account, the `id` of its record and the SHA-256 of the `ct` of
  the record, and under the delegation its read ran under: the signing public key of the grant
  and the revoke serial of the account. It is handed to a read of that record and of that
  delegation alone. A record of another ciphertext (the same mailbox under a new record) has a
  session of its own. A read after a revoke runs under a larger revoke serial, and a read under
  the grant of another key under another signing public key: neither gets a session that was
  kept before, and the session ends when such a read asks for it.
- The read that takes a session, and the read that gives one back, look at the account at that
  moment: a session is taken and kept only while the grant of the account is within its time,
  the account accepted no revoke since the read created its event, and the node is not closing.
  So no read goes over a session after a revoke, after the end of its grant, or while the node
  closes, and a read that was in progress then leaves no session behind.
- A session that carries no read ends 30 seconds after its last read, and 300 seconds after
  its login at the latest, whether a read asks for it or not: the node ends it at that time. A
  session is handed to no read 300 seconds after its login, so the server accepted the
  application password of a read at most that long before the read, also while reads follow
  each other closely. The sessions are kept beside the idle connections to the providers and
  not in the state of an account: the end of a grant, a revoke, `grants/prune` and `close`
  end no session by themselves, and a session of such an account is held for its idle time at
  the longest and carries no read in it.
- A panic and the sessions (3.1). The session a read goes over is held by that read and is not
  among the kept sessions while the read runs: a read that panics drops it, and its connection
  ends with the read. The table of the kept sessions is state of the whole node. Its lock is
  held around a change of the table alone, a session that leaves the table is dropped after the
  lock is free, and no byte of a server is read under it; a panic while it is held ends the
  process. An account the node halted has no grant, so no read of it takes or keeps a session:
  a mail call of the account ends with `internal` before it comes to one, a read that was
  reading its mailbox when the account was halted runs to its end, is answered and leaves no
  session, and a session the node kept for the account ends at its idle time.
- A record keeps one session: of two reads of a record that ran at the same time, the session
  of the later login stays. A node keeps 1,024 sessions; at that number the session that
  carried no read for the longest time ends for the one that comes.
- A session is kept when its read left it in step with the server: every command of the read
  got its completion, whatever the read answered (a message that is not there, another
  generation of the mailbox, a folder the server does not open). A response nobody asked for
  that the server sent behind the last completion is read by the next read of the session. A
  read that ended inside a response (a failure of the connection, the input bound, the end of
  its share of the body budget, its time limit) leaves no session.
- A kept session that ended while it carried no read (the server closed it) does not fail the
  read that takes it. When the connection ends before the server completed a command of the
  read, the read starts once more over a new connection, with a login. Every command of a read
  examines, lists, searches or fetches and changes nothing in the mailbox (`EXAMINE` and
  `BODY.PEEK`), so the second start repeats no act. A session that fails after the server
  completed a command of the read fails the read.
- A verification logs in on a connection of its own and keeps no session. A login the server
  refuses (the frame status 401) ends the session the record keeps.
- `health` reports the reads that went over a kept session since the node started (`mail` of
  `egress.idle_reuses`) and the sessions the node keeps at this moment (`mail` of
  `state.idle_connections`).

FROM and SUBJECT search values use synchronizing UTF-8 literals with byte lengths, waiting
for the server continuation before each literal (RFC 3501 sections 4.3 and 6.4.4). This avoids
assuming that an IMAP server accepts non-ASCII quoted strings or supports LITERAL+.
