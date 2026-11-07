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
│   ├── tests/fixtures/           # real Nitro attestation documents, an unrelated root certificate, a real entry of the transparency log
│   └── vectors.json              # the test vectors of protocol.md section 13
├── enclave/                      # crate credential-enclave (binary credential-enclave)
│   ├── release/{release-key.pem,rekor-key.pem,predecessors.json}   # compiled into the node program (5.13, 11.1)
│   ├── src/main.rs               # the argument, the choice of the platform, the start of the server
│   ├── src/platform/mod.rs       # trait Platform (section 2)
│   ├── src/platform/nitro.rs     # NSM attestation, vsock listener, vsock egress
│   ├── src/platform/local.rs     # unsigned document, TCP listener, direct egress
│   ├── src/state.rs              # the state of a node (section 3), the counts of health, the events of the log
│   ├── src/subset.rs             # the delegation subset: which accounts a node holds (protocol.md 10.4)
│   ├── src/clock.rs              # node time (section 8)
│   ├── src/api/mod.rs            # the router, the failure responses
│   ├── src/api/responses.rs      # every response type (rule E3 of the egress policy)
│   ├── src/api/{health,config,attestation,messages,status,oauth,refresh,revoke,forward,forward_batch,mail,app_password,release,close,peer,grants,log_store}.rs
│   ├── src/attest.rs             # which peer a node accepts (same platform; same measurement, a later release with an endorsement, a predecessor)
│   ├── src/lineage.rs            # the release key, the log key and the list of predecessors of the program (5.13)
│   ├── src/load.rs               # the CPU time and the memory of the kernel, from procfs, for `load` of health (5.1)
│   ├── src/descriptors.rs        # the limit of open descriptors the node raises at its start, and the two descriptor values of `load` of health (section 8)
│   ├── src/providers/mod.rs      # the provider definitions: parsing, validation, the address check
│   ├── src/providers/definitions.json
│   ├── src/oauth.rs              # the authorization address, the token address call, the merge rules, the public fields
│   ├── src/vault.rs              # the vault kinds and the value `release` hands out
│   ├── src/provider_response.rs  # the check of a provider response before `forward` returns it
│   ├── src/egress.rs             # the TLS client (rustls), the idle connections per (account, host), the node-wide bound of provider requests
│   ├── src/log_store.rs          # the log store: the group commit, the write of an entry, its signature, the pending entries, the idle connections (5.14)
│   ├── src/frame.rs              # the frame of `forward` (5.8) and of `forward/batch` (5.8b)
│   ├── src/testing.rs            # tests only: the provider stand-in, the test platform and clock
│   └── src/tests/                # tests only: the tests of the whole node (section 12)
├── host/                         # crate credential-enclave-host (binary credential-enclave-host)
│   └── src/{main,launch,relay,egress,config,health,watch,descriptors,drain,http,testing}.rs
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
- The release profile is a build input of the measured binary: `opt-level = 3`, `lto = "fat"`,
  `codegen-units = 1`, `panic = "abort"`, `strip = true`.

### 1.1 The modules of the protocol crate

The protocol crate holds the pure functions that the node program, the generator of the test
vectors and the verifiers of a node share. No function of the crate performs input or output or
reads a clock: randomness and time are arguments.

| Module | What it holds |
| --- | --- |
| `lib.rs` | The purpose strings of protocol.md section 3 (`purpose`), the constants of section 12 and the length limits (`limits`), the failure codes (`ProtocolError`: its variants and the codes of section 11 correspond one to one), the name rule of section 1 (`is_valid_name`) |
| `encoding.rs` | base64url without padding, the JSON serialization rule, the carriage of signed values `{body, sig}`, Ed25519 signing and verification over the purpose string and the body bytes |
| `secret.rs` | The types that hold a secret: `Secret<T>` and `NodeKeys` (rule E1 of the egress policy). A `Secret` is read through `expose_secret` only, implements neither `Serialize` nor `Display`, prints a fixed string as `Debug`, and is overwritten with zeros when it is dropped. `NodeKeys` offers the operations that use the two private keys of a node (sign, open) and no function that returns them |
| `keys.rs` | The custody mode, `node` and `key_id`, HKDF-SHA256, the derivation of the record key, the binding document, the name of a log store (`LogStoreId`: a bucket name and a region name of the forms of protocol.md 4.1) |
| `envelope.rs` | The command envelope and the commands inside it (the checks 1 to 9 of protocol.md 5.3), the signed reply, the transfer envelope between nodes (protocol.md 10.1), and the single-shot HPKE seal and open |
| `record.rs` | The credential record: the kinds and their use modes, the AAD, opening and creating |
| `log.rs` | The log entry of format 2 (one entry, one or more events) and of format 1 (read only), the two chain hashes, the head, the key of an entry in the log store and its parsing into the parts of either format |
| `statement.rs` | The node statements: the challenge statement of an attestation response (protocol.md 4.2), and `oauth_begin` and `oauth_complete` (protocol.md 8.2) |
| `totp.rs` | TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30 seconds) |
| `release.rs` | The delegation transfer to a later release (protocol.md 10.3): the release statement, the six checks of an endorsement (the statement, the log identifier, the signed entry timestamp, the body of the entry with the release key and its signature, the time of the entry, the order of the two releases), the order of release tags, the reader of a list of predecessors, the reader of the PEM of a public key. The release key and the log key are arguments |
| `attestation.rs` | Reading and verifying attestation documents: the Nitro document (CBOR, COSE_Sign1, the certificate chain, the signature, the PCRs), the binding, the local document. It holds the trust root (AWS Nitro Enclaves Root-G1, DER) as a public constant. It returns what a document states and does not judge a measurement: which PCR values are acceptable is the decision of the caller |
| `app.rs` | The app side of the protocol: the derivation of the account keys, the check of a challenge statement, sealing a command, opening log entries, verifying a chain of format 2 from the keys of the listing (index verification) and from its entries (content verification), verifying a chain of format 1. The node program does not call this module. The generator of the test vectors and the tests use it in the place of the app |
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
    fn listen(&self) -> impl Future<Output = Result<Listener, PlatformError>> + Send;   // where the calls of the backend arrive
    fn connect(&self, host: &str, port: u16) -> impl Future<Output = Result<Stream, PlatformError>> + Send;  // the outbound byte pipe to a provider or to the log store
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
| `listen` | vsock, port 8080, any CID (`VMADDR_CID_ANY`) | TCP `0.0.0.0:8080` |
| `connect` | The node connects to vsock port 8443 of the parent (CID 3), sends `CONNECT {host}:{port}\n` as the first line, receives `OK\n`, and uses the connection as the byte pipe from then on. The host is a DNS name: lower-case letters, digits, `.` and `-`. The hosts a node asks for are those of its provider definitions and the host of its log store | A direct TCP connection |

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
    config: RwLock<Option<Arc<OperatorConfig>>>,
    log_store: LogStore,             // { required, id: OnceLock<LogStoreId>, endpoint: OnceLock<Option<LogStoreEndpoint>>, credentials: RwLock<Option<Arc<Credentials>>>, idle: IdleConnections } (5.14)
    log_counters: LogCounters,       // { entries, events, writes, write_failures, batch_calls, batch_requests, write_attempt_failures: { connect, tls, closed, timeout, status_4xx, status_5xx }, write_retries, write_ms_buckets: [u64; 8], write_ms_sum, write_count }: the counts of `log` of health (5.1)
    late_refreshes: Arc<Semaphore>,  // the places of the token address calls of refresh that go on after their time limit: 128 (5.7)
    refresh_counters: RefreshCounters,  // { late_kept, late_dropped, late_failed, late_abandoned }: the counts of `refresh` of health (5.1)
    challenges: Mutex<Expiring<[u8; 16], u64>>,         // the issued challenges, each with its serial. Removed after 300 seconds or on use. At most 100,000
    serials: AtomicU64,                                 // the next serial: one count for the challenges the node issues and the revoke commands it accepts. It starts at 1 and only grows
    accounts: RwLock<BTreeMap<String, Arc<Mutex<Account>>>>,  // user_id -> the state of the account, in the order of user_id: a page of accounts after a user_id is a range of the map. One lock per account
    pending: Mutex<Expiring<String, PendingAuth>>,      // node_state -> the pending authorization (600 seconds, used once). At most 100,000
    chains: AtomicUsize,                                // the accounts that have a chain: `accounts` of health (5.1)
    counters: Arc<StateCounters>,                       // { grants, pending_accounts, pending_entries, kept_refreshes, merge_keys, open_batches, pending_oldest_since_ms }: the counts of health kept by the methods of Account (5.1)
    // and: the platform, the clock, the provider definitions, the TLS client (with the idle connections to the providers, 5.8, the bound of connections being opened and the counts of `egress` of health, 5.1), the limits of section 8
}
struct Account {
    grant: GrantState,               // None | Active { key_id, sign_pk, log_pk, custody, user_key, not_after_ms, exported_to } | Expired { key_id, not_after_ms } | Revoked { key_id, sign_pk }
    head: Head,                      // { seq, hash }. Without entries: seq 0 and a hash of 32 zero bytes
    open: OpenBatch,                 // the use events whose entry does not exist yet: { events: Vec<Value>, bytes, seq: Arc<OnceLock<u64>> (the cell that receives the seq of the entry when the batch is closed), key_id, log_pk }
    writer: bool,                    // true while a call of this account writes to the log store (the writer of the group commit, protocol.md 7.1)
    notify: Arc<Notify>,             // woken when a write of this account ended: the waiting calls look at their entries again
    unconfirmed: Vec<Unconfirmed>,   // the entries the log store has not confirmed: { seq, key, entry, writing, pending_since_ms, prev_hash, outcome_unknown }. Empty on a node without a log store (5.14)
    recent: HashMap<[u8; 32], Recent>,  // merge key -> { entry_ms, target: EventPlace } of its event. Removed after 300 seconds (the GET requests of forward that have no body)
    final_head: Option<Signed>,      // the final head that the orderly shutdown created (5.11)
    kept_refreshes: VecDeque<KeptRefresh>,  // the responses of the successful refresh calls of the last 3,600 seconds, at most 16 (5.7)
    counters: Arc<StateCounters>,    // the counts of the node: the methods that change grant, unconfirmed, recent, kept_refreshes and open move them
    last_entry_ms: u64,              // the time_ms of the last entry of the chain (section 8)
    last_event_ms: u64,              // the time_ms of the last event created (section 8)
    revoked_here: bool,              // true once this node accepted a revoke command of the account (protocol.md 10.1)
    revoke_serial: u64,              // the serial of the last revoke command of the account that this node accepted, 0 when there is none (protocol.md 5.4)
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
- `exported_to` of an `Active` grant is the list of the nodes that the grant was handed to with
  `peer/export`: the signing public key of each and the `seq` of the entry
  `grant_transferred_out` that names it, at most 64 (protocol.md 10.1). A grant command, a
  revoke, the end of the grant and a transfer that puts a grant in place create a new state, and
  the list of a new grant is empty.
- The open batch of an account holds use events in the order of their creation. It is closed into
  an entry by the call that finds no writer, by the writer when its write ends and the batch is
  not empty, when the next event would exceed 128 events or 1,048,576 bytes of plaintext, when
  the next event is created under another key than the batch was opened under, and before a
  control event is created. Closing happens inside the lock of the account: the `seq`, the seal,
  the signature and the new end of the chain are assigned there, and the cell of the batch
  receives the `seq`. The write runs outside the lock.
- A call whose event is in the open batch waits on the notification of the account until the
  entry that holds its event is confirmed (it acts), or its own write was not confirmed
  (`log_store_unavailable`), or it waited for twice the time limit of a write
  (`log_store_unavailable`), or the node is closing when it looks again (`closing`). A call that
  wakes and finds no writer and its entry unconfirmed becomes the writer. A forward batch waits
  for every entry that holds one of its events. A writer whose call ends before its write does
  (the caller closed the connection) is no longer the writer: the account has no writer until the
  next call, and its entries are pending entries.
- The sweep of the node: a task that runs every 30 seconds (`log_store::keep_sweeping`) in three
  passes. The first pass visits every account once, in the order of the sorted index and one
  chunk of 1,000 accounts of the index at a time (the index is locked for one chunk, not for the
  walk): it ends a grant whose time passed, drops the merge keys whose window of 300 seconds
  passed (`recent`) and the kept `refresh` responses whose 3,600 seconds passed, and collects
  the accounts that have a pending entry. The second pass visits the collected accounts in an
  order the random source of the platform shuffles and writes the pending entries of each again
  with the rules of a write (at most 32 at the same time, over the idle connections). It writes
  the pending entries of an account only when the oldest of them has been pending for longer
  than a jitter it draws for that account in `[0, 30 seconds)`; otherwise they wait for the next
  sweep. Over the whole node it writes at most 64 entries per second (`sweep_write_rate` of
  section 8: a token bucket with a burst of one second), and the pass ends when the next sweep
  is due, so the accounts it did not reach wait for that sweep. The third pass reads the oldest
  pending entry of the collected accounts again and keeps its `pending_since_ms` in the counts
  of the node (0 when none is left): `pending_oldest_ms` of health is computed from that value
  until the next sweep. Without the sweep, a pending entry of an account that makes no further
  call would stay out of the store for as long as the account is idle, and a reader of the store
  would take that gap for an omission; the merge keys and the kept responses of an idle account
  would stay in memory until its next call; and the user key of an idle account whose grant ended
  would stay until its next call. The random order, the jitter and the rate spread the writes of
  the accounts whose entries became pending at one moment (an outage of the store) over two
  sweeps and keep the recovery from more than doubling the live load on the store. The sweep
  ends when the orderly shutdown starts.
- `unconfirmed` of an account holds the entries that the log store has not confirmed, in the
  order of their `seq`. `writing` is true while a call writes the entry. `pending_since_ms` is
  the node time at which the entry was created: the age of the oldest pending entry of the node,
  as the last sweep found it, is `pending_oldest_ms` of `log_store` of health (5.1). `prev_hash`
  is the hash of the end of the chain before the entry (the `prev` of its body): the orderly
  shutdown ends a chain whose last entries are unconfirmed at that point (5.11). `outcome_unknown`
  is true once an attempt to write the entry ended with the connection closed without a response,
  passed its time limit after the request left, was answered by the store with a 5xx status, or
  was abandoned by the call that owned it while the store held the request (5.14): the store may
  hold the object, and the orderly shutdown does not drop such an entry; it does not go back to
  false while the entry is unconfirmed. An entry of this list that no call writes is a pending entry
  (protocol.md 7.6). A call takes the entries
  it writes out of the pending state inside the lock of the account and puts back the ones the
  store did not confirm, also when the call ends before its writes do (the caller closed the
  connection).
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
- The creation of an event, the close of the open batch into an entry and the update of the head
  of one account happen inside the lock of that account (the chain of one account does not fork).
  A provider call and a write to the log store run outside the lock.
- The kept responses of `refresh` (5.7): a kept response holds what the response held, which is a
  record (a ciphertext), the public fields and the `log` object of the entry. A revoke command,
  the expiry of the grant, and a grant of another signing key drop the kept responses of the
  account.

## 4. The common rules of the call surface

- Transport: HTTP/1.1. On nitro the node listens on vsock port 8080, on local on TCP 8080. The host
  program moves TCP 8080 inside the cluster to the vsock listener (section 9).
- The caller is the operator domain (its backend processes). A node does not trust its caller: a
  decision rests on the grant of the account, on the AEAD authentication of a record and on the
  provider definitions, and on nothing else.
- Bodies: `POST /v1/forward` and `POST /v1/forward/batch` take and return a frame (5.8). Every
  other body is `application/json`.
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
(protocol.md section 6). A JSON body is accepted up to 1 MiB, and a longer one is `too_large`. The
responses of a node carry no `Date` header (it would be a value of the system clock).

- The common front of the calls that use a credential (`forward`, `forward/batch`,
  `app-password/verify`, `refresh`, `revoke-token`, `release`, `oauth/complete`, the mail
  calls): (1) the node is not `closing`. (2)
  The operator configuration is present (`release` is the exception). (3) The node can write to
  its log store, and the account has fewer than 64 pending entries (5.14. A node of platform
  `local` without a log store passes. An account the node holds no state of fails before this
  step, with `grant_required`). (4) The grant of the account is Active and within its time. (5)
  The node opens the record (protocol.md section 6. `oauth/complete` creates a record and has no
  step 5). `oauth/merge` passes (1), (4) and (5) only (it creates no event and calls no provider).
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
GET /v1/health -> {"node":"...","release":"v2.1.0","platform":"nitro","custody":"enclave","started_ms":0,"time_ms":0,"configured":true,"closing":false,"accounts":0,"grants":0,
                   "mail_providers":["naver_mail"],"app_password_providers":["naver_calendar"],
                   "log_store":{"bucket":"...","region":"...","credentials_expires_ms":0,"pending":0,"pending_oldest_ms":0}|null,
                   "log":{"entries":0,"events":0,"writes":0,"write_failures":0,"open_batches":0,"batch_calls":0,"batch_requests":0,
                          "write_attempt_failures":{"connect":0,"tls":0,"closed":0,"timeout":0,"status_4xx":0,"status_5xx":0},"write_retries":0,
                          "write_ms_buckets":{"25":0,"50":0,"100":0,"250":0,"500":0,"1000":0,"2500":0,"5000":0},"write_ms_sum":0,"write_count":0},
                   "load":{"provider_inflight":0,"forward_calls":0,"inbound_connections":0,"inbound_refused":0,"cpu_user_ms":0|null,"cpu_system_ms":0|null,"cpu_idle_ms":0|null,"memory_total_bytes":0|null,"memory_available_bytes":0|null,"descriptors_open":0|null,"descriptors_limit":0|null},
                   "egress":{"opens":0,"open_failures":{"transport":0,"relay_refused":0,"tls":0,"http":0},"open_retries":0,"open_inflight":0,"idle_reuses":{"provider":0,"log_store":0}},
                   "refresh":{"late":{"kept":0,"dropped":0,"failed":0,"abandoned":0},"late_inflight":0},
                   "state":{"kept_refreshes":0,"merge_keys":0,"pending_entries":0,"idle_connections":{"provider":0,"log_store":0}}}
POST /v1/config {"providers":{"google_workspace":{"client_id":"...","client_secret":"...","redirect_uri":"https://.../api/integrations/google_workspace/oauth/callback","publishable_key":""}, ...},
                 "log_store":{"bucket":"...","region":"...","endpoint":"http://host:port"}}
             -> {"configured":true}
```

- `accounts` of `health` is the number of accounts that have a chain (a `seq` of at least 1).
  `grants` is the number of accounts that have a grant within its time (the operator domain reads
  this value to see that a delegation transfer arrived). Both are counts the node keeps with the
  state (section 3): a health call locks no account, and its time does not grow with the number
  of accounts. A grant whose time passed is counted until the first read of the account or the
  sweep ends it, at most one sweep interval (30 seconds) after its end.
- `log_store` of `health` is null on a node without a log store. Otherwise it names the bucket
  and its region, the end of the credentials the node holds (`credentials_expires_ms`, 0 when it
  holds none), the number of accounts that have an entry the store has not confirmed
  (`pending`, a count kept with the state) and the age of the oldest pending entry in
  milliseconds of node time (`pending_oldest_ms`). The age is computed from the oldest pending
  entry the last sweep of the node found (section 3): it grows with the node time until the next
  sweep, it is 0 when that sweep found no pending entry or no sweep ran yet, and the set of
  entries it stands for is up to 30 seconds old. The endpoint of a node of the local platform is
  not reported.
- `state` of `health`: the sizes of the variable state of the accounts at the moment of the
  call, each a count kept with the state (section 3). `kept_refreshes` is the number of kept
  `refresh` responses over every account (5.7), `merge_keys` the number of merge keys over every
  account (protocol.md 7.2), `pending_entries` the number of entries the log store has not
  confirmed over every account, and `idle_connections` the number of idle connections the node
  keeps at this moment, to the providers over every account and host (`provider`, 5.8 step 8)
  and to the log store (`log_store`, 5.14). The operator domain reads these values to tell the
  memory of the delegation state from the memory of the variable state.
- `log` of `health`: counts since the node started. `entries` is the number of entries the node
  created, `events` the number of events in them, `writes` the number of attempts to write an
  entry to the log store (`PUT` requests, confirmed or not: an entry the store did not confirm
  at the first attempt is counted once per attempt, 5.14), `write_failures` the number of
  entries whose attempts ended without a confirmation within their budget, `open_batches` the
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
  to a provider (`provider`, 5.8 step 8) and to the log store (`log_store`, 5.14).
- `refresh` of `health`: the token address calls of `refresh` the node continued after their time
  limit (5.7). `late` counts them since the node started by outcome: `kept` (the late success
  became the kept response of its record), `dropped` (the late success was not kept: the grant
  had ended, a revoke or a grant of another key arrived, or the node was closing), `failed` (the
  late call ended with a refusal of the provider, a transport failure or the late limit) and
  `abandoned` (the call found no free place at its time limit and was ended there).
  `late_inflight` is the number of late calls in progress at this moment.
- `load` of `health`: the load of the node at the moment of the call. `provider_inflight` is the
  number of provider requests in flight (the taken places of the node-wide bound of section 8),
  and `forward_calls` the number of calls that hold one of the places of the bound of concurrent
  `forward` and `forward/batch` calls (`forward`, `forward/batch` and the mail calls take one
  each). `cpu_user_ms`, `cpu_system_ms` and `cpu_idle_ms` are the CPU time of the kernel the node
  runs in, over all its processors, since that kernel booted, in milliseconds: the first line of
  `/proc/stat` (`user` and `nice`; `system`, `irq`, `softirq` and `steal`; `idle` and `iowait`),
  at the clock ticks per second that the auxiliary vector of the node process states
  (`AT_CLKTCK` of `/proc/self/auxv`). `memory_total_bytes` and `memory_available_bytes` are
  `MemTotal` and `MemAvailable` of `/proc/meminfo`, in bytes. The node reads the three files at
  every call. Each of the five values of the kernel is null when the kernel exposes no procfs
  value (a kernel without procfs, or a development machine that is not Linux); the two counts
  are always numbers. `inbound_connections` is the number of connections from the backend the
  node holds open at this moment, and `inbound_refused` the number of connections it closed at
  accept because its bound of open connections was reached, since it started (section 8).
  `descriptors_open` is the number of open file descriptors of the node process (the entries of
  `/proc/self/fd`, null when the kernel exposes none) and `descriptors_limit` the soft limit of
  open file descriptors in force (null when the platform has no such limit): the limit the
  node raised at its start (section 8), or the limit the kernel gave it when the kernel refused
  the raise. The operator domain reads the two to see a node that approaches its limit.
- `log_store` of `config` names the log store of the node (protocol.md 4.1 gives the form of the
  two names. Another form is `invalid_request`). The key is optional. A node takes a log store
  once: a later configuration that names the same log store, or none, leaves it in place, and a
  configuration that names another one is `invalid_request` and changes nothing, also not the
  client values. From the call that named it, the binding of the attestation responses of the
  node carries it as `log`. A node of the local platform also takes an optional `endpoint` in
  `log_store` (5.14): an `http://host:port` or `https://host:port` origin it writes to in
  path-style, set once with the log store. A node of the nitro platform refuses a configuration
  with `endpoint` (`invalid_request`), and a value that is not such an origin is `invalid_request`
  on both platforms.
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
the control entry the command created (a grant that was accepted, a revoke of an account with a
grant) and is null for a command that created none. The responses other than 200 are a violation
of the form of the call itself (`invalid_request`), `closing`, and a failure of the platform
(`internal`). `grant` is the plaintext copy that the caller (the backend) reads:
the state of the account that the call named, after the processing. `state` is `active`, `none` or
`revoked`, and a grant whose time has passed is reported as `none`. `key_id`, `custody` and
`not_after_ms` have values in the state `active` only, and `revoked` has `key_id` only. `custody`
is the custody of the platform of that node.

### 5.4 `POST /v1/status`

```json
{"user_id":"...","nonce":"<b64u>"} -> {"head":{"body":"...","sig":"..."},"grant":{"state":"active|none|revoked|expired","key_id":"...","custody":"enclave","not_after_ms":0}}
```

`nonce` is b64u of 1 to 64 bytes. A `user_id` without account state receives the empty head (`seq`
0) and `none`. The state `expired` carries `key_id` and `not_after_ms`.

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
  creates no entry, and the `final` heads of `close/heads` cover it.
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
`identity`, decodes nothing, and does not return a body of another encoding (step 10). The order
of the processing:

0. The frame: meta is a JSON object of at most 1 MiB (a longer meta, and a meta that is no object,
   is `invalid_request`). A payload above 64 MiB is `too_large`. A `timeout_ms` that is not an
   integer from 1,000 to 120,000 is `invalid_request` (when it is omitted, it is 30,000).
1. The common front. The record opens by its kind: a record of kind `oauth` or `oauth_imported`
   with the OAuth definition of its provider (a provider without one is `provider_unknown`), or
   a record of kind `app_password` of a provider that has an application password definition
   (6.5; a record of kind `app_password` of another provider, `naver_mail` included, is
   `not_allowed`). Any other kind is `not_allowed`.
2. The address check (section 7) against the `api` rules of that definition. A violation is
   `not_allowed`.
3. The method is one of `GET`, `POST`, `PUT`, `PATCH`, `DELETE` for a token record, and one of
   the `methods` of the definition for an application password (any other is `not_allowed`).
4. The header check: a name holds token characters only, and a value holds no control character
   (CR and LF included). A violation is `invalid_request`. A value can hold characters outside
   ASCII and is sent as UTF-8. A call with a header named `x-http-method-override`,
   `x-http-method` or `x-method-override` (ASCII letters compared without regard to case) is
   refused with `not_allowed`: such a header asks a provider to treat the request as one of
   another method than the method the request is sent with, which is the method the entry of
   step 6 names. The node refuses the call. It does not drop the header and send the rest. The
   node drops the names below and the credential header of the definition (`inject.header`, or
   `Authorization` for an application password definition):
   `authorization`, `proxy-authorization`, `cookie`, `host`, `content-length`,
   `transfer-encoding`, `connection`, `keep-alive`, `upgrade`, `te`, `trailer`, `expect`,
   `accept-encoding`.
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
   or the method is `POST`, `PUT` or `PATCH`, then the credential header (made by the injection
   rule of an OAuth definition, or HTTP Basic of the login and the password of an application
   password, 6.5), then `Accept-Encoding: identity`, then the headers of the caller, then
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
    `chunked`, fails the check: the node does not hand on a body it cannot search. A response
    fails the check when a header name, a header value or the body holds the injected credential
    (the token without the prefix of the definition, or the application password). Each of the
    three is read as it was
    received and with its percent escapes decoded (up to three times, for a value that was
    encoded more than once), and each reading is searched for the credential as it is, in base64
    or base64url (each of the three byte alignments, without padding) and in hexadecimal (lower
    or upper case). A form shorter than 8 bytes is not searched for. A failed check is
    `response_withheld`: no part of the response leaves. The event `provider_request` is already
    on the chain, because the request went to the provider.

The value of the credential header of a token record: `inject.prefix` followed by the value at
the first path of `inject.paths` that holds a non-empty string in the token object. When there is
no such value, the call fails with `record_invalid`. The credential header of an application
password is `Authorization` with the value `Basic` and the base64 of `{login}:{password}`, where
the login is the account name of the record without the domain of the definition (6.5).

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

### 5.8c `POST /v1/app-password/verify`

The check, at the time a connection is made, that a provider accepts the application password of
a record whose provider has an application password definition (6.5). The frame is the frame of
5.8. Its meta is `{"user_id":"...","record":{...},"context":"...","request":{},"timeout_ms":30000}`:
`request` is absent, `null` or the empty object and the payload is empty (anything else is
`invalid_request`), and `timeout_ms` is read as in 5.8 step 0. Its response is the frame of 5.8
with `status`, `headers`, `log` and a JSON body.

1. The common front of section 4. The record opens as an application password and nothing else:
   the provider must have an application password definition (the password of `naver_mail`,
   whose calls are the mail calls, is `not_allowed`), and the kind must be `app_password`. A
   record of another kind is `not_allowed` before its plaintext is read, whatever its provider:
   a token record whose provider has no OAuth definition is `not_allowed` here and
   `provider_unknown` on `forward`.
2. The request is the `verify` request of that definition: its method, its address, its headers
   and its body. It passes steps 2 to 4 of 5.8 as a request of the caller would (the validation
   of the definition guarantees that it does: 6.5), and steps 5 and 6: the event
   `provider_request` names it, and the request leaves only after the log store confirmed the
   entry that holds the event.
3. Steps 8 to 10 of 5.8, within `timeout_ms`: the request leaves with the credential header of
   the password, and the response passes the check of rule E4 with the password as the
   searched credential (a response that reflects it is `response_withheld`).
4. The response of the provider stays inside the node. Its status decides what leaves:

| Status of the provider | `status` of the frame | Body of the frame |
| --- | --- | --- |
| A status of `verify.accepted` of the definition | 200 | `{"identity":"...","node":"...","statement":{"body":"...","sig":"..."}}`: the identity of the account (`{login}@{domain}` of the definition), the identifier of the node and the statement `app_password_verified` of protocol.md (its `provider` is the provider of the record) |
| 401 | 401 | `{"code":"authentication_failed"}` |
| Any other | 502 | `{"code":"verification_failed","status":n}`: `n` is the status of the provider, as an integer |

The three frame statuses are the node's: a 2xx answer that is not an accepted status (a page that
answers 200 whatever the credential) is the last row, not the first. The node follows no
redirect: a 3xx answer is a status of the last row too. The `headers` of the frame are
`[["content-type","application/json"]]` in every row, and no other byte of the provider response
leaves. The call takes a forward slot and its share of the body budget as `forward` does
(section 8).

### 5.9 `POST /v1/release`

```json
{"user_id":"...","record":{...},"field":"password|totp|card_number|card_cvc","origin":"https://host","context":"..."}
-> {"value":"...","log":{"seq":1,"index":0,"created":true}}
```

| Record kind | Allowed field | The value that is returned | Event |
| --- | --- | --- | --- |
| `vault_password` | `password` | `value` of the plaintext | `secret_released` |
| `vault_totp` | `totp` | The 6-digit code computed from the seed of the plaintext (RFC 6238, node time). The seed does not leave | `totp_issued` |
| `vault_card` | `card_number`, `card_cvc` | `number` or `cvc` of the plaintext | `secret_released` |

Any other pair of kind and field is `not_allowed`, and so is a record of kind `oauth` or
`oauth_imported`: no call hands out the plaintext of a token. A plaintext without the field, and a
seed that is not base32, are `record_invalid`. The entry that holds the event is on the chain, and
the log store confirmed it, before the value leaves the node.

`origin` is an origin string `https://host` or `https://host:port` of at most 512 bytes (the node
checks the form only). Whether that origin is the site of the vault item is decided by the backend,
and the node writes the value it received into the entry. The call works without the operator
configuration.

### 5.10 `POST /v1/log/entries`, `POST /v1/log/ack`

The calls `POST /v1/log/entries` and `POST /v1/log/ack` are not part of the call surface. A node
answers them with 404 `invalid_request`, like every path that is not defined. The log store is the
one place an entry is read from (protocol.md 7.6): no call hands an entry out, and no call takes an
acknowledgement of its storage.

### 5.11 `POST /v1/close`, `POST /v1/close/heads`

```json
close       {} -> {"accounts":0}
close/heads {"cursor":"","limit":1000} -> {"heads":[{"body":"...","sig":"..."}],"next":"","truncated":0,"skipped":0}
```

`close` raises `closing`: from then on, the calls that use a credential and the commands are
refused with `closing`, and a call that was in progress runs to its end. `accounts` of `close` is
the number of accounts that have a chain. `close/heads` returns the `final` head of every account
that has a chain, in the lexical order of `user_id` (`cursor` is the last `user_id` of the page
before, and an empty `next` ends the listing). `close/heads` before `close` is `invalid_request`.
A node creates the `final` head of an account once, and a repeated call returns the same head.
`limit` is at least 1, and a value above 1,000 is read as 1,000. The host program starts this
sequence when it receives the termination signal (section 9), and the pre-stop hook of the pod
starts it before the signal (section 9, `drain`).

A page of `close/heads` is the first `limit` accounts after the cursor that have a chain (an
account whose final head stands at `seq` 0 stays listed). The call closes the open batch of every
account of the page into an entry and writes the entries of these accounts that the store has not
confirmed in one round of writes (the entries it closed and the pending entries, with the attempts
of a write of 5.14). It then signs a final head for each account of the page by the state of its
unconfirmed entries after the round:

| The unconfirmed entries of the account | The final head |
| --- | --- |
| None | At the head of the chain |
| A tail of the chain whose every entry is known not to be in the store: every `seq` from the first unconfirmed one to the head is unconfirmed, and every attempt to write each of them failed before a request byte left the node (the connection, the TLS handshake, a time limit that passed while the connection opened) or was answered by the store with a 4xx status | At the entry before the first unconfirmed one: its `seq` is that entry's `seq` and its `hash` the `prev` of the first unconfirmed entry (`seq` 0 and 32 zero bytes when the first unconfirmed entry is entry 1). The unconfirmed entries are dropped from the chain and from the entries the store has not confirmed, so no sweep writes them again, and the account is counted in `truncated`. Their acts never took place: an act follows the confirmation of its entry. A dropped `grant_transferred_in` entry leaves the grant it recorded in place on the closing node, and the `grant_transferred_out` of the giving node records the handover |
| An unconfirmed entry whose write may have reached the store (an attempt ended with the connection closed without a response, passed its time limit after the request left, was answered with a 5xx status, or was abandoned by its call while the store held the request: `outcome_unknown` of the entry, section 3), an unconfirmed entry below a confirmed one (a gap inside the chain), or an entry that a call writes at this moment | No final head in this call: the account is counted in `skipped`, its entries stay as they are (the sweep ended with `close`; the round of every later `close/heads` call writes the pending ones again), and it is listed in the pages of a later call, which looks again. An entry whose write may have reached the store is not dropped: the node leaves no final head for that account until the store confirms the entry, because a reader that found the object above the final head would mark the chain |

`truncated` and `skipped` count the accounts of the page. A call that passed the common front
before `close` and waits for a write runs to its end: its event is on the chain, and when the
store confirms the entry the final head covers it. A final head once signed is returned as it is,
and counted in neither value, by every later call.

### 5.12 `POST /v1/seal`, `POST /v1/open`

The calls `POST /v1/seal` and `POST /v1/open` are not part of the call surface. A node answers
them with 404 `invalid_request`, like every path that is not defined. No call takes a credential
in the clear, and no call hands the plaintext of a token out.

### 5.13 `POST /v1/peer/export`, `POST /v1/peer/import`

```json
export {"peer":{the attestation response of the receiving node},"after":"","limit":1000,
        "subset":{"pods":3,"pod":1,"copies":2},
        "endorsement":{"statement":"...","entry":{"body":"...","integrated_time":0,"log_index":0,"log_id":"...","signed_entry_timestamp":"..."}}}
  -> {"envelope":{...}|null,"logs":[{"user_id":"...","seq":1}],"next":""}
import {"peer":{the attestation response of the giving node},"envelope":{...},"subset":{"pods":3,"pod":2,"copies":2}}
  -> {"imported":0,"logs":[{"user_id":"...","seq":1}]}
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
- `logs` of export names the control entry `grant_transferred_out` (its `user_id` and `seq`) of
  every grant of the page that the node hands to this peer for the first time (protocol.md 10.1;
  the open batch of such an account is closed before it). A grant that the node handed to the
  same peer before is in the envelope again and has no new entry: a repeated call returns the
  envelope and an empty `logs`. An account whose grant was handed to 64 other peers is not
  selected. It is not in the envelope, it has no entry, and it does not count toward `limit`.
- export works in the state `closing` too (the orderly shutdown hands the delegations over before
  the node ends). An account whose final head is already signed is skipped. So the order of the
  orderly shutdown is `close`, `peer/export`, `close/heads`. import is refused with `closing` in
  the state `closing`, and when the shutdown starts during an import, the call answers with what
  it took until then.
- The pages of export: the node goes through the accounts in the order of `user_id`, reading its
  sorted index one chunk of 1,000 accounts at a time (section 3), until `limit` grants are
  selected, and `next` is the last `user_id` it looked at (the last page can be empty). An
  omitted `limit` is 1,000 and an omitted `after` is the empty string. `imported` of import is
  the number of grants that this call put in place (it equals the number of elements of `logs`,
  the control entries `grant_transferred_in` the call created). Within the 1 MiB limit of a JSON
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
  the seven checks of that section. The keys it checks with are the release key and the log key
  inside the binary, the release it compares with is the release tag inside the binary, and the
  time of check 5 is the node time (section 8) in seconds. The one allowed measurement is that of
  the statement, with the `release` of the statement in the binding of the peer. The measurement
  of the node itself is not allowed then, and a node of platform `local` accepts no peer. An
  `endorsement` that is not a JSON object is `invalid_request`. An endorsement that lacks a key,
  holds a value of another type or fails a check is `peer_unverified`: the response does not say
  which check failed. A refused call creates no entry.
- import: the allowed measurements are that of `Platform::measurement()` and those of the list of
  predecessors inside the binary (`enclave/release/predecessors.json`), each of the list with the
  `release` of its element in the binding of the peer. The call has no key for an endorsement: a
  receiving node does not look at one.
- The node reads the two keys and the list when it starts (`lineage.rs`). It does not start when a
  key is not an ECDSA P-256 public key, or when the list fails the rules of protocol.md 10.3 (a
  malformed list, an element whose release is not earlier than the release of the node, any
  element for a node whose release is not a release tag).
- export and the log store: the node hands a grant over only after the log store confirmed the
  entry `grant_transferred_out` of that grant for that peer (protocol.md 10.1, steps 4a to 5b).
  When the store does not confirm the entry of one account of the page, the call fails with
  `log_store_unavailable` and the response carries no envelope and no `logs`. The entries the
  call created are on their chains and wait for the store (pending entries). The next call for
  the same peer creates no entry for these accounts, so its `logs` are those of the grants it
  hands over for the first time only.
- import and the log store: the grants are put in place first, and the call then writes the
  entries `grant_transferred_in` it created in one round (the pending entries of the same
  accounts along) when the node has credentials for its log store. The call does not need the
  credentials: without them, and for an entry the store does not confirm, the entry is a pending
  entry that the next write of the account on this node takes along, and the call succeeds all
  the same. The round is what puts the chain of the receiving node into the store for an account
  whose calls keep going to another node.
- Both calls work without the operator configuration. On a node of platform `nitro`, the log
  store of that configuration is what makes a peer acceptable and an export possible.

### 5.14 `POST /v1/log-store/credentials`, the log store

```json
{"access_key_id":"...","secret_access_key":"...","session_token":"...","expires_ms":0}
-> {"credentials_expires_ms":0}
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

The write of an entry (`enclave/src/log_store.rs`) is the request of protocol.md 7.6:

| Item | Rule |
| --- | --- |
| Connection | The connection of every outbound call (`Egress::open`): the byte pipe of the platform to port 443 of `{bucket}.s3.{region}.amazonaws.com`, TLS that ends inside the node, the trust roots of `webpki-roots`, the certificate verified at node time. An attempt to open a connection that fails before any request byte left the node (the byte pipe, a refusal of the egress relay, the TLS handshake, the HTTP/1.1 handshake) is repeated: at most 3 attempts (`OPEN_ATTEMPTS`), with a full jitter backoff between them (a random time up to 50 milliseconds, doubled for every attempt after the first, at most 400 milliseconds, drawn from the random source of the platform), as long as the attempts and the backoff stay within half the time limit of the call the connection is for (for a write to the log store: half the time limit of the attempt). This rule holds for every outbound connection of the node: to a provider (5.7, 5.8, the mail hosts) and to the log store. The node opens at most 256 connections at the same time (`open_concurrency` of section 8); a further open waits for a place within the time limit of its call. The node keeps at most 32 idle HTTP/1.1 connections to its log store: open connections that carry no write. A write takes the most recently used one. A connection carries one write at a time and is idle again only when its response has ended. A connection that closed or failed, or whose write was cancelled, is not kept |
| Request | `PUT` of the object of protocol.md 7.6, signed with AWS Signature Version 4 (the service `s3`, the region of the bucket). Every header of the request except `Content-Length` is signed. The times of `x-amz-date` and of the retention are node time |
| Confirmation | The status 200. The node reads no response body and follows no redirect. An attempt that is not confirmed is repeated over a new connection with a full jitter backoff (a random time up to 100 milliseconds, doubled for every attempt after the first, at most 1 second) within a budget of twice the time limit of a write per entry, when the failure is a failed connection, a connection that closed without a response, the time limit of the attempt, a 5xx status or 429; a 4xx status other than 429 is not repeated, and neither is an attempt whose backoff and a margin of one second would not fit in the budget. A `PUT` is idempotent (RFC 9110 9.2.2), and a repeated attempt adds a version of the same object with the same body: the request renews the date and the signature only (protocol.md 7.6). Every attempt is a write of `log` of health, and every failed attempt is counted under its cause (5.1) |
| Local endpoint | A node of platform `local` takes an optional `endpoint` in the `log_store` of its configuration (5.1): an `http://host:port` or `https://host:port` origin. With it, the node writes to `{endpoint}/{bucket}/{key}` (path-style) with the `Host` header of the endpoint and, when the scheme is `http`, over the plain byte pipe of the platform without TLS; the signature region is the region of the configuration and the signed headers are the same. A node of platform `nitro` refuses a configuration with `endpoint` (`invalid_request`). The binding carries the bucket and the region only |
| Time limit | 5 seconds for one attempt to write an entry: the connection, the TLS handshake and the exchange. The first attempt goes over an idle connection when there is one and gets half this time, so a connection that stalls leaves the time for an attempt over a new connection; every later attempt opens a new connection. The attempts of one entry end within twice this time. A call that waits for the write of another call waits for at most twice this time |
| Writes of one call | The entries the act of the call waits for, and the pending entries of the same accounts. At most 32 writes run at the same time, the entries an act waits for first. After a round in which a write was not confirmed, the call starts no further write. The group commit (protocol.md 7.1, section 3): one call of an account writes at a time, and the events of the calls that arrive meanwhile form the next entry |
| Sweep | The sweep of section 3 visits the accounts in a random order, writes the pending entries of an account only after a jitter of up to 30 seconds since the oldest of them became pending, and writes at most 64 entries per second over the whole node (`sweep_write_rate` of section 8). An account the sweep did not reach before the next sweep is due waits for that sweep |
| The limit of pending entries | An account whose pending entries reached 64 gets no further entry from a call that uses a credential (step 3 of the common front): the call writes the pending entries again, goes on when fewer than 64 are left, and otherwise ends with `log_store_unavailable` without an entry. A command and a delegation transfer are not stopped by this limit |
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

A definition is of one of two forms, told apart by the key `credential`. An entry without that
key is an OAuth definition (6.1 to 6.4): the node issues and refreshes the tokens of the provider
and injects them into the requests of `forward`. An entry with `"credential": "app_password"` is
an application password definition (6.5): the device encrypts a password the user made at the
provider, and the node sends it as HTTP Basic to the hosts of the definition. Both forms have an
`api` list (section 7). A provider name is of one form only.

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

### 6.5 Application password definitions

A definition with the key `"credential": "app_password"` describes a provider whose credential is
an application password the user made at the provider: a record of kind `app_password` that the
device encrypted (protocol.md section 6). The node sends it as HTTP Basic (the header
`Authorization` with the value `Basic` and the base64 of `{login}:{password}`) to the hosts of the
definition, in the requests of `forward` and `forward/batch` (5.8, 5.8b) and in the one request of
`app-password/verify` (5.8c). Such a definition has none of the keys of 6.1: no client, no
authorization address, no token address, no revocation address, no public fields, and the host
program carries no client values for it (section 9).

```json
{
  "naver_calendar": {
    "credential": "app_password",
    "account_domain": "naver.com",
    "methods": ["PROPFIND", "REPORT", "GET", "PUT", "DELETE"],
    "api": [{"host": "caldav.calendar.naver.com", "prefixes": ["/"], "exact": []}],
    "verify": {"method": "PROPFIND", "url": "https://caldav.calendar.naver.com/", "accepted": [207], "headers": [["Depth", "0"], ["Content-Type", "application/xml; charset=utf-8"]], "body": "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:current-user-principal/></d:prop></d:propfind>"}
  }
}
```

| Key | Meaning |
| --- | --- |
| `credential` | `app_password`, the one value. The key tells the two forms of definition apart: an entry without it is an OAuth definition |
| `account_domain` | The domain of the account: a lower-case DNS name with a dot. The `username` of the plaintext of a record is the login of the account, with or without `@` and this domain, compared without regard to case: 1 to 64 letters, digits, `_`, `.` and `-` (another form is `record_invalid`). The login is the user name of the HTTP Basic credential, and `{login}@{domain}` is the identity a verification declassifies. This form of the login is one rule for every application password definition (`AppPassword::from_plaintext` in `enclave/src/mail.rs`): a provider whose account names have another form needs a change of that rule, which is a release |
| `methods` | The methods `forward` sends with the password: distinct upper-case HTTP tokens, at least one. A request of another method is `not_allowed` |
| `api` | Section 7: the hosts and the paths a password of this provider may be sent to, under the rules of an `api` list of 6.1 |
| `verify` | The request of `app-password/verify` (5.8c): `method` (one of `methods`), `url` (an address that passes the address check of this definition), `accepted` (the statuses that mean the provider accepted the password: distinct 2xx statuses, at least one; any other 2xx is no acceptance), `headers` (`[name, value]` pairs under the header rules of 5.8 step 4; a header that `forward` drops or refuses, the credential header `Authorization` among them, is refused here, so the request leaves as it is written) and `body` (text of at most 4,096 bytes) |

The values of the one definition:

| | naver_calendar |
| --- | --- |
| account_domain | `naver.com` |
| methods | `PROPFIND`, `REPORT`, `GET`, `PUT`, `DELETE` |
| api | `caldav.calendar.naver.com`, prefix `/` (section 7) |
| verify | `PROPFIND https://caldav.calendar.naver.com/` with `Depth: 0` and `Content-Type: application/xml; charset=utf-8`, and the `propfind` body above, which asks for `current-user-principal`. Accepted: 207 (Multi-Status, the answer of a PROPFIND that succeeded) |

The definitions are validated when the node loads them, and a node with an invalid one does not
start (`AppPasswordDefinition::validate` in `enclave/src/providers/mod.rs`): the name is a valid
name, the domain has the form above, the methods and the `api` rules follow their rules, and the
`verify` request is one that `forward` would send as it is written (its method is one of
`methods`, its address passes the address check, none of its headers is one that 5.8 step 4 drops
or refuses, its body is within its limit, its accepted statuses are distinct 2xx statuses). A key
the format does not define is refused, and so is a key of 6.1 on such an entry. `health` lists the
providers of these definitions as `app_password_providers` (5.1).

## 7. The address check (`forward`)

| Definition | host | Allowed paths |
| --- | --- | --- |
| google_workspace | `gmail.googleapis.com` | Prefixes `/gmail/v1/`, `/upload/gmail/v1/` |
| | `www.googleapis.com` | Prefixes `/calendar/v3/`, `/drive/v3/`, `/upload/drive/v3/`, `/download/drive/v3/`. Exact `/oauth2/v3/userinfo` |
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
| github | `api.github.com` | Prefixes `/user`, `/users/`, `/repos/`, `/search/`, `/orgs/`, `/rate_limit`. Exact `/graphql` |
| | `uploads.github.com` | Prefix `/repos/` (the release asset uploads `/repos/{owner}/{repo}/releases/{id}/assets`) |
| | `github.com` | Suffixes `/info/refs`, `/git-upload-pack`, `/git-receive-pack` (the git smart HTTP addresses `/{owner}/{repo}.git/info/refs`, `.../git-upload-pack`, `.../git-receive-pack`) |
| naver_calendar (6.5) | `caldav.calendar.naver.com` | Prefix `/`: every path of the host, with the methods of the definition |

The rules, which hold for the `api` list of either form of definition:

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
  refused. The one rule that sets it is that of `sheets.googleapis.com`: the values address of
  Google Sheets, `/v4/spreadsheets/{id}/values/{range}`, carries the range as one path segment,
  and the name of a tab that contains `/` arrives as `%2F`. Everything else holds under such a
  rule too. The prefix comparison stays on the path as it was received (an encoded `/` is no
  segment boundary), and the rule on dot segments reads the decoded path, so
  `x%2F..%2F..%2Fy` and `x%2F..;%2Fy` are refused. `%252F` is refused there as on every host.
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
  `time_ms` values of the entries of one chain do not decrease with `seq`, the `time_ms` values of
  its events do not decrease with (`seq`, index), and no event is dated after its entry (the one
  place that creates an event or closes a batch never dates it before the one in front of it),
  and an expiry that has passed does not come back into force.
- Randomness: the kernel random source.
- Concurrency: at most 512 `forward` and `forward/batch` calls run at the same time (a semaphore; a
  batch call takes one place, and holds it for the round trips of its requests, so the places
  are not the bound of the throughput of a node: the provider requests in flight and the body
  budget are). At most 512 provider requests of the node are in flight at once,
  and a batch sends at most 6 of its requests at a time. The bodies of a request and of a
  response are held in memory, and each of them is `too_large` above 64 MiB (for a batch, the
  bodies of its results together). A call that would raise the sum of the bodies in memory above
  2 GiB waits until there is room.
- Connections from the backend: the node holds at most 16,384 of them open at the same time
  (`inbound_connections`). A connection accepted while that many are open is closed without a
  byte and counted in `inbound_refused` of `load` of health; the caller sees a connection that
  ended without a response, as it does for a node that is gone, and what it does next follows
  its own retry rules (the backend of the operator tries another node for a call it may
  repeat). A
  connection that waits longer than 60 seconds (`inbound_idle`) for the head of its next
  request, before its first request or idle between two requests, is closed. The queue of the
  listener (the connections that wait for accept) holds 1,024 connections on the nitro platform.
- Descriptors: every connection the node accepts and every connection it opens holds one file
  descriptor. The kernel of the enclave starts the node with the default limit of its first
  process, 1,024 open descriptors; at its start the node raises the limit to 65,536
  (`DESCRIPTOR_LIMIT` of `descriptors.rs`: the soft limit, and the hard limit when it is below
  the target), or to its hard limit when the kernel refuses the target. `load` of health reports
  the limit in force and the open descriptors. The bounds of this section keep the descriptors
  of a node below the target: 16,384 connections from the backend, 1,024 idle connections to the
  providers, 32 idle connections to the log store, 512 provider requests in flight, 256
  connections being opened, and the writes to the log store of the calls in progress.
- The size of the enclave: 2 vCPUs (a constant of the host program) and the memory that the
  environment variable `CREDENTIAL_ENCLAVE_MEMORY_MIB` of the host program gives in MiB, 4,096
  when the variable is not set (section 9).
- Output: the node writes nothing to the standard output (a production enclave has no console).
  Diagnostic values leave through `health` and through the failure codes of the calls only. A
  failure message is a fixed string of the source: it carries no credential, no key, no body and
  no query string of an address. The one other output is a fixed line on the standard error when
  the start of the node fails (section 2).

The limits, as the source states them:

| Limit | Value |
| --- | --- |
| JSON body of a call | 1 MiB |
| `meta` of a `forward` or `forward/batch` frame | 1 MiB |
| Body of a provider request and of a provider response (`forward`); the bodies of the results of a `forward/batch` call together | 64 MiB each |
| Sum of the bodies in memory | 2 GiB |
| Concurrent `forward` and `forward/batch` calls | 512 |
| Connections from the backend held open at once (`inbound_connections`) | 16,384 |
| Idle time after which a connection from the backend is closed (`inbound_idle`) | 60 seconds |
| Queue of the listener of the node (nitro platform) | 1,024 connections |
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
| Inbound relay | For every connection on TCP `0.0.0.0:8080` it opens a connection to vsock `16:8080` and moves the bytes in both directions. It does not read the bytes: the call surface of the node ends inside the enclave. It counts the connections for which the vsock connection to the node failed or did not open within its time limit of 5 seconds (the Status row): a caller whose connection the relay closes without a byte |
| Egress relay | It listens on vsock port 8443. It reads the first line `CONNECT {host}:{port}\n`. When the host is on the allow list and the port is 443, it connects by TCP, answers `OK\n` and moves the bytes. Otherwise it sends `ERR\n` and closes. The allow list is the hosts of section 7 (the `api` hosts of the OAuth definitions and of the application password definitions), the hosts of the token addresses and the revocation addresses of 6.2 (the host program is built from the same definitions file), and the host of the log store, `{bucket}.s3.{region}.amazonaws.com`, when the two variables of the next row name one. TLS ends inside the node, so the relay sees ciphertext only. This list is a second line: the node itself sends a credential only to the addresses of its definitions, and log entries only to its log store. Its listener has a backlog of 1,024 connections (the queue of connections that wait for accept; the kernel of the parent instance resets a connection request that finds the queue full); when the kernel refuses to set it the host program logs one line and keeps the default. A failed accept, on this listener and on the two TCP listeners, is classified by its error: `ECONNABORTED`, `EPROTO`, `EINTR` and `EAGAIN` (the connection was gone before accept returned it, or the call was interrupted) are followed by the next accept at once; `EMFILE`, `ENFILE`, `ENOBUFS` and `ENOMEM` (the process or the kernel is out of descriptors or memory) and every other error are followed by a pause of 50 milliseconds. The egress relay counts its failed accepts by class (`aborted`, `resources`, `other`), its connections by outcome and the connections whose bytes it moves at this moment (the Status row) |
| Operator configuration | It reads the values of every provider from environment variables and calls `POST /v1/config` once the `health` call of the node answers. The variables: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `OUTLOOK_CLIENT_ID`, `OUTLOOK_CLIENT_SECRET`, `SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET`, `NOTION_CLIENT_ID`, `NOTION_CLIENT_SECRET`, `X_CLIENT_ID`, `X_CLIENT_SECRET`, `LINK_CLIENT_ID`, `LINK_CLIENT_SECRET`, `STRIPE_PUBLISHABLE_KEY`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, and `CHARACTER_API_BASE_URL` (the front of the callback address `{value}/api/integrations/{provider}/oauth/callback`). The configuration names every OAuth provider of the definitions (an application password definition has no client values and is not named): `redirect_uri` is always set, and a value without a variable is the empty string. `CREDENTIAL_ENCLAVE_LOG_BUCKET` and `CREDENTIAL_ENCLAVE_LOG_REGION` name the log store: when both are set and have the forms of protocol.md 4.1, the configuration carries them as `log_store`. When one is missing or has another form, the configuration carries no `log_store` and one line of the log says why. Without `CHARACTER_API_BASE_URL` no configuration is sent. A configuration that the node refuses is not sent again. The host program does not send the credentials for the log store: the backend sends them (5.14) |
| Status | TCP 9091: `GET /healthz` (200 when the round trip of the `health` call of the node succeeds within 8 seconds, 503 otherwise: the responsiveness of the node, read by the startup and readiness probes of the pod), `GET /livez` (200 while the enclave runs, 503 once the watch of the enclave (the Watch row) confirmed that it ended: the life of the enclave, read by the liveness probe of the pod. It makes no call to the node: a node that does not answer is not a dead enclave, and a pod replaced for that reason would lose the delegations of a living node) and `GET /metrics` (the Prometheus text format). Four gauges: `credential_enclave_up` (1 when the `health` round trip succeeds, 0 when it fails), `credential_enclave_configured` (1 when `configured` of `health` is true), `credential_enclave_accounts` (`accounts` of `health`), `credential_enclave_started_timestamp_seconds` (`started_ms` of `health` in seconds). From the `log` object of `health`, when the node answers with one: the counters `credential_enclave_log_entries_total` (`entries`), `credential_enclave_log_events_total` (`events`), `credential_enclave_log_store_writes_total` (`writes`), `credential_enclave_log_store_write_failures_total` (`write_failures`), `credential_enclave_forward_batch_calls_total` (`batch_calls`), `credential_enclave_forward_batch_requests_total` (`batch_requests`), and the gauge `credential_enclave_log_open_batches` (`open_batches`); and, when the object holds the write counts of 5.1: the counter `credential_enclave_log_store_write_attempt_failures_total{cause}` (`write_attempt_failures`; `cause` is `connect`, `tls`, `closed`, `timeout`, `status_4xx` or `status_5xx`), the counter `credential_enclave_log_store_write_retries_total` (`write_retries`), and the histogram `credential_enclave_log_store_write_seconds`: `_bucket{le}` for `le` `0.025`, `0.05`, `0.1`, `0.25`, `0.5`, `1`, `2.5` and `5` from the cumulative counts of `write_ms_buckets`, `_bucket{le="+Inf"}` and `_count` from `write_count`, `_sum` from `write_ms_sum` as seconds with three decimals. From the `log_store` object of `health`, when it is not null: the gauge `credential_enclave_log_store_pending_accounts` (`pending`) and, when the object holds `pending_oldest_ms`, the gauge `credential_enclave_log_store_pending_oldest_seconds` (its milliseconds as seconds with three decimals). From the `load` object of `health`, when the node answers with one: the gauges `credential_enclave_provider_inflight` (`provider_inflight`) and `credential_enclave_forward_calls` (`forward_calls`); when its three CPU values are not null, the counters `credential_enclave_cpu_user_seconds_total`, `credential_enclave_cpu_system_seconds_total` and `credential_enclave_cpu_idle_seconds_total` (the milliseconds of `health` as seconds with three decimals); when its two memory values are not null, the gauges `credential_enclave_memory_total_bytes` and `credential_enclave_memory_available_bytes`; when the object holds the two counts of the connections from the backend (a node of release v2.2.0 or later), the gauge `credential_enclave_inbound_connections` (`inbound_connections`) and the counter `credential_enclave_inbound_refused_total` (`inbound_refused`); when it holds the value, the gauge `credential_enclave_descriptors_open` (`descriptors_open`) and the gauge `credential_enclave_descriptors_limit` (`descriptors_limit`). From the `egress` object of `health`, when the node answers with one: the counter `credential_enclave_egress_opens_total` (`opens`), the counter `credential_enclave_egress_open_failures_total{cause}` (`open_failures`; `cause` is `transport`, `relay_refused`, `tls` or `http`), the counter `credential_enclave_egress_open_retries_total` (`open_retries`), the gauge `credential_enclave_egress_open_inflight` (`open_inflight`) and the counter `credential_enclave_egress_idle_reuses_total{peer}` (`idle_reuses`; `peer` is `provider` or `log_store`). From the `refresh` object of `health`, when the node answers with one: the counter `credential_enclave_refresh_late_total{outcome}` (`late`; `outcome` is `kept`, `dropped`, `failed` or `abandoned`) and the gauge `credential_enclave_refresh_late_inflight` (`late_inflight`). After the series of the objects, when the answer holds the value: the gauge `credential_enclave_grants` (`grants` of `health`, the accounts with a grant within its time; every release answers it). From the `state` object of `health`, when the node answers with one: the gauges `credential_enclave_kept_refreshes` (`kept_refreshes`), `credential_enclave_merge_keys` (`merge_keys`), `credential_enclave_pending_entries` (`pending_entries`) and `credential_enclave_idle_connections{peer}` (`idle_connections`; `peer` is `provider` or `log_store`). From the host program itself, with every answer, after the series of `health`: the gauge `credential_enclave_host_enclave_running` (1 while the last `describe-enclaves` of the watch listed a running enclave or none ran yet, 0 when it listed none), the gauges `credential_enclave_host_descriptors_open` and `credential_enclave_host_descriptors_limit` (the open descriptors of the host program and its limit in force, when the kernel gives both), the counter `credential_enclave_host_egress_accept_errors_total{cause}` (the failed accepts of the egress relay; `cause` is `aborted`, `resources` or `other`), the counter `credential_enclave_host_egress_relays_total{outcome}` (the connections of the node the egress relay served; `outcome` is `relayed`, `malformed`, `not_allowed` or `unreachable`), the gauge `credential_enclave_host_egress_relays_inflight` (the connections whose bytes the egress relay moves at this moment) and the counter `credential_enclave_host_inbound_node_connect_failures_total` (the connections of callers for which the inbound relay could not open its connection to the node). When the `health` call fails, the answer is `credential_enclave_up 0` and the series of the host program. A counter of the node restarts at 0 when the node restarts (the started timestamp changes), a CPU counter when the kernel of the node boots, and a counter of the host program when the host program starts |
| Sending the operator configuration again | Does not happen. The configuration is sent once at the start. To change a value, the pod is replaced |
| Watch | Every 10 seconds the host program runs `nitro-cli describe-enclaves` (in a blocking task; an answer is waited for 5 seconds, a run that takes longer is waited for at the next poll and no second run starts beside it) and reads its JSON list: an element whose `State` is `RUNNING` is a running enclave. Before the third consecutive answer without a running enclave counts, the host program makes one `health` call to the node: a node that answers is alive whatever the list said, the answer counts as a running enclave and the count starts over (a node that does not answer is judged by the list alone). Three consecutive answers without a running enclave confirm that the enclave ended on its own (the node program aborted, the enclave ran out of memory, the hypervisor ended it): the host program logs it, makes the shutdown collection call of the Shutdown row (the backend records the node as closed; the collection fails at its first stage, as the node is gone), calls `nitro-cli terminate-enclave --all` and ends with a status that is not 0, so that the container runtime starts it again with a new enclave, which takes its delegations from the living nodes. One answer without a running enclave does not confirm the end (one line of the log says that the list was empty), and a run that failed or passed its 5 seconds changes nothing: a host program that ended on a reading failure would end a living node and lose its delegations. `GET /livez` and the gauge `credential_enclave_host_enclave_running` of the Status row read the same observations |
| Shutdown | On SIGTERM (or SIGINT) the host program logs one line with the output of `nitro-cli describe-enclaves` on one line (the JSON list of the running enclaves: the enclave object while the node is alive, `[]` when the enclave ended before the signal; the line says whether the node was alive when the signal came), then calls `POST {CREDENTIAL_ENCLAVE_DRAIN_URL}` (the shutdown collection route of the backend): the body `{"pod": "<the value of CREDENTIAL_ENCLAVE_POD_NAME>"}`, the headers `Authorization: Bearer {CREDENTIAL_ENCLAVE_DRAIN_TOKEN}` and `Content-Type: application/json`. Inside that request the backend makes the calls of the orderly shutdown to the node (5.11, 5.13), through the inbound relay. Before the call the host program reads `accounts` of the `health` call of the node and waits for the response for 100 seconds plus 4 seconds for every started page of 1,000 accounts, at most 600 seconds (`drain::response_timeout`: the backend hands the delegations over and collects the final heads page by page, 1,000 accounts a page, measured at about 2 seconds and about 1 second a page; a node that does not answer its `health` call gets the 100 seconds). The log names the wait and the accounts. Then it calls `nitro-cli terminate-enclave --all` and ends. The `terminationGracePeriodSeconds` of the pod must cover the longest wait of the `drain` subcommand, the longest wait of this call and a margin: 610 + 600 + 30 = 1,240 seconds. When one of the three variables (`CREDENTIAL_ENCLAVE_DRAIN_URL`, `CREDENTIAL_ENCLAVE_DRAIN_TOKEN`, `CREDENTIAL_ENCLAVE_POD_NAME`) is missing, it ends the enclave without the collection. The call of the signal path repeats the call of the `drain` subcommand when the pre-stop hook made one: the backend takes a repeated call for the same pod as the same collection |
| `drain` | `credential-enclave-host drain` makes the shutdown collection call of the Shutdown row alone (the same request, from the same three variables, after the same `health` call for the accounts of the node), waits for the response for the wait of the Shutdown row plus 10 seconds from its start (110 seconds for a node without accounts, at most 610 seconds), logs one line with the outcome (the status of the response and the elapsed milliseconds, the failure and the elapsed milliseconds, or the end of the wait) and ends with the status 0 in every case: a failed collection does not hold the end of the pod. When one of the three variables is missing, or the address cannot be used, it logs one line and ends with the status 0 without a call. The pre-stop hook of the pod runs it before the termination signal reaches the host program, while the node is alive |
| local | The node program with `--platform local` runs alone, without the host program. Whatever starts it sends the operator configuration |

The output of the host program is its log: lines on the standard output, and the output of
`nitro-cli`. The client values of the operator are never part of a line.

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
| 1 | `Dockerfile.enclave`: in a fixed Rust builder image (Alpine), `cargo build --release --locked --target x86_64-unknown-linux-musl -p credential-enclave`. The result is copied into an image `FROM scratch` with `ENTRYPOINT ["/credential-enclave","--platform","nitro"]` | The digest of the builder image. The build installs no package: the builder image holds the C library headers (`musl-dev`) that the C parts of the crate `ring` need, and the Dockerfile asserts their version and the version of `rustc`. `rust-toolchain.toml`, `Cargo.lock`, the release profile (`opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = true`), `WORKDIR /build`, `SOURCE_DATE_EPOCH` (the time of the commit), `CARGO_INCREMENTAL=0`, `TZ=UTC`, `LC_ALL=C`, `--remap-path-prefix` |
| 2 | BuildKit creates the image with `SOURCE_DATE_EPOCH` and `--output type=docker,rewrite-timestamp=true` | The version of BuildKit (the digest of its image) |
| 3 | `Dockerfile.eif`: `amazonlinux:2023`, fixed by digest, with `aws-nitro-enclaves-cli` and `aws-nitro-enclaves-cli-devel` of a fixed version. In it, `nitro-cli build-enclave --docker-uri ... --output-file enclave.eif` | The digest of the base image, the name, version and release of the two packages, and the SHA-256 of the files that `nitro-cli` puts into every enclave image file (`bzImage`, `cmdline`, `init`, `linuxkit`, `nsm.ko`), which the build records |
| 4 | The output: `out/enclave.eif` and `out/measurements.json` (`{"release","git_commit","pcr0","pcr1","pcr2","inputs":{...}}`). `inputs` names what the three measurements were made of: the digests of the three images, the SHA-256 of `rust-toolchain.toml`, `Cargo.toml`, `Cargo.lock`, the two Dockerfiles and `build.sh`, of the five files of row 3, and of the node binary | |
| 5 | `Dockerfile.host`: the host program, built with the builder image of row 1 and linked statically, on the base image of row 3 with `nitro-cli`. Files: `/usr/local/bin/credential-enclave-host`, `/opt/credential-enclave/enclave.eif`, `/opt/credential-enclave/measurements.json`. Directories: `/run/nitro_enclaves`, `/var/log/nitro_enclaves`. `ENTRYPOINT ["/usr/local/bin/credential-enclave-host"]` (no argument). The user is root (`nitro-cli` needs it for the enclave device). The host program listens on TCP 8080 and 9091. This image is not measured | |
| 6 | `Dockerfile.local`: the node program, built with the same builder image, as the one file of an image `FROM scratch`. It builds natively on linux/amd64 and on linux/arm64: `docker build -f build/Dockerfile.local -t credential-enclave-local:dev .`. `ENTRYPOINT ["/credential-enclave","--platform","local"]`. It listens on TCP 8080. This image is for development stacks. No workflow builds or publishes it: a release consists of what the measurements cover and of the host image around it | |

- The release tag is a build input: `build.sh` passes the git tag of the commit (`v*`, or `dev`
  for a commit without a tag) as `CREDENTIAL_ENCLAVE_RELEASE`, and the node program compiles that
  value in as a constant (the `release` of `binding`).
- Three files of `enclave/release/` are build inputs: the node program compiles them in, so they
  are part of the measurement (protocol.md 10.3). `release-key.pem` is the release key of the
  operator and `rekor-key.pem` is the public key of the transparency log Rekor of
  rekor.sigstore.dev, each an ECDSA P-256 public key as a SubjectPublicKeyInfo in PEM.
  `predecessors.json` is the list of the releases whose nodes a node of this build takes
  delegations from: `[{"release","pcr0","pcr1","pcr2"}]`, with the values of the
  `measurements.json` of each of those releases. Every release of the list is earlier than the
  release of the build. A build without a tag (`dev`) starts with the empty list only.
- The endorsement of a release (protocol.md 10.3) is made outside this repository: the operator
  signs the `measurements.json` of the release with the private half of the release key and
  records the signature in the transparency log. This repository holds the public half only, and
  no workflow of it creates an endorsement.
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
| `check.yml` | A push to any branch, a pull request | `check`: `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`, the vector check (`cargo run --locked -p credential-enclave-protocol --bin vectors -- --check`: the committed file equals the output of the generator), `scripts/secret-access.sh --check` (rule E2 of egress-policy.md), and the tests of the secure program on the model of the bridge (`node --test secure-program/tests/program.test.js`, secure-program/README.md). `measure` (on a push): `build/build.sh eif`, and `out/measurements.json` as the artifact `measurements` |
| `release.yml` | The push of a `v*` tag | `check`: the checks above and `cargo audit` (no dependency of `Cargo.lock` has a security advisory). `build-a`, `build-b`: `build/build.sh eif` each, and the release of the build is the pushed tag. `compare`: the two `measurements.json` are equal, otherwise there is no release. `publish`: the host image around the enclave image file of `build-a` to `ghcr.io/pickle-com/credential-enclave/host:{tag}`, the GitHub release with `enclave.eif` and `measurements.json`, two attestations of the enclave image file (its build provenance, and the release statement of protocol.md section 9, whose predicate is `measurements.json`), and their bundles on the GitHub release (`provenance.sigstore.json`, `release-statement.sigstore.json`) |
| `secure-program-release.yml` | The push of a `secure-program-v*` tag | `release`: `secure-program/statement.py` writes the release statement of the tag (protocol.md, "The secure program release"; the job fails when the version of `secure-program/secure-program.js` is not the N of the tag), creates the GitHub release of the tag with `secure-program.js` and `statement.json`, and attaches a build provenance attestation of the file (`secure-program-provenance.sigstore.json`). The signature of the release key and the entry of the transparency log are made outside this repository, by the operator on the machine that holds the release key, and uploaded to the same release as `secure-program.release.json` |
| `secure-program-monitor.yml` | Every hour (`17 * * * *`), and `workflow_dispatch` | `monitor`: `secure-program/monitor.py` asks Rekor for every entry of the release key (`POST /api/v1/index/retrieve`) and compares the statement hash of each with the statements of the releases of this repository: of every `secure-program-v*` tag (the statement rebuilt from the file and the commit of the tag) and of every `v*` tag (the bytes of `measurements.json` of its GitHub release). An entry that no release explains, an entry of another key, or a log that cannot be read fails the job, and the job then opens the issue "Transparency log: entry of the release key without a matching release" with the report, or adds the report as a comment to the open one |

- The runner is `ubuntu-24.04`, and every action is fixed by its commit SHA. The permissions of
  `publish` are `id-token: write`, `contents: write`, `attestations: write` and
  `packages: write`. The permissions of `release` of `secure-program-release.yml` are
  `contents: write`, `id-token: write` and `attestations: write`; those of `monitor` of
  `secure-program-monitor.yml` are `contents: read` and `issues: write`.
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
| Formats, per module | The unit tests of `protocol/src/` | Encodings, key derivation, the command envelope and its failure order, the record and its kinds, the log chain, the statements, TOTP, the failure codes |
| Endorsement of a later release | The unit tests of `protocol/src/release.rs`, with `protocol/tests/fixtures/rekor-entry-150000000.json` | With keys the tests create: an endorsement that holds, and the refusal of another log identifier, of a signed entry timestamp over another body, time or index, of a body with a character outside the base64 alphabet, of a body with the hash of another statement, with another public key or with the signature of another key, of a statement with a missing or malformed value or of more than 16,384 bytes, of an entry time more than 300 seconds ahead, and of a release that is not later than the own release (the candidates `-rc.{n}` and an own release `dev` included). The form of a release tag and the order of releases. The signed entry timestamp of a real entry of Rekor verifies with the log key of the node program. The list of predecessors: a valid list, malformed elements, an element that is not earlier than the own release |
| Keys and predecessors of the program | The unit tests of `enclave/src/lineage.rs` | The two keys of `enclave/release/` are ECDSA P-256 keys, the log key has the log identifier of Rekor, the list of the source is valid for the release of the crate version, and a node does not start with a malformed key or list |
| Secret types | `protocol/src/secret.rs` | The `compile_fail` examples and the compile-time assertions of rule E1 (a secret cannot be serialized, formatted, dereferenced or compared, and the private keys of `NodeKeys` cannot be read), and that the `Debug` output of a secret never holds its bytes |
| Attestation documents | The unit tests of `protocol/src/attestation.rs`, `enclave/src/attest.rs` and `enclave/src/platform/nitro.rs`, with the files of `protocol/tests/fixtures/` | The certificate chain and the signature of real Nitro attestation documents, the definite and the indefinite form of the payload, the refusal of another root, of a changed document, of other PCRs and of a debug-mode enclave. A peer under the statement of a later release and a peer of a listed predecessor: accepted with the measurement and the release of the real document, refused with another release in the binding, with another PCR, with another log store, on the local platform, and as a debug-mode enclave |
| Command processing | `enclave/src/tests/commands.rs` | The state transitions of sequences of grant and revoke: a challenge is used once and for 300 seconds, a command for another node or of another user, the range of the expiry, the custody of a grant, a revoke and an old envelope after it, a grant that was held back until after a revoke, replacement, an expired grant |
| Records | `enclave/src/tests/records.rs` | A record of another account, of another key or of another custody does not open, and neither does a record with a changed field of its AAD. The kind of a record decides the fields that `release` hands out |
| Log | `enclave/src/tests/log.rs` | The entry is on the chain before the provider is called (the provider stand-in looks at the head at the time of the call), the group commit (the events that arrive during a write form the next entry; a merged GET waits for the entry of the event it shares; a control event closes the open batch and stands alone; the caps of 128 events and 1,048,576 bytes), the `log` object of every response, the chain verified from the keys of the store and its head (index and content verification, a gap, a changed key), the final heads of `close` when the store confirmed every entry, a final head that covers an open batch, the times of the events and entries of a chain |
| Orderly shutdown | `enclave/src/tests/close.rs` | The final head rule of 5.11 against a store that refuses writes: pending entries that are the tail of a chain are dropped and the final head stands at the last confirmed entry (the sweep writes nothing more, the keys the store holds reach the head, `truncated` 1); a chain whose every entry is pending ends at `seq` 0 and leaves the account without a chain; a confirmed entry above a pending one leaves the account without a head and counted in `skipped` until a later call finds the gap closed; a repeated call returns the same head |
| Log store | `enclave/src/tests/log_store.rs`, the unit tests of `enclave/src/log_store.rs` | Against a stand-in for Amazon S3 on the TLS server of the provider stand-in: the write of an entry arrives before the request to the provider, under the key of format 2 whose seven parts the test computes again from the body, with the headers and a signature that the test computes again from the request. A write the store does not confirm (a status other than 200, a 412 included, no connection, no answer within the time limit) stops the act of every call, the writer and the calls that waited for it. A pending entry is written again with the next write of its account, and a request that shares an event waits for its entry. The signed refusal of a grant, a revoke that erases the key whatever the store answers, the failure and the repetition of `peer/export`, the refusal of a peer of another log store, a node of the nitro platform without a log store or credentials, the limit of pending entries, calls that end before their write (the account has no writer afterwards), calls that run at the same time form one entry and write each entry once. The idle connections: one connection for writes in a row, a connection the store closed, a write whose idle connection ends without a response, the current credentials over an idle connection. The attempts of a write: a 5xx status and 429 are repeated over a new connection with the same body within the budget, a 4xx status is not, an idle connection that stalls or that closes without a response is left for a new connection, a new connection that closes without a response is repeated as well, a store that cannot be reached is asked for three connections, and the causes and the counts of health. The sweep: its rate, its random order, and the jitter before it writes the entries of an account. The local endpoint: a path-style write over plain HTTP with the host of the endpoint, refused on the nitro platform and for a value that is not an origin. The signature against the examples of the AWS documentation |
| Address check | The unit tests of `enclave/src/providers/mod.rs` | The refusals of section 7 (another host, a path outside the lists, a denied path in its spellings, dot segments, dot segments in front of a path parameter, encoded separators and separators that are encoded twice, a port, user information), and the validation of the definitions, including the rules for public fields and the application password definitions of 6.5 (the two forms, the domain of the account, the methods, the `verify` request, the one embedded definition and the addresses and methods it allows) |
| OAuth | `enclave/src/tests/oauth.rs`, the unit tests of `enclave/src/oauth.rs` | Against the provider stand-in: exchange, refresh, the merge of a reconnect, the nested token place of slack and its `ok: false`, the public fields and the containment check, the closed vocabulary of `provider_error`, the kept response of a repeated refresh, a token address call of `refresh` whose response arrives after the time limit of the call (kept for the next call with the same record; dropped after a revoke or after `close`; a late refusal and the late limit; the bound of the late calls and their counts in health), a record of kind `oauth_imported` |
| forward | `enclave/src/tests/forward.rs`, the unit tests of `enclave/src/provider_response.rs` and `enclave/src/egress.rs` | Header removal, the refusal of a header that overrides the method and of the batch address of Microsoft Graph, the injected credential, the event of a GET request with a body, the whole path and the whole query in the event of the longest address, redirects that are not followed, chunked responses, the body limit, the time limit, a response that reflects the credential (as it is, under percent escapes of up to three layers, in base64 and in hexadecimal), the idle connections per (account, host): two accounts never share one, a connection is dropped after 30 seconds idle, a GET over an idle connection that ends without a response is sent once more and a POST is not; an open that fails before a request byte left is repeated within half the time limit of the call (two refusals and then a success, three refusals, a refusal that arrives after half the time limit), the bound of connections being opened at once, and the counts of `egress` of health |
| forward/batch | `enclave/src/tests/forward_batch.rs` | One entry names every request before any leaves; a batch of 100 with 6 in flight; a request that fails the address check refuses the whole call with its index and creates no event; a merged request inside a batch shares the event; two entries when the open batch reaches its cap inside a batch; one failed request leaves the other results intact and keeps its `log` object; the bodies of the results together under the body limit; the results in the order of the requests; the bodies split by `body_bytes`; a batch of 0 or 101 requests is invalid |
| Application passwords over HTTP | `enclave/src/tests/app_password.rs` | Against a stand-in for the CalDAV host of NAVER Calendar: `forward` with a record of kind `app_password` of `naver_calendar` sends HTTP Basic of the login and the password (the account name without its domain, in lower case; the credential header of the caller is dropped) and logs a `provider_request`; the methods and the hosts of the definition bound the password (another method, another host, another port, a token toward the CalDAV host); the password of `naver_mail` and a vault record are refused by `forward` and `app-password/verify`, and so is a token record by `app-password/verify`; `app-password/verify` sends the request of the definition, states the identity with a statement that verifies, refuses a request or a payload of its own, reports 401 as `authentication_failed` and any other status as it is, and follows no redirect; a response that reflects the password is withheld by both calls; and the route in a success and a failure case, with the password reaching the CalDAV host only |
| Delegation transfer | `enclave/src/tests/peer.rs` | The round trip of export and import between two nodes of the local platform, paging, the exclusion of expired grants and of accounts that revoked, a grant of another `sign_pk` is not replaced, the refusal of a changed envelope and of an envelope for another node, the entries `grant_transferred_out` and `grant_transferred_in` (the `logs` of the responses and the objects of the store), a repeated export to the same peer without a new entry, the limit of 64 peers per grant, an export with an endorsement that does not hold (it hands nothing over and leaves no entry, also for a peer the call without an endorsement accepts), the `subset` of export (the share of the peer alone, with entries for it alone, and pages that count the selected grants) and of import (the share of the receiving node alone out of a transfer of every account, `copies` at or above `pods` names every account, `null` is a call without a subset, a subset outside its bounds is refused by both calls) |
| Delegation subset and pruning | `enclave/src/tests/grants.rs`, the unit tests of `enclave/src/subset.rs` | The assignment vectors of protocol.md 10.4 and the agreement of `contains` with `assign`; `grants/prune` drops the grants within their time and the expired grants outside the share page by page in `user_id` order, leaves the chains, the revocation markers and the grants of the share, prunes nothing more on a repeated walk, works in the state `closing`, and refuses a missing subset, a subset outside its bounds and a `limit` of 0; after grants, a refresh, merged GET requests, refused writes, an expiry, a revoke, an import, a prune, two sweeps and the shutdown, every count of health (`accounts`, `grants`, `pending`, `pending_entries`, `kept_refreshes`, `merge_keys`, `open_batches`) equals a scan of the accounts |
| Call surface | `enclave/src/tests/surface.rs`, the unit tests of `enclave/src/load.rs` and `enclave/src/descriptors.rs` | `health` with the counts of its `log`, `egress`, `refresh` and `state` objects and the values of its `load` object (the readers of `/proc/stat`, `/proc/meminfo` and the auxiliary vector on sample text: the columns of each mode, a line with fewer columns, malformed text; the limit of open descriptors is raised or kept and never lowered, and the count of open descriptors follows the descriptors the process holds), the bound of the connections from the backend (a connection above the bound is closed without a byte and counted, an idle connection is closed after the idle time and frees its place), the operator configuration, attestation and its challenge statement, the failure bodies, HTTP/1.1 over a real connection, that `log/entries` and `log/ack` do not exist, and that the calls of the router are the calls of the table in section 4 of egress-policy.md |
| Egress policy | `enclave/src/tests/canary.rs` | The canary test of egress-policy.md: every secret carries a distinct marker, the provider stand-in breaks its contract on purpose (reflected credentials, tokens in public fields, content and transfer codings, cookies, redirects), every call of the router is made in a success and in a failure, no marker appears in a response in any of the searched encodings, and a credential reaches only the addresses of its own provider. The one exception is the requested field of a successful `release`. Both nodes of the walk have a log store: no write to it carries a secret of the account, and of the credentials for it the session token reaches the log store alone and the secret access key no request |
| Host program | The unit tests of `host/src/` | The relays (the inbound relay counts the connections for which the node could not be reached), the allow list of the egress relay with the host of the log store, the operator configuration with the log store of the environment, the memory of the enclave from its variable (the default, a value, the refused values), the description line of the enclaves, the one argument `drain`, the status surface (the four gauges, the seven series of the `log` object of `health`, which the answer of a node of a release before v2.0.0 does not have, the seven series of its `load` object, which the answer of a node of a release before v2.0.1 does not have and whose CPU and memory series are absent when the values are null, the series of its `egress`, `refresh` and `state` objects, the gauge of its `grants` value, and the four series of the two relays) the shutdown call and its wait (the base, the pages of the accounts of the node, the longest wait), the watch of the enclave (the reading of the answer of `describe-enclaves`, three consecutive answers without a running enclave confirm the end and one does not, a failed run does not count, a node that answers its health call keeps the end from being confirmed), `/livez` from the watch and not from the node, the series of a node of release v2.2.0 (the connections from the backend, the descriptors of the node and of the host program, the gauge of the watch), and the limit of open descriptors of the host program, against a stand-in for the node over in-memory pipes |
| Verification tool | The unit tests of `verify/src/`, `verify/tests/offline.rs`, with the files of `verify/tests/fixtures/` | The checks on a stored attestation document of a node of release v1.0.0 against the `measurements.json` of that release, the refusals, the report with the log store of a binding, and the exit status of the built tool |


## Mail call surface

GET /v1/health adds `mail_providers: ["naver_mail"]`. An absent field on an older release means
no mail support. `app_password_providers` of the same call lists the providers of the application
password definitions (6.5), whose password travels over HTTP and whose verification is 5.8c; an
absent field on an older release means no such provider. POST /v1/mail/verify, /v1/mail/read and
/v1/mail/submit use the forward binary
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

Mail protocol input is bounded at the stream: verify, folder listing and search (including
headers) accept at most 4 MiB of protocol input per connection, and reading one raw message
allows the configured body limit plus 1 MiB of protocol overhead, while the returned message
itself still has the body limit. The same bound applies to a literal declaration before the
protocol parser reads it: a server line that declares a literal (`{N}` CRLF) above the
connection's bound ends the connection as a provider failure, because the SDK parser
(async-imap 0.12) grows its buffer to a declared length with a zero-filled allocation of up to
512 MiB before the octets arrive. With the guard, the parser buffer never exceeds the bound
plus one 4 KiB block. A search whose UID set or headers exceeds the bound must be narrowed. Unknown IMAP login refusals remain provider
failures; a `NO` reply to `LOGIN` classifies the application password as refused only when it
carries the RFC 5530 response code `AUTHENTICATIONFAILED` or the information `Authentication
failed`, which imap.naver.com sends with its own response code `[AUTH]`.

A mail call reserves its request frame from the shared body budget before reading it (the
declared length, else the frame limit), and once the operation, the action and the payload are
known, and before a credential is opened, resizes the reservation to the operation's amount.
Verify, folder listing and search reserve six times the 4 MiB input bound (the parser
buffer, which the parsed rows borrow, the base64 headers, the JSON and the frame) plus two
frame metadata limits: 26 MiB at the 1 MiB metadata limit. Reading one raw message reserves its input bound
plus the body limit (the parser buffer and the message copy) plus two metadata limits: 131 MiB
at the default 64 MiB body limit. Submit reserves its payload plus two metadata limits. At the 2 GiB budget this admits about seventy listing calls or fifteen raw-message
reads at once, bounded further by the 512 forwarding slots. Mail takes both its forwarding slot
and body reservation without waiting. Insufficient capacity returns HTTP 503 `capacity_unavailable`
before a credential is opened or a provider is called; the request frame may already have been
read under its own reservation. No mail
reservation enters the shared FIFO semaphore queue, so it cannot hold a smaller eligible
HTTP call behind it. Admitted calls retain the 30-second deadline. The 512 forwarding slots
are not a promise of 512 concurrent mail calls; capacity planning must include the body budget.

FROM and SUBJECT search values use synchronizing UTF-8 literals with byte lengths, waiting
for the server continuation before each literal (RFC 3501 sections 4.3 and 6.4.4). This avoids
assuming that an IMAP server accepts non-ASCII quoted strings or supports LITERAL+.
