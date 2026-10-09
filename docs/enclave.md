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
│   ├── src/state.rs              # the state of a node (section 3), the events of the log
│   ├── src/clock.rs              # node time (section 8)
│   ├── src/api/mod.rs            # the router, the failure responses
│   ├── src/api/responses.rs      # every response type (rule E3 of the egress policy)
│   ├── src/api/{health,config,attestation,messages,status,oauth,refresh,revoke,forward,release,log,close,peer,log_store}.rs
│   ├── src/attest.rs             # which peer a node accepts (same platform; same measurement, a later release with an endorsement, a predecessor)
│   ├── src/lineage.rs            # the release key, the log key and the list of predecessors of the program (5.13)
│   ├── src/providers/mod.rs      # the provider definitions: parsing, validation, the address check
│   ├── src/providers/definitions.json
│   ├── src/oauth.rs              # the authorization address, the token address call, the merge rules, the public fields
│   ├── src/vault.rs              # the vault kinds and the value `release` hands out
│   ├── src/provider_response.rs  # the check of a provider response before `forward` returns it
│   ├── src/egress.rs             # the TLS client (rustls), one HTTP/1.1 exchange per connection
│   ├── src/log_store.rs          # the log store: the write of an entry, its signature, the pending entries (5.14)
│   ├── src/frame.rs              # the frame of `forward` (5.8)
│   ├── src/testing.rs            # tests only: the provider stand-in, the test platform and clock
│   └── src/tests/                # tests only: the tests of the whole node (section 12)
├── host/                         # crate credential-enclave-host (binary credential-enclave-host)
│   └── src/{main,launch,relay,egress,config,health,drain,http,testing}.rs
├── verify/                       # crate credential-enclave-verify (binary credential-enclave-verify)
│   ├── src/{main,arguments,evaluate,fetch,render}.rs
│   └── tests/{offline.rs,fixtures/}
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
└── .github/workflows/{check.yml,release.yml}
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
| `log.rs` | The log entry, the chain hash, the head, the key of an entry in the log store |
| `statement.rs` | The node statements: the challenge statement of an attestation response (protocol.md 4.2), and `oauth_begin` and `oauth_complete` (protocol.md 8.2) |
| `totp.rs` | TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30 seconds) |
| `release.rs` | The delegation transfer to a later release (protocol.md 10.3): the release statement, the six checks of an endorsement (the statement, the log identifier, the signed entry timestamp, the body of the entry with the release key and its signature, the time of the entry, the order of the two releases), the order of release tags, the reader of a list of predecessors, the reader of the PEM of a public key. The release key and the log key are arguments |
| `attestation.rs` | Reading and verifying attestation documents: the Nitro document (CBOR, COSE_Sign1, the certificate chain, the signature, the PCRs), the binding, the local document. It holds the trust root (AWS Nitro Enclaves Root-G1, DER) as a public constant. It returns what a document states and does not judge a measurement: which PCR values are acceptable is the decision of the caller |
| `app.rs` | The app side of the protocol: the derivation of the account keys, the check of a challenge statement, sealing a command, opening log entries, verifying a chain. The node program does not call this module. The generator of the test vectors and the tests use it in the place of the app |
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
    log_store: LogStore,             // { required, id: OnceLock<LogStoreId>, credentials: RwLock<Option<Arc<Credentials>>> } (5.14)
    challenges: Mutex<Expiring<[u8; 16], u64>>,         // the issued challenges, each with its serial. Removed after 300 seconds or on use. At most 100,000
    serials: AtomicU64,                                 // the next serial: one count for the challenges the node issues and the revoke commands it accepts. It starts at 1 and only grows
    accounts: RwLock<HashMap<String, Arc<Mutex<Account>>>>,  // user_id -> the state of the account. One lock per account
    pending: Mutex<Expiring<String, PendingAuth>>,      // node_state -> the pending authorization (600 seconds, used once). At most 100,000
    // and: the platform, the clock, the provider definitions, the TLS client, the limits of section 8
}
struct Account {
    grant: GrantState,               // None | Active { key_id, sign_pk, log_pk, custody, user_key, not_after_ms, exported_to } | Expired { key_id, not_after_ms } | Revoked { key_id, sign_pk }
    head: Head,                      // { seq, hash }. Without entries: seq 0 and a hash of 32 zero bytes
    unacked: VecDeque<Entry>,        // the entries without a storage acknowledgement. A call that uses a credential stops at 64 (section 4)
    unconfirmed: Vec<Unconfirmed>,   // the entries the log store has not confirmed: { seq, hash, entry, writing }. Empty on a node without a log store (5.14)
    recent: HashMap<[u8; 32], Recent>,  // merge key -> { entry_ms, seq } of its entry. Removed after 300 seconds (the GET requests of forward that have no body)
    final_head: Option<Signed>,      // the final head that the orderly shutdown created (5.11)
    kept_refreshes: VecDeque<KeptRefresh>,  // the responses of the successful refresh calls of the last 3,600 seconds, at most 16 (5.7)
    last_entry_ms: u64,              // the time_ms of the last entry of the chain (section 8)
    revoked_here: bool,              // true once this node accepted a revoke command of the account (protocol.md 10.1)
    revoke_serial: u64,              // the serial of the last revoke command of the account that this node accepted, 0 when there is none (protocol.md 5.4)
}
struct KeptRefresh { key: [u8; 32], kept_ms: u64, response: Refreshed }   // key = SHA-256(the ct of the record that was sent)
struct PendingAuth { user_id, key_id, sign_pk: [u8; 32], provider, code_verifier: Option<PkceVerifier>, client_id: String, redirect_uri: String, state: String, expires_ms }
struct OperatorConfig { providers: HashMap<String, ProviderCredentials> }
struct ProviderCredentials { client_id: String, client_secret: Secret<String>, redirect_uri: String, publishable_key: String }
struct Credentials { access_key_id: String, secret_access_key: Secret<String>, session_token: Secret<String>, expires_ms: u64 }   // of the log store
```

- A node writes nothing to disk. Nodes share no state. The one exchange between nodes is the
  delegation transfer (5.13). The witnessing of stage 2 is in section 10.
- A grant whose time has passed: every place that reads the state of an account (a call that uses
  a credential, a command, `status`) first checks `now >= not_after_ms`. When that is true, the
  node erases the user key and changes the state to `Expired { key_id, not_after_ms }`, and judges
  after that. A call that uses a credential refuses `Expired` with `grant_expired`. There is no
  case in which an `Active` state holds a user key that is overwritten with zeros (protocol.md
  5.4).
- `exported_to` of an `Active` grant is the list of the nodes that the grant was handed to with
  `peer/export`: the signing public key of each and the `seq` of the entry
  `grant_transferred_out` that names it, at most 64 (protocol.md 10.1). A grant command, a
  revoke, the end of the grant and a transfer that puts a grant in place create a new state, and
  the list of a new grant is empty.
- `unconfirmed` of an account holds the entries that the log store has not confirmed. `writing`
  is true while a call writes the entry. An entry of this list that no call writes is a pending
  entry (protocol.md 7.6). A call takes the entries it writes out of the pending state inside
  the lock of the account and puts back the ones the store did not confirm, also when the call
  ends before its writes do (the caller closed the connection).
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
- The creation of an entry and the update of the head of one account happen inside the lock of
  that account (the chain of one account does not fork). A provider call and a write to the log
  store run outside the lock.
- The kept responses of `refresh` (5.7): a kept response holds what the response held, which is a
  record (a ciphertext), the public fields and a log entry. A revoke command, the expiry of the
  grant, and a grant of another signing key drop the kept responses of the account.

## 4. The common rules of the call surface

- Transport: HTTP/1.1. On nitro the node listens on vsock port 8080, on local on TCP 8080. The host
  program moves TCP 8080 inside the cluster to the vsock listener (section 9).
- The caller is the operator domain (its backend processes). A node does not trust its caller: a
  decision rests on the grant of the account, on the AEAD authentication of a record and on the
  provider definitions, and on nothing else.
- Bodies: `POST /v1/forward` takes and returns a frame (5.8). Every other body is
  `application/json`.
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
| 429 | `log_backlog` |
| 500 | `internal` |
| 502 | `exchange_failed`, `refresh_failed`, `provider_unreachable`, `response_withheld` |
| 503 | `not_configured`, `closing`, `log_store_unavailable` |
| 504 | `timeout` |

A path that is not defined is 404, and a method that a path does not accept is 405. Both have the
code `invalid_request`. `user_mismatch` is 400 also when the account of a record does not match
(protocol.md section 6). A JSON body is accepted up to 1 MiB, and a longer one is `too_large`. The
responses of a node carry no `Date` header (it would be a value of the system clock).

- The common front of the calls that use a credential (`forward`, `refresh`, `revoke-token`,
  `release`, `oauth/complete`): (1) the node is not `closing`. (2) The operator configuration is
  present (`release` is the exception). (3) The node can write to its log store, and the account
  has fewer than 64 pending entries (5.14. A node of platform `local` without a log store
  passes. An account the node holds no state of fails before this step, with `grant_required`).
  (4) The grant of the account is Active and within its time. (5) `unacked` of the account is
  below 64. (6) The node opens the record (protocol.md section 6. `oauth/complete` creates a
  record and has no step 6). `oauth/merge` passes (1), (4) and (6) only (it creates no entry and
  calls no provider). `oauth/begin` passes (1), (2) and (4).
- A command (`messages`) is not stopped by the limits of (3) and (5): a revocation must always be
  possible. The entries of commands and of delegation transfers can raise `unacked` above 64.
- The entry, the log store and the act. A call that creates an entry writes it to the log store
  and performs its act only after the store confirmed the entry (protocol.md 7.6 names the act of
  every call). When the store does not confirm it, the call ends with `log_store_unavailable`
  (503) and the act does not take place.
- A call that creates an entry carries that entry in its response (`entry`). An entry whose
  response did not reach the caller is fetched again with 5.10. That includes the cases in which
  the log store did not confirm the entry, or the provider call failed after the entry was
  created: the failure response carries no entry.
- From step (4) of the front to the creation of the entry, a call runs inside the lock of the
  account. So a call either fails on the state of the grant, or its entry is on the chain before
  the entry of a later revoke: a revoke that is answered before a call reaches this part leaves no
  request of that call behind it. The write to the log store and the act follow outside the lock.

## 5. The calls

### 5.1 `GET /v1/health`, `POST /v1/config`

```json
GET /v1/health -> {"node":"...","release":"v1.0.0","platform":"nitro","custody":"enclave","started_ms":0,"time_ms":0,"configured":true,"closing":false,"accounts":0,"grants":0,
                   "log_store":{"bucket":"...","region":"...","credentials_expires_ms":0,"pending":0}|null}
POST /v1/config {"providers":{"google_workspace":{"client_id":"...","client_secret":"...","redirect_uri":"https://.../api/integrations/google_workspace/oauth/callback","publishable_key":""}, ...},
                 "log_store":{"bucket":"...","region":"..."}}
             -> {"configured":true}
```

- `accounts` of `health` is the number of accounts that have a chain (a `seq` of at least 1).
  `grants` is the number of accounts that have a grant within its time (the operator domain reads
  this value to see that a delegation transfer arrived).
- `log_store` of `health` is null on a node without a log store. Otherwise it names the bucket
  and its region, the end of the credentials the node holds (`credentials_expires_ms`, 0 when it
  holds none) and the number of accounts that have a pending entry (`pending`).
- `log_store` of `config` names the log store of the node (protocol.md 4.1 gives the form of the
  two names. Another form is `invalid_request`). The key is optional. A node takes a log store
  once: a later configuration that names the same log store, or none, leaves it in place, and a
  configuration that names another one is `invalid_request` and changes nothing, also not the
  client values. From the call that named it, the binding of the attestation responses of the
  node carries it as `log`.
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
-> {"reply":{"body":"...","sig":"..."},"entry":{"body":"...","sig":"..."}|null,"grant":{"state":"active","key_id":"...","custody":"enclave","not_after_ms":0}}
```

The processing is that of protocol.md 5.3 and 5.4. A command that fails is answered with 200 as
well, and `ok` of `reply` is false (the app receives a signed failure). That includes a grant
that the node refuses with `log_store_unavailable`: before the challenge is used when the node
cannot write to its log store, and after the entry `grant_accepted` was created when the store
did not confirm it (`entry` of the response is null, and the entry is fetched with 5.10). The responses other than
200 are a violation of the form of the call itself (`invalid_request`), `closing`, and a failure
of the platform (`internal`). `grant` is the plaintext copy that the caller (the backend) reads:
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
      -> {"record":{...},"public":{...},"statement":{"body":"...","sig":"..."},"entry":{"body":"...","sig":"..."}}
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
   call fails with `response_withheld`, and no record, no public field and no entry leaves.
5. The node creates the entry `connection_created` and writes it to the log store. After the
   store confirmed it, the node returns the record, the entry, the statement `oauth_complete` and
   the public fields (6.4). When the store does not confirm the entry, the call fails with
   `log_store_unavailable`: the record is dropped inside the node, and the pending authorization
   was used, so the connection is started again. A node that cannot write to its log store (it
   has none, or no credentials within their time) ends the call before step 1: the pending
   authorization stays and the code is not spent, so the same call passes once the node can
   write.

merge moves the `refresh_token` of the old record when, in a reconnect, the new response has none
(protocol.md 8.3). The node opens both records (both are of kind `oauth`, otherwise `not_allowed`).
Their providers must be equal (otherwise `invalid_request`). The node returns the new record,
encrypted again under the `id` of the new record, and its public fields. merge creates no entry.
It works without the operator configuration and is not stopped by the limit of `unacked`
(section 4).

### 5.7 `POST /v1/refresh`, `POST /v1/revoke-token`

```json
refresh      {"user_id":"...","record":{...},"context":"..."} -> {"record":{...},"public":{...},"entry":{...}}
revoke-token {"user_id":"...","record":{...},"context":"..."} -> {"revoked":true,"entry":{...}}
```

- Both calls take a record of kind `oauth` or `oauth_imported` (otherwise `not_allowed`).
- refresh: when the token place of the plaintext of the record has no `refresh_token`, the call
  fails with `record_invalid`, without an entry and without a provider call (on this code the
  backend marks the connection as one that needs a new authorization). When there is one, the node
  creates the entry `credential_refreshed`, writes it to the log store, calls the token address
  with `grant_type=refresh_token` after the store confirmed the entry, and creates the new record
  of the same `id` and the same kind by the merge rules (protocol.md 8.3). When the provider refuses, the call fails with `refresh_failed`,
  and the body carries `provider_status` and `provider_error`.
- `provider_error` is a word of a closed vocabulary, `other`, or the empty string. The node reads
  the error string of the provider response: when the response is a JSON object, a string `error`
  is that string. For an object `error` it is the string `code` of that object (else its string
  `message`). Without an `error` it is the top-level string `code`. The node compares that string
  with the list of rule E5 of egress-policy.md. What leaves is the element of the list that equals
  the string, the empty string when the response has no such string, and `other` otherwise. Each
  of them is a constant of the source: no byte of a refused response leaves the node. The backend
  decides from that word whether the connection needs a new authorization.
- The kept response of a refresh: a node keeps the response of a successful `refresh` for 3,600
  seconds, per account, the 16 most recent ones, under the SHA-256 of the `ct` of the record that
  was sent. A repeated `refresh` of the same record by the same account passes the common front
  and the opening of the record, and then returns the kept response as it is: the node calls no
  provider and creates no entry. A revoke command, the expiry of the grant, and a grant of another
  signing key drop the kept responses. A response is not kept when the grant under which the
  refresh ran is no longer in force at the end of the call. The reason for keeping a response: a
  provider that rotates refresh tokens invalidates the old token at the first call, so a response
  that never reached the caller would end the connection.
- revoke-token: the node creates the entry `connection_removed` and writes it to the log store.
  After the store confirmed it, the node calls the revocation address, when the definition has `revoke` and the plaintext of the record has a
  token (`token` = the refresh token when there is one, else the access token, with its
  `token_type_hint`. The time limit is 5 seconds). `provider_revoke` of the entry says whether the
  node makes that call (protocol.md 7.2), and `revoked` of the response is the outcome of the
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
response meta: {"status":200,"headers":[["name","value"],...],"entry":{"body":"...","sig":"..."}|null}
```

The payload of the request is the body to send to the provider. The payload of the response is the
body that the provider returned, as the provider sent it: the node asks for the encoding
`identity`, decodes nothing, and does not return a body of another encoding (step 10). The order
of the processing:

0. The frame: meta is a JSON object of at most 1 MiB (a longer meta, and a meta that is no object,
   is `invalid_request`). A payload above 64 MiB is `too_large`. A `timeout_ms` that is not an
   integer from 1,000 to 120,000 is `invalid_request` (when it is omitted, it is 30,000).
1. The common front. The kind of the record is `oauth` or `oauth_imported` (any other kind is
   `not_allowed`).
2. The address check (section 7). A violation is `not_allowed`.
3. The method is one of `GET`, `POST`, `PUT`, `PATCH`, `DELETE` (any other is `not_allowed`).
4. The header check: a name holds token characters only, and a value holds no control character
   (CR and LF included). A violation is `invalid_request`. A value can hold characters outside
   ASCII and is sent as UTF-8. A call with a header named `x-http-method-override`,
   `x-http-method` or `x-method-override` (ASCII letters compared without regard to case) is
   refused with `not_allowed`: such a header asks a provider to treat the request as one of
   another method than the method the request is sent with, which is the method the entry of
   step 6 names. The node refuses the call. It does not drop the header and send the rest. The
   node drops the names below and the name that equals `inject.header` of the definition:
   `authorization`, `proxy-authorization`, `cookie`, `host`, `content-length`,
   `transfer-encoding`, `connection`, `keep-alive`, `upgrade`, `te`, `trailer`, `expect`,
   `accept-encoding`.
5. The merge decision (protocol.md 7.2): a GET request without a body shares the entry of an
   identical one of the last 300 seconds. In case of a merge the call continues at step 8
   without an entry of its own, once the log store confirmed the entry it shares: when that
   entry is a pending entry, the call writes it again, and it fails with `log_store_unavailable`
   when the store does not confirm it. A request with a body is never merged.
6. The node creates the entry `provider_request` and raises the end of the chain. The entry
   names the request that step 8 sends: its method, its host, its whole path and its whole
   query, and the size and the SHA-256 of its body. The node writes the entry to the log store
   and continues after the store confirmed it. Otherwise the call fails with
   `log_store_unavailable` and no request is sent.
7. (Stage 2) The node obtains the witness signatures.
8. The node assembles the request and sends it: `Host`, then `Content-Length` when there is a body
   or the method is `POST`, `PUT` or `PATCH`, then the credential header made by the injection
   rule of the definition, then `Accept-Encoding: identity`, then the headers of the caller, then
   `Connection: close` (one request per provider connection). The node follows no redirect (a 3xx
   response is returned as it is). A response with `Transfer-Encoding: chunked` is returned
   decoded. The node sends no `TE` header, and a response under any other transfer coding fails
   the check of step 10. The hop-by-hop headers of the response (`connection`, `keep-alive`,
   `proxy-authenticate`, `proxy-authorization`, `te`, `trailer`, `transfer-encoding`, `upgrade`,
   and the names that its `Connection` header lists), `Set-Cookie` and `Set-Cookie2` are left out.
9. The time limit is `timeout_ms` (`timeout`). A transport failure is `provider_unreachable`, and
   a response body above 64 MiB is `too_large`.
10. The response check (rule E4 of egress-policy.md, `enclave/src/provider_response.rs`). A
    response with a `Content-Encoding` other than `identity`, or with a transfer coding other than
    `chunked`, fails the check: the node does not hand on a body it cannot search. A response
    fails the check when a header name, a header value or the body holds the injected credential
    (the token without the prefix of the definition). Each of the three is read as it was
    received and with its percent escapes decoded (up to three times, for a value that was
    encoded more than once), and each reading is searched for the credential as it is, in base64
    or base64url (each of the three byte alignments, without padding) and in hexadecimal (lower
    or upper case). A form shorter than 8 bytes is not searched for. A failed check is
    `response_withheld`: no part of the response leaves. The entry `provider_request` is already
    on the chain, because the request went to the provider.

The value of the credential header: `inject.prefix` followed by the value at the first path of
`inject.paths` that holds a non-empty string in the token object. When there is no such value, the
call fails with `record_invalid`.

The node does not judge the expiry of a token and does not refresh. The response of the provider
(a 401 and the `ok: false` of slack included) goes back as it is, after the check of step 10.
Refreshing (`refresh`) and calling again are the work of the backend.

### 5.9 `POST /v1/release`

```json
{"user_id":"...","record":{...},"field":"password|totp|card_number|card_cvc","origin":"https://host","context":"..."}
-> {"value":"...","entry":{...}}
```

| Record kind | Allowed field | The value that is returned | Entry |
| --- | --- | --- | --- |
| `vault_password` | `password` | `value` of the plaintext | `secret_released` |
| `vault_totp` | `totp` | The 6-digit code computed from the seed of the plaintext (RFC 6238, node time). The seed does not leave | `totp_issued` |
| `vault_card` | `card_number`, `card_cvc` | `number` or `cvc` of the plaintext | `secret_released` |

Any other pair of kind and field is `not_allowed`, and so is a record of kind `oauth` or
`oauth_imported`: no call hands out the plaintext of a token. A plaintext without the field, and a
seed that is not base32, are `record_invalid`. The entry is on the chain, and the log store
confirmed it, before the value leaves the node.

`origin` is an origin string `https://host` or `https://host:port` of at most 512 bytes (the node
checks the form only). Whether that origin is the site of the vault item is decided by the backend,
and the node writes the value it received into the entry. The call works without the operator
configuration.

### 5.10 `POST /v1/log/entries`, `POST /v1/log/ack`

```json
entries {"user_id":"...","after_seq":0} -> {"entries":[{"body":"...","sig":"..."}],"head":{"seq":0,"hash":"..."}}
ack     {"user_id":"...","seq":0}       -> {"unacked":0}
```

- A node keeps an entry it created in `unacked` until it receives the storage acknowledgement
  (`ack`). `ack` removes the entries with a `seq` up to the given one. `entries` returns the
  entries of `unacked` with a `seq` above `after_seq`.
- The two calls do not look at the log store. `entries` returns an entry whether the log store
  confirmed it or not, and `ack` does not end a pending entry: the node keeps a pending entry
  until the store confirmed it (5.14).
- The backend calls `ack` after it stored the entries in its database. An entry whose response was
  lost is fetched again with `entries`.
- The use of a credential of an account whose `unacked` reached 64 is refused with `log_backlog`:
  a caller that uses credentials without storing the entries stops after 64 uses per account (and
  before that, the verification of the app shows the omission).

### 5.11 `POST /v1/close`, `POST /v1/close/heads`

```json
close       {} -> {"accounts":0}
close/heads {"cursor":"","limit":1000} -> {"heads":[{"body":"...","sig":"..."}],"next":""}
```

`close` raises `closing`: from then on, the calls that use a credential and the commands are
refused with `closing`, and a call that was in progress runs to its end. `accounts` of `close` is
the number of accounts that have a chain. `close/heads` returns the `final` head of every account
that has a chain, in the lexical order of `user_id` (`cursor` is the last `user_id` of the page
before, and an empty `next` ends the listing). `close/heads` before `close` is `invalid_request`.
A node creates the `final` head of an account once, and a repeated call returns the same head.
`limit` is at least 1, and a value above 1,000 is read as 1,000.
The entries that are left in `unacked` are fetched with `log/entries` first. The host program
starts this sequence when it receives the termination signal (section 9).

### 5.12 `POST /v1/seal`, `POST /v1/open`

The calls `POST /v1/seal` and `POST /v1/open` are not part of the call surface. A node answers
them with 404 `invalid_request`, like every path that is not defined. No call takes a credential
in the clear, and no call hands the plaintext of a token out.

### 5.13 `POST /v1/peer/export`, `POST /v1/peer/import`

```json
export {"peer":{the attestation response of the receiving node},"after":"","limit":1000,
        "endorsement":{"statement":"...","entry":{"body":"...","integrated_time":0,"log_index":0,"log_id":"...","signed_entry_timestamp":"..."}}}
  -> {"envelope":{...}|null,"entries":[{"body":"...","sig":"..."}],"next":""}
import {"peer":{the attestation response of the giving node},"envelope":{...}}
  -> {"imported":0,"entries":[{"body":"...","sig":"..."}]}
```

The rules are those of protocol.md 10.1 and 10.3. What this document adds:

- `peer` is the response of `POST /v1/attestation` of that peer, as it is (the nonce is a value
  that the caller chose, and the node does not look at it).
- `limit` of export is 1 to 1,000 (a larger value is read as 1,000). `after` is the `next` of the
  page before (the empty string for the first page). When a page has no grant to hand over,
  `envelope` is null and `entries` is an empty list. An empty `next` ends the listing.
- `entries` of export holds one entry for every grant of the page that the node hands to this
  peer for the first time (protocol.md 10.1). A grant that the node handed to the same peer
  before is in the envelope again and has no entry: a repeated call returns the envelope and an
  empty `entries`. An account whose grant was handed to 64 other peers is not selected. It is
  not in the envelope, it has no entry, and it does not count toward `limit`.
- export works in the state `closing` too (the orderly shutdown hands the delegations over before
  the node ends). An account whose final head is already signed is skipped. So the order of the
  orderly shutdown is `close`, `peer/export`, `log/entries`, `close/heads`. import is refused with
  `closing` in the state `closing`, and when the shutdown starts during an import, the call
  answers with what it took until then.
- The pages of export: the node goes through the accounts in the order of `user_id` until `limit`
  grants are selected, and `next` is the last `user_id` it looked at (the last page can be empty).
  An omitted `limit` is 1,000 and an omitted `after` is the empty string. `imported` of import is
  the number of grants that this call put in place (it equals the number of entries). Within the
  1 MiB limit of a JSON body, a page of 1,000 grants fits when a `user_id` is at most about 350
  bytes long (a `user_id` of the length of a UUID fits).
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
  `log_store_unavailable` and the response carries no envelope and no entry. The entries the call
  created are on their chains and are fetched with 5.10. The next call for the same peer creates
  no entry for these accounts, so its `entries` are those of the grants it hands over for the
  first time only.
- import and the log store: the entries of an import are pending entries. The call does not write
  to the log store and does not need credentials for it.
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
| Connection | The connection of every outbound call (`Egress::open`): the byte pipe of the platform to port 443 of `{bucket}.s3.{region}.amazonaws.com`, TLS that ends inside the node, the trust roots of `webpki-roots`, the certificate verified at node time. One request per connection (`Connection: close`). The node does not keep a connection to the log store open between two writes |
| Request | `PUT` of the object of protocol.md 7.6, signed with AWS Signature Version 4 (the service `s3`, the region of the bucket). Every header of the request except `Content-Length` and `Connection` is signed. The times of `x-amz-date` and of the retention are node time |
| Confirmation | The status 200. The node reads nothing else of the response. It follows no redirect, and it does not repeat a write inside one call |
| Time limit | 5 seconds for one write: the connection, the TLS handshake and the exchange |
| Writes of one call | The entries the act of the call waits for, and the pending entries of the same accounts. At most 32 writes run at the same time, the entries an act waits for first. After a round in which a write was not confirmed, the call starts no further write |
| The limit of pending entries | An account whose pending entries reached 64 gets no further entry from a call that uses a credential (step 3 of the common front): the call writes the pending entries again, goes on when fewer than 64 are left, and otherwise ends with `log_store_unavailable` without an entry. A command and a delegation transfer are not stopped by this limit |
| Platform | A node of platform `nitro` requires a log store (protocol.md 7.6). A node of platform `local` keeps account of the entries it creates from the call of `config` that named its log store: the entries it created before are not written |

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
| `inject` | The credential header that `forward` sets: `header: prefix + token[the first path of paths that exists]`. A path is object keys joined by `.` |
| `public`, `id_token_claims` | 6.4 |
| `api` | Section 7. A rule is `{"host", "prefixes", "exact"}`, the optional boolean `encoded_slash` (false when it is absent) and the optional list `denied` (empty when it is absent) |

The definitions are validated when the node loads them, and a node with an invalid definition does
not start (`Definition::validate` in `enclave/src/providers/mod.rs`). A key that the format does
not define is refused. The authorization address, the token address and the revocation address
are plain addresses `https://host/path`: a lower-case DNS name, no user information, no port, no
query, no fragment. The token address and the revocation address must not be reachable through
the `api` list of the same definition (section 7). An `allowed` parameter must not be a parameter
that the node sets itself (`response_type`, `client_id`, `redirect_uri`, `state`,
`code_challenge`, `code_challenge_method`, a `fixed` name, `key_param`). The rules for `public`
and `id_token_claims` are in 6.4, the rules for `api` in section 7.

### 6.2 The values of the definitions

| | google_workspace | microsoft | slack | notion | x | link | granola | mercury |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| client | static | static | static | static | static | static | dynamic | dynamic |
| authorize url | `https://accounts.google.com/o/oauth2/v2/auth` | `https://login.microsoftonline.com/common/oauth2/v2.0/authorize` | `https://slack.com/oauth/v2/authorize` | `https://api.notion.com/v1/oauth/authorize` | `https://x.com/i/oauth2/authorize` | `https://login.link.com/auth` | `https://mcp-auth.granola.ai/oauth2/authorize` | `https://mcp.mercury.com/authorize` |
| authorize fixed | None | None | None | `owner=user` | None | None | `resource=https://mcp.granola.ai/mcp` | `resource=https://mcp.mercury.com/mcp` |
| authorize allowed | `scope`, `access_type`, `prompt`, `include_granted_scopes`, `login_hint` | `scope`, `prompt`, `login_hint` | `user_scope` | None | `scope` | `scope` | `scope` | `scope` |
| key_param | None | None | None | None | None | `key` | None | None |
| scope_param, delimiter | `scope`, space | `scope`, space | `user_scope`, `,` | None | `scope`, space | `scope`, space | `scope`, space | `scope`, space |
| pkce | S256 | S256 | none | none | S256 | S256 | S256 | S256 |
| token url | `https://oauth2.googleapis.com/token` | `https://login.microsoftonline.com/common/oauth2/v2.0/token` | `https://slack.com/api/oauth.v2.access` | `https://api.notion.com/v1/oauth/token` | `https://api.x.com/2/oauth2/token` | `https://login.link.com/auth/token` | `https://mcp-auth.granola.ai/oauth2/token` | `https://mcp.mercury.com/token` |
| token client_auth, body | body, form | body, form | body, form | basic, json | basic, form | body, form | none, form | none, form |
| token headers | None | None | None | `Notion-Version: 2025-09-03` | None | None | None | None |
| token bearer | None | None | None | None | None | `publishable_key` | None | None |
| token fixed | None | None | None | None | None | None | `resource=https://mcp.granola.ai/mcp` | `resource=https://mcp.mercury.com/mcp` |
| ok_field | None | None | `ok` | None | None | None | None | None |
| token_container | None | None | `authed_user` | None | None | None | None | None |
| revoke | `https://oauth2.googleapis.com/revoke`, client_auth none | None | None | None | `https://api.x.com/2/oauth2/revoke`, client_auth basic | `https://login.link.com/auth/revoke`, client_auth body, bearer `publishable_key` | None | None |
| inject paths | `access_token` | `access_token` | `authed_user.access_token`, `access_token` | `access_token` | `access_token` | `access_token` | `access_token` | `access_token` |

Every definition injects the header `Authorization` with the prefix `Bearer `.

The public fields of the definitions (path: type, and the limit of a string in bytes):

| Provider | `public` | `id_token_claims` |
| --- | --- | --- |
| google_workspace | `scope`: string 8192. `expires_in`: integer. `token_type`: string 32 | `sub`: string 255. `email`: string 320. `email_verified`: boolean. `hd`: string 255. `name`: string 256. `picture`: string 2048 |
| microsoft | `scope`: string 8192. `expires_in`: integer. `ext_expires_in`: integer. `token_type`: string 32 | `tid`: string 64. `oid`: string 64. `preferred_username`: string 320 |
| slack | `team.id`: string 32. `team.name`: string 256. `enterprise.id`: string 32. `enterprise.name`: string 256. `app_id`: string 32. `is_enterprise_install`: boolean. `authed_user.id`: string 32. `authed_user.scope`: string 8192. `authed_user.expires_in`: integer. `authed_user.token_type`: string 32 | None |
| notion | `workspace_id`: string 64. `workspace_name`: string 256. `workspace_icon`: string 2048. `bot_id`: string 64. `duplicated_template_id`: string 64. `owner.type`: string 32. `owner.user.id`: string 64. `owner.user.name`: string 256. `owner.user.avatar_url`: string 2048. `owner.user.type`: string 32. `owner.user.person.email`: string 320 | None |
| x, link, granola, mercury | `scope`: string 8192. `expires_in`: integer. `token_type`: string 32 | None |

No definition has a list of allowed scopes (`scopes`): the consent page of the provider shows the
requested scopes to the user, and the `api` list bounds the addresses that a token can reach.

For a provider with `pkce` `S256`, the authorization code that passes through the callback of the
operator is of no use outside the node, because the verifier never leaves the node. This rests on
the token address of the provider: it must require the `code_verifier` of an authorization that
carried a `code_challenge` (RFC 7636 section 4.6). That is part of the contract of a provider that
section 1 of egress-policy.md assumes. The providers with `pkce` `none` (slack, notion) are a
stated limit (section 5 of egress-policy.md).

### 6.3 The call of the token address

- The body of an exchange: `grant_type=authorization_code`, `code`, `redirect_uri`,
  (`code_verifier`), the client authentication values, `token.fixed`.
- The body of a refresh: `grant_type=refresh_token`, `refresh_token`, the client authentication
  values, `token.fixed`. When `client` is `dynamic`, `client_id` is the value of the plaintext of
  the record.
- The time limit is 15 seconds. The node reads at most 1 MiB of the response. A success is: the
  status is 200, the body is a JSON object, the `ok_field` check passes, and the token place holds
  an `access_token` string (reading the token place: protocol.md 8.3).
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
  `time_ms` values of the entries of one chain do not decrease with `seq` (the one place that
  creates an entry never dates it before the entry in front of it), and an expiry that has passed
  does not come back into force.
- Randomness: the kernel random source.
- Concurrency: at most 64 `forward` calls run at the same time (a semaphore). The bodies of a
  request and of a response are held in memory, and each of them is `too_large` above 64 MiB. A
  call that would raise the sum of the bodies in memory above 2 GiB waits until there is room.
- The size of the enclave: 2 vCPUs and 4,096 MiB of memory (constants of the host program).
- Output: the node writes nothing to the standard output (a production enclave has no console).
  Diagnostic values leave through `health` and through the failure codes of the calls only. A
  failure message is a fixed string of the source: it carries no credential, no key, no body and
  no query string of an address. The one other output is a fixed line on the standard error when
  the start of the node fails (section 2).

The limits, as the source states them:

| Limit | Value |
| --- | --- |
| JSON body of a call | 1 MiB |
| `meta` of a `forward` frame | 1 MiB |
| Body of a provider request and of a provider response (`forward`) | 64 MiB each |
| Sum of the bodies in memory | 2 GiB |
| Concurrent `forward` calls | 64 |
| `timeout_ms` of `forward` | 1,000 to 120,000, default 30,000 |
| Address of `forward` | 8,192 bytes |
| Response of a token address | 1 MiB, time limit 15 seconds |
| Call of a revocation address | Time limit 5 seconds |
| Authorization code | 4,096 bytes |
| Value of an authorization parameter | 1,024 characters |
| `client_id` of a dynamic client | 256 characters |
| `redirect_uri` of the operator configuration | 2,048 bytes |
| `origin` of `release` | 512 bytes |
| Challenges a node keeps | 100,000 |
| Pending authorizations a node keeps | 100,000 |
| One write to the log store | Time limit 5 seconds |
| Writes of one call to the log store at the same time | 32 |
| Pending entries of an account at which a call that uses a credential creates no further entry | 64 |
| `access_key_id`, `secret_access_key`, `session_token` of the log store | 128 characters, 256 bytes, 8,192 bytes |

The constants of the protocol (the lifetime of a grant, of a challenge and of a pending
authorization, the merge window, the kept `refresh` responses, the page of a transfer, the nodes
that one grant is handed to, the limit of `unacked`, the retention of an object of the log store,
the longest `context`) are in protocol.md section 12.

## 9. The host program (`credential-enclave-host`)

The host program runs inside the parent pod of the enclave. It is an untrusted component: nothing
that a node guarantees depends on it. It is kept in this repository next to the node program. It
takes no argument, and it reads its configuration from environment variables.

| Function | What it does |
| --- | --- |
| Start | `nitro-cli run-enclave --eif-path /opt/credential-enclave/enclave.eif --cpu-count 2 --memory 4096 --enclave-cid 16`. When the start fails, the host program prints the ends of the `nitro-cli` log files and ends with a status that is not 0 |
| Inbound relay | For every connection on TCP `0.0.0.0:8080` it opens a connection to vsock `16:8080` and moves the bytes in both directions. It does not read the bytes: the call surface of the node ends inside the enclave |
| Egress relay | It listens on vsock port 8443. It reads the first line `CONNECT {host}:{port}\n`. When the host is on the allow list and the port is 443, it connects by TCP, answers `OK\n` and moves the bytes. Otherwise it sends `ERR\n` and closes. The allow list is the hosts of section 7, the hosts of the token addresses and the revocation addresses of 6.2 (the host program is built from the same definitions file), and the host of the log store, `{bucket}.s3.{region}.amazonaws.com`, when the two variables of the next row name one. TLS ends inside the node, so the relay sees ciphertext only. This list is a second line: the node itself sends a credential only to the addresses of its definitions, and log entries only to its log store |
| Operator configuration | It reads the values of every provider from environment variables and calls `POST /v1/config` once the `health` call of the node answers. The variables: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `OUTLOOK_CLIENT_ID`, `OUTLOOK_CLIENT_SECRET`, `SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET`, `NOTION_CLIENT_ID`, `NOTION_CLIENT_SECRET`, `X_CLIENT_ID`, `X_CLIENT_SECRET`, `LINK_CLIENT_ID`, `LINK_CLIENT_SECRET`, `STRIPE_PUBLISHABLE_KEY`, and `CHARACTER_API_BASE_URL` (the front of the callback address `{value}/api/integrations/{provider}/oauth/callback`). The configuration names every provider of the definitions: `redirect_uri` is always set, and a value without a variable is the empty string. `CREDENTIAL_ENCLAVE_LOG_BUCKET` and `CREDENTIAL_ENCLAVE_LOG_REGION` name the log store: when both are set and have the forms of protocol.md 4.1, the configuration carries them as `log_store`. When one is missing or has another form, the configuration carries no `log_store` and one line of the log says why. Without `CHARACTER_API_BASE_URL` no configuration is sent. A configuration that the node refuses is not sent again. The host program does not send the credentials for the log store: the backend sends them (5.14) |
| Status | TCP 9091: `GET /healthz` (200 when the round trip of the `health` call of the node succeeds within 2 seconds, 503 otherwise) and `GET /metrics` (the Prometheus text format). Four gauges: `credential_enclave_up` (1 when the `health` round trip succeeds, 0 when it fails), `credential_enclave_configured` (1 when `configured` of `health` is true), `credential_enclave_accounts` (`accounts` of `health`), `credential_enclave_started_timestamp_seconds` (`started_ms` of `health` in seconds) |
| Sending the operator configuration again | Does not happen. The configuration is sent once at the start. To change a value, the pod is replaced |
| Shutdown | On SIGTERM (or SIGINT) the host program calls `POST {CREDENTIAL_ENCLAVE_DRAIN_URL}` (the shutdown collection route of the backend): the body `{"pod": "<the value of CREDENTIAL_ENCLAVE_POD_NAME>"}`, the headers `Authorization: Bearer {CREDENTIAL_ENCLAVE_DRAIN_TOKEN}` and `Content-Type: application/json`. Inside that request the backend makes the calls of the orderly shutdown to the node (5.11, 5.13), through the inbound relay. The host program waits for the response (at most 100 seconds), then calls `nitro-cli terminate-enclave --all` and ends. When one of the three variables (`CREDENTIAL_ENCLAVE_DRAIN_URL`, `CREDENTIAL_ENCLAVE_DRAIN_TOKEN`, `CREDENTIAL_ENCLAVE_POD_NAME`) is missing, it ends the enclave without the collection |
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
| `check.yml` | A push to any branch, a pull request | `check`: `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`, the vector check (`cargo run --locked -p credential-enclave-protocol --bin vectors -- --check`: the committed file equals the output of the generator), `scripts/secret-access.sh --check` (rule E2 of egress-policy.md). `measure` (on a push): `build/build.sh eif`, and `out/measurements.json` as the artifact `measurements` |
| `release.yml` | The push of a `v*` tag | `check`: the checks above and `cargo audit` (no dependency of `Cargo.lock` has a security advisory). `build-a`, `build-b`: `build/build.sh eif` each, and the release of the build is the pushed tag. `compare`: the two `measurements.json` are equal, otherwise there is no release. `publish`: the host image around the enclave image file of `build-a` to `ghcr.io/pickle-com/credential-enclave/host:{tag}`, the GitHub release with `enclave.eif` and `measurements.json`, two attestations of the enclave image file (its build provenance, and the release statement of protocol.md section 9, whose predicate is `measurements.json`), and their bundles on the GitHub release (`provenance.sigstore.json`, `release-statement.sigstore.json`) |

- The runner is `ubuntu-24.04`, and every action is fixed by its commit SHA. The permissions of
  `publish` are `id-token: write`, `contents: write`, `attestations: write` and
  `packages: write`.
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
| Log | `enclave/src/tests/log.rs` | The entry is on the chain before the provider is called (the provider stand-in looks at the head at the time of the call), merging, the limit of `unacked`, `ack`, the final heads of `close`, the times of the entries of a chain |
| Log store | `enclave/src/tests/log_store.rs`, the unit tests of `enclave/src/log_store.rs` | Against a stand-in for Amazon S3 on the TLS server of the provider stand-in: the write of an entry arrives before the request to the provider, and with the key, the body, the headers and a signature that the test computes again from the request. A write the store does not confirm (a status other than 200, a 412 included, no connection, no answer within the time limit) stops the act of every call. A pending entry is written again with the next write of its account, and a request that shares an entry waits for it. The signed refusal of a grant, a revoke that erases the key whatever the store answers, the failure and the repetition of `peer/export`, the refusal of a peer of another log store, a node of the nitro platform without a log store or credentials, the limit of pending entries, calls that end before their write, calls that run at the same time. The signature against the examples of the AWS documentation |
| Address check | The unit tests of `enclave/src/providers/mod.rs` | The refusals of section 7 (another host, a path outside the lists, a denied path in its spellings, dot segments, dot segments in front of a path parameter, encoded separators and separators that are encoded twice, a port, user information), and the validation of the definitions, including the rules for public fields |
| OAuth | `enclave/src/tests/oauth.rs`, the unit tests of `enclave/src/oauth.rs` | Against the provider stand-in: exchange, refresh, the merge of a reconnect, the nested token place of slack and its `ok: false`, the public fields and the containment check, the closed vocabulary of `provider_error`, the kept response of a repeated refresh, a record of kind `oauth_imported` |
| forward | `enclave/src/tests/forward.rs`, the unit tests of `enclave/src/provider_response.rs` and `enclave/src/egress.rs` | Header removal, the refusal of a header that overrides the method and of the batch address of Microsoft Graph, the injected credential, the entry of a GET request with a body, the whole path and the whole query in the entry of the longest address, redirects that are not followed, chunked responses, the body limit, the time limit, a response that reflects the credential (as it is, under percent escapes of up to three layers, in base64 and in hexadecimal) |
| Delegation transfer | `enclave/src/tests/peer.rs` | The round trip of export and import between two nodes of the local platform, paging, the exclusion of expired grants and of accounts that revoked, a grant of another `sign_pk` is not replaced, the refusal of a changed envelope and of an envelope for another node, the entries `grant_transferred_out` and `grant_transferred_in`, a repeated export to the same peer without a new entry, the limit of 64 peers per grant, an export with an endorsement that does not hold (it hands nothing over and leaves no entry, also for a peer the call without an endorsement accepts) |
| Call surface | `enclave/src/tests/surface.rs` | `health`, the operator configuration, attestation and its challenge statement, the failure bodies, HTTP/1.1 over a real connection, and that the calls of the router are the calls of the table in section 4 of egress-policy.md |
| Egress policy | `enclave/src/tests/canary.rs` | The canary test of egress-policy.md: every secret carries a distinct marker, the provider stand-in breaks its contract on purpose (reflected credentials, tokens in public fields, content and transfer codings, cookies, redirects), every call of the router is made in a success and in a failure, no marker appears in a response in any of the searched encodings, and a credential reaches only the addresses of its own provider. The one exception is the requested field of a successful `release`. Both nodes of the walk have a log store: no write to it carries a secret of the account, and of the credentials for it the session token reaches the log store alone and the secret access key no request |
| Host program | The unit tests of `host/src/` | The relays, the allow list of the egress relay with the host of the log store, the operator configuration with the log store of the environment, the status surface and the shutdown call, against a stand-in for the node over in-memory pipes |
| Verification tool | The unit tests of `verify/src/`, `verify/tests/offline.rs`, with the files of `verify/tests/fixtures/` | The checks on a stored attestation document of a node of release v1.0.0 against the `measurements.json` of that release, the refusals, the report with the log store of a binding, and the exit status of the built tool |


## Mail call surface

GET /v1/health adds `mail_providers: ["naver_mail"]`. An absent field on an older release means
no mail support. POST /v1/mail/verify, /v1/mail/read and /v1/mail/submit use the forward binary
frame. Meta is `{user_id, record, context, request}`; only submit has payload bytes (ASCII SMTP
MIME with CRLF). The response is the forward frame with `status`, `headers`, `entry` and body.

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

Mail protocol input is bounded at the stream: verify,
folder listing and search (including headers) accept at most 4 MiB of protocol input per
connection. This is a byte-read bound; the API separately reserves the SDK parser maximum
of 512 MiB because a server literal declaration can allocate ahead of the read. Reading one raw message allows the configured body limit plus 1 MiB for protocol
overhead, while the returned message itself still has the body limit. A search whose UID set
or headers exceeds this bound must be narrowed. Unknown IMAP login refusals remain provider
failures; only AUTHENTICATIONFAILED classifies the application password as refused.

FROM and SUBJECT search values use synchronizing UTF-8 literals with byte lengths, waiting
for the server continuation before each literal (RFC 3501 sections 4.3 and 6.4.4). This avoids
assuming that an IMAP server accepts non-ASCII quoted strings or supports LITERAL+.
