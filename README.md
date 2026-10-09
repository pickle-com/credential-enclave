# credential-enclave

This repository is the source of the program that holds and uses the credentials of Pickle
accounts inside an AWS Nitro Enclave. It contains four things:

| Part | What it is |
| --- | --- |
| The node program (`enclave/`) | The process inside the enclave. It holds the user key of an account for a limited time and, with that key, issues, opens, uses and records credentials |
| The host program (`host/`) | The process in the parent pod. It starts the enclave and relays bytes to and from it. Nothing the node guarantees depends on it |
| The protocol crate (`protocol/`) | The formats that the node and the app of an account share: keys, messages, records, the log, attestation documents |
| The verification tool (`verify/`) | `credential-enclave-verify`: it fetches the attestation of the running nodes and compares it with the measurements of a build of this source |

A reader can build this source, compare the measurements of the build with what the running nodes
attest, and read here what a node does with a credential.

## Structure

An account is one user. The app is the iOS app of that account. The operator is the company that
runs the service, and the operator domain is everything it runs outside a node: the backend, its
storage, the host program, the network. A provider is a service whose credentials a node holds
(Google, Microsoft, Slack, Notion, X, Link, Granola, Mercury, NAVER Mail).

```text
device of the account (the app)
  master key (created on the device, kept in the iCloud Keychain)
   ├─ account signing key      signs the commands grant and revoke
   ├─ log decryption key       opens the log entries of the account
   └─ user key                 encrypts and opens the records of the account
        │
        │  1. the app verifies the attestation of a node: its measurements, its two public keys
        │  2. grant: the user key, sealed to the sealing key of that node, for at most 30 days
        ▼
operator domain (not trusted by the node)        node (AWS Nitro Enclave, memory only)
  backend       calls the node, carries the        signing key, sealing key (created at boot)
                sealed messages of the app         per account: the user key until the grant
  storage       records (ciphertext under the        ends, and the end of the log chain
                user key), log entries (sealed     PKCE verifiers of pending authorizations
                to the log key), public fields     provider definitions (compiled in, measured)
  host program  starts the enclave, relays ◀──▶    calls: oauth/begin, oauth/complete, refresh,
                the calls and the TLS bytes          revoke-token, forward, release, ...
                                                       │  TLS that ends inside the node
                                                       ▼
                                   log store (Amazon S3, Object Lock)   providers
                                   1. the entry of an act               2. the act, after the
                                                                           store confirmed 1
```

| Value | Device of the account | Node | Operator domain |
| --- | --- | --- | --- |
| Master key, account signing key, log decryption key | Yes | Never | Never |
| User key | Derived from the master key | In memory, while a grant is in force | Never, for a node inside an enclave |
| Node signing key, node sealing key | No | In memory, for the life of the process | Never |
| OAuth token of a connection (record kind `oauth`) | Never | In memory, while a call uses it | Ciphertext only |
| Mail application password (record kind `app_password`) | When the user enters it, encrypted on-device | In memory, while a fixed IMAP/SMTP call uses it | Ciphertext only |
| Vault value (password, card number, CVC) | When the user enters it | In memory, while `release` runs | The ciphertext, and the value after `release` handed it out |
| TOTP seed | When the user enters it | In memory, while `release` computes a code | Ciphertext only. `release` hands out the 6-digit code |
| Log entry | Opens it with the log decryption key | Creates it, writes it to the log store before the act, keeps it until its storage is acknowledged | Stores it sealed. Cannot delete the copy in the log store for 365 days |

A node writes nothing to disk. A node that restarts has new keys and no user keys. It takes the
delegations from a living node of the same measurement and the same log store (`peer/export`,
`peer/import`), or from the apps the next time they run. A node of a later release takes them
from a living node of an earlier release with the same log store, when the earlier node verified
that the operator's release key signed the measurements of the later release and that the public
transparency log recorded the signature, and when the later release lists the earlier one as a
predecessor.

The log store is an Amazon S3 bucket with Object Lock. A node writes every log entry there
itself, over TLS that ends inside the node, with a retention in compliance mode of 365 days, and
performs the act the entry describes only after the store confirmed the entry. The binding of
the attestation of a node names the bucket, so a verifier of a node knows where its entries go.

The same program also runs as an ordinary process (platform `local`), for development. No
attestation verifies such a node. The protocol keeps the two apart by the custody of the user key:
the app derives one user key for nodes inside an enclave (custody `enclave`) and another one for
`local` nodes (custody `operator`), and it hands a node only the key of that node's custody.

## What the source guarantees

Each row holds for a node that runs this source inside a Nitro Enclave (see "How to verify").

| Guarantee | The mechanism in the source | Where to read it |
| --- | --- | --- |
| A stored credential is a ciphertext under the user key | A record is encrypted with ChaCha20-Poly1305 under a key derived from the user key. Its AAD binds the record id, the account, the key, the custody, the kind and the provider. The node writes nothing to disk, and a credential leaves it for storage as a record only | [protocol.md](docs/protocol.md) section 6, `protocol/src/record.rs` |
| The user key exists on the device of the account and in the memory of a node whose attestation the app verified, for at most 30 days per delegation. A node erases it when the delegation ends and when a revoke of the account reaches it, and a grant that was made before that revoke does not bring it back | The grant is sealed to the sealing key that the attestation document binds. A node shortens a grant to 30 days of its own clock, erases the user key when the grant ends or a revoke arrives, and hands user keys only to a node whose attestation it verified and whose measurement is one of two: its own, or the measurement of a later release whose statement the operator's release key signed and the public transparency log recorded. Such a transfer is received only by a release that lists the giving release as a predecessor. A node refuses a grant whose challenge it issued before a revoke of that account: whoever carries a sealed grant cannot keep it and deliver it after the revoke | protocol.md sections 3, 5, 10.1 and 10.3, `enclave/src/api/messages.rs`, `enclave/src/attest.rs`, `protocol/src/release.rs` |
| The OAuth token of a connection is issued to the node by the provider and used inside the node only. No call hands its plaintext out | The node creates the PKCE verifier and exchanges the authorization code itself, over TLS that ends inside it. `forward` puts the token into a request to an address of the compiled-in provider definitions. A secret is a type that cannot become a response, the functions that read a secret are a closed list, and `release` refuses a record that holds a token | [egress-policy.md](docs/egress-policy.md), `protocol/src/secret.rs`, `enclave/src/oauth.rs`, `egress/secret-access.tsv` |
| A use of a credential has a log entry that only the account can read. The entry is created before the use, and for a new connection before its record leaves the node. Identical GET requests of one record within 300 seconds share one entry. A missing or changed entry in the storage of the operator shows in the app's verification of the chain | `forward`, `refresh`, `revoke-token`, `release`, the commands grant and revoke, and `peer/export` create their entry before the act: before the node calls the provider, hands the value out, changes the delegation or seals the user key to a peer. `oauth/complete` receives the token from the provider first and creates the entry `connection_created` before the record leaves the node: no part of an accepted token response leaves before that entry exists, and when a later step fails, the tokens are dropped inside the node and nothing leaves. `oauth/merge` calls no provider and creates no entry. An entry is sealed to the log key of the account, signed by the node, and chained per node and account. The node signs the end of each chain (the head), and the app verifies the stored entries against it | protocol.md section 7, `protocol/src/log.rs`, `enclave/src/state.rs` |
| A use of a credential has an entry in the log store that nobody can delete for 365 days: not the operator, and not the root user of its AWS account. The entry is in the store before the use | A node writes each entry to its log store with `PUT`, over TLS that ends inside the node, with a retention in the compliance mode of S3 Object Lock until 365 days after the write. It calls the provider, hands the vault value out, hands the record of a new connection out, takes a user key or hands a grant to a peer only after the store answered that write with the status 200. It takes no other answer for a confirmation, also not the answer that an object of that key exists: the operator domain can write to the same bucket. The binding inside the attestation document names the bucket and its region, a node takes a log store once, and a node hands delegations only to a node of the same log store. A node inside an enclave refuses these acts while it has no log store or no credentials for it | protocol.md 7.6 and 4.1, enclave.md 5.14, `enclave/src/log_store.rs`, `enclave/src/tests/log_store.rs` |
| A vault value leaves through `release` only, one field at a time, after its log entry. A TOTP seed never leaves | The type of a vault value has one way out, `hand_out`, which takes the log entry of that release as an argument. For a TOTP record the value it holds is the code | [enclave.md](docs/enclave.md) 5.9, `enclave/src/vault.rs` |
| The code a node runs is this source, and anyone can check that with the measurements | The build is reproducible: one commit gives the same PCR0, PCR1 and PCR2 on every build. The attestation document of a node, signed under the AWS Nitro Enclaves root certificate, states the three values of the running enclave and binds the public keys of the node. A node does not start in a debug-mode enclave | enclave.md section 11, `build/build.sh`, `protocol/src/attestation.rs`, `verify/` |

A vault value is protected by the node up to `release`. `release` hands a password, a card number
or a CVC to the worker of the operator, which fills a form with it. From that moment the node no
longer protects the value: what the source shows is that it was stored as a ciphertext and that
every release has its log entry.

## What it does not guarantee

The first twelve rows are the limits that section 5 of egress-policy.md states.

| Limit | What it means |
| --- | --- |
| The contract of a provider | A token that a provider sends at a place the definition does not list, in another form, or a second credential an API derives from the token and returns, is not found by the checks of the node on provider responses |
| Consent outside the app | The OAuth application (client id and client secret) belongs to the operator. When a user consents on the authorization page outside the connect flow of the app, that authorization does not pass through a node and the rules of the node do not reach it. The app continues its connect flow only after it verified the signature and the 32-byte `sign_pk` of the node statement (protocol.md 8.2) |
| Providers without PKCE (`slack`, `notion`) | The authorization code passes through the callback of the operator domain, which also holds the client secret: the operator domain can exchange that code itself. With PKCE the verifier never leaves the node, so the code is of no use outside it |
| A token of kind `oauth_imported` | The operator domain held it before the device encrypted it. From then on the node keeps it like any token. What happened to it before is outside the rules of the node. A new connection of the account gives a record of kind `oauth` |
| APIs that open a lasting access, and signed addresses | An API call can open an access on the side of the provider that lasts (a watch, a forwarding rule, a share link, a signed upload address). An API can also return a credential that the provider derives from the token (for example an application password of Microsoft Graph, when the token carries administrator scopes). The guarantee ends with the log entry of that call |
| The width of the address lists | The `api` lists of the definitions are path prefixes. A credential can reach every address under them |
| `previous` of `oauth/merge` | Any record of kind `oauth` of the same account and provider is taken. The operator domain can choose to move the refresh token of one connection of a user into another connection of the same user and provider. That is a limit of integrity, not of confidentiality |
| The freshness of a record | A node keeps no state about records. The operator domain stores them and can present an older record of an account, for example the one from before a refresh. That decides which token is used. It does not let anyone read one |
| The honesty of the app | The app holds the master key and verifies the attestation. The app is not open source yet. Until it is, "the app is honest" is an assumption: an app that is not the published one can leak the master key. Verifying the app is outside this repository |
| Side channels | The size and the time of a response |
| The log store | The guarantee of the log store rests on AWS: on S3 Object Lock in compliance mode, and on the AWS account of the operator, which holds the bucket. When that account is closed, the bucket goes with it. An object can be deleted when its retention ended, 365 days after the write. The operator domain carries the bytes between a node and the store and can stop them: the node then uses no credential (the calls end with `log_store_unavailable`), so stopping the store stops the service and hides no use. The store can hold more entries than there were acts: an entry whose act failed afterwards or never started is in the store like any other. The operator domain holds the credentials for the bucket and can add objects to it: an object is an entry of a node when its body verifies under the signing key of that node (protocol.md 7.6) |
| The transfer to a later release | The operator can move the delegations of a node to a node of a later release: a release whose measurements it signs with its release key and publishes in the public transparency log (protocol.md 10.3). The later release is another program, and the user keys are then under the rules of its source. The notice period between the entry of the log and the transfer is zero: an account does not learn of a release before its delegation can move there. What stays is the record: every release that received delegations is permanently in the public log, with the hash of its measurements under the signature of the release key |
| The transparency log | The honesty of the log rests on the operation of Sigstore Rekor. A node checks the signed entry timestamp of the log: the signature of the log key over the entry. It checks no inclusion proof and no checkpoint, so it does not show that the log kept the entry |
| A change of the log key | A node holds one public key of the log, compiled into its program. When the log key changes, a node of an older release cannot check an endorsement made after the change and hands no delegation to the later release. The delegations of the later release then come from the apps |
| Reading the log store | This repository holds the writer. That an account reads the store without passing through the operator domain, and compares it with what the operator domain stores, is the work of the app and is not shown by this source |
| The log of a node that ended without its orderly shutdown | Such a node leaves no `final` head. The entries it wrote after the last point that the app verified cannot be checked against a head (protocol.md 7.4). The entries of its acts are in the log store: a node writes an entry there before the act. The witness signatures of stage 2 of the protocol are not implemented in this release |
| What a credential fetches | The response of `forward` or a mail call goes to the operator domain: the node protects the token, not the data that the token gives access to |
| Withdrawing a delegation | A revoke reaches a node through the operator domain. The app counts a delegation as withdrawn when every node that the operator domain lists as alive answered the revoke with its signed reply, and it shows a revoke without that reply as incomplete. The operator domain can leave a living node off that list: that node keeps the user key until its grant ends (at most 30 days). A use in that time is an entry on the chain of that node, and a node that is gone without a `final` head shows in the app as a part of the log that cannot be checked |
| Availability | The operator can stop the service and delete what it stores in its own storage. A deleted or withheld log entry shows as a gap in the app's verification of the chain. It cannot delete an entry of the log store before the retention of that entry ended |

The guarantees rest on: the isolation and the attestation of AWS Nitro Enclaves, Object Lock of
Amazon S3, the WebPKI roots compiled into the node binary, the algorithms of protocol.md section
2, the API contract of each provider, the honesty of the app, the public transparency log
(Sigstore Rekor), and the release key of the operator.

## How to verify

### 1. Build the enclave image file and get its measurements

```bash
git clone https://github.com/pickle-com/credential-enclave
cd credential-enclave
git checkout {tag}        # the release to check, for example v1.0.0
build/build.sh eif        # writes out/enclave.eif and out/measurements.json
```

The script needs git and Docker with buildx. Its reference machine is Linux x86_64. It builds the
commit `HEAD` (it stops when the work tree has uncommitted changes) and prints the measurements to
the standard output:

```json
{
  "release": "v1.0.0",
  "git_commit": "(40 hex digits)",
  "pcr0": "(96 hex digits)",
  "pcr1": "(96 hex digits)",
  "pcr2": "(96 hex digits)",
  "inputs": { "image/rust": "(SHA-256)", "binary/credential-enclave": "(SHA-256)", "...": "..." }
}
```

PCR0, PCR1 and PCR2 are the identity of a release. PCR0 measures the enclave image file, PCR1 the
kernel and the boot ramdisk, PCR2 the node program. The release tag is compiled into the node
program, so a build of a commit without a `v*` tag has the release `dev` and other measurements.
`inputs` lists the SHA-256 of everything the three values were made of: when two builds disagree,
the first key that differs says where they parted.

On an Apple Silicon Mac the node program builds under emulation, but the step that assembles the
enclave image file (`nitro-cli`) has been observed to crash under the QEMU emulation of Docker
Desktop. Without a Linux x86_64 machine, two builds made by others are available: the `check`
workflow builds the image on every push and keeps `measurements.json` as an artifact of the run,
and the `release` workflow builds it twice on independent machines and refuses to release when the
measurements differ.

### 2. Compare with the running nodes

```bash
cargo build --release --locked -p credential-enclave-verify
target/release/credential-enclave-verify \
  --url https://{api host} --measurements out/measurements.json
```

The tool sends one request without a credential,
`GET {url}/api/credential-enclave/attestation?nonce={nonce}`, with a nonce of 32 random bytes. It
does not follow a redirect. For every node of the response it verifies the Nitro attestation
document with the code a node uses for a peer (`protocol/src/attestation.rs`): the form of the
document, the certificate chain up to the AWS Nitro Enclaves Root-G1 compiled into the tool, the
signature, the nonce, that no PCR is all zero, PCR0, PCR1 and PCR2 against the expected values,
and the binding of the node keys. It prints one block per node and a summary as the last line.
The block of a node names the log store that its binding states (`log_store`: the bucket and
its region, or `none`).

| Option | Meaning |
| --- | --- |
| `--url {address}` | Verify the running nodes behind that address |
| `--document {file}` with `--nonce {hex}` | Verify one stored Nitro attestation document (raw CBOR bytes). `--nonce` is required: it is the nonce the document was requested with |
| `--measurements {file}` | The expected measurements: the `measurements.json` of a build or of a release |
| `--pcr0 {hex} --pcr1 {hex} --pcr2 {hex}` | The expected measurements as three values of 96 lower-case hexadecimal characters |
| `--allow-local` | With `--url`: do not count a node of the `local` platform as a failure |
| `--help` | Print the usage text |

| Exit status | Meaning |
| --- | --- |
| 0 | Every node passed. Without expected measurements the three comparisons do not run: the tool prints the measurements it saw, says that nothing was compared, and exits 0 when the other checks pass |
| 1 | At least one node failed |
| 2 | There is no result: the arguments, a file, the network, the HTTP status or the response (an empty list of nodes included) |

The tool verifies the nodes that the route lists. The app runs the same verification for every
node before it hands that node a user key.

The repository holds one stored document to try the tool without the service: the attestation
document of a node that ran a build made before the first release, and the measurements of that
build. They are test inputs: the measurements of a release are those of its GitHub release.

```bash
target/release/credential-enclave-verify \
  --document verify/tests/fixtures/nitro-attestation-alpha-prerelease.cbor \
  --nonce 488818963c99ac32f3c43f92a73f1ee1978e32ed1a597020cb0efaf2957978de \
  --measurements verify/tests/fixtures/measurements-prerelease.json
```

### 3. Compare with the published measurements

Every GitHub release carries `enclave.eif` and the `measurements.json` that two independent builds
agreed on, and the Sigstore bundles of two attestations of the enclave image file (its build
provenance, and a release statement whose predicate is `measurements.json`).

```bash
curl -L -O \
  https://github.com/pickle-com/credential-enclave/releases/download/{tag}/measurements.json
diff measurements.json out/measurements.json
target/release/credential-enclave-verify --url https://{api host} --measurements measurements.json
```

When `diff` prints nothing, your build of the tag is the published one. When the tool exits 0, the
running nodes attest those measurements.

## The egress policy

[docs/egress-policy.md](docs/egress-policy.md) states which bytes can leave a node and what in the
source enforces it. A secret (a key, a token, the plaintext of a record, a PKCE verifier) is a type
that cannot be serialized, so a response type with a secret field does not compile. The functions
that read the bytes of a secret are a closed list, checked on every push
(`scripts/secret-access.sh --check`), and a secret leaves through five sinks only: as a record
under the user key, sealed to a verified peer node, inside a TLS request to an address of the
provider definitions, as one vault value from `release`, and, for the credentials of the
operator for the log store, inside the TLS request that writes a log entry there. Every field of every response is
classified, a provider response is checked before any part of it is returned, and a test plants a
marker in every secret and searches every response for it.

## Repository

```text
protocol/    crate credential-enclave-protocol: the formats, the test vectors (vectors.json)
enclave/     crate credential-enclave: the node program
enclave/release/   compiled into the node program: the release key of the operator, the public
             key of the transparency log, the list of predecessors (predecessors.json)
host/        crate credential-enclave-host: the host program
verify/      crate credential-enclave-verify: the verification tool
egress/      the list of the functions that read a secret, the list of the callers of the sinks
scripts/     secret-access.sh: compares the source with the two lists
build/       build.sh and the Dockerfiles of the reproducible build
docs/        protocol.md, enclave.md, egress-policy.md
.github/     the check and release workflows
```

The toolchain is fixed by `rust-toolchain.toml` (Rust 1.98.1). The checks of every change:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
# protocol/vectors.json is the output of the generator
cargo run --locked -p credential-enclave-protocol --bin vectors -- --check
# the functions that read a secret, and the callers of the sinks, are the listed ones
scripts/secret-access.sh --check
```

The tests of the node run the embedded provider definitions against a TLS server on the loopback
interface. The node program also runs without an enclave:

```bash
cargo run -p credential-enclave -- --platform local      # listens on TCP 0.0.0.0:8080
curl http://127.0.0.1:8080/v1/health
```

## Documents

| Document | Content |
| --- | --- |
| [docs/protocol.md](docs/protocol.md) | The keys, the attestation, the commands of the app, the record, the log and the log store, the node statements, the delegation transfer, the failure codes, the test vectors |
| [docs/enclave.md](docs/enclave.md) | The node program and the host program: the state of a node, every call, the write to the log store, the provider definitions, the address check, the build and the release |
| [docs/egress-policy.md](docs/egress-policy.md) | What can leave a node, the rules E1 to E6, the class of every response field, the limits |

## License and security

Apache-2.0. See [LICENSE](LICENSE).

To report a security problem, write to `contact@pickle.com`.
