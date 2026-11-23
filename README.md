# credential-enclave

This repository is the source of the program that holds and uses the credentials of Pickle
accounts inside an AWS Nitro Enclave, and of the program that the Pickle apps run on the device
side of the same protocol. It contains five things:

| Part | What it is |
| --- | --- |
| The node program (`enclave/`) | The process inside the enclave. It holds the user key of an account for a limited time and, with that key, issues, opens, uses and records credentials |
| The host program (`host/`) | The process in the parent pod. It starts the enclave and relays bytes to and from it. Nothing the node guarantees depends on it |
| The protocol crate (`protocol/`) | The formats that the node and the app of an account share: keys, messages, records, the log, attestation documents |
| The verification tool (`verify/`) | `credential-enclave-verify`: it fetches the attestation of the running nodes and compares it with the measurements of a build of this source, and it verifies the release proof of the secure program |
| The secure program (`secure-program/`) | The JavaScript program that the apps run for the device side of the protocol: it creates the master key, verifies nodes, seals grants, encrypts records and reads the log. The backend serves a byte-identical copy to the apps, and a release build of an app loads it only with the release proof of a release of this repository ([secure-program/README.md](secure-program/README.md)) |

A reader can build this source, compare the measurements of the build with what the running nodes
attest, read here what a node does with a credential, and read the program that the apps run with
the master key.

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
| Vault value that is typed into a page (a password, a card number, a CVC, and a vault secret whose slot is `field`) | When the user enters it | In memory, while `release` runs | The ciphertext, and the value after `release` handed it out (under the seal of a key the caller named, when the call names one) |
| Vault secret that goes into requests (an API key: a named value whose record lists a header, a query parameter, a form field, a JSON member, the path or a half of HTTP Basic), entered on the device | When the user enters it | In memory of the node that holds the grant while `vault/handoff` runs, and of a node of the forward role while it sends the one request the value is for | Ciphertext only, within the three limits "The entry of a value on the device", "The rest of a request that carries a vault secret" and "An earlier record" below |
| Vault value the operator domain gave a node (`vault/store`: a value a page showed, a command printed, or a password the backend made) | No | In memory, while the call runs | It knew the value when it gave it. From then on one of the two rows above, by the slots of the record. The record says that the operator domain gave the value |
| TOTP seed | When the user enters it | In memory, while `release` computes a code | Ciphertext only. `release` hands out the 6-digit code |
| Log entry | Opens it with the log decryption key | Creates it, writes it to the log store before the act, keeps it until its storage is acknowledged | Stores it sealed. Cannot delete the copy in the log store for 365 days |

A node of this program takes one of three roles, once. A node of the delegation role
is the node of the picture: it holds the delegations of accounts, and it connects to the addresses
of its provider definitions and to its log store only. A node of the reserve role holds
delegations as well and uses none of them: it takes the grant and the revoke of an app and hands
delegations to other nodes and takes them from other nodes, it refuses every call that uses a
credential, and it connects to its log store only. The operator keeps one copy of the delegation
of an account on such a node, in another availability zone than the nodes that use it, so that
what ends the nodes that read provider responses does not end every node that holds the
delegation (protocol.md 10.4). A node of the forward role holds no user
key, opens no record and writes no log entry. It receives one value of a vault secret at a time,
sealed to it by a node of the delegation role of the same measurement together with the one
request the value is for, and sends that request to the host of that request: a host the account
chose. So the node that holds the keys of every account talks to no host an account names, and
the node that talks to such a host holds one value for one request.

A node writes nothing to disk. A node that restarts has new keys and no user keys. It takes the
delegations from a living node of the same measurement and the same log store (`peer/export`,
`peer/import`), or from the apps the next time they run. A node of a later release takes them
from a living node of an earlier release with the same log store, when the earlier node verified
that the operator's release key signed the measurements of the later release and that a public
transparency log of its table holds the record of the signature, and when the later release
lists the earlier one as a predecessor.

A node that ends takes the user keys it holds with it, so a fault of the node program (a panic,
in its own code or in a library it is built with) ends as little of a node as it can have left in
doubt: the one call it happened in, the state of one account on that node, or, for a fault under
state every account depends on, the node. A call that ended this way gets no response, and no
fault makes a node act without the confirmed entry of the act ([enclave.md](docs/enclave.md)
3.1).

The log store is a set of Amazon S3 buckets with Object Lock. A node writes every log entry there
itself, over TLS that ends inside the node, with a retention in compliance mode of 365 days, and
performs the act the entry describes only after the store confirmed the entry. The binding of the
attestation of a node names the store by one bucket name, and the buckets follow from that name by a
rule of the node program, so a verifier of a node knows where its entries go: the entries of one
account are all under the prefixes of that account in one bucket, whichever node wrote them. A node
also writes its own attestation document to the store before it takes a user key, so a reader of the
store verifies which program wrote an entry without asking the node.

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
| A use of a credential has a log event that only the account can read, in an entry that is created before the use, and for a new connection before its record leaves the node. One entry holds the events of the acts of one account that arrived while the write before it ran (the group commit), and the requests of one `forward/batch` call are named one by one in one entry before any of them leaves; every event names its act exactly. Identical GET requests of one record within 300 seconds share one event. The entries of an account are under the prefixes of that account in the log store, whichever node wrote them: a reader lists them there directly, verifies every object it reads against its key, and verifies with the attestation document of the node, which the node itself wrote to the store, in which program the signing key of an entry was created (protocol.md 7.4 and 7.7). For the nodes of the releases before v2.4.0, the app verifies the chain of every node from the keys of the listing up to the head the node signed, and reads the control entries and every entry it shows (`secure-program/secure-program.js`, `walkStore`) | `forward`, `forward/batch`, `refresh`, `revoke-token`, `release`, the command grant that puts a user key into a node, the command revoke, and `peer/export` to a node of a later release create their event before the act: before the node calls the provider, hands the value out, changes the delegation or seals the user key to a peer. `oauth/complete` receives the token from the provider first and creates the entry `connection_created` before the record leaves the node: no part of an accepted token response leaves before that entry exists, and when a later step fails, the tokens are dropped inside the node and nothing leaves. `oauth/merge` calls no provider and creates no event. A grant command that renews the grant in force and a transfer between two nodes of one measurement put no user key under another program and create no event; a transfer to a later release names the release and the measurement of the receiving node in its event. An entry is sealed to the log key of the account and signed by the node; the key of its object in the store carries the time of the entry, the node and the hash of its body. A node writes its own attestation document to the store before it takes a user key and signs no head: what a reader needs of a node is in the store, also when the node is gone | protocol.md section 7, `protocol/src/log.rs`, `enclave/src/state.rs`, `enclave/src/log_store.rs` |
| A use of a credential has an entry in the log store that nobody can delete for 365 days: not the operator, and not the root user of its AWS account. The entry is in the store before the use | A node writes each entry to its log store with `PUT`, over TLS that ends inside the node (the node keeps idle connections to the store and sends every write over one), with a retention in the compliance mode of S3 Object Lock until 365 days after the write. It calls the provider, hands the vault value out, hands the record of a new connection out, takes a user key by a grant command or hands a grant to a node of a later release only after the store answered that write with the status 200. It takes no other answer for a confirmation, also not the answer that an object of that key exists: the operator domain can write to the same bucket. Every write names the encryption of its object under a key the store manages, so no key that someone can disable stands between a reader and an entry. The binding inside the attestation document names the log store by one bucket name and its region, the buckets a node writes to follow from that name by a rule of the node program, a node takes a log store once, and a node hands delegations only to a node of the same log store. A node inside an enclave refuses these acts while it has no log store, no credentials for it or no node document in it | protocol.md 7.6, 7.7 and 4.1, enclave.md 5.14, `enclave/src/log_store.rs`, `enclave/src/tests/log_store.rs` |
| A vault value leaves through `release` only, one field at a time, after its log entry. A TOTP seed never leaves. No answer of `release` depends on the content of a value unless an entry records the call | The type of a vault value has one way out, `hand_out`, which takes the log entry of that release as an argument. For a TOTP record the value it holds is the code. The plaintext is read for the value only after the log store confirmed the entry | [enclave.md](docs/enclave.md) 5.9, `enclave/src/vault.rs` |
| A vault secret says where its value may go, and nobody without the user key can change that. `release` hands the value of a record with the slot `field` out for an origin of the hosts of the record, and the value of a record with slots of a request is handed out by no call | The hosts and the slots of a record of kind `vault_secret` are part of its plaintext, which is encrypted under the user key. The two calls that use the value hold their caller to them, and no record lists the slot `field` beside a slot of a request | [protocol.md](docs/protocol.md) section 6, enclave.md 5.9 and 5.9c, `protocol/src/vault_secret.rs` |
| A vault secret that goes into a request leaves the node that opened its record only under a seal to a node of the forward role of the same measurement, for one request to a host of the record, with the value at a slot of the record, after the log entry of that request. The node of the forward role sends that request once, and hands on no response that holds the value in a form its search knows | The seal takes the log entry of the use and a node whose attestation was verified. The request that leaves is built from the opened envelope alone: its host, its address and the hash of its body are those of the entry. The response passes the reflection check of the egress policy while it arrives | protocol.md 10.5, enclave.md 5.9c and 5.16, `enclave/src/bound.rs`, `enclave/src/provider_response.rs` |
| A value the operator domain stored in the vault says so, and its storing has a log entry | `vault/store` writes the plaintext itself, with the source `operator`, under an `id` and a nonce the node draws, and hands the record out after the log store confirmed the entry | enclave.md 5.9b |
| The node that holds user keys connects to no host an account chose, and the node that does holds no user key | A node takes one role. A node of the forward role refuses every call that takes a command, a delegation transfer or a record, a node of the delegation role has no call that sends a request outside the addresses of its definitions, and a node of the reserve role refuses every call that opens a record or sends a request to a provider | protocol.md 4.1, enclave.md section 4, `enclave/src/role.rs` |
| The code a node runs is this source, and anyone can check that with the measurements | The build is reproducible: one commit gives the same PCR0, PCR1 and PCR2 on every build. The attestation document of a node, signed under the AWS Nitro Enclaves root certificate, states the three values of the running enclave and binds the public keys of the node. A node does not start in a debug-mode enclave | enclave.md section 11, `build/build.sh`, `protocol/src/attestation.rs`, `verify/` |

A vault value that is typed into a page is protected by the node up to `release`. `release` hands
a password, a card number, a CVC or a vault secret with the slot `field` to the worker of the
operator, which fills a form with it. From that moment the node no longer protects the value: what
the source shows is that it was stored as a ciphertext and that every release has its log entry. A
`release` call can name a key to seal the value to, so the value does not cross the network of the
operator in the clear. The caller chooses that key, so the seal is no limit on the operator.

A vault secret that goes into requests does not pass through `release`. What the source shows for
a value a user entered on the device is that no call hands it out, that every request that carried
it has a log entry with its method, host, path, query and the hash of its body, and that a
response that sends it back is cut. The limits of that are in the next section.

## What it does not guarantee

The first eighteen rows, but for the row "The entry of a value on the device", are the limits that
section 5 of egress-policy.md states.

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
| The honesty of the app | The app holds the master key and verifies the attestation. The app binary is not open source yet. The secure program that the app runs for this protocol is in this repository (`secure-program/`) and bound to the public record: a release build loads a served program only with the release proof of a release of this repository ([secure-program/README.md](secure-program/README.md)). What that does not show is that the binary runs the program unchanged: until the app is open source, "the app is honest" is an assumption, and an app that is not the published one can leak the master key. Verifying the app binary is outside this repository |
| Side channels | The size and the time of a response, and the sizes of the parts of a response that is handed on as a stream |
| The entry of a value on the device | A value a user enters reaches the secure program through a screen of the app. An app build that draws the input field of a value, and the text that says where the value may go, from a screen definition the backend of the operator serves leaves both to the operator domain: it can show other hosts than the record names. Only a build that draws that sheet itself removes this |
| The rest of a request that carries a vault secret | A record binds the host and the slot of a value. The path of that host a request goes to, its body and its other headers are chosen by the caller, the operator domain. A host with an address that stores what it receives and returns it to another request, or that returns a value in a form the reflection check does not know (encrypted, compressed, split), lets the operator domain read the value there. Every such request is on the log of the account |
| A value that can be guessed | The node withholds the response to a request that carried a vault secret, or cuts it, exactly when the response holds the value, and the operator domain, which calls the node, sees that verdict. So the verdict on a response whose content the caller chose says whether that content holds the value, and a value of a small set of candidates (a word of a dictionary, a short number) can be told from the others that way. A value that cannot be guessed, as a key a provider issued, is not found this way. Every such request is on the log of the account |
| An earlier record | After a user narrowed the reach of a vault secret or deleted it, the operator domain can still hold the earlier record, and a node opens it while a grant is in force. Its use is on the log like any other |
| A value a page receives | The origin of a `release` call is what the caller stated: the node holds it to the hosts of a vault secret and writes it into the entry, and it does not know where a browser is |
| A value the operator domain gave | The operator domain knew a value it stored through `vault/store`. The record says so. What the source shows for such a value begins with the record |
| The log store | The guarantee of the log store rests on AWS: on S3 Object Lock in compliance mode, and on the AWS account of the operator, which holds the buckets. When that account is closed, the buckets go with it. An object can be deleted when its retention ended, 365 days after the write. The operator domain carries the bytes between a node and the store and can stop them: the node then uses no credential (the calls end with `log_store_unavailable`), so stopping the store stops the service and hides no use. The store can hold more entries than there were acts: an entry whose act failed afterwards or never started is in the store like any other. The operator domain holds the credentials for the buckets and can add objects to them: an object is an entry of a node when it verifies against its key under the signing key of that node and the store holds the node document of that node (protocol.md 7.4) |
| The transfer to a later release | The operator can move the delegations of a node to a node of a later release: a release whose measurements it signs with its release key and publishes in the public transparency log (protocol.md 10.3). The later release is another program, and the user keys are then under the rules of its source. The notice period between the entry of the log and the transfer is zero: an account does not learn of a release before its delegation can move there. What stays is the record: every release that received delegations is permanently in the public log, with the hash of its measurements under the signature of the release key, and the log of every account whose key moved holds the entry of the giving node that names the release and the measurement of the receiving node |
| The transparency logs | The honesty of a log rests on the operation of Sigstore. A node holds a table of transparency logs and takes an entry of a log of its table (protocol.md 10.3). The table of this release has one row, `rekor.sigstore.dev`: a log has a row when the trusted root of the public instance of Sigstore names it and the monitor of this repository reads the entries of the release key in it. For an entry of a log of the form Rekor v1, such as `rekor.sigstore.dev`, a node checks the signed entry timestamp of the log, the signature of the log key over the entry, and no inclusion proof: it does not show that the log kept the entry. For an entry of a log of the form Rekor v2 it checks the inclusion proof: the audit path of the entry and the checkpoint in which the log signed the head of its tree. In neither case does it check the signature of a witness, so it does not show that the log presents the same tree to every reader. The second log of that trusted root, `log2025-1.rekor.sigstore.dev` of the form Rekor v2, answers no search by key, the monitor does not read it, and it has no row |
| A log that takes no further entry | The table of logs is compiled into the node program. A node checks an entry of a log of its table and of no other log. Sigstore, the operator of `rekor.sigstore.dev`, has stated that it will announce the end of the uploads to that log one year ahead, and that it replaces a log such as `log2025-1.rekor.sigstore.dev` by a log with another key about every six months. A release that is endorsed after no log of the table of an older node takes entries any more receives no delegation from that node, and its delegations then come from the apps. So a release whose table has a log that goes on taking entries, and whose monitor reads that log, is built and endorsed while a log of the tables in service still takes entries (protocol.md 10.3) |
| Reading the log store | The app reads the store without passing through the operator domain: the operator's backend only presigns the addresses, and the program verifies that each address names the bucket of its server target and the prefix of its own account before it calls it. An operator that signs no address stops the verification (the app shows pending, and attention after 3 days). The operator holds no copy of the entries: what the app shows comes from the store, and entries older than the retention of the bucket (400 days) are gone. What this source does not show is that the app binary runs the published program unchanged (the row "The honesty of the app") |
| The log of a node of a release before v2.4.0 that ended without its orderly shutdown | Such a node left no `final` head. The entries it wrote after the last point that the app verified cannot be checked against a head (protocol.md 7.4). The entries of its acts are in the log store: a node writes an entry there before the act. A node of release v2.4.0 or later signs no head, and its end leaves no such part: the entries of its acts are under the prefixes of the account whether it ended in order or not |
| What a credential fetches | The response of `forward` or a mail call goes to the operator domain: the node protects the token, not the data that the token gives access to |
| A mail session a node keeps | A node keeps the authenticated IMAP session of a read for the next read of the same record, for at most 30 seconds between two reads and 300 seconds after its login. An application password the account withdrew at the provider can still read the mailbox over such a session until that age. Every read has its log entry before it reaches the mailbox, over a kept session as over a new one, and no read goes over a session after the account revoked its delegation, after the end of its grant or while the node closes (enclave.md, "Mail call surface") |
| Withdrawing a delegation | A revoke reaches a node through the operator domain. The app counts a delegation as withdrawn when every node that the operator domain lists as alive answered the revoke with its signed reply, and it shows a revoke without that reply as incomplete. The operator domain can leave a living node off that list: that node keeps the user key until its grant ends (at most 30 days). A use in that time is an entry in the log store, under the prefixes of the account |
| Availability | The operator can stop the service and delete what it stores in its own storage. The operator cannot delete an entry of the log store before the retention of that entry ended |

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

### 4. Verify the secure program

The apps run the device side of the protocol as a JavaScript program that this repository holds at
`secure-program/secure-program.js` and that the backend of the operator serves to the apps. A
release build of an app loads a served program only with the release proof of a release
`secure-program-v{N}` of this repository: the statement of the release, signed by the release key
and recorded in Rekor, with the inclusion proof of the entry ([docs/protocol.md](docs/protocol.md),
"The secure program release").

```bash
git checkout secure-program-v{N}
curl -L -O https://github.com/pickle-com/credential-enclave/releases/download/secure-program-v{N}/secure-program.release.json
target/release/credential-enclave-verify program \
  --source secure-program/secure-program.js --release secure-program.release.json
```

The tool runs the ten checks of the apps with the release key and the log key compiled into it and
exits 0 with `program release secure-program-v{N}: version {N}, sha256 {hex}, log index {i}: ok`,
or 1 with the code of the check that failed (`--help` lists the options). The encryption key
screen of the app shows the version and the SHA-256 of the program it runs.
[secure-program/README.md](secure-program/README.md) has the steps without the tool, and the
limits.

## The egress policy

[docs/egress-policy.md](docs/egress-policy.md) states which bytes can leave a node and what in the
source enforces it. A secret (a key, a token, the plaintext of a record, a PKCE verifier) is a type
that cannot be serialized, so a response type with a secret field does not compile. The functions
that read the bytes of a secret are a closed list, checked on every push
(`scripts/secret-access.sh --check`), and a secret leaves through nine sinks only: as a record
under the user key, sealed to a verified peer node, inside a TLS request to an address of the
provider definitions, as one vault value from `release`, for the credentials of the operator for
the log store inside the TLS request that writes a log entry there, inside the TLS connections to
the two fixed mail endpoints, sealed to a verified node of the forward role with the one request
it is for, and, on such a node, inside that one TLS request to the host the seal names. Every field of every response is
classified, a provider response is checked before any part of it is returned (a response that is
handed on as a stream is checked while it arrives, and is cut in front of a credential it holds),
and a test plants a marker in every secret and searches every response for it.

## Repository

```text
protocol/    crate credential-enclave-protocol: the formats, the test vectors (vectors.json)
enclave/     crate credential-enclave: the node program
enclave/release/   compiled into the node program: the release key of the operator, the public
             key of the transparency log, the list of predecessors (predecessors.json)
host/        crate credential-enclave-host: the host program
verify/      crate credential-enclave-verify: the verification tool
secure-program/   the secure program of the apps (the source of truth), the release statement
             and monitor scripts, its README
egress/      the list of the functions that read a secret, the list of the callers of the sinks
scripts/     secret-access.sh: compares the source with the two lists
build/       build.sh and the Dockerfiles of the reproducible build
docs/        protocol.md, enclave.md, egress-policy.md
.github/     the check and release workflows, and the release and monitor workflows of the
             secure program
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
| [docs/enclave.md](docs/enclave.md) | The node program and the host program: the state of a node, what a fault of the program ends, every call, the write to the log store, the provider definitions, the address check, the build and the release |
| [docs/egress-policy.md](docs/egress-policy.md) | What can leave a node, the rules E1 to E6, the class of every response field, the limits |
| [secure-program/README.md](secure-program/README.md) | The secure program of the apps: what it is, what it never does, how a release is made and verified, its limits |

## License and security

Apache-2.0. See [LICENSE](LICENSE).

To report a security problem, write to `contact@pickle.com`.
