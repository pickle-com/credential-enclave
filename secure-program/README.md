# The secure program

## What this is

`secure-program.js` is the program that the secure executor of the Pickle apps runs: the iOS app
in JavaScriptCore, the Android app in QuickJS. It is the program that [docs/protocol.md](../docs/protocol.md)
calls "the app": the device side of the credential protocol. It creates the master key and derives
the account keys from it (protocol.md section 3), verifies the attestation of enclave nodes
(section 4), seals grants and revokes to a verified node (section 5), encrypts credential records
(section 6) and vault secrets, reads and judges the credential log (section 7), keeps the grants it
handed to nodes (a node the backend lists for its revokes alone is handed none), keeps the
settings of the delegation (the switch and the lifetime of a grant) and reads the ones the other
devices of the account made before it sends a command to a node, and transfers
the master key between the devices of one account. What the program
does, in which order and under which limits, is specified in protocol.md, "The program of the
app".

The program hands a grant to a node whose measurement is an element of its list of accepted
releases, or is shown to it by release proofs that it verifies on the device (protocol.md, "The
release proofs"): the signature of the release key over the measurements of the release in the
public transparency log, a signature of a deploy key of the operator, and the attestation GitHub
made of those measurements for the job of the build workflow of this repository, at the commit of
that workflow file the program holds, in a run of the tag of the release. A release of the
enclave made after a program so reaches a device that runs that program, when its build method is
the one that workflow file fixes (the four build files by their SHA-256, and packages from
crates.io alone): a release that changes its build method has no attestation the program takes
and reaches the device with a program that lists it. A release whose proofs fail a check is to that device a release it does not list, and so
is a release whose statement states a version of the program above the one the device runs
(`program_min`). The proofs reach the program with the attestation of a node, in a node document,
or from the backend for the digest of a measurement.

The program lists the log store itself (protocol.md 7.4): the listing of the two prefixes of its
account, read from Amazon S3 through addresses it checks, names every act that took place with the
key of the account. It judges the log by that listing and by the node documents of the nodes that
wrote the entries. A node document proves itself and reaches the program through the backend.
Whether the store holds no node document of a node id is read from the store: the listing of the
versions under the key of that document, in the bucket of the node id, through an address the
program checks. An object under a node id without a node document is no entry of a node and is
left out; a key whose node document is withheld is a read held back. For the entries of format 3
the program reads no head, verifies no chain equation and traces no transfer from node to node. A
round reads the control entries; the log screen reads the entries it shows and counts the summary
of the last seven days from the use entries of that window (each counted once per device and kept,
sealed with a key derived from the master key, with the first page of the screen). A read that was
held back, whoever made it, is made again by every round until it is not, and what a round reads
of a read of the log screen is kept on the device for the screen (sealed the same way): the entry
under a key the screen asked for, the listing pages, the entries and the node prefixes of the
chains of formats 1 and 2. The screen takes an entry from there before it asks for it, and a
listing page when its own read is held back again, so an answer the backend gives a round is an
answer the user sees. The reads of the screen that cannot be kept in a form that answers every
later read (a later listing page, the listing of a chain of formats 1 and 2) are noted by the
screen itself when they are held back, and mark the log when such reads of three days stay
unread by the screen: with every opening the screen reads its listings on from their start down
to what was noted, so a read that failed once ends with the next opening the backend answers.
A round that left reads undone and spent what it read on entries its nodes wrote catches up and
counts as none, 32 rounds in a row at most; a round whose time passed, or one of whose requests
was not answered, counts, and rounds that keep counting are rounds held back. The rounds held
back count one for a day. A request for a list of keys that is not answered is asked again for
its first key alone, and an entry of 32,768 bytes or more is asked for alone at the end of a
round with the time its size takes, so a network that carries little is not read as a backend
that holds reads back. A round
ends its reading when the app goes to the background and is judged on what it read, and the keys
it listed and did not come to judge are the first the next round asks for, so a device whose
stays in the app are short reads the log on with every stay. A measurement no list of the
program has that held the key of the account marks the log once the device first saw it a day
ago, the runtime knows that no later program than this one is served, and the backend answered
its request for the release proofs of that measurement without proofs that show it: a runtime
that knows that a later program is served judges nothing, writes none of the values the rounds
judge by, and reports once that it is behind. The signature of an object reaches the device through the
backend, so a body handed out with a signature that does not verify marks the log only when the
answers of two rounds carried none that does, and until one does. The
entries of the nodes of the releases before v2.4.0 (formats 1 and 2) are read from the bucket
their bindings name, for display and to follow a transfer of the delegation a node of such a
release made: under one `seq` of such a chain the program reads eight objects at most until one
is the entry of the node, a round reads a chain on only where its node wrote, and the screen
takes a range of a chain as known only from a listing that was read as far as the range reaches.
The rounds follow the chain of every node the store names under the prefix of the account, read
from the listing of that bucket once a day, so a transfer made by a node this device never
handed a grant to is judged as well.
The storage of the operator holds no entry. An entry older than 365 days (the
retention of its Object Lock) is expected by nobody, and the lifecycle rule of a bucket removes
entries at 400 days (7.6).

The work of the program runs on three lines that do not wait for one another (the procedures a
user starts, the synchronizations, the reads of the log screen), every request has a time limit,
and a procedure ends itself before the executor gives it up.

This file is the source of truth of the program. The repository `pickle-com/interactive-character`
(the backend of the operator) vendors a byte-identical copy at `backend/assets/ui/secure-program.js`
and serves it to the apps together with their UI definitions, so the operator can fix a defect or
add a procedure on both platforms with a backend deployment. A release build of an app loads a
served program only when the program is the subject of a release of this repository: a release
statement that names the SHA-256 of the file, signed by the release key of the operator and
recorded in the public transparency log Rekor, with an inclusion proof that the app verifies on the
device. Every program a release build can run is therefore a tag `secure-program-v{N}` of this
repository, where N is the `const VERSION` of the file, and anyone can read it here.

The program reaches native code only through the global `native`, the bridge primitives of the
apps. Every cryptographic algorithm is a bridge primitive; the file parses formats only (base64url,
UTF-8, CBOR, query strings). The top level of the file defines things and calls nothing. The
contract between the program and the two executors is `docs/ssot/client/secure-executor.md` of
`pickle-com/interactive-character`.

## What the program never does

The master key is written to the key store of the device (`native.keychainSet`: the iCloud
Keychain on iOS, Block Store with end-to-end encryption on Android) and read from it
(`native.keychainGet`), and nowhere else. What leaves the device is: the public keys and the
signatures derived from the master key; the user key, sealed with HPKE to the sealing key of a
node whose attestation the program verified (`native.hpkeSeal`); the ciphertext of credential
records (`native.aeadSeal`); and, during the transfer of the master key to another device of the
same account, the master key sealed with the session key that the two devices derived from the
6-digit code (CPace over X25519) after the confirmation tag of the other device verified
(`native.aeadSeal` in `transferSeal`). The master key, the user key and the plaintext of a record
are never part of a request (`native.http`) or of a published value (`native.publish`) in any
other form.

The value of a vault secret goes into the record the device seals, and nowhere else: it is part of
no request, of no published value and of no value of the program store (`native.storeSet`). When
the user asks to see a value, the program opens the record on the device and hands the value to
the protected sheet of the app (`native.presentSecret`); in a build without that sheet the value
is the result of the procedure, which the user interface definition shows. The hosts and the
places a value may go to are part of the record the device seals: where the screen showed them to
the user, the program seals nothing under other ones, and in a build with the confirmation of the
app (`native.confirmDestinations`) the user confirms a change of them on a surface the app binary
draws. The first page of the
log screen and what the rounds read for the screen, which name services and addresses, are kept in
the program store sealed with a key derived from the master key.

The settings of the delegation (the time the user turned it off or on, the lifetime of a grant)
and the nodes of the releases before v2.4.0 the device handed a grant to reach the other devices
of the account as a ledger sealed with a key derived from the master key (`native.aeadSeal` in
`sealLedger`): the backend stores that value and cannot open it. A message of a master key
transfer that gives no shared value (the X25519 result is 32 zero bytes) ends the transfer before
anything is sealed with a key made from it.

What the program reports to the backend about itself names no secret and nothing of the content of
an account: the result of a round (the status, counts, the names of releases, node ids), the
outcomes of its procedures (the names of procedures, failure codes, times) and the result of a
synchronization a push started (the key state, the state of the grants, counts, a time). Every
request to a route of the backend under `/api/secure/` names the version of the program (the
query `program`), and no other request does.

A reader checks this in the file. The search terms: `keychainSet` and `keychainGet` (where the
master key is stored and read), `hpkeSeal` (what is sealed to a node), `aeadSeal` (what is
encrypted as a record, what the transfer seals, the ledger of the settings of the delegation, the
kept screen and what the rounds keep for the screen), `native.http(` (every
request the program sends: `request` builds the requests to the backend and `fetchStore` the
requests to the log store), `native.publish(` (every value the program hands to the user
interface), `native.storeSet(` (every value the program keeps on the device outside the key
store), `presentSecret` and `promptSecret` (where a vault value passes the app), and
`confirmDestinations` (where the user confirms the hosts and places of a vault value).

## How a release is made

A program that is to accept the nodes of a new enclave release lists the measurement of that
release in `const ACCEPTED_RELEASES` (protocol.md 4.5). One command puts the element in, from the
`measurements.json` of the GitHub release of the enclave tag, and compares what the list holds
with that file:

```bash
python3 secure-program/accept_release.py --measurements measurements.json
```

It exits 0 when the list holds the three values of the file, and `--check` compares without
writing ([`accept_release.py`](accept_release.py)).

1. The commit that changes the file sets `const VERSION` to a new N and is tagged
   `secure-program-v{N}`. The push of the tag starts the workflow
   [`.github/workflows/secure-program-release.yml`](../.github/workflows/secure-program-release.yml).
2. The workflow writes the release statement of the tag with [`statement.py`](statement.py) (it
   stops when the N of the tag is not the `VERSION` of the file), creates the GitHub release of the
   tag, and uploads `secure-program.js`, `statement.json` and a build provenance attestation of
   the file (`secure-program-provenance.sigstore.json`). The same push starts
   [`.github/workflows/secure-program-source-release.yml`](../.github/workflows/secure-program-source-release.yml),
   which calls [`secure-program-source.yml`](../.github/workflows/secure-program-source.yml) at a
   fixed commit: that workflow attests the SHA-256 of the file as the commit of the tag holds it,
   and the bundle is uploaded to the same release as `secure-program-source.sigstore.json`
   (docs/protocol.md, "The attestation of the source").
3. The operator, on the machine that holds the release key, rebuilds the statement from the tag,
   compares it byte for byte with the `statement.json` of the GitHub release, signs it with the
   release key (ECDSA P-256 with SHA-256) and records the signature in Rekor as a `hashedrekord`
   entry. From the response of the log it writes the release proof `secure-program.release.json`
   (the statement, the entry, the signed entry timestamp, the inclusion proof and the checkpoint),
   vendors the file and the proof into `pickle-com/interactive-character`, and uploads the proof to
   the same GitHub release.

The bytes of the statement, the entry and the release proof are specified in
[docs/protocol.md](../docs/protocol.md), "The secure program release".

## How to verify

1. The file of the tag is the subject of the statement:

   ```bash
   git show secure-program-v{N}:secure-program/secure-program.js | sha256sum
   ```

   equals `sha256` of the `statement.json` of the GitHub release, and `version` of the statement
   is the `const VERSION` of that file.

2. The log holds the entry:

   ```bash
   curl 'https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}'
   ```

   with `entry.log_index` of `secure-program.release.json`. The `body` of the response, decoded
   from base64, is a `hashedrekord` whose `spec.data.hash.value` is the SHA-256 of the statement
   bytes and whose `spec.signature.publicKey.content` decodes to the PEM of
   [`enclave/release/release-key.pem`](../enclave/release/release-key.pem).

3. The release proof holds under the keys compiled into the verification tool:

   ```bash
   cargo run --locked -p credential-enclave-verify -- program \
     --source secure-program/secure-program.js --release secure-program.release.json
   ```

   runs the ten checks of the apps and exits 0 with
   `program release secure-program-v{N}: version {N}, sha256 {hex}, log index {i}: ok`.

4. The app runs that release: the encryption key screen of the app shows "Security program v{N}"
   and the SHA-256 of the program it loaded, and they equal `version` and `sha256` of the
   statement.

5. The file is the file of the commit of the tag, attested by the workflow at its fixed commit
   (the commit after the `@` in `secure-program-source-release.yml`):

   ```bash
   gh attestation verify secure-program.js --repo pickle-com/credential-enclave \
     --bundle secure-program-source.sigstore.json \
     --signer-workflow pickle-com/credential-enclave/.github/workflows/secure-program-source.yml \
     --signer-digest {the fixed commit} \
     --source-ref refs/tags/secure-program-v{N} --deny-self-hosted-runners
   ```

   The certificate of the bundle states the commit of the tag as the Source Repository Digest
   (the extension `1.3.6.1.4.1.57264.1.13`), and
   `git show {that commit}:secure-program/secure-program.js | sha256sum` equals the SHA-256 of
   the subject.

## The tests

`tests/` runs the program on a model of the bridge of the apps, with Node alone:

```bash
node --test secure-program/tests/program.test.js secure-program/tests/proofs.test.js
```

`tests/bridge.js` is the model: the global `native` on the crypto module of Node (HKDF, Ed25519,
X25519, HPKE of RFC 9180, ChaCha20-Poly1305, ECDSA P-384), a device (the key store, the program
store, the published state, the build of the app with or without the bridge primitives of a later
build), the backend of the operator and the buckets of the log store as the program reaches them
over `native.http` (the listings of object versions with their delete markers, and the route of
the node documents with the origin of a document and the addresses of the listings of the node
document keys, which answers from the node registry alone while the backend holds the store of
format 3 closed), and enclave nodes with their keys, attestation documents, node documents,
commands and log entries of formats 2 and 3 (`docs/protocol.md` sections 4, 5 and 7). The time of
the model moves only when nothing else can happen, so a test runs a wait of minutes at once. The
certificate chain of a nitro document is modelled (one leaf of the model stands for the
certificate); the signature of the document is a real ECDSA signature over the Sig_structure the
program encodes. The loader evaluates the program the way the executors do: a fresh context whose
globals are `native`, `SecureError` and `console`, the top level evaluated with the bridge closed.
The first tests check the model against `protocol/vectors.json`, the reference the apps test their
bridges against, and run the program on the entries, the keys, the node document and the buckets
of the vectors `log_v3` and `log_store` and on the forms of the vectors `vault_secret`: the program
gives the answers of the reference reader (`protocol/src/app.rs`). `tests/scenarios.js` holds the
scenarios (worlds and runs) and returns plain results; `tests/program.test.js` fixes the expected
results of the current program.

`tests/proofs.test.js` holds the tests of the release proofs (`docs/protocol.md`, "The release
proofs"). `tests/proofs.js` is the model of the parties that make such proofs: an operator with a
release key and deploy keys, a transparency log of the form Rekor v1 with its tree and its
checkpoints, a certificate authority that issues the certificate of a workflow run as Fulcio does
(X.509 in DER, written by the encoder of that file), and the attestation of a release statement
as the job of the build workflow makes it (the workflow file and the commit the program of the
checkout holds). Every key is made there, and the program of a test runs with
those keys and certificates in the place of its constants. `tests/proof-cases.js` states proofs
that hold and proofs that differ from them in one place, each with the check that refuses them;
the test runs every case through a synchronization and compares whether the node received the
grant and what the program logged. The other tests run histories: the key of an account moving
through releases the program does not list, read by the device that saw every move and by an
installation that kept nothing; a closed node whose proofs the backend hands out for the digest
of its measurement; a release whose statement states a later program; and proofs that reach the
device after it read the entries of a node. `tests/fixtures/release-proofs-v2.3.0.json` holds the proofs of
a published release from public values (its `measurements.json`, the entry of that statement on
rekor.sigstore.dev, and its `release-statement.sigstore.json`, the attestation of a job of the
release workflow): they run against the constants of the program as they are, with the deploy
keys of the test and without the element of that release in the list. The program refuses them at
the workflow of the job, and a program that holds the workflow and the commit of that certificate
passes every check. The endorsement cases of `protocol/vectors.json` run through the program as well: the
program reads a release statement and the entry of its record as a node does.

`tests/prove.js` prints what the program makes of release proofs read from a file
(`node secure-program/tests/prove.js RELEASE_PROOFS_JSON [--attestation ATTESTATIONS_JSON]
[--node ATTESTATION_RESPONSE_JSON]... [--target prod|dev|alpha] [--program PROGRAM_JS]`): the
verdict of the program of this checkout, or of the source `--program` names, with its constants as
they are and for a build of the server target named. Release proofs are public values, so whoever
makes or carries them can ask a version of the program for its verdict before a node of the
release takes a key.

A release may hold several attestations of its release statement: a job of the release workflow
makes one, and the job of the build workflow another, which is the one the program takes
(protocol.md, "The release proofs", P4). `--attestation` names a file with attestations: one
Sigstore bundle, bundles one a line, or the answer of the attestation API of GitHub
(`{attestations: [{bundle}]}`). For every bundle the file prints what P4 makes of it: each value
the certificate states of the run (the extensions `1.3.6.1.4.1.57264.1.{8..22}`) beside the value
the program requires, the other checks of the bundle as one line (the certificate under the
certificate authority at the time of the log entry, the signature of the envelope, the entry of
the log, its signed entry timestamp, its inclusion proof and its checkpoint), and the predicate
beside the statement. With `RELEASE_PROOFS_JSON` the attestation of the proofs is then the bundle
of that file the program takes. Without proofs,
`node secure-program/tests/prove.js --statement MEASUREMENTS_JSON --attestation ATTESTATIONS_JSON
[--program PROGRAM_JS]` prints that report alone for the file `measurements.json` of a release,
and its status is 0 when P4 holds for a bundle of the file.

The verdict on the proofs is that of the five checks on the proofs alone. The measurement a node
presents and the binding of that node are read from the attestation of the node: `--node` names a
file with what a node answered a request for its attestation (protocol.md 4.2), or with an answer
that carries such responses (`{nodes: [...]}`). For each response the file prints the three PCRs
of the document beside those of the statement and what the binding states (`release`, `log`,
`role`, `program_min`), and states whether the program hands that node a grant when the response
carries these proofs, or the check of the program that refuses it: a measurement that is not the
one of the statement, a binding whose `release` is not the release of the statement, a `log` that
is not the log store of the server target, a role that receives no grant, a `program_min` above
the version of the program. The certificate chain of the document is verified with the X.509
implementation of Node, against the root the program holds and at the time the document states,
and the nonce is taken from the document: the file judges an answer that was saved, not its
freshness. The status is 0 when the proofs make the release one the program accepts and every
node named presents the measurement of the statement and receives a grant.

`SECURE_PROGRAM_VECTORS` names the vector files to read instead of `protocol/vectors.json` (paths
separated by commas). A test of vectors that the files do not hold is skipped.

`node secure-program/tests/compare.js <program-a.js> <program-b.js>` runs the scenarios on two
versions of the program and prints what changed between them (the file of a tag is
`git show secure-program-v{N}:secure-program/secure-program.js`).

`tests/test_monitor.py` and `tests/test_accept_release.py` test the two Python tools of this
directory (`python3 -m unittest discover -s secure-program/tests`).

## Limits

- The operator can write a program that leaks the master key, sign it and record it. That program
  is a tag of this repository and an entry of the public log under the release key, so it can be
  read and found, but nothing stops it from being loaded: the notice period between the entry and
  the loading is zero, as for an enclave release (protocol.md 10.3).
- Serving an older release leaves no new entry. An app loads a served program only when its
  version is at least the version of the program the app ships with and at least the highest
  version that installation has loaded, so a new installation can be served any release from the
  shipped version on. The window closes with every app release that ships a newer program.
- The apps compile in the public key of the log. When Rekor signs with a new key, an app of an
  older build verifies no entry made after the change and loads no new program until the app is
  updated (the limit of a node is the same: README of this repository, "A change of the log key").
- The honesty of the log rests on the operation of Sigstore Rekor. An app verifies the inclusion
  proof and the signed checkpoint, so it has shown that the log signed a tree that holds the entry.
  That everyone is shown the same tree is not shown without witnesses.
- The monitor [`.github/workflows/secure-program-monitor.yml`](../.github/workflows/secure-program-monitor.yml)
  asks the log every hour for the entries of the release key and compares them with the releases
  of this repository ([`monitor.py`](monitor.py)); an entry that no release explains opens an
  issue. A run that could not read the log or the statement of a release reports the entries it
  could not compare as not checked, not as unexplained, and a later run in which every entry is
  the statement of a release closes the issue. The guarantee of the apps does not rest on the
  monitor, and anyone can run the same comparison, or watch the whole log for the release key
  with the monitor of Sigstore (rekor-monitor).
- The app binaries are not open source. What this directory shows is the program, not that the
  binary runs it unchanged (README of this repository, "The honesty of the app").
