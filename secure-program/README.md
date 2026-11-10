# The secure program

## What this is

`secure-program.js` is the program that the secure executor of the Pickle apps runs: the iOS app
in JavaScriptCore, the Android app in QuickJS. It is the program that [docs/protocol.md](../docs/protocol.md)
calls "the app": the device side of the credential protocol. It creates the master key and derives
the account keys from it (protocol.md section 3), verifies the attestation of enclave nodes
(section 4), seals grants and revokes to a verified node (section 5), encrypts credential records
(section 6), verifies and decrypts the credential log (section 7), keeps the ledger of the nodes
that hold a grant, and transfers the master key between the devices of one account. The program
reads the log store directly (protocol.md 7.4): it verifies the log from the keys of the object
version listing of the account's prefix up to the head a node signed (the index verification),
reads the control entries and the entries it shows, and counts the summary of the last seven days
of the log screen from the entries of that window (each read once per device and kept as the
summary tally). The storage of the operator holds no entry. The absence of an entry older than 365
days (the retention of its Object Lock) is expired, not an omission (protocol.md 7.4), and the
lifecycle rule of the bucket removes entries at 400 days (7.6). The program sends the requests of one
procedure that do not depend on each other together (the account query with the node list, the grants
to every node, the reads of one verification run in four stages: heads and listing addresses,
listings, object addresses, objects) and judges the results in the order protocol.md 7.4 gives. A
run that finds a node in the store only, with an entry sealed to the key of the account that no
traced transfer explains, reads the heads of the nodes of its ledger once more and walks those
chains on before it counts the node (the second look of protocol.md 7.4 step 5: a transfer of the
delegation that landed between the heads and the listing of the run is traced there); a run without
such a node reads nothing twice.

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

A reader checks this in the file. The search terms: `keychainSet` and `keychainGet` (where the
master key is stored and read), `hpkeSeal` (what is sealed to a node), `aeadSeal` (what is
encrypted as a record, and what the transfer seals), `native.http(` (every request the program
sends, with its body), `native.publish(` (every value the program hands to the user interface).

## How a release is made

1. The commit that changes the file sets `const VERSION` to a new N and is tagged
   `secure-program-v{N}`. The push of the tag starts the workflow
   [`.github/workflows/secure-program-release.yml`](../.github/workflows/secure-program-release.yml).
2. The workflow writes the release statement of the tag with [`statement.py`](statement.py) (it
   stops when the N of the tag is not the `VERSION` of the file), creates the GitHub release of the
   tag, and uploads `secure-program.js`, `statement.json` and a build provenance attestation of
   the file (`secure-program-provenance.sigstore.json`).
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

## The tests

`tests/` runs the program on a model of the bridge of the apps, with Node alone:

```bash
node --test secure-program/tests/program.test.js
```

`tests/bridge.js` is the model: the global `native` on the crypto module of Node (HKDF, Ed25519,
X25519, HPKE of RFC 9180, ChaCha20-Poly1305, ECDSA P-384), a device (the key store, the program
store, the published state), the backend of the operator and the log store as the program reaches
them over `native.http`, and enclave nodes with their keys, attestation documents, commands, heads
and log chains (`docs/protocol.md` sections 4, 5 and 7). The certificate chain of a nitro document
is modelled (one leaf of the model stands for the certificate); the signature of the document is a
real ECDSA signature over the Sig_structure the program encodes. The loader evaluates the program
the way the executors do: a fresh context whose globals are `native`, `SecureError` and `console`,
the top level evaluated with the bridge closed. The first tests check the model against
`protocol/vectors.json`, the reference the apps test their bridges against. `tests/scenarios.js`
holds the scenarios (worlds and runs) and returns plain results; `tests/program.test.js` fixes the
expected results of the current program.

`node secure-program/tests/compare.js <program-a.js> <program-b.js>` runs the scenarios on two
versions of the program and prints what changed between them (the file of a tag is
`git show secure-program-v{N}:secure-program/secure-program.js`).

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
