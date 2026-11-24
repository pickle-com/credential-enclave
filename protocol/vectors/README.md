# The shared cases of the release proofs

Release proofs are the public build proof of the measurement of a release
([docs/protocol.md](../../docs/protocol.md) section 9): the release statement of the release and
the Sigstore bundle of its attestation by the job of the build workflow. A node accepts a node of
another release by them, and so does the secure program of the apps. This directory holds the
file that holds the implementations of the checks to one verdict on the same input, the script
that writes it, and the published proofs of two releases that the script reads.

| File | What it is |
| --- | --- |
| `release-proofs.json` | 330 cases: release proofs as JSON text, the measurement they are verified for, the values they are verified with, and the verdict: accepted with the release their statement names, or refused with the check that refuses them (`form`, or `V1` to `V7` of protocol.md 9.4). protocol.md section 13 states the form of the file |
| `release_proofs.py` | The script that writes `release-proofs.json`. It shares no code with a verifier |
| `published/v2.4.0-rc.1/` | `measurements.json` (2,128 bytes) and `release-statement.sigstore.json` (12,896 bytes): two assets of the GitHub release `v2.4.0-rc.1` of this repository, without a change. The job of the build workflow `.github/workflows/enclave-build.yml` at the commit `3f84e8368fcdf1f89e42ca629670bfe0989b6f13` built that release candidate from the commit `4c21e0083064aec5300f6f8472a796607e83d9f3` on 2026-11-24 and made the attestation: it is the first public build proof of this repository. SHA-256 `bf30758914f71fcad01a61d09330a2dc708155a56900f780947ce7e95d3c40f4` and `65c5402ff6a3e29f8a7d7ac1daafdff2bb4be7473cdc0b861ff6146728cb75ff` |
| `published/v2.3.0/` | `measurements.json` (1,824 bytes) and `release-statement.sigstore.json` (12,192 bytes): two assets of the GitHub release `v2.3.0` of this repository, without a change. A job of the release workflow of that tag (`.github/workflows/release.yml` at the commit of the tag, `29d450c2867b9c198c2f9680905a11120178d2b5`) made the attestation, before the build workflow existed: no verifier of this source takes it. SHA-256 `2b5c57bd52be6898a8e36c3ec123c7845a1eb5c208cdd6534da6c883978092f3` and `30fb25f0ed95d3690d22e1cfa8e28b86dc4638cf5b86932b84ff9763059a604f` |

The published files are public records: a release statement and the bundle of an attestation
that the public transparency log holds. They are under the license of this repository (Apache
License 2.0).

## Who reads the file

- The node implementation: `protocol/tests/release_proofs.rs` runs `verify_release_proofs` of
  `protocol/src/release_proofs.rs` on every case and compares the verdict, the release and the
  check with the file. It also requires at least five cases of every verdict. `cargo test` runs
  it.
- The secure program of the apps: `proveRelease` of `secure-program/secure-program.js` must give
  the verdict of every case as well. Its check loads the program on the model of the bridge
  (`secure-program/tests/bridge.js`), parses `release_proofs_text` inside the program, builds a
  trust of the file from `fulcio_root`, `fulcio_intermediate`, `log_keys` and `builders`, takes
  the constants of the program for `source`, and compares the verdict and the release with the
  file.
- The tests of the node program that need release proofs for a measurement
  (`enclave/src/testing.rs`) take them from the cases by name.

## The values a case is verified with

A case names a trust: a member of `trusts` of the file, or `source`.

- A trust of the file holds the root certificate and the intermediate certificate of a
  certificate authority, the keys of the transparency logs, the issuer of the tokens, the
  repository with its two identifiers, and a list of build workflows. The private keys behind
  them are keys of the script: it signs the certificates, the envelopes, the entries and the
  checkpoints of its cases with them, so every part of a case holds except the one value the
  case changes, and the check the case names is the one it fails. Every private key follows
  from a fixed label inside the script. The keys are trusted by nothing but the cases that name
  them: no program compiles them in.
- `source` stands for the values of the verifier itself: for the node, the files of
  `enclave/release/` (the two certificates of the certificate authority of Sigstore, the key of
  Rekor, the list of build workflows) and the repository of this source. The cases of this
  trust are the published proofs of `published/` and those proofs with one value changed. No
  key of the script signs them, so a changed value is refused by the first check it breaks.

## Writing the file again

```bash
python3 protocol/vectors/release_proofs.py            # writes release-proofs.json
python3 protocol/vectors/release_proofs.py --check    # fails when the committed file differs
```

The script needs Python 3.11 or later and the package `cryptography` 43 or later, linked with
OpenSSL 3.2 or later: it signs with deterministic ECDSA (RFC 6979), so a second run writes the
same bytes. It reads the files of `published/` and the files of `enclave/release/`, and nothing
else. The workflows of this repository do not run it: `cargo test` and the tests of the secure
program read the committed file. After a change of the script, of `enclave/release/` or of
`published/`, the file is written again and committed with the change, and both test suites
pass with it.

A case is added for a value that two readers could read differently: the bounds of a length, a
form of a number, a member that occurs twice, an encoding with spare bits. The verdict of a new
case is the verdict the checks of protocol.md 9.4 give, and a case on which the two
implementations disagree is a fault of one of them, not a case to remove.
