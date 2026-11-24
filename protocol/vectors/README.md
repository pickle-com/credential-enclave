# The shared cases of the release proofs

Release proofs are the public build proof of the measurement of a release
([docs/protocol.md](../../docs/protocol.md) section 9): the release statement of the release and
the Sigstore bundle of its attestation by the job of the build workflow. A node accepts a node of
another release by them, and so does the secure program of the apps. This directory holds the
file that holds the implementations of the checks to one verdict on the same input, the script
that writes it, and the published proofs of three releases that the script reads.

| File | What it is |
| --- | --- |
| `release-proofs.json` | 335 cases: release proofs as JSON text, the measurement they are verified for, the values they are verified with, and the verdict: accepted with the release their statement names, or refused with the check that refuses them (`form`, or `V1` to `V7` of protocol.md 9.4). protocol.md section 13 states the form of the file |
| `release_proofs.py` | The script that writes `release-proofs.json`. It shares no code with a verifier |
| `published/v2.4.0-rc.2/` | `measurements.json` (2,128 bytes) and `release-statement.sigstore.json` (12,845 bytes): two assets of the GitHub release `v2.4.0-rc.2` of this repository, without a change. The job of the build workflow `.github/workflows/enclave-build.yml` at the commit `e522d06d8388bee590678963f8940cd7a2b69f5c`, the build workflow a verifier of this source lists, built that release candidate from the commit `ebf4358294a6a1e92db804ab3286684b232f8981` on 2026-11-24 and made the attestation: a verifier of this source takes it. SHA-256 `f556f4fa0a32401c1c34ec504b7e4196a6a1a4748d77efd10b8dfc498b9cae1c` and `fdefdad6b4abf74f422914b3342afde81fa064bff9539ed1b0bf66e82ac99cbe` |
| `published/v2.4.0-rc.1/` | `measurements.json` (2,128 bytes) and `release-statement.sigstore.json` (12,896 bytes): two assets of the GitHub release `v2.4.0-rc.1` of this repository, without a change. The job of the build workflow `.github/workflows/enclave-build.yml` at the commit `3f84e8368fcdf1f89e42ca629670bfe0989b6f13` built that release candidate from the commit `4c21e0083064aec5300f6f8472a796607e83d9f3` on 2026-11-24 and made the attestation: it is the first public build proof of this repository. The node program of that tag hands delegations on under a signature of the operator, so no verifier of this source lists that commit of the build workflow file, and none takes this attestation. SHA-256 `bf30758914f71fcad01a61d09330a2dc708155a56900f780947ce7e95d3c40f4` and `65c5402ff6a3e29f8a7d7ac1daafdff2bb4be7473cdc0b861ff6146728cb75ff` |
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
  the verdict of every case as well. A check of it loads the program on the model of the bridge
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
  repository with its two identifiers, and a list of build workflows.
- The trust `test` and the five trusts whose names begin with `test-` hold values of the
  script. The private keys behind them are keys of the script: it signs the certificates, the
  envelopes, the entries and the checkpoints of its cases with them, so every part of a case
  holds except the one value the case changes, and the check the case names is the one it
  fails. Every private key follows from a fixed label inside the script. The keys are trusted
  by nothing but the cases that name them: no program compiles them in.
- The two trusts whose names begin with `sigstore-` hold the two certificates of the
  certificate authority of Sigstore and the key of Rekor, which the script reads from
  `enclave/release/`, with a list of build workflows that is not the one of this source.
  `sigstore-build-workflow-v2.4.0-rc.1` names the build workflow at the commit whose job
  attested the release candidate `v2.4.0-rc.1`: under it the published proofs of that release
  candidate pass, and those of the release candidate `v2.4.0-rc.2` are refused at `V6`.
  `sigstore-release-workflow-v2.3.0` names the release workflow of the tag `v2.3.0` at the
  commit of that tag: under it the published proofs of the release `v2.3.0` pass, and those of
  the release candidate `v2.4.0-rc.2` are refused at `V6`.
- `source` stands for the values of the verifier itself: for the node, the files of
  `enclave/release/` (the two certificates of the certificate authority of Sigstore, the key of
  Rekor, the list of build workflows) and the repository of this source. The cases of this
  trust are made of the published proofs of `published/`. The proofs of the release candidate
  `v2.4.0-rc.2` pass: the job of the build workflow at the commit the list of this source
  names attested it. The same proofs with one value changed are refused. No key of the script
  signs them, so a changed value is refused by the first check it breaks, and a changed value
  that no check reads (the `inputs` of the statement) leaves the proofs accepted. The proofs
  of the release candidate `v2.4.0-rc.1` and of the release `v2.3.0`, as they are, are refused
  at `V6`: the list of build workflows of this source names neither the commit of the build
  workflow file whose job attested that release candidate nor the release workflow of the tag
  `v2.3.0`.

## Writing the file again

```bash
python3 protocol/vectors/release_proofs.py            # writes release-proofs.json
python3 protocol/vectors/release_proofs.py --check    # fails when the committed file differs
```

The script needs Python 3.11 or later and the package `cryptography` 43 or later, linked with
OpenSSL 3.2 or later: it signs with deterministic ECDSA (RFC 6979), so a second run writes the
same bytes. It reads the files of `published/` and the files of `enclave/release/`, and nothing
else. The job `check` of `.github/workflows/check.yml` runs the script with `--check` on every
push to a branch and on every pull request, in a new Python virtual environment into which it
installs three packages at fixed versions and nothing else: `cryptography` 50.0.2 and the two
packages it depends on, `cffi` 2.1.0 and `pycparser` 3.0. `cargo test` reads the committed
file. After a change of the script, of `enclave/release/` or of `published/`, the file is
written again and committed with the change, and every verifier that reads the file passes
with it.

A case is added for a value that two readers could read differently: the bounds of a length, a
form of a number, a member that occurs twice, an encoding with spare bits. The verdict of a new
case is the verdict the checks of protocol.md 9.4 give, and a case on which the two
implementations disagree is a fault of one of them, not a case to remove.
