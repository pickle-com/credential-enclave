# Fixtures of the tests of the verification tool

Test inputs of the tests in `verify/src/`, `verify/tests/offline.rs` and
`verify/tests/program.rs`. Only tests read them: no built program contains them. The tests
also read three documents of `protocol/tests/fixtures/` (a document of another build and two
documents of debug-mode enclaves), which that directory describes.

The certificate of a Nitro attestation document is valid for about three hours. The tests
pass at any time because the verification validates the certificate chain at the time the
document states, not at the time of the machine.

## `nitro-attestation-alpha-prerelease.cbor` and `nitro-attestation-alpha-prerelease.cbor.nonce`

- What it is: a Nitro attestation document (a COSE_Sign1 structure in CBOR, 4627 bytes) of
  a production-mode enclave that ran a build made before the first release of this repository,
  the answer to an attestation call of a node. That build carried the tag `v1.0.0` and came
  from a commit that is not part of the history of this repository: its measurements are not
  those of release v1.0.0. The `.nonce` file holds the 32 bytes of the nonce of that call
  (`488818963c99ac32f3c43f92a73f1ee1978e32ed1a597020cb0efaf2957978de` in hex). PCR0, PCR1
  and PCR2 of the document are those of `measurements-prerelease.json`. Its user data is the
  binding of the node `Vpgk3Ygj_gz6Sy-9R8y7wgparrJ8ZseizfJiB8ZLmRE` with the release tag of
  that build, `v1.0.0`. `module_id` `i-00e27c4213a488340-enc01a0f5b621ecd411`, time 2026-10-01T04:26:30Z.
- Origin: recorded by the maintainers of this repository from an enclave of the alpha
  environment of the service.
- License: the license of this repository (Apache License 2.0).
- SHA-256: `7b3cdc1ee62fe725f157a6f13ce486e12dc110f7cd9182d0b6efffc69b679269` (the document),
  `8af79b6d107bdc5419b3889117f8abc084e501c4407e7e27f340a6b307762591` (the nonce)

## `measurements-prerelease.json`

- What it is: the `measurements.json` of the build that the document above comes from, as
  `build/build.sh eif` wrote it: PCR0, PCR1 and PCR2 of the enclave image file of that build
  and the table of the inputs of the build. It is a test input, not the measurements of a
  release: those are in the GitHub release of the tag.
- Origin: written by the build of that enclave image file, kept by the maintainers of this
  repository.
- License: the license of this repository (Apache License 2.0).
- SHA-256: `22edae8512f61915751eb9bf5f2ae80031827c1dec4362caf63614affc842d81`

## `rekor-entry-3267788759.json`

- What it is: the entry with the index 3,267,788,759 of the transparency log Rekor of
  rekor.sigstore.dev, as `GET https://rekor.sigstore.dev/api/v1/log/entries?logIndex=3267788759`
  returned it (3581 bytes, one line): an object with one key, the identifier of the entry
  (`108e9186e8c5677a63cc4d501459567a29567f204a5b99893f0f308be228598b697b841179ea53ab`), whose
  value holds `body` (the `hashedrekord` of version 0.0.1 of the endorsement of the enclave
  release v1.5.2 of this repository, signed by the release key, in standard base64),
  `integratedTime` (1792090738), `logIndex`, `logID`
  (`c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d`, the log key of
  `enclave/release/rekor-key.pem`) and `verification` with `signedEntryTimestamp` and
  `inclusionProof` (`logIndex` 3145884497 in the shard, `treeSize` 3165115354, `rootHash`, 31
  `hashes`, `checkpoint`). The tests of `verify/src/program.rs` turn it into the `entry` of a
  release proof and run checks 5 to 10 of protocol.md, "The secure program release", against
  the compiled-in release key and log key: this fixes, against a real entry, the bytes the log
  signs, the path computation of the inclusion proof and the form of the checkpoint.
- Origin: the response of that request, recorded by the maintainers of this repository on
  2026-10-17. The repository `pickle-com/interactive-character` holds a byte-identical copy at
  `client/fixtures/rekor-entry-3267788759.json` for the tests of the apps.
- License: the entry is a public record of the log. The file is under the license of this
  repository (Apache License 2.0).
- SHA-256: `3833365ac4febb7c526976a54aa87172c01154b70dbb7ad15ad662a2535f985b`

## `endorsement-v1.5.2-statement.b64u`

- What it is: the statement of the entry above, in base64url without padding (2433 characters,
  one line): the 1824 bytes of `measurements.json` of the GitHub release v1.5.2 of this
  repository (release `v1.5.2`, commit `2dcf8957a4afb78a1c0400e3d37df0053faa97ad`). The SHA-256
  of the decoded bytes, `a3be7d71d7f2d15a969a4d9201cead9dfbc9ae720f34d4c1de1a76ce402317d8`, is
  `spec.data.hash.value` of the body of the entry.
- Origin: the value `statement` of the endorsement `v1.5.2` in
  `backend/assets/credential-enclave/endorsements.json` of `pickle-com/interactive-character`,
  which `infra/secrets/endorse-enclave-release.py` of that repository wrote when it recorded
  the entry.
- License: the license of this repository (Apache License 2.0).
- SHA-256: `44f55df0514bb328ce76ed5d9ff8558e6d4636fb05f16ff0e470d48b084e1f56`

## `secure-program/`

Five files for `verify/tests/program.rs`: a synthetic release proof of a synthetic program, made
with two throw-away ECDSA P-256 keys whose private halves were not kept. The tests pass the two
public keys with `--release-key` and `--log-key`; under the compiled-in keys the proof fails at
check 5 (`unknown_log`), which the tests check as well.

- `source.js` (190 bytes): a program of six lines that declares `const VERSION = 27;` and
  defines nothing else. Its SHA-256,
  `a4610f0a732e639bb818fadc7a51b373c6629d42e4d603333c4949f0bf7d52d0`, is the `sha256` of both
  statements below.
- `release-key.pem` (178 bytes): the public key that stands for the release key. SHA-256
  `5a06d989de7fb54d6fc09364a883cb2fc4979dd697f8e300191bb79b1896a02d`.
- `log-key.pem` (178 bytes): the public key that stands for the log key. Its log identifier is
  `4ee42dc6266ac1b77225b3f7395d6a5242e806c53b5aa062fc823725c53d9c5c`. SHA-256
  `67a763aefdecf654ede9a25042c5a434260bf5e578a5a25e961be5826c5f9f58`.
- `release.json` (1843 bytes): a release proof that holds: the statement of `secure-program-v27`
  (version 27, the commit `7777777777777777777777777777777777777777`), a `hashedrekord` body
  signed by the release key, a signed entry timestamp of the log key (integrated time
  1792000000, global index 42, the log identifier above) and the inclusion proof of a tree of
  one leaf (index 0 in the shard, tree size 1, no path, the root equal to the leaf) with a
  checkpoint of the origin `rekor.test - 1` signed by the log key. SHA-256
  `affeaf0ee592e58a7209cd97d3530f1293e1e41163f56e9910b72cbe0872378d`.
- `release-version-28.json` (1843 bytes): the same, with a statement of `secure-program-v28`
  (version 28) over the same file: the verification ends at check 4 (`version_mismatch`).
  SHA-256 `1f656f42f1aaec711fc5907613280789f8eb0d61ec029762ae78de71bac4c714`.
- Origin: generated by the maintainers of this repository with the statement function of the
  backend of `pickle-com/interactive-character` and the Python `cryptography` package.
- License: the license of this repository (Apache License 2.0).
