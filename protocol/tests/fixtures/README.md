# Fixtures of the attestation tests and of the release tests

Test inputs of the tests in `protocol/src/attestation.rs`, `protocol/src/release.rs`,
`protocol/src/certificate.rs`, `protocol/src/release_proofs.rs`, `enclave/src/attest.rs`,
`enclave/src/lineage.rs`, `enclave/src/platform/nitro.rs`, `enclave/src/tests/peer.rs` and
`verify/src/`. Only tests read them: no built program contains them. The shared cases of the
release proofs and the published proofs of three releases are in `protocol/vectors/`, which has a
README of its own.

The certificate of a Nitro attestation document is valid for about three hours. The tests
pass at any time because the verification validates the certificate chain at the time the
document states, not at the time of the machine.

## `nitro-attestation-document.cbor`

- What it is: a Nitro attestation document (a COSE_Sign1 structure in CBOR, 4748 bytes) of a
  debug-mode enclave of another program. PCR0, PCR1 and PCR2 are all zero. Its user data
  (91 bytes) is a public key of that program and not a binding. Its nonce is 256 bytes. Its
  payload is a definite-length map. `module_id` `i-0918f6c55e3b61d89-enc018aa8b8e2285d13`,
  time 2023-09-18T15:03:30Z.
- Origin: the file `test-data/valid-attestation-doc-base64` of the repository
  <https://github.com/evervault/attestation-doc-validation>, as of its commit
  `6e477381464fbfefe1afa606052f9ad81b99120d` (2023-09-18). The file here is the base64
  decoding of that file: the same bytes in another encoding, with no other change.
- License: Apache License 2.0, the license of that repository (its `LICENSE` file; it has no
  `NOTICE` file). The text of that license is the `LICENSE` file at the root of this
  repository.
- SHA-256: `6f80ac250af2f06f1e423051f64a8b29926cc474a728d0bf1f7a4d21074ec9e5`

## `nitro-attestation-document-operational.cbor`

- What it is: a Nitro attestation document (4639 bytes) of a production-mode enclave, the
  answer to an attestation call of a node. Its user data is the binding of that node
  (release `v0.0.0-diag.local`, a diagnostic build) and its nonce is
  `ccaba542c08b40eece75fa9c337500d56d5670def7168bd932b358fe9552df4b`. Its payload is an
  indefinite-length map, the form the Nitro Secure Module writes. `module_id`
  `i-00e27c4213a488340-enc01a0f59ef3fce7ac`, time 2026-10-01T04:00:55Z.
- Origin: recorded by the maintainers of this repository from an enclave of the alpha
  environment of the service.
- License: the license of this repository (Apache License 2.0).
- SHA-256: `fb19375b2929d39281b5894cc88b8f584741479b1d1dc39cf9b3859314da57fd`

## `nitro-attestation-document-boot.cbor`

- What it is: a Nitro attestation document (4461 bytes) as a node receives it from its own
  Nitro Secure Module at boot, issued to a debug-mode enclave. PCR0, PCR1 and PCR2 are all
  zero, user data and nonce are null. Its payload is an indefinite-length map. `module_id`
  `i-00e27c4213a488340-enc01a0f58c05ad8fe0`, time 2026-10-01T03:39:51Z.
- Origin: recorded by the maintainers of this repository from an enclave of the alpha
  environment of the service.
- License: the license of this repository (Apache License 2.0).
- SHA-256: `105d27b5da899ed8e9f4815f240e72262ae18181b2582101cfc20a07de09d309`

## `unrelated-root.der`

- What it is: a self-signed X.509 certificate of a certificate authority (DER, 503 bytes)
  with the subject `CN=unrelated-root, O=Pickle Test` and an ECDSA P-384 key, valid from
  2026-09-30 to 2126-09-06. No document of this directory chains to it. The tests pass it as
  the trust root in the place of the AWS Nitro Enclaves Root-G1 and expect the verification
  to refuse the document as `Untrusted`: the copy of the AWS root that a document carries is
  not a ground for trust. Its private key is not in this repository.
- Origin: made by the maintainers of this repository for these tests.
- License: the license of this repository (Apache License 2.0).
- SHA-256: `24d6b5c9f929a8063e17c5e94187d3fdc123ac4a847e24cc0ef54b6a7cd92639`

## `rekor-entry-150000000.json`

- What it is: the entry with the index 150,000,000 of the transparency log Rekor of
  rekor.sigstore.dev, as an object of what the log returned for it: `body` (a `hashedrekord` of
  version 0.0.1 of another signer, in standard base64), `integrated_time` (1732051154,
  2024-11-19T21:19:14Z), `log_index`, `log_id` and `signed_entry_timestamp`. The key `uuid` is
  the identifier of the entry in the log. The tests verify the signed entry timestamp with the
  log key of the node program (`enclave/release/rekor-key.pem`): this fixes, against a real
  entry, the bytes the log signs for an entry (protocol.md 9.4, rule 4 of the entry).
- Origin: the response of `GET https://rekor.sigstore.dev/api/v1/log/entries?logIndex=150000000`.
  `body` is the `body` of that response without a change. `integrated_time`, `log_index`,
  `log_id` and `signed_entry_timestamp` are its `integratedTime`, `logIndex`, `logID` and
  `verification.signedEntryTimestamp`.
- License: the entry is a public record of the log. The file is under the license of this
  repository (Apache License 2.0).
- SHA-256: `c340515579e40b7305f1ad7a5c868291edcd589fd06de23f082bc82bfbf53954`

## `rekor-log2025-1-key.pem`

- What it is: the public key of the transparency log log2025-1.rekor.sigstore.dev (Ed25519, a
  SubjectPublicKeyInfo in PEM), a log of the form Rekor v2. No program holds it: a node takes no
  entry of that log, which signs no entry timestamp and which the monitor of this repository
  does not read (protocol.md 10.3). The test of `enclave/src/lineage.rs` names it as the one
  transparency log of the trusted root below that the node program holds no key for.
- Origin: the `publicKey.rawBytes` of the transparency log `https://log2025-1.rekor.sigstore.dev`
  of `sigstore-trusted-root.json` below, in PEM.
- License: a public key is a public value. The file is under the license of this repository
  (Apache License 2.0).
- SHA-256: `8510d81fd7fc7d8a6dd1f2c6ebeade515b79baa6137aa9c02fc97f8509becd75`

## `sigstore-trusted-root.json`

- What it is: the trusted root of the public instance of Sigstore (6,787 bytes). Its `tlogs`
  names the transparency logs of that instance, each with its address (`baseUrl`), its public
  key (`publicKey.rawBytes`, the DER of the SubjectPublicKeyInfo in standard base64, with
  `keyDetails`) and its log identifier (`logId.keyId`, in standard base64): rekor.sigstore.dev
  (ECDSA P-256, valid from 2021-01-12) and log2025-1.rekor.sigstore.dev (Ed25519, valid from
  2025-09-23). Its `certificateAuthorities` names the certificate authorities of that instance,
  each with its certificate chain (`certChain.certificates`, the DER of each certificate in
  standard base64) and its validity. The test of `enclave/src/lineage.rs` compares the values of
  the node program with it (`enclave/release/`): every log of the file is the log of
  `rekor-key.pem`, with the log identifier the file states, or the log of
  `rekor-log2025-1-key.pem` above, and the two certificates of the node program are the chain
  of the one certificate authority of the file whose validity has no end. The workflow
  `trusted-root-monitor.yml` compares the `tlogs` and the `certificateAuthorities` of the
  trusted root that the TUF repository of Sigstore distributes with those of this file every
  hour (`secure-program/monitor.py --trusted-root`, enclave.md 11.2): when they differ, this
  file is replaced by the trusted root as it is distributed then, and the values and the test
  follow. The other parts of the file (the certificate transparency logs, the timestamp
  authority) are not read.
- Origin: `targets/trusted_root.json` of the repository
  <https://github.com/sigstore/root-signing>, as of its commit
  `c09d62f9397fcff8b98b5bcd2dc9044a4f853cd4` (2026-11-23), without a change. The TUF
  repository of Sigstore distributed the same bytes on that day:
  `https://tuf-repo-cdn.sigstore.dev/targets/6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66.trusted_root.json`,
  the target `trusted_root.json` of its `targets.json` of version 14.
- License: Apache License 2.0, the license of that repository. The text of that license is the
  `LICENSE` file at the root of this repository.
- SHA-256: `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`

## `fulcio-certificate-v2.4.0-rc.1.der`

- What it is: the certificate of the attestation of the release statement of the release
  candidate `v2.4.0-rc.1` of this repository (X.509, DER, 1930 bytes): the certificate that the
  certificate authority of the public instance of Sigstore issued to the job of the build
  workflow that built that release, for an ECDSA P-256 key, valid from 2026-11-24T17:48:31Z to
  2026-11-24T17:58:31Z, under the intermediate certificate
  `enclave/release/fulcio-intermediate.pem`. Its extensions `1.3.6.1.4.1.57264.1.{number}` state
  the run: the build workflow `.github/workflows/enclave-build.yml` at the commit
  `3f84e8368fcdf1f89e42ca629670bfe0989b6f13` (9 and 10), a runner GitHub hosts (11), the
  repository `https://github.com/pickle-com/credential-enclave` with the identifiers
  `1400118248` and `151645824` (12, 15 and 17), the commit
  `4c21e0083064aec5300f6f8472a796607e83d9f3` and the ref `refs/tags/v2.4.0-rc.1` (13 and 14), the
  push that started the run (20) and the visibility `public` (22). The tests read the
  certificate and its extensions with the reader of the protocol crate, verify that the
  intermediate certificate issued it, and validate its path at the two ends of its validity.
- Origin: `verificationMaterial.certificate.rawBytes` of
  `protocol/vectors/published/v2.4.0-rc.1/release-statement.sigstore.json`, decoded from
  standard base64 without a change.
- License: a certificate of a public attestation is a public value. The file is under the
  license of this repository (Apache License 2.0).
- SHA-256: `409a56076de2836d460b02ccf40fb00a73dc77a4c3472d2c4c2118f5af2ec443`
