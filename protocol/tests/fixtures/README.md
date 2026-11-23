# Fixtures of the attestation tests and of the release tests

Test inputs of the tests in `protocol/src/attestation.rs`, `protocol/src/release.rs`,
`protocol/tests/endorsement_vectors.rs`, `enclave/src/attest.rs`, `enclave/src/lineage.rs`,
`enclave/src/platform/nitro.rs`, `enclave/src/tests/peer.rs` and `verify/src/`. Only tests read
them: no built program contains them.

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
  rekor.sigstore.dev, in the form of the `entry` of an endorsement (protocol.md 10.3): `body`
  (a `hashedrekord` of version 0.0.1 of another signer, in standard base64), `integrated_time`
  (1732051154, 2024-11-19T21:19:14Z), `log_index`, `log_id` and `signed_entry_timestamp`. The
  key `uuid` is the identifier of the entry in the log. The tests verify the signed entry
  timestamp with the log key of the node program (`enclave/release/rekor-key.pem`): this fixes
  the bytes the log signs for an entry.
- Origin: the response of `GET https://rekor.sigstore.dev/api/v1/log/entries?logIndex=150000000`.
  `body` is the `body` of that response without a change. `integrated_time`, `log_index`,
  `log_id` and `signed_entry_timestamp` are its `integratedTime`, `logIndex`, `logID` and
  `verification.signedEntryTimestamp`.
- License: the entry is a public record of the log. The file is under the license of this
  repository (Apache License 2.0).
- SHA-256: `c340515579e40b7305f1ad7a5c868291edcd589fd06de23f082bc82bfbf53954`

## `rekor-log2025-1-entry-200000163.json`

- What it is: the entry with the index 200,000,163 of the transparency log
  log2025-1.rekor.sigstore.dev, a log of the form Rekor v2, in the form of the `entry` of an
  endorsement (protocol.md 10.3): `log_id` (the log identifier of that log), `body` (a
  `hashedrekord` of version 0.0.2 under the ECDSA P-256 public key of another signer, in
  standard base64: the form of the entry of a key its holder keeps, which the entry of the
  release key has) and `inclusion_proof` with `log_index`, `hashes` (the audit path of the
  entry in a tree of 212,315,329 leaves, 28 hashes in lower-case hexadecimal) and `checkpoint`
  (the note of that tree head with the signature of the log and the signatures of four
  witnesses). The tests verify the checkpoint and the audit path with the key of that log
  (`rekor-log2025-1-key.pem` below): this fixes, against a real entry, the hash of the leaf
  of an entry, the bytes the log signs for a tree head, the key ID of its signature and the
  form of the body.
- Origin: read from the log on 2026-11-23 by the read addresses of a tiled log
  (c2sp.org/tlog-tiles): `GET https://log2025-1.rekor.sigstore.dev/api/v2/checkpoint` for the
  checkpoint, the entry bundle `api/v2/tile/entries/x781/250` for the body (its entry 163),
  and the hash tiles `api/v2/tile/0/x781/250`, `api/v2/tile/0/x829/356.p/193`,
  `api/v2/tile/1/x003/051`, `api/v2/tile/1/x003/239.p/172`, `api/v2/tile/2/011`,
  `api/v2/tile/2/012.p/167` and `api/v2/tile/3/000.p/12` for the audit path, which is computed
  from them by RFC 6962 section 2.1.1. `body` is the bytes of the entry in standard base64,
  and the checkpoint is the text of the response without a change.
- License: the entry is a public record of the log. The file is under the license of this
  repository (Apache License 2.0).
- SHA-256: `f73aa39da77b5bc1257a0640bf1f2a3abb326a02132c3658763aad73391c81a8`

## `rekor-log2025-1-key.pem`

- What it is: the public key of the transparency log log2025-1.rekor.sigstore.dev (Ed25519, a
  SubjectPublicKeyInfo in PEM), a log of the form Rekor v2. No program holds it: the table of
  transparency logs of the node program has no row for that log, which the monitor of this
  repository does not read (protocol.md 10.3). The tests of the form Rekor v2 verify a real
  entry of the log with it, and the tests of `enclave/src/lineage.rs` compare it with the
  trusted root below.
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
  2025-09-23). The test of `enclave/src/lineage.rs` compares the table of transparency logs of
  the node program with it: every log of the file has a row with its key, and the log
  identifier of that row is the one the file states. The workflow `trusted-root-monitor.yml`
  compares the `tlogs` of the trusted root that the TUF repository of Sigstore distributes with
  the `tlogs` of this file every hour (`secure-program/monitor.py --trusted-root`, enclave.md
  11.2): when they differ, this file is replaced by the trusted root as it is distributed then,
  and the table and the test follow. The other parts of the file (the certificate authorities,
  the certificate transparency logs, the timestamp authority) are not read.
- Origin: `targets/trusted_root.json` of the repository
  <https://github.com/sigstore/root-signing>, as of its commit
  `c09d62f9397fcff8b98b5bcd2dc9044a4f853cd4` (2026-11-23), without a change. The TUF
  repository of Sigstore distributed the same bytes on that day:
  `https://tuf-repo-cdn.sigstore.dev/targets/6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66.trusted_root.json`,
  the target `trusted_root.json` of its `targets.json` of version 14.
- License: Apache License 2.0, the license of that repository. The text of that license is the
  `LICENSE` file at the root of this repository.
- SHA-256: `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`

## `endorsement-vectors.json`

- What it is: 22 endorsements for the test `protocol/tests/endorsement_vectors.rs`, made by an
  implementation that shares no code with this repository (Python with the `cryptography`
  package). `release_key_pem` and `log_key_pem` are a test release key and a test log key
  (ECDSA P-256, made for this file; their private keys were not kept). Each element of `cases`
  holds a `name`, the `endorsement` (protocol.md 10.3), the release of the giving node
  (`own_release`), its clock in Unix epoch seconds (`now`) and the verdict `ok`. Four cases
  hold. Each of the others breaks one check: the log id, the signed entry timestamp (another
  log key, a changed time, a changed index), the hash of the statement, the logged public key,
  the release signature, the time of the entry, the order of releases, the form of the
  statement, and the alphabet of the body.
- Origin: generated by the maintainers of this repository.
- License: the license of this repository (Apache License 2.0).
- SHA-256: `7436ad9b3d4c32053531f1aed5d3f326ac43d9a5893b186f66a25743aa103246`

## `endorsement-vectors-rekor-v2.json`

- What it is: 108 endorsements for the test `protocol/tests/endorsement_vectors.rs`, made by an
  implementation that shares no code with this repository (Python with the `cryptography`
  package), for a giving node whose table holds a log of each form. `release_key_pem` is a test
  release key (ECDSA P-256), `log_origin`, `log_key_pem` and `log_id` are the origin, the key
  (Ed25519) and the log identifier of a test log of the form Rekor v2, and
  `rekor_v1_log_key_pem` is the key (ECDSA P-256) of a test log of the form Rekor v1. The keys
  were made for this file, and their private halves were not kept. Each element of `cases`
  holds a `name`, the `endorsement` (protocol.md 10.3), the release of the giving node
  (`own_release`), its clock in Unix epoch seconds (`now`) and the verdict `ok`. 22 cases hold:
  an entry at different places of trees of 1 to 257 leaves, a checkpoint with the signatures
  of witnesses, with an extension line and with a line of another key under the name of the
  log, an entry with keys a node does not read, a body with a key a node does not read, and an
  entry of the log of the form Rekor v1. Each of the others breaks one rule: the log
  identifier, the form of the entry of its log, the inclusion proof as a value, the checkpoint
  (no signature of the log, the signature of another key, another key ID, another name, a
  second line of the log that does not verify, another origin, a size or a root that is not
  the one the log signed or does not have its form, a line the log did not sign), the audit
  path (a changed, missing or added hash, a hash of another form, another index, the path of
  another entry, the checkpoint of a later tree, another body than the leaf), the body (the
  record of another statement or of another key, another signature, another version, kind,
  algorithm or kind of key, a certificate in the place of the key, a key that occurs twice,
  the record of the other form), the statement, the order of releases, and the shape of the
  endorsement.
- Origin: generated by the maintainers of this repository.
- License: the license of this repository (Apache License 2.0).
- SHA-256: `1be71b82fda3f394da9f8eb630e929bfef5ad02681782656fc0c5fa06c1a5f9c`
