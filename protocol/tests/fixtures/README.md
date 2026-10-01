# Fixtures of the attestation tests

Test inputs of the tests in `protocol/src/attestation.rs`, `enclave/src/attest.rs`,
`enclave/src/platform/nitro.rs` and `verify/src/`. Only tests read them: no built program
contains them.

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
