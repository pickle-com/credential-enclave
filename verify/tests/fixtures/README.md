# Fixtures of the tests of the verification tool

Test inputs of the tests in `verify/src/` and `verify/tests/offline.rs`. Only tests read
them: no built program contains them. The tests also read three documents of
`protocol/tests/fixtures/` (a document of another build and two documents of debug-mode
enclaves), which that directory describes.

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
