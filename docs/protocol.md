# Protocol specification (protocol v1)

This document is the single specification of the keys, the messages and the storage formats that
two programs implement together: the app (the program on the iPhone of an account that holds the
master key of that account) and the enclave node of this repository. The backend of the operator
carries and stores the values of this document. It does not create them and it does not open them.

| Term | Meaning |
| --- | --- |
| Account | One user of the service. An account has one master key, which its app creates |
| App | The iOS app of an account. "The app" in this document is the program inside it that implements this protocol |
| Node | One running instance of the node program of this repository: a process inside an AWS Nitro Enclave (platform `nitro`) or an ordinary process (platform `local`) |
| Operator | The company that runs the service. The operator domain is everything outside a node that the operator runs: the backend, its storage, the host program, the network |
| Provider | A service whose credentials a node holds for an account (Google and the others of the provider definitions) |
| Log store | The Amazon S3 bucket that a node writes every log entry to before the act the entry describes (7.6). Its objects are locked: until the retention of an object ends, nobody can delete it |

The calls of a node are in [enclave.md](enclave.md). The rules on what leaves a node are in
[egress-policy.md](egress-policy.md).

The formats of this document are fixed for all stages. A stage is a part of the format:

| Stage | Part of the format |
| --- | --- |
| 1 | Every item without a stage marker. The current release implements it |
| 2 | Witness signatures (7.5, 10.2) |
| 3 | The verification of release statements and of the public record by the app and by a node (section 9), the list of allowed measurements in a grant (4.5), the delegation transfer to a release of that list (10.1) |
| 4 | The sealed delivery of the authorization code (5.6) |

An item marked stage 2, 3 or 4 is a field or a message that the current release does not use.
Records and log entries that are already stored are not written again when a later stage comes
into use.

The log (section 7) has two formats. Format 1 is the format of the releases before v2.0.0: one
entry holds one event, and the key of its object in the log store is `{seq}-{hash}`. Format 2 is
the format of the releases from v2.0.0 on: one entry holds the events of one or more acts of one
account, and the key of its object carries the hash of the body and the hash of the chain. A node
writes one format for its whole life, the format of its release. A reader (the app) reads both:
the shape of the key tells the format. Entries that are already stored are not written again.

---

## 1. Common rules

| Item | Rule |
| --- | --- |
| Characters | JSON is UTF-8 and has no BOM |
| JSON serialization (the side that creates a value) | Serialization without whitespace (separators `,` and `:`). The keys of an object are in the order this document writes them. Integers are written without an exponent |
| JSON parsing (the side that receives a value) | Does not rely on the key order or on whitespace. Keys this document does not define are ignored. Exception: an unknown key of the `policy` object is refused (5.2) |
| Byte values | base64url without padding (RFC 4648 section 5). `b64u(x)` in this document |
| Times | A value whose name ends with `_ms` is an integer of milliseconds since the Unix epoch |
| Signatures | Ed25519 (RFC 8032). The signature input is the purpose string (ASCII, ends with `\n`) followed by the message bytes |
| Carriage of signed values | A signed JSON value is always carried as the pair `{"body": b64u(body bytes), "sig": b64u(signature)}`. The signature is verified over the received `body` bytes as they are, and `body` is parsed as JSON after that. An implementation that serializes the JSON again and verifies the result is not allowed |
| Hash | SHA-256 |
| Version | Every object carries `"v":1`, except the body of a log entry of format 2, which carries `"v":2` (7.1). The receiver refuses another `v` (`unsupported_version`) |
| Length limits | `user_id`, `provider` and `kind` are 1 to 128 characters long and hold no control character (U+0000 to U+001F) |

Identifiers:

| Name | Definition | Length |
| --- | --- | --- |
| `user_id` | The user id string of the operator's backend | Variable |
| `node` | `b64u(node signing public key, 32 bytes)`. It lives as long as the node process (it changes on a restart) | 43 characters |
| `key_id` | `hex(the first 8 bytes of SHA-256(account signing public key, 32 bytes))`, lower case | 16 characters |
| record `id` | `b64u(16 random bytes)` | 22 characters |
| `release` | The release tag of this repository (`v{major}.{minor}.{patch}`) | Variable |

In the examples of this document, `v1.0.0` stands for the release tag of the node.

## 2. Algorithms

| Use | Algorithm | Note |
| --- | --- | --- |
| Key derivation | HKDF-SHA256 (RFC 5869) | A derivation that names no salt uses the empty salt (length 0) |
| Account signature, node signature | Ed25519 | The private key is represented by its 32-byte seed |
| Public key sealing | HPKE base mode (RFC 9180), KEM DHKEM(X25519, HKDF-SHA256), KDF HKDF-SHA256, AEAD ChaCha20-Poly1305, single-shot seal | The output is `enc` (32 bytes) and `ct` (the ciphertext followed by the 16-byte tag) |
| Record encryption | ChaCha20-Poly1305 (RFC 8439), a random nonce of 12 bytes | The output `ct` is the ciphertext followed by the 16-byte tag |
| Chain | SHA-256 | |
| TOTP | RFC 6238, HMAC-SHA1, 6 digits, 30 seconds | Only a node computes it |
| Signature of a release statement, signed entry timestamp of the transparency log (10.3) | ECDSA P-256 with SHA-256, the signature in ASN.1 DER | Only a node verifies them. The two public keys are compiled into the node program |
| Attestation | Per platform (section 4) | |

The app performs every operation above with native functions of its binary, which call the
cryptographic implementation of the operating system. The program of the app that implements this
protocol is JavaScript, and it does not implement a cryptographic algorithm itself (reading a
format such as CBOR or DER is not an algorithm). This rule is the basis of the export compliance
declaration of the app (`ITSAppUsesNonExemptEncryption: false`).

## 3. Keys

```text
master key MK = 32 random bytes (the app creates it. An item of the synchronized iCloud Keychain)

account signing seed       = HKDF(ikm = MK, info = "pickle.secure.v1.sign", 32)      -> Ed25519 key pair, public key sign_pk
log decryption private key = HKDF(ikm = MK, info = "pickle.secure.v1.log", 32)       -> X25519 private key, public key log_pk
user key UK[enclave]       = HKDF(ikm = MK, info = "pickle.secure.v1.user-key", 32)
user key UK[operator]      = HKDF(ikm = MK, info = "pickle.secure.v1.user-key.operator", 32)
key_id                     = hex(SHA-256(sign_pk)[0..8])

record key                 = HKDF(ikm = the UK of the custody of that record, salt = the 16 bytes of the record id, info = "pickle.secure.v1.record", 32)

node signing seed, node sealing private key = two values of 32 random bytes that the node creates at boot (Ed25519, X25519)
node                       = b64u(node signing public key)
```

- Derived keys are not stored. A new use adds a new info string. The meaning of an existing info
  string does not change.
- An X25519 private key is the 32 bytes of the HKDF output as they are (the X25519 implementation
  does the clamping).
- The custody mode is the kind of node that holds a user key. It has two values: `enclave` (a node
  of platform `nitro` whose attestation the app verified) and `operator` (a node of platform
  `local`: an ordinary process that no attestation verifies). The user key is derived separately
  for each custody. The app hands a node only the user key of the custody that corresponds to the
  platform of that node: UK[enclave] does not go to a party that did not pass the attestation
  verification. For an account that had a period of custody `operator`, the records made after the
  move to custody `enclave` open only under a key that was never handed to the operator.
- Only a holder of the UK of a custody can create and open the records of that custody. The
  holders of a UK are the app (it derives the UK from MK), a node to which the app handed it with a
  grant (until an expiry, in memory), and a node to which that node transferred the delegation
  under the conditions of section 10: a node of the same measurement (10.1), or a node of a later
  release (10.3). There is no other holder.
- `key_id` is an 8-byte identifier for display and for early rejection. Where a binding is needed
  (statements, the comparison of a pending authorization with the grant, revocation), all 32 bytes
  of `sign_pk` are compared.

All purpose strings (no string outside this table is used):

| String | Where it is used |
| --- | --- |
| `pickle.secure.v1.sign`, `pickle.secure.v1.log`, `pickle.secure.v1.user-key`, `pickle.secure.v1.user-key.operator` | HKDF info of the derivations from MK |
| `pickle.secure.v1.record` | HKDF info of the record key, first line of the record AAD |
| `pickle.secure.v1.message` | HPKE info of the envelope of an app command |
| `pickle.secure.v1.command\n` | Signature purpose of an app command |
| `pickle.secure.v1.reply\n` | Signature purpose of a node reply |
| `pickle.secure.v1.statement\n` | Signature purpose of a node statement |
| `pickle.secure.v1.challenge\n` | Signature purpose of a challenge statement (4.2) |
| `pickle.secure.v1.log-entry` | HPKE info of a log entry |
| `pickle.secure.v1.log-entry\n` | Signature purpose of a log entry |
| `pickle.secure.v1.log-chain\n` | Prefix of the log chain hash |
| `pickle.secure.v1.head\n` | Signature purpose of a head |
| `pickle.secure.v1.register\n` | Signature purpose of the account key registration (the operator's backend verifies it) |
| `pickle.secure.v1.witness\n` | Signature purpose of a witness signature (stage 2) |
| `pickle.secure.v1.peer`, `pickle.secure.v1.peer\n` | HPKE info and signature purpose of the messages between nodes (section 10) |

## 4. Attestation

### 4.1 The binding document

A node binds its two public keys to the attestation of its platform.

```text
binding = UTF-8(JSON {"v":1,"sign":b64u(node signing public key),"seal":b64u(node sealing public key),"release":"v1.0.0",
                      "log":{"bucket":"...","region":"..."}})
```

- `binding` is at most 512 bytes long.
- `log` names the log store of the node (7.6): the bucket and its region. A node that has no log
  store writes no `log` key: its binding ends with `release`. A node takes a log store once and
  does not change it (enclave.md 5.1), so the `log` of a binding a verifier read holds for as long
  as that node lives.
- `bucket` is 3 to 63 characters: lower-case letters, digits and `-`, and neither the first nor
  the last character is `-`. `region` has the form of an AWS region name: parts joined by `-`, at
  least three, where the first part is two lower-case letters, the last part is one or two digits
  and every part between them is lower-case letters (`us-west-2`). A `log` of another form is
  not a binding: a verifier refuses the document.
- `program_min`, when a binding states it, is a non-negative integer: the lowest version of the
  secure program whose grant command the node takes ("The nodes that receive a grant" in "The
  program of the app"). A binding without the key states none.

### 4.2 The attestation response

The value that the `attestation` call of a node (enclave.md 5.2) returns:

```json
{"v":1,"platform":"nitro","document":"<b64u>","node":"<node>","challenge":"<b64u 16 bytes>","release":"v1.0.0","challenge_statement":{"body":"<b64u>","sig":"<b64u>"}}
```

| platform | `document` | Stage |
| --- | --- | --- |
| `nitro` | An AWS Nitro attestation document (COSE_Sign1, CBOR). `user_data` = `binding`, `nonce` = the nonce bytes of the requester, `public_key` absent | 1 |
| `local` | `UTF-8(JSON {"v":1,"platform":"local","binding":b64u(binding),"nonce":b64u,"time_ms":n})`. It has no signature | 1 (for development) |

`challenge` is a single-use value that this node issued (5.3). `node` and `release` are copies for
convenience. A verifier trusts only the values it read from the `binding` inside `document`.

A response may carry one more member, `release_proofs`: the release proofs of the release of the
node ("The release proofs" in "The program of the app"). It is a public value outside the
document, which the app verifies by its own checks whoever put it there. The app asks for it with
the query `proofs=1` of the request for the attestation.

The challenge statement:

```text
challenge_statement = {"body": b64u(body), "sig": b64u(Ed25519(node signing key, "pickle.secure.v1.challenge\n" || body))}
body = UTF-8(JSON {"v":1,"type":"challenge","node":"...","nonce":b64u(the nonce bytes of this request),"challenge":"...","time_ms":n})
```

- `challenge_statement` is always present, on platform `nitro` and on platform `local`. `challenge`
  of the body is the same string as the `challenge` of the response. `time_ms` is the node time at
  which the challenge was issued.
- What it is for: `challenge` is outside the attestation document. A relay in the operator domain
  could replace it with a challenge that the node issued earlier, and later return an old signed
  reply that carries that old challenge (for example an old `revoke_reply`). The statement binds
  the challenge to the nonce of the requester: a node draws a new challenge on every attestation
  call and signs it together with the nonce of that call. So a challenge with a valid statement
  for the fresh nonce of the app was issued after the app chose that nonce, and a reply that
  carries this challenge cannot be older than that.
- What the app verifies: after it verified `document` (4.3 or 4.4) and took the node signing public
  key from the `binding`, the app verifies the signature of `challenge_statement` with that key
  and the purpose string above, over the received `body` bytes. It then checks that `type` is
  `challenge`, that `node` is the identifier of that node, that `nonce` is the b64u of the nonce it
  sent, and that `challenge` equals the `challenge` of the response. The app refuses a response
  without `challenge_statement` and a response that fails one of these checks.

### 4.3 Verification of a nitro document

The verifiers are the app, and a node that hands over or takes over delegations (section 10).

Input: the `document` bytes, the nonce that was sent with the request (32 bytes), the trust root
(the DER of AWS Nitro Enclaves Root-G1, SHA-256
`641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`), and the list of allowed
measurements. A node that verifies the document of a peer (section 10) skips step 6 (the nonce).
The document of a peer must still carry `nonce` and `user_data` as byte strings: it is a document
that an attestation call made. For a node, the list of allowed measurements has one element: its
own PCR0, PCR1 and PCR2.

1. Parse the document as CBOR. Arrays and maps are accepted at any place in both forms, with a
   definite and with an indefinite length. Strings are accepted in the definite-length form only.
   The top level is an array of 4 elements (a tag 18 around it is removed):
   `[protected(bstr), unprotected(map), payload(bstr), signature(bstr)]`.
2. `protected`, parsed as CBOR, is `{1: -35}`. `signature` is 96 bytes long.
3. `payload`, parsed as CBOR, is a map. The Nitro Secure Module (NSM) writes this map in the
   indefinite-length form: the first byte is 0xbf, the last byte is 0xff. A verifier must read both
   forms of arrays and maps. The map has these keys: `module_id` (text), `digest` (text
   `"SHA384"`), `timestamp` (uint, milliseconds), `pcrs` (map: uint -> bstr of 48 bytes),
   `certificate` (bstr, DER), `cabundle` (array of bstr, at least 1 element), `user_data` (bstr),
   `nonce` (bstr). A `user_data`, a `nonce` and a `public_key` that the request did not give are
   CBOR null (the request with which a node reads its own time and measurement).
4. Certificate chain: the leaf is `certificate`, the intermediate certificates are the elements of
   `cabundle` from the second one to the last one, and the one anchor is the trust root (the copy of
   the root that the document carries as the first element of `cabundle` is not read). The time of
   the verification is `timestamp` in seconds. CRLs, OCSP and the extended key usage (EKU) are not
   looked at. The app does this with its native function
   `native.x509Verify({leaf, intermediates, anchors, atEpochS})`.
5. Signature: the message to verify is the encoding of the CBOR array
   `["Signature1", protected, h'', payload]` (the second and the fourth element are the received
   byte strings as they are, the third is a byte string of length 0). The ECDSA SHA-384 signature
   (`signature` is the raw 96 bytes of r followed by s) is verified with the public key (P-384) of
   the leaf certificate.
6. `nonce` equals the nonce that was sent.
7. The values 0, 1 and 2 of `pcrs` all equal one element of the list of allowed measurements. A
   PCR whose value is all zero (an enclave in debug mode) is never put on the list.
8. `user_data` is parsed as `binding` (`v` is 1). It gives the signing public key and the sealing
   public key of the node, `release`, and the log store of the node when the binding names one.
9. (The app) The challenge statement of the response verifies under the signing public key of
   step 8 (4.2).
10. The log store. The app accepts a node of platform `nitro` only when the `log` of its binding
    equals the log store that the program of the app names for the server environment it talks to
    (a constant list of the program, `LOG_STORES`: one `{bucket, region}` per environment). A
    binding without `log`, and one that names another bucket or region, is refused. The app does
    not apply this step to a node it only sends a revoke to. A node that verifies a peer applies
    it with its own log store (10.1).

A later release (the app). A document that passes every step but step 7, with no PCR all zero, is
the document of a node of a release that the program of the app does not list: a release later
than the program (4.5: the list is a constant of the signed program). The app applies step 10 to
such a document as well (a node of this deployment writes to the log store of the environment).
When release proofs show the measurement of the document to the program ("The release proofs" in
"The program of the app": the release key signed the measurements of the release and the public
log recorded that, a deploy key signed them, GitHub attested them for the release workflow at the
tag of the release in this repository, and the release is later than the listed ones), the
release is an accepted one for that program, as an element of its list is. Without such proofs
the app hands the node no key, as for any measurement outside the list, and does not count the
document as a failed verification: its verification of the log (7.4) leaves the chain of that
node pending, counts the node as a node of a later release, and the program that lists the
release verifies the chain. A document that fails another step, a PCR all zero, and a binding
that names another log store are failed verifications, as before.

Freshness comes from the nonce. `timestamp` is not compared with the clock of the verifier. The app
uses the `timestamp` (milliseconds) of a document that passed the verification as the present time
of that node (the computation of the expiry of a grant: 5.2). In a local document, `time_ms` is that
value.

### 4.4 The conditions for accepting a local document

A node of platform `local` is not verified by attestation. The app accepts platform `local` only
when the app is a debug build, or when the server environment that the app talks to is on a
constant list of the program of the app (`OPERATOR_CUSTODY_TARGETS`). To such a node the app hands
only the user key of custody `operator` (section 3). Every other build of the app refuses platform
`local`. The verification of a local document is the comparison of `nonce` and the parsing of
`binding`, and nothing else. After it, the app verifies the challenge statement of the response
with the signing public key of that `binding` (4.2).

### 4.5 Who owns the list of allowed measurements

| Stage | The app | A node (verification of a peer) |
| --- | --- | --- |
| 1, 2 | A constant list inside the signed program of the app (`[{release, pcr0, pcr1, pcr2}]`, each PCR as 96 lower-case hexadecimal characters), and the measurements of releases later than every element of that list whose release proofs the program verified on the device ("The release proofs" in "The program of the app"). A release reaches an app with a program that lists it, or with its release proofs. An app whose program does not list a release and has not verified its proofs treats the nodes of that release as nodes of a later release (4.3): no key, and a pending verification of their chains (7.4) until the app verifies the proofs or loads the program that lists it | Its own measurement. A giving node also accepts the measurement of a later release whose endorsement it verified, and a receiving node also accepts the measurements of the list of predecessors inside its program (10.3) |
| 3 | The app obtains it by verifying the release statements of the public record (section 9) | Its own measurement, and the list of allowed measurements that the grant of that account carries (the app verifies the release statements and writes the list into the grant) |

## 5. The commands an app sends to a node

### 5.1 The envelope

```text
payload  = UTF-8(JSON command)                                        (5.2)
signed   = UTF-8(JSON {"payload": b64u(payload),
                       "sig": b64u(Ed25519(account signing key, "pickle.secure.v1.command\n" || payload))})
envelope = JSON {"v":1,"node":<node>,"enc":b64u,"ct":b64u}
           HPKE single-shot seal: recipient public key = node sealing public key, info = UTF-8("pickle.secure.v1.message"),
           aad = UTF-8(<node>), plaintext = signed
```

### 5.2 The commands

```json
{"v":1,"type":"grant","user_id":"...","node":"...","challenge":"...","sign_pk":"...","log_pk":"...","custody":"enclave","user_key":"...","not_after_ms":0,"policy":{}}
{"v":1,"type":"revoke","user_id":"...","node":"...","challenge":"...","sign_pk":"..."}
{"v":1,"type":"oauth_code","user_id":"...","node":"...","challenge":"...","sign_pk":"...","state":"...","code":"..."}
```

`oauth_code` is a command of stage 4 (5.6). A node of stages 1 to 3 refuses this type with
`invalid_request`.

| Field | Meaning |
| --- | --- |
| `challenge` | The value that the attestation response of that node gave |
| `sign_pk`, `log_pk` | The public keys of section 3 (b64u of 32 bytes) |
| `custody` | `enclave` or `operator` (section 3). A node refuses a grant whose custody is not the custody of its own platform (`enclave` for nitro, `operator` for local) |
| `user_key` | The UK of that custody (b64u of 32 bytes) |
| `not_after_ms` | The end of the delegation. The app writes the time of the attestation document of that node (4.3) plus 30 days. It does not use the clock of the device. A node refuses a grant with `not_after_ms <= now` (`bad_expiry`). A value larger than `now + 30 days` is accepted and shortened to `now + 30 days`. The accepted value is the `not_after_ms` of the reply |
| `policy` | The place for the conditions of a delegation. In stages 1 to 4 it is the empty object `{}`, and a node refuses a grant that has any key in it (`unsupported_policy`). A change that adds a condition (for example: certain requests need an approval of the device) is used by the app only after the release in which the node implements that key |

A grant is self-contained: a node holds no state about registered accounts, and it verifies the
signature of a grant with the `sign_pk` that the grant carries. A new grant of the same `user_id`
replaces the grant before it.

### 5.3 The order in which a node processes a grant

The order is the order of this table. When a command fails several checks, its failure code is the
code of the first of them.

| Step | Check | Failure code |
| --- | --- | --- |
| 1 | `envelope.v` is 1 and `envelope.node` is the `node` of this node | `unsupported_version`, `wrong_node` |
| 2 | `enc` and `ct` decode as b64u, and the HPKE open succeeds | `open_failed` |
| 3 | `signed` parses as JSON, `payload` and `sig` decode as b64u, `payload` parses as JSON (an object) | `invalid_request` |
| 4 | `payload.v` is 1 | `unsupported_version` |
| 5 | `type` is `grant` or `revoke`, and `sign_pk` is b64u of 32 bytes | `invalid_request` |
| 6 | `sig` verifies under `payload.sign_pk` | `bad_signature` |
| 7 | `payload.node` is the `node` of this node | `wrong_node` |
| 8 | The form of the fields: `user_id` keeps the length limit of section 1 and `challenge` is a string. A grant has more checks: `log_pk` and `user_key` are b64u of 32 bytes, `log_pk` is a key HPKE can seal to (not a point of small order, for which the X25519 output is all zero: RFC 9180 7.1.4), `not_after_ms` is an unsigned integer, `policy` is an object, `custody` is `enclave` or `operator` | `invalid_request` |
| 9 | (grant) `policy` is the empty object | `unsupported_policy` |
| 10 | (grant) `custody` is the custody of the platform of this node | `custody_mismatch` |
| 11 | `payload.user_id` equals the `user_id` that the caller stated (the plaintext argument of the call) | `user_mismatch` |
| 11a | (grant) The node can write to its log store: it has one, and credentials for it within their time (7.6). A node of platform `local` without a log store passes | `log_store_unavailable` |
| 12 | This node issued `challenge`, not more than 300 seconds ago, and it was not used before. When this check passes, the challenge is marked as used. (grant) The node issued the challenge after the last revoke of that account that it accepted (5.4) | `bad_challenge` |
| 13 | (grant) `not_after_ms > now`. A value larger than `now + 30 days` is shortened to `now + 30 days` (5.2) | `bad_expiry` |
| 14 | (grant) The node creates the log entry `grant_accepted` (section 7) and writes it to the log store. After the store confirmed the entry, it puts the grant into its memory (the grant replaces the grant and the revocation marker that were there) | `log_store_unavailable`, `bad_challenge` |
| 15 | The node signs the reply and returns it (5.5) | |

A command that fails in steps 1 to 11a does not use up the challenge (it can be sent again with
the same challenge). The challenge of a grant that step 12 refuses because the node issued it
before a revoke of that account is already used, and so is the challenge of a command that fails
in step 13 or in step 14.

The lock of the account in steps 12 to 14: the node compares the challenge with the last revoke,
checks the end of the grant and creates the entry inside the lock of that account. It writes the
entry to the log store outside the lock. It puts the grant into its memory inside the lock again,
after it compared the challenge with the last revoke of the account a second time: a revoke that
the node accepted while the entry was written stands, and the grant is refused with
`bad_challenge`. When the log store does not confirm the entry, the grant is refused with
`log_store_unavailable`. In both cases the entry `grant_accepted` is on the chain and the node
holds no user key of that grant (7.6: an entry can describe an act that did not take place).

### 5.4 The order in which a node processes a revoke

A revoke passes steps 1 to 8, 11 and 12 of 5.3 in the same order, without the items for a grant.
After that, inside the lock of that account:

- When the account has a grant within its time, `payload.sign_pk` must equal the `sign_pk` of that
  grant (otherwise `bad_signature`). When there is no grant, or its time has passed, the revoke
  passes without this check (it is idempotent).
- When there was a grant within its time, the node creates the log entry `grant_revoked`. The
  `key_id` and the sealing public key of this entry are the `key_id` and the `log_pk` of the grant
  that is revoked. When there was no grant, no entry is created.
- The node erases the user key of that account (it overwrites the memory with zeros) and leaves the
  revocation marker `{key_id, sign_pk}` (the `sign_pk` of the command and its key_id).
- A revoke does not wait for the log store. The node creates the entry and erases the key inside
  the lock of the account. After that it tries to write the entry to the log store. When the store
  does not confirm it, the entry is a pending entry (7.6), and the reply is that of a revoke that
  succeeded. A node without a log store, or without credentials for it, takes a revoke as well.
- The node notes when it accepted the revoke. It keeps one count that only grows: every challenge
  it issues gets the next value, and so does every revoke it accepts, with or without a grant. From
  then on the node refuses a grant of that account whose challenge has a smaller value than the
  revoke (step 12 of 5.3), also after a later grant replaced the revocation marker.

A grant that was sealed before a revoke does not undo that revoke. A sealed command is a value that
its carrier can keep. Without the rule of step 12, a carrier could hold a grant back, deliver a
later revoke of the same account, let the app receive the signed reply of that revoke, and then
deliver the kept grant within the 300 seconds of its challenge: the node would hold the user key
again. With the rule, a grant that follows a revoke needs a challenge that the node issued after
it accepted the revoke. An app that receives `bad_challenge` for a grant requests a new attestation
response and sends the grant with the new challenge. An account that never revoked on a node is not
affected, and neither are the grants of other accounts.

A grant whose time has passed is, in every call, the same as no grant: at the place where a node
sees such a grant, it erases the user key and changes the state of that account to "expired" (only
`key_id` and `not_after_ms` remain). There is no state in which a grant counts as valid while its
user key is overwritten with zeros.

### 5.5 The reply

```text
reply = {"body": b64u(body), "sig": b64u(Ed25519(node signing key, "pickle.secure.v1.reply\n" || body))}
body  = UTF-8(JSON {"v":1,"type":"grant_reply","ok":true,"code":"","node":"...","user_id":"...",
                    "challenge":"...","key_id":"...","not_after_ms":0,"head":{"seq":0,"hash":"..."},"time_ms":0})
```

- `type` is `grant_reply` or `revoke_reply`. In the reply of a failure, `ok` is false and `code` is
  the failure code.
- `head` is the end of the chain of that (node, account) pair at the time of the reply (`seq` and
  `hash` of 7.3). The empty head is `seq` 0 with a `hash` of 32 zero bytes.
- The app verifies `sig` with the node signing public key it obtained from the attestation, and it
  checks that `challenge` equals the value it sent and that `key_id` is its own.

The values of the fields:

| Reply | `type` | `user_id`, `challenge` | `key_id` | `not_after_ms` | `head` |
| --- | --- | --- | --- | --- | --- |
| A grant that succeeded | `grant_reply` | The values of the command | The key_id of the `sign_pk` of the command | The value the node accepted (it can be the value shortened to the limit of 5.2) | The end of the chain of that account (with the entry just created) |
| A revoke that succeeded | `revoke_reply` | The values of the command | The key_id of the `sign_pk` of the command | 0 | The end of the chain of that account |
| A failure in steps 1 to 10 of 5.3 (the node could not verify the command, or it cannot take the command) | `grant_reply` | Empty strings | Empty string | 0 | The empty head |
| `user_mismatch` | The type of the command | The values of the command | The key_id of the `sign_pk` of the command | 0 | The empty head |
| `bad_challenge`, `bad_expiry`, `log_store_unavailable`, the `bad_signature` of a revoke | The type of the command | The values of the command | The key_id of the `sign_pk` of the command | 0 | The end of the chain of that account (with the entry `grant_accepted` of a grant that failed in step 14) |

### 5.6 The sealed delivery of the authorization code (stage 4)

This is the path that keeps the authorization code from the servers of the operator for a provider
without PKCE. The app receives the https callback itself (an app build of stage 4), reads `code`
and `state` from the return URL, and sends them with the command `oauth_code`.

- What the node does: steps 1 to 7 of 5.3, and `payload.sign_pk` must equal the `sign_pk` of the
  grant of that account (`bad_signature`). After that it completes the pending authorization of
  that `state` with `code` (the same processing as the complete call of enclave.md 5.6).
- The reply: `type` is `oauth_code_reply`, and the body carries `state` and `record_id` in
  addition. The plaintext response of the call is that of complete (`record`, `public`,
  `statement`, `log`).
- The callback address (redirect_uri) of a provider that uses this path is an https address that
  the app intercepts. No request for that address reaches the servers of the operator.

## 6. The credential record

```text
record = JSON {"v":1,"id":<id>,"user_id":"...","key_id":"...","custody":"...","kind":"...","provider":"...","nonce":b64u(12),"ct":b64u}
aad    = UTF-8("pickle.secure.v1.record\n1\n" + id + "\n" + user_id + "\n" + key_id + "\n" + custody + "\n" + kind + "\n" + provider)
ct     = ChaCha20-Poly1305(record key, nonce, aad, plaintext)
```

`custody` is the custody of the user key that encrypted the record (section 3: `enclave` or
`operator`).

The use mode of a kind says how a record of that kind is used. With enclave-use, the node uses the
value itself and the value does not leave the node. With release, the node hands the value to the
caller, after the log entry of that release is on the chain.

| kind | provider | Created by | Use mode | Plaintext (UTF-8 JSON) |
| --- | --- | --- | --- | --- |
| `oauth` | The name of a provider (enclave.md section 6) | A node (`oauth/complete`: the node receives the token from the provider itself). `refresh` and `oauth/merge` write the record again | enclave-use: the token is used through `forward` only. No call hands the plaintext out | `{"token":{the token response of the provider, merged by the rules of section 8},"obtained_ms":n}`. A dynamically registered client (granola, mercury) also carries `"client_id"` |
| `oauth_imported` | The name of a provider | The device of the account: the app encrypted a token that the operator domain held before it used a node. No call of a node creates a record of this kind | enclave-use: `forward`, `refresh` and `revoke-token` take the record by the same rules as kind `oauth`, and `refresh` writes the record again under the same kind. `oauth/merge` and `release` refuse it (`not_allowed`) | The form of kind `oauth` |
| `app_password` | `naver_mail` | The app | enclave-use: mail calls only; no release | `{"username":"...","password":"..."}` |
| `vault_password` | `vault` | The app | release: `release` hands the value out | `{"value":"..."}` |
| `vault_totp` | `vault` | The app | enclave-use: the seed does not leave. `release` hands out only the code that the node computed | `{"value":"<base32 seed>"}` |
| `vault_card` | `vault` | The app | release | `{"number":"...","cvc":"..."}` |

The guarantee tier of a record follows from the use mode of this table and from the `custody` of
the record. A record with `custody` `enclave` and use mode enclave-use is of the provable tier:
the source of the node shows that no call hands its plaintext out, and anyone can check with the
attestation that a node runs this source. The proof covers the node. That the app is honest is an
assumption as long as the source of the app is not public. Kind `oauth_imported` is the exception:
a record of this kind is of the promised tier, because the operator domain knew the token once. A
new connection of the account gives a record of kind `oauth`. Every other record is of the promised
tier as well: the structure keeps the stored value confidential and puts every release on the log,
and what happens to a value after it left the node is a promise of the operator.

- A record is bound to its own `id`, not to a name or to a connection id. Renaming an item of the
  vault encrypts nothing again.
- Writing the same `id` again (a token refresh) encrypts with a new nonce. `id`, `kind` and
  `provider` do not change.
- The checks of the side that opens a record (a node), in this order: `v` is 1 (otherwise
  `unsupported_version`). `user_id` is the account that the call names (otherwise
  `user_mismatch`). `key_id` and `custody` are the `key_id` and the `custody` of the grant of that
  account (when either differs: `key_mismatch`). `id` is b64u of 16 bytes, `nonce` is b64u of 12
  bytes, the other fields have the form this document gives them, and the AEAD verification passes
  (a failure is `record_invalid`).
- When the opened record has a `kind` that the call does not take, the call fails with
  `not_allowed` (enclave.md section 5 names the kinds of every call). A kind that the release does
  not know is `not_allowed` too. When the plaintext is not a JSON object, or the plaintext lacks
  the field that the call uses, the call fails with `record_invalid`.
- A secret value of the vault is one record per secret field (a password and a TOTP seed are two
  records). A save that changes one of them does not touch the record of the other.

## 7. The credential log

### 7.1 The entry

```text
entry = {"body": b64u(body), "sig": b64u(Ed25519(node signing key, "pickle.secure.v2.log-entry\n" || body))}
body  = UTF-8(JSON {"v":2,"node":"...","user_id":"...","key_id":"...","seq":1,"prev":b64u(32),"time_ms":0,"kind":"u","count":1,"enc":b64u,"ct":b64u})
        enc, ct = HPKE single-shot seal: recipient public key = the log_pk of the grant at that time, info = UTF-8("pickle.secure.v2.log-entry"),
                  aad = UTF-8(node + "\n" + user_id + "\n" + key_id + "\n" + seq in decimal),
                  plaintext = UTF-8(JSON array of the events, in the order of their creation)
body_hash  = SHA-256(body)
entry_hash = SHA-256("pickle.secure.v2.log-chain\n" || prev || body_hash || UTF-8(fields))
             prev:   the 32 bytes of the entry_hash of the entry before
             fields: the first five parts of the key of the entry as the key writes them (7.6),
                     "{seq}-{time_ms}-{kind}-{count}-{key_id}" (57 characters)
```

- There is one chain per (node, account) pair. The `seq` of the first entry is 1 and its `prev` is
  32 zero bytes. The `prev` of every later entry is the `entry_hash` of the entry before it. `count`
  is the number of events in the plaintext (1 to 128) and `kind` is the letter of the kind of the
  entry.
- The two kinds of entry. A use entry (`kind` `u`) holds use events: `provider_request`,
  `credential_refreshed`, `mail_request`, `secret_released`, `totp_issued`. A control entry (`kind`
  `c`) holds one control event: `grant_accepted`, `grant_revoked`, `connection_created`,
  `connection_removed`, `grant_transferred_out`, `grant_transferred_in`. A control entry is never
  merged with another event. The first entry of a chain is a control entry: no node uses a user key
  before it accepted a grant or a transfer.
- The open batch and the group commit. A node keeps, per account, the use events whose entry does
  not exist yet (the open batch). A call that creates a use event puts it into the open batch. When
  no write of that account is in progress, the call closes the open batch into one entry (the entry
  gets the next `seq`, is sealed and signed, and the end of the chain rises) and writes it (7.6):
  the call is the writer of the account. While a write of the account is in progress, the call
  waits: the writer closes the open batch into the next entry when its write ends, and one of the
  waiting calls writes it. So an entry holds the events that arrived while the write before it
  ran. An open batch is closed before it holds more than 128 events or more than 1,048,576 bytes
  of plaintext, and a control event closes the open batch before it and forms an entry of its own.
  An act waits for the confirmation of the entry that holds its event (7.6): no event is in two
  entries, and no entry is created for an act that the common front refused. When the store does
  not confirm the write, the writer fails with `log_store_unavailable` and the entry is a pending
  entry (7.6); a call that waited for that entry writes it once more, as the next writer, and a
  call that waited for twice the time limit of a write fails with `log_store_unavailable`.
- A forward batch (enclave.md 5.8b) creates one use event per request of the batch, in the order of
  the requests, all into the open batch of the account in one step. The requests of one batch may
  end up in two entries when the open batch reaches a cap between them; the batch waits for the
  confirmation of every entry that holds one of its events.
- The entry and the act. `forward`, `forward/batch`, `refresh`, `revoke-token`, `release`, the
  commands grant and revoke, and `peer/export` create their event before the act: the node creates
  the event, and the entry that holds it, and after that it calls the provider, hands the value
  out, changes the delegation or seals the user key to a peer. `peer/import` creates its entry
  before it puts a grant in place, and writes it after (7.6). `oauth/complete` receives the token response of the provider
  first and creates the entry `connection_created` before the record leaves the node: no part of
  an accepted token response leaves the node before that entry exists, and when a step after the
  response fails, the tokens are dropped inside the node and nothing of them leaves. `oauth/merge`
  calls no provider and creates no event.
- The entry and the log store. A node that has a log store writes the entry to it between the
  creation of the entry and the act, and acts only after the store confirmed the entry. 7.6 names
  the act of every call and the two calls that do not wait.
- The cases that share an event or create none are named where they are described: identical GET
  requests (7.2), a repeated `refresh` of the same record and a `refresh` of a record without a
  refresh token (enclave.md 5.7), a revoke of an account without a grant (5.4), a repeated
  transfer of a grant to the same node, a transfer that a node takes for an account whose grant
  of the same key it holds (10.1), and a call that uses a credential of an account that has 64
  pending entries (enclave.md 5.14).
- The entry is not carried in the response of a call. The response names the entry and the index
  of the event in it (the `log` object of a response, enclave.md section 4). The storage of the
  operator's backend holds no entry: the log store is the one place an entry is read from.
- The ephemeral key pair of the HPKE seal is `DeriveKeyPair` (RFC 9180 7.1.3) with 32 random bytes
  as the input keying material. A node uses new random bytes for every entry. The test vectors
  (section 13) fix these 32 bytes (`hpke_seed`).
- The key order of the event JSON is the order that the table of 7.2 gives (`t` is the first key
  and `time_ms` the second).

Format 1 (the releases before v2.0.0): the signature purpose is `pickle.secure.v1.log-entry\n`,
the body is `{"v":1,"node","user_id","key_id","seq","prev","time_ms","enc","ct"}`, the HPKE info is
`pickle.secure.v1.log-entry`, the plaintext is one event (the JSON object, not an array),
`entry_hash = SHA-256("pickle.secure.v1.log-chain\n" || body)`, and the object key is
`{seq}-{b64u(entry_hash)}` (7.6). A reader verifies a chain of format 1 by its entries (7.4,
"Format 1").

### 7.2 The events (the plaintext of an entry)

| `t` | The other keys | Created by |
| --- | --- | --- |
| `grant_accepted` | `time_ms`, `not_after_ms`, `custody` | The command grant |
| `grant_revoked` | `time_ms` | The command revoke |
| `connection_created` | `time_ms`, `record_id`, `provider`, `scope` (the scope string among the public fields of enclave.md 6.4: the `scope` of the token place, else the top-level `scope`, when the provider definition lists it. Otherwise the empty string) | `oauth/complete` |
| `credential_refreshed` | `time_ms`, `record_id`, `provider`. It records a refresh call (the event is created before the call, so a refresh that the provider refused is on the log as well) | `refresh` |
| `connection_removed` | `time_ms`, `record_id`, `provider`, `provider_revoke` (bool: whether the node calls the revocation address of the provider after this event. It is true when the definition has a revocation address and the plaintext of the record has a token. The event is created before the call, so it does not carry the outcome of the call) | `revoke-token` |
| `provider_request` | `time_ms`, `record_id`, `provider`, `method`, `host`, `path`, `query`, `body_bytes`, `body_sha256` (b64u, the empty string when there is no body), `context`, `window_s` (300, only on a request that can be merged) | `forward`, `forward/batch` (one per request) |
| `mail_request` | `time_ms`, `record_id`, `provider`, `operation`, `request`, `body_bytes`, `body_sha256`, `context` (the mail call surface at the end of this document) | `mail/verify`, `mail/read`, `mail/submit` |
| `secret_released` | `time_ms`, `record_id`, `kind`, `field`, `origin`, `context` | `release` |
| `totp_issued` | `time_ms`, `record_id`, `origin`, `context` | `release` |
| `grant_transferred_out` | `time_ms`, `to` (the `node` of the receiving node) | `peer/export` (section 10) |
| `grant_transferred_in` | `time_ms`, `from` (the `node` of the giving node), `not_after_ms`, `custody` | `peer/import` (section 10) |

- `time_ms` is the node time at which the event was created: the moment the call passed the common
  front and the account lock created the event. The `time_ms` of an entry (7.1) is the time at
  which the open batch was closed, and it is never before the `time_ms` of an event of the entry.
  The times of the events of one chain do not decrease with (`seq`, index), and neither do the
  times of its entries.
- `method`, `host`, `path` and `query` are those of the request that the node sends. `path` and
  `query` are whole: an address of `forward` is at most 8,192 bytes long (enclave.md section 7),
  and an event holds up to 8,192 bytes of each.
- `context` is a string of at most 256 characters that the caller (the operator domain) gave. The
  node does not verify this value. The log screen of the app shows it apart, as a context that the
  operator stated.
- Merging of identical requests: a `provider_request` whose method is GET and whose body is empty
  creates no new event when such an event of the same account for the same record and the same
  address (equal host, path and query) was created less than 300 seconds before, in the open batch
  or in an entry. The request shares that event and waits for the entry that holds it. Two
  identical GET requests inside one forward batch share one event the same way. The window belongs
  to the grant: a revoke, an expiry and a grant of another key clear it, so no request merges into
  an event made under a grant that is over. An event that can
  be the target of a merge (a GET without a body) carries `window_s: 300`: it says that the same
  request may have happened any number of times in the 300 seconds after it. A GET request with a
  body, a request of another method and the release of a vault value (`release`) are not merged:
  each has its own event.
- The identifier of a node (`node`) is the signing public key of that node. So an app that read the
  `to` of a `grant_transferred_out` can verify the signatures of the entries of the receiving node
  with that value.

### 7.3 The head

```text
head = {"body": b64u(body), "sig": b64u(Ed25519(node signing key, "pickle.secure.v1.head\n" || body))}
body = UTF-8(JSON {"v":1,"type":"head","node":"...","user_id":"...","seq":0,"hash":b64u(32),"nonce":b64u,"time_ms":0,"final":false})
```

- `seq` and `hash` are the `seq` and the `entry_hash` of the last entry of that chain. A chain
  without entries has `seq` 0 and a `hash` of 32 zero bytes.
- `nonce` is the value that the requester gave (in a head whose `final` is true it is the empty
  string).
- A node creates a head whose `final` is true in its orderly shutdown, one per account, at the
  last entry of the chain that the log store confirmed. When the entries above that one are the
  end of the chain and the store confirmed none of them, the node drops them from its chain and
  signs the final head below them (enclave.md 5.11): a final head of `seq` 0 says that the store
  holds no confirmed entry of the node for that account. An entry whose write may have reached the
  store (the connection closed without a response, the attempt passed its time limit after the
  request left, the store answered with a 5xx status, or the call that owned the write ended while
  the store held the request) is not dropped: the node leaves no final head for that account
  until the store confirms the entry.
  After that the node creates no entry for that account.
- The head covers entries. The events of an open batch are not on the chain yet, and their acts
  have not taken place (an act follows the confirmation of its entry, which follows the close of
  the batch). So a head names every act that took place or could have taken place. A final head
  names every act of the node for that account: an entry the store never confirmed names acts
  that did not take place, and the final head stands below it.

### 7.4 Verification (the app)

For one (node, account) chain the app starts from the signing public key of that node (the node
identifier is that key), which it keeps in its list of nodes, and from its last verified point
`{seq, hash, time_ms}`. The app reads the log store itself (7.6): it lists the object versions
under the prefix of the account and of the node through addresses the operator's backend signs,
checks every address before it calls it (the host of the bucket of `LOG_STORES` of its server
target, or, in a debug build only, the path-style form of the bucket of the S3 stand-in of the
local stack at the host the backend hands out, over http or https; the prefix of its own account,
the path, prefix, key, markers and version of the request, no query key besides those of that
request, the page size of 1,000, the encoding `url` of the names and the signature), and takes
the listing as the index of completeness. The responses come from S3 over
TLS and the operator domain cannot change them. The content of an entry is read from the object of
its key, never from the backend.

The two verifications:

| Verification | What it reads | When |
| --- | --- | --- |
| Index verification | The head, the keys of the listing, and the bodies of the control entries | Every synchronization (every 24 hours), and every time the log screen opens |
| Content verification | The body of an entry: signature, `body_hash`, `prev`, the opening of the plaintext | The entries beyond the vouched end, the entries of format 1, the control entries, a `seq` with more than one candidate key that satisfies the chain equation, and the entries the screen shows |

Index verification of a chain of format 2:

1. The app obtains a head: from a living node with a new nonce (signature and nonce checked), from
   the backend the `final` head of a node that is gone (signature checked). The `seq` of the head is
   the vouched end. A node that is gone without a `final` head has no vouched end. When the `seq`
   and the `hash` of the head equal the verified point, the chain is verified and the app reads no
   listing of that node in this run.
2. The app lists the keys of the node prefix from the key marker of its verified point (the `seq`
   as 20 digits followed by `-~`: every key of that `seq` sorts before it). A key of format 2 has
   seven parts: `seq` (20 digits), `time_ms` (13 digits), `kind` (`c` or `u`), `count` (3 digits),
   `key_id` (16 hexadecimal characters), `b64u(body_hash)`, `b64u(entry_hash)`. A key of another
   shape under the node prefix is left out, and so is a delete marker of the listing.
3. For every `seq` after the verified point up to the vouched end, in order: among the keys of that
   `seq` (a key counts once however many versions of its object the listing shows: a write the node
   repeated adds a version) the app takes the candidates whose `entry_hash` equals
   `SHA-256("pickle.secure.v2.log-chain\n" || cursor.hash || body_hash || UTF-8(the first five parts of the key))`.
   A key of other parts than the node wrote (another `time_ms`, `kind`, `count` or `key_id` beside
   the hashes of the entry) does not satisfy the equation. When exactly one candidate
   satisfies the equation and its `kind` is `u`, the cursor moves to it without reading its object.
   When its `kind` is `c`, the app reads the object (the latest version first), verifies the
   signature of the node, `body.seq`, `body.prev` = `cursor.hash`, `SHA-256(body)` = `body_hash`,
   `body.key_id` = `key_id`, `body.count` = 1, opens the event when `key_id` is its own, and traces
   a transfer (`grant_transferred_out`: the receiving node enters the list of nodes). When more
   than one candidate satisfies the equation (the operator domain can add objects under any key),
   the app reads their objects and takes the one whose signature verifies. When no candidate
   satisfies the equation: a gap (missing) and attention.
4. At the vouched end the cursor hash equals the hash of the head, otherwise attention. Beyond the
   vouched end (entries written after the head was signed) the app stops: the next run reads them
   from a newer head. For a node that is gone without a `final` head, every entry after the
   verified point is read by content verification (the signature alone proves that the node wrote
   it).
5. The verified point moves to the cursor (`seq`, `hash` and the `time_ms` of the key). The listing
   of the account prefix (delimiter `/`) is the discovery of nodes: a node the list of the app does
   not know is verified from `seq` 1 with its first entry (a control entry) read by content. When
   that entry is sealed to the key of this account and no traced transfer explains the node, the
   app reads the heads once more before it counts the node (the second look). The heads of the
   nodes of its list were read before the listing of the account prefix, and a transfer of the
   delegation that landed between the two (10.1: the giving node wrote `grant_transferred_out`, the
   store confirmed it, the grant went over, the receiving node wrote `grant_transferred_in`) puts
   the receiving node into the listing while the chain of the giving node was walked to a head
   signed before the transfer. The second look reads the node summary of the backend, the status
   of every node whose head the first reads held and whose chain verified to that head, and the
   listing addresses of those nodes, and walks those chains on from their verified points to the
   new heads within the key, body and time budgets of the run (`LOG_VERIFY_KEYS`,
   `LOG_VERIFY_BODIES`, `LOG_VERIFY_TIME_MS`: a run that reaches a budget leaves the chains it has
   not walked, and the rest of the chain it was walking, pending at their verified points, and the
   next synchronization of that runtime, or the next log screen, walks on from them; such a run is
   cut short, as is a run whose listing of one chain goes on beyond `LOG_STORE_PAGES` pages, and a
   run cut short marks no node found in the store only unless `LOG_STORE_STALE_MS` has passed since
   the entry sealed to the key of this account was first verified on the chain of that node: the
   transfer that explains the node may lie in the part of a chain the run could not walk; the app reads
   at most `LOG_STORE_CONCURRENCY` objects of the store at once; a synchronization that a user
   procedure starts, the creation or reset of the master key, the access switch or the transfer of
   the key, does not run the verification and leaves it to the next synchronization of that
   runtime); a transfer traced there explains the node. A node that no traced transfer explains after the
   second look is a delegation the app did not make (attention) and stays in the list with that
   mark. A run that finds no such node reads no head twice. The
   nodes of the listing that the list of nodes does not know are examined after the known nodes, at
   most `LOG_STORE_NODES` of them in one run (more leave the run pending). A node of a release later
   than the program of the app (4.3: a node whose attestation the app verified in its last
   synchronization with the nodes, with a measurement the program does not list) is not read in the
   run, whether the listing or the list of nodes holds it: its chain is pending, its mark (when an
   earlier program left one) is not counted, and the run is pending. The program that lists the
   release reads that chain from the verified point the list of nodes keeps (`seq` 0 for a node no
   program read).
6. The list of nodes of a device (its node ledger) holds the nodes the device delegated to and the
   nodes the tracing of a transfer added. A device writes a node to its list before it sends a
   grant to that node (the attestation of the node verified), so a grant whose reply never reaches
   the device is a delegation the device made. The devices of one account share their lists
   through the operator's backend as one value per account, sealed with a key derived from the
   master key (ChaCha20-Poly1305, a fresh nonce, the additional data naming the purpose, the
   account and the `key_id`): a device reads the value and merges it into its list before it
   judges the log, and uploads the merged list when the value does not cover a node it holds a
   grant for. The operator cannot read or forge the value, and a value the operator withholds
   leaves the judgement of the device as it is. A node of the listing that the merged list
   explains as a grant of a device of the account is not a delegation the app did not make. A
   run whose judgement took longer than `LOG_RUN_STALE_MS` (the app was suspended while it ran)
   is judged again on fresh reads before it is published.

Expired entries: an object of the store cannot be deleted for 365 days (7.6), and after that its
absence says nothing about the operator domain (the lifecycle rule of the bucket removes it at 400
days, and nothing forbids its removal before then once its retention ended). When the listing from
the verified point starts at a `seq` above `verified.seq + 1` and the `time_ms` of the verified
point, or of the first listed entry, is more than 365 days before the node time of the head, the
entries between are expired: the app moves the verified point to the first listed key (reading that
object by content when its `kind` is `u`, so that the new point is a signed entry of the node) and
continues. A verified point of format 1 has no `time_ms` (0) and never qualifies as expired.

Young gaps: a node writes an entry the store did not confirm again with the next write of the
account and, at the latest, in its sweep of 30 seconds (7.6), so a gap below the vouched end is
usually an entry that is about to be written. A gap whose first key after it (every key of that
`seq`) is a key of format 2 younger than one hour (`LOG_GAP_GRACE_MS`) leaves the chain pending:
the next run reads the gap again. A gap whose first key after it is older than that is missing
(attention): the node did not write the entry in time, and the acts of the entries of a gap did not
take place (an act follows the confirmation of its entry).

Why the equation suffices up to the vouched end: the hash of the head is signed by the node, each
`entry_hash` commits to the `entry_hash` before it, to `body_hash` and to the five parts of its own
key, and `body_hash` commits to the body. A sequence of keys that satisfies the equations and ends
at the hash of the head fixes the keys and the bodies of the chain under the collision resistance
of SHA-256. An object the operator domain added either fails the equation or, when it satisfies it
with the hashes of a genuine entry, has the same key as the genuine object (a second version, whose
body does not verify): a key of other parts (another `time_ms`, `kind`, `count` or `key_id`) fails
it. The genuine objects cannot be deleted before their retention ends, so the chain of genuine keys
is always in the listing.

| Result | Meaning |
| --- | --- |
| Everything passes | The entries that this node wrote for this account are in the store without a gap up to the vouched end, the chain hashes agree with the head, and every control entry verifies |
| A `seq` without a candidate whose first key after it is older than one hour, a candidate chain that does not reach the hash of the head, a control entry that does not verify | The stored log has an omission or a change |
| A `seq` without a candidate whose first key after it is younger than one hour | Pending: the node has still to write the entry again (7.6); the next run reads the gap |
| A node appears in the listing that no grant of the app and no traced transfer explains, after the second look of step 5, with a first entry sealed to the key of this account | A node used the key of the account outside the delegations the app knows |
| A node of a release later than the program of the app (4.3) is in the listing or in the list of nodes | Pending: the program does not list the release, so it hands the node no key and does not read its chain. The program that lists the release reads the chain from the verified point of the node. The number of such nodes is reported with the run (`newer_release_nodes`) |
| A node that is gone has no `final` head | The entries after the verified point are read by content verification. The part the app has not read yet is pending |
| A node that is gone has a `final` head, and a key of its prefix lies above the `seq` of that head | The stored log holds an object the node did not vouch for: attention (step 4). A node avoids this state in its orderly shutdown: it signs the final head below an unconfirmed tail only when every write attempt of those entries failed before a request byte left the node or was answered by the store with a 4xx status, and it leaves no final head for an account with an unconfirmed entry whose write may have reached the store (7.3) |
| The store cannot be listed or read, an address the backend handed out is not one of the request, the node discovery listing of the account goes on beyond `LOG_STORE_PAGES` pages (the run lists no chain: `discovery:pages`), or a release build of the app is refused the store | The verification is pending (the app does not treat it as complete); the refusal of a release build marks the log, and reads that keep failing for `LOG_STORE_STALE_MS` mark the log. The first run that read the store (every read of the store it made answered, the node discovery window truncating the run or not) clears that mark, whether its walk completed or its time budget left entries pending |
| More node prefixes the list of nodes does not know than `LOG_STORE_NODES` are listed | The verification is pending and the run reports the store truncated (`discovery:nodes`); the store was read, so this is not a failing read. The run examines `LOG_STORE_NODES` of them, beginning after the node the last run examined last (the discovery cursor the list of nodes keeps, in the id order of the listing) and wrapping to the start of the listing, so the next synchronization (which runs the verification at once, as after a run cut short by its time budget) examines the nodes after them whether or not the examined nodes stayed in the list: every such node is examined within ceil(n / `LOG_STORE_NODES`) + 1 synchronizations. A node under examination stays in the list of nodes with its verification point (a node walked to its head that holds nothing sealed to the key of this account stays at its head, so the next runs read nothing new from it and are not pending for it; it leaves the list when the listing no longer names it, and first when the list is over its size limit), and the fact that its chain holds an entry sealed to the key of this account stays with it (`sealed_ms`) from the run that verified the entry: the node is marked by the first run that completes within its budgets (time, keys, bodies, and the listing pages of every chain) without a traced transfer explaining it, and by any run once `LOG_STORE_STALE_MS` has passed since that entry was first verified |

Format 1 (the chains of nodes of the releases before v2.0.0): the app verifies every entry by its
object (signature, `node`, `user_id`, `seq`, `prev`, and `entry_hash` equal to the hash of the
key), up to the head. These chains end when their nodes are drained (`final` head), and the app
reads them until its verified point reaches the `final` head.

The authenticity of an entry the app displays is checked with the node signature of that entry and
with its key (`body_hash`), and its content is opened with the log decryption private key. The app
does not open an entry whose `key_id` is not its own. It shows such an entry as part of a
delegation of another key.

### 7.5 The witness signature (stage 2)

```text
witness = {"node": <witness node>, "sig": b64u(Ed25519(witness node signing key, "pickle.secure.v1.witness\n" || entry_hash))}
```

- After a node created an entry and before the act, it sends `{user_id, node, seq, entry_hash}` to
  one or more other living nodes and receives a witness signature from each (section 10). A witness
  node keeps the last `{seq, entry_hash}` of that (node, account) pair in its memory.
- A witness signature is stored next to the entry, apart from it (it is no input of `entry_hash`).
- The end of the chain of a node that is gone is settled by the `final` head of that node, or by a
  head that the witness nodes signed (a witness node creates it from the last `{seq, entry_hash}`
  it saw). A part that cannot be checked remains only when all nodes disappear at the same time.

### 7.6 The log store

The log store is the one place an entry is stored, and the place where an entry cannot be deleted:
a node writes every entry there itself, and acts only after the store confirmed the entry. The
storage of the operator's backend holds no entry.

| Item | Value |
| --- | --- |
| Store | One Amazon S3 bucket with Object Lock and versioning. The binding of a node names the bucket and its region (4.1) |
| Object key | Format 2: `v1/accounts/{user_id}/{node}/{seq}-{time_ms}-{kind}-{count}-{key_id}-{body_hash}-{entry_hash}`. `seq` is the `seq` of the entry as 20 decimal digits with zeros in front, `time_ms` the `time_ms` of the entry as 13 decimal digits with zeros in front, `kind` the letter `c` (a control entry) or `u` (a use entry), `count` the `count` of the entry as 3 decimal digits with zeros in front, `key_id` the `key_id` of the entry (16 lower-case hexadecimal characters), `body_hash` and `entry_hash` the b64u of the two hashes of 7.1. Format 1: `v1/accounts/{user_id}/{node}/{seq}-{hash}` with `hash` = `b64u(entry_hash)`. The prefix of the store is the same for both formats |
| Object body | The signed entry: `{"body":"...","sig":"..."}` |
| Retention | Every object version is written with mode `COMPLIANCE` and a retention until the node time of the write plus 365 days. Until then nobody, the root user of the AWS account included, can delete that object version, overwrite it or shorten its retention. The lifecycle rule of the bucket expires current versions 400 days after their creation and removes noncurrent versions 400 days after they became noncurrent. So an entry is in the store for at least 365 days and at most about 400 days, and a reader treats the absence of an entry older than 365 days as expired, not as an omission (7.4) |

The write of one entry:

```text
PUT https://{bucket}.s3.{region}.amazonaws.com/{object key}
Content-Type: application/json
x-amz-object-lock-mode: COMPLIANCE
x-amz-object-lock-retain-until-date: YYYY-MM-DDTHH:MM:SSZ
x-amz-checksum-sha256: base64(SHA-256(body))
x-amz-content-sha256: hex(SHA-256(body))
x-amz-date: YYYYMMDDTHHMMSSZ
x-amz-security-token: {session token}
Authorization: AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...
```

- TLS ends inside the node, and the certificate of the host is verified against the trust roots
  of the node binary at node time. The request is signed with AWS Signature Version 4 over the
  method, the path, every header above and `Host`, and the hash of the body, with credentials
  that the operator domain gives the node (enclave.md 5.14). In the path, every byte of the key
  outside the unreserved characters of RFC 3986 is percent-encoded, and `/` is not: a `user_id`
  is written into the key as it is.
- The node keeps up to 32 idle HTTP/1.1 connections to the store and sends the first attempt of
  a write over the most recently used one. An attempt the store does not confirm because the
  connection failed, the connection closed without a response, the attempt passed its time
  limit, or the status was 5xx or 429 is repeated over a new connection, with a full jitter
  backoff between the attempts, within a budget of twice the time limit of a write per entry; a
  4xx status other than 429 is not repeated (enclave.md 5.14). A `PUT` is idempotent, and a
  repeated attempt adds a version of the same object with the same body. A connection carries
  one write at a time.
- The one confirmation of a write is the status 200 of that request. Every other status, a
  failure of the connection and a write that takes longer than its time limit are no
  confirmation. A bucket without Object Lock refuses a request with these headers, so a node
  whose configuration names such a bucket confirms nothing.
- The request states no condition on the key (it carries no `If-None-Match`), and a node does not
  take the answer "an object of this key exists" for a confirmation. The operator domain holds
  the credentials the node writes with and can write to the same bucket, and it knows the key of
  an entry as soon as the entry exists (the head of the chain gives `seq` and `hash`). An object
  that someone else wrote under that key can have another body or no retention. So a write that
  is repeated (the answer of the first one was lost) adds a second version of the same object. A
  reader of the store takes a key for an entry of the node when one version of the object is an
  entry that verifies: the signature of the node over its `body`, and the hashes of the key equal
  to those of the body (7.1).

The acts that wait for the confirmation. A node that has a log store does not perform the act of a
row before the store confirmed the entry that holds the event of that row. The group commit (7.1)
means that one write confirms the acts of every event of the entry, and a write that is not
confirmed fails every call that waits for that entry with `log_store_unavailable` and leaves the
entry as a pending entry (a call that waited writes it once more, 7.1):

| Call | Event | The act that waits | When the store does not confirm the entry |
| --- | --- | --- | --- |
| `forward` | `provider_request` | The request to the provider. A request that shares the event of an identical GET request (7.2) waits for the entry that holds it: when the store confirmed it before, nothing is written, and when it is a pending entry, the call writes it again | `log_store_unavailable`. No request is sent |
| `forward/batch` | `provider_request`, one per request | The requests to the provider, all of them, after every entry that holds one of their events is confirmed | `log_store_unavailable` for the whole call. No request is sent |
| `refresh` | `credential_refreshed` | The call of the token address | `log_store_unavailable`. The token address is not called |
| `revoke-token` | `connection_removed` | The call of the revocation address | `log_store_unavailable`. The revocation address is not called |
| `release` | `secret_released`, `totp_issued` | The value in the response | `log_store_unavailable`. The value does not leave |
| `oauth/complete` | `connection_created` | The record in the response (the code is exchanged before the entry is created, 7.1) | `log_store_unavailable`. The record does not leave and the tokens are dropped inside the node: the connection is started again |
| The command grant | `grant_accepted` | The user key is put into the memory of the node | The signed reply has `ok` false and the code `log_store_unavailable`. The node holds no key |
| The command revoke | `grant_revoked` | None. The user key is erased whatever the store answers | The reply is that of a revoke that succeeded. The entry is a pending entry |
| `peer/export` | `grant_transferred_out`, one per account | The grant of that account enters the transfer | `log_store_unavailable` for the whole call, also when the store confirmed the entries of other accounts: no grant is handed over. The next call for the same receiving node creates no entry for these accounts: it writes the entries that wait again |
| `peer/import` | `grant_transferred_in`, one per account | None. The grant is put in place first; the call then writes the entries it created in one round, when the node has credentials for its log store | The grant stays in place and the entry is a pending entry: the next write of the account takes it along. The call succeeds all the same |

- A pending entry is an entry that the store has not confirmed and that no call is writing. It
  stays in the memory of the node (it is on the chain). The next write of the same account takes
  the pending entries of that account along, at the same time as its own entry, and a request
  that merges into an event of a pending entry waits for that write. The sweep of the node (a task
  that runs every 30 seconds, `SWEEP_INTERVAL`) writes the pending entries of every account again
  as well, so an account that makes no further call does not leave a gap in the store for longer
  than the sweep and the write take. A pending entry that the store refuses again does not fail
  that call: the condition of an act is the confirmation of the entry of that act. An account
  whose pending entries reached 64 gets no further entry from a call that uses a credential
  (enclave.md 5.14).
- What a missing object means. An object of the log store cannot be deleted before its retention
  ends. So for a `seq` of a chain whose object is not in the store, the act that entry describes
  did not take place: the node did not call the provider, did not hand the value out, did not
  take the user key, did not hand the grant over. The two exceptions are the rows without an act
  that waits: a revoke erased the key, and an import put the grant in place (the giving node's
  `grant_transferred_out` of that grant is in the store). The store can hold more entries than
  there were acts, and not fewer: an entry whose act failed afterwards or never started (the
  provider refused, the call ended, the store confirmed and the answer was lost) is in the store
  like any other.
- A node of platform `nitro` does not act without a log store: while it has no log store in its
  configuration, or no credentials within their time, it refuses every act of the table with
  `log_store_unavailable`, before it creates an entry (a revoke and an import are taken, and
  their entries are pending entries). A node of platform `local` without a log store in its
  configuration works without one. With one, it follows the rules of this section.
- The operator domain carries the bytes between a node and the log store and can stop them. A
  node then uses no credential: the calls of the table end with `log_store_unavailable`.

## 8. Issuing and refreshing OAuth tokens

### 8.1 The state

```text
state = node_state + "." + operator_state
node_state     = b64u(16 random bytes of the node)
operator_state = a string that the operator's backend gave (1 to 1,024 characters, only [A-Za-z0-9._-])
```

A node finds a pending authorization by its `node_state`. A node does not interpret
`operator_state`.

### 8.2 The node statements

```text
statement = {"body": b64u(body), "sig": b64u(Ed25519(node signing key, "pickle.secure.v1.statement\n" || body))}
oauth_begin    body = UTF-8(JSON {"v":1,"type":"oauth_begin","node":"...","user_id":"...","key_id":"...","sign_pk":"...","provider":"...","state":"...","url_sha256":b64u(SHA-256(UTF-8(authorization address))),"time_ms":0})
oauth_complete body = UTF-8(JSON {"v":1,"type":"oauth_complete","node":"...","user_id":"...","key_id":"...","sign_pk":"...","provider":"...","state":"...","record_id":"...","time_ms":0})
```

`sign_pk` is the account signing public key (b64u of 32 bytes) of the grant under which the
authorization started. The app opens the web authentication session only after it verified three
things of the `oauth_begin` statement: the signature, `sign_pk` (all 32 bytes equal its own public
key) and `url_sha256` (the hash of the address it is about to open). From the `oauth_complete`
statement the app learns that the token of that `state` was issued inside that node and became the
record `record_id`, and it compares `sign_pk` in the same way. A node keeps `sign_pk` in the
pending authorization. When, at the completion, the `sign_pk` of the grant is not that value, the
node refuses with `key_mismatch`. A comparison of `key_id` (8 bytes) alone is no binding: a node
takes a new grant of the same `user_id` from anyone and replaces the grant before it, so the grant
of another signing key whose first 8 hash bytes are equal would pass that comparison.

### 8.3 The merge rules of the token object (node)

| Situation | Rule |
| --- | --- |
| First exchange | `token` = the token response object of the provider |
| Refresh | `token` = the old `token` with the keys of the response written over it. When the response has no `scope`, the old value stays. When the response has no `expires_in`, that key is removed |
| A provider whose token place is nested (`token_container` of the definition, `authed_user` for slack) | The `access_token`, the `refresh_token` and the `expires_in` of the refresh response are written into that place. When the response has no `expires_in`, that key is removed from that place |
| The merge of a reconnect (`oauth/merge`) | When the new `token` has no `refresh_token`, the `refresh_token` of the old record is moved into it (at the token place). Only the `refresh_token` moves (the `client_id` of a dynamically registered client stays the value of the new record) |

Reading the token place: for a provider with a `token_container`, `access_token`, `refresh_token`,
`scope` and `expires_in` are looked up inside that object first, and at the top level when they are
not there (the exchange response of slack is nested and its refresh response is flat). A token
response is accepted when `access_token` is at one of the two places. A `scope` of a refresh
response that is the empty string counts as absent (the old value stays).

## 9. Release statements and the public record (stage 3)

- A release statement is an in-toto statement. Its `predicateType` is
  `https://pickle.com/credential-enclave/release/v1`, its `subject` is the enclave image file (name
  `enclave.eif`, digest sha256), and its `predicate` is
  `{"release":"v1.0.0","git_commit":"<40 hex>","pcr0":"<96 hex>","pcr1":"<96 hex>","pcr2":"<96 hex>","inputs":{the table of the sha256 of the build inputs}}`.
- The `release` workflow of this repository creates the signature and the entry of the public
  record as a GitHub artifact attestation (a Sigstore bundle: a short-lived certificate issued by
  Fulcio, a DSSE signature, a proof of the entry in Rekor).
- The verification rules of a verifier (the app, a node):
  1. Verify the DSSE signature with the public key of the certificate of the bundle (ECDSA P-256,
     SHA-256).
  2. Verify the certificate chain up to the pinned Fulcio root (the time of the verification is
     the time of the Rekor entry).
  3. Check in the extensions of the certificate: the issuer
     `https://token.actions.githubusercontent.com`, the repository `pickle-com/credential-enclave`,
     the workflow `.github/workflows/release.yml`, and a ref that is a tag starting with
     `refs/tags/v`.
  4. Verify the proof of the Rekor entry (the signed entry time, or the inclusion proof and the
     checkpoint signature) with the pinned Rekor public key.
  5. Read the `predicateType` of the statement and the measurements of its `predicate`.
- In the app, the JavaScript program does this verification with the native functions
  `ecdsaVerify`, `x509Verify` and `sha256`.

## 10. Delegation transfer between nodes and witnessing

A node hands delegations to another node only after it verified that node by its attestation. The
operator domain supplies the address of the peer and carries the messages (a node does not trust
the carrier). The delegation transfer (10.1) and the delegation transfer to a later release (10.3)
are part of stage 1. Witnessing (10.2) is stage 2.

### 10.1 The delegation transfer

Purpose: the delegation of an account stays when a node restarts or is replaced. A node that
started takes the delegations from a node that is alive. The delegations are lost only when all
nodes disappear at the same time. In that case the app delegates again the next time it runs its
synchronization with the nodes (when the app is opened, or when a push of the operator's backend
wakes it in the background).

```text
payload  = UTF-8(JSON {"v":1,"type":"transfer","from":<giving node>,"to":<receiving node>,"time_ms":0,
                       "grants":[{"user_id":"...","sign_pk":"...","log_pk":"...","custody":"...","user_key":"...","not_after_ms":0}]})
signed   = UTF-8(JSON {"payload": b64u(payload),
                       "sig": b64u(Ed25519(giving node signing key, "pickle.secure.v1.peer\n" || payload))})
envelope = JSON {"v":1,"from":<giving node>,"to":<receiving node>,"enc":b64u,"ct":b64u}
           HPKE single-shot seal: recipient public key = the sealing public key of the receiving node, info = UTF-8("pickle.secure.v1.peer"),
           aad = UTF-8(from + "\n" + to), plaintext = signed
```

The rules of the giving node (`peer/export`. The input is the attestation response of the
receiving node):

| Step | Rule | Failure code |
| --- | --- | --- |
| 1 | The node verifies the attestation response of the receiving node: platform `nitro` by 4.3 (without the nonce check), platform `local` by parsing `binding`. This gives the signing public key and the sealing public key of the receiving node | `peer_unverified` |
| 2 | The platform of the receiving node is the platform of this node (nothing is handed to a node of another custody) | `peer_unverified` |
| 3 | Platform `nitro`: PCR0, PCR1 and PCR2 of the receiving node all equal those of this node (without an endorsement, delegations go to a node of the same release only. A PCR whose value is all zero is refused). A call with an endorsement follows check 7 of 10.3 in the place of this step | `peer_unverified` |
| 3a | The log store that the binding of the receiving node names is the log store of this node: the same bucket and the same region, or no `log` on both sides (delegations stay among nodes that write to the same log store) | `peer_unverified` |
| 4 | The receiving node is not this node | `invalid_request` |
| 4a | The node can write to its log store (7.6). A node of platform `local` without a log store passes | `log_store_unavailable` |
| 5 | The node selects the accounts that have a grant within its time, in the lexical order of `user_id`, one page at a time (at most 1,000 accounts). An account whose final head (`final`) is already signed is skipped (no entry may follow a final head, and no transfer is made without its entry). An account whose grant was handed to 64 other nodes is skipped as well (see below). For every selected account, inside the lock of that account: when the node hands that grant to the receiving node for the first time, it creates the log entry `grant_transferred_out` | |
| 5a | The node writes the entries to the log store: the entries of step 5, and the entry of an earlier call for the same receiving node that the store has not confirmed. It goes on only when the store confirmed the entry of every selected account | `log_store_unavailable` |
| 5b | For every selected account, inside the lock of that account again, the node puts the grant into the transfer when the account still has that grant: the grant within its time whose entry for this receiving node the store confirmed. An account that revoked in between, and an account whose grant was replaced in between, is left out | |
| 6 | The node signs the transfer, seals it to the sealing public key of the receiving node and returns it. The entries that step 5 created are carried in the same response | |

- The nonce and the age of the document of the receiving node are not looked at. The document
  proves that the private key of that sealing public key was created inside an enclave of that
  measurement, and that fact does not change with time. A transfer made for the old document of a
  node that is gone can be opened by no private key.
- The entries of a transfer are not stopped by the limit of entries without a storage
  acknowledgement (64), like the entries of a command.
- There is one entry per grant and receiving node. A node keeps, with every grant in its memory,
  the list of the nodes it handed that grant to. The first transfer of a grant to a node creates
  the entry `grant_transferred_out` and puts that node on the list. A repeated transfer of the
  same grant to a node of the list carries the grant again and creates no entry: a transfer whose
  envelope was lost on its way is made again, and the entry that names the receiving node is on
  the chain already. A node is put on the list when the entry is created, also when the log store
  does not confirm that entry: the repeated call writes that entry again and hands the grant
  over once the store confirmed it. The list holds at most 64 nodes. A grant whose list is full is handed to no
  further node: its account is skipped, without an entry. So a carrier that repeats the call adds
  at most 64 entries per grant to a chain.
- The list belongs to the grant state in the memory of the node. A grant command, a revoke, the
  end of the grant and a transfer that puts a grant in place on this node (step 3 of the
  receiving node) create a new state, and the list of a new grant is empty.

The rules of the receiving node (`peer/import`. The input is the attestation response of the
giving node and the envelope):

| Step | Rule | Failure code |
| --- | --- | --- |
| 1 | The node verifies the attestation response of the giving node by the rules of steps 1 to 3a above. In step 3 the measurement of the giving node is that of this node or that of a predecessor of this node (10.3) | `peer_unverified` |
| 2 | The `to` of the envelope is the `node` of this node and its `from` is the giving node of step 1. The node opens the envelope with its sealing private key and verifies the signature with the signing public key of the giving node. `from` and `to` of the payload equal those of the envelope | `wrong_node`, `open_failed`, `bad_signature` |
| 3 | For every grant: only a grant whose `custody` is the custody of the platform of this node and whose `not_after_ms > now` is looked at. A grant of an account whose revoke command this node accepted before is skipped (see below). When the account has no grant within its time, the node puts the grant into its memory and creates the log entry `grant_transferred_in`. When the account has a grant of the same `sign_pk` within its time, the larger `not_after_ms` stays (no entry). When the account has a grant of another `sign_pk`, the grant of the transfer is skipped | |

- The receiving node shortens the `not_after_ms` of a grant it takes to the limit of 5.2
  (`now + 30 days`).
- The receiving node does not write its entry `grant_transferred_in` to the log store in that
  call: the entry is a pending entry, and the next write of the account on that node takes it
  along (7.6). What says where a grant went is the `grant_transferred_out` of the giving node,
  which the store confirmed before the transfer was made.
- Revocation and delegation transfer: a node that once accepted a revoke command of an account
  takes no delegation transfer for that account for as long as the node lives. This holds also
  after a grant command replaced the revocation marker. Grant commands of the app are taken as
  before. The reason: an envelope is a value that the carrier can keep and send again. Without this
  rule, a carrier could erase the revocation marker after a revoke with the grant of an arbitrary
  key that ends at once, send the kept envelope again, and bring the revoked user key back until
  its old expiry.
- The order of the checks of an envelope and their codes: a `v` of the envelope or of the payload
  that is not 1 is `unsupported_version`. When the `to` of the envelope is not this node, or its
  `from` is not the verified peer, the code is `wrong_node`. A failed open is `open_failed`. A
  signature that does not verify is `bad_signature` (the signature is verified before the payload
  is parsed). A wrong `type` of the payload, a grant of a wrong form and a transfer of more than
  1,000 grants make the whole transfer `invalid_request`. When `from` and `to` of the payload
  differ from those of the envelope, the code is `wrong_node`.
- The app reads `grant_transferred_out` on the chain of the giving node and learns the receiving
  node from it. It verifies the signatures of the entries of the receiving node with that `to`
  value (the signing public key of the receiving node). This tracing is part of the guarantee of
  the log: if the app did not verify the chain of the receiving node, it would not show when the
  entries of a credential that was used on the node that took over the delegation are not stored.
- The app sends the revocation of a delegation to every living node: a node to which the app never
  handed a delegation can hold one that it took over. A node that accepted the revocation takes no
  transfer for that account (step 3 of the table above).
- Both calls take an optional `subset` object (10.4). With it, the giving node selects the
  accounts of the share of the receiving node alone, and the receiving node keeps the grants of
  its own share alone.
- A transfer to a node of a later release follows 10.3: the release key of the operator and the
  public transparency log decide which release receives the delegations of a node.
- A transfer to a node of another release under a rule of the account is stage 3: the app writes
  the list of the measurements it verified against the public record into the grant (the device of
  the account decides which releases may receive its key), and the giving node hands a delegation
  over when the measurement of the receiving node is on the list of that account. In stages 1 and
  2, a node of a new release that receives no delegation by 10.3 receives its delegations from the
  apps (the operator runs the nodes of the old release alongside for that time).

### 10.2 Witnessing (stage 2)

```text
payload = {"v":1,"type":"witness_request","user_id":"...","node":<from>,"seq":1,"entry_hash":b64u,"challenge":"..."}
```

The envelope and the signature are those of 10.1. `challenge` is the value that the attestation
response of the receiving node gave (it prevents a replay). The response is the `witness` of 7.5. A
witness node accepts only a `seq` that is larger than the last `seq` it holds for that
(node, account) pair.

### 10.3 The delegation transfer to a later release

Purpose: the delegations of the accounts stay when the operator replaces the nodes of one release
with the nodes of a later release. A giving node hands delegations to a node of a later release
when the release key of the operator signed the measurements of that release and the public
transparency log Rekor (rekor.sigstore.dev) recorded that signature. A receiving node takes
delegations from a node of a release that its own program lists as a predecessor. The payload, the
envelope, the entries and the rules of the log store are those of 10.1. This section states which
node of another release a node accepts.

Three values are compiled into the node program, so they are part of its measurement:

| Value | What it is |
| --- | --- |
| The release key | The public key of the operator whose signature over a release statement a giving node asks for: ECDSA P-256, as the DER of its SubjectPublicKeyInfo (91 bytes) |
| The log key | The public key of the transparency log: ECDSA P-256, in the same form. The log identifier is the lower-case hexadecimal SHA-256 of that DER. For Rekor of rekor.sigstore.dev it is `c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d` |
| The list of predecessors | `[{"release":"v1.1.0-rc.1","pcr0":"<96 hex>","pcr1":"<96 hex>","pcr2":"<96 hex>"}]`: the releases whose nodes a node of this program takes delegations from, each with its measurement |

The release statement of this section is the exact bytes of the file `measurements.json` of the
later release (enclave.md 11.1). It is not the in-toto statement of section 9. A node reads four
keys of it: the string `release` and the strings `pcr0`, `pcr1` and `pcr2`. It does not read the
other keys.

The log entry: the operator signs the bytes of the statement with the release key (ECDSA P-256
with SHA-256, the signature in ASN.1 DER) and records the signature in the log as an entry of the
kind `hashedrekord`, version 0.0.1. The body of the entry is, after its standard base64 is
decoded:

```text
{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{
   "data":{"hash":{"algorithm":"sha256","value":"<lower-case hex SHA-256 of the statement>"}},
   "signature":{"content":"<standard base64 of the signature>",
                "publicKey":{"content":"<standard base64 of the PEM of the release public key>"}}}}
```

The log returns the body with the time at which it took the entry, the index of the entry, its
log identifier and the signed entry timestamp. The signed entry timestamp is the signature of the
log key (ECDSA P-256 with SHA-256, ASN.1 DER) over the UTF-8 bytes of

```text
{"body":"<body>","integratedTime":<integrated_time>,"logID":"<log_id>","logIndex":<log_index>}
```

with the keys in this order, without white space, `<body>` as the standard base64 string the log
returned, and the two integers in decimal.

The endorsement is the value of the key `endorsement` of `peer/export`:

```text
endorsement = JSON {"statement": b64u(the bytes of the statement),
                    "entry": {"body":"<standard base64, exactly as the log returned it>",
                              "integrated_time":0,"log_index":0,
                              "log_id":"<64 lower-case hexadecimal characters>",
                              "signed_entry_timestamp":"<standard base64>"}}
```

The rules of the giving node (`peer/export` with `endorsement`). Every check must hold. The failure
code of each of them is `peer_unverified`:

| Check | Rule |
| --- | --- |
| 1 | The statement is at most 16,384 bytes long and is a JSON object whose `release` is a string and whose `pcr0`, `pcr1` and `pcr2` are 96 lower-case hexadecimal characters each. A statement that holds one of these four keys twice is refused |
| 2 | `entry.log_id` equals the log identifier of the log key of the node |
| 3 | `entry.body` consists only of the characters `A` to `Z`, `a` to `z`, `0` to `9`, `+`, `/` and `=`. `entry.signed_entry_timestamp`, decoded with standard base64, is a signature of the log key over the bytes above, built from `entry.body`, `entry.integrated_time`, the log identifier of check 2 and `entry.log_index` |
| 4 | `entry.body`, decoded with standard base64, is a JSON object with `apiVersion` `"0.0.1"`, `kind` `"hashedrekord"` and `spec.data.hash.algorithm` `"sha256"`. Its `spec.data.hash.value` equals the lower-case hexadecimal SHA-256 of the statement. Its `spec.signature.publicKey.content`, decoded with standard base64 and then as PEM, gives DER bytes that equal the DER of the release key of the node. Its `spec.signature.content`, decoded with standard base64, is a signature of the release key over the bytes of the statement |
| 5 | `entry.integrated_time` lies at most 300 seconds after the time of the node. The notice period is the age an entry must have before its statement counts: with a notice period above zero, `entry.integrated_time` plus the notice period is not after the time of the node, and the 300 seconds do not shorten the period. The notice period is 0 seconds |
| 6 | The release of the statement is later than the release of the node, in the order below. A node whose own release is not a release tag (for example `dev`) accepts no endorsement |
| 7 | The receiving node: its attestation response verifies by step 1 of 10.1 on platform `nitro`, and the platform of this node is `nitro` (a node of platform `local` accepts no endorsement). PCR0, PCR1 and PCR2 of its document equal those of the statement, not those of this node. No PCR is all zero. The `release` of its binding equals the `release` of the statement. Its binding names the log store of this node (step 3a of 10.1) |

After check 7 the call continues with step 4 of 10.1. A call without `endorsement` follows 10.1.
When `endorsement` is present, the checks above apply and step 3 of 10.1 does not: a node of the
measurement of the giving node is not the node of the statement.

The rule of the receiving node (`peer/import`): in step 1 of the receiving node of 10.1, the
measurement of the giving node is accepted when PCR0, PCR1 and PCR2 equal those of this node, or
when they equal those of one element of the list of predecessors and the `release` of the binding
of the giving node equals the `release` of that element. The other steps are those of 10.1. A node
reads the list once, when it starts. It does not start when the list is not a JSON array of such
elements, when the `release` of an element is not a release tag or is not earlier than the release
of the node, or when a PCR of an element is all zero. A node whose own release is not a release
tag starts with the empty list only.

The order of releases: a release tag is `v{major}.{minor}.{patch}` or
`v{major}.{minor}.{patch}-rc.{n}`. Each number is decimal without a leading zero (a lone `0` is a
number) and fits an unsigned 32-bit integer. Releases are ordered by major, then minor, then patch,
each as a number. Of two releases with the same three numbers, the one with `-rc.{n}` is earlier
than the one without, and of two with `-rc.{n}` the one with the smaller `n` is earlier. A text of
any other form is not a release tag and has no place in the order.

- A transfer between two releases goes from the earlier release to the later one. It takes place
  when both programs agree: the giving node verified the endorsement of the later release, and the
  program of the later release lists the giving release as a predecessor with the measurement of
  the giving node.
- A statement counts only with its entry in the public log. A release that received delegations
  under this section has its statement hash, signed by the release key, in a log from which no
  entry is removed.
- The node verifies the signed entry timestamp: the statement of the log, signed with the log key,
  that it took the entry at that time. The node does not verify an inclusion proof or a checkpoint
  of the log. That the log holds every entry it signed a timestamp for rests on the operation of
  Sigstore Rekor.
- A node holds one log key. When the log signs its entries with another key, a node with the old
  key verifies no endorsement made after that change and hands no delegation to a later release.
  The nodes of the later release then receive their delegations from the apps (10.1).
- An endorsement is a public value and has no end: a node of an earlier release accepts it for as
  long as that node runs. The age of the entry is looked at in check 5 only.
- The account sees the transfer on its chain as it sees every transfer: the entry
  `grant_transferred_out` on the chain of the giving node names the receiving node (10.1).

### 10.4 The delegation subset

Purpose: the operator runs `pods` nodes and gives the delegation of every account to `copies` of
them, so that the state of a node and the work of a transfer grow with the accounts of its share
and not with every account. The nodes are numbered by their ordinal, 0 to `pods - 1`, and the
operator's backend lists for an account the nodes of its share. The nodes of an account are a
function of the account and the two integers alone:

```text
rank(user_id, ordinal) = SHA-256(UTF-8(user_id) || "\n" || UTF-8(ordinal as decimal digits))
assign(user_id, pods, copies) = the first min(copies, pods) ordinals of 0..pods in the ascending
                                order of (rank(user_id, ordinal), ordinal)
```

The order of two ranks is the order of their 32 bytes. A node that restarts keeps its ordinal
and its share. When `pods` grows by one, the accounts whose first `copies` ordinals gain the new
ordinal hand one ordinal over to it and every other account keeps its ordinals; when `pods`
shrinks by one, the accounts that held the removed ordinal gain the ordinal that ranks next for
them and every other account keeps its ordinals.

The `subset` object of a request names the nodes the operator runs, the ordinal of the node the
request is about and the nodes per account:

```text
subset = {"pods": 3, "pod": 1, "copies": 2}
```

`pods` is 1 to 1,024, `pod` is below `pods` and `copies` is at least 1; a `copies` at or above
`pods` names every node. Another value is `invalid_request`. A node does not know its own
ordinal: the caller names it. A false value from the caller makes a node hold fewer grants, never
more: the receiving node of a transfer and the node that prunes still verify every other rule.

| Call | What `subset` does |
| --- | --- |
| `peer/export` (`pod` is the ordinal of the receiving node) | The page selects the accounts whose `assign(user_id, pods, copies)` contains `pod` alone, and `limit` counts those. Without the key the page selects every account with a grant, as 10.1 states |
| `peer/import` (`pod` is the ordinal of this node) | A grant of the envelope whose account's `assign(user_id, pods, copies)` does not contain `pod` is left out: not put in place, no entry, not counted in `imported`. Without the key every grant of the envelope is taken. A giving node of a release without this rule hands every account over, and the receiving node keeps its share all the same |
| `grants/prune` (`pod` is the ordinal of this node; the key is required) | The node walks its accounts in `user_id` order after `after` and drops the grant, within its time or expired, of every account whose `assign(user_id, pods, copies)` does not contain `pod`: the user key is overwritten with zeros and the account has no grant, as at the end of a grant. No entry is created (nothing is used: the operator chose which nodes hold a key). A revocation marker and the chain of the account stay. The response lists the `user_id` of every pruned account and the `user_id` the walk continues after, the empty string when it reached the end (enclave.md 5.15) |

Test vectors of the assignment; the backend of the operator computes the same function:

| `user_id` | `pods` | `copies` | `assign` |
| --- | --- | --- | --- |
| `user-1` | 3 | 2 | {0, 1} |
| `00000000-0000-4000-8000-000000000007` | 12 | 2 | {2, 6} |
| `alice` | 5 | 3 | {0, 2, 3} |
| `bob` | 4 | 1 | {1} |
| `사용자 1` | 6 | 2 | {0, 4} |
| `carol` | 2 | 5 | {0, 1} |

## 11. All failure codes (node)

| Code | Meaning |
| --- | --- |
| `invalid_request` | A violation of a form, a length or a required key. A call of a path that is not defined and a call with a method that is not allowed have this code too |
| `unsupported_version` | `v` is not 1 (envelope, command, record) |
| `wrong_node`, `open_failed`, `bad_signature`, `bad_challenge`, `bad_expiry`, `unsupported_policy`, `custody_mismatch` | Failures of command processing (5.3). `custody_mismatch` means that the `custody` of the grant is not the custody of the platform of that node |
| `peer_unverified` | The attestation response of a peer does not verify, or its platform, its measurement or its log store is not one this node accepts (10.1). The endorsement of a later release fails a check of 10.3 |
| `user_mismatch` | The `user_id` of a command is not the account of the call (5.3). The `user_id` of a record is not the account of the call (section 6). The account of a pending authorization is not the account of the call |
| `internal` | A failure of the platform (the attestation device, the random source). The call ends without changing anything |
| `not_configured` | The operator configuration has not arrived yet |
| `closing` | The orderly shutdown has started |
| `grant_required` | The account has no grant |
| `grant_revoked` | The account revoked its delegation |
| `grant_expired` | The time of the grant has passed |
| `key_mismatch` | The `key_id` or the `custody` of a record is not that of the grant. The `sign_pk` of a pending authorization is not the `sign_pk` of the grant |
| `record_invalid` | The form of a record is wrong, or its AEAD verification failed. The plaintext lacks the field that the call uses (no token to inject, no `refresh_token` to refresh with) |
| `provider_unknown` | The provider has no definition |
| `not_allowed` | An address, a method, an authorization parameter or a field that the provider definition does not allow. A record of a kind that the call does not take |
| `state_unknown` | There is no pending authorization, or its time (600 seconds) has passed |
| `exchange_failed`, `refresh_failed` | The provider refused the exchange or the refresh. The failure carries the HTTP status of the provider and one word of a closed vocabulary for the error of its response (enclave.md 5.7) |
| `provider_unreachable`, `timeout` | A transport failure, a time limit that passed |
| `response_withheld` | A provider response failed a check of rule E4 of the egress policy (egress-policy.md) and was not handed on. A repeated call does not change the outcome |
| `too_large` | A body above the limit (64 MiB each for a request and a response; for `forward/batch`, the bodies of the results together) |
| `log_store_unavailable` | The log store did not confirm the entry of the call, or the node cannot write to it: it has no log store in its configuration, or no credentials within their time (7.6). The act of the call did not take place. A repeated call can succeed |
| `capacity_unavailable` | The mail call could not immediately reserve its slot or body budget. No credential was opened and no provider request was sent. A later call can succeed |

## 12. Constants

| Name | Value |
| --- | --- |
| Longest time of a grant | 30 days (of node time. A node accepts a larger value and shortens it) |
| Interval at which the app renews a grant | The smaller of 24 hours and half of the lifetime of the grant |
| Lifetime of a challenge | 300 seconds |
| Lifetime of a pending authorization | 600 seconds |
| Merge window of identical GET requests | 300 seconds |
| Time a node keeps the response of a successful `refresh` (enclave.md 5.7) | 3,600 seconds |
| Kept `refresh` responses per account | 16 (the most recent ones) |
| Longest time a node keeps receiving the response of a token address call of `refresh` after the time limit of the call, counted from the start of the call (`TOKEN_LATE_LIMIT`, enclave.md 5.7) | 120 seconds |
| Token address calls of `refresh` a node continues after their time limit at once (`REFRESH_LATE_TASKS`) | 128 |
| Most accounts in one delegation transfer | 1,000 |
| Most nodes that a node hands one grant to (10.1) | 64 |
| Nodes a delegation subset names (`pods`, 10.4) | 1 to 1,024 |
| Nodes per account of a delegation subset (`copies`, 10.4) | 1 to `pods` (a larger value names every node) |
| Most pruned accounts in one page of `grants/prune` (10.4, enclave.md 5.15) | 1,000 |
| Most accounts one `grants/prune` call looks at (`SCAN_LIMIT`) | 10,000 |
| Longest release statement (10.3) | 16,384 bytes |
| Notice period of a release (10.3) | 0 seconds |
| Longest time by which a log entry lies after the time of the node (10.3) | 300 seconds |
| Most events in one entry (`ENTRY_EVENTS`) | 128 |
| Most bytes of the plaintext of one entry (`ENTRY_PLAINTEXT_BYTES`) | 1,048,576 |
| Most requests in one forward batch (`FORWARD_BATCH_REQUESTS`) | 100 |
| Requests of one forward batch in flight at once (`FORWARD_BATCH_CONCURRENCY`) | 6 |
| Provider requests of a node in flight at once (`PROVIDER_INFLIGHT`) | 512 |
| Idle connections of a node to its log store (`LOG_STORE_IDLE_CONNECTIONS`) | 32 |
| Idle connections of a node to one provider host for one account, and their idle time (`PROVIDER_IDLE_CONNECTIONS`, `PROVIDER_IDLE_MS`) | 8, 30 seconds |
| Pending entries of an account at which a call that uses a credential creates no entry (`PENDING_ENTRIES`) | 64 |
| Interval of the sweep of a node, which writes the pending entries of every account again (`SWEEP_INTERVAL`) | 30 seconds |
| Retention of an object of the log store (Object Lock), expiry of the bucket lifecycle (`LOG_RETENTION_DAYS`, `LOG_EXPIRY_DAYS`) | 365 days from the node time of the write, 400 days |
| `API_TIMEOUT_MS`, `LOG_API_TIMEOUT_MS`, `LOG_STORE_TIMEOUT_MS`, `NODE_TIMEOUT_MS` (the app) | 30,000, 10,000, 10,000 and 30,000: the time limit of a request to the backend, of a request of a round or of the log screen to the backend, of one attempt of a request to the log store, and of a command to a node through the relay route ("The program of the app") |
| `PROCEDURE_LIMIT_MS`, `LOG_ROUND_LIMIT_MS` (the app) | 100,000 and 60,000: the longest time of one procedure, without the time the device waits for the user, and of one round |
| `GRANT_REFILL_MS`, `ATTESTATION_NODES` (the app) | 60,000: the age of the last grant the device sent a node from which a synchronization of the push reason `grant_required` hands that node a grant again when the backend reports none for it. 32: the nodes one attestation request names |
| `LOG_ROUND_INTERVAL_MS`, `LOG_ROUND_RETRY_MS` (the app) | 24 hours and 60,000: a synchronization runs a round when the last completed one is this old, and tries a round that did not complete again not sooner than this after it |
| `LOG_CONTROL_PAGES` (the app) | 4: the listing pages of the control prefix one round reads (1,000 object versions each); a longer listing is read on by the next round |
| `LOG_DOCUMENT_NODES`, `LOG_DOCUMENT_REQUESTS`, `LOG_BODY_KEYS`, `LOG_ROUND_BODY_REQUESTS` (the app) | 64 and 2: the nodes one request for node documents names, and such requests per round (the store is asked for one listing per node such a request hands out no verifying document for). 200 and 4: the keys one request for bodies names, and such requests per round |
| `LOG_WITHHELD_KEYS`, `LOG_WITHHELD_PAGES`, `LOG_WITHHELD_OBJECTS`, `LOG_WITHHELD_CHAINS` (the app) | 32, 2, 16 and 8: the keys of entries, the listing pages of the log screen, the entries of chains of formats 1 and 2 and the listings of such chains whose read was held back that the device keeps for the rounds to make again. 32 is also the number of new control keys a round listed and did not come to judge that the device keeps for the next round, and 16 the number of `seq`s of chains under which more objects lie than the screen reads |
| `LOG_LEFT_DOCUMENT_REQUESTS`, `LOG_LEFT_BODY_REQUESTS` (the app) | 2 and 2: the requests for node documents and for bodies a round sends for the keys an earlier read left it, before it asks for a listing. They are not taken from the requests of the listing pages |
| `LOG_WATCH_MS` (the app) | 30 days: the time every round of a synchronization goes on reading the first listing pages for the log screen after that read was held back from the screen, unless the screen makes it sooner |
| `LOG_RECOVERED_KEYS`, `LOG_RECOVERED_EVENTS`, `LOG_RECOVERED_TEXT`, `LOG_RECOVERED_PAGES`, `LOG_RECOVERED_PAGE_EVENTS`, `LOG_RECOVERED_BYTES` (the app) | 128, 512 and 160: the entries the rounds keep for the log screen because the screen asked for their keys, the events of those entries (an entry holds 128 at most, so one entry is always kept), and the characters kept of one string of an event. 4 and 100: the listing pages they keep, and the events of the page kept of one (its entries are kept with it and take no place from the former). 262,144: the bytes of the kept value before it is sealed (beyond them an entry or a listing page leaves, whichever was kept first) |
| `LOG_DENIED_INTERVAL_MS`, `LOG_DENIED_KEPT_MS`, `LOG_DENIED_READS`, `LOG_DENIED_CHAINS` (the app) | 20 hours: a read held back from the log screen is noted as one more read when the last one noted is this old (the reads of one day are one, and the reads of two days in a row are two whatever the hours). 30 days: a read noted that is not among reads that mark the log ends this long after it was noted, and reads that mark the log end together when the last of them is this old. 8 and 8: the reads noted of one kind (the later pages, the listings of one chain of formats 1 and 2, the pages that held no entry), and the chains whose listings are noted |
| `LOG_UNFINISHED_ROUNDS`, `LOG_SYNC_ROUNDS` (the app) | 8: the rounds of synchronizations in a row that may end with more to read than a round reads before the first round of a synchronization that ends that way counts as one whose reads are held back (A3). 8: the rounds one synchronization has follow one another at most while each ends that way |
| `WAIT_LATE_MS` (the app) | 5,000: a wait that ends later than its own limit by more than this ended in a runtime that did not run for a part of it (the app was suspended), and a read of the log that fails that way failed with the device |
| `LOG_RELEASE_GRACE_MS`, `SERVED_FRESH_MS` (the app) | 24 hours: the time a measurement no list of the program has may hold the key of the account before it marks the log (A1). 1 hour: the age up to which a reading of the served version, or in a build that knows it itself the last check of the app for a new program, says that no later program is served |
| `LOG_DOUBT_ROUNDS` (the app) | 2: the rounds whose answers carried no signature that verifies for a key before the signatures of its node contradict each other (A2) |
| `LOG_BLOCKED_ROUNDS`, `LOG_BLOCKED_MS`, `LOG_REACH_MS`, `LOG_URL_FRESH_MS` (the app) | 3 and 3 days: the rounds in a row whose reads were held back (or the reads of one kind the log screen notes as held back from it), and the age of the first of them, at which the log is marked (A3). 60,000: a request that was not answered counts as held back when the backend answered another request of the runtime within this time. 240,000: the age of a signed address from which a refusal of the store is the age of the address |
| `LOG_RETENTION_DAYS` (the app) | 365: a key older than this is expected by no reader (the retention of its lock), and a key is expected in the listing while it is a day younger (A4) |
| `LOG_SAMPLE_KEYS`, `LOG_SEEN_PART`, `LOG_SEEN_PARTS`, `LOG_SEEN_KEYS`, `LOG_NODES_KEPT` (the app) | 64: the control keys of the sample of A4. 4,096, 9 and 32,768: the digests of the control keys the device judged are kept in parts of 4,096, nine parts at most (when one more begins, the oldest leaves), so the device remembers 32,768 judgements or more. 256: the nodes whose judgement the device keeps |
| `LOG_SCREEN_EVENTS`, `LOG_KEEP_EVENTS`, `LOG_SCREEN_WAIT_MS`, `LOG_SCREEN_REFILLS` (the app) | 50, 50 and 3,000: the events of one further page of the log screen, the events of the first page the device keeps, and the time `read_log` waits for the read of the store before it answers from what the device kept. 2: the times a page is read on below keys that turned out to be no entries |
| `LOG_PAGE_READS`, `LOG_CATCHUP_READS`, `LOG_SCREEN_KEYS` (the app) | 4: the requests that read the listings of the screen on for one later page. 16: the requests that read them on at one opening of the screen down to the later pages noted as held back. 20,000: the keys of the two listings the screen holds in a runtime (a page below them is listed from the marker of its time) |
| `LEGACY_SCREEN_LISTS`, `LEGACY_DISPLAY_LIST`, `LEGACY_HEAD_PAGES`, `LEGACY_ANCHOR_WALKS` (the app) | 12: the listings of chains of formats 1 and 2 one call of the log screen reads. 1,000: the `seq`s of one range of a chain the screen lists. 4: the pages of the listing of the end of a chain an opening reads before a listing without an end is noted as held back. 3: the times one call walks the chains because a chain stood on a `seq` that holds no entry of its node |
| `VAULT_MADE_NAMES` (the app) | 8: the names of the vault items `store_secret` made and that hold no value yet that the device keeps |
| `LOG_SUMMARY_DAYS`, `LOG_SUMMARY_ENTRIES`, `LOG_SUMMARY_REQUESTS` (the app) | 7, 1,000 and 5: the days of the summary of the log screen, the most entries one opening counts into it, and the requests for bodies one opening of the screen sends |
| `LEGACY_NODES`, `LEGACY_ROUND_PASSES`, `LEGACY_ROUND_BODIES`, `LEGACY_CLOSE_SLACK_MS` (the app) | 64, 4, 64 and 1 day: the chains of formats 1 and 2 one round follows (of more open chains, the ones a round listed longest ago), the passes of listings and the entry bodies it spends on them (one request for the documents of receiving nodes per pass; the receiving nodes that wait for a document count into the entry bodies of a round), and the time after the end of a grant at which the chain of its node is read for the last time |
| `LEGACY_SEQ_READS`, `LEGACY_PROBE_SEQS`, `LEGACY_SEQ_VERSIONS` (the app) | 8: the object versions a round reads under one `seq` of a chain for a control entry, and the log screen for an entry. 2: the `seq`s at the end of a listing page of a chain that a round reads to see how far the node wrote, when their keys name no control entry. 5: the object versions per `seq` a listing page of a chain that goes on holds at most, on average, when it holds what a node wrote and no more |
| `LEGACY_TRANSFER_DOCUMENTS_FROM_MS` (the app) | 1,795,392,000,000 (2026-11-23T00:00:00Z): for an event of this time or later, the receiving node of a transfer that a node of a release before v2.4.0 made is judged by a document that verifies and by nothing else ("Formats 1 and 2") |
| `LOG_STORE_CONCURRENCY`, `LOG_STORE_OBJECTS` (the app) | 8 and 100: the reads of the bucket of formats 1 and 2 in flight at once, and the object versions one address request names |
| `LOG_STORE_ATTEMPTS`, `LOG_STORE_RETRY_MS` (the app) | 2 attempts of one request to the store, a pause of 500 milliseconds between them: a transport failure, a 429 and a 5xx status are tried again |
| `OUTCOME_BOUNDS_MS`, `OUTCOME_EVENTS`, `OUTCOME_SLOW_MS` (the app) | 250, 1,000, 3,000, 10,000 and 30,000: the upper bounds of the classes a time of a procedure is counted into. 32: the calls a report carries one by one. 10,000: the time from which a call is reported one by one |
| Body limit | 64 MiB (67,108,864 bytes) |
| Longest `context` | 256 characters |

## 13. Test vectors

`protocol/vectors.json` of this repository is the reference file. The tests of the app use a
byte-identical copy of it. The tests of the node implementation and the tests of the app (they run
the program of the app on its native functions) must pass with the same file.

`cargo run -p credential-enclave-protocol --bin vectors` creates the file from fixed seeds: the
same input gives the same bytes, and the option `--check` fails when the committed file differs.
The top level is `{"v":1,"description":...}` and the keys below. Byte values are b64u. A key whose
name ends with `_text` holds the same value again as UTF-8 text.

| Key | What it holds | What the user of the vector expects |
| --- | --- | --- |
| `key_derivation` | `master_key`, `sign_seed`, `sign_pk`, `log_private`, `log_pk`, `user_key` (custody `enclave`), `user_key_operator` (custody `operator`), `key_id` | The other values follow from MK (section 3) |
| `record` | `user_key`, `id`, `nonce`, `user_id`, `key_id`, `custody`, `kind`, `provider`, `plaintext`, `aad_text`, `record_key`, `record` (the finished record), `tampered` (records with one field changed each, and `opens: false`. One of them has a changed `custody`), `imported` (a record of kind `oauth_imported` under the same user key: `id`, `nonce`, `kind`, `provider`, `plaintext`, `aad_text`, `record_key`, `record`) | A record created from the same input equals `record`, and the records of `tampered` do not open. The record of `imported` opens under `user_key` and has the plaintext form of kind `oauth` |
| `command` | The node keys (`node_sign_seed`, `node_sign_pk`, `node_seal_private`, `node_seal_pk`, `node`), the `info` and the `aad` of HPKE, the signature purpose, `cases` (`name`, `envelope`, `result`, `opens`, the opened `payload` and `sig`, `signature_valid`) | A node implementation opens the envelope and gives `result` (`ok` for a success, the code of 5.3 for a failure) |
| `signed` | `authorization_url_text`, `cases` (`name`, the signature purpose, `public_key`, `body`, `sig`, `valid`): replies, the two statements about an authorization, heads, a challenge statement, and changed ones (among them a reply offered under the purpose string of a challenge statement) | Every case verifies as `valid` says. The `url_sha256` of the `oauth_begin` statement is the hash of `authorization_url_text` |
| `log` | Format 2: the node signing public key, `user_id`, `key_id`, `log_private`, `log_pk`, `checkpoint`, `entries` (three entries: a control entry `grant_accepted`, a use entry with three `provider_request` events, a use entry with one `secret_released` event; each with `seq`, `hpke_seed`, `time_ms`, `kind`, `count`, `events_text`, `entry`, `body_text`, `body_hash`, `entry_hash`, `key`), `head_nonce`, `head`, `final_head`, `index_valid` (the keys alone verify to the head), `content_valid`, `missing_middle` (the keys without the middle one: `index_valid` false), `forged_key` (the keys with one more key of `seq` 2 whose `body_hash` is another and whose `entry_hash` is consistent with it: `ambiguous_seq` 2, and the content verification takes the genuine object alone) | The index verification of the keys and the content verification of the entries give these results, every entry opens to `events_text`, and an entry created with the same `hpke_seed` equals `entry` |
| `log_v1` | The vector `log` of format 1 as the releases before v2.0.0 wrote it: the node signing public key, `user_id`, `key_id`, `log_private`, `log_pk`, `checkpoint`, `entries` (three entries: `seq`, `hpke_seed`, `time_ms`, `event_text`, `entry`, `entry_hash`), `head_nonce`, `head`, `final_head`, `chain_valid`, `missing_middle` | A reader of format 1 verifies the chain with the same result and opens every entry to `event_text` |
| `attestation.local` | `nonce`, `response` (with its `challenge_statement`), `document_text`, `binding` (of a node without a log store: it has no `log` key), `sign_pk`, `seal_pk`, `release`, `challenge_statement_text` (the body of the statement), `accepted`, `rejected`: another nonce, a binding of version 2, and four responses with the accepted document and nonce that fail for the challenge statement alone (the statement is missing, it is the statement of another request, of another challenge, of another node) | The result of the verification of a local document and of its challenge statement (4.2, 4.4) |
| `attestation.nitro` | `included` (bool). When it is true: a real Nitro document, its nonce and the expected `binding`. In the committed file it is false, and a `note` states that the file holds no Nitro document | Nothing while `included` is false. Real Nitro documents are inputs of the tests of this repository (`protocol/tests/fixtures/`, `verify/tests/fixtures/`) |
| `totp` | A list of `seed_base32`, `time_ms`, `code` | RFC 6238 |
| `transfer` | The keys of the giving node and of the receiving node, `payload_text`, `signed`, `envelope`, `hpke_seed`, the result that the receiving node opened (`grants`), and `cases`: an envelope with a changed ciphertext (`opens: false`), a transfer signed by another key (`signature_valid: false`), an envelope for another node | A receiving node implementation opens the envelope and obtains the same list of grants (10.1) |

Of these, the tests of the app use `key_derivation`, `record`, `signed`, `log` and
`attestation.local`. Opening a `command` and computing a `totp` code are the work of a node. The
tests of the app open the envelopes that the app created themselves and check them.


## Mail statements and records

The mail record uses the same v1 record AAD and custody as every other credential record.
The plaintext username is a Naver account id or naver.com address and password is the application
password. Verification returns a statement signed with the `statement` purpose. Its body has
`v=1`, `type=app_password_verified`, `node`, `user_id`, `provider=naver_mail`, `record_id`,
`key_id`, the full `sign_pk`, `ciphertext_sha256` (base64url SHA-256 of the record.ct string's
UTF-8 bytes), `identity` (canonical naver.com address) and `time_ms`. The app verifies the signer
against its attested grant ledger and every binding against the record it created.

`mail_request` is the encrypted log event for verification, reads and submission. It records
`record_id`, `provider`, `operation`, typed `request`, `body_bytes`, `body_sha256` and `context`.
The act starts only after the log store confirmed it. This is an attempted act, not a delivery
receipt. Message content and application passwords are not in the event.

## The program of the app

This section states what the secure program of this repository (`secure-program/secure-program.js`,
from version 43 on) does on a device: the order of its work and its time limits, the
synchronization that hands the grants, how it reads and judges the log, what it shows on the log
screen, what it reports, and the procedures of the vault secrets. "The app" of sections 3 to 7 and
10 is this program. The formats, the commands and the verifications it applies are those of the
sections named in each part. Every number of this section is a constant of the program.

### The lines, the locks and the time limits

The work of the program runs on three lines. A line runs one piece of work at a time, in the order
of the calls, and the lines do not wait for one another.

| Line | What runs on it |
| --- | --- |
| The procedures a user starts | `create_key`, `reset_key`, `connect`, `set_connection_writes`, `manage_repositories`, `connect_app_password`, `begin_app_password_setup`, `cancel_app_password_setup`, `store_login`, `store_card`, `store_secret`, `reveal_secret`, `update_secret`, `delete_secret`, `reveal_login_password`, `set_grant_days`, `set_delegation`, the five procedures of the master key transfer and the steps of its polling |
| The synchronizations | The procedure `sync` and the synchronization an event starts. One runs and at most one waits: a trigger that arrives while one waits is served by the one that waits |
| The reads of the log screen | The read of the first page that `read_log` starts, `read_log_page` and `read_security_record` |

Two locks protect what two lines could change at once. The lock of the grants holds from the
judgement of the key to the record of the replies of the grant commands: a synchronization, and a
procedure that makes sure a node holds the grant before it connects or stores, do not overlap in
that span. The lock of the round holds one round of the log. Whoever holds a lock waits only for
requests, and every request has a time limit.

| Limit | Value |
| --- | --- |
| A request to the backend of a round or of the log screen | 10 s |
| A request to the log store (two attempts: a transport failure, a 429 and a 5xx status are tried once more after 0.5 s) | 10 s per attempt |
| Any other request to the backend, and a command to a node through the relay route | 30 s |
| One procedure, from its call to its end | 100 s |
| One round, from its start | 60 s |

A request that is not answered within its limit fails with the code `timeout`; an answer that
arrives later is dropped. A wait that ends more than 5 s after its own limit, or that was open
when the app went to the background, ended in a runtime that may not have run for a part of it:
its failure is marked, and a read of the log that fails with that mark failed with the device
("The round"). A procedure whose time is used up fails with `timeout` and its line goes
on to the next call. The time the runtime spends in an operation that waits for the user (`webAuth`,
`deviceOwnerAuth`, `promptSecret`, `presentSecret`) is not counted into the time of any procedure,
as the executors of the apps do not count it into their own limit of 120 s. Every loop of the
program has a bound on its turns (pages of a listing, requests, polls); the polling of a master
key transfer ends with the expiry of the transfer. A poll of a transfer that fails with the
transport, with its time, or with an answer of the status 429 or 500 to 599 (whatever code the
body names) is left to the next poll; any other failure ends the transfer as failed.

### The events

| Event | What the program does |
| --- | --- |
| `session_ready` | Clears the state of a master key transfer (a runtime does not take over the transfer of the runtime before it), publishes whether the build has the protected sheets and `runtime.named_secrets` as false ("The synchronization"), publishes the log as pending when this program has ended no round on the installation (the state an earlier program published is not a judgement of this one), counts the calls the runtime before left open as interrupted, judges the measurements the device kept (A1, "The round"), and starts a synchronization |
| `foreground` | Judges the measurements the device kept (A1) and starts a synchronization |
| `background` | Ends the reading of the round that runs: the round is judged on what it read and writes what it kept within the event ("The round"). Judges the measurements the device kept (A1), and notes the time for the calls that are open (the report of the outcomes) |
| `push` | With the reason `transfer_request`: reads the pending requests of a master key transfer. With any other reason: judges the measurements the device kept (A1), starts a synchronization and, when it ended, sends the report of the synchronization. A synchronization of the reason `grant_required` hands a grant again to a node the backend reports no grant for (below) |
| `account_end` | With the reasons `account_deleted` and `dev_reset`: deletes the master key item, the node ledger and the reception key of a mail setup from the key store, and everything the program store holds of the account. Work that is still running writes nothing of the account after that |

A synchronization the app itself triggers (`session_ready`, `foreground`) within 5 s of the start
of the one that runs is served by that one.

### The synchronization

1. `GET /api/secure/account` and, when the device holds a master key and delegation is on,
   `GET /api/secure/grants`, sent together. The second lists the nodes of the account without
   calling a node: `{"nodes":[{"node","not_after_ms","revoke_only"}]}`, where `not_after_ms` is
   the end of the grant the backend recorded for the account on that node, or null, and
   `revoke_only` true marks a node that is listed for its revokes alone ("The nodes that receive
   a grant"). Every request the program sends to a route under `/api/secure/`, these two among
   them, carries the query `program` with the version of the program: what the backend answers
   a device may depend on the program the device runs (the nodes it lists, the node it names
   for a connection), and a backend that does not know the query ignores it. No request to the
   log store and no request to another route carries it. The answer of the first may name the
   version of the program the backend serves (`served_program_version`, "A runtime behind the
   served program").
2. The judgement of the key: the master key of the key store against the `key_id` registered on
   the account (`absent`, `waiting`, `present`, `mismatch`, `account_mismatch`). A device with a
   master key registers its public keys when the account has none.
3. With the key `present` and delegation on, a listed node receives a grant when one of these
   holds: the device keeps no grant of it; the last grant the device handed it is the renewal
   interval old (the smaller of 24 hours and half of the lifetime of a grant); or the
   synchronization was started by a push of the reason `grant_required`, the backend reports no
   grant for the node (`not_after_ms` null), and the last grant the device sent it is 60 s old.
   What the backend reports decides nothing else: when a grant was handed and when it ends is what
   the device kept. A node the list marks `revoke_only` is none of these nodes.
4. When a node is to receive a grant, the program requests the attestation of those nodes only
   (`GET /api/secure/nodes` with `nonce` and `nodes`, the ids joined by commas, 32 per request),
   verifies each (4.3 and the next part), and sends the grant commands together (5.2). A node
   whose document verifies with a measurement no list has and no release proofs showed is asked
   once more, with the query `proofs=1` ("The release proofs"), before the commands go out. A
   synchronization without such a node sends no request that calls a node. A backend that has no
   route `GET /api/secure/grants` (status 404) is asked for the attestation of every node of the
   account instead, and what the device kept decides which of them receives a grant. Any other
   failure of the list fails the synchronization: a failed answer is never read as a list of nodes
   without grants.
5. With delegation off, the revoke is sent again to every listed node (5.4), whatever role the
   binding of the node names: a revoke hands no key over, so a node of a role this program does
   not know takes it as any node does. A node whose binding has the role `forward` holds no
   delegation and takes no command: it is sent none, and counts as revoked.
6. The state of the grants is published (`state.grant`: `active`, `partial`, `none`, `off`, with
   the earliest end), and `runtime.ready`.
7. While delegation is on, the sealing of values stored before the switch to device-side
   sealing (`GET` and `PUT /api/secure/sealing`, until a query found none) and the completion
   of a mail setup; then a round of the log when one is due.
8. The catch-up of a master key transfer.

The program publishes one more value of the answer of step 1, on a device with a master key and
on one without:

| Published | Value |
| --- | --- |
| `runtime.named_secrets` | Whether the backend turned the vault items with a name on for the account. A runtime publishes false at its start (what a runtime before it published, of this account or of another, does not stand) and true once the answer to `GET /api/secure/account` of the account of the device carries `named_secrets` true; any other answer, and a query that fails, leave the value as it is. The value is what the operator domain says, handed on to the screens as it is: the screens of the app choose their names by it, and no procedure of the program acts on it |
| `state.named_secrets` | The same value in the state, which the app keeps over its restarts (it keeps none of the runtime values): true with every answer that says so, and false with the first answer that does not say so after the device published true. An account that was never told true has no such key in its state (the device remembers in `vault.named` that it published true) |
| `runtime.program_stale` | Whether the runtime knows that a later program than this one is served ("A runtime behind the served program"), published whenever that changes. The screens of the app read it to tell the user that the app is loading a later program, and a build of the app may take it as the occasion to load the program that waits |

A procedure that needs a node holding the grant (a connection, the storing of a value) runs steps
1 to 4 once under the lock of the grants. With delegation off it fails with `delegation_off`; when
no listed node holds a grant, with `grant_required`, or with `attestation_failed` when every listed
node failed the verification or is of a release the program does not list. In a stale runtime
that no listed node takes a grant of (every listed node is of a release the program does not
list or failed the verification, or the backend lists none), the failure is `program_stale`: the
program is behind, and the app loads the served one at its next start or return to the
foreground. The outcome of the procedure is reported as a failure with that code. The statements
a node signs for a connection (8.2) are verified under the node id of a node the device handed a
grant to.

### The nodes that receive a grant

A node receives a grant when its attestation verifies (4.3) and:

- its measurement (PCR0, PCR1, PCR2) equals an element of the list of accepted releases of the
  program (4.5), or release proofs that this runtime verified show it ("The release proofs"). A
  document that verifies with a measurement no list has and no proofs showed is the document of
  a release later than the program: the node receives no grant and is not asked again by that
  program, but for the release proofs of its measurement an hour after the last request for
  them;
- its binding states no `program_min` above the version of the program (below);
- its binding names the log store of the server target (4.3 step 10, a node of platform
  `nitro`);
- its binding has no `role`, or the role `reserve` (a node that holds delegations and takes no
  call that uses a credential). A node whose binding has the role `forward` (a node that holds no
  delegation) or any other role receives no grant.

A node of platform `local` (4.4) is taken when the server target is one of the operator custody
targets, in a debug build, and in a build made for the local stack (`deviceInfo().local_stack_build`).

A node the backend lists with `revoke_only` true is a node of an earlier release outside the nodes
that serve the calls of this program, which holds a grant another device of the account handed it
(a device that runs a program before this one). This program hands it no grant, asks it for no
attestation in a synchronization, counts it neither among the nodes that hold a grant nor among
the ones that do not (it changes nothing of `state.grant` or of the result of a synchronization),
and does not write it into the node ledger of the programs before version 43: the entry of a
grant this program made on such a node is one those programs cannot explain. The revoke goes to
it as to every listed node when the user turns delegation off (after the attestation a revoke
needs), and `set_grant_days` sends it the revoke when the lifetime of a grant was shortened, so
that the grant it holds does not outlast a grant of the new lifetime; a revoke it does not
confirm fails that call with `grant_incomplete` and leaves the lifetime as it was. A longer
lifetime, and delegation turned on again, send it nothing. The chain of format 2 such a node
wrote is read as any chain of formats 1 and 2.

A binding may state `program_min`, a non-negative integer: the lowest version of the program whose
grant command the node takes. A node of an accepted release whose `program_min` is above the
version of the program receives no grant of that program. It is counted with the nodes of a later
release in the result of a synchronization, and a runtime asks it once. It is no node of a release
the program does not accept: its entries are judged as those of an accepted node, and nothing is
kept of its measurement. A binding whose `program_min` is anything but a non-negative integer is
refused (the target of a revoke is read whatever it states). A binding without the key states
none.

### The release proofs

The list of accepted releases is a constant of the program, so it holds the releases that existed
when the program was written. The nodes of a release made after that state a measurement the list
does not have. Such a measurement is that of an accepted release when release proofs show it:
values that anyone may hand to the program, and that the program verifies on the device with
constants of its own. With proofs that pass, the release counts as an element of the list that
writes to the log store: a node of the measurement receives the grant by the rules of "The nodes
that receive a grant" (its binding names the log store of the server target), the format of its
log follows from the name of the release, and its entries, and a transfer of the key of the account
to its measurement, are judged as those of an accepted release (7.4, A1). Without proofs that
pass, the node is one of a later release (4.3).

The proofs are a JSON object:

```text
release_proofs = {"statement": b64u(the bytes of the release statement),
                  "entry": {"log_id": "...", "body": "...", "integrated_time": 0, "log_index": 0,
                            "signed_entry_timestamp": "..."},
                  "deploy_signatures": [{"key_id": "prod", "signature": "<standard base64 of 64 bytes>"}],
                  "attestation": {the Sigstore bundle of the attestation of the release statement}}
```

`statement` and `entry` are the endorsement of 10.3 for a log of the form Rekor v1: the release
statement is the bytes of the file `measurements.json` of the release, and the entry is what the
log returned for the record of the signature of the release key over those bytes. `attestation` is
the bundle the release workflow of this repository attaches to the GitHub release of the tag as
`release-statement.sigstore.json` (enclave.md 11.2). The program does not read other members.

Every check must hold, for a measurement M (PCR0, PCR1 and PCR2 of a document that verified by
4.3):

| Check | Rule |
| --- | --- |
| P1 | The statement is at most 16,384 bytes long and a JSON object that states `release`, `pcr0`, `pcr1` and `pcr2` once each: `release` a release tag (10.3), each PCR 96 lower-case hexadecimal characters. The three PCRs equal those of M. Other members of the statement are not read |
| P2 | The release key signed the statement and a transparency log of the program recorded that signature: checks 2, 3 and 4 of 10.3 for a log of the form Rekor v1, with the release key and the log key the program holds. The time of the entry is compared with no clock (check 5 of 10.3 asks the clock of a node, and the notice period is 0 seconds) |
| P3 | `deploy_signatures` has at most 8 elements, each with the texts `key_id` and `signature`. Exactly one element names the key id of the server target of the build (`prod` for the server target `prod`, `dev` for every other), and its signature is the Ed25519 signature of that deploy key over the UTF-8 bytes of `pickle-enclave-release-statement-v1`, a line feed, the lower-case hexadecimal SHA-256 of the statement and a line feed. The deploy keys are the keys with which the apps verify the deploy signature of a served program, by the same rule of the key id. The deploy signature of a program covers `pickle-secure-program-v1`, a line feed and the program, so neither signature is one of the other kind |
| P4 | GitHub attested the statement: the attestation verifies by the rules below, under the identity of the release workflow at the tag `release` of the statement, and its in-toto statement has the predicate type `https://pickle.com/credential-enclave/release/v1` and a predicate whose `release`, `pcr0`, `pcr1` and `pcr2` equal those of the statement |
| P5 | The release of the statement is later than every release of the list of accepted releases of the program, in the order of releases (10.3) |

The attestation (P4) is a Sigstore bundle: the certificate Fulcio issued to the workflow run
(`verificationMaterial.certificate.rawBytes`), one entry of the transparency log
(`verificationMaterial.tlogEntries`), and the DSSE envelope of the in-toto statement
(`dsseEnvelope`: `payload`, `payloadType`, one signature). The program checks, in this order:

1. The bundle, as JSON without white space, is at most 65,536 bytes long, and it holds the
   certificate, exactly one log entry and an envelope with exactly one signature.
2. The payload type is `application/vnd.in-toto+json`, and the payload (standard base64) is a JSON
   object.
3. The certificate chain. The program holds the root certificate and the intermediate certificate
   of the certificate authority of the public instance of Sigstore (the SHA-256 of their DER:
   `3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1` and
   `15d795348226b4649f750f5802592c393bee7cc53c3b86982175b7ad087efe47`). The certificate of the
   bundle and these two are valid at the time the log took the entry (`integratedTime`: the
   certificate is valid for ten minutes, and no clock of a device is asked). The two certificates
   of the program are those of certificate authorities, and the certificate of the bundle is not.
   The intermediate issued the certificate of the bundle and the root issued the intermediate:
   the issuer name is the subject name of the issuer as encoded, and the signature is the ECDSA
   signature of the key of the issuer over the signed part. No trust store of the device and no
   network is asked.
4. The identity. The certificate states each of these values in its extension
   `1.3.6.1.4.1.57264.1.{number}`, whose value is the DER of one UTF8String. A certificate without
   one of them, or with another value, is refused. `{tag}` is the release of the statement.

   | Number | What it states | Value |
   | --- | --- | --- |
   | 8 | The issuer of the token the certificate was issued for | `https://token.actions.githubusercontent.com` |
   | 9 | The workflow that signed | `https://github.com/pickle-com/credential-enclave/.github/workflows/release.yml@refs/tags/{tag}` |
   | 11 | The runner | `github-hosted` |
   | 12 | The repository | `https://github.com/pickle-com/credential-enclave` |
   | 14 | The ref of the run | `refs/tags/{tag}` |
   | 15 | The identifier of the repository | `1400118248` |
   | 17 | The identifier of the owner of the repository | `151645824` |
   | 18 | The workflow that started the run | The value of 9 |
   | 20 | What started the run | `push` |
   | 22 | The visibility of the repository when the certificate was issued | `public` |

5. The signature of the envelope is the ECDSA P-256 signature of the key of the certificate over
   the pre-authentication encoding of DSSE: `DSSEv1`, a space, the length of the payload type, a
   space, the payload type, a space, the length of the payload, a space and the payload.
6. The log entry. Its log is a log of the program (`logId.keyId`). Its body
   (`canonicalizedBody`) is a JSON object of the kind `dsse` and the version `0.0.1`, whose
   `spec.payloadHash` is the SHA-256 of the payload, and whose `spec.signatures` is one element
   with the signature of the envelope and, as `verifier`, the PEM of the certificate of the
   bundle. The signed entry timestamp (`inclusionPromise.signedEntryTimestamp`) is the signature
   of the log key over the bytes of 10.3, built from the body, `integratedTime`, the log
   identifier and `logIndex`. The audit path (`inclusionProof`: at most 64 hashes) leads from the
   leaf of the body to `rootHash` in a tree of `treeSize` leaves, by the path computation of
   check 9 of "The secure program release". The checkpoint (`inclusionProof.checkpoint.envelope`)
   is the note of that size and that root, and it holds at least one line of the log key (a line
   whose bytes begin with the first four bytes of the log identifier), and every such line is an
   ECDSA signature of the log key over the note.

The signed certificate timestamps of the certificate are not read: that Fulcio issued the
certificate is on the log the program verifies, whose entry holds the certificate. The times and
the indexes of an attestation are non-negative integers, or decimal digits in a text without a
leading zero, below 2^53.

The identity of step 4 is what ties an attestation to this repository. 9 and 18 together say that
the release workflow at the tag signed and that it was started as itself: a workflow another
workflow calls shares the run of its caller, and runs with what the caller hands it. 11 says that a
runner GitHub hosts ran the job: a runner the owner of a repository registers signs whatever its
owner hands it, under the same workflow and the same tag. 15 and 17 name the repository and its
owner by identifiers that do not change and are not given to another repository: the address of 12
alone would also be that of a repository made later under the same name. 20 says that the push of
the tag started the run: a run started another way takes inputs that are not public. 14 and 22
say that the run was of the tag, in a repository that was public then.

The formats are read in one form. Base64 is the standard alphabet with its padding, or the
URL-safe alphabet without padding where a value is b64u, and a text whose last character carries
bits of no byte is refused. A text of JSON is UTF-8 and holds no number outside the finite ones,
no half of a surrogate pair, and at most 32 arrays and objects inside one another. An element of
DER has its shortest length form. An ECDSA signature is the DER of two non-negative integers
without unneeded bytes. Every signature is verified by a primitive of the bridge.

Where the proofs come from. Whoever hands them over, the checks above decide.

- The attestation response of a node (4.2) may carry them as the member `release_proofs`. The
  grant step asks for them: when the document of a node verifies with a measurement no list has
  and no proofs showed, the program requests the attestation of that node once more with the
  query `proofs=1` (`GET /api/secure/nodes` with `nonce`, `nodes` and `proofs`), for one node of
  each such measurement and four nodes at most in one step. With proofs that pass, that node and
  the other nodes of the measurement whose attestation the step holds receive their grants in the
  same step. No other request carries the query, and a step whose nodes are all of listed releases
  sends none. A request for proofs that fails leaves the node one of a later release for that
  step and fails nothing else.
- A node document (7.7) may carry them as the member `release_proofs`. A round that reads the
  document of a node of a measurement no list has verifies them with that document.

A node kept as one of a later release is asked for the proofs of its measurement again when the
last request for them is an hour old: the proofs of a release may reach the backend after its
nodes. A runtime verifies no further proofs while 8 of them failed within an hour. Proofs that
fail are logged with the check that failed (`release proofs refused: p4: identity 11`).

A node of a measurement the proofs show states the release of the proofs in its binding: a
document of that measurement whose binding names another release fails the verification.

What the device keeps (`log.proven`): the measurement, the release, the time and the proofs, under
the version of the program that verified them. A program reads what a program of another version
kept as nothing. The kept verdict counts where the log is judged. A node receives a key only from
a runtime that verified the proofs itself: a runtime verifies the kept proofs again before the
first grant it hands to a node of that measurement, and a kept verdict whose proofs fail is kept
no longer. The device keeps four measurements at most, and the proofs of one when their JSON is
at most 131,072 characters long (the verdict of longer proofs is kept without them, and the next
runtime asks for the proofs again).

What the proofs show, and what they do not. A release whose proofs pass has: the signature of the
release key over its measurements in the public log, where the monitor of this repository reads
every entry of that key (enclave.md 11.2); a signature of a deploy key of the operator; and an
attestation that a job of the file `.github/workflows/release.yml`, as that file is at the tag in
the repository with the identifier above, ran on a runner GitHub hosts, started by the push of the
tag, while the repository was public, and attested these measurements. The entry of that
attestation is in the public log with its certificate, which names the commit of the tag and the
run. The proofs do not show what that file and the files of that commit do. A tag whose workflow
or build attests measurements of other code is a public commit that anyone can read and build
again, and whose measurements then differ from the attested ones; a tag that is moved or deleted
afterwards leaves the two entries of the log, which name a commit that is not the one of the tag.
A workflow that reads values that are not public (a cache, a secret or a variable of the
repository, an action or an image it names by a tag, a runner image of the owner) shows that
reference in its file. The proofs rest on GitHub (the token of the run and its claims), on Fulcio
and on the log of Sigstore, as the release proof of the program does.

When a constant of the program no longer fits (the log key or the certificates of Sigstore
change, the repository moves), the proofs of a release made after that fail on a device that runs
this program, and its nodes are nodes of a later release to it: the release reaches that device
with a program that lists it.

### What the device keeps

The program store holds, per account, what the device knows of its grants and of the log. None of
it is a secret; what names services and addresses is sealed with a key derived from the master key
(HKDF-SHA256, info `pickle.secure.v1.log-cache`).

| Key | Content |
| --- | --- |
| `log.grants` | The nodes this device handed a grant to: the time of the grant, its end, the release and platform of the node, the time of the last attempt. A node is written before its grant goes out |
| `log.nodes` | What the node documents that verified said: per node id the digest of the measurement, the platform, the release, the time first seen, and the time a contradiction of its signatures was found. A node id without a document that verifies is not kept, whatever the store showed of it |
| `log.unaccepted` | The measurements no list of the program has and no release proofs showed, each with the time it was first seen, whether the key of the account went to a node of it, and the time the grant step last asked for its release proofs |
| `log.proven` | The measurements release proofs showed to this program: per measurement the release, the three PCRs, the time and the proofs, under the version of the program that verified them ("The release proofs"). Four measurements at most |
| `log.blocked` | The rounds in a row whose reads were held back: the time of the first and their number |
| `log.sample` | The 64 latest control keys the device verified |
| `log.seen`, `log.seen.{n}` | The digests of the control keys the device judged, in parts of 4,096 digests: `log.seen` names the parts, the oldest first, and `log.seen.{n}` holds one. Nine parts are kept; when one more begins, the oldest leaves with the digests it holds, so 32,768 judgements or more are remembered |
| `log.missing` | The keys of the sample that left the listing within their retention, until a listing names them again |
| `log.doubted` | The keys whose body an answer handed out with a signature that does not verify under the accepted node of the key (32 at most): the number of rounds whose answers did, the time of the first, and the node id. A key leaves when an answer carries a signature that verifies |
| `log.withheld` | The reads that were held back and that every round makes again. Of format 3: the keys of entries whose document or body was held back, and the keys the log screen asked for that no answer of the bodies reached (32 at most), with a mark on the ones the log screen asked for; the listing pages of the log screen that were held back (2 at most); and the time until which the rounds go on reading the first listing pages for the screen. Of the bucket of formats 1 and 2, as the log screen read it: the entries whose object versions were held back (16 at most), the `seq`s under which more objects lie than the screen reads, none of the ones it read the entry of the node (16 at most), the listings of chains (8 at most), and the listing of the node prefixes. And reads nobody held back: the new control keys a round listed and did not come to judge (`unjudged`, 32 at most), which the next round asks for before its listing |
| `log.recovered` | What the rounds read of the reads of the log screen that were held back, kept for the screen and sealed (the key of `log.cache`, with associated data of its own): the entries the screen asked for, as the screen shows them, each string cut to 160 characters (128 entries and 512 events at most; beyond that the ones kept first leave), the listing pages (4 at most, each the keys of 100 events with their entries, which leave with the page), and the node prefixes of the bucket of formats 1 and 2. The value holds 262,144 bytes at most before it is sealed: beyond them an entry the screen asked for or a listing page leaves, whichever was kept first |
| `log.denied` | The reads held back from the log screen that the screen notes itself and has not read since, one for each day on which a read was held back (8 at most of one kind): the later pages of format 3 (the time the read was noted, the lowest time a page held back that day began below, the events it was asked for), per node (8 at most) the listings of its chain of format 1 or 2 (the time, and the lowest `seq` a listing held back that day began after), and the days on which a page of the screen held no entry because every key it took was no entry (`filled`) |
| `log.cursor`, `log.resume` | The latest control key of the last round that covered the whole listing, and where a round that its page limit cut short goes on, with a mark when a round of that walk through the listing left keys unjudged |
| `log.legacy` | The chains of formats 1 and 2 the device follows: per node the `seq` up to which the control entries were read and the latest end of a grant. And the receiving nodes of transfers whose documents the device has still to judge |
| `log.round` | The last round: when it ran, how it ended, the published state, what the app was told, and the rounds of synchronizations in a row that had more to read than they read |
| `log.cache` | The first page of the log screen, the time the screen last read the listings of that page itself, the summary tally, and what the screen knows of the end of each chain of formats 1 and 2 (the last `seq` the device knows its node wrote, and the latest time a key of the chain names, kept only for a chain whose end the screen had among the keys it knew), sealed |
| `vault.made` | The names of the vault items `store_secret` made and that hold no value yet (8 at most) |
| `vault.named` | The mark that the device published `state.named_secrets` true for the account |
| `outcomes` | The outcomes of the procedures that are not reported yet |
| `ledger`, `ledger_shared`, `log.migrated`, `sealing_checked` | The device copy of the node ledger, the node ids its last exchange with the backend covered, the mark that the ledger was carried over, and the mark that the sealing check is done |

The settings of the delegation (the time of the last revocation and resumption, the lifetime of a
grant) are shared by the devices of an account in a synchronized key store item, the node ledger of
the programs before version 43. The program judges nothing by the nodes of that ledger. On its
first run on an installation it carries the ledger over once: a node with a grant time becomes a
grant of the device, and the verified point of every node the ledger explains becomes the point
from which the chain of that node is read (`log.legacy`); the marks of the earlier program are not
carried over. A device of the account that still runs an earlier program counts a chain of a node
no ledger explains as a delegation the app did not make, so the program writes every node of a
release before v2.4.0 that it hands a grant to into the ledger, in the form of those programs,
and exchanges the sealed ledger with the backend by their rule (`GET` and `PUT
/api/secure/ledger`: the value is read and merged before it is uploaded, because an upload
replaces it). A node of a release from v2.4.0 on is not written to the ledger.

### The round

A round is one reading and judging of the log of the account (7.4). A synchronization runs a round
when the last completed round is 24 hours old, when this program has completed none on the
installation, when the last round did not complete, and while the device keeps a read that was
held back (in the last two cases not sooner than 60 s after the round before; the first listing
pages the rounds go on reading for the screen make no round due by themselves). A round of a
synchronization that ends with more to read than a round reads is followed at once by the next
round, eight in a row at most. The log screen runs a round with its first page, and starts one
when the reads it notes as held back from it begin or cease to mark the log. One round runs at a
time: a round whose time passed judges and writes what it kept before the next round begins.

A round ends its reading when the app goes to the background (the event `background`). It calls
the backend and the store no more, and it judges what it read and writes what it kept within that
event, as a round whose time passed while the runtime did not run: nothing is counted, and the
next synchronization runs a round however soon it comes. A read that ends this way, or with the
time of the round, judges what was answered before the end. So a device whose stays in the app
are shorter than a round reads the log on with every stay, and no backend that answers slowly
keeps a round from its judgement.

Before step 1, a round asks for the keys an earlier read left it (`log.withheld`): the keys whose
read was held back, and the new control keys a round listed and did not come to judge (32 at
most, the keys of the nodes of an accepted measurement first, the earliest entry first: an object
under the id of such a node is the entry its key names or its read ends in a count, so nothing
uncounted takes those places from an entry). Their documents and bodies are asked for as in steps
3 and 4, with requests of their own (two document requests and two body requests at most), which
take none from the requests of the listing pages.

1. The listing addresses from the backend (`POST /api/secure/log/read`). The program calls an
   address only when its host is the host of the bucket the program computed from its own
   `user_id` (7.6), its path is `/`, its query has `versions`, the prefix `a3/{user_id}/c/` or
   `a3/{user_id}/u/` of its own account, `max-keys` 1000, the markers it asked for and no others,
   `encoding-type` `url` when given, and no other key besides the keys of the signature
   (`X-Amz-...`). An address of the store that gives a query key twice, or that carries a
   fragment, is not called: the program judges an address by the one value it reads for a key, and
   Amazon S3 answers a key that is given twice by its first value.
2. The listing of the control prefix, from Amazon S3. A round reads the listing from its start: an
   entry a node wrote late lies below the entries the device saw before, so the round judges every
   key it has not judged wherever it lies. A round reads four pages at most; a longer listing is
   read on by the next round. A key older than 365 days is left out.
3. The node documents of the nodes the device has no judgement of (`POST
   /api/secure/log/documents`, verified by 7.7). The answer hands out, per node, the object the
   node wrote to the store (`origin` `log_store`) or the attestation document the backend kept of
   the node (`origin` `node_registry`: it carries the nonce of a request of the backend, and the
   program does not compare its nonce), and for every node it was asked for the address of the
   listing of the versions under the key of its node document (`listings`). For a node the answer
   hands out no document that verifies for, whatever the answer says of it (`missing`, `unread`,
   a document that fails), the program reads from the store whether a node document of that node
   id exists. It calls the address of that listing only when its host is the host of the bucket
   the program computed from the node id (7.6), its path is `/`, its query has `versions`, the
   prefix `n3/{node}`, `max-keys` 1000, no marker, `encoding-type` `url` when given, and no other
   key besides the keys of the signature. When the listing ends with its first page and names no
   version of the key `n3/{node}` (a delete marker is no version), the store holds no node
   document of that node id.
4. The bodies of the keys it has not judged whose nodes it has a judgement of (`POST
   /api/secure/log/bodies`): with the request of step 3 for the nodes it had a judgement of
   before, and after it for the nodes step 3 judged (while a document is asked for, the first
   leave one request to the second, so the entries of a node this read judges are read with
   it). No body is asked for under a key whose node has no judgement. A request names the keys
   an earlier read found held back first, and then its
   other keys, each group with the earliest entry first. The backend answers the keys in the order
   of the request and may end early: a key that is neither among the entries of the answer nor
   among its missing keys (the answer reports it as `unread`, or does not name it) is asked for
   again by the next round.
   Each object is verified by 7.4: the SHA-256 of the body against the `body_hash` of the key, the
   signature under the node id of the key, and the fields of the body against the key and the
   account. The events of an entry of the device's own `key_id` are opened. A body that is the
   one its key names, handed out with a signature that does not verify under the accepted node
   of the key, leaves the key unjudged: the signature reaches the device through the backend,
   so one answer proves nothing of the node. The key is read again by every round, with the
   keys held back, and the round is not complete (A2 below).
5. The reads that were held back before (`log.withheld`): the keys are read before step 1 (above),
   and each listing page of the log screen is asked for again in the request the screen sends for
   it, with the entries of the page the screen would show there.
6. The chains of formats 1 and 2 the device follows, and the reads of that bucket that the log
   screen made and that were held back (the last part of this section).
7. The judgement, the published state, and the report (`POST /api/secure/log/verified`). What the
   round read for the log screen is kept for the screen before the reads it answers leave
   `log.withheld`.

A backend that answers the route of the listing addresses with the status 404 and no code of its
own, or with the code `log_store_disabled`, states that its environment has no store of format 3.
The round then reads the chains of formats 1 and 2 only. When the device handed a grant to a node
of a release that writes format 3, or read that store before, the same answer is a read held
back, and so is that answer from any other route of the reads for keys a listing of the store
named.

What the backend hands out and what the store shows. The bodies and the node documents reach the
device through the backend. A body cannot be replaced (the key of the listing carries its hash)
and a node document proves itself, so the backend may hand both on. Both can be withheld, and the
signature of an object reaches the device the same way. So a key of the listing is never set aside
for what the backend hands out or does not hand out, and that a node has no node document is
nothing the backend can state: the program reads it from the store (step 3). A node writes its
node document before it takes a user key and writes no entry without it (7.7), and no object
version of the store can be deleted (7.6). So an object the store listed under a node id, while
the store held no version of the node document of that id, is no entry of a node: the operator
domain holds the credentials of the buckets and can write objects under any key. Such an object is
left out. It is not shown, no body is asked for under its key, it marks nothing, and the report of
the round counts its node id.

That judgement holds for the keys the listings before it named, and for no key a later listing
names: a node that writes its node document afterwards writes entries afterwards. The program
makes it again with every read that finds a key of a node without a document that verifies, and
keeps no judgement of such a node id.

A key whose node has no document that verifies, while the store shows a version under the key of
its node document or more than one page there, is a read held back (A3 below): a node document
outlives the entries of its node (7.7), so either the document is withheld or someone wrote an
object under the key of a node document. A key whose body the backend does not hand out is a read
held back as well. Besides the objects of a node id without a node document, only an object whose
body is the one its key names and whose fields are not those of the key, under a signature of the
node of the key, is no entry.

A listing longer than the four pages of a round is walked over several rounds, and a later round
of the walk does not list the pages of an earlier one again. A walk in which a round listed more
keys than it judged or left to the next round does not end as a reading that read everything: the
round that ends it has more to read than it read, and the next round walks again from the start of
the listing. The device remembers the judgements of 32,768 control keys or more, as many as the 32
listing pages name that the rounds of one synchronization read, so an account that holds that many
control objects is read to its end and verifies.

A read that was held back is made again by every round until it is not (step 5). The log screen
reads the use entries and the later pages of the two listings, which a round of a synchronization
does not read. So a round that reads the control entries alone does not end a count of rounds held
back while a read the screen made stays held back. A key of the log screen that an answer of the
bodies did not reach goes to the rounds as well, without a count: the round asks for it as the
first key of a request, where an answer that does not name it holds it back.

What a round reads of a read of the log screen is kept for the screen (`log.recovered`), so that an
answer the backend gives a round is an answer the user sees, whichever requests the backend
chooses to answer:

- An entry. What the round reads under a key the screen asked for (the entry as the screen shows
  it, or the finding that the object is no entry) is kept, and the screen takes it from there
  before it asks for the key. A key that a round alone asked for is not kept.
- The first listing pages. A round that reads them again keeps the page the screen would show
  (the keys of 100 events, and their entries, read as the screen reads them). The screen asks for
  its listings first, and makes its first page from the kept one when they are held back. From
  the read that was held back, every round of a synchronization reads those pages for the screen,
  for 30 days or until the screen reads them itself, so the kept page is as new as the last round.
- A later listing page. A round that reads it again keeps the page the same way, and a read of
  the screen that is held back is made from a kept page that begins at or above the time asked
  for and reaches below it.

Two kinds of listings cannot be kept in a form that answers every later read of the screen: a
later page is asked for by the time it begins below, which moves with every entry that arrives
above it, and the keys of a chain of formats 1 and 2 are kept for a runtime only. What the
operator domain holds back of these is noted by the reads of the screen themselves
(`log.denied`), whatever the rounds read in between. The device keeps the reads held back that
the screen has not read since, one for each day on which a read was held back: the screen and its
user repeat a read within seconds, while the device spreads its rounds over the synchronizations,
so a read held back within 20 hours of the last one noted is taken into that one.

- A read of a later page that is held back, and that no kept page answers, is noted with the time
  the page begins below (the lowest such time of its day). It ends when the listings the screen
  holds name the keys of that page. The screen reads those listings on from the start of the two
  listings, each page from the last key of the page before it, so a note ends only when the
  screen was given the listings from the first page down to that page. While a page is noted,
  every opening of the screen reads its listings on down to it, 16 requests at most for one
  opening, with the requests a user who scrolls that far has the screen send; within a runtime
  the next opening reads on from where the one before it stopped. So a page that was held back
  once ends with the next opening of the screen the backend answers, without a scroll, and a
  request of that reading that is held back is noted for its day. A page that is held back and
  then given ends what was noted for it and nothing noted for a page below it.
- A listing of a chain that is held back is noted with the `seq` it began after (the lowest of
  its day). It ends when the screen itself read the chain from its end down to that `seq`: at an
  opening it read the listing of the end of the chain to its end, it knows every key from the
  `seq` after that one on, and the lowest `seq` it knows holds an entry of the node (or the chain
  is read down to its first `seq`). A chain with listings noted is read that far with every
  opening of the screen. A listing of the end of a chain that goes on over four pages at one
  opening without an end, and a chain the screen cannot bring down to an entry of its node, are
  noted the same way ("Formats 1 and 2").
- A page of the screen on which every key taken was no entry (an object under a node id the store
  holds no node document of), with keys left below, shows the user no entry. It is noted for its
  day. No read ends such a note: while such objects keep the pages, every opening notes it again.

The reads noted of one kind (the later pages, the listings of one chain, the pages that held no
entry) mark the log when they are three or more and the first of them is three days old. A read
noted that is not among reads that mark the log ends 30 days after it was noted: the reads that
mark the log are reads held back on three days within 30 days, none of which the screen has read
since. Reads that mark the log stay until the screen reads what was held back, or until the last
of them is 30 days old (the screen made no such read for that long). A request that was not
answered is noted when the backend answered another request of the runtime within 60 s.

A round that leaves reads undone because there was more to read than one round reads (the control
listing goes on beyond its four pages, more nodes are without a judgement than its document
requests name, more bodies are to be read than its body requests name, an answer of the bodies
ends before its last key, the chains of formats 1 and 2 hold more control entries than it reads,
the listing of such a chain goes on over pages that hold many object versions for each `seq`, or
its time of 60 s passes before it has read everything) is pending, and the next round reads on
from where it stopped: a round whose time passes is judged on what it read and keeps what it
judged. A synchronization has the next round follow such a round at once, eight rounds in a row
at most, and does not wait for them: a device with much to read (a new device, a device that was
off for long) reads it during its stays in the app, and not one round a day. The eight rounds of
one synchronization read 32 listing pages, the documents of 1,024 nodes and 6,400 bodies, which
an account in normal use does not hold within the retention of the store.

The rounds of synchronizations that end that way in a row are counted, and a round that reads
everything ends the row. Beyond eight such rounds in a row, the first round of a synchronization
that ends that way again is a round whose reads are held back: someone writes objects under the
prefix of the account faster than the device reads them, or the answers of the backend never
reach their end. It counts once for its synchronization: the rounds that follow it read on, and
neither add to the count of the rounds held back nor end it. So such reads mark the log when three
or more synchronizations were counted that way and three days have passed since the first of
them. Time that passed while the runtime did not run is not time the round had (the app
went to the background during the round, or the time of the round passed more than 5 s later than
a running runtime lets it): a round that ends that way is pending, is not counted in that row,
and is followed by none.

The result of a round is `verified`, `pending` or `attention`. It is `attention` when one of four
conditions holds, and each holds only in a situation that is a problem:

| | Condition | When it holds |
| --- | --- | --- |
| A1 | The key of the account went to a node of a release the program does not accept | A node of an accepted measurement wrote `grant_transferred_out` under the device's own `key_id` naming a measurement no list of the program has, or a node whose document states such a measurement wrote an entry under that `key_id`; 24 hours have passed since the device first saw that measurement; and the runtime knows that no later program than this one is served ("A runtime behind the served program"). Until all of that holds the measurement waits and the round is pending: a program that lists a new release is served before a node of that release takes a grant, and a device may run the program before it for longer than a day. The program that lists the release clears the condition. Once it holds, every round that ends states it, however its reads ended, and for a measurement the device kept the events of the app state it without a read when the runtime knows by then that no later program is served (a new runtime that learns it from the backend has read nothing at its event `session_ready`). A receiving node whose document the device has not seen is no measurement: it waits for its document, a round whose request for that document is answered without one that verifies is a round held back (A3), and no time marks the log for it. The receiving node of a transfer a round judged is kept whatever kept its document from that round |
| A2 | The signatures of a node that passed attestation contradict each other | Under a key of a node of an accepted measurement: an entry of the device's own `key_id` that the node signed and that does not open; two different bodies of one `seq` that both verify; or the body the key names for which the answers of two rounds carried no signature that verifies. The first two are marks no answer can make up, and stay. The third holds until an answer carries a signature that verifies for that key: the key is read again by every round, and a round it is held back from is a round held back (A3) |
| A3 | The operator domain has held the reads back for three days | Three rounds in a row or more were held back and the first of them is three days old; or the log screen notes three or more reads of one kind as held back from it (the later pages, the listings of one chain of formats 1 and 2, the pages that held no entry), on three days within 30 days, that it has not read since, and the first of them is three days old. A round is held back when a route of the reads answers with an error status, or does not answer within its limit while the backend answered another request of the runtime within 60 s; when an address is not the one of the request; when the store answers an address not older than 240 s with a status other than 200, 429 and 5xx; when the backend hands out no body, or another body, for a key of the listing whose node the device has a judgement of; when an answer of the bodies names none of the keys of a request, or names a key and not one before it in the request; when the backend hands out no verifying document for the node of a key of the listing and the store does not show that it holds none (it holds a version under the key of that node document or more than a page there, the answer gives no address of that listing or another address, or the store refuses the address); when the backend answers the request for the document of the receiving node of a transfer without a document that verifies (a transfer an entry of format 3 names, and a transfer a node of a release before v2.4.0 made on or after 2026-11-23T00:00:00Z: "Formats 1 and 2"); when a key whose signature an answer did not carry is held back from a round (A2); when a measurement past the 24 hours of A1 cannot be judged because the checks of the app for a new program fail on the side of the server ("A runtime behind the served program"); when more objects lie under a `seq` of a chain of formats 1 and 2 than are read there and none of the ones read is the entry of the node, or a listing page of such a chain goes on and shows the node writing nowhere ("Formats 1 and 2"); when a read the log screen made of the bucket of formats 1 and 2 is still held back; and, beyond eight rounds in a row that left reads undone because there was more to read than a round reads, when the first round of a synchronization ends that way again. A round that made every read, the reads held back before included, clears the count of the rounds. A read the screen makes itself ends the reads it noted that this read covers, and the reads it noted end together when the last of them is 30 days old |
| A4 | An entry the device saw left the listing within its retention | A key of the sample that is younger than 364 days and lies in the range the listing covered is in neither of two readings of the listing. The condition ends for a key when a listing a round reads names it again |

A device without a network, a store that answers 5xx or 429, and an address that aged while the
app was suspended leave the round pending and count nothing. So does a request to the backend
that failed in a runtime that did not run for a part of its wait: the app went to the background
while the request was open (the events `background` and `foreground` tell the program), or the
request ended more than 5 s after its own limit, which no running runtime lets a wait do. A
runtime does not run while its app is suspended, and what it had sent fails when it runs again;
such a failure says nothing of the backend, in a round and in a read of the log screen alike. A
request the backend answers with an error status counts whenever it is answered. A round that
runs when the app goes to the background does not wait for that failure: it ends its reading with
the event.

These mark nothing: an object under a node id the store holds no node document of (it is no entry
of a node), a `seq` of a node that no key carries (an entry the store did not confirm: its act did
not take place), a node whose entries end (with or without its orderly shutdown), and an entry of
another `key_id` (the screen shows it as part of a delegation of another key).

The program publishes the result as `state.log`:

| Key | Value |
| --- | --- |
| `status` | `verified`, `pending`, `attention` |
| `verified_ms` | The time of the last round that ended `verified` or `attention` |
| `newer_release_nodes` | The measurements that wait for A1: within its 24 hours, or past them while the runtime does not know that no later program is served |
| `unknown_nodes` | The measurements for which A1 holds |
| `unverified_nodes` | The nodes for which A2 holds |
| `missing` | The keys for which A4 holds |
| `expired` | 0 |
| `store` | `verified`, `unreachable` (the device or the store failed), `blocked` (a read was held back, or the reads the log screen notes as held back from it mark the log), `truncated` (the control listing goes on beyond the pages of the round, and no more than eight rounds in a row ended with more to read; beyond eight, the value is `blocked`) |
| `store_failure` | The first failed read of the round, as `{request}:{status or code}` |
| `store_failing_ms` | The time of the first of the rounds held back in a row or, when there is none, of the first of the reads the log screen notes that mark the log |
| `program_version` | The version of the program |

In a build of the app that has the bridge primitive `securityStatus`, the program tells the app
the result of every round: `ok` for `verified`; `attention` with one reason per condition that
holds (`unlisted_release`, `conflicting_signatures`, `verification_blocked`, `missing_entries`);
and `pending`, unless the value it told last is `attention`. The app binary shows that value
outside the user interface definitions the backend serves.

The report of a round carries its status and store state, the numbers of nodes, of keys checked,
of bodies read, of control keys and of node ids without a verifying document (the ones the store
holds no node document of, and the ones whose read was held back), the names of the releases of
A1, the node ids the key went to, the number of rounds held back in a row, the first failed read,
the time the round took, the version of the program and, for a round of the log screen, the times
of the steps of the screen. The first failed read names the request and what it answered: among
others `documents:missing` and `documents:rejected` (no document of a node was handed out, or one
that does not verify, and the store shows an object under its key), `documents:url` (no address,
or another address, for the listing of a node document), `document:{status}` (the store answered
that listing with that status), `bodies:missing`, `bodies:hash`, `bodies:skipped`,
`receiver:missing` and `receiver:rejected` (the receiving node of a transfer of formats 1 and 2),
`listings:{status}` and `objects:{status}` (a read of the bucket of formats 1 and 2),
`chain:keys` (more objects lie under a `seq` of a chain of formats 1 and 2 than are read there,
none of them the entry of the node, or a listing page of the chain shows the node writing
nowhere), `round:time` (the time of the round passed before it had read everything),
`round:unfinished` (a round counted as held back because the rounds keep ending with more to read
than a round reads), `screen:held` (the reads the log screen notes as held back from it mark the
log), `delivery:{status}` and `delivery:silent` (the checks of the app for a new program failed
on the side of the server while a measurement waited to be judged), `program:stale` (the report
of a stale runtime), and `{request}:suspended` and `round:suspended` (a request, or the round,
ended in a runtime that did not run for a part of it, or the round ended its reading because the
app went to the background).

### A runtime behind the served program

A node of a release this program does not list may hold the key of the account for no other reason
than that this program is no longer the one served: a later program lists that release, and the
runtime has not loaded it. A device runs an earlier program for minutes or for days. So a runtime
judges nothing while it knows that a later program is served, and A1 holds only for a runtime that
knows that none is.

What the backend serves: the answer of `GET /api/secure/account` may carry the integer
`served_program_version`, the version of the program the backend serves the account. A runtime
reads it from every answer of that route and keeps it in memory alone; an answer without the
member, or with a value that is no integer, leaves it unknown.

A stale runtime is one that knows that a version above its own is served. While it is stale it

- starts no round, for a synchronization or for the log screen, and a round that learned it during
  its reading judges nothing and writes nothing of what it read;
- states nothing of the measurements the device kept (A1);
- writes none of the values the rounds judge by (`log.unaccepted`, `log.blocked`, `log.sample`,
  `log.seen`, `log.missing`, `log.doubted`, `log.withheld`, `log.recovered`, `log.denied`,
  `log.nodes`, `log.legacy`, `log.cursor`, `log.resume`, `log.round`), the reads of the log
  screen included: what a program that is behind reads of the nodes and formats of a later
  release is nothing the next program is to judge by;
- publishes no judgement, tells the app none and reports none. The state the device kept stays
  published as it is.

It publishes `runtime.program_stale` and reports once that it is stale: a report of a round (`POST
/api/secure/log/verified`) with the status `pending`, the first failed read `program:stale` and
its own version. It goes on handing its grants to the nodes of the releases it lists (a node of a
later release it meets is kept for the time of the runtime only), serving the procedures the user
starts, and reading the log for the screen: the first page is then read as a later page is,
without a round, with the summary the device kept marked as not complete.

A1 holds for a measurement no list has only when, besides the 24 hours since the device first saw
it, the runtime read the served version, that version is not above its own, and the reading is
not earlier than the time the device first saw the measurement and not older than one hour. A
round that holds such a measurement and no reading that young asks for the account once before it
judges. A backend that names no served version leaves such a measurement waiting: it marks
nothing, and no round counts as held back for it.

A build with the bridge primitive `programDelivery` knows the delivery of the program itself, and
judges by that. The primitive returns `{verified, settled_ms, failed_ms, failed_status}`: the
highest version among the programs the installation verified (the one that runs, the one the app
ships with, one that waits to be loaded), the time the last check of the app for a new program
ended with an answer the app processed, and the time and the HTTP status (0: no response) of the
last check that ended without one. In such a build

- the runtime is stale when the installation verified a later program. The word of the backend
  alone makes it stale only for a time: from the first of the answers in a row that named a later
  version until the check of the app that follows has ended, that is, a check ended with an
  answer the app processed at or after that time (or within 60 s before it), or a check failed
  after it for a reason on the side of the server;
- A1 holds when the installation verified no later program and the last check that ended with an
  answer the app processed is not earlier than the time the device first saw the measurement and
  not older than one hour, besides the 24 hours;
- a measurement past its 24 hours that cannot be judged because no such check is at hand, while
  the last check failed for a reason on the side of the server (a status of 400 or above, or no
  response while the backend answered another request of the runtime within 60 s of it), makes
  the round one held back (A3, first failed read `delivery:{status}` or `delivery:silent`). A
  check that failed with the network of the device leaves the round pending.

### The log screen

`read_log` returns the first page of the screen and the summary of the last seven days. The device
keeps the first page it showed last (50 events) and the summary tally, sealed. A call starts a
read of the store on the line of the screen (or joins the one in flight) and waits for it for 3 s;
when the read has not ended by then, or failed, the call answers from what the device kept, with
`cached` true and the status `pending`, and the read goes on. With the argument `kept` true the
call answers from what the device kept at once.

The read of the first page is a round started by the screen: it reads the first page of the
control prefix and of the use prefix together, takes the keys later than the ones it kept, and
asks for their documents and bodies with those of the round. An entry is shown as verified when
its object verifies (7.4) under a node the device accepts, and it is opened when its `key_id` is
the device's own. An object under a node id the store holds no node document of is left out, and
not counted into the summary. An entry whose node has no document that verifies while the store
does not show that it holds none, or whose object does not verify, is shown as not verified. An
entry whose object was not read is shown as not verified in that answer and is not kept: the next
read asks for it again, and its key goes to the rounds, which ask for it first. An entry the
rounds read for the screen (`log.recovered`) is taken from there and not asked for. When the
listings of the first page are held back, the page is made from the listing page the rounds kept
since the screen last read those listings itself, and otherwise from what the device kept of the
first page. The summary counts the use entries of the last seven days, each once per device, the
1,000 latest at most (a count that is not complete is marked as such).

A page takes its keys from the listings by the number of events the keys name, before it reads
them. A key that turns out to be no entry (an object under a node id the store holds no node
document of) is passed: it takes no entry from the screen. A page covers the listings down to the
time of the last key it took, and the page after it begins there, whatever the time of the last
entry it shows; the entries of formats 1 and 2 of a page lie above that time. A page is read on
below the keys it passed, twice at most, as a later page is read. A page that passed every key it
took shows no entry and says that there is more; with keys left below, that is noted for its day
("The round").

`read_log_page` returns one later page (50 events before `before_ms`). A listing page of the store
names up to 1,000 keys, so the keys of a later page are taken from the listings the screen holds
in the runtime as far as they reach (they hold a whole page above the place where one of them
goes on, or neither goes on). When they do not reach the page they are read on where they
stopped, each request with the markers the store gave with the page before it (four requests at
most for one page), and a screen that holds no listings from the start of the two listings reads
their first pages before that. Only where those reads do not reach (the screen holds 20,000 keys,
or the page lies further below) are the two listings read from the marker of the time of the
page. The bodies of the page are asked for in as many requests as its keys fill, and one more for
the keys of the nodes whose documents the read judges, so an entry of a node the runtime meets
for the first time is read with its page. The entries of formats 1 and 2 are merged in by their
times. A later
page changes no kept judgement. A read it finds held back (its listings, the document or the body
of one of its keys, a read of the bucket of formats 1 and 2) is kept for the rounds, which make it
again and count it. When its listings are held back, the page is made from a listing page the
rounds kept that covers its time; when they kept none, the read is noted among the later pages
held back from the screen ("The round"). `read_security_record` returns the same entries as
`{items: [{id, time_ms, kind, subject, detail, count}], next_before_ms}` for the security record
screen the app binary draws. An entry whose body an answer handed out with a signature that does
not verify is shown as not verified in that answer and is not kept with the first page: the next
read asks for it again.

### The reports of the program

The program counts how its procedures end: per name the calls, the failures, the time a call
waited for its line and the time it took (without the time the device waited for the user), in
six classes of duration. A call that failed or took 10 s or longer is also kept one by one with
its failure code, 32 at most. A call that has not ended is kept as open, and a runtime counts the
calls it finds open at its start as interrupted, each with the time the app had gone to the
background while it was open. The failure `cancelled` (the runtime went down, or the user closed
the web session or the sheet the procedure waited in) is not counted as a failure. The names are
the names of the procedures, `event_sync` for a synchronization an event started and `log_screen`
for a read of the first page of the screen. The program sends the counts with `POST
/api/secure/procedures/outcomes` 5 s after a call failed or was slow, and at the end of a
synchronization when the last report is 24 hours old; what the backend accepted leaves the device.
The report names procedures, failure codes and times, and nothing of the arguments or the results
of a call.

After a synchronization a push started, the program sends `POST /api/secure/sync/report`: the
reason of the push, the key state, the state of the grants, the numbers of nodes that took a grant
and that failed the verification, and the time it took. Nothing waits for the answer of a report.

### The vault secrets

A vault secret is a record of kind `vault_secret` (section 6): a value with its name, the hosts it
may go to and the places it may be put, all inside the plaintext the device seals.

| Procedure | What it does | The device owner authentication |
| --- | --- | --- |
| `store_secret` | Seals the value the user entered into a record and uploads it. The name, the hosts and the places of the item come from the backend and are checked against the form of section 6 before they enter the plaintext; an item of another form fails the call. The plaintext is padded to the shortest of the lengths 256, 512, 1,024, 2,048, 4,096, 8,192 and 12,272 bytes it fits. With a name (an item that exists), the arguments `sites` and `slots`, when given, are the hosts and the places the screen showed the user: when the item names other ones (compared as sets), nothing is sealed and the call fails with `binding_changed`. Without a name (an item the user adds), the item is made from the arguments `label`, `sites` and `slots`, and only once the value is one an item can hold (below) | None |
| `reveal_secret` | Opens the record on the device and shows the value to the user. It opens a record of kind `vault_secret` only, and a plaintext that names another name than the one asked for is `record_invalid` | Before the query |
| `update_secret` | Changes the hosts and the places of an item: the record is opened and sealed again under the same id with the new ones. Without the argument `slots` (absent or blank) the places stay what the item has. In a build with the bridge primitive `confirmDestinations` the user confirms the new hosts and places first (below) | After the confirmation, before the query whose record is opened |
| `delete_secret` | Removes an item | Before the request |
| `reveal_login_password` | Shows a password a node made for a login. It opens a record of kind `vault_password` only, and a plaintext whose `source` is not `operator` is `record_invalid`: a password the user typed is not shown | Before the query |

In a build of the app that has the protected sheets (`promptSecret` and `presentSecret`),
`store_secret` takes no value as an argument: it asks for the value in the input sheet, with one
line per host that says where the value can go, made from the hosts and places that are sealed
into the record. `reveal_secret` and `reveal_login_password` hand the value to the display sheet
and return no value. In a build without the sheets the value is the argument of `store_secret` and
part of the result of the two procedures. The program publishes which of the two a build is
(`runtime.protected_sheets`). In no build is the value part of a request, of a published value or
of the program store.

`store_secret` without a name makes no item it cannot fill. It checks the form of the label (80
characters at most, no control character), of the hosts and of the places, asks for the value (in
a build with the protected sheets, in the input sheet, with the lines made from the hosts and
places given), and checks the value (not empty, no U+0000, a plaintext within 12,272 bytes
whatever name the item gets) before `POST /api/secure/vault/secret`. The item the backend made
must name the hosts and the places that were shown (`binding_changed` otherwise). When a step
after that request fails, the program sends `DELETE /api/secure/vault/secret/{name}` once, without
a device owner authentication and whatever that request answers, and the call ends with the
failure of that step. The name of an item the call made is kept on the device (`vault.made`)
until the item holds its value or is removed: a runtime that begins removes the items kept there
that still hold no value (a runtime that ended between the making of an item and its filling
left one), and leaves an item that holds a value. An item whose making request was sent and
whose answer never reached the program has no name the device knows, and stays. A name that is
white space alone is `invalid_input`, and not the absence of a name.

In a build with the bridge primitive `confirmDestinations({title, destinations})`, `update_secret`
shows the user the new hosts and places on a surface the app binary draws, with the lines
`store_secret` gives the input sheet, before the device owner authentication and before any
request that changes the item. The primitive resolves to `{confirmed: true}`, or to null when the
user closes it: the call then ends with `cancelled`, which is no failure of the procedure ("The
reports of the program"), and nothing is asked of the device owner or of the backend. The time the
user takes is not counted into the time of the procedure. When the places stay what the item has,
the item is read before the confirmation, so that the lines name them, and an item whose places
are other ones when it is read again after the confirmation is not written (`binding_changed`).
A build without the primitive changes the item as before. In every build the form of the hosts is
checked before anything is asked of the user, of the device owner or of the backend, and a title
the program hands to a surface of the app is cut between characters.

A list argument of a definition action is an array, the JSON of one, the string `any`, or one
string of names: the hosts of `sites` separated by commas or white space, the places of `slots`
by white space alone (the name of a `json:` place may hold a comma).

### Formats 1 and 2

The entries of the nodes of the releases before v2.4.0 stay in the bucket their bindings name
until their retention ends. The program reads them for two things.

The log screen shows them: below the entries of format 3 and merged with them by time, from the
chains the device follows and the node prefixes the listing of the account prefix names. An entry
is shown as verified when the signature of the node id of its prefix verifies over its body, its
key and body agree (for format 2: `seq`, `time_ms`, `kind`, `count`, `key_id` and the hash of the
body), and it opens with the key of the account.

Under one `seq` the screen reads the latest version of eight objects at most, as a round does for
a control entry, and the first that verifies is the entry of that `seq`, shown at its own time.
When none verifies, the `seq` is one line that is not verified, placed at the latest time the
keys under the `seq` name and not later than the `seq` above it: a key someone wrote there with
an earlier time moves the line no further down the list. A `seq` whose keys name several times is
read before it is placed. When more objects lie under a `seq` than the screen reads and none of
the ones it read is the entry of the node, the `seq` goes to the rounds (`log.withheld`): every
round lists the objects under it again and reads the latest eight, and while none of them is the
entry of the node and more lie under the `seq`, the round is one held back (`chain:keys`). An
entry the screen opened is opened again when a listing names other object versions under its
`seq`.

The screen takes the keys of a chain from its own listings, and a range of `seq`s as known only
from a listing that was read as far as the range reaches. The listing of the end of a chain is
read on page after page to its end, and a range below the keys the screen knows (1,000 `seq`s)
enters them when its listing named a `seq` at or above them or ended; a range without keys does
not end the chain (the last `seq` below it is searched for, and the range begins there). With
every opening of the screen the end of every chain that may still be written is listed again,
the first pages of all such chains with one request for their addresses, from the last `seq` the
device knows the node wrote (the `seq` up to which the rounds read the chain, or a `seq` whose
entry the screen opened): a node writes its next entry under the `seq` after its last one, so an
entry it just wrote is on the screen whatever lies above the end of the chain. The entries of a
chain are taken by their times, the latest first, whatever their `seq`s. What lies below the keys
the screen knows is no later than the entry under the lowest `seq` it knows when the node wrote
that entry: the screen reads that entry with the page, and when it is no entry of the node the
chain is read on below at once (three such walks in one call at most). A listing of the end of a
chain that goes on over four pages at one opening without an end, and a chain that still stands
on a `seq` without an entry of its node when a call ends, are noted as listings held back from
the screen ("The round"). The time the device keeps for the end of a chain that ended, by which a
later runtime leaves the chain unlisted until a page reaches it, is kept only for a chain whose
end the screen had among the keys it knew.

A read of that bucket that the log screen makes and that is held back goes to the rounds
(`log.withheld`), which make it again, and a round that finds it still held back is a round held
back: the listing of the node prefixes, the listing of a chain (from the `seq` the screen asked
for; a listing that only looks for the end of a chain is not made again), and the object versions
of an entry. What the round reads is for the screen. The node prefixes and the entries it opens
are kept (`log.recovered`): the screen asks for none of those entries, and the kept node prefixes
stand in when the listing is held back from the screen again. A listing of a chain a round makes
again says only whether the read is still held back: the screen takes the keys of a chain from
its own listings alone, so the listings of a chain that are held back from the screen are noted
by its own reads ("The round"). A backend that
states it has no such store holds a read back when the store is known to hold the chain: the
store named its prefix when the screen last listed the node prefixes, or the device follows the
chain and its entries are within the retention of the store. The object versions of an entry
were named by a listing of the store, so that answer holds them back in every case.

A round follows the delegation: for every node of such a release that the device handed a grant
to, it lists the chain from the `seq` up to which it read, reads the control entries, and follows
`grant_transferred_out` of the device's own `key_id`. The operator domain can write objects into
that bucket as well, so under one `seq` the round reads the object versions whose keys name a
control entry, the latest first, until one is the entry of the node (eight at most: a node writes
one object under a `seq`, and one more version when it repeats a write). When none of the eight
is and more are left, the read is held back (`chain:keys`) and the chain is not read past that
`seq`. The last `seq` of a listing page that goes on is read with the page after it.

The `seq` up to which a round read a chain moves on only to a `seq` under which the node is seen
to have written: an object the node signed for that `seq`. The round sees that in the control
entries it reads and in the last two `seq`s of a listing page, whose objects it reads for that
alone when their keys name no control entry (eight versions each at most). An object someone else
wrote under a `seq` the node has not reached, or far beyond the end of the chain, moves nothing:
the entry the node writes there later is read. A listing page that goes on and shows the node
writing nowhere cannot be read on, and the read is held back (`chain:keys`); a page a node wrote
always shows it in its last `seq`s.

A chain an account used heavily is long, and the rounds read on through it, four listing pages a
round, without a count; a listing that goes on over pages that hold more than five object
versions for each `seq` they name, on average, is one of the reads that leave a round with more
to read than it reads ("The round"). The event of a transfer names the receiving node and
no measurement, so the program asks for the document of the receiving node (`POST
/api/secure/log/documents`: the node document of a node of a release from v2.4.0 on, the
attestation document the backend kept of a node of an earlier release). A receiving node whose
document states a measurement no list has counts for A1; a receiving node of a release that
writes format 3 has its entries in the listing of format 3; a receiving node of an accepted
release before that has its chain followed in turn.

A receiving node the backend hands out no document that verifies for is judged by the time of the
event. From 2026-11-23T00:00:00Z on the backend keeps the attestation document of every node that
takes a transfer, for longer than the store keeps the entry of the transfer. For an event of that
time or later, and not older than 365 days, the node waits: every round asks for its document
again, a round whose request for it is answered without a document that verifies is a round held
back (A3), no time alone marks the log for it, and its chain is not followed before a document
verifies. The receiving node of a transfer an entry of format 3 names waits the same way,
whatever the time of the event. The
store is not asked whether it holds a node document of such a node: a node of a release before
v2.4.0 wrote none. For an event before that time, the receiving node is followed as a node of the
release of the giving node. The route of the node documents hands out what the backend kept of a
node whether or not the backend reads the store of format 3, so a backend that answers that it
has no such route, or no such store, holds the document back in every environment.

A chain is read for the last time one day after the grant of its node ended. The program reads no
head, verifies no chain equation, and judges neither an empty `seq` nor a node no grant explains.

## The secure program release

The secure program (`secure-program/secure-program.js`) is the program of the app that implements
the device side of this protocol: "the app" of sections 3 to 7 and 10.1. This repository is the
source of truth of that file. The backend of the operator serves a byte-identical copy to the apps,
and a release build of an app loads a served program only after it verified, on the device, that
the program is the subject of a release statement signed by the release key of the operator and
recorded in the public transparency log. This section states the release, the statement, the entry
of the log, the release proof the backend hands the app, the keys, and the verification.

### The release and its statement

A release of the program is a tag `secure-program-v{N}` of this repository, where N is the value of
the line `const VERSION = N;` of the file at that tag (the first such line in the file; a file
without the line has the version 0). The release workflow refuses a tag whose N is not the version
of the file. The tags `secure-program-v*` and the enclave release tags `v*` do not overlap.

The release statement is one JSON object serialized to bytes by these rules:

- Exactly seven keys, in this order: `kind`, `release`, `version`, `sha256`, `git_commit`,
  `repository`, `path`.
- No white space between tokens, characters outside ASCII escaped (the output of Python
  `json.dumps(statement, separators=(",", ":"), ensure_ascii=True)`), followed by one LF (0x0A).
  No other line break and no other white space.
- `kind` is `"secure-program"`. `release` is the tag. `version` is the integer N, without a sign
  and without a leading zero. `sha256` is the SHA-256 of the bytes of the file at the tag, 64
  lower-case hexadecimal characters. `git_commit` is the commit the tag points to (an annotated tag
  is peeled), 40 lower-case hexadecimal characters. `repository` is
  `"pickle-com/credential-enclave"`. `path` is `"secure-program/secure-program.js"`.
- At most 16,384 bytes, the limit of 10.3.

```text
{"kind":"secure-program","release":"secure-program-v27","version":27,"sha256":"<64 hex>","git_commit":"<40 hex>","repository":"pickle-com/credential-enclave","path":"secure-program/secure-program.js"}
```

`secure-program/statement.py` writes these bytes. The workflow `secure-program-release.yml`
(enclave.md 11.2) runs it for the pushed tag and attaches the result to the GitHub release of the
tag as `statement.json`, next to the file.

A node does not take this statement for an endorsement of 10.3: check 1 of 10.3 requires `pcr0`,
`pcr1` and `pcr2`, which this statement does not have. The two kinds of statement are signed by the
same release key and do not mix.

### The entry of the log

The operator signs the bytes of the statement with the release key (ECDSA P-256 with SHA-256, the
signature in ASN.1 DER) and records the signature in Rekor (rekor.sigstore.dev) as an entry of the
kind `hashedrekord`, version 0.0.1: the body of 10.3, with the SHA-256 of the statement in
`spec.data.hash.value`, the signature in `spec.signature.content` and the PEM of the release public
key in `spec.signature.publicKey.content`. The log returns the body, the time at which it took the
entry (`integratedTime`), the global index of the entry (`logIndex`), the log identifier (`logID`),
the signed entry timestamp (the signature of the log key over the bytes stated in 10.3) and the
inclusion proof: the index of the leaf in the active shard of the log (`inclusionProof.logIndex`,
a value other than the global index), the size of the tree (`treeSize`), the root hash
(`rootHash`), the hashes of the path from the leaf to the root (`hashes`) and the checkpoint, a
signed note of that tree head (`checkpoint`).

### The release proof

The release proof is the JSON object the operator writes from the response of the log. The backend
of the operator hands it to the app next to the program, and the same object is attached to the
GitHub release of the tag as `secure-program.release.json`.

```text
{"statement": "<b64u of the bytes of the statement>",
 "entry": {"body": "<standard base64, exactly as the log returned it>",
           "integrated_time": <integer>, "log_index": <integer: the global index>,
           "log_id": "<64 lower-case hexadecimal characters>",
           "signed_entry_timestamp": "<standard base64>",
           "inclusion_proof": {"log_index": <integer: the index in the shard>,
                               "tree_size": <integer>,
                               "root_hash": "<64 lower-case hexadecimal characters>",
                               "hashes": ["<64 lower-case hexadecimal characters>", ...],
                               "checkpoint": "<the checkpoint, exactly as the log returned it, its line breaks included>"}}}
```

### The keys

Two values are compiled into the apps and into the verification tool of this repository
(`credential-enclave-verify program`, `verify/src/program.rs`):

| Value | What it is |
| --- | --- |
| The release key | The public key of the operator, the key of 10.3: `enclave/release/release-key.pem`. The apps hold the DER of its SubjectPublicKeyInfo |
| The log key table | The public keys of the transparency log, by log identifier (the lower-case hexadecimal SHA-256 of the DER of the key, as in 10.3). The identifier `c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d` maps to `enclave/release/rekor-key.pem`. When the log signs with a new key, an app release adds a row; an app of an older build verifies no entry of the new key |

### The verification

The input is the bytes of the served program, the version the program declares (the
`const VERSION = N;` line, 0 when the line is absent), the release proof, the release key and the
log key table. The ten checks run in this order, and the first one that fails ends the
verification with its code. An app logs a failure as `secure program rejected: release proof {code}`
and does not load the program; the assembly of the backend refuses a bundle whose proof fails; the
tool prints `program release: failed: {code}: {detail}`. No check reads a clock: the notice period
is 0 seconds, as in 10.3. A decoding that fails (base64, UTF-8, JSON, hexadecimal) is a failure of
the check that reads the value.

| Check | Rule | Code |
| --- | --- | --- |
| 1 | The proof is a JSON object whose `statement` is a string and whose `entry` is an object | `proof_shape` |
| 2 | `statement`, decoded from base64url without padding, is 1 to 16,384 bytes of UTF-8 that read as a JSON object with `kind` equal to `"secure-program"`, `version` an integer from 0 to 2^31 − 1, `sha256` 64 lower-case hexadecimal characters and `release` equal to `"secure-program-v"` followed by the decimal `version`. The other keys are not read | `statement_shape` |
| 3 | The SHA-256 of the bytes of the program, in lower-case hexadecimal, equals `sha256` | `source_hash` |
| 4 | The version the program declares equals `version` | `version_mismatch` |
| 5 | `entry.log_id` is a key of the log key table. Its value is the log key of the checks below | `unknown_log` |
| 6 | `entry.body` is a string of the characters `A` to `Z`, `a` to `z`, `0` to `9`, `+`, `/` and `=` that decodes to a JSON object with `apiVersion` `"0.0.1"`, `kind` `"hashedrekord"`, `spec.data.hash.algorithm` `"sha256"` and `spec.data.hash.value` equal to the lower-case hexadecimal SHA-256 of the statement bytes. `spec.signature.publicKey.content`, decoded from standard base64 and then read as PEM, gives the DER of the release key. `spec.signature.content` is a string, and `entry.integrated_time` and `entry.log_index` are integers | `entry_shape` |
| 7 | `spec.signature.content`, decoded from standard base64, is an ASN.1 DER ECDSA signature of the release key over the statement bytes (SHA-256) | `release_signature` |
| 8 | `entry.signed_entry_timestamp`, decoded from standard base64, is a signature of the log key over the UTF-8 bytes `{"body":"<entry.body>","integratedTime":<entry.integrated_time>,"logID":"<entry.log_id>","logIndex":<entry.log_index>}`: the keys in this order, no white space, the integers in decimal | `log_signature` |
| 9 | `entry.inclusion_proof` is an object whose `log_index` and `tree_size` are integers (`tree_size` at least 1) and whose `root_hash` and every element of `hashes` are 64 lower-case hexadecimal characters. With `leaf = SHA-256(0x00 ∥ the decoded body)`, the path computation below ends with `sn = 0` and a root equal to `root_hash` | `inclusion_proof` |
| 10 | `checkpoint` is a string that holds `"\n\n"`. The part before the first `"\n\n"`, split at `"\n"`, has at least three lines: the first is not empty (the origin of the log), the second is `tree_size` in decimal, and the third, decoded from standard base64, is the bytes of `root_hash`. Among the lines of the part after it, at least one starts with `"— "` (U+2014 and a space), continues as `{name} {base64}` with a non-empty name, and its base64 decodes to bytes whose first four equal the first four bytes of the SHA-256 of the DER of the log key and whose remainder is an ASN.1 DER ECDSA signature of the log key over the UTF-8 bytes of the part before the `"\n\n"` followed by one `"\n"` | `checkpoint` |

The path computation of check 9 is that of RFC 6962 section 2.1.1:

```text
fn = inclusion_proof.log_index, sn = tree_size − 1, r = leaf
for each p of hashes, in order:
    if sn == 0: fail
    if fn is odd or fn == sn:
        r = SHA-256(0x01 ∥ p ∥ r)
        while not (fn is odd or fn == 0): fn = fn >> 1, sn = sn >> 1
    else:
        r = SHA-256(0x01 ∥ r ∥ p)
    fn = fn >> 1, sn = sn >> 1
pass when sn == 0 and r == root_hash
```

### What the app requires

An app runs the verification for a program that the backend served, in a release build. The
program an app ships with is loaded without it, and a debug build loads a served program without
it unless its verification lever is set. A served program also carries the deployment signatures
of the operator (Ed25519, one per server target), which the app checks as before: the release
proof is a second condition, not a replacement. An app that loaded a program shows the version and
the SHA-256 of that program on its encryption key screen, so a user can compare them with a
release of this repository.

Three implementations run the same ten checks with the same codes: the apps (Swift on iOS, Kotlin
on Android), the assembly of the backend of the operator (Python), and
`credential-enclave-verify program` of this repository (Rust).
