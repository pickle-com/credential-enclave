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
| Version | Every object carries `"v":1`. The receiver refuses a `v` that is not 1 (`unsupported_version`) |
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
| 1, 2 | A constant list inside the signed program of the app (`[{release, pcr0, pcr1, pcr2}]`, each PCR as 96 lower-case hexadecimal characters). For every release of the enclave the list is changed and the program is signed again | Its own measurement. A giving node also accepts the measurement of a later release whose endorsement it verified, and a receiving node also accepts the measurements of the list of predecessors inside its program (10.3) |
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
  `statement`, `entry`).
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
entry = {"body": b64u(body), "sig": b64u(Ed25519(node signing key, "pickle.secure.v1.log-entry\n" || body))}
body  = UTF-8(JSON {"v":1,"node":"...","user_id":"...","key_id":"...","seq":1,"prev":b64u(32),"time_ms":0,"enc":b64u,"ct":b64u})
        enc, ct = HPKE single-shot seal: recipient public key = the log_pk of the grant at that time, info = UTF-8("pickle.secure.v1.log-entry"),
                  aad = UTF-8(node + "\n" + user_id + "\n" + key_id + "\n" + seq in decimal), plaintext = UTF-8(JSON event)
entry_hash = SHA-256("pickle.secure.v1.log-chain\n" || body)
```

- There is one chain per (node, account) pair. The `seq` of the first entry is 1 and its `prev` is
  32 zero bytes. The `prev` of every later entry is the `entry_hash` of the entry before it.
- The entry and the act. `forward`, `refresh`, `revoke-token`, `release`, the commands grant and
  revoke, and `peer/export` create their entry before the act: the node creates the entry and
  raises the end of the chain in its memory, and after that it calls the provider, hands the value
  out, changes the delegation or seals the user key to a peer. `peer/import` creates its entry
  before it puts a grant in place. `oauth/complete` receives the token response of the provider
  first and creates the entry `connection_created` before the record leaves the node: no part of
  an accepted token response leaves the node before that entry exists, and when a step after the
  response fails, the tokens are dropped inside the node and nothing of them leaves. `oauth/merge`
  calls no provider and creates no entry.
- The entry and the log store. A node that has a log store writes the entry to it between the
  creation of the entry and the act, and acts only after the store confirmed the entry. 7.6 names
  the act of every call and the two calls that do not wait.
- The cases that share an entry or create none are named where they are described: identical GET
  requests (7.2), a repeated `refresh` of the same record and a `refresh` of a record without a
  refresh token (enclave.md 5.7), a revoke of an account without a grant (5.4), a repeated
  transfer of a grant to the same node, a transfer that a node takes for an account whose grant
  of the same key it holds (10.1), and a call that uses a credential of an account that has 64
  pending entries (enclave.md 5.14).
- The entry is carried in the response of the call, and the operator's backend stores it. The
  backend stores the bytes of `body` and `sig` as they are. The log store holds the same bytes
  (7.6): the storage of the backend is the place a reader fetches an entry from quickly, and the
  log store is the place where an entry cannot be deleted.
- The ephemeral key pair of the HPKE seal is `DeriveKeyPair` (RFC 9180 7.1.3) with 32 random bytes
  as the input keying material. A node uses new random bytes for every entry. The test vectors
  (section 13) fix these 32 bytes (`hpke_seed`).
- The key order of the event JSON is the order that the table of 7.2 gives (`t` is the first key).

### 7.2 The events (the plaintext of an entry)

| `t` | The other keys | Created by |
| --- | --- | --- |
| `grant_accepted` | `not_after_ms`, `custody` | The command grant |
| `grant_revoked` | | The command revoke |
| `connection_created` | `record_id`, `provider`, `scope` (the scope string among the public fields of enclave.md 6.4: the `scope` of the token place, else the top-level `scope`, when the provider definition lists it. Otherwise the empty string) | `oauth/complete` |
| `credential_refreshed` | `record_id`, `provider`. It records a refresh call (the entry is created before the call, so a refresh that the provider refused is on the log as well) | `refresh` |
| `connection_removed` | `record_id`, `provider`, `provider_revoke` (bool: whether the node calls the revocation address of the provider after this entry. It is true when the definition has a revocation address and the plaintext of the record has a token. The entry is created before the call, so it does not carry the outcome of the call) | `revoke-token` |
| `provider_request` | `record_id`, `provider`, `method`, `host`, `path`, `query`, `body_bytes`, `body_sha256` (b64u, the empty string when there is no body), `context`, `window_s` (300, only on a request that can be merged) | `forward` |
| `secret_released` | `record_id`, `kind`, `field`, `origin`, `context` | `release` |
| `totp_issued` | `record_id`, `origin`, `context` | `release` |
| `grant_transferred_out` | `to` (the `node` of the receiving node) | `peer/export` (section 10) |
| `grant_transferred_in` | `from` (the `node` of the giving node), `not_after_ms`, `custody` | `peer/import` (section 10) |

- `method`, `host`, `path` and `query` are those of the request that the node sends. `path` and
  `query` are whole: an address of `forward` is at most 8,192 bytes long (enclave.md section 7),
  and an event holds up to 8,192 bytes of each.
- `context` is a string of at most 256 characters that the caller (the operator domain) gave. The
  node does not verify this value. The log screen of the app shows it apart, as a context that the
  operator stated.
- Merging of identical requests: a `provider_request` whose method is GET and whose body is empty
  creates no new entry when such an entry of the same account for the same record and the same
  address (equal host, path and query) was created less than 300 seconds before. An entry that can
  be the target of a merge (a GET without a body) carries `window_s: 300`: it says that the same
  request may have happened any number of times in the 300 seconds after it. A GET request with a
  body, a request of another method and the release of a vault value (`release`) are not merged:
  each has its own entry.
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
- A node creates a head whose `final` is true in its orderly shutdown, one per account. After that
  the node creates no entry for that account.

### 7.4 Verification (the app)

For one (node, account) chain, the app starts from the signing public key of that node, which it
keeps in its list of nodes, and from its last verified point `{seq, hash}`.

1. The app obtains a head. From a living node it requests one with a new nonce and checks the
   signature and the nonce. For a node that is gone it checks the signature of the `final` head
   that the operator's backend stored.
2. The app receives the entries in order, from the `seq` after the verified point to the `seq` of
   the head. For every entry it checks the signature, `node`, `user_id`, that `seq` continues
   without a gap, and that `prev` equals the `entry_hash` of the entry before it.
3. When the `entry_hash` of the last entry equals the `hash` of the head, the app raises the
   verified point to the head.

| Result | Meaning |
| --- | --- |
| Everything passes | The entries that this node wrote for this account are stored without a gap up to the head |
| Entries are missing, or the chain is broken | The stored log has an omission or a change |
| A node that is gone has no `final` head | The part after the last verified point cannot be checked against a head (the node disappeared without its orderly shutdown). The entries of the acts of that node are in the log store all the same: a node writes an entry there before the act (7.6) |

The authenticity of an entry that the app displays is checked with the node signature of that
entry (the whole chain is not needed for this), and the content is opened with the log decryption
private key. The app does not open an entry whose `key_id` is not its own. It shows such an entry
as part of a delegation of another key.

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

The storage of the operator's backend is inside the operator domain: an entry that is stored there
can be deleted there, and what the app's verification of the chain shows is that something is
missing. The log store is the place where an entry cannot be deleted: a node writes every entry
there itself, and acts only after the store confirmed the entry.

| Item | Value |
| --- | --- |
| Store | One Amazon S3 bucket with Object Lock and versioning. The binding of a node names the bucket and its region (4.1) |
| Object key | `v1/accounts/{user_id}/{node}/{seq}-{hash}`. `seq` is the `seq` of the entry as 20 decimal digits, with zeros in front. `hash` is `b64u(entry_hash)` of the entry (7.1) |
| Object body | The signed entry as a response carries it: `{"body":"...","sig":"..."}`, the same bytes |
| Retention | Mode `COMPLIANCE`, until the node time of the write plus 365 days. Until then nobody, the root user of the AWS account included, can delete that object version, overwrite it or shorten its retention |

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
  entry that verifies: the signature of the node over its `body`, and `entry_hash(body)` equal to
  the `hash` of the key.

The acts that wait for the confirmation. A node that has a log store does not perform the act of a
row before the store confirmed the entry of that row:

| Call | Entry | The act that waits | When the store does not confirm the entry |
| --- | --- | --- | --- |
| `forward` | `provider_request` | The request to the provider. A request that shares the entry of an identical GET request (7.2) waits for that entry: when the store confirmed it before, nothing is written, and when it is a pending entry, the call writes it again | `log_store_unavailable`. No request is sent |
| `refresh` | `credential_refreshed` | The call of the token address | `log_store_unavailable`. The token address is not called |
| `revoke-token` | `connection_removed` | The call of the revocation address | `log_store_unavailable`. The revocation address is not called |
| `release` | `secret_released`, `totp_issued` | The value in the response | `log_store_unavailable`. The value does not leave |
| `oauth/complete` | `connection_created` | The record in the response (the code is exchanged before the entry is created, 7.1) | `log_store_unavailable`. The record does not leave and the tokens are dropped inside the node: the connection is started again |
| The command grant | `grant_accepted` | The user key is put into the memory of the node | The signed reply has `ok` false and the code `log_store_unavailable`. The node holds no key |
| The command revoke | `grant_revoked` | None. The user key is erased whatever the store answers | The reply is that of a revoke that succeeded. The entry is a pending entry |
| `peer/export` | `grant_transferred_out`, one per account | The grant of that account enters the transfer | `log_store_unavailable` for the whole call, also when the store confirmed the entries of other accounts: no grant is handed over. The next call for the same receiving node creates no entry for these accounts: it writes the entries that wait again |
| `peer/import` | `grant_transferred_in`, one per account | None. The grant is put in place, and the entry is a pending entry | Does not apply: the call does not write |

- A pending entry is an entry that the store has not confirmed and that no call is writing. It
  stays in the memory of the node (it is on the chain and among the entries without a storage
  acknowledgement). The next write of the same account takes the pending entries of that account
  along, at the same time as its own entry. A pending entry that the store refuses again does not
  fail that call: the condition of an act is the confirmation of the entry of that act.
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
| `too_large` | A body above the limit (64 MiB each for a request and a response) |
| `log_backlog` | The entries of that account without a storage acknowledgement reached the limit (64) |
| `log_store_unavailable` | The log store did not confirm the entry of the call, or the node cannot write to it: it has no log store in its configuration, or no credentials within their time (7.6). The act of the call did not take place. A repeated call can succeed |
| `capacity_unavailable` | The mail call could not immediately reserve its slot or body budget. No credential was opened and no provider request was sent. A later call can succeed |

## 12. Constants

| Name | Value |
| --- | --- |
| Longest time of a grant | 30 days (of node time. A node accepts a larger value and shortens it) |
| Interval at which the app renews a grant | 24 hours |
| Lifetime of a challenge | 300 seconds |
| Lifetime of a pending authorization | 600 seconds |
| Merge window of identical GET requests | 300 seconds |
| Time a node keeps the response of a successful `refresh` (enclave.md 5.7) | 3,600 seconds |
| Kept `refresh` responses per account | 16 (the most recent ones) |
| Most accounts in one delegation transfer | 1,000 |
| Most nodes that a node hands one grant to (10.1) | 64 |
| Longest release statement (10.3) | 16,384 bytes |
| Notice period of a release (10.3) | 0 seconds |
| Longest time by which a log entry lies after the time of the node (10.3) | 300 seconds |
| Most entries without a storage acknowledgement (per account) | 64 |
| Retention of an object of the log store | 365 days from the node time of the write |
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
| `log` | The node signing public key, `user_id`, `key_id`, `log_private`, `log_pk`, `checkpoint`, `entries` (three entries: `seq`, `hpke_seed`, `time_ms`, `event_text`, `entry`, `entry_hash`), `head_nonce`, `head`, `final_head`, `chain_valid`, `missing_middle` (the list without the middle entry, and `chain_valid: false`) | The verification of the chain gives the same result, every entry opens to `event_text`, and an entry created with the same `hpke_seed` equals `entry` |
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
