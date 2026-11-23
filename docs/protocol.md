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
| Log store | The Amazon S3 buckets that a node writes every log entry to before the act the entry describes (7.6). The binding of a node names the store by one bucket name. Its objects are locked: until the retention of an object ends, nobody can delete it |

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

The log (section 7) has three formats. Format 1 is the format of the releases before v2.0.0: one
entry holds one event, and the key of its object in the log store is `{seq}-{hash}`. Format 2 is the
format of the releases from v2.0.0 to v2.3.0: one entry holds the events of one or more acts of one
account, the key of its object carries the hash of the body and the hash of the chain, and the node
signs the end of each chain. Format 3 is the format of the releases from v2.4.0 on: the key of an
object carries the time of its entry, the node that created it and the hash of its body, the keys of
one account sort from the latest entry to the earliest, the store is a set of buckets, and a node
writes its own attestation document to the store and signs no head. A node writes one format for its
whole life, the format of its release. A reader (the app) reads all three: the shape of the key
tells the format. Entries that are already stored are not written again.

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
| `pickle.secure.v3.log-entry`, `pickle.secure.v2.log-entry`, `pickle.secure.v1.log-entry` | HPKE info of a log entry of format 3, of format 2 and of format 1 (7.1) |
| `pickle.secure.v3.log-entry\n`, `pickle.secure.v2.log-entry\n`, `pickle.secure.v1.log-entry\n` | Signature purpose of a log entry of format 3, of format 2 and of format 1 (7.1) |
| `pickle.secure.v2.log-chain\n`, `pickle.secure.v1.log-chain\n` | Prefix of the chain hash of format 2 and of format 1 (7.1) |
| `pickle.secure.v1.head\n` | Signature purpose of a head (formats 1 and 2, 7.3) |
| `pickle.secure.v3.node-document\n` | Prefix of the nonce of a node document (7.7) |
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
- `log` names the log store of the node (7.6): a bucket name and its region. The buckets a node
  writes to follow from that name by a rule of the node program (7.6), so the name fixes them. A
  node that has no log store writes no `log` key: its binding ends with `release`. A node takes a
  log store once and does not change it (enclave.md 5.1), so the `log` of a binding a verifier read
  holds for as long as that node lives.
- `bucket` is 3 to 63 characters: lower-case letters, digits and `-`, and neither the first nor
  the last character is `-`. `region` has the form of an AWS region name: parts joined by `-`, at
  least three, where the first part is two lower-case letters, the last part is one or two digits
  and every part between them is lower-case letters (`us-west-2`). A `log` of another form is
  not a binding: a verifier refuses the document. A node takes a log store only when its bucket
  name is at most 49 characters long (7.6).

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

A later release (the app). A document that passes every step but step 7, with no PCR all zero, is
the document of a node of a release that the program of the app does not list: a release later
than the program (4.5: the list is a constant of the signed program, and a new release of the
enclave reaches the apps as a new program). The app applies step 10 to such a document as well (a
node of this deployment writes to the log store of the environment). The app hands such a node no
key, as for any measurement outside the list, and does not count the document as a failed
verification: its verification of the log (7.4) leaves the chain of that node pending, counts the
node as a node of a later release, and the program that lists the release verifies the chain. A
document that fails another step, a PCR all zero, and a binding that names another log store are
failed verifications, as before.

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
| 1, 2 | A constant list inside the signed program of the app (`[{release, pcr0, pcr1, pcr2}]`, each PCR as 96 lower-case hexadecimal characters). For every release of the enclave the list is changed and the program is signed again. An app whose program does not list a release treats the nodes of that release as nodes of a later release (4.3): no key, and a pending verification of their chains (7.4) until the app loads the program that lists it | Its own measurement. A giving node also accepts the measurement of a later release whose endorsement it verified, and a receiving node also accepts the measurements of the list of predecessors inside its program (10.3) |
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
| 11a | (grant) The node can write to its log store: it has one, credentials for it within their time, and its node document in the store (7.6, 7.7). A node of platform `local` without a log store passes | `log_store_unavailable` |
| 12 | This node issued `challenge`, not more than 300 seconds ago, and it was not used before. When this check passes, the challenge is marked as used. (grant) The node issued the challenge after the last revoke of that account that it accepted (5.4) | `bad_challenge` |
| 13 | (grant) `not_after_ms > now`. A value larger than `now + 30 days` is shortened to `now + 30 days` (5.2) | `bad_expiry` |
| 13a | (grant) When the account has a grant of the same `sign_pk` within its time, the command renews that grant: its end becomes the end of step 13, earlier or later than the end it had. The node creates no entry and writes nothing, step 14 does not apply, and the reply carries the end the grant has now | |
| 14 | (grant) In every other case (the account has no grant, its grant ended by its time or by a revoke, or its grant has another `sign_pk`) the node creates the log entry `grant_accepted` (section 7) and writes it to the log store. After the store confirmed the entry, it puts the grant into its memory (the grant replaces the grant and the revocation marker that were there) | `log_store_unavailable`, `bad_challenge` |
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
`log_store_unavailable`. In both cases the entry `grant_accepted` exists (in the store, or as a
pending entry of the node) and the node holds no user key of that grant (7.6: an entry can
describe an act that did not take place).

The renewal of step 13a. The entry `grant_accepted` that the store confirmed when the node took the
user key names that key, and the node holds the same key before and after a renewal: a renewal puts
no key into the node, so it has no entry. It is a command of the account all the same: it passed
steps 1 to 13, so only the key of the account moves the end of its grant, and a carrier cannot
repeat it (its challenge is used). A grant that ended, by its time or by a revoke, is not renewed:
the next grant command of that key is a grant of step 14 and has its entry. A renewal can shorten
a grant: the end in force is the end of the last grant command of that key the node accepted, so
an account that lowers the time of its delegation does so with a grant command and without a
revoke. When another command put a grant of the same key in place while the entry of step 14 was
written, the end of the command whose entry was written is the end in force.

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
  succeeded. A node without a log store, without credentials for it or without its node
  document in the store (7.7) takes a revoke as well.
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
                    "challenge":"...","key_id":"...","not_after_ms":0,"time_ms":0})
```

- `type` is `grant_reply` or `revoke_reply`. In the reply of a failure, `ok` is false and `code` is
  the failure code.
- The reply of a node of a release before v2.4.0 carries one more key between `not_after_ms` and
  `time_ms`: `"head":{"seq":0,"hash":"..."}`, the end of the chain of that (node, account) pair at
  the time of the reply (7.3). A verifier checks the signature over the body bytes as it received
  them and reads the keys named here.
- The app verifies `sig` with the node signing public key it obtained from the attestation, and it
  checks that `challenge` equals the value it sent and that `key_id` is its own.

The values of the fields:

| Reply | `type` | `user_id`, `challenge` | `key_id` | `not_after_ms` |
| --- | --- | --- | --- | --- |
| A grant that succeeded | `grant_reply` | The values of the command | The key_id of the `sign_pk` of the command | The end of the grant after the command: the value the node accepted (it can be the value shortened to the limit of 5.2), or, for a renewal (step 13a of 5.3), the later of that value and the end the grant had |
| A revoke that succeeded | `revoke_reply` | The values of the command | The key_id of the `sign_pk` of the command | 0 |
| A failure in steps 1 to 10 of 5.3 (the node could not verify the command, or it cannot take the command) | `grant_reply` | Empty strings | Empty string | 0 |
| `user_mismatch`, `bad_challenge`, `bad_expiry`, `log_store_unavailable`, the `bad_signature` of a revoke | The type of the command | The values of the command | The key_id of the `sign_pk` of the command | 0 |

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
entry = {"body": b64u(body), "sig": b64u(Ed25519(node signing key, "pickle.secure.v3.log-entry\n" || body))}
body  = UTF-8(JSON {"v":3,"node":"...","user_id":"...","key_id":"...","seq":1,"prev":b64u(32),"time_ms":0,"kind":"u","count":1,"enc":b64u,"ct":b64u})
        enc, ct = HPKE single-shot seal: recipient public key = the log_pk of the grant at that time, info = UTF-8("pickle.secure.v3.log-entry"),
                  aad = UTF-8(node + "\n" + user_id + "\n" + key_id + "\n" + seq in decimal),
                  plaintext = UTF-8(JSON array of the events, in the order of their creation)
body_hash = SHA-256(body)
```

- This is format 3, the format of the releases from v2.4.0 on. A node numbers the entries it creates
  for one account: the `seq` of the first one is 1 and its `prev` is 32 zero bytes, and the `prev`
  of every later entry is the `body_hash` of the entry the node created before it for that account.
  These entries, in the order of their `seq`, are the chain of the node for the account, and an
  entry is on the chain from the moment the node created it. The completeness of the log does not
  rest on the chain: it rests on the log store (7.4, 7.6). `count` is the number of events in the
  plaintext (1 to 128) and `kind` is the letter of the kind of the entry.
- The two kinds of entry. A use entry (`kind` `u`) holds use events: `provider_request`,
  `credential_refreshed`, `mail_request`, `secret_released`, `totp_issued`. A control entry (`kind`
  `c`) holds one control event: `grant_accepted`, `grant_revoked`, `connection_created`,
  `connection_removed`, `grant_transferred_out`, `grant_transferred_in`. A control entry is never
  merged with another event. The first entry of a node for an account is a control entry when the
  node took the user key by a grant command or from a node of an earlier release, and it can be a
  use entry when the node took the key from a node of its own measurement, a transfer that has no
  entry (10.1).
- The open batch and the group commit. A node keeps, per account, the use events whose entry does
  not exist yet (the open batch). A call that creates a use event puts it into the open batch. When
  no write of that account is in progress, the call closes the open batch into one entry (the entry
  gets the next `seq` and is sealed and signed) and writes it (7.6): the call is the writer of the
  account. While a write of the account is in progress, the call waits: the writer closes the open
  batch into the next entry when its write ends, and one of the waiting calls writes it. So an entry
  holds the events that arrived while the write before it ran. An open batch is closed before it
  holds more than 128 events or more than 1,048,576 bytes of plaintext, and a control event closes
  the open batch before it and forms an entry of its own. An act waits for the confirmation of the
  entry that holds its event (7.6): no event is in two entries, and no entry is created for an act
  that the common front refused. When the store does not confirm the write, the writer fails with
  `log_store_unavailable` and the entry is a pending entry (7.6); a call that waited for that entry
  writes it once more, as the next writer, and a call that waited for twice the time limit of a
  write fails with `log_store_unavailable`.
- A forward batch (enclave.md 5.8b) creates one use event per request of the batch, in the order of
  the requests, all into the open batch of the account in one step. The requests of one batch may
  end up in two entries when the open batch reaches a cap between them; the batch waits for the
  confirmation of every entry that holds one of its events.
- The entry and the act. `forward`, `forward/batch`, `refresh`, `revoke-token`, `release`, the
  command grant that puts a user key into the node, the command revoke, and `peer/export` to a node
  of a later release create their event before the act: the node creates the event, and the entry
  that holds it, and after that it calls the provider, hands the value out, changes the delegation
  or seals the user key to the peer. `peer/import` of a transfer from an earlier release creates its
  entry before it puts a grant in place, and writes it after (7.6). `oauth/complete` receives the
  token response of the provider first and creates the entry `connection_created` before the record
  leaves the node: no part of an accepted token response leaves the node before that entry exists,
  and when a step after the response fails, the tokens are dropped inside the node and nothing of
  them leaves. `oauth/merge` calls no provider and creates no event.
- The entry and the log store. A node that has a log store writes the entry to it between the
  creation of the entry and the act, and acts only after the store confirmed the entry. 7.6 names
  the act of every call and the two calls that do not wait.
- The cases that share an event or create none are named where they are described: identical GET
  requests (7.2), a repeated `refresh` of the same record and a `refresh` of a record without a
  refresh token (enclave.md 5.7), a revoke of an account without a grant (5.4), a grant command that
  renews the grant in force (5.3), a transfer between two nodes of one measurement, a repeated
  transfer of a grant to the same node of a later release, a transfer that a node takes for an
  account whose grant of the same key it holds (10.1), and a call that uses a credential of an
  account that has 64 pending entries (enclave.md 5.14).
- The entry is not carried in the response of a call. The response names the entry and the index of
  the event in it (the `log` object of a response, enclave.md section 4). The storage of the
  operator's backend holds no entry: the log store is the one place an entry is read from.
- An event whose JSON alone is longer than the plaintext of an entry may be is refused with
  `too_large` before anything changes: no entry could hold it.
- The ephemeral key pair of the HPKE seal is `DeriveKeyPair` (RFC 9180 7.1.3) with 32 random bytes
  as the input keying material. A node uses new random bytes for every entry. The test vectors
  (section 13) fix these 32 bytes (`hpke_seed`).
- The key order of the event JSON is the order that the table of 7.2 gives (`t` is the first key and
  `time_ms` the second).

Format 2 (the releases from v2.0.0 to v2.3.0): the signature purpose is
`pickle.secure.v2.log-entry\n`, the body is the body above with `"v":2`, the HPKE info is
`pickle.secure.v2.log-entry`, and the entries of one (node, account) pair form a chain: the `prev`
of an entry is the `entry_hash` of the entry before it, with

```text
entry_hash = SHA-256("pickle.secure.v2.log-chain\n" || prev || body_hash || UTF-8(fields))
             prev:   the 32 bytes of the entry_hash of the entry before
             fields: the first five parts of the key of the entry as the key writes them (7.6),
                     "{seq}-{time_ms}-{kind}-{count}-{key_id}" (57 characters)
```

The key of its object carries `body_hash` and `entry_hash` (7.6), the node signs the end of the
chain (the head, 7.3), and a reader verifies the chain from the keys of a listing up to a head (7.4,
"Formats 1 and 2"). A node of format 2 creates the entry `grant_accepted` for every grant command it
accepts and the entries `grant_transferred_out` and `grant_transferred_in` for every transfer.

Format 1 (the releases before v2.0.0): the signature purpose is `pickle.secure.v1.log-entry\n`, the
body is `{"v":1,"node","user_id","key_id","seq","prev","time_ms","enc","ct"}`, the HPKE info is
`pickle.secure.v1.log-entry`, the plaintext is one event (the JSON object, not an array),
`entry_hash = SHA-256("pickle.secure.v1.log-chain\n" || body)`, and the object key is
`{seq}-{b64u(entry_hash)}` (7.6). A reader verifies a chain of format 1 by its entries (7.4,
"Formats 1 and 2").

A node writes format 3. A reader reads all three: the entries of the earlier formats stay in the
store until their retention ends (7.6), and the shape of a key tells the format of its entry.

### 7.2 The events (the plaintext of an entry)

| `t` | The other keys | Created by |
| --- | --- | --- |
| `grant_accepted` | `time_ms`, `not_after_ms`, `custody` | The command grant that puts a user key into the node. A grant that renews the grant in force creates no event (5.3) |
| `grant_revoked` | `time_ms` | The command revoke |
| `connection_created` | `time_ms`, `record_id`, `provider`, `scope` (the scope string among the public fields of enclave.md 6.4: the `scope` of the token place, else the top-level `scope`, when the provider definition lists it. Otherwise the empty string) | `oauth/complete` |
| `credential_refreshed` | `time_ms`, `record_id`, `provider`. It records a refresh call (the event is created before the call, so a refresh that the provider refused is on the log as well) | `refresh` |
| `connection_removed` | `time_ms`, `record_id`, `provider`, `provider_revoke` (bool: whether the node calls the revocation address of the provider after this event. It is true when the definition has a revocation address and the plaintext of the record has a token. The event is created before the call, so it does not carry the outcome of the call) | `revoke-token` |
| `provider_request` | `time_ms`, `record_id`, `provider`, `method`, `host`, `path`, `query`, `body_bytes`, `body_sha256` (b64u, the empty string when there is no body), `context`, `window_s` (300, only on an event that a later identical request can share) | `forward`, `forward/batch` (one per request) |
| `mail_request` | `time_ms`, `record_id`, `provider`, `operation`, `request`, `body_bytes`, `body_sha256`, `context` (the mail call surface at the end of this document) | `mail/verify`, `mail/read`, `mail/submit` |
| `secret_released` | `time_ms`, `record_id`, `kind`, `field`, `origin`, `context` | `release` |
| `totp_issued` | `time_ms`, `record_id`, `origin`, `context` | `release` |
| `grant_transferred_out` | `time_ms`, `to` (the `node` of the receiving node), `release` (the release of the receiving node), `pcr0`, `pcr1`, `pcr2` (the measurement of the receiving node, 96 lower-case hexadecimal characters each: the values of the statement the release key signed, which the attestation document of the receiving node states, 10.3) | `peer/export` to a node of a later release (10.3). A transfer to a node of the measurement of the giving node creates no event (10.1) |
| `grant_transferred_in` | `time_ms`, `from` (the `node` of the giving node), `release` (the release of the giving node, as its binding names it), `not_after_ms`, `custody` | `peer/import` of a transfer from a node of an earlier release (10.3). A transfer from a node of the measurement of the receiving node creates no event (10.1) |

- `time_ms` is the node time at which the event was created: the moment the call passed the common
  front and the account lock created the event. The `time_ms` of an entry (7.1) is the time at
  which the open batch was closed, and it is never before the `time_ms` of an event of the entry.
  The times of the events one node created for one account do not decrease with (`seq`, index),
  and neither do the times of its entries.
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
  an event made under a grant that is over. An event that a later request can share carries
  `window_s: 300`: it says that the same request may have happened any number of times in the 300
  seconds after it. A node remembers at most 8,192 such events of one account at one time
  (`MERGE_KEYS`). A GET request without a body that finds no event to share while its account has
  that many has an event of its own without `window_s`: the node does not remember it, and no later
  request shares it. A GET request with a body, a request of another method and the release of a
  vault value (`release`) are not merged: each has its own event.
- The identifier of a node (`node`) is the signing public key of that node. So a reader that read
  the `to` of a `grant_transferred_out` can verify the signatures of the entries of the receiving
  node with that value.
- The events of the releases before v2.4.0: `grant_transferred_out` carries `time_ms` and `to` only,
  `grant_transferred_in` carries no `release`, and a node of those releases created the two for
  every transfer and `grant_accepted` for every grant command.

### 7.3 The head (formats 1 and 2)

A node of release v2.4.0 or later signs no head: `status` returns none, a reply carries none (5.5),
and its orderly shutdown signs nothing (enclave.md 5.11). What a reader needs of such a node is in
the log store: its entries and its node document (7.4, 7.7). This section states the head of the
nodes of the releases before, whose chains a reader verifies with it (7.4, "Formats 1 and 2").

```text
head = {"body": b64u(body), "sig": b64u(Ed25519(node signing key, "pickle.secure.v1.head\n" || body))}
body = UTF-8(JSON {"v":1,"type":"head","node":"...","user_id":"...","seq":0,"hash":b64u(32),"nonce":b64u,"time_ms":0,"final":false})
```

- `seq` and `hash` are the `seq` and the `entry_hash` of the last entry of that chain. A chain
  without entries has `seq` 0 and a `hash` of 32 zero bytes.
- `nonce` is the value that the requester gave (in a head whose `final` is true it is the empty
  string).
- A node of those releases creates a head whose `final` is true in its orderly shutdown, one per
  account, at the last entry of the chain that the log store confirmed, and creates no entry for
  that account afterwards. A node that ended without its orderly shutdown left no such head.
- The head covers entries. The events of an open batch are not on the chain yet, and their acts
  have not taken place (an act follows the confirmation of its entry, which follows the close of
  the batch).

### 7.4 Verification (a reader of the store)

A reader is whoever reads the log of one account from the log store: the app of the account, and
anyone who holds what the app holds. It needs the `user_id`, the name of the log store (the bucket
name and the region its program holds for its server target, which the binding of every node it
accepted names: 4.3 step 10) and, to open the entries, the log decryption private key. The reader
lists the store itself (7.6): a listing comes from Amazon S3 over TLS, through an address the
operator's backend signs, and the reader checks every address before it calls it (the bucket is the
one it computed, the prefix is one of its own account, the request is the listing it asked for). The
operator domain cannot change the response of a listing.

Format 3 (the nodes of the releases from v2.4.0 on). The listing is the index of completeness. Four
facts carry that:

1. A node performs an act with the user key of an account only after the log store answered the
   write of the entry of that act with the status 200 (7.6). The node runs the program of a
   measurement the account accepted (section 4), and this rule is part of that program.
2. TLS ends inside the node, and the node takes no other answer for a confirmation, also not the
   answer that an object of that key exists (7.6).
3. Nobody can delete an object version of the store, overwrite it or shorten its retention for 365
   days from its write (7.6).
4. The reader lists the object versions under the two prefixes of its account, `a3/{user_id}/c/` and
   `a3/{user_id}/u/`, in the bucket of its account (7.6). A listing of versions shows a version also
   when a delete marker lies on its key.

So the key of the entry of every act of the last 365 days is in the listing of the account, and an
entry that is not in the listing describes an act that did not take place (7.6). No head, no chain
equation and no tracing of a transfer from node to node is part of this: a reader does not need to
know which nodes held the key of the account to read everything they did with it.

The listing can hold more than the entries of nodes: the operator domain holds the credentials for
the buckets and can add objects under any key. The reader decides what is an entry:

| Step | What the reader checks | When the check fails |
| --- | --- | --- |
| The key | The key has the shape of format 3 for this account (7.6) | The object is not an entry and is left out. A delete marker is left out too, and a key counts once however many versions its object has (a write the node repeated adds a version) |
| The node | The node of the key has a node document in the store that verifies (7.7). It states the measurement of the enclave inside which the signing key of that node was created | The objects under the keys of that node are not entries. A node writes its document before it takes a user key and writes no entry without it, so no act of a node stands behind such an object |
| The object | A version of the object is `{"body","sig"}`, the SHA-256 of its body is the `body_hash` of the key, the signature verifies under the signing public key that the node identifier of the key is (purpose `pickle.secure.v3.log-entry\n`), and in the body `v` is 3 and `node`, `user_id`, `key_id`, `seq`, `time_ms`, `kind` and `count` are those of the key and of the account | A version whose body has another hash is not the object the key names (another version of it can be). A body of that hash that fails the signature or a field is the fourth row of the next table |
| The content | For an entry whose `key_id` is its own, the reader opens the plaintext with the log decryption private key (HPKE info `pickle.secure.v3.log-entry`, the AAD of 7.1) and reads `count` events | An entry of another `key_id` is an entry of another key of the account: the reader does not open it and shows it as part of a delegation of another key |

The control entries of an account are few (the life of a grant and of a connection) and its use
entries grow with its use, which is why the two kinds have two prefixes: a reader judges the log
from the control entries and reads the use entries it shows. The keys of a prefix sort from the
latest entry to the earliest (7.6), so a reader that read a prefix before reads its first page down
to a key it knows.

What the store shows a reader:

| What the reader finds | What it means |
| --- | --- |
| An entry of a node whose measurement the reader accepts (4.5) | An act of that node with the user key of the account: one that took place, or one whose entry the store confirmed and that did not follow (7.6) |
| An entry `grant_transferred_out` of such a node under the reader's own `key_id`, whose `release`, `pcr0`, `pcr1` and `pcr2` are those of a release the reader accepts | The user key went to a node of that release (10.3) |
| An entry `grant_transferred_out` of such a node under the reader's own `key_id` that names a measurement the reader does not accept, or an entry under the reader's own `key_id` of a node whose document states a measurement the reader does not accept | The user key is held by a program the reader did not accept. A reader whose program is older than a release finds this for a time: until it loads the program that lists the release (4.5) |
| Under a key of a node whose measurement the reader accepts: an object whose body has the `body_hash` of the key and fails the signature or a field, or two bodies of one `seq` that both verify | The signing key of that node signed values that contradict each other, or someone wrote an object in the name of the node. Neither happens while the node runs the accepted program and the operator domain leaves the store alone |
| A `seq` of a node that no key of the listing carries | An entry the store did not confirm: its act did not take place. It is no omission |
| A node whose entries end | A node that ended, with or without its orderly shutdown. Its entries are in the listing, and there is no end of a chain to verify |
| Keys of a node without a node document, or with one that does not verify | Objects that are not entries. They hide nothing: the entries of the nodes are in the listing beside them |
| A key the reader found in an earlier listing, of an entry younger than 365 days, is no longer listed | The store gave up an object version inside its retention: fact 3 does not hold |
| The reader cannot list: the backend signs no address, an address is not one of the listing the reader asked for, or the store refuses a signed address | The operator domain keeps the reader from the store. A failure of the reader's own network is not this case |

A program of the app reads format 3 by this section when it lists a release of format 3 among its
accepted releases (4.5). A program that lists none hands no key to a node of such a release and
counts it as a node of a release later than the program (4.3, and the table of "Formats 1 and 2"
below): the secure program of this repository (`secure-program/`) is in that state until its release
that lists one. The reference reader of this repository is `protocol/src/app.rs` (`verify_entry_v3`,
`open_entry_v3`, `read_node_document`), and the vectors `log_v3` and `log_store` (section 13) fix
its results.

Formats 1 and 2 (the nodes of the releases before v2.4.0). Their entries are in the bucket the
binding names (7.6), one chain per (node, account) pair, until their retention ends. The app
verifies such a chain as follows.

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

The witness signature is defined over the chain of format 2 (`entry_hash`), and no release
implements it. Format 3 has no end of a chain to settle: the entries of a node that is gone are in
the listing of the account (7.4).

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
| Store | A set of Amazon S3 buckets with Object Lock and versioning, in one region. The binding of a node names the store by one bucket name and its region (4.1), and the buckets of the set follow from that name (below) |
| Object key | Format 3: `a3/{user_id}/c/{rtime}.{node}.{seq}.{event}.{key_id}.{body_hash}` for a control entry and `a3/{user_id}/u/{rtime}.{node}.{seq}.{count}.{key_id}.{body_hash}` for a use entry, in the bucket of the account. `user_id` is written as it is. `rtime` is `9999999999999 − time_ms` of the entry as 13 decimal digits with zeros in front, `node` the identifier of the node that created the entry (43 characters), `seq` the `seq` of the entry in decimal without zeros in front, `event` the `t` of the one event of a control entry (1 to 64 lower-case letters, digits and `_`), `count` the `count` of a use entry in decimal without zeros in front (1 to 128), `key_id` the `key_id` of the entry (16 lower-case hexadecimal characters) and `body_hash` the b64u of the hash of 7.1 (43 characters). The parts are joined by `.`, which is no character of any of them. A key of another shape under the prefix of an account is not the key of an entry |
| Order of the keys | A listing returns the keys of a prefix in the order of their bytes. With `rtime` in front, the keys of one prefix of an account sort from the latest entry to the earliest, whichever node created them: the first page of a listing holds the latest 1,000 keys |
| Object body | The signed entry: `{"body":"...","sig":"..."}` |
| Retention | Every object version is written with mode `COMPLIANCE` and a retention until the node time of the write plus 365 days. Until then nobody, the root user of the AWS account included, can delete that object version, overwrite it or shorten its retention. The lifecycle rule of a bucket expires current versions 400 days after their creation and removes noncurrent versions 400 days after they became noncurrent. So an entry is in the store for at least 365 days and at most about 400 days, and a reader treats the absence of an entry older than 365 days as expired, not as an omission (7.4) |
| Encryption | Every write names the encryption of its object: `AES256`, a key the store manages |
| Node document | `n3/{node}` in the bucket of the node: the attestation document of the node, which the node writes itself (7.7) |
| Formats 1 and 2 | The entries of the releases before v2.4.0 are in the bucket the binding names, under `v1/accounts/{user_id}/{node}/`. Format 2: `{seq}-{time_ms}-{kind}-{count}-{key_id}-{body_hash}-{entry_hash}`, where `seq` is 20 decimal digits with zeros in front, `time_ms` 13 decimal digits with zeros in front, `kind` the letter `c` or `u`, `count` 3 decimal digits with zeros in front, `key_id` 16 lower-case hexadecimal characters, and `body_hash` and `entry_hash` the b64u of the two hashes of 7.1. Format 1: `{seq}-{hash}` with `hash` = `b64u(entry_hash)`. A node of format 3 writes nothing to that bucket |

The buckets of a log store. A binding names the bucket `B` in the region `R`. The log store has `N`
buckets, numbered 0 to `N − 1`:

```text
N        = 1,024  for B = character-credential-log-prod-1
           4      for B = character-credential-log-local-1
           32     for every other B
name(i)  = h8(i) + "-" + B + "-" + i, with i as four decimal digits with zeros in front
           h8(i) = the first 8 characters of the lower-case hexadecimal SHA-256 of UTF-8(B + "-" + i)
shard(x) = (the first two bytes of SHA-256(UTF-8(x)), as a big-endian unsigned integer) mod N
the bucket of an account         = name(shard(user_id))
the bucket of a node document    = name(shard(node))
```

- `N` is a power of two and a constant of `B`. The table is part of the node program, so it is part
  of the measurement, and a reader holds the same table. The entries of one account are all in one
  bucket, whichever node wrote them. The number of buckets of a store does not change: after a
  change, the entries of an account would lie in two buckets for 365 days.
- The hash in front of a name keeps the names of the buckets of one store apart in the name order of
  the service, so that the write rate of one bucket is not bound to the buckets whose names would
  lie beside it.
- A bucket name is at most 63 characters long, so `B` is at most 49 characters long. A node does not
  take a log store with a longer name (`invalid_request`).
- A reader computes the bucket of its account from its own `user_id` and the `B` and `R` its program
  holds, and lists no other bucket for format 3. A node computes the bucket of a write from the `B`
  of its binding, which every verifier of that binding compared with the name it expects (4.3 step
  10, 10.1 step 3a). So the one name fixes where a node writes and where a reader looks.

The write of one entry:

```text
PUT https://s3.{region}.amazonaws.com/{bucket of the account}/{object key}
Content-Type: application/json
x-amz-object-lock-mode: COMPLIANCE
x-amz-object-lock-retain-until-date: YYYY-MM-DDTHH:MM:SSZ
x-amz-server-side-encryption: AES256
x-amz-checksum-sha256: base64(SHA-256(body))
x-amz-content-sha256: hex(SHA-256(body))
x-amz-date: YYYYMMDDTHHMMSSZ
x-amz-security-token: {session token}
Authorization: AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...
```

- The request goes to the endpoint of Amazon S3 in the region of the store, and the bucket is the
  first part of the path: the connections of a node to that one host carry the writes of every
  bucket of the store. TLS ends inside the node, and the certificate of the host is verified against
  the trust roots of the node binary at node time. The request is signed with AWS Signature Version
  4 over the method, the path, every header above and `Host`, and the hash of the body, with
  credentials that the operator domain gives the node (enclave.md 5.14). In the path, every byte of
  the key outside the unreserved characters of RFC 3986 is percent-encoded, and `/` is not: a
  `user_id` is written into the key as it is. The store reads the path as it was sent: the first
  part is the bucket and the rest is the key, byte for byte, so a `user_id` that holds `..` or `/`
  moves no object to another bucket and to no other key. The key of an entry of one account never
  has the shape of a key of another account: the 13 digits of `rtime` follow the prefix of the
  account at once, and a reader checks the shape of a key and the `user_id` of the body (7.4).
- The node keeps up to 32 idle HTTP/1.1 connections to the store and sends the first attempt of a
  write over the most recently used one. An attempt the store does not confirm because the
  connection failed, the connection closed without a response, the attempt passed its time limit, or
  the status was 5xx or 429 is repeated over a new connection, with a full jitter backoff between
  the attempts, within a budget of twice the time limit of a write per entry; a 4xx status other
  than 429 is not repeated (enclave.md 5.14). A `PUT` is idempotent, and a repeated attempt adds a
  version of the same object with the same body. A connection carries one write at a time.
- The one confirmation of a write is the status 200 of that request. Every other status, a failure
  of the connection and a write that takes longer than its time limit are no confirmation. A bucket
  without Object Lock refuses a request with these headers, so a node whose buckets are not locked
  confirms nothing.
- The request names the encryption of the object itself, and a header of the request comes before
  the default encryption of the bucket. So a bucket whose default names a key of the key management
  service does not put that key on an entry: no key that someone can disable or delete stands
  between a reader and an entry. A bucket whose policy refuses a request with this header confirms
  nothing.
- The request states no condition on the key (it carries no `If-None-Match`), and a node does not
  take the answer "an object of this key exists" for a confirmation. The operator domain holds the
  credentials the node writes with and can write to the same buckets under any key. An object that
  someone else wrote under a key can have another body or no retention. So a write that is repeated
  (the answer of the first one was lost) adds a second version of the same object. A reader of the
  store takes a key for an entry of a node when one version of the object is an entry that verifies
  against the key (7.4).

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
| The command grant that puts a user key into the node (step 14 of 5.3) | `grant_accepted` | The user key is put into the memory of the node | The signed reply has `ok` false and the code `log_store_unavailable`. The node holds no key |
| The command grant that renews the grant in force (step 13a of 5.3) | None | None: the node holds the same key before and after, and the entry `grant_accepted` of that key is in the store | |
| The command revoke | `grant_revoked` | None. The user key is erased whatever the store answers | The reply is that of a revoke that succeeded. The entry is a pending entry |
| `peer/export` to a node of a later release (10.3) | `grant_transferred_out`, one per account | The grant of that account enters the transfer | `log_store_unavailable` for the whole call, also when the store confirmed the entries of other accounts: no grant is handed over. The next call for the same receiving node creates no entry for these accounts: it writes the entries that wait again |
| `peer/export` to a node of the measurement of this node (10.1) | None | None: the user key moves between two nodes of one program, and each of the two has its node document in the store (7.7) | |
| `peer/import` of a transfer from a node of an earlier release (10.3) | `grant_transferred_in`, one per account | None. The grant is put in place first; the call then writes the entries it created in one round, when the node has credentials for its log store | The grant stays in place and the entry is a pending entry: the next write of the account takes it along. The call succeeds all the same |
| `peer/import` of a transfer from a node of the measurement of this node (10.1) | None | None | |

- A pending entry is an entry that the store has not confirmed and that no call is writing. It stays
  in the memory of the node. The next write of the same account takes the pending entries of that
  account along, at the same time as its own entry, and a request that merges into an event of a
  pending entry waits for that write. The sweep of the node (a task that runs every 30 seconds,
  `SWEEP_INTERVAL`) writes the pending entries of every account again as well, so the entry of an
  account that makes no further call reaches the store as soon as the store takes it. A pending
  entry that the store refuses again does not fail that call: the condition of an act is the
  confirmation of the entry of that act. An account whose pending entries reached 64 gets no further
  entry from a call that uses a credential (enclave.md 5.14). A pending entry is gone with its node:
  a node that ends, with or without its orderly shutdown, leaves in the store what the store
  confirmed and nothing else.
- What a missing object means. An object version of the log store cannot be deleted before its
  retention ends. So for an entry that is not in the store, the act that entry describes did not
  take place: the node did not call the provider, did not hand the value out, did not take the user
  key, did not hand the grant to a later release. This holds for an entry the store never confirmed,
  whose `seq` no key of the store carries, and for whatever a node held in memory when it ended. The
  two exceptions are the rows without an act that waits: a revoke erased the key, and an import from
  an earlier release put the grant in place (the giving node's `grant_transferred_out` of that grant
  is in the store). The store can hold more entries than there were acts, and not fewer: an entry
  whose act failed afterwards or never started (the provider refused, the call ended, the store
  confirmed and the answer was lost) is in the store like any other.
- A node of platform `nitro` does not act without a log store: while it has no log store in its
  configuration, no credentials within their time, or no node document in the store that outlives an
  entry written now (7.7), it refuses every act of the table with `log_store_unavailable`, before it
  creates an entry. A revoke is taken in every case, and a transfer is taken while the store holds
  the node document of the node: their entries are pending entries. A node of platform `local`
  without a log store in its configuration works without one. With one, it follows the rules of this
  section.
- The operator domain carries the bytes between a node and the log store and can stop them. A node
  then uses no credential: the calls of the table end with `log_store_unavailable`.

### 7.7 The node document

A node writes its own attestation document to its log store. With it a reader of the store
verifies, for an entry, in which program the signing key of the entry was created, without asking
the node and without a record of the operator domain: the node can be gone.

```text
key   n3/{node}                    in the bucket of the node (7.6)
body  UTF-8(JSON {"v":1,"platform":"nitro","document":b64u(the document of the platform),"node":"...","release":"v2.4.0"})
```

- The object has the keys of an attestation response (4.2) without the challenge. On platform
  `nitro`, `document` is an AWS Nitro attestation document whose `user_data` is the binding of the
  node (4.1, with its `log`) and whose `nonce` is `SHA-256("pickle.secure.v3.node-document\n" || the
  32 bytes of the node signing public key)`. No requester chose that nonce: a reader computes it
  from the node identifier, and a document with this nonce is one the node made for its node
  document. On platform `local`, `document` is the local document of 4.2 with that nonce.
- The write is the request of 7.6 with the key and the bucket above and a retention of 400 days from
  the node time of the write. The object holds public values only: the binding and the measurement
  of the node.
- When a node writes it. A node writes its node document once it has a log store and credentials for
  it: in the call that completes the two (`config` or `log-store/credentials`, enclave.md 5.1 and
  5.14), and in its sweep when that write was not confirmed. It writes the document again, under the
  same key, when the latest write the store confirmed is 30 days old: every write makes a new
  document of the platform and adds a version of the object.
- No user key and no entry without it. A node whose log store confirmed no write of its node
  document in the last 31 days takes no grant command and no transfer, and writes no entry
  (`log_store_unavailable`: step 11a of 5.3, step 1a of the receiving node of 10.1, and the rule of
  7.6 for a node of platform `nitro`). So the store holds, for every entry, a version of the
  document of its node whose retention ends after the retention of the entry: the entry was written
  at most 31 days after that version, and 31 + 365 days are less than 400.
- What a reader verifies. The object parses, its `node` is the node of the key, and on platform
  `nitro` its `document` passes steps 1 to 5 of 4.3 against the trust root, with the `timestamp` of
  the document as the time of the certificate chain (what the document proves, that the signing key
  was created inside an enclave of that measurement, does not change with time). In the place of
  step 6, the `nonce` of the document is the value above. The `user_data` is a binding (step 8)
  whose signing public key is the key the node identifier is and whose `release` is the `release` of
  the object. The reader then judges, as for an attestation response: the measurement (step 7: one
  of its list, never a PCR that is all zero) and the log store of the binding (step 10: the name it
  expects).
- A node document of platform `local` proves nothing, like a local attestation document: a reader
  takes it where it takes a node of platform `local` (4.4) and nowhere else.
- A node of a release before v2.4.0 wrote no node document. A reader verifies the entries of such a
  node by the rules of the two earlier formats (7.4).

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
| 4a | (A transfer with an endorsement, 10.3) The node can write to its log store (7.6, 7.7). A node of platform `local` without a log store passes. A transfer to a node of the measurement of this node writes nothing and passes this step in every case | `log_store_unavailable` |
| 5 | The node selects the accounts that have a grant within its time, in the lexical order of `user_id`, one page at a time (at most 1,000 accounts). A transfer to a node of the measurement of this node creates no entry: every selected grant goes on to step 5b. A transfer with an endorsement (10.3) has entries: an account whose grant was handed to 64 other nodes of a later release is skipped (see below), and for every selected account, inside the lock of that account, the node creates the log entry `grant_transferred_out` when it hands that grant to the receiving node for the first time. The entry names the receiving node, its release and its measurement (7.2) | |
| 5a | (With an endorsement) The node writes the entries to the log store: the entries of step 5, and the entry of an earlier call for the same receiving node that the store has not confirmed. It goes on only when the store confirmed the entry of every selected account | `log_store_unavailable` |
| 5b | For every selected account, inside the lock of that account again, the node puts the grant into the transfer when the account still has a grant within its time and, with an endorsement, that grant is the one whose entry for this receiving node the store confirmed. An account that revoked in between is left out, and so is, with an endorsement, an account whose grant was replaced in between | |
| 6 | The node signs the transfer, seals it to the sealing public key of the receiving node and returns it. The entries that step 5 created are named in the same response | |

- The nonce and the age of the document of the receiving node are not looked at. The document
  proves that the private key of that sealing public key was created inside an enclave of that
  measurement, and that fact does not change with time. A transfer made for the old document of a
  node that is gone can be opened by no private key.
- A transfer between two nodes of one measurement has no entry. The two nodes run one program: the
  account accepted that program when it delegated, the user key is under the same rules before and
  after, and every act with it has its entry under the prefix of the account whichever of the two
  nodes performs it (7.4). What a reader needs of the receiving node is its node document, which
  that node wrote before it took the key (7.7). So the nodes that are alive fill a node that
  restarted without a write to the log store, also while the log store cannot be written.
- The entries of a transfer to a later release are not stopped by the limit of entries without a
  storage acknowledgement (64), like the entries of a command.
- There is one entry per grant and receiving node of a later release. A node keeps, with every grant
  in its memory, the list of the nodes of a later release it handed that grant to. The first
  transfer of a grant to such a node creates the entry `grant_transferred_out` and puts that node on
  the list. A repeated transfer of the same grant to a node of the list carries the grant again and
  creates no entry: a transfer whose envelope was lost on its way is made again, and the entry that
  names the receiving node exists already. A node is put on the list when the entry is created, also
  when the log store does not confirm that entry: the repeated call writes that entry again and
  hands the grant over once the store confirmed it. The list holds at most 64 nodes. A grant whose
  list is full is handed to no further node of a later release: its account is skipped, without an
  entry. So a carrier that repeats the call adds at most 64 entries per grant.
- The list belongs to the grant state in the memory of the node. A grant command that puts a grant
  in place (step 14 of 5.3), a revoke, the end of the grant and a transfer that puts a grant in
  place on this node (step 3 of the receiving node) create a new state, and the list of a new grant
  is empty. A renewal (step 13a of 5.3) keeps the grant and its list.

The rules of the receiving node (`peer/import`. The input is the attestation response of the
giving node and the envelope):

| Step | Rule | Failure code |
| --- | --- | --- |
| 1 | The node verifies the attestation response of the giving node by the rules of steps 1 to 3a above. In step 3 the measurement of the giving node is that of this node or that of a predecessor of this node (10.3) | `peer_unverified` |
| 1a | The log store of this node holds its node document, with a retention that outlives an entry written now (7.7). A node of platform `local` without a log store passes. The node needs no credentials for its log store here | `log_store_unavailable` |
| 2 | The `to` of the envelope is the `node` of this node and its `from` is the giving node of step 1. The node opens the envelope with its sealing private key and verifies the signature with the signing public key of the giving node. `from` and `to` of the payload equal those of the envelope | `wrong_node`, `open_failed`, `bad_signature` |
| 3 | For every grant: only a grant whose `custody` is the custody of the platform of this node and whose `not_after_ms > now` is looked at. A grant of an account whose revoke command this node accepted before is skipped (see below). When the account has no grant within its time, the node puts the grant into its memory. For a grant from a node of an earlier release (10.3) it creates the log entry `grant_transferred_in`, which names the giving node and its release (7.2); a grant from a node of the measurement of this node is put in place without an entry. When the account has a grant of the same `sign_pk` within its time, the larger `not_after_ms` stays (no entry). When the account has a grant of another `sign_pk`, the grant of the transfer is skipped | |

- The receiving node shortens the `not_after_ms` of a grant it takes to the limit of 5.2
  (`now + 30 days`).
- The receiving node of a transfer from an earlier release puts the grants in place first and then
  writes the entries `grant_transferred_in` it created (7.6). An entry the store does not confirm is
  a pending entry, and the next write of the account on that node takes it along. What says where a
  grant went is the `grant_transferred_out` of the giving node, which the store confirmed before the
  transfer was made.
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
- A reader of format 3 traces no transfer: the entries of every node that used the key of an account
  are under the prefix of that account (7.4), and a transfer to a later release is on the log with
  the measurement of the receiving node. For the chains of the releases before v2.4.0 the app reads
  `grant_transferred_out` on the chain of the giving node, learns the receiving node from its `to`
  and verifies the chain of that node with that value, the signing public key of the receiving node
  (7.4, "Formats 1 and 2").
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

Witnessing is defined for the chain of format 2 and no release implements it (7.5). The envelope
and the signature are those of 10.1. `challenge` is the value that the attestation response of the
receiving node gave (it prevents a replay). The response is the `witness` of 7.5. A
witness node accepts only a `seq` that is larger than the last `seq` it holds for that
(node, account) pair.

### 10.3 The delegation transfer to a later release

Purpose: the delegations of the accounts stay when the operator replaces the nodes of one release
with the nodes of a later release. A giving node hands delegations to a node of a later release
when the release key of the operator signed the measurements of that release and the public
transparency log Rekor (rekor.sigstore.dev) recorded that signature. A receiving node takes
delegations from a node of a release that its own program lists as a predecessor. The payload and
the envelope are those of 10.1. Such a transfer is on the log of the account: the giving node
creates the entry `grant_transferred_out` of every grant and hands the grant over after the log
store confirmed that entry (steps 4a to 5b of 10.1), and the receiving node creates the entry
`grant_transferred_in` (step 3 of the receiving node). This section states which node of another
release a node accepts.

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
- The account sees the transfer on its log: the entry `grant_transferred_out` of the giving node
  names the receiving node, its release and its measurement (7.2). So a reader learns from its own
  log which program received its key, and whether that is a program it accepts (7.4). The
  measurement on the entry is the one the giving node verified: the values of the statement the
  release key signed, which the attestation document of the receiving node states (check 7). A
  giving node of a release before v2.4.0 names the receiving node only.

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
| `too_large` | A body above the limit (64 MiB each for a request and a response; for `forward/batch`, the bodies of the results together). An event that no entry can hold (7.1) |
| `log_store_unavailable` | The log store did not confirm the entry of the call, or the node cannot write to it: it has no log store in its configuration, no credentials within their time, or no node document in the store (7.6, 7.7). The act of the call did not take place. A repeated call can succeed |
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
| Longest time a node keeps receiving the response of a token address call of `refresh` after the time limit of the call, counted from the start of the call (`TOKEN_LATE_LIMIT`, enclave.md 5.7) | 120 seconds |
| Token address calls of `refresh` a node continues after their time limit at once (`REFRESH_LATE_TASKS`) | 128 |
| Most accounts in one delegation transfer | 1,000 |
| Most nodes of a later release that a node hands one grant to (10.1) | 64 |
| Nodes a delegation subset names (`pods`, 10.4) | 1 to 1,024 |
| Nodes per account of a delegation subset (`copies`, 10.4) | 1 to `pods` (a larger value names every node) |
| Most pruned accounts in one page of `grants/prune` (10.4, enclave.md 5.15) | 1,000 |
| Most accounts one `grants/prune` call looks at (`SCAN_LIMIT`) | 10,000 |
| Longest release statement (10.3) | 16,384 bytes |
| Notice period of a release (10.3) | 0 seconds |
| Longest time by which a log entry lies after the time of the node (10.3) | 300 seconds |
| Most events in one entry (`ENTRY_EVENTS`) | 128 |
| Most bytes of the plaintext of one entry (`ENTRY_PLAINTEXT_BYTES`) | 1,048,576 |
| Events of GET requests without a body that a node remembers for one account at one time (`MERGE_KEYS`, 7.2) | 8,192 |
| Most requests in one forward batch (`FORWARD_BATCH_REQUESTS`) | 100 |
| Requests of one forward batch in flight at once (`FORWARD_BATCH_CONCURRENCY`) | 6 |
| Provider requests of a node in flight at once (`PROVIDER_INFLIGHT`) | 512 |
| Idle connections of a node to its log store (`LOG_STORE_IDLE_CONNECTIONS`) | 32 |
| Idle connections of a node to one provider host for one account, and their idle time (`PROVIDER_IDLE_CONNECTIONS`, `PROVIDER_IDLE_MS`) | 8, 30 seconds |
| Pending entries of an account at which a call that uses a credential creates no entry (`PENDING_ENTRIES`) | 64 |
| Interval of the sweep of a node, which writes the pending entries of every account again (`SWEEP_INTERVAL`) | 30 seconds |
| Retention of an object of the log store (Object Lock), expiry of the bucket lifecycle (`LOG_RETENTION_DAYS`, `LOG_EXPIRY_DAYS`) | 365 days from the node time of the write, 400 days |
| Buckets of a log store, by the bucket name of the binding (7.6) | 1,024 for `character-credential-log-prod-1`, 4 for `character-credential-log-local-1`, 32 for every other name |
| Longest bucket name of a binding that a node takes as its log store (`LOG_STORE_NAME_CHARS`, 7.6) | 49 characters |
| Retention of a node document, the age of its latest confirmed write at which a node writes it again, and the age up to which a node takes a user key and writes an entry (`NODE_DOCUMENT_RETENTION_DAYS`, `NODE_DOCUMENT_RENEW_DAYS`, `NODE_DOCUMENT_VALID_DAYS`, 7.7) | 400 days, 30 days, 31 days |
| `LOG_VERIFY_KEYS` (the app) | 8,000: the keys one index verification run walks (a run that spends them is cut short, as a run that reaches its time budget: 7.4) |
| `LOG_VERIFY_BODIES` (the app) | 2,000: the entry bodies one run reads (a run that spends them is cut short, as above) |
| `LOG_VERIFY_TIME_MS`, `LOG_VERIFY_LEAST_STEPS` (the app) | 10,000 and 8: the time from the start of one index verification run after which the run stops walking (the chains not walked and the rest of the chain being walked stay pending at their verification points, and the next synchronization of the runtime walks on), once the run has made at least that many steps (keys walked or bodies read); a run cut short makes no mark unless `LOG_STORE_STALE_MS` has passed since the entry it would mark for was first verified (7.4) |
| `LOG_EXPIRES_DAYS` (the app) | 365: the age at which a reader treats the absence of an entry as expired, the retention of its lock (7.4) |
| `LOG_GAP_GRACE_MS` (the app) | 3,600,000: a gap whose first key after it is younger than this leaves the chain pending, not attention (7.4) |
| `LOG_SCREEN_EVENTS` (the app) | 50: the events of one further page of the log screen (the first page reads the events its definition asks for) |
| `LOG_SUMMARY_DAYS`, `LOG_SUMMARY_STEP`, `LOG_SUMMARY_ENTRIES` (the app) | 7, 100, 1,000: the days of the summary of the log screen (the reads, sends and changes of the events of the entries of that window, counted once per device from their bodies and kept on the device as the summary tally), the entries one read of the screen counts before answering and each later step counts, and the most entries of the window the tally counts (the screen shows the counts with a plus while entries of the window are not counted) |
| `LOG_STORE_STALE_MS` (the app) | 3 days: reads of the store that have been failing for this long mark the log (a node discovery listing beyond `LOG_STORE_PAGES` pages is a failing read); the first run that read the store (verified, or truncated by the node discovery window) clears the mark, pending at its walk or not. The same time bounds a node found in the store only that holds an entry sealed to the key of this account: once it has passed since the entry was first verified, a run cut short by one of its budgets (time, keys, bodies, or the listing pages of one chain) marks the node too (7.4) |
| `LOG_STORE_NODES` (the app) | 16: the nodes of the listing the list of nodes does not know that one verification run examines, beginning after the discovery cursor of the list of nodes (the node the last run examined last) and wrapping to the start of the listing; the nodes beyond them are examined by the next synchronizations, and a node under examination stays in the list of nodes with its verification point until its chain is walked to the head (7.4) |
| Listing pages one verification run reads per node (the app) | 8 pages of 1,000 keys |
| Object versions one verification run fetches at a time (the app) | 8 |
| `LOG_RUN_STALE_MS` (the app) | 600,000: a run whose judgement took longer than this is judged again on fresh reads (7.4) |
| `LOG_STORE_ATTEMPTS`, `LOG_STORE_RETRY_MS` (the app) | 3 attempts of one request to the store, pauses of 500 and 1,500 milliseconds between them: a transport failure, a 429 and a 5xx status are tried again |
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
| `log_v3` | Format 3: the node signing public key and `node`, `user_id`, `key_id`, `log_private`, `log_pk`, the HPKE info and the signature purpose as text, the two prefixes of the account, `entries` (four entries of one node: a control entry `grant_accepted`, a use entry with three `provider_request` events, a use entry with one `secret_released` event, a control entry `grant_transferred_out` to a later release; each with `seq`, `hpke_seed`, `time_ms`, `kind`, `count`, `events_text`, `entry`, `body_text`, `body_hash`, `key`), `control_listing` and `use_listing` (the keys of each prefix in the order of a listing), `verifies`, `rejected` (three objects that are not the entry of their key: the body of another entry, the signature of another node, a key of another `seq`; each with `key`, `entry` and `result`: `body`, `signature` or `fields`), `not_keys` (strings that are no keys of format 3 of the account) with `a_key_of_not_keys_parses` false, and `node_document` (the `key`, the `bucket`, the `nonce` and the text in front of the key in its hash, `binding_text`, `document_text` and `object_text` of a node document of platform `local`, `accepted`, and `rejected`: a document with another nonce, an object with another release, the object read as the document of another node) | Every key parses to the parts of its entry, every entry verifies against its key (7.4) and opens to `events_text`, an entry created with the same `hpke_seed` equals `entry`, the listings are in the order of the bytes of the keys (the latest entry first), the objects of `rejected` fail with their `result`, no string of `not_keys` is a key, and the node document reads as `accepted` says (7.7) |
| `log_store` | `stores` (five log stores by the bucket name of their binding: `bucket`, `region`, `host`, `shards`, `first_bucket`, `last_bucket`, and `owners`: for three `user_id` values and one node identifier the `hash`, the `index` and the `bucket`), `longest_name` (a bucket name of 49 characters and its first bucket), `name_without_buckets` (a bucket name of 50 characters: `first_bucket` is null) | The number of buckets, their names and the bucket of every owner follow from the bucket name of the binding by 7.6 |
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
