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
| 3 | The list of allowed measurements in a grant (4.5), the delegation transfer to a release of that list (10.1) |
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
| `release` | The name of the release of a node program: the name of the tag of this repository the program was built for (`v` followed by one or more of the characters `A` to `Z`, `a` to `z`, `0` to `9`, `.`, `_` and `-`, for example `v2.4.0` and `v2.4.0-rc.1`), or `dev` for a build without a tag. A node compares two release names for equality and for nothing else: no rule of a node orders releases by their names | Variable |

In the examples of this document, `v1.0.0` stands for the release of the node.

## 2. Algorithms

| Use | Algorithm | Note |
| --- | --- | --- |
| Key derivation | HKDF-SHA256 (RFC 5869) | A derivation that names no salt uses the empty salt (length 0) |
| Account signature, node signature | Ed25519 | The private key is represented by its 32-byte seed |
| Public key sealing | HPKE base mode (RFC 9180), KEM DHKEM(X25519, HKDF-SHA256), KDF HKDF-SHA256, AEAD ChaCha20-Poly1305, single-shot seal | The output is `enc` (32 bytes) and `ct` (the ciphertext followed by the 16-byte tag) |
| Record encryption | ChaCha20-Poly1305 (RFC 8439), a random nonce of 12 bytes | The output `ct` is the ciphertext followed by the 16-byte tag |
| Chain | SHA-256 | |
| TOTP | RFC 6238, HMAC-SHA1, 6 digits, 30 seconds | Only a node computes it |
| Signature of the envelope of the attestation of a release statement, signed entry timestamp and checkpoint signature of the transparency log (section 9) | ECDSA P-256 with SHA-256, the signature in ASN.1 DER | The key of the envelope is the key of the certificate of the attestation. The key of the log is compiled into the node program |
| Signature of a certificate of the attestation of a release statement by its issuer (section 9) | ECDSA with SHA-256 or SHA-384 under a key on P-256 or P-384, the signature in ASN.1 DER | The two certificates of the certificate authority are compiled into the node program |
| Inclusion proof of the entry of the transparency log (section 9) | The Merkle tree of RFC 6962 section 2.1 with SHA-256 | |
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
  under the conditions of section 10: a node of the same measurement (10.1), or a node of another
  release under the rules of 10.3. There is no other holder.
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
| `pickle.secure.v3.secret-use`, `pickle.secure.v3.secret-use\n` | HPKE info and signature purpose of the envelope of one use of a vault secret (10.5) |
| `pickle.secure.v3.release` | HPKE info of a vault value that `release` seals to a key its caller named (section 6) |

## 4. Attestation

### 4.1 The binding document

A node binds its two public keys to the attestation of its platform.

```text
binding = UTF-8(JSON {"v":1,"sign":b64u(node signing public key),"seal":b64u(node sealing public key),"release":"v1.0.0",
                      "log":{"bucket":"...","region":"..."}})
```

- `binding` is at most 512 bytes long.
- `role` names the role of a node, and a binding states it by its value. A node of the delegation
  role holds the delegations of accounts and uses their credentials, and its binding has no
  `role` key. The value `reserve` names the reserve role. A node of that role holds delegations
  as well: it takes the commands of the apps (section 5) and gives and takes delegation transfers
  (10.1). It uses no credential: it answers no call that opens or creates a record or calls a
  provider (enclave.md section 4), so the entries it writes are control entries (7.1), and it
  connects to its log store alone. Its binding carries the key behind its `log`:

  ```text
  binding = UTF-8(JSON {"v":1,"sign":b64u(node signing public key),"seal":b64u(node sealing public key),"release":"v1.0.0",
                        "log":{"bucket":"...","region":"..."},"role":"reserve"})
  ```

  The value `forward` names the forward
  role (enclave.md section 4): such a node holds no delegation, opens no record, writes no log entry
  and has no node document (7.7). It sends the one request of a use of a vault secret that a node of
  the delegation role sealed to it (10.5). Its binding is the two keys and the release with
  `"role":"forward"` behind them, and it has no `log` key:

  ```text
  binding = UTF-8(JSON {"v":1,"sign":b64u(node signing public key),"seal":b64u(node sealing public key),"release":"v1.0.0","role":"forward"})
  ```

  A `role` of any other value names no role: a document with such a binding is no binding, and
  so is one with the role `forward` and a `log`. A node takes its role once and does not change
  it, so the `role` of a binding a verifier read holds for as long as that node lives. A binding
  without the key is that of a node of the delegation role, or of a node that has taken no role
  yet and can still take each of the three (enclave.md section 4). Whatever role such a node
  takes, a user key that is handed to it afterwards is in a node that holds delegations: a node
  of the forward role answers neither the grant command nor the delegation transfer. Whoever
  hands a user key to a node reads the role by its value: an app before it sends the command
  grant (5.3), and a node before it seals a delegation transfer (10.1), hand a user key to a
  node whose binding has no `role` key or the `role` `reserve`, and to no node whose binding
  has the `role` `forward` or a value this section does not define. A node of the delegation
  role seals a use of a vault secret to a node whose binding has the `role` `forward`, and to
  no other node (10.5).
- `log` names the log store of the node (7.6): a bucket name and its region. The buckets a node
  writes to follow from that name by a rule of the node program (7.6), so the name fixes them. A
  node that has no log store writes no `log` key: the binding of such a node of the delegation role
  ends with `release`. A node takes a log store once and does not change it (enclave.md 5.1), so the
  `log` of a binding a verifier read holds for as long as that node lives.
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

A response may carry one more member, `release_proofs`: the release proofs of the release of the
node ("The release proofs" in "The program of the app"). It is a public value outside the
document, which the app verifies by its own checks whoever put it there. The app asks for it with
the query `proofs=1` of the request for the attestation. The same value may stand in a node
document (7.7), and the backend hands it out for the digest of a measurement.

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
that an attestation call made. For a node, the allowed measurements are its own PCR0, PCR1 and
PCR2 and the ones that 10.3 adds for a delegation transfer (4.5).

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

A measurement no list has (the app). A document that passes every step but step 7, with no PCR all
zero, is the document of a node whose measurement no list of the program of the app holds (4.5: the
lists are constants of the signed program, and no release is added to them). The app applies step
10 to such a document as well (a node of this deployment writes to the log store of the
environment). When release proofs show the measurement of the document to the program ("The
release proofs" in "The program of the app": the public build proof of section 9, the attestation
the job of the build workflow of this repository made of the measurements of a release in a run
the push of the tag of that release started, recorded in the public transparency log), the release
is an accepted one for that program, as an element of its lists is. Without such proofs the app
hands the node no key, and does not count the document as a failed verification: the node is one
of a measurement the program does not accept ("The nodes that receive a grant" in "The program of
the app"), and a round judges what the log says of the key of the account on such a measurement
("The round", A1). A document that fails another step, a PCR all zero, and a binding that names
another log store are failed verifications.

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
| 1, 2 | The lists inside the signed program of the app (`[{release, pcr0, pcr1, pcr2}]`, each PCR as 96 lower-case hexadecimal characters: the releases before v2.4.0 and the builds before the first release), which are closed, and the measurements whose public build proof the program verified on the device (section 9, and "The release proofs" in "The program of the app"). A release from v2.4.0 on reaches an app with its release proofs: no release is added to the lists, and no program is signed again for a release. A document that verifies with a measurement no list has and no proofs showed is the document of a measurement the program does not accept: its node receives no key ("The nodes that receive a grant") | Its own measurement. A giving node also accepts a measurement whose public build proof the call carries (section 9), and a receiving node also accepts such a measurement and the measurements of the list of old releases inside its program (10.3) |
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
| `vault_password` | `vault` | The app, and a node (`vault/store` with `kind` `vault_password`: the operator domain gave the value) | release: `release` hands the value out | `{"value":"..."}` of the app, `{"value":"...","source":"operator"}` of a node |
| `vault_totp` | `vault` | The app | enclave-use: the seed does not leave. `release` hands out only the code that the node computed | `{"value":"<base32 seed>"}` |
| `vault_card` | `vault` | The app | release | `{"number":"...","cvc":"..."}` |
| `vault_secret` | `vault` | The app, and a node (`vault/store`: the operator domain gave the value) | By the slots of the record. A record whose slot is `field`: release, `release` hands the value out for an origin of its sites. A record with slots of a request: enclave-use, `vault/handoff` seals the value to a node of the forward role for one request to a site of the record (10.5), and no call hands the plaintext out | `{"value":"...","name":"...","sites":[...],"slots":[...],"source":"...","pad":"..."}` (below) |

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
- The longest record. The plaintext of a record a node opens or creates is at most 65,536
  bytes, so its `ct` (the plaintext and the tag of 16 bytes in b64u) is at most 87,403
  characters. A record with a longer `ct` is `record_invalid` in every call that carries a
  record, before the node opens it and before an entry is created: the length of a ciphertext
  says nothing of what it holds, so this judgement needs no key. The records of the vault are
  shorter by their own rule (a plaintext of at most 12,272 bytes).
- When the opened record has a `kind` that the call does not take, the call fails with
  `not_allowed` (enclave.md section 5 names the kinds of every call). A kind that the release does
  not know is `not_allowed` too. When the plaintext is not a JSON object, or the plaintext lacks
  the field that the call uses, the call fails with `record_invalid`.
- The bounds of a token object. The plaintext of a record of kind `oauth` or `oauth_imported`
  holds a token object, and a node reads one within two bounds. It handles no token of more
  than 16,384 bytes: the strings at `access_token`, `refresh_token` and `id_token` of the
  token object (at its top level and in the token place of the provider), and the string a
  provider definition injects as the credential. A token travels in the value of a request
  header, and a header value of that length is above what servers commonly take. And it
  parses no plaintext whose parsed
  form would take more than 262,144 bytes of memory, by a count it makes of the text before
  it parses it: the bytes of the text and a quarter, 512 bytes for each array and object, 448
  bytes for each comma outside a string, and 1,024 bytes (a text of 65,536 bytes may hold 350
  arrays and objects or 400 further elements; the token objects of the defined providers hold
  some thirty values). A node makes no copy of a longer token and does not parse such a
  plaintext. Whether a record is above these bounds depends on the content of its plaintext,
  so a call that creates an entry makes the judgement behind that entry: it creates the event
  of its act, waits until the log store confirmed the entry, and ends with `record_invalid`
  without the act (`forward`, `forward/batch` and `refresh` send nothing, enclave.md 5.7 and
  5.8). `revoke-token` sends no token of such a record, and its entry says so. `oauth/merge`,
  which creates no entry, refuses such a record with `record_invalid`. A node creates no
  record above these bounds: a token response it would not read again from a record is not
  taken (section 8).
- A secret value of the vault is one record per secret field (a password and a TOTP seed are two
  records). A save that changes one of them does not touch the record of the other.

**The plaintext of a record of kind `vault_secret`.** The record holds a value under a name,
where that value may go, and which side made the record:

```text
{"value":"sk-...","name":"OPENAI_API_KEY","sites":["api.openai.com"],"slots":["header:authorization"],"source":"device","pad":"...."}
```

`sites` and `slots` together are the reach of the record: the hosts and the places its value may
go to. They are part of the plaintext, so whoever cannot encrypt under the user key cannot change
them. A node reads the keys of this table and passes over every other key of the plaintext.

| Key | Form |
| --- | --- |
| `value` | A string. A node hands out or uses the whole of it |
| `name` | `[A-Z][A-Z0-9_]{0,63}`: an ASCII capital letter, then at most 63 ASCII capital letters, digits and `_` |
| `sites` | The string `"any"` (every host), or a list of 1 to 8 hosts, each named once. A host is a DNS name in lower case: two labels or more joined by `.`, each label 1 to 63 characters of `[a-z0-9-]` that neither begins nor ends with `-`, at most 253 bytes in all, and the last label begins with a letter. A scheme, a port, a path, a dot at the end, a capital letter and a character outside ASCII make a string no host: a reader does not repair it |
| `slots` | A list of 1 to 4 slots, each named once: the one slot `field`, or slots of a request (the table below). No record lists `field` beside a slot of a request, and a record whose `sites` is `"any"` lists `field` |
| `source` | `device` for a record the device of the account made of a value its user entered, `operator` for a record a node made of a value the operator domain gave it (`vault/store`). A record without this key, and one with another value, does not open as a record of this kind |
| `pad` | Only in a record of a device: a string of the character `.`, as long as it takes to make the UTF-8 length of the whole plaintext the smallest of 256, 512, 1,024, 2,048, 4,096, 8,192 and 12,272 bytes the plaintext fits. So the length of a record tells one of seven steps and not the length of its value. A node does not read this key |

| Slot | The place of the value |
| --- | --- |
| `field` | An input field of a web page, typed there by whoever fills the page. `release` hands the value out |
| `header:<name>` | Inside the value of the request header `<name>`. The name is 1 to 64 characters of `[a-z0-9-]`, and it is none of the headers a node of the forward role drops or refuses (10.5) |
| `query:<name>` | The whole value of a query parameter `<name>`. The name is 1 to 64 of the characters a query writes without a percent escape: ASCII letters, digits, `-`, `.`, `_` and `~` |
| `form:<name>` | The whole value of a field `<name>` of a body of the type `application/x-www-form-urlencoded`. The name has the form of the name of `query` |
| `json:<name>` | A string member of a JSON body. The name is the keys of the objects on the way to the member joined by `.` (`auth.token` is the member `token` of the member `auth` of the top-level object): no key is empty, no key holds a control character or a space character, and the name is at most 64 bytes of UTF-8 |
| `path` | Inside the path of the request |
| `basic:user`, `basic:password` | The whole user-id, or the whole password, of the credentials of HTTP Basic in the `Authorization` header (RFC 7617) |

A host covers what its slot says. For a slot of a request it is that host alone: a value stored
for `api.openai.com` goes into no request to `files.openai.com`. For the slot `field` it is that
host and every host below it: `release` hands the value of a record whose `sites` hold
`shop.example` out for the origin `https://pay.shop.example`, and not for
`https://notshop.example`.

**A value `release` hands out sealed.** A `release` call may carry `seal_to`, the b64u of an
X25519 public key its caller made for that one call. The node then answers with `sealed` in the
place of `value`:

```text
sealed = {"enc": b64u(32 bytes), "ct": b64u}
enc, ct = single-shot HPKE (section 2) to the key seal_to,
          info = UTF-8("pickle.secure.v3.release"),
          aad  = UTF-8(user_id + "\n" + record id + "\n" + field + "\n" + origin),
          plaintext = the UTF-8 bytes of the value the call hands out
```

The seal changes where the value is in the clear on its way: whoever carries the response between
the node and the holder of the private key carries a ciphertext. It does not change who can read
the value: the caller chose the key, the caller is the operator domain, and a sealed value is a
released value with the log entry of a release. A call without `seal_to` gets the value as it is.

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
  node took the user key by a grant command or from a node of another release, and it can be a
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
- The entry and the act. `forward`, `forward/batch`, `refresh`, `revoke-token`, `release`,
  `vault/handoff`, the command grant that puts a user key into the node, the command revoke, and
  `peer/export` to a node of another release create their event before the act: the node creates the
  event, and the entry that holds it, and after that it calls the provider, hands the value out,
  seals the value of a vault secret for its one request (10.5), changes the delegation or seals the
  user key to the peer. `peer/import` of a transfer from another release creates its entry before
  it puts a grant in place, and writes it after (7.6). `oauth/complete` receives the token response
  of the provider first and creates the entry `connection_created` before the record leaves the
  node: no part of an accepted token response leaves the node before that entry exists, and when a
  step after the response fails, the tokens are dropped inside the node and nothing of them leaves.
  `vault/store` makes a record of the value its caller gave and creates the entry
  `connection_created` of that record before the record leaves the node. `oauth/merge` calls no
  provider and creates no event.
- The entry and the log store. A node that has a log store writes the entry to it between the
  creation of the entry and the act, and acts only after the store confirmed the entry. 7.6 names
  the act of every call and the two calls that do not wait.
- The cases that share an event or create none are named where they are described: identical GET
  requests (7.2), a repeated `refresh` of the same record and a `refresh` of a record without a
  refresh token (enclave.md 5.7), a revoke of an account without a grant (5.4), a grant command that
  renews the grant in force (5.3), a transfer between two nodes of one measurement, a repeated
  transfer of a grant to the same node of another release, a transfer that a node takes for an
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
| `connection_created` | `time_ms`, `record_id`, `provider`, `scope` (the scope string among the public fields of enclave.md 6.4: the `scope` of the token place, else the top-level `scope`, when the provider definition lists it. Otherwise the empty string). The event of `vault/store` has the provider `vault`, the empty `scope`, and behind them `kind` (`vault_secret` or `vault_password`), `name` (the name of a `vault_secret`) or `site` (the host the call stated for the login of a `vault_password`), and `context` | `oauth/complete`, `vault/store` |
| `credential_refreshed` | `time_ms`, `record_id`, `provider`. It records a refresh call (the event is created before the call, so a refresh that the provider refused is on the log as well) | `refresh` |
| `connection_removed` | `time_ms`, `record_id`, `provider`, `provider_revoke` (bool: whether the node calls the revocation address of the provider after this event. It is true when the definition has a revocation address and the plaintext of the record has a token. The event is created before the call, so it does not carry the outcome of the call) | `revoke-token` |
| `provider_request` | `time_ms`, `record_id`, `provider`, `method`, `host`, `path`, `query`, `body_bytes`, `body_sha256` (b64u, the empty string when there is no body), `context`, `window_s` (300, only on an event that a later identical request can share). The event of `vault/handoff` has the provider `vault`, no `window_s`, and behind `context` the keys `name` (the name of the record), `slot` (the place of the value in the request) and `to` (the `node` of the node of the forward role the value was sealed to). Its `path` and its `query` hold the placeholder where the value goes, and its `body_sha256` is that of the body with the placeholder in it: no part of the value is in the event | `forward`, `forward/batch` (one per request), `vault/handoff` |
| `mail_request` | `time_ms`, `record_id`, `provider`, `operation`, `request`, `body_bytes`, `body_sha256`, `context` (the mail call surface at the end of this document) | `mail/verify`, `mail/read`, `mail/submit` |
| `secret_released` | `time_ms`, `record_id`, `kind`, `field`, `origin`, `context`, and for a record of kind `vault_secret` the `name` of the record behind them | `release` |
| `totp_issued` | `time_ms`, `record_id`, `origin`, `context` | `release` |
| `grant_transferred_out` | `time_ms`, `to` (the `node` of the receiving node), `release` (the release of the receiving node), `pcr0`, `pcr1`, `pcr2` (the measurement of the receiving node, 96 lower-case hexadecimal characters each: the values of the release statement whose public build proof the giving node verified, which the attestation document of the receiving node states, 10.3) | `peer/export` to a node of another release (10.3). A transfer to a node of the measurement of the giving node creates no event (10.1) |
| `grant_transferred_in` | `time_ms`, `from` (the `node` of the giving node), `release` (the release of the giving node, as its binding names it), `not_after_ms`, `custody` | `peer/import` of a transfer from a node of another release (10.3). A transfer from a node of the measurement of the receiving node creates no event (10.1) |

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
  request shares it. A GET request with a body, a request of another method, the release of a
  vault value (`release`) and the use of a vault secret in a request (`vault/handoff`)
  are not merged: each has its own event.
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
- The node keeps up to 32 idle HTTP/1.1 connections to the store, each for at most 30 seconds,
  and sends the first attempt of a write over the most recently used one. A connection whose 30
  seconds passed carries no write, and the node closes it at its next sweep at the latest
  (enclave.md 5.14). An attempt the store does not confirm because the
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
| `release` | `secret_released`, `totp_issued` | The value in the response, as it is or under the seal of the key the call named (section 6). The node reads the plaintext of the record for the value only after the confirmation: a plaintext that does not hold the value, and a seed that is not base32, end the call with `record_invalid` then, and the entry stays (enclave.md 5.9) | `log_store_unavailable`. The value does not leave, and the plaintext is not read for it |
| `vault/store` | `connection_created` | The record in the response (enclave.md 5.9b) | `log_store_unavailable`. The record does not leave and is dropped inside the node, the value with it |
| `vault/handoff` | `provider_request` | The envelope in the response: the node reads the plaintext of the record for the value and seals it, with the one request it is for, to the node of the forward role only after the confirmation (10.5). A value no envelope carries ends the call with `record_invalid` then, and the entry stays (enclave.md 5.9c) | `log_store_unavailable`. No envelope leaves, so no request is sent |
| `oauth/complete` | `connection_created` | The record in the response (the code is exchanged before the entry is created, 7.1) | `log_store_unavailable`. The record does not leave and the tokens are dropped inside the node: the connection is started again |
| The command grant that puts a user key into the node (step 14 of 5.3) | `grant_accepted` | The user key is put into the memory of the node | The signed reply has `ok` false and the code `log_store_unavailable`. The node holds no key |
| The command grant that renews the grant in force (step 13a of 5.3) | None | None: the node holds the same key before and after, and the entry `grant_accepted` of that key is in the store | |
| The command revoke | `grant_revoked` | None. The user key is erased whatever the store answers | The reply is that of a revoke that succeeded. The entry is a pending entry |
| `peer/export` to a node of another release (10.3) | `grant_transferred_out`, one per account | The grant of that account enters the transfer | `log_store_unavailable` for the whole call, also when the store confirmed the entries of other accounts: no grant is handed over. The next call for the same receiving node creates no entry for these accounts: it writes the entries that wait again |
| `peer/export` to a node of the measurement of this node (10.1) | None | None: the user key moves between two nodes of one program, and each of the two has its node document in the store (7.7) | |
| `peer/import` of a transfer from a node of another release (10.3) | `grant_transferred_in`, one per account | None. The grant is put in place first; the call then writes the entries it created in one round, when the node has credentials for its log store | The grant stays in place and the entry is a pending entry: the next write of the account takes it along. The call succeeds all the same |
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
  confirmed and nothing else. A node that halted an account after a fault gives up the pending
  entries of that account the same way, and performs no act for the account afterwards
  (enclave.md 3.1).
- What a missing object means. An object version of the log store cannot be deleted before its
  retention ends. So for an entry that is not in the store, the act that entry describes did not
  take place: the node did not call the provider, did not hand the value out, did not hand the
  record of a stored value out, did not seal the value of a vault secret for a request, did not take
  the user key, did not hand the grant to another release. This holds for an entry the store never
  confirmed, whose `seq` no key of the store carries, and for whatever a node held in memory when it
  ended or when it halted the account. The two exceptions are the rows without an act that waits: a revoke erased the key, and an
  import from another release put the grant in place (the giving node's `grant_transferred_out`
  of that grant is in the store). The store can hold more entries than there were acts, and not
  fewer: an entry whose act failed afterwards or never started (the provider refused, the call
  ended, the store confirmed and the answer was lost) is in the store like any other.
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
| First exchange | `token` = what the node keeps of the token response object of the provider (below) |
| Refresh | `token` = the old `token` with the keys of what the node keeps of the response written over it. When the response has no `scope`, the old value stays. When the response has no `expires_in`, that key is removed |
| A provider whose token place is nested (`token_container` of the definition, `authed_user` for slack) | The `access_token`, the `refresh_token` and the `expires_in` of the refresh response are written into that place. When the response has no `expires_in`, that key is removed from that place |
| The merge of a reconnect (`oauth/merge`) | When the new `token` has no `refresh_token`, the `refresh_token` of the old record is moved into it (at the token place). Only the `refresh_token` moves (the `client_id` of a dynamically registered client stays the value of the new record) |

Reading the token place: for a provider with a `token_container`, `access_token`, `refresh_token`,
`scope` and `expires_in` are looked up inside that object first, and at the top level when they are
not there (the exchange response of slack is nested and its refresh response is flat). A token
response is accepted when `access_token` is at one of the two places. A `scope` of a refresh
response that is the empty string counts as absent (the old value stays).

What a node keeps of a token response. A node reads at most 1 MiB (1,048,576 bytes) of a
response. Of the response object it keeps every value but the strings it reads from no token
object: a member whose value is a string of more than 8,192 bytes is left out unless that
string is a token (the strings at `access_token`, `refresh_token` and `id_token` of the object,
at its top level and in the token place of the provider, and the string a provider definition
injects as the credential), and so are a member whose name is longer than 8,192 bytes and an
element of an array that is such a string, at every depth. 8,192 bytes is the longest value a
public field holds (enclave.md 6.4). So a response with a long string that is no token gives a
record, and that record does not hold the string.

A node takes a token response within the bounds of a token object (section 6) and makes no
record above them. A response whose parsed form would take more than 1,572,864 bytes by the
count of section 6 is not parsed. A response with a token of more than 16,384 bytes, and a
response of which the node would keep more than 262,144 bytes by that count, is not taken. In
each case the call fails as for a response that is no JSON object
(`exchange_failed`, `refresh_failed`, with the status of the provider). When the plaintext a
rule of the table above gives is longer than 65,536 bytes, or its parsed form would take more
than 262,144 bytes by that count, the node makes no record of it:
`oauth/complete` fails with `exchange_failed` and `refresh` with `refresh_failed`, both with
`provider_status` 200 and an empty `provider_error`, and `oauth/merge` with `record_invalid`.

## 9. The release statement and the public build proof

A release is a tag of this repository and the enclave image file that the build workflow of this
repository built from the commit of that tag. What a verifier accepts of a release is its
measurement: PCR0, PCR1 and PCR2 of that file. The public build proof of a measurement shows that
the build workflow measured it for a tag of this repository while the repository was public, so
whoever accepts a measurement by its proof accepts an enclave whose source anyone can read. A
node accepts a node of another release by this proof (10.3). No key of the operator takes part in
it, and no check compares the name of one release with the name of another.

This section states the release statement, the proof, the values a verifier holds and the checks.
Two programs of this source make the checks with one function
(`verify_release_proofs` of `protocol/src/release_proofs.rs`): the node program, and the tool
`credential-enclave-verify release-proofs` (README, "How to verify"). The secure program of the
apps makes the same checks from its version 43 on, and the shared cases of section 13 hold the
implementations to the same verdict on the same input.

### 9.1 The release statement

The release statement is the bytes of the file `measurements.json` of a release (enclave.md
11.1): a JSON object of at most 16,384 bytes.

| Member | Value |
| --- | --- |
| `release` | The name of the tag of the release: `v` followed by one or more of the characters `A` to `Z`, `a` to `z`, `0` to `9`, `.`, `_` and `-` |
| `git_commit` | The commit of that tag, 40 lower-case hexadecimal characters |
| `pcr0`, `pcr1`, `pcr2` | The measurement of the enclave image file of the release, 96 lower-case hexadecimal characters each |
| `inputs` | The SHA-256 of what the measurement was made of. No check reads it: it serves a person who builds the release again and compares |

A reader of a release statement ignores the members this table does not name.

### 9.2 The public build proof

The public build proof of a release is the attestation that the job of the build workflow made of
its release statement, in the run that built the release (enclave.md 11.2). It is a Sigstore
bundle with three parts:

- The certificate: an X.509 certificate that the certificate authority of the public instance of
  Sigstore (Fulcio) issued to that workflow run, for a key the run created, valid for ten
  minutes. Its extensions state the identity of the run as GitHub stated it to the certificate
  authority.
- The envelope (DSSE): an in-toto statement with the predicate type
  `https://pickle.com/credential-enclave/release/v1`, whose predicate is the release statement,
  and the signature of the key of the certificate over it.
- The entry of the transparency log (Rekor): the record of that envelope and that certificate in
  `rekor.sigstore.dev`, with what the log returned for it: the time at which it took the entry,
  its signature over the entry (the signed entry timestamp), and the inclusion proof of the entry
  (the audit path to the root of a tree, and the checkpoint in which the log signed the head of
  that tree).

The value that carries a release statement and its proof is named `release_proofs`:

```text
release_proofs = JSON {"statement": b64u(the bytes of the release statement),
                       "attestation": bundle}

bundle = {"verificationMaterial": {
            "certificate": {"rawBytes": "<standard base64 of the DER of the certificate>"},
            "tlogEntries": [{
              "logIndex": <count>,
              "logId": {"keyId": "<standard base64 of the 32 bytes of the log identifier>"},
              "integratedTime": <count>,
              "inclusionPromise": {"signedEntryTimestamp": "<standard base64>"},
              "inclusionProof": {"logIndex": <count>, "treeSize": <count>,
                                 "rootHash": "<standard base64 of 32 bytes>",
                                 "hashes": ["<standard base64 of 32 bytes>", ...],
                                 "checkpoint": {"envelope": "<the checkpoint, its line feeds included>"}},
              "canonicalizedBody": "<standard base64 of the body of the entry>"}]},
          "dsseEnvelope": {"payload": "<standard base64 of the in-toto statement>",
                           "payloadType": "application/vnd.in-toto+json",
                           "signatures": [{"sig": "<standard base64>"}]}}
```

The bundle is the JSON object that the attestation of GitHub writes, as it is. `release_proofs` is
a public value: whoever carries it, the checks of 9.4 decide. A reader ignores the members of
`release_proofs` and of the bundle that this section does not name (among them `mediaType`,
`kindVersion` and `timestampVerificationData` of a bundle).

### 9.3 The values of a verifier

A verifier holds five values. In the node program they are compiled in, so they are part of its
measurement (`enclave/src/lineage.rs` with the files of `enclave/release/`, and the repository in
`protocol/src/release_proofs.rs`). The tool `credential-enclave-verify release-proofs` compiles in
the same files.

| Value | What it is |
| --- | --- |
| The root certificate | The root certificate of the certificate authority of the public instance of Sigstore (`enclave/release/fulcio-root.pem`). The SHA-256 of its DER is `3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1` |
| The intermediate certificate | The certificate of that authority that the root certificate issued and that issues the certificates of workflow runs (`enclave/release/fulcio-intermediate.pem`). The SHA-256 of its DER is `15d795348226b4649f750f5802592c393bee7cc53c3b86982175b7ad087efe47` |
| The key of the transparency log | The public key of `rekor.sigstore.dev`, a log of the form Rekor v1: ECDSA P-256, as the DER of its SubjectPublicKeyInfo (91 bytes; `enclave/release/rekor-key.pem`). The log identifier is the SHA-256 of that DER: `c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d` in lower-case hexadecimal |
| The repository | The address `https://github.com/pickle-com/credential-enclave`, the identifier of the repository (`1400118248`) and the identifier of its owner (`151645824`), as GitHub numbers them. GitHub does not change these identifiers and does not give them to another repository or owner |
| The list of build workflows | `[{"workflow":"<the path of a workflow file in the repository>","commit":"<40 lower-case hexadecimal characters>"}]` (`enclave/release/builders.json`): the workflow files whose job a verifier takes the attestation of, each at one commit of that file. The list of this release has one element: `.github/workflows/enclave-build.yml` at the commit `e522d06d8388bee590678963f8940cd7a2b69f5c` |

- The two certificates and the key of the log are those that the trusted root of the public
  instance of Sigstore names (`targets/trusted_root.json` of the repository
  `sigstore/root-signing`, which the TUF repository of Sigstore distributes). A test of
  `enclave/src/lineage.rs` holds them to the copy of that trusted root in this repository
  (enclave.md 11.1).
- A node does not start when one of the two certificates is not a certificate of a certificate
  authority in the form of 9.4, when the root certificate did not issue the intermediate
  certificate, when the key of the log is not such a key, and when the list of build workflows is
  not a JSON array of such elements or names one build workflow twice. The path of a workflow is
  one or more of the characters `!` to `~` without `@`.
- None of the five is a value of one release: a release is built, tagged and deployed without a
  change to them. The first three change when the certificate authority or the log of Sigstore
  does, and the list of build workflows when the build workflow does: the job of a workflow file
  does what the file of that commit states, so a changed build workflow is another element.
- A verifier takes the proof of a release that a build workflow of its own list built. A release
  that a build workflow outside that list built, a certificate of another certificate authority
  and an entry of another log have no proof this verifier takes: for a node, the nodes of such a
  release receive no delegation from it and are delegated to by the apps (10.1).
- Every release the job of a listed build workflow attested is a release a verifier takes, so
  the list names a commit of the build workflow file only when every tag that job attested
  carries a node program that accepts another release by its proof alone. The release candidate
  `v2.4.0-rc.1` was attested by the job of `.github/workflows/enclave-build.yml` at the commit
  `3f84e8368fcdf1f89e42ca629670bfe0989b6f13`, and its node program hands delegations on under a
  signature of the operator. The list does not name that commit: no node and no secure program
  of this release takes the proof of that release candidate.

### 9.4 The checks

A verifier takes `release_proofs` for a measurement M (PCR0, PCR1 and PCR2 of an attestation
document that verified by 4.3) when the value has the form of the first row and every check V1 to
V7 holds. A node answers a failure of any of them with `peer_unverified` (10.3).

| Check | Rule |
| --- | --- |
| The form | `release_proofs` is a JSON object whose `statement` is a string of at most 32,768 UTF-16 code units and whose `attestation` is an object, and the value holds at most 32 arrays and objects inside one another |
| V1, the release statement | `statement`, decoded from base64url without padding, is at most 16,384 bytes of JSON text that reads as an object. The object states `release`, `git_commit`, `pcr0`, `pcr1` and `pcr2` once each, as strings: `release` has the form of 9.1, `git_commit` is 40 lower-case hexadecimal characters, and each PCR is 96 lower-case hexadecimal characters that are not all zero (a PCR that is all zero is the value of an enclave in debug mode, whatever that enclave runs). The three PCRs equal those of M |
| V2, the form of the bundle | `attestation` holds the string `verificationMaterial.certificate.rawBytes`, the array `verificationMaterial.tlogEntries` with exactly one element, which is an object (the entry), and the object `dsseEnvelope` with the strings `payload` and `payloadType` and the array `signatures` with exactly one element, whose `sig` is a string. `attestation`, written as JSON without white space, is at most 65,536 bytes of UTF-8. `payload`, decoded from standard base64, is JSON text that reads as an object (the in-toto statement), and `payloadType` is `application/vnd.in-toto+json` |
| V3, the certificate chain | `rawBytes`, decoded from standard base64, is one certificate in the form below. That certificate, the intermediate certificate and the root certificate are valid at the time of the entry (`integratedTime` of V4, in seconds since the Unix epoch): the time is neither before the start nor after the end of the validity of any of the three. The certificate of the bundle is not the certificate of a certificate authority. The intermediate certificate issued it: its issuer name is the subject name of the intermediate certificate, byte for byte as encoded, its signature algorithm is ECDSA with SHA-256 or with SHA-384, and its signature is the signature of the key of the intermediate certificate over its signed part. The function of this source also validates the X.509 path from the certificate over the intermediate certificate to the root certificate at that time, with the path validation a node uses for the certificates of an attestation document (4.3): every extended key usage is accepted and no revocation list is read. So a node also refuses a certificate that the rules of this row take and that path validation refuses, a certificate with a critical extension the validation does not know among them |
| V4, the entry of the log | The rules of the entry below |
| V5, the signature of the envelope | `sig`, decoded from standard base64, is the ECDSA P-256 SHA-256 signature (ASN.1 DER) of the key of the certificate over the pre-authentication encoding of DSSE: the ASCII text `DSSEv1`, a space, the number of bytes of `payloadType` in decimal, a space, `payloadType`, a space, the number of bytes of the decoded payload in decimal, a space, and the decoded payload. A certificate whose key is not on P-256 signed nothing |
| V6, the identity | The certificate states every value of the table of the identity below |
| V7, the predicate | The `predicateType` of the in-toto statement is `https://pickle.com/credential-enclave/release/v1`, and the strings `release`, `git_commit`, `pcr0`, `pcr1` and `pcr2` of its `predicate` equal those of the release statement of V1. The `subject` of the in-toto statement is not read: a verifier holds no enclave image file, and what it accepts is the predicate |

The checks are made in this order, and the first one that fails ends the verification: the form,
V1, V2, the time of the entry (the first rule of V4), V3, V6, V5, the other rules of V4, V7.

The entry (V4). `tlogEntries[0]` is the entry of a log of the form Rekor v1. An entry of another
form (the entry of a log that signs no entry timestamp among them) fails these rules.

1. `integratedTime` is a count: the time at which the log took the entry, in seconds since the
   Unix epoch.
2. `logId.keyId`, decoded from standard base64, is the 32 bytes of the log identifier of the log
   of the verifier.
3. `canonicalizedBody`, decoded from standard base64, is JSON text that reads as an object with
   `kind` `"dsse"` and `apiVersion` `"0.0.1"`. Its `spec.payloadHash.algorithm` is `"sha256"`, and
   its `spec.payloadHash.value` is the lower-case hexadecimal SHA-256 of the decoded payload of
   V2. Its `spec.signatures` is an array with exactly one element: `signature`, decoded from
   standard base64, is the bytes of the signature of V5, and `verifier`, decoded from standard
   base64 and then read as the PEM of a `CERTIFICATE`, is the DER of the certificate of V3, byte
   for byte.
4. `logIndex` is a count, and `inclusionPromise.signedEntryTimestamp`, decoded from standard
   base64, is the ECDSA P-256 SHA-256 signature (ASN.1 DER) of the log key over the UTF-8 bytes of

   ```text
   {"body":"<canonicalizedBody>","integratedTime":<integratedTime>,"logID":"<log identifier>","logIndex":<logIndex>}
   ```

   with the keys in this order, without white space, `<canonicalizedBody>` as the string of the
   bundle, the two counts in decimal, and the log identifier as the 64 lower-case hexadecimal
   characters the verifier computed from the key of the log.
5. `inclusionProof.logIndex` and `inclusionProof.treeSize` are counts, `inclusionProof.rootHash`
   is the standard base64 of 32 bytes, and `inclusionProof.hashes` is an array of at most 64
   strings, each the standard base64 of 32 bytes. `inclusionProof.logIndex` is below `treeSize`,
   and with `leaf = SHA-256(0x00 ∥ the decoded body)`, `fn = inclusionProof.logIndex` and
   `sn = treeSize − 1`, the path computation of check 9 of "The secure program release" ends with
   `sn = 0` and with the bytes of `rootHash`. `inclusionProof.logIndex` is the index of the leaf
   in the tree of the checkpoint, a value other than `logIndex`, the index the log signed in rule
   4.
6. `inclusionProof.checkpoint.envelope` is a string that holds `"\n\n"`. The part before the
   first `"\n\n"`, split at `"\n"`, has at least three lines: the first is not empty (the origin
   of the log, which is not compared with a value of the verifier), the second is `treeSize` in
   decimal, and the third, decoded from standard base64, is the bytes of `rootHash`. That part
   followed by one `"\n"` is the note. A line of the part after the first `"\n\n"` is a line of
   the log when it is `"— "` (U+2014 and a space), a name that is not empty, a space, and the
   standard base64 of more than four bytes whose first four are the first four bytes of the log
   identifier. The checkpoint holds at least one line of the log, and in every line of the log
   the bytes after the first four are the ECDSA P-256 SHA-256 signature (ASN.1 DER) of the log
   key over the UTF-8 bytes of the note. A line of the log that is no such signature refuses the
   checkpoint, also beside one that is. Every other line (the signature of a witness, a line of
   another key) is not read, and neither are further lines of the note, which the signature of
   the log covers.

The identity (V6). The certificate states each value below in its extension
`1.3.6.1.4.1.57264.1.{number}`, whose value is the DER of one UTF8String. A certificate without
one of these extensions, or with another value in it, is refused. `{release}` and `{git_commit}`
are those of the release statement of V1.

| Number | What it states | The value a verifier asks for |
| --- | --- | --- |
| 8 | The issuer of the token the certificate was issued for | `https://token.actions.githubusercontent.com` (GitHub Actions) |
| 9 | The workflow of the job that signed | The text before its last `@` is the address of the repository, `/` and the `workflow` of an element of the list of build workflows. The text after that `@` is the ref the calling workflow wrote: it is not empty and is not judged |
| 10 | The commit of the file of that workflow | The `commit` of an element of the list with the `workflow` of 9 |
| 11 | The runner | `github-hosted` |
| 12 | The repository the run took place in | The address of the repository |
| 13 | The commit that started the run | `{git_commit}` |
| 14 | The ref that started the run | `refs/tags/{release}` |
| 15 | The identifier of that repository | The identifier of the repository |
| 17 | The identifier of the owner of that repository | The identifier of the owner |
| 20 | What started the run | `push` |
| 22 | The visibility of the repository when the certificate was issued | `public` |

The extension 18, the workflow that started the run and called the build workflow, is not judged:
its file is a file of the commit of the tag, and the job that signed does what the file of the
build workflow states.

The forms. Every value is read in one form, and a value in another form is refused:

- Base64. Standard base64 is the alphabet of RFC 4648 section 4 with its padding, and base64url
  the alphabet of section 5 without padding. A text with a character outside the alphabet, with
  white space, with missing or surplus padding, or whose last character carries bits of no byte
  is refused.
- JSON text. The bytes are UTF-8 and one JSON value that holds no number outside the finite
  ones, no half of a surrogate pair and at most 32 arrays and objects inside one another. Of two
  members of one object with the same name the last one counts, except for the five members of a
  release statement, each of which occurs once (V1).
- A count is a non-negative integer of at most 2^53 − 1, written as a string of 1 to 16 decimal
  digits without a leading zero (a lone `0` is a count), which is how a bundle writes its times
  and indexes. A JSON number is no count: the readers of JSON do not read every text of a number
  as the same double, and a count decides what the log signed.
- A JSON text inside a string. The release statement, the payload of the envelope and the body of
  the log entry are JSON texts that stand inside strings of the proofs. A node reads such a text
  only when it has at most 1,024 arrays, objects and commas outside its strings, counted
  together: what a parsed text holds in memory grows with these and not with its length, and no
  signature covers the text at the moment it is read. A text with more of them is refused by the
  check that reads it (V1, V2, V4). The three texts of a release the build workflow attested
  have 24, 32 and 13.
- The length of `attestation` (V2) is the number of bytes of the value written as JSON without
  white space: a string with the two-character escapes of `"`, `\`, backspace, form feed, line
  feed, carriage return and tab, the six-character escape of every other character below U+0020
  and the UTF-8 bytes of every other character, and a number as ECMAScript writes it.
- A certificate. An element of DER has a tag of one byte and its shortest length form. The
  certificate is one SEQUENCE of the signed part, the signature algorithm and the signature (a BIT
  STRING without unused bits), with no byte behind it. The signed part holds, behind a version
  `[0]` it may begin with: the serial number, the signature algorithm (the bytes of the one of
  the certificate), the issuer name, the validity (two times, each a UTCTime `YYMMDDHHMMSSZ` or a
  GeneralizedTime `YYYYMMDDHHMMSSZ` of a day the calendar has, not before 1950), the subject name
  and the SubjectPublicKeyInfo. What follows is a unique identifier (`[1]`, `[2]`), which is not
  read, or the extensions (`[3]`): each a SEQUENCE of an object identifier, an optional BOOLEAN
  and an OCTET STRING, and no object identifier twice. A certificate is one of a certificate
  authority when the value of its extension 2.5.29.19 (basic constraints) is a SEQUENCE that
  begins with a BOOLEAN of one byte that is not zero.
- A key. The key of a certificate is an ECDSA key on P-256 or on P-384, as a SubjectPublicKeyInfo
  with an uncompressed point (91 or 120 bytes). An ECDSA signature is the DER of two non-negative
  integers without unneeded bytes.
- A PEM text of a kind is the line `-----BEGIN {kind}-----`, standard base64 and the line
  `-----END {kind}-----`, with white space around it and inside the base64 left out.

### 9.5 What the checks show

- The identity of V6 is what ties an attestation to this repository and to one workflow file. The
  extensions 9 and 10 say that the job of a build workflow of the list signed, as the file of
  that workflow is at the commit of the list. What that job does is what that file states,
  whatever the commit of a tag holds: an attestation that the job of another workflow file made
  (the workflow that the push of the tag starts among them) states that file in 9 and is
  refused, and so is the build workflow at any other commit (10). The ref behind the last `@` of
  9 is not judged, because 10 states the commit that ref led to. 13 and 14 say that the run was
  started at the commit the statement names, by the push of the tag the statement names as its
  release. 11 says that a runner GitHub hosts ran the job: a runner that the owner of a
  repository registers signs whatever its owner hands it, under the same workflow and the same
  tag. 12, 15 and 17 name the repository the run took place in: a workflow of another repository
  can call the build workflow, and the certificate of that run states that repository. 20 says
  that the push of the tag started the run: a run that is started another way takes inputs that
  are not public. 22 says that the repository was public when the certificate was issued.
- So a measurement with a proof that passes is the measurement that the job of a build workflow
  of the list wrote into the release statement, for the commit of a tag of this repository that
  was public at that time. What that job builds from the commit, and what it keeps away from the
  programs of the commit while it builds, is stated with the build workflow (enclave.md 11.2).
  The proof says nothing about what the source of the release does: it says which source it is.
- The proof names the commit and the tag as the repository held them when the run took place.
  It does not show that the repository holds them still: a tag can be deleted after its release
  was attested, and a commit that no branch and no tag names may stop being served. What stays
  is the record of the attestation in the log, with the commit and the name of the tag.
- The proof rests on GitHub, which states the identity of a workflow run to the certificate
  authority, on the certificate authority of Sigstore, which issues a certificate for the
  identity it was shown and no other, and on the transparency log of Sigstore. The signed
  certificate timestamps of the certificate are not read: that the certificate was issued is on
  the log a verifier checks, whose entry holds the certificate.
- A verifier sends no request and reads no clock. The verdict depends on the bytes of
  `release_proofs`, on the measurement and on the values of the verifier. The time at which the
  certificates are valid is the time the log signed for the entry, and the certificate of the
  bundle is valid for ten minutes.
- Of the log a verifier checks what the log returned for the entry: the signed entry timestamp,
  and the inclusion proof with the checkpoint. It reads no signature of a witness, so the checks
  do not show that the log presents the same tree to every reader.
- `release_proofs` has no end. A verifier takes the proofs of a release for as long as it holds
  the values they verify under, and nothing withdraws a proof.
- Where a value could be read in more than one way, it is refused. Proofs that hold and are
  refused keep the nodes of a release from receiving delegations from other nodes. Proofs that do
  not hold and are accepted hand user keys to an enclave whose source nobody can read.
- The node program refuses some proofs that the secure program of the apps takes, and none the
  other way round. Its reader of JSON refuses a whole text that holds, anywhere in it, a number
  outside the range of a double, an escape of half of a surrogate pair, or more than 128 arrays
  and objects inside one another: also where a later member of the same name hides that value
  from a reader that keeps the last member. It refuses a JSON text inside a string of the proofs
  that has more than 1,024 arrays, objects and commas (9.4, "The forms"). And it verifies the
  path of the certificate a second time with a library that refuses forms the certificate
  authority of Sigstore does not issue: a signature of a certificate with SHA-512, a critical
  extension it does not know, a version other than 3, a unique identifier, and two sets of
  extensions. The proofs the build workflow makes have none of these.

## 10. Delegation transfer between nodes and witnessing

A node hands delegations to another node only after it verified that node by its attestation. The
operator domain supplies the address of the peer and carries the messages and the release proofs
(a node does not trust the carrier). The delegation transfer (10.1) and the delegation transfer
between two releases (10.3) are part of stage 1. Witnessing (10.2) is stage 2.

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
receiving node and, for a receiving node of another release, its release proofs):

| Step | Rule | Failure code |
| --- | --- | --- |
| 1 | The node verifies the attestation response of the receiving node: platform `nitro` by 4.3 (without the nonce check), platform `local` by parsing `binding`. This gives the signing public key and the sealing public key of the receiving node | `peer_unverified` |
| 2 | The platform of the receiving node is the platform of this node (nothing is handed to a node of another custody) | `peer_unverified` |
| 3 | Platform `nitro`: PCR0, PCR1 and PCR2 of the receiving node are a measurement this node hands delegations to: the three values equal those of this node, or the release proofs of the call show them as the measurement of a release (10.3). Without release proofs that hold, delegations go to a node of the measurement of this node only. A PCR whose value is all zero is refused | `peer_unverified` |
| 3a | The log store that the binding of the receiving node names is the log store of this node: the same bucket and the same region, or no `log` on both sides (delegations stay among nodes that write to the same log store) | `peer_unverified` |
| 3b | The binding of the receiving node has no `role` key or the `role` `reserve` (4.1: delegations stay among nodes that hold delegations. A node of the forward role takes none, and a binding with any other `role` is no binding) | `peer_unverified` |
| 4 | The receiving node is not this node | `invalid_request` |
| 4a | (A transfer to a node of another release, 10.3) The node can write to its log store (7.6, 7.7). A transfer to a node of the measurement of this node writes nothing and passes this step in every case | `log_store_unavailable` |
| 5 | The node selects the accounts that have a grant within its time, in the lexical order of `user_id`, one page at a time (at most 1,000 accounts). A transfer to a node of the measurement of this node creates no entry: every selected grant goes on to step 5b. A transfer to a node of another release (10.3) has entries: an account whose grant was handed to 64 other nodes of another release is skipped (see below), and for every selected account, inside the lock of that account, the node creates the log entry `grant_transferred_out` when it hands that grant to the receiving node for the first time. The entry names the receiving node, its release and its measurement (7.2) | |
| 5a | (To a node of another release) The node writes the entries to the log store: the entries of step 5, and the entry of an earlier call for the same receiving node that the store has not confirmed. It goes on only when the store confirmed the entry of every selected account | `log_store_unavailable` |
| 5b | For every selected account, inside the lock of that account again, the node puts the grant into the transfer when the account still has a grant within its time and, for a node of another release, that grant is the one whose entry for this receiving node the store confirmed. An account that revoked in between is left out, and so is, for a node of another release, an account whose grant was replaced in between | |
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
- The entries of a transfer to another release are not stopped by the limit of entries without a
  storage acknowledgement (64), like the entries of a command.
- There is one entry per grant and receiving node of another release. A node keeps, with every grant
  in its memory, the list of the nodes of another release it handed that grant to. The first
  transfer of a grant to such a node creates the entry `grant_transferred_out` and puts that node on
  the list. A repeated transfer of the same grant to a node of the list carries the grant again and
  creates no entry: a transfer whose envelope was lost on its way is made again, and the entry that
  names the receiving node exists already. A node is put on the list when the entry is created, also
  when the log store does not confirm that entry: the repeated call writes that entry again and
  hands the grant over once the store confirmed it. The list holds at most 64 nodes. A grant whose
  list is full is handed to no further node of another release: its account is skipped, without an
  entry. So a carrier that repeats the call adds at most 64 entries per grant.
- The list belongs to the grant state in the memory of the node. A grant command that puts a grant
  in place (step 14 of 5.3), a revoke, the end of the grant and a transfer that puts a grant in
  place on this node (step 3 of the receiving node) create a new state, and the list of a new grant
  is empty. A renewal (step 13a of 5.3) keeps the grant and its list.

The rules of the receiving node (`peer/import`. The input is the attestation response of the
giving node, the envelope and, for a giving node of another release, its release proofs):

| Step | Rule | Failure code |
| --- | --- | --- |
| 1 | The node verifies the attestation response of the giving node by the rules of steps 1 to 3b above. In step 3 the measurement of the giving node is that of this node, that of an element of the list of old releases of this node, or one that the release proofs of the call show as the measurement of a release (10.3) | `peer_unverified` |
| 1a | The log store of this node holds its node document, with a retention that outlives an entry written now (7.7). A node of platform `local` without a log store passes. The node needs no credentials for its log store here | `log_store_unavailable` |
| 2 | The `to` of the envelope is the `node` of this node and its `from` is the giving node of step 1. The node opens the envelope with its sealing private key and verifies the signature with the signing public key of the giving node. `from` and `to` of the payload equal those of the envelope | `wrong_node`, `open_failed`, `bad_signature` |
| 3 | For every grant: only a grant whose `custody` is the custody of the platform of this node and whose `not_after_ms > now` is looked at. A grant of an account whose revoke command this node accepted before is skipped (see below). When the account has no grant within its time, the node puts the grant into its memory. For a grant from a node of another release (10.3) it creates the log entry `grant_transferred_in`, which names the giving node and its release (7.2); a grant from a node of the measurement of this node is put in place without an entry. When the account has a grant of the same `sign_pk` within its time, the larger `not_after_ms` stays (no entry). When the account has a grant of another `sign_pk`, the grant of the transfer is skipped | |

- The receiving node shortens the `not_after_ms` of a grant it takes to the limit of 5.2
  (`now + 30 days`).
- The receiving node of a transfer from another release puts the grants in place first and then
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
  are under the prefix of that account (7.4), and a transfer to another release is on the log with
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
- A transfer between two nodes of different releases follows 10.3: the public build proof of the
  measurement of the other node decides and, for a receiving node, the list of old releases of
  its program.
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

### 10.3 The delegation transfer between two releases

Purpose: the delegations of the accounts stay when the operator replaces the nodes of one release
with the nodes of another. A node hands delegations to a node of another measurement, and takes
them from one, when the public build proof of that measurement holds (section 9): the measurement
is the one the build workflow of this repository measured for a public tag. A receiving node also
takes delegations from the nodes of the old releases its program lists. The payload and the
envelope are those of 10.1. Such a transfer is on the log of the account: the giving node creates
the entry `grant_transferred_out` of every grant and hands the grant over after the log store
confirmed that entry (steps 4a to 5b of 10.1), and the receiving node creates the entry
`grant_transferred_in` (step 3 of the receiving node). This section states which node of another
measurement a node accepts.

Both calls take the release proofs of the other node as the key `release_proofs` of their body
(9.2, enclave.md 5.13). The operator domain supplies them as it supplies the attestation
response. They are public values: the verdict is the one of the checks of 9.4, made with the
values that are compiled into the node (9.3).

The rule of the giving node (`peer/export`). In step 3 of 10.1 the measurement of the receiving
node is accepted in one of two cases:

| Case | Rule | Entry |
| --- | --- | --- |
| The measurement of this node | PCR0, PCR1 and PCR2 of the document of the receiving node equal those of this node. `release_proofs` is not read | None (10.1) |
| A measurement with a public build proof | `release_proofs` passes every check of 9.4 for PCR0, PCR1 and PCR2 of the document of the receiving node, and the `release` of the binding of the receiving node equals the `release` of the release statement of the proofs | `grant_transferred_out`, which the log store confirms before the grant is handed over |

A giving node hands nothing to a node of any other measurement: not to a node of an old release
of its list, and not under a signature of the operator. A measurement of the list of old releases
is refused before `release_proofs` is read: proofs that hold for such a measurement do not make
its node a receiving node. A giving node does not read the key `endorsement`, which the releases
before v2.4.0 read.

The rule of the receiving node (`peer/import`). In step 1 of the receiving node of 10.1 the
measurement of the giving node is accepted in one of three cases:

| Case | Rule | Entry |
| --- | --- | --- |
| The measurement of this node | PCR0, PCR1 and PCR2 of the document of the giving node equal those of this node. `release_proofs` is not read | None (10.1) |
| An old release | The three values equal those of one element of the list of old releases, and the `release` of the binding of the giving node equals the `release` of that element. `release_proofs` is not read | `grant_transferred_in` |
| A measurement with a public build proof | `release_proofs` passes every check of 9.4 for the three values, and the `release` of the binding of the giving node equals the `release` of the release statement of the proofs | `grant_transferred_in` |

The cases are tried in the order of each table. In every case no PCR is all zero, and the other
steps of 10.1 apply: the two nodes run on one platform, the binding of the other node names the
log store of this node (step 3a) and no role or the role `reserve` (step 3b). For a node whose
measurement no other case accepts, a call that carries no `release_proofs`, and a call whose
`release_proofs` fails a check of 9.4, ends with `peer_unverified`. A node of platform `local`
reads no release proofs: a local document states no measurement, and the peers of such a node
are those of 10.1.

The list of old releases is compiled into the node program
(`enclave/release/predecessors.json`), so it is part of its measurement:

```text
[{"release":"v2.3.0","pcr0":"<96 hex>","pcr1":"<96 hex>","pcr2":"<96 hex>"}, ...]
```

It holds the releases that were built before the build workflow of section 9 and have no public
build proof, each with the values of its `measurements.json`: v1.5.2, v2.0.0, v2.0.1, v2.1.0,
v2.2.0 and v2.3.0. A release that the build workflow built is not put on the list: it is
accepted by its proof. A node reads the list once, when it starts. It does not start when the
list is not a JSON array of such elements, when the `release` of an element has not the form of
the name of a release (9.1), or when a PCR of an element is not 96 lower-case hexadecimal
characters or is all zero.

- No order of releases. A node compares the release of a binding with the release of a statement
  or of an element of the list for equality, and compares no release with its own. It hands
  delegations to a release whose proof holds whatever the name of that release is, a name that
  sorts before its own included. The name of a tag is chosen by whoever pushes it, so a
  comparison of names holds nobody who can push a tag: an old source under a higher name passes
  it.
- No key of the operator. A giving node of this release asks for no signature of the operator,
  and no public key of the operator is compiled into it. What the operator cannot make is a
  proof for an enclave whose source is not a public tag of this repository: the certificate of a
  proof is issued to a run of the build workflow, and the record of it is in the transparency
  log (9.5). What a party that can push a tag to this repository and that carries the calls
  between the nodes can do is move delegations to an enclave built from that tag: its source, its
  tag and its commit are public then, and so is the record of its attestation.
- A transfer between two releases takes place when the receiving node accepts the giving node as
  well: by its own measurement, by its list of old releases, or by the release proofs of the
  giving node, which the `peer/import` call carries.
- The nodes of an old release follow the rules of their own release, which this release cannot
  change. Such a node hands delegations to a node of this release by 10.3 of the document of its
  tag: it asks for the endorsement of the receiving release, the signature of the release key of
  the operator over the release statement with the record of that signature in
  `rekor.sigstore.dev`, and for a release name later than its own, where a release name has the
  form `v{major}.{minor}.{patch}` or `v{major}.{minor}.{patch}-rc.{n}`. So while nodes of an old
  release are to hand their delegations to a release, the operator makes that endorsement for
  it, outside this repository, and names the release in that form. A node of this release
  neither makes nor reads an endorsement.
- A node sends no request to the certificate authority or to the log and reads no clock for a
  proof. The proofs are bytes of the call, and the verdict depends on them, on the attestation
  document of the other node and on the values compiled into the node (9.5).
- A proof has no end: a node accepts the proofs of a release for as long as that node runs.
- No notice period lies between the entry of the log and a transfer: a node hands delegations to
  a release as soon as a call carries its proofs. An account does not learn of a release before
  its delegation can move there. What it learns from is its own log (the last item below).
- The values of a node are those of the day its release was built (9.3). A release that is built
  after the certificate authority of Sigstore changed its certificates, after
  `rekor.sigstore.dev` stopped taking entries or changed its key, or by a build workflow outside
  the list of a node, has no proof that node takes: the node hands it no delegation, and the
  nodes of that release receive their delegations from the apps (10.1). Sigstore, the operator of
  `rekor.sigstore.dev`, has stated that it will announce the end of the uploads to that log one
  year ahead (the announcement of the general availability of Rekor v2, as of 2026-11-23). A
  workflow of this repository compares, every hour, the transparency logs and the certificate
  authorities of the trusted root that the TUF repository of Sigstore distributes with the ones
  of the copy of that trusted root in this repository, to which a test ties the two certificates
  and the key of the log of this release, and opens an issue when they differ (enclave.md 11.2).
  The workflow tells people that the values may have to follow. It checks no signature of the
  TUF repository, and no node depends on it.
- The trusted root of Sigstore names a second log, `log2025-1.rekor.sigstore.dev`, of the form
  Rekor v2 (as of 2026-11-23). A node holds no key for it and takes no entry of it: that log
  signs no entry timestamp, so an entry of it has not the form of V4 (9.4).
- The account sees the transfer on its log: the entry `grant_transferred_out` of the giving node
  names the receiving node, its release and its measurement (7.2). So a reader learns from its
  own log which program received its key, and whether that is a program it accepts (7.4). The
  measurement on the entry is the one the giving node verified: the values of the release
  statement of the proofs, which the attestation document of the receiving node states. A giving
  node of a release before v2.4.0 names the receiving node only.

### 10.4 The delegation subset

Purpose: a delegation is in the memory of nodes and nowhere else, so the delegation of an account
is lost when every node that holds it ends at the same time (10.1). The operator gives the
delegation of every account to a fixed number of its nodes, so that the state of a node and the
work of a transfer grow with the accounts of its share and not with every account, and it places
those nodes where they do not end together: in different groups (a group is the place a node runs
in, for the nodes of the operator its availability zone), and one of them among nodes of the
reserve role, which no call that uses a credential reaches (4.1).

The operator runs its nodes in pools: the nodes of one role that are numbered together. The nodes
of a pool are numbered by their ordinal, 0 to `pods - 1`, and every account has its delegation on
`copies` of them. The placement of a pool is `pods`, `copies` and, for a pool with groups, the
name of the group of every ordinal (`groups`) and the number of groups an account passes over
(`skip`). The operator's backend lists for an account the nodes of its share. The nodes of an
account in a pool are a function of the account and the placement alone:

```text
rank(user_id, ordinal)     = SHA-256(UTF-8(user_id) || "\n" || UTF-8(ordinal as decimal digits))
group_rank(user_id, group) = SHA-256(UTF-8(user_id) || "\n" || "zone" || "\n" || the bytes of the name)

without groups:
assign(user_id, pods, copies) = the first min(copies, pods) ordinals of 0..pods in the ascending
                                order of (rank(user_id, ordinal), ordinal)

with groups:
group_order(user_id)   = the different names of groups in the ascending order of
                         (group_rank(user_id, name), the bytes of the name)
first(user_id, group)  = the ordinal whose group is that name and that is first in the ascending
                         order of (rank(user_id, ordinal), ordinal)
assign(user_id, pods, copies, groups, skip)
                       = first(user_id, group) of each of the copies groups at the positions
                         skip to skip + copies - 1 of group_order(user_id), in that order
```

The order of two hashes is the order of their 32 bytes. A `user_id` holds no line feed (section
1) and a group name none either, so no ordinal and no group of any account share the input of
their hash.

- Without groups the assignment is that of the releases before v2.4.0, and `skip` is not read: it
  counts groups, and such a pool has none. A node that restarts keeps its ordinal and its share.
  When `pods` grows by one, the accounts whose first `copies` ordinals gain the new ordinal hand
  one ordinal over to it and every other account keeps its ordinals; when `pods` shrinks by one,
  the accounts that held the removed ordinal gain the ordinal that ranks next for them and every
  other account keeps its ordinals.
- With groups an account has one node in each of `copies` different groups, so the loss of one
  group takes one node of an account at the most. A node more in a group takes, from a node of
  that group, the accounts that rank it first there and whose groups of this pool include that
  group, and every other account keeps its nodes; a node less, in a group that keeps another
  node, hands its accounts to the node of its group that ranks next for each of them.
- The order of the groups of an account depends on the account and on the names alone, not on
  the ordinals. Two pools whose `groups` hold the same names therefore agree on it. With a pool
  of nodes of the delegation role that takes the first two groups of an account (`copies` 2,
  `skip` 0) and a pool of nodes of the reserve role that takes its third group (`copies` 1,
  `skip` 2), an account has its delegation on two nodes that use it and on one node that does
  not, in three different groups. This rests on the two pools naming the same groups: a pool
  whose `groups` hold a name the other pool lacks ranks that name among the others, and the
  positions of the two pools then no longer name different groups.

One placement numbers 1,024 nodes at the most, so the nodes of one role of a larger fleet are
several pools, and each of those pools holds the accounts of its span, a range of span numbers:

```text
span_number(user_id) = the first four bytes of SHA-256(UTF-8(user_id) || "\n" || "span"), as an
                       unsigned integer with the most significant byte first: 0 to 4,294,967,295
span                 = [first, last] with first <= last
a span holds user_id when first <= span_number(user_id) <= last
```

- An account that the span of a pool does not hold has no node in that pool, whatever its
  assignment there says. A pool without a span holds every account, so the nodes of an account in
  a pool with a span are its nodes under the placement of that pool, when the span holds it, and
  none otherwise.
- Both ends are part of a span. The spans `[first, m]` and `[m + 1, last]` therefore hold every
  account of `[first, last]`, and no account twice: a pool is divided by dividing its span, and
  the pools of one role hold every account once when their spans divide the numbers 0 to
  4,294,967,295 between them.
- The input of the span number is the input of no other hash of an account: after the line feed,
  the input of a rank holds decimal digits, that of a group rank a second line feed, and the
  input of the bucket of an account in a log store (7.6) holds no line feed. The span of an
  account therefore tells nothing about its nodes in a pool, the order of its groups or its
  bucket: the accounts of one span spread over the ordinals, the groups and the buckets as the
  accounts of every span do.

The `subset` object of a request names the placement of a pool, the span of that pool when it
has one, and the ordinal of the node of that pool the request is about:

```text
subset = {"pods": 3, "pod": 1, "copies": 2}
subset = {"pods": 6, "pod": 4, "copies": 2, "skip": 0,
          "groups": ["us-west-2a", "us-west-2b", "us-west-2c", "us-west-2a", "us-west-2b", "us-west-2c"]}
subset = {"pods": 3, "pod": 1, "copies": 2, "span": [0, 2147483647]}
```

| Key | Value |
| --- | --- |
| `pods` | An integer of 1 to 1,024 |
| `pod` | An integer below `pods` |
| `copies` | An integer of at least 1. Without `groups`, a `copies` at or above `pods` names every node |
| `groups` | Optional: an array of exactly `pods` strings, the name of the group of every ordinal. A name is 1 to 63 bytes, each an ASCII letter, a digit, `-`, `_` or `.`, and two names are the same group when their bytes are equal. Absent or `null`: a pool without groups |
| `skip` | Optional: an integer below 4,294,967,296, absent or `null` for 0. With `groups`, the different names are at least `skip + copies`. Without `groups` its value changes nothing |
| `span` | Optional: an array of exactly two integers below 4,294,967,296, the first and the last span number of the pool, the first not above the last. Absent or `null`: a pool without a span |

Another value is `invalid_request`, also `groups` with fewer different names than
`skip + copies`: an account would have fewer nodes than its copies there, or two of them in one
group. The caller gives such a pool a placement without groups. A `span` of another form is
`invalid_request` as well: a node computes no share from a span it does not read, so a prune with
such a span drops nothing. Keys the object does not define are not read. A node does not know its
own ordinal, its group or the span of its pool: the caller names them. A false value from the
caller makes a node hold fewer grants, never more: the receiving node of a transfer and the node
that prunes still verify every other rule.

The share of a node is the set of the accounts a `subset` selects: those whose assignment under
the placement contains `pod` and, with a `span`, that the span holds.

A node of a release before v2.4.0 reads the three integers and no other key: for an object with
`groups` it computes the assignment without groups, and for an object with a `span` the share of
a pool without a span. A caller therefore sends `groups`, a `skip` that it means and a `span`
only in calls to nodes of release v2.4.0 or later. An object without `groups` and without a
`span` selects the same accounts on a node of every release that reads the key `subset`.

| Call | What `subset` does |
| --- | --- |
| `peer/export` (`pod` is the ordinal of the receiving node, and the placement and the span those of its pool) | The page selects the accounts of the share of `pod` alone, and `limit` counts those. Without the key the page selects every account with a grant, as 10.1 states. The giving node can be a node of another pool than the receiving node: it selects by the placement and the span the call names |
| `peer/import` (`pod` is the ordinal of this node) | A grant of the envelope whose account is outside the share of `pod` is left out: not put in place, no entry, not counted in `imported`. Without the key every grant of the envelope is taken. A giving node of a release without this rule hands every account over, and the receiving node keeps its share all the same |
| `grants/prune` (`pod` is the ordinal of this node; the key is required) | The node walks its accounts in `user_id` order after `after` and drops the grant, within its time or expired, of every account outside the share of `pod`: the user key is overwritten with zeros and the account has no grant, as at the end of a grant. No entry is created (nothing is used: the operator chose which nodes hold a key). A revocation marker and the chain of the account stay. The response lists the `user_id` of every pruned account and the `user_id` the walk continues after, the empty string when it reached the end (enclave.md 5.15) |

A change of the placement of a pool (a node more or less, a group for every node, another
`copies`) or of its span (a pool divided into two, or two pools with adjoining spans made one)
moves delegations in two steps that the caller orders. First every node whose share grows is
filled with the subset of the new placement and span, from the nodes that hold its accounts
(`peer/export` and `peer/import`): a giving node drops nothing. Then the nodes are pruned with
the subset of the new placement and span. Between the two steps an account is on its nodes of
both, so no account has fewer nodes than before at any moment.

Test vectors of the assignment without groups, each as the set of its ordinals; the backend of
the operator computes the same function:

| `user_id` | `pods` | `copies` | `assign` |
| --- | --- | --- | --- |
| `user-1` | 3 | 2 | {0, 1} |
| `00000000-0000-4000-8000-000000000007` | 12 | 2 | {2, 6} |
| `alice` | 5 | 3 | {0, 2, 3} |
| `bob` | 4 | 1 | {1} |
| `사용자 1` | 6 | 2 | {0, 4} |
| `carol` | 2 | 5 | {0, 1} |

With groups, each with the order of its groups and the ordinals in the order the account takes
them (`a`, `b` and `c` stand for `us-west-2a`, `us-west-2b` and `us-west-2c`):

| `user_id` | `groups` | `copies` | `skip` | `group_order` | `assign` |
| --- | --- | --- | --- | --- | --- |
| `user-1` | a, b, c, a, b, c | 2 | 0 | c, a, b | 2, 0 |
| `user-1` | a, b, c | 1 | 2 | c, a, b | 1 |
| `사용자 1` | c, c, b, b, a, a | 3 | 0 | a, c, b | 4, 0, 2 |
| `bob` | `zone_1.a`, `Zone-2`, `zone_1.a`, `Zone-2` | 1 | 1 | `Zone-2`, `zone_1.a` | 0 |

The first two rows are the two pools of one fleet: the account `user-1` has the ordinals 2 and 0
of the first pool, in the groups c and a, and the ordinal 1 of the second pool, in the group b.

The span numbers of the same accounts, and the one of three pools that holds each when the spans
of the pools are `[0, 1431655764]`, `[1431655765, 2863311529]` and `[2863311530, 4294967295]`:

| `user_id` | `span_number` | Pool |
| --- | --- | --- |
| `user-1` | 2,518,581,323 | The second |
| `00000000-0000-4000-8000-000000000007` | 2,233,096,642 | The second |
| `alice` | 4,154,312,765 | The third |
| `bob` | 1,836,545,875 | The second |
| `사용자 1` | 1,136,083,252 | The first |
| `carol` | 3,992,269,495 | The third |

The key `subset` of `protocol/vectors.json` holds these cases and further ones, with the rank
order of every group, `subset` objects with the verdict of their form, and under `spans` the span
numbers, shares with a span and `span` values with the verdict of their form (section 13).

### 10.5 The use of a vault secret in a request

A node of the delegation role holds user keys and connects to the addresses of its provider
definitions and to its log store only. The site of a vault secret is a host the account chose, so
that node does not connect to it. It records the use, and then seals the value, with the one
request the value is for, to a node of the forward role (4.1), which holds no user key and sends
that request.

**The request object.** `vault/handoff` (enclave.md 5.9c) states the request the value goes into,
without the value: a placeholder stands where the value goes.

```text
request = {"method":"POST","host":"api.openai.com","path":"/v1/chat/completions","query":"",
           "slot":"header:authorization","placeholder":"...","body_bytes":0,"body_sha256":""}
```

| Key | Form |
| --- | --- |
| `method` | `GET`, `POST`, `PUT`, `PATCH` or `DELETE` |
| `host` | A host of the form of section 6. The request goes to port 443 of it |
| `path` | Begins with `/`: at most 8,192 bytes of printable ASCII (0x21 to 0x7e) without `?` and `#` |
| `query` | At most 8,192 bytes of printable ASCII without `#`. The empty string for a request without a query |
| `slot` | A slot of a request of section 6: not `field` |
| `placeholder` | 16 to 128 characters of `[A-Za-z0-9_-]` |
| `body_bytes`, `body_sha256` | The length of the body, at most 64 MiB, and the b64u of its SHA-256 (the empty string for a request without a body). The body is the body the caller sends, with the placeholder in it |

The placeholder and the address agree with the slot. For the slot `path` the placeholder occurs
once in the path and not in the query, and the path in front of it does not end with the
beginning of a percent escape, neither as it stands nor with its percent escapes decoded up to
three times. For a slot `query:<name>` exactly one pair of the query (its pairs are the texts that
`&` separates) is the name, `=` and the placeholder, with nothing else, and the placeholder occurs
nowhere else in the address. A query may hold further pairs of the same name beside that one: a
request with them is sent. For every other slot the placeholder occurs neither in the path nor in
the query.

**The envelope.** After the log store confirmed the entry that holds the event `provider_request`
of the use (7.2), the node of the delegation role signs and seals:

```text
payload  = UTF-8(JSON {"v":1,"type":"secret_use","from":<node>,"to":<node>,"time_ms":n,"not_after_ms":n,
                       "nonce":b64u(16),"user_id":"...","record_id":<id>,"value":"...","request":{...}})
signed   = UTF-8(JSON {"payload":b64u(payload),"sig":b64u(Ed25519(giving node key, "pickle.secure.v3.secret-use\n" + payload))})
envelope = JSON {"v":1,"from":<node>,"to":<node>,"enc":b64u(32),"ct":b64u}
enc, ct  = single-shot HPKE to the sealing key of the receiving node,
           info = UTF-8("pickle.secure.v3.secret-use"), aad = UTF-8(from + "\n" + to), plaintext = signed
```

- `not_after_ms` is `time_ms` plus 30,000: an envelope can be used for 30 seconds of the time of
  the giving node. `nonce` is 16 fresh random bytes, the number of the use.
- `value` is the value of the record: at most 12,000 bytes, of which 8 or more are left without
  the characters a server strips at its ends. Those are the white space characters (the Unicode
  property White_Space), the control characters (U+0000 to U+001F and U+007F to U+009F) and
  U+FEFF, the byte order mark: what the function that strips a text removes in one runtime or
  another. The search of the response to its request looks for the value without those
  characters at its ends, and a text of fewer than 8 bytes is not searched for
  (egress-policy.md, rule E4), so no node seals or sends a value with fewer.
- The purpose strings are those of this envelope alone. A node opens a delegation transfer (10.1)
  under other ones, so a node of the forward role has no operation that opens a transfer, and a
  node of the delegation role has none that opens this envelope.
- Before it seals, the giving node verifies the attestation response of the receiving node by
  the rules of 10.1 for a node of its own platform and measurement, and the binding of that
  node has the `role` `forward` (4.1). A node that fails a check is `peer_unverified`. The giving
  node seals to no node of another measurement: a node of the forward role is a node that runs
  the source of the node that opened the record.

**The checks of the receiving node** (`vault/send`, enclave.md 5.16), in this order:

| Check | Failure |
| --- | --- |
| `envelope.v` is 1 | `unsupported_version` |
| `envelope.to` is this node | `wrong_node` |
| `enc` and `ct` are b64u and the HPKE open succeeds | `open_failed` |
| `signed` is JSON with b64u `payload` and `sig`, and `envelope.from` is b64u of 32 bytes | `invalid_request` |
| `sig` verifies under the signing key that `envelope.from` names | `bad_signature` |
| `payload` is a JSON object with `v` 1 and `type` `secret_use` | `unsupported_version`, `invalid_request` |
| `payload.from` and `payload.to` equal those of the envelope | `wrong_node` |
| The form of the fields: the two times, a `nonce` of 16 bytes, a `user_id`, a `record_id` of 16 bytes, a `value` of at most 12,000 bytes with 8 or more of them without the characters a server strips at its ends, a request object | `invalid_request`, `too_large` for a body above 64 MiB |
| The time of the node is before `not_after_ms`, and `not_after_ms` is at most 60 seconds ahead of it | `bad_expiry` |
| The body of the call has the length and the SHA-256 the request object states, and the request of the call is the request of the envelope (below) | `invalid_request`, `not_allowed` |
| The `nonce` was not marked before | `bad_challenge` |

The receiving node does not verify an attestation of the giving node: it holds no secret of its
own, and what an envelope makes it do is send the value inside the envelope to the host inside
the envelope. What the giving node relies on is its own verification of the receiving node.

**One envelope, one request.** Right before the request leaves, the receiving node marks the
`nonce` of the envelope as used, at a node time before `not_after_ms`, and keeps the mark for 60
seconds. An envelope whose number is marked sends nothing. The number is marked also when the
request then fails: the request may have reached the host.

**The request that leaves.** The caller of `vault/send` gives the headers and the body, with the
placeholder where the value goes. The method, the host, the path and the query are those of the
envelope. The node puts the value at the slot and nowhere else:

- The placeholder occurs once in the whole request (the names and the values of the headers, the
  path, the query, the body), and that occurrence is at the slot. A request with the placeholder
  at another place, or with none at the slot, is not sent.
- The value is written in the form of its place: as it is inside a header value (a value with a
  control character is not written there), percent-encoded in the path, in a query parameter and
  in a form field, and as the content of a JSON string in a JSON body.
- `header:<name>`: the header is stated once. The placeholder begins its value or stands behind a
  space, `=`, `:` or `"`. In a header a server reads credentials from (`Authorization`, and every
  header whose name holds that word) the text in front of the placeholder is ASCII and names none
  of the schemes `basic`, `digest`, `negotiate` and `ntlm`, in any case of their letters and at
  any place: behind such a name a server decodes what follows, and may send back bytes the search
  of the response does not find.
- `basic:user`, `basic:password`: the one `Authorization` header of the caller is `Basic`, a
  space and the base64 text of `user-id:password`, and the placeholder is the whole of the half
  the slot names. The node writes the header anew with the value as that half. A value with a
  control character, and for the user-id a value with a colon, is not written. Credentials with
  the placeholder as the other half are not sent: a value its record holds as a password does not
  leave as a user-id.
- `form:<name>`, `json:<name>`: the one `Content-Type` header of the caller is
  `application/x-www-form-urlencoded` for a form slot and a JSON type (`application/json`, or a
  type whose subtype ends with `+json`) for a JSON slot, it states no `charset` but UTF-8, and the
  caller states no `Content-Encoding`. For a form slot exactly one pair of the body is the name,
  `=` and the placeholder, with nothing else, as in a query for its slot: a body may hold further
  fields of the same name beside that one. For a JSON slot the placeholder is the whole content of
  the string member the name leads to, written without an escape; a body in which one object
  names that member, or an object on the way to it, twice is not sent.
- The node drops these headers of the caller: `host`, `content-length`, `transfer-encoding`,
  `connection`, `keep-alive`, `proxy-connection`, `upgrade`, `te`, `trailer`, `expect`,
  `accept-encoding`, `proxy-authorization`, `range`, `if-range` and `accept-charset`. It writes
  the host and the framing of the body itself, asks for the coding `identity` and for the whole of
  a response, and says `Connection: close`.
- The node refuses a call that carries one of these headers, with `not_allowed`:
  `x-http-method-override`, `x-http-method`, `x-method-override`, `forwarded`, `x-forwarded-host`,
  `x-forwarded-server`, `x-forwarded-uri`, `x-forwarded-prefix`, `x-original-url`,
  `x-original-uri`, `x-original-host`, `x-rewrite-url`, `x-host` and `x-http-host-override`. Such a
  header asks a server to treat a request as one of another method, or as one to another host or
  path, than the entry of the use names. An `Accept` header that names another character encoding
  than UTF-8 is refused the same way.
- A header name is compared in lower case and with `-` for every `_`: some servers read the two
  characters as one. No slot names a header of the two lists.

The request goes to port 443 of the host over TLS that ends inside the node, with a certificate
verified for that host, on a connection that carries this one request. The node follows no
redirect. The response passes rule E4 of the egress policy before any part of it is handed on
(egress-policy.md).

## 11. All failure codes (node)

| Code | Meaning |
| --- | --- |
| `invalid_request` | A violation of a form, a length or a required key. A call of a path that is not defined and a call with a method that is not allowed have this code too |
| `unsupported_version` | `v` is not 1 (envelope, command, record) |
| `wrong_node`, `open_failed`, `bad_signature`, `bad_challenge`, `bad_expiry`, `unsupported_policy`, `custody_mismatch` | Failures of command processing (5.3). `custody_mismatch` means that the `custody` of the grant is not the custody of the platform of that node |
| `peer_unverified` | The attestation response of a peer does not verify, or its platform, its measurement or its log store is not one this node accepts (10.1). The release proofs of a peer of another release fail a check of 9.4, or the binding of that peer names another release than their statement (10.3). The node a use of a vault secret is to be sealed to is not a node of the forward role of the measurement of this node (10.5) |
| `user_mismatch` | The `user_id` of a command is not the account of the call (5.3). The `user_id` of a record is not the account of the call (section 6). The account of a pending authorization is not the account of the call |
| `internal` | A failure of the platform (the attestation device, the random source), or a call that needs the state of an account the node halted after a fault (enclave.md 3.1). The call performed no act, and another node that holds the delegation of the account can take it |
| `not_configured` | The operator configuration has not arrived yet |
| `closing` | The orderly shutdown has started |
| `grant_required` | The account has no grant |
| `grant_revoked` | The account revoked its delegation |
| `grant_expired` | The time of the grant has passed |
| `key_mismatch` | The `key_id` or the `custody` of a record is not that of the grant. The `sign_pk` of a pending authorization is not the `sign_pk` of the grant |
| `record_invalid` | The form of a record is wrong (a `ct` of more than 87,403 characters included), or its AEAD verification failed. The plaintext lacks the field that the call uses (no token to inject, no `refresh_token` to refresh with). The plaintext of a token record is above what a node reads (section 6: the room of a token object, a token of more than 16,384 bytes): a call that creates an entry ends with this code behind its confirmed entry, with the message `the plaintext of the record is above what a node reads; nothing was sent` |
| `provider_unknown` | The provider has no definition |
| `not_allowed` | An address, a method, an authorization parameter or a field that the provider definition does not allow. A record of a kind that the call does not take. A use of a vault secret outside the reach of its record: an origin, a host or a slot the record does not list (section 6, 10.5). A call that the role of the node does not answer (enclave.md section 4: a node has one of three roles) |
| `state_unknown` | There is no pending authorization, or its time (600 seconds) has passed |
| `exchange_failed`, `refresh_failed` | The provider refused the exchange or the refresh, or answered with a response a node does not take as a token object or makes no record of (8.3). The failure carries the HTTP status of the provider and one word of a closed vocabulary for the error of its response (enclave.md 5.7) |
| `provider_unreachable`, `timeout` | A transport failure, a time limit that passed |
| `response_withheld` | A provider response failed a check of rule E4 of the egress policy (egress-policy.md) and was not handed on. A repeated call does not change the outcome |
| `too_large` | A body above the limit (64 MiB each for a request and a response; for `forward/batch`, the bodies of the results together; 1 MiB for a JSON body). A request, the JSON body of a call or the meta of a frame, whose share of the budget of the node would be above the largest share of one request (enclave.md section 8: 64 MiB, and 256 KiB for `attestation` and `messages`): the node does not parse it, and the message is `the request takes more room than a node gives one request`. An event that no entry can hold (7.1) |
| `log_store_unavailable` | The log store did not confirm the entry of the call, or the node cannot write to it: it has no log store in its configuration, no credentials within their time, or no node document in the store (7.6, 7.7). The act of the call did not take place. A repeated call can succeed |
| `capacity_unavailable` | The node has no room for the call. A `forward`, `forward/batch` or `vault/send` call was not admitted within its wait, or a mail call could not take its place or the first part of its share of the body budget at once: no credential was opened and no provider request was sent. A call with a JSON body did not get the share of its request within its wait (enclave.md section 8: of the body budget, and of the command budget for `attestation` and `messages`): the node parsed nothing of the request, created no entry and sent nothing. A `refresh` or an `oauth/complete` did not get the share of what it holds of the token response within that wait: no entry was created, no provider was called, and the authorization of an `oauth/complete` is not used up. A `mail/read` also ends with this code while it reads, when the body budget has no room for its input (the message `the node has no room for the mail the call reads; the call changed nothing`): that call has its entry, read from the mailbox and changed nothing in it (enclave.md, "Mail call surface"). A node of the forward role also answers a `vault/send` with this code when it holds the marks of as many used envelopes as it keeps (10.5): no request was sent, and the envelope stays unused. A later call can succeed |

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
| Sum of the kept `refresh` responses of a node over every account, above which the node drops the ones it kept first (`REFRESH_KEPT_BYTES`, enclave.md 5.7) | 512 MiB of what the node counts for them: for each the bytes of its body and of the `user_id` of its account, a quarter more, and 384 bytes |
| Longest time a node keeps receiving the response of a token address call of `refresh` after the time limit of the call, counted from the start of the call (`TOKEN_LATE_LIMIT`, enclave.md 5.7) | 120 seconds |
| Token address calls of `refresh` a node continues after their time limit at once (`REFRESH_LATE_TASKS`) | 128 |
| Most accounts in one delegation transfer | 1,000 |
| Most nodes of another release that a node hands one grant to (10.1) | 64 |
| Nodes a delegation subset names (`pods`, 10.4) | 1 to 1,024 |
| Nodes per account of a delegation subset (`copies`, 10.4) | Without `groups`: 1 to `pods` (a larger value names every node). With `groups`: at least 1, and `skip + copies` at most the number of different group names |
| Longest name of a group of a delegation subset (10.4) | 63 bytes |
| Span numbers of a delegation subset (`span_number` and the two ends of `span`, 10.4) | 0 to 4,294,967,295 |
| Most pruned accounts in one page of `grants/prune` (10.4, enclave.md 5.15) | 1,000 |
| Most accounts one `grants/prune` call looks at (`SCAN_LIMIT`) | 10,000 |
| Longest release statement (9.1) | 16,384 bytes |
| Longest `statement` of release proofs before it is decoded (9.4) | 32,768 UTF-16 code units |
| Longest attestation of release proofs, as JSON without white space (9.4) | 65,536 bytes |
| Most arrays and objects inside one another of a JSON value of release proofs (9.4) | 32 |
| Most arrays, objects and commas, counted together outside its strings, of a JSON text inside a string of release proofs that a node reads (`RELEASE_TEXT_MARKS`, 9.4) | 1,024 |
| Most hashes of the audit path of the inclusion proof of a log entry (9.4) | 64 |
| Most events in one entry (`ENTRY_EVENTS`) | 128 |
| Most bytes of the plaintext of one entry (`ENTRY_PLAINTEXT_BYTES`) | 1,048,576 |
| Events of GET requests without a body that a node remembers for one account at one time (`MERGE_KEYS`, 7.2) | 8,192 |
| Most requests in one forward batch (`FORWARD_BATCH_REQUESTS`) | 100 |
| Requests of one forward batch in flight at once (`FORWARD_BATCH_CONCURRENCY`) | 6 |
| Provider requests of a node in flight at once (`PROVIDER_INFLIGHT`) | 512 |
| Idle connections of a node to its log store, and their idle time (`LOG_STORE_IDLE_CONNECTIONS`, `LOG_STORE_IDLE_MS`) | 32, 30 seconds |
| Idle connections of a node to one provider host for one account, and their idle time (`PROVIDER_IDLE_CONNECTIONS`, `PROVIDER_IDLE_MS`) | 8, 30 seconds |
| Authenticated IMAP sessions a node keeps between the reads of a record: per record and per node, the time one is kept after its last read, and the longest time after its login at which one is handed to a read (`KEPT_SESSIONS`, `SESSION_IDLE_MS`, `SESSION_LOGIN_MS`, enclave.md, "Mail call surface") | 1 and 1,024, 30 seconds, 300 seconds |
| Pending entries of an account at which a call that uses a credential creates no entry (`PENDING_ENTRIES`) | 64 |
| Interval of the sweep of a node, which writes the pending entries of every account again (`SWEEP_INTERVAL`) | 30 seconds |
| Retention of an object of the log store (Object Lock), expiry of the bucket lifecycle (`LOG_RETENTION_DAYS`, `LOG_EXPIRY_DAYS`) | 365 days from the node time of the write, 400 days |
| Buckets of a log store, by the bucket name of the binding (7.6) | 1,024 for `character-credential-log-prod-1`, 4 for `character-credential-log-local-1`, 32 for every other name |
| Longest bucket name of a binding that a node takes as its log store (`LOG_STORE_NAME_CHARS`, 7.6) | 49 characters |
| Retention of a node document, the age of its latest confirmed write at which a node writes it again, and the age up to which a node takes a user key and writes an entry (`NODE_DOCUMENT_RETENTION_DAYS`, `NODE_DOCUMENT_RENEW_DAYS`, `NODE_DOCUMENT_VALID_DAYS`, 7.7) | 400 days, 30 days, 31 days |
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
| `PROOF_BUILDERS` (the app) | One element, `.github/workflows/enclave-build.yml` at the commit `e522d06d8388bee590678963f8940cd7a2b69f5c`: the build workflows whose job the program takes as the signer of an attestation, each by the path of its workflow file and the commit of that file ("The release proofs", and 9.3). The workflow that called the job is not judged |
| `PROOF_STATEMENT_BYTES`, `PROOF_ATTESTATION_BYTES`, `PROOF_PATH_HASHES`, `PROOF_JSON_DEPTH` (the app) | 16,384, 65,536, 64 and 32: the bytes of a release statement, the bytes of the attestation of release proofs as JSON without white space, the hashes of its audit path, and the arrays and objects inside one another of a JSON value of release proofs (9.4, "The release proofs") |
| `PROOF_ROUND_REQUESTS`, `PROOF_SEEK_RETRY_MS` (the app) | 4 and 5 minutes: the requests to the backend for release proofs one step of the grants or one round sends at most, each for one measurement, and the time after an answer that showed no proofs that hold before a runtime asks for that measurement again (a request that was not answered is sent again by the next step or round: "The release proofs") |
| `PROOF_REFUSED_KEPT`, `PROOF_REFUSED_CHARS` (the app) | 8 and 131,072: the measurements for which a runtime remembers the release proofs it refused last, which it does not verify a second time, and the characters of the JSON of such proofs up to which it remembers them |
| `PROOF_KEPT_VERDICTS` (the app) | 256: the measurements whose verdicts of release proofs the device keeps. Beyond that number the verdict made longest ago leaves first, and a verdict that left is made again when the device meets the measurement again ("What the device keeps") |
| `LOG_BLOCKED_ROUNDS`, `LOG_BLOCKED_MS`, `LOG_REACH_MS`, `LOG_URL_FRESH_MS` (the app) | 3 and 3 days: the rounds in a row whose reads were held back (or the reads of one kind the log screen notes as held back from it), and the age of the first of them, at which the log is marked (A3). 60,000: a request that was not answered counts as held back when the backend answered another request of the runtime within this time. 240,000: the age of a signed address from which a refusal of the store is the age of the address |
| `LOG_RETENTION_DAYS` (the app) | 365: a key older than this is expected by no reader (the retention of its lock), and a key is expected in the listing while it is a day younger (A4) |
| `LOG_SAMPLE_KEYS`, `LOG_SEEN_PART`, `LOG_SEEN_PARTS`, `LOG_SEEN_KEYS`, `LOG_NODES_KEPT` (the app) | 64: the control keys of the sample of A4. 4,096, 9 and 32,768: the digests of the control keys the device judged are kept in parts of 4,096, nine parts at most (when one more begins, the oldest leaves), so the device remembers 32,768 judgements or more. 256: the nodes whose judgement the device keeps |
| `LOG_SCREEN_EVENTS`, `LOG_KEEP_EVENTS`, `LOG_SCREEN_WAIT_MS`, `LOG_SCREEN_REFILLS` (the app) | 50, 50 and 3,000: the events of one further page of the log screen, the events of the first page the device keeps, and the time `read_log` waits for the read of the store before it answers from what the device kept. 2: the times a page is read on below keys that turned out to be no entries |
| `LOG_PAGE_READS`, `LOG_CATCHUP_READS`, `LOG_SCREEN_KEYS` (the app) | 4: the requests that read the listings of the screen on for one later page. 16: the requests that read them on at one opening of the screen down to the later pages noted as held back. 20,000: the keys of the two listings the screen holds in a runtime (a page below them is listed from the marker of its time) |
| `LEGACY_SCREEN_LISTS`, `LEGACY_DISPLAY_LIST`, `LEGACY_HEAD_PAGES`, `LEGACY_ANCHOR_WALKS` (the app) | 12: the listings of chains of formats 1 and 2 one call of the log screen reads. 1,000: the `seq`s of one range of a chain the screen lists. 4: the pages of the listing of the end of a chain an opening reads before a listing without an end is noted as held back. 3: the times one call walks the chains because a chain stood on a `seq` that holds no entry of its node |
| `VAULT_MADE_NAMES` (the app) | 8: the names of the vault items `store_secret` made and that hold no value yet that the device keeps |
| `LOG_SUMMARY_DAYS`, `LOG_SUMMARY_ENTRIES`, `LOG_SUMMARY_REQUESTS` (the app) | 7, 1,000 and 5: the days of the summary of the log screen, the most entries one opening counts into it, and the requests for bodies one opening of the screen sends |
| `LEGACY_NODES`, `LEGACY_ROUND_PASSES`, `LEGACY_ROUND_BODIES`, `LEGACY_CLOSE_SLACK_MS` (the app) | 64, 32, 512 and 1 day: the chains of formats 1 and 2 one round follows (of more open chains, the ones a round listed longest ago), the passes of listings and the entry bodies it spends on them (one request for the documents of receiving nodes per pass; the receiving nodes that wait for a document count into the entry bodies of a round), and the time after the end of a grant at which the chain of its node is read for the last time |
| `LEGACY_SCREEN_PASSES`, `LEGACY_ROW_ENTRIES` (the app) | 2 and 16,384: the passes over the chains of formats 1 and 2 a round the log screen started makes at most, and the entries the rounds open on those chains (what 32 rounds open) beyond which a round that leaves reads of its chains undone is a round whose reads are held back ("Formats 1 and 2") |
| `LEGACY_SEQ_READS`, `LEGACY_PROBE_SEQS`, `LEGACY_SEQ_VERSIONS` (the app) | 8: the object versions a round reads under one `seq` of a chain for a control entry, and the log screen for an entry. 2: the `seq`s at the end of a listing page of a chain that a round reads to see how far the node wrote, when their keys name no control entry. 5: the object versions per `seq` a listing page of a chain that goes on holds at most, on average, when it holds what a node wrote and no more |
| `LEGACY_TRANSFER_DOCUMENTS_FROM_MS` (the app) | 1,795,392,000,000 (2026-11-23T00:00:00Z): for an event of this time or later, the receiving node of a transfer that a node of a release before v2.4.0 made is judged by a document that verifies and by nothing else ("Formats 1 and 2") |
| `LOG_STORE_CONCURRENCY`, `LOG_STORE_OBJECTS` (the app) | 8 and 100: the reads of the bucket of formats 1 and 2 in flight at once, and the object versions one address request names |
| `LOG_STORE_ATTEMPTS`, `LOG_STORE_RETRY_MS` (the app) | 2 attempts of one request to the store, a pause of 500 milliseconds between them: a transport failure, a 429 and a 5xx status are tried again |
| `OUTCOME_BOUNDS_MS`, `OUTCOME_EVENTS`, `OUTCOME_SLOW_MS` (the app) | 250, 1,000, 3,000, 10,000 and 30,000: the upper bounds of the classes a time of a procedure is counted into. 32: the calls a report carries one by one. 10,000: the time from which a call is reported one by one |
| Longest token a node handles (`TOKEN_BYTES`, section 6) | 16,384 bytes |
| Longest plaintext of a record a node opens or creates, and the longest `ct` of a record (`RECORD_PLAINTEXT_BYTES`, `RECORD_CT_CHARS`, section 6) | 65,536 bytes, 87,403 characters |
| Most memory the parsed form of a token object may take, by the count of section 6 | 262,144 bytes |
| Longest response of a token address a node reads, and the most memory its parsed form may take by the count of section 6 (8.3) | 1,048,576 bytes, 1,572,864 bytes |
| Longest string a node keeps of the response of a token address beside its tokens, and longest name of a member it keeps (8.3) | 8,192 bytes |
| Hosts in `sites`, slots in `slots` of a record of kind `vault_secret` (section 6) | 1 to 8, 1 to 4 |
| Longest name of such a record, longest name inside a slot | 64 characters, 64 bytes |
| Longest `value` that `vault/store` takes, longest plaintext of a record it makes | 12,000 bytes, 12,272 bytes |
| Lengths a device pads the plaintext of a record of kind `vault_secret` to | 256, 512, 1,024, 2,048, 4,096, 8,192 and 12,272 bytes |
| Value of a vault secret that is used in a request (10.5) | At most 12,000 bytes, 8 or more of them without the characters a server strips at its ends (white space, control characters, U+FEFF) |
| Time an envelope of a use of a vault secret can be used, time a node keeps the mark of a used one | 30 seconds, 60 seconds |
| Marks of used envelopes a node of the forward role keeps at once | 1,048,576 |
| Placeholder of a request (10.5) | 16 to 128 characters |
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
| `log_v3` | Format 3: the node signing public key and `node`, `user_id`, `key_id`, `log_private`, `log_pk`, the HPKE info and the signature purpose as text, the two prefixes of the account, `entries` (four entries of one node: a control entry `grant_accepted`, a use entry with three `provider_request` events, a use entry with one `secret_released` event, a control entry `grant_transferred_out` to another release; each with `seq`, `hpke_seed`, `time_ms`, `kind`, `count`, `events_text`, `entry`, `body_text`, `body_hash`, `key`), `control_listing` and `use_listing` (the keys of each prefix in the order of a listing), `verifies`, `rejected` (three objects that are not the entry of their key: the body of another entry, the signature of another node, a key of another `seq`; each with `key`, `entry` and `result`: `body`, `signature` or `fields`), `not_keys` (strings that are no keys of format 3 of the account) with `a_key_of_not_keys_parses` false, and `node_document` (the `key`, the `bucket`, the `nonce` and the text in front of the key in its hash, `binding_text`, `document_text` and `object_text` of a node document of platform `local`, `accepted`, and `rejected`: a document with another nonce, an object with another release, the object read as the document of another node) | Every key parses to the parts of its entry, every entry verifies against its key (7.4) and opens to `events_text`, an entry created with the same `hpke_seed` equals `entry`, the listings are in the order of the bytes of the keys (the latest entry first), the objects of `rejected` fail with their `result`, no string of `not_keys` is a key, and the node document reads as `accepted` says (7.7) |
| `log_store` | `stores` (five log stores by the bucket name of their binding: `bucket`, `region`, `host`, `shards`, `first_bucket`, `last_bucket`, and `owners`: for three `user_id` values and one node identifier the `hash`, the `index` and the `bucket`), `longest_name` (a bucket name of 49 characters and its first bucket), `name_without_buckets` (a bucket name of 50 characters: `first_bucket` is null) | The number of buckets, their names and the bucket of every owner follow from the bucket name of the binding by 7.6 |
| `log` | Format 2: the node signing public key, `user_id`, `key_id`, `log_private`, `log_pk`, `checkpoint`, `entries` (three entries: a control entry `grant_accepted`, a use entry with three `provider_request` events, a use entry with one `secret_released` event; each with `seq`, `hpke_seed`, `time_ms`, `kind`, `count`, `events_text`, `entry`, `body_text`, `body_hash`, `entry_hash`, `key`), `head_nonce`, `head`, `final_head`, `index_valid` (the keys alone verify to the head), `content_valid`, `missing_middle` (the keys without the middle one: `index_valid` false), `forged_key` (the keys with one more key of `seq` 2 whose `body_hash` is another and whose `entry_hash` is consistent with it: `ambiguous_seq` 2, and the content verification takes the genuine object alone) | The index verification of the keys and the content verification of the entries give these results, every entry opens to `events_text`, and an entry created with the same `hpke_seed` equals `entry` |
| `log_v1` | The vector `log` of format 1 as the releases before v2.0.0 wrote it: the node signing public key, `user_id`, `key_id`, `log_private`, `log_pk`, `checkpoint`, `entries` (three entries: `seq`, `hpke_seed`, `time_ms`, `event_text`, `entry`, `entry_hash`), `head_nonce`, `head`, `final_head`, `chain_valid`, `missing_middle` | A reader of format 1 verifies the chain with the same result and opens every entry to `event_text` |
| `attestation.local` | `nonce`, `response` (with its `challenge_statement`), `document_text`, `binding` (of a node without a log store: it has no `log` key), `sign_pk`, `seal_pk`, `release`, `challenge_statement_text` (the body of the statement), `accepted`, `rejected`: another nonce, a binding of version 2, and four responses with the accepted document and nonce that fail for the challenge statement alone (the statement is missing, it is the statement of another request, of another challenge, of another node) | The result of the verification of a local document and of its challenge statement (4.2, 4.4) |
| `attestation.nitro` | `included` (bool). When it is true: a real Nitro document, its nonce and the expected `binding`. In the committed file it is false, and a `note` states that the file holds no Nitro document | Nothing while `included` is false. Real Nitro documents are inputs of the tests of this repository (`protocol/tests/fixtures/`, `verify/tests/fixtures/`) |
| `totp` | A list of `seed_base32`, `time_ms`, `code` | RFC 6238 |
| `vault_secret` | A record of that kind (`id`, `nonce`, `plaintext`, `aad_text`, `record_key`, `record`), and the verdicts of the form rules of its plaintext: `names`, `hosts` and `slots` (lists of `text` and `valid`), `reserved_headers` (the slot of every header no slot names) and `reaches` (lists of `sites`, `slots` and `valid`) | A reader of a name, a host, a slot and a reach gives the verdict `valid` on every case. A node, an app and the caller of a node read these four forms, and all of them pass with this file |
| `sealed_release` | A `release` call that named a key to seal to: `receiver_private` and `seal_to` (the key pair of the caller), `hpke_seed`, `user_id`, `record_id`, `field`, `origin`, `info_text`, `aad_text`, `value_text` and `sealed` | `sealed` opens with `receiver_private` to `value_text`, and does not open under another `aad` |
| `basic_credentials` | `placeholder_text`, `value_text` and `cases`: values of an `Authorization` header (`authorization_text`) with the `slot` of the half the placeholder is (`basic:user`, `basic:password`, or null for a header a node sends under neither), and `written_text`, the header a node of the forward role writes for the value | The caller of a node tells from a header which of the two slots it is |
| `header_values` | `placeholder_text`, `refused_schemes` and `cases`: values of the header of a slot `header:<name>` with `valid`, whether a node of the forward role puts the value in the place of the placeholder (10.5) | The same |
| `subset` | `cases`: a pool of `pods` nodes with `copies` nodes per account, `skip`, and with or without `groups`, each with `assign`, the ordinals that hold the delegation of `user_id` in the order the account takes them; without `groups` also `ranked`, every ordinal in the order of its rank; with `groups` also `group_order`, the groups in the order of the account, and `group_ranked`, the ordinals of each of those groups by their rank. `pools`: the placements of two pools with the same groups (`calls`: `copies` 2, `skip` 0; `reserve`: `copies` 1, `skip` 2) and, for six accounts, the nodes of the account in both and the three groups of those nodes. `objects`: `subset` objects of a request, each with `valid`. `spans`: `numbers`, the `number` of the span of six accounts; `contains`, `subset` objects with and without a `span`, each with a `user_id` and whether the share of `pod` holds that account (`contains`); `fleet`, the spans of three pools that divide the span numbers (`pools`) and the one pool of each of the six accounts (`accounts`); `objects`, `subset` objects with a `span`, each with `valid` | A node and the backend of the operator compute `assign` for every case (10.4): the node to select the share of a node, the backend to list the nodes of an account. The nodes of an account in the two pools lie in three different groups. A node reads an object with `valid` true and answers `invalid_request` to one with `valid` false. Both compute `number` for every account of `spans`, and `contains` from the span and the assignment: the node to select the share of a node of a pool with a span, the backend to name the pool of an account. Every account of `fleet` is in the span of its pool and in no other |
| `transfer` | The keys of the giving node and of the receiving node, `payload_text`, `signed`, `envelope`, `hpke_seed`, the result that the receiving node opened (`grants`), and `cases`: an envelope with a changed ciphertext (`opens: false`), a transfer signed by another key (`signature_valid: false`), an envelope for another node | A receiving node implementation opens the envelope and obtains the same list of grants (10.1) |

Of these, the tests of the app use `key_derivation`, `record`, `signed`, `log` and
`attestation.local`. Opening a `command` and computing a `totp` code are the work of a node. The
tests of the app open the envelopes that the app created themselves and check them.

`protocol/vectors/release-proofs.json` holds the shared cases of the release proofs (section 9):
the file that holds the verifiers of this repository to one verdict. Every implementation of the
checks of 9.4 must give the verdict the file states on every case: the node implementation,
whose test `protocol/tests/release_proofs.rs` reads the file, and `proveRelease` of the secure
program of the apps.
`protocol/vectors/release_proofs.py` writes the file from fixed keys and with deterministic
signatures, so the same script gives the same bytes, and its option `--check` fails when the
committed file differs ([protocol/vectors/README.md](../protocol/vectors/README.md)). The script
shares no code with a verifier. The top level is
`{"v":1,"description":...,"trusts":{...},"cases":[...]}`:

| Key | What it holds |
| --- | --- |
| `trusts` | The values of a verifier (9.3), by a name: `fulcio_root` and `fulcio_intermediate` (the DER of the two certificates, b64u), `log_keys` (the DER of the SubjectPublicKeyInfo of each log key, b64u), `issuer` (the issuer of the tokens), `repository`, `repository_id`, `owner_id`, and `builders` (the list of build workflows). The keys behind the values of `test` and of the trusts whose names begin with `test-` are keys of the script, which signs the certificates, the envelopes and the entries of their cases with them. The two trusts whose names begin with `sigstore-` hold the two certificates of the certificate authority of Sigstore and the key of Rekor with a list of build workflows that is not the one of this source: `sigstore-build-workflow-v2.4.0-rc.1` names the build workflow at the commit whose job attested the release candidate `v2.4.0-rc.1`, and `sigstore-release-workflow-v2.3.0` names the release workflow of the tag `v2.3.0` at the commit of that tag. The name `source` is not a member of `trusts`: it stands for the values of the verifier itself, the certificates of Sigstore, the key of Rekor and the list of build workflows of this source |
| `cases` | Per case: `name`, `trust` (a name of `trusts`, or `source`), `measurement` (`pcr0`, `pcr1` and `pcr2`: the measurement the proofs are verified for), `release_proofs_text` (the JSON text of `release_proofs`. It is a text so that a case can hold what a parsed value does not: a member that occurs twice, a number outside the finite ones, a text that is no JSON), `accepted`, `release` (the `release` of the statement of an accepted case, null for a refused one) and `rule` (null for an accepted case, and for a refused one the check of 9.4 that refuses it: `form`, or `V1` to `V7`) |

A verifier parses `release_proofs_text` with its own reader of JSON, and a text that reader
refuses is a case of the rule `form`. Under a trust whose two certificates are not the root
certificate and the intermediate certificate of one certificate authority, every case is refused
at `V3`. A verifier gives `accepted` on every case, and the check at which it refuses a case is
the `rule` of the case. The cases hold proofs that pass and, for the form and for each of the
checks V1 to V7, proofs that fail it and proofs at its bounds. The cases that no key of the
script signs are made of the published proofs of three releases of this repository, whose files
are in `protocol/vectors/published/`. The job of the build workflow at the commit the list of
this source names attested the release candidate `v2.4.0-rc.2`. The job of the build workflow
attested the release candidate `v2.4.0-rc.1` at a commit of the workflow file that the list of
this source does not name (9.3), and a job of the release workflow of its tag attested the
release `v2.3.0`. Under the trust `source` the proofs of the release candidate `v2.4.0-rc.2`
pass, and the same proofs with one place changed are refused by the first check the change
breaks, or pass where no check reads the changed place (the `inputs` of the statement); the
proofs of the release candidate `v2.4.0-rc.1` and of the release `v2.3.0` are refused at `V6`.
Under the trust `sigstore-build-workflow-v2.4.0-rc.1` the proofs of the release candidate
`v2.4.0-rc.1` pass, and under the trust `sigstore-release-workflow-v2.3.0` those of the release
`v2.3.0`; under either, the proofs of the release candidate `v2.4.0-rc.2` are refused at `V6`.


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

Every mail call has its own event. A node keeps the authenticated IMAP session of a read for
the next read of the same record, for at most 30 seconds between two reads and 300 seconds
after its login, so a read does not always log in. A read that goes over a kept session
creates its event and waits for the confirmation of its entry like a read that logs in, and
takes the session only then: the reads of an account that reached its mailbox are the
`mail_request` events of operation `read` on its chain, whether or not each of them logged in.

A node reads the plaintext of a mail record after that confirmation, and not before. What it
judges before it creates the event is the same for every value the record can hold: the grant,
the AEAD verification, the kind and the provider of the record, and the form of the request. A
plaintext that is no JSON object, a `username` that is no NAVER account name, and a `password`
shorter than 8 bytes, longer than 256 bytes or with a control character are `record_invalid`
after the entry; a submission whose `From` field is not the account of the record is refused
after the entry as well (enclave.md, "Mail call surface"). In both cases nothing goes to the
provider, and the entry stays on the chain as the entry of a mail call that did not take place.
So no answer of a mail call depends on the content of a record unless an entry records the call.

## The program of the app

This section states what the secure program of this repository (`secure-program/secure-program.js`,
from version 43 on) does on a device: the order of its work and its time limits, the
synchronization that hands the grants, the settings of the delegation and the key of the account,
how it reads and judges the log, what it shows on the log
screen, what it reports, and the procedures of the vault secrets. "The app" of sections 3 to 7 and
10 is this program. The formats, the commands and the verifications it applies are those of the
sections named in each part. Every number of this section is a constant of the program.

### The lines, the locks and the time limits

The work of the program runs on three lines. A line runs one piece of work at a time, in the order
of the calls, and the lines do not wait for one another.

| Line | What runs on it |
| --- | --- |
| The procedures a user starts | `create_key`, `reset_key`, `connect`, `set_connection_writes`, `manage_repositories`, `connect_app_password`, `begin_app_password_setup`, `cancel_app_password_setup`, `store_login`, `store_card`, `store_secret`, `reveal_secret`, `update_secret`, `delete_secret`, `reveal_login_password`, `set_grant_days`, `set_delegation`, the five procedures of the master key transfer and the steps of its polling |
| The synchronizations | The procedure `sync` and the synchronization an event starts. A synchronization holds the line until its grants are handed (steps 1 to 6 of "The synchronization"): one hands its grants and at most one waits for that, and a trigger that arrives while one waits is served by the one that waits |
| The reads of the log screen | The read of the first page that `read_log` starts, `read_log_page` and `read_security_record` |

Two locks protect what two lines could change at once. The lock of the grants holds from the
judgement of the key to the record of the replies of the grant commands: a synchronization, and a
procedure that makes sure a node holds the grant before it connects or stores, do not overlap in
that span. The lock of the round holds one round of the log. Whoever holds a lock waits only for
requests, and every request has a time limit. What follows the grants in a synchronization
(step 7: the sealing of earlier values and the completion of a mail setup) runs one
synchronization at a time on a line of its own, beside the line of the synchronizations.

| Limit | Value |
| --- | --- |
| A request to the backend of a round or of the log screen | 10 s |
| The request a round sends at its end for the body of one big key ("The round") | The time its size takes at 8,192 bytes a second: 10 s at least, 240 s at most |
| A request to the log store (two attempts: a transport failure, a 429 and a 5xx status are tried once more after 0.5 s) | 10 s per attempt |
| Any other request to the backend, and a command to a node through the relay route | 30 s |
| One procedure, from its call to its end | 100 s |
| One round, from its start | 60 s, and on top of it the time of the requests for big keys at its end (240 s at most) |

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

A request is sent once. The requests of three kinds are sent once more, 0.5 s after an answer
that fails for a moment (a failure of the transport, the status 429, a status of 500 to 599; a
request that ran out of its time is not sent again):

- the two requests at the front of a synchronization and of a procedure that needs the grants:
  the account query and the list of the nodes ("The synchronization");
- the reading of the sealed ledger of the backend ("The settings of the delegation");
- the requests of a procedure that follow what the user did in it, so that one answer of a
  backend that is being deployed does not throw that away: the completion query of a connection
  after the web session returned; the request that stores the value the user entered for a vault
  item, and, for an item the call made, the query of that item before it; and the query of
  `reveal_secret` after the device owner authentication. The request that makes a vault item is
  not among them: sent twice, it could make two items.

No other request is sent twice, so a backend that is down is not asked double. The reads of the
log follow rules of their own ("The round").

### The events

| Event | What the program does |
| --- | --- |
| `session_ready` | Clears the state of a master key transfer (a runtime does not take over the transfer of the runtime before it), publishes whether the build has the protected sheets, `runtime.named_secrets` as false and `runtime.log_rounds` as true ("The synchronization"), publishes the log as pending when this program has ended no round on the installation (the state an earlier program published is not a judgement of this one), counts the calls the runtime before left open as interrupted, judges the measurements the device kept (A1, "The round"), and starts a synchronization |
| `foreground` | Judges the measurements the device kept (A1) and starts a synchronization |
| `background` | Ends the reading of the round that runs: the round is judged on what it read and writes what it kept within the event ("The round"). Judges the measurements the device kept (A1), and notes the time for the calls that are open (the report of the outcomes) |
| `push` | With the reason `transfer_request`: reads the pending requests of a master key transfer. With any other reason: judges the measurements the device kept (A1), starts a synchronization and, when it ended, sends the report of the synchronization. A synchronization of the reason `grant_required` hands a grant again to a node the backend reports no grant for (below) |
| `account_end` | With the reasons `account_deleted` and `dev_reset`: deletes the master key item, the node ledger and the reception key of a mail setup from the key store, and everything the program store holds of the account. Work that is still running writes nothing of the account after that |

A synchronization the app itself triggers (`session_ready`, `foreground`) within 5 s of the start
of the one that began last, while that one has not ended, is served by that one.

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
   served program"). Each of the two requests is sent once more after an answer that fails for a
   moment ("The lines, the locks and the time limits").
2. The judgement of the key: the master key of the key store against the `key_id` registered on
   the account (`absent`, `waiting`, `present`, `mismatch`, `account_mismatch`). A device with a
   master key registers its public keys when the account has none. A device without a master key
   whose account has a key waits for that key from another device (`waiting`), unless the key is
   one `create_key` made on this device and never wrote to the key store: no device holds such a
   key, and the state is `absent` ("The key of the account").
3. With the key `present` and delegation on, a listed node receives a grant when one of these
   holds: the device keeps no grant of it; the last grant the device handed it is the renewal
   interval old (the smaller of 24 hours and half of the lifetime of a grant); or the
   synchronization was started by a push of the reason `grant_required`, the backend reports no
   grant for the node (`not_after_ms` null), and the last grant the device sent it is 60 s old.
   What the backend reports decides nothing else: when a grant was handed and when it ends is what
   the device kept. A node the list marks `revoke_only` is none of these nodes.
4. When a node is to receive a grant, the program requests the attestation of those nodes only
   (`GET /api/secure/nodes` with `nonce` and `nodes`, the ids joined by commas, 32 per request),
   verifies each (4.3 and the next part), and sends the grant commands together (5.2). For a
   node whose document verifies with a measurement no list has and no release proofs showed,
   the program asks the backend for the release proofs of that measurement before the commands
   go out ("The release proofs"): when they hold, the node receives its grant in that step. A
   synchronization with no node that is to receive a grant sends no request that calls a node. A
   backend that has no
   route `GET /api/secure/grants` (status 404) is asked for the attestation of every node of the
   account instead, and what the device kept decides which of them receives a grant. Any other
   failure of the list fails the synchronization: a failed answer is never read as a list of nodes
   without grants. Before the first grant of a step goes out, the program reads the sealed ledger
   of the backend and merges it into its own ("The settings of the delegation"): another device
   of the account may have turned the delegation off, or set another lifetime. A step that hands
   no grant sends no such request. When the merged ledger says that the delegation is off, no
   grant goes out and the step goes on with step 5. When that read fails, no grant goes out in
   that step, and the next step asks again: a grant handed without it could turn a delegation on
   again that another device turned off.
5. With delegation off, the sealed ledger of the backend is read first (another device of the
   account may have turned the delegation on again: the step then hands the grants of step 3;
   when the read fails, the step goes on with what this device knows), and the revoke is sent
   again to every listed node (5.4), whatever role the
   binding of the node names: a revoke hands no key over, so a node of a role this program does
   not know takes it as any node does. A node whose binding has the role `forward` holds no
   delegation and takes no command: it is sent none, and counts as revoked.
6. The state of the grants is published (`state.grant`: `active`, `partial`, `none`, `off`, with
   the earliest end), and `runtime.ready`.
7. While delegation is on, the sealing of values stored before the switch to device-side
   sealing (`GET` and `PUT /api/secure/sealing`, until a query found none) and the completion
   of a mail setup; then a round of the log when one is due. While none is due and the device
   keeps a measurement that marked the log (A1), the synchronization asks the backend for the
   release proofs of that measurement, and proofs that show it make a round due at once ("The
   release proofs"). The procedures a user starts read
   and write the key store item of a mail setup on a line of their own, so the completion reads
   that item again after every request it waited for: when the item is gone, or is the item of
   another setup, the user cancelled the setup or began another one meanwhile, and the step
   writes, deletes and publishes nothing of the setup it worked on.
8. The catch-up of a master key transfer.

The line of the synchronizations is held for steps 1 to 6, and steps 7 and 8 run beside it. So
the grants of a synchronization wait for the grants of the synchronization before it, and for
no round: a push of the reason `grant_required`, which wakes a device to hand a grant to a node
that holds none, hands that grant while the round of an earlier synchronization reads. The
round runs under the lock of the round, and a synchronization that finds a round running takes
the result of that one. The call of a synchronization ends when all its steps ended, and the
report of a push follows that. A synchronization that ends after one that began later publishes
no `state.error` over it.

A runtime whose node ledger holds a value this program does not read ("The settings of the
delegation") does not know whether the delegation is on. In steps 3 to 5 it asks no node for an
attestation, hands no grant, sends no revoke, and publishes no state of the grants: the app keeps
what the last runtime that read the ledger published.

The program publishes one more value of the answer of step 1, on a device with a master key and
on one without:

| Published | Value |
| --- | --- |
| `runtime.named_secrets` | Whether the backend turned the vault items with a name on for the account. A runtime publishes false at its start (what a runtime before it published, of this account or of another, does not stand) and true once the answer to `GET /api/secure/account` of the account of the device carries `named_secrets` true; any other answer, and a query that fails, leave the value as it is. The value is what the operator domain says, handed on to the screens as it is: the screens of the app choose their names by it, and no procedure of the program acts on it |
| `state.named_secrets` | The same value in the state, which the app keeps over its restarts (it keeps none of the runtime values): true with every answer that says so, and false with the first answer that does not say so after the device published true. An account that was never told true has no such key in its state (the device remembers in `vault.named` that it published true) |
| `runtime.program_stale` | Whether the runtime knows that a later program than this one is served ("A runtime behind the served program"), or reads a node ledger that holds a value this program does not read (a later program wrote it: "The settings of the delegation"), published whenever that changes. The screens of the app read it to tell the user that the app is loading a later program, and a build of the app may take it as the occasion to load the program that waits |
| `runtime.log_rounds` | True: this program judges the log by rounds ("The round"), and publishes `state.log` in the form of that section. A runtime publishes it at its start. The screens of the app choose their wording of the log by this value, and not by the number of the version of the program; no procedure of the program acts on it |
| `runtime.ledger_ahead` | Whether `runtime.program_stale` is true because the node ledger holds a value this program does not read (the key store item, the copy of the device, or the sealed ledger of the backend), whatever else makes it true. False when the ledger is one this program reads. It is published with `runtime.program_stale`. The screens of the app tell the two reasons apart by it, and no procedure of the program acts on it |

A procedure that needs a node holding the grant (a connection, the storing of a value) runs steps
1 to 4 once under the lock of the grants. With delegation off it fails with `delegation_off`; when
no listed node holds a grant, with `grant_required`, or with `attestation_failed` when every listed
node failed the verification or is of a measurement the program does not accept. A listed node
that took no grant for no other reason than that the request for the release proofs of its
measurement failed (it was not answered, or was answered with a status or a body that is no
answer: "The release proofs") is no node of a measurement the program does not accept: no
attestation failed, the backend did not say that it holds no proofs, and the next step asks
again. With such a node among the listed ones and no node that holds a grant, the failure is
`grant_required`, in a stale runtime as in any other. In a stale
runtime that no listed node takes a grant of (every listed node is of a measurement the program
does not accept or failed the verification, or the backend lists none), the failure is
`program_stale`: the
program is behind, and the app loads the served one at its next start or return to the
foreground. In a runtime whose node ledger holds a value this program does not read, the failure
is `program_stale` as well, and nothing is sent to a node. When the step was about to hand a
grant and could not read the sealed ledger, the procedure fails with the failure of that read:
what this device keeps of its grants says nothing of a delegation another device turned off. The
outcome of the procedure is reported as a failure with that code. The statements
a node signs for a connection (8.2) are verified under the node id of a node the device handed a
grant to. When the backend names a node for a connection that is none of those
(the delegation of the account moved to a node the list did not name when the procedure read
it), steps 1 to 4 run once more: the device verifies that node and hands it a grant as it does
for every listed node, and its statement is judged as before. A node the device still handed no
grant to makes no statement it accepts; in a stale runtime that failure is `program_stale`.

### The nodes that receive a grant

A node receives a grant when its attestation verifies (4.3) and:

- its measurement (PCR0, PCR1, PCR2) equals an element of the lists of the program (the releases
  before v2.4.0 and the builds before the first release: 4.5), or release proofs that this
  program verified show it as the measurement of a release ("The release proofs"). The lists
  are closed: no release is added to them, and a release from v2.4.0 on is accepted by its
  proofs. A document that verifies with a measurement no list has and no proofs showed is the
  document of a measurement the program does not accept: the node receives no grant and is not
  asked for its attestation again, and the backend is asked for the release proofs of the
  measurement again five minutes after its last answer;
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
wrote is read as any chain of formats 1 and 2, though this device handed the node no grant: the
rounds follow the chain of every node the store names under the prefix of the account, and a
node the list names this way whose chain the device does not follow has the next
synchronization run a round that looks for it ("Formats 1 and 2").

### The settings of the delegation

The settings of the delegation are values of the node ledger: the time the user last turned the
delegation off (`revoked_ms`), the time the user last turned it on again (`resumed_ms`), and the
lifetime of a grant in days with the time it was set (`ttl_days`, `ttl_set_ms`). The delegation
is off while the revocation time is later than the resumption time.

The node ledger is a key store item the program writes as synchronizable, and a copy in the
program store; the ledger the program works with is the merge of the two. The key store of a
platform carries that item between the devices of an account or does not: the iCloud Keychain
does, and on Android an item of the key store does not travel between devices in use (an iOS
device without the iCloud Keychain keeps it to itself as well). So the devices of an account learn
the settings of one another from the sealed ledger of the backend: the ledger of a device, sealed
with a key derived from the master key (HKDF-SHA256, info `pickle.secure.v1.ledger`;
ChaCha20-Poly1305 with a fresh nonce; the associated data names the account and the `key_id`),
read with `GET /api/secure/ledger` and replaced with `PUT /api/secure/ledger`. The backend keeps
one value for an account and cannot open it.

Two ledgers merge value by value: the later of the two revocation times, the later of the two
resumption times, and the lifetime that was set last.

- A step that is about to send a command to a node reads the sealed ledger first and merges it
  into the ledger of the device: before the first grant of a step ("The synchronization", step
  4), before the revokes of a step whose delegation is off (step 5), and at the head of
  `set_grant_days` and of `set_delegation`. So a delegation the user turned off on one device is
  not handed again by another, and a lifetime the user shortened is the one the other devices
  renew with. A device none of whose grants is due sends no such request: it learns the setting
  with its next grant (the renewal interval at the latest) or with a push of the reason
  `grant_required`, and publishes the state it knew until then.
- A read that fails (it is asked once more after an answer that fails for a moment) hands no
  grant in that step, and a procedure that needed the grant fails with the failure of the read.
  The revokes of a delegation that is off go out all the same. A backend without a sealed ledger
  of the account (no value, or the status 404) has nothing to merge, and neither has a sealed
  ledger of another `key_id` (the key the account had before).
- When the sealed ledger lacks what the device holds (a setting, or a node of a release before
  v2.4.0 the device handed a grant to), the device seals the merged ledger and uploads it. The
  upload replaces the value of the backend, which is why the value is read and merged first. The
  device keeps what it uploaded (`ledger_shared`), taken from the ledger as it was sealed, and
  every synchronization and every procedure that needs the grants starts the exchange again
  while the ledger holds a node or a setting that mark does not cover: an upload that failed is
  made again. A setting made while an exchange is open is uploaded when that one has ended.
- An exchange that is open while the key of the account is replaced on the device merges nothing
  and is followed by none: its answer is the sealed ledger of the key of before.

`set_grant_days` sets the lifetime (an integer from 1 to 30). It hands a grant of that lifetime
to every listed node at once, whatever the renewal interval says. A shorter lifetime is applied
to every listed node or to none: when the step has no grant command for a listed node (its
attestation did not arrive or did not verify, or it is of a measurement the program does not
accept),
no grant and no revoke goes out, the lifetime stays as it was, and the call fails with
`grant_incomplete`, or with `program_stale` in a stale runtime. When a node did not take the
grant, or a node listed for its revokes alone did not confirm the revoke that a shorter lifetime
sends it ("The nodes that receive a grant"), the lifetime of the ledger is left as it was and the
call fails with `grant_incomplete`. With delegation off only the value is written.

`set_delegation` turns the switch.

- On: the resumption time is written (not before the revocation time, whatever the clocks of the
  devices say), and a grant goes to every listed node, whatever this device keeps of the grants
  it handed before: that a node holds the key after the switch is not read from those records.
  When the reading of the sealed ledger fails, the call fails with that failure and the switch
  stays off.
- Off: the revocation time is set after the resumption time of the merged ledger and not before
  any grant time the device or the ledger keeps, so the last operation decides the switch when
  the clock of a device runs ahead or behind. When the reading of the sealed ledger fails, the
  call goes on with what this device knows: turning the delegation off does not wait for the
  backend. The revocation time is written, and the state published, before the first revoke
  goes out: a runtime that ends between the two leaves a ledger that says off, and the
  synchronizations while off send the revoke again. When the ledger cannot be written, no
  revoke goes out and the call fails with that failure: the switch is on, as the user sees it.
  When a listed node did not confirm the revoke, or the step that sends the revokes failed, the
  call fails with `revoke_incomplete` and the switch is off.

A node ledger that holds a value this program does not read (a value that is there and is no
JSON object whose `v` is 1: in the key store item, in the copy of the device, or in a sealed
ledger of the `key_id` of the device) is the ledger of a later program, and may hold what this
program cannot see: the time the user turned the delegation off, a shorter lifetime. A runtime
that reads such a ledger hands no grant to any node, sends no revoke of its own accord, leaves
the value as it is on every side, and uploads nothing over it. A procedure that needs the
delegation, `set_grant_days`, and `set_delegation` in either direction end with `program_stale`
and send nothing to a node: a revoke that went out without the revocation time in the ledger
would leave the nodes without the key and the switch on for every device of the account. The
runtime publishes `runtime.program_stale` and `runtime.ledger_ahead` true, and the app loads the
program that wrote the value. A replacement of the key on such a device leaves that value as it
is as well.

Two things follow for the parties around the program:

- The backend keeps the route `GET /api/secure/ledger` answering. While it fails, the grants that
  are due do not go out, and the delegations of the accounts end with the lifetime of their
  grants.
- A later program that changes the form of the node ledger (its `v`) makes a change that is not
  taken back: a device that runs this program reads the ledger such a program wrote as one it
  does not read. Once a program of another form of the ledger was served to an account, a device
  of that account that runs this program again renews no grant.

### The key of the account

`create_key` makes the key of an account that has none, on a device without a master key (the
state `absent`). The key is registered on the account first and written to the key store only
after that, so when two devices make a key at the same time, the one whose registration came
second writes nothing and waits for the key of the other.

- The `key_id` of the key is noted in the program store before the registration is asked for
  (`key.made`, a public value), and until the key is in the key store.
- A registration that ended without an answer (the request failed on its way, ran out of its
  time, or was answered with a status of 500 to 599) may have reached the backend. The account
  query says whether the key of the account is the one of the call: when it is, the key is
  written and the call goes on; when it is not, or the query fails as well, the call ends with
  the failure of the registration.
- A key the account has registered that is among the ones noted, on a device without a master
  key, is a key no device holds: it was never written to a key store. The state is `absent` and
  not `waiting`, and `create_key` registers its new key in the place of that one.
- A registration that is answered with `key_exists` (a key was registered between the query and
  the registration) is judged again. When another device holds that key, the call ends with the
  state `waiting`. When it is a key this device made and no device holds, the key of the call is
  registered in its place. A call does not end well with the state `absent`.
- The note ends when the device holds a master key, and when the account has another key
  registered. A read of the key store that fails is a failure, and is not read as a key store
  without a key.

`reset_key` replaces the key of the account, on a device that waits for the key of another device
or holds another key than the one registered. The node ledger and what the device kept of the
log belong to the key of before: once the new key is registered, the ledger is emptied and those
values are erased, and then the new key is written to the key store. A runtime that ends before
that write leaves the key of before (or none) with an empty ledger, and the replacement is made
again; no runtime finds the new key with the ledger and the log values of the key before.

The master key moves to another device of the account by a transfer the user approves on a
device that holds it, over a session key the two devices derive from a 6-digit code (CPace over
X25519). A device asks for the transfer in the state `waiting` and in the state `mismatch`: on a
device whose key store carries no key from the other devices of the account, the key reaches it
this way and no other. Three checks of the device that takes the key:

- a message of the other device that gives no shared value (the X25519 result is 32 zero bytes:
  the message is no point a device makes from the code, and a session key made from it would
  depend on nothing the code says) ends the transfer as failed, on either device, before
  anything sealed with that key is sent;
- the key is written to the key store only when the `key_id` of the signing key derived from it
  is the `key_id` registered on the account;
- a device that held another key empties its node ledger and erases what it kept of the log
  before it writes the key of the account, as `reset_key` does.

### The release proofs

The lists of accepted releases are constants of the program, and they are closed: they hold the
releases before v2.4.0 and the builds before the first release, and no release is added to them.
The nodes of a release from v2.4.0 on state a measurement no list has. Such a measurement is that
of an accepted release when release proofs show it: the public build proof of the release
(section 9), which anyone may hand to the program and which the program verifies on the device
with constants of its own. No key of the operator takes part in that verdict, and the program
compares the name of no release with the name of another. With proofs that hold, a node of the
measurement receives the grant by the rules of "The nodes that receive a grant", it counts as a
node that writes format 3 to the log store (its binding names the log store of the server
target), and the rounds judge what it wrote as the entries of an accepted node.

The proofs are a JSON object (9.2):

```text
release_proofs = {"statement": b64u(the bytes of the release statement),
                  "attestation": <the Sigstore bundle of the attestation GitHub made of the statement>}
```

The program takes release proofs for a measurement when they have the form and pass the checks
V1 to V7 of 9.4, which it makes in the order of that section. In short:

| Check | What the program requires |
| --- | --- |
| The form | An object with the text `statement` and the object `attestation`, of sound JSON no deeper than the program reads |
| V1 | The statement is at most 16,384 bytes of JSON that state `release` (the name of a tag: `v` and one or more of `A`-`Z`, `a`-`z`, `0`-`9`, `.`, `_`, `-`), `git_commit` (40 lower-case hexadecimal characters) and `pcr0`, `pcr1`, `pcr2` (96 lower-case hexadecimal characters each, none all zero) once each, and the three PCRs are those of the measurement |
| V2 | The bundle has one certificate, one entry of the log and one envelope with one signature, is at most 65,536 bytes as JSON, and its payload is an in-toto statement |
| V3 | The certificate of the bundle was issued by the intermediate certificate of Sigstore the program holds, which the root certificate it holds issued, and all three are valid at the time of the entry of the log |
| V4 | The entry is one of the transparency log whose key the program holds (Rekor v1): it names the envelope, its signature and the certificate, the log signed the entry (the signed entry timestamp), and the inclusion proof leads to a checkpoint the log signed. The four counts of the entry (`integratedTime`, `logIndex`, and `logIndex` and `treeSize` of `inclusionProof`) are strings of decimal digits |
| V5 | The key of the certificate signed the envelope |
| V6 | The certificate states the identity below |
| V7 | The predicate type is `https://pickle.com/credential-enclave/release/v1`, and the predicate states the `release`, the `git_commit` and the three PCRs of the statement |

The identity (V6) is read from the extensions `1.3.6.1.4.1.57264.1.N` of the certificate, each a
UTF-8 text that must equal the value exactly:

| N | Value |
| --- | --- |
| 8 | `https://token.actions.githubusercontent.com` (the issuer of the token of the run) |
| 9 and 10 | The build workflow: the text of 9 before its last `@` is the repository and the path of an element of the list of build workflows of the program, and 10 is the commit of that element. The list (`PROOF_BUILDERS`) has one element: `.github/workflows/enclave-build.yml` at `e522d06d8388bee590678963f8940cd7a2b69f5c` |
| 11 | `github-hosted` |
| 12 | `https://github.com/pickle-com/credential-enclave` |
| 13 | The `git_commit` of the statement |
| 14 | `refs/tags/` and the `release` of the statement |
| 15 and 17 | `1400118248` and `151645824`, the identifiers of the repository and of its owner |
| 20 | `push` |
| 22 | `public` |

A count (the time and the index of the entry of the log, the index and the tree size of its
inclusion proof) is a non-negative integer of at most 2^53 − 1, written as a string of 1 to 16
decimal digits without a zero in front (a lone `0` is a count): the form in which a bundle
writes its times and indexes. A count written as a JSON number is refused, also a number of the
value the log signed. What a JSON number reads as differs between the engines the program runs
on for some notations (a number written with many digits that lies halfway between two values
reads as one value in JavaScriptCore and as the other in QuickJS), so a count written that way
would pass V4 on one platform of the app and fail it on the other; a string of digits reads the
same on both, and in the node implementation.

No other extension is read (the workflow that called the build workflow, extension 18, among
them). The program verifies with the bridge primitives `ecdsaVerify` (P-256 and P-384) and `sha`
and parses the certificates, the envelope and the entry itself. Proofs that fail are logged with
the check that failed (`release proofs refused: v6: identity 11`), and the proofs a runtime
refused last for a measurement are refused again without a second verification. The shared cases
of section 13 (`protocol/vectors/release-proofs.json`) hold the program and the node
implementation to one verdict on the same input.

Where the proofs come from. The program asks the backend, and whoever hands the proofs over, the
checks decide:

```text
GET /api/secure/release-proofs?measurement={digest}
-> 200 {"statement": "...", "attestation": {...}}      the proofs of that measurement
-> 404                                                the backend holds no proofs of it
```

- A digest is the base64url (without padding) of the SHA-256 of the UTF-8 bytes of `pcr0`, `pcr1`
  and `pcr2` of the measurement, each as 96 lower-case hexadecimal characters, one after another:
  the form in which the program keeps a measurement.
- One request names one measurement. The answer with the status 200 is the proofs as they are,
  or an object that holds them as its member `release_proofs`; they count when their statement
  states the measurement of the request. An answer with the status 404, whatever its body, says
  that the backend holds none. Any other outcome (another status, a body that is no JSON object,
  no answer) is a request that failed.
- The step of the grants asks for the measurement of a node that is to receive a grant, when
  the attestation of the node verified with a measurement no list has and no proofs showed.
  With proofs that hold, the nodes of that measurement receive their grants in the same step,
  with the attestations the step holds. A round asks for the measurements it met that way and
  the device kept (`log.unaccepted`), the ones that held the key of the account first: at its
  start, before anything is read, and before its judgement. The attestation response of a node
  and a node document carry no proofs the program reads.
- A step and a round send four such requests at most, together. A round that leaves a
  measurement unasked has more to read than it read ("The round"). A runtime asks for one
  measurement not sooner than five minutes after the backend answered for it (the proofs of a
  release may reach the backend after its nodes), and a request that failed is none the
  measurement was asked with: the next step or round asks again. No request goes out while the
  device has met no such measurement. A stale runtime asks in its step of the grants (it hands
  the grant to a node whose proofs hold) and runs no round. It keeps a node of a measurement
  it does not accept in memory, with that measurement, and every later step of the grants of
  that runtime asks for the proofs of the measurement by the same rule (at once after a
  request that failed, five minutes after an answer without proofs that hold), and not the
  node for its attestation, until proofs show the measurement: no failure of one request keeps
  a node from its grant for the time of a runtime.
- A round in which the proofs show a measurement is followed by a synchronization at once,
  whose step of the grants hands the nodes of that measurement their grants (once for a
  measurement in a runtime).
- While the device keeps a measurement that marked the log (A1) and that no proofs showed
  since, a synchronization that runs no round asks for the proofs of that measurement after
  its step of the grants (the step and this request send four requests between them at most,
  and none for a measurement twice). A round whose mark stands is followed by the next round
  24 hours later, so without this request a mark made on one answer would stand for a day
  after the backend handed the proofs out. Proofs that show the measurement make a round due
  at once: it takes the mark back and tells the app, in the stay in which the backend handed
  the proofs out. A stale runtime sends no such request.

What the answer means for A1 ("The round"). A measurement no list has marks the log only for a
runtime that knows that the backend hands out no release proofs that show it: the backend
answered a request for the proofs of that measurement, the answer is not earlier than the time
the device first saw the measurement and not older than one hour, and no proofs of it showed the
measurement (the answer was a 404, or it carried proofs that fail a check: the proofs of an
answer are always verified, whatever failed before). A request that failed is no answer: the
measurement waits, the round is pending, and the next round asks again. Past the 24 hours of A1,
a round whose request for the proofs failed on the side of the server (an error status other than
404, an answer that is no JSON object, or no answer while the backend answered another request of
the runtime within 60 s) is a round held back (A3), whether or not the runtime knows what program
is served; a request that failed with the network of the device leaves the round pending and
counts nothing. The status 404 is the one answer that says "no proofs", whatever sends it: a
backend that holds the proofs of a release and cannot read them at the moment answers with a
5xx status, because a 404 marks the log of a device whose measurement is past its 24 hours.
Such a mark is taken back at the next synchronization that is handed the proofs (above). While a measurement past its 24 hours waits for that answer, no round ends the
count of the rounds held back: the count ends when the backend answers the request. So a device
that could not ask, or was not answered, states nothing of a release whose proofs it has not
seen, and a backend that does not answer the route for three days marks the log by A3. The
route therefore has no limit of requests that a device in normal use reaches: a refusal with the
status 429 is a request that failed on the side of the server.

Proofs that reach the device after it read the entries of a node. A control key is remembered as
judged when its node is an accepted one ("The round"). The keys of a node of a measurement no
list has are read again by every round. So when proofs make that measurement one of an accepted
release, the next round judges the entries its nodes wrote before as those of accepted nodes: a
transfer of the key they name is followed (A1), and what the node signed counts for A2. A round
whose request shows a measurement is not complete, and the next one judges those entries.

A node of a measurement the proofs show states the release of the proofs in its binding: a
document of that measurement whose binding names another release fails the verification. A
binding and a release statement state no version of the program, and the program reads none.

What the device keeps (`log.proven`): per measurement the release of the statement and the time
of the verdict, under the version of the program that made it. A program reads what a program of
another version kept as nothing, and asks for the proofs itself. A kept verdict is not verified
again, and no proofs are kept. The device keeps the verdicts of 256 measurements, the ones made
last; a verdict a runtime made stays with that runtime whether or not the program store holds it,
and a verdict that left is made again when the device meets the measurement again. The end of
the account erases them.

The format of the log of a node, and whether it writes to the log store, follow from its
measurement at the time of its attestation and are kept with what the device keeps of the node
(`log.grants`): an element of a list states them (format 1 for the releases before v2.0.0 and
the builds before the first release, format 2 for v2.0.0 to v2.3.0, and whether the release
writes to the log store), and any other measurement of platform `nitro` is one of format 3 that
writes to the log store. The name of the release of a node decides neither.

What the proofs show, and what they do not, is stated in 9.5. In short: the job of a build
workflow of the list, as the file of that workflow is at its commit, ran on a runner GitHub
hosts, in a run the push of the tag started at the commit the statement names, in the repository
with the identifiers above while it was public, and attested these measurements; the entry of
that attestation is in the public log with its certificate. The proofs do not show what the
source of that commit does: the commit is public, and what its code does is for the one who
reads it. They rest on GitHub (the token of the run and its claims), on Fulcio and on the log of
Sigstore.

When a constant of the program no longer fits (the log key or the certificates of Sigstore
change, the repository moves, the build workflow is another file or another commit), the proofs
of a release made after that fail on a device that runs this program, and its nodes are nodes of
a measurement the program does not accept: such a release needs a later program, which holds
the new value. A runtime that knows a later program is served judges nothing ("A runtime behind
the served program").

### What the device keeps

The program store holds, per account, what the device knows of its grants and of the log. None of
it is a secret; what names services and addresses is sealed with a key derived from the master key
(HKDF-SHA256, info `pickle.secure.v1.log-cache`).

| Key | Content |
| --- | --- |
| `log.grants` | The nodes this device handed a grant to: the time of the grant, its end, the release and platform of the node, the time of the last attempt, and the format of its log with whether it writes to the log store, as its measurement said when it was attested ("The release proofs"). A node is written before its grant goes out |
| `log.nodes` | What the node documents that verified said: per node id the digest of the measurement, the platform, the release, the time first seen, and the time a contradiction of its signatures was found. A node id without a document that verifies is not kept, whatever the store showed of it |
| `log.unaccepted` | The measurements no list of the program has and no release proofs showed, each with the time it was first seen, whether the key of the account went to a node of it, whether it marked the log (a measurement that did marks it on) |
| `log.proven` | The measurements whose release proofs this program verified: per digest the release of the statement and the time of the verdict, under the version of the program that made it ("The release proofs"). 256 measurements at most, the ones verified last |
| `log.blocked` | The rounds held back that count, in a row: the time of the first, their number, and the time of the last one counted |
| `log.sample` | The 64 latest control keys the device verified |
| `log.seen`, `log.seen.{n}` | The digests of the control keys the device judged (a key whose node is of a measurement no list has is not among them: every round reads it again), in parts of 4,096 digests: `log.seen` names the parts, the oldest first, and `log.seen.{n}` holds one. Nine parts are kept; when one more begins, the oldest leaves with the digests it holds, so 32,768 judgements or more are remembered |
| `log.missing` | The keys of the sample that left the listing within their retention, until a listing names them again |
| `log.doubted` | The keys whose body an answer handed out with a signature that does not verify under the accepted node of the key (32 at most): the number of rounds whose answers did, the time of the first, and the node id. A key leaves when an answer carries a signature that verifies |
| `log.withheld` | The reads that were held back and that every round makes again. Of format 3: the keys of entries whose document or body was held back, and the keys the log screen asked for that no answer of the bodies reached (32 at most), with a mark on the ones the log screen asked for; the listing pages of the log screen that were held back (2 at most); and the time until which the rounds go on reading the first listing pages for the screen. Of the bucket of formats 1 and 2, as the log screen read it: the entries whose object versions were held back (16 at most), the `seq`s under which more objects lie than the screen reads, none of the ones it read the entry of the node (16 at most), the listings of chains (8 at most), and the listing of the node prefixes. And reads nobody held back: the new control keys a round listed and did not come to judge (`unjudged`, 32 at most), which the next round asks for before its listing |
| `log.recovered` | What the rounds read of the reads of the log screen that were held back, kept for the screen and sealed (the key of `log.cache`, with associated data of its own): the entries the screen asked for, as the screen shows them, each string cut to 160 characters (128 entries and 512 events at most; beyond that the ones kept first leave), the listing pages (4 at most, each the keys of 100 events with their entries, which leave with the page), and the node prefixes of the bucket of formats 1 and 2. The value holds 262,144 bytes at most before it is sealed: beyond them an entry the screen asked for or a listing page leaves, whichever was kept first |
| `log.denied` | The reads held back from the log screen that the screen notes itself and has not read since, one for each day on which a read was held back (8 at most of one kind): the later pages of format 3 (the time the read was noted, the lowest time a page held back that day began below, the events it was asked for), per node (8 at most) the listings of its chain of format 1 or 2 (the time, and the lowest `seq` a listing held back that day began after), and the days on which a page of the screen held no entry because every key it took was no entry (`filled`) |
| `log.cursor`, `log.resume` | The latest control key of the last round that covered the whole listing, and where a round that its page limit cut short goes on, with a mark when a round of that walk through the listing left keys unjudged |
| `log.legacy` | The chains of formats 1 and 2 the device follows: per node the `seq` up to which the control entries were read, the latest end of a grant, the times a round last listed the chain and last read it to its end, whether the chain is followed because the store names its prefix, and, while a round looks for the place of 2026-11-23 in a long chain, where it lists the chain next ("Formats 1 and 2"). The receiving nodes of transfers whose documents the device has still to judge. And what the rounds keep of the node discovery listing: the time they last took it in, whether it went on beyond the pages a round reads, the chains read to their end (2,048 at most, each a digest of its node id with the `seq` it was read to), the place and the time of the last of them that was listed again, and the nodes listed for their revokes alone that the rounds looked for (16 at most, each with the expiry the list named for it) |
| `log.round` | The last round: when it ran, how it ended, the published state, what the app was told, the row of the rounds of synchronizations that had more to read than they read (the ones that counted, and the time the row began), and the number of entries of chains of formats 1 and 2, written on or after 2026-11-23, that the rounds opened since a round last read the chains to their end ("Formats 1 and 2") |
| `log.big` | The sizes of the big keys of format 3 the listings named (32 at most, the latest entries) |
| `log.cache` | The first page of the log screen, the time the screen last read the listings of that page itself, the summary tally, and what the screen knows of the end of each chain of formats 1 and 2 (the last `seq` the device knows its node wrote, and the latest time a key of the chain names, kept only for a chain whose end the screen had among the keys it knew), sealed |
| `vault.made` | The names of the vault items `store_secret` made and that hold no value yet (8 at most) |
| `key.made` | The `key_id`s of the keys `create_key` made on this device and has not written to the key store (4 at most): public values |
| `vault.named` | The mark that the device published `state.named_secrets` true for the account |
| `outcomes` | The outcomes of the procedures that are not reported yet |
| `ledger`, `ledger_shared`, `log.migrated`, `sealing_checked` | The device copy of the node ledger, what its last exchange with the backend covered (the node ids and the times of the settings of the delegation), the mark that the ledger was carried over, and the mark that the sealing check is done |

The settings of the delegation (the time of the last revocation and resumption, the lifetime of a
grant) are kept in the node ledger of the programs before version 43: a key store item written as
synchronizable, and the copy of the device. The key store carries that item between the devices
of an account on some platforms and not on others, so the devices learn the settings of one
another from the sealed ledger of the backend ("The settings of the delegation"). The program
judges nothing by the nodes of that ledger. On its
first run on an installation it carries the ledger over once: a node with a grant time becomes a
grant of the device, and every node the ledger explains becomes a chain the rounds read
(`log.legacy`). A chain is read on from the point up to which the earlier program verified it
when the ledger keeps the time of the entry there and that time lies more than a day before
2026-11-23T00:00:00Z. A chain whose point is of a later time is read from its first `seq`,
whatever the earlier program verified of it; so is a chain of format 2 whose point the ledger
keeps no time of, and a chain of format 1 without that time is read on from its point
("Formats 1 and 2"). The marks of the earlier program are not
carried over. A device of the account that still runs an earlier program counts a chain of a node
no ledger explains as a delegation the app did not make, so the program writes every node of a
release of its lists that it hands a grant to into the ledger, in the form of those programs,
and exchanges the sealed ledger with the backend by their rule (`GET` and `PUT
/api/secure/ledger`: the value is read and merged before it is uploaded, because an upload
replaces it). A node of a measurement that release proofs showed (a release from v2.4.0 on) is
not written to the ledger.

### The round

A round is one reading and judging of the log of the account (7.4). A synchronization runs a round
when the last completed round is 24 hours old, when this program has completed none on the
installation, when the last round did not complete, while the device keeps a read that was
held back, while the list of the nodes names a node for its revokes alone whose chain the
device neither follows nor looked for since the list named that expiry for it, and when
release proofs showed a measurement that marked the log, so that the round takes the mark back
("The release proofs") (in the last four
cases not sooner than 60 s after the round before; the first listing
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

An answer of the backend is bounded in bytes and not in time: a network that carries few bytes a
second brings an answer of many keys later than 10 s, and a network that drops long answers never
brings it. Neither is a read the operator domain holds back.

- A request of a read that names a list (the bodies of keys, the documents of nodes, the
  addresses of object versions of a chain of formats 1 and 2) and ends without an answer (its
  time, or a failure on its way) is asked again once for its first item alone. An answer to that
  stands for the answer of the request, as one that ended after its first item: the read has
  more to read, and nothing was held back. No answer leaves the request one that was not
  answered, and a read asks that way no more once such a question stayed without an answer. A
  request that named one item is sent once more only after a failure on its way.
- A runtime whose request was answered that way names less in a request from then on, one
  request at a time: 16 keys, 4 nodes or 8 object versions, and after one more such answer 1 of
  each (a read then asks for 32 keys with each of its body requests). An hour after it last
  named less, a request names 200 keys, 64 nodes or 100 object versions again.
- An object of format 3 of 32,768 bytes or more is a big key (the listing of the store states
  the size of every object version): its body does not arrive within 10 s on such a network,
  whatever else the request names. A round asks for a big key alone, after everything else it
  reads, with the time its size takes at 8,192 bytes a second (10 s at least, 240 s at most), 16
  of them in a round. The round has the time of those requests on top of its own, and everything
  else it read is judged whatever becomes of them. The size of a key is the smallest size among
  the versions a listing page shows under it, and the last key of a page that goes on has none
  (its versions may go on with the next page): a version a node wrote stays in the store, so no
  object someone else writes under the key of an entry makes that entry a big key. The device
  keeps the sizes of the 32 latest big keys it listed (`log.big`). A read of the log screen that
  is no round asks for a big key alone within the usual 10 s, and a key that does not arrive
  goes to the rounds.

Before step 1, a round asks for the keys an earlier read left it (`log.withheld`): the keys whose
read was held back, and the new control keys a round listed and did not come to judge (32 at
most, the keys of the nodes of an accepted measurement first, the earliest entry first: an object
under the id of such a node is the entry its key names or its read ends in a count, so nothing
uncounted takes those places from an entry). Their documents and bodies are asked for as in steps
3 and 4, with requests of their own (two document requests and two body requests at most), which
take none from the requests of the listing pages. Before any of that, a round that begins with a
measurement no list has among what the device kept asks the backend for its release proofs ("The
release proofs").

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
   document of that node id. For a document that verifies with a measurement no list has and
   that carries no release proofs that pass, the round asks the backend for the release proofs
   of that measurement before it judges the entries of the node ("The release proofs").
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
   keys held back, and the round is not complete (A2 below). A control key whose read came to a
   judgement is remembered as judged when its node is an accepted one. A key of a node of a
   measurement no list has is not: every round reads it again, so the entries such a node wrote
   are judged as those of an accepted node once release proofs make its measurement one of an
   accepted release.
5. The reads that were held back before (`log.withheld`): the keys are read before step 1 (above),
   and each listing page of the log screen is asked for again in the request the screen sends for
   it, with the entries of the page the screen would show there.
6. The chains of formats 1 and 2 the device follows (the chains of the nodes it handed a grant
   to, of the nodes those handed the delegation on to, and of every node the store names under
   the prefix of the account), and the reads of that bucket that the log screen made and that
   were held back (the last part of this section).
7. The judgement, the published state, and the report (`POST /api/secure/log/verified`). Before
   the judgement the round asks the backend for the release proofs of the measurements no list
   has that it noted ("The release proofs"). What the round read for the log screen is kept for
   the screen before the reads it answers leave `log.withheld`.

A backend that answers the route of the listing addresses with the status 404 and no code of its
own, or with the code `log_store_disabled`, states that its environment has no store of format 3.
The round then reads the chains of formats 1 and 2 only. When the device handed a grant to a node
of a release that writes format 3, or read that store before, the same answer is a read held
back, and so is that answer from any other route of the reads for keys a listing of the store
named. On a device that knows of no such store, that answer (to a round, or to a read of a later
page) also ends what the log screen noted of later pages held back from it (below): they are
pages of a store that environment does not have.

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
answered is noted when the backend answers after that failure (the account query the read then
asks once).

A round that leaves reads undone because there was more to read than one round reads (the control
listing goes on beyond its four pages, more nodes are without a judgement than its document
requests name, more bodies are to be read than its body requests name, an answer of the bodies
ends before its last key, a request was answered for its first item alone, more big keys wait
than it asks for at its end, more measurements no list has wait for their release proofs than
its requests for them name, the chains of formats 1 and 2 hold more control entries than it
reads (512), more of those chains are open than it follows (64),
the listing of such a chain goes on beyond what a round reads of it (32 passes for a round of a
synchronization and 2 for a round the log screen started, the time a pass needs, and a round of
the log screen that waits for the round to end: "Formats 1 and 2"),
the node discovery listing goes on beyond its two pages, or
its time of 60 s passes before it has read everything) is pending, and the next round reads on
from where it stopped: a round whose time passes is judged on what it read and keeps what it
judged. A synchronization has the next round follow such a round at once, eight rounds in a row
at most, and does not wait for them: a device with much to read (a new device, a device that was
off for long) reads it during its stays in the app, and not one round a day. The eight rounds of
one synchronization read 32 listing pages, the documents of 1,024 nodes and 6,400 bodies, which
an account in normal use does not hold within the retention of the store.

The rounds of synchronizations that end that way in a row are a row, and a round that reads
everything ends it. A round of a row that left reads undone is one that catches up, and counts
as none, when all of this holds:

- it ended because it came to one of the numbers a round reads (the listing pages, the documents
  and the bodies its requests name, an answer of the bodies that ended before its last key, the
  chains a round follows, the pages of the node discovery listing, the big keys at its end), and
  not because its time passed;
- none of its reads failed or stayed without an answer, a request that was asked again for its
  first item and answered then among them;
- it read no object that no node wrote (an object under a node id the store holds no node
  document of, an object version under a `seq` of a chain that the node of the chain did not
  sign, a listing page of a chain that holds many object versions for each `seq`);
- it moved on: it judged an entry of an accepted node for the first time, or it read a listing
  on beyond the place the round before stopped at (the listing of format 3 from where the walk
  through it stood, a chain from the `seq` it was read to). The keys judged before that a round
  lists again from the start of the listing are no step;
- and one of the entries it so judged or passed was written before the row began.

A device that was away has as many entries to read as its nodes wrote in that time, and reads
them over as many rounds as that takes without a round of them counting. What counts: a round
whose time passed (a backend that answers late leaves a round no time for what it has to read,
and a round that is slow is not a round that has much to read), a round with a request that was
not answered, objects no node wrote that take the reads of a round, a round that judged nothing
new and read no listing on, and rounds that read only entries written after the row began and
still do not reach the end (entries arrive faster than the device reads them).

The chains of formats 1 and 2 have a rule of their own, because the chain of an account in heavy
use is long (the longest of this service held 1.67 million objects in November 2026), a node
of such a release that still runs goes on writing while a device reads, and a device reads a
chain on at the pace of its network. A round that left reads undone for no other reason than
that its chains have more to read than it read (their listings go on beyond the passes or the
time of a round, or they hold more control entries than a round reads) counts as none when its
time did not pass, none of its reads failed or stayed without an answer, it read no object that
no node wrote, and it read a chain on (the `seq` a chain was read to moved on to a `seq` under
which its node wrote, or the stretch in which the place of a chain lies became shorter:
"Formats 1 and 2"). It counts as none whatever the time of the entries it read and however many
such rounds follow one another, and it ends the count of the rounds of the row that counted
before it: it read everything else it had to read. So the length of a chain marks nothing. The
reads of a chain mark the log as any reads do: when they are held back, when they fail, or when
the pages of the chain hold objects no node wrote. And one number of the chains is bounded,
because an account holds only so much of it: the entries the rounds open (the control entries
of format 2 and the entries of format 1 that their nodes wrote on or after
2026-11-23T00:00:00Z; a use entry of format 2 is not opened). Once the rounds have opened more
than 16,384 of them without reading the chains to their end, a round that leaves reads of its
chains undone is a round held back, whoever started it and whatever ended it, until a round
reads the chains to their end ("Formats 1 and 2"): someone had nodes write those entries, and
a transfer of the delegation written behind them is kept from the device for as long as it
reads them. What this leaves is stated in "Formats 1 and
2": a node of such a release that holds the delegation of the account and goes on writing use
entries faster than a device reads keeps that device from the end of its chain, and the log is
pending for that time.

Beyond eight rounds of a row that counted, the first round of a synchronization
that counts again is a round whose reads are held back: someone writes objects under the
prefix of the account faster than the device reads them, or the answers of the backend never
reach their end, or come too late for a round to read. It counts once for its synchronization:
the rounds that follow it read on, and
neither add to the count of the rounds held back nor end it, and neither does a round that
catches up while the row is beyond eight (a round that only read chains on ends the count of
the row, above). So such reads mark the log when rounds
were counted that way on three days and three days have passed since the first of
them. Time that passed while the runtime did not run is not time the round had (the app
went to the background during the round, or the time of the round passed more than 5 s later than
a running runtime lets it): a round that ends that way is pending, is not counted in that row,
and is followed by none.

The result of a round is `verified`, `pending` or `attention`. It is `attention` when one of four
conditions holds, and each holds only in a situation that is a problem:

| | Condition | When it holds |
| --- | --- | --- |
| A1 | The key of the account went to a node of a release the program does not accept | A node of an accepted measurement wrote `grant_transferred_out` under the device's own `key_id` naming a measurement no list of the program has and no release proofs show as that of a release the program accepts ("The release proofs"), or a node whose document states such a measurement wrote an entry under that `key_id`; 24 hours have passed since the device first saw that measurement; the runtime knows that no later program than this one is served ("A runtime behind the served program"); and the runtime knows that the backend hands out no release proofs that show the measurement (the backend answered a request for them not earlier than the device first saw the measurement and not longer than one hour ago: "The release proofs"). Until all of that holds the measurement waits and the round is pending: the backend hands out the release proofs of a release before a node of that release takes a grant, a program that accepts what this one does not is served before such a node does, and a device may run the program before it for longer than a day. Release proofs that show the measurement as that of a release clear the condition, and so does a program that accepts it. Once it holds, every round that ends states it, however its reads ended, and for a measurement the device kept the events of the app state it without a read when the runtime knows by then that no later program is served and that the backend hands out no release proofs that show the measurement (a new runtime has asked for neither at its event `session_ready`: the round of that event asks for the proofs before it reads). A measurement that marked the log marks it on: a round that cannot say at its end what is served or whether the backend hands out release proofs (its reading is older than an hour and no new one arrived) takes no mark back. Release proofs that show the measurement take it back: while the mark stands, every synchronization asks the backend for those proofs again, and the round that follows an answer with proofs that hold tells the app ("The release proofs"). A receiving node whose document the device has not seen is no measurement: it waits for its document, a round whose request for that document is answered without one that verifies is a round held back (A3), and no time marks the log for it. The receiving node of a transfer a round judged is kept whatever kept its document from that round, and a round judges the nodes that wait first, with a request of its own, before it reads the chains |
| A2 | The signatures of a node that passed attestation contradict each other | Under a key of a node of an accepted measurement: an entry of the device's own `key_id` that the node signed and that does not open; two different bodies of one `seq` that both verify; or the body the key names for which the answers of two rounds carried no signature that verifies. The first two are marks no answer can make up, and stay. The third holds until an answer carries a signature that verifies for that key: the key is read again by every round, and a round it is held back from is a round held back (A3) |
| A3 | The operator domain has held the reads back for three days | Rounds held back were counted three times or more in a row and the first of them is three days old (the rounds of one day count as one: a round held back less than 20 hours after the last one counted adds nothing to the count and ends nothing); or the log screen notes three or more reads of one kind as held back from it (the later pages, the listings of one chain of formats 1 and 2, the pages that held no entry), on three days within 30 days, that it has not read since, and the first of them is three days old. A round is held back when a route of the reads answers with an error status; when a request of the reads ends without an answer (its time, or a failure on its way; for a request that names a list, when the question for its first item stayed without an answer as well) and the backend answers after that failure (an answer to another request that arrived after it, or the answer to the account query the round then asks once); when an address is not the one of the request; when the store answers an address not older than 240 s with a status other than 200, a 429 or a 5xx status at both attempts of the request among them; when the backend hands out no body, or another body, for a key of the listing whose node the device has a judgement of; when an answer of the bodies names none of the keys of a request, or names a key and not one before it in the request; when the backend hands out no verifying document for the node of a key of the listing and the store does not show that it holds none (it holds a version under the key of that node document or more than a page there, the answer gives no address of that listing or another address, or the store refuses the address); when the backend answers the request for the document of the receiving node of a transfer without a document that verifies (a transfer an entry of format 3 names, and a transfer a node that writes format 1 or format 2 made on or after 2026-11-23T00:00:00Z: "Formats 1 and 2"); when a key whose signature an answer did not carry is held back from a round (A2); when a measurement past the 24 hours of A1 cannot be judged because the checks of the app for a new program fail on the side of the server ("A runtime behind the served program"), or because the request for its release proofs fails on the side of the server ("The release proofs"); when more objects lie under a `seq` of a chain of formats 1 and 2 than are read there and none of the ones read is the entry of the node, or a listing page of such a chain goes on and shows the node writing nowhere ("Formats 1 and 2"); when the rounds have opened more than 16,384 entries of chains of formats 1 and 2 that their nodes wrote on or after 2026-11-23T00:00:00Z without reading the chains to their end, and the round leaves reads of its chains undone ("Formats 1 and 2": such a round reads on, and no round ends that count before one reads the chains to their end); when a read the log screen made of the bucket of formats 1 and 2 is still held back; and, beyond eight rounds of a row that left reads undone and counted (above), when the first round of a synchronization counts again. A round that made every read, the reads held back before included, clears the count of the rounds. A read the screen makes itself ends the reads it noted that this read covers, and the reads it noted end together when the last of them is 30 days old |
| A4 | An entry the device saw left the listing within its retention | A key of the sample that is younger than 364 days and lies in the range the listing covered is in neither of two readings of the listing. The condition ends for a key when a listing a round reads names it again |

A device without a network, a request to the store that fails on its way or runs out of its
time, and an address that aged while the
app was suspended leave the round pending and count nothing. So does a request to the backend
that failed in a runtime that did not run for a part of its wait: the app went to the background
while the request was open (the events `background` and `foreground` tell the program), or the
request ended more than 5 s after its own limit, which no running runtime lets a wait do. A
runtime does not run while its app is suspended, and what it had sent fails when it runs again;
such a failure says nothing of the backend, in a round and in a read of the log screen alike. A
request the backend answers with an error status counts whenever it is answered. A round that
runs when the app goes to the background does not wait for that failure: it ends its reading with
the event.

A store that answers a request with the status 429 or a 5xx status at both attempts holds the
read back: a store that answers the reads of an account that way for days keeps them from the
device as a refusal does. What such an answer is counted into depends on who made the read. In a
round it makes the round one held back: the rounds held back count one for a day, and one round
that reads everything ends that count, so a store that fails for a moment marks nothing there.
In a read of the log screen of a kind the screen notes itself (a later page, the listing of a
chain of formats 1 and 2) it is noted for its day, and no round ends what the screen noted: it
ends when the screen reads that place again, which every opening of the screen does. So such
answers on three days on which the screen was open, with no opening between or after them in
which the read went through, mark the log until the screen is opened again.

Several steps judge by the same values: a round, the step of the grants of a synchronization, an
event of the app. Each reads what the store holds in the step in which it writes, and adds to
it: a measurement one of them noted as one that held the key stays one, the earliest time it
was seen is kept, a contradiction noted on a node stays, and a round reads what the app was told
last when it ends, so a round that is not complete tells no pending over an attention an event
told while it read. A round, and a read of the log screen, that began before what the device
keeps of the log was erased (a new key, the end of the account) writes nothing it read under the
values of before, and such a round publishes, tells and reports nothing.

These mark nothing: an object under a node id the store holds no node document of (it is no entry
of a node), a `seq` of a node that no key carries (an entry the store did not confirm: its act did
not take place), a node whose entries end (with or without its orderly shutdown), and an entry of
another `key_id` (the screen shows it as part of a delegation of another key).

The program publishes the result as `state.log`:

| Key | Value |
| --- | --- |
| `status` | `verified`, `pending`, `attention` |
| `verified_ms` | The time of the last round that ended `verified` or `attention` |
| `newer_release_nodes` | The measurements that wait for A1: within its 24 hours, or past them while the runtime does not know that no later program is served or that the backend hands out no release proofs that show the measurement |
| `unknown_nodes` | The measurements for which A1 holds |
| `unverified_nodes` | The nodes for which A2 holds |
| `missing` | The keys for which A4 holds |
| `expired` | 0 |
| `store` | `verified`, `unreachable` (the device or the store failed), `blocked` (a read was held back, or the reads the log screen notes as held back from it mark the log), `truncated` (the control listing goes on beyond the pages of the round, and no more than eight rounds of the row counted; beyond eight, the value is `blocked`) |
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
A1, the node ids the key went to, the number of rounds held back that were counted in a row
(one for a day), the first failed read,
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
nowhere), `chain:entries` (the rounds opened more entries of those chains than an account holds
without reading the chains to their end), `round:time` (the time of the round passed before it had read everything),
`round:unfinished` (a round counted as held back because the rounds keep ending with more to read
than a round reads), `screen:held` (the reads the log screen notes as held back from it mark the
log), `delivery:{status}` and `delivery:silent` (the checks of the app for a new program failed
on the side of the server while a measurement waited to be judged), `proofs:{status}`,
`proofs:timeout`, `proofs:transport` and `proofs:invalid` (the request for the release proofs of
a measurement that waited to be judged failed on the side of the server), `program:stale` (the report
of a stale runtime), and `{request}:suspended` and `round:suspended` (a request, or the round,
ended in a runtime that did not run for a part of it, or the round ended its reading because the
app went to the background).

### A runtime behind the served program

A node of a release this program does not accept may hold the key of the account for no other
reason than that this program is no longer the one served: a later program accepts that release
(it takes a build workflow, or a key of the transparency log, that this one does not: "The
release proofs"), and the runtime has not loaded it. A device runs an earlier program for
minutes or for days. So a runtime
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
  `log.nodes`, `log.legacy`, `log.cursor`, `log.resume`, `log.round`, `log.big`), the reads of
  the log screen included: what a program that is behind reads of nodes and formats the served
  program accepts and it does not is nothing the next program is to judge by;
- publishes no judgement, tells the app none and reports none. The state the device kept stays
  published as it is.

It publishes `runtime.program_stale` and reports once that it is stale: a report of a round (`POST
/api/secure/log/verified`) with the status `pending`, the first failed read `program:stale` and
its own version. It goes on handing its grants to the nodes of the releases it accepts (the
lists, and the measurements release proofs show: it asks for the proofs in its step of the
grants; a node of a measurement it does not accept that it meets is kept in memory alone, with
that measurement, and every later step asks for the proofs of the measurement again, so a
request that failed keeps no node from its grant: "The release proofs"), serving the procedures the user
starts, and reading the log for the screen: the first page is then read as a later page is,
without a round, with the summary the device kept marked as not complete.

A1 holds for a measurement no list has only when, besides the 24 hours since the device first saw
it, the runtime read the served version, that version is not above its own, and the reading is
not earlier than the time the device first saw the measurement and not older than one hour, and
the backend answered a request of the runtime for the release proofs of the measurement within
the same bounds, without proofs that show it ("The release proofs"). A
round that holds such a measurement and no reading that young asks for the account once before it
judges, and every round asks for the release proofs of such a measurement before it reads. A backend that names no served version leaves such a measurement waiting: it marks
nothing, and no round counts as held back for it.

A round that is about to mark a log that is not marked, for whatever condition, judges by what is
served then. When what the runtime read of the served version is none, or older than one hour (a
round the log screen started long after a synchronization), the round asks for the account once
before it writes, publishes or tells anything. An answer that names a later version ends the
round as one of a stale runtime: it judges nothing. Without an answer the round stands as it was
judged, so a backend that leaves the account query unanswered puts off no mark that way. A round
of a log that is marked already, and a round that marks nothing, send no such request.

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

With the argument `wait` true the call waits for that read for 60 s, the time of a round, and
not for 3 s. The read of the screen runs a round behind the round that reads at that moment
(the round of a synchronization), so a call that answers after 3 s shows the kept page with the
status `pending`, and the judgement of the round is published later. The chains of formats 1
and 2 of an account with much to read do not keep the screen waiting: a round of a
synchronization that has read a chain on ends that reading with the pass it is in while a round
of the screen waits, the round of the screen makes two passes over the chains and no more, and
the rounds of the synchronizations read the chains on after it ("Formats 1 and 2"). A screen passes `wait` with the last of the calls it
makes for one opening (it calls `read_log`, and while the answer is `pending` calls again): that
call answers when the read ended, with the page as the store holds it and the judgement of the
round, without the user doing anything. The interpreters of the builds of November 2026 have no
event for a published value that changed, so the screen cannot ask again when a round ends. A
call that waits holds no line. The next call for the log screen (`read_log`, `read_log_page`,
`read_security_record`) ends its wait at once, and it answers from what the device kept as a
call whose wait passed does.

A round the screen started is reported by the
read of the screen that takes what the round read; a round that goes on after the screen stopped
waiting for it (it waits for a big key at its end) sends its report itself.

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
read asks for it again. A read of the screen whose time passed while the runtime did not run
(the app was suspended in the middle of it) ends with `timeout`, the end of its time, whatever
failure of a request arrives when the runtime runs again.

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

The entries of the nodes of the releases of the lists of the program (the releases before
v2.4.0) stay in the bucket their bindings name until their retention ends. The program reads
them for two things.

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

A round follows the delegation along the chains: the chain of every node of such a release
that the device handed a grant to, of every node such a node handed the delegation on to, and of
every node the store names under the prefix of the account (below). For each it lists the chain
from the `seq` up to which it read, reads the control entries of 2026-11-23T00:00:00Z and later
(below), and follows `grant_transferred_out` of the device's own `key_id`. The operator domain can write objects into
that bucket as well, so under one `seq` the round reads the object versions whose keys name a
control entry, the latest first, until one is the entry of the node (eight at most: a node writes
one object under a `seq`, and one more version when it repeats a write). When none of the eight
is and more are left, the read is held back (`chain:keys`) and the chain is not read past that
`seq`. The last `seq` of a listing page that goes on is read with the page after it. When the
reading of the object versions of a round ends before its end (the time of the round passed, or
a request failed), what was read is judged, and each chain is read up to the `seq` before the
first one an object version of which was not read: what was not read is not read as something
nobody wrote, and the next round reads each chain on from the `seq` it was read to. The object
versions the store answered of the request at which the reading ended are among what was read
(the store answers the object versions of one request one by one, eight at a time): on a
network on which those answers take longer than a round has for one request, every round reads
its chains on by the object versions that arrived, and none asks for the same request again and
again without reading any of it. A chain a round listed and read nothing of is the first the
next round reads.

The `seq` up to which a round read a chain moves on only to a `seq` under which the node is seen
to have written: an object the node signed for that `seq`. The round sees that in the control
entries it reads and in the last two `seq`s of a listing page, whose objects it reads for that
alone when their keys name no control entry (eight versions each at most). An object someone else
wrote under a `seq` the node has not reached, or far beyond the end of the chain, moves nothing:
the entry the node writes there later is read. A listing page that goes on and shows the node
writing nowhere cannot be read on, and the read is held back (`chain:keys`); a page a node wrote
always shows it in its last `seq`s.

What a round reads of a chain. From 2026-11-23T00:00:00Z on the backend keeps the attestation
document of every node that takes a transfer (below), so a transfer a node wrote from that time
on is judged, by every device of the account, and nothing a node wrote before that time is read:

- A control key of format 2 that names an earlier time is passed and not read, in every chain:
  the key of an entry is written by its node, and no transfer of that time is judged by a
  document. The chain of the node that took such a transfer is followed because the store names
  its prefix. A key of format 1 names no time and is read.
- A long chain is not listed page after page up to that time. When a listing page that goes on
  ends with an entry its node wrote more than a day before that time, the round looks for the
  place of that time in the chain: it lists the chain 2,000 `seq`s further on, then twice as far
  beyond the `seq` it reached, and so on, until a page holds an entry of a later time or the
  chain ends there, and then lists it halfway into the stretch in between until that stretch is
  1,000 `seq`s or fewer. Of each such page it reads the object versions under the first and
  the last `seq` (eight versions each at most), and the `seq` up to which the chain is read
  moves on only to a `seq` under which the node wrote an entry that names a time more than a day
  before that time. A node writes its entries in the order of its clock, and the day is for a
  clock that was set back: no entry of that time or later lies before such an entry. An object
  someone else wrote says nothing of a time, whatever its key names, so it moves that `seq`
  nowhere: a page that shows no entry of the node under those two `seq`s ends the looking for
  that round, and the chain is read on page after page from the `seq` it was read to. Where the
  stretch begins and ends only chooses where the next listing lies; the chain is read from the
  `seq` it was read to, whatever those listings showed. A chain of 200,000 entries takes 15
  listings and 20 object versions to its end. What the device keeps of the looking
  (`log.legacy`) lets the next round go on with it.
- A chain of format 2 that the ledger of a program before version 43 explains ("What the device
  keeps") is read by the same rule, from its first `seq`: that program verified the chain up
  to a point and judged no transfer by the measurement of its receiving node, so a transfer a
  node wrote from that time on and that program passed is read and judged by this one. Only
  when the ledger keeps the time of the entry at that point, and that time lies more than a day
  before 2026-11-23T00:00:00Z, is the chain read on from that point (and left closed when the
  point reached the final head of its node): no entry of that time or later lies before it. A
  chain of format 1 the ledger explains is carried over the same way when the ledger keeps
  the time of its point: read on from the point when that time lies more than a day before
  2026-11-23T00:00:00Z, and from its first `seq`, entry by entry, when it does not. The last
  node of a release that writes format 1 ran in October 2026, so a point of a later time is
  the point of a node someone started since, and a transfer that node wrote and the earlier
  program passed is judged. A chain of format 1 whose point the ledger keeps no time of (a
  program before version 29, the first that kept it, moved the point last) is read on from
  that point: the rounds would open every entry of such a chain, and version 29 came with the
  first release of format 2, in October 2026.

How much a round reads. A round reads its chains in passes: a pass lists one page of every chain
that has more to read (16 chains in one request for their addresses), reads the object versions
of those pages in one request for 100 of them, and judges the receiving nodes they name. A round
a synchronization started makes 32 passes at most, and begins a pass only while it has 20 s of
its time left, and twice the time its longest pass took (30 s at most): it ends its reading of
the chains by those numbers and not because its time passed, on a network that carries little
as on any other. A round the log screen started makes 2 passes at most: the read of the screen
waits for that round, and what a chain has beyond those passes is read on by the rounds of the
synchronizations. And a round of a synchronization that has read a chain on makes no further
pass while a round the log screen started waits for the round to end; the next round of the
synchronization reads on after the one of the screen. A round
reads 512 control entries of chains at most, and reads the object versions under the last
`seq`s of its pages besides (8,192 at most). A round that ends with chains that have more to
read is followed by the next round at once ("The round"), and such a round counts as none while
it read a chain on and none of its reads failed: the length of a chain marks nothing, however
many rounds it takes. A listing that goes on over pages that hold more than five object versions
for each `seq` they name, on average, holds objects no node wrote, and a round that ends that
way counts.

How many entries the rounds open. A round opens the control entries of format 2 that their nodes
wrote on or after 2026-11-23T00:00:00Z, and the entries of format 1 (a key of that format names
neither a time nor a kind). The device counts the entries of those two kinds that their nodes
wrote on or after that time and that its rounds opened since a round last read the chains to
their end (`log.round`): every round adds the ones it opened, whoever started it and whatever
ended it, and a round that made its reading of the chains, left none of them with more to read
and had no read fail begins the number anew. An entry counts as it counts among the 512 of a
round: one for each object version the round asks for under its `seq` (a node writes one
object version under a `seq`, and one more when it repeats a write), so copies of an entry
that someone stores under its key give the rounds no more rounds before the number is reached.
Once the number is above 16,384 (the control
entries 32 rounds open), a round that leaves reads of its chains undone is a round held back
(first failed read `chain:entries`), and no round ends the count of the rounds held back before
one reads the chains to their end. The rounds read on all the while, eight in a
synchronization, so the log is marked three days after the first such round unless the rounds
reach the end before (A3), and what lies behind those entries is judged when the rounds come to
it. The number is one an account does not reach: a node of such a release writes a control
entry for a grant command (a device renews the grant of a node once a day, twice with a
lifetime of one day), for a connection made or removed, for a revoke and for a transfer of the
delegation. Of the accounts of this service in the 30 days before 2026-11-24, the one with the
most grant commands had 295 of them, which is 3,934 at that pace in the 400 days after which
the store removes an object, and no node of a release that writes format 1 ran after October
2026. But a node of a release of the lists can be made to write control entries of an account
without the user, as many as someone likes and ahead of time: two nodes of one release hand
the delegation of an account back and forth, and each hand-over is an entry. A transfer to a
node of a measurement the program does not accept that is written behind such entries is read
only once they are read, and the count makes that delay one the device reports. The use
entries of format 2 are not opened and not counted.

What this leaves. A node of such a release that holds the delegation of an account writes a use
entry for every use of it, and one that goes on writing use entries faster than a device reads
keeps that device from the end of its chain for as long as it does: the log of that device is
pending for that time, nothing is counted (the chain of an account in heavy use is long, and
the device cannot tell the two apart), and a transfer the node wrote behind those entries is
judged when the device reaches it. A device reads 32 pages of a chain (32,000 object versions)
in a round and eight rounds in a synchronization, far more than a node writes in that time, so
this takes a node that writes day and night for a device that reads during its stays in the
app: a day of such a delay takes 256,000 use entries for a device that makes one
synchronization a day (4,096 control entries would take a device as long to read, and those
are the entries the number above bounds). Once no node
of such a release holds the delegation, a chain grows no more and every device reads it to its
end. And a backend that answers the reads of the chains late leaves a round fewer passes, or
lets its time pass (a round whose time passed counts as every such round does: "The round").
The number above counts the entries and not the rounds, so it is reached all the same, over as
many more rounds as the rounds open fewer entries: it bounds how many such entries can lie
ahead of a transfer unreported, and not the time a backend that answers late can take over
them.

The event of a transfer names the receiving node and
no measurement, so the program asks for the document of the receiving node (`POST
/api/secure/log/documents`: the node document of a node that writes format 3, the
attestation document the backend kept of a node of a release of the lists). A receiving node
whose document states a measurement the program does not accept counts for A1; a receiving node of a release that
writes format 3 has its entries in the listing of format 3; a receiving node of an accepted
release before that has its chain followed in turn. A receiving node waits from the moment the
entry that names it is read until it is judged, whatever ends the reading of that round, and a
round judges the nodes that wait first, with a request of its own for their documents, before it
lists a chain: what a round reads of the chains takes the time of the round, and the judgement
of a transfer the device read is not put off by that.

Which chains an account has is read from the store, and not from a list of the backend: the
listing of the node prefixes under the prefix of the account (the node discovery listing), which
the rounds read once in 24 hours, two pages of 1,000 prefixes at most (what the log screen read
of it within that time is taken when it is later than what the rounds took in and names fewer
than 1,000 prefixes). So a grant another device of the account handed to a node this device
never met leaves a chain this device follows, and a transfer such a node makes to a node of a
measurement no list has is judged (A1) as on any other chain. For a chain that is followed
because the store names it:

- The chain is followed from its first `seq`, and read as every chain is: nothing its node
  wrote before 2026-11-23T00:00:00Z is read, and a long chain is not listed page after page up
  to that time (above).
- The latest time the node can hold a grant is taken as 30 days (the longest lifetime of a
  grant) after the latest time the keys of the chain name: a node of such a release writes an
  entry with every grant it takes. One day after that, a reading that reaches the end of the
  chain is its last, and the device remembers the chain as read to its end, by a digest of its
  node id and the `seq` it was read to (2,048 of them; beyond that the ones remembered first
  leave, and the listing has the device follow them from their first `seq` once more).
- Every chain the device read to its end is listed again once in 30 days, from where it was read
  to, whatever the list of the nodes says of its node: with a reading of the node discovery
  listing, as many of the chains it names as the time since the last ones makes due, in the
  order of their digests. A node whose chain ended may be handed a grant again by another
  device, and writes on.
- When the list of the nodes names a node for its revokes alone whose chain the device does not
  follow, the next synchronization runs a round that reads the node discovery listing at once,
  or follows the chain again when the device read it to its end before: once for each expiry
  the list names for that node.
- Every prefix the listing names is followed. A listing that goes on beyond its two pages leaves
  the round with more to read than it read, and the next round reads it again. An account has
  as many node prefixes as its nodes made, far fewer than two pages hold, so a listing that goes
  on holds names no node made: a round that ends that way is one of the rounds that left reads
  undone ("The round"), and rounds that go on ending that way mark the log as reads held back
  do. A round follows 64 chains, the ones listed longest ago first; with more of them open, the
  next round follows at once and takes the others, and lists no chain again that a round of
  that row read to its end within the last 10 minutes. A chain a round begins to follow while
  it follows that many (the chain of the receiving node of a transfer it read) is one of the
  others.
- A read of the node discovery listing that is held back, and a read of such a chain that is
  held back, is a read of the round held back as on any chain (A3), with no opening of the log
  screen. A backend that states it has no store of these chains is believed by a device that
  knows of no chain, and holds the listing back from a device that follows one.
- The node that wrote such a chain is not judged by a document: its entries are verified under
  the node id its prefix names, and the receiving node of a transfer it made is judged by its
  document as on any chain.
- A stale runtime reads no node discovery listing and follows no chain.

A receiving node the backend hands out no document that verifies for is judged by the time of the
event. From 2026-11-23T00:00:00Z on the backend keeps the attestation document of every node that
takes a transfer, for longer than the store keeps the entry of the transfer. For an event of that
time or later, and not older than 365 days, the node waits: every round asks for its document
again, a round whose request for it is answered without a document that verifies is a round held
back (A3), no time alone marks the log for it, and its chain is not followed before a document
verifies. The receiving node of a transfer an entry of format 3 names waits the same way,
whatever the time of the event. The
store is not asked whether it holds a node document of such a node: a node that writes format 1
or format 2 wrote none. An event before that time is one a round reads only in a chain of
format 1 (the keys of that format name no time): its receiving node is followed as a node of
the release of the giving node. The route of the node documents hands out what the backend kept of a
node whether or not the backend reads the store of format 3, so a backend that answers that it
has no such route, or no such store, holds the document back in every environment.

A chain is read for the last time one day after the grant of its node ended. The program reads no
head, verifies no chain equation, and marks nothing for an empty `seq` or for a node no grant of
this device explains: it follows the chain of such a node as any other.

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
- At most 16,384 bytes.

```text
{"kind":"secure-program","release":"secure-program-v27","version":27,"sha256":"<64 hex>","git_commit":"<40 hex>","repository":"pickle-com/credential-enclave","path":"secure-program/secure-program.js"}
```

`secure-program/statement.py` writes these bytes. The workflow `secure-program-release.yml`
(enclave.md 11.2) runs it for the pushed tag and attaches the result to the GitHub release of the
tag as `statement.json`, next to the file.

A node of this release reads no statement that the release key signed (10.3). A node of a release
before v2.4.0 does not take this statement for the endorsement of a node release: the first check
of an endorsement requires `pcr0`, `pcr1` and `pcr2`, which this statement does not have. So the
two kinds of statement that the release key signs do not mix.

### The entry of the log

The operator signs the bytes of the statement with the release key (ECDSA P-256 with SHA-256, the
signature in ASN.1 DER) and records the signature in Rekor (rekor.sigstore.dev) as an entry of the
kind `hashedrekord`, version 0.0.1. The body of the entry is, after its standard base64 is decoded:

```text
{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{
   "data":{"hash":{"algorithm":"sha256","value":"<lower-case hex SHA-256 of the statement>"}},
   "signature":{"content":"<standard base64 of the signature>",
                "publicKey":{"content":"<standard base64 of the PEM of the release public key>"}}}}
```

The log returns the body, the time at which it took the
entry (`integratedTime`), the global index of the entry (`logIndex`), the log identifier (`logID`),
the signed entry timestamp (the signature of the log key over the bytes of check 8 below) and the
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
| The release key | The public key of the operator, ECDSA P-256: `enclave/release/release-key.pem`. The apps hold the DER of its SubjectPublicKeyInfo. The node program does not hold it (10.3) |
| The log key table | The public keys of the transparency log, by log identifier (the lower-case hexadecimal SHA-256 of the DER of the key: the log identifier of 9.3). The identifier `c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d` maps to `enclave/release/rekor-key.pem`. When the log signs with a new key, an app release adds a row; an app of an older build verifies no entry of the new key. The ten checks below are those of an entry of a log of the form Rekor v1, a log that signs an entry timestamp: this table holds no log of another form, and the release proof of a program is an entry of rekor.sigstore.dev |

### The verification

The input is the bytes of the served program, the version the program declares (the
`const VERSION = N;` line, 0 when the line is absent), the release proof, the release key and the
log key table. The ten checks run in this order, and the first one that fails ends the
verification with its code. An app logs a failure as `secure program rejected: release proof {code}`
and does not load the program; the assembly of the backend refuses a bundle whose proof fails; the
tool prints `program release: failed: {code}: {detail}`. No check reads a clock. A decoding that
fails (base64, UTF-8, JSON, hexadecimal) is a failure of the check that reads the value.

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

### The attestation of the source

The GitHub release of a tag `secure-program-v{N}` carries two attestations that GitHub made for
runs the push of the tag started. Each is a Sigstore bundle: an in-toto statement whose subject is
`secure-program.js` with the SHA-256 of the file, signed under a certificate of the public
Sigstore instance that states the workflow run, and recorded in Rekor.

| Bundle | What made it | What its certificate states as the signer |
| --- | --- | --- |
| `secure-program-provenance.sigstore.json` | The job of `secure-program-release.yml` (enclave.md 11.2), a file of the commit of the tag | That workflow at the tag |
| `secure-program-source.sigstore.json` | The job of `secure-program-source.yml` at one fixed commit, which `secure-program-source-release.yml` calls | `secure-program-source.yml` at that fixed commit |

The first is made by a workflow of the commit of the tag, so that commit decides what its job
attests. The second is the attestation of the source: it is made by a workflow whose file a
verifier fixes by its commit, and the commit of the tag decides nothing of it but the bytes of the
program file. The rules of that workflow:

- It is started only by the call of another workflow and takes no input and no secret.
- Its job runs on a runner GitHub hosts. It reads the bytes of `secure-program/secure-program.js`
  as the commit that started the run holds them: the blob of that commit, a regular file, read
  from the object and not from a file of a working tree (the conversions a working tree applies
  do not reach it). It attests the SHA-256 of those bytes.
- It runs no script and no action of that commit. The actions it uses are fixed by their commits
  in its own file.

GitHub writes the identity of the run into the token the job signs with, and Fulcio copies it
into the certificate (the extensions `1.3.6.1.4.1.57264.1.{n}`). For a job of a workflow that
another workflow called, the certificate states the called workflow as what signed and the caller
as what started the run:

| Extension | Name | What it states for the attestation of the source |
| --- | --- | --- |
| 8 | Issuer | `https://token.actions.githubusercontent.com` |
| 9 | Build Signer URI | The workflow of the job: `.github/workflows/secure-program-source.yml` of this repository |
| 10 | Build Signer Digest | The commit of that workflow file: the fixed commit the caller names |
| 11 | Runner Environment | `github-hosted` |
| 12, 15, 17 | Source Repository URI, its identifier, the identifier of its owner | The repository in which the run took place: `https://github.com/pickle-com/credential-enclave`, `1400118248`, `151645824` |
| 13 | Source Repository Digest | The commit that started the run: the commit of the tag |
| 14 | Source Repository Ref | `refs/tags/secure-program-v{N}` |
| 18 | Build Config URI | The workflow that started the run, at the tag |
| 20 | Build Trigger | `push` |
| 22 | Source Repository Visibility At Signing | `public` |

A verifier that requires the extensions 8, 9, 10, 11, 12, 14, 15, 17, 20 and 22 of a certificate
that chains to the certificate authority of the public Sigstore instance, verifies the signature
of the bundle and its entry of the log, and compares the SHA-256 of the subject with the SHA-256
of a program, has verified this: the bytes of that program are the bytes of
`secure-program/secure-program.js` of the commit the certificate states (extension 13), and that
commit was pushed to this repository under the tag `secure-program-v{N}` while the repository was
public. Anyone can read that commit by its hash and compare:

```bash
git show {commit}:secure-program/secure-program.js | sha256sum
```

What the attestation does not show: that the commit is on a branch of this repository, or that
the tag still names it (a tag can be moved or removed after the run; the certificate and the entry
of the log keep the hash of the commit), and what the program of that commit does, which is for
the reader of the file. It rests on GitHub writing the true identity of the run into the token, on
the certificate authority and on the log. Another repository can call the same workflow: the
certificate of such a run states that repository (extensions 12, 15 and 17), and a run on a runner
of a repository owner states `self-hosted` (extension 11).

The ten checks of "The verification" read neither attestation.

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
