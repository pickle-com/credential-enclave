# The egress policy of a node

This document states which bytes can leave a credential enclave node, and how the source
enforces it. It is the rule set a reader checks the source against: every rule names the code
that enforces it and the test that fixes it.

The formats are in [protocol.md](protocol.md). The calls are in [enclave.md](enclave.md).

## 1. Purpose and threat model

A node holds credentials for accounts: OAuth tokens of their connections, and vault values
(passwords, TOTP seeds, card numbers). The operator of the service calls the node to use them.
The policy answers one question:

> For any field of any response, whatever its name is: can the source show that its value is
> not a credential in the clear?

The answer does not rest on field names or on the shape of values. It rests on where a value
comes from, and the source fixes that with types and with a closed list of places that read a
secret.

| Party | Trust |
| --- | --- |
| The operator domain: everything outside the node. The backend processes that call it, the host program in the same pod, the parent instance, the network, the storage | Not trusted. It chooses every input of every call. It sees every response, and of every connection the node opens it sees the destination, the size, the time and the TLS records |
| The servers of a provider (Google and the others of the definitions) | Assumed to follow the public API contract of that provider: in a response of the token address the tokens are at `access_token`, `refresh_token` and `id_token`, and an API does not send the token of its caller back. Rule E4 is the defense for a response that breaks this assumption |
| The log store (Amazon S3) | Trusted to keep an object it confirmed until the retention of that object ends (Object Lock in compliance mode), and to confirm a write only after it stored the object. It receives log entries, which are ciphertexts, the names in their keys, and the node document of every node, which holds public values |
| The app of the account | Trusted to be honest: it holds the master key. This document does not cover it |
| The holder of the release key and the transparency log (Sigstore Rekor) | The holder of the release key, the operator, decides which later release receives the user keys of a node. It is not trusted to do so unseen: a node accepts its signature only with an entry of the transparency log. The log is trusted to keep every entry whose signed entry timestamp it issued (protocol.md 10.3) |

Out of scope: what the size and the time of a response reveal. APIs that open a lasting access
on the side of the provider with one call (a watch, a forwarding rule, a share link, a signed
upload address): such a call is on the log like any other, and what the provider does after it
does not pass through the node.

## 2. Values

### 2.1 Secrets

| Secret | Where it comes from |
| --- | --- |
| The signing private key and the sealing private key of the node | Created inside the node at start |
| A user key | The node opens the grant an app sealed to it, or the transfer a verified peer node sealed to it |
| A record key | Derived from a user key |
| The plaintext of a record: the token object of kind `oauth` and `oauth_imported`, an application password, a vault password, a TOTP seed, a card number, a CVC | The node opens a record |
| The response of a token address, as a whole, accepted or refused | The node calls the token address of a provider |
| A PKCE verifier | `oauth/begin` creates it |
| The key material of an HPKE seal the node makes | The random source of the platform |

The client secret of the operator configuration is a value the operator domain gave, so it is
no secret from it. It is held as a secret all the same: it reaches the token address and the
revocation address of its own provider and appears in no response.

The same holds for the credentials of the log store (enclave.md 5.14): the secret access key and
the session token are values the operator domain gave. They are held as secrets: the session
token reaches the log store and nothing else, the secret access key signs the requests to the
log store and is part of none, and neither appears in a response.

### 2.2 Channels

| Channel | To | What |
| --- | --- | --- |
| C1 | The operator domain | The response of a call: status, headers, body |
| C2 | A provider | A TLS connection that ends inside the node. Its destination is an address of the provider definitions or one of the fixed Naver mail endpoints. A connection to a provider carries the requests of one account: the node keeps at most 8 idle connections per (account, host) for at most 30 seconds, and sends the requests of a forward batch at most 6 at a time. The operator domain sees TLS records only |
| C3 | The console | Exists in a debug-mode enclave only (its attestation has all-zero PCRs and an app refuses it). In any mode the node writes fixed strings of its source only |
| C4 | The log store | A TLS connection that ends inside the node, to `s3.{region}.amazonaws.com`, the endpoint of Amazon S3 in the region of the log store of the node (a node of the local platform may write to the endpoint of its configuration instead). It carries log entries (class C below), the key of each (`user_id` E, the node identifier, `seq`, `time_ms`, the kind, the count or the name of the control event, the hash of the body P, `key_id` E), the bucket of each (it follows from the bucket name of the binding and a hash of `user_id`, protocol.md 7.6), the node document of the node (the attestation document of the platform over the binding: S and P) and the credentials of the operator for the store. The node keeps at most 32 idle connections to the store. The operator domain sees TLS records only, and it can read the buckets |
| C5 | The site of a vault secret | A TLS connection that ends inside a node of the forward role (protocol.md 4.1), to port 443 of the host the envelope of one use of a vault secret names (protocol.md 10.5). It carries the one request of that use, with the value at its slot, and ends with the response to it. The operator domain sees TLS records only |

There is no other channel: the node writes no file and opens no other socket. A node of the
delegation role has the channels C1 to C4, a node of the reserve role C1, C3 and C4, and a node
of the forward role C1, C3 and C5: the node that holds user keys opens no connection to a host
an account chose, and the node that opens such a connection holds no user key and no record. A
node of the reserve role holds user keys and opens no record: it answers no call that uses a
credential (enclave.md section 4), so it has no connection to a provider, and what it writes on
C4 is its node document and control entries.

### 2.3 What a response can carry

Every value on C1 is of exactly one of seven classes.

| Class | Definition | Examples |
| --- | --- | --- |
| P, public | A constant of the source, the node clock, a count or a size, node randomness, a public key, a hash of public values | `release`, `node`, `expires_ms`, the node part of `state`, the end of a chain |
| E, echo | A value the operator domain gave in the clear, in this call or in the operator configuration | `user_id`, `provider`, `operator_state`, the `params` inside the authorization address |
| D, declassified | A value that came from a sealed input or from a secret and that the protocol makes public. Section 4 lists all of them | The `key_id` and the `not_after_ms` of a grant, the S256 challenge, `has_refresh_token` |
| C, ciphertext | A ciphertext that holds secrets: a record (a key derived from the user key), a transfer envelope (the sealing public key of a verified peer). A log entry (sealed to the log public key of the account) is a ciphertext of this class that leaves on C4 only: no response carries one | `record`, `envelope` |
| S, signature | A signature of the node signing key over values of the classes above, and the attestation document of the platform | `statement`, `challenge_statement`, `reply`, `document` |
| V, vault release | One value of a vault record that `release` hands out, after its log entry is on the chain | `value` of `release` |
| R, from a provider | A value a provider sent, after the checks of rule E4 | The response of `forward`, the public fields, `provider_status`, `provider_error`, `revoked` |

A hash, a MAC or another derivation of a secret is not P. The values that are computed from a
secret and leave are the ones section 4 lists as D, and the TOTP code as V.

The random values of P come from one function, which reads the random source of the platform
and nothing else (`Node::random_public` in `enclave/src/state.rs`). The times of P come from
the clock module (`enclave/src/clock.rs`). No function that takes a secret produces a value
that is used as a random value or as a time.

## 3. Rules

### E1. A secret is a type that cannot become a response

- The types that hold a secret are defined in one module, `protocol/src/secret.rs`: `Secret<T>`
  and `NodeKeys`. Their fields are private to that module.
- They implement neither `Serialize` nor `Display` nor `ToString`. Their `Debug` output is a
  fixed string. Their bytes are overwritten with zeros on drop. Only a key (`Secret<[u8; N]>`)
  can be cloned.
- The secrets with structure (a token response, the plaintext of a record) are types whose
  fields are `Secret` values and private to the module that owns them: `enclave/src/oauth.rs`
  for tokens, `enclave/src/vault.rs` for vault values.
- A response body is a value of a type that implements the marker trait `OperatorResponse`,
  and the functions that build a response take nothing else. The trait is implemented in one
  file, `enclave/src/api/responses.rs` (its supertrait is private to that file), and each
  field there carries its class. Adding a response type means changing that file.

Since `OperatorResponse` requires `Serialize` and no secret type implements it, a response
type with a secret field does not compile.

Fixed by: the `compile_fail` examples and the compile-time assertions of
`protocol/src/secret.rs` (a secret cannot be serialized, formatted, dereferenced or compared,
and the private keys of `NodeKeys` cannot be read), and its test that the `Debug` output of a
secret never holds its bytes.

### E2. The places that read a secret are a closed list

The bytes of a secret are read through `Secret::expose_secret` and through nothing else. The
functions that call it are of three kinds.

| Kind | Meaning |
| --- | --- |
| A sink, K1 to K7 | The bytes leave the node, in the form the table below allows |
| In-node | The bytes are used inside the node. The result is a secret again, a public key, a signature, a ciphertext or the outcome of a check |
| Declassify | The result leaves in the clear and is one of the values section 4 lists |

The sinks:

| Sink | What it does | Condition, and what enforces it |
| --- | --- | --- |
| K1 `record::seal` | Encrypts a plaintext with AEAD under a record key derived from the user key | The AAD binds `id`, `user_id`, `key_id`, `custody`, `kind` and `provider`. It has two callers. `OauthPlaintext::seal`: the plaintext is a token response the node received, an opened record, or the merge rules applied to those. `OperatorValue::seal`: the plaintext is one the node wrote of a value the caller of `vault/store` gave, with the source `operator`, under an `id` and a nonce the node drew (E6) |
| K2 `seal_transfer` | Seals user keys with HPKE to the sealing public key of a verified peer node | The peer is a `Peer`, a type only `verify_peer` creates. A verified peer is one of two nodes. The first: its attestation document verifies up to the AWS Nitro root, it is not a debug-mode enclave, and PCR0, PCR1 and PCR2 equal those of this node. A node of the same measurement is the same program and keeps the same rules. The second, for a call with an endorsement (protocol.md 10.3): its attestation document verifies in the same way, it is not a debug-mode enclave, PCR0, PCR1 and PCR2 equal those of a release statement, and its binding names the release of that statement. The statement names a release later than the release of this node, the release key inside the binary signed it, and the transparency log whose key is inside the binary recorded that signature in an entry whose signed entry timestamp verifies. Such a node is another program: the rules it keeps are those of its own source. In both cases the binding of the peer names the log store of this node. A transfer to a node of the first kind has no log entry: the user key stays under the rules of one program. A transfer to a node of the second kind is on the log of every account it carries before the seal: the log store confirmed the entry `grant_transferred_out`, which names the peer, its release and its measurement (protocol.md 10.1). A node of the `local` platform accepts no peer under an endorsement and holds user keys of custody `operator` only |
| K3 `Egress::send_to_provider` | Writes a request with a credential, a token request or a revocation request to a TLS connection | The request is addressed to a `Destination`, a type only the provider definitions create: an address that passed the address check of `forward`, the token address, or the revocation address. The certificate is verified against the WebPKI roots compiled into the binary. The node follows no redirect |
| K4 `Selected::hand_out` | Puts one value of a vault record into the response of `release`, as it is or under the seal of a key the caller named | The record is of a vault kind and the field is one of that kind (E6). A record of kind `vault_secret` lists the slot `field`, and its sites hold the host of the origin of the call or a host above it. The function takes the log entry of the release as an argument: the entry is on the chain before the value leaves. A sealed value is a released value: the caller chose the key |
| K5 `send_to_log_store` | Writes one object to the log store over a TLS connection, in a request signed with the credentials of the operator | What it takes is one of two objects, and the credentials of the log store. The first is a signed entry (`Signed`: the body and the signature of the node, whose content is sealed to the log public key of the account) with its key and the hash that names its bucket. The second is the node document: the attestation document of the platform over the binding of the node, which holds public values (protocol.md 7.7). No argument of it is a type that holds a user key, the plaintext of a record or a token: the secrets it reads are the two the operator domain gave. The destination is a bucket of the log store of the operator configuration (the buckets that follow from the bucket name of the binding, protocol.md 7.6), at the endpoint of Amazon S3 in the region of the store, a region name of a fixed form under `amazonaws.com`, and the certificate is verified against the WebPKI roots compiled into the binary |
| K6 `AppPassword::imap` | Sends account name and application password through IMAP TLS | Only imap.naver.com:993, verified roots and trusted node clock; after grant and log-store confirmation |
| K7 `AppPassword::smtp` | Sends account name and application password through SMTP TLS | Only smtp.naver.com:465 with the same verification and logging; one transaction, no retry after DATA |
| K8 `seal_secret_use` | Seals the value of a record of kind `vault_secret`, with the one request it is for, with HPKE to the sealing public key of a node of the forward role | The receiving node is a `ForwardNode`, a type only the verification of an attestation response creates: a node of the platform and the measurement of this node whose binding names the role `forward`. The request is one the reach of the record admits (its host is one of the sites, its slot one of the slots), and the function takes the log entry of the use as an argument: the event `provider_request` is on the chain, and the log store confirmed it, before the value is sealed |
| K9 `Egress::send_to_bound_host` | On a node of the forward role, sends the one request of an opened envelope, with the value written into it (`BoundRequest::build`), over a TLS connection | The request is a `BoundRequest`, a type only `BoundRequest::build` creates. It reads the host and the method from a `SecretUse`, a type only the opening of an envelope creates: an envelope sealed to this node and signed by the node it names, within its 30 seconds, whose number was not used before. The address is that of the envelope, the body the body the envelope names by its length and its hash, and the value stands at the slot of the envelope and nowhere else (protocol.md 10.5). The certificate is verified for that host against the WebPKI roots compiled into the binary, the connection carries this one request, and the node follows no redirect |

Fixed by: `scripts/secret-access.sh --check`, which the `check` and `release` workflows run.
It lists every function of the node source that names `expose_secret` (for
`protocol/src/secret.rs`: every function that touches the private fields) and every function
that calls a sink, and compares the two lists with `egress/secret-access.tsv` and
`egress/sink-callers.tsv`. Those files say for each function what it does with the bytes and
what holds at each sink call. A function that is not listed fails the check.

What the script reads, and what else fails the check:

- The node source is the `.rs` files of `protocol/src` and `enclave/src`, without the vector
  generator (`protocol/src/bin/`) and without the code that is compiled for tests only:
  `enclave/src/tests/`, `enclave/src/testing.rs`, and in each file its test module. The test
  module of a file is the lines from a `#[cfg(test)]` at the start of a line that is followed
  by `mod tests {` or `pub mod tests {`. A test module that lies in a file of its own
  (`#[cfg(test)]` followed by `mod tests;`) does not end the reading of the file that declares
  it.
- A file is read up to its test module. The check fails when a line that is neither empty nor
  a comment follows the test module of a file: no code of the node lies where the script does
  not read.
- A comment line (a line that begins with `//`) names no function and is no use. The line that
  defines `expose_secret` or a sink (`fn name(`) is no use either.
- The functions of `enclave/src/log_store.rs` that read a secret are listed with the use K5:
  the secret is one of the two of the operator for the log store, and what leaves goes to the
  log store.
- A call of a sink is the name of its function in front of `(`, where the name is not the end
  of a longer name. It is found after a path (`record::seal(`) and where the name is imported
  and stands alone (`seal(`). K1 is a function and no method: `.seal(` is a call of the method
  `OauthPlaintext::seal`, the one function that calls K1. The check fails when a line gives a
  sink another name (`seal as`), because a call under that name would not be found.
- The second count: apart from the reading that makes the two lists, the script counts in the
  lines of the node source how often `expose_secret` is named and how often each sink is
  called. The check fails when a count is not the sum of its list.

What the check does not show by itself: that each listed function does what its line says. That
is what a reader verifies, function by function. The list is short for that reason, and every
helper a listed function hands exposed bytes to is private to the same module or is one of the
pure format functions of the protocol crate.

### E3. Every response is classified

Section 4 lists every call and the class of every field of its response. The types of
`enclave/src/api/responses.rs` carry the same classes in their comments.

Fixed by: a test compares the calls of the router with the calls of the table in section 4
(`the_calls_of_the_egress_policy_document_are_the_calls_of_the_router`), and the canary test
calls every one of them.

### E4. What a provider sent

**An accepted response of a token address.** The whole response is a secret. What leaves is
the public fields: the leaves the provider definition lists.

- `public` of a definition is a list of `{path, type, max}`. `path` is object keys joined by
  `.` and names a leaf. `type` is `string`, `integer` or `boolean`. `max` is the longest
  `string` in bytes of UTF-8. An `integer` is a JSON integer or a string of 1 to 20 ASCII
  digits.
- A value of another type, an object, an array, and a string above its limit are left out.
  That is not a failure.
- `id_token_claims` is a list of the same form: claim name, type, limit.
- A definition that lists a path that names a token (`access_token`, `refresh_token`,
  `id_token`, at any depth), the path the node injects as a credential, the same path twice,
  or a path that is the parent of another listed path, is refused when the definitions are
  loaded: the node does not start.
- The containment check: when a string among the public fields and claims holds the string
  at `access_token`, `refresh_token` or `id_token` of the response or of the merged token
  object (at the top level and in the token container), the call fails with
  `response_withheld`. No record and no public field leaves. A string holds a token when it
  contains the token as it is, or in one of the encoded forms of the reflection check below.

**A refused response of a token address.** What leaves is `provider_status` (the HTTP status
as an integer, 0 for a transport failure) and `provider_error` (rule E5).

**The response of `forward`.** The request is E, the response is R. The node enforces:

| Item | Rule |
| --- | --- |
| `Accept-Encoding` of the request | The node drops the value of the caller and sends `identity` |
| A request header that overrides the method | A call with a header `X-HTTP-Method-Override`, `X-HTTP-Method` or `X-Method-Override` is refused with `not_allowed`, before an entry is created. The entry `provider_request` names the method the request is sent with, and a provider that reads such a header would carry out another one. The node refuses the call and does not drop the header |
| The name of a request header | A name is compared in lower case and with `-` for every `_`: some servers read the two as one character, so `X_HTTP_Method_Override` is the header that overrides the method for them, and `Accept_Encoding` asks for a coded body |
| `Range` and `If-Range` of the request | The node drops them: it asks for the whole of a response. The reflection check reads what one response holds. Of a response that held the credential, two parts that are asked for one by one would each pass it, and a response of several ranges holds its parts with other bytes between them |
| The character encoding of the response | The node drops `Accept-Charset`, and a call with an `Accept` header that names a character encoding other than UTF-8 is refused with `not_allowed`, before an entry is created. The reflection check reads bytes, and under UTF-16 the bytes of a credential are not the bytes it looks for |
| `Content-Encoding` of the response | Present and not `identity`: `response_withheld`. The node does not hand on a body it cannot search. The header is read as it arrived, before the node leaves out the headers that the `Connection` header of the response lists: a response that lists `Content-Encoding` there is withheld like any other coded response. A response under an instance manipulation (RFC 3229: the status 226, or a header `IM`) is `response_withheld` as well |
| `Transfer-Encoding` of the response | A coding other than `chunked`: `response_withheld`. The node sends no `TE` header, so `chunked` is the one transfer coding it removes. Under another one (`gzip, chunked`) the body would leave still coded, without the header that says so |
| Response headers | The hop-by-hop headers, `Set-Cookie` and `Set-Cookie2` are left out. The node drops the `Cookie` of every request, so no cookie is in use, and a cookie handed to the caller would be an access that no log entry records |
| The reflection check | A header name, a header value and the body are each read in six readings: as received, with their percent escapes decoded once, twice and three times (for a value that was encoded more than once), and with their JSON string escapes decoded once and twice (for a JSON text inside a JSON string). When one of these readings holds the injected credential (the token without the prefix of the definition) in one of these forms, the call fails with `response_withheld`: as it is, base64 or base64url (each of the three byte alignments, without padding), hexadecimal (lower or upper case). Decoding the escapes finds the credential under every percent-encoding and under every way a writer of JSON escapes it: whichever bytes an encoder escapes and whichever case its digits have. A header whose bytes are not UTF-8 is handed on with one character for each byte, and it is searched as those bytes as well. A form shorter than 8 bytes is not searched for. The check overwrites the headers and the body it withholds with zeros before it drops them. It runs off the threads that serve the calls, and it makes at most one copy of what it reads |
| Redirects | Not followed. A 3xx response is returned as it is |
| A response that is handed on as a stream | A call that asks for it gets the body of the provider in parts while it arrives (enclave.md 5.8 step 11). The head passes the rows above before the status 200 leaves: a coded body, and a header name or a header value that holds the credential, is `response_withheld`, and no stream begins. The body passes the reflection check in parts (`StreamCheck` of `enclave/src/provider_response.rs`). Each of the six readings is decoded part by part from the first byte of the body (an escape that a part begins and does not end waits for the bytes that follow) and searched together with its last bytes from the part before, so the verdict on a body is the verdict of the check of a whole response on the same bytes, whatever its parts are. The check holds back the last bytes it received, as many as one byte more than the longest form of the credential can take in a reading (36 bytes for each of them: a byte takes at most 36 bytes under two layers of JSON string escapes and 27 under three layers of percent escapes), and hands on the bytes in front of them once a search found no form (it searches when 4,096 new bytes have arrived, or four times the length of the longest form when that is more, and at the end of the body). A form that ends in a byte still to come begins inside the bytes held back, so no byte of a form the check finds has left, and neither has the byte in front of it. How far the handed on bytes lag depends on the length of the credential and on nothing else: no byte leaves sooner or later because it resembles the credential. A body that holds the credential is cut in front of it, and the end record of the stream says `response_withheld`. The bytes held back leave at the end of the body as its sender ended it: of a body that is cut (a failed connection, the time limit of the call) they do not leave |

`response_withheld` is a failure after the entry `provider_request` is on the chain: the
request went to the provider. Of a frame, no part of the response leaves. Of a stream, the
head and the bytes of the body in front of the bytes held back have left when the check
finds the credential: bytes of the provider (class R) that passed the check, and no byte of
a form of the credential.

**The response of `vault/send`.** The request carried the value of a vault secret to a host an
account chose, and the response is R. The rows of the table above hold for it with the value in
the place of the injected credential, and with these differences:

| Item | Rule |
| --- | --- |
| The request | The node of the forward role sends the request of the envelope and no other one (protocol.md 10.5, sink K9): it drops and refuses the headers of that section, asks for `identity` and for the whole of a response, and refuses an `Accept` header that names another character encoding than UTF-8 |
| The response | Always a stream. The head passes the checks of a stream before the status 200 leaves, and the body passes the reflection check in parts. The value is 8 bytes or longer (a shorter one is sealed by no node), so every form of it is searched for |
| The memory of the search | A value has up to 12,000 bytes, and the search holds back 36 bytes for each byte of its longest form. The call holds the share of the body budget of the node that the search can hold, from before its request leaves to the end of the stream |
| A second request | None. One envelope is one request, and a response that was cut or withheld is followed by no other request of the node: whoever asks again leaves another `provider_request` on the log of the account |

What the search does not find is a value in a form it does not know: a host that sends the value
back encrypted, compressed, split, or under an encoding other than the ones above is not held
back. The entry of the use names the method, the host, the path and the query of every request
that carried the value.

**The response of the revocation address.** What leaves is `revoked`: one bit, whether the
status was 2xx.

Fixed by: the tests of `enclave/src/oauth.rs` and `enclave/src/provider_response.rs` (for a
stream: bodies in parts of any length, cut in front of every form at every place, with the
verdict of the check of a whole response, and with the credential behind a run of backslashes),
the tests of the stream form in `enclave/src/tests/forward.rs`, the tests of
`enclave/src/tests/vault_send.rs` and `enclave/src/bound.rs`, the definition tests of
`enclave/src/providers/mod.rs`, and the canary test.

### E5. Diagnostics are a closed vocabulary

- The `code` of a failure is one of the list of protocol.md section 11. The `message` is a
  `&'static str`: a fixed string of the source.
- `provider_error` is a word of a closed list. The node reads the error strings of the provider
  response, in this order: a string `error`; for an object `error` its string `code` and then
  its string `message`; and, when none of those is a non-empty string, the top-level string
  `code`. It compares each of them with the list below. What leaves is the first element of
  the list that equals one of them, the empty string when the response has no such string, and
  `other` otherwise. Each of them is a constant of the source: no byte of a refused response
  leaves.

  ```text
  invalid_request invalid_client invalid_grant unauthorized_client unsupported_grant_type
  invalid_scope access_denied server_error temporarily_unavailable invalid_target
  interaction_required login_required consent_required invalid_resource
  invalid_refresh_token token_revoked token_expired invalid_auth account_inactive invalid_code
  code_already_used bad_client_secret invalid_client_id bad_redirect_uri invalid_grant_type
  ratelimited request_timeout fatal_error internal_error service_unavailable
  rate_limit_exceeded
  unauthorized internal_server_error rate_limited validation_error restricted_resource
  object_not_found
  bad_refresh_token bad_verification_code incorrect_client_credentials
  "refresh_token not found"
  ```

  The last element is one string with a space.
- The crates of the node deny the lints `print_stdout`, `print_stderr` and `dbg_macro`. The one
  exception is the function `diagnostic` of `enclave/src/main.rs`, which takes a fixed string
  and reports a failed start.
- A panic of the node writes nothing of a call. The message of a panic cannot hold a secret
  (E1: `Debug`), and it can hold another value of the call it happened in, so the panic hook
  of the node counts the panic and has no output (`faults::silence`, enclave.md 3.1). What
  leaves of a panic is that count, in `health`, and the end of the connection of its call.
  When a second panic ends the process while a first one unwinds, the standard library writes
  one line of its own to the standard error: a fixed string, without the message or the place
  of either panic.

Fixed by: the type of `ApiError` and `ProviderError`, the lint attributes at the crate roots,
the tests of `enclave/src/oauth.rs`, and the two tests of the output of a panic in
`enclave/src/faults.rs`.

### E6. No plaintext of the caller becomes a credential, and the kind says where a value came from

| Kind | Where the plaintext was made | Use mode | Opened by |
| --- | --- | --- | --- |
| `oauth` | The node: the response of the token address that `oauth/complete` received, and after that the results of `refresh` and `oauth/merge` | enclave-use | `forward`, `refresh`, `revoke-token`, `oauth/merge` |
| `oauth_imported` | The device of the account: it encrypted a token the operator domain held before it used this node. The plaintext has the form of kind `oauth` | enclave-use. The operator domain knew this token once: the record does not say that its token never left a node. A new connection of the account gives a record of kind `oauth` | `forward`, `refresh`, `revoke-token` |
| `app_password` | The device encrypts a NAVER application password and account name | enclave-use; authenticated identity is declassified after verification | `mail/verify`, `mail/read`, `mail/submit` |
| `vault_password` | The device: the app encrypts what the user entered. Or a node, of a value the operator domain gave it (`vault/store`): the plaintext of such a record says `source` `operator`, and the plaintext of a device has no such key | release | `release`, field `password` |
| `vault_totp` | The device | enclave-use: the seed stays, the code leaves as V | `release`, field `totp` |
| `vault_card` | The device | release | `release`, fields `card_number`, `card_cvc` |
| `vault_secret` | The device, of a value its user entered (`source` `device`), or a node, of a value the operator domain gave it (`vault/store`, `source` `operator`). The plaintext names the hosts and the slots the value may go to | By its slots. The slot `field`: release. Slots of a request: enclave-use, the value goes into a request of a node of the forward role and no call hands it out | `release`, field `value`, for a record with the slot `field`. `vault/handoff` for a record with slots of a request |

- No call takes a plaintext and makes a token record of it. The node creates a record of kind
  `oauth` from a token response it received itself, and writes an existing record of kind `oauth`
  or `oauth_imported` again after a refresh, under the kind it had. `oauth/merge` takes records
  of kind `oauth` only: the refresh token of an imported record is not moved into an issued one.
- `vault/store` is the one call that takes a value of its caller and makes a record of it: a
  record of kind `vault_secret` or `vault_password`. The node writes the plaintext itself, with
  the source `operator`, under an `id` and a nonce it draws itself, and after the control event
  `connection_created` of that record is on the chain and the log store confirmed it. So a value
  the operator domain knew does not pass for a value a user entered on a device, the call
  overwrites no record that exists, and every record it made has an entry.
- The reach of a record of kind `vault_secret` (its sites and its slots) is part of its plaintext.
  Whoever cannot encrypt under the user key cannot widen it, and the two calls that use the value
  hold their caller to it: `release` to the slot `field` and to an origin of the sites,
  `vault/handoff` to a host of the sites and a slot of the slots. No record lists `field` beside
  a slot of a request, so a value that goes into requests is handed out by no call.
- The kind is an enum (`Kind` in `protocol/src/record.rs`) and part of the AAD of a record, so
  a record that opens has the kind it names. A kind the release does not know is `not_allowed`.
- A record is opened by the function of its call family, and the two return different types.
  `oauth::open_record` takes the two token kinds and refuses a vault kind. `vault::open_record`
  takes the vault kinds and refuses a token kind. So the code of `release` cannot hold the
  plaintext of a token, and the code of `forward` cannot hold a vault plaintext. The type of a
  vault value offers one way out, `hand_out`, and for a `vault_totp` record the value it holds
  is the code: the seed has no way out. The value of a record with slots of a request has another
  type, whose one way out is the seal of sink K8.

Fixed by: the types of `enclave/src/oauth.rs` and `enclave/src/vault.rs`, the tests of the
calls, and `egress/sink-callers.tsv` (the two callers of K1).

### The canary test

`enclave/src/tests/canary.rs`, run by `cargo test`.

- Every secret gets a distinct marker of high entropy: the user key and the record keys derived
  from it, the two private keys of the node and the scalars the curves compute from them, the
  PKCE verifier, the authorization code, the access token, the refresh token, the signature
  and an unlisted claim of the `id_token`, the fields of a token response that no definition
  lists, a vault password, a TOTP seed (its bytes and its base32 text), a card number, a CVC,
  the client secret of every provider, and the secret access key and the session token of the
  log store.
- The provider stand-in breaks its contract on purpose: a token response with a token inside a
  listed public field and inside a listed claim, a refused token response with the refresh
  token in `error` and `error_description`, an API response that sends the `Authorization` of
  the request back in its body and in a header (as it is, under several percent-encodings,
  base64 and base64url at each alignment, hexadecimal, in two chunks, inside the address of a
  redirect), a revocation address that sends the token back, a response with `Set-Cookie`, a
  response with a `Content-Encoding` or a `Transfer-Encoding` the node does not remove, a 3xx
  to another host.
- Every call of the router is made, in a success and in a failure. The list of calls is the
  one the router is built from, and the test fails when the set of calls it made differs from
  it.
- The verdict on C1: no marker appears in any response (status, headers, body) as it is,
  base64 or base64url in any of the three alignments, or hexadecimal, in the bytes of the
  response or under the encodings that wrap them: percent escapes, the strings and byte arrays
  of JSON, the two parts of a `forward` frame, base64 text, each of them again inside the
  others. The one exception is the value of the requested field in a successful `release`. A
  TOTP seed is never an exception. A failure carries a body of the one failure form.
- The verdict on C2 and C4: a node asks its platform for connections to port 443 of the hosts
  of the definitions and of the host of its log store only. A credential marker appears only in
  requests to the address the definition of that provider names for that purpose, and the client
  secret of one provider appears in no request to another provider. Both nodes of the walk have
  a log store. Of all markers, a write to the log store carries the session token for the log
  store and no other: no secret of the account, and not the secret access key.
- The node of the reserve role of the fixture takes the delegation of the account from a node
  of the delegation role, so it holds the marked user key. It refuses every call that uses a
  credential, with the marked records of the account in the body of the call, and hands the
  delegation on to a node that uses it. Its responses are part of the verdict on C1, and the
  verdict on C2 and C4 holds that it asked its platform for connections to the host of its log
  store and to no other host.
- The verdict on C5: a node of the forward role asks its platform for connections to the site of
  the vault secret whose use it was handed, and to no other host. The marked value of a vault
  secret appears in the one request to that site, and in no response of the node of the forward
  role or of the node of the delegation role that sealed it. A site that sends the value back,
  in a header or in the body, in the forms of E4, has its response withheld or cut in front of
  the value.
- A record of kind `oauth_imported` with marked tokens is used by `forward`, `refresh` and
  `revoke-token` and refused by `oauth/merge` and `release`. Records of the kinds this release
  removed (`oauth_operator`, `api_key`) are used by no call.

## 4. The calls

| Call | The fields of a successful response and their classes |
| --- | --- |
| `GET /v1/health` | `node` P, `release` P, `platform` P, `custody` P, `role` P, `started_ms` P, `time_ms` P, `configured` P, `closing` P, `accounts` P, `grants` P, `mail_providers` P, `log_store` E and P (`bucket`, `region` and `credentials_expires_ms` E, `shards`, `node_document_ms`, `pending` and `pending_oldest_ms` P), `log` P (seven counts, six counts of failed write attempts under constant cause names, the count of repeated attempts, eight cumulative counts of the time to confirmation under constant bounds, their sum and their count), `load` P (two counts of the calls, two counts of the connections from the backend and their bound, three CPU times and two sizes of the kernel, two counts of the descriptors of the process, two counts of the connections that wait for the end of their peer, and two counts of the faults the node contained: the panics of the program and the accounts it halted; the five of the kernel are null when it exposes none, so is each count of the descriptors when the kernel or the platform gives none, and so are the two counts of the waiting connections on the local platform), `egress` P (the count of opened connections, four counts of failed opens under constant cause names, the counts of repeated opens and of opens in progress, two counts of reused idle connections), `refresh` P (four counts of late token address calls under constant outcome names, the count of those in progress), `state` P (three counts of kept `refresh` responses, merge keys and unconfirmed entries, two counts of idle connections under constant peer names) |
| `POST /v1/config` | `configured` P, `node_document_ms` P |
| `POST /v1/attestation` | `v` P, `platform` P, `document` S (the platform signs the two public keys of the node, the release and the nonce of the caller), `node` P, `challenge` P, `release` P, `challenge_statement` S (its body: `type`, `node`, `challenge`, `time_ms` P, the nonce of the caller E) |
| `POST /v1/messages` | `reply` S (its body: `type`, `ok`, `code`, `node`, `time_ms` P, `user_id`, `challenge`, `key_id`, `not_after_ms` D), `log` P, `grant` D |
| `POST /v1/status` | `grant` D |
| `POST /v1/oauth/begin` | `authorization_url` P, E and D (the address of the definition, `client_id` and `redirect_uri` of the operator configuration, the parameters of the caller, the state, the S256 challenge), `state` P and E, `statement` S, `expires_ms` P |
| `POST /v1/oauth/complete` | `record` C, `public` R, P and D, `statement` S, `log` P |
| `POST /v1/oauth/merge` | `record` C, `public` R, P and D |
| `POST /v1/refresh` | `record` C, `public` R, P and D, `log` P |
| `POST /v1/revoke-token` | `revoked` R, `log` P |
| `POST /v1/forward` | `status` R, `headers` R, the body R, `log` P. A call that asks for a stream: the same four, the body in parts, and the end record `complete` P, `code` P (a failure code) and `message` P (a fixed string of the source) |
| `POST /v1/forward/batch` | `results` P: one result per request, in order, each `status` R, `headers` R, `body_bytes` P and the body R, or `error` P; each with `log` P |
| `POST /v1/mail/verify` | `identity` D, `node` P, `statement` S (identity D, record bindings E/P), `log` P, after E4 |
| `POST /v1/mail/read` | `status` P, `headers` P, bounded provider mail data R, `log` P, after E4 |
| `POST /v1/mail/submit` | `status` P, `headers` P, submission status P, SMTP code R, `log` P, after E4. A lost reply is not a rejection |
| `POST /v1/release` | `value` V, or for a call that named a key to seal to `sealed` V (the value under the seal of that key: the caller holds the key), `log` P |
| `POST /v1/vault/store` | `record` C (its plaintext: the value, the name, the sites and the slots E, the source P; its `id` and nonce P), `log` P |
| `POST /v1/vault/handoff` | `envelope` C (K8: sealed to a node of the forward role; `from` and `to` P), `log` P |
| `POST /v1/vault/send` | `status` R, `headers` R, the body R in parts, and the end record `complete` P, `code` P (a failure code) and `message` P (a fixed string of the source) |
| `POST /v1/close` | `accounts` P |
| `POST /v1/peer/export` | `envelope` C (K2), `logs` E and P (`user_id` E, `seq` P), `next` E |
| `POST /v1/peer/import` | `imported` P, `accounts` E (the `user_id` of every account whose grant the call put in place), `logs` E and P (`user_id` E, `seq` P) |
| `POST /v1/grants/prune` | `pruned` E (the `user_id` of every account whose grant the call dropped), `next` E |
| `POST /v1/log-store/credentials` | `credentials_expires_ms` E, `node_document_ms` P |

The `log` object of a response is P: the `seq` of the entry that holds the event of the call,
the index of the event in that entry, and whether the call created the event. No response
carries an entry: the log store is the one place an entry is read from.

Every failure: `code` P, `message` P, `provider_status` R, `provider_error` R, and `index` P
(the request of a `forward/batch` call the failure is about).

The declassified values, all of them:

| Value | From | Where it leaves |
| --- | --- | --- |
| `user_id`, `challenge`, `sign_pk` and its `key_id`, `log_pk`, `custody`, `not_after_ms` of a grant, and `user_id`, `challenge`, `sign_pk` of a revoke | The command an app sealed to the node, or the transfer a verified peer sealed to it | The reply, the grant state of `messages` and `status`, the statements, the bodies of log entries |
| The public keys of the node | Its private keys | `node`, the binding inside the attestation document |
| The S256 challenge | The PKCE verifier | The authorization address |
| `has_refresh_token` | The token object | `public` |
| The outcome of a check | A secret | The failure code of a call, for example `record_invalid` (a record does not open under the user key, or its plaintext lacks the field the call needs), `not_allowed` (the kind of an opened record), `response_withheld` (a provider response held a token) |

No other value that comes from a secret or from a sealed input leaves in the clear.

`POST /v1/refresh` keeps the response of a successful refresh for 3,600 seconds, for the
account and under the hash of the `ct` of the record that was sent. What it keeps is what the
response held: C, R, P and D values. A token address call that did not answer within the time
limit of the call fails the call, and the node keeps receiving its response for up to 120
seconds: a success that arrives then is kept the same way, when the grant it ran under is still
in force and the node is not closing, and nothing of it leaves otherwise. Section 5.7 of
enclave.md describes it.

## 5. What these rules show and what they do not

They show: when the source of a node and its measurement agree, the operator domain cannot,
with any input, obtain on C1 a token of a record of kind `oauth` or `oauth_imported`, a user
key, a private key of the node, a PKCE verifier or a TOTP seed. A vault value leaves through
`release` only, one requested field at a time, after its log entry. The value of a record of
kind `vault_secret` with slots of a request leaves through no call: it goes, sealed, to a node
of the forward role of the same measurement, and from there into one request to a host of the
record, at a slot of the record, after the log entry of that request. Every request that carries
a credential to a provider has its log entry. On a node with a log store, that entry is in the
log store before the request leaves and before the vault value leaves (protocol.md 7.6), and
what the node writes to the log store is entries, which are ciphertexts under the log public key
of the account, and its own node document, which holds public values.

They do not show:

| Limit | What it means |
| --- | --- |
| The contract of a provider | A token that a provider sends at a place the definition does not list, in another form, or a second credential an API derives from the token and returns, is not found by the checks of E4 |
| The rest of a request that carries a vault secret | The reach of a record binds the host and the slot. Which path of that host a request goes to, and what its body and its other headers are, is chosen by the caller, the operator domain. A host with an address that stores what it receives and returns it to another request, or that returns a value in a form the reflection check does not know, lets the operator domain read the value there. Every such request is on the log with its method, host, path, query and the hash of its body |
| A value a page receives | A value `release` hands out (a record with the slot `field`) is in the hands of the operator domain from then on, sealed or not: the caller chose the key of the seal. The origin of a release is what the caller stated. The rules hold the origin an entry names to the sites of the record, and they do not show that a browser was at that origin |
| A value the operator domain gave | A record `vault/store` made holds a value the operator domain knew, and says so (`source` `operator`). What the rules show for it begins with the record |
| An earlier record | The operator domain stores records and can present an earlier record of a vault secret, with the reach it had then, for as long as a grant is in force. Its use is on the log like any other |
| Consent outside the app | The OAuth application (client id and client secret) belongs to the operator. When a user consents on the authorization page outside the connect flow of the app, that authorization does not pass through a node and these rules do not reach it. The app continues its connect flow only after it verified the signature and the 32-byte `sign_pk` of the node statement (protocol.md 8.2) |
| Providers without PKCE (`slack`, `notion`) | The authorization code passes through the callback of the operator domain, which also holds the client secret: the operator domain can exchange that code itself. With PKCE the verifier never leaves the node, so the code is of no use outside it |
| A token of kind `oauth_imported` | The operator domain held it before the device encrypted it. From then on the node keeps it like any token. What happened to it before is outside these rules |
| APIs that open a lasting access, and signed addresses | The guarantee ends with the log entry of the call |
| The width of the address lists | The `api` lists of the definitions are path prefixes. A credential can reach every address under them |
| `previous` of `oauth/merge` | Any record of kind `oauth` of the same account and provider is taken. The operator domain can choose to move the refresh token of one connection of a user into another connection of the same user and provider. That is a limit of integrity, not of confidentiality |
| The freshness of a record | A node keeps no state about records. The operator domain stores them and can present an older record of an account, for example the one from before a refresh. That decides which token is used. It does not let anyone read one |
| The honesty of the app | An app that is not the published one can leak the master key. Verifying the app is outside this repository |
| Side channels | The size and the time of a response. The sizes of the parts of a stream follow the number of bytes the reflection check holds back, which follows the length of the credential; the size of the request to the provider shows that length as well |
| The log store | The log store is trusted (section 1). An object can be deleted when its retention of 365 days ended. The operator domain can stop the bytes between a node and the store: the node then uses no credential. The store can hold entries of acts that did not take place, and the operator domain, which holds the credentials for the store, can add objects to it: an object counts as an entry of a node when it verifies against its key under the signing key of that node and the store holds the node document of that node (protocol.md 7.4) |
| The transfer to a later release | A node hands user keys to a node of a later release when the release key of the operator signed the measurements of that release and the transparency log Rekor recorded the signature (protocol.md 10.3). So the operator can move the delegations of a node to a program it wrote later, and that program keeps the rules of its own source, not of this one. The notice period between the entry of the log and the transfer is zero. What stays is the record: no such transfer takes place without an entry of the public log for the measurements of that release, and a release that takes delegations names the releases it takes them from in its source. The node verifies the signed entry timestamp of the log and no inclusion proof: that the log keeps every entry rests on the operation of Sigstore Rekor |

## 6. How to check

```bash
cargo test --workspace --locked        # the compile-fail examples, the canary test, the rest
scripts/secret-access.sh               # prints the functions that read a secret and the sink callers
scripts/secret-access.sh --check       # compares them with egress/*.tsv and counts again
cargo clippy --workspace --all-targets --locked -- -D warnings   # the output lints
```

To read the source against this document: start with `protocol/src/secret.rs` (E1), then
`egress/secret-access.tsv` and the functions it names (E2), then
`enclave/src/api/responses.rs` (E3), `enclave/src/oauth.rs` and
`enclave/src/provider_response.rs` (E4, E5), and `enclave/src/vault.rs` (E6).

## Mail credentials

`app_password` of provider `naver_mail` is created on the device and is enclave-use only.
`enclave/src/mail.rs` owns its plaintext. The authenticated account identity is declassified
only after successful IMAP and SMTP authentication; verify binds it, the ciphertext digest,
record id and account signing key in a node statement. OAuth forward/refresh and vault release
refuse this kind. The three mail calls require a configured log store and confirm `mail_request`
before authentication. The encrypted event holds the operation, request parameters and payload
length/digest, never the application password or message body.

The two mail authentication sinks are K6 (`AppPassword::imap`) and K7 (`AppPassword::smtp`).
Both use `Egress::open_mail`, whose destination check admits only imap.naver.com:993 and
smtp.naver.com:465. Certificate verification and the trusted clock stay inside the node.
Protocol error text and authentication transcripts never become response bodies. Read results
pass the existing credential reflection check before the frame response. The provider-contract
assumption and the limits of E4 remain the same as for HTTP forwarding.

All mail calls share the forward semaphore and body budget. A call reserves six body limits
plus two metadata limits to cover MIME and JSON/base64 copies. IMAP calls also reserve the
512 MiB maximum parser buffer of async-imap 0.12, since a declared literal can allocate
ahead of the bounded stream. Every call has an
end-to-end 30 second deadline including admission. IMAP reads use EXAMINE and BODY.PEEK.
SMTP performs one transaction; no transport failure triggers a second connection or submission.
