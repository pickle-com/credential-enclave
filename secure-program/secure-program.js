// The secure program of the Pickle apps. The secure executor of the iOS app (JavaScriptCore) and
// of the Android app (QuickJS) runs this file. It owns the device side of the credential protocol:
// the creation and derivation of the master key, the verification of the attestation of enclave
// nodes, the sealed delivery of grants and revokes, the encryption of credential records, the
// verification and decryption of the credential log, the node ledger, and the transfer of the
// master key between the devices of one account.
//
// This file is the source of truth. The repository pickle-com/interactive-character vendors a
// byte-identical copy at backend/assets/ui/secure-program.js and serves it to the apps. A release
// build of an app loads a served program only when its SHA-256 is the subject of a release
// statement signed by the release key of the operator and recorded in the public transparency log
// (docs/protocol.md, "The secure program release"). Every version an app can load is therefore a
// tag secure-program-v{VERSION} of this repository.
//
// Native functions reach the program through the global `native` only (the bridge primitives of
// the apps); every cryptographic algorithm is a bridge primitive. This file parses formats only
// (base64url, UTF-8, CBOR, query strings). The top level of the file is evaluated with the bridge
// closed, so the top level defines things and calls nothing.
// Contract: docs/ssot/client/secure-executor.md of pickle-com/interactive-character.
(function () {
  "use strict";

  // ---- Constants ----

  const VERSION = 29;
  const MASTER_KEY_SERVICE = "com.pickle.client.secure.master-key";
  const LEDGER_SERVICE = "com.pickle.client.secure.ledger";
  const LEDGER_STORE_KEY = "ledger";
  // The lifetime of a grant is a number of days the user chooses (an integer from 1 to 30, 30 by
  // default). The renewal interval is the smaller of 24 hours and half of that lifetime.
  const DAY_MS = 86400000;
  const GRANT_DAYS_MAX = 30;
  const GRANT_RENEW_MS = 86400000;
  // The period of the log verification (24 hours), the most keys one run of the index
  // verification walks (every node together) and the most entry bodies one run reads (the control
  // entries, the entries of format 1, the entries nobody vouches for, a seq with two linked keys,
  // the landing after expired entries).
  const LOG_VERIFY_INTERVAL_MS = 86400000;
  const LOG_VERIFY_KEYS = 8000;
  const LOG_VERIFY_BODIES = 2000;
  // The log store (docs/protocol.md 7.4 and 7.6): the most listing pages one run reads per node
  // (1,000 keys each), the most object versions one address request names (the limit of the
  // backend route), the digits of seq and of time_ms in an object key, the most events one entry
  // holds, and the timeout of one request to the store.
  const LOG_STORE_PAGES = 8;
  const LOG_STORE_OBJECTS = 100;
  const LOG_STORE_SEQ_DIGITS = 20;
  const LOG_STORE_TIME_DIGITS = 13;
  // The characters of the first five parts of a key of format 2 (seq, time_ms, the kind letter, the
  // count as three digits, the key_id as 16 characters, with their four separators): an input of
  // the chain hash (docs/protocol.md 7.1).
  const LOG_STORE_KEY_FIELDS_CHARS = LOG_STORE_SEQ_DIGITS + 1 + LOG_STORE_TIME_DIGITS + 1 + 1 + 1 + 3 + 1 + 16;
  const LOG_ENTRY_EVENTS = 128;
  const LOG_STORE_TIMEOUT_MS = 20000;
  // The nodes one verification run examines beyond the ledger (the node discovery listing). More
  // unknown prefixes than this leave the run pending (the store state truncated).
  const LOG_STORE_NODES = 16;
  // The retention of an object of the store (Object Lock, days): an entry older than this may be gone
  // (its lock ended; the lifecycle rule of the bucket removes it at 400 days), so a gap of entries
  // older than this is expired, not missing (docs/protocol.md 7.4).
  const LOG_EXPIRES_DAYS = 365;
  // A gap below the vouched end whose next listed key is younger than this is pending, not
  // attention: the node writes an entry the store did not confirm again, with the next write of
  // the account and in its sweep (docs/protocol.md 7.6), so a gap that stays beyond this time is an
  // omission.
  const LOG_GAP_GRACE_MS = 3600000;
  // Reads of the store that have kept failing for this long mark the log (attention): a pending
  // the operator keeps up is not a verification that completes.
  const LOG_STORE_STALE_MS = 3 * DAY_MS;
  // The route of the report of one verification run.
  const LOG_REPORT_PATH = "/api/secure/log/verified";
  // The query keys a presigned listing address may carry besides the signature keys (X-Amz-...):
  // the versions listing, its prefix and delimiter, the markers of the page, the page size (1000)
  // and the encoding of the names in the response (url: the keys are decoded).
  const LISTING_QUERY_KEYS = [
    "versions", "prefix", "delimiter", "key-marker", "version-id-marker", "max-keys", "encoding-type",
  ];
  // The log screen: the days of the overview (drawn from the keys alone), the events of the recent
  // activity (the entries read for the first page), the events of one later page, the keys one
  // listing of the screen reads down a chain, the entries the screen keeps opened in a runtime, the
  // objects whose addresses are requested along with the one being read, and the objects the full
  // verification reads at a time.
  const LOG_OVERVIEW_DAYS = 7;
  const LOG_RECENT_EVENTS = 20;
  const LOG_SCREEN_EVENTS = 50;
  const LOG_DISPLAY_LIST = 1000;
  const LOG_DISPLAY_ENTRIES = 1000;
  const LOG_DISPLAY_AHEAD = 10;
  const LOG_FULL_FETCHES = 8;
  // The limit of the serialized node ledger (UTF-8, bytes).
  const LEDGER_LIMIT_BYTES = 65536;
  // The DER of the AWS Nitro Enclaves Root-G1 certificate (base64url). Its SHA-256 is
  // 641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b.
  const NITRO_ROOT =
    "MIICETCCAZagAwIBAgIRAPkxdWgbkK_hHUbMtOTn-FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoM" +
    "BkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcN" +
    "NDkxMDI4MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMM" +
    "EmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL__Zy" +
    "2YlES1BR5TSksfbb48C8WBoyt7F2Bw7eEtaaP-ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZEh8l5YoQwTcU_" +
    "9KNCMEAwDwYDVR0TAQH_BAUwAwEB_zAdBgNVHQ4EFgQUkCW1DdkFR-eWw5b6cp3PmanfS5YwDgYDVR0PAQH_BAQDAgGG" +
    "MAoGCCqGSM49BAMDA2kAMGYCMQCjfy-Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMC" +
    "MQCi85sWBbJwKKXdS6BptQFuZbT73o_gBh1qUxl_nNr12UO8Yfwr6wPLb-6NIwLz3_Y";
  // The list of accepted measurements: for every enclave release its {release, pcr0, pcr1, pcr2}
  // (96 lower-case hex characters each). Every element is a build that anyone can make again from
  // that tag of the public repository pickle-com/credential-enclave. A nitro document whose PCR0,
  // PCR1 and PCR2 do not all equal an element of this list (or of PRERELEASE_BUILDS when the server
  // target is in PRERELEASE_TARGETS) is refused. A node of a release with log_store true writes
  // the log entry to the log store (storage from which nothing is deleted) before the act the entry
  // precedes, and the binding of such a node must name the value of LOG_STORES.
  const ACCEPTED_RELEASES = [
    // pickle-com/credential-enclave v1.1.0 (commit 98cdbef4902e17d079e2a003804db6b3b10a8140).
    {
      release: "v1.1.0",
      pcr0: "b7750ca30f77ecaaf3637ec64aeb808c20ce1326d2e2bdfe10339eb24474f7a392495086cab56c7b9a3edac9e248f9fc",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "fcdb145cb1d571f5e7d5bd40f2338d25bd32c6c8d293691c090ef81faa63a9fba35e63bde4b9eb09f77f235f6a75be86",
      log_store: true,
    },
    // pickle-com/credential-enclave v1.2.0 (commit e5ad5a26a9c7ad35dc3707119fb6f9d964ee5b6b).
    {
      release: "v1.2.0",
      pcr0: "56aa136a46cdda7e4cc75f88d853b48e9a638c673ba5e8601f2eaceccdb62aae90cb167dfbadcb99b6936ee1bbcb8176",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "48a9ad30d2aed1a74da5a882276040fc8104c1bc978d87c53299bc07f6435beb7c6c5ed58642a63c3e5bcd2c474cb047",
      log_store: true,
    },
    // pickle-com/credential-enclave v1.3.0 (commit 172283b48d4f32d1fb56891729c13c319bb062dd).
    {
      release: "v1.3.0",
      pcr0: "3079688b6a202656abd434c799b8825f2b2594dd574d7bbc35403a2c1dfc4e65497cb9d1d23826e7eaa7994b733066dc",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "44d3c047fafab6c5165e12be192b2fbfbaed760925abd7ddfb1f59f6207d3a53fad31fc27c52fcfdbf45385972831262",
      log_store: true,
    },
    // pickle-com/credential-enclave v1.4.0 (commit dac46abbd60dcf0526a3682b4d27230fd8381de6).
    {
      release: "v1.4.0",
      pcr0: "9fb99e7c9f44808f80eda1937242c3b2117bde968cd4afdcbd277b9ddaf8b2f973e84bffb62794c1a1eddb06d122dd06",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "409f0336df11e68219b758724ce0c20f71deb815b25015a793ea4dc4dfe52a53f29654f45e938850cb8ee90cb419a9d7",
      log_store: true,
    },
    // pickle-com/credential-enclave v1.5.0 (commit ed7ac2a5c0d9c083142f7f709b98f34bddcc18c3).
    {
      release: "v1.5.0",
      pcr0: "1e93cb844f7f355581c45ab375410f83ca754fafe03cd4968976f47dd88b85d30c03040a48afba0f6f2f4e2f94ffa98a",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "37b282369d357e6a182a04bb906495865182c15decc5f19c5a83ef1049beeba7500234429891e5953f80667e8c694d7d",
      log_store: true,
    },
    // pickle-com/credential-enclave v1.5.2 (commit 2dcf8957a4afb78a1c0400e3d37df0053faa97ad).
    {
      release: "v1.5.2",
      pcr0: "edf5a93aec5f096f0bcd6717a2ffcf4265404cf121c1c0a40be66682e7d5f6e0d1a54b841e96e0f91d6ec806aa861143",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "2724b25256d100dbb5a6868d68e1d1dc219415c1a28f21e4a130ca14338466b102349e0737d5185fe34f89a666374639",
      log_store: true,
    },
  ];
  // Measurements of builds that never ran in prod: builds made from commits that are not in the
  // history of the public repository (marked pre-), and releases of the public repository that went
  // to alpha and dev only. They are accepted only when the server target is in PRERELEASE_TARGETS:
  // those envs still hold the log chains written by the nodes of these builds, and the verification
  // of those chains needs the documents of those nodes.
  const PRERELEASE_TARGETS = ["alpha", "dev"];
  const PRERELEASE_BUILDS = [
    {
      release: "pre-v1.1.0",
      pcr0: "2c362ce05f7d902770d2c8548f0d6ee7853199b34ac53b4281412fa5f91b668b7461b645827346e3759126266f555c86",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "b97775faf25cb1bb8d19d373fdd8a59dfe29aefeed2c0133ade1637d7d59f841a218ce665042c5fd9f46b688c4ca40e9",
    },
    {
      release: "pre-v1.1.1",
      pcr0: "974d950fdcad286a75e306f11498ae5bd4cd5d5bd75f5b760719a472b27f2c9e408d177803a6510c9eee9ed6be7f7fcd",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "2ecc25ab9c9d1c5229204b431a66157052815bc35d65ba368fa1448af1556aa10f13bff95730323cedca8cb92db63af9",
    },
    {
      release: "pre-v1.2.0",
      pcr0: "dce85342328a246829fc501d04680ccfda9d43f722f82d233b42e7f7bcc99ce360c117dbdee33bacbe05408b250c07ec",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "4db199114e57f05b048e57a06fc6be7bf51f784ea2a5cc9120528e19f69271cfa220095b228d5d9e3b5032eb0acff12d",
      log_store: true,
    },
    // pickle-com/credential-enclave v1.0.0.
    {
      release: "v1.0.0",
      pcr0: "a49acc0d349d87bea23da55f305efa010d5672b4a14d25599173e89dff67c71527016cddeb1609ad15c306f98e966ad5",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "c4071dc342fc4b0b68fa732e1010fecb14332374d4dccb104a8fe23c9a853b0880475378f247974d05e07b2bbeedee27",
      log_store: true,
    },
    // pickle-com/credential-enclave v1.1.0-rc.1 (commit 4a21460a06b7373260813c826e027b851816cfd3).
    {
      release: "v1.1.0-rc.1",
      pcr0: "b038b65ad0a56493482ef26db2f6e85c66eef7742831c6b0973bb7907d98cd11d5b5e9ca617abf34f2814843d370466f",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "6c1cb1daea2e80ee17c639463f3134b4bdc50cc98c1d9bf496594e4035e1074c19c88a254ca82a25fd5b0c35ebbeb074",
      log_store: true,
    },
  ];
  // The log store per server target: the S3 Object Lock bucket and region that receive the
  // credential log of that env. A nitro node of a release with log_store true is accepted only when
  // the log of its binding equals this value: every node that receives a user key is a node that
  // writes to this bucket first.
  // local is the S3 stand-in of the local stack. It is not the store of a server target (the bridge
  // of a debug build reports the server target prod whatever backend the app talks to): it names
  // the bucket of the path-style addresses a debug build accepts (storeAddressAccepted). A release
  // build pins every address to the host of the store of its server target.
  const LOG_STORES = {
    alpha: { bucket: "character-credential-log-alpha-1", region: "us-west-2" },
    dev: { bucket: "character-credential-log-dev-1", region: "us-west-2" },
    prod: { bucket: "character-credential-log-prod-1", region: "us-west-2" },
    local: { bucket: "character-credential-log-local-1", region: "us-west-2" },
  };
  // The server targets that accept a node of platform local (an ordinary process that no
  // attestation verifies: the custody operator). A release build whose server target is outside
  // this list refuses local nodes. A DEBUG build always accepts them.
  const OPERATOR_CUSTODY_TARGETS = ["alpha", "dev"];
  // The record kinds this program makes in the migration (the device-side sealing of what was
  // stored before the switch), and the most rounds of fetching and uploading one sync runs (one
  // fetch carries up to 100 items).
  const SEALING_KINDS = ["oauth_imported", "vault_password", "vault_totp", "vault_card"];
  const SEALING_ROUNDS = 5;
  // How far the time of a reply of a node may lie before the time of the attestation document of
  // that node (the correction error of the clock of the node).
  const REPLY_SKEW_MS = 5000;

  // ---- Bytes ----

  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  /** Uint8Array -> base64url (no padding). The byte representation of the bridge. */
  function encode(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i += 3) {
      const a = bytes[i];
      const b = bytes[i + 1];
      const c = bytes[i + 2];
      out += ALPHABET[a >> 2] + ALPHABET[((a & 3) << 4) | ((b === undefined ? 0 : b) >> 4)];
      if (b !== undefined) out += ALPHABET[((b & 15) << 2) | ((c === undefined ? 0 : c) >> 6)];
      if (c !== undefined) out += ALPHABET[c & 63];
    }
    return out;
  }

  /** A base64url or base64 string -> Uint8Array. */
  function decode(encoded) {
    const clean = String(encoded).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
    const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
    let bits = 0;
    let acc = 0;
    let at = 0;
    for (let i = 0; i < clean.length; i += 1) {
      const value = ALPHABET.indexOf(clean[i]);
      if (value < 0) throw native.error("invalid_argument", "base64");
      acc = ((acc << 6) | value) & 0xffff;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out[at] = (acc >> bits) & 255;
        at += 1;
      }
    }
    return out;
  }

  /** A string -> UTF-8 bytes. */
  function utf8(value) {
    const out = [];
    for (const symbol of String(value)) {
      const code = symbol.codePointAt(0);
      if (code < 0x80) {
        out.push(code);
      } else if (code < 0x800) {
        out.push(0xc0 | (code >> 6), 0x80 | (code & 63));
      } else if (code < 0x10000) {
        out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
      } else {
        out.push(
          0xf0 | (code >> 18), 0x80 | ((code >> 12) & 63), 0x80 | ((code >> 6) & 63),
          0x80 | (code & 63));
      }
    }
    return new Uint8Array(out);
  }

  /** UTF-8 bytes -> a string. A byte that is not UTF-8 becomes U+FFFD. */
  function text(bytes) {
    let out = "";
    let at = 0;
    while (at < bytes.length) {
      const lead = bytes[at];
      const size = lead < 0x80 ? 1 : lead >= 0xc2 && lead < 0xe0 ? 2 : lead >= 0xe0 && lead < 0xf0 ? 3
        : lead >= 0xf0 && lead < 0xf5 ? 4 : 0;
      let code = size === 1 ? lead : size === 2 ? lead & 0x1f : size === 3 ? lead & 0x0f : lead & 0x07;
      let valid = size > 0 && at + size <= bytes.length;
      for (let i = 1; valid && i < size; i += 1) {
        const next = bytes[at + i];
        if ((next & 0xc0) === 0x80) code = (code << 6) | (next & 0x3f);
        else valid = false;
      }
      // A value that is not the shortest form, a surrogate, and a value above U+10FFFF are not UTF-8.
      if (valid && size === 3 && (code < 0x800 || (code >= 0xd800 && code <= 0xdfff))) valid = false;
      if (valid && size === 4 && (code < 0x10000 || code > 0x10ffff)) valid = false;
      out += valid ? String.fromCodePoint(code) : "�";
      at += valid ? size : 1;
    }
    return out;
  }

  function hex(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i += 1) out += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
    return out;
  }

  /** The concatenation of several byte arrays, in order. */
  function concat(...parts) {
    let total = 0;
    for (const part of parts) total += part.length;
    const out = new Uint8Array(total);
    let at = 0;
    for (const part of parts) {
      out.set(part, at);
      at += part.length;
    }
    return out;
  }

  /** Whether two byte arrays have the same length and content. */
  function equal(a, b) {
    if (a.length !== b.length) return false;
    let difference = 0;
    for (let i = 0; i < a.length; i += 1) difference |= a[i] ^ b[i];
    return difference === 0;
  }

  // ---- CBOR ----

  /** CBOR (RFC 8949) decoding: integers, bstr, tstr, arrays, maps, tags, false, true and null.
   *  Arrays and maps are read in both the definite-length form and the indefinite-length form
   *  (ended by a break): the payload of a real Nitro attestation document is an indefinite-length
   *  map. Strings are read in the definite-length form only. A bstr is a Uint8Array, a map is a
   *  Map, and a tag is removed so that the inner value is returned. */
  function cborDecode(bytes) {
    let at = 0;
    function need(count) {
      if (at + count > bytes.length) throw native.error("attestation_failed", "cbor truncated");
    }
    function argument(additional) {
      if (additional < 24) return additional;
      const width = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4
        : additional === 27 ? 8 : 0;
      if (width === 0) throw native.error("attestation_failed", "cbor length form");
      need(width);
      let value = 0;
      for (let i = 0; i < width; i += 1) value = value * 256 + bytes[at + i];
      at += width;
      return value;
    }
    // Whether the end of an indefinite-length array or map (the break, 0xff) was reached. When it
    // was, that byte is consumed.
    function atBreak() {
      need(1);
      if (bytes[at] !== 0xff) return false;
      at += 1;
      return true;
    }
    function item() {
      need(1);
      const initial = bytes[at];
      at += 1;
      const major = initial >> 5;
      const additional = initial & 31;
      if (major === 0) return argument(additional);
      if (major === 1) return -1 - argument(additional);
      if (major === 2 || major === 3) {
        const length = argument(additional);
        need(length);
        const slice = bytes.subarray(at, at + length);
        at += length;
        return major === 2 ? slice : text(slice);
      }
      if (major === 4) {
        const out = [];
        if (additional === 31) {
          while (!atBreak()) out.push(item());
          return out;
        }
        const count = argument(additional);
        for (let i = 0; i < count; i += 1) out.push(item());
        return out;
      }
      if (major === 5) {
        const out = new Map();
        if (additional === 31) {
          while (!atBreak()) {
            const key = item();
            out.set(key, item());
          }
          return out;
        }
        const count = argument(additional);
        for (let i = 0; i < count; i += 1) {
          const key = item();
          out.set(key, item());
        }
        return out;
      }
      if (major === 6) {
        argument(additional);
        return item();
      }
      if (additional === 20) return false;
      if (additional === 21) return true;
      if (additional === 22) return null;
      throw native.error("attestation_failed", "cbor simple value");
    }
    const value = item();
    if (at !== bytes.length) throw native.error("attestation_failed", "cbor trailing bytes");
    return value;
  }

  /** The CBOR encoding of one bstr (the head followed by the content bytes). */
  function cborByteString(bytes) {
    const n = bytes.length;
    const head = n < 24 ? [0x40 | n] : n < 256 ? [0x58, n] : n < 65536 ? [0x59, n >> 8, n & 255]
      : [0x5a, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
    return concat(new Uint8Array(head), bytes);
  }

  /** The encoding of the Sig_structure a COSE_Sign1 (RFC 9052) signature covers: the array
   *  ["Signature1", protected, h'', payload]. The second and the fourth element are the received
   *  bstr values as they are. */
  function cborEncodeSigStructure(protectedHeader, payload) {
    // 0x84 is an array of 4 elements, 0x6a the head of a 10-byte tstr, 0x40 a bstr of length 0.
    const context = new Uint8Array(
      [0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31]);
    return concat(
      context, cborByteString(protectedHeader), new Uint8Array([0x40]), cborByteString(payload));
  }

  // ---- Attestation ----

  function attestationFailure(reason) {
    return native.error("attestation_failed", reason);
  }

  /** The verification of an AWS Nitro attestation document (COSE_Sign1). document and nonce are
   *  bytes. On success it returns the binding bytes (user_data), the measurement and the time of
   *  the document (milliseconds); on a mismatch it throws attestation_failed. When gate is false
   *  the measurement is not checked against the accepted list (the target of a revoke: the
   *  signature of the document, the nonce and the binding are checked as before). */
  function verifyNitro(document, nonce, gate) {
    const cose = cborDecode(document);
    if (!Array.isArray(cose) || cose.length !== 4) throw attestationFailure("cose shape");
    const protectedHeader = cose[0];
    const payload = cose[2];
    const signature = cose[3];
    if (!(protectedHeader instanceof Uint8Array) || !(cose[1] instanceof Map) ||
        !(payload instanceof Uint8Array) || !(signature instanceof Uint8Array)) {
      throw attestationFailure("cose element types");
    }
    // The protected header is {1: -35} (the algorithm ES384) and the signature is r and s
    // concatenated, 96 bytes.
    const header = cborDecode(protectedHeader);
    if (!(header instanceof Map) || header.size !== 1 || header.get(1) !== -35) {
      throw attestationFailure("cose algorithm");
    }
    if (signature.length !== 96) throw attestationFailure("cose signature length");

    const fields = cborDecode(payload);
    if (!(fields instanceof Map)) throw attestationFailure("document shape");
    const timestamp = fields.get("timestamp");
    const pcrs = fields.get("pcrs");
    const certificate = fields.get("certificate");
    const bundle = fields.get("cabundle");
    const userData = fields.get("user_data");
    const documentNonce = fields.get("nonce");
    if (typeof fields.get("module_id") !== "string" || fields.get("digest") !== "SHA384" ||
        !Number.isSafeInteger(timestamp) || timestamp < 0 || !(pcrs instanceof Map) ||
        !(certificate instanceof Uint8Array) || !Array.isArray(bundle) || bundle.length < 1 ||
        !(userData instanceof Uint8Array) || !(documentNonce instanceof Uint8Array)) {
      throw attestationFailure("document fields");
    }
    for (const authority of bundle) {
      if (!(authority instanceof Uint8Array)) throw attestationFailure("cabundle element");
    }
    pcrs.forEach(function (value, index) {
      const indexed = Number.isSafeInteger(index) && index >= 0;
      if (!indexed || !(value instanceof Uint8Array) || value.length !== 48) {
        throw attestationFailure("pcr shape");
      }
    });

    // The certificate chain: the leaf is certificate, the intermediates are the elements of
    // cabundle from the second on, and the anchor is the one pinned root. The verification time
    // is the timestamp of the document (milliseconds) in seconds.
    const leaf = encode(certificate);
    const trust = native.x509Verify({
      leaf: leaf, intermediates: bundle.slice(1).map(encode), anchors: [NITRO_ROOT],
      atEpochS: Math.floor(timestamp / 1000),
    });
    if (!trust.ok) throw attestationFailure("certificate chain");
    const key = native.x509PublicKey(leaf);
    if (key.algorithm !== "ec" || key.bits !== 384) throw attestationFailure("certificate key");
    const signed = native.ecdsaVerify({
      curve: "p384", hash: "sha384", format: "raw", publicKey: key.publicKey,
      message: encode(cborEncodeSigStructure(protectedHeader, payload)), signature: encode(signature),
    });
    if (!signed) throw attestationFailure("cose signature");

    if (!equal(documentNonce, nonce)) throw attestationFailure("nonce");

    // The measurement: PCR0, PCR1 and PCR2 must all equal one element of the accepted list. A PCR
    // whose value is all zero is the value of a debug-mode enclave and is accepted by no list.
    const measurement = { pcr0: "", pcr1: "", pcr2: "" };
    for (const index of [0, 1, 2]) {
      const value = pcrs.get(index);
      if (value === undefined || (gate && /^0+$/.test(hex(value)))) throw attestationFailure("measurement");
      measurement["pcr" + index] = hex(value);
    }
    const prerelease = PRERELEASE_TARGETS.indexOf(native.deviceInfo().server_target) >= 0;
    const accepted = ACCEPTED_RELEASES.concat(prerelease ? PRERELEASE_BUILDS : []).find(function (release) {
      return release.pcr0 === measurement.pcr0 && release.pcr1 === measurement.pcr1 &&
        release.pcr2 === measurement.pcr2;
    });
    if (gate && accepted === undefined) throw attestationFailure("measurement");
    return {
      binding: userData, measurement: measurement, timeMs: timestamp,
      logStore: gate && accepted.log_store === true,
    };
  }

  /** The verification of a document of platform local: UTF-8 JSON {v, platform, binding, nonce,
   *  time_ms} without a signature (a node that no attestation verifies). Only a DEBUG build or an
   *  app whose server target is in OPERATOR_CUSTODY_TARGETS accepts it (when gate is false this
   *  condition is not checked: the target of a revoke). The verification is the nonce match only.
   *  On success it returns the binding bytes and the time of the document (milliseconds). */
  function verifyLocal(document, nonce, gate) {
    const device = native.deviceInfo();
    if (gate && device.debug_build !== true && OPERATOR_CUSTODY_TARGETS.indexOf(device.server_target) < 0) {
      throw attestationFailure("local platform is not accepted by this build");
    }
    const fields = JSON.parse(text(document));
    if (fields === null || typeof fields !== "object" || fields.v !== 1 || fields.platform !== "local" ||
        !Number.isSafeInteger(fields.time_ms) || fields.time_ms < 0) {
      throw attestationFailure("local document shape");
    }
    if (!equal(decode(fields.nonce), nonce)) throw attestationFailure("nonce");
    return { binding: decode(fields.binding), timeMs: fields.time_ms };
  }

  /** Verifies one attestation response of a node. nonce is the value sent with the request
   *  (base64url). The signing public key, the sealing public key and the release of the node are
   *  read from the binding the document binds only (the node and release fields of the response
   *  are not read). custody is the kind of user key that node receives: enclave for platform
   *  nitro, operator for local. timeMs is the time of that node as the document carries it. The
   *  challenge of the response is a value outside the document, so the signed statement that this
   *  node issued that challenge in answer to the nonce of this request (challenge_statement) is
   *  checked with the signing public key the document binds. When gate is false the acceptance
   *  conditions (the accepted measurements, debug mode, a build that accepts local) are not
   *  checked: used only for the target of a revoke, which hands no user key over. Returns {node,
   *  signPk, sealPk, release, platform, custody, timeMs, measurement}. */
  function verifyAttestation(response, nonce, gate) {
    try {
      if (response === null || typeof response !== "object" || response.v !== 1) {
        throw attestationFailure("response shape");
      }
      const document = decode(response.document);
      const sent = decode(nonce);
      let bindingBytes = null;
      let measurement = null;
      let timeMs = 0;
      let logStore = false;
      if (response.platform === "nitro") {
        const verified = verifyNitro(document, sent, gate !== false);
        bindingBytes = verified.binding;
        measurement = verified.measurement;
        timeMs = verified.timeMs;
        logStore = verified.logStore;
      } else if (response.platform === "local") {
        const verified = verifyLocal(document, sent, gate !== false);
        bindingBytes = verified.binding;
        timeMs = verified.timeMs;
      } else {
        throw attestationFailure("unknown platform");
      }
      // The binding: UTF-8 JSON {v, sign, seal, release}, at most 512 bytes.
      if (bindingBytes.length > 512) throw attestationFailure("binding size");
      const binding = JSON.parse(text(bindingBytes));
      if (binding === null || typeof binding !== "object" || binding.v !== 1 ||
          typeof binding.release !== "string" || binding.release === "") {
        throw attestationFailure("binding shape");
      }
      const signPk = decode(binding.sign);
      const sealPk = decode(binding.seal);
      if (signPk.length !== 32 || sealPk.length !== 32) throw attestationFailure("binding keys");
      // The log store: the binding names the bucket a node of that release writes to. A node that
      // writes somewhere other than the bucket of this server target, and a node that names no
      // bucket, is not accepted.
      if (logStore) {
        const expected = LOG_STORES[native.deviceInfo().server_target];
        const log = binding.log;
        if (expected === undefined || log === null || typeof log !== "object" ||
            log.bucket !== expected.bucket || log.region !== expected.region) {
          throw attestationFailure("log store");
        }
      }
      // The challenge statement: the signed value that this node issued the challenge of the
      // response in answer to the nonce of this request. The challenge is plaintext outside the
      // document, so without the statement the relay could hand the challenge of an earlier request
      // and replay the signed reply of an old command that carried that challenge. A response
      // without the statement, or with a statement that does not match, is not accepted.
      let statement = null;
      try {
        statement = openSigned(response.challenge_statement, encode(signPk), purpose("challenge") + "\n");
      } catch (error) {
        throw attestationFailure("challenge statement");
      }
      if (statement.type !== "challenge" || statement.node !== encode(signPk) ||
          statement.nonce !== encode(sent) || typeof response.challenge !== "string" ||
          statement.challenge !== response.challenge) {
        throw attestationFailure("challenge statement");
      }
      return {
        node: encode(signPk), signPk: encode(signPk), sealPk: encode(sealPk),
        release: binding.release, platform: response.platform,
        custody: response.platform === "nitro" ? "enclave" : "operator", timeMs: timeMs,
        measurement: measurement,
      };
    } catch (error) {
      if (error && error.code === "attestation_failed") throw error;
      throw attestationFailure(String((error && error.message) || error));
    }
  }

  // ---- Keys ----

  /** The purpose strings of the protocol: used as HKDF info, HPKE info and signature purposes
   *  (with a newline appended). */
  function purpose(name) {
    return "pickle.secure.v1." + name;
  }

  function info(name) {
    return encode(utf8(purpose(name)));
  }

  function userId() {
    return native.deviceInfo().user_id;
  }

  /** The keychain item of the master key: one per account, synchronized through the iCloud
   *  Keychain. */
  function masterKeyItem() {
    return { service: MASTER_KEY_SERVICE, account: userId(), synchronizable: true };
  }

  function readMasterKey() {
    return native.keychainGet(masterKeyItem());
  }

  /** Every key derived from the master key (nothing is stored: the same master key gives the same
   *  values): the account signing seed and public key, the log decryption private key and public
   *  key, the user key of each custody, and the key_id. userKeys.enclave is handed only to nitro
   *  nodes whose attestation was verified, and userKeys.operator to local nodes: the user key of
   *  the enclave custody never goes to an unverified party. */
  function deriveKeys(masterKey) {
    const signSeed = native.hkdf("sha256", masterKey, null, info("sign"), 32);
    const logSk = native.hkdf("sha256", masterKey, null, info("log"), 32);
    const signPk = native.ed25519PublicKey(signSeed);
    return {
      signSeed: signSeed,
      signPk: signPk,
      logSk: logSk,
      logPk: native.x25519PublicKey(logSk),
      userKeys: {
        enclave: native.hkdf("sha256", masterKey, null, info("user-key"), 32),
        operator: native.hkdf("sha256", masterKey, null, info("user-key.operator"), 32),
      },
      keyId: hex(decode(native.sha256(signPk)).subarray(0, 8)),
    };
  }

  function writeMasterKey(bytes) {
    const item = masterKeyItem();
    native.keychainSet({
      service: item.service, account: item.account, value: bytes,
      synchronizable: true, accessible: "after_first_unlock",
    });
  }

  function deleteMasterKey() {
    native.keychainDelete(masterKeyItem());
  }

  // ---- The api ----

  /** A call of an api route (the account credential is carried). The values of query are strings.
   *  Returns {status, json} where json is the JSON object of the response body. A response outside
   *  2xx throws the first string among code, detail and error of the body (or "http_" + status
   *  when there is none) as the failure code, and a 2xx response whose body is not a JSON object is
   *  invalid_response. */
  async function api(method, path, body, query) {
    const request = { method: method, path: path };
    if (query) request.query = query;
    if (body !== undefined && body !== null) request.body = JSON.stringify(body);
    const response = await native.http(request);
    let json = null;
    try {
      json = JSON.parse(response.body);
    } catch (error) {
      json = null;
    }
    const isObject = json !== null && typeof json === "object" && !Array.isArray(json);
    if (response.status < 200 || response.status > 299) {
      const candidates = isObject ? [json.code, json.detail, json.error] : [];
      const code = candidates.find(function (value) { return typeof value === "string" && value !== ""; });
      throw native.error(code === undefined ? "http_" + response.status : code, method + " " + path);
    }
    if (!isObject) throw native.error("invalid_response", method + " " + path);
    return { status: response.status, json: json };
  }

  // ---- Signed values ----

  /** Opens a signed value {body, sig}: the signed input is the purpose string (context, ending in
   *  a newline) followed by the received body bytes as they are. The body is parsed as JSON only
   *  after the signature verified. A signature mismatch and a malformed value are bad_signature, a
   *  body whose v is not version (1 when not given) is unsupported_version. */
  function openSigned(signed, publicKey, context, version) {
    let parsed = null;
    try {
      const body = decode(signed.body);
      const valid = native.ed25519Verify(publicKey, encode(concat(utf8(context), body)), signed.sig);
      if (valid) parsed = JSON.parse(text(body));
    } catch (error) {
      parsed = null;
    }
    if (parsed === null || typeof parsed !== "object") throw native.error("bad_signature", context.trim());
    if (parsed.v !== (version === undefined ? 1 : version)) {
      throw native.error("unsupported_version", context.trim());
    }
    return parsed;
  }

  // ---- The node ledger ----

  const NODE_ID = /^[A-Za-z0-9_-]{43}$/;
  // The base64url of 32 zero bytes: the end of a chain without entries and the prev of the first
  // entry.
  const ZERO_HASH = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

  function ledgerItem() {
    return { service: LEDGER_SERVICE, account: userId(), synchronizable: true };
  }

  function emptyLedger() {
    return {
      v: 1, revoked_ms: 0, resumed_ms: 0, ttl_days: GRANT_DAYS_MAX, ttl_set_ms: 0,
      // The time the reads of the log store began to fail, 0 while they succeed (a run that
      // completes with the store read clears it).
      store_failing_ms: 0,
      nodes: Object.create(null),
    };
  }

  /** The days of the grant lifetime: the value when it is an integer from 1 to 30, otherwise 30. */
  function grantDays(value) {
    return Number.isSafeInteger(value) && value >= 1 && value <= GRANT_DAYS_MAX ? value : GRANT_DAYS_MAX;
  }

  /** The value when it is a non-negative integer, otherwise 0. */
  function whole(value) {
    return Number.isSafeInteger(value) && value >= 0 ? value : 0;
  }

  /** One point of a chain {seq, hash, time_ms}: time_ms is the time of the entry at that point
   *  (0 when it is not known: the empty chain, and a point a program before this one wrote). null
   *  when the form is wrong. */
  function chainPoint(value) {
    if (value === null || typeof value !== "object") return null;
    if (!Number.isSafeInteger(value.seq) || value.seq < 0 || typeof value.hash !== "string") return null;
    return { seq: value.seq, hash: value.hash, time_ms: whole(value.time_ms) };
  }

  /** Reads one stored JSON text as a ledger. A missing value and a malformed value are the empty
   *  ledger, and a malformed node is left out. The key order of the nodes object is the
   *  serialization order. */
  function parseLedger(json) {
    const ledger = emptyLedger();
    let raw = null;
    try {
      raw = json === null ? null : JSON.parse(json);
    } catch (error) {
      raw = null;
    }
    if (raw === null || typeof raw !== "object" || raw.v !== 1) return ledger;
    ledger.revoked_ms = whole(raw.revoked_ms);
    ledger.resumed_ms = whole(raw.resumed_ms);
    ledger.ttl_days = grantDays(raw.ttl_days);
    ledger.ttl_set_ms = whole(raw.ttl_set_ms);
    ledger.store_failing_ms = whole(raw.store_failing_ms);
    const nodes = raw.nodes !== null && typeof raw.nodes === "object" ? raw.nodes : {};
    for (const id of Object.keys(nodes)) {
      const node = nodes[id];
      if (!NODE_ID.test(id) || node === null || typeof node !== "object" ||
          typeof node.sign_pk !== "string" || typeof node.seal_pk !== "string") {
        continue;
      }
      ledger.nodes[id] = {
        sign_pk: node.sign_pk, seal_pk: node.seal_pk,
        platform: String(node.platform), release: String(node.release),
        first_ms: whole(node.first_ms), granted_ms: whole(node.granted_ms),
        not_after_ms: whole(node.not_after_ms),
        checkpoint: chainPoint(node.checkpoint) || { seq: 0, hash: ZERO_HASH, time_ms: 0 },
        final: chainPoint(node.final), gone_ms: whole(node.gone_ms),
        // How the node entered the ledger: grant (a grant of this app or the tracing of a
        // delegation transfer) or store (found in the log store only: no grant of this app and no
        // traced transfer explains it).
        origin: node.origin === "store" ? "store" : "grant",
        // For a node of origin store: the time an entry sealed to the key of this account was
        // first verified on it (a delegation the app did not make), 0 otherwise.
        unknown_ms: node.origin === "store" ? whole(node.unknown_ms) : 0,
      };
    }
    return ledger;
  }

  /** The merge of two ledgers. The nodes are the union; a node present in both takes the
   *  granted_ms and not_after_ms of the side with the larger granted_ms, the checkpoint of the side
   *  with the larger checkpoint.seq, the final that is not null, the smaller non-zero gone_ms, the
   *  smaller first_ms, the non-empty sealing public key (with the platform and release of that
   *  side), the origin grant when either side has it, and the smaller non-zero unknown_ms (0 when
   *  the origin is grant). revoked_ms and resumed_ms are each the larger value, ttl_days is the
   *  value of the side with the larger ttl_set_ms (the one set later), and store_failing_ms is the
   *  smaller non-zero value. */
  function mergeLedger(a, b) {
    const merged = emptyLedger();
    merged.revoked_ms = Math.max(a.revoked_ms, b.revoked_ms);
    merged.resumed_ms = Math.max(a.resumed_ms, b.resumed_ms);
    const later = b.ttl_set_ms > a.ttl_set_ms ? b : a;
    merged.ttl_days = later.ttl_days;
    merged.ttl_set_ms = later.ttl_set_ms;
    merged.store_failing_ms = a.store_failing_ms === 0 || b.store_failing_ms === 0
      ? Math.max(a.store_failing_ms, b.store_failing_ms)
      : Math.min(a.store_failing_ms, b.store_failing_ms);
    for (const side of [a, b]) {
      for (const id of Object.keys(side.nodes)) {
        const node = side.nodes[id];
        const kept = merged.nodes[id];
        if (kept === undefined) {
          merged.nodes[id] = {
            sign_pk: node.sign_pk, seal_pk: node.seal_pk, platform: node.platform,
            release: node.release, first_ms: node.first_ms, granted_ms: node.granted_ms,
            not_after_ms: node.not_after_ms,
            checkpoint: {
              seq: node.checkpoint.seq, hash: node.checkpoint.hash, time_ms: node.checkpoint.time_ms,
            },
            final: node.final === null ? null : { seq: node.final.seq, hash: node.final.hash },
            gone_ms: node.gone_ms, origin: node.origin, unknown_ms: node.unknown_ms,
          };
          continue;
        }
        kept.first_ms = Math.min(kept.first_ms, node.first_ms);
        if (kept.origin === "store" && node.origin !== "store") kept.origin = "grant";
        if (node.unknown_ms !== 0 && (kept.unknown_ms === 0 || node.unknown_ms < kept.unknown_ms)) {
          kept.unknown_ms = node.unknown_ms;
        }
        if (kept.origin !== "store") kept.unknown_ms = 0;
        // A node that entered through the tracing of a delegation transfer has an empty sealing
        // public key: the value of the side that verified the attestation is used.
        if (kept.seal_pk === "" && node.seal_pk !== "") {
          kept.seal_pk = node.seal_pk;
          kept.platform = node.platform;
          kept.release = node.release;
        }
        if (node.granted_ms > kept.granted_ms) {
          kept.granted_ms = node.granted_ms;
          kept.not_after_ms = node.not_after_ms;
        }
        if (node.checkpoint.seq > kept.checkpoint.seq) {
          kept.checkpoint = {
            seq: node.checkpoint.seq, hash: node.checkpoint.hash, time_ms: node.checkpoint.time_ms,
          };
        }
        if (kept.final === null && node.final !== null) {
          kept.final = { seq: node.final.seq, hash: node.final.hash };
        }
        if (node.gone_ms !== 0 && (kept.gone_ms === 0 || node.gone_ms < kept.gone_ms)) {
          kept.gone_ms = node.gone_ms;
        }
      }
    }
    return merged;
  }

  /** Reads the node ledger: the merge of the keychain item and the device copy (when the
   *  synchronization between devices overwrites one side's write, the other side remains). */
  function loadLedger() {
    const kept = native.keychainGet(ledgerItem());
    const keychainLedger = parseLedger(kept === null ? null : text(decode(kept)));
    return mergeLedger(keychainLedger, parseLedger(native.storeGet(LEDGER_STORE_KEY)));
  }

  /** Writes the node ledger to the keychain item and the device copy (a side whose stored value is
   *  the same is not written). When the serialization exceeds the limit, the nodes whose
   *  verification reached the final head (final is set and checkpoint.seq equals final.seq) are
   *  removed, oldest gone_ms first, until it fits. */
  function saveLedger(ledger) {
    let json = JSON.stringify(ledger);
    if (utf8(json).length > LEDGER_LIMIT_BYTES) {
      const finished = Object.keys(ledger.nodes).filter(function (id) {
        const node = ledger.nodes[id];
        return node.final !== null && node.checkpoint.seq === node.final.seq;
      });
      finished.sort(function (x, y) { return ledger.nodes[x].gone_ms - ledger.nodes[y].gone_ms; });
      for (const id of finished) {
        delete ledger.nodes[id];
        json = JSON.stringify(ledger);
        if (utf8(json).length <= LEDGER_LIMIT_BYTES) break;
      }
    }
    const item = ledgerItem();
    const value = encode(utf8(json));
    if (native.keychainGet(item) !== value) {
      native.keychainSet({
        service: item.service, account: item.account, value: value,
        synchronizable: true, accessible: "after_first_unlock",
      });
    }
    if (native.storeGet(LEDGER_STORE_KEY) !== json) native.storeSet(LEDGER_STORE_KEY, json);
  }

  /** The lifetime of a grant as the ledger sets it (milliseconds). */
  function grantTtlMs(ledger) {
    return ledger.ttl_days * DAY_MS;
  }

  /** The interval at which a grant is handed again: the smaller of 24 hours and half of the
   *  lifetime (12 hours for a lifetime of one day). */
  function grantRenewMs(ledger) {
    return Math.min(GRANT_RENEW_MS, grantTtlMs(ledger) / 2);
  }

  /** Whether the user turned delegation off. */
  function delegationOff(ledger) {
    return ledger.revoked_ms > ledger.resumed_ms;
  }

  /** Whether that node holds a grant within its time. A grant handed before the last revocation
   *  time counts as revoked and is not counted. */
  function holdsGrant(ledger, id, now) {
    const node = ledger.nodes[id];
    return node !== undefined && node.granted_ms > ledger.revoked_ms && node.not_after_ms > now;
  }

  /** The published state grant: accepted is the Set of node ids accepted this time. When every one
   *  of them holds a grant within its time the state is active, when only some do it is partial,
   *  when none does it is none, and when delegation is off it is off. not_after_ms is the earliest
   *  end among those grants. */
  function grantState(ledger, accepted, now) {
    if (delegationOff(ledger)) return { state: "off", not_after_ms: 0 };
    let holding = 0;
    let earliest = 0;
    accepted.forEach(function (id) {
      if (!holdsGrant(ledger, id, now)) return;
      holding += 1;
      const limit = ledger.nodes[id].not_after_ms;
      earliest = earliest === 0 ? limit : Math.min(earliest, limit);
    });
    const state = holding === 0 ? "none" : holding === accepted.size ? "active" : "partial";
    return { state: state, not_after_ms: earliest };
  }

  // ---- Delegation ----

  /** Sends one command to a node. The command JSON is signed with the account signing key, and
   *  {payload, sig} is sealed with HPKE to the sealing public key of that node as the envelope {v,
   *  node, enc, ct} carried by the relay route. The reply is checked, after its node signature, for
   *  its type, node, account, challenge and key_id being those of the sent command. A failure reply
   *  signed by the node has its code as the failure code. node is {node, signPk, sealPk}. Returns
   *  the verified reply body. */
  async function sendCommand(node, command, replyType, keys) {
    const payload = utf8(JSON.stringify(command));
    const signature = native.ed25519Sign(
      keys.signSeed, encode(concat(utf8(purpose("command") + "\n"), payload)));
    const signed = utf8(JSON.stringify({ payload: encode(payload), sig: signature }));
    const sealed = native.hpkeSeal({
      kem: "x25519", kdf: "sha256", aead: "chacha20poly1305", recipientPublicKey: node.sealPk,
      info: info("message"), aad: encode(utf8(node.node)), plaintext: encode(signed),
    });
    const envelope = { v: 1, node: node.node, enc: sealed.enc, ct: sealed.ciphertext };
    const path = "/api/secure/nodes/" + node.node + "/messages";
    const response = await api("POST", path, { envelope: envelope });
    const reply = openSigned(response.json.reply, node.signPk, purpose("reply") + "\n");
    if (reply.node !== node.node) throw native.error("bad_signature", "reply is from another node");
    // The failure reply of a node that could not open the envelope has an empty account, challenge
    // and key_id: the failure is checked first.
    if (reply.ok !== true) {
      const refused = typeof reply.code === "string" && reply.code !== "";
      throw native.error(refused ? reply.code : "bad_signature", replyType);
    }
    if (reply.type !== replyType || reply.user_id !== command.user_id ||
        reply.challenge !== command.challenge || reply.key_id !== keys.keyId) {
      throw native.error("bad_signature", "reply is not for this command");
    }
    // The reply must be the one to this command. The challenge is plaintext outside the
    // attestation document, so the relay can swap in an old value, and then the signed reply of an
    // old command passes every comparison above. A reply that lies more than REPLY_SKEW_MS before
    // the time of the document verified this time (the time of a node whose freshness the request
    // nonce established) is not the reply to this command.
    if (whole(reply.time_ms) + REPLY_SKEW_MS < node.timeMs) {
      throw native.error("bad_signature", "reply predates the attestation");
    }
    return reply;
  }

  /** Sends a grant: the user key of the custody of that node, the two public keys and the expiry.
   *  The expiry is the time of the attestation document of that node (node.timeMs) plus the
   *  lifetime (the device clock is not used: the grant of a device whose clock runs ahead is not
   *  refused). The expiry the node accepted is not_after_ms of the reply. Returns {granted_ms,
   *  not_after_ms} for the ledger, both in device clock time: not_after_ms is now plus the lifetime
   *  the node accepted (the expiry of the reply minus the time of the document). */
  async function sendGrant(node, challenge, keys, ttlMs) {
    const reply = await sendCommand(node, {
      v: 1, type: "grant", user_id: userId(), node: node.node, challenge: challenge,
      sign_pk: keys.signPk, log_pk: keys.logPk, custody: node.custody,
      user_key: keys.userKeys[node.custody], not_after_ms: node.timeMs + ttlMs, policy: {},
    }, "grant_reply", keys);
    const lifetime = Math.min(ttlMs, Math.max(0, whole(reply.not_after_ms) - node.timeMs));
    const granted = native.nowMs();
    return { granted_ms: granted, not_after_ms: granted + lifetime };
  }

  /** Sends the revocation of a grant: the node erases the user key of that account. */
  async function sendRevoke(node, challenge, keys) {
    await sendCommand(node, {
      v: 1, type: "revoke", user_id: userId(), node: node.node, challenge: challenge,
      sign_pk: keys.signPk,
    }, "revoke_reply", keys);
  }

  // ---- Records ----

  /** The custody of a record the app makes: among the nodes of the ledger that hold a grant within
   *  its time, enclave is preferred. null when there is no such node. */
  function heldCustody(ledger, now) {
    let found = null;
    for (const id of Object.keys(ledger.nodes)) {
      if (!holdsGrant(ledger, id, now)) continue;
      if (ledger.nodes[id].platform === "nitro") return "enclave";
      found = "operator";
    }
    return found;
  }

  /** Decides the custody of a record the app makes. When delegation is off it is delegation_off.
   *  When no node holds a grant within its time, one sync runs and the ledger is read again. When
   *  there still is none it is grant_required (no record is made under a custody that no node can
   *  open). */
  async function recordCustody() {
    const ledger = loadLedger();
    if (delegationOff(ledger)) throw native.error("delegation_off", "delegation is turned off");
    let custody = heldCustody(ledger, native.nowMs());
    if (custody === null) {
      const outcome = await runSync();
      if (outcome.keyState !== "present") throw native.error("key_required", outcome.keyState);
      custody = heldCustody(loadLedger(), native.nowMs());
    }
    if (custody === null) throw native.error("grant_required", "no node holds a grant");
    return custody;
  }

  /** Makes one credential record. The record key is derived from the user key of that custody with
   *  the record id (16 random bytes) as the salt, and the plaintext bytes (plaintext: base64url)
   *  are encrypted with ChaCha20-Poly1305 under a random 12-byte nonce. The AAD binds the id, the
   *  account, the key_id, the custody, the kind and the provider. */
  function sealRecordBytes(keys, custody, kind, provider, plaintext) {
    const id = native.randomBytes(16);
    const nonce = native.randomBytes(12);
    const user = userId();
    const recordKey = native.hkdf("sha256", keys.userKeys[custody], id, info("record"), 32);
    const aad = [purpose("record"), "1", id, user, keys.keyId, custody, kind, provider].join("\n");
    const ct = native.aeadSeal({
      alg: "chacha20poly1305", key: recordKey, nonce: nonce, aad: encode(utf8(aad)), plaintext: plaintext,
    });
    return {
      v: 1, id: id, user_id: user, key_id: keys.keyId, custody: custody, kind: kind,
      provider: provider, nonce: nonce, ct: ct,
    };
  }

  /** Makes one credential record whose plaintext is the JSON of plaintextObject. */
  function sealRecord(keys, custody, kind, provider, plaintextObject) {
    return sealRecordBytes(keys, custody, kind, provider, encode(utf8(JSON.stringify(plaintextObject))));
  }

  // ---- The log ----

  const PROVIDER_NAMES = new Map([
    ["google_workspace", "Google"], ["microsoft", "Microsoft"], ["slack", "Slack"],
    ["notion", "Notion"], ["x", "X"], ["link", "Link"], ["granola", "Granola"],
    ["mercury", "Mercury"], ["naver_mail", "NAVER Mail"], ["github", "GitHub"],
  ]);

  // For every service (a product inside a provider) of a provider request: the display name, the
  // short name of the summary line (appended to the provider name; an empty value is not appended),
  // and the icon (a definition image ui_image/{name}: when glyph is true a glyph on a tile, when
  // false an image that fills the tile). A service outside the table has an empty icon.
  const SERVICES = new Map([
    ["gmail", { name: "Gmail", short: "Gmail", image: "product-gmail", glyph: true }],
    ["google_calendar", { name: "Google Calendar", short: "Calendar", image: "product-google-calendar", glyph: true }],
    ["google_drive", { name: "Google Drive", short: "Drive", image: "product-google-drive", glyph: true }],
    ["google_workspace", { name: "Google", short: "", image: "connection-icon-google-workspace-mail", glyph: false }],
    ["outlook_mail", { name: "Outlook", short: "Mail", image: "connection-icon-microsoft", glyph: false }],
    ["outlook_calendar", { name: "Outlook Calendar", short: "Calendar", image: "connection-icon-microsoft", glyph: false }],
    ["teams", { name: "Microsoft Teams", short: "Teams", image: "connection-icon-microsoft", glyph: false }],
    ["microsoft", { name: "Microsoft", short: "", image: "connection-icon-microsoft", glyph: false }],
    ["slack", { name: "Slack", short: "", image: "connection-icon-slack", glyph: false }],
    ["notion", { name: "Notion", short: "", image: "connection-icon-notion", glyph: false }],
    ["x", { name: "X", short: "", image: "connection-icon-x", glyph: false }],
    ["link", { name: "Link", short: "", image: "connection-icon-link", glyph: false }],
    ["granola", { name: "Granola", short: "", image: "connection-icon-granola", glyph: false }],
    ["mercury", { name: "Mercury", short: "", image: "connection-icon-mercury", glyph: false }],
    ["naver_mail", { name: "NAVER Mail", short: "", image: "connection-icon-naver-mail", glyph: false }],
    ["github", { name: "GitHub", short: "", image: "connection-icon-github", glyph: false }],
  ]);

  /** The service id of a provider request: google_workspace is split by host and path into Gmail,
   *  Calendar and Drive, microsoft by path into Teams (chats, teams), mail and calendar, and every
   *  other provider is the provider itself. */
  function serviceOf(provider, host, path) {
    if (provider === "google_workspace") {
      if (host === "gmail.googleapis.com") return "gmail";
      if (path.startsWith("/calendar/")) return "google_calendar";
      if (path.startsWith("/drive/") || path.startsWith("/upload/drive/")) return "google_drive";
      return "google_workspace";
    }
    if (provider === "microsoft") {
      if (path.indexOf("/chats/") >= 0 || path.indexOf("/teams/") >= 0 || path.indexOf("/joinedTeams") >= 0) {
        return "teams";
      }
      if (path.indexOf("/messages") >= 0 || path.indexOf("/mailFolders") >= 0 || path.indexOf("/sendMail") >= 0) {
        return "outlook_mail";
      }
      if (path.indexOf("/events") >= 0 || path.indexOf("/calendar") >= 0) return "outlook_calendar";
      return "microsoft";
    }
    return provider;
  }

  function providerName(provider) {
    const name = PROVIDER_NAMES.get(provider);
    return name === undefined ? String(provider) : name;
  }

  function serviceName(service) {
    const entry = SERVICES.get(service);
    return entry === undefined ? providerName(service) : entry.name;
  }

  // The kinds of context the caller (the operator domain) declared. The definition chooses its
  // wording per kind.
  const CONTEXT_KINDS = new Map([
    ["connect:naver_mail", "connect"], ["connect:installation", "repositories"],
    ["link:spend_watch", "payment_check"], ["browser:link_card", "checkout_card"],
    ["browser:fill", "web_fill"], ["context:today_calendar", "today_calendar"],
    ["profile:connected_profiles", "profiles"], ["profile:x_bio", "x_bio"],
    ["connect", "connect"], ["connect:identity", "identity"], ["connect:rejected", "undo_connect"],
    ["refresh", "signed_in"], ["refresh:auth_failure", "signed_in"], ["refresh:scheduled", "signed_in"],
    ["disconnect", "disconnect"], ["account:delete", "account_delete"],
    ["operator:connection_smoke", "smoke"],
  ]);

  /** The kind of a context: the value of the table, `cli:*` is task (a task being handled), and
   *  everything else (the memo the forwarding proxy attaches to a git or gh request of the isolated
   *  shell: `git fetch owner/repo`, `gh GET /repos/...`, `gh graphql read IssueList owner/repo`) is
   *  memo (the definition shows the context string as it is). An absent context is the empty
   *  string. */
  function contextKind(context) {
    if (typeof context !== "string" || context === "") return "";
    const kind = CONTEXT_KINDS.get(context);
    if (kind !== undefined) return kind;
    return context.startsWith("cli:") ? "task" : "memo";
  }

  // The GitHub memos of the forwarding proxy that belong to read requests: `git fetch …`,
  // `gh GET …`, `gh HEAD …`, `gh graphql read …`. A GraphQL read is a POST, so without the memo it
  // would show as Changed.
  function readMemo(context) {
    if (typeof context !== "string") return false;
    return context.startsWith("git fetch ") || context.startsWith("gh GET ") ||
      context.startsWith("gh HEAD ") || context.startsWith("gh graphql read ");
  }

  /** Whether two base64url values are the same bytes (a malformed value equals nothing). */
  function sameBytes(a, b) {
    try {
      return equal(decode(a), decode(b));
    } catch (error) {
      return false;
    }
  }

  /** Verifies one signed head and returns the end of the chain {seq, hash, time_ms} (time_ms is
   *  the node time at which the head was signed). When nonce is null the head must be the final
   *  head a node left at its orderly shutdown (final true and an empty nonce), otherwise the head
   *  that answered that nonce (final false). */
  function openHead(signed, node, id, nonce) {
    const body = openSigned(signed, node.sign_pk, purpose("head") + "\n");
    const point = chainPoint(body);
    const fresh = nonce === null
      ? body.final === true && body.nonce === ""
      : body.final === false && sameBytes(body.nonce, nonce);
    if (body.type !== "head" || body.node !== id || body.user_id !== userId() || point === null || !fresh) {
      throw native.error("bad_signature", "head is not for this chain");
    }
    return point;
  }

  /** Opens the event (the plaintext) of one log entry body of format 1 with the log decryption
   *  private key. An entry whose key_id is not ours is not opened and gives null. */
  function openEvent(body, keys) {
    if (body.key_id !== keys.keyId) return null;
    const aad = [body.node, body.user_id, body.key_id, String(body.seq)].join("\n");
    const event = JSON.parse(text(decode(native.hpkeOpen({
      kem: "x25519", kdf: "sha256", aead: "chacha20poly1305", recipientPrivateKey: keys.logSk,
      enc: body.enc, info: info("log-entry"), aad: encode(utf8(aad)), ciphertext: body.ct,
    }))));
    if (event === null || typeof event !== "object") throw native.error("bad_signature", "event");
    return event;
  }

  /** Opens the events (the plaintext: a JSON array of count events) of one log entry body of
   *  format 2 with the log decryption private key. The caller checked that the key_id is ours. A
   *  plaintext that is not an array of count objects is bad_signature. */
  function openEventsV2(body, keys) {
    const aad = [body.node, body.user_id, body.key_id, String(body.seq)].join("\n");
    const events = JSON.parse(text(decode(native.hpkeOpen({
      kem: "x25519", kdf: "sha256", aead: "chacha20poly1305", recipientPrivateKey: keys.logSk,
      enc: body.enc, info: infoV2("log-entry"), aad: encode(utf8(aad)), ciphertext: body.ct,
    }))));
    const shaped = Array.isArray(events) && events.length === body.count &&
      events.every(function (event) { return event !== null && typeof event === "object"; });
    if (!shaped) throw native.error("bad_signature", "events");
    return events;
  }

  /** The tracing of a delegation transfer: when the events of a verified entry (null when the
   *  entry is not ours) hold the event grant_transferred_out, the receiving node (to) is added to
   *  the ledger. A node id is the signing public key of that node, so the entries and the head of
   *  that node verify with that value. The expiry of the added node is the expiry of the giving
   *  node (the latest the transferred grant can be alive). The app never handed a grant directly,
   *  so granted_ms is 0 (the next sync verifies the attestation of that node and sends a grant)
   *  and the sealing public key is empty. Without this tracing, missing log entries of
   *  credentials used on the node that took over the delegation would not show in the
   *  verification of the app. */
  function followTransfer(ledger, node, body, events) {
    if (events === null) return;
    const event = events.find(function (event) { return event.t === "grant_transferred_out"; });
    if (event === undefined) return;
    const to = event.to;
    if (typeof to !== "string" || !NODE_ID.test(to)) return;
    const known = ledger.nodes[to];
    if (known !== undefined) {
      // A node the log store listing put into the ledger before this trace reached it: the
      // transfer explains it, so it takes the shape of a traced node.
      if (known.origin === "store") {
        known.origin = "grant";
        known.unknown_ms = 0;
        known.platform = node.platform;
        known.release = node.release;
        known.first_ms = Math.min(known.first_ms, whole(body.time_ms));
        known.not_after_ms = Math.max(known.not_after_ms, node.not_after_ms);
        known.gone_ms = 0;
      }
      return;
    }
    ledger.nodes[to] = {
      sign_pk: to, seal_pk: "", platform: node.platform, release: node.release,
      first_ms: whole(body.time_ms), granted_ms: 0, not_after_ms: node.not_after_ms,
      checkpoint: { seq: 0, hash: ZERO_HASH, time_ms: 0 }, final: null, gone_ms: 0, origin: "grant",
      unknown_ms: 0,
    };
  }

  // ---- The log store ----

  // The tail of an object key of the log store under the node prefix (docs/protocol.md 7.6). Format
  // 2 (the releases from v2.0.0 on): the seq as digits, the time_ms of the entry as digits, the kind
  // letter (c: a control entry, u: a use entry), the count of events as three digits, the key_id, the
  // base64url of the body hash and of the entry hash. Format 1 (the releases before v2.0.0): the seq
  // as digits and the base64url of the entry hash.
  const STORE_KEY_V2 = new RegExp(
    "^(\\d{" + LOG_STORE_SEQ_DIGITS + "})-(\\d{" + LOG_STORE_TIME_DIGITS + "})-([cu])-(\\d{3})-" +
    "([0-9a-f]{16})-([A-Za-z0-9_-]{43})-([A-Za-z0-9_-]{43})$");
  const STORE_KEY_V1 = new RegExp("^(\\d{" + LOG_STORE_SEQ_DIGITS + "})-([A-Za-z0-9_-]{43})$");
  // The events a control entry holds (one per entry) and the events a use entry holds
  // (docs/protocol.md 7.1).
  const CONTROL_EVENTS = [
    "grant_accepted", "grant_revoked", "connection_created", "connection_removed",
    "grant_transferred_out", "grant_transferred_in",
  ];
  const USE_EVENTS = ["provider_request", "credential_refreshed", "mail_request", "secret_released", "totp_issued"];

  /** A failed read of the log store. kind is unreachable (a listing or an object could not be
   *  fetched or read), url_rejected (an address the backend handed out does not name the bucket of
   *  this server target or the key, prefix, markers and query of the request), truncated (a listing
   *  went on beyond LOG_STORE_PAGES pages, or more unknown node prefixes than LOG_STORE_NODES) or
   *  disabled (the backend of this env has no log store). */
  function storeFailure(kind) {
    return { log_store_failure: true, kind: kind };
  }

  function isStoreFailure(error) {
    return error !== null && typeof error === "object" && error.log_store_failure === true;
  }

  /** Records a store failure of this run in store (the state of the store reads of the run): the
   *  refusal of a backend without a log store is absent for a debug build and refused for a release
   *  build, any other failure is its kind. */
  function storeFailed(store, error) {
    if (error.kind === "disabled") {
      store.state = native.deviceInfo().debug_build === true ? "absent" : "refused";
    } else {
      store.state = error.kind;
    }
  }

  /** The log store of this server target (an element of LOG_STORES), undefined when the target has
   *  none. */
  function logStore() {
    return LOG_STORES[native.deviceInfo().server_target];
  }

  /** The host of the log store of this server target (the virtual-hosted S3 address), null when
   *  the target has none. */
  function logStoreHost() {
    const store = logStore();
    return store === undefined ? null : store.bucket + ".s3." + store.region + ".amazonaws.com";
  }

  /** Whether a debug build may call the S3 stand-in of the local stack: an address over http or
   *  https, at the host the backend hands out, in the path-style form of the bucket of
   *  LOG_STORES.local (storeAddressAccepted). The bridge of a debug build reports the server target
   *  prod whatever backend the app talks to, so the build configuration alone decides. A release
   *  build calls the host of the store of its server target and nothing else. */
  function storeUnpinned() {
    return native.deviceInfo().debug_build === true;
  }

  /** The object key prefix of this account in the log store. */
  function accountPrefix() {
    return "v1/accounts/" + userId() + "/";
  }

  /** The parts of an address: the host (lower case, with its port when one is given), the path
   *  (percent-decoded) and the query table. The scheme is https, or http as well when plain is
   *  true. null when the value is not such an address with a host or the path does not decode. */
  function splitUrl(url, plain) {
    if (typeof url !== "string") return null;
    const scheme = url.slice(0, 8) === "https://" ? "https://"
      : plain === true && url.slice(0, 7) === "http://" ? "http://" : null;
    if (scheme === null) return null;
    const rest = url.slice(scheme.length);
    let end = rest.length;
    for (const stop of ["/", "?", "#"]) {
      const at = rest.indexOf(stop);
      if (at >= 0 && at < end) end = at;
    }
    const host = rest.slice(0, end).toLowerCase();
    if (host === "") return null;
    const tail = rest.slice(end);
    const cut = tail.search(/[?#]/);
    let path = cut < 0 ? tail : tail.slice(0, cut);
    if (path === "") path = "/";
    try {
      path = decodeURIComponent(path);
    } catch (error) {
      return null;
    }
    return { host: host, path: path, query: parseQuery(tail) };
  }

  /** Whether the query of a presigned address carries only the keys allowed and the signature keys
   *  (X-Amz-...). Any other key rejects the address: a key that changes what S3 lists or returns is
   *  not one the backend may add. */
  function queryKeysAccepted(query, allowed) {
    return Object.keys(query).every(function (key) {
      return allowed.indexOf(key) >= 0 || key.slice(0, 6) === "X-Amz-";
    });
  }

  /** Whether the host and the path of a store address are the ones of this store for key (the empty
   *  key is a listing): the host of the log store of the server target and the path "/" + key (the
   *  virtual-hosted form), or, in a debug build only, any host with the path-style form
   *  "/{bucket}/" + key of the stand-in of the local stack (a listing may also be "/{bucket}"). An
   *  address of another host in the virtual-hosted form is refused in every build. */
  function storeAddressAccepted(parts, key) {
    const host = logStoreHost();
    if (host !== null && parts.host === host && parts.path === "/" + key) return true;
    if (!storeUnpinned()) return false;
    const bucket = LOG_STORES.local.bucket;
    return parts.path === "/" + bucket + "/" + key || (key === "" && parts.path === "/" + bucket);
  }

  /** Whether a listing address the backend handed out is called: the host and path of the store,
   *  only the query keys of LISTING_QUERY_KEYS and the signature, the query versions, the prefix
   *  expected, the delimiter "/" for the node discovery listing and absent otherwise, the markers the
   *  ones requested (absent when none was requested), a page size of 1000 when given and the
   *  encoding url when given. */
  function listingUrlAccepted(url, expected) {
    const parts = splitUrl(url, storeUnpinned());
    if (parts === null || !storeAddressAccepted(parts, "")) return false;
    const query = parts.query;
    if (!queryKeysAccepted(query, LISTING_QUERY_KEYS)) return false;
    if (!("versions" in query) || query.prefix !== expected.prefix) return false;
    if ("max-keys" in query && query["max-keys"] !== "1000") return false;
    if ("encoding-type" in query && query["encoding-type"] !== "url") return false;
    if (expected.nodes ? query.delimiter !== "/" : "delimiter" in query) return false;
    if (expected.keyMarker === null
        ? "key-marker" in query
        : query["key-marker"] !== expected.keyMarker) {
      return false;
    }
    if (expected.versionIdMarker === null
        ? "version-id-marker" in query
        : query["version-id-marker"] !== expected.versionIdMarker) {
      return false;
    }
    return true;
  }

  /** Whether an object address the backend handed out is called: the host and path of the store for
   *  that key, the query versionId of that version and no other query key besides the signature. */
  function objectUrlAccepted(url, key, versionId) {
    const parts = splitUrl(url, storeUnpinned());
    return parts !== null && storeAddressAccepted(parts, key) &&
      parts.query.versionId === versionId && queryKeysAccepted(parts.query, ["versionId"]);
  }

  /** One GET of the log store: {status, body}. A transport failure is unreachable. */
  async function fetchStore(url) {
    let response = null;
    try {
      response = await native.http({ method: "GET", url: url, timeoutMs: LOG_STORE_TIMEOUT_MS });
    } catch (error) {
      throw storeFailure("unreachable");
    }
    return { status: response.status, body: typeof response.body === "string" ? response.body : "" };
  }

  const XML_ENTITIES = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'" };

  function xmlText(value) {
    return value.replace(/&(amp|lt|gt|quot|apos);/g, function (match, name) { return XML_ENTITIES[name]; });
  }

  /** The text of the first element name of xml (the empty string for an empty element), null when
   *  the element is absent. */
  function xmlField(xml, name) {
    const match = new RegExp("<" + name + "(?:\\s[^>]*)?(?:/>|>([^<]*)</" + name + ">)").exec(xml);
    if (match === null) return null;
    return xmlText(match[1] === undefined ? "" : match[1]);
  }

  /** The inner texts of every element name of xml. */
  function xmlBlocks(xml, name) {
    const out = [];
    const pattern = new RegExp("<" + name + "(?:\\s[^>]*)?>([\\s\\S]*?)</" + name + ">", "g");
    let match = pattern.exec(xml);
    while (match !== null) {
      out.push(match[1]);
      match = pattern.exec(xml);
    }
    return out;
  }

  /** Reads a ListVersionsResult document of S3: whether the listing is truncated and the markers of
   *  the next page, the versions {key, versionId, isLatest} and the common prefixes. When the
   *  document declares the encoding url (the listing was requested with encoding-type url), the
   *  keys, the common prefixes and the next key marker are percent-decoded. Delete markers are not
   *  read (a delete marker hides no preserved version from a listing of versions). null when the
   *  document is not a ListVersionsResult or a name does not decode. */
  function parseListVersions(xml) {
    if (typeof xml !== "string" || !/<ListVersionsResult[\s>]/.test(xml)) return null;
    const top = xml.replace(/<(Version|DeleteMarker|CommonPrefixes)(?:\s[^>]*)?>[\s\S]*?<\/\1>/g, "");
    const encoded = xmlField(top, "EncodingType") === "url";
    function name(value) {
      if (value === null || !encoded) return value;
      try {
        return decodeURIComponent(value.replace(/\+/g, " "));
      } catch (error) {
        return undefined;
      }
    }
    const versions = [];
    for (const block of xmlBlocks(xml, "Version")) {
      const key = name(xmlField(block, "Key"));
      const versionId = xmlField(block, "VersionId");
      if (key === undefined) return null;
      if (key !== null && versionId !== null) {
        versions.push({ key: key, versionId: versionId, isLatest: xmlField(block, "IsLatest") === "true" });
      }
    }
    const prefixes = [];
    for (const block of xmlBlocks(xml, "CommonPrefixes")) {
      const prefix = name(xmlField(block, "Prefix"));
      if (prefix === undefined) return null;
      if (prefix !== null) prefixes.push(prefix);
    }
    const nextKeyMarker = name(xmlField(top, "NextKeyMarker"));
    if (nextKeyMarker === undefined) return null;
    const nextVersionIdMarker = xmlField(top, "NextVersionIdMarker");
    return {
      truncated: xmlField(top, "IsTruncated") === "true",
      nextKeyMarker: nextKeyMarker === null || nextKeyMarker === "" ? null : nextKeyMarker,
      nextVersionIdMarker:
        nextVersionIdMarker === null || nextVersionIdMarker === "" ? null : nextVersionIdMarker,
      versions: versions, prefixes: prefixes,
    };
  }

  /** The seq of an object key as LOG_STORE_SEQ_DIGITS digits with leading zeros (the order of the
   *  keys is the order of seq). */
  function seqDigits(seq) {
    let digits = String(seq);
    while (digits.length < LOG_STORE_SEQ_DIGITS) digits = "0" + digits;
    return digits;
  }

  /** The parts an object key under the node prefix names: {format: 2, seq, time_ms, kind, count,
   *  key_id, body_hash, entry_hash} for a key of format 2 (seq 1 or more, count 1 to
   *  LOG_ENTRY_EVENTS), {format: 1, seq, hash} for a key of format 1, null for any other key. */
  function parseStoreKey(key, prefix) {
    if (typeof key !== "string" || key.slice(0, prefix.length) !== prefix) return null;
    const tail = key.slice(prefix.length);
    const v2 = STORE_KEY_V2.exec(tail);
    if (v2 !== null) {
      const seq = Number(v2[1]);
      const timeMs = Number(v2[2]);
      const count = Number(v2[4]);
      if (!Number.isSafeInteger(seq) || seq < 1 || !Number.isSafeInteger(timeMs) ||
          count < 1 || count > LOG_ENTRY_EVENTS) {
        return null;
      }
      return {
        format: 2, seq: seq, time_ms: timeMs, kind: v2[3], count: count, key_id: v2[5],
        body_hash: v2[6], entry_hash: v2[7], fields: tail.slice(0, LOG_STORE_KEY_FIELDS_CHARS),
      };
    }
    const v1 = STORE_KEY_V1.exec(tail);
    if (v1 === null) return null;
    const seq = Number(v1[1]);
    return Number.isSafeInteger(seq) && seq > 0 ? { format: 1, seq: seq, hash: v1[2] } : null;
  }

  /** One page of a listing of the log store through an address the backend hands out: nodes true
   *  is the node discovery listing of the account prefix (delimiter "/"), otherwise the object
   *  versions of the node prefix after the markers. Throws a store failure. */
  async function listStorePage(nodes, node, keyMarker, versionIdMarker) {
    const query = {};
    if (nodes) query.nodes = "1";
    if (node !== null) query.node = node;
    if (keyMarker !== null) query.key_marker = keyMarker;
    if (versionIdMarker !== null) query.version_id_marker = versionIdMarker;
    let listing = null;
    try {
      listing = (await api("GET", "/api/secure/log/store", null, query)).json;
    } catch (error) {
      throw storeFailure(error && error.code === "log_store_disabled" ? "disabled" : "unreachable");
    }
    const expected = {
      prefix: accountPrefix() + (node === null ? "" : node + "/"), nodes: nodes,
      keyMarker: keyMarker, versionIdMarker: versionIdMarker,
    };
    if (!listingUrlAccepted(listing.list_url, expected)) throw storeFailure("url_rejected");
    const response = await fetchStore(listing.list_url);
    const parsed = response.status === 200 ? parseListVersions(response.body) : null;
    if (parsed === null) throw storeFailure("unreachable");
    return parsed;
  }

  /** The nodes of this account in the log store: the common prefixes of the account prefix (the
   *  node discovery listing). A prefix that does not name a node id is left out. */
  async function discoverStoreNodes() {
    const prefix = accountPrefix();
    const nodes = [];
    let keyMarker = null;
    let versionIdMarker = null;
    for (let page = 0; page < LOG_STORE_PAGES; page += 1) {
      const listing = await listStorePage(true, null, keyMarker, versionIdMarker);
      for (const common of listing.prefixes) {
        if (common.slice(0, prefix.length) !== prefix || common.slice(-1) !== "/") continue;
        const id = common.slice(prefix.length, -1);
        if (NODE_ID.test(id) && nodes.indexOf(id) < 0) nodes.push(id);
      }
      if (!listing.truncated || listing.nextKeyMarker === null) return nodes;
      keyMarker = listing.nextKeyMarker;
      versionIdMarker = listing.nextVersionIdMarker;
    }
    throw storeFailure("truncated");
  }

  /** The index of completeness of one chain after afterSeq: the object versions of the node prefix
   *  listed from the key marker of that seq, at most pages pages. entries maps a seq to its
   *  candidates {key, versionId, isLatest, parts} (the node wrote one key per seq; another key with
   *  the same seq is an object someone else put there, and only a key the chain equation or a
   *  verified object confirms counts), min is the smallest listed seq (0 when none), max the
   *  largest (afterSeq when none), truncated whether the listing went on beyond pages pages. */
  async function storeIndex(id, afterSeq, pages) {
    const prefix = accountPrefix() + id + "/";
    const index = { entries: new Map(), min: 0, max: afterSeq, truncated: false };
    let keyMarker = prefix + seqDigits(afterSeq) + "-~";
    let versionIdMarker = null;
    for (let page = 0; page < pages; page += 1) {
      const listing = await listStorePage(false, id, keyMarker, versionIdMarker);
      for (const version of listing.versions) {
        const parts = parseStoreKey(version.key, prefix);
        if (parts === null || parts.seq <= afterSeq) continue;
        if (!index.entries.has(parts.seq)) index.entries.set(parts.seq, []);
        index.entries.get(parts.seq).push({
          key: version.key, versionId: version.versionId, isLatest: version.isLatest, parts: parts,
        });
        if (index.min === 0 || parts.seq < index.min) index.min = parts.seq;
        if (parts.seq > index.max) index.max = parts.seq;
      }
      if (!listing.truncated || listing.nextKeyMarker === null) return index;
      keyMarker = listing.nextKeyMarker;
      versionIdMarker = listing.nextVersionIdMarker;
    }
    index.truncated = true;
    return index;
  }

  /** The smallest listed seq after seq (the far end of a gap), seq itself when none is listed. */
  function nextListedSeq(index, seq) {
    let next = Infinity;
    for (const listed of index.entries.keys()) {
      if (listed > seq && listed < next) next = listed;
    }
    return next === Infinity ? seq : next;
  }

  /** The addresses the backend hands out for the object versions of the candidates wanted (at most
   *  LOG_STORE_OBJECTS). Returns a table from key + "\n" + versionId to the address. An address
   *  that does not name its key and version, and a candidate without an address, reject the batch. */
  async function storeObjectUrls(wanted) {
    let signed = null;
    try {
      signed = (await api("POST", "/api/secure/log/store/objects", {
        objects: wanted.map(function (item) { return { key: item.key, version_id: item.versionId }; }),
      })).json;
    } catch (error) {
      throw storeFailure(error && error.code === "log_store_disabled" ? "disabled" : "unreachable");
    }
    const urls = new Map();
    for (const item of Array.isArray(signed.objects) ? signed.objects : []) {
      if (item === null || typeof item !== "object" ||
          !objectUrlAccepted(item.url, item.key, item.version_id)) {
        throw storeFailure("url_rejected");
      }
      urls.set(item.key + "\n" + item.version_id, item.url);
    }
    for (const item of wanted) {
      if (!urls.has(item.key + "\n" + item.versionId)) throw storeFailure("url_rejected");
    }
    return urls;
  }

  /** The signed value {body, sig} stored as one object version of the log store and the size of the
   *  response: {signed, bytes}. signed is null when the store has no such version (404). Any other
   *  response outside 200 (a refused or expired address, a failing store) is unreachable: the run
   *  stays pending and the next one reads the version again. */
  async function fetchStoreObject(url) {
    const response = await fetchStore(url);
    if (response.status === 404) return { signed: null, bytes: response.body.length };
    if (response.status !== 200) throw storeFailure("unreachable");
    let value = null;
    try {
      value = JSON.parse(response.body);
    } catch (error) {
      value = null;
    }
    if (value === null || typeof value !== "object" ||
        typeof value.body !== "string" || typeof value.sig !== "string") {
      return { signed: null, bytes: response.body.length };
    }
    return { signed: { body: value.body, sig: value.sig }, bytes: response.body.length };
  }

  /** The objects of several addresses (a table from name to address), fetched limit at a time: a
   *  table from name to the result of fetchStoreObject. */
  async function fetchStoreObjects(urls, limit) {
    const names = Array.from(urls.keys());
    const fetched = new Map();
    let at = 0;
    async function worker() {
      while (at < names.length) {
        const name = names[at];
        at += 1;
        fetched.set(name, await fetchStoreObject(urls.get(name)));
      }
    }
    const workers = [];
    for (let count = 0; count < Math.min(limit, names.length); count += 1) {
      workers.push(worker());
    }
    await Promise.all(workers);
    return fetched;
  }

  /** A reader of object versions of the store that requests addresses in batches: object(candidate,
   *  ahead) returns the signed value of that version (null when the store has no such version) and
   *  requests, along with its address, the addresses of the candidates of ahead (the objects the
   *  caller will read next), LOG_STORE_OBJECTS addresses per request. fetched and bytes count the
   *  objects read and their size. */
  function storeReader() {
    const urls = new Map();
    const reader = {
      fetched: 0,
      bytes: 0,
      object: async function (candidate, ahead) {
        const name = candidate.key + "\n" + candidate.versionId;
        if (!urls.has(name)) {
          const wanted = [candidate];
          for (const other of ahead) {
            if (wanted.length >= LOG_STORE_OBJECTS) break;
            if (other !== candidate && !urls.has(other.key + "\n" + other.versionId)) wanted.push(other);
          }
          const signed = await storeObjectUrls(wanted);
          signed.forEach(function (url, key) { urls.set(key, url); });
        }
        const response = await fetchStoreObject(urls.get(name));
        reader.fetched += 1;
        reader.bytes += response.bytes;
        return response.signed;
      },
    };
    return reader;
  }

  /** The purpose strings of format 2 of the log. */
  function purposeV2(name) {
    return "pickle.secure.v2." + name;
  }

  function infoV2(name) {
    return encode(utf8(purposeV2(name)));
  }

  /** The chain hash of format 2 (docs/protocol.md 7.1): SHA-256 of the chain prefix, the entry hash
   *  before, the body hash of the key parts and the first five parts of that key (parts.fields). A
   *  key whose entry hash satisfies the equation carries the seq, time, kind, count and key_id the
   *  node wrote. prevHash is a base64url string; a malformed hash gives null. */
  function chainHash(prevHash, parts) {
    try {
      const prev = decode(prevHash);
      const body = decode(parts.body_hash);
      if (prev.length !== 32 || body.length !== 32) return null;
      return native.sha256(encode(concat(utf8(purposeV2("log-chain") + "\n"), prev, body, utf8(parts.fields))));
    } catch (error) {
      return null;
    }
  }

  /** The hash of the body of a signed value (base64url). */
  function bodyHashOf(signed) {
    return native.sha256(encode(decode(signed.body)));
  }

  /** Whether a gap below the vouched end is young: every key of the first seq listed after it is a
   *  key of format 2 younger than LOG_GAP_GRACE_MS before headTime (the node time of the head, or
   *  now). The node writes an entry the store did not confirm again within its sweep, so such a gap
   *  is pending; a gap that stays is missing. */
  function gapIsYoung(index, farSeq, headTime) {
    const after = index.entries.get(farSeq);
    if (after === undefined || after.length === 0) return false;
    return after.every(function (candidate) {
      return candidate.parts.format === 2 && headTime - candidate.parts.time_ms < LOG_GAP_GRACE_MS;
    });
  }

  /** Checks one signed object version against the parts of its key, the node signature, the
   *  account, seq and, when cursor is given, prev as the hash of the entry before. For format 2 the
   *  body carries the key_id, count, kind and time_ms of the key, SHA-256(body) is the body hash of
   *  the key, the entry hash of the key is the chain hash of prev, the body hash and the five parts
   *  of the key, and the plaintext
   *  (opened when the key_id is ours) holds count events: one control event for a control entry, use
   *  events for a use entry. For format 1 the entry hash of the key is the chain hash of the body.
   *  Returns {entry, failure}: entry is {format, seq, body, hash, time_ms, ours, events} (events null
   *  when the key_id is not ours) or null, and failure names what failed (signature, hash, open) or
   *  is empty. */
  function checkEntry(signed, node, id, parts, cursor, keys) {
    const failed = function (failure) { return { entry: null, failure: failure }; };
    let body = null;
    try {
      body = parts.format === 2
        ? openSigned(signed, node.sign_pk, purposeV2("log-entry") + "\n", 2)
        : openSigned(signed, node.sign_pk, purpose("log-entry") + "\n", 1);
    } catch (error) {
      return failed("signature");
    }
    if (body.node !== id || body.user_id !== userId() || body.seq !== parts.seq ||
        (cursor !== null && !sameBytes(body.prev, cursor.hash))) {
      return failed("hash");
    }
    let hash = null;
    try {
      if (parts.format === 2) {
        if (body.key_id !== parts.key_id || body.count !== parts.count || body.kind !== parts.kind ||
            body.time_ms !== parts.time_ms || !sameBytes(bodyHashOf(signed), parts.body_hash)) {
          return failed("hash");
        }
        hash = chainHash(body.prev, parts);
        if (hash === null || !sameBytes(hash, parts.entry_hash)) return failed("hash");
      } else {
        hash = native.sha256(encode(concat(utf8(purpose("log-chain") + "\n"), decode(signed.body))));
        if (!sameBytes(hash, parts.hash)) return failed("hash");
      }
    } catch (error) {
      return failed("hash");
    }
    const ours = body.key_id === keys.keyId;
    let events = null;
    if (ours) {
      try {
        events = parts.format === 2 ? openEventsV2(body, keys) : [openEvent(body, keys)];
      } catch (error) {
        return failed("open");
      }
      if (parts.format === 2) {
        const allowed = parts.kind === "c" ? CONTROL_EVENTS : USE_EVENTS;
        if (parts.kind === "c" && events.length !== 1) return failed("open");
        const kinds = events.every(function (event) {
          return event !== null && typeof event === "object" && allowed.indexOf(event.t) >= 0;
        });
        if (!kinds) return failed("open");
      }
    }
    return {
      entry: {
        format: parts.format, seq: parts.seq, body: body, hash: hash, time_ms: whole(body.time_ms),
        ours: ours, events: events,
      },
      failure: "",
    };
  }

  /** Whether the entries of a node are in the log store: every node but one of a build that writes
   *  no entry to the store (a prerelease build without log_store). */
  function writesToStore(node) {
    if (node.origin === "store" || node.platform === "local") return true;
    const builds = ACCEPTED_RELEASES.concat(PRERELEASE_BUILDS);
    const build = builds.find(function (item) { return item.release === node.release; });
    return build === undefined || build.log_store === true;
  }

  /** The content verification of one seq (docs/protocol.md 7.4): the candidate objects (the latest
   *  version first) are read until one verifies against cursor (null: no prev check). Every object
   *  read spends one body of the budget, and nothing is read once the budget is spent. ahead names
   *  the candidates whose addresses are requested along. Returns the verified entry or null. */
  async function contentStep(node, id, cursor, candidates, keys, budgets, reader, ahead) {
    const ordered = candidates.slice().sort(function (a, b) {
      return (b.isLatest ? 1 : 0) - (a.isLatest ? 1 : 0);
    });
    for (const candidate of ordered) {
      if (budgets.bodies <= 0) return null;
      budgets.bodies -= 1;
      const signed = await reader.object(candidate, ahead);
      if (signed === null) continue;
      const checked = checkEntry(signed, node, id, candidate.parts, cursor, keys);
      if (checked.entry !== null) return checked.entry;
    }
    return null;
  }

  /** The candidates of the seqs after seq whose objects the walk will read by content as well, in
   *  the order of seq: every candidate when nothing vouches for the chain, otherwise the format 1
   *  candidates of the seqs that follow without a break (a format 2 chain with a head is walked by
   *  its keys, so only the seq at hand is read). */
  function contentAhead(index, seq, vouched) {
    const ahead = [];
    for (let next = seq + 1; next <= index.max; next += 1) {
      if (vouched !== null && next > vouched) break;
      const candidates = index.entries.get(next);
      if (candidates === undefined) {
        if (vouched !== null) break;
        continue;
      }
      const taken = vouched === null
        ? candidates
        : candidates.filter(function (candidate) { return candidate.parts.format === 1; });
      if (taken.length === 0) break;
      for (const candidate of taken) ahead.push(candidate);
      if (ahead.length >= LOG_STORE_OBJECTS) break;
    }
    return ahead;
  }

  /** Verifies one (node, account) chain from the verification point of the ledger (docs/protocol.md
   *  7.4). The head is the head received for a fresh nonce when the node is alive, and the stored
   *  final head when the node is gone. A node whose head equals the verification point is verified
   *  without a listing. summary is the element of the log node query for that node (undefined when
   *  absent), budgets the keys and bodies this run may still spend, store the state of the store
   *  reads of this run (a failure changes it). Returns {state, checked, missing, expired, ours}
   *  whose state is verified, pending (a budget ran out, the store could not be read, or the store
   *  has pages or entries still to confirm) or attention (a gap, a mismatch, or a part that cannot
   *  be checked). */
  async function verifyChain(ledger, id, summary, budgets, keys, store) {
    const node = ledger.nodes[id];
    const stored = summary === undefined ? { live: false, final_head: null } : summary;
    const outcome = { state: "verified", checked: 0, missing: 0, expired: 0, ours: false };
    if (node.final !== null && node.checkpoint.seq >= node.final.seq) return outcome;
    if (!writesToStore(node)) {
      // A node of a build that wrote no entry to the store has no chain here. A gone one leaves
      // the ledger; a living one is not walked.
      if (node.gone_ms !== 0) delete ledger.nodes[id];
      return outcome;
    }

    let head = node.final;
    let live = head === null && stored.live === true;
    if (live) {
      const nonce = native.randomBytes(32);
      let response = null;
      try {
        response = await api("POST", "/api/secure/nodes/" + id + "/status", { nonce: nonce });
      } catch (error) {
        if (error.code !== "node_not_found") throw error;
        live = false;
      }
      if (response !== null) {
        try {
          head = openHead(response.json.head, node, id, nonce);
        } catch (error) {
          outcome.state = "attention";
          return outcome;
        }
      }
    }
    if (head === null && stored.final_head !== null && stored.final_head !== undefined) {
      try {
        head = openHead(stored.final_head, node, id, null);
      } catch (error) {
        outcome.state = "attention";
        return outcome;
      }
      node.final = { seq: head.seq, hash: head.hash };
    }
    if (head !== null && head.seq === node.checkpoint.seq && sameBytes(head.hash, node.checkpoint.hash)) {
      // Nothing was written since the verification point: the listing is not read this run.
      return outcome;
    }
    if (store.state !== "verified") {
      // The store could not be read earlier in this run, or this env has no store to read: the
      // chain waits for a run that reads it.
      outcome.state = "pending";
      return outcome;
    }
    return walkStore(ledger, node, id, head, budgets, keys, store, outcome);
  }

  /** The verification of one chain with the listing of the log store as the index of completeness
   *  (docs/protocol.md 7.4). Every seq after the verification point up to the vouched end (the seq of
   *  the head) must have a key that the chain equation links to the hash before it: a use entry of
   *  format 2 with exactly one such key advances the walk without a read, every other seq (a control
   *  entry, a seq with two linked keys, a chain nobody vouches for, format 1) is read by content and
   *  the first object that verifies is the entry. A seq without a linked key below the vouched end
   *  is a gap (missing). Beyond the vouched end the walk stops (the next run reads from a newer
   *  head). A listing that starts beyond the seq after the verification point is read from its first
   *  verifying entry: the entries before it are expired when the verification point, or the entry
   *  itself, is older than the retention of the store, otherwise missing. For a node found in the
   *  store only, a prefix that is not a chain is left out. */
  async function walkStore(ledger, node, id, head, budgets, keys, store, outcome) {
    let cursor = node.checkpoint;
    if (head !== null &&
        (head.seq < cursor.seq || (head.seq === cursor.seq && !sameBytes(head.hash, cursor.hash)))) {
      outcome.state = "attention";
      return outcome;
    }
    let index = null;
    try {
      index = await storeIndex(id, cursor.seq, LOG_STORE_PAGES);
    } catch (error) {
      if (!isStoreFailure(error)) throw error;
      storeFailed(store, error);
      outcome.state = "pending";
      return outcome;
    }
    rememberKeys(id, index.entries);
    if (node.final !== null && index.max > node.final.seq) {
      // The store holds entries after the final head of the node.
      outcome.state = "attention";
      return outcome;
    }
    const vouched = head !== null ? head.seq : null;
    const discovered = node.origin === "store";
    const headTime = head !== null && head.time_ms !== 0 ? head.time_ms : native.nowMs();
    const retention = LOG_EXPIRES_DAYS * DAY_MS;
    const reader = storeReader();
    try {
      if (index.min !== 0 && index.min > cursor.seq + 1) {
        // The listing begins beyond the seq after the verification point: the entries between are
        // expired or missing. The landing is the first listed entry that verifies by content.
        const seqs = Array.from(index.entries.keys()).sort(function (a, b) { return a - b; });
        let landed = null;
        for (const seq of seqs) {
          if (vouched !== null && seq > vouched) break;
          if (budgets.bodies <= 0) break;
          landed = await contentStep(
            node, id, null, index.entries.get(seq), keys, budgets, reader, contentAhead(index, seq, vouched));
          if (landed !== null) break;
        }
        const beyond = landed !== null &&
          ((cursor.time_ms !== 0 && headTime - cursor.time_ms > retention) ||
           headTime - landed.time_ms > retention);
        if (landed === null && budgets.bodies <= 0) {
          outcome.state = "pending";
        } else if (!beyond) {
          if (!discovered) {
            outcome.missing += (landed === null ? nextListedSeq(index, cursor.seq) : landed.seq) - cursor.seq - 1;
            // A young gap is an entry the node has still to write again (pending); an old one is
            // an omission.
            const young = landed !== null && headTime - landed.time_ms < LOG_GAP_GRACE_MS;
            outcome.state = young ? "pending" : "attention";
          }
        } else {
          outcome.expired += landed.seq - cursor.seq - 1;
          followTransfer(ledger, node, landed.body, landed.events);
          if (landed.ours) outcome.ours = true;
          cursor = { seq: landed.seq, hash: landed.hash, time_ms: landed.time_ms };
          outcome.checked += 1;
        }
      }
      while (outcome.state === "verified" && cursor.seq < index.max) {
        const next = cursor.seq + 1;
        if (vouched !== null && next > vouched) break;
        const candidates = index.entries.get(next);
        if (candidates === undefined) {
          if (discovered) break;
          const far = nextListedSeq(index, next);
          outcome.missing += far - next;
          outcome.state = gapIsYoung(index, far, headTime) ? "pending" : "attention";
          break;
        }
        const linked = candidates.filter(function (candidate) {
          return candidate.parts.format === 2 &&
            sameBytes(candidate.parts.entry_hash, chainHash(cursor.hash, candidate.parts));
        });
        const legacy = candidates.filter(function (candidate) { return candidate.parts.format === 1; });
        let step = null;
        if (linked.length === 1 && linked[0].parts.kind === "u" && vouched !== null) {
          if (budgets.keys <= 0) {
            outcome.state = "pending";
            break;
          }
          budgets.keys -= 1;
          const parts = linked[0].parts;
          step = { seq: next, hash: parts.entry_hash, time_ms: parts.time_ms, ours: parts.key_id === keys.keyId };
        } else if (linked.length > 0 || legacy.length > 0) {
          if (budgets.bodies <= 0) {
            outcome.state = "pending";
            break;
          }
          step = await contentStep(
            node, id, cursor, linked.length > 0 ? linked : legacy, keys, budgets, reader,
            contentAhead(index, next, vouched));
          if (step === null) {
            if (budgets.bodies <= 0) {
              outcome.state = "pending";
            } else if (vouched !== null) {
              // Below the vouched end a seq whose objects do not verify is an entry that was
              // changed or an object someone else put there in the place of one.
              outcome.state = "attention";
            }
            // Beyond anything the node vouches for, an object that does not verify is someone
            // else's and ends the walk without a mark.
            break;
          }
          followTransfer(ledger, node, step.body, step.events);
        } else {
          // Keys of format 2 only, none of which the chain equation links: the entry of the chain
          // is not among them (an object someone else put at this seq while the entry of the node
          // waits to be written, or an omission).
          if (discovered) break;
          outcome.missing += 1;
          outcome.state = gapIsYoung(index, next, headTime) ? "pending" : "attention";
          break;
        }
        if (vouched !== null && next === vouched && !sameBytes(step.hash, head.hash)) {
          outcome.state = "attention";
          break;
        }
        if (step.ours) outcome.ours = true;
        cursor = { seq: next, hash: step.hash, time_ms: step.time_ms };
        outcome.checked += 1;
      }
    } catch (error) {
      if (!isStoreFailure(error)) throw error;
      storeFailed(store, error);
      outcome.state = "pending";
    }
    budgets.fetched += reader.fetched;
    if (outcome.state === "verified" &&
        (index.truncated || (vouched !== null && vouched > index.max))) {
      outcome.state = "pending";
    }
    node.checkpoint = cursor;
    anchorDisplay(id, cursor);
    return outcome;
  }

  let formats = null;

  /** Strings in the locale and time zone of the device: date is the date (medium), time the time
   *  (short), seconds the time with seconds (medium). */
  function formatTime(ms, style) {
    if (formats === null) {
      formats = {
        date: new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }),
        time: new Intl.DateTimeFormat(undefined, { timeStyle: "short" }),
        seconds: new Intl.DateTimeFormat(undefined, { timeStyle: "medium" }),
      };
    }
    return formats[style].format(new Date(whole(ms)));
  }

  /** The host of an origin string (https://host). */
  function originHost(origin) {
    const value = String(origin);
    const start = value.indexOf("://");
    const rest = start < 0 ? value : value.slice(start + 3);
    const end = rest.indexOf("/");
    return end < 0 ? rest : rest.slice(0, end);
  }

  /** The action of one provider request: read (GET or a read memo), send_mail (a mail sending
   *  path), send_message (a Slack message, a Teams chat or channel message POST), payment (a Link
   *  payment request), delete (DELETE), and change for everything else. */
  function requestAction(method, host, path, context) {
    if (path.endsWith("/send") || path.endsWith("/sendMail")) return "send_mail";
    if (path === "/api/chat.postMessage") return "send_message";
    if (method === "POST" && path.endsWith("/messages") &&
        (path.indexOf("/chats/") >= 0 || path.indexOf("/channels/") >= 0)) {
      return "send_message";
    }
    if (host === "api.link.com" && method === "POST" && path.startsWith("/spend_requests")) return "payment";
    if (method === "GET" || readMemo(context)) return "read";
    if (method === "DELETE") return "delete";
    return "change";
  }

  /** The display kind of an event (the plaintext of an entry). kind is the kind the definition
   *  chooses its wording by (request, grant_renewed, grant_revoked, connected, disconnected,
   *  signed_in, used, moved, filled, code, other), action is the action of a request (read,
   *  send_mail, send_message, payment, delete, change, verify), service is the service id of the
   *  icon and the name, detail is a value outside the wording (the expiry date, the recipients or
   *  the mailbox of a mail, the host of a filled site), field is the kind of the filled vault value,
   *  and method and target describe one request. */
  function describeEvent(event) {
    const kind = event.t;
    const provider = typeof event.provider === "string" ? event.provider : "";
    const shown = {
      kind: "other", action: "", provider: provider, service: provider, detail: "", field: "",
      method: "", target: "",
    };
    if (kind === "grant_accepted") {
      shown.kind = "grant_renewed";
      shown.detail = formatTime(event.not_after_ms, "date");
    } else if (kind === "grant_revoked") {
      shown.kind = "grant_revoked";
    } else if (kind === "connection_created") {
      shown.kind = "connected";
    } else if (kind === "connection_removed") {
      shown.kind = "disconnected";
    } else if (kind === "credential_refreshed") {
      shown.kind = "signed_in";
    } else if (kind === "credential_sealed") {
      shown.kind = event.renewal === true ? "signed_in" : "connected";
    } else if (kind === "credential_opened") {
      shown.kind = "used";
    } else if (kind === "grant_transferred_out" || kind === "grant_transferred_in") {
      shown.kind = "moved";
    } else if (kind === "provider_request") {
      const method = String(event.method);
      const host = String(event.host);
      const path = String(event.path);
      shown.kind = "request";
      shown.service = serviceOf(provider, host, path);
      shown.action = requestAction(method, host, path, event.context);
      shown.method = method;
      shown.target = host + path;
    } else if (kind === "mail_request") {
      const request = event.request || {};
      shown.kind = "request";
      shown.action = event.operation === "submit" ? "send_mail" : event.operation === "verify" ? "verify" : "read";
      shown.target = event.operation === "submit" && Array.isArray(request.recipients)
        ? request.recipients.join(", ") : String(request.mailbox || "");
    } else if (kind === "secret_released") {
      shown.kind = "filled";
      shown.field = String(event.field);
      shown.detail = originHost(event.origin);
    } else if (kind === "totp_issued") {
      shown.kind = "code";
      shown.detail = originHost(event.origin);
    }
    return shown;
  }

  /** One opened item of the log screen for an event: the display kind and its fields (describeEvent)
   *  and the context the caller declared. */
  function eventItem(itemId, timeMs, event) {
    const described = describeEvent(event);
    return {
      id: itemId, time_ms: timeMs, kind: described.kind, action: described.action,
      provider: described.provider, service: described.service,
      context: typeof event.context === "string" ? event.context : "", detail: described.detail,
      field: described.field, method: described.method, target: described.target, verified: true,
    };
  }

  /** The items of one entry of the log screen. An entry that did not verify is one item of kind
   *  unverified (not opened), an entry of another key_id (the delegation of another key) one item of
   *  kind other_key (its signature verified, not opened), an entry of format 1 one item of its event,
   *  and an entry of format 2 one item per event (id node:seq:index, time_ms the time of the event).
   *  keyTime is the time_ms of the key of the entry (0 for a key of format 1). */
  function openEntryItems(id, seq, verified, keyTime) {
    const base = id + ":" + seq;
    if (verified === null) {
      return [{
        id: base, time_ms: keyTime, kind: "unverified", action: "", provider: "", service: "",
        context: "", detail: "", field: "", method: "", target: "", verified: false,
      }];
    }
    if (verified.events === null) {
      return [{
        id: base, time_ms: verified.time_ms, kind: "other_key", action: "", provider: "", service: "",
        context: "", detail: "", field: "", method: "", target: "", verified: true,
      }];
    }
    if (verified.format === 1) return [eventItem(base, verified.time_ms, verified.events[0])];
    return verified.events.map(function (event, index) {
      const time = whole(event.time_ms);
      return eventItem(base + ":" + index, time === 0 ? verified.time_ms : time, event);
    });
  }

  /** One request row inside a group (every item of a request group is a verified one: openEntry
   *  gives kind request to verified entries only). */
  function requestRow(item) {
    return {
      id: item.id, method: item.method, target: item.target, target_short: item.target, time_ms: item.time_ms,
      time_text: formatTime(item.time_ms, "seconds"),
    };
  }

  /** The short form of the requests of a group that share the host of the first request but have
   *  another path: `…/` followed by the last two segments of the path. A request with the same
   *  target as the first, and a request with another host, stay as they are. */
  function shortenTargets(requests) {
    if (requests.length < 2) return;
    const first = requests[0].target;
    const slash = first.indexOf("/");
    const host = slash < 0 ? first : first.slice(0, slash);
    for (let at = 1; at < requests.length; at += 1) {
      const target = requests[at].target;
      if (target === first || !target.startsWith(host + "/")) continue;
      const segments = target.slice(host.length + 1).split("/").filter(function (part) { return part !== ""; });
      if (segments.length < 2) continue;
      requests[at].target_short = "\u2026/" + segments.slice(-2).join("/");
    }
  }

  /** The day key of yesterday: the date 23 hours before now when it differs from today, otherwise
   *  (just before midnight) the date 25 hours before now. The date 24 hours before now skips a day
   *  or stays on today on the 23-hour and 25-hour days of a daylight saving transition. */
  function yesterdayKey(now, today) {
    const near = formatTime(now - 23 * 3600000, "date");
    return near === today ? formatTime(now - 25 * 3600000, "date") : near;
  }

  /** Turns the list of opened items (time_ms descending) into the list of display groups.
   *  Consecutive request items (kind request) of the same day, provider, service, action and
   *  context form one group (count is the number of request items, requests the list of requests in
   *  ascending time, time_ms the time of the latest request), and every other item is a group of its
   *  own. A node merges identical GET requests of the same address within a five-minute window into
   *  one event, so count is the number of events, not of HTTP requests. day_key is the date
   *  string of the device locale (groups of the same day share the key), day_offset is 0 for today,
   *  1 for yesterday and 2 for earlier days. The service icon (icon_image, icon_glyph) exists for
   *  request groups only; the other kinds have empty values (the definition draws the icon of the
   *  kind). */
  function displayGroups(items) {
    const now = native.nowMs();
    const today = formatTime(now, "date");
    const yesterday = yesterdayKey(now, today);
    const groups = [];
    for (const item of items) {
      const last = groups.length === 0 ? null : groups[groups.length - 1];
      const dayKey = formatTime(item.time_ms, "date");
      if (last !== null && item.kind === "request" && last.kind === "request" && last.day_key === dayKey &&
          last.provider === item.provider && last.service === item.service &&
          last.action === item.action && last.context === item.context) {
        last.count += 1;
        last.requests.unshift(requestRow(item));
        continue;
      }
      const service = SERVICES.get(item.service);
      groups.push({
        id: item.id, time_ms: item.time_ms, time_text: formatTime(item.time_ms, "time"),
        day_key: dayKey, day_offset: dayKey === today ? 0 : dayKey === yesterday ? 1 : 2,
        kind: item.kind, action: item.action, provider: item.provider,
        provider_name: item.provider === "" ? "" : providerName(item.provider),
        service: item.service, service_name: item.service === "" ? "" : serviceName(item.service),
        icon_image: item.kind !== "request" || service === undefined || service.image === ""
          ? "" : "ui_image/" + service.image,
        icon_glyph: item.kind === "request" && service !== undefined && service.glyph,
        context: item.context, context_kind: contextKind(item.context),
        detail: item.detail, field: item.field,
        count: 1, verified: item.verified,
        requests: item.kind === "request" ? [requestRow(item)] : [],
      });
    }
    for (const group of groups) shortenTargets(group.requests);
    return groups;
  }

  /** Splits the list of display groups into the list of day groups {key, offset, groups}
   *  (consecutive groups with the same day_key are one day). */
  function displayDays(groups) {
    const days = [];
    for (const group of groups) {
      const last = days.length === 0 ? null : days[days.length - 1];
      if (last !== null && last.key === group.day_key) {
        last.groups.push(group);
        continue;
      }
      days.push({ key: group.day_key, offset: group.day_offset, groups: [group] });
    }
    return days;
  }

  /** Adds one opened item to the counts of the pages read (readLogPage). A request counts by
   *  its action as reads (read, verify), changes (delete, change) or sends (everything else), and
   *  filled and code count as sends. The other kinds are not counted. providers is, per provider
   *  used, the list of the short names of the services used. */
  function countInto(summary, item) {
    if (item.kind === "request") {
      if (item.action === "read" || item.action === "verify") summary.reads += 1;
      else if (item.action === "delete" || item.action === "change") summary.changes += 1;
      else summary.sends += 1;
    } else if (item.kind === "filled" || item.kind === "code") {
      summary.sends += 1;
      return;
    } else {
      return;
    }
    let used = null;
    for (const entry of summary.providers) {
      if (entry.provider === item.provider) used = entry;
    }
    if (used === null) {
      used = { provider: item.provider, name: providerName(item.provider), services: [] };
      summary.providers.push(used);
    }
    const service = SERVICES.get(item.service);
    if (service !== undefined && service.short !== "" && used.services.indexOf(service.short) < 0) {
      used.services.push(service.short);
    }
  }

  /** The provider line of the summary: per provider, its name followed by the short names of the
   *  services used joined with " · " (the name alone when there is no service), and " / " between
   *  providers. */
  function providersText(summary) {
    return summary.providers.map(function (entry) {
      return entry.services.length === 0 ? entry.name : entry.name + " \u00b7 " + entry.services.join(", ");
    }).join(" / ");
  }

  // ---- The log screen ----

  // What the screen read in this runtime (a new runtime starts empty). displayNodes maps a node id
  // to {candidates: Map<seq, candidate[]>, floor, exhausted, sorted, anchor, linked}: the keys the
  // screen knows, the smallest seq whose listing was read (0 while none was), whether the listing
  // reached the start of the chain (or everything below is expired), the seqs in descending order
  // (null when the candidates changed), the verification point of the ledger the keys of the chain
  // are found from (anchorDisplay) and the keys of the chain found from it (linkedKeys, null until
  // computed). displayEntries maps "node:seq" to the entry the screen opened {id, seq, time_ms,
  // items}, at most LOG_DISPLAY_ENTRIES of them (the oldest read leaves first).
  const displayNodes = new Map();
  const displayEntries = new Map();

  function displayNode(id) {
    let node = displayNodes.get(id);
    if (node === undefined) {
      node = { candidates: new Map(), floor: 0, exhausted: false, sorted: null, anchor: null, linked: null };
      displayNodes.set(id, node);
    }
    return node;
  }

  /** Puts the candidates of a listing (a table from seq to candidates) into the keys the screen
   *  knows of node id. The candidates of a seq already known are replaced. */
  function rememberKeys(id, entries) {
    const node = displayNode(id);
    entries.forEach(function (candidates, seq) {
      node.candidates.set(seq, candidates);
      if (node.floor === 0 || seq < node.floor) node.floor = seq;
    });
    node.sorted = null;
    node.linked = null;
  }

  /** Makes the verification point of the ledger (checkpoint {seq, hash}) the anchor of the keys the
   *  screen knows of node id: the keys of the chain are found from it (linkedKeys). */
  function anchorDisplay(id, checkpoint) {
    const node = displayNode(id);
    const same = node.anchor !== null && node.anchor.seq === checkpoint.seq &&
      sameBytes(node.anchor.hash, checkpoint.hash);
    if (same) return;
    node.anchor = { seq: checkpoint.seq, hash: checkpoint.hash };
    node.linked = null;
  }

  /** The keys of the chain among the keys the screen knows of a node: a table from seq to the one
   *  candidate of that seq the chain names. At the anchor (the verification point of the ledger) it
   *  is the key whose entry hash is the hash of the point; below it, seq by seq, it is the key whose
   *  entry hash the chain equation of the key above links to (that hash alone is the prev of the
   *  key above, and the five parts of a key are an input of its hash, so no other key links). The
   *  walk ends at a seq the screen knows no key of, at a seq no key of format 2 links at, and at
   *  the start of the chain. A key the table does not name is not a key the app verified: the
   *  operator domain can add objects under any key, and the screen counts and orders by the keys of
   *  the chain alone. */
  function linkedKeys(node) {
    if (node.linked !== null) return node.linked;
    const linked = new Map();
    if (node.anchor !== null && node.anchor.seq > 0) {
      let above = null;
      for (let seq = node.anchor.seq; seq >= 1; seq -= 1) {
        const candidates = node.candidates.get(seq);
        if (candidates === undefined) break;
        const found = candidates.find(function (candidate) {
          if (candidate.parts.format !== 2) return false;
          return above === null
            ? sameBytes(candidate.parts.entry_hash, node.anchor.hash)
            : sameBytes(chainHash(candidate.parts.entry_hash, above.parts), above.parts.entry_hash);
        });
        if (found === undefined) break;
        linked.set(seq, found);
        above = found;
      }
    }
    node.linked = linked;
    return linked;
  }

  /** The seqs the screen knows of node id, the largest first. */
  function sortedSeqs(node) {
    if (node.sorted === null) {
      node.sorted = Array.from(node.candidates.keys()).sort(function (a, b) { return b - a; });
    }
    return node.sorted;
  }

  /** The candidates of seq among the keys the screen knows: the key of the chain (linkedKeys) first
   *  when it is known, then the others with the latest version first, so a read tries them in that
   *  order. */
  function orderedCandidates(node, seq) {
    const candidates = (node.candidates.get(seq) || []).slice().sort(function (a, b) {
      return (b.isLatest ? 1 : 0) - (a.isLatest ? 1 : 0);
    });
    const named = linkedKeys(node).get(seq);
    if (named === undefined) return candidates;
    return [named].concat(candidates.filter(function (candidate) { return candidate !== named; }));
  }

  /** The time of the key of seq of node id: the time_ms of a key of format 2, null for a key of
   *  format 1 (the entry carries the time). */
  function keyTimeOf(node, seq) {
    const candidates = orderedCandidates(node, seq);
    return candidates.length > 0 && candidates[0].parts.format === 2 ? candidates[0].parts.time_ms : null;
  }

  /** Reads the keys of node id below the seqs the screen knows: a listing from the key marker of
   *  seq from = max(0, beforeSeq - LOG_DISPLAY_LIST - 1), continued while its pages end before
   *  beforeSeq, at most LOG_STORE_PAGES pages. The keys with from < seq < beforeSeq enter the keys
   *  the screen knows and the floor becomes from + 1. The chain is exhausted when the listing began
   *  at seq 0 or added no key (everything below is expired). Throws a store failure. */
  async function loadKeysBefore(id, beforeSeq) {
    const node = displayNode(id);
    const prefix = accountPrefix() + id + "/";
    const from = Math.max(0, beforeSeq - LOG_DISPLAY_LIST - 1);
    let keyMarker = prefix + seqDigits(from) + "-~";
    let versionIdMarker = null;
    let added = 0;
    for (let page = 0; page < LOG_STORE_PAGES; page += 1) {
      const listing = await listStorePage(false, id, keyMarker, versionIdMarker);
      let last = from;
      for (const version of listing.versions) {
        const parts = parseStoreKey(version.key, prefix);
        if (parts === null) continue;
        if (parts.seq > last) last = parts.seq;
        if (parts.seq <= from || parts.seq >= beforeSeq) continue;
        if (!node.candidates.has(parts.seq)) {
          node.candidates.set(parts.seq, []);
          added += 1;
        }
        node.candidates.get(parts.seq).push({
          key: version.key, versionId: version.versionId, isLatest: version.isLatest, parts: parts,
        });
      }
      if (!listing.truncated || listing.nextKeyMarker === null || last >= beforeSeq - 1) break;
      keyMarker = listing.nextKeyMarker;
      versionIdMarker = listing.nextVersionIdMarker;
    }
    node.sorted = null;
    node.linked = null;
    node.floor = from + 1;
    if (from === 0 || added === 0) node.exhausted = true;
  }

  /** The hash the entry of seq must name as prev when the screen knows it: the zero hash for the
   *  first entry, the entry hash of the key of the chain at seq - 1 (linkedKeys); null when the key
   *  of the chain before it is not known (the chain is then the matter of the index verification). */
  function linkedBefore(node, seq) {
    if (seq === 1) return { hash: ZERO_HASH };
    const before = linkedKeys(node).get(seq - 1);
    return before === undefined ? null : { hash: before.parts.entry_hash };
  }

  /** The entry of seq of node id as the screen shows it: {id, seq, time_ms, items}. The candidate
   *  objects are read in the order of orderedCandidates until one verifies: the screen checks the
   *  signature of the node, the key, the body hash of an entry and, when the key before it is known
   *  and alone, its prev (linkedBefore). The entries the screen opened are kept for the runtime. */
  async function displayEntry(ledger, id, seq, keys, reader) {
    const name = id + ":" + seq;
    const kept = displayEntries.get(name);
    if (kept !== undefined) return kept;
    const node = displayNode(id);
    const signer = ledger.nodes[id] !== undefined ? ledger.nodes[id] : { sign_pk: id };
    const before = linkedBefore(node, seq);
    const candidates = orderedCandidates(node, seq);
    const ahead = [];
    for (const lower of sortedSeqs(node)) {
      if (lower >= seq) continue;
      if (ahead.length >= LOG_DISPLAY_AHEAD) break;
      for (const candidate of orderedCandidates(node, lower)) ahead.push(candidate);
    }
    let verified = null;
    let keyTime = 0;
    for (const candidate of candidates) {
      if (candidate.parts.format === 2 && keyTime === 0) keyTime = candidate.parts.time_ms;
      const signed = await reader.object(candidate, ahead);
      if (signed === null) continue;
      const checked = checkEntry(signed, signer, id, candidate.parts, before, keys);
      if (checked.entry !== null) {
        verified = checked.entry;
        break;
      }
    }
    const entry = {
      id: id, seq: seq, time_ms: verified !== null ? verified.time_ms : keyTime,
      items: openEntryItems(id, seq, verified, keyTime),
    };
    if (displayEntries.size >= LOG_DISPLAY_ENTRIES) {
      displayEntries.delete(displayEntries.keys().next().value);
    }
    displayEntries.set(name, entry);
    return entry;
  }

  /** The time of the entry of seq of node id: the time_ms of its key (format 2), otherwise the
   *  time_ms of the entry read from the store (format 1). */
  async function entryTime(ledger, id, seq, keys, reader) {
    const keyTime = keyTimeOf(displayNode(id), seq);
    if (keyTime !== null) return keyTime;
    return (await displayEntry(ledger, id, seq, keys, reader)).time_ms;
  }

  /** The largest seq of node id below startSeq whose entry is before beforeMs, 0 when there is
   *  none. The keys are read further down the chain while the seqs known are not enough. */
  async function pointerBelow(ledger, id, beforeMs, startSeq, keys, reader) {
    const node = displayNode(id);
    for (;;) {
      for (const seq of sortedSeqs(node)) {
        if (seq >= startSeq) continue;
        if ((await entryTime(ledger, id, seq, keys, reader)) < beforeMs) return seq;
      }
      if (node.exhausted) return 0;
      await loadKeysBefore(id, node.floor === 0 ? startSeq : node.floor);
    }
  }

  /** The entries of the screen before beforeMs (every node of ids, the latest first) until their
   *  events reach limit; the entries of the same millisecond as the last one stay on the same
   *  page. Returns {entries, items, last_ms, has_more}: the entries read, their items with the
   *  latest first (the events of one entry in the reverse of their index), the time of the last
   *  entry and whether an entry before it exists. */
  async function collectEntries(ledger, ids, keys, beforeMs, limit) {
    const reader = storeReader();
    const pointers = new Map();
    for (const id of ids) {
      pointers.set(id, await pointerBelow(ledger, id, beforeMs, Infinity, keys, reader));
    }
    const entries = [];
    const items = [];
    let count = 0;
    let lastMs = 0;
    for (;;) {
      let bestId = null;
      let bestSeq = 0;
      let bestTime = -1;
      for (const id of ids) {
        const seq = pointers.get(id);
        if (seq === 0) continue;
        const time = await entryTime(ledger, id, seq, keys, reader);
        if (time > bestTime || (time === bestTime && id < bestId)) {
          bestId = id;
          bestSeq = seq;
          bestTime = time;
        }
      }
      if (bestId === null) break;
      if (count >= limit && bestTime !== lastMs) break;
      const entry = await displayEntry(ledger, bestId, bestSeq, keys, reader);
      entries.push(entry);
      for (let at = entry.items.length - 1; at >= 0; at -= 1) items.push(entry.items[at]);
      count += entry.items.length;
      lastMs = bestTime;
      pointers.set(bestId, await pointerBelow(ledger, bestId, beforeMs, bestSeq, keys, reader));
    }
    let hasMore = false;
    pointers.forEach(function (seq) { if (seq !== 0) hasMore = true; });
    return { entries: entries, items: items, last_ms: lastMs, has_more: hasMore };
  }

  /** Anchors the keys the screen knows of every node of ids that the ledger knows at the
   *  verification point of the ledger (anchorDisplay). */
  function anchorScreen(ledger, ids) {
    for (const id of ids) {
      if (ledger.nodes[id] !== undefined) anchorDisplay(id, ledger.nodes[id].checkpoint);
    }
  }

  /** The nodes the screen shows: the nodes of the ledger with a verified entry or found in the store,
   *  and the nodes the screen knows keys of. */
  function screenNodes(ledger) {
    const ids = [];
    for (const id of Object.keys(ledger.nodes)) {
      const node = ledger.nodes[id];
      if (node.checkpoint.seq > 0 || node.origin === "store") ids.push(id);
    }
    displayNodes.forEach(function (node, id) {
      if (ids.indexOf(id) < 0 && node.candidates.size > 0) ids.push(id);
    });
    return ids;
  }

  /** The date strings (device locale) of today and the count - 1 days before it, today first. The
   *  days are found by stepping back one hour at a time (a step of a day skips or repeats a day on
   *  the days of a daylight saving transition). */
  function dayLabels(now, count) {
    const labels = [formatTime(now, "date")];
    let at = now;
    while (labels.length < count) {
      at -= 3600000;
      const label = formatTime(at, "date");
      if (label !== labels[labels.length - 1]) labels.push(label);
    }
    return labels;
  }

  /** Reads, for every node of ids, the keys of the last LOG_OVERVIEW_DAYS days (and a day before, for
   *  the boundary of the first day) when the screen does not know them yet: down the chain from the
   *  verification point until a key older than that or the start of the chain, at most two listings
   *  per node and call. */
  async function loadOverviewKeys(ledger, ids, now) {
    const since = now - (LOG_OVERVIEW_DAYS + 1) * DAY_MS;
    for (const id of ids) {
      const node = displayNode(id);
      for (let round = 0; round < 2; round += 1) {
        if (node.exhausted) break;
        const seqs = sortedSeqs(node);
        if (seqs.length > 0) {
          const oldest = keyTimeOf(node, seqs[seqs.length - 1]);
          if (oldest === null || oldest < since) break;
        }
        const start = node.floor !== 0 ? node.floor
          : ledger.nodes[id] !== undefined ? ledger.nodes[id].checkpoint.seq + 1 : 1;
        if (start <= 1) {
          node.exhausted = true;
          break;
        }
        await loadKeysBefore(id, start);
      }
    }
  }

  /** The overview of the last LOG_OVERVIEW_DAYS days from the keys of the chain the screen knows
   *  (linkedKeys): per day (today first) the number of events and entries, per node the number of
   *  events and whether it is alive, the number of nodes alive (nodes_live), whether any node has
   *  keys of format 1 (format1), whether the keys of some node do not cover the window (partial: the
   *  listing stopped before the start of the chain or a key older than the window, or the keys of
   *  the chain end before that) and the totals. A key of format 1 carries no time and is not
   *  counted; its node is marked format1. A key the chain does not name is not counted. */
  function overviewOf(ledger, ids, now) {
    const labels = dayLabels(now, LOG_OVERVIEW_DAYS);
    const days = labels.map(function (label) { return { key: label, label: label, events: 0, entries: 0 }; });
    const byLabel = new Map();
    for (const day of days) byLabel.set(day.key, day);
    const since = now - (LOG_OVERVIEW_DAYS + 1) * DAY_MS;
    const nodes = [];
    let nodesLive = 0;
    let anyFormat1 = false;
    let partial = false;
    let totalEvents = 0;
    let totalEntries = 0;
    for (const id of ids) {
      const node = displayNode(id);
      const linked = linkedKeys(node);
      let events = 0;
      let format1 = false;
      let oldest = null;
      for (const seq of sortedSeqs(node)) {
        const named = linked.get(seq);
        if (named === undefined) {
          const others = node.candidates.get(seq) || [];
          if (others.some(function (candidate) { return candidate.parts.format === 1; })) format1 = true;
          continue;
        }
        const parts = named.parts;
        oldest = parts.time_ms;
        if (parts.time_ms < since) break;
        const day = byLabel.get(formatTime(parts.time_ms, "date"));
        if (day === undefined) continue;
        day.events += parts.count;
        day.entries += 1;
        events += parts.count;
        totalEvents += parts.count;
        totalEntries += 1;
      }
      // The window is covered when the keys reach the start of the chain (or everything below is
      // expired) or a key of the chain older than the window was reached.
      if (!node.exhausted && (oldest === null || oldest >= since)) partial = true;
      const known = ledger.nodes[id];
      const live = known !== undefined && known.gone_ms === 0;
      nodes.push({ node: id, events: events, live: live, format1: format1 });
      if (live) nodesLive += 1;
      if (format1) anyFormat1 = true;
    }
    return {
      days: days, nodes: nodes, nodes_live: nodesLive, format1: anyFormat1, partial: partial,
      total_events: totalEvents, total_entries: totalEntries,
    };
  }

  // ---- Procedures ----

  // The result of the last log verification (runtime lifetime). sync decides the time of the next
  // verification from it. store is the state of the log store reads of that run: verified,
  // unreachable, url_rejected, truncated, refused (a release build whose backend has no log store),
  // absent (a debug build whose backend has no log store) or pending (no run yet).
  let logState = {
    status: "pending", verified_ms: 0, unverified_nodes: 0, missing: 0, expired: 0,
    unknown_nodes: 0, store: "pending", store_failing_ms: 0,
  };

  function failureCode(error) {
    return error && error.code ? String(error.code) : "program_error";
  }

  // The mismatch marker of the runtime lifetime: the last account query answered a user_id other
  // than the bound userId (so that the account end of that runtime does not erase the master key of
  // another account).
  let accountMismatch = false;

  /** The key_id registered on the account (null when there is none). When the user_id of the
   *  response differs from the bound userId (the account the server authenticated and the bound
   *  account of this device differ), the key is not read, key_state account_mismatch is published
   *  and the call ends with account_mismatch (a response without user_id is a server from before
   *  this change and counts as no mismatch). */
  async function registeredKeyId() {
    const body = (await api("GET", "/api/secure/account")).json;
    if (typeof body.user_id === "string" && body.user_id !== "" && body.user_id !== userId()) {
      accountMismatch = true;
      native.publish({
        state: { key_state: "account_mismatch", key_id: null },
        runtime: { ready: true, account_mismatch: true },
      });
      throw native.error("account_mismatch", "server account differs from bound account");
    }
    accountMismatch = false;
    const key = body.key;
    if (key === null) return null;
    if (key === undefined || typeof key !== "object" || typeof key.key_id !== "string" || key.key_id === "") {
      throw native.error("invalid_response", "account key");
    }
    return key.key_id;
  }

  /** Registers the account signing public key and the log public key on the account. proof is the
   *  signature of the account signing key over the account id. When replace is false, an account
   *  with another registered key fails with key_exists. */
  async function registerKey(keys, replace) {
    const proof = native.ed25519Sign(keys.signSeed, encode(utf8(purpose("register") + "\n" + userId())));
    await api("PUT", "/api/secure/account/key", {
      sign_pk: keys.signPk, log_pk: keys.logPk, proof: proof, replace: replace,
    });
  }

  function publishKey(keyState, keys) {
    const keyId = keys === null ? null : keys.keyId;
    native.publish({ state: { key_state: keyState, key_id: keyId } });
    return { keyState: keyState, keyId: keyId, keys: keys };
  }

  /** The judgement of the key state: the master key of the keychain is compared with the key_id
   *  registered on the account, and key_state and key_id are published. When there is a master key
   *  and the account has no registered key, its public key is registered. When the account query
   *  fails nothing is published and the failure is thrown. */
  async function judgeKey() {
    const masterKey = readMasterKey();
    const registered = await registeredKeyId();
    if (masterKey === null) return publishKey(registered === null ? "absent" : "waiting", null);
    const keys = deriveKeys(masterKey);
    let keyState = registered === null || registered === keys.keyId ? "present" : "mismatch";
    if (registered === null) {
      try {
        await registerKey(keys, false);
      } catch (error) {
        // Another device registered another key between the query and the registration.
        if (error.code !== "key_exists") throw error;
        keyState = "mismatch";
      }
    }
    return publishKey(keyState, keys);
  }

  /** The derived keys when key_state is present. Otherwise key_required. */
  async function presentKeys() {
    const judged = await judgeKey();
    if (judged.keyState !== "present") throw native.error("key_required", judged.keyState);
    return judged.keys;
  }

  /** Renews the grant of every living node. A node that is in the ledger and whose last grant is
   *  within the renewal interval (grantRenewMs) is skipped (not when force is true); every other
   *  node has its attestation verified, receives a grant with the lifetime the ledger sets, and is
   *  written to the ledger. A node of the ledger that is not in the response list gets its gone
   *  time. Returns the Set of accepted node ids, the number of nodes whose attestation failed to
   *  verify, and the number of nodes whose attestation verified but did not take the grant. */
  async function renewGrants(keys, ledger, force) {
    const nonce = native.randomBytes(32);
    const offered = (await api("GET", "/api/secure/nodes", null, { nonce: nonce })).json.nodes;
    const listed = new Set();
    const accepted = new Set();
    let rejected = 0;
    let failed = 0;
    for (const response of Array.isArray(offered) ? offered : []) {
      const claimed = response !== null && typeof response === "object" ? response.node : undefined;
      listed.add(claimed);
      const known = typeof claimed === "string" ? ledger.nodes[claimed] : undefined;
      if (force !== true && known !== undefined && known.granted_ms > ledger.revoked_ms &&
          native.nowMs() - known.granted_ms < grantRenewMs(ledger)) {
        accepted.add(claimed);
        continue;
      }
      let node = null;
      try {
        node = verifyAttestation(response, nonce);
      } catch (error) {
        rejected += 1;
        native.log("attestation rejected: " + String(error.message));
        continue;
      }
      listed.add(node.node);
      accepted.add(node.node);
      try {
        const grant = await sendGrant(node, response.challenge, keys, grantTtlMs(ledger));
        // The grant time written to the ledger is after the last revocation time (a device clock
        // that runs backwards does not make a grant after a revoke read as one before it).
        const granted = Math.max(grant.granted_ms, ledger.revoked_ms + 1);
        const existing = ledger.nodes[node.node];
        if (existing !== undefined && existing.seal_pk === "") {
          // A node that entered the ledger through the tracing of a delegation transfer: the values
          // of the attestation verified this time are filled in.
          existing.seal_pk = node.sealPk;
          existing.platform = node.platform;
          existing.release = node.release;
        }
        if (existing === undefined) {
          // The chain of a node seen for the first time is verified from its first entry (another
          // device may have delegated to it first).
          ledger.nodes[node.node] = {
            sign_pk: node.signPk, seal_pk: node.sealPk, platform: node.platform, release: node.release,
            first_ms: granted, granted_ms: granted, not_after_ms: grant.not_after_ms,
            checkpoint: { seq: 0, hash: ZERO_HASH, time_ms: 0 }, final: null, gone_ms: 0, origin: "grant",
            unknown_ms: 0,
          };
        } else {
          existing.granted_ms = granted;
          existing.not_after_ms = grant.not_after_ms;
          existing.origin = "grant";
          existing.unknown_ms = 0;
        }
      } catch (error) {
        // A node that did not take the grant is not written to the ledger (the published state
        // grant becomes partial or none).
        failed += 1;
        native.log("grant failed: " + failureCode(error));
      }
    }
    const now = native.nowMs();
    for (const id of Object.keys(ledger.nodes)) {
      if (!listed.has(id) && ledger.nodes[id].gone_ms === 0) ledger.nodes[id].gone_ms = now;
    }
    return { accepted: accepted, rejected: rejected, failed: failed };
  }

  /** The published state log of one run and its bookkeeping in the ledger: store_failing_ms starts
   *  at the first run whose store reads failed and clears at a run that completed (not pending) with
   *  the store read. The state is attention when any node has a gap, a mismatch, or a part that
   *  cannot be checked, when an entry of a node no grant of this app explains verified, when a
   *  release build is refused the log store, and when the reads of the store have been failing for
   *  LOG_STORE_STALE_MS; otherwise pending when a chain has entries left to verify or the store could
   *  not be read in this run; otherwise verified. */
  function publishLogState(ledger, store, counts, now) {
    const unread = store.state !== "verified" && store.state !== "absent" && store.state !== "refused";
    if (unread) {
      if (ledger.store_failing_ms === 0) ledger.store_failing_ms = now;
    } else if (store.state === "verified" && !counts.pending) {
      ledger.store_failing_ms = 0;
    }
    const stale = unread && now - ledger.store_failing_ms >= LOG_STORE_STALE_MS;
    saveLedger(ledger);
    const attention = counts.unverified > 0 || counts.unknown > 0 || store.state === "refused" || stale;
    const status = attention ? "attention" : counts.pending || unread ? "pending" : "verified";
    logState = {
      status: status,
      verified_ms: status === "pending" ? logState.verified_ms : now,
      unverified_nodes: counts.unverified, missing: counts.missing, expired: counts.expired,
      unknown_nodes: counts.unknown, store: store.state, store_failing_ms: ledger.store_failing_ms,
    };
    native.publish({ state: { log: logState } });
    return logState;
  }

  /** Reports the result of one verification run to the backend (the one way the server learns what
   *  the device verified). A failure is logged and changes nothing. */
  async function reportVerification(result, counts, nodes, elapsedMs) {
    try {
      await api("POST", LOG_REPORT_PATH, {
        status: result.status, store: result.store, nodes: nodes, keys_checked: counts.keys,
        bodies_fetched: counts.bodies, missing: counts.missing, expired: counts.expired,
        unknown_nodes: counts.unknown, elapsed_ms: elapsedMs, program_version: VERSION,
      });
    } catch (error) {
      native.log("verification report: " + failureCode(error));
    }
  }

  /** The log verification (docs/protocol.md 7.4): lists the nodes of the account in the log store,
   *  checks the chain of every node of the ledger and then of at most LOG_STORE_NODES nodes of the
   *  listing the ledger does not know (a node found in the store only is kept in the ledger, with
   *  origin store and unknown_ms, only when an entry sealed to the key of this account verified on
   *  it: a delegation the app did not make, counted as unknown in every run until a traced transfer
   *  explains the node), publishes the state log (publishLogState) and reports the run. One run
   *  spends at most LOG_VERIFY_KEYS keys and LOG_VERIFY_BODIES bodies over every node. A run whose
   *  node discovery listing cannot be read verifies nothing (the verification points stay). */
  async function verifyAll(ledger, keys) {
    const started = native.nowMs();
    const listed = (await api("GET", "/api/secure/log/nodes")).json.nodes;
    const summaries = Object.create(null);
    for (const summary of Array.isArray(listed) ? listed : []) {
      if (summary !== null && typeof summary === "object" && typeof summary.node === "string") {
        summaries[summary.node] = summary;
      }
    }
    const store = { state: "verified" };
    const now = native.nowMs();
    const counts = { pending: false, unverified: 0, missing: 0, expired: 0, unknown: 0, keys: 0, bodies: 0 };
    let discovered = [];
    try {
      discovered = await discoverStoreNodes();
    } catch (error) {
      if (!isStoreFailure(error)) throw error;
      storeFailed(store, error);
      if (store.state !== "absent" && store.state !== "refused") {
        counts.pending = true;
        const result = publishLogState(ledger, store, counts, now);
        await reportVerification(result, counts, Object.keys(ledger.nodes).length, native.nowMs() - started);
        return result;
      }
    }
    // The nodes of the listing the ledger does not know: examined after the nodes of the ledger (the
    // key order of the nodes object is the order of the queue), at most LOG_STORE_NODES in one run.
    const unknownIds = discovered.filter(function (id) { return ledger.nodes[id] === undefined; });
    const examined = unknownIds.slice(0, LOG_STORE_NODES);
    for (const id of examined) {
      ledger.nodes[id] = {
        sign_pk: id, seal_pk: "", platform: "", release: "", first_ms: now, granted_ms: 0,
        not_after_ms: 0, checkpoint: { seq: 0, hash: ZERO_HASH, time_ms: 0 }, final: null, gone_ms: now,
        origin: "store", unknown_ms: 0,
      };
    }
    const budgets = { keys: LOG_VERIFY_KEYS, bodies: LOG_VERIFY_BODIES, fetched: 0 };
    // The nodes whose verified entries include one sealed to the key of this account.
    const ours = new Set();
    // The verification of a chain can add nodes to the ledger (the tracing of a delegation
    // transfer). The added nodes are verified in this run too.
    const queue = Object.keys(ledger.nodes);
    const queued = new Set(queue);
    while (queue.length > 0) {
      const id = queue.shift();
      if (ledger.nodes[id] === undefined) continue;
      const outcome = await verifyChain(ledger, id, summaries[id], budgets, keys, store);
      counts.missing += outcome.missing;
      counts.expired += outcome.expired;
      if (outcome.ours) ours.add(id);
      if (outcome.state === "pending") counts.pending = true;
      if (outcome.state === "attention") counts.unverified += 1;
      for (const added of Object.keys(ledger.nodes)) {
        if (!queued.has(added)) {
          queued.add(added);
          queue.push(added);
        }
      }
    }
    counts.keys = LOG_VERIFY_KEYS - budgets.keys;
    counts.bodies = budgets.fetched;
    if (unknownIds.length > examined.length && store.state === "verified") store.state = "truncated";
    // A node found in the store only that holds an entry sealed to this key is a delegation the app
    // did not make and no verified transfer explained (a trace that reaches the node later in the
    // run changes its origin before this mark). The mark stays in the ledger; a node of the listing
    // without such an entry is not kept (the next run examines it again).
    for (const id of ours) {
      const node = ledger.nodes[id];
      if (node !== undefined && node.origin === "store" && node.unknown_ms === 0) node.unknown_ms = now;
    }
    for (const id of Object.keys(ledger.nodes)) {
      const node = ledger.nodes[id];
      if (node.origin !== "store") continue;
      if (node.unknown_ms !== 0) {
        counts.unknown += 1;
      } else {
        delete ledger.nodes[id];
      }
    }
    const result = publishLogState(ledger, store, counts, now);
    await reportVerification(result, counts, Object.keys(ledger.nodes).length, native.nowMs() - started);
    return result;
  }

  /** The migration of what was stored before the switch: the tokens of connections and the vault
   *  values that were stored under the KMS envelope of the operator before the switch are handed out
   *  by the backend sealed to the log public key of this account. They are opened with the log
   *  decryption private key, made into records under the user key of the custody of a node that
   *  holds a grant, and uploaded. From then on only a node opens them. The plaintext of the record
   *  is the opened bytes as they are (re-serializing the JSON would change integers above 2^53, the
   *  notation of numbers and escape sequences): only that it is a JSON object is checked. Nothing is
   *  done when no node holds a grant (no node could open those records). A failure is only logged
   *  and does not change the result of sync. Returns the number of stored items. */
  async function sealPending(keys, ledger) {
    let sealed = 0;
    try {
      const custody = heldCustody(ledger, native.nowMs());
      if (custody === null) return 0;
      const user = userId();
      for (let round = 0; round < SEALING_ROUNDS; round += 1) {
        const pending = (await api("GET", "/api/secure/sealing")).json;
        const items = Array.isArray(pending.items) ? pending.items : [];
        const records = [];
        for (const item of items) {
          if (item === null || typeof item !== "object" || typeof item.id !== "string" ||
              typeof item.provider !== "string" || SEALING_KINDS.indexOf(item.kind) < 0) continue;
          try {
            const aad = [user, item.id, item.kind, item.provider].join("\n");
            const opened = native.hpkeOpen({
              kem: "x25519", kdf: "sha256", aead: "chacha20poly1305", recipientPrivateKey: keys.logSk,
              enc: item.enc, info: info("pending"), aad: encode(utf8(aad)), ciphertext: item.ct,
            });
            const parsed = JSON.parse(text(decode(opened)));
            if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) continue;
            records.push({ id: item.id, record: sealRecordBytes(keys, custody, item.kind, item.provider, opened) });
          } catch (error) {
            native.log("pending item skipped: " + failureCode(error));
          }
        }
        if (records.length === 0) break;
        const stored = (await api("PUT", "/api/secure/sealing", { items: records })).json;
        sealed += Array.isArray(stored.sealed) ? stored.sealed.length : 0;
        if (pending.more !== true) break;
      }
    } catch (error) {
      native.log("sealing pending records failed: " + failureCode(error));
    }
    return sealed;
  }

  /** From the delegation step of sync to its end: when delegation is on the grants of the living
   *  nodes are renewed, the ledger is saved, grant is published, the log is verified when its
   *  period has elapsed, and runtime.ready is published. */
  async function delegate(keys, ledger) {
    let renewed = { accepted: new Set(), rejected: 0 };
    if (!delegationOff(ledger)) {
      renewed = await renewGrants(keys, ledger);
    } else {
      // While delegation is off the revoke is sent again to every living node: it reaches the nodes
      // that were not reached when it was turned off, and the nodes that took over a delegation
      // from them. A failure does not stop sync.
      try {
        await revokeEverywhere(keys, ledger);
      } catch (error) {
        native.log("revoke retry failed: " + failureCode(error));
      }
    }
    saveLedger(ledger);
    const grant = grantState(ledger, renewed.accepted, native.nowMs());
    native.publish({
      state: { grant: grant, grant_days: ledger.ttl_days },
      runtime: { rejected_nodes: renewed.rejected },
    });
    if (!delegationOff(ledger)) {
      await sealPending(keys, ledger);
      await finishAppPasswordSetup(keys, ledger);
    }
    if (native.nowMs() - logState.verified_ms >= LOG_VERIFY_INTERVAL_MS) await verifyAll(ledger, keys);
    native.publish({ runtime: { ready: true } });
    return { grant: grant, accepted: renewed.accepted.size, rejected: renewed.rejected };
  }

  /** The body of sync. A failure publishes its code to state.error, a success clears it. */
  async function runSync() {
    try {
      const judged = await judgeKey();
      let outcome = { grant: { state: "none", not_after_ms: 0 }, accepted: 0, rejected: 0 };
      if (judged.keyState === "present") outcome = await delegate(judged.keys, loadLedger());
      else native.publish({ runtime: { ready: true } });
      native.publish({ state: { error: null } });
      // Catching up on the master key transfer: a device with the key reads the pending requests, a
      // device with a transfer in progress advances one step, and the polling loop is started again.
      // A failure does not change the result of sync.
      try {
        if (judged.keyState === "present") await checkTransferRequests();
        else await transferStep();
        if (transferRun !== null && !transferTerminal(transferRun.phase)) transferLoop();
      } catch (error) {
        native.log("transfer sync: " + failureCode(error));
      }
      return {
        keyState: judged.keyState, keyId: judged.keyId, grant: outcome.grant,
        accepted: outcome.accepted, rejected: outcome.rejected,
      };
    } catch (error) {
      native.publish({ state: { error: failureCode(error) } });
      throw error;
    }
  }

  async function sync() {
    const outcome = await runSync();
    return { key_state: outcome.keyState, grant: outcome.grant };
  }

  /** The front of a connection: checks that delegation is on and that at least one living node
   *  holds the grant of this account. The list of living nodes is fetched again and a node without
   *  a grant (a node that restarted) receives one. When delegation is off it is delegation_off; when
   *  no living node holds a grant it is grant_required (attestation_failed when every living node
   *  failed the attestation verification). Returns the renewed ledger. */
  async function liveGrantLedger(keys) {
    const ledger = loadLedger();
    if (delegationOff(ledger)) throw native.error("delegation_off", "delegation is turned off");
    const renewed = await renewGrants(keys, ledger);
    saveLedger(ledger);
    const grant = grantState(ledger, renewed.accepted, native.nowMs());
    native.publish({ state: { grant: grant }, runtime: { rejected_nodes: renewed.rejected } });
    if (grant.state === "none") {
      const allRejected = renewed.rejected > 0 && renewed.accepted.size === 0;
      throw native.error(allRejected ? "attestation_failed" : "grant_required", "no live node holds a grant");
    }
    return ledger;
  }

  /** Key creation: a new key is made only when the keychain has no master key and the account has
   *  no registered key. The account registration comes first and the keychain is written only after
   *  it succeeded: when two devices create a key at the same time, the one that loses the
   *  registration does not write to the keychain. */
  async function createKey() {
    const judged = await judgeKey();
    if (judged.keyState !== "absent") return { key_state: judged.keyState, key_id: judged.keyId };
    const masterKey = native.randomBytes(32);
    const keys = deriveKeys(masterKey);
    try {
      await registerKey(keys, false);
    } catch (error) {
      if (error.code !== "key_exists") throw error;
      const outcome = await runSync();
      return { key_state: outcome.keyState, key_id: outcome.keyId };
    }
    writeMasterKey(masterKey);
    publishKey("present", keys);
    await delegate(keys, loadLedger());
    return { key_state: "present", key_id: keys.keyId };
  }

  /** Key replacement: while waiting for the key of another device, or while another key is
   *  registered, the key of the account is replaced with a new one. The nodes of the old ledger
   *  belong to the records of the old key, so a new node ledger is made. */
  async function resetKey() {
    const judged = await judgeKey();
    if (judged.keyState !== "waiting" && judged.keyState !== "mismatch") {
      throw native.error("invalid_state", judged.keyState);
    }
    const masterKey = native.randomBytes(32);
    const keys = deriveKeys(masterKey);
    await registerKey(keys, true);
    writeMasterKey(masterKey);
    const ledger = emptyLedger();
    saveLedger(ledger);
    logState = {
      status: "pending", verified_ms: 0, unverified_nodes: 0, missing: 0, expired: 0,
      unknown_nodes: 0, store: "pending", store_failing_ms: 0,
    };
    publishKey("present", keys);
    await delegate(keys, ledger);
    return { key_state: "present", key_id: keys.keyId };
  }

  /** Reads the query string of a URL as a table from name to value. */
  function parseQuery(url) {
    const out = Object.create(null);
    const start = url.indexOf("?");
    if (start < 0) return out;
    const end = url.indexOf("#", start);
    const query = url.slice(start + 1, end < 0 ? url.length : end);
    function component(value) {
      try {
        return decodeURIComponent(value.replace(/\+/g, " "));
      } catch (error) {
        return value;
      }
    }
    for (const pair of query.split("&")) {
      if (pair === "") continue;
      const at = pair.indexOf("=");
      out[component(at < 0 ? pair : pair.slice(0, at))] = at < 0 ? "" : component(pair.slice(at + 1));
    }
    return out;
  }

  /** A connection: opens the authorization address a node made in the web authentication session
   *  and, after the callback, checks the completion statement of the node. The authorization address
   *  is opened only after a statement of a node of the ledger over its account, the whole account
   *  signing public key (sign_pk, 32 bytes) and the hash of that address verified. A comparison of
   *  the key_id (8 bytes) alone is not a binding: a node takes a new grant of the same account from
   *  anyone, so the grant of another key whose first 8 bytes agree passes that comparison. */
  async function connect(args) {
    const target = typeof args.target === "string" ? args.target.trim() : "";
    if (target === "") throw native.error("invalid_input", "target");
    const keys = await presentKeys();
    const ledger = await liveGrantLedger(keys);

    const request = { target: target };
    for (const name of ["login_hint", "request_id"]) {
      if (typeof args[name] === "string") request[name] = args[name];
    }
    for (const name of ["reward_notice", "new_account"]) {
      if (typeof args[name] === "boolean") request[name] = args[name];
    }
    const begin = (await api("POST", "/api/secure/connections/begin", request)).json;
    const user = userId();
    const node = typeof begin.node === "string" ? ledger.nodes[begin.node] : undefined;
    let authorized = false;
    try {
      const statement = openSigned(begin.statement, node.sign_pk, purpose("statement") + "\n");
      authorized = statement.type === "oauth_begin" && statement.node === begin.node &&
        statement.user_id === user && sameBytes(statement.sign_pk, keys.signPk) &&
        typeof begin.state === "string" && statement.state === begin.state &&
        typeof begin.authorization_url === "string" &&
        sameBytes(statement.url_sha256, native.sha256(encode(utf8(begin.authorization_url))));
    } catch (error) {
      authorized = false;
    }
    if (!authorized) throw native.error("unverified_authorization", "begin statement");

    const returned = await native.webAuth({
      url: begin.authorization_url, callbackScheme: "pickle", ephemeral: begin.ephemeral_session === true,
    });
    // A session closed without a return: the callback may have stored the connection and the user
    // closed the window on the second screen (the repository picker of GitHub). When the completion
    // of that authorization (kept as node_state) exists, it is connected, not cancelled.
    const nodeState = typeof begin.state === "string" ? begin.state.split(".")[0] : "";
    const query = returned === null
      ? { oauth_status: "connected", oauth_state: nodeState, closed_early: "true" }
      : parseQuery(String(returned));
    if (returned === null) {
      let kept = null;
      try {
        kept = (await api("GET", "/api/secure/connections/completion", null, { state: nodeState })).json;
      } catch (error) {
        kept = null;
      }
      if (kept === null) throw native.error("cancelled", "web session closed");
    }
    if (query.oauth_status !== "connected") {
      throw native.error(query.oauth_error ? query.oauth_error : "connect_failed", "oauth callback");
    }
    if (!query.oauth_state) throw native.error("unverified_connection", "callback state");
    const completion = (await api(
      "GET", "/api/secure/connections/completion", null, { state: query.oauth_state })).json;
    let completed = false;
    try {
      const statement = openSigned(completion.statement, node.sign_pk, purpose("statement") + "\n");
      completed = statement.type === "oauth_complete" && statement.node === begin.node &&
        statement.user_id === user && sameBytes(statement.sign_pk, keys.signPk) &&
        statement.state === begin.state;
    } catch (error) {
      completed = false;
    }
    if (!completed) throw native.error("unverified_connection", "completion statement");
    const reward = Number(query.oauth_reward);
    return {
      connection_id: completion.connection_id, provider: completion.provider,
      reward: Number.isFinite(reward) ? reward : 0,
    };
  }

  function stringArgument(value) {
    return typeof value === "string" ? value : "";
  }

  /** Turning a write kind switch (Issues and pull requests, Code, Actions of a GitHub connection)
   *  on or off: PUT /api/integrations/{provider}/{connection_id}/writes. A setting that uses no
   *  credential, but one that decides how the credential is used, so it is a procedure of this
   *  program (secure_run of the definition calls it). */
  async function setConnectionWrites(args) {
    const provider = stringArgument(args.provider).trim();
    const connectionId = stringArgument(args.connection_id).trim();
    const kind = stringArgument(args.kind).trim();
    if (provider === "" || connectionId === "" || kind === "") throw native.error("invalid_input", "writes");
    await api(
      "PUT",
      "/api/integrations/" + encodeURIComponent(provider) + "/" + encodeURIComponent(connectionId) + "/writes",
      { kind: kind, enabled: args.enabled === true },
    );
    return { provider: provider, connection_id: connectionId, kind: kind, enabled: args.enabled === true };
  }

  /** Opens the repository picker (installation) screen of GitHub in the web authentication session
   *  (the "Manage repositories on GitHub" row of the connection detail). The server makes the
   *  address together with a signed state (POST /api/integrations/{provider}/installation-url), and
   *  the return place (the Setup URL) refreshes the list of installation accounts before sending the
   *  user back to pickle://oauth. Closing the window changes nothing, so the result is an empty
   *  object (not a cancellation). */
  async function manageRepositories(args) {
    const provider = stringArgument(args.provider).trim();
    if (provider === "") throw native.error("invalid_input", "provider");
    const minted = (await api(
      "POST", "/api/integrations/" + encodeURIComponent(provider) + "/installation-url", {})).json;
    if (typeof minted.url !== "string" || minted.url === "") {
      throw native.error("connect_failed", "installation url");
    }
    const returned = await native.webAuth({ url: minted.url, callbackScheme: "pickle", ephemeral: false });
    if (returned === null) return {};
    const query = parseQuery(String(returned));
    if (query.oauth_status !== "connected") {
      throw native.error(query.oauth_error ? query.oauth_error : "connect_failed", "installation return");
    }
    return { provider: provider };
  }

  /** An application password is encrypted on the device, and the completion statement is checked
   *  against the delegated node and the record. */
  async function connectAppPassword(args) {
    const username = stringArgument(args.username).trim().toLowerCase();
    const password = stringArgument(args.password);
    if (!username || !password) throw native.error("invalid_input", "mail connection");
    const keys = await presentKeys();
    const ledger = await liveGrantLedger(keys);
    const custody = await recordCustody();
    const record = sealRecord(keys, custody, "app_password", "naver_mail", {
      username: username, password: password,
    });
    return saveAppPasswordRecord(keys, ledger, record, args);
  }

  async function saveAppPasswordRecord(keys, ledger, record, args) {
    const body = { record: record };
    if (typeof args.request_id === "string") body.request_id = args.request_id;
    if (typeof args.setup_id === "string") body.setup_id = args.setup_id;
    const saved = (await api("PUT", "/api/secure/connections/naver_mail/app-password", body)).json;
    const node = typeof saved.node === "string" ? ledger.nodes[saved.node] : undefined;
    let verified = false;
    try {
      const statement = openSigned(saved.statement, node.sign_pk, purpose("statement") + "\n");
      verified = statement.type === "app_password_verified" && statement.node === saved.node &&
        statement.user_id === userId() && sameBytes(statement.sign_pk, keys.signPk) &&
        statement.provider === "naver_mail" && statement.record_id === record.id &&
        statement.key_id === keys.keyId && statement.identity === saved.identity &&
        sameBytes(statement.ciphertext_sha256, native.sha256(encode(utf8(record.ct))));
    } catch (error) {
      verified = false;
    }
    if (!verified) throw native.error("unverified_connection", "mail completion statement");
    return { provider: "naver_mail", connection_id: saved.connection_id, identity: saved.identity };
  }

  // ---- The device-side reception of an application password issued in the browser ----

  const MAIL_SETUP_CONTEXT = "pickle-app-password-setup-v1";
  const MAIL_SETUP_PATH = "/api/secure/connections/naver_mail/setup";
  const MAIL_SETUP_TTL_MS = 2 * 60 * 60 * 1000;

  function mailSetupItem() {
    return {service: "com.pickle.client.secure.mail-setup", account: userId(), synchronizable: false};
  }

  function readMailSetup() {
    const raw = native.keychainGet(mailSetupItem());
    return raw === null ? null : JSON.parse(text(decode(raw)));
  }

  function writeMailSetup(value) {
    const item = mailSetupItem();
    native.keychainSet({service: item.service, account: item.account, synchronizable: false,
      accessible: "after_first_unlock", value: encode(utf8(JSON.stringify(value)))});
  }

  async function beginAppPasswordSetup(args) {
    const keys = await presentKeys();
    await liveGrantLedger(keys);
    let identity = stringArgument(args.identity).trim().toLowerCase();
    if (identity && identity.indexOf("@") < 0) identity += "@naver.com";
    if (identity && !/^[a-z0-9_.-]{1,64}@naver\.com$/.test(identity)) {
      throw native.error("invalid_input", "NAVER account");
    }
    let local = readMailSetup();
    if (local && (local.intent.key_id !== keys.keyId || local.intent.expires_ms <= native.nowMs())) {
      // The capturing state of the server does not release its observation protection on a
      // cancellation alone.
      await api("DELETE", MAIL_SETUP_PATH + "/" + local.intent.id);
      native.keychainDelete(mailSetupItem());
      local = null;
    }
    if (local) {
      const remote = (await api("GET", MAIL_SETUP_PATH, null, {setup_id: local.intent.id})).json.setup;
      if (remote && remote.setup_id === local.intent.id && remote.request.payload === local.signed.payload &&
          (remote.phase === "failed" || remote.phase === "cancelled")) {
        native.keychainDelete(mailSetupItem());
        local = null;
      }
    }
    if (local && local.intent.identity !== identity) {
      throw native.error("setup_in_progress", "another mail setup is pending");
    }
    if (!local) {
      const sk = native.randomBytes(32);
      const now = Math.floor(native.nowMs());
      const intent = {id: native.randomBytes(16), user_id: userId(), key_id: keys.keyId,
        provider: "naver_mail", recipient_pk: native.x25519PublicKey(sk), identity: identity,
        request_id: stringArgument(args.request_id), issued_ms: now, expires_ms: now + MAIL_SETUP_TTL_MS};
      const payload = encode(utf8(JSON.stringify(intent)));
      const signature = native.ed25519Sign(keys.signSeed,
        encode(concat(utf8(MAIL_SETUP_CONTEXT + "\n"), decode(payload))));
      local = {intent: intent, sk: sk, signed: {payload: payload, signature: signature}, record: null};
      // The same request and reception key are used again when the POST response is lost.
      writeMailSetup(local);
    }
    const saved = (await api("POST", MAIL_SETUP_PATH, local.signed)).json;
    native.publish({state: {mail_setup: {phase: saved.phase, error: null}}});
    return saved;
  }

  async function finishAppPasswordSetup(keys, ledger) {
    const local = readMailSetup();
    if (!local) return;
    const intent = local.intent;
    if (intent.user_id !== userId() || intent.key_id !== keys.keyId || intent.expires_ms <= native.nowMs()) {
      native.keychainDelete(mailSetupItem());
      native.publish({state: {mail_setup: {phase: "expired", error: null}}});
      return;
    }
    try {
      const pending = (await api("GET", MAIL_SETUP_PATH, null, {setup_id: intent.id})).json.setup;
      if (!pending) {
        if (local.completed) {
          native.keychainDelete(mailSetupItem());
          native.publish({state: {mail_setup: {phase: "connected", identity: local.completed.identity, error: null}}});
        }
        return;
      }
      if (pending.setup_id !== intent.id || pending.request.payload !== local.signed.payload ||
          pending.request.signature !== local.signed.signature) {
        throw native.error("unverified_connection", "mail setup request");
      }
      native.publish({state: {mail_setup: {phase: pending.phase, error: null}}});
      if (pending.phase === "failed" || pending.phase === "cancelled") {
        native.keychainDelete(mailSetupItem());
        return;
      }
      if (pending.phase !== "captured" && pending.phase !== "connected") return;
      const custody = heldCustody(ledger, native.nowMs());
      if (custody === null) return;
      if (!local.record) {
        if (!pending.capture) throw native.error("invalid_response", "mail setup capture");
        const opened = native.hpkeOpen({
          kem: "x25519", kdf: "sha256", aead: "chacha20poly1305", recipientPrivateKey: local.sk,
          info: encode(utf8(MAIL_SETUP_CONTEXT)), aad: native.sha256(local.signed.payload),
          enc: pending.capture.enc, ciphertext: pending.capture.ct,
        });
        const credential = JSON.parse(text(decode(opened)));
        if (!credential || typeof credential.username !== "string" ||
            !/^[a-z0-9_.-]{1,64}@naver\.com$/.test(credential.username) ||
            typeof credential.password !== "string" || !credential.password ||
            (intent.identity && intent.identity !== credential.username)) {
          throw native.error("unverified_connection", "mail setup account");
        }
        local.record = sealRecordBytes(keys, custody, "app_password", "naver_mail", opened);
        // The same ciphertext is sent again so that a lost response does not become a second
        // registration.
        writeMailSetup(local);
      }
      const saved = await saveAppPasswordRecord(keys, ledger, local.record, {
        setup_id: intent.id, request_id: intent.request_id,
      });
      local.completed = saved;
      writeMailSetup(local);
      await api("DELETE", MAIL_SETUP_PATH + "/" + intent.id);
      native.keychainDelete(mailSetupItem());
      native.publish({state: {mail_setup: {phase: "connected", identity: saved.identity, error: null}}});
    } catch (error) {
      // Neither the remote error body nor a secret is published. The next sync resumes the stored
      // request.
      native.publish({state: {mail_setup: {phase: "pending", error: failureCode(error)}}});
    }
  }

  async function cancelAppPasswordSetup() {
    const local = readMailSetup();
    if (local) await api("DELETE", MAIL_SETUP_PATH + "/" + local.intent.id);
    native.keychainDelete(mailSetupItem());
    native.publish({state: {mail_setup: null}});
    return {};
  }

  /** Storing a site login: the password and the TOTP seed each become a record in the vault. An
   *  empty one is not sent (the backend keeps the existing record). */
  async function storeLogin(args) {
    const username = stringArgument(args.username).trim();
    const password = stringArgument(args.password);
    const totp = stringArgument(args.totp).replace(/\s/g, "").toUpperCase();
    if (username === "" || typeof args.name !== "string") throw native.error("invalid_input", "login");
    if (totp !== "" && !/^[A-Z2-7]+=*$/.test(totp)) throw native.error("invalid_input", "totp");
    const keys = await presentKeys();
    const body = { name: args.name, username: username };
    if (password !== "" || totp !== "") {
      const custody = await recordCustody();
      if (password !== "") {
        body.password = sealRecord(keys, custody, "vault_password", "vault", { value: password });
      }
      if (totp !== "") body.totp = sealRecord(keys, custody, "vault_totp", "vault", { value: totp });
    }
    const saved = (await api("PUT", "/api/secure/vault/login", body)).json;
    return { name: saved.name };
  }

  /** The Luhn check of a card number. */
  function luhnValid(digits) {
    let sum = 0;
    for (let i = 0; i < digits.length; i += 1) {
      let digit = digits.charCodeAt(digits.length - 1 - i) - 48;
      if (i % 2 === 1) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
    }
    return sum % 10 === 0;
  }

  function cardBrand(number) {
    const two = Number(number.slice(0, 2));
    const four = Number(number.slice(0, 4));
    if (number[0] === "4") return "visa";
    if ((two >= 51 && two <= 55) || (four >= 2221 && four <= 2720)) return "mastercard";
    if (two === 34 || two === 37) return "amex";
    return "card";
  }

  /** Storing a card: the number and the CVC become one record in the vault. When both the number
   *  and the CVC are empty, neither the record nor brand and last4 are sent (the backend keeps the
   *  existing values). */
  async function storeCard(args) {
    const number = stringArgument(args.number).replace(/[\s-]/g, "");
    const cvc = stringArgument(args.cvc).trim();
    const expiry = stringArgument(args.expiry).replace(/[^0-9]/g, "");
    if (number !== "" && (!/^[0-9]{12,19}$/.test(number) || !luhnValid(number))) {
      throw native.error("invalid_input", "number");
    }
    if (cvc !== "" && !/^[0-9]{3,4}$/.test(cvc)) throw native.error("invalid_input", "cvc");
    if ((number === "") !== (cvc === "")) throw native.error("invalid_input", "number and cvc");
    if (expiry.length !== 4 && expiry.length !== 6) throw native.error("invalid_input", "expiry");
    const month = Number(expiry.slice(0, 2));
    const year = expiry.length === 4 ? 2000 + Number(expiry.slice(2)) : Number(expiry.slice(2));
    if (month < 1 || month > 12 || year < 2000 || year > 2099) throw native.error("invalid_input", "expiry");
    const keys = await presentKeys();
    const body = {
      name: stringArgument(args.name), label: stringArgument(args.label),
      cardholder: stringArgument(args.cardholder),
    };
    if (number !== "") {
      body.brand = cardBrand(number);
      body.last4 = number.slice(-4);
    }
    body.exp_month = month;
    body.exp_year = year;
    body.postal = stringArgument(args.postal);
    if (number !== "") {
      const custody = await recordCustody();
      body.value = sealRecord(keys, custody, "vault_card", "vault", { number: number, cvc: cvc });
    }
    body.request_id = stringArgument(args.request_id);
    const saved = (await api("PUT", "/api/secure/vault/card", body)).json;
    return { name: saved.name };
  }

  // The places of the later pages of the log screen (runtime lifetime): {id, before_ms, after_day,
  // rows, opened}. The screen draws a page for each place and reads it with read_log_page when it
  // scrolls near it.
  let logPagePlaces = [];

  function publishLogPages() {
    native.publish({ runtime: { log_pages: logPagePlaces } });
  }

  /** The place of the next page after one page: before_ms is the time of the last entry of that
   *  page (every entry of that millisecond is on that page), rows the number of display groups up
   *  to that page (rows up to the previous pages plus shown, the groups of this page). null when the
   *  page has no entry or there is no more. */
  function logPageAfter(page, rows, shown) {
    if (page.has_more !== true || page.last_ms < 1) return null;
    return {
      id: String(page.last_ms), before_ms: page.last_ms, after_day: formatTime(page.last_ms, "date"),
      rows: rows + shown, opened: false,
    };
  }

  /** The before_ms argument: an integer of 1 or more, or its decimal string. Otherwise null. */
  function logPageCursor(value) {
    const before = typeof value === "string" && /^[0-9]+$/.test(value) ? Number(value) : value;
    return Number.isSafeInteger(before) && before >= 1 ? before : null;
  }

  /** A failed read of the store while the screen reads it: the failure code names the kind. */
  function screenStoreError(error) {
    return isStoreFailure(error) ? native.error("log_store_" + error.kind, "log screen") : error;
  }

  // The counts of the later pages read in this runtime (the reads, sends and changes of their
  // request items, the providers used, the entries read) and the ids of the entries counted. The
  // log screen reads them as runtime.log_counts (published after every page).
  let pageCounts = { reads: 0, sends: 0, changes: 0, providers: [], entries: 0, counted: new Set() };

  function publishLogCounts() {
    native.publish({ runtime: { log_counts: {
      reads: pageCounts.reads, sends: pageCounts.sends, changes: pageCounts.changes,
      providers_text: providersText(pageCounts), entries: pageCounts.entries,
    } } });
  }

  /** The log query (the first page of the log screen): verifies the chains (index verification),
   *  reads the keys of the last LOG_OVERVIEW_DAYS days, draws the overview from the keys alone and
   *  reads the latest entries until LOG_RECENT_EVENTS events (the recent activity). When the
   *  verification could not read the store (its state is not verified: a store that failed, an
   *  address that was rejected, an env without a store) the screen reads nothing: the overview is
   *  null and the recent activity empty, and the state of the verification says why. The list of
   *  the places of the later pages becomes the one place of the second page (an empty list when
   *  there is no more). */
  async function readLog() {
    const keys = await presentKeys();
    const ledger = loadLedger();
    const log = await verifyAll(ledger, keys);
    const ids = log.store === "verified" ? screenNodes(ledger) : [];
    anchorScreen(ledger, ids);
    const now = native.nowMs();
    let overview = null;
    let recent = { entries: [], items: [], last_ms: 0, has_more: false };
    if (ids.length > 0) {
      try {
        await loadOverviewKeys(ledger, ids, now);
        overview = overviewOf(ledger, ids, now);
        recent = await collectEntries(ledger, ids, keys, Infinity, LOG_RECENT_EVENTS);
      } catch (error) {
        throw screenStoreError(error);
      }
    }
    const groups = displayGroups(recent.items);
    const next = logPageAfter(recent, 0, groups.length);
    logPagePlaces = next === null ? [] : [next];
    publishLogPages();
    return {
      status: log.status, verified_ms: log.verified_ms, unverified_nodes: log.unverified_nodes,
      missing: log.missing, expired: log.expired, unknown_nodes: log.unknown_nodes, store: log.store,
      store_failing_ms: log.store_failing_ms, overview: overview, recent: recent.items,
      recent_days: displayDays(groups), has_more: recent.has_more,
    };
  }

  /** Records that the screen started reading the page of that place (at the call of read_log_page:
   *  it does not wait for the earlier procedures). A place that is not in the list and a place
   *  already recorded are left unchanged. */
  function openLogPage(before) {
    const at = logPagePlaces.findIndex(function (place) { return place.before_ms === before; });
    if (at < 0 || logPagePlaces[at].opened) return;
    const place = logPagePlaces[at];
    logPagePlaces = logPagePlaces.slice();
    logPagePlaces[at] = {
      id: place.id, before_ms: place.before_ms, after_day: place.after_day, rows: place.rows, opened: true,
    };
    publishLogPages();
  }

  /** One later page of the log screen: the entries before before_ms until LOG_SCREEN_EVENTS events,
   *  as the list of day groups (consecutive requests and days that straddle a page boundary are
   *  grouped per page). The counts of the pages read in this runtime are published as
   *  runtime.log_counts (the log screen shows them above the pages). The chains are not verified
   *  (read_log does that): the signature check of each entry is the verified of the group. When
   *  that place is the last of the list and there is more, the next place is appended (a call that
   *  reads an earlier page again, and a call that ended after read_log replaced the list, append
   *  nothing). */
  async function readLogPage(args) {
    const before = logPageCursor(args.before_ms);
    if (before === null) throw native.error("invalid_input", "before_ms");
    const keys = await presentKeys();
    const ledger = loadLedger();
    const ids = screenNodes(ledger);
    anchorScreen(ledger, ids);
    let page = null;
    try {
      page = await collectEntries(ledger, ids, keys, before, LOG_SCREEN_EVENTS);
    } catch (error) {
      throw screenStoreError(error);
    }
    for (const entry of page.entries) {
      const name = entry.id + ":" + entry.seq;
      if (pageCounts.counted.has(name)) continue;
      pageCounts.counted.add(name);
      pageCounts.entries += 1;
      for (const item of entry.items) countInto(pageCounts, item);
    }
    publishLogCounts();
    const groups = displayGroups(page.items);
    const last = logPagePlaces.length === 0 ? null : logPagePlaces[logPagePlaces.length - 1];
    const next = last !== null && last.before_ms === before ? logPageAfter(page, last.rows, groups.length) : null;
    if (next !== null) {
      logPagePlaces = logPagePlaces.concat([next]);
      publishLogPages();
    }
    return { has_more: page.has_more, days: displayDays(groups) };
  }

  // ---- The full verification ----

  // The full verification in progress (null when none): the run the loop checks for a cancel, and
  // the published state log_full {status, started_ms, finished_ms, finished_text, nodes_total,
  // nodes_done, entries_total, entries_checked, events_checked, expired, bytes, failures: {signature,
  // hash, open, missing}, failure}.
  let fullRun = null;
  let fullState = null;

  function publishFull() {
    native.publish({ state: { log_full: fullState } });
  }

  /** The index of a whole chain: every page of the listing of the node prefix. Throws a store
   *  failure; stops (returning what it read) when the run was cancelled. */
  async function storeIndexAll(id, run) {
    const prefix = accountPrefix() + id + "/";
    const index = { entries: new Map(), min: 0, max: 0 };
    let keyMarker = prefix + seqDigits(0) + "-~";
    let versionIdMarker = null;
    for (;;) {
      if (run.cancelled) return index;
      const listing = await listStorePage(false, id, keyMarker, versionIdMarker);
      for (const version of listing.versions) {
        const parts = parseStoreKey(version.key, prefix);
        if (parts === null) continue;
        if (!index.entries.has(parts.seq)) index.entries.set(parts.seq, []);
        index.entries.get(parts.seq).push({
          key: version.key, versionId: version.versionId, isLatest: version.isLatest, parts: parts,
        });
        if (index.min === 0 || parts.seq < index.min) index.min = parts.seq;
        if (parts.seq > index.max) index.max = parts.seq;
      }
      if (!listing.truncated || listing.nextKeyMarker === null) return index;
      keyMarker = listing.nextKeyMarker;
      versionIdMarker = listing.nextVersionIdMarker;
    }
  }

  /** The full verification (docs/protocol.md 7.4): every entry of every chain of the account in the
   *  store, from the smallest listed seq, read by content (signature, body hash, prev as the hash of
   *  the entry before, the opening of the plaintext when the key_id is ours), LOG_STORE_OBJECTS
   *  addresses per request and LOG_FULL_FETCHES objects at a time. The seqs below the smallest listed
   *  one are expired; a seq absent between two listed ones is missing; an entry that does not verify
   *  counts by what failed (the failure of its latest version). Nothing is kept on the device. The
   *  loop runs apart from the procedure calls and ends at a cancel, at a store failure (failed) or
   *  when every chain was read (done). */
  async function fullVerificationLoop(ledger, keys, run) {
    try {
      const ids = await discoverStoreNodes();
      fullState.nodes_total = ids.length;
      publishFull();
      for (const id of ids) {
        const index = await storeIndexAll(id, run);
        if (run.cancelled) break;
        const seqs = Array.from(index.entries.keys()).sort(function (a, b) { return a - b; });
        fullState.entries_total += seqs.length;
        if (index.min > 1) fullState.expired += index.min - 1;
        const signer = ledger.nodes[id] !== undefined ? ledger.nodes[id] : { sign_pk: id };
        let cursor = index.min === 1 ? { seq: 0, hash: ZERO_HASH } : null;
        for (let at = 0; at < seqs.length;) {
          if (run.cancelled) break;
          const batch = [];
          const wanted = [];
          while (at < seqs.length && wanted.length + index.entries.get(seqs[at]).length <= LOG_STORE_OBJECTS) {
            batch.push(seqs[at]);
            for (const candidate of index.entries.get(seqs[at])) wanted.push(candidate);
            at += 1;
          }
          if (batch.length === 0) {
            // A seq with more candidates than one request carries: its latest versions only.
            const latest = index.entries.get(seqs[at]).slice(0, LOG_STORE_OBJECTS);
            batch.push(seqs[at]);
            for (const candidate of latest) wanted.push(candidate);
            at += 1;
          }
          const urls = await storeObjectUrls(wanted);
          const fetched = await fetchStoreObjects(urls, LOG_FULL_FETCHES);
          for (const seq of batch) {
            if (cursor !== null && seq !== cursor.seq + 1) {
              fullState.failures.missing += seq - cursor.seq - 1;
              cursor = null;
            }
            const candidates = index.entries.get(seq).slice().sort(function (a, b) {
              return (b.isLatest ? 1 : 0) - (a.isLatest ? 1 : 0);
            });
            let verified = null;
            let failure = "missing";
            for (const candidate of candidates) {
              const response = fetched.get(candidate.key + "\n" + candidate.versionId);
              if (response === undefined) continue;
              fullState.bytes += response.bytes;
              if (response.signed === null) continue;
              const checked = checkEntry(response.signed, signer, id, candidate.parts, cursor, keys);
              if (checked.entry !== null) {
                verified = checked.entry;
                break;
              }
              if (failure === "missing") failure = checked.failure;
            }
            if (verified === null) {
              fullState.failures[failure] += 1;
              cursor = null;
            } else {
              fullState.entries_checked += 1;
              fullState.events_checked += verified.events !== null ? verified.events.length
                : verified.format === 2 ? verified.body.count : 1;
              cursor = { seq: seq, hash: verified.hash };
            }
          }
          publishFull();
        }
        if (run.cancelled) break;
        fullState.nodes_done += 1;
        publishFull();
      }
      const now = native.nowMs();
      fullState.status = run.cancelled ? "cancelled" : "done";
      fullState.finished_ms = now;
      fullState.finished_text = formatTime(now, "time");
    } catch (error) {
      fullState.status = "failed";
      fullState.finished_ms = native.nowMs();
      fullState.failure = isStoreFailure(error) ? "log_store_" + error.kind : failureCode(error);
    }
    fullRun = null;
    publishFull();
  }

  /** Starts the full verification (when none is running) and returns the state log_full at once; the
   *  loop goes on inside the runtime apart from the procedure calls and publishes its progress. */
  async function startFullVerification() {
    if (fullRun !== null) return { log_full: fullState };
    const keys = await presentKeys();
    const ledger = loadLedger();
    fullRun = { cancelled: false };
    fullState = {
      status: "running", started_ms: native.nowMs(), finished_ms: 0, finished_text: "",
      nodes_total: 0, nodes_done: 0, entries_total: 0, entries_checked: 0, events_checked: 0,
      expired: 0, bytes: 0, failures: { signature: 0, hash: 0, open: 0, missing: 0 }, failure: "",
    };
    publishFull();
    fullVerificationLoop(ledger, keys, fullRun);
    return { log_full: fullState };
  }

  /** Stops the full verification in progress: the loop ends after the batch it is reading. */
  async function cancelFullVerification() {
    if (fullRun !== null) fullRun.cancelled = true;
    return { log_full: fullState };
  }

  /** Setting the grant lifetime: days is an integer from 1 to 30 (or its decimal string). A grant
   *  of that lifetime is handed again to every living node (without regard to the renewal interval:
   *  a shortened lifetime applies at once), and when every node took it the value is written to the
   *  ledger. When any node did not take the grant the lifetime of the ledger is left unchanged (the
   *  grant times and expiries of the nodes that took it are written) and the call fails with
   *  grant_incomplete: that node may still hold a grant of the earlier lifetime. When delegation is
   *  off only the value is written. */
  async function setGrantDays(args) {
    const textual = typeof args.days === "string" && /^[0-9]+$/.test(args.days);
    const days = textual ? Number(args.days) : args.days;
    if (!Number.isSafeInteger(days) || days < 1 || days > GRANT_DAYS_MAX) {
      throw native.error("invalid_input", "days");
    }
    const keys = await presentKeys();
    const ledger = loadLedger();
    const kept = { ttl_days: ledger.ttl_days, ttl_set_ms: ledger.ttl_set_ms };
    ledger.ttl_days = days;
    ledger.ttl_set_ms = Math.max(native.nowMs(), ledger.ttl_set_ms + 1);
    let renewed = { accepted: new Set(), rejected: 0, failed: 0 };
    if (!delegationOff(ledger)) renewed = await renewGrants(keys, ledger, true);
    if (renewed.failed > 0) {
      ledger.ttl_days = kept.ttl_days;
      ledger.ttl_set_ms = kept.ttl_set_ms;
    }
    saveLedger(ledger);
    const grant = grantState(ledger, renewed.accepted, native.nowMs());
    native.publish({
      state: { grant: grant, grant_days: ledger.ttl_days },
      runtime: { rejected_nodes: renewed.rejected },
    });
    if (renewed.failed > 0) throw native.error("grant_incomplete", "a live node did not take the grant");
    return { grant: grant, days: ledger.ttl_days };
  }

  /** Sends a revoke to every living node, also to nodes that are not in the ledger: a node hands
   *  delegations to nodes of the same release (the delegation transfer), so a node this device
   *  never handed a grant to can hold the user key of this account. The revoke of a node without a
   *  grant changes nothing and passes. A node whose sealing public key is in the ledger is sealed to
   *  with that key, every other node with the key obtained by verifying its attestation. Returns
   *  whether a living node did not confirm the revoke (nodes whose attestation failed to verify
   *  included: there is no key to seal the revoke to for them). */
  async function revokeEverywhere(keys, ledger) {
    const nonce = native.randomBytes(32);
    const offered = (await api("GET", "/api/secure/nodes", null, { nonce: nonce })).json.nodes;
    let incomplete = false;
    for (const response of Array.isArray(offered) ? offered : []) {
      const id = response !== null && typeof response === "object" ? response.node : undefined;
      const known = typeof id === "string" ? ledger.nodes[id] : undefined;
      try {
        // The attestation of this response is verified for nodes of the ledger too: the time of the
        // document that decides the freshness of the reply and the check of the challenge statement
        // come from it. A revoke does not check the acceptance conditions (the accepted
        // measurements, a build that accepts local): that gate decides who receives a user key, and
        // a revoke command carries no secret. The revoke also reaches a node of a release that left
        // the list, and a node that took over a delegation from it.
        const target = verifyAttestation(response, nonce, false);
        if (known !== undefined && target.node !== id) throw attestationFailure("another node");
        await sendRevoke(target, response.challenge, keys);
      } catch (error) {
        incomplete = true;
        native.log("revoke failed: " + failureCode(error));
      }
    }
    return incomplete;
  }

  /** The delegation switch. Turning it off sends a revoke to every living node and writes the
   *  revocation time to the ledger (a node that is not alive has no user key any more). When a
   *  living node did not answer the revoke, the revocation time is written and the call fails with
   *  revoke_incomplete (the syncs while off send the revoke again). Turning it on writes the
   *  resumption time and hands the grants again. */
  async function setDelegation(args) {
    if (typeof args.enabled !== "boolean") throw native.error("invalid_input", "enabled");
    const keys = await presentKeys();
    const ledger = loadLedger();
    // The resumption time is not before the revocation time and the revocation time is after the
    // resumption time: the last operation decides the state of the switch even when the device
    // clock runs backwards or the clock of another device runs ahead.
    if (args.enabled) {
      ledger.resumed_ms = Math.max(native.nowMs(), ledger.revoked_ms);
      return { grant: (await delegate(keys, ledger)).grant };
    }
    const incomplete = await revokeEverywhere(keys, ledger);
    // The revocation time is after the resumption time and not before any grant time of the
    // ledger: even when the device clock ran backwards or the clock of the device that wrote a
    // grant runs ahead, a grant handed before the revoke is not read as one after it.
    let revoked = Math.max(native.nowMs(), ledger.resumed_ms + 1);
    for (const id of Object.keys(ledger.nodes)) revoked = Math.max(revoked, ledger.nodes[id].granted_ms);
    ledger.revoked_ms = revoked;
    saveLedger(ledger);
    const grant = grantState(ledger, new Set(), ledger.revoked_ms);
    native.publish({ state: { grant: grant } });
    if (incomplete) throw native.error("revoke_incomplete", "a live node did not confirm");
    return { grant: grant };
  }

  /** An account end that erases the account records: deletes the master key item and the node
   *  ledger (the keychain item and the device copy). */
  async function eraseAccountKeys() {
    deleteMasterKey();
    native.keychainDelete(ledgerItem());
    native.keychainDelete(mailSetupItem());
    native.storeSet(LEDGER_STORE_KEY, null);
  }

  // ---- Serialization ----

  let queue = Promise.resolve();

  /** Procedures and event handlers run one at a time: the next starts after the previous one ended,
   *  and the failure of the previous one does not block the next. */
  function serial(work) {
    const run = queue.then(work);
    queue = run.then(function () {}, function () {});
    return run;
  }

  // ---- Master key transfer (device approval transfer) ----
  // A device of the same account without the key (the requesting device) receives the master key
  // from a device with the key (the approving device). When the user enters the 6-digit code shown
  // by the approving device into the requesting device, the two devices agree on a session key with
  // CPace (a PAKE over X25519: the generator is the hash of the account, the request id and the
  // code, mapped with Elligator2), and the approving device seals the master key with that key and
  // sends it through the api. The api carries only the public messages (ya, yb), the confirmation
  // tags (ta, tb) and the ciphertext; the code, the PAKE secrets, the session key and the plaintext
  // exist on the two devices only. The server checks the phase transitions. The secrets of a
  // transfer in progress live in the runtime variable transferRun only; the published state
  // state.transfer carries the role, the phase, the device descriptions and the result only, and the
  // code goes to runtime.transfer_code only (no device storage), which the executor hands to its
  // native transfer cover and never to the definition. Contract: docs/ssot/client/
  // secure-executor.md of pickle-com/interactive-character, the master key transfer section.

  const TRANSFER_PATH = "/api/secure/transfers";
  // The server polling interval. The lifetime of a request (600 seconds) is set by the server and
  // arrives as expires_ms of the response.
  const TRANSFER_POLL_MS = 2000;
  // The budget for which the code entry procedure waits inside itself for the sealed envelope
  // (below the 120-second procedure limit).
  const TRANSFER_INLINE_WAIT_MS = 90000;
  const TRANSFER_CODE_MODULUS = 1000000;
  // The terminal phases: done (the requesting device received the key, the approving device handed
  // the envelope over), failed (confirmation tag mismatch, verification failure), expired (not
  // finished within the lifetime), cancelled (cancelled by the requesting device), declined
  // (declined by the approving device), taken (another device approved first).
  const TRANSFER_TERMINAL = ["done", "failed", "expired", "cancelled", "declined", "taken"];
  // The field of X25519 (2^255 - 19), the Montgomery coefficient A, and the non-square constant Z of
  // Elligator2 (RFC 9380 8.5).
  const FIELD_P = (1n << 255n) - 19n;
  const CURVE_A = 486662n;
  const ELLIGATOR_Z = 2n;
  // The sealing nonce: the session key seals exactly once per request, so it is fixed.
  const TRANSFER_NONCE = encode(new Uint8Array(12));

  let transferRun = null;
  let transferLoopActive = false;

  function fieldMod(x) {
    const r = x % FIELD_P;
    return r < 0n ? r + FIELD_P : r;
  }

  function fieldPow(base, exponent) {
    let result = 1n;
    let b = fieldMod(base);
    let e = exponent;
    while (e > 0n) {
      if (e & 1n) result = (result * b) % FIELD_P;
      b = (b * b) % FIELD_P;
      e >>= 1n;
    }
    return result;
  }

  function fieldIsSquare(x) {
    const v = fieldMod(x);
    return v === 0n || fieldPow(v, (FIELD_P - 1n) / 2n) === 1n;
  }

  /** The u coordinate of Elligator 2 (RFC 9380 F.3) for curve25519 (A = 486662, B = 1, Z = 2). */
  function elligator2(u) {
    let tv1 = fieldMod(ELLIGATOR_Z * u * u);
    if (tv1 === FIELD_P - 1n) tv1 = 0n;
    const x1 = fieldMod(-CURVE_A * fieldPow(tv1 + 1n, FIELD_P - 2n));
    const gx1 = fieldMod(((x1 + CURVE_A) * x1 + 1n) * x1);
    const x2 = fieldMod(-x1 - CURVE_A);
    return fieldIsSquare(gx1) ? x1 : x2;
  }

  function fieldFromBytes(bytes) {
    let v = 0n;
    for (let i = 0; i < bytes.length; i += 1) v = (v << 8n) | BigInt(bytes[i]);
    return fieldMod(v);
  }

  /** A field element -> the X25519 u coordinate representation (32 bytes, little-endian). */
  function fieldToBytes(x) {
    const out = new Uint8Array(32);
    let v = x;
    for (let i = 0; i < 32; i += 1) {
      out[i] = Number(v & 255n);
      v >>= 8n;
    }
    return out;
  }

  /** The PAKE generator (an X25519 public key representation): the SHA-512 of the account, the
   *  request id and the code, reduced to a field element and mapped with Elligator2. */
  function transferGenerator(requestId, code) {
    const seed = utf8(purpose("transfer.pake") + "\n" + userId() + "\n" + requestId + "\n" + code);
    return encode(fieldToBytes(elligator2(fieldFromBytes(decode(native.sha512(encode(seed)))))));
  }

  function transferTranscript(requestId, ya, yb) {
    return concat(utf8(userId()), utf8(requestId), decode(ya), decode(yb));
  }

  /** The session key: derived from the X25519 shared secret with the transcript (the account, the
   *  request id, ya, yb) bound into the info. */
  function transferSessionKey(shared, requestId, ya, yb) {
    const info = concat(utf8(purpose("transfer.session")), transferTranscript(requestId, ya, yb));
    return native.hkdf("sha256", shared, null, encode(info), 32);
  }

  function transferTag(sessionKey, side) {
    return native.hmac("sha256", sessionKey, encode(utf8(purpose("transfer.confirm." + side))));
  }

  function transferEnvelope(sessionKey, requestId, ya, yb) {
    return {
      alg: "chacha20poly1305",
      key: native.hkdf("sha256", sessionKey, null, info("transfer.envelope"), 32),
      nonce: TRANSFER_NONCE,
      aad: encode(transferTranscript(requestId, ya, yb)),
    };
  }

  /** The 6-digit code: drawn without bias from 4 random bytes (only values below a multiple of the
   *  code space are taken). */
  function transferCode() {
    for (;;) {
      const bytes = decode(native.randomBytes(4));
      const value = bytes[0] * 16777216 + bytes[1] * 65536 + bytes[2] * 256 + bytes[3];
      if (value < 4294000000) return String(value % TRANSFER_CODE_MODULUS).padStart(6, "0");
    }
  }

  /** The device description: platform, model and app_version of deviceInfo. A value that is not a
   *  string (an app build that does not provide the key) is the empty string. */
  function transferDevice() {
    const device = native.deviceInfo();
    function field(name) {
      return typeof device[name] === "string" ? device[name] : "";
    }
    return { platform: field("platform"), model: field("model"), app_version: field("app_version") };
  }

  function transferTerminal(phase) {
    return TRANSFER_TERMINAL.indexOf(phase) >= 0;
  }

  function transferView() {
    if (transferRun === null) return null;
    return {
      role: transferRun.role, phase: transferRun.phase, request_id: transferRun.requestId,
      device: transferRun.device, approver: transferRun.approver, expires_ms: transferRun.expiresMs,
      failure: transferRun.failure,
    };
  }

  function publishTransfer() {
    const showingCode = transferRun !== null && transferRun.role === "approving" && transferRun.phase === "approved";
    native.publish({
      state: { transfer: transferView() },
      runtime: { transfer_code: showingCode ? transferRun.code : null },
    });
  }

  function resetTransfer() {
    transferRun = null;
    publishTransfer();
  }

  /** Settlement: records the phase and the result and drops the secrets (the PAKE scalar, the
   *  session key, the code). */
  function transferSettle(phase, failure) {
    if (transferRun === null) return;
    transferRun.phase = phase;
    transferRun.failure = failure === undefined ? null : failure;
    transferRun.scalar = null;
    transferRun.sessionKey = null;
    transferRun.code = null;
    publishTransfer();
  }

  /** The server state of the request. A missing request (404) is an expiry or the cleanup of the
   *  other device, and gives null. */
  async function transferFetch() {
    try {
      return (await api("GET", TRANSFER_PATH + "/" + transferRun.requestId)).json.transfer;
    } catch (error) {
      if (error.code === "not_found") return null;
      throw error;
    }
  }

  /** One step: reads the server state and does the next thing of the role of this device. */
  async function transferStep() {
    if (transferRun === null || transferTerminal(transferRun.phase)) return;
    const remote = await transferFetch();
    if (remote === null) {
      // An absence seen by the approving device that handed the envelope over is the receipt
      // confirmation of the requesting device (done); every other absence is an expiry.
      transferSettle(transferRun.role === "approving" && transferRun.phase === "sealed" ? "done" : "expired");
      return;
    }
    const phase = remote.phase;
    if (phase === "failed" || phase === "cancelled" || phase === "declined") {
      transferSettle(phase, typeof remote.failure === "string" ? remote.failure : phase);
      return;
    }
    if (transferRun.role === "requesting") {
      if (phase === "approved" && transferRun.phase === "requested") {
        transferRun.yb = String(remote.yb);
        transferRun.approver = remote.approver;
        transferRun.phase = "code_entry";
        publishTransfer();
      } else if (phase === "sealed" && transferRun.phase === "replied") {
        await transferReceive(remote);
      }
    } else if (phase === "replied" && transferRun.phase === "approved") {
      await transferSeal(remote);
    }
  }

  /** The polling loop: advances one step on the serial queue at every interval until the transfer
   *  in progress settles. It runs inside the runtime apart from the procedure calls, a transport
   *  failure is left to the next poll, and every other failure ends the transfer as failed. */
  async function transferLoop() {
    if (transferLoopActive) return;
    transferLoopActive = true;
    try {
      while (transferRun !== null && !transferTerminal(transferRun.phase)) {
        if (native.nowMs() > transferRun.expiresMs) {
          transferSettle("expired");
          break;
        }
        await native.sleep(TRANSFER_POLL_MS);
        try {
          await serial(transferStep);
        } catch (error) {
          if (error.code === "transport" || /^http_5/.test(String(error.code))) continue;
          native.log("transfer: " + failureCode(error));
          transferSettle("failed", failureCode(error));
        }
      }
    } finally {
      transferLoopActive = false;
    }
  }

  /** The requesting device: creates a transfer request and waits for the approval. It holds only
   *  when key_state is waiting. */
  async function beginTransfer() {
    if (transferRun !== null && !transferTerminal(transferRun.phase)) return { transfer: transferView() };
    const judged = await judgeKey();
    if (judged.keyState !== "waiting") throw native.error("invalid_state", judged.keyState);
    const device = transferDevice();
    const created = (await api("POST", TRANSFER_PATH, { device: device })).json.transfer;
    transferRun = {
      role: "requesting", requestId: String(created.request_id), phase: "requested", device: device,
      approver: null, expiresMs: Number(created.expires_ms), failure: null, yb: null, ya: null,
      scalar: null, sessionKey: null, code: null,
    };
    publishTransfer();
    transferLoop();
    return { transfer: transferView() };
  }

  /** The requesting device: makes the PAKE message and the confirmation tag from the code on the
   *  screen of the approving device and uploads them. */
  async function enterTransferCode(args) {
    const code = typeof args.code === "string" ? args.code.replace(/\D/g, "") : "";
    if (code.length !== 6) throw native.error("invalid_input", "code");
    if (transferRun === null || transferRun.role !== "requesting" || transferRun.phase !== "code_entry") {
      throw native.error("invalid_state", transferRun === null ? "none" : transferRun.phase);
    }
    const generator = transferGenerator(transferRun.requestId, code);
    const scalar = native.randomBytes(32);
    const ya = native.x25519(scalar, generator);
    const sessionKey = transferSessionKey(
      native.x25519(scalar, transferRun.yb), transferRun.requestId, ya, transferRun.yb);
    await api("PUT", TRANSFER_PATH + "/" + transferRun.requestId + "/reply", {
      ya: ya, ta: transferTag(sessionKey, "request"),
    });
    transferRun.ya = ya;
    transferRun.sessionKey = sessionKey;
    transferRun.phase = "replied";
    publishTransfer();
    // The envelope of the approving device arrives within seconds of the reply, so this procedure
    // waits for it inside itself (a budget within the procedure limit): when it ends the screen
    // shows the result at once. When it does not arrive within the budget the polling loop takes
    // over.
    const deadline = native.nowMs() + TRANSFER_INLINE_WAIT_MS;
    while (transferRun !== null && !transferTerminal(transferRun.phase) && native.nowMs() < deadline) {
      await native.sleep(TRANSFER_POLL_MS);
      try {
        await transferStep();
      } catch (error) {
        if (error.code !== "transport" && !/^http_5/.test(String(error.code))) throw error;
      }
    }
    if (transferRun !== null && !transferTerminal(transferRun.phase)) transferLoop();
    return { transfer: transferView() };
  }

  /** The requesting device: the reception of the sealed master key. The confirmation tag of the
   *  approving device is compared and the ciphertext opened, and the key is written to the keychain
   *  only when the key_id of the derived account signing public key equals the registered key_id of
   *  the account. */
  async function transferReceive(remote) {
    const run = transferRun;
    if (!equal(decode(transferTag(run.sessionKey, "approve")), decode(String(remote.tb)))) {
      transferSettle("failed", "bad_tag");
      return;
    }
    let masterKey = null;
    try {
      const envelope = transferEnvelope(run.sessionKey, run.requestId, run.ya, run.yb);
      masterKey = native.aeadOpen({
        alg: envelope.alg, key: envelope.key, nonce: envelope.nonce, aad: envelope.aad,
        ciphertext: String(remote.ciphertext),
      });
    } catch (error) {
      transferSettle("failed", "bad_envelope");
      return;
    }
    const keys = deriveKeys(masterKey);
    const registered = await registeredKeyId();
    if (registered !== keys.keyId) {
      transferSettle("failed", "key_mismatch");
      return;
    }
    writeMasterKey(masterKey);
    publishKey("present", keys);
    try {
      await api("POST", TRANSFER_PATH + "/" + run.requestId + "/ack", {});
    } catch (error) {
      native.log("transfer ack: " + failureCode(error));
    }
    transferSettle("done");
    await delegate(keys, loadLedger());
  }

  /** The approving device: when it has the key and no transfer is in progress, the oldest pending
   *  request is raised to pending approval. */
  async function checkTransferRequests() {
    if (transferRun !== null && !transferTerminal(transferRun.phase)) return;
    if (readMasterKey() === null) return;
    const pending = (await api("GET", TRANSFER_PATH)).json.transfers;
    if (!Array.isArray(pending) || pending.length === 0) return;
    const request = pending[0];
    transferRun = {
      role: "approving", requestId: String(request.request_id), phase: "pending_approval",
      device: request.device, approver: transferDevice(), expiresMs: Number(request.expires_ms),
      failure: null, yb: null, ya: null, scalar: null, sessionKey: null, code: null,
    };
    publishTransfer();
  }

  /** The device owner authentication prompt of approve_transfer, in the device language (en, ko, ja).
   *  The text names the requesting device, so the prompt itself says what is being approved. */
  function transferAuthReason(device) {
    const model = device && typeof device.model === "string" && device.model !== "" ? device.model : null;
    const locale = String(native.deviceInfo().locale || "");
    if (locale.indexOf("ko") === 0) return (model === null ? "이 기기" : model) + "에 암호화 키 공유 승인";
    if (locale.indexOf("ja") === 0) return (model === null ? "このデバイス" : model) + "への暗号化キー共有の承認";
    return "Approve sharing your encryption key with " + (model === null ? "this device" : model);
  }

  /** The approving device: after the device owner authentication, makes the code and the PAKE
   *  message, uploads the approval and shows the code. */
  async function approveTransfer(args) {
    if (transferRun === null || transferRun.role !== "approving" || transferRun.phase !== "pending_approval") {
      throw native.error("invalid_state", transferRun === null ? "none" : transferRun.phase);
    }
    if (typeof args.request_id === "string" && args.request_id !== transferRun.requestId) {
      throw native.error("invalid_state", "request");
    }
    await presentKeys();
    if (!(await native.deviceOwnerAuth(transferAuthReason(transferRun.device)))) throw native.error("auth_failed", "device owner authentication");
    const code = transferCode();
    const scalar = native.randomBytes(32);
    const yb = native.x25519(scalar, transferGenerator(transferRun.requestId, code));
    try {
      await api("PUT", TRANSFER_PATH + "/" + transferRun.requestId + "/approval", {
        yb: yb, device: transferRun.approver,
      });
    } catch (error) {
      if (error.code === "invalid_phase") {
        transferSettle("taken");
        return { transfer: transferView() };
      }
      if (error.code === "not_found") {
        transferSettle("expired");
        return { transfer: transferView() };
      }
      throw error;
    }
    transferRun.code = code;
    transferRun.scalar = scalar;
    transferRun.yb = yb;
    transferRun.phase = "approved";
    publishTransfer();
    transferLoop();
    return { transfer: transferView() };
  }

  /** The approving device: compares the reply of the requesting device with the confirmation tag
   *  (a mismatch is reported to the server as a failure) and uploads the master key sealed with the
   *  session key. */
  async function transferSeal(remote) {
    const run = transferRun;
    const ya = String(remote.ya);
    const sessionKey = transferSessionKey(native.x25519(run.scalar, ya), run.requestId, ya, run.yb);
    if (!equal(decode(transferTag(sessionKey, "request")), decode(String(remote.ta)))) {
      try {
        await api("POST", TRANSFER_PATH + "/" + run.requestId + "/fail", {});
      } catch (error) {
        native.log("transfer fail: " + failureCode(error));
      }
      transferSettle("failed", "code_mismatch");
      return;
    }
    const masterKey = readMasterKey();
    if (masterKey === null) {
      transferSettle("failed", "key_required");
      return;
    }
    const envelope = transferEnvelope(sessionKey, run.requestId, ya, run.yb);
    const ciphertext = native.aeadSeal({
      alg: envelope.alg, key: envelope.key, nonce: envelope.nonce, aad: envelope.aad, plaintext: masterKey,
    });
    await api("PUT", TRANSFER_PATH + "/" + run.requestId + "/envelope", {
      ciphertext: ciphertext, tb: transferTag(sessionKey, "approve"),
    });
    run.scalar = null;
    run.code = null;
    run.phase = "sealed";
    publishTransfer();
  }

  /** Both devices: ends the transfer in progress on the server (cancelled on the requesting device,
   *  declined on an approving device still waiting for the approval, cancelled on an approving
   *  device showing the code) and clears the state. A settled transfer only has its state cleared. */
  async function cancelTransfer() {
    if (transferRun === null) return {};
    if (!transferTerminal(transferRun.phase)) {
      const declined = transferRun.role === "approving" && transferRun.phase === "pending_approval";
      try {
        await api("DELETE", TRANSFER_PATH + "/" + transferRun.requestId, null,
          declined ? { reason: "declined" } : undefined);
      } catch (error) {
        if (error.code !== "not_found" && error.code !== "invalid_phase") throw error;
      }
    }
    resetTransfer();
    return {};
  }

  /** Both devices: advances one step now and starts the polling loop (retry from the screen, return
   *  to the foreground). */
  async function pollTransfer() {
    if (transferRun !== null && !transferTerminal(transferRun.phase)) {
      await transferStep();
      if (transferRun !== null && !transferTerminal(transferRun.phase)) transferLoop();
    }
    return { transfer: transferView() };
  }

  // ---- Registration ----

  globalThis.secureProgram = {
    version: VERSION,
    procedures: {
      sync: function () { return serial(sync); },
      create_key: function () { return serial(createKey); },
      reset_key: function () { return serial(resetKey); },
      begin_transfer: function () { return serial(beginTransfer); },
      enter_transfer_code: function (args) {
        return serial(function () { return enterTransferCode(args); });
      },
      approve_transfer: function (args) {
        return serial(function () { return approveTransfer(args); });
      },
      cancel_transfer: function () { return serial(cancelTransfer); },
      poll_transfer: function () { return serial(pollTransfer); },
      connect: function (args) { return serial(function () { return connect(args); }); },
      set_connection_writes: function (args) {
        return serial(function () { return setConnectionWrites(args); });
      },
      manage_repositories: function (args) {
        return serial(function () { return manageRepositories(args); });
      },
      begin_app_password_setup: function (args) {
        return serial(function () { return beginAppPasswordSetup(args); });
      },
      cancel_app_password_setup: function () { return serial(cancelAppPasswordSetup); },
      connect_app_password: function (args) {
        return serial(function () { return connectAppPassword(args); });
      },
      store_login: function (args) { return serial(function () { return storeLogin(args); }); },
      store_card: function (args) { return serial(function () { return storeCard(args); }); },
      read_log: function () { return serial(readLog); },
      read_log_page: function (args) {
        const before = logPageCursor(args.before_ms);
        if (before !== null) openLogPage(before);
        return serial(function () { return readLogPage(args); });
      },
      start_full_verification: function () { return serial(startFullVerification); },
      cancel_full_verification: function () { return serial(cancelFullVerification); },
      set_grant_days: function (args) { return serial(function () { return setGrantDays(args); }); },
      set_delegation: function (args) { return serial(function () { return setDelegation(args); }); },
    },
    onEvent: function (name, payload) {
      if (name === "session_ready") {
        // A new runtime does not take over the transfer of the previous runtime (the secrets exist
        // in the runtime only), nor a full verification in progress: the published states are
        // cleared.
        resetTransfer();
        fullState = null;
        publishFull();
        return serial(sync);
      }
      if (name === "foreground") return serial(sync);
      if (name === "push") {
        if (payload && payload.reason === "transfer_request") return serial(checkTransferRequests);
        return serial(sync);
      }
      if (name === "account_end") transferRun = null;
      if (name === "account_end" && payload &&
          (payload.reason === "account_deleted" || payload.reason === "dev_reset")) {
        // The deletion or reset of a runtime whose account mismatched does not erase the master key
        // of another account (the runtime goes down).
        if (accountMismatch) {
          accountMismatch = false;
          return undefined;
        }
        return serial(eraseAccountKeys);
      }
      return undefined;
    },
  };
})();
