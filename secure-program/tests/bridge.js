// The model of the bridge of the apps for the tests of the secure program. It gives the program
// the global `native` (the bridge primitive tables of docs/ssot/client/secure-executor.md of
// pickle-com/interactive-character) on the crypto module of Node, a device (the key store, the
// program store, the published state), the backend of the operator and the log store as the program
// reaches them over native.http, enclave nodes with their keys, attestation documents, commands,
// heads and log chains (docs/protocol.md sections 4, 5 and 7), and the loader that evaluates the
// program the way the executors do: in a fresh context whose globals are native, SecureError and
// console, with the bridge closed during the top-level evaluation and open after it.
//
// The crypto of this file is real (HKDF, Ed25519, X25519, HPKE of RFC 9180, ChaCha20-Poly1305,
// ECDSA P-384): program.test.js checks it against protocol/vectors.json. The certificate chain of
// a nitro document is modelled: x509Verify accepts the one leaf of the model (the SPKI of a P-384
// key stands for the certificate), and the signature of the document is a real ECDSA signature of
// that key over the Sig_structure the program encodes.
"use strict";

const crypto = require("node:crypto");
const vm = require("node:vm");

// ---- Bytes ----

/** Buffer -> base64url without padding (the byte representation of the bridge). */
function b64u(buffer) {
  return Buffer.from(buffer).toString("base64url");
}

/** base64url or standard base64 -> Buffer (the bridge accepts both). */
function bytes(value) {
  if (typeof value !== "string") throw new SecureError("invalid_argument", "bytes");
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, ""), "base64");
}

function utf8(text) {
  return Buffer.from(text, "utf8");
}

function concat(...parts) {
  return Buffer.concat(parts.map((part) => Buffer.from(part)));
}

// ---- Hashes ----

function sha(algorithm, data) {
  return crypto.createHash(algorithm).update(data).digest();
}

function hmac(algorithm, key, data) {
  return crypto.createHmac(algorithm, key).update(data).digest();
}

/** HKDF-Extract and HKDF-Expand (RFC 5869) with the hash named (sha256, sha384, sha512). */
function hkdfExtract(algorithm, salt, ikm) {
  return hmac(algorithm, salt.length === 0 ? Buffer.alloc(hashLength(algorithm)) : salt, ikm);
}

function hkdfExpand(algorithm, prk, info, length) {
  const out = [];
  let previous = Buffer.alloc(0);
  for (let counter = 1; Buffer.concat(out).length < length; counter += 1) {
    previous = hmac(algorithm, prk, concat(previous, info, Buffer.from([counter])));
    out.push(previous);
  }
  return Buffer.concat(out).subarray(0, length);
}

function hashLength(algorithm) {
  return { sha256: 32, sha384: 48, sha512: 64 }[algorithm];
}

// ---- Ed25519 and X25519 (raw keys through the DER prefixes of PKCS#8 and SPKI) ----

const ED25519_PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const X25519_PKCS8 = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI = Buffer.from("302a300506032b656e032100", "hex");

function privateKeyObject(prefix, raw) {
  return crypto.createPrivateKey({ key: concat(prefix, raw), format: "der", type: "pkcs8" });
}

function publicKeyObject(prefix, raw) {
  return crypto.createPublicKey({ key: concat(prefix, raw), format: "der", type: "spki" });
}

function rawPublicKey(privateKey) {
  return crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(12);
}

function ed25519PublicKey(seed) {
  return rawPublicKey(privateKeyObject(ED25519_PKCS8, seed));
}

function ed25519Sign(seed, message) {
  return crypto.sign(null, message, privateKeyObject(ED25519_PKCS8, seed));
}

function ed25519Verify(publicKey, message, signature) {
  try {
    return crypto.verify(null, message, publicKeyObject(ED25519_SPKI, publicKey), signature);
  } catch (error) {
    return false;
  }
}

function x25519PublicKey(privateKey) {
  return rawPublicKey(privateKeyObject(X25519_PKCS8, privateKey));
}

function x25519(privateKey, publicKey) {
  return crypto.diffieHellman({
    privateKey: privateKeyObject(X25519_PKCS8, privateKey),
    publicKey: publicKeyObject(X25519_SPKI, publicKey),
  });
}

// ---- AEAD and HPKE (RFC 9180, base mode) ----

const AEADS = {
  chacha20poly1305: { cipher: "chacha20-poly1305", id: 0x0003, keyLength: 32, nonceLength: 12 },
  aes128gcm: { cipher: "aes-128-gcm", id: 0x0001, keyLength: 16, nonceLength: 12 },
  aes256gcm: { cipher: "aes-256-gcm", id: 0x0002, keyLength: 32, nonceLength: 12 },
};

function aeadSeal(algorithm, key, nonce, aad, plaintext) {
  const aead = AEADS[algorithm];
  const cipher = crypto.createCipheriv(aead.cipher, key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  return concat(cipher.update(plaintext), cipher.final(), cipher.getAuthTag());
}

function aeadOpen(algorithm, key, nonce, aad, ciphertext) {
  const aead = AEADS[algorithm];
  if (ciphertext.length < 16) throw new SecureError("crypto_failed", "aead");
  const decipher = crypto.createDecipheriv(aead.cipher, key, nonce, { authTagLength: 16 });
  decipher.setAAD(aad, { plaintextLength: ciphertext.length - 16 });
  decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
  try {
    return concat(decipher.update(ciphertext.subarray(0, ciphertext.length - 16)), decipher.final());
  } catch (error) {
    throw new SecureError("crypto_failed", "aead");
  }
}

const KEM_X25519_ID = 0x0020;
const KDF_SHA256_ID = 0x0001;

function i2osp2(value) {
  return Buffer.from([value >> 8, value & 255]);
}

function labeledExtract(suiteId, salt, label, ikm) {
  return hkdfExtract("sha256", salt, concat(utf8("HPKE-v1"), suiteId, utf8(label), ikm));
}

function labeledExpand(suiteId, prk, label, info, length) {
  return hkdfExpand("sha256", prk, concat(i2osp2(length), utf8("HPKE-v1"), suiteId, utf8(label), info), length);
}

const KEM_SUITE = concat(utf8("KEM"), i2osp2(KEM_X25519_ID));

/** DeriveKeyPair of DHKEM(X25519, HKDF-SHA256): the private key from 32 bytes of keying material. */
function hpkeDeriveKeyPair(ikm) {
  const prk = labeledExtract(KEM_SUITE, Buffer.alloc(0), "dkp_prk", ikm);
  const privateKey = labeledExpand(KEM_SUITE, prk, "sk", Buffer.alloc(0), 32);
  return { privateKey: privateKey, publicKey: x25519PublicKey(privateKey) };
}

function hpkeSharedSecret(dh, kemContext) {
  const prk = labeledExtract(KEM_SUITE, Buffer.alloc(0), "eae_prk", dh);
  return labeledExpand(KEM_SUITE, prk, "shared_secret", kemContext, 32);
}

function hpkeKeySchedule(aead, sharedSecret, info) {
  const suiteId = concat(utf8("HPKE"), i2osp2(KEM_X25519_ID), i2osp2(KDF_SHA256_ID), i2osp2(aead.id));
  const pskIdHash = labeledExtract(suiteId, Buffer.alloc(0), "psk_id_hash", Buffer.alloc(0));
  const infoHash = labeledExtract(suiteId, Buffer.alloc(0), "info_hash", info);
  const context = concat(Buffer.from([0]), pskIdHash, infoHash);
  const secret = labeledExtract(suiteId, sharedSecret, "secret", Buffer.alloc(0));
  return {
    key: labeledExpand(suiteId, secret, "key", context, aead.keyLength),
    nonce: labeledExpand(suiteId, secret, "base_nonce", context, aead.nonceLength),
  };
}

/** The single-shot seal of HPKE base mode with DHKEM(X25519) and HKDF-SHA256. seed (32 bytes)
 *  fixes the ephemeral key pair (DeriveKeyPair); without it the pair is random. */
function hpkeSeal(aeadName, recipientPublicKey, info, aad, plaintext, seed) {
  const aead = AEADS[aeadName];
  const ephemeral = hpkeDeriveKeyPair(seed === undefined ? crypto.randomBytes(32) : seed);
  const dh = x25519(ephemeral.privateKey, recipientPublicKey);
  const shared = hpkeSharedSecret(dh, concat(ephemeral.publicKey, recipientPublicKey));
  const schedule = hpkeKeySchedule(aead, shared, info);
  return { enc: ephemeral.publicKey, ciphertext: aeadSeal(aeadName, schedule.key, schedule.nonce, aad, plaintext) };
}

function hpkeOpen(aeadName, recipientPrivateKey, enc, info, aad, ciphertext) {
  const aead = AEADS[aeadName];
  const dh = x25519(recipientPrivateKey, enc);
  const shared = hpkeSharedSecret(dh, concat(enc, x25519PublicKey(recipientPrivateKey)));
  const schedule = hpkeKeySchedule(aead, shared, info);
  return aeadOpen(aeadName, schedule.key, schedule.nonce, aad, ciphertext);
}

// ---- ECDSA P-384 and the model of the certificate of a nitro document ----

function x963Of(keyObject) {
  const jwk = keyObject.export({ format: "jwk" });
  return concat(Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url"));
}

function ecPublicKeyObject(curve, x963) {
  const size = (x963.length - 1) / 2;
  return crypto.createPublicKey({
    key: {
      kty: "EC", crv: curve,
      x: x963.subarray(1, 1 + size).toString("base64url"),
      y: x963.subarray(1 + size).toString("base64url"),
    },
    format: "jwk",
  });
}

/** The signer of nitro documents of this model: a P-384 key whose SPKI stands for the leaf
 *  certificate, a root and an intermediate that are opaque bytes. */
function makeNitroSigner() {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  return {
    privateKey: pair.privateKey,
    leaf: pair.publicKey.export({ format: "der", type: "spki" }),
    publicKey: x963Of(pair.publicKey),
    root: utf8("the root certificate of the model"),
    intermediate: utf8("the intermediate certificate of the model"),
  };
}

function ecdsaSignP384(privateKey, message) {
  return crypto.sign("sha384", message, { key: privateKey, dsaEncoding: "ieee-p1363" });
}

// ---- CBOR (the encoder of the attestation documents of the model: definite lengths) ----

function cborHead(major, argument) {
  const type = major << 5;
  if (argument < 24) return Buffer.from([type | argument]);
  if (argument < 0x100) return Buffer.from([type | 24, argument]);
  if (argument < 0x10000) return Buffer.from([type | 25, argument >> 8, argument & 255]);
  if (argument < 0x100000000) {
    const head = Buffer.alloc(5);
    head[0] = type | 26;
    head.writeUInt32BE(argument, 1);
    return head;
  }
  const head = Buffer.alloc(9);
  head[0] = type | 27;
  head.writeBigUInt64BE(BigInt(argument), 1);
  return head;
}

function cbor(value) {
  if (value === null) return Buffer.from([0xf6]);
  if (typeof value === "number") return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  if (typeof value === "string") {
    const encoded = utf8(value);
    return concat(cborHead(3, encoded.length), encoded);
  }
  if (Buffer.isBuffer(value)) return concat(cborHead(2, value.length), value);
  if (Array.isArray(value)) return concat(cborHead(4, value.length), ...value.map(cbor));
  if (value instanceof Map) {
    const parts = [cborHead(5, value.size)];
    for (const [key, item] of value) parts.push(cbor(key), cbor(item));
    return concat(...parts);
  }
  throw new Error("cbor: unsupported value");
}

// ---- The error type of the bridge ----

class SecureError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "SecureError";
    this.code = code;
  }
}

// ---- Signed values of the protocol ----

/** {body, sig}: the Ed25519 signature of seed over the purpose string (ending in a newline) and
 *  the UTF-8 JSON of the object. */
function signedValue(seed, purpose, object) {
  const body = utf8(JSON.stringify(object));
  return { body: b64u(body), sig: b64u(ed25519Sign(seed, concat(utf8(purpose), body))) };
}

/** The keys of an account as the program derives them from the master key (docs/protocol.md 3). */
function deriveAccountKeys(masterKey) {
  const info = (name) => utf8("pickle.secure.v1." + name);
  const signSeed = Buffer.from(crypto.hkdfSync("sha256", masterKey, Buffer.alloc(0), info("sign"), 32));
  const logSk = Buffer.from(crypto.hkdfSync("sha256", masterKey, Buffer.alloc(0), info("log"), 32));
  const signPk = ed25519PublicKey(signSeed);
  return {
    signSeed: signSeed, signPk: signPk, logSk: logSk, logPk: x25519PublicKey(logSk),
    keyId: sha("sha256", signPk).subarray(0, 8).toString("hex"),
  };
}

// ---- The world: the device, the backend of the operator, the log store and the nodes ----

const DAY_MS = 86400000;
const SEQ_DIGITS = 20;
const TIME_DIGITS = 13;

function zeros(value, digits) {
  return String(value).padStart(digits, "0");
}

/** One enclave node of the model: its keys, its release and measurement, the chains it wrote for
 *  the accounts and the grants it holds. The node id is the b64u of its signing public key. */
class Node {
  constructor(world, options) {
    this.world = world;
    this.release = options.release;
    this.measurement = options.measurement;
    // The log store the binding names: the store of the world unless the fixture names another
    // (or null for a binding without log).
    this.log = options.log === undefined ? { bucket: world.bucket, region: world.region } : options.log;
    // Whether the COSE signature of the attestation documents of this node is corrupted.
    this.brokenSignature = options.brokenSignature === true;
    this.alive = true;
    this.signSeed = crypto.randomBytes(32);
    this.signPk = ed25519PublicKey(this.signSeed);
    this.sealSk = crypto.randomBytes(32);
    this.sealPk = x25519PublicKey(this.sealSk);
    this.id = b64u(this.signPk);
    this.chains = new Map();
    this.grants = new Map();
    this.finalHeads = new Map();
    this.commands = [];
  }

  bindingObject() {
    const binding = { v: 1, sign: b64u(this.signPk), seal: b64u(this.sealPk), release: this.release };
    if (this.log !== null) binding.log = this.log;
    return binding;
  }

  /** The attestation response of this node for a request nonce (docs/protocol.md 4.2). */
  attestation(nonce) {
    const challenge = b64u(crypto.randomBytes(16));
    const pcrs = new Map();
    for (let index = 0; index < 16; index += 1) pcrs.set(index, Buffer.alloc(48));
    pcrs.set(0, Buffer.from(this.measurement.pcr0, "hex"));
    pcrs.set(1, Buffer.from(this.measurement.pcr1, "hex"));
    pcrs.set(2, Buffer.from(this.measurement.pcr2, "hex"));
    const payload = cbor(new Map([
      ["module_id", "i-0123456789abcdef0-enc0123456789abcde"],
      ["digest", "SHA384"],
      ["timestamp", this.world.now],
      ["pcrs", pcrs],
      ["certificate", this.world.nitro.leaf],
      ["cabundle", [this.world.nitro.root, this.world.nitro.intermediate]],
      ["public_key", null],
      ["user_data", utf8(JSON.stringify(this.bindingObject()))],
      ["nonce", bytes(nonce)],
    ]));
    const protectedHeader = cbor(new Map([[1, -35]]));
    const sigStructure = concat(
      Buffer.from([0x84]), cbor("Signature1"), cbor(protectedHeader), Buffer.from([0x40]), cbor(payload));
    const signature = ecdsaSignP384(this.world.nitro.privateKey, sigStructure);
    if (this.brokenSignature) signature[0] ^= 1;
    const document = cbor([protectedHeader, new Map(), payload, signature]);
    return {
      v: 1, platform: "nitro", document: b64u(document), node: this.id, challenge: challenge,
      release: this.release,
      challenge_statement: signedValue(this.signSeed, "pickle.secure.v1.challenge\n", {
        v: 1, type: "challenge", node: this.id, nonce: nonce, challenge: challenge, time_ms: this.world.now,
      }),
    };
  }

  reply(fields) {
    return signedValue(this.signSeed, "pickle.secure.v1.reply\n", Object.assign({ v: 1, node: this.id }, fields));
  }

  /** The command envelope of the app (docs/protocol.md 5): opened, verified, executed. */
  handleMessage(envelope) {
    const failure = (code) => this.reply({
      ok: false, code: code, type: "", user_id: "", challenge: "", key_id: "", time_ms: this.world.now,
    });
    let command = null;
    let payload = null;
    let signed = null;
    try {
      signed = JSON.parse(hpkeOpen(
        "chacha20poly1305", this.sealSk, bytes(envelope.enc), utf8("pickle.secure.v1.message"),
        utf8(this.id), bytes(envelope.ct)).toString("utf8"));
      payload = bytes(signed.payload);
      command = JSON.parse(payload.toString("utf8"));
    } catch (error) {
      return failure("open_failed");
    }
    const signPk = bytes(command.sign_pk);
    if (!ed25519Verify(signPk, concat(utf8("pickle.secure.v1.command\n"), payload), bytes(signed.sig))) {
      return failure("bad_signature");
    }
    const keyId = sha("sha256", signPk).subarray(0, 8).toString("hex");
    this.commands.push(command);
    const common = { user_id: command.user_id, challenge: command.challenge, key_id: keyId, time_ms: this.world.now };
    if (command.type === "grant") {
      const notAfter = Math.min(command.not_after_ms, this.world.now + 30 * DAY_MS);
      this.grants.set(command.user_id, {
        sign_pk: command.sign_pk, log_pk: command.log_pk, key_id: keyId, custody: command.custody,
        not_after_ms: notAfter,
      });
      this.appendEntry(command.user_id, "c", [
        { t: "grant_accepted", time_ms: this.world.now, not_after_ms: notAfter, custody: command.custody },
      ], { logPk: bytes(command.log_pk), keyId: keyId });
      return this.reply(Object.assign({ ok: true, type: "grant_reply", not_after_ms: notAfter }, common));
    }
    if (command.type === "revoke") {
      const grant = this.grants.get(command.user_id);
      this.grants.delete(command.user_id);
      if (grant !== undefined) {
        this.appendEntry(command.user_id, "c", [{ t: "grant_revoked", time_ms: this.world.now }],
          { logPk: bytes(grant.log_pk), keyId: grant.key_id });
      }
      return this.reply(Object.assign({ ok: true, type: "revoke_reply" }, common));
    }
    return failure("invalid_request");
  }

  /** Appends one entry of format 2 to the chain of user (docs/protocol.md 7.1) and writes its
   *  object to the log store unless options.stored is false (a pending entry: the gap of a chain).
   *  options: logPk and keyId of the grant the entry is sealed under, timeMs (the world time when
   *  absent), stored, hpkeSeed. */
  appendEntry(user, kind, events, options) {
    const chain = this.chains.get(user) || [];
    const seq = chain.length + 1;
    const prev = seq === 1 ? Buffer.alloc(32) : chain[chain.length - 1].entryHash;
    const timeMs = options.timeMs === undefined ? this.world.now : options.timeMs;
    const aad = utf8([this.id, user, options.keyId, String(seq)].join("\n"));
    const sealed = hpkeSeal(
      "chacha20poly1305", options.logPk, utf8("pickle.secure.v2.log-entry"), aad,
      utf8(JSON.stringify(events)), options.hpkeSeed);
    const body = utf8(JSON.stringify({
      v: 2, node: this.id, user_id: user, key_id: options.keyId, seq: seq, prev: b64u(prev),
      time_ms: timeMs, kind: kind, count: events.length, enc: b64u(sealed.enc), ct: b64u(sealed.ciphertext),
    }));
    const sig = ed25519Sign(this.signSeed, concat(utf8("pickle.secure.v2.log-entry\n"), body));
    const bodyHash = sha("sha256", body);
    const fields = [zeros(seq, SEQ_DIGITS), zeros(timeMs, TIME_DIGITS), kind, zeros(events.length, 3), options.keyId].join("-");
    const entryHash = sha("sha256", concat(utf8("pickle.secure.v2.log-chain\n"), prev, bodyHash, utf8(fields)));
    const entry = {
      seq: seq, time_ms: timeMs, kind: kind, events: events, body: body, bodyHash: bodyHash,
      entryHash: entryHash,
      key: "v1/accounts/" + user + "/" + this.id + "/" + fields + "-" + b64u(bodyHash) + "-" + b64u(entryHash),
      object: JSON.stringify({ body: b64u(body), sig: b64u(sig) }),
    };
    chain.push(entry);
    this.chains.set(user, chain);
    if (options.stored !== false) this.world.putObject(entry.key, entry.object);
    return entry;
  }

  /** The signed head of the chain of user (docs/protocol.md 7.3). */
  head(user, nonce, final) {
    const chain = this.chains.get(user) || [];
    const last = chain.length === 0 ? null : chain[chain.length - 1];
    return signedValue(this.signSeed, "pickle.secure.v1.head\n", {
      v: 1, type: "head", node: this.id, user_id: user, seq: last === null ? 0 : last.seq,
      hash: b64u(last === null ? Buffer.alloc(32) : last.entryHash), nonce: final ? "" : nonce,
      time_ms: this.world.now, final: final,
    });
  }

  /** The orderly shutdown of the node: a final head per account, and the node is gone. */
  shutDown() {
    for (const user of this.chains.keys()) this.finalHeads.set(user, this.head(user, "", true));
    this.alive = false;
  }
}

/** The device, the backend of the operator, the log store and the nodes of one account. */
class World {
  constructor(options) {
    const given = options || {};
    this.userId = given.userId || "user-7f3a";
    this.serverTarget = given.serverTarget || "prod";
    this.bucket = "character-credential-log-" + this.serverTarget + "-1";
    this.region = "us-west-2";
    this.now = given.now || 1790000000000;
    this.nitro = makeNitroSigner();
    this.keychain = new Map();
    this.store = new Map();
    this.state = {};
    this.runtime = {};
    this.logs = [];
    this.reports = [];
    this.requests = [];
    this.account = { key: null, keys: null };
    this.nodes = new Map();
    this.objects = new Map();
    this.versionCounter = 0;
    this.bridgeOpen = false;
  }

  get storeHost() {
    return this.bucket + ".s3." + this.region + ".amazonaws.com";
  }

  advance(ms) {
    this.now += ms;
  }

  /** A master key in the key store of the device and the registration of its keys on the account
   *  (the state of a device whose key state is present). */
  createAccount() {
    const masterKey = crypto.randomBytes(32);
    this.keychain.set("com.pickle.client.secure.master-key\n" + this.userId,
      { value: b64u(masterKey), synchronizable: true });
    const keys = deriveAccountKeys(masterKey);
    this.account.keys = keys;
    this.account.key = { sign_pk: b64u(keys.signPk), log_pk: b64u(keys.logPk), key_id: keys.keyId };
    return keys;
  }

  addNode(options) {
    const node = new Node(this, options);
    this.nodes.set(node.id, node);
    return node;
  }

  offeredNodes() {
    return Array.from(this.nodes.values()).filter((node) => node.alive);
  }

  putObject(key, body) {
    this.versionCounter += 1;
    const versions = this.objects.get(key) || [];
    versions.unshift({ versionId: "v" + zeros(this.versionCounter, 6), body: body });
    this.objects.set(key, versions);
  }

  /** The node ledger as the program stored it in the device copy (null when none). */
  ledger() {
    const json = this.store.get("ledger");
    return json === undefined ? null : JSON.parse(json);
  }

  // ---- The backend of the operator (native.http with path) ----

  listingUrl(options) {
    const prefix = "v1/accounts/" + this.userId + "/" + (options.node ? options.node + "/" : "");
    let query = "versions&prefix=" + encodeURIComponent(prefix);
    if (options.nodes) query += "&delimiter=" + encodeURIComponent("/");
    if (options.keyMarker) query += "&key-marker=" + encodeURIComponent(options.keyMarker);
    if (options.versionIdMarker) query += "&version-id-marker=" + encodeURIComponent(options.versionIdMarker);
    query += "&max-keys=1000&encoding-type=url&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=" +
      crypto.randomBytes(8).toString("hex");
    return "https://" + this.storeHost + "/?" + query;
  }

  objectUrl(key, versionId) {
    return "https://" + this.storeHost + "/" + encodeURIComponent(key) + "?versionId=" +
      encodeURIComponent(versionId) + "&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=" +
      crypto.randomBytes(8).toString("hex");
  }

  api(method, path, query, bodyText) {
    const json = (status, value) => ({ status: status, headers: {}, body: JSON.stringify(value), bodyBase64: null });
    const body = typeof bodyText === "string" && bodyText !== "" ? JSON.parse(bodyText) : null;
    if (method === "GET" && path === "/api/secure/account") {
      return json(200, { user_id: this.userId, key: this.account.key === null ? null : { key_id: this.account.key.key_id } });
    }
    if (method === "PUT" && path === "/api/secure/account/key") {
      const signPk = bytes(body.sign_pk);
      const proof = ed25519Verify(signPk, utf8("pickle.secure.v1.register\n" + this.userId), bytes(body.proof));
      if (!proof) return json(400, { code: "invalid_input" });
      if (this.account.key !== null && body.replace !== true) return json(409, { code: "key_exists" });
      this.account.key = { sign_pk: body.sign_pk, log_pk: body.log_pk, key_id: sha("sha256", signPk).subarray(0, 8).toString("hex") };
      return json(200, {});
    }
    if (method === "GET" && path === "/api/secure/nodes") {
      if (typeof query.nonce !== "string") return json(400, { code: "invalid_input" });
      return json(200, {
        nodes: this.offeredNodes().map((node, index) => Object.assign(node.attestation(query.nonce), { pod: index })),
      });
    }
    const nodeRoute = /^\/api\/secure\/nodes\/([A-Za-z0-9_-]{43})\/(messages|status)$/.exec(path);
    if (nodeRoute !== null && method === "POST") {
      const node = this.nodes.get(nodeRoute[1]);
      if (node === undefined || !node.alive) return json(404, { code: "node_not_found" });
      if (nodeRoute[2] === "messages") return json(200, { reply: node.handleMessage(body.envelope) });
      return json(200, { head: node.head(this.userId, body.nonce, false) });
    }
    if (method === "GET" && path === "/api/secure/log/nodes") {
      const nodes = [];
      for (const node of this.nodes.values()) {
        const chain = node.chains.get(this.userId);
        if (chain === undefined && !node.finalHeads.has(this.userId)) continue;
        nodes.push({
          node: node.id, release: node.release, live: node.alive,
          max_seq: chain === undefined ? 0 : chain.length,
          final_head: node.finalHeads.get(this.userId) || null,
        });
      }
      return json(200, { nodes: nodes });
    }
    if (method === "POST" && path === "/api/secure/log/store/listings") {
      return json(200, {
        discovery: body.discovery ? { list_url: this.listingUrl({ nodes: true }) } : null,
        nodes: (body.nodes || []).map((target) => ({
          node: target.node,
          list_url: this.listingUrl({
            node: target.node, keyMarker: target.key_marker, versionIdMarker: target.version_id_marker,
          }),
        })),
      });
    }
    if (method === "GET" && path === "/api/secure/log/store") {
      return json(200, {
        list_url: this.listingUrl({
          nodes: query.nodes === "1", node: query.node || null, keyMarker: query.key_marker || null,
          versionIdMarker: query.version_id_marker || null,
        }),
      });
    }
    if (method === "POST" && path === "/api/secure/log/store/objects") {
      return json(200, {
        objects: body.objects.map((item) => ({
          key: item.key, version_id: item.version_id, url: this.objectUrl(item.key, item.version_id),
        })),
      });
    }
    if (method === "POST" && path === "/api/secure/log/verified") {
      this.reports.push(body);
      return json(200, {});
    }
    if (method === "GET" && path === "/api/secure/sealing") return json(200, { items: [], more: false });
    if (method === "GET" && path === "/api/secure/transfers") return json(200, { transfers: [] });
    return json(404, { code: "not_found" });
  }

  // ---- The log store (native.http with url) ----

  storeHttp(method, url) {
    const address = new URL(url);
    const text = (status, body) => ({ status: status, headers: {}, body: body, bodyBase64: null });
    if (method !== "GET" || address.host !== this.storeHost) return text(403, "");
    if (address.pathname === "/" && address.searchParams.has("versions")) {
      return text(200, this.listing(address.searchParams));
    }
    const key = decodeURIComponent(address.pathname.slice(1));
    const versionId = address.searchParams.get("versionId");
    const version = (this.objects.get(key) || []).find((item) => item.versionId === versionId);
    return version === undefined ? text(404, "") : text(200, version.body);
  }

  listing(params) {
    const prefix = params.get("prefix") || "";
    const delimiter = params.get("delimiter");
    const keyMarker = params.get("key-marker");
    const keys = Array.from(this.objects.keys())
      .filter((key) => key.startsWith(prefix) && (keyMarker === null || key > keyMarker))
      .sort();
    const parts = [
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
      "<ListVersionsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
      "<Name>" + this.bucket + "</Name><Prefix>" + encodeURIComponent(prefix) + "</Prefix>",
      "<MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><EncodingType>url</EncodingType>",
    ];
    if (delimiter !== null) {
      const prefixes = new Set();
      for (const key of keys) {
        const rest = key.slice(prefix.length);
        const at = rest.indexOf(delimiter);
        if (at >= 0) prefixes.add(prefix + rest.slice(0, at + delimiter.length));
      }
      for (const common of prefixes) {
        parts.push("<CommonPrefixes><Prefix>" + encodeURIComponent(common) + "</Prefix></CommonPrefixes>");
      }
    } else {
      for (const key of keys) {
        const versions = this.objects.get(key);
        versions.forEach((version, index) => {
          parts.push(
            "<Version><Key>" + encodeURIComponent(key) + "</Key><VersionId>" + version.versionId +
            "</VersionId><IsLatest>" + (index === 0 ? "true" : "false") + "</IsLatest>" +
            "<LastModified>2026-11-05T00:00:00.000Z</LastModified><Size>" + version.body.length + "</Size></Version>");
        });
      }
    }
    parts.push("</ListVersionsResult>");
    return parts.join("");
  }

  http(request) {
    this.requests.push(request);
    const method = request.method || "GET";
    if (typeof request.path === "string") return this.api(method, request.path, request.query || {}, request.body);
    if (typeof request.url === "string") return this.storeHttp(method, request.url);
    throw new SecureError("invalid_argument", "http: neither path nor url");
  }
}

// ---- The bridge ----

function keychainName(item) {
  const service = String(item.service);
  if (service !== "com.pickle.client.secure" && !service.startsWith("com.pickle.client.secure.")) {
    throw new SecureError("invalid_argument", "keychain service");
  }
  return service + "\n" + String(item.account);
}

/** The global native of one runtime on world: every function of the four bridge tables that the
 *  flows of the tests reach, and a stub that fails with invalid_argument for the ones they do not
 *  (the hardware key of the device, RSA, the web authentication session, the owner authentication).
 *  While world.bridgeOpen is false (the top-level evaluation) every call fails with cancelled. */
function makeNative(world) {
  const functions = {
    randomBytes: (n) => b64u(crypto.randomBytes(n)),
    sha256: (data) => b64u(sha("sha256", bytes(data))),
    sha384: (data) => b64u(sha("sha384", bytes(data))),
    sha512: (data) => b64u(sha("sha512", bytes(data))),
    hmac: (hash, key, data) => b64u(hmac(hash, bytes(key), bytes(data))),
    hkdf: (hash, ikm, salt, info, length) => b64u(Buffer.from(crypto.hkdfSync(
      hash, bytes(ikm), salt === null || salt === undefined ? Buffer.alloc(0) : bytes(salt),
      info === null || info === undefined ? Buffer.alloc(0) : bytes(info), length))),
    x25519PublicKey: (privateKey) => b64u(x25519PublicKey(bytes(privateKey))),
    x25519: (privateKey, publicKey) => b64u(x25519(bytes(privateKey), bytes(publicKey))),
    ed25519PublicKey: (seed) => b64u(ed25519PublicKey(bytes(seed))),
    ed25519Sign: (seed, message) => b64u(ed25519Sign(bytes(seed), bytes(message))),
    ed25519Verify: (publicKey, message, signature) => ed25519Verify(bytes(publicKey), bytes(message), bytes(signature)),
    ecdsaVerify: (args) => {
      try {
        const curve = { p256: "P-256", p384: "P-384", p521: "P-521" }[args.curve];
        const hash = { sha256: "sha256", sha384: "sha384", sha512: "sha512" }[args.hash];
        return crypto.verify(hash, bytes(args.message), {
          key: ecPublicKeyObject(curve, bytes(args.publicKey)),
          dsaEncoding: args.format === "der" ? "der" : "ieee-p1363",
        }, bytes(args.signature));
      } catch (error) {
        return false;
      }
    },
    aeadSeal: (args) => b64u(aeadSeal(args.alg, bytes(args.key), bytes(args.nonce),
      args.aad === null || args.aad === undefined ? Buffer.alloc(0) : bytes(args.aad), bytes(args.plaintext))),
    aeadOpen: (args) => b64u(aeadOpen(args.alg, bytes(args.key), bytes(args.nonce),
      args.aad === null || args.aad === undefined ? Buffer.alloc(0) : bytes(args.aad), bytes(args.ciphertext))),
    hpkeSeal: (args) => {
      if (args.kem !== "x25519" || args.kdf !== "sha256") throw new SecureError("invalid_argument", "hpke suite");
      const sealed = hpkeSeal(args.aead, bytes(args.recipientPublicKey), bytes(args.info),
        args.aad === null || args.aad === undefined ? Buffer.alloc(0) : bytes(args.aad), bytes(args.plaintext));
      return { enc: b64u(sealed.enc), ciphertext: b64u(sealed.ciphertext) };
    },
    hpkeOpen: (args) => {
      if (args.kem !== "x25519" || args.kdf !== "sha256") throw new SecureError("invalid_argument", "hpke suite");
      return b64u(hpkeOpen(args.aead, bytes(args.recipientPrivateKey), bytes(args.enc), bytes(args.info),
        args.aad === null || args.aad === undefined ? Buffer.alloc(0) : bytes(args.aad), bytes(args.ciphertext)));
    },
    x509Verify: (args) => {
      const trusted = Array.isArray(args.anchors) && args.anchors.length > 0 &&
        bytes(args.leaf).equals(world.nitro.leaf) &&
        Number.isSafeInteger(args.atEpochS) && args.atEpochS >= 0;
      return trusted ? { ok: true, error: null } : { ok: false, error: "the leaf is not the certificate of the model" };
    },
    x509PublicKey: (certificate) => {
      if (!bytes(certificate).equals(world.nitro.leaf)) throw new SecureError("invalid_argument", "certificate");
      return { algorithm: "ec", bits: 384, publicKey: b64u(world.nitro.publicKey) };
    },
    secureEnclaveAvailable: () => false,
    keychainGet: (item) => {
      const kept = world.keychain.get(keychainName(item));
      if (kept === undefined) return null;
      if (item.synchronizable !== undefined && kept.synchronizable !== item.synchronizable) return null;
      return kept.value;
    },
    keychainSet: (item) => {
      world.keychain.set(keychainName(item), { value: String(item.value), synchronizable: item.synchronizable === true });
    },
    keychainDelete: (item) => world.keychain.delete(keychainName(item)),
    nowMs: () => world.now,
    deviceInfo: () => ({
      platform: "ios", app_version: "1.1.0", app_build: "1", system_version: "26.0", model: "iPhone",
      server_target: world.serverTarget, user_id: world.userId, program_origin: "server",
      locale: "en-US", debug_build: false,
    }),
    log: (message) => { world.logs.push(String(message)); },
    storeGet: (key) => { const value = world.store.get(String(key)); return value === undefined ? null : value; },
    storeSet: (key, value) => {
      if (typeof value === "string") world.store.set(String(key), value);
      else world.store.delete(String(key));
    },
    publish: (object) => {
      for (const tree of ["state", "runtime"]) {
        const given = object === null || typeof object !== "object" ? null : object[tree];
        if (given === null || typeof given !== "object") continue;
        for (const key of Object.keys(given)) {
          if (given[key] === null) delete world[tree][key];
          else world[tree][key] = JSON.parse(JSON.stringify(given[key]));
        }
      }
    },
    error: (code, message) => new SecureError(code, message),
  };
  const asyncFunctions = {
    http: async (request) => world.http(request),
    sleep: (ms) => new Promise((resolve) => setImmediate(resolve)),
  };
  const stubs = ["rsaVerify", "secureEnclaveP256Create", "secureEnclaveP256PublicKey", "secureEnclaveP256Sign"];
  const asyncStubs = ["webAuth", "deviceOwnerAuth"];
  const native = {};
  const closed = (name) => new SecureError("cancelled", name + ": the bridge is not open");
  for (const name of Object.keys(functions)) {
    native[name] = function () {
      if (!world.bridgeOpen) throw closed(name);
      return functions[name].apply(null, arguments);
    };
  }
  for (const name of Object.keys(asyncFunctions)) {
    native[name] = function () {
      if (!world.bridgeOpen) return Promise.reject(closed(name));
      return asyncFunctions[name].apply(null, arguments);
    };
  }
  for (const name of stubs) {
    native[name] = function () {
      if (!world.bridgeOpen) throw closed(name);
      throw new SecureError("invalid_argument", name + " is not part of the model");
    };
  }
  for (const name of asyncStubs) {
    native[name] = function () {
      return Promise.reject(world.bridgeOpen ? new SecureError("invalid_argument", name + " is not part of the model") : closed(name));
    };
  }
  return Object.freeze(native);
}

/** Evaluates the program source as a runtime on world: a fresh context with the globals native,
 *  SecureError and console, the top level evaluated with the bridge closed, and the global
 *  secureProgram returned once the bridge is open. The runtime tree of the published state starts
 *  empty (a new runtime); the state tree and the stores of the device stay (the executor keeps them
 *  across runtimes). */
function loadProgram(source, world) {
  world.bridgeOpen = false;
  world.runtime = {};
  const native = makeNative(world);
  const context = vm.createContext({
    native: native, SecureError: SecureError, console: { log: (message) => native.log(message) },
  });
  vm.runInContext(source, context, { filename: "secure-program.js" });
  const program = context.secureProgram;
  if (program === null || typeof program !== "object" || typeof program.procedures !== "object") {
    throw new Error("the program did not define secureProgram.procedures");
  }
  world.bridgeOpen = true;
  return program;
}

/** The measurements of ACCEPTED_RELEASES of a program source, in the order of the list. */
function listedMeasurements(source) {
  const start = source.indexOf("const ACCEPTED_RELEASES = [");
  const end = source.indexOf("];", start);
  const pattern = /release: "([^"]+)",\s*pcr0: "([0-9a-f]{96})",\s*pcr1: "([0-9a-f]{96})",\s*pcr2: "([0-9a-f]{96})"/g;
  const out = [];
  let match = pattern.exec(source.slice(start, end));
  while (match !== null) {
    out.push({ release: match[1], pcr0: match[2], pcr1: match[3], pcr2: match[4] });
    match = pattern.exec(source.slice(start, end));
  }
  return out;
}

/** The version a program source declares (const VERSION = N;). */
function declaredVersion(source) {
  const match = /^\s*const VERSION = (\d+);/m.exec(source);
  return match === null ? 0 : Number(match[1]);
}

/** A measurement no list has. */
function randomMeasurement() {
  return {
    pcr0: crypto.randomBytes(48).toString("hex"),
    pcr1: crypto.randomBytes(48).toString("hex"),
    pcr2: crypto.randomBytes(48).toString("hex"),
  };
}

/** The source of a later program: the same program with one more accepted release and the version
 *  given (the program the operator serves once it lists the release). */
function withListedRelease(source, release, measurement, version) {
  const start = source.indexOf("const ACCEPTED_RELEASES = [");
  const end = source.indexOf("  ];", start);
  const element = "    {\n      release: \"" + release + "\",\n      pcr0: \"" + measurement.pcr0 +
    "\",\n      pcr1: \"" + measurement.pcr1 + "\",\n      pcr2: \"" + measurement.pcr2 +
    "\",\n      log_store: true,\n    },\n";
  const patched = source.slice(0, end) + element + source.slice(end);
  return patched.replace(/^\s*const VERSION = \d+;/m, "  const VERSION = " + version + ";");
}

module.exports = {
  b64u, bytes, utf8, concat, sha, hmac, hkdfExtract, hkdfExpand,
  ed25519PublicKey, ed25519Sign, ed25519Verify, x25519PublicKey, x25519,
  aeadSeal, aeadOpen, hpkeSeal, hpkeOpen, hpkeDeriveKeyPair,
  cbor, SecureError, signedValue, deriveAccountKeys,
  Node, World, makeNative, loadProgram, listedMeasurements, declaredVersion, randomMeasurement,
  withListedRelease, DAY_MS,
};
