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
const RTIME_MAX = 9999999999999;

// The buckets of format 3 per server target (docs/protocol.md 7.6): the number of buckets, and the
// name of the log store (the bucket the binding of a node names) the bucket names are made from.
const SHARDS = {
  prod: { count: 1024, base: "character-credential-log-prod-1" },
  dev: { count: 32, base: "character-credential-log-dev-1" },
  alpha: { count: 32, base: "character-credential-log-alpha-1" },
  local: { count: 4, base: "character-credential-log-local-1" },
};

function zeros(value, digits) {
  return String(value).padStart(digits, "0");
}

/** The name of the bucket of format 3 that holds the objects of owner in the log store of env. */
function shardBucket(env, owner) {
  const shards = SHARDS[env];
  const index = sha("sha256", utf8(owner)).readUInt16BE(0) % shards.count;
  const tail = shards.base + "-" + zeros(index, 4);
  return sha("sha256", utf8(tail)).subarray(0, 4).toString("hex") + "-" + tail;
}

/** Whether a release writes format 3 (from v2.4.0 on). */
function writesFormat3(release) {
  const match = /^v(\d+)\.(\d+)\.(\d+)/.exec(release);
  if (match === null) return false;
  const major = Number(match[1]);
  return major > 2 || (major === 2 && Number(match[2]) >= 4);
}

/** One enclave node of the model: its keys, its release and measurement, the entries it wrote for
 *  the accounts and the grants it holds. The node id is the b64u of its signing public key. A node
 *  of a release from v2.4.0 on writes format 3 and its node document; a node of an earlier release
 *  writes a chain of format 2 into the bucket its binding names. */
class Node {
  constructor(world, options) {
    this.world = world;
    this.release = options.release;
    this.measurement = options.measurement;
    this.platform = options.platform || "nitro";
    this.format = options.format || (writesFormat3(options.release) ? 3 : 2);
    this.role = options.role;
    // The lowest version of the program whose grant command the node takes (the program_min of
    // its binding); undefined for a binding that states none.
    this.programMin = options.programMin;
    // The release proofs the node document of this node carries (release_proofs); undefined for
    // a document without them.
    this.documentProofs = options.documentProofs;
    // The log store the binding names: the store of the world unless the fixture names another
    // (or null for a binding without log).
    this.log = options.log === undefined ? { bucket: world.bucket, region: world.region } : options.log;
    // Whether the COSE signature of the attestation documents of this node is corrupted.
    this.brokenSignature = options.brokenSignature === true;
    // Whether the backend names this node in the list of nodes of the account.
    this.offered = options.offered !== false;
    this.alive = true;
    this.signSeed = options.signSeed || crypto.randomBytes(32);
    this.signPk = ed25519PublicKey(this.signSeed);
    this.sealSk = crypto.randomBytes(32);
    this.sealPk = x25519PublicKey(this.sealSk);
    this.id = b64u(this.signPk);
    this.chains = new Map();
    this.last = new Map();
    this.grants = new Map();
    this.finalHeads = new Map();
    this.commands = [];
    this.attestations = 0;
    // Whether the node takes a grant (false: its reply is a failure the node signed).
    this.refuses = null;
    if (this.format === 3 && options.document !== false) this.writeDocument();
  }

  bindingObject() {
    const binding = { v: 1, sign: b64u(this.signPk), seal: b64u(this.sealPk), release: this.release };
    if (this.log !== null) binding.log = this.log;
    if (this.role !== undefined) binding.role = this.role;
    if (this.programMin !== undefined) binding.program_min = this.programMin;
    return binding;
  }

  /** The document of the platform over the binding of this node and nonce (bytes). */
  platformDocument(nonce) {
    if (this.platform === "local") {
      return utf8(JSON.stringify({
        v: 1, platform: "local", binding: b64u(utf8(JSON.stringify(this.bindingObject()))),
        nonce: b64u(nonce), time_ms: this.world.now,
      }));
    }
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
      ["nonce", Buffer.from(nonce)],
    ]));
    const protectedHeader = cbor(new Map([[1, -35]]));
    const sigStructure = concat(
      Buffer.from([0x84]), cbor("Signature1"), cbor(protectedHeader), Buffer.from([0x40]), cbor(payload));
    const signature = ecdsaSignP384(this.world.nitro.privateKey, sigStructure);
    if (this.brokenSignature) signature[0] ^= 1;
    return cbor([protectedHeader, new Map(), payload, signature]);
  }

  /** The attestation response of this node for a request nonce (docs/protocol.md 4.2). */
  attestation(nonce) {
    this.attestations += 1;
    const challenge = b64u(crypto.randomBytes(16));
    return {
      v: 1, platform: this.platform, document: b64u(this.platformDocument(bytes(nonce))), node: this.id,
      challenge: challenge, release: this.release,
      challenge_statement: signedValue(this.signSeed, "pickle.secure.v1.challenge\n", {
        v: 1, type: "challenge", node: this.id, nonce: nonce, challenge: challenge, time_ms: this.world.now,
      }),
    };
  }

  /** The node document as the node writes it to the log store (docs/protocol.md 7.7). */
  documentObject() {
    const nonce = sha("sha256", concat(utf8("pickle.secure.v3.node-document\n"), this.signPk));
    const object = {
      v: 1, platform: this.platform, document: b64u(this.platformDocument(nonce)), node: this.id,
      release: this.release,
    };
    if (this.documentProofs !== undefined) object.release_proofs = this.documentProofs;
    return object;
  }

  writeDocument() {
    this.world.putObject(shardBucket(this.world.serverTarget, this.id), "n3/" + this.id, JSON.stringify(this.documentObject()));
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
      if (this.refuses !== null) {
        return this.reply(Object.assign({ ok: false, code: this.refuses, type: "grant_reply", not_after_ms: 0 }, common));
      }
      const notAfter = Math.min(command.not_after_ms, this.world.now + 30 * DAY_MS);
      const held = this.grants.get(command.user_id);
      // A node of format 3 writes no entry for a grant that renews the one it holds.
      const renewal = this.format === 3 && held !== undefined && held.sign_pk === command.sign_pk &&
        held.not_after_ms > this.world.now;
      this.grants.set(command.user_id, {
        sign_pk: command.sign_pk, log_pk: command.log_pk, key_id: keyId, custody: command.custody,
        not_after_ms: notAfter,
      });
      if (!renewal) {
        this.write(command.user_id, "c", [
          { t: "grant_accepted", time_ms: this.world.now, not_after_ms: notAfter, custody: command.custody },
        ], { logPk: bytes(command.log_pk), keyId: keyId });
      }
      return this.reply(Object.assign({ ok: true, type: "grant_reply", not_after_ms: notAfter }, common));
    }
    if (command.type === "revoke") {
      const grant = this.grants.get(command.user_id);
      this.grants.delete(command.user_id);
      if (grant !== undefined) {
        this.write(command.user_id, "c", [{ t: "grant_revoked", time_ms: this.world.now }],
          { logPk: bytes(grant.log_pk), keyId: grant.key_id });
      }
      return this.reply(Object.assign({ ok: true, type: "revoke_reply" }, common));
    }
    return failure("invalid_request");
  }

  /** Writes one entry in the format of this node. */
  write(user, kind, events, options) {
    return this.format === 3 ? this.appendEntry3(user, kind, events, options) : this.appendEntry(user, kind, events, options);
  }

  /** Writes an entry of the kind given for the account of the world, sealed to its key. */
  record(kind, events, options) {
    const keys = this.world.account.keys;
    return this.write(this.world.userId, kind, events, Object.assign({ logPk: keys.logPk, keyId: keys.keyId }, options || {}));
  }

  /** Appends one entry of format 3 (docs/protocol.md 7.1 and 7.6) and writes its object to the
   *  bucket of the account unless options.stored is false. options: logPk and keyId of the grant
   *  the entry is sealed under, timeMs (the world time when absent), stored, seq (the seq of the
   *  entry when the fixture writes a second entry under a seq), signSeed (another signing key:
   *  an object the node did not sign), key (the name the object is written under). */
  appendEntry3(user, kind, events, options) {
    const last = this.last.get(user) || { seq: 0, bodyHash: Buffer.alloc(32) };
    const seq = options.seq === undefined ? last.seq + 1 : options.seq;
    const timeMs = options.timeMs === undefined ? this.world.now : options.timeMs;
    const aad = utf8([this.id, user, options.keyId, String(seq)].join("\n"));
    const sealed = hpkeSeal(
      "chacha20poly1305", options.logPk, utf8("pickle.secure.v3.log-entry"), aad, utf8(JSON.stringify(events)));
    const body = utf8(JSON.stringify({
      v: 3, node: this.id, user_id: user, key_id: options.keyId, seq: seq, prev: b64u(last.bodyHash),
      time_ms: timeMs, kind: kind, count: events.length, enc: b64u(sealed.enc), ct: b64u(sealed.ciphertext),
    }));
    const sig = ed25519Sign(options.signSeed || this.signSeed, concat(utf8("pickle.secure.v3.log-entry\n"), body));
    const bodyHash = sha("sha256", body);
    const label = kind === "c" ? events[0].t : String(events.length);
    const key = options.key || "a3/" + user + "/" + kind + "/" + zeros(RTIME_MAX - timeMs, 13) + "." + this.id + "." +
      seq + "." + label + "." + options.keyId + "." + b64u(bodyHash);
    const entry = {
      seq: seq, time_ms: timeMs, kind: kind, events: events, body: body, bodyHash: bodyHash, key: key,
      object: JSON.stringify({ body: b64u(body), sig: b64u(sig) }),
    };
    if (options.seq === undefined) this.last.set(user, { seq: seq, bodyHash: bodyHash });
    const chain = this.chains.get(user) || [];
    chain.push(entry);
    this.chains.set(user, chain);
    if (options.stored !== false) this.world.putObject(shardBucket(this.world.serverTarget, user), key, entry.object);
    return entry;
  }

  /** Appends one entry of format 2 to the chain of user (docs/protocol.md 7.1) and writes its
   *  object to the bucket the binding names unless options.stored is false. */
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
    if (options.stored !== false) this.world.putObject(this.world.bucket, entry.key, entry.object);
    return entry;
  }

  /** The signed head of the chain of user (docs/protocol.md 7.3), as a node before v2.4.0 signs it. */
  head(user, nonce, final) {
    const chain = this.chains.get(user) || [];
    const last = chain.length === 0 ? null : chain[chain.length - 1];
    return signedValue(this.signSeed, "pickle.secure.v1.head\n", {
      v: 1, type: "head", node: this.id, user_id: user, seq: last === null ? 0 : last.seq,
      hash: b64u(last === null ? Buffer.alloc(32) : last.entryHash), nonce: final ? "" : nonce,
      time_ms: this.world.now, final: final,
    });
  }

  /** The orderly shutdown of the node: a final head per account for a node before v2.4.0, and the
   *  node is gone. */
  shutDown() {
    if (this.format !== 3) {
      for (const user of this.chains.keys()) this.finalHeads.set(user, this.head(user, "", true));
    }
    this.alive = false;
  }
}

/** The device, the backend of the operator, the log store and the nodes of one account. Time is
 *  the time of the model: native.nowMs reads it, native.sleep waits on it, and run and settle move
 *  it on when nothing else is left to happen. */
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
    this.outcomeReports = [];
    this.syncReports = [];
    this.securityStatuses = [];
    this.requests = [];
    // How often the program asked the bridge for the device (native.deviceInfo, a synchronous call).
    this.deviceInfoCalls = 0;
    // The account: its registered key, and what the backend says of the program it serves
    // (servedProgram: the value of served_program_version in the answer of the account query;
    // undefined for a backend that names none).
    this.account = { key: null, keys: null, servedProgram: undefined };
    this.nodes = new Map();
    this.buckets = new Map();
    this.versionCounter = 0;
    this.bridgeOpen = false;
    this.timers = [];
    this.pageSize = 1000;
    // The device: the build and what its user does.
    this.device = {
      platform: "ios", debug_build: false, locale: "en-US", sheets: false, securityStatus: false,
      ownerAuth: true, ownerAuths: [], prompts: [], presented: [], promptAnswer: null, webAuth: null,
      confirmations: false, confirmAnswer: true, confirmed: [],
      // What the app knows of the delivery of the program itself (the bridge primitive
      // programDelivery, in a build that has it): {verified, settled_ms, failed_ms,
      // failed_status}, or a function that returns it. null: a build without the primitive.
      delivery: null,
    };
    if (given.device) Object.assign(this.device, given.device);
    // The backend: which routes it has, and the faults of a fixture (see fault).
    this.routes = { grants: true, log: "on", outcomes: true, syncReport: true };
    this.faults = [];
    this.vault = { secrets: new Map(), logins: new Map(), created: 0 };
    // The authorizations the nodes began (POST /api/secure/connections/begin), by node state.
    this.connections = new Map();
    // The shared ledger the backend keeps for the account (GET/PUT /api/secure/ledger).
    this.sharedLedger = null;
    this.ledgerUploads = 0;
    // The attestation documents the backend kept of the nodes of releases before v2.4.0.
    this.keptDocuments = new Map();
    // The release proofs the backend holds, by release: it hands them out with the attestation
    // of a node of that release when a request asks for them (the query proofs), or with every
    // attestation when proofsUnasked is set.
    this.releaseProofs = new Map();
    this.proofsUnasked = false;
  }

  get storeHost() {
    return this.bucket + ".s3." + this.region + ".amazonaws.com";
  }

  get shardHost() {
    return shardBucket(this.serverTarget, this.userId) + ".s3." + this.region + ".amazonaws.com";
  }

  // ---- The time of the model ----

  /** A promise that resolves when the time of the model has moved on by ms. */
  sleep(ms) {
    return new Promise((resolve) => {
      this.timers.push({ at: this.now + Math.max(0, Number(ms) || 0), resolve: resolve });
    });
  }

  /** Lets everything that can happen without time passing happen. */
  async drain() {
    for (let turn = 0; turn < 3; turn += 1) await new Promise((resolve) => setImmediate(resolve));
  }

  /** Moves the time on to the earliest timer and fires what is due. False when no timer waits. */
  step() {
    if (this.timers.length === 0) return false;
    let earliest = this.timers[0].at;
    for (const timer of this.timers) earliest = Math.min(earliest, timer.at);
    this.now = Math.max(this.now, earliest);
    const due = this.timers.filter((timer) => timer.at <= this.now);
    this.timers = this.timers.filter((timer) => timer.at > this.now);
    for (const timer of due) timer.resolve();
    return true;
  }

  /** Runs the model until promise settles, moving the time on whenever nothing else can happen,
   *  and returns its value (or throws its failure). */
  async run(promise) {
    const outcome = { settled: false, failed: false, value: undefined };
    Promise.resolve(promise).then(
      (value) => { outcome.settled = true; outcome.value = value; },
      (error) => { outcome.settled = true; outcome.failed = true; outcome.value = error; });
    for (let turn = 0; turn < 100000; turn += 1) {
      await this.drain();
      if (outcome.settled) break;
      if (!this.step()) throw new Error("the model is idle and the promise has not settled");
    }
    if (!outcome.settled) throw new Error("the promise did not settle");
    if (outcome.failed) throw outcome.value;
    return outcome.value;
  }

  /** Lets the work nothing waits for go on for ms of the time of the model (reports, the timers of
   *  requests that were answered). */
  async settle(ms) {
    const end = this.now + (ms === undefined ? 0 : ms);
    for (let turn = 0; turn < 100000; turn += 1) {
      await this.drain();
      const next = this.timers.reduce((least, timer) => Math.min(least, timer.at), Infinity);
      if (next > end) break;
      this.step();
    }
    this.now = Math.max(this.now, end);
    await this.drain();
  }

  advance(ms) {
    this.now += ms;
  }

  // ---- The account and the nodes ----

  /** A master key in the key store of the device and the registration of its keys on the account
   *  (the state of a device whose key state is present). */
  createAccount() {
    const masterKey = crypto.randomBytes(32);
    this.keychain.set("com.pickle.client.secure.master-key\n" + this.userId,
      { value: b64u(masterKey), synchronizable: true });
    const keys = deriveAccountKeys(masterKey);
    keys.masterKey = masterKey;
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
    return Array.from(this.nodes.values()).filter((node) => node.alive && node.offered);
  }

  // ---- The log store ----

  objectsOf(bucket) {
    let objects = this.buckets.get(bucket);
    if (objects === undefined) {
      objects = new Map();
      this.buckets.set(bucket, objects);
    }
    return objects;
  }

  /** The objects of the bucket of format 1 and format 2 (key -> versions). */
  get objects() {
    return this.objectsOf(this.bucket);
  }

  /** The objects of the bucket of format 3 of the account. */
  get entries3() {
    return this.objectsOf(shardBucket(this.serverTarget, this.userId));
  }

  putObject(bucket, key, body) {
    this.versionCounter += 1;
    const objects = this.objectsOf(bucket);
    const versions = objects.get(key) || [];
    versions.unshift({ versionId: "v" + zeros(this.versionCounter, 6), body: body });
    objects.set(key, versions);
  }

  /** Puts a delete marker on a key (what a delete request leaves in a bucket with versions: the
   *  versions under it stay). */
  putDeleteMarker(bucket, key) {
    this.versionCounter += 1;
    const objects = this.objectsOf(bucket);
    const versions = objects.get(key) || [];
    versions.unshift({ versionId: "v" + zeros(this.versionCounter, 6), body: "", deleteMarker: true });
    objects.set(key, versions);
  }

  /** A stored value of the program store as JSON (undefined when there is none). */
  stored(key) {
    const value = this.store.get(key);
    return value === undefined ? undefined : JSON.parse(value);
  }

  /** The node ledger as the program stored it in the device copy (null when none). */
  ledger() {
    const value = this.stored("ledger");
    return value === undefined ? null : value;
  }

  // ---- The faults of a fixture ----

  /** Adds a fault: {match, respond, times}. match is a string the request line must begin with
   *  ("POST /api/secure/log/read", or "S3 " + host for a request to the store), or a function of
   *  the request; respond is {status, body}, "hang" (the request is never answered), "transport"
   *  (the request fails on the device), or a function of the request that returns one of these
   *  (undefined: no fault). With delay_ms the answer comes that long after the request ({delay_ms}
   *  alone delays the answer of the model, and with fail "transport" the request fails on the
   *  device then). times bounds how often the fault applies. Returns the fault. */
  fault(match, respond, times) {
    const fault = { match: match, respond: respond, times: times === undefined ? Infinity : times, hits: 0 };
    this.faults.push(fault);
    return fault;
  }

  clearFaults() {
    this.faults = [];
  }

  faultFor(line, request) {
    for (const fault of this.faults) {
      if (fault.times <= 0) continue;
      const matches = typeof fault.match === "function" ? fault.match(line, request) : line.startsWith(fault.match);
      if (!matches) continue;
      const answer = typeof fault.respond === "function" ? fault.respond(request, line) : fault.respond;
      if (answer === undefined) continue;
      fault.times -= 1;
      fault.hits += 1;
      return answer;
    }
    return undefined;
  }

  // ---- The backend of the operator (native.http with path) ----

  legacyListingUrl(options) {
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

  /** The presigned address of one listing page of format 3. */
  readUrl(page) {
    let query = "versions&prefix=" + encodeURIComponent("a3/" + this.userId + "/" + page.prefix + "/");
    if (page.key_marker) query += "&key-marker=" + encodeURIComponent(page.key_marker);
    if (page.version_id_marker) query += "&version-id-marker=" + encodeURIComponent(page.version_id_marker);
    query += "&max-keys=1000&encoding-type=url&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=" +
      crypto.randomBytes(8).toString("hex");
    return "https://" + this.shardHost + "/?" + query;
  }

  /** The presigned address of the listing of the versions of the node document of a node. */
  documentUrl(node) {
    return "https://" + shardBucket(this.serverTarget, node) + ".s3." + this.region + ".amazonaws.com/?versions&prefix=" +
      encodeURIComponent("n3/" + node) + "&max-keys=1000&encoding-type=url&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=" +
      crypto.randomBytes(8).toString("hex");
  }

  /** The node the backend names for a connection of the account: one that holds a grant of it.
   *  A request that names the program that asks (the query program) is answered with a node of
   *  the nodes that serve calls; a request that names none comes from a device that runs an
   *  earlier program, and is answered with a node listed for its revokes alone (revokeOnly)
   *  when one holds a grant. */
  namedNode(query) {
    const holders = this.offeredNodes().filter((candidate) => candidate.grants.has(this.userId));
    const guard = holders.find((candidate) => candidate.revokeOnly === true);
    const pool = holders.find((candidate) => candidate.revokeOnly !== true);
    return query !== null && query !== undefined && query.program !== undefined ? (pool || guard) : (guard || pool);
  }

  api(method, path, query, bodyText) {
    const json = (status, value) => ({ status: status, headers: {}, body: JSON.stringify(value), bodyBase64: null });
    const body = typeof bodyText === "string" && bodyText !== "" ? JSON.parse(bodyText) : null;
    const absent = () => json(404, { detail: "Not Found" });
    if (method === "GET" && path === "/api/secure/account") {
      const account = { user_id: this.userId, key: this.account.key === null ? null : { key_id: this.account.key.key_id } };
      // The backend names the vault items with a name only for an account it turned them on for.
      if (this.account.namedSecrets === true) account.named_secrets = true;
      if (this.account.servedProgram !== undefined) account.served_program_version = this.account.servedProgram;
      return json(200, account);
    }
    if (method === "PUT" && path === "/api/secure/account/key") {
      const signPk = bytes(body.sign_pk);
      const proof = ed25519Verify(signPk, utf8("pickle.secure.v1.register\n" + this.userId), bytes(body.proof));
      if (!proof) return json(400, { code: "invalid_input" });
      if (this.account.key !== null && body.replace !== true) return json(409, { code: "key_exists" });
      this.account.key = { sign_pk: body.sign_pk, log_pk: body.log_pk, key_id: sha("sha256", signPk).subarray(0, 8).toString("hex") };
      return json(200, {});
    }
    if (method === "GET" && path === "/api/secure/grants") {
      if (!this.routes.grants) return absent();
      return json(200, {
        nodes: this.offeredNodes().map((node) => {
          const grant = node.grants.get(this.userId);
          const item = { node: node.id, not_after_ms: grant === undefined ? null : grant.not_after_ms };
          // A node the backend lists for its revokes alone (node.revokeOnly: a node of an earlier
          // release outside the nodes that serve calls, which holds a grant of the account).
          if (node.revokeOnly === true) item.revoke_only = true;
          return item;
        }),
      });
    }
    if (method === "GET" && path === "/api/secure/nodes") {
      if (typeof query.nonce !== "string") return json(400, { code: "invalid_input" });
      let nodes = this.offeredNodes();
      if (typeof query.nodes === "string") {
        const wanted = query.nodes.split(",");
        nodes = wanted.map((id) => this.nodes.get(id)).filter((node) => node !== undefined && node.alive);
      }
      const proofs = query.proofs === "1" || this.proofsUnasked;
      return json(200, {
        nodes: nodes.map((node, index) => {
          const response = Object.assign(node.attestation(query.nonce), { pod: index });
          if (proofs && this.releaseProofs.has(node.release)) response.release_proofs = this.releaseProofs.get(node.release);
          return response;
        }),
      });
    }
    const nodeRoute = /^\/api\/secure\/nodes\/([A-Za-z0-9_-]{43})\/(messages|status)$/.exec(path);
    if (nodeRoute !== null && method === "POST") {
      const node = this.nodes.get(nodeRoute[1]);
      if (node === undefined || !node.alive) return json(404, { code: "node_not_found" });
      if (nodeRoute[2] === "messages") return json(200, { reply: node.handleMessage(body.envelope) });
      return json(200, node.format === 3 ? {} : { head: node.head(this.userId, body.nonce, false) });
    }
    if (method === "GET" && path === "/api/secure/log/nodes") {
      const nodes = [];
      for (const node of this.nodes.values()) {
        if (node.format === 3) continue;
        const chain = node.chains.get(this.userId);
        if (chain === undefined && !node.finalHeads.has(this.userId)) continue;
        nodes.push({
          node: node.id, release: node.release, live: node.alive, max_seq: 0,
          final_head: node.finalHeads.get(this.userId) || null,
        });
      }
      return json(200, { nodes: nodes });
    }
    if (method === "POST" && path === "/api/secure/log/store/listings") {
      return json(200, {
        discovery: body.discovery ? { list_url: this.legacyListingUrl({ nodes: true }) } : null,
        nodes: (body.nodes || []).map((target) => ({
          node: target.node,
          list_url: this.legacyListingUrl({
            node: target.node, keyMarker: target.key_marker, versionIdMarker: target.version_id_marker,
          }),
        })),
      });
    }
    if (method === "GET" && path === "/api/secure/log/store") {
      return json(200, {
        list_url: this.legacyListingUrl({
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
    if (method === "POST" && /^\/api\/secure\/log\/(read|bodies|documents)$/.test(path)) {
      if (this.routes.log === "absent") return absent();
      // A backend that holds the store of format 3 closed answers the listings and the bodies
      // with log_store_disabled. It answers the node documents all the same, from the node
      // registry alone: it reads no store and gives no listing address.
      const closed = this.routes.log === "disabled";
      if (closed && !path.endsWith("/documents")) return json(409, { detail: "log_store_disabled" });
      if (path.endsWith("/read")) {
        const valid = Array.isArray(body.pages) && body.pages.length >= 1 && body.pages.length <= 8 &&
          body.pages.every((page) => page.prefix === "c" || page.prefix === "u");
        if (!valid) return json(400, { detail: "invalid_input" });
        return json(200, {
          store: { generation: 3, bucket: shardBucket(this.serverTarget, this.userId), region: this.region },
          pages: body.pages.map((page) => ({ prefix: page.prefix, url: this.readUrl(page) })),
          expires_ms: this.now + 300000,
        });
      }
      if (path.endsWith("/bodies")) {
        const prefix = "a3/" + this.userId + "/";
        const valid = Array.isArray(body.keys) && body.keys.length >= 1 && body.keys.length <= 200 &&
          body.keys.every((key) => typeof key === "string" && key.startsWith(prefix));
        if (!valid) return json(400, { detail: "invalid_input" });
        const entries = [];
        const missing = [];
        for (const key of body.keys) {
          const hash = key.slice(key.lastIndexOf(".") + 1);
          const version = (this.entries3.get(key) || []).find((item) => {
            try {
              return b64u(sha("sha256", bytes(JSON.parse(item.body).body))) === hash;
            } catch (error) {
              return false;
            }
          });
          if (version === undefined) missing.push(key);
          else entries.push(Object.assign({ key: key }, JSON.parse(version.body)));
        }
        return json(200, { entries: entries, missing: missing, unread: [] });
      }
      const valid = Array.isArray(body.nodes) && body.nodes.length >= 1 && body.nodes.length <= 64 &&
        body.nodes.every((id) => typeof id === "string" && /^[A-Za-z0-9_-]{43}$/.test(id));
      if (!valid) return json(400, { detail: "invalid_input" });
      // The document of a node: the latest version of its object in the store that has the form
      // of a node document, or else the attestation document the node registry kept of it.
      const documents = [];
      const missing = [];
      for (const id of body.nodes) {
        const versions = closed ? [] : this.objectsOf(shardBucket(this.serverTarget, id)).get("n3/" + id) || [];
        const written = versions.map((version) => {
          try {
            const value = version.deleteMarker === true ? null : JSON.parse(version.body);
            return value !== null && typeof value === "object" && value.node === id ? value : null;
          } catch (error) {
            return null;
          }
        }).find((value) => value !== null);
        if (written !== undefined) documents.push({ node: id, origin: "log_store", document: written });
        else if (this.keptDocuments.has(id)) documents.push({ node: id, origin: "node_registry", document: this.keptDocuments.get(id) });
        else missing.push(id);
      }
      return json(200, {
        documents: documents, missing: missing, unread: [],
        listings: closed ? [] : body.nodes.map((id) => ({ node: id, url: this.documentUrl(id) })),
        expires_ms: this.now + 300000,
      });
    }
    if (method === "POST" && path === "/api/secure/log/verified") {
      this.reports.push(body);
      return json(200, {});
    }
    if (method === "POST" && path === "/api/secure/procedures/outcomes") {
      if (!this.routes.outcomes) return absent();
      this.outcomeReports.push(body);
      return json(200, {});
    }
    if (method === "POST" && path === "/api/secure/sync/report") {
      if (!this.routes.syncReport) return absent();
      this.syncReports.push(body);
      return json(200, {});
    }
    if (path === "/api/secure/ledger") {
      if (method === "GET") return json(200, { ledger: this.sharedLedger });
      if (method === "PUT") {
        const shaped = body !== null && typeof body.key_id === "string" &&
          typeof body.nonce === "string" && typeof body.ct === "string";
        if (!shaped) return json(400, { code: "invalid_input" });
        if (this.account.key === null || body.key_id !== this.account.key.key_id) {
          return json(409, { code: "key_mismatch" });
        }
        this.sharedLedger = { key_id: body.key_id, nonce: body.nonce, ct: body.ct, updated_ms: this.now };
        this.ledgerUploads += 1;
        return json(200, {});
      }
    }
    const secret = /^\/api\/secure\/vault\/secret(?:\/([A-Z][A-Z0-9_]{0,63}))?(\/binding)?$/.exec(path);
    if (secret !== null) {
      const name = secret[1];
      if (name === undefined && method === "POST") {
        this.vault.created += 1;
        const made = "SECRET_" + this.vault.created;
        this.vault.secrets.set(made, {
          name: made, label: body.label, sites: body.sites, slots: body.slots, state: "empty", source: "device",
        });
        return json(200, { name: made, sites: body.sites, slots: body.slots });
      }
      const item = name === undefined ? undefined : this.vault.secrets.get(name);
      if (item === undefined) return json(404, { code: "not_found" });
      if (method === "GET" && secret[2] === undefined) return json(200, item);
      if (method === "PUT" && secret[2] === undefined) {
        item.record = body.record;
        item.sites = body.sites;
        item.slots = body.slots;
        item.state = "ready";
        return json(200, { name: name, state: "ready" });
      }
      if (method === "POST" && secret[2] !== undefined) {
        item.sites = body.sites;
        item.slots = body.slots;
        if (body.record !== undefined) item.record = body.record;
        return json(200, { name: name, sites: item.sites, slots: item.slots });
      }
      if (method === "DELETE" && secret[2] === undefined) {
        this.vault.secrets.delete(name);
        return json(200, {});
      }
    }
    const login = /^\/api\/secure\/vault\/login\/([^/]+)\/passwords$/.exec(path);
    if (login !== null && method === "GET") {
      const kept = this.vault.logins.get(decodeURIComponent(login[1]));
      return kept === undefined ? json(404, { code: "not_found" }) : json(200, kept);
    }
    if (method === "PUT" && (path === "/api/secure/vault/login" || path === "/api/secure/vault/card")) {
      this.vault.lastSaved = body;
      return json(200, { name: body.name });
    }
    if (method === "POST" && path === "/api/secure/connections/begin") {
      // A node that holds the grant of the account states the authorization it began (8.2).
      const node = this.namedNode(query);
      if (node === undefined) return json(409, { code: "grant_required" });
      const grant = node.grants.get(this.userId);
      const nodeState = b64u(crypto.randomBytes(16));
      const state = nodeState + ".operator";
      const url = "https://provider.example/authorize?state=" + state;
      this.connections.set(nodeState, { node: node, state: state, provider: body.target, completed: false });
      return json(200, {
        node: node.id, state: state, authorization_url: url, ephemeral_session: false,
        statement: signedValue(node.signSeed, "pickle.secure.v1.statement\n", {
          v: 1, type: "oauth_begin", node: node.id, user_id: this.userId, key_id: grant.key_id,
          sign_pk: grant.sign_pk, provider: body.target, state: state,
          url_sha256: b64u(sha("sha256", utf8(url))), time_ms: this.now,
        }),
      });
    }
    if (method === "PUT" && path === "/api/secure/connections/naver_mail/app-password") {
      const node = this.namedNode(query);
      if (node === undefined) return json(409, { code: "grant_required" });
      const grant = node.grants.get(this.userId);
      const identity = "user@naver.com";
      return json(200, {
        node: node.id, connection_id: "connection-mail", identity: identity,
        statement: signedValue(node.signSeed, "pickle.secure.v1.statement\n", {
          v: 1, type: "app_password_verified", node: node.id, user_id: this.userId, key_id: grant.key_id,
          sign_pk: grant.sign_pk, provider: "naver_mail", record_id: body.record.id, identity: identity,
          ciphertext_sha256: b64u(sha("sha256", utf8(body.record.ct))), time_ms: this.now,
        }),
      });
    }
    if (method === "GET" && path === "/api/secure/connections/completion") {
      const kept = this.connections.get(query.state);
      if (kept === undefined || !kept.completed) return json(404, { code: "not_found" });
      const grant = kept.node.grants.get(this.userId);
      return json(200, {
        connection_id: "connection-1", provider: kept.provider,
        statement: signedValue(kept.node.signSeed, "pickle.secure.v1.statement\n", {
          v: 1, type: "oauth_complete", node: kept.node.id, user_id: this.userId, key_id: grant.key_id,
          sign_pk: grant.sign_pk, provider: kept.provider, state: kept.state, record_id: "ARUgUDnTSlTyTpffFFUt0w",
          time_ms: this.now,
        }),
      });
    }
    if (method === "GET" && path === "/api/secure/sealing") return json(200, { items: [], more: false });
    if (method === "GET" && path === "/api/secure/transfers") return json(200, { transfers: [] });
    return absent();
  }

  // ---- The log store (native.http with url) ----

  storeHttp(method, url) {
    const address = new URL(url);
    const text = (status, body) => ({ status: status, headers: {}, body: body, bodyBase64: null });
    const bucket = address.host.split(".s3.")[0];
    if (method !== "GET" || !address.host.endsWith(".s3." + this.region + ".amazonaws.com")) return text(403, "");
    if (address.pathname === "/" && address.searchParams.has("versions")) {
      return text(200, this.listing(bucket, address.searchParams));
    }
    const key = decodeURIComponent(address.pathname.slice(1));
    const versionId = address.searchParams.get("versionId");
    const version = (this.objectsOf(bucket).get(key) || []).find((item) => item.versionId === versionId);
    return version === undefined ? text(404, "") : text(200, version.body);
  }

  listing(bucket, params) {
    const prefix = params.get("prefix") || "";
    const delimiter = params.get("delimiter");
    const keyMarker = params.get("key-marker");
    const objects = this.objectsOf(bucket);
    const keys = Array.from(objects.keys())
      .filter((key) => key.startsWith(prefix) && (keyMarker === null || key > keyMarker))
      .sort();
    const parts = [
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
      "<ListVersionsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
      "<Name>" + bucket + "</Name><Prefix>" + encodeURIComponent(prefix) + "</Prefix>",
      "<MaxKeys>1000</MaxKeys><EncodingType>url</EncodingType>",
    ];
    let truncated = false;
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
      // A page holds pageSize object versions at most and never splits the versions of one key.
      let count = 0;
      let last = null;
      for (const key of keys) {
        const versions = objects.get(key);
        if (count > 0 && count + versions.length > this.pageSize) {
          truncated = true;
          break;
        }
        count += versions.length;
        last = { key: key, versionId: versions[versions.length - 1].versionId };
        versions.forEach((version, index) => {
          const tag = version.deleteMarker === true ? "DeleteMarker" : "Version";
          parts.push(
            "<" + tag + "><Key>" + encodeURIComponent(key) + "</Key><VersionId>" + version.versionId +
            "</VersionId><IsLatest>" + (index === 0 ? "true" : "false") + "</IsLatest>" +
            "<LastModified>2026-11-05T00:00:00.000Z</LastModified>" +
            (version.deleteMarker === true ? "" : "<Size>" + version.body.length + "</Size>") + "</" + tag + ">");
        });
      }
      if (truncated) {
        parts.push("<NextKeyMarker>" + encodeURIComponent(last.key) + "</NextKeyMarker>" +
          "<NextVersionIdMarker>" + last.versionId + "</NextVersionIdMarker>");
      }
    }
    parts.push("<IsTruncated>" + (truncated ? "true" : "false") + "</IsTruncated>");
    parts.push("</ListVersionsResult>");
    return parts.join("");
  }

  /** One request of the program. The answer of a fault of the fixture comes first. */
  http(request) {
    this.requests.push(request);
    const method = request.method || "GET";
    const line = typeof request.path === "string"
      ? method + " " + request.path : "S3 " + new URL(request.url).host + new URL(request.url).pathname;
    const fault = this.faultFor(line, request);
    if (fault === "hang") return new Promise(() => {});
    if (fault === "transport") return Promise.reject(new SecureError("transport", line));
    if (fault !== undefined && typeof fault.delay_ms === "number") {
      return this.sleep(fault.delay_ms).then(() => {
        if (fault.fail === "transport") throw new SecureError("transport", line);
        return this.answer(method, request, fault);
      });
    }
    return Promise.resolve(this.answer(method, request, fault));
  }

  answer(method, request, fault) {
    if (fault !== undefined && typeof fault.status === "number") {
      return {
        status: fault.status, headers: {}, bodyBase64: null,
        body: typeof fault.body === "string" ? fault.body : JSON.stringify(fault.body === undefined ? {} : fault.body),
      };
    }
    if (typeof request.path === "string") return this.api(method, request.path, request.query || {}, request.body);
    if (typeof request.url === "string") return this.storeHttp(method, request.url);
    throw new SecureError("invalid_argument", "http: neither path nor url");
  }

  /** The requests the program sent whose line begins with prefix ("GET /api/secure/nodes", "S3 "). */
  sent(prefix) {
    return this.requests.filter((request) => {
      const method = request.method || "GET";
      const line = typeof request.path === "string" ? method + " " + request.path : "S3 " + new URL(request.url).host;
      return line.startsWith(prefix);
    });
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

/** The global native of one runtime on world: the functions of the bridge tables that the flows of
 *  the tests reach, and a stub that fails with invalid_argument for the ones they do not (the
 *  hardware key of the device, RSA). The functions a later build of the apps adds
 *  (securityStatus, promptSecret, presentSecret, confirmDestinations, programDelivery) exist only
 *  when the device of the world has them.
 *  While world.bridgeOpen is false (the top-level evaluation) every call fails with cancelled. */
function makeNative(world) {
  const device = world.device;
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
    deviceInfo: () => {
      world.deviceInfoCalls += 1;
      const info = {
        platform: device.platform, app_version: "1.1.0", app_build: "1", system_version: "26.0", model: "iPhone",
        server_target: world.serverTarget, user_id: world.userId, program_origin: "server",
        locale: device.locale, debug_build: device.debug_build === true,
      };
      if (device.local_stack_build !== undefined) info.local_stack_build = device.local_stack_build;
      return info;
    },
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
    http: (request) => world.http(request),
    sleep: (ms) => world.sleep(Math.min(Math.max(0, Number(ms) || 0), 60000)),
    webAuth: (args) => {
      if (typeof device.webAuth !== "function") return Promise.reject(new SecureError("invalid_argument", "webAuth is not part of this fixture"));
      return Promise.resolve(device.webAuth(args));
    },
    deviceOwnerAuth: (reason) => {
      device.ownerAuths.push(String(reason));
      return typeof device.ownerAuth === "function" ? Promise.resolve(device.ownerAuth(reason)) : Promise.resolve(device.ownerAuth);
    },
  };
  if (device.securityStatus) {
    functions.securityStatus = (args) => {
      const valid = args !== null && typeof args === "object" && ["ok", "pending", "attention"].indexOf(args.status) >= 0 &&
        (args.reasons === undefined || (Array.isArray(args.reasons) && args.reasons.length <= 8 &&
          args.reasons.every((reason) => /^[a-z0-9_]{1,64}$/.test(reason))));
      if (!valid) throw new SecureError("invalid_argument", "securityStatus");
      world.securityStatuses.push({ status: args.status, reasons: Array.from(args.reasons || []), at_ms: world.now });
      return null;
    };
  }
  if (device.sheets) {
    const lines = (value) => Array.isArray(value) && value.length >= 1 && value.length <= 16 &&
      value.every((line) => typeof line === "string" && line.length >= 1 && line.length <= 200);
    asyncFunctions.promptSecret = (args) => {
      const valid = args !== null && typeof args === "object" && typeof args.title === "string" &&
        args.title.length >= 1 && args.title.length <= 120 && lines(args.destinations);
      if (!valid) return Promise.reject(new SecureError("invalid_argument", "promptSecret"));
      device.prompts.push(JSON.parse(JSON.stringify(args)));
      const answer = typeof device.promptAnswer === "function" ? device.promptAnswer(args) : device.promptAnswer;
      return Promise.resolve(answer === null ? null : { value: answer });
    };
    asyncFunctions.presentSecret = (args) => {
      const valid = args !== null && typeof args === "object" && typeof args.title === "string" &&
        args.title.length >= 1 && args.title.length <= 120 && typeof args.value === "string" &&
        args.value.length >= 1 && args.value.length <= 16384 &&
        (args.destinations === undefined || args.destinations === null || lines(args.destinations));
      if (!valid) return Promise.reject(new SecureError("invalid_argument", "presentSecret"));
      device.presented.push(JSON.parse(JSON.stringify(args)));
      return Promise.resolve(null);
    };
  }
  if (device.delivery !== null && device.delivery !== undefined) {
    functions.programDelivery = () => {
      const value = typeof world.device.delivery === "function" ? world.device.delivery() : world.device.delivery;
      return value === null || typeof value !== "object" ? value : Object.assign({}, value);
    };
  }
  if (device.confirmations) {
    asyncFunctions.confirmDestinations = (args) => {
      const valid = args !== null && typeof args === "object" && typeof args.title === "string" &&
        args.title.length >= 1 && args.title.length <= 120 && Array.isArray(args.destinations) &&
        args.destinations.length >= 1 && args.destinations.length <= 16 &&
        args.destinations.every((line) => typeof line === "string" && line.length >= 1 && line.length <= 200);
      if (!valid) return Promise.reject(new SecureError("invalid_argument", "confirmDestinations"));
      device.confirmed.push(JSON.parse(JSON.stringify(args)));
      const answer = typeof device.confirmAnswer === "function" ? device.confirmAnswer(args) : device.confirmAnswer;
      return Promise.resolve(answer === true ? { confirmed: true } : null);
    };
  }
  const stubs = ["rsaVerify", "secureEnclaveP256Create", "secureEnclaveP256PublicKey", "secureEnclaveP256Sign"];
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
  world.timers = [];
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

/** The measurements of ACCEPTED_RELEASES of a program source, in the order of the list, each with
 *  log_store (true when the element says so: the node writes the log entry to the log store). */
function listedMeasurements(source) {
  const start = source.indexOf("const ACCEPTED_RELEASES = [");
  const end = source.indexOf("];", start);
  const pattern = /release: "([^"]+)",\s*pcr0: "([0-9a-f]{96})",\s*pcr1: "([0-9a-f]{96})",\s*pcr2: "([0-9a-f]{96})",(\s*log_store: true,)?/g;
  const out = [];
  let match = pattern.exec(source.slice(start, end));
  while (match !== null) {
    out.push({ release: match[1], pcr0: match[2], pcr1: match[3], pcr2: match[4], log_store: match[5] !== undefined });
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

/** The source of a program that lists one more release: the same program with one more element at
 *  the end of ACCEPTED_RELEASES, and the version given when one is given (the program the operator
 *  serves once it lists the release). */
function withListedRelease(source, release, measurement, version) {
  const start = source.indexOf("const ACCEPTED_RELEASES = [");
  const end = source.indexOf("  ];", start);
  const element = "    {\n      release: \"" + release + "\",\n      pcr0: \"" + measurement.pcr0 +
    "\",\n      pcr1: \"" + measurement.pcr1 + "\",\n      pcr2: \"" + measurement.pcr2 +
    "\",\n      log_store: true,\n    },\n";
  const patched = source.slice(0, end) + element + source.slice(end);
  return version === undefined ? patched : patched.replace(/^\s*const VERSION = \d+;/m, "  const VERSION = " + version + ";");
}

module.exports = {
  b64u, bytes, utf8, concat, sha, hmac, hkdfExtract, hkdfExpand,
  ed25519PublicKey, ed25519Sign, ed25519Verify, x25519PublicKey, x25519,
  aeadSeal, aeadOpen, hpkeSeal, hpkeOpen, hpkeDeriveKeyPair,
  cbor, SecureError, signedValue, deriveAccountKeys,
  Node, World, makeNative, loadProgram, listedMeasurements, declaredVersion, randomMeasurement,
  withListedRelease, writesFormat3, shardBucket, SHARDS, DAY_MS, RTIME_MAX,
};
