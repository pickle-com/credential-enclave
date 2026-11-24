// The model of the parties that make release proofs, for the tests of the secure program
// (docs/protocol.md, "The release proofs"): an operator with a release key and deploy keys, a
// transparency log of the form Rekor v1 (it signs an entry timestamp, holds its entries in a
// Merkle tree and signs the head of that tree), a certificate authority that issues a certificate
// to a workflow run as Fulcio does, and the release workflow that attests a release statement
// with the key of such a certificate. Every key is made here and signs what a test asks for, so a
// test can state proofs that hold and proofs that differ from them in one place.
//
// The crypto is that of Node. The certificates are X.509 in DER, written by the small encoder of
// this file with the fields and extensions the program reads.
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

// ---- Bytes ----

function b64(buffer) {
  return Buffer.from(buffer).toString("base64");
}

function b64u(buffer) {
  return Buffer.from(buffer).toString("base64url");
}

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest();
}

// ---- DER ----

function derLength(length) {
  if (length < 0x80) return Buffer.from([length]);
  const bytes = [];
  for (let rest = length; rest > 0; rest = Math.floor(rest / 256)) bytes.unshift(rest % 256);
  return Buffer.from([0x80 | bytes.length].concat(bytes));
}

function tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

const der = {
  tlv: tlv,
  sequence: (...items) => tlv(0x30, Buffer.concat(items)),
  set: (...items) => tlv(0x31, Buffer.concat(items)),
  /** A non-negative integer from a number or from the bytes of its magnitude. */
  integer: (value) => {
    const digits = Buffer.isBuffer(value) ? value.toString("hex") : value.toString(16);
    let bytes = Buffer.from(digits.length % 2 === 1 ? "0" + digits : digits, "hex");
    while (bytes.length > 1 && bytes[0] === 0 && bytes[1] < 0x80) bytes = bytes.subarray(1);
    if (bytes[0] >= 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
    return tlv(0x02, bytes);
  },
  oid: (dotted) => {
    const parts = dotted.split(".").map(Number);
    const bytes = [40 * parts[0] + parts[1]];
    for (const part of parts.slice(2)) {
      const digits = [part % 128];
      for (let rest = Math.floor(part / 128); rest > 0; rest = Math.floor(rest / 128)) digits.unshift(0x80 | (rest % 128));
      bytes.push(...digits);
    }
    return tlv(0x06, Buffer.from(bytes));
  },
  utf8: (value) => tlv(0x0c, Buffer.from(value, "utf8")),
  printable: (value) => tlv(0x13, Buffer.from(value, "ascii")),
  boolean: (value) => tlv(0x01, Buffer.from([value ? 0xff : 0x00])),
  octets: (value) => tlv(0x04, value),
  bits: (value) => tlv(0x03, Buffer.concat([Buffer.from([0]), value])),
  explicit: (number, content) => tlv(0xa0 | number, content),
  /** A UTCTime of seconds since 1970. */
  time: (seconds) => {
    const date = new Date(seconds * 1000);
    const two = (value) => String(value).padStart(2, "0");
    return tlv(0x17, Buffer.from(two(date.getUTCFullYear() % 100) + two(date.getUTCMonth() + 1) + two(date.getUTCDate()) +
      two(date.getUTCHours()) + two(date.getUTCMinutes()) + two(date.getUTCSeconds()) + "Z", "ascii"));
  },
};

const OID = {
  ecdsaSha256: "1.2.840.10045.4.3.2",
  ecdsaSha384: "1.2.840.10045.4.3.3",
  organization: "2.5.4.10",
  commonName: "2.5.4.3",
  basicConstraints: "2.5.29.19",
  keyUsage: "2.5.29.15",
  fulcio: "1.3.6.1.4.1.57264.1",
};

function name(organization, commonName) {
  return der.sequence(
    der.set(der.sequence(der.oid(OID.organization), der.printable(organization))),
    der.set(der.sequence(der.oid(OID.commonName), der.printable(commonName))));
}

function pem(label, bytes) {
  const lines = b64(bytes).match(/.{1,64}/g).join("\n");
  return "-----BEGIN " + label + "-----\n" + lines + "\n-----END " + label + "-----\n";
}

/** A key pair on a curve (prime256v1, secp384r1): {privateKey, publicKey, spki, pem}. */
function ecKeyPair(curve) {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: curve });
  const spki = pair.publicKey.export({ format: "der", type: "spki" });
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, spki: spki, pem: pem("PUBLIC KEY", spki) };
}

/** An ECDSA signature in ASN.1 DER. */
function ecdsaSign(key, hash, message) {
  return crypto.sign(hash, message, { key: key.privateKey, dsaEncoding: "der" });
}

let serial = 1;

/** An X.509 certificate in DER.
 *    key        the key pair whose public key the certificate holds
 *    signer     the key pair that signs it
 *    subject, issuer  the two names (DER)
 *    notBefore, notAfter  seconds since 1970
 *    authority  true, false or undefined: the basic constraints state a certificate authority,
 *               state none, or are absent
 *    texts      {number: text}: the extensions 1.3.6.1.4.1.57264.1.{number}, each one UTF8String
 *    extensions further extensions, each a DER element
 *    hash       the hash of the signature (sha384) */
function certificate(options) {
  const hash = options.hash || "sha384";
  const algorithm = der.sequence(der.oid(hash === "sha256" ? OID.ecdsaSha256 : OID.ecdsaSha384));
  const extensions = [];
  if (options.authority !== undefined) {
    extensions.push(der.sequence(der.oid(OID.basicConstraints), der.boolean(true),
      der.octets(options.authority ? der.sequence(der.boolean(true)) : der.sequence())));
  }
  for (const number of Object.keys(options.texts || {})) {
    extensions.push(der.sequence(der.oid(OID.fulcio + "." + number), der.octets(der.utf8(options.texts[number]))));
  }
  for (const extension of options.extensions || []) extensions.push(extension);
  serial += 1;
  const parts = [
    der.explicit(0, der.integer(2)), der.integer(serial), algorithm, options.issuer,
    der.sequence(der.time(options.notBefore), der.time(options.notAfter)), options.subject, options.key.spki,
  ];
  if (extensions.length > 0) parts.push(der.explicit(3, der.sequence(...extensions)));
  const signed = der.sequence(...parts);
  return der.sequence(signed, algorithm, der.bits(ecdsaSign(options.signer, hash, signed)));
}

// ---- The certificate authority ----

/** A certificate authority of two certificates, as the public instance of Sigstore has: a root
 *  that signed itself and an intermediate the root signed, both on P-384. issue makes the
 *  certificate of a workflow run. */
function makeAuthority(options) {
  const given = options || {};
  const from = given.notBefore === undefined ? 1600000000 : given.notBefore;
  const until = given.notAfter === undefined ? 1950000000 : given.notAfter;
  const rootKey = ecKeyPair("secp384r1");
  const intermediateKey = ecKeyPair("secp384r1");
  const rootName = name("sigstore.dev", "sigstore");
  const intermediateName = name("sigstore.dev", "sigstore-intermediate");
  const authority = {
    rootKey: rootKey, intermediateKey: intermediateKey, rootName: rootName, intermediateName: intermediateName,
    root: certificate({
      key: rootKey, signer: rootKey, subject: rootName, issuer: rootName, notBefore: from, notAfter: until,
      authority: given.rootAuthority === undefined ? true : given.rootAuthority,
    }),
    intermediate: certificate({
      key: intermediateKey, signer: given.intermediateSigner || rootKey, subject: intermediateName, issuer: rootName,
      notBefore: from, notAfter: until,
      authority: given.intermediateAuthority === undefined ? true : given.intermediateAuthority,
    }),
  };
  /** The certificate of a workflow run for key: valid for ten minutes from notBefore. options
   *  of certificate() replace what this function sets. */
  authority.issue = (key, texts, edit) => certificate(Object.assign({
    key: key, signer: intermediateKey, subject: der.sequence(), issuer: intermediateName,
    notBefore: 1795000000, notAfter: 1795000600, authority: false, texts: texts,
  }, edit || {}));
  return authority;
}

// ---- The transparency log ----

/** The hash of the Merkle tree over leaves (the hashes of its leaves): RFC 6962 section 2.1. */
function treeHash(leaves) {
  if (leaves.length === 1) return leaves[0];
  let split = 1;
  while (split * 2 < leaves.length) split *= 2;
  return sha256(Buffer.concat([Buffer.from([1]), treeHash(leaves.slice(0, split)), treeHash(leaves.slice(split))]));
}

/** The audit path of the leaf index of a tree over leaves, from the leaf upwards. */
function auditPath(index, leaves) {
  if (leaves.length === 1) return [];
  let split = 1;
  while (split * 2 < leaves.length) split *= 2;
  return index < split
    ? auditPath(index, leaves.slice(0, split)).concat([treeHash(leaves.slice(split))])
    : auditPath(index - split, leaves.slice(split)).concat([treeHash(leaves.slice(0, split))]);
}

/** A transparency log of the form Rekor v1 with a key of its own: {key, id, origin, promise,
 *  include}. */
function makeLog(origin) {
  const key = ecKeyPair("prime256v1");
  const log = { key: key, id: sha256(key.spki).toString("hex"), origin: origin || "log.example - 1" };
  /** The signed entry timestamp of the log for a body (standard base64 text): standard base64. */
  log.promise = (body, integratedTime, logIndex, logId) => b64(ecdsaSign(key, "sha256", Buffer.from(
    "{\"body\":\"" + body + "\",\"integratedTime\":" + integratedTime + ",\"logID\":\"" + (logId || log.id) +
    "\",\"logIndex\":" + logIndex + "}", "utf8")));
  /** The checkpoint of a tree of size leaves with the root hash root, signed by signer (the
   *  key of the log when absent). */
  log.checkpoint = (size, root, signer) => {
    const note = log.origin + "\n" + size + "\n" + b64(root) + "\n";
    const by = signer || log;
    const signature = Buffer.concat([Buffer.from(by.id, "hex").subarray(0, 4), ecdsaSign(by.key, "sha256", Buffer.from(note, "utf8"))]);
    // A signature line of a signed note begins with U+2014 and a space.
    return note + "\n" + String.fromCharCode(0x2014) + " " + log.origin.split(" ")[0] + " " + b64(signature) + "\n";
  };
  /** What the log returns to show that it holds the entry with the decoded body body: the
   *  entry is the leaf index of a tree of size leaves. {logIndex, treeSize, rootHash, hashes,
   *  checkpoint}. */
  log.include = (body, index, size) => {
    const leaves = [];
    for (let at = 0; at < size; at += 1) {
      leaves.push(at === index ? sha256(Buffer.concat([Buffer.from([0]), body])) : sha256(Buffer.from("leaf " + at)));
    }
    const root = treeHash(leaves);
    return { logIndex: index, treeSize: size, rootHash: root, hashes: auditPath(index, leaves), checkpoint: log.checkpoint(size, root) };
  };
  return log;
}

// ---- The operator ----

function ed25519KeyPair() {
  const pair = crypto.generateKeyPairSync("ed25519");
  return { privateKey: pair.privateKey, publicKey: b64u(pair.publicKey.export({ format: "der", type: "spki" }).subarray(12)) };
}

/** The parties of release proofs: the release key and the deploy keys of an operator, a
 *  transparency log and a certificate authority. */
function makeParties() {
  return {
    release: ecKeyPair("prime256v1"),
    deploy: { prod: ed25519KeyPair(), dev: ed25519KeyPair() },
    log: makeLog(),
    authority: makeAuthority(),
  };
}

const DEPLOY_CONTEXT = "pickle-enclave-release-statement-v1\n";
const REPOSITORY = "https://github.com/pickle-com/credential-enclave";

/** What a program holds of the signer of an attestation: {workflow, commit, caller}, the path of
 *  the build workflow, the commit of that workflow file and the path of the workflow that calls
 *  it (the constants PROOF_BUILD_WORKFLOW, PROOF_BUILD_COMMIT and PROOF_RELEASE_WORKFLOW of the
 *  source). */
function pinsOf(source) {
  const read = (name) => {
    const match = new RegExp("\\n  const " + name + " = \"([^\"\\n]*)\";\\n").exec(source);
    if (match === null) throw new Error("the program has no constant " + name);
    return match[1];
  };
  return { workflow: read("PROOF_BUILD_WORKFLOW"), commit: read("PROOF_BUILD_COMMIT"), caller: read("PROOF_RELEASE_WORKFLOW") };
}

// The values of the program of this checkout: the attestations of this model are those of the
// job that program takes.
const PINS = pinsOf(fs.readFileSync(path.join(__dirname, "..", "secure-program.js"), "utf8"));
// The commit a release of this model is built from (the git_commit of its statement).
const COMMIT = "5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e";
const PREDICATE_TYPE = "https://pickle.com/credential-enclave/release/v1";
const PAYLOAD_TYPE = "application/vnd.in-toto+json";

/** The bytes of a release statement: the file measurements.json of a release, as its build
 *  writes it. */
function statementOf(release, measurement, more) {
  return Buffer.from(JSON.stringify(Object.assign({
    release: release, git_commit: COMMIT,
    pcr0: measurement.pcr0, pcr1: measurement.pcr1, pcr2: measurement.pcr2, inputs: {},
  }, more || {}), null, 2) + "\n", "utf8");
}

/** The deploy signature of a key over a statement: standard base64. */
function deploySignature(key, statement, context) {
  const message = Buffer.from((context === undefined ? DEPLOY_CONTEXT : context) + sha256(statement).toString("hex") + "\n", "utf8");
  return b64(crypto.sign(null, message, key.privateKey));
}

/** The entry of a transparency log that records the signature of the release key over a
 *  statement, as an endorsement carries it (docs/protocol.md 10.3). options change one part:
 *    signer        the key pair that signs (the release key)
 *    signed        the bytes it signs (the statement)
 *    hashed        the bytes whose hash the record states (the statement)
 *    loggedKey     the PEM the record names (that of signer)
 *    log           the log that takes the entry (parties.log)
 *    record        (record) => void: changes the record before the log takes it
 *    integratedTime, logIndex  what the log states for the entry */
function recordedEntry(parties, statement, options) {
  const given = options || {};
  const signer = given.signer || parties.release;
  const log = given.log || parties.log;
  const record = {
    apiVersion: "0.0.1", kind: "hashedrekord",
    spec: {
      data: { hash: { algorithm: "sha256", value: sha256(given.hashed || statement).toString("hex") } },
      signature: {
        content: b64(ecdsaSign(signer, "sha256", given.signed || statement)),
        publicKey: { content: b64(Buffer.from(given.loggedKey || signer.pem, "utf8")) },
      },
    },
  };
  if (given.record) given.record(record);
  const body = b64(Buffer.from(JSON.stringify(record), "utf8"));
  const integratedTime = given.integratedTime === undefined ? 1795000000 : given.integratedTime;
  const logIndex = given.logIndex === undefined ? 4100000000 : given.logIndex;
  return {
    log_id: log.id, body: body, integrated_time: integratedTime, log_index: logIndex,
    signed_entry_timestamp: log.promise(body, integratedTime, logIndex),
  };
}

/** The values the certificate of the attestation of the release statement of a release states,
 *  by the number of its extension: the certificate of the job of the build workflow, called at
 *  the commit the program holds by the release workflow, in a run the push of the tag of the
 *  release started at commit (the commit of this model when absent). */
function identityOf(release, commit) {
  const ref = "refs/tags/" + release;
  const built = commit === undefined ? COMMIT : commit;
  return {
    8: "https://token.actions.githubusercontent.com", 9: REPOSITORY + "/" + PINS.workflow + "@" + PINS.commit, 10: PINS.commit,
    11: "github-hosted", 12: REPOSITORY, 13: built, 14: ref,
    15: "1400118248", 16: "https://github.com/pickle-com", 17: "151645824", 18: REPOSITORY + "/" + PINS.caller + "@" + ref,
    19: built, 20: "push",
    21: REPOSITORY + "/actions/runs/1/attempts/1", 22: "public",
  };
}

/** The attestation of a release statement as the job of the build workflow makes it: a Sigstore
 *  bundle with the certificate of the run, the envelope of the in-toto statement and the entry
 *  of the log. stated is {release, pcr0, pcr1, pcr2, program_min, git_commit}, the values of
 *  the predicate (program_min and git_commit when it has them); the certificate states
 *  git_commit as the commit that started the run. options change one part:
 *    identity      {number: text or null}: replaces or leaves out extensions of the certificate
 *    certificate   options of certificate() for the certificate of the run
 *    issuer        the authority that issues the certificate (parties.authority)
 *    predicate, predicateType, payloadType, statement  the parts of the in-toto statement
 *    signer        the key pair that signs the envelope (the key of the certificate)
 *    curve         the curve of the key of the certificate (prime256v1)
 *    log           the log that takes the entry (parties.log)
 *    record        (record) => void: changes the record of the log before the log takes it
 *    integratedTime, logIndex, leafIndex, treeSize  what the log states for the entry
 *    entry         (entry) => void: changes the entry after the log made it
 *    bundle        (bundle) => void: changes the bundle at the end */
function attestationOf(parties, stated, options) {
  const given = options || {};
  const log = given.log || parties.log;
  const key = ecKeyPair(given.curve || "prime256v1");
  const texts = identityOf(stated.release, stated.git_commit);
  for (const number of Object.keys(given.identity || {})) {
    if (given.identity[number] === null) delete texts[number];
    else texts[number] = given.identity[number];
  }
  const leaf = (given.issuer || parties.authority).issue(key, texts, given.certificate);
  const statement = given.statement || {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "enclave.eif", digest: { sha256: sha256(Buffer.from(stated.release)).toString("hex") } }],
    predicateType: given.predicateType === undefined ? PREDICATE_TYPE : given.predicateType,
    predicate: given.predicate || Object.assign(
      { release: stated.release, pcr0: stated.pcr0, pcr1: stated.pcr1, pcr2: stated.pcr2 },
      stated.program_min === undefined ? {} : { program_min: stated.program_min },
      stated.git_commit === undefined ? {} : { git_commit: stated.git_commit }),
  };
  const payload = Buffer.from(JSON.stringify(statement), "utf8");
  const payloadType = given.payloadType === undefined ? PAYLOAD_TYPE : given.payloadType;
  const type = Buffer.from(payloadType, "utf8");
  const signature = ecdsaSign(given.signer || key, "sha256", Buffer.concat([
    Buffer.from("DSSEv1 " + type.length + " ", "utf8"), type, Buffer.from(" " + payload.length + " ", "utf8"), payload]));
  const record = {
    apiVersion: "0.0.1", kind: "dsse",
    spec: {
      envelopeHash: { algorithm: "sha256", value: sha256(payload).toString("hex") },
      payloadHash: { algorithm: "sha256", value: sha256(payload).toString("hex") },
      signatures: [{ signature: b64(signature), verifier: b64(Buffer.from(pem("CERTIFICATE", leaf), "utf8")) }],
    },
  };
  if (given.record) given.record(record);
  const bodyBytes = Buffer.from(JSON.stringify(record), "utf8");
  const body = b64(bodyBytes);
  const integratedTime = given.integratedTime === undefined ? 1795000100 : given.integratedTime;
  const logIndex = given.logIndex === undefined ? 4100000001 : given.logIndex;
  const included = log.include(bodyBytes, given.leafIndex === undefined ? 5 : given.leafIndex, given.treeSize === undefined ? 11 : given.treeSize);
  const entry = {
    logIndex: String(logIndex), logId: { keyId: b64(Buffer.from(log.id, "hex")) },
    kindVersion: { kind: "dsse", version: "0.0.1" }, integratedTime: String(integratedTime),
    inclusionPromise: { signedEntryTimestamp: log.promise(body, integratedTime, logIndex) },
    inclusionProof: {
      logIndex: String(included.logIndex), rootHash: b64(included.rootHash), treeSize: String(included.treeSize),
      hashes: included.hashes.map(b64), checkpoint: { envelope: included.checkpoint },
    },
    canonicalizedBody: body,
  };
  if (given.entry) given.entry(entry);
  const bundle = {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: { certificate: { rawBytes: b64(leaf) }, tlogEntries: [entry], timestampVerificationData: {} },
    dsseEnvelope: { payload: b64(payload), payloadType: payloadType, signatures: [{ sig: b64(signature) }] },
  };
  if (given.bundle) given.bundle(bundle);
  return bundle;
}

/** The git_commit a release statement (bytes) states, or undefined. */
function commitOf(statement) {
  try {
    const value = JSON.parse(statement.toString("utf8"));
    return value !== null && typeof value === "object" && typeof value.git_commit === "string" ? value.git_commit : undefined;
  } catch (error) {
    return undefined;
  }
}

/** The release proofs of a release with a measurement, by the parties: {statement, entry,
 *  deploy_signatures, attestation}. options:
 *    statement     the bytes of the release statement (statementOf(release, measurement))
 *    entry         options of recordedEntry
 *    deploy        the value of deploy_signatures (one signature of each deploy key)
 *    attested      the values of the predicate of the attestation (those of the statement).
 *                  Values that name no git_commit take the one of the statement
 *    attestation   options of attestationOf */
function proofsOf(parties, release, measurement, options) {
  const given = options || {};
  // programMin: the statement states that program_min, and the attestation states it with it.
  const stated = given.programMin === undefined ? {} : { program_min: given.programMin };
  const statement = given.statement || statementOf(release, measurement, stated);
  return {
    statement: b64u(statement),
    entry: recordedEntry(parties, statement, given.entry),
    deploy_signatures: given.deploy || [
      { key_id: "dev", signature: deploySignature(parties.deploy.dev, statement) },
      { key_id: "prod", signature: deploySignature(parties.deploy.prod, statement) },
    ],
    attestation: attestationOf(parties, Object.assign(
      commitOf(statement) === undefined ? {} : { git_commit: commitOf(statement) },
      given.attested || Object.assign({ release: release }, measurement, stated)), given.attestation),
  };
}

/** The source of a program whose constants of the release proofs are those of the parties: the
 *  same program with the release key, the log keys, the two certificates of the certificate
 *  authority and the deploy keys of the parties in the place of those of the operator, Sigstore
 *  and Rekor. logs replaces the log keys ([spki]: the key of parties.log when absent). */
function withParties(source, parties, logs) {
  let patched = withConstant(source, "RELEASE_KEY", JSON.stringify(b64u(parties.release.spki)));
  patched = withConstant(patched, "PROOF_LOG_KEYS", JSON.stringify((logs || [parties.log.key.spki]).map(b64u)));
  patched = withConstant(patched, "FULCIO_ROOT", JSON.stringify(b64u(parties.authority.root)));
  patched = withConstant(patched, "FULCIO_INTERMEDIATE", JSON.stringify(b64u(parties.authority.intermediate)));
  return withDeployKeys(patched, parties.deploy);
}

/** The source of a program whose constant name has the value given (a JavaScript expression). */
function withConstant(source, name, value) {
  const pattern = new RegExp("(\\n  const " + name + " =)[\\s\\S]*?;\\n");
  if (!pattern.test(source)) throw new Error("the program has no constant " + name);
  return source.replace(pattern, (match, head) => head + " " + value + ";\n");
}

/** The source of a program whose deploy keys are the two given ({prod, dev}, each a key pair of
 *  ed25519KeyPair): the same program with them in the place of the deploy keys of the operator. */
function withDeployKeys(source, deploy) {
  return withConstant(source, "DEPLOY_KEYS", JSON.stringify({ prod: deploy.prod.publicKey, dev: deploy.dev.publicKey }));
}

module.exports = {
  b64, b64u, sha256, der, pem, ecKeyPair, ecdsaSign, certificate, makeAuthority, makeLog, treeHash, auditPath,
  ed25519KeyPair, makeParties, statementOf, deploySignature, recordedEntry, identityOf, attestationOf, proofsOf,
  withParties, withConstant, withDeployKeys, pinsOf, PINS, COMMIT, DEPLOY_CONTEXT, REPOSITORY, PREDICATE_TYPE, PAYLOAD_TYPE,
};
