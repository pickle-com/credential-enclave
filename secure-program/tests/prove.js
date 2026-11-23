// The verdict of the secure program on release proofs read from a file (docs/protocol.md, "The
// release proofs"), and on what a node of that release answered a request for its attestation.
// Release proofs are public values: whoever makes or carries them can ask the program of a
// version what it makes of them before a node of the release takes a key.
//
//   node secure-program/tests/prove.js RELEASE_PROOFS_JSON [--node ATTESTATION_RESPONSE_JSON]...
//       [--target prod|dev|alpha] [--program PROGRAM_JS]
//
// RELEASE_PROOFS_JSON holds {statement, entry, deploy_signatures, attestation}. The measurement is
// the one the statement states. The program (secure-program.js of this checkout unless --program
// names another source) runs with its constants as they are: its release key, its log key, its
// certificates, its deploy keys, its list of accepted releases and its version. The signatures
// are verified by the model of the bridge (bridge.js). The file prints what the program makes of
// the proofs for a build of the server target (prod unless --target names another) and ends
// with the status 0 when the proofs make the release one that program accepts, and 1 otherwise.
//
// The verdict on the proofs is that of the five checks on the proofs alone. Whether a node
// presents the measurement the statement states, and what the binding of that node states (the
// program requires its release to be the release of the statement, and reads its log, role and
// program_min), is the attestation of the node. --node names a file with what a node answered
// a request for its attestation (docs/protocol.md 4.2: {v, platform, document, node, release,
// challenge, challenge_statement}), or with an answer that carries such responses ({nodes:
// [...]}: the answer of the backend to GET /api/secure/nodes). For each response the file
// prints the three PCRs of the document beside those of the statement, what the binding
// states, and what the program makes of the response when it carries these proofs: that the
// node receives a grant, or the check of the program that refuses it. With --node the status is
// 0 only when, besides, every node of the files presents the measurement of the statement and
// receives a grant.
//
// The nonce of the request is taken from the document: the file judges an answer that was
// saved, not its freshness. The certificate chain of a nitro document is verified with the
// X.509 implementation of Node, against the root the program holds and at the time the
// document states (the model of the bridge only models the two bridge primitives x509Verify
// and x509PublicKey, so with --node they are the ones of this file).
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const bridge = require("./bridge.js");

const USAGE = "usage: node prove.js RELEASE_PROOFS_JSON [--node ATTESTATION_RESPONSE_JSON]... " +
  "[--target prod|dev|alpha] [--program PROGRAM_JS]";

const flags = { target: "prod", program: path.join(__dirname, "..", "secure-program.js") };
const files = [];
const nodeFiles = [];
for (let at = 2; at < process.argv.length; at += 1) {
  const argument = process.argv[at];
  if (argument === "--target" || argument === "--program") {
    flags[argument.slice(2)] = process.argv[at + 1];
    at += 1;
  } else if (argument === "--node") {
    nodeFiles.push(process.argv[at + 1]);
    at += 1;
  } else {
    files.push(argument);
  }
}
if (files.length !== 1 || typeof flags.target !== "string" || typeof flags.program !== "string" ||
    nodeFiles.some((file) => typeof file !== "string")) {
  console.error(USAGE);
  process.exit(2);
}

// ---- The two bridge primitives of certificates, on the X.509 implementation of Node ----

/** The bytes of a value of the bridge (base64url or standard base64). */
function bytesOf(value) {
  return Buffer.from(String(value).replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, ""), "base64");
}

/** x509Verify: the leaf chains to one of the anchors over the intermediates given (in any
 *  order), every signature of the chain verifies, every certificate of it is valid at atEpochS
 *  and every certificate above the leaf is a certificate authority. */
function x509Verify(args) {
  try {
    const at = Number(args.atEpochS) * 1000;
    const read = (value) => new crypto.X509Certificate(bytesOf(value));
    const valid = (certificate) => Date.parse(certificate.validFrom) <= at && at <= Date.parse(certificate.validTo);
    const issued = (certificate, issuer) => certificate.checkIssued(issuer) && certificate.verify(issuer.publicKey);
    const anchors = args.anchors.map(read);
    const pool = args.intermediates.map(read);
    let current = read(args.leaf);
    if (!valid(current)) return { ok: false, error: "the leaf is not valid at the time given" };
    for (let depth = 0; depth <= pool.length; depth += 1) {
      const subject = current;
      const anchor = anchors.find((item) => issued(subject, item));
      if (anchor !== undefined) {
        return anchor.ca && valid(anchor)
          ? { ok: true, error: null }
          : { ok: false, error: "the anchor is no certificate authority that is valid at the time given" };
      }
      const next = pool.find((item) => issued(subject, item));
      if (next === undefined) return { ok: false, error: "no certificate given issued a certificate of the chain" };
      if (!next.ca || !valid(next)) {
        return { ok: false, error: "an intermediate is no certificate authority that is valid at the time given" };
      }
      current = next;
    }
    return { ok: false, error: "the chain does not end at an anchor" };
  } catch (error) {
    return { ok: false, error: String((error && error.message) || error) };
  }
}

/** x509PublicKey: {algorithm, bits, publicKey} of a certificate, the public key of an EC key as
 *  its uncompressed point. */
function x509PublicKey(certificate) {
  const key = new crypto.X509Certificate(bytesOf(certificate)).publicKey;
  if (key.asymmetricKeyType !== "ec") return { algorithm: String(key.asymmetricKeyType), bits: 0, publicKey: "" };
  const jwk = key.export({ format: "jwk" });
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]);
  return { algorithm: "ec", bits: { "P-256": 256, "P-384": 384, "P-521": 521 }[jwk.crv] || 0, publicKey: point.toString("base64url") };
}

// ---- The program ----

// The program, with one line before its end that hands out the verdicts and what they are
// verified with. Nothing else of the source changes.
const source = fs.readFileSync(flags.program, "utf8");
const end = source.lastIndexOf("})();");
if (end < 0 || source.indexOf("function proveRelease(") < 0) {
  console.error("the program holds no verdict of release proofs: " + flags.program);
  process.exit(2);
}
const handed = source.slice(0, end) +
  "  globalThis.releaseProofsVerdict = { proveRelease: proveRelease, releaseTrust: releaseTrust, version: VERSION,\n" +
  "    verifyAttestation: verifyAttestation, verifyNitro: verifyNitro, decode: decode, encode: encode, text: text };\n" +
  source.slice(end);
const world = new bridge.World({ serverTarget: flags.target });
world.bridgeOpen = false;
const native = Object.assign({}, bridge.makeNative(world), nodeFiles.length > 0 ? { x509Verify: x509Verify, x509PublicKey: x509PublicKey } : {});
const context = vm.createContext({
  native: Object.freeze(native), SecureError: bridge.SecureError, console: { log: () => {} },
});
vm.runInContext(handed, context, { filename: path.basename(flags.program) });
world.bridgeOpen = true;
const verdict = context.releaseProofsVerdict;

// ---- The proofs ----

const proofs = JSON.parse(fs.readFileSync(files[0], "utf8"));
let stated = null;
try {
  stated = JSON.parse(Buffer.from(String(proofs.statement), "base64url").toString("utf8"));
} catch (error) {
  stated = null;
}
const measurement = stated !== null && typeof stated === "object"
  ? { pcr0: stated.pcr0, pcr1: stated.pcr1, pcr2: stated.pcr2 } : { pcr0: "", pcr1: "", pcr2: "" };
const name = "program version " + verdict.version + ", server target " + flags.target + ": ";
let accepted = false;
try {
  const shown = verdict.proveRelease(proofs, measurement, verdict.releaseTrust(), flags.target);
  if (shown.programMin > verdict.version) {
    console.log(name + "the proofs hold, and the statement of release " + shown.release + " states program " +
      shown.programMin + " or later: the release is none this program accepts");
  } else {
    console.log(name + "the proofs show release " + shown.release + " (program_min " + shown.programMin + ")");
    accepted = true;
  }
} catch (error) {
  if (!error || error.code !== "release_unproven") throw error;
  console.log(name + "refused: " + error.message);
}

// ---- The nodes ----

/** A value of a binding as it is printed: its JSON, or "none" for a key the binding lacks. */
function written(value) {
  return value === undefined ? "none" : JSON.stringify(value);
}

/** Prints what the document and the binding of one attestation response state and what the
 *  program makes of the response when it carries the proofs. Returns whether the node presents
 *  the measurement of the statement and receives a grant. */
function judgeNode(response, label) {
  console.log(label + ":");
  if (response === null || typeof response !== "object" || typeof response.document !== "string") {
    console.log("  no attestation response: an object with the member document is expected (docs/protocol.md 4.2)");
    return false;
  }
  if (response.platform !== "nitro") {
    console.log("  platform " + written(response.platform) + ": release proofs show the measurement of a nitro document, and this response carries none");
    return false;
  }
  let read = null;
  try {
    read = verdict.verifyNitro(verdict.decode(response.document), null, true);
  } catch (error) {
    if (!error || error.code !== "attestation_failed") throw error;
    console.log("  the document does not verify: " + error.message);
    return false;
  }
  console.log("  the document verifies (the certificate chain to the root the program holds, at the time of the document " +
    new Date(read.timeMs).toISOString() + ", and the signature of its certificate)");
  let same = true;
  for (const pcr of ["pcr0", "pcr1", "pcr2"]) {
    const equal = read.measurement[pcr] === measurement[pcr];
    if (!equal) same = false;
    console.log("  " + pcr + " " + read.measurement[pcr] + (equal ? ": that of the statement" : ": NOT that of the statement (" + measurement[pcr] + ")"));
  }
  let binding = null;
  try {
    binding = JSON.parse(verdict.text(read.binding));
  } catch (error) {
    binding = null;
  }
  if (binding === null || typeof binding !== "object") {
    console.log("  the binding is no JSON object");
  } else {
    console.log("  binding: release " + written(binding.release) + ", log " + written(binding.log) + ", role " + written(binding.role) +
      ", program_min " + written(binding.program_min));
  }
  let granted = false;
  const logged = world.logs.length;
  try {
    const verified = verdict.verifyAttestation(Object.assign({}, response, { release_proofs: proofs }), verdict.encode(read.nonce), true);
    if (!verified.listed) {
      const refusal = world.logs.slice(logged).filter((line) => line.indexOf("release ") === 0);
      console.log("  the program hands this node no grant: its measurement is one no list of the program has and no release proofs showed" +
        (refusal.length > 0 ? " (" + refusal.join("; ") + ")" : ""));
    } else if (verified.programMin > verdict.version) {
      console.log("  the program hands this node no grant: its binding states program_min " + verified.programMin +
        ", and the node takes the grant command of that program or a later one");
    } else {
      console.log("  the program hands this node a grant: release " + verified.release + ", log format " + verified.format +
        (verified.role === undefined ? "" : ", role " + verified.role));
      granted = true;
    }
  } catch (error) {
    if (!error || error.code !== "attestation_failed") throw error;
    console.log("  the program hands this node no grant: attestation rejected: " + error.message);
  }
  return same && granted;
}

let nodes = true;
for (const file of nodeFiles) {
  const answer = JSON.parse(fs.readFileSync(file, "utf8"));
  const responses = answer !== null && typeof answer === "object" && Array.isArray(answer.nodes) ? answer.nodes : [answer];
  if (responses.length === 0) {
    console.log(file + ": no attestation response");
    nodes = false;
  }
  responses.forEach((response, index) => {
    const id = response !== null && typeof response === "object" && typeof response.node === "string" ? " (" + response.node + ")" : "";
    if (!judgeNode(response, file + ", response " + (index + 1) + id)) nodes = false;
  });
}
process.exit(accepted && nodes ? 0 : 1);
