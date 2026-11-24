// The verdict of the secure program on release proofs read from a file (docs/protocol.md, "The
// release proofs"), on the attestations GitHub holds of a release statement, and on what a node
// of that release answered a request for its attestation. Release proofs are public values:
// whoever makes or carries them can ask the program of a version what it makes of them before a
// node of the release takes a key.
//
//   node secure-program/tests/prove.js RELEASE_PROOFS_JSON [--attestation ATTESTATIONS_JSON]
//       [--node ATTESTATION_RESPONSE_JSON]... [--target prod|dev|alpha] [--program PROGRAM_JS]
//   node secure-program/tests/prove.js --statement MEASUREMENTS_JSON --attestation ATTESTATIONS_JSON
//       [--program PROGRAM_JS]
//
// RELEASE_PROOFS_JSON holds {statement, entry, deploy_signatures, attestation}. The measurement is
// the one the statement states. The program (secure-program.js of this checkout unless --program
// names another source) runs with its constants as they are: its release key, its log key, its
// certificates, its deploy keys, the workflow and the commit it takes an attestation of, its list
// of accepted releases and its version. The signatures are verified by the model of the bridge
// (bridge.js). The file prints what the program makes of the proofs for a build of the server
// target (prod unless --target names another) and ends with the status 0 when the proofs make
// the release one that program accepts, and 1 otherwise.
//
// --attestation names a file with attestations of the release statement: one Sigstore bundle,
// bundles one a line, or the answer of the attestation API of GitHub ({attestations: [{bundle}]}).
// A release may have several (the job of the release workflow makes one, and the job of the
// build workflow another): the program takes the one of the job of the build workflow at the
// commit it holds. For every bundle of the file this file prints what the fourth check (P4)
// makes of it: each value the certificate states of the run (the extensions
// 1.3.6.1.4.1.57264.1.{8..22}) beside the value the program requires, the other checks of the
// bundle, and the predicate beside the statement. With RELEASE_PROOFS_JSON the attestation of
// the proofs is then the bundle of the file that the program takes. With --statement (the file
// measurements.json of the release) and no proofs, the file prints that report alone and ends
// with the status 0 when P4 holds for a bundle of the file.
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

const USAGE = "usage: node prove.js RELEASE_PROOFS_JSON [--attestation ATTESTATIONS_JSON] [--node ATTESTATION_RESPONSE_JSON]... " +
  "[--target prod|dev|alpha] [--program PROGRAM_JS]\n" +
  "       node prove.js --statement MEASUREMENTS_JSON --attestation ATTESTATIONS_JSON [--program PROGRAM_JS]";

const flags = { target: "prod", program: path.join(__dirname, "..", "secure-program.js"), attestation: null, statement: null };
const files = [];
const nodeFiles = [];
for (let at = 2; at < process.argv.length; at += 1) {
  const argument = process.argv[at];
  if (argument === "--target" || argument === "--program" || argument === "--attestation" || argument === "--statement") {
    flags[argument.slice(2)] = process.argv[at + 1];
    at += 1;
  } else if (argument === "--node") {
    nodeFiles.push(process.argv[at + 1]);
    at += 1;
  } else {
    files.push(argument);
  }
}
const alone = files.length === 0 && typeof flags.statement === "string" && typeof flags.attestation === "string" && nodeFiles.length === 0;
const whole = files.length === 1 && flags.statement === null && (flags.attestation === null || typeof flags.attestation === "string");
if ((!alone && !whole) || typeof flags.target !== "string" || typeof flags.program !== "string" ||
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
if (flags.attestation !== null && source.indexOf("function identityStated(") < 0) {
  console.error("the program does not judge the certificate of an attestation as this file reports it: " + flags.program);
  process.exit(2);
}
const handed = source.slice(0, end) +
  "  globalThis.releaseProofsVerdict = { proveRelease: proveRelease, releaseTrust: releaseTrust, version: VERSION,\n" +
  "    verifyAttestation: verifyAttestation, verifyNitro: verifyNitro, decode: decode, encode: encode, text: text,\n" +
  "    readReleaseStatement: readReleaseStatement, decodeStrict: decodeStrict, readCertificate: readCertificate,\n" +
  "    fulcioText: fulcioText, attestedStatement: attestedStatement,\n" +
  "    attestedIdentity: typeof attestedIdentity === \"function\" ? attestedIdentity : null,\n" +
  "    identityStated: typeof identityStated === \"function\" ? identityStated : null,\n" +
  "    predicateType: PROOF_PREDICATE_TYPE };\n" +
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

// ---- The attestations of the release statement ----

// The names of the extensions 1.3.6.1.4.1.57264.1.{number} of a certificate of Fulcio.
const EXTENSIONS = {
  8: "Issuer", 9: "Build Signer URI", 10: "Build Signer Digest", 11: "Runner Environment", 12: "Source Repository URI",
  13: "Source Repository Digest", 14: "Source Repository Ref", 15: "Source Repository Identifier",
  16: "Source Repository Owner URI", 17: "Source Repository Owner Identifier", 18: "Build Config URI",
  19: "Build Config Digest", 20: "Build Trigger", 21: "Run Invocation URI", 22: "Source Repository Visibility At Signing",
};

/** The Sigstore bundles of a file: one bundle, an array of bundles, the answer of the
 *  attestation API of GitHub ({attestations: [{bundle}]}), or one of these on every line. */
function bundlesOf(file) {
  const content = fs.readFileSync(file, "utf8");
  const found = [];
  const take = (value) => {
    if (Array.isArray(value)) {
      value.forEach(take);
    } else if (value !== null && typeof value === "object") {
      if (Array.isArray(value.attestations)) value.attestations.forEach(take);
      else if (value.bundle !== null && typeof value.bundle === "object") found.push(value.bundle);
      else found.push(value);
    }
  };
  try {
    take(JSON.parse(content));
  } catch (error) {
    for (const line of content.split("\n")) {
      if (line.trim() !== "") take(JSON.parse(line));
    }
  }
  return found;
}

/** What the program reads of a release statement (its bytes): the value of readReleaseStatement,
 *  or null. */
function statedOf(bytes) {
  const decoded = verdict.decodeStrict(Buffer.from(bytes).toString("base64url"), true);
  return decoded === null ? null : verdict.readReleaseStatement(decoded);
}

/** Prints what P4 makes of one bundle for a statement the program read (stated). Returns
 *  {signer, holds}: whether the certificate is that of the job of the build workflow at the
 *  commit the program holds, and whether P4 holds. */
function judgeAttestation(bundle, stated, label) {
  console.log(label + ":");
  let leaf = null;
  try {
    const der = verdict.decodeStrict(bundle.verificationMaterial.certificate.rawBytes, false);
    leaf = der === null ? null : verdict.readCertificate(der);
  } catch (error) {
    leaf = null;
  }
  if (leaf === null) {
    console.log("  no certificate that reads (verificationMaterial.certificate.rawBytes)");
    console.log("  P4: fails");
    return { signer: false, holds: false };
  }
  let identity = true;
  let signer = true;
  if (stated.git_commit === null) {
    console.log("  the statement does not state git_commit once as 40 lower-case hexadecimal characters (p4: statement commit)");
    identity = false;
  }
  const required = new Map(verdict.attestedIdentity(stated.release, stated.git_commit).map((item) => [item[0], item]));
  for (let number = 8; number <= 22; number += 1) {
    const text = verdict.fulcioText(leaf, number);
    const item = required.get(number);
    const head = "  extension " + String(number).padStart(2, " ") + " (" + EXTENSIONS[number] + "): " + (text === undefined ? "absent" : JSON.stringify(text));
    if (item === undefined) {
      if (text !== undefined) console.log(head + ": not judged");
      continue;
    }
    const holds = verdict.identityStated(leaf, item);
    if (!holds) {
      identity = false;
      if (number === 9 || number === 10) signer = false;
    }
    console.log(head + (holds ? ": holds" : ": NOT the value required (" + JSON.stringify(item[1]) + (item[2] === "path" ? " before its last \"@\"" : "") + ")") +
      (holds && item[2] === "path" ? " (the text before its last \"@\")" : ""));
  }
  let statement = null;
  let others = true;
  try {
    statement = verdict.attestedStatement(bundle, [], verdict.releaseTrust());
    console.log("  the other checks of the bundle (its form, the certificate under the certificate authority at the time of the log entry, " +
      "the signature of the envelope, the entry of the log, its signed entry timestamp, its inclusion proof and its checkpoint): hold");
  } catch (error) {
    if (!error || error.code !== "release_unproven") throw error;
    others = false;
    console.log("  the other checks of the bundle fail at: " + error.message);
  }
  let predicate = statement !== null;
  if (statement !== null) {
    if (statement.predicateType !== verdict.predicateType) {
      predicate = false;
      console.log("  predicate type " + JSON.stringify(statement.predicateType) + ": NOT " + JSON.stringify(verdict.predicateType));
    }
    const stands = statement.predicate !== null && typeof statement.predicate === "object" ? statement.predicate : {};
    const differing = ["release", "pcr0", "pcr1", "pcr2", "program_min", "git_commit"].filter((name) => stands[name] !== stated[name]);
    if (differing.length > 0) predicate = false;
    console.log("  predicate: " + (differing.length === 0
      ? "its release, pcr0, pcr1, pcr2, program_min and git_commit are those of the statement"
      : "NOT that of the statement in " + differing.join(", ")));
  }
  const holds = identity && others && predicate;
  console.log("  P4: " + (holds ? "holds" : "fails"));
  return { signer: signer, holds: holds };
}

/** Prints the report of every bundle of the file of --attestation for the statement the program
 *  read. Returns the bundle the program takes (the first bundle of the job of the build
 *  workflow at the commit the program holds for which P4 holds, or the first of that job), or
 *  null when the file holds no bundle of that job; held is whether P4 holds for it. */
function chooseAttestation(stated) {
  const bundles = bundlesOf(flags.attestation);
  if (bundles.length === 0) console.log(flags.attestation + ": no bundle");
  let chosen = null;
  let held = false;
  bundles.forEach((bundle, index) => {
    const judged = judgeAttestation(bundle, stated, flags.attestation + ", bundle " + (index + 1));
    if (judged.signer && (chosen === null || (judged.holds && !held))) {
      chosen = bundle;
      held = judged.holds;
    }
  });
  if (bundles.length > 0 && chosen === null) {
    console.log(flags.attestation + ": no bundle of the job of the build workflow at the commit the program holds");
  }
  return { bundle: chosen, held: held };
}

if (alone) {
  const stated = statedOf(fs.readFileSync(flags.statement));
  if (stated === null) {
    console.log(flags.statement + ": no release statement the program reads (p1: statement)");
    process.exit(1);
  }
  console.log("program version " + verdict.version + ": release statement of " + stated.release + ", git_commit " + JSON.stringify(stated.git_commit));
  process.exit(chooseAttestation(stated).held ? 0 : 1);
}

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
if (flags.attestation !== null) {
  const read = typeof proofs.statement === "string" ? statedOf(Buffer.from(proofs.statement, "base64url")) : null;
  if (read === null) {
    console.log(flags.attestation + ": not read, the proofs hold no release statement the program reads");
  } else {
    const chosen = chooseAttestation(read);
    if (chosen.bundle !== null) proofs.attestation = chosen.bundle;
  }
}
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
