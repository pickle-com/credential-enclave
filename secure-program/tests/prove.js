// The verdict of the secure program on release proofs read from a file (docs/protocol.md, "The
// release proofs"). Release proofs are public values: whoever makes or carries them can ask the
// program of a version what it makes of them before a node of the release takes a key.
//
//   node secure-program/tests/prove.js RELEASE_PROOFS_JSON [--target prod|dev|alpha] [--program PROGRAM_JS]
//
// RELEASE_PROOFS_JSON holds {statement, entry, deploy_signatures, attestation}. The measurement is
// the one the statement states. The program (secure-program.js of this checkout unless --program
// names another source) runs with its constants as they are: its release key, its log key, its
// certificates, its deploy keys, its list of accepted releases and its version. The signatures
// are verified by the model of the bridge (bridge.js). The file prints what the program makes of
// the proofs for a build of the server target (prod unless --target names another) and ends
// with the status 0 when the proofs make the release one that program accepts, and 1 otherwise.
//
// The verdict is that of the five checks on the proofs alone. Whether a node presents the
// measurement the statement states, and what the binding of that node states (the program
// requires its release to be the release of the statement, and reads its log, role and
// program_min), is the attestation of the node: this file reads no node.
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const bridge = require("./bridge.js");

const flags = { target: "prod", program: path.join(__dirname, "..", "secure-program.js") };
const files = [];
for (let at = 2; at < process.argv.length; at += 1) {
  const argument = process.argv[at];
  if (argument === "--target" || argument === "--program") {
    flags[argument.slice(2)] = process.argv[at + 1];
    at += 1;
  } else {
    files.push(argument);
  }
}
if (files.length !== 1 || typeof flags.target !== "string" || typeof flags.program !== "string") {
  console.error("usage: node prove.js RELEASE_PROOFS_JSON [--target prod|dev|alpha] [--program PROGRAM_JS]");
  process.exit(2);
}

// The program, with one line before its end that hands out the verdict and what it is verified
// with. Nothing else of the source changes.
const source = fs.readFileSync(flags.program, "utf8");
const end = source.lastIndexOf("})();");
if (end < 0 || source.indexOf("function proveRelease(") < 0) {
  console.error("the program holds no verdict of release proofs: " + flags.program);
  process.exit(2);
}
const handed = source.slice(0, end) +
  "  globalThis.releaseProofsVerdict = { proveRelease: proveRelease, releaseTrust: releaseTrust, version: VERSION };\n" +
  source.slice(end);
const world = new bridge.World({ serverTarget: flags.target });
world.bridgeOpen = false;
const context = vm.createContext({
  native: Object.freeze(bridge.makeNative(world)), SecureError: bridge.SecureError, console: { log: () => {} },
});
vm.runInContext(handed, context, { filename: path.basename(flags.program) });
world.bridgeOpen = true;
const verdict = context.releaseProofsVerdict;

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
try {
  const shown = verdict.proveRelease(proofs, measurement, verdict.releaseTrust(), flags.target);
  if (shown.programMin > verdict.version) {
    console.log(name + "the proofs hold, and the statement of release " + shown.release + " states program " +
      shown.programMin + " or later: the release is none this program accepts");
    process.exit(1);
  }
  console.log(name + "the proofs show release " + shown.release + " (program_min " + shown.programMin + ")");
} catch (error) {
  if (!error || error.code !== "release_unproven") throw error;
  console.log(name + "refused: " + error.message);
  process.exit(1);
}
