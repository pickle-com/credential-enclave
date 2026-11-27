// Release proofs that differ in one place from proofs that hold, each with the check that
// refuses them (docs/protocol.md, "The release proofs"). The proofs are made by the model of
// proofs.js: every other part of a case is signed and recorded as for proofs that hold, so the
// check named is the one that the case fails.
"use strict";

const crypto = require("node:crypto");
const model = require("./proofs.js");

const { b64, b64u, der } = model;

function randomMeasurement() {
  return {
    pcr0: crypto.randomBytes(48).toString("hex"), pcr1: crypto.randomBytes(48).toString("hex"),
    pcr2: crypto.randomBytes(48).toString("hex"),
  };
}

/** The same PCR with another first character. */
function otherPcr(pcr) {
  return (pcr[0] === "0" ? "1" : "0") + pcr.slice(1);
}

/** The cases for a release. Returns [{name, reason, proofs, measurement, release, constants,
 *  logs, builders, debug}]: reason is null for proofs that hold, and the text the program logs
 *  for the check that refuses the others (shape, or v{number of the check}: {what failed});
 *  measurement and release are those of the node that presents the measurement; constants are
 *  the parties whose keys and certificates the program holds; logs are the keys of the logs the
 *  program holds (null: the key of the log of the constants); builders are the build workflows
 *  the program takes (null: those of the program of this checkout); debug is true for the
 *  proofs of a measurement no node presents (a PCR of it is all zero). */
function proofCases(release) {
  const parties = model.makeParties();
  const measurement = randomMeasurement();
  const cases = [];
  const add = (name, reason, proofs, more) => cases.push(Object.assign({
    name: name, reason: reason, proofs: proofs, measurement: measurement, release: release,
    constants: parties, logs: null, builders: null,
  }, more || {}));
  const proofsOf = (options, forRelease, forMeasurement) =>
    model.proofsOf(parties, forRelease || release, forMeasurement || measurement, options);
  const edited = (edit, options) => {
    const proofs = proofsOf(options);
    edit(proofs);
    return proofs;
  };
  const statementOf = (more, forRelease, forMeasurement) =>
    model.statementOf(forRelease || release, forMeasurement || measurement, more);
  /** Proofs of a statement of other bytes, attested as that statement. */
  const ofStatement = (statement, attested) => proofsOf({ statement: statement, attested: attested });
  /** A commit that differs from commit in its first character. */
  const otherCommit = (commit) => (commit[0] === "0" ? "1" : "0") + commit.slice(1);

  // ---- Proofs that hold ----
  add("proofs that hold", null, proofsOf());
  add("a statement with members the program does not read", null, ofStatement(statementOf({ note: ["x", { y: 1 }] })));
  add("a statement that states program_min, a member the program does not read", null,
    ofStatement(statementOf({ program_min: 99 })));
  add("proofs with members the program does not read", null, edited((proofs) => { proofs.note = "x"; }));
  add("proofs with the members entry and deploy_signatures, which the program does not read", null, edited((proofs) => {
    proofs.entry = { log_id: "00", body: "e30=", integrated_time: 1, log_index: 1, signed_entry_timestamp: "AA==" };
    proofs.deploy_signatures = [{ key_id: "prod", signature: b64(crypto.randomBytes(64)) }];
  }));
  // The name of a release is the name of its tag: a text that begins with v. No release is
  // compared with another.
  for (const tag of ["v1.0.0", "v2.3.0", release + "-rc.1", "v2.5.0-beta.1", "v2.5", "v02.5.0", "v2.5.0.1", "v2026.11.24_a-B",
    "v4294967296.0.0", "v9"]) {
    add("the release " + JSON.stringify(tag), null,
      proofsOf({ statement: statementOf({}, tag), attested: Object.assign({ release: tag }, measurement) }, tag), { release: tag });
  }

  // ---- The shape ----
  for (const [name, value] of [["null", null], ["an array", []], ["a text", "proofs"], ["a number", 7]]) {
    add("proofs that are " + name, "shape", value);
  }
  for (const part of ["statement", "attestation"]) {
    add("proofs without " + part, "shape", edited((proofs) => { delete proofs[part]; }));
  }
  add("proofs whose statement is no text", "shape", edited((proofs) => { proofs.statement = 7; }));
  add("proofs whose attestation is an array", "shape", edited((proofs) => { proofs.attestation = [proofs.attestation]; }));
  add("proofs whose attestation is a text", "shape", edited((proofs) => { proofs.attestation = JSON.stringify(proofs.attestation); }));
  add("proofs with half of a surrogate pair in a text", "shape", edited((proofs) => { proofs.note = "\ud83d"; }));
  add("proofs with arrays inside one another beyond the depth the program reads", "shape", edited((proofs) => {
    let nested = [];
    for (let depth = 0; depth < 40; depth += 1) nested = [nested];
    proofs.note = nested;
  }));

  // ---- V1: the release statement ----
  add("a statement in base64 with padding", "v1: statement", edited((proofs) => { proofs.statement += "="; }));
  // The bytes ??? and >>> give a character of the standard alphabet that the URL-safe one lacks.
  const marked = statementOf({ note: "???>>>" });
  add("a statement in the standard alphabet of base64", "v1: statement",
    edited((proofs) => { proofs.statement = b64(marked).replace(/=+$/, ""); }, { statement: marked }));
  add("a statement that is no base64", "v1: statement", edited((proofs) => { proofs.statement = "*" + proofs.statement; }));
  add("a statement of more than 16,384 bytes", "v1: statement", ofStatement(statementOf({ padding: "x".repeat(16300) })));
  add("a statement that is no JSON", "v1: statement", ofStatement(Buffer.from("release " + release, "utf8")));
  add("a statement that is a JSON array", "v1: statement", ofStatement(Buffer.from(JSON.stringify([JSON.parse(statementOf().toString())]), "utf8")));
  add("a statement that is no UTF-8", "v1: statement",
    ofStatement(Buffer.concat([statementOf().subarray(0, 4), Buffer.from([0xff]), statementOf().subarray(4)])));
  add("a statement with a byte order mark", "v1: statement", ofStatement(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), statementOf()])));
  for (const field of ["release", "git_commit", "pcr0", "pcr1", "pcr2"]) {
    const value = JSON.parse(statementOf().toString());
    const twice = statementOf().toString().replace("{", "{\n  " + JSON.stringify(field) + ": " + JSON.stringify(value[field]) + ",");
    add("a statement that states " + field + " twice", "v1: statement", ofStatement(Buffer.from(twice, "utf8")));
    const missing = Object.assign({}, value);
    delete missing[field];
    add("a statement without " + field, "v1: statement", ofStatement(Buffer.from(JSON.stringify(missing), "utf8")));
  }
  add("a statement that states pcr0 twice, once with an escaped key", "v1: statement", ofStatement(Buffer.from(
    statementOf().toString().replace("{", "{\n  \"pcr\\u0030\": " + JSON.stringify(measurement.pcr0) + ","), "utf8")));
  add("a statement with a PCR in upper case", "v1: statement", ofStatement(statementOf({ pcr1: measurement.pcr1.toUpperCase() })));
  add("a statement with a PCR of 95 characters", "v1: statement", ofStatement(statementOf({ pcr2: measurement.pcr2.slice(1) })));
  add("a statement whose release is a number", "v1: statement", ofStatement(statementOf({ release: 2 })));
  for (const tag of ["dev", "2.5.0", "V2.5.0", "v", "", "v2.5.0 ", " v2.5.0", "v2.5.0\n", "v2.5.0+build", "v2.5/0", "release-v2.5.0", "v2.5.0é"]) {
    add("a statement whose release is " + JSON.stringify(tag), "v1: statement",
      model.proofsOf(parties, tag, measurement, {
        statement: model.statementOf(tag, measurement), attested: Object.assign({ release: tag }, measurement),
      }));
  }
  for (const [name, value] of [
    ["in upper case", model.COMMIT.toUpperCase()], ["of 39 characters", model.COMMIT.slice(1)], ["of 41 characters", model.COMMIT + "0"],
    ["a number", 7], ["null", null], ["the name of a branch", "main"],
  ]) {
    add("a statement whose git_commit is " + name, "v1: statement", ofStatement(statementOf({ git_commit: value })));
  }
  for (const field of ["pcr0", "pcr1", "pcr2"]) {
    const other = Object.assign({}, measurement, { [field]: otherPcr(measurement[field]) });
    add("the proofs of another measurement: one character of " + field, "v1: measurement", proofsOf({}, release, other));
  }
  // A PCR whose value is all zero is the value of an enclave in debug mode. The document of such
  // an enclave fails the attestation, so no node presents these proofs: they reach the program
  // for the digest of a measurement that an entry names (debug).
  const zero = "0".repeat(96);
  for (const [name, debug] of [
    ["pcr0", Object.assign({}, measurement, { pcr0: zero })], ["pcr1", Object.assign({}, measurement, { pcr1: zero })],
    ["pcr2", Object.assign({}, measurement, { pcr2: zero })], ["every PCR", { pcr0: zero, pcr1: zero, pcr2: zero }],
  ]) {
    add("the proofs of a measurement whose " + name + " is all zero", "v1: statement", proofsOf({}, release, debug),
      { measurement: debug, debug: true });
  }

  // ---- V2: the form of the attestation ----
  const otherLog = model.makeLog("other.example - 2");
  const otherKey = model.ecKeyPair("prime256v1");
  const attested = (options, edit) => {
    const proofs = proofsOf({ attestation: options });
    if (edit) edit(proofs.attestation);
    return proofs;
  };
  const entryOfBundle = (bundle) => bundle.verificationMaterial.tlogEntries[0];
  add("an attestation without a certificate", "v2: shape", attested({}, (bundle) => { delete bundle.verificationMaterial.certificate; }));
  add("an attestation with two log entries", "v2: shape", attested({}, (bundle) => {
    bundle.verificationMaterial.tlogEntries.push(entryOfBundle(bundle));
  }));
  add("an attestation without a log entry", "v2: shape", attested({}, (bundle) => { bundle.verificationMaterial.tlogEntries = []; }));
  add("an envelope with two signatures", "v2: shape", attested({}, (bundle) => {
    bundle.dsseEnvelope.signatures.push(bundle.dsseEnvelope.signatures[0]);
  }));
  add("an envelope without a signature", "v2: shape", attested({}, (bundle) => { bundle.dsseEnvelope.signatures = []; }));
  add("an envelope without a payload", "v2: shape", attested({}, (bundle) => { delete bundle.dsseEnvelope.payload; }));
  add("an attestation of more than 65,536 bytes", "v2: size", attested({}, (bundle) => { bundle.note = "x".repeat(66000); }));
  add("an envelope of another payload type", "v2: payload", attested({ payloadType: "application/vnd.other+json" }));
  add("a payload that is no JSON object", "v2: payload", attested({ statement: ["release"] }));
  add("a payload in base64url", "v2: payload", attested({}, (bundle) => {
    bundle.dsseEnvelope.payload = b64u(Buffer.from(bundle.dsseEnvelope.payload, "base64")) + "_";
  }));

  // ---- V3: the certificate under the certificate authority ----
  add("a certificate that is no DER", "v3: certificate", attested({}, (bundle) => {
    bundle.verificationMaterial.certificate.rawBytes = b64(Buffer.from("certificate"));
  }));
  add("a certificate with bytes behind it", "v3: certificate", attested({}, (bundle) => {
    const certificate = bundle.verificationMaterial.certificate;
    certificate.rawBytes = b64(Buffer.concat([Buffer.from(certificate.rawBytes, "base64"), Buffer.from([0])]));
  }));
  add("a certificate that states the runner twice", "v3: certificate", attested({
    certificate: { extensions: [der.sequence(der.oid("1.3.6.1.4.1.57264.1.11"), der.octets(der.utf8("github-hosted")))] },
  }));
  add("a log entry time before the validity of the certificate", "v3: certificate validity", attested({ integratedTime: 1794999999 }));
  add("a log entry time after the validity of the certificate", "v3: certificate validity", attested({ integratedTime: 1795000601 }));
  add("a log entry time at the first second of the validity of the certificate", null, attested({ integratedTime: 1795000000 }));
  add("a log entry time at the last second of the validity of the certificate", null, attested({ integratedTime: 1795000600 }));
  add("a certificate of a certificate authority", "v3: certificate authority", attested({ certificate: { authority: true } }));
  const sameNames = model.makeAuthority();
  add("a certificate that another authority of the same names issued", "v3: certificate issuer", attested({ issuer: sameNames }));
  add("a certificate the root issued", "v3: certificate issuer", attested({
    certificate: { signer: parties.authority.rootKey, issuer: parties.authority.rootName },
  }));
  add("a certificate the root signed under the name of the intermediate", "v3: certificate issuer", attested({
    certificate: { signer: parties.authority.rootKey },
  }));
  add("a certificate signed with SHA-256 by the intermediate", null, attested({ certificate: { hash: "sha256" } }));
  const otherRoot = Object.assign({}, parties, { authority: Object.assign({}, parties.authority, { root: sameNames.root }) });
  add("an intermediate that the root of the program did not issue", "v3: certificate root", proofsOf(), { constants: otherRoot });
  const expiredRoot = model.makeAuthority({ notAfter: 1794000000 });
  const expired = Object.assign({}, parties, { authority: expiredRoot });
  add("a root and an intermediate that ended before the time of the log entry", "v3: certificate validity",
    model.proofsOf(expired, release, measurement), { constants: expired });

  // ---- V6: what the certificate states of the run ----
  const identity = model.identityOf(release);
  const pins = model.PINS;
  const build = model.REPOSITORY + "/" + pins.workflow;
  const caller = model.REPOSITORY + "/" + pins.caller;
  const others = {
    8: ["https://gitlab.com"],
    // The workflow of the job that signed: another workflow file of the repository at the
    // commit the program holds, the build workflow of a repository of another owner, the
    // release workflow itself at the tag (a job that no workflow called), the build workflow
    // without a ref and with an empty one, and a file whose name begins with its name.
    9: [model.REPOSITORY + "/.github/workflows/other.yml@" + pins.commit,
      "https://github.com/someone/credential-enclave/" + pins.workflow + "@" + pins.commit,
      caller + "@refs/tags/" + release, build, build + "@", build + "@other.yml@" + pins.commit],
    10: [otherCommit(pins.commit), pins.commit.slice(1), pins.commit.toUpperCase()],
    11: ["self-hosted"],
    12: ["https://github.com/someone/credential-enclave", model.REPOSITORY + "/"],
    13: [otherCommit(model.COMMIT), model.COMMIT.slice(1)],
    14: ["refs/heads/main", "refs/tags/" + release + "-rc.1", "refs/heads/tags/" + release, "refs/tags/" + release.slice(0, -1)],
    15: ["1400118249"],
    17: ["151645825"],
    20: ["workflow_dispatch", "release"],
    22: ["private", "internal"],
  };
  for (const number of Object.keys(others)) {
    for (const value of others[number]) {
      add("a certificate whose extension " + number + " is " + JSON.stringify(value) + " in the place of " + JSON.stringify(identity[number]),
        "v6: identity " + number, attested({ identity: { [number]: value } }), { identity: Number(number) });
    }
    add("a certificate without the extension " + number, "v6: identity " + number, attested({ identity: { [number]: null } }),
      { identity: Number(number) });
  }
  add("a certificate whose extension 11 is a text that is no DER", "v6: identity 11", attested({
    identity: { 11: null },
    certificate: { extensions: [der.sequence(der.oid("1.3.6.1.4.1.57264.1.11"), der.octets(Buffer.from("github-hosted")))] },
  }), { identity: 11 });
  // What follows the last "@" of the extension 9 names the ref the caller wrote: it is not
  // judged, and the commit of the workflow file is (the extension 10).
  add("the build workflow named by a branch whose head is the commit the program holds", null,
    attested({ identity: { 9: build + "@refs/heads/main" } }));
  add("the build workflow named by a tag at the commit the program holds", null,
    attested({ identity: { 9: build + "@refs/tags/" + release } }));
  add("the build workflow called at another commit", "v6: identity 10",
    attested({ identity: { 9: build + "@" + otherCommit(pins.commit), 10: otherCommit(pins.commit) } }), { identity: 10 });
  add("the build workflow called by a branch whose head is another commit", "v6: identity 10",
    attested({ identity: { 9: build + "@refs/heads/main", 10: otherCommit(pins.commit) } }), { identity: 10 });
  add("the attestation of a job of the release workflow itself, which no workflow called", "v6: identity 9",
    attested({ identity: { 9: caller + "@refs/tags/" + release, 10: model.COMMIT } }), { identity: 9 });
  add("the attestation of a run in another repository, whose workflow called the build workflow", "v6: identity 12", attested({
    identity: {
      12: "https://github.com/another-owner/another-repository", 15: "999999991", 16: "https://github.com/another-owner",
      17: "999999992", 18: "https://github.com/another-owner/another-repository/.github/workflows/release.yml@refs/tags/" + release,
      21: "https://github.com/another-owner/another-repository/actions/runs/1/attempts/1",
    },
  }), { identity: 12 });
  add("the attestation of another release", "v6: identity 14",
    proofsOf({ attested: Object.assign({ release: release.replace(/\d+$/, "9") + "9" }, measurement) }));
  // The workflow that started the run and called the job (the extension 18) is not judged.
  for (const value of [model.REPOSITORY + "/.github/workflows/caller.yml@refs/tags/" + release, caller + "@refs/heads/main",
    "https://github.com/someone/credential-enclave/" + pins.caller + "@refs/tags/" + release]) {
    add("a certificate whose extension 18 is " + JSON.stringify(value), null, attested({ identity: { 18: value } }));
  }
  add("a certificate without the extension 18", null, attested({ identity: { 18: null } }));
  // The build workflows a program takes are a list: a certificate states one element of it, by
  // its path and by its commit together.
  const second = { workflow: ".github/workflows/enclave-build-2.yml", commit: otherCommit(pins.commit) };
  const secondBuild = model.REPOSITORY + "/" + second.workflow;
  add("the second build workflow of a program that takes two", null,
    attested({ identity: { 9: secondBuild + "@" + second.commit, 10: second.commit } }), { builders: [pins, second] });
  add("the first build workflow of a program that takes two", null, proofsOf(), { builders: [pins, second] });
  add("the path of one build workflow with the commit of the other", "v6: identity 10",
    attested({ identity: { 9: secondBuild + "@" + pins.commit, 10: pins.commit } }), { builders: [pins, second], identity: 10 });
  add("a build workflow the program does not take, of a program that takes another", "v6: identity 9", proofsOf(),
    { builders: [second], identity: 9 });
  add("a program that takes no build workflow", "v6: identity 9", proofsOf(), { builders: [], identity: 9 });
  add("a program whose build workflow names a commit of 39 characters, stated by the certificate", "v6: identity 10",
    attested({ identity: { 10: "0".repeat(39) } }), { builders: [{ workflow: pins.workflow, commit: "0".repeat(39) }], identity: 10 });

  // ---- V5: the signature of the envelope ----
  add("an envelope another key signed", "v5: signature", attested({ signer: model.ecKeyPair("prime256v1") }));
  add("a certificate with a key on P-384", "v5: signature", attested({ curve: "secp384r1" }));
  add("an envelope whose signature is in base64url", "v5: signature", attested({}, (bundle) => {
    const signature = bundle.dsseEnvelope.signatures[0];
    signature.sig = b64u(Buffer.from(signature.sig, "base64")) + "-";
  }));

  // ---- V4: the entry of the transparency log ----
  add("a log entry without a time", "v4: log entry time", attested({}, (bundle) => { delete entryOfBundle(bundle).integratedTime; }));
  add("a log entry whose time is negative", "v4: log entry time", attested({}, (bundle) => { entryOfBundle(bundle).integratedTime = "-1"; }));
  add("a log entry of a log the program does not know", "v4: log", attested({ log: otherLog }));
  add("a log entry that names a log the program does not know", "v4: log", attested({}, (bundle) => {
    entryOfBundle(bundle).logId.keyId = b64(Buffer.from(otherLog.id, "hex"));
  }));
  add("a log entry of another kind", "v4: log entry kind", attested({ record: (record) => { record.kind = "intoto"; } }));
  add("a log entry of another version", "v4: log entry kind", attested({ record: (record) => { record.apiVersion = "0.0.2"; } }));
  add("a log entry of another payload", "v4: log entry payload", attested({
    record: (record) => { record.spec.payloadHash.value = model.sha256(Buffer.from("another payload")).toString("hex"); },
  }));
  add("a log entry of a hash of another algorithm", "v4: log entry payload", attested({
    record: (record) => { record.spec.payloadHash.algorithm = "sha512"; },
  }));
  add("a log entry of another signature", "v4: log entry signature", attested({
    record: (record) => { record.spec.signatures[0].signature = b64(model.ecdsaSign(otherKey, "sha256", Buffer.from("x"))); },
  }));
  add("a log entry of two signatures", "v4: log entry signature", attested({
    record: (record) => { record.spec.signatures.push(record.spec.signatures[0]); },
  }));
  add("a log entry of another certificate", "v4: log entry certificate", attested({
    record: (record) => {
      record.spec.signatures[0].verifier = b64(Buffer.from(model.pem("CERTIFICATE", parties.authority.issue(otherKey, identity)), "utf8"));
    },
  }));
  add("another index than the log signed", "v4: signed entry timestamp", attested({}, (bundle) => {
    entryOfBundle(bundle).logIndex = String(Number(entryOfBundle(bundle).logIndex) + 1);
  }));
  add("another time than the log signed, within the validity of the certificate", "v4: signed entry timestamp", attested({}, (bundle) => {
    entryOfBundle(bundle).integratedTime = String(Number(entryOfBundle(bundle).integratedTime) + 1);
  }));
  // A log of another form (one that signs no entry timestamp) is none this program takes.
  add("a log entry without an inclusion promise", "v4: signed entry timestamp", attested({}, (bundle) => {
    delete entryOfBundle(bundle).inclusionPromise;
  }));
  add("a signed entry timestamp of another key", "v4: signed entry timestamp", attested({}, (bundle) => {
    const entry = entryOfBundle(bundle);
    entry.inclusionPromise.signedEntryTimestamp = otherLog.promise(
      entry.canonicalizedBody, entry.integratedTime, entry.logIndex, parties.log.id);
  }));
  add("a signed entry timestamp with bytes behind the signature", "v4: signed entry timestamp", attested({}, (bundle) => {
    const promise = entryOfBundle(bundle).inclusionPromise;
    promise.signedEntryTimestamp = b64(Buffer.concat([Buffer.from(promise.signedEntryTimestamp, "base64"), Buffer.from([0])]));
  }));
  add("a changed hash of the audit path", "v4: inclusion proof", attested({}, (bundle) => {
    const hashes = entryOfBundle(bundle).inclusionProof.hashes;
    hashes[0] = b64(model.sha256(Buffer.from(hashes[0], "base64")));
  }));
  add("an audit path without its last hash", "v4: inclusion proof", attested({}, (bundle) => {
    entryOfBundle(bundle).inclusionProof.hashes.pop();
  }));
  add("an audit path with one hash more", "v4: inclusion proof", attested({}, (bundle) => {
    entryOfBundle(bundle).inclusionProof.hashes.push(b64(crypto.randomBytes(32)));
  }));
  add("the index of another leaf", "v4: inclusion proof", attested({}, (bundle) => {
    entryOfBundle(bundle).inclusionProof.logIndex = "4";
  }));
  add("an index that is not below the size of the tree", "v4: inclusion proof", attested({}, (bundle) => {
    entryOfBundle(bundle).inclusionProof.logIndex = "11";
  }));
  add("an audit path of 65 hashes", "v4: inclusion proof", attested({}, (bundle) => {
    const proof = entryOfBundle(bundle).inclusionProof;
    proof.hashes = Array.from({ length: 65 }, () => proof.hashes[0]);
  }));
  add("a log entry without an inclusion proof", "v4: inclusion proof", attested({}, (bundle) => {
    delete entryOfBundle(bundle).inclusionProof;
  }));
  add("the last leaf of a tree", null, attested({ leafIndex: 10, treeSize: 11 }));
  add("the only leaf of a tree", null, attested({ leafIndex: 0, treeSize: 1 }));
  add("the first leaf of a tree of 4,096 leaves", null, attested({ leafIndex: 0, treeSize: 4096 }));
  // The four counts of an entry are strings of decimal digits, as a bundle writes them. A
  // count written as a JSON number is none, also a number of the value the log signed: what a
  // JSON number reads as differs between the engines the program runs on for some notations.
  add("a log entry whose time is a JSON number of the time the log signed", "v4: log entry time", attested({}, (bundle) => {
    const entry = entryOfBundle(bundle);
    entry.integratedTime = Number(entry.integratedTime);
  }));
  add("a log entry whose index is a JSON number of the index the log signed", "v4: signed entry timestamp", attested({}, (bundle) => {
    const entry = entryOfBundle(bundle);
    entry.logIndex = Number(entry.logIndex);
  }));
  add("an inclusion proof whose index is a JSON number of the index of the leaf", "v4: inclusion proof", attested({}, (bundle) => {
    const proof = entryOfBundle(bundle).inclusionProof;
    proof.logIndex = Number(proof.logIndex);
  }));
  add("an inclusion proof whose tree size is a JSON number of the size of the tree", "v4: inclusion proof", attested({}, (bundle) => {
    const proof = entryOfBundle(bundle).inclusionProof;
    proof.treeSize = Number(proof.treeSize);
  }));
  add("an inclusion proof whose index is the JSON number zero", "v4: inclusion proof", attested({ leafIndex: 0, treeSize: 1 }, (bundle) => {
    entryOfBundle(bundle).inclusionProof.logIndex = 0;
  }));
  add("a log entry whose time has a zero in front", "v4: log entry time", attested({}, (bundle) => {
    const entry = entryOfBundle(bundle);
    entry.integratedTime = "0" + entry.integratedTime;
  }));
  add("a log entry whose time is a string of digits with a fraction", "v4: log entry time", attested({}, (bundle) => {
    const entry = entryOfBundle(bundle);
    entry.integratedTime = entry.integratedTime + ".0";
  }));
  add("an inclusion proof whose tree size is a string of seventeen digits", "v4: inclusion proof", attested({}, (bundle) => {
    entryOfBundle(bundle).inclusionProof.treeSize = "10000000000000000";
  }));
  const checkpointOf = (edit) => attested({}, (bundle) => {
    const proof = entryOfBundle(bundle).inclusionProof;
    proof.checkpoint.envelope = edit(proof.checkpoint.envelope, Number(proof.treeSize), Buffer.from(proof.rootHash, "base64"));
  });
  add("a checkpoint another key signed", "v4: checkpoint", checkpointOf((text, size, root) => parties.log.checkpoint(size, root, otherLog)));
  add("a checkpoint of a tree of another size", "v4: checkpoint", checkpointOf((text, size, root) => parties.log.checkpoint(size + 1, root)));
  add("a checkpoint of another root", "v4: checkpoint", checkpointOf((text, size) => parties.log.checkpoint(size, crypto.randomBytes(32))));
  add("a checkpoint without its signature lines", "v4: checkpoint", checkpointOf((text) => text.slice(0, text.indexOf("\n\n") + 2)));
  add("a checkpoint with a changed note under the signature of the log", "v4: checkpoint",
    checkpointOf((text) => text.replace("log.example", "log.examplf")));
  add("a checkpoint with a second line of the log that is no signature of the log", "v4: checkpoint", checkpointOf((text, size, root) => {
    const line = parties.log.checkpoint(size, crypto.randomBytes(32)).split("\n\n")[1];
    return text + line;
  }));
  add("a checkpoint with the line of a witness beside the line of the log", null, checkpointOf((text, size, root) => {
    return text + otherLog.checkpoint(size, root).split("\n\n")[1];
  }));
  add("a checkpoint whose note has a line behind the root hash, signed by the log", null, checkpointOf((text, size, root) => {
    const note = "log.example - 1\n" + size + "\n" + b64(root) + "\n1795000100\n";
    const signed = Buffer.concat([Buffer.from(parties.log.id, "hex").subarray(0, 4), model.ecdsaSign(parties.log.key, "sha256", Buffer.from(note, "utf8"))]);
    return note + "\n" + String.fromCharCode(0x2014) + " log.example " + b64(signed) + "\n";
  }));
  add("no checkpoint", "v4: checkpoint", attested({}, (bundle) => { delete entryOfBundle(bundle).inclusionProof.checkpoint; }));

  // ---- V7: the predicate ----
  add("a statement of another predicate type", "v7: predicate type", attested({ predicateType: "https://slsa.dev/provenance/v1" }));
  for (const field of ["pcr0", "pcr1", "pcr2"]) {
    add("a predicate of another " + field, "v7: predicate " + field,
      proofsOf({ attested: Object.assign({ release: release }, measurement, { [field]: otherPcr(measurement[field]) }) }));
  }
  add("a predicate of another git_commit than the statement", "v7: predicate git_commit",
    attested({ predicate: Object.assign({ release: release }, measurement, { git_commit: otherCommit(model.COMMIT) }) }));
  add("a predicate without the git_commit of the statement", "v7: predicate git_commit",
    attested({ predicate: Object.assign({ release: release }, measurement) }));
  add("a predicate of another release under the certificate of this release", "v7: predicate release",
    attested({ predicate: Object.assign({ release: release + "-rc.1", git_commit: model.COMMIT }, measurement) }));
  add("a predicate without a PCR", "v7: predicate pcr2",
    attested({ predicate: { release: release, git_commit: model.COMMIT, pcr0: measurement.pcr0, pcr1: measurement.pcr1 } }));
  add("a predicate with members the program does not read", null,
    attested({ predicate: Object.assign({ release: release, git_commit: model.COMMIT, program_min: 99, inputs: { a: "b" } }, measurement) }));
  add("a statement without a predicate", "v7: predicate release", attested({
    statement: { _type: "https://in-toto.io/Statement/v1", subject: [], predicateType: model.PREDICATE_TYPE },
  }));
  return cases;
}

module.exports = { proofCases, randomMeasurement };
