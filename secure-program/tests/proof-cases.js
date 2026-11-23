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

/** The cases for a release tag that is later than every release the program lists. listed is
 *  the latest release the program lists and version the version of the program. Returns
 *  [{name, reason, proofs, measurement, release, target, constants, logs, later, debug}]: reason
 *  is null for proofs that hold, and the text the program logs for the check that refuses the
 *  others; measurement and release are those of the node that presents the proofs; target is
 *  the server target of the build; constants are the parties whose keys and certificates the
 *  program holds; logs are the keys of the logs the program holds (null: the key of the log of
 *  the constants); later is true for proofs that hold and whose statement states a program
 *  later than version (the release is none the program accepts); debug is true for the proofs
 *  of a measurement no node presents (a PCR of it is all zero). */
function proofCases(release, listed, version) {
  const parties = model.makeParties();
  const measurement = randomMeasurement();
  const cases = [];
  const add = (name, reason, proofs, more) => cases.push(Object.assign({
    name: name, reason: reason, proofs: proofs, measurement: measurement, release: release, target: "prod",
    constants: parties, logs: null,
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
  /** Proofs of a statement of other bytes, signed, recorded and attested as that statement. */
  const ofStatement = (statement, attested) => proofsOf({ statement: statement, attested: attested });

  // ---- Proofs that hold ----
  add("proofs that hold", null, proofsOf());
  add("proofs that hold, for a build of the server target dev", null, proofsOf(), { target: "dev" });
  add("proofs that hold, for a build of the server target alpha", null, proofsOf(), { target: "alpha" });
  add("proofs with the deploy signature of the server target alone", null,
    proofsOf({ deploy: [{ key_id: "prod", signature: model.deploySignature(parties.deploy.prod, statementOf()) }] }));
  add("proofs with a deploy signature of a key id the program does not know beside its own", null,
    edited((proofs) => proofs.deploy_signatures.push({ key_id: "next", signature: b64(crypto.randomBytes(64)) })));
  add("a statement with members the program does not read", null, ofStatement(statementOf({ note: ["x", { y: 1 }] })));
  add("proofs with members the program does not read", null, edited((proofs) => { proofs.note = "x"; }));
  add("a release candidate later than the listed releases", null, proofsOf({}, release + "-rc.1"), { release: release + "-rc.1" });

  // ---- The shape ----
  for (const [name, value] of [["null", null], ["an array", []], ["a text", "proofs"], ["a number", 7]]) {
    add("proofs that are " + name, "shape", value);
  }
  for (const part of ["statement", "entry", "deploy_signatures", "attestation"]) {
    add("proofs without " + part, "shape", edited((proofs) => { delete proofs[part]; }));
  }
  add("proofs whose statement is no text", "shape", edited((proofs) => { proofs.statement = 7; }));
  add("proofs whose entry is an array", "shape", edited((proofs) => { proofs.entry = [proofs.entry]; }));
  add("proofs whose deploy_signatures is an object", "shape", edited((proofs) => { proofs.deploy_signatures = {}; }));
  add("proofs with half of a surrogate pair in a text", "shape", edited((proofs) => { proofs.note = "\ud83d"; }));
  add("proofs with arrays inside one another beyond the depth the program reads", "shape", edited((proofs) => {
    let nested = [];
    for (let depth = 0; depth < 40; depth += 1) nested = [nested];
    proofs.note = nested;
  }));

  // ---- P1: the release statement ----
  add("a statement in base64 with padding", "p1: statement", edited((proofs) => { proofs.statement += "="; }));
  // The bytes ??? and >>> give a character of the standard alphabet that the URL-safe one lacks.
  const marked = statementOf({ note: "???>>>" });
  add("a statement in the standard alphabet of base64", "p1: statement",
    edited((proofs) => { proofs.statement = b64(marked).replace(/=+$/, ""); }, { statement: marked }));
  add("a statement that is no base64", "p1: statement", edited((proofs) => { proofs.statement = "*" + proofs.statement; }));
  add("a statement of more than 16,384 bytes", "p1: statement", ofStatement(statementOf({ padding: "x".repeat(16000) })));
  add("a statement that is no JSON", "p1: statement", ofStatement(Buffer.from("release " + release, "utf8")));
  add("a statement that is a JSON array", "p1: statement", ofStatement(Buffer.from(JSON.stringify([JSON.parse(statementOf().toString())]), "utf8")));
  add("a statement that is no UTF-8", "p1: statement",
    ofStatement(Buffer.concat([statementOf().subarray(0, 4), Buffer.from([0xff]), statementOf().subarray(4)])));
  add("a statement with a byte order mark", "p1: statement", ofStatement(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), statementOf()])));
  for (const field of ["release", "pcr0", "pcr1", "pcr2"]) {
    const value = JSON.parse(statementOf().toString());
    const twice = statementOf().toString().replace("{", "{\n  " + JSON.stringify(field) + ": " + JSON.stringify(value[field]) + ",");
    add("a statement that states " + field + " twice", "p1: statement", ofStatement(Buffer.from(twice, "utf8")));
    const missing = Object.assign({}, value);
    delete missing[field];
    add("a statement without " + field, "p1: statement", ofStatement(Buffer.from(JSON.stringify(missing), "utf8")));
  }
  add("a statement that states pcr0 twice, once with an escaped key", "p1: statement", ofStatement(Buffer.from(
    statementOf().toString().replace("{", "{\n  \"pcr\\u0030\": " + JSON.stringify(measurement.pcr0) + ","), "utf8")));
  add("a statement with a PCR in upper case", "p1: statement", ofStatement(statementOf({ pcr1: measurement.pcr1.toUpperCase() })));
  add("a statement with a PCR of 95 characters", "p1: statement", ofStatement(statementOf({ pcr2: measurement.pcr2.slice(1) })));
  add("a statement whose release is a number", "p1: statement", ofStatement(statementOf({ release: 2 })));
  for (const tag of ["dev", "2.5.0", "v2.5", "v2.5.0.1", "v02.5.0", "v2.5.0-beta.1", "v2.5.0-rc.01", "v2.5.0-rc.1-rc.2", "v2.5.0 ", "v4294967296.0.0"]) {
    add("a statement whose release is " + JSON.stringify(tag), "p1: release tag",
      proofsOf({ statement: statementOf({}, tag), attested: Object.assign({ release: tag }, measurement) }, tag));
  }
  for (const field of ["pcr0", "pcr1", "pcr2"]) {
    const other = Object.assign({}, measurement, { [field]: otherPcr(measurement[field]) });
    add("the proofs of another measurement: one character of " + field, "p1: measurement", proofsOf({}, release, other));
  }
  // A PCR whose value is all zero is the value of an enclave in debug mode. The document of such
  // an enclave fails the attestation, so no node presents these proofs: they reach the program
  // for the digest of a measurement that an entry names (debug).
  const zero = "0".repeat(96);
  for (const [name, debug] of [
    ["pcr0", Object.assign({}, measurement, { pcr0: zero })], ["pcr1", Object.assign({}, measurement, { pcr1: zero })],
    ["pcr2", Object.assign({}, measurement, { pcr2: zero })], ["every PCR", { pcr0: zero, pcr1: zero, pcr2: zero }],
  ]) {
    add("the proofs of a measurement whose " + name + " is all zero", "p1: statement", proofsOf({}, release, debug),
      { measurement: debug, debug: true });
  }

  // ---- P1: the program_min of the statement ----
  add("a statement that states the program_min of this program", null, proofsOf({ programMin: version }));
  add("a statement that states program_min 0", null, proofsOf({ programMin: 0 }));
  add("a statement that states the program_min of the next program", null, proofsOf({ programMin: version + 1 }), { later: true });
  add("a statement that states the highest program_min the program holds exactly", null,
    proofsOf({ programMin: 9007199254740991 }), { later: true });
  /** Proofs of a statement that writes its program_min as the text written, attested with the
   *  value attested for it. */
  const minimum = (written, attested) => proofsOf({
    statement: Buffer.from(statementOf().toString().replace("{", "{\n  \"program_min\": " + written + ","), "utf8"),
    attested: Object.assign({ release: release }, measurement, { program_min: attested }),
  });
  for (const [name, written, attested] of [
    ["a text", "\"44\"", "44"], ["a fraction", "44.5", 44.5], ["a negative number", "-1", -1], ["null", "null", null],
    ["true", "true", true], ["an array", "[44]", [44]], ["written with an exponent", "4.4e1", 44],
    ["written with a fraction part", "44.0", 44], ["written as -0", "-0", 0],
    ["a number the program does not hold exactly", "9007199254740993", 9007199254740992],
    ["a number of seventeen digits", "10000000000000000", 10000000000000000],
  ]) {
    add("a statement whose program_min is " + name, "p1: statement", minimum(written, attested));
  }
  add("a statement that states program_min twice", "p1: statement", proofsOf({
    statement: Buffer.from(statementOf({ program_min: version }).toString().replace("{", "{\n  \"program_min\": " + version + ","), "utf8"),
    attested: Object.assign({ release: release }, measurement, { program_min: version }),
  }));

  // ---- P5: the order of releases ----
  for (const earlier of [listed, "v1.0.0", listed + "-rc.3"]) {
    add("the proofs of the release " + earlier + ", which is not later than the listed ones", "p5: release order",
      proofsOf({}, earlier));
  }

  // ---- P3: the deploy signature ----
  const signature = (key, statement, context) => model.deploySignature(key, statement || statementOf(), context);
  add("a deploy signature without a key id", "p3: shape", proofsOf({ deploy: [{ signature: signature(parties.deploy.prod) }] }));
  add("a deploy signature that is no object", "p3: shape", proofsOf({ deploy: [signature(parties.deploy.prod)] }));
  add("nine deploy signatures", "p3: shape", proofsOf({
    deploy: [{ key_id: "prod", signature: signature(parties.deploy.prod) }].concat(
      Array.from({ length: 8 }, (item, index) => ({ key_id: "other" + index, signature: b64(crypto.randomBytes(64)) }))),
  }));
  add("no deploy signature", "p3: signature", proofsOf({ deploy: [] }));
  add("no deploy signature of the key of the server target", "p3: signature",
    proofsOf({ deploy: [{ key_id: "dev", signature: signature(parties.deploy.dev) }] }));
  add("no deploy signature of the key of the server target, for a build of the server target dev", "p3: signature",
    proofsOf({ deploy: [{ key_id: "prod", signature: signature(parties.deploy.prod) }] }), { target: "dev" });
  add("two deploy signatures of the key of the server target", "p3: signature", proofsOf({
    deploy: [{ key_id: "prod", signature: signature(parties.deploy.prod) }, { key_id: "prod", signature: signature(parties.deploy.prod) }],
  }));
  add("a deploy signature of another key", "p3: signature",
    proofsOf({ deploy: [{ key_id: "prod", signature: signature(model.ed25519KeyPair()) }] }));
  add("the signature of the deploy key dev under the key id prod", "p3: signature",
    proofsOf({ deploy: [{ key_id: "prod", signature: signature(parties.deploy.dev) }] }));
  add("the deploy signature of another statement", "p3: signature",
    proofsOf({ deploy: [{ key_id: "prod", signature: signature(parties.deploy.prod, statementOf({ note: 1 })) }] }));
  add("a signature of the deploy key in the form of the deploy signature of a program", "p3: signature",
    proofsOf({ deploy: [{ key_id: "prod", signature: signature(parties.deploy.prod, statementOf(), "pickle-secure-program-v1\n") }] }));
  add("a signature of the deploy key over the statement itself", "p3: signature", proofsOf({
    deploy: [{ key_id: "prod", signature: b64(crypto.sign(null, statementOf(), parties.deploy.prod.privateKey)) }],
  }));
  add("a deploy signature in base64url", "p3: signature", proofsOf({
    deploy: [{ key_id: "prod", signature: b64u(Buffer.from(signature(parties.deploy.prod), "base64")) + "-" }],
  }));

  // ---- P2: the record of the signature of the release key ----
  const otherLog = model.makeLog("other.example - 2");
  const otherKey = model.ecKeyPair("prime256v1");
  const entryOf = (options, edit) => {
    const proofs = proofsOf({ entry: options });
    if (edit) edit(proofs.entry);
    return proofs;
  };
  add("an entry without a body", "p2: entry", entryOf({}, (entry) => { delete entry.body; }));
  add("an entry whose log_id is a number", "p2: entry", entryOf({}, (entry) => { entry.log_id = 7; }));
  add("an entry of a log the program does not know", "p2: log", entryOf({ log: otherLog }));
  add("an entry that names a log the program does not know", "p2: log", entryOf({}, (entry) => { entry.log_id = otherLog.id; }));
  add("an entry whose time is a text", "p2: promise", entryOf({}, (entry) => { entry.integrated_time = String(entry.integrated_time); }));
  add("an entry whose index is negative", "p2: promise", entryOf({}, (entry) => { entry.log_index = -1; }));
  add("an entry whose index is no integer", "p2: promise", entryOf({}, (entry) => { entry.log_index = 0.5; }));
  add("an entry whose index is above 2^53", "p2: promise", entryOf({ logIndex: 9007199254740993 }));
  add("an entry without a signed entry timestamp", "p2: promise", entryOf({}, (entry) => { delete entry.signed_entry_timestamp; }));
  add("an entry whose body ends the text of the signed bytes", "p2: promise", entryOf({}, (entry) => {
    entry.body += "\",\"integratedTime\":0,\"x\":\"";
  }));
  add("another time than the log signed", "p2: signed entry timestamp", entryOf({}, (entry) => { entry.integrated_time += 1; }));
  add("another index than the log signed", "p2: signed entry timestamp", entryOf({}, (entry) => { entry.log_index += 1; }));
  add("another body than the log signed", "p2: signed entry timestamp", entryOf({}, (entry) => {
    entry.body = model.recordedEntry(parties, statementOf({ note: 2 })).body;
  }));
  add("a signed entry timestamp of another key", "p2: signed entry timestamp", entryOf({}, (entry) => {
    entry.signed_entry_timestamp = otherLog.promise(entry.body, entry.integrated_time, entry.log_index, parties.log.id);
  }));
  add("a signed entry timestamp with bytes behind the signature", "p2: signed entry timestamp", entryOf({}, (entry) => {
    entry.signed_entry_timestamp = b64(Buffer.concat([Buffer.from(entry.signed_entry_timestamp, "base64"), Buffer.from([0])]));
  }));
  add("a record of another kind", "p2: body", entryOf({ record: (record) => { record.kind = "rekord"; } }));
  add("a record of another version", "p2: body", entryOf({ record: (record) => { record.apiVersion = "0.0.2"; } }));
  add("a record of a hash of another algorithm", "p2: body",
    entryOf({ record: (record) => { record.spec.data.hash.algorithm = "sha512"; } }));
  add("a body that is no JSON object", "p2: body", (() => {
    const proofs = proofsOf();
    const body = b64(Buffer.from("[]", "utf8"));
    proofs.entry.body = body;
    proofs.entry.signed_entry_timestamp = parties.log.promise(body, proofs.entry.integrated_time, proofs.entry.log_index);
    return proofs;
  })());
  add("the record of another statement", "p2: statement hash", entryOf({ hashed: statementOf({ note: 3 }) }));
  add("the record of the hash in upper case", "p2: statement hash",
    entryOf({ record: (record) => { record.spec.data.hash.value = record.spec.data.hash.value.toUpperCase(); } }));
  add("the record of another key", "p2: release key", entryOf({ signer: otherKey }));
  add("a record that names another key beside the signature of the release key", "p2: release key",
    entryOf({ loggedKey: otherKey.pem }));
  add("a record whose key is the DER of the release key without its PEM", "p2: release key",
    entryOf({ record: (record) => { record.spec.signature.publicKey.content = b64(parties.release.spki); } }));
  add("the release key with a signature over other bytes", "p2: release signature", entryOf({ signed: statementOf({ note: 4 }) }));
  add("the release key with the signature of another key", "p2: release signature", entryOf({
    record: (record) => { record.spec.signature.content = b64(model.ecdsaSign(otherKey, "sha256", statementOf())); },
  }));

  // ---- P4: the attestation ----
  const attested = (options, edit) => {
    const proofs = proofsOf({ attestation: options });
    if (edit) edit(proofs.attestation);
    return proofs;
  };
  const entryOfBundle = (bundle) => bundle.verificationMaterial.tlogEntries[0];
  add("an attestation without a certificate", "p4: shape", attested({}, (bundle) => { delete bundle.verificationMaterial.certificate; }));
  add("an attestation with two log entries", "p4: shape", attested({}, (bundle) => {
    bundle.verificationMaterial.tlogEntries.push(entryOfBundle(bundle));
  }));
  add("an attestation without a log entry", "p4: shape", attested({}, (bundle) => { bundle.verificationMaterial.tlogEntries = []; }));
  add("an envelope with two signatures", "p4: shape", attested({}, (bundle) => {
    bundle.dsseEnvelope.signatures.push(bundle.dsseEnvelope.signatures[0]);
  }));
  add("an envelope without a payload", "p4: shape", attested({}, (bundle) => { delete bundle.dsseEnvelope.payload; }));
  add("an attestation of more than 65,536 bytes", "p4: size", attested({}, (bundle) => { bundle.note = "x".repeat(66000); }));
  add("an envelope of another payload type", "p4: payload", attested({ payloadType: "application/vnd.other+json" }));
  add("a payload that is no JSON object", "p4: payload", attested({ statement: ["release"] }));
  add("a payload in base64url", "p4: payload", attested({}, (bundle) => {
    bundle.dsseEnvelope.payload = b64u(Buffer.from(bundle.dsseEnvelope.payload, "base64")) + "_";
  }));
  add("a certificate that is no DER", "p4: certificate", attested({}, (bundle) => {
    bundle.verificationMaterial.certificate.rawBytes = b64(Buffer.from("certificate"));
  }));
  add("a certificate with bytes behind it", "p4: certificate", attested({}, (bundle) => {
    const certificate = bundle.verificationMaterial.certificate;
    certificate.rawBytes = b64(Buffer.concat([Buffer.from(certificate.rawBytes, "base64"), Buffer.from([0])]));
  }));
  add("a certificate that states the runner twice", "p4: certificate", attested({
    certificate: { extensions: [der.sequence(der.oid("1.3.6.1.4.1.57264.1.11"), der.octets(der.utf8("github-hosted")))] },
  }));
  add("a log entry without a time", "p4: certificate", attested({}, (bundle) => { delete entryOfBundle(bundle).integratedTime; }));
  add("a log entry time before the validity of the certificate", "p4: certificate validity", attested({ integratedTime: 1794999999 }));
  add("a log entry time after the validity of the certificate", "p4: certificate validity", attested({ integratedTime: 1795000601 }));
  add("a log entry time at the first second of the validity of the certificate", null, attested({ integratedTime: 1795000000 }));
  add("a log entry time at the last second of the validity of the certificate", null, attested({ integratedTime: 1795000600 }));
  add("a certificate of a certificate authority", "p4: certificate authority", attested({ certificate: { authority: true } }));
  const sameNames = model.makeAuthority();
  add("a certificate that another authority of the same names issued", "p4: certificate issuer", attested({ issuer: sameNames }));
  add("a certificate the root issued", "p4: certificate issuer", attested({
    certificate: { signer: parties.authority.rootKey, issuer: parties.authority.rootName },
  }));
  add("a certificate the root signed under the name of the intermediate", "p4: certificate issuer", attested({
    certificate: { signer: parties.authority.rootKey },
  }));
  add("a certificate signed with SHA-256 by the intermediate", null, attested({ certificate: { hash: "sha256" } }));
  const otherRoot = Object.assign({}, parties, { authority: Object.assign({}, parties.authority, { root: sameNames.root }) });
  add("an intermediate that the root of the program did not issue", "p4: certificate root", proofsOf(), { constants: otherRoot });
  const expiredRoot = model.makeAuthority({ notAfter: 1794000000 });
  const expired = Object.assign({}, parties, { authority: expiredRoot });
  add("a root and an intermediate that ended before the time of the log entry", "p4: certificate validity",
    model.proofsOf(expired, release, measurement), { constants: expired });
  const identity = model.identityOf(release);
  const others = {
    8: ["https://gitlab.com"],
    9: [model.REPOSITORY + "/.github/workflows/other.yml@refs/tags/" + release,
      model.REPOSITORY + "/.github/workflows/release.yml@refs/heads/main",
      "https://github.com/someone/credential-enclave/.github/workflows/release.yml@refs/tags/" + release],
    11: ["self-hosted"],
    12: ["https://github.com/someone/credential-enclave", model.REPOSITORY + "/"],
    14: ["refs/heads/main", "refs/tags/" + release + "-rc.1", "refs/heads/tags/" + release],
    15: ["1400118249"],
    17: ["151645825"],
    18: [model.REPOSITORY + "/.github/workflows/caller.yml@refs/tags/" + release],
    20: ["workflow_dispatch", "release"],
    22: ["private", "internal"],
  };
  for (const number of Object.keys(others)) {
    for (const value of others[number]) {
      add("a certificate whose extension " + number + " is " + JSON.stringify(value) + " in the place of " + JSON.stringify(identity[number]),
        "p4: identity " + number, attested({ identity: { [number]: value } }), { identity: Number(number) });
    }
    add("a certificate without the extension " + number, "p4: identity " + number, attested({ identity: { [number]: null } }),
      { identity: Number(number) });
  }
  add("a certificate whose extension 11 is a text that is no DER", "p4: identity 11", attested({
    identity: { 11: null },
    certificate: { extensions: [der.sequence(der.oid("1.3.6.1.4.1.57264.1.11"), der.octets(Buffer.from("github-hosted")))] },
  }), { identity: 11 });
  add("the attestation of another release", "p4: identity 9",
    proofsOf({ attested: Object.assign({ release: release.replace(/\d+$/, "9") }, measurement) }));
  add("an envelope another key signed", "p4: signature", attested({ signer: model.ecKeyPair("prime256v1") }));
  add("a certificate with a key on P-384", "p4: signature", attested({ curve: "secp384r1" }));
  add("a log entry of a log the program does not know", "p4: log", attested({ log: otherLog }));
  add("a log entry that names a log the program does not know", "p4: log", attested({}, (bundle) => {
    entryOfBundle(bundle).logId.keyId = b64(Buffer.from(otherLog.id, "hex"));
  }));
  add("a log entry of another kind", "p4: log entry kind", attested({ record: (record) => { record.kind = "intoto"; } }));
  add("a log entry of another version", "p4: log entry kind", attested({ record: (record) => { record.apiVersion = "0.0.2"; } }));
  add("a log entry of another payload", "p4: log entry payload", attested({
    record: (record) => { record.spec.payloadHash.value = model.sha256(Buffer.from("another payload")).toString("hex"); },
  }));
  add("a log entry of a hash of another algorithm", "p4: log entry payload", attested({
    record: (record) => { record.spec.payloadHash.algorithm = "sha512"; },
  }));
  add("a log entry of another signature", "p4: log entry signature", attested({
    record: (record) => { record.spec.signatures[0].signature = b64(model.ecdsaSign(otherKey, "sha256", Buffer.from("x"))); },
  }));
  add("a log entry of two signatures", "p4: log entry signature", attested({
    record: (record) => { record.spec.signatures.push(record.spec.signatures[0]); },
  }));
  add("a log entry of another certificate", "p4: log entry certificate", attested({
    record: (record) => {
      record.spec.signatures[0].verifier = b64(Buffer.from(model.pem("CERTIFICATE", parties.authority.issue(otherKey, identity)), "utf8"));
    },
  }));
  add("another index than the log signed", "p4: signed entry timestamp", attested({}, (bundle) => {
    entryOfBundle(bundle).logIndex = String(Number(entryOfBundle(bundle).logIndex) + 1);
  }));
  add("a log entry without an inclusion promise", "p4: signed entry timestamp", attested({}, (bundle) => {
    delete entryOfBundle(bundle).inclusionPromise;
  }));
  add("a signed entry timestamp of another key", "p4: signed entry timestamp", attested({}, (bundle) => {
    const entry = entryOfBundle(bundle);
    entry.inclusionPromise.signedEntryTimestamp = otherLog.promise(
      entry.canonicalizedBody, entry.integratedTime, entry.logIndex, parties.log.id);
  }));
  add("a changed hash of the audit path", "p4: inclusion proof", attested({}, (bundle) => {
    const hashes = entryOfBundle(bundle).inclusionProof.hashes;
    hashes[0] = b64(model.sha256(Buffer.from(hashes[0], "base64")));
  }));
  add("an audit path without its last hash", "p4: inclusion proof", attested({}, (bundle) => {
    entryOfBundle(bundle).inclusionProof.hashes.pop();
  }));
  add("an audit path with one hash more", "p4: inclusion proof", attested({}, (bundle) => {
    entryOfBundle(bundle).inclusionProof.hashes.push(b64(crypto.randomBytes(32)));
  }));
  add("the index of another leaf", "p4: inclusion proof", attested({}, (bundle) => {
    entryOfBundle(bundle).inclusionProof.logIndex = "4";
  }));
  add("an index that is not below the size of the tree", "p4: inclusion proof", attested({}, (bundle) => {
    entryOfBundle(bundle).inclusionProof.logIndex = "11";
  }));
  add("an audit path of 65 hashes", "p4: inclusion proof", attested({}, (bundle) => {
    const proof = entryOfBundle(bundle).inclusionProof;
    proof.hashes = Array.from({ length: 65 }, () => proof.hashes[0]);
  }));
  add("a log entry without an inclusion proof", "p4: inclusion proof", attested({}, (bundle) => {
    delete entryOfBundle(bundle).inclusionProof;
  }));
  add("the last leaf of a tree", null, attested({ leafIndex: 10, treeSize: 11 }));
  add("the only leaf of a tree", null, attested({ leafIndex: 0, treeSize: 1 }));
  add("the first leaf of a tree of 4,096 leaves", null, attested({ leafIndex: 0, treeSize: 4096 }));
  const checkpointOf = (edit) => attested({}, (bundle) => {
    const proof = entryOfBundle(bundle).inclusionProof;
    proof.checkpoint.envelope = edit(proof.checkpoint.envelope, Number(proof.treeSize), Buffer.from(proof.rootHash, "base64"));
  });
  add("a checkpoint another key signed", "p4: checkpoint", checkpointOf((text, size, root) => parties.log.checkpoint(size, root, otherLog)));
  add("a checkpoint of a tree of another size", "p4: checkpoint", checkpointOf((text, size, root) => parties.log.checkpoint(size + 1, root)));
  add("a checkpoint of another root", "p4: checkpoint", checkpointOf((text, size) => parties.log.checkpoint(size, crypto.randomBytes(32))));
  add("a checkpoint without its signature lines", "p4: checkpoint", checkpointOf((text) => text.slice(0, text.indexOf("\n\n") + 2)));
  add("a checkpoint with a changed note under the signature of the log", "p4: checkpoint",
    checkpointOf((text) => text.replace("log.example", "log.examplf")));
  add("a checkpoint with a second line of the log that is no signature of the log", "p4: checkpoint", checkpointOf((text, size, root) => {
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
  add("no checkpoint", "p4: checkpoint", attested({}, (bundle) => { delete entryOfBundle(bundle).inclusionProof.checkpoint; }));
  add("a statement of another predicate type", "p4: predicate type", attested({ predicateType: "https://slsa.dev/provenance/v1" }));
  for (const field of ["pcr0", "pcr1", "pcr2"]) {
    add("a predicate of another " + field, "p4: predicate " + field,
      proofsOf({ attested: Object.assign({ release: release }, measurement, { [field]: otherPcr(measurement[field]) }) }));
  }
  add("a predicate without the program_min of the statement", "p4: predicate program_min",
    proofsOf({ statement: statementOf({ program_min: version }) }));
  add("a predicate with a program_min the statement does not state", "p4: predicate program_min",
    proofsOf({ attested: Object.assign({ release: release }, measurement, { program_min: version }) }));
  add("a predicate of another program_min than the statement", "p4: predicate program_min", proofsOf({
    statement: statementOf({ program_min: version + 1 }),
    attested: Object.assign({ release: release }, measurement, { program_min: version }),
  }));
  add("a predicate whose program_min is a text", "p4: predicate program_min", proofsOf({
    statement: statementOf({ program_min: version }),
    attested: Object.assign({ release: release }, measurement, { program_min: String(version) }),
  }));
  add("a predicate of another release under the certificate of this release", "p4: predicate release",
    attested({ predicate: Object.assign({ release: release + "-rc.1" }, measurement) }));
  add("a predicate without a PCR", "p4: predicate pcr2",
    attested({ predicate: { release: release, pcr0: measurement.pcr0, pcr1: measurement.pcr1 } }));
  add("a statement without a predicate", "p4: predicate release", attested({
    statement: { _type: "https://in-toto.io/Statement/v1", subject: [], predicateType: model.PREDICATE_TYPE },
  }));
  return cases;
}

module.exports = { proofCases, randomMeasurement };
