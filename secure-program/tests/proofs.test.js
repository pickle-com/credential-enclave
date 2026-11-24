// The tests of the release proofs of the secure program (docs/protocol.md, "The release proofs"),
// on the model of the bridge (bridge.js) and the model of the parties that make release proofs
// (proofs.js). Run: node --test secure-program/tests/proofs.test.js
//
// What is checked is what the program does when it meets a measurement no list of it has: the
// request it sends the backend for the release proofs of that measurement, whether a node of the
// measurement receives the grant, what the program logs for proofs it refuses, how its rounds
// judge the entries of such a node, and what the program store holds. Where the proofs are made
// here, the program runs with the keys and the certificates of the model in the place of its
// constants (proofs.withParties: the fixture of scenarios.js does so); the proofs of a published
// release run against the constants of the program as they are.
"use strict";

const assert = require("node:assert/strict");
const child = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const bridge = require("./bridge.js");
const S = require("./scenarios.js");
const model = require("./proofs.js");
const { proofCases } = require("./proof-cases.js");

const source = fs.readFileSync(path.join(__dirname, "..", "secure-program.js"), "utf8");
// The shared cases of the release proofs (docs/protocol.md 13): protocol/vectors/release-proofs.json
// of this checkout, or the file SECURE_PROGRAM_PROOF_CASES names. The node implementation reads
// the same file (protocol/tests/release_proofs.rs). The test of the cases is skipped when the
// checkout holds no such file and none is named.
const SHARED_CASES_PATH = process.env.SECURE_PROGRAM_PROOF_CASES ||
  path.join(__dirname, "..", "..", "protocol", "vectors", "release-proofs.json");
const shared = fs.existsSync(SHARED_CASES_PATH) ? JSON.parse(fs.readFileSync(SHARED_CASES_PATH, "utf8")) : null;
const { HOUR_MS, DAY_MS } = S;
const MINUTE_MS = 60000;
const REFUSED = "release proofs refused: ";
const PROOFS_PATH = "/api/secure/release-proofs";
const VERSION = bridge.declaredVersion(source);

// ---- Helpers ----

/** The lines the program logged for release proofs it refused, without their head. */
function refusals(world) {
  return world.logs.filter((line) => line.indexOf(REFUSED) === 0).map((line) => line.slice(REFUSED.length));
}

/** The requests for attestations the program sent since the index from: the node ids each
 *  named. No such request carries a query besides nonce, nodes and program. */
function attestationRequests(world, from) {
  const sent = world.requests.slice(from === undefined ? 0 : from).filter((request) => request.path === "/api/secure/nodes");
  for (const request of sent) {
    assert.deepEqual(Object.keys(request.query).filter((key) => ["nonce", "nodes", "program"].indexOf(key) < 0), []);
  }
  return sent.map((request) => String(request.query.nodes || "").split(",").filter((id) => id !== ""));
}

/** The verdicts of release proofs the program store keeps: the releases, in the order of the
 *  store. A verdict is {release, proven_ms} and nothing else. */
function keptProven(world) {
  const kept = world.stored("log.proven");
  if (kept === undefined) return [];
  for (const item of Object.values(kept.measures)) assert.deepEqual(Object.keys(item).sort(), ["proven_ms", "release"]);
  return Object.values(kept.measures).map((item) => item.release);
}

/** The digests the program asked the backend the release proofs of since the index from, one
 *  request for one digest (the query measurement, beside the query program). */
function proofRequests(world, from) {
  const sent = world.requests.slice(from === undefined ? 0 : from).filter((request) => request.path === PROOFS_PATH);
  for (const request of sent) assert.deepEqual(Object.keys(request.query).sort(), ["measurement", "program"]);
  return sent.map((request) => request.query.measurement);
}

/** The digest of a measurement as the program names it: the base64url SHA-256 of its three PCR
 *  values in hexadecimal, one after another. */
function digestOf(measurement) {
  return bridge.b64u(bridge.sha("sha256", bridge.utf8(measurement.pcr0 + measurement.pcr1 + measurement.pcr2)));
}

/** What the app was told of the log and what the program published, as one line. */
function told(world) {
  const last = world.securityStatuses.length === 0 ? null : world.securityStatuses[world.securityStatuses.length - 1];
  return world.state.log.status + (last === null ? "" : " told " + last.status + (last.reasons.length > 0 ? ":" + last.reasons.join(",") : "")) +
    " grant " + world.state.grant.state;
}

/** The key of the account moves from the node from (of fromRelease) to the node to (of the
 *  measurement and the release given): the entries the two nodes write, and the giving node is
 *  closed. */
function moveKey(world, from, fromRelease, to, measurement, release) {
  from.record("c", [{
    t: "grant_transferred_out", time_ms: world.now, to: to.id, release: release,
    pcr0: measurement.pcr0, pcr1: measurement.pcr1, pcr2: measurement.pcr2,
  }]);
  to.grants.set(world.userId, from.grants.get(world.userId));
  to.record("c", [{
    t: "grant_transferred_in", time_ms: world.now, from: from.id, release: fromRelease,
    not_after_ms: world.now + 30 * DAY_MS, custody: "enclave",
  }]);
  to.record("u", [S.providerRequest(world.now)]);
  from.alive = false;
}

/** Runs one round by a synchronization a day after the last one. */
async function nextDay(fx) {
  fx.world.advance(25 * HOUR_MS);
  await S.event(fx, "foreground");
}

/** A fixture with a node of one more release no list has: the fixture of scenarios.js (one node
 *  of release v2.4.0, whose release proofs the backend holds) and a node of release with a
 *  measurement of its own, whose proofs the backend holds when held is not false. options are
 *  those of S.fixture; node are options of the node. */
function laterFixture(release, options, node, held) {
  const fx = S.fixture(source, options);
  fx.laterMeasurement = bridge.randomMeasurement();
  fx.later = fx.world.addNode(Object.assign({ release: release, measurement: fx.laterMeasurement }, node || {}));
  if (held !== false) fx.world.releaseProofs.set(release, model.proofsOf(fx.parties, release, fx.laterMeasurement));
  return fx;
}

// ---- The proofs of a published release, against the constants of the program ----

test("the public build proof of the tag v2.4.0-rc.1 (the first run of the build workflow on GitHub), from public values: the program takes it with its constants as they are, a node of that measurement receives its grant, and the same proof changed in one place is refused by the check of that place", async () => {
  const real = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "release-proofs-v2.4.0-rc.1.json"), "utf8"));
  assert.deepEqual(Object.keys(real).sort(), ["attestation", "statement"]);
  const statement = Buffer.from(real.statement, "base64url");
  const stated = JSON.parse(statement.toString("utf8"));
  const measurement = { pcr0: stated.pcr0, pcr1: stated.pcr1, pcr2: stated.pcr2 };
  assert.equal(stated.release, "v2.4.0-rc.1");
  // The measurement is in no list of the program.
  assert.equal(bridge.listedMeasurements(source).concat(bridge.listedMeasurements(source, "PRERELEASE_BUILDS"))
    .some((item) => item.pcr0 === stated.pcr0), false);
  const run = async (text, proofs, binding) => {
    const world = new bridge.World({ serverTarget: "prod" });
    world.account.servedProgram = bridge.declaredVersion(text);
    const fx = { world: world, keys: world.createAccount(), source: text, nodes: [], legacy: [], program: null };
    fx.nodes.push(world.addNode({ release: binding || stated.release, measurement: measurement }));
    if (proofs !== null) world.measureProofs.set(digestOf(measurement), proofs);
    await S.start(fx);
    return fx;
  };
  const changed = (edit) => {
    const proofs = JSON.parse(JSON.stringify(real));
    edit(proofs, proofs.attestation, proofs.attestation.verificationMaterial.tlogEntries[0]);
    return proofs;
  };
  // The program as it is: the proofs hold, the node receives its grant and writes format 3, and
  // the device keeps the verdict.
  const shown = await run(source, real);
  assert.deepEqual(refusals(shown.world), []);
  assert.equal(shown.nodes[0].grants.has(shown.world.userId), true);
  assert.equal(shown.world.state.grant.state, "active");
  assert.equal(shown.world.state.log.status, "verified");
  assert.deepEqual(proofRequests(shown.world), [digestOf(measurement)]);
  assert.deepEqual(keptProven(shown.world), ["v2.4.0-rc.1"]);
  assert.equal(shown.world.stored("log.grants")[shown.nodes[0].id].format, 3);
  // Without the proofs the node receives no grant.
  const bare = await run(source, null);
  assert.equal(bare.nodes[0].grants.has(bare.world.userId), false);
  assert.deepEqual(keptProven(bare.world), []);
  // A node of that measurement whose binding names another release than the statement.
  const renamed = await run(source, real, "v2.4.0");
  assert.equal(renamed.nodes[0].grants.has(renamed.world.userId), false);
  assert.equal(renamed.world.runtime.rejected_nodes, 1);
  // The proof changed in one place. (A statement of other bytes is the statement of another
  // measurement, of another release or of another commit: what GitHub attested is not it.)
  const restated = (edit) => changed((proofs) => {
    const value = JSON.parse(statement.toString("utf8"));
    edit(value);
    proofs.statement = Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
  });
  const flipped = (text) => {
    const bytes = Buffer.from(text, "base64");
    bytes[bytes.length - 1] ^= 1;
    return bytes.toString("base64");
  };
  for (const [name, proofs, reason] of [
    ["another measurement in the statement", restated((value) => { value.pcr0 = (value.pcr0[0] === "0" ? "1" : "0") + value.pcr0.slice(1); }), "v1: measurement"],
    ["another release in the statement", restated((value) => { value.release = "v2.4.0"; }), "v6: identity 14"],
    ["another commit in the statement", restated((value) => { value.git_commit = "0".repeat(40); }), "v6: identity 13"],
    ["a further member in the statement", restated((value) => { value.note = "x"; }), null],
    ["the signature of the envelope changed", changed((proofs, bundle) => {
      bundle.dsseEnvelope.signatures[0].sig = flipped(bundle.dsseEnvelope.signatures[0].sig);
    }), "v5: signature"],
    ["the payload of the envelope changed", changed((proofs, bundle) => {
      const payload = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8"));
      payload.predicate.pcr0 = payload.predicate.pcr1;
      bundle.dsseEnvelope.payload = Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
    }), "v5: signature"],
    ["the time of the log entry an hour later", changed((proofs, bundle, entry) => {
      entry.integratedTime = String(Number(entry.integratedTime) + 3600);
    }), "v3: certificate validity"],
    ["the time of the log entry a second later", changed((proofs, bundle, entry) => {
      entry.integratedTime = String(Number(entry.integratedTime) + 1);
    }), "v4: signed entry timestamp"],
    ["the signed entry timestamp changed", changed((proofs, bundle, entry) => {
      entry.inclusionPromise.signedEntryTimestamp = flipped(entry.inclusionPromise.signedEntryTimestamp);
    }), "v4: signed entry timestamp"],
    ["no signed entry timestamp", changed((proofs, bundle, entry) => { delete entry.inclusionPromise; }), "v4: signed entry timestamp"],
    ["a hash of the audit path changed", changed((proofs, bundle, entry) => {
      entry.inclusionProof.hashes[0] = flipped(entry.inclusionProof.hashes[0]);
    }), "v4: inclusion proof"],
    ["the checkpoint changed", changed((proofs, bundle, entry) => {
      entry.inclusionProof.checkpoint.envelope = entry.inclusionProof.checkpoint.envelope.replace("rekor.sigstore.dev", "rekor.sigstore.dew");
    }), "v4: checkpoint"],
    ["the body of the log entry changed", changed((proofs, bundle, entry) => {
      const body = JSON.parse(Buffer.from(entry.canonicalizedBody, "base64").toString("utf8"));
      body.spec.payloadHash.value = "0".repeat(64);
      entry.canonicalizedBody = Buffer.from(JSON.stringify(body), "utf8").toString("base64");
    }), "v4: log entry payload"],
    ["the certificate changed", changed((proofs, bundle) => {
      bundle.verificationMaterial.certificate.rawBytes = flipped(bundle.verificationMaterial.certificate.rawBytes);
    }), "v3: certificate issuer"],
    ["no attestation", changed((proofs) => { delete proofs.attestation; }), "shape"],
  ]) {
    const fx = await run(source, proofs);
    if (reason === null) {
      // A statement of other bytes that states the same values: the predicate GitHub attested
      // states them, so the proofs hold (V7 compares the values the program reads).
      assert.deepEqual(refusals(fx.world), [], name);
      assert.equal(fx.nodes[0].grants.has(fx.world.userId), true, name);
      continue;
    }
    assert.deepEqual(refusals(fx.world), [reason], name);
    assert.equal(fx.nodes[0].grants.has(fx.world.userId), false, name);
    assert.deepEqual(keptProven(fx.world), [], name);
  }
  // A program that takes another build workflow, or the same file at another commit, takes
  // these proofs for nothing; one that takes both takes them.
  const pins = model.PINS;
  const other = { workflow: pins.workflow, commit: "f".repeat(40) };
  for (const [name, builders, reason] of [
    ["the build workflow at another commit", [other], "v6: identity 10"],
    ["another workflow file at that commit", [{ workflow: ".github/workflows/release.yml", commit: pins.commit }], "v6: identity 9"],
    ["no build workflow", [], "v6: identity 9"],
    ["two build workflows, the second being the one of the proofs", [other, { workflow: pins.workflow, commit: pins.commit }], null],
  ]) {
    const fx = await run(model.withBuilders(source, builders), real);
    assert.deepEqual(refusals(fx.world), reason === null ? [] : [reason], name);
    assert.equal(fx.nodes[0].grants.has(fx.world.userId), reason === null, name);
  }
  // The build workflow the program of this checkout takes is the one of those proofs.
  assert.deepEqual(model.buildersOf(source), [{ workflow: ".github/workflows/enclave-build.yml", commit: "3f84e8368fcdf1f89e42ca629670bfe0989b6f13" }]);
});

// ---- Proofs that differ in one place from proofs that hold ----

test("release proofs that hold hand the node its grant, and proofs that differ from them in one place are refused by the check of that place: the node stays one of a measurement the program does not accept", async () => {
  const cases = proofCases("v2.5.0");
  const seen = new Map();
  for (const item of cases) {
    const patched = (fx) => {
      let text = model.withParties(source, item.constants, item.logs);
      if (item.builders !== null) text = model.withBuilders(text, item.builders);
      // The node of the fixture is of a measurement the parties of the fixture made proofs
      // for: this program holds other keys, so the backend holds no proofs of it that hold.
      fx.world.releaseProofs.clear();
      return text;
    };
    if (item.debug === true) {
      // A measurement with a PCR that is all zero is that of no node whose attestation verifies,
      // so no node presents it: an accepted node writes a transfer of the key that names the
      // measurement, and the backend hands the proofs out for its digest. The statement is
      // refused (whoever signed the rest), and the measurement is one no list has and no proofs
      // showed: it marks the log a day later.
      const debug = S.fixture(source);
      await S.start(debug);
      const receiver = debug.world.addNode({ release: item.release, measurement: bridge.randomMeasurement(), offered: false });
      debug.nodes[0].record("c", [{
        t: "grant_transferred_out", time_ms: debug.world.now, to: receiver.id, release: item.release,
        pcr0: item.measurement.pcr0, pcr1: item.measurement.pcr1, pcr2: item.measurement.pcr2,
      }]);
      debug.world.measureProofs.set(digestOf(item.measurement), item.proofs);
      await nextDay(debug);
      seen.set(item.reason, (seen.get(item.reason) || 0) + 1);
      assert.deepEqual(refusals(debug.world), [item.reason], item.name);
      assert.deepEqual(keptProven(debug.world), ["v2.4.0"], item.name);
      assert.equal(debug.world.state.log.status, "pending", item.name);
      await nextDay(debug);
      assert.equal(debug.world.state.log.status, "attention", item.name);
      assert.equal(debug.world.state.log.unknown_nodes, 1, item.name);
      assert.deepEqual(refusals(debug.world), [item.reason], item.name);
      continue;
    }
    const fx = S.fixture(source, { nodes: 0, legacy: 1 });
    const world = fx.world;
    const text = patched(fx);
    const later = world.addNode({ release: item.release, measurement: item.measurement });
    // (An answer of the backend is a JSON object: proofs that are none are handed out as the
    // member release_proofs of one.)
    const plain = item.proofs !== null && typeof item.proofs === "object" && !Array.isArray(item.proofs);
    world.measureProofs.set(digestOf(item.measurement), plain ? item.proofs : { release_proofs: item.proofs });
    await S.start(fx, text);
    seen.set(item.reason, (seen.get(item.reason) || 0) + 1);
    // The listed node receives its grant whatever the backend hands out for the other.
    assert.equal(fx.legacy[0].grants.has(world.userId), true, item.name);
    assert.deepEqual(attestationRequests(world).map((nodes) => nodes.length), [2], item.name);
    assert.deepEqual(proofRequests(world), [digestOf(item.measurement)], item.name);
    if (item.reason === null) {
      assert.deepEqual(refusals(world), [], item.name);
      assert.equal(later.grants.has(world.userId), true, item.name);
      assert.equal(world.state.log.status, "verified", item.name);
      assert.equal(world.state.log.newer_release_nodes, 0, item.name);
      assert.deepEqual(keptProven(world), [item.release], item.name);
      continue;
    }
    // The proofs are refused once: the round that follows the step of the grants does not ask
    // for them again within five minutes.
    assert.deepEqual(refusals(world), [item.reason], item.name);
    assert.equal(later.grants.has(world.userId), false, item.name);
    assert.equal(world.state.log.status, "pending", item.name);
    assert.equal(world.state.log.newer_release_nodes, 1, item.name);
    assert.deepEqual(keptProven(world), [], item.name);
    assert.equal(world.runtime.rejected_nodes, 0, item.name);
  }
  // Every check has its cases.
  for (const reason of [
    null, "shape", "v1: statement", "v1: measurement", "v2: shape", "v2: size", "v2: payload", "v3: certificate",
    "v3: certificate validity", "v3: certificate authority", "v3: certificate issuer", "v3: certificate root",
    "v4: log entry time", "v4: log", "v4: log entry kind", "v4: log entry payload", "v4: log entry signature",
    "v4: log entry certificate", "v4: signed entry timestamp", "v4: inclusion proof", "v4: checkpoint", "v5: signature",
    "v6: identity 8", "v6: identity 9", "v6: identity 10", "v6: identity 11", "v6: identity 12", "v6: identity 13",
    "v6: identity 14", "v6: identity 15", "v6: identity 17", "v6: identity 20", "v6: identity 22",
    "v7: predicate type", "v7: predicate release", "v7: predicate git_commit", "v7: predicate pcr0", "v7: predicate pcr1",
    "v7: predicate pcr2",
  ]) {
    assert.ok(seen.get(reason) >= 1, "cases of " + reason);
  }
});

test("the shared cases of the release proofs: on every case the program gives the verdict the file states, with the release of an accepted case and the check that refuses a refused one, as the node implementation does on the same file", { skip: shared === null }, () => {
  // The program of a trust of the file holds the two certificates, the keys of the logs and the
  // list of build workflows of that trust in the place of its constants; the program of the
  // trust "source" is the program as it is.
  const programs = new Map();
  const verdictOf = (trust) => {
    if (!programs.has(trust)) {
      let text = source;
      if (trust !== "source") {
        const values = shared.trusts[trust];
        assert.notEqual(values, undefined, "the trust " + trust);
        text = model.withConstant(text, "PROOF_LOG_KEYS", JSON.stringify(values.log_keys));
        text = model.withConstant(text, "FULCIO_ROOT", JSON.stringify(values.fulcio_root));
        text = model.withConstant(text, "FULCIO_INTERMEDIATE", JSON.stringify(values.fulcio_intermediate));
        text = model.withBuilders(text, values.builders);
      }
      programs.set(trust, model.verdictsOf(text));
    }
    return programs.get(trust);
  };
  // (The issuer of the tokens and the repository with its two identifiers are constants of the
  // program that no trust of the file changes.)
  for (const values of Object.values(shared.trusts)) {
    assert.deepEqual([values.issuer, values.repository, values.repository_id, values.owner_id],
      ["https://token.actions.githubusercontent.com", model.REPOSITORY, "1400118248", "151645824"]);
  }
  const seen = new Map();
  for (const item of shared.cases) {
    const got = verdictOf(item.trust)(item.release_proofs_text, item.measurement);
    assert.deepEqual([got.accepted, got.release, got.rule], [item.accepted, item.release, item.rule],
      item.trust + ": " + item.name + (got.reason === "" ? "" : " (" + got.reason + ")"));
    seen.set(String(item.rule), (seen.get(String(item.rule)) || 0) + 1);
  }
  assert.ok(shared.cases.length >= 300);
  for (const rule of ["null", "form", "V1", "V2", "V3", "V4", "V5", "V6", "V7"]) {
    assert.ok(seen.get(rule) >= 5, "cases of " + rule);
  }
});

// ---- The requests ----

test("a node of a listed release is asked for no release proofs, and members of an attestation response and of a binding that this program does not read change nothing", async () => {
  const plain = S.fixture(source, { nodes: 0, legacy: 2 });
  await S.start(plain);
  const fx = S.fixture(source, { nodes: 0, legacy: 2 });
  const world = fx.world;
  // The backend hands release proofs out with every attestation, unasked, as a backend of an
  // earlier design did: proofs that hold for no measurement of these nodes. The bindings state
  // a program_min.
  world.attestationMore = () => ({ release_proofs: model.proofsOf(fx.parties, "v2.4.0", bridge.randomMeasurement()) });
  for (const node of fx.legacy) node.bindingMore = { program_min: 99 };
  await S.start(fx);
  // The same requests in the same order as without them (the ids of the nodes of a fixture are
  // its own).
  const lines = (of) => S.requestLines(of).map((line) => line.replace(/\/nodes\/[A-Za-z0-9_-]{43}\//, "/nodes/{node}/"));
  assert.deepEqual(S.result(fx), S.result(plain));
  assert.deepEqual(lines(world), lines(plain.world));
  assert.deepEqual(refusals(world), []);
  // The renewals of the next days, and a procedure of the user, ask for none either, and the
  // log screen asks for none.
  for (let day = 0; day < 3; day += 1) await nextDay(fx);
  await S.call(fx, "sync", {});
  await S.call(fx, "read_log", { limit: 10 });
  assert.deepEqual(proofRequests(world), []);
  assert.equal(world.stored("log.proven"), undefined);
  for (const node of fx.legacy) assert.equal(node.grants.has(world.userId), true);
});

test("release proofs that hold: the backend is asked for the proofs of the measurement once, every node of the measurement receives its grant in that step, the device keeps the verdict, and a later runtime asks for none and verifies none", async () => {
  const fx = laterFixture("v2.5.0", { nodes: 1 });
  const world = fx.world;
  const second = world.addNode({ release: "v2.5.0", measurement: fx.laterMeasurement });
  const reserve = world.addNode({ release: "v2.5.0", measurement: fx.laterMeasurement, role: "reserve" });
  await S.start(fx);
  for (const node of [fx.nodes[0], fx.later, second, reserve]) assert.equal(node.grants.has(world.userId), true);
  assert.equal(world.state.grant.state, "active");
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.runtime.rejected_nodes, 0);
  // One request names the four nodes; the backend is asked once for each of the two
  // measurements, by its digest; and no node is asked a second time.
  assert.deepEqual(attestationRequests(world).map((nodes) => nodes.length), [4]);
  assert.deepEqual(proofRequests(world).sort(), [digestOf(fx.measurement), digestOf(fx.laterMeasurement)].sort());
  for (const node of [fx.nodes[0], fx.later, second, reserve]) assert.equal(node.attestations, 1);
  assert.deepEqual(keptProven(world).sort(), ["v2.4.0", "v2.5.0"]);
  assert.equal(world.stored("log.proven").v, VERSION);
  assert.deepEqual(Object.keys(world.stored("log.proven").measures).sort(), [digestOf(fx.measurement), digestOf(fx.laterMeasurement)].sort());
  // The grants of the device name the release the proofs name, and the nodes write format 3 to
  // the log store: no node of the release is written into the ledger of the earlier programs.
  const grant = world.stored("log.grants")[fx.later.id];
  assert.deepEqual([grant.release, grant.format, grant.store], ["v2.5.0", 3, true]);
  assert.equal(world.ledger(), null);
  // The renewal a day later, in a new runtime, with a backend that holds the proofs no longer:
  // no request asks for proofs, nothing is verified again, and the grants are renewed.
  const before = world.requests.length;
  const commands = fx.later.commands.length;
  const logged = world.logs.length;
  world.advance(25 * HOUR_MS);
  world.releaseProofs.clear();
  await S.start(fx);
  assert.deepEqual(attestationRequests(world, before).map((nodes) => nodes.length), [4]);
  assert.deepEqual(proofRequests(world, before), []);
  assert.equal(fx.later.commands.length, commands + 1);
  assert.equal(world.state.grant.state, "active");
  assert.deepEqual(world.logs.slice(logged).filter((line) => line.indexOf("release proofs") >= 0), []);
  // A procedure of the user that needs a node holding the grant goes through, with the node of
  // release v2.4.0 gone.
  fx.nodes[0].alive = false;
  world.advance(25 * HOUR_MS);
  const synced = await S.call(fx, "sync", {});
  assert.equal(synced.ok, true);
  assert.equal(world.state.grant.state, "active");
});

test("the answer of the backend holds the release proofs as they are or as its member release_proofs, and a body that is neither is proofs that fail", async () => {
  for (const [name, arrange, granted, refused] of [
    ["the proofs as the body", () => {}, true, []],
    ["the proofs as the member release_proofs", (world) => { world.proofsWrapped = true; }, true, []],
    ["an empty object", (world, digest) => { world.measureProofs.set(digest, {}); }, false, ["shape"]],
    ["the member release_proofs as a text", (world, digest) => { world.measureProofs.set(digest, { release_proofs: "x" }); }, false, ["shape"]],
  ]) {
    const fx = laterFixture("v2.5.0", { nodes: 1 });
    arrange(fx.world, digestOf(fx.laterMeasurement));
    await S.start(fx);
    assert.equal(fx.later.grants.has(fx.world.userId), granted, name);
    assert.deepEqual(refusals(fx.world), refused, name);
  }
});

test("without release proofs, and with proofs that fail, the node is one the program does not accept: it receives no grant and is not asked for its attestation again, the backend is asked again five minutes after its last answer, and proofs that then hold hand the node its grant", async () => {
  for (const absent of ["no proofs", "no route"]) {
    const fx = laterFixture("v2.5.0", { nodes: 1 }, undefined, false);
    const world = fx.world;
    const digest = digestOf(fx.laterMeasurement);
    const asked = (from) => proofRequests(world, from).filter((item) => item === digest).length;
    if (absent === "no route") {
      // A backend without the route answers 404 as one that holds no proofs does. (The proofs
      // of the node of release v2.4.0 are kept from an earlier runtime.)
      await S.start(fx);
      world.routes.proofs = false;
      world.advance(10 * MINUTE_MS);
    }
    let before = world.requests.length;
    await S.start(fx);
    assert.equal(fx.later.grants.has(world.userId), false, absent);
    assert.equal(world.state.log.newer_release_nodes, 1, absent);
    assert.equal(fx.later.attestations, 1, absent);
    const attested = fx.later.attestations;
    assert.ok(asked(0) >= 1, absent);
    // Within five minutes of the answer nothing is asked again, by an event or by a procedure
    // of the user.
    before = world.requests.length;
    world.advance(2 * MINUTE_MS);
    await S.event(fx, "foreground");
    await S.call(fx, "sync", {});
    assert.equal(asked(before), 0, absent);
    assert.deepEqual(attestationRequests(world, before), [], absent);
    // After five minutes the backend is asked again. It holds proofs of a runner the owner of
    // the repository hosts: refused, and the node is not asked for its attestation.
    world.routes.proofs = true;
    world.releaseProofs.set("v2.5.0", model.proofsOf(fx.parties, "v2.5.0", fx.laterMeasurement, { attestation: { identity: { 11: "self-hosted" } } }));
    before = world.requests.length;
    world.advance(4 * MINUTE_MS);
    await S.event(fx, "foreground");
    assert.equal(asked(before), 1, absent);
    assert.deepEqual(refusals(world), ["v6: identity 11"], absent);
    assert.equal(fx.later.grants.has(world.userId), false, absent);
    assert.equal(fx.later.attestations, attested, absent);
    assert.deepEqual(keptProven(world), ["v2.4.0"], absent);
    // The same proofs are handed out again: they are not verified a second time.
    before = world.requests.length;
    world.advance(6 * MINUTE_MS);
    await S.event(fx, "foreground");
    assert.equal(asked(before), 1, absent);
    assert.deepEqual(refusals(world), ["v6: identity 11"], absent);
    // The backend holds proofs that hold: the next request for them shows the measurement, the
    // node is asked for its attestation and receives its grant in that step.
    world.releaseProofs.set("v2.5.0", model.proofsOf(fx.parties, "v2.5.0", fx.laterMeasurement));
    before = world.requests.length;
    world.advance(6 * MINUTE_MS);
    await S.event(fx, "foreground");
    assert.equal(asked(before), 1, absent);
    assert.deepEqual(attestationRequests(world, before), [[fx.later.id]], absent);
    assert.equal(fx.later.grants.has(world.userId), true, absent);
    assert.equal(world.state.grant.state, "active", absent);
    // The round of the next day forgets the measurement it kept as one no list has.
    await nextDay(fx);
    assert.equal(world.state.log.status, "verified", absent);
    assert.equal(world.state.log.newer_release_nodes, 0, absent);
    assert.deepEqual(world.stored("log.unaccepted"), {}, absent);
  }
});

test("a request for release proofs that fails leaves the node without its grant for this step and fails nothing else: the round that follows the step asks again and the synchronization after it hands the grant, a step no round follows leaves the node to the next step, which asks again at once, and a procedure of the user that needs the grant of that node alone ends with grant_required until then, not with attestation_failed, which is the failure of a node the backend holds no proofs of", async () => {
  for (const failure of [{ status: 503, body: { detail: "unavailable" } }, { status: 429, body: { detail: "too_many_requests" } }, "transport", "hang"]) {
    const name = JSON.stringify(failure);
    const failed = (world) => world.logs.filter((line) => line.indexOf("release proofs request failed") === 0).length;
    // The step of the grants of a synchronization that a round follows: the round asks for the
    // proofs again, they show the measurement, and a synchronization follows the round at once
    // whose step hands the node its grant.
    const fx = laterFixture("v2.5.0", { nodes: 1 });
    const world = fx.world;
    const digest = digestOf(fx.laterMeasurement);
    const fault = world.fault((line, request) => request.path === PROOFS_PATH && request.query.measurement === digest, failure, 1);
    await S.start(fx);
    assert.equal(fault.hits, 1, name);
    assert.equal(failed(world), 1, name);
    assert.deepEqual(refusals(world), [], name);
    assert.equal(proofRequests(world).filter((item) => item === digest).length, 2, name);
    assert.equal(fx.nodes[0].grants.has(world.userId), true, name);
    assert.equal(fx.later.grants.has(world.userId), true, name);
    assert.equal(world.state.grant.state, "active", name);
    assert.equal(world.state.log.newer_release_nodes, 0, name);
    // A step no round follows (the last round completed minutes ago): the node is without its
    // grant, nothing else failed, and the next step asks again without waiting for the five
    // minutes of a measurement the backend answered for.
    const quiet = S.fixture(source, { nodes: 1 });
    await S.start(quiet);
    assert.equal(quiet.world.state.log.status, "verified", name);
    const measurement = bridge.randomMeasurement();
    const later = quiet.world.addNode({ release: "v2.5.0", measurement: measurement });
    quiet.world.releaseProofs.set("v2.5.0", model.proofsOf(quiet.parties, "v2.5.0", measurement));
    const second = quiet.world.fault((line, request) => request.path === PROOFS_PATH && request.query.measurement === digestOf(measurement), failure, 1);
    quiet.world.advance(10 * MINUTE_MS);
    await S.event(quiet, "foreground");
    assert.equal(second.hits, 1, name);
    assert.equal(failed(quiet.world), 1, name);
    assert.equal(later.grants.has(quiet.world.userId), false, name);
    assert.equal(quiet.nodes[0].grants.has(quiet.world.userId), true, name);
    assert.equal(quiet.world.state.grant.state, "active", name);
    assert.equal(quiet.world.state.log.status, "verified", name);
    const before = quiet.world.requests.length;
    quiet.world.advance(2 * MINUTE_MS);
    await S.event(quiet, "foreground");
    assert.deepEqual(proofRequests(quiet.world, before), [digestOf(measurement)], name);
    assert.equal(later.grants.has(quiet.world.userId), true, name);
    assert.equal(quiet.world.state.grant.state, "active", name);
  }
  // The one node of the account is of a release no list has, and the request for its proofs
  // fails (an error status, a failure on its way, no answer): no attestation failed and the
  // backend did not say that it holds no proofs, so the procedure ends with grant_required, the
  // failure of a step that could hand no grant for the moment, and goes through when the user
  // tries again.
  for (const failure of [{ status: 503, body: { detail: "unavailable" } }, { status: 429, body: { detail: "too_many_requests" } }, "transport", "hang"]) {
    const name = JSON.stringify(failure);
    const alone = S.fixture(source, { nodes: 1 });
    const fault = alone.world.fault((line, request) => request.path === PROOFS_PATH, failure);
    await S.start(alone);
    assert.equal(alone.world.state.grant.state, "none", name);
    const first = await S.call(alone, "store_login", { name: "example.com", username: "u", password: "p" });
    assert.deepEqual([first.ok, first.code], [false, "grant_required"], name);
    fault.times = 0;
    const second = await S.call(alone, "store_login", { name: "example.com", username: "u", password: "p" });
    assert.equal(second.ok, true, name);
    assert.equal(alone.nodes[0].grants.has(alone.world.userId), true, name);
  }
  // The backend answers that it holds no proofs of the measurement of that node (404), or
  // hands out proofs that fail: the node is one of a measurement the program does not accept,
  // and the procedure ends with attestation_failed.
  for (const held of [false, true]) {
    const refused = S.fixture(source, { nodes: 1, proofs: false });
    if (held) {
      refused.world.releaseProofs.set("v2.4.0", model.proofsOf(refused.parties, "v2.4.0", refused.measurement, { attestation: { identity: { 11: "self-hosted" } } }));
    }
    await S.start(refused);
    const call = await S.call(refused, "store_login", { name: "example.com", username: "u", password: "p" });
    assert.deepEqual([call.ok, call.code], [false, "attestation_failed"], String(held));
  }
});

test("what the device keeps of release proofs: a program of another version reads it as nothing and verifies anew, a verdict that is not of the form this program writes is not read, and the end of the account erases it", async () => {
  const fx = laterFixture("v2.5.0", { nodes: 1 });
  const world = fx.world;
  await S.start(fx);
  assert.equal(fx.later.grants.has(world.userId), true);
  const kept = world.stored("log.proven");
  assert.equal(kept.v, VERSION);
  // The next version of the program, with the same constants: it asks for the proofs itself.
  let before = world.requests.length;
  world.advance(25 * HOUR_MS);
  await S.start(fx, fx.source.replace(/^\s*const VERSION = \d+;/m, "  const VERSION = " + (kept.v + 1) + ";"));
  assert.deepEqual(proofRequests(world, before).sort(), Object.keys(kept.measures).sort());
  assert.equal(world.stored("log.proven").v, kept.v + 1);
  // The program of this version again finds the value of the other version: it asks again.
  before = world.requests.length;
  world.advance(25 * HOUR_MS);
  await S.start(fx);
  assert.deepEqual(proofRequests(world, before).sort(), Object.keys(kept.measures).sort());
  // A verdict whose release is no name of a release, and one under a key that is no digest,
  // are not read: the proofs of that measurement are asked for.
  const digest = digestOf(fx.laterMeasurement);
  const altered = JSON.parse(JSON.stringify(kept));
  altered.measures[digest].release = "2.5.0";
  altered.measures["not-a-digest"] = { release: "v9.9.9", proven_ms: 1 };
  world.store.set("log.proven", JSON.stringify(altered));
  before = world.requests.length;
  world.advance(25 * HOUR_MS);
  await S.start(fx);
  assert.deepEqual(proofRequests(world, before), [digest]);
  assert.deepEqual(keptProven(world).sort(), ["v2.4.0", "v2.5.0"]);
  // The end of the account erases what was kept.
  await S.event(fx, "account_end", { reason: "account_deleted" });
  assert.equal(world.stored("log.proven"), undefined);
});

test("the release of the binding of a node is the release its proofs name: a node of the measurement that states another release fails the verification", async () => {
  const fx = laterFixture("v2.5.1", { nodes: 1 }, undefined, false);
  const world = fx.world;
  world.releaseProofs.set("v2.5.0", model.proofsOf(fx.parties, "v2.5.0", fx.laterMeasurement));
  await S.start(fx);
  assert.equal(fx.later.grants.has(world.userId), false);
  assert.equal(world.runtime.rejected_nodes, 1);
  assert.ok(world.logs.some((line) => line === "attestation rejected: release of the binding"));
  assert.deepEqual(keptProven(world).sort(), ["v2.4.0", "v2.5.0"]);
});

test("the marks of the log of a node follow from its measurement and not from the name of its release: a node that names a listed release and has another measurement is one of format 3, and a node of platform local has the marks of the name its binding states", async () => {
  const fx = S.fixture(source, { nodes: 0, legacy: 1 });
  const world = fx.world;
  // A release of the public repository that someone tagged with the name of a listed release:
  // its measurement is another one, its proofs hold, and its nodes write format 3.
  const measurement = bridge.randomMeasurement();
  const named = world.addNode({ release: fx.latest.release, measurement: measurement });
  assert.equal(named.format, 3);
  world.releaseProofs.set("named", model.proofsOf(fx.parties, fx.latest.release, measurement));
  await S.start(fx);
  assert.equal(named.grants.has(world.userId), true);
  const grants = world.stored("log.grants");
  assert.deepEqual([grants[named.id].format, grants[named.id].store], [3, true]);
  assert.deepEqual([grants[fx.legacy[0].id].format, grants[fx.legacy[0].id].store], [2, true]);
  // The node of the listed measurement is written into the ledger of the earlier programs, and
  // the node of format 3 is not.
  await world.settle(1000);
  assert.deepEqual(Object.keys(world.ledger().nodes), [fx.legacy[0].id]);
  // What the node of the other measurement writes is read from the buckets of format 3, with
  // its node document: an entry it wrote is judged, and a transfer it names is followed.
  const other = bridge.randomMeasurement();
  const receiver = world.addNode({ release: "v9.0.0", measurement: other, offered: false });
  named.record("c", [{
    t: "grant_transferred_out", time_ms: world.now, to: receiver.id, release: "v9.0.0",
    pcr0: other.pcr0, pcr1: other.pcr1, pcr2: other.pcr2,
  }]);
  await nextDay(fx);
  assert.equal(world.state.log.status, "pending");
  assert.equal(world.state.log.newer_release_nodes, 1);
  assert.deepEqual(Object.keys(world.stored("log.unaccepted")), [digestOf(other)]);

  // A node of platform local: the marks of the name of its release.
  for (const [release, format] of [[fx.latest.release, 2], ["v2.4.0", 3], ["dev", 3]]) {
    const local = S.fixture(source, { nodes: 0, target: "dev" });
    const node = local.world.addNode({
      release: release, measurement: bridge.randomMeasurement(), platform: "local",
      log: { bucket: local.world.bucket, region: local.world.region },
    });
    assert.equal(node.format, format, release);
    await S.start(local);
    assert.equal(node.grants.has(local.world.userId), true, release);
    assert.deepEqual([local.world.stored("log.grants")[node.id].format, local.world.stored("log.grants")[node.id].store], [format, true], release);
    assert.deepEqual(proofRequests(local.world), [], release);
  }
});

// ---- The rounds ----

test("the rounds judge the nodes of a measurement release proofs showed as accepted nodes: an entry such a node wrote, a transfer of the key to that measurement, and the node document of a node this device handed no grant", async () => {
  // A node of the proven release that holds the grant writes entries: the round verifies them.
  const fx = laterFixture("v2.5.0", { nodes: 1 });
  const world = fx.world;
  await S.start(fx);
  fx.later.record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r", provider: "slack", scope: "" }]);
  fx.later.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/a", "POST")]);
  // A node of release v2.4.0 hands the key on to another node of the other proven measurement.
  const receiver = world.addNode({ release: "v2.5.0", measurement: fx.laterMeasurement, offered: false });
  fx.nodes[0].record("c", [{
    t: "grant_transferred_out", time_ms: world.now, to: receiver.id, release: "v2.5.0",
    pcr0: fx.laterMeasurement.pcr0, pcr1: fx.laterMeasurement.pcr1, pcr2: fx.laterMeasurement.pcr2,
  }]);
  receiver.record("c", [{ t: "grant_transferred_in", time_ms: world.now, from: fx.nodes[0].id, release: "v2.4.0" }]);
  await nextDay(fx);
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.state.log.newer_release_nodes, 0);
  assert.equal(world.state.log.unknown_nodes, 0);
  assert.deepEqual(world.stored("log.unaccepted"), {});
  const shown = await S.call(fx, "read_log", { limit: 10 });
  assert.equal(shown.value.status, "verified");

  // A device that hands the node no grant itself (the backend lists the node to it for no
  // grant) learns the measurement from the node document, and asks the backend for the release
  // proofs of that measurement in the round that reads the document: with proofs that hold the
  // entries of the node are those of an accepted node; without them the measurement is one no
  // list has, pending for its day and then marked. A member release_proofs of a node document
  // is not read.
  for (const held of [true, false]) {
    const reader = S.fixture(source, { nodes: 1, device: { securityStatus: true } });
    const measurement = bridge.randomMeasurement();
    const proofs = model.proofsOf(reader.parties, "v2.5.0", measurement);
    const node = reader.world.addNode({
      release: "v2.5.0", measurement: measurement, offered: false, documentMore: { release_proofs: proofs },
    });
    if (held) reader.world.releaseProofs.set("v2.5.0", proofs);
    await S.start(reader);
    reader.nodes[0].record("c", [{
      t: "grant_transferred_out", time_ms: reader.world.now, to: node.id, release: "v2.5.0",
      pcr0: measurement.pcr0, pcr1: measurement.pcr1, pcr2: measurement.pcr2,
    }]);
    node.record("c", [{ t: "grant_transferred_in", time_ms: reader.world.now, from: reader.nodes[0].id, release: "v2.4.0" }]);
    const before = reader.world.requests.length;
    await nextDay(reader);
    assert.ok(proofRequests(reader.world, before).indexOf(digestOf(measurement)) >= 0, String(held));
    assert.equal(reader.world.state.log.newer_release_nodes, held ? 0 : 1, String(held));
    assert.deepEqual(keptProven(reader.world).sort(), held ? ["v2.4.0", "v2.5.0"] : ["v2.4.0"], String(held));
    await nextDay(reader);
    assert.equal(told(reader.world), held ? "verified told ok grant active" : "attention told attention:unlisted_release grant active", String(held));
  }
});

test("release proofs that reach the backend after the device read the entries of a node: the entries that node wrote are judged again as those of an accepted node, and a transfer of the key they name to a measurement no list has marks the log", async () => {
  const fx = S.fixture(source, { nodes: 1, device: { securityStatus: true } });
  const world = fx.world;
  await S.start(fx);
  // The key moves to a node of release v2.5.0, whose proofs the backend does not hold yet, and
  // that node hands it on to a node of a measurement nobody made proofs for.
  const measurement = bridge.randomMeasurement();
  const middle = world.addNode({ release: "v2.5.0", measurement: measurement, offered: false });
  const other = bridge.randomMeasurement();
  const last = world.addNode({ release: "v2.6.0", measurement: other, offered: false, document: false });
  fx.nodes[0].record("c", [{
    t: "grant_transferred_out", time_ms: world.now, to: middle.id, release: "v2.5.0",
    pcr0: measurement.pcr0, pcr1: measurement.pcr1, pcr2: measurement.pcr2,
  }]);
  middle.record("c", [{
    t: "grant_transferred_out", time_ms: world.now, to: last.id, release: "v2.6.0",
    pcr0: other.pcr0, pcr1: other.pcr1, pcr2: other.pcr2,
  }]);
  await nextDay(fx);
  assert.equal(world.state.log.status, "pending");
  assert.deepEqual(Object.keys(world.stored("log.unaccepted")), [digestOf(measurement)]);
  // The proofs of release v2.5.0 reach the backend: the round verifies them, reads the entries
  // of its node as those of an accepted node, and notes the measurement that node handed the
  // key to.
  world.releaseProofs.set("v2.5.0", model.proofsOf(fx.parties, "v2.5.0", measurement));
  world.advance(HOUR_MS);
  await S.event(fx, "foreground");
  await world.settle(1000);
  assert.deepEqual(Object.keys(world.stored("log.unaccepted")), [digestOf(other)]);
  assert.equal(world.stored("log.unaccepted")[digestOf(other)].held, true);
  assert.equal(world.state.log.status, "pending");
  await nextDay(fx);
  assert.equal(told(world), "attention told attention:unlisted_release grant active");
});

test("a measurement no list has marks the log only once the backend answered a request for its release proofs without proofs that hold: a backend that fails that request holds the rounds back, which marks the log after three days as any read held back does, and a device without a network is told nothing", async () => {
  const scene = async () => {
    const fx = S.fixture(source, { nodes: 1, device: { securityStatus: true } });
    await S.start(fx);
    const other = bridge.randomMeasurement();
    const receiver = fx.world.addNode({ release: "v2.6.0", measurement: other, offered: false });
    fx.nodes[0].record("c", [{
      t: "grant_transferred_out", time_ms: fx.world.now, to: receiver.id, release: "v2.6.0",
      pcr0: other.pcr0, pcr1: other.pcr1, pcr2: other.pcr2,
    }]);
    fx.other = other;
    return fx;
  };
  const failing = (fx, respond) => fx.world.fault((line, request) => request.path === PROOFS_PATH && request.query.measurement === digestOf(fx.other), respond);
  // The backend answers 404: pending for a day, then marked for the release.
  const denied = await scene();
  await nextDay(denied);
  assert.equal(told(denied.world), "pending told pending grant active");
  await nextDay(denied);
  assert.equal(told(denied.world), "attention told attention:unlisted_release grant active");
  // The backend fails the request with a 503 (and with a 429): the measurement is not marked
  // for the release, the rounds are held back, and three days of that mark the log as reads
  // held back.
  for (const status of [503, 429]) {
    const blocked = await scene();
    failing(blocked, { status: status, body: { detail: "unavailable" } });
    const lines = [];
    for (let day = 0; day < 5; day += 1) {
      await nextDay(blocked);
      lines.push(told(blocked.world));
    }
    assert.deepEqual(lines.slice(0, 3), Array(3).fill("pending told pending grant active"), String(status));
    assert.equal(lines[4], "attention told attention:verification_blocked grant active", String(status));
    assert.equal(blocked.world.state.log.unknown_nodes, 0, String(status));
    assert.equal(blocked.world.state.log.store, "blocked", String(status));
    assert.equal(blocked.world.state.log.store_failure, "proofs:" + status, String(status));
    // The backend answers the request (it holds no proofs): the round is held back no longer,
    // and the measurement, long past its day, marks the log for the release.
    blocked.world.clearFaults();
    await nextDay(blocked);
    assert.equal(told(blocked.world), "attention told attention:unlisted_release grant active", String(status));
  }
  // The request fails on its way while nothing else is answered either (a device without a
  // network): nothing is counted and nothing is told, however long.
  const offline = await scene();
  await nextDay(offline);
  offline.world.fault(() => true, "transport");
  // (The synchronization of the event fails with the failure of its first request.)
  for (let day = 0; day < 6; day += 1) await nextDay(offline).then(() => assert.fail("a synchronization without a network"), () => {});
  assert.equal(offline.world.state.log.status, "pending");
  assert.equal(offline.world.securityStatuses.filter((item) => item.status === "attention").length, 0);
});

test("a stale runtime verifies release proofs as any runtime does: the node of the proven release receives its grant from a program that is behind the served one", async () => {
  const fx = laterFixture("v2.5.0", { nodes: 0 });
  const world = fx.world;
  world.account.servedProgram = bridge.declaredVersion(fx.source) + 1;
  await S.start(fx);
  assert.equal(world.runtime.program_stale, true);
  assert.equal(fx.later.grants.has(world.userId), true);
  assert.equal(world.state.grant.state, "active");
  const called = await S.call(fx, "sync", {});
  assert.equal(called.ok, true);
});

test("a stale runtime whose request for release proofs failed asks again with its next step, and one the backend answered without proofs asks again five minutes later: no failure of one request keeps a node from its grant for the time of the runtime, and a procedure that ends without a grant says grant_required after a request that failed and program_stale after the answer that the backend holds no proofs", async () => {
  // The one living node of the account is of a release no list has, whose proofs the backend
  // holds, and the runtime knows that a later program is served. The first request for the
  // proofs fails.
  for (const failure of [{ status: 503, body: { detail: "unavailable" } }, { status: 429, body: { detail: "too_many_requests" } }, "transport", "hang"]) {
    const name = JSON.stringify(failure);
    const fx = laterFixture("v2.5.0", { nodes: 0 });
    const world = fx.world;
    const digest = digestOf(fx.laterMeasurement);
    world.account.servedProgram = VERSION + 1;
    const fault = world.fault((line, request) => request.path === PROOFS_PATH, failure, 1);
    await S.start(fx);
    assert.equal(world.runtime.program_stale, true, name);
    assert.equal(fault.hits, 1, name);
    assert.equal(fx.later.grants.has(world.userId), false, name);
    // A stale runtime writes none of what the rounds judge by.
    assert.equal(world.stored("log.nodes"), undefined, name);
    assert.equal(world.stored("log.unaccepted"), undefined, name);
    // The next step (an event a minute later) asks for the proofs again, and not the node for
    // its attestation before they hold: the proofs show the measurement, and the node receives
    // its grant in that step.
    const before = world.requests.length;
    world.advance(MINUTE_MS);
    await S.event(fx, "foreground");
    assert.deepEqual(proofRequests(world, before), [digest], name);
    assert.deepEqual(attestationRequests(world, before), [[fx.later.id]], name);
    assert.equal(fx.later.grants.has(world.userId), true, name);
    assert.equal(world.state.grant.state, "active", name);
    const stored = await S.call(fx, "store_login", { name: "example.com", username: "u", password: "p" });
    assert.equal(stored.ok, true, name);
  }
  // A procedure of the user in that runtime while the requests for the proofs fail: the step
  // could hand no grant for the moment (grant_required), and the same call goes through once
  // the backend answers.
  const failing = laterFixture("v2.5.0", { nodes: 0 });
  failing.world.account.servedProgram = VERSION + 1;
  const outage = failing.world.fault((line, request) => request.path === PROOFS_PATH, { status: 503, body: { detail: "unavailable" } });
  await S.start(failing);
  const during = await S.call(failing, "store_login", { name: "example.com", username: "u", password: "p" });
  assert.deepEqual([during.ok, during.code], [false, "grant_required"]);
  assert.ok(outage.hits >= 2);
  outage.times = 0;
  const after = await S.call(failing, "store_login", { name: "example.com", username: "u", password: "p" });
  assert.equal(after.ok, true);
  assert.equal(failing.later.grants.has(failing.world.userId), true);
  // The backend holds no proofs of the measurement (the program is behind: the served one
  // accepts that release another way). The procedure says program_stale, the runtime asks the
  // backend again not sooner than five minutes after its answer and the node for no
  // attestation meanwhile, and proofs that then hold hand the node its grant.
  const behind = laterFixture("v2.5.0", { nodes: 0 }, undefined, false);
  const world = behind.world;
  const digest = digestOf(behind.laterMeasurement);
  world.account.servedProgram = VERSION + 1;
  await S.start(behind);
  assert.deepEqual(proofRequests(world), [digest]);
  const call = await S.call(behind, "store_login", { name: "example.com", username: "u", password: "p" });
  assert.deepEqual([call.ok, call.code], [false, "program_stale"]);
  let before = world.requests.length;
  world.advance(2 * MINUTE_MS);
  await S.event(behind, "foreground");
  assert.deepEqual(proofRequests(world, before), []);
  assert.deepEqual(attestationRequests(world, before), []);
  world.releaseProofs.set("v2.5.0", model.proofsOf(behind.parties, "v2.5.0", behind.laterMeasurement));
  before = world.requests.length;
  world.advance(4 * MINUTE_MS);
  await S.event(behind, "foreground");
  assert.deepEqual(proofRequests(world, before), [digest]);
  assert.deepEqual(attestationRequests(world, before), [[behind.later.id]]);
  assert.equal(behind.later.grants.has(world.userId), true);
  assert.equal(world.state.grant.state, "active");
});

test("a measurement that marked the log is asked for again by every synchronization, and proofs that then show it take the mark back in that stay: a backend that answered 404 for the proofs of a release it holds (a process that had not read them, an image without the route) leaves the mark until the next synchronization and not for a day", async () => {
  for (const moment of ["no route", "no row"]) {
    // The device holds the grant of the node of release v2.4.0. A node of release v2.5.0, whose
    // proofs the backend holds, holds the key of the account through another device, and wrote
    // an entry of that key.
    const fx = S.fixture(source, { nodes: 1, device: { securityStatus: true } });
    const world = fx.world;
    await S.start(fx);
    const measurement = bridge.randomMeasurement();
    const digest = digestOf(measurement);
    const other = world.addNode({ release: "v2.5.0", measurement: measurement, format: 3, offered: false });
    world.releaseProofs.set("v2.5.0", model.proofsOf(fx.parties, "v2.5.0", measurement));
    other.grants.set(world.userId, { sign_pk: bridge.b64u(fx.keys.signPk), log_pk: bridge.b64u(fx.keys.logPk), key_id: fx.keys.keyId, custody: "enclave", not_after_ms: world.now + 30 * DAY_MS });
    other.record("c", [{ t: "grant_accepted", time_ms: world.now, not_after_ms: world.now + 30 * DAY_MS, custody: "enclave" }]);
    // The first stay after that: the route of the proofs answers 503, and the measurement waits.
    const failing = world.fault((line, request) => request.path === PROOFS_PATH, { status: 503, body: { detail: "unavailable" } });
    await nextDay(fx);
    assert.equal(told(world), "pending told pending grant active", moment);
    failing.times = 0;
    // A day and a half later, a new runtime: the route answers 404 for that stay, and the
    // measurement, past its day, marks the log.
    world.advance(36 * HOUR_MS);
    let absent = null;
    if (moment === "no route") world.routes.proofs = false;
    else absent = world.fault((line, request) => request.path === PROOFS_PATH, { status: 404, body: { detail: "not_found" } });
    await S.start(fx);
    await world.settle(MINUTE_MS);
    assert.equal(told(world), "attention told attention:unlisted_release grant active", moment);
    assert.equal(world.stored("log.unaccepted")[digest].stood, true, moment);
    // Within five minutes of that answer, a synchronization of the same runtime asks nothing.
    let before = world.requests.length;
    world.advance(2 * MINUTE_MS);
    await S.event(fx, "foreground");
    assert.deepEqual(proofRequests(world, before), [], moment);
    assert.equal(told(world), "attention told attention:unlisted_release grant active", moment);
    // The backend hands the proofs out again. The next synchronization (ten minutes after the
    // mark, with no round due for a day) asks for them, they show the measurement, and the round
    // that follows at once takes the mark back and tells the app.
    world.routes.proofs = true;
    if (absent !== null) absent.times = 0;
    before = world.requests.length;
    world.advance(8 * MINUTE_MS);
    await S.event(fx, "foreground");
    await world.settle(MINUTE_MS);
    assert.deepEqual(proofRequests(world, before), [digest], moment);
    assert.equal(told(world), "verified told ok grant active", moment);
    assert.deepEqual(world.stored("log.unaccepted"), {}, moment);
    assert.equal(world.state.log.unknown_nodes, 0, moment);
    // Nothing is asked again from then on.
    before = world.requests.length;
    world.advance(10 * MINUTE_MS);
    await S.event(fx, "foreground");
    assert.deepEqual(proofRequests(world, before), [], moment);
  }
  // A measurement the backend holds no proofs of marks the log on: every synchronization asks
  // again (not sooner than five minutes after an answer), the mark stands, and a stale runtime
  // asks nothing.
  const fx = S.fixture(source, { nodes: 1, device: { securityStatus: true } });
  const world = fx.world;
  await S.start(fx);
  const other = bridge.randomMeasurement();
  const receiver = world.addNode({ release: "v2.6.0", measurement: other, offered: false });
  fx.nodes[0].record("c", [{
    t: "grant_transferred_out", time_ms: world.now, to: receiver.id, release: "v2.6.0", pcr0: other.pcr0, pcr1: other.pcr1, pcr2: other.pcr2,
  }]);
  await nextDay(fx);
  await nextDay(fx);
  assert.equal(told(world), "attention told attention:unlisted_release grant active");
  for (let stay = 0; stay < 3; stay += 1) {
    const before = world.requests.length;
    world.advance(10 * MINUTE_MS);
    await S.event(fx, "foreground");
    assert.deepEqual(proofRequests(world, before), [digestOf(other)]);
    assert.equal(told(world), "attention told attention:unlisted_release grant active");
  }
  world.account.servedProgram = VERSION + 1;
  const before = world.requests.length;
  world.advance(10 * MINUTE_MS);
  await S.event(fx, "foreground");
  assert.deepEqual(proofRequests(world, before), []);
});

// ---- The verdicts the device keeps, and the releases a log holds ----

/** A node of release with a measurement of its own and release proofs: {node, measurement,
 *  release, proofs}. The backend holds the proofs when held is not false. proofs are options of
 *  model.proofsOf, node options of the node. */
function releaseNode(fx, release, given) {
  const options = given || {};
  const measurement = bridge.randomMeasurement();
  const proofs = model.proofsOf(fx.parties, release, measurement, options.proofs);
  if (options.held !== false) fx.world.releaseProofs.set(release, proofs);
  const node = fx.world.addNode(Object.assign({ release: release, measurement: measurement }, options.node || {}));
  return { node: node, measurement: measurement, release: release, proofs: proofs };
}

/** The key of the account moves from the node of the fixture through count releases no list
 *  has, one a day, with a synchronization of the device after each move. made(at) are the
 *  options of releaseNode for the release at the index at. Returns {lines, holders}: what the
 *  device published and was told after each day, and the releases. */
async function movedThrough(fx, count, made) {
  const world = fx.world;
  const lines = [];
  const holders = [];
  let holder = { node: fx.nodes[0], release: "v2.4.0" };
  for (let at = 0; at < count; at += 1) {
    const next = releaseNode(fx, "v2." + (5 + at) + ".0", made === undefined ? undefined : made(at));
    moveKey(world, holder.node, holder.release, next.node, next.measurement, next.release);
    holder = next;
    holders.push(next);
    await nextDay(fx);
    lines.push(told(world));
  }
  return { lines: lines, holders: holders };
}

/** The app starts on an installation that kept nothing of the program store (the Keychain is
 *  there), and synchronizes once a day for days days. Returns what the device published and was
 *  told at the start and after each day. */
async function freshInstallation(fx, days) {
  const world = fx.world;
  world.store.clear();
  world.securityStatuses.length = 0;
  await S.start(fx);
  const lines = [told(world)];
  for (let day = 0; day < days; day += 1) {
    await nextDay(fx);
    lines.push(told(world));
  }
  return lines;
}

test("the key of the account moves through releases no list has, each with release proofs that hold: the device that saw every move and an installation that kept nothing verify the log and keep the grant, with five, ten and thirty such releases, and no release is asked for more than once by an installation", async () => {
  for (const count of [5, 10, 30]) {
    const fx = S.fixture(source, { nodes: 1, device: { securityStatus: true } });
    const world = fx.world;
    await S.start(fx);
    // The device that saw every move: the log is verified after each of them.
    const seen = await movedThrough(fx, count);
    for (let day = 0; day < 2; day += 1) {
      await nextDay(fx);
      seen.lines.push(told(world));
    }
    assert.deepEqual(Array.from(new Set(seen.lines)), ["verified told ok grant active"], String(count));
    assert.equal(keptProven(world).length, count + 1, String(count));
    const every = [fx.measurement].concat(seen.holders.map((item) => item.measurement)).map(digestOf).sort();
    assert.deepEqual(proofRequests(world).sort(), every, String(count));
    const shown = await S.call(fx, "read_log", { limit: 50 });
    assert.equal(shown.value.status, "verified", String(count));
    // An installation that kept nothing reads the same history: the release that holds the key
    // is shown by its node, and the releases before it by the node documents of their nodes.
    // The backend is asked for the proofs of each measurement once, four in a step or a round.
    const before = world.requests.length;
    const fresh = await freshInstallation(fx, 3);
    assert.equal(fresh[fresh.length - 1], "verified told ok grant active", String(count));
    assert.ok(fresh.every((line) => line.indexOf("attention") < 0 && line.indexOf("grant active") > 0), String(count) + ": " + fresh.join(" | "));
    assert.equal(keptProven(world).length, count + 1, String(count));
    assert.equal(world.securityStatuses.filter((item) => item.status === "attention").length, 0, String(count));
    assert.deepEqual(proofRequests(world, before).sort(), every, String(count));
    // The runtime after it, and the screen.
    await S.start(fx);
    await nextDay(fx);
    assert.equal(told(world), "verified told ok grant active", String(count));
    assert.equal((await S.call(fx, "read_log", { limit: 50 })).value.status, "verified", String(count));
    assert.deepEqual(refusals(world), [], String(count));
  }
});

test("a release among them without release proofs that hold stays a measurement no list has: the log of an installation that kept nothing is pending for a day and then marked", async () => {
  // The third of five releases that held the key has no proofs, proofs of a runner the owner of
  // the repository hosts, or proofs of another measurement; the others have proofs that hold.
  const other = bridge.randomMeasurement();
  for (const [name, broken, refused] of [
    ["no proofs", { held: false }, []],
    ["proofs of another runner", { proofs: { attestation: { identity: { 11: "self-hosted" } } } }, ["v6: identity 11"]],
    ["a statement of another measurement", { proofs: { statement: null } }, ["v1: measurement"]],
  ]) {
    const fx = S.fixture(source, { nodes: 1, device: { securityStatus: true } });
    const world = fx.world;
    await S.start(fx);
    const made = (at) => {
      if (at !== 2) return undefined;
      if (broken.proofs !== undefined && broken.proofs.statement === null) {
        return { held: false, proofs: { statement: model.statementOf("v2.7.0", other), attested: Object.assign({ release: "v2.7.0" }, other) } };
      }
      return broken;
    };
    const moved = await movedThrough(fx, 5, made);
    if (name === "a statement of another measurement") {
      // (The backend hands the proofs of the other measurement out for the digest of this one.)
      world.measureProofs.set(digestOf(moved.holders[2].measurement), moved.holders[2].proofs);
    }
    const fresh = await freshInstallation(fx, 2);
    assert.equal(fresh[0], "pending told pending grant active", name);
    assert.equal(fresh[1], "attention told attention:unlisted_release grant active", name);
    assert.equal(fresh[2], "attention told attention:unlisted_release grant active", name);
    assert.deepEqual(keptProven(world).sort(), ["v2.4.0", "v2.5.0", "v2.6.0", "v2.8.0", "v2.9.0"], name);
    assert.deepEqual(Array.from(new Set(refusals(world))), refused, name);
    // The one measurement the device keeps as one no list has is that of the third release,
    // and it held the key.
    const kept = world.stored("log.unaccepted");
    assert.deepEqual(Object.keys(kept), [digestOf(moved.holders[2].measurement)], name);
    assert.equal(kept[digestOf(moved.holders[2].measurement)].held, true, name);
  }
});

test("the device keeps the verdicts of 256 measurements, the ones made last: a verdict that left is made again when the device meets the measurement again", async () => {
  const fx = S.fixture(source, { nodes: 1 });
  const world = fx.world;
  await S.start(fx);
  const digest = digestOf(fx.measurement);
  // 300 verdicts in the store, each made a minute after the one before, the one of the fixture
  // first of all.
  const kept = world.stored("log.proven");
  kept.measures[digest].proven_ms = 1000;
  for (let at = 0; at < 299; at += 1) {
    kept.measures[digestOf(bridge.randomMeasurement())] = { release: "v3." + at + ".0", proven_ms: 1000 + (at + 1) * MINUTE_MS };
  }
  world.store.set("log.proven", JSON.stringify(kept));
  // A runtime that proves one more measurement writes the 256 made last: the one of the fixture
  // leaves the store, and stays with the runtime (its node keeps its grant without a request).
  const more = releaseNode(fx, "v2.5.0");
  let before = world.requests.length;
  world.advance(25 * HOUR_MS);
  await S.start(fx);
  assert.deepEqual(proofRequests(world, before), [digestOf(more.measurement)]);
  const written = world.stored("log.proven").measures;
  assert.equal(Object.keys(written).length, 256);
  assert.equal(written[digest], undefined);
  assert.equal(written[digestOf(more.measurement)].release, "v2.5.0");
  assert.equal(Object.values(written).filter((item) => item.proven_ms < 1000 + 45 * MINUTE_MS).length, 0);
  assert.equal(fx.nodes[0].grants.has(world.userId), true);
  assert.equal(more.node.grants.has(world.userId), true);
  // The next runtime meets the measurement of the fixture again: it asks for its proofs once
  // more, verifies them, and the node keeps its grant. Nothing marks the log meanwhile.
  before = world.requests.length;
  world.advance(25 * HOUR_MS);
  await S.start(fx);
  assert.deepEqual(proofRequests(world, before), [digest]);
  assert.equal(world.state.grant.state, "active");
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.stored("log.proven").measures[digest].release, "v2.4.0");
  assert.equal(Object.keys(world.stored("log.proven").measures).length, 256);
});

// ---- The file that states the verdict of the program on proofs ----

test("prove.js ends with the status 0 for release proofs the program takes and with 1 for proofs it refuses, with the check that refuses them, and states what the program makes of the attestation response of a node of that release", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "prove-"));
  const run = (args) => child.spawnSync(process.execPath, [path.join(__dirname, "prove.js")].concat(args), { encoding: "utf8" });
  const real = path.join(__dirname, "fixtures", "release-proofs-v2.4.0-rc.1.json");
  // The proofs of a published release, with one argument (the call of the release workflow).
  const held = run([real]);
  assert.equal(held.status, 0, held.stdout + held.stderr);
  assert.ok(held.stdout.endsWith("program version " + VERSION + ": the proofs show release v2.4.0-rc.1\n"), held.stdout);
  assert.match(held.stdout, /extension {2}9 \(Build Signer URI\): "https:\/\/github\.com\/pickle-com\/credential-enclave\/\.github\/workflows\/enclave-build\.yml@3f84e8368fcdf1f89e42ca629670bfe0989b6f13": holds/);
  assert.match(held.stdout, /extension 18 \(Build Config URI\): .*: not judged/);
  // The same proofs from the two files a build leaves: the statement and the bundle.
  const proofs = JSON.parse(fs.readFileSync(real, "utf8"));
  const statementFile = path.join(dir, "measurements.json");
  const bundleFile = path.join(dir, "bundle.json");
  fs.writeFileSync(statementFile, Buffer.from(proofs.statement, "base64url"));
  fs.writeFileSync(bundleFile, JSON.stringify(proofs.attestation));
  assert.equal(run(["--statement", statementFile, "--attestation", bundleFile]).status, 0);
  // Proofs changed in one place: the status 1 and the check.
  const changed = JSON.parse(JSON.stringify(proofs));
  changed.attestation.verificationMaterial.tlogEntries[0].inclusionProof.treeSize = "1";
  const changedFile = path.join(dir, "changed.json");
  fs.writeFileSync(changedFile, JSON.stringify(changed));
  const refused = run([changedFile]);
  assert.equal(refused.status, 1, refused.stdout + refused.stderr);
  assert.match(refused.stdout, /refused: v4: inclusion proof\n$/);
  // A program that takes another build workflow.
  const programFile = path.join(dir, "program.js");
  fs.writeFileSync(programFile, model.withBuilders(source, [{ workflow: ".github/workflows/other.yml", commit: "0".repeat(40) }]));
  const other = run([real, "--program", programFile]);
  assert.equal(other.status, 1);
  assert.match(other.stdout, /extension {2}9 .*NOT a build workflow the program takes/);
  assert.match(other.stdout, /refused: v6: identity 9\n$/);
  // No file, or two: the usage.
  assert.equal(run([]).status, 2);
  assert.equal(run([real, real]).status, 2);
  fs.rmSync(dir, { recursive: true });
});
