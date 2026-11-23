// The tests of the release proofs of the secure program (docs/protocol.md, "The release proofs"),
// on the model of the bridge (bridge.js) and the model of the parties that make release proofs
// (proofs.js). Run: node --test secure-program/tests/proofs.test.js
//
// What is checked is what the program does when a node of a measurement its list does not have
// presents release proofs: whether the node receives the grant, the requests the program sends,
// what it logs for proofs it refuses, how its rounds judge the entries of such a node, and what
// the program store holds. Where the proofs are made here, the program runs with the keys and the
// certificates of the model in the place of its constants (proofs.withParties); the proofs of a
// published release run against the constants of the program as they are.
"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const bridge = require("./bridge.js");
const S = require("./scenarios.js");
const model = require("./proofs.js");
const { proofCases } = require("./proof-cases.js");

const source = fs.readFileSync(path.join(__dirname, "..", "secure-program.js"), "utf8");
const VECTORS_PATHS = (process.env.SECURE_PROGRAM_VECTORS || path.join(__dirname, "..", "..", "protocol", "vectors.json"))
  .split(",").map((item) => item.trim()).filter((item) => item !== "");
const vectors = {};
for (const file of VECTORS_PATHS) {
  const read = JSON.parse(fs.readFileSync(file, "utf8"));
  for (const name of Object.keys(read)) {
    if (vectors[name] === undefined) vectors[name] = read[name];
  }
}
const { HOUR_MS } = S;
const REFUSED = "release proofs refused: ";
const PROOFS_PATH = "/api/secure/release-proofs";
const VERSION = bridge.declaredVersion(source);

// ---- Helpers ----

/** The lines the program logged for release proofs it refused, without their head. */
function refusals(world) {
  return world.logs.filter((line) => line.indexOf(REFUSED) === 0).map((line) => line.slice(REFUSED.length));
}

/** The requests for attestations the program sent since the index from: for each the node ids
 *  it named and whether it asked for the release proofs. */
function attestationRequests(world, from) {
  return world.requests.slice(from === undefined ? 0 : from).filter((request) => request.path === "/api/secure/nodes")
    .map((request) => ({ nodes: String(request.query.nodes || "").split(",").filter((id) => id !== ""), proofs: request.query.proofs }));
}

/** The verdicts of release proofs the program store keeps: [{release, proofs}] (proofs: whether
 *  the proofs are kept with the verdict), with program_min for a verdict whose statement states
 *  one above 0. */
function keptProven(world) {
  const kept = world.stored("log.proven");
  if (kept === undefined) return [];
  return Object.values(kept.measures).map((item) => Object.assign(
    { release: item.release, proofs: item.proofs !== null && typeof item.proofs === "object" },
    item.program_min === 0 ? {} : { program_min: item.program_min }));
}

/** The requests the program sent for the release proofs of measurements since the index from:
 *  for each the digests it named. */
function proofRequests(world, from) {
  return world.requests.slice(from === undefined ? 0 : from).filter((request) => request.path === PROOFS_PATH)
    .map((request) => String(request.query.measures || "").split(",").filter((digest) => digest !== ""));
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
    not_after_ms: world.now + 30 * S.DAY_MS, custody: "enclave",
  }]);
  to.record("u", [S.providerRequest(world.now)]);
  from.alive = false;
}

/** Runs one round by a synchronization a day after the last one. */
async function nextDay(fx) {
  fx.world.advance(25 * HOUR_MS);
  await S.event(fx, "foreground");
}

/** A fixture with a node of a release the program does not list: the fixture of scenarios.js
 *  (one listed node of release v2.4.0), the parties that make release proofs, and a node of
 *  release with a measurement of its own. The program of the fixture holds the keys and the
 *  certificates of the parties. options are those of S.fixture; node are options of the node. */
function laterFixture(release, options, node) {
  const fx = S.fixture(source, options);
  fx.parties = model.makeParties();
  fx.source = model.withParties(fx.source, fx.parties);
  fx.laterMeasurement = bridge.randomMeasurement();
  fx.later = fx.world.addNode(Object.assign({ release: release, measurement: fx.laterMeasurement }, node || {}));
  return fx;
}

/** The source of a program without the element of release in its list. */
function withoutListedRelease(text, release) {
  const pattern = new RegExp("\\n    \\{\\n      release: \"" + release.replace(/\./g, "\\.") + "\",[\\s\\S]*?\\n    \\},");
  assert.ok(pattern.test(text), "the program lists " + release);
  return text.replace(pattern, "");
}

// ---- The proofs of a published release, against the constants of the program ----

test("the release proofs of release v2.3.0, from public values, show its measurement to a program that lists the releases before it: the node receives the grant", async () => {
  const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "release-proofs-v2.3.0.json"), "utf8"));
  const statement = Buffer.from(fixture.statement, "base64url");
  const stated = JSON.parse(statement.toString("utf8"));
  const measurement = { pcr0: stated.pcr0, pcr1: stated.pcr1, pcr2: stated.pcr2 };
  assert.deepEqual(bridge.listedMeasurements(source).filter((item) => item.release === "v2.3.0").map((item) => item.pcr0), [stated.pcr0]);
  // The program keeps its release key, its log key, its certificates of the certificate
  // authority and the identity it asks of an attestation. The deploy keys are those of the test
  // (the deploy keys of the operator sign no release statement here), and the element of
  // v2.3.0 is taken out of the list.
  const deploy = { prod: model.ed25519KeyPair(), dev: model.ed25519KeyPair() };
  const program = model.withDeployKeys(withoutListedRelease(source, "v2.3.0"), deploy);
  const proofs = (keyId, key) => ({
    statement: fixture.statement, entry: fixture.entry, attestation: fixture.attestation,
    deploy_signatures: [{ key_id: keyId, signature: model.deploySignature(key, statement) }],
  });
  const run = async (text, target, held) => {
    const world = new bridge.World({ serverTarget: target });
    world.account.servedProgram = bridge.declaredVersion(text);
    const fx = { world: world, keys: world.createAccount(), source: text, nodes: [], legacy: [], program: null };
    const listed = bridge.listedMeasurements(text);
    const before = listed.filter((item) => item.release === "v2.2.0")[0];
    fx.legacy.push(world.addNode({ release: "v2.2.0", measurement: before }));
    fx.nodes.push(world.addNode({ release: "v2.3.0", measurement: measurement }));
    if (held !== null) world.releaseProofs.set("v2.3.0", held);
    await S.start(fx);
    return fx;
  };
  const shown = await run(program, "prod", proofs("prod", deploy.prod));
  assert.deepEqual(refusals(shown.world), []);
  assert.equal(shown.nodes[0].grants.has(shown.world.userId), true);
  assert.equal(shown.legacy[0].grants.has(shown.world.userId), true);
  assert.equal(shown.world.state.grant.state, "active");
  assert.deepEqual(attestationRequests(shown.world).map((request) => [request.nodes.length, request.proofs]), [[2, undefined], [1, "1"]]);
  assert.deepEqual(keptProven(shown.world), [{ release: "v2.3.0", proofs: true }]);
  // The same proofs for a build of the server target dev: the deploy key dev signs.
  const dev = await run(program, "dev", proofs("dev", deploy.dev));
  assert.equal(dev.nodes[0].grants.has(dev.world.userId), true);
  const unsigned = await run(program, "dev", proofs("prod", deploy.prod));
  assert.deepEqual(refusals(unsigned.world), ["p3: signature"]);
  assert.equal(unsigned.nodes[0].grants.has(unsigned.world.userId), false);
  // Under the deploy keys of the program the signature of the test key is none.
  const real = await run(withoutListedRelease(source, "v2.3.0"), "prod", proofs("prod", deploy.prod));
  assert.deepEqual(refusals(real.world), ["p3: signature"]);
  assert.equal(real.nodes[0].grants.has(real.world.userId), false);
  // The program that lists v2.3.0 asks for no proofs and reads none: the release is not later
  // than a listed one, and its node receives the grant by the list.
  const listed = await run(model.withDeployKeys(source, deploy), "prod", proofs("prod", deploy.prod));
  assert.equal(listed.nodes[0].grants.has(listed.world.userId), true);
  assert.deepEqual(attestationRequests(listed.world).map((request) => request.proofs), [undefined]);
  assert.deepEqual(keptProven(listed.world), []);
  // Another measurement than the one the statement names.
  const other = await run(program, "prod", proofs("prod", deploy.prod));
  const stranger = other.world.addNode({ release: "v2.3.0", measurement: bridge.randomMeasurement() });
  other.world.advance(2 * HOUR_MS);
  await S.event(other, "foreground");
  assert.deepEqual(refusals(other.world), ["p1: measurement"]);
  assert.equal(stranger.grants.has(other.world.userId), false);
});

// ---- Proofs that differ in one place from proofs that hold ----

test("release proofs that hold hand the node its grant, and proofs that differ from them in one place are refused by the check of that place: the node stays a node of a later release", async () => {
  const listed = bridge.listedMeasurements(S.fixture(source).source);
  const cases = proofCases("v2.5.0", listed[listed.length - 1].release, VERSION);
  const seen = new Map();
  for (const item of cases) {
    const fx = S.fixture(source, { target: item.target });
    const world = fx.world;
    const later = world.addNode({ release: item.release, measurement: item.measurement });
    world.releaseProofs.set(item.release, item.proofs);
    await S.start(fx, model.withParties(fx.source, item.constants, item.logs));
    seen.set(item.reason, (seen.get(item.reason) || 0) + 1);
    // The listed node receives its grant whatever the other node presents.
    assert.equal(fx.nodes[0].grants.has(world.userId), true, item.name);
    assert.deepEqual(attestationRequests(world).map((request) => [request.nodes.length, request.proofs]), [[2, undefined], [1, "1"]], item.name);
    if (item.reason === null && item.later !== true) {
      assert.deepEqual(refusals(world), [], item.name);
      assert.equal(later.grants.has(world.userId), true, item.name);
      assert.equal(world.state.log.status, "verified", item.name);
      assert.equal(world.state.log.newer_release_nodes, 0, item.name);
      assert.equal(keptProven(world).length, 1, item.name);
      assert.equal(keptProven(world)[0].release, item.release, item.name);
      assert.equal(keptProven(world)[0].proofs, true, item.name);
      // The backend is asked for the proofs of no measurement: the node showed them.
      assert.deepEqual(proofRequests(world), [], item.name);
      continue;
    }
    if (item.reason === null) {
      // Proofs that hold and whose statement states a later program: nothing is refused, the
      // verdict is kept without the proofs, and the node is one of a release this program does
      // not accept.
      assert.deepEqual(refusals(world), [], item.name);
      assert.equal(later.grants.has(world.userId), false, item.name);
      assert.equal(world.state.log.status, "pending", item.name);
      assert.equal(world.state.log.newer_release_nodes, 1, item.name);
      assert.equal(keptProven(world).length, 1, item.name);
      assert.equal(keptProven(world)[0].proofs, false, item.name);
      assert.ok(keptProven(world)[0].program_min > VERSION, item.name);
      assert.deepEqual(proofRequests(world), [], item.name);
      continue;
    }
    // Proofs that are null are no proofs: nothing is verified and nothing refused. The proofs
    // the node presented are refused once: the backend hands the same proofs out for the
    // measurement, and the program does not verify them a second time.
    assert.deepEqual(refusals(world), item.proofs === null ? [] : [item.reason], item.name);
    assert.equal(later.grants.has(world.userId), false, item.name);
    assert.equal(world.state.log.status, "pending", item.name);
    assert.equal(world.state.log.newer_release_nodes, 1, item.name);
    assert.deepEqual(keptProven(world), [], item.name);
    assert.equal(world.runtime.rejected_nodes, 0, item.name);
    assert.deepEqual(proofRequests(world), [[digestOf(item.measurement)]], item.name);
  }
  // Every check has its cases.
  for (const reason of [
    null, "shape", "p1: statement", "p1: release tag", "p1: measurement", "p5: release order", "p3: shape", "p3: signature",
    "p2: entry", "p2: log", "p2: promise", "p2: signed entry timestamp", "p2: body", "p2: statement hash", "p2: release key",
    "p2: release signature", "p4: shape", "p4: size", "p4: payload", "p4: certificate", "p4: certificate validity",
    "p4: certificate authority", "p4: certificate issuer", "p4: certificate root", "p4: identity 8", "p4: identity 9",
    "p4: identity 11", "p4: identity 12", "p4: identity 14", "p4: identity 15", "p4: identity 17", "p4: identity 18",
    "p4: identity 20", "p4: identity 22", "p4: signature", "p4: log", "p4: log entry kind", "p4: log entry payload",
    "p4: log entry signature", "p4: log entry certificate", "p4: signed entry timestamp", "p4: inclusion proof",
    "p4: checkpoint", "p4: predicate type", "p4: predicate release", "p4: predicate pcr0", "p4: predicate pcr1", "p4: predicate pcr2",
    "p4: predicate program_min",
  ]) {
    assert.ok(seen.get(reason) >= 1, "cases of " + reason);
  }
});

// ---- The verdict of a node on the same statement and entry ----

test("the program reads a release statement and the entry of its record as a node does: the endorsement cases of the vectors", { skip: vectors.endorsement === undefined }, async () => {
  const given = vectors.endorsement;
  const spkiOf = (pem) => Buffer.from(pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s/g, ""), "base64");
  const logOfVectors = given.logs.filter((log) => log.form === "rekor_v1")[0];
  const stated = JSON.parse(given.statement_text);
  const measurement = { pcr0: stated.pcr0, pcr1: stated.pcr1, pcr2: stated.pcr2 };
  // The reasons the program logs for the checks of docs/protocol.md 10.3. The program asks no
  // clock (check 5), and its one log is of the form Rekor v1: an entry of another log fails
  // check 2.
  const reasons = {
    1: ["p1: statement"], 2: ["p2: log"], 3: ["p2: promise", "p2: signed entry timestamp"],
    4: ["p2: body", "p2: statement hash", "p2: release key", "p2: release signature"], 6: ["p5: release order", "p1: release tag"],
  };
  let compared = 0;
  for (const item of given.cases) {
    // The release of the node of a case is the latest release the program lists.
    if (!/^v\d+\.\d+\.\d+$/.test(item.own_release)) continue;
    const parties = model.makeParties();
    const fx = S.fixture(source, { nodes: 0, legacy: 1 });
    const world = fx.world;
    const constants = Object.assign({}, parties, { release: { spki: spkiOf(given.release_key_pem) } });
    let program = model.withParties(fx.source, constants, [spkiOf(logOfVectors.key_pem), parties.log.key.spki]);
    if (item.own_release !== "v2.4.0") program = bridge.withListedRelease(program, item.own_release, bridge.randomMeasurement());
    const statement = Buffer.from(item.endorsement.statement, "base64url");
    let attested = Object.assign({ release: given.release }, measurement);
    try {
      const read = JSON.parse(statement.toString("utf8"));
      attested = { release: read.release, pcr0: read.pcr0, pcr1: read.pcr1, pcr2: read.pcr2 };
    } catch (error) {
      // A statement that is no JSON is refused before its attestation is read.
    }
    const later = world.addNode({ release: given.release, measurement: measurement, format: 3 });
    world.releaseProofs.set(given.release, {
      statement: item.endorsement.statement, entry: item.endorsement.entry,
      deploy_signatures: [{ key_id: "prod", signature: model.deploySignature(parties.deploy.prod, statement) }],
      attestation: model.attestationOf(parties, attested),
    });
    await S.start(fx, program);
    const own = item.endorsement.entry !== null && typeof item.endorsement.entry === "object" &&
      item.endorsement.entry.log_id === logOfVectors.log_id;
    const check = item.accepted ? null : item.check;
    const expected = check === 1 || check === 6 ? reasons[check] : !own ? reasons[2] : check === null || check === 5 ? null : reasons[check];
    const refused = refusals(world);
    if (expected === null) {
      assert.deepEqual(refused, [], item.name);
      assert.equal(later.grants.has(world.userId), true, item.name);
    } else {
      assert.equal(refused.length, 1, item.name);
      assert.ok(expected.indexOf(refused[0]) >= 0, item.name + ": " + refused[0]);
      assert.equal(later.grants.has(world.userId), false, item.name);
    }
    compared += 1;
  }
  assert.ok(compared >= 20);
});

// ---- The grant step ----

test("a node of a listed release is asked for no release proofs, and release proofs a response of such a node carries are not read", async () => {
  const plain = S.fixture(source, { nodes: 2, legacy: 1 });
  await S.start(plain);
  const fx = S.fixture(source, { nodes: 2, legacy: 1 });
  const world = fx.world;
  // The backend hands release proofs out with every attestation, unasked: proofs that hold for
  // no measurement of these nodes.
  const parties = model.makeParties();
  world.proofsUnasked = true;
  world.releaseProofs.set("v2.4.0", model.proofsOf(parties, "v2.4.0", bridge.randomMeasurement()));
  world.releaseProofs.set(fx.latest.release, { statement: "x" });
  await S.start(fx, model.withParties(fx.source, parties));
  // The same requests in the same order as without them (the ids of the nodes of a fixture are
  // its own).
  const lines = (of) => S.requestLines(of).map((line) => line.replace(/\/nodes\/[A-Za-z0-9_-]{43}\//, "/nodes/{node}/"));
  assert.deepEqual(S.result(fx), S.result(plain));
  assert.deepEqual(lines(world), lines(plain.world));
  assert.ok(world.requests.every((request) => request.query === undefined || request.query === null || request.query.proofs === undefined));
  assert.deepEqual(refusals(world), []);
  assert.deepEqual(keptProven(world), []);
  // The renewals of the next days, and a procedure of the user, ask for none either. The
  // backend is asked for the release proofs of no measurement, and the log screen asks for none.
  for (let day = 0; day < 3; day += 1) await nextDay(fx);
  await S.call(fx, "sync", {});
  await S.call(fx, "read_log", { limit: 10 });
  assert.ok(world.requests.every((request) => request.query === undefined || request.query === null || request.query.proofs === undefined));
  assert.deepEqual(proofRequests(world), []);
  assert.equal(world.stored("log.proven"), undefined);
});

test("release proofs that hold: one node of the measurement is asked for them once, every node of the measurement receives its grant in that step, and a later runtime verifies the kept proofs again and asks for none", async () => {
  const fx = laterFixture("v2.5.0", { nodes: 1 });
  const world = fx.world;
  const second = world.addNode({ release: "v2.5.0", measurement: fx.laterMeasurement });
  const reserve = world.addNode({ release: "v2.5.0", measurement: fx.laterMeasurement, role: "reserve" });
  world.releaseProofs.set("v2.5.0", model.proofsOf(fx.parties, "v2.5.0", fx.laterMeasurement));
  await S.start(fx);
  for (const node of [fx.nodes[0], fx.later, second, reserve]) assert.equal(node.grants.has(world.userId), true);
  assert.equal(world.state.grant.state, "active");
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.runtime.rejected_nodes, 0);
  // One request names the four nodes, and one more names one node of the measurement with the
  // query proofs.
  const requests = attestationRequests(world);
  assert.deepEqual(requests.map((request) => [request.nodes.length, request.proofs]), [[4, undefined], [1, "1"]]);
  assert.ok([fx.later.id, second.id, reserve.id].indexOf(requests[1].nodes[0]) >= 0);
  assert.deepEqual(keptProven(world), [{ release: "v2.5.0", proofs: true }]);
  // The grants of the device name the release the proofs name, and the nodes write format 3: no
  // node of the release is written into the ledger of the earlier programs.
  assert.equal(world.stored("log.grants")[fx.later.id].release, "v2.5.0");
  // The renewal a day later, in a new runtime: the kept proofs are verified again by that
  // runtime, no request asks for proofs, and the grants are renewed.
  const before = world.requests.length;
  const commands = fx.later.commands.length;
  world.advance(25 * HOUR_MS);
  world.releaseProofs.clear();
  await S.start(fx);
  assert.deepEqual(attestationRequests(world, before).map((request) => [request.nodes.length, request.proofs]), [[4, undefined]]);
  assert.equal(fx.later.commands.length, commands + 1);
  assert.equal(world.state.grant.state, "active");
  assert.deepEqual(refusals(world), []);
  // A procedure of the user that needs a node holding the grant goes through, with the nodes
  // of the listed release gone.
  fx.nodes[0].alive = false;
  world.advance(25 * HOUR_MS);
  const synced = await S.call(fx, "sync", {});
  assert.equal(synced.ok, true);
  assert.equal(world.state.grant.state, "active");
});

test("without release proofs, and with proofs that fail, the node is one of a later release: it receives no grant, the proofs are asked for again an hour after the last request, and proofs that then hold hand it the grant", async () => {
  const fx = laterFixture("v2.5.0", { nodes: 1 });
  const world = fx.world;
  await S.start(fx);
  assert.equal(fx.later.grants.has(world.userId), false);
  assert.equal(world.state.log.newer_release_nodes, 1);
  assert.deepEqual(attestationRequests(world).map((request) => [request.nodes.length, request.proofs]), [[2, undefined], [1, "1"]]);
  // Within the hour the node is not asked again, by an event or by a procedure of the user.
  let before = world.requests.length;
  world.advance(HOUR_MS / 2);
  await S.event(fx, "foreground");
  await S.call(fx, "sync", {});
  assert.deepEqual(attestationRequests(world, before), []);
  // After the hour it is asked for its attestation with the proofs, in one request. The backend
  // holds proofs of a runner the owner of the repository hosts: refused.
  world.releaseProofs.set("v2.5.0", model.proofsOf(fx.parties, "v2.5.0", fx.laterMeasurement, { attestation: { identity: { 11: "self-hosted" } } }));
  before = world.requests.length;
  world.advance(HOUR_MS / 2 + 1000);
  await S.event(fx, "foreground");
  assert.deepEqual(attestationRequests(world, before), [{ nodes: [fx.later.id], proofs: "1" }]);
  assert.deepEqual(refusals(world), ["p4: identity 11"]);
  assert.equal(fx.later.grants.has(world.userId), false);
  assert.deepEqual(keptProven(world), []);
  // The backend holds proofs that hold: the next request for them, an hour later, shows the
  // measurement, and the node receives its grant in that step.
  world.releaseProofs.set("v2.5.0", model.proofsOf(fx.parties, "v2.5.0", fx.laterMeasurement));
  before = world.requests.length;
  world.advance(HOUR_MS + 1000);
  await S.event(fx, "foreground");
  assert.deepEqual(attestationRequests(world, before), [{ nodes: [fx.later.id], proofs: "1" }]);
  assert.equal(fx.later.grants.has(world.userId), true);
  assert.equal(world.state.grant.state, "active");
  // The round of the next day forgets the measurement it kept as one no list has.
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.state.log.newer_release_nodes, 0);
  assert.deepEqual(world.stored("log.unaccepted"), {});
});

test("a request for release proofs that fails leaves the node one of a later release for this step and fails nothing else", async () => {
  const fx = laterFixture("v2.5.0", { nodes: 1 });
  const world = fx.world;
  world.releaseProofs.set("v2.5.0", model.proofsOf(fx.parties, "v2.5.0", fx.laterMeasurement));
  // (The backend of this test hands out no proofs for the digest of a measurement: the node is
  // the one place the proofs come from.)
  world.routes.proofs = false;
  world.fault((line, request) => request.path === "/api/secure/nodes" && request.query.proofs === "1", { status: 503, body: { detail: "unavailable" } }, 1);
  await S.start(fx);
  assert.equal(fx.nodes[0].grants.has(world.userId), true);
  assert.equal(fx.later.grants.has(world.userId), false);
  assert.equal(world.state.grant.state, "active");
  assert.ok(world.logs.some((line) => line.indexOf("release proofs request failed") === 0));
  // A request that failed is none the measurement was asked with: the next step asks again,
  // without waiting for the hour, and the node receives its grant.
  const before = world.requests.length;
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.deepEqual(attestationRequests(world, before), [{ nodes: [fx.later.id], proofs: "1" }]);
  assert.equal(fx.later.grants.has(world.userId), true);
});

test("what the device keeps of release proofs: a program of another version reads it as nothing, proofs that were altered are verified by no runtime and kept no longer, and the end of the account erases it", async () => {
  const fx = laterFixture("v2.5.0", { nodes: 1 });
  const world = fx.world;
  const proofs = model.proofsOf(fx.parties, "v2.5.0", fx.laterMeasurement);
  world.releaseProofs.set("v2.5.0", proofs);
  await S.start(fx);
  assert.equal(fx.later.grants.has(world.userId), true);
  const kept = world.stored("log.proven");
  assert.equal(kept.v, bridge.declaredVersion(fx.source));
  // The next version of the program, with the same list: it asks for the proofs itself.
  let before = world.requests.length;
  world.advance(25 * HOUR_MS);
  await S.start(fx, fx.source.replace(/^\s*const VERSION = \d+;/m, "  const VERSION = " + (kept.v + 1) + ";"));
  assert.deepEqual(attestationRequests(world, before).map((request) => [request.nodes.length, request.proofs]), [[2, undefined], [1, "1"]]);
  assert.equal(world.stored("log.proven").v, kept.v + 1);
  // The program of this version again, with a verdict in the store whose proofs name another
  // measurement: the runtime verifies the kept proofs before a node receives a key, refuses
  // them and keeps the verdict no longer. The backend holds no proofs now.
  const altered = JSON.parse(JSON.stringify(kept));
  const digest = Object.keys(altered.measures)[0];
  const other = bridge.randomMeasurement();
  altered.measures[digest].proofs = model.proofsOf(fx.parties, "v2.5.0", other);
  world.store.set("log.proven", JSON.stringify(altered));
  world.releaseProofs.clear();
  before = world.requests.length;
  world.advance(25 * HOUR_MS);
  const commands = fx.later.commands.length;
  await S.start(fx);
  assert.deepEqual(refusals(world).slice(-1), ["p1: measurement"]);
  assert.equal(fx.later.commands.length, commands);
  assert.deepEqual(keptProven(world), []);
  // A verdict without proofs in the store hands no key either: the proofs are asked for.
  const bare = JSON.parse(JSON.stringify(kept));
  bare.measures[digest].proofs = null;
  world.store.set("log.proven", JSON.stringify(bare));
  world.advance(25 * HOUR_MS);
  await S.start(fx);
  assert.equal(fx.later.commands.length, commands);
  // The end of the account erases what was kept.
  world.store.set("log.proven", JSON.stringify(kept));
  await S.event(fx, "account_end", { reason: "account_deleted" });
  assert.equal(world.stored("log.proven"), undefined);
});

test("the release of the binding of a node is the release its proofs name: a node of the measurement that states another release fails the verification", async () => {
  const fx = laterFixture("v2.5.1", { nodes: 1 });
  const world = fx.world;
  world.releaseProofs.set("v2.5.1", model.proofsOf(fx.parties, "v2.5.0", fx.laterMeasurement));
  await S.start(fx);
  assert.deepEqual(refusals(world), []);
  assert.equal(fx.later.grants.has(world.userId), false);
  assert.equal(world.runtime.rejected_nodes, 1);
  assert.ok(world.logs.some((line) => line.indexOf("attestation rejected: release of the binding") === 0));
});

test("a runtime verifies no further release proofs once eight failed within an hour", async () => {
  const fx = S.fixture(source, { nodes: 1 });
  const world = fx.world;
  const parties = model.makeParties();
  // Twelve nodes of twelve measurements, each with proofs of another measurement: the grant
  // step asks four of them for proofs, and the next steps the others.
  for (let at = 0; at < 12; at += 1) {
    world.addNode({ release: "v2.5." + at, measurement: bridge.randomMeasurement() });
    world.releaseProofs.set("v2.5." + at, model.proofsOf(parties, "v2.5." + at, bridge.randomMeasurement()));
  }
  await S.start(fx, model.withParties(fx.source, parties));
  assert.equal(refusals(world).length, 4);
  // The measurements already asked for are due again after an hour; the eight that were not
  // asked yet are asked in the steps before that.
  for (let step = 0; step < 4; step += 1) {
    world.advance(60000);
    await S.event(fx, "foreground");
  }
  assert.equal(refusals(world).length, 8);
  assert.ok(refusals(world).every((reason) => reason === "p1: measurement"));
});

// ---- program_min ----

test("a node of an accepted release whose binding asks for a later program receives no grant of this program, is asked once in a runtime, and is judged as the node of an accepted release that it is", async () => {
  const fx = S.fixture(source, { nodes: 1 });
  const world = fx.world;
  const version = bridge.declaredVersion(fx.source);
  const ahead = world.addNode({ release: "v2.4.0", measurement: fx.measurement, programMin: version + 1 });
  const same = world.addNode({ release: "v2.4.0", measurement: fx.measurement, programMin: version });
  await S.start(fx);
  assert.equal(ahead.grants.has(world.userId), false);
  assert.equal(same.grants.has(world.userId), true);
  assert.equal(fx.nodes[0].grants.has(world.userId), true);
  assert.equal(world.state.grant.state, "active");
  assert.equal(world.runtime.rejected_nodes, 0);
  // The node is none of a release the program does not accept: nothing is kept of it as such.
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.state.log.newer_release_nodes, 0);
  assert.deepEqual(world.stored("log.unaccepted"), {});
  assert.equal(ahead.attestations, 1);
  world.advance(HOUR_MS);
  await S.event(fx, "foreground");
  await S.call(fx, "sync", {});
  assert.equal(ahead.attestations, 1);
  // An entry the node writes for the key of the account is the entry of an accepted node.
  ahead.record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r", provider: "slack", scope: "" }]);
  await nextDay(fx);
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.state.log.unknown_nodes, 0);
  // The program of the version the node asks for hands it the grant.
  await S.start(fx, fx.source.replace(/^\s*const VERSION = \d+;/m, "  const VERSION = " + (version + 1) + ";"));
  assert.equal(ahead.grants.has(world.userId), true);
  // A node whose binding states a program_min that is no non-negative integer fails the
  // attestation of a node that is to receive a key. Its node document is read as that of any
  // node: when the key of the account reaches it by a transfer, its entries are those of an
  // accepted node, and no round is held back.
  for (const value of ["44", -1, 1.5, null]) {
    const odd = S.fixture(source, { nodes: 1, device: { securityStatus: true } });
    const node = odd.world.addNode({ release: "v2.4.0", measurement: odd.measurement, programMin: value });
    await S.start(odd);
    assert.equal(node.grants.has(odd.world.userId), false, String(value));
    assert.equal(odd.world.runtime.rejected_nodes, 1, String(value));
    const first = odd.nodes[0];
    first.record("c", [{
      t: "grant_transferred_out", time_ms: odd.world.now, to: node.id, release: "v2.4.0",
      pcr0: odd.measurement.pcr0, pcr1: odd.measurement.pcr1, pcr2: odd.measurement.pcr2,
    }]);
    node.grants.set(odd.world.userId, first.grants.get(odd.world.userId));
    node.record("c", [{ t: "grant_transferred_in", time_ms: odd.world.now, from: first.id, release: "v2.4.0", not_after_ms: odd.world.now + 30 * S.DAY_MS, custody: "enclave" }]);
    node.record("c", [{ t: "connection_created", time_ms: odd.world.now, record_id: "r", provider: "slack", scope: "" }]);
    for (let day = 0; day < 4; day += 1) {
      await nextDay(odd);
      assert.equal(odd.world.state.log.status, "verified", String(value) + " day " + day);
    }
    assert.deepEqual(odd.world.stored("log.blocked"), { first_ms: 0, count: 0 }, String(value));
    assert.equal(odd.world.securityStatuses.filter((item) => item.status === "attention").length, 0, String(value));
    assert.equal(odd.world.stored("log.nodes")[node.id].r, "v2.4.0", String(value));
  }
  // When no node takes a grant of this program, a procedure of the user fails as for the nodes
  // of a later release.
  const alone = S.fixture(source, { nodes: 0 });
  alone.world.addNode({ release: "v2.4.0", measurement: alone.measurement, programMin: version + 1 });
  await S.start(alone);
  assert.equal(alone.world.state.grant.state, "none");
  assert.deepEqual(await S.call(alone, "connect", { target: "github" }), { ok: false, code: "attestation_failed" });
});

// ---- The rounds ----

test("the rounds judge the nodes of a measurement release proofs showed as accepted nodes: an entry such a node wrote, a transfer of the key to that measurement, and a node document that carries the proofs", async () => {
  // A node of the proven release that holds the grant writes entries: the round verifies them.
  const fx = laterFixture("v2.5.0", { nodes: 1 });
  const world = fx.world;
  const proofs = model.proofsOf(fx.parties, "v2.5.0", fx.laterMeasurement);
  world.releaseProofs.set("v2.5.0", proofs);
  await S.start(fx);
  fx.later.record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r", provider: "slack", scope: "" }]);
  fx.later.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/a", "POST")]);
  // A node of the listed release hands the key on to another node of the proven measurement.
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
  // grant) learns the measurement from the node document: with the proofs in the document the
  // entries of the node are those of an accepted node; without them the measurement is one no
  // list has, pending for its day.
  for (const carried of [true, false]) {
    const reader = S.fixture(source, { nodes: 1 });
    const parties = model.makeParties();
    const measurement = bridge.randomMeasurement();
    const held = reader.world.addNode({
      release: "v2.5.0", measurement: measurement, offered: false,
      documentProofs: carried ? model.proofsOf(parties, "v2.5.0", measurement) : undefined,
    });
    await S.start(reader, model.withParties(reader.source, parties));
    reader.nodes[0].record("c", [{
      t: "grant_transferred_out", time_ms: reader.world.now, to: held.id, release: "v2.5.0",
      pcr0: measurement.pcr0, pcr1: measurement.pcr1, pcr2: measurement.pcr2,
    }]);
    held.record("c", [{ t: "grant_transferred_in", time_ms: reader.world.now, from: reader.nodes[0].id, release: "v2.4.0" }]);
    await nextDay(reader);
    // The entry of the receiving node is read with its document in the round that reads the
    // transfer: the proofs of the document show the measurement before the round is judged.
    assert.equal(reader.world.state.log.status, carried ? "verified" : "pending", String(carried));
    assert.equal(reader.world.state.log.newer_release_nodes, carried ? 0 : 1, String(carried));
    assert.deepEqual(keptProven(reader.world), carried ? [{ release: "v2.5.0", proofs: true }] : [], String(carried));
    assert.deepEqual(attestationRequests(reader.world).filter((request) => request.proofs !== undefined), [], String(carried));
    await nextDay(reader);
    assert.equal(reader.world.state.log.status, carried ? "verified" : "attention", String(carried));
  }
});

test("a node document whose release proofs fail is the document of a measurement no list has, as one without proofs", async () => {
  const reader = S.fixture(source, { nodes: 1 });
  const parties = model.makeParties();
  const measurement = bridge.randomMeasurement();
  const held = reader.world.addNode({
    release: "v2.5.0", measurement: measurement, offered: false,
    documentProofs: model.proofsOf(parties, "v2.5.0", measurement, { attestation: { identity: { 20: "workflow_dispatch" } } }),
  });
  await S.start(reader, model.withParties(reader.source, parties));
  held.record("c", [{ t: "connection_created", time_ms: reader.world.now, record_id: "r", provider: "slack", scope: "" }]);
  await nextDay(reader);
  assert.deepEqual(refusals(reader.world), ["p4: identity 20"]);
  assert.equal(reader.world.state.log.status, "pending");
  assert.equal(reader.world.state.log.newer_release_nodes, 1);
});

test("a stale runtime verifies release proofs as any runtime does: the node of the proven release receives its grant from a program that is behind the served one", async () => {
  const fx = laterFixture("v2.5.0", { nodes: 0 });
  const world = fx.world;
  world.account.servedProgram = bridge.declaredVersion(fx.source) + 1;
  world.releaseProofs.set("v2.5.0", model.proofsOf(fx.parties, "v2.5.0", fx.laterMeasurement));
  await S.start(fx);
  assert.equal(world.runtime.program_stale, true);
  assert.equal(fx.later.grants.has(world.userId), true);
  assert.equal(world.state.grant.state, "active");
  const called = await S.call(fx, "sync", {});
  assert.equal(called.ok, true);
});

// ---- The verdicts the device keeps, and the releases a log holds ----

/** A fixture whose program holds the keys and the certificates of parties that make release
 *  proofs: the fixture of scenarios.js with one listed node of release v2.4.0. */
function partiesFixture(options) {
  const fx = S.fixture(source, Object.assign({ nodes: 1, device: { securityStatus: true } }, options || {}));
  fx.parties = model.makeParties();
  fx.source = model.withParties(fx.source, fx.parties);
  return fx;
}

/** A node of release with a measurement of its own and release proofs: {node, measurement,
 *  release, proofs}. The backend holds the proofs when held is true, and the node document
 *  carries them when carried is true. proofs are options of model.proofsOf, node options of the
 *  node. */
function releaseNode(fx, release, given) {
  const options = given || {};
  const measurement = bridge.randomMeasurement();
  const proofs = model.proofsOf(fx.parties, release, measurement, options.proofs);
  if (options.held !== false) fx.world.releaseProofs.set(release, proofs);
  const node = fx.world.addNode(Object.assign(
    { release: release, measurement: measurement, documentProofs: options.carried === false ? undefined : proofs }, options.node || {}));
  return { node: node, measurement: measurement, release: release, proofs: proofs };
}

/** The key of the account moves from the listed node of the fixture through count releases the
 *  program does not list, one a day, with a synchronization of the device after each move.
 *  made(at) are the options of releaseNode for the release at the index at. Returns {lines,
 *  holders}: what the device published and was told after each day, and the releases. */
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

test("the key of the account moves through releases the program does not list, each with release proofs that hold: the device that saw every move and an installation that kept nothing verify the log and keep the grant, with five, ten and thirty such releases", async () => {
  for (const count of [5, 10, 30]) {
    const fx = partiesFixture();
    const world = fx.world;
    await S.start(fx);
    // The device that saw every move: the log is verified after each of them.
    const seen = await movedThrough(fx, count);
    for (let day = 0; day < 2; day += 1) {
      await nextDay(fx);
      seen.lines.push(told(world));
    }
    assert.deepEqual(Array.from(new Set(seen.lines)), ["verified told ok grant active"], String(count));
    assert.equal(keptProven(world).length, count, String(count));
    assert.equal(keptProven(world).filter((item) => item.proofs).length, Math.min(count, 4), String(count));
    const shown = await S.call(fx, "read_log", { limit: 50 });
    assert.equal(shown.value.status, "verified", String(count));
    // An installation that kept nothing reads the same history: the release that holds the key
    // is shown by its node, and the releases before it by the node documents of their nodes.
    const fresh = await freshInstallation(fx, 3);
    assert.deepEqual(Array.from(new Set(fresh)), ["verified told ok grant active"], String(count));
    assert.equal(keptProven(world).length, count, String(count));
    assert.equal(world.securityStatuses.filter((item) => item.status === "attention").length, 0, String(count));
    // The runtime after it, and the screen.
    await S.start(fx);
    await nextDay(fx);
    assert.equal(told(world), "verified told ok grant active", String(count));
    assert.equal((await S.call(fx, "read_log", { limit: 50 })).value.status, "verified", String(count));
    assert.deepEqual(refusals(world), [], String(count));
  }
});

test("the same history where the node documents carry no release proofs: the backend is asked for the proofs of the measurements of the closed nodes by their digests, and an installation that kept nothing verifies the log without a mark", async () => {
  for (const count of [5, 10, 30]) {
    const fx = partiesFixture();
    const world = fx.world;
    await S.start(fx);
    const seen = await movedThrough(fx, count, () => ({ carried: false }));
    assert.deepEqual(Array.from(new Set(seen.lines)), ["verified told ok grant active"], String(count));
    // The device that saw every move asked a node for the proofs of each release, and the
    // backend for those of no measurement.
    assert.deepEqual(proofRequests(world), [], String(count));
    const before = world.requests.length;
    const fresh = await freshInstallation(fx, 3);
    assert.equal(fresh[fresh.length - 1], "verified told ok grant active", String(count));
    assert.ok(fresh.every((line) => line.indexOf("attention") < 0 && line.indexOf("grant active") > 0), String(count) + ": " + fresh.join(" | "));
    assert.equal(world.securityStatuses.filter((item) => item.status === "attention").length, 0, String(count));
    assert.equal(keptProven(world).length, count, String(count));
    // Every measurement of a closed node was asked for once, eight in one request at most.
    const asked = proofRequests(world, before);
    assert.ok(asked.every((digests) => digests.length >= 1 && digests.length <= 8), String(count));
    assert.deepEqual(asked.flat().sort(), seen.holders.slice(0, count - 1).map((item) => digestOf(item.measurement)).sort(), String(count));
    assert.deepEqual(refusals(world), [], String(count));
  }
});

test("a release among them without release proofs that hold stays a measurement no list has: the log of an installation that kept nothing is pending for a day and then marked", async () => {
  // The third of five releases that held the key has no proofs, proofs of a runner the owner of
  // the repository hosts, or proofs of another measurement; the others have proofs that hold.
  const other = bridge.randomMeasurement();
  for (const [name, broken, refused] of [
    ["no proofs", { held: false, carried: false }, []],
    ["proofs of another runner", { proofs: { attestation: { identity: { 11: "self-hosted" } } } }, ["p4: identity 11"]],
    ["a statement of another measurement", { proofs: { statement: null } }, ["p1: measurement"]],
  ]) {
    const fx = partiesFixture();
    const world = fx.world;
    await S.start(fx);
    const made = (at) => {
      if (at !== 2) return undefined;
      if (broken.proofs !== undefined && broken.proofs.statement === null) {
        return { proofs: { statement: model.statementOf("v2.7.0", other), attested: Object.assign({ release: "v2.7.0" }, other) } };
      }
      return broken;
    };
    const moved = await movedThrough(fx, 5, made);
    const fresh = await freshInstallation(fx, 2);
    assert.equal(fresh[0], "pending told pending grant active", name);
    assert.equal(fresh[1], "attention told attention:unlisted_release grant active", name);
    assert.equal(fresh[2], "attention told attention:unlisted_release grant active", name);
    assert.deepEqual(keptProven(world).map((item) => item.release).sort(), ["v2.5.0", "v2.6.0", "v2.8.0", "v2.9.0"], name);
    assert.deepEqual(Array.from(new Set(refusals(world))), refused, name);
    // The one measurement the device keeps as one no list has is that of the third release,
    // and it held the key.
    const kept = world.stored("log.unaccepted");
    assert.deepEqual(Object.keys(kept), [digestOf(moved.holders[2].measurement)], name);
    assert.equal(kept[digestOf(moved.holders[2].measurement)].held, true, name);
  }
});

test("the release of a closed node whose node document carries no release proofs: the backend hands the proofs out for the digest of the measurement and the log is verified; without them, from a backend without the route, and with proofs that fail, the log is pending for a day and then marked", async () => {
  // The listed node hands the key to a node of release v2.5.0, which hands it to a node of
  // release v2.6.0 and is closed. The node of v2.6.0 is alive and the backend holds its proofs.
  const scene = async (given, days) => {
    const fx = partiesFixture();
    const world = fx.world;
    await S.start(fx);
    const closed = releaseNode(fx, "v2.5.0", { held: false, carried: false, node: { offered: false } });
    const alive = releaseNode(fx, "v2.6.0");
    moveKey(world, fx.nodes[0], "v2.4.0", closed.node, closed.measurement, "v2.5.0");
    world.advance(S.DAY_MS);
    moveKey(world, closed.node, "v2.5.0", alive.node, alive.measurement, "v2.6.0");
    given(world, closed);
    const before = world.requests.length;
    const lines = await freshInstallation(fx, days === undefined ? 2 : days);
    return { fx: fx, world: world, closed: closed, lines: lines, asked: proofRequests(world, before) };
  };
  // The backend holds the proofs of v2.5.0: one request names the digest of its measurement.
  const held = await scene((world, closed) => world.releaseProofs.set("v2.5.0", closed.proofs));
  assert.deepEqual(held.lines, ["verified told ok grant active", "verified told ok grant active", "verified told ok grant active"]);
  assert.deepEqual(held.asked, [[digestOf(held.closed.measurement)]]);
  assert.deepEqual(keptProven(held.world).map((item) => item.release).sort(), ["v2.5.0", "v2.6.0"]);
  // The backend holds none: it is asked at the first read, and again when the round a day
  // later judges.
  const marked = ["pending told pending grant active", "attention told attention:unlisted_release grant active",
    "attention told attention:unlisted_release grant active"];
  const none = await scene(() => {});
  assert.deepEqual(none.lines, marked);
  assert.deepEqual(none.asked, [[digestOf(none.closed.measurement)], [digestOf(none.closed.measurement)], [digestOf(none.closed.measurement)]]);
  assert.equal(none.world.state.log.store, "verified");
  assert.deepEqual(none.world.stored("log.blocked"), { first_ms: 0, count: 0 });
  // A backend without the route: the request fails, and nothing is counted as held back.
  const absent = await scene((world) => { world.routes.proofs = false; });
  assert.deepEqual(absent.lines, marked);
  assert.equal(absent.world.state.log.store, "verified");
  assert.deepEqual(absent.world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.ok(absent.world.logs.some((line) => line.indexOf("release proofs request failed") === 0));
  // A backend that answers the request with an error has not said that it hands out no proofs:
  // the measurement waits, and past its day each round that cannot ask is a round held back
  // (the log is marked for that after three days, and for nothing else). Every round asks
  // again, once.
  const failing = await scene((world) => world.fault("GET " + PROOFS_PATH, { status: 503, body: { detail: "unavailable" } }));
  assert.deepEqual(failing.lines, ["pending told pending grant active", "pending told pending grant active", "pending told pending grant active"]);
  assert.equal(failing.asked.length, 3);
  assert.equal(failing.world.stored("log.blocked").count, 2);
  assert.equal(failing.world.state.log.store + ":" + failing.world.state.log.store_failure, "blocked:proofs:503");
  // A round of a runtime that does not know what program is served (the answer of the account
  // names none) asks as well and is held back as well: the count does not begin again.
  failing.world.account.servedProgram = undefined;
  failing.world.advance(2 * HOUR_MS);
  await S.event(failing.fx, "foreground");
  assert.equal(failing.world.stored("log.blocked").count, 3);
  failing.world.account.servedProgram = VERSION;
  await nextDay(failing.fx);
  assert.equal(told(failing.world), "pending told pending grant active");
  await nextDay(failing.fx);
  assert.equal(told(failing.world), "attention told attention:verification_blocked grant active");
  assert.equal(failing.world.state.log.unknown_nodes, 0);
  // The backend answers again, without proofs: the count ends and the measurement marks the log.
  failing.world.faults.length = 0;
  failing.world.advance(2 * 60000);
  await S.event(failing.fx, "foreground");
  assert.deepEqual(failing.world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.equal(told(failing.world), "attention told attention:unlisted_release grant active");
  // A device without a network a day later: nothing is asked, so the measurement waits and
  // nothing counts. When the backend answers again, without proofs, the measurement marks the
  // log.
  const offline = await scene(() => {}, 0);
  assert.deepEqual(offline.lines, ["pending told pending grant active"]);
  offline.world.fault(() => true, "transport");
  offline.world.advance(25 * HOUR_MS);
  Promise.resolve(offline.fx.program.onEvent("foreground", {})).then(() => {}, () => {});
  await offline.world.settle(1000);
  assert.equal(told(offline.world), "pending told pending grant active");
  assert.deepEqual(offline.world.stored("log.blocked"), { first_ms: 0, count: 0 });
  offline.world.faults.length = 0;
  offline.world.advance(2 * 60000);
  await S.event(offline.fx, "foreground");
  assert.equal(told(offline.world), "attention told attention:unlisted_release grant active");
  // The one request that fails on the device while the backend answers the others of the
  // runtime is a request the operator domain did not answer: a round held back.
  const silent = await scene((world) => world.fault("GET " + PROOFS_PATH, "transport"));
  assert.equal(silent.lines[2], "pending told pending grant active");
  assert.equal(silent.world.stored("log.blocked").count, 2);
  // Proofs that fail, proofs of another measurement, and an answer for a digest that was not
  // asked for.
  const forged = await scene((world, closed) => world.measureProofs.set(digestOf(closed.measurement),
    model.proofsOf(model.makeParties(), "v2.5.0", closed.measurement)));
  assert.deepEqual(forged.lines, marked);
  assert.deepEqual(Array.from(new Set(refusals(forged.world))), ["p3: signature"]);
  const swapped = await scene((world, closed) => world.measureProofs.set(digestOf(closed.measurement),
    world.releaseProofs.get("v2.6.0")));
  assert.deepEqual(swapped.lines, marked);
  assert.deepEqual(Array.from(new Set(refusals(swapped.world))), ["p1: measurement"]);
  // The proofs reach the backend after the log was marked: the round that asks next verifies
  // the log, and the app is told so.
  none.world.releaseProofs.set("v2.5.0", none.closed.proofs);
  await nextDay(none.fx);
  assert.equal(told(none.world), "verified told ok grant active");
  assert.deepEqual(none.world.stored("log.unaccepted"), {});
});

test("a backend that hands release proofs out for a digest is asked again for a measurement not sooner than five minutes after the last request of the runtime", async () => {
  const fx = partiesFixture();
  const world = fx.world;
  await S.start(fx);
  const closed = releaseNode(fx, "v2.5.0", { held: false, carried: false, node: { offered: false } });
  moveKey(world, fx.nodes[0], "v2.4.0", closed.node, closed.measurement, "v2.5.0");
  await nextDay(fx);
  assert.deepEqual(proofRequests(world), [[digestOf(closed.measurement)]]);
  assert.equal(world.state.log.status, "pending");
  // Within the five minutes: the rounds of the next events, a procedure of the user and the
  // log screen ask for none.
  for (let step = 0; step < 3; step += 1) {
    world.advance(61000);
    await S.event(fx, "foreground");
  }
  await S.call(fx, "sync", {});
  await S.call(fx, "read_log", { limit: 10 });
  assert.deepEqual(proofRequests(world), [[digestOf(closed.measurement)]]);
  // After the five minutes, with the proofs at the backend: the round asks, the measurement is
  // shown, and the entries of its node are judged as those of an accepted node.
  world.releaseProofs.set("v2.5.0", closed.proofs);
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(proofRequests(world).length, 2);
  assert.equal(world.state.log.status, "verified");
  assert.deepEqual(world.stored("log.unaccepted"), {});
  assert.equal(world.securityStatuses.filter((item) => item.status === "attention").length, 0);
});

test("the device keeps the verdicts of 256 measurements, those of the latest releases, and the proofs of the latest four", async () => {
  const fx = partiesFixture();
  const world = fx.world;
  // 256 verdicts of this program in the program store, of the releases v2.5.0 to v2.260.0.
  const measures = {};
  for (let at = 0; at < 256; at += 1) {
    measures[digestOf(bridge.randomMeasurement())] = { release: "v2." + (5 + at) + ".0", program_min: 0, proven_ms: 1000 + at };
  }
  world.store.set("log.proven", JSON.stringify({ v: VERSION, measures: measures }));
  // A node of release v2.100.1, later than 96 of them, and one of v3.0.0, later than all.
  const middle = releaseNode(fx, "v2.100.1");
  const last = releaseNode(fx, "v3.0.0");
  await S.start(fx);
  assert.equal(middle.node.grants.has(world.userId), true);
  assert.equal(last.node.grants.has(world.userId), true);
  const kept = world.stored("log.proven");
  const releases = Object.values(kept.measures).map((item) => item.release);
  assert.equal(releases.length, 256);
  // The two earliest releases left; the two that were shown now are kept, with their proofs.
  assert.equal(releases.indexOf("v2.5.0"), -1);
  assert.equal(releases.indexOf("v2.6.0"), -1);
  assert.ok(releases.indexOf("v2.7.0") >= 0);
  assert.deepEqual(keptProven(world).filter((item) => item.proofs).map((item) => item.release).sort(), ["v2.100.1", "v3.0.0"]);
  // A verdict that left the program store stays with the runtime that made it: a release
  // earlier than every kept one is shown, its node receives the grant, and the same runtime
  // renews it.
  const first = releaseNode(fx, "v2.4.1");
  world.advance(2 * HOUR_MS);
  await S.event(fx, "foreground");
  assert.equal(first.node.grants.has(world.userId), true);
  assert.equal(Object.values(world.stored("log.proven").measures).some((item) => item.release === "v2.4.1"), false);
  const commands = first.node.commands.length;
  await nextDay(fx);
  assert.equal(first.node.commands.length, commands + 1);
  assert.equal(world.state.grant.state, "active");
  // The next runtime asks the node for the proofs again and hands it the grant.
  const before = world.requests.length;
  world.advance(25 * HOUR_MS);
  await S.start(fx);
  assert.deepEqual(attestationRequests(world, before).filter((request) => request.proofs === "1").map((request) => request.nodes), [[first.node.id]]);
  assert.equal(first.node.commands.length, commands + 2);
});

// ---- The program_min of a release statement ----

/** Writes one object under the prefix of format 3 in the name of node, for the account of the
 *  world, as a node of format 3 does but for the parts given: keyEvent (the event name of the
 *  key of a control entry), info (the HPKE info of the sealing), purpose (the purpose of the
 *  signature). Returns the key. */
function deviantEntry(world, node, events, given) {
  const keys = world.account.keys;
  const user = world.userId;
  const last = node.last.get(user) || { seq: 0, bodyHash: Buffer.alloc(32) };
  const seq = last.seq + 1;
  const sealed = bridge.hpkeSeal(
    "chacha20poly1305", keys.logPk, bridge.utf8(given.info || "pickle.secure.v3.log-entry"),
    bridge.utf8([node.id, user, keys.keyId, String(seq)].join("\n")), bridge.utf8(JSON.stringify(events)));
  const body = bridge.utf8(JSON.stringify({
    v: 3, node: node.id, user_id: user, key_id: keys.keyId, seq: seq, prev: bridge.b64u(last.bodyHash),
    time_ms: world.now, kind: "c", count: events.length, enc: bridge.b64u(sealed.enc), ct: bridge.b64u(sealed.ciphertext),
  }));
  const sig = bridge.ed25519Sign(node.signSeed, bridge.concat(bridge.utf8(given.purpose || "pickle.secure.v3.log-entry\n"), body));
  const bodyHash = bridge.sha("sha256", body);
  const key = "a3/" + user + "/c/" + String(bridge.RTIME_MAX - world.now).padStart(13, "0") + "." + node.id + "." + seq + "." +
    (given.keyEvent || events[0].t) + "." + keys.keyId + "." + bridge.b64u(bodyHash);
  node.last.set(user, { seq: seq, bodyHash: bodyHash });
  world.putObject(bridge.shardBucket(world.serverTarget, user), key, JSON.stringify({ body: bridge.b64u(body), sig: bridge.b64u(sig) }));
  return key;
}

test("a release whose statement states a later program is none this program accepts: its nodes receive no grant, what they write in another form marks no node, and the release holding the key marks the log after its day unless a later program is served", async () => {
  /** A node of release v2.5.0 with release proofs that hold: stated is the program_min of its
   *  release statement and bound that of its binding (undefined: none). The key of the account
   *  moves to that node, which writes a control entry whose key names another event than its
   *  plaintext and one sealed with another HPKE info. */
  const scene = async (stated, bound, served) => {
    const fx = partiesFixture({ served: served });
    const world = fx.world;
    const later = releaseNode(fx, "v2.5.0", { proofs: stated === undefined ? undefined : { programMin: stated }, node: { programMin: bound } });
    await S.start(fx);
    const granted = later.node.grants.has(world.userId);
    world.advance(2 * 60000);
    const first = fx.nodes[0];
    first.record("c", [{
      t: "grant_transferred_out", time_ms: world.now, to: later.node.id, release: "v2.5.0",
      pcr0: later.measurement.pcr0, pcr1: later.measurement.pcr1, pcr2: later.measurement.pcr2,
    }]);
    if (!granted) later.node.grants.set(world.userId, first.grants.get(world.userId));
    later.node.record("c", [{ t: "grant_transferred_in", time_ms: world.now, from: first.id, release: "v2.4.0", not_after_ms: world.now + 30 * S.DAY_MS, custody: "enclave" }]);
    deviantEntry(world, later.node, [{ t: "connection_created", time_ms: world.now, record_id: "r", provider: "github", scope: "" }], { keyEvent: "policy_changed" });
    deviantEntry(world, later.node, [{ t: "policy_changed", time_ms: world.now }], { info: "pickle.secure.v4.log-entry" });
    return { fx: fx, world: world, later: later, granted: granted };
  };
  const reasons = (world) => world.securityStatuses.filter((item) => item.status === "attention").map((item) => item.reasons.join(","));

  // The statement states the next program, and the backend serves this one.
  const held = await scene(VERSION + 1, undefined, VERSION);
  assert.equal(held.granted, false);
  assert.deepEqual(keptProven(held.world), [{ release: "v2.5.0", proofs: false, program_min: VERSION + 1 }]);
  assert.ok(held.world.logs.some((line) => line === "release v2.5.0 takes program " + (VERSION + 1) + " or later"));
  assert.equal(held.world.state.log.newer_release_nodes, 1);
  // The round that reads what the node wrote: nothing marks the node, and the release that
  // holds the key is within its day.
  await S.event(held.fx, "foreground");
  assert.equal(told(held.world), "pending told pending grant active");
  assert.equal(held.world.state.log.unverified_nodes, 0);
  assert.equal(held.world.stored("log.unaccepted")[digestOf(held.later.measurement)].held, true);
  held.world.advance(12 * HOUR_MS);
  await S.event(held.fx, "foreground");
  assert.equal(told(held.world), "pending told pending grant active");
  // A day after the device first saw the release: the log is marked for the release, and for
  // nothing else.
  held.world.advance(13 * HOUR_MS);
  await S.event(held.fx, "foreground");
  assert.deepEqual(reasons(held.world), ["unlisted_release"]);
  assert.equal(held.world.state.log.status, "attention");
  assert.equal(held.world.state.log.unverified_nodes, 0);
  // The node was asked for its proofs once, the backend for those of no measurement, and the
  // node received no grant of this program.
  assert.equal(attestationRequests(held.world).filter((request) => request.proofs === "1").length, 1);
  assert.deepEqual(proofRequests(held.world), []);
  assert.equal(held.later.node.commands.length, 0);
  assert.deepEqual(refusals(held.world), []);

  // The backend serves the next program: the runtime is stale and states nothing.
  const stale = await scene(VERSION + 1, undefined, VERSION + 1);
  for (let day = 0; day < 3; day += 1) await nextDay(stale.fx);
  assert.equal(stale.world.runtime.program_stale, true);
  assert.deepEqual(reasons(stale.world), []);
  assert.equal(stale.later.node.commands.length, 0);

  // The backend serves this program, and the next one within the day: no mark.
  const served = await scene(VERSION + 1, undefined, VERSION);
  await S.event(served.fx, "foreground");
  assert.equal(told(served.world), "pending told pending grant active");
  served.world.advance(12 * HOUR_MS);
  served.world.account.servedProgram = VERSION + 1;
  for (let day = 0; day < 3; day += 1) await nextDay(served.fx);
  assert.deepEqual(reasons(served.world), []);

  // A statement without program_min, and one that states this program: the node is that of an
  // accepted release. It receives its grant, and what it wrote in another form marks it.
  for (const stated of [undefined, VERSION, 0]) {
    const accepted = await scene(stated, undefined, VERSION);
    assert.equal(accepted.granted, true, String(stated));
    await nextDay(accepted.fx);
    assert.deepEqual(reasons(accepted.world), ["conflicting_signatures"], String(stated));
  }

  // The binding alone states the next program: the node receives no grant, and it is judged as
  // the node of an accepted release that it is.
  const bound = await scene(undefined, VERSION + 1, VERSION);
  assert.equal(bound.granted, false);
  assert.deepEqual(keptProven(bound.world), [{ release: "v2.5.0", proofs: true }]);
  await nextDay(bound.fx);
  assert.deepEqual(reasons(bound.world), ["conflicting_signatures"]);
});

// ---- Release proofs that arrive after the entries ----

test("release proofs that reach the device after it read the entries of a node: the entries that node wrote are judged again as those of an accepted node, and a transfer of the key they name to a measurement no list has marks the log", async () => {
  const fx = partiesFixture();
  const world = fx.world;
  await S.start(fx);
  // A node of release v2.5.0 takes the key from the listed node and hands it on to a node of a
  // measurement no list has and no proofs show, which writes nothing. The backend hands the
  // proofs of v2.5.0 out nowhere yet.
  const middle = releaseNode(fx, "v2.5.0", { held: false, carried: false, node: { offered: false } });
  const hidden = bridge.randomMeasurement();
  const receiver = world.addNode({ release: "v2.6.0", measurement: hidden, offered: false });
  const first = fx.nodes[0];
  first.record("c", [{
    t: "grant_transferred_out", time_ms: world.now, to: middle.node.id, release: "v2.5.0",
    pcr0: middle.measurement.pcr0, pcr1: middle.measurement.pcr1, pcr2: middle.measurement.pcr2,
  }]);
  middle.node.record("c", [{ t: "grant_transferred_in", time_ms: world.now, from: first.id, release: "v2.4.0", not_after_ms: world.now + 30 * S.DAY_MS, custody: "enclave" }]);
  world.advance(60000);
  middle.node.record("c", [{
    t: "grant_transferred_out", time_ms: world.now, to: receiver.id, release: "v2.6.0",
    pcr0: hidden.pcr0, pcr1: hidden.pcr1, pcr2: hidden.pcr2,
  }]);
  // The device reads the entries: the release v2.5.0 held the key and is within its day.
  await nextDay(fx);
  assert.equal(told(world), "pending told pending grant active");
  assert.deepEqual(Object.keys(world.stored("log.unaccepted")), [digestOf(middle.measurement)]);
  // The proofs of v2.5.0 reach the backend. The round that asks next shows the measurement, and
  // judges what its node wrote before: the transfer to the other measurement.
  world.releaseProofs.set("v2.5.0", middle.proofs);
  world.advance(2 * HOUR_MS);
  await S.event(fx, "foreground");
  assert.deepEqual(keptProven(world).map((item) => item.release), ["v2.5.0"]);
  assert.deepEqual(Object.keys(world.stored("log.unaccepted")), [digestOf(hidden)]);
  assert.equal(world.stored("log.unaccepted")[digestOf(hidden)].held, true);
  assert.equal(told(world), "pending told pending grant active");
  // A day later the measurement that took the key marks the log.
  await nextDay(fx);
  assert.equal(told(world), "attention told attention:unlisted_release grant active");
});

test("a device that could not get the release proofs of a release when it first saw it, and that leaves the app a day later before the proofs are answered, is told nothing: a measurement marks the log only once the backend answered a request for its proofs", async () => {
  const fx = partiesFixture();
  const world = fx.world;
  await S.start(fx);
  const later = releaseNode(fx, "v2.5.0", { carried: false });
  const first = fx.nodes[0];
  first.record("c", [{
    t: "grant_transferred_out", time_ms: world.now, to: later.node.id, release: "v2.5.0",
    pcr0: later.measurement.pcr0, pcr1: later.measurement.pcr1, pcr2: later.measurement.pcr2,
  }]);
  later.node.grants.set(world.userId, first.grants.get(world.userId));
  later.node.record("c", [{ t: "grant_transferred_in", time_ms: world.now, from: first.id, release: "v2.4.0", not_after_ms: world.now + 30 * S.DAY_MS, custody: "enclave" }]);
  // The synchronization that first sees the release: the request to the node for its proofs and
  // the request for the proofs of the measurement both fail.
  world.fault((line, request) => request.path === "/api/secure/nodes" && request.query.proofs === "1", { status: 503, body: { detail: "unavailable" } }, 1);
  world.fault("GET " + PROOFS_PATH, { status: 503, body: { detail: "unavailable" } }, 2);
  await nextDay(fx);
  assert.equal(told(world), "pending told pending grant active");
  assert.equal(later.node.commands.length, 0);
  // A day later the app is opened and left after three seconds, while the requests that call a
  // node and the request for the proofs are still on their way. The measurement is past its
  // day and the runtime knows that no later program is served, and nothing is stated: the
  // backend has not answered whether it hands out proofs.
  world.faults.length = 0;
  world.fault("GET /api/secure/nodes", { delay_ms: 9000 });
  world.fault("GET " + PROOFS_PATH, { delay_ms: 9000 });
  world.advance(25 * HOUR_MS);
  Promise.resolve(fx.program.onEvent("foreground", {})).then(() => {}, () => {});
  await world.settle(3000);
  fx.program.onEvent("background", {});
  await world.drain();
  assert.equal(told(world), "pending told pending grant active");
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
  // The next stay: the round is answered the proofs of the measurement and the log is
  // verified. The synchronization after it hands the node its grant.
  world.faults.length = 0;
  world.advance(10 * 60000);
  await S.event(fx, "foreground");
  assert.equal(told(world), "verified told ok grant active");
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(later.node.commands.length, 1);
  assert.equal(world.securityStatuses.filter((item) => item.status === "attention").length, 0);
});

test("the grant step that asks a node the device knows for the release proofs of its measurement again writes nothing of that measurement but the time it asked: what a round that ran meanwhile noted of it stands", async () => {
  const fx = partiesFixture();
  const world = fx.world;
  await S.start(fx);
  // A node of a measurement no list has and no proofs show. The device met it two hours ago and
  // keeps it as a node of a later release.
  const hidden = bridge.randomMeasurement();
  const later = world.addNode({ release: "v2.6.0", measurement: hidden });
  world.advance(2 * HOUR_MS);
  await S.event(fx, "foreground");
  assert.equal(world.stored("log.unaccepted")[digestOf(hidden)].held, false);
  // 70 minutes later the listed node hands the key of the account to it. The user reads the log
  // screen (a round) while a synchronization runs (the grant step, which asks the node for the
  // proofs of its measurement again): the first request of the round is answered after two
  // seconds and the attestation request with the query proofs after eight, so the round ends
  // while the grant step waits.
  world.advance(70 * 60000);
  const first = fx.nodes[0];
  first.record("c", [{
    t: "grant_transferred_out", time_ms: world.now, to: later.id, release: "v2.6.0",
    pcr0: hidden.pcr0, pcr1: hidden.pcr1, pcr2: hidden.pcr2,
  }]);
  later.grants.set(world.userId, first.grants.get(world.userId));
  world.fault("POST /api/secure/log/read", { delay_ms: 2000 }, 1);
  world.fault((line, request) => request.path === "/api/secure/nodes" && request.query.proofs === "1", { delay_ms: 8000 }, 1);
  const before = world.requests.length;
  const asked = world.now;
  const outcome = await world.run(Promise.allSettled([fx.program.procedures.read_log({ limit: 10 }), fx.program.onEvent("foreground", {})]));
  await world.settle(0);
  assert.deepEqual(outcome.map((item) => item.status), ["fulfilled", "fulfilled"]);
  assert.deepEqual(attestationRequests(world, before), [{ nodes: [later.id], proofs: "1" }]);
  // The round noted that the measurement took the key, and the grant step that ended after it
  // left that and wrote the time of its request.
  const kept = world.stored("log.unaccepted")[digestOf(hidden)];
  assert.equal(kept.held, true);
  assert.equal(kept.asked_ms, asked);
  // A day after the device first saw the measurement, it marks the log.
  await nextDay(fx);
  assert.equal(told(world), "attention told attention:unlisted_release grant active");
});
