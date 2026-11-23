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

/** The measurements the program store keeps as shown by release proofs: [{release, proofs}]
 *  (proofs: whether the proofs are kept with the verdict). */
function keptProven(world) {
  const kept = world.stored("log.proven");
  if (kept === undefined) return [];
  return Object.values(kept.measures).map((item) => ({ release: item.release, proofs: item.proofs !== null }));
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
  const cases = proofCases("v2.5.0", listed[listed.length - 1].release);
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
    if (item.reason === null) {
      assert.deepEqual(refusals(world), [], item.name);
      assert.equal(later.grants.has(world.userId), true, item.name);
      assert.equal(world.state.log.status, "verified", item.name);
      assert.equal(world.state.log.newer_release_nodes, 0, item.name);
      assert.deepEqual(keptProven(world), [{ release: item.release, proofs: true }], item.name);
      continue;
    }
    // Proofs that are null are no proofs: nothing is verified and nothing refused.
    assert.deepEqual(refusals(world), item.proofs === null ? [] : [item.reason], item.name);
    assert.equal(later.grants.has(world.userId), false, item.name);
    assert.equal(world.state.log.status, "pending", item.name);
    assert.equal(world.state.log.newer_release_nodes, 1, item.name);
    assert.deepEqual(keptProven(world), [], item.name);
    assert.equal(world.runtime.rejected_nodes, 0, item.name);
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
  // The renewals of the next days, and a procedure of the user, ask for none either.
  for (let day = 0; day < 3; day += 1) await nextDay(fx);
  await S.call(fx, "sync", {});
  assert.ok(world.requests.every((request) => request.query === undefined || request.query === null || request.query.proofs === undefined));
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
  world.fault((line, request) => request.path === "/api/secure/nodes" && request.query.proofs === "1", { status: 503, body: { detail: "unavailable" } }, 1);
  await S.start(fx);
  assert.equal(fx.nodes[0].grants.has(world.userId), true);
  assert.equal(fx.later.grants.has(world.userId), false);
  assert.equal(world.state.grant.state, "active");
  assert.ok(world.logs.some((line) => line.indexOf("release proofs request failed") === 0));
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
  // A binding whose program_min is no non-negative integer is no binding.
  for (const value of ["44", -1, 1.5, null]) {
    const odd = S.fixture(source, { nodes: 1 });
    const node = odd.world.addNode({ release: "v2.4.0", measurement: odd.measurement, programMin: value });
    await S.start(odd);
    assert.equal(node.grants.has(odd.world.userId), false, String(value));
    assert.equal(odd.world.runtime.rejected_nodes, 1, String(value));
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
