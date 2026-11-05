// The scenarios of the tests of the secure program: each builds a world (bridge.js), runs the
// program on it the way the executor does (the event session_ready starts the synchronization of
// the runtime) and returns a plain result: the last verification report the program sent
// (POST /api/secure/log/verified), the published state log and grant, the grants and chains of the
// nodes by fixture name, and the node ledger. The results are deterministic for one program (the
// time of the world does not run, node ids are not part of the result), so compare.js can run the
// same scenarios on two versions of the program and show what changed.
"use strict";

const bridge = require("./bridge.js");

const HOUR_MS = 3600000;
const DAY_MS = bridge.DAY_MS;

/** A world with an account whose key state is present, and node0: a node of the latest release
 *  the program lists. */
function baseWorld(source, options) {
  const world = new bridge.World(options);
  const keys = world.createAccount();
  const listed = bridge.listedMeasurements(source);
  const latest = listed[listed.length - 1];
  const node0 = world.addNode({ release: latest.release, measurement: latest });
  return { world: world, keys: keys, latest: latest, node0: node0, named: { node0: node0 } };
}

/** The chain another party had node write for the account before the run: the transfer the node
 *  took in two hours ago and one provider request an hour ago. */
function writeForeignChain(world, keys, node, from) {
  const seal = { logPk: keys.logPk, keyId: keys.keyId };
  node.appendEntry(world.userId, "c", [{
    t: "grant_transferred_in", time_ms: world.now - 2 * HOUR_MS, from: from,
    not_after_ms: world.now + 29 * DAY_MS, custody: "enclave",
  }], Object.assign({ timeMs: world.now - 2 * HOUR_MS }, seal));
  node.appendEntry(world.userId, "u", [providerRequest(world.now - HOUR_MS)],
    Object.assign({ timeMs: world.now - HOUR_MS }, seal));
}

function providerRequest(timeMs) {
  return {
    t: "provider_request", time_ms: timeMs, record_id: "record-1", provider: "slack", method: "GET",
    host: "slack.com", path: "/api/conversations.list", query: "", body_bytes: 0, body_sha256: "",
    context: "chat", window_s: 300,
  };
}

/** The result of the runs so far on world. named maps fixture names to nodes. */
function outcome(world, named) {
  const ledger = world.ledger();
  const nodes = {};
  for (const name of Object.keys(named)) {
    const node = named[name];
    const kept = ledger === null ? undefined : ledger.nodes[node.id];
    nodes[name] = {
      grants: node.grants.size,
      chain: (node.chains.get(world.userId) || []).length,
      ledger: kept === undefined ? null : {
        origin: kept.origin, unknown: kept.unknown_ms !== 0, checkpoint: kept.checkpoint.seq,
        gone: kept.gone_ms !== 0,
      },
    };
  }
  return {
    report: world.reports.length === 0 ? null : world.reports[world.reports.length - 1],
    reports: world.reports.length,
    log: world.state.log === undefined ? null : world.state.log,
    grant: world.state.grant === undefined ? null : world.state.grant,
    rejected_nodes: world.runtime.rejected_nodes === undefined ? null : world.runtime.rejected_nodes,
    nodes: nodes,
  };
}

async function start(source, world) {
  const program = bridge.loadProgram(source, world);
  await program.onEvent("session_ready", {});
  return program;
}

/** One node of the latest listed release, nothing else: the account delegates to it and verifies
 *  the chain its grant started. */
async function plain(source) {
  const base = baseWorld(source);
  await start(source, base.world);
  return outcome(base.world, base.named);
}

/** node1 is of a release the program does not list (a valid document with a measurement no list
 *  has) and holds a chain for the account: the run is pending, not attention, node1 gets no grant
 *  and does not enter the ledger. The log screen (read_log) reports the same. */
async function laterRelease(source) {
  const base = baseWorld(source);
  const node1 = base.world.addNode({ release: "v9.9.9", measurement: bridge.randomMeasurement() });
  base.named.node1 = node1;
  writeForeignChain(base.world, base.keys, node1, base.node0.id);
  const program = await start(source, base.world);
  const result = outcome(base.world, base.named);
  const screen = await program.procedures.read_log({ limit: 10 });
  result.screen = {
    status: screen.status, unknown_nodes: screen.unknown_nodes,
    newer_release_nodes: screen.newer_release_nodes === undefined ? null : screen.newer_release_nodes,
    days: screen.days.length,
  };
  return result;
}

/** node1 names the latest listed measurement but the signature of its document is corrupted: the
 *  attestation fails, and the chain node1 holds is a delegation the app did not make (attention). */
async function listedBrokenSignature(source) {
  const base = baseWorld(source);
  const node1 = base.world.addNode({ release: base.latest.release, measurement: base.latest, brokenSignature: true });
  base.named.node1 = node1;
  writeForeignChain(base.world, base.keys, node1, base.node0.id);
  await start(source, base.world);
  return outcome(base.world, base.named);
}

/** node1 has a measurement no list has and a corrupted signature: a document that does not verify
 *  is not a later release (attention, as before). */
async function unlistedBrokenSignature(source) {
  const base = baseWorld(source);
  const node1 = base.world.addNode({
    release: "v9.9.9", measurement: bridge.randomMeasurement(), brokenSignature: true,
  });
  base.named.node1 = node1;
  writeForeignChain(base.world, base.keys, node1, base.node0.id);
  await start(source, base.world);
  return outcome(base.world, base.named);
}

/** node1 has a measurement no list has and a binding that names another log store: not a node of
 *  this deployment (attention, as for a listed node whose binding names another store). */
async function unlistedOtherStore(source) {
  const base = baseWorld(source);
  const node1 = base.world.addNode({
    release: "v9.9.9", measurement: bridge.randomMeasurement(),
    log: { bucket: "another-bucket-1", region: "us-west-2" },
  });
  base.named.node1 = node1;
  writeForeignChain(base.world, base.keys, node1, base.node0.id);
  await start(source, base.world);
  return outcome(base.world, base.named);
}

/** node1 is an enclave in debug mode (PCR0 all zero): refused, never a later release (attention). */
async function unlistedDebugEnclave(source) {
  const base = baseWorld(source);
  const measurement = bridge.randomMeasurement();
  measurement.pcr0 = "0".repeat(96);
  const node1 = base.world.addNode({ release: "v9.9.9", measurement: measurement });
  base.named.node1 = node1;
  writeForeignChain(base.world, base.keys, node1, base.node0.id);
  await start(source, base.world);
  return outcome(base.world, base.named);
}

/** node0 (listed) handed the delegation to node1 (a release the program does not list): the
 *  transfer is on the chain of node0, so node1 enters the ledger by the trace. Its chain is left
 *  pending (the program does not read the chain of a later release) and the run is pending. */
async function laterReleaseTraced(source) {
  const base = baseWorld(source);
  const node1 = base.world.addNode({ release: "v9.9.9", measurement: bridge.randomMeasurement() });
  base.named.node1 = node1;
  const seal = { logPk: base.keys.logPk, keyId: base.keys.keyId };
  base.node0.appendEntry(base.world.userId, "c", [{
    t: "grant_accepted", time_ms: base.world.now - 3 * HOUR_MS,
    not_after_ms: base.world.now + 29 * DAY_MS, custody: "enclave",
  }], Object.assign({ timeMs: base.world.now - 3 * HOUR_MS }, seal));
  base.node0.appendEntry(base.world.userId, "c", [{
    t: "grant_transferred_out", time_ms: base.world.now - 2 * HOUR_MS, to: node1.id,
  }], Object.assign({ timeMs: base.world.now - 2 * HOUR_MS }, seal));
  writeForeignChain(base.world, base.keys, node1, base.node0.id);
  await start(source, base.world);
  return outcome(base.world, base.named);
}

/** The chain of node0 has a gap: the second of three entries written before the run is not in the
 *  store, and the entry after the gap is older than the grace of a young gap (attention, missing 1). */
async function gap(source) {
  const base = baseWorld(source);
  const seal = { logPk: base.keys.logPk, keyId: base.keys.keyId };
  const now = base.world.now;
  base.node0.appendEntry(base.world.userId, "c", [{
    t: "grant_accepted", time_ms: now - 3 * HOUR_MS, not_after_ms: now + 29 * DAY_MS, custody: "enclave",
  }], Object.assign({ timeMs: now - 3 * HOUR_MS }, seal));
  base.node0.appendEntry(base.world.userId, "u", [providerRequest(now - 2 * HOUR_MS)],
    Object.assign({ timeMs: now - 2 * HOUR_MS, stored: false }, seal));
  base.node0.appendEntry(base.world.userId, "u", [providerRequest(now - 90 * 60000)],
    Object.assign({ timeMs: now - 90 * 60000 }, seal));
  await start(source, base.world);
  return outcome(base.world, base.named);
}

/** The ledger an earlier program left: node1 found in the store, with the mark of a delegation the
 *  app did not make (unknown_ms) and the verified point at the end of its chain. */
function seedUnknownMark(world, node1, entries) {
  const last = entries[entries.length - 1];
  const ledger = {
    v: 1, revoked_ms: 0, resumed_ms: 0, ttl_days: 30, ttl_set_ms: 0, store_failing_ms: 0,
    nodes: {},
  };
  ledger.nodes[node1.id] = {
    sign_pk: node1.id, seal_pk: "", platform: "", release: "", first_ms: world.now - HOUR_MS,
    granted_ms: 0, not_after_ms: 0,
    checkpoint: { seq: last.seq, hash: bridge.b64u(last.entryHash), time_ms: last.time_ms },
    final: null, gone_ms: world.now - HOUR_MS, origin: "store", unknown_ms: world.now - HOUR_MS,
  };
  const json = JSON.stringify(ledger);
  world.store.set("ledger", json);
  world.keychain.set("com.pickle.client.secure.ledger\n" + world.userId,
    { value: bridge.b64u(bridge.utf8(json)), synchronizable: true });
}

/** The replacement of the program. Phase one: node1 (a release the program does not list) carries
 *  the mark an earlier program left in the ledger; the run of this program is pending, the mark is
 *  not counted. Phase two: a runtime of the same program verifies again at its first
 *  synchronization, and a synchronization of a running runtime within the period does not. Phase
 *  three: the program that lists the release (the same source with the release added, version + 1)
 *  grants to node1 and verifies its chain: verified, nothing pending, nothing unknown. */
async function replacement(source) {
  const base = baseWorld(source);
  const node1 = base.world.addNode({ release: "v9.9.9", measurement: bridge.randomMeasurement() });
  base.named.node1 = node1;
  writeForeignChain(base.world, base.keys, node1, base.node0.id);
  seedUnknownMark(base.world, node1, node1.chains.get(base.world.userId));
  const first = await start(source, base.world);
  const phases = { marked: outcome(base.world, base.named) };
  const reportsAfterFirst = base.world.reports.length;
  base.world.advance(60000);
  await first.onEvent("foreground", {});
  phases.foreground_reports = base.world.reports.length - reportsAfterFirst;
  await start(source, base.world);
  phases.new_runtime_reports = base.world.reports.length - reportsAfterFirst - phases.foreground_reports;
  base.world.advance(60000);
  const later = bridge.withListedRelease(source, "v9.9.9", node1.measurement, bridge.declaredVersion(source) + 1);
  await start(later, base.world);
  phases.listed = outcome(base.world, base.named);
  return phases;
}

module.exports = {
  scenarios: {
    plain: plain,
    later_release: laterRelease,
    listed_broken_signature: listedBrokenSignature,
    unlisted_broken_signature: unlistedBrokenSignature,
    unlisted_other_store: unlistedOtherStore,
    unlisted_debug_enclave: unlistedDebugEnclave,
    later_release_traced: laterReleaseTraced,
    gap: gap,
    replacement: replacement,
  },
};
