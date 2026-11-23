// The fixtures and the scenarios of the tests of the secure program. A fixture builds a world
// (bridge.js) and runs the program on it the way the executor does (the event session_ready starts
// the synchronization of the runtime). A scenario returns a plain result: the last report of a
// round the program sent (POST /api/secure/log/verified), the published state log and grant, and
// what the nodes hold. The results are deterministic for one program (node ids are not part of a
// result), so compare.js can run the scenarios on two versions of the program and show what
// changed.
"use strict";

const bridge = require("./bridge.js");

const HOUR_MS = 3600000;
const DAY_MS = bridge.DAY_MS;

/** A fixture: a world with an account whose key state is present, and the program that runs on
 *  it. options:
 *    target      the server target of the world (prod)
 *    legacy      the number of nodes of the latest release the checked-out program lists among
 *                the releases that write format 2 (the releases before v2.4.0); 0 when absent
 *    nodes       the number of nodes of release v2.4.0 (format 3), listed by the program of the
 *                fixture under a measurement of the fixture; 1 when absent
 *    account     false for a device without a master key and an account without a registered key
 *    device      the build of the device (bridge.js World.device)
 *    served      what the backend says of the program it serves (served_program_version of the
 *                account query): the version of the program of the fixture when absent (a backend
 *                that serves this program), and null for a backend that names no version
 *  Returns {world, keys, source, release, measurement, latest, nodes, legacy, version}: source is
 *  the program with release v2.4.0 listed, and version the VERSION of the program. */
function fixture(source, options) {
  const given = options || {};
  const world = new bridge.World({ serverTarget: given.target || "prod", device: given.device });
  const keys = given.account === false ? null : world.createAccount();
  const version = Number(/const VERSION = (\d+);/.exec(source)[1]);
  world.account.servedProgram = given.served === undefined ? version : given.served === null ? undefined : given.served;
  const listed = bridge.listedMeasurements(source).filter((item) => !bridge.writesFormat3(item.release));
  const latest = listed[listed.length - 1];
  const measurement = bridge.randomMeasurement();
  const out = {
    world: world, keys: keys, source: bridge.withListedRelease(source, "v2.4.0", measurement),
    release: "v2.4.0", measurement: measurement, latest: latest, nodes: [], legacy: [], program: null,
    version: version,
  };
  for (let i = 0; i < (given.legacy === undefined ? 0 : given.legacy); i += 1) {
    out.legacy.push(world.addNode({ release: latest.release, measurement: latest }));
  }
  for (let i = 0; i < (given.nodes === undefined ? 1 : given.nodes); i += 1) {
    out.nodes.push(world.addNode({ release: "v2.4.0", measurement: measurement }));
  }
  return out;
}

/** Loads the program of a fixture as a new runtime (source: another program for the same world).
 *  The runtime before it goes down. */
function load(fx, source) {
  fx.program = bridge.loadProgram(source === undefined ? fx.source : source, fx.world);
  return fx.program;
}

/** Starts a runtime on the fixture: the program is loaded and the event session_ready is handled
 *  to its end. */
async function start(fx, source) {
  load(fx, source);
  await fx.world.run(fx.program.onEvent("session_ready", {}));
  await fx.world.settle(0);
  return fx.program;
}

/** Handles one event to its end. */
async function event(fx, name, payload) {
  const outcome = await fx.world.run(Promise.resolve(fx.program.onEvent(name, payload === undefined ? {} : payload)));
  await fx.world.settle(0);
  return outcome;
}

/** Calls one procedure to its end and returns {ok, value} or {ok: false, code}. */
async function call(fx, name, args) {
  try {
    const value = await fx.world.run(fx.program.procedures[name](args === undefined ? {} : args));
    await fx.world.settle(0);
    // The result as plain values of this realm (the program runs in a context of its own).
    return { ok: true, value: value === undefined ? undefined : JSON.parse(JSON.stringify(value)) };
  } catch (error) {
    await fx.world.settle(0);
    return { ok: false, code: error && error.code ? error.code : String(error) };
  }
}

/** One provider request event at timeMs. */
function providerRequest(timeMs, path, method) {
  return {
    t: "provider_request", time_ms: timeMs, record_id: "ARUgUDnTSlTyTpffFFUt0w", provider: "google_workspace",
    method: method || "GET", host: "gmail.googleapis.com", path: path || "/gmail/v1/users/me/messages", query: "",
    body_bytes: 0, body_sha256: "", context: "cli:task",
  };
}

/** The last report of a round the program sent, without the times that differ from run to run. */
function lastReport(world) {
  if (world.reports.length === 0) return null;
  const report = Object.assign({}, world.reports[world.reports.length - 1]);
  delete report.elapsed_ms;
  delete report.screen_ms;
  delete report.unknown_node_ids;
  return report;
}

/** The published state of the log without its times. */
function logState(world) {
  const log = Object.assign({}, world.state.log);
  delete log.verified_ms;
  delete log.store_failing_ms;
  return log;
}

/** The lines of the requests the program sent since the index from. */
function requestLines(world, from) {
  return world.requests.slice(from === undefined ? 0 : from).map((request) => {
    const method = request.method || "GET";
    return typeof request.path === "string" ? method + " " + request.path : "S3 " + new URL(request.url).host;
  });
}

/** The plain result of a scenario. */
function result(fx) {
  return {
    report: lastReport(fx.world), log: logState(fx.world), grant: fx.world.state.grant.state,
    granted: fx.nodes.concat(fx.legacy).map((node) => node.grants.has(fx.world.userId)),
  };
}

// ---- The scenarios compare.js runs on two programs ----

/** A node of format 3 receives the grant and its entries verify. */
async function plain(source) {
  const fx = fixture(source);
  await start(fx);
  return result(fx);
}

/** The shape of an environment whose nodes all write format 2 and whose backend has no store of
 *  format 3: the node receives the grant and the round reads its chain. */
async function formatTwoOnly(source) {
  const fx = fixture(source, { nodes: 0, legacy: 1 });
  fx.world.routes.log = "disabled";
  await start(fx);
  return result(fx);
}

/** The key of the account moved to a node of a measurement no list has: pending within the grace,
 *  attention after it. */
async function movedToUnlistedRelease(source) {
  const fx = fixture(source);
  await start(fx);
  const other = bridge.randomMeasurement();
  fx.nodes[0].record("c", [{
    t: "grant_transferred_out", time_ms: fx.world.now, to: fx.world.addNode({
      release: "v9.0.0", measurement: other, offered: false,
    }).id, release: "v9.0.0", pcr0: other.pcr0, pcr1: other.pcr1, pcr2: other.pcr2,
  }]);
  fx.world.advance(2 * HOUR_MS);
  await event(fx, "foreground");
  const within = result(fx);
  fx.world.advance(25 * HOUR_MS);
  await event(fx, "foreground");
  return { within: within, after: result(fx) };
}

/** The backend answers the route of the listing addresses with an error for four days. */
async function readsHeldBack(source) {
  const fx = fixture(source);
  await start(fx);
  fx.world.fault("POST /api/secure/log/read", { status: 503, body: { detail: "log_store_unreachable" } });
  const states = [];
  for (let day = 0; day < 4; day += 1) {
    fx.world.advance(25 * HOUR_MS);
    await event(fx, "foreground");
    states.push(fx.world.state.log.status + ":" + fx.world.state.log.store);
  }
  return { states: states, last: result(fx) };
}

const scenarios = {
  plain: plain,
  formatTwoOnly: formatTwoOnly,
  movedToUnlistedRelease: movedToUnlistedRelease,
  readsHeldBack: readsHeldBack,
};

module.exports = {
  scenarios, fixture, load, start, event, call, providerRequest, lastReport, logState, requestLines, result,
  HOUR_MS, DAY_MS,
};
