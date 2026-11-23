// The tests of the secure program on the model of the bridge (bridge.js) with the fixtures of
// scenarios.js. Run: node --test secure-program/tests/program.test.js
//
// The first tests check the model against protocol/vectors.json (the reference the apps test their
// bridges against) so that the fixtures run on the bytes the protocol specifies. The tests after
// them check the observable contract of the program: the requests it sends, what it reports
// (POST /api/secure/log/verified, the outcomes of its procedures), what it publishes (state.log,
// state.grant), which node receives a grant, and what the program store holds.
"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const bridge = require("./bridge.js");
const S = require("./scenarios.js");

const PROGRAM_PATH = path.join(__dirname, "..", "secure-program.js");
const source = fs.readFileSync(PROGRAM_PATH, "utf8");
const VECTORS_PATH = process.env.SECURE_PROGRAM_VECTORS || path.join(__dirname, "..", "..", "protocol", "vectors.json");
const vectors = JSON.parse(fs.readFileSync(VECTORS_PATH, "utf8"));
const { b64u, bytes, utf8, concat } = bridge;
const { HOUR_MS, DAY_MS } = S;

// ---- Helpers ----

/** The record key of a record of the account of keys (docs/protocol.md 3 and 6). */
function recordKey(keys, record) {
  const purpose = record.custody === "enclave" ? "pickle.secure.v1.user-key" : "pickle.secure.v1.user-key.operator";
  const userKey = Buffer.from(crypto.hkdfSync("sha256", keys.masterKey, Buffer.alloc(0), utf8(purpose), 32));
  return Buffer.from(crypto.hkdfSync("sha256", userKey, bytes(record.id), utf8("pickle.secure.v1.record"), 32));
}

function recordAad(record) {
  return utf8(["pickle.secure.v1.record", "1", record.id, record.user_id, record.key_id, record.custody,
    record.kind, record.provider].join("\n"));
}

/** The plaintext of a record, opened with the keys of the account (the bytes and the JSON). */
function openRecord(keys, record) {
  const plain = bridge.aeadOpen("chacha20poly1305", recordKey(keys, record), bytes(record.nonce), recordAad(record), bytes(record.ct));
  return { bytes: plain, json: JSON.parse(plain.toString("utf8")) };
}

/** A record as a node makes it for the account of the fixture. */
function makeRecord(fx, kind, plaintext) {
  const record = {
    v: 1, id: b64u(crypto.randomBytes(16)), user_id: fx.world.userId, key_id: fx.keys.keyId, custody: "enclave",
    kind: kind, provider: "vault", nonce: b64u(crypto.randomBytes(12)), ct: "",
  };
  record.ct = b64u(bridge.aeadSeal(
    "chacha20poly1305", recordKey(fx.keys, record), bytes(record.nonce), recordAad(record), utf8(JSON.stringify(plaintext))));
  return record;
}

/** The node ledger of a program before v43, as that program kept it in the key store. */
function writeLedger(fx, settings, nodes) {
  const ledger = Object.assign({ v: 1, revoked_ms: 0, resumed_ms: 0, ttl_days: 30, ttl_set_ms: 0, store_failing_ms: 0, discovery_after: "", nodes: {} }, settings);
  for (const item of nodes) {
    ledger.nodes[item.node.id] = Object.assign({
      sign_pk: item.node.id, seal_pk: b64u(item.node.sealPk), platform: "nitro", release: item.node.release,
      first_ms: fx.world.now - 40 * DAY_MS, granted_ms: 0, not_after_ms: 0,
      checkpoint: { seq: 0, hash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", time_ms: 0 }, final: null, gone_ms: 0,
      origin: "grant", unknown_ms: 0, sealed_ms: 0, attempted_ms: 0,
    }, item.fields);
  }
  const json = JSON.stringify(ledger);
  fx.world.keychain.set("com.pickle.client.secure.ledger\n" + fx.world.userId, { value: b64u(utf8(json)), synchronizable: true });
  fx.world.store.set("ledger", json);
  return ledger;
}

/** The ledger the program keeps in the key store. */
function readLedger(fx) {
  const kept = fx.world.keychain.get("com.pickle.client.secure.ledger\n" + fx.world.userId);
  return kept === undefined ? null : JSON.parse(bytes(kept.value).toString("utf8"));
}

/** Every item of the days of a result of read_log, in the order of the screen. */
function shownGroups(result) {
  const groups = [];
  for (const day of result.days) for (const group of day.groups) groups.push(group);
  return groups;
}

/** Runs one round by a synchronization a day after the last one. */
async function nextDay(fx) {
  fx.world.advance(25 * HOUR_MS);
  await S.event(fx, "foreground");
}

// ---- The model against the vectors ----

test("the model derives the account keys of the vectors", () => {
  const expected = vectors.key_derivation;
  const keys = bridge.deriveAccountKeys(bytes(expected.master_key));
  assert.equal(b64u(keys.signSeed), expected.sign_seed);
  assert.equal(b64u(keys.signPk), expected.sign_pk);
  assert.equal(b64u(keys.logSk), expected.log_private);
  assert.equal(b64u(keys.logPk), expected.log_pk);
  assert.equal(keys.keyId, expected.key_id);
});

test("the model opens, seals and signs the log entries of the vectors", () => {
  const log = vectors.log;
  for (const entry of log.entries) {
    const body = JSON.parse(bytes(entry.entry.body).toString("utf8"));
    const aad = utf8([body.node, body.user_id, body.key_id, String(body.seq)].join("\n"));
    const info = utf8(log.hpke_info_text);
    const opened = bridge.hpkeOpen("chacha20poly1305", bytes(log.log_private), bytes(body.enc), info, aad, bytes(body.ct));
    assert.equal(opened.toString("utf8"), entry.events_text);
    const sealed = bridge.hpkeSeal("chacha20poly1305", bytes(log.log_pk), info, aad, utf8(entry.events_text), bytes(entry.hpke_seed));
    assert.equal(b64u(sealed.enc), body.enc);
    assert.equal(b64u(sealed.ciphertext), body.ct);
    const signed = bridge.ed25519Verify(
      bytes(log.node_sign_pk), concat(utf8(log.signature_context_text), bytes(entry.entry.body)), bytes(entry.entry.sig));
    assert.equal(signed, true);
    assert.equal(b64u(bridge.sha("sha256", bytes(entry.entry.body))), entry.body_hash);
  }
});

test("the model verifies the signed values of the vectors as the vectors say", () => {
  for (const item of vectors.signed.cases) {
    const valid = bridge.ed25519Verify(
      bytes(item.public_key), concat(utf8(item.context_text), bytes(item.body)), bytes(item.sig));
    assert.equal(valid, item.valid, item.name);
  }
});

test("the program reads the entries and the node document of format 3 of the vectors, and refuses what the vectors refuse", { skip: vectors.log_v3 === undefined }, async () => {
  const log = vectors.log_v3;
  const world = new bridge.World({ serverTarget: "dev", userId: log.user_id });
  const masterKey = bytes(vectors.key_derivation.master_key);
  world.keychain.set("com.pickle.client.secure.master-key\n" + world.userId, { value: b64u(masterKey), synchronizable: true });
  const keys = bridge.deriveAccountKeys(masterKey);
  assert.equal(keys.keyId, log.key_id);
  world.account.keys = keys;
  world.account.key = { key_id: keys.keyId };
  const bucket = bridge.shardBucket("dev", world.userId);
  for (const entry of log.entries) world.putObject(bucket, entry.key, JSON.stringify(entry.entry));
  for (const refused of log.rejected) {
    // A refused case stands under a key of its own, so that it is judged apart from the entries.
    if (!log.entries.some((entry) => entry.key === refused.key)) world.putObject(bucket, refused.key, JSON.stringify(refused.entry));
  }
  assert.equal(bridge.shardBucket("dev", log.node), log.node_document.bucket);
  world.putObject(log.node_document.bucket, log.node_document.key, log.node_document.object_text);
  const fx = { world: world, keys: keys, program: null, source: source };
  await S.start(fx);
  const shown = await S.call(fx, "read_log", { limit: 100 });
  assert.equal(shown.ok, true);
  const groups = shownGroups(shown.value);
  const events = log.entries.reduce((sum, entry) => sum + entry.count, 0);
  assert.equal(groups.reduce((sum, group) => sum + group.count, 0), events);
  assert.ok(groups.every((group) => group.verified === true));
  assert.equal(world.state.log.unverified_nodes, 0);
  // The listing address the program called is the one of the bucket whose number the vectors give.
  if (vectors.log_store !== undefined) {
    const store = vectors.log_store.stores.find((item) => item.bucket === "character-credential-log-dev-1");
    const owner = store.owners.find((item) => item.owner === log.user_id);
    const host = new URL(world.sent("S3 ")[0].url).host;
    assert.ok(host.split(".")[0].endsWith("-" + String(owner.index).padStart(4, "0")), host);
  }
});

test("the program calls the bucket of an account that the vectors name, for every log store and owner of the vectors", { skip: vectors.log_store === undefined }, async () => {
  const targets = { "character-credential-log-prod-1": "prod", "character-credential-log-dev-1": "dev",
    "character-credential-log-alpha-1": "alpha" };
  let checked = 0;
  for (const store of vectors.log_store.stores) {
    const target = targets[store.bucket];
    if (target === undefined) continue;
    assert.equal(bridge.SHARDS[target].count, store.shards);
    for (const owner of store.owners) {
      assert.equal(bridge.shardBucket(target, owner.owner), owner.bucket);
      const fx = S.fixture(source, { target: target });
      fx.world.userId = owner.owner;
      fx.world.keychain.clear();
      fx.keys = fx.world.createAccount();
      await S.start(fx);
      const hosts = fx.world.sent("S3 ").map((request) => new URL(request.url).host);
      assert.deepEqual(hosts, [owner.bucket + ".s3." + store.region + ".amazonaws.com"], target + " " + owner.owner);
      assert.equal(fx.world.state.log.status, "verified", target + " " + owner.owner);
      checked += 1;
    }
  }
  assert.equal(checked, 12);
});

test("the program refuses the node documents the vectors refuse", { skip: vectors.log_v3 === undefined }, async () => {
  const log = vectors.log_v3;
  for (const refused of log.node_document.rejected) {
    const world = new bridge.World({ serverTarget: "dev", userId: log.user_id });
    const masterKey = bytes(vectors.key_derivation.master_key);
    world.keychain.set("com.pickle.client.secure.master-key\n" + world.userId, { value: b64u(masterKey), synchronizable: true });
    const keys = bridge.deriveAccountKeys(masterKey);
    world.account.keys = keys;
    world.account.key = { key_id: keys.keyId };
    const entry = log.entries[0];
    const key = entry.key.replace(log.node, refused.node);
    world.putObject(bridge.shardBucket("dev", world.userId), key, JSON.stringify(entry.entry));
    world.putObject(bridge.shardBucket("dev", refused.node), "n3/" + refused.node, refused.object_text);
    const fx = { world: world, keys: keys, program: null, source: source };
    await S.start(fx);
    assert.equal(world.reports[world.reports.length - 1].undocumented_nodes, 1, refused.name);
  }
});

// ---- The program as a file ----

test("the top level of the program defines secureProgram and calls nothing", () => {
  const world = new bridge.World();
  const program = bridge.loadProgram(source, world);
  assert.equal(program.version, bridge.declaredVersion(source));
  assert.equal(program.version, 43);
  assert.equal(typeof program.procedures.sync, "function");
  assert.equal(typeof program.onEvent, "function");
  assert.equal(world.requests.length, 0);
  assert.equal(world.logs.length, 0);
  assert.equal(world.timers.length, 0);
});

test("the program lists the releases of the public repository in order, each writing to the log store", () => {
  const listed = bridge.listedMeasurements(source);
  const names = listed.map((release) => release.release);
  assert.deepEqual(names.slice(0, 11), [
    "v1.1.0", "v1.2.0", "v1.3.0", "v1.4.0", "v1.5.0", "v1.5.2", "v2.0.0", "v2.0.1", "v2.1.0", "v2.2.0",
    "v2.3.0",
  ]);
  assert.ok(listed.every((release) => release.log_store === true));
  const measurements = new Set(listed.map((release) => release.pcr0 + release.pcr1 + release.pcr2));
  assert.equal(measurements.size, listed.length);
});

test("the procedures of the program are the ones the definition and the app call", () => {
  const program = bridge.loadProgram(source, new bridge.World());
  assert.deepEqual(Object.keys(program.procedures).sort(), [
    "approve_transfer", "begin_app_password_setup", "begin_transfer", "cancel_app_password_setup", "cancel_transfer",
    "connect", "connect_app_password", "create_key", "delete_secret", "enter_transfer_code", "manage_repositories",
    "poll_transfer", "read_log", "read_log_page", "read_security_record", "reset_key", "reveal_login_password",
    "reveal_secret", "set_connection_writes", "set_delegation", "set_grant_days", "store_card", "store_login",
    "store_secret", "sync", "update_secret",
  ]);
});

// ---- The synchronization ----

test("a node of format 3 receives the grant after one request for its attestation, and the round verifies", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  assert.equal(world.state.key_state, "present");
  assert.deepEqual(world.state.grant.state, "active");
  assert.equal(world.runtime.ready, true);
  assert.equal(fx.nodes[0].grants.has(world.userId), true);
  assert.deepEqual(S.logState(world), {
    status: "verified", unverified_nodes: 0, missing: 0, expired: 0, unknown_nodes: 0, newer_release_nodes: 0,
    store: "verified", store_failure: "", program_version: 43,
  });
  assert.deepEqual(S.lastReport(world), {
    status: "verified", store: "verified", nodes: 1, keys_checked: 1, bodies_fetched: 1, missing: 0, expired: 0,
    unknown_nodes: 0, newer_release_nodes: 0, program_version: 43, store_failure: "", unaccepted_releases: [],
    blocked_attempts: 0, undocumented_nodes: 0, control_keys: 1,
  });
  const attested = world.sent("GET /api/secure/nodes");
  assert.equal(attested.length, 1);
  assert.equal(attested[0].query.nodes, fx.nodes[0].id);
  const grants = world.stored("log.grants");
  assert.deepEqual(Object.keys(grants), [fx.nodes[0].id]);
  assert.equal(grants[fx.nodes[0].id].release, "v2.4.0");
  assert.ok(grants[fx.nodes[0].id].granted_ms > 0);
  // A node of format 3 is not written into the ledger of the earlier programs, and nothing of the
  // ledger is exchanged with the backend.
  assert.equal(world.sent("GET /api/secure/ledger").length, 0);
  assert.equal(world.sent("PUT /api/secure/ledger").length, 0);
  assert.equal(world.sent("S3 " + world.storeHost).length, 0);
});

test("a synchronization with no node to hand a grant to sends no request that calls a node", async () => {
  const fx = S.fixture(source, { nodes: 2 });
  await S.start(fx);
  const world = fx.world;
  const before = world.requests.length;
  const attestations = fx.nodes.map((node) => node.attestations);
  world.advance(HOUR_MS);
  await S.event(fx, "foreground");
  await world.settle(0);
  assert.deepEqual(S.requestLines(world, before).sort(), [
    "GET /api/secure/account", "GET /api/secure/grants", "GET /api/secure/transfers",
  ]);
  assert.deepEqual(fx.nodes.map((node) => node.attestations), attestations);
  // A day later the grants are renewed: one request names the nodes, and a node of format 3
  // writes no entry for a grant that renews the one it holds.
  const entries = world.entries3.size;
  world.advance(24 * HOUR_MS);
  const from = world.requests.length;
  await S.event(fx, "foreground");
  const nodes = world.sent("GET /api/secure/nodes").slice(-1)[0];
  assert.deepEqual(nodes.query.nodes.split(",").sort(), fx.nodes.map((node) => node.id).sort());
  assert.equal(S.requestLines(world, from).filter((line) => line.endsWith("/messages")).length, 2);
  assert.equal(world.entries3.size, entries);
  assert.equal(world.state.log.status, "verified");
});

test("a push with the reason grant_required hands a grant again to a node the backend reports no grant row for, not sooner than a minute after the last", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  const node = fx.nodes[0];
  node.grants.delete(world.userId);
  // An event of the app, and a push of another reason, hand no grant: the grant this device kept
  // is within its renewal interval.
  world.advance(5 * 60000);
  await S.event(fx, "foreground");
  await S.event(fx, "push", { reason: "refresh" });
  assert.equal(node.grants.has(world.userId), false);
  assert.equal(world.syncReports.length, 1);
  assert.deepEqual(Object.assign({}, world.syncReports[0], { elapsed_ms: 0 }), {
    trigger: "push", reason: "refresh", key_state: "present", grant: "active", granted: 0, rejected: 0,
    elapsed_ms: 0, program_version: 43,
  });
  await S.event(fx, "push", { reason: "grant_required" });
  assert.equal(node.grants.has(world.userId), true);
  assert.equal(world.syncReports[1].reason, "grant_required");
  assert.equal(world.syncReports[1].granted, 1);
  // Within a minute of that grant the same push hands none.
  node.grants.delete(world.userId);
  world.advance(30000);
  await S.event(fx, "push", { reason: "grant_required" });
  assert.equal(node.grants.has(world.userId), false);
  assert.equal(world.syncReports[2].granted, 0);
  world.advance(40000);
  await S.event(fx, "push", { reason: "grant_required" });
  assert.equal(node.grants.has(world.userId), true);
});

test("a backend without the route of the node list is asked for the attestations of every node, and what the device kept decides the grants", async () => {
  const fx = S.fixture(source, { nodes: 2 });
  fx.world.routes.grants = false;
  await S.start(fx);
  const world = fx.world;
  assert.equal(world.state.grant.state, "active");
  assert.equal(world.sent("GET /api/secure/nodes")[0].query.nodes, undefined);
  const commands = fx.nodes.map((node) => node.commands.length);
  world.advance(HOUR_MS);
  await S.event(fx, "foreground");
  assert.equal(world.sent("GET /api/secure/nodes").length, 2);
  assert.deepEqual(fx.nodes.map((node) => node.commands.length), commands);
  assert.equal(world.state.grant.state, "active");
});

test("a failure of the node list that is not the absence of its route fails the synchronization and hands no grant", async () => {
  const fx = S.fixture(source);
  fx.world.fault("GET /api/secure/grants", { status: 503, body: { detail: "unavailable" } });
  S.load(fx);
  await assert.rejects(fx.world.run(fx.program.onEvent("session_ready", {})), (error) => error.code === "unavailable");
  assert.equal(fx.world.state.error, "unavailable");
  assert.equal(fx.nodes[0].commands.length, 0);
  assert.equal(fx.world.sent("GET /api/secure/nodes").length, 0);
});

test("the role of a binding: a node without a role and a reserve node receive the grant, a forward node and a node of an unknown role do not", async () => {
  const fx = S.fixture(source, { nodes: 0 });
  const world = fx.world;
  const add = (role) => world.addNode({ release: "v2.4.0", measurement: fx.measurement, role: role });
  const plain = add(undefined);
  const reserve = add("reserve");
  const forward = add("forward");
  const other = add("observer");
  await S.start(fx);
  assert.equal(plain.grants.has(world.userId), true);
  assert.equal(reserve.grants.has(world.userId), true);
  assert.equal(forward.grants.has(world.userId), false);
  assert.equal(other.grants.has(world.userId), false);
  assert.equal(world.runtime.rejected_nodes, 2);
  assert.equal(world.state.grant.state, "active");
  assert.deepEqual(Object.keys(world.stored("log.grants")).sort(), [plain.id, reserve.id].sort());
  // The entries a reserve node wrote are entries of an accepted node.
  assert.equal(world.state.log.status, "verified");
});

test("a node of platform local is accepted by a build for the local stack, a debug build, or a server target of the operator custody, and by no other", async () => {
  const cases = [
    { target: "prod", device: {}, accepted: false },
    { target: "prod", device: { local_stack_build: false }, accepted: false },
    { target: "prod", device: { local_stack_build: true }, accepted: true },
    { target: "prod", device: { debug_build: true }, accepted: true },
    { target: "dev", device: {}, accepted: true },
  ];
  for (const item of cases) {
    const fx = S.fixture(source, { nodes: 0, target: item.target, device: item.device });
    const node = fx.world.addNode({ release: "v2.4.0", measurement: fx.measurement, platform: "local" });
    await S.start(fx);
    assert.equal(node.grants.has(fx.world.userId), item.accepted, JSON.stringify(item));
    if (item.accepted) assert.equal(node.grants.get(fx.world.userId).custody, "operator");
  }
});

test("a node of a release the program does not list receives no grant, is asked for its attestation once, and leaves the log pending for a day", async () => {
  const fx = S.fixture(source);
  const world = fx.world;
  const later = world.addNode({ release: "v2.5.0", measurement: bridge.randomMeasurement() });
  await S.start(fx);
  assert.equal(later.grants.has(world.userId), false);
  assert.equal(world.state.grant.state, "active");
  assert.equal(world.state.log.status, "pending");
  assert.equal(world.state.log.newer_release_nodes, 1);
  assert.equal(world.runtime.rejected_nodes, 0);
  assert.equal(later.attestations, 1);
  world.advance(HOUR_MS);
  await S.event(fx, "foreground");
  assert.equal(later.attestations, 1);
  // The measurement held no key of the account: after the day it is not counted.
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.state.log.newer_release_nodes, 0);
  // The program that lists the release hands that node a grant.
  await S.start(fx, bridge.withListedRelease(fx.source, "v2.5.0", later.measurement, 44));
  assert.equal(later.grants.has(world.userId), true);
});

test("a device without a master key judges the key and calls no node", async () => {
  const fx = S.fixture(source, { account: false });
  await S.start(fx);
  assert.equal(fx.world.state.key_state, "absent");
  assert.equal(fx.world.runtime.ready, true);
  assert.deepEqual(S.requestLines(fx.world), ["GET /api/secure/account"]);
  const created = await S.call(fx, "create_key");
  assert.equal(created.ok, true);
  assert.equal(created.value.key_state, "present");
  assert.equal(fx.world.state.grant.state, "active");
  assert.equal(fx.nodes[0].grants.has(fx.world.userId), true);
});

// ---- The ledger of the programs before v43 ----

test("the ledger of the program before is carried over once: its grants and verification points, and none of its marks", async () => {
  const fx = S.fixture(source, { nodes: 0, legacy: 3 });
  const world = fx.world;
  const [living, ended, unexplained] = fx.legacy;
  const seal = { logPk: fx.keys.logPk, keyId: fx.keys.keyId };
  // A node that lives and holds a grant of two hours ago, a node that ended a month ago whose chain
  // the earlier program verified to its final head, and a node the earlier program found in the
  // store only and marked as a delegation the app did not make.
  living.grants.set(world.userId, { sign_pk: b64u(fx.keys.signPk), log_pk: b64u(fx.keys.logPk), key_id: fx.keys.keyId, custody: "enclave", not_after_ms: world.now + 29 * DAY_MS });
  living.appendEntry(world.userId, "c", [{ t: "grant_accepted", time_ms: world.now - 2 * HOUR_MS, not_after_ms: world.now + 29 * DAY_MS, custody: "enclave" }], Object.assign({ timeMs: world.now - 2 * HOUR_MS }, seal));
  living.appendEntry(world.userId, "u", [S.providerRequest(world.now - HOUR_MS)], Object.assign({ timeMs: world.now - HOUR_MS }, seal));
  ended.appendEntry(world.userId, "c", [{ t: "grant_accepted", time_ms: world.now - 40 * DAY_MS, not_after_ms: world.now - 10 * DAY_MS, custody: "enclave" }], Object.assign({ timeMs: world.now - 40 * DAY_MS }, seal));
  ended.shutDown();
  unexplained.offered = false;
  unexplained.appendEntry(world.userId, "u", [S.providerRequest(world.now - 3 * DAY_MS)], Object.assign({ timeMs: world.now - 3 * DAY_MS }, seal));
  writeLedger(fx, { ttl_days: 7, ttl_set_ms: world.now - 50 * DAY_MS, store_failing_ms: world.now - 5 * DAY_MS }, [
    { node: living, fields: { granted_ms: world.now - 2 * HOUR_MS, not_after_ms: world.now + 7 * DAY_MS, checkpoint: { seq: 2, hash: b64u(living.chains.get(world.userId)[1].entryHash), time_ms: world.now - HOUR_MS } } },
    { node: ended, fields: { granted_ms: world.now - 40 * DAY_MS, not_after_ms: world.now - 10 * DAY_MS, gone_ms: world.now - 30 * DAY_MS, checkpoint: { seq: 1, hash: b64u(ended.chains.get(world.userId)[0].entryHash), time_ms: world.now - 40 * DAY_MS }, final: { seq: 1, hash: b64u(ended.chains.get(world.userId)[0].entryHash) } } },
    { node: unexplained, fields: { origin: "store", unknown_ms: world.now - DAY_MS, sealed_ms: world.now - DAY_MS, checkpoint: { seq: 1, hash: b64u(unexplained.chains.get(world.userId)[0].entryHash), time_ms: world.now - 3 * DAY_MS } } },
  ]);
  world.state.log = { status: "attention", unknown_nodes: 1, program_version: 42 };
  await S.start(fx);
  const grants = world.stored("log.grants");
  assert.deepEqual(Object.keys(grants).sort(), [living.id, ended.id].sort());
  assert.equal(grants[living.id].granted_ms, world.now - 2 * HOUR_MS);
  const legacy = world.stored("log.legacy").nodes;
  assert.deepEqual(Object.keys(legacy).sort(), [living.id, ended.id].sort());
  assert.equal(legacy[living.id].seq, 2);
  assert.equal(legacy[living.id].closed, false);
  assert.equal(legacy[ended.id].closed, true);
  assert.equal(world.store.get("log.migrated"), "43");
  // The first round of this program judges by its own conditions: the mark of the earlier program
  // is gone, and the grant of two hours ago is not handed again.
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.state.log.unknown_nodes, 0);
  assert.equal(world.state.log.program_version, 43);
  assert.equal(living.commands.length, 0);
  // The settings of the delegation stay in the ledger of the key store.
  assert.equal(world.state.grant_days, 7);
  assert.equal(readLedger(fx).ttl_days, 7);
  assert.equal(readLedger(fx).nodes[unexplained.id].unknown_ms, world.now - DAY_MS);
  // The ledger is carried over once.
  const kept = JSON.stringify(world.stored("log.grants"));
  await S.start(fx);
  assert.equal(JSON.stringify(world.stored("log.grants")), kept);
});

test("a grant to a node of a release before v2.4.0 is written into the ledger and shared, for the devices of the account that run an earlier program", async () => {
  const fx = S.fixture(source, { nodes: 1, legacy: 1 });
  await S.start(fx);
  const world = fx.world;
  await world.settle(1000);
  const ledger = readLedger(fx);
  assert.deepEqual(Object.keys(ledger.nodes), [fx.legacy[0].id]);
  const kept = ledger.nodes[fx.legacy[0].id];
  assert.equal(kept.origin, "grant");
  assert.ok(kept.granted_ms > 0 && kept.not_after_ms > kept.granted_ms);
  assert.equal(kept.checkpoint.seq, 0);
  assert.equal(kept.unknown_ms, 0);
  assert.equal(world.sent("GET /api/secure/ledger").length, 1);
  assert.equal(world.ledgerUploads, 1);
  // The same grant a day later changes no node of the ledger: nothing is shared again.
  await nextDay(fx);
  await world.settle(1000);
  assert.equal(world.ledgerUploads, 1);
});

// ---- The round: the four conditions that mark the log ----

test("A1: the key of the account at a measurement no list has is pending for a day and marks the log after it; the program that lists the release clears the mark", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  const other = bridge.randomMeasurement();
  const receiver = world.addNode({ release: "v9.0.0", measurement: other, offered: false });
  fx.nodes[0].record("c", [{
    t: "grant_transferred_out", time_ms: world.now, to: receiver.id, release: "v9.0.0",
    pcr0: other.pcr0, pcr1: other.pcr1, pcr2: other.pcr2,
  }]);
  await nextDay(fx);
  assert.equal(world.state.log.status, "pending");
  assert.equal(world.state.log.newer_release_nodes, 1);
  assert.equal(world.state.log.unknown_nodes, 0);
  assert.deepEqual(world.reports.slice(-1)[0].unaccepted_releases, ["v9.0.0"]);
  assert.deepEqual(world.securityStatuses.slice(-1)[0].status, "pending");
  await nextDay(fx);
  assert.equal(world.state.log.status, "attention");
  assert.equal(world.state.log.unknown_nodes, 1);
  assert.equal(world.state.log.newer_release_nodes, 0);
  assert.deepEqual(world.reports.slice(-1)[0].unknown_node_ids, [receiver.id]);
  const told = world.securityStatuses.slice(-1)[0];
  assert.deepEqual({ status: told.status, reasons: told.reasons }, { status: "attention", reasons: ["unlisted_release"] });
  await S.start(fx, bridge.withListedRelease(fx.source, "v9.0.0", other, 44));
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.state.log.unknown_nodes, 0);
});

test("A1: an entry of the key of the account written by a node whose document verifies with a measurement no list has", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  const later = world.addNode({ release: "v9.0.0", measurement: bridge.randomMeasurement(), offered: false });
  later.record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r", provider: "slack", scope: "" }]);
  await nextDay(fx);
  assert.equal(world.state.log.status, "pending");
  assert.equal(world.state.log.newer_release_nodes, 1);
  await nextDay(fx);
  assert.equal(world.state.log.status, "attention");
  assert.equal(world.state.log.unknown_nodes, 1);
  // An entry of another key written by such a node says nothing of the key of this account.
  const quiet = S.fixture(source);
  await S.start(quiet);
  const stranger = quiet.world.addNode({ release: "v9.0.0", measurement: bridge.randomMeasurement(), offered: false });
  stranger.write(quiet.world.userId, "c", [{ t: "grant_revoked", time_ms: quiet.world.now }], {
    logPk: bridge.x25519PublicKey(crypto.randomBytes(32)), keyId: "0123456789abcdef",
  });
  await nextDay(quiet);
  await nextDay(quiet);
  assert.equal(quiet.world.state.log.status, "verified");
});

test("A1: a transfer a node of an earlier release made is followed through its chain of format 2 to the node document of the receiving node", async () => {
  const fx = S.fixture(source, { nodes: 0, legacy: 1 });
  await S.start(fx);
  const world = fx.world;
  const giver = fx.legacy[0];
  const receiver = world.addNode({ release: "v9.0.0", measurement: bridge.randomMeasurement(), offered: false });
  giver.record("c", [{ t: "grant_transferred_out", time_ms: world.now, to: receiver.id }]);
  await nextDay(fx);
  assert.equal(world.state.log.status, "pending");
  assert.equal(world.state.log.newer_release_nodes, 1);
  await nextDay(fx);
  assert.equal(world.state.log.status, "attention");
  assert.equal(world.state.log.unknown_nodes, 1);
});

test("a transfer between nodes of an earlier release is followed: the chain of the receiving node is read, and nothing marks the log", async () => {
  const fx = S.fixture(source, { nodes: 0, legacy: 1 });
  await S.start(fx);
  const world = fx.world;
  const giver = fx.legacy[0];
  const receiver = world.addNode({ release: fx.latest.release, measurement: fx.latest, offered: false });
  const third = world.addNode({ release: fx.latest.release, measurement: fx.latest, offered: false });
  giver.record("c", [{ t: "grant_transferred_out", time_ms: world.now, to: receiver.id }]);
  receiver.record("c", [{ t: "grant_transferred_in", time_ms: world.now, from: giver.id, not_after_ms: world.now + DAY_MS, custody: "enclave" }]);
  receiver.record("c", [{ t: "grant_transferred_out", time_ms: world.now, to: third.id }]);
  third.record("c", [{ t: "grant_transferred_in", time_ms: world.now, from: receiver.id, not_after_ms: world.now + DAY_MS, custody: "enclave" }]);
  await nextDay(fx);
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  const followed = world.stored("log.legacy").nodes;
  assert.deepEqual(Object.keys(followed).sort(), [giver.id, receiver.id, third.id].sort());
  assert.equal(followed[receiver.id].seq, 2);
  assert.equal(followed[third.id].seq, 1);
});

test("A2: a body its key names without a signature of the accepted node of that key, and two bodies an accepted node signed for one seq", async () => {
  const forged = S.fixture(source, { device: { securityStatus: true } });
  await S.start(forged);
  forged.nodes[0].record("c", [{ t: "connection_removed", time_ms: forged.world.now, record_id: "r", provider: "slack", provider_revoke: false }], {
    signSeed: crypto.randomBytes(32),
  });
  await nextDay(forged);
  assert.equal(forged.world.state.log.status, "attention");
  assert.equal(forged.world.state.log.unverified_nodes, 1);
  assert.deepEqual(forged.world.securityStatuses.slice(-1)[0].reasons, ["conflicting_signatures"]);
  // The mark stays with the node: a round that reads nothing new keeps it.
  await nextDay(forged);
  assert.equal(forged.world.state.log.status, "attention");

  const twice = S.fixture(source);
  await S.start(twice);
  const event = (provider) => [{ t: "connection_created", time_ms: twice.world.now, record_id: "r", provider: provider, scope: "" }];
  twice.nodes[0].record("c", event("slack"), { seq: 7 });
  twice.nodes[0].record("c", event("notion"), { seq: 7 });
  await nextDay(twice);
  assert.equal(twice.world.state.log.status, "attention");
  assert.equal(twice.world.state.log.unverified_nodes, 1);
});

test("A3: reads the backend holds back mark the log after three days and three rounds, and one round that reads the store clears the count", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  world.fault("POST /api/secure/log/read", { status: 503, body: { detail: "log_store_unreachable" } });
  const states = [];
  for (let day = 0; day < 4; day += 1) {
    await nextDay(fx);
    states.push(world.state.log.status + ":" + world.state.log.store + ":" + world.reports.slice(-1)[0].blocked_attempts);
  }
  assert.deepEqual(states, ["pending:blocked:1", "pending:blocked:2", "pending:blocked:3", "attention:blocked:4"]);
  assert.equal(world.state.log.store_failure, "read:503");
  assert.ok(world.state.log.store_failing_ms > 0);
  assert.deepEqual(world.securityStatuses.slice(-1)[0].reasons, ["verification_blocked"]);
  world.clearFaults();
  world.advance(HOUR_MS);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.state.log.store_failing_ms, 0);
  assert.equal(world.securityStatuses.slice(-1)[0].status, "ok");
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
});

test("A3: three blocked rounds within three days do not mark the log", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  world.fault("POST /api/secure/log/read", { status: 500 });
  await nextDay(fx);
  for (let turn = 0; turn < 5; turn += 1) {
    world.advance(10 * 60000);
    await S.event(fx, "foreground");
  }
  assert.equal(world.reports.slice(-1)[0].blocked_attempts, 6);
  assert.equal(world.state.log.status, "pending");
});

test("A3: what counts as a read the operator domain holds back", async () => {
  const blocked = async (name, arrange, expected) => {
    const fx = S.fixture(source);
    await S.start(fx);
    await arrange(fx);
    await nextDay(fx);
    assert.equal(fx.world.state.log.store, "blocked", name);
    assert.equal(fx.world.state.log.status, "pending", name);
    assert.equal(fx.world.state.log.store_failure, expected, name);
    assert.equal(fx.world.stored("log.blocked").count, 1, name);
  };
  await blocked("an address of another bucket", async (fx) => {
    fx.world.fault("POST /api/secure/log/read", (request) => ({
      status: 200, body: {
        store: {}, expires_ms: 0,
        pages: JSON.parse(request.body).pages.map((page) => ({
          prefix: page.prefix, url: fx.world.readUrl(page).replace(fx.world.shardHost, fx.world.storeHost),
        })),
      },
    }));
  }, "read:url");
  await blocked("an address of the prefix of another account", async (fx) => {
    fx.world.fault("POST /api/secure/log/read", (request) => ({
      status: 200, body: {
        pages: JSON.parse(request.body).pages.map((page) => ({
          prefix: page.prefix, url: fx.world.readUrl(page).replace(encodeURIComponent("a3/" + fx.world.userId + "/"), encodeURIComponent("a3/someone-else/")),
        })),
      },
    }));
  }, "read:url");
  await blocked("an address with a marker the program did not ask for", async (fx) => {
    fx.world.fault("POST /api/secure/log/read", (request) => ({
      status: 200, body: {
        pages: JSON.parse(request.body).pages.map((page) => ({
          prefix: page.prefix, url: fx.world.readUrl(Object.assign({}, page, { key_marker: "a3/" + fx.world.userId + "/c/5" })),
        })),
      },
    }));
  }, "read:url");
  await blocked("the store refuses the address the backend signed", async (fx) => {
    fx.world.fault("S3 " + fx.world.shardHost, { status: 403, body: "" });
  }, "listing:403");
  await blocked("the backend hands out no body for a key the listing names", async (fx) => {
    fx.nodes[0].record("c", [{ t: "connection_created", time_ms: fx.world.now, record_id: "r", provider: "slack", scope: "" }]);
    fx.world.fault("POST /api/secure/log/bodies", (request) => ({
      status: 200, body: { entries: [], missing: JSON.parse(request.body).keys },
    }));
  }, "bodies:missing");
  await blocked("the backend hands out another body than the key names", async (fx) => {
    const kept = fx.nodes[0].chains.get(fx.world.userId)[0];
    fx.nodes[0].record("c", [{ t: "connection_created", time_ms: fx.world.now, record_id: "r", provider: "slack", scope: "" }]);
    fx.world.fault("POST /api/secure/log/bodies", (request) => ({
      status: 200, body: {
        entries: JSON.parse(request.body).keys.map((key) => Object.assign({ key: key }, JSON.parse(kept.object))), missing: [],
      },
    }));
  }, "bodies:hash");
  await blocked("the route of the bodies does not answer while the backend answers other requests", async (fx) => {
    fx.nodes[0].record("c", [{ t: "connection_created", time_ms: fx.world.now, record_id: "r", provider: "slack", scope: "" }]);
    fx.world.fault("POST /api/secure/log/bodies", "hang");
  }, "bodies:timeout");
  await blocked("a signed entry of a node without a node document", async (fx) => {
    const silent = fx.world.addNode({ release: "v2.4.0", measurement: fx.measurement, offered: false, document: false });
    silent.record("c", [{ t: "connection_created", time_ms: fx.world.now, record_id: "r", provider: "slack", scope: "" }]);
  }, "documents:missing");
  await blocked("a signed entry of a node whose document does not verify", async (fx) => {
    const broken = fx.world.addNode({ release: "v2.4.0", measurement: fx.measurement, offered: false, brokenSignature: true });
    broken.record("c", [{ t: "connection_created", time_ms: fx.world.now, record_id: "r", provider: "slack", scope: "" }]);
  }, "documents:rejected");
  await blocked("a backend that states it has no store of format 3 after this device handed a grant to a node that writes it", async (fx) => {
    fx.world.routes.log = "disabled";
  }, "read:log_store_disabled");
});

test("a device without a network, and a store that fails, leave the log pending and count no blocked round, however long", async () => {
  const offline = S.fixture(source);
  await S.start(offline);
  offline.world.advance(2 * HOUR_MS);
  offline.world.fault(() => true, "transport");
  for (let day = 0; day < 5; day += 1) {
    offline.world.advance(25 * HOUR_MS);
    const shown = await S.call(offline, "read_log", { limit: 10 });
    assert.equal(shown.ok, true);
    assert.equal(shown.value.status, "pending");
    await offline.world.settle(40000);
  }
  assert.equal(offline.world.state.log.status, "pending");
  assert.equal(offline.world.state.log.store, "unreachable");
  assert.deepEqual(offline.world.stored("log.blocked"), { first_ms: 0, count: 0 });

  const failing = S.fixture(source);
  await S.start(failing);
  failing.world.fault("S3 ", { status: 503, body: "" });
  for (let day = 0; day < 5; day += 1) await nextDay(failing);
  assert.equal(failing.world.state.log.status, "pending");
  assert.equal(failing.world.state.log.store, "unreachable");
  assert.equal(failing.world.state.log.store_failure, "listing:503");
  assert.deepEqual(failing.world.stored("log.blocked"), { first_ms: 0, count: 0 });
});

test("A4: an entry this device verified that left the listing within its retention marks the log, after the listing was read a second time", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  const seen = fx.nodes[0].chains.get(world.userId)[0].key;
  assert.equal(world.stored("log.sample").length, 1);
  world.entries3.delete(seen);
  const before = world.sent("POST /api/secure/log/read").length;
  await nextDay(fx);
  assert.equal(world.sent("POST /api/secure/log/read").length, before + 2);
  assert.equal(world.state.log.status, "attention");
  assert.equal(world.state.log.missing, 1);
  // An entry older than the retention of the store is expected by nobody.
  const aged = S.fixture(source);
  await S.start(aged);
  aged.world.entries3.delete(aged.nodes[0].chains.get(aged.world.userId)[0].key);
  aged.world.advance(366 * DAY_MS);
  await S.event(aged, "foreground");
  assert.equal(aged.world.state.log.missing, 0);
});

test("what does not mark the log: an object nobody signed under a node id without a document, an empty seq, a node that ended without a shutdown, an entry of another key", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  const node = fx.nodes[0];
  // An object under a node id no document exists for, with a body the key names and no signature
  // of that node id.
  const ghost = new bridge.Node(world, { release: "v2.4.0", measurement: fx.measurement, document: false });
  ghost.record("c", [{ t: "grant_revoked", time_ms: world.now }], { signSeed: crypto.randomBytes(32) });
  // A seq the store never confirmed, between two entries.
  node.record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r1", provider: "slack", scope: "" }], { stored: false });
  node.record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r2", provider: "notion", scope: "" }]);
  // An entry sealed to an earlier key of the account.
  node.write(world.userId, "c", [{ t: "grant_revoked", time_ms: world.now }], {
    logPk: bridge.x25519PublicKey(crypto.randomBytes(32)), keyId: "0123456789abcdef",
  });
  // The node ends without an orderly shutdown.
  node.alive = false;
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.state.log.store, "verified");
  assert.equal(world.reports.slice(-1)[0].undocumented_nodes, 1);
  const shown = await S.call(fx, "read_log", { limit: 50 });
  const kinds = shownGroups(shown.value).map((group) => group.kind);
  assert.deepEqual(kinds, ["other_key", "connected", "grant_renewed"]);
  assert.equal(world.state.log.status, "verified");
});

test("a listing longer than the pages of one round is read on by the next round, and the keys judged once are not read again", async () => {
  const fx = S.fixture(source);
  const world = fx.world;
  world.pageSize = 3;
  for (let i = 0; i < 20; i += 1) {
    world.advance(1000);
    fx.nodes[0].record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r" + i, provider: "slack", scope: "" }]);
  }
  await S.start(fx);
  assert.equal(world.state.log.status, "pending");
  assert.equal(world.state.log.store, "truncated");
  assert.equal(world.reports.slice(-1)[0].keys_checked, 12);
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.stored("log.seen").length, 21);
  // A round after it reads the listing from its start and asks for no body.
  const bodies = world.sent("POST /api/secure/log/bodies").length;
  world.pageSize = 1000;
  await nextDay(fx);
  assert.equal(world.sent("POST /api/secure/log/bodies").length, bodies);
  assert.equal(world.state.log.status, "verified");
});

test("an entry that lands below the entries this device saw is judged by the next round", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  const other = bridge.randomMeasurement();
  const late = world.now - 10 * 60000;
  world.advance(HOUR_MS);
  fx.nodes[0].record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r", provider: "slack", scope: "" }]);
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  // The node wrote this entry at an earlier time of its clock and the store confirmed it only now.
  fx.nodes[0].record("c", [{
    t: "grant_transferred_out", time_ms: late, to: world.addNode({ release: "v9.0.0", measurement: other, offered: false }).id,
    release: "v9.0.0", pcr0: other.pcr0, pcr1: other.pcr1, pcr2: other.pcr2,
  }], { timeMs: late });
  await nextDay(fx);
  assert.equal(world.state.log.newer_release_nodes, 1);
  assert.equal(world.state.log.status, "pending");
});

// ---- An environment whose nodes write format 2 ----

test("an environment without a node of format 3 and without the routes of this program: the grants, the round and the screen work on the routes of the program before, and nothing marks the log however long", async () => {
  const fx = S.fixture(source, { nodes: 0, legacy: 2 });
  const world = fx.world;
  world.routes = { grants: false, log: "absent", outcomes: false, syncReport: false };
  const node = fx.legacy[0];
  await S.start(fx);
  assert.equal(world.state.grant.state, "active");
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.state.log.store, "verified");
  for (let i = 0; i < 6; i += 1) {
    world.advance(60000);
    node.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, i % 2 === 0 ? "GET" : "POST")]);
  }
  // A seq the store never confirmed and a node that ended without its final head mark nothing.
  node.record("u", [S.providerRequest(world.now)], { stored: false });
  node.record("u", [S.providerRequest(world.now + 1, "/gmail/v1/users/me/labels")]);
  fx.legacy[1].alive = false;
  const shown = await S.call(fx, "read_log", { limit: 100 });
  assert.equal(shown.ok, true);
  assert.equal(shown.value.status, "verified");
  const groups = shownGroups(shown.value);
  assert.equal(groups.reduce((sum, group) => sum + group.count, 0), 9);
  assert.deepEqual(shown.value.summary, { reads: 4, sends: 0, changes: 3, providers_text: "Google · Gmail", truncated: false });
  for (let day = 0; day < 6; day += 1) {
    await nextDay(fx);
    assert.equal(world.state.log.status, "verified", "day " + day);
  }
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.equal(world.reports.every((report) => report.status === "verified"), true);
});

test("an environment whose backend has the routes and holds the store of format 3 closed: the round reads the chains of format 2 and verifies", async () => {
  const outcome = await S.scenarios.formatTwoOnly(source);
  assert.equal(outcome.log.status, "verified");
  assert.equal(outcome.grant, "active");
  assert.deepEqual(outcome.granted, [true]);
  assert.equal(outcome.report.control_keys, 0);
  assert.equal(outcome.report.keys_checked, 1);
});

test("the chain of a node of an earlier release is closed once its grant ran out and its end was read", async () => {
  const fx = S.fixture(source, { nodes: 1, legacy: 1 });
  await S.start(fx);
  const world = fx.world;
  const id = fx.legacy[0].id;
  fx.legacy[0].alive = false;
  assert.equal(world.stored("log.legacy").nodes[id].closed, false);
  world.advance(32 * DAY_MS);
  await S.event(fx, "foreground");
  assert.equal(world.stored("log.legacy").nodes[id].closed, true);
  const listings = world.sent("POST /api/secure/log/store/listings").length;
  await nextDay(fx);
  assert.equal(world.sent("POST /api/secure/log/store/listings").length, listings);
  assert.equal(world.state.log.status, "verified");
});

// ---- The judgement the app is told ----

test("the app is told ok, pending and attention, and an attention is not covered by a round that did not complete", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  assert.deepEqual(world.securityStatuses.map((told) => told.status), ["ok"]);
  fx.nodes[0].record("c", [{ t: "connection_removed", time_ms: world.now, record_id: "r", provider: "slack", provider_revoke: false }], {
    signSeed: crypto.randomBytes(32),
  });
  await nextDay(fx);
  assert.equal(world.securityStatuses.slice(-1)[0].status, "attention");
  const told = world.securityStatuses.length;
  world.fault("S3 ", { status: 503, body: "" });
  await nextDay(fx);
  assert.equal(world.state.log.status, "attention");
  assert.equal(world.securityStatuses.length, told + 1);
  assert.equal(world.securityStatuses.slice(-1)[0].status, "attention");
  // A build without the primitive is told nothing, and the round runs the same.
  const plain = S.fixture(source);
  await S.start(plain);
  assert.equal(plain.world.securityStatuses.length, 0);
  assert.equal(plain.world.state.log.status, "verified");
});
