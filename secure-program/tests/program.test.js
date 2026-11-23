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
// The vectors: protocol/vectors.json of this checkout, or the files SECURE_PROGRAM_VECTORS names
// (paths separated by commas; a later file adds the vectors the files before it do not have). A
// test of vectors a file set does not hold is skipped.
const VECTORS_PATHS = (process.env.SECURE_PROGRAM_VECTORS || path.join(__dirname, "..", "..", "protocol", "vectors.json"))
  .split(",").map((item) => item.trim()).filter((item) => item !== "");
const vectors = {};
for (const file of VECTORS_PATHS) {
  const read = JSON.parse(fs.readFileSync(file, "utf8"));
  for (const name of Object.keys(read)) {
    if (vectors[name] === undefined) vectors[name] = read[name];
  }
}
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

/** Has the backend of a fixture answer the route of the node documents as its model does, with
 *  what edit(answer, nodes) changes in that answer. Returns the fault. */
function documentsAnswer(fx, edit) {
  return fx.world.fault("POST /api/secure/log/documents", (request) => {
    const answer = JSON.parse(fx.world.api("POST", "/api/secure/log/documents", null, request.body).body);
    edit(answer, JSON.parse(request.body).nodes);
    return { status: 200, body: answer };
  });
}

/** Has the backend of a fixture hand out no document for the nodes ids: it reports them under
 *  field (missing or unread) and answers everything else as its model does. */
function withhold(fx, ids, field) {
  return documentsAnswer(fx, (answer, nodes) => {
    answer.documents = answer.documents.filter((item) => ids.indexOf(item.node) < 0);
    for (const id of nodes) {
      if (ids.indexOf(id) >= 0 && answer[field].indexOf(id) < 0) answer[field].push(id);
    }
  });
}

/** The addresses of the listings of node documents the program called at the store. */
function documentListings(world) {
  return world.sent("S3 ").map((request) => new URL(request.url))
    .filter((url) => String(url.searchParams.get("prefix")).startsWith("n3/"));
}

/** Whether a request of the program is the listing of a node document at the store. */
function isDocumentListing(line, request) {
  return typeof request.url === "string" && String(new URL(request.url).searchParams.get("prefix")).startsWith("n3/");
}

/** The attestation document of a node as the node registry of the backend keeps it: the document
 *  that answered a request of the backend, with the nonce of that request. */
function registryDocument(node) {
  return {
    v: 1, platform: node.platform, document: b64u(node.platformDocument(crypto.randomBytes(32))), node: node.id,
    release: node.release,
  };
}

/** The keys of the bodies the program asked the backend for, over all its requests. */
function askedBodies(world) {
  let keys = [];
  for (const request of world.sent("POST /api/secure/log/bodies")) keys = keys.concat(JSON.parse(request.body).keys);
  return keys;
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

/** A fixture of the account of the vectors of format 3 on the server target given: the device
 *  holds the master key of the vectors, the bucket of the account holds the entries of the
 *  vectors, and the bucket of the node of the vectors holds its node document. The node of the
 *  vectors is of platform local and its binding names the log store of dev, so a build for dev
 *  accepts it. */
function vectorFixture(target) {
  const log = vectors.log_v3;
  const world = new bridge.World({ serverTarget: target || "dev", userId: log.user_id });
  const masterKey = bytes(vectors.key_derivation.master_key);
  world.keychain.set("com.pickle.client.secure.master-key\n" + world.userId, { value: b64u(masterKey), synchronizable: true });
  const keys = bridge.deriveAccountKeys(masterKey);
  assert.equal(keys.keyId, log.key_id);
  world.account.keys = keys;
  world.account.key = { key_id: keys.keyId };
  const bucket = bridge.shardBucket(world.serverTarget, world.userId);
  for (const entry of log.entries) world.putObject(bucket, entry.key, JSON.stringify(entry.entry));
  world.putObject(bridge.shardBucket(world.serverTarget, log.node), log.node_document.key, log.node_document.object_text);
  return { world: world, keys: keys, program: null, source: source };
}

/** Has the backend of a fixture hand out the object given for one key of format 3, and what it
 *  holds for every other key. */
function handOut(fx, key, object) {
  fx.world.fault("POST /api/secure/log/bodies", (request) => {
    const answer = JSON.parse(fx.world.api("POST", "/api/secure/log/bodies", null, request.body).body);
    if (JSON.parse(request.body).keys.indexOf(key) < 0) return { status: 200, body: answer };
    return {
      status: 200, body: {
        entries: answer.entries.filter((item) => item.key !== key).concat([Object.assign({ key: key }, object)]),
        missing: answer.missing.filter((item) => item !== key),
      },
    };
  });
}

test("the program reads the keys, the bodies, the sealed events and the node document of format 3 of the vectors", { skip: vectors.log_v3 === undefined }, async () => {
  const log = vectors.log_v3;
  assert.equal(log.verifies, true);
  assert.equal(log.node_document.accepted, true);
  const fx = vectorFixture("dev");
  const world = fx.world;
  assert.equal(bridge.shardBucket("dev", log.node), log.node_document.bucket);
  await S.start(fx);
  // The round reads the control prefix: the keys the vectors list under it, each a verified entry
  // of the node of the vectors. The last of them hands the delegation on to a measurement no list
  // has, so the round is pending within the grace and names the release of the event.
  const report = world.reports[world.reports.length - 1];
  assert.equal(report.control_keys, log.control_listing.length);
  assert.equal(report.keys_checked, log.control_listing.length);
  assert.equal(report.undocumented_nodes, 0);
  assert.equal(report.store, "verified");
  const moved = JSON.parse(log.entries.find((entry) => entry.key === log.control_listing[0]).events_text)[0];
  assert.deepEqual(report.unaccepted_releases, [moved.release]);
  assert.deepEqual(report.unknown_node_ids, [moved.to]);
  assert.equal(world.state.log.status, "pending");
  assert.equal(world.state.log.newer_release_nodes, 1);
  assert.equal(world.state.log.unverified_nodes, 0);
  // The screen opens every entry: the events of the vectors, the latest first.
  const shown = await S.call(fx, "read_log", { limit: 100 });
  assert.equal(shown.ok, true);
  const groups = shownGroups(shown.value);
  const events = log.entries.reduce((sum, entry) => sum + entry.count, 0);
  assert.equal(groups.reduce((sum, group) => sum + group.count, 0), events);
  assert.ok(groups.every((group) => group.verified === true));
  assert.deepEqual(groups.map((group) => group.kind), ["moved", "filled", "request", "grant_renewed"]);
  const opened = log.entries.map((entry) => JSON.parse(entry.events_text));
  const filled = opened.find((list) => list[0].t === "secret_released")[0];
  assert.equal(groups[1].field, filled.field);
  assert.equal(groups[1].detail, new URL(filled.origin).host);
  const requests = opened.find((list) => list[0].t === "provider_request");
  assert.deepEqual(
    groups[2].requests.map((row) => row.target).sort(),
    requests.map((event) => event.host + event.path).sort());
  assert.deepEqual(groups.map((group) => group.time_ms), [
    opened[3][0].time_ms, filled.time_ms, Math.max.apply(null, requests.map((event) => event.time_ms)), opened[0][0].time_ms,
  ]);
  // The listing addresses the program called are the ones of the bucket the vectors give for
  // this account, one per prefix.
  if (vectors.log_store !== undefined) {
    const store = vectors.log_store.stores.find((item) => item.bucket === "character-credential-log-dev-1");
    const owner = store.owners.find((item) => item.owner === log.user_id);
    const called = world.sent("S3 ").map((request) => new URL(request.url))
      .filter((url) => String(url.searchParams.get("prefix")).startsWith("a3/"));
    assert.ok(called.every((url) => url.host === owner.bucket + ".s3." + store.region + ".amazonaws.com"));
    assert.deepEqual(
      Array.from(new Set(called.map((url) => url.searchParams.get("prefix")))).sort(),
      [log.control_prefix, log.use_prefix]);
  }
  // A day later the measurement of the event still is on no list: the log is marked (A1).
  await nextDay(fx);
  assert.equal(world.state.log.status, "attention");
  assert.equal(world.state.log.unknown_nodes, 1);
});

test("the program answers the objects the vectors refuse as the reference does: another body, another signature, a key of another seq", { skip: vectors.log_v3 === undefined }, async () => {
  const log = vectors.log_v3;
  const byName = (name) => log.rejected.find((item) => item.name === name);
  assert.deepEqual(log.rejected.map((item) => item.result).sort(), ["body", "fields", "signature"]);
  const events = log.entries.reduce((sum, entry) => sum + entry.count, 0);
  const count = (shown) => shownGroups(shown.value).reduce((sum, group) => sum + group.count, 0);

  // body: the object does not hold the body its key names. The listing of the store named the
  // key, so the body the backend handed out is a read held back.
  const other = vectorFixture("dev");
  const body = byName("the_body_of_another_entry");
  assert.equal(body.result, "body");
  handOut(other, body.key, body.entry);
  await S.start(other);
  await S.call(other, "read_log", { limit: 100 });
  assert.equal(other.world.state.log.store, "blocked");
  assert.equal(other.world.state.log.store_failure, "bodies:hash");
  assert.equal(other.world.state.log.unverified_nodes, 0);

  // signature: the body its key names, and a signature that is not one of the node of the key.
  // The node passed its document, so the object contradicts it (A2).
  const forged = vectorFixture("dev");
  const signature = byName("the_signature_of_another_node");
  assert.equal(signature.result, "signature");
  handOut(forged, signature.key, signature.entry);
  await S.start(forged);
  const marked = await S.call(forged, "read_log", { limit: 100 });
  assert.equal(forged.world.state.log.unverified_nodes, 1);
  assert.equal(forged.world.state.log.status, "attention");
  assert.equal(shownGroups(marked.value).filter((group) => group.verified !== true).length, 1);

  // fields: a body the node signed, under a key the node did not write for it. It is no entry:
  // the screen leaves it out and nothing is marked.
  const moved = vectorFixture("dev");
  const fields = byName("a_key_of_another_seq");
  assert.equal(fields.result, "fields");
  assert.ok(!log.entries.some((entry) => entry.key === fields.key));
  moved.world.putObject(bridge.shardBucket("dev", log.user_id), fields.key, JSON.stringify(fields.entry));
  await S.start(moved);
  const left = await S.call(moved, "read_log", { limit: 100 });
  assert.equal(count(left), events);
  assert.ok(shownGroups(left.value).every((group) => group.verified === true));
  assert.equal(moved.world.state.log.store, "verified");
  assert.equal(moved.world.state.log.unverified_nodes, 0);
});

test("a key the vectors give as no key of format 3 is no entry to the program", { skip: vectors.log_v3 === undefined }, async () => {
  const log = vectors.log_v3;
  assert.equal(log.a_key_of_not_keys_parses, false);
  const fx = vectorFixture("dev");
  const world = fx.world;
  // Every such key under a prefix of this account holds the object of a real entry: a reader
  // that took it for a key would verify the object and count it.
  const listed = log.not_keys.filter((key) => key.startsWith(log.control_prefix) || key.startsWith(log.use_prefix));
  assert.equal(listed.length, 3);
  for (const key of listed) {
    const real = log.entries.find((entry) => key.endsWith(entry.body_hash));
    world.putObject(bridge.shardBucket("dev", log.user_id), key, JSON.stringify(real.entry));
  }
  await S.start(fx);
  const report = world.reports[world.reports.length - 1];
  assert.equal(report.control_keys, log.control_listing.length);
  assert.equal(report.store, "verified");
  const shown = await S.call(fx, "read_log", { limit: 100 });
  const events = log.entries.reduce((sum, entry) => sum + entry.count, 0);
  assert.equal(shownGroups(shown.value).reduce((sum, group) => sum + group.count, 0), events);
  assert.equal(world.state.log.store, "verified");
  // The bodies of those keys were asked of nobody.
  for (const request of world.sent("POST /api/secure/log/bodies")) {
    for (const key of JSON.parse(request.body).keys) assert.ok(listed.indexOf(key) < 0, key);
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

test("a debug build calls the bucket of the local stack the vectors name for an account, in the path-style form, and no other", { skip: vectors.log_store === undefined }, async () => {
  const store = vectors.log_store.stores.find((item) => item.bucket === "character-credential-log-local-1");
  assert.equal(store.shards, 4);
  const empty = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListVersionsResult><IsTruncated>false</IsTruncated></ListVersionsResult>";
  for (const owner of store.owners) {
    for (const bucket of [owner.bucket, store.first_bucket === owner.bucket ? store.last_bucket : store.first_bucket]) {
      // The bridge of a debug build reports the server target prod whatever backend it talks to.
      const fx = S.fixture(source, { target: "prod", nodes: 0, device: { debug_build: true } });
      fx.world.userId = owner.owner;
      fx.world.keychain.clear();
      fx.keys = fx.world.createAccount();
      const local = fx.world.addNode({ release: "v2.4.0", measurement: fx.measurement, platform: "local", log: { bucket: store.bucket, region: store.region } });
      fx.world.fault("POST /api/secure/log/read", (request) => ({
        status: 200, body: {
          pages: JSON.parse(request.body).pages.map((page) => ({
            prefix: page.prefix,
            url: "http://localhost:4566/" + bucket + "?versions&prefix=" +
              encodeURIComponent("a3/" + owner.owner + "/" + page.prefix + "/") + "&max-keys=1000&encoding-type=url",
          })),
        },
      }));
      fx.world.fault("S3 localhost:4566", { status: 200, body: empty });
      await S.start(fx);
      const called = fx.world.sent("S3 localhost:4566").length;
      if (bucket === owner.bucket) {
        assert.equal(called, 1, owner.owner);
        assert.equal(fx.world.state.log.store, "verified", owner.owner);
      } else {
        assert.equal(called, 0, owner.owner);
        assert.equal(fx.world.state.log.store_failure, "read:url", owner.owner);
      }
      assert.equal(local.grants.has(owner.owner), true);
    }
  }
});

test("the node document of the vectors, a document of platform local, is accepted by a build that takes local nodes and by no other", { skip: vectors.log_v3 === undefined }, async () => {
  assert.equal(vectors.log_v3.node_document.accepted, true);
  // dev and alpha take a node of platform local (the custody operator): its document is no
  // attestation, and the program judges nothing by it.
  for (const target of ["dev", "alpha"]) {
    const taken = vectorFixture(target);
    await S.start(taken);
    assert.equal(taken.world.reports.slice(-1)[0].undocumented_nodes, 0, target);
    assert.equal(taken.world.state.log.store, "verified", target);
  }
  // prod takes no node of platform local: the entries of that node id are entries of no node the
  // device accepts, and the read counts as held back.
  const refused = vectorFixture("prod");
  await S.start(refused);
  assert.equal(refused.world.reports.slice(-1)[0].undocumented_nodes, 1);
  assert.equal(refused.world.state.log.store_failure, "documents:rejected");
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
  // The releases before v2.4.0 stay listed (their nodes hold grants while the fleet moves on, and
  // their chains are read for the retention of the store); v2.4.0 follows them once it is listed.
  assert.deepEqual(names.slice(0, 11), [
    "v1.1.0", "v1.2.0", "v1.3.0", "v1.4.0", "v1.5.0", "v1.5.2", "v2.0.0", "v2.0.1", "v2.1.0", "v2.2.0",
    "v2.3.0",
  ]);
  assert.ok(names.length === 11 || (names.length === 12 && names[11] === "v2.4.0"), names.join(" "));
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
  await blocked("an entry of a node whose document the store holds and the backend does not hand out", async (fx) => {
    const hidden = fx.world.addNode({ release: "v2.4.0", measurement: fx.measurement, offered: false });
    hidden.record("c", [{ t: "connection_created", time_ms: fx.world.now, record_id: "r", provider: "slack", scope: "" }]);
    withhold(fx, [hidden.id], "missing");
  }, "documents:missing");
  await blocked("the same, when the backend reports the document as unread", async (fx) => {
    const hidden = fx.world.addNode({ release: "v2.4.0", measurement: fx.measurement, offered: false });
    hidden.record("c", [{ t: "connection_created", time_ms: fx.world.now, record_id: "r", provider: "slack", scope: "" }]);
    withhold(fx, [hidden.id], "unread");
  }, "documents:missing");
  await blocked("an entry of a node whose document does not verify", async (fx) => {
    const broken = fx.world.addNode({ release: "v2.4.0", measurement: fx.measurement, offered: false, brokenSignature: true });
    broken.record("c", [{ t: "connection_created", time_ms: fx.world.now, record_id: "r", provider: "slack", scope: "" }]);
  }, "documents:rejected");
  await blocked("an entry of a node id under whose document key the store holds an object that is no node document", async (fx) => {
    const forged = new bridge.Node(fx.world, { release: "v2.4.0", measurement: fx.measurement, document: false });
    forged.record("c", [{ t: "connection_created", time_ms: fx.world.now, record_id: "r", provider: "slack", scope: "" }]);
    fx.world.putObject(bridge.shardBucket("prod", forged.id), "n3/" + forged.id, "not a node document");
  }, "documents:missing");
  await blocked("the route of the bodies answers that it does not exist, for keys the listing of the store named", async (fx) => {
    fx.nodes[0].record("c", [{ t: "connection_created", time_ms: fx.world.now, record_id: "r", provider: "slack", scope: "" }]);
    fx.world.fault("POST /api/secure/log/bodies", { status: 404, body: { detail: "Not Found" } });
  }, "bodies:Not Found");
  await blocked("the route of the node documents answers that it does not exist, for a node of a key the listing named", async (fx) => {
    const other = fx.world.addNode({ release: "v2.4.0", measurement: fx.measurement, offered: false });
    other.record("c", [{ t: "connection_created", time_ms: fx.world.now, record_id: "r", provider: "slack", scope: "" }]);
    fx.world.fault("POST /api/secure/log/documents", { status: 404, body: { detail: "Not Found" } });
  }, "documents:Not Found");
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

// ---- The node documents: what the backend hands out, and what the store shows ----

test("A3: the control entry of a node whose document the backend withholds is a read held back: the store shows the document, three rounds and three days mark the log, and the document clears it", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  // A node of the accepted measurement that this device handed no grant to: it took the
  // delegation from another node of its measurement, which writes no entry, and then wrote one.
  const hidden = world.addNode({ release: "v2.4.0", measurement: fx.measurement, offered: false });
  const written = hidden.record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r", provider: "slack", scope: "" }]);
  const fault = withhold(fx, [hidden.id], "missing");
  const states = [];
  for (let day = 0; day < 4; day += 1) {
    await nextDay(fx);
    states.push(world.state.log.status + ":" + world.state.log.store + ":" + world.reports.slice(-1)[0].blocked_attempts);
  }
  assert.deepEqual(states, ["pending:blocked:1", "pending:blocked:2", "pending:blocked:3", "attention:blocked:4"]);
  assert.equal(world.state.log.store_failure, "documents:missing");
  assert.equal(world.reports.slice(-1)[0].undocumented_nodes, 1);
  assert.deepEqual(world.securityStatuses.slice(-1)[0].reasons, ["verification_blocked"]);
  // The program asked the store itself whether it holds the document of that node: the listing
  // of the versions under the key of the document, in the bucket of the node id, once per round.
  const listings = documentListings(world);
  assert.equal(listings.length, 4);
  for (const url of listings) {
    assert.equal(url.host, bridge.shardBucket("prod", hidden.id) + ".s3.us-west-2.amazonaws.com");
    assert.equal(url.pathname, "/");
    assert.equal(url.searchParams.get("prefix"), "n3/" + hidden.id);
    assert.equal(url.searchParams.get("max-keys"), "1000");
  }
  // No body was asked for under the key of a node without a judgement, and no judgement of the
  // node is kept.
  assert.ok(askedBodies(world).indexOf(written.key) < 0);
  assert.equal(world.stored("log.nodes")[hidden.id], undefined);
  // The screen shows the entry as not verified.
  const shown = await S.call(fx, "read_log", { limit: 50 });
  assert.deepEqual(shownGroups(shown.value).map((group) => group.kind).sort(), ["grant_renewed", "unverified"]);
  // The backend hands the document out: the node is one of an accepted measurement and its
  // entry verifies.
  fault.times = 0;
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.state.log.store, "verified");
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.equal(world.securityStatuses.slice(-1)[0].status, "ok");
  assert.equal(world.stored("log.withheld"), undefined);
  const after = await S.call(fx, "read_log", { limit: 50 });
  assert.deepEqual(shownGroups(after.value).map((group) => group.kind).sort(), ["connected", "grant_renewed"]);
  assert.ok(shownGroups(after.value).every((group) => group.verified === true));
});

test("A3: a use entry of a node whose document the backend withholds, which only the screen reads, is asked for again by every round and marks the log after three days", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  const hidden = world.addNode({ release: "v2.4.0", measurement: fx.measurement, offered: false });
  world.advance(HOUR_MS);
  const used = hidden.record("u", [S.providerRequest(world.now)]);
  const fault = withhold(fx, [hidden.id], "missing");
  // A round a synchronization starts reads the control entries: it does not find the entry.
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  // The screen reads the use entries: the entry is shown as not verified and its read is held
  // back.
  const shown = await S.call(fx, "read_log", { limit: 50 });
  assert.deepEqual(shownGroups(shown.value).map((group) => group.kind), ["unverified", "grant_renewed"]);
  assert.equal(world.state.log.store, "blocked");
  assert.equal(world.state.log.store_failure, "documents:missing");
  assert.deepEqual(world.stored("log.withheld"), { keys: [used.key], pages: [] });
  // The rounds after it ask for that key again, though they read the control entries only: the
  // count of the rounds held back goes on, and the log is marked after three days.
  const states = [];
  for (let day = 0; day < 3; day += 1) {
    await nextDay(fx);
    states.push(world.state.log.status + ":" + world.state.log.store + ":" + world.reports.slice(-1)[0].blocked_attempts);
  }
  assert.deepEqual(states, ["pending:blocked:2", "pending:blocked:3", "attention:blocked:4"]);
  assert.deepEqual(world.securityStatuses.slice(-1)[0].reasons, ["verification_blocked"]);
  assert.ok(askedBodies(world).indexOf(used.key) < 0);
  // The document is handed out: the round reads the entry, and nothing is kept as held back.
  fault.times = 0;
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.stored("log.withheld"), undefined);
  assert.ok(askedBodies(world).indexOf(used.key) >= 0);
  const after = await S.call(fx, "read_log", { limit: 50 });
  assert.deepEqual(shownGroups(after.value).map((group) => group.kind), ["request", "grant_renewed"]);
});

test("a node whose document the backend hands out is judged without a read of the store, and a document the node registry kept verifies without the nonce of a node document", async () => {
  // The document a node wrote to the store: one request for it, and no listing of the store.
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  const other = world.addNode({ release: "v2.4.0", measurement: fx.measurement, offered: false });
  other.record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r", provider: "slack", scope: "" }]);
  const sent = world.requests.length;
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.reports.slice(-1)[0].undocumented_nodes, 0);
  assert.equal(documentListings(world).length, 0);
  assert.equal(S.requestLines(world, sent).filter((line) => line === "POST /api/secure/log/documents").length, 1);
  assert.equal(world.stored("log.nodes")[other.id].r, "v2.4.0");
  // The next round asks for no document of that node.
  const documents = world.sent("POST /api/secure/log/documents").length;
  other.record("c", [{ t: "connection_removed", time_ms: world.now, record_id: "r", provider: "slack", provider_revoke: false }]);
  await nextDay(fx);
  assert.equal(world.sent("POST /api/secure/log/documents").length, documents);
  assert.equal(world.reports.slice(-1)[0].keys_checked, 1);

  // The backend could not read the object of the store and hands out the attestation document
  // its node registry kept of the node (the nonce is the one of a request of the backend).
  const kept = S.fixture(source);
  await S.start(kept);
  const node = kept.world.addNode({ release: "v2.4.0", measurement: kept.measurement, offered: false });
  node.record("c", [{ t: "connection_created", time_ms: kept.world.now, record_id: "r", provider: "slack", scope: "" }]);
  const origin = { value: "node_registry" };
  documentsAnswer(kept, (answer) => {
    answer.documents = [{ node: node.id, origin: origin.value, document: registryDocument(node) }];
    answer.missing = [];
  });
  await nextDay(kept);
  assert.equal(kept.world.state.log.status, "verified");
  assert.equal(documentListings(kept.world).length, 0);
  // The same document handed out as the object of the store is not the node document of the
  // node: the store holds one, so the read is held back.
  const wrong = S.fixture(source);
  await S.start(wrong);
  const third = wrong.world.addNode({ release: "v2.4.0", measurement: wrong.measurement, offered: false });
  third.record("c", [{ t: "connection_created", time_ms: wrong.world.now, record_id: "r", provider: "slack", scope: "" }]);
  documentsAnswer(wrong, (answer) => {
    answer.documents = [{ node: third.id, origin: "log_store", document: registryDocument(third) }];
    answer.missing = [];
  });
  await nextDay(wrong);
  assert.equal(wrong.world.state.log.store, "blocked");
  assert.equal(wrong.world.state.log.store_failure, "documents:rejected");
});

test("an object under a node id the store holds no node document of is no entry: it marks nothing, holds nothing back, no body is asked for, and the screen leaves it out", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  // Objects under the prefix of the account whose keys name a node id no node has: nothing wrote a
  // node document under that id.
  const ghost = new bridge.Node(world, { release: "v2.4.0", measurement: fx.measurement, document: false });
  world.advance(HOUR_MS);
  const control = ghost.record("c", [{ t: "grant_revoked", time_ms: world.now }]);
  const use = ghost.record("u", [S.providerRequest(world.now)]);
  const reports = [];
  for (let day = 0; day < 5; day += 1) {
    await nextDay(fx);
    const report = world.reports.slice(-1)[0];
    reports.push([report.status, report.store, report.blocked_attempts, report.undocumented_nodes].join(":"));
  }
  // The round that finds the key reads from the store that no document of the node exists and
  // counts the node; the rounds after it have nothing to judge.
  assert.deepEqual(reports, ["verified:verified:0:1", "verified:verified:0:0", "verified:verified:0:0",
    "verified:verified:0:0", "verified:verified:0:0"]);
  assert.equal(documentListings(world).length, 1);
  assert.equal(world.state.log.status, "verified");
  assert.deepEqual(world.securityStatuses.map((told) => told.status), ["ok", "ok", "ok", "ok", "ok", "ok"]);
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.equal(world.stored("log.withheld"), undefined);
  assert.equal(world.stored("log.nodes")[ghost.id], undefined);
  // The screen leaves both objects out, and asks the store again (the judgement is not kept).
  const shown = await S.call(fx, "read_log", { limit: 50 });
  assert.deepEqual(shownGroups(shown.value).map((group) => group.kind), ["grant_renewed"]);
  assert.equal(shown.value.status, "verified");
  assert.equal(documentListings(world).length, 2);
  for (const key of [control.key, use.key]) assert.ok(askedBodies(world).indexOf(key) < 0, key);
  // A delete marker on the key of the node document is no version of it: nobody wrote a document.
  world.putDeleteMarker(bridge.shardBucket("prod", ghost.id), "n3/" + ghost.id);
  world.advance(HOUR_MS);
  const marked = await S.call(fx, "read_log", { limit: 50 });
  assert.deepEqual(shownGroups(marked.value).map((group) => group.kind), ["grant_renewed"]);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.state.log.store, "verified");
});

test("that the store holds no document of a node id is judged for the keys listed before, and again for a key listed later: a node that writes its document then is read as a node", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  // A node of the accepted measurement that has not written its node document yet. An object
  // under its node id is no entry of it: a node writes no entry before its document.
  const late = world.addNode({ release: "v2.4.0", measurement: fx.measurement, offered: false, document: false });
  world.advance(HOUR_MS);
  late.record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r0", provider: "slack", scope: "" }], {
    signSeed: crypto.randomBytes(32),
  });
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.reports.slice(-1)[0].undocumented_nodes, 1);
  // The node writes its document, takes the delegation and writes entries. The keys the store
  // lists now are judged by the document of the node, not by the earlier reading of the store.
  late.writeDocument();
  world.advance(HOUR_MS);
  late.record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r1", provider: "notion", scope: "" }]);
  late.record("u", [S.providerRequest(world.now)]);
  await nextDay(fx);
  assert.equal(world.reports.slice(-1)[0].undocumented_nodes, 0);
  assert.equal(world.reports.slice(-1)[0].keys_checked, 1);
  const shown = await S.call(fx, "read_log", { limit: 50 });
  const groups = shownGroups(shown.value);
  assert.deepEqual(groups.filter((group) => group.verified === true).map((group) => group.kind), ["request", "connected", "grant_renewed"]);
  // The object that was there before the document is one the node did not sign: under a node
  // that passed attestation, it contradicts the node (A2).
  assert.equal(groups.filter((group) => group.verified !== true).length, 1);
  assert.equal(world.state.log.unverified_nodes, 1);
  assert.equal(world.state.log.status, "attention");
});

test("A3: the listing of a node document is read through the address of that listing only: another bucket, another prefix, a marker, another page size, a key given twice or a fragment hold the read back, and so does an answer without the address", async () => {
  const held = async (name, change, expected) => {
    const fx = S.fixture(source);
    await S.start(fx);
    const world = fx.world;
    const hidden = world.addNode({ release: "v2.4.0", measurement: fx.measurement, offered: false });
    hidden.record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r", provider: "slack", scope: "" }]);
    documentsAnswer(fx, (answer) => {
      answer.documents = [];
      answer.missing = [hidden.id];
      change(answer, hidden, world);
    });
    await nextDay(fx);
    assert.equal(world.state.log.store, "blocked", name);
    assert.equal(world.state.log.status, "pending", name);
    assert.equal(world.state.log.store_failure, expected, name);
    assert.equal(world.stored("log.blocked").count, 1, name);
    return world;
  };
  const prefix = (node) => encodeURIComponent("n3/" + node.id);
  // The address of the listing as the backend signs it is called, and the store shows the
  // document the backend did not hand out.
  const called = await held("the address of the listing", () => {}, "documents:missing");
  assert.equal(documentListings(called).length, 1);
  // The address as the SDK of the backend presigns it for a session of temporary credentials
  // (list-object-versions with Prefix and MaxKeys: the SDK writes versions= and adds the encoding).
  const presigned = await held("the address the SDK presigns", (answer, hidden) => {
    answer.listings = [{
      node: hidden.id,
      url: "https://" + bridge.shardBucket("prod", hidden.id) + ".s3.us-west-2.amazonaws.com/?versions=&prefix=n3%2F" + hidden.id +
        "&max-keys=1000&encoding-type=url&X-Amz-Algorithm=AWS4-HMAC-SHA256" +
        "&X-Amz-Credential=AKIAEXAMPLEEXAMPLE00%2F20261123%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20261123T095134Z" +
        "&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Security-Token=example%2Fsession%2Btoken%3D%3D&X-Amz-Signature=00",
    }];
  }, "documents:missing");
  assert.equal(documentListings(presigned).length, 1);
  const uncalled = async (name, rewrite) => {
    const world = await held(name, (answer, hidden, world) => {
      answer.listings = answer.listings.map((item) => ({ node: item.node, url: rewrite(item.url, hidden, world) }));
    }, "documents:url");
    assert.equal(documentListings(world).length, 0, name);
    assert.equal(world.sent("S3 ").filter((request) => request.url.indexOf("n3") >= 0).length, 0, name);
  };
  await uncalled("the bucket of another owner", (url, hidden, world) => {
    // The bucket of the account, or of another owner when the node id falls into that one.
    const own = bridge.shardBucket("prod", hidden.id);
    const others = [world.userId, "owner-1", "owner-2", "owner-3"].map((owner) => bridge.shardBucket("prod", owner));
    return url.replace(own, others.find((bucket) => bucket !== own));
  });
  await uncalled("the bucket the binding names", (url, hidden, world) =>
    url.replace(bridge.shardBucket("prod", hidden.id), world.bucket));
  await uncalled("the prefix of another node id", (url, hidden) =>
    url.replace(prefix(hidden), encodeURIComponent("n3/" + b64u(crypto.randomBytes(32)))));
  await uncalled("a prefix below the key of the document", (url, hidden) =>
    url.replace(prefix(hidden), prefix(hidden) + "%2F"));
  await uncalled("a prefix that is a part of the key of the document", (url, hidden) =>
    url.replace(prefix(hidden), encodeURIComponent("n3/" + hidden.id.slice(0, 42))));
  await uncalled("a key marker", (url, hidden) => url.replace("&max-keys=1000", "&key-marker=" + prefix(hidden) + "&max-keys=1000"));
  await uncalled("a version id marker", (url) => url.replace("&max-keys=1000", "&version-id-marker=v000001&max-keys=1000"));
  await uncalled("a delimiter", (url) => url.replace("&max-keys=1000", "&delimiter=%2F&max-keys=1000"));
  await uncalled("another page size", (url) => url.replace("&max-keys=1000", "&max-keys=1"));
  await uncalled("no page size", (url) => url.replace("&max-keys=1000", ""));
  await uncalled("not a listing of versions", (url) => url.replace("?versions&", "?"));
  await uncalled("another query key", (url) => url + "&list-type=2");
  await uncalled("the prefix given twice, the other one first", (url, hidden) =>
    url.replace("prefix=" + prefix(hidden), "prefix=n3%2Fnone&prefix=" + prefix(hidden)));
  await uncalled("the page size given twice", (url) => url.replace("&max-keys=1000", "&max-keys=1&max-keys=1000"));
  await uncalled("a fragment in front of the query", (url) => url.replace("/?", "/#?"));
  await uncalled("a fragment behind the query", (url) => url + "#x");
  await uncalled("a path", (url) => url.replace("/?", "/n3?"));
  await uncalled("http", (url) => url.replace("https://", "http://"));
  await held("an answer without the addresses", (answer) => { delete answer.listings; }, "documents:url");
  await held("an answer with the address of another node only", (answer, hidden, world) => {
    answer.listings = [{ node: b64u(crypto.randomBytes(32)), url: world.documentUrl(hidden.id) }];
  }, "documents:url");
  // The store refuses the address the backend signed.
  const refused = S.fixture(source);
  await S.start(refused);
  const node = refused.world.addNode({ release: "v2.4.0", measurement: refused.measurement, offered: false });
  node.record("c", [{ t: "connection_created", time_ms: refused.world.now, record_id: "r", provider: "slack", scope: "" }]);
  withhold(refused, [node.id], "missing");
  refused.world.fault(isDocumentListing, { status: 403, body: "" });
  await nextDay(refused);
  assert.equal(refused.world.state.log.store, "blocked");
  assert.equal(refused.world.state.log.store_failure, "document:403");
});

test("the answers Amazon S3 gives for the listing of the versions under a node document key are read as the store states them", async () => {
  // Answers of Amazon S3 (us-west-2, a bucket with versioning, 2026-11-23) to the address a
  // backend presigns for that listing (list-object-versions with the prefix n3/{node} and
  // max-keys 1000; the SDK adds encoding-type url). NODE stands for the node id, and the owner
  // id of the bucket is replaced.
  const head = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListVersionsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" +
    "<Name>bucket</Name><Prefix>n3/NODE</Prefix><KeyMarker></KeyMarker><VersionIdMarker></VersionIdMarker><MaxKeys>1000</MaxKeys>" +
    "<EncodingType>url</EncodingType><IsTruncated>false</IsTruncated>";
  const owner = "<Owner><ID>0000000000000000000000000000000000000000000000000000000000000000</ID></Owner>";
  const version = (key, id, latest) => "<Version><Key>" + key + "</Key><VersionId>" + id + "</VersionId><IsLatest>" + latest +
    "</IsLatest><LastModified>2026-11-23T09:42:52.000Z</LastModified><ETag>&quot;a191475ae2bf7db9c7e320f7da455bbb&quot;</ETag>" +
    "<ChecksumAlgorithm>CRC32</ChecksumAlgorithm><ChecksumType>FULL_OBJECT</ChecksumType><Size>7</Size>" + owner +
    "<StorageClass>STANDARD</StorageClass></Version>";
  const marker = (key, id) => "<DeleteMarker><Key>" + key + "</Key><VersionId>" + id + "</VersionId><IsLatest>true</IsLatest>" +
    "<LastModified>2026-11-23T09:42:52.000Z</LastModified>" + owner + "</DeleteMarker>";
  const tail = "</ListVersionsResult>";
  const answers = [
    // No object under the key.
    { name: "nothing", xml: head + tail, held: false },
    // A delete request on a key nothing was written under.
    { name: "a delete marker alone", xml: head + marker("n3/NODE", ".jMBCIFW4NPrlvTe0fB41Ntu.Sa5VjHN") + tail, held: false },
    // An object of a longer key with the same prefix.
    { name: "a longer key", xml: head + version("n3/NODE/x", "n9ai.N4kxQnakCWEEfdGxye8jDXRliDU", "true") + tail, held: false },
    // Two versions of the object, and an object of a longer key.
    {
      name: "two versions", held: true,
      xml: head + version("n3/NODE", "MnGCFGbDzgSOxfZW8ARFpxfrYY4ZxIHU", "true") + version("n3/NODE", "R4oqorkd1wZcl6VWAFo6hdeKfqKCb4zj", "false") +
        version("n3/NODE.other", "SrHRidnnOpKpjM7bdkTivwv2Ynm5bTZ6", "true") + tail,
    },
    // One version with a delete marker on top of it.
    {
      name: "a version under a delete marker", held: true,
      xml: head + marker("n3/NODE", "ZqNvwFyG7X6L2uI6GQlNNKwkn7mx7RaQ") + version("n3/NODE", "XcHdAe4TXQGDvuIHuFE_BYGVaZxBnTMC", "false") + tail,
    },
  ];
  for (const answer of answers) {
    const fx = S.fixture(source);
    await S.start(fx);
    const ghost = new bridge.Node(fx.world, { release: "v2.4.0", measurement: fx.measurement, document: false });
    ghost.record("c", [{ t: "grant_revoked", time_ms: fx.world.now }]);
    fx.world.fault(isDocumentListing, { status: 200, body: answer.xml.split("NODE").join(ghost.id) });
    await nextDay(fx);
    assert.equal(fx.world.reports.slice(-1)[0].undocumented_nodes, 1, answer.name);
    assert.equal(fx.world.state.log.store, answer.held ? "blocked" : "verified", answer.name);
    assert.equal(fx.world.state.log.store_failure, answer.held ? "documents:missing" : "", answer.name);
    assert.equal(fx.world.state.log.status, answer.held ? "pending" : "verified", answer.name);
  }
});

test("a debug build reads the listing of a node document of the local stack in the path-style form of the bucket of the node id, and in that of no other bucket", async () => {
  const run = async (bucketOf) => {
    // The bridge of a debug build reports the server target prod whatever backend it talks to.
    const fx = S.fixture(source, { target: "prod", nodes: 0, device: { debug_build: true } });
    const world = fx.world;
    world.addNode({ release: "v2.4.0", measurement: fx.measurement, platform: "local", log: { bucket: "character-credential-log-local-1", region: "us-west-2" } });
    const ghost = new bridge.Node(world, { release: "v2.4.0", measurement: fx.measurement, document: false });
    // The stand-in of the local stack: path-style addresses, answered from the objects of the
    // model (the bucket of the account for the entries, the bucket of a node id for a document).
    const standIn = (bucket, prefix) => "http://localhost:4566/" + bucket + "?versions&prefix=" +
      encodeURIComponent(prefix) + "&max-keys=1000&encoding-type=url";
    world.fault("POST /api/secure/log/read", (request) => ({
      status: 200, body: {
        pages: JSON.parse(request.body).pages.map((page) => ({
          prefix: page.prefix, url: standIn(bridge.shardBucket("local", world.userId), "a3/" + world.userId + "/" + page.prefix + "/"),
        })),
      },
    }));
    documentsAnswer(fx, (answer) => {
      answer.listings = answer.listings.map((item) => ({ node: item.node, url: standIn(bucketOf(item.node), "n3/" + item.node) }));
    });
    world.fault("S3 localhost:4566", (request) => {
      const params = new URL(request.url).searchParams;
      const owner = params.get("prefix").startsWith("n3/") ? params.get("prefix").slice(3) : world.userId;
      return { status: 200, body: world.listing(bridge.shardBucket("prod", owner), params) };
    });
    await S.start(fx);
    assert.equal(world.state.log.status, "verified");
    ghost.record("c", [{ t: "grant_revoked", time_ms: world.now }]);
    await nextDay(fx);
    return { world: world, ghost: ghost };
  };
  // The bucket of the node id among the buckets of the local stack: the store holds no document.
  const right = await run((node) => bridge.shardBucket("local", node));
  assert.equal(right.world.state.log.status, "verified");
  assert.equal(right.world.reports.slice(-1)[0].undocumented_nodes, 1);
  const called = right.world.sent("S3 localhost:4566").map((request) => new URL(request.url))
    .filter((url) => url.searchParams.get("prefix") === "n3/" + right.ghost.id);
  assert.deepEqual(called.map((url) => url.pathname), ["/" + bridge.shardBucket("local", right.ghost.id)]);
  // Another bucket of the local stack: the address is not called.
  const wrong = await run((node) => {
    const own = bridge.shardBucket("local", node);
    for (let i = 0; i < 64; i += 1) {
      const other = bridge.shardBucket("local", "owner-" + i);
      if (other !== own) return other;
    }
    return own;
  });
  assert.equal(wrong.world.state.log.store, "blocked");
  assert.equal(wrong.world.state.log.store_failure, "documents:url");
  assert.equal(wrong.world.sent("S3 localhost:4566").filter((request) => request.url.indexOf("n3%2F") >= 0).length, 0);
});

test("a listing of a node document that goes on beyond its page holds the read back, and one the store fails to answer leaves the round pending without a count", async () => {
  // More than a page of versions under the key of the document, none of them one the program
  // can take for a version of the document: the store does not show that it holds none.
  const long = S.fixture(source);
  await S.start(long);
  const ghost = new bridge.Node(long.world, { release: "v2.4.0", measurement: long.measurement, document: false });
  ghost.record("c", [{ t: "grant_revoked", time_ms: long.world.now }]);
  long.world.fault(isDocumentListing, {
    status: 200,
    body: "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListVersionsResult><IsTruncated>true</IsTruncated>" +
      "<NextKeyMarker>n3%2F" + ghost.id + "</NextKeyMarker><NextVersionIdMarker>v1</NextVersionIdMarker></ListVersionsResult>",
  });
  await nextDay(long);
  assert.equal(long.world.state.log.store, "blocked");
  assert.equal(long.world.state.log.store_failure, "documents:missing");
  // A listing that does not say whether it ends is no listing that ends.
  const vague = S.fixture(source);
  await S.start(vague);
  const other = new bridge.Node(vague.world, { release: "v2.4.0", measurement: vague.measurement, document: false });
  other.record("c", [{ t: "grant_revoked", time_ms: vague.world.now }]);
  vague.world.fault(isDocumentListing, { status: 200, body: "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListVersionsResult></ListVersionsResult>" });
  await nextDay(vague);
  assert.equal(vague.world.state.log.store_failure, "documents:missing");
  // The store fails: the round is pending, nothing is counted as held back, and the next round
  // asks again.
  const failing = S.fixture(source);
  await S.start(failing);
  const third = new bridge.Node(failing.world, { release: "v2.4.0", measurement: failing.measurement, document: false });
  third.record("c", [{ t: "grant_revoked", time_ms: failing.world.now }]);
  const fault = failing.world.fault(isDocumentListing, { status: 503, body: "" });
  for (let day = 0; day < 5; day += 1) await nextDay(failing);
  assert.equal(failing.world.state.log.status, "pending");
  assert.equal(failing.world.state.log.store, "unreachable");
  assert.equal(failing.world.state.log.store_failure, "document:503");
  assert.deepEqual(failing.world.stored("log.blocked"), { first_ms: 0, count: 0 });
  fault.times = 0;
  await nextDay(failing);
  assert.equal(failing.world.state.log.status, "verified");
  assert.equal(failing.world.reports.slice(-1)[0].undocumented_nodes, 1);
});

test("a key whose read was held back is asked for before the new keys of a round: more node ids without a document than a round asks for do not take its request", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  const hidden = world.addNode({ release: "v2.4.0", measurement: fx.measurement, offered: false });
  world.advance(HOUR_MS);
  const used = hidden.record("u", [S.providerRequest(world.now)]);
  withhold(fx, [hidden.id], "missing");
  await S.call(fx, "read_log", { limit: 50 });
  assert.deepEqual(world.stored("log.withheld"), { keys: [used.key], pages: [] });
  assert.equal(world.stored("log.blocked").count, 1);
  // 130 objects under 130 node ids no node has, all later than the entry: one round asks for the
  // documents of 128 nodes.
  for (let i = 0; i < 130; i += 1) {
    world.advance(1000);
    new bridge.Node(world, { release: "v2.4.0", measurement: fx.measurement, document: false })
      .record("c", [{ t: "grant_revoked", time_ms: world.now }]);
  }
  await nextDay(fx);
  const asked = world.sent("POST /api/secure/log/documents").slice(-2).map((request) => JSON.parse(request.body).nodes);
  assert.equal(asked[0][0], hidden.id);
  assert.equal(asked[0].length + asked[1].length, 128);
  assert.equal(world.state.log.store, "blocked");
  assert.equal(world.state.log.store_failure, "documents:missing");
  assert.equal(world.stored("log.blocked").count, 2);
  assert.equal(world.reports.slice(-1)[0].undocumented_nodes, 128);
});

test("a later page of the screen that finds a read held back hands the key to the rounds, which count it", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  const hidden = world.addNode({ release: "v2.4.0", measurement: fx.measurement, offered: false });
  world.advance(HOUR_MS);
  const old = hidden.record("u", [S.providerRequest(world.now)]);
  // Eight days later (the entry is outside the days the summary counts): entries of the node of
  // the device, enough to fill the first page of the screen.
  world.advance(8 * DAY_MS);
  for (let i = 0; i < 3; i += 1) {
    world.advance(60000);
    fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
  }
  withhold(fx, [hidden.id], "missing");
  const first = await S.call(fx, "read_log", { limit: 3 });
  assert.equal(first.value.has_more, true);
  assert.equal(world.state.log.store, "verified");
  assert.equal(world.stored("log.withheld"), undefined);
  const before = world.runtime.log_pages[0].before_ms;
  const page = await S.call(fx, "read_log_page", { before_ms: before });
  assert.equal(page.ok, true);
  assert.ok(shownGroups(page.value).some((group) => group.kind === "unverified"));
  assert.deepEqual(world.stored("log.withheld"), { keys: [old.key], pages: [] });
  // The next synchronization runs a round for that key, though the last round completed.
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.store, "blocked");
  assert.equal(world.state.log.store_failure, "documents:missing");
  assert.equal(world.stored("log.blocked").count, 1);
});

test("A3: a listing only the screen reads that is held back is read again by every round: the listing of the use entries, and the listings of a later page", async () => {
  // The backend gives the address of another prefix for the listing of the use entries, and the
  // right one for the listing of the control entries.
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  world.advance(HOUR_MS);
  fx.nodes[0].record("u", [S.providerRequest(world.now)]);
  const elsewhere = world.fault("POST /api/secure/log/read", (request) => ({
    status: 200, body: {
      pages: JSON.parse(request.body).pages.map((page) => ({
        prefix: page.prefix,
        url: page.prefix === "c" ? world.readUrl(page)
          : world.readUrl(page).replace(encodeURIComponent("a3/" + world.userId + "/u/"), encodeURIComponent("a3/" + world.userId + "/x/")),
      })),
    },
  }));
  // A round of a synchronization reads the control listing alone: nothing is held back.
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  // The screen reads both listings: its read is held back, and the screen shows no entry of
  // format 3 (it kept none).
  const shown = await S.call(fx, "read_log", { limit: 50 });
  assert.equal(shown.value.status, "pending");
  assert.deepEqual(shownGroups(shown.value), []);
  assert.equal(world.state.log.store, "blocked");
  assert.equal(world.state.log.store_failure, "read:url");
  assert.deepEqual(world.stored("log.withheld"), { keys: [], pages: [0] });
  // Every round after it asks for the two listings as the screen does.
  const states = [];
  for (let day = 0; day < 3; day += 1) {
    await nextDay(fx);
    states.push(world.state.log.status + ":" + world.state.log.store + ":" + world.reports.slice(-1)[0].blocked_attempts);
    const asked = JSON.parse(world.sent("POST /api/secure/log/read").slice(-1)[0].body).pages;
    assert.deepEqual(asked.map((page) => page.prefix + ":" + page.key_marker), ["c:", "u:"]);
  }
  assert.deepEqual(states, ["pending:blocked:2", "pending:blocked:3", "attention:blocked:4"]);
  assert.deepEqual(world.securityStatuses.slice(-1)[0].reasons, ["verification_blocked"]);
  elsewhere.times = 0;
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.stored("log.withheld"), undefined);
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });

  // An environment without a store of format 3, on a device that knows of none: a read of the
  // screen that failed once is made again, and the statement that there is no such store ends it.
  const closed = S.fixture(source, { nodes: 0, legacy: 1 });
  closed.world.routes.log = "disabled";
  await S.start(closed);
  closed.world.fault("POST /api/secure/log/read", { status: 503, body: { detail: "log_store_unreachable" } }, 1);
  await S.call(closed, "read_log", { limit: 50 });
  assert.deepEqual(closed.world.stored("log.withheld"), { keys: [], pages: [0] });
  for (let day = 0; day < 4; day += 1) {
    await nextDay(closed);
    assert.equal(closed.world.state.log.status, "verified", "day " + day);
  }
  assert.equal(closed.world.stored("log.withheld"), undefined);
  assert.deepEqual(closed.world.stored("log.blocked"), { first_ms: 0, count: 0 });

  // A later page: the backend answers the request for the listings below a time with an error,
  // and then with the statement that it has no store of format 3.
  for (const answer of [{ status: 503, body: { detail: "log_store_unreachable" } }, { status: 409, body: { detail: "log_store_disabled" } }]) {
    const later = S.fixture(source);
    await S.start(later);
    for (let i = 0; i < 4; i += 1) {
      later.world.advance(60000);
      later.nodes[0].record("u", [S.providerRequest(later.world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
    }
    const first = await S.call(later, "read_log", { limit: 2 });
    assert.equal(first.value.has_more, true);
    const before = later.world.runtime.log_pages[0].before_ms;
    later.world.fault("POST /api/secure/log/read", (request) =>
      (JSON.parse(request.body).pages.some((page) => page.key_marker !== "") ? answer : undefined));
    const page = await S.call(later, "read_log_page", { before_ms: before });
    assert.deepEqual(page, { ok: false, code: "log_store_unreachable" });
    assert.deepEqual(later.world.stored("log.withheld"), { keys: [], pages: [before] });
    later.world.advance(2 * 60000);
    await S.event(later, "foreground");
    assert.equal(later.world.state.log.store, "blocked", JSON.stringify(answer));
    assert.equal(later.world.stored("log.blocked").count, 1);
    later.world.clearFaults();
    later.world.advance(2 * 60000);
    await S.event(later, "foreground");
    assert.equal(later.world.state.log.status, "verified");
    assert.equal(later.world.stored("log.withheld"), undefined);
  }
});

test("an address of the store that gives a query key twice, or carries a fragment, is not called: the listing of format 3 and the listing of a chain of format 2", async () => {
  // The listing of the entries of format 3: the prefix of the account stands last, another first.
  const twice = S.fixture(source);
  await S.start(twice);
  const own = (world, letter) => "prefix=" + encodeURIComponent("a3/" + world.userId + "/" + letter + "/");
  const reread = (fx, rewrite) => fx.world.fault("POST /api/secure/log/read", (request) => ({
    status: 200, body: {
      pages: JSON.parse(request.body).pages.map((page) => ({
        prefix: page.prefix, url: rewrite(fx.world.readUrl(page), page.prefix),
      })),
    },
  }));
  reread(twice, (url, letter) => url.replace(own(twice.world, letter), "prefix=a3%2Fnone%2F&" + own(twice.world, letter)));
  let calls = twice.world.sent("S3 ").length;
  await nextDay(twice);
  assert.equal(twice.world.state.log.store, "blocked");
  assert.equal(twice.world.state.log.store_failure, "read:url");
  assert.equal(twice.world.sent("S3 ").length, calls);
  for (const rewrite of [(url) => url.replace("/?", "/#?"), (url) => url + "#", (url) => url.replace("&max-keys=1000", "&max-keys=1000&max-keys=1000")]) {
    const fx = S.fixture(source);
    await S.start(fx);
    reread(fx, rewrite);
    calls = fx.world.sent("S3 ").length;
    await nextDay(fx);
    assert.equal(fx.world.state.log.store_failure, "read:url");
    assert.equal(fx.world.sent("S3 ").length, calls);
  }
  // The listing of a chain of format 2.
  const chain = S.fixture(source, { nodes: 0, legacy: 1 });
  chain.world.routes.log = "disabled";
  await S.start(chain);
  assert.equal(chain.world.state.log.status, "verified");
  chain.world.fault("POST /api/secure/log/store/listings", (request) => {
    const answer = JSON.parse(chain.world.api("POST", "/api/secure/log/store/listings", null, request.body).body);
    for (const item of answer.nodes) {
      item.list_url = item.list_url.replace("versions&prefix=", "versions&prefix=v1%2Faccounts%2Fnone%2F&prefix=");
    }
    return { status: 200, body: answer };
  });
  calls = chain.world.sent("S3 ").length;
  await nextDay(chain);
  assert.equal(chain.world.state.log.store, "blocked");
  assert.equal(chain.world.state.log.store_failure, "listings:url");
  assert.equal(chain.world.sent("S3 ").length, calls);
});

test("the bridge is asked for the device as often for a listing of many keys as for one of few: the user_id of the account is read once in a runtime", async () => {
  const calls = async (entries) => {
    const fx = S.fixture(source);
    await S.start(fx);
    const world = fx.world;
    for (let i = 0; i < entries; i += 1) {
      world.advance(1000);
      fx.nodes[0].record("u", [S.providerRequest(world.now)]);
    }
    const before = world.deviceInfoCalls;
    const shown = await S.call(fx, "read_log", { limit: 50 });
    assert.equal(shown.ok, true);
    assert.equal(shown.value.status, "verified");
    await world.settle(60000);
    return world.deviceInfoCalls - before;
  };
  const few = await calls(3);
  const many = await calls(300);
  assert.equal(many, few);
  assert.ok(few < 40, String(few));
});

// ---- A transfer of the delegation a node of an earlier release made ----

// 2026-11-23T00:00:00Z (LEGACY_TRANSFER_DOCUMENTS_FROM_MS).
const TRANSFER_DOCUMENTS_FROM_MS = Date.UTC(2026, 10, 23);

test("a transfer a node of an earlier release made to a node the backend hands out no document for: before 2026-11-23 the receiving node is followed as a node of that release, from then on the read is held back until a document verifies", async () => {
  const fx = S.fixture(source, { nodes: 0, legacy: 1, device: { securityStatus: true } });
  const world = fx.world;
  world.now = TRANSFER_DOCUMENTS_FROM_MS - 3 * DAY_MS;
  await S.start(fx);
  const giver = fx.legacy[0];
  const earlier = world.addNode({ release: fx.latest.release, measurement: fx.latest, offered: false });
  const last = world.addNode({ release: fx.latest.release, measurement: fx.latest, offered: false });
  const first = world.addNode({ release: fx.latest.release, measurement: fx.latest, offered: false });
  // A transfer three days before that time, and one in the last millisecond before it.
  giver.record("c", [{ t: "grant_transferred_out", time_ms: world.now, to: earlier.id }]);
  world.now = TRANSFER_DOCUMENTS_FROM_MS - 1;
  giver.record("c", [{ t: "grant_transferred_out", time_ms: world.now, to: last.id }]);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "verified");
  assert.deepEqual(Object.keys(world.stored("log.legacy").nodes).sort(), [giver.id, earlier.id, last.id].sort());
  assert.deepEqual(world.stored("log.legacy").waiting, {});
  // The first millisecond of that time: the backend keeps the document of every node that takes
  // a transfer from then on, and hands none out for this one.
  world.now = TRANSFER_DOCUMENTS_FROM_MS;
  giver.record("c", [{ t: "grant_transferred_out", time_ms: world.now, to: first.id }]);
  const states = [];
  for (let day = 0; day < 4; day += 1) {
    await nextDay(fx);
    states.push(world.state.log.status + ":" + world.state.log.store + ":" + world.reports.slice(-1)[0].blocked_attempts);
  }
  assert.deepEqual(states, ["pending:blocked:1", "pending:blocked:2", "pending:blocked:3", "attention:blocked:4"]);
  assert.equal(world.state.log.store_failure, "receiver:missing");
  assert.deepEqual(world.securityStatuses.slice(-1)[0].reasons, ["verification_blocked"]);
  // The node waits and its chain is not followed. The store is not asked whether it holds a node
  // document of it: a node of such a release wrote none.
  assert.deepEqual(Object.keys(world.stored("log.legacy").waiting), [first.id]);
  assert.equal(world.stored("log.legacy").nodes[first.id], undefined);
  assert.equal(documentListings(world).length, 0);
  // A document that answered a request of the backend, handed out as the object of the store: its
  // nonce is not the one of a node document.
  world.keptDocuments.set(first.id, registryDocument(first));
  const fault = documentsAnswer(fx, (answer) => {
    for (const item of answer.documents) item.origin = "log_store";
  });
  await nextDay(fx);
  assert.equal(world.state.log.store_failure, "receiver:rejected");
  // The same document, handed out as what the node registry kept: the node is one of a release
  // the program accepts, and its chain is followed.
  fault.times = 0;
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.state.log.store, "verified");
  assert.deepEqual(world.stored("log.legacy").waiting, {});
  assert.equal(world.stored("log.legacy").nodes[first.id].closed, false);
  assert.equal(world.stored("log.nodes")[first.id].r, fx.latest.release);
});

test("a transfer a node of an earlier release made on or after 2026-11-23 to a node whose document states a measurement no list has marks the log (A1), and a backend that holds the store of format 3 closed, or has no route of the node documents, judges the receiving node no other way", async () => {
  // The backend hands out the document it kept: the receiving node is of a measurement no list
  // of the program has.
  const moved = S.fixture(source, { nodes: 0, legacy: 1 });
  moved.world.now = TRANSFER_DOCUMENTS_FROM_MS + DAY_MS;
  await S.start(moved);
  const rogue = moved.world.addNode({ release: "v2.3.9", measurement: bridge.randomMeasurement(), format: 2, offered: false });
  moved.world.keptDocuments.set(rogue.id, registryDocument(rogue));
  moved.legacy[0].record("c", [{ t: "grant_transferred_out", time_ms: moved.world.now, to: rogue.id }]);
  await nextDay(moved);
  assert.equal(moved.world.state.log.status, "pending");
  assert.equal(moved.world.state.log.newer_release_nodes, 1);
  await nextDay(moved);
  assert.equal(moved.world.state.log.status, "attention");
  assert.equal(moved.world.state.log.unknown_nodes, 1);
  // A backend that holds the store of format 3 closed, on a device that knows of no such store:
  // the route of the node documents answers all the same, with what the node registry kept. The
  // receiving node is judged by that document, as in any other environment.
  const closed = S.fixture(source, { nodes: 0, legacy: 1 });
  closed.world.now = TRANSFER_DOCUMENTS_FROM_MS + DAY_MS;
  closed.world.routes.log = "disabled";
  await S.start(closed);
  const receiver = closed.world.addNode({ release: closed.latest.release, measurement: closed.latest, offered: false });
  closed.world.keptDocuments.set(receiver.id, registryDocument(receiver));
  closed.legacy[0].record("c", [{ t: "grant_transferred_out", time_ms: closed.world.now, to: receiver.id }]);
  for (let day = 0; day < 4; day += 1) {
    await nextDay(closed);
    assert.equal(closed.world.state.log.status, "verified", "day " + day);
  }
  assert.deepEqual(Object.keys(closed.world.stored("log.legacy").nodes).sort(), [closed.legacy[0].id, receiver.id].sort());
  assert.equal(closed.world.stored("log.nodes")[receiver.id].r, closed.latest.release);
  assert.deepEqual(closed.world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.equal(documentListings(closed.world).length, 0);
  // The same backend, and a receiving node of a measurement no list has: A1, as above.
  const unlisted = S.fixture(source, { nodes: 0, legacy: 1 });
  unlisted.world.now = TRANSFER_DOCUMENTS_FROM_MS + DAY_MS;
  unlisted.world.routes.log = "disabled";
  await S.start(unlisted);
  const other = unlisted.world.addNode({ release: "v2.3.9", measurement: bridge.randomMeasurement(), format: 2, offered: false });
  unlisted.world.keptDocuments.set(other.id, registryDocument(other));
  unlisted.legacy[0].record("c", [{ t: "grant_transferred_out", time_ms: unlisted.world.now, to: other.id }]);
  await nextDay(unlisted);
  await nextDay(unlisted);
  assert.equal(unlisted.world.state.log.status, "attention");
  assert.equal(unlisted.world.state.log.unknown_nodes, 1);
  // The same backend hands out no document for the receiving node, and a backend answers that
  // it has no route of the node documents: the device knows of no store of format 3 in either
  // case, and the read is held back all the same. Nothing but a document that verifies says of
  // which release the receiving node is.
  for (const [routes, failure] of [["disabled", "receiver:missing"], ["absent", "documents:Not Found"]]) {
    const held = S.fixture(source, { nodes: 0, legacy: 1 });
    held.world.now = TRANSFER_DOCUMENTS_FROM_MS + DAY_MS;
    held.world.routes.log = routes;
    await S.start(held);
    const hidden = held.world.addNode({ release: held.latest.release, measurement: held.latest, offered: false });
    held.legacy[0].record("c", [{ t: "grant_transferred_out", time_ms: held.world.now, to: hidden.id }]);
    const states = [];
    for (let day = 0; day < 4; day += 1) {
      await nextDay(held);
      states.push(held.world.state.log.status + ":" + held.world.state.log.store + ":" + held.world.reports.slice(-1)[0].blocked_attempts);
    }
    assert.deepEqual(states, ["pending:blocked:1", "pending:blocked:2", "pending:blocked:3", "attention:blocked:4"], routes);
    assert.equal(held.world.state.log.store_failure, failure, routes);
    assert.deepEqual(Object.keys(held.world.stored("log.legacy").waiting), [hidden.id], routes);
    assert.equal(held.world.stored("log.legacy").nodes[hidden.id], undefined, routes);
  }
  // A device that reads such a transfer when its event is older than the retention of the store:
  // the backend keeps the document of a node no longer than that, so nothing is held back.
  const aged = S.fixture(source, { nodes: 0, legacy: 1 });
  aged.world.now = TRANSFER_DOCUMENTS_FROM_MS;
  await S.start(aged);
  const gone = aged.world.addNode({ release: aged.latest.release, measurement: aged.latest, offered: false });
  aged.legacy[0].record("c", [{ t: "grant_transferred_out", time_ms: aged.world.now, to: gone.id }]);
  aged.world.advance(366 * DAY_MS);
  await S.event(aged, "foreground");
  assert.equal(aged.world.state.log.status, "verified");
  assert.deepEqual(aged.world.stored("log.legacy").waiting, {});
  assert.notEqual(aged.world.stored("log.legacy").nodes[gone.id], undefined);
});

test("what does not mark the log: an empty seq, a node that ended without a shutdown, an entry of another key", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  const node = fx.nodes[0];
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
  assert.equal(world.reports.slice(-1)[0].undocumented_nodes, 0);
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

// ---- The lines, the locks and the time limits ----

/** A web session of a fixture: the user completes the authorization after ms and the session
 *  returns the callback of the connection. */
function webSession(fx, ms) {
  return (args) => fx.world.sleep(ms).then(() => {
    const nodeState = new URL(args.url).searchParams.get("state").split(".")[0];
    fx.world.connections.get(nodeState).completed = true;
    return "pickle://oauth?oauth_status=connected&oauth_state=" + nodeState;
  });
}

/** The outcome of a call of a procedure as a value. */
function outcomeOf(promise) {
  return promise.then(
    (value) => ({ ok: true, value: value === undefined ? undefined : JSON.parse(JSON.stringify(value)) }),
    (error) => ({ ok: false, code: error && error.code ? error.code : String(error) }));
}

test("the time a user spends in a web session ends no wait: the connection completes, the procedure behind it runs after it, and neither is counted as slow", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  world.device.webAuth = webSession(fx, 10 * 60000);
  const began = world.now;
  const results = await world.run(Promise.all([
    outcomeOf(fx.program.procedures.connect({ target: "google_workspace" })),
    outcomeOf(fx.program.procedures.store_login({ name: "", username: "user" })),
  ]));
  assert.deepEqual(results[0], { ok: true, value: { connection_id: "connection-1", provider: "google_workspace", reward: 0 } });
  assert.equal(results[1].ok, true);
  assert.ok(world.now - began >= 10 * 60000);
  // The calls took ten minutes of the clock and next to nothing of their counted time.
  await world.settle(10000);
  assert.equal(world.outcomeReports.length, 0);
  const kept = world.stored("outcomes");
  assert.equal(kept.done.connect.calls, 1);
  assert.equal(kept.done.connect.failed, 0);
  assert.ok(kept.done.connect.max_ms < 1000);
  assert.ok(kept.done.store_login.wait_ms < 1000);
});

test("a request that is not answered fails with timeout at its limit, and the line and the lock go on to the next piece of work", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  world.advance(2 * HOUR_MS);
  // The account query of a synchronization is never answered: the synchronization holds the lock
  // of the grants until the limit of the request, then fails; the connection that waited for the
  // lock goes on.
  world.fault("GET /api/secure/account", "hang", 1);
  world.device.webAuth = webSession(fx, 1000);
  const began = world.now;
  const sync = outcomeOf(fx.program.procedures.sync({}));
  const connect = outcomeOf(fx.program.procedures.connect({ target: "google_workspace" }));
  const results = await world.run(Promise.all([sync, connect]));
  assert.deepEqual(results[0], { ok: false, code: "timeout" });
  assert.equal(results[1].ok, true);
  assert.ok(world.now - began >= 30000 && world.now - began < 40000, String(world.now - began));
  assert.equal(world.state.error, "timeout");
  // The next synchronization clears the failure.
  world.advance(HOUR_MS);
  await S.event(fx, "foreground");
  assert.equal(world.state.error, undefined);
});

test("the three lines do not wait for one another: while the read of the log screen hangs, a procedure of the user and a synchronization end", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  world.advance(2 * HOUR_MS);
  world.fault("S3 ", "hang");
  const began = world.now;
  // read_log answers from what the device kept after its wait, and its read of the store goes on.
  const shown = await world.run(outcomeOf(fx.program.procedures.read_log({ limit: 50 })));
  assert.equal(shown.ok, true);
  assert.equal(shown.value.cached, true);
  assert.equal(shown.value.status, "pending");
  assert.ok(world.now - began <= 3500);
  const stored = await world.run(outcomeOf(fx.program.procedures.store_login({ name: "", username: "user" })));
  assert.equal(stored.ok, true);
  const synced = await world.run(outcomeOf(fx.program.procedures.sync({})));
  assert.equal(synced.ok, true);
  assert.ok(world.now - began <= 4000, String(world.now - began));
  // A second page of the screen waits for the line of the screen, and for nothing else.
  const page = outcomeOf(fx.program.procedures.read_log_page({ before_ms: world.now }));
  const again = await world.run(outcomeOf(fx.program.procedures.store_login({ name: "", username: "user" })));
  assert.equal(again.ok, true);
  world.clearFaults();
  await world.run(page);
});

test("a synchronization that waits serves the triggers that arrive while it waits, and the synchronization that runs serves an event of the app that arrives right after its start", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  world.advance(2 * HOUR_MS);
  const before = world.sent("GET /api/secure/account").length;
  world.fault("GET /api/secure/account", { delay_ms: 8000 }, 1);
  const first = fx.program.onEvent("foreground", {});
  const same = fx.program.onEvent("foreground", {});
  await world.settle(6000);
  // Six seconds later the running one is no longer fresh: one more is put on the line, and the
  // triggers after it join that one.
  const second = fx.program.onEvent("push", { reason: "refresh" });
  const third = fx.program.onEvent("push", { reason: "grant_required" });
  const fourth = fx.program.procedures.sync({});
  await world.run(Promise.all([first, same, second, third, fourth]));
  await world.settle(0);
  assert.equal(world.sent("GET /api/secure/account").length, before + 2);
  assert.deepEqual(world.syncReports.map((report) => report.reason), ["refresh", "grant_required"]);
});

// ---- The outcomes of the procedures ----

test("a procedure that failed is reported with its code and its times five seconds later, and what the backend accepted leaves the device", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  world.fault("PUT /api/secure/vault/login", { status: 503, body: { detail: "unavailable" }, delay_ms: 1200 }, 1);
  const failed = await S.call(fx, "store_login", { name: "", username: "user" });
  assert.deepEqual(failed, { ok: false, code: "unavailable" });
  const fine = await S.call(fx, "store_login", { name: "", username: "user" });
  assert.equal(fine.ok, true);
  assert.equal(world.outcomeReports.length, 0);
  await world.settle(5000);
  assert.equal(world.outcomeReports.length, 1);
  const report = world.outcomeReports[0];
  assert.equal(report.program_version, 43);
  assert.deepEqual(report.bounds_ms, [250, 1000, 3000, 10000, 30000]);
  assert.ok(report.since_ms <= report.until_ms);
  const done = report.done.find((item) => item.name === "store_login");
  assert.equal(done.calls, 2);
  assert.equal(done.failed, 1);
  assert.deepEqual(done.classes, [1, 0, 1, 0, 0, 0]);
  assert.ok(done.max_ms >= 1200 && done.total_ms >= 1200);
  assert.equal(report.events.length, 1);
  assert.deepEqual(Object.keys(report.events[0]).sort(), ["at_ms", "code", "name", "total_ms", "wait_ms"]);
  assert.equal(report.events[0].name, "store_login");
  assert.equal(report.events[0].code, "unavailable");
  assert.deepEqual(report.interrupted, []);
  assert.equal(report.dropped, 0);
  // The synchronization of the start of the runtime is counted under the name of an event.
  assert.ok(report.done.some((item) => item.name === "event_sync" && item.failed === 0));
  // Nothing of the arguments of a call is in a report.
  assert.ok(JSON.stringify(report).indexOf("user") < 0);
  const kept = world.stored("outcomes");
  assert.deepEqual(kept.done, {});
  assert.deepEqual(kept.events, []);
});

test("a call the user closed is not counted as failed, and a call cut off with its runtime is reported as interrupted by the next runtime", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  world.device.webAuth = () => null;
  const closed = await S.call(fx, "connect", { target: "google_workspace" });
  assert.deepEqual(closed, { ok: false, code: "cancelled" });
  await world.settle(6000);
  assert.equal(world.outcomeReports.length, 0);
  assert.equal(world.stored("outcomes").done.connect.failed, 0);
  // A call that never ends: the app goes to the background and its process is ended.
  world.fault("PUT /api/secure/vault/login", "hang");
  const called = world.now;
  fx.program.procedures.store_login({ name: "", username: "user" }).then(() => {}, () => {});
  await world.settle(2000);
  fx.program.onEvent("background", {});
  const gone = world.now;
  world.clearFaults();
  world.advance(HOUR_MS);
  await S.start(fx);
  await world.settle(6000);
  const report = world.outcomeReports.slice(-1)[0];
  assert.deepEqual(report.interrupted, [{ name: "store_login", called_ms: called, found_ms: called + 2000 + HOUR_MS, background_ms: gone }]);
  assert.deepEqual(world.stored("outcomes").interrupted, []);
});

test("a backend without the route of the outcomes is asked once in a runtime", async () => {
  const fx = S.fixture(source);
  fx.world.routes.outcomes = false;
  await S.start(fx);
  const world = fx.world;
  world.fault("PUT /api/secure/vault/login", { status: 503, body: { detail: "unavailable" } });
  for (let turn = 0; turn < 3; turn += 1) {
    await S.call(fx, "store_login", { name: "", username: "user" });
    await world.settle(6000);
  }
  assert.equal(world.sent("POST /api/secure/procedures/outcomes").length, 1);
});

// ---- The vault secrets ----

/** Whether a value occurs in anything the program sent, published, kept or logged. */
function leaked(world, value) {
  const sent = world.requests.some((request) => JSON.stringify(request).indexOf(value) >= 0);
  const published = JSON.stringify([world.state, world.runtime]).indexOf(value) >= 0;
  const kept = Array.from(world.store.values()).some((text) => text.indexOf(value) >= 0);
  return sent || published || kept || world.logs.some((line) => line.indexOf(value) >= 0);
}

test("store_secret seals the value with the name and the reach the backend gave into a record of kind vault_secret, padded to a step, and the value is in no request", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  assert.equal(world.runtime.protected_sheets, false);
  const value = "sk-live-0123456789abcdefghij";
  const stored = await S.call(fx, "store_secret", {
    label: "OpenAI API key", sites: ["api.openai.com"], slots: "header:authorization", value: value,
  });
  assert.deepEqual(stored, { ok: true, value: { name: "SECRET_1", state: "ready" } });
  const item = world.vault.secrets.get("SECRET_1");
  assert.deepEqual(Object.keys(item.record).sort(), ["ct", "custody", "id", "key_id", "kind", "nonce", "provider", "user_id", "v"]);
  assert.equal(item.record.kind, "vault_secret");
  assert.equal(item.record.provider, "vault");
  assert.equal(item.record.custody, "enclave");
  const plain = openRecord(fx.keys, item.record);
  assert.deepEqual(Object.keys(plain.json), ["value", "name", "sites", "slots", "source", "pad"]);
  assert.deepEqual(
    { value: plain.json.value, name: plain.json.name, sites: plain.json.sites, slots: plain.json.slots, source: plain.json.source },
    { value: value, name: "SECRET_1", sites: ["api.openai.com"], slots: ["header:authorization"], source: "device" });
  assert.ok(/^\.*$/.test(plain.json.pad));
  assert.equal(plain.bytes.length, 256);
  assert.equal(leaked(world, value), false);
  // A longer value takes the next step, and one beyond the last step is refused before any request.
  const long = await S.call(fx, "store_secret", { name: "SECRET_1", value: "x".repeat(300) });
  assert.equal(long.ok, true);
  assert.equal(openRecord(fx.keys, world.vault.secrets.get("SECRET_1").record).bytes.length, 512);
  const before = world.sent("PUT /api/secure/vault/secret").length;
  assert.deepEqual(await S.call(fx, "store_secret", { name: "SECRET_1", value: "x".repeat(12300) }), { ok: false, code: "too_large" });
  assert.deepEqual(await S.call(fx, "store_secret", { name: "SECRET_1", value: "" }), { ok: false, code: "invalid_input" });
  assert.equal(world.sent("PUT /api/secure/vault/secret").length, before);
  // A reach of another form that the backend gives is refused: nothing is sealed under it.
  world.vault.secrets.get("SECRET_1").slots = ["field", "path"];
  assert.deepEqual(await S.call(fx, "store_secret", { name: "SECRET_1", value: value }), { ok: false, code: "invalid_response" });
});

test("in a build with the protected sheets the value comes from the input sheet and goes to the display sheet, with the lines of the reach that is sealed", async () => {
  const fx = S.fixture(source, { device: { sheets: true, locale: "en-US" } });
  await S.start(fx);
  const world = fx.world;
  assert.equal(world.runtime.protected_sheets, true);
  const value = "4821";
  world.device.promptAnswer = value;
  world.vault.secrets.set("COUPAY_PIN", {
    name: "COUPAY_PIN", label: "Coupay PIN", sites: ["coupang.com"], slots: ["field"], state: "empty", source: "",
  });
  // The argument value of a definition is not what is sealed.
  const stored = await S.call(fx, "store_secret", { name: "COUPAY_PIN", value: "from-the-definition" });
  assert.deepEqual(stored, { ok: true, value: { name: "COUPAY_PIN", state: "ready" } });
  assert.deepEqual(world.device.prompts, [{ title: "Coupay PIN", destinations: ["coupang.com and the hosts below it · typed into its pages"] }]);
  const plain = openRecord(fx.keys, world.vault.secrets.get("COUPAY_PIN").record).json;
  assert.equal(plain.value, value);
  assert.deepEqual(plain.sites, ["coupang.com"]);
  assert.deepEqual(plain.slots, ["field"]);
  // The display: the device owner is asked before the query, and the result carries no value.
  const queries = world.sent("GET /api/secure/vault/secret/COUPAY_PIN").length;
  world.device.ownerAuth = false;
  assert.deepEqual(await S.call(fx, "reveal_secret", { name: "COUPAY_PIN" }), { ok: false, code: "auth_failed" });
  assert.equal(world.sent("GET /api/secure/vault/secret/COUPAY_PIN").length, queries);
  world.device.ownerAuth = true;
  const shown = await S.call(fx, "reveal_secret", { name: "COUPAY_PIN" });
  assert.deepEqual(shown, { ok: true, value: { name: "COUPAY_PIN" } });
  assert.deepEqual(world.device.presented, [{
    title: "Coupay PIN", value: value, destinations: ["coupang.com and the hosts below it · typed into its pages"],
  }]);
  // A sheet the user closed stores nothing and is not a failure of the procedure.
  world.device.promptAnswer = null;
  const puts = world.sent("PUT /api/secure/vault/secret").length;
  assert.deepEqual(await S.call(fx, "store_secret", { name: "COUPAY_PIN" }), { ok: false, code: "cancelled" });
  assert.equal(world.sent("PUT /api/secure/vault/secret").length, puts);
});

test("reveal_secret opens a record of kind vault_secret of the name asked for and no other, update_secret seals the value again under the same id with the new reach, and delete_secret asks the device owner first", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  const value = "sk-live-0123456789abcdefghij";
  await S.call(fx, "store_secret", { label: "key", sites: ["api.openai.com"], slots: ["header:authorization"], value: value });
  const shown = await S.call(fx, "reveal_secret", { name: "SECRET_1" });
  assert.deepEqual(shown, {
    ok: true, value: { name: "SECRET_1", value: value, sites: ["api.openai.com"], slots: ["header:authorization"], source: "device" },
  });
  assert.equal(world.device.ownerAuths.length, 1);
  // A record whose plaintext names another name, and a record of another kind, are not shown.
  const item = world.vault.secrets.get("SECRET_1");
  world.vault.secrets.set("OTHER", Object.assign({}, item, { name: "OTHER" }));
  assert.deepEqual(await S.call(fx, "reveal_secret", { name: "OTHER" }), { ok: false, code: "record_invalid" });
  world.vault.secrets.set("LOGIN", Object.assign({}, item, { name: "LOGIN", record: makeRecord(fx, "vault_password", { value: "typed-by-the-user" }) }));
  assert.deepEqual(await S.call(fx, "reveal_secret", { name: "LOGIN" }), { ok: false, code: "record_invalid" });
  // The reach changes: the same id, the new reach in the plaintext, the source as it was.
  const id = item.record.id;
  const changed = await S.call(fx, "update_secret", { name: "SECRET_1", sites: "api.openai.com,files.openai.com", slots: "header:authorization" });
  assert.deepEqual(changed, { ok: true, value: { name: "SECRET_1", sites: ["api.openai.com", "files.openai.com"], slots: ["header:authorization"] } });
  const sealed = world.vault.secrets.get("SECRET_1").record;
  assert.equal(sealed.id, id);
  const plain = openRecord(fx.keys, sealed).json;
  assert.deepEqual([plain.value, plain.name, plain.sites, plain.source], [value, "SECRET_1", ["api.openai.com", "files.openai.com"], "device"]);
  assert.deepEqual(await S.call(fx, "update_secret", { name: "SECRET_1", sites: ["Api.OpenAI.com"], slots: ["field"] }), { ok: false, code: "invalid_input" });
  // The deletion: no request without the device owner.
  world.device.ownerAuth = false;
  assert.deepEqual(await S.call(fx, "delete_secret", { name: "SECRET_1" }), { ok: false, code: "auth_failed" });
  assert.equal(world.vault.secrets.has("SECRET_1"), true);
  world.device.ownerAuth = true;
  assert.deepEqual(await S.call(fx, "delete_secret", { name: "SECRET_1" }), { ok: true, value: { name: "SECRET_1" } });
  assert.equal(world.vault.secrets.has("SECRET_1"), false);
  assert.equal(leaked(world, value), false);
});

test("reveal_login_password shows a password a node made and none the user typed", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  const made = makeRecord(fx, "vault_password", { value: "made-by-the-vault", source: "operator" });
  const earlier = makeRecord(fx, "vault_password", { value: "made-before", source: "operator" });
  const typed = makeRecord(fx, "vault_password", { value: "typed-by-the-user" });
  world.vault.logins.set("shop.example", {
    current: { made_by: "vault", at: "2026-11-23T05:00:00Z", record: made },
    history: [{ made_by: "vault", at: "2026-11-01T05:00:00Z", record: earlier }, { made_by: "device", at: "2026-10-01T05:00:00Z" }],
  });
  assert.deepEqual(await S.call(fx, "reveal_login_password", { site: "shop.example" }), { ok: true, value: { site: "shop.example", value: "made-by-the-vault" } });
  assert.deepEqual(await S.call(fx, "reveal_login_password", { site: "shop.example", at: "2026-11-01T05:00:00Z" }), { ok: true, value: { site: "shop.example", value: "made-before" } });
  assert.deepEqual(await S.call(fx, "reveal_login_password", { site: "shop.example", at: "2026-10-01T05:00:00Z" }), { ok: false, code: "password_unavailable" });
  // A record of a password the user typed, handed out in the place of one a node made.
  world.vault.logins.set("shop.example", { current: { made_by: "vault", at: "2026-11-23T05:00:00Z", record: typed }, history: [] });
  assert.deepEqual(await S.call(fx, "reveal_login_password", { site: "shop.example" }), { ok: false, code: "record_invalid" });
  assert.equal(world.device.ownerAuths.length, 4);
});

test("the form of a name, a host, a slot and a reach of a vault secret is the one of the vectors", { skip: vectors.vault_secret === undefined }, async () => {
  const cases = vectors.vault_secret;
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  // What the backend gives for an item is checked before it enters the plaintext of a record: a
  // reach or a name of another form fails the call, and nothing is sealed.
  const accepted = async (name, sites, slots) => {
    world.clearFaults();
    world.fault("POST /api/secure/vault/secret", { status: 200, body: { name: name, sites: sites, slots: slots } });
    world.fault("GET /api/secure/vault/secret/", { status: 200, body: { name: name, label: "", sites: sites, slots: slots, state: "empty", source: "" } });
    world.fault("PUT /api/secure/vault/secret/", { status: 200, body: { name: name, state: "ready" } });
    const puts = world.sent("PUT /api/secure/vault/secret/").length;
    const result = await S.call(fx, "store_secret", { label: "x", sites: ["example.com"], slots: ["field"], value: "v" });
    assert.equal(world.sent("PUT /api/secure/vault/secret/").length, puts + (result.ok ? 1 : 0));
    return result.ok;
  };
  for (const item of cases.names) assert.equal(await accepted(item.text, ["example.com"], ["field"]), item.valid, "name " + JSON.stringify(item.text));
  for (const item of cases.hosts) assert.equal(await accepted("NAME", [item.text], ["field"]), item.valid, "host " + JSON.stringify(item.text));
  for (const item of cases.slots.concat(cases.reserved_headers)) {
    assert.equal(await accepted("NAME", ["example.com"], [item.text]), item.valid, "slot " + JSON.stringify(item.text));
  }
  for (const item of cases.reaches) {
    assert.equal(await accepted("NAME", item.sites, item.slots), item.valid, "reach " + JSON.stringify([item.sites, item.slots]));
  }
  // The record of the vectors opens on the device to the value of the vectors.
  const record = cases.record;
  const owner = new bridge.World({ serverTarget: "prod", userId: record.user_id });
  const masterKey = bytes(vectors.key_derivation.master_key);
  owner.keychain.set("com.pickle.client.secure.master-key\n" + owner.userId, { value: b64u(masterKey), synchronizable: true });
  const keys = bridge.deriveAccountKeys(masterKey);
  owner.account.keys = keys;
  owner.account.key = { key_id: keys.keyId };
  const plaintext = JSON.parse(cases.plaintext_text);
  owner.vault.secrets.set(plaintext.name, {
    name: plaintext.name, label: "", sites: plaintext.sites, slots: plaintext.slots, state: "ready", source: "device", record: record,
  });
  const reader = { world: owner, keys: keys, program: null, source: source };
  await S.start(reader);
  const shown = await S.call(reader, "reveal_secret", { name: plaintext.name });
  assert.deepEqual(shown, {
    ok: true, value: { name: plaintext.name, value: plaintext.value, sites: plaintext.sites, slots: plaintext.slots, source: plaintext.source },
  });
});

// ---- The state a program before this one left ----

test("the state of the log a program before published is not shown as a judgement of this program: the log is pending until this program ends a round", async () => {
  const fx = S.fixture(source);
  const world = fx.world;
  // What a program before version 43 left on the device: a published attention, and no round of
  // this program.
  world.state.log = {
    status: "attention", verified_ms: world.now - DAY_MS, unverified_nodes: 0, missing: 2, expired: 0, unknown_nodes: 3,
    newer_release_nodes: 0, store: "verified", store_failing_ms: 0, program_version: 42,
  };
  // The device is without a network at the start of the runtime: no round can run.
  world.fault(() => true, "transport");
  S.load(fx);
  await world.run(outcomeOf(Promise.resolve(fx.program.onEvent("session_ready", {}))));
  assert.equal(world.state.log.status, "pending");
  assert.equal(world.state.log.unknown_nodes, 0);
  assert.equal(world.state.log.missing, 0);
  assert.equal(world.state.log.program_version, 43);
  // The first round of this program judges by its own conditions.
  world.clearFaults();
  world.advance(HOUR_MS);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "verified");
  // A later runtime keeps what this program judged.
  await S.start(fx);
  assert.equal(world.state.log.status, "verified");
});

// ---- An answer of the bodies that does not name every key ----

test("A3: an answer of the bodies that ends early is asked on, and an answer that names no key, or a key and not one before it, is a read held back", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  const node = fx.nodes[0];
  const written = [];
  for (const id of ["r1", "r2", "r3"]) {
    world.advance(1000);
    written.push(node.record("c", [{ t: "connection_created", time_ms: world.now, record_id: id, provider: "slack", scope: "" }]));
  }
  const answerOnly = (keep) => {
    world.clearFaults();
    world.fault("POST /api/secure/log/bodies", (request) => {
      const answer = JSON.parse(world.api("POST", "/api/secure/log/bodies", null, request.body).body);
      return { status: 200, body: { entries: answer.entries.filter((item) => keep(item.key)), missing: [] } };
    });
  };
  const asked = () => JSON.parse(world.sent("POST /api/secure/log/bodies").slice(-1)[0].body).keys;
  // The backend answers the first key of the request and ends there: the keys are asked for with
  // the earliest entry first, the round is not complete, and nothing was held back.
  answerOnly((key) => key === written[0].key);
  await nextDay(fx);
  assert.deepEqual(asked(), written.map((entry) => entry.key));
  assert.equal(world.state.log.status, "pending");
  assert.equal(world.state.log.store, "verified");
  assert.equal(world.stored("log.blocked").count, 0);
  // The next round asks for the keys that were left, the earliest first. The backend names the
  // later one and not the one before it.
  answerOnly((key) => key === written[2].key);
  await nextDay(fx);
  assert.deepEqual(asked(), [written[1].key, written[2].key]);
  assert.equal(world.state.log.store, "blocked");
  assert.equal(world.state.log.store_failure, "bodies:skipped");
  // The key that was left out stands first in the next request, and an answer that names no key
  // holds it back again.
  answerOnly(() => false);
  await nextDay(fx);
  assert.deepEqual(asked(), [written[1].key]);
  assert.equal(world.state.log.store, "blocked");
  assert.equal(world.stored("log.blocked").count, 2);
  world.clearFaults();
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.stored("log.blocked").count, 0);
});

test("an answer of the bodies that reports keys as unread is read as an answer that does not name them: unread keys at its end are asked for again, and an unread key in front of a key it names is a read held back", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  const written = [];
  for (const id of ["r1", "r2", "r3"]) {
    world.advance(1000);
    written.push(fx.nodes[0].record("c", [{ t: "connection_created", time_ms: world.now, record_id: id, provider: "slack", scope: "" }]));
  }
  // The backend answers the keys of a request in their order: everything from the first key it
  // does not answer on is unread.
  const answerUntil = (count) => {
    world.clearFaults();
    world.fault("POST /api/secure/log/bodies", (request) => {
      const answer = JSON.parse(world.api("POST", "/api/secure/log/bodies", null, request.body).body);
      const keys = JSON.parse(request.body).keys;
      return {
        status: 200, body: {
          entries: answer.entries.filter((item) => keys.indexOf(item.key) < count), missing: [],
          unread: keys.slice(count),
        },
      };
    });
  };
  const asked = () => JSON.parse(world.sent("POST /api/secure/log/bodies").slice(-1)[0].body).keys;
  answerUntil(1);
  await nextDay(fx);
  assert.deepEqual(asked(), written.map((entry) => entry.key));
  assert.equal(world.state.log.status, "pending");
  assert.equal(world.state.log.store, "verified");
  assert.equal(world.stored("log.blocked").count, 0);
  assert.equal(world.stored("log.withheld"), undefined);
  // Every key of the next request is unread: its first key is held back.
  answerUntil(0);
  await nextDay(fx);
  assert.deepEqual(asked(), [written[1].key, written[2].key]);
  assert.equal(world.state.log.store, "blocked");
  assert.equal(world.state.log.store_failure, "bodies:skipped");
  assert.deepEqual(world.stored("log.withheld"), { keys: [written[1].key], pages: [] });
  // An unread key in front of a key the answer names.
  world.clearFaults();
  world.fault("POST /api/secure/log/bodies", (request) => {
    const answer = JSON.parse(world.api("POST", "/api/secure/log/bodies", null, request.body).body);
    return {
      status: 200, body: {
        entries: answer.entries.filter((item) => item.key === written[2].key), missing: [], unread: [written[1].key],
      },
    };
  });
  await nextDay(fx);
  assert.equal(world.state.log.store_failure, "bodies:skipped");
  assert.equal(world.stored("log.blocked").count, 2);
  world.clearFaults();
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.stored("log.withheld"), undefined);
});

// ---- An entry of the screen whose object was not read ----

test("an entry the screen could not read once is not kept as not verified: the next opening reads it", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  world.advance(HOUR_MS);
  fx.nodes[0].record("u", [S.providerRequest(world.now)]);
  // The first opening: the backend does not answer the bodies. The screen shows the entry as not
  // verified, and the round counts a read held back.
  world.fault("POST /api/secure/log/bodies", "hang", 1);
  const first = await S.call(fx, "read_log", { limit: 50 });
  assert.equal(first.ok, true);
  await world.settle(60000);
  const waited = await S.call(fx, "read_log", { limit: 50, kept: true });
  assert.ok(shownGroups(waited.value).every((group) => group.kind !== "unverified"));
  // The next opening reads the entry and shows it as verified.
  world.advance(HOUR_MS);
  const second = await S.call(fx, "read_log", { limit: 50 });
  const groups = shownGroups(second.value);
  assert.deepEqual(groups.map((group) => group.kind), ["request", "grant_renewed"]);
  assert.ok(groups.every((group) => group.verified === true));
});
