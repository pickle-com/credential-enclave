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

/** The reads held back that the device keeps for the rounds (log.withheld), without the time
 *  until which the rounds read the first listing pages for the screen (undefined when the device
 *  keeps nothing but that time, or nothing). */
function heldReads(world) {
  const kept = world.stored("log.withheld");
  if (kept === undefined) return undefined;
  delete kept.watch_ms;
  return kept.keys.length + kept.pages.length === 0 && Object.keys(kept).length === 3 ? undefined : kept;
}

/** The number of control keys the device remembers as judged (log.seen: the index and its parts,
 *  each part the digests of 12 characters one after another). */
function judgedKeys(world) {
  const index = world.stored("log.seen");
  if (index === undefined) return 0;
  return index.parts.reduce((sum, number) => sum + (world.store.get("log.seen." + number) || "").length / 12, 0);
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
  // (The backend serves the program of the tests.)
  world.account.servedProgram = Number(/const VERSION = (\d+);/.exec(source)[1]);
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

test("A3: a synchronization has rounds follow one another while each ends with more to read, eight at most, and beyond eight such rounds in a row its first round counts as a round held back: objects that keep piling up under the prefix of an account faster than the device reads them mark the log three days after the second synchronization", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  // Before every synchronization, 1,500 objects under 1,500 node ids no node has. A round asks
  // the documents of 128 nodes for the keys of its listing pages and of 32 more for the keys
  // the round before left it, and the eight rounds of one synchronization of 1,280 at most: no
  // round reaches the end of what there is to read.
  const bucket = bridge.shardBucket(world.serverTarget, world.userId);
  const pile = () => {
    for (let i = 0; i < 1500; i += 1) {
      world.advance(10);
      world.putObject(bucket, "a3/" + world.userId + "/c/" + String(bridge.RTIME_MAX - world.now).padStart(13, "0") + "." +
        b64u(crypto.randomBytes(32)) + ".1.grant_revoked." + fx.keys.keyId + "." + b64u(crypto.randomBytes(32)), "x");
    }
  };
  const states = [];
  const rounds = [];
  for (let day = 0; day < 5; day += 1) {
    pile();
    const before = world.reports.length;
    await nextDay(fx);
    await world.settle(1000);
    rounds.push(world.reports.length - before);
    states.push(world.state.log.status + ":" + world.state.log.store + ":" + world.reports.slice(-1)[0].blocked_attempts);
  }
  // The eight rounds of the first synchronization count nothing. From the second synchronization
  // on its first round counts, once, and the fifth is three days after the second.
  assert.deepEqual(rounds, [8, 8, 8, 8, 8]);
  assert.deepEqual(states, ["pending:verified:0", "pending:blocked:1", "pending:blocked:2", "pending:blocked:3", "attention:blocked:4"]);
  assert.equal(world.state.log.store_failure, "round:unfinished");
  assert.equal(world.stored("log.round").unfinished, 40);
  assert.deepEqual(world.securityStatuses.slice(-1)[0].reasons, ["verification_blocked"]);
  // A round the log screen starts during that time ends no count and adds to none: it has more
  // to read as well.
  await S.call(fx, "read_log", { limit: 10 });
  assert.equal(world.state.log.status, "attention");
  assert.equal(world.stored("log.blocked").count, 4);
  assert.equal(world.stored("log.round").unfinished, 40);
  // The objects stop arriving: the rounds judge the rest, and the walk through the listing that
  // leaves no key unjudged clears the mark. The device remembers the judgement of every one of
  // the 7,500 objects (in two parts of the program store).
  for (let turn = 0; turn < 8 && world.state.log.status !== "verified"; turn += 1) {
    world.advance(2 * 60000);
    await S.event(fx, "foreground");
    await world.settle(1000);
  }
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.state.log.store, "verified");
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.equal(world.stored("log.round").unfinished, 0);
  assert.equal(world.securityStatuses.slice(-1)[0].status, "ok");
  assert.equal(judgedKeys(world), 7501);
  assert.deepEqual(world.stored("log.seen"), { v: 2, parts: [0, 1] });
});

test("a listing longer than the pages of one round is walked over several rounds, and a walk in which a round left keys unjudged does not end as a reading that read everything: the rounds walk again until every key is judged", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  // 450 objects under 450 node ids no node has, in listing pages of 100: five pages. A round
  // reads four pages and asks the documents of 128 nodes for their keys, and of 32 more for the
  // keys the round before left it.
  world.pageSize = 100;
  const bucket = bridge.shardBucket(world.serverTarget, world.userId);
  for (let i = 0; i < 450; i += 1) {
    world.advance(10);
    world.putObject(bucket, "a3/" + world.userId + "/c/" + String(bridge.RTIME_MAX - world.now).padStart(13, "0") + "." +
      b64u(crypto.randomBytes(32)) + ".1.grant_revoked." + fx.keys.keyId + "." + b64u(crypto.randomBytes(32)), "x");
  }
  const before = world.reports.length;
  const judged = judgedKeys(world);
  await nextDay(fx);
  await world.settle(1000);
  // The second round ends the first walk: it judged every key of the page it listed, and the
  // round before it left keys of the first four pages unjudged. It does not verify, and neither
  // does a later round that ends a walk that way.
  const told = world.reports.slice(before).map((report) => report.status);
  assert.deepEqual(told, Array(told.length - 1).fill("pending").concat(["verified"]));
  assert.ok(told.length > 2);
  assert.equal(judgedKeys(world), judged + 450);
  assert.equal(world.stored("log.round").unfinished, 0);
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.equal(heldReads(world), undefined);
  assert.ok(world.securityStatuses.every((status) => status.status !== "attention"));
});

test("an account with more to read than one round reads is read to its end by the rounds that follow one another, and nothing marks the log: a long listing of control entries, entries of more nodes than a round asks the documents of, and more than the rounds of one synchronization read", async () => {
  const told = (world) => world.reports.map((report) => report.status + ":" + report.store + ":" + report.blocked_attempts);
  // 61 control entries in listing pages of three: 21 pages, four per round. The first
  // synchronization reads them in six rounds.
  const long = S.fixture(source);
  long.world.pageSize = 3;
  for (let i = 0; i < 60; i += 1) {
    long.world.advance(1000);
    long.nodes[0].record("c", [{ t: "connection_created", time_ms: long.world.now, record_id: "r" + i, provider: "slack", scope: "" }]);
  }
  await S.start(long);
  await long.world.settle(1000);
  assert.deepEqual(told(long.world), Array(5).fill("pending:truncated:0").concat(["verified:verified:0"]));
  assert.equal(judgedKeys(long.world), 61);
  assert.equal(long.world.stored("log.round").unfinished, 0);

  // Control entries of 300 nodes of the accepted measurement that this device has no judgement
  // of (a device that reads the log of its account for the first time): three rounds.
  const wide = S.fixture(source);
  for (let i = 0; i < 300; i += 1) {
    wide.world.advance(1000);
    wide.world.addNode({ release: "v2.4.0", measurement: wide.measurement, offered: false })
      .record("c", [{ t: "connection_created", time_ms: wide.world.now, record_id: "r" + i, provider: "slack", scope: "" }]);
  }
  await S.start(wide);
  await wide.world.settle(1000);
  assert.deepEqual(told(wide.world), ["pending:verified:0", "pending:verified:0", "verified:verified:0"]);
  assert.equal(wide.world.reports.slice(-1)[0].undocumented_nodes, 0);

  // 61 control entries in listing pages of one: sixteen rounds. The eight rounds of the first
  // synchronization leave the log pending. The first round of the second counts as a round held
  // back (pending, not attention), and the round that reaches the end clears that count.
  const deep = S.fixture(source, { device: { securityStatus: true } });
  deep.world.pageSize = 1;
  for (let i = 0; i < 60; i += 1) {
    deep.world.advance(1000);
    deep.nodes[0].record("c", [{ t: "connection_created", time_ms: deep.world.now, record_id: "r" + i, provider: "slack", scope: "" }]);
  }
  await S.start(deep);
  await deep.world.settle(1000);
  assert.deepEqual(told(deep.world), Array(8).fill("pending:truncated:0"));
  assert.equal(deep.world.stored("log.round").unfinished, 8);
  deep.world.advance(4 * DAY_MS);
  await S.event(deep, "foreground");
  await deep.world.settle(1000);
  assert.deepEqual(told(deep.world).slice(8), Array(7).fill("pending:blocked:1").concat(["verified:verified:0"]));
  assert.equal(judgedKeys(deep.world), 61);
  assert.deepEqual(deep.world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.ok(deep.world.securityStatuses.every((status) => status.status !== "attention"));
});

test("a round whose time runs out is judged on what it read and keeps it: slow answers leave the rounds pending, each reads on from where the one before stopped, and the last one verifies", async () => {
  const fx = S.fixture(source);
  const world = fx.world;
  world.pageSize = 3;
  for (let i = 0; i < 20; i += 1) {
    world.advance(1000);
    fx.nodes[0].record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r" + i, provider: "slack", scope: "" }]);
  }
  // Every request of the reads is answered, nine seconds after it was sent: a listing page takes
  // 27 seconds (the address, the listing, the bodies), and a round has 60.
  world.fault("POST /api/secure/log/read", { delay_ms: 9000 });
  world.fault("POST /api/secure/log/bodies", { delay_ms: 9000 });
  world.fault("S3 " + world.shardHost, { delay_ms: 9000 });
  await S.start(fx);
  assert.equal(world.state.log.status + ":" + world.state.log.store + ":" + world.state.log.store_failure, "pending:truncated:round:time");
  assert.equal(judgedKeys(world), 6);
  // The rounds that follow run while the app stays in the foreground: each judged the keys of
  // the pages it read, and the next did not read them again.
  await world.settle(10 * 60000);
  assert.deepEqual(world.reports.map((report) => report.status + ":" + report.store + ":" + report.store_failure + ":" + report.keys_checked),
    ["pending:truncated:round:time:6", "pending:truncated:round:time:6", "pending:truncated:round:time:6", "verified:verified::3"]);
  assert.equal(judgedKeys(world), 21);
  assert.equal(world.stored("log.round").unfinished, 0);
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
});

test("a round whose time passed judges and writes what it kept before the next round begins: the round of the log screen that waits behind it starts after the report of that round", async () => {
  const fx = S.fixture(source);
  const world = fx.world;
  world.pageSize = 3;
  for (let i = 0; i < 20; i += 1) {
    world.advance(1000);
    fx.nodes[0].record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r" + i, provider: "slack", scope: "" }]);
  }
  world.fault("POST /api/secure/log/read", { delay_ms: 9000 });
  world.fault("POST /api/secure/log/bodies", { delay_ms: 9000 });
  world.fault("S3 " + world.shardHost, { delay_ms: 9000 });
  // The round of the first synchronization reads slowly. Thirty seconds in, the user opens the
  // log screen: its round waits for the round that runs.
  S.load(fx);
  const started = Promise.resolve(fx.program.onEvent("session_ready", {}));
  started.then(() => {}, () => {});
  await world.settle(30000);
  const shown = fx.program.procedures.read_log({ limit: 10 });
  shown.then(() => {}, () => {});
  await world.settle(10 * 60000);
  // The requests in the order they were sent: the report of the first round, whose time passed,
  // stands before the request for listing addresses of the round of the screen (the one that
  // names the first pages of both prefixes).
  const order = world.requests.map((request) => {
    if (request.path === "/api/secure/log/verified") return "report";
    if (request.path === "/api/secure/log/read" && JSON.parse(request.body).pages.length === 2) return "screen";
    return "";
  });
  assert.ok(order.indexOf("report") >= 0);
  assert.ok(order.indexOf("screen") > order.indexOf("report"));
  assert.equal(world.reports[0].store_failure, "round:time");
  // What the first round judged is kept: the rounds after it read on, and the log verifies.
  assert.equal(world.state.log.status, "verified");
  assert.equal(judgedKeys(world), 21);
  assert.equal(world.stored("log.round").unfinished, 0);
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

test("a read that ends because the app was suspended counts nothing: a round whose request fails when the runtime runs again is pending, however often in a row, and a later page of the screen that fails that way is not noted", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  for (let i = 0; i < 6; i += 1) {
    world.advance(HOUR_MS);
    fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
  }
  const listed = () => world.sent("POST /api/secure/log/read").length;
  // Starts work and lets it go on until it sent its request for listing addresses.
  const untilListed = async (work) => {
    const before = listed();
    const running = Promise.resolve(work());
    running.then(() => {}, () => {});
    for (let turn = 0; turn < 50 && listed() === before; turn += 1) await world.settle(0);
    assert.equal(listed(), before + 1);
    return { running: running };
  };
  // Lets the work end (a synchronization may end with the time of its round) and what it left
  // behind go on.
  const ended = async (work) => {
    let failure = null;
    try {
      await world.run(work.running);
    } catch (error) {
      failure = error;
    }
    await world.settle(30000);
    return failure;
  };
  world.advance(25 * HOUR_MS);
  const states = [];
  for (let at = 0; at < 15; at += 1) {
    world.advance(9 * HOUR_MS);
    if (at % 3 === 0) {
      // The user leaves the app while the first request of the round is on its way. The app
      // tells the program, and the round ends its reading there (the request fails five seconds
      // later, when the runtime runs again).
      world.fault("POST /api/secure/log/read", { delay_ms: 5000, fail: "transport" }, 1);
      const sync = await untilListed(() => fx.program.onEvent("foreground", {}));
      fx.program.onEvent("background", {});
      await ended(sync);
    } else {
      // The runtime stops without a word and runs again later: after thirty seconds (the request
      // that was not answered ends long after its limit, within the time of the round), or
      // after ten minutes (it ends after the time of the round).
      world.fault("POST /api/secure/log/read", "hang", 1);
      const sync = await untilListed(() => fx.program.onEvent("foreground", {}));
      world.advance(at % 3 === 1 ? 30000 : 10 * 60000);
      await ended(sync);
    }
    states.push(world.state.log.status + ":" + world.state.log.store + ":" + world.state.log.store_failure);
    assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 }, "round " + at);
    assert.equal(world.stored("log.round").unfinished, 0, "round " + at);
  }
  const three = ["pending:unreachable:round:suspended", "pending:unreachable:read:suspended", "pending:unreachable:round:suspended"];
  assert.deepEqual(states, three.concat(three, three, three, three));
  assert.ok(world.securityStatuses.every((told) => told.status !== "attention"));
  // A round the runtime runs to its end verifies.
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "verified");

  // A later page of the screen: the request for its listings fails the same way. Nothing is
  // noted as held back from the screen, and nothing goes to the rounds.
  world.pageSize = 2;
  await S.start(fx);
  const first = await S.call(fx, "read_log", { limit: 2 });
  assert.equal(first.value.has_more, true);
  const before = world.runtime.log_pages[0].before_ms;
  world.fault("POST /api/secure/log/read", { delay_ms: 5000, fail: "transport" }, 1);
  const page = await untilListed(() => fx.program.procedures.read_log_page({ before_ms: before }));
  fx.program.onEvent("background", {});
  assert.equal((await ended(page)).code, "log_store_unreachable");
  assert.equal(world.stored("log.denied"), undefined);
  assert.equal(heldReads(world), undefined);
  // The same failure with the app in the foreground is a read held back: the backend answered
  // another request of the runtime a moment before.
  await S.event(fx, "foreground");
  world.fault("POST /api/secure/log/read", { delay_ms: 5000, fail: "transport" }, 1);
  const again = await untilListed(() => fx.program.procedures.read_log_page({ before_ms: before }));
  assert.equal((await ended(again)).code, "log_store_unreachable");
  assert.equal(world.stored("log.denied").pages.length, 1);
});

test("A1: a measurement that held the key marks the log at an event of the app once the device first saw it a day ago and this runtime read within the hour that no later program is served, whatever the reads of the log answer: a runtime states nothing before it has read what is served", async () => {
  // Sends an event to the runtime and lets what needs no answer go on.
  const unanswered = (fx, name) => {
    Promise.resolve(fx.program.onEvent(name, {})).then(() => {}, () => {});
    return fx.world.drain();
  };
  for (const name of ["session_ready", "foreground", "background", "push"]) {
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
    assert.equal(world.state.log.status, "pending", name);
    assert.equal(world.state.log.newer_release_nodes, 1, name);
    const reports = world.reports.length;
    // From here on no read of the log is answered. Within the day the log stays pending.
    world.fault((line) => line.indexOf("/api/secure/log/") >= 0, "hang");
    world.advance(HOUR_MS);
    if (name === "session_ready") S.load(fx);
    await unanswered(fx, name);
    assert.equal(world.state.log.status, "pending", name);
    // (The round that waits for its answers ends when its time has passed.)
    await world.settle(3 * 60000);
    assert.equal(world.state.log.status, "pending", name);
    // A day after the device first saw the measurement. What this runtime read of the served
    // program is a day old (a new runtime has read nothing): the event states nothing. The
    // synchronization of that event reads that no later program is served.
    world.advance(25 * HOUR_MS);
    if (name === "session_ready") S.load(fx);
    await unanswered(fx, name === "background" ? "foreground" : name);
    assert.equal(world.state.log.status, "pending", name);
    assert.ok(world.securityStatuses.every((told) => told.status !== "attention"), name);
    // The next event, seconds later, marks the log itself: no read of the log was answered, and
    // no round ended.
    world.advance(5000);
    await unanswered(fx, name === "session_ready" ? "foreground" : name);
    assert.equal(world.state.log.status, "attention", name);
    assert.equal(world.state.log.unknown_nodes, 1, name);
    const told = world.securityStatuses.slice(-1)[0];
    assert.deepEqual({ status: told.status, reasons: told.reasons }, { status: "attention", reasons: ["unlisted_release"] }, name);
    assert.equal(world.reports.length, reports, name);
    // The program that lists the release judges nothing from what the device kept, and its
    // first round clears the mark.
    world.clearFaults();
    await S.start(fx, bridge.withListedRelease(fx.source, "v9.0.0", other, 44));
    assert.equal(world.state.log.status, "verified", name);
    assert.equal(world.state.log.unknown_nodes, 0, name);
  }
});

test("a receiving node whose document this device has not seen waits for it: no time marks the log for it, a round whose request for the document is answered without one is a round held back, and a document a round then reads ends the wait", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  // A transfer whose event names no measurement, to a node of the accepted measurement. The
  // backend answers the request for the document of that node without a document.
  const receiver = world.addNode({ release: "v2.4.0", measurement: fx.measurement, offered: false });
  fx.nodes[0].record("c", [{ t: "grant_transferred_out", time_ms: world.now, to: receiver.id, release: "v2.4.0" }]);
  withhold(fx, [receiver.id], "missing");
  await nextDay(fx);
  assert.equal(world.state.log.status + ":" + world.state.log.store + ":" + world.state.log.store_failure, "pending:blocked:receiver:missing");
  assert.equal(world.stored("log.blocked").count, 1);
  assert.deepEqual(Object.keys(world.stored("log.legacy").waiting), [receiver.id]);
  assert.deepEqual(world.stored("log.unaccepted"), {});
  // The device is not used for five days. The round that then asks for the document ends with
  // the app in the background before it is answered: no time marks the log for a node that waits.
  world.clearFaults();
  world.advance(5 * DAY_MS);
  world.fault("POST /api/secure/log/documents", { delay_ms: 9000 });
  Promise.resolve(fx.program.onEvent("foreground", {})).then(() => {}, () => {});
  await world.settle(5000);
  assert.deepEqual(JSON.parse(world.sent("POST /api/secure/log/documents").slice(-1)[0].body).nodes, [receiver.id]);
  fx.program.onEvent("background", {});
  await world.drain();
  assert.equal(world.state.log.status + ":" + world.state.log.store_failure, "pending:round:suspended");
  assert.equal(world.state.log.newer_release_nodes + world.state.log.unknown_nodes, 0);
  // The backend hands the document out: the wait ends, and the log verifies.
  world.clearFaults();
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "verified");
  assert.deepEqual(world.stored("log.legacy").waiting, {});
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.ok(world.securityStatuses.every((told) => told.status !== "attention"));
  // A transfer to a node id of which neither the backend nor the store holds a document: the
  // request for its document is answered without one, and the round is one held back.
  const ghost = b64u(crypto.randomBytes(32));
  fx.nodes[0].record("c", [{ t: "grant_transferred_out", time_ms: world.now, to: ghost, release: "v2.4.0" }]);
  await nextDay(fx);
  assert.equal(world.state.log.status + ":" + world.state.log.store + ":" + world.state.log.store_failure, "pending:blocked:receiver:missing");
  assert.equal(world.stored("log.blocked").count, 1);
  assert.deepEqual(Object.keys(world.stored("log.legacy").waiting), [ghost]);
});

test("a round ends its reading when the app goes to the background: it sends nothing more, judges what it read within that event, and leaves the keys it listed and did not judge to the next round, which asks for them before its listing", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  const judged = judgedKeys(world);
  // Three control entries of the node of the device, and one of a node of a measurement no list
  // has (the key of the account is at that node).
  const written = [];
  for (const id of ["r1", "r2", "r3"]) {
    world.advance(1000);
    written.push(fx.nodes[0].record("c", [{ t: "connection_created", time_ms: world.now, record_id: id, provider: "slack", scope: "" }]));
  }
  const later = world.addNode({ release: "v9.0.0", measurement: bridge.randomMeasurement(), offered: false });
  world.advance(1000);
  const moved = later.record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r4", provider: "slack", scope: "" }]);
  // Every request of the reads is answered nine seconds after it was sent, and the user stays in
  // the app for fifteen seconds at a time.
  world.fault("POST /api/secure/log/read", { delay_ms: 9000 });
  world.fault("POST /api/secure/log/bodies", { delay_ms: 9000 });
  world.fault("POST /api/secure/log/documents", { delay_ms: 9000 });
  const reads = (from) => world.requests.slice(from).map((request) => String(request.path))
    .filter((line) => line.startsWith("/api/secure/log/") && !line.endsWith("/verified"))
    .map((line) => line.slice("/api/secure/log/".length));
  const stay = async () => {
    const from = world.requests.length;
    Promise.resolve(fx.program.onEvent("foreground", {})).then(() => {}, () => {});
    await world.settle(15000);
    const sent = reads(from);
    const reports = world.reports.length;
    const left = world.requests.length;
    // The app goes to the background: the round ends within the event (no time of the model
    // passes), and it sends its report and no read.
    fx.program.onEvent("background", {});
    await world.drain();
    assert.equal(world.reports.length, reports + 1);
    assert.deepEqual(reads(left), []);
    // The app is suspended for two minutes.
    world.advance(2 * 60000);
    return sent;
  };
  world.advance(25 * HOUR_MS);
  // The first stay: the listing is read, and the app leaves while the documents and the bodies
  // are on their way. Nothing was judged, and nothing counts. The four keys are left to the next
  // round: the keys of the node of the accepted measurement first, the earliest first.
  assert.deepEqual(await stay(), ["read", "documents", "bodies"]);
  assert.equal(world.state.log.status + ":" + world.state.log.store + ":" + world.state.log.store_failure, "pending:unreachable:round:suspended");
  assert.deepEqual(heldReads(world), { keys: [], shown: [], pages: [], unjudged: written.map((entry) => entry.key).concat([moved.key]) });
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.equal(world.stored("log.round").unfinished, 0);
  assert.equal(judgedKeys(world), judged);
  // The second stay: the round asks for those keys and for no listing. The three entries of the
  // node of the device are judged, and the document of the other node says of which measurement
  // it is; its entry is asked for when the app leaves.
  assert.deepEqual(await stay(), ["documents", "bodies", "bodies"]);
  assert.deepEqual(heldReads(world), { keys: [], shown: [], pages: [], unjudged: [moved.key] });
  assert.equal(judgedKeys(world), judged + 3);
  assert.equal(world.state.log.newer_release_nodes, 0);
  // The third stay: the entry of the other node is read before the listing is asked for. The key
  // of the account is at a measurement no list has: pending for a day.
  assert.deepEqual(await stay(), ["bodies", "read"]);
  assert.equal(heldReads(world), undefined);
  assert.equal(judgedKeys(world), judged + 4);
  assert.equal(world.state.log.status, "pending");
  assert.equal(world.state.log.newer_release_nodes, 1);
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.ok(world.securityStatuses.every((told) => told.status !== "attention"));
  // A day later. The synchronization of the next event reads that no later program is served,
  // and when the app leaves, the round that still waits for its answers judges: the
  // measurement marks the log, however slowly the backend answers.
  world.advance(25 * HOUR_MS);
  Promise.resolve(fx.program.onEvent("foreground", {})).then(() => {}, () => {});
  await world.settle(1000);
  assert.equal(world.state.log.status, "pending");
  fx.program.onEvent("background", {});
  await world.drain();
  assert.equal(world.state.log.status, "attention");
  assert.deepEqual(world.securityStatuses.slice(-1)[0].reasons, ["unlisted_release"]);
});

test("the keys a round listed and did not judge are kept for the next round, 32 at most: the keys of the nodes of an accepted measurement first and the earliest entry first, and a round that ended with the app in the background is followed by a round at the next return, however soon", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  // Five objects under node ids no node has, and after them 34 control entries of the node of
  // the device.
  const bucket = bridge.shardBucket(world.serverTarget, world.userId);
  for (let i = 0; i < 5; i += 1) {
    world.advance(1000);
    world.putObject(bucket, "a3/" + world.userId + "/c/" + String(bridge.RTIME_MAX - world.now).padStart(13, "0") + "." +
      b64u(crypto.randomBytes(32)) + ".1.grant_revoked." + fx.keys.keyId + "." + b64u(crypto.randomBytes(32)), "x");
  }
  const written = [];
  for (let i = 0; i < 34; i += 1) {
    world.advance(1000);
    written.push(fx.nodes[0].record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r" + i, provider: "slack", scope: "" }]));
  }
  world.fault("POST /api/secure/log/bodies", { delay_ms: 9000 });
  world.fault("POST /api/secure/log/documents", { delay_ms: 9000 });
  world.advance(25 * HOUR_MS);
  Promise.resolve(fx.program.onEvent("foreground", {})).then(() => {}, () => {});
  await world.settle(5000);
  fx.program.onEvent("background", {});
  await world.drain();
  assert.deepEqual(heldReads(world).unjudged, written.slice(0, 32).map((entry) => entry.key));
  // The user returns five seconds later: a round runs, and its first request names those keys.
  world.clearFaults();
  world.advance(5000);
  const before = world.sent("POST /api/secure/log/bodies").length;
  await S.event(fx, "foreground");
  await world.settle(1000);
  assert.deepEqual(JSON.parse(world.sent("POST /api/secure/log/bodies")[before].body).keys, written.slice(0, 32).map((entry) => entry.key));
  assert.equal(world.state.log.status, "verified");
  assert.equal(heldReads(world), undefined);
});

test("the receiving node of a transfer is noted when the reading of the round ends while its document is asked for: the entry of the transfer is judged once, the node waits, and the measurement its document states counts from the time the device read it", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  // A transfer whose event names no measurement, to a node of a measurement no list has.
  const receiver = world.addNode({ release: "v9.0.0", measurement: bridge.randomMeasurement(), offered: false });
  const transfer = fx.nodes[0].record("c", [{ t: "grant_transferred_out", time_ms: world.now, to: receiver.id, release: "v9.0.0" }]);
  world.fault("POST /api/secure/log/documents", { delay_ms: 9000 });
  world.advance(25 * HOUR_MS);
  Promise.resolve(fx.program.onEvent("foreground", {})).then(() => {}, () => {});
  await world.settle(5000);
  assert.equal(JSON.parse(world.sent("POST /api/secure/log/documents").slice(-1)[0].body).nodes[0], receiver.id);
  fx.program.onEvent("background", {});
  await world.drain();
  assert.equal(world.state.log.store_failure, "round:suspended");
  assert.deepEqual(Object.keys(world.stored("log.legacy").waiting), [receiver.id]);
  assert.equal(world.state.log.newer_release_nodes, 0);
  // Two days pass without a round: nothing is marked. The next round does not read the entry
  // of the transfer again and asks for the document of the node that waits: it states a
  // measurement no list has, which the device sees for the first time now.
  world.clearFaults();
  world.advance(2 * DAY_MS);
  const bodies = askedBodies(world).filter((key) => key === transfer.key).length;
  await S.event(fx, "foreground");
  assert.equal(askedBodies(world).filter((key) => key === transfer.key).length, bodies);
  assert.equal(world.state.log.status, "pending");
  assert.equal(world.state.log.newer_release_nodes, 1);
  assert.deepEqual(world.stored("log.legacy").waiting, {});
  await nextDay(fx);
  assert.equal(world.state.log.status, "attention");
  assert.equal(world.state.log.unknown_nodes, 1);
});

test("a round whose reading ended calls the store no more: the listings of node documents that waited for their turn are not sent", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  // 30 objects under 30 node ids no node has: the round asks the store for one listing of a node
  // document for each, eight at a time, and the store answers each after nine seconds.
  const bucket = bridge.shardBucket(world.serverTarget, world.userId);
  for (let i = 0; i < 30; i += 1) {
    world.advance(10);
    world.putObject(bucket, "a3/" + world.userId + "/c/" + String(bridge.RTIME_MAX - world.now).padStart(13, "0") + "." +
      b64u(crypto.randomBytes(32)) + ".1.grant_revoked." + fx.keys.keyId + "." + b64u(crypto.randomBytes(32)), "x");
  }
  world.fault(isDocumentListing, { delay_ms: 9000 });
  const before = documentListings(world).length;
  world.advance(25 * HOUR_MS);
  Promise.resolve(fx.program.onEvent("foreground", {})).then(() => {}, () => {});
  await world.settle(5000);
  assert.equal(documentListings(world).length, before + 8);
  fx.program.onEvent("background", {});
  await world.drain();
  await world.settle(60000);
  assert.equal(documentListings(world).length, before + 8);
  assert.equal(world.state.log.store_failure, "round:suspended");
  // The next round reads them all.
  world.clearFaults();
  await S.event(fx, "foreground");
  await world.settle(1000);
  assert.equal(world.state.log.status, "verified");
  assert.equal(heldReads(world), undefined);
});

test("objects under the use prefix that are no entries take no entry from the log screen: the first page is read on below them, and when more of them lie on top than it passes, the page after it begins below the ones it passed and the day is noted: such pages on three days mark the log", async () => {
  // Five use entries, and objects under node ids no node has whose keys name a time a month from
  // now and 128 events each: they sort in front of every entry, and each fills a page by what its
  // key says.
  const build = async (strays) => {
    const fx = S.fixture(source, { device: { securityStatus: true } });
    const world = fx.world;
    await S.start(fx);
    for (let i = 0; i < 5; i += 1) {
      world.advance(HOUR_MS);
      fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
    }
    const bucket = bridge.shardBucket(world.serverTarget, world.userId);
    for (let i = 0; i < strays; i += 1) {
      const time = world.now + 30 * DAY_MS + i * 1000;
      world.putObject(bucket, "a3/" + world.userId + "/u/" + String(bridge.RTIME_MAX - time).padStart(13, "0") + "." +
        b64u(crypto.randomBytes(32)) + ".1.128." + fx.keys.keyId + "." + b64u(crypto.randomBytes(32)), "x");
    }
    return fx;
  };
  const requests = (result) => shownGroups(result.value).filter((group) => group.kind === "request")
    .reduce((sum, group) => sum + group.count, 0);
  // One such object: the first page shows the five entries, and nothing is noted.
  const one = await build(1);
  const shown = await S.call(one, "read_log", { limit: 100 });
  assert.equal(requests(shown), 5);
  assert.equal(shown.value.status, "verified");
  assert.equal(one.world.stored("log.denied"), undefined);
  // Six: the first page passes three of them and shows no entry. It says that there is more,
  // and the pages after it pass the rest and show the five entries.
  const six = await build(6);
  const world = six.world;
  const first = await S.call(six, "read_log", { limit: 100 });
  assert.equal(requests(first), 0);
  assert.equal(first.value.has_more, true);
  let found = 0;
  for (let page = 0; page < 6 && found === 0; page += 1) {
    const places = world.runtime.log_pages;
    assert.ok(places.length > page, "page " + page);
    const next = await S.call(six, "read_log_page", { before_ms: places[page].before_ms });
    assert.equal(next.ok, true);
    found = requests(next);
  }
  assert.equal(found, 5);
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.equal(heldReads(world), undefined);
  // A page that held no entry because every key it took was no entry: one note for the day.
  // While such objects keep the first page, every day adds one, and the third day after the
  // first marks the log.
  assert.deepEqual([world.stored("log.denied").pages.length, world.stored("log.denied").filled.length], [0, 1]);
  const states = [];
  for (let day = 0; day < 3; day += 1) {
    world.advance(DAY_MS + HOUR_MS);
    await S.event(six, "foreground");
    await S.call(six, "read_log", { limit: 100 });
    await world.settle(0);
    states.push(world.state.log.status + ":" + world.stored("log.denied").filled.length);
  }
  assert.deepEqual(states, ["verified:2", "verified:3", "attention:4"]);
  assert.equal(world.state.log.store_failure, "screen:held");
  assert.deepEqual(world.securityStatuses.slice(-1)[0].reasons, ["verification_blocked"]);
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
  assert.equal(heldReads(world), undefined);
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
  assert.deepEqual(heldReads(world), { keys: [used.key], shown: [used.key], pages: [] });
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
  assert.equal(heldReads(world), undefined);
  assert.ok(askedBodies(world).indexOf(used.key) >= 0);
  const after = await S.call(fx, "read_log", { limit: 50 });
  assert.deepEqual(shownGroups(after.value).map((group) => group.kind), ["request", "grant_renewed"]);
});

// ---- What a round reads of a read of the screen that was held back reaches the screen ----

/** A backend that tells the requests of the log screen from the requests of a round a
 *  synchronization started (by the requests around them) and holds reads back from the screen
 *  alone. The fixture says which of the two is running (mode.screen); while it is the screen,
 *  the backend hands out no document for the nodes ids and no body for the keys held(key). */
function screenOnly(fx, ids, held) {
  const mode = { screen: false };
  documentsAnswer(fx, (answer, nodes) => {
    if (!mode.screen) return;
    answer.documents = answer.documents.filter((item) => ids.indexOf(item.node) < 0);
    for (const id of nodes) {
      if (ids.indexOf(id) >= 0 && answer.missing.indexOf(id) < 0) answer.missing.push(id);
    }
  });
  fx.world.fault("POST /api/secure/log/bodies", (request) => {
    if (!mode.screen) return undefined;
    const answer = JSON.parse(fx.world.api("POST", "/api/secure/log/bodies", null, request.body).body);
    return {
      status: 200, body: {
        entries: answer.entries.filter((item) => !held(item.key)),
        missing: answer.missing.concat(JSON.parse(request.body).keys.filter(held)), unread: [],
      },
    };
  });
  return mode;
}

/** Calls a procedure of the log screen as the backend of screenOnly sees it. */
async function onScreen(fx, mode, name, args) {
  mode.screen = true;
  const outcome = await S.call(fx, name, args);
  mode.screen = false;
  return outcome;
}

test("a backend that answers the rounds and not the screen shows the user what it answered: the entry a round read again is on the screen with its content, and the screen does not ask for it", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  // A node of the accepted measurement that took the delegation from another node of its
  // measurement (no entry says so) and used a credential.
  const hidden = world.addNode({ release: "v2.4.0", measurement: fx.measurement, offered: false });
  world.advance(HOUR_MS);
  const used = hidden.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/send", "POST")]);
  const mode = screenOnly(fx, [hidden.id], (key) => key === used.key);
  // The screen: the document of the node is held back, and the entry is shown as not verified.
  const first = await onScreen(fx, mode, "read_log", { limit: 50 });
  assert.deepEqual(shownGroups(first.value).map((group) => group.kind), ["unverified", "grant_renewed"]);
  assert.equal(world.state.log.store, "blocked");
  assert.deepEqual(heldReads(world), { keys: [used.key], shown: [used.key], pages: [] });
  assert.equal(world.stored("log.recovered"), undefined);
  // The next round reads that key again, and the backend answers it: nothing is held back, and
  // the count ends. What the round read is kept for the screen, sealed.
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "verified");
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.equal(heldReads(world), undefined);
  const kept = world.store.get("log.recovered");
  assert.equal(typeof kept, "string");
  assert.equal(kept.indexOf("gmail"), -1);
  assert.equal(kept.indexOf(hidden.id), -1);
  assert.deepEqual(Object.keys(JSON.parse(kept)).sort(), ["ct", "key_id", "nonce", "v"]);
  // The screen again, with the backend holding the same reads back from it: the entry is shown
  // with what it says, the screen asks neither for its document nor for its body, and nothing
  // is counted.
  const documents = world.sent("POST /api/secure/log/documents").length;
  const bodies = askedBodies(world).filter((key) => key === used.key).length;
  const second = await onScreen(fx, mode, "read_log", { limit: 50 });
  const groups = shownGroups(second.value);
  assert.deepEqual(groups.map((group) => group.kind), ["request", "grant_renewed"]);
  assert.equal(groups[0].action, "send_mail");
  assert.equal(groups[0].requests[0].target, "gmail.googleapis.com/gmail/v1/users/me/messages/send");
  assert.equal(groups[0].verified, true);
  assert.deepEqual(second.value.summary, { reads: 0, sends: 1, changes: 0, providers_text: "Google · Gmail", truncated: false });
  assert.equal(second.value.status, "verified");
  assert.equal(world.sent("POST /api/secure/log/documents").length, documents);
  assert.equal(askedBodies(world).filter((key) => key === used.key).length, bodies);
  assert.equal(heldReads(world), undefined);
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
  // The security record the app draws reads the same.
  const record = await onScreen(fx, mode, "read_security_record", { limit: 50 });
  assert.deepEqual(record.value.items.map((item) => item.kind), ["mail_sent", "delegation_renewed"]);
  assert.equal(record.value.items[0].detail, "gmail.googleapis.com/gmail/v1/users/me/messages/send");
  // A runtime after it has the same.
  await S.start(fx);
  const third = await onScreen(fx, mode, "read_log", { limit: 50 });
  assert.deepEqual(shownGroups(third.value).map((group) => group.kind), ["request", "grant_renewed"]);
});

test("the same for an entry of a later page of the screen, and a key that a round alone asked for is not kept for the screen", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  world.advance(HOUR_MS);
  const old = fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/drafts", "DELETE")]);
  world.advance(8 * DAY_MS);
  for (let i = 0; i < 3; i += 1) {
    world.advance(60000);
    fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
  }
  const mode = screenOnly(fx, [], (key) => key === old.key);
  const first = await onScreen(fx, mode, "read_log", { limit: 3 });
  assert.equal(first.value.has_more, true);
  const before = world.runtime.log_pages[0].before_ms;
  const page = await onScreen(fx, mode, "read_log_page", { before_ms: before });
  assert.ok(shownGroups(page.value).some((group) => group.kind === "unverified"));
  assert.deepEqual(heldReads(world), { keys: [old.key], shown: [old.key], pages: [] });
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "verified");
  assert.equal(heldReads(world), undefined);
  const bodies = askedBodies(world).filter((key) => key === old.key).length;
  const again = await onScreen(fx, mode, "read_log_page", { before_ms: before });
  const groups = shownGroups(again.value);
  assert.ok(groups.every((group) => group.kind !== "unverified"));
  assert.ok(groups.some((group) => group.kind === "request" && group.action === "delete"));
  assert.equal(askedBodies(world).filter((key) => key === old.key).length, bodies);
  assert.equal(heldReads(world), undefined);
  const older = await onScreen(fx, mode, "read_security_record", { limit: 50, before_ms: before });
  assert.ok(older.value.items.some((item) => item.kind === "deleted"));

  // A control key a round of a synchronization finds held back and reads at the next round was
  // never asked for by the screen: nothing is kept.
  const own = S.fixture(source);
  await S.start(own);
  const written = own.nodes[0].record("c", [{ t: "connection_created", time_ms: own.world.now, record_id: "r", provider: "slack", scope: "" }]);
  own.world.fault("POST /api/secure/log/bodies", (request) => ({
    status: 200, body: { entries: [], missing: JSON.parse(request.body).keys },
  }), 1);
  await nextDay(own);
  assert.deepEqual(heldReads(own.world), { keys: [written.key], shown: [], pages: [] });
  await nextDay(own);
  assert.equal(own.world.state.log.status, "verified");
  assert.equal(heldReads(own.world), undefined);
  assert.equal(own.world.stored("log.recovered"), undefined);
});

test("A3: a key of the screen that an answer of the bodies ends in front of is asked for by the next round as the first key of its request: an answer that ends in front of it again is a read held back, and what the round reads is on the screen", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  const written = [];
  for (let i = 0; i < 3; i += 1) {
    world.advance(HOUR_MS);
    written.push(fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]));
  }
  // The backend answers the keys of a request in their order and ends in front of one key,
  // whatever stands before it: that key and the keys after it are unread.
  const stop = written[1].key;
  const ending = world.fault("POST /api/secure/log/bodies", (request) => {
    const answer = JSON.parse(world.api("POST", "/api/secure/log/bodies", null, request.body).body);
    const keys = JSON.parse(request.body).keys;
    const at = keys.indexOf(stop);
    if (at < 0) return undefined;
    return {
      status: 200, body: {
        entries: answer.entries.filter((item) => keys.indexOf(item.key) < at), missing: [], unread: keys.slice(at),
      },
    };
  });
  // The screen: the answer ends early, which holds nothing back. The two entries it did not
  // reach are shown as not verified, and their keys go to the rounds.
  const first = await S.call(fx, "read_log", { limit: 50 });
  assert.deepEqual(shownGroups(first.value).map((group) => group.kind), ["unverified", "unverified", "request", "grant_renewed"]);
  assert.equal(world.state.log.store, "verified");
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.deepEqual(heldReads(world), {
    keys: [written[1].key, written[2].key], shown: [written[1].key, written[2].key], pages: [],
  });
  // Every round asks for those keys in front of everything else. An answer that ends in front
  // of the first key of the request names no key: the read is held back.
  const states = [];
  for (let day = 0; day < 4; day += 1) {
    await nextDay(fx);
    states.push(world.state.log.status + ":" + world.state.log.store + ":" + world.reports.slice(-1)[0].blocked_attempts);
    assert.deepEqual(JSON.parse(world.sent("POST /api/secure/log/bodies").slice(-1)[0].body).keys, [written[1].key, written[2].key]);
  }
  assert.deepEqual(states, ["pending:blocked:1", "pending:blocked:2", "pending:blocked:3", "attention:blocked:4"]);
  assert.equal(world.state.log.store_failure, "bodies:skipped");
  assert.deepEqual(world.securityStatuses.slice(-1)[0].reasons, ["verification_blocked"]);
  // The backend answers the round: the count ends, and the screen shows both entries, though the
  // backend ends its answers to the screen where it did before.
  ending.times = 0;
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(heldReads(world), undefined);
  ending.times = Infinity;
  const second = await S.call(fx, "read_log", { limit: 50 });
  const groups = shownGroups(second.value);
  assert.deepEqual(groups.map((group) => group.kind), ["request", "grant_renewed"]);
  assert.equal(groups[0].count, 3);
  assert.equal(heldReads(world), undefined);
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
});

/** What the rounds kept for the screen of a fixture (log.recovered), opened with the key of the
 *  account as the program derives it: {v, entries, pages, found}, or null when nothing is kept. */
function openRecovered(fx) {
  const sealed = fx.world.stored("log.recovered");
  if (sealed === undefined) return null;
  const key = Buffer.from(crypto.hkdfSync("sha256", fx.keys.masterKey, Buffer.alloc(0), utf8("pickle.secure.v1.log-cache"), 32));
  const aad = utf8("pickle.secure.v1.log-recovered\n" + fx.world.userId + "\n" + fx.keys.keyId);
  return JSON.parse(bridge.aeadOpen("chacha20poly1305", key, bytes(sealed.nonce), aad, bytes(sealed.ct)).toString("utf8"));
}

/** Has the backend of a fixture answer the request for listing addresses with an error while
 *  the log screen is running (mode.screen) and held(pages) says so for the pages it asks for. */
function listingsFromScreen(fx, mode, held) {
  return fx.world.fault("POST /api/secure/log/read", (request) => {
    if (!mode.screen || !held(JSON.parse(request.body).pages)) return undefined;
    return { status: 503, body: { detail: "log_store_unreachable" } };
  });
}

test("a backend that gives the rounds the listings of the first page and not the screen shows the user what the rounds read: the page is made from the listing page a round kept, as new as the last round", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  for (let i = 0; i < 3; i += 1) {
    world.advance(HOUR_MS);
    fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
  }
  const mode = { screen: false };
  listingsFromScreen(fx, mode, () => true);
  // The screen: its listings are held back, it kept nothing, and it shows nothing of format 3.
  const first = await onScreen(fx, mode, "read_log", { limit: 50 });
  assert.equal(first.value.status, "pending");
  assert.deepEqual(shownGroups(first.value), []);
  assert.equal(world.state.log.store, "blocked");
  assert.deepEqual(heldReads(world), { keys: [], shown: [], pages: [0] });
  // The next round reads the two listings as the screen asks for them, and the entries of the
  // page: the count ends, and what it read is kept.
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "verified");
  assert.equal(heldReads(world), undefined);
  const kept = openRecovered(fx);
  // (The entries of a listing page are kept with the page.)
  assert.deepEqual(kept.pages.map((page) => [page[0], page[2], page[3].length, page[4].length]), [[0, false, 4, 4]]);
  assert.equal(kept.entries.length, 0);
  // The screen again, its listings held back as before: the page is the one the round read, and
  // the screen asks for no body.
  const bodies = world.sent("POST /api/secure/log/bodies").length;
  const second = await onScreen(fx, mode, "read_log", { limit: 50 });
  const groups = shownGroups(second.value);
  assert.deepEqual(groups.map((group) => group.kind), ["request", "grant_renewed"]);
  assert.equal(groups[0].count, 3);
  assert.ok(groups.every((group) => group.verified === true));
  assert.equal(world.sent("POST /api/secure/log/bodies").length, bodies);
  // From the read that was held back on, every round of a synchronization reads those listing
  // pages for the screen, until the screen reads them itself: an entry written after the round
  // that followed the read of the screen is on the screen at its next opening.
  assert.ok(world.stored("log.withheld").watch_ms > world.now + 29 * DAY_MS);
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(heldReads(world), undefined);
  world.advance(HOUR_MS);
  fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/labels", "GET")]);
  const listings = world.sent("POST /api/secure/log/read").length;
  await nextDay(fx);
  assert.deepEqual(JSON.parse(world.sent("POST /api/secure/log/read").slice(-1)[0].body).pages.map((page) => page.prefix), ["c", "u"]);
  assert.equal(world.sent("POST /api/secure/log/read").length, listings + 2);
  const watched = await onScreen(fx, mode, "read_log", { limit: 50 });
  assert.ok(shownGroups(watched.value).some((group) => group.kind === "request" && group.action === "read"));
  // That read of the screen was held back again: the rounds read the page again, and a new entry
  // is on the screen after the round that follows it. The count never passes one.
  for (let day = 0; day < 5; day += 1) {
    world.advance(DAY_MS);
    fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/drafts/" + day, "DELETE")]);
    world.advance(HOUR_MS);
    await S.event(fx, "foreground");
    assert.equal(world.state.log.status, "verified", "day " + day);
    const shown = await onScreen(fx, mode, "read_log", { limit: 50 });
    const requests = shownGroups(shown.value).filter((group) => group.kind === "request");
    assert.equal(requests.reduce((sum, group) => sum + group.count, 0), 5 + day, "day " + day);
    assert.equal(world.state.log.status, "pending", "day " + day);
    assert.equal(world.stored("log.blocked").count, 1, "day " + day);
  }
  assert.ok(world.securityStatuses.every((told) => told.status !== "attention"));
  // The backend gives the screen its listings: the screen reads the page itself, and the listing
  // page the rounds kept is dropped.
  world.clearFaults();
  const own = await S.call(fx, "read_log", { limit: 50 });
  assert.equal(own.value.status, "verified");
  assert.equal(openRecovered(fx), null);
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.equal(world.stored("log.withheld"), undefined);
  const after = world.sent("POST /api/secure/log/read").length;
  await nextDay(fx);
  assert.equal(world.sent("POST /api/secure/log/read").length, after + 1);
});

test("A3: a later page of the screen that is held back is made from the listing page a round kept for it, and later pages that keep being held back where the rounds kept nothing mark the log after such reads on three days, whatever the rounds read in between", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  const node = fx.nodes[0];
  // Listing pages of three keys: the listings the first page of the screen reads do not reach
  // the second page, and the screen asks for the listings of that page.
  world.pageSize = 3;
  for (let i = 0; i < 4; i += 1) {
    world.advance(HOUR_MS);
    node.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/drafts/" + i, "DELETE")]);
  }
  world.advance(8 * DAY_MS);
  const recent = (count) => {
    for (let i = 0; i < count; i += 1) {
      world.advance(60000);
      node.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
    }
  };
  recent(3);
  // The backend holds the listings of the later pages back from the screen, and answers every
  // other request, the ones of the rounds among them.
  const mode = { screen: false };
  const fault = listingsFromScreen(fx, mode, (pages) => pages.some((page) => page.key_marker !== ""));
  const open = async () => {
    const shown = await onScreen(fx, mode, "read_log", { limit: 3 });
    assert.equal(shown.value.has_more, true);
    return world.runtime.log_pages[0].before_ms;
  };
  const before = await open();
  const held = await onScreen(fx, mode, "read_log_page", { before_ms: before });
  assert.deepEqual(held, { ok: false, code: "log_store_unreachable" });
  assert.deepEqual(heldReads(world), { keys: [], shown: [], pages: [before] });
  assert.equal(world.stored("log.denied").pages.length, 1);
  assert.equal(world.stored("log.denied").pages[0].before_ms, before);
  // The round reads that page as the screen asks for it and keeps it.
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "verified");
  assert.equal(heldReads(world), undefined);
  assert.deepEqual(openRecovered(fx).pages.map((page) => [page[0], page[2], page[3].length]), [[before, true, 3]]);
  // The same page again, held back again: it is made from what the round kept, and it does not
  // add to the count.
  const again = await onScreen(fx, mode, "read_log_page", { before_ms: before });
  assert.equal(again.ok, true);
  const deleted = shownGroups(again.value).filter((group) => group.kind === "request" && group.action === "delete");
  assert.equal(deleted.reduce((sum, group) => sum + group.count, 0), 3);
  assert.equal(again.value.has_more, true);
  assert.equal(world.stored("log.denied").pages.length, 1);
  // New entries move the time the second page begins below. The rounds kept no page that begins
  // there: each such read of the screen is counted, and the rounds that read the page in
  // between end nothing of that count.
  const states = [];
  for (let day = 0; day < 3; day += 1) {
    world.advance(DAY_MS + HOUR_MS);
    recent(2);
    await S.event(fx, "foreground");
    const moved = await open();
    assert.ok(moved > before);
    const page = await onScreen(fx, mode, "read_log_page", { before_ms: moved });
    assert.deepEqual(page, { ok: false, code: "log_store_unreachable" }, "day " + day);
    await world.settle(1000);
    states.push(world.state.log.status + ":" + world.state.log.store + ":" + world.stored("log.denied").pages.length);
  }
  assert.deepEqual(states, ["verified:verified:2", "verified:verified:3", "attention:blocked:4"]);
  assert.deepEqual(world.securityStatuses.slice(-1)[0].reasons, ["verification_blocked"]);
  // A round that reads everything it asks for does not end it.
  await nextDay(fx);
  assert.equal(world.state.log.status, "attention");
  assert.equal(world.state.log.store, "blocked");
  assert.equal(world.state.log.store_failure, "screen:held");
  assert.equal(world.state.log.store_failing_ms, world.stored("log.denied").pages[0].t);
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
  // The backend gives the screen the listing of that page: the count ends, and a round that the
  // read starts clears the mark.
  fault.times = 0;
  const lowest = Math.min(...world.stored("log.denied").pages.map((page) => page.before_ms));
  assert.equal(lowest, before);
  const served = await S.call(fx, "read_log_page", { before_ms: lowest });
  assert.equal(served.ok, true);
  assert.equal(world.stored("log.denied"), undefined);
  await world.settle(1000);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.securityStatuses.slice(-1)[0].status, "ok");
});

test("a later page of the screen that fails for the network of the device, or once for the backend, counts nothing that marks the log: the page the screen reads next ends the count", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  world.pageSize = 2;
  for (let i = 0; i < 6; i += 1) {
    world.advance(HOUR_MS);
    fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
  }
  const first = await S.call(fx, "read_log", { limit: 2 });
  assert.equal(first.value.has_more, true);
  const before = world.runtime.log_pages[0].before_ms;
  // The device has no network, on four days.
  world.fault(() => true, "transport");
  for (let day = 0; day < 4; day += 1) {
    world.advance(DAY_MS);
    const page = await S.call(fx, "read_log_page", { before_ms: before });
    assert.deepEqual(page, { ok: false, code: "log_store_unreachable" });
    await world.settle(40000);
  }
  assert.equal(world.stored("log.denied"), undefined);
  assert.notEqual(world.state.log.status, "attention");
  world.clearFaults();
  world.advance(HOUR_MS);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "verified");
  assert.equal(heldReads(world), undefined);

  // The backend answers one request for the listings of a later page with an error.
  const once = S.fixture(source);
  once.world.pageSize = 2;
  await S.start(once);
  for (let i = 0; i < 6; i += 1) {
    once.world.advance(HOUR_MS);
    once.nodes[0].record("u", [S.providerRequest(once.world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
  }
  await S.call(once, "read_log", { limit: 2 });
  const below = once.world.runtime.log_pages[0].before_ms;
  once.world.fault("POST /api/secure/log/read", { status: 500 }, 1);
  const failed = await S.call(once, "read_log_page", { before_ms: below });
  assert.deepEqual(failed, { ok: false, code: "log_store_unreachable" });
  assert.equal(once.world.stored("log.denied").pages.length, 1);
  const retried = await S.call(once, "read_log_page", { before_ms: below });
  assert.equal(retried.ok, true);
  assert.equal(once.world.stored("log.denied"), undefined);
  assert.equal(heldReads(once.world), undefined);
  for (let day = 0; day < 4; day += 1) {
    await nextDay(once);
    assert.equal(once.world.state.log.status, "verified", "day " + day);
  }
});

test("A3: a later page that is held back from the screen and then given ends what was noted for it: the next opening of the screen reads its listings on from the first page down to that page and ends the note without a scroll, the listings must be given all the way down to it, and while the backend holds those reads back each day adds a note and the third day marks the log", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  const node = fx.nodes[0];
  // Listing pages of three keys, and pages of the screen of three events: every page of the
  // screen below the first needs a listing page more.
  world.pageSize = 3;
  for (let i = 0; i < 24; i += 1) {
    world.advance(HOUR_MS);
    node.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
  }
  // The backend refuses the requests of the screen for listings below its first pages, after as
  // many as allowed, and answers every other request, the ones of the rounds among them.
  const mode = { screen: false };
  let allowed = Infinity;
  listingsFromScreen(fx, mode, (pages) => {
    if (!pages.some((page) => page.key_marker !== "")) return false;
    allowed -= 1;
    return allowed < 0;
  });
  const read = (before) => onScreen(fx, mode, "read_security_record", before === undefined ? { limit: 3 } : { limit: 3, before_ms: before });
  const notes = () => (world.stored("log.denied") || { pages: [] }).pages.map((note) => note.before_ms);
  const listings = () => world.sent("POST /api/secure/log/read").length;
  // The user scrolls to the third page, whose listings are held back.
  const first = await read();
  const second = await read(first.value.next_before_ms);
  const third = second.value.next_before_ms;
  allowed = 0;
  assert.deepEqual(await read(third), { ok: false, code: "log_store_unreachable" });
  assert.deepEqual(notes(), [third]);
  // A round in between reads the page for the screen and ends nothing of the note.
  allowed = Infinity;
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "verified");
  assert.deepEqual(notes(), [third]);
  // The next opening of the screen, which the backend answers: the listings are read on down to
  // that page and the note ends. The user did not scroll, and the page is then made from those
  // listings, without a request.
  let asked = listings();
  await read();
  assert.deepEqual(notes(), []);
  assert.equal(listings(), asked + 2);
  asked = listings();
  const again = await read(third);
  assert.equal(again.ok, true);
  assert.equal(listings(), asked);
  // A page further down is held back. In a new runtime the backend lets three of the requests
  // through that read the listings on down to it, and holds the fourth back: the note stays, and
  // the request held back is noted with it. The next opening reads on from where that one
  // stopped (the request held back is the only one below the first page that is sent twice),
  // and the note ends.
  const fourth = await read(again.value.next_before_ms);
  allowed = 0;
  const fifth = fourth.value.next_before_ms;
  assert.deepEqual(await read(fifth), { ok: false, code: "log_store_unreachable" });
  assert.deepEqual(notes(), [fifth]);
  allowed = Infinity;
  await S.start(fx);
  allowed = 3;
  asked = listings();
  await read();
  assert.equal(notes().length, 1);
  assert.equal(listings(), asked + 5);
  allowed = Infinity;
  await read();
  assert.deepEqual(notes(), []);
  const markers = world.sent("POST /api/secure/log/read").slice(asked)
    .map((request) => JSON.parse(request.body).pages.map((page) => page.prefix + page.key_marker).join(" "));
  assert.equal(markers.length - new Set(markers).size, 2);
  // The backend holds back every read of the screen below its first page, day after day: the
  // page the user scrolls to on the first day, and the reading down to it at every opening.
  // Each day adds a note, whatever the rounds read in between, and the third day after the
  // first marks the log.
  await S.start(fx);
  allowed = 0;
  assert.deepEqual(await read((await read()).value.next_before_ms), { ok: false, code: "log_store_unreachable" });
  const states = [];
  for (let day = 0; day < 3; day += 1) {
    world.advance(DAY_MS + HOUR_MS);
    allowed = Infinity;
    await S.event(fx, "foreground");
    allowed = 0;
    await read();
    await world.settle(0);
    states.push(world.state.log.status + ":" + notes().length);
  }
  assert.deepEqual(states, ["verified:2", "verified:3", "attention:4"]);
  assert.equal(world.state.log.store_failure, "screen:held");
  assert.deepEqual(world.securityStatuses.slice(-1)[0].reasons, ["verification_blocked"]);
  // The backend answers an opening: the listings are read on, every note ends, and the round
  // that follows clears the mark.
  allowed = Infinity;
  await read();
  await world.settle(0);
  assert.deepEqual(notes(), []);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.securityStatuses.slice(-1)[0].status, "ok");
});

test("a later page that was held back from the screen is ended by listings the screen reads itself that name its keys: the first listings of the next opening end it without a scroll, and a note of a screen that is not opened again ends thirty days after it was made", async () => {
  const fx = S.fixture(source, { device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  const node = fx.nodes[0];
  for (let i = 0; i < 6; i += 1) {
    world.advance(HOUR_MS);
    node.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
  }
  // The device kept a first page. In a later runtime the backend answers no request for
  // listing addresses of the screen with anything but an error: the first page is the kept one,
  // and the second page is held back.
  await S.call(fx, "read_log", { limit: 2 });
  const mode = { screen: false };
  const fault = listingsFromScreen(fx, mode, () => true);
  await S.start(fx);
  const kept = await onScreen(fx, mode, "read_log", { limit: 2 });
  assert.equal(kept.value.has_more, true);
  const before = world.runtime.log_pages[0].before_ms;
  assert.deepEqual(await onScreen(fx, mode, "read_log_page", { before_ms: before }), { ok: false, code: "log_store_unreachable" });
  assert.deepEqual(world.stored("log.denied").pages.map((read) => read.before_ms), [before]);
  // The backend answers again. Entries arrive, so the second page of the next opening begins
  // below a later time than the page that was held back. The rounds end nothing that was noted.
  fault.times = 0;
  for (let i = 0; i < 2; i += 1) {
    world.advance(HOUR_MS);
    node.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/drafts/" + i, "DELETE")]);
  }
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(world.stored("log.denied").pages.length, 1);
  // The first page of the screen: its listings name the keys of the page that was held back.
  const opened = await S.call(fx, "read_log", { limit: 2 });
  assert.equal(opened.value.status, "verified");
  assert.ok(world.runtime.log_pages[0].before_ms > before);
  assert.equal(world.stored("log.denied"), undefined);
  assert.ok(world.securityStatuses.every((told) => told.status !== "attention"));

  // A page far down that is held back once, on a device whose user does not open the screen
  // again for a month: what was noted ends thirty days later, and a read held back after that is
  // the first of its kind.
  const far = S.fixture(source);
  far.world.pageSize = 3;
  await S.start(far);
  for (let i = 0; i < 15; i += 1) {
    far.world.advance(HOUR_MS);
    far.nodes[0].record("u", [S.providerRequest(far.world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
  }
  const deep = async () => {
    const top = await S.call(far, "read_security_record", { limit: 3 });
    const next = await S.call(far, "read_security_record", { limit: 3, before_ms: top.value.next_before_ms });
    far.world.fault("POST /api/secure/log/read", { status: 500 }, 1);
    assert.deepEqual(
      await S.call(far, "read_security_record", { limit: 3, before_ms: next.value.next_before_ms }),
      { ok: false, code: "log_store_unreachable" });
    return far.world.stored("log.denied").pages;
  };
  const once = await deep();
  assert.equal(once.length, 1);
  far.world.advance(31 * DAY_MS);
  await S.start(far);
  assert.equal(far.world.state.log.status, "verified");
  const again = await deep();
  assert.equal(again.length, 1);
  assert.ok(again[0].t > once[0].t);
});

test("what the rounds keep for the screen has its limits: of entries that hold more events than the device keeps, the ones kept first leave, and the screen asks for them again", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  // Six entries of 100 events each: 600 events, and the device keeps 512. The first page of the
  // screen shows the five latest, and the summary counts all six.
  const heavy = [];
  for (let i = 0; i < 6; i += 1) {
    world.advance(HOUR_MS);
    const events = [];
    for (let at = 0; at < 100; at += 1) events.push(S.providerRequest(world.now + at, "/gmail/v1/users/me/messages/" + i + "-" + at, "POST"));
    heavy.push(fx.nodes[0].record("u", events));
  }
  const names = heavy.map((entry) => entry.key);
  const mode = screenOnly(fx, [], (key) => names.indexOf(key) >= 0);
  const first = await onScreen(fx, mode, "read_log", { limit: 500 });
  assert.equal(shownGroups(first.value).filter((group) => group.kind === "unverified").length, 5);
  assert.equal(heldReads(world).keys.length, 6);
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "verified");
  // Of the entries a round kept at the same time, the earliest leaves first.
  const kept = openRecovered(fx);
  assert.equal(kept.entries.length, 5);
  assert.equal(kept.entries.reduce((sum, item) => sum + item[3].items.length, 0), 500);
  assert.ok(kept.entries.every((item) => item[0] !== "3:" + names[0].slice(names[0].indexOf("/u/") + 3)));
  // The five kept are shown with their events; the one that left is asked for again (for the
  // summary), held back again, and goes to the rounds again.
  const second = await onScreen(fx, mode, "read_log", { limit: 500 });
  const groups = shownGroups(second.value);
  assert.equal(groups.filter((group) => group.kind === "unverified").length, 0);
  assert.equal(groups.filter((group) => group.kind === "request").reduce((sum, group) => sum + group.count, 0), 500);
  assert.deepEqual(heldReads(world).keys, [names[0]]);

  // Five entries of 100 events with long strings: fewer events than the device keeps, and more
  // bytes than it keeps (262,144). The entries kept first leave until the value is within them.
  const wide = S.fixture(source);
  await S.start(wide);
  const long = [];
  for (let i = 0; i < 5; i += 1) {
    wide.world.advance(HOUR_MS);
    const events = [];
    for (let at = 0; at < 100; at += 1) {
      events.push(Object.assign(
        S.providerRequest(wide.world.now + at, "/" + "p".repeat(300) + "/" + i + "-" + at, "POST"), { context: "c".repeat(300) }));
    }
    long.push(wide.nodes[0].record("u", events));
  }
  const wideNames = long.map((entry) => entry.key);
  const wideMode = screenOnly(wide, [], (key) => wideNames.indexOf(key) >= 0);
  await onScreen(wide, wideMode, "read_log", { limit: 500 });
  wide.world.advance(2 * 60000);
  await S.event(wide, "foreground");
  assert.equal(wide.world.state.log.status, "verified");
  const wideKept = openRecovered(wide);
  assert.ok(Buffer.byteLength(JSON.stringify(wideKept), "utf8") <= 262144);
  assert.equal(wideKept.entries.length, 4);
  assert.ok(wideKept.entries.every((item) => item[0] !== "3:" + wideNames[0].slice(wideNames[0].indexOf("/u/") + 3)));
  // Every string kept is cut to 160 characters.
  assert.ok(wideKept.entries.every((item) => item[3].items.every((shown) => shown.target.length === 160 && shown.context.length === 160)));
});

test("the later pages of the screen are made from the listings its first page read: no listing is asked for, and listings that do not reach a page are read on where they stopped", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  for (let i = 0; i < 9; i += 1) {
    world.advance(60000);
    fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, i % 2 === 0 ? "GET" : "POST")]);
  }
  const first = await S.call(fx, "read_log", { limit: 3 });
  assert.equal(first.value.has_more, true);
  const listings = world.sent("POST /api/secure/log/read").length;
  const later = await S.call(fx, "read_log_page", { before_ms: world.runtime.log_pages[0].before_ms });
  assert.equal(later.ok, true);
  assert.equal(later.value.has_more, false);
  assert.equal(shownGroups(later.value).reduce((sum, group) => sum + group.count, 0), 7);
  const record = await S.call(fx, "read_security_record", { limit: 50, before_ms: world.runtime.log_pages[0].before_ms });
  assert.equal(record.value.items.reduce((sum, item) => sum + item.count, 0), 7);
  assert.equal(world.sent("POST /api/secure/log/read").length, listings);
  // Listing pages of four keys: the first listings do not hold the second page of the screen.
  // They are read on from the markers of the store, two pages more, and name every key then.
  const short = S.fixture(source);
  short.world.pageSize = 4;
  await S.start(short);
  for (let i = 0; i < 9; i += 1) {
    short.world.advance(60000);
    short.nodes[0].record("u", [S.providerRequest(short.world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
  }
  await S.call(short, "read_log", { limit: 3 });
  const asked = short.world.sent("POST /api/secure/log/read").length;
  const below = short.world.runtime.log_pages[0].before_ms;
  const page = await S.call(short, "read_log_page", { before_ms: below });
  assert.equal(page.ok, true);
  assert.equal(page.value.has_more, false);
  assert.equal(shownGroups(page.value).reduce((sum, group) => sum + group.count, 0), 7);
  assert.equal(short.world.sent("POST /api/secure/log/read").length, asked + 2);
  const markers = JSON.parse(short.world.sent("POST /api/secure/log/read").slice(-1)[0].body).pages.map((item) => item.key_marker);
  assert.ok(markers.every((marker) => marker !== "" && !marker.endsWith("~")));
  // The same page in a runtime whose screen has read no first page: the screen reads the first
  // pages of the two listings and reads them on from there. No request names the time of the
  // page: every listing it is made from goes on from the one before it.
  await S.start(short);
  const from = short.world.sent("POST /api/secure/log/read").length;
  const again = await S.call(short, "read_log_page", { before_ms: below });
  assert.equal(again.ok, true);
  assert.equal(shownGroups(again.value).reduce((sum, group) => sum + group.count, 0), 7);
  const requests = short.world.sent("POST /api/secure/log/read").slice(from)
    .map((request) => JSON.parse(request.body).pages.map((item) => item.key_marker));
  assert.equal(requests.length, 3);
  assert.deepEqual(requests[0], ["", ""]);
  assert.ok(requests.every((asked) => asked.every((marker) => !marker.endsWith("~"))));
});

test("a runtime that ends in the middle of a read of the log leaves what the device kept as it was, and the end of an account erases what the rounds kept for the screen", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  world.advance(HOUR_MS);
  const used = fx.nodes[0].record("u", [S.providerRequest(world.now)]);
  // The read of the screen waits for an answer that does not come, and the app is ended.
  world.fault("POST /api/secure/log/bodies", "hang");
  const pending = fx.program.procedures.read_log({ limit: 50 });
  pending.then(() => {}, () => {});
  await world.drain();
  const before = JSON.stringify([world.stored("log.blocked"), world.stored("log.withheld"), world.stored("log.round").unfinished]);
  world.clearFaults();
  await S.start(fx);
  assert.equal(JSON.stringify([world.stored("log.blocked"), world.stored("log.withheld"), world.stored("log.round").unfinished]), before);
  assert.notEqual(world.state.log.status, "attention");
  // A read held back from the screen, read again by a round: kept for the screen. The account
  // ends, and nothing of it stays on the device.
  const mode = screenOnly(fx, [], (key) => key === used.key);
  await onScreen(fx, mode, "read_log", { limit: 50 });
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.notEqual(world.stored("log.recovered"), undefined);
  await S.event(fx, "account_end", { reason: "account_deleted" });
  for (const key of ["log.recovered", "log.withheld", "log.denied", "log.cache", "log.round", "log.seen", "log.seen.0"]) {
    assert.equal(world.store.get(key), undefined, key);
  }
});

test("the entries of the listing pages the rounds keep take no place from an entry the screen asked for: it stays kept however many entries the rounds read for the first page", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  world.advance(HOUR_MS);
  const old = fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/drafts", "DELETE")]);
  world.advance(8 * DAY_MS);
  for (let i = 0; i < 3; i += 1) {
    world.advance(60000);
    fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
  }
  // The body of one entry of a later page is held back from the screen, and a round reads it.
  const mode = screenOnly(fx, [], (key) => key === old.key);
  await onScreen(fx, mode, "read_log", { limit: 3 });
  await onScreen(fx, mode, "read_log_page", { before_ms: world.runtime.log_pages[0].before_ms });
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  const id = "3:" + old.key.slice(old.key.indexOf("/u/") + 3);
  assert.deepEqual(openRecovered(fx).entries.map((item) => item[0]), [id]);
  // The first listing pages are held back from the screen as well: from then on every round
  // keeps the first page for the screen, 100 events of it, while 120 entries arrive a day.
  listingsFromScreen(fx, mode, () => true);
  await onScreen(fx, mode, "read_log", { limit: 3 });
  for (let day = 0; day < 6; day += 1) {
    for (let i = 0; i < 120; i += 1) {
      world.advance(60000);
      fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + day + "-" + i, "GET")]);
    }
    await nextDay(fx);
    assert.equal(world.state.log.status, "verified", "day " + day);
  }
  const kept = openRecovered(fx);
  assert.deepEqual(kept.entries.map((item) => item[0]), [id]);
  assert.deepEqual(kept.pages.map((page) => [page[0], page[3].length, page[4].length]), [[0, 100, 100]]);
});

// ---- The reads of the chains of format 1 and format 2 that are held back from the screen ----

test("an entry of a chain of format 2 whose object the backend gives the rounds and not the screen is on the screen with its content, and when the rounds do not receive it either, the log is marked", async () => {
  const fx = S.fixture(source, { nodes: 0, legacy: 1, device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  const node = fx.legacy[0];
  for (let i = 0; i < 3; i += 1) {
    world.advance(HOUR_MS);
    node.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
  }
  const mode = { screen: false };
  const fault = world.fault("POST /api/secure/log/store/objects", () =>
    (mode.screen ? { status: 503, body: { detail: "log_store_unreachable" } } : undefined));
  // The screen: the objects of the chain are held back, and none of its entries is shown. The
  // versions it asked for go to the rounds.
  const first = await onScreen(fx, mode, "read_log", { limit: 50 });
  assert.deepEqual(shownGroups(first.value), []);
  const held = heldReads(world);
  assert.deepEqual(Object.keys(held).sort(), ["keys", "objects", "pages", "shown"]);
  assert.equal(held.objects.length, 4);
  assert.ok(held.objects.every((versions) => versions.length === 1 && versions[0][0].startsWith("v1/accounts/" + world.userId + "/" + node.id + "/")));
  // The next round reads those objects, and the backend answers it: what it opened is kept.
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "verified");
  assert.equal(heldReads(world), undefined);
  assert.equal(openRecovered(fx).entries.filter((item) => item[0].startsWith("2:" + node.id + ":")).length, 4);
  // The screen again: the entries are shown with what they say, and no object is asked for.
  const asked = world.sent("POST /api/secure/log/store/objects").length;
  const second = await onScreen(fx, mode, "read_log", { limit: 50 });
  const groups = shownGroups(second.value);
  assert.deepEqual(groups.map((group) => group.kind), ["request", "grant_renewed"]);
  assert.equal(groups[0].count, 3);
  assert.equal(groups[0].requests[0].target, "gmail.googleapis.com/gmail/v1/users/me/messages/0");
  assert.equal(world.sent("POST /api/secure/log/store/objects").length, asked);
  assert.equal(heldReads(world), undefined);
  // A runtime after it has the same.
  await S.start(fx);
  const third = await onScreen(fx, mode, "read_log", { limit: 50 });
  assert.equal(shownGroups(third.value)[0].count, 3);
  assert.equal(world.sent("POST /api/secure/log/store/objects").length, asked);

  // A new entry, and a backend that hands its object to nobody: every round is held back.
  world.advance(HOUR_MS);
  node.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/drafts", "DELETE")]);
  fault.times = 0;
  world.fault("POST /api/secure/log/store/objects", { status: 503, body: { detail: "log_store_unreachable" } });
  await S.call(fx, "read_log", { limit: 50 });
  assert.equal(heldReads(world).objects.length, 1);
  // (The round the screen started read the object of the last seq of the chain as well, to see
  // how far the node wrote: it is the first round held back.)
  assert.equal(world.stored("log.blocked").count, 1);
  const states = [];
  for (let day = 0; day < 4; day += 1) {
    await nextDay(fx);
    states.push(world.state.log.status + ":" + world.state.log.store + ":" + world.reports.slice(-1)[0].blocked_attempts);
  }
  assert.deepEqual(states, ["pending:blocked:2", "pending:blocked:3", "attention:blocked:4", "attention:blocked:5"]);
  assert.equal(world.state.log.store_failure, "objects:503");
  assert.deepEqual(world.securityStatuses.slice(-1)[0].reasons, ["verification_blocked"]);
  world.clearFaults();
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(heldReads(world), undefined);
});

test("A3: the listing of a chain of format 2 that is held back from the screen is noted, a round that reads it ends nothing of the note, and the opening of the screen that reads the chain from its end ends it: listings that keep being held back mark the log after three days", async () => {
  const fx = S.fixture(source, { nodes: 0, legacy: 1, device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  const node = fx.legacy[0];
  for (let i = 0; i < 3; i += 1) {
    world.advance(HOUR_MS);
    node.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
  }
  // The backend holds the listing of a chain back from the screen: the request for the listing
  // addresses that names nodes.
  const mode = { screen: false };
  const fault = world.fault("POST /api/secure/log/store/listings", (request) =>
    (mode.screen && JSON.parse(request.body).nodes.length > 0 ? { status: 503, body: { detail: "log_store_unreachable" } } : undefined));
  await S.start(fx);
  const first = await onScreen(fx, mode, "read_log", { limit: 50 });
  assert.deepEqual(shownGroups(first.value), []);
  assert.deepEqual(heldReads(world).chains, [[node.id, 0, 0]]);
  assert.deepEqual(Object.keys(world.stored("log.denied").chains), [node.id]);
  assert.equal(world.stored("log.denied").chains[node.id].length, 1);
  // The next round lists the chain and is answered: the read leaves the reads the rounds make
  // again, and the note of the screen stays. The screen takes the keys of a chain from its own
  // listings alone, so the next opening, held back again, shows none of its entries.
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "verified");
  assert.equal(heldReads(world), undefined);
  const second = await onScreen(fx, mode, "read_log", { limit: 50 });
  assert.deepEqual(shownGroups(second.value), []);
  assert.equal(world.stored("log.denied").chains[node.id].length, 1);
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  // The listing is held back from the screen day after day: each day adds a note, and the
  // rounds in between end nothing of that count.
  const states = [];
  for (let day = 0; day < 3; day += 1) {
    world.advance(DAY_MS + HOUR_MS);
    await S.start(fx);
    await onScreen(fx, mode, "read_log", { limit: 50 });
    await world.settle(1000);
    states.push(world.state.log.status + ":" + world.stored("log.denied").chains[node.id].length);
    world.advance(2 * 60000);
    await S.event(fx, "foreground");
  }
  // (The round the screen starts lists the chain as well and is held back with it; the round of
  // the synchronization that follows reads everything.)
  assert.deepEqual(states, ["pending:2", "pending:3", "attention:4"]);
  assert.equal(world.state.log.status, "attention");
  assert.equal(world.state.log.store, "blocked");
  assert.equal(world.state.log.store_failure, "screen:held");
  assert.deepEqual(world.securityStatuses.slice(-1)[0].reasons, ["verification_blocked"]);
  // The backend gives the screen the listing: the screen reads the chain from its end, the note
  // ends, and a round clears the mark.
  fault.times = 0;
  await S.start(fx);
  const served = await S.call(fx, "read_log", { limit: 50 });
  assert.equal(shownGroups(served.value).filter((group) => group.kind === "request")[0].count, 3);
  await world.settle(1000);
  assert.equal(world.stored("log.denied"), undefined);
  assert.equal(world.state.log.status, "verified");
});

test("the node prefixes of the chains of format 2 that a round listed for the screen stand in when the listing is held back from the screen", async () => {
  const fx = S.fixture(source, { nodes: 0, legacy: 1 });
  await S.start(fx);
  const world = fx.world;
  // A node of the same release that another device of the account handed a grant to: this device
  // finds its chain by the node discovery listing alone.
  const other = world.addNode({ release: fx.latest.release, measurement: fx.latest, offered: false });
  world.advance(HOUR_MS);
  other.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/drafts", "DELETE")]);
  const mode = { screen: false };
  world.fault("POST /api/secure/log/store/listings", (request) =>
    (mode.screen && JSON.parse(request.body).discovery === true ? { status: 503, body: { detail: "log_store_unreachable" } } : undefined));
  const first = await onScreen(fx, mode, "read_log", { limit: 50 });
  assert.ok(shownGroups(first.value).every((group) => group.kind !== "request"));
  assert.equal(heldReads(world).nodes, true);
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "verified");
  assert.equal(heldReads(world), undefined);
  assert.deepEqual(openRecovered(fx).found.ids.slice().sort(), [fx.legacy[0].id, other.id].sort());
  const second = await onScreen(fx, mode, "read_log", { limit: 50 });
  const requests = shownGroups(second.value).filter((group) => group.kind === "request");
  assert.equal(requests.length, 1);
  assert.equal(requests[0].action, "delete");
  // That read of the screen was held back again, and the rounds make it again.
  assert.equal(heldReads(world).nodes, true);
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
  assert.equal(heldReads(world), undefined);
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
  assert.deepEqual(heldReads(world), { keys: [used.key], shown: [used.key], pages: [] });
  assert.equal(world.stored("log.blocked").count, 1);
  // 130 objects under 130 node ids no node has, all later than the entry: one round asks for the
  // documents of 128 nodes for the keys of its listing. The key that was held back has a request
  // of its own, sent before the round asks for a listing.
  for (let i = 0; i < 130; i += 1) {
    world.advance(1000);
    new bridge.Node(world, { release: "v2.4.0", measurement: fx.measurement, document: false })
      .record("c", [{ t: "grant_revoked", time_ms: world.now }]);
  }
  const before = world.requests.length;
  await nextDay(fx);
  const order = world.requests.slice(before).map((request) => String(request.path))
    .filter((line) => line === "/api/secure/log/documents" || line === "/api/secure/log/read");
  assert.deepEqual(order.slice(0, 2), ["/api/secure/log/documents", "/api/secure/log/read"]);
  const asked = world.sent("POST /api/secure/log/documents").slice(-3).map((request) => JSON.parse(request.body).nodes);
  assert.deepEqual(asked[0], [hidden.id]);
  assert.equal(asked[1].length + asked[2].length, 128);
  assert.equal(world.state.log.store, "blocked");
  assert.equal(world.state.log.store_failure, "documents:missing");
  assert.equal(world.stored("log.blocked").count, 2);
  assert.equal(world.reports.slice(-1)[0].undocumented_nodes, 129);
  // The two keys the round listed and had no request left for are kept for the next round, beside
  // the key that is held back.
  assert.equal(heldReads(world).keys.length, 1);
  assert.equal(heldReads(world).unjudged.length, 2);
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
  assert.equal(heldReads(world), undefined);
  const before = world.runtime.log_pages[0].before_ms;
  const page = await S.call(fx, "read_log_page", { before_ms: before });
  assert.equal(page.ok, true);
  assert.ok(shownGroups(page.value).some((group) => group.kind === "unverified"));
  assert.deepEqual(heldReads(world), { keys: [old.key], shown: [old.key], pages: [] });
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
  assert.deepEqual(heldReads(world), { keys: [], shown: [], pages: [0] });
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
  assert.equal(heldReads(world), undefined);
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });

  // An environment without a store of format 3, on a device that knows of none: a read of the
  // screen that failed once is made again, and the statement that there is no such store ends it.
  const closed = S.fixture(source, { nodes: 0, legacy: 1 });
  closed.world.routes.log = "disabled";
  await S.start(closed);
  closed.world.fault("POST /api/secure/log/read", { status: 503, body: { detail: "log_store_unreachable" } }, 1);
  await S.call(closed, "read_log", { limit: 50 });
  assert.deepEqual(heldReads(closed.world), { keys: [], shown: [], pages: [0] });
  for (let day = 0; day < 4; day += 1) {
    await nextDay(closed);
    assert.equal(closed.world.state.log.status, "verified", "day " + day);
  }
  assert.equal(heldReads(closed.world), undefined);
  assert.deepEqual(closed.world.stored("log.blocked"), { first_ms: 0, count: 0 });

  // A later page: the backend answers the request for the listings below a time with an error,
  // and then with the statement that it has no store of format 3.
  for (const answer of [{ status: 503, body: { detail: "log_store_unreachable" } }, { status: 409, body: { detail: "log_store_disabled" } }]) {
    const later = S.fixture(source);
    later.world.pageSize = 2;
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
    assert.deepEqual(heldReads(later.world), { keys: [], shown: [], pages: [before] });
    later.world.advance(2 * 60000);
    await S.event(later, "foreground");
    assert.equal(later.world.state.log.store, "blocked", JSON.stringify(answer));
    assert.equal(later.world.stored("log.blocked").count, 1);
    later.world.clearFaults();
    later.world.advance(2 * 60000);
    await S.event(later, "foreground");
    assert.equal(later.world.state.log.status, "verified");
    assert.equal(heldReads(later.world), undefined);
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

// ---- Objects someone else wrote into a chain of format 2 ----

/** A fixture whose node of an earlier release handed the delegation on, after 2026-11-23, to a
 *  node of a measurement no list has (the backend kept its document): {fx, moved}, moved the
 *  entry of the transfer. Read by a round, the transfer counts for A1. */
async function movedFromEarlierRelease() {
  const fx = S.fixture(source, { nodes: 0, legacy: 1, device: { securityStatus: true } });
  fx.world.now = TRANSFER_DOCUMENTS_FROM_MS + DAY_MS;
  await S.start(fx);
  const world = fx.world;
  const rogue = world.addNode({ release: "v2.3.9", measurement: bridge.randomMeasurement(), format: 2, offered: false });
  world.keptDocuments.set(rogue.id, registryDocument(rogue));
  world.advance(HOUR_MS);
  const moved = fx.legacy[0].record("c", [{ t: "grant_transferred_out", time_ms: world.now, to: rogue.id }]);
  return { fx: fx, moved: moved };
}

test("A1: objects someone else wrote under the seq of a transfer in a chain of format 2 do not take the place of the entry of the node, and more of them than a round reads hold the read back", async () => {
  // Two later versions under the key of the entry, and two keys of use entries under its seq
  // that sort in front of it: the round reads the versions whose key names a control entry until
  // one is the entry of the node.
  const { fx, moved } = await movedFromEarlierRelease();
  const world = fx.world;
  world.putObject(world.bucket, moved.key, "not an entry");
  world.putObject(world.bucket, moved.key, JSON.stringify({ body: "AAAA", sig: "AAAA" }));
  const prefix = moved.key.slice(0, moved.key.indexOf("-", moved.key.lastIndexOf("/")) + 1);
  for (const filler of ["A", "B"]) {
    world.putObject(world.bucket, prefix + "0000000000001-u-001-" + fx.keys.keyId + "-" + filler.repeat(43) + "-" + filler.repeat(43), "x");
  }
  await nextDay(fx);
  assert.equal(world.state.log.status, "pending");
  assert.equal(world.state.log.newer_release_nodes, 1);
  await nextDay(fx);
  assert.equal(world.state.log.status, "attention");
  assert.equal(world.state.log.unknown_nodes, 1);

  // Nine later versions under the key of the entry: none of the eight the round reads is the
  // entry of the node, and one more is left. The read is held back, and the chain is not read
  // past that seq.
  const crowded = await movedFromEarlierRelease();
  const other = crowded.fx.world;
  for (let i = 0; i < 9; i += 1) other.putObject(other.bucket, crowded.moved.key, "not an entry " + i);
  const reached = other.stored("log.legacy").nodes[crowded.fx.legacy[0].id].seq;
  const states = [];
  for (let day = 0; day < 4; day += 1) {
    await nextDay(crowded.fx);
    states.push(other.state.log.status + ":" + other.state.log.store + ":" + other.reports.slice(-1)[0].blocked_attempts);
  }
  assert.deepEqual(states, ["pending:blocked:1", "pending:blocked:2", "pending:blocked:3", "attention:blocked:4"]);
  assert.equal(other.state.log.store_failure, "chain:keys");
  // (Each daily synchronization renewed the grant, and the node wrote an entry for it after the
  // transfer: the chain is read up to the seq before the transfer and no further.)
  assert.equal(other.stored("log.legacy").nodes[crowded.fx.legacy[0].id].seq, reached);
  assert.deepEqual(other.securityStatuses.slice(-1)[0].reasons, ["verification_blocked"]);
});

test("A3: a chain of format 2 whose listing goes on over pages that hold many objects under one seq keeps the rounds from its end and marks the log, and a long chain a node wrote is read on round after round without a count", async () => {
  // A use entry and then a transfer to a node of a measurement no list has. Under the seq of
  // the use entry, more objects than the listing pages of a round hold (pages of ten object
  // versions): the rounds do not reach the transfer.
  const fx = S.fixture(source, { nodes: 0, legacy: 1, device: { securityStatus: true } });
  fx.world.now = TRANSFER_DOCUMENTS_FROM_MS + DAY_MS;
  await S.start(fx);
  const world = fx.world;
  const node = fx.legacy[0];
  const rogue = world.addNode({ release: "v2.3.9", measurement: bridge.randomMeasurement(), format: 2, offered: false });
  world.keptDocuments.set(rogue.id, registryDocument(rogue));
  world.advance(HOUR_MS);
  const before = node.record("u", [S.providerRequest(world.now)]);
  const moved = node.record("c", [{ t: "grant_transferred_out", time_ms: world.now, to: rogue.id }]);
  world.pageSize = 10;
  const prefix = before.key.slice(0, before.key.indexOf("-", before.key.lastIndexOf("/")) + 1);
  for (let i = 0; i < 60; i += 1) {
    const filler = String(i).padStart(2, "0") + "A".repeat(41);
    world.putObject(world.bucket, prefix + "0000000000001-u-001-" + fx.keys.keyId + "-" + filler + "-" + filler, "x");
  }
  assert.ok(moved.seq > before.seq);
  const states = [];
  for (let day = 0; day < 4; day += 1) {
    await nextDay(fx);
    await world.settle(1000);
    states.push(world.state.log.status + ":" + world.state.log.store + ":" + world.reports.slice(-1)[0].blocked_attempts);
  }
  // The listing page goes on and shows the node writing nowhere beyond the seq the chain was
  // read to: every round is held back, and no round follows a round held back.
  assert.deepEqual(states, ["pending:blocked:1", "pending:blocked:2", "pending:blocked:3", "attention:blocked:4"]);
  assert.equal(world.state.log.store_failure, "chain:keys");
  assert.equal(world.state.log.newer_release_nodes, 0);

  // 9,000 entries a node wrote, one object under each seq, in listing pages of 1,000: a round
  // lists four pages, and the rounds after it read on. Nothing is counted.
  const long = S.fixture(source, { nodes: 0, legacy: 1 });
  for (let i = 0; i < 9000; i += 1) {
    long.world.advance(1000);
    long.legacy[0].record("u", [S.providerRequest(long.world.now)]);
  }
  await S.start(long);
  const walked = [long.world.state.log.status];
  for (let day = 0; day < 2; day += 1) {
    await nextDay(long);
    walked.push(long.world.state.log.status);
    assert.equal(long.world.stored("log.round").unfinished, 0, "day " + day);
    assert.equal(long.world.stored("log.blocked").count, 0, "day " + day);
  }
  assert.deepEqual(walked, ["pending", "pending", "verified"]);
});

/** Writes an object no node signed under the seq of a chain of format 2 (chain: the prefix of the
 *  chain, ending in "/"), with a key that names the time and the kind given. */
function strayObject(fx, chain, seq, timeMs, kind, mark) {
  const filler = String(mark === undefined ? "" : mark).padEnd(43, "A");
  fx.world.putObject(fx.world.bucket, chain + String(seq).padStart(20, "0") + "-" + String(timeMs).padStart(13, "0") + "-" +
    (kind || "u") + "-001-" + fx.keys.keyId + "-" + filler + "-" + filler, "x");
}

test("A1: the seq up to which a round read a chain of format 2 moves on only where the node wrote: an object someone else wrote far beyond the end of the chain, or under a seq the node has not reached, hides no transfer the node writes after it", async () => {
  for (const where of ["far", "ahead"]) {
    const fx = S.fixture(source, { nodes: 0, legacy: 1, device: { securityStatus: true } });
    fx.world.now = TRANSFER_DOCUMENTS_FROM_MS + DAY_MS;
    await S.start(fx);
    const world = fx.world;
    const node = fx.legacy[0];
    const top = () => node.chains.get(world.userId).slice(-1)[0].seq;
    world.advance(HOUR_MS);
    const used = node.record("u", [S.providerRequest(world.now)]);
    const chain = used.key.slice(0, used.key.lastIndexOf("/") + 1);
    // The object lies two seqs beyond the end of the chain (the node writes one entry with the
    // next synchronization, and the transfer under that seq after it), or far beyond it.
    const stray = where === "far" ? top() + 100000 : top() + 2;
    strayObject(fx, chain, stray, world.now, "u");
    await nextDay(fx);
    assert.equal(world.state.log.status, "verified", where);
    assert.equal(world.stored("log.legacy").nodes[node.id].seq, top(), where);
    assert.ok(top() < stray, where);
    // The node hands the delegation on to a node of a measurement no list has.
    const rogue = world.addNode({ release: "v2.3.9", measurement: bridge.randomMeasurement(), format: 2, offered: false });
    world.keptDocuments.set(rogue.id, registryDocument(rogue));
    const moved = node.record("c", [{ t: "grant_transferred_out", time_ms: world.now, to: rogue.id }]);
    if (where === "ahead") assert.equal(moved.seq, stray);
    await nextDay(fx);
    assert.equal(world.state.log.status, "pending", where);
    assert.equal(world.state.log.newer_release_nodes, 1, where);
    await nextDay(fx);
    assert.equal(world.state.log.status, "attention", where);
    assert.equal(world.state.log.unknown_nodes, 1, where);
    assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 }, where);
  }
});

test("A3: objects someone else wrote under every seq of a long chain of format 2 keep the rounds from its end: the rounds read on a few seqs each, have more to read than they read, and mark the log three days after the second synchronization", async () => {
  // 300 use entries and then a transfer to a node of a measurement no list has. Six objects
  // someone else wrote lie under every seq, and a listing page holds ten object versions: a page
  // holds the objects of one seq, and a round reads the chain on by four seqs.
  const fx = S.fixture(source, { nodes: 0, legacy: 1, device: { securityStatus: true } });
  fx.world.now = TRANSFER_DOCUMENTS_FROM_MS + DAY_MS;
  await S.start(fx);
  const world = fx.world;
  const node = fx.legacy[0];
  const rogue = world.addNode({ release: "v2.3.9", measurement: bridge.randomMeasurement(), format: 2, offered: false });
  world.keptDocuments.set(rogue.id, registryDocument(rogue));
  world.advance(HOUR_MS);
  let chain = "";
  for (let i = 0; i < 300; i += 1) {
    world.advance(1000);
    const used = node.record("u", [S.providerRequest(world.now)]);
    chain = used.key.slice(0, used.key.lastIndexOf("/") + 1);
    for (let j = 0; j < 6; j += 1) strayObject(fx, chain, used.seq, 1, "u", String(j));
  }
  node.record("c", [{ t: "grant_transferred_out", time_ms: world.now, to: rogue.id }]);
  world.pageSize = 10;
  const from = world.stored("log.legacy").nodes[node.id].seq;
  const states = [];
  for (let day = 0; day < 5; day += 1) {
    await nextDay(fx);
    await world.settle(1000);
    states.push(world.state.log.status + ":" + world.state.log.store + ":" + world.reports.slice(-1)[0].blocked_attempts);
  }
  // The eight rounds of the first synchronization count nothing. The first round of each
  // synchronization after it counts, and the fifth is three days after the second.
  assert.deepEqual(states, ["pending:verified:0", "pending:blocked:1", "pending:blocked:2", "pending:blocked:3", "attention:blocked:4"]);
  assert.equal(world.state.log.store_failure, "round:unfinished");
  assert.equal(world.state.log.newer_release_nodes, 0);
  // The chain was read on: by the seqs of 160 listing pages, one seq a page.
  assert.equal(world.stored("log.legacy").nodes[node.id].seq, from + 160);
});

test("the log screen reads eight objects under a seq of a chain of format 2: objects someone else wrote there do not take the place of the entry of the node, a key with an earlier time moves its line no further down, and more of them than the screen reads go to the rounds, which count the read as held back", async () => {
  const fx = S.fixture(source, { nodes: 0, legacy: 1, device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  const node = fx.legacy[0];
  const used = [];
  for (let i = 0; i < 4; i += 1) {
    world.advance(DAY_MS);
    used.push(node.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]));
  }
  const chain = used[0].key.slice(0, used[0].key.lastIndexOf("/") + 1);
  // The lines of the requests and of the seqs that are not verified, in the order of the screen:
  // the last character of the address of a request, "?" for a line that is not verified.
  const lines = (result) => shownGroups(result.value).filter((group) => group.kind === "request" || group.kind === "unverified")
    .map((group) => (group.kind === "unverified" ? "?" : group.requests.map((row) => row.target.slice(-1)).join(""))).join("");
  // Seven objects under the seq of the latest entry, with keys that name the first millisecond
  // (they sort in front of the key of the node, and name a time years before it).
  for (let j = 0; j < 7; j += 1) strayObject(fx, chain, used[3].seq, 1, "u", String(j));
  await S.start(fx);
  const shown = await S.call(fx, "read_log", { limit: 50 });
  // The entry of the node is the first of those lines, verified.
  assert.equal(lines(shown), "3210");
  assert.equal(heldReads(world), undefined);
  // Nine objects someone else wrote under the seq of the entry before it, eight of them in front
  // of the key of the node and one whose key names a time a year from now: none of the eight the
  // screen reads is the entry of the node. Its line is not verified, and it stands between the
  // entry after it and the entry before it (the earlier times move it no further down, and the
  // later time does not move it above the seq after it). The read goes to the rounds.
  for (let j = 0; j < 8; j += 1) strayObject(fx, chain, used[2].seq, 1, "u", String(j));
  strayObject(fx, chain, used[2].seq, world.now + 400 * DAY_MS, "u", "9");
  await S.start(fx);
  const again = await S.call(fx, "read_log", { limit: 50 });
  assert.equal(lines(again), "3?10");
  assert.deepEqual(heldReads(world).crowded, [[node.id, used[2].seq]]);
  // Every round reads the objects under that seq again and is held back while none of the
  // eight it reads is the entry of the node.
  const states = [];
  for (let day = 0; day < 4; day += 1) {
    await nextDay(fx);
    states.push(world.state.log.status + ":" + world.state.log.store + ":" + world.reports.slice(-1)[0].blocked_attempts);
  }
  assert.deepEqual(states, ["pending:blocked:1", "pending:blocked:2", "pending:blocked:3", "attention:blocked:4"]);
  assert.equal(world.state.log.store_failure, "chain:keys");
  assert.deepEqual(world.securityStatuses.slice(-1)[0].reasons, ["verification_blocked"]);
  assert.deepEqual(heldReads(world).crowded, [[node.id, used[2].seq]]);
});

/** The request events a result of read_log shows. */
function shownRequests(result) {
  return shownGroups(result.value).filter((group) => group.kind === "request").reduce((sum, group) => sum + group.count, 0);
}

test("the log screen shows the entries a node wrote into its chain of format 2 whatever someone else wrote above the end of that chain: an object far beyond the end, or objects on top of it, with keys that name an early time, take no entry of the node off the screen, in a chain this device follows and in one it does not, and an entry the node writes after them is on the screen at the next opening", async () => {
  for (const where of ["far", "pile"]) {
    for (const followed of [true, false]) {
      const label = where + (followed ? ", followed" : ", found");
      const fx = S.fixture(source, { nodes: 1, legacy: followed ? 1 : 0, device: { securityStatus: true } });
      const world = fx.world;
      // A chain this device does not follow: the chain of a node of an earlier release this
      // device handed no grant to (another device of the account did). The screen finds it by
      // the node prefixes of the account.
      const node = followed ? fx.legacy[0] : world.addNode({ release: fx.latest.release, measurement: fx.latest, offered: false });
      await S.start(fx);
      // Sixty entries of the node of format 3, and after them five entries of the chain: the
      // first page of the screen is full, and the entries of the chain are the latest on it.
      for (let i = 0; i < 60; i += 1) {
        world.advance(60000);
        fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/n" + i, "GET")]);
      }
      const used = [];
      for (let i = 0; i < 5; i += 1) {
        world.advance(HOUR_MS);
        used.push(node.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]));
      }
      const chain = used[0].key.slice(0, used[0].key.lastIndexOf("/") + 1);
      const end = used[4].seq;
      // The request events of the chain a result of read_log shows.
      const ofChain = (result) => shownGroups(result.value).filter((group) => group.kind === "request")
        .reduce((sum, group) => sum + group.requests.filter((row) => /\/messages\/\d+$/.test(row.target)).length, 0);
      // Objects someone else wrote above the end of the chain, each under a seq of its own, with
      // keys that name the first millisecond: one far beyond the end, or twelve on top of it.
      if (where === "far") strayObject(fx, chain, end + 100000, 1, "u");
      else for (let j = 0; j < 12; j += 1) strayObject(fx, chain, end + 3 + j, 1, "u", String(j));
      await nextDay(fx);
      assert.equal(world.stored("log.legacy").nodes[node.id] !== undefined, followed, label);
      const first = await S.call(fx, "read_log", { limit: 50 });
      assert.equal(ofChain(first), 5, label);
      assert.equal(first.value.has_more, true, label);
      assert.equal(first.value.status, "verified", label);
      assert.equal(world.stored("log.denied"), undefined, label);
      assert.equal(heldReads(world), undefined, label);
      // The node writes an entry. The next opening of the screen, in the same runtime and with no
      // synchronization in between, shows it: the screen lists the chain from the last entry it
      // knows the node wrote, and not from the last seq a key names.
      world.advance(HOUR_MS);
      node.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/5", "POST")]);
      const second = await S.call(fx, "read_log", { limit: 50 });
      assert.equal(ofChain(second), 6, label);
      assert.equal(world.stored("log.denied"), undefined, label);
      // The summary counts the entries of the node as well: a key above them that names a time
      // before the window does not end the count.
      const summary = second.value.summary;
      assert.equal(summary.reads + summary.sends + summary.changes, 66, label);
      assert.equal(summary.truncated, false, label);
    }
  }
});

test("objects someone else wrote that keep the screen from the entries of a chain of format 2 are noted as a listing held back: while what the screen knows of the chain stands on a seq that holds no entry of its node, the page says that more may lie below, and the note ends when the screen reaches the entries of the node", async () => {
  const fx = S.fixture(source, { nodes: 1, device: { securityStatus: true } });
  const world = fx.world;
  const node = world.addNode({ release: fx.latest.release, measurement: fx.latest, offered: false });
  await S.start(fx);
  const used = [];
  for (let i = 0; i < 5; i += 1) {
    world.advance(HOUR_MS);
    used.push(node.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]));
  }
  const chain = used[0].key.slice(0, used[0].key.lastIndexOf("/") + 1);
  // Four objects, each alone and far above the one before it, with keys that name the first
  // millisecond: below each of them the screen finds the next one, and no entry of the node.
  for (let j = 1; j <= 4; j += 1) strayObject(fx, chain, used[4].seq + j * 5000, 1, "u", String(j));
  await nextDay(fx);
  const first = await S.call(fx, "read_log", { limit: 50 });
  assert.equal(shownRequests(first), 0);
  assert.equal(first.value.has_more, true);
  assert.equal(world.stored("log.denied").chains[node.id].length, 1);
  // The next opening reads on below the place the one before reached, comes to the entries of
  // the node, and shows them. The note ends.
  const second = await S.call(fx, "read_log", { limit: 50 });
  assert.equal(shownRequests(second), 5);
  assert.equal(second.value.status, "verified");
  assert.equal(world.stored("log.denied"), undefined);
  assert.ok(world.securityStatuses.every((told) => told.status !== "attention"));
});

test("the log screen takes a range of a chain of format 2 as known only from a listing that was read as far as the range reaches: with listing pages that hold a part of a range, every entry of a long chain is on the screen once", async () => {
  const fx = S.fixture(source, { nodes: 0, legacy: 1 });
  await S.start(fx);
  const world = fx.world;
  const node = fx.legacy[0];
  for (let i = 0; i < 1400; i += 1) {
    world.advance(1000);
    node.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
  }
  // The rounds read the chain to its end, so the screen begins a thousand seqs under it. A
  // listing page holds 250 object versions: the listing of the end of the chain takes four
  // pages, and the range below it two.
  world.pageSize = 250;
  await nextDay(fx);
  for (let turn = 0; turn < 6 && world.stored("log.legacy").nodes[node.id].seq < 1400; turn += 1) {
    world.advance(2 * 60000);
    await S.event(fx, "foreground");
  }
  assert.ok(world.stored("log.legacy").nodes[node.id].seq >= 1400);
  let shown = 0;
  let page = await S.call(fx, "read_security_record", { limit: 500 });
  for (let guard = 0; guard < 8; guard += 1) {
    assert.equal(page.ok, true);
    for (const item of page.value.items) {
      if (item.detail.indexOf("/messages/") >= 0) shown += item.count;
    }
    if (page.value.next_before_ms === null) break;
    page = await S.call(fx, "read_security_record", { limit: 500, before_ms: page.value.next_before_ms });
  }
  assert.equal(page.value.next_before_ms, null);
  assert.equal(shown, 1400);
  assert.equal(world.stored("log.denied"), undefined);
  // A new runtime, ten days later (the entries lie before the window of the summary, which
  // reads nothing below the first thousand seqs then). The user scrolls down to the range below
  // them, and the backend holds the listing of that range back from the screen: it is noted.
  const mode = { held: false };
  world.fault("POST /api/secure/log/store/listings", (request) =>
    (mode.held && JSON.parse(request.body).nodes.length > 0 ? { status: 503, body: { detail: "log_store_unreachable" } } : undefined));
  world.advance(10 * DAY_MS);
  await S.start(fx);
  const top = await S.call(fx, "read_security_record", { limit: 500 });
  mode.held = true;
  await S.call(fx, "read_security_record", { limit: 500, before_ms: top.value.next_before_ms });
  mode.held = false;
  assert.deepEqual(world.stored("log.denied").chains[node.id].map((note) => note.after), [0]);
  // The next opening of the screen, which the backend answers, reads the chain from its end
  // down to that range, and the note ends. The user did not scroll.
  const listed = world.sent("POST /api/secure/log/store/listings").length;
  await S.call(fx, "read_security_record", { limit: 5 });
  assert.equal(world.stored("log.denied"), undefined);
  assert.ok(world.sent("POST /api/secure/log/store/listings").length >= listed + 3);
});

test("a listing of the end of a chain of format 2 that does not end within the pages one call of the screen reads is noted as a listing held back: the entries of the node it named are on the screen, and the note ends when the screen has read the listing to its end", async () => {
  const fx = S.fixture(source, { nodes: 0, legacy: 1, device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  const node = fx.legacy[0];
  const used = [];
  for (let i = 0; i < 5; i += 1) {
    world.advance(HOUR_MS);
    used.push(node.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]));
  }
  const chain = used[0].key.slice(0, used[0].key.lastIndexOf("/") + 1);
  await nextDay(fx);
  // Sixty objects someone else wrote above the end of the chain, each under a seq of its own, and
  // listing pages of four object versions: the listing of the end of the chain goes on over
  // more pages than one call of the screen reads.
  world.pageSize = 4;
  for (let j = 0; j < 60; j += 1) strayObject(fx, chain, used[4].seq + 10 + j, 1, "u", String(j));
  const shown = (result) => result.value.items.reduce((sum, item) => sum + (item.detail.indexOf("/messages/") >= 0 ? item.count : 0), 0);
  const first = await S.call(fx, "read_security_record", { limit: 50 });
  assert.equal(shown(first), 5);
  assert.notEqual(first.value.next_before_ms, null);
  assert.equal(world.stored("log.denied").chains[node.id].length, 1);
  // The page after it: the listing is read on where it stopped, to its end, and the note ends.
  const second = await S.call(fx, "read_security_record", { limit: 50, before_ms: first.value.next_before_ms });
  assert.equal(second.ok, true);
  assert.equal(world.stored("log.denied"), undefined);
});

test("an opening of the log screen after the first of a runtime lists the end of every chain of format 2 that may still be written, with one request for the listing addresses of them all, and reads no entry it holds again", async () => {
  const fx = S.fixture(source, { nodes: 1, legacy: 3 });
  await S.start(fx);
  const world = fx.world;
  for (let i = 0; i < 4; i += 1) {
    world.advance(HOUR_MS);
    fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/n" + i, "POST")]);
    for (const node of fx.legacy) node.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/l" + i, "GET")]);
  }
  await nextDay(fx);
  const first = await S.call(fx, "read_log", { limit: 50 });
  assert.equal(shownRequests(first), 16);
  const sent = (line) => world.sent(line).length;
  const before = { listings: sent("POST /api/secure/log/store/listings"), objects: sent("POST /api/secure/log/store/objects"), store: sent("S3 ") };
  const second = await S.call(fx, "read_log", { limit: 50 });
  assert.equal(shownRequests(second), 16);
  // The round of the opening lists the chains it follows with one request, and the screen lists
  // their ends with one more: three listings of the store each.
  assert.equal(sent("POST /api/secure/log/store/listings") - before.listings, 2);
  assert.equal(sent("POST /api/secure/log/store/objects") - before.objects, 0);
  const listed = world.sent("POST /api/secure/log/store/listings").slice(-1)[0];
  assert.equal(JSON.parse(listed.body).nodes.length, 3);
});

test("more open chains of format 2 than a round follows are all read within the rounds that follow: the chains listed longest ago come first", async () => {
  const fx = S.fixture(source, { nodes: 0, legacy: 66 });
  await S.start(fx);
  const world = fx.world;
  // The first round follows 64 chains, and is not complete.
  const first = world.stored("log.legacy").nodes;
  assert.equal(Object.keys(first).length, 66);
  assert.equal(Object.keys(first).filter((id) => first[id].seq === 0).length, 2);
  assert.equal(world.state.log.status, "pending");
  // The next round begins with the two it left.
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  const second = world.stored("log.legacy").nodes;
  assert.equal(Object.keys(second).filter((id) => second[id].seq === 0).length, 0);
  assert.equal(world.stored("log.round").unfinished, 0);
  assert.deepEqual(world.stored("log.blocked"), { first_ms: 0, count: 0 });
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
  await world.settle(1000);
  // The first round reads four pages and is not complete; the round that follows it at once
  // reads the rest.
  assert.deepEqual(world.reports.map((report) => report.status + ":" + report.store + ":" + report.keys_checked),
    ["pending:truncated:12", "verified:verified:9"]);
  assert.equal(world.state.log.status, "verified");
  assert.equal(judgedKeys(world), 21);
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

test("a node the backend lists for its revokes alone is handed no grant and asked for no attestation, changes nothing of the state of the grants, and takes the revoke when the user turns the delegation off or shortens the lifetime of a grant", async () => {
  const fx = S.fixture(source, { nodes: 1, legacy: 1 });
  const world = fx.world;
  const guard = fx.legacy[0];
  // A node of an earlier release outside the nodes that serve calls. Another device of the
  // account handed it a grant, and the backend lists it for this account as revoke_only.
  const hand = () => guard.grants.set(world.userId, {
    sign_pk: b64u(fx.keys.signPk), log_pk: b64u(fx.keys.logPk), key_id: fx.keys.keyId, custody: "enclave",
    not_after_ms: world.now + 20 * DAY_MS,
  });
  guard.revokeOnly = true;
  hand();
  const attested = () => world.sent("GET /api/secure/nodes")
    .filter((request) => request.query.nodes === undefined || String(request.query.nodes).split(",").indexOf(guard.id) >= 0).length;
  await S.start(fx);
  assert.equal(world.state.grant.state, "active");
  assert.deepEqual(guard.commands, []);
  assert.equal(attested(), 0);
  assert.equal(fx.nodes[0].commands.filter((command) => command.type === "grant").length, 1);
  // The grants are renewed over the weeks, and a push says that a grant is required: nothing
  // goes to that node, and the ledger of the earlier programs does not name it.
  for (let week = 0; week < 6; week += 1) {
    world.advance(7 * DAY_MS);
    await S.event(fx, "push", { reason: "grant_required" });
    assert.equal(world.state.grant.state, "active", "week " + week);
  }
  assert.deepEqual(guard.commands, []);
  assert.equal(attested(), 0);
  assert.equal(JSON.stringify(readLedger(fx)).indexOf(guard.id), -1);
  assert.equal(world.stored("log.grants")[guard.id], undefined);
  assert.ok(fx.nodes[0].commands.filter((command) => command.type === "grant").length >= 3);
  // The user shortens the lifetime: the grant that node holds is of the lifetime before, and
  // the revoke goes to it (with the attestation a revoke needs). The other node takes a grant of
  // the new lifetime.
  const shorter = await S.call(fx, "set_grant_days", { days: 7 });
  assert.equal(shorter.value.days, 7);
  assert.deepEqual(guard.commands.map((command) => command.type), ["revoke"]);
  assert.equal(guard.grants.has(world.userId), false);
  assert.equal(attested(), 1);
  assert.equal(world.state.grant.state, "active");
  // The other device hands that node its grant again. A longer lifetime sends that node nothing.
  hand();
  assert.equal((await S.call(fx, "set_grant_days", { days: 14 })).value.days, 14);
  assert.deepEqual(guard.commands.map((command) => command.type), ["revoke"]);
  assert.equal(attested(), 1);
  // A revoke that node does not confirm leaves the lifetime as it was: grant_incomplete.
  world.fault("POST /api/secure/nodes/" + guard.id + "/messages", { status: 503, body: {} }, 1);
  assert.deepEqual(await S.call(fx, "set_grant_days", { days: 3 }), { ok: false, code: "grant_incomplete" });
  assert.equal(world.state.grant_days, 14);
  assert.equal(guard.grants.has(world.userId), true);
  // The user turns the delegation off: the revoke goes to every listed node, that one among
  // them. Turned on again, the node of the pool takes a grant and that node takes nothing.
  const before = guard.commands.length;
  assert.equal((await S.call(fx, "set_delegation", { enabled: false })).ok, true);
  assert.deepEqual(guard.commands.slice(before).map((command) => command.type), ["revoke"]);
  assert.equal(guard.grants.has(world.userId), false);
  assert.equal(fx.nodes[0].grants.has(world.userId), false);
  const revoked = guard.commands.length;
  assert.equal((await S.call(fx, "set_delegation", { enabled: true })).ok, true);
  assert.equal(guard.commands.length, revoked);
  assert.equal(fx.nodes[0].grants.has(world.userId), true);
  assert.equal(world.state.grant.state, "active");
});

// ---- The program the backend serves, and a runtime behind it ----

/** What the program store holds of the values the rounds judge by, as stored: every value under
 *  log. but the grants this device handed out (log.grants) and the kept screen (log.cache). */
function judgedStores(world) {
  const kept = {};
  for (const key of Array.from(world.store.keys()).sort()) {
    if (key.startsWith("log.") && key !== "log.grants" && key !== "log.cache") kept[key] = world.store.get(key);
  }
  return kept;
}

/** Has a node of a measurement no list of the program has take the key of the account over from
 *  the node of the fixture, and write an entry. Returns the measurement. */
function moveKeyToUnlisted(fx) {
  const world = fx.world;
  const other = bridge.randomMeasurement();
  const receiver = world.addNode({ release: "v9.0.0", measurement: other, offered: false });
  fx.nodes[0].record("c", [{
    t: "grant_transferred_out", time_ms: world.now, to: receiver.id, release: "v9.0.0",
    pcr0: other.pcr0, pcr1: other.pcr1, pcr2: other.pcr2,
  }]);
  world.advance(1000);
  receiver.record("c", [{ t: "connection_created", time_ms: world.now, record_id: "r9", provider: "slack", scope: "" }]);
  return other;
}

test("a runtime that knows a later program is served judges nothing: a node of a release this program does not list that holds the key of the account marks nothing while the backend names a later version, over days and runtimes, nothing the rounds judge by is written, and the runtime reports once that it is stale", async () => {
  const fx = S.fixture(source, { nodes: 1, legacy: 1, device: { securityStatus: true } });
  await S.start(fx);
  const world = fx.world;
  for (let i = 0; i < 6; i += 1) {
    world.advance(HOUR_MS);
    fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/n" + i, "POST")]);
    fx.legacy[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/l" + i, "GET")]);
  }
  // The next release is put out: a node of a measurement no list of this program has takes the
  // key of the account over and writes an entry. This runtime read that its own program is the
  // one served, so its round sees the measurement, and the log is pending for a day.
  const other = moveKeyToUnlisted(fx);
  await nextDay(fx);
  assert.equal(world.state.log.status, "pending");
  assert.equal(world.state.log.newer_release_nodes, 1);
  assert.equal(Object.values(world.stored("log.unaccepted"))[0].held, true);
  // From here on the backend serves the next program, and lists a node of the new release.
  world.account.servedProgram = fx.version + 1;
  const listed = world.addNode({ release: "v9.0.0", measurement: other });
  const kept = judgedStores(world);
  const state = JSON.stringify(world.state.log);
  const reports = world.reports.length;
  const told = world.securityStatuses.length;
  const refused = { status: 503, body: { detail: "log_store_unreachable" } };
  const attested = () => world.sent("GET /api/secure/nodes")
    .filter((request) => String(request.query.nodes || "").split(",").indexOf(listed.id) >= 0).length;
  let runtimes = 0;
  const unchanged = (label) => {
    assert.equal(JSON.stringify(world.state.log), state, label);
    assert.deepEqual(judgedStores(world), kept, label);
    assert.equal(world.securityStatuses.length, told, label);
    const sent = world.reports.slice(reports);
    assert.equal(sent.length, runtimes, label);
    assert.ok(sent.every((report) => report.status === "pending" && report.store_failure === "program:stale" &&
      report.program_version === fx.version), label);
  };
  for (let day = 0; day < 5; day += 1) {
    // A new runtime, more than a day after the device first saw the measurement: the event
    // session_ready states nothing of what the device kept, and its synchronization learns that
    // the runtime is stale.
    world.advance(25 * HOUR_MS);
    const before = attested();
    const listings = world.sent("POST /api/secure/log/read").length;
    await S.start(fx);
    runtimes += 1;
    // The events of the app, a synchronization the user asks for, and the screen with reads
    // held back from it: its first page, a later page, a listing of a chain.
    await S.event(fx, "foreground");
    await S.event(fx, "push", { reason: "unknown" });
    // (No round started: no listing was asked for.)
    assert.equal(world.sent("POST /api/secure/log/read").length, listings, "day " + day);
    // The screen goes on reading the store: an entry a node wrote now is on its first page.
    fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/s" + day, "POST")]);
    const fresh = await S.call(fx, "read_log", { limit: 3 });
    assert.equal(shownGroups(fresh.value).filter((group) => group.kind === "request")[0].requests[0].target.slice(-2), "s" + day);
    world.fault("POST /api/secure/log/bodies", refused, 1);
    const first = await S.call(fx, "read_log", { limit: 3 });
    assert.equal(first.ok, true, "day " + day);
    assert.equal(first.value.status, "pending", "day " + day);
    world.fault("POST /api/secure/log/read", refused, 1);
    await S.call(fx, "read_security_record", { limit: 3, before_ms: world.now - HOUR_MS });
    world.fault("POST /api/secure/log/store/listings", refused, 1);
    await S.call(fx, "read_log", { limit: 3 });
    await S.call(fx, "sync", {});
    await S.event(fx, "background");
    await world.settle(1000);
    unchanged("day " + day);
    // The node of the new release was asked for its attestation once in the runtime, and
    // holds no grant.
    assert.equal(attested(), before + 1, "day " + day);
    assert.equal(listed.grants.has(world.userId), false, "day " + day);
    world.clearFaults();
  }
  // A runtime whose screen starts a round before the runtime has read what is served: the round
  // reads, the synchronization learns that the runtime is stale, and the round judges nothing
  // and writes nothing of what it read.
  world.advance(25 * HOUR_MS);
  S.load(fx);
  const early = fx.program.procedures.read_log({ limit: 3 });
  await world.run(fx.program.onEvent("session_ready", {}));
  await world.run(early);
  await world.settle(1000);
  runtimes += 1;
  unchanged("a round in flight");
  // The backend names this program as the one it serves again: the round of the next
  // synchronization judges, and the measurement, long past its day, marks the log.
  world.account.servedProgram = fx.version;
  world.advance(2 * 60000);
  await S.event(fx, "foreground");
  assert.equal(world.state.log.status, "attention");
  assert.deepEqual(world.securityStatuses.slice(-1)[0].reasons, ["unlisted_release"]);
  assert.equal(world.reports.slice(-1)[0].status, "attention");
  // A round the screen starts two hours later, with no synchronization in between: what the
  // runtime read of the served program is older than an hour, so the round asks for the account
  // once before it judges, and the mark stays.
  world.advance(2 * HOUR_MS);
  const asked = world.sent("GET /api/secure/account").length;
  const shown = await S.call(fx, "read_log", { limit: 3 });
  assert.equal(shown.value.status, "attention");
  assert.equal(world.state.log.status, "attention");
  assert.equal(world.sent("GET /api/secure/account").length, asked + 1);
});

test("a backend that names no served program leaves a measurement no list has pending: nothing marks the log for it and no round counts as held back, and the rounds judge everything else as before", async () => {
  for (const served of [null, "44", 44.5]) {
    const label = String(served);
    const fx = S.fixture(source, { served: served, device: { securityStatus: true } });
    await S.start(fx);
    const world = fx.world;
    assert.equal(world.state.log.status, "verified", label);
    moveKeyToUnlisted(fx);
    const states = [];
    for (let day = 0; day < 5; day += 1) {
      const judged = judgedKeys(world);
      world.advance(HOUR_MS);
      fx.nodes[0].record("c", [{ t: "connection_created", time_ms: world.now, record_id: "d" + day, provider: "slack", scope: "" }]);
      await nextDay(fx);
      states.push(world.state.log.status + ":" + world.state.log.newer_release_nodes + ":" + world.state.log.unknown_nodes + ":" +
        world.stored("log.blocked").count);
      assert.ok(judgedKeys(world) > judged, label);
    }
    assert.deepEqual(states, ["pending:1:0:0", "pending:1:0:0", "pending:1:0:0", "pending:1:0:0", "pending:1:0:0"], label);
    assert.ok(world.securityStatuses.every((told) => told.status !== "attention"), label);
    assert.ok(world.reports.every((report) => report.status !== "attention" && report.store_failure !== "program:stale"), label);
  }
});

test("a build that knows the delivery of the program itself judges by what the app verified: the word of the backend counts until the check of the app that follows it has ended, a measurement no list has marks the log once such a check ended after the device first saw it, and checks that fail on the side of the server are rounds held back", async () => {
  const build = async (served) => {
    const delivery = { verified: 0, settled_ms: 0, failed_ms: 0, failed_status: 0 };
    const fx = S.fixture(source, { device: { securityStatus: true, delivery: delivery } });
    delivery.verified = fx.version;
    fx.world.account.servedProgram = served === "later" ? fx.version + 1 : fx.version;
    await S.start(fx);
    return { fx: fx, world: fx.world, delivery: delivery };
  };
  const stale = (world) => world.reports.filter((report) => report.store_failure === "program:stale").length;

  // The backend names a later version from the start, and goes on naming it.
  const lied = await build("later");
  // The runtime began before a check of the app had ended: the word of the backend counts, and
  // no round runs.
  assert.equal(lied.world.reports.length, 1);
  assert.equal(stale(lied.world), 1);
  // The check of the app ends, with no later program. The word of the backend counts no more,
  // however often it is said again: the round of the next synchronization runs.
  lied.delivery.settled_ms = lied.world.now;
  lied.world.advance(2 * 60000);
  await S.event(lied.fx, "foreground");
  assert.equal(lied.world.state.log.status, "verified");
  moveKeyToUnlisted(lied.fx);
  await nextDay(lied.fx);
  assert.equal(lied.world.state.log.status, "pending");
  assert.equal(lied.world.state.log.newer_release_nodes, 1);
  // A day later, in a new runtime. The check the app made as it began ended with no later
  // program, after the device first saw the measurement: the log is marked, by the event
  // session_ready itself and by the round, whatever the backend names.
  lied.world.advance(25 * HOUR_MS);
  lied.delivery.settled_ms = lied.world.now;
  lied.world.advance(30000);
  S.load(lied.fx);
  Promise.resolve(lied.fx.program.onEvent("session_ready", {})).then(() => {}, () => {});
  assert.equal(lied.world.state.log.status, "attention");
  await lied.world.settle(1000);
  assert.equal(lied.world.state.log.status, "attention");
  assert.deepEqual(lied.world.securityStatuses.slice(-1)[0].reasons, ["unlisted_release"]);
  assert.equal(lied.world.reports.slice(-1)[0].status, "attention");
  assert.equal(stale(lied.world), 1);

  // The same backend, and the checks of the app fail on the side of the server from the day the
  // key moved: the word of the backend does not keep the runtime from its rounds, and once the
  // measurement is past its day, each round that cannot judge it is a round held back.
  const held = await build("later");
  held.delivery.settled_ms = held.world.now;
  moveKeyToUnlisted(held.fx);
  const states = [];
  for (let day = 0; day < 5; day += 1) {
    held.world.advance(25 * HOUR_MS);
    held.delivery.failed_ms = held.world.now;
    held.delivery.failed_status = 503;
    await S.start(held.fx);
    states.push(held.world.state.log.status + ":" + held.world.stored("log.blocked").count + ":" + held.world.state.log.store_failure);
  }
  assert.deepEqual(states, [
    "pending:0:", "pending:1:delivery:503", "pending:2:delivery:503", "pending:3:delivery:503", "attention:4:delivery:503",
  ]);
  assert.deepEqual(held.world.securityStatuses.slice(-1)[0].reasons, ["verification_blocked"]);
  assert.equal(held.world.state.log.unknown_nodes, 0);
  // A check that ends with no later program: the count ends, and the measurement marks the log.
  held.world.advance(2 * 60000);
  held.delivery.settled_ms = held.world.now;
  await S.event(held.fx, "foreground");
  assert.deepEqual(held.world.stored("log.blocked"), { first_ms: 0, count: 0 });
  assert.deepEqual(held.world.securityStatuses.slice(-1)[0].reasons, ["unlisted_release"]);

  // A check of the app that ended after the device first saw the measurement, within its day,
  // and none since: the checks fail on the side of the server. A check older than an hour says
  // nothing of what is served now, so each round past that day is a round held back as well.
  const late = await build("same");
  late.delivery.settled_ms = late.world.now;
  moveKeyToUnlisted(late.fx);
  await nextDay(late.fx);
  late.delivery.settled_ms = late.world.now;
  const waits = [];
  for (let day = 0; day < 2; day += 1) {
    late.world.advance(25 * HOUR_MS);
    late.delivery.failed_ms = late.world.now;
    late.delivery.failed_status = 500;
    await S.event(late.fx, "foreground");
    waits.push(late.world.state.log.status + ":" + late.world.stored("log.blocked").count + ":" + late.world.state.log.store_failure);
  }
  assert.deepEqual(waits, ["pending:1:delivery:500", "pending:2:delivery:500"]);

  // A backend that names this program, and checks that fail without a response. While the
  // backend answered nothing around the check, the device was without a network: the round is
  // pending and counts nothing. When the backend answered other requests of the runtime around
  // it, the check was held back.
  const quiet = await build("same");
  quiet.delivery.settled_ms = quiet.world.now;
  moveKeyToUnlisted(quiet.fx);
  await nextDay(quiet.fx);
  const counts = [];
  for (let day = 0; day < 2; day += 1) {
    quiet.world.advance(25 * HOUR_MS);
    quiet.delivery.failed_ms = quiet.world.now - 10 * 60000;
    quiet.delivery.failed_status = 0;
    await S.event(quiet.fx, "foreground");
    counts.push(quiet.world.state.log.status + ":" + quiet.world.stored("log.blocked").count);
  }
  quiet.world.advance(25 * HOUR_MS);
  quiet.delivery.failed_ms = quiet.world.now;
  await S.event(quiet.fx, "foreground");
  counts.push(quiet.world.state.log.status + ":" + quiet.world.stored("log.blocked").count + ":" + quiet.world.state.log.store_failure);
  assert.deepEqual(counts, ["pending:0", "pending:0", "pending:1:delivery:silent"]);

  // An installation that verified a later program is stale whatever the backend names: no round
  // runs, and nothing is stated of what the device kept.
  const ahead = await build("same");
  assert.equal(ahead.world.state.log.status, "verified");
  const rounds = ahead.world.reports.length;
  ahead.delivery.verified = ahead.fx.version + 1;
  await nextDay(ahead.fx);
  assert.equal(ahead.world.reports.length, rounds + 1);
  assert.equal(stale(ahead.world), 1);
});

test("every request to the backend under /api/secure/ names the version of the program, and no other request does: by it the backend names a node this device handed its grant to for a connection and for a mail password, in an account with a node listed for its revokes alone", async () => {
  const fx = S.fixture(source, { nodes: 1, legacy: 1 });
  const world = fx.world;
  // A node listed for its revokes alone that holds a grant another device handed it. The
  // backend of the model names it for a request that does not say which program asks.
  const guard = fx.legacy[0];
  guard.revokeOnly = true;
  guard.grants.set(world.userId, {
    sign_pk: b64u(fx.keys.signPk), log_pk: b64u(fx.keys.logPk), key_id: fx.keys.keyId, custody: "enclave",
    not_after_ms: world.now + 20 * DAY_MS,
  });
  await S.start(fx);
  for (let i = 0; i < 4; i += 1) {
    world.advance(HOUR_MS);
    fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/" + i, "POST")]);
    guard.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/g" + i, "GET")]);
  }
  await nextDay(fx);
  // A connection: the backend names the node of the pool, whose statements the device verifies.
  world.device.webAuth = (args) => {
    const state = new URL(args.url).searchParams.get("state").split(".")[0];
    world.connections.get(state).completed = true;
    return "pickle://oauth?oauth_status=connected&oauth_state=" + state;
  };
  assert.deepEqual(await S.call(fx, "connect", { target: "github" }),
    { ok: true, value: { connection_id: "connection-1", provider: "github", reward: 0 } });
  // A mail password: the same.
  const mail = await S.call(fx, "connect_app_password", { username: "user@naver.com", password: "abcd efgh ijkl" });
  assert.deepEqual(mail, { ok: true, value: { provider: "naver_mail", connection_id: "connection-mail", identity: "user@naver.com" } });
  // More of what the program sends: the screen and a later page, a vault item, the lifetime of
  // a grant, the switch of the delegation, a push, and a request to a route outside
  // /api/secure/.
  const shown = await S.call(fx, "read_log", { limit: 2 });
  await S.call(fx, "read_log_page", { before_ms: world.runtime.log_pages[0].before_ms });
  assert.equal(shown.ok, true);
  await S.call(fx, "store_secret", { label: "key", sites: "api.example.com", slots: "header:authorization", value: "sk-0123456789" });
  await S.call(fx, "set_grant_days", { days: 7 });
  await S.call(fx, "set_delegation", { enabled: false });
  await S.call(fx, "set_delegation", { enabled: true });
  await S.event(fx, "push", { reason: "grant_required" });
  await S.call(fx, "set_connection_writes", { provider: "github", connection_id: "connection-1", kind: "issues", enabled: true });
  await world.settle(6000);
  const routes = new Set();
  let others = 0;
  for (const request of world.requests) {
    if (typeof request.path === "string" && request.path.startsWith("/api/secure/")) {
      assert.equal(request.query.program, String(fx.version), (request.method || "GET") + " " + request.path);
      routes.add((request.method || "GET") + " " + request.path.replace(/\/nodes\/[^/]+\//, "/nodes/{id}/").replace(/\/secret\/.*/, "/secret/{name}"));
    } else if (typeof request.path === "string") {
      assert.ok(request.query === undefined || request.query.program === undefined, request.path);
      others += 1;
    } else {
      assert.equal(new URL(request.url).searchParams.get("program"), null);
      others += 1;
    }
  }
  assert.ok(others > 10);
  for (const route of ["GET /api/secure/account", "GET /api/secure/grants", "GET /api/secure/nodes",
    "POST /api/secure/nodes/{id}/messages", "POST /api/secure/connections/begin", "GET /api/secure/connections/completion",
    "PUT /api/secure/connections/naver_mail/app-password", "POST /api/secure/log/read", "POST /api/secure/log/bodies",
    "POST /api/secure/log/store/listings", "POST /api/secure/log/verified", "POST /api/secure/vault/secret",
    "POST /api/secure/sync/report"]) {
    assert.ok(routes.has(route), route);
  }
});

test("a procedure that needs a node holding the grant ends with program_stale in a stale runtime that no listed node takes a grant of, and the runtime publishes that it is stale: a runtime that is not stale fails as before", async () => {
  for (const nodes of ["later", "none"]) {
    for (const stale of [true, false]) {
      const label = nodes + (stale ? ", stale" : ", not stale");
      const fx = S.fixture(source, { nodes: 0 });
      const world = fx.world;
      // Every node the backend lists is of a release this program does not list, or it lists none.
      if (nodes === "later") world.addNode({ release: "v9.0.0", measurement: bridge.randomMeasurement() });
      if (stale) world.account.servedProgram = fx.version + 1;
      await S.start(fx);
      assert.equal(world.runtime.program_stale, stale, label);
      const code = stale ? "program_stale" : nodes === "later" ? "attestation_failed" : "grant_required";
      assert.deepEqual(await S.call(fx, "connect", { target: "github" }), { ok: false, code: code }, label);
      assert.deepEqual(await S.call(fx, "store_login", { name: "example.com", username: "u", password: "p" }), { ok: false, code: code }, label);
      assert.deepEqual(
        await S.call(fx, "store_secret", { label: "x", sites: "example.com", slots: "field", value: "v" }), { ok: false, code: code }, label);
      // The outcome of the procedure is reported as a failure with that code.
      await world.settle(6000);
      const events = world.outcomeReports.reduce((all, report) => all.concat(report.events), []);
      assert.deepEqual(events.filter((event) => event.name === "connect").map((event) => event.code), [code], label);
    }
  }
  // A runtime that is stale no more says so: the backend names this program as the one served.
  const fx = S.fixture(source);
  fx.world.account.servedProgram = fx.version + 1;
  await S.start(fx);
  assert.equal(fx.world.runtime.program_stale, true);
  // (A node of a listed release holds the grant: the procedures of a stale runtime go on.)
  assert.equal((await S.call(fx, "store_secret", { label: "x", sites: "example.com", slots: "field", value: "v" })).ok, true);
  fx.world.account.servedProgram = fx.version;
  fx.world.advance(60000);
  await S.event(fx, "foreground");
  assert.equal(fx.world.runtime.program_stale, false);
});

test("the state the app keeps over its restarts says whether the backend names vault items for the account: true once the account query says so, false again once it says so no more, and an account that was never told so has no such key", async () => {
  // An account the backend never turned the items on for: the state holds no such key.
  const off = S.fixture(source);
  await S.start(off);
  await nextDay(off);
  await S.start(off);
  assert.equal("named_secrets" in off.world.state, false);
  assert.equal(off.world.store.has("vault.named"), false);
  // An account it turned them on for.
  const on = S.fixture(source);
  const world = on.world;
  world.account.namedSecrets = true;
  await S.start(on);
  assert.equal(world.state.named_secrets, true);
  assert.equal(world.runtime.named_secrets, true);
  // A new runtime: the state the app kept says true before the query of that runtime is
  // answered (the runtime value is false until then), and a query that fails changes nothing.
  world.fault("GET /api/secure/account", "transport");
  S.load(on);
  await world.run(Promise.resolve(on.program.onEvent("session_ready", {})).then(() => {}, () => {}));
  assert.equal(world.state.named_secrets, true);
  assert.equal(world.runtime.named_secrets, false);
  world.clearFaults();
  // The backend turns the items off for the account: the synchronization that reads so takes
  // the value back, and a later one turns it on again.
  world.account.namedSecrets = false;
  world.advance(60000);
  await S.event(on, "foreground");
  assert.equal(world.state.named_secrets, false);
  assert.equal(world.store.has("vault.named"), false);
  world.account.namedSecrets = true;
  world.advance(60000);
  await S.event(on, "foreground");
  assert.equal(world.state.named_secrets, true);
  assert.equal(world.store.has("vault.named"), true);
  // The end of the account erases what the device kept of it.
  await S.event(on, "account_end", { reason: "account_deleted" });
  assert.equal(world.store.has("vault.named"), false);
});

test("the transfer of the master key goes on through answers of the backend that fail for a moment: a 503 that names a dependency and a 429 among the answers to the polls of either device leave the transfer in progress, and the key arrives", async () => {
  const giving = S.fixture(source);
  const taking = S.fixture(source, { account: false });
  // One account: the device that takes the key has none, and the account has the key of the
  // device that gives it registered.
  taking.world.account.key = giving.world.account.key;
  // The routes of the transfer, on the backend the two devices share.
  const transfers = new Map();
  const answer = (status, body) => ({ status: status, body: body });
  // The answers that fail for a moment, handed out to the next polls of each device.
  const failing = { giving: [], taking: [] };
  const backend = (side, world) => (request) => {
    const method = request.method || "GET";
    const body = typeof request.body === "string" && request.body !== "" ? JSON.parse(request.body) : {};
    if (method === "POST" && request.path === "/api/secure/transfers") {
      const id = b64u(crypto.randomBytes(16));
      transfers.set(id, { request_id: id, phase: "requested", device: body.device, expires_ms: world.now + 15 * 60000 });
      return answer(200, { transfer: transfers.get(id) });
    }
    if (method === "GET" && request.path === "/api/secure/transfers") {
      return answer(200, { transfers: Array.from(transfers.values()).filter((transfer) => transfer.phase === "requested") });
    }
    const match = /^\/api\/secure\/transfers\/([^/]+)(?:\/([a-z]+))?$/.exec(request.path);
    if (match === null) return undefined;
    const transfer = transfers.get(match[1]);
    if (transfer === undefined) return answer(404, { code: "not_found" });
    if (method === "GET" && match[2] === undefined) {
      return failing[side].length > 0 ? failing[side].shift() : answer(200, { transfer: transfer });
    }
    if (method === "PUT" && match[2] === "approval") Object.assign(transfer, { phase: "approved", yb: body.yb, approver: body.device });
    else if (method === "PUT" && match[2] === "reply") Object.assign(transfer, { phase: "replied", ya: body.ya, ta: body.ta });
    else if (method === "PUT" && match[2] === "envelope") Object.assign(transfer, { phase: "sealed", ciphertext: body.ciphertext, tb: body.tb });
    else if (method === "POST" && match[2] === "ack") transfers.delete(match[1]);
    else return answer(400, { code: "invalid_input" });
    return answer(200, {});
  };
  giving.world.fault((line) => line.indexOf("/api/secure/transfers") >= 0, backend("giving", giving.world));
  taking.world.fault((line) => line.indexOf("/api/secure/transfers") >= 0, backend("taking", taking.world));
  await S.start(giving);
  await S.start(taking);
  assert.equal(taking.world.state.key_state, "waiting");
  const begun = await S.call(taking, "begin_transfer", {});
  assert.equal(begun.value.transfer.phase, "requested");
  // The device with the key learns of the request, and its user approves it.
  await S.event(giving, "push", { reason: "transfer_request" });
  assert.equal(giving.world.state.transfer.phase, "pending_approval");
  const moment = () => [answer(503, { detail: "postgresql_unavailable" }), answer(429, { detail: "too_many_requests" })];
  failing.taking = moment();
  failing.giving = moment();
  assert.equal((await S.call(giving, "approve_transfer", {})).value.transfer.phase, "approved");
  const code = giving.world.runtime.transfer_code;
  assert.match(code, /^[0-9]{6}$/);
  // The polls of the two devices, two seconds apart.
  const pass = async (turns) => {
    for (let turn = 0; turn < turns; turn += 1) {
      await taking.world.settle(2500);
      await giving.world.settle(2500);
    }
  };
  await pass(5);
  assert.equal(taking.world.state.transfer.phase, "code_entry");
  assert.deepEqual(failing, { giving: [], taking: [] });
  // The user enters the code, and the polls that follow meet such answers once more.
  failing.taking = moment();
  failing.giving = moment();
  await S.call(taking, "enter_transfer_code", { code: code });
  await pass(8);
  assert.deepEqual(failing, { giving: [], taking: [] });
  assert.equal(taking.world.state.transfer.phase, "done");
  assert.equal(giving.world.state.transfer.phase, "done");
  assert.equal(taking.world.state.key_state, "present");
  const item = "com.pickle.client.secure.master-key\n" + taking.world.userId;
  assert.equal(taking.world.keychain.get(item).value, giving.world.keychain.get(item).value);
});

test("an entry of a node the runtime has no judgement of is read with the page that shows it: the first read of a later page shows it verified", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  // A node of the accepted measurement that took the delegation from the node of the device (a
  // transfer between nodes of one measurement writes no entry), and wrote use entries only.
  const other = world.addNode({ release: "v2.4.0", measurement: fx.measurement, offered: false });
  for (let i = 0; i < 6; i += 1) {
    world.advance(60000);
    fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/a" + i, "POST")]);
    world.advance(60000);
    other.record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/b" + i, "GET")]);
  }
  // Ten days later (the entries lie before the window of the summary), three newer entries of
  // the node of the device, and a new runtime: no round judges the other node.
  world.advance(10 * DAY_MS);
  for (let i = 0; i < 3; i += 1) {
    world.advance(60000);
    fx.nodes[0].record("u", [S.providerRequest(world.now, "/gmail/v1/users/me/messages/c" + i, "POST")]);
  }
  await S.start(fx);
  await S.call(fx, "read_log", { limit: 3 });
  assert.equal(world.stored("log.nodes")[other.id], undefined);
  const bodies = world.sent("POST /api/secure/log/bodies").length;
  const page = await S.call(fx, "read_log_page", { before_ms: world.runtime.log_pages[0].before_ms });
  const groups = shownGroups(page.value);
  assert.equal(groups.filter((group) => group.kind === "request").reduce((sum, group) => sum + group.count, 0), 12);
  assert.ok(groups.every((group) => group.verified === true));
  // (The bodies of the node the device knew go out with the request for the document, and the
  // bodies of the node that document judged after it.)
  assert.equal(world.sent("POST /api/secure/log/bodies").length, bodies + 2);
});

test("turning the delegation off sends the revoke to a listed node whatever role its binding names, and none to a node that holds no delegation: a node of a role this program does not know is handed no grant, and takes the revoke", async () => {
  const fx = S.fixture(source);
  const world = fx.world;
  // A node whose binding names a role this program does not know, which holds the delegation of
  // the account (a node of its release handed it on), and a node of the role forward.
  const relay = world.addNode({ release: "v2.4.0", measurement: fx.measurement, role: "relay" });
  const forward = world.addNode({ release: "v2.4.0", measurement: fx.measurement, role: "forward" });
  relay.grants.set(world.userId, {
    sign_pk: b64u(fx.keys.signPk), log_pk: b64u(fx.keys.logPk), key_id: fx.keys.keyId, custody: "enclave",
    not_after_ms: world.now + 20 * DAY_MS,
  });
  await S.start(fx);
  assert.deepEqual(relay.commands, []);
  assert.deepEqual(forward.commands, []);
  assert.equal(fx.nodes[0].grants.has(world.userId), true);
  const off = await S.call(fx, "set_delegation", { enabled: false });
  assert.equal(off.ok, true);
  assert.deepEqual(relay.commands.map((command) => command.type), ["revoke"]);
  assert.equal(relay.grants.has(world.userId), false);
  assert.deepEqual(forward.commands, []);
  assert.equal(fx.nodes[0].grants.has(world.userId), false);
  assert.equal(world.state.grant.state, "off");
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

test("update_secret has the user confirm the new reach on a surface the app draws, before the device owner is asked and before anything is asked of the backend, in a build that has the confirmation; a confirmation the user closes changes nothing and is no failure", async () => {
  const value = "sk-live-0123456789abcdefghij";
  for (const confirmations of [false, true]) {
    const fx = S.fixture(source, { device: { confirmations: confirmations, locale: "ko-KR" } });
    await S.start(fx);
    const world = fx.world;
    await S.call(fx, "store_secret", { label: "key", sites: ["api.openai.com"], slots: ["header:authorization"], value: value });
    const auths = world.device.ownerAuths.length;
    const requests = world.requests.length;
    let seen = null;
    world.device.confirmAnswer = () => {
      seen = { auths: world.device.ownerAuths.length, requests: world.requests.length };
      return true;
    };
    const changed = await S.call(fx, "update_secret", { name: "SECRET_1", sites: "api.openai.com files.openai.com", slots: "header:authorization" });
    assert.deepEqual(changed, { ok: true, value: { name: "SECRET_1", sites: ["api.openai.com", "files.openai.com"], slots: ["header:authorization"] } });
    assert.equal(world.device.ownerAuths.length, auths + 1);
    if (confirmations) {
      // The lines are the ones of the reach that is sealed, and the user saw them first.
      assert.deepEqual(world.device.confirmed, [{
        title: "SECRET_1", destinations: ["api.openai.com · 요청 헤더 authorization", "files.openai.com · 요청 헤더 authorization"],
      }]);
      assert.deepEqual(seen, { auths: auths, requests: requests });
    } else {
      assert.equal(seen, null);
    }
    assert.deepEqual(openRecord(fx.keys, world.vault.secrets.get("SECRET_1").record).json.sites, ["api.openai.com", "files.openai.com"]);
  }
  // The user closes the confirmation: no device owner authentication, no request, the item as it
  // was, and the call is not counted as one that failed.
  const fx = S.fixture(source, { device: { confirmations: true, confirmAnswer: false } });
  await S.start(fx);
  const world = fx.world;
  await S.call(fx, "store_secret", { label: "pin", sites: ["coupang.com"], slots: ["field"], value: "4821" });
  const auths = world.device.ownerAuths.length;
  const requests = world.requests.length;
  assert.deepEqual(await S.call(fx, "update_secret", { name: "SECRET_1", sites: "coupang.com pay.coupang.com", slots: "field" }), { ok: false, code: "cancelled" });
  assert.equal(world.device.ownerAuths.length, auths);
  assert.equal(world.requests.length, requests);
  assert.deepEqual(world.device.confirmed[0].destinations, [
    "coupang.com and the hosts below it · typed into its pages", "pay.coupang.com and the hosts below it · typed into its pages",
  ]);
  assert.deepEqual(world.vault.secrets.get("SECRET_1").sites, ["coupang.com"]);
  const counted = world.stored("outcomes").done.update_secret;
  assert.deepEqual([counted.calls, counted.failed], [1, 0]);
});

test("store_secret without a name makes the item only once the value is one an item can hold, and removes an item it made and could not fill: a sheet the user closes, a value that is too long and a request that fails leave no item in the vault", async () => {
  // A build with the protected sheets: the lines of the sheet are made from the reach given, and
  // a sheet the user closes ends the call before any item is made.
  const sheets = S.fixture(source, { device: { sheets: true, locale: "ko-KR" } });
  await S.start(sheets);
  const made = () => sheets.world.sent("POST /api/secure/vault/secret").length;
  sheets.world.device.promptAnswer = null;
  assert.deepEqual(await S.call(sheets, "store_secret", { name: "", label: "쿠페이 비밀번호", sites: "coupang.com", slots: "field" }), { ok: false, code: "cancelled" });
  assert.deepEqual(sheets.world.device.prompts, [{ title: "쿠페이 비밀번호", destinations: ["coupang.com 및 그 하위 호스트 · 웹 페이지에 입력"] }]);
  assert.equal(made(), 0);
  assert.equal(sheets.world.vault.secrets.size, 0);
  // A value from the sheet that no item can hold: no item is made either.
  sheets.world.device.promptAnswer = "x".repeat(12300);
  assert.deepEqual(await S.call(sheets, "store_secret", { name: "", label: "pin", sites: "coupang.com", slots: "field" }), { ok: false, code: "too_large" });
  assert.equal(made(), 0);
  sheets.world.device.promptAnswer = "4821";
  assert.deepEqual(await S.call(sheets, "store_secret", { name: "", label: "pin", sites: "coupang.com", slots: "field" }), { ok: true, value: { name: "SECRET_1", state: "ready" } });
  assert.equal(openRecord(sheets.keys, sheets.world.vault.secrets.get("SECRET_1").record).json.value, "4821");

  // A build without the sheets: the form of the label, the sites, the slots and the value is
  // checked before the item is made.
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  const base = { name: "", label: "key", sites: "api.openai.com", slots: "header:authorization", value: "sk-live" };
  for (const [change, code] of [
    [{ value: "x".repeat(12300) }, "too_large"], [{ value: "" }, "invalid_input"], [{ value: "a\u0000b" }, "invalid_input"],
    [{ label: "x".repeat(81) }, "invalid_input"], [{ label: "a\u0007b" }, "invalid_input"],
    [{ sites: "Api.OpenAI.com" }, "invalid_input"], [{ slots: "header:host" }, "invalid_input"],
  ]) {
    assert.deepEqual(await S.call(fx, "store_secret", Object.assign({}, base, change)), { ok: false, code: code }, JSON.stringify(change).slice(0, 40));
  }
  assert.equal(world.sent("POST /api/secure/vault/secret").length, 0);
  // A step after the item was made fails: the item is removed with one request, without the
  // device owner being asked, and the call ends with the failure of that step.
  const removed = () => world.sent("DELETE /api/secure/vault/secret/").length;
  world.fault("PUT /api/secure/vault/secret/", { status: 503, body: { code: "unavailable" } }, 1);
  assert.deepEqual(await S.call(fx, "store_secret", base), { ok: false, code: "unavailable" });
  assert.equal(world.vault.secrets.size, 0);
  assert.equal(removed(), 1);
  assert.equal(world.device.ownerAuths.length, 0);
  // The backend gives the item it made another reach than the one shown: nothing is sealed.
  world.fault("GET /api/secure/vault/secret/", (request) => {
    const item = JSON.parse(world.api("GET", request.path, null, undefined).body);
    return { status: 200, body: Object.assign({}, item, { sites: ["api.openai.com", "evil.example"] }) };
  }, 1);
  const puts = world.sent("PUT /api/secure/vault/secret/").length;
  assert.deepEqual(await S.call(fx, "store_secret", base), { ok: false, code: "binding_changed" });
  assert.equal(world.sent("PUT /api/secure/vault/secret/").length, puts);
  assert.equal(world.vault.secrets.size, 0);
  assert.equal(removed(), 2);
  // The request that removes the item fails as well: the call ends with the failure of the step.
  world.fault("PUT /api/secure/vault/secret/", { status: 503, body: { code: "unavailable" } }, 1);
  world.fault("DELETE /api/secure/vault/secret/", { status: 500, body: {} }, 1);
  assert.deepEqual(await S.call(fx, "store_secret", base), { ok: false, code: "unavailable" });
  assert.equal(removed(), 3);
  assert.equal(leaked(world, base.value), false);
});

test("store_secret with a name seals nothing when the reach of the item is not the one the screen showed: the arguments sites and slots are compared with it as sets", async () => {
  for (const sheets of [false, true]) {
    const fx = S.fixture(source, { device: { sheets: sheets, promptAnswer: "4821" } });
    await S.start(fx);
    const world = fx.world;
    world.vault.secrets.set("COUPAY_PIN", {
      name: "COUPAY_PIN", label: "Coupay PIN", sites: ["coupang.com", "pay.coupang.com"], slots: ["field"], state: "empty", source: "",
    });
    const puts = () => world.sent("PUT /api/secure/vault/secret/").length;
    // Another reach: other hosts, a host more, other slots.
    for (const shown of [
      { sites: "coupang.com", slots: "field" }, { sites: "coupang.com pay.coupang.com evil.example", slots: "field" },
      { sites: "coupang.com,pay.coupang.com", slots: "header:authorization" }, { sites: "any" }, { slots: "path" },
    ]) {
      assert.deepEqual(await S.call(fx, "store_secret", Object.assign({ name: "COUPAY_PIN", value: "4821" }, shown)), { ok: false, code: "binding_changed" }, JSON.stringify(shown));
    }
    assert.equal(puts(), 0);
    assert.equal(world.device.prompts.length, 0);
    // The same reach in another order, and no reach at all.
    assert.equal((await S.call(fx, "store_secret", { name: "COUPAY_PIN", value: "4821", sites: "pay.coupang.com, coupang.com", slots: ["field"] })).ok, true);
    assert.equal((await S.call(fx, "store_secret", { name: "COUPAY_PIN", value: "4821", sites: "", slots: "" })).ok, true);
    assert.equal((await S.call(fx, "store_secret", { name: "COUPAY_PIN", value: "4821" })).ok, true);
    assert.equal(puts(), 3);
    assert.equal(world.device.prompts.length, sheets ? 3 : 0);
  }
});

test("the slots of a list argument are separated by white space alone and the hosts by commas or white space, and update_secret without slots leaves the slots of the item as they are", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  const value = "sk-live-0123456789abcdefghij";
  // The name of a json slot holds a comma.
  const stored = await S.call(fx, "store_secret", { name: "", label: "key", sites: "api.example.com, files.example.com", slots: "json:auth,key  header:x-api-key", value: value });
  assert.deepEqual(stored, { ok: true, value: { name: "SECRET_1", state: "ready" } });
  const item = world.vault.secrets.get("SECRET_1");
  assert.deepEqual([item.sites, item.slots], [["api.example.com", "files.example.com"], ["json:auth,key", "header:x-api-key"]]);
  // The hosts change and the slots stay: without the argument, and with a blank one.
  const id = item.record.id;
  for (const [args, sites] of [[{ sites: "api.example.com" }, ["api.example.com"]], [{ sites: "api.example.com,cdn.example.com", slots: " " }, ["api.example.com", "cdn.example.com"]]]) {
    const changed = await S.call(fx, "update_secret", Object.assign({ name: "SECRET_1" }, args));
    assert.deepEqual(changed, { ok: true, value: { name: "SECRET_1", sites: sites, slots: ["json:auth,key", "header:x-api-key"] } });
    const plain = openRecord(fx.keys, world.vault.secrets.get("SECRET_1").record).json;
    assert.deepEqual([plain.value, plain.sites, plain.slots], [value, sites, ["json:auth,key", "header:x-api-key"]]);
    assert.equal(world.vault.secrets.get("SECRET_1").record.id, id);
  }
  // The slots change when the argument names them.
  const narrowed = await S.call(fx, "update_secret", { name: "SECRET_1", sites: "api.example.com", slots: "json:auth,key" });
  assert.deepEqual(narrowed.value.slots, ["json:auth,key"]);
  // A build with the confirmation reads the item first, so that the lines name the slots that stay.
  const confirming = S.fixture(source, { device: { confirmations: true } });
  await S.start(confirming);
  await S.call(confirming, "store_secret", { name: "", label: "key", sites: "api.example.com", slots: "header:x-api-key", value: value });
  const kept = await S.call(confirming, "update_secret", { name: "SECRET_1", sites: "api.example.com files.example.com" });
  assert.deepEqual(kept.value.slots, ["header:x-api-key"]);
  assert.deepEqual(confirming.world.device.confirmed, [{
    title: "key", destinations: ["api.example.com · request header x-api-key", "files.example.com · request header x-api-key"],
  }]);
  // An item whose slots are other ones when it is read again after the confirmation is not written.
  confirming.world.device.confirmAnswer = () => {
    confirming.world.vault.secrets.get("SECRET_1").slots = ["header:authorization"];
    return true;
  };
  assert.deepEqual(await S.call(confirming, "update_secret", { name: "SECRET_1", sites: "api.example.com" }), { ok: false, code: "binding_changed" });
  assert.deepEqual(confirming.world.vault.secrets.get("SECRET_1").sites, ["api.example.com", "files.example.com"]);
});

test("the runtime publishes whether the backend names vault items for the account: true once the account query says so, false in a new runtime until its own query says so", async () => {
  // An account the backend turned the items on for, on a device with a master key and on one
  // without.
  for (const account of [true, false]) {
    const fx = S.fixture(source, { account: account });
    fx.world.account.namedSecrets = true;
    await S.start(fx);
    assert.equal(fx.world.runtime.named_secrets, true, String(account));
  }
  // An account whose query does not say so.
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  assert.equal(world.runtime.named_secrets, false);
  // The query says so later: true from then on, whatever a later answer says or fails to say.
  world.account.namedSecrets = true;
  await S.event(fx, "foreground");
  assert.equal(world.runtime.named_secrets, true);
  world.account.namedSecrets = false;
  world.advance(60000);
  await S.event(fx, "foreground");
  assert.equal(world.runtime.named_secrets, true);
  // A new runtime (another account signed in on the device): what the runtime before published
  // does not stand.
  await S.start(fx);
  assert.equal(world.runtime.named_secrets, false);
  // A query that fails changes nothing.
  world.account.namedSecrets = true;
  world.fault("GET /api/secure/account", "transport");
  S.load(fx);
  await world.run(Promise.resolve(fx.program.onEvent("session_ready", {})).then(() => {}, () => {}));
  assert.equal(world.runtime.named_secrets, false);
});

test("an item store_secret made and did not fill before its runtime ended is removed by the next runtime while it holds no value, and an item that holds a value is left", async () => {
  const fx = S.fixture(source);
  await S.start(fx);
  const world = fx.world;
  const base = { name: "", label: "key", sites: "api.openai.com", slots: "header:authorization", value: "sk-live-0123456789" };
  // The request that stores the value is never answered, and the runtime ends.
  world.fault("PUT /api/secure/vault/secret/", "hang");
  fx.program.procedures.store_secret(base).then(() => {}, () => {});
  await world.drain();
  assert.equal(world.vault.secrets.size, 1);
  assert.deepEqual(world.stored("vault.made"), ["SECRET_1"]);
  // The next runtime cannot reach the backend: the name stays. The one after it removes the item,
  // without the device owner being asked.
  world.clearFaults();
  world.fault("GET /api/secure/vault/secret/", { status: 503, body: { code: "unavailable" } }, 1);
  await S.start(fx);
  await world.settle(0);
  assert.equal(world.vault.secrets.size, 1);
  assert.deepEqual(world.stored("vault.made"), ["SECRET_1"]);
  await S.start(fx);
  await world.settle(0);
  assert.equal(world.vault.secrets.size, 0);
  assert.equal(world.stored("vault.made"), undefined);
  assert.equal(world.device.ownerAuths.length, 0);
  // An item that holds its value (the value was stored, and the runtime ended before the device
  // forgot the name) is not removed, and neither is anything once the name is forgotten.
  const stored = await S.call(fx, "store_secret", base);
  assert.equal(stored.ok, true);
  assert.equal(world.stored("vault.made"), undefined);
  world.store.set("vault.made", JSON.stringify([stored.value.name, "GONE_ITEM"]));
  const removed = world.sent("DELETE /api/secure/vault/secret/").length;
  await S.start(fx);
  await world.settle(0);
  assert.equal(world.vault.secrets.has(stored.value.name), true);
  assert.equal(world.sent("DELETE /api/secure/vault/secret/").length, removed);
  assert.equal(world.stored("vault.made"), undefined);
  assert.equal(leaked(world, base.value), false);
});

test("a name of white space alone is no name of an item, the form of the hosts is checked before the device owner is asked, and a title is cut between characters", async () => {
  const fx = S.fixture(source, { device: { sheets: true, confirmations: true, promptAnswer: "4821" } });
  await S.start(fx);
  const world = fx.world;
  // A name of white space alone: not an item to make, and nothing is asked of anyone.
  const requests = world.requests.length;
  assert.deepEqual(await S.call(fx, "store_secret", { name: "  ", label: "pin", sites: "coupang.com", slots: "field" }), { ok: false, code: "invalid_input" });
  assert.equal(world.requests.length, requests);
  assert.equal(world.device.prompts.length, 0);
  // A label of 80 characters whose 120th code unit is the first half of a character: the title
  // of the sheet ends with the character before it.
  const label = "a" + "\u{1F600}".repeat(79);
  const made = await S.call(fx, "store_secret", { name: "", label: label, sites: "coupang.com", slots: "field" });
  assert.equal(made.ok, true);
  assert.equal(world.device.prompts[0].title, "a" + "\u{1F600}".repeat(59));
  // Hosts of another form: update_secret ends before the confirmation, the device owner
  // authentication and any request, with the argument slots and without it.
  for (const args of [{ sites: "Coupang.com", slots: "field" }, { sites: "coupang.com,coupang.com" }, { sites: "" }, {}]) {
    const before = world.requests.length;
    assert.deepEqual(await S.call(fx, "update_secret", Object.assign({ name: made.value.name }, args)), { ok: false, code: "invalid_input" }, JSON.stringify(args));
    assert.equal(world.requests.length, before);
  }
  assert.equal(world.device.confirmed.length, 0);
  assert.equal(world.device.ownerAuths.length, 0);
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
  // (made: the call makes the item and takes its name from the backend; otherwise the item
  // exists and is asked for by its name.)
  const accepted = async (name, sites, slots, made) => {
    world.clearFaults();
    world.fault("POST /api/secure/vault/secret", { status: 200, body: { name: name, sites: sites, slots: slots } });
    world.fault("GET /api/secure/vault/secret/", { status: 200, body: { name: name, label: "", sites: sites, slots: slots, state: "empty", source: "" } });
    world.fault("PUT /api/secure/vault/secret/", { status: 200, body: { name: name, state: "ready" } });
    const puts = world.sent("PUT /api/secure/vault/secret/").length;
    const result = made
      ? await S.call(fx, "store_secret", { label: "x", sites: sites, slots: slots, value: "v" })
      : await S.call(fx, "store_secret", { name: name, value: "v" });
    assert.equal(world.sent("PUT /api/secure/vault/secret/").length, puts + (result.ok ? 1 : 0));
    return result.ok;
  };
  for (const item of cases.names) assert.equal(await accepted(item.text, ["example.com"], ["field"], true), item.valid, "name " + JSON.stringify(item.text));
  for (const item of cases.hosts) assert.equal(await accepted("NAME", [item.text], ["field"], false), item.valid, "host " + JSON.stringify(item.text));
  for (const item of cases.slots.concat(cases.reserved_headers)) {
    assert.equal(await accepted("NAME", ["example.com"], [item.text], false), item.valid, "slot " + JSON.stringify(item.text));
  }
  for (const item of cases.reaches) {
    assert.equal(await accepted("NAME", item.sites, item.slots, false), item.valid, "reach " + JSON.stringify([item.sites, item.slots]));
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
  const answerOnly = (keep, times) => {
    world.clearFaults();
    world.fault("POST /api/secure/log/bodies", (request) => {
      const answer = JSON.parse(world.api("POST", "/api/secure/log/bodies", null, request.body).body);
      return { status: 200, body: { entries: answer.entries.filter((item) => keep(item.key)), missing: [] } };
    }, times);
  };
  const asked = (back) => JSON.parse(world.sent("POST /api/secure/log/bodies").slice(back === undefined ? -1 : back)[0].body).keys;
  // The backend answers the first key of one request and ends there: the keys are asked for with
  // the earliest entry first, the round is not complete, and nothing was held back. The round
  // that follows it at once asks for the keys that were left, the earliest first.
  answerOnly((key) => key === written[0].key, 1);
  await nextDay(fx);
  await world.settle(1000);
  assert.deepEqual(asked(-2), written.map((entry) => entry.key));
  assert.deepEqual(asked(), [written[1].key, written[2].key]);
  assert.deepEqual(world.reports.slice(-2).map((report) => report.status + ":" + report.store), ["pending:verified", "verified:verified"]);
  assert.equal(world.stored("log.blocked").count, 0);
  // Two more entries. The backend names the later one and not the one before it: a read held
  // back, and no round follows a round held back.
  for (const id of ["r4", "r5"]) {
    world.advance(1000);
    written.push(node.record("c", [{ t: "connection_created", time_ms: world.now, record_id: id, provider: "slack", scope: "" }]));
  }
  answerOnly((key) => key === written[4].key);
  const sent = world.sent("POST /api/secure/log/bodies").length;
  await nextDay(fx);
  await world.settle(1000);
  assert.equal(world.sent("POST /api/secure/log/bodies").length, sent + 1);
  assert.deepEqual(asked(), [written[3].key, written[4].key]);
  assert.equal(world.state.log.store, "blocked");
  assert.equal(world.state.log.store_failure, "bodies:skipped");
  // The key that was left out stands first in the next request, and an answer that names no key
  // holds it back again.
  answerOnly(() => false);
  await nextDay(fx);
  assert.deepEqual(asked(), [written[3].key]);
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
  const answerUntil = (count, times) => {
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
    }, times);
  };
  const asked = (back) => JSON.parse(world.sent("POST /api/secure/log/bodies").slice(back === undefined ? -1 : back)[0].body).keys;
  // One answer names the first key and reports the rest as unread: the round is not complete,
  // nothing is held back, and the round that follows it at once asks for the rest.
  answerUntil(1, 1);
  await nextDay(fx);
  await world.settle(1000);
  assert.deepEqual(asked(-2), written.map((entry) => entry.key));
  assert.deepEqual(asked(), [written[1].key, written[2].key]);
  assert.deepEqual(world.reports.slice(-2).map((report) => report.status + ":" + report.store), ["pending:verified", "verified:verified"]);
  assert.equal(world.stored("log.blocked").count, 0);
  assert.equal(heldReads(world), undefined);
  // Two more entries, and every key of the request is unread: its first key is held back.
  for (const id of ["r4", "r5"]) {
    world.advance(1000);
    written.push(fx.nodes[0].record("c", [{ t: "connection_created", time_ms: world.now, record_id: id, provider: "slack", scope: "" }]));
  }
  answerUntil(0);
  await nextDay(fx);
  assert.deepEqual(asked(), [written[3].key, written[4].key]);
  assert.equal(world.state.log.store, "blocked");
  assert.equal(world.state.log.store_failure, "bodies:skipped");
  // (The key behind it was listed and not judged: the next round asks for it as well.)
  assert.deepEqual(heldReads(world), { keys: [written[3].key], shown: [], pages: [], unjudged: [written[4].key] });
  // An unread key in front of a key the answer names.
  world.clearFaults();
  world.fault("POST /api/secure/log/bodies", (request) => {
    const answer = JSON.parse(world.api("POST", "/api/secure/log/bodies", null, request.body).body);
    return {
      status: 200, body: {
        entries: answer.entries.filter((item) => item.key === written[4].key), missing: [], unread: [written[3].key],
      },
    };
  });
  await nextDay(fx);
  assert.equal(world.state.log.store_failure, "bodies:skipped");
  assert.equal(world.stored("log.blocked").count, 2);
  world.clearFaults();
  await nextDay(fx);
  assert.equal(world.state.log.status, "verified");
  assert.equal(heldReads(world), undefined);
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
