// The tests of the secure program on the model of the bridge (bridge.js) and the scenarios of
// scenarios.js. Run: node --test secure-program/tests/
//
// The first tests check the model against protocol/vectors.json (the reference the apps test their
// bridges against) so that the scenarios run on the bytes the protocol specifies. The scenarios
// then check the observable contract of the program: what it reports (POST /api/secure/log/verified),
// what it publishes (state.log, state.grant), which node receives a grant, and what the ledger holds.
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const bridge = require("./bridge.js");
const { scenarios } = require("./scenarios.js");

const PROGRAM_PATH = path.join(__dirname, "..", "secure-program.js");
const source = fs.readFileSync(PROGRAM_PATH, "utf8");
const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "protocol", "vectors.json"), "utf8"));
const { b64u, bytes, utf8, concat } = bridge;

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
  assert.equal(bridge.ed25519Verify(
    bytes(log.node_sign_pk), concat(utf8("pickle.secure.v1.head\n"), bytes(log.head.body)), bytes(log.head.sig)), true);
});

test("the model verifies the signed values of the vectors as the vectors say", () => {
  for (const item of vectors.signed.cases) {
    const valid = bridge.ed25519Verify(
      bytes(item.public_key), concat(utf8(item.context_text), bytes(item.body)), bytes(item.sig));
    assert.equal(valid, item.valid, item.name);
  }
});

test("the top level of the program defines secureProgram and calls nothing", () => {
  const world = new bridge.World();
  const program = bridge.loadProgram(source, world);
  assert.equal(program.version, bridge.declaredVersion(source));
  assert.equal(typeof program.procedures.sync, "function");
  assert.equal(typeof program.onEvent, "function");
  assert.equal(world.requests.length, 0);
  assert.equal(world.logs.length, 0);
});

test("the program lists the releases of the public repository in order, each writing to the log store", () => {
  const listed = bridge.listedMeasurements(source);
  assert.deepEqual(listed.map((release) => release.release), [
    "v1.1.0", "v1.2.0", "v1.3.0", "v1.4.0", "v1.5.0", "v1.5.2", "v2.0.0", "v2.0.1", "v2.1.0", "v2.2.0",
    "v2.3.0",
  ]);
  assert.ok(listed.every((release) => release.log_store === true));
  const measurements = new Set(listed.map((release) => release.pcr0 + release.pcr1 + release.pcr2));
  assert.equal(measurements.size, listed.length);
});

test("the nodes of the newest three releases side by side: each receives the grant, the transfer between them is traced, the three chains verify", async () => {
  const result = await scenarios.releases_side_by_side(source);
  assert.deepEqual(result.releases, ["v2.1.0", "v2.2.0", "v2.3.0"]);
  assert.equal(result.report.status, "verified");
  assert.equal(result.report.nodes, 3);
  assert.equal(result.report.unknown_nodes, 0);
  assert.equal(result.report.newer_release_nodes, 0);
  assert.equal(result.report.missing, 0);
  assert.equal(result.log.status, "verified");
  assert.equal(result.rejected_nodes, 0);
  for (const name of ["node0", "node1", "node2"]) {
    assert.equal(result.nodes[name].grants, 1, name);
    assert.deepEqual(result.nodes[name].ledger, {
      origin: "grant", unknown: false, checkpoint: result.nodes[name].chain, gone: false,
    }, name);
  }
  // node2: the transfer in, the provider request and the grant of this run.
  assert.equal(result.nodes.node2.chain, 3);
});

test("a node of the latest listed release receives the grant and its chain verifies", async () => {
  const result = await scenarios.plain(source);
  assert.equal(result.report.status, "verified");
  assert.equal(result.report.unknown_nodes, 0);
  assert.equal(result.report.newer_release_nodes, 0);
  assert.equal(result.report.nodes, 1);
  assert.equal(result.report.program_version, bridge.declaredVersion(source));
  assert.equal(result.log.status, "verified");
  assert.equal(result.log.program_version, bridge.declaredVersion(source));
  assert.equal(result.grant.state, "active");
  assert.equal(result.nodes.node0.grants, 1);
  assert.equal(result.nodes.node0.chain, 1);
  assert.deepEqual(result.nodes.node0.ledger, { origin: "grant", unknown: false, checkpoint: 1, gone: false });
});

test("a node of a release the program does not list leaves the run pending, not attention", async () => {
  const result = await scenarios.later_release(source);
  assert.equal(result.report.status, "pending");
  assert.equal(result.report.newer_release_nodes, 1);
  assert.equal(result.report.unknown_nodes, 0);
  assert.equal(result.report.missing, 0);
  assert.equal(result.log.status, "pending");
  assert.equal(result.log.newer_release_nodes, 1);
  assert.equal(result.log.unknown_nodes, 0);
  assert.equal(result.log.unverified_nodes, 0);
  // No grant went to the node, it is not a rejected attestation, and it is not in the ledger.
  assert.equal(result.nodes.node1.grants, 0);
  assert.equal(result.nodes.node1.ledger, null);
  assert.equal(result.rejected_nodes, 0);
  assert.equal(result.grant.state, "active");
  assert.equal(result.nodes.node0.grants, 1);
  // The log screen reports the same judgement.
  assert.equal(result.screen.status, "pending");
  assert.equal(result.screen.newer_release_nodes, 1);
  assert.equal(result.screen.unknown_nodes, 0);
});

test("a listed measurement with a corrupted signature is a failed attestation (attention)", async () => {
  const result = await scenarios.listed_broken_signature(source);
  assert.equal(result.report.status, "attention");
  assert.equal(result.report.unknown_nodes, 1);
  assert.equal(result.report.newer_release_nodes, 0);
  assert.equal(result.rejected_nodes, 1);
  assert.equal(result.nodes.node1.grants, 0);
  assert.deepEqual(result.nodes.node1.ledger, { origin: "store", unknown: true, checkpoint: 2, gone: true });
});

test("an unlisted measurement with a corrupted signature is not a later release (attention)", async () => {
  const result = await scenarios.unlisted_broken_signature(source);
  assert.equal(result.report.status, "attention");
  assert.equal(result.report.unknown_nodes, 1);
  assert.equal(result.report.newer_release_nodes, 0);
  assert.equal(result.rejected_nodes, 1);
  assert.equal(result.nodes.node1.grants, 0);
});

test("an unlisted measurement whose binding names another log store is refused (attention)", async () => {
  const result = await scenarios.unlisted_other_store(source);
  assert.equal(result.report.status, "attention");
  assert.equal(result.report.unknown_nodes, 1);
  assert.equal(result.report.newer_release_nodes, 0);
  assert.equal(result.rejected_nodes, 1);
  assert.equal(result.nodes.node1.grants, 0);
});

test("an enclave in debug mode is refused, never a later release (attention)", async () => {
  const result = await scenarios.unlisted_debug_enclave(source);
  assert.equal(result.report.status, "attention");
  assert.equal(result.report.unknown_nodes, 1);
  assert.equal(result.report.newer_release_nodes, 0);
  assert.equal(result.rejected_nodes, 1);
  assert.equal(result.nodes.node1.grants, 0);
});

test("a traced node of a release the program does not list is left pending, not read", async () => {
  const result = await scenarios.later_release_traced(source);
  assert.equal(result.report.status, "pending");
  assert.equal(result.report.newer_release_nodes, 1);
  assert.equal(result.report.unknown_nodes, 0);
  assert.equal(result.log.unverified_nodes, 0);
  assert.equal(result.nodes.node1.grants, 0);
  // The trace put the node into the ledger; its chain was not walked (the verified point stays).
  assert.deepEqual(result.nodes.node1.ledger, { origin: "grant", unknown: false, checkpoint: 0, gone: false });
  assert.equal(result.nodes.node0.ledger.checkpoint, 3);
});

test("a gap older than the grace of a young gap is attention with the missing count", async () => {
  const result = await scenarios.gap(source);
  assert.equal(result.report.status, "attention");
  assert.equal(result.report.missing, 1);
  assert.equal(result.report.unknown_nodes, 0);
  assert.equal(result.report.newer_release_nodes, 0);
  assert.equal(result.log.unverified_nodes, 1);
});

test("the replacement of the program: the mark of an earlier program is pending, a new runtime verifies at once, the program that lists the release verifies the chain", async () => {
  const phases = await scenarios.replacement(source);
  // Phase one: the mark the earlier program left (origin store, unknown_ms) is not counted.
  assert.equal(phases.marked.report.status, "pending");
  assert.equal(phases.marked.report.newer_release_nodes, 1);
  assert.equal(phases.marked.report.unknown_nodes, 0);
  assert.deepEqual(phases.marked.nodes.node1.ledger, { origin: "store", unknown: true, checkpoint: 2, gone: true });
  // Phase two: a pending run keeps verified_ms, so the next synchronization of the runtime verifies
  // again; the first synchronization of a new runtime verifies in every case.
  assert.equal(phases.foreground_reports, 1);
  assert.equal(phases.new_runtime_reports, 1);
  // Phase three: the program that lists the release.
  assert.equal(phases.listed.report.status, "verified");
  assert.equal(phases.listed.report.program_version, bridge.declaredVersion(source) + 1);
  assert.equal(phases.listed.report.newer_release_nodes, 0);
  assert.equal(phases.listed.report.unknown_nodes, 0);
  assert.equal(phases.listed.nodes.node1.grants, 1);
  assert.deepEqual(phases.listed.nodes.node1.ledger, { origin: "grant", unknown: false, checkpoint: 3, gone: false });
});

test("a node another device delegated to is known through the shared ledger, not a delegation the app did not make", async () => {
  const result = await scenarios.second_device(source);
  assert.equal(result.first_device.report.status, "verified");
  assert.equal(result.first_device.ledger.node1, "grant");
  assert.equal(result.second_device.report.status, "verified");
  assert.equal(result.second_device.report.unknown_nodes, 0);
  assert.equal(result.second_device.ledger.node1, "grant+gone");
  assert.ok(result.uploads >= 1);
});

test("a grant whose reply was lost is a grant of this app: the node that ends after it is not marked", async () => {
  const result = await scenarios.reply_lost_then_node_ends(source);
  assert.equal(result.node_took_grant, true);
  assert.equal(result.next_day.status, "verified");
  assert.equal(result.next_day.unknown_nodes, 0);
  assert.equal(result.day_after.status, "verified");
  assert.equal(result.ledger.node1, "grant+gone");
});

test("a grant whose reply was lost to a living node verifies in the same run", async () => {
  const result = await scenarios.reply_lost_node_lives(source);
  assert.equal(result.first_run.status, "verified");
  assert.equal(result.first_run.unknown_nodes, 0);
  assert.equal(result.second_run.status, "verified");
  assert.equal(result.ledger.node1, "grant");
});

test("the log screen renews the grants before it judges the log", async () => {
  const result = await scenarios.log_screen_before_sync(source);
  assert.equal(result.screen.status, "verified");
  assert.equal(result.screen.unknown_nodes, 0);
  assert.equal(result.published_after_screen, "verified");
  assert.equal(result.published_after_sync, "verified");
  assert.equal(result.ledger.node1, "grant");
});

test("a run suspended across a transfer is judged again on fresh reads before it is published", async () => {
  const result = await scenarios.suspended_run_crosses_transfer(source);
  assert.equal(result.suspended_run.report.status, "verified");
  assert.equal(result.suspended_run.report.unknown_nodes, 0);
  assert.equal(result.suspended_run.published, "verified");
  assert.equal(result.after_next_sync, "verified");
  assert.equal(result.ledger.node1, "grant");
});

test("a transfer that lands between the heads and the listing of a run is explained in that run, whether the giving node lives on or ends", async () => {
  for (const name of ["transfer_after_heads", "transfer_after_heads_giver_ends"]) {
    const result = await scenarios[name](source);
    assert.equal(result.run.report.status, "verified", name);
    assert.equal(result.run.report.unknown_nodes, 0, name);
    assert.equal(result.run.published, "verified", name);
    // The second look traced the transfer: node1 is a grant node of the ledger before the next
    // synchronization grants to it.
    assert.equal(result.run.ledger.node1, "grant", name);
    assert.equal(result.after_next_sync, "verified", name);
    assert.equal(result.node1_grants, 1, name);
  }
  const ended = await scenarios.transfer_after_heads_giver_ends(source);
  assert.equal(ended.ledger.node0, "grant+gone");
});

test("a store request that failed once is made again, and a read that keeps failing is named in the report", async () => {
  const once = await scenarios.store_answers_once_503(source);
  assert.equal(once.failed_answers, 1);
  assert.equal(once.report.status, "verified");
  assert.equal(once.report.store, "verified");
  assert.equal(once.store_failure, "");
  const always = await scenarios.store_objects_fail(source);
  assert.equal(always.report.status, "pending");
  assert.equal(always.report.store, "unreachable");
  assert.equal(always.store_failure, "object:503");
});

test("the report names the nodes counted as delegations the app did not make", async () => {
  const result = await scenarios.listed_broken_signature(source);
  assert.equal(result.report.unknown_nodes, 1);
  assert.equal(result.report.unknown_node_ids.length, 1);
  assert.match(result.report.unknown_node_ids[0], /^[A-Za-z0-9_-]{43}$/);
  assert.equal(result.report.store_failure, "");
});

test("a verified run is not repeated within the period, and a new runtime verifies at its first synchronization", async () => {
  const world = new bridge.World();
  world.createAccount();
  const listed = bridge.listedMeasurements(source);
  world.addNode({ release: listed[listed.length - 1].release, measurement: listed[listed.length - 1] });
  const first = bridge.loadProgram(source, world);
  await first.onEvent("session_ready", {});
  assert.equal(world.reports.length, 1);
  assert.equal(world.reports[0].status, "verified");
  world.advance(60000);
  await first.onEvent("foreground", {});
  assert.equal(world.reports.length, 1);
  const second = bridge.loadProgram(source, world);
  await second.onEvent("session_ready", {});
  assert.equal(world.reports.length, 2);
  assert.equal(world.reports[1].status, "verified");
});

// ---- Application passwords: the provider of the procedures ----

/** A world whose account has delegated to one node of the latest listed release (the run of
 *  session_ready), and the program on it. */
async function delegatedProgram() {
  const world = new bridge.World();
  world.createAccount();
  const listed = bridge.listedMeasurements(source);
  const latest = listed[listed.length - 1];
  world.addNode({ release: latest.release, measurement: latest });
  const program = bridge.loadProgram(source, world);
  await program.onEvent("session_ready", {});
  return { world: world, program: program };
}

function requestsTo(world, method, path) {
  return world.requests.filter((request) => (request.method || "GET") === method && request.path === path);
}

/** A value the program returned, as plain data of this realm (the objects of the program belong to
 *  the context the loader made, so a strict deep comparison would see another prototype). */
function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

test("connect_app_password seals the record for the provider of the argument, saves it on the path of that provider and checks the statement against it; the absent provider is naver_mail", async () => {
  const { world, program } = await delegatedProgram();
  const calendar = await program.procedures.connect_app_password({
    username: "Alice@naver.com", password: "fixture12345", provider: "naver_calendar",
  });
  assert.deepEqual(plain(calendar), { provider: "naver_calendar", connection_id: "connection-1", identity: "alice@naver.com" });
  const saves = requestsTo(world, "PUT", "/api/secure/connections/naver_calendar/app-password");
  assert.equal(saves.length, 1);
  const record = JSON.parse(saves[0].body).record;
  assert.equal(record.kind, "app_password");
  assert.equal(record.provider, "naver_calendar");
  assert.equal(record.user_id, world.userId);
  assert.ok(!saves[0].body.includes("fixture12345"), "the password leaves only inside the ciphertext");

  const mail = await program.procedures.connect_app_password({ username: "alice@naver.com", password: "fixture12345" });
  assert.equal(mail.provider, "naver_mail");
  assert.equal(requestsTo(world, "PUT", "/api/secure/connections/naver_mail/app-password").length, 1);
  assert.equal(JSON.parse(requestsTo(world, "PUT", "/api/secure/connections/naver_mail/app-password")[0].body).record.provider, "naver_mail");

  const before = world.requests.length;
  await assert.rejects(
    program.procedures.connect_app_password({ username: "alice@naver.com", password: "fixture12345", provider: "naver_cafe" }),
    (error) => error.code === "invalid_input");
  assert.equal(world.requests.length, before, "an unknown provider sends nothing");

  // A statement that names another provider than the path is not a verified connection.
  world.appPasswordStatementProvider = "naver_mail";
  await assert.rejects(
    program.procedures.connect_app_password({ username: "alice@naver.com", password: "fixture12345", provider: "naver_calendar" }),
    (error) => error.code === "unverified_connection");
});

test("begin_app_password_setup registers the request on the path of its provider and refuses another provider while it is pending; sync finishes the capture as a record of that provider", async () => {
  const { world, program } = await delegatedProgram();
  const begun = await program.procedures.begin_app_password_setup({ identity: "Alice", provider: "naver_calendar" });
  assert.equal(begun.phase, "ready");
  const posts = requestsTo(world, "POST", "/api/secure/connections/naver_calendar/setup");
  assert.equal(posts.length, 1);
  const signed = JSON.parse(posts[0].body);
  const intent = JSON.parse(bytes(signed.payload).toString("utf8"));
  assert.equal(intent.provider, "naver_calendar");
  assert.equal(intent.identity, "alice@naver.com");
  assert.equal(intent.user_id, world.userId);
  assert.deepEqual(world.state.mail_setup, { phase: "ready", provider: "naver_calendar", error: null });
  assert.equal(world.keychain.has("com.pickle.client.secure.mail-setup\n" + world.userId), true);

  await assert.rejects(
    program.procedures.begin_app_password_setup({ identity: "alice", provider: "naver_mail" }),
    (error) => error.code === "setup_in_progress");
  assert.equal(requestsTo(world, "POST", "/api/secure/connections/naver_mail/setup").length, 0);
  // The same request again is the same registration.
  const again = await program.procedures.begin_app_password_setup({ identity: "alice", provider: "naver_calendar" });
  assert.deepEqual(plain(again), plain(begun));
  assert.equal(requestsTo(world, "POST", "/api/secure/connections/naver_calendar/setup").length, 2);

  // The browser issued the password: the backend holds the capture sealed to the reception key.
  const password = "fixture12345";
  const plaintext = utf8(JSON.stringify({ username: "alice@naver.com", password: password }));
  const sealed = bridge.hpkeSeal("chacha20poly1305", bytes(intent.recipient_pk), utf8("pickle-app-password-setup-v1"),
    bridge.sha("sha256", bytes(signed.payload)), plaintext);
  world.appPasswordSetup.phase = "captured";
  world.appPasswordSetup.capture = { enc: b64u(sealed.enc), ct: b64u(sealed.ciphertext) };
  await program.procedures.sync();
  assert.equal(world.appPasswordSaves.length, 1);
  assert.equal(world.appPasswordSaves[0].provider, "naver_calendar");
  assert.equal(world.appPasswordSaves[0].body.setup_id, intent.id);
  assert.equal(world.appPasswordSaves[0].body.record.provider, "naver_calendar");
  assert.deepEqual(world.state.mail_setup,
    { phase: "connected", provider: "naver_calendar", identity: "alice@naver.com", error: null });
  assert.equal(world.appPasswordSetup, null, "the request is deleted after the save");
  assert.equal(world.keychain.has("com.pickle.client.secure.mail-setup\n" + world.userId), false);
  assert.ok(!JSON.stringify(world.state).includes(password));
  assert.ok(!JSON.stringify(world.appPasswordSaves).includes(password));
});

test("cancel_app_password_setup deletes the pending request on the path of its provider and clears the published setup", async () => {
  const { world, program } = await delegatedProgram();
  await program.procedures.begin_app_password_setup({ identity: "alice", provider: "naver_calendar" });
  const setupId = world.appPasswordSetup.setup_id;
  assert.deepEqual(plain(await program.procedures.cancel_app_password_setup()), {});
  assert.equal(requestsTo(world, "DELETE", "/api/secure/connections/naver_calendar/setup/" + setupId).length, 1);
  assert.equal(world.appPasswordSetup, null);
  assert.equal(world.state.mail_setup, undefined);
  assert.equal(world.keychain.has("com.pickle.client.secure.mail-setup\n" + world.userId), false);
});
