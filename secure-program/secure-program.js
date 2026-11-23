// The secure program of the Pickle apps. The secure executor of the iOS app (JavaScriptCore) and
// of the Android app (QuickJS) runs this file. It owns the device side of the credential protocol:
// the creation and derivation of the master key, the verification of the attestation of enclave
// nodes, the sealed delivery of grants and revokes, the encryption of credential records and of
// vault secrets, the reading and judging of the credential log, and the transfer of the master key
// between the devices of one account.
//
// This file is the source of truth. The repository pickle-com/interactive-character vendors a
// byte-identical copy at backend/assets/ui/secure-program.js and serves it to the apps. A release
// build of an app loads a served program only when its SHA-256 is the subject of a release
// statement signed by the release key of the operator and recorded in the public transparency log
// (docs/protocol.md, "The secure program release"). Every version an app can load is therefore a
// tag secure-program-v{VERSION} of this repository.
//
// Native functions reach the program through the global `native` only (the bridge primitives of
// the apps); every cryptographic algorithm is a bridge primitive. This file parses formats only
// (base64url, UTF-8, CBOR, query strings, the XML of a listing). The top level of the file is
// evaluated with the bridge closed, so the top level defines things and calls nothing.
// Contract: docs/ssot/client/secure-executor.md of pickle-com/interactive-character.
//
// How the work of the program is ordered (docs/protocol.md, "The program of the app"): three
// lines, each running one piece of work at a time (the procedures a user starts, the
// synchronizations, the reads of the log screen), two locks (the grants, one round of the log),
// a time limit on every request and on every procedure, and no loop without a bound on its turns.
(function () {
  "use strict";

  // ---- Constants ----

  const VERSION = 43;
  const MASTER_KEY_SERVICE = "com.pickle.client.secure.master-key";
  const DAY_MS = 86400000;

  // ---- The time limits ----
  // Every request the program sends has a time limit: the program lets the request race a sleep of
  // the bridge and treats the request as failed with the code timeout when the sleep ends first
  // (an answer that arrives later is dropped). The timeoutMs of native.http applies to requests
  // of an absolute address only, so the requests to the backend are bound the same way.
  //   API_TIMEOUT_MS         a request to the backend outside the log
  //   LOG_API_TIMEOUT_MS     a request to the backend of a round or of the log screen
  //   LOG_STORE_TIMEOUT_MS   a request to the log store (Amazon S3)
  //   NODE_TIMEOUT_MS        a command to a node, carried by the relay route of the backend
  const API_TIMEOUT_MS = 30000;
  const LOG_API_TIMEOUT_MS = 10000;
  const LOG_STORE_TIMEOUT_MS = 10000;
  const NODE_TIMEOUT_MS = 30000;
  // The longest time one procedure takes, from its call to its end, without the time the device
  // spent in an operation that waits for the user (webAuth, deviceOwnerAuth, promptSecret,
  // presentSecret). The executors end a procedure at 120 seconds from outside the queue of the
  // runtime and leave its JavaScript running; a procedure that ends itself before that leaves no
  // work behind that holds a line.
  const PROCEDURE_LIMIT_MS = 100000;
  // The bridge cuts a sleep at 60 seconds: a wait longer than this is made of sleeps of this
  // length at most.
  const SLEEP_STEP_MS = 30000;
  // The time a turn waits in an operation that waits for the user is not counted into it. A wait
  // of a turn outlasts this many such operations of the runtime, and ends with the next.
  const WAIT_INTERACTIVE_PASSES = 64;
  // A wait of a running runtime ends at its limit. A wait that ends later than its own limit by
  // more than this ended in a runtime that did not run for a part of it (the app was suspended).
  // The time is longer than any piece of work of the program keeps the runtime from its timers.
  const WAIT_LATE_MS = 5000;

  // ---- Grants ----
  // The lifetime of a grant is a number of days the user chooses (an integer from 1 to 30, 30 by
  // default). The renewal interval is the smaller of 24 hours and half of that lifetime.
  const GRANT_DAYS_MAX = 30;
  const GRANT_RENEW_MS = 86400000;
  // A synchronization a push with the reason grant_required started hands a grant again to a node
  // the backend reports no grant row for, when the last grant this device sent that node is older
  // than this.
  const GRANT_REFILL_MS = 60000;
  // The nodes one attestation request names, and the most such requests one step sends.
  const ATTESTATION_NODES = 32;
  const ATTESTATION_REQUESTS = 4;
  // How far the time of a reply of a node may lie before the time of the attestation document of
  // that node (the correction error of the clock of the node).
  const REPLY_SKEW_MS = 5000;

  // ---- The node ledger of the programs before v43 ----
  // The settings of the delegation (the revocation time, the resumption time, the lifetime of a
  // grant and the time it was set) are shared by the devices of an account in a synchronized key
  // store item, in the form the programs before v43 gave it (the node ledger). This program keeps
  // the settings there. It judges nothing by the nodes of that ledger; it writes a node of a
  // release before LOG_FORMAT_3_FROM that it hands a grant to into the ledger, in the form of
  // those programs, and uploads the sealed ledger by their rule, because a device of the account
  // that still runs such a program counts a chain of a node no ledger of the account explains as
  // a delegation the app did not make.
  const LEDGER_SERVICE = "com.pickle.client.secure.ledger";
  const LEDGER_STORE_KEY = "ledger";
  const LEDGER_SHARE_PATH = "/api/secure/ledger";
  const LEDGER_SHARE_STORE_KEY = "ledger_shared";
  const LEDGER_SHARE_NONCE_BYTES = 12;
  const LEDGER_LIMIT_BYTES = 65536;

  // ---- The log (docs/protocol.md section 7) ----
  // The keys of the program store that hold what this device knows of the log of the account. No
  // secret value is among them; what names services and addresses (the kept screen, and what the
  // rounds read for the screen) is sealed with a key derived from the master key.
  //   log.grants      the nodes this device handed a grant to: {node: {granted_ms, not_after_ms,
  //                   release, first_ms, platform, attempted_ms}}
  //   log.cursor      the newest control key of the last round that covered the whole listing
  //   log.resume      where a round that was cut short by its page limit goes on
  //   log.nodes       what the node documents said: {node: {m, p, r, f, c}} (the digest of the
  //                   measurement, the platform, the release, the time first seen, the time a
  //                   contradiction of its signatures was found)
  //   log.unaccepted  the measurements no list of this program has: {digest: {first_ms, release,
  //                   held, node}} (held: the key of this account went to a node of it)
  //   log.blocked     the blocked rounds in a row: {first_ms, count}
  //   log.sample      the newest control keys the last round verified (LOG_SAMPLE_KEYS at most)
  //   log.seen        the digests of the control keys judged (LOG_SEEN_KEYS at most)
  //   log.missing     the keys of log.sample that left the listing within their retention
  //   log.withheld    the reads that were held back and are made again by every round: {keys:
  //                   [key], shown: [key], pages: [before_ms], watch_ms, objects, chains, nodes}
  //                   (the keys of entries of format 3, those of them a read of the log screen
  //                   asked for, the listing pages of the screen by the time they begin below, 0
  //                   for the first, the time until which the rounds read the first listing pages
  //                   for the screen, and the reads the screen made of the bucket of format 1
  //                   and format 2: the object versions of entries, the listings of chains, the
  //                   node discovery listing)
  //   log.recovered   what the rounds read of the reads of the log screen that were held back,
  //                   kept for the screen, sealed: the entries, the listing pages, the node
  //                   prefixes of the bucket of format 1 and format 2
  //   log.denied      the reads held back from the log screen that the screen notes itself and
  //                   has not read since: {pages: [{t, before_ms, limit}], chains: {node:
  //                   [{t, after, deep}]}} (the later pages of format 3, and the listings of
  //                   the chains of format 1 and format 2, one read for each day)
  //   log.legacy      the chains of format 1 and format 2: {nodes: {node: {seq, time_ms, until_ms,
  //                   closed, read_ms}}, waiting: {node: {until_ms, time_ms}}} (waiting: the receiving
  //                   nodes of transfers whose documents this device has still to judge)
  //   log.round       the last round: {v, done_ms, tried_ms, last, told, state, unfinished}
  //                   (unfinished: the rounds in a row that had more to read than they read)
  //   log.cache       the kept screen, sealed (the first page, the time the screen last read
  //                   its listings itself, the summary tally, what it knows of the chains)
  //   log.migrated    the mark that the ledger of the program before was carried over
  const STORE_GRANTS = "log.grants";
  const STORE_CURSOR = "log.cursor";
  const STORE_RESUME = "log.resume";
  const STORE_NODES = "log.nodes";
  const STORE_UNACCEPTED = "log.unaccepted";
  const STORE_BLOCKED = "log.blocked";
  const STORE_SAMPLE = "log.sample";
  const STORE_SEEN = "log.seen";
  const STORE_MISSING = "log.missing";
  const STORE_WITHHELD = "log.withheld";
  const STORE_RECOVERED = "log.recovered";
  const STORE_DENIED = "log.denied";
  const STORE_LEGACY = "log.legacy";
  const STORE_ROUND = "log.round";
  const STORE_CACHE = "log.cache";
  const STORE_MIGRATED = "log.migrated";
  const STORE_OUTCOMES = "outcomes";
  // The key of the device store that marks the sealing check as done for this device and account: a
  // query of the pending values (GET /api/secure/sealing) that found none, or an upload that left none.
  // Writing a master key (a new key, a replaced key, a transferred key) clears it.
  const SEALING_CHECK_STORE_KEY = "sealing_checked";
  // The keys of the program store the programs before v43 wrote and this one does not read.
  const RETIRED_STORE_KEYS = ["log_summary"];

  // The first release whose nodes write format 3 (major, minor, patch). A node of a release before
  // it wrote format 1 or format 2 into the bucket its binding names.
  const LOG_FORMAT_3_FROM = [2, 4, 0];
  // A round runs when the last completed one is this old.
  const LOG_ROUND_INTERVAL_MS = 86400000;
  // A round that ended pending is tried again by the next synchronization, not sooner than this
  // after the round before.
  const LOG_ROUND_RETRY_MS = 60000;
  // The longest time one round takes, from its start (a round runs in a turn of its own: a
  // synchronization and the log screen wait for it within their own turns).
  const LOG_ROUND_LIMIT_MS = 60000;
  // An event of the app itself (the start of the runtime, the return to the foreground) is served
  // by the synchronization that runs when that one began less than this ago.
  const EVENT_SYNC_FRESH_MS = 5000;
  // The listing pages of the control prefix one round reads (1,000 object versions each).
  const LOG_CONTROL_PAGES = 4;
  // The nodes one document request names and the most such requests one round sends, the keys one
  // body request names and the most such requests one round sends for its judgement. The store is
  // asked for one listing per node such a request names and hands out no document that verifies
  // for: the document requests of a read bound its listings of node documents.
  const LOG_DOCUMENT_NODES = 64;
  const LOG_DOCUMENT_REQUESTS = 2;
  const LOG_BODY_KEYS = 200;
  const LOG_ROUND_BODY_REQUESTS = 4;
  // The time a measurement no list of this program has may hold the key of the account before it
  // marks the log: a program that lists a new release is served before a node of that release
  // takes a grant, and a runtime loads the served program at the next start or return to the
  // foreground.
  const LOG_RELEASE_GRACE_MS = 86400000;
  // The reads the operator domain holds back mark the log when this many rounds in a row were
  // blocked and the first of them is this old.
  const LOG_BLOCKED_ROUNDS = 3;
  const LOG_BLOCKED_MS = 3 * DAY_MS;
  // A round that leaves reads undone because there was more to read than one round reads (more
  // listing pages, more nodes without a judgement, more bodies than its requests name, an answer
  // of the bodies that ended before its last key, more than fits its time) is not complete, and
  // the next round reads on.
  // An account in normal use is read to its end within a few such rounds, whatever it holds: the
  // rounds of a synchronization that end that way in a row, beyond this many, are rounds whose
  // reads are held back (someone writes objects under the prefix of the account faster than the
  // device reads them, or the answers of the backend never reach the end).
  const LOG_UNFINISHED_ROUNDS = 8;
  // A request of a round that was not answered counts as held back by the operator domain when
  // the backend answered another request of this runtime within this time of it.
  const LOG_REACH_MS = 60000;
  // An address the backend signed is valid for 300 seconds. A refusal of the store for an address
  // older than this is the age of the address (the app was suspended), not a refusal.
  const LOG_URL_FRESH_MS = 240000;
  const LOG_SAMPLE_KEYS = 64;
  const LOG_SEEN_KEYS = 4096;
  const LOG_MISSING_KEYS = 16;
  const LOG_NODES_KEPT = 256;
  // The reads that were held back that the device keeps for the rounds to make again: the keys
  // of entries, and the listing pages of the screen.
  const LOG_WITHHELD_KEYS = 32;
  const LOG_WITHHELD_PAGES = 2;
  // The time the rounds go on reading the listing pages that begin the two listings for the
  // screen after that read was held back from the screen, unless the screen makes it sooner.
  const LOG_WATCH_MS = 30 * DAY_MS;
  // What the rounds read of the reads of the log screen that were held back, kept for the screen
  // (log.recovered): the entries kept at most because the screen asked for their keys, the
  // events of those entries at most (an entry holds LOG_ENTRY_EVENTS at most, so one entry is
  // always kept), and the characters kept of one string of an event. Beyond the limits, what
  // was kept first leaves first. The entries of a kept listing page are kept with the page.
  const LOG_RECOVERED_KEYS = 128;
  const LOG_RECOVERED_EVENTS = 512;
  const LOG_RECOVERED_TEXT = 160;
  // The listing pages of the screen the rounds keep at most, and the events of the page a round
  // keeps of one (the entries of the same millisecond as the last one stay on the page).
  const LOG_RECOVERED_PAGES = 4;
  const LOG_RECOVERED_PAGE_EVENTS = 100;
  // The bytes of the value the rounds keep for the screen, before it is sealed. Entries and
  // pages of the usual size stay far below it; the limit bounds the work of reading the value.
  const LOG_RECOVERED_BYTES = 262144;
  // The reads of the bucket of format 1 and format 2 that were held back from the screen and
  // that the device keeps for the rounds to make again: the entries (each the object versions
  // the screen asked for under one seq) and the listings of chains.
  const LOG_WITHHELD_OBJECTS = 16;
  const LOG_WITHHELD_CHAINS = 8;
  // The reads held back from the screen that the screen notes itself (log.denied): the chains
  // whose listings it notes, and the reads it notes of one kind (the later pages, the listings
  // of one chain). A read held back is noted as one more read when the last one noted is
  // LOG_DENIED_INTERVAL_MS old (20 hours: the reads of one day are one, and the reads of two
  // days in a row are two, whatever the hours of the day), and a read noted that is not among
  // reads that mark the log ends LOG_DENIED_KEPT_MS after it was noted: the reads that mark the
  // log are reads held back on three days within that time. Reads that mark the log end
  // together when the last of them is that old.
  const LOG_DENIED_CHAINS = 8;
  const LOG_DENIED_READS = 8;
  const LOG_DENIED_INTERVAL_MS = 20 * 3600000;
  const LOG_DENIED_KEPT_MS = 30 * DAY_MS;
  // The retention of an object of the store (Object Lock, days). The absence of a key older than
  // this says nothing; a key is expected in the listing while it is a day younger than this.
  const LOG_RETENTION_DAYS = 365;
  // The most events one entry holds (docs/protocol.md 7.1).
  const LOG_ENTRY_EVENTS = 128;
  const RTIME_MAX = 9999999999999;

  // ---- The log screen ----
  // The events of one later page, the events of the first page the device keeps, the days of the
  // summary, the most entries one opening counts into it, the body requests one opening of the
  // screen sends (for its page, its round and its summary together), the time a call of read_log
  // waits for the read of the store before it answers from what the device kept, and the bodies
  // one read of a later page asks for at most.
  const LOG_SCREEN_EVENTS = 50;
  const LOG_KEEP_EVENTS = 50;
  const LOG_SUMMARY_DAYS = 7;
  const LOG_SUMMARY_ENTRIES = 1000;
  const LOG_SUMMARY_REQUESTS = 5;
  const LOG_SCREEN_WAIT_MS = 3000;
  const LOG_SCREEN_BODIES = 200;

  // ---- The chains of format 1 and format 2 (the bucket the binding names) ----
  // The chains one round follows, the nodes one address request names, the passes of listings
  // and the entry bodies one round spends, the object versions it reads under one seq of a
  // chain for a control entry, the object versions per seq a listing page that goes on holds
  // at most on average when it holds what a node wrote and no more, the pages of the node
  // discovery listing, the time
  // after the end of a grant at which the chain of its node is read for the last time, the reads
  // of the store in flight at once, the object versions one address request names, the digits of
  // seq and of time_ms in an object key, the listings one call of the screen spends on going down
  // the chains, the steps that find the end of a chain nothing else gives, and the entries the
  // screen keeps opened in a runtime.
  const LEGACY_NODES = 64;
  const LEGACY_LISTING_NODES = 16;
  const LEGACY_ROUND_PASSES = 4;
  const LEGACY_ROUND_BODIES = 64;
  const LEGACY_SEQ_READS = 8;
  const LEGACY_SEQ_VERSIONS = 5;
  const LEGACY_DISCOVERY_PAGES = 2;
  const LEGACY_CLOSE_SLACK_MS = DAY_MS;
  const LEGACY_FOUND_INTERVAL_MS = DAY_MS;
  const LOG_STORE_CONCURRENCY = 8;
  const LOG_STORE_OBJECTS = 100;
  const LOG_STORE_SEQ_DIGITS = 20;
  const LOG_STORE_TIME_DIGITS = 13;
  const LEGACY_SCREEN_LISTS = 12;
  const LEGACY_TOP_STEPS = 48;
  const LEGACY_DISPLAY_ENTRIES = 1000;
  const LEGACY_DISPLAY_LIST = 1000;
  // 2026-11-23T00:00:00Z. A node of a release before LOG_FORMAT_3_FROM names no measurement in
  // the event of a transfer of the delegation (grant_transferred_out), so the document of the
  // receiving node is what says of which release that node is. From this time on the backend
  // keeps the attestation document of every node that takes a transfer, for longer than the
  // store keeps the entry of the transfer. For a transfer whose event is of this time or later
  // and within the retention of the store (LOG_RETENTION_DAYS), the receiving node counts as
  // judged only by a document that verifies. The receiving node of any other transfer without
  // such a document is followed as a node of the release of the giving node (followLegacy).
  const LEGACY_TRANSFER_DOCUMENTS_FROM_MS = 1795392000000;
  // One request to the log store is made up to this many times: a transport failure, a 429 and a
  // 5xx status are tried again after the pauses below (milliseconds, one per further attempt).
  const LOG_STORE_ATTEMPTS = 2;
  const LOG_STORE_RETRY_MS = [500];
  // The query keys a presigned listing address may carry besides the signature keys (X-Amz-...):
  // the versions listing, its prefix and delimiter, the markers of the page, the page size (1000)
  // and the encoding of the names in the response (url: the keys are decoded).
  const LISTING_QUERY_KEYS = [
    "versions", "prefix", "delimiter", "key-marker", "version-id-marker", "max-keys", "encoding-type",
  ];

  // ---- Routes ----
  const LOG_READ_PATH = "/api/secure/log/read";
  const LOG_BODIES_PATH = "/api/secure/log/bodies";
  const LOG_DOCUMENTS_PATH = "/api/secure/log/documents";
  const LOG_REPORT_PATH = "/api/secure/log/verified";
  const LOG_LISTINGS_PATH = "/api/secure/log/store/listings";
  const LOG_OBJECTS_PATH = "/api/secure/log/store/objects";
  const GRANTS_PATH = "/api/secure/grants";
  const NODES_PATH = "/api/secure/nodes";
  const OUTCOMES_PATH = "/api/secure/procedures/outcomes";
  const SYNC_REPORT_PATH = "/api/secure/sync/report";
  const VAULT_PATH = "/api/secure/vault";

  // ---- The outcomes of the procedures ----
  // The upper bounds of the classes a time is counted into (ms; a longer time is the last class),
  // the calls reported one by one that a report carries, the time from which a call is reported
  // one by one, the pause before such a report, and the interval of the report of the counts.
  const OUTCOME_BOUNDS_MS = [250, 1000, 3000, 10000, 30000];
  const OUTCOME_EVENTS = 32;
  const OUTCOME_SLOW_MS = 10000;
  const OUTCOMES_WAIT_MS = 5000;
  const OUTCOMES_INTERVAL_MS = DAY_MS;
  const OUTCOME_NAMES_MAX = 64;

  // ---- The vault ----
  // The lengths the plaintext of a record of kind vault_secret is padded to (bytes), and the
  // limits of the form of a vault secret (docs/protocol.md section 6).
  const VAULT_PADDED_BYTES = [256, 512, 1024, 2048, 4096, 8192, 12272];
  const VAULT_SITES_MAX = 8;
  const VAULT_SLOTS_MAX = 4;
  const VAULT_SLOT_NAME_BYTES = 64;
  // The request headers no slot names: the headers a node of the forward role does not send for
  // its caller, and the headers it refuses a call for (docs/protocol.md 10.5).
  const VAULT_RESERVED_HEADERS = [
    "host", "content-length", "transfer-encoding", "connection", "keep-alive", "proxy-connection",
    "upgrade", "te", "trailer", "expect", "accept-encoding", "proxy-authorization", "range",
    "if-range", "accept-charset",
    "x-http-method-override", "x-http-method", "x-method-override", "forwarded", "x-forwarded-host",
    "x-forwarded-server", "x-forwarded-uri", "x-forwarded-prefix", "x-original-url",
    "x-original-uri", "x-original-host", "x-rewrite-url", "x-host", "x-http-host-override",
  ];

  // The DER of the AWS Nitro Enclaves Root-G1 certificate (base64url). Its SHA-256 is
  // 641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b.
  const NITRO_ROOT =
    "MIICETCCAZagAwIBAgIRAPkxdWgbkK_hHUbMtOTn-FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoM" +
    "BkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcN" +
    "NDkxMDI4MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMM" +
    "EmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL__Zy" +
    "2YlES1BR5TSksfbb48C8WBoyt7F2Bw7eEtaaP-ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZEh8l5YoQwTcU_" +
    "9KNCMEAwDwYDVR0TAQH_BAUwAwEB_zAdBgNVHQ4EFgQUkCW1DdkFR-eWw5b6cp3PmanfS5YwDgYDVR0PAQH_BAQDAgGG" +
    "MAoGCCqGSM49BAMDA2kAMGYCMQCjfy-Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMC" +
    "MQCi85sWBbJwKKXdS6BptQFuZbT73o_gBh1qUxl_nNr12UO8Yfwr6wPLb-6NIwLz3_Y";
  // The list of accepted measurements: for every enclave release its {release, pcr0, pcr1, pcr2}
  // (96 lower-case hex characters each). Every element is a build that anyone can make again from
  // that tag of the public repository pickle-com/credential-enclave. A node receives a grant only
  // when PCR0, PCR1 and PCR2 of its nitro document all equal an element of this list (or of
  // PRERELEASE_BUILDS when the server target is in PRERELEASE_TARGETS). A document that verifies
  // (certificate chain, signature, nonce, binding, challenge statement) with a measurement no list
  // has is the document of a release later than this program (verifyNitro): the node receives no
  // grant, and the key of the account moving to such a measurement marks the log once
  // LOG_RELEASE_GRACE_MS has passed (judgeRound). A node of a release with log_store true writes
  // the log entry to the log store (storage from which nothing is deleted) before the act the entry
  // precedes, and the binding of such a node must name the value of LOG_STORES. The name of the
  // release decides the format of its log (logFormatOf): a release from LOG_FORMAT_3_FROM on
  // writes format 3.
  //
  // A new release of the enclave is one more element at the end of this list, in the form of the
  // elements before it: {release: "v2.4.0", pcr0, pcr1, pcr2, log_store: true}.
  const ACCEPTED_RELEASES = [
    // pickle-com/credential-enclave v1.1.0 (commit 98cdbef4902e17d079e2a003804db6b3b10a8140).
    {
      release: "v1.1.0",
      pcr0: "b7750ca30f77ecaaf3637ec64aeb808c20ce1326d2e2bdfe10339eb24474f7a392495086cab56c7b9a3edac9e248f9fc",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "fcdb145cb1d571f5e7d5bd40f2338d25bd32c6c8d293691c090ef81faa63a9fba35e63bde4b9eb09f77f235f6a75be86",
      log_store: true,
    },
    // pickle-com/credential-enclave v1.2.0 (commit e5ad5a26a9c7ad35dc3707119fb6f9d964ee5b6b).
    {
      release: "v1.2.0",
      pcr0: "56aa136a46cdda7e4cc75f88d853b48e9a638c673ba5e8601f2eaceccdb62aae90cb167dfbadcb99b6936ee1bbcb8176",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "48a9ad30d2aed1a74da5a882276040fc8104c1bc978d87c53299bc07f6435beb7c6c5ed58642a63c3e5bcd2c474cb047",
      log_store: true,
    },
    // pickle-com/credential-enclave v1.3.0 (commit 172283b48d4f32d1fb56891729c13c319bb062dd).
    {
      release: "v1.3.0",
      pcr0: "3079688b6a202656abd434c799b8825f2b2594dd574d7bbc35403a2c1dfc4e65497cb9d1d23826e7eaa7994b733066dc",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "44d3c047fafab6c5165e12be192b2fbfbaed760925abd7ddfb1f59f6207d3a53fad31fc27c52fcfdbf45385972831262",
      log_store: true,
    },
    // pickle-com/credential-enclave v1.4.0 (commit dac46abbd60dcf0526a3682b4d27230fd8381de6).
    {
      release: "v1.4.0",
      pcr0: "9fb99e7c9f44808f80eda1937242c3b2117bde968cd4afdcbd277b9ddaf8b2f973e84bffb62794c1a1eddb06d122dd06",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "409f0336df11e68219b758724ce0c20f71deb815b25015a793ea4dc4dfe52a53f29654f45e938850cb8ee90cb419a9d7",
      log_store: true,
    },
    // pickle-com/credential-enclave v1.5.0 (commit ed7ac2a5c0d9c083142f7f709b98f34bddcc18c3).
    {
      release: "v1.5.0",
      pcr0: "1e93cb844f7f355581c45ab375410f83ca754fafe03cd4968976f47dd88b85d30c03040a48afba0f6f2f4e2f94ffa98a",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "37b282369d357e6a182a04bb906495865182c15decc5f19c5a83ef1049beeba7500234429891e5953f80667e8c694d7d",
      log_store: true,
    },
    // pickle-com/credential-enclave v1.5.2 (commit 2dcf8957a4afb78a1c0400e3d37df0053faa97ad).
    {
      release: "v1.5.2",
      pcr0: "edf5a93aec5f096f0bcd6717a2ffcf4265404cf121c1c0a40be66682e7d5f6e0d1a54b841e96e0f91d6ec806aa861143",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "2724b25256d100dbb5a6868d68e1d1dc219415c1a28f21e4a130ca14338466b102349e0737d5185fe34f89a666374639",
      log_store: true,
    },
    {
      release: "v2.0.0",
      pcr0: "172a6fae5d3597949155d20d4934d73f8089c8c50b4d531e21369a36e417f8f188d8bd2eaee700ae9d4f4b796d6ed59e",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "cffa93aaef31b351d79341b30048a5028c863dcb3ec6bdb093870541c7f135733357261b63609fa512d59dc8e7a13de7",
      log_store: true,
    },
    // pickle-com/credential-enclave v2.0.1 (commit daf520b17b70f1d89b571f06b0231e66092d57ef).
    {
      release: "v2.0.1",
      pcr0: "04349059fa93cdbee77b1e7143278d080a38e6024df90eac578562f3a0bfb3ebe27226f6c9c6eca3be938835d5020d50",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "6dfa057738dcfabb85bc7e395e745a9f58f98f54269fa07ef53c9e4d39669e62643574874a45628cd256083c9f2d32a9",
      log_store: true,
    },
    // pickle-com/credential-enclave v2.1.0 (commit 9f123732ad5e20640ec9e3a27fb9f628eadf9187).
    {
      release: "v2.1.0",
      pcr0: "4b636738685e1a61dd102c59d6c1cc5ddd50f6fb1c92afdf8850899a2bb58608198d423d4772ca77c711a172a70428ff",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "5ed1f53c8c96dfcc7e675663f24f4b2593e5f25d9e5e0bebad9e0be82891027875fe74d2b7c5ca5e899366773f1f84ba",
      log_store: true,
    },
    // pickle-com/credential-enclave v2.2.0 (commit c8a3cd4bd126e7a851929a1892d74efa8375fea2).
    {
      release: "v2.2.0",
      pcr0: "9e24cdfa167557ed423a4fcd8db9f9ec7b0040fa0fc82e42940b82d7e58c39c0c4e9c4540ba13d8f9871dc2ecd0284cc",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "f9e869ff68bc4bb473cac139c74d7a55358a70c737a56672fcc01d4421c1ae2f9ba4ee6cd29a4b63af6074c1a473bc6d",
      log_store: true,
    },
    // pickle-com/credential-enclave v2.3.0 (commit 29d450c2867b9c198c2f9680905a11120178d2b5).
    {
      release: "v2.3.0",
      pcr0: "8835de060043c5aec2220f2ced2ab91e29c33a1875bda879621df8d59b5da5524394a6fec9eaec8e09ff159a9ac6ac65",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "6ba116c4b0277f37dc8271a5913c7e06f9c5f66ccd684a667f0f7156adbcb14820fc89f2afd6baceea393f669a0633eb",
      log_store: true,
    },
    // The place of the element of release v2.4.0, the first release whose nodes write format 3
    // (LOG_FORMAT_3_FROM). Its three values are the measurement of the build of the tag v2.4.0 of
    // pickle-com/credential-enclave, as anyone makes it again from that tag:
    //   // pickle-com/credential-enclave v2.4.0 (commit <the commit of the tag>).
    //   {
    //     release: "v2.4.0",
    //     pcr0: "<96 lower-case hexadecimal characters>",
    //     pcr1: "<96 lower-case hexadecimal characters>",
    //     pcr2: "<96 lower-case hexadecimal characters>",
    //     log_store: true,
    //   },
  ];
  // Measurements of builds that never ran in prod: builds made from commits that are not in the
  // history of the public repository (marked pre-), and releases of the public repository that went
  // to alpha and dev only. They are accepted only when the server target is in PRERELEASE_TARGETS:
  // those envs still hold the log chains written by the nodes of these builds, and the verification
  // of those chains needs the documents of those nodes.
  const PRERELEASE_TARGETS = ["alpha", "dev"];
  const PRERELEASE_BUILDS = [
    {
      release: "pre-v1.1.0",
      pcr0: "2c362ce05f7d902770d2c8548f0d6ee7853199b34ac53b4281412fa5f91b668b7461b645827346e3759126266f555c86",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "b97775faf25cb1bb8d19d373fdd8a59dfe29aefeed2c0133ade1637d7d59f841a218ce665042c5fd9f46b688c4ca40e9",
    },
    {
      release: "pre-v1.1.1",
      pcr0: "974d950fdcad286a75e306f11498ae5bd4cd5d5bd75f5b760719a472b27f2c9e408d177803a6510c9eee9ed6be7f7fcd",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "2ecc25ab9c9d1c5229204b431a66157052815bc35d65ba368fa1448af1556aa10f13bff95730323cedca8cb92db63af9",
    },
    {
      release: "pre-v1.2.0",
      pcr0: "dce85342328a246829fc501d04680ccfda9d43f722f82d233b42e7f7bcc99ce360c117dbdee33bacbe05408b250c07ec",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "4db199114e57f05b048e57a06fc6be7bf51f784ea2a5cc9120528e19f69271cfa220095b228d5d9e3b5032eb0acff12d",
      log_store: true,
    },
    // pickle-com/credential-enclave v1.0.0.
    {
      release: "v1.0.0",
      pcr0: "a49acc0d349d87bea23da55f305efa010d5672b4a14d25599173e89dff67c71527016cddeb1609ad15c306f98e966ad5",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "c4071dc342fc4b0b68fa732e1010fecb14332374d4dccb104a8fe23c9a853b0880475378f247974d05e07b2bbeedee27",
      log_store: true,
    },
    // pickle-com/credential-enclave v1.1.0-rc.1 (commit 4a21460a06b7373260813c826e027b851816cfd3).
    {
      release: "v1.1.0-rc.1",
      pcr0: "b038b65ad0a56493482ef26db2f6e85c66eef7742831c6b0973bb7907d98cd11d5b5e9ca617abf34f2814843d370466f",
      pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      pcr2: "6c1cb1daea2e80ee17c639463f3134b4bdc50cc98c1d9bf496594e4035e1074c19c88a254ca82a25fd5b0c35ebbeb074",
      log_store: true,
    },
  ];
  // The log store per server target (docs/protocol.md 7.6). bucket and region are the value the
  // binding of a node names: the bucket that holds the entries of format 1 and format 2. A nitro
  // node of a release with log_store true is accepted only when the log of its binding equals this
  // value: every node that receives a user key is a node that writes to the log store of this
  // environment first. The entries of format 3 are in shards buckets: bucket number i of them is
  // named "{h8}-{bucket}-{i as four digits}", where h8 is the first 8 characters of the lower-case
  // hexadecimal SHA-256 of "{bucket}-{i as four digits}" (shardBucket). The entries of an account
  // are in the bucket whose number is the first two bytes of SHA-256(user_id), read as a
  // big-endian integer, modulo shards; the node document of a node is in the bucket of its node id
  // by the same rule. shards is a constant of the name of the log store, the one the nodes
  // compile in: 1,024 for the store of prod, 4 for the store of the local stack, 32 for any other.
  // local is the S3 stand-in of the local stack. It is not the store of a server target (the bridge
  // of a debug build reports the server target prod whatever backend the app talks to): it names
  // the buckets of the path-style addresses a debug build accepts (storeAddressAccepted). A release
  // build pins every address to the host of a bucket of its server target.
  const LOG_STORES = {
    alpha: { bucket: "character-credential-log-alpha-1", region: "us-west-2", shards: 32 },
    dev: { bucket: "character-credential-log-dev-1", region: "us-west-2", shards: 32 },
    prod: { bucket: "character-credential-log-prod-1", region: "us-west-2", shards: 1024 },
    local: { bucket: "character-credential-log-local-1", region: "us-west-2", shards: 4 },
  };
  // The server targets that accept a node of platform local (an ordinary process that no
  // attestation verifies: the custody operator). A build whose server target is outside this list
  // refuses local nodes unless it is a debug build or a build made for the local stack
  // (localAccepted).
  const OPERATOR_CUSTODY_TARGETS = ["alpha", "dev"];
  // The record kinds this program makes in the migration (the device-side sealing of what was
  // stored before the switch), and the most rounds of fetching and uploading one sync runs (one
  // fetch carries up to 100 items).
  const SEALING_KINDS = ["oauth_imported", "vault_password", "vault_totp", "vault_card"];
  const SEALING_ROUNDS = 5;

  // ---- Bytes ----

  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  /** Uint8Array -> base64url (no padding). The byte representation of the bridge. */
  function encode(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i += 3) {
      const a = bytes[i];
      const b = bytes[i + 1];
      const c = bytes[i + 2];
      out += ALPHABET[a >> 2] + ALPHABET[((a & 3) << 4) | ((b === undefined ? 0 : b) >> 4)];
      if (b !== undefined) out += ALPHABET[((b & 15) << 2) | ((c === undefined ? 0 : c) >> 6)];
      if (c !== undefined) out += ALPHABET[c & 63];
    }
    return out;
  }

  /** A base64url or base64 string -> Uint8Array. */
  function decode(encoded) {
    const clean = String(encoded).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
    const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
    let bits = 0;
    let acc = 0;
    let at = 0;
    for (let i = 0; i < clean.length; i += 1) {
      const value = ALPHABET.indexOf(clean[i]);
      if (value < 0) throw native.error("invalid_argument", "base64");
      acc = ((acc << 6) | value) & 0xffff;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out[at] = (acc >> bits) & 255;
        at += 1;
      }
    }
    return out;
  }

  /** A string -> UTF-8 bytes. */
  function utf8(value) {
    const out = [];
    for (const symbol of String(value)) {
      const code = symbol.codePointAt(0);
      if (code < 0x80) {
        out.push(code);
      } else if (code < 0x800) {
        out.push(0xc0 | (code >> 6), 0x80 | (code & 63));
      } else if (code < 0x10000) {
        out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
      } else {
        out.push(
          0xf0 | (code >> 18), 0x80 | ((code >> 12) & 63), 0x80 | ((code >> 6) & 63),
          0x80 | (code & 63));
      }
    }
    return new Uint8Array(out);
  }

  /** UTF-8 bytes -> a string. A byte that is not UTF-8 becomes U+FFFD. */
  function text(bytes) {
    let out = "";
    let at = 0;
    while (at < bytes.length) {
      const lead = bytes[at];
      const size = lead < 0x80 ? 1 : lead >= 0xc2 && lead < 0xe0 ? 2 : lead >= 0xe0 && lead < 0xf0 ? 3
        : lead >= 0xf0 && lead < 0xf5 ? 4 : 0;
      let code = size === 1 ? lead : size === 2 ? lead & 0x1f : size === 3 ? lead & 0x0f : lead & 0x07;
      let valid = size > 0 && at + size <= bytes.length;
      for (let i = 1; valid && i < size; i += 1) {
        const next = bytes[at + i];
        if ((next & 0xc0) === 0x80) code = (code << 6) | (next & 0x3f);
        else valid = false;
      }
      // A value that is not the shortest form, a surrogate, and a value above U+10FFFF are not UTF-8.
      if (valid && size === 3 && (code < 0x800 || (code >= 0xd800 && code <= 0xdfff))) valid = false;
      if (valid && size === 4 && (code < 0x10000 || code > 0x10ffff)) valid = false;
      out += valid ? String.fromCodePoint(code) : "�";
      at += valid ? size : 1;
    }
    return out;
  }

  function hex(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i += 1) out += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
    return out;
  }

  /** The concatenation of several byte arrays, in order. */
  function concat(...parts) {
    let total = 0;
    for (const part of parts) total += part.length;
    const out = new Uint8Array(total);
    let at = 0;
    for (const part of parts) {
      out.set(part, at);
      at += part.length;
    }
    return out;
  }

  /** Whether two byte arrays have the same length and content. */
  function equal(a, b) {
    if (a.length !== b.length) return false;
    let difference = 0;
    for (let i = 0; i < a.length; i += 1) difference |= a[i] ^ b[i];
    return difference === 0;
  }

  // ---- CBOR ----

  /** CBOR (RFC 8949) decoding: integers, bstr, tstr, arrays, maps, tags, false, true and null.
   *  Arrays and maps are read in both the definite-length form and the indefinite-length form
   *  (ended by a break): the payload of a real Nitro attestation document is an indefinite-length
   *  map. Strings are read in the definite-length form only. A bstr is a Uint8Array, a map is a
   *  Map, and a tag is removed so that the inner value is returned. */
  function cborDecode(bytes) {
    let at = 0;
    function need(count) {
      if (at + count > bytes.length) throw native.error("attestation_failed", "cbor truncated");
    }
    function argument(additional) {
      if (additional < 24) return additional;
      const width = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4
        : additional === 27 ? 8 : 0;
      if (width === 0) throw native.error("attestation_failed", "cbor length form");
      need(width);
      let value = 0;
      for (let i = 0; i < width; i += 1) value = value * 256 + bytes[at + i];
      at += width;
      return value;
    }
    // Whether the end of an indefinite-length array or map (the break, 0xff) was reached. When it
    // was, that byte is consumed.
    function atBreak() {
      need(1);
      if (bytes[at] !== 0xff) return false;
      at += 1;
      return true;
    }
    function item() {
      need(1);
      const initial = bytes[at];
      at += 1;
      const major = initial >> 5;
      const additional = initial & 31;
      if (major === 0) return argument(additional);
      if (major === 1) return -1 - argument(additional);
      if (major === 2 || major === 3) {
        const length = argument(additional);
        need(length);
        const slice = bytes.subarray(at, at + length);
        at += length;
        return major === 2 ? slice : text(slice);
      }
      if (major === 4) {
        const out = [];
        if (additional === 31) {
          while (!atBreak()) out.push(item());
          return out;
        }
        const count = argument(additional);
        for (let i = 0; i < count; i += 1) out.push(item());
        return out;
      }
      if (major === 5) {
        const out = new Map();
        if (additional === 31) {
          while (!atBreak()) {
            const key = item();
            out.set(key, item());
          }
          return out;
        }
        const count = argument(additional);
        for (let i = 0; i < count; i += 1) {
          const key = item();
          out.set(key, item());
        }
        return out;
      }
      if (major === 6) {
        argument(additional);
        return item();
      }
      if (additional === 20) return false;
      if (additional === 21) return true;
      if (additional === 22) return null;
      throw native.error("attestation_failed", "cbor simple value");
    }
    const value = item();
    if (at !== bytes.length) throw native.error("attestation_failed", "cbor trailing bytes");
    return value;
  }

  /** The CBOR encoding of one bstr (the head followed by the content bytes). */
  function cborByteString(bytes) {
    const n = bytes.length;
    const head = n < 24 ? [0x40 | n] : n < 256 ? [0x58, n] : n < 65536 ? [0x59, n >> 8, n & 255]
      : [0x5a, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
    return concat(new Uint8Array(head), bytes);
  }

  /** The encoding of the Sig_structure a COSE_Sign1 (RFC 9052) signature covers: the array
   *  ["Signature1", protected, h'', payload]. The second and the fourth element are the received
   *  bstr values as they are. */
  function cborEncodeSigStructure(protectedHeader, payload) {
    // 0x84 is an array of 4 elements, 0x6a the head of a 10-byte tstr, 0x40 a bstr of length 0.
    const context = new Uint8Array(
      [0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31]);
    return concat(
      context, cborByteString(protectedHeader), new Uint8Array([0x40]), cborByteString(payload));
  }

  // ---- Attestation ----

  function attestationFailure(reason) {
    return native.error("attestation_failed", reason);
  }

  /** Whether this build takes a node of platform local (an ordinary process that no attestation
   *  verifies): its server target is in OPERATOR_CUSTODY_TARGETS, it is a debug build, or it is a
   *  build made for the local stack (deviceInfo().local_stack_build, a key only a build that knows
   *  it reports). */
  function localAccepted() {
    const device = native.deviceInfo();
    return OPERATOR_CUSTODY_TARGETS.indexOf(device.server_target) >= 0 || device.debug_build === true ||
      device.local_stack_build === true;
  }

  /** The builds whose measurements this runtime accepts: ACCEPTED_RELEASES, and PRERELEASE_BUILDS
   *  when the server target is in PRERELEASE_TARGETS. */
  function acceptedBuilds() {
    const prerelease = PRERELEASE_TARGETS.indexOf(native.deviceInfo().server_target) >= 0;
    return ACCEPTED_RELEASES.concat(prerelease ? PRERELEASE_BUILDS : []);
  }

  /** The element of acceptedBuilds a measurement {pcr0, pcr1, pcr2} equals, undefined when none. */
  function listedBuild(measurement) {
    return acceptedBuilds().find(function (build) {
      return build.pcr0 === measurement.pcr0 && build.pcr1 === measurement.pcr1 &&
        build.pcr2 === measurement.pcr2;
    });
  }

  /** The digest of a measurement: the base64url SHA-256 of its three PCR values in hexadecimal.
   *  The program keeps a measurement in this form. */
  function measureOf(measurement) {
    return native.sha256(encode(utf8(measurement.pcr0 + measurement.pcr1 + measurement.pcr2)));
  }

  // The digests of the measurements of acceptedBuilds, by digest: the build. Computed at the first
  // use in a runtime (the top level calls nothing).
  let acceptedDigests = null;

  /** The build of acceptedBuilds with the digest measure, undefined when none. */
  function buildOfMeasure(measure) {
    if (acceptedDigests === null) {
      acceptedDigests = new Map();
      for (const build of acceptedBuilds()) acceptedDigests.set(measureOf(build), build);
    }
    return acceptedDigests.get(measure);
  }

  /** The format of the log of the nodes of a release, by its name: 3 from LOG_FORMAT_3_FROM on,
   *  2 before it (the releases that wrote format 1 or format 2 into the bucket of their binding).
   *  A name of another form than v{major}.{minor}.{patch} is a build made before the first release
   *  when it begins with "pre-", and a release of the present format otherwise. */
  function logFormatOf(release) {
    const name = String(release);
    const match = /^v(\d+)\.(\d+)\.(\d+)/.exec(name);
    if (match === null) return name.slice(0, 4) === "pre-" ? 2 : 3;
    for (let at = 0; at < 3; at += 1) {
      const part = Number(match[at + 1]);
      if (part !== LOG_FORMAT_3_FROM[at]) return part > LOG_FORMAT_3_FROM[at] ? 3 : 2;
    }
    return 3;
  }

  /** The verification of an AWS Nitro attestation document (COSE_Sign1). document is bytes; nonce
   *  is the bytes the document must carry, or null when the caller compares the nonce itself (a
   *  node document: the nonce follows from the signing key the binding names). On success it
   *  returns the binding bytes (user_data), the nonce of the document, the measurement and the
   *  time of the document (milliseconds), the build of the accepted lists the measurement equals
   *  (build, undefined when none) and whether the binding must name the log store (logStore); on a
   *  mismatch it throws attestation_failed. A document that verifies with a measurement no list
   *  has is not a mismatch: it is the document of a release later than this program (the list is a
   *  constant of the program, and a new release of the enclave reaches the app as a new program),
   *  returned without a build. The caller hands such a node no key. When gate is false the
   *  measurement decides nothing (the target of a revoke: the signature of the document, the nonce
   *  and the binding are checked as before, and a zero PCR is not refused). */
  function verifyNitro(document, nonce, gate) {
    const cose = cborDecode(document);
    if (!Array.isArray(cose) || cose.length !== 4) throw attestationFailure("cose shape");
    const protectedHeader = cose[0];
    const payload = cose[2];
    const signature = cose[3];
    if (!(protectedHeader instanceof Uint8Array) || !(cose[1] instanceof Map) ||
        !(payload instanceof Uint8Array) || !(signature instanceof Uint8Array)) {
      throw attestationFailure("cose element types");
    }
    // The protected header is {1: -35} (the algorithm ES384) and the signature is r and s
    // concatenated, 96 bytes.
    const header = cborDecode(protectedHeader);
    if (!(header instanceof Map) || header.size !== 1 || header.get(1) !== -35) {
      throw attestationFailure("cose algorithm");
    }
    if (signature.length !== 96) throw attestationFailure("cose signature length");

    const fields = cborDecode(payload);
    if (!(fields instanceof Map)) throw attestationFailure("document shape");
    const timestamp = fields.get("timestamp");
    const pcrs = fields.get("pcrs");
    const certificate = fields.get("certificate");
    const bundle = fields.get("cabundle");
    const userData = fields.get("user_data");
    const documentNonce = fields.get("nonce");
    if (typeof fields.get("module_id") !== "string" || fields.get("digest") !== "SHA384" ||
        !Number.isSafeInteger(timestamp) || timestamp < 0 || !(pcrs instanceof Map) ||
        !(certificate instanceof Uint8Array) || !Array.isArray(bundle) || bundle.length < 1 ||
        !(userData instanceof Uint8Array) || !(documentNonce instanceof Uint8Array)) {
      throw attestationFailure("document fields");
    }
    for (const authority of bundle) {
      if (!(authority instanceof Uint8Array)) throw attestationFailure("cabundle element");
    }
    pcrs.forEach(function (value, index) {
      const indexed = Number.isSafeInteger(index) && index >= 0;
      if (!indexed || !(value instanceof Uint8Array) || value.length !== 48) {
        throw attestationFailure("pcr shape");
      }
    });

    // The certificate chain: the leaf is certificate, the intermediates are the elements of
    // cabundle from the second on, and the anchor is the one pinned root. The verification time
    // is the timestamp of the document (milliseconds) in seconds.
    const leaf = encode(certificate);
    const trust = native.x509Verify({
      leaf: leaf, intermediates: bundle.slice(1).map(encode), anchors: [NITRO_ROOT],
      atEpochS: Math.floor(timestamp / 1000),
    });
    if (!trust.ok) throw attestationFailure("certificate chain");
    const key = native.x509PublicKey(leaf);
    if (key.algorithm !== "ec" || key.bits !== 384) throw attestationFailure("certificate key");
    const signed = native.ecdsaVerify({
      curve: "p384", hash: "sha384", format: "raw", publicKey: key.publicKey,
      message: encode(cborEncodeSigStructure(protectedHeader, payload)), signature: encode(signature),
    });
    if (!signed) throw attestationFailure("cose signature");

    if (nonce !== null && !equal(documentNonce, nonce)) throw attestationFailure("nonce");

    // The measurement: PCR0, PCR1 and PCR2 must all equal one element of the accepted list for the
    // node to receive a grant. A PCR whose value is all zero is the value of a debug-mode enclave
    // and is accepted by no list: it is refused here, so a document returned without a build is
    // the document of an enclave of a build this program does not list (a later release).
    const measurement = { pcr0: "", pcr1: "", pcr2: "" };
    for (const index of [0, 1, 2]) {
      const value = pcrs.get(index);
      if (value === undefined || (gate && /^0+$/.test(hex(value)))) throw attestationFailure("measurement");
      measurement["pcr" + index] = hex(value);
    }
    const build = listedBuild(measurement);
    return {
      binding: userData, nonce: documentNonce, measurement: measurement, timeMs: timestamp, build: build,
      // The binding of a node of a listed release that writes to the log store, and of a release
      // later than this program (every release from v1.1.0 on writes to it), must name the store.
      logStore: gate && (build === undefined || build.log_store === true),
    };
  }

  /** The verification of a document of platform local: UTF-8 JSON {v, platform, binding, nonce,
   *  time_ms} without a signature (a node that no attestation verifies). Only a build that takes
   *  local nodes accepts it (localAccepted; when gate is false this condition is not checked: the
   *  target of a revoke). The verification is the nonce match only (nonce null: the caller
   *  compares it). On success it returns the binding bytes, the nonce and the time of the document
   *  (milliseconds). */
  function verifyLocal(document, nonce, gate) {
    if (gate && !localAccepted()) throw attestationFailure("local platform is not accepted by this build");
    const fields = JSON.parse(text(document));
    if (fields === null || typeof fields !== "object" || fields.v !== 1 || fields.platform !== "local" ||
        !Number.isSafeInteger(fields.time_ms) || fields.time_ms < 0) {
      throw attestationFailure("local document shape");
    }
    const documentNonce = decode(fields.nonce);
    if (nonce !== null && !equal(documentNonce, nonce)) throw attestationFailure("nonce");
    return { binding: decode(fields.binding), nonce: documentNonce, timeMs: fields.time_ms };
  }

  /** Reads a binding (docs/protocol.md 4.1): UTF-8 JSON {v, sign, seal, release, log}, at most 512
   *  bytes. A binding without the key role is the binding of a node that takes the calls that use
   *  a credential, and a binding whose role is reserve the binding of a node that holds
   *  delegations and hands them on but takes no such call: both receive a grant. A binding with
   *  any other role (forward: a node that holds no delegation, receives no command and writes no
   *  entry; a role this program does not know) is refused. When logStore is true the binding must
   *  name the log store of this server target. Returns {signPk, sealPk, release}. */
  function readBinding(bindingBytes, logStore) {
    if (bindingBytes.length > 512) throw attestationFailure("binding size");
    const binding = JSON.parse(text(bindingBytes));
    if (binding === null || typeof binding !== "object" || binding.v !== 1 ||
        typeof binding.release !== "string" || binding.release === "") {
      throw attestationFailure("binding shape");
    }
    if (binding.role !== undefined && binding.role !== "reserve") throw attestationFailure("binding role");
    const signPk = decode(binding.sign);
    const sealPk = decode(binding.seal);
    if (signPk.length !== 32 || sealPk.length !== 32) throw attestationFailure("binding keys");
    // The log store: the binding names the bucket a node of that release writes to. A node that
    // writes somewhere other than the store of this server target, and a node that names no
    // store, is not accepted.
    if (logStore) {
      const expected = LOG_STORES[native.deviceInfo().server_target];
      const log = binding.log;
      if (expected === undefined || log === null || typeof log !== "object" ||
          log.bucket !== expected.bucket || log.region !== expected.region) {
        throw attestationFailure("log store");
      }
    }
    return { signPk: signPk, sealPk: sealPk, release: binding.release };
  }

  /** Verifies one attestation response of a node. nonce is the value sent with the request
   *  (base64url). The signing public key, the sealing public key and the release of the node are
   *  read from the binding the document binds only (the node and release fields of the response
   *  are not read). custody is the kind of user key that node receives: enclave for platform
   *  nitro, operator for local. timeMs is the time of that node as the document carries it. The
   *  challenge of the response is a value outside the document, so the signed statement that this
   *  node issued that challenge in answer to the nonce of this request (challenge_statement) is
   *  checked with the signing public key the document binds. When gate is false the acceptance
   *  conditions (the accepted measurements, debug mode, a build that accepts local) are not
   *  checked: used only for the target of a revoke, which hands no user key over. Returns {node,
   *  signPk, sealPk, release, platform, custody, timeMs, measure, listed, format}. listed is false
   *  for a nitro document that verified with a measurement no list has (a release later than this
   *  program, verifyNitro): such a node receives no grant. measure is the digest of the
   *  measurement (the empty string for platform local) and format the format of the log of the
   *  node. */
  function verifyAttestation(response, nonce, gate) {
    try {
      if (response === null || typeof response !== "object" || response.v !== 1) {
        throw attestationFailure("response shape");
      }
      const document = decode(response.document);
      const sent = decode(nonce);
      let verified = null;
      let measure = "";
      let listed = true;
      let build = undefined;
      if (response.platform === "nitro") {
        verified = verifyNitro(document, sent, gate !== false);
        measure = measureOf(verified.measurement);
        build = verified.build;
        listed = build !== undefined;
      } else if (response.platform === "local") {
        verified = verifyLocal(document, sent, gate !== false);
      } else {
        throw attestationFailure("unknown platform");
      }
      const binding = readBinding(verified.binding, verified.logStore === true);
      // The challenge statement: the signed value that this node issued the challenge of the
      // response in answer to the nonce of this request. The challenge is plaintext outside the
      // document, so without the statement the relay could hand the challenge of an earlier request
      // and replay the signed reply of an old command that carried that challenge. A response
      // without the statement, or with a statement that does not match, is not accepted.
      let statement = null;
      try {
        statement = openSigned(response.challenge_statement, encode(binding.signPk), purpose("challenge") + "\n");
      } catch (error) {
        throw attestationFailure("challenge statement");
      }
      if (statement.type !== "challenge" || statement.node !== encode(binding.signPk) ||
          statement.nonce !== encode(sent) || typeof response.challenge !== "string" ||
          statement.challenge !== response.challenge) {
        throw attestationFailure("challenge statement");
      }
      return {
        node: encode(binding.signPk), signPk: encode(binding.signPk), sealPk: encode(binding.sealPk),
        release: binding.release, platform: response.platform,
        custody: response.platform === "nitro" ? "enclave" : "operator", timeMs: verified.timeMs,
        measure: measure, listed: listed,
        format: response.platform === "nitro" ? (build === undefined ? 3 : logFormatOf(build.release))
          : logFormatOf(binding.release),
      };
    } catch (error) {
      if (error && error.code === "attestation_failed") throw error;
      throw attestationFailure(String((error && error.message) || error));
    }
  }

  /** The nonce of the document inside a node document (docs/protocol.md 7.7): the SHA-256 of the
   *  purpose string and the 32 bytes of the signing public key of the node. No requester chose it:
   *  a document with this nonce was made by the node for its node document. */
  function nodeDocumentNonce(signPk) {
    return decode(native.sha256(encode(concat(utf8(purposeV3("node-document") + "\n"), signPk))));
  }

  /** Verifies the node document of the node id: the object {v, platform, document, node, release}
   *  a node of format 3 wrote to the log store, or the attestation document the backend kept of a
   *  node, in the same form. It proves that the signing key id was created inside an enclave of
   *  the measurement the document states: the document is verified like an attestation response
   *  without a requester (the certificate chain at the time of the document, the signature, the
   *  measurement, the binding and its log store), and the signing key of its binding is id. The
   *  nonce of an object a node wrote to the store is the one of nodeDocumentNonce. With registry
   *  true (a document the backend kept: it answered a request of the backend and carries the
   *  nonce of that request) the nonce is not compared: what the document proves does not depend
   *  on its nonce. Returns {platform, release, measure, listed, format} and throws
   *  attestation_failed for a document that does not verify. */
  function verifyNodeDocument(object, id, registry) {
    try {
      if (object === null || typeof object !== "object" || object.v !== 1) {
        throw attestationFailure("node document shape");
      }
      const document = decode(object.document);
      let verified = null;
      let measure = "";
      let build = undefined;
      if (object.platform === "nitro") {
        verified = verifyNitro(document, null, true);
        measure = measureOf(verified.measurement);
        build = verified.build;
      } else if (object.platform === "local") {
        verified = verifyLocal(document, null, true);
      } else {
        throw attestationFailure("unknown platform");
      }
      const binding = readBinding(verified.binding, verified.logStore === true);
      if (object.node !== id || encode(binding.signPk) !== id) throw attestationFailure("another node");
      if (object.release !== binding.release) throw attestationFailure("another release");
      const format = object.platform === "nitro" ? (build === undefined ? 3 : logFormatOf(build.release))
        : logFormatOf(binding.release);
      if (registry !== true && !equal(verified.nonce, nodeDocumentNonce(binding.signPk))) {
        throw attestationFailure("node document nonce");
      }
      return {
        platform: object.platform, release: binding.release, measure: measure,
        listed: object.platform !== "nitro" || build !== undefined, format: format,
      };
    } catch (error) {
      if (error && error.code === "attestation_failed") throw error;
      throw attestationFailure(String((error && error.message) || error));
    }
  }

  // ---- Keys ----

  /** The purpose strings of the protocol: used as HKDF info, HPKE info and signature purposes
   *  (with a newline appended). */
  function purpose(name) {
    return "pickle.secure.v1." + name;
  }

  function info(name) {
    return encode(utf8(purpose(name)));
  }

  /** The purpose strings of format 2 and of format 3 of the log. */
  function purposeV2(name) {
    return "pickle.secure.v2." + name;
  }

  function purposeV3(name) {
    return "pickle.secure.v3." + name;
  }

  // The user_id of the account of this runtime (null: not read yet). An executor binds a runtime
  // to one account and makes a new runtime for another, so the bridge is asked for it once: the
  // prefix of every key of a listing and the fields of every entry are compared with it.
  let accountId = null;

  function userId() {
    if (accountId !== null) return accountId;
    const id = native.deviceInfo().user_id;
    if (typeof id === "string" && id !== "") accountId = id;
    return id;
  }

  /** The keychain item of the master key: one per account, synchronized through the iCloud
   *  Keychain. */
  function masterKeyItem() {
    return { service: MASTER_KEY_SERVICE, account: userId(), synchronizable: true };
  }

  function readMasterKey() {
    return native.keychainGet(masterKeyItem());
  }

  /** Every key derived from the master key (nothing is stored: the same master key gives the same
   *  values): the account signing seed and public key, the log decryption private key and public
   *  key, the user key of each custody, the key that seals the shared ledger (ledgerKey) and the
   *  key that seals the kept log screen (cacheKey), neither of which leaves the device in any form,
   *  and the key_id. userKeys.enclave is handed only to nitro nodes whose attestation was verified,
   *  and userKeys.operator to local nodes: the user key of the enclave custody never goes to an
   *  unverified party. */
  function deriveKeys(masterKey) {
    const signSeed = native.hkdf("sha256", masterKey, null, info("sign"), 32);
    const logSk = native.hkdf("sha256", masterKey, null, info("log"), 32);
    const signPk = native.ed25519PublicKey(signSeed);
    return {
      signSeed: signSeed,
      signPk: signPk,
      logSk: logSk,
      logPk: native.x25519PublicKey(logSk),
      userKeys: {
        enclave: native.hkdf("sha256", masterKey, null, info("user-key"), 32),
        operator: native.hkdf("sha256", masterKey, null, info("user-key.operator"), 32),
      },
      ledgerKey: native.hkdf("sha256", masterKey, null, info("ledger"), 32),
      cacheKey: native.hkdf("sha256", masterKey, null, info("log-cache"), 32),
      keyId: hex(decode(native.sha256(signPk)).subarray(0, 8)),
    };
  }

  function writeMasterKey(bytes) {
    if (accountClosed) return;
    const item = masterKeyItem();
    native.keychainSet({
      service: item.service, account: item.account, value: bytes,
      synchronizable: true, accessible: "after_first_unlock",
    });
    // A key this device did not have before (new, replaced, transferred) may be the key the pending
    // values of the account are to be sealed under: the sealing check runs once more.
    native.storeSet(SEALING_CHECK_STORE_KEY, null);
  }

  function deleteMasterKey() {
    native.keychainDelete(masterKeyItem());
  }

  // ---- The program store ----

  /** The JSON value the program store keeps under key; fallback when there is none or it does not
   *  parse. */
  function storedJson(key, fallback) {
    const kept = native.storeGet(key);
    if (kept === null) return fallback;
    try {
      const value = JSON.parse(kept);
      return value === null || value === undefined ? fallback : value;
    } catch (error) {
      return fallback;
    }
  }

  function storeJson(key, value) {
    native.storeSet(key, value === null || value === undefined ? null : JSON.stringify(value));
  }

  /** A stored value when it is a plain object (not an array), otherwise a new empty object. */
  function storedObject(key) {
    const value = storedJson(key, null);
    return value !== null && typeof value === "object" && !Array.isArray(value) ? value : {};
  }

  /** The value when it is a non-negative integer, otherwise 0. */
  function whole(value) {
    return Number.isSafeInteger(value) && value >= 0 ? value : 0;
  }

  // ---- Turns: the bounded time of one piece of work ----

  function noop() {}

  function failureCode(error) {
    return error && error.code ? String(error.code) : "program_error";
  }

  // The time this runtime spent in operations that wait for the user (webAuth, deviceOwnerAuth,
  // promptSecret, presentSecret). That time is taken out of the time of every turn, as the
  // executors take it out of the time of every procedure.
  let interactiveDepth = 0;
  let interactiveSince = 0;
  let interactiveClosedMs = 0;
  // The waits for the end of the operations that wait for the user (interactiveIdle).
  let interactiveWaiters = [];

  function interactiveMs() {
    const open = interactiveDepth > 0 ? Math.max(0, native.nowMs() - interactiveSince) : 0;
    return interactiveClosedMs + open;
  }

  /** A promise that resolves when no operation that waits for the user is in progress any more. */
  function interactiveIdle() {
    return new Promise(function (resolve) { interactiveWaiters.push(resolve); });
  }

  /** A turn: the time one piece of work may take from its call (limitMs, Infinity for work that
   *  is bound by the limits of its requests alone). name is the name the outcome of the work is
   *  counted under (the empty string: not counted). */
  function newTurn(limitMs, name) {
    return {
      name: typeof name === "string" ? name : "", calledMs: native.nowMs(), startedMs: 0, waitedMs: 0,
      limitMs: limitMs, interactiveAtCall: interactiveMs(), id: "",
    };
  }

  /** The counted time of a turn: the time since its call without the time the runtime spent in
   *  operations that wait for the user. */
  function turnSpent(turn) {
    return Math.max(0, native.nowMs() - turn.calledMs - (interactiveMs() - turn.interactiveAtCall));
  }

  function turnLeft(turn) {
    return turn.limitMs === Infinity ? Infinity : turn.limitMs - turnSpent(turn);
  }

  function timeoutError(what) {
    return native.error("timeout", what);
  }

  // The time the app last went to the background (the event background; 0: not in this
  // runtime). A runtime does not run while its app is suspended there, and the requests it had
  // sent fail when it runs again. A wait that was open when the app went to the background, or
  // that ends later than its own limit by more than WAIT_LATE_MS, may have failed for that
  // reason alone: its failure carries the mark frozen (limited), and a read of the log that
  // fails with that mark failed with the device, whatever the backend did (backendFailure).
  let appBackgroundMs = 0;

  /** Waits for ms milliseconds in sleeps of SLEEP_STEP_MS at most (the bridge cuts a longer
   *  sleep), and ends early once stop.done is set. The number of sleeps is bounded by the time. */
  async function pause(ms, stop) {
    const end = native.nowMs() + ms;
    const steps = Math.ceil(ms / SLEEP_STEP_MS) + 1;
    for (let step = 0; step < steps; step += 1) {
      const left = end - native.nowMs();
      if (left <= 0 || (stop !== undefined && stop.done)) return;
      await native.sleep(Math.min(left, SLEEP_STEP_MS));
    }
  }

  /** Resolves when the wait of a turn is over: limitMs have passed since the call (Infinity: the
   *  wait has no limit of its own), or the counted time of the turn is used up. The time the
   *  runtime spends in an operation that waits for the user is not counted into a turn
   *  (turnSpent), so while such an operation is in progress only limitMs ends the wait: a wait
   *  without a limit of its own waits for the end of that operation. Ends early once stop.done is
   *  set. The passes are bounded: a pass sleeps SLEEP_STEP_MS at most or waits for the end of the
   *  operations that wait for the user, and the wait is over after WAIT_INTERACTIVE_PASSES of the
   *  latter. */
  async function expire(turn, limitMs, stop) {
    const started = native.nowMs();
    const passes = Math.ceil(Math.min(limitMs, turn.limitMs) / SLEEP_STEP_MS) + 2 * WAIT_INTERACTIVE_PASSES + 2;
    for (let pass = 0; pass < passes; pass += 1) {
      if (stop.done) return;
      const own = limitMs - (native.nowMs() - started);
      if (!(own > 0)) return;
      if (interactiveDepth > 0) {
        if (own === Infinity) await interactiveIdle();
        else await native.sleep(Math.min(own, SLEEP_STEP_MS));
        continue;
      }
      const left = Math.min(own, turnLeft(turn));
      if (!(left > 0)) return;
      await native.sleep(Math.min(left, SLEEP_STEP_MS));
    }
  }

  /** The value of promise, or the failure timeout when limitMs or the rest of the turn passes
   *  first (what names the wait). The rest of the turn is its counted time: the time the runtime
   *  spends in an operation that waits for the user ends no wait of a turn (expire). The promise
   *  goes on by itself after a timeout and its outcome is dropped. A wait without a limit in a
   *  turn without a limit is the promise itself. */
  function limited(turn, promise, limitMs, what) {
    const left = Math.min(limitMs, turnLeft(turn));
    if (left === Infinity) return promise;
    if (!(left > 0)) {
      promise.then(noop, noop);
      return Promise.reject(timeoutError(what));
    }
    const stop = { done: false };
    const began = native.nowMs();
    // The failure of the wait, marked frozen when the runtime may not have run for a part of
    // the wait (appBackgroundMs).
    const marked = function (error) {
      try {
        const late = limitMs !== Infinity && native.nowMs() - began - limitMs > WAIT_LATE_MS;
        if ((late || appBackgroundMs >= began) && error !== null && typeof error === "object") error.frozen = true;
      } catch (failure) {
        // The bridge is closed, or the failure takes no mark.
      }
      return error;
    };
    const guarded = promise.then(
      function (value) { stop.done = true; return value; },
      function (error) { stop.done = true; throw marked(error); });
    const timer = expire(turn, limitMs, stop).then(function () { throw marked(timeoutError(what)); });
    guarded.then(noop, noop);
    timer.then(noop, noop);
    return Promise.race([guarded, timer]);
  }

  /** An operation that waits for the user: start() returns its promise. The time it takes is not
   *  counted into any turn. A turn whose time has passed starts no such operation. */
  async function interactive(turn, start) {
    if (!(turnLeft(turn) > 0)) throw timeoutError("interactive");
    if (interactiveDepth === 0) interactiveSince = native.nowMs();
    interactiveDepth += 1;
    try {
      return await start();
    } finally {
      interactiveDepth -= 1;
      if (interactiveDepth === 0) {
        try {
          interactiveClosedMs += Math.max(0, native.nowMs() - interactiveSince);
        } catch (error) {
          // The bridge is closed: the runtime is going down and counts no time any more.
        }
        const waiters = interactiveWaiters;
        interactiveWaiters = [];
        for (const resolve of waiters) resolve();
      }
    }
  }

  /** A line: pieces of work that run one at a time, in the order of their calls. run(turn, work)
   *  starts work when the work before it ended and returns its outcome. The wait for the line and
   *  the work itself are bound by the turn: when its time passes, the call fails with timeout and
   *  the line goes on to the next piece of work (the work that was running ends at its next
   *  request, which the same turn bounds). With fresh true the time of the turn begins when the
   *  work begins (work an event starts: nobody waits on a limit that began at the event). busy()
   *  says whether work is running or waiting. */
  function newLine() {
    let tail = Promise.resolve();
    let pending = 0;
    return {
      busy: function () { return pending > 0; },
      run: function (turn, work, fresh) {
        const before = tail;
        let release = noop;
        tail = new Promise(function (resolve) { release = resolve; });
        pending += 1;
        const done = function () {
          pending -= 1;
          release();
        };
        const waiting = fresh === true ? before : limited(turn, before, Infinity, "line");
        return waiting.then(
          function () {
            let running = null;
            try {
              const now = native.nowMs();
              if (fresh === true) {
                turn.calledMs = now;
                turn.interactiveAtCall = interactiveMs();
              }
              // The first line a turn enters is the line it waited for (a lock it takes later is
              // part of its work).
              if (turn.startedMs === 0) {
                turn.startedMs = now;
                turn.waitedMs = turnSpent(turn);
              }
              running = limited(turn, Promise.resolve(work()), Infinity, "procedure");
            } catch (error) {
              running = Promise.reject(error);
            }
            return running.then(
              function (value) { done(); return value; },
              function (error) { done(); throw error; });
          },
          function (error) {
            // The turn ended while it waited: its place is given up when the work before it ends.
            before.then(done, done);
            throw error;
          });
      },
    };
  }

  // The three lines (the procedures a user starts, the synchronizations, the reads of the log
  // screen) and the two locks (the judgement of the key with the grants that follow it, one round
  // of the log). A lock is a line: whoever holds it runs alone, and everything it waits for while
  // it holds the lock is a request with a time limit.
  const userLine = newLine();
  const syncLine = newLine();
  const screenLine = newLine();
  const grantLock = newLine();
  const roundLock = newLine();

  /** A turn for work nothing waits on with a limit of its own (a report, the polling of a key
   *  transfer): each of its requests has its time limit. */
  function freeTurn() {
    return newTurn(Infinity, "");
  }

  // ---- The api ----

  // The time the backend last answered a request of this runtime, with any status (0: never). A
  // round uses it to tell a request the operator domain held back from a device without a network.
  let lastAnswerMs = 0;

  /** One request to a route of the backend (the account credential is carried). The values of
   *  query are strings. Returns {status, json, code}: json is the JSON object of the response body
   *  (null when the body is not one) and code the first string among code, detail and error of a
   *  body outside 2xx (null when there is none). The request is given up after limitMs
   *  (API_TIMEOUT_MS when none is given) or when the time of the turn passes: the failure timeout.
   *  A failure of the transport is the failure transport. */
  async function request(turn, method, path, body, query, limitMs) {
    const sent = { method: method, path: path };
    if (query) sent.query = query;
    if (body !== undefined && body !== null) sent.body = JSON.stringify(body);
    let pending = null;
    try {
      pending = native.http(sent);
    } catch (error) {
      pending = Promise.reject(error);
    }
    const limit = Number.isSafeInteger(limitMs) && limitMs > 0 ? limitMs : API_TIMEOUT_MS;
    const response = await limited(turn, pending, limit, method + " " + path);
    lastAnswerMs = native.nowMs();
    let json = null;
    try {
      json = JSON.parse(response.body);
    } catch (error) {
      json = null;
    }
    if (json === null || typeof json !== "object" || Array.isArray(json)) json = null;
    let code = null;
    if (json !== null && (response.status < 200 || response.status > 299)) {
      const found = [json.code, json.detail, json.error].find(function (value) {
        return typeof value === "string" && value !== "";
      });
      code = found === undefined ? null : found;
    }
    return { status: response.status, json: json, code: code };
  }

  /** A call of an api route. Returns {status, json} where json is the JSON object of the response
   *  body. A response outside 2xx throws the first string among code, detail and error of the body
   *  (or "http_" + status when there is none) as the failure code, with the status as the status
   *  of the failure, and a 2xx response whose body is not a JSON object is invalid_response. */
  async function api(turn, method, path, body, query, limitMs) {
    const answer = await request(turn, method, path, body, query, limitMs);
    if (answer.status < 200 || answer.status > 299) {
      const refused = native.error(answer.code === null ? "http_" + answer.status : answer.code, method + " " + path);
      refused.status = answer.status;
      throw refused;
    }
    if (answer.json === null) {
      const invalid = native.error("invalid_response", method + " " + path);
      invalid.status = answer.status;
      throw invalid;
    }
    return { status: answer.status, json: answer.json };
  }

  /** The status of a failure of api (0 for a failure that is not an answer of the backend). */
  function failureStatus(error) {
    return error && Number.isSafeInteger(error.status) ? error.status : 0;
  }

  /** Whether a failure of api says that the backend has no such route or has turned its store
   *  off: the status 404 without a code of the route's own, or the code log_store_disabled. */
  function routeAbsent(error) {
    const code = failureCode(error);
    if (code === "log_store_disabled") return true;
    return failureStatus(error) === 404 && (code === "http_404" || code === "Not Found" || code === "not_found");
  }

  /** The outcome of a promise as a value: {ok: true, value} or {ok: false, error}. The requests of one
   *  stage are awaited through this so that the failure of one does not drop the responses of the
   *  others; what a failure means is decided where the response is used. */
  function settled(promise) {
    return promise.then(
      function (value) { return { ok: true, value: value }; },
      function (error) { return { ok: false, error: error }; });
  }

  /** One stage: the requests of promises are already sent (native.http is called when the promise is
   *  made); the stage ends when every one of them settled. Returns their settled outcomes in order. */
  function stage(promises) {
    return Promise.all(promises.map(settled));
  }

  /** A gate of limit calls in flight at once: run(work) starts work when a place is free (the
   *  next starts when one ended) and returns its promise. A place is handed to the next waiting
   *  call directly, so never more than limit are in flight. */
  function gate(limit) {
    let active = 0;
    const waiting = [];
    return {
      run: async function (work) {
        if (active >= limit) await new Promise(function (resolve) { waiting.push(resolve); });
        else active += 1;
        try {
          return await work();
        } finally {
          const next = waiting.shift();
          if (next !== undefined) next();
          else active -= 1;
        }
      },
    };
  }

  // The gate of the reads of the bucket of format 1 and format 2 (LOG_STORE_CONCURRENCY in flight
  // at once).
  const storeGate = gate(LOG_STORE_CONCURRENCY);

  /** The settled outcomes of work over items, in order, each call through the store gate. */
  function pooled(items, work) {
    return Promise.all(items.map(function (item) {
      return settled(storeGate.run(function () { return work(item); }));
    }));
  }

  // ---- Signed values ----

  /** Opens a signed value {body, sig}: the signed input is the purpose string (context, ending in
   *  a newline) followed by the received body bytes as they are. The body is parsed as JSON only
   *  after the signature verified. A signature mismatch and a malformed value are bad_signature, a
   *  body whose v is not version (1 when not given) is unsupported_version. */
  function openSigned(signed, publicKey, context, version) {
    let parsed = null;
    try {
      const body = decode(signed.body);
      const valid = native.ed25519Verify(publicKey, encode(concat(utf8(context), body)), signed.sig);
      if (valid) parsed = JSON.parse(text(body));
    } catch (error) {
      parsed = null;
    }
    if (parsed === null || typeof parsed !== "object") throw native.error("bad_signature", context.trim());
    if (parsed.v !== (version === undefined ? 1 : version)) {
      throw native.error("unsupported_version", context.trim());
    }
    return parsed;
  }

  // ---- The node ledger ----

  const NODE_ID = /^[A-Za-z0-9_-]{43}$/;
  // The base64url of 32 zero bytes: the end of a chain without entries and the prev of the first
  // entry.
  const ZERO_HASH = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

  function ledgerItem() {
    return { service: LEDGER_SERVICE, account: userId(), synchronizable: true };
  }

  function emptyLedger() {
    return {
      v: 1, revoked_ms: 0, resumed_ms: 0, ttl_days: GRANT_DAYS_MAX, ttl_set_ms: 0,
      // The time the reads of the log store began to fail, 0 while they succeed (a run that
      // completes with the store read clears it).
      store_failing_ms: 0,
      // The discovery cursor: the id of the node the last verification run examined last among the
      // nodes of the node discovery listing the ledger did not know ("" before the first). The
      // window of the next run begins after it in the id order of the listing (verifyRun).
      discovery_after: "",
      nodes: Object.create(null),
    };
  }

  /** The days of the grant lifetime: the value when it is an integer from 1 to 30, otherwise 30. */
  function grantDays(value) {
    return Number.isSafeInteger(value) && value >= 1 && value <= GRANT_DAYS_MAX ? value : GRANT_DAYS_MAX;
  }

  /** One point of a chain {seq, hash, time_ms}: time_ms is the time of the entry at that point
   *  (0 when it is not known: the empty chain, and a point a program before this one wrote). null
   *  when the form is wrong. */
  function chainPoint(value) {
    if (value === null || typeof value !== "object") return null;
    if (!Number.isSafeInteger(value.seq) || value.seq < 0 || typeof value.hash !== "string") return null;
    return { seq: value.seq, hash: value.hash, time_ms: whole(value.time_ms) };
  }

  /** Reads one stored JSON text as a ledger. A missing value and a malformed value are the empty
   *  ledger, and a malformed node is left out. The key order of the nodes object is the
   *  serialization order. */
  function parseLedger(json) {
    const ledger = emptyLedger();
    let raw = null;
    try {
      raw = json === null ? null : JSON.parse(json);
    } catch (error) {
      raw = null;
    }
    if (raw === null || typeof raw !== "object" || raw.v !== 1) return ledger;
    ledger.revoked_ms = whole(raw.revoked_ms);
    ledger.resumed_ms = whole(raw.resumed_ms);
    ledger.ttl_days = grantDays(raw.ttl_days);
    ledger.ttl_set_ms = whole(raw.ttl_set_ms);
    ledger.store_failing_ms = whole(raw.store_failing_ms);
    // A program before v42 leaves the cursor out of its own ledger and drops it from one it reads.
    ledger.discovery_after = typeof raw.discovery_after === "string" && NODE_ID.test(raw.discovery_after)
      ? raw.discovery_after : "";
    const nodes = raw.nodes !== null && typeof raw.nodes === "object" ? raw.nodes : {};
    for (const id of Object.keys(nodes)) {
      const node = nodes[id];
      if (!NODE_ID.test(id) || node === null || typeof node !== "object" ||
          typeof node.sign_pk !== "string" || typeof node.seal_pk !== "string") {
        continue;
      }
      ledger.nodes[id] = {
        sign_pk: node.sign_pk, seal_pk: node.seal_pk,
        platform: String(node.platform), release: String(node.release),
        first_ms: whole(node.first_ms), granted_ms: whole(node.granted_ms),
        not_after_ms: whole(node.not_after_ms),
        checkpoint: chainPoint(node.checkpoint) || { seq: 0, hash: ZERO_HASH, time_ms: 0 },
        final: chainPoint(node.final), gone_ms: whole(node.gone_ms),
        // How the node entered the ledger: grant (a grant of this app or the tracing of a
        // delegation transfer) or store (found in the log store only: no grant of this app and no
        // traced transfer explains it).
        origin: node.origin === "store" ? "store" : "grant",
        // For a node of origin store: the time the node was marked a delegation the app did not
        // make (an entry sealed to the key of this account verified on it that no traced transfer
        // explained), 0 otherwise.
        unknown_ms: node.origin === "store" ? whole(node.unknown_ms) : 0,
        // For a node of origin store: the time an entry sealed to the key of this account was first
        // verified on its chain, 0 while none was. The fact stays with the node across runs: a run
        // cut short by its budget leaves the node at its verification point, and the run that marks
        // it may read nothing new (verifyRun). A program before v42 leaves the field out of its own
        // ledger and drops it from one it reads.
        sealed_ms: node.origin === "store" ? whole(node.sealed_ms) : 0,
        // The time this app last sent a grant to the node (written before the grant goes out:
        // renewGrants), 0 for a node that entered the ledger another way. A program before v34
        // leaves the field out of its own ledger and drops it from one it reads.
        attempted_ms: whole(node.attempted_ms),
      };
    }
    return ledger;
  }

  /** The merge of two ledgers. The nodes are the union; a node present in both takes the
   *  granted_ms and not_after_ms of the side with the larger granted_ms, the checkpoint of the side
   *  with the larger checkpoint.seq, the final that is not null, the smaller non-zero gone_ms, the
   *  smaller first_ms, the non-empty sealing public key (with the platform and release of that
   *  side), the origin grant when either side has it, and the smaller non-zero unknown_ms and
   *  sealed_ms (0 when the origin is grant). revoked_ms and resumed_ms are each the larger value,
   *  ttl_days is the value of the side with the larger ttl_set_ms (the one set later),
   *  store_failing_ms is the smaller non-zero value, and discovery_after is the larger id (the
   *  window of either side moved past the nodes before it). */
  function mergeLedger(a, b) {
    const merged = emptyLedger();
    merged.revoked_ms = Math.max(a.revoked_ms, b.revoked_ms);
    merged.resumed_ms = Math.max(a.resumed_ms, b.resumed_ms);
    const later = b.ttl_set_ms > a.ttl_set_ms ? b : a;
    merged.ttl_days = later.ttl_days;
    merged.ttl_set_ms = later.ttl_set_ms;
    merged.store_failing_ms = a.store_failing_ms === 0 || b.store_failing_ms === 0
      ? Math.max(a.store_failing_ms, b.store_failing_ms)
      : Math.min(a.store_failing_ms, b.store_failing_ms);
    merged.discovery_after = a.discovery_after > b.discovery_after ? a.discovery_after : b.discovery_after;
    for (const side of [a, b]) {
      for (const id of Object.keys(side.nodes)) {
        const node = side.nodes[id];
        const kept = merged.nodes[id];
        if (kept === undefined) {
          merged.nodes[id] = {
            sign_pk: node.sign_pk, seal_pk: node.seal_pk, platform: node.platform,
            release: node.release, first_ms: node.first_ms, granted_ms: node.granted_ms,
            not_after_ms: node.not_after_ms,
            checkpoint: {
              seq: node.checkpoint.seq, hash: node.checkpoint.hash, time_ms: node.checkpoint.time_ms,
            },
            final: node.final === null ? null : { seq: node.final.seq, hash: node.final.hash },
            gone_ms: node.gone_ms, origin: node.origin, unknown_ms: node.unknown_ms,
            sealed_ms: node.sealed_ms, attempted_ms: node.attempted_ms,
          };
          continue;
        }
        kept.first_ms = Math.min(kept.first_ms, node.first_ms);
        kept.attempted_ms = Math.max(kept.attempted_ms, node.attempted_ms);
        if (kept.origin === "store" && node.origin !== "store") kept.origin = "grant";
        if (node.unknown_ms !== 0 && (kept.unknown_ms === 0 || node.unknown_ms < kept.unknown_ms)) {
          kept.unknown_ms = node.unknown_ms;
        }
        if (node.sealed_ms !== 0 && (kept.sealed_ms === 0 || node.sealed_ms < kept.sealed_ms)) {
          kept.sealed_ms = node.sealed_ms;
        }
        if (kept.origin !== "store") {
          kept.unknown_ms = 0;
          kept.sealed_ms = 0;
        }
        // A node that entered through the tracing of a delegation transfer has an empty sealing
        // public key: the value of the side that verified the attestation is used.
        if (kept.seal_pk === "" && node.seal_pk !== "") {
          kept.seal_pk = node.seal_pk;
          kept.platform = node.platform;
          kept.release = node.release;
        }
        if (node.granted_ms > kept.granted_ms) {
          kept.granted_ms = node.granted_ms;
          kept.not_after_ms = node.not_after_ms;
        }
        if (node.checkpoint.seq > kept.checkpoint.seq) {
          kept.checkpoint = {
            seq: node.checkpoint.seq, hash: node.checkpoint.hash, time_ms: node.checkpoint.time_ms,
          };
        }
        if (kept.final === null && node.final !== null) {
          kept.final = { seq: node.final.seq, hash: node.final.hash };
        }
        if (node.gone_ms !== 0 && (kept.gone_ms === 0 || node.gone_ms < kept.gone_ms)) {
          kept.gone_ms = node.gone_ms;
        }
      }
    }
    return merged;
  }

  /** Reads the node ledger: the merge of the keychain item and the device copy (when the
   *  synchronization between devices overwrites one side's write, the other side remains). */
  function loadLedger() {
    const kept = native.keychainGet(ledgerItem());
    const keychainLedger = parseLedger(kept === null ? null : text(decode(kept)));
    return mergeLedger(keychainLedger, parseLedger(native.storeGet(LEDGER_STORE_KEY)));
  }

  /** Writes the node ledger to the keychain item and the device copy (a side whose stored value is
   *  the same is not written). When the serialization exceeds the limit, first the clean prefixes
   *  found in the store only (origin store, nothing sealed to this key, no mark: the discovery
   *  cursor examines them again when the listing still names them) are removed, oldest first_ms
   *  first, then the nodes whose verification reached the final head (final is set and
   *  checkpoint.seq equals final.seq), oldest gone_ms first, until it fits. */
  function saveLedger(ledger) {
    if (accountClosed) return;
    let json = JSON.stringify(ledger);
    if (utf8(json).length > LEDGER_LIMIT_BYTES) {
      const clean = Object.keys(ledger.nodes).filter(function (id) {
        const node = ledger.nodes[id];
        return node.origin === "store" && node.unknown_ms === 0 && node.sealed_ms === 0;
      });
      clean.sort(function (x, y) { return ledger.nodes[x].first_ms - ledger.nodes[y].first_ms; });
      const finished = Object.keys(ledger.nodes).filter(function (id) {
        const node = ledger.nodes[id];
        return node.origin !== "store" && node.final !== null && node.checkpoint.seq === node.final.seq;
      });
      finished.sort(function (x, y) { return ledger.nodes[x].gone_ms - ledger.nodes[y].gone_ms; });
      for (const id of clean.concat(finished)) {
        delete ledger.nodes[id];
        json = JSON.stringify(ledger);
        if (utf8(json).length <= LEDGER_LIMIT_BYTES) break;
      }
    }
    const item = ledgerItem();
    const value = encode(utf8(json));
    if (native.keychainGet(item) !== value) {
      native.keychainSet({
        service: item.service, account: item.account, value: value,
        synchronizable: true, accessible: "after_first_unlock",
      });
    }
    if (native.storeGet(LEDGER_STORE_KEY) !== json) native.storeSet(LEDGER_STORE_KEY, json);
  }

  // ---- The shared ledger (for the devices of the account that run a program before v43) ----

  /** The ids of the nodes a ledger explains as delegations of this account (origin grant), sorted. */
  function grantNodeIds(ledger) {
    return Object.keys(ledger.nodes).filter(function (id) {
      return ledger.nodes[id].origin === "grant";
    }).sort();
  }

  /** The additional authenticated data of the shared ledger: the purpose, the account and the
   *  key_id (a value sealed for another account or another key does not open). */
  function ledgerShareAad(keys) {
    return encode(utf8(purpose("ledger") + "\n" + userId() + "\n" + keys.keyId));
  }

  /** The shared value of a ledger: {key_id, nonce, ct}, the ledger JSON sealed with ledgerKey
   *  (ChaCha20-Poly1305, a fresh nonce). */
  function sealLedger(keys, ledger) {
    const nonce = native.randomBytes(LEDGER_SHARE_NONCE_BYTES);
    const ct = native.aeadSeal({
      alg: "chacha20poly1305", key: keys.ledgerKey, nonce: nonce, aad: ledgerShareAad(keys),
      plaintext: encode(utf8(JSON.stringify(ledger))),
    });
    return { key_id: keys.keyId, nonce: nonce, ct: ct };
  }

  /** The ledger of a shared value, or null when the value is absent, of another key, of another
   *  shape, or does not open (an opened value that is not a ledger is the empty ledger). */
  function openSharedLedger(keys, shared) {
    if (shared === null || typeof shared !== "object" || shared.key_id !== keys.keyId ||
        typeof shared.nonce !== "string" || typeof shared.ct !== "string") {
      return null;
    }
    try {
      return parseLedger(text(decode(native.aeadOpen({
        alg: "chacha20poly1305", key: keys.ledgerKey, nonce: shared.nonce, aad: ledgerShareAad(keys),
        ciphertext: shared.ct,
      }))));
    } catch (error) {
      native.log("shared ledger: " + failureCode(error));
      return null;
    }
  }

  /** Whether the shared ledger covers this one: every grant node of this ledger is a grant node
   *  of the shared one, and the revocation, resumption and lifetime settings are not newer here. */
  function ledgerCovered(ledger, shared) {
    const known = new Set(grantNodeIds(shared));
    return grantNodeIds(ledger).every(function (id) { return known.has(id); }) &&
      ledger.revoked_ms <= shared.revoked_ms && ledger.resumed_ms <= shared.resumed_ms &&
      ledger.ttl_set_ms <= shared.ttl_set_ms;
  }

  /** Whether the ledger of this device holds a grant node the last exchange did not cover. */
  function ledgerShareDue(ledger) {
    const ids = grantNodeIds(ledger);
    if (ids.length === 0) return false;
    const covered = native.storeGet(LEDGER_SHARE_STORE_KEY);
    return covered === null || JSON.stringify(ids) !== covered;
  }

  /** The exchange of the ledger with the backend, as the programs before v43 make it: the shared
   *  value is read and merged into the ledger of this device (the nodes and the settings of the
   *  other devices enter the ledger, which this program judges nothing by), and, when the shared
   *  value does not cover the merged ledger, the merged ledger is sealed and uploaded. The upload
   *  replaces the value of the backend, so the value is read first: an upload of this ledger alone
   *  would drop the nodes the other devices wrote. A failure of either request is logged and
   *  changes nothing else. */
  async function shareLedger(turn, keys) {
    const fetched = await settled(api(turn, "GET", LEDGER_SHARE_PATH));
    if (!fetched.ok) {
      native.log("shared ledger read: " + failureCode(fetched.error));
      return;
    }
    const ledger = loadLedger();
    const shared = openSharedLedger(keys, fetched.value.json.ledger);
    if (shared !== null) {
      const merged = mergeLedger(ledger, shared);
      // The gone time of a node this device granted to at least as recently as the shared value
      // did is the one this device knows.
      for (const id of Object.keys(merged.nodes)) {
        const mine = ledger.nodes[id];
        const theirs = shared.nodes[id];
        if (mine !== undefined && theirs !== undefined && mine.granted_ms >= theirs.granted_ms) {
          merged.nodes[id].gone_ms = mine.gone_ms;
        }
      }
      ledger.revoked_ms = merged.revoked_ms;
      ledger.resumed_ms = merged.resumed_ms;
      ledger.ttl_days = merged.ttl_days;
      ledger.ttl_set_ms = merged.ttl_set_ms;
      ledger.nodes = merged.nodes;
      saveLedger(ledger);
    }
    if (shared === null || !ledgerCovered(ledger, shared)) {
      try {
        await api(turn, "PUT", LEDGER_SHARE_PATH, sealLedger(keys, ledger));
      } catch (error) {
        native.log("shared ledger write: " + failureCode(error));
        return;
      }
    }
    native.storeSet(LEDGER_SHARE_STORE_KEY, JSON.stringify(grantNodeIds(ledger)));
  }

  // Whether an exchange of the ledger is in flight (one at a time).
  let ledgerShareFlight = false;

  /** Starts the exchange of the ledger when this device holds a grant node the last exchange did
   *  not cover, or when force is set (a setting of the delegation changed). Nothing waits for it. */
  function shareLedgerSoon(keys, force) {
    if (ledgerShareFlight || accountClosed || (force !== true && !ledgerShareDue(loadLedger()))) return;
    ledgerShareFlight = true;
    shareLedger(freeTurn(), keys).then(noop, function (error) {
      try {
        native.log("shared ledger: " + failureCode(error));
      } catch (closed) {
        // The bridge is closed.
      }
    }).then(function () { ledgerShareFlight = false; });
  }

  /** Writes a node of a release before LOG_FORMAT_3_FROM that this device handed a grant to into
   *  the ledger, in the form of the programs before v43: origin grant, the grant time, the expiry,
   *  and, for a node the ledger did not hold, a verification point at seq 0. A node the ledger
   *  holds keeps its verification point. */
  function noteLedgerGrant(ledger, node, grantedMs, notAfterMs, sentMs) {
    let record = ledger.nodes[node.node];
    if (record === undefined) {
      record = {
        sign_pk: node.signPk, seal_pk: node.sealPk, platform: node.platform, release: node.release,
        first_ms: sentMs, granted_ms: 0, not_after_ms: 0,
        checkpoint: { seq: 0, hash: ZERO_HASH, time_ms: 0 }, final: null, gone_ms: 0, origin: "grant",
        unknown_ms: 0, sealed_ms: 0, attempted_ms: sentMs,
      };
      ledger.nodes[node.node] = record;
    }
    if (record.seal_pk === "") {
      record.seal_pk = node.sealPk;
      record.platform = node.platform;
      record.release = node.release;
    }
    record.granted_ms = grantedMs;
    record.not_after_ms = notAfterMs;
    record.attempted_ms = sentMs;
    record.origin = "grant";
    record.unknown_ms = 0;
    record.sealed_ms = 0;
    record.gone_ms = 0;
  }

  // ---- The grants of this device ----

  /** The lifetime of a grant as the ledger sets it (milliseconds). */
  function grantTtlMs(ledger) {
    return ledger.ttl_days * DAY_MS;
  }

  /** The interval at which a grant is handed again: the smaller of 24 hours and half of the
   *  lifetime (12 hours for a lifetime of one day). */
  function grantRenewMs(ledger) {
    return Math.min(GRANT_RENEW_MS, grantTtlMs(ledger) / 2);
  }

  /** Whether the user turned delegation off. */
  function delegationOff(ledger) {
    return ledger.revoked_ms > ledger.resumed_ms;
  }

  /** Whether the entries of a node are in the log store: every node but one of a build that writes
   *  no entry to the store (a prerelease build without log_store). */
  function writesToStore(platform, release) {
    if (platform === "local") return true;
    const build = ACCEPTED_RELEASES.concat(PRERELEASE_BUILDS).find(function (item) {
      return item.release === release;
    });
    return build === undefined || build.log_store === true;
  }

  /** One record of the grants of this device, read from a stored value: null when it is none. */
  function grantRecord(value) {
    if (value === null || typeof value !== "object") return null;
    return {
      granted_ms: whole(value.granted_ms), not_after_ms: whole(value.not_after_ms),
      release: typeof value.release === "string" ? value.release : "",
      first_ms: whole(value.first_ms), platform: value.platform === "local" ? "local" : "nitro",
      attempted_ms: whole(value.attempted_ms),
    };
  }

  /** Carries the node ledger of the program before v43 over, once per installation and account:
   *  a node of the ledger with a grant time becomes a grant of this device, and every node the
   *  ledger explains becomes a chain of format 1 or format 2 this program reads on from the
   *  verification point of the ledger (closed when that point reached the final head of the node
   *  or the build of the node wrote no entry to the store). The marks of the earlier program (gaps,
   *  ends it could not confirm, nodes it could not explain, the time its reads began to fail) are
   *  not carried over: the first round of this program judges by its own conditions. Nothing is
   *  carried over while the device holds no master key. */
  function migrateLedger() {
    if (native.storeGet(STORE_MIGRATED) !== null || readMasterKey() === null) return;
    const ledger = loadLedger();
    const grants = storedObject(STORE_GRANTS);
    const legacy = loadLegacy();
    for (const id of Object.keys(ledger.nodes)) {
      const node = ledger.nodes[id];
      if (node.origin !== "grant") continue;
      if (node.granted_ms > 0 && grantRecord(grants[id]) === null) {
        grants[id] = {
          granted_ms: node.granted_ms, not_after_ms: node.not_after_ms, release: node.release,
          first_ms: node.first_ms, platform: node.platform === "local" ? "local" : "nitro",
          attempted_ms: node.attempted_ms,
        };
      }
      if (legacy.nodes[id] === undefined) {
        const ended = node.final !== null && node.checkpoint.seq >= node.final.seq;
        legacy.nodes[id] = {
          seq: node.checkpoint.seq, time_ms: node.checkpoint.time_ms, until_ms: node.not_after_ms,
          closed: ended || !writesToStore(node.platform, node.release),
        };
      }
    }
    storeJson(STORE_GRANTS, grants);
    saveLegacy(legacy);
    for (const key of RETIRED_STORE_KEYS) native.storeSet(key, null);
    native.storeSet(STORE_MIGRATED, String(VERSION));
  }

  /** The grants of this device: {node: {granted_ms, not_after_ms, release, first_ms, platform,
   *  attempted_ms}}. granted_ms is 0 for a node this device verified and sent a grant that the
   *  node did not confirm. A record whose grant ended longer ago than the retention of the log is
   *  dropped. */
  function loadGrants() {
    migrateLedger();
    const kept = storedObject(STORE_GRANTS);
    const grants = Object.create(null);
    const horizon = native.nowMs() - (LOG_RETENTION_DAYS + GRANT_DAYS_MAX + 5) * DAY_MS;
    for (const id of Object.keys(kept)) {
      const record = NODE_ID.test(id) ? grantRecord(kept[id]) : null;
      if (record === null) continue;
      if (Math.max(record.not_after_ms, record.attempted_ms, record.granted_ms) < horizon) continue;
      grants[id] = record;
    }
    return grants;
  }

  function saveGrants(grants) {
    if (accountClosed) return;
    storeJson(STORE_GRANTS, grants);
  }

  /** Whether that node holds a grant within its time. A grant handed before the last revocation
   *  time counts as revoked and is not counted. */
  function holdsGrant(ledger, grants, id, now) {
    const record = grants[id];
    return record !== undefined && record.granted_ms > ledger.revoked_ms && record.not_after_ms > now;
  }

  /** The published state grant: accepted is the Set of node ids accepted this time. When every one
   *  of them holds a grant within its time the state is active, when only some do it is partial,
   *  when none does it is none, and when delegation is off it is off. not_after_ms is the earliest
   *  end among those grants. */
  function grantState(ledger, grants, accepted, now) {
    if (delegationOff(ledger)) return { state: "off", not_after_ms: 0 };
    let holding = 0;
    let earliest = 0;
    accepted.forEach(function (id) {
      if (!holdsGrant(ledger, grants, id, now)) return;
      holding += 1;
      const limit = grants[id].not_after_ms;
      earliest = earliest === 0 ? limit : Math.min(earliest, limit);
    });
    const state = holding === 0 ? "none" : holding === accepted.size ? "active" : "partial";
    return { state: state, not_after_ms: earliest };
  }

  /** The custody of a record the app makes: among the nodes this device handed a grant to that
   *  hold it within its time, enclave is preferred. null when there is no such node. */
  function heldCustody(ledger, grants, now) {
    let found = null;
    for (const id of Object.keys(grants)) {
      if (!holdsGrant(ledger, grants, id, now)) continue;
      if (grants[id].platform === "nitro") return "enclave";
      found = "operator";
    }
    return found;
  }

  // ---- Delegation ----

  /** Sends one command to a node. The command JSON is signed with the account signing key, and
   *  {payload, sig} is sealed with HPKE to the sealing public key of that node as the envelope {v,
   *  node, enc, ct} carried by the relay route. The reply is checked, after its node signature, for
   *  its type, node, account, challenge and key_id being those of the sent command. A failure reply
   *  signed by the node has its code as the failure code. node is {node, signPk, sealPk}. Returns
   *  the verified reply body. */
  async function sendCommand(turn, node, command, replyType, keys) {
    const payload = utf8(JSON.stringify(command));
    const signature = native.ed25519Sign(
      keys.signSeed, encode(concat(utf8(purpose("command") + "\n"), payload)));
    const signed = utf8(JSON.stringify({ payload: encode(payload), sig: signature }));
    const sealed = native.hpkeSeal({
      kem: "x25519", kdf: "sha256", aead: "chacha20poly1305", recipientPublicKey: node.sealPk,
      info: info("message"), aad: encode(utf8(node.node)), plaintext: encode(signed),
    });
    const envelope = { v: 1, node: node.node, enc: sealed.enc, ct: sealed.ciphertext };
    const path = NODES_PATH + "/" + node.node + "/messages";
    const response = await api(turn, "POST", path, { envelope: envelope }, null, NODE_TIMEOUT_MS);
    const reply = openSigned(response.json.reply, node.signPk, purpose("reply") + "\n");
    if (reply.node !== node.node) throw native.error("bad_signature", "reply is from another node");
    // The failure reply of a node that could not open the envelope has an empty account, challenge
    // and key_id: the failure is checked first.
    if (reply.ok !== true) {
      const refused = typeof reply.code === "string" && reply.code !== "";
      throw native.error(refused ? reply.code : "bad_signature", replyType);
    }
    if (reply.type !== replyType || reply.user_id !== command.user_id ||
        reply.challenge !== command.challenge || reply.key_id !== keys.keyId) {
      throw native.error("bad_signature", "reply is not for this command");
    }
    // The reply must be the one to this command. The challenge is plaintext outside the
    // attestation document, so the relay can swap in an old value, and then the signed reply of an
    // old command passes every comparison above. A reply that lies more than REPLY_SKEW_MS before
    // the time of the document verified this time (the time of a node whose freshness the request
    // nonce established) is not the reply to this command.
    if (whole(reply.time_ms) + REPLY_SKEW_MS < node.timeMs) {
      throw native.error("bad_signature", "reply predates the attestation");
    }
    return reply;
  }

  /** Sends a grant: the user key of the custody of that node, the two public keys and the expiry.
   *  The expiry is the time of the attestation document of that node (node.timeMs) plus the
   *  lifetime (the device clock is not used: the grant of a device whose clock runs ahead is not
   *  refused). The expiry the node accepted is not_after_ms of the reply. Returns {granted_ms,
   *  not_after_ms}, both in device clock time: not_after_ms is now plus the lifetime the node
   *  accepted (the expiry of the reply minus the time of the document). */
  async function sendGrant(turn, node, challenge, keys, ttlMs) {
    // The user key goes to a node of a listed release only (verifyAttestation).
    if (node.listed !== true) throw attestationFailure("measurement");
    const reply = await sendCommand(turn, node, {
      v: 1, type: "grant", user_id: userId(), node: node.node, challenge: challenge,
      sign_pk: keys.signPk, log_pk: keys.logPk, custody: node.custody,
      user_key: keys.userKeys[node.custody], not_after_ms: node.timeMs + ttlMs, policy: {},
    }, "grant_reply", keys);
    const lifetime = Math.min(ttlMs, Math.max(0, whole(reply.not_after_ms) - node.timeMs));
    const granted = native.nowMs();
    return { granted_ms: granted, not_after_ms: granted + lifetime };
  }

  /** Sends the revocation of a grant: the node erases the user key of that account. */
  async function sendRevoke(turn, node, challenge, keys) {
    await sendCommand(turn, node, {
      v: 1, type: "revoke", user_id: userId(), node: node.node, challenge: challenge,
      sign_pk: keys.signPk,
    }, "revoke_reply", keys);
  }

  // ---- Records ----

  /** The additional authenticated data of a record: it binds the id, the account, the key_id, the
   *  custody, the kind and the provider. */
  function recordAad(id, user, keyId, custody, kind, provider) {
    return encode(utf8([purpose("record"), "1", id, user, keyId, custody, kind, provider].join("\n")));
  }

  /** Makes one credential record. The record key is derived from the user key of that custody with
   *  the record id (16 random bytes, or the id given: writing a record again keeps its id) as the
   *  salt, and the plaintext bytes (plaintext: base64url) are encrypted with ChaCha20-Poly1305
   *  under a random 12-byte nonce. */
  function sealRecordBytes(keys, custody, kind, provider, plaintext, givenId) {
    const id = givenId === undefined ? native.randomBytes(16) : givenId;
    const nonce = native.randomBytes(12);
    const user = userId();
    const recordKey = native.hkdf("sha256", keys.userKeys[custody], id, info("record"), 32);
    const ct = native.aeadSeal({
      alg: "chacha20poly1305", key: recordKey, nonce: nonce,
      aad: recordAad(id, user, keys.keyId, custody, kind, provider), plaintext: plaintext,
    });
    return {
      v: 1, id: id, user_id: user, key_id: keys.keyId, custody: custody, kind: kind,
      provider: provider, nonce: nonce, ct: ct,
    };
  }

  /** Makes one credential record whose plaintext is the JSON of plaintextObject. */
  function sealRecord(keys, custody, kind, provider, plaintextObject) {
    return sealRecordBytes(keys, custody, kind, provider, encode(utf8(JSON.stringify(plaintextObject))));
  }

  /** Opens a record of this account and key with the user key the device derives: the plaintext
   *  as a JSON object. The record must be of the kind and the provider given. A record of another
   *  account, key, kind or form, and one that does not open, is record_invalid. */
  function openRecord(keys, record, kind, provider) {
    const shaped = record !== null && typeof record === "object" && record.v === 1 &&
      typeof record.id === "string" && typeof record.nonce === "string" && typeof record.ct === "string" &&
      (record.custody === "enclave" || record.custody === "operator");
    if (!shaped || record.user_id !== userId() || record.key_id !== keys.keyId ||
        record.kind !== kind || record.provider !== provider) {
      throw native.error("record_invalid", kind);
    }
    let plain = null;
    try {
      const recordKey = native.hkdf("sha256", keys.userKeys[record.custody], record.id, info("record"), 32);
      plain = JSON.parse(text(decode(native.aeadOpen({
        alg: "chacha20poly1305", key: recordKey, nonce: record.nonce,
        aad: recordAad(record.id, record.user_id, record.key_id, record.custody, record.kind, record.provider),
        ciphertext: record.ct,
      }))));
    } catch (error) {
      plain = null;
    }
    if (plain === null || typeof plain !== "object" || Array.isArray(plain)) {
      throw native.error("record_invalid", kind);
    }
    return plain;
  }

  // ---- The log ----

  const PROVIDER_NAMES = new Map([
    ["google_workspace", "Google"], ["microsoft", "Microsoft"], ["slack", "Slack"],
    ["notion", "Notion"], ["x", "X"], ["link", "Link"], ["granola", "Granola"],
    ["mercury", "Mercury"], ["naver_mail", "NAVER Mail"], ["github", "GitHub"],
    ["vault", "Vault"],
  ]);

  // For every service (a product inside a provider) of a provider request: the display name, the
  // short name of the summary line (appended to the provider name; an empty value is not appended),
  // and the icon (a definition image ui_image/{name}: when glyph is true a glyph on a tile, when
  // false an image that fills the tile). A service outside the table has an empty icon.
  const SERVICES = new Map([
    ["gmail", { name: "Gmail", short: "Gmail", image: "product-gmail", glyph: true }],
    ["google_calendar", { name: "Google Calendar", short: "Calendar", image: "product-google-calendar", glyph: true }],
    ["google_drive", { name: "Google Drive", short: "Drive", image: "product-google-drive", glyph: true }],
    ["google_workspace", { name: "Google", short: "", image: "connection-icon-google-workspace-mail", glyph: false }],
    ["outlook_mail", { name: "Outlook", short: "Mail", image: "connection-icon-microsoft", glyph: false }],
    ["outlook_calendar", { name: "Outlook Calendar", short: "Calendar", image: "connection-icon-microsoft", glyph: false }],
    ["teams", { name: "Microsoft Teams", short: "Teams", image: "connection-icon-microsoft", glyph: false }],
    ["microsoft", { name: "Microsoft", short: "", image: "connection-icon-microsoft", glyph: false }],
    ["slack", { name: "Slack", short: "", image: "connection-icon-slack", glyph: false }],
    ["notion", { name: "Notion", short: "", image: "connection-icon-notion", glyph: false }],
    ["x", { name: "X", short: "", image: "connection-icon-x", glyph: false }],
    ["link", { name: "Link", short: "", image: "connection-icon-link", glyph: false }],
    ["granola", { name: "Granola", short: "", image: "connection-icon-granola", glyph: false }],
    ["mercury", { name: "Mercury", short: "", image: "connection-icon-mercury", glyph: false }],
    ["naver_mail", { name: "NAVER Mail", short: "", image: "connection-icon-naver-mail", glyph: false }],
    ["github", { name: "GitHub", short: "", image: "connection-icon-github", glyph: false }],
  ]);

  /** The service id of a provider request: google_workspace is split by host and path into Gmail,
   *  Calendar and Drive, microsoft by path into Teams (chats, teams), mail and calendar, and every
   *  other provider is the provider itself. */
  function serviceOf(provider, host, path) {
    if (provider === "google_workspace") {
      if (host === "gmail.googleapis.com") return "gmail";
      if (path.startsWith("/calendar/")) return "google_calendar";
      if (path.startsWith("/drive/") || path.startsWith("/upload/drive/")) return "google_drive";
      return "google_workspace";
    }
    if (provider === "microsoft") {
      if (path.indexOf("/chats/") >= 0 || path.indexOf("/teams/") >= 0 || path.indexOf("/joinedTeams") >= 0) {
        return "teams";
      }
      if (path.indexOf("/messages") >= 0 || path.indexOf("/mailFolders") >= 0 || path.indexOf("/sendMail") >= 0) {
        return "outlook_mail";
      }
      if (path.indexOf("/events") >= 0 || path.indexOf("/calendar") >= 0) return "outlook_calendar";
      return "microsoft";
    }
    return provider;
  }

  function providerName(provider) {
    const name = PROVIDER_NAMES.get(provider);
    return name === undefined ? String(provider) : name;
  }

  function serviceName(service) {
    const entry = SERVICES.get(service);
    return entry === undefined ? providerName(service) : entry.name;
  }

  // The kinds of context the caller (the operator domain) declared. The definition chooses its
  // wording per kind.
  const CONTEXT_KINDS = new Map([
    ["connect:naver_mail", "connect"], ["connect:installation", "repositories"],
    ["link:spend_watch", "payment_check"], ["browser:link_card", "checkout_card"],
    ["browser:fill", "web_fill"], ["context:today_calendar", "today_calendar"],
    ["profile:connected_profiles", "profiles"], ["profile:x_bio", "x_bio"],
    ["connect", "connect"], ["connect:identity", "identity"], ["connect:rejected", "undo_connect"],
    ["refresh", "signed_in"], ["refresh:auth_failure", "signed_in"], ["refresh:scheduled", "signed_in"],
    ["disconnect", "disconnect"], ["account:delete", "account_delete"],
    ["operator:connection_smoke", "smoke"],
  ]);

  /** The kind of a context: the value of the table, `cli:*` is task (a task being handled), and
   *  everything else (the memo the forwarding proxy attaches to a git or gh request of the isolated
   *  shell: `git fetch owner/repo`, `gh GET /repos/...`, `gh graphql read IssueList owner/repo`) is
   *  memo (the definition shows the context string as it is). An absent context is the empty
   *  string. */
  function contextKind(context) {
    if (typeof context !== "string" || context === "") return "";
    const kind = CONTEXT_KINDS.get(context);
    if (kind !== undefined) return kind;
    return context.startsWith("cli:") ? "task" : "memo";
  }

  // The GitHub memos of the forwarding proxy that belong to read requests: `git fetch …`,
  // `gh GET …`, `gh HEAD …`, `gh graphql read …`. A GraphQL read is a POST, so without the memo it
  // would show as Changed.
  function readMemo(context) {
    if (typeof context !== "string") return false;
    return context.startsWith("git fetch ") || context.startsWith("gh GET ") ||
      context.startsWith("gh HEAD ") || context.startsWith("gh graphql read ");
  }

  /** Whether two base64url values are the same bytes (a malformed value equals nothing). */
  function sameBytes(a, b) {
    try {
      return equal(decode(a), decode(b));
    } catch (error) {
      return false;
    }
  }

  // The base64url of 32 zero bytes: the end of a chain without entries and the prev of the first
  // entry.
  // (ZERO_HASH and NODE_ID are defined with the node ledger above.)

  /** Opens the event (the plaintext) of one log entry body of format 1 with the log decryption
   *  private key. An entry whose key_id is not ours is not opened and gives null. */
  function openEvent(body, keys) {
    if (body.key_id !== keys.keyId) return null;
    const aad = [body.node, body.user_id, body.key_id, String(body.seq)].join("\n");
    const event = JSON.parse(text(decode(native.hpkeOpen({
      kem: "x25519", kdf: "sha256", aead: "chacha20poly1305", recipientPrivateKey: keys.logSk,
      enc: body.enc, info: info("log-entry"), aad: encode(utf8(aad)), ciphertext: body.ct,
    }))));
    if (event === null || typeof event !== "object") throw native.error("bad_signature", "event");
    return event;
  }

  /** Opens the events (the plaintext: a JSON array of count events) of one log entry body of
   *  format 2 or format 3 (version) with the log decryption private key. The caller checked that
   *  the key_id is ours. A plaintext that is not an array of count objects is bad_signature. */
  function openEvents(body, keys, version) {
    const aad = [body.node, body.user_id, body.key_id, String(body.seq)].join("\n");
    const purposeOf = version === 3 ? purposeV3 : purposeV2;
    const events = JSON.parse(text(decode(native.hpkeOpen({
      kem: "x25519", kdf: "sha256", aead: "chacha20poly1305", recipientPrivateKey: keys.logSk,
      enc: body.enc, info: encode(utf8(purposeOf("log-entry"))), aad: encode(utf8(aad)), ciphertext: body.ct,
    }))));
    const shaped = Array.isArray(events) && events.length === body.count &&
      events.every(function (event) { return event !== null && typeof event === "object"; });
    if (!shaped) throw native.error("bad_signature", "events");
    return events;
  }

  // ---- The log store ----

  // The events a control entry holds (one per entry) and the events a use entry holds
  // (docs/protocol.md 7.1) in the chains of format 2. A key of format 3 names the event of its
  // control entry itself, and a release may add names.
  const CONTROL_EVENTS = [
    "grant_accepted", "grant_revoked", "connection_created", "connection_removed",
    "grant_transferred_out", "grant_transferred_in",
  ];
  const USE_EVENTS = ["provider_request", "credential_refreshed", "mail_request", "secret_released", "totp_issued"];

  /** A failed read of the log. kind says what the failure means for the round:
   *    blocked      the operator domain held the read back (the backend refused, an address is not
   *                 the one of the request, the store refused a fresh address, a body or a document
   *                 the listing names was not handed out)
   *    silent       the backend did not answer in time: blocked when the backend answered another
   *                 request of this runtime around that time, unreachable otherwise (reachJudged)
   *    unreachable  the device or the store failed (no network, a 5xx status of the store, an
   *                 address that aged while the app was suspended)
   *    absent       the backend has no such store
   *  detail names the request and what it answered, for the report of the round, as
   *  "{request}:{status | code}". */
  function storeFailure(kind, detail) {
    return { log_store_failure: true, kind: kind, detail: typeof detail === "string" ? detail : "" };
  }

  function isStoreFailure(error) {
    return error !== null && typeof error === "object" && error.log_store_failure === true;
  }

  /** The failure of a read of the log for a failed request to the backend (name: the request). */
  function backendFailure(error, name) {
    if (isStoreFailure(error)) return error;
    const code = failureCode(error);
    if (routeAbsent(error)) return storeFailure("absent", name + ":" + code);
    if (failureStatus(error) !== 0) return storeFailure("blocked", name + ":" + failureStatus(error));
    if (code === "timeout" || code === "transport") {
      // A request that failed in a runtime that may not have run for a part of its wait (the
      // app was suspended) says nothing of the backend.
      if (error.frozen === true) return storeFailure("unreachable", name + ":suspended");
      return storeFailure("silent", name + ":" + code);
    }
    if (code === "invalid_response") return storeFailure("blocked", name + ":invalid");
    return error;
  }

  /** The log store of this server target (an element of LOG_STORES), undefined when the target has
   *  none. */
  function logStore() {
    return LOG_STORES[native.deviceInfo().server_target];
  }

  /** Whether a debug build may call the S3 stand-in of the local stack: an address over http or
   *  https, at the host the backend hands out, in the path-style form of a bucket of
   *  LOG_STORES.local. The bridge of a debug build reports the server target prod whatever backend
   *  the app talks to, so the build configuration alone decides. A release build calls the host of
   *  a bucket of its server target and nothing else. */
  function storeUnpinned() {
    return native.deviceInfo().debug_build === true;
  }

  /** The name of the bucket of format 3 that holds the objects of owner (the user_id of an
   *  account, or a node id) in the log store given (docs/protocol.md 7.6). */
  function shardBucket(store, owner) {
    const digest = decode(native.sha256(encode(utf8(owner))));
    const index = ((digest[0] << 8) | digest[1]) % store.shards;
    const tail = store.bucket + "-" + String(index).padStart(4, "0");
    return hex(decode(native.sha256(encode(utf8(tail)))).subarray(0, 4)) + "-" + tail;
  }

  /** The object key prefix of this account in the bucket of format 1 and format 2. */
  function accountPrefix() {
    return "v1/accounts/" + userId() + "/";
  }

  /** The prefix of the entries of format 3 of this account: letter c for the control entries, u
   *  for the use entries. */
  function entryPrefix(letter) {
    return "a3/" + userId() + "/" + letter + "/";
  }

  /** Reads the query string of a URL as a table from name to value. With once true, a query that
   *  gives a name twice has no table (null). */
  function parseQuery(url, once) {
    const out = Object.create(null);
    const start = url.indexOf("?");
    if (start < 0) return out;
    const end = url.indexOf("#", start);
    const query = url.slice(start + 1, end < 0 ? url.length : end);
    function component(value) {
      try {
        return decodeURIComponent(value.replace(/\+/g, " "));
      } catch (error) {
        return value;
      }
    }
    for (const pair of query.split("&")) {
      if (pair === "") continue;
      const at = pair.indexOf("=");
      const name = component(at < 0 ? pair : pair.slice(0, at));
      if (once === true && name in out) return null;
      out[name] = at < 0 ? "" : component(pair.slice(at + 1));
    }
    return out;
  }

  /** The parts of an address of the log store: the host (lower case, with its port when one is
   *  given), the path (percent-decoded) and the query table. The scheme is https, or http as well
   *  when plain is true. null when the value is not such an address with a host, the path does
   *  not decode, the query gives a name twice, or the address carries a fragment: the program
   *  judges an address by the one value it reads for a name, so an address the store could read
   *  another way is not called (the store answers a name that is given twice by its first value,
   *  and a fragment is not part of the request the device sends). */
  function splitUrl(url, plain) {
    if (typeof url !== "string" || url.indexOf("#") >= 0) return null;
    const scheme = url.slice(0, 8) === "https://" ? "https://"
      : plain === true && url.slice(0, 7) === "http://" ? "http://" : null;
    if (scheme === null) return null;
    const rest = url.slice(scheme.length);
    let end = rest.length;
    for (const stop of ["/", "?", "#"]) {
      const at = rest.indexOf(stop);
      if (at >= 0 && at < end) end = at;
    }
    const host = rest.slice(0, end).toLowerCase();
    if (host === "") return null;
    const tail = rest.slice(end);
    const cut = tail.search(/[?#]/);
    let path = cut < 0 ? tail : tail.slice(0, cut);
    if (path === "") path = "/";
    try {
      path = decodeURIComponent(path);
    } catch (error) {
      return null;
    }
    const query = parseQuery(tail, true);
    return query === null ? null : { host: host, path: path, query: query };
  }

  /** Whether the query of a presigned address carries only the keys allowed and the signature keys
   *  (X-Amz-...). Any other key rejects the address: a key that changes what S3 lists or returns is
   *  not one the backend may add. */
  function queryKeysAccepted(query, allowed) {
    return Object.keys(query).every(function (key) {
      return allowed.indexOf(key) >= 0 || key.slice(0, 6) === "X-Amz-";
    });
  }

  /** Whether the host and the path of a store address name the object key (the empty key: a
   *  listing) of the bucket of this server target (pinned) or, in a debug build only, of the bucket
   *  of the local stack in the path-style form at any host (local; a listing may also be
   *  "/{bucket}"). An address of another host in the virtual-hosted form is refused in every
   *  build. */
  function addressOfBucket(parts, key, pinned, local) {
    const store = logStore();
    if (store !== undefined && pinned !== null &&
        parts.host === pinned + ".s3." + store.region + ".amazonaws.com" && parts.path === "/" + key) {
      return true;
    }
    if (!storeUnpinned() || local === null) return false;
    return parts.path === "/" + local + "/" + key || (key === "" && parts.path === "/" + local);
  }

  /** Whether an address of the bucket of format 1 and format 2 is one of this store for key. */
  function storeAddressAccepted(parts, key) {
    const store = logStore();
    return addressOfBucket(parts, key, store === undefined ? null : store.bucket, LOG_STORES.local.bucket);
  }

  /** Whether a listing address of the bucket of format 1 and format 2 the backend handed out is
   *  called: the host and path of the store, only the query keys of LISTING_QUERY_KEYS and the
   *  signature, the query versions, the prefix expected, the delimiter "/" for the node discovery
   *  listing and absent otherwise, the markers the ones requested (absent when none was requested),
   *  a page size of 1000 when given and the encoding url when given. */
  function listingUrlAccepted(url, expected) {
    const parts = splitUrl(url, storeUnpinned());
    if (parts === null || !storeAddressAccepted(parts, "")) return false;
    const query = parts.query;
    if (!queryKeysAccepted(query, LISTING_QUERY_KEYS)) return false;
    if (!("versions" in query) || query.prefix !== expected.prefix) return false;
    if ("max-keys" in query && query["max-keys"] !== "1000") return false;
    if ("encoding-type" in query && query["encoding-type"] !== "url") return false;
    if (expected.nodes ? query.delimiter !== "/" : "delimiter" in query) return false;
    if (expected.keyMarker === null
        ? "key-marker" in query
        : query["key-marker"] !== expected.keyMarker) {
      return false;
    }
    if (expected.versionIdMarker === null
        ? "version-id-marker" in query
        : query["version-id-marker"] !== expected.versionIdMarker) {
      return false;
    }
    return true;
  }

  /** Whether a listing address of format 3 the backend handed out is called (docs/protocol.md
   *  7.4): the host of the bucket computed from the user_id of this account, the path "/", the
   *  query versions, the prefix of the control or of the use entries of this account, a page size
   *  of 1000, the markers the ones requested (absent when none was requested), the encoding url
   *  when given, and no query key besides these and the signature. */
  function readUrlAccepted(url, letter, keyMarker, versionIdMarker) {
    const parts = splitUrl(url, storeUnpinned());
    if (parts === null) return false;
    const store = logStore();
    const user = userId();
    const pinned = store === undefined ? null : shardBucket(store, user);
    if (!addressOfBucket(parts, "", pinned, shardBucket(LOG_STORES.local, user))) return false;
    const query = parts.query;
    if (!queryKeysAccepted(query, ["versions", "prefix", "key-marker", "version-id-marker", "max-keys", "encoding-type"])) {
      return false;
    }
    if (!("versions" in query) || query.prefix !== entryPrefix(letter)) return false;
    if (query["max-keys"] !== "1000") return false;
    if ("encoding-type" in query && query["encoding-type"] !== "url") return false;
    if (keyMarker === "" ? "key-marker" in query : query["key-marker"] !== keyMarker) return false;
    if (versionIdMarker === "" ? "version-id-marker" in query : query["version-id-marker"] !== versionIdMarker) {
      return false;
    }
    return true;
  }

  /** The object key of the node document of a node (docs/protocol.md 7.7). */
  function documentKey(node) {
    return "n3/" + node;
  }

  /** Whether the address of the listing of the versions of the node document of node that the
   *  backend handed out is called: the host of the bucket computed from the node id (the buckets
   *  of format 3 hold a node document by the rule that holds the entries of an account, with the
   *  node id in the place of the user_id), the path "/", the query versions, the prefix that is
   *  the key of that node document, a page size of 1000, the encoding url when given, and no query
   *  key besides these and the signature. The address carries no marker: the one page that begins
   *  the listing is read. */
  function documentUrlAccepted(url, node) {
    const parts = splitUrl(url, storeUnpinned());
    if (parts === null) return false;
    const store = logStore();
    const pinned = store === undefined ? null : shardBucket(store, node);
    if (!addressOfBucket(parts, "", pinned, shardBucket(LOG_STORES.local, node))) return false;
    const query = parts.query;
    if (!queryKeysAccepted(query, ["versions", "prefix", "max-keys", "encoding-type"])) return false;
    if (!("versions" in query) || query.prefix !== documentKey(node)) return false;
    if (query["max-keys"] !== "1000") return false;
    if ("encoding-type" in query && query["encoding-type"] !== "url") return false;
    return true;
  }

  /** Whether an object address of the bucket of format 1 and format 2 the backend handed out is
   *  called: the host and path of the store for that key, the query versionId of that version and
   *  no other query key besides the signature. */
  function objectUrlAccepted(url, key, versionId) {
    const parts = splitUrl(url, storeUnpinned());
    return parts !== null && storeAddressAccepted(parts, key) &&
      parts.query.versionId === versionId && queryKeysAccepted(parts.query, ["versionId"]);
  }

  /** One GET of the log store: {status, body}. Each attempt has LOG_STORE_TIMEOUT_MS. A failure
   *  of the transport, a timeout, a 429 and a 5xx status are tried again (LOG_STORE_ATTEMPTS
   *  attempts in all, with the pauses of LOG_STORE_RETRY_MS between them); a failure that remains
   *  is unreachable, with the request named in its detail. */
  async function fetchStore(turn, url, name) {
    for (let attempt = 1; attempt <= LOG_STORE_ATTEMPTS; attempt += 1) {
      let response = null;
      try {
        response = await limited(
          turn, native.http({ method: "GET", url: url, timeoutMs: LOG_STORE_TIMEOUT_MS }),
          LOG_STORE_TIMEOUT_MS, name);
      } catch (error) {
        if (failureCode(error) === "cancelled") throw error;
        if (attempt >= LOG_STORE_ATTEMPTS || !(turnLeft(turn) > 0)) {
          throw storeFailure("unreachable", name + ":" + (failureCode(error) === "timeout" ? "timeout" : "transport"));
        }
        await limited(turn, native.sleep(LOG_STORE_RETRY_MS[attempt - 1]), LOG_STORE_TIMEOUT_MS, name);
        continue;
      }
      const again = response.status === 429 || (response.status >= 500 && response.status <= 599);
      if (again && attempt < LOG_STORE_ATTEMPTS) {
        await limited(turn, native.sleep(LOG_STORE_RETRY_MS[attempt - 1]), LOG_STORE_TIMEOUT_MS, name);
        continue;
      }
      return { status: response.status, body: typeof response.body === "string" ? response.body : "" };
    }
    throw storeFailure("unreachable", name + ":transport");
  }

  /** The failure of a read for a response of the store outside 200 to an address signed at
   *  signedMs: a 5xx status and a 429 are the store failing (unreachable); any other status is a
   *  refusal of the address the backend signed (blocked), unless the address had aged (the app was
   *  suspended between the answer of the backend and the call: unreachable, the next round reads
   *  again). */
  function storeRefusal(status, name, signedMs) {
    if (status === 429 || (status >= 500 && status <= 599)) return storeFailure("unreachable", name + ":" + status);
    const aged = native.nowMs() - signedMs > LOG_URL_FRESH_MS;
    return storeFailure(aged ? "unreachable" : "blocked", name + ":" + status);
  }

  const XML_ENTITIES = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'" };

  function xmlText(value) {
    return value.replace(/&(amp|lt|gt|quot|apos);/g, function (match, name) { return XML_ENTITIES[name]; });
  }

  /** The text of the first element name of xml (the empty string for an empty element), null when
   *  the element is absent. */
  function xmlField(xml, name) {
    const match = new RegExp("<" + name + "(?:\\s[^>]*)?(?:/>|>([^<]*)</" + name + ">)").exec(xml);
    if (match === null) return null;
    return xmlText(match[1] === undefined ? "" : match[1]);
  }

  /** The inner texts of every element name of xml. */
  function xmlBlocks(xml, name) {
    const out = [];
    const pattern = new RegExp("<" + name + "(?:\\s[^>]*)?>([\\s\\S]*?)</" + name + ">", "g");
    let match = pattern.exec(xml);
    while (match !== null) {
      out.push(match[1]);
      match = pattern.exec(xml);
    }
    return out;
  }

  /** Reads a ListVersionsResult document of S3: whether the listing is truncated and the markers of
   *  the next page, the versions {key, versionId, isLatest} and the common prefixes. When the
   *  document declares the encoding url (the listing was requested with encoding-type url), the
   *  keys, the common prefixes and the next key marker are percent-decoded. Delete markers are not
   *  read (a delete marker hides no preserved version from a listing of versions). complete says
   *  that the document states that the listing ends with this page, and skipped is the number of
   *  version elements without a key or a version id (elements the program cannot name). null
   *  when the document is not a ListVersionsResult or a name does not decode. */
  function parseListVersions(xml) {
    if (typeof xml !== "string" || !/<ListVersionsResult[\s>]/.test(xml)) return null;
    const top = xml.replace(/<(Version|DeleteMarker|CommonPrefixes)(?:\s[^>]*)?>[\s\S]*?<\/\1>/g, "");
    const encoded = xmlField(top, "EncodingType") === "url";
    function name(value) {
      if (value === null || !encoded) return value;
      try {
        return decodeURIComponent(value.replace(/\+/g, " "));
      } catch (error) {
        return undefined;
      }
    }
    const versions = [];
    let skipped = 0;
    for (const block of xmlBlocks(xml, "Version")) {
      const key = name(xmlField(block, "Key"));
      const versionId = xmlField(block, "VersionId");
      if (key === undefined) return null;
      if (key !== null && versionId !== null) {
        versions.push({ key: key, versionId: versionId, isLatest: xmlField(block, "IsLatest") === "true" });
      } else {
        skipped += 1;
      }
    }
    const prefixes = [];
    for (const block of xmlBlocks(xml, "CommonPrefixes")) {
      const prefix = name(xmlField(block, "Prefix"));
      if (prefix === undefined) return null;
      if (prefix !== null) prefixes.push(prefix);
    }
    const nextKeyMarker = name(xmlField(top, "NextKeyMarker"));
    if (nextKeyMarker === undefined) return null;
    const nextVersionIdMarker = xmlField(top, "NextVersionIdMarker");
    const truncated = xmlField(top, "IsTruncated");
    return {
      truncated: truncated === "true", complete: truncated === "false",
      nextKeyMarker: nextKeyMarker === null || nextKeyMarker === "" ? null : nextKeyMarker,
      nextVersionIdMarker:
        nextVersionIdMarker === null || nextVersionIdMarker === "" ? null : nextVersionIdMarker,
      versions: versions, skipped: skipped, prefixes: prefixes,
    };
  }

  /** What a listing of the versions under the key of the node document of node says: true when
   *  the store holds a version of that object or the listing does not show that it holds none
   *  (it goes on beyond this page, or it has a version element the program cannot name), false
   *  when the listing ends with this page and names no version of that key (a delete marker is no
   *  version: nobody wrote a document under the key), null when the document is no listing. */
  function documentListed(xml, node) {
    const listing = parseListVersions(xml);
    if (listing === null) return null;
    if (!listing.complete || listing.skipped > 0) return true;
    const key = documentKey(node);
    return listing.versions.some(function (version) { return version.key === key; });
  }

  // ---- Format 3: the keys, the listings, the bodies and the node documents ----

  const KEY_PART_43 = /^[A-Za-z0-9_-]{43}$/;
  const KEY_ID = /^[0-9a-f]{16}$/;
  const EVENT_NAME = /^[a-z0-9_]{1,64}$/;
  const PLAIN_NUMBER = /^[1-9][0-9]{0,15}$/;

  /** Whether a part of a key is the one way to write 32 bytes in base64url. */
  function canonical32(value) {
    if (!KEY_PART_43.test(value)) return false;
    try {
      return encode(decode(value)) === value;
    } catch (error) {
      return false;
    }
  }

  /** The first part of the name of an entry of format 3 for the time ms: 9999999999999 minus the
   *  time, as 13 digits. The keys of a prefix sort with the latest entry first. */
  function rtimeDigits(ms) {
    return String(RTIME_MAX - Math.min(RTIME_MAX, Math.max(0, ms))).padStart(13, "0");
  }

  /** Reads an object key as the key of an entry of format 3 of this account under the prefix of
   *  letter (docs/protocol.md 7.6): {key, tail, letter, time_ms, node, seq, event, count, key_id,
   *  body_hash}. tail is the part after the prefix: the tails of a prefix sort with the latest
   *  entry first. event is the name of the one event of a control entry (the empty string for a
   *  use entry). null for a key of any other shape: such a key is not an entry. */
  function parseEntryKey(key, letter) {
    const prefix = entryPrefix(letter);
    if (typeof key !== "string" || key.slice(0, prefix.length) !== prefix) return null;
    const tail = key.slice(prefix.length);
    const parts = tail.split(".");
    if (parts.length !== 6 || !/^[0-9]{13}$/.test(parts[0])) return null;
    if (!canonical32(parts[1]) || !canonical32(parts[5]) || !KEY_ID.test(parts[4])) return null;
    if (!PLAIN_NUMBER.test(parts[2])) return null;
    const seq = Number(parts[2]);
    if (!Number.isSafeInteger(seq)) return null;
    let count = 1;
    let event = "";
    if (letter === "c") {
      if (!EVENT_NAME.test(parts[3])) return null;
      event = parts[3];
    } else {
      if (!PLAIN_NUMBER.test(parts[3])) return null;
      count = Number(parts[3]);
      if (!(count >= 1 && count <= LOG_ENTRY_EVENTS)) return null;
    }
    return {
      key: key, tail: tail, letter: letter, time_ms: RTIME_MAX - Number(parts[0]), node: parts[1],
      seq: seq, event: event, count: count, key_id: parts[4], body_hash: parts[5],
    };
  }

  /** Verifies the object {body, sig} of a key of format 3 (docs/protocol.md 7.4): the SHA-256 of
   *  the body against the body_hash of the key, the signature under the signing key that the node
   *  id of the key is, and the fields v, node, user_id, key_id, seq, time_ms, kind and count of the
   *  body against the key and the account. Returns {body, failure}: body is the parsed body or
   *  null, and failure names the first check that failed (body, signature, fields) or is empty.
   *  The function does not judge the node: whether the signing key was created inside an enclave of
   *  an accepted measurement is what the node document says. */
  function checkEntry(parsed, entry) {
    const failed = function (failure) { return { body: null, failure: failure }; };
    let bytes = null;
    try {
      bytes = decode(entry.body);
      if (!sameBytes(native.sha256(encode(bytes)), parsed.body_hash)) return failed("body");
    } catch (error) {
      return failed("body");
    }
    let signed = false;
    try {
      signed = native.ed25519Verify(
        parsed.node, encode(concat(utf8(purposeV3("log-entry") + "\n"), bytes)), entry.sig) === true;
    } catch (error) {
      signed = false;
    }
    if (!signed) return failed("signature");
    let body = null;
    try {
      body = JSON.parse(text(bytes));
    } catch (error) {
      body = null;
    }
    if (body === null || typeof body !== "object" || body.v !== 3 || body.node !== parsed.node ||
        body.user_id !== userId() || body.key_id !== parsed.key_id || body.seq !== parsed.seq ||
        body.time_ms !== parsed.time_ms || body.kind !== parsed.letter || body.count !== parsed.count) {
      return failed("fields");
    }
    return { body: body, failure: "" };
  }

  /** The events of a verified entry of format 3 whose key_id is ours: the plaintext opened with
   *  the log decryption key, an array of count events (the one event of a control entry has the
   *  name its key writes). null when the entry does not open to that. */
  function entryEvents(parsed, body, keys) {
    try {
      const events = openEvents(body, keys, 3);
      if (parsed.letter === "c" && (events.length !== 1 || events[0].t !== parsed.event)) return null;
      return events;
    } catch (error) {
      return null;
    }
  }

  /** The listings of format 3 for the pages given ([{prefix, key_marker, version_id_marker}], the
   *  empty string for no marker), read in one stage: the addresses from the backend in one request
   *  (LOG_READ_PATH), each checked before it is called (readUrlAccepted), and the listings from the
   *  store, which the operator domain cannot change. Returns one {letter, keys, tails, truncated,
   *  next_key_marker, next_version_id_marker} per page: keys are the entries the page names (a key
   *  counts once however many versions the listing shows, in the order of the listing: the latest
   *  first), tails the set of their tails. Throws a store failure. */
  async function readListings(turn, pages) {
    let answer = null;
    try {
      answer = (await api(turn, "POST", LOG_READ_PATH, { pages: pages }, null, LOG_API_TIMEOUT_MS)).json;
    } catch (error) {
      throw backendFailure(error, "read");
    }
    const signedMs = native.nowMs();
    const given = Array.isArray(answer.pages) ? answer.pages : [];
    if (given.length !== pages.length) throw storeFailure("blocked", "read:url");
    for (let at = 0; at < pages.length; at += 1) {
      const item = given[at];
      const wanted = pages[at];
      if (item === null || typeof item !== "object" || item.prefix !== wanted.prefix ||
          !readUrlAccepted(item.url, wanted.prefix, wanted.key_marker, wanted.version_id_marker)) {
        throw storeFailure("blocked", "read:url");
      }
    }
    const fetched = await stage(given.map(function (item) { return fetchStore(turn, item.url, "listing"); }));
    const out = [];
    for (let at = 0; at < pages.length; at += 1) {
      if (!fetched[at].ok) throw fetched[at].error;
      const response = fetched[at].value;
      if (response.status !== 200) throw storeRefusal(response.status, "listing", signedMs);
      const listing = parseListVersions(response.body);
      if (listing === null) throw storeFailure("unreachable", "listing:body");
      const letter = pages[at].prefix;
      const keys = [];
      const tails = new Set();
      for (const version of listing.versions) {
        const parsed = parseEntryKey(version.key, letter);
        if (parsed === null || tails.has(parsed.tail)) continue;
        tails.add(parsed.tail);
        keys.push(parsed);
      }
      out.push({
        letter: letter, keys: keys, tails: tails, truncated: listing.truncated && listing.nextKeyMarker !== null,
        next_key_marker: listing.nextKeyMarker === null ? "" : listing.nextKeyMarker,
        next_version_id_marker: listing.nextVersionIdMarker === null ? "" : listing.nextVersionIdMarker,
      });
    }
    return out;
  }

  /** The bodies of entries of format 3 from the backend (LOG_BODIES_PATH; LOG_BODY_KEYS keys at
   *  most): a table from key to {body, sig}, or to null for a key the backend reports missing. A
   *  key that is neither among the entries of the answer nor among its missing keys is absent
   *  from the table, whether the answer reports it as unread or does not name it: the backend
   *  answers the keys in the order of the request and may end before the last. The backend reads
   *  the objects in the region of the store and hands them on; a body is checked against the
   *  body_hash of its key and the signature of its node, so the backend cannot hand out another
   *  one. Throws a store failure. */
  async function readBodies(turn, keys) {
    let answer = null;
    try {
      answer = (await api(turn, "POST", LOG_BODIES_PATH, { keys: keys }, null, LOG_API_TIMEOUT_MS)).json;
    } catch (error) {
      throw backendFailure(error, "bodies");
    }
    const wanted = new Set(keys);
    const out = new Map();
    for (const item of Array.isArray(answer.entries) ? answer.entries : []) {
      if (item !== null && typeof item === "object" && wanted.has(item.key) &&
          typeof item.body === "string" && typeof item.sig === "string") {
        out.set(item.key, { body: item.body, sig: item.sig });
      }
    }
    for (const key of Array.isArray(answer.missing) ? answer.missing : []) {
      if (wanted.has(key) && !out.has(key)) out.set(key, null);
    }
    return out;
  }

  /** The node documents of nodes from the backend (LOG_DOCUMENTS_PATH; LOG_DOCUMENT_NODES nodes
   *  at most): {signedMs, documents, listings}. documents is a table from node id to {document,
   *  registry} for the nodes the answer hands a document out for (registry: its origin is
   *  node_registry, a document the backend kept of the node; otherwise it is the object the node
   *  wrote to the store). A node the answer reports as missing or unread, or does not name, is
   *  not in that table: the program has no document of it, whatever the answer calls that.
   *  listings is a table from node id to the address the answer gives for the listing of the
   *  versions of the node document of that node, signed at signedMs. A node document proves
   *  itself (verifyNodeDocument), so the backend may hand it on; that a node has none is read from
   *  the store (learnNodes). Throws a store failure. */
  async function readDocuments(turn, nodes) {
    let answer = null;
    try {
      answer = (await api(turn, "POST", LOG_DOCUMENTS_PATH, { nodes: nodes }, null, LOG_API_TIMEOUT_MS)).json;
    } catch (error) {
      throw backendFailure(error, "documents");
    }
    const wanted = new Set(nodes);
    const out = { signedMs: native.nowMs(), documents: new Map(), listings: new Map() };
    for (const item of Array.isArray(answer.documents) ? answer.documents : []) {
      if (item !== null && typeof item === "object" && wanted.has(item.node) && !out.documents.has(item.node) &&
          item.document !== null && typeof item.document === "object") {
        out.documents.set(item.node, { document: item.document, registry: item.origin === "node_registry" });
      }
    }
    for (const item of Array.isArray(answer.listings) ? answer.listings : []) {
      if (item !== null && typeof item === "object" && wanted.has(item.node) && !out.listings.has(item.node) &&
          typeof item.url === "string") {
        out.listings.set(item.node, item.url);
      }
    }
    return out;
  }

  // ---- What the node documents said (log.nodes) ----

  /** The kept judgements of nodes: {node: {m, p, r, f, c}} (the digest of the measurement, the
   *  platform, the release, the time first seen, the time a contradiction of its signatures was
   *  found; 0 for none). */
  function loadNodes() {
    const kept = storedObject(STORE_NODES);
    const nodes = Object.create(null);
    for (const id of Object.keys(kept)) {
      const value = kept[id];
      if (!NODE_ID.test(id) || value === null || typeof value !== "object") continue;
      nodes[id] = {
        m: typeof value.m === "string" ? value.m : "", p: value.p === "local" ? "local" : "nitro",
        r: typeof value.r === "string" ? value.r : "", f: whole(value.f), c: whole(value.c),
      };
    }
    return nodes;
  }

  /** Writes the kept judgements. Above LOG_NODES_KEPT nodes, the nodes seen first leave first (a
   *  node with a contradiction stays). */
  function saveNodes(nodes) {
    const ids = Object.keys(nodes);
    if (ids.length > LOG_NODES_KEPT) {
      ids.sort(function (x, y) { return nodes[x].f - nodes[y].f; });
      for (const id of ids) {
        if (Object.keys(nodes).length <= LOG_NODES_KEPT) break;
        if (nodes[id].c === 0) delete nodes[id];
      }
    }
    storeJson(STORE_NODES, nodes);
  }

  /** What this device knows of the node id: {state, release, platform, format, measure}, or null
   *  for a node it has no judgement of. state is accepted for a node this device verified and
   *  handed a grant to, and for a node whose document verified with a measurement of the accepted
   *  lists (or of platform local, in a build that takes local nodes); unaccepted for a node whose
   *  document verified with a measurement no list of this program has. The lists are read at every
   *  call: a program that lists a release accepts the nodes an earlier program kept as unaccepted. */
  function nodeVerdict(grants, nodes, id) {
    const kept = nodes[id];
    if (kept !== undefined && kept.p === "nitro" && kept.m !== "") {
      const build = buildOfMeasure(kept.m);
      return {
        state: build === undefined ? "unaccepted" : "accepted", release: kept.r, platform: "nitro",
        format: build === undefined ? 3 : logFormatOf(build.release), measure: kept.m,
      };
    }
    const granted = grants[id];
    if (granted !== undefined) {
      return {
        state: "accepted", release: granted.release, platform: granted.platform,
        format: logFormatOf(granted.release), measure: "",
      };
    }
    if (kept !== undefined && kept.p === "local" && localAccepted()) {
      return { state: "accepted", release: kept.r, platform: "local", format: logFormatOf(kept.r), measure: "" };
    }
    return null;
  }

  // ---- Format 1 and format 2: the chains in the bucket the binding names ----
  //
  // A node of a release before LOG_FORMAT_3_FROM wrote one chain per account under the prefix
  // v1/accounts/{user_id}/{node}/. This program reads those chains for two things only: to show
  // their entries on the log screen, and to find a transfer of the delegation that such a node
  // made to another node (followLegacy). It verifies an entry by the signature of the node whose
  // id its prefix names and by the body hash of its key, and opens it with the key of this
  // account. It reads no head, verifies no chain equation, and judges neither an empty seq nor a
  // node no grant explains.

  // The tail of an object key under the node prefix (docs/protocol.md 7.6). Format 2 (the releases
  // from v2.0.0 to the last before LOG_FORMAT_3_FROM): the seq as digits, the time_ms of the entry
  // as digits, the kind letter (c: a control entry, u: a use entry), the count of events as three
  // digits, the key_id, the base64url of the body hash and of the entry hash. Format 1 (the
  // releases before v2.0.0): the seq as digits and the base64url of the entry hash.
  const STORE_KEY_V2 = new RegExp(
    "^(\\d{" + LOG_STORE_SEQ_DIGITS + "})-(\\d{" + LOG_STORE_TIME_DIGITS + "})-([cu])-(\\d{3})-" +
    "([0-9a-f]{16})-([A-Za-z0-9_-]{43})-([A-Za-z0-9_-]{43})$");
  const STORE_KEY_V1 = new RegExp("^(\\d{" + LOG_STORE_SEQ_DIGITS + "})-([A-Za-z0-9_-]{43})$");

  /** The seq of an object key as LOG_STORE_SEQ_DIGITS digits with leading zeros (the order of the
   *  keys is the order of seq). */
  function seqDigits(seq) {
    return String(seq).padStart(LOG_STORE_SEQ_DIGITS, "0");
  }

  /** The parts an object key under the node prefix names: {format: 2, seq, time_ms, kind, count,
   *  key_id, body_hash} for a key of format 2 (seq 1 or more, count 1 to LOG_ENTRY_EVENTS),
   *  {format: 1, seq} for a key of format 1, null for any other key. */
  function parseStoreKey(key, prefix) {
    if (typeof key !== "string" || key.slice(0, prefix.length) !== prefix) return null;
    const tail = key.slice(prefix.length);
    const v2 = STORE_KEY_V2.exec(tail);
    if (v2 !== null) {
      const seq = Number(v2[1]);
      const timeMs = Number(v2[2]);
      const count = Number(v2[4]);
      if (!Number.isSafeInteger(seq) || seq < 1 || !Number.isSafeInteger(timeMs) ||
          count < 1 || count > LOG_ENTRY_EVENTS) {
        return null;
      }
      return { format: 2, seq: seq, time_ms: timeMs, kind: v2[3], count: count, key_id: v2[5], body_hash: v2[6] };
    }
    const v1 = STORE_KEY_V1.exec(tail);
    if (v1 === null) return null;
    const seq = Number(v1[1]);
    return Number.isSafeInteger(seq) && seq > 0 ? { format: 1, seq: seq } : null;
  }

  /** The key marker of the listing of one node after the seq afterSeq: every key of that seq sorts
   *  before it. */
  function listingMarker(id, afterSeq) {
    return accountPrefix() + id + "/" + seqDigits(afterSeq) + "-~";
  }

  /** The listing addresses of the bucket of format 1 and format 2 in one request
   *  (LOG_LISTINGS_PATH): the node discovery listing of the account prefix (discovery) and the
   *  listing of every node of targets ({node, key_marker, version_id_marker}; LEGACY_LISTING_NODES
   *  at most) from its marker. Every address is checked (listingUrlAccepted); an address that is
   *  not the one requested and a missing address reject the whole response. Returns {signedMs,
   *  discovery: url | null, nodes: [url]} in the order of targets. Throws a store failure. */
  async function legacyAddresses(turn, discovery, targets) {
    let response = null;
    try {
      response = (await api(
        turn, "POST", LOG_LISTINGS_PATH, { discovery: discovery, nodes: targets }, null, LOG_API_TIMEOUT_MS)).json;
    } catch (error) {
      throw backendFailure(error, "listings");
    }
    const out = { signedMs: native.nowMs(), discovery: null, nodes: [] };
    if (discovery) {
      const item = response.discovery;
      const expected = { prefix: accountPrefix(), nodes: true, keyMarker: null, versionIdMarker: null };
      if (item === null || typeof item !== "object" || !listingUrlAccepted(item.list_url, expected)) {
        throw storeFailure("blocked", "listings:url");
      }
      out.discovery = item.list_url;
    }
    const listed = Array.isArray(response.nodes) ? response.nodes : [];
    if (listed.length !== targets.length) throw storeFailure("blocked", "listings:url");
    for (let at = 0; at < targets.length; at += 1) {
      const wanted = targets[at];
      const item = listed[at];
      const expected = {
        prefix: accountPrefix() + wanted.node + "/", nodes: false,
        keyMarker: wanted.key_marker, versionIdMarker: wanted.version_id_marker,
      };
      if (item === null || typeof item !== "object" || item.node !== wanted.node ||
          !listingUrlAccepted(item.list_url, expected)) {
        throw storeFailure("blocked", "listings:url");
      }
      out.nodes.push(item.list_url);
    }
    return out;
  }

  /** One listing of the bucket of format 1 and format 2 through an address the backend signed at
   *  signedMs: the parsed listing. Throws a store failure. */
  async function legacyListing(turn, url, signedMs) {
    const response = await storeGate.run(function () { return fetchStore(turn, url, "chain"); });
    if (response.status !== 200) throw storeRefusal(response.status, "chain", signedMs);
    const parsed = parseListVersions(response.body);
    if (parsed === null) throw storeFailure("unreachable", "chain:body");
    return parsed;
  }

  /** The listings of several chains in one stage: targets are {node, key_marker,
   *  version_id_marker}; the addresses are requested LEGACY_LISTING_NODES per request, the
   *  requests and then the listings sent together. Returns the settled outcomes in the order of
   *  targets ({ok, value: listing} or {ok: false, error}). */
  async function legacyListings(turn, targets) {
    const batches = [];
    for (let at = 0; at < targets.length; at += LEGACY_LISTING_NODES) {
      batches.push(targets.slice(at, at + LEGACY_LISTING_NODES));
    }
    const addressed = await stage(batches.map(function (batch) { return legacyAddresses(turn, false, batch); }));
    const reads = [];
    for (let at = 0; at < batches.length; at += 1) {
      const outcome = addressed[at];
      for (let i = 0; i < batches[at].length; i += 1) {
        reads.push(outcome.ok
          ? legacyListing(turn, outcome.value.nodes[i], outcome.value.signedMs)
          : Promise.reject(outcome.error));
      }
    }
    return stage(reads);
  }

  /** The nodes of this account in the bucket of format 1 and format 2: the common prefixes of the
   *  account prefix (the node discovery listing), LEGACY_DISCOVERY_PAGES pages at most. A prefix
   *  that does not name a node id is left out. Throws a store failure. */
  async function discoverLegacyNodes(turn) {
    const prefix = accountPrefix();
    const nodes = [];
    let keyMarker = null;
    let versionIdMarker = null;
    for (let page = 0; page < LEGACY_DISCOVERY_PAGES; page += 1) {
      let url = null;
      let signedMs = 0;
      if (page === 0) {
        const addresses = await legacyAddresses(turn, true, []);
        url = addresses.discovery;
        signedMs = addresses.signedMs;
      } else {
        let listing = null;
        const query = { nodes: "1", key_marker: keyMarker };
        if (versionIdMarker !== null) query.version_id_marker = versionIdMarker;
        try {
          listing = (await api(turn, "GET", "/api/secure/log/store", null, query, LOG_API_TIMEOUT_MS)).json;
        } catch (error) {
          throw backendFailure(error, "listings");
        }
        signedMs = native.nowMs();
        const expected = { prefix: prefix, nodes: true, keyMarker: keyMarker, versionIdMarker: versionIdMarker };
        if (!listingUrlAccepted(listing.list_url, expected)) throw storeFailure("blocked", "listings:url");
        url = listing.list_url;
      }
      const listing = await legacyListing(turn, url, signedMs);
      for (const common of listing.prefixes) {
        if (common.slice(0, prefix.length) !== prefix || common.slice(-1) !== "/") continue;
        const id = common.slice(prefix.length, -1);
        if (NODE_ID.test(id) && nodes.indexOf(id) < 0) nodes.push(id);
      }
      if (!listing.truncated || listing.nextKeyMarker === null) break;
      keyMarker = listing.nextKeyMarker;
      versionIdMarker = listing.nextVersionIdMarker;
    }
    return nodes;
  }

  /** The signed values of object versions of the bucket of format 1 and format 2: wanted are
   *  {key, versionId} (LOG_STORE_OBJECTS at most). The addresses come from the backend in one
   *  request (LOG_OBJECTS_PATH), each checked (objectUrlAccepted), and the objects from the store
   *  (through the store gate). Returns a table from key + "\n" + versionId to {body, sig}, or to
   *  null for a version the store does not hold or that is no signed value. Throws a store
   *  failure. */
  async function legacyObjects(turn, wanted) {
    const out = new Map();
    if (wanted.length === 0) return out;
    let signed = null;
    try {
      signed = (await api(turn, "POST", LOG_OBJECTS_PATH, {
        objects: wanted.map(function (item) { return { key: item.key, version_id: item.versionId }; }),
      }, null, LOG_API_TIMEOUT_MS)).json;
    } catch (error) {
      throw backendFailure(error, "objects");
    }
    const signedMs = native.nowMs();
    const urls = new Map();
    for (const item of Array.isArray(signed.objects) ? signed.objects : []) {
      if (item === null || typeof item !== "object" ||
          !objectUrlAccepted(item.url, item.key, item.version_id)) {
        throw storeFailure("blocked", "objects:url");
      }
      urls.set(item.key + "\n" + item.version_id, item.url);
    }
    for (const item of wanted) {
      if (!urls.has(item.key + "\n" + item.versionId)) throw storeFailure("blocked", "objects:url");
    }
    const names = wanted.map(function (item) { return item.key + "\n" + item.versionId; });
    const fetched = await pooled(names, function (name) { return fetchStore(turn, urls.get(name), "object"); });
    for (let at = 0; at < names.length; at += 1) {
      if (!fetched[at].ok) throw fetched[at].error;
      const response = fetched[at].value;
      if (response.status === 404) {
        out.set(names[at], null);
        continue;
      }
      if (response.status !== 200) throw storeRefusal(response.status, "object", signedMs);
      let value = null;
      try {
        value = JSON.parse(response.body);
      } catch (error) {
        value = null;
      }
      const shaped = value !== null && typeof value === "object" &&
        typeof value.body === "string" && typeof value.sig === "string";
      out.set(names[at], shaped ? { body: value.body, sig: value.sig } : null);
    }
    return out;
  }

  /** Checks one signed object version of a chain of format 1 or format 2 against the parts of its
   *  key: the signature of the node id of its prefix, the account and the seq, and, for format 2,
   *  the key_id, count, kind and time_ms of the key and the body hash of the key. The plaintext is
   *  opened when the key_id is ours: one control event for a control entry, use events for a use
   *  entry. Returns {format, seq, body, time_ms, ours, events} (events null when the key_id is not
   *  ours) or null for an object that is not that entry. */
  function checkLegacyEntry(signed, id, parts, keys) {
    let body = null;
    try {
      body = parts.format === 2
        ? openSigned(signed, id, purposeV2("log-entry") + "\n", 2)
        : openSigned(signed, id, purpose("log-entry") + "\n", 1);
    } catch (error) {
      return null;
    }
    if (body.node !== id || body.user_id !== userId() || body.seq !== parts.seq) return null;
    if (parts.format === 2) {
      let hashed = false;
      try {
        hashed = sameBytes(native.sha256(encode(decode(signed.body))), parts.body_hash);
      } catch (error) {
        hashed = false;
      }
      if (!hashed || body.key_id !== parts.key_id || body.count !== parts.count ||
          body.kind !== parts.kind || body.time_ms !== parts.time_ms) {
        return null;
      }
    }
    const ours = body.key_id === keys.keyId;
    let events = null;
    if (ours) {
      try {
        events = parts.format === 2 ? openEvents(body, keys, 2) : [openEvent(body, keys)];
      } catch (error) {
        return null;
      }
      if (parts.format === 2) {
        const allowed = parts.kind === "c" ? CONTROL_EVENTS : USE_EVENTS;
        if (parts.kind === "c" && events.length !== 1) return null;
        if (!events.every(function (event) { return allowed.indexOf(event.t) >= 0; })) return null;
      }
    }
    return {
      format: parts.format, seq: parts.seq, body: body, time_ms: whole(body.time_ms), ours: ours, events: events,
    };
  }

  // ---- The chains this device follows (log.legacy) ----

  /** The kept state of the chains of format 1 and format 2: {nodes: {node: {seq, time_ms,
   *  until_ms, closed, read_ms}}, waiting: {node: {until_ms, time_ms}}} (read_ms: the time a
   *  round last listed the chain). seq is the seq up to which the
   *  control entries of the chain were read (the verification point of the program before v43 for
   *  a node its ledger held), time_ms the time of the entry there (0 when it is not known),
   *  until_ms the latest time the node can hold a grant this device knows of, and closed whether
   *  the chain is read no more. waiting holds the receiving nodes of transfers of the delegation
   *  whose documents this device has still to judge (LEGACY_ROUND_BODIES at most): until_ms as
   *  for a chain, and time_ms the time of the latest event that names the node. */
  function loadLegacy() {
    const kept = storedObject(STORE_LEGACY);
    const legacy = { nodes: Object.create(null), waiting: Object.create(null) };
    const nodes = kept.nodes !== null && typeof kept.nodes === "object" ? kept.nodes : {};
    for (const id of Object.keys(nodes)) {
      const value = nodes[id];
      if (!NODE_ID.test(id) || value === null || typeof value !== "object") continue;
      legacy.nodes[id] = {
        seq: whole(value.seq), time_ms: whole(value.time_ms), until_ms: whole(value.until_ms),
        closed: value.closed === true, read_ms: whole(value.read_ms),
      };
    }
    const waiting = kept.waiting !== null && typeof kept.waiting === "object" ? kept.waiting : {};
    for (const id of Object.keys(waiting).slice(0, LEGACY_ROUND_BODIES)) {
      const value = waiting[id];
      if (!NODE_ID.test(id) || value === null || typeof value !== "object") continue;
      legacy.waiting[id] = { until_ms: whole(value.until_ms), time_ms: whole(value.time_ms) };
    }
    return legacy;
  }

  /** Writes the kept state. Above 2 * LEGACY_NODES chains, the closed chains with the earliest
   *  end leave first. */
  function saveLegacy(legacy) {
    const ids = Object.keys(legacy.nodes);
    if (ids.length > 2 * LEGACY_NODES) {
      const closed = ids.filter(function (id) { return legacy.nodes[id].closed; });
      closed.sort(function (x, y) { return legacy.nodes[x].until_ms - legacy.nodes[y].until_ms; });
      for (const id of closed) {
        if (Object.keys(legacy.nodes).length <= 2 * LEGACY_NODES) break;
        delete legacy.nodes[id];
      }
    }
    storeJson(STORE_LEGACY, legacy);
  }

  // ---- The round: one reading and judging of the log of the account (docs/protocol.md 7.4) ----
  //
  // What makes the log complete is not something a round verifies: a node writes the entry of an
  // act to the log store and acts only after the store confirmed it, and no object version of the
  // store can be deleted for 365 days. So the listing of the prefix of an account, read from the
  // store itself, names every act that took place with the key of the account. A round reads that
  // listing and judges four things, which hold in a situation that is a problem and in no other:
  //   A1  the key of the account went to a node of a release this program does not accept
  //   A2  the signatures of a node that passed attestation contradict each other
  //   A3  the operator domain has been holding the reads back for LOG_BLOCKED_MS
  //   A4  an entry this device saw left the listing within its retention
  // A round reads the control entries only (grants, revocations, connections, transfers of the
  // delegation): the use entries are read by the log screen. A read that was held back, whoever
  // made it (a round, the first page of the screen, a later page), is kept (log.withheld: the key
  // of an entry whose document or body was held back, the key of the screen that an answer of
  // the bodies did not reach, the listing page of the screen that was held back, and the reads
  // the screen makes of the bucket of format 1 and format 2: the node discovery listing, the
  // listing of a chain, the object versions of an entry) and made again by every round, in
  // front of its other reads, until it is no longer held back. So a round that reads the control
  // entries alone does not end a count of rounds held back while a read the screen made stays
  // held back. What a round reads that way is kept for the screen (log.recovered), which takes
  // it from there: the backend gains nothing by answering the rounds and not the screen, because
  // an answer to a round is an answer the user sees. Two kinds of listings cannot be kept in a
  // form that answers every later read of the screen (a later page of format 3, the listing of a
  // chain); what is held back of them is noted by the reads of the screen themselves
  // (log.denied), and those reads mark the log as the count of the rounds does. And a round that
  // keeps ending with more to read than a round reads is, from LOG_UNFINISHED_ROUNDS such rounds
  // in a row on, a round whose reads are held back.
  //
  // What is an entry is decided by the listing and by the node documents. The operator domain can
  // write objects under any key of the store, so a key of the listing is the key of an entry only
  // when its node has a node document that verifies. A document proves itself and the backend
  // hands it on; that a node has none is not something the backend can state, so the program
  // reads it from the store: the listing of the versions under the key of that node document,
  // asked for after the listing that named the key. A node writes its document before it takes a
  // user key and writes no entry without it, so a key the store listed while it held no version
  // of the document of its node is no entry of a node. That judgement covers the keys the
  // listings before it named and no key a later listing names: it is made again by every read
  // and is not kept by node.

  /** The digest by which the program remembers that it judged a key: 9 bytes of its SHA-256. */
  function keyDigest(key) {
    return encode(decode(native.sha256(encode(utf8(key)))).subarray(0, 9));
  }

  /** The time of the entry a tail of a key of format 3 names (its first 13 characters). */
  function tailTime(tail) {
    return RTIME_MAX - Number(String(tail).slice(0, 13));
  }

  /** Everything this device keeps of the log of the account, read from the program store. */
  function loadLog() {
    const strings = function (key, limit) {
      const kept = storedJson(key, []);
      return (Array.isArray(kept) ? kept : []).filter(function (item) {
        return typeof item === "string" && item !== "";
      }).slice(0, limit);
    };
    const blocked = storedObject(STORE_BLOCKED);
    const resume = storedJson(STORE_RESUME, null);
    const seen = strings(STORE_SEEN, LOG_SEEN_KEYS);
    const missing = storedJson(STORE_MISSING, []);
    const cursor = native.storeGet(STORE_CURSOR);
    return {
      grants: loadGrants(), nodes: loadNodes(), unaccepted: storedObject(STORE_UNACCEPTED),
      blocked: { first_ms: whole(blocked.first_ms), count: whole(blocked.count) },
      sample: strings(STORE_SAMPLE, LOG_SAMPLE_KEYS), seen: { list: seen, set: new Set(seen) },
      missing: (Array.isArray(missing) ? missing : []).filter(function (item) {
        return item !== null && typeof item === "object" && typeof item.key === "string";
      }).slice(0, LOG_MISSING_KEYS),
      legacy: loadLegacy(), round: storedObject(STORE_ROUND), cursor: cursor === null ? "" : cursor,
      resume: resume !== null && typeof resume === "object" && typeof resume.key_marker === "string" ? {
        key_marker: resume.key_marker,
        version_id_marker: typeof resume.version_id_marker === "string" ? resume.version_id_marker : "",
        top: typeof resume.top === "string" ? resume.top : "",
        until: typeof resume.until === "string" ? resume.until : "", tail: resume.tail === true,
      } : null,
    };
  }

  /** Remembers that a key was judged. Above LOG_SEEN_KEYS digests the ones added first leave. */
  function markSeen(log, digest) {
    if (log.seen.set.has(digest)) return;
    log.seen.set.add(digest);
    log.seen.list.push(digest);
    if (log.seen.list.length > LOG_SEEN_KEYS) log.seen.set.delete(log.seen.list.shift());
  }

  /** Notes a measurement no list of this program has (digest: the digest of the measurement, or
   *  "node:" and a node id when only the node is known). held says that the key of this account
   *  went to a node of it. The time it was first seen is kept. */
  function noteUnaccepted(log, digest, release, node, held) {
    let item = log.unaccepted[digest];
    if (item === null || typeof item !== "object") {
      item = { first_ms: native.nowMs(), release: String(release || "").slice(0, 64), held: false, node: node };
      log.unaccepted[digest] = item;
    }
    if (held) item.held = true;
  }

  /** Notes that the signatures of the node id contradict each other (A2). */
  function noteConflict(log, id, verdict) {
    let kept = log.nodes[id];
    if (kept === undefined) {
      kept = { m: verdict.measure, p: verdict.platform, r: verdict.release, f: native.nowMs(), c: 0 };
      log.nodes[id] = kept;
    }
    if (kept.c === 0) kept.c = native.nowMs();
  }

  /** Notes a failed read of a round: what the failure means for the round, and the detail of the
   *  first one for the report. A failure that is not one of the log (the bridge closed, a defect)
   *  is thrown, and so is every failure once the time of the turn has passed: a failure that
   *  arrives then says nothing of the backend (a round ends its reading there: runRound). */
  function noteFailure(turn, run, failure) {
    if (!isStoreFailure(failure) || !(turnLeft(turn) > 0)) throw failure;
    // A backend without the store that was asked for holds nothing back.
    if (failure.kind === "absent") return;
    if (run.detail === "") run.detail = failure.detail.slice(0, 64);
    if (failure.kind === "blocked") run.blocked = true;
    else if (failure.kind === "silent") run.silent = true;
    else if (failure.kind === "unreachable") run.unreachable = true;
  }

  /** The failure of a request for the bodies or the node documents of keys the listing of the
   *  store named: a backend that answers that it has no such route or no such store (absent) holds
   *  them back, because the listing came from that store. Any other failure is itself. */
  function heldBack(failure) {
    if (isStoreFailure(failure) && failure.kind === "absent") return storeFailure("blocked", failure.detail);
    return failure;
  }

  /** Reads an object key as the key of an entry of format 3 of this account under either prefix
   *  (parseEntryKey); null for any other key. */
  function parseAccountKey(key) {
    const control = parseEntryKey(key, "c");
    return control !== null ? control : parseEntryKey(key, "u");
  }

  /** The reads that were held back and that this device keeps for the rounds to make again
   *  (log.withheld): {keys, shown, pages, objects, chains, nodes}. keys are the object keys of
   *  entries of format 3 whose document or body was held back, or that an answer of the bodies
   *  to the log screen did not reach (LOG_WITHHELD_KEYS at most); shown are those of them that a
   *  read of the log screen asked for (what a round reads under such a key is kept for the
   *  screen: log.recovered); pages are the listing pages of format 3 of the screen that were
   *  held back (LOG_WITHHELD_PAGES at most), each the time below which the page of the two
   *  prefixes was asked for (0: the pages that begin the two listings). The rest are reads of the
   *  bucket of format 1 and format 2 that the screen made: objects are the entries whose object
   *  versions were held back, each the list of the versions [key, version id] the screen asked
   *  for under one seq of one chain (LOG_WITHHELD_OBJECTS at most); chains are the listings of
   *  chains that were held back, each [node, after, below] (the seq the listing began after, and
   *  the seq it was read below, 0 for none; LOG_WITHHELD_CHAINS at most); nodes says that the
   *  node discovery listing was held back. watch_ms is the time until which every round of a
   *  synchronization reads the listing pages that begin the two listings for the screen (0: no
   *  such time): from the read of the screen that was held back to LOG_WATCH_MS after it, or to
   *  the read the screen makes itself. */
  function loadWithheld() {
    const kept = storedObject(STORE_WITHHELD);
    const keys = (Array.isArray(kept.keys) ? kept.keys : []).filter(function (key) {
      return typeof key === "string" && key !== "";
    }).slice(0, LOG_WITHHELD_KEYS);
    const prefix = accountPrefix();
    const objects = [];
    for (const group of Array.isArray(kept.objects) ? kept.objects : []) {
      const versions = (Array.isArray(group) ? group : []).filter(function (version) {
        return Array.isArray(version) && typeof version[0] === "string" && version[0].slice(0, prefix.length) === prefix &&
          typeof version[1] === "string";
      }).slice(0, 2);
      if (versions.length > 0 && objects.length < LOG_WITHHELD_OBJECTS) objects.push(versions);
    }
    return {
      keys: keys,
      shown: (Array.isArray(kept.shown) ? kept.shown : []).filter(function (key) { return keys.indexOf(key) >= 0; }),
      pages: (Array.isArray(kept.pages) ? kept.pages : []).filter(function (before) {
        return Number.isSafeInteger(before) && before >= 0;
      }).slice(0, LOG_WITHHELD_PAGES),
      objects: objects,
      chains: (Array.isArray(kept.chains) ? kept.chains : []).filter(function (chain) {
        return Array.isArray(chain) && typeof chain[0] === "string" && NODE_ID.test(chain[0]) &&
          Number.isSafeInteger(chain[1]) && chain[1] >= 0 && Number.isSafeInteger(chain[2]) && chain[2] >= 0;
      }).slice(0, LOG_WITHHELD_CHAINS),
      nodes: kept.nodes === true,
      watch_ms: whole(kept.watch_ms) > native.nowMs() ? whole(kept.watch_ms) : 0,
    };
  }

  /** The two listing pages of the screen below the time before (0: from the start of the two
   *  listings), as a request of readListings. */
  function screenPages(before) {
    return ["c", "u"].map(function (letter) {
      return { prefix: letter, key_marker: before === 0 ? "" : pageMarker(letter, before), version_id_marker: "" };
    });
  }

  /** Whether a failed read of the log is one the rounds make again: the backend refused it or did
   *  not answer it, an address was not the one of the request, or the store refused an address. A
   *  read that failed with the network of the device or with the store is not kept: the next read
   *  of the same kind makes it. */
  function heldKind(failure) {
    return isStoreFailure(failure) && (failure.kind === "blocked" || failure.kind === "silent");
  }

  /** Whether the withheld reads hold a read the rounds have still to make again (the page the
   *  rounds watch for the screen alone is none: it is read when a round runs). */
  function withheldDue(held) {
    return held.keys.length > 0 || held.pages.length > 0 || held.objects.length > 0 || held.chains.length > 0 || held.nodes;
  }

  /** The name of an entry of a chain whose object versions were held back: the node id and the
   *  seq the key of its first version names ("" for a key that names none). */
  function objectName(versions) {
    const rest = versions[0][0].slice(accountPrefix().length);
    const id = rest.slice(0, 43);
    const parts = parseStoreKey(versions[0][0], accountPrefix() + id + "/");
    return parts === null || !NODE_ID.test(id) ? "" : id + ":" + parts.seq;
  }

  /** Writes the withheld reads after a read (run: withheld and settled, the keys it found held
   *  back and the keys whose read came to a judgement; shown, the keys among the former that the
   *  log screen asked for; pagesHeld and pagesRead, the same for listing pages; and, when the
   *  read made them, objectsHeld and objectsRead (the entries of chains, as lists of versions,
   *  and the names of the entries read), chainsHeld and chainsRead (the listings of chains, and
   *  their names node:after:below), nodesHeld and nodesRead (the node discovery listing)): what
   *  the device kept without what that read settled, then what that read found held back, up to
   *  the limits. A key older than the retention of the store leaves. The kept value is read at
   *  the call and written in the same step: a round and a read of the screen may end in either
   *  order. */
  function saveWithheld(run) {
    const kept = loadWithheld();
    const horizon = native.nowMs() - LOG_RETENTION_DAYS * DAY_MS;
    const keys = [];
    for (const key of kept.keys.concat(Array.from(run.withheld))) {
      if (run.settled.has(key) || keys.indexOf(key) >= 0 || keys.length >= LOG_WITHHELD_KEYS) continue;
      const parsed = parseAccountKey(key);
      if (parsed === null || parsed.time_ms < horizon) continue;
      keys.push(key);
    }
    const shown = keys.filter(function (key) { return kept.shown.indexOf(key) >= 0 || run.shown.has(key); });
    const pages = [];
    for (const before of kept.pages.concat(Array.from(run.pagesHeld))) {
      if (run.pagesRead.has(before) || pages.indexOf(before) >= 0 || pages.length >= LOG_WITHHELD_PAGES) continue;
      pages.push(before);
    }
    const objects = [];
    const named = new Set();
    for (const versions of kept.objects.concat(run.objectsHeld === undefined ? [] : run.objectsHeld)) {
      const name = objectName(versions);
      if (name === "" || named.has(name) || objects.length >= LOG_WITHHELD_OBJECTS) continue;
      if (run.objectsRead !== undefined && run.objectsRead.has(name)) continue;
      named.add(name);
      objects.push(versions.slice(0, 2));
    }
    const chains = [];
    const listed = new Set();
    for (const chain of kept.chains.concat(run.chainsHeld === undefined ? [] : run.chainsHeld)) {
      const name = chain.join(":");
      if (listed.has(name) || chains.length >= LOG_WITHHELD_CHAINS) continue;
      if (run.chainsRead !== undefined && run.chainsRead.has(name)) continue;
      listed.add(name);
      chains.push(chain);
    }
    const nodes = (kept.nodes || run.nodesHeld === true) && run.nodesRead !== true;
    // The time until which the rounds read the first listing pages for the screen: it begins
    // anew when that read is held back from the screen, and ends when the screen makes it.
    const watch = run.pageSeen === true ? 0 : run.pageWatch === true ? native.nowMs() + LOG_WATCH_MS : kept.watch_ms;
    // The stored value names the reads of the bucket of format 1 and format 2 only when it holds
    // some.
    const value = function (held) {
      const stored = { keys: held.keys, shown: held.shown, pages: held.pages };
      if (held.objects.length > 0) stored.objects = held.objects;
      if (held.chains.length > 0) stored.chains = held.chains;
      if (held.nodes) stored.nodes = true;
      if (held.watch_ms > 0) stored.watch_ms = held.watch_ms;
      return stored;
    };
    const next = value({
      keys: keys, shown: shown, pages: pages, objects: objects, chains: chains, nodes: nodes, watch_ms: watch,
    });
    if (JSON.stringify(next) === JSON.stringify(value(kept))) return;
    const empty = keys.length === 0 && pages.length === 0 && objects.length === 0 && chains.length === 0 && !nodes &&
      watch === 0;
    storeJson(STORE_WITHHELD, empty ? null : next);
  }

  /** Whether what this device kept says that its environment has a store of format 3: it handed
   *  a grant to a node of a release that writes format 3, or it read that store (a listing of it
   *  named the keys it keeps). A listing page that was held back says nothing of that. */
  function storeKnown(log, kept) {
    return log.cursor !== "" || log.seen.list.length > 0 || log.resume !== null || kept.keys.length > 0 ||
      Object.keys(log.grants).some(function (id) { return logFormatOf(log.grants[id].release) === 3; });
  }

  /** Whether a string is 96 lower-case hexadecimal characters (one PCR). */
  function hex96(value) {
    return typeof value === "string" && /^[0-9a-f]{96}$/.test(value);
  }

  /** Judges the event of a transfer of the delegation that an accepted node wrote for the key of
   *  this account (grant_transferred_out): the measurement the event names, or, for an event
   *  without one, what this device knows of the receiving node. A measurement no list of this
   *  program has is noted as holding the key (A1). Returns the id of a receiving node this device
   *  has no judgement of (the caller asks for its document), or null. */
  function judgeTransfer(log, event) {
    const to = typeof event.to === "string" && NODE_ID.test(event.to) ? event.to : "";
    if (hex96(event.pcr0) && hex96(event.pcr1) && hex96(event.pcr2)) {
      const measurement = { pcr0: event.pcr0, pcr1: event.pcr1, pcr2: event.pcr2 };
      if (listedBuild(measurement) === undefined) {
        noteUnaccepted(log, measureOf(measurement), event.release, to, true);
      }
      return null;
    }
    if (to === "") return null;
    const verdict = nodeVerdict(log.grants, log.nodes, to);
    if (verdict === null) return to;
    if (verdict.state === "unaccepted") noteUnaccepted(log, verdict.measure, verdict.release, to, true);
    return null;
  }

  /** Asks for the node documents of ids (LOG_DOCUMENT_NODES per request, budget.documents requests
   *  at most, sent together) and keeps what the documents that verify say in log.nodes. kind says
   *  whose nodes they are:
   *    key       the nodes of keys a listing of format 3 named, read before this call
   *    receiver  the receiving nodes of transfers an entry of format 3 names without a measurement
   *    chain     the receiving nodes of transfers a chain of format 2 names
   *  Returns a table from node id to {state, detail} for the nodes that got no judgement:
   *    missing, rejected  the backend handed out no document, or one that does not verify
   *    absent    (key) the same, and the store holds no version of the node document of the node:
   *              the listing of the versions under its key, read from the store through the
   *              address the answer gives for the node (documentUrlAccepted), ends with its first
   *              page and names none. No node wrote the keys that the listings before this call
   *              named under that node id
   *    held      (key) the same, and the store does not show that: it holds a version of that
   *              object or more than a page under its key, the answer gives no address for the
   *              node or one that is not the address of that listing, or the store refuses the
   *              address. detail names the read that is held back
   *    failed    the backend refused the request or did not answer it (the failure is noted on run)
   *    unasked   the budget was spent (run.over), or the device or the store could not be
   *              reached (the failure is noted on run)
   *  A request the backend answers with the statement that it has no such route or no such store
   *  holds the documents back, for nodes of every kind: a listing of the store named the keys of
   *  a node, and the route hands out what the node registry of the backend kept of a receiving
   *  node whether or not the backend reads the store of format 3. */
  async function learnNodes(turn, log, run, ids, budget, kind) {
    const left = new Map();
    const requests = [];
    for (let at = 0; at < ids.length; at += LOG_DOCUMENT_NODES) {
      const batch = ids.slice(at, at + LOG_DOCUMENT_NODES);
      if (budget.documents <= 0) {
        // More nodes without a judgement than the document requests of this read name.
        run.over = true;
        for (const id of batch) left.set(id, { state: "unasked", detail: "" });
        continue;
      }
      budget.documents -= 1;
      requests.push({ ids: batch, sent: settled(readDocuments(turn, batch)) });
    }
    // The nodes of listed keys without a document that verifies: {id, why, url, signedMs}.
    const checks = [];
    for (const item of requests) {
      const outcome = await item.sent;
      if (!outcome.ok) {
        const refused = heldBack(outcome.error);
        noteFailure(turn, run, refused);
        const state = refused.kind === "blocked" || refused.kind === "silent" ? "failed" : "unasked";
        for (const id of item.ids) left.set(id, { state: state, detail: "" });
        continue;
      }
      for (const id of item.ids) {
        const given = outcome.value.documents.get(id);
        let why = "missing";
        if (given !== undefined) {
          try {
            const facts = verifyNodeDocument(given.document, id, given.registry);
            log.nodes[id] = { m: facts.measure, p: facts.platform, r: facts.release, f: native.nowMs(), c: 0 };
            continue;
          } catch (error) {
            if (failureCode(error) !== "attestation_failed") throw error;
            why = "rejected";
          }
        }
        if (kind !== "key") {
          left.set(id, { state: why, detail: "" });
          continue;
        }
        checks.push({ id: id, why: why, url: outcome.value.listings.get(id), signedMs: outcome.value.signedMs });
      }
    }
    if (checks.length === 0) return left;
    // Whether the store holds the node document of each of them: one listing per node, from the
    // store itself, after the listings that named the keys of the node.
    const listed = await pooled(checks, async function (check) {
      if (typeof check.url !== "string" || !documentUrlAccepted(check.url, check.id)) {
        throw storeFailure("blocked", "documents:url");
      }
      const response = await fetchStore(turn, check.url, "document");
      if (response.status !== 200) throw storeRefusal(response.status, "document", check.signedMs);
      const held = documentListed(response.body, check.id);
      if (held === null) throw storeFailure("unreachable", "document:body");
      return held;
    });
    for (let at = 0; at < checks.length; at += 1) {
      const check = checks[at];
      const outcome = listed[at];
      if (outcome.ok) {
        left.set(check.id, outcome.value
          ? { state: "held", detail: "documents:" + check.why } : { state: "absent", detail: "" });
        continue;
      }
      const failure = outcome.error;
      if (isStoreFailure(failure) && failure.kind === "blocked" && turnLeft(turn) > 0) {
        left.set(check.id, { state: "held", detail: failure.detail.slice(0, 64) });
        continue;
      }
      noteFailure(turn, run, failure);
      left.set(check.id, { state: "unasked", detail: "" });
    }
    return left;
  }

  /** Reads and verifies the entries of format 3 that items name ([{parsed, fresh, held, keep,
   *  shown}]: fresh marks a control key this device has not judged, held a key an earlier read
   *  found held back, keep a key whose reading is kept for the log screen, shown a key the log
   *  screen asks for) and judges them. Every item was named by a listing of the store that was
   *  read before this call. The documents of the nodes this device has no
   *  judgement of are requested together with the bodies of the keys whose nodes it has one of,
   *  and the bodies of the keys whose nodes those documents judged after them (budget.documents
   *  and budget.bodies requests at most). No body is asked for under a key whose node has no
   *  judgement. For every item whose object was judged, run.entries receives {parsed, state,
   *  verdict, ours, events}: state is ok for a verified entry, and signature, fields, open or
   *  absent for an object that is not the entry its key names. What the judgement finds:
   *    a key of a node the store holds no node document of (learnNodes: absent) is no entry of a
   *    node. It is left out (run.junk), counted (run.undocumented) and marks nothing;
   *    a key of a node without a document that verifies, when the store does not show that it
   *    holds no document of that node, a body the backend did not hand out, and a body that is
   *    not the one the key names are reads the operator domain held back (run.blocked). Whatever
   *    the backend hands out with such a key, the key is not set aside. It is kept
   *    (run.withheld) for the rounds to ask for it again;
   *    a body the node of the key signed under a key that node did not write for it (the fields
   *    of the body are not the ones the key names) is an object someone else put there: it is no
   *    entry (run.junk) and marks nothing;
   *    an entry of this key written by a node of a measurement no list has, and a transfer of the
   *    delegation to such a measurement, are noted (A1);
   *    a signature of an accepted node that does not verify over the body its key names, an entry
   *    of this key it signed that does not open, and two bodies it signed for one seq are noted on
   *    the node (A2).
   *  A fresh control key that was judged is remembered (markSeen); one whose read was held back or
   *  cut short is judged again by the next round. run.settled receives the keys whose read came
   *  to a judgement, run.kept those of them whose item says keep, and run.shown the keys kept
   *  for the rounds (run.withheld) that the log screen asked for: the ones held back, and the
   *  ones no answer of the bodies reached. */
  async function readEntries(turn, keys, log, run, items, budget) {
    if (items.length === 0) return;
    const unknown = [];
    // The keys of the items the log screen asked for: one of them that is held back, or that
    // no answer reached, is kept for the rounds as a key the screen asked for.
    const shown = new Set();
    for (const item of items) {
      const id = item.parsed.node;
      if (nodeVerdict(log.grants, log.nodes, id) === null && unknown.indexOf(id) < 0) unknown.push(id);
      if (item.shown === true) shown.add(item.parsed.key);
    }
    const hold = function (key) {
      run.withheld.add(key);
      if (shown.has(key)) run.shown.add(key);
    };
    const learning = learnNodes(turn, log, run, unknown, budget, "key");
    // The keys whose bodies are asked for: each key once, in the order of items, as many as the
    // requests left to this read carry. A request names the keys an earlier read found held
    // back first (held), and then its other keys, each group with the earliest entry first: a
    // key that was held back is the first key of the request of every round, where an answer
    // that does not name it holds it back again, and a key an answer left out stands in front
    // of the entries that arrive later.
    const named = new Set();
    const requests = [];
    // The keys a request of this read named.
    const requested = new Set();
    const ask = function (judged) {
      let wanted = [];
      for (const item of items) {
        const parsed = item.parsed;
        if (named.has(parsed.key) || wanted.length >= budget.bodies * LOG_BODY_KEYS || !judged(parsed.node)) continue;
        named.add(parsed.key);
        wanted.push(item);
      }
      wanted.sort(function (x, y) {
        if ((x.held === true) !== (y.held === true)) return x.held === true ? -1 : 1;
        const a = x.parsed;
        const b = y.parsed;
        if (a.time_ms !== b.time_ms) return a.time_ms - b.time_ms;
        return a.tail < b.tail ? 1 : a.tail > b.tail ? -1 : 0;
      });
      wanted = wanted.map(function (item) { return item.parsed.key; });
      for (let at = 0; at < wanted.length && budget.bodies > 0; at += LOG_BODY_KEYS) {
        budget.bodies -= 1;
        const batch = wanted.slice(at, at + LOG_BODY_KEYS);
        for (const key of batch) requested.add(key);
        requests.push({ keys: batch, sent: settled(readBodies(turn, batch)) });
      }
    };
    // The keys of the nodes this device has a judgement of go out with the request for the
    // documents; the keys of the nodes those documents judged follow them.
    ask(function (node) { return unknown.indexOf(node) < 0; });
    const left = await learning;
    ask(function (node) { return nodeVerdict(log.grants, log.nodes, node) !== null; });
    const bodies = new Map();
    // The keys of the requests that failed: their bodies are missing for that failure, not
    // because the read had more keys than its requests name.
    const failed = new Set();
    for (const asked of requests) {
      const outcome = await asked.sent;
      if (!outcome.ok) {
        // A request the backend refused or did not answer: its keys are asked for again by the
        // rounds (a request that failed with the network of the device is one they answer then).
        const failure = heldBack(outcome.error);
        noteFailure(turn, run, failure);
        for (const key of asked.keys) failed.add(key);
        if (failure.kind === "blocked" || failure.kind === "silent") {
          for (const key of asked.keys) hold(key);
        }
        continue;
      }
      // An answer names the keys in the order of the request and may end early (the backend
      // bounds the size and the time of an answer): the keys after the last key it names are
      // asked for again by the next read. An answer that names none of the keys, or names a key
      // and not one before it in the request, held a body back: the first key of the request, or
      // the keys it left out before the last one it names.
      let last = -1;
      for (let at = 0; at < asked.keys.length; at += 1) {
        if (outcome.value.has(asked.keys[at])) last = at;
      }
      const skipped = last < 0 ? [asked.keys[0]] : asked.keys.slice(0, last).filter(function (key) {
        return !outcome.value.has(key);
      });
      if (skipped.length > 0) {
        run.blocked = true;
        if (run.detail === "") run.detail = "bodies:skipped";
        for (const key of skipped) hold(key);
      }
      outcome.value.forEach(function (value, key) { bodies.set(key, value); });
    }
    // The verified entries by node and seq: two of them with two bodies contradict each other.
    const signedBySeq = new Map();
    const transfers = [];
    // The items the log screen asked for that a request named and no answer reached (a key this
    // read had no request left for is asked for by the next read of the screen).
    const unanswered = [];
    for (const item of items) {
      const parsed = item.parsed;
      const digest = item.fresh ? keyDigest(parsed.key) : "";
      const verdict = nodeVerdict(log.grants, log.nodes, parsed.node);
      if (verdict === null) {
        const why = left.get(parsed.node);
        if (why === undefined || (why.state !== "absent" && why.state !== "held")) {
          // A request for the document that the backend refused or did not answer: the key is
          // asked for again by the rounds.
          if (why !== undefined && why.state === "failed") hold(parsed.key);
          run.cut = true;
          continue;
        }
        run.undocumented.add(parsed.node);
        if (why.state === "absent") {
          // The store listed this key and holds no version of the node document of its node. A
          // node writes its document before it takes a user key and writes no entry without it,
          // so no act of a node stands behind this object: it is no entry.
          run.entries.set(parsed.key, { parsed: parsed, state: "absent", verdict: null, ours: false, events: null });
          run.junk.add(parsed.key);
          run.settled.add(parsed.key);
          if (item.keep === true) run.kept.add(parsed.key);
          if (item.fresh) markSeen(log, digest);
          continue;
        }
        // The listing of the store names this key, the backend hands out no document that
        // verifies for its node, and the store does not show that it holds none. The document of
        // a node outlives its entries, so the document of the node is held back, or someone
        // wrote an object under the key of that document. The read counts as held back, and the
        // screen shows the entry as not verified.
        run.blocked = true;
        if (run.detail === "") run.detail = why.detail;
        hold(parsed.key);
        continue;
      }
      const entry = bodies.get(parsed.key);
      if (entry === undefined) {
        // The body was not asked for (the requests of this read were spent) or the answer ended
        // before this key: the read has more to read than it read.
        run.cut = true;
        if (!failed.has(parsed.key)) {
          run.over = true;
          if (shown.has(parsed.key) && requested.has(parsed.key)) unanswered.push(parsed);
        }
        continue;
      }
      const checked = entry === null ? { body: null, failure: "body" } : checkEntry(parsed, entry);
      run.bodies += 1;
      if (checked.failure === "body") {
        run.blocked = true;
        if (run.detail === "") run.detail = entry === null ? "bodies:missing" : "bodies:hash";
        hold(parsed.key);
        continue;
      }
      const record = { parsed: parsed, state: "ok", verdict: verdict, ours: false, events: null };
      run.entries.set(parsed.key, record);
      run.settled.add(parsed.key);
      if (item.keep === true) run.kept.add(parsed.key);
      if (item.fresh) markSeen(log, digest);
      if (checked.failure === "signature") {
        // The body is the one the key names and the signature of the node does not verify over it.
        record.state = "signature";
        if (verdict.state === "accepted") noteConflict(log, parsed.node, verdict);
        continue;
      }
      if (checked.failure === "fields") {
        // A body the node signed, under a key the node did not write for it: not an entry.
        record.state = "fields";
        run.junk.add(parsed.key);
        continue;
      }
      const name = parsed.node + ":" + parsed.seq;
      const before = signedBySeq.get(name);
      if (before !== undefined && before !== parsed.body_hash && verdict.state === "accepted") {
        noteConflict(log, parsed.node, verdict);
      }
      signedBySeq.set(name, parsed.body_hash);
      record.ours = parsed.key_id === keys.keyId;
      if (record.ours) {
        record.events = entryEvents(parsed, checked.body, keys);
        if (record.events === null) {
          record.state = "open";
          if (verdict.state === "accepted") noteConflict(log, parsed.node, verdict);
          continue;
        }
        if (verdict.state === "unaccepted") {
          noteUnaccepted(log, verdict.measure, verdict.release, parsed.node, true);
        } else if (parsed.letter === "c" && parsed.event === "grant_transferred_out") {
          const receiver = judgeTransfer(log, record.events[0]);
          if (receiver !== null) transfers.push({ to: receiver, event: record.events[0] });
        }
      }
      if (parsed.letter === "c") {
        run.checked += 1;
        run.verified.push(parsed.tail);
      }
    }
    // A key the log screen asked for that no answer reached is asked for by the rounds, in front
    // of their other keys: an answer that ends before it every time is then an answer that does
    // not name the first key of its request. The keys go to the rounds with the earliest entry
    // first, the order of a request: the key an answer ended in front of is among them however
    // many keys came after it.
    unanswered.sort(function (a, b) {
      if (a.time_ms !== b.time_ms) return a.time_ms - b.time_ms;
      return a.tail < b.tail ? 1 : a.tail > b.tail ? -1 : 0;
    });
    for (const parsed of unanswered) hold(parsed.key);
    // The receiving nodes of transfers whose events name no measurement: their documents.
    if (transfers.length > 0) {
      const ids = [];
      for (const transfer of transfers) {
        if (ids.indexOf(transfer.to) < 0) ids.push(transfer.to);
      }
      await learnNodes(turn, log, run, ids, budget, "receiver");
      for (const transfer of transfers) {
        const verdict = nodeVerdict(log.grants, log.nodes, transfer.to);
        if (verdict === null) noteUnaccepted(log, "node:" + transfer.to, transfer.event.release, transfer.to, true);
        else if (verdict.state === "unaccepted") {
          noteUnaccepted(log, verdict.measure, verdict.release, transfer.to, true);
        }
      }
    }
  }

  /** The control keys of one listing page that a round has still to judge, and the keys of one
   *  node and seq with two different bodies (their entries are read whether or not they were
   *  judged before): [{parsed, fresh}]. A key older than the retention of the store is left out
   *  (its node document may be gone with it). */
  function freshControl(log, run, listing) {
    const horizon = native.nowMs() - LOG_RETENTION_DAYS * DAY_MS;
    const bySeq = new Map();
    for (const parsed of listing.keys) {
      const name = parsed.node + ":" + parsed.seq;
      bySeq.set(name, (bySeq.get(name) || 0) + 1);
    }
    const items = [];
    for (const parsed of listing.keys) {
      if (parsed.time_ms < horizon) continue;
      run.controlKeys += 1;
      run.nodes.add(parsed.node);
      const seen = log.seen.set.has(keyDigest(parsed.key));
      if (!seen) items.push({ parsed: parsed, fresh: true });
      else if (bySeq.get(parsed.node + ":" + parsed.seq) > 1) items.push({ parsed: parsed, fresh: false });
    }
    return items;
  }

  /** A4 for a listing page read from the start of the control prefix: the keys of the sample this
   *  device keeps that are within their retention (with a day to spare) and within the range the
   *  page covers, and are not in the page. The same page is read once more, and a key absent from
   *  both readings is noted as missing. */
  async function judgeSample(turn, log, run, listing) {
    const now = native.nowMs();
    const expected = log.sample.filter(function (tail) {
      const age = now - tailTime(tail);
      if (!(age < (LOG_RETENTION_DAYS - 1) * DAY_MS)) return false;
      if (!listing.truncated) return true;
      return listing.keys.length > 0 && tail <= listing.keys[listing.keys.length - 1].tail;
    });
    let gone = expected.filter(function (tail) { return !listing.tails.has(tail); });
    if (gone.length === 0) return;
    let again = null;
    try {
      again = (await readListings(turn, [{ prefix: "c", key_marker: "", version_id_marker: "" }]))[0];
    } catch (failure) {
      // The first reading of this round came from the store: a backend that now answers that the
      // store is absent holds the second reading back.
      noteFailure(turn, run, heldBack(failure));
      return;
    }
    gone = gone.filter(function (tail) { return !again.tails.has(tail); });
    for (const tail of gone) {
      const known = log.missing.some(function (item) { return item.key === tail; });
      if (!known && log.missing.length < LOG_MISSING_KEYS) log.missing.push({ key: tail, found_ms: now });
    }
  }

  // ---- The round and the chains of format 1 and format 2 ----

  /** Puts a chain of format 1 or format 2 among the chains this device follows: the node id, and
   *  the latest time the node can hold the grant that reached it. */
  function followChain(log, id, untilMs) {
    const kept = log.legacy.nodes[id];
    if (kept === undefined) {
      log.legacy.nodes[id] = { seq: 0, time_ms: 0, until_ms: untilMs, closed: false, read_ms: 0 };
      return;
    }
    if (untilMs > kept.until_ms) {
      kept.until_ms = untilMs;
      kept.closed = false;
    }
  }

  /** The part of a round that reads the chains of format 1 and format 2 this device follows: the
   *  chains of the nodes of releases before LOG_FORMAT_3_FROM that it handed a grant to, and of
   *  the nodes such a node handed the delegation on to. Each open chain is listed from the seq up
   *  to which it was read, the control entries of the new keys are read (LEGACY_ROUND_BODIES per
   *  round), and a transfer of the delegation (the event
   *  grant_transferred_out of this key) is followed. Such an event names the receiving node and
   *  no measurement, so the document of that node is asked for (one request per pass):
   *    a receiving node whose document verifies with a measurement no list has is noted (A1);
   *    a receiving node of a release that writes format 3 has its entries in the listing of
   *    format 3;
   *    a receiving node of an accepted release before that has its chain followed in turn, in the
   *    same round (LEGACY_ROUND_PASSES passes of listings per round: a pass lists the chains
   *    whose listing went on and the chains the pass before found);
   *    a receiving node the backend hands out no document that verifies for is judged by the
   *    time of the event. From LEGACY_TRANSFER_DOCUMENTS_FROM_MS on, and within the retention of
   *    the store, the read is held back (run.blocked) and the node waits (legacy.waiting): every
   *    later round asks for its document again, and its chain is not followed before one
   *    verifies. For an event of another time the node is followed as a node of the release of
   *    the giving node;
   *    a receiving node whose document could not be asked for waits as well, and the round is
   *    not complete.
   *  A chain is closed by the first reading that reached its end after the grant of its node ran
   *  out (LEGACY_CLOSE_SLACK_MS later): a node holds no key after that. The keys read are handed
   *  to the log screen (rememberKeys). */
  async function followLegacy(turn, keys, log, run) {
    const legacy = log.legacy;
    const now = native.nowMs();
    for (const id of Object.keys(log.grants)) {
      const record = log.grants[id];
      if (logFormatOf(record.release) === 3 || !writesToStore(record.platform, record.release)) continue;
      followChain(log, id, record.not_after_ms);
    }
    let open = Object.keys(legacy.nodes).filter(function (id) { return !legacy.nodes[id].closed; });
    const waited = Object.keys(legacy.waiting);
    if (open.length === 0 && waited.length === 0) return;
    // More open chains than a round follows: the chains listed longest ago come first (among
    // them the ones whose grant ends last), so every chain is read within a few rounds.
    open.sort(function (x, y) {
      if (legacy.nodes[x].read_ms !== legacy.nodes[y].read_ms) return legacy.nodes[x].read_ms - legacy.nodes[y].read_ms;
      return legacy.nodes[y].until_ms - legacy.nodes[x].until_ms;
    });
    if (open.length > LEGACY_NODES) {
      open = open.slice(0, LEGACY_NODES);
      run.cut = true;
    }
    // A control entry names one receiving node at most, and the nodes that wait are asked for
    // with the first pass: the entries of a round and the nodes that wait fit one request.
    let bodiesLeft = Math.max(0, LEGACY_ROUND_BODIES - waited.length);
    // Each pass lists the chains that have keys left to read: the open chains first, then the
    // chains whose listing went on and the chains of the receiving nodes the pass before found.
    // The first pass also asks for the documents of the nodes that wait.
    // thin: a listing page that goes on named more than LEGACY_SEQ_VERSIONS object versions for
    // each seq it names, on average. A node writes one object under a seq, and a version more
    // when it repeats a write, so such a page holds objects a node did not write.
    let thin = false;
    for (let pass = 0; pass < LEGACY_ROUND_PASSES; pass += 1) {
      if (open.length === 0 && (pass > 0 || waited.length === 0)) break;
      const targets = open.map(function (id) {
        return { node: id, key_marker: listingMarker(id, legacy.nodes[id].seq), version_id_marker: null };
      });
      const listings = await legacyListings(turn, targets);
      const plans = [];
      const wanted = [];
      for (let at = 0; at < open.length; at += 1) {
        const id = open[at];
        const outcome = listings[at];
        if (!outcome.ok) {
          // The binding of the node of this chain named the store (the device verified it, or a
          // node it verified handed the delegation on): the store of these chains exists.
          noteFailure(turn, run, heldBack(outcome.error));
          continue;
        }
        const prefix = accountPrefix() + id + "/";
        const entries = new Map();
        let versions = 0;
        for (const version of outcome.value.versions) {
          const parts = parseStoreKey(version.key, prefix);
          if (parts === null || parts.seq <= legacy.nodes[id].seq) continue;
          versions += 1;
          if (!entries.has(parts.seq)) entries.set(parts.seq, []);
          entries.get(parts.seq).push({
            key: version.key, versionId: version.versionId, isLatest: version.isLatest, parts: parts,
          });
        }
        rememberKeys(id, entries);
        run.nodes.add(id);
        legacy.nodes[id].read_ms = now;
        const seqs = Array.from(entries.keys()).sort(function (a, b) { return a - b; });
        const more = outcome.value.truncated && outcome.value.nextKeyMarker !== null;
        // The last seq of a listing page that goes on may have further object versions on the
        // page after it: it is read with that page, from the seq before it.
        if (more) seqs.pop();
        if (more && versions > LEGACY_SEQ_VERSIONS * Math.max(1, seqs.length)) thin = true;
        const plan = { id: id, seqs: seqs, entries: entries, reads: new Map(), crowded: new Set(), stop: 0, more: more };
        for (const seq of seqs) {
          // The object versions whose keys name a control entry, the latest first, up to
          // LEGACY_SEQ_READS of them: an object someone else wrote under the seq of a control
          // entry does not take the place of the entry of the node.
          const shaped = entries.get(seq).filter(function (candidate) {
            return candidate.parts.format === 1 || candidate.parts.kind === "c";
          }).sort(function (a, b) { return (b.isLatest ? 1 : 0) - (a.isLatest ? 1 : 0); });
          if (shaped.length === 0) continue;
          const candidates = shaped.slice(0, LEGACY_SEQ_READS);
          if (bodiesLeft < candidates.length) {
            // The entries of this round are spent: the chain is read on from here by the next.
            plan.stop = seq;
            run.cut = true;
            run.over = true;
            break;
          }
          bodiesLeft -= candidates.length;
          plan.reads.set(seq, candidates);
          if (shaped.length > candidates.length) plan.crowded.add(seq);
          for (const candidate of candidates) wanted.push(candidate);
        }
        plans.push(plan);
      }
      let objects = new Map();
      try {
        for (let at = 0; at < wanted.length; at += LOG_STORE_OBJECTS) {
          const batch = await legacyObjects(turn, wanted.slice(at, at + LOG_STORE_OBJECTS));
          batch.forEach(function (value, name) { objects.set(name, value); });
        }
      } catch (failure) {
        noteFailure(turn, run, heldBack(failure));
        objects = null;
      }
      const next = [];
      // The receiving nodes of the transfers this pass read, and with the first pass the nodes
      // that wait: {until_ms, time_ms} (the latest time the node can hold the grant, and the time
      // of the latest event that names it).
      const receivers = new Map();
      if (pass === 0) {
        for (const id of waited) receivers.set(id, legacy.waiting[id]);
      }
      for (const plan of plans) {
        const chain = legacy.nodes[plan.id];
        let reached = chain.seq;
        let reachedMs = chain.time_ms;
        let held = false;
        for (const seq of plan.seqs) {
          if (plan.stop !== 0 && seq >= plan.stop) {
            held = true;
            break;
          }
          const candidates = plan.reads.get(seq);
          if (candidates !== undefined) {
            if (objects === null) {
              held = true;
              break;
            }
            let found = false;
            for (const candidate of candidates) {
              const signed = objects.get(candidate.key + "\n" + candidate.versionId);
              const entry = signed === undefined || signed === null
                ? null : checkLegacyEntry(signed, plan.id, candidate.parts, keys);
              run.bodies += 1;
              if (entry === null) continue;
              found = true;
              run.checked += 1;
              if (entry.events !== null) {
                for (const event of entry.events) {
                  if (event.t === "grant_transferred_out" && typeof event.to === "string" && NODE_ID.test(event.to)) {
                    // The time of the event, or of its entry for an event that names none.
                    const eventMs = whole(event.time_ms) > 0 ? event.time_ms : entry.time_ms;
                    const before = receivers.get(event.to) || { until_ms: 0, time_ms: 0 };
                    receivers.set(event.to, {
                      until_ms: Math.max(before.until_ms, chain.until_ms), time_ms: Math.max(before.time_ms, eventMs),
                    });
                  }
                }
              }
              break;
            }
            if (!found && plan.crowded.has(seq)) {
              // More object versions under this seq name a control entry than the round reads,
              // and none of the ones read is the entry of the node: the entry, if the node
              // wrote one, is held back behind objects someone else wrote there.
              run.blocked = true;
              if (run.detail === "") run.detail = "chain:keys";
              held = true;
              break;
            }
          }
          reached = seq;
          const first = plan.entries.get(seq)[0].parts;
          reachedMs = first.format === 2 ? first.time_ms : reachedMs;
        }
        chain.seq = reached;
        chain.time_ms = reachedMs;
        if (held) continue;
        if (plan.more) {
          next.push(plan.id);
          continue;
        }
        if (now > chain.until_ms + LEGACY_CLOSE_SLACK_MS) chain.closed = true;
      }
      // The receiving nodes this device has no judgement of: their documents.
      const unknown = [];
      receivers.forEach(function (receiver, id) {
        if (nodeVerdict(log.grants, log.nodes, id) === null) unknown.push(id);
      });
      const left = unknown.length === 0 ? new Map()
        : await learnNodes(turn, log, run, unknown.slice(0, LOG_DOCUMENT_NODES), { documents: 1 }, "chain");
      receivers.forEach(function (receiver, id) {
        const verdict = nodeVerdict(log.grants, log.nodes, id);
        if (verdict !== null) {
          delete legacy.waiting[id];
          if (verdict.state === "unaccepted") {
            noteUnaccepted(log, verdict.measure, verdict.release, id, true);
            return;
          }
          if (verdict.format === 3) return;
        } else {
          const why = left.get(id);
          const state = why === undefined ? "unasked" : why.state;
          if (state === "unasked" || state === "failed") {
            // Its document could not be asked for: the next round asks again. A node that was
            // left out of the one request of this pass is one more than a round asks for.
            legacy.waiting[id] = receiver;
            run.cut = true;
            if (why === undefined) run.over = true;
            return;
          }
          const kept = receiver.time_ms >= LEGACY_TRANSFER_DOCUMENTS_FROM_MS &&
            now - receiver.time_ms < LOG_RETENTION_DAYS * DAY_MS;
          if (kept) {
            // The backend keeps the document of every node that took a transfer from that time
            // on, for longer than the store keeps the entry of the transfer, and hands none out
            // that verifies for this one.
            legacy.waiting[id] = receiver;
            run.blocked = true;
            if (run.detail === "") run.detail = "receiver:" + state;
            return;
          }
          delete legacy.waiting[id];
        }
        const known = legacy.nodes[id] !== undefined;
        followChain(log, id, receiver.until_ms);
        if (!known && next.indexOf(id) < 0) next.push(id);
      });
      open = next.slice(0, LEGACY_NODES);
    }
    // The chains whose listing still goes on are read on by the next round. A chain of an
    // account in heavy use is long, and a round that reads on through it has not more to read
    // than a round reads in the sense that counts (LOG_UNFINISHED_ROUNDS): only a listing that
    // goes on over pages that hold many object versions for each seq does.
    if (open.length > 0) {
      run.cut = true;
      if (thin) run.over = true;
    }
  }

  // ---- The state a round publishes ----

  // The state of the log as the last round left it (runtime lifetime; the device keeps it in
  // log.round, and the executor keeps the published tree).
  let logState = null;

  function emptyLogState() {
    return {
      status: "pending", verified_ms: 0, unverified_nodes: 0, missing: 0, expired: 0,
      unknown_nodes: 0, newer_release_nodes: 0, store: "pending", store_failure: "", store_failing_ms: 0,
      program_version: VERSION,
    };
  }

  /** The state of the log this device keeps: the one the last round of this program published, or
   *  the empty state when this program has ended no round on this installation. */
  function keptLogState() {
    if (logState !== null) return logState;
    const round = storedObject(STORE_ROUND);
    const kept = round.v === VERSION && round.state !== null && typeof round.state === "object" ? round.state : null;
    logState = emptyLogState();
    if (kept !== null && (kept.status === "verified" || kept.status === "pending" || kept.status === "attention")) {
      logState.status = kept.status;
      for (const name of ["verified_ms", "unverified_nodes", "missing", "unknown_nodes", "newer_release_nodes", "store_failing_ms"]) {
        logState[name] = whole(kept[name]);
      }
      logState.store = typeof kept.store === "string" ? kept.store : "pending";
      logState.store_failure = typeof kept.store_failure === "string" ? kept.store_failure : "";
    }
    return logState;
  }

  /** Whether a round is due: this program has ended none on this installation, the last one that
   *  completed is LOG_ROUND_INTERVAL_MS old, or the last one did not complete (it ended pending,
   *  or it could not read the store while a mark of an earlier round stood) or a read of the
   *  screen found a key held back since (then not sooner than LOG_ROUND_RETRY_MS after it). */
  function roundDue() {
    const round = storedObject(STORE_ROUND);
    const now = native.nowMs();
    if (round.v !== VERSION) return true;
    const tried = whole(round.tried_ms);
    const nominated = withheldDue(loadWithheld());
    if (round.open === true || nominated || (round.last !== "verified" && round.last !== "attention")) {
      return now < tried || now - tried >= LOG_ROUND_RETRY_MS;
    }
    const done = whole(round.done_ms);
    return now < done || now - done >= LOG_ROUND_INTERVAL_MS;
  }

  /** Tells the app the judgement of a round (the bridge primitive securityStatus, in the builds
   *  that have it): ok for a verified round, attention with one reason per condition that holds,
   *  and pending for a round that did not complete, unless the value told last is attention (an
   *  attention is not covered by a round that could not judge). Returns the value now told. */
  function tellStatus(status, reasons, told) {
    if (typeof native.securityStatus !== "function") return told;
    const value = status === "verified" ? "ok" : status;
    if (value === "pending" && told === "attention") return told;
    try {
      native.securityStatus({ status: value, reasons: value === "attention" ? reasons.slice(0, 8) : [] });
    } catch (error) {
      if (failureCode(error) === "cancelled") throw error;
      native.log("security status: " + failureCode(error));
      return told;
    }
    return value;
  }

  /** Reports the result of one round to the backend (the one way the server learns what the device
   *  judged). Nothing waits for the answer: a failure is logged when it arrives and changes
   *  nothing. */
  function reportRound(state, run, counts, elapsedMs) {
    const body = {
      status: state.status, store: state.store, nodes: run.nodes.size, keys_checked: run.checked,
      bodies_fetched: run.bodies, missing: state.missing, expired: 0, unknown_nodes: state.unknown_nodes,
      newer_release_nodes: state.newer_release_nodes, elapsed_ms: elapsedMs, program_version: VERSION,
      store_failure: state.store_failure, unknown_node_ids: counts.heldNodes.slice(0, 16),
      unaccepted_releases: counts.releases.slice(0, 16), blocked_attempts: counts.blockedRounds,
      undocumented_nodes: run.undocumented.size, control_keys: run.controlKeys,
    };
    if (run.screenMs !== null) body.screen_ms = run.screenMs;
    settled(api(freeTurn(), "POST", LOG_REPORT_PATH, body, null, LOG_API_TIMEOUT_MS)).then(function (outcome) {
      try {
        if (!outcome.ok) native.log("round report: " + failureCode(outcome.error));
      } catch (error) {
        // The bridge is closed.
      }
    });
  }

  /** Whether the backend answered a request of this runtime around a round that began at
   *  startedMs (from LOG_REACH_MS before it): a request of the round that was not answered was
   *  then held back by the operator domain and not lost with the network of the device. When
   *  nothing answered in that time, the account query is asked once. */
  async function reachJudged(turn, startedMs) {
    if (lastAnswerMs >= startedMs - LOG_REACH_MS) return true;
    try {
      await request(turn, "GET", "/api/secure/account", null, null, LOG_API_TIMEOUT_MS);
      return true;
    } catch (error) {
      if (failureCode(error) === "cancelled" || !(turnLeft(turn) > 0)) throw error;
      return false;
    }
  }

  /** One round (docs/protocol.md 7.4). origin is sync (a synchronization started it: the control
   *  prefix is read, LOG_CONTROL_PAGES listing pages at most) or screen (the log screen started
   *  it: the first page of the control prefix and of the use prefix are read together, and extra,
   *  when given, names the further entries the screen wants read along with what the round reads:
   *  extra(pages) returns [{parsed}]). The steps:
   *    1 the listing addresses from the backend, each checked before it is called
   *    2 the control listing from the store. A round reads the listing from its start: an entry a
   *      node wrote late lies below the entries this device saw before, so the round judges every
   *      key it has not judged (log.seen) wherever it lies. A listing longer than the pages of one
   *      round is read on by the next round from where this one stopped (log.resume)
   *    3 the documents of the nodes this device has no judgement of and, for a node without a
   *      document that verifies, the listing of the versions of its node document from the store,
   *      and 4 the bodies of the keys it has not judged whose nodes it has a judgement of
   *      (readEntries). The keys an earlier read found held back are read with the first page,
   *      and the listing pages of the screen an earlier read found held back after the listing
   *      (log.withheld), each with the entries of the page the screen would show there
   *    5 the chains of format 1 and format 2 this device follows (followLegacy), and the reads of
   *      that bucket the screen made that an earlier read found held back (rereadChains)
   *    6 the judgement, the published state, the report. What the round read for the screen is
   *      kept for it (log.recovered) before the reads it answers leave log.withheld
   *  A round that ends with reads left undone because there was more to read than a round reads
   *  (run.truncated, run.over) is not complete and the next round reads on. From the round after
   *  LOG_UNFINISHED_ROUNDS such rounds of synchronizations in a row, a round that ends that way
   *  counts as a round whose reads are held back.
   *  A backend that states it has no store of format 3 (the route is absent, or it answers
   *  log_store_disabled) is read as an environment without entries of format 3, unless this device
   *  knows otherwise: it handed a grant to a node of a release that writes format 3, or it read
   *  that store before. Then the answer is a read the operator domain holds back.
   *  Returns {log, pages: {c, u}, entries, absent}: the published state, the first listing pages
   *  (null when they were not read), the entries read by key, and whether the environment has no
   *  store of format 3. */
  async function runRound(turn, keys, origin, extra) {
    const started = native.nowMs();
    const log = loadLog();
    // The reads an earlier read found held back, and whether what this device kept before this
    // round says that its environment has a store of format 3.
    const withheld = loadWithheld();
    const known = storeKnown(log, withheld);
    const run = {
      origin: origin, detail: "", blocked: false, silent: false, unreachable: false, truncated: false,
      cut: false, over: false, controlKeys: 0, checked: 0, bodies: 0, nodes: new Set(), undocumented: new Set(),
      verified: [], entries: new Map(), junk: new Set(), screenMs: null, withheld: new Set(),
      shown: new Set(), kept: new Set(), settled: new Set(), pagesHeld: new Set(), pagesRead: new Set(),
      pagesKept: new Map(), pageOf: new Map(), store3: known, objectsRead: new Set(), chainsRead: new Set(),
      nodesRead: false, chainKept: [], found: null,
    };
    // What the rounds kept for the screen before this round: an entry kept there is not read
    // again.
    const had = loadRecovered(keys);
    const budget = { documents: LOG_DOCUMENT_REQUESTS, bodies: origin === "screen" ? LOG_SUMMARY_REQUESTS : LOG_ROUND_BODY_REQUESTS };
    const pages = { c: null, u: null };
    let absent = false;
    let complete = false;
    // Where this round reads the control listing: from its start, or on from where the round
    // before stopped (a synchronization only: the screen reads the first page).
    let place = origin === "sync" && log.resume !== null ? log.resume
      : { key_marker: "", version_id_marker: "", top: "", until: "", tail: false };
    const pageLimit = origin === "screen" ? 1 : LOG_CONTROL_PAGES;
    // The time of a round is one of the things it has only so much of. A failure that arrives
    // once that time has passed (the failure of the request that was waiting, or of the one
    // after it) ends the reading and not the round: the round is judged on what it read, and
    // counts as one that had more to read than it read. It keeps what it judged, so the next
    // round reads on. A runtime that goes down ends the round.
    let expired = false;
    const ranOut = function (failure) {
      if (failureCode(failure) === "cancelled" || turnLeft(turn) > 0) throw failure;
      expired = true;
      run.cut = true;
      // Time that passed while the runtime did not run (the app went to the background during
      // the round, or the time of the round passed later than a running runtime lets it) is not
      // time the round had: it could not read, and has not more to read than a round reads.
      const away = appBackgroundMs >= started || turnSpent(turn) - turn.limitMs > WAIT_LATE_MS;
      if (away) run.unreachable = true;
      else run.over = true;
      if (run.detail === "") run.detail = away ? "round:suspended" : "round:time";
    };
    try {
      for (let page = 0; page < pageLimit && !complete; page += 1) {
        const wanted = [{ prefix: "c", key_marker: place.key_marker, version_id_marker: place.version_id_marker }];
        if (origin === "screen") wanted.push({ prefix: "u", key_marker: "", version_id_marker: "" });
        let listings = null;
        try {
          listings = await readListings(turn, wanted);
        } catch (failure) {
          if (isStoreFailure(failure) && failure.kind === "absent" && turnLeft(turn) > 0) {
            if (!known) {
              absent = true;
              complete = true;
              break;
            }
            run.blocked = true;
            if (run.detail === "") run.detail = failure.detail.slice(0, 64);
            if (origin === "screen") {
              run.pagesHeld.add(0);
              run.pageWatch = true;
            }
            break;
          }
          noteFailure(turn, run, failure);
          // The pages that begin the two listings, which the screen reads and a round of a
          // synchronization does not: the rounds make that read again, and go on making it with
          // every round until the screen reads those pages itself (pageWatch).
          if (origin === "screen" && heldKind(failure)) {
            run.pagesHeld.add(0);
            run.pageWatch = true;
          }
          break;
        }
        const control = listings[0];
        // The store of format 3 answered: the routes of its bodies and documents exist.
        run.store3 = true;
        if (origin === "screen") {
          run.pagesRead.add(0);
          run.pageSeen = true;
        }
        if (place.key_marker === "") {
          pages.c = control;
          if (listings.length > 1) pages.u = listings[1];
          if (place.top === "" && control.keys.length > 0) place.top = control.keys[0].tail;
        }
        let items = freshControl(log, run, control);
        if (page === 0) {
          // With the first page: the keys whose read an earlier read found held back (the listing
          // of that read named them), and the entries the screen wants read. The keys held back
          // stand first, so that no number of new keys takes the requests of the round from them.
          // What the round reads under a key the log screen asked for is kept for the screen
          // (keep), and a key the screen asks for now is marked as one it asked for (shown).
          const fresh = new Set(items.map(function (item) { return item.parsed.key; }));
          const named = new Map();
          const first = [];
          for (const key of withheld.keys) {
            const parsed = parseAccountKey(key);
            if (parsed === null || named.has(parsed.key)) continue;
            const asked = withheld.shown.indexOf(key) >= 0;
            const item = { parsed: parsed, fresh: fresh.has(parsed.key), held: true, keep: asked, shown: asked };
            named.set(parsed.key, item);
            first.push(item);
          }
          const rest = items.filter(function (item) { return !named.has(item.parsed.key); });
          for (const item of rest) named.set(item.parsed.key, item);
          items = first.concat(rest);
          for (const more of typeof extra === "function" ? extra(pages) : []) {
            const listed = named.get(more.parsed.key);
            if (listed !== undefined) {
              listed.shown = true;
              continue;
            }
            const item = { parsed: more.parsed, fresh: false, shown: true };
            named.set(more.parsed.key, item);
            items.push(item);
          }
        }
        await readEntries(turn, keys, log, run, items, budget);
        if (place.key_marker === "") await judgeSample(turn, log, run, control);
        const met = place.until !== "" && control.keys.some(function (parsed) { return parsed.tail >= place.until; });
        if (met || !control.truncated) {
          if (place.tail) {
            // The rest of an earlier listing is read: now the keys that arrived above it since.
            place = { key_marker: "", version_id_marker: "", top: "", until: place.top, tail: false };
            if (place.until === "") complete = true;
            continue;
          }
          complete = true;
          break;
        }
        place = {
          key_marker: control.next_key_marker, version_id_marker: control.next_version_id_marker,
          top: place.top, until: place.until, tail: place.tail,
        };
      }
    } catch (failure) {
      ranOut(failure);
    }
    const readFailed = run.blocked || run.silent || run.unreachable;
    if (!complete && !readFailed) run.truncated = true;
    // The listing pages of the screen that an earlier read found held back are read again, each
    // in the request the screen sends for it. A backend that states it has no store of format 3
    // holds such a page back on a device that knows of that store, and has no such page on a
    // device that knows of none.
    // What the round reads there is kept for the screen: the page the screen would show below
    // that time (LOG_RECOVERED_PAGE_EVENTS events), and the entries of that page, which the
    // round reads as the screen would. An entry of the page whose read is held back, or that no
    // answer reaches, is a key the rounds ask for again.
    // The page that begins the two listings is read with every round of a synchronization from
    // the time it was held back from the screen until the screen reads it itself
    // (withheld.watch_ms): the first page the screen falls back on is then as new as the last
    // round, and not as old as the round after the screen last asked.
    const again = withheld.pages.slice();
    if (origin === "sync" && withheld.watch_ms > started && again.indexOf(0) < 0) again.push(0);
    try {
      for (const before of expired ? [] : again) {
        if (run.pagesRead.has(before) || run.pagesHeld.has(before)) continue;
        let listings = null;
        try {
          listings = await readListings(turn, screenPages(before));
        } catch (failure) {
          if (isStoreFailure(failure) && failure.kind === "absent" && !run.store3 && turnLeft(turn) > 0) {
            // No store of format 3, and so no such page: the rounds read it no longer.
            run.pagesRead.add(before);
            if (before === 0) run.pageSeen = true;
            continue;
          }
          noteFailure(turn, run, heldBack(failure));
          continue;
        }
        run.pagesRead.add(before);
        const page = choosePage(
          { c: listings[0], u: listings[1] }, before === 0 ? Infinity : before, LOG_RECOVERED_PAGE_EVENTS);
        run.pagesKept.set(before, { more: page.more, keys: page.chosen });
        const wanted = [];
        for (const parsed of page.chosen) {
          if (!run.pageOf.has(parsed.key)) run.pageOf.set(parsed.key, before);
          if (had.entries.has("3:" + parsed.tail)) continue;
          if (run.entries.has(parsed.key)) run.kept.add(parsed.key);
          else if (wanted.length < LOG_SCREEN_BODIES) wanted.push({ parsed: parsed, fresh: false, shown: true, keep: true });
        }
        await readEntries(turn, keys, log, run, wanted, budget);
      }
      if (!expired) {
        try {
          await followLegacy(turn, keys, log, run);
        } catch (failure) {
          noteFailure(turn, run, heldBack(failure));
        }
        // The reads of the bucket of format 1 and format 2 that the log screen made and found held
        // back.
        await rereadChains(turn, keys, run, withheld);
      }
    } catch (failure) {
      ranOut(failure);
    }
    // The judgement. A round whose time ran out asks whether the backend can be reached in a
    // turn of its own.
    const now = native.nowMs();
    const judging = expired ? newTurn(2 * LOG_API_TIMEOUT_MS, "") : turn;
    const denied = run.blocked || (run.silent && await reachJudged(judging, started));
    const unreachable = !denied && (run.unreachable || run.silent);
    // The rounds of a synchronization in a row that left reads undone because there was more to
    // read than a round reads. A round that read everything it had to read ends the row; a round
    // whose reads were held back, or that could not reach the store, leaves it as it is. Beyond
    // LOG_UNFINISHED_ROUNDS such rounds, a round that ends that way is one whose reads are held
    // back (a round the log screen started reads one listing page and adds nothing to the row).
    const over = !unreachable && (run.truncated || run.over);
    let unfinished = log.round.v === VERSION ? whole(log.round.unfinished) : 0;
    if (over) {
      if (origin === "sync") unfinished += 1;
    } else if (!denied && !unreachable) {
      unfinished = 0;
    }
    const overrun = over && unfinished > LOG_UNFINISHED_ROUNDS;
    if (overrun && run.detail === "") run.detail = "round:unfinished";
    const blocked = denied || overrun;
    let grace = 0;
    let established = 0;
    const releases = [];
    const heldNodes = [];
    for (const digest of Object.keys(log.unaccepted)) {
      const item = log.unaccepted[digest];
      const node = item !== null && typeof item === "object" && typeof item.node === "string" ? item.node : "";
      const listed = item === null || typeof item !== "object" ? true
        : digest.slice(0, 5) === "node:"
          ? (function () {
            const verdict = nodeVerdict(log.grants, log.nodes, digest.slice(5));
            return verdict !== null && verdict.state === "accepted";
          })()
          : buildOfMeasure(digest) !== undefined;
      if (listed) {
        delete log.unaccepted[digest];
        continue;
      }
      // A first time that lies after now is the clock of the device having run backwards: the
      // grace begins again from now (a clock that was wrong marks nothing at once).
      if (whole(item.first_ms) > now) item.first_ms = now;
      const age = now - whole(item.first_ms);
      const within = age < LOG_RELEASE_GRACE_MS;
      if (item.held !== true && !within) {
        // A measurement that was listed to this device and never held its key: nothing to judge.
        if (age >= 30 * DAY_MS) delete log.unaccepted[digest];
        continue;
      }
      if (within) grace += 1;
      else established += 1;
      const release = typeof item.release === "string" && item.release !== "" ? item.release.slice(0, 64) : "unknown";
      if (releases.indexOf(release) < 0) releases.push(release);
      if (item.held === true && NODE_ID.test(node) && heldNodes.indexOf(node) < 0) heldNodes.push(node);
    }
    const conflicts = Object.keys(log.nodes).filter(function (id) { return log.nodes[id].c !== 0; }).length;
    if (blocked) {
      if (log.blocked.count === 0 || log.blocked.first_ms === 0 || log.blocked.first_ms > now) log.blocked.first_ms = now;
      log.blocked.count += 1;
    } else if (!unreachable) {
      log.blocked = { first_ms: 0, count: 0 };
    }
    // The reads held back from the screen that the reads of the screen count themselves.
    const deniedMs = deniedSince(loadDenied(), now);
    const deep = deniedMs !== 0;
    if (deep && run.detail === "") run.detail = "screen:held";
    const held = deep || (log.blocked.count >= LOG_BLOCKED_ROUNDS && now - log.blocked.first_ms >= LOG_BLOCKED_MS);
    const reasons = [];
    if (established > 0) reasons.push("unlisted_release");
    if (conflicts > 0) reasons.push("conflicting_signatures");
    if (held) reasons.push("verification_blocked");
    if (log.missing.length > 0) reasons.push("missing_entries");
    // A round that did not read everything it had to read, or that waits for a release to be
    // listed, is not complete: the next synchronization runs a round again.
    const incomplete = blocked || unreachable || run.truncated || run.cut || grace > 0;
    const status = reasons.length > 0 ? "attention" : incomplete ? "pending" : "verified";
    const before = keptLogState();
    const state = {
      status: status, verified_ms: status === "pending" ? before.verified_ms : now,
      unverified_nodes: conflicts, missing: log.missing.length, expired: 0, unknown_nodes: established,
      newer_release_nodes: grace,
      store: blocked || deep ? "blocked" : unreachable ? "unreachable" : run.truncated ? "truncated" : "verified",
      store_failure: run.detail, program_version: VERSION,
      store_failing_ms: log.blocked.first_ms !== 0 || !deep ? log.blocked.first_ms : deniedMs,
    };
    // What the device keeps of this round.
    if (complete && !absent && !readFailed) {
      if (place.top !== "") log.cursor = place.top;
      log.resume = null;
    } else if (run.truncated && origin === "sync") {
      // A walk toward the end of the listing that the page limit cut: the round that reads its
      // rest then reads the keys that arrived above its start since (tail).
      log.resume = {
        key_marker: place.key_marker, version_id_marker: place.version_id_marker, top: place.top,
        until: place.until, tail: place.tail || place.until === "",
      };
    } else if (run.truncated && log.resume === null && pages.c !== null) {
      log.resume = {
        key_marker: pages.c.next_key_marker, version_id_marker: pages.c.next_version_id_marker,
        top: place.top, until: "", tail: true,
      };
    }
    if (pages.c !== null || run.verified.length > 0) {
      const horizon = now - (LOG_RETENTION_DAYS - 1) * DAY_MS;
      const sample = log.sample.concat(run.verified).filter(function (tail, at, all) {
        return all.indexOf(tail) === at && tailTime(tail) >= horizon;
      }).sort();
      log.sample = sample.slice(0, LOG_SAMPLE_KEYS);
    }
    // What this round read for the log screen is kept for the screen first (the entries under
    // the keys the screen had asked for, the listing pages, the entries and the node prefixes of
    // the chains): a read leaves the withheld ones, the count of the rounds held back ends and
    // the app is told the judgement only after what was read is where the screen takes it from.
    // A listing page the screen read itself in this round is not kept: what the rounds kept of
    // it is dropped.
    const own = origin === "screen" && pages.c !== null && had.pages.some(function (page) { return page.before === 0; });
    if (run.kept.size > 0 || run.pagesKept.size > 0 || own || run.chainKept.length > 0 || run.found !== null) {
      const recovered = loadRecovered(keys);
      for (const item of run.chainKept) {
        recovered.entries.delete("2:" + item.name);
        recovered.entries.set("2:" + item.name, {
          t: now, m: item.entry.time_ms > 0 ? item.entry.time_ms : now, e: clippedEntry(item.entry),
        });
      }
      if (run.found !== null) recovered.found = { t: now, ids: run.found.slice(0, 2 * LEGACY_NODES) };
      // An entry is kept because the screen asked for its key and the read was held back, or
      // as a part of a listing page the round read again.
      run.kept.forEach(function (key) {
        const record = run.entries.get(key);
        const page = withheld.shown.indexOf(key) >= 0 ? undefined : run.pageOf.get(key);
        keepRecovered(recovered, record.parsed, record, run.junk.has(key), page);
      });
      if (own) recovered.pages = recovered.pages.filter(function (page) { return page.before !== 0; });
      run.pagesKept.forEach(function (page, before) {
        recovered.pages = recovered.pages.filter(function (kept) { return kept.before !== before; });
        recovered.pages.push({ before: before, t: now, more: page.more, keys: page.keys });
      });
      saveRecovered(keys, recovered);
    }
    const told = tellStatus(status, reasons, typeof log.round.told === "string" && log.round.v === VERSION ? log.round.told : "");
    saveNodes(log.nodes);
    storeJson(STORE_UNACCEPTED, log.unaccepted);
    storeJson(STORE_BLOCKED, log.blocked);
    storeJson(STORE_SAMPLE, log.sample);
    storeJson(STORE_SEEN, log.seen.list);
    storeJson(STORE_MISSING, log.missing);
    saveWithheld(run);
    saveLegacy(log.legacy);
    native.storeSet(STORE_CURSOR, log.cursor === "" ? null : log.cursor);
    storeJson(STORE_RESUME, log.resume);
    storeJson(STORE_ROUND, {
      v: VERSION, tried_ms: now, last: status, open: incomplete, told: told, state: state,
      done_ms: status === "pending" ? (log.round.v === VERSION ? whole(log.round.done_ms) : 0) : now,
      unfinished: unfinished,
    });
    logState = state;
    native.publish({ state: { log: state } });
    run.elapsedMs = Math.max(0, now - started);
    run.report = function (screenMs) {
      run.screenMs = screenMs === undefined ? null : screenMs;
      reportRound(state, run, { releases: releases, heldNodes: heldNodes, blockedRounds: log.blocked.count },
        Math.max(0, native.nowMs() - started));
    };
    if (origin !== "screen") run.report();
    return {
      log: state, pages: pages, entries: run.entries, junk: run.junk, absent: absent, report: run.report,
    };
  }

  // The round in flight (null: none). A round that a synchronization asks for while one runs takes
  // the result of the one that runs.
  let roundFlight = null;

  /** Asks for a round and waits for it within the turn of the caller. A round runs in a turn of
   *  its own (LOG_ROUND_LIMIT_MS from its start), one at a time (the round lock). */
  function requestRound(turn, keys, origin, extra) {
    if (origin === "sync" && roundFlight !== null) return limited(turn, roundFlight, Infinity, "round");
    const own = newTurn(LOG_ROUND_LIMIT_MS, "");
    const flight = roundLock.run(own, function () { return runRound(own, keys, origin, extra); }, true);
    const ended = function () {
      if (roundFlight === flight) roundFlight = null;
    };
    flight.then(ended, ended);
    roundFlight = flight;
    return limited(turn, flight, Infinity, "round");
  }

  let formats = null;

  /** Strings in the locale and time zone of the device: date is the date (medium), time the time
   *  (short), seconds the time with seconds (medium). */
  function formatTime(ms, style) {
    if (formats === null) {
      formats = {
        date: new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }),
        time: new Intl.DateTimeFormat(undefined, { timeStyle: "short" }),
        seconds: new Intl.DateTimeFormat(undefined, { timeStyle: "medium" }),
      };
    }
    return formats[style].format(new Date(whole(ms)));
  }

  /** The host of an origin string (https://host). */
  function originHost(origin) {
    const value = String(origin);
    const start = value.indexOf("://");
    const rest = start < 0 ? value : value.slice(start + 3);
    const end = rest.indexOf("/");
    return end < 0 ? rest : rest.slice(0, end);
  }

  /** The action of one provider request: read (GET or a read memo), send_mail (a mail sending
   *  path), send_message (a Slack message, a Teams chat or channel message POST), payment (a Link
   *  payment request), delete (DELETE), and change for everything else. */
  function requestAction(method, host, path, context) {
    if (path.endsWith("/send") || path.endsWith("/sendMail")) return "send_mail";
    if (path === "/api/chat.postMessage") return "send_message";
    if (method === "POST" && path.endsWith("/messages") &&
        (path.indexOf("/chats/") >= 0 || path.indexOf("/channels/") >= 0)) {
      return "send_message";
    }
    if (host === "api.link.com" && method === "POST" && path.startsWith("/spend_requests")) return "payment";
    if (method === "GET" || readMemo(context)) return "read";
    if (method === "DELETE") return "delete";
    return "change";
  }

  /** The display kind of an event (the plaintext of an entry). kind is the kind the definition
   *  chooses its wording by (request, grant_renewed, grant_revoked, connected, disconnected,
   *  signed_in, used, moved, filled, code, secret_sent, secret_saved, other), action is the action
   *  of a request (read, send_mail, send_message, payment, delete, change, verify), service is the
   *  service id of the icon and the name, detail is a value outside the wording (the expiry date,
   *  the recipients or the mailbox of a mail, the host a vault value went to, the site of a
   *  password the vault made), field is the kind of the filled vault value (for a vault secret put
   *  into a request, the slot; for a value saved by a node, the kind of its record), name is the
   *  name of a vault secret, and method and target describe one request. A vault secret a node
   *  put into a request (a provider_request of provider vault) is secret_sent, and a value a node
   *  saved into the vault (a connection_created of kind vault_secret or vault_password) is
   *  secret_saved. */
  function describeEvent(event) {
    const kind = event.t;
    const provider = typeof event.provider === "string" ? event.provider : "";
    const shown = {
      kind: "other", action: "", provider: provider, service: provider, detail: "", field: "",
      method: "", target: "", name: "",
    };
    if (kind === "grant_accepted") {
      shown.kind = "grant_renewed";
      shown.detail = formatTime(event.not_after_ms, "date");
    } else if (kind === "grant_revoked") {
      shown.kind = "grant_revoked";
    } else if (kind === "connection_created" && (event.kind === "vault_secret" || event.kind === "vault_password")) {
      shown.kind = "secret_saved";
      shown.field = event.kind;
      shown.name = typeof event.name === "string" ? event.name : "";
      shown.detail = typeof event.site === "string" ? event.site : "";
    } else if (kind === "connection_created") {
      shown.kind = "connected";
    } else if (kind === "connection_removed") {
      shown.kind = "disconnected";
    } else if (kind === "credential_refreshed") {
      shown.kind = "signed_in";
    } else if (kind === "credential_sealed") {
      shown.kind = event.renewal === true ? "signed_in" : "connected";
    } else if (kind === "credential_opened") {
      shown.kind = "used";
    } else if (kind === "grant_transferred_out" || kind === "grant_transferred_in") {
      shown.kind = "moved";
    } else if (kind === "provider_request" && provider === "vault") {
      shown.kind = "secret_sent";
      shown.name = typeof event.name === "string" ? event.name : "";
      shown.field = typeof event.slot === "string" ? event.slot : "";
      shown.method = String(event.method);
      shown.detail = String(event.host);
      shown.target = String(event.host) + String(event.path);
    } else if (kind === "provider_request") {
      const method = String(event.method);
      const host = String(event.host);
      const path = String(event.path);
      shown.kind = "request";
      shown.service = serviceOf(provider, host, path);
      shown.action = requestAction(method, host, path, event.context);
      shown.method = method;
      shown.target = host + path;
    } else if (kind === "mail_request") {
      const request = event.request || {};
      shown.kind = "request";
      shown.action = event.operation === "submit" ? "send_mail" : event.operation === "verify" ? "verify" : "read";
      shown.target = event.operation === "submit" && Array.isArray(request.recipients)
        ? request.recipients.join(", ") : String(request.mailbox || "");
    } else if (kind === "secret_released") {
      shown.kind = "filled";
      shown.field = String(event.field);
      shown.name = typeof event.name === "string" ? event.name : "";
      shown.detail = originHost(event.origin);
    } else if (kind === "totp_issued") {
      shown.kind = "code";
      shown.detail = originHost(event.origin);
    }
    return shown;
  }

  /** One opened item of the log screen for an event: the display kind and its fields (describeEvent)
   *  and the context the caller declared. */
  function eventItem(itemId, timeMs, event) {
    const described = describeEvent(event);
    return {
      id: itemId, time_ms: timeMs, kind: described.kind, action: described.action,
      provider: described.provider, service: described.service,
      context: typeof event.context === "string" ? event.context : "", detail: described.detail,
      field: described.field, method: described.method, target: described.target, name: described.name,
      verified: true,
    };
  }

  /** The items of one entry of the log screen. An entry that did not verify is one item of kind
   *  unverified (not opened), an entry of another key_id (the delegation of another key) one item of
   *  kind other_key (its signature verified, not opened), an entry of format 1 one item of its event,
   *  and an entry of format 2 one item per event (id node:seq:index, time_ms the time of the event).
   *  keyTime is the time_ms of the key of the entry (0 for a key of format 1). */
  function openEntryItems(id, seq, verified, keyTime) {
    const base = id + ":" + seq;
    if (verified === null) {
      return [{
        id: base, time_ms: keyTime, kind: "unverified", action: "", provider: "", service: "",
        context: "", detail: "", field: "", method: "", target: "", verified: false,
      }];
    }
    if (verified.events === null) {
      return [{
        id: base, time_ms: verified.time_ms, kind: "other_key", action: "", provider: "", service: "",
        context: "", detail: "", field: "", method: "", target: "", verified: true,
      }];
    }
    if (verified.format === 1) return [eventItem(base, verified.time_ms, verified.events[0])];
    return verified.events.map(function (event, index) {
      const time = whole(event.time_ms);
      return eventItem(base + ":" + index, time === 0 ? verified.time_ms : time, event);
    });
  }

  /** One request row inside a group (every item of a request group is a verified one: openEntry
   *  gives kind request to verified entries only). */
  function requestRow(item) {
    return {
      id: item.id, method: item.method, target: item.target, target_short: item.target, time_ms: item.time_ms,
      time_text: formatTime(item.time_ms, "seconds"),
    };
  }

  /** The short form of the requests of a group that share the host of the first request but have
   *  another path: `…/` followed by the last two segments of the path. A request with the same
   *  target as the first, and a request with another host, stay as they are. */
  function shortenTargets(requests) {
    if (requests.length < 2) return;
    const first = requests[0].target;
    const slash = first.indexOf("/");
    const host = slash < 0 ? first : first.slice(0, slash);
    for (let at = 1; at < requests.length; at += 1) {
      const target = requests[at].target;
      if (target === first || !target.startsWith(host + "/")) continue;
      const segments = target.slice(host.length + 1).split("/").filter(function (part) { return part !== ""; });
      if (segments.length < 2) continue;
      requests[at].target_short = "\u2026/" + segments.slice(-2).join("/");
    }
  }

  /** The day key of yesterday: the date 23 hours before now when it differs from today, otherwise
   *  (just before midnight) the date 25 hours before now. The date 24 hours before now skips a day
   *  or stays on today on the 23-hour and 25-hour days of a daylight saving transition. */
  function yesterdayKey(now, today) {
    const near = formatTime(now - 23 * 3600000, "date");
    return near === today ? formatTime(now - 25 * 3600000, "date") : near;
  }

  /** Turns the list of opened items (time_ms descending) into the list of display groups.
   *  Consecutive request items (kind request) of the same day, provider, service, action and
   *  context form one group (count is the number of request items, requests the list of requests in
   *  ascending time, time_ms the time of the latest request), and every other item is a group of its
   *  own. A node merges identical GET requests of the same address within a five-minute window into
   *  one event, so count is the number of events, not of HTTP requests. day_key is the date
   *  string of the device locale (groups of the same day share the key), day_offset is 0 for today,
   *  1 for yesterday and 2 for earlier days. The service icon (icon_image, icon_glyph) exists for
   *  request groups only; the other kinds have empty values (the definition draws the icon of the
   *  kind). */
  function displayGroups(items) {
    const now = native.nowMs();
    const today = formatTime(now, "date");
    const yesterday = yesterdayKey(now, today);
    const groups = [];
    for (const item of items) {
      const last = groups.length === 0 ? null : groups[groups.length - 1];
      const dayKey = formatTime(item.time_ms, "date");
      if (last !== null && item.kind === "request" && last.kind === "request" && last.day_key === dayKey &&
          last.provider === item.provider && last.service === item.service &&
          last.action === item.action && last.context === item.context) {
        last.count += 1;
        last.requests.unshift(requestRow(item));
        continue;
      }
      const service = SERVICES.get(item.service);
      groups.push({
        id: item.id, time_ms: item.time_ms, time_text: formatTime(item.time_ms, "time"),
        day_key: dayKey, day_offset: dayKey === today ? 0 : dayKey === yesterday ? 1 : 2,
        kind: item.kind, action: item.action, provider: item.provider,
        provider_name: item.provider === "" ? "" : providerName(item.provider),
        service: item.service, service_name: item.service === "" ? "" : serviceName(item.service),
        icon_image: item.kind !== "request" || service === undefined || service.image === ""
          ? "" : "ui_image/" + service.image,
        icon_glyph: item.kind === "request" && service !== undefined && service.glyph,
        context: item.context, context_kind: contextKind(item.context),
        detail: item.detail, field: item.field, name: typeof item.name === "string" ? item.name : "",
        count: 1, verified: item.verified,
        requests: item.kind === "request" ? [requestRow(item)] : [],
      });
    }
    for (const group of groups) shortenTargets(group.requests);
    return groups;
  }

  /** Splits the list of display groups into the list of day groups {key, offset, groups}
   *  (consecutive groups with the same day_key are one day). */
  function displayDays(groups) {
    const days = [];
    for (const group of groups) {
      const last = days.length === 0 ? null : days[days.length - 1];
      if (last !== null && last.key === group.day_key) {
        last.groups.push(group);
        continue;
      }
      days.push({ key: group.day_key, offset: group.day_offset, groups: [group] });
    }
    return days;
  }

  /** Adds one opened item to the counts of the pages read (readLogPage). A request counts by
   *  its action as reads (read, verify), changes (delete, change) or sends (everything else), and
   *  filled and code count as sends. The other kinds are not counted. providers is, per provider
   *  used, the list of the short names of the services used. */
  function countInto(summary, item) {
    if (item.kind === "request") {
      if (item.action === "read" || item.action === "verify") summary.reads += 1;
      else if (item.action === "delete" || item.action === "change") summary.changes += 1;
      else summary.sends += 1;
    } else if (item.kind === "filled" || item.kind === "code") {
      summary.sends += 1;
      return;
    } else {
      return;
    }
    let used = null;
    for (const entry of summary.providers) {
      if (entry.provider === item.provider) used = entry;
    }
    if (used === null) {
      used = { provider: item.provider, name: providerName(item.provider), services: [] };
      summary.providers.push(used);
    }
    const service = SERVICES.get(item.service);
    if (service !== undefined && service.short !== "" && used.services.indexOf(service.short) < 0) {
      used.services.push(service.short);
    }
  }

  /** The provider line of the summary: per provider, its name followed by the short names of the
   *  services used joined with " · " (the name alone when there is no service), and " / " between
   *  providers. */
  function providersText(summary) {
    return summary.providers.map(function (entry) {
      return entry.services.length === 0 ? entry.name : entry.name + " \u00b7 " + entry.services.join(", ");
    }).join(" / ");
  }

  // ---- The log screen ----
  //
  // The screen shows the entries of the account, the latest first: the entries of format 3 from
  // the two listings of the account (control and use), and below and between them the entries of
  // the chains of format 1 and format 2. An entry is shown as verified when the signature of the
  // node of its key verifies over the body its key names, and it is opened with the key of this
  // account. The first page and the summary are kept on the device, sealed with a key derived
  // from the master key, and answer the next opening before any request.

  // The chains of format 1 and format 2 the screen knows keys of (runtime lifetime). displayNodes
  // maps a node id to {candidates: Map<seq, candidate[]>, floor, exhausted, sorted}: the keys the
  // screen knows, the smallest seq whose listing was read (0 while none was), whether the listing
  // reached the start of the chain, and the seqs in descending order (null when the candidates
  // changed). displayEntries maps "node:seq" to the entry the screen opened {id, time_ms, count,
  // items}, at most LEGACY_DISPLAY_ENTRIES of them (the oldest read leaves first).
  const displayNodes = new Map();
  const displayEntries = new Map();
  // The node documents the reads of later pages learned (runtime lifetime; a round keeps its own
  // in the program store).
  const pageNodes = Object.create(null);

  function displayNode(id) {
    let node = displayNodes.get(id);
    if (node === undefined) {
      node = { candidates: new Map(), floor: 0, exhausted: false, sorted: null };
      displayNodes.set(id, node);
    }
    return node;
  }

  /** Puts the candidates of a listing (a table from seq to candidates) into the keys the screen
   *  knows of node id. The candidates of a seq already known are replaced. */
  function rememberKeys(id, entries) {
    const node = displayNode(id);
    entries.forEach(function (candidates, seq) {
      node.candidates.set(seq, candidates);
      if (node.floor === 0 || seq < node.floor) node.floor = seq;
    });
    node.sorted = null;
  }

  /** The seqs the screen knows of a chain, the largest first. */
  function sortedSeqs(node) {
    if (node.sorted === null) {
      node.sorted = Array.from(node.candidates.keys()).sort(function (a, b) { return b - a; });
    }
    return node.sorted;
  }

  /** The candidates of seq among the keys the screen knows, the latest version first, two at
   *  most (a write a node repeated adds a version of the same object). */
  function orderedCandidates(node, seq) {
    return (node.candidates.get(seq) || []).slice().sort(function (a, b) {
      return (b.isLatest ? 1 : 0) - (a.isLatest ? 1 : 0);
    }).slice(0, 2);
  }

  /** The time and the number of events the key of seq names: {time_ms, count} for a key of format
   *  2, null for a key of format 1 (the entry carries the time). */
  function keyFacts(node, seq) {
    const candidates = orderedCandidates(node, seq);
    if (candidates.length === 0 || candidates[0].parts.format !== 2) return null;
    return { time_ms: candidates[0].parts.time_ms, count: candidates[0].parts.count };
  }

  /** What a read of the log screen collects of its reads of the bucket of format 1 and format 2:
   *  the entries and the listings of chains it found held back (objectsHeld, chainsHeld: for the
   *  rounds, log.withheld), the ones it read itself (objectsRead, chainsRead: their names),
   *  whether the listings held back of a chain began or ceased to mark the log (judge), and
   *  whether the backend answered another request of this runtime around the read (reached:
   *  null until a request of the read was not answered and that was looked into, once). live(id)
   *  says whether the store is known to hold the chain of node id: the store named its prefix
   *  when the screen last listed the node prefixes (cache.found), or this device follows the
   *  chain and its entries are within the retention of the store. A backend that states it has
   *  no such store is believed for any other chain. */
  function chainReads(cache) {
    const legacy = loadLegacy();
    const now = native.nowMs();
    return {
      objectsHeld: [], objectsRead: new Set(), chainsHeld: [], chainsRead: new Set(), judge: false, reached: null,
      live: function (id) {
        if (cache.found.indexOf(id) >= 0) return true;
        const followed = legacy.nodes[id];
        return followed !== undefined && (!followed.closed || now - followed.until_ms < LOG_RETENTION_DAYS * DAY_MS);
      },
    };
  }

  /** Lists chains of format 1 and format 2 in one stage: targets are [{id, after, below, probe}]
   *  (the keys of node id above the seq after; with below, only the keys under that seq). The keys
   *  enter the keys the screen knows, unless probe is set (a listing that only looks where a chain
   *  ends). Each target receives last (the largest seq the listing named, after when none) and
   *  more (whether the listing goes on); a target whose listing failed receives neither, and
   *  failure, the failure of its read. With reads (the listings are the ones of a read of the log
   *  screen: chainReads), a listing that is held back goes to the rounds and is noted
   *  (denyChain: a request that was not answered counts when the backend answered another
   *  request of this runtime around it), and a listing that was read ends what was noted when it
   *  covers what was held back (serveChain). A backend that states it has no such store holds
   *  the listing of a chain back that the store is known to hold (reads.live). Throws a failure
   *  that is not one of the store. */
  async function loadChainKeys(turn, targets, reads) {
    const started = native.nowMs();
    const listings = await legacyListings(turn, targets.map(function (target) {
      return { node: target.id, key_marker: listingMarker(target.id, target.after), version_id_marker: null };
    }));
    for (let at = 0; at < targets.length; at += 1) {
      const target = targets[at];
      const outcome = listings[at];
      const name = [target.id, target.after, target.below === undefined ? 0 : target.below].join(":");
      if (!outcome.ok) {
        const failure = outcome.error;
        if (!isStoreFailure(failure)) throw failure;
        target.failure = failure;
        if (reads === undefined || failure.kind === "unreachable" || !(turnLeft(turn) > 0)) continue;
        if (failure.kind === "absent" && !reads.live(target.id)) continue;
        // A listing that only looks for the end of a chain is not one the rounds make again.
        if (target.probe !== true && reads.chainsHeld.length < LOG_WITHHELD_CHAINS) {
          reads.chainsHeld.push([target.id, target.after, target.below === undefined ? 0 : target.below]);
        }
        if (failure.kind === "silent" && reads.reached === null) reads.reached = await reachJudged(turn, started);
        if (failure.kind !== "silent" || reads.reached === true) {
          if (denyChain(target.id, target.after, target.below !== undefined)) reads.judge = true;
        }
        continue;
      }
      const prefix = accountPrefix() + target.id + "/";
      const entries = new Map();
      let last = target.after;
      for (const version of outcome.value.versions) {
        const parts = parseStoreKey(version.key, prefix);
        if (parts === null || parts.seq <= target.after) continue;
        if (parts.seq > last) last = parts.seq;
        if (target.below !== undefined && parts.seq >= target.below) continue;
        if (!entries.has(parts.seq)) entries.set(parts.seq, []);
        entries.get(parts.seq).push({
          key: version.key, versionId: version.versionId, isLatest: version.isLatest, parts: parts,
        });
      }
      target.more = outcome.value.truncated && outcome.value.nextKeyMarker !== null;
      target.last = last;
      if (reads !== undefined) {
        reads.chainsRead.add(name);
        if (serveChain(target.id, target)) reads.judge = true;
      }
      if (target.probe === true) continue;
      const node = displayNode(target.id);
      rememberKeys(target.id, entries);
      if (node.floor === 0 || target.after + 1 < node.floor) node.floor = target.after + 1;
      // The listing began at the start of the chain, or named nothing under the keys known
      // (everything below is gone with its retention): there is nothing further down.
      if (target.after === 0 || (target.below !== undefined && entries.size === 0)) node.exhausted = true;
    }
  }

  /** Finds the end of a chain the device knows no seq of: listings that only look (probe), from
   *  seq 0, jumping ahead while the chain goes on and halving the range once a jump passed the
   *  end, LEGACY_TOP_STEPS at most. Returns the largest seq seen (0 for a chain without keys), or
   *  -1 when a listing failed or the listings of this call are spent. */
  async function findChainTop(turn, id, budget) {
    let known = 0;
    let high = 0;
    let jump = 4 * LEGACY_DISPLAY_LIST;
    let probe = 0;
    for (let step = 0; step < LEGACY_TOP_STEPS; step += 1) {
      if (budget.lists <= 0) return -1;
      budget.lists -= 1;
      const target = { id: id, after: probe, probe: true };
      await loadChainKeys(turn, [target], budget.reads);
      if (target.last === undefined) return -1;
      if (target.last > probe) {
        known = target.last;
        if (!target.more) return known;
        if (high !== 0 && high - known <= 1) return known;
        probe = high === 0 ? known + jump : known + Math.floor((high - known) / 2);
        if (high === 0) jump *= 4;
      } else {
        // Nothing above the probe: the end is at or below it.
        high = probe;
        if (high - known <= 1) return known;
        probe = known + Math.floor((high - known) / 2);
      }
    }
    return known;
  }

  /** The entry of seq of a chain as the screen shows it: {id, time_ms, count, items}, from the
   *  signed values of its candidate object versions (objects: a table from key and version to the
   *  signed value). The first candidate that verifies is the entry; when none does, the entry is
   *  one item that is not verified. null when no candidate was read. The entries the screen opened
   *  are kept for the runtime. */
  function legacyEntry(keys, id, seq, objects) {
    const name = id + ":" + seq;
    const kept = displayEntries.get(name);
    if (kept !== undefined) return kept;
    const node = displayNode(id);
    let verified = null;
    let keyTime = 0;
    let read = false;
    for (const candidate of orderedCandidates(node, seq)) {
      if (candidate.parts.format === 2 && keyTime === 0) keyTime = candidate.parts.time_ms;
      const signed = objects.get(candidate.key + "\n" + candidate.versionId);
      if (signed === undefined) continue;
      read = true;
      if (signed === null) continue;
      verified = checkLegacyEntry(signed, id, candidate.parts, keys);
      if (verified !== null) break;
    }
    if (!read) return null;
    const items = openEntryItems(id, seq, verified, keyTime);
    const entry = {
      id: "2:" + name, time_ms: verified !== null ? verified.time_ms : keyTime, count: items.length, items: items,
    };
    if (displayEntries.size >= LEGACY_DISPLAY_ENTRIES) {
      displayEntries.delete(displayEntries.keys().next().value);
    }
    displayEntries.set(name, entry);
    return entry;
  }

  /** The object versions of the candidates of the seqs given ([{id, seq}]) that the screen has
   *  not opened, read in batches of LOG_STORE_OBJECTS: a table from key and version to the signed
   *  value. An entry the screen holds opened (the ones the rounds read for it among them) is not
   *  asked for. With reads (chainReads), the entries of a read that is held back go to the rounds
   *  (the versions asked for under each seq), and the names of the entries read are noted. Throws
   *  a store failure. */
  async function readChainObjects(turn, wanted, reads) {
    const versions = [];
    const groups = [];
    for (const item of wanted) {
      const name = item.id + ":" + item.seq;
      if (displayEntries.has(name)) continue;
      const candidates = orderedCandidates(displayNode(item.id), item.seq);
      if (candidates.length > 0) groups.push({ name: name, versions: candidates });
      for (const candidate of candidates) versions.push(candidate);
    }
    const objects = new Map();
    try {
      for (let at = 0; at < versions.length; at += LOG_STORE_OBJECTS) {
        const batch = await legacyObjects(turn, versions.slice(at, at + LOG_STORE_OBJECTS));
        batch.forEach(function (value, name) { objects.set(name, value); });
      }
    } catch (failure) {
      // A read the backend refused or did not answer (a read that failed with the network of the
      // device is one the rounds answer then). The keys were named by a listing of the store, so
      // a backend that states it has no such store holds them back.
      if (reads !== undefined && isStoreFailure(failure) && failure.kind !== "unreachable" && turnLeft(turn) > 0) {
        for (const group of groups) {
          if (reads.objectsHeld.length >= LOG_WITHHELD_OBJECTS) break;
          reads.objectsHeld.push(group.versions.map(function (candidate) { return [candidate.key, candidate.versionId]; }));
        }
      }
      throw failure;
    }
    if (reads !== undefined) {
      for (const group of groups) reads.objectsRead.add(group.name);
    }
    return objects;
  }

  /** Puts the entries of chains that the rounds opened for the screen (log.recovered) among the
   *  entries the screen holds opened: the screen asks for none of them. */
  function useRecoveredChains(recovered) {
    recovered.entries.forEach(function (kept, id) {
      if (id.slice(0, 2) !== "2:" || kept.e === null) return;
      const name = id.slice(2);
      if (!displayEntries.has(name)) displayEntries.set(name, kept.e);
    });
  }

  /** Hands the reads of the bucket of format 1 and format 2 that a read of the screen found held
   *  back to the rounds, and takes the ones it read itself from the reads the rounds make again
   *  (reads: chainReads; nodesHeld and nodesRead: the same for the node discovery listing). When
   *  the listings held back of a chain began or ceased to mark the log, a round judges and
   *  publishes that now. */
  function saveChainReads(keys, reads, nodesHeld, nodesRead) {
    if (reads.objectsHeld.length > 0 || reads.chainsHeld.length > 0 || nodesHeld || native.storeGet(STORE_WITHHELD) !== null) {
      saveWithheld({
        withheld: new Set(), shown: new Set(), settled: new Set(), pagesHeld: new Set(), pagesRead: new Set(),
        objectsHeld: reads.objectsHeld, objectsRead: reads.objectsRead, chainsHeld: reads.chainsHeld,
        chainsRead: reads.chainsRead, nodesHeld: nodesHeld, nodesRead: nodesRead,
      });
    }
    if (reads.judge) requestRound(freeTurn(), keys, "sync").then(noop, noop);
  }

  /** Makes again the reads of the bucket of format 1 and format 2 that a read of the log screen
   *  found held back (withheld: log.withheld), as a part of a round: the node discovery listing,
   *  the listings of chains, each from the seq the screen asked for, and the entries, each the
   *  object versions the screen asked for. A read that is still held back is noted on run (the
   *  round is one held back) and stays with the rounds. What is read is for the screen: the
   *  node prefixes (run.found) and the entries, opened as the screen opens them (run.chainKept),
   *  are kept (log.recovered), and the keys of a listing enter the keys the screen knows for the
   *  time of this runtime. */
  async function rereadChains(turn, keys, run, withheld) {
    if (withheld.nodes) {
      try {
        run.found = await discoverLegacyNodes(turn);
        run.nodesRead = true;
      } catch (failure) {
        noteFailure(turn, run, heldBack(failure));
      }
    }
    if (withheld.chains.length > 0) {
      const targets = withheld.chains.map(function (chain) {
        return chain[2] === 0 ? { id: chain[0], after: chain[1] } : { id: chain[0], after: chain[1], below: chain[2] };
      });
      await loadChainKeys(turn, targets);
      for (let at = 0; at < targets.length; at += 1) {
        if (targets[at].failure !== undefined) noteFailure(turn, run, heldBack(targets[at].failure));
        else run.chainsRead.add(withheld.chains[at].join(":"));
      }
    }
    if (withheld.objects.length === 0) return;
    const wanted = [];
    for (const versions of withheld.objects) {
      for (const version of versions) wanted.push({ key: version[0], versionId: version[1] });
    }
    let objects = null;
    try {
      objects = await legacyObjects(turn, wanted.slice(0, LOG_STORE_OBJECTS));
    } catch (failure) {
      noteFailure(turn, run, heldBack(failure));
      return;
    }
    for (const versions of withheld.objects) {
      const name = objectName(versions);
      if (name === "") continue;
      const id = name.slice(0, 43);
      const seq = Number(name.slice(44));
      let verified = null;
      let keyTime = 0;
      for (const version of versions) {
        const parts = parseStoreKey(version[0], accountPrefix() + id + "/");
        if (parts === null) continue;
        if (parts.format === 2 && keyTime === 0) keyTime = parts.time_ms;
        const signed = objects.get(version[0] + "\n" + version[1]);
        if (signed === undefined || signed === null) continue;
        verified = checkLegacyEntry(signed, id, parts, keys);
        if (verified !== null) break;
      }
      const items = openEntryItems(id, seq, verified, keyTime);
      const entry = {
        id: "2:" + name, time_ms: verified !== null ? verified.time_ms : keyTime, count: items.length, items: items,
      };
      run.chainKept.push({ name: name, entry: entry });
      run.objectsRead.add(name);
      displayEntries.set(name, entry);
    }
  }

  /** The nodes whose chains of format 1 and format 2 the screen shows: the chains this device
   *  follows, the node prefixes the node discovery listing named, and the nodes the screen knows
   *  keys of. */
  function chainNodes(cache) {
    const ids = Object.keys(loadLegacy().nodes);
    for (const id of cache.found) {
      if (ids.indexOf(id) < 0) ids.push(id);
    }
    displayNodes.forEach(function (node, id) {
      if (ids.indexOf(id) < 0 && node.candidates.size > 0) ids.push(id);
    });
    return ids;
  }

  /** What the device knows of the end of a chain the screen has not listed: {seq, time_ms} from
   *  the kept screen or from the chains this device follows; null when nothing is known. */
  function chainHint(cache, legacy, id) {
    const kept = cache.tops[id];
    const followed = legacy.nodes[id];
    if (kept !== undefined && (followed === undefined || kept.seq >= followed.seq)) return kept;
    return followed === undefined ? null : { seq: followed.seq, time_ms: followed.time_ms };
  }

  /** The next step of one chain for a page of entries before beforeMs, below the seq pointer:
   *    {step: "entry", seq, time, count}  its next entry, with the time and the number of events
   *                                       its key names (for a chain of format 1, whose keys name
   *                                       no time, of the entry the screen opened)
   *    {step: "top", hint, time}          the chain is not listed yet: time is the time the
   *                                       device knows of its end (Infinity when it knows none)
   *    {step: "below", time}              the keys listed are used up and the chain goes on below
   *                                       them: time is the time of the lowest key listed
   *    {step: "open", seqs, time}         a chain of format 1 whose next entries are not opened
   *  time is the latest time the next entry of the chain can have. null when the chain has no
   *  entry left for the page. */
  function nextOfChain(cache, legacy, id, pointer, beforeMs) {
    const node = displayNode(id);
    if (node.candidates.size === 0) {
      if (node.exhausted) return null;
      const hint = chainHint(cache, legacy, id);
      return { id: id, step: "top", hint: hint, time: hint === null || hint.time_ms === 0 ? Infinity : hint.time_ms };
    }
    const seqs = sortedSeqs(node);
    let lowest = Infinity;
    const unopened = [];
    for (const seq of seqs) {
      if (seq >= pointer) continue;
      const facts = keyFacts(node, seq);
      if (facts !== null) {
        lowest = facts.time_ms;
        if (facts.time_ms < beforeMs) return { id: id, step: "entry", seq: seq, time: facts.time_ms, count: facts.count };
        continue;
      }
      const opened = displayEntries.get(id + ":" + seq);
      if (opened === undefined) {
        unopened.push(seq);
        if (unopened.length >= LOG_SCREEN_EVENTS) break;
        continue;
      }
      if (unopened.length > 0) break;
      lowest = opened.time_ms;
      if (opened.time_ms < beforeMs) return { id: id, step: "entry", seq: seq, time: opened.time_ms, count: 1 };
    }
    if (unopened.length > 0) {
      const hint = cache.tops[id];
      const bound = lowest !== Infinity ? lowest : hint !== undefined && hint.time_ms !== 0 ? hint.time_ms : Infinity;
      return { id: id, step: "open", seqs: unopened, time: bound };
    }
    if (!node.exhausted && node.floor > 1) return { id: id, step: "below", time: lowest };
    return null;
  }

  /** The entries of the chains of format 1 and format 2 before beforeMs, the latest first, until
   *  their events reach limit or the next one is not later than floorMs (0: no such bound; the
   *  entries of the same millisecond as the last one stay on the page). The chains are merged by
   *  the times their keys name; a chain the screen has not listed takes part with the time the
   *  device knows of its end and is listed when its turn comes, so a chain older than the page
   *  costs no request. budget bounds the listings of this call (lists). Returns {entries, more}:
   *  more says that entries before the last one exist or may exist. Throws a store failure. */
  async function chainPage(turn, keys, cache, beforeMs, limit, floorMs, budget) {
    const legacy = loadLegacy();
    const ids = chainNodes(cache);
    const pointers = new Map();
    const done = new Set();
    const chosen = [];
    let count = 0;
    let lastMs = 0;
    let more = false;
    let opens = 2;
    const turns = limit + 4 * ids.length + 3 * LEGACY_SCREEN_LISTS + 16;
    let round = 0;
    for (; round < turns; round += 1) {
      let best = null;
      for (const id of ids) {
        if (done.has(id)) continue;
        const next = nextOfChain(cache, legacy, id, pointers.has(id) ? pointers.get(id) : Infinity, beforeMs);
        if (next === null) {
          done.add(id);
          continue;
        }
        if (best === null || next.time > best.time || (next.time === best.time && next.id < best.id)) best = next;
      }
      if (best === null) break;
      const under = floorMs > 0 && best.time <= floorMs;
      if (best.step === "entry") {
        if (under || (count >= limit && best.time !== lastMs)) {
          more = true;
          break;
        }
        chosen.push(best);
        count += best.count;
        lastMs = best.time;
        pointers.set(best.id, best.seq);
        continue;
      }
      // The chain is listed or opened before its next entry is known; best.time bounds the time of
      // that entry from above. A chain that lies before this page is left for a later page.
      if (under || (count >= limit && best.time < lastMs)) {
        more = true;
        done.add(best.id);
        continue;
      }
      const node = displayNode(best.id);
      if (best.step === "open") {
        if (opens <= 0) {
          more = true;
          break;
        }
        opens -= 1;
        const objects = await readChainObjects(
          turn, best.seqs.map(function (seq) { return { id: best.id, seq: seq }; }), budget.reads);
        for (const seq of best.seqs) {
          if (legacyEntry(keys, best.id, seq, objects) === null) {
            displayEntries.set(best.id + ":" + seq, {
              id: "2:" + best.id + ":" + seq, time_ms: 0, count: 1, items: openEntryItems(best.id, seq, null, 0),
            });
          }
        }
        const top = displayEntries.get(best.id + ":" + sortedSeqs(node)[0]);
        if (top !== undefined) cache.tops[best.id] = { seq: sortedSeqs(node)[0], time_ms: top.time_ms };
        continue;
      }
      if (budget.lists <= 0) {
        more = true;
        break;
      }
      if (best.step === "top") {
        const top = best.hint === null ? await findChainTop(turn, best.id, budget) : best.hint.seq;
        const target = { id: best.id, after: Math.max(0, top - LEGACY_DISPLAY_LIST) };
        if (top >= 0 && budget.lists > 0) {
          budget.lists -= 1;
          await loadChainKeys(turn, [target], budget.reads);
        }
        if (target.last === undefined) {
          more = true;
          done.add(best.id);
          continue;
        }
        if (node.candidates.size === 0) node.exhausted = true;
      } else {
        budget.lists -= 1;
        const below = node.floor;
        const target = { id: best.id, after: Math.max(0, below - LEGACY_DISPLAY_LIST - 1), below: below };
        await loadChainKeys(turn, [target], budget.reads);
        if (target.last === undefined) {
          more = true;
          done.add(best.id);
          continue;
        }
      }
      const seqs = sortedSeqs(node);
      if (seqs.length > 0) {
        const facts = keyFacts(node, seqs[0]);
        if (facts !== null) cache.tops[best.id] = { seq: seqs[0], time_ms: facts.time_ms };
      }
    }
    if (round >= turns) more = true;
    const objects = await readChainObjects(turn, chosen, budget.reads);
    const entries = [];
    for (const item of chosen) {
      const entry = legacyEntry(keys, item.id, item.seq, objects);
      if (entry !== null) entries.push(entry);
    }
    return { entries: entries, more: more };
  }

  // ---- The kept screen ----

  function emptyTally() {
    return { buckets: {}, top: "", floor: "", chains: {} };
  }

  function emptyCache() {
    return {
      v: 1, saved_ms: 0, listed_ms: 0, entries: [], has_more: false, tally: emptyTally(), tops: {}, found: [],
      found_ms: 0,
    };
  }

  function cacheAad(keys) {
    return encode(utf8(purpose("log-cache") + "\n" + userId() + "\n" + keys.keyId));
  }

  /** The kept screen of this device and key: the entries of the first page it showed last (and
   *  the time the screen last read the listings of that page itself, listed_ms), the summary
   *  tally, and what it knows of the chains of format 1 and format 2. The value names
   *  services and addresses, so the program store holds it sealed with a key derived from the
   *  master key (ChaCha20-Poly1305, a fresh nonce). A value of another key, or one that does not
   *  open, is no kept screen. */
  function loadCache(keys) {
    const cache = emptyCache();
    const sealed = storedJson(STORE_CACHE, null);
    if (sealed === null || typeof sealed !== "object" || sealed.key_id !== keys.keyId ||
        typeof sealed.nonce !== "string" || typeof sealed.ct !== "string") {
      return cache;
    }
    let kept = null;
    try {
      kept = JSON.parse(text(decode(native.aeadOpen({
        alg: "chacha20poly1305", key: keys.cacheKey, nonce: sealed.nonce, aad: cacheAad(keys), ciphertext: sealed.ct,
      }))));
    } catch (error) {
      return cache;
    }
    if (kept === null || typeof kept !== "object" || kept.v !== 1) return cache;
    cache.saved_ms = whole(kept.saved_ms);
    cache.listed_ms = whole(kept.listed_ms);
    cache.has_more = kept.has_more === true;
    for (const entry of Array.isArray(kept.entries) ? kept.entries : []) {
      if (entry !== null && typeof entry === "object" && typeof entry.id === "string" && Array.isArray(entry.items)) {
        cache.entries.push({ id: entry.id, time_ms: whole(entry.time_ms), count: whole(entry.count), items: entry.items });
      }
    }
    const tally = kept.tally;
    if (tally !== null && typeof tally === "object" && tally.buckets !== null && typeof tally.buckets === "object") {
      cache.tally = {
        buckets: tally.buckets, top: typeof tally.top === "string" ? tally.top : "",
        floor: typeof tally.floor === "string" ? tally.floor : "",
        chains: tally.chains !== null && typeof tally.chains === "object" ? tally.chains : {},
      };
    }
    const tops = kept.tops !== null && typeof kept.tops === "object" ? kept.tops : {};
    for (const id of Object.keys(tops)) {
      if (NODE_ID.test(id) && tops[id] !== null && typeof tops[id] === "object") {
        cache.tops[id] = { seq: whole(tops[id].seq), time_ms: whole(tops[id].time_ms) };
      }
    }
    for (const id of Array.isArray(kept.found) ? kept.found : []) {
      if (typeof id === "string" && NODE_ID.test(id) && cache.found.indexOf(id) < 0) cache.found.push(id);
    }
    cache.found_ms = whole(kept.found_ms);
    return cache;
  }

  function saveCache(keys, cache) {
    const nonce = native.randomBytes(12);
    const ct = native.aeadSeal({
      alg: "chacha20poly1305", key: keys.cacheKey, nonce: nonce, aad: cacheAad(keys),
      plaintext: encode(utf8(JSON.stringify(cache))),
    });
    storeJson(STORE_CACHE, { v: 1, key_id: keys.keyId, nonce: nonce, ct: ct });
  }

  // ---- What the rounds read for the screen (log.recovered) ----
  //
  // A read of the log screen that was held back is made again by the rounds (log.withheld). What
  // a round reads that way is kept here, and the screen takes it from here: an entry before the
  // screen asks for it, a listing page when the read of the screen for it is held back again. So
  // an answer the backend gives a round is an answer the user sees, whichever requests the
  // backend chooses to answer. The value names services and addresses: it is sealed as the kept
  // screen is, with the same key and its own associated data. It is read and written in one
  // step wherever it is changed (a round and a read of the screen may end in either order), and
  // it is written before the read it answers leaves log.withheld.

  function emptyRecovered() {
    return { entries: new Map(), pages: [], found: null };
  }

  function recoveredAad(keys) {
    return encode(utf8(purpose("log-recovered") + "\n" + userId() + "\n" + keys.keyId));
  }

  /** What the rounds read for the screen, as this device and key keep it: {entries, pages,
   *  found}. entries is a table from the id of an entry of the screen ("3:" and the tail of a
   *  key of format 3, "2:" and node:seq for an entry of a chain of format 1 or format 2) to
   *  {t, m, e, page}: the time it was kept, the time of the entry, the entry as the screen shows
   *  it ({id, time_ms, count, items}), or null for an object a round found to be no entry, and,
   *  for an entry that is kept as part of a listing page and for no other reason, the time that
   *  page begins below (undefined for an entry kept because the screen asked for its key and the
   *  read was held back). pages are the listing pages of the screen the rounds read again:
   *  {before, t, more, keys} (the time the page begins below, 0 for the page that begins the two
   *  listings; the time it was kept; whether the listings go on below it; the keys of the page,
   *  the latest first). found is the node prefixes of the bucket of format 1 and format 2 a
   *  round read again ({t, ids}), or null. An entry older than the retention of the store is
   *  left out. A value of another key, or one that does not open, is no kept value. */
  function loadRecovered(keys) {
    const recovered = emptyRecovered();
    const sealed = storedJson(STORE_RECOVERED, null);
    if (sealed === null || typeof sealed !== "object" || sealed.key_id !== keys.keyId ||
        typeof sealed.nonce !== "string" || typeof sealed.ct !== "string") {
      return recovered;
    }
    let kept = null;
    try {
      kept = JSON.parse(text(decode(native.aeadOpen({
        alg: "chacha20poly1305", key: keys.cacheKey, nonce: sealed.nonce, aad: recoveredAad(keys), ciphertext: sealed.ct,
      }))));
    } catch (error) {
      return recovered;
    }
    if (kept === null || typeof kept !== "object" || kept.v !== 1) return recovered;
    const horizon = native.nowMs() - LOG_RETENTION_DAYS * DAY_MS;
    const take = function (items, page) {
      for (const item of Array.isArray(items) ? items : []) {
        if (!Array.isArray(item) || typeof item[0] !== "string" || whole(item[2]) < horizon) continue;
        const entry = item[3];
        const shaped = entry === null || (typeof entry === "object" && typeof entry.id === "string" && Array.isArray(entry.items));
        if (!shaped || (page !== undefined && recovered.entries.has(item[0]))) continue;
        recovered.entries.set(item[0], {
          t: whole(item[1]), m: whole(item[2]), page: page,
          e: entry === null ? null : { id: entry.id, time_ms: whole(entry.time_ms), count: whole(entry.count), items: entry.items },
        });
      }
    };
    take(kept.entries, undefined);
    for (const item of Array.isArray(kept.pages) ? kept.pages : []) {
      if (!Array.isArray(item) || !Number.isSafeInteger(item[0]) || item[0] < 0 || !Array.isArray(item[3])) continue;
      const parsed = [];
      for (const name of item[3]) {
        const letter = typeof name === "string" ? name.slice(0, 1) : "";
        const key = letter === "c" || letter === "u" ? parseEntryKey(entryPrefix(letter) + name.slice(1), letter) : null;
        if (key !== null) parsed.push(key);
      }
      if (parsed.length !== item[3].length) continue;
      recovered.pages.push({ before: item[0], t: whole(item[1]), more: item[2] === true, keys: parsed });
      take(item[4], item[0]);
    }
    const found = kept.found;
    if (found !== null && typeof found === "object" && Array.isArray(found.ids)) {
      recovered.found = {
        t: whole(found.t),
        ids: found.ids.filter(function (id) { return typeof id === "string" && NODE_ID.test(id); }).slice(0, 2 * LEGACY_NODES),
      };
    }
    return recovered;
  }

  /** Writes what the rounds read for the screen. The entries kept because the screen asked for
   *  their keys have limits of their own: beyond LOG_RECOVERED_KEYS of them or
   *  LOG_RECOVERED_EVENTS events, the ones kept first leave first (among the ones kept at the
   *  same time, the earliest entry). The entries of a listing page are kept with that page and
   *  leave with it, so they take no place from the former. Beyond LOG_RECOVERED_PAGES listing
   *  pages, the pages kept first leave. Beyond LOG_RECOVERED_BYTES of the value, an entry the
   *  screen asked for or a listing page leaves, whichever was kept first. Nothing kept: no
   *  value. */
  function saveRecovered(keys, recovered) {
    recovered.pages = recovered.pages.slice(-LOG_RECOVERED_PAGES);
    // The entries kept as parts of listing pages, with each kept page that names them.
    const paged = new Map();
    for (const page of recovered.pages) {
      const held = [];
      for (const parsed of page.keys) {
        const kept = recovered.entries.get("3:" + parsed.tail);
        if (kept !== undefined && kept.page !== undefined) held.push(["3:" + parsed.tail, kept.t, kept.m, kept.e]);
      }
      paged.set(page.before, held);
    }
    const asked = [];
    let events = 0;
    recovered.entries.forEach(function (kept, id) {
      if (kept.page !== undefined) return;
      asked.push(id);
      events += kept.e === null ? 0 : kept.e.items.length;
    });
    asked.sort(function (x, y) {
      const a = recovered.entries.get(x);
      const b = recovered.entries.get(y);
      return a.t !== b.t ? a.t - b.t : a.m - b.m;
    });
    let leave = 0;
    for (; leave < asked.length; leave += 1) {
      if (asked.length - leave <= LOG_RECOVERED_KEYS && events <= LOG_RECOVERED_EVENTS) break;
      const kept = recovered.entries.get(asked[leave]);
      events -= kept.e === null ? 0 : kept.e.items.length;
    }
    const entries = asked.slice(leave).map(function (id) {
      const kept = recovered.entries.get(id);
      return [id, kept.t, kept.m, kept.e];
    });
    if (entries.length === 0 && recovered.pages.length === 0 && recovered.found === null) {
      native.storeSet(STORE_RECOVERED, null);
      return;
    }
    const pages = recovered.pages.map(function (page) {
      return [
        page.before, page.t, page.more, page.keys.map(function (parsed) { return parsed.letter + parsed.tail; }),
        paged.get(page.before) || [],
      ];
    });
    // The bytes kept have a limit as well (LOG_RECOVERED_BYTES): beyond it, what was kept first
    // leaves first, an entry the screen asked for or a listing page with its entries. (A
    // character is three bytes at most in the values the program keeps here: the bytes are
    // counted only when the characters could reach the limit.)
    let characters = 64 + JSON.stringify(recovered.found).length;
    for (const part of entries.concat(pages)) characters += JSON.stringify(part).length + 1;
    if (3 * characters > LOG_RECOVERED_BYTES) {
      const size = function (value) { return utf8(JSON.stringify(value)).length + 1; };
      const entrySizes = entries.map(size);
      const pageSizes = pages.map(size);
      let bytes = 64 + size(recovered.found);
      for (const part of entrySizes.concat(pageSizes)) bytes += part;
      while (bytes > LOG_RECOVERED_BYTES && entries.length + pages.length > 0) {
        const entryAt = entries.length > 0 ? entries[0][1] : Infinity;
        const pageAt = pages.length > 0 ? pages[0][1] : Infinity;
        if (entryAt <= pageAt) {
          entries.shift();
          bytes -= entrySizes.shift();
        } else {
          pages.shift();
          bytes -= pageSizes.shift();
        }
      }
    }
    if (entries.length === 0 && pages.length === 0 && recovered.found === null) {
      native.storeSet(STORE_RECOVERED, null);
      return;
    }
    const nonce = native.randomBytes(12);
    const ct = native.aeadSeal({
      alg: "chacha20poly1305", key: keys.cacheKey, nonce: nonce, aad: recoveredAad(keys),
      plaintext: encode(utf8(JSON.stringify({ v: 1, entries: entries, pages: pages, found: recovered.found }))),
    });
    storeJson(STORE_RECOVERED, { v: 1, key_id: keys.keyId, nonce: nonce, ct: ct });
  }

  /** An entry of the screen as log.recovered keeps it: the same entry with every string of its
   *  items cut to LOG_RECOVERED_TEXT characters (the last one an ellipsis). */
  function clippedEntry(entry) {
    const clip = function (value) {
      if (typeof value !== "string" || value.length <= LOG_RECOVERED_TEXT) return value;
      return value.slice(0, LOG_RECOVERED_TEXT - 1) + "\u2026";
    };
    return {
      id: entry.id, time_ms: entry.time_ms, count: entry.count,
      items: entry.items.map(function (item) {
        const kept = {};
        for (const name of Object.keys(item)) kept[name] = clip(item[name]);
        return kept;
      }),
    };
  }

  /** Keeps what a round read under a key of format 3 for the screen: the entry as the screen
   *  shows it (record: what readEntries left for the key), or the finding that the object is no
   *  entry (junk). page is the time the listing page begins below that the entry is kept as a
   *  part of, or undefined for an entry kept because the screen asked for its key. An entry kept
   *  before under that key is replaced and counts as kept now; one that was kept because the
   *  screen asked for it stays kept for that reason. */
  function keepRecovered(recovered, parsed, record, junk, page) {
    const id = "3:" + parsed.tail;
    const before = recovered.entries.get(id);
    recovered.entries.delete(id);
    recovered.entries.set(id, {
      t: native.nowMs(), m: parsed.time_ms, e: junk ? null : clippedEntry(entryOfRecord(parsed, record)),
      page: before !== undefined && before.page === undefined ? undefined : page,
    });
  }

  /** The page of the screen for the entries before beforeMs (Infinity: from the start of the two
   *  listings), made from a listing page the rounds kept: {chosen, more, count, t}, as choosePage
   *  returns it, with the time the page was kept. A kept page answers when it begins at that time
   *  or above it and reaches below it: its keys before that time are every key the listings named
   *  from there down to its last key. Among several, the one kept last. null when no kept page
   *  covers that time. */
  function recoveredPage(recovered, beforeMs, limit) {
    let best = null;
    for (const page of recovered.pages) {
      if (page.keys.length === 0 || (page.before !== 0 && page.before < beforeMs)) continue;
      if (!(beforeMs > page.keys[page.keys.length - 1].time_ms)) continue;
      if (best === null || page.t > best.t) best = page;
    }
    if (best === null) return null;
    const below = best.keys.filter(function (parsed) { return parsed.time_ms < beforeMs; });
    const chosen = [];
    let count = 0;
    let at = 0;
    for (; at < below.length; at += 1) {
      const parsed = below[at];
      if (count >= limit && parsed.time_ms !== chosen[chosen.length - 1].time_ms) break;
      chosen.push(parsed);
      count += parsed.count;
    }
    return { chosen: chosen, more: at < below.length || best.more, count: count, t: best.t };
  }

  /** Forgets the listing page the rounds kept for the page that begins below before (0: the page
   *  that begins the two listings), once the screen read that page itself. recovered is what the
   *  caller read; the kept value is read again and written in the same step. */
  function dropRecoveredPage(keys, recovered, before) {
    if (!recovered.pages.some(function (page) { return page.before === before; })) return;
    const kept = loadRecovered(keys);
    kept.pages = kept.pages.filter(function (page) { return page.before !== before; });
    saveRecovered(keys, kept);
  }

  // ---- The reads held back from the screen that the screen notes itself (log.denied) ----
  //
  // Two kinds of listings are read by the screen alone and cannot be kept for it in a form that
  // answers every later read: a later page of the listings of format 3, which is asked for by
  // the time it begins below (that time moves with every entry that arrives above it, so a
  // listing page the rounds kept answers the read that was held back and a read near it, and
  // not every later one), and the listing of a chain of format 1 or format 2, whose keys the
  // device keeps for a runtime only. So what the operator domain holds back of these is noted
  // by the reads of the screen themselves, whatever the rounds read in between. The device
  // keeps the reads held back that the screen has not read since, one for each
  // LOG_DENIED_INTERVAL_MS in which a read was held back (a read is made again by the user and
  // by the screen within seconds, so the reads of one day are one: a read held back within that
  // time of the last one noted is taken into it):
  //   a read of a later page that is held back, and that nothing the rounds kept answers, is
  //   noted with the time the page begins below (the lowest such time of its day). It ends when
  //   the screen itself reads listings that name the keys of that page (the screen then makes
  //   the page itself), or a listing that begins at or below that time for at least as many
  //   events (the page that was held back was then shown, or a page below it). A page that is
  //   held back and then given ends what was noted for it, and nothing noted for a page below
  //   it;
  //   a listing of a chain that is held back is noted with the seq it began after (the lowest
  //   of its day). The screen lists a chain from its end downward, each listing below the one
  //   before, so the listing that was held back stands in the way of every listing below it. It
  //   ends when the screen itself reads a listing of that chain that covers what was held back
  //   (serveChain).
  // The reads noted of one kind (the later pages, or the listings of one chain) mark the log as
  // the count of the rounds held back does: LOG_BLOCKED_ROUNDS of them, the first LOG_BLOCKED_MS
  // old. A read noted that is not among reads that mark the log ends LOG_DENIED_KEPT_MS after it
  // was noted: the reads that mark the log are reads held back on three days within that time,
  // none of which the screen has read since. Reads that mark the log stay until the screen
  // reads what was held back, or until the last of them is LOG_DENIED_KEPT_MS old: the screen
  // then made no such read for that long, and a mark that nothing confirms any more ends.

  /** The reads held back from the screen that the screen has not read since: {pages, chains}.
   *  pages are the later pages, the earliest first: [{t, before_ms, limit}] (the time the read
   *  was noted, the lowest time a page held back on its day begins below, the most events such
   *  a page was asked for). chains maps a node id to the listings of its chain, the earliest
   *  first: [{t, after, deep}] (the lowest seq a listing held back on its day began after, and
   *  whether one of them was a listing below the keys the screen knew). A read noted that is
   *  LOG_DENIED_KEPT_MS old is left out, unless it is among reads that mark the log and the
   *  last of those is younger than that. A time that lies after now is the clock of the device
   *  having run backwards: it counts as now. */
  function loadDenied() {
    const kept = storedObject(STORE_DENIED);
    const now = native.nowMs();
    const reads = function (items, shaped) {
      const list = [];
      for (const item of Array.isArray(items) ? items : []) {
        if (item === null || typeof item !== "object" || !(whole(item.t) > 0)) continue;
        const read = shaped(item);
        if (read === null) continue;
        read.t = Math.min(whole(item.t), now);
        list.push(read);
      }
      list.sort(function (a, b) { return a.t - b.t; });
      const all = list.slice(0, LOG_DENIED_READS);
      // Reads that mark the log stay together while the last of them is young enough; any
      // other read ends by its own age.
      if (heldLong(all, now)) return now - all[all.length - 1].t < LOG_DENIED_KEPT_MS ? all : [];
      return all.filter(function (read) { return now - read.t < LOG_DENIED_KEPT_MS; });
    };
    const denied = {
      pages: reads(kept.pages, function (item) {
        return whole(item.before_ms) > 0
          ? { t: 0, before_ms: whole(item.before_ms), limit: Math.max(1, whole(item.limit)) } : null;
      }),
      chains: Object.create(null),
    };
    const chains = kept.chains !== null && typeof kept.chains === "object" ? kept.chains : {};
    for (const id of Object.keys(chains).slice(0, LOG_DENIED_CHAINS)) {
      if (!NODE_ID.test(id)) continue;
      const list = reads(chains[id], function (item) {
        return { t: 0, after: whole(item.after), deep: item.deep === true };
      });
      if (list.length > 0) denied.chains[id] = list;
    }
    return denied;
  }

  /** Writes the reads held back from the screen. Above LOG_DENIED_CHAINS chains, a chain whose
   *  reads do not mark the log leaves before one whose reads do, and among those the chain
   *  whose last read is the oldest. Nothing noted: no value. */
  function saveDenied(denied) {
    const now = native.nowMs();
    const ids = Object.keys(denied.chains);
    const rank = function (id) {
      const list = denied.chains[id];
      return [heldLong(list, now) ? 1 : 0, list[list.length - 1].t];
    };
    ids.sort(function (x, y) {
      const a = rank(x);
      const b = rank(y);
      return a[0] !== b[0] ? a[0] - b[0] : a[1] - b[1];
    });
    for (const id of ids.slice(0, Math.max(0, ids.length - LOG_DENIED_CHAINS))) delete denied.chains[id];
    const empty = denied.pages.length === 0 && Object.keys(denied.chains).length === 0;
    storeJson(STORE_DENIED, empty ? null : denied);
  }

  /** Whether a list of reads held back ([{t}], the earliest first) marks the log at the time
   *  now: LOG_BLOCKED_ROUNDS reads, the first of them LOG_BLOCKED_MS old. */
  function heldLong(reads, now) {
    return reads.length >= LOG_BLOCKED_ROUNDS && now - reads[0].t >= LOG_BLOCKED_MS;
  }

  /** The time of the first read of the earliest list of reads held back from the screen that
   *  marks the log at the time now (0: none marks it). */
  function deniedSince(denied, now) {
    let first = 0;
    const lists = Object.keys(denied.chains).map(function (id) { return denied.chains[id]; });
    lists.push(denied.pages);
    for (const reads of lists) {
      if (heldLong(reads, now) && (first === 0 || reads[0].t < first)) first = Math.max(1, reads[0].t);
    }
    return first;
  }

  /** Notes a read held back at the time now in a list of such reads: as one more read (read)
   *  when the last one of the list was noted LOG_DENIED_INTERVAL_MS ago or longer and the list
   *  has room (LOG_DENIED_READS), and otherwise within the last one (merge(last)). The device
   *  makes a round again by itself, with every synchronization, so rounds held back in a row
   *  are attempts spread over time. A read of the screen is made again by the user and by the
   *  screen within seconds, so the reads of one day are one. */
  function noteDenied(reads, now, read, merge) {
    const last = reads.length === 0 ? null : reads[reads.length - 1];
    if (last === null || (now - last.t >= LOG_DENIED_INTERVAL_MS && reads.length < LOG_DENIED_READS)) reads.push(read);
    else merge(last);
  }

  /** Notes a read of a later page of the screen that was held back (the page begins below
   *  beforeMs and was asked for limit events). Returns whether the later pages held back mark
   *  the log now. */
  function denyPage(beforeMs, limit) {
    const now = native.nowMs();
    const denied = loadDenied();
    noteDenied(denied.pages, now, { t: now, before_ms: beforeMs, limit: limit }, function (last) {
      last.before_ms = Math.min(last.before_ms, beforeMs);
      last.limit = Math.max(last.limit, limit);
    });
    saveDenied(denied);
    return heldLong(denied.pages, now);
  }

  /** Ends the later pages held back that the screen has read itself since: the listings it
   *  holds in this runtime name the keys of the page (ownPage), or the page it read now begins
   *  at or below the time of that page (beforeMs; Infinity for the page that begins the two
   *  listings) for as many events or more (limit). Returns whether the later pages held back
   *  marked the log and no longer do. */
  function servePage(beforeMs, limit) {
    const denied = loadDenied();
    if (denied.pages.length === 0) return false;
    const now = native.nowMs();
    const left = denied.pages.filter(function (kept) {
      const below = beforeMs <= kept.before_ms && limit >= kept.limit;
      return !below && ownPage(kept.before_ms, kept.limit) === null;
    });
    if (left.length === denied.pages.length) return false;
    const marked = heldLong(denied.pages, now);
    denied.pages = left;
    saveDenied(denied);
    return marked && !heldLong(left, now);
  }

  /** Notes a listing of the chain of node id that was held back from the screen (after: the
   *  seq the listing began after; below: whether it was a listing below the keys the screen
   *  knows). Returns whether the listings of that chain held back mark the log now. */
  function denyChain(id, after, below) {
    const now = native.nowMs();
    const denied = loadDenied();
    const reads = denied.chains[id] === undefined ? [] : denied.chains[id];
    noteDenied(reads, now, { t: now, after: after, deep: below }, function (last) {
      last.after = Math.min(last.after, after);
      if (below) last.deep = true;
    });
    denied.chains[id] = reads;
    saveDenied(denied);
    return heldLong(reads, now);
  }

  /** Ends the listings of the chain of node id held back that a listing the screen read itself
   *  covers (target: {after, below, probe, more}): a listing below the keys the screen knows
   *  that begins at or below the seq the one held back began after; or a listing that reaches
   *  the end of the chain, when it begins at or below that seq or when every listing held back
   *  with it was one of the end of the chain (what such a listing would have named and this one
   *  does not name lies below it now, where a listing below the keys the screen knows is what
   *  names it). A listing that only looks for the end of a chain ends nothing. Returns whether
   *  the listings of that chain held back marked the log and no longer do. */
  function serveChain(id, target) {
    if (target.probe === true || (target.below === undefined && target.more === true)) return false;
    const denied = loadDenied();
    const reads = denied.chains[id];
    if (reads === undefined) return false;
    const now = native.nowMs();
    const left = reads.filter(function (kept) {
      return target.after > kept.after && (target.below !== undefined || kept.deep);
    });
    if (left.length === reads.length) return false;
    const marked = heldLong(reads, now);
    if (left.length === 0) delete denied.chains[id];
    else denied.chains[id] = left;
    saveDenied(denied);
    return marked && !heldLong(left, now);
  }

  // ---- The summary of the last LOG_SUMMARY_DAYS days ----

  // The summary tally: what this device counted of the entries of the window, kept with the kept
  // screen. buckets maps the start of an hour (ms, as a decimal string) to the counts of the
  // events of that hour {reads, sends, changes, entries, providers}; top and floor are the tails
  // of the latest and the earliest key of format 3 counted (every key between them was counted);
  // chains maps a node id to the range {lo, hi} of the seqs of its chain of format 2 whose entries
  // were counted. An entry is counted once, each of its events into the bucket of its time.
  const SUMMARY_BUCKET_MS = 3600000;

  function summarySince(now) {
    return now - LOG_SUMMARY_DAYS * DAY_MS;
  }

  function summaryHour(ms) {
    return Math.floor(ms / SUMMARY_BUCKET_MS) * SUMMARY_BUCKET_MS;
  }

  /** Removes the buckets of the hours that ended before the window began. */
  function pruneSummary(tally, since) {
    const floor = summaryHour(since);
    for (const key of Object.keys(tally.buckets)) {
      if (!(Number(key) >= floor)) delete tally.buckets[key];
    }
  }

  function summaryBucket(tally, ms) {
    const key = String(summaryHour(ms));
    let bucket = tally.buckets[key];
    if (bucket === undefined || bucket === null || typeof bucket !== "object" || !Array.isArray(bucket.providers)) {
      bucket = { reads: 0, sends: 0, changes: 0, entries: 0, providers: [] };
      tally.buckets[key] = bucket;
    }
    return bucket;
  }

  /** Counts one opened entry into the tally: the entry into the bucket of its time and every item
   *  of it into the bucket of the time of the item. */
  function countEntryInto(tally, entry) {
    summaryBucket(tally, entry.time_ms).entries += 1;
    for (const item of entry.items) countInto(summaryBucket(tally, item.time_ms), item);
  }

  /** The entries counted into the buckets of the window (from since). */
  function summaryEntries(tally, since) {
    const floor = summaryHour(since);
    let entries = 0;
    for (const key of Object.keys(tally.buckets)) {
      if (Number(key) >= floor) entries += whole(tally.buckets[key].entries);
    }
    return entries;
  }

  /** The summary of the window from the tally {reads, sends, changes, providers_text, truncated}:
   *  the sums of the buckets from since, the providers in the order of their latest use, and
   *  truncated as given (whether entries of the window are not counted: the screen shows the
   *  counts with a plus). null when nothing was ever counted and nothing remains to count. */
  function summaryResult(tally, since, truncated) {
    const floor = summaryHour(since);
    const hours = Object.keys(tally.buckets).map(Number).filter(function (hour) { return hour >= floor; });
    if (hours.length === 0 && !truncated) return null;
    hours.sort(function (a, b) { return b - a; });
    const total = { reads: 0, sends: 0, changes: 0, providers: [] };
    for (const hour of hours) {
      const bucket = summaryBucket(tally, hour);
      total.reads += whole(bucket.reads);
      total.sends += whole(bucket.sends);
      total.changes += whole(bucket.changes);
      for (const used of bucket.providers) {
        if (used === null || typeof used !== "object" || !Array.isArray(used.services)) continue;
        let merged = null;
        for (const entry of total.providers) {
          if (entry.provider === used.provider) merged = entry;
        }
        if (merged === null) {
          merged = { provider: used.provider, name: providerName(used.provider), services: [] };
          total.providers.push(merged);
        }
        for (const service of used.services) {
          if (merged.services.indexOf(service) < 0) merged.services.push(service);
        }
      }
    }
    return {
      reads: total.reads, sends: total.sends, changes: total.changes,
      providers_text: providersText(total), truncated: truncated,
    };
  }

  /** The use keys of format 3 of the window that the tally has not counted, from the first listing
   *  page of the use prefix: the keys later than tally.top (the one nearest to it first) and the
   *  keys earlier than tally.floor (the one nearest to it first), room of them at most. When more
   *  keys are later than tally.top than LOG_SUMMARY_ENTRIES (a long absence, a very active
   *  account), the tally starts over from the latest key. Returns {above, below, reset}. */
  function summaryKeys(tally, listing, since, room) {
    const inWindow = listing.keys.filter(function (parsed) { return parsed.time_ms >= since; });
    let above = tally.top === "" ? [] : inWindow.filter(function (parsed) { return parsed.tail < tally.top; });
    let below = tally.top === "" ? inWindow : inWindow.filter(function (parsed) { return parsed.tail > tally.floor; });
    let reset = false;
    if (above.length > LOG_SUMMARY_ENTRIES) {
      reset = true;
      above = [];
      below = inWindow;
    }
    above = above.slice().reverse().slice(0, room);
    below = below.slice(0, Math.max(0, room - above.length));
    return { above: above, below: below, reset: reset };
  }

  // ---- The pages of the screen ----

  /** The items of one entry of format 3 the screen read (record: what readEntries left for its
   *  key, undefined when the entry was not read): {id, time_ms, count, items}. An entry that was
   *  not read, or whose object is not the entry its key names, is one item that is not verified
   *  (an entry that was not read is marked unread: the kept screen leaves it out);
   *  an entry of another key_id (the delegation of another key) is one item that is not opened. */
  function entryOfRecord(parsed, record) {
    const base = parsed.node + ":" + parsed.seq;
    let items = null;
    if (record === undefined || record.state !== "ok") {
      items = openEntryItems(parsed.node, parsed.seq, null, parsed.time_ms);
    } else if (!record.ours) {
      items = openEntryItems(parsed.node, parsed.seq, { time_ms: parsed.time_ms, events: null }, parsed.time_ms);
    } else {
      items = record.events.map(function (event, index) {
        const time = whole(event.time_ms);
        return eventItem(base + ":" + index, time === 0 ? parsed.time_ms : time, event);
      });
    }
    const entry = { id: "3:" + parsed.tail, time_ms: parsed.time_ms, count: parsed.count, items: items };
    // An entry whose object was not read (the answer of the bodies ended before it, or its read
    // failed) is shown as not verified in this answer and is not kept: the next read asks for it.
    if (record === undefined) entry.unread = true;
    return entry;
  }

  /** The keys of format 3 before beforeMs that the two listing pages name, the latest first, until
   *  their events reach limit (the keys of the same millisecond as the last one stay on the page).
   *  Only the range both listings cover is used: below the last key of a listing that goes on, the
   *  other listing may hold later keys. Returns {chosen, more}: more says that keys before the last
   *  chosen one exist or may exist. */
  function choosePage(pages, beforeMs, limit) {
    const lists = [pages.c, pages.u].filter(function (listing) { return listing !== null; });
    let bound = null;
    for (const listing of lists) {
      if (!listing.truncated || listing.keys.length === 0) continue;
      const last = listing.keys[listing.keys.length - 1].tail;
      if (bound === null || last < bound) bound = last;
    }
    let merged = [];
    for (const listing of lists) merged = merged.concat(listing.keys);
    merged = merged.filter(function (parsed) {
      return parsed.time_ms < beforeMs && (bound === null || parsed.tail <= bound);
    });
    // The latest first; among the entries of one millisecond, the later seq of a node first.
    merged.sort(function (a, b) {
      if (a.time_ms !== b.time_ms) return b.time_ms - a.time_ms;
      if (a.node === b.node && a.seq !== b.seq) return b.seq - a.seq;
      return a.tail < b.tail ? -1 : a.tail > b.tail ? 1 : 0;
    });
    const chosen = [];
    let count = 0;
    let at = 0;
    for (; at < merged.length; at += 1) {
      const parsed = merged[at];
      if (count >= limit && parsed.time_ms !== chosen[chosen.length - 1].time_ms) break;
      chosen.push(parsed);
      count += parsed.count;
    }
    return { chosen: chosen, more: at < merged.length || bound !== null, count: count };
  }

  /** Merges the entries of format 3 and the entries of the chains of format 1 and format 2 of one
   *  page by time, the latest first, until their events reach limit (the entries of the same
   *  millisecond as the last one stay on the page). Returns {entries, items, last_ms, has_more}:
   *  items are the items of the entries with the latest first (the events of one entry in the
   *  reverse of their index). */
  function mergePage(first, second, limit, more) {
    const all = first.concat(second).sort(function (a, b) { return b.time_ms - a.time_ms; });
    const entries = [];
    const items = [];
    let count = 0;
    let lastMs = 0;
    let left = false;
    for (const entry of all) {
      if (count >= limit && entry.time_ms !== lastMs) {
        left = true;
        break;
      }
      entries.push(entry);
      for (let at = entry.items.length - 1; at >= 0; at -= 1) items.push(entry.items[at]);
      count += entry.items.length;
      lastMs = entry.time_ms;
    }
    return { entries: entries, items: items, last_ms: lastMs, has_more: left || more };
  }

  /** The key marker of a listing of format 3 that begins below the time beforeMs: every key of an
   *  entry of that millisecond or later sorts before it. The empty string for no bound. */
  function pageMarker(letter, beforeMs) {
    if (beforeMs === Infinity) return "";
    return entryPrefix(letter) + rtimeDigits(beforeMs) + "~";
  }

  // The listings of format 3 the screen read last in this runtime (null: none): {c, u, top}, the
  // two listing pages as readListings returns them and the time they begin below (Infinity for
  // the pages that begin the two listings). A listing page of the store names up to 1,000 keys,
  // many more than one page of the screen shows, so the later pages of the screen are made from
  // these listings as far as they reach, and the backend is asked for the address of a further
  // listing page only below them.
  let screenListings = null;

  /** The page of the screen for the entries before beforeMs, made from the listings the screen
   *  read in this runtime: what choosePage returns, or null when those listings do not reach far
   *  enough. They do when they begin at or above that time and either hold a whole page above
   *  the place where one of them goes on (the page ends above the time of the last key of such
   *  a listing, so no entry of its last millisecond lies beyond it) or neither goes on. */
  function ownPage(beforeMs, limit) {
    if (screenListings === null || beforeMs > screenListings.top) return null;
    const lists = [screenListings.c, screenListings.u].filter(function (listing) {
      return listing !== null && listing.truncated && listing.keys.length > 0;
    });
    const page = choosePage(screenListings, beforeMs, limit);
    if (lists.length === 0) return page;
    let floor = 0;
    for (const listing of lists) floor = Math.max(floor, listing.keys[listing.keys.length - 1].time_ms);
    const full = page.count >= limit && page.chosen[page.chosen.length - 1].time_ms > floor;
    return full ? page : null;
  }

  /** One later page of the screen: the entries before beforeMs, read without a round. The keys
   *  of the page are taken from the listings of format 3 the screen read in this runtime, or,
   *  below them, from the two listings read from the marker of that time. The entries of the
   *  page come from the backend, each verified as a round verifies it; what the page finds
   *  changes no kept judgement (the rounds judge). An entry the rounds read for the screen
   *  (log.recovered) is taken from there and not asked for. A read the page finds held back (its
   *  listings, the document or the body of one of its keys) and a key no answer of the bodies
   *  reached are kept for the rounds, which make the read again and count it (log.withheld).
   *  When the listings of the page are held back and the rounds kept a listing page that covers
   *  that time, the page is made from it; when they kept none, the read is noted among the later
   *  pages held back from the screen (log.denied), and listings the screen then reads itself
   *  that name the keys of that page, or that begin at or below its time, end it (servePage).
   *  The entries of the chains of format 1 and format 2 are merged in. Returns the page of
   *  mergePage. */
  async function readPage(turn, keys, cache, beforeMs, limit) {
    const started = native.nowMs();
    let chosen = { chosen: [], more: false, count: 0 };
    const records = new Map();
    const junk = new Set();
    const run = {
      detail: "", blocked: false, silent: false, unreachable: false, cut: false, over: false, checked: 0, bodies: 0,
      nodes: new Set(), undocumented: new Set(), verified: [], entries: records, junk: junk,
      withheld: new Set(), shown: new Set(), kept: new Set(), settled: new Set(), pagesHeld: new Set(),
      pagesRead: new Set(), store3: true,
    };
    const log = loadLog();
    // What the rounds read for the screen: an entry kept there is not asked for.
    const recovered = loadRecovered(keys);
    let unread = false;
    let listings = null;
    // The listings the screen read in this runtime name the keys of the page when they reach
    // that far: no listing is asked for then.
    const own = ownPage(beforeMs, limit);
    try {
      if (own === null) listings = await readListings(turn, screenPages(beforeMs));
    } catch (failure) {
      if (!isStoreFailure(failure) || !(turnLeft(turn) > 0)) throw failure;
      // A backend that states it has no store of format 3 is believed by a device that knows of
      // none; for any other device that answer holds the page back.
      const absent = failure.kind === "absent" && !storeKnown(log, loadWithheld());
      if (!absent) {
        const refused = failure.kind === "absent" || failure.kind === "blocked";
        if (refused || failure.kind === "silent") run.pagesHeld.add(beforeMs);
        const page = recoveredPage(recovered, beforeMs, limit);
        if (page !== null) {
          chosen = page;
        } else {
          unread = true;
          // The operator domain held the page back (a request that was not answered counts when
          // the backend answered another request of this runtime around it), and the rounds
          // kept nothing that covers it.
          if (refused || (failure.kind === "silent" && await reachJudged(turn, started))) {
            // When the later pages held back mark the log, a round judges and publishes it now.
            if (denyPage(beforeMs, limit)) requestRound(freeTurn(), keys, "sync").then(noop, noop);
          }
        }
      }
    }
    if (listings !== null) {
      screenListings = { c: listings[0], u: listings[1], top: beforeMs };
      chosen = choosePage(screenListings, beforeMs, limit);
    } else if (own !== null) {
      chosen = own;
    }
    if (listings !== null || own !== null) {
      run.pagesRead.add(beforeMs);
      // The later pages held back that this read covers end here; when they marked the log and
      // no longer do, a round judges and publishes that now.
      if (servePage(beforeMs, limit)) requestRound(freeTurn(), keys, "sync").then(noop, noop);
      dropRecoveredPage(keys, recovered, beforeMs);
    }
    if (chosen.chosen.length > 0) {
      try {
        for (const id of Object.keys(pageNodes)) {
          if (log.nodes[id] === undefined) log.nodes[id] = pageNodes[id];
        }
        const wanted = chosen.chosen.filter(function (parsed) { return !recovered.entries.has("3:" + parsed.tail); })
          .slice(0, LOG_SCREEN_BODIES).map(function (parsed) { return { parsed: parsed, fresh: false, shown: true }; });
        await readEntries(turn, keys, log, run, wanted, { documents: 1, bodies: 1 });
        for (const id of Object.keys(log.nodes)) pageNodes[id] = log.nodes[id];
      } catch (failure) {
        if (!isStoreFailure(failure) || !(turnLeft(turn) > 0)) throw failure;
        unread = true;
      }
    }
    // A read this page found held back (the page itself, the document or the body of a key) is
    // handed to the rounds, which make it again and count it.
    saveWithheld(run);
    if (unread && chosen.chosen.length === 0) throw native.error("log_store_unreachable", "log screen");
    const first = [];
    for (const parsed of chosen.chosen) {
      const kept = recovered.entries.get("3:" + parsed.tail);
      if (kept !== undefined) {
        if (kept.e !== null) first.push(kept.e);
      } else if (!junk.has(parsed.key)) {
        first.push(entryOfRecord(parsed, records.get(parsed.key)));
      }
    }
    const floorMs = chosen.count >= limit && first.length > 0 ? first[first.length - 1].time_ms : 0;
    // The chains of format 1 and format 2. A read of that bucket that is held back goes to the
    // rounds, and the entries the rounds opened for the screen stand in.
    const reads = chainReads(cache);
    let chains = { entries: [], more: false };
    let failed = null;
    useRecoveredChains(recovered);
    try {
      chains = await chainPage(turn, keys, cache, beforeMs, limit, floorMs, { lists: LEGACY_SCREEN_LISTS, reads: reads });
    } catch (failure) {
      if (!isStoreFailure(failure) || !(turnLeft(turn) > 0)) throw failure;
      failed = failure;
    }
    saveChainReads(keys, reads, false, false);
    if (failed !== null && failed.kind !== "absent" && first.length === 0) {
      throw native.error("log_store_unreachable", "log screen");
    }
    return mergePage(first, chains.entries, limit, chosen.more || chains.more);
  }

  /** The first page of the screen and the summary, read from the store: one round started by the
   *  screen (the first listing pages of the control and of the use prefix, the judgement, and the
   *  bodies of the entries of the page and of the summary in the same requests), then the entries
   *  of the chains of format 1 and format 2 that belong on the page and into the window of the
   *  summary. The page and the tally are kept for the next opening. Returns {page, summary, log}. */
  async function readScreen(turn, keys, limit) {
    const began = native.nowMs();
    const cache = loadCache(keys);
    const since = summarySince(began);
    const tally = cache.tally;
    pruneSummary(tally, since);
    const keptById = new Map();
    for (const entry of cache.entries) keptById.set(entry.id, entry);
    // What the rounds read for the screen: an entry kept there is not asked for.
    let recovered = loadRecovered(keys);
    let plan = null;
    // The time each step took from the start of the read (ms), for the report of the round.
    const timing = { listing: 0, bodies: 0, summary: 0, total: 0 };
    const round = await requestRound(turn, keys, "screen", function (pages) {
      timing.listing = Math.max(0, native.nowMs() - began);
      const chosen = choosePage(pages, Infinity, limit);
      const fetch = chosen.chosen.filter(function (parsed) { return !keptById.has("3:" + parsed.tail); });
      const room = Math.max(0, LOG_SUMMARY_REQUESTS * LOG_BODY_KEYS - fetch.length - 100);
      const counted = pages.u === null ? { above: [], below: [], reset: false }
        : summaryKeys(tally, pages.u, since, Math.min(room, LOG_SUMMARY_ENTRIES));
      plan = { chosen: chosen, counted: counted };
      return fetch.concat(counted.above, counted.below).filter(function (parsed) {
        return !recovered.entries.has("3:" + parsed.tail);
      }).map(function (parsed) { return { parsed: parsed }; });
    });
    // The round may have kept more for the screen (the keys it read again).
    recovered = loadRecovered(keys);
    // The entry of a key of the page or of the summary: what the device kept of the first page,
    // what the rounds read for the screen, or what this round read. null for an object that is
    // no entry, undefined (with read true) for a key of the summary that was not read.
    const entryOf = function (parsed, read) {
      const kept = recovered.entries.get("3:" + parsed.tail);
      if (kept !== undefined) return kept.e;
      if (round.junk.has(parsed.key)) return null;
      if (read === true && !round.entries.has(parsed.key)) return undefined;
      return entryOfRecord(parsed, round.entries.get(parsed.key));
    };
    timing.bodies = Math.max(0, native.nowMs() - began);
    let first = [];
    let more = false;
    let floorMs = 0;
    let truncated = false;
    // The listings this read gave the screen name the keys of its later pages as far as they
    // reach.
    screenListings = round.pages.c !== null && round.pages.u !== null
      ? { c: round.pages.c, u: round.pages.u, top: Infinity } : null;
    // The later pages held back from the screen whose keys those listings name end here; when
    // they marked the log and no longer do, a round judges and publishes that now.
    if (screenListings !== null && servePage(Infinity, 0)) requestRound(freeTurn(), keys, "sync").then(noop, noop);
    if (plan !== null) {
      cache.listed_ms = began;
      for (const parsed of plan.chosen.chosen) {
        const kept = keptById.get("3:" + parsed.tail);
        const entry = kept !== undefined ? kept : entryOf(parsed, false);
        if (entry !== null) first.push(entry);
      }
      more = plan.chosen.more;
      if (plan.chosen.count >= limit && first.length > 0) floorMs = first[first.length - 1].time_ms;
      // The summary: the keys above the counted range from the one nearest to it, then the keys
      // below it; the range stays one range, so the count stops at the first entry not read.
      if (plan.counted.reset) {
        tally.buckets = {};
        tally.top = "";
        tally.floor = "";
        tally.chains = {};
      }
      // An object that is no entry is passed and not counted.
      for (const parsed of plan.counted.above) {
        const entry = entryOf(parsed, true);
        if (entry === undefined) break;
        if (entry !== null) countEntryInto(tally, entry);
        tally.top = parsed.tail;
      }
      for (const parsed of plan.counted.below) {
        const entry = entryOf(parsed, true);
        if (entry === undefined) break;
        if (entry !== null) countEntryInto(tally, entry);
        if (tally.top === "") tally.top = parsed.tail;
        tally.floor = parsed.tail;
      }
      const use = round.pages.u;
      if (use !== null) {
        const window = use.keys.filter(function (parsed) { return parsed.time_ms >= since; });
        const uncounted = window.some(function (parsed) {
          return tally.top === "" || parsed.tail < tally.top || parsed.tail > tally.floor;
        });
        const beyond = use.truncated && use.keys.length > 0 && use.keys[use.keys.length - 1].time_ms >= since;
        truncated = uncounted || beyond;
      }
    } else if (!round.absent) {
      // The listings of format 3 were not read. When the rounds read them again since the screen
      // last read them itself, the page is made from the listing page the rounds kept, with the
      // entries they kept; an entry of that page they did not keep is shown as not read, and its
      // key goes to the rounds. Otherwise the entries of format 3 the device kept of the first
      // page stand in.
      const page = recoveredPage(recovered, Infinity, limit);
      if (page !== null && page.t >= cache.listed_ms) {
        const missing = new Set();
        for (const parsed of page.chosen) {
          const kept = recovered.entries.get("3:" + parsed.tail);
          if (kept === undefined) {
            first.push(entryOfRecord(parsed, undefined));
            if (missing.size < LOG_WITHHELD_KEYS) missing.add(parsed.key);
          } else if (kept.e !== null) {
            first.push(kept.e);
          }
        }
        more = page.more;
        if (page.count >= limit && first.length > 0) floorMs = first[first.length - 1].time_ms;
        if (missing.size > 0) {
          saveWithheld({ withheld: missing, shown: missing, settled: new Set(), pagesHeld: new Set(), pagesRead: new Set() });
        }
      } else {
        first = cache.entries.filter(function (entry) { return entry.id.slice(0, 2) === "3:"; });
        more = cache.has_more;
      }
      truncated = true;
    }
    // The chains of format 1 and format 2: the node prefixes of the account once in
    // LEGACY_FOUND_INTERVAL_MS, the entries of the page, and the entries of the window. A read
    // of that bucket that is held back goes to the rounds (reads), and what the rounds read for
    // the screen stands in: the entries they opened, and the node prefixes they listed.
    const reads = chainReads(cache);
    const budget = { lists: LEGACY_SCREEN_LISTS, reads: reads };
    let chains = { entries: [], more: false };
    let nodesHeld = false;
    let nodesRead = false;
    useRecoveredChains(recovered);
    try {
      if (began - cache.found_ms >= LEGACY_FOUND_INTERVAL_MS || began < cache.found_ms) {
        try {
          cache.found = await discoverLegacyNodes(turn);
          cache.found_ms = began;
          nodesRead = true;
        } catch (failure) {
          if (!isStoreFailure(failure) || !(turnLeft(turn) > 0)) throw failure;
          // A backend that states it has no such store is believed by a device that knows of no
          // chain the store holds; for a device that knows of one, that answer holds the listing
          // back.
          const known = chainNodes(cache).some(reads.live);
          if (failure.kind === "absent" && !known) throw failure;
          if (failure.kind !== "unreachable") nodesHeld = true;
          truncated = true;
          if (recovered.found !== null && recovered.found.t >= cache.found_ms) {
            for (const id of recovered.found.ids) {
              if (cache.found.indexOf(id) < 0) cache.found.push(id);
            }
          }
        }
      }
      chains = await chainPage(turn, keys, cache, Infinity, limit, floorMs, budget);
      if (await countChains(turn, keys, cache, tally, since, budget)) truncated = true;
    } catch (failure) {
      if (!isStoreFailure(failure) || !(turnLeft(turn) > 0)) throw failure;
      if (failure.kind !== "absent") truncated = true;
    }
    saveChainReads(keys, reads, nodesHeld, nodesRead);
    timing.summary = Math.max(0, native.nowMs() - began);
    const page = mergePage(first, chains.entries, limit, more || chains.more);
    // What the device keeps: the entries of the page up to LOG_KEEP_EVENTS events, and the tally.
    const kept = [];
    let keptEvents = 0;
    for (const entry of page.entries) {
      if (keptEvents >= LOG_KEEP_EVENTS) break;
      if (entry.unread === true) continue;
      kept.push(entry);
      keptEvents += entry.items.length;
    }
    cache.entries = kept;
    cache.has_more = page.has_more || kept.length < page.entries.length;
    cache.saved_ms = native.nowMs();
    saveCache(keys, cache);
    timing.total = Math.max(0, native.nowMs() - began);
    round.report(timing);
    return { page: page, summary: summaryResult(tally, since, truncated), log: round.log };
  }

  /** The range {lo, hi} of the seqs of a chain whose entries the tally counted, when the tally
   *  holds one; null otherwise. */
  function countedRange(tally, id) {
    const range = tally.chains[id];
    const shaped = range !== null && typeof range === "object" && Number.isSafeInteger(range.lo) &&
      Number.isSafeInteger(range.hi);
    return shaped ? range : null;
  }

  /** Counts the entries of the window of the summary (from since) of the chains of format 2 into
   *  the tally: for every chain the screen knows keys of in the window, the entries above the
   *  counted range (the one nearest to it first) and the entries below it (the one nearest to it
   *  first), read in one batch (LOG_SUMMARY_ENTRIES entries at most in the window). The counted
   *  range of a chain stays one range: the count of a chain stops at the first entry that was not
   *  read. A chain whose known end lies in the window and whose keys of the window the screen has
   *  not listed is listed once per call. A key of format 1 names no time and ends the descent of
   *  its chain (the releases that wrote format 1 ended before any window this program counts).
   *  Returns whether entries of the window remain uncounted. */
  async function countChains(turn, keys, cache, tally, since, budget) {
    const legacy = loadLegacy();
    const ids = chainNodes(cache);
    const targets = [];
    for (const id of ids) {
      const node = displayNode(id);
      const seqs = sortedSeqs(node);
      if (node.exhausted || targets.length >= budget.lists) continue;
      if (seqs.length === 0) {
        const hint = chainHint(cache, legacy, id);
        if (hint !== null && hint.time_ms >= since) {
          targets.push({ id: id, after: Math.max(0, hint.seq - LEGACY_DISPLAY_LIST) });
        }
        continue;
      }
      const lowest = keyFacts(node, seqs[seqs.length - 1]);
      if (lowest !== null && lowest.time_ms >= since && node.floor > 1) {
        targets.push({ id: id, after: Math.max(0, node.floor - LEGACY_DISPLAY_LIST - 1), below: node.floor });
      }
    }
    if (targets.length > 0) {
      budget.lists -= targets.length;
      await loadChainKeys(turn, targets, budget.reads);
    }
    const plans = [];
    const wanted = [];
    let uncounted = false;
    let room = Math.max(0, LOG_SUMMARY_ENTRIES - summaryEntries(tally, since));
    for (const id of ids) {
      const node = displayNode(id);
      const seqs = sortedSeqs(node);
      if (seqs.length === 0) continue;
      const range = countedRange(tally, id);
      const inWindow = function (seq) {
        const facts = keyFacts(node, seq);
        return facts !== null && facts.time_ms >= since;
      };
      // Above the counted range from the seq nearest to it, below it from the seq nearest to it.
      const above = range === null ? [] : seqs.filter(function (seq) { return seq > range.hi; }).reverse();
      const below = [];
      for (const seq of seqs) {
        if (range !== null && seq >= range.lo) continue;
        if (!inWindow(seq)) break;
        below.push(seq);
      }
      const plan = { id: id, above: [], below: [] };
      for (const seq of above) {
        if (!inWindow(seq)) continue;
        if (room <= 0) {
          uncounted = true;
          break;
        }
        room -= 1;
        plan.above.push(seq);
      }
      for (const seq of below) {
        if (room <= 0) {
          uncounted = true;
          break;
        }
        room -= 1;
        plan.below.push(seq);
      }
      const lowest = keyFacts(node, seqs[seqs.length - 1]);
      if (lowest !== null && lowest.time_ms >= since && !node.exhausted && node.floor > 1) uncounted = true;
      if (plan.above.length + plan.below.length === 0) continue;
      plans.push(plan);
      for (const seq of plan.above.concat(plan.below)) wanted.push({ id: id, seq: seq });
    }
    if (wanted.length === 0) return uncounted;
    const objects = await readChainObjects(turn, wanted, budget.reads);
    for (const plan of plans) {
      let range = countedRange(tally, plan.id);
      const count = function (seq) {
        const entry = legacyEntry(keys, plan.id, seq, objects);
        if (entry === null) return false;
        if (entry.time_ms >= since) countEntryInto(tally, entry);
        if (range === null) {
          range = { lo: seq, hi: seq };
          tally.chains[plan.id] = range;
        }
        if (seq < range.lo) range.lo = seq;
        if (seq > range.hi) range.hi = seq;
        return true;
      };
      for (const seq of plan.above) {
        if (!count(seq)) {
          uncounted = true;
          break;
        }
      }
      for (const seq of plan.below) {
        if (!count(seq)) {
          uncounted = true;
          break;
        }
      }
    }
    return uncounted;
  }

  // ---- The outcomes of the procedures ----
  //
  // What the server learns of how the procedures of this program end. Nothing of the bridge reports
  // the failure or the time of a procedure, so without this a procedure that fails or waits on a
  // device leaves no trace outside that device. The program counts, per name, the calls that ended
  // and their times (the time a call waited for its line and the time from its call to its end,
  // without the time the device waited for the user), and keeps the counts in the program store
  // (STORE_OUTCOMES). A call that failed, or that took OUTCOME_SLOW_MS or longer, is also kept one
  // by one with its failure code. A call that has not ended is kept as open: the calls a runtime
  // finds open at its start were cut off with the runtime before it (the app was ended, or the
  // executor gave the call up), and they are reported as interrupted, each with the time the app
  // had gone to the background while it was open (0: it was cut off in the foreground). A report
  // (OUTCOMES_PATH) names procedures, failure codes and times, and nothing of the arguments or the
  // results of a call. What a report the backend accepted carried leaves the store. The failure
  // cancelled (the runtime went down, or the user closed what the procedure waited in) is not a
  // failure of the procedure. A backend without the route turns the reports of this runtime off.
  // The names: the name of a procedure, event_sync for a synchronization an event started, and
  // log_screen for a read of the log screen from the store.

  let outcomeState = null;
  let outcomeSeq = 0;
  let outcomesFlight = false;
  let outcomesOff = false;
  let outcomesDue = false;
  // Whether the account of this runtime ended: nothing is counted or kept after that.
  let accountClosed = false;

  function emptyOutcomes(now) {
    return { v: 1, since_ms: now, open: {}, done: {}, events: [], interrupted: [], dropped: 0, background_ms: 0 };
  }

  /** The kept outcomes of this device and account, read from the program store at their first use
   *  in a runtime: the calls the store holds as open then are the calls of an earlier runtime that
   *  did not end, and they become interrupted. */
  function outcomes() {
    if (outcomeState !== null) return outcomeState;
    const now = native.nowMs();
    let state = emptyOutcomes(now);
    const raw = storedJson(STORE_OUTCOMES, null);
    if (raw !== null && typeof raw === "object" && raw.v === 1 && raw.open !== null && typeof raw.open === "object" &&
        raw.done !== null && typeof raw.done === "object" && Array.isArray(raw.events) && Array.isArray(raw.interrupted)) {
      state = raw;
      state.since_ms = whole(raw.since_ms);
      state.dropped = whole(raw.dropped);
      state.background_ms = whole(raw.background_ms);
      state.events = raw.events.slice(0, OUTCOME_EVENTS);
      state.interrupted = raw.interrupted.slice(0, OUTCOME_EVENTS);
    }
    for (const id of Object.keys(state.open)) {
      const call = state.open[id];
      if (Array.isArray(call) && typeof call[0] === "string" && state.interrupted.length < OUTCOME_EVENTS) {
        state.interrupted.push({
          name: call[0], called_ms: whole(call[1]), found_ms: now, background_ms: state.background_ms,
        });
      } else {
        state.dropped += 1;
      }
    }
    const found = Object.keys(state.open).length > 0;
    state.open = {};
    state.background_ms = 0;
    outcomeState = state;
    if (found) {
      saveOutcomes();
      outcomesSoon();
    }
    return state;
  }

  function saveOutcomes() {
    if (outcomeState !== null) storeJson(STORE_OUTCOMES, outcomeState);
  }

  /** The class of a time among OUTCOME_BOUNDS_MS (the index of the first bound it is below; the
   *  number of bounds for a longer time). */
  function outcomeClass(ms) {
    for (let at = 0; at < OUTCOME_BOUNDS_MS.length; at += 1) {
      if (ms < OUTCOME_BOUNDS_MS[at]) return at;
    }
    return OUTCOME_BOUNDS_MS.length;
  }

  /** Sends the kept outcomes. One report is in flight at a time. When the backend accepted it,
   *  what it carried leaves the kept outcomes (the calls that ended meanwhile stay); a report that
   *  failed leaves them as they are, for the next one. */
  function reportOutcomes() {
    outcomesDue = false;
    if (outcomesFlight || outcomesOff || accountClosed || outcomeState === null) return;
    const state = outcomeState;
    const now = native.nowMs();
    const names = Object.keys(state.done);
    if (names.length === 0 && state.events.length === 0 && state.interrupted.length === 0) return;
    const sent = {
      done: names.map(function (name) {
        const done = state.done[name];
        return {
          name: name, calls: whole(done.calls), failed: whole(done.failed), wait_ms: whole(done.wait_ms),
          total_ms: whole(done.total_ms), max_ms: whole(done.max_ms), classes: done.classes.slice(),
        };
      }),
      events: state.events.slice(), interrupted: state.interrupted.slice(), dropped: state.dropped,
    };
    const body = {
      program_version: VERSION, since_ms: state.since_ms, until_ms: now, bounds_ms: OUTCOME_BOUNDS_MS,
      done: sent.done, events: sent.events, interrupted: sent.interrupted, dropped: sent.dropped,
    };
    outcomesFlight = true;
    settled(api(freeTurn(), "POST", OUTCOMES_PATH, body)).then(function (outcome) {
      outcomesFlight = false;
      if (!outcome.ok) {
        const status = failureStatus(outcome.error);
        if (status === 404 || status === 405) outcomesOff = true;
        return;
      }
      if (accountClosed || outcomeState === null) return;
      const kept = outcomeState;
      for (const item of sent.done) {
        const done = kept.done[item.name];
        if (done === undefined) continue;
        done.calls -= item.calls;
        done.failed -= item.failed;
        done.wait_ms -= item.wait_ms;
        done.total_ms -= item.total_ms;
        for (let at = 0; at < done.classes.length; at += 1) done.classes[at] -= whole(item.classes[at]);
        if (done.calls <= 0) delete kept.done[item.name];
      }
      kept.events = kept.events.slice(sent.events.length);
      kept.interrupted = kept.interrupted.slice(sent.interrupted.length);
      kept.dropped = Math.max(0, kept.dropped - sent.dropped);
      kept.since_ms = now;
      saveOutcomes();
    }).then(noop, noop);
  }

  /** Has the kept outcomes reported OUTCOMES_WAIT_MS from now (once, however often it is asked). */
  function outcomesSoon() {
    if (outcomesDue || outcomesOff) return;
    outcomesDue = true;
    native.sleep(OUTCOMES_WAIT_MS).then(reportOutcomes).then(noop, noop);
  }

  /** Reports the kept outcomes when the last report is OUTCOMES_INTERVAL_MS old (the end of a
   *  synchronization asks). */
  function outcomesDaily() {
    if (outcomeState === null || outcomesOff || accountClosed) return;
    const now = native.nowMs();
    if (now < outcomeState.since_ms || now - outcomeState.since_ms >= OUTCOMES_INTERVAL_MS) reportOutcomes();
  }

  /** Notes that the app went to the background (gone true) or came back to the foreground, for
   *  the calls that are open. The program store is written only when the note changes. */
  function noteBackground(gone) {
    if (outcomeState === null || outcomesOff || accountClosed) return;
    const at = gone && Object.keys(outcomeState.open).length > 0 ? native.nowMs() : 0;
    if (whole(outcomeState.background_ms) === at) return;
    outcomeState.background_ms = at;
    saveOutcomes();
  }

  /** Counts the end of the call of a turn: code is ok or the failure code. */
  function endCall(turn, code) {
    const state = outcomes();
    const now = native.nowMs();
    const total = turnSpent(turn);
    const waited = turn.startedMs === 0 ? total : Math.min(total, whole(turn.waitedMs));
    delete state.open[turn.id];
    let done = state.done[turn.name];
    if (done === undefined || done === null || !Array.isArray(done.classes) ||
        done.classes.length !== OUTCOME_BOUNDS_MS.length + 1) {
      if (Object.keys(state.done).length >= OUTCOME_NAMES_MAX) {
        state.dropped += 1;
        saveOutcomes();
        return;
      }
      done = {
        calls: 0, failed: 0, wait_ms: 0, total_ms: 0, max_ms: 0,
        classes: OUTCOME_BOUNDS_MS.map(function () { return 0; }).concat([0]),
      };
      state.done[turn.name] = done;
    }
    const failed = code !== "ok" && code !== "cancelled";
    done.calls += 1;
    if (failed) done.failed += 1;
    done.wait_ms += waited;
    done.total_ms += total;
    if (total > done.max_ms) done.max_ms = total;
    done.classes[outcomeClass(total)] += 1;
    if (failed || total >= OUTCOME_SLOW_MS) {
      if (state.events.length < OUTCOME_EVENTS) {
        state.events.push({ name: turn.name, code: failed ? code.slice(0, 64) : "ok", wait_ms: waited, total_ms: total, at_ms: now });
      } else {
        state.events.shift();
        state.events.push({ name: turn.name, code: failed ? code.slice(0, 64) : "ok", wait_ms: waited, total_ms: total, at_ms: now });
        state.dropped += 1;
      }
      outcomesSoon();
    }
    saveOutcomes();
  }

  /** Work whose calls are counted under name: call(args, turn) returns the promise of the work in
   *  the turn of the call (PROCEDURE_LIMIT_MS from the call). The counting never changes what a
   *  call returns or throws. */
  function tracked(name, call) {
    return function (args) {
      let turn = null;
      try {
        turn = newTurn(PROCEDURE_LIMIT_MS, name);
      } catch (error) {
        return Promise.reject(error);
      }
      let counted = false;
      try {
        if (name !== "" && !outcomesOff && !accountClosed) {
          const state = outcomes();
          outcomeSeq += 1;
          turn.id = String(turn.calledMs) + "-" + String(outcomeSeq);
          state.open[turn.id] = [name, turn.calledMs];
          saveOutcomes();
          counted = true;
        }
      } catch (error) {
        counted = false;
      }
      const ended = function (code) {
        if (!counted || accountClosed) return;
        try {
          endCall(turn, code);
        } catch (error) {
          // Counting failed (the bridge is closed): the call ends as it ends.
        }
      };
      let run = null;
      try {
        run = Promise.resolve(call(args === null || typeof args !== "object" ? {} : args, turn));
      } catch (error) {
        run = Promise.reject(error);
      }
      return run.then(
        function (value) { ended("ok"); return value; },
        function (error) { ended(failureCode(error)); throw error; });
    };
  }

  /** A counted procedure that runs on the line of the procedures a user starts. */
  function userProcedure(name, work) {
    return tracked(name, function (args, turn) {
      return userLine.run(turn, function () { return work(turn, args); });
    });
  }

  // ---- The key of the account ----

  // The mismatch marker of the runtime lifetime: the last account query answered a user_id other
  // than the bound userId (so that the account end of that runtime does not erase the master key of
  // another account).
  let accountMismatch = false;

  /** The key_id registered on the account (null when there is none), from the account query
   *  (fetched: the promise of the query when the caller sent it ahead). When the user_id of the
   *  response differs from the bound userId (the account the server authenticated and the bound
   *  account of this device differ), the key is not read, key_state account_mismatch is published
   *  and the call ends with account_mismatch (a response without user_id counts as no mismatch). */
  async function registeredKeyId(turn, fetched) {
    const body = (await (fetched === undefined ? api(turn, "GET", "/api/secure/account") : fetched)).json;
    if (typeof body.user_id === "string" && body.user_id !== "" && body.user_id !== userId()) {
      accountMismatch = true;
      native.publish({
        state: { key_state: "account_mismatch", key_id: null },
        runtime: { ready: true, account_mismatch: true },
      });
      throw native.error("account_mismatch", "server account differs from bound account");
    }
    accountMismatch = false;
    const key = body.key;
    if (key === null) return null;
    if (key === undefined || typeof key !== "object" || typeof key.key_id !== "string" || key.key_id === "") {
      throw native.error("invalid_response", "account key");
    }
    return key.key_id;
  }

  /** Registers the account signing public key and the log public key on the account. proof is the
   *  signature of the account signing key over the account id. When replace is false, an account
   *  with another registered key fails with key_exists. */
  async function registerKey(turn, keys, replace) {
    const proof = native.ed25519Sign(keys.signSeed, encode(utf8(purpose("register") + "\n" + userId())));
    await api(turn, "PUT", "/api/secure/account/key", {
      sign_pk: keys.signPk, log_pk: keys.logPk, proof: proof, replace: replace,
    });
  }

  function publishKey(keyState, keys) {
    const keyId = keys === null ? null : keys.keyId;
    native.publish({ state: { key_state: keyState, key_id: keyId } });
    return { keyState: keyState, keyId: keyId, keys: keys };
  }

  /** The judgement of the key state: the master key of the keychain is compared with the key_id
   *  registered on the account, and key_state and key_id are published. When there is a master key
   *  and the account has no registered key, its public key is registered. When the account query
   *  fails nothing is published and the failure is thrown. */
  async function judgeKey(turn, fetched) {
    const masterKey = readMasterKey();
    const registered = await registeredKeyId(turn, fetched);
    if (masterKey === null) return publishKey(registered === null ? "absent" : "waiting", null);
    const keys = deriveKeys(masterKey);
    let keyState = registered === null || registered === keys.keyId ? "present" : "mismatch";
    if (registered === null) {
      try {
        await registerKey(turn, keys, false);
      } catch (error) {
        // Another device registered another key between the query and the registration.
        if (error.code !== "key_exists") throw error;
        keyState = "mismatch";
      }
    }
    return publishKey(keyState, keys);
  }

  /** The derived keys when key_state is present. Otherwise key_required. */
  async function presentKeys(turn) {
    const judged = await judgeKey(turn);
    if (judged.keyState !== "present") throw native.error("key_required", judged.keyState);
    return judged.keys;
  }

  // ---- The grants: the nodes of the account and the commands ----

  /** The nodes the backend lists for this account, each with the expiry of the grant the backend
   *  recorded for the account on that node: [{node, not_after_ms}] (not_after_ms null when it
   *  recorded none). One request the backend answers without calling a node. The list says which
   *  nodes are there to delegate to; whether a node is handed a key is decided by its attestation
   *  alone (renewGrants), and when a grant was handed and when it ends is what this device kept. */
  async function fetchListed(turn) {
    const listed = (await api(turn, "GET", GRANTS_PATH)).json.nodes;
    const out = [];
    for (const item of Array.isArray(listed) ? listed : []) {
      if (item === null || typeof item !== "object" || typeof item.node !== "string" || !NODE_ID.test(item.node)) continue;
      if (out.some(function (other) { return other.node === item.node; })) continue;
      out.push({ node: item.node, not_after_ms: Number.isSafeInteger(item.not_after_ms) && item.not_after_ms > 0 ? item.not_after_ms : null });
    }
    return out;
  }

  /** The attestations of nodes for a fresh nonce: {nonce, nodes}. With ids, the attestations of
   *  those nodes (the ones among them that are alive and answer; ATTESTATION_NODES ids per request,
   *  ATTESTATION_REQUESTS requests at most, sent together); with null, those of every node the
   *  backend lists for the account. Each attestation is a call of its node, so a caller names the
   *  nodes it has a command for. */
  async function fetchOffered(turn, ids) {
    const nonce = native.randomBytes(32);
    if (ids === null) {
      const nodes = (await api(turn, "GET", NODES_PATH, null, { nonce: nonce })).json.nodes;
      return { nonce: nonce, nodes: Array.isArray(nodes) ? nodes : [] };
    }
    const requests = [];
    for (let at = 0; at < ids.length && requests.length < ATTESTATION_REQUESTS; at += ATTESTATION_NODES) {
      requests.push(api(turn, "GET", NODES_PATH, null, {
        nonce: nonce, nodes: ids.slice(at, at + ATTESTATION_NODES).join(","),
      }));
    }
    const nodes = [];
    for (const answer of await Promise.all(requests)) {
      for (const response of Array.isArray(answer.json.nodes) ? answer.json.nodes : []) nodes.push(response);
    }
    return { nonce: nonce, nodes: nodes };
  }

  /** Hands the grants of this account to the nodes that are to receive one (steps 3 and 4 of a
   *  synchronization). The nodes the backend lists for the account are read first (fetchListed: no
   *  node is called; options.listed is the settled outcome of that request when the caller sent it
   *  ahead), and the attestation is requested of the nodes that are to receive a grant only. A
   *  listed node receives a grant when
   *    this device keeps no grant of it (or one from before the last revocation),
   *    the last grant this device handed it is the renewal interval old (grantRenewMs),
   *    options.refill is set (a push with the reason grant_required started the synchronization),
   *    the backend reports no grant row of the account on it, and the last grant this device sent
   *    it is GRANT_REFILL_MS old, or
   *    options.force is set (a new lifetime applies at once).
   *  A synchronization without such a node sends no request that calls a node. A node whose
   *  attestation is requested has it verified and receives a grant with the lifetime the ledger
   *  sets; the grants go out together (one stage). A node is kept among the grants of this device
   *  before its grant goes out (with the attempt time): a node that takes the grant whose reply
   *  never reaches this program is a node this device handed its key to. A node whose document
   *  verifies with a measurement no list has is a node of a later release: it receives no grant,
   *  it is kept as such (log.nodes) and not asked again by this program. A backend without the
   *  route of the list (404) is asked for the attestations of every node it lists, and what this
   *  device kept decides which of them receives a grant; any other failure of the list is the
   *  failure of this step. Returns {accepted, rejected, failed, later, granted, ledgerChanged}:
   *  the Set of the ids of the nodes that hold or were sent a grant, the number of nodes whose
   *  attestation failed to verify, of nodes that did not take the grant, of nodes of a later
   *  release, and of nodes that took a grant now. */
  async function renewGrants(turn, keys, ledger, grants, options) {
    const accepted = new Set();
    const nodes = loadNodes();
    const unaccepted = storedObject(STORE_UNACCEPTED);
    let noted = false;
    let later = 0;
    const now = native.nowMs();
    const fresh = function (id) {
      const known = grants[id];
      return known !== undefined && known.granted_ms > ledger.revoked_ms &&
        known.granted_ms <= now + GRANT_REFILL_MS && now - known.granted_ms < grantRenewMs(ledger);
    };
    // A node an earlier synchronization of this program found to be of a later release.
    const laterKnown = function (id) {
      const kept = nodes[id];
      return kept !== undefined && kept.p === "nitro" && kept.m !== "" && buildOfMeasure(kept.m) === undefined;
    };
    const sent = options.listed !== undefined && options.listed !== null
      ? await options.listed : await settled(fetchListed(turn));
    let offered = null;
    const due = new Set();
    if (!sent.ok) {
      if (failureStatus(sent.error) !== 404) throw sent.error;
      offered = await fetchOffered(turn, null);
    } else {
      for (const item of sent.value) {
        const known = grants[item.node];
        if (options.force !== true && laterKnown(item.node)) {
          later += 1;
          continue;
        }
        const refill = options.refill === true && item.not_after_ms === null && known !== undefined &&
          now - Math.max(known.granted_ms, known.attempted_ms) >= GRANT_REFILL_MS;
        if (options.force === true || !fresh(item.node) || refill) due.add(item.node);
        else accepted.add(item.node);
      }
      offered = due.size === 0 ? { nonce: "", nodes: [] } : await fetchOffered(turn, Array.from(due));
    }
    let rejected = 0;
    let failed = 0;
    // The nodes that receive a grant in this run, in the order of the list.
    const wanted = [];
    for (const response of offered.nodes) {
      const claimed = response !== null && typeof response === "object" ? response.node : undefined;
      if (!sent.ok && options.force !== true && typeof claimed === "string" && fresh(claimed)) {
        accepted.add(claimed);
        continue;
      }
      let node = null;
      try {
        node = verifyAttestation(response, offered.nonce);
      } catch (error) {
        rejected += 1;
        native.log("attestation rejected: " + String(error.message));
        continue;
      }
      if (sent.ok && !due.has(node.node)) continue;
      if (wanted.some(function (item) { return item.node.node === node.node; })) continue;
      if (!node.listed) {
        later += 1;
        native.log("attestation of a later release: " + node.release);
        nodes[node.node] = { m: node.measure, p: "nitro", r: node.release, f: now, c: 0 };
        if (unaccepted[node.measure] === undefined) {
          unaccepted[node.measure] = { first_ms: now, release: String(node.release).slice(0, 64), held: false, node: node.node };
        }
        noted = true;
        continue;
      }
      accepted.add(node.node);
      wanted.push({ node: node, challenge: response.challenge });
    }
    if (noted) {
      saveNodes(nodes);
      storeJson(STORE_UNACCEPTED, unaccepted);
    }
    const sentMs = native.nowMs();
    for (const item of wanted) {
      const node = item.node;
      const known = grants[node.node];
      grants[node.node] = {
        granted_ms: known === undefined ? 0 : known.granted_ms,
        not_after_ms: known === undefined ? 0 : known.not_after_ms,
        release: node.release, first_ms: known === undefined ? sentMs : known.first_ms,
        platform: node.platform, attempted_ms: sentMs,
      };
    }
    if (wanted.length > 0) saveGrants(grants);
    const results = await stage(wanted.map(function (item) {
      return sendGrant(turn, item.node, item.challenge, keys, grantTtlMs(ledger));
    }));
    let granted = 0;
    let ledgerChanged = false;
    for (let i = 0; i < wanted.length; i += 1) {
      const node = wanted[i].node;
      const result = results[i];
      if (!result.ok) {
        // A node that did not take the grant keeps no new grant time (the published state grant
        // becomes partial or none); the record of the attempt stays.
        failed += 1;
        native.log("grant failed: " + failureCode(result.error));
        continue;
      }
      // The grant time kept is after the last revocation time (a device clock that runs backwards
      // does not make a grant after a revoke read as one before it).
      const grantedMs = Math.max(result.value.granted_ms, ledger.revoked_ms + 1);
      grants[node.node].granted_ms = grantedMs;
      grants[node.node].not_after_ms = result.value.not_after_ms;
      granted += 1;
      if (node.format !== 3) {
        noteLedgerGrant(ledger, node, grantedMs, result.value.not_after_ms, sentMs);
        ledgerChanged = true;
      }
    }
    return {
      accepted: accepted, rejected: rejected, failed: failed, later: later, granted: granted,
      ledgerChanged: ledgerChanged,
    };
  }

  /** Sends a revoke to every node the backend lists for the account, also to nodes this device
   *  handed no grant to: a node hands delegations to nodes of the same release, so a node this
   *  device never handed a grant to can hold the user key of this account. The revoke of a node
   *  without a grant changes nothing and passes. The attestation of every listed node is requested
   *  (the time of the document that decides the freshness of the reply and the check of the
   *  challenge statement come from it). A revoke does not check the acceptance conditions (the
   *  accepted measurements, a build that accepts local): that gate decides who receives a user key,
   *  and a revoke command carries no secret. Returns whether a listed node did not confirm the
   *  revoke (nodes whose attestation failed to verify or did not arrive included). */
  async function revokeEverywhere(turn, keys) {
    const listed = await settled(fetchListed(turn));
    if (!listed.ok && failureStatus(listed.error) !== 404) throw listed.error;
    const ids = listed.ok ? listed.value.map(function (item) { return item.node; }) : null;
    if (ids !== null && ids.length === 0) return false;
    const offered = await fetchOffered(turn, ids);
    const confirmed = new Set();
    const results = await stage(offered.nodes.map(async function (response) {
      const target = verifyAttestation(response, offered.nonce, false);
      await sendRevoke(turn, target, response.challenge, keys);
      confirmed.add(target.node);
    }));
    let incomplete = false;
    for (const result of results) {
      if (!result.ok) {
        incomplete = true;
        native.log("revoke failed: " + failureCode(result.error));
      }
    }
    if (ids !== null && ids.some(function (id) { return !confirmed.has(id); })) incomplete = true;
    return incomplete;
  }

  /** The step of the grants, for a caller that holds the grant lock: with delegation on, the
   *  grants are handed to the nodes that are to receive one (renewGrants); with delegation off,
   *  the revoke is sent again to every listed node (it reaches the nodes that were not reached
   *  when it was turned off, and the nodes that took over a delegation from them; a failure does
   *  not stop the step). What this device keeps is written and the state grant is published.
   *  Returns {ledger, grants, renewed, grant}. */
  async function grantStep(turn, keys, options) {
    const ledger = loadLedger();
    const grants = loadGrants();
    let renewed = { accepted: new Set(), rejected: 0, failed: 0, later: 0, granted: 0, ledgerChanged: false };
    if (!delegationOff(ledger)) {
      renewed = await renewGrants(turn, keys, ledger, grants, options);
    } else {
      try {
        await revokeEverywhere(turn, keys);
      } catch (error) {
        if (failureCode(error) === "cancelled" || !(turnLeft(turn) > 0)) throw error;
        native.log("revoke retry failed: " + failureCode(error));
      }
    }
    saveGrants(grants);
    if (renewed.ledgerChanged) saveLedger(ledger);
    const grant = grantState(ledger, grants, renewed.accepted, native.nowMs());
    native.publish({
      state: { grant: grant, grant_days: ledger.ttl_days },
      runtime: { rejected_nodes: renewed.rejected },
    });
    return { ledger: ledger, grants: grants, renewed: renewed, grant: grant };
  }

  /** The front of a procedure that needs a node holding the grant of this account: under the grant
   *  lock, the account query and the list of the nodes are sent together, the key is judged, and
   *  the grants are handed to the nodes that are to receive one. When delegation is off it is
   *  delegation_off; when no listed node holds a grant it is grant_required (attestation_failed
   *  when every listed node failed the attestation verification or is of a release later than this
   *  program). Returns {keys, ledger, grants}. */
  function withGrants(turn) {
    return grantLock.run(turn, async function () {
      const account = api(turn, "GET", "/api/secure/account");
      account.then(noop, noop);
      const held = readMasterKey() !== null;
      if (held && delegationOff(loadLedger())) {
        const judged = await judgeKey(turn, account);
        if (judged.keyState !== "present") throw native.error("key_required", judged.keyState);
        throw native.error("delegation_off", "delegation is turned off");
      }
      const listed = held ? settled(fetchListed(turn)) : null;
      const judged = await judgeKey(turn, account);
      if (judged.keyState !== "present") throw native.error("key_required", judged.keyState);
      const step = await grantStep(turn, judged.keys, { listed: listed });
      if (delegationOff(step.ledger)) throw native.error("delegation_off", "delegation is turned off");
      if (step.grant.state === "none") {
        const refused = step.renewed.rejected + step.renewed.later > 0 && step.renewed.accepted.size === 0;
        throw native.error(refused ? "attestation_failed" : "grant_required", "no listed node holds a grant");
      }
      shareLedgerSoon(judged.keys);
      return { keys: judged.keys, ledger: step.ledger, grants: step.grants };
    });
  }

  /** Decides the custody of a record the app makes. When delegation is off it is delegation_off.
   *  When no node this device handed a grant to holds it within its time, the grants are handed
   *  first (withGrants). When there still is none it is grant_required (no record is made under a
   *  custody that no node can open). */
  async function recordCustody(turn) {
    let ledger = loadLedger();
    if (delegationOff(ledger)) throw native.error("delegation_off", "delegation is turned off");
    let custody = heldCustody(ledger, loadGrants(), native.nowMs());
    if (custody === null) {
      const held = await withGrants(turn);
      ledger = held.ledger;
      custody = heldCustody(ledger, held.grants, native.nowMs());
    }
    if (custody === null) throw native.error("grant_required", "no node holds a grant");
    return custody;
  }

  // ---- The synchronization ----

  /** The migration of what was stored before the switch: the tokens of connections and the vault
   *  values that were stored under the KMS envelope of the operator before the switch are handed out
   *  by the backend sealed to the log public key of this account. They are opened with the log
   *  decryption private key, made into records under the user key of the custody of a node that
   *  holds a grant, and uploaded. From then on only a node opens them. The plaintext of the record
   *  is the opened bytes as they are (re-serializing the JSON would change integers above 2^53, the
   *  notation of numbers and escape sequences): only that it is a JSON object is checked. Nothing is
   *  done when no node holds a grant (no node could open those records). A failure is only logged
   *  and does not change the result of sync. A query that found no item, and an upload that left
   *  none, mark the check as complete (SEALING_CHECK_STORE_KEY); a failed query marks nothing (the
   *  next sync queries again). The rounds of fetching and uploading are bounded (SEALING_ROUNDS). */
  async function sealPending(turn, keys, custody) {
    try {
      const user = userId();
      for (let round = 0; round < SEALING_ROUNDS; round += 1) {
        const pending = (await api(turn, "GET", "/api/secure/sealing")).json;
        const items = Array.isArray(pending.items) ? pending.items : [];
        const records = [];
        for (const item of items) {
          if (item === null || typeof item !== "object" || typeof item.id !== "string" ||
              typeof item.provider !== "string" || SEALING_KINDS.indexOf(item.kind) < 0) continue;
          try {
            const aad = [user, item.id, item.kind, item.provider].join("\n");
            const opened = native.hpkeOpen({
              kem: "x25519", kdf: "sha256", aead: "chacha20poly1305", recipientPrivateKey: keys.logSk,
              enc: item.enc, info: info("pending"), aad: encode(utf8(aad)), ciphertext: item.ct,
            });
            const parsed = JSON.parse(text(decode(opened)));
            if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) continue;
            records.push({ id: item.id, record: sealRecordBytes(keys, custody, item.kind, item.provider, opened) });
          } catch (error) {
            native.log("pending item skipped: " + failureCode(error));
          }
        }
        if (items.length === 0) {
          native.storeSet(SEALING_CHECK_STORE_KEY, "1");
          break;
        }
        if (records.length === 0) break;
        await api(turn, "PUT", "/api/secure/sealing", { items: records });
        // The check is marked complete only by a query that found nothing: after an upload the next
        // sync queries once more (an item the backend rejected stays pending and is offered again).
        if (pending.more !== true) break;
      }
    } catch (error) {
      if (failureCode(error) === "cancelled" || !(turnLeft(turn) > 0)) throw error;
      native.log("sealing pending records failed: " + failureCode(error));
    }
  }

  /** What follows the grants while delegation is on (step 7 of a synchronization, and the end of
   *  the procedures that hand the grants of a new key or turn delegation on again): the sealing
   *  check, when a node this device handed a grant to holds it and the check is not marked as
   *  done, and the completion of an application password setup. step is the result of grantStep. */
  async function afterGrants(turn, keys, step) {
    if (delegationOff(step.ledger)) return;
    const custody = heldCustody(step.ledger, step.grants, native.nowMs());
    if (custody !== null && native.storeGet(SEALING_CHECK_STORE_KEY) === null) {
      await sealPending(turn, keys, custody);
    }
    await finishAppPasswordSetup(turn, keys, step.ledger, step.grants);
  }

  /** One synchronization (docs/protocol.md, "The program of the app"). trigger says what started
   *  it: {refill} (a push with the reason grant_required: a node the backend reports no grant row
   *  for is handed a grant again). The steps:
   *    1 the account query and, when this device holds a master key, the list of the nodes of the
   *      account, sent together
   *    2 the judgement of the key (judgeKey)
   *    3 which listed nodes are to receive a grant, 4 their attestations and the grants
   *      (renewGrants), or 5, with delegation off, the revoke to every listed node
   *    6 the published state grant and runtime.ready
   *    7 what follows the grants: the sealing check, the completion of an application password
   *      setup, and a round of the log when one is due
   *    8 the catch-up of a transfer of the master key
   *  Steps 1 to 5 run under the grant lock. A failure publishes its code to state.error, a success
   *  clears it. Returns {keyState, keyId, grant, granted, rejected}. */
  async function runSync(turn, trigger) {
    try {
      const step = await grantLock.run(turn, async function () {
        const account = api(turn, "GET", "/api/secure/account");
        account.then(noop, noop);
        const held = readMasterKey() !== null;
        const listed = held && !delegationOff(loadLedger()) ? settled(fetchListed(turn)) : null;
        const judged = await judgeKey(turn, account);
        if (judged.keyState !== "present") return { judged: judged, grants: null };
        return { judged: judged, grants: await grantStep(turn, judged.keys, { listed: listed, refill: trigger.refill === true }) };
      });
      const judged = step.judged;
      // Step 6: the grant step published the state of the grants; the runtime is ready (the key is
      // judged and the grants are handed). What follows does not hold the screens back.
      native.publish({ runtime: { ready: true } });
      let grant = { state: "none", not_after_ms: 0 };
      let granted = 0;
      let rejected = 0;
      if (step.grants !== null) {
        const keys = judged.keys;
        grant = step.grants.grant;
        granted = step.grants.renewed.granted;
        rejected = step.grants.renewed.rejected;
        await afterGrants(turn, keys, step.grants);
        if (roundDue()) {
          try {
            await requestRound(turn, keys, "sync");
          } catch (error) {
            if (failureCode(error) === "cancelled") throw error;
            native.log("round: " + failureCode(error));
          }
        }
        shareLedgerSoon(keys);
      }
      native.publish({ state: { error: null } });
      // Catching up on the master key transfer: a device with the key reads the pending requests, a
      // device with a transfer in progress advances one step, and the polling loop is started again.
      // The transfer belongs to the line of the procedures a user starts; the synchronization does
      // not wait for it.
      userLine.run(freeTurn(), function () { return transferCatchUp(judged.keyState === "present"); }).then(noop, function (error) {
        try {
          native.log("transfer sync: " + failureCode(error));
        } catch (closed) {
          // The bridge is closed.
        }
      });
      outcomesDaily();
      return { keyState: judged.keyState, keyId: judged.keyId, grant: grant, granted: granted, rejected: rejected };
    } catch (error) {
      native.publish({ state: { error: failureCode(error) } });
      throw error;
    }
  }

  // The synchronization that waits for the one that runs (null: none): {trigger, promise}. A
  // trigger that arrives while one waits is served by it. runningSync is the one that runs (null:
  // none): {startedMs, promise}.
  let waitingSync = null;
  let runningSync = null;

  /** Asks for a synchronization on the line of the synchronizations: one runs and at most one
   *  waits. A trigger that arrives while one waits joins it (its refill is taken over). An event
   *  of the app itself (own: the start of the runtime, the return to the foreground) is also
   *  served by the synchronization that runs when it began less than EVENT_SYNC_FRESH_MS ago: what
   *  it reads is as new as what a synchronization of that event would read. Otherwise a new
   *  synchronization is put on the line, which runs at once when none runs. The time of a
   *  synchronization begins when it begins. Returns the promise of its result. */
  function requestSync(trigger) {
    if (waitingSync !== null) {
      if (trigger.refill === true) waitingSync.trigger.refill = true;
      return waitingSync.promise;
    }
    if (trigger.own === true && runningSync !== null &&
        native.nowMs() - runningSync.startedMs < EVENT_SYNC_FRESH_MS) {
      return runningSync.promise;
    }
    const entry = { trigger: { refill: trigger.refill === true }, promise: null };
    const waits = syncLine.busy();
    const start = tracked(trigger.name, function (args, turn) {
      return syncLine.run(turn, function () {
        if (waitingSync === entry) waitingSync = null;
        const running = { startedMs: native.nowMs(), promise: entry.promise };
        runningSync = running;
        const ended = function () {
          if (runningSync === running) runningSync = null;
        };
        const work = runSync(turn, entry.trigger);
        work.then(ended, ended);
        return work;
      }, true);
    });
    entry.promise = start({});
    if (waits) waitingSync = entry;
    return entry.promise;
  }

  /** The procedure sync: a synchronization, within the turn of the call. */
  async function syncProcedure(turn) {
    const outcome = await limited(turn, requestSync({ name: "", refill: false }), Infinity, "sync");
    return { key_state: outcome.keyState, grant: outcome.grant };
  }

  /** A synchronization an event started (counted as event_sync). own says that the event is one of
   *  the app itself. For a push, the report of the synchronization follows it (SYNC_REPORT_PATH):
   *  the backend learns that the device woke and whether it can hand a grant. Nothing waits for
   *  the answer of the report. */
  function eventSync(push, own) {
    const began = native.nowMs();
    const reason = push !== null && typeof push.reason === "string" && /^[a-z0-9_]{1,32}$/.test(push.reason)
      ? push.reason : "unknown";
    const run = requestSync({
      name: "event_sync", refill: push !== null && reason === "grant_required", own: own === true,
    });
    if (push === null) return run;
    const report = function (outcome) {
      settled(api(freeTurn(), "POST", SYNC_REPORT_PATH, {
        trigger: "push", reason: reason,
        key_state: outcome === null ? "unknown" : outcome.keyState,
        grant: outcome === null ? "unknown" : outcome.grant.state,
        granted: outcome === null ? 0 : outcome.granted, rejected: outcome === null ? 0 : outcome.rejected,
        elapsed_ms: Math.max(0, native.nowMs() - began), program_version: VERSION,
      })).then(function (sent) {
        try {
          if (!sent.ok) native.log("sync report: " + failureCode(sent.error));
        } catch (closed) {
          // The bridge is closed.
        }
      });
    };
    return run.then(
      function (outcome) { report(outcome); return outcome; },
      function (error) {
        if (failureCode(error) !== "cancelled") report(null);
        throw error;
      });
  }

  // ---- The key procedures ----

  /** Forgets what this device kept of the log of the account (a new key begins a new log): the
   *  grants, the judgements, the kept screen. The ledger of the earlier programs is not carried
   *  over again. */
  function clearLog() {
    for (const key of [STORE_GRANTS, STORE_CURSOR, STORE_RESUME, STORE_NODES, STORE_UNACCEPTED, STORE_BLOCKED,
      STORE_SAMPLE, STORE_SEEN, STORE_MISSING, STORE_WITHHELD, STORE_RECOVERED, STORE_DENIED, STORE_LEGACY,
      STORE_ROUND, STORE_CACHE]) {
      native.storeSet(key, null);
    }
    native.storeSet(STORE_MIGRATED, String(VERSION));
    logState = emptyLogState();
    displayNodes.clear();
    displayEntries.clear();
    logPagePlaces = [];
    screenListings = null;
  }

  /** Key creation: a new key is made only when the keychain has no master key and the account has
   *  no registered key. The account registration comes first and the keychain is written only after
   *  it succeeded: when two devices create a key at the same time, the one that loses the
   *  registration does not write to the keychain. The grants follow under the same lock, and what
   *  follows the grants (afterGrants) after it. */
  async function createKey(turn) {
    const made = await grantLock.run(turn, async function () {
      const judged = await judgeKey(turn);
      if (judged.keyState !== "absent") return { keyState: judged.keyState, keyId: judged.keyId, keys: null, step: null };
      const masterKey = native.randomBytes(32);
      const keys = deriveKeys(masterKey);
      try {
        await registerKey(turn, keys, false);
      } catch (error) {
        if (error.code !== "key_exists") throw error;
        const again = await judgeKey(turn);
        return { keyState: again.keyState, keyId: again.keyId, keys: null, step: null };
      }
      writeMasterKey(masterKey);
      publishKey("present", keys);
      return { keyState: "present", keyId: keys.keyId, keys: keys, step: await grantStep(turn, keys, {}) };
    });
    if (made.step !== null) {
      await afterGrants(turn, made.keys, made.step);
      native.publish({ runtime: { ready: true } });
    }
    return { key_state: made.keyState, key_id: made.keyId };
  }

  /** Key replacement: while waiting for the key of another device, or while another key is
   *  registered, the key of the account is replaced with a new one. The nodes of the old ledger
   *  belong to the records of the old key, so a new node ledger is made and what this device kept
   *  of the log is forgotten. */
  async function resetKey(turn) {
    const made = await grantLock.run(turn, async function () {
      const judged = await judgeKey(turn);
      if (judged.keyState !== "waiting" && judged.keyState !== "mismatch") {
        throw native.error("invalid_state", judged.keyState);
      }
      const masterKey = native.randomBytes(32);
      const keys = deriveKeys(masterKey);
      await registerKey(turn, keys, true);
      writeMasterKey(masterKey);
      saveLedger(emptyLedger());
      clearLog();
      native.publish({ state: { log: logState } });
      publishKey("present", keys);
      return { keys: keys, step: await grantStep(turn, keys, {}) };
    });
    await afterGrants(turn, made.keys, made.step);
    native.publish({ runtime: { ready: true } });
    return { key_state: "present", key_id: made.keys.keyId };
  }

  // ---- Connections ----

  /** Verifies a statement a node signed (docs/protocol.md 8.2) and returns its body. The node
   *  must be one this device verified by its attestation and sent a grant: the node id is the
   *  signing key of the node. A statement of another node, and one that does not verify, is null. */
  function nodeStatement(grants, node, statement) {
    if (typeof node !== "string" || grants[node] === undefined) return null;
    try {
      return openSigned(statement, node, purpose("statement") + "\n");
    } catch (error) {
      return null;
    }
  }

  /** A connection: opens the authorization address a node made in the web authentication session
   *  and, after the callback, checks the completion statement of the node. The authorization address
   *  is opened only after a statement of a node this device handed a grant to verified over its
   *  account, the whole account signing public key (sign_pk, 32 bytes) and the hash of that
   *  address. A comparison of the key_id (8 bytes) alone is not a binding: a node takes a new grant
   *  of the same account from anyone, so the grant of another key whose first 8 bytes agree passes
   *  that comparison. */
  async function connect(turn, args) {
    const target = typeof args.target === "string" ? args.target.trim() : "";
    if (target === "") throw native.error("invalid_input", "target");
    const held = await withGrants(turn);
    const keys = held.keys;

    const sent = { target: target };
    for (const name of ["login_hint", "request_id"]) {
      if (typeof args[name] === "string") sent[name] = args[name];
    }
    for (const name of ["reward_notice", "new_account"]) {
      if (typeof args[name] === "boolean") sent[name] = args[name];
    }
    const begin = (await api(turn, "POST", "/api/secure/connections/begin", sent)).json;
    const user = userId();
    const opening = nodeStatement(held.grants, begin.node, begin.statement);
    const authorized = opening !== null && opening.type === "oauth_begin" && opening.node === begin.node &&
      opening.user_id === user && sameBytes(opening.sign_pk, keys.signPk) &&
      typeof begin.state === "string" && opening.state === begin.state &&
      typeof begin.authorization_url === "string" &&
      sameBytes(opening.url_sha256, native.sha256(encode(utf8(begin.authorization_url))));
    if (!authorized) throw native.error("unverified_authorization", "begin statement");

    const returned = await interactive(turn, function () {
      return native.webAuth({
        url: begin.authorization_url, callbackScheme: "pickle", ephemeral: begin.ephemeral_session === true,
      });
    });
    // A session closed without a return: the callback may have stored the connection and the user
    // closed the window on the second screen (the repository picker of GitHub). When the completion
    // of that authorization (kept as node_state) exists, it is connected, not cancelled.
    const nodeState = begin.state.split(".")[0];
    const query = returned === null
      ? { oauth_status: "connected", oauth_state: nodeState, closed_early: "true" }
      : parseQuery(String(returned));
    if (returned === null) {
      let kept = null;
      try {
        kept = (await api(turn, "GET", "/api/secure/connections/completion", null, { state: nodeState })).json;
      } catch (error) {
        if (failureCode(error) === "cancelled" || !(turnLeft(turn) > 0)) throw error;
        kept = null;
      }
      if (kept === null) throw native.error("cancelled", "web session closed");
    }
    if (query.oauth_status !== "connected") {
      throw native.error(query.oauth_error ? query.oauth_error : "connect_failed", "oauth callback");
    }
    if (!query.oauth_state) throw native.error("unverified_connection", "callback state");
    const completion = (await api(
      turn, "GET", "/api/secure/connections/completion", null, { state: query.oauth_state })).json;
    const closing = nodeStatement(held.grants, begin.node, completion.statement);
    const completed = closing !== null && closing.type === "oauth_complete" && closing.node === begin.node &&
      closing.user_id === user && sameBytes(closing.sign_pk, keys.signPk) && closing.state === begin.state;
    if (!completed) throw native.error("unverified_connection", "completion statement");
    const reward = Number(query.oauth_reward);
    return {
      connection_id: completion.connection_id, provider: completion.provider,
      reward: Number.isFinite(reward) ? reward : 0,
    };
  }

  function stringArgument(value) {
    return typeof value === "string" ? value : "";
  }

  /** Turning a write kind switch (Issues and pull requests, Code, Actions of a GitHub connection)
   *  on or off: PUT /api/integrations/{provider}/{connection_id}/writes. A setting that uses no
   *  credential, but one that decides how the credential is used, so it is a procedure of this
   *  program (secure_run of the definition calls it). */
  async function setConnectionWrites(turn, args) {
    const provider = stringArgument(args.provider).trim();
    const connectionId = stringArgument(args.connection_id).trim();
    const kind = stringArgument(args.kind).trim();
    if (provider === "" || connectionId === "" || kind === "") throw native.error("invalid_input", "writes");
    await api(
      turn, "PUT",
      "/api/integrations/" + encodeURIComponent(provider) + "/" + encodeURIComponent(connectionId) + "/writes",
      { kind: kind, enabled: args.enabled === true },
    );
    return { provider: provider, connection_id: connectionId, kind: kind, enabled: args.enabled === true };
  }

  /** Opens the repository picker (installation) screen of GitHub in the web authentication session
   *  (the "Manage repositories on GitHub" row of the connection detail). The server makes the
   *  address together with a signed state (POST /api/integrations/{provider}/installation-url), and
   *  the return place (the Setup URL) refreshes the list of installation accounts before sending the
   *  user back to pickle://oauth. Closing the window changes nothing, so the result is an empty
   *  object (not a cancellation). */
  async function manageRepositories(turn, args) {
    const provider = stringArgument(args.provider).trim();
    if (provider === "") throw native.error("invalid_input", "provider");
    const minted = (await api(
      turn, "POST", "/api/integrations/" + encodeURIComponent(provider) + "/installation-url", {})).json;
    if (typeof minted.url !== "string" || minted.url === "") {
      throw native.error("connect_failed", "installation url");
    }
    const returned = await interactive(turn, function () {
      return native.webAuth({ url: minted.url, callbackScheme: "pickle", ephemeral: false });
    });
    if (returned === null) return {};
    const query = parseQuery(String(returned));
    if (query.oauth_status !== "connected") {
      throw native.error(query.oauth_error ? query.oauth_error : "connect_failed", "installation return");
    }
    return { provider: provider };
  }

  /** An application password is encrypted on the device, and the completion statement is checked
   *  against the delegated node and the record. */
  async function connectAppPassword(turn, args) {
    const username = stringArgument(args.username).trim().toLowerCase();
    const password = stringArgument(args.password);
    if (!username || !password) throw native.error("invalid_input", "mail connection");
    const held = await withGrants(turn);
    const custody = heldCustody(held.ledger, held.grants, native.nowMs());
    if (custody === null) throw native.error("grant_required", "no node holds a grant");
    const record = sealRecord(held.keys, custody, "app_password", "naver_mail", {
      username: username, password: password,
    });
    return saveAppPasswordRecord(turn, held.keys, held.grants, record, args);
  }

  async function saveAppPasswordRecord(turn, keys, grants, record, args) {
    const body = { record: record };
    if (typeof args.request_id === "string") body.request_id = args.request_id;
    if (typeof args.setup_id === "string") body.setup_id = args.setup_id;
    const saved = (await api(turn, "PUT", "/api/secure/connections/naver_mail/app-password", body)).json;
    const statement = nodeStatement(grants, saved.node, saved.statement);
    const verified = statement !== null && statement.type === "app_password_verified" &&
      statement.node === saved.node && statement.user_id === userId() &&
      sameBytes(statement.sign_pk, keys.signPk) && statement.provider === "naver_mail" &&
      statement.record_id === record.id && statement.key_id === keys.keyId &&
      statement.identity === saved.identity &&
      sameBytes(statement.ciphertext_sha256, native.sha256(encode(utf8(record.ct))));
    if (!verified) throw native.error("unverified_connection", "mail completion statement");
    return { provider: "naver_mail", connection_id: saved.connection_id, identity: saved.identity };
  }

  // ---- The device-side reception of an application password issued in the browser ----

  const MAIL_SETUP_CONTEXT = "pickle-app-password-setup-v1";
  const MAIL_SETUP_PATH = "/api/secure/connections/naver_mail/setup";
  const MAIL_SETUP_TTL_MS = 2 * 60 * 60 * 1000;

  function mailSetupItem() {
    return { service: "com.pickle.client.secure.mail-setup", account: userId(), synchronizable: false };
  }

  function readMailSetup() {
    const raw = native.keychainGet(mailSetupItem());
    return raw === null ? null : JSON.parse(text(decode(raw)));
  }

  function writeMailSetup(value) {
    if (accountClosed) return;
    const item = mailSetupItem();
    native.keychainSet({
      service: item.service, account: item.account, synchronizable: false,
      accessible: "after_first_unlock", value: encode(utf8(JSON.stringify(value))),
    });
  }

  async function beginAppPasswordSetup(turn, args) {
    const held = await withGrants(turn);
    const keys = held.keys;
    let identity = stringArgument(args.identity).trim().toLowerCase();
    if (identity && identity.indexOf("@") < 0) identity += "@naver.com";
    if (identity && !/^[a-z0-9_.-]{1,64}@naver\.com$/.test(identity)) {
      throw native.error("invalid_input", "NAVER account");
    }
    let local = readMailSetup();
    if (local && (local.intent.key_id !== keys.keyId || local.intent.expires_ms <= native.nowMs())) {
      // The capturing state of the server does not release its observation protection on a
      // cancellation alone.
      await api(turn, "DELETE", MAIL_SETUP_PATH + "/" + local.intent.id);
      native.keychainDelete(mailSetupItem());
      local = null;
    }
    if (local) {
      const remote = (await api(turn, "GET", MAIL_SETUP_PATH, null, { setup_id: local.intent.id })).json.setup;
      if (remote && remote.setup_id === local.intent.id && remote.request.payload === local.signed.payload &&
          (remote.phase === "failed" || remote.phase === "cancelled")) {
        native.keychainDelete(mailSetupItem());
        local = null;
      }
    }
    if (local && local.intent.identity !== identity) {
      throw native.error("setup_in_progress", "another mail setup is pending");
    }
    if (!local) {
      const sk = native.randomBytes(32);
      const now = Math.floor(native.nowMs());
      const intent = {
        id: native.randomBytes(16), user_id: userId(), key_id: keys.keyId,
        provider: "naver_mail", recipient_pk: native.x25519PublicKey(sk), identity: identity,
        request_id: stringArgument(args.request_id), issued_ms: now, expires_ms: now + MAIL_SETUP_TTL_MS,
      };
      const payload = encode(utf8(JSON.stringify(intent)));
      const signature = native.ed25519Sign(
        keys.signSeed, encode(concat(utf8(MAIL_SETUP_CONTEXT + "\n"), decode(payload))));
      local = { intent: intent, sk: sk, signed: { payload: payload, signature: signature }, record: null };
      // The same request and reception key are used again when the POST response is lost.
      writeMailSetup(local);
    }
    const saved = (await api(turn, "POST", MAIL_SETUP_PATH, local.signed)).json;
    native.publish({ state: { mail_setup: { phase: saved.phase, error: null } } });
    return saved;
  }

  async function finishAppPasswordSetup(turn, keys, ledger, grants) {
    const local = readMailSetup();
    if (!local) return;
    const intent = local.intent;
    if (intent.user_id !== userId() || intent.key_id !== keys.keyId || intent.expires_ms <= native.nowMs()) {
      native.keychainDelete(mailSetupItem());
      native.publish({ state: { mail_setup: { phase: "expired", error: null } } });
      return;
    }
    try {
      const pending = (await api(turn, "GET", MAIL_SETUP_PATH, null, { setup_id: intent.id })).json.setup;
      if (!pending) {
        if (local.completed) {
          native.keychainDelete(mailSetupItem());
          native.publish({ state: { mail_setup: { phase: "connected", identity: local.completed.identity, error: null } } });
        }
        return;
      }
      if (pending.setup_id !== intent.id || pending.request.payload !== local.signed.payload ||
          pending.request.signature !== local.signed.signature) {
        throw native.error("unverified_connection", "mail setup request");
      }
      native.publish({ state: { mail_setup: { phase: pending.phase, error: null } } });
      if (pending.phase === "failed" || pending.phase === "cancelled") {
        native.keychainDelete(mailSetupItem());
        return;
      }
      if (pending.phase !== "captured" && pending.phase !== "connected") return;
      const custody = heldCustody(ledger, grants, native.nowMs());
      if (custody === null) return;
      if (!local.record) {
        if (!pending.capture) throw native.error("invalid_response", "mail setup capture");
        const opened = native.hpkeOpen({
          kem: "x25519", kdf: "sha256", aead: "chacha20poly1305", recipientPrivateKey: local.sk,
          info: encode(utf8(MAIL_SETUP_CONTEXT)), aad: native.sha256(local.signed.payload),
          enc: pending.capture.enc, ciphertext: pending.capture.ct,
        });
        const credential = JSON.parse(text(decode(opened)));
        if (!credential || typeof credential.username !== "string" ||
            !/^[a-z0-9_.-]{1,64}@naver\.com$/.test(credential.username) ||
            typeof credential.password !== "string" || !credential.password ||
            (intent.identity && intent.identity !== credential.username)) {
          throw native.error("unverified_connection", "mail setup account");
        }
        local.record = sealRecordBytes(keys, custody, "app_password", "naver_mail", opened);
        // The same ciphertext is sent again so that a lost response does not become a second
        // registration.
        writeMailSetup(local);
      }
      const saved = await saveAppPasswordRecord(turn, keys, grants, local.record, {
        setup_id: intent.id, request_id: intent.request_id,
      });
      local.completed = saved;
      writeMailSetup(local);
      await api(turn, "DELETE", MAIL_SETUP_PATH + "/" + intent.id);
      native.keychainDelete(mailSetupItem());
      native.publish({ state: { mail_setup: { phase: "connected", identity: saved.identity, error: null } } });
    } catch (error) {
      if (failureCode(error) === "cancelled") throw error;
      // Neither the remote error body nor a secret is published. The next sync resumes the stored
      // request.
      native.publish({ state: { mail_setup: { phase: "pending", error: failureCode(error) } } });
    }
  }

  async function cancelAppPasswordSetup(turn) {
    const local = readMailSetup();
    if (local) await api(turn, "DELETE", MAIL_SETUP_PATH + "/" + local.intent.id);
    native.keychainDelete(mailSetupItem());
    native.publish({ state: { mail_setup: null } });
    return {};
  }

  // ---- The vault ----

  /** Storing a site login: the password and the TOTP seed each become a record in the vault. An
   *  empty one is not sent (the backend keeps the existing record). */
  async function storeLogin(turn, args) {
    const username = stringArgument(args.username).trim();
    const password = stringArgument(args.password);
    const totp = stringArgument(args.totp).replace(/\s/g, "").toUpperCase();
    if (username === "" || typeof args.name !== "string") throw native.error("invalid_input", "login");
    if (totp !== "" && !/^[A-Z2-7]+=*$/.test(totp)) throw native.error("invalid_input", "totp");
    const keys = await presentKeys(turn);
    const body = { name: args.name, username: username };
    if (password !== "" || totp !== "") {
      const custody = await recordCustody(turn);
      if (password !== "") {
        body.password = sealRecord(keys, custody, "vault_password", "vault", { value: password });
      }
      if (totp !== "") body.totp = sealRecord(keys, custody, "vault_totp", "vault", { value: totp });
    }
    const saved = (await api(turn, "PUT", VAULT_PATH + "/login", body)).json;
    return { name: saved.name };
  }

  /** The Luhn check of a card number. */
  function luhnValid(digits) {
    let sum = 0;
    for (let i = 0; i < digits.length; i += 1) {
      let digit = digits.charCodeAt(digits.length - 1 - i) - 48;
      if (i % 2 === 1) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
    }
    return sum % 10 === 0;
  }

  function cardBrand(number) {
    const two = Number(number.slice(0, 2));
    const four = Number(number.slice(0, 4));
    if (number[0] === "4") return "visa";
    if ((two >= 51 && two <= 55) || (four >= 2221 && four <= 2720)) return "mastercard";
    if (two === 34 || two === 37) return "amex";
    return "card";
  }

  /** Storing a card: the number and the CVC become one record in the vault. When both the number
   *  and the CVC are empty, neither the record nor brand and last4 are sent (the backend keeps the
   *  existing values). */
  async function storeCard(turn, args) {
    const number = stringArgument(args.number).replace(/[\s-]/g, "");
    const cvc = stringArgument(args.cvc).trim();
    const expiry = stringArgument(args.expiry).replace(/[^0-9]/g, "");
    if (number !== "" && (!/^[0-9]{12,19}$/.test(number) || !luhnValid(number))) {
      throw native.error("invalid_input", "number");
    }
    if (cvc !== "" && !/^[0-9]{3,4}$/.test(cvc)) throw native.error("invalid_input", "cvc");
    if ((number === "") !== (cvc === "")) throw native.error("invalid_input", "number and cvc");
    if (expiry.length !== 4 && expiry.length !== 6) throw native.error("invalid_input", "expiry");
    const month = Number(expiry.slice(0, 2));
    const year = expiry.length === 4 ? 2000 + Number(expiry.slice(2)) : Number(expiry.slice(2));
    if (month < 1 || month > 12 || year < 2000 || year > 2099) throw native.error("invalid_input", "expiry");
    const keys = await presentKeys(turn);
    const body = {
      name: stringArgument(args.name), label: stringArgument(args.label),
      cardholder: stringArgument(args.cardholder),
    };
    if (number !== "") {
      body.brand = cardBrand(number);
      body.last4 = number.slice(-4);
    }
    body.exp_month = month;
    body.exp_year = year;
    body.postal = stringArgument(args.postal);
    if (number !== "") {
      const custody = await recordCustody(turn);
      body.value = sealRecord(keys, custody, "vault_card", "vault", { number: number, cvc: cvc });
    }
    body.request_id = stringArgument(args.request_id);
    const saved = (await api(turn, "PUT", VAULT_PATH + "/card", body)).json;
    return { name: saved.name };
  }

  // ---- Vault secrets (docs/protocol.md section 6, kind vault_secret) ----
  //
  // A vault secret is a value under a name, with the hosts it may go to (sites) and the places it
  // may be put (slots). The reach (sites and slots) and the name are part of the plaintext of the
  // record, so whoever cannot encrypt under the user key cannot change them. The value of a secret
  // is never part of a request, of a published value or of the program store: it goes into the
  // record this device seals, and, when the user asks to see it, to the protected sheet of the app
  // (in a build without that sheet, into the result of the procedure).

  const SECRET_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;

  /** Whether the two protected sheets of the app exist in this build (promptSecret, presentSecret). */
  function protectedSheets() {
    return typeof native.promptSecret === "function" && typeof native.presentSecret === "function";
  }

  /** Whether host is the host of a site: a DNS name in lower case of at most 253 bytes with two or
   *  more labels, each label 1 to 63 characters of a to z, 0 to 9 and "-" that neither begins nor
   *  ends with "-", whose last label begins with a letter (an address in any spelling is no host). */
  function isSiteHost(host) {
    if (typeof host !== "string" || host.length > 253) return false;
    const labels = host.split(".");
    if (labels.length < 2) return false;
    for (const label of labels) {
      if (!/^[a-z0-9-]{1,63}$/.test(label) || label[0] === "-" || label[label.length - 1] === "-") return false;
    }
    return /^[a-z]/.test(labels[labels.length - 1]);
  }

  /** Whether a name holds neither a control character nor a white space character. */
  function plainName(name) {
    for (const symbol of name) {
      const code = symbol.codePointAt(0);
      if (code <= 0x20 || (code >= 0x7f && code <= 0xa0) || code === 0x1680 || (code >= 0x2000 && code <= 0x200a) ||
          code === 0x2028 || code === 0x2029 || code === 0x202f || code === 0x205f || code === 0x3000) {
        return false;
      }
    }
    return true;
  }

  /** Whether a text is a slot: field (an input of a web page), path, basic:user, basic:password,
   *  header:<name> (1 to 64 characters of a to z, 0 to 9 and "-", and no header a node of the
   *  forward role drops or refuses), query:<name> and form:<name> (1 to 64 unreserved characters),
   *  or json:<name> (1 to 64 bytes without a control or white space character, object keys joined
   *  by "."). The name is what follows the first colon. */
  function isSlot(slot) {
    if (typeof slot !== "string") return false;
    if (slot === "field" || slot === "path" || slot === "basic:user" || slot === "basic:password") return true;
    const colon = slot.indexOf(":");
    if (colon < 0) return false;
    const kind = slot.slice(0, colon);
    const name = slot.slice(colon + 1);
    const size = utf8(name).length;
    if (size < 1 || size > VAULT_SLOT_NAME_BYTES) return false;
    if (kind === "header") return /^[a-z0-9-]+$/.test(name) && VAULT_RESERVED_HEADERS.indexOf(name) < 0;
    if (kind === "query" || kind === "form") return /^[A-Za-z0-9._~-]+$/.test(name);
    if (kind === "json") {
      return plainName(name) && name.split(".").every(function (key) { return key !== ""; });
    }
    return false;
  }

  /** Reads the reach of a vault secret: sites is the string "any" or 1 to VAULT_SITES_MAX hosts,
   *  no host twice; slots is 1 to VAULT_SLOTS_MAX slots, no slot twice, and either the one slot
   *  field or slots of a request; a secret whose sites is "any" has the one slot field. Returns
   *  {sites, slots} or null for any other form. */
  function readReach(sites, slots) {
    let hosts = null;
    if (sites === "any") {
      hosts = "any";
    } else if (Array.isArray(sites) && sites.length >= 1 && sites.length <= VAULT_SITES_MAX) {
      hosts = [];
      for (const host of sites) {
        if (!isSiteHost(host) || hosts.indexOf(host) >= 0) return null;
        hosts.push(host);
      }
    } else {
      return null;
    }
    if (!Array.isArray(slots) || slots.length < 1 || slots.length > VAULT_SLOTS_MAX) return null;
    const places = [];
    for (const slot of slots) {
      if (!isSlot(slot) || places.indexOf(slot) >= 0) return null;
      places.push(slot);
    }
    const typed = places.length === 1 && places[0] === "field";
    if (places.indexOf("field") >= 0 && !typed) return null;
    if (hosts === "any" && !typed) return null;
    return { sites: hosts, slots: places };
  }

  /** A list argument of a definition action: an array, the JSON of one, the string "any", or
   *  names separated by commas or white space. */
  function listArgument(value) {
    if (Array.isArray(value)) return value;
    if (typeof value !== "string") return null;
    const trimmed = value.trim();
    if (trimmed === "any") return "any";
    if (trimmed[0] === "[") {
      try {
        const parsed = JSON.parse(trimmed);
        return Array.isArray(parsed) ? parsed : null;
      } catch (error) {
        return null;
      }
    }
    return trimmed.split(/[\s,]+/).filter(function (part) { return part !== ""; });
  }

  /** The plaintext of a record of kind vault_secret as a device writes it (base64url of the UTF-8
   *  JSON): value, name, sites, slots, source and pad, in this order. pad is a string of "."
   *  that brings the plaintext to the shortest length of VAULT_PADDED_BYTES it fits, so the length
   *  of the record tells the operator domain, which stores it, one of seven steps and not the
   *  length of the value. A value that is empty or holds U+0000 is invalid_input, and a plaintext
   *  above the longest step is too_large. */
  function secretPlaintext(value, name, reach, source) {
    if (typeof value !== "string" || value === "" || value.indexOf("\u0000") >= 0) {
      throw native.error("invalid_input", "value");
    }
    const written = function (pad) {
      return utf8(JSON.stringify({
        value: value, name: name, sites: reach.sites, slots: reach.slots, source: source, pad: pad,
      }));
    };
    const bare = written("").length;
    const padded = VAULT_PADDED_BYTES.find(function (step) { return step >= bare; });
    if (padded === undefined) throw native.error("too_large", "value");
    return encode(written(".".repeat(padded - bare)));
  }

  /** The language of the lines this program writes for the user: ko, ja or en, by the locale of
   *  the device. */
  function language() {
    const locale = String(native.deviceInfo().locale || "");
    return locale.indexOf("ko") === 0 ? "ko" : locale.indexOf("ja") === 0 ? "ja" : "en";
  }

  const SLOT_WORDS = {
    en: { field: "typed into its pages", path: "the path of a request", "basic:user": "the user name of a request", "basic:password": "the password of a request", header: "request header ", query: "request parameter ", form: "form field ", json: "JSON field ", any: "Any website", below: " and the hosts below it" },
    ko: { field: "웹 페이지에 입력", path: "요청의 주소 경로", "basic:user": "요청의 사용자 이름", "basic:password": "요청의 비밀번호", header: "요청 헤더 ", query: "요청 매개변수 ", form: "폼 필드 ", json: "JSON 필드 ", any: "모든 웹사이트", below: "과 그 하위 호스트" },
    ja: { field: "ページに入力", path: "リクエストのパス", "basic:user": "リクエストのユーザー名", "basic:password": "リクエストのパスワード", header: "リクエストヘッダー ", query: "リクエストパラメータ ", form: "フォーム項目 ", json: "JSON項目 ", any: "すべてのウェブサイト", below: "とその下位ホスト" },
  };

  /** The lines that say where the value of a vault secret can go, one per host: the host and the
   *  places of the reach, in the language of the device. The lines are made from the reach that is
   *  sealed into the record, so what the user reads is what the record binds. */
  function destinationLines(reach) {
    const words = SLOT_WORDS[language()];
    const places = reach.slots.map(function (slot) {
      if (words[slot] !== undefined) return words[slot];
      const colon = slot.indexOf(":");
      return words[slot.slice(0, colon)] + slot.slice(colon + 1);
    }).join(", ");
    const typed = reach.slots.length === 1 && reach.slots[0] === "field";
    const hosts = reach.sites === "any" ? [words.any] : reach.sites.map(function (host) {
      return typed ? host + words.below : host;
    });
    return hosts.map(function (host) { return (host + " · " + places).slice(0, 200); });
  }

  const OWNER_AUTH_REASONS = {
    en: { reveal: "Show the saved value", change: "Change where the saved value can be used", remove: "Delete the saved value" },
    ko: { reveal: "저장된 값 보기", change: "저장된 값이 쓰이는 곳 변경", remove: "저장된 값 삭제" },
    ja: { reveal: "保存した値を表示", change: "保存した値の使用先を変更", remove: "保存した値を削除" },
  };

  /** The device owner authentication a procedure asks for before it reads or changes a secret.
   *  A refusal is auth_failed. */
  async function ownerAuth(turn, purposeOf) {
    const reason = OWNER_AUTH_REASONS[language()][purposeOf];
    const passed = await interactive(turn, function () { return native.deviceOwnerAuth(reason); });
    if (passed !== true) throw native.error("auth_failed", "device owner authentication");
  }

  /** The keys of the master key this device holds; key_required when it holds none. */
  function heldKeys() {
    const masterKey = readMasterKey();
    if (masterKey === null) throw native.error("key_required", "no master key on this device");
    return deriveKeys(masterKey);
  }

  function secretName(args) {
    const name = stringArgument(args.name).trim();
    if (!SECRET_NAME.test(name)) throw native.error("invalid_input", "name");
    return name;
  }

  /** The title a protected sheet shows: the label of the item, or its name. */
  function sheetTitle(label, name) {
    const title = typeof label === "string" && label.trim() !== "" ? label.trim() : name;
    return title.slice(0, 120);
  }

  /** store_secret: makes the value the user entered a record of kind vault_secret and uploads it.
   *  The name, the sites and the slots of the item come from the backend and are checked against
   *  the form of a vault secret before they enter the plaintext. Without a name, the item is made
   *  first from the label, sites and slots given (an item the user adds on the vault screen). In a
   *  build with the protected sheets the value is asked for in the input sheet, with the lines of
   *  where the value can go made from the reach that is sealed; otherwise it is the argument
   *  value. A node that holds the grant is made sure of before the value is asked for. */
  async function storeSecret(turn, args) {
    const keys = await presentKeys(turn);
    const custody = await recordCustody(turn);
    let name = stringArgument(args.name).trim();
    if (name === "") {
      const wanted = readReach(listArgument(args.sites), listArgument(args.slots));
      if (wanted === null) throw native.error("invalid_input", "sites and slots");
      const made = (await api(turn, "POST", VAULT_PATH + "/secret", {
        label: stringArgument(args.label).trim(), sites: wanted.sites, slots: wanted.slots,
      })).json;
      name = stringArgument(made.name);
    }
    if (!SECRET_NAME.test(name)) throw native.error("invalid_input", "name");
    const item = (await api(turn, "GET", VAULT_PATH + "/secret/" + name)).json;
    const reach = readReach(item.sites, item.slots);
    if (item.name !== name || reach === null) throw native.error("invalid_response", "secret");
    let value = args.value;
    if (protectedSheets()) {
      const answer = await interactive(turn, function () {
        return native.promptSecret({ title: sheetTitle(item.label, name), destinations: destinationLines(reach) });
      });
      if (answer === null || typeof answer !== "object") throw native.error("cancelled", "secret prompt");
      value = answer.value;
    }
    const record = sealRecordBytes(keys, custody, "vault_secret", "vault", secretPlaintext(value, name, reach, "device"));
    const saved = (await api(turn, "PUT", VAULT_PATH + "/secret/" + name, {
      record: record, sites: reach.sites, slots: reach.slots,
    })).json;
    return { name: name, state: typeof saved.state === "string" ? saved.state : "ready" };
  }

  /** The plaintext of the record of the item name, opened with the user key of this device:
   *  {value, reach, source}. A record whose plaintext names another name, or has another form, is
   *  record_invalid; an item without a record is secret_empty. */
  function openSecret(keys, item, name) {
    if (item.record === undefined || item.record === null) throw native.error("secret_empty", name);
    const plain = openRecord(keys, item.record, "vault_secret", "vault");
    const reach = readReach(plain.sites, plain.slots);
    if (plain.name !== name || typeof plain.value !== "string" || reach === null ||
        (plain.source !== "device" && plain.source !== "operator")) {
      throw native.error("record_invalid", "vault_secret");
    }
    return { value: plain.value, reach: reach, source: plain.source };
  }

  /** reveal_secret: shows the value of an item to the user. The device owner authentication comes
   *  before the query. The record is opened on this device; nothing of the value passes a server.
   *  In a build with the protected sheets the value is shown in the display sheet and is not part
   *  of the result. */
  async function revealSecret(turn, args) {
    const name = secretName(args);
    const keys = heldKeys();
    await ownerAuth(turn, "reveal");
    const item = (await api(turn, "GET", VAULT_PATH + "/secret/" + name)).json;
    const secret = openSecret(keys, item, name);
    if (!protectedSheets()) {
      return { name: name, value: secret.value, sites: secret.reach.sites, slots: secret.reach.slots, source: secret.source };
    }
    await interactive(turn, function () {
      return native.presentSecret({
        title: sheetTitle(item.label, name), value: secret.value, destinations: destinationLines(secret.reach),
      });
    });
    return { name: name };
  }

  /** update_secret: changes the reach of an item. The device owner authentication comes before
   *  the query. An item with a record has it opened and sealed again under the same id with the new
   *  reach (the source of the value stays what it was). */
  async function updateSecret(turn, args) {
    const name = secretName(args);
    const reach = readReach(listArgument(args.sites), listArgument(args.slots));
    if (reach === null) throw native.error("invalid_input", "sites and slots");
    const keys = heldKeys();
    await ownerAuth(turn, "change");
    const item = (await api(turn, "GET", VAULT_PATH + "/secret/" + name)).json;
    const body = { sites: reach.sites, slots: reach.slots };
    if (item.record !== undefined && item.record !== null) {
      const secret = openSecret(keys, item, name);
      body.record = sealRecordBytes(
        keys, item.record.custody, "vault_secret", "vault",
        secretPlaintext(secret.value, name, reach, secret.source), item.record.id);
    }
    const saved = (await api(turn, "POST", VAULT_PATH + "/secret/" + name + "/binding", body)).json;
    return { name: name, sites: saved.sites === undefined ? reach.sites : saved.sites, slots: saved.slots === undefined ? reach.slots : saved.slots };
  }

  /** delete_secret: removes an item. The device owner authentication comes before the request. */
  async function deleteSecret(turn, args) {
    const name = secretName(args);
    await ownerAuth(turn, "remove");
    await api(turn, "DELETE", VAULT_PATH + "/secret/" + name);
    return { name: name };
  }

  /** reveal_login_password: shows a password the vault made for a login (a record of kind
   *  vault_password whose plaintext says that a node made it: source operator). The device owner
   *  authentication comes before the query. args.at names an earlier password of the login by its
   *  time; without it the current one is shown. */
  async function revealLoginPassword(turn, args) {
    const site = stringArgument(args.site).trim();
    if (site === "" || site.length > 253) throw native.error("invalid_input", "site");
    const keys = heldKeys();
    await ownerAuth(turn, "reveal");
    const listed = (await api(turn, "GET", VAULT_PATH + "/login/" + encodeURIComponent(site) + "/passwords")).json;
    const wanted = typeof args.at === "string" && /^[0-9]+$/.test(args.at) ? Number(args.at) : args.at;
    let found = listed.current === undefined ? null : listed.current;
    if (wanted !== undefined && wanted !== null && wanted !== "") {
      const all = (found === null ? [] : [found]).concat(Array.isArray(listed.history) ? listed.history : []);
      found = all.find(function (item) { return item !== null && typeof item === "object" && item.at === wanted; });
    }
    if (found === undefined || found === null || typeof found !== "object" ||
        found.record === undefined || found.record === null) {
      throw native.error("password_unavailable", "login password");
    }
    const plain = openRecord(keys, found.record, "vault_password", "vault");
    if (plain.source !== "operator" || typeof plain.value !== "string" || plain.value === "") {
      throw native.error("record_invalid", "vault_password");
    }
    if (!protectedSheets()) return { site: site, value: plain.value };
    await interactive(turn, function () {
      return native.presentSecret({ title: site.slice(0, 120), value: plain.value });
    });
    return { site: site };
  }

  // ---- The procedures of the log screen ----

  // The places of the later pages of the log screen (runtime lifetime): {id, before_ms, after_day,
  // rows, opened}. The screen draws a page for each place and reads it with read_log_page when it
  // scrolls near it.
  let logPagePlaces = [];

  function publishLogPages() {
    native.publish({ runtime: { log_pages: logPagePlaces } });
  }

  /** The place of the next page after one page: before_ms is the time of the last entry of that
   *  page (every entry of that millisecond is on that page), rows the number of display groups up
   *  to that page (rows up to the previous pages plus shown, the groups of this page). null when the
   *  page has no entry or there is no more. */
  function logPageAfter(page, rows, shown) {
    if (page.has_more !== true || page.last_ms < 1) return null;
    return {
      id: String(page.last_ms), before_ms: page.last_ms, after_day: formatTime(page.last_ms, "date"),
      rows: rows + shown, opened: false,
    };
  }

  /** The before_ms argument: an integer of 1 or more, or its decimal string. Otherwise null. */
  function logPageCursor(value) {
    const before = typeof value === "string" && /^[0-9]+$/.test(value) ? Number(value) : value;
    return Number.isSafeInteger(before) && before >= 1 ? before : null;
  }

  /** The limit argument of read_log and read_security_record: a number or its decimal string (the
   *  arguments of a definition action arrive as evaluated strings), from 1 to 500; fallback when
   *  it is neither. */
  function screenLimit(args, fallback) {
    const textual = typeof args.limit === "string" && args.limit.trim() !== "";
    const given = textual ? Number(args.limit) : args.limit;
    return Number.isFinite(given) ? Math.min(500, Math.max(1, Math.floor(given))) : fallback;
  }

  /** The page of the screen the device kept: the entries of the first page it showed last, up to
   *  limit events. null when it kept none. */
  function keptPage(cache, limit) {
    if (cache.saved_ms === 0) return null;
    const entries = [];
    const items = [];
    let count = 0;
    for (const entry of cache.entries) {
      if (count >= limit) break;
      entries.push(entry);
      for (let at = entry.items.length - 1; at >= 0; at -= 1) items.push(entry.items[at]);
      count += entry.items.length;
    }
    return {
      entries: entries, items: items, last_ms: entries.length === 0 ? 0 : entries[entries.length - 1].time_ms,
      has_more: cache.has_more || entries.length < cache.entries.length,
    };
  }

  /** The result of read_log for one page of the screen: the list as day groups, the summary, and
   *  the state of the log. For an answer made from the kept screen alone the status is pending
   *  (the screen asks again, and the read that goes on answers then), cached is true and cached_ms
   *  is the time the device kept the screen. The place of the second page becomes the list of the
   *  places of the later pages, unless that place already begins the list (a read that changed
   *  nothing leaves the pages the screen opened below it alone). */
  function screenResult(page, summary, log, cachedMs) {
    const groups = displayGroups(page.items);
    const next = logPageAfter(page, 0, groups.length);
    const same = next !== null && logPagePlaces.length > 0 && logPagePlaces[0].before_ms === next.before_ms &&
      logPagePlaces[0].rows === next.rows;
    if (!same) {
      logPagePlaces = next === null ? [] : [next];
      publishLogPages();
    }
    return {
      status: cachedMs === null ? log.status : "pending", verified_ms: log.verified_ms,
      unverified_nodes: log.unverified_nodes, missing: log.missing, expired: 0,
      unknown_nodes: log.unknown_nodes, newer_release_nodes: log.newer_release_nodes, store: log.store,
      store_failing_ms: log.store_failing_ms, has_more: page.has_more, summary: summary,
      days: displayDays(groups), cached: cachedMs !== null, cached_ms: cachedMs === null ? 0 : cachedMs,
    };
  }

  /** The answer of read_log from the kept screen alone: no request is sent. An empty list when
   *  the device kept no screen. */
  function keptAnswer(keys, limit) {
    const cache = loadCache(keys);
    const page = keptPage(cache, limit) || { entries: [], items: [], last_ms: 0, has_more: false };
    const since = summarySince(native.nowMs());
    pruneSummary(cache.tally, since);
    const summary = cache.saved_ms === 0 ? null : summaryResult(cache.tally, since, true);
    return screenResult(page, summary, keptLogState(), cache.saved_ms);
  }

  // The read of the first page from the store in flight (null: none): {promise, limit}.
  let screenFlight = null;

  // A read of the first page from the store, counted under the name log_screen, on the line of the
  // screen.
  const countedScreenRead = tracked("log_screen", function (args, turn) {
    return screenLine.run(turn, function () { return readScreen(turn, heldKeys(), args.limit); });
  });

  /** The read of the first page from the store that a call of read_log waits for: the one in
   *  flight when it reads at least limit events, otherwise a new one. */
  function screenRead(limit) {
    if (screenFlight !== null && screenFlight.limit >= limit) return screenFlight.promise;
    const flight = { limit: limit, promise: null };
    flight.promise = countedScreenRead({ limit: limit });
    const ended = function () {
      if (screenFlight === flight) screenFlight = null;
    };
    flight.promise.then(ended, ended);
    screenFlight = flight;
    return flight.promise;
  }

  /** read_log: the first page of the log screen and the summary. The call starts a read of the
   *  screen from the store (or joins the one in flight) and waits for it for LOG_SCREEN_WAIT_MS;
   *  when the read has not ended by then, the call answers from the screen the device kept, with
   *  the status pending, and the read goes on (the screen asks again and receives what was read).
   *  With the argument kept true the call answers from the kept screen at once, without waiting. */
  async function readLog(turn, args) {
    const limit = screenLimit(args, 100);
    const keys = heldKeys();
    const read = screenRead(limit);
    read.then(noop, noop);
    if (args.kept === true || args.kept === "true") return keptAnswer(keys, limit);
    const waited = await Promise.race([
      settled(read),
      pause(Math.min(LOG_SCREEN_WAIT_MS, Math.max(0, turnLeft(turn)))).then(function () { return null; }),
    ]);
    if (waited === null) return keptAnswer(keys, limit);
    if (!waited.ok) {
      const code = failureCode(waited.error);
      if (code === "cancelled" || code === "key_required") throw waited.error;
      native.log("log screen: " + code);
      return keptAnswer(keys, limit);
    }
    return screenResult(waited.value.page, waited.value.summary, waited.value.log, null);
  }

  /** Records that the screen started reading the page of that place (at the call of read_log_page:
   *  it does not wait for the earlier procedures). A place that is not in the list and a place
   *  already recorded are left unchanged. */
  function openLogPage(before) {
    const at = logPagePlaces.findIndex(function (place) { return place.before_ms === before; });
    if (at < 0 || logPagePlaces[at].opened) return;
    const place = logPagePlaces[at];
    logPagePlaces = logPagePlaces.slice();
    logPagePlaces[at] = {
      id: place.id, before_ms: place.before_ms, after_day: place.after_day, rows: place.rows, opened: true,
    };
    publishLogPages();
  }

  /** read_log_page: one later page of the log screen, the entries before before_ms until
   *  LOG_SCREEN_EVENTS events, as the list of day groups (consecutive requests and days that
   *  straddle a page boundary are grouped per page). When that place is the last of the list and
   *  there is more, the next place is appended (a call that reads an earlier page again, and a call
   *  that ended after read_log replaced the list, append nothing). */
  async function readLogPage(turn, args) {
    const before = logPageCursor(args.before_ms);
    if (before === null) throw native.error("invalid_input", "before_ms");
    const keys = heldKeys();
    const cache = loadCache(keys);
    const page = await readPage(turn, keys, cache, before, LOG_SCREEN_EVENTS);
    const groups = displayGroups(page.items);
    const last = logPagePlaces.length === 0 ? null : logPagePlaces[logPagePlaces.length - 1];
    const next = last !== null && last.before_ms === before ? logPageAfter(page, last.rows, groups.length) : null;
    if (next !== null) {
      logPagePlaces = logPagePlaces.concat([next]);
      publishLogPages();
    }
    return { has_more: page.has_more, days: displayDays(groups) };
  }

  // The code the security record screen of the app shows a display group under, by its kind and,
  // for a request, by its action.
  const RECORD_KINDS = {
    grant_renewed: "delegation_renewed", grant_revoked: "delegation_revoked", moved: "delegation_moved",
    connected: "connected", disconnected: "disconnected", signed_in: "sign_in_renewed",
    used: "credential_used", filled: "value_filled", secret_sent: "value_sent", secret_saved: "value_saved",
    code: "code_issued", other_key: "other_key", unverified: "unverified",
  };
  const RECORD_ACTIONS = {
    read: "read", change: "changed", delete: "deleted", send_mail: "mail_sent",
    send_message: "message_sent", payment: "payment_requested", verify: "sign_in_checked",
  };

  /** One item of the security record screen for a display group: {id, time_ms, kind, subject,
   *  detail, count}. subject is the name of what the record is about (the service of a request,
   *  the name of a vault value) and detail the place (the address of a request, the host a value
   *  went to, the end of a grant). */
  function recordItem(group) {
    let kind = RECORD_KINDS[group.kind];
    let subject = group.service_name !== "" ? group.service_name : group.provider_name;
    let detail = group.detail;
    if (group.kind === "request") {
      kind = RECORD_ACTIONS[group.action];
      detail = group.requests.length > 0 ? group.requests[group.requests.length - 1].target : "";
    } else if (group.kind === "filled" || group.kind === "secret_sent" || group.kind === "secret_saved") {
      subject = group.name !== "" ? group.name : group.field;
    } else if (group.kind === "code") {
      subject = "";
    }
    return {
      id: group.id, time_ms: group.time_ms, kind: kind === undefined ? "other" : kind,
      subject: String(subject).slice(0, 300), detail: String(detail).slice(0, 300), count: group.count,
    };
  }

  /** read_security_record: the access record of the security record screen the app binary draws.
   *  Without before_ms it reads the first page from the store (a round runs with it, and its
   *  judgement reaches the app through securityStatus); with before_ms the page before that time.
   *  Returns {items, next_before_ms}: the items with the latest first, and the before_ms of the
   *  next page (null when there is none). */
  async function readSecurityRecord(turn, args) {
    const limit = screenLimit(args, LOG_SCREEN_EVENTS);
    const keys = heldKeys();
    const before = args.before_ms === undefined || args.before_ms === null ? null : logPageCursor(args.before_ms);
    if (before === null && args.before_ms !== undefined && args.before_ms !== null) {
      throw native.error("invalid_input", "before_ms");
    }
    const page = before === null
      ? (await readScreen(turn, keys, limit)).page
      : await readPage(turn, keys, loadCache(keys), before, limit);
    const items = displayGroups(page.items).map(recordItem);
    return { items: items, next_before_ms: page.has_more && page.last_ms >= 1 ? page.last_ms : null };
  }

  // ---- The settings of the delegation ----

  /** set_grant_days: the lifetime of a grant, an integer from 1 to 30 (or its decimal string). A
   *  grant of that lifetime is handed again to every listed node (without regard to the renewal
   *  interval: a shortened lifetime applies at once), and when every node took it the value is
   *  written to the ledger. When any node did not take the grant the lifetime of the ledger is left
   *  unchanged (the grant times and expiries of the nodes that took it are kept) and the call fails
   *  with grant_incomplete: that node may still hold a grant of the earlier lifetime. When
   *  delegation is off only the value is written. */
  function setGrantDays(turn, args) {
    const textual = typeof args.days === "string" && /^[0-9]+$/.test(args.days);
    const days = textual ? Number(args.days) : args.days;
    if (!Number.isSafeInteger(days) || days < 1 || days > GRANT_DAYS_MAX) {
      throw native.error("invalid_input", "days");
    }
    return grantLock.run(turn, async function () {
      const keys = await presentKeys(turn);
      const ledger = loadLedger();
      const kept = { ttl_days: ledger.ttl_days, ttl_set_ms: ledger.ttl_set_ms };
      ledger.ttl_days = days;
      ledger.ttl_set_ms = Math.max(native.nowMs(), ledger.ttl_set_ms + 1);
      saveLedger(ledger);
      let grant = grantState(ledger, loadGrants(), new Set(), native.nowMs());
      let failed = 0;
      if (!delegationOff(ledger)) {
        let step = null;
        try {
          step = await grantStep(turn, keys, { force: true });
        } catch (error) {
          const back = loadLedger();
          back.ttl_days = kept.ttl_days;
          back.ttl_set_ms = kept.ttl_set_ms;
          saveLedger(back);
          throw error;
        }
        grant = step.grant;
        failed = step.renewed.failed;
      }
      const written = loadLedger();
      if (failed > 0) {
        written.ttl_days = kept.ttl_days;
        written.ttl_set_ms = kept.ttl_set_ms;
        saveLedger(written);
      }
      native.publish({ state: { grant: grant, grant_days: written.ttl_days } });
      shareLedgerSoon(keys, true);
      if (failed > 0) throw native.error("grant_incomplete", "a listed node did not take the grant");
      return { grant: grant, days: written.ttl_days };
    });
  }

  /** set_delegation: the delegation switch. Turning it off sends a revoke to every listed node and
   *  writes the revocation time to the ledger (a node that is not alive has no user key any more).
   *  When a listed node did not confirm the revoke, the revocation time is written and the call
   *  fails with revoke_incomplete (the synchronizations while off send the revoke again). Turning
   *  it on writes the resumption time and hands the grants again. */
  async function setDelegation(turn, args) {
    if (typeof args.enabled !== "boolean") throw native.error("invalid_input", "enabled");
    const done = await grantLock.run(turn, async function () {
      const keys = await presentKeys(turn);
      const ledger = loadLedger();
      // The resumption time is not before the revocation time and the revocation time is after the
      // resumption time: the last operation decides the state of the switch even when the device
      // clock runs backwards or the clock of another device runs ahead.
      if (args.enabled) {
        ledger.resumed_ms = Math.max(native.nowMs(), ledger.revoked_ms);
        saveLedger(ledger);
        const step = await grantStep(turn, keys, {});
        shareLedgerSoon(keys, true);
        return { grant: step.grant, keys: keys, step: step };
      }
      const incomplete = await revokeEverywhere(turn, keys);
      // The revocation time is after the resumption time and not before any grant time this device
      // or the ledger keeps: even when the device clock ran backwards or the clock of the device
      // that wrote a grant runs ahead, a grant handed before the revoke is not read as one after it.
      let revoked = Math.max(native.nowMs(), ledger.resumed_ms + 1);
      const grants = loadGrants();
      for (const id of Object.keys(grants)) revoked = Math.max(revoked, grants[id].granted_ms);
      const written = loadLedger();
      for (const id of Object.keys(written.nodes)) revoked = Math.max(revoked, written.nodes[id].granted_ms);
      written.revoked_ms = revoked;
      saveLedger(written);
      const grant = grantState(written, grants, new Set(), revoked);
      native.publish({ state: { grant: grant } });
      shareLedgerSoon(keys, true);
      if (incomplete) throw native.error("revoke_incomplete", "a listed node did not confirm");
      return { grant: grant, keys: keys, step: null };
    });
    if (done.step !== null) {
      // Delegation is on again: what follows the grants (afterGrants), then the runtime is ready.
      await afterGrants(turn, done.keys, done.step);
      native.publish({ runtime: { ready: true } });
    }
    return { grant: done.grant };
  }

  /** An account end that erases the account records: deletes the master key item, the node ledger
   *  (the keychain item and the device copy), the reception key of a mail setup, and everything
   *  the program store holds of the account. */
  async function eraseAccountKeys() {
    deleteMasterKey();
    native.keychainDelete(ledgerItem());
    native.keychainDelete(mailSetupItem());
    for (const key of [LEDGER_STORE_KEY, LEDGER_SHARE_STORE_KEY, SEALING_CHECK_STORE_KEY, STORE_GRANTS,
      STORE_CURSOR, STORE_RESUME, STORE_NODES, STORE_UNACCEPTED, STORE_BLOCKED, STORE_SAMPLE, STORE_SEEN,
      STORE_MISSING, STORE_WITHHELD, STORE_RECOVERED, STORE_DENIED, STORE_LEGACY, STORE_ROUND, STORE_CACHE,
      STORE_MIGRATED, STORE_OUTCOMES].concat(RETIRED_STORE_KEYS)) {
      native.storeSet(key, null);
    }
    outcomeState = null;
    logState = null;
  }

  // ---- Master key transfer (device approval transfer) ----
  // A device of the same account without the key (the requesting device) receives the master key
  // from a device with the key (the approving device). When the user enters the 6-digit code shown
  // by the approving device into the requesting device, the two devices agree on a session key with
  // CPace (a PAKE over X25519: the generator is the hash of the account, the request id and the
  // code, mapped with Elligator2), and the approving device seals the master key with that key and
  // sends it through the api. The api carries only the public messages (ya, yb), the confirmation
  // tags (ta, tb) and the ciphertext; the code, the PAKE secrets, the session key and the plaintext
  // exist on the two devices only. The server checks the phase transitions. The secrets of a
  // transfer in progress live in the runtime variable transferRun only; the published state
  // state.transfer carries the role, the phase, the device descriptions and the result only, and the
  // code goes to runtime.transfer_code only (no device storage), which the executor hands to its
  // native transfer cover and never to the definition. Contract: docs/ssot/client/
  // secure-executor.md of pickle-com/interactive-character, the master key transfer section.

  const TRANSFER_PATH = "/api/secure/transfers";
  // The server polling interval. The lifetime of a request (600 seconds) is set by the server and
  // arrives as expires_ms of the response; the program follows a transfer no longer than
  // TRANSFER_LIFETIME_MAX_MS from the time it learned of it, whatever the server states.
  const TRANSFER_POLL_MS = 2000;
  const TRANSFER_LIFETIME_MAX_MS = 900000;
  // The budget for which the code entry procedure waits inside itself for the sealed envelope
  // (below the limit of a procedure).
  const TRANSFER_INLINE_WAIT_MS = 60000;
  const TRANSFER_CODE_MODULUS = 1000000;
  // The terminal phases: done (the requesting device received the key, the approving device handed
  // the envelope over), failed (confirmation tag mismatch, verification failure), expired (not
  // finished within the lifetime), cancelled (cancelled by the requesting device), declined
  // (declined by the approving device), taken (another device approved first).
  const TRANSFER_TERMINAL = ["done", "failed", "expired", "cancelled", "declined", "taken"];
  // The field of X25519 (2^255 - 19), the Montgomery coefficient A, and the non-square constant Z of
  // Elligator2 (RFC 9380 8.5).
  const FIELD_P = (1n << 255n) - 19n;
  const CURVE_A = 486662n;
  const ELLIGATOR_Z = 2n;
  // The sealing nonce: the session key seals exactly once per request, so it is fixed.
  const TRANSFER_NONCE = encode(new Uint8Array(12));

  let transferRun = null;
  let transferLoopActive = false;

  function fieldMod(x) {
    const r = x % FIELD_P;
    return r < 0n ? r + FIELD_P : r;
  }

  function fieldPow(base, exponent) {
    let result = 1n;
    let b = fieldMod(base);
    let e = exponent;
    while (e > 0n) {
      if (e & 1n) result = (result * b) % FIELD_P;
      b = (b * b) % FIELD_P;
      e >>= 1n;
    }
    return result;
  }

  function fieldIsSquare(x) {
    const v = fieldMod(x);
    return v === 0n || fieldPow(v, (FIELD_P - 1n) / 2n) === 1n;
  }

  /** The u coordinate of Elligator 2 (RFC 9380 F.3) for curve25519 (A = 486662, B = 1, Z = 2). */
  function elligator2(u) {
    let tv1 = fieldMod(ELLIGATOR_Z * u * u);
    if (tv1 === FIELD_P - 1n) tv1 = 0n;
    const x1 = fieldMod(-CURVE_A * fieldPow(tv1 + 1n, FIELD_P - 2n));
    const gx1 = fieldMod(((x1 + CURVE_A) * x1 + 1n) * x1);
    const x2 = fieldMod(-x1 - CURVE_A);
    return fieldIsSquare(gx1) ? x1 : x2;
  }

  function fieldFromBytes(bytes) {
    let v = 0n;
    for (let i = 0; i < bytes.length; i += 1) v = (v << 8n) | BigInt(bytes[i]);
    return fieldMod(v);
  }

  /** A field element -> the X25519 u coordinate representation (32 bytes, little-endian). */
  function fieldToBytes(x) {
    const out = new Uint8Array(32);
    let v = x;
    for (let i = 0; i < 32; i += 1) {
      out[i] = Number(v & 255n);
      v >>= 8n;
    }
    return out;
  }

  /** The PAKE generator (an X25519 public key representation): the SHA-512 of the account, the
   *  request id and the code, reduced to a field element and mapped with Elligator2. */
  function transferGenerator(requestId, code) {
    const seed = utf8(purpose("transfer.pake") + "\n" + userId() + "\n" + requestId + "\n" + code);
    return encode(fieldToBytes(elligator2(fieldFromBytes(decode(native.sha512(encode(seed)))))));
  }

  function transferTranscript(requestId, ya, yb) {
    return concat(utf8(userId()), utf8(requestId), decode(ya), decode(yb));
  }

  /** The session key: derived from the X25519 shared secret with the transcript (the account, the
   *  request id, ya, yb) bound into the info. */
  function transferSessionKey(shared, requestId, ya, yb) {
    const bound = concat(utf8(purpose("transfer.session")), transferTranscript(requestId, ya, yb));
    return native.hkdf("sha256", shared, null, encode(bound), 32);
  }

  function transferTag(sessionKey, side) {
    return native.hmac("sha256", sessionKey, encode(utf8(purpose("transfer.confirm." + side))));
  }

  function transferEnvelope(sessionKey, requestId, ya, yb) {
    return {
      alg: "chacha20poly1305",
      key: native.hkdf("sha256", sessionKey, null, info("transfer.envelope"), 32),
      nonce: TRANSFER_NONCE,
      aad: encode(transferTranscript(requestId, ya, yb)),
    };
  }

  /** The 6-digit code: drawn without bias from 4 random bytes (only values below a multiple of the
   *  code space are taken; 64 draws at most, each of which fails once in a thousand). */
  function transferCode() {
    for (let draw = 0; draw < 64; draw += 1) {
      const bytes = decode(native.randomBytes(4));
      const value = bytes[0] * 16777216 + bytes[1] * 65536 + bytes[2] * 256 + bytes[3];
      if (value < 4294000000) return String(value % TRANSFER_CODE_MODULUS).padStart(6, "0");
    }
    throw native.error("crypto_failed", "transfer code");
  }

  /** The device description: platform, model and app_version of deviceInfo. A value that is not a
   *  string (an app build that does not provide the key) is the empty string. */
  function transferDevice() {
    const device = native.deviceInfo();
    function field(name) {
      return typeof device[name] === "string" ? device[name] : "";
    }
    return { platform: field("platform"), model: field("model"), app_version: field("app_version") };
  }

  function transferTerminal(phase) {
    return TRANSFER_TERMINAL.indexOf(phase) >= 0;
  }

  /** The time until which this program follows a transfer: the expiry the server states, not later
   *  than TRANSFER_LIFETIME_MAX_MS from now. */
  function transferExpiry(stated) {
    const limit = native.nowMs() + TRANSFER_LIFETIME_MAX_MS;
    const given = Number(stated);
    return Number.isFinite(given) && given > 0 ? Math.min(given, limit) : limit;
  }

  function transferView() {
    if (transferRun === null) return null;
    return {
      role: transferRun.role, phase: transferRun.phase, request_id: transferRun.requestId,
      device: transferRun.device, approver: transferRun.approver, expires_ms: transferRun.expiresMs,
      failure: transferRun.failure,
    };
  }

  function publishTransfer() {
    const showingCode = transferRun !== null && transferRun.role === "approving" && transferRun.phase === "approved";
    native.publish({
      state: { transfer: transferView() },
      runtime: { transfer_code: showingCode ? transferRun.code : null },
    });
  }

  function resetTransfer() {
    transferRun = null;
    publishTransfer();
  }

  /** Settlement: records the phase and the result and drops the secrets (the PAKE scalar, the
   *  session key, the code). */
  function transferSettle(phase, failure) {
    if (transferRun === null) return;
    transferRun.phase = phase;
    transferRun.failure = failure === undefined ? null : failure;
    transferRun.scalar = null;
    transferRun.sessionKey = null;
    transferRun.code = null;
    publishTransfer();
  }

  /** The server state of the request. A missing request (404) is an expiry or the cleanup of the
   *  other device, and gives null. */
  async function transferFetch(turn) {
    try {
      return (await api(turn, "GET", TRANSFER_PATH + "/" + transferRun.requestId)).json.transfer;
    } catch (error) {
      if (error.code === "not_found") return null;
      throw error;
    }
  }

  /** One step: reads the server state and does the next thing of the role of this device. */
  async function transferStep(turn) {
    if (transferRun === null || transferTerminal(transferRun.phase)) return;
    const remote = await transferFetch(turn);
    if (transferRun === null || transferTerminal(transferRun.phase)) return;
    if (remote === null) {
      // An absence seen by the approving device that handed the envelope over is the receipt
      // confirmation of the requesting device (done); every other absence is an expiry.
      transferSettle(transferRun.role === "approving" && transferRun.phase === "sealed" ? "done" : "expired");
      return;
    }
    const phase = remote.phase;
    if (phase === "failed" || phase === "cancelled" || phase === "declined") {
      transferSettle(phase, typeof remote.failure === "string" ? remote.failure : phase);
      return;
    }
    if (transferRun.role === "requesting") {
      if (phase === "approved" && transferRun.phase === "requested") {
        transferRun.yb = String(remote.yb);
        transferRun.approver = remote.approver;
        transferRun.phase = "code_entry";
        publishTransfer();
      } else if (phase === "sealed" && transferRun.phase === "replied") {
        await transferReceive(turn, remote);
      }
    } else if (phase === "replied" && transferRun.phase === "approved") {
      await transferSeal(turn, remote);
    }
  }

  /** Whether a failure of a step of the transfer is one the next poll may get past: the transport,
   *  a request that was not answered in time, a 5xx status. */
  function transferRetryable(error) {
    const code = failureCode(error);
    return code === "transport" || code === "timeout" || /^http_5/.test(code);
  }

  /** The polling loop: advances one step on the line of the procedures a user starts at every
   *  interval until the transfer in progress settles or its expiry passes (the number of its
   *  turns is bounded by the longest lifetime of a transfer). It runs inside the runtime apart
   *  from the procedure calls, a failure the next poll may get past is left to it, and every other
   *  failure ends the transfer as failed. */
  async function transferLoop() {
    if (transferLoopActive) return;
    transferLoopActive = true;
    try {
      const polls = Math.ceil(TRANSFER_LIFETIME_MAX_MS / TRANSFER_POLL_MS) + 1;
      for (let poll = 0; poll < polls; poll += 1) {
        if (transferRun === null || transferTerminal(transferRun.phase)) break;
        if (native.nowMs() > transferRun.expiresMs) {
          transferSettle("expired");
          break;
        }
        await native.sleep(TRANSFER_POLL_MS);
        try {
          const turn = freeTurn();
          await userLine.run(turn, function () { return transferStep(turn); });
        } catch (error) {
          if (failureCode(error) === "cancelled") break;
          if (transferRetryable(error)) continue;
          native.log("transfer: " + failureCode(error));
          transferSettle("failed", failureCode(error));
        }
      }
    } finally {
      transferLoopActive = false;
    }
  }

  /** Starts the polling loop. Nothing waits for it. */
  function startTransferLoop() {
    transferLoop().then(noop, noop);
  }

  /** The requesting device: creates a transfer request and waits for the approval. It holds only
   *  when key_state is waiting. */
  async function beginTransfer(turn) {
    if (transferRun !== null && !transferTerminal(transferRun.phase)) return { transfer: transferView() };
    const judged = await judgeKey(turn);
    if (judged.keyState !== "waiting") throw native.error("invalid_state", judged.keyState);
    const device = transferDevice();
    const created = (await api(turn, "POST", TRANSFER_PATH, { device: device })).json.transfer;
    transferRun = {
      role: "requesting", requestId: String(created.request_id), phase: "requested", device: device,
      approver: null, expiresMs: transferExpiry(created.expires_ms), failure: null, yb: null, ya: null,
      scalar: null, sessionKey: null, code: null,
    };
    publishTransfer();
    startTransferLoop();
    return { transfer: transferView() };
  }

  /** The requesting device: makes the PAKE message and the confirmation tag from the code on the
   *  screen of the approving device and uploads them. */
  async function enterTransferCode(turn, args) {
    const code = typeof args.code === "string" ? args.code.replace(/\D/g, "") : "";
    if (code.length !== 6) throw native.error("invalid_input", "code");
    if (transferRun === null || transferRun.role !== "requesting" || transferRun.phase !== "code_entry") {
      throw native.error("invalid_state", transferRun === null ? "none" : transferRun.phase);
    }
    const generator = transferGenerator(transferRun.requestId, code);
    const scalar = native.randomBytes(32);
    const ya = native.x25519(scalar, generator);
    const sessionKey = transferSessionKey(
      native.x25519(scalar, transferRun.yb), transferRun.requestId, ya, transferRun.yb);
    await api(turn, "PUT", TRANSFER_PATH + "/" + transferRun.requestId + "/reply", {
      ya: ya, ta: transferTag(sessionKey, "request"),
    });
    transferRun.ya = ya;
    transferRun.sessionKey = sessionKey;
    transferRun.phase = "replied";
    publishTransfer();
    // The envelope of the approving device arrives within seconds of the reply, so this procedure
    // waits for it inside itself: when it ends the screen shows the result at once. The wait ends
    // with the budget below or with the time of the procedure, whichever is first; the polling
    // loop then takes over.
    const deadline = native.nowMs() + Math.min(TRANSFER_INLINE_WAIT_MS, Math.max(0, turnLeft(turn) - 2 * API_TIMEOUT_MS));
    const polls = Math.ceil(TRANSFER_INLINE_WAIT_MS / TRANSFER_POLL_MS);
    for (let poll = 0; poll < polls; poll += 1) {
      if (transferRun === null || transferTerminal(transferRun.phase) || native.nowMs() >= deadline) break;
      await native.sleep(TRANSFER_POLL_MS);
      try {
        await transferStep(turn);
      } catch (error) {
        if (!transferRetryable(error) || !(turnLeft(turn) > 0)) throw error;
      }
    }
    if (transferRun !== null && !transferTerminal(transferRun.phase)) startTransferLoop();
    return { transfer: transferView() };
  }

  /** The requesting device: the reception of the sealed master key. The confirmation tag of the
   *  approving device is compared and the ciphertext opened, and the key is written to the keychain
   *  only when the key_id of the derived account signing public key equals the registered key_id of
   *  the account. The grants to the nodes of the account follow. */
  async function transferReceive(turn, remote) {
    const run = transferRun;
    if (!equal(decode(transferTag(run.sessionKey, "approve")), decode(String(remote.tb)))) {
      transferSettle("failed", "bad_tag");
      return;
    }
    let masterKey = null;
    try {
      const envelope = transferEnvelope(run.sessionKey, run.requestId, run.ya, run.yb);
      masterKey = native.aeadOpen({
        alg: envelope.alg, key: envelope.key, nonce: envelope.nonce, aad: envelope.aad,
        ciphertext: String(remote.ciphertext),
      });
    } catch (error) {
      transferSettle("failed", "bad_envelope");
      return;
    }
    const keys = deriveKeys(masterKey);
    const registered = await registeredKeyId(turn);
    if (registered !== keys.keyId) {
      transferSettle("failed", "key_mismatch");
      return;
    }
    writeMasterKey(masterKey);
    publishKey("present", keys);
    try {
      await api(turn, "POST", TRANSFER_PATH + "/" + run.requestId + "/ack", {});
    } catch (error) {
      if (failureCode(error) === "cancelled") throw error;
      native.log("transfer ack: " + failureCode(error));
    }
    transferSettle("done");
    // The device holds the key now: a synchronization hands the grants (nothing waits for it here).
    requestSync({ name: "event_sync", refill: false }).then(noop, noop);
  }

  /** The approving device: when it has the key and no transfer is in progress, the oldest pending
   *  request is raised to pending approval. */
  async function checkTransferRequests(turn) {
    if (transferRun !== null && !transferTerminal(transferRun.phase)) return;
    if (readMasterKey() === null) return;
    const pending = (await api(turn, "GET", TRANSFER_PATH)).json.transfers;
    if (!Array.isArray(pending) || pending.length === 0) return;
    if (transferRun !== null && !transferTerminal(transferRun.phase)) return;
    const waiting = pending[0];
    transferRun = {
      role: "approving", requestId: String(waiting.request_id), phase: "pending_approval",
      device: waiting.device, approver: transferDevice(), expiresMs: transferExpiry(waiting.expires_ms),
      failure: null, yb: null, ya: null, scalar: null, sessionKey: null, code: null,
    };
    publishTransfer();
  }

  /** The catch-up of a transfer after a synchronization: a device with the key reads the pending
   *  requests, a device with a transfer in progress advances one step, and the polling loop is
   *  started again. */
  async function transferCatchUp(present) {
    const turn = freeTurn();
    if (present) await checkTransferRequests(turn);
    else await transferStep(turn);
    if (transferRun !== null && !transferTerminal(transferRun.phase)) startTransferLoop();
  }

  /** The device owner authentication prompt of approve_transfer, in the device language (en, ko, ja).
   *  The text names the requesting device, so the prompt itself says what is being approved. */
  function transferAuthReason(device) {
    const model = device && typeof device.model === "string" && device.model !== "" ? device.model : null;
    const spoken = language();
    if (spoken === "ko") return (model === null ? "이 기기" : model) + "에 암호화 키 공유 승인";
    if (spoken === "ja") return (model === null ? "このデバイス" : model) + "への暗号化キー共有の承認";
    return "Approve sharing your encryption key with " + (model === null ? "this device" : model);
  }

  /** The approving device: after the device owner authentication, makes the code and the PAKE
   *  message, uploads the approval and shows the code. */
  async function approveTransfer(turn, args) {
    if (transferRun === null || transferRun.role !== "approving" || transferRun.phase !== "pending_approval") {
      throw native.error("invalid_state", transferRun === null ? "none" : transferRun.phase);
    }
    if (typeof args.request_id === "string" && args.request_id !== transferRun.requestId) {
      throw native.error("invalid_state", "request");
    }
    const keys = await presentKeys(turn);
    const reason = transferAuthReason(transferRun.device);
    const passed = await interactive(turn, function () { return native.deviceOwnerAuth(reason); });
    if (passed !== true) throw native.error("auth_failed", "device owner authentication");
    if (transferRun === null || transferRun.role !== "approving" || transferRun.phase !== "pending_approval") {
      throw native.error("invalid_state", transferRun === null ? "none" : transferRun.phase);
    }
    // The ledger of this device is shared before the key goes out: a device that receives the key
    // and runs a program before v43 finds the grants this device made at its first synchronization.
    if (ledgerShareDue(loadLedger())) await shareLedger(turn, keys);
    const code = transferCode();
    const scalar = native.randomBytes(32);
    const yb = native.x25519(scalar, transferGenerator(transferRun.requestId, code));
    try {
      await api(turn, "PUT", TRANSFER_PATH + "/" + transferRun.requestId + "/approval", {
        yb: yb, device: transferRun.approver,
      });
    } catch (error) {
      if (error.code === "invalid_phase") {
        transferSettle("taken");
        return { transfer: transferView() };
      }
      if (error.code === "not_found") {
        transferSettle("expired");
        return { transfer: transferView() };
      }
      throw error;
    }
    transferRun.code = code;
    transferRun.scalar = scalar;
    transferRun.yb = yb;
    transferRun.phase = "approved";
    publishTransfer();
    startTransferLoop();
    return { transfer: transferView() };
  }

  /** The approving device: compares the reply of the requesting device with the confirmation tag
   *  (a mismatch is reported to the server as a failure) and uploads the master key sealed with the
   *  session key. */
  async function transferSeal(turn, remote) {
    const run = transferRun;
    const ya = String(remote.ya);
    const sessionKey = transferSessionKey(native.x25519(run.scalar, ya), run.requestId, ya, run.yb);
    if (!equal(decode(transferTag(sessionKey, "request")), decode(String(remote.ta)))) {
      try {
        await api(turn, "POST", TRANSFER_PATH + "/" + run.requestId + "/fail", {});
      } catch (error) {
        if (failureCode(error) === "cancelled") throw error;
        native.log("transfer fail: " + failureCode(error));
      }
      transferSettle("failed", "code_mismatch");
      return;
    }
    const masterKey = readMasterKey();
    if (masterKey === null) {
      transferSettle("failed", "key_required");
      return;
    }
    const envelope = transferEnvelope(sessionKey, run.requestId, ya, run.yb);
    const ciphertext = native.aeadSeal({
      alg: envelope.alg, key: envelope.key, nonce: envelope.nonce, aad: envelope.aad, plaintext: masterKey,
    });
    await api(turn, "PUT", TRANSFER_PATH + "/" + run.requestId + "/envelope", {
      ciphertext: ciphertext, tb: transferTag(sessionKey, "approve"),
    });
    run.scalar = null;
    run.code = null;
    run.phase = "sealed";
    publishTransfer();
  }

  /** Both devices: ends the transfer in progress on the server (cancelled on the requesting device,
   *  declined on an approving device still waiting for the approval, cancelled on an approving
   *  device showing the code) and clears the state. A settled transfer only has its state cleared. */
  async function cancelTransfer(turn) {
    if (transferRun === null) return {};
    if (!transferTerminal(transferRun.phase)) {
      const declined = transferRun.role === "approving" && transferRun.phase === "pending_approval";
      try {
        await api(turn, "DELETE", TRANSFER_PATH + "/" + transferRun.requestId, null,
          declined ? { reason: "declined" } : undefined);
      } catch (error) {
        if (error.code !== "not_found" && error.code !== "invalid_phase") throw error;
      }
    }
    resetTransfer();
    return {};
  }

  /** Both devices: advances one step now and starts the polling loop (retry from the screen, return
   *  to the foreground). */
  async function pollTransfer(turn) {
    if (transferRun !== null && !transferTerminal(transferRun.phase)) {
      await transferStep(turn);
      if (transferRun !== null && !transferTerminal(transferRun.phase)) startTransferLoop();
    }
    return { transfer: transferView() };
  }

  // ---- Registration ----

  /** A counted procedure that runs on the line of the reads of the log screen. */
  function screenProcedure(name, work) {
    return tracked(name, function (args, turn) {
      return screenLine.run(turn, function () { return work(turn, args); });
    });
  }

  const readLogPageProcedure = screenProcedure("read_log_page", readLogPage);

  globalThis.secureProgram = {
    version: VERSION,
    procedures: {
      sync: tracked("sync", function (args, turn) { return syncProcedure(turn); }),
      create_key: userProcedure("create_key", createKey),
      reset_key: userProcedure("reset_key", resetKey),
      begin_transfer: userProcedure("begin_transfer", beginTransfer),
      enter_transfer_code: userProcedure("enter_transfer_code", enterTransferCode),
      approve_transfer: userProcedure("approve_transfer", approveTransfer),
      cancel_transfer: userProcedure("cancel_transfer", cancelTransfer),
      poll_transfer: userProcedure("poll_transfer", pollTransfer),
      connect: userProcedure("connect", connect),
      set_connection_writes: userProcedure("set_connection_writes", setConnectionWrites),
      manage_repositories: userProcedure("manage_repositories", manageRepositories),
      begin_app_password_setup: userProcedure("begin_app_password_setup", beginAppPasswordSetup),
      cancel_app_password_setup: userProcedure("cancel_app_password_setup", cancelAppPasswordSetup),
      connect_app_password: userProcedure("connect_app_password", connectAppPassword),
      store_login: userProcedure("store_login", storeLogin),
      store_card: userProcedure("store_card", storeCard),
      store_secret: userProcedure("store_secret", storeSecret),
      reveal_secret: userProcedure("reveal_secret", revealSecret),
      update_secret: userProcedure("update_secret", updateSecret),
      delete_secret: userProcedure("delete_secret", deleteSecret),
      reveal_login_password: userProcedure("reveal_login_password", revealLoginPassword),
      set_grant_days: userProcedure("set_grant_days", setGrantDays),
      set_delegation: userProcedure("set_delegation", setDelegation),
      // read_log answers within LOG_SCREEN_WAIT_MS and waits on no line: the read of the store it
      // starts runs on the line of the screen (screenRead).
      read_log: tracked("read_log", function (args, turn) { return readLog(turn, args); }),
      read_log_page: function (args) {
        const before = args !== null && typeof args === "object" ? logPageCursor(args.before_ms) : null;
        if (before !== null) openLogPage(before);
        return readLogPageProcedure(args);
      },
      read_security_record: screenProcedure("read_security_record", readSecurityRecord),
    },
    onEvent: function (name, payload) {
      if (name === "session_ready") {
        // A new runtime does not take over the transfer of the previous runtime (the secrets exist
        // in the runtime only): the transfer state is cleared. The calls the runtime before left
        // open are counted as interrupted (outcomes), and the build is asked for its protected
        // sheets.
        resetTransfer();
        native.publish({ runtime: { protected_sheets: protectedSheets() } });
        // The state of the log that a program before this one published is not a judgement of
        // this program: until this program ended a round on this installation, the log is pending.
        if (storedObject(STORE_ROUND).v !== VERSION) native.publish({ state: { log: keptLogState() } });
        outcomes();
        return eventSync(null, true);
      }
      if (name === "foreground") {
        noteBackground(false);
        return eventSync(null, true);
      }
      if (name === "background") {
        appBackgroundMs = native.nowMs();
        noteBackground(true);
        return undefined;
      }
      if (name === "push") {
        if (payload && payload.reason === "transfer_request") {
          const turn = newTurn(PROCEDURE_LIMIT_MS, "");
          return userLine.run(turn, function () { return checkTransferRequests(turn); });
        }
        return eventSync(payload !== null && typeof payload === "object" ? payload : {}, false);
      }
      if (name === "account_end") {
        transferRun = null;
        if (payload && (payload.reason === "account_deleted" || payload.reason === "dev_reset")) {
          // The deletion or reset of a runtime whose account mismatched does not erase the master key
          // of another account (the runtime goes down).
          if (accountMismatch) {
            accountMismatch = false;
            return undefined;
          }
          // Work that is still running writes nothing of the account after this.
          accountClosed = true;
          return eraseAccountKeys();
        }
      }
      return undefined;
    },
  };
})();
