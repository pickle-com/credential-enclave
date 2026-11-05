// Runs the scenarios of scenarios.js on two versions of the program and prints, per scenario, the
// result of each and the paths whose values differ:
//
//   node secure-program/tests/compare.js <program-a.js> <program-b.js>
//
// Both programs run on the model of the bridge (bridge.js) with the same scenarios. The exit status
// is 0 whatever the differences are: what a difference means is judged by the reader (a release of
// the program changes some results on purpose, and the tests of program.test.js fix the expected
// results of the current program).
"use strict";

const fs = require("node:fs");

const { scenarios } = require("./scenarios.js");

function flatten(value, prefix, out) {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    for (const key of Object.keys(value)) flatten(value[key], prefix === "" ? key : prefix + "." + key, out);
    return out;
  }
  out[prefix] = JSON.stringify(value);
  return out;
}

async function main(argv) {
  if (argv.length !== 2) {
    process.stderr.write("usage: node secure-program/tests/compare.js <program-a.js> <program-b.js>\n");
    return 2;
  }
  const sources = argv.map((file) => fs.readFileSync(file, "utf8"));
  for (const name of Object.keys(scenarios)) {
    const results = [];
    for (const source of sources) results.push(flatten(await scenarios[name](source), "", {}));
    const keys = Array.from(new Set(Object.keys(results[0]).concat(Object.keys(results[1])))).sort();
    const differences = keys.filter((key) => results[0][key] !== results[1][key]);
    process.stdout.write("== " + name + ": " + (differences.length === 0 ? "same" : differences.length + " differences") + "\n");
    for (const key of differences) {
      process.stdout.write("  " + key + ": " + (results[0][key] === undefined ? "(absent)" : results[0][key]) +
        " -> " + (results[1][key] === undefined ? "(absent)" : results[1][key]) + "\n");
    }
  }
  return 0;
}

main(process.argv.slice(2)).then(
  (status) => { process.exitCode = status; },
  (error) => { process.stderr.write(String(error && error.stack ? error.stack : error) + "\n"); process.exitCode = 1; });
