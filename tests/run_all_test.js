const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { test } = require("node:test");
const { parseArgs, countResults, suitesFor, runSuite, profiles } = require("./run_all.js");

function temporaryDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ESP32PTPL2Follower-run-all-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

test("arguments require external output and validate profiles", t => {
  const out = temporaryDirectory(t);
  assert.throws(() => parseArgs([]), /Usage:/);
  assert.throws(() => parseArgs([__dirname]), /outside the source tree/);
  assert.throws(() => parseArgs([path.resolve(__dirname, "..")]), /outside the source tree/);
  assert.throws(() => parseArgs([out, "--unknown"]), /Usage:/);
  assert.throws(() => parseArgs([out, "--profile"]), /Usage:/);
  assert.throws(() => parseArgs([out, "--profile", "esp32"]), /Unknown profile/);
  assert.throws(() => parseArgs([out, "--python"]), /Usage:/);
  const options = parseArgs([out, "--overwrite", "--profile", "s31", "--profile", "s31", "--python", "py"]);
  assert.equal(options.overwrite, true);
  assert.deepEqual(options.profiles, ["s31"]);
  assert.equal(options.python, "py");
  assert.equal(suitesFor(options).length, 4);
  assert.deepEqual(suitesFor(options)[3].args.slice(-2), ["--profile", "s31"]);
  assert.deepEqual(parseArgs([out, "--profile", "all"]).profiles, profiles);
  const hostSuites = suitesFor(parseArgs([out]));
  assert.equal(hostSuites.length, 3);
  assert.deepEqual(hostSuites.map(suite => path.basename(suite.args[0])), ["run_tests.py", "run_clock_tests.py", "run_auth_tests.py"]);
  for (const suite of hostSuites) assert.ok(fs.existsSync(suite.args[0]), suite.args[0]);
  assert.ok(fs.existsSync(path.resolve(__dirname, "..", "tools", "check_builds.py")));
});

test("counts project result markers without counting diagnostics or the summary", () => {
  const text = [
    "PASS: lifecycle: 67 checks, 0 failures",
    "PASS 73 checks (PTP ready 0, auth available 0, keys 0)",
    "PASS: 0 failed build/test process(es)",
    "core_tests UTC0: 96 checks, 0 failures",
    "FAIL line 259: follower::settings::ptp_auth_required == bool(EXPECT_PTP_REQUIRED)",
    "ERROR: VS2022 cl.exe was not found",
    "x.h(52): error C2220: FAIL example",
    "PASSED_NOT_A_MARKER",
    "Total passes: 3",
    "Total fails: 2",
  ].join("\r\n");
  assert.deepEqual(countResults(text), { passes: 3, fails: 2 });
});

test("suite captures both output streams without a shell", t => {
  const directory = temporaryDirectory(t);
  const results = path.join(directory, "results.txt");
  const log = fs.openSync(results, "w");
  try {
    const passed = runSuite({ name: "Fixture", command: process.execPath, args: ["-e", "process.stdout.write('PASS: fixture\\n'); process.stderr.write('diagnostic\\n')"] }, log, results);
    assert.equal(passed, true);
    const text = fs.readFileSync(results, "utf8");
    assert.match(text, /diagnostic/);
    assert.deepEqual(countResults(text), { passes: 1, fails: 0 });
  } finally {
    fs.closeSync(log);
  }
});

test("failed and silent suites are recorded and later suites still execute", t => {
  const directory = temporaryDirectory(t);
  const results = path.join(directory, "results.txt");
  const log = fs.openSync(results, "w");
  const suite = name => ({ name, command: "python", args: [] });
  try {
    assert.equal(runSuite(suite("Exit failure"), log, results, () => ({ status: 2 })), false);
    assert.equal(runSuite(suite("Spawn failure"), log, results, () => ({ error: new Error("ENOENT") })), false);
    assert.equal(runSuite(suite("Signal failure"), log, results, () => ({ status: null, signal: "SIGTERM" })), false);
    assert.equal(runSuite(suite("Silent"), log, results, () => ({ status: 0 })), false);
    assert.equal(runSuite(suite("Explicit failure"), log, results, () => {
      fs.writeSync(log, "FAIL line 1: fixture\n");
      return { status: 0 };
    }), false);
    assert.equal(runSuite(suite("Recovery"), log, results, () => {
      fs.writeSync(log, "PASS: subsequent suite\n");
      return { status: 0 };
    }), true);
    assert.deepEqual(countResults(fs.readFileSync(results, "utf8")), { passes: 1, fails: 5 });
  } finally {
    fs.closeSync(log);
  }
});

for (const failed of [false, true]) {
  test(`CLI combines logs, overwrites with permission, and summarizes ${failed ? "failure" : "success"}`, t => {
    const directory = temporaryDirectory(t);
    const results = path.join(directory, "results.txt");
    const fixture = path.join(directory, "preload.cjs");
    fs.writeFileSync(results, "old results");
    fs.writeFileSync(fixture, `
const fs = require("node:fs");
let calls = 0;
require("node:child_process").spawnSync = (command, args, options) => {
  calls++;
  fs.writeSync(options.stdio[1], "PASS: fixture " + calls + "\\n");
  fs.writeSync(options.stdio[2], "stderr fixture " + calls + "\\n");
  return { status: ${failed} && calls === 1 ? 2 : 0 };
};
`);
    const args = ["-r", fixture, path.join(__dirname, "run_all.js"), directory, "--overwrite"];
    if (failed) args.push("--profile", "s31");
    const result = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.equal(result.status, failed ? 1 : 0, result.stderr);
    const text = fs.readFileSync(results, "utf8");
    assert.doesNotMatch(text, /old results/);
    assert.match(text, /stderr fixture 2/);
    assert.match(result.stdout, new RegExp(`Total passes: ${failed ? 4 : 3}`));
    assert.match(result.stdout, new RegExp(`Total fails: ${failed ? 1 : 0}`));
    assert.match(result.stdout, new RegExp(`Suites completed successfully: ${failed ? "3/4" : "3/3"}`));
    assert.deepEqual(countResults(text), { passes: failed ? 4 : 3, fails: failed ? 1 : 0 });
    assert.equal(text.includes("SKIP:"), !failed);
  });
}

test("noninteractive overwrite refusal preserves existing results", t => {
  const directory = temporaryDirectory(t);
  const results = path.join(directory, "results.txt");
  fs.writeFileSync(results, "existing results");
  const result = spawnSync(process.execPath, [path.join(__dirname, "run_all.js"), directory], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /--overwrite/);
  assert.equal(fs.readFileSync(results, "utf8"), "existing results");
});
