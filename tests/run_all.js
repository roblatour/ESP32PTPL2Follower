const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const readline = require("node:readline/promises");

const root = path.resolve(__dirname, "..");
const profiles = ["pre_v3", "v3_0", "v3_1", "s31"];
const usage = "Usage: node .\\tests\\run_all.js <output-directory> [--profile <pre_v3|v3_0|v3_1|s31|all>]... [--python <python-executable>] [--overwrite]";

function parseArgs(args) {
  const options = { overwrite: false, profiles: [] };
  const value = index => (args[index + 1] && !args[index + 1].startsWith("--") ? args[index + 1] : undefined);
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === "--overwrite") options.overwrite = true;
    else if (argument === "--profile" && value(index)) {
      const profile = args[++index];
      if (profile === "all") options.profiles.push(...profiles);
      else if (profiles.includes(profile)) options.profiles.push(profile);
      else throw new Error(`Unknown profile '${profile}'. ${usage}`);
    } else if (argument === "--python" && value(index)) {
      if (options.python) throw new Error(usage);
      options.python = args[++index];
    } else if (!argument.startsWith("--") && !options.out) options.out = path.resolve(argument);
    else throw new Error(usage);
  }
  if (!options.out) throw new Error(usage);
  const relative = path.relative(root, options.out);
  if (!relative || (!path.isAbsolute(relative) && relative !== ".." && !relative.startsWith(`..${path.sep}`)))
    throw new Error("Choose an output directory outside the source tree.");
  options.profiles = [...new Set(options.profiles)];
  options.python = options.python || process.env.PYTHON || (process.platform === "win32" ? "python" : "python3");
  return options;
}

// Grouped result markers printed by the Python runners and the C++ test executables.
function countResults(text) {
  const lines = text.split(/\r?\n/);
  return {
    passes: lines.filter(line => /^PASS\b/.test(line)).length,
    fails: lines.filter(line => /^FAIL\b/.test(line) || /^ERROR:/.test(line)).length,
  };
}

function suitesFor(options) {
  const python = options.python;
  const suites = [
    { name: "Core host tests (PTP core, Sync rate, MAC, time conversion)", command: python, args: [path.join(__dirname, "run_tests.py")] },
    { name: "Clock owner host tests (simulated ESP32-P4 and ESP32-S31 targets)", command: python, args: [path.join(__dirname, "run_clock_tests.py")] },
    { name: "PTP authentication host tests (policy matrix, key rings, crypto)", command: python, args: [path.join(__dirname, "run_auth_tests.py")] },
  ];
  for (const profile of options.profiles) suites.push({
    name: `Firmware PTP policy builds (${profile})`,
    command: python,
    args: [path.join(root, "tools", "check_builds.py"), "--profile", profile],
  });
  return suites;
}

function runSuite(suite, log, results, execute = spawnSync) {
  const started = Date.now();
  const start = fs.fstatSync(log).size;
  fs.writeSync(log, `\n=== ${suite.name} ===\n${JSON.stringify([suite.command, ...suite.args])}\n`);
  console.log(`Running: ${suite.name} (output saved to ${results})`);
  let failure;
  try {
    const result = execute(suite.command, suite.args, {
      cwd: root,
      stdio: ["ignore", log, log],
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1", PYTHONUNBUFFERED: "1" },
    });
    if (result.error) failure = result.error.message;
    else if (result.status !== 0) failure = result.signal ? `signal ${result.signal}` : `exit code ${result.status}`;
  } catch (error) {
    failure = error.message;
  }
  const section = fs.readFileSync(results).subarray(start).toString("utf8");
  const counts = countResults(section);
  if (!failure && counts.fails) failure = "failure markers reported despite a zero exit code";
  if (!failure && !counts.passes) failure = "no recognized pass results were reported";
  if (failure && !counts.fails) fs.writeSync(log, `\nFAIL: ${suite.name}: ${failure}\n`);
  fs.writeSync(log, `\nSUITE ${failure ? "FAILED" : "COMPLETED"}: ${suite.name} (${((Date.now() - started) / 1000).toFixed(1)} seconds)${failure ? `: ${failure}` : ""}\n`);
  console.log(`${failure ? "Failed" : "Completed"}: ${suite.name}`);
  return !failure;
}

async function main(args = process.argv.slice(2)) {
  if (args.length === 1 && args[0] === "--help") {
    console.log(usage);
    return;
  }
  const options = parseArgs(args);
  const results = path.join(options.out, "results.txt");
  if (fs.existsSync(results) && !options.overwrite) {
    if (!process.stdin.isTTY) throw new Error(`Results already exist: ${results}. Use --overwrite for a noninteractive run.`);
    const prompt = readline.createInterface({ input: process.stdin, output: process.stdout });
    let answer;
    try {
      answer = await prompt.question(`Overwrite ${results}? [y/N] `);
    } finally {
      prompt.close();
    }
    if (!/^y(es)?$/i.test(answer.trim())) {
      console.log("Cancelled; existing results were not changed.");
      process.exitCode = 1;
      return;
    }
  }
  fs.mkdirSync(options.out, { recursive: true });
  const log = fs.openSync(results, "w");
  const interrupted = () => {
    fs.writeSync(log, "\nFAIL: Regression run interrupted; results are incomplete.\n");
    fs.closeSync(log);
    console.error(`Interrupted; partial results saved to ${results}`);
    process.exit(130);
  };
  process.once("SIGINT", interrupted);
  let failedSuites = 0;
  const suites = suitesFor(options);
  try {
    fs.writeSync(log, `ESP32PTPL2Follower regression results\nStarted: ${new Date().toISOString()}\nRepository: ${root}\nNode: ${process.version}\nPython: ${options.python}\n`);
    if (!options.profiles.length) {
      const skipped = "SKIP: Firmware PTP policy builds (supply --profile <pre_v3|v3_0|v3_1|s31|all> from an ESP-IDF v6.1 environment).";
      fs.writeSync(log, `${skipped}\n`);
      console.log(skipped);
    }
    for (const suite of suites) {
      if (!runSuite(suite, log, results)) failedSuites++;
      await new Promise(resolve => setImmediate(resolve));
    }
    const counts = countResults(fs.readFileSync(results, "utf8"));
    const summary = `\nTotal passes: ${counts.passes}\nTotal fails: ${counts.fails}\nSuites completed successfully: ${suites.length - failedSuites}/${suites.length}\nFinished: ${new Date().toISOString()}\n`;
    fs.writeSync(log, summary);
    console.log(summary.trim());
    console.log(`Results: ${results}`);
    if (counts.fails || failedSuites) process.exitCode = 1;
  } finally {
    process.removeListener("SIGINT", interrupted);
    fs.closeSync(log);
  }
}

if (require.main === module) main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});

module.exports = { parseArgs, countResults, suitesFor, runSuite, profiles };
