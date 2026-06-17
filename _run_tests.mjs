// One-command test battery: spawns the echo stub + a cordon instance, runs the unit
// suite (under tsx) and the integration suites, then tears everything down.
//
//   npm test
import { spawn } from "node:child_process";
import { rmSync } from "node:fs";

const STUB = "http://localhost:8900";
const base = { OPENAI_BASE: STUB, ANTHROPIC_BASE: STUB };

// port → instance env
const instances = {
  8810: { ADMIN_TOKEN: "secret", AUDIT_LOG: "./_audit_test.jsonl", CORDON_TEST_HOOKS: "1" },
};

// Suites importing TS modules directly run under the tsx loader.
const TSX_SUITES = new Set(["_test_unit.mjs"]);
const suites = ["_test_unit.mjs", "_test_proxy.mjs", "_test_stream.mjs"];

// Fresh audit chain each run.
try { rmSync("./_audit_test.jsonl", { force: true }); } catch {}

const children = [];
const launch = (args, env = {}) => {
  const c = spawn(process.execPath, args, { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  children.push(c);
  return c;
};
const die = (code) => {
  for (const c of children) c.kill();
  process.exit(code);
};

async function waitUp(url, label, tries = 50) {
  for (let i = 0; i < tries; i++) {
    try {
      if ((await fetch(url)).ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  console.error(`launch: ${label} never came up at ${url}`);
  die(1);
}

(async () => {
  launch(["_stub-upstream.mjs"]);
  await waitUp(`${STUB}/__calls`, "stub");

  for (const [port, env] of Object.entries(instances)) {
    launch(["--import", "tsx", "src/index.ts"], { PORT: port, ...base, ...env });
  }
  await Promise.all(Object.keys(instances).map((p) => waitUp(`http://localhost:${p}/healthz`, `cordon:${p}`)));

  let failed = 0;
  for (const suite of suites) {
    console.log(`\n=== ${suite} ===`);
    const args = TSX_SUITES.has(suite) ? ["--import", "tsx", suite] : [suite];
    const code = await new Promise((resolve) => {
      const t = spawn(process.execPath, args, { stdio: "inherit", env: process.env });
      t.on("exit", resolve);
    });
    if (code !== 0) failed++;
  }

  console.log(failed ? `\n${failed} suite(s) FAILED` : "\nall suites green");
  die(failed ? 1 : 0);
})();
