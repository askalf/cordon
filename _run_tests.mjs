// One-command test battery: spawns the echo stub + a cordon instance, runs the unit
// suite (under tsx) and the integration suites, then tears everything down.
//
//   npm test
import { spawn, execSync } from "node:child_process";
import { rmSync } from "node:fs";

const STUB_PORT = 8900;
const STUB = `http://localhost:${STUB_PORT}`;
const base = { OPENAI_BASE: STUB, ANTHROPIC_BASE: STUB };

// port → instance env
const instances = {
  8810: { ADMIN_TOKEN: "secret", AUDIT_LOG: "./_audit_test.jsonl", CORDON_TEST_HOOKS: "1" },
};

// Suites importing TS modules directly run under the tsx loader.
const TSX_SUITES = new Set(["_test_unit.mjs", "_test_fuzz.js"]);
const suites = ["_test_unit.mjs", "_test_fuzz.js", "_test_proxy.mjs", "_test_stream.mjs"];

// Fresh audit chain each run.
try { rmSync("./_audit_test.jsonl", { force: true }); } catch {}

/**
 * Kill whatever is already LISTENING on `port`. Prior runs can leave an orphaned stub
 * or cordon instance behind — most often on Windows, where a parent's .kill() doesn't
 * always reap the spawned node process — which would then EADDRINUSE this run.
 */
const freePort = (port) => {
  try {
    if (process.platform === "win32") {
      const out = execSync("netstat -ano -p tcp", { encoding: "utf8" });
      const pids = new Set();
      for (const line of out.split("\n")) {
        const t = line.trim().split(/\s+/); // [proto, local, foreign, state, pid]
        if (t.length >= 5 && t[3] === "LISTENING" && t[1].endsWith(":" + port)) pids.add(t[4]);
      }
      for (const pid of pids) try { execSync(`taskkill /PID ${pid} /F /T`, { stdio: "ignore" }); } catch {}
    } else {
      try { execSync(`fuser -k ${port}/tcp`, { stdio: "ignore" }); }
      catch {
        try {
          for (const pid of execSync(`lsof -ti tcp:${port}`, { encoding: "utf8" }).trim().split(/\s+/).filter(Boolean))
            try { process.kill(Number(pid), "SIGKILL"); } catch {}
        } catch {}
      }
    }
  } catch {}
};

const children = [];
const launch = (args, env = {}) => {
  const c = spawn(process.execPath, args, { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  children.push(c);
  return c;
};
const die = (code) => {
  for (const c of children) {
    // .kill() on Windows leaves the child's own children (and sometimes the child) alive;
    // taskkill /T tears down the whole tree so nothing lingers on a port for the next run.
    if (process.platform === "win32" && c.pid) {
      try { execSync(`taskkill /PID ${c.pid} /F /T`, { stdio: "ignore" }); } catch {}
    } else {
      try { c.kill(); } catch {}
    }
  }
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
  // Reclaim any port a prior run left occupied before we try to bind it.
  for (const port of [STUB_PORT, ...Object.keys(instances).map(Number)]) freePort(port);

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
