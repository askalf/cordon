// One-command test battery: spawns the echo stub + a cordon instance, runs the unit
// suite (under tsx) and the integration suites, then tears everything down.
//
//   npm test
import { spawn, execSync } from "node:child_process";
import { rmSync } from "node:fs";
import { createServer } from "node:net";
import { parsePorts, portsEnv, url } from "./_test_ports.mjs";

/**
 * A loopback port the kernel reports free right now. Each run takes its six ports this way, so
 * concurrent batteries on one host get distinct stubs and instances. CORDON_TEST_PORTS set by
 * hand pins the ports instead.
 */
const freePort = () =>
  new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });

async function pickPorts() {
  if (process.env.CORDON_TEST_PORTS) return parsePorts(process.env.CORDON_TEST_PORTS);
  const names = ["stub", "dead", "main", "nosecret", "noadmin", "restore"];
  const ports = {};
  for (const n of names) {
    let p;
    do p = await freePort(); while (Object.values(ports).includes(p));
    ports[n] = p;
  }
  return ports;
}

const PORTS = await pickPorts();
process.env.CORDON_TEST_PORTS = portsEnv(PORTS);
const STUB = url(PORTS.stub);
const base = { OPENAI_BASE: STUB, ANTHROPIC_BASE: STUB };

// port → instance env
const instances = {
  // Primary instance: has a strong TENANT_SECRET, so consistent-pseudonym requests work, and
  // opts in to X-Tenant (TRUST_TENANT_HEADER) so the tenant-selection rule is exercised.
  [PORTS.main]: { ADMIN_TOKEN: "secret", AUDIT_LOG: "./_audit_test.jsonl", SHAPE_LOG: "./_shapes_test.jsonl", CORDON_RESTORE_TOOLS: "*", CORDON_TEST_HOOKS: "1", TENANT_SECRET: "test-secret-0123456789abcdef", TRUST_TENANT_HEADER: "true" },
  // Secret-less instance: consistent pseudonyms enabled per-tenant here must FAIL CLOSED
  // (no ALLOW_WEAK_PSEUDONYM_SECRET) — exercises the per-request pseudonym-secret guard.
  // TRUST_TENANT_HEADER is left at its default, so X-Tenant is ignored here.
  [PORTS.nosecret]: { ADMIN_TOKEN: "secret", AUDIT_LOG: "./_audit_test_nosecret.jsonl", CORDON_RESTORE_TOOLS: "*" },
  // No ADMIN_TOKEN; an Anthropic upstream accepts connections but never answers.
  // The proxy suite opens it on the dead port with a short timeout for the 504 path.
  [PORTS.noadmin]: {
    AUDIT_LOG: "./_audit_test_noadmin.jsonl",
    ANTHROPIC_BASE: `http://127.0.0.1:${PORTS.dead}`,
    UPSTREAM_TIMEOUT_MS: "500",
  },
  // A restore allowlist: only the `text` argument of the `echo` tool gets real values back.
  [PORTS.restore]: { AUDIT_LOG: "./_audit_test_restore.jsonl", CORDON_RESTORE_TOOLS: "echo.text,send" },
};

// Suites importing TS modules directly run under the tsx loader.
const TSX_SUITES = new Set(["_test_unit.mjs", "_test_fuzz.js", "_test_subject.mjs", "_test_fuzz_subject.js", "_test_replay.mjs", "_test_shapes.mjs"]);
const suites = ["_test_unit.mjs", "_test_subject.mjs", "_test_fuzz.js", "_test_fuzz_subject.js", "_test_replay.mjs", "_test_shapes.mjs", "_test_proxy.mjs", "_test_subject_proxy.mjs", "_test_replay_recorded.mjs", "_test_stream.mjs", "_test_labeler_config.mjs", "_test_release_notes.mjs", "_test_build_inputs.mjs"];

// Fresh audit chains + scratch files each run.
for (const f of ["./_audit_test.jsonl", "./_shapes_test.jsonl", "./_audit_test_nosecret.jsonl", "./_audit_test_noadmin.jsonl", "./_audit_test_restore.jsonl", "./_policy_unit.json", "./_policy_bad.json"])
  try { rmSync(f, { force: true }); } catch {}

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
  console.log(`ports: ${process.env.CORDON_TEST_PORTS} (stub,dead,main,nosecret,noadmin,restore)`);
  launch(["_stub-upstream.mjs"], { STUB_PORT: String(PORTS.stub) });
  await waitUp(`${STUB}/__calls`, "stub");

  for (const [port, env] of Object.entries(instances)) {
    launch(["--import", "tsx", "src/index.ts"], { PORT: port, ...base, ADMIN_TOKEN: "", ...env });
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
