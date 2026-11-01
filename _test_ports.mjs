// The loopback ports the test battery uses, one table for the runner, the stub and every suite.
// The runner picks free ports for each run and hands them down in CORDON_TEST_PORTS, so two
// batteries on one host (two CI jobs of this repository on the same self-hosted machine, say)
// never share a stub or kill each other's instances. Without the variable the historical fixed
// ports apply, so a suite can still be run by hand against a stub and an instance started by hand.
//
//   CORDON_TEST_PORTS=stub,dead,main,nosecret,noadmin,restore
//
// stub: the echo upstream; dead: an upstream that accepts and never answers (the proxy suite
// listens on it); main, nosecret, noadmin, restore: the four cordon instances the runner starts.
// The six ports must be distinct: the runner keys its instances by port.
import { closeSync, mkdirSync, openSync, rmSync, writeSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

const DEFAULTS = { stub: 8900, dead: 8901, main: 8810, nosecret: 8811, noadmin: 8812, restore: 8813 };
const NAMES = Object.keys(DEFAULTS);

export function parsePorts(value) {
  const ports = { ...DEFAULTS };
  if (!value) return ports;
  const given = String(value).split(",").map((x) => Number(x.trim()));
  if (given.length !== NAMES.length || given.some((p) => !Number.isInteger(p) || p < 1 || p > 65535) || new Set(given).size !== NAMES.length)
    throw new Error(`CORDON_TEST_PORTS must be ${NAMES.length} distinct ports (${NAMES.join(",")}), got "${value}"`);
  NAMES.forEach((n, i) => { ports[n] = given[i]; });
  return ports;
}

export const PORTS = parsePorts(process.env.CORDON_TEST_PORTS);
export const url = (port) => `http://localhost:${port}`;
export const portsEnv = (ports) => NAMES.map((n) => ports[n]).join(",");

/**
 * Host-wide directory where batteries record the ports they own, one `<port>.lock` file each.
 * It has to be the same for every battery on the host, so it does not follow a per-job TMPDIR
 * on POSIX; CORDON_TEST_PORT_LOCKS overrides it.
 */
export const LOCK_DIR =
  process.env.CORDON_TEST_PORT_LOCKS || (process.platform === "win32" ? join(tmpdir(), "cordon-test-ports") : "/tmp/cordon-test-ports");

/** A loopback port the kernel reports free right now. Nothing holds it once this resolves. */
export const probePort = () =>
  new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });

/**
 * Reserve one port per name. A probed port is only taken once its lock file is created with
 * O_EXCL, so of two batteries that probe the same port in the window before either binds it,
 * exactly one owns it and the other probes again. The locks are held until `release()`, which
 * covers the whole run, including the dead port that is only bound when its suite runs.
 * A lock left by a battery that was killed is skipped, never reclaimed: deleting another
 * process's lock cannot be made atomic with the check that its owner is gone.
 */
export async function reservePorts({ dir = LOCK_DIR, probe = probePort, tries = 200 } = {}) {
  mkdirSync(dir, { recursive: true });
  const held = [];
  const release = () => {
    for (const f of held.splice(0)) try { rmSync(f, { force: true }); } catch {}
  };
  const ports = {};
  try {
    for (const n of NAMES) {
      for (let i = 0; ; i++) {
        if (i >= tries) throw new Error(`no free test port for ${n} after ${tries} tries (locks in ${dir})`);
        const p = await probe();
        const file = join(dir, `${p}.lock`);
        let fd;
        try {
          fd = openSync(file, "wx");
        } catch (e) {
          if (e.code === "EEXIST") continue;
          throw e;
        }
        held.push(file);
        try { writeSync(fd, String(process.pid)); } finally { closeSync(fd); }
        ports[n] = p;
        break;
      }
    }
  } catch (e) {
    release();
    throw e;
  }
  return { ports, release };
}
