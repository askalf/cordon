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
