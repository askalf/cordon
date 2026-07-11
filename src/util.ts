import { createHash, createHmac } from "node:crypto";

export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

// No default-key fallback: an empty key must never silently produce a "valid-looking"
// keyed token. On the consistent-pseudonym path a missing/weak secret is caught up front
// (config.pseudonymSecretGuard + the per-request guard in proxy.ts) so an empty key never
// reaches here; keeping hmac total (empty key still hashes) is fine for any other caller.
export const hmac = (key: string, s: string) =>
  createHmac("sha256", key).update(s).digest("hex");

export const nowMs = () => Date.now();

/** Recursively sort object keys so serialization is deterministic (hash-chain safe). */
export const sortDeep = (v: any): any =>
  Array.isArray(v)
    ? v.map(sortDeep)
    : v && typeof v === "object"
      ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortDeep(v[k])]))
      : v;

/** Canonical JSON: stable key order so the same record always hashes the same. */
export const canonicalJSON = (v: any): string => JSON.stringify(sortDeep(v));

/** Reject an operation that takes too long. */
export const withTimeout = <T>(p: Promise<T>, ms: number): Promise<T> =>
  Promise.race([
    p,
    new Promise<T>((_, r) => setTimeout(() => r(new Error("cordon-timeout")), ms)),
  ]);

/** Deep clone a JSON-shaped body so redaction never mutates the caller's object. */
export const clone = <T>(v: T): T =>
  typeof structuredClone === "function" ? structuredClone(v) : JSON.parse(JSON.stringify(v));
