// Per-tenant policy. In-memory by default; set via the admin API. Every field is optional
// and falls back to the global config; an unset tenant uses defaults everywhere.
//
// Optionally file-backed (POLICY_STORE): when set, policy is loaded at startup and
// re-written on every change, so a restart/redeploy doesn't silently revert a tenant that
// was configured STRICTER than the global default (mode:"strip", failMode:"closed", a
// narrowed activeSets, a residency upstreamOverride) back to the weaker default. Unset =
// pure in-memory, exactly as before — no datastore, still a single self-contained container.

import { readFile, writeFile } from "node:fs/promises";
import { config } from "./config";
import type { Provider, RedactMode, RedactSet } from "./types";

export interface TenantPolicy {
  /** Default redact mode for this tenant (X-Redact-Mode still overrides per-request). */
  mode?: RedactMode;
  /** Active entity sets for this tenant (X-Redact-Sets still overrides per-request). */
  activeSets?: RedactSet[];
  /** Per-tenant fail-mode override. */
  failMode?: "closed" | "open";
  /** Stable HMAC pseudonyms instead of per-request counters. */
  consistentPseudonyms?: boolean;
  /** When false, never redact the system prompt (application scaffolding, not user data). */
  redactSystem?: boolean;
  /** Data-residency: route this tenant's traffic to a specific upstream base. */
  upstreamOverride?: Partial<Record<Provider, string>>;
}

const policies = new Map<string, TenantPolicy>();
const DEFAULT: TenantPolicy = {};

export const getPolicy = (tenant: string): TenantPolicy => policies.get(tenant) ?? DEFAULT;

export const setPolicy = (tenant: string, patch: Partial<TenantPolicy>): TenantPolicy => {
  const next = { ...getPolicy(tenant), ...patch };
  policies.set(tenant, next);
  // Persist (fire-and-forget). The in-memory value is already updated, so an admin write
  // must never fail on a disk hiccup — save() logs and swallows IO errors.
  save();
  return next;
};

export const allPolicies = () => Object.fromEntries(policies);

// Serializes writes so concurrent admin changes can't interleave a half-written file
// (mirrors the audit log's append discipline).
let persistTail: Promise<void> = Promise.resolve();

/**
 * Persist the full policy map to POLICY_STORE (no-op when unset). Returns the write
 * promise so callers/tests can await durability; setPolicy fires it and ignores the
 * result. Write failures are logged, not thrown.
 */
export function save(path = config.policyStore): Promise<void> {
  if (!path) return Promise.resolve();
  const snapshot = JSON.stringify(Object.fromEntries(policies), null, 2);
  persistTail = persistTail
    .then(() => writeFile(path, snapshot))
    .catch((e: any) => console.warn(`[policy] could not persist to ${path}: ${e?.message ?? e}`));
  return persistTail;
}

/**
 * Load persisted policy from POLICY_STORE (no-op when unset) BEFORE serving traffic,
 * replacing the in-memory set with what's on disk. Fail-safe: an absent, unreadable, or
 * malformed file leaves the current set untouched and never throws (so a disk hiccup can't
 * take the gateway down or wipe good in-memory state) — it just logs and continues.
 */
export async function load(path = config.policyStore): Promise<void> {
  if (!path) return;
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (e: any) {
    if (e?.code !== "ENOENT")
      console.warn(`[policy] could not read ${path}: ${e?.message ?? e} — keeping current policy set`);
    return; // absent/unreadable → fail-safe, no change
  }
  let obj: any;
  try {
    obj = JSON.parse(raw);
  } catch {
    console.warn(`[policy] ${path} is not valid JSON — keeping current policy set`);
    return;
  }
  if (!obj || typeof obj !== "object") return;
  policies.clear();
  for (const [tenant, pol] of Object.entries(obj))
    if (pol && typeof pol === "object") policies.set(tenant, pol as TenantPolicy);
}
