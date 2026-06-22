// Per-tenant policy. In-memory; set via the admin API. Every field is optional and
// falls back to the global config; an unset tenant uses defaults everywhere.

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
  return next;
};

export const allPolicies = () => Object.fromEntries(policies);
