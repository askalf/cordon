import type { RedactMode, RedactSet } from "./types";

const env = process.env;

const ALL_SETS: RedactSet[] = ["pii", "phi", "pci", "secrets"];

/** Parse a comma list into a validated RedactSet[] (unknown tokens dropped). */
export const parseSets = (csv: string | undefined, fallback: RedactSet[]): RedactSet[] => {
  if (!csv) return fallback;
  const out = csv
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s): s is RedactSet => (ALL_SETS as string[]).includes(s));
  return out.length ? out : fallback;
};

export const config = {
  port: Number(env.PORT ?? 8080),
  /** Centralised brand string — never hardcode the name elsewhere. */
  brand: env.BRAND ?? "cordon",

  // Fail-closed is the whole point: a detection error must block, never leak.
  // "open" exists only as an explicit dev-time escape hatch.
  failMode: (env.FAIL_MODE ?? "closed") as "closed" | "open",

  defaultMode: (env.DEFAULT_MODE ?? "reversible") as RedactMode,
  activeSets: parseSets(env.ACTIVE_SETS, ALL_SETS),

  consistentPseudonyms: (env.CONSISTENT_PSEUDONYMS ?? "false") === "true",
  // HMAC key for consistent pseudonyms. The value being hashed is the PII; the key
  // keeps tokens from being reversible by anyone who guesses inputs.
  tenantSecret: env.TENANT_SECRET || "",

  auditLog: env.AUDIT_LOG || "./audit.jsonl",

  admin: {
    token: env.ADMIN_TOKEN || "", // empty = admin endpoints open (dev only)
  },

  // When no X-Tenant is sent, derive the tenant from the API key so different
  // callers get isolated policy / pseudonym namespaces.
  tenantFromAuth: (env.TENANT_FROM_AUTH ?? "true") === "true",

  upstream: {
    openai: env.OPENAI_BASE ?? "https://api.openai.com",
    anthropic: env.ANTHROPIC_BASE ?? "https://api.anthropic.com",
  },

  // Gated test affordances (forced fail-closed via header). OFF unless explicitly set,
  // so production carries no backdoor.
  testHooks: env.CORDON_TEST_HOOKS === "1",
};

export const ALL_REDACT_SETS = ALL_SETS;
