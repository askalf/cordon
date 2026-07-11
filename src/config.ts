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

  // The system prompt is application scaffolding, not user input. When false, cordon
  // never redacts it — agent frameworks (e.g. Claude Code) put framework text there
  // (the date, example emails); redacting it corrupts the model's instructions for no
  // user-PII benefit. Default true keeps the redact-everything guarantee.
  redactSystem: (env.REDACT_SYSTEM ?? "true") === "true",

  consistentPseudonyms: (env.CONSISTENT_PSEUDONYMS ?? "false") === "true",
  // HMAC key for consistent pseudonyms. The value being hashed is the PII; the key
  // keeps tokens from being reversible by anyone who guesses inputs. Consistent-pseudonym
  // mode REQUIRES an adequate secret (see pseudonymSecretGuard) — an empty/weak key makes
  // every stable token guessable from the public source, i.e. a partial-PII leak.
  tenantSecret: env.TENANT_SECRET || "",

  auditLog: env.AUDIT_LOG || "./audit.jsonl",

  // Optional file-backed persistence for per-tenant policy. Empty (default) = in-memory
  // only, exactly as before — no datastore, still a single self-contained container. When
  // set, policy is loaded at startup and re-written on every admin change so a restart
  // doesn't silently revert tenants to global defaults.
  policyStore: env.POLICY_STORE || "",

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

// ---- consistent-pseudonym secret guard (fail-closed) ----

/** Minimum acceptable TENANT_SECRET length before we'll mint keyed pseudonyms. */
export const MIN_PSEUDONYM_SECRET_LEN = 16;

/** A secret is adequate to key consistent pseudonyms only if it's long enough that the
 *  tokens aren't reproducible by anyone guessing inputs. */
export const adequatePseudonymSecret = (secret: string): boolean =>
  secret.length >= MIN_PSEUDONYM_SECRET_LEN;

/** Explicit dev escape hatch: run the weak/empty-secret pseudonym path anyway (tests +
 *  local dev). Off in production, so the guard can't be silently disabled. */
export const allowWeakPseudonymSecret = (): boolean => env.ALLOW_WEAK_PSEUDONYM_SECRET === "1";

/**
 * Fail-closed gate for consistent-pseudonym mode. Consistent pseudonyms hash the PII
 * with TENANT_SECRET; with no (or a too-short) secret every stable token is guessable
 * from the public source — a partial-PII leak. A compliance gateway must refuse that mode
 * rather than silently degrade. Returns an actionable error when the mode is on but the
 * secret is inadequate and the escape hatch is off; `{ ok: true }` otherwise.
 */
export function pseudonymSecretGuard(opts: {
  consistentPseudonyms: boolean;
  secret: string;
  allowWeak: boolean;
}): { ok: boolean; error?: string } {
  if (!opts.consistentPseudonyms || opts.allowWeak || adequatePseudonymSecret(opts.secret))
    return { ok: true };
  const why = opts.secret ? `too short (< ${MIN_PSEUDONYM_SECRET_LEN} chars)` : "unset";
  return {
    ok: false,
    error:
      `consistent pseudonyms are enabled but TENANT_SECRET is ${why} — refusing to mint ` +
      `guessable tokens. Set a strong random TENANT_SECRET (>= ${MIN_PSEUDONYM_SECRET_LEN} chars), ` +
      `or set ALLOW_WEAK_PSEUDONYM_SECRET=1 to override (dev only).`,
  };
}
