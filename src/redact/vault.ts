import { hmac } from "../util";
import type { RedactMode } from "../types";

/**
 * Per-request ephemeral value↔placeholder map. Created fresh for every request and
 * discarded when the response finishes — values are NEVER persisted to disk, the
 * audit log, or any cache. This is the only place raw PII lives, and only for the
 * lifetime of one request.
 *
 *   reversible : <TYPE_N>  (or <TYPE_HMAC8> with consistent pseudonyms) + reverse map
 *   strip      : [TYPE]    (irreversible — no reverse map kept)
 *
 * A given value always maps to the same placeholder within a request, so repeated
 * mentions stay consistent and re-identification restores all occurrences.
 */
export class Vault {
  private fwd = new Map<string, string>(); // value → placeholder
  private rev = new Map<string, string>(); // placeholder → value (reversible only)
  private counters = new Map<string, number>(); // type → next counter

  constructor(
    public readonly mode: RedactMode,
    private readonly opts: { consistentPseudonyms?: boolean; secret?: string } = {},
  ) {}

  /** Placeholder for a value of a given entity type (stable within this request). */
  placeholderFor(value: string, type: string): string {
    const existing = this.fwd.get(value);
    if (existing) return existing;

    let token: string;
    if (this.mode === "strip") {
      token = `[${type}]`;
    } else if (this.opts.consistentPseudonyms) {
      // Deterministic, keyed token: same value → same token across requests, while
      // the value itself is never stored or derivable without the secret.
      token = `<${type}_${hmac(this.opts.secret || "", value).slice(0, 8).toUpperCase()}>`;
    } else {
      const n = (this.counters.get(type) ?? 0) + 1;
      this.counters.set(type, n);
      token = `<${type}_${n}>`;
    }

    this.fwd.set(value, token);
    if (this.mode === "reversible") this.rev.set(token, value);
    return token;
  }

  /** Look up the real value behind a placeholder (reversible mode only). */
  lookup(placeholder: string): string | undefined {
    return this.rev.get(placeholder);
  }

  /** Whether any reverse mappings exist (i.e. there is anything to re-identify). */
  get hasReverse(): boolean {
    return this.rev.size > 0;
  }
}

// Matches placeholders this vault emits: <TYPE_…> with an underscore + suffix.
// Liberal on the type (may contain underscores, e.g. US_ROUTING); exact restoration
// is decided by the vault's reverse map, so over-matching is harmless.
export const PLACEHOLDER_RE = /<[A-Z][A-Z0-9_]*>/g;

/** A buffer tail that could still be GROWING into a placeholder (unclosed '<…'). */
export const isFormingPlaceholder = (tail: string): boolean =>
  tail.startsWith("<") && tail.indexOf(">") === -1 && /^<[A-Z0-9_]*$/.test(tail);
