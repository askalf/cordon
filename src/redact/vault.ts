import { randomBytes } from "node:crypto";
import { hmac } from "../util";
import type { RedactMode } from "../types";

/**
 * Per-request ephemeral value↔placeholder map. Created fresh for every request and
 * discarded when the response finishes — values are NEVER persisted to disk, the
 * audit log, or any cache. This is the only place raw PII lives, and only for the
 * lifetime of one request.
 *
 *   reversible : <TYPE_NONCE_N>  (or <TYPE_HMAC8> with consistent pseudonyms) + reverse map
 *   strip      : [TYPE]         (irreversible — no reverse map kept)
 *
 * A given value always maps to the same placeholder within a request, so repeated
 * mentions stay consistent and re-identification restores all occurrences.
 *
 * Counter tokens carry a per-request random NONCE (<EMAIL_7F3A2B_1>, not <EMAIL_1>) so a
 * caller's own placeholder-shaped text (e.g. asking "what does <EMAIL_1> mean?") can never
 * collide with a minted token and get rewritten to a real value on the way back. The
 * caller can't know the nonce, so it can't craft a colliding literal. The nonce is
 * uppercase hex, so tokens still fit the <[A-Z][A-Z0-9_]*> grammar the streaming buffer
 * relies on (PLACEHOLDER_RE / isFormingPlaceholder).
 */
export class Vault {
  private fwd = new Map<string, string>(); // value → placeholder
  private rev = new Map<string, string>(); // placeholder → value (reversible only)
  private counters = new Map<string, number>(); // type → next counter
  // Per-request nonce for counter tokens (uppercase hex). Fresh per Vault, so it's stable
  // within a request but unpredictable to the caller.
  private readonly nonce = randomBytes(3).toString("hex").toUpperCase();

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
      // Nonce keeps the token from colliding with any placeholder-shaped string the
      // caller supplied (which would otherwise be rewritten to a real value on restore).
      token = `<${type}_${this.nonce}_${n}>`;
    }

    this.fwd.set(value, token);
    if (this.mode === "reversible") this.rev.set(token, value);
    return token;
  }

  /** Look up the real value behind a placeholder (reversible mode only). */
  lookup(placeholder: string): string | undefined {
    return this.rev.get(placeholder);
  }

  /** Resolve a TRUNCATED placeholder (a stream that ended mid-token, e.g. "<EMAIL_1"
   *  with no closing ">") by UNIQUE prefix match — so the real value is restored
   *  rather than the partial placeholder being emitted to the client. Ambiguous or
   *  no match → undefined (emit as-is). Reversible mode only. */
  resolvePartial(partial: string): string | undefined {
    if (this.mode !== "reversible" || !partial.startsWith("<")) return undefined;
    let found: string | undefined;
    for (const [token, value] of this.rev) {
      if (token.startsWith(partial)) {
        if (found !== undefined) return undefined; // ambiguous — don't guess
        found = value;
      }
    }
    return found;
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
