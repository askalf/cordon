import { clone } from "../util";
import { adapterFor } from "../providers";
import { PLACEHOLDER_RE, isFormingPlaceholder, Vault } from "./vault";
import type { Provider } from "../types";

/** Replace every placeholder we minted with its real value; leave unknown ones as-is. */
function restore(text: string, vault: Vault): string {
  return text.replace(PLACEHOLDER_RE, (m) => vault.lookup(m) ?? m);
}

/**
 * Full-body re-identification for a NON-streaming response: walk the provider
 * response's assistant-text fields and restore real values in place.
 */
export function reidentifyBody(body: any, provider: Provider, vault: Vault): any {
  if (!vault.hasReverse) return body; // nothing was redacted → nothing to restore
  const out = clone(body);
  for (const sl of adapterFor(provider).responseTextSlots(out)) sl.set(restore(sl.get(), vault));
  return out;
}

/**
 * Streaming re-identification — the boundary-safe restorer (the novel piece).
 *
 * Placeholders like `<EMAIL_1>` can be split across SSE frames / token deltas
 * (`<EMA` … `IL_1>`). We keep a rolling buffer and only flush the portion that
 * cannot still be growing into a placeholder: everything up to the last UNCLOSED
 * `<` that looks like a forming placeholder is safe to emit (with complete
 * placeholders restored); the possibly-forming tail is held until more text arrives.
 */
export class StreamReidentifier {
  private buf = "";
  constructor(private readonly vault: Vault) {}

  /** Push a raw assistant-text delta; return the text safe to emit now (may be ""). */
  push(textDelta: string): string {
    this.buf += textDelta;

    const lastOpen = this.buf.lastIndexOf("<");
    let flushLen = this.buf.length;
    if (lastOpen !== -1 && isFormingPlaceholder(this.buf.slice(lastOpen))) {
      flushLen = lastOpen; // hold from the forming '<' onward
    }

    const flush = this.buf.slice(0, flushLen);
    this.buf = this.buf.slice(flushLen);
    return restore(flush, this.vault);
  }

  /** Flush the remainder at end-of-stream. A stream that ended mid-placeholder
   *  leaves a forming token like "<EMAIL_1" that restore() can't match — emitting
   *  it verbatim would leak a partial placeholder to the client instead of the
   *  real value. Resolve such a truncated tail by unique prefix first. */
  end(): string {
    let tail = this.buf;
    this.buf = "";
    const lastOpen = tail.lastIndexOf("<");
    if (lastOpen !== -1 && isFormingPlaceholder(tail.slice(lastOpen))) {
      const real = this.vault.resolvePartial(tail.slice(lastOpen));
      if (real !== undefined) tail = tail.slice(0, lastOpen) + real;
    }
    return restore(tail, this.vault);
  }
}
