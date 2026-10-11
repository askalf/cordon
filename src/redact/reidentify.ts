import { clone } from "../util";
import { adapterFor } from "../providers";
import { PLACEHOLDER_RE, isFormingPlaceholder, Vault } from "./vault";
import type { Dialect, Provider } from "../types";

/** Replace every placeholder we minted with its real value; leave unknown ones as-is. */
export function restore(text: string, vault: Vault): string {
  return text.replace(PLACEHOLDER_RE, (m) => vault.lookup(m) ?? m);
}

/** A real value as it must appear INSIDE a JSON string literal: JSON.stringify's own
 *  escaping with the surrounding quotes dropped. A value with a quote or a backslash
 *  spliced in raw would end the literal early and leave the arguments unparseable. */
const jsonFragment = (v: string): string => JSON.stringify(v).slice(1, -1);

/** restore() for text that is the inside of JSON string literals: a tool call's
 *  arguments as they stream, fragment by fragment. */
export function restoreJsonText(text: string, vault: Vault): string {
  return text.replace(PLACEHOLDER_RE, (m) => {
    const v = vault.lookup(m);
    return v === undefined ? m : jsonFragment(v);
  });
}

/** Restore every string leaf of an object or array in place (a tool_use `input`). */
export function restoreLeaves(node: any, vault: Vault, depth = 0): void {
  if (depth > 16 || !node || typeof node !== "object") return;
  const keys = Array.isArray(node) ? node.map((_: any, i: number) => i) : Object.keys(node);
  for (const k of keys) {
    const v = node[k];
    if (typeof v === "string") node[k] = restore(v, vault);
    else if (v && typeof v === "object") restoreLeaves(v, vault, depth + 1);
  }
}

/** restore() for a whole JSON document carried as a string (a tool call's
 *  `arguments`): parsed, every string leaf restored, re-serialised, so the value stays
 *  the JSON the client will parse. Text that is not JSON is restored as JSON text. */
export function restoreJsonString(text: string, vault: Vault): string {
  let parsed: any;
  try { parsed = JSON.parse(text); } catch { return restoreJsonText(text, vault); }
  if (typeof parsed === "string") return JSON.stringify(restore(parsed, vault));
  if (!parsed || typeof parsed !== "object") return text;
  restoreLeaves(parsed, vault);
  return JSON.stringify(parsed);
}

/**
 * Full-body re-identification for a NON-streaming response: walk the provider
 * response's assistant-text fields and restore real values in place. A slot marked
 * `json` holds a JSON document as a string (tool-call arguments) and is restored
 * leaf-wise so it stays valid JSON.
 */
export function reidentifyBody(body: any, provider: Provider, vault: Vault, dialect?: Dialect): any {
  if (!vault.hasReverse) return body; // nothing was redacted → nothing to restore
  const out = clone(body);
  for (const sl of adapterFor(provider, dialect).responseTextSlots(out))
    sl.set(sl.json ? restoreJsonString(sl.get(), vault) : restore(sl.get(), vault));
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
 *
 * In `json` mode the deltas are fragments of JSON string literals (a streamed tool
 * call's arguments), so a restored value is JSON-escaped on the way out.
 */
export class StreamReidentifier {
  private buf = "";
  private readonly json: boolean;
  constructor(private readonly vault: Vault, opts: { json?: boolean } = {}) {
    this.json = !!opts.json;
  }

  private restoreText(text: string): string {
    return this.json ? restoreJsonText(text, this.vault) : restore(text, this.vault);
  }

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
    return this.restoreText(flush);
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
      if (real !== undefined) tail = tail.slice(0, lastOpen) + (this.json ? jsonFragment(real) : real);
    }
    return this.restoreText(tail);
  }
}
