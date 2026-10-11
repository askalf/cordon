import { clone } from "../util";
import { adapterFor } from "../providers";
import { PLACEHOLDER_RE, isFormingPlaceholder, Vault } from "./vault";
import { restorePolicy, type RestorePolicy } from "./restorePolicy";
import type { Dialect, Provider } from "../types";

/** Replace every placeholder we minted with its real value; leave unknown ones as-is. */
export function restore(text: string, vault: Vault): string {
  return text.replace(PLACEHOLDER_RE, (m) => vault.lookup(m) ?? m);
}

// ----------------------------- tool arguments -----------------------------
//
// A tool call's arguments are not prose. The runner executes them, so three things hold
// that do not hold for text: a value goes back only where the restore policy allows it; a
// placeholder this request did not mint must not reach the runner unnoticed (it would be
// typed into a form or stored as data), so it is counted and the caller fails the call;
// and arguments that are a JSON document are restored on their raw text, never parsed and
// re-serialised, so the client gets the provider's bytes with only the placeholders
// replaced (big numbers keep their digits, and a streamed document's fragments join into
// exactly the document the done frame carries).

/** The inside of a placeholder this vault class mints: the counter form
 *  `TYPE_<6 hex nonce>_<n>` and the consistent-pseudonym form `TYPE_<8 hex>`. A
 *  placeholder-shaped literal of any other shape (a caller's own `<EMAIL_1>`) is text. */
const MINTED_NAME = /^[A-Z][A-Z0-9_]*_(?:[0-9A-F]{6}_\d+|[0-9A-F]{8})$/;
export const isMintedPlaceholder = (token: string): boolean =>
  token.startsWith("<") && token.endsWith(">") && MINTED_NAME.test(token.slice(1, -1));

/** A placeholder inside JSON text. In valid JSON `<` only occurs inside a string literal,
 *  and a serializer may write it as `<` (and `>` as `>`), so both spellings are
 *  one placeholder. */
const JSON_PLACEHOLDER_RE = /(?:<|\\u003[cC])([A-Z][A-Z0-9_]*)(?:>|\\u003[eE])/g;
const TEXT_PLACEHOLDER_RE = /<([A-Z][A-Z0-9_]*)>/g;

/** A real value as it must appear INSIDE a JSON string literal: JSON.stringify's own
 *  escaping with the surrounding quotes dropped. A value with a quote, a backslash or a
 *  newline spliced in raw would end the literal early or break the document. */
const jsonFragment = (v: string): string => JSON.stringify(v).slice(1, -1);

/**
 * Which top-level argument key a position in a JSON object's text belongs to, fed the
 * text in order, one fragment at a time. A placeholder at any depth under key K belongs
 * to K; a position outside every top-level value (a key itself, a document that is not an
 * object) belongs to none (undefined).
 */
export class TopKeyTracker {
  private depth = 0;
  private inString = false;
  private escaped = false;
  private collecting = false; // the current string is a top-level key
  private raw = "";
  private candidate: string | undefined;
  private topIsObject = false;
  private expectKey = false;
  key: string | undefined;

  feed(s: string): void {
    for (let i = 0; i < s.length; i++) this.step(s[i]);
  }

  private step(ch: string): void {
    if (this.inString) {
      if (this.escaped) {
        this.escaped = false;
        if (this.collecting) this.raw += ch;
        return;
      }
      if (ch === "\\") {
        this.escaped = true;
        if (this.collecting) this.raw += ch;
        return;
      }
      if (ch === '"') {
        this.inString = false;
        if (this.collecting) {
          this.collecting = false;
          this.candidate = this.raw;
        }
        return;
      }
      if (this.collecting) this.raw += ch;
      return;
    }
    if (ch === '"') {
      this.inString = true;
      this.collecting = this.depth === 1 && this.topIsObject && this.expectKey;
      this.raw = "";
      return;
    }
    if (ch === "{" || ch === "[") {
      this.depth++;
      if (this.depth === 1) {
        this.topIsObject = ch === "{";
        this.expectKey = this.topIsObject;
        this.key = undefined;
      }
      return;
    }
    if (ch === "}" || ch === "]") {
      this.depth--;
      if (this.depth <= 0) this.key = undefined;
      return;
    }
    if (this.depth !== 1 || !this.topIsObject) return;
    if (ch === ":" && this.candidate !== undefined) {
      try {
        this.key = JSON.parse(`"${this.candidate}"`);
      } catch {
        this.key = this.candidate;
      }
      this.candidate = undefined;
      this.expectKey = false;
      return;
    }
    if (ch === ",") {
      this.expectKey = true;
      this.key = undefined;
    }
  }
}

/** What restoring one tool call's arguments needs. One per call, shared by its fragments. */
export interface ArgContext {
  vault: Vault;
  /** The arguments are JSON text (a function call) rather than plain text (a custom
   *  tool's input): placeholders are matched in both spellings and values JSON-escaped. */
  json: boolean;
  /** Whether a value at a top-level argument key may be restored (restorePolicy). */
  allowKey: (key: string | undefined) => boolean;
  /** Tracks the top-level key across fragments; JSON arguments only. */
  keys?: TopKeyTracker;
  /** Minted-shape placeholders this vault cannot resolve, counted for the caller. */
  stats: { unresolved: number };
}

export function argContext(
  vault: Vault,
  json: boolean,
  tool: string | undefined,
  stats: { unresolved: number },
  policy: RestorePolicy = restorePolicy,
): ArgContext {
  return { vault, json, allowKey: policy.forTool(tool), keys: json ? new TopKeyTracker() : undefined, stats };
}

/** Restore the placeholders in one run of argument text (a whole document, or the part of
 *  a stream that cannot still be forming a placeholder). */
export function restoreArgs(text: string, c: ArgContext): string {
  const re = c.json ? JSON_PLACEHOLDER_RE : TEXT_PLACEHOLDER_RE;
  re.lastIndex = 0;
  let out = "";
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const before = text.slice(last, m.index);
    c.keys?.feed(before);
    out += before;
    const token = `<${m[1]}>`;
    const value = c.vault.lookup(token);
    if (value === undefined) {
      if (isMintedPlaceholder(token)) c.stats.unresolved++;
      out += m[0];
    } else if (c.allowKey(c.keys?.key)) {
      out += c.json ? jsonFragment(value) : value;
    } else {
      out += m[0];
    }
    c.keys?.feed(m[0]);
    last = m.index + m[0].length;
  }
  const rest = text.slice(last);
  c.keys?.feed(rest);
  return out + rest;
}

/** Restore the string leaves of an already-parsed argument object (Anthropic
 *  `tool_use.input`), each judged by the top-level key it sits under. Returns whether
 *  anything changed. */
export function restoreArgObject(obj: any, c: ArgContext): boolean {
  let changed = false;
  const walk = (node: any, key: string | undefined, depth: number) => {
    if (depth > 16 || !node || typeof node !== "object") return;
    for (const k of Array.isArray(node) ? node.map((_: any, i: number) => i) : Object.keys(node)) {
      const v = node[k];
      const top = depth === 0 && !Array.isArray(node) ? String(k) : key;
      if (typeof v === "string") {
        const r = restoreArgs(v, { ...c, json: false, keys: undefined, allowKey: () => c.allowKey(top) });
        if (r !== v) {
          node[k] = r;
          changed = true;
        }
      } else if (v && typeof v === "object") walk(v, top, depth + 1);
    }
  };
  walk(obj, undefined, 0);
  return changed;
}

/** Where a forming placeholder starts in `s`, or -1. JSON text can also be forming the
 *  escaped spelling: `\`, `\u00`, `<` and a name, or a name and a partial `>`. */
function formingStart(s: string, json: boolean): number {
  const cands = [s.lastIndexOf("<")];
  if (json) cands.push(s.lastIndexOf("\\"), Math.max(s.lastIndexOf("\\u003c"), s.lastIndexOf("\\u003C")));
  let best = -1;
  for (const p of cands) if (p !== -1 && isForming(s.slice(p), json) && (best === -1 || p < best)) best = p;
  return best;
}

function isForming(tail: string, json: boolean): boolean {
  let rest: string;
  if (tail.startsWith("<")) rest = tail.slice(1);
  else if (json && tail.startsWith("\\")) {
    if (tail.length < 6) return "\\u003c".startsWith(tail.toLowerCase());
    if (tail.slice(0, 6).toLowerCase() !== "\\u003c") return false;
    rest = tail.slice(6);
  } else return false;
  return json ? /^[A-Z0-9_]*(?:\\(?:u(?:0(?:0(?:3)?)?)?)?)?$/.test(rest) : /^[A-Z0-9_]*$/.test(rest);
}

/** A forming tail as the vault spells it: `<` and the name so far, open and partial close
 *  stripped. */
function canonicalPartial(tail: string): string {
  const rest = tail.startsWith("<") ? tail.slice(1) : tail.slice(6);
  return "<" + rest.replace(/\\.*$/, "");
}

/**
 * A tool call's arguments as they stream, fragment by fragment. Like StreamReidentifier,
 * the part that may still be growing into a placeholder is held until it completes; unlike
 * it, values are restored by restoreArgs (policy, unresolved count, JSON escaping).
 */
export class ArgStream {
  private buf = "";
  constructor(private readonly c: ArgContext) {}

  push(delta: string): string {
    this.buf += delta;
    const p = formingStart(this.buf, this.c.json);
    const flushLen = p === -1 ? this.buf.length : p;
    const flush = this.buf.slice(0, flushLen);
    this.buf = this.buf.slice(flushLen);
    return restoreArgs(flush, this.c);
  }

  /** The held remainder at the end of the call. A tail cut off mid-placeholder resolves by
   *  unique prefix, as text does, so the runner is not handed a partial token. */
  end(): string {
    const tail = this.buf;
    this.buf = "";
    const p = formingStart(tail, this.c.json);
    if (p === -1) return restoreArgs(tail, this.c);
    let out = restoreArgs(tail.slice(0, p), this.c);
    const forming = tail.slice(p);
    const real = this.c.vault.resolvePartial(canonicalPartial(forming));
    out += real !== undefined && this.c.allowKey(this.c.keys?.key) ? (this.c.json ? jsonFragment(real) : real) : forming;
    this.c.keys?.feed(forming);
    return out;
  }
}

// ----------------------------- whole bodies -----------------------------

/**
 * Full-body re-identification for a NON-streaming response: assistant text restored in
 * place, and every tool call's arguments restored under the restore policy. `stats`
 * collects the placeholders in arguments that this request cannot restore; the caller
 * refuses to deliver a body with any.
 */
export function reidentifyBody(
  body: any,
  provider: Provider,
  vault: Vault,
  dialect?: Dialect,
  stats: { unresolved: number } = { unresolved: 0 },
  policy: RestorePolicy = restorePolicy,
): any {
  const out = clone(body);
  for (const sl of adapterFor(provider, dialect).responseTextSlots(out)) {
    if (sl.kind === "text") sl.set(restore(sl.get(), vault));
    else if (sl.kind === "args") sl.set(restoreArgs(sl.get(), argContext(vault, sl.json, sl.tool, stats, policy)));
    else restoreArgObject(sl.obj, argContext(vault, false, sl.tool, stats, policy));
  }
  return out;
}

/**
 * Streaming re-identification of assistant text: the boundary-safe restorer.
 *
 * Placeholders like `<EMAIL_1>` can be split across SSE frames / token deltas
 * (`<EMA` … `IL_1>`). We keep a rolling buffer and only flush the portion that
 * cannot still be growing into a placeholder: everything up to the last UNCLOSED
 * `<` that looks like a forming placeholder is safe to emit (with complete
 * placeholders restored); the possibly-forming tail is held until more text arrives.
 * Tool-call arguments stream through ArgStream instead.
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

/** What the caller is told when tool-call arguments hold placeholders it cannot restore. */
export const unresolvedMessage = (n: number): string =>
  `cordon: the model's tool-call arguments hold ${n} placeholder${n === 1 ? "" : "s"} this request did not mint and cannot restore; the call was not delivered`;
