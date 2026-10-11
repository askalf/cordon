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
// A name character may itself be written as a JSON escape (\u0041 for A): only the
// escapes of [0-9A-Z_] count, so an escaped < or > never becomes part of a name.
const NAME_ESCAPE = String.raw`\\u00(?:3[0-9]|4[1-9A-Fa-f]|5[0-9Aa]|5[Ff])`;
const JSON_PLACEHOLDER_RE = new RegExp(String.raw`(?:<|\\u003[cC])((?:[A-Z0-9_]|${NAME_ESCAPE})+)(?:>|\\u003[eE])`, "g");
/** A placeholder name as the vault spells it, its JSON escapes decoded. */
const decodeName = (raw: string): string => raw.replace(/\\u00([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
/** The strip form of a placeholder: its type without the per-request suffix. */
const stripForm = (name: string): string => `[${name.replace(/_(?:[0-9A-F]{6}_\d+|[0-9A-F]{8})$/, "")}]`;
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

/** What a call's arguments did that must stop it: placeholders this vault cannot resolve
 *  (counted), and the first reason the arguments could not be restored safely at all. */
export interface ArgStats {
  unresolved: number;
  rejected?: string;
}

/** Whether a call must not be delivered. */
export const argsFailed = (s: ArgStats): boolean => s.unresolved > 0 || s.rejected !== undefined;

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
  /** The run of backslashes that ended the text restored so far: whether the next
   *  `<` is an escape (an even run before it) or text (an odd run escapes it). */
  backslashes?: number;
  stats: ArgStats;
}

export function argContext(
  vault: Vault,
  json: boolean,
  tool: string | undefined,
  stats: ArgStats,
  policy: RestorePolicy = restorePolicy,
): ArgContext {
  return { vault, json, allowKey: policy.forTool(tool), keys: json ? new TopKeyTracker() : undefined, backslashes: 0, stats };
}

const trailingBackslashes = (s: string): number => {
  let n = 0;
  for (let i = s.length - 1; i >= 0 && s[i] === "\\"; i--) n++;
  return n;
};

/** Restore the placeholders in one run of argument text (a whole document, or the part of
 *  a stream that cannot still be forming a placeholder). In JSON text a `<` only opens
 *  a placeholder when its backslash is not itself escaped: `\\u003c` is a backslash and
 *  the letters u003c, so the count of backslashes before it (across fragments) decides. */
export function restoreArgs(text: string, c: ArgContext): string {
  const re = c.json ? JSON_PLACEHOLDER_RE : TEXT_PLACEHOLDER_RE;
  re.lastIndex = 0;
  let out = "";
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    if (c.json && m[0][0] === "\\") {
      const head = text.slice(0, m.index);
      let run = trailingBackslashes(head);
      if (run === head.length) run += c.backslashes ?? 0;
      if (run % 2 === 1) {
        re.lastIndex = m.index + 1;
        continue;
      }
    }
    // Validated before anything is written or fed to the key tracker: a literal such as
    // <3> is ordinary text, left in place for the slice after the next real placeholder.
    const name = c.json ? decodeName(m[1]) : m[1];
    if (!/^[A-Z][A-Z0-9_]*$/.test(name)) {
      re.lastIndex = m.index + 1;
      continue;
    }
    const before = text.slice(last, m.index);
    c.keys?.feed(before);
    out += before;
    const token = `<${name}>`;
    const value = c.vault.lookup(token);
    if (value === undefined) {
      if (isMintedPlaceholder(token)) c.stats.unresolved++;
      out += m[0];
    } else if (c.allowKey(c.keys?.key)) {
      out += c.json ? jsonFragment(value) : value;
    } else {
      // Withheld: the tool gets the strip form ([EMAIL]), not the minted token, which a
      // later turn would carry back as a placeholder this vault no longer knows.
      out += stripForm(name);
    }
    c.keys?.feed(m[0]);
    last = m.index + m[0].length;
  }
  const rest = text.slice(last);
  c.keys?.feed(rest);
  if (c.json) {
    const t = trailingBackslashes(text);
    c.backslashes = t === text.length ? (c.backslashes ?? 0) + t : t;
  }
  return out + rest;
}

/**
 * Whether a JSON document has an object with two property names that decode to the same
 * string. A scan over the text, not a parse, so the numbers in it are never re-read; text
 * that is not well-formed JSON reports false (the tool's parser is the judge of that).
 */
export function hasDuplicateKeys(text: string): boolean {
  const stack: Array<{ keys: Set<string>; wantKey: boolean } | null> = [];
  let i = 0;
  try {
    while (i < text.length) {
      const ch = text[i];
      if (ch === '"') {
        let j = i + 1;
        while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
        const top = stack[stack.length - 1];
        if (top?.wantKey) {
          const key = JSON.parse(text.slice(i, j + 1)) as string;
          if (top.keys.has(key)) return true;
          top.keys.add(key);
          top.wantKey = false;
        }
        i = j + 1;
        continue;
      }
      if (ch === "{") stack.push({ keys: new Set(), wantKey: true });
      else if (ch === "[") stack.push(null);
      else if (ch === "}" || ch === "]") stack.pop();
      else if (ch === ",") {
        const top = stack[stack.length - 1];
        if (top) top.wantKey = true;
      }
      i++;
    }
  } catch {
    return false;
  }
  return false;
}

/** Refuse a restore that made two property names in one object the same: a restored value
 *  or two withheld ones ([EMAIL]) can collide, and the tool's parser keeps only one. A
 *  document that arrived with duplicates is the model's, not this restore's. */
function checkArgKeys(before: string, after: string, stats: ArgStats): void {
  if (before !== after && hasDuplicateKeys(after) && !hasDuplicateKeys(before)) {
    stats.rejected ??= "two argument names restore to the same name";
  }
}

/** restoreArgs for a whole argument document, refused as the streamed path refuses the
 *  same text: when it ends inside a placeholder, and (JSON text) when the restore made two
 *  of its property names the same (as restoreArgObject refuses for objects). */
export function restoreArgsWhole(text: string, c: ArgContext): string {
  const out = restoreArgs(text, c);
  const p = formingStart(text, c.json);
  if (p !== -1 && truncatedToken(formingName(text.slice(p)), c.vault)) {
    c.stats.unresolved++;
    c.stats.rejected ??= "the arguments end inside a placeholder";
  }
  if (c.json) checkArgKeys(text, out, c.stats);
  return out;
}

/** How deep an argument object may nest before it is refused rather than walked. */
export const MAX_ARG_DEPTH = 64;

/**
 * Restore an already-parsed argument object (Anthropic `tool_use.input`) the way the JSON
 * text path restores the same document: string values and property names alike, each
 * judged by the top-level key it sits under (a top-level property name by none, as a key
 * string in JSON text is). Two names that restore to the same name, or nesting deeper than
 * MAX_ARG_DEPTH, reject the call rather than drop or overwrite anything. Iterative, so a
 * deep object cannot exhaust the stack. Returns whether anything changed.
 */
export function restoreArgObject(obj: any, c: ArgContext): boolean {
  let changed = false;
  const one = (s: string, top: string | undefined) =>
    restoreArgs(s, { ...c, json: false, keys: undefined, allowKey: () => c.allowKey(top) });
  const stack: Array<{ node: any; top: string | undefined; depth: number }> = [];
  if (obj && typeof obj === "object") stack.push({ node: obj, top: undefined, depth: 0 });
  while (stack.length) {
    const { node, top, depth } = stack.pop()!;
    if (depth > MAX_ARG_DEPTH) {
      c.stats.rejected ??= `the arguments nest deeper than ${MAX_ARG_DEPTH} levels`;
      return changed;
    }
    if (!Array.isArray(node)) {
      const entries = Object.keys(node).map((k) => [k, node[k]] as [string, any]);
      const names = entries.map(([k]) => one(k, depth === 0 ? undefined : top));
      if (names.some((n, i) => n !== entries[i][0])) {
        if (new Set(names).size !== names.length) {
          c.stats.rejected ??= "two argument names restore to the same name";
          return changed;
        }
        for (const [k] of entries) delete node[k];
        entries.forEach(([, v], i) => Object.defineProperty(node, names[i], { value: v, writable: true, enumerable: true, configurable: true }));
        changed = true;
      }
    }
    for (const k of Array.isArray(node) ? node.map((_: any, i: number) => i) : Object.keys(node)) {
      const v = node[k];
      const below = depth === 0 && !Array.isArray(node) ? String(k) : top;
      if (typeof v === "string") {
        const r = one(v, below);
        if (r !== v) {
          node[k] = r;
          changed = true;
        }
      } else if (v && typeof v === "object") stack.push({ node: v, top: below, depth: depth + 1 });
    }
  }
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
  return json
    ? new RegExp(String.raw`^(?:[A-Z0-9_]|${NAME_ESCAPE})*(?:\\(?:u(?:0(?:0(?:[345])?)?)?)?)?$`).test(rest)
    : /^[A-Z0-9_]*$/.test(rest);
}

/** The name part of a forming tail, open and partial close stripped. */
function formingName(tail: string): string {
  const rest = tail.startsWith("<") ? tail.slice(1) : tail.slice(6);
  return decodeName(rest.replace(/\\(?:u(?:0(?:0(?:[345])?)?)?)?$/, ""));
}

/**
 * A tool call's arguments as they stream, fragment by fragment. Like StreamReidentifier,
 * the part that may still be growing into a placeholder is held until it completes; unlike
 * it, values are restored by restoreArgs (policy, unresolved count, JSON escaping), and a
 * stream that ends inside a placeholder is rejected rather than guessed at: the streamed
 * arguments and the whole-document restore of the same text must agree.
 */
export class ArgStream {
  private buf = "";
  // JSON arguments as received and as restored, for the property-name check at the end.
  private src = "";
  private out = "";
  constructor(private readonly c: ArgContext) {}

  push(delta: string): string {
    this.buf += delta;
    const p = formingStart(this.buf, this.c.json);
    const flushLen = p === -1 ? this.buf.length : p;
    const flush = this.buf.slice(0, flushLen);
    this.buf = this.buf.slice(flushLen);
    return this.emit(flush, restoreArgs(flush, this.c));
  }

  end(): string {
    const tail = this.buf;
    this.buf = "";
    const p = formingStart(tail, this.c.json);
    let out: string;
    if (p === -1) out = this.emit(tail, restoreArgs(tail, this.c));
    else {
      const forming = tail.slice(p);
      out = this.emit(tail.slice(0, p), restoreArgs(tail.slice(0, p), this.c));
      if (truncatedToken(formingName(forming), this.c.vault)) {
        this.c.stats.unresolved++;
        this.c.stats.rejected ??= "the arguments end inside a placeholder";
      }
      this.c.keys?.feed(forming);
      out += this.emit(forming, forming);
    }
    if (this.c.json) checkArgKeys(this.src, this.out, this.c.stats);
    return out;
  }

  private emit(src: string, out: string): string {
    if (this.c.json) {
      this.src += src;
      this.out += out;
    }
    return out;
  }
}

/**
 * Whether a name a stream ended inside is a cut-off placeholder rather than text: the
 * start of one this vault minted, or a name with the minted shape up to its nonce or
 * hash (a foreign token). Anything else (`<README`, `x<Y`) is text the tool
 * receives as written, as it would in a whole document.
 */
function truncatedToken(name: string, vault: Vault): boolean {
  if (!name) return false;
  if (/^[A-Z][A-Z0-9_]*_(?:[0-9A-F]{1,8}|[0-9A-F]{6}_\d*)$/.test(name)) return true;
  return vault.hasTokenPrefix(`<${name}`);
}

/**
 * A call's arguments held whole until the call ends, for when the restore policy depends
 * on a tool name that may still be arriving in fragments (`send`, then `_email`): nothing
 * is restored, and nothing emitted, under a name that is not final.
 */
export class DeferredArgs {
  private buf = "";
  constructor(private readonly make: () => ArgContext) {}
  push(delta: string): string {
    this.buf += delta;
    return "";
  }
  end(): string {
    const a = new ArgStream(this.make());
    return a.push(this.buf) + a.end();
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
  stats: ArgStats = { unresolved: 0 },
  policy: RestorePolicy = restorePolicy,
): any {
  const out = clone(body);
  for (const sl of adapterFor(provider, dialect).responseTextSlots(out)) {
    if (sl.kind === "text") sl.set(restore(sl.get(), vault));
    else if (sl.kind === "args") sl.set(restoreArgsWhole(sl.get(), argContext(vault, sl.json, sl.tool, stats, policy)));
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

/** What the caller is told when a call's arguments cannot be delivered. */
export function failMessage(s: ArgStats): string {
  if (s.unresolved)
    return `cordon: the model's tool-call arguments hold ${s.unresolved} placeholder${s.unresolved === 1 ? "" : "s"} this request did not mint and cannot restore; the call was not delivered`;
  return `cordon: the model's tool-call arguments could not be restored safely (${s.rejected}); the call was not delivered`;
}
