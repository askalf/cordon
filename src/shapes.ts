// Request shapes: the structure of a request with none of its text, so real traffic can be
// replayed with invented people (src/tools/replay-shapes.ts). A shape keeps the provider's own
// keys, array lengths, string lengths and line counts, the API's enum values and the names of
// tools; its markers start with `$`, which no provider key does. It never keeps text, a caller-defined key (written `*0`, `*1`, ...) or anything under
// one, a participant name, or a number's value.
import { appendFile, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { PROTOCOL_KEYS, ENUM_FIELDS, ENUM_VALUES, CALLER_CONTAINERS, isToolCall } from "./subject";
import { canonicalJSON } from "./util";

/** A string's size class: exact up to 16, then the next power of two (capped at 2^20). */
export const sizeClass = (n: number) => (n <= 16 ? n : 2 ** Math.min(20, Math.ceil(Math.log2(n))));
const TOOL_NAME = /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/;
const ENUM_TOKEN = /^[a-z][a-z0-9_./+-]{0,39}$/;
const MAX_ITEMS = 12;
const MAX_DEPTH = 32;

/**
 * The shape of one JSON value. `caller` is true below caller-defined data (as in the egress
 * walk), where keys are anonymised and no value is kept. `tool` is true where a `name` is a
 * tool's name: a tool definition, a tool call, a chat `function`.
 */
export function skeleton(node: unknown, depth = 0, caller = false, tool = false): unknown {
  if (depth > MAX_DEPTH) return { $deep: 1 };
  if (typeof node === "string") {
    const s: Record<string, unknown> = { $s: sizeClass(node.length) };
    const nl = node.split("\n").length - 1;
    if (nl) s.$nl = sizeClass(nl);
    const lead = node.trimStart()[0];
    if (lead === "{" || lead === "[") {
      try {
        const decoded = JSON.parse(node);
        if (decoded && typeof decoded === "object") {
          s.$json = skeleton(decoded, depth + 1, true);
          if (/\n[ \t]/.test(node)) s.$pretty = 1;
        }
      } catch {
        /* text that only starts like JSON */
      }
    }
    return s;
  }
  if (typeof node === "number" || typeof node === "bigint") return { $n: 1 };
  if (typeof node === "boolean") return { $b: 1 };
  if (node === null || typeof node !== "object") return null;
  if (Array.isArray(node)) {
    const items = node.slice(0, MAX_ITEMS).map((v) => skeleton(v, depth + 1, caller, tool));
    if (node.length > MAX_ITEMS) items.push({ $more: node.length - MAX_ITEMS });
    return items;
  }
  const out: Record<string, unknown> = {};
  let anon = 0;
  for (const [k, v] of Object.entries(node)) {
    const protocol = !caller && PROTOCOL_KEYS.has(k);
    const key = protocol ? k : `*${anon++}`;
    // An enum field's value is the API's own vocabulary ("content", "image/png"), kept when it is
    // a short lowercase token; anything else there is treated as text.
    if (protocol && ENUM_FIELDS.has(k) && typeof v === "string" && (ENUM_VALUES.has(v) || ENUM_TOKEN.test(v))) { out[key] = v; continue; }
    if (protocol && k === "name" && typeof v === "string" && (tool || isToolCall(node)) && TOOL_NAME.test(v)) { out[key] = { $tool: v }; continue; }
    if (protocol && k === "model" && typeof v === "string") { out[key] = { $model: 1 }; continue; }
    const below = !protocol || CALLER_CONTAINERS.has(k) || (k === "input" && isToolCall(node));
    const toolHere = protocol && (k === "tools" || k === "function" || k === "tool_choice");
    out[key] = skeleton(v, depth + 1, below, toolHere);
  }
  return out;
}

export interface ShapeRecord {
  ts: number;
  h: string; // a digest of provider, dialect and shape: the dedup key
  provider: string;
  dialect: string;
  shape: unknown;
}

export const shapeDigest = (provider: string, dialect: string, shape: unknown) =>
  createHash("sha256").update(canonicalJSON({ provider, dialect, shape })).digest("hex").slice(0, 16);

/** Appends each new shape once, up to `max` shapes. Never throws: a shape log must not affect traffic. */
export class ShapeLog {
  private seen: Set<string> | null = null;
  private tail: Promise<unknown> = Promise.resolve();
  constructor(private readonly path: string, private readonly max: number) {}

  private async init(): Promise<Set<string>> {
    if (this.seen) return this.seen;
    const seen = new Set<string>();
    try {
      for (const line of (await readFile(this.path, "utf8")).split("\n"))
        if (line) try { seen.add(JSON.parse(line).h); } catch { /* skip */ }
    } catch {
      /* no log yet */
    }
    this.seen = seen;
    return seen;
  }

  record(provider: string, dialect: string, body: unknown): Promise<void> {
    if (!this.path) return Promise.resolve();
    const next = this.tail.then(async () => {
      try {
        const seen = await this.init();
        if (seen.size >= this.max) return;
        const shape = skeleton(body);
        const h = shapeDigest(provider, dialect, shape);
        if (seen.has(h)) return;
        seen.add(h);
        const rec: ShapeRecord = { ts: Date.now(), h, provider, dialect, shape };
        await appendFile(this.path, JSON.stringify(rec) + "\n");
      } catch {
        /* never affects the request */
      }
    });
    this.tail = next;
    return next;
  }
}
