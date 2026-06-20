import { clone } from "../util";
import type { Detector, Provider, RedactSet, Span } from "../types";
import type { Vault } from "./vault";

type Slot = { get(): string; set(v: string): void; numeric?: boolean };

/** A closure over (parent object, key) that reads/writes one string field in place. */
const slot = (obj: any, key: string | number): Slot => ({
  get: () => obj[key],
  set: (v) => (obj[key] = v),
});

// A numeric/bigint leaf, coerced to text for detection and marked `numeric` so the
// redaction pass only treats it as PII when its ENTIRE value is a checksum-validated
// financial identifier (see applyRedaction). A 16-digit card or 9-digit routing
// number sent as a JSON NUMBER would otherwise skip detection and reach the model.
const numSlot = (obj: any, key: string | number): Slot => ({
  get: () => String(obj[key]),
  set: (v) => (obj[key] = v),
  numeric: true,
});

// Recursively push a slot for every string leaf — and every numeric leaf — of an
// object/array. Used for model-visible structured fields that carry user data
// (tool_use inputs, tool schemas, tool_call arguments) — a raw email/card hiding
// in any of them would otherwise reach the model. Depth-capped so a pathological
// schema can't blow the stack (a redaction crash would fail the request closed,
// but cheap to avoid).
const MAX_LEAF_DEPTH = 16;
function pushStringLeaves(node: any, slots: Slot[], depth = 0): void {
  if (depth > MAX_LEAF_DEPTH || !node || typeof node !== "object") return;
  const keys = Array.isArray(node) ? node.map((_: any, i: number) => i) : Object.keys(node);
  for (const k of keys) {
    const v = (node as any)[k];
    if (typeof v === "string") slots.push(slot(node, k));
    else if (typeof v === "number" || typeof v === "bigint") slots.push(numSlot(node, k));
    else if (v && typeof v === "object") pushStringLeaves(v, slots, depth + 1);
  }
}

/**
 * Collect every REDACTABLE text field in a provider REQUEST body. Walks message
 * content (string or content-part array), Anthropic system blocks + tool_result
 * content, AND every model-visible structured field that can carry user data:
 * OpenAI message `name` + assistant `tool_calls[].function.arguments`, tool
 * definitions (descriptions + parameter schemas), and Anthropic `tool_use` inputs.
 * Only image parts and raw provider-auth headers are intentionally left untouched.
 */
function requestTextSlots(body: any, provider: Provider): { slots: Slot[]; finalizers: (() => void)[] } {
  const slots: Slot[] = [];
  const finalizers: (() => void)[] = []; // run after redaction (re-serialize parsed JSON-string fields)

  const pushContent = (container: any, key: string | number) => {
    const c = container[key];
    if (typeof c === "string") {
      slots.push(slot(container, key));
    } else if (Array.isArray(c)) {
      for (let i = 0; i < c.length; i++) {
        const part = c[i];
        if (typeof part === "string") { slots.push(slot(c, i)); continue; } // a bare-string content element
        if (!part || typeof part !== "object") continue;
        if (part.type === "text" && typeof part.text === "string") {
          slots.push(slot(part, "text"));
        } else if (part.type === "tool_result") {
          // Anthropic tool_result content can itself be a string or block array.
          if (typeof part.content === "string") slots.push(slot(part, "content"));
          else if (Array.isArray(part.content)) pushContent(part, "content");
        } else if (part.type === "tool_use" && part.input && typeof part.input === "object") {
          // Anthropic tool_use args are user-supplied data, not a fixed schema.
          pushStringLeaves(part.input, slots);
        }
      }
    }
  };

  if (provider === "anthropic") {
    if (typeof body.system === "string") slots.push(slot(body, "system"));
    else if (Array.isArray(body.system))
      for (const b of body.system)
        if (b?.type === "text" && typeof b.text === "string") slots.push(slot(b, "text"));
    if (Array.isArray(body.tools))
      for (const t of body.tools) {
        if (t && typeof t.description === "string") slots.push(slot(t, "description"));
        if (t && t.input_schema && typeof t.input_schema === "object") pushStringLeaves(t.input_schema, slots);
      }
  } else {
    // OpenAI tool definitions: description + parameter schema string leaves.
    if (Array.isArray(body.tools))
      for (const t of body.tools) {
        const fn = t?.function;
        if (fn && typeof fn.description === "string") slots.push(slot(fn, "description"));
        if (fn && fn.parameters && typeof fn.parameters === "object") pushStringLeaves(fn.parameters, slots);
      }
  }

  for (const msg of body.messages ?? []) {
    if (!msg || typeof msg !== "object") continue;
    if (typeof msg.content === "string" || Array.isArray(msg.content)) pushContent(msg, "content");
    // OpenAI: participant `name` and assistant `tool_calls` arguments are model-visible.
    if (typeof msg.name === "string") slots.push(slot(msg, "name"));
    if (Array.isArray(msg.tool_calls))
      for (const tc of msg.tool_calls) {
        const fn = tc?.function;
        if (!fn || typeof fn.arguments !== "string") continue;
        // arguments is a JSON STRING. Parse → redact its leaves (incl. NUMERIC PII)
        // → re-serialize, so a redacted number becomes a QUOTED "<TYPE_N>" and the
        // args stay valid JSON (a textual replace left an unquoted placeholder).
        // Unparseable args fall back to text redaction.
        let parsed: any;
        try { parsed = JSON.parse(fn.arguments); } catch { parsed = undefined; }
        if (parsed && typeof parsed === "object") {
          pushStringLeaves(parsed, slots);
          finalizers.push(() => { fn.arguments = JSON.stringify(parsed); });
        } else {
          slots.push(slot(fn, "arguments"));
        }
      }
  }

  return { slots, finalizers };
}

/** Replace spans in one string right-to-left so earlier offsets stay valid. */
function replaceSpans(text: string, spans: Span[], vault: Vault): string {
  const ordered = [...spans].sort((a, b) => b.start - a.start);
  let out = text;
  for (const s of ordered) {
    const token = vault.placeholderFor(s.value, s.type);
    out = out.slice(0, s.start) + token + out.slice(s.end);
  }
  return out;
}

export interface RedactionResult {
  deidBody: any;
  spans: Span[]; // every entity redacted, across all fields (for audit / headers)
}

/**
 * De-identify a provider request body: clone it, detect entities in each text field,
 * replace them with vault placeholders. Returns the rebuilt body + all spans.
 *
 * Throws if the detector throws — the spine turns that into a fail-closed response
 * (the request is NEVER forwarded with raw PII intact).
 */
export function applyRedaction(
  rawBody: any,
  provider: Provider,
  vault: Vault,
  activeSets: RedactSet[],
  detector: Detector,
): RedactionResult {
  const deidBody = clone(rawBody);
  const { slots, finalizers } = requestTextSlots(deidBody, provider);
  const all: Span[] = [];

  for (const sl of slots) {
    const text = sl.get();
    if (!text) continue;
    let spans = detector.detect(text, activeSets);
    if (sl.numeric)
      // A bare number is PII only when its WHOLE value is a checksum-validated
      // financial identifier. The format-only patterns (PHONE, SSN, DATE) would
      // false-positive on benign numeric ids / quantities / timestamps, so they
      // are not applied to numeric leaves.
      spans = spans.filter((s) => NUMERIC_PII.has(s.type) && s.start === 0 && s.end === text.length);
    if (!spans.length) continue;
    sl.set(replaceSpans(text, spans, vault));
    all.push(...spans);
  }
  for (const f of finalizers) f(); // re-serialize parsed JSON-string fields (tool_calls.arguments)

  return { deidBody, spans: all };
}

// Entity types safe to redact from a bare numeric leaf — each has a checksum
// validator, so a whole-value match is high-confidence rather than format noise.
const NUMERIC_PII = new Set(["CREDIT_CARD", "IBAN", "US_ROUTING"]);

/** Tally spans into { TYPE: count } for the audit record and X-Redacted-Types header. */
export function tally(spans: Span[]): Record<string, number> {
  const t: Record<string, number> = {};
  for (const s of spans) t[s.type] = (t[s.type] ?? 0) + 1;
  return t;
}
