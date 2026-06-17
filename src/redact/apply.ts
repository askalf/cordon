import { clone } from "../util";
import type { Detector, Provider, RedactSet, Span } from "../types";
import type { Vault } from "./vault";

type Slot = { get(): string; set(v: string): void };

/** A closure over (parent object, key) that reads/writes one string field in place. */
const slot = (obj: any, key: string | number): Slot => ({
  get: () => obj[key],
  set: (v) => (obj[key] = v),
});

/**
 * Collect every REDACTABLE assistant/user text field in a provider REQUEST body.
 * Walks message content (string or content-part array) and Anthropic system blocks
 * and tool_result content. Images, tool schemas, and tool_use inputs are left alone.
 */
function requestTextSlots(body: any, provider: Provider): Slot[] {
  const slots: Slot[] = [];

  const pushContent = (container: any, key: string | number) => {
    const c = container[key];
    if (typeof c === "string") {
      slots.push(slot(container, key));
    } else if (Array.isArray(c)) {
      for (let i = 0; i < c.length; i++) {
        const part = c[i];
        if (!part || typeof part !== "object") continue;
        if (part.type === "text" && typeof part.text === "string") {
          slots.push(slot(part, "text"));
        } else if (part.type === "tool_result") {
          // Anthropic tool_result content can itself be a string or block array.
          if (typeof part.content === "string") slots.push(slot(part, "content"));
          else if (Array.isArray(part.content)) pushContent(part, "content");
        }
      }
    }
  };

  if (provider === "anthropic") {
    if (typeof body.system === "string") slots.push(slot(body, "system"));
    else if (Array.isArray(body.system))
      for (const b of body.system)
        if (b?.type === "text" && typeof b.text === "string") slots.push(slot(b, "text"));
  }

  for (const msg of body.messages ?? []) {
    if (msg && (typeof msg.content === "string" || Array.isArray(msg.content)))
      pushContent(msg, "content");
  }

  return slots;
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
  const slots = requestTextSlots(deidBody, provider);
  const all: Span[] = [];

  for (const sl of slots) {
    const text = sl.get();
    if (!text) continue;
    const spans = detector.detect(text, activeSets);
    if (!spans.length) continue;
    sl.set(replaceSpans(text, spans, vault));
    all.push(...spans);
  }

  return { deidBody, spans: all };
}

/** Tally spans into { TYPE: count } for the audit record and X-Redacted-Types header. */
export function tally(spans: Span[]): Record<string, number> {
  const t: Record<string, number> = {};
  for (const s of spans) t[s.type] = (t[s.type] ?? 0) + 1;
  return t;
}
