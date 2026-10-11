import { clone } from "../util";
import type { Detector, Dialect, Provider, RedactSet, Span } from "../types";
import type { Vault } from "./vault";

type Slot = { get(): string; set(v: string): void; numeric?: boolean };

// Leaf keys come from client-supplied bodies, so a key can literally be named
// "__proto__" or "constructor". Write those via defineProperty so the redacted value
// lands on the OWN property and the inherited prototype setter is never invoked —
// the leaf must still be redacted (skipping it would forward the raw value upstream).
const setLeaf = (obj: any, key: string | number, v: string): void => {
  if (key === "__proto__" || key === "constructor")
    Object.defineProperty(obj, key, { value: v, writable: true, enumerable: true, configurable: true });
  else obj[key] = v;
};

/** A closure over (parent object, key) that reads/writes one string field in place. */
const slot = (obj: any, key: string | number): Slot => ({
  get: () => obj[key],
  set: (v) => setLeaf(obj, key, v),
});

// A numeric/bigint leaf, coerced to text for detection and marked `numeric` so the
// redaction pass only treats it as PII when its ENTIRE value is a checksum-validated
// financial identifier (see applyRedaction). A 16-digit card or 9-digit routing
// number sent as a JSON NUMBER would otherwise skip detection and reach the model.
const numSlot = (obj: any, key: string | number): Slot => ({
  get: () => String(obj[key]),
  set: (v) => setLeaf(obj, key, v),
  numeric: true,
});

// The deepest a structured field is walked: the same 64 levels the response side
// restores tool arguments to (reidentify.ts MAX_ARG_DEPTH), so whatever came back real in
// a tool call is read again when the runner replays that call as history. Deeper is
// refused (a throw is a fail-closed 422 in the proxy), never walked part way.
const MAX_LEAF_DEPTH = 64;
const tooDeep = (what: string) =>
  new Error(`${what} nested deeper than ${MAX_LEAF_DEPTH} levels; refusing to forward unread fields`);

// Recursively push a slot for every string leaf — and every numeric leaf — of an
// object/array. Used for model-visible structured fields that carry user data
// (tool_use inputs, tool schemas, tool_call arguments) — a raw email/card hiding
// in any of them would otherwise reach the model. With `finalizers` (tool-call
// arguments) the property names are redacted too: the response side restores a value
// in a property name as it does in a value, and the replayed call must not carry it.
function pushStringLeaves(node: any, slots: Slot[], depth = 0, finalizers?: (() => void)[]): void {
  if (!node || typeof node !== "object") return;
  if (depth > MAX_LEAF_DEPTH) throw tooDeep("A structured field");
  const keys = Array.isArray(node) ? node.map((_: any, i: number) => i) : Object.keys(node);
  if (finalizers && !Array.isArray(node)) pushKeySlots(node, keys as string[], slots, finalizers);
  for (const k of keys) {
    const v = (node as any)[k];
    if (typeof v === "string") slots.push(slot(node, k));
    else if (typeof v === "number" || typeof v === "bigint") slots.push(numSlot(node, k));
    else if (v && typeof v === "object") pushStringLeaves(v, slots, depth + 1, finalizers);
  }
}

// One slot per property name of an argument object. A redacted name is applied after
// every value is written (a finalizer, ahead of any re-serialisation pushed later), with
// the object's key order kept. Two names that redact to the same name refuse the request
// rather than drop one of the values.
function pushKeySlots(obj: any, keys: string[], slots: Slot[], finalizers: (() => void)[]): void {
  const renamed = new Map<string, string>();
  for (const k of keys) slots.push({ get: () => k, set: (v) => { renamed.set(k, v); } });
  finalizers.push(() => {
    if (renamed.size === 0) return;
    const entries = keys.map((k) => [renamed.get(k) ?? k, obj[k]] as [string, any]);
    if (new Set(entries.map(([k]) => k)).size !== entries.length)
      throw new Error("two tool-call argument names redact to the same name; refusing to forward the request");
    for (const k of keys) delete obj[k];
    for (const [k, v] of entries) Object.defineProperty(obj, k, { value: v, writable: true, enumerable: true, configurable: true });
  });
}

// A JSON-string field (tool-call arguments): parse → redact its leaves (incl. NUMERIC
// PII) → re-serialize, so a redacted number becomes a QUOTED "<TYPE_N>" and the args
// stay valid JSON (a textual replace left an unquoted placeholder). Unparseable args
// fall back to text redaction.
function pushJsonString(obj: any, key: string, slots: Slot[], finalizers: (() => void)[]): void {
  let parsed: any;
  try { parsed = JSON.parse(obj[key]); } catch { parsed = undefined; }
  if (parsed && typeof parsed === "object") {
    pushStringLeaves(parsed, slots, 0, finalizers);
    finalizers.push(() => { obj[key] = JSON.stringify(parsed); });
  } else {
    slots.push(slot(obj, key));
  }
}

// Keys the Responses input walk never redacts, at any depth. The walk is fail-closed (every
// other string leaf of an input item is redacted, whatever the item type), so a key belongs
// here only when its value must reach the upstream byte-exact AND is not text the model
// reads as content:
//   type, role, status   enums the upstream validates against a fixed set
//   id, call_id,         references the upstream resolves by exact match to an earlier
//   approval_request_id  item or call; a rewritten id points at nothing
//   name, model          tool and model identifiers matched against the request
//   encrypted_content    an opaque reasoning blob only the upstream can decrypt
//   image_url, file_id,  media references and base64 payloads, the same fields an
//   file_url, file_data  input_image / input_file part carries (those parts are skipped)
// A caller-named key (a prompt variable, a JSON key inside arguments) is never matched
// against this list.
const RESPONSES_STRUCTURAL_KEYS = new Set([
  "type", "role", "status", "id", "call_id", "approval_request_id", "name", "model",
  "encrypted_content", "image_url", "file_id", "file_url", "file_data",
]);

// Objects the Responses walk skips whole: media parts (image pixels and file bytes are not
// text) and a generated image fed back as input (its `result` is base64 image data).
const RESPONSES_MEDIA_TYPES = new Set(["input_image", "input_file", "image_generation_call"]);

/**
 * Push a slot for every non-structural string leaf (and numeric leaf) of a Responses
 * input item, content part or prompt variable. This walk has no allow-list of item
 * types: an item type added to the API after this code was written is redacted the same
 * way as a known one, because an unread field would otherwise reach the model raw.
 * `arguments` is a JSON string in every item that carries it (function_call, mcp_call,
 * mcp_approval_request), so it is parsed and redacted leaf-wise to stay valid JSON.
 * Past MAX_LEAF_DEPTH the walk throws rather than stop: stopping would forward the
 * deeper leaves unread, and a throw is a fail-closed 422 in the proxy.
 */
function pushResponsesLeaves(node: any, slots: Slot[], finalizers: (() => void)[], depth = 0): void {
  if (depth > MAX_LEAF_DEPTH) throw tooDeep("Responses input");
  if (!Array.isArray(node) && RESPONSES_MEDIA_TYPES.has(node.type)) return;
  const keys = Array.isArray(node) ? node.map((_: any, i: number) => i) : Object.keys(node);
  for (const k of keys) {
    if (typeof k === "string" && RESPONSES_STRUCTURAL_KEYS.has(k)) continue;
    const v = node[k];
    if (typeof v === "string") {
      if (k === "arguments") pushJsonString(node, k, slots, finalizers);
      else slots.push(slot(node, k));
    } else if (typeof v === "number" || typeof v === "bigint") slots.push(numSlot(node, k));
    else if (v && typeof v === "object") pushResponsesLeaves(v, slots, finalizers, depth + 1);
  }
}

/**
 * Collect every REDACTABLE text field in a provider REQUEST body. Walks message
 * content (string or content-part array), Anthropic system blocks + tool_result
 * content, Responses `instructions`, `input` items and `prompt.variables`, AND every
 * model-visible structured field that can carry user data: OpenAI message `name` +
 * assistant `tool_calls[].function.arguments`, tool definitions (descriptions +
 * parameter schemas), and Anthropic `tool_use` inputs. Responses input items are walked
 * fail-closed (see pushResponsesLeaves). Chat and Messages content is read by part and
 * block type: media (image, audio, file and document file sources, search_result
 * sources), thinking blocks, ids, tool names, and any type not handled here pass as sent;
 * README "Fronting an agent runner" lists both sides.
 */
function requestTextSlots(
  body: any,
  provider: Provider,
  redactSystem: boolean,
  dialect: Dialect,
): { slots: Slot[]; finalizers: (() => void)[] } {
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
        if (
          (part.type === "text" || part.type === "input_text" || part.type === "output_text") &&
          typeof part.text === "string"
        ) {
          // output_text is an ASSISTANT part: a stateless Responses conversation appends
          // the previous reply's output to the next request's input, and that reply left
          // here with its real values restored.
          slots.push(slot(part, "text"));
        } else if (part.type === "refusal" && typeof part.refusal === "string") {
          slots.push(slot(part, "refusal"));
        } else if (part.type === "tool_result" || part.type === "mcp_tool_result") {
          // Anthropic tool_result content can itself be a string or block array.
          if (typeof part.content === "string") slots.push(slot(part, "content"));
          else if (Array.isArray(part.content)) pushContent(part, "content");
        } else if (
          (part.type === "tool_use" || part.type === "server_tool_use" || part.type === "mcp_tool_use") &&
          part.input && typeof part.input === "object"
        ) {
          // Tool inputs are user-supplied data, not a fixed schema; an earlier reply's call
          // comes back here with its real values restored.
          pushStringLeaves(part.input, slots, 0, finalizers);
        } else if (part.type === "document") {
          // A document's title and context are read by the model, and so is a plain-text
          // source (its data is the text) or a content source (text blocks). A base64 or
          // URL source is a file, left as sent.
          if (typeof part.title === "string") slots.push(slot(part, "title"));
          if (typeof part.context === "string") slots.push(slot(part, "context"));
          const src = part.source;
          if (src?.type === "text" && typeof src.data === "string") slots.push(slot(src, "data"));
          else if (src?.type === "content") {
            if (typeof src.content === "string") slots.push(slot(src, "content"));
            else if (Array.isArray(src.content)) pushContent(src, "content");
          }
        } else if (part.type === "search_result") {
          // A search result's title and text blocks are content; its source is the
          // result's identifier (a URL), cited back by the model as given.
          if (typeof part.title === "string") slots.push(slot(part, "title"));
          if (Array.isArray(part.content)) pushContent(part, "content");
        }
      }
    }
  };

  if (provider === "anthropic") {
    // The system prompt is application scaffolding; skip it unless redactSystem is on.
    if (redactSystem) {
      if (typeof body.system === "string") slots.push(slot(body, "system"));
      else if (Array.isArray(body.system))
        for (const b of body.system)
          if (b?.type === "text" && typeof b.text === "string") slots.push(slot(b, "text"));
    }
    if (Array.isArray(body.tools))
      for (const t of body.tools) {
        if (t && typeof t.description === "string") slots.push(slot(t, "description"));
        if (t && t.input_schema && typeof t.input_schema === "object") pushStringLeaves(t.input_schema, slots);
      }
  } else if (dialect === "responses") {
    // Responses: `instructions` is the system prompt; tools are flat objects.
    if (redactSystem && typeof body.instructions === "string") slots.push(slot(body, "instructions"));
    if (Array.isArray(body.tools))
      for (const t of body.tools) {
        if (!t || typeof t !== "object") continue;
        // A description is model-visible prose on every tool type that has one (function,
        // custom); an MCP server's description is shown to the model the same way. Other
        // tool fields are config the upstream acts on (MCP auth headers, vector store ids,
        // a custom tool's grammar) and are left as sent.
        if (typeof t.description === "string") slots.push(slot(t, "description"));
        if (typeof t.server_description === "string") slots.push(slot(t, "server_description"));
        if (t.type === "function" && t.parameters && typeof t.parameters === "object") pushStringLeaves(t.parameters, slots);
      }
    // A stored prompt's variables are substituted into the prompt the model reads. The
    // variable names are the caller's own keys, so each value is taken as content.
    const vars = body.prompt?.variables;
    if (vars && typeof vars === "object")
      for (const k of Object.keys(vars)) {
        if (typeof vars[k] === "string") slots.push(slot(vars, k));
        else if (vars[k] && typeof vars[k] === "object") pushResponsesLeaves(vars[k], slots, finalizers);
      }
    // `input` is a string, or a list of items. Every item is walked fail-closed: messages,
    // tool calls and tool outputs (string or part-array `output`) of every tool kind, and
    // any item type this code does not know.
    if (typeof body.input === "string") slots.push(slot(body, "input"));
    else if (Array.isArray(body.input))
      for (let i = 0; i < body.input.length; i++) {
        const item = body.input[i];
        if (typeof item === "string") { slots.push(slot(body.input, i)); continue; }
        if (!item || typeof item !== "object") continue;
        if (!redactSystem && (item.role === "system" || item.role === "developer")) continue;
        pushResponsesLeaves(item, slots, finalizers);
      }
    return { slots, finalizers };
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
    // OpenAI carries the system prompt as a role:"system" message — skip it too.
    if (!redactSystem && msg.role === "system") continue;
    if (typeof msg.content === "string" || Array.isArray(msg.content)) pushContent(msg, "content");
    // OpenAI: participant `name`, an assistant's `refusal`, and its `tool_calls` and
    // legacy `function_call` arguments are model-visible.
    if (typeof msg.name === "string") slots.push(slot(msg, "name"));
    if (typeof msg.refusal === "string") slots.push(slot(msg, "refusal"));
    if (msg.function_call && typeof msg.function_call.arguments === "string")
      pushJsonString(msg.function_call, "arguments", slots, finalizers);
    if (Array.isArray(msg.tool_calls))
      for (const tc of msg.tool_calls) {
        const fn = tc?.function;
        if (!fn || typeof fn.arguments !== "string") continue;
        pushJsonString(fn, "arguments", slots, finalizers);
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
  redactSystem = true,
  dialect: Dialect = provider === "anthropic" ? "messages" : "chat",
): RedactionResult {
  const deidBody = clone(rawBody);
  const { slots, finalizers } = requestTextSlots(deidBody, provider, redactSystem, dialect);
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
