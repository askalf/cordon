import { config } from "./config";
import { sha256 } from "./util";
import { getPolicy } from "./policy";
import type { CanonicalRequest, Dialect, Provider, RedactMode, RedactSet } from "./types";

/**
 * A ProviderAdapter knows one wire dialect: how to read a text delta off a
 * streamed frame, and — the inverse cordon needs — how to synthesize a
 * text-carrying SSE frame from a (re-identified) text chunk.
 */
export interface ProviderAdapter {
  /** Read a streamed SSE `data:` payload. */
  parseDelta(data: string): { textDelta?: string; done: boolean };
  /** Build a dialect-correct SSE frame carrying one assistant-text chunk at `index`
   *  (the content-block index; ignored by dialects without block indices). `ctx` is
   *  the addressing the dialect needs beyond an index (Responses: item_id,
   *  output_index, content_index) plus the upstream event `type`, copied from the
   *  frame being re-emitted. */
  frameFromText(text: string, index?: number, ctx?: Record<string, unknown>): string;
  /** Walk a non-streaming response body's restorable fields (for re-identify): assistant
   *  text, and every tool call's arguments with the tool's name (redact/reidentify.ts
   *  restores arguments under the restore policy). */
  responseTextSlots(body: any): Array<ResponseSlot>;
}

export type ResponseSlot =
  /** Assistant prose. */
  | { kind: "text"; get(): string; set(v: string): void }
  /** A tool call's arguments as a string: a JSON document (`json`) or a custom tool's
   *  plain-text input. */
  | { kind: "args"; json: boolean; tool: string | undefined; get(): string; set(v: string): void }
  /** A tool call's arguments already parsed into an object (Anthropic `input`). */
  | { kind: "args-object"; tool: string | undefined; obj: any };

const textSlot = (obj: any, key: string): ResponseSlot => ({ kind: "text", get: () => obj[key], set: (v) => (obj[key] = v) });
const argsSlot = (obj: any, key: string, tool: unknown, json = true): ResponseSlot => ({
  kind: "args",
  json,
  tool: typeof tool === "string" ? tool : undefined,
  get: () => obj[key],
  set: (v) => (obj[key] = v),
});

// ----------------------------- OpenAI (chat.completions) -----------------------------
export const openai: ProviderAdapter = {
  parseDelta(data) {
    try {
      const j = JSON.parse(data);
      const ch = j.choices?.[0];
      return { textDelta: ch?.delta?.content ?? "", done: ch?.finish_reason != null };
    } catch {
      return { done: false };
    }
  },
  frameFromText(text, _index = 0) {
    // OpenAI chat.completions has no content-block index; always choices[0].
    return `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: text } }] })}\n\n`;
  },
  responseTextSlots(body) {
    const slots: ResponseSlot[] = [];
    // Every choice, not only the first: a request with n > 1 gets one message per choice.
    for (const ch of body?.choices ?? []) {
      const msg = ch?.message;
      if (msg && typeof msg.content === "string") {
        slots.push(textSlot(msg, "content"));
      } else if (msg && Array.isArray(msg.content)) {
        for (const part of msg.content)
          if (part?.type === "text" && typeof part.text === "string") slots.push(textSlot(part, "text"));
      }
      // The arguments the model chose for a tool, a JSON string per call.
      for (const tc of Array.isArray(msg?.tool_calls) ? msg.tool_calls : []) {
        const fn = tc?.function;
        if (fn && typeof fn.arguments === "string") slots.push(argsSlot(fn, "arguments", fn.name));
      }
      // The legacy single function call (functions / function_call request fields).
      const fc = msg?.function_call;
      if (fc && typeof fc.arguments === "string") slots.push(argsSlot(fc, "arguments", fc.name));
    }
    return slots;
  },
};

// ----------------------------- Anthropic (messages) -----------------------------
export const anthropic: ProviderAdapter = {
  parseDelta(data) {
    try {
      const j = JSON.parse(data);
      if (j.type === "content_block_delta") return { textDelta: j.delta?.text ?? "", done: false };
      if (j.type === "message_stop") return { done: true };
      return { done: false };
    } catch {
      return { done: false };
    }
  },
  frameFromText(text, index = 0) {
    const data = { type: "content_block_delta", index, delta: { type: "text_delta", text } };
    return `event: content_block_delta\ndata: ${JSON.stringify(data)}\n\n`;
  },
  responseTextSlots(body) {
    const slots: ResponseSlot[] = [];
    for (const block of body?.content ?? []) {
      if (block?.type === "text" && typeof block.text === "string") slots.push(textSlot(block, "text"));
      // A tool call's input arrives parsed. Client tools (tool_use), server tools
      // (server_tool_use) and MCP connector tools (mcp_tool_use) all carry one.
      else if (ANTHROPIC_TOOL_BLOCKS.has(block?.type) && block.input && typeof block.input === "object")
        slots.push({ kind: "args-object", tool: typeof block.name === "string" ? block.name : undefined, obj: block.input });
    }
    return slots;
  },
};

/** Anthropic content blocks that carry a tool call's input. */
export const ANTHROPIC_TOOL_BLOCKS = new Set(["tool_use", "server_tool_use", "mcp_tool_use"]);

// ----------------------------- OpenAI (responses) -----------------------------
/** Streamed Responses events carrying restorable assistant text. Output text and a
 *  refusal are DISTINCT event types and a client consuming refusals reads only its
 *  own, so a refusal delta must be re-emitted as a refusal delta. */
const RESPONSES_TEXT_DELTAS = new Set(["response.output_text.delta", "response.refusal.delta"]);
/** The streamed fragments of a tool call's arguments, re-emitted under their own event
 *  type once restored, like a refusal delta. Function and MCP calls stream a JSON
 *  document; a custom tool streams plain text. */
export const RESPONSES_JSON_ARGUMENT_DELTAS = new Set(["response.function_call_arguments.delta", "response.mcp_call_arguments.delta"]);
export const RESPONSES_ARGUMENT_DELTAS = new Set([...RESPONSES_JSON_ARGUMENT_DELTAS, "response.custom_tool_call_input.delta"]);
const RESPONSES_REEMITTED = new Set([...RESPONSES_TEXT_DELTAS, ...RESPONSES_ARGUMENT_DELTAS]);

export const openaiResponses: ProviderAdapter = {
  parseDelta(data) {
    try {
      const j = JSON.parse(data);
      if (RESPONSES_TEXT_DELTAS.has(j.type)) return { textDelta: j.delta ?? "", done: false };
      if (j.type === "response.completed") return { done: true };
      return { done: false };
    } catch {
      return { done: false };
    }
  },
  frameFromText(text, _index = 0, ctx = {}) {
    // The Responses stream addresses a delta by item_id / output_index / content_index,
    // not by a single block index; `ctx` carries those from the frame being re-emitted,
    // along with that frame's event type so a refusal delta stays a refusal delta.
    const type =
      typeof ctx.type === "string" && RESPONSES_REEMITTED.has(ctx.type)
        ? ctx.type
        : "response.output_text.delta";
    const data = { ...ctx, type, delta: text };
    return `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  },
  responseTextSlots(body) {
    const slots: ResponseSlot[] = [];
    for (const item of body?.output ?? []) {
      // A function or MCP call's arguments are a JSON string and a custom tool's input
      // plain text: the values the caller's tool (or the MCP server) runs on.
      if ((item?.type === "function_call" || item?.type === "mcp_call") && typeof item.arguments === "string") {
        slots.push(argsSlot(item, "arguments", item.name));
        continue;
      }
      if (item?.type === "custom_tool_call" && typeof item.input === "string") {
        slots.push(argsSlot(item, "input", item.name, false));
        continue;
      }
      if (item?.type !== "message" || !Array.isArray(item.content)) continue;
      for (const part of item.content) {
        if (part?.type === "output_text" && typeof part.text === "string") slots.push(textSlot(part, "text"));
        else if (part?.type === "refusal" && typeof part.refusal === "string") slots.push(textSlot(part, "refusal"));
      }
    }
    return slots;
  },
};

export const adapterFor = (p: Provider, dialect?: Dialect) =>
  p === "anthropic" ? anthropic : dialect === "responses" ? openaiResponses : openai;

// ----------------------------- normalize: HTTP → CanonicalRequest -----------------------------

const VALID_MODES = new Set<RedactMode>(["reversible", "strip", "off"]);

function resolveMode(headers: Record<string, string>, tenant: string): RedactMode {
  const h = (headers["x-redact-mode"] || "").toLowerCase();
  if (VALID_MODES.has(h as RedactMode)) return h as RedactMode;
  const p = getPolicy(tenant).mode;
  if (p && VALID_MODES.has(p)) return p;
  return config.defaultMode;
}

// How much a mode protects: off forwards raw, reversible de-identifies, strip de-identifies
// and never restores. A caller header may move up this scale, never down.
const MODE_STRENGTH: Record<RedactMode, number> = { off: 0, reversible: 1, strip: 2 };

/**
 * A caller's X-Redact-Mode / X-Redact-Sets may only make redaction stricter than the
 * policy the operator set (tenant policy, else global config), unless header override is
 * allowed globally or for the tenant. Returns why the request loosens policy, or null.
 */
export function headerOverrideViolation(headers: Record<string, string>): string | null {
  const tenant = resolveTenant(headers);
  const pol = getPolicy(tenant);
  if (pol.allowHeaderOverride ?? config.allowHeaderOverride) return null;

  const h = (headers["x-redact-mode"] || "").toLowerCase();
  if (VALID_MODES.has(h as RedactMode)) {
    const floor = pol.mode && VALID_MODES.has(pol.mode) ? pol.mode : config.defaultMode;
    if (MODE_STRENGTH[h as RedactMode] < MODE_STRENGTH[floor])
      return `X-Redact-Mode: ${h} is weaker than the policy mode (${floor})`;
  }
  if (headers["x-redact-sets"]) {
    const asked = new Set(resolveSets(headers, tenant));
    const missing = (pol.activeSets ?? config.activeSets).filter((s) => !asked.has(s));
    if (missing.length) return `X-Redact-Sets drops policy set(s): ${missing.join(", ")}`;
  }
  return null;
}

function resolveSets(headers: Record<string, string>, tenant: string): RedactSet[] {
  const h = headers["x-redact-sets"];
  if (h) {
    const out = h
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter((s): s is RedactSet => ["pii", "phi", "pci", "secrets"].includes(s));
    if (out.length) return out;
  }
  return getPolicy(tenant).activeSets ?? config.activeSets;
}

/** The three redacted generation endpoints, keyed by canonical path. */
const GENERATION_ROUTES = new Map<string, [Provider, Dialect]>([
  ["/v1/chat/completions", ["openai", "chat"]],
  ["/v1/responses", ["openai", "responses"]],
  ["/v1/messages", ["anthropic", "messages"]],
]);

/**
 * The generation endpoint a request path can reach upstream, or null for any other path.
 * The path is forwarded as the caller sent it, and the upstream does not read those bytes
 * literally: fetch resolves "." and ".." segments (%2e forms too) and treats "\" as "/",
 * and a server may decode percent-escapes, ignore case, or drop a trailing or doubled
 * slash. Any of those can turn a spelling that is not literally a generation endpoint
 * (`/v1/chat/completions/`) into one, so the path is classified on the most lenient of
 * those readings; classifying on the literal bytes sent such a request down the verbatim
 * passthrough with its body unread. A sub-path (/v1/messages/count_tokens) is still not a
 * generation endpoint.
 */
export function generationRoute(bare: string): [Provider, Dialect] | null {
  let p = bare;
  try {
    p = decodeURIComponent(p);
  } catch {
    /* a malformed escape: classify the undecoded bytes */
  }
  const segs: string[] = [];
  for (const s of p.toLowerCase().split(/[\\/]+/)) {
    if (s === "" || s === ".") continue;
    if (s === "..") segs.pop();
    else segs.push(s);
  }
  return GENERATION_ROUTES.get("/" + segs.join("/")) ?? null;
}

export function normalize(
  path: string,
  body: any,
  headers: Record<string, string>,
): CanonicalRequest | null {
  // Sub-paths (e.g. /v1/messages/count_tokens) are NOT generation requests and take the
  // transparent-passthrough route instead; see generationRoute for what counts as a match.
  const bare = path.split("?")[0];
  const route = generationRoute(bare);
  if (!route || !body || typeof body !== "object") return null;
  const [provider, dialect] = route;

  const tenant = resolveTenant(headers);

  return {
    provider,
    dialect,
    model: body.model,
    tenant,
    mode: resolveMode(headers, tenant),
    activeSets: resolveSets(headers, tenant),
    stream: !!body.stream,
    raw: body,
    fwdHeaders: authHeaders(headers),
    path,
    bare,
    testFail: config.testHooks && headers["x-cordon-fail"] === "1",
  };
}

/** Auth + version headers that pass through to the provider verbatim. */
export function authHeaders(headers: Record<string, string>): Record<string, string> {
  const fwd: Record<string, string> = {};
  for (const h of ["authorization", "x-api-key", "anthropic-version", "anthropic-beta", "openai-organization"])
    if (headers[h]) fwd[h] = headers[h];
  return fwd;
}

/** The tenant a request's credentials alone give it: derived from the API key
 *  (TENANT_FROM_AUTH), else "public". */
function credentialTenant(headers: Record<string, string>): string {
  if (config.tenantFromAuth) {
    const auth = headers["authorization"] || headers["x-api-key"] || "";
    if (auth) return "auth:" + sha256(auth).slice(0, 16);
  }
  return "public";
}

/** Tenant resolution: X-Tenant only when TRUST_TENANT_HEADER is on (index.ts refuses a
 *  selection tenantSelectionViolation rejects before this is used), else the credential
 *  tenant. */
export function resolveTenant(headers: Record<string, string>): string {
  if (config.trustTenantHeader && headers["x-tenant"]) return headers["x-tenant"];
  return credentialTenant(headers);
}

/** Every policy knob a tenant resolves to, global config filling the unset ones. */
function effectivePolicy(tenant: string) {
  const p = getPolicy(tenant);
  return {
    mode: p.mode && VALID_MODES.has(p.mode) ? p.mode : config.defaultMode,
    activeSets: p.activeSets ?? config.activeSets,
    failMode: p.failMode ?? config.failMode,
    redactSystem: p.redactSystem ?? config.redactSystem,
    consistentPseudonyms: p.consistentPseudonyms ?? config.consistentPseudonyms,
    allowHeaderOverride: p.allowHeaderOverride ?? config.allowHeaderOverride,
  };
}

/**
 * With TRUST_TENANT_HEADER on, X-Tenant may only select a policy at least as strict as the
 * one the caller's credentials already give it, on every knob:
 *   mode                  off < reversible < strip
 *   activeSets            must include every set of the credential tenant
 *   failMode              open < closed
 *   redactSystem          false < true
 *   consistentPseudonyms  true < false (a stable token lets the upstream link one value
 *                         across requests; a per-request token does not)
 *   allowHeaderOverride   true < false
 *   upstream bases        must be identical: a residency route has no stricter direction
 * Returns why the selection loosens policy, or null. The header still picks the audit and
 * metrics label freely; that is the trust the operator grants by turning it on.
 */
export function tenantSelectionViolation(headers: Record<string, string>): string | null {
  const asked = headers["x-tenant"];
  if (!config.trustTenantHeader || !asked) return null;
  const home = credentialTenant(headers);
  if (asked === home) return null;
  const a = effectivePolicy(asked);
  const h = effectivePolicy(home);
  const looser: string[] = [];
  if (MODE_STRENGTH[a.mode] < MODE_STRENGTH[h.mode]) looser.push("mode");
  if (h.activeSets.some((s) => !a.activeSets.includes(s))) looser.push("activeSets");
  if (a.failMode === "open" && h.failMode !== "open") looser.push("failMode");
  if (!a.redactSystem && h.redactSystem) looser.push("redactSystem");
  if (a.consistentPseudonyms && !h.consistentPseudonyms) looser.push("consistentPseudonyms");
  if (a.allowHeaderOverride && !h.allowHeaderOverride) looser.push("allowHeaderOverride");
  if (baseFor("openai", asked) !== baseFor("openai", home) || baseFor("anthropic", asked) !== baseFor("anthropic", home))
    looser.push("upstreamOverride");
  return looser.length ? `X-Tenant selects a policy that is not at least as strict as this caller's own (${looser.join(", ")})` : null;
}

/** Upstream base for a provider, honouring a per-tenant data-residency override. */
export function baseFor(provider: Provider, tenant?: string): string {
  if (tenant) {
    const ov = getPolicy(tenant).upstreamOverride;
    if (ov?.[provider]) return ov[provider]!;
  }
  return provider === "openai" ? config.upstream.openai : config.upstream.anthropic;
}

/**
 * fetch with a deadline on the response HEADERS (UPSTREAM_TIMEOUT_MS). The timer is
 * cleared once headers arrive, so a long-running stream body is never cut off.
 */
async function upstreamFetch(url: string, init: RequestInit): Promise<Response> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(new UpstreamTimeout()), config.upstreamTimeoutMs);
  try {
    return await fetch(url, { ...init, signal: ac.signal });
  } finally {
    clearTimeout(timer);
  }
}

/** The provider did not answer within UPSTREAM_TIMEOUT_MS. */
export class UpstreamTimeout extends Error {
  constructor() {
    super("upstream timeout");
    this.name = "UpstreamTimeout";
  }
}

/** Generic upstream POST preserving the original path + auth passthrough. */
export async function forwardRaw(
  base: string,
  path: string,
  fwdHeaders: Record<string, string>,
  body: any,
): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/json", ...fwdHeaders };
  return upstreamFetch(base + path, { method: "POST", headers, body: JSON.stringify(body) });
}

/** Forward a (de-identified) body upstream. `bodyOverride` is the redacted copy. */
export function forwardUpstream(r: CanonicalRequest, bodyOverride?: any): Promise<Response> {
  return forwardRaw(baseFor(r.provider, r.tenant), r.path, r.fwdHeaders, bodyOverride ?? r.raw);
}

/**
 * Which provider base an unrecognized /v1/* path belongs to. Path prefix first
 * (e.g. /v1/messages/count_tokens → Anthropic), else infer from the auth style.
 */
export function passthroughBase(path: string, headers: Record<string, string>): string {
  if (path.startsWith("/v1/messages")) return config.upstream.anthropic;
  if (
    path.startsWith("/v1/chat") ||
    path.startsWith("/v1/responses") ||
    path.startsWith("/v1/embeddings") ||
    path.startsWith("/v1/completions")
  )
    return config.upstream.openai;
  return headers["x-api-key"] ? config.upstream.anthropic : config.upstream.openai;
}

/** Method-agnostic verbatim forward for paths cordon doesn't redact. */
export function forwardVerbatim(
  base: string,
  path: string,
  headers: Record<string, string>,
  method: string,
  body?: any,
): Promise<Response> {
  const fwd = authHeaders(headers);
  if (method === "GET" || body === undefined) return upstreamFetch(base + path, { method, headers: fwd });
  return upstreamFetch(base + path, {
    method,
    headers: { "content-type": "application/json", ...fwd },
    body: JSON.stringify(body),
  });
}
