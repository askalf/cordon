import { config } from "./config";
import { sha256 } from "./util";
import { getPolicy } from "./policy";
import type { CanonicalRequest, Provider, RedactMode, RedactSet } from "./types";

/**
 * A ProviderAdapter knows the wire dialect of one provider: how to read a text
 * delta off a streamed frame, and — the inverse cordon needs — how to synthesize a
 * text-carrying SSE frame from a (re-identified) text chunk.
 */
export interface ProviderAdapter {
  /** Read a streamed SSE `data:` payload. */
  parseDelta(data: string): { textDelta?: string; done: boolean };
  /** Build a provider-correct SSE frame carrying one assistant-text chunk. */
  frameFromText(text: string): string;
  /** Walk a non-streaming response body's assistant-text fields (for re-identify). */
  responseTextSlots(body: any): Array<{ get(): string; set(v: string): void }>;
}

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
  frameFromText(text) {
    return `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: text } }] })}\n\n`;
  },
  responseTextSlots(body) {
    const slots: Array<{ get(): string; set(v: string): void }> = [];
    for (const ch of body?.choices ?? []) {
      const msg = ch?.message;
      if (msg && typeof msg.content === "string") {
        slots.push({ get: () => msg.content, set: (v) => (msg.content = v) });
      } else if (msg && Array.isArray(msg.content)) {
        for (const part of msg.content)
          if (part?.type === "text" && typeof part.text === "string")
            slots.push({ get: () => part.text, set: (v) => (part.text = v) });
      }
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
  frameFromText(text) {
    const data = { type: "content_block_delta", index: 0, delta: { type: "text_delta", text } };
    return `event: content_block_delta\ndata: ${JSON.stringify(data)}\n\n`;
  },
  responseTextSlots(body) {
    const slots: Array<{ get(): string; set(v: string): void }> = [];
    for (const block of body?.content ?? [])
      if (block?.type === "text" && typeof block.text === "string")
        slots.push({ get: () => block.text, set: (v) => (block.text = v) });
    return slots;
  },
};

export const adapterFor = (p: Provider) => (p === "openai" ? openai : anthropic);

// ----------------------------- normalize: HTTP → CanonicalRequest -----------------------------

const VALID_MODES = new Set<RedactMode>(["reversible", "strip", "off"]);

function resolveMode(headers: Record<string, string>, tenant: string): RedactMode {
  const h = (headers["x-redact-mode"] || "").toLowerCase();
  if (VALID_MODES.has(h as RedactMode)) return h as RedactMode;
  const p = getPolicy(tenant).mode;
  if (p && VALID_MODES.has(p)) return p;
  return config.defaultMode;
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

export function normalize(
  path: string,
  body: any,
  headers: Record<string, string>,
): CanonicalRequest | null {
  // EXACT endpoint match — sub-paths (e.g. /v1/messages/count_tokens) are NOT
  // generation requests and must take the transparent-passthrough route instead.
  const bare = path.split("?")[0];
  const provider: Provider | null =
    bare === "/v1/chat/completions" ? "openai" : bare === "/v1/messages" ? "anthropic" : null;
  if (!provider || !body || typeof body !== "object") return null;

  const tenant = resolveTenant(headers);

  return {
    provider,
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

/** Tenant resolution: explicit X-Tenant, else (optionally) derived from the API key. */
export function resolveTenant(headers: Record<string, string>): string {
  if (headers["x-tenant"]) return headers["x-tenant"];
  if (config.tenantFromAuth) {
    const auth = headers["authorization"] || headers["x-api-key"] || "";
    if (auth) return "auth:" + sha256(auth).slice(0, 16);
  }
  return "public";
}

/** Upstream base for a provider, honouring a per-tenant data-residency override. */
export function baseFor(provider: Provider, tenant?: string): string {
  if (tenant) {
    const ov = getPolicy(tenant).upstreamOverride;
    if (ov?.[provider]) return ov[provider]!;
  }
  return provider === "openai" ? config.upstream.openai : config.upstream.anthropic;
}

/** Generic upstream POST preserving the original path + auth passthrough. */
export async function forwardRaw(
  base: string,
  path: string,
  fwdHeaders: Record<string, string>,
  body: any,
): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/json", ...fwdHeaders };
  return fetch(base + path, { method: "POST", headers, body: JSON.stringify(body) });
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
  if (path.startsWith("/v1/chat") || path.startsWith("/v1/embeddings") || path.startsWith("/v1/completions"))
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
  if (method === "GET" || body === undefined) return fetch(base + path, { method, headers: fwd });
  return fetch(base + path, {
    method,
    headers: { "content-type": "application/json", ...fwd },
    body: JSON.stringify(body),
  });
}
