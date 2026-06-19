import Fastify from "fastify";
import { normalize, passthroughBase, forwardVerbatim } from "./providers";
import { handle } from "./proxy";
import { config } from "./config";
import { metrics } from "./metrics";
import { setPolicy, allPolicies } from "./policy";
import { audit } from "./audit";
import { dashboardHtml } from "./dashboard";
import type { RedactMode, RedactSet } from "./types";

const app = Fastify({ logger: false, bodyLimit: 16 * 1024 * 1024 });

// Default Fastify 400s a JSON POST with an empty body; admin endpoints take no body,
// so treat empty as undefined instead.
app.addContentTypeParser("application/json", { parseAs: "string" }, (_req, body, done) => {
  if (!body) return done(null, undefined);
  try {
    done(null, JSON.parse(body as string));
  } catch (e) {
    done(e as Error, undefined);
  }
});

app.get("/healthz", async () => ({ ok: true, brand: config.brand }));
app.get("/dashboard", async (_req, reply) => reply.type("text/html").send(dashboardHtml));
app.get("/metrics", async () => metrics.snapshot());
app.get("/metrics.prom", async (_req, reply) => reply.type("text/plain").send(metrics.prometheus()));

// ---- admin API ----
function adminOk(req: any, reply: any): boolean {
  if (!config.admin.token) return true; // dev: open
  if (req.headers["x-admin-token"] !== config.admin.token) {
    reply.code(403).send({ error: `${config.brand}: invalid admin token` });
    return false;
  }
  return true;
}

app.get("/admin/stats", async (req, reply) => {
  if (!adminOk(req, reply)) return reply;
  return { metrics: metrics.report(), tenants: allPolicies() };
});

// Tamper check on the hash-chained audit log.
app.get("/admin/audit/verify", async (req, reply) => {
  if (!adminOk(req, reply)) return reply;
  return audit.verify();
});

const VALID_MODES = new Set<RedactMode>(["reversible", "strip", "off"]);
const VALID_SETS = new Set<RedactSet>(["pii", "phi", "pci", "secrets"]);

// Set tenant policy. Body: { tenant, mode?, activeSets?, failMode?, consistentPseudonyms?, upstreamOverride? }
app.post("/admin/tenant", async (req, reply) => {
  if (!adminOk(req, reply)) return reply;
  const b = (req.body as any) ?? {};
  if (!b.tenant) {
    reply.code(400);
    return { error: `${config.brand}: \`tenant\` required` };
  }
  const patch: any = {};
  if (b.mode !== undefined) {
    if (!VALID_MODES.has(b.mode)) {
      reply.code(400);
      return { error: `${config.brand}: invalid mode (reversible|strip|off)` };
    }
    patch.mode = b.mode;
  }
  if (b.activeSets !== undefined) {
    const sets = (Array.isArray(b.activeSets) ? b.activeSets : []).filter((s: any) => VALID_SETS.has(s));
    patch.activeSets = sets;
  }
  if (b.failMode === "closed" || b.failMode === "open") patch.failMode = b.failMode;
  if (typeof b.consistentPseudonyms === "boolean") patch.consistentPseudonyms = b.consistentPseudonyms;
  if (b.upstreamOverride && typeof b.upstreamOverride === "object") patch.upstreamOverride = b.upstreamOverride;
  return setPolicy(b.tenant, patch);
});

// ---- the proxy: OpenAI + Anthropic ----
function safeError(reply: any, e: unknown) {
  try {
    reply.raw.statusCode = 502;
    reply.raw.setHeader("content-type", "application/json");
    reply.raw.end(JSON.stringify({ error: `${config.brand} upstream error: ${String(e)}` }));
  } catch {
    /* socket already gone */
  }
}

/** Headers lower-cased; path split from query (preserved verbatim on every forward). */
function reqParts(req: any) {
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers))
    headers[k.toLowerCase()] = Array.isArray(v) ? v.join(",") : String(v ?? "");
  const path = req.raw.url ?? "";
  const i = path.indexOf("?");
  return { headers, bare: i === -1 ? path : path.slice(0, i), path };
}

/** Verbatim forward for /v1/* paths cordon doesn't redact (count_tokens, models, …). */
async function passthroughUnknown(req: any, reply: any, method: string) {
  const { headers, bare, path } = reqParts(req);
  reply.hijack();
  const res = reply.raw as any;
  try {
    const up = await forwardVerbatim(passthroughBase(bare, headers), path, headers, method, req.body);
    metrics.bypass("path");
    res.statusCode = up.status;
    res.setHeader("X-Redacted", "0");
    res.setHeader("content-type", up.headers.get("content-type") ?? "application/json");
    if (up.body) {
      const reader = (up.body as any).getReader();
      const dec = new TextDecoder();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        res.write(dec.decode(value, { stream: true }));
      }
    }
    res.end();
  } catch (e) {
    safeError(reply, e);
  }
}

app.post("/v1/*", async (req, reply) => {
  const { headers, bare, path } = reqParts(req);

  // Only the two generation endpoints are redacted; everything else (count_tokens,
  // embeddings, …) forwards verbatim so it is never normalize-mangled.
  if (bare !== "/v1/chat/completions" && bare !== "/v1/messages") {
    return passthroughUnknown(req, reply, "POST");
  }

  // Normalize first so a bad request 400s cleanly (pre-hijack).
  const creq = normalize(path, req.body, headers);
  if (!creq || !creq.model) {
    reply.code(400);
    return { error: `${config.brand}: unsupported route or missing \`model\`` };
  }
  reply.hijack();
  try {
    await handle(creq, reply.raw as any);
  } catch (e) {
    safeError(reply, e);
  }
});

// GET /v1/* (models listing etc.) — transparent passthrough.
app.get("/v1/*", async (req, reply) => passthroughUnknown(req, reply, "GET"));

app.listen({ port: config.port, host: "0.0.0.0" }).then(() => {
  console.log(
    `${config.brand} listening on :${config.port}  ` +
      `[mode=${config.defaultMode}, fail=${config.failMode}, sets=${config.activeSets.join("+")}` +
      `${config.consistentPseudonyms ? ", pseudonyms=consistent" : ""}` +
      `${config.tenantFromAuth ? ", tenant=from-auth" : ""}]`,
  );
  if (!config.admin.token) console.warn("[admin] ADMIN_TOKEN unset — /admin/* endpoints are OPEN (dev only)");
  if (config.consistentPseudonyms && !config.tenantSecret)
    console.warn("[pseudonyms] CONSISTENT_PSEUDONYMS=true but TENANT_SECRET unset — tokens use a weak default key");
  if (config.failMode === "open")
    console.warn("[fail] FAIL_MODE=open — a redaction error will forward RAW PII upstream (dev only)");
});
