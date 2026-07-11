// Integration: cordon (:8810) in front of the echo stub (:8900). Proves the model
// never sees raw PII, reversible restores it, strip/off behave, fail-closed blocks,
// and the audit log verifies and holds no values. Run with: node _test_proxy.mjs
import { readFileSync } from "node:fs";

const BASE = "http://localhost:8810";
const BASE2 = "http://localhost:8811"; // secret-less instance (pseudonym-without-secret must fail closed)
const STUB = "http://localhost:8900";
const ADMIN = "secret";
const PII = "email john@acme.com about card 4012888888881881";

let pass = 0, fail = 0;
const ok = (n, c, e = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"}  ${n}${e ? "   (" + e + ")" : ""}`); };

const reset = () => fetch(STUB + "/__reset");
const calls = async () => (await fetch(STUB + "/__calls")).json();
const postTo = (base) => (path, body, headers = {}) =>
  fetch(base + path, {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": "test-key", "anthropic-version": "2023-06-01", ...headers },
    body: JSON.stringify(body),
  });
const post = postTo(BASE);
const post2 = postTo(BASE2);
const aBody = (text, extra = {}) => ({ model: "claude-haiku-4-5", messages: [{ role: "user", content: text }], ...extra });
const oBody = (text, extra = {}) => ({ model: "gpt-4o-mini", messages: [{ role: "user", content: text }], ...extra });
const setTenantOn = (base) => (patch) =>
  fetch(base + "/admin/tenant", { method: "POST", headers: { "content-type": "application/json", "x-admin-token": ADMIN }, body: JSON.stringify(patch) });
const setTenant = setTenantOn(BASE);
const setTenant2 = setTenantOn(BASE2);

(async () => {
  // ---- reversible (Anthropic) ----
  await reset();
  let res = await post("/v1/messages", aBody(PII));
  let text = (await res.json())?.content?.[0]?.text || "";
  ok("reversible/anthropic: email restored in reply", text.includes("john@acme.com") && !text.includes("<EMAIL"));
  ok("reversible/anthropic: card restored in reply", text.includes("4012888888881881"));
  ok("reversible/anthropic: X-Redacted >= 2", Number(res.headers.get("x-redacted")) >= 2, res.headers.get("x-redacted"));
  ok("reversible/anthropic: X-Redacted-Types lists EMAIL", (res.headers.get("x-redacted-types") || "").includes("EMAIL"));
  let sent = JSON.stringify(await calls());
  ok("reversible/anthropic: upstream saw placeholder", /<EMAIL_[0-9A-F]+_1>/.test(sent));
  ok("reversible/anthropic: upstream NEVER saw raw email", !sent.includes("john@acme.com"));
  ok("reversible/anthropic: upstream NEVER saw raw card", !sent.includes("4012888888881881"));

  // ---- reversible (OpenAI) ----
  await reset();
  res = await post("/v1/chat/completions", oBody(PII));
  text = (await res.json())?.choices?.[0]?.message?.content || "";
  ok("reversible/openai: email restored in reply", text.includes("john@acme.com") && !text.includes("<EMAIL"));
  sent = JSON.stringify(await calls());
  ok("reversible/openai: upstream NEVER saw raw PII", !sent.includes("john@acme.com") && !sent.includes("4012888888881881"));

  // ---- placeholder-collision resistance: a caller's own <EMAIL_1> literal is never
  //      rewritten to a real value on the way back (issue #19) ----
  await reset();
  {
    const q = "in our redaction format what does <EMAIL_1> mean? also email real@acme.com";
    res = await post("/v1/messages", aBody(q));
    text = (await res.json())?.content?.[0]?.text || "";
    ok("collision: caller's literal <EMAIL_1> returned unchanged", text.includes("<EMAIL_1>"), text);
    ok("collision: the real email is still restored", text.includes("real@acme.com"), text);
    sent = JSON.stringify(await calls());
    ok("collision: upstream never saw the raw email", !sent.includes("real@acme.com"));
  }

  // ---- strip ----
  await reset();
  res = await post("/v1/messages", aBody(PII), { "x-redact-mode": "strip" });
  text = (await res.json())?.content?.[0]?.text || "";
  ok("strip: placeholders persist (not restored)", text.includes("[EMAIL]") && !text.includes("john@acme.com"));
  ok("strip: X-Redact-Mode echoed", res.headers.get("x-redact-mode") === "strip");
  sent = JSON.stringify(await calls());
  ok("strip: upstream saw [EMAIL], not raw", sent.includes("[EMAIL]") && !sent.includes("john@acme.com"));

  // ---- off (passthrough) ----
  await reset();
  res = await post("/v1/messages", aBody(PII), { "x-redact-mode": "off" });
  text = (await res.json())?.content?.[0]?.text || "";
  ok("off: reply echoes raw (nothing redacted)", text.includes("john@acme.com"));
  ok("off: X-Redacted is 0", res.headers.get("x-redacted") === "0");
  sent = JSON.stringify(await calls());
  ok("off: upstream saw RAW (verbatim passthrough)", sent.includes("john@acme.com"));

  // ---- fail-closed ----
  await reset();
  res = await post("/v1/messages", aBody(PII), { "x-cordon-fail": "1" });
  ok("fail-closed: status 422", res.status === 422);
  ok("fail-closed: upstream NOT called", (await calls()).total === 0);

  // ---- X-Redact-Sets: unknown token rejected (a typo must NOT silently drop a set) ----
  await reset();
  res = await post("/v1/messages", aBody(PII), { "x-redact-sets": "pii,scerets" });
  ok("unknown set: rejected with 400", res.status === 400, String(res.status));
  ok("unknown set: error names the bad token", JSON.stringify(await res.json().catch(() => ({}))).includes("scerets"));
  ok("unknown set: upstream NOT called (PII never forwarded)", (await calls()).total === 0);
  await reset();
  res = await post("/v1/messages", aBody(PII), { "x-redact-sets": "pii,pci" });
  ok("valid sets: accepted (200, not over-rejected)", res.status === 200, String(res.status));

  // ---- passthrough (count_tokens) ----
  await reset();
  res = await post("/v1/messages/count_tokens", aBody("hello"));
  ok("passthrough: count_tokens forwarded verbatim", (await res.json())?.input_tokens === 42);
  ok("passthrough: X-Redacted 0", res.headers.get("x-redacted") === "0");

  // ---- admin auth ----
  ok("admin: 403 without token", (await fetch(BASE + "/admin/stats")).status === 403);
  ok("admin: 200 with token", (await fetch(BASE + "/admin/stats", { headers: { "x-admin-token": ADMIN } })).status === 200);

  // ---- admin activeSets validation (a typo'd set is rejected, not silently dropped) ----
  ok("admin: unknown activeSet rejected (400)", (await setTenant({ tenant: "t1", activeSets: ["pii", "scerets"] })).status === 400);
  ok("admin: valid activeSets accepted (200)", (await setTenant({ tenant: "t2", activeSets: ["pii", "pci"] })).status === 200);

  // ---- consistent pseudonyms via tenant policy ----
  await setTenant({ tenant: "acme", consistentPseudonyms: true, mode: "reversible" });
  await reset();
  await post("/v1/messages", aBody("mail john@acme.com"), { "x-tenant": "acme" });
  await post("/v1/messages", aBody("again john@acme.com"), { "x-tenant": "acme" });
  {
    const bodies = (await calls()).bodies;
    const t1 = bodies[0]?.body?.messages?.[0]?.content?.match(/<EMAIL_[0-9A-F]{8}>/)?.[0];
    const t2 = bodies[1]?.body?.messages?.[0]?.content?.match(/<EMAIL_[0-9A-F]{8}>/)?.[0];
    ok("pseudonym: stable token across requests", !!t1 && t1 === t2, `${t1} vs ${t2}`);
  }

  // ---- consistent pseudonyms WITHOUT an adequate secret must fail closed (issue #18) ----
  // :8811 runs with an empty TENANT_SECRET and no ALLOW_WEAK_PSEUDONYM_SECRET escape hatch,
  // so a tenant that turns on consistentPseudonyms there can't mint guessable tokens.
  await reset();
  await setTenant2({ tenant: "leaky", consistentPseudonyms: true, mode: "reversible" });
  res = await post2("/v1/messages", aBody("mail john@acme.com"), { "x-tenant": "leaky" });
  ok("pseudonym-no-secret: fails closed (422)", res.status === 422, String(res.status));
  ok("pseudonym-no-secret: upstream NOT called (PII never forwarded)", (await calls()).total === 0);
  ok("pseudonym-no-secret: error names the pseudonym-secret stage",
    JSON.stringify(await res.json().catch(() => ({}))).includes("pseudonym-secret"));
  // a normal (non-pseudonym) request on the same instance is unaffected
  await reset();
  res = await post2("/v1/messages", aBody("mail bob@x.io"));
  ok("pseudonym-no-secret: non-pseudonym request still works (200)", res.status === 200, String(res.status));

  // ---- data-residency upstream override ----
  await setTenant({ tenant: "eu", upstreamOverride: { anthropic: "http://127.0.0.1:1" } });
  res = await post("/v1/messages", aBody("hi jane@corp.io"), { "x-tenant": "eu" });
  ok("residency: override routes away from stub (502)", res.status === 502, String(res.status));

  // ---- audit chain + no values ----
  const v = await (await fetch(BASE + "/admin/audit/verify", { headers: { "x-admin-token": ADMIN } })).json();
  ok("audit: chain verifies", v.ok === true && v.records > 0, JSON.stringify(v));
  const log = readFileSync("./_audit_test.jsonl", "utf8");
  ok("audit: records carry entity types", log.includes("EMAIL"));
  ok("audit: log contains NO raw email", !log.includes("john@acme.com"));
  ok("audit: log contains NO raw card", !log.includes("4012888888881881"));
  ok("audit: log contains NO raw jane", !log.includes("jane@corp.io"));

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
