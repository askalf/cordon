// Integration for known subjects: cordon (:8810) in front of the echo stub (:8900). Proves the
// model never sees a subject's identifiers, the reply comes back real, a request the egress
// check or the media rule refuses never reaches the stub, report-only forwards unchanged and
// says so, and receipts are served per ref with no values. Every person here is invented.
// Run with: node _test_subject_proxy.mjs
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const BASE = "http://localhost:8810";
const STUB = "http://localhost:8900";
const ADMIN = "secret";
let pass = 0, fail = 0;
const ok = (n, c, e = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"}  ${n}${e ? "   (" + e + ")" : ""}`); };

const reset = () => fetch(STUB + "/__reset");
const calls = async () => (await fetch(STUB + "/__calls")).json();
const keyTenant = (key) => "auth:" + createHash("sha256").update(key).digest("hex").slice(0, 16);
const setTenant = (patch) =>
  fetch(BASE + "/admin/tenant", { method: "POST", headers: { "content-type": "application/json", "x-admin-token": ADMIN }, body: JSON.stringify(patch) });
const enc = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const PERSON = { names: ["Marisol Quintero-Vance"], emails: ["mqvance77@example.com"], phones: ["404-555-0187"], addresses: ["1428 Elm Street, Decatur, GA"] };
const SUBJECT = (extra = {}) => enc({ ref: "case-int-1", subjects: [PERSON], ...extra });
const TEXT = "Marisol Quintero-Vance (mqvance77@example.com, 404.555.0187) lives at 1428 Elm St.";
const RAW = ["Marisol", "Quintero", "mqvance77", "555.0187", "555-0187", "1428 Elm"];
const post = (path, body, headers = {}, key = "test-key") =>
  fetch(BASE + path, {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01", ...headers },
    body: JSON.stringify(body),
  });
const aBody = (content, extra = {}) => ({ model: "claude-haiku-4-5", messages: [{ role: "user", content }], ...extra });
const seen = async () => JSON.stringify(await calls());
const leaked = (s) => RAW.filter((r) => s.includes(r));

(async () => {
  // ---- the model sees placeholders, the caller gets the real text back ----
  await reset();
  let res = await post("/v1/messages", aBody(TEXT), { "x-cordon-subject": SUBJECT() });
  let body = await res.json();
  let up = await seen();
  ok("subject: 200", res.status === 200, String(res.status));
  ok("subject: nothing identifying reached the model", leaked(up).length === 0, leaked(up).join(","));
  ok("subject: the model saw SUBJECT1 placeholders", /SUBJECT1_NAME/.test(up) && /SUBJECT1_ADDRESS/.test(up) && /SUBJECT1_PHONE/.test(up));
  ok("subject: the reply is restored for the caller", JSON.stringify(body).includes("Marisol Quintero-Vance") && JSON.stringify(body).includes("1428 Elm St"));
  ok("subject: the header is never forwarded", !/x-cordon-subject/i.test(up));
  const receipt = res.headers.get("x-cordon-receipt");
  ok("subject: a receipt header is returned", /^[0-9a-f]{64}$/.test(receipt ?? ""), receipt);

  // ---- Responses and chat dialects ----
  await reset();
  res = await post("/v1/responses", { model: "gpt-4o-mini", input: TEXT }, { "x-cordon-subject": SUBJECT() });
  up = await seen();
  ok("subject (Responses): nothing identifying reached the model", res.status === 200 && leaked(up).length === 0, `${res.status} ${leaked(up)}`);
  await reset();
  res = await post("/v1/chat/completions", { model: "gpt-4o-mini", messages: [{ role: "user", content: TEXT }] }, { "x-cordon-subject": SUBJECT() });
  up = await seen();
  ok("subject (chat): nothing identifying reached the model", res.status === 200 && leaked(up).length === 0, `${res.status} ${leaked(up)}`);

  // ---- streaming restores across frame splits ----
  await reset();
  res = await post("/v1/messages", aBody(TEXT, { stream: true }), { "x-cordon-subject": SUBJECT() });
  const streamed = await res.text();
  up = await seen();
  ok("subject (stream): nothing identifying reached the model", leaked(up).length === 0, leaked(up).join(","));
  ok("subject (stream): the caller's stream carries the real values", streamed.includes("Quintero-Vance") || streamed.replace(/[^A-Za-z]/g, "").includes("QuinteroVance"));

  // ---- refusals: upstream never called ----
  await reset();
  res = await post("/v1/messages", aBody(TEXT), { "x-cordon-subject": "%%%" });
  ok("bad header: 400", res.status === 400, String(res.status));
  ok("bad header: the stub was not called", (await calls()).total === 0);

  await reset();
  const img = [{ type: "text", text: TEXT }, { type: "image", source: { type: "base64", media_type: "image/png", data: "iVBORw0KGgo=" } }];
  res = await post("/v1/messages", aBody(img), { "x-cordon-subject": SUBJECT() });
  ok("media: an image with a subject is refused (422)", res.status === 422, String(res.status));
  ok("media: the stub was not called", (await calls()).total === 0);
  ok("media: the refusal names the stage", /at media/.test((await res.json().catch(() => ({}))).error ?? ""));

  await reset();
  res = await post("/v1/messages", aBody(img), { "x-cordon-subject": SUBJECT({ media: "allow" }) });
  ok("media: the header alone cannot allow media (the policy must too)", res.status === 422, String(res.status));
  await setTenant({ tenant: keyTenant("media-key"), subjectMedia: "allow" });
  await reset();
  res = await post("/v1/messages", aBody(img), { "x-cordon-subject": SUBJECT({ media: "allow" }) }, "media-key");
  ok("media: policy and header together allow it", res.status === 200, String(res.status));

  // ---- mask mode: identifiers painted over in the image, which is read again before it goes ----
  {
    const sharp = (await import("sharp")).default;
    const { createWorker } = await import("tesseract.js");
    const { createRequire } = await import("node:module");
    const { dirname, join } = await import("node:path");
    const require = createRequire(import.meta.url);
    const langPath = join(dirname(require.resolve("@tesseract.js-data/eng/package.json")), "4.0.0_best_int");
    const shotLines = ["Case notes", "Name: Marisol Quintero-Vance", "Email: mqvance77@example.com", "Phone: 404-555-0187", "Last login from Atlanta"];
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="900" height="300"><rect width="100%" height="100%" fill="#fff"/>${shotLines.map((l, i) => `<text x="30" y="${50 + i * 48}" font-family="Arial, DejaVu Sans, sans-serif" font-size="28" fill="#111">${l}</text>`).join("")}</svg>`;
    const shot = (await sharp(Buffer.from(svg)).png().toBuffer()).toString("base64");
    const ocr = await createWorker("eng", 1, { langPath, gzip: true, cacheMethod: "none", logger: () => {} });
    const readable = (await ocr.recognize(Buffer.from(shot, "base64"))).data.text;
    if (!/Quintero/.test(readable)) {
      console.log("SKIP  mask: this machine renders no readable text into the fixture (no fonts)");
    } else {
      await setTenant({ tenant: keyTenant("mask-key"), subjectMedia: "mask" });
      await reset();
      const part = [{ type: "text", text: "what does this show?" }, { type: "image", source: { type: "base64", media_type: "image/png", data: shot } }];
      res = await post("/v1/messages", aBody(part), { "x-cordon-subject": SUBJECT() }, "mask-key");
      const c = await calls();
      const sentImg = c.bodies?.[0]?.body?.messages?.[0]?.content?.find?.((b) => b.type === "image");
      ok("mask: 200", res.status === 200, String(res.status));
      ok("mask: an image went upstream", typeof sentImg?.source?.data === "string" && sentImg.source.data !== shot);
      const seenText = sentImg ? (await ocr.recognize(Buffer.from(sentImg.source.data, "base64"))).data.text : "";
      ok("mask: the image the model got shows no identifier", !/Marisol|Quintero|mqvance|555/i.test(seenText), seenText.replace(/\s+/g, " "));
      ok("mask: the rest of the image is still readable", /Atlanta/.test(seenText), seenText.replace(/\s+/g, " "));
      
      await reset();
      const pdf = [{ type: "document", source: { type: "base64", media_type: "application/pdf", data: "JVBERi0xLjQK" } }];
      res = await post("/v1/messages", aBody(pdf), { "x-cordon-subject": SUBJECT() }, "mask-key");
      ok("mask: a PDF cannot be read here and is refused", res.status === 422 && (await calls()).total === 0, String(res.status));
      res = await post("/v1/messages", aBody([{ type: "image", source: { type: "url", url: "https://img.example/x.png" } }]), { "x-cordon-subject": SUBJECT() }, "mask-key");
      ok("mask: an image by URL is refused", res.status === 422, String(res.status));
      res = await post("/v1/messages", aBody(part), { "x-cordon-subject": SUBJECT({ media: "block" }) }, "mask-key");
      ok("mask: the header can tighten mask to block", res.status === 422, String(res.status));
    }
    await ocr.terminate();
  }

  // The system prompt is not redacted for this tenant, so the name there survives redaction:
  // the egress check must catch it and refuse.
  await setTenant({ tenant: keyTenant("sys-key"), redactSystem: false });
  await reset();
  res = await post("/v1/messages", aBody("hello", { system: "You are helping Marisol Quintero-Vance." }), { "x-cordon-subject": SUBJECT() }, "sys-key");
  const refusal = await res.json().catch(() => ({}));
  ok("egress: an identifier left in the body is refused (422)", res.status === 422, String(res.status));
  ok("egress: the stub was not called", (await calls()).total === 0);
  ok("egress: the refusal names the kind, not the value", /SUBJECT1_NAME/.test(refusal.detail ?? "") && !/Marisol/.test(JSON.stringify(refusal)), JSON.stringify(refusal));

  await setTenant({ tenant: keyTenant("off-key"), mode: "off" });
  await reset();
  res = await post("/v1/messages", aBody(TEXT), { "x-cordon-subject": SUBJECT() }, "off-key");
  ok("mode off: a subject request is refused, not passed through", res.status === 422 && (await calls()).total === 0, String(res.status));

  await setTenant({ tenant: keyTenant("req-key"), requireSubject: true });
  await reset();
  res = await post("/v1/messages", aBody("no subject here"), {}, "req-key");
  ok("requireSubject: a request without the header is refused (400)", res.status === 400 && (await calls()).total === 0, String(res.status));

  // ---- report only: forwarded unchanged, verdict in headers and the audit ----
  await setTenant({ tenant: keyTenant("report-key"), reportOnly: true });
  await reset();
  res = await post("/v1/messages", aBody(TEXT), { "x-cordon-subject": SUBJECT() }, "report-key");
  up = await seen();
  ok("report only: 200", res.status === 200, String(res.status));
  ok("report only: the request went out unchanged", up.includes("Marisol Quintero-Vance"));
  ok("report only: the verdict is in X-Cordon-Report", /redact=\d+; egress=verified/.test(res.headers.get("x-cordon-report") ?? ""), res.headers.get("x-cordon-report"));

  // ---- receipts and the audit log ----
  res = await fetch(BASE + "/admin/receipts?ref=case-int-1", { headers: { "x-admin-token": ADMIN } });
  const rc = await res.json();
  ok("receipts: served for the ref", res.status === 200 && Array.isArray(rc.receipts) && rc.receipts.length >= 4, `${res.status} ${rc.receipts?.length}`);
  ok("receipts: the chain verified first", rc.chain?.ok === true);
  ok("receipts: the header's receipt is among them", rc.receipts.some((r) => r.hash === receipt));
  ok("receipts: refusals are recorded with their stage", rc.receipts.some((r) => r.egress === "media") && rc.receipts.some((r) => r.egress === "egress"));
  ok("receipts: report-only requests are marked", rc.receipts.some((r) => r.report === true));
  ok("receipts: the ref itself is not stored", !JSON.stringify(rc.receipts).includes("case-int-1"));
  res = await fetch(BASE + "/admin/receipts", { headers: { "x-admin-token": ADMIN } });
  ok("receipts: no ref is a 400", res.status === 400);
  res = await fetch(BASE + "/admin/receipts?ref=case-int-1");
  ok("receipts: admin token required", res.status === 403);
  const log = readFileSync("./_audit_test.jsonl", "utf8");
  ok("audit: no subject value is ever written", leaked(log).length === 0 && !log.includes("case-int-1"), leaked(log).join(","));
  res = await fetch(BASE + "/admin/audit/verify", { headers: { "x-admin-token": ADMIN } });
  ok("audit: the chain still verifies with the new fields", (await res.json()).ok === true);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
