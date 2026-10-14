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

  // An image inside a document's content source is media like any other image part.
  await reset();
  const docImg = [{ type: "document", source: { type: "content", content: [{ type: "text", text: "attached" }, { type: "image", source: { type: "base64", media_type: "image/png", data: "iVBORw0KGgo=" } }] } }];
  res = await post("/v1/messages", aBody(docImg), { "x-cordon-subject": SUBJECT() });
  ok("media: an image inside a content-source document is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));

  // An image inside an MCP tool result is media like any other image part.
  await reset();
  const mcpImg = [{ type: "mcp_tool_result", tool_use_id: "mcptoolu_1", content: [{ type: "text", text: "screenshot" }, { type: "image", source: { type: "base64", media_type: "image/png", data: "iVBORw0KGgo=" } }] }];
  res = await post("/v1/messages", aBody(mcpImg), { "x-cordon-subject": SUBJECT() });
  ok("media: an image inside an MCP tool result is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));

  await reset();
  res = await post("/v1/messages", aBody(img), { "x-cordon-subject": SUBJECT({ media: "allow" }) });
  ok("media: the header alone cannot allow media (the policy must too)", res.status === 422, String(res.status));
  await setTenant({ tenant: keyTenant("media-key"), subjectMedia: "allow" });
  await reset();
  res = await post("/v1/messages", aBody(img), { "x-cordon-subject": SUBJECT({ media: "allow" }) }, "media-key");
  ok("media: policy and header together allow it", res.status === 200, String(res.status));

  // A tool input shaped like an image is tool data, not media: allowing media does not exempt it.
  await reset();
  res = await post("/v1/messages", {
    model: "claude-haiku-4-5",
    messages: [
      { role: "user", content: "look this up" },
      { role: "assistant", content: [{ type: "tool_use", id: "t1", name: "lookup", input: { type: "image", data: "m a r i s o l q u i n t e r o v a n c e" } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: "no match" }] },
    ],
  }, { "x-cordon-subject": SUBJECT({ media: "allow" }) }, "media-key");
  ok("media: a media-shaped tool input is checked and refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));

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

      // The same image inside a document's content source is masked before it goes.
      await reset();
      const docPart = [{ type: "document", source: { type: "content", content: [{ type: "text", text: "what does this show?" }, { type: "image", source: { type: "base64", media_type: "image/png", data: shot } }] } }];
      res = await post("/v1/messages", aBody(docPart), { "x-cordon-subject": SUBJECT() }, "mask-key");
      const docSent = (await calls()).bodies?.[0]?.body?.messages?.[0]?.content?.[0]?.source?.content?.find?.((b) => b.type === "image");
      ok("mask: an image inside a content-source document is masked", res.status === 200 && typeof docSent?.source?.data === "string" && docSent.source.data !== shot, String(res.status));
      const docText = docSent ? (await ocr.recognize(Buffer.from(docSent.source.data, "base64"))).data.text : "";
      ok("mask: the document's image the model got shows no identifier", !/Marisol|Quintero|mqvance|555/i.test(docText), docText.replace(/\s+/g, " "));

      // The same image inside an MCP tool result is masked before it goes.
      await reset();
      const mcpPart = [{ type: "mcp_tool_result", tool_use_id: "mcptoolu_1", content: [{ type: "image", source: { type: "base64", media_type: "image/png", data: shot } }] }];
      res = await post("/v1/messages", aBody(mcpPart), { "x-cordon-subject": SUBJECT() }, "mask-key");
      const mcpSent = (await calls()).bodies?.[0]?.body?.messages?.[0]?.content?.[0]?.content?.find?.((b) => b.type === "image");
      ok("mask: an image inside an MCP tool result is masked", res.status === 200 && typeof mcpSent?.source?.data === "string" && mcpSent.source.data !== shot, String(res.status));
      const mcpText = mcpSent ? (await ocr.recognize(Buffer.from(mcpSent.source.data, "base64"))).data.text : "";
      ok("mask: the MCP tool result's image the model got shows no identifier", !/Marisol|Quintero|mqvance|555/i.test(mcpText), mcpText.replace(/\s+/g, " "));

      // Tool input shaped like media is tool data: neither refused as media nor rewritten.
      await reset();
      const toolInput = { type: "file", name: "notes", thumb: { type: "image", source: { type: "base64", media_type: "image/png", data: "iVBORw0KGgo=" } } };
      res = await post("/v1/messages", {
        model: "claude-haiku-4-5",
        messages: [
          { role: "user", content: "save my notes" },
          { role: "assistant", content: [{ type: "tool_use", id: "t1", name: "save", input: toolInput }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: "saved" }, ...part] },
        ],
      }, { "x-cordon-subject": SUBJECT() }, "mask-key");
      const toolSent = (await calls()).bodies?.[0]?.body?.messages?.[1]?.content?.[0]?.input;
      ok("mask: media-shaped tool input is not refused as media", res.status === 200, String(res.status));
      ok("mask: media-shaped tool input is not rewritten", JSON.stringify(toolSent) === JSON.stringify(toolInput));
      
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

  // A payload-looking key outside any media part is ordinary text: read, and refused here
  // because Responses metadata is not redacted.
  await reset();
  res = await post("/v1/responses", { model: "gpt-4o-mini", input: "hello", metadata: { result: "Marisol Quintero-Vance", data: "data:x" } }, { "x-cordon-subject": SUBJECT() });
  ok("egress: a declared name in metadata.result is refused, not skipped", res.status === 422 && (await calls()).total === 0, String(res.status));
  // A declared ID sent as a JSON number in exponent form, in a field redaction leaves alone.
  await reset();
  res = await post("/v1/responses", { model: "gpt-4o-mini", input: "hello", metadata: { account: 1e21 } }, { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ ids: ["1000000000000000000000"] }] }) });
  ok("egress: an exponent-form numeric ID in metadata is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  // The same for an ID longer than the default number expansion, as a number and in a string.
  const longId = enc({ ref: "case-int-1", subjects: [{ ids: ["1" + "0".repeat(40)] }] });
  await reset();
  res = await post("/v1/responses", { model: "gpt-4o-mini", input: "hello", metadata: { account: 1e40 } }, { "x-cordon-subject": longId });
  ok("egress: a 41-digit ID as 1e40 in metadata is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/responses", { model: "gpt-4o-mini", input: "hello", metadata: { note: "acct 1e40" } }, { "x-cordon-subject": longId });
  ok("egress: a 41-digit ID as 1e40 in an unredacted string is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  for (const note of ["acct \uff11\uff45\uff14\uff10", "acct 1\u200be\u200d40", "acct \uff11\u2060\uff45\ufeff\uff14\uff10"]) {
    await reset();
    res = await post("/v1/responses", { model: "gpt-4o-mini", input: "hello", metadata: { note } }, { "x-cordon-subject": longId });
    ok(`egress: a 41-digit ID as 1e40 in full-width or zero-width-split form is refused, upstream never called: ${JSON.stringify(note)}`, res.status === 422 && (await calls()).total === 0, String(res.status));
  }
  // The same exponent spellings as a metadata key rather than a value.
  for (const key of ["1e40", "\uff11\uff45\uff14\uff10", "1\u200be\u200d40", "\uff11\u2060\uff45\ufeff\uff14\uff10"]) {
    await reset();
    res = await post("/v1/responses", { model: "gpt-4o-mini", input: "hello", metadata: { [key]: "x" } }, { "x-cordon-subject": longId });
    ok(`egress: a 41-digit ID as 1e40 in a metadata key is refused, upstream never called: ${JSON.stringify(key)}`, res.status === 422 && (await calls()).total === 0, String(res.status));
  }
  // A declared literal that is also an API enum word is read outside the enum fields.
  await reset();
  res = await post("/v1/responses", { model: "gpt-4o-mini", input: "hello", instructions: "high" }, { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ other: ["high"] }] }) }, "sys-key");
  ok("egress: an enum-word literal in unredacted instructions is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  // A declared literal spelled like a placeholder type, inside placeholder-shaped text the
  // caller wrote in unredacted instructions: read as written, not taken for a minted token.
  for (const instructions of ["Client code: [EMAIL]", "Client code: <EMAIL_1A2B3C_1>"]) {
    await reset();
    res = await post("/v1/responses", { model: "gpt-4o-mini", input: "hello", instructions }, { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ other: ["EMAIL"] }] }) }, "sys-key");
    ok(`egress: a declared literal in caller placeholder text is refused, upstream never called: ${instructions}`, res.status === 422 && (await calls()).total === 0, String(res.status));
  }
  await reset();
  res = await post("/v1/responses", { model: "gpt-4o-mini", input: "hello", metadata: { note: "high" } }, { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ other: ["high"] }] }) });
  ok("egress: an enum-word literal in metadata is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/responses", { model: "gpt-4o-mini", input: "hello", metadata: { detail: "high" } }, { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ other: ["high"] }] }) });
  ok("egress: an enum-word literal under an enum-named metadata key is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/responses", { model: "gpt-4o-mini", input: "hello", metadata: { name: "x" } }, { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ names: ["Name Bdeqnsk"] }] }) });
  ok("egress: a caller metadata key named like a protocol key is read and refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  // A stored prompt's variables carry input parts: an image there is media like any other.
  const promptImage = { model: "gpt-4o-mini", input: "describe it", prompt: { id: "pmpt_1", variables: { photo: { type: "input_image", image_url: "https://example.com/p.jpg" } } } };
  await reset();
  res = await post("/v1/responses", promptImage, { "x-cordon-subject": SUBJECT() });
  ok("media: an image in a prompt variable is refused under block, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await setTenant({ tenant: keyTenant("mask-key"), subjectMedia: "mask" });
  await reset();
  res = await post("/v1/responses", promptImage, { "x-cordon-subject": SUBJECT({ media: "mask" }) }, "mask-key");
  ok("media: a URL image in a prompt variable is refused under mask, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  // Digits spread wider than detection reaches are still caught on the way out.
  await reset();
  res = await post("/v1/messages", aBody("call 4    0    4    5    5    5    0    1    8    7"), { "x-cordon-subject": SUBJECT() });
  up = await seen();
  ok("phone: four spaces between digits is redacted", res.status === 200 && !/4\s+0\s+4\s+5/.test(up), String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("call " + "4045550187".split("").join(" ".repeat(12))), { "x-cordon-subject": SUBJECT() });
  ok("phone: twelve spaces between digits is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  // A leading country code attached and the rest spread wider than detection reaches, in
  // Responses metadata, which redaction leaves; for a phone declared plain and with +1.
  for (const phones of [["404-555-0187"], ["+1 404 555 0187"]]) {
    await reset();
    res = await post("/v1/responses", { model: "gpt-4o-mini", input: "hello", metadata: { note: "1404" + "5550187".split("").map((d) => " ".repeat(12) + d).join("") } }, { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ phones }] }) });
    ok(`phone: an attached leading 1 with wide separators in metadata is refused, upstream never called: ${phones[0]}`, res.status === 422 && (await calls()).total === 0, String(res.status));
  }
  await reset();
  res = await post("/v1/messages", aBody("acct " + "1234".split("").join(" ".repeat(12))), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ ids: ["1234"] }] }) });
  ok("id: a short ID with twelve spaces between digits is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("profile: a b c d"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ handles: ["@abcd"] }] }) });
  ok("handle: a short handle spaced out is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("code z q 9 x 7"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ other: ["zq9x7"] }] }) });
  ok("other: a short literal spaced out is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("surname C a r d"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ names: ["Lena Card"] }] }) });
  ok("name: a spaced-out surname that is also a field word is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("Name Bdeqnsk asked about the lookup tool"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ names: ["Name Bdeqnsk"] }] }) });
  ok("name: a field-word name redacts and forwards a clean body", res.status === 200 && (await calls()).total === 1, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("handle a b c"),{ "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ handles: ["@ab-c"] }] }) });
  ok("handle: a punctuated short handle spaced out is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("ref x y z"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ other: ["xy-z"] }] }) });
  ok("other: a punctuated short literal spaced out is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("see abcdefgh, a b x c d and abxcd"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ handles: ["@abcd"] }] }) });
  ok("handle: longer or different words beside a short handle are forwarded", res.status === 200 && (await calls()).total === 1, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("signed by Grace, W. today"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ names: ["Will Grace"] }] }) });
  up = await seen();
  ok("name: surname-first initial of a common-word name never reaches upstream", res.status === 200 && !/Grace, W/.test(up), `${res.status} ${up.slice(0, 300)}`);
  await reset();
  res = await post("/v1/messages", aBody("w i l l h e n r y g r a c e"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ names: ["Will Henry Grace"] }] }) });
  ok("name: a spaced-out three-part name is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("w . h . g r a c e"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ names: ["Will Henry Grace"] }] }) });
  ok("name: an initialled name with its surname spread out is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("w . r a y"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ names: ["Will Ray"] }] }) });
  ok("name: a short initial and surname spread out is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("W . L i"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ names: ["Will Li"] }] }) });
  ok("name: a three-letter initial and surname spread out is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("Z o r a"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ names: ["Zora"] }] }) });
  ok("name: a short single-token name spread out is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("see zoras and zorathustra"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ names: ["Zora"] }] }) });
  ok("name: longer words beside a short single-token name are forwarded", res.status === 200 && (await calls()).total === 1, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("Z o e"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ names: ["Zoe"] }] }) });
  ok("name: a three-letter single-token name spread out is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("see zoes and the ozone"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ names: ["Zoe"] }] }) });
  ok("name: longer words beside a three-letter single-token name are forwarded", res.status === 200 && (await calls()).total === 1, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("M a r i s o l"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ names: ["Marisol Quintero-Vance"] }] }) });
  ok("name: a spaced-out first name from a full-name declaration is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("q u i n t e r o v a n c e"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ names: ["Marisol Quintero-Vance"] }] }) });
  ok("name: a spaced-out surname from a full-name declaration is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("w i l l and g r a c e"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ names: ["Will Grace"] }] }) });
  ok("name: common-word tokens of a full-name declaration spread out alone are forwarded", res.status === 200 && (await calls()).total === 1, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("a b c d e"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ emails: ["abcde@example.com"] }] }) });
  ok("email: a spaced-out five-character local part is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("1 O a k S t"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ addresses: ["1 Oak St"] }] }) });
  ok("address: a spaced-out short address is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  await reset();
  res = await post("/v1/messages", aBody("1 O a k S t r e e t"), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ addresses: ["1 Oak St"] }] }) });
  ok("address: a spaced-out short address with its suffix expanded is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));

  // A phone sent as a JSON number in exponent form, in replayed tool arguments: redacted
  // whole, never forwarded in any spelling.
  await reset();
  res = await post("/v1/chat/completions", {
    model: "gpt-4o-mini",
    messages: [
      { role: "user", content: "look this up" },
      { role: "assistant", content: null, tool_calls: [{ id: "c1", type: "function", function: { name: "lookup", arguments: '{"phone":4.045550187e9}' } }] },
      { role: "tool", tool_call_id: "c1", content: "no match" },
    ],
  }, { "x-cordon-subject": SUBJECT() });
  up = await seen();
  ok("numeric: an exponent-form subject phone never reaches upstream", res.status === 200 && !/4\.045550187e9|4045550187/.test(up), `${res.status} ${up.match(/arguments[^}]*\}/)?.[0]}`);
  // A spaced-out name spelled in JSON unicode escapes inside replayed tool arguments: the
  // provider decodes it into the name, so it is refused.
  await reset();
  const uEsc = (s) => [...s].map((ch) => (ch === " " ? " " : "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"))).join("");
  res = await post("/v1/chat/completions", {
    model: "gpt-4o-mini",
    messages: [
      { role: "user", content: "look this up" },
      { role: "assistant", content: null, tool_calls: [{ id: "c1", type: "function", function: { name: "lookup", arguments: `{"q":"${uEsc("W i l l G r a c e")}"}` } }] },
      { role: "tool", tool_call_id: "c1", content: "no match" },
    ],
  }, { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ names: ["Will Grace"] }] }) });
  ok("egress: an escaped, spaced-out name in tool arguments is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  // An abbreviated, spaced-out address in a system prompt this tenant leaves unredacted.
  await reset();
  res = await post("/v1/messages", aBody("hello", { system: "Client lives at 1428 E l m S t." }), { "x-cordon-subject": SUBJECT() }, "sys-key");
  ok("egress: a spaced-out abbreviated address is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));
  // A date of birth with spaces around its separators, in the same unredacted system prompt.
  await reset();
  res = await post("/v1/messages", aBody("hello", { system: "DOB: 7 / 14 / 1986" }), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ ...PERSON, dates: ["1986-07-14"] }] }) }, "sys-key");
  const dobRefusal = await res.json().catch(() => ({}));
  ok("egress: a spaced numeric date of birth is refused, upstream never called", res.status === 422 && (await calls()).total === 0 && /SUBJECT1_DOB/.test(dobRefusal.detail ?? ""), `${res.status} ${JSON.stringify(dobRefusal)}`);
  // The same date with the digits of the day and year spread apart.
  await reset();
  res = await post("/v1/messages", aBody("hello", { system: "DOB: 7 / 1 4 / 1 9 8 6" }), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ ...PERSON, dates: ["1986-07-14"] }] }) }, "sys-key");
  const spreadRefusal = await res.json().catch(() => ({}));
  ok("egress: a numeric date of birth with spread digits is refused, upstream never called", res.status === 422 && (await calls()).total === 0 && /SUBJECT1_DOB/.test(spreadRefusal.detail ?? ""), `${res.status} ${JSON.stringify(spreadRefusal)}`);
  // A spelled-out date of birth with its month spaced out, in the same unredacted system prompt.
  for (const dob of ["DOB: J u l y 14, 1986", "DOB: 1 4 J u l 1986"]) {
    await reset();
    res = await post("/v1/messages", aBody("hello", { system: dob }), { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ ...PERSON, dates: ["1986-07-14"] }] }) }, "sys-key");
    const spelledRefusal = await res.json().catch(() => ({}));
    ok(`egress: a spaced spelled-out date of birth is refused, upstream never called: ${dob}`, res.status === 422 && (await calls()).total === 0 && /SUBJECT1_DOB/.test(spelledRefusal.detail ?? ""), `${res.status} ${JSON.stringify(spelledRefusal)}`);
  }

  // A date of birth declared spelled out, spaced out in Responses metadata, which redaction leaves.
  await reset();
  res = await post("/v1/responses", { model: "gpt-4o-mini", input: "hello", metadata: { note: "J u l y 1 4 1 9 8 6" } }, { "x-cordon-subject": enc({ ref: "case-int-1", subjects: [{ dates: ["July 14, 1986"] }] }) });
  const declaredRefusal = await res.json().catch(() => ({}));
  ok("egress: a spelled-out declared date spaced out in metadata is refused, upstream never called", res.status === 422 && (await calls()).total === 0 && /SUBJECT1_DOB/.test(declaredRefusal.detail ?? ""), `${res.status} ${JSON.stringify(declaredRefusal)}`);

  // :8811 has no TENANT_SECRET, so a consistent-pseudonym tenant fails at the secret guard; with
  // failMode open that would forward the raw body, but never for a request that names subjects.
  await fetch("http://localhost:8811/admin/tenant", { method: "POST", headers: { "content-type": "application/json", "x-admin-token": ADMIN }, body: JSON.stringify({ tenant: keyTenant("open-key"), consistentPseudonyms: true, failMode: "open" }) });
  await reset();
  res = await fetch("http://localhost:8811/v1/messages", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": "open-key", "anthropic-version": "2023-06-01", "x-cordon-subject": SUBJECT() },
    body: JSON.stringify(aBody(TEXT)),
  });
  ok("fail open: a subject request at the pseudonym-secret guard is refused, upstream never called", res.status === 422 && (await calls()).total === 0, String(res.status));

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
