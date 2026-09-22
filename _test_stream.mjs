// Integration: streaming re-identification. The stub chunks its echoed reply into
// 3-char SSE frames, so placeholders like <EMAIL_1> are SPLIT across frame
// boundaries — the critical hold-back-buffer case. Run with: node _test_stream.mjs
const BASE = "http://localhost:8810";
const STUB = "http://localhost:8900";
const PII = "email john@acme.com about card 4012888888881881";

let pass = 0, fail = 0;
const ok = (n, c, e = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"}  ${n}${e ? "   (" + e + ")" : ""}`); };

const reset = () => fetch(STUB + "/__reset");
const calls = async () => (await fetch(STUB + "/__calls")).json();
const post = (path, body, headers = {}) =>
  fetch(BASE + path, {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": "test-key", "anthropic-version": "2023-06-01", ...headers },
    body: JSON.stringify(body),
  });
const aBody = (text, extra = {}) => ({ model: "claude-haiku-4-5", messages: [{ role: "user", content: text }], stream: true, ...extra });
const oBody = (text, extra = {}) => ({ model: "gpt-4o-mini", messages: [{ role: "user", content: text }], stream: true, ...extra });
const rBody = (text, extra = {}) => ({ model: "gpt-4o-mini", input: text, stream: true, ...extra });

/** Reconstruct assistant text from an SSE response body. */
function reconstruct(sse, provider) {
  let out = "";
  for (const frame of sse.split("\n\n")) {
    const line = frame.split("\n").find((l) => l.startsWith("data:"));
    if (!line) continue;
    const data = line.slice(5).trim();
    if (!data || data === "[DONE]") continue;
    let j;
    try {
      j = JSON.parse(data);
    } catch {
      continue;
    }
    if (provider === "anthropic") {
      if (j.type === "content_block_delta") out += j.delta?.text ?? "";
    } else if (provider === "responses") {
      if (j.type === "response.output_text.delta") out += j.delta ?? "";
    } else {
      out += j.choices?.[0]?.delta?.content ?? "";
    }
  }
  return out;
}

/** Every Responses frame that carries the full text, in stream order. A client SDK
 *  reads the final text from these, not from the deltas, so each must be restored. */
function responsesFullTexts(sse) {
  const out = [];
  for (const frame of sse.split("\n\n")) {
    const line = frame.split("\n").find((l) => l.startsWith("data:"));
    if (!line) continue;
    let j;
    try { j = JSON.parse(line.slice(5).trim()); } catch { continue; }
    if (j.type === "response.output_text.done") out.push(["output_text.done", j.text]);
    if (j.type === "response.content_part.done") out.push(["content_part.done", j.part?.text]);
    if (j.type === "response.output_item.done") out.push(["output_item.done", j.item?.content?.[0]?.text]);
    if (j.type === "response.completed") out.push(["completed", j.response?.output?.[0]?.content?.[0]?.text]);
  }
  return out;
}

/** Every re-emitted Responses delta as [eventLine, dataType, delta], in stream order.
 *  A refusal must stay a refusal on BOTH the `event:` line and the data payload — a
 *  client subscribing to refusal events reads nothing if either says output_text. */
function responsesDeltaKinds(sse) {
  const out = [];
  for (const frame of sse.split("\n\n")) {
    const lines = frame.split("\n");
    const ev = lines.find((l) => l.startsWith("event:"));
    const line = lines.find((l) => l.startsWith("data:"));
    if (!line) continue;
    let j;
    try { j = JSON.parse(line.slice(5).trim()); } catch { continue; }
    if (j.type === "response.output_text.delta" || j.type === "response.refusal.delta")
      out.push([ev?.slice(6).trim(), j.type, j.delta]);
  }
  return out;
}

/** Addressing on every re-emitted Responses delta must match the upstream's. */
function responsesDeltaAddressing(sse) {
  const seen = new Set();
  for (const frame of sse.split("\n\n")) {
    const line = frame.split("\n").find((l) => l.startsWith("data:"));
    if (!line) continue;
    let j;
    try { j = JSON.parse(line.slice(5).trim()); } catch { continue; }
    if (j.type === "response.output_text.delta") seen.add(`${j.item_id}/${j.output_index}/${j.content_index}`);
  }
  return [...seen];
}

/** Strict SSE validator mimicking the client SDK: a `text_delta` must land on a
 *  `text` block, a `thinking_delta` on a `thinking` block. Catches the exact failure
 *  ("Content block is not a text block") cordon hit with real CLI traffic. */
function validateSSE(sse) {
  const blockType = {}; // index -> declared block type
  let text = "", thinking = "", sawThinking = false, error = "";
  for (const frame of sse.split("\n\n")) {
    const line = frame.split("\n").find((l) => l.startsWith("data:"));
    if (!line) continue;
    const data = line.slice(5).trim();
    if (!data || data === "[DONE]") continue;
    let j;
    try { j = JSON.parse(data); } catch { continue; }
    if (j.type === "content_block_start") {
      blockType[j.index] = j.content_block?.type;
      if (j.content_block?.type === "thinking") sawThinking = true;
    } else if (j.type === "content_block_delta") {
      const bt = blockType[j.index], dt = j.delta?.type;
      if (dt === "text_delta") {
        if (bt !== "text") error ||= `text_delta on '${bt}' block @${j.index}`;
        text += j.delta.text ?? "";
      } else if (dt === "thinking_delta") {
        if (bt !== "thinking") error ||= `thinking_delta on '${bt}' block @${j.index}`;
        thinking += j.delta.thinking ?? "";
      }
    }
  }
  return { ok: !error, error, text, thinking, sawThinking };
}

(async () => {
  // ---- reversible streaming WITH extended thinking (Anthropic) ----
  // Regression for "Content block is not a text block": the response has a thinking
  // block at index 0 and the text block at index 1; re-emitted (restored) text deltas
  // must carry index 1, never collide with the thinking block at index 0.
  await reset();
  let traw = await (await post("/v1/messages", aBody(PII, { thinking: { type: "enabled", budget_tokens: 1024 } }))).text();
  let v = validateSSE(traw);
  ok("stream/thinking: SSE block structure valid (no text_delta on thinking block)", v.ok, v.error);
  ok("stream/thinking: thinking block present + passed through verbatim", v.sawThinking && v.thinking.length > 0);
  ok("stream/thinking: email restored in text block", v.text.includes("john@acme.com") && !v.text.includes("<EMAIL"));
  ok("stream/thinking: card restored in text block", v.text.includes("4012888888881881") && !v.text.includes("<CREDIT_CARD"));

  // ---- reversible streaming (Anthropic) ----
  await reset();
  let txt = await (await post("/v1/messages", aBody(PII))).text();
  let text = reconstruct(txt, "anthropic");
  ok("stream/anthropic: email restored across frame split", text.includes("john@acme.com") && !text.includes("<EMAIL"));
  ok("stream/anthropic: card restored across frame split", text.includes("4012888888881881") && !text.includes("<CREDIT_CARD"));
  let sent = JSON.stringify(await calls());
  ok("stream/anthropic: upstream saw placeholder not raw", /<EMAIL_[0-9A-F]+_1>/.test(sent) && !sent.includes("john@acme.com"));

  // ---- reversible streaming (OpenAI) ----
  await reset();
  txt = await (await post("/v1/chat/completions", oBody(PII))).text();
  text = reconstruct(txt, "openai");
  ok("stream/openai: email restored across frame split", text.includes("john@acme.com") && !text.includes("<EMAIL"));
  ok("stream/openai: card restored across frame split", text.includes("4012888888881881") && !text.includes("<CREDIT_CARD"));
  sent = JSON.stringify(await calls());
  ok("stream/openai: upstream saw placeholder not raw", /<EMAIL_[0-9A-F]+_1>/.test(sent) && !sent.includes("john@acme.com"));

  // ---- reversible streaming (OpenAI Responses API) ----
  await reset();
  txt = await (await post("/v1/responses", rBody(PII))).text();
  text = reconstruct(txt, "responses");
  ok("stream/responses: email restored across frame split", text.includes("john@acme.com") && !text.includes("<EMAIL"), text);
  ok("stream/responses: card restored across frame split", text.includes("4012888888881881") && !text.includes("<CREDIT_CARD"));
  {
    const full = responsesFullTexts(txt);
    ok("stream/responses: all four full-text frames present", full.map((f) => f[0]).join(",") === "output_text.done,content_part.done,output_item.done,completed", full.map((f) => f[0]).join(","));
    ok("stream/responses: every full-text frame restored", full.every((f) => typeof f[1] === "string" && f[1].includes("john@acme.com") && !f[1].includes("<EMAIL")), JSON.stringify(full));
    const addr = responsesDeltaAddressing(txt);
    ok("stream/responses: re-emitted deltas keep the upstream item addressing", addr.length === 1 && /^msg_stub\d+\/0\/0$/.test(addr[0]), JSON.stringify(addr));
    ok("stream/responses: event: lines preserved", txt.includes("event: response.output_text.delta") && txt.includes("event: response.completed"));
  }
  sent = JSON.stringify(await calls());
  ok("stream/responses: upstream saw placeholder not raw", /<EMAIL_[0-9A-F]+_1>/.test(sent) && !sent.includes("john@acme.com"));

  // ---- reversible streaming (Responses, two interleaved content parts) ----
  // Responses addresses a delta by item_id/output_index/content_index and parts can
  // interleave. With one buffer for the whole stream, part B's text lands inside a
  // placeholder part A had half-written and is re-emitted under B's address.
  await reset();
  txt = await (await post("/v1/responses", rBody("INTERLEAVE " + PII))).text();
  {
    const byAddr = new Map();
    for (const f of txt.split("\n\n")) {
      const d = f.split("\n").find((l) => l.startsWith("data:"));
      if (!d) continue;
      let j; try { j = JSON.parse(d.slice(5).trim()); } catch { continue; }
      if (j?.type !== "response.output_text.delta") continue;
      const k = `${j.item_id}/${j.output_index}/${j.content_index}`;
      byAddr.set(k, (byAddr.get(k) ?? "") + (j.delta ?? ""));
    }
    ok("stream/responses/interleave: both parts present", byAddr.size === 2, JSON.stringify([...byAddr.keys()]));
    const joined = [...byAddr.values()];
    ok("stream/responses/interleave: the PII part is restored whole",
      joined.some((t) => t.includes("john@acme.com")) && !joined.join("").includes("<EMAIL"), JSON.stringify(joined));
    ok("stream/responses/interleave: the other part keeps its own text",
      joined.some((t) => t.startsWith("second part repeats")), JSON.stringify(joined));
    // The stub closes item A (output_text.done, content_part.done, output_item.done)
    // while item B is holding a half-written placeholder. Closing A must not end B's
    // re-identifier, or B's email resolves early and its suffix arrives on its own.
    ok("stream/responses/interleave: a part still open survives another item closing",
      joined.every((t) => t.includes("john@acme.com") && !/<EMAIL|<CREDIT|IL_[0-9A-F]+_\d>/.test(t)), JSON.stringify(joined));
  }

  // ---- reversible streaming (Responses REFUSAL) ----
  // A refusal carries restorable text too, but under its own event type. Regression:
  // the re-emit path shared frameFromText with output text and hardcoded the
  // output-text type, so a refusal reached the client as ordinary output text.
  await reset();
  txt = await (await post("/v1/responses", rBody("FORCE_REFUSAL cannot help with john@acme.com"))).text();
  {
    const kinds = responsesDeltaKinds(txt);
    ok("stream/responses/refusal: deltas present", kinds.length > 0, String(kinds.length));
    ok("stream/responses/refusal: every re-emitted delta is a refusal delta",
      kinds.every((k) => k[1] === "response.refusal.delta"), JSON.stringify(kinds.map((k) => k[1])));
    ok("stream/responses/refusal: event: line matches the data type",
      kinds.every((k) => k[0] === k[1]), JSON.stringify(kinds.map((k) => [k[0], k[1]])));
    ok("stream/responses/refusal: no output_text delta leaked",
      !txt.includes("event: response.output_text.delta") && !txt.includes('"response.output_text.delta"'));
    const refusal = kinds.map((k) => k[2] ?? "").join("");
    ok("stream/responses/refusal: refusal text restored across frame split",
      refusal.includes("john@acme.com") && !refusal.includes("<EMAIL"), refusal);
    ok("stream/responses/refusal: refusal.done restored",
      /"refusal":"[^"]*john@acme\.com/.test(txt) && !/"refusal":"[^"]*<EMAIL/.test(txt));
  }

  // ---- strip streaming (Responses) ----
  await reset();
  txt = await (await post("/v1/responses", rBody(PII), { "x-redact-mode": "strip" })).text();
  text = reconstruct(txt, "responses");
  ok("stream/responses/strip: placeholders persist", text.includes("[EMAIL]") && !text.includes("john@acme.com"));

  // ---- strip streaming: placeholders persist, no restore, no hold-back ----
  await reset();
  txt = await (await post("/v1/messages", aBody(PII), { "x-redact-mode": "strip" })).text();
  text = reconstruct(txt, "anthropic");
  ok("stream/strip: placeholders persist", text.includes("[EMAIL]") && !text.includes("john@acme.com"));

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
