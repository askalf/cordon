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
    } else {
      out += j.choices?.[0]?.delta?.content ?? "";
    }
  }
  return out;
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

  // ---- strip streaming: placeholders persist, no restore, no hold-back ----
  await reset();
  txt = await (await post("/v1/messages", aBody(PII), { "x-redact-mode": "strip" })).text();
  text = reconstruct(txt, "anthropic");
  ok("stream/strip: placeholders persist", text.includes("[EMAIL]") && !text.includes("john@acme.com"));

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
