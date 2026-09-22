// Throwaway stub provider for testing cordon (not part of the app). It ECHOES the
// text it received back as the assistant reply — so a test can assert (a) the body the
// "model" saw contained only placeholders, never raw PII, and (b) in reversible mode
// the client gets the real values restored. Records every received body at /__calls.
import http from "node:http";

// byPath is keyed by the raw request URL — null prototype so a path like
// "/__proto__" can only ever be a plain counter key.
let calls = { total: 0, byPath: Object.create(null), bodies: [] };

const json = (res, obj) => {
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(obj));
};

/** All user-supplied text in a request, in order — this is what the model "saw". */
function collectText(body, provider) {
  const parts = [];
  const pushContent = (c) => {
    if (typeof c === "string") parts.push(c);
    else if (Array.isArray(c))
      for (const p of c) {
        if (typeof p?.text === "string") parts.push(p.text);
        if (p?.type === "tool_result") pushContent(p.content);
      }
  };
  if (provider === "anthropic" && body.system) pushContent(body.system);
  for (const m of body.messages || []) if (m.role === "user") pushContent(m.content);
  // Responses API: `input` is a string or a list of items (messages, function calls, outputs).
  if (typeof body.input === "string") parts.push(body.input);
  else for (const item of body.input || []) {
    if (item?.role === "user") pushContent(item.content);
    if (item?.type === "function_call_output" && typeof item.output === "string") parts.push(item.output);
  }
  return parts.join(" ");
}

const responsesBody = (n, text) => ({
  id: "resp_stub" + n, object: "response", model: "gpt-4o-mini", status: "completed",
  output: [{ id: "msg_stub" + n, type: "message", role: "assistant", status: "completed",
    content: [{ type: "output_text", text, annotations: [] }] }],
  usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 }, _stub_call: n,
});

const openaiBody = (n, text) => ({
  id: "stub-" + n, object: "chat.completion", model: "gpt-4o-mini",
  choices: [{ index: 0, message: { role: "assistant", content: text }, finish_reason: "stop" }],
  usage: { prompt_tokens: 10, completion_tokens: 5 }, _stub_call: n,
});
const anthropicBody = (n, text) => ({
  id: "stub-" + n, type: "message", role: "assistant", model: "claude-haiku-4-5-20251001",
  content: [{ type: "text", text }], stop_reason: "end_turn",
  usage: { input_tokens: 10, output_tokens: 5 }, _stub_call: n,
});

// Chunk size 3 deliberately splits placeholders like <EMAIL_1> across SSE frames —
// the critical streaming-reidentify boundary case.
const chunk3 = (s) => {
  const out = [];
  for (let i = 0; i < s.length; i += 3) out.push(s.slice(i, i + 3));
  return out.length ? out : [""];
};

function streamOpenAI(res, text) {
  res.setHeader("content-type", "text/event-stream");
  res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { role: "assistant" } }] })}\n\n`);
  for (const c of chunk3(text))
    res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: c } }] })}\n\n`);
  res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\n`);
  res.write("data: [DONE]\n\n");
  res.end();
}
function streamResponses(res, text, n) {
  res.setHeader("content-type", "text/event-stream");
  let seq = 0;
  const f = (type, d) => res.write(`event: ${type}\ndata: ${JSON.stringify({ type, sequence_number: seq++, ...d })}\n\n`);
  const addr = { item_id: "msg_stub" + n, output_index: 0, content_index: 0 };
  const shell = (status) => ({ id: "resp_stub" + n, object: "response", model: "gpt-4o-mini", status, output: [] });
  f("response.created", { response: shell("in_progress") });
  f("response.in_progress", { response: shell("in_progress") });
  f("response.output_item.added", { output_index: 0, item: { id: addr.item_id, type: "message", role: "assistant", status: "in_progress", content: [] } });
  f("response.content_part.added", { ...addr, part: { type: "output_text", text: "", annotations: [] } });
  for (const c of chunk3(text)) f("response.output_text.delta", { ...addr, delta: c });
  f("response.output_text.done", { ...addr, text });
  f("response.content_part.done", { ...addr, part: { type: "output_text", text, annotations: [] } });
  const item = { id: addr.item_id, type: "message", role: "assistant", status: "completed", content: [{ type: "output_text", text, annotations: [] }] };
  f("response.output_item.done", { output_index: 0, item });
  f("response.completed", { response: { ...shell("completed"), output: [item], usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 } } });
  res.end();
}
// A REFUSED Responses turn streams the same frame shape under refusal-flavoured
// event types (`response.refusal.delta` / `.done`, a `refusal` content part). A
// client consuming refusals reads only those, so cordon must re-emit a restored
// refusal delta as a refusal delta — not as output text.
function streamResponsesRefusal(res, text, n) {
  res.setHeader("content-type", "text/event-stream");
  let seq = 0;
  const f = (type, d) => res.write(`event: ${type}\ndata: ${JSON.stringify({ type, sequence_number: seq++, ...d })}\n\n`);
  const addr = { item_id: "msg_stub" + n, output_index: 0, content_index: 0 };
  const shell = (status) => ({ id: "resp_stub" + n, object: "response", model: "gpt-4o-mini", status, output: [] });
  f("response.created", { response: shell("in_progress") });
  f("response.output_item.added", { output_index: 0, item: { id: addr.item_id, type: "message", role: "assistant", status: "in_progress", content: [] } });
  f("response.content_part.added", { ...addr, part: { type: "refusal", refusal: "" } });
  for (const c of chunk3(text)) f("response.refusal.delta", { ...addr, delta: c });
  f("response.refusal.done", { ...addr, refusal: text });
  f("response.content_part.done", { ...addr, part: { type: "refusal", refusal: text } });
  const item = { id: addr.item_id, type: "message", role: "assistant", status: "completed", content: [{ type: "refusal", refusal: text }] };
  f("response.output_item.done", { output_index: 0, item });
  f("response.completed", { response: { ...shell("completed"), output: [item], usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 } } });
  res.end();
}
function streamAnthropic(res, text, body = {}) {
  res.setHeader("content-type", "text/event-stream");
  const f = (e, d) => res.write(`event: ${e}\ndata: ${JSON.stringify({ type: e, ...d })}\n\n`);
  f("message_start", { message: { id: "stub", type: "message", role: "assistant", model: "claude-haiku-4-5-20251001", content: [], usage: { input_tokens: 10, output_tokens: 0 } } });
  let idx = 0;
  // Extended thinking: a `thinking` block streams FIRST (index 0), then the text block
  // (index 1) — the shape the real Claude CLI produces and the regression the streaming
  // re-identifier must survive (don't emit a text_delta against the thinking block).
  if (body.thinking) {
    f("content_block_start", { index: idx, content_block: { type: "thinking", thinking: "" } });
    for (const t of chunk3("Let me reason about this request step by step.")) f("content_block_delta", { index: idx, delta: { type: "thinking_delta", thinking: t } });
    f("content_block_delta", { index: idx, delta: { type: "signature_delta", signature: "c3R1Yg==" } });
    f("content_block_stop", { index: idx });
    idx++;
  }
  f("content_block_start", { index: idx, content_block: { type: "text", text: "" } });
  for (const t of chunk3(text)) f("content_block_delta", { index: idx, delta: { type: "text_delta", text: t } });
  f("content_block_stop", { index: idx });
  f("message_delta", { delta: { stop_reason: "end_turn" }, usage: { output_tokens: 5 } });
  f("message_stop", {});
  res.end();
}

http
  .createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", async () => {
      if (req.url === "/__calls") return json(res, calls);
      if (req.url === "/__reset") { calls = { total: 0, byPath: Object.create(null), bodies: [] }; return json(res, { ok: true }); }
      const body = b ? JSON.parse(b) : {};

      calls.total++;
      calls.byPath[req.url] = (calls.byPath[req.url] || 0) + 1;
      calls.bodies.push({ url: req.url, body });
      const n = calls.total;

      // Forced upstream error (to test error piping; no real PII exists upstream).
      const text = collectText(body, req.url.includes("/messages") ? "anthropic" : "openai");
      if (text.includes("FORCE_ERROR")) {
        res.statusCode = 500;
        return json(res, { error: { message: "forced upstream error", type: "server_error" } });
      }

      // Non-generation endpoints — prove cordon passes them through verbatim.
      if (req.url.includes("count_tokens")) return json(res, { input_tokens: 42, _stub_call: n, _url: req.url });
      if (req.method === "GET" && req.url.startsWith("/v1/models"))
        return json(res, { object: "list", data: [], _url: req.url });

      // Echo the received text back as the assistant reply.
      if (req.url.includes("/chat/completions"))
        return body.stream ? streamOpenAI(res, text) : json(res, openaiBody(n, text));
      if (req.url.includes("/responses"))
        return body.stream
          ? text.includes("FORCE_REFUSAL") ? streamResponsesRefusal(res, text, n) : streamResponses(res, text, n)
          : json(res, responsesBody(n, text));
      if (req.url.includes("/messages"))
        return body.stream ? streamAnthropic(res, text, body) : json(res, anthropicBody(n, text));
      res.statusCode = 404;
      res.end("nope");
    });
  })
  .listen(8900, () => console.log("stub upstream (echo) on :8900"));
