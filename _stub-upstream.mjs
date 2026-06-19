// Throwaway stub provider for testing cordon (not part of the app). It ECHOES the
// text it received back as the assistant reply — so a test can assert (a) the body the
// "model" saw contained only placeholders, never raw PII, and (b) in reversible mode
// the client gets the real values restored. Records every received body at /__calls.
import http from "node:http";

let calls = { total: 0, byPath: {}, bodies: [] };

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
  return parts.join(" ");
}

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
function streamAnthropic(res, text) {
  res.setHeader("content-type", "text/event-stream");
  const f = (e, d) => res.write(`event: ${e}\ndata: ${JSON.stringify({ type: e, ...d })}\n\n`);
  f("message_start", { message: { id: "stub", type: "message", role: "assistant", model: "claude-haiku-4-5-20251001", content: [], usage: { input_tokens: 10, output_tokens: 0 } } });
  f("content_block_start", { index: 0, content_block: { type: "text", text: "" } });
  for (const t of chunk3(text)) f("content_block_delta", { index: 0, delta: { type: "text_delta", text: t } });
  f("content_block_stop", { index: 0 });
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
      if (req.url === "/__reset") { calls = { total: 0, byPath: {}, bodies: [] }; return json(res, { ok: true }); }
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
      if (req.url.includes("/messages"))
        return body.stream ? streamAnthropic(res, text) : json(res, anthropicBody(n, text));
      res.statusCode = 404;
      res.end("nope");
    });
  })
  .listen(8900, () => console.log("stub upstream (echo) on :8900"));
