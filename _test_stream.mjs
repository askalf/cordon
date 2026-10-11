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

  // ---- Responses stream that ends with no terminal frame ----
  // The upstream stops after a delta that leaves a placeholder half-written: the
  // per-part buffers are the only place that text lives, so the end-of-reader path
  // has to flush THEM. Flushing the chat-dialect buffer there emits nothing and the
  // client silently loses the tail.
  await reset();
  txt = await (await post("/v1/responses", rBody("TRUNCATE " + PII))).text();
  {
    let got = "";
    for (const f of txt.split("\n\n")) {
      const d = f.split("\n").find((l) => l.startsWith("data:"));
      if (!d) continue;
      let j; try { j = JSON.parse(d.slice(5).trim()); } catch { continue; }
      if (j?.type === "response.output_text.delta") got += j.delta ?? "";
    }
    ok("stream/responses/truncated: the resolved text arrives", got.includes("john@acme.com"), JSON.stringify(got));
    // The card's placeholder was still held when the socket closed. Flushing the
    // per-part buffer restores it; flushing the chat buffer instead emits nothing and
    // the client's text stops at "about card ".
    ok("stream/responses/truncated: the held tail is not dropped", got.includes("4012888888881881"), JSON.stringify(got));
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

  // ---- streamed tool calls: arguments restored across 3-character fragments, every dialect ----
  // The stub chunks the arguments JSON in 3-character fragments, so each placeholder is
  // split across frames inside a JSON string literal; what reaches the client must be the
  // real values, JSON-escaped, and the fragments must join into JSON that parses.
  const TOOL = [{ type: "function", name: "echo", description: "echo", parameters: { type: "object", properties: { text: { type: "string" } } } }];
  const joinFrames = (sse, pick) => {
    let out = "";
    for (const frame of sse.split("\n\n")) {
      const line = frame.split("\n").find((l) => l.startsWith("data:"));
      if (!line) continue;
      let j; try { j = JSON.parse(line.slice(5).trim()); } catch { continue; }
      out += pick(j) ?? "";
    }
    return out;
  };
  const parsesTo = (s) => { try { return JSON.parse(s); } catch { return null; } };
  await reset();
  txt = await (await post("/v1/responses", rBody("TOOLCALL " + PII, { tools: TOOL }))).text();
  {
    const args = joinFrames(txt, (j) => (j.type === "response.function_call_arguments.delta" ? j.delta : ""));
    const parsed = parsesTo(args);
    ok("stream/tool/responses: argument fragments join into JSON", !!parsed, args);
    ok("stream/tool/responses: email restored across fragments", !!parsed && parsed.text.includes("john@acme.com") && !args.includes("<EMAIL"), args);
    ok("stream/tool/responses: card restored across fragments", !!parsed && parsed.text.includes("4012888888881881"));
    const done = joinFrames(txt, (j) => (j.type === "response.function_call_arguments.done" ? j.arguments : ""));
    ok("stream/tool/responses: arguments.done frame restored", done.includes("john@acme.com") && !done.includes("<EMAIL"), done);
    const item = joinFrames(txt, (j) => (j.type === "response.output_item.done" ? j.item?.arguments : ""));
    ok("stream/tool/responses: output_item.done arguments restored", item.includes("john@acme.com") && !item.includes("<EMAIL"), item);
    ok("stream/tool/responses: event lines kept for the re-emitted fragments", txt.includes("event: response.function_call_arguments.delta"));
    sent = JSON.stringify(await calls());
    ok("stream/tool/responses: upstream never saw the raw values", !sent.includes("john@acme.com") && !sent.includes("4012888888881881"));
  }
  await reset();
  txt = await (await post("/v1/chat/completions", oBody("TOOLCALL " + PII, { tools: [{ type: "function", function: TOOL[0] }] }))).text();
  {
    const args = joinFrames(txt, (j) => (j.choices?.[0]?.delta?.tool_calls ?? []).map((tc) => tc.function?.arguments ?? "").join(""));
    const parsed = parsesTo(args);
    ok("stream/tool/chat: argument fragments join into JSON", !!parsed, args);
    ok("stream/tool/chat: email restored across fragments", !!parsed && parsed.text.includes("john@acme.com") && !args.includes("<EMAIL"), args);
    const first = joinFrames(txt, (j) => (j.choices?.[0]?.delta?.tool_calls?.[0]?.id ? j.choices[0].delta.tool_calls[0].id : ""));
    ok("stream/tool/chat: the tool call's id frame passes through", first.startsWith("call_stub"), first);
    sent = JSON.stringify(await calls());
    ok("stream/tool/chat: upstream never saw the raw values", !sent.includes("john@acme.com"));
  }
  await reset();
  txt = await (await post("/v1/messages", aBody("TOOLCALL " + PII, { tools: [{ name: "echo", description: "echo", input_schema: TOOL[0].parameters }] }))).text();
  {
    const args = joinFrames(txt, (j) => (j.type === "content_block_delta" && j.delta?.type === "input_json_delta" ? j.delta.partial_json : ""));
    const parsed = parsesTo(args);
    ok("stream/tool/anthropic: input_json fragments join into JSON", !!parsed, args);
    ok("stream/tool/anthropic: email restored across fragments", !!parsed && parsed.text.includes("john@acme.com") && !args.includes("<EMAIL"), args);
    ok("stream/tool/anthropic: card restored across fragments", !!parsed && parsed.text.includes("4012888888881881"));
    const v = validateSSE(txt);
    ok("stream/tool/anthropic: the text block before the tool call is intact", v.ok && v.text === "Calling the tool.", v.error || v.text);
    sent = JSON.stringify(await calls());
    ok("stream/tool/anthropic: upstream never saw the raw values", !sent.includes("john@acme.com") && !sent.includes("4012888888881881"));
  }

  // ---- streamed tool arguments: done frames, shapes, escaping, ordering, unresolved, policy ----
  const PEM = '-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0"BAQ\\EFAASCAUAwggE8\n-----END PRIVATE KEY-----';
  const frames = (sse) => {
    const out = [];
    for (const frame of sse.split("\n\n")) {
      const lines = frame.split("\n");
      const ev = lines.find((l) => l.startsWith("event:"))?.slice(6).trim();
      const line = lines.find((l) => l.startsWith("data:"));
      if (!line) continue;
      const raw = line.slice(5).trim();
      let j = null;
      try { j = JSON.parse(raw); } catch {}
      out.push({ ev, raw, j });
    }
    return out;
  };
  const respTool = (extra = "") => rBody("TOOLCALL " + extra + PII, { tools: TOOL });

  // Responses: the deltas join into exactly what the done frame, the item and the completed
  // response carry, raw text and all (a number beyond 2^53 keeps its digits).
  await reset();
  txt = await (await post("/v1/responses", respTool())).text();
  {
    const f = frames(txt);
    const joined = f.filter((x) => x.j?.type === "response.function_call_arguments.delta").map((x) => x.j.delta).join("");
    const done = f.find((x) => x.j?.type === "response.function_call_arguments.done")?.j?.arguments;
    const item = f.find((x) => x.j?.type === "response.output_item.done")?.j?.item?.arguments;
    const completed = f.find((x) => x.j?.type === "response.completed")?.j?.response?.output?.[0]?.arguments;
    ok("stream/args: the deltas join into the done frame's arguments byte for byte", joined === done, JSON.stringify([joined, done]));
    ok("stream/args: output_item.done and response.completed carry the same arguments", item === done && completed === done);
    ok("stream/args: a number beyond 2^53 keeps its digits in the frame text", f.some((x) => x.j?.type === "response.function_call_arguments.done" && x.raw.includes("9007199254740993")));
  }
  await reset();
  txt = await (await post("/v1/responses", rBody("TOOLCALL key " + PEM, { tools: TOOL }))).text();
  {
    const joined = frames(txt).filter((x) => x.j?.type === "response.function_call_arguments.delta").map((x) => x.j.delta).join("");
    ok("stream/args: a PEM key restored across fragments, JSON-escaped, document parses", parsesTo(joined)?.text?.includes(PEM), joined);
  }
  await reset();
  txt = await (await post("/v1/responses", respTool("ESCAPED "))).text();
  {
    const f = frames(txt);
    const joined = f.filter((x) => x.j?.type === "response.function_call_arguments.delta").map((x) => x.j.delta).join("");
    const done = f.find((x) => x.j?.type === "response.function_call_arguments.done")?.j?.arguments;
    ok("stream/args: \\u003c-spelled placeholders restored in the deltas", parsesTo(joined)?.text?.includes("john@acme.com") && !/u003cEMAIL/.test(joined), joined);
    ok("stream/args: and the deltas still match the done frame", joined === done);
  }
  await reset();
  txt = await (await post("/v1/responses", rBody("TOOLCALL CUSTOM key " + PEM, { tools: TOOL }))).text();
  {
    const f = frames(txt);
    const joined = f.filter((x) => x.j?.type === "response.custom_tool_call_input.delta").map((x) => x.j.delta).join("");
    const done = f.find((x) => x.j?.type === "response.custom_tool_call_input.done")?.j?.input;
    ok("stream/custom: a custom tool's streamed input gets the raw value, not a JSON-escaped one", joined.includes(PEM) && !joined.includes("\\n"), JSON.stringify(joined));
    ok("stream/custom: the deltas match the done frame", joined === done);
  }
  await reset();
  txt = await (await post("/v1/responses", respTool("MCP "))).text();
  {
    const f = frames(txt);
    const joined = f.filter((x) => x.j?.type === "response.mcp_call_arguments.delta").map((x) => x.j.delta).join("");
    const done = f.find((x) => x.j?.type === "response.mcp_call_arguments.done")?.j?.arguments;
    ok("stream/mcp: mcp_call arguments restored across fragments", parsesTo(joined)?.text?.includes("john@acme.com"), joined);
    ok("stream/mcp: the deltas match the done frame", joined === done);
  }

  // Chat: a frame carrying text and the first argument fragment keeps both.
  const chatTool = (extra, more = {}) => oBody("TOOLCALL " + extra + PII, { tools: [{ type: "function", function: TOOL[0] }], ...more });
  const chatArgs = (sse, ci = 0) =>
    frames(sse).map((x) => (x.j?.choices ?? []).filter((c) => (c.index ?? 0) === ci).map((c) => (c.delta?.tool_calls ?? []).map((t) => t.function?.arguments ?? "").join("") + (c.delta?.function_call?.arguments ?? "")).join("")).join("");
  await reset();
  txt = await (await post("/v1/chat/completions", chatTool("MIXED "))).text();
  {
    const text = reconstruct(txt, "openai");
    const args = chatArgs(txt);
    ok("stream/chat-mixed: the text in the mixed frame survives", text.includes("Calling."), text);
    ok("stream/chat-mixed: the argument fragment in the mixed frame survives", parsesTo(args)?.text?.includes("john@acme.com"), args);
    ok("stream/chat-mixed: the tool call's id and name pass through", txt.includes("call_stub") && txt.includes('"name":"echo"'));
  }
  await reset();
  txt = await (await post("/v1/chat/completions", chatTool("FINISHJOINED "))).text();
  {
    const f = frames(txt);
    const args = chatArgs(txt);
    const finishAt = f.findIndex((x) => x.j?.choices?.[0]?.finish_reason);
    const fragAfter = f.slice(finishAt + 1).some((x) => (x.j?.choices?.[0]?.delta?.tool_calls ?? []).length);
    ok("stream/chat-finish: the last fragment sharing the finish frame is kept", parsesTo(args)?.text?.includes("john@acme.com"), args);
    ok("stream/chat-finish: no argument fragment comes after the finish", finishAt >= 0 && !fragAfter);
  }
  await reset();
  txt = await (await post("/v1/chat/completions", chatTool("LEGACY ", { tools: undefined, functions: [TOOL[0]] }))).text();
  {
    const args = chatArgs(txt);
    ok("stream/chat-legacy: function_call argument fragments restored", parsesTo(args)?.text?.includes("john@acme.com"), args);
  }
  await reset();
  txt = await (await post("/v1/chat/completions", chatTool("CHOICE1 ", { n: 2 }))).text();
  {
    const args = chatArgs(txt, 1);
    ok("stream/chat-choices: the second choice's argument fragments restored", parsesTo(args)?.text?.includes("john@acme.com"), args);
    ok("stream/chat-choices: the first choice's text is intact", txt.includes('"content":"ok"'));
  }

  // A stream that stops inside a placeholder in the arguments: the call is rejected with
  // the dialect's error frame, never completed by guessing which placeholder it was.
  await reset();
  txt = await (await post("/v1/chat/completions", chatTool("ARGTRUNC "))).text();
  {
    const f = frames(txt);
    ok("stream/chat-truncated: ends with an error frame", f.at(-1)?.j?.error?.code === "cordon_unresolved_placeholder", JSON.stringify(f.at(-1)?.j));
    ok("stream/chat-truncated: no value is guessed into the arguments", !chatArgs(txt).includes("john@acme.com"));
  }
  await reset();
  txt = await (await post("/v1/messages", aBody("TOOLCALL ARGTRUNC " + PII, { tools: [{ name: "echo", description: "echo", input_schema: TOOL[0].parameters }] }))).text();
  {
    const f = frames(txt);
    const args = joinFrames(txt, (j) => (j.type === "content_block_delta" && j.delta?.type === "input_json_delta" ? j.delta.partial_json : ""));
    ok("stream/anthropic-truncated: ends with an error frame", f.at(-1)?.j?.type === "error" && f.at(-1)?.ev === "error", JSON.stringify(f.at(-1)?.j));
    ok("stream/anthropic-truncated: no value is guessed into the input", !args.includes("john@acme.com"));
  }
  await reset();
  txt = await (await post("/v1/messages", aBody("TOOLCALL STARTINPUT " + PII, { tools: [{ name: "echo", description: "echo", input_schema: TOOL[0].parameters }] }))).text();
  {
    const start = frames(txt).find((x) => x.j?.type === "content_block_start" && x.j.content_block?.type === "tool_use");
    ok("stream/anthropic-start: an input given whole on content_block_start is restored", start?.j?.content_block?.input?.text?.includes("john@acme.com"), JSON.stringify(start?.j?.content_block?.input));
  }

  // A placeholder this request never minted: the dialect's error frame, and nothing after it.
  for (const [label, path, body, isError] of [
    ["responses", "/v1/responses", respTool("FOREIGN "), (x) => x.j?.type === "error" && x.j.code === "cordon_unresolved_placeholder"],
    ["chat", "/v1/chat/completions", chatTool("FOREIGN "), (x) => x.j?.error?.code === "cordon_unresolved_placeholder"],
    ["anthropic", "/v1/messages", aBody("TOOLCALL FOREIGN " + PII, { tools: [{ name: "echo", description: "echo", input_schema: TOOL[0].parameters }] }), (x) => x.j?.type === "error" && x.ev === "error"],
  ]) {
    await reset();
    txt = await (await post(path, body)).text();
    const f = frames(txt);
    const at = f.findIndex(isError);
    ok(`stream/unresolved/${label}: an error frame ends the stream`, at >= 0 && at === f.length - 1, JSON.stringify(f.map((x) => x.j?.type ?? (x.j?.error ? "error" : x.raw.slice(0, 20)))));
    ok(`stream/unresolved/${label}: the foreign placeholder never reaches the client`, !txt.includes("EMAIL_ABCDEF_7"));
  }

  // CORDON_RESTORE_TOOLS=echo.text on :8813, streamed: same per-field decision as whole.
  {
    const post4 = (path, body) =>
      fetch("http://localhost:8813" + path, { method: "POST", headers: { "content-type": "application/json", "x-api-key": "test-key", "anthropic-version": "2023-06-01" }, body: JSON.stringify(body) });
    await reset();
    txt = await (await post4("/v1/responses", respTool())).text();
    const f = frames(txt);
    const joined = f.filter((x) => x.j?.type === "response.function_call_arguments.delta").map((x) => x.j.delta).join("");
    const p = parsesTo(joined);
    ok("stream/policy: echo.text restored, echo.note withheld as [EMAIL]", p?.text?.includes("john@acme.com") && (p?.note ?? "").includes("[EMAIL]") && !/<EMAIL_/.test(p?.note ?? ""), joined);
    ok("stream/policy: a withheld placeholder does not end the stream", !f.some((x) => x.j?.type === "error"));

    // A name streamed in fragments: "send" is on the list, "send_email" is not. The policy
    // must apply to the whole name, never to the first fragment.
    for (const legacy of [false, true]) {
      const label = legacy ? "function_call" : "tool_calls";
      const tools = legacy ? { functions: [{ ...TOOL[0], name: "send_email" }] } : { tools: [{ type: "function", function: { ...TOOL[0], name: "send_email" } }] };
      await reset();
      txt = await (await post4("/v1/chat/completions", oBody("TOOLCALL NAMESPLIT " + (legacy ? "LEGACY " : "") + PII, { stream: true, ...tools }))).text();
      const args = chatArgs(txt);
      ok(`stream/policy/${label}: send_email (streamed as send + _email) gets nothing back`, args.length > 0 && !args.includes("john@acme.com") && args.includes("[EMAIL]"), args);
      ok(`stream/policy/${label}: and the call still completes`, !!parsesTo(args) && !frames(txt).some((x) => x.j?.error));
      const toolsSend = legacy ? { functions: [{ ...TOOL[0], name: "send" }] } : { tools: [{ type: "function", function: { ...TOOL[0], name: "send" } }] };
      await reset();
      txt = await (await post4("/v1/chat/completions", oBody("TOOLCALL " + (legacy ? "LEGACY " : "") + PII, { stream: true, ...toolsSend }))).text();
      ok(`stream/policy/${label}: send itself, on the list, is restored`, parsesTo(chatArgs(txt))?.text?.includes("john@acme.com"), chatArgs(txt));
    }
  }

  // Responses: every frame cordon writes, its own flushes included, has a unique and
  // increasing sequence_number.
  await reset();
  txt = await (await post("/v1/responses", respTool())).text();
  {
    const seqs = frames(txt).map((x) => x.j?.sequence_number).filter((n) => typeof n === "number");
    ok("stream/sequence: sequence_numbers are unique and increasing", seqs.length > 3 && seqs.every((n, i) => i === 0 || n === seqs[i - 1] + 1), JSON.stringify(seqs));
  }
  await reset();
  txt = await (await post("/v1/responses", rBody("INTERLEAVE " + PII))).text();
  {
    const seqs = frames(txt).map((x) => x.j?.sequence_number).filter((n) => typeof n === "number");
    ok("stream/sequence: and with interleaved parts flushed at their done frames", seqs.every((n, i) => i === 0 || n === seqs[i - 1] + 1), JSON.stringify(seqs));
  }
  // Upstream frames with spaced JSON ("sequence_number": 6) share the counter with the
  // compact frames cordon rewrites.
  await reset();
  txt = await (await post("/v1/responses", respTool("SPACED "))).text();
  {
    const seqs = frames(txt).map((x) => x.j?.sequence_number).filter((n) => typeof n === "number");
    ok("stream/sequence: spaced upstream frames and rewritten frames share one increasing count", seqs.length > 3 && seqs.every((n, i) => i === 0 || n === seqs[i - 1] + 1), JSON.stringify(seqs));
  }
  await reset();
  txt = await (await post("/v1/responses", rBody("INTERLEAVE SPACED " + PII))).text();
  {
    const seqs = frames(txt).map((x) => x.j?.sequence_number).filter((n) => typeof n === "number");
    ok("stream/sequence: spaced, with cordon's own flush frames between them", seqs.length > 3 && seqs.every((n, i) => i === 0 || n === seqs[i - 1] + 1), JSON.stringify(seqs));
  }
  // A custom tool's plain-text input that ends in an uppercase name after < is text, as
  // it is in the whole document: delivered, not refused as a cut-off placeholder.
  await reset();
  txt = await (await post("/v1/responses", rBody("TOOLCALL CUSTOM cat <README", { tools: TOOL }))).text();
  {
    const f = frames(txt);
    const joined = f.filter((x) => x.j?.type === "response.custom_tool_call_input.delta").map((x) => x.j.delta).join("");
    ok("stream/custom-tail: `cat <README` is delivered as written", joined.endsWith("cat <README") && !f.some((x) => x.j?.type === "error"), joined + " | " + JSON.stringify(f.at(-1)?.j));
  }
  // Messages: an input given whole at content_block_start is restored on the frame's own
  // text, so an integer beyond 2^53 keeps its digits.
  await reset();
  txt = await (await post("/v1/messages", aBody("TOOLCALL STARTINPUT " + PII, { tools: [{ name: "echo", description: "echo", input_schema: TOOL[0].parameters }] }))).text();
  {
    const start = frames(txt).find((x) => x.j?.type === "content_block_start" && x.j.content_block?.type === "tool_use");
    ok("stream/anthropic-start: restored in place, the big integer's digits intact", start?.raw?.includes('"n":9007199254740993') && start.raw.includes("john@acme.com"), start?.raw);
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
