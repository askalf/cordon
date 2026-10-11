import type { Dialect, HttpRes, Provider } from "./types";
import { ANTHROPIC_TOOL_BLOCKS, RESPONSES_ARGUMENT_DELTAS, RESPONSES_JSON_ARGUMENT_DELTAS, type ProviderAdapter } from "./providers";
import {
  ArgStream,
  argContext,
  reidentifyBody,
  restore,
  restoreArgObject,
  restoreArgs,
  StreamReidentifier,
  DeferredArgs,
  argsFailed,
  failMessage,
  type ArgStats,
} from "./redact/reidentify";
import { restorePolicy } from "./redact/restorePolicy";
import type { Vault } from "./redact/vault";

/** Pipe an upstream Response straight to the client, verbatim (strip / off / errors). */
export async function pipeUpstream(up: Response, res: HttpRes): Promise<void> {
  res.statusCode = up.status;
  if (up.body) {
    res.setHeader("content-type", up.headers.get("content-type") ?? "application/json");
    const reader = (up.body as any).getReader();
    const dec = new TextDecoder();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      res.write(dec.decode(value, { stream: true }));
    }
    res.end();
  } else {
    const txt = await up.text();
    res.setHeader("content-type", up.headers.get("content-type") ?? "application/json");
    res.end(txt);
  }
}

/** The same SSE frame with its `data:` payload replaced by `j` (event: lines kept). */
function reframe(frame: string, j: unknown): string {
  // A function replacement, never a string: `$&`, `$\`` and `$'` inside model text are
  // replacement metacharacters to String.replace and would splice the original line
  // into the payload unescaped.
  return frame.replace(/^data:.*$/m, () => `data: ${JSON.stringify(j)}`);
}

/**
 * The dialect's own error frame for a tool call whose arguments hold placeholders this
 * request did not mint. Response headers are already sent by the time a stream finds
 * one, so the error travels in the stream (a whole response gets a 502 and
 * X-Cordon-Unresolved instead); the stream ends after it.
 */
function unresolvedFrame(provider: Provider, dialect: Dialect, stats: ArgStats): string {
  const message = failMessage(stats);
  if (provider === "anthropic")
    return `event: error\ndata: ${JSON.stringify({ type: "error", error: { type: "api_error", message } })}\n\n`;
  if (dialect === "responses")
    return `event: error\ndata: ${JSON.stringify({ type: "error", code: "cordon_unresolved_placeholder", message, param: null })}\n\n`;
  return `data: ${JSON.stringify({ error: { message, type: "cordon_unresolved_placeholder", code: "cordon_unresolved_placeholder" } })}\n\n`;
}

/**
 * The [start, end) of the value at an object-key `path` in JSON text, or null. Used to
 * restore a value in place on the provider's own text, so nothing else in the frame is
 * re-serialised (a number beyond 2^53 keeps its digits).
 */
export function valueSpan(text: string, path: string[]): [number, number] | null {
  let i = 0;
  const ws = () => {
    while (i < text.length && " \t\r\n".includes(text[i])) i++;
  };
  const str = (): string => {
    const s0 = i++;
    while (i < text.length) {
      if (text[i] === "\\") i += 2;
      else if (text[i] === '"') return text.slice(s0, ++i);
      else i++;
    }
    throw new Error("unterminated string");
  };
  const skip = (): void => {
    ws();
    const ch = text[i];
    if (ch === '"') {
      str();
      return;
    }
    if (ch === "{" || ch === "[") {
      const close = ch === "{" ? "}" : "]";
      i++;
      ws();
      if (text[i] === close) {
        i++;
        return;
      }
      for (;;) {
        ws();
        if (ch === "{") {
          str();
          ws();
          i++; // ':'
        }
        skip();
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        i++; // close
        return;
      }
    }
    while (i < text.length && !",}] \t\r\n".includes(text[i])) i++;
  };
  const find = (depth: number): [number, number] | null => {
    ws();
    if (depth === path.length) {
      const s0 = i;
      skip();
      return [s0, i];
    }
    if (text[i] !== "{") return null;
    i++;
    ws();
    if (text[i] === "}") return null;
    for (;;) {
      ws();
      const k = JSON.parse(str());
      ws();
      i++; // ':'
      if (k === path[depth]) return find(depth + 1);
      skip();
      ws();
      if (text[i] === ",") {
        i++;
        continue;
      }
      return null;
    }
  };
  try {
    return find(0);
  } catch {
    return null;
  }
}

const RESPONSES_TOOL_ITEMS = new Set(["function_call", "custom_tool_call", "mcp_call"]);
const RESPONSES_JSON_ARGUMENT_DONE = new Set(["response.function_call_arguments.done", "response.mcp_call_arguments.done"]);

/**
 * Reversible streaming: tee the upstream SSE stream while restoring real values in
 * flight. Text-carrying frames are suppressed and re-emitted (re-identified) via the
 * adapter; structural frames (message_start, usage, finish, [DONE]) pass through
 * verbatim. The held-back tail is flushed right before each text block closes, so a
 * placeholder split across a frame boundary is still restored before the client sees
 * the block end. Tool-call arguments are restored the same way through ArgStream, under
 * the restore policy, and a placeholder in them that this request did not mint ends the
 * stream with an error frame instead of reaching the client's tool.
 */
export async function captureAndReidentify(
  upBody: ReadableStream<Uint8Array>,
  res: HttpRes,
  adapter: ProviderAdapter,
  vault: Vault,
  provider: Provider,
  dialect: Dialect = provider === "anthropic" ? "messages" : "chat",
): Promise<void> {
  res.setHeader("content-type", "text/event-stream");
  res.setHeader("cache-control", "no-cache");

  // Responses frames carry a sequence_number, and cordon writes frames of its own (a held
  // tail flushed at a done frame), so every Responses frame it writes is renumbered from
  // one counter that starts where the upstream started: unique and increasing.
  let seq: number | undefined;
  const renumber = (frame: string): string =>
    frame.replace(/^(data:.*?"sequence_number":)(\d+)/m, (_m, head: string, n: string) => {
      if (seq === undefined) seq = Number(n);
      return head + seq++;
    });
  const send = (frame: string) => res.write(provider !== "anthropic" && dialect === "responses" ? renumber(frame) : frame);

  // Placeholders in tool arguments that this vault cannot resolve, across the stream.
  const stats: ArgStats = { unresolved: 0 };
  let stopped = false;
  /** True while the stream may go on; on the first unresolved placeholder, writes the
   *  error frame instead and stops the stream. Checked before every argument write. */
  const guard = (): boolean => {
    if (stopped) return false;
    if (!argsFailed(stats)) return true;
    stopped = true;
    send(unresolvedFrame(provider, dialect, stats));
    return false;
  };

  const reider = new StreamReidentifier(vault);
  // The content-block index our re-emitted text frames target. Anthropic responses can
  // interleave blocks (a `thinking` block at index 0, the `text` block at index 1, plus
  // tool_use blocks); a re-emitted text_delta MUST carry the matching block index or the
  // client SDK throws "Content block is not a text block".
  let emitIndex = 0;
  // Responses addresses a delta by item_id / output_index / content_index; a re-emitted
  // delta carries the addressing of the frame it stands in for.
  const emitText = (chunk: string, index = emitIndex, ctx: Record<string, unknown> = {}) => {
    if (chunk) send(adapter.frameFromText(chunk, index, ctx));
  };

  // ---- Anthropic: tool blocks by index, each with its name and its input's ArgStream ----
  const toolBlocks = new Map<number, { name?: string; args?: ArgStream }>();
  const emitJson = (index: number, chunk: string) => {
    if (!chunk) return;
    const data = { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: chunk } };
    send(`event: content_block_delta\ndata: ${JSON.stringify(data)}\n\n`);
  };
  const flushToolBlock = (index: number): boolean => {
    const blk = toolBlocks.get(index);
    toolBlocks.delete(index);
    if (!blk?.args) return true;
    const chunk = blk.args.end();
    if (!guard()) return false;
    emitJson(index, chunk);
    return true;
  };

  // ---- Responses: a re-identifier per content part, tool names per output item ----
  // A Responses stream can carry several content parts at once (two output items, or two
  // content indices of one item) and their deltas interleave. One buffer for all of them
  // would splice part B's text into a placeholder part A had half-written, and re-emit it
  // under B's address. Each part gets its own re-identifier and its own addressing, and
  // is flushed and dropped when that part's own done frame arrives.
  type Part = { r: { push(s: string): string; end(): string }; ctx: Record<string, unknown> };
  const parts = new Map<string, Part>();
  const partKey = (j: any) => `${j?.item_id ?? ""}/${j?.output_index ?? 0}/${j?.content_index ?? 0}`;
  const partFor = (j: any, ctx: Record<string, unknown>, make: () => Part["r"]) => {
    const key = partKey(j);
    const found = parts.get(key);
    if (found) {
      found.ctx = ctx;
      return found;
    }
    const made = { r: make(), ctx };
    parts.set(key, made);
    return made;
  };
  // The tool a call's argument frames belong to, from its output_item.added: the restore
  // policy is per tool, and argument deltas carry only the item id and index.
  const itemTools = new Map<string, string | undefined>();
  const indexTools = new Map<number, string | undefined>();
  const toolFor = (j: any): string | undefined =>
    j?.item_id !== undefined && itemTools.has(j.item_id) ? itemTools.get(j.item_id) : indexTools.get(Number(j?.output_index));
  /** Flush the parts matching `pick`, each under its own addressing, and forget them. */
  const flushParts = (pick: (key: string, ctx: Record<string, unknown>) => boolean): boolean => {
    for (const [key, part] of parts) {
      if (!pick(key, part.ctx)) continue;
      const chunk = part.r.end();
      parts.delete(key);
      if (!guard()) return false;
      emitText(chunk, 0, part.ctx);
    }
    return true;
  };
  /** Flush one part's held tail under its own addressing and forget it. */
  const flushPart = (j: any): boolean => {
    const k = partKey(j);
    return flushParts((key) => key === k);
  };
  /** Every part still open: only for the frames that close the whole response. */
  const flushAllParts = () => flushParts(() => true);
  /**
   * The parts of ONE output item, on its `output_item.done`. Closing item A must not
   * end item B's re-identifier: B may be holding a half-written placeholder, and
   * ending it early emits the resolved value and then B's own suffix separately.
   */
  const flushOutputItem = (j: any): boolean => {
    const id = j?.item?.id;
    const idx = j?.output_index;
    return flushParts((_k, ctx) => (id !== undefined && ctx["item_id"] === id) || (idx !== undefined && ctx["output_index"] === idx));
  };

  // ---- Chat completions: everything per choice (a request with n > 1 streams several) ----
  // A choice's text and each of its tool calls (by tool-call index, or "fc" for the legacy
  // function_call) hold their own tails; a call's name arrives on its first fragment.
  type Choice = { text: StreamReidentifier; args: Map<string, ArgStream | DeferredArgs>; names: Map<string, string> };
  const choices = new Map<number, Choice>();
  const choiceFor = (ci: number): Choice => {
    let st = choices.get(ci);
    if (!st) {
      st = { text: new StreamReidentifier(vault), args: new Map(), names: new Map() };
      choices.set(ci, st);
    }
    return st;
  };
  // A call's name can arrive in fragments, so a policy that depends on the name waits for
  // the call to end (DeferredArgs). When every name is treated alike ("*", or nothing
  // restored) the arguments stream as they come.
  const argsFor = (st: Choice, key: string): ArgStream | DeferredArgs => {
    let a = st.args.get(key);
    if (!a) {
      a = restorePolicy.all || restorePolicy.none
        ? new ArgStream(argContext(vault, true, undefined, stats))
        : new DeferredArgs(() => argContext(vault, true, st.names.get(key), stats));
      st.args.set(key, a);
    }
    return a;
  };
  const chatFrame = (ci: number, delta: unknown) => `data: ${JSON.stringify({ choices: [{ index: ci, delta }] })}\n\n`;
  const argDelta = (key: string, chunk: string) =>
    key === "fc" ? { function_call: { arguments: chunk } } : { tool_calls: [{ index: Number(key.slice(1)), function: { arguments: chunk } }] };
  /** Everything one choice still holds, except what the current frame already carried. */
  const flushChoice = (ci: number, st: Choice, skipText: boolean, skipArgs: Set<string>): boolean => {
    if (!skipText) {
      const t = st.text.end();
      if (t) send(chatFrame(ci, { content: t }));
    }
    for (const [key, a] of st.args) {
      if (skipArgs.has(key)) continue;
      const chunk = a.end();
      if (!guard()) return false;
      if (chunk) send(chatFrame(ci, argDelta(key, chunk)));
    }
    return true;
  };

  /**
   * Whatever is still held, for the paths that end a stream rather than close it: the
   * terminal [DONE], the reader throwing, and an upstream that simply stops. Text tails
   * and tool-argument tails alike, in every dialect.
   */
  const flushHeld = () => {
    if (stopped) return;
    if (provider === "anthropic") {
      emitText(reider.end(), emitIndex);
      for (const index of [...toolBlocks.keys()]) if (!flushToolBlock(index)) return;
      return;
    }
    if (dialect === "responses") {
      flushAllParts();
      return;
    }
    for (const [ci, st] of choices) if (!flushChoice(ci, st, false, new Set())) return;
    choices.clear();
  };

  const handleFrame = (frame: string) => {
    if (stopped) return;
    const dataLine = frame.split("\n").find((l) => l.startsWith("data:"));
    const data = dataLine ? dataLine.slice(5).trim() : "";
    if (!data) {
      send(frame); // structural lines (event:, ping comments) pass through
      return;
    }
    if (data === "[DONE]") {
      flushHeld();
      if (!stopped) send(frame);
      return;
    }

    if (provider === "anthropic") {
      let j: any;
      try {
        j = JSON.parse(data);
      } catch {}
      const type = j?.type;
      if (type === "content_block_start") {
        const cb = j?.content_block;
        if (cb && ANTHROPIC_TOOL_BLOCKS.has(cb.type)) {
          const index = Number(j.index ?? 0);
          const name = typeof cb.name === "string" ? cb.name : undefined;
          toolBlocks.set(index, { name });
          // An input given whole at the start (not streamed as input_json_delta) is
          // restored here; the frame passes byte-for-byte when nothing in it changes.
          if (cb.input && typeof cb.input === "object") {
            // Restored on the frame's own text: a re-serialised input would lose the digits
            // of an integer beyond 2^53.
            const span = valueSpan(data, ["content_block", "input"]);
            if (span) {
              const raw = data.slice(span[0], span[1]);
              const restored = restoreArgs(raw, argContext(vault, true, name, stats));
              if (!guard()) return;
              send(restored === raw ? frame : frame.replace(/^data:.*$/m, () => `data: ${data.slice(0, span[0])}${restored}${data.slice(span[1])}`));
              return;
            }
            const changed = restoreArgObject(cb.input, argContext(vault, false, name, stats));
            if (!guard()) return;
            send(changed ? reframe(frame, j) : frame);
            return;
          }
        }
        send(frame);
        return;
      }
      if (type === "content_block_delta") {
        // Text deltas and a tool block's input fragments are restored; thinking_delta and
        // signature_delta carry nothing restorable and pass through at their own index.
        if (j.delta?.type === "text_delta") {
          emitIndex = j.index ?? emitIndex;
          emitText(reider.push(j.delta.text ?? ""), emitIndex); // suppress original, re-emit restored
        } else if (j.delta?.type === "input_json_delta") {
          const index = Number(j.index ?? 0);
          let blk = toolBlocks.get(index);
          if (!blk) toolBlocks.set(index, (blk = {}));
          blk.args ??= new ArgStream(argContext(vault, true, blk.name, stats));
          const chunk = blk.args.push(j.delta.partial_json ?? "");
          if (!guard()) return;
          emitJson(index, chunk);
        } else {
          send(frame);
        }
        return;
      }
      if (type === "content_block_stop") {
        const index = Number(j?.index ?? emitIndex);
        if (toolBlocks.has(index)) {
          if (!flushToolBlock(index)) return;
        } else emitText(reider.end(), index); // flush held text BEFORE this block closes
        send(frame);
        return;
      }
      send(frame); // message_start / message_delta / message_stop / ping / error
      return;
    }

    if (dialect === "responses") {
      let j: any;
      try {
        j = JSON.parse(data);
      } catch {}
      const type = j?.type;
      if (type === "response.output_item.added" && j.item && typeof j.item === "object") {
        if (RESPONSES_TOOL_ITEMS.has(j.item.type)) {
          const name = typeof j.item.name === "string" ? j.item.name : undefined;
          if (j.item.id !== undefined) itemTools.set(j.item.id, name);
          if (j.output_index !== undefined) indexTools.set(Number(j.output_index), name);
          // Arguments given whole on the added frame (not streamed) are restored here.
          if ((typeof j.item.arguments === "string" && j.item.arguments) || (typeof j.item.input === "string" && j.item.input)) {
            const item = reidentifyBody({ output: [j.item] }, provider, vault, dialect, stats).output[0];
            if (!guard()) return;
            send(reframe(frame, { ...j, item }));
            return;
          }
        }
        send(frame);
        return;
      }
      if (RESPONSES_ARGUMENT_DELTAS.has(type)) {
        // A tool call's arguments or a custom tool's input, fragment by fragment: the
        // values the caller's tool will run on. A function or MCP call's arguments are
        // JSON (values JSON-escaped); a custom tool's input is plain text.
        const { delta: _d, ...ctx } = j;
        const json = RESPONSES_JSON_ARGUMENT_DELTAS.has(type);
        const part = partFor(j, ctx, () => new ArgStream(argContext(vault, json, toolFor(j), stats)));
        const chunk = part.r.push(j.delta ?? "");
        if (!guard()) return;
        emitText(chunk, 0, part.ctx);
        return;
      }
      if (RESPONSES_JSON_ARGUMENT_DONE.has(type)) {
        // The whole document, restored on its raw text: byte-for-byte what the deltas
        // above joined into.
        if (!flushPart(j)) return;
        if (typeof j.arguments === "string") j.arguments = restoreArgs(j.arguments, argContext(vault, true, toolFor(j), stats));
        if (!guard()) return;
        send(reframe(frame, j));
        return;
      }
      if (type === "response.custom_tool_call_input.done") {
        if (!flushPart(j)) return;
        if (typeof j.input === "string") j.input = restoreArgs(j.input, argContext(vault, false, toolFor(j), stats));
        if (!guard()) return;
        send(reframe(frame, j));
        return;
      }
      if (type === "response.output_text.delta" || type === "response.refusal.delta") {
        // Suppress the original delta, re-emit the restorable prefix under the same
        // addressing AND the same event type — a refusal delta re-emitted as output
        // text would break a client that reads refusal events; the possibly-forming
        // tail stays held in the re-identifier.
        const { delta: _d, ...ctx } = j;
        const part = partFor(j, ctx, () => new StreamReidentifier(vault));
        emitText(part.r.push(j.delta ?? ""), 0, part.ctx);
        return;
      }
      // Every frame below carries the text in full, so the held tail is flushed first
      // (a placeholder split across deltas is then already restored on the client) and
      // the frame's own text is restored before it passes.
      if (type === "response.output_text.done" || type === "response.refusal.done") {
        if (!flushPart(j)) return;
        if (typeof j.text === "string") j.text = restore(j.text, vault);
        if (typeof j.refusal === "string") j.refusal = restore(j.refusal, vault);
        send(reframe(frame, j));
        return;
      }
      if (type === "response.content_part.done" && j.part && typeof j.part === "object") {
        if (!flushPart(j)) return;
        if (typeof j.part.text === "string") j.part.text = restore(j.part.text, vault);
        if (typeof j.part.refusal === "string") j.part.refusal = restore(j.part.refusal, vault);
        send(reframe(frame, j));
        return;
      }
      if (type === "response.output_item.done" && j.item && typeof j.item === "object") {
        if (!flushOutputItem(j)) return;
        const item = reidentifyBody({ output: [j.item] }, provider, vault, dialect, stats).output[0];
        if (!guard()) return;
        send(reframe(frame, { ...j, item }));
        return;
      }
      if (type === "response.completed" || type === "response.incomplete" || type === "response.failed") {
        if (!flushAllParts()) return;
        if (j.response && typeof j.response === "object") {
          const response = reidentifyBody(j.response, provider, vault, dialect, stats);
          if (!guard()) return;
          send(reframe(frame, { ...j, response }));
        } else send(frame);
        return;
      }
      send(frame); // response.created / in_progress / content_part.added / ping / error
      return;
    }

    // ---- chat completions ----
    // Each frame is rewritten in place, so a frame carrying text and tool-call fragments
    // together (or a finish_reason with its last fragment) keeps all of them, and the
    // provider's other fields (id, model, created, a tool call's id and name) pass as sent.
    let oj: any;
    try {
      oj = JSON.parse(data);
    } catch {}
    if (!oj || !Array.isArray(oj.choices)) {
      send(frame); // an error object or anything else without choices
      return;
    }
    let changed = false;
    const finishing: Array<{ ci: number; st: Choice; hadText: boolean; hadArgs: Set<string> }> = [];
    for (const ch of oj.choices) {
      if (!ch || typeof ch !== "object") continue;
      const ci = Number(ch.index ?? 0);
      const st = choiceFor(ci);
      const d = ch.delta;
      const fin = ch.finish_reason != null;
      let hadText = false;
      const hadArgs = new Set<string>();
      if (d && typeof d.content === "string" && d.content.length) {
        d.content = st.text.push(d.content) + (fin ? st.text.end() : "");
        changed = hadText = true;
      }
      for (const tc of Array.isArray(d?.tool_calls) ? d.tool_calls : []) {
        const key = `t${Number(tc?.index ?? 0)}`;
        if (typeof tc?.function?.name === "string") st.names.set(key, (st.names.get(key) ?? "") + tc.function.name);
        if (typeof tc?.function?.arguments === "string") {
          const a = argsFor(st, key);
          tc.function.arguments = a.push(tc.function.arguments) + (fin ? a.end() : "");
          changed = true;
          hadArgs.add(key);
        }
      }
      const fc = d?.function_call;
      if (fc && typeof fc === "object") {
        if (typeof fc.name === "string") st.names.set("fc", (st.names.get("fc") ?? "") + fc.name);
        if (typeof fc.arguments === "string") {
          const a = argsFor(st, "fc");
          fc.arguments = a.push(fc.arguments) + (fin ? a.end() : "");
          changed = true;
          hadArgs.add("fc");
        }
      }
      if (fin) finishing.push({ ci, st, hadText, hadArgs });
    }
    if (!guard()) return;
    // A choice that finishes in this frame: whatever it still holds that this frame did
    // not carry goes out first, so the finish comes after every argument fragment.
    for (const f of finishing) {
      if (!flushChoice(f.ci, f.st, f.hadText, f.hadArgs)) return;
      choices.delete(f.ci);
    }
    send(changed ? reframe(frame, oj) : frame);
  };

  const reader = upBody.getReader();
  const dec = new TextDecoder();
  let buf = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i: number;
      while ((i = buf.indexOf("\n\n")) !== -1) {
        const frame = buf.slice(0, i + 2);
        buf = buf.slice(i + 2);
        handleFrame(frame);
      }
      if (stopped) break;
    }
    if (buf.length && !stopped) handleFrame(buf); // trailing frame without a terminating blank line
  } catch {
    flushHeld(); // best-effort restore of whatever was held
    res.end();
    return;
  }
  if (stopped) {
    try {
      await reader.cancel();
    } catch {}
  }

  flushHeld(); // safety: flush if the stream ended without an explicit close frame
  res.end();
}
