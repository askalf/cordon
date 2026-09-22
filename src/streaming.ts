import type { Dialect, HttpRes, Provider } from "./types";
import type { ProviderAdapter } from "./providers";
import { reidentifyBody, restore, StreamReidentifier } from "./redact/reidentify";
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
 * Reversible streaming: tee the upstream SSE stream while restoring real values in
 * flight. Text-carrying frames are suppressed and re-emitted (re-identified) via the
 * adapter; structural frames (message_start, usage, finish, [DONE]) pass through
 * verbatim. The held-back tail is flushed right before each text block closes, so a
 * placeholder split across a frame boundary is still restored before the client sees
 * the block end.
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

  const reider = new StreamReidentifier(vault);
  // The content-block index our re-emitted text frames target. Anthropic responses can
  // interleave blocks (a `thinking` block at index 0, the `text` block at index 1, plus
  // tool_use blocks); a re-emitted text_delta MUST carry the matching block index or the
  // client SDK throws "Content block is not a text block". OpenAI has no block index → 0.
  let emitIndex = 0;
  // Responses addresses a delta by item_id / output_index / content_index; a re-emitted
  // delta carries the addressing of the frame it stands in for.
  let emitCtx: Record<string, unknown> = {};
  const emitText = (chunk: string, index = emitIndex, ctx = emitCtx) => {
    if (chunk) res.write(adapter.frameFromText(chunk, index, ctx));
  };
  const flushTail = () => emitText(reider.end(), emitIndex);

  // A Responses stream can carry several content parts at once (two output items, or two
  // content indices of one item) and their deltas interleave. One buffer for all of them
  // would splice part B's text into a placeholder part A had half-written, and re-emit it
  // under B's address. Each part gets its own re-identifier and its own addressing, and
  // is flushed and dropped when that part's own done frame arrives.
  const parts = new Map<string, { reider: StreamReidentifier; ctx: Record<string, unknown> }>();
  const partKey = (j: any) => `${j?.item_id ?? ""}/${j?.output_index ?? 0}/${j?.content_index ?? 0}`;
  const partFor = (j: any, ctx: Record<string, unknown>) => {
    const key = partKey(j);
    const found = parts.get(key);
    if (found) { found.ctx = ctx; return found; }
    const made = { reider: new StreamReidentifier(vault), ctx };
    parts.set(key, made);
    return made;
  };
  /** Flush one part's held tail under its own addressing and forget it. */
  const flushPart = (j: any) => {
    const key = partKey(j);
    const part = parts.get(key);
    if (!part) return;
    emitText(part.reider.end(), 0, part.ctx);
    parts.delete(key);
  };
  /** Flush the parts matching `pick`, each under its own addressing, and forget them. */
  const flushParts = (pick: (ctx: Record<string, unknown>) => boolean) => {
    for (const [key, part] of parts) {
      if (!pick(part.ctx)) continue;
      emitText(part.reider.end(), 0, part.ctx);
      parts.delete(key);
    }
  };
  /** Every part still open: only for the frames that close the whole response. */
  const flushAllParts = () => flushParts(() => true);
  /**
   * Whatever this dialect is holding, for the paths that end a stream rather than
   * close it: the terminal frame, the reader throwing, and an upstream that simply
   * stops. Responses keeps its held text in the per-part map, so calling the single
   * `flushTail` buffer there emits nothing and the client loses the tail.
   */
  const flushHeld = () => (dialect === "responses" ? flushAllParts() : flushTail());
  /**
   * The parts of ONE output item, on its `output_item.done`. Closing item A must not
   * end item B's re-identifier: B may be holding a half-written placeholder, and
   * ending it early emits the resolved value and then B's own suffix separately.
   */
  const flushOutputItem = (j: any) => {
    const id = j?.item?.id;
    const idx = j?.output_index;
    flushParts((ctx) => (id !== undefined && ctx["item_id"] === id) || (idx !== undefined && ctx["output_index"] === idx));
  };

  const handleFrame = (frame: string) => {
    const dataLine = frame.split("\n").find((l) => l.startsWith("data:"));
    const data = dataLine ? dataLine.slice(5).trim() : "";
    if (!data) {
      res.write(frame); // structural lines (event:, ping comments) pass through
      return;
    }
    if (data === "[DONE]") {
      flushHeld();
      res.write(frame);
      return;
    }

    if (provider === "anthropic") {
      let j: any;
      try {
        j = JSON.parse(data);
      } catch {}
      const type = j?.type;
      if (type === "content_block_delta") {
        // Re-identify ONLY text deltas (matching the non-streaming path, which restores
        // type:"text" blocks only). thinking_delta / signature_delta / input_json_delta
        // carry no restorable assistant text and pass through verbatim at their own index.
        if (j.delta?.type === "text_delta") {
          emitIndex = j.index ?? emitIndex;
          emitText(reider.push(j.delta.text ?? ""), emitIndex); // suppress original, re-emit restored
        } else {
          res.write(frame);
        }
        return;
      }
      if (type === "content_block_stop") {
        emitText(reider.end(), j?.index ?? emitIndex); // flush held text BEFORE this block closes (no-op for non-text)
        res.write(frame);
        return;
      }
      res.write(frame); // content_block_start / message_start / message_delta / message_stop / ping
      return;
    }

    if (dialect === "responses") {
      let j: any;
      try {
        j = JSON.parse(data);
      } catch {}
      const type = j?.type;
      if (type === "response.output_text.delta" || type === "response.refusal.delta") {
        // Suppress the original delta, re-emit the restorable prefix under the same
        // addressing AND the same event type — a refusal delta re-emitted as output
        // text would break a client that reads refusal events; the possibly-forming
        // tail stays held in the re-identifier.
        const { delta: _d, ...ctx } = j;
        const part = partFor(j, ctx);
        emitText(part.reider.push(j.delta ?? ""), 0, part.ctx);
        return;
      }
      // Every frame below carries the text in full, so the held tail is flushed first
      // (a placeholder split across deltas is then already restored on the client) and
      // the frame's own text is restored before it passes.
      if (type === "response.output_text.done" || type === "response.refusal.done") {
        flushPart(j);
        if (typeof j.text === "string") j.text = restore(j.text, vault);
        if (typeof j.refusal === "string") j.refusal = restore(j.refusal, vault);
        res.write(reframe(frame, j));
        return;
      }
      if (type === "response.content_part.done" && j.part && typeof j.part === "object") {
        flushPart(j);
        if (typeof j.part.text === "string") j.part.text = restore(j.part.text, vault);
        if (typeof j.part.refusal === "string") j.part.refusal = restore(j.part.refusal, vault);
        res.write(reframe(frame, j));
        return;
      }
      if (type === "response.output_item.done" && j.item && typeof j.item === "object") {
        flushOutputItem(j);
        res.write(reframe(frame, { ...j, item: reidentifyBody({ output: [j.item] }, provider, vault, dialect).output[0] }));
        return;
      }
      if (type === "response.completed" || type === "response.incomplete" || type === "response.failed") {
        flushAllParts();
        if (j.response && typeof j.response === "object")
          res.write(reframe(frame, { ...j, response: reidentifyBody(j.response, provider, vault, dialect) }));
        else res.write(frame);
        return;
      }
      res.write(frame); // response.created / in_progress / output_item.added / content_part.added / function-call frames / ping
      return;
    }

    // openai
    let ch: any;
    try {
      ch = JSON.parse(data).choices?.[0];
    } catch {}
    const content = ch?.delta?.content;
    if (typeof content === "string" && content.length) {
      emitText(reider.push(content)); // suppress original
      return;
    }
    if (ch?.finish_reason != null) {
      flushTail();
      res.write(frame);
      return;
    }
    res.write(frame); // role frame / empty delta / other
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
    }
    if (buf.length) handleFrame(buf); // trailing frame without a terminating blank line
  } catch {
    flushHeld(); // best-effort restore of whatever was held
    res.end();
    return;
  }

  flushHeld(); // safety: flush if the stream ended without an explicit close frame
  res.end();
}
