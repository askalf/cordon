import type { HttpRes, Provider } from "./types";
import type { ProviderAdapter } from "./providers";
import { StreamReidentifier } from "./redact/reidentify";
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
): Promise<void> {
  res.setHeader("content-type", "text/event-stream");
  res.setHeader("cache-control", "no-cache");

  const reider = new StreamReidentifier(vault);
  // The content-block index our re-emitted text frames target. Anthropic responses can
  // interleave blocks (a `thinking` block at index 0, the `text` block at index 1, plus
  // tool_use blocks); a re-emitted text_delta MUST carry the matching block index or the
  // client SDK throws "Content block is not a text block". OpenAI has no block index → 0.
  let emitIndex = 0;
  const emitText = (chunk: string, index = emitIndex) => {
    if (chunk) res.write(adapter.frameFromText(chunk, index));
  };
  const flushTail = () => emitText(reider.end(), emitIndex);

  const handleFrame = (frame: string) => {
    const dataLine = frame.split("\n").find((l) => l.startsWith("data:"));
    const data = dataLine ? dataLine.slice(5).trim() : "";
    if (!data) {
      res.write(frame); // structural lines (event:, ping comments) pass through
      return;
    }
    if (data === "[DONE]") {
      flushTail();
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
    flushTail(); // best-effort restore of whatever was held
    res.end();
    return;
  }

  flushTail(); // safety: flush if the stream ended without an explicit close frame
  res.end();
}
