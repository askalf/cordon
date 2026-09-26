// Fuzz target: the de-identification pass — cordon's actual product guarantee.
//
// applyRedaction() builds the body that is sent to the provider. The guarantee
// on the tin is "the model never sees raw PII", so the invariant here is a LEAK
// check, not just a crash check: every value cordon itself decided was an entity
// must be gone from the body it forwards.
//
// The check is stated as an OCCURRENCE COUNT rather than mere presence, because
// presence is wrong on self-overlapping text — see the comment on the check
// itself. It is also scoped to values the detector actually claimed: asserting
// "no detectable PII survives" in the absolute would flag detector coverage gaps
// (a pattern that never matched at all), which is a different bug class. What
// makes a leak a FAIL-OPEN is cordon finding a value, counting it in the audit
// log and the X-Redacted header, and then forwarding it anyway.
//
// Body keys come straight off the wire, so a leaf can literally be named
// `__proto__` or `constructor` — apply.ts defends that with defineProperty, and
// this target asserts the prototype is still clean afterwards.
//
// applyRedaction has no throw contract on a hostile BODY: proxy.ts turns any
// throw into a fail-closed 422, so a body shape that reliably throws is a remote
// DoS on the gateway. Hence no try/catch.
import { detector } from '../src/detect/index';
import { applyRedaction } from '../src/redact/apply';
import { reidentifyBody } from '../src/redact/reidentify';
import { Vault } from '../src/redact/vault';
import type { Dialect, Provider, RedactMode, RedactSet } from '../src/types';

const ALL_SETS: RedactSet[] = ['pii', 'phi', 'pci', 'secrets'];
const MODES: RedactMode[] = ['reversible', 'strip'];

/** Split the input into a few chunks the body template can be built from. */
function fields(text: string): string[] {
  const parts = text.split('\u0000');
  return parts.length >= 2 ? parts : [text, text.slice(Math.floor(text.length / 2))];
}

/**
 * Every string/number leaf of a body, joined. Comparing leaves directly (rather
 * than JSON.stringify output) keeps the count exact: JSON escaping would rewrite
 * quotes, backslashes and control characters, so a value containing them would
 * silently never be found and the check would pass vacuously.
 */
function allLeafText(node: any, out: string[] = [], depth = 0): string[] {
  if (depth > 20 || node == null) return out;
  if (typeof node === 'string') out.push(node);
  else if (typeof node === 'number' || typeof node === 'bigint') out.push(String(node));
  else if (typeof node === 'object')
    for (const k of Object.keys(node)) allLeafText((node as any)[k], out, depth + 1);
  return out;
}

/** Occurrences of `needle` in `hay`, INCLUDING overlapping ones — repeated text
 *  is exactly where the leak check has to be exact. */
function countOccurrences(hay: string, needle: string): number {
  if (!needle) return 0;
  let n = 0;
  for (let i = hay.indexOf(needle); i !== -1; i = hay.indexOf(needle, i + 1)) n++;
  return n;
}

/**
 * A Responses API body carrying the fuzzed text in every input shape the walk reads:
 * message content (string and part array, including a prior assistant turn), tool calls
 * and their outputs for each tool kind (string and part-array outputs), an item type the
 * walk has no special case for, tool descriptions, and prompt variables. The walk is
 * fail-closed over item types, so the unknown item must come out as redacted as the rest.
 */
function responsesBody(a: string, b: string, c: string): any {
  return {
    model: 'gpt-4o',
    instructions: b,
    input: [
      { role: 'user', content: a },
      {
        role: 'user',
        content: [
          { type: 'input_text', text: b },
          { type: 'input_image', image_url: 'data:image/png;base64,AAAA' },
        ],
      },
      { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: c, annotations: [] }] },
      { type: 'function_call', call_id: 'call_1', name: 'f', arguments: JSON.stringify({ q: a, n: c }) },
      { type: 'function_call_output', call_id: 'call_1', output: [{ type: 'input_text', text: b }] },
      { type: 'custom_tool_call', call_id: 'call_2', name: 'g', input: c },
      { type: 'custom_tool_call_output', call_id: 'call_2', output: a },
      { type: 'local_shell_call_output', call_id: 'call_3', output: b },
      { type: 'future_item', id: 'fi_1', payload: { note: c, list: [a] } },
    ],
    tools: [
      { type: 'function', name: 'f', description: b, parameters: { example: c } },
      { type: 'custom', name: 'g', description: a },
    ],
    prompt: { id: 'pmpt_1', variables: { v: a, w: { type: 'input_text', text: c } } },
  };
}

export function fuzz(data: Buffer): void {
  const text = data.toString('utf8');
  const sel = data.length ? data[0] : 0;
  const provider: Provider = sel & 1 ? 'openai' : 'anthropic';
  const mode = MODES[(sel >> 1) % MODES.length];
  // Bit 2 sends an OpenAI input through the Responses API walk instead of chat.completions.
  const dialect: Dialect = provider === 'anthropic' ? 'messages' : sel & 4 ? 'responses' : 'chat';
  const [a, b = '', c = ''] = fields(text);

  // Exercise the structured, model-visible fields as well as plain content —
  // tool arguments and tool schemas carry user data and are redacted too.
  const body: any =
    dialect === 'responses'
      ? responsesBody(a, b, c)
      : provider === 'anthropic'
      ? {
          model: 'claude-haiku-4-5',
          system: b,
          messages: [
            { role: 'user', content: a },
            {
              role: 'assistant',
              content: [
                { type: 'text', text: b },
                { type: 'tool_use', input: { note: c, nested: { deep: a } } },
              ],
            },
            { role: 'user', content: [{ type: 'tool_result', content: c }] },
          ],
          tools: [{ name: 't', description: b, input_schema: { example: a } }],
        }
      : {
          model: 'gpt-4o',
          messages: [
            { role: 'system', content: b },
            { role: 'user', content: a, name: c },
            {
              role: 'assistant',
              content: null,
              // arguments is a JSON STRING: parsed, redacted leaf-wise and
              // re-serialized, so a redacted numeric leaf must stay valid JSON.
              tool_calls: [{ function: { name: 'f', arguments: JSON.stringify({ q: a, n: c }) } }],
            },
          ],
          tools: [{ function: { name: 'f', description: b, parameters: { example: c } } }],
        };

  const beforeText = allLeafText(body).join('\u0000');
  const vault = new Vault(mode);
  const { deidBody, spans } = applyRedaction(body, provider, vault, ALL_SETS, detector, true, dialect);

  // A hostile key name must not have reached Object.prototype.
  if (({} as any).polluted !== undefined || (Object.prototype as any).polluted !== undefined) {
    throw new Error('prototype pollution via a redacted leaf key');
  }

  // Walk coverage (Responses). The occurrence budget below only covers values the
  // detector claimed, so a field the walk never read would pass it. Detection is per
  // field and deterministic, and the vault maps a value to one token, so every field
  // carrying the same fuzzed text must come out exactly like the message field holding
  // that text. A skipped field still holds the raw text and fails this.
  if (dialect === 'responses') {
    const d = deidBody;
    const [A, B, C] = [d.input[0].content, d.input[1].content[0].text, d.input[2].content[0].text];
    let args: any;
    try {
      args = JSON.parse(d.input[3].arguments);
    } catch {
      throw new Error('function_call.arguments is no longer valid JSON after redaction');
    }
    const fieldsOf: Array<[string, unknown, string]> = [
      ['instructions', d.instructions, B],
      ['function_call.arguments.q', args.q, A],
      ['function_call.arguments.n', args.n, C],
      ['function_call_output.output[0].text', d.input[4].output[0].text, B],
      ['custom_tool_call.input', d.input[5].input, C],
      ['custom_tool_call_output.output', d.input[6].output, A],
      ['local_shell_call_output.output', d.input[7].output, B],
      ['future_item.payload.note', d.input[8].payload.note, C],
      ['future_item.payload.list[0]', d.input[8].payload.list[0], A],
      ['tools[0].description', d.tools[0].description, B],
      ['tools[0].parameters.example', d.tools[0].parameters.example, C],
      ['tools[1].description', d.tools[1].description, A],
      ['prompt.variables.v', d.prompt.variables.v, A],
      ['prompt.variables.w.text', d.prompt.variables.w.text, C],
    ];
    for (const [label, got, want] of fieldsOf)
      if (got !== want) throw new Error(`Responses ${label} was not de-identified like the message text it copies (mode=${mode})`);
  }

  if (!spans.length) return; // nothing was detected — nothing to leak

  // THE guarantee, as an occurrence count.
  //
  // Presence alone is the wrong test on self-overlapping text: `'1'.repeat(500)`
  // yields ONE 13-digit PHONE span, and once that span is spliced out the
  // REMAINING digits still spell an identical-looking 13-run. That survivor is a
  // different occurrence the detector never claimed — a coverage question, not a
  // leak. So each value gets a budget: however many times it appeared originally,
  // minus the occurrences the detector actually claimed. Unclaimed occurrences
  // may survive; every claimed one must be gone.
  //
  // This still catches the real fail-open mechanism — stale or overlapping
  // offsets making the right-to-left splice miss one of several occurrences —
  // because that shows up as a count that failed to drop by the claimed amount.
  const afterText = allLeafText(deidBody).join('\u0000');
  const claimed = new Map<string, number>();
  for (const s of spans) claimed.set(s.value, (claimed.get(s.value) ?? 0) + 1);

  for (const [value, n] of claimed) {
    const budget = Math.max(0, countOccurrences(beforeText, value) - n);
    const survived = countOccurrences(afterText, value);
    if (survived > budget) {
      throw new Error(
        `redacted value survived into the de-identified body: ${survived} occurrence(s) ` +
          `remain but at most ${budget} allowed (${n} claimed, type=${
            spans.find((s) => s.value === value)?.type
          }, mode=${mode}, provider=${provider}, dialect=${dialect})`,
      );
    }
  }

  // strip mode is irreversible by design — it must not retain a reverse map,
  // or the "nothing is restored" hardened guarantee is a lie.
  if (mode === 'strip' && vault.hasReverse) {
    throw new Error('strip mode retained a reverse mapping');
  }

  // Reversible mode must round-trip: a response echoing the placeholders comes
  // back as the original values. If restoration is lossy the client gets a
  // corrupted answer, which is the failure that makes reversible mode unusable.
  if (mode === 'reversible' && vault.hasReverse) {
    const placeholders = spans.map((s) => vault.placeholderFor(s.value, s.type));
    const echoed = placeholders.join(' ');
    const response =
      dialect === 'responses'
        ? { output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: echoed }] }] }
        : provider === 'anthropic'
        ? { content: [{ type: 'text', text: echoed }] }
        : { choices: [{ message: { role: 'assistant', content: echoed } }] };
    const restoredBody: any = reidentifyBody(response, provider, vault, dialect);
    const restored: string =
      dialect === 'responses'
        ? restoredBody.output[0].content[0].text
        : provider === 'anthropic'
        ? restoredBody.content[0].text
        : restoredBody.choices[0].message.content;
    for (const placeholder of placeholders) {
      if (restored.includes(placeholder)) {
        throw new Error(`placeholder ${placeholder} was not restored by reidentifyBody`);
      }
    }
  }
}
