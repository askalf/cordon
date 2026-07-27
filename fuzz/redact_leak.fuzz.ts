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
import type { Provider, RedactMode, RedactSet } from '../src/types';

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

export function fuzz(data: Buffer): void {
  const text = data.toString('utf8');
  const sel = data.length ? data[0] : 0;
  const provider: Provider = sel & 1 ? 'openai' : 'anthropic';
  const mode = MODES[(sel >> 1) % MODES.length];
  const [a, b = '', c = ''] = fields(text);

  // Exercise the structured, model-visible fields as well as plain content —
  // tool arguments and tool schemas carry user data and are redacted too.
  const body: any =
    provider === 'anthropic'
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
  const { deidBody, spans } = applyRedaction(body, provider, vault, ALL_SETS, detector, true);

  // A hostile key name must not have reached Object.prototype.
  if (({} as any).polluted !== undefined || (Object.prototype as any).polluted !== undefined) {
    throw new Error('prototype pollution via a redacted leaf key');
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
          }, mode=${mode}, provider=${provider})`,
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
      provider === 'anthropic'
        ? { content: [{ type: 'text', text: echoed }] }
        : { choices: [{ message: { role: 'assistant', content: echoed } }] };
    const restoredBody: any = reidentifyBody(response, provider, vault);
    const restored: string =
      provider === 'anthropic'
        ? restoredBody.content[0].text
        : restoredBody.choices[0].message.content;
    for (const placeholder of placeholders) {
      if (restored.includes(placeholder)) {
        throw new Error(`placeholder ${placeholder} was not restored by reidentifyBody`);
      }
    }
  }
}
