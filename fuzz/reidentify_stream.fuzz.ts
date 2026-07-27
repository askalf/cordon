// Fuzz target: the boundary-safe streaming re-identifier.
//
// StreamReidentifier is the subtlest code in cordon. A placeholder like
// <EMAIL_1> arrives from the provider split across arbitrary SSE frames
// (`<EMA` … `IL_1>`), so the restorer holds back any tail that could still be
// growing into a token. Two ways that goes wrong, both client-visible:
//   - flush too eagerly and the client receives a raw `<EMAIL_1>` placeholder
//     instead of the value it sent — reversible mode silently degraded;
//   - hold too much and the held text is never emitted at all — truncated answer.
//
// The invariant that captures both at once is CHUNKING INVARIANCE: streaming a
// text through any arbitrary split must produce exactly what restoring the whole
// text at once produces. The fuzzer chooses the split points, which is precisely
// the adversarial-framing search a fixed unit test can't do.
//
// The text being chunked is untrusted twice over: it is the model's output, and
// the model was reading attacker-supplied prompt text — so a page that convinces
// the model to emit near-miss placeholder syntax (`<EMAIL_`, `<EMAIL_11>`,
// `<<EMAIL_1>`) is reachable in production.
//
// Neither push() nor end() has a throw contract — they run mid-stream, where the
// response headers are already sent and there is no fail-closed path left.
import { StreamReidentifier } from '../src/redact/reidentify';
import { PLACEHOLDER_RE, Vault } from '../src/redact/vault';

export function fuzz(data: Buffer): void {
  const text = data.toString('utf8');

  // Build a vault holding a few real mappings so there is something to restore,
  // then let the fuzzed text decide how tokens appear in the stream.
  const vault = new Vault('reversible');
  const email = vault.placeholderFor('john@acme.com', 'EMAIL');
  const card = vault.placeholderFor('4012-8888-8888-1881', 'CREDIT_CARD');
  const ssn = vault.placeholderFor('123-45-6789', 'SSN');

  // Weave the real placeholders into the fuzzed text so split points land inside
  // them; the fuzzed bytes supply the hostile near-miss syntax around them.
  const stream = `${text}${email} and ${card}${text.slice(0, 32)}${ssn}`;

  // Reference: restore the whole thing in one go.
  const oneShot = stream.replace(PLACEHOLDER_RE, (m) => vault.lookup(m) ?? m);

  // Derive chunk boundaries from the input so the fuzzer searches split points.
  const re = new StreamReidentifier(vault);
  let out = '';
  let i = 0;
  let k = 0;
  while (i < stream.length) {
    // 1..64 chars per chunk, driven by the input bytes.
    const step = data.length ? (data[k++ % data.length] % 64) + 1 : 17;
    out += re.push(stream.slice(i, i + step));
    i += step;
  }
  out += re.end();

  if (out !== oneShot) {
    throw new Error(
      `chunking changed the restored output (streamed ${JSON.stringify(out.slice(0, 200))} ` +
        `vs one-shot ${JSON.stringify(oneShot.slice(0, 200))})`,
    );
  }

  // Nothing may be swallowed: every mapped value that the one-shot restore
  // produced must also survive the streamed path. (Implied by equality above,
  // but asserted explicitly so a future refactor that weakens the equality
  // check still fails here.)
  for (const value of ['john@acme.com', '4012-8888-8888-1881', '123-45-6789']) {
    if (oneShot.includes(value) && !out.includes(value)) {
      throw new Error(`streamed output dropped a restored value: ${value}`);
    }
  }

  // A stream that ends mid-token must not emit a partial placeholder to the
  // client when that partial resolves to exactly one known value — leaking
  // `<EMAIL_1` instead of the address is the truncation bug resolvePartial exists
  // to fix. Feed a genuinely truncated tail and require it to be resolved.
  const trunc = new StreamReidentifier(vault);
  const cut = email.slice(0, email.length - 1); // "<EMAIL_1" — no closing '>'
  let tailOut = trunc.push(text.slice(0, 16) + cut);
  tailOut += trunc.end();
  if (vault.resolvePartial(cut) !== undefined && tailOut.endsWith(cut)) {
    throw new Error(`truncated stream emitted the partial placeholder ${cut} verbatim`);
  }
}
