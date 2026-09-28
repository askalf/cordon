import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { allLeafText } from './leaf-text.ts';
import { fuzz } from './redact_leak.fuzz.ts';

const shapes = {
  responses: (argumentsText) => ({ input: [{ type: 'function_call', arguments: argumentsText }] }),
  chat: (argumentsText) => ({ messages: [{ tool_calls: [{ function: { arguments: argumentsText } }] }] }),
};
for (const [dialect, shape] of Object.entries(shapes)) {
  for (const value of ['11\nST', 'a\\b', 'a"b']) {
    const encoded = JSON.stringify({ q: value, nested: [value, 123], arguments: JSON.stringify({ q: value }) });
    const leaves = allLeafText(shape(encoded), dialect);
    assert.equal(leaves.filter((s) => s === value).length, 2);
    assert.ok(leaves.includes('123'));
    assert.ok(leaves.includes(JSON.stringify({ q: value })), 'decoded user keys must not trigger recursive parsing');
    const ordinary = { messages: [{ content: encoded }], input: [{ content: encoded }] };
    assert.equal(allLeafText(ordinary, dialect).filter((s) => s === encoded).length, 2);
  }
  for (const text of ['{"q":"11\\nST"', '"11\\nST"', 'null', '123']) {
    assert.ok(allLeafText(shape(text), dialect).includes(text), 'malformed/primitive JSON must stay raw');
  }
  assert.ok(allLeafText(shape('[]'), dialect).every((s) => s !== '[]'));
}
assert.deepEqual(allLeafText({ input: { arguments: '{"q":"x"}' } }, 'messages'), ['{"q":"x"}']);

// Claimed address + unclaimed duplicates, including the reduced CI crash. Both
// OpenAI dialects and both modes must preserve the same occurrence budget.
for (const selector of [1, 3, 5, 7]) {
  fuzz(Buffer.from(String.fromCharCode(selector) + '11\nST\u0000x11\nST123'));
  fuzz(Buffer.from(String.fromCharCode(selector) + '11 ST\u0000x11 ST123'));
}

// Exercise the ACTUAL oracle, not a duplicate budget implementation: inject a
// missed replacement in one argument after the independent walk-coverage check.
// A claimed decoded occurrence reaching the provider must still fail.
const target = new URL(`./.leak-negative-${process.pid}.ts`, import.meta.url);
const source = readFileSync(new URL('./redact_leak.fuzz.ts', import.meta.url), 'utf8');
const anchor = '  const afterText = allLeafText(deidBody, dialect)';
assert.equal(source.split(anchor).length, 2);
writeFileSync(target, source.replace(anchor,
  '  if (dialect === "responses") deidBody.input[3].arguments = body.input[3].arguments;\n' +
  '  else deidBody.messages[2].tool_calls[0].function.arguments = body.messages[2].tool_calls[0].function.arguments;\n' + anchor));
try {
  const { fuzz: missedReplacement } = await import(target.href);
  for (const selector of [1, 3, 5, 7]) {
    assert.throws(() => missedReplacement(Buffer.from(String.fromCharCode(selector) + '11\nST\u0000x11\nST123')),
      /redacted value survived into the de-identified body/);
  }
} finally { unlinkSync(target); }
console.log('PASS  decoded argument leaf oracle regressions and missed-replacement controls');
