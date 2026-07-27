// Fuzz target: the detector over raw untrusted bytes.
//
// runAll() is the first thing that touches attacker-controlled prompt text, and
// it sits INSIDE cordon's fail-closed boundary (proxy.ts wraps applyRedaction in
// try/catch). It therefore has no throw contract at all: any uncontrolled
// exception is a crafted prompt that turns every request into a 422, and under
// the FAIL_MODE=open escape hatch it is worse — the ORIGINAL body is forwarded
// upstream with the PII intact. That is the fail-open this target exists to find.
//
// The span invariants are load-bearing downstream. replaceSpans() splices
// right-to-left assuming spans are well-formed, in-range and non-overlapping; a
// span whose offsets don't match its value, or that overlaps its neighbour,
// silently corrupts the de-identified body — which in reversible mode corrupts
// the answer the client gets back.
//
// This target is also the ReDoS surface: the catalog is regex-driven (EMAIL and
// STREET_ADDRESS have the classic nested-quantifier shapes), so libFuzzer's
// timeout is what catches catastrophic backtracking on an adversarial prompt.
import { runAll } from '../src/detect/index';
import type { RedactSet } from '../src/types';

const SET_COMBOS: RedactSet[][] = [
  ['pii', 'phi', 'pci', 'secrets'],
  ['pii'],
  ['pci'],
  ['secrets'],
  ['phi', 'pci'],
];

export function fuzz(data: Buffer): void {
  const text = data.toString('utf8');

  // The first byte picks the active-set combination, so the fuzzer can steer
  // which half of the catalog runs — the set filter is itself parsed input.
  const combo = SET_COMBOS[(data.length ? data[0] : 0) % SET_COMBOS.length];

  // No try/catch: runAll has no sanctioned throw on hostile input.
  const spans = runAll(text, combo);

  let prevEnd = -1;
  for (const s of spans) {
    if (!Number.isInteger(s.start) || !Number.isInteger(s.end)) {
      throw new Error(`non-integer span offsets: ${s.type} [${s.start},${s.end})`);
    }
    if (s.start < 0 || s.end > text.length || s.end <= s.start) {
      throw new Error(
        `span out of range for text length ${text.length}: ${s.type} [${s.start},${s.end})`,
      );
    }
    // replaceSpans() splices by offset and the vault stores `value` as the thing
    // to restore, so the two MUST agree — otherwise reversible mode restores a
    // value that was never in the prompt.
    if (s.value !== text.slice(s.start, s.end)) {
      throw new Error(
        `span value does not match its offsets: ${s.type} [${s.start},${s.end}) ` +
          `value=${JSON.stringify(s.value)} slice=${JSON.stringify(text.slice(s.start, s.end))}`,
      );
    }
    // Sorted-by-start AND non-overlapping. Overlap resolution is the whole point
    // of the precedence pass (a card must not also be clipped as a phone); if two
    // accepted spans overlap, the right-to-left splice mangles the body.
    if (s.start < prevEnd) {
      throw new Error(`spans overlap or are unsorted at ${s.type} [${s.start},${s.end})`);
    }
    prevEnd = s.end;

    // A span from a set the caller did not activate is a policy violation:
    // X-Redact-Sets is a caller-visible contract, and redacting outside it
    // corrupts prompt text the tenant explicitly asked to be left alone.
    if (!s.sets.some((set) => combo.includes(set))) {
      throw new Error(`span from inactive set: ${s.type} sets=${s.sets.join(',')}`);
    }
  }
}
