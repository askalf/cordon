// Property-based fuzzing of known subjects (fast-check). For random invented people written
// in random forms inside random text and fields:
//   - no identifier survives into the de-identified body (read separator-blind), and the
//     egress check agrees the body may leave;
//   - an identifier slipped back in after redaction, obfuscated with spacing, case,
//     zero-width characters or full-width digits, is caught by the egress check;
//   - text that holds none of the identifiers is never refused (no false blocks);
//   - parsing and matching are total on byte soup.
// Run inside the battery (npm test) or: node --import tsx _test_fuzz_subject.js
// CORDON_FUZZ_RUNS deepens the search (default 75 runs per property).
import fc from "fast-check";
import { parseSubjectHeader, compileSubjects, withSubjects, subjectSpans, egressViolations, SubjectError } from "./src/subject.ts";
import { detector } from "./src/detect/index.ts";
import { Vault } from "./src/redact/vault.ts";
import { applyRedaction } from "./src/redact/apply.ts";

const RUNS = Math.max(10, Number(process.env.CORDON_FUZZ_RUNS) || 75);
let pass = 0, fail = 0;
const prop = (name, p) => {
  try { fc.assert(p, { numRuns: RUNS }); pass++; console.log(`PASS  ${name}`); }
  catch (e) { fail++; console.log(`FAIL  ${name}\n${String(e && e.message).slice(0, 2000)}`); }
};

const lower = "abcdefghijklmnopqrstuvwxyz";
const word = (min, max) => fc.string({ unit: fc.constantFrom(...lower), minLength: min, maxLength: max });
const cap = (w) => w[0].toUpperCase() + w.slice(1);
// Invented names: random letters, so never a common word, a placeholder or another field.
const nameWord = word(4, 9).filter((w) => /[aeiou]/.test(w) && /[^aeiou]/.test(w));
const digits = (n) => fc.array(fc.integer({ min: 0, max: 9 }), { minLength: n, maxLength: n }).map((a) => a.join(""));
const SUFFIX = [["Street", "St"], ["Avenue", "Ave"], ["Road", "Rd"], ["Drive", "Dr"], ["Lane", "Ln"], ["Court", "Ct"], ["Boulevard", "Blvd"]];
const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

const person = fc.record({
  first: nameWord, last: nameWord,
  phone: fc.tuple(fc.integer({ min: 2, max: 9 }), digits(2), fc.integer({ min: 2, max: 9 }), digits(6)).map(([a, b, c, d]) => `${a}${b}${c}${d}`),
  num: fc.integer({ min: 100, max: 99999 }), street: nameWord, suffix: fc.constantFrom(...SUFFIX),
  local: word(6, 10), domain: word(4, 8),
  y: fc.integer({ min: 1930, max: 2010 }), m: fc.integer({ min: 1, max: 12 }), d: fc.integer({ min: 1, max: 28 }),
  ssn: fc.tuple(fc.integer({ min: 100, max: 665 }), fc.integer({ min: 10, max: 99 }), fc.integer({ min: 1000, max: 9999 })),
}).filter((p) => p.first !== p.last && p.street !== p.first && p.street !== p.last);

const p2 = (n) => String(n).padStart(2, "0");
const specOf = (p) => ({
  ref: "fuzz",
  subjects: [{
    names: [`${cap(p.first)} ${cap(p.last)}`],
    emails: [`${p.local}@${p.domain}.com`],
    phones: [p.phone],
    addresses: [`${p.num} ${cap(p.street)} ${p.suffix[0]}`],
    dates: [`${p.y}-${p2(p.m)}-${p2(p.d)}`],
    ids: [`${p.ssn[0]}-${p.ssn[1]}-${p.ssn[2]}`],
  }],
});

// Every way the generators write an identifier; each must be caught.
const renderings = (p) => {
  const F = cap(p.first), L = cap(p.last), ph = p.phone;
  return fc.constantFrom(
    `${F} ${L}`, `${L}, ${F}`, `${F[0]}. ${L}`, `${F.toUpperCase()} ${L.toUpperCase()}`, `${p.first}${p.last}`, `${p.first}.${p.last}`, `${p.first}_${p.last}`, L,
    `${p.local}@${p.domain}.com`, `${p.local.toUpperCase()}@${p.domain}.COM`, `user ${p.local}`,
    ph, `(${ph.slice(0, 3)}) ${ph.slice(3, 6)}-${ph.slice(6)}`, `${ph.slice(0, 3)}.${ph.slice(3, 6)}.${ph.slice(6)}`, `+1 ${ph.slice(0, 3)} ${ph.slice(3, 6)} ${ph.slice(6)}`,
    `${p.num} ${cap(p.street)} ${p.suffix[0]}`, `${p.num} ${cap(p.street)} ${p.suffix[1]}.`, `${p.num} ${cap(p.street)} ${p.suffix[1]}`,
    `${p.y}-${p2(p.m)}-${p2(p.d)}`, `${p.m}/${p.d}/${p.y}`, `${p2(p.m)}/${p2(p.d)}/${String(p.y).slice(2)}`, `${MONTHS[p.m - 1]} ${p.d}, ${p.y}`, `${p.d} ${MONTHS[p.m - 1]} ${p.y}`,
    `${p.ssn[0]}-${p.ssn[1]}-${p.ssn[2]}`, `${p.ssn[0]} ${p.ssn[1]} ${p.ssn[2]}`, `${p.ssn[0]}${p.ssn[1]}${p.ssn[2]}`,
  );
};
// What must never be found in the outbound body, read with separators and case ignored.
const needles = (p) => [
  (p.first + p.last).toLowerCase(), p.local, p.phone, `${p.num}${p.street}`, `${p.y}${p2(p.m)}${p2(p.d)}`, `${p.ssn[0]}${p.ssn[1]}${p.ssn[2]}`,
];
const flat = (s) => s.normalize("NFKC").toLowerCase().replace(/[^\p{L}\p{N}]+/gu, "");
const filler = fc.array(fc.oneof(word(1, 8), fc.constantFrom(" ", " ", ", ", ". ", "\n", " - ", ": ", " (", ") ", " and ", " the ")), { maxLength: 12 }).map((a) => a.join(""));
const pad = (s) => ` ${s} `; // a word boundary each side, as identifiers appear in prose

// Places a text can sit in a Messages request.
const place = (texts) => ({
  model: "m",
  system: texts[0] ?? "",
  messages: [
    { role: "user", content: texts[1] ?? "" },
    { role: "assistant", content: [{ type: "tool_use", id: "t1", name: "lookup", input: { q: texts[2] ?? "", nested: { note: texts[3] ?? "" } } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: texts[4] ?? "" }, { type: "text", text: texts.slice(5).join("\n") }] },
  ],
});

const redactWith = (p, body) => {
  const comp = compileSubjects(parseSubjectHeader(Buffer.from(JSON.stringify(specOf(p))).toString("base64url")), "fuzz-key");
  const v = new Vault("reversible");
  const { deidBody } = applyRedaction(body, "anthropic", v, ["pii", "pci", "secrets"], withSubjects(detector, comp), true, "messages");
  return { comp, deidBody, own: { minted: v.minted, raw: body } };
};

prop("no identifier survives redaction, in any form or field, and egress agrees", fc.property(
  person.chain((p) => fc.tuple(fc.constant(p), fc.array(fc.tuple(filler, renderings(p), filler).map(([a, r, b]) => a + pad(r) + b), { minLength: 1, maxLength: 9 }))),
  ([p, texts]) => {
    const { comp, deidBody, own } = redactWith(p, place(texts));
    const out = flat(JSON.stringify(deidBody));
    const left = needles(p).filter((n) => out.includes(n));
    const eg = egressViolations(deidBody, comp, own);
    if (left.length || eg.length) throw new Error(`left=${left} egress=${eg} texts=${JSON.stringify(texts)} out=${JSON.stringify(deidBody).slice(0, 800)}`);
    return true;
  },
));

const ZW = ["​", "‌", "‍", "⁠", "﻿"];
const fullWidth = (s) => s.replace(/\d/g, (d) => String.fromCharCode(0xff10 + Number(d)));
const obfuscate = (s, seps, mode) => {
  const chars = [...s];
  if (mode === 0) return chars.join(seps);
  if (mode === 1) return chars.map((c, i) => (i % 2 ? c.toUpperCase() : c)).join("");
  if (mode === 2) return chars.map((c, i) => c + ZW[i % ZW.length]).join("");
  return fullWidth(chars.join(seps));
};
prop("an identifier slipped back in after redaction is caught, however it is disguised", fc.property(
  person, fc.integer({ min: 0, max: 5 }), fc.constantFrom(" ", "-", ".", " / ", "_", ""), fc.integer({ min: 0, max: 3 }), filler,
  (p, which, seps, mode, noise) => {
    const raw = [`${cap(p.first)} ${cap(p.last)}`, p.phone, `${p.local}@${p.domain}.com`, `${p.ssn[0]}${p.ssn[1]}${p.ssn[2]}`, `${p.y}${p2(p.m)}${p2(p.d)}`, `${p.num} ${cap(p.street)} ${p.suffix[0]}`][which];
    const { comp, deidBody, own } = redactWith(p, place([noise]));
    deidBody.messages[0].content += pad(obfuscate(raw, seps, mode));
    const eg = egressViolations(deidBody, comp, own);
    if (!eg.length) throw new Error(`missed ${JSON.stringify(obfuscate(raw, seps, mode))}`);
    return true;
  },
));

prop("text without the identifiers is never refused", fc.property(person, fc.array(filler, { minLength: 1, maxLength: 6 }), (p, texts) => {
  const body = place(texts);
  const { comp, deidBody, own } = redactWith(p, body);
  const hay = flat(JSON.stringify(body));
  if (needles(p).some((n) => hay.includes(n))) return true; // the noise happened to spell one
  const eg = egressViolations(deidBody, comp, own);
  if (eg.length) throw new Error(`false block ${eg} on ${JSON.stringify(texts)}`);
  return true;
}));

prop("the header parser is total: a value or a SubjectError, never anything else", fc.property(fc.string({ unit: "binary", maxLength: 400 }), (s) => {
  for (const raw of [s, Buffer.from(s).toString("base64url")]) {
    try { parseSubjectHeader(raw); } catch (e) { if (!(e instanceof SubjectError)) throw e; }
  }
  return true;
}));

prop("matching is total and well-formed on byte soup", fc.property(person, fc.string({ unit: "binary", maxLength: 400 }), (p, text) => {
  const comp = compileSubjects(parseSubjectHeader(Buffer.from(JSON.stringify(specOf(p))).toString("base64url")), "k");
  for (const s of subjectSpans(text, comp)) if (!(s.start >= 0 && s.end > s.start && s.end <= text.length && text.slice(s.start, s.end) === s.value)) throw new Error("bad span");
  egressViolations({ messages: [{ role: "user", content: text }] }, comp);
  return true;
}));

console.log(`\nfuzz (subjects): ${pass} passed, ${fail} failed (${RUNS} runs/property)`);
process.exit(fail ? 1 : 0);
