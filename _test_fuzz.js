// Property-based fuzzing of the detect → redact → re-identify plane (fast-check).
// Where the unit suite pins exact examples, these properties assert the invariants
// that must hold for EVERY input: the detector is total and well-formed on byte
// soup, seeded PII never survives into a de-identified body (even under unicode
// evasion), and redaction round-trips to identity through both the full-body and
// the boundary-safe streaming re-identifier.
//
// Run inside the battery (npm test) or standalone: node --import tsx _test_fuzz.js
// CORDON_FUZZ_RUNS deepens the search (default 75 runs per property).
//
// (This file is intentionally `.js`, not `.mjs`: OpenSSF Scorecard's Fuzzing check
// only greps *.js/*.ts for the fast-check import. ESM regardless, via type:module.)
import fc from "fast-check";
import { runAll, detector } from "./src/detect/index.ts";
import { luhn, abaRouting } from "./src/detect/validators.ts";
import { Vault } from "./src/redact/vault.ts";
import { applyRedaction, tally } from "./src/redact/apply.ts";
import { reidentifyBody, StreamReidentifier } from "./src/redact/reidentify.ts";

const RUNS = Math.max(10, Number(process.env.CORDON_FUZZ_RUNS) || 75);
let pass = 0, fail = 0;
const prop = (name, p) => {
  try { fc.assert(p, { numRuns: RUNS }); pass++; console.log(`PASS  ${name}`); }
  catch (e) { fail++; console.log(`FAIL  ${name}\n${String(e && e.message).slice(0, 1500)}`); }
};

const ALL = ["pii", "phi", "pci", "secrets"];
const userBody = (content) => ({ model: "m", messages: [{ role: "user", content }] });

// ---------------- generators ----------------

// Arbitrary code points — the "byte soup" the gateway must never choke on.
const anyText = fc.string({ unit: "binary", maxLength: 300 });

// Lowercase-alpha noise: cannot itself be PII, and (being non-digit, non-@, non-<)
// cannot extend an adjacent seed's match or collide with a vault placeholder.
const alpha = fc.string({
  unit: fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz"),
  minLength: 1,
  maxLength: 10,
});

// Seeds the catalog MUST catch — each constructed to satisfy its validator.
const emailSeed = fc
  .tuple(alpha, alpha, fc.constantFrom("com", "org", "io", "dev"))
  .map(([l, d, t]) => `${l}@${d}.${t}`);
const luhnCard = fc
  .array(fc.integer({ min: 0, max: 9 }), { minLength: 15, maxLength: 15 })
  .map((ds) => {
    const p = ds.join("");
    for (let d = 0; d <= 9; d++) if (luhn(p + d)) return p + d; // exactly one check digit satisfies mod-10
    return p + "0"; // unreachable
  });
const ssnSeed = fc
  .tuple(
    fc.integer({ min: 1, max: 899 }).filter((a) => a !== 666),
    fc.integer({ min: 1, max: 99 }),
    fc.integer({ min: 1, max: 9999 }),
  )
  .map(([a, g, s]) => `${String(a).padStart(3, "0")}-${String(g).padStart(2, "0")}-${String(s).padStart(4, "0")}`);
const phoneSeed = fc
  .tuple(fc.integer({ min: 200, max: 989 }), fc.integer({ min: 100, max: 999 }), fc.integer({ min: 0, max: 9999 }))
  .map(([a, b, c]) => `${a}-${b}-${String(c).padStart(4, "0")}`);
const piiSeed = fc.oneof(
  emailSeed.map((value) => ({ value, type: "EMAIL" })),
  luhnCard.map((value) => ({ value, type: "CREDIT_CARD" })),
  ssnSeed.map((value) => ({ value, type: "SSN" })),
  phoneSeed.map((value) => ({ value, type: "PHONE" })),
);

// Seeds space-embedded in alpha noise (spaces keep each seed's \b word boundaries).
const seededText = fc
  .tuple(fc.array(piiSeed, { minLength: 1, maxLength: 4 }), fc.array(alpha, { minLength: 5, maxLength: 5 }))
  .map(([seeds, noise]) => {
    const parts = [noise[0]];
    seeds.forEach((s, i) => parts.push(s.value, noise[(i + 1) % noise.length]));
    return { text: parts.join(" "), seeds };
  });

// For round-trip identity the original must not itself contain a placeholder-shaped
// token: a literal "<EMAIL_1>" in client text could collide with a minted one, and
// restoring it to the redacted value is then the CORRECT (non-identity) behavior.
const cleanText = anyText.filter((t) => !/<[A-Z][A-Z0-9_]*>/.test(t));

// ---------------- detector plane ----------------

prop(
  "detector total on byte soup; spans sorted, disjoint, in-bounds, faithful, set-gated",
  fc.property(anyText, fc.uniqueArray(fc.constantFrom(...ALL), { maxLength: 4 }), (text, sets) => {
    const spans = runAll(text, sets); // must not throw
    let prevEnd = -1;
    for (const s of spans) {
      if (!(s.start >= 0 && s.start < s.end && s.end <= text.length)) return false;
      if (s.start < prevEnd) return false; // sorted AND non-overlapping
      if (s.value !== text.slice(s.start, s.end)) return false; // value is the real bytes
      if (!s.sets.some((x) => sets.includes(x))) return false; // nothing fires outside its active set
      prevEnd = s.end;
    }
    return true;
  }),
);

prop(
  "detector deterministic (shared-regex lastIndex is never a reentrancy hazard)",
  fc.property(anyText, (text) => {
    return JSON.stringify(runAll(text, ALL)) === JSON.stringify(runAll(text, ALL));
  }),
);

// ---------------- seeded PII must never leak ----------------

prop(
  "seeded PII (email/card/SSN/phone) never survives into the de-identified body",
  fc.property(seededText, ({ text, seeds }) => {
    const v = new Vault("reversible");
    const body = userBody(text);
    const before = JSON.stringify(body);
    const { deidBody, spans } = applyRedaction(body, "openai", v, ALL, detector);
    const out = deidBody.messages[0].content;
    if (seeds.some((s) => out.includes(s.value))) return false;
    if (JSON.stringify(body) !== before) return false; // caller's body never mutated
    const counted = Object.values(tally(spans)).reduce((a, b) => a + b, 0);
    return spans.length >= 1 && counted === spans.length;
  }),
);

prop(
  "zero-width splicing cannot smuggle an email past detection",
  fc.property(
    emailSeed,
    fc.array(
      fc.tuple(
        fc.integer({ min: 0, max: 50 }),
        fc.constantFrom("​", "‌", "‍", "⁠", "﻿", "­"),
      ),
      { minLength: 1, maxLength: 6 },
    ),
    (email, cuts) => {
      let evaded = email;
      for (const [pos, ch] of cuts) {
        const p = 1 + (pos % (evaded.length - 1)); // interior positions only
        evaded = evaded.slice(0, p) + ch + evaded.slice(p);
      }
      const v = new Vault("reversible");
      const { deidBody, spans } = applyRedaction(userBody(`q ${evaded} q`), "openai", v, ["pii"], detector);
      const clean = deidBody.messages[0].content.replace(/[​-‍⁠﻿­]/g, "").normalize("NFKC");
      return spans.some((s) => s.type === "EMAIL") && !clean.includes(email);
    },
  ),
);

prop(
  "full-width digits cannot smuggle a card past detection",
  fc.property(luhnCard, fc.array(fc.integer({ min: 0, max: 15 }), { minLength: 1, maxLength: 8 }), (card, idxs) => {
    const FW = "０１２３４５６７８９"; // U+FF10–FF19, NFKC-normalize to ASCII digits
    const chars = card.split("");
    for (const i of idxs) chars[i] = FW[Number(card[i])];
    const spans = runAll(`pay ${chars.join("")} now`, ["pci"]);
    return spans.some((s) => s.type === "CREDIT_CARD");
  }),
);

// ---------------- vault ----------------

prop(
  "vault (reversible): distinct values → distinct tokens; stable; invertible",
  fc.property(
    fc.uniqueArray(fc.string({ unit: "binary", minLength: 1, maxLength: 20 }), { minLength: 1, maxLength: 20 }),
    fc.constantFrom("EMAIL", "PHONE", "CREDIT_CARD", "SSN"),
    (values, type) => {
      const v = new Vault("reversible");
      const tokens = values.map((x) => v.placeholderFor(x, type));
      if (new Set(tokens).size !== tokens.length) return false;
      return values.every((x, i) => v.placeholderFor(x, type) === tokens[i] && v.lookup(tokens[i]) === x);
    },
  ),
);

prop(
  "vault (strip): irreversible — no reverse map, and re-identify is a no-op",
  fc.property(seededText, ({ text }) => {
    const v = new Vault("strip");
    const { deidBody } = applyRedaction(userBody(text), "openai", v, ALL, detector);
    if (v.hasReverse) return false;
    if (/<[A-Z][A-Z0-9_]*>/.test(deidBody.messages[0].content)) return false; // strip mints [TYPE], never <TYPE_N>
    const resp = { choices: [{ message: { role: "assistant", content: deidBody.messages[0].content } }] };
    return JSON.stringify(reidentifyBody(resp, "openai", v)) === JSON.stringify(resp);
  }),
);

prop(
  "consistent pseudonyms: same secret+value → same token across requests, still invertible",
  fc.property(
    fc.string({ unit: "binary", minLength: 1, maxLength: 24 }),
    fc.string({ minLength: 1, maxLength: 12 }),
    (value, secret) => {
      const a = new Vault("reversible", { consistentPseudonyms: true, secret });
      const b = new Vault("reversible", { consistentPseudonyms: true, secret });
      const ta = a.placeholderFor(value, "EMAIL");
      return ta === b.placeholderFor(value, "EMAIL") && /^<EMAIL_[0-9A-F]{8}>$/.test(ta) && a.lookup(ta) === value;
    },
  ),
);

// ---------------- redact → re-identify round-trip ----------------

prop(
  "redact→re-identify round-trips to identity on arbitrary text (both providers)",
  fc.property(cleanText, fc.constantFrom("openai", "anthropic"), (text, provider) => {
    const v = new Vault("reversible");
    const { deidBody } = applyRedaction(userBody(text), provider, v, ALL, detector);
    const deid = deidBody.messages[0].content;
    const resp =
      provider === "openai"
        ? { choices: [{ message: { role: "assistant", content: deid } }] }
        : { content: [{ type: "text", text: deid }] };
    const back = reidentifyBody(resp, provider, v);
    return (provider === "openai" ? back.choices[0].message.content : back.content[0].text) === text;
  }),
);

prop(
  "stream re-identifier reassembles identity under ANY chunking (split placeholders)",
  fc.property(seededText, fc.array(fc.integer({ min: 0, max: 400 }), { maxLength: 12 }), ({ text }, cutSeed) => {
    const v = new Vault("reversible");
    const { deidBody } = applyRedaction(userBody(text), "openai", v, ALL, detector);
    const deid = deidBody.messages[0].content;
    const cuts = [...new Set(cutSeed.map((c) => c % (deid.length + 1)))].sort((a, b) => a - b);
    const r = new StreamReidentifier(v);
    let out = "", prev = 0;
    for (const c of cuts) { out += r.push(deid.slice(prev, c)); prev = c; }
    out += r.push(deid.slice(prev)) + r.end();
    return out === text;
  }),
);

prop(
  "a stream truncated mid-placeholder still restores the real value (unique prefix)",
  fc.property(alpha, alpha, emailSeed, fc.integer({ min: 0, max: 500 }), (preRaw, postRaw, email, cutRaw) => {
    const pre = preRaw + " ", post = " " + postRaw;
    const v = new Vault("reversible");
    const { deidBody, spans } = applyRedaction(userBody(pre + email + post), "openai", v, ["pii"], detector);
    if (spans.length !== 1) return false; // alpha noise can't be PII; exactly the one email
    const deid = deidBody.messages[0].content;
    const tokStart = deid.indexOf("<");
    const tokEnd = deid.indexOf(">") + 1;
    const cut = cutRaw % (deid.length + 1);
    const r = new StreamReidentifier(v);
    const out = r.push(deid.slice(0, cut)) + r.end();
    const expected =
      cut <= tokStart ? deid.slice(0, cut) // cut before the token: emit what was sent
        : cut < tokEnd ? pre + email // cut inside it: resolve the partial to the real value
          : pre + email + deid.slice(tokEnd, cut); // cut after it: normal restore
    return out === expected;
  }),
);

// ---------------- collision resistance (issue #19) ----------------

prop(
  "a caller's own <TYPE_N>-shaped literal is never rewritten on restore (nonce'd tokens)",
  fc.property(
    seededText,
    fc.constantFrom("EMAIL", "PHONE", "SSN", "CREDIT_CARD", "IPV4"),
    fc.integer({ min: 1, max: 20 }),
    ({ text }, ltype, ln) => {
      const literal = `<${ltype}_${ln}>`; // exactly the pre-fix (bare-counter) token shape
      const v = new Vault("reversible");
      // the literal is forwarded verbatim (not a detected entity) alongside real PII
      const { deidBody } = applyRedaction(userBody(`${literal} ${text}`), "openai", v, ALL, detector);
      const deid = deidBody.messages[0].content;
      if (!deid.includes(literal)) return false; // literal must reach the model untouched
      // the model "echoes" the de-identified text; restore rewrites minted tokens only
      const resp = { choices: [{ message: { role: "assistant", content: deid } }] };
      const back = reidentifyBody(resp, "openai", v).choices[0].message.content;
      return back.includes(literal); // caller's literal comes back exactly as written
    },
  ),
);

// ---------------- body-walking hardening ----------------

prop(
  "__proto__/constructor-named leaves are still redacted, without prototype pollution",
  fc.property(fc.constantFrom("__proto__", "constructor", "safe_key"), luhnCard, (key, card) => {
    const body = {
      model: "m",
      messages: [
        {
          role: "assistant",
          content: "",
          tool_calls: [{ id: "t", type: "function", function: { name: "f", arguments: JSON.stringify({ [key]: `card ${card}` }) } }],
        },
      ],
    };
    const v = new Vault("reversible");
    const { deidBody } = applyRedaction(body, "openai", v, ["pci"], detector);
    const outArgs = deidBody.messages[0].tool_calls[0].function.arguments;
    const val = JSON.parse(outArgs)[key]; // own JSON-parsed property shadows the inherited accessor
    return (
      !outArgs.includes(card) &&
      /^card <CREDIT_CARD_[0-9A-F]+_1>$/.test(val) && // nonce'd counter token
      Object.prototype.constructor === Object && // prototype untouched
      {}.polluted === undefined
    );
  }),
);

prop(
  "numeric leaves: whole-value checksum-valid cards redact; all other numbers pass through untouched",
  fc.property(
    luhnCard.filter((c) => String(Number(c)) === c), // survives float precision, no leading zero
    fc.integer({ min: 0, max: 2 ** 48 }),
    (card, n) => {
      fc.pre(!luhn(String(n)) && !abaRouting(String(n)));
      const body = userBody([{ type: "tool_use", id: "u", name: "f", input: { card: Number(card), other: n } }]);
      const v = new Vault("reversible");
      const { deidBody } = applyRedaction(body, "anthropic", v, ["pci"], detector);
      const input = deidBody.messages[0].content[0].input;
      return /^<CREDIT_CARD_[0-9A-F]+_1>$/.test(input.card) && input.other === n;
    },
  ),
);

prop(
  "applyRedaction is total on malformed message shapes and never mutates its input",
  fc.property(
    fc.array(
      fc.record({ role: fc.constantFrom("user", "assistant", "system", "tool"), content: fc.jsonValue() }, { requiredKeys: ["role"] }),
      { maxLength: 4 },
    ),
    fc.constantFrom("openai", "anthropic"),
    (messages, provider) => {
      const body = { model: "m", messages };
      const before = JSON.stringify(body);
      const v = new Vault("reversible");
      const { deidBody } = applyRedaction(body, provider, v, ALL, detector); // must not throw
      JSON.stringify(deidBody); // and must stay serializable
      return JSON.stringify(body) === before;
    },
  ),
);

console.log(`\nfuzz: ${pass} passed, ${fail} failed (${RUNS} runs/property)`);
process.exit(fail ? 1 : 0);
