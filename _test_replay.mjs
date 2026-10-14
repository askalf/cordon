// Replays: realistic request shapes (a chat turn, an agent's tool loop with a form submission
// in a tool result, Chat Completions tool calls, Responses function calls, MCP-named tools),
// filled with generated people, through redaction, the egress check and the response restore.
//
// Every combination must
//   1. leak nothing: once redacted, the egress check finds no declared identifier;
//   2. not refuse ordinary text: a message whose only overlap with the person is their name's
//      words used as ordinary lowercase words passes the egress check;
//   3. round-trip: a reply that uses the placeholders gets the real values back in its text and
//      in an allowed tool's arguments, and a tool the policy does not name keeps placeholders.
//
// The people are invented, and the hard cases are on purpose: names that are ordinary words,
// one-word names, hyphens and apostrophes, accents, initials, every common phone spelling.
// Run inside the battery (npm test) or: node --import tsx _test_replay.mjs
// CORDON_FUZZ_RUNS deepens the generated part (default 75 runs per property).
import fc from "fast-check";
import { parseSubjectHeader, compileSubjects, withSubjects, egressViolations } from "./src/subject.ts";
import { detector } from "./src/detect/index.ts";
import { Vault } from "./src/redact/vault.ts";
import { applyRedaction } from "./src/redact/apply.ts";
import { reidentifyBody } from "./src/redact/reidentify.ts";
import { parseRestoreTools } from "./src/redact/restorePolicy.ts";

const RUNS = Math.max(10, Number(process.env.CORDON_FUZZ_RUNS) || 75);
let pass = 0;
let fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) pass++;
  else fail++;
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? `   (${detail})` : ""}`);
};
const prop = (name, p) => {
  try { fc.assert(p, { numRuns: RUNS }); pass++; console.log(`PASS  ${name}`); }
  catch (e) { fail++; console.log(`FAIL  ${name}\n${String(e && e.message).slice(0, 2000)}`); }
};
const enc = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");

// ---- people ----
const HARD_NAMES = [
  "Grant", "Test User", "Chase Hope", "May Bell", "Bill Price", "Art Rush", "Sky Day", "Ivy Stone",
  "Anne-Marie Okafor", "D'Angelo Rivers", "José Núñez", "Zoë Ström", "Li Na", "Mary-Kate Dunne",
  "Orsolya Vantreeck", "Teodor Halvorsen-Ruiz", "Priya Raghunathan",
];
const slug = (s) => s.normalize("NFD").replace(/\p{M}+/gu, "").toLowerCase().replace(/[^a-z]+/g, "");
const person = (name, i) => {
  const words = name.split(/\s+/);
  const n = String(1000 + ((i * 7919) % 9000));
  return {
    name, first: words[0], last: words[words.length - 1], words,
    email: `${slug(words[0])}.${slug(words[words.length - 1])}${i}@example.com`,
    phone: `(404) 555-${n}`,
    phoneAlt: [`404.555.${n}`, `+1 404 555 ${n}`, `4045550${n.slice(1)}`, `404-555-${n}`][i % 4],
  };
};
const subjectOf = (p) => ({ ref: "replay", subjects: [{ names: [p.name], emails: [p.email], phones: [p.phone] }] });

// ---- what people write ----
const withIdentifiers = [
  (p) => `Hi, I'm ${p.name}. You can reach me at ${p.email} or ${p.phone}.`,
  (p) => `${p.first} here (${p.email}). Best number is ${p.phoneAlt}.`,
  (p) => `This is ${p.name.toUpperCase()}, my number is ${p.phoneAlt}, email ${p.email.toUpperCase()}.`,
  (p) => `Name: ${p.name}\nEmail: ${p.email}\nPhone: ${p.phone}\n\nSomeone opened accounts in my name.`,
  (p) => p.words.length > 1 ? `Please write to ${p.last}, ${p.first} at ${p.email}.` : `Please write to ${p.first} at ${p.email}.`,
];
// Only the name's plain words (no hyphen or apostrophe, which make a word the name itself),
// lowercase and apart from each other: ordinary text, not the person.
const plainWords = (p) => p.words.filter((w) => /^\p{L}+$/u.test(w)).map((w) => w.toLowerCase());
const ordinary = [
  (p) => `please ${plainWords(p)[0] ?? "send"} us access when you can; the form says it is fine.`,
  (p) => { const w = plainWords(p); return `i will ${w[0] ?? "send"} the details later.${w.length > 1 ? ` the other part, ${w[w.length - 1]}, can wait.` : ""}`; },
];

// A form submission rendered as text, the way a site mails it on.
const formText = (p, message) =>
  ["New request from the site.", "", `Name:           ${p.name}`, `Email:          ${p.email}`, `Phone:          ${p.phone}`, "", "Message:", message].join("\n");

// ---- request shapes ----
const SHAPES = {
  "messages: one turn": (p, m) => ({ provider: "anthropic", dialect: "messages", body: { model: "m", max_tokens: 64, system: "You help people with account problems.", messages: [{ role: "user", content: m }] } }),
  "messages: tool loop with a form in a tool result": (p, m) => ({
    provider: "anthropic", dialect: "messages",
    body: {
      model: "m", max_tokens: 64, system: "Read the request with lookup_request, then draft a reply with draft_reply.",
      messages: [
        { role: "user", content: "Handle request R1." },
        { role: "assistant", content: [{ type: "text", text: "Reading it." }, { type: "tool_use", id: "t1", name: "lookup_request", input: { id: "R1" } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: JSON.stringify({ request: { id: "R1", text: formText(p, m) } }, null, 2) }] },
        { role: "assistant", content: [{ type: "tool_use", id: "t2", name: "draft_reply", input: { to: p.email, body: `Hi ${p.first},\n\nThanks for writing. We can help.` } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "t2", content: [{ type: "text", text: "filed" }] }] },
      ],
    },
  }),
  "messages: MCP-named tools": (p, m) => ({
    provider: "anthropic", dialect: "messages",
    body: {
      model: "m", max_tokens: 64,
      messages: [
        { role: "user", content: m },
        { role: "assistant", content: [{ type: "tool_use", id: "t1", name: "mcp__records__search", input: { query: p.name } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: [{ type: "text", text: `1 match: ${p.name} <${p.email}>` }] }] },
      ],
    },
  }),
  "chat: tool calls": (p, m) => ({
    provider: "openai", dialect: "chat",
    body: {
      model: "m",
      messages: [
        { role: "system", content: "You help people with account problems." },
        { role: "user", content: m },
        { role: "assistant", content: null, tool_calls: [{ id: "c1", type: "function", function: { name: "search", arguments: JSON.stringify({ q: `${p.name} ${p.phone}` }) } }] },
        { role: "tool", tool_call_id: "c1", content: JSON.stringify({ results: [{ email: p.email, phone: p.phoneAlt }] }) },
      ],
    },
  }),
  "responses: function calls": (p, m) => ({
    provider: "openai", dialect: "responses",
    body: {
      model: "m", store: false,
      input: [
        { role: "user", content: [{ type: "input_text", text: m }] },
        { type: "function_call", call_id: "c1", name: "search", arguments: JSON.stringify({ q: p.name }) },
        { type: "function_call_output", call_id: "c1", output: JSON.stringify({ hit: p.email }) },
      ],
    },
  }),
};

// A reply that uses the placeholders, in each provider's shape.
const replyFor = (provider, dialect, text, tool, args) => {
  if (provider === "anthropic") return { content: [{ type: "text", text }, { type: "tool_use", id: "r1", name: tool, input: args }] };
  if (dialect === "chat") return { choices: [{ index: 0, message: { role: "assistant", content: text, tool_calls: [{ id: "r1", type: "function", function: { name: tool, arguments: JSON.stringify(args) } }] } }] };
  return { output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text }] }, { type: "function_call", call_id: "r1", name: tool, arguments: JSON.stringify(args) }] };
};
const toolArgs = (provider, dialect, reply) => {
  if (provider === "anthropic") return reply.content.find((b) => b.type === "tool_use").input;
  if (dialect === "chat") return JSON.parse(reply.choices[0].message.tool_calls[0].function.arguments);
  return JSON.parse(reply.output.find((o) => o.type === "function_call").arguments);
};
const replyText = (provider, dialect, reply) =>
  provider === "anthropic" ? reply.content[0].text : dialect === "chat" ? reply.choices[0].message.content : reply.output[0].content[0].text;

const POLICY = parseRestoreTools("draft_reply");

function replay(p, message, shapeName) {
  const comp = compileSubjects(parseSubjectHeader(enc(subjectOf(p))), "replay-key");
  const { provider, dialect, body } = SHAPES[shapeName](p, message);
  const vault = new Vault("reversible");
  const { deidBody } = applyRedaction(body, provider, vault, ["pii", "pci", "secrets"], withSubjects(detector, comp), true, dialect);
  const where = new Map();
  const hits = egressViolations(deidBody, comp, { minted: vault.minted, raw: body }, where);
  return { comp, provider, dialect, body, vault, deidBody, hits, where };
}

// ---- 1 and 2: every hard name, every message, every shape ----
let leaks = [];
let refusals = [];
let combos = 0;
HARD_NAMES.forEach((name, i) => {
  const p = person(name, i);
  for (const shape of Object.keys(SHAPES)) {
    for (const [k, m] of withIdentifiers.entries()) {
      combos++;
      const r = replay(p, m(p), shape);
      if (r.hits.length) leaks.push(`${name} | ${shape} | message ${k} | ${[...r.where].map(([t, w]) => `${t}@${w}`).join(" ")}`);
    }
    for (const [k, m] of ordinary.entries()) {
      combos++;
      // Only the plain one-turn shape: the others carry the person's identifiers in tool data by design.
      if (shape !== "messages: one turn") continue;
      const r = replay(p, m(p), shape);
      if (r.hits.length) refusals.push(`${name} | message ${k} | ${[...r.where].map(([t, w]) => `${t}@${w}`).join(" ")}`);
    }
  }
});
ok(`replay: no identifier survives redaction (${HARD_NAMES.length} people, ${Object.keys(SHAPES).length} shapes)`, leaks.length === 0, leaks.slice(0, 6).join(" ;; "));
ok("replay: a name's words used as ordinary lowercase words are not refused", refusals.length === 0, refusals.slice(0, 6).join(" ;; "));

// ---- 3: the reply round trip ----
{
  const problems = [];
  HARD_NAMES.forEach((name, i) => {
    const p = person(name, i);
    for (const shape of Object.keys(SHAPES)) {
      const r = replay(p, withIdentifiers[0](p), shape);
      const byType = new Map();
      for (const [token, type] of r.vault.minted) if (!byType.has(type)) byType.set(type, token);
      const emailToken = byType.get("SUBJECT1_EMAIL");
      const nameToken = byType.get("SUBJECT1_NAME");
      if (!emailToken || !nameToken) { problems.push(`${name} | ${shape} | nothing minted`); continue; }
      const allowed = reidentifyBody(replyFor(r.provider, r.dialect, `Hello ${nameToken}, we wrote to ${emailToken}.`, "draft_reply", { to: emailToken }), r.provider, r.vault, r.dialect, { unresolved: 0 }, POLICY);
      const text = replyText(r.provider, r.dialect, allowed);
      if (!text.includes(p.email) || text.includes(emailToken)) problems.push(`${name} | ${shape} | reply text not restored`);
      if (toolArgs(r.provider, r.dialect, allowed).to !== p.email) problems.push(`${name} | ${shape} | allowed tool argument not restored`);
      const other = reidentifyBody(replyFor(r.provider, r.dialect, "ok", "unlisted_tool", { to: emailToken }), r.provider, r.vault, r.dialect, { unresolved: 0 }, POLICY);
      if (toolArgs(r.provider, r.dialect, other).to === p.email) problems.push(`${name} | ${shape} | a tool the policy does not name got the real value`);
    }
  });
  ok("replay: a reply's text and an allowed tool's arguments get the real values; an unlisted tool does not", problems.length === 0, problems.slice(0, 6).join(" ;; "));
}

// ---- generated people through every shape ----
const lower = "abcdefghijklmnopqrstuvwxyz";
const word = fc.string({ unit: fc.constantFrom(...lower), minLength: 3, maxLength: 9 }).filter((w) => /[aeiou]/.test(w) && /[^aeiou]/.test(w));
const cap = (w) => w[0].toUpperCase() + w.slice(1);
const genPerson = fc.record({ a: word, b: word, sep: fc.constantFrom(" ", "-", " O'"), i: fc.integer({ min: 0, max: 9999 }) })
  .filter(({ a, b }) => a !== b)
  .map(({ a, b, sep, i }) => person(sep === " " ? `${cap(a)} ${cap(b)}` : sep === "-" ? `${cap(a)} ${cap(a)}-${cap(b)}` : `${cap(a)} O'${cap(b)}`, i));
prop("replay (generated): no identifier survives redaction in any shape", fc.property(genPerson, fc.integer({ min: 0, max: withIdentifiers.length - 1 }), fc.constantFrom(...Object.keys(SHAPES)), (p, k, shape) => replay(p, withIdentifiers[k](p), shape).hits.length === 0));
prop("replay (generated): ordinary lowercase use of a name's words is not refused", fc.property(genPerson, fc.integer({ min: 0, max: ordinary.length - 1 }), (p, k) => replay(p, ordinary[k](p), "messages: one turn").hits.length === 0));

console.log(`\nreplay: ${combos} fixed combinations; ${pass} passed, ${fail} failed (${RUNS} runs/property)`);
process.exit(fail ? 1 : 0);
