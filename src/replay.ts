// Replay recorded request shapes (src/shapes.ts) with invented people: each shape is filled in
// twice per person, once with the person's identifiers written into its text and once with only
// ordinary words (their name's plain words among them, lowercase), and run through redaction and
// the egress check. The first must leak nothing once redacted; the second must not be refused.
import { ENUM_FIELDS, compileSubjects, egressViolations, parseSubjectHeader, withSubjects } from "./subject";
import { detector } from "./detect";
import { Vault } from "./redact/vault";
import { applyRedaction } from "./redact/apply";
import type { Dialect, Provider } from "./types";
import type { ShapeRecord } from "./shapes";

export interface Person {
  name: string;
  email: string;
  phone: string;
}

/** Invented people, hard on purpose: ordinary-word names, one word, hyphens, apostrophes, accents. */
export const REPLAY_PEOPLE: Person[] = [
  { name: "Grant", email: "grant.okoro4@example.com", phone: "(404) 555-0143" },
  { name: "Test User", email: "test.user7@example.org", phone: "404.555.0177" },
  { name: "Chase Hope", email: "chope@example.net", phone: "+1 404 555 0112" },
  { name: "Anne-Marie Okafor", email: "annemarie.okafor@example.com", phone: "404-555-0188" },
  { name: "D'Angelo Rivers", email: "dangelo.rivers@example.com", phone: "(470) 555-0109" },
  { name: "José Núñez", email: "jose.nunez@example.com", phone: "678.555.0164" },
  { name: "Orsolya Vantreeck", email: "orsolya.vantreeck@example.com", phone: "(404) 555-0130" },
];

const ORDINARY = "the account was opened last week and we would like to know what happens next please reply when you can thanks again for the help with this request".split(" ");

/** A deterministic stream of picks, so a failure replays the same way. */
function picker(seed: number) {
  let x = seed >>> 0 || 1;
  return (n: number) => {
    x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
    return x % n;
  };
}

type Mode = "identifiers" | "ordinary" | "neutral";

function phrases(p: Person, mode: Mode): string[] {
  const words = p.name.split(/\s+/);
  if (mode === "neutral") return [];
  if (mode === "ordinary") return words.filter((w) => /^\p{L}+$/u.test(w)).map((w) => w.toLowerCase());
  const first = words[0];
  const last = words[words.length - 1];
  return [p.name, first, p.email, p.phone, p.name.toUpperCase(), words.length > 1 ? `${last}, ${first}` : first, `Name: ${p.name}`];
}

function text(size: number, lines: number, p: Person, mode: Mode, pick: (n: number) => number): string {
  const target = Math.min(size, 2000);
  const own = phrases(p, mode);
  const out: string[] = [];
  let len = 0;
  let i = 0;
  while (len < target) {
    // Every few words one of the person's phrases (identifiers, or their plain name words).
    const w = own.length && i % 5 === 2 ? own[pick(own.length)] : ORDINARY[pick(ORDINARY.length)];
    out.push(w);
    len += w.length + 1;
    i++;
  }
  let s = out.join(" ").slice(0, Math.max(target, 1));
  // Spread the line breaks through the text; a JSON escape before a name is the point.
  for (let n = 0; n < Math.min(lines, 40); n++) {
    const at = s.indexOf(" ", Math.floor(((n + 1) * s.length) / (Math.min(lines, 40) + 1)));
    if (at > 0) s = s.slice(0, at) + "\n" + s.slice(at + 1);
  }
  return s;
}

// Payload fields of media parts: base64 data, URLs and file ids, never prose.
const PAYLOAD_KEYS = new Set(["data", "url", "image_url", "file_data", "file_id"]);
// Opaque protocol values: a thinking block's text and signature, the ids that pair a tool call
// with its result, an encrypted reasoning blob. The upstream mints and verifies them (the
// signature covers the thinking text), so redaction leaves them as they are and the restore never
// writes identifiers into them (src/streaming.ts): a thinking block echoed back carries
// placeholders at most. The egress check still reads them, so an identifier written there by a
// fill would count as a leak that no real request can carry (every live anthropic/messages shape
// with a thinking block failed the replay from 2026-10-15, once forge's agents started sending them).
const OPAQUE_KEYS = new Set(["thinking", "signature", "id", "tool_use_id", "tool_call_id", "call_id", "encrypted_content", "previous_response_id"]);

/**
 * Fills one shape in. Anonymised keys become `field<n>`; numbers, booleans and models are fixed.
 * The person's identifiers go only where cordon redacts: message and tool text, and tool-call
 * arguments and JSON text inside them (`data` true below those). Caller-defined fields outside
 * them (metadata, prompt variables, unknown keys), media payloads and opaque protocol values
 * (signatures, tool-call ids), which cordon reads at egress but does not rewrite, get neutral
 * words only: a declared identifier there is refused by design, which is not what a replay
 * measures.
 */
export function instantiate(shape: unknown, p: Person, mode: Mode, pick: (n: number) => number, data = false): unknown {
  if (typeof shape === "string") return shape; // an enum value, kept as recorded
  if (shape === null || typeof shape !== "object") return shape;
  if (Array.isArray(shape)) {
    const out: unknown[] = [];
    for (const item of shape) {
      const more = item && typeof item === "object" && !Array.isArray(item) && "$more" in item ? Number((item as { $more: unknown }).$more) : 0;
      if (more) {
        const last = shape[shape.length - 2];
        // Every recorded item: a long history is replayed at its real length.
        for (let k = 0; k < more; k++) out.push(instantiate(last, p, mode, pick, data));
      } else out.push(instantiate(item, p, mode, pick, data));
    }
    return out;
  }
  const o = shape as Record<string, unknown>;
  if ("$tool" in o) return `tool_${o.$tool}`;
  if ("$model" in o) return "m";
  if ("$n" in o) return 7;
  if ("$b" in o) return true;
  if ("$deep" in o) return null;
  if (typeof o.$s === "number") {
    if (o.$json !== undefined) return JSON.stringify(instantiate(o.$json, p, mode, pick, true), null, o.$pretty ? 2 : undefined);
    return text(o.$s, typeof o.$nl === "number" ? o.$nl : 0, p, mode, pick);
  }
  const toolCall = typeof o.type === "string" && /tool_use$|_call$/.test(o.type);
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) {
    const caller = k.startsWith("*");
    // An enum field whose value was not kept (recorded as text) gets neutral words: it is the
    // API's vocabulary slot, not prose.
    const neutral = k === "metadata" || PAYLOAD_KEYS.has(k) || OPAQUE_KEYS.has(k) || ENUM_FIELDS.has(k) || (caller && !data);
    const below = data || (k === "input" && toolCall);
    out[caller ? `field${k.slice(1)}` : k] = instantiate(v, p, neutral ? "neutral" : mode, pick, below);
  }
  return out;
}

export interface ReplayFailure {
  h: string;
  provider: string;
  dialect: string;
  person: number;
  check: "leak" | "refusal";
  where: string;
}

const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");

/** Runs every shape against every person; returns the failures (shape digest, person index, kind, where). */
export function replayShapes(records: ShapeRecord[], people: Person[] = REPLAY_PEOPLE): { runs: number; failures: ReplayFailure[] } {
  const failures: ReplayFailure[] = [];
  let runs = 0;
  people.forEach((p, i) => {
    const comp = compileSubjects(parseSubjectHeader(enc({ ref: "replay", subjects: [{ names: [p.name], emails: [p.email], phones: [p.phone] }] })), "replay");
    const det = withSubjects(detector, comp);
    for (const rec of records) {
      const provider = rec.provider as Provider;
      const dialect = (rec.dialect || undefined) as Dialect | undefined;
      for (const mode of ["identifiers", "ordinary"] as const) {
        runs++;
        const body = instantiate(rec.shape, p, mode, picker(i * 7919 + rec.h.length));
        const vault = new Vault("reversible");
        const { deidBody } = applyRedaction(body, provider, vault, ["pii", "pci", "secrets"], det, true, dialect);
        const where = new Map<string, string>();
        const hits = egressViolations(deidBody, comp, { minted: vault.minted, raw: body }, where);
        if (hits.length)
          failures.push({ h: rec.h, provider: rec.provider, dialect: rec.dialect, person: i, check: mode === "identifiers" ? "leak" : "refusal", where: [...where].map(([k, w]) => `${k}@${w}`).join(" ") });
      }
    }
  });
  return { runs, failures };
}
