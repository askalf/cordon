// Known subjects: the people a request is about, declared by the caller.
//
// Pattern detection finds what has a shape (an email, a card, an SSN). It cannot know that
// "Marisol Quintero-Vance", "Quintero-Vance, M.", "mqvance77" and "1428 Elm St" all point at one person. A
// caller that already holds a case file can say so: X-Cordon-Subject carries the subjects'
// identifiers for this request only. cordon then
//
//   1. matches each identifier in the forms it is written in (name order and initials,
//      street-suffix abbreviations, phone and ID separators, date formats, handles), ahead
//      of the pattern catalog, so the model sees <SUBJECT1_NAME_…> and never the value;
//   2. checks the de-identified body once more before it leaves (egressViolations): every
//      string leaf, object keys included, is searched for every identifier under a looser
//      reading (NFKC, zero-width characters dropped, case folded, separators ignored). One
//      hit refuses the request, upstream never called;
//   3. handles media by the stricter of the policy and the header: refuse it (block, the
//      default), mask the identifiers in each image and read it again before it goes
//      (mask, media/mask.ts), or forward it unread (allow).
//
// The header is read once, held in this request's memory, never forwarded (providers
// forward an allowlist of auth headers), never written to the audit log or metrics. Only
// an opaque digest of `ref` is recorded, so a caller can ask for the receipts of one case.

import { createHash } from "node:crypto";
import type { Detector, RedactSet, Span } from "./types";
import { exactDecimal, MAX_INTEGRAL_DIGITS } from "./redact/apply";

/** Most bytes the header may carry, before base64url decoding. */
export const MAX_SUBJECT_HEADER = 12 * 1024;
/** Most subjects in one request, and identifiers per list. */
const MAX_SUBJECTS = 8;
const MAX_PER_LIST = 32;
const MAX_VALUE = 200;

export interface SubjectInput {
  names?: string[];
  emails?: string[];
  phones?: string[];
  addresses?: string[];
  dates?: string[];
  ids?: string[];
  handles?: string[];
  other?: string[];
}

export interface SubjectSpec {
  /** Opaque caller reference (a case id). Never PII; stored only as a digest. */
  ref?: string;
  subjects: SubjectInput[];
  /** What the caller asks for media: block, mask or allow. Unset leaves it to the policy. */
  media?: MediaMode;
}

/** One compiled identifier: a matcher for detection and needles for the egress check. */
interface Matcher {
  type: string; // SUBJECT<n>_<KIND>
  /** Case-insensitive forms, and the capitalised single tokens (case-sensitive). */
  res: RegExp[];
  /** Lower-cased alphanumeric needles for the egress check (separator-blind). */
  folded: string[];
  /** Digit sequences for the egress check, matched with up to 3 separators between digits. */
  digits: string[];
  /** The digit sequences as regexes, compiled once per request, plus any egress-only
   *  forms (dates with spaced separators, IDs with any run of separators). */
  digitRes: RegExp[];
  /** Name tokens read at egress with any separators: a match counts only when it is spread out
   *  or starts with a capital (a lowercase ordinary word is not the name). */
  spreadRes: RegExp[];
}

export interface CompiledSubjects {
  ref?: string;
  refDigest?: string;
  media?: MediaMode;
  matchers: Matcher[];
  /** The most digits any declared identifier holds: a number literal is read at egress at its
   *  exact decimal value up to this length, so no declared number hides in exponent form. */
  numberDigits: number;
}

const LISTS: Array<[keyof SubjectInput, string]> = [
  ["names", "NAME"],
  ["emails", "EMAIL"],
  ["phones", "PHONE"],
  ["addresses", "ADDRESS"],
  ["dates", "DOB"],
  ["ids", "ID"],
  ["handles", "HANDLE"],
  ["other", "OTHER"],
];

export class SubjectError extends Error {}

/** How a known-subject request's media is handled, strictest first. */
export type MediaMode = "block" | "mask" | "allow";
export const MEDIA_MODES: MediaMode[] = ["block", "mask", "allow"];
/** The stricter of the policy's mode and the caller's (a header may tighten, never loosen). */
export const strictestMedia = (policy: MediaMode | undefined, asked: MediaMode | undefined): MediaMode => {
  const p = MEDIA_MODES.indexOf(policy ?? "block");
  const a = asked === undefined ? p : MEDIA_MODES.indexOf(asked);
  return MEDIA_MODES[Math.min(p, a)];
};

/** Decode and validate X-Cordon-Subject (base64url JSON). Throws SubjectError on any defect. */
export function parseSubjectHeader(raw: string | undefined): SubjectSpec | undefined {
  if (raw === undefined || raw === "") return undefined;
  if (raw.length > MAX_SUBJECT_HEADER) throw new SubjectError(`X-Cordon-Subject is over ${MAX_SUBJECT_HEADER} bytes`);
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(raw)) throw new SubjectError("X-Cordon-Subject is not base64url");
  let obj: any;
  try {
    obj = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
  } catch {
    throw new SubjectError("X-Cordon-Subject is not base64url JSON");
  }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) throw new SubjectError("X-Cordon-Subject must be a JSON object");
  const subjects = obj.subjects;
  if (!Array.isArray(subjects) || subjects.length === 0) throw new SubjectError("X-Cordon-Subject needs a non-empty subjects array");
  if (subjects.length > MAX_SUBJECTS) throw new SubjectError(`X-Cordon-Subject has more than ${MAX_SUBJECTS} subjects`);
  const out: SubjectInput[] = subjects.map((s: any, i: number) => {
    if (!s || typeof s !== "object" || Array.isArray(s)) throw new SubjectError(`subject ${i + 1} must be an object`);
    const clean: SubjectInput = {};
    for (const key of Object.keys(s)) {
      if (!LISTS.some(([k]) => k === key)) throw new SubjectError(`subject ${i + 1} has an unknown list "${key}"`);
      const list = s[key];
      if (!Array.isArray(list) || list.length > MAX_PER_LIST || list.some((v) => typeof v !== "string" || v.length > MAX_VALUE))
        throw new SubjectError(`subject ${i + 1} ${key} must be up to ${MAX_PER_LIST} strings of up to ${MAX_VALUE} characters`);
      clean[key as keyof SubjectInput] = list.map((v: string) => v.trim()).filter(Boolean);
    }
    return clean;
  });
  if (obj.ref !== undefined && (typeof obj.ref !== "string" || obj.ref.length > 128)) throw new SubjectError("ref must be a string of up to 128 characters");
  if (obj.media !== undefined && !MEDIA_MODES.includes(obj.media)) throw new SubjectError('media must be "block", "mask" or "allow"');
  return { ref: obj.ref, subjects: out, media: obj.media };
}

/** Opaque, stable digest of a caller ref for the audit log (the ref itself is never stored). */
export const refDigest = (ref: string, key: string) =>
  createHash("sha256").update(`cordon-subject-ref\0${key}\0${ref}`).digest("hex").slice(0, 24);

// ---- text normalisation shared by detection and the egress check ----

const ZERO_WIDTH = /[​-‍⁠﻿­]/g;
/** What the egress check reads: NFKC, zero-width characters dropped, case folded. */
export const foldText = (s: string) => s.normalize("NFKC").replace(ZERO_WIDTH, "").toLowerCase();
/** A declared identifier as compiled: NFKC with zero-width characters dropped, case kept, so a
 *  full-width digit or letter is read as its ASCII form before digits or letters are extracted. */
const declared = (s: string) => s.normalize("NFKC").replace(ZERO_WIDTH, "").trim();
/** The same letters without accents: "José" and "Jose" read alike. */
export const unaccent = (s: string) => s.normalize("NFD").replace(/\p{M}+/gu, "").normalize("NFC");
/** Letters and digits only, after foldText: separators, spacing and punctuation ignored. */
export const alnum = (s: string) => unaccent(foldText(s)).replace(/[^\p{L}\p{N}]+/gu, "");
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** A name token, escaped, with apostrophes and hyphens loosened: O'Brien, O’Brien, OBrien;
 *  Quintero-Vance, Quintero Vance, QuinteroVance. */
const tok = (t: string) => esc(t).replace(/['’]/g, "['’]?").replace(/-/g, "[\\s\\-]?");
/** A literal whose internal whitespace and punctuation may vary: "Elm  Street", "Elm-Street". */
const loose = (s: string) =>
  s
    .trim()
    .split(/[\s.,'’\-_]+/)
    .filter(Boolean)
    .map(esc)
    .join("[\\s.,'’\\-_]*");
/** Digits with up to 8 separator characters between each (phones, IDs), for detection. */
const digitPattern = (d: string) => d.split("").join("[^\\p{L}\\p{N}]{0,8}");
/** The egress reading: any run of separators between the digits, but never a letter or
 *  another digit, so "4    0    4 ..." is caught and two numbers split by a word are not joined. */
const egressDigitPattern = (d: string) => d.split("").join("[^\\p{L}\\p{N}]*");
/** The egress reading of a short literal (handles, other): its letters and digits with any run
 *  of separators between them, word-bounded, so "a b c d" is caught and "abcdef" is not.
 *  Shorter than `min` characters gives no pattern. */
const egressSpread = (s: string, min = 4) =>
  alnum(s).length >= min ? [`(?<![\\p{L}\\p{N}])${[...alnum(s)].map(esc).join("[^\\p{L}\\p{N}]*")}(?![\\p{L}\\p{N}])`] : [];
/** A name joined like a username (marisolvance, mvance, vancem): letter-bounded, so digits may
 *  follow ("mvance77") but another word may not start or end it ("advancement" holds vancem,
 *  "the stone might" flattens to stonemight). For detection, contiguous; for egress, with any
 *  separators between the letters. */
const handleForm = (h: string) => `(?<!\\p{L})${esc(h.toLowerCase())}(?!\\p{L})`;
const handleSpread = (h: string) => `(?<!\\p{L})${[...alnum(h)].map(esc).join("[^\\p{L}\\p{N}]*")}(?!\\p{L})`;

// Common words that are also given names or surnames. Alone and capitalised they still
// read as words often enough ("Will you", "Hope Street") that redacting them would corrupt
// instructions; they are matched only as part of a fuller form of the name.
const COMMON = new Set(
  ("will mark grace hope faith joy rose may june april august bill pat sue art rich young white black brown " +
    "green king long rice bell hill wood cook page case hunt fox love price miles chase lane dawn summer " +
    "autumn winter day guy max ray jack frank sterling major baker carter mason hunter parker cooper " +
    "taylor walker turner ward wells park gray grey stone ford hall field holly ivy iris amber crystal " +
    "eve sky star river sage reed rush north south west east")
    .split(" "),
);

// The provider APIs' own object keys, exactly as they are spelled. Every body carries them,
// so at egress a key is read only when it is not one of these: a subject named "Name" would
// otherwise refuse every request on its "name" key. Values are still read under every key.
export const PROTOCOL_KEYS = new Set(
  ("model messages system role content type text name id input output instructions tools tool_choice " +
    "tool_calls tool_call_id tool_use_id function arguments parameters properties required description " +
    "items enum default format source media_type data url image_url input_image detail file file_id " +
    "file_data filename result is_error metadata stream temperature top_p top_k max_tokens " +
    "max_output_tokens max_completion_tokens stop stop_sequences thinking budget_tokens signature " +
    "cache_control ephemeral reasoning effort summary store previous_response_id user response_format " +
    "json_schema schema strict additionalProperties call_id status title")
    .split(" "),
);

// The APIs' own enum fields and values ("type": "text", "role": "user"). A value is skipped at
// egress only under one of these fields and only when it is exactly one of these words; the
// same word in instructions, metadata or any other field is read.
export const ENUM_FIELDS = new Set(["type", "role", "media_type", "detail", "status", "effort", "tool_choice", "stop_reason", "finish_reason", "object"]);
export const ENUM_VALUES = new Set(
  ("text image document tool_use tool_result thinking redacted_thinking input_text input_image input_file " +
    "output_text refusal function function_call function_call_output message reasoning summary_text user " +
    "assistant system developer tool base64 url file auto low medium high minimal none any required " +
    "ephemeral object string number integer boolean array null json_schema json_object image_url " +
    "image/png image/jpeg image/gif image/webp application/pdf text/plain completed in_progress enabled disabled")
    .split(" "),
);

const STREET_SUFFIX: Record<string, string[]> = {
  street: ["street", "st"], avenue: ["avenue", "ave", "av"], road: ["road", "rd"], drive: ["drive", "dr"],
  lane: ["lane", "ln"], court: ["court", "ct"], boulevard: ["boulevard", "blvd"], circle: ["circle", "cir"],
  place: ["place", "pl"], parkway: ["parkway", "pkwy"], highway: ["highway", "hwy"], terrace: ["terrace", "ter"],
  trail: ["trail", "trl"], way: ["way", "wy"], square: ["square", "sq"], crossing: ["crossing", "xing"],
  point: ["point", "pt"], ridge: ["ridge", "rdg"], run: ["run"], cove: ["cove", "cv"], loop: ["loop"],
  pike: ["pike"], path: ["path"], walk: ["walk"], row: ["row"], alley: ["alley", "aly"],
};
const DIRECTION: Record<string, string[]> = {
  north: ["north", "n"], south: ["south", "s"], east: ["east", "e"], west: ["west", "w"],
  northeast: ["northeast", "ne"], northwest: ["northwest", "nw"], southeast: ["southeast", "se"], southwest: ["southwest", "sw"],
};
const variantsOf = (table: Record<string, string[]>, word: string): string[] | undefined => {
  const w = word.toLowerCase().replace(/\.$/, "");
  for (const forms of Object.values(table)) if (forms.includes(w)) return forms;
  return undefined;
};

// Words that start the unit part of a street line ("Apt 4", "Suite 200", "#4"). What follows
// one names a unit inside the street address, so the street before it is identifying alone.
const UNIT = /^(?:#.*|apt|apartment|unit|suite|ste|room|rm|floor|fl|bldg|building|lot|trlr|spc)\.?$/i;

const MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];

// ---- per-kind matchers ----

function nameForms(name: string): { patterns: string[]; exact: string[]; folded: string[]; egress: string[]; spread: string[] } {
  const tokens = name.split(/[\s,]+/).map((t) => t.replace(/\.$/, "")).filter(Boolean);
  const patterns = new Set<string>();
  const exact = new Set<string>();
  const folded = new Set<string>();
  const egress = new Set<string>();
  if (!tokens.length) return { patterns: [], exact: [], folded: [], egress: [], spread: [] };
  const first = tokens[0];
  const last = tokens[tokens.length - 1];
  const middle = tokens.slice(1, -1);
  const S = "[\\s.,'’\\-_]+";
  if (tokens.length >= 2) {
    patterns.add(tokens.map(tok).join(S)); // as given
    patterns.add(`${tok(first)}${S}${tok(last)}`); // first last
    patterns.add(`${tok(last)}\\s*,\\s*${tok(first)}(?:${S}${middle.map(tok).join(S)})?`); // last, first [middle]
    patterns.add(`${esc(first[0])}\\.?${S}${middle.length ? `(?:${middle.map((m) => `${esc(m[0])}\\.?`).join(S)}${S})?` : ""}${tok(last)}`); // M. [L.] Vance
    patterns.add(`(?<![\\p{L}\\p{N}])${tok(last)}\\s*,\\s*${esc(first[0])}\\.?${middle.length ? `(?:${S}${middle.map((m) => `${esc(m[0])}\\.?`).join(S)})?` : ""}(?![\\p{L}\\p{N}])`); // Vance, M. [L.]
    if (middle.length) patterns.add(`${tok(first)}${S}${middle.map((m) => `${esc(m[0])}\\.?`).join(S)}${S}${tok(last)}`); // Marisol L. Vance
    // Handles and concatenations: marisolvance, marisol.vance, mvance, vancem
    // A form too short to be a needle or a handle ("Will Ray" as wray, rayw; "Will Li" as wli)
    // is still read at egress word-bounded with any separators, however short, so "w . r a y"
    // and "W . L i" are caught and "wrays" is not.
    // The full first-and-last joins are also separator-blind needles (long enough not to turn up
    // by chance); the initial joins are read letter-bounded only, since a surname followed by
    // any word starting with the initial would otherwise hold one.
    for (const h of [first + last, last + first, first[0] + last, last + first[0]]) {
      if (h.length >= 6) patterns.add(handleForm(h));
      if (alnum(h)) egress.add(handleSpread(h));
    }
    folded.add(alnum(first + last));
    folded.add(alnum(last + first));
    // The whole name in order, middle names included: "w i l l h e n r y g r a c e".
    folded.add(alnum(tokens.join("")));
    // The middle-initial forms detection accepts, read separator-blind: "w . h . g r a c e",
    // "will h grace", "grace, w. h.".
    if (middle.length) {
      const initials = middle.map((m) => m[0]).join("");
      for (const h of [first[0] + initials + last, first + initials + last, last + first[0] + initials])
        if (alnum(h).length >= 6) folded.add(alnum(h));
        else for (const p of egressSpread(h, 1)) egress.add(p);
    }
  }
  // Single tokens alone (word-bounded, capitalised): skipped for short and common words.
  // A one-token name is matched only this way, so "Will" never matches "we will" or "willing".
  for (const t of tokens)
    if (t.length >= 3 && !COMMON.has(t.toLowerCase())) {
      exact.add(`(?<![\\p{L}\\p{N}])${esc(t[0].toUpperCase())}${tok(t.slice(1))}(?![\\p{L}\\p{N}])`);
      // In capitals too ("GRANT"), which the capitalised form does not match.
      exact.add(`(?<![\\p{L}\\p{N}])${tok(t.toUpperCase())}(?![\\p{L}\\p{N}])`);
    }
  // At egress every token matched alone is also read word-bounded with any separators, down to
  // the three letters the capitalised match accepts, whether the name was declared as one token
  // or several: "Z o e" and "M a r i s o l" (from "Marisol Quintero-Vance") are caught, "zoes"
  // and "marisols" are not. These are `spread` forms: a match counts only when it is spread out
  // or starts with a capital, because a name token is often an ordinary word too, and "this is
  // a test" or "grant access" written in lowercase is not the visitor named Test or Grant.
  const spread = new Set<string>();
  for (const t of tokens)
    if (t.length >= 3 && !COMMON.has(t.toLowerCase())) for (const p of egressSpread(t, 3)) spread.add(p);
  return { patterns: [...patterns], exact: [...exact], folded: [...folded], egress: [...egress], spread: [...spread] };
}

function addressForms(addr: string): { patterns: string[]; folded: string[] } {
  // The street line carries the identity; city, state and ZIP alone are shared by thousands.
  // A unit written without a comma ("1428 Elm Street Apt 4") is cut off the street line too,
  // so the street alone in any spelling is matched and read at egress.
  const line = addr.split(/,|\n/)[0].trim().split(/\s+/).filter(Boolean);
  const unitAt = line.findIndex((w, i) => i >= 2 && UNIT.test(w));
  const words = unitAt > 0 ? line.slice(0, unitAt) : line;
  const street = words.join(" ");
  if (words.length < 2) return { patterns: [loose(addr)], folded: [alnum(addr)] };
  const partOf = (w: string) => {
    const forms = variantsOf(STREET_SUFFIX, w) ?? variantsOf(DIRECTION, w);
    return forms ? `(?:${forms.map(esc).join("|")})\\.?` : esc(w.replace(/\.$/, ""));
  };
  const patterns = [words.map(partOf).join("[\\s,]+"), loose(addr)];
  // The street with its unit, in any spelling, so "1428 Elm St Apt 4" is replaced whole.
  if (unitAt > 0) patterns.push(line.map(partOf).join("[\\s,]+"));
  // Unit numbers: "1428 Elm St Apt 4", "1428 Elm St #4" are covered by the street line.
  // The egress reading ignores separators, so each spelling the patterns accept ("Street",
  // "St"; "North", "N") is its own needle: "1428 E l m S t" flattens to 1428elmst.
  let spellings = [""];
  for (const w of words) {
    const forms = variantsOf(STREET_SUFFIX, w) ?? variantsOf(DIRECTION, w) ?? [w.replace(/\.$/, "")];
    spellings = spellings.flatMap((s) => forms.map((f) => s + f)).slice(0, 64);
  }
  return { patterns, folded: [...new Set([alnum(street), ...spellings.map(alnum)])] };
}

/** A month written as a word ("July", "Jul.", "Sept"), as its number, or 0. */
const monthOf = (w: string) => {
  const x = w.toLowerCase().replace(/\.$/, "");
  return MONTHS.findIndex((mo) => x === mo || x === mo.slice(0, 3) || (mo === "september" && x === "sept")) + 1;
};

function dateForms(date: string): { patterns: string[]; digits: string[]; egress: string[] } {
  // A date in a form not parsed below is matched as written, and read at egress word-bounded
  // with any separators between its letters and digits, like any other literal.
  const literal = () => ({ patterns: [loose(date)], digits: [], egress: egressSpread(date, 1) });
  let y: number, m: number, d: number;
  const iso = /^(\d{4})-(\d{1,2})-(\d{1,2})$/.exec(date);
  const us = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(date);
  // Spelled-out months: "July 14, 1986", "Jul 14th 1986", "14 July 1986", "14th of July, 1986".
  const mdy = /^(\p{L}+\.?)\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})$/iu.exec(date);
  const dmy = /^(\d{1,2})(?:st|nd|rd|th)?\s+(?:of\s+)?(\p{L}+\.?),?\s+(\d{4})$/iu.exec(date);
  if (iso) [y, m, d] = [Number(iso[1]), Number(iso[2]), Number(iso[3])];
  else if (us) [y, m, d] = [Number(us[3]), Number(us[1]), Number(us[2])];
  else if (mdy && monthOf(mdy[1])) [y, m, d] = [Number(mdy[3]), monthOf(mdy[1]), Number(mdy[2])];
  else if (dmy && monthOf(dmy[2])) [y, m, d] = [Number(dmy[3]), monthOf(dmy[2]), Number(dmy[1])];
  else return literal();
  if (m < 1 || m > 12 || d < 1 || d > 31) return literal();
  const mm = String(m).padStart(2, "0");
  const dd = String(d).padStart(2, "0");
  const yy = String(y).slice(2);
  const month = MONTHS[m - 1];
  const mon = `(?:${month}|${month.slice(0, 3)}\\.?${month === "september" ? "|sept\\.?" : ""})`;
  const nb = (s: string) => `(?<!\\d)${s}(?!\\d)`;
  const patterns = [
    nb(`${y}[-/.]0?${m}[-/.]0?${d}`), // 1985-03-02
    nb(`0?${m}[-/.]0?${d}[-/.](?:${y}|${yy})`), // 03/02/1985, 3/2/85
    `${mon}\\s+0?${d}(?:st|nd|rd|th)?,?\\s+${y}`, // March 2, 1985
    nb(`0?${d}(?:st|nd|rd|th)?\\s+(?:of\\s+)?${mon},?\\s+${y}`), // 2 March 1985
    nb(`${y}${mm}${dd}`), // 19850302
    nb(`${mm}${dd}${y}`), // 03021985
  ];
  // The spelled-out forms the patterns accept, read separator-blind: any run of separators
  // between every letter and digit ("J u l y 14, 1986", "1 4 t h of j u l 1986").
  const G = "[^\\p{L}\\p{N}]*";
  const spread = (s: string) => [...s].map(esc).join(G);
  // The egress reading of the separated numeric forms, padded or not and with either year:
  // any run of separators between the digits of each part ("7 / 1 4 / 1 9 8 6") and at
  // least one between the parts ("3 - 2 - 85"), so a bare short number such as 3285 is
  // never read as the date.
  const SEP = "[^\\p{L}\\p{N}]+";
  const mG = `(?:0${G})?${spread(String(m))}`;
  const dG = `(?:0${G})?${spread(String(d))}`;
  const egress = [nb(`${spread(String(y))}${SEP}${mG}${SEP}${dG}`), nb(`${mG}${SEP}${dG}${SEP}(?:${spread(String(y))}|${spread(yy)})`)];
  const monG = `(?:${[month, month.slice(0, 3), ...(month === "september" ? ["sept"] : [])].map(spread).join("|")})`;
  const dayG = `(?:0${G})?${spread(String(d))}(?:${G}(?:${["st", "nd", "rd", "th"].map(spread).join("|")}))?`;
  const yearG = `${spread(String(y))}(?!\\d)`;
  egress.push(`${monG}${G}${dayG}${G}${yearG}`, `(?<!\\d)${dayG}${G}(?:${spread("of")}${G})?${monG}${G}${yearG}`);
  return { patterns, digits: [`${y}${mm}${dd}`, `${mm}${dd}${y}`], egress };
}

/** Compile a spec into matchers. Identifiers too short to match safely are dropped. */
export function compileSubjects(spec: SubjectSpec, refKey: string): CompiledSubjects {
  const matchers: Matcher[] = [];
  let numberDigits = MAX_INTEGRAL_DIGITS;
  spec.subjects.forEach((s, i) => {
    const n = i + 1;
    for (const [key, kind] of LISTS) {
      for (const raw of s[key] ?? []) {
        const value = declared(raw);
        if (!value) continue;
        numberDigits = Math.max(numberDigits, value.replace(/\D/g, "").length);
        let patterns: string[] = [];
        let exact: string[] = [];
        let folded: string[] = [];
        let digits: string[] = [];
        let egress: string[] = [];
        let spread: string[] = [];
        switch (kind) {
          case "NAME": {
            const f = nameForms(value);
            patterns = f.patterns;
            exact = f.exact;
            folded = f.folded;
            egress = f.egress;
            spread = f.spread;
            break;
          }
          case "EMAIL": {
            const at = value.lastIndexOf("@");
            patterns = [esc(value)];
            folded = [alnum(value)];
            const local = at > 0 ? value.slice(0, at) : "";
            // The local part is often reused as a username elsewhere.
            if (local.length >= 5) {
              patterns.push(`(?<![\\p{L}\\p{N}])${loose(local)}(?![\\p{L}\\p{N}])`);
              if (alnum(local).length >= 6) folded.push(alnum(local));
              // At egress it is also read word-bounded with any separators, however short it is
              // once punctuation is dropped: "a b c d e" (from abcde@...) is caught, "abcdef" is not.
              egress = egressSpread(local, 1);
            }
            break;
          }
          case "PHONE": {
            let d = value.replace(/\D/g, "");
            if (d.length === 11 && d.startsWith("1")) d = d.slice(1);
            if (d.length < 7) continue;
            patterns = [`(?<!\\d)(?:\\+?1[^\\p{L}\\p{N}]{0,3})?${digitPattern(d)}(?!\\d)`];
            digits = [d];
            // At egress the same optional leading country code, with any separators: "1" then the
            // digits spread wider than detection reaches is the declared number.
            egress = [`(?<!\\d)(?:1[^\\p{L}\\p{N}]*)?${egressDigitPattern(d)}(?!\\d)`];
            break;
          }
          case "ADDRESS": {
            const f = addressForms(value);
            patterns = f.patterns;
            folded = f.folded.filter((x) => x.length >= 8);
            // A spelling too short to be a needle ("1 Oak St" as 1oakst, "1 A" as 1a) is still read
            // at egress word-bounded with any separators, however short, so "1 O a k S t" and
            // "1 / A" are caught.
            egress = f.folded.filter((x) => x.length < 8).flatMap((x) => egressSpread(x, 1));
            break;
          }
          case "DOB": {
            const f = dateForms(value);
            patterns = f.patterns;
            digits = f.digits;
            egress = f.egress;
            break;
          }
          case "ID": {
            // Letters and numbers in any script are kept: dropping "é" from "ABé1234" would
            // compile an ID that is never written.
            const d = value.replace(/[^\p{L}\p{N}]/gu, "");
            if ([...d].length < 4) continue;
            const idPattern = (s: string) => `(?<![\\p{L}\\p{N}])${[...s].map(esc).join("[^\\p{L}\\p{N}]{0,8}")}(?![\\p{L}\\p{N}])`;
            patterns = [idPattern(d)];
            // The same ID written without its accents is the same ID.
            if (unaccent(d) !== d) patterns.push(idPattern(unaccent(d)));
            // The egress reading: any run of separators between the characters, word-bounded and
            // without accents, so a short ID spread wider than detection reaches is still caught.
            egress = egressSpread(d, 1);
            if (/^\d+$/.test(d) && d.length >= 7) digits = [d];
            else if (alnum(d).length >= 6) folded = [alnum(d)];
            break;
          }
          case "HANDLE": {
            const h = value.replace(/^@/, "");
            if (h.length < 4) continue;
            patterns = [`@?${loose(h)}`];
            egress = egressSpread(h, 1);
            if (alnum(h).length >= 6) folded = [alnum(h)];
            break;
          }
          default: {
            if (value.length < 4) continue;
            patterns = [loose(value)];
            egress = egressSpread(value, 1);
            if (alnum(value).length >= 6) folded = [alnum(value)];
          }
        }
        if (!patterns.length && !exact.length) continue;
        if (kind === "NAME" || kind === "ADDRESS" || kind === "OTHER") {
          const plain = unaccent(value);
          if (plain !== value) {
            const again: { patterns: string[]; exact?: string[] } = kind === "NAME" ? nameForms(plain) : kind === "ADDRESS" ? addressForms(plain) : { patterns: [loose(plain)] };
            patterns = [...patterns, ...again.patterns];
            exact = [...exact, ...(again.exact ?? [])];
          }
        }
        // The identifier as the caller wrote it (full-width, say) is redacted where it appears so.
        if (raw.trim() !== value && loose(raw)) patterns = [...patterns, `(?<![\\p{L}\\p{N}])${loose(raw)}(?![\\p{L}\\p{N}])`];
        // One regex per form, not one alternation: an alternation stops at the first form that
        // matches at a position, so "mqvance77" would win over "mqvance77@example.com". Every
        // form's spans are collected and withSubjects keeps the longest of any overlap.
        const res = [...patterns.map((p) => new RegExp(p, "giud")), ...exact.map((p) => new RegExp(p, "gud"))];
        const digitRes = [
          ...digits.map((d) => new RegExp(`(?<!\\d)${egressDigitPattern(d)}(?!\\d)`, "u")),
          ...egress.map((p) => new RegExp(p, "u")),
        ];
        const spreadRes = spread.map((p) => new RegExp(p, "giu"));
        matchers.push({ type: `SUBJECT${n}_${kind}`, res, folded, digits, digitRes, spreadRes });
      }
    }
  });
  return { ref: spec.ref, refDigest: spec.ref ? refDigest(spec.ref, refKey) : undefined, media: spec.media, matchers, numberDigits };
}

const SUBJECT_SETS: RedactSet[] = ["pii"];

/** Spans for every subject identifier in one text field (local offsets, original text). */
export function subjectSpans(text: string, compiled: CompiledSubjects): Span[] {
  const out: Span[] = [];
  // JSON text (a tool result's content, say) writes a newline as \n, and that n glues to the
  // name after it and defeats the word boundary. Escapes are read as separators of the same
  // length, so every offset still points into the original text.
  const probe = text.includes("\\") ? text.replace(/\\[nrtbf"\\/]/g, "  ") : text;
  for (const m of compiled.matchers)
    for (const re of m.res) {
      // matchAll starts at the regex's lastIndex, which the egress check's test() moves: reset it.
      re.lastIndex = 0;
      for (const hit of probe.matchAll(re)) {
        const start = hit.index ?? 0;
        const end = start + hit[0].length;
        if (end > start) out.push({ start, end, type: m.type, value: text.slice(start, end), sets: SUBJECT_SETS });
      }
    }
  return out;
}

const overlaps = (a: Span, b: Span) => a.start < b.end && b.start < a.end;

/**
 * A detector that runs the subjects first and the catalog second. A subject span wins any
 * overlap (longest first among subjects); a catalog span is kept only where no subject
 * span claims its characters. Subject identifiers are redacted whatever sets are active.
 */
export function withSubjects(base: Detector, compiled: CompiledSubjects): Detector {
  return {
    name: `${base.name}+subjects`,
    detect(text: string, activeSets: RedactSet[]): Span[] {
      const known = subjectSpans(text, compiled).sort((a, b) => b.end - b.start - (a.end - a.start) || a.start - b.start);
      const accepted: Span[] = [];
      for (const s of known) if (!accepted.some((a) => overlaps(a, s))) accepted.push(s);
      for (const s of base.detect(text, activeSets)) if (!accepted.some((a) => overlaps(a, s))) accepted.push(s);
      return accepted.sort((a, b) => a.start - b.start);
    },
  };
}

// ---- the egress check ----

// Parts whose payload is pixels or file bytes. A Messages document with a text or content
// source is text, read like any other field; with a base64, URL or file source it is media.
const MEDIA_TYPES = new Set(["image", "input_image", "input_file", "image_url", "file", "audio", "input_audio", "image_generation_call"]);
const BINARY_SOURCES = new Set(["base64", "url", "file"]);
const MEDIA_PAYLOAD_KEYS = new Set(["data", "file_data", "result", "image_url", "url"]);

const isMediaPart = (node: any): boolean =>
  !!node && typeof node === "object" && typeof node.type === "string" &&
  (MEDIA_TYPES.has(node.type) || (node.type === "document" && BINARY_SOURCES.has(node.source?.type)));
/** The media parts of a body, found only where the provider schemas carry them: a message's
 *  content parts, a Chat Completions assistant message's audio reference, a tool or MCP tool
 *  result's content, a document's content source, a Responses input item or its output parts. An
 *  object of the same shape anywhere else (tool_use input, function arguments, metadata) is
 *  ordinary data and is read in full. Counting, the egress check and masking all use this. */
export function mediaPartsOf(body: any): Set<object> {
  const found = new Set<object>();
  const parts = (list: any) => {
    if (!Array.isArray(list)) return;
    for (const p of list) {
      if (isMediaPart(p)) found.add(p);
      else if (p?.type === "tool_result" || p?.type === "mcp_tool_result" || p?.type === "function_call_output") {
        parts(p.content);
        parts(p.output);
      } else if (p?.type === "document" && p.source?.type === "content") parts(p.source.content);
    }
  };
  if (!body || typeof body !== "object") return found;
  for (const m of Array.isArray(body.messages) ? body.messages : []) {
    parts(m?.content);
    // An earlier audio reply replayed by id: the provider resolves it to the audio itself.
    if (m?.audio && typeof m.audio === "object" && !Array.isArray(m.audio)) found.add(m.audio);
  }
  for (const list of [body.input, body.instructions])
    if (Array.isArray(list))
      for (const item of list) {
        if (isMediaPart(item)) found.add(item);
        else {
          parts(item?.content);
          parts(item?.output);
        }
      }
  // A Responses stored prompt's variables: each value is a string or one input part, an
  // input_image or input_file among them.
  const vars = body.prompt?.variables;
  if (vars && typeof vars === "object" && !Array.isArray(vars))
    for (const v of Object.values(vars)) {
      if (isMediaPart(v)) found.add(v as object);
      else if (Array.isArray(v)) parts(v);
    }
  return found;
}
/** A payload string the egress check does not read: inside a media part only, base64 data
 *  or a data: URL under one of the payload keys. The same key anywhere else (a metadata
 *  "result", a "data" field) is ordinary text and is read. */
const isPayload = (key: string, v: string) =>
  MEDIA_PAYLOAD_KEYS.has(key) && (v.startsWith("data:") || key === "data" || key === "file_data" || key === "result");

/** Count media parts (image, file, audio) in a request body's content locations. */
export function countMedia(body: any): number {
  return mediaPartsOf(body).size;
}

const isDigit = (c: number) => c >= 48 && c <= 57;

/** The number literals in a string that have a fraction or an exponent, in one left-to-right
 *  pass. A regex tried from every offset rescans a long digit run each time (quadratic in
 *  the run, which the caller chooses); this reads each run once, from its first digit. */
function numberLiterals(text: string): string[] {
  const out: string[] = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    if (!isDigit(text.charCodeAt(i)) || (i > 0 && isDigit(text.charCodeAt(i - 1)))) { i++; continue; }
    const start = i > 0 && text[i - 1] === "-" ? i - 1 : i;
    while (i < n && isDigit(text.charCodeAt(i))) i++;
    let marked = false;
    if (text[i] === "." && isDigit(text.charCodeAt(i + 1))) {
      i++;
      while (i < n && isDigit(text.charCodeAt(i))) i++;
      marked = true;
    }
    if (text[i] === "e" || text[i] === "E") {
      let j = i + 1;
      if (text[j] === "+" || text[j] === "-") j++;
      if (isDigit(text.charCodeAt(j))) {
        while (j < n && isDigit(text.charCodeAt(j))) j++;
        i = j;
        marked = true;
      }
    }
    if (marked) out.push(text.slice(start, i));
  }
  return out;
}

// Protocol fields whose contents the caller defines: metadata, a stored prompt's variables,
// tool schemas and a tool call's input. Below them every key and value is read.
export const CALLER_CONTAINERS = new Set(["metadata", "variables", "parameters", "properties", "schema", "input_schema", "json_schema", "additionalProperties", "arguments"]);
export const isToolCall = (node: any) => typeof node?.type === "string" && /tool_use$|_call$/.test(node.type);

/** A text as written, then each number literal in it (a fraction or an exponent, in the
 *  text or its folded spelling, so "１ｅ４０" counts as "1e40") at its exact decimal value,
 *  the spelling the identifiers are matched in. String leaves and object keys both go here. */
function pushText(text: string, out: string[], maxDigits: number): void {
  out.push(text);
  const folded = foldText(text);
  const lits = new Set(numberLiterals(text));
  if (folded !== text) for (const lit of numberLiterals(folded)) lits.add(lit);
  for (const lit of lits) {
    const exact = exactDecimal(lit, maxDigits);
    if (exact !== lit) out.push(exact);
  }
}

/** Every string leaf and object key, with media payloads skipped (they are counted, not read).
 *  `inMedia` is true below a recognised media part, the only place a payload is skipped.
 *  `caller` is true below caller-defined data (a caller container, a key the protocol does not
 *  define, decoded JSON text), where protocol keys and enum values are read like any other.
 *  When `paths` is given, it gets one entry per entry pushed to `out`: where that text sits,
 *  spelled with the protocol's own keys and array indexes only. A caller-defined key is
 *  written `*`, so a path never carries the caller's text. */
function leaves(node: any, out: string[], parts: Set<object>, maxDigits: number, depth = 0, inMedia = false, caller = false, paths?: string[], at = "$"): void {
  if (depth > 64) throw new Error("body nested deeper than 64 levels; refusing to forward unread fields");
  const mark = (where: string) => { if (paths) while (paths.length < out.length) paths.push(where); };
  if (typeof node === "string") {
    // Tool arguments arrive as JSON text: a number written 4.045550187e9 or 4045550187.0 is
    // read again at its exact decimal value.
    pushText(node, out, maxDigits);
    mark(at);
    // A JSON-string field (tool-call arguments) is decoded by the provider: its keys and
    // values are read again as decoded, so \u0057-style escapes cannot hide the letters.
    const lead = node.trimStart()[0];
    if (lead === "{" || lead === "[") {
      let decoded: unknown;
      try { decoded = JSON.parse(node); } catch { decoded = undefined; }
      if (decoded && typeof decoded === "object") leaves(decoded, out, parts, maxDigits, depth + 1, false, true, paths, `${at}<json>`);
    }
    return;
  }
  if (typeof node === "number" || typeof node === "bigint") {
    // A JSON number such as 1e21 prints as "1e+21": it is read at its exact decimal value too.
    const written = String(node);
    out.push(written);
    const exact = exactDecimal(written, maxDigits);
    if (exact !== written) out.push(exact);
    mark(at);
    return;
  }
  if (!node || typeof node !== "object") return;
  const media = inMedia || parts.has(node);
  if (Array.isArray(node)) {
    node.forEach((v, i) => leaves(v, out, parts, maxDigits, depth + 1, media, caller, paths, `${at}[${i}]`));
    return;
  }
  for (const [k, v] of Object.entries(node)) {
    const protocol = !caller && PROTOCOL_KEYS.has(k);
    const here = `${at}.${protocol ? k : "*"}`;
    if (!protocol) { pushText(k, out, maxDigits); mark(`${here}<key>`); }
    if (protocol && ENUM_FIELDS.has(k) && typeof v === "string" && ENUM_VALUES.has(v)) continue; // "type": "text"
    if (media && typeof v === "string" && isPayload(k, v)) continue; // base64 or a data: URL
    const below = !protocol || CALLER_CONTAINERS.has(k) || (k === "input" && isToolCall(node));
    leaves(v, out, parts, maxDigits, depth + 1, media, below, paths, here);
  }
}

/** A name-token form matches when some occurrence is spread out (a separator between its
 *  letters: "T e s t", "t.e.s.t") or starts with a capital ("Test", "TEST"). A plain lowercase
 *  word ("this is a test") is ordinary text, not the name. */
function spreadHit(re: RegExp, text: string): boolean {
  re.lastIndex = 0;
  for (const m of text.matchAll(re)) {
    const s = m[0];
    if (/[^\p{L}\p{N}]/u.test(s) || s[0] !== s[0].toLowerCase()) return true;
  }
  return false;
}

/** What this request's redaction minted (placeholder to entity type) and the body the
 *  caller sent, so the egress read can tell a minted placeholder from the caller's own text. */
export interface Redaction {
  minted: ReadonlyMap<string, string>;
  raw: unknown;
}

/** The placeholders whose type word the egress read drops, so "<SUBJECT1_NAME_1A2B3C_1>"
 *  does not match a subject named "Name": only those this request's redaction minted and the
 *  caller's body never held anywhere. Any other placeholder-shaped text, including a minted
 *  token the caller also wrote, is read as written. */
function ownPlaceholders(redaction: Redaction | undefined, compiled: CompiledSubjects): Array<[string, string]> {
  if (!redaction || !redaction.minted.size) return [];
  const sent: string[] = [];
  leaves(redaction.raw, sent, mediaPartsOf(redaction.raw), compiled.numberDigits);
  const callerText = sent.join("\u0000");
  return [...redaction.minted].filter(([token]) => !callerText.includes(token));
}

/**
 * Search the de-identified body for any subject identifier, read more loosely than detection:
 * the matchers again on folded text, every alphanumeric needle with separators ignored, and
 * every digit needle with up to 3 separators between digits. Returns the kinds found (never
 * the values); an empty array means the body may leave. With `where`, each kind found also
 * gets where it was first seen and which reading caught it ("pattern", "folded" or "digits"),
 * e.g. `$.messages[2].content[0].content (folded)`: protocol keys and indexes, never text.
 */
export function egressViolations(deidBody: any, compiled: CompiledSubjects, redaction?: Redaction, where?: Map<string, string>): string[] {
  const found = new Set<string>();
  const texts: string[] = [];
  const paths: string[] | undefined = where ? [] : undefined;
  leaves(deidBody, texts, mediaPartsOf(deidBody), compiled.numberDigits, 0, false, false, paths);
  const own = ownPlaceholders(redaction, compiled);
  const hit = (type: string, i: number, by: string) => {
    found.add(type);
    if (where && paths && !where.has(type)) where.set(type, `${paths[i] ?? "$"} (${by})`);
  };
  for (const [i, leaf] of texts.entries()) {
    if (!leaf) continue;
    let raw = leaf;
    for (const [token, type] of own) if (raw.includes(token)) raw = raw.split(token).join(token.replace(type, ""));
    const folded = foldText(raw);
    const plain = unaccent(folded);
    const flat = plain.replace(/[^\p{L}\p{N}]+/gu, "");
    // Case kept, for the name-token forms: normalised like `plain` but not lower-cased.
    const cased = unaccent(raw.normalize("NFKC").replace(ZERO_WIDTH, ""));
    for (const m of compiled.matchers) {
      if (found.has(m.type)) continue;
      if (m.res.some((re) => [raw, folded, plain].some((t) => { re.lastIndex = 0; const ok = re.test(t); re.lastIndex = 0; return ok; }))) {
        hit(m.type, i, "pattern");
        continue;
      }
      if (m.folded.some((needle) => needle && flat.includes(needle))) {
        hit(m.type, i, "folded");
        continue;
      }
      if (m.spreadRes.some((re) => spreadHit(re, cased))) {
        hit(m.type, i, "spread");
        continue;
      }
      if (m.digitRes.some((re) => re.test(folded) || re.test(plain))) hit(m.type, i, "digits");
    }
  }
  return [...found];
}
