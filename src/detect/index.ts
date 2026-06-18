import type { Detector, PatternDef, RedactSet, Span } from "../types";
import { patterns } from "./patterns";
import { secretPatterns } from "./secrets";

const ALL_DEFS: PatternDef[] = [...patterns, ...secretPatterns];

const intersects = (a: RedactSet[], b: RedactSet[]) => a.some((x) => b.includes(x));

/** Run one pattern over a text, yielding validated candidate spans (local offsets). */
function candidatesFor(def: PatternDef, text: string): Span[] {
  const out: Span[] = [];
  // Clone so the shared module-level regex's lastIndex is never a reentrancy hazard.
  const re = new RegExp(def.regex.source, def.regex.flags.includes("g") ? def.regex.flags : def.regex.flags + "g");
  for (const m of text.matchAll(re)) {
    const full = m[0];
    if (def.validate && !def.validate(full)) continue;

    let start: number;
    let end: number;
    if (def.group != null) {
      const idx = (m as any).indices?.[def.group];
      if (!idx) continue; // group didn't participate
      [start, end] = idx;
    } else {
      start = m.index ?? 0;
      end = start + full.length;
    }
    if (end <= start) continue; // skip empty
    out.push({ start, end, type: def.type, value: text.slice(start, end), sets: def.sets });
  }
  return out;
}

const overlaps = (a: Span, b: Span) => a.start < b.end && b.start < a.end;
const priOf = (s: Span) => ALL_DEFS.find((d) => d.type === s.type)?.priority ?? 0;

// Anti-evasion: detect on an NFKC-normalized, zero-width-stripped COPY (so
// full-width digits and a zero-width-spaced email can't slip past ASCII-only
// regexes), but keep a per-char index map back to the ORIGINAL text so we redact
// the real bytes and re-identification restores exactly what the client sent.
const ZERO_WIDTH = /[​-‍⁠﻿­]/;
function normalizeForDetect(text: string): { norm: string; map: number[] } {
  let norm = "";
  const map: number[] = []; // map[i] = original UTF-16 index of normalized char i
  let i = 0;
  for (const ch of text) {
    const cpLen = ch.length; // 1 or 2 (surrogate pair)
    if (!ZERO_WIDTH.test(ch)) {
      const n = ch.normalize("NFKC");
      for (let j = 0; j < n.length; j++) {
        norm += n[j];
        map.push(i);
      }
    }
    i += cpLen;
  }
  map.push(text.length); // sentinel: a span ending at norm.length maps to original end
  return { norm, map };
}

/**
 * Detect every entity in ONE text field for the given active sets, then resolve
 * overlaps so each character is claimed by at most one span. Resolution order:
 * priority desc → length desc → earliest start. (A card beats a phone; a longer
 * span beats a shorter one.) Returns spans (offsets + values in the ORIGINAL text)
 * sorted by start.
 *
 * This is the NER plug-in seam: a sidecar implementing `Detector` slots in here.
 */
export function runAll(text: string, activeSets: RedactSet[]): Span[] {
  if (!text) return [];
  const { norm, map } = normalizeForDetect(text);
  const changed = norm !== text;
  const src = changed ? norm : text; // pure-ASCII fast path: detect on the original
  const defs = ALL_DEFS.filter((d) => intersects(d.sets, activeSets));

  const candidates: Span[] = [];
  for (const def of defs) candidates.push(...candidatesFor(def, src));

  // Interval selection by precedence.
  candidates.sort((a, b) => priOf(b) - priOf(a) || (b.end - b.start) - (a.end - a.start) || a.start - b.start);
  const accepted: Span[] = [];
  for (const cand of candidates) {
    if (accepted.some((s) => overlaps(s, cand))) continue;
    accepted.push(cand);
  }
  accepted.sort((a, b) => a.start - b.start);

  if (changed) {
    // Remap from normalized offsets back to the original text so replaceSpans
    // redacts the real bytes and the vault stores the original value.
    for (const s of accepted) {
      const os = map[s.start] ?? 0;
      const oe = map[s.end] ?? text.length;
      s.start = os;
      s.end = oe;
      s.value = text.slice(os, oe);
    }
    accepted.sort((a, b) => a.start - b.start);
  }
  return accepted;
}

/** The deterministic detector — what the spine uses. Drop-in replaceable. */
export const detector: Detector = {
  name: "deterministic",
  detect: runAll,
};
