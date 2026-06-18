import type { PatternDef } from "../types";
import { luhn, ibanMod97, abaRouting, ssnValid } from "./validators";

// Plausible-date check for the DOB/DATE pattern (kills "99/99/9999"-style noise).
function plausibleDate(s: string): boolean {
  const m = s.match(/(\d{1,4})[/-](\d{1,2})[/-](\d{2,4})/);
  if (!m) return false;
  const nums = [m[1], m[2], m[3]].map(Number);
  // ISO (yyyy-mm-dd) vs locale (mm/dd/yyyy) — accept if some arrangement is a real date.
  const ok = (mo: number, d: number) => mo >= 1 && mo <= 12 && d >= 1 && d <= 31;
  return ok(nums[0], nums[1]) || ok(nums[1], nums[2]) || ok(nums[0], nums[2]);
}

/**
 * The deterministic entity catalog. Higher `priority` wins when spans overlap, so a
 * 16-digit card isn't also clipped as a phone number. Patterns are cloned per use in
 * the detector, so the global flag here is safe.
 */
export const patterns: PatternDef[] = [
  // ---- secrets-adjacent structured PII (high priority: very specific) ----
  {
    type: "CREDIT_CARD",
    sets: ["pci"],
    regex: /\b\d(?:[ .-]?\d){12,18}\b/g,
    validate: luhn,
    priority: 7,
  },
  {
    type: "IBAN",
    sets: ["pci"],
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/g,
    validate: ibanMod97,
    priority: 7,
  },

  // ---- contact / network PII ----
  {
    type: "EMAIL",
    sets: ["pii"],
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    priority: 6,
  },
  {
    type: "MAC",
    sets: ["pii"],
    regex: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,
    priority: 6,
  },
  {
    type: "IPV4",
    sets: ["pii"],
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    priority: 5,
  },
  {
    // Full 8-group form only (no :: compression) — keeps it unambiguous vs MAC.
    type: "IPV6",
    sets: ["pii"],
    regex: /\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b/g,
    priority: 4,
  },
  {
    // Compressed form (one `::`). Requires a hex group before and after the `::`,
    // so it can't match a single-colon MAC or a stray `a::b` scope operator.
    type: "IPV6",
    sets: ["pii"],
    regex: /\b(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}:?){0,5}[0-9A-Fa-f]{1,4}\b/g,
    priority: 4,
  },

  // ---- government / financial identifiers ----
  {
    type: "SSN",
    sets: ["pii", "phi"],
    regex: /\b\d{3}[- ]\d{2}[- ]\d{4}\b/g,
    validate: ssnValid,
    priority: 5,
  },
  {
    // Bare 9-digit ABA-valid number. Lower priority so SSN/card overlaps win.
    type: "US_ROUTING",
    sets: ["pci"],
    regex: /\b\d{9}\b/g,
    validate: abaRouting,
    priority: 3,
  },
  {
    type: "PHONE",
    sets: ["pii"],
    regex: /(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
    priority: 2,
  },
  {
    // International / E.164 form: an explicit `+<country code>` then 7–14 more
    // digits with arbitrary grouping. The required leading `+` keeps FP low; the
    // validator pins the total digit count to a real phone-number length.
    type: "PHONE",
    sets: ["pii"],
    regex: /\+\d[\d\s().-]{6,16}\d/g,
    validate: (s) => {
      const d = s.replace(/\D/g, "");
      return d.length >= 8 && d.length <= 15;
    },
    priority: 2,
  },

  // ---- street address (heuristic) ----
  {
    type: "STREET_ADDRESS",
    sets: ["pii"],
    regex:
      /\b\d{1,6}\s+(?:[A-Za-z0-9.'#]+\s+){0,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter|Circle|Cir|Highway|Hwy|Parkway|Pkwy|Square|Sq)\b\.?/gi,
    priority: 4,
  },

  // ---- PHI ----
  {
    type: "MRN",
    sets: ["phi"],
    regex: /\bMRN[:#]?\s*(\d{5,12})\b/gid,
    group: 1,
    priority: 4,
  },
  {
    type: "DATE",
    sets: ["phi"],
    regex: /\b(?:\d{4}-\d{1,2}-\d{1,2}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b/g,
    validate: plausibleDate,
    priority: 1,
  },
];
