// Checksum validators. Redacting the WRONG token corrupts the prompt (and, in
// reversible mode, the answer), so every numeric entity that has a check digit is
// verified before its span is accepted. These cut the bulk of false positives.

const digits = (s: string) => s.replace(/\D/g, "");

/** Luhn (mod-10) — credit/debit card numbers. */
export function luhn(input: string): boolean {
  const d = digits(input);
  if (d.length < 12 || d.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

/** ISO 7064 mod-97 — IBAN. */
export function ibanMod97(input: string): boolean {
  const s = input.replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(s)) return false;
  // Move the first four chars to the end, then map letters A→10 … Z→35.
  const rearranged = s.slice(4) + s.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch >= "A" && ch <= "Z" ? (ch.charCodeAt(0) - 55).toString() : ch;
    for (const c of code) remainder = (remainder * 10 + (c.charCodeAt(0) - 48)) % 97;
  }
  return remainder === 1;
}

/** ABA routing-number checksum (US bank routing, 9 digits). */
export function abaRouting(input: string): boolean {
  const d = digits(input);
  if (d.length !== 9) return false;
  const n = d.split("").map((c) => c.charCodeAt(0) - 48);
  const sum =
    3 * (n[0] + n[3] + n[6]) + 7 * (n[1] + n[4] + n[7]) + 1 * (n[2] + n[5] + n[8]);
  return sum % 10 === 0 && sum !== 0;
}

/** US SSN structural validity (area/group/serial rules — not a checksum, but kills obvious FPs). */
export function ssnValid(input: string): boolean {
  const d = digits(input);
  if (d.length !== 9) return false;
  const area = +d.slice(0, 3);
  const group = +d.slice(3, 5);
  const serial = +d.slice(5, 9);
  if (area === 0 || area === 666 || area >= 900) return false;
  if (group === 0) return false;
  if (serial === 0) return false;
  return true;
}
