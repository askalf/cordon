// Unit checks for known subjects (src/subject.ts). Run with: node --import tsx _test_subject.mjs
// Every person, address and number here is invented.
import { parseSubjectHeader, compileSubjects, withSubjects, subjectSpans, egressViolations, countMedia, refDigest, SubjectError, strictestMedia } from "./src/subject.ts";
import { detector } from "./src/detect/index.ts";
import { applyRedaction } from "./src/redact/apply.ts";
import { Vault } from "./src/redact/vault.ts";

let pass = 0, fail = 0;
const ok = (n, c, e = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"}  ${n}${e ? "   (" + e + ")" : ""}`); };
const enc = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const throwsSubject = (raw) => { try { parseSubjectHeader(raw); return false; } catch (e) { return e instanceof SubjectError; } };

const PERSON = {
  names: ["Marisol Quintero-Vance", "Mari Vance"],
  emails: ["mqvance77@example.com"],
  phones: ["(404) 555-0187"],
  addresses: ["1428 Elm Street, Apt 4, Decatur, GA 30030"],
  dates: ["1986-07-14"],
  ids: ["123-45-6789"],
  handles: ["@mari.q.vance"],
};
const spec = parseSubjectHeader(enc({ ref: "case-1", subjects: [PERSON, { names: ["Dmitri Okonkwo"] }] }));
const comp = compileSubjects(spec, "unit-key");
const det = withSubjects(detector, comp);
const hit = (text) => subjectSpans(text, comp).map((s) => text.slice(s.start, s.end));
const redact = (text) => {
  const body = { model: "m", messages: [{ role: "user", content: text }] };
  const { deidBody } = applyRedaction(body, "anthropic", new Vault("reversible"), ["pii", "pci", "secrets"], det, true, "messages");
  return deidBody.messages[0].content;
};
const clean = (text, raw) => !redact(text).includes(raw);

// ---- the header ----
ok("header: a valid list parses; media is left to the policy when unset", spec.subjects.length === 2 && spec.media === undefined && spec.ref === "case-1");
ok("header: absent is undefined", parseSubjectHeader(undefined) === undefined && parseSubjectHeader("") === undefined);
ok("header: not base64url is refused", throwsSubject("not base64!"));
ok("header: not JSON is refused", throwsSubject(Buffer.from("{nope").toString("base64url")));
ok("header: no subjects is refused", throwsSubject(enc({ subjects: [] })));
ok("header: an unknown list is refused", throwsSubject(enc({ subjects: [{ nicknames: ["x"] }] })));
ok("header: a non-string value is refused", throwsSubject(enc({ subjects: [{ names: [42] }] })));
ok("header: more than 8 subjects is refused", throwsSubject(enc({ subjects: Array(9).fill({ names: ["A Person"] }) })));
ok("header: over the size cap is refused", throwsSubject("A".repeat(13 * 1024)));
ok("header: a bad media value is refused", throwsSubject(enc({ subjects: [{ names: ["A B"] }], media: "maybe" })));
ok("media: the stricter of policy and header wins", strictestMedia("allow", "mask") === "mask" && strictestMedia("mask", "allow") === "mask" && strictestMedia(undefined, "allow") === "block" && strictestMedia("mask", undefined) === "mask");

// ---- names ----
ok("name: as given", clean("Marisol Quintero-Vance called", "Marisol"));
ok("name: last, first", clean("Quintero-Vance, Marisol", "Quintero"));
ok("name: initial and surname", clean("M. Quintero-Vance and M Quintero-Vance", "Quintero"));
ok("name: an alias", clean("goes by Mari Vance", "Mari Vance"));
ok("name: a handle made of the name", clean("profile marisolquintero-vance", "marisol"));
ok("name: the surname alone, capitalised", clean("the Quintero-Vance household", "Quintero-Vance"));
ok("name: case-insensitive full form", clean("MARISOL QUINTERO-VANCE", "MARISOL"));
ok("name: a second subject gets its own prefix", /SUBJECT2_NAME/.test(redact("met Dmitri Okonkwo")));
ok("name: the first subject's tokens say SUBJECT1", /SUBJECT1_NAME/.test(redact("Marisol Quintero-Vance")));
{
  const c = compileSubjects(parseSubjectHeader(enc({ subjects: [{ names: ["Will Grace"] }] })), "k");
  const d = withSubjects(detector, c);
  const body = { model: "m", messages: [{ role: "user", content: "Will you check? Grace period ends. Will Grace signed." }] };
  const out = applyRedaction(body, "anthropic", new Vault("reversible"), ["pii"], d, true, "messages").deidBody.messages[0].content;
  ok("name: common words alone are left as words", out.startsWith("Will you check? Grace period ends.") && !out.includes("Will Grace"), out);
}
ok("name: a lower-case single token is not a name", !hit("he will mark it").length);

// ---- contact details ----
ok("email: the whole address wins over its local part", /^<SUBJECT1_EMAIL_[0-9A-F]+_\d+>$/.test(redact("MQVance77@Example.com")));
ok("email: the local part reused as a username", clean("user mqvance77 on forums", "mqvance77"));
for (const p of ["404-555-0187", "(404) 555-0187", "404.555.0187", "+1 404 555 0187", "14045550187", "4045550187"])
  ok(`phone: ${p}`, clean(`call ${p} now`, "0187"));
ok("phone: not inside a longer number", !hit("ref 94045550187 and 40455501879").length);
ok("address: Street written as St", clean("lives at 1428 Elm St, Decatur", "1428 Elm"));
ok("address: as given, with the unit", clean("1428 Elm Street, Apt 4", "1428 Elm"));
ok("address: the street name alone is not the address", !hit("Elm Street is lovely").length);
for (const d of ["1986-07-14", "07/14/1986", "7/14/86", "July 14, 1986", "Jul 14 1986", "14 July 1986", "19860714"])
  ok(`date of birth: ${d}`, hit(`born ${d}`).length > 0, d);
ok("date of birth: another date is not it", !hit("born 1986-07-15 or 7/14/1987").length);
for (const id of ["123-45-6789", "123 45 6789", "123456789"]) ok(`id: ${id}`, clean(`ssn ${id}`, "6789"));
ok("handle: with and without @", clean("IG @mari.q.vance and mari.q.vance", "mari.q"));

// ---- the catalog still runs beside the subjects ----
{
  const out = redact("Marisol at mqvance77@example.com, and other@else.com, card 4012888888881881");
  ok("catalog: other entities are still redacted", /<EMAIL_/.test(out) && /<CREDIT_CARD_/.test(out) && /<SUBJECT1_EMAIL_/.test(out), out);
}

// ---- the egress check ----
{
  const body = { model: "m", messages: [{ role: "user", content: "Marisol Quintero-Vance, 1428 Elm St, 404-555-0187" }] };
  const { deidBody } = applyRedaction(body, "anthropic", new Vault("reversible"), ["pii"], det, true, "messages");
  ok("egress: a redacted body passes", egressViolations(deidBody, comp).length === 0);
  const leak = (s) => egressViolations({ model: "m", messages: [{ role: "user", content: s }] }, comp);
  ok("egress: a spaced-out name is caught", leak("m a r i s o l q u i n t e r o v a n c e").includes("SUBJECT1_NAME"));
  ok("egress: a phone with odd separators is caught", leak("4 0 4 / 5 5 5 / 0 1 8 7").includes("SUBJECT1_PHONE"));
  ok("egress: full-width digits are caught", leak("４０４５５５０１８７").includes("SUBJECT1_PHONE"));
  ok("egress: zero-width characters do not hide a name", leak("Mari​sol Quin‌tero-Vance").includes("SUBJECT1_NAME"));
  ok("egress: an object key is read too", egressViolations({ messages: [{ role: "user", content: [{ type: "text", text: "x", "Marisol Quintero-Vance": 1 }] }] }, comp).includes("SUBJECT1_NAME"));
  ok("egress: placeholder text is not a hit", leak("<SUBJECT1_NAME_ABC123_1> at <SUBJECT1_ADDRESS_ABC123_1>").length === 0);
  ok("egress: unrelated digits are not a hit", leak("order 4045 shipped 5550 units, 187 left").length === 0);
  const img = { model: "m", messages: [{ role: "user", content: [{ type: "image", source: { type: "base64", media_type: "image/png", data: "TWFyaXNvbCBRdWludGVyby1WYW5jZQ4045550187" } }] }] };
  ok("egress: base64 image data is skipped, not read", egressViolations(img, comp).length === 0);
  ok("media: an image part is counted", countMedia(img) === 1);
  const doc = { model: "m", messages: [{ role: "user", content: [{ type: "document", source: { type: "text", media_type: "text/plain", data: "Marisol Quintero-Vance" } }] }] };
  ok("media: a text document is not media", countMedia(doc) === 0);
  ok("egress: a text document is read", egressViolations(doc, comp).includes("SUBJECT1_NAME"));
  const oai = { model: "m", messages: [{ role: "user", content: [{ type: "image_url", image_url: { url: "data:image/png;base64,AAAA" } }] }] };
  ok("media: an OpenAI image part is counted", countMedia(oai) === 1 && egressViolations(oai, comp).length === 0);
  const resp = { model: "m", input: [{ role: "user", content: [{ type: "input_image", image_url: "https://img.example/marisol-quintero-vance.png" }] }] };
  ok("egress: an image URL is text and is read", egressViolations(resp, comp).includes("SUBJECT1_NAME"));
}

// ---- spelling variants ----
ok("name: a hyphenated surname written with a space", clean("Marisol Quintero Vance", "Quintero Vance"));
ok("name: a hyphenated surname run together", clean("Marisol QuinteroVance", "QuinteroVance"));
{
  const c = compileSubjects(parseSubjectHeader(enc({ subjects: [{ names: ["José García-O'Brien"] }] })), "k");
  const d = withSubjects(detector, c);
  const red = (t) => applyRedaction({ model: "m", messages: [{ role: "user", content: t }] }, "anthropic", new Vault("reversible"), ["pii"], d, true, "messages").deidBody.messages[0].content;
  ok("name: accents as given", !/Jos|Garc/.test(red("José García-O'Brien called")));
  ok("name: the same name without accents", !/Jos|Garc/.test(red("Jose Garcia-O'Brien called")), red("Jose Garcia-O'Brien called"));
  ok("name: a curly apostrophe", !/Brien/.test(red("Mr. García-O’Brien")), red("Mr. García-O’Brien"));
  ok("name: the apostrophe left out", !/Brien/.test(red("Jose Garcia-OBrien")), red("Jose Garcia-OBrien"));
  ok("egress: an unaccented leak is caught", egressViolations({ messages: [{ role: "user", content: "jose garcia obrien" }] }, c).includes("SUBJECT1_NAME"));
}

// ---- the ref digest ----
ok("ref: the digest is stable and does not contain the ref", refDigest("case-1", "k") === refDigest("case-1", "k") && !refDigest("case-1", "k").includes("case"));
ok("ref: a different key gives a different digest", refDigest("case-1", "k") !== refDigest("case-1", "k2"));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
