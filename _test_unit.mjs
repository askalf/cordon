// Unit checks needing module access (run with: node --import tsx _test_unit.mjs).
import { runAll, detector } from "./src/detect/index.ts";
import { luhn, ibanMod97, abaRouting, ssnValid } from "./src/detect/validators.ts";
import { Vault } from "./src/redact/vault.ts";
import { applyRedaction, tally } from "./src/redact/apply.ts";
import { reidentifyBody, StreamReidentifier } from "./src/redact/reidentify.ts";

let pass = 0, fail = 0;
const ok = (n, c, e = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"}  ${n}${e ? "   (" + e + ")" : ""}`); };
const types = (spans) => spans.map((s) => s.type).sort();

const ALL = ["pii", "phi", "pci", "secrets"];

// ---------------- detection ----------------
ok("detect EMAIL", types(runAll("ping john@acme.com now", ["pii"])).includes("EMAIL"));
ok("detect PHONE", types(runAll("call 555-123-4567", ["pii"])).includes("PHONE"));
ok("detect SSN", types(runAll("ssn 123-45-6789", ["pii"])).includes("SSN"));
ok("detect IPV4", types(runAll("host 192.168.1.1", ["pii"])).includes("IPV4"));
ok("detect MAC", types(runAll("nic 00:1A:2B:3C:4D:5E", ["pii"])).includes("MAC"));
ok("detect CREDIT_CARD (Luhn-valid)", types(runAll("card 4012888888881881", ["pci"])).includes("CREDIT_CARD"));
ok("detect IBAN (mod97-valid)", types(runAll("iban DE89370400440532013000", ["pci"])).includes("IBAN"));
ok("detect US_ROUTING (ABA-valid)", types(runAll("aba 021000021", ["pci"])).includes("US_ROUTING"));
ok("detect ANTHROPIC_KEY", types(runAll("key sk-ant-abcdefghijklmnopqrstuvwxyz0123", ["secrets"])).includes("ANTHROPIC_KEY"));
ok("detect AWS_ACCESS_KEY", types(runAll("AKIAIOSFODNN7EXAMPLE", ["secrets"])).includes("AWS_ACCESS_KEY"));

// false positives rejected by validators
ok("invalid card rejected", !types(runAll("card 4012888888881882", ["pci"])).includes("CREDIT_CARD"));
ok("invalid IBAN rejected", !types(runAll("iban DE89370400440532013001", ["pci"])).includes("IBAN"));

// set gating: a phi-only type doesn't fire when only pii is active
ok("set gating: DATE off without phi", runAll("dob 1990-05-21", ["pii"]).length === 0);
ok("set gating: DATE on with phi", types(runAll("dob 1990-05-21", ["phi"])).includes("DATE"));

// overlap resolution: a card is one CREDIT_CARD span, not also a PHONE
{
  const spans = runAll("pay 4012 8888 8888 1881 today", ["pii", "pci"]);
  ok("overlap: card wins over phone", spans.length === 1 && spans[0].type === "CREDIT_CARD", types(spans).join(","));
}

// ---------------- validators ----------------
ok("luhn accepts valid", luhn("4012888888881881") === true);
ok("luhn rejects invalid", luhn("4012888888881882") === false);
ok("ibanMod97 valid", ibanMod97("DE89370400440532013000") === true);
ok("ibanMod97 invalid", ibanMod97("DE00370400440532013000") === false);
ok("abaRouting valid", abaRouting("021000021") === true);
ok("abaRouting invalid", abaRouting("021000020") === false);
ok("ssnValid rejects area 000", ssnValid("000-12-3456") === false);
ok("ssnValid accepts normal", ssnValid("123-45-6789") === true);

// ---------------- vault ----------------
{
  const v = new Vault("reversible");
  const t1 = v.placeholderFor("a@b.com", "EMAIL");
  const t1b = v.placeholderFor("a@b.com", "EMAIL");
  const t2 = v.placeholderFor("c@d.com", "EMAIL");
  ok("vault stable within request", t1 === "<EMAIL_1>" && t1b === t1);
  ok("vault increments per value", t2 === "<EMAIL_2>");
  ok("vault reverse lookup", v.lookup(t1) === "a@b.com" && v.hasReverse);
}
{
  const v = new Vault("strip");
  ok("strip token is irreversible label", v.placeholderFor("a@b.com", "EMAIL") === "[EMAIL]");
  ok("strip keeps no reverse map", v.lookup("[EMAIL]") === undefined && !v.hasReverse);
}
{
  const a = new Vault("reversible", { consistentPseudonyms: true, secret: "k" });
  const b = new Vault("reversible", { consistentPseudonyms: true, secret: "k" });
  const ta = a.placeholderFor("x@y.com", "EMAIL");
  const tb = b.placeholderFor("x@y.com", "EMAIL");
  ok("consistent pseudonym stable across requests", ta === tb && /^<EMAIL_[0-9A-F]{8}>$/.test(ta), ta);
}

// ---------------- apply (request de-identification) ----------------
{
  const v = new Vault("reversible");
  const body = { model: "m", messages: [{ role: "user", content: "email john@acme.com about card 4012888888881881" }] };
  const { deidBody, spans } = applyRedaction(body, "openai", v, ALL, detector);
  ok("apply: original body untouched (clone)", body.messages[0].content.includes("john@acme.com"));
  ok("apply: de-id has placeholders, no raw", deidBody.messages[0].content === "email <EMAIL_1> about card <CREDIT_CARD_1>", deidBody.messages[0].content);
  ok("apply: span count", spans.length === 2 && tally(spans).EMAIL === 1 && tally(spans).CREDIT_CARD === 1);

  // round-trip restore on a response shaped like the echo
  const resp = { choices: [{ message: { role: "assistant", content: "re <EMAIL_1> and <CREDIT_CARD_1>" } }] };
  const restored = reidentifyBody(resp, "openai", v);
  ok("reidentify round-trips", restored.choices[0].message.content === "re john@acme.com and 4012888888881881", restored.choices[0].message.content);
}
{
  // content-part array: text redacted, image left untouched
  const v = new Vault("reversible");
  const body = { model: "m", messages: [{ role: "user", content: [{ type: "text", text: "call 555-123-4567" }, { type: "image_url", image_url: { url: "http://x/y.png" } }] }] };
  const { deidBody } = applyRedaction(body, "openai", v, ALL, detector);
  ok("apply: array text redacted", deidBody.messages[0].content[0].text === "call <PHONE_1>");
  ok("apply: image part untouched", deidBody.messages[0].content[1].image_url.url === "http://x/y.png");
}
{
  // anthropic system + tool_result
  const v = new Vault("strip");
  const body = {
    model: "m",
    system: "agent for jane@corp.io",
    messages: [{ role: "user", content: [{ type: "tool_result", content: [{ type: "text", text: "ip 10.0.0.9" }] }] }],
  };
  const { deidBody, spans } = applyRedaction(body, "anthropic", v, ALL, detector);
  ok("apply: anthropic system redacted", deidBody.system === "agent for [EMAIL]");
  ok("apply: anthropic tool_result redacted", deidBody.messages[0].content[0].content[0].text === "ip [IPV4]", JSON.stringify(deidBody.messages[0].content));
  ok("apply: strip span count", spans.length === 2);
}

// ---------------- streaming re-identify (boundary split) ----------------
{
  const v = new Vault("reversible");
  v.placeholderFor("john@acme.com", "EMAIL"); // → <EMAIL_1>
  const sr = new StreamReidentifier(v);
  let out = "";
  for (const d of ["Hi <EM", "AIL_1", ">!"]) out += sr.push(d); // placeholder split across 3 frames
  out += sr.end();
  ok("stream: split placeholder restored", out === "Hi john@acme.com!", out);
}
{
  const v = new Vault("reversible");
  const sr = new StreamReidentifier(v);
  let out = "";
  for (const d of ["5 ", "< 10 ", "and more"]) out += sr.push(d); // literal '<' must not stall
  out += sr.end();
  ok("stream: literal '<' does not stall", out === "5 < 10 and more", out);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
