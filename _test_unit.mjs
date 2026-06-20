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

// ---------------- Class 1: model-visible structured fields are redacted ----------------
const noRaw = (body, raw) => !JSON.stringify(body).includes(raw);
{
  const v = new Vault("reversible");
  const body = { messages: [{ role: "assistant", tool_calls: [{ id: "c1", type: "function", function: { name: "send", arguments: '{"to":"jane@acme.com","card":"4012888888881881"}' } }] }] };
  const { deidBody } = applyRedaction(body, "openai", v, ALL, detector);
  ok("Class1: openai tool_calls.arguments redacted", noRaw(deidBody, "jane@acme.com") && noRaw(deidBody, "4012888888881881"));
}
{
  const v = new Vault("reversible");
  const body = { messages: [{ role: "user", name: "bob@corp.io", content: "hi" }] };
  const { deidBody } = applyRedaction(body, "openai", v, ALL, detector);
  ok("Class1: openai message.name redacted", noRaw(deidBody, "bob@corp.io"));
}
{
  const v = new Vault("reversible");
  const body = { messages: [{ role: "user", content: "x" }], tools: [{ type: "function", function: { name: "f", description: "e.g. john@acme.com", parameters: { type: "object", properties: { note: { type: "string", description: "card 4012888888881881" } } } } }] };
  const { deidBody } = applyRedaction(body, "openai", v, ALL, detector);
  ok("Class1: openai tool description+params redacted", noRaw(deidBody, "john@acme.com") && noRaw(deidBody, "4012888888881881"));
}
{
  const v = new Vault("reversible");
  const body = { messages: [{ role: "assistant", content: [{ type: "tool_use", id: "t1", name: "lookup", input: { phone: "555-123-4567", email: "deep@x.com" } }] }] };
  const { deidBody } = applyRedaction(body, "anthropic", v, ALL, detector);
  ok("Class1: anthropic tool_use.input redacted", noRaw(deidBody, "555-123-4567") && noRaw(deidBody, "deep@x.com"));
}
{
  // Class1b: a card / routing number sent as a JSON NUMBER (not a string) must be
  // redacted, while benign numeric ids/quantities must NOT be over-redacted.
  const v = new Vault("reversible");
  const body = { messages: [{ role: "assistant", content: [{ type: "tool_use", id: "t1", name: "pay", input: { amount: 1299, card: 4012888888881881, order_id: 7350112233 } }] }] };
  const { deidBody } = applyRedaction(body, "anthropic", v, ALL, detector);
  ok("Class1b: numeric card in tool_use.input redacted", noRaw(deidBody, "4012888888881881"), JSON.stringify(deidBody));
  ok("Class1b: benign numeric id/amount NOT over-redacted",
    JSON.stringify(deidBody).includes("7350112233") && JSON.stringify(deidBody).includes("1299"), JSON.stringify(deidBody));
}
{
  // Class1c: a numeric card inside tool_calls.arguments (a JSON STRING) is redacted
  // AND the arguments stay valid JSON (a quoted placeholder, not a bare token).
  const v = new Vault("reversible");
  const body = { messages: [{ role: "assistant", tool_calls: [{ id: "c1", type: "function", function: { name: "pay", arguments: '{"card":4012888888881881,"qty":3}' } }] }] };
  const { deidBody } = applyRedaction(body, "openai", v, ALL, detector);
  const args = deidBody.messages[0].tool_calls[0].function.arguments;
  ok("Class1c: numeric card in tool_calls.arguments redacted", noRaw(deidBody, "4012888888881881"), args);
  let valid = false; try { const o = JSON.parse(args); valid = typeof o.card === "string" && o.qty === 3; } catch {}
  ok("Class1c: redacted arguments remain valid JSON", valid, args);
}
{
  // Class1d: a bare-STRING element in a content array must be redacted (was skipped).
  const v = new Vault("reversible");
  const body = { messages: [{ role: "user", content: ["email john@acme.com please"] }] };
  const { deidBody } = applyRedaction(body, "openai", v, ALL, detector);
  ok("Class1d: bare-string content-array element redacted", noRaw(deidBody, "john@acme.com"), JSON.stringify(deidBody));
}
{
  // Finding 3: a stream that ends mid-placeholder ("<EMAIL_1", no closing '>') must
  // restore by unique prefix, not emit the partial placeholder to the client.
  const v = new Vault("reversible");
  v.placeholderFor("john@acme.com", "EMAIL"); // → <EMAIL_1>
  const sr = new StreamReidentifier(v);
  let out = sr.push("see <EMAIL_1"); // ends mid-token; the forming tail is held
  out += sr.end();                   // stream ends — must resolve, not leak the partial
  ok("stream: truncated trailing placeholder restored (not leaked)", out === "see john@acme.com", out);
}

// ---------------- Class 2: unicode / zero-width / full-width evasion ----------------
ok("Class2: zero-width email detected", types(runAll("mail john​@acme.com now", ["pii"])).includes("EMAIL"));
ok("Class2: full-width card detected", types(runAll("card ４０１２８８８８８８８８１８８１", ["pci"])).includes("CREDIT_CARD"));
{
  const v = new Vault("reversible");
  const body = { messages: [{ role: "user", content: "reach john​@acme.com" }] };
  const { deidBody } = applyRedaction(body, "openai", v, ALL, detector);
  const sent = deidBody.messages[0].content;
  ok("Class2: zero-width email redacted in body", !sent.includes("acme.com") && sent.includes("<EMAIL_1>"), sent);
  ok("Class2: re-id restores original zero-width value", v.lookup("<EMAIL_1>") === "john​@acme.com");
}

// ---------------- Class 3: format / secret-key coverage ----------------
ok("Class3: intl phone (+44)", types(runAll("ring +44 20 7946 0958 please", ["pii"])).includes("PHONE"));
ok("Class3: dot-separated card", types(runAll("card 4012.8888.8888.1881", ["pci"])).includes("CREDIT_CARD"));
ok("Class3: compressed IPv6", types(runAll("addr 2001:db8::1 up", ["pii"])).includes("IPV6"));
ok("Class3: Stripe key", types(runAll("k sk_live_abcdefghijklmnopqrstuvwx", ["secrets"])).includes("STRIPE_KEY"));
ok("Class3: npm token", types(runAll("t npm_abcdefghijklmnopqrstuvwxyz0123456789", ["secrets"])).includes("NPM_TOKEN"));
ok("Class3: Slack webhook", types(runAll("h https://hooks.slack.com/services/T00/B11/abcdefghijklmnopqrstuvwx", ["secrets"])).includes("SLACK_WEBHOOK"));
ok("Class3: SendGrid key", types(runAll("sg SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", ["secrets"])).includes("SENDGRID_KEY"));
ok("Class3: GitHub fine-grained PAT", types(runAll("p github_pat_" + "A".repeat(82), ["secrets"])).includes("GITHUB_FINEGRAINED_PAT"));

// ---------------- FP guards: the new coverage must not over-redact ----------------
ok("FP: plain ASCII email unaffected", types(runAll("a@b.com", ["pii"])).join() === "EMAIL");
ok("FP: version string is not a card", !types(runAll("v1.2.3.4.5.6.7", ["pci"])).includes("CREDIT_CARD"));
ok("FP: a normal sentence has no spans", runAll("the quick brown fox jumps", ALL).length === 0);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
