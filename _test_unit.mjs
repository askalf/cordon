// Unit checks needing module access (run with: node --import tsx _test_unit.mjs).
import { rmSync, writeFileSync, readFileSync } from "node:fs";
import { runAll, detector } from "./src/detect/index.ts";
import { luhn, ibanMod97, abaRouting, ssnValid } from "./src/detect/validators.ts";
import { Vault } from "./src/redact/vault.ts";
import { applyRedaction, tally, exactDecimal } from "./src/redact/apply.ts";
import { restoreCitation, reidentifyBody, StreamReidentifier, ArgStream, argContext, restoreArgs, restoreArgsWhole, hasDuplicateKeys, restoreArgObject, DeferredArgs, MAX_ARG_DEPTH, TopKeyTracker, isMintedPlaceholder } from "./src/redact/reidentify.ts";
import { parseRestoreTools } from "./src/redact/restorePolicy.ts";
import { pseudonymSecretGuard, adequatePseudonymSecret, MIN_PSEUDONYM_SECRET_LEN, parseTimeoutMs, DEFAULT_UPSTREAM_TIMEOUT_MS, MAX_TIMEOUT_MS } from "./src/config.ts";
import { setPolicy, getPolicy, allPolicies, save as savePolicy, load as loadPolicy } from "./src/policy.ts";

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
  // Counter tokens carry a per-request nonce (<EMAIL_<hex>_N>), stable within the request,
  // so a caller's literal <EMAIL_1> can never collide with a minted token (issue #19).
  ok("vault stable within request", /^<EMAIL_[0-9A-F]+_1>$/.test(t1) && t1b === t1, t1);
  ok("vault increments per value", /^<EMAIL_[0-9A-F]+_2>$/.test(t2) && t2 !== t1, t2);
  ok("vault nonce shared within a request", t1.split("_")[1] === t2.split("_")[1], `${t1} / ${t2}`);
  ok("vault mints no bare <EMAIL_N> (collision-resistant)", t1 !== "<EMAIL_1>" && t2 !== "<EMAIL_2>");
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
  const deid = deidBody.messages[0].content;
  ok("apply: de-id has placeholders, no raw",
    /^email <EMAIL_[0-9A-F]+_1> about card <CREDIT_CARD_[0-9A-F]+_1>$/.test(deid) && !deid.includes("john@acme.com"), deid);
  ok("apply: span count", spans.length === 2 && tally(spans).EMAIL === 1 && tally(spans).CREDIT_CARD === 1);

  // round-trip restore on a response shaped like the echo (use the actual minted tokens)
  const et = v.placeholderFor("john@acme.com", "EMAIL"); // idempotent → returns the minted token
  const ct = v.placeholderFor("4012888888881881", "CREDIT_CARD");
  const resp = { choices: [{ message: { role: "assistant", content: `re ${et} and ${ct}` } }] };
  const restored = reidentifyBody(resp, "openai", v);
  ok("reidentify round-trips", restored.choices[0].message.content === "re john@acme.com and 4012888888881881", restored.choices[0].message.content);
}
{
  // content-part array: text redacted, image left untouched
  const v = new Vault("reversible");
  const body = { model: "m", messages: [{ role: "user", content: [{ type: "text", text: "call 555-123-4567" }, { type: "image_url", image_url: { url: "http://x/y.png" } }] }] };
  const { deidBody } = applyRedaction(body, "openai", v, ALL, detector);
  ok("apply: array text redacted", /^call <PHONE_[0-9A-F]+_1>$/.test(deidBody.messages[0].content[0].text), deidBody.messages[0].content[0].text);
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
{
  // Anthropic blocks that carry text beyond text parts, and the media that passes as sent.
  const v = new Vault("strip");
  const body = {
    model: "m",
    messages: [
      { role: "user", content: [
        { type: "document", title: "jane@corp.io notes", context: "from 10.0.0.9", source: { type: "text", media_type: "text/plain", data: "mail jane@corp.io" } },
        { type: "document", source: { type: "content", content: [{ type: "text", text: "ip 10.0.0.9" }] } },
        { type: "document", source: { type: "url", url: "https://x.example/jane@corp.io.pdf" } },
        { type: "search_result", title: "jane@corp.io", source: "https://x.example/r?u=jane@corp.io", content: [{ type: "text", text: "ip 10.0.0.9" }] },
        { type: "tool_result", tool_use_id: "toolu_1", content: [{ type: "image", source: { type: "url", url: "https://x.example/jane@corp.io.png" } }, { type: "text", text: "ip 10.0.0.9" }] },
        { type: "mcp_tool_result", tool_use_id: "mcptoolu_1", content: [{ type: "text", text: "ip 10.0.0.9" }] },
      ] },
      { role: "assistant", content: [
        { type: "server_tool_use", id: "srvtoolu_1", name: "web_search", input: { query: "jane@corp.io" } },
        { type: "mcp_tool_use", id: "mcptoolu_1", name: "lookup", server_name: "crm", input: { who: "jane@corp.io" } },
      ] },
    ],
  };
  const { deidBody: d } = applyRedaction(body, "anthropic", v, ALL, detector);
  const [doc, docC, docU, sr, tr, mtr] = d.messages[0].content;
  ok("apply: document title, context and plain-text source redacted", doc.title === "[EMAIL] notes" && doc.context === "from [IPV4]" && doc.source.data === "mail [EMAIL]", JSON.stringify(doc));
  ok("apply: document content source redacted", docC.source.content[0].text === "ip [IPV4]", JSON.stringify(docC));
  ok("apply: a URL document source passes as sent", docU.source.url === "https://x.example/jane@corp.io.pdf");
  ok("apply: search_result title and text redacted, its source as sent", sr.title === "[EMAIL]" && sr.content[0].text === "ip [IPV4]" && sr.source === "https://x.example/r?u=jane@corp.io", JSON.stringify(sr));
  ok("apply: a tool_result image source passes as sent, its text is redacted", tr.content[0].source.url === "https://x.example/jane@corp.io.png" && tr.content[1].text === "ip [IPV4]" && tr.tool_use_id === "toolu_1", JSON.stringify(tr));
  ok("apply: mcp_tool_result text redacted", mtr.content[0].text === "ip [IPV4]", JSON.stringify(mtr));
  const [stu, mtu] = d.messages[1].content;
  ok("apply: server_tool_use and mcp_tool_use input redacted, names and ids as sent", stu.input.query === "[EMAIL]" && mtu.input.who === "[EMAIL]" && stu.name === "web_search" && mtu.id === "mcptoolu_1" && mtu.server_name === "crm", JSON.stringify(d.messages[1]));
}
{
  // A tool call replayed as history is read as deep as the response side restores (64
  // levels): a leaf past the old 16-level walk is redacted, and past 64 the request is
  // refused rather than forwarded part read.
  const nest = (n, leaf) => { let o = leaf; for (let i = 0; i < n; i++) o = { a: o }; return o; };
  const v = new Vault("strip");
  const body20 = { model: "m", messages: [{ role: "assistant", content: [{ type: "tool_use", id: "toolu_1", name: "lookup", input: nest(20, { who: "jane@corp.io" }) }] }] };
  const d20 = applyRedaction(body20, "anthropic", v, ALL, detector).deidBody;
  ok("apply: a tool_use leaf 20 levels down is redacted", JSON.stringify(d20).includes("[EMAIL]") && !JSON.stringify(d20).includes("jane@corp.io"), JSON.stringify(d20).slice(-80));
  const chat20 = { model: "m", messages: [{ role: "assistant", content: null, tool_calls: [{ id: "c1", type: "function", function: { name: "lookup", arguments: JSON.stringify(nest(20, { who: "jane@corp.io" })) } }] }] };
  const c20 = applyRedaction(chat20, "openai", v, ALL, detector).deidBody;
  ok("apply: a tool_calls argument 20 levels down is redacted", c20.messages[0].tool_calls[0].function.arguments.includes("[EMAIL]") && !c20.messages[0].tool_calls[0].function.arguments.includes("jane@corp.io"));
  for (const [label, b, p] of [
    ["tool_use input", { model: "m", messages: [{ role: "assistant", content: [{ type: "tool_use", id: "toolu_1", name: "lookup", input: nest(70, { who: "jane@corp.io" }) }] }] }, "anthropic"],
    ["tool_calls arguments", { model: "m", messages: [{ role: "assistant", content: null, tool_calls: [{ id: "c1", type: "function", function: { name: "lookup", arguments: JSON.stringify(nest(70, { who: "jane@corp.io" })) } }] }] }, "openai"],
  ]) {
    let threw = "";
    try { applyRedaction(b, p, v, ALL, detector); } catch (e) { threw = String(e.message); }
    ok(`apply: ${label} nested 70 levels is refused, not walked part way`, /deeper than 64/.test(threw), threw);
  }
}
{
  // Property names in tool-call arguments are redacted like values, so a call whose names
  // came back real (CORDON_RESTORE_TOOLS=lookup.payload) is re-redacted when replayed.
  const rv = new Vault("reversible");
  const tok = rv.placeholderFor("jane@corp.io", "EMAIL");
  const lookupPayload = parseRestoreTools("lookup.payload");
  // Anthropic: the response restores the name, the replayed history redacts it again.
  const input = { payload: { [tok]: true, note: "x" } };
  restoreArgObject(input, argContext(rv, false, "lookup", { unresolved: 0 }, lookupPayload));
  ok("round trip (Messages): the response restores the property name", Object.keys(input.payload)[0] === "jane@corp.io", JSON.stringify(input));
  const next = new Vault("reversible");
  const hist = { model: "m", messages: [{ role: "assistant", content: [{ type: "tool_use", id: "toolu_1", name: "lookup", input }] }] };
  const dh = applyRedaction(hist, "anthropic", next, ALL, detector).deidBody;
  const keysOut = Object.keys(dh.messages[0].content[0].input.payload);
  ok("round trip (Messages): the replayed name is redacted, order kept", /^<EMAIL_[0-9A-F]{6}_1>$/.test(keysOut[0]) && keysOut[1] === "note" && !JSON.stringify(dh).includes("jane@corp.io"), JSON.stringify(dh.messages[0].content[0].input));
  // JSON-string arguments: the same, on chat tool_calls.
  const args = restoreArgsWhole(JSON.stringify({ payload: { [tok]: true } }), argContext(rv, true, "lookup", { unresolved: 0 }, lookupPayload));
  ok("round trip (JSON text): the response restores the property name", JSON.parse(args).payload["jane@corp.io"] === true, args);
  const chist = { model: "m", messages: [{ role: "assistant", content: null, tool_calls: [{ id: "c1", type: "function", function: { name: "lookup", arguments: args } }] }] };
  const dc = applyRedaction(chist, "openai", new Vault("reversible"), ALL, detector).deidBody;
  const ca = dc.messages[0].tool_calls[0].function.arguments;
  ok("round trip (JSON text): the replayed name is redacted", /"<EMAIL_[0-9A-F]{6}_1>":true/.test(ca) && !ca.includes("jane@corp.io"), ca);
  const rhist = { model: "m", input: [{ type: "function_call", call_id: "call_1", name: "lookup", arguments: args }] };
  const dr = applyRedaction(rhist, "openai", new Vault("reversible"), ALL, detector, true, "responses").deidBody;
  const ra = dr.input[0].arguments;
  ok("round trip (Responses): the replayed name is redacted", /"<EMAIL_[0-9A-F]{6}_1>":true/.test(ra) && !ra.includes("jane@corp.io") && dr.input[0].call_id === "call_1", ra);
  // Two names that redact to the same name refuse the request.
  for (const [label, b, p] of [
    ["Messages", { model: "m", messages: [{ role: "assistant", content: [{ type: "tool_use", id: "t", name: "lookup", input: { "a@corp.io": 1, "b@corp.io": 2 } }] }] }, "anthropic"],
    ["JSON text", { model: "m", messages: [{ role: "assistant", content: null, tool_calls: [{ id: "c", type: "function", function: { name: "lookup", arguments: '{"a@corp.io":1,"b@corp.io":2}' } }] }] }, "openai"],
  ]) {
    let threw = "";
    try { applyRedaction(b, p, new Vault("strip"), ALL, detector); } catch (e) { threw = String(e.message); }
    ok(`apply: argument names that collide after redaction refuse the request (${label})`, /redact to the same name/.test(threw), threw);
  }
  // Schema property names are field names, not arguments: left as written.
  const sch = applyRedaction({ model: "m", tools: [{ name: "t", description: "d", input_schema: { type: "object", properties: { email: { type: "string" } } } }], messages: [] }, "anthropic", new Vault("strip"), ALL, detector).deidBody;
  ok("apply: tool schema property names are left as written", Object.keys(sch.tools[0].input_schema.properties)[0] === "email");
}
{
  // JSON-string arguments are redacted on their own text: untouched numbers keep every
  // digit (beyond 2^53 too), with or without another field to redact, on legacy
  // function_call, tool_calls and Responses arguments alike.
  const big = '{"id":9007199254740993,"f":1.50,"e":1e400}';
  const withPii = '{"id":9007199254740993,"to":"jane@corp.io","card":4012888888881881}';
  const v = new Vault("strip");
  const legacy = (args) => applyRedaction({ model: "m", messages: [{ role: "assistant", content: null, function_call: { name: "f", arguments: args } }] }, "openai", v, ALL, detector).deidBody.messages[0].function_call.arguments;
  ok("apply: legacy arguments with nothing to redact are byte for byte", legacy(big) === big, legacy(big));
  ok("apply: legacy arguments keep a big integer next to a redacted field", legacy(withPii) === '{"id":9007199254740993,"to":"[EMAIL]","card":"[CREDIT_CARD]"}', legacy(withPii));
  const tc = applyRedaction({ model: "m", messages: [{ role: "assistant", content: null, tool_calls: [{ id: "c", type: "function", function: { name: "f", arguments: withPii } }] }] }, "openai", v, ALL, detector).deidBody.messages[0].tool_calls[0].function.arguments;
  ok("apply: tool_calls arguments keep a big integer next to a redacted field", tc === '{"id":9007199254740993,"to":"[EMAIL]","card":"[CREDIT_CARD]"}', tc);
  const ra = applyRedaction({ model: "m", input: [{ type: "function_call", call_id: "c", name: "f", arguments: withPii }] }, "openai", v, ALL, detector, true, "responses").deidBody.input[0].arguments;
  ok("apply: Responses arguments keep a big integer next to a redacted field", ra === '{"id":9007199254740993,"to":"[EMAIL]","card":"[CREDIT_CARD]"}', ra);
  // A card spelled with a decimal or an exponent is still the card: detected on the exact
  // decimal value of the literal, and the whole literal replaced.
  for (const [lex, want] of [["4.111111111111111e15", "4111111111111111"], ["4111111111111111.0", "4111111111111111"], ["41111111111111110E-1", "4111111111111111"], ["-12e2", "-1200"], ["1.5", "1.5"], ["0.0", "0"], ["1e999", "1e999"], ["9007199254740993", "9007199254740993"],
    ["4111111111111111" + "0".repeat(401) + "e-401", "4111111111111111"], ["0.0004111111111111111e19", "4111111111111111"], ["1e-99999999999999999999", "1e-99999999999999999999"], ["7e99999999999999999999", "7e99999999999999999999"], ["1" + "0".repeat(41), "1" + "0".repeat(41)], ["1" + "0".repeat(39), "1" + "0".repeat(39)]])
    ok(`exactDecimal: ${lex} -> ${want}`, exactDecimal(lex) === want, exactDecimal(lex));
  {
    // A huge exponent costs nothing: decided by counting, never by building the digits.
    const t0 = Date.now();
    const out = legacy('{"n":1e999999999,"m":5e-999999999}');
    ok("apply: a huge exponent is left as written, quickly", out === '{"n":1e999999999,"m":5e-999999999}' && Date.now() - t0 < 1000, out);
  }
  for (const lex of ["4111111111111111.0", "4.111111111111111e15", "4111111111111111" + "0".repeat(401) + "e-401"]) {
    const out = legacy(`{"card":${lex},"f":1.50}`);
    ok(`apply: a card written ${lex} is redacted whole, other numbers byte for byte`, out === '{"card":"[CREDIT_CARD]","f":1.50}', out);
  }
  const spaced = '{ "to" : "jane@corp.io" ,\n "n": 2 }';
  const so = legacy(spaced);
  ok("apply: the arguments' own spacing is kept", so === '{ "to" : "[EMAIL]" ,\n "n": 2 }', so);
}
{
  // Citations into a plain-text document cordon redacted: cited_text and document_title get
  // real values back, and char_location offsets are the caller's, not the redacted text's.
  const v = new Vault("reversible");
  const orig = "Contact jane@corp.io today. Then call nobody.";
  const body = { model: "m", messages: [{ role: "user", content: [
    { type: "document", source: { type: "url", url: "https://x.example/a.pdf" } },
    { type: "document", title: "notes for jane@corp.io", citations: { enabled: true }, source: { type: "text", media_type: "text/plain", data: orig } },
  ] }] };
  const sent = applyRedaction(body, "anthropic", v, ALL, detector).deidBody.messages[0].content[1];
  const red = sent.source.data;
  const tok = red.slice(8, red.indexOf(" today"));
  const cite = (from, to) => ({ type: "char_location", cited_text: red.slice(from, to), document_index: 1, document_title: sent.title, start_char_index: from, end_char_index: to });
  const after = cite(red.indexOf("Then"), red.indexOf("Then") + 4);
  const over = cite(0, red.indexOf(" today"));
  const inside = cite(red.indexOf(tok) + 3, red.indexOf(tok) + 6);
  const resp = { content: [{ type: "text", text: "see", citations: [after, over, inside] }] };
  const out = reidentifyBody(resp, "anthropic", v, "messages").content[0].citations;
  ok("citations: an offset after a placeholder is the caller's", out[0].start_char_index === orig.indexOf("Then") && out[0].end_char_index === orig.indexOf("Then") + 4 && out[0].cited_text === "Then", JSON.stringify(out[0]));
  ok("citations: a range over a placeholder covers the whole value, cited_text restored", out[1].start_char_index === 0 && out[1].end_char_index === orig.indexOf(" today") && out[1].cited_text === "Contact jane@corp.io", JSON.stringify(out[1]));
  ok("citations: a range inside a placeholder maps to the value it replaced", out[2].start_char_index === orig.indexOf("jane") && out[2].end_char_index === orig.indexOf(" today") && out[2].cited_text === "jane@corp.io", JSON.stringify(out[2]));
  // One endpoint inside a placeholder: the range widens to the whole value, and cited_text
  // quotes the caller's text over the widened range, never a piece of the token.
  const startIn = reidentifyBody({ content: [{ type: "text", text: "s", citations: [cite(red.indexOf(tok) + 3, red.indexOf("today") + 5)] }] }, "anthropic", v, "messages").content[0].citations[0];
  ok("citations: a range starting inside a placeholder quotes the caller's text", startIn.start_char_index === orig.indexOf("jane") && startIn.end_char_index === orig.indexOf("today") + 5 && startIn.cited_text === "jane@corp.io today", JSON.stringify(startIn));
  const endIn = reidentifyBody({ content: [{ type: "text", text: "e", citations: [cite(0, red.indexOf(tok) + 4)] }] }, "anthropic", v, "messages").content[0].citations[0];
  ok("citations: a range ending inside a placeholder quotes the caller's text", endIn.start_char_index === 0 && endIn.end_char_index === orig.indexOf(" today") && endIn.cited_text === "Contact jane@corp.io", JSON.stringify(endIn));
  ok("citations: document_title restored", out[0].document_title === "notes for jane@corp.io", out[0].document_title);
  // A document cordon did not change, or another document_index, is left as cited.
  const plain = reidentifyBody({ content: [{ type: "text", text: "x", citations: [{ type: "char_location", cited_text: "ab", document_index: 0, start_char_index: 3, end_char_index: 5 }] }] }, "anthropic", v, "messages").content[0].citations[0];
  ok("citations: an untouched document keeps its offsets", plain.start_char_index === 3 && plain.end_char_index === 5);
  // Replayed as history, the restored citation is redacted again (cited_text and title).
  const next = new Vault("reversible");
  const hist = { model: "m", messages: [{ role: "user", content: "q" }, { role: "assistant", content: [{ type: "text", text: "see", citations: out }] }] };
  const rh = applyRedaction(hist, "anthropic", next, ALL, detector).deidBody.messages[1].content[0].citations;
  ok("citations: replayed as history, cited_text and document_title are redacted again", !JSON.stringify(rh).includes("jane@corp.io") && /<EMAIL_/.test(rh[1].cited_text) && /<EMAIL_/.test(rh[0].document_title), JSON.stringify(rh));
  // Offsets count Unicode characters: a character outside the BMP before the value.
  const ev = new Vault("reversible");
  const origU = "\u{1F600} jane@corp.io end";
  const sentU = applyRedaction({ model: "m", messages: [{ role: "user", content: [{ type: "document", source: { type: "text", media_type: "text/plain", data: origU } }] }] }, "anthropic", ev, ALL, detector).deidBody.messages[0].content[0].source.data;
  const ci = (t, sub) => Array.from(t.slice(0, t.indexOf(sub))).length;
  const cu = { type: "char_location", cited_text: "end", document_index: 0, start_char_index: ci(sentU, "end"), end_char_index: ci(sentU, "end") + 3 };
  restoreCitation(cu, ev);
  ok("citations: offsets in Unicode characters, past a character outside the BMP", cu.start_char_index === ci(origU, "end") && cu.end_char_index === ci(origU, "end") + 3, JSON.stringify(cu));
}
{
  // Chat: an assistant's refusal and legacy function_call arguments are model-visible.
  const v = new Vault("strip");
  const body = { model: "m", messages: [
    { role: "assistant", content: null, refusal: "not for jane@corp.io", function_call: { name: "send", arguments: '{"to":"jane@corp.io","n":1}' } },
    { role: "function", name: "send", content: "sent to jane@corp.io" },
  ] };
  const { deidBody: d } = applyRedaction(body, "openai", v, ALL, detector);
  const fc = JSON.parse(d.messages[0].function_call.arguments);
  ok("apply: chat refusal redacted", d.messages[0].refusal === "not for [EMAIL]", d.messages[0].refusal);
  ok("apply: legacy function_call arguments redacted and still JSON", fc.to === "[EMAIL]" && fc.n === 1 && d.messages[0].function_call.name === "send", d.messages[0].function_call.arguments);
  ok("apply: a function message's content redacted", d.messages[1].content === "sent to [EMAIL]");
  // A custom tool call replayed as history: its plain-text input is redacted.
  const cb = applyRedaction({ model: "m", messages: [{ role: "assistant", content: null, tool_calls: [{ id: "c", type: "custom", custom: { name: "shell", input: "mail jane@corp.io" } }] }] }, "openai", new Vault("strip"), ALL, detector).deidBody;
  ok("apply: a chat custom tool call's input redacted on replay", cb.messages[0].tool_calls[0].custom.input === "mail [EMAIL]" && cb.messages[0].tool_calls[0].custom.name === "shell", JSON.stringify(cb.messages[0]));
}
{
  // redactSystem=false → system prompt is application scaffolding, left untouched;
  // user message content (and OpenAI role:"system" messages) handled accordingly.
  const va = new Vault("strip");
  const aBody = { model: "m", system: "agent for jane@corp.io", messages: [{ role: "user", content: "mail bob@x.io" }] };
  const { deidBody: da } = applyRedaction(aBody, "anthropic", va, ALL, detector, false);
  ok("apply: redactSystem=false leaves anthropic system intact", da.system === "agent for jane@corp.io");
  ok("apply: redactSystem=false still redacts user message", da.messages[0].content === "mail [EMAIL]");

  const vo = new Vault("strip");
  const oBody = { model: "m", messages: [{ role: "system", content: "ops for jane@corp.io" }, { role: "user", content: "mail bob@x.io" }] };
  const { deidBody: doo } = applyRedaction(oBody, "openai", vo, ALL, detector, false);
  ok("apply: redactSystem=false leaves openai system message intact", doo.messages[0].content === "ops for jane@corp.io");
  ok("apply: redactSystem=false still redacts openai user message", doo.messages[1].content === "mail [EMAIL]");
}

// ---------------- streaming re-identify (boundary split) ----------------
{
  const v = new Vault("reversible");
  const tok = v.placeholderFor("john@acme.com", "EMAIL"); // e.g. <EMAIL_7F3A2B_1>
  const s = `Hi ${tok}!`;
  const c1 = 5, c2 = 3 + Math.floor(tok.length / 2); // both cuts fall INSIDE the placeholder
  const sr = new StreamReidentifier(v);
  let out = "";
  for (const d of [s.slice(0, c1), s.slice(c1, c2), s.slice(c2)]) out += sr.push(d); // split across 3 frames
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
  const tok = v.placeholderFor("john@acme.com", "EMAIL"); // → <EMAIL_<hex>_1>
  const sr = new StreamReidentifier(v);
  let out = sr.push("see " + tok.slice(0, -1)); // ends mid-token (drop the closing '>'); tail is held
  out += sr.end();                              // stream ends — must resolve, not leak the partial
  ok("stream: truncated trailing placeholder restored (not leaked)", out === "see john@acme.com", out);
}

// ---------------- Responses API: every request shape reaches the detector ----------------
{
  const RAW = "john.doe@acme.com";
  const rRedact = (body, v = new Vault("reversible"), redactSystem = true) =>
    applyRedaction({ model: "gpt-4o-mini", ...body }, "openai", v, ALL, detector, redactSystem, "responses");
  const cases = [
    ["function_call_output.output as input_text parts",
      { input: [{ type: "function_call_output", call_id: "call_1", output: [{ type: "input_text", text: `owner ${RAW}` }] }] }],
    ["custom_tool_call.input",
      { input: [{ type: "custom_tool_call", call_id: "call_2", name: "send_mail", input: `to: ${RAW}` }] }],
    ["custom_tool_call_output.output (string)",
      { input: [{ type: "custom_tool_call_output", call_id: "call_2", output: `sent to ${RAW}` }] }],
    ["custom_tool_call_output.output (input_text parts)",
      { input: [{ type: "custom_tool_call_output", call_id: "call_2", output: [{ type: "input_text", text: `sent to ${RAW}` }] }] }],
    ["local_shell_call_output.output",
      { input: [{ type: "local_shell_call_output", id: "lsh_1", call_id: "call_3", output: `users.csv: ${RAW}` }] }],
    ["custom tool description",
      { input: "hi", tools: [{ type: "custom", name: "lookup", description: `escalations go to ${RAW}` }] }],
    // The variable is deliberately called `name`: variable names are the caller's own
    // keys, so the structural-key exemption must not apply to them.
    ["prompt.variables string value",
      { prompt: { id: "pmpt_1", variables: { name: RAW } } }],
    ["prompt.variables input_text value",
      { prompt: { id: "pmpt_1", variables: { customer: { type: "input_text", text: RAW } } } }],
    ["an unknown future item type with a text field",
      { input: [{ type: "future_item_v9", id: "fi_1", text: `note ${RAW}` }] }],
  ];
  for (const [name, body] of cases) {
    const { deidBody, spans } = rRedact(body);
    ok(`responses: ${name} redacted`, noRaw(deidBody, RAW) && spans.some((s) => s.type === "EMAIL"), JSON.stringify(deidBody));
  }

  // Structural fields and media payloads reach the upstream byte-exact.
  const struct = {
    input: [
      { type: "function_call_output", call_id: "call_555-123-4567", output: [
        { type: "input_text", text: `owner ${RAW}` },
        { type: "input_image", image_url: "data:image/png;base64,QUtJQUlPU0ZPRE5ON0VYQU1QTEU=" },
      ] },
      { type: "reasoning", id: "rs_1", summary: [{ type: "summary_text", text: `asked about ${RAW}` }], encrypted_content: "gAAAA555-123-4567" },
      { type: "future_item_v9", id: "fi_1", status: "completed", arguments: JSON.stringify({ to: RAW, qty: 3 }) },
    ],
  };
  const { deidBody: sd } = rRedact(struct);
  ok("responses: call_id, encrypted_content and input_image forwarded untouched",
    sd.input[0].call_id === "call_555-123-4567" && sd.input[1].encrypted_content === "gAAAA555-123-4567" &&
      sd.input[0].output[1].image_url === struct.input[0].output[1].image_url, JSON.stringify(sd));
  ok("responses: reasoning summary text redacted", noRaw(sd.input[1], RAW), JSON.stringify(sd.input[1]));
  {
    let args;
    try { args = JSON.parse(sd.input[2].arguments); } catch {}
    ok("responses: an unknown item's arguments stay valid JSON with a placeholder",
      /^<EMAIL_/.test(args?.to ?? "") && args?.qty === 3, sd.input[2].arguments);
  }

  // A shape nested past the walk's depth cap is refused (the proxy turns the throw into a
  // fail-closed 422), never forwarded with its deep leaves unread.
  {
    let deep = { text: RAW };
    for (let i = 0; i < 70; i++) deep = { nested: deep };
    let threw = false;
    try { rRedact({ input: [{ type: "future_item_v9", payload: deep }] }); } catch { threw = true; }
    ok("responses: an item nested past the depth cap throws (fail closed)", threw);
  }

  // redactSystem=false still exempts system/developer items, whatever their shape.
  {
    const { deidBody } = rRedact({ input: [{ role: "developer", type: "future_item_v9", text: `ops ${RAW}` }] }, new Vault("reversible"), false);
    ok("responses: redactSystem=false leaves developer items alone", deidBody.input[0].text === `ops ${RAW}`);
  }

  // Round trip: a reply echoing any of these placeholders comes back with the real value.
  {
    const v = new Vault("reversible");
    const all = { input: cases.flatMap(([, b]) => b.input && Array.isArray(b.input) ? b.input : []), tools: cases[5][1].tools, prompt: cases[6][1].prompt };
    const { deidBody } = rRedact(all, v);
    const toks = [...new Set(JSON.stringify(deidBody).match(/<EMAIL_[0-9A-F]+_\d+>/g) ?? [])];
    const resp = { output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text: `saw ${toks.join(" ")}` }] }] };
    const back = reidentifyBody(resp, "openai", v, "responses").output[0].content[0].text;
    ok("responses: placeholders from the new shapes restore on the way back",
      toks.length === 1 && back === `saw ${RAW}`, `${toks.join(",")} -> ${back}`);
  }
}

// ---------------- Class 2: unicode / zero-width / full-width evasion ----------------
ok("Class2: zero-width email detected", types(runAll("mail john​@acme.com now", ["pii"])).includes("EMAIL"));
ok("Class2: full-width card detected", types(runAll("card ４０１２８８８８８８８８１８８１", ["pci"])).includes("CREDIT_CARD"));
{
  const v = new Vault("reversible");
  const body = { messages: [{ role: "user", content: "reach john​@acme.com" }] };
  const { deidBody } = applyRedaction(body, "openai", v, ALL, detector);
  const sent = deidBody.messages[0].content;
  const etok = sent.match(/<EMAIL_[0-9A-F]+_1>/)?.[0];
  // Assert the exact redacted form ("reach <token>") rather than a substring check — proves
  // the whole raw email (domain and all) was replaced, with no host-shaped literal to trip
  // CodeQL's incomplete-URL-sanitization heuristic in a test assertion.
  ok("Class2: zero-width email redacted in body", !!etok && sent === `reach ${etok}`, sent);
  ok("Class2: re-id restores original zero-width value", v.lookup(etok) === "john​@acme.com");
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

// ---------------- consistent-pseudonym secret guard (issue #18, fail-closed) ----------------
const guard = (consistentPseudonyms, secret, allowWeak = false) => pseudonymSecretGuard({ consistentPseudonyms, secret, allowWeak });
ok("secret guard: OK when pseudonyms off", guard(false, "").ok === true);
ok("secret guard: BLOCK pseudonyms + empty secret", guard(true, "").ok === false);
ok("secret guard: BLOCK pseudonyms + too-short secret", guard(true, "x".repeat(MIN_PSEUDONYM_SECRET_LEN - 1)).ok === false);
ok("secret guard: OK pseudonyms + adequate secret", guard(true, "x".repeat(MIN_PSEUDONYM_SECRET_LEN)).ok === true);
ok("secret guard: escape hatch overrides", guard(true, "", true).ok === true);
ok("secret guard: error names TENANT_SECRET", (guard(true, "").error || "").includes("TENANT_SECRET"));
ok("adequatePseudonymSecret threshold", !adequatePseudonymSecret("short") && adequatePseudonymSecret("x".repeat(MIN_PSEUDONYM_SECRET_LEN)));

// ---------------- UPSTREAM_TIMEOUT_MS: an invalid value falls back to the default ----------------
ok("timeout: unset -> default", parseTimeoutMs(undefined) === DEFAULT_UPSTREAM_TIMEOUT_MS);
ok("timeout: a positive number is used", parseTimeoutMs("1500") === 1500);
ok("timeout: non-numeric -> default, not NaN (NaN would 504 every request)", parseTimeoutMs("ten-minutes") === DEFAULT_UPSTREAM_TIMEOUT_MS);
ok("timeout: the largest Node timer delay is accepted", parseTimeoutMs(String(MAX_TIMEOUT_MS)) === MAX_TIMEOUT_MS);
ok("timeout: above 2^31-1 -> default (an overflowing delay fires at once)", parseTimeoutMs(String(MAX_TIMEOUT_MS + 1)) === DEFAULT_UPSTREAM_TIMEOUT_MS && parseTimeoutMs("1e12") === DEFAULT_UPSTREAM_TIMEOUT_MS);
ok("timeout: empty, zero, negative and Infinity -> default",
  ["", "  ", "0", "-5", "Infinity"].every((v) => parseTimeoutMs(v) === DEFAULT_UPSTREAM_TIMEOUT_MS));

// ---------------- tenant policy persistence (issue #20, optional file-backed) ----------------
{
  const tmp = "./_policy_unit.json";
  try { rmSync(tmp, { force: true }); } catch {}
  setPolicy("acme", { mode: "strip", failMode: "closed" }); // stricter-than-default tenant
  await savePolicy(tmp);
  ok("policy persist: file written with the tenant", readFileHas(tmp, "acme") && readFileHas(tmp, "strip"));
  // simulate a restart: in-memory drifts, then load() replaces the map from disk
  setPolicy("acme", { mode: "reversible" });
  setPolicy("ephemeral", { failMode: "open" });
  await loadPolicy(tmp);
  ok("policy persist: stricter tenant restored after reload", getPolicy("acme").mode === "strip" && getPolicy("acme").failMode === "closed");
  ok("policy persist: reload is source-of-truth (drops unsaved tenants)", !allPolicies().ephemeral);

  // fail-safe: absent + malformed files never throw and never wipe good state
  await loadPolicy("./_policy_does_not_exist.json");
  ok("policy persist: absent file non-fatal, state preserved", getPolicy("acme").mode === "strip");
  const bad = "./_policy_bad.json";
  writeFileSync(bad, "{ not valid json ");
  await loadPolicy(bad);
  ok("policy persist: malformed file non-fatal, state preserved", getPolicy("acme").mode === "strip");
  try { rmSync(tmp, { force: true }); } catch {}
  try { rmSync(bad, { force: true }); } catch {}
}

// ---------------- tool-call arguments ----------------
{
  const ALL_TOOLS = parseRestoreTools("*");
  const v = new Vault("reversible");
  // A value with a quote, a backslash and a newline: spliced into a JSON string literal raw,
  // any one of them breaks the document.
  const tricky = 'she said "hi" \\ then\nleft';
  const tok = v.placeholderFor(tricky, "PRIVATE_KEY");
  const em = v.placeholderFor("john@acme.com", "EMAIL");
  const doc = `{"text":"pre ${tok} post","n":9007199254740993,"e":"${em}"}`;
  const whole = restoreArgs(doc, argContext(v, true, "echo", { unresolved: 0 }, ALL_TOOLS));
  let parsed = null;
  try { parsed = JSON.parse(whole); } catch {}
  ok("args: quote, backslash and newline are JSON-escaped and the document parses", parsed?.text === `pre ${tricky} post`, whole);
  ok("args: the email is restored", parsed?.e === "john@acme.com");
  ok("args: a number beyond 2^53 keeps its digits (raw text, never re-serialised)", whole.includes('"n":9007199254740993'), whole);

  // Streamed one character, then three characters, at a time: the fragments join into exactly
  // the whole-document restore (what a done frame carries).
  const streamed = (text, size) => {
    const s = new ArgStream(argContext(v, true, "echo", { unresolved: 0 }, ALL_TOOLS));
    let out = "";
    for (let i = 0; i < text.length; i += size) out += s.push(text.slice(i, i + size));
    return out + s.end();
  };
  ok("args stream: 1-character fragments join into the whole-document restore", streamed(doc, 1) === whole, streamed(doc, 1));
  ok("args stream: 3-character fragments join into the whole-document restore", streamed(doc, 3) === whole);

  // A serializer that spells < and > as \u003c and \u003e: one placeholder all the same,
  // in the whole document and in the fragments.
  const esc = doc.replace(/</g, "\\u003c").replace(/>/g, "\\u003e");
  const wholeEsc = restoreArgs(esc, argContext(v, true, "echo", { unresolved: 0 }, ALL_TOOLS));
  let pe = null;
  try { pe = JSON.parse(wholeEsc); } catch {}
  ok("args: \\u003c-spelled placeholders restored in the whole document", pe?.e === "john@acme.com" && pe?.text === `pre ${tricky} post`, wholeEsc);
  ok("args stream: \\u003c-spelled placeholders restored across 1-character fragments", streamed(esc, 1) === wholeEsc, streamed(esc, 1));
  ok("args stream: \\u003c-spelled placeholders restored across 3-character fragments", streamed(esc, 3) === wholeEsc);
  // An unrelated \u escape near the end is held only while it could be an opening.
  ok("args stream: a \\u00e9 escape passes through", streamed('{"a":"caf\\u00e9"}', 1) === '{"a":"caf\\u00e9"}');

  // Plain-text input (a custom tool): the value goes back raw, not JSON-escaped.
  const plain = restoreArgs(`pre ${tok}`, argContext(v, false, "echo", { unresolved: 0 }, ALL_TOOLS));
  ok("args text: a custom tool's input gets the raw value, not a JSON-escaped one", plain === `pre ${tricky}`, JSON.stringify(plain));

  // Placeholders this vault never minted: the counter form and the pseudonym form are
  // counted; a caller's own literal of another shape is not.
  const st = { unresolved: 0 };
  restoreArgs('{"a":"<EMAIL_ABCDEF_7> <PHONE_0A1B2C3D> <EMAIL_1>"}', argContext(v, true, "echo", st, ALL_TOOLS));
  ok("args: foreign counter-form and pseudonym-form placeholders are counted, a caller literal is not", st.unresolved === 2, String(st.unresolved));
  const st2 = { unresolved: 0 };
  restoreArgs('{"a":"\\u003cEMAIL_ABCDEF_7\\u003e"}', argContext(v, true, "echo", st2, ALL_TOOLS));
  ok("args: a foreign placeholder in the \\u003c spelling is counted too", st2.unresolved === 1);
  ok("isMintedPlaceholder: counter and pseudonym forms only", isMintedPlaceholder("<EMAIL_ABCDEF_7>") && isMintedPlaceholder("<US_ROUTING_0A1B2C3D>") && !isMintedPlaceholder("<EMAIL_1>") && !isMintedPlaceholder("<EMAIL_abcdef_1>"));

  // The restore policy.
  for (const [label, raw] of [["unset", undefined], ["empty", ""], ["spaces", "   "], ["only commas", " , ,"]]) {
    const np = parseRestoreTools(raw);
    ok(`restore policy: ${label} restores no tool's arguments`, np.none && !np.all && !np.forTool("echo")("text") && !np.forTool(undefined)(undefined));
    const out = restoreArgs(`{"text":"${em}"}`, argContext(v, true, "echo", { unresolved: 0 }, np));
    ok(`restore policy: ${label} sends the strip form, never the value`, out === '{"text":"[EMAIL]"}', out);
  }
  const star = parseRestoreTools(" * ");
  ok("restore policy: * is the opt-in that restores everything", star.all && !star.none && star.forTool("anything")(undefined));
  const p = parseRestoreTools("echo.text, other");
  ok("restore policy: tool.field allows only that field", p.forTool("echo")("text") && !p.forTool("echo")("note") && !p.forTool("echo")(undefined));
  ok("restore policy: a bare tool allows all its fields", p.forTool("other")("anything") && p.forTool("other")(undefined));
  ok("restore policy: an unlisted or unnamed tool gets nothing", !p.forTool("nope")("text") && !p.forTool(undefined)("text"));
  const st3 = { unresolved: 0 };
  const pol = restoreArgs(`{"text":"${em}","note":"${em}"}`, argContext(v, true, "echo", st3, p));
  let pp = null;
  try { pp = JSON.parse(pol); } catch {}
  ok("restore policy: the allowed field is restored, the other gets the strip form", pp?.text === "john@acme.com" && pp?.note === "[EMAIL]", pol);
  ok("restore policy: a placeholder withheld by policy is not an unresolved one", st3.unresolved === 0);
  const ps = new ArgStream(argContext(v, true, "echo", { unresolved: 0 }, p));
  let pstream = "";
  const pdoc = `{"text":"${em}","note":"${em}"}`;
  for (const ch of pdoc) pstream += ps.push(ch);
  pstream += ps.end();
  ok("restore policy: the same per-field decision across 1-character fragments", pstream === pol, pstream);

  // The top-level key a position belongs to.
  const kt = new TopKeyTracker();
  const keys = [];
  for (const ch of '{"a":"x","b":{"c":"y"},"d":["z"],"e\\"q":"w"}') {
    kt.feed(ch);
    if ("xyzw".includes(ch)) keys.push(kt.key);
  }
  ok("top-level key tracker: nested values, arrays and escaped keys", JSON.stringify(keys) === JSON.stringify(["a", "b", "d", 'e"q']), JSON.stringify(keys));

  // Whole bodies: an unresolved placeholder in a tool call's arguments is reported, not passed.
  const body = { output: [{ type: "function_call", name: "echo", arguments: '{"a":"<EMAIL_ABCDEF_7>"}' }] };
  const bst = { unresolved: 0 };
  reidentifyBody(body, "openai", v, "responses", bst);
  ok("reidentifyBody: an unresolved placeholder in arguments is counted", bst.unresolved === 1);
  const fresh = new Vault("reversible");
  const fst = { unresolved: 0 };
  reidentifyBody(body, "openai", fresh, "responses", fst);
  ok("reidentifyBody: counted even when the request redacted nothing", fst.unresolved === 1);

  // An escaped backslash before u003c is a backslash and the letters u003c, not a placeholder.
  // JSON text: two backslashes (an escaped backslash), u003c, the name, then a real >.
  const lit = `{"a":"\\\\u003c${em.slice(1, -1)}\\u003e"}`;
  const lst = { unresolved: 0 };
  const litOut = restoreArgs(lit, argContext(v, true, "echo", lst, ALL_TOOLS));
  ok("args: \\u003c (an escaped backslash) is text, not a placeholder", litOut === lit && !litOut.includes("john@acme.com"), litOut);
  const ls = new ArgStream(argContext(v, true, "echo", { unresolved: 0 }, ALL_TOOLS));
  let litStream = "";
  for (const ch of lit) litStream += ls.push(ch);
  litStream += ls.end();
  ok("args stream: the same across 1-character fragments", litStream === lit, litStream);

  // A stream that ends inside a placeholder is rejected, never completed by guessing.
  const tst = { unresolved: 0 };
  const ts = new ArgStream(argContext(v, true, "echo", tst, ALL_TOOLS));
  const cut = `{"a":"${em.slice(0, 5)}`;
  const tout = ts.push(cut) + ts.end();
  ok("args stream: a tail cut inside a placeholder is rejected and counted unresolved", tst.rejected === "the arguments end inside a placeholder" && tst.unresolved === 1, JSON.stringify(tst));
  ok("args stream: and nothing of the refused call is released", tout === "" && !tout.includes("john@acme.com"), tout);

  // JSON arguments are released only once the whole-document checks pass: fragments give
  // nothing, a clean call gives the whole restored document at the end, and a call refused
  // for colliding names or depth gives nothing at all.
  {
    const bv = new Vault("reversible");
    const e1 = bv.placeholderFor("a@corp.io", "EMAIL");
    const e2 = bv.placeholderFor("b@corp.io", "EMAIL");
    const run = (doc, pol) => {
      const st = { unresolved: 0 };
      const s = new ArgStream(argContext(bv, true, "echo", st, pol));
      const parts = [];
      for (let i = 0; i < doc.length; i += 4) parts.push(s.push(doc.slice(i, i + 4)));
      return { parts, end: s.end(), st };
    };
    const clean = run(`{"to":"${e1}","n":1}`, ALL_TOOLS);
    ok("args stream: a clean call releases nothing until the end, then the whole document", clean.parts.every((p) => p === "") && clean.end === '{"to":"a@corp.io","n":1}', JSON.stringify(clean));
    const coll = run(`{"${e1}":1,"${e2}":2}`, parseRestoreTools(""));
    ok("args stream: a call refused for colliding names releases nothing", coll.parts.every((p) => p === "") && coll.end === "" && /same name/.test(coll.st.rejected ?? ""), JSON.stringify(coll));
    const deep = run("[".repeat(70) + `"${e1}"` + "]".repeat(70), ALL_TOOLS);
    ok("args stream: a call refused for depth releases nothing", deep.parts.every((p) => p === "") && deep.end === "" && /deeper than 64/.test(deep.st.rejected ?? ""), JSON.stringify(deep.st));
  }

  // A parsed input: property names are restored like values, collisions and deep nesting rejected.
  const o1 = { [em]: "x", nested: { [em]: em } };
  const ost = { unresolved: 0 };
  restoreArgObject(o1, argContext(v, false, "echo", ost, ALL_TOOLS));
  ok("args object: a top-level property name is restored", Object.keys(o1)[0] === "john@acme.com" && !ost.rejected, JSON.stringify(o1));
  ok("args object: nested names and values are restored", o1.nested["john@acme.com"] === "john@acme.com");
  const o2 = { [em]: 1, "john@acme.com": 2 };
  const cst = { unresolved: 0 };
  restoreArgObject(o2, argContext(v, false, "echo", cst, ALL_TOOLS));
  ok("args object: two names restoring to one name are rejected", cst.rejected === "two argument names restore to the same name", String(cst.rejected));
  let deep = { leaf: em };
  for (let i = 0; i < MAX_ARG_DEPTH + 5; i++) deep = { d: deep };
  const dst = { unresolved: 0 };
  restoreArgObject(deep, argContext(v, false, "echo", dst, ALL_TOOLS));
  ok("args object: nesting past the limit is rejected, not cut silently", /deeper than/.test(dst.rejected ?? ""), String(dst.rejected));
  let wide = {};
  for (let i = 0; i < 20000; i++) wide = { d: wide };
  const wst = { unresolved: 0 };
  let threw = false;
  try { restoreArgObject(wide, argContext(v, false, "echo", wst, ALL_TOOLS)); } catch { threw = true; }
  ok("args object: a very deep object is refused without exhausting the stack", !threw && !!wst.rejected);

  // A withheld top-level name that becomes an allowed field name ([EMAIL]) never authorizes
  // its value: parsed input and JSON text judge the value by the name the model wrote.
  {
    const em2 = v.placeholderFor("jane@acme.com", "EMAIL");
    const stripKey = parseRestoreTools("echo.[EMAIL]");
    const obj = { [em]: em2 };
    restoreArgObject(obj, argContext(v, false, "echo", { unresolved: 0 }, stripKey));
    const text = restoreArgsWhole(JSON.stringify({ [em]: em2 }), argContext(v, true, "echo", { unresolved: 0 }, stripKey));
    ok("args object: a withheld name renamed to an allowed field does not restore its value", JSON.stringify(obj) === '{"[EMAIL]":"[EMAIL]"}', JSON.stringify(obj));
    ok("args parity: parsed input and JSON text withhold the same value", text === JSON.stringify(obj), text);
  }

  // A call whose name may still be arriving: nothing restored or emitted until it ends.
  const names = { k: "send" };
  const sendOnly = parseRestoreTools("send");
  const dfa = new DeferredArgs(() => argContext(v, true, names.k, { unresolved: 0 }, sendOnly));
  const dpush = dfa.push(`{"to":"${em}"}`);
  names.k = "send_email";
  const dend = dfa.end();
  ok("deferred args: nothing emitted before the call ends", dpush === "");
  ok("deferred args: the final name decides (send_email is not on the list)", dend === '{"to":"[EMAIL]"}', dend);

  // A name character written as a JSON escape (\u0045 for E) is the same placeholder.
  const nm = em.slice(1, -1);
  const escName = "\\u00" + nm.charCodeAt(0).toString(16).toUpperCase() + nm.slice(1);
  const escDoc = `{"a":"<${escName}>"}`;
  const escOut = restoreArgs(escDoc, argContext(v, true, "echo", { unresolved: 0 }, ALL_TOOLS));
  ok("args: an escape inside the placeholder name is decoded", JSON.parse(escOut).a === "john@acme.com", escOut);
  const es = new ArgStream(argContext(v, true, "echo", { unresolved: 0 }, ALL_TOOLS));
  let escStream = "";
  for (const ch of escDoc) escStream += es.push(ch);
  escStream += es.end();
  ok("args stream: and across 1-character fragments", escStream === escOut, escStream);
  // An escaped < or > never joins a name.
  const notName = restoreArgs('{"a":"<EMAIL\\u003c>"}', argContext(v, true, "echo", { unresolved: 0 }, ALL_TOOLS));
  ok("args: an escaped < inside the brackets is not a name character", notName === '{"a":"<EMAIL\\u003c>"}', notName);

  // Text that is not a placeholder (<3>, a<b>c, <>) passes through once, untouched, next
  // to a real token, whole and streamed at 1, 2 and 3 characters; and with an empty vault.
  const litDoc = JSON.stringify({ x: "<3>", y: "a<b>c", z: "<>", w: `p<3>q${em}r<3>`, k: { "<3>": em } });
  const litDocWant = JSON.stringify({ x: "<3>", y: "a<b>c", z: "<>", w: "p<3>qjohn@acme.comr<3>", k: { "<3>": "john@acme.com" } });
  const litStats = { unresolved: 0 };
  const litWhole = restoreArgs(litDoc, argContext(v, true, "echo", litStats, ALL_TOOLS));
  ok("args: literals next to a token pass through once", litWhole === litDocWant && litStats.unresolved === 0, litWhole);
  for (const n of [1, 2, 3]) {
    const ls = new ArgStream(argContext(v, true, "echo", { unresolved: 0 }, ALL_TOOLS));
    let lo = "";
    for (let i = 0; i < litDoc.length; i += n) lo += ls.push(litDoc.slice(i, i + n));
    lo += ls.end();
    ok(`args stream: literals next to a token, ${n}-character fragments`, lo === litDocWant, lo);
  }
  const litEmptyV = new Vault("reversible");
  const litPlain = JSON.stringify({ x: "<3>", y: "a<3>b<3>c" });
  const litPlainOut = restoreArgs(litPlain, argContext(litEmptyV, true, "echo", { unresolved: 0 }, ALL_TOOLS));
  ok("args: an empty vault leaves <3> literals byte for byte", litPlainOut === litPlain, litPlainOut);

  // Property names that become the same after a restore are refused on the JSON-text path,
  // whole and streamed, as restoreArgObject refuses them on parsed objects.
  {
    const kv = new Vault("reversible");
    const a1 = kv.placeholderFor("alice@example.com", "EMAIL");
    const a2 = kv.placeholderFor("bob@example.com", "EMAIL");
    ok("hasDuplicateKeys: same name twice in one object", hasDuplicateKeys('{"a":{"x":1,"x":2}}') && !hasDuplicateKeys('{"a":{"x":1},"b":{"x":2}}') && !hasDuplicateKeys('["x","x"]') && hasDuplicateKeys('{"\\u0078":1,"x":2}'));
    const cases = [
      ["a restored name meets a literal one", `{"users":{"alice@example.com":"viewer","${a1}":"admin"}}`, ALL_TOOLS, true],
      ["two withheld names both become [EMAIL]", `{"${a1}":1,"${a2}":2}`, parseRestoreTools(""), true],
      ["distinct restored names pass", `{"${a1}":1,"${a2}":2}`, ALL_TOOLS, false],
      ["duplicates the model wrote itself are not this restore's", `{"x":1,"x":2,"y":"${a1}"}`, ALL_TOOLS, false],
    ];
    // An unrelated duplicate the model wrote in one object never hides a new collision in
    // another.
    cases.push(["a collision next to an unrelated duplicate elsewhere", `{"a":{"x":1,"x":2},"b":{"alice@example.com":1,"${a1}":2}}`, ALL_TOOLS, true]);
    cases.push(["a collision in the same object as an unrelated duplicate", `{"x":1,"x":2,"alice@example.com":3,"${a1}":4}`, ALL_TOOLS, true]);
    for (const [label, doc, pol, bad] of cases) {
      const ws = { unresolved: 0 };
      restoreArgsWhole(doc, argContext(kv, true, "echo", ws, pol));
      ok(`args collide (whole): ${label}`, (ws.rejected === "two argument names restore to the same name") === bad, JSON.stringify(ws));
      for (const n of [1, 3]) {
        const ss = { unresolved: 0 };
        const as = new ArgStream(argContext(kv, true, "echo", ss, pol));
        for (let i = 0; i < doc.length; i += n) as.push(doc.slice(i, i + n));
        as.end();
        ok(`args collide (${n}-character stream): ${label}`, (ss.rejected === "two argument names restore to the same name") === bad, JSON.stringify(ss));
      }
    }
  }

  // A top-level value is judged by the key the model wrote: with echo.[EMAIL] on the list,
  // a withheld placeholder key that becomes [EMAIL] does not authorize its value, on parsed
  // input and on JSON text alike.
  {
    const kv2 = new Vault("reversible");
    const k1 = kv2.placeholderFor("key@corp.io", "EMAIL");
    const v1 = kv2.placeholderFor("value@corp.io", "EMAIL");
    const pol = parseRestoreTools("echo.[EMAIL]");
    const obj = { [k1]: v1 };
    restoreArgObject(obj, argContext(kv2, false, "echo", { unresolved: 0 }, pol));
    const txt = restoreArgsWhole(JSON.stringify({ [k1]: v1 }), argContext(kv2, true, "echo", { unresolved: 0 }, pol));
    ok("policy parity: a renamed key does not authorize its value (parsed input)", JSON.stringify(obj) === '{"[EMAIL]":"[EMAIL]"}', JSON.stringify(obj));
    ok("policy parity: and JSON text gives the same arguments", txt === JSON.stringify(obj), txt);
  }

  // A placeholder outside a string literal ({"phone":<PHONE_…>}) is refused before anything
  // is substituted: restored, a digit-only phone would turn into a JSON number, which the
  // replay walk does not redact as a phone.
  {
    const pv = new Vault("reversible");
    const ph = pv.placeholderFor("5551234567", "PHONE");
    const em2 = pv.placeholderFor("jane@corp.io", "EMAIL");
    const bare = `{"phone":${ph},"note":"${em2}"}`;
    const outside = /outside a JSON string/;
    const ws = { unresolved: 0 };
    const wo = restoreArgsWhole(bare, argContext(pv, true, "echo", ws, ALL_TOOLS));
    ok("args: a placeholder outside a string is refused (whole)", outside.test(ws.rejected ?? "") && wo.includes(ph) && !wo.includes("5551234567"), JSON.stringify({ ws, wo }));
    for (const n of [1, 2, 3]) {
      const ss = { unresolved: 0 };
      const as = new ArgStream(argContext(pv, true, "echo", ss, ALL_TOOLS));
      let so = "";
      for (let i = 0; i < bare.length; i += n) so += as.push(bare.slice(i, i + n));
      so += as.end();
      ok(`args: a placeholder outside a string is refused (${n}-character stream)`, outside.test(ss.rejected ?? "") && !so.includes("5551234567"), JSON.stringify({ ss, so }));
    }
    // Inside a string, keys and values alike, it is restored as before.
    const quoted = `{"phone":"${ph}","${em2}":1}`;
    const qs = { unresolved: 0 };
    const qo = restoreArgsWhole(quoted, argContext(pv, true, "echo", qs, ALL_TOOLS));
    ok("args: the same placeholder inside a string is restored", !qs.rejected && JSON.parse(qo).phone === "5551234567" && JSON.parse(qo)["jane@corp.io"] === 1, qo);
    // An escaped quote inside a string does not end it; a placeholder after it is inside.
    const esc = `{"a":"say \\"hi\\" ${ph}"}`;
    const es = { unresolved: 0 };
    const eo = restoreArgsWhole(esc, argContext(pv, true, "echo", es, ALL_TOOLS));
    ok("args: a placeholder after an escaped quote is still inside the string", !es.rejected && JSON.parse(eo).a === 'say "hi" 5551234567', eo);
    // Replay: what the refused call carried is the token, so a later turn redacts nothing
    // it never had; had the number gone out, the walk would have forwarded it as a number.
    const replay = applyRedaction({ model: "m", messages: [{ role: "assistant", content: null, tool_calls: [{ id: "c", type: "function", function: { name: "echo", arguments: '{"phone":5551234567}' } }] }] }, "openai", new Vault("reversible"), ALL, detector).deidBody;
    ok("replay: a digit-only phone as a JSON number is not redacted (why it must never be produced)", replay.messages[0].tool_calls[0].function.arguments.includes("5551234567"), replay.messages[0].tool_calls[0].function.arguments);
  }

  // Nesting deeper than MAX_ARG_DEPTH is refused on JSON text, whole and streamed, as on
  // parsed objects; 64 levels pass.
  {
    const nest = (n, inner) => '{"a":'.repeat(n) + inner + "}".repeat(n);
    const dv = new Vault("reversible");
    const dt = dv.placeholderFor("john@acme.com", "EMAIL");
    for (const [label, doc, bad] of [
      ["70 levels with a placeholder", nest(70, `"${dt}"`), true],
      ["70 levels of arrays without one", "[".repeat(70) + "1" + "]".repeat(70), true],
      ["65 levels (depth 64) with a placeholder", nest(65, `"${dt}"`), false],
    ]) {
      const ws = { unresolved: 0 };
      restoreArgsWhole(doc, argContext(dv, true, "echo", ws, ALL_TOOLS));
      const nestRe = /nest deeper than 64/;
      ok(`args depth (whole): ${label}`, nestRe.test(ws.rejected ?? "") === bad, JSON.stringify(ws));
      for (const n of [1, 7]) {
        const ss = { unresolved: 0 };
        const as = new ArgStream(argContext(dv, true, "echo", ss, ALL_TOOLS));
        for (let i = 0; i < doc.length; i += n) as.push(doc.slice(i, i + n));
        as.end();
        ok(`args depth (${n}-character stream): ${label}`, nestRe.test(ss.rejected ?? "") === bad, JSON.stringify(ss));
      }
    }
    const deepObj = JSON.parse(nest(70, `"${dt}"`));
    const os = { unresolved: 0 };
    restoreArgObject(deepObj, argContext(dv, false, "echo", os, ALL_TOOLS));
    ok("args depth: the object path refuses the same 70-level document", /nest deeper than 64/.test(os.rejected ?? ""), JSON.stringify(os));
  }

  // A stream that ends inside `<NAME` is refused only when NAME is the start of a token
  // this vault minted or has the minted shape; other text is delivered as written, as the
  // whole document would be.
  {
    const tv = new Vault("reversible");
    const tok = tv.placeholderFor("john@acme.com", "EMAIL");
    const tail = (text, json) => {
      const ts = { unresolved: 0 };
      const s = new ArgStream(argContext(tv, json, "echo", ts, ALL_TOOLS));
      let o = "";
      for (const ch of text) o += s.push(ch);
      o += s.end();
      return { o, ts };
    };
    for (const text of ["cat <README", "x<Y", "SELECT * FROM t WHERE x<Y"]) {
      const { o, ts } = tail(text, false);
      ok(`args stream tail: \`${text}\` is delivered as written`, o === text && !ts.rejected && ts.unresolved === 0, JSON.stringify({ o, ts }));
    }
    const cut = tail("x " + tok.slice(0, 5), false);
    ok("args stream tail: the start of a minted token is refused", cut.ts.rejected === "the arguments end inside a placeholder" && cut.ts.unresolved === 1, JSON.stringify(cut));
    const foreign = tail("x <PHONE_ABCDEF_", false);
    ok("args stream tail: a foreign minted shape is refused", foreign.ts.rejected === "the arguments end inside a placeholder", JSON.stringify(foreign));
    // The whole document is judged the same way as the stream.
    for (const [text, bad] of [["use <EMAIL_ABC", true], ["x " + tok.slice(0, 5), true], ["cat <README", false], ["x<Y", false]]) {
      const ws = { unresolved: 0 };
      const o = restoreArgsWhole(text, argContext(tv, false, "echo", ws, ALL_TOOLS));
      const st = tail(text, false).ts;
      ok(`args tail parity: \`${text}\` ${bad ? "refused" : "delivered"} whole and streamed`, !!ws.rejected === bad && !!st.rejected === bad && (bad || o === text), JSON.stringify({ ws, st, o }));
    }
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

function readFileHas(path, needle) {
  try { return readFileSync(path, "utf8").includes(needle); } catch { return false; }
}
