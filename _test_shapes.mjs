// Request shapes (src/shapes.ts) and their replay (src/replay.ts): a shape never holds text,
// recording deduplicates and stops at its cap, and shapes taken from realistic requests replay
// with invented people without a leak or a refusal.
// Run inside the battery (npm test) or: node --import tsx _test_shapes.mjs
import { readFileSync, rmSync } from "node:fs";
import { skeleton, ShapeLog, shapeDigest } from "./src/shapes.ts";
import { replayShapes, instantiate, REPLAY_PEOPLE } from "./src/replay.ts";

let pass = 0;
let fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) pass++;
  else fail++;
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? `   (${detail})` : ""}`);
};

// A realistic agent turn, full of things a shape must never carry.
const SECRET = ["Marisol Quintero-Vance", "mqvance77@example.com", "(404) 555-0187", "Decatur", "case-1234", "sk-live-abc", "marisol"];
const form = `Name: ${SECRET[0]}\nEmail: ${SECRET[1]}\nPhone: ${SECRET[2]}\n\nI live in ${SECRET[3]}.`;
const agentBody = {
  model: "claude-sonnet-5-5",
  max_tokens: 512,
  system: `You handle ${SECRET[4]}. Key ${SECRET[5]}.`,
  tools: [{ name: "lookup_request", description: "Reads a request.", input_schema: { type: "object", properties: { id: { type: "string" } } } }],
  metadata: { [SECRET[0]]: SECRET[1] },
  messages: [
    { role: "user", content: "Handle request R1." },
    { role: "assistant", content: [{ type: "tool_use", id: "t1", name: "lookup_request", input: { id: SECRET[4], [SECRET[6]]: 1 } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: JSON.stringify({ request: { text: form } }, null, 2) }] },
  ],
};
const chatBody = {
  model: "gpt-6",
  messages: [
    { role: "user", name: SECRET[6], content: form },
    { role: "assistant", content: null, tool_calls: [{ id: "c1", type: "function", function: { name: "search", arguments: JSON.stringify({ q: SECRET[0] }) } }] },
    { role: "tool", tool_call_id: "c1", content: JSON.stringify({ email: SECRET[1] }) },
  ],
};
const responsesBody = {
  model: "gpt-6", store: false,
  input: [
    { role: "user", content: [{ type: "input_text", text: form }] },
    { type: "function_call", call_id: "c1", name: "search", arguments: JSON.stringify({ q: SECRET[0] }) },
    { type: "function_call_output", call_id: "c1", output: JSON.stringify({ hit: SECRET[1] }) },
  ],
};

for (const [label, body] of [["messages", agentBody], ["chat", chatBody], ["responses", responsesBody]]) {
  const s = JSON.stringify(skeleton(body));
  const leaked = SECRET.filter((v) => s.toLowerCase().includes(v.toLowerCase()));
  ok(`shape (${label}): holds no text, caller key or participant name`, leaked.length === 0, leaked.join(", ") || s.slice(0, 160));
}
{
  const s = skeleton(agentBody);
  ok("shape: listed enum values and protocol keys are kept; a tool name is a stable digest", /^[0-9a-f]{8}$/.test(s.tools[0].name.$tool) && s.tools[0].name.$tool === s.messages[1].content[0].name.$tool && s.messages[1].content[0].type === "tool_use" && s.model.$model === 1 && !JSON.stringify(s).includes("lookup_request"));
  {
    const odd = skeleton({ messages: [{ role: "user", content: [{ type: "marisolquinterovance", text: "x" }, { type: "image", source: { type: "base64", media_type: "image/marisol", data: "AAAA" } }] }], tools: [{ name: "marisol_lookup" }] });
    const t = JSON.stringify(odd);
    ok("shape: a caller-chosen value in an enum field or a tool name is never kept", !/marisol|quintero|vance/i.test(t), t.slice(0, 200));
    ok("shape: an unlisted enum value is recorded by size", typeof odd.messages[0].content[0].type.$s === "number" && typeof odd.messages[0].content[1].source.media_type.$s === "number");
  }
  ok("shape: a JSON string's own shape is kept, pretty or not", s.messages[2].content[0].content.$json !== undefined && s.messages[2].content[0].content.$pretty === 1);
  ok("shape: line counts and size classes, not lengths", s.messages[2].content[0].content.$json["*0"]["*0"].$nl === 4 && [16, 32, 64, 128].includes(s.messages[2].content[0].content.$json["*0"]["*0"].$s));
  const c = skeleton(chatBody);
  ok("shape: a chat participant name is text, not a tool name", c.messages[0].name.$tool === undefined && typeof c.messages[0].name.$s === "number");
  ok("shape: a chat function name is a digest", /^[0-9a-f]{8}$/.test(c.messages[1].tool_calls[0].function.name.$tool));
  ok("shape: long arrays are cut with a count", JSON.stringify(skeleton({ messages: Array.from({ length: 30 }, () => ({ role: "user", content: "x" })) })).includes('"$more":18'));
}

// ---- recording ----
{
  const file = "./_shapes_unit.jsonl";
  rmSync(file, { force: true });
  const log = new ShapeLog(file, 2);
  await log.record("anthropic", "messages", agentBody);
  await log.record("anthropic", "messages", { ...agentBody, system: "a different text of another length entirely, much longer than before" });
  await log.record("anthropic", "messages", agentBody);
  let lines = readFileSync(file, "utf8").trim().split("\n");
  ok("record: one line per distinct shape", lines.length === 2, String(lines.length));
  await log.record("openai", "chat", chatBody);
  lines = readFileSync(file, "utf8").trim().split("\n");
  ok("record: stops at its cap", lines.length === 2, String(lines.length));
  ok("record: the file holds no text", !SECRET.some((v) => readFileSync(file, "utf8").toLowerCase().includes(v.toLowerCase())));
  const again = new ShapeLog(file, 10);
  await again.record("anthropic", "messages", agentBody);
  ok("record: a restart reads the seen shapes back", readFileSync(file, "utf8").trim().split("\n").length === 2);
  rmSync(file, { force: true });
  ok("record: off when no path is set", (await new ShapeLog("", 10).record("anthropic", "messages", agentBody)) === undefined);
}

// ---- replay ----
{
  const records = [["anthropic", "messages", agentBody], ["openai", "chat", chatBody], ["openai", "responses", responsesBody]].map(([provider, dialect, body]) => {
    const shape = skeleton(body);
    return { ts: 0, h: shapeDigest(provider, dialect, shape), provider, dialect, shape };
  });
  const filled = instantiate(records[0].shape, REPLAY_PEOPLE[0], "identifiers", () => 0);
  ok("replay: a filled shape has the original structure", /^tool_[0-9a-f]{8}$/.test(filled.messages[1].content[0].name) && filled.messages[1].content[0].name === filled.tools[0].name && typeof filled.messages[2].content[0].content === "string" && JSON.parse(filled.messages[2].content[0].content).field0 !== undefined);
  for (const n of [13, 33, 140]) {
    const long = skeleton({ messages: Array.from({ length: n }, (_, i) => ({ role: i % 2 ? "assistant" : "user", content: `turn ${i}` })) });
    const back = instantiate(long, REPLAY_PEOPLE[1], "ordinary", () => 0);
    ok(`replay: a ${n}-item array is replayed at its recorded length`, back.messages.length === n, String(back.messages.length));
  }
  const { runs, failures } = replayShapes(records);
  ok(`replay: real shapes with invented people neither leak nor refuse (${runs} runs)`, failures.length === 0, failures.slice(0, 4).map((f) => `${f.check} ${f.dialect} p${f.person} ${f.where}`).join(" ;; "));

  // An agent turn with extended thinking: the thinking text, its signature, the tool_use id and
  // the tool_result's tool_use_id are opaque values the upstream mints and verifies; redaction
  // leaves them alone, so the fill must not write identifiers into them (every recorded shape
  // with a thinking block failed before).
  const thinkingBody = {
    model: "claude-sonnet-4-5", max_tokens: 1024, thinking: { type: "enabled", budget_tokens: 2048 },
    tools: [{ name: "lookup_case", description: "Finds a case", input_schema: { type: "object", properties: { q: { type: "string" } } } }],
    messages: [
      { role: "user", content: "Please look up the case for Grant and tell me what happens next." },
      { role: "assistant", content: [
        { type: "thinking", thinking: "The user wants the case looked up; I will call the tool.", signature: "ErUBCkYIBBgCIkDh3x5Wz2zqkz0m5m2n1aVdqmRTzpDqsP3I7jYtm1HlQ8Y0QZ2sJqcNfz1xVmQ7jS6b0mPBk6HGy8tFwJdG0wIaDN1X2T4" },
        { type: "tool_use", id: "toolu_01A09q90qw90lq917835lq9", name: "lookup_case", input: { q: "Grant" } },
      ] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_01A09q90qw90lq917835lq9", content: "{\"owner\":\"Grant\",\"status\":\"open\"}" }] },
    ],
  };
  const tshape = skeleton(thinkingBody);
  const tfilled = instantiate(tshape, REPLAY_PEOPLE[0], "identifiers", () => 2);
  const sig = tfilled.messages[1].content[0].signature;
  const id = tfilled.messages[1].content[1].id;
  const think = tfilled.messages[1].content[0].thinking;
  const idents = [REPLAY_PEOPLE[0].name, REPLAY_PEOPLE[0].email, REPLAY_PEOPLE[0].phone];
  const clean = (v) => typeof v === "string" && !idents.some((x) => v.includes(x));
  ok("replay: thinking text, its signature and tool ids are filled with neutral words, never identifiers", clean(think) && clean(sig) && clean(id), `${String(think).slice(0, 30)} | ${sig.slice(0, 30)} | ${id.slice(0, 30)}`);
  const prose = `${tfilled.messages[0].content} ${JSON.stringify(tfilled.messages[1].content[1].input)} ${tfilled.messages[2].content[0].content}`;
  ok("replay: the identifiers still go into the message text, the tool input or the tool result", idents.some((x) => prose.includes(x)), prose.slice(0, 80));
  const tr = replayShapes([{ ts: 0, h: shapeDigest("anthropic", "messages", tshape), provider: "anthropic", dialect: "messages", shape: tshape }]);
  ok(`replay: a thinking-block agent turn neither leaks nor refuses (${tr.runs} runs)`, tr.failures.length === 0, tr.failures.slice(0, 3).map((f) => `${f.check} p${f.person} ${f.where}`).join(" ;; "));

  // The opaque names are protocol positions only: below a tool call's arguments an `id` is the
  // caller's own field and carries identifiers like any other argument.
  const argShape = { type: "tool_use", id: { $s: 32 }, name: { $tool: "0badc0de" }, input: { id: { $s: 64 }, signature: { $s: 64 } } };
  const argFilled = instantiate(argShape, REPLAY_PEOPLE[0], "identifiers", () => 2);
  ok("replay: a tool argument named id gets identifiers, the call's own id does not", !clean(argFilled.input.id) && !clean(argFilled.input.signature) && clean(argFilled.id), `${argFilled.input.id.slice(0, 40)} | ${argFilled.id.slice(0, 30)}`);
}

console.log(`\nshapes: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
