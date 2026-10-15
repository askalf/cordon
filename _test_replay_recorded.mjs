// Replays the shapes the proxy suites' own traffic recorded (SHAPE_LOG=./_shapes_test.jsonl on the
// main test instance) with the replay CLI, as the box runs it against live shapes. Runs after the
// proxy suites in the battery.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";

let pass = 0;
let fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) pass++;
  else fail++;
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? `   (${detail})` : ""}`);
};

ok("recorded shapes: the proxy suites left a shape log", existsSync("./_shapes_test.jsonl"));
const r = spawnSync(process.execPath, ["--import", "tsx", "src/tools/replay-shapes.ts", "./_shapes_test.jsonl"], { encoding: "utf8" });
const out = `${r.stdout ?? ""}${r.stderr ?? ""}`.trim();
const m = /(\d+) shape\(s\)[^=]*= (\d+) runs, (\d+) failed/.exec(out);
ok("recorded shapes: replayed with invented people, nothing leaks or is refused", r.status === 0 && !!m && Number(m[3]) === 0, out.split("\n").slice(0, 6).join(" | "));
ok("recorded shapes: the log held a realistic spread of shapes", !!m && Number(m[1]) >= 10, m ? `${m[1]} shapes, ${m[2]} runs` : "no summary");

console.log(`\nrecorded shapes: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
