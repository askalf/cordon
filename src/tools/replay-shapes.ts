// CLI: replay the recorded request shapes with invented people.
//   npm run replay:shapes              # the shapes in $SHAPE_LOG
//   npm run replay:shapes -- file.jsonl
// Prints a summary and every failure (shape digest, person, check, where: no text). Exits 1 on
// any failure, 0 otherwise (including when no shape has been recorded yet).
import { readFileSync } from "node:fs";
import { config } from "../config";
import { replayShapes, REPLAY_PEOPLE } from "../replay";
import type { ShapeRecord } from "../shapes";

const file = process.argv[2] || config.shapeLog;
if (!file) {
  console.error("replay-shapes: no file given and SHAPE_LOG is not set");
  process.exit(2);
}
let records: ShapeRecord[] = [];
try {
  records = readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as ShapeRecord);
} catch (e) {
  if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
}
if (!records.length) {
  console.log(`replay-shapes: no shapes in ${file} yet`);
  process.exit(0);
}
const { runs, failures } = replayShapes(records);
console.log(`replay-shapes: ${records.length} shape(s) x ${REPLAY_PEOPLE.length} people x 2 fills = ${runs} runs, ${failures.length} failed`);
for (const f of failures.slice(0, 50)) console.log(`  FAIL ${f.check} shape=${f.h} ${f.provider}/${f.dialect || "-"} person=${f.person} ${f.where}`);
process.exit(failures.length ? 1 : 0);
