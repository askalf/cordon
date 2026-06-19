// CLI: verify the hash-chained audit log and print a tamper report.
//   npm run audit            # verify ./audit.jsonl (or $AUDIT_LOG)
import { audit } from "../audit";
import { config } from "../config";

(async () => {
  const r = await audit.verify();
  if (r.ok) {
    console.log(`${config.brand}: audit chain OK — ${r.records} record(s) in ${config.auditLog}`);
    process.exit(0);
  }
  console.error(
    `${config.brand}: audit chain BROKEN at record ${r.brokenAt} (${r.reason}) in ${config.auditLog}`,
  );
  process.exit(1);
})();
