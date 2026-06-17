import { appendFile, readFile } from "node:fs/promises";
import { config } from "./config";
import { sha256, canonicalJSON, nowMs } from "./util";
import type { AuditRecord, Provider, RedactMode, RedactSet } from "./types";

// Append-only, hash-chained audit log. Each record's hash covers the previous hash,
// so any edit/deletion/reorder downstream breaks the chain and `verify()` reports it.
// Records carry COUNTS and TYPES only — never raw values. The genesis link is "0".

const GENESIS = "0";

export interface AuditInput {
  tenant: string;
  provider: Provider;
  model: string;
  mode: RedactMode;
  entityCounts: Record<string, number>;
  sets: RedactSet[];
  total: number;
}

/** The exact payload that gets hashed (record minus its own hash). */
const hashable = (r: Omit<AuditRecord, "hash">) =>
  canonicalJSON({
    ts: r.ts,
    tenant: r.tenant,
    provider: r.provider,
    model: r.model,
    mode: r.mode,
    entityCounts: r.entityCounts,
    sets: r.sets,
    total: r.total,
    prevHash: r.prevHash,
  });

const linkHash = (r: Omit<AuditRecord, "hash">) => sha256(r.prevHash + hashable(r));

class AuditLog {
  private prevHash: string | null = null; // null = not yet initialised from disk
  private tail: Promise<any> = Promise.resolve(); // serializes appends → consistent chain

  constructor(private readonly path: string) {}

  /** Lazily recover the chain head from the last line on disk. */
  private async ensureInit(): Promise<void> {
    if (this.prevHash !== null) return;
    try {
      const lines = (await readFile(this.path, "utf8")).split("\n").filter(Boolean);
      const last = lines.at(-1);
      this.prevHash = last ? (JSON.parse(last).hash as string) : GENESIS;
    } catch {
      this.prevHash = GENESIS; // no file yet
    }
  }

  /** Append one record. Resolves once the line is durably written. Throws on IO error
   *  so the spine can fail-closed (a compliance log that can't be written must block). */
  append(input: AuditInput): Promise<AuditRecord> {
    this.tail = this.tail.then(async () => {
      await this.ensureInit();
      const base: Omit<AuditRecord, "hash"> = {
        ts: nowMs(),
        tenant: input.tenant,
        provider: input.provider,
        model: input.model,
        mode: input.mode,
        entityCounts: input.entityCounts,
        sets: input.sets,
        total: input.total,
        prevHash: this.prevHash as string,
      };
      const record: AuditRecord = { ...base, hash: linkHash(base) };
      await appendFile(this.path, JSON.stringify(record) + "\n");
      this.prevHash = record.hash;
      return record;
    });
    return this.tail;
  }

  /** Walk the on-disk chain and report the first break (if any). */
  async verify(): Promise<{ ok: boolean; records: number; brokenAt?: number; reason?: string }> {
    let lines: string[];
    try {
      lines = (await readFile(this.path, "utf8")).split("\n").filter(Boolean);
    } catch {
      return { ok: true, records: 0 }; // no log = trivially intact
    }
    let prev = GENESIS;
    for (let i = 0; i < lines.length; i++) {
      let rec: AuditRecord;
      try {
        rec = JSON.parse(lines[i]);
      } catch {
        return { ok: false, records: lines.length, brokenAt: i, reason: "unparseable line" };
      }
      if (rec.prevHash !== prev)
        return { ok: false, records: lines.length, brokenAt: i, reason: "prevHash mismatch" };
      const { hash, ...rest } = rec;
      if (linkHash(rest) !== hash)
        return { ok: false, records: lines.length, brokenAt: i, reason: "hash mismatch" };
      prev = hash;
    }
    return { ok: true, records: lines.length };
  }
}

export const audit = new AuditLog(config.auditLog);
