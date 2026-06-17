export type Provider = "openai" | "anthropic";

export interface Msg {
  role: string;
  content: any;
}

export interface Tool {
  name: string;
  [k: string]: any;
}

/** Output handling for detected entities. */
export type RedactMode = "reversible" | "strip" | "off";

/**
 * Selectable entity groupings. A request's `activeSets` (policy or X-Redact-Sets)
 * decides which catalog entries run. Each catalog entry declares the set(s) it
 * belongs to; the audit reports counts by type and which sets were active.
 *   pii     — emails, phones, IPs, addresses, names-ish        (GDPR)
 *   phi     — health identifiers + dates                       (HIPAA)
 *   pci     — card numbers, IBANs, bank routing                (PCI-DSS)
 *   secrets — API keys, tokens, private keys, JWTs
 */
export type RedactSet = "pii" | "phi" | "pci" | "secrets";

/** A detected entity span within a SINGLE text field (offsets are local to it). */
export interface Span {
  start: number; // inclusive
  end: number; // exclusive
  type: string; // EMAIL, SSN, CREDIT_CARD, AWS_KEY, …
  value: string; // the raw matched substring (the thing that must not leak)
  sets: RedactSet[]; // which active set(s) this entity belongs to
}

/** One catalog entry: a regex (+ optional checksum) that finds one entity type. */
export interface PatternDef {
  type: string;
  sets: RedactSet[];
  regex: RegExp; // MUST be created with the global flag
  /** Reject false positives (Luhn / mod-97 / ABA / SSN-area …). */
  validate?: (match: string) => boolean;
  /** Capture-group index whose range becomes the span (default: whole match). */
  group?: number;
  /** Higher wins when spans overlap; ties break on span length. Default 0. */
  priority?: number;
}

/**
 * The detector seam. The deterministic engine (`detect/index.ts`) implements this;
 * a later NER/Presidio sidecar can implement the same interface over HTTP without
 * touching the spine. `detect` works on ONE text field and returns local spans.
 */
export interface Detector {
  name: string;
  detect(text: string, activeSets: RedactSet[]): Span[];
}

export interface CanonicalRequest {
  provider: Provider;
  model: string;
  tenant: string;
  /** Resolved: X-Redact-Mode header > tenant policy > config.defaultMode. */
  mode: RedactMode;
  /** Resolved active sets: X-Redact-Sets > tenant policy > config.activeSets. */
  activeSets: RedactSet[];
  stream: boolean;
  /** Original upstream body. The spine forwards a DE-IDENTIFIED copy, never this. */
  raw: any;
  /** Auth + version headers passed through to the provider verbatim. */
  fwdHeaders: Record<string, string>;
  /** Original request path incl. query string — forwarded verbatim. */
  path: string;
  /** Bare path (no query). */
  bare: string;
  /** Test-only: forces a detection failure to exercise the fail-closed path. */
  testFail?: boolean;
}

/** Minimal surface cordon needs from a Node ServerResponse. */
export interface HttpRes {
  statusCode: number;
  setHeader(k: string, v: string): void;
  write(c: string): void;
  end(c?: string): void;
}

/** One append-only audit record. NEVER contains raw values. */
export interface AuditRecord {
  ts: number;
  tenant: string;
  provider: Provider;
  model: string;
  mode: RedactMode;
  /** entity type → count (e.g. { EMAIL: 2, SSN: 1 }). */
  entityCounts: Record<string, number>;
  /** which sets were active for this request. */
  sets: RedactSet[];
  /** total entities redacted. */
  total: number;
  prevHash: string;
  hash: string;
}
