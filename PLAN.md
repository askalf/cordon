# cordon — a PII-redacting LLM compliance gateway

> Snapshot of the approved build plan (canonical copy lives in the Claude Code plans dir). This in-repo copy exists so cloud plan-refinement has it as repo context.

> Name: **`cordon`** (locked) — "a cordon around your sensitive data," matching the warden/keeper/canon security family. Still kept in one constant (`config.brand`) rather than hardcoded like deja does. Tagline: **"own your prompts — PII never leaves your perimeter."**

## Context

The studio's "Own Your Stack" portfolio already ships `deja` ("own your LLM cache") and the agent-security trilogy `warden`/`canon`/`keeper`. The missing piece for **highly sensitive / regulated clients** is a drop-in gateway that sits between any app and the LLM provider and guarantees **raw PII/PHI/PCI/secrets never reach the model** — while keeping the model's answer usable. This is both a real compliance product (the wedge: "your data never leaves the building") and a showable OSS tool that pitches into healthcare, fintech, and any enterprise nervous about what employees paste into AI.

It is architecturally a **near-mirror of `deja`** with the spine inverted: deja reads a cache and **fails open** (a miss is harmless); cordon **mutates the request body** to strip PII and **fails closed** (a detection error must block, never leak). ~70% of deja's skeleton (Fastify bootstrap, provider normalize/forward, SSE tee, per-tenant policy, metrics/dashboard/admin, Docker deploy, test harness) is reused.

### Locked decisions (from clarifying Qs)
1. **Output = both modes, policy-selectable.** `reversible` (de-identify → forward → restore real values in the response; default-on demo experience) and `strip` (irreversible placeholders; hardened mode). Chosen per-tenant policy or per-request `X-Redact-Mode` header.
2. **Detection = deterministic core first.** Regex + checksum validators only (zero ML deps, 100% auditable). A clean `Detector` interface is exposed so a Presidio/NER sidecar drops in later (Phase 5, **not now**) without touching the spine.
3. **Catalog = broad, tagged by regime.** One superset entity catalog (PII + PHI + PCI + secrets), each type tagged `hipaa|gdpr|pci|secret`; policy selects active sets.

## Where it lives
New standalone repo at **`Desktop\cordon`** (sibling to `Desktop\deja`), its own package/README/Docker — matching the one-repo-per-tool portfolio pattern.

## Architecture (mirrors deja `src/`)

```
client ──▶ cordon ──▶ OpenAI / Anthropic
            │  1. detect PII (deterministic spans)
            │  2. redact/tokenize body  (ephemeral per-request vault)
            │  3. forward DE-IDENTIFIED body upstream   ← model never sees raw PII
            │  4. reversible? restore real values in the response (incl. streaming)
            └─ audit: hash-chained log of COUNTS/TYPES (never values), fail-CLOSED
```

### The spine — `src/proxy.ts` (rewrite of deja's; the inversion)
```
handle(r, res):
  policy = getPolicy(r.tenant); mode = header(X-Redact-Mode) ?? policy.mode
  if mode==='off' or non-redactable per policy → passthrough verbatim (audited as bypass)
  spans = detect(textFields(r), policy.activeSets)        // throws → failClosed(res): 4xx, DO NOT forward
  vault = new Vault(mode, tenantSecret)
  deidBody = applyRedaction(r.raw, spans, vault)          // rebuilt provider body w/ placeholders
  audit.append({tenant, model, mode, countsByType, regimes})   // NEVER values
  up = forwardUpstream({...r, raw: deidBody})
  if !up.ok → pipe sanitized error (no real PII exists to leak)
  if r.stream → captureAndReidentify(up.body, res, adapter, vault, mode)   // hard part
  else        → res.end( mode==='reversible' ? reidentifyBody(await up.json(), vault) : body )
```
Key inversion vs deja: **fail-closed** (`FAIL_MODE=closed` default; detector/vault error ⇒ no upstream call) and **body mutation** (deja forwards `r.raw` verbatim; cordon forwards a de-identified copy).

### Files — reuse vs new
| File | Origin |
|---|---|
| `src/index.ts` | **Adapt deja** — Fastify, custom JSON parser, `/healthz` `/metrics` `/dashboard`, admin gate (`adminOk`), `/v1/*` POST → `reqParts`→`normalize`→`reply.hijack()`→`handle(creq, reply.raw)`, `safeError`, `passthroughUnknown`. |
| `src/providers.ts` | **Adapt deja** — reuse `normalize()`, `resolveTenant()`, `authHeaders()`, `forwardUpstream/forwardRaw`, `adapterFor`, and the OpenAI/Anthropic adapters' `parseDelta` (to read text deltas). **Add** the inverse `frameFromText(textDelta)` per provider for re-emitting transformed stream frames, and a per-tenant `upstream` override (data-residency routing). |
| `src/types.ts` | **Adapt deja** — keep `CanonicalRequest`, `HttpRes`, `Provider`, `Msg`. Add `Span {start,end,type,value,regime[]}`, `RedactMode`, `Vault` types. |
| `src/config.ts` | **Adapt deja** — flat env object: `port`, `brand`, `upstream.*`, `failMode`, `defaultMode`, `activeSets`, `tenantSecret`, `auditLog`, `admin.token`, `tenantFromAuth`. |
| `src/proxy.ts` | **Rewrite** — the inverted spine above. |
| `src/streaming.ts` | **Rewrite/extend deja's `captureAndForward`** — tee **and** re-identify in flight (see "hard part"). `strip` mode forwards verbatim (deja's path unchanged). |
| `src/detect/patterns.ts` | **New** — regex catalog, each `{type, regime[], regex, validate?}`: EMAIL, PHONE, SSN, CREDIT_CARD, IBAN, US_ROUTING, IPV4/6, MAC, DOB/DATE, street-address heuristic, etc. |
| `src/detect/validators.ts` | **New** — Luhn (cards), mod-97 (IBAN), ABA (routing), SSN-area — cut false positives (redacting the wrong token corrupts output). |
| `src/detect/secrets.ts` | **New, reuse `dario/src/redact.ts`** patterns (`sk-ant-…`, JWT triple, `Bearer …`) + cloud keys (`AKIA…`, `ghp_…`) — stops credential leakage into prompts. |
| `src/detect/index.ts` | **New** — `Detector` interface + `runAll(text, activeSets)`: run active detectors, **merge/dedupe overlapping spans** (longest/priority wins so a card # isn't also matched as phone), return sorted. This interface is the NER plug-in seam. |
| `src/redact/vault.ts` | **New** — per-request ephemeral `value↔placeholder` map; `<TYPE_N>` (reversible) / `[TYPE]` (strip); consistent within a request. Optional `consistentPseudonyms`: placeholder = `HMAC(tenantSecret, value)` (same person→same token across requests, **value never stored**). Discarded at request end; never persisted. |
| `src/redact/apply.ts` | **New** — walk provider body text fields (OpenAI `messages[].content` string\|array; Anthropic `system` + `messages[].content` blocks + `tool_result`), replace spans **right-to-left** (offset-safe), leave images/tool schemas untouched. Returns `{deidBody, vault}`. |
| `src/redact/reidentify.ts` | **New** — full-body restore (walk response text fields) + the **streaming** boundary-safe restorer. |
| `src/policy.ts` | **Adapt deja** — per-tenant `{mode, activeSets, failMode, consistentPseudonyms, upstreamOverride}` + admin setter. |
| `src/audit.ts` | **New, small** — append-only JSONL, `hash = sha256(prevHash + canonicalJSON(record))`; record = `{ts,tenant,model,mode,provider,entityCounts,regimes,prevHash,hash}`, **never values**. `verify()` walks the chain → tamper report (mirrors keeper/warden `./audit`). |
| `src/metrics.ts`, `src/dashboard.ts`, `src/util.ts` | **Adapt deja** — metrics: redactions by type, mode mix, fail-closed count. dashboard: same single-file ops view. util: `sha256`, add `hmac`, keep `withTimeout`/`nowMs`. |
| root: `package.json` `tsconfig.json` `Dockerfile` `docker-compose.yml` `.env.example` `.gitignore` `deploy.sh` `_run_tests.mjs` `README.md` | **Adapt deja** — same dev/start/test scripts, Fastify dep, optional ioredis; compose `cordon` (+optional redis), localhost-bound; `deploy.sh` clone/pull/build/healthcheck. |

### The hard part — streaming re-identification (`reversible` only)
Restored values must replace placeholders (`/<[A-Z_]+_\d+>/`) that can be **split across SSE frames / token deltas** (`<EMA` … `IL_1>`). Solution = **hold-back buffer**:
- Per stream, keep a rolling assistant-text buffer. On each upstream frame: `parseDelta` → text; append to buffer.
- Flush everything up to the last **unclosed `<`** (a `<` with no following `>` yet could be a forming placeholder); replace complete placeholders in the flushed portion via the vault; re-emit as a provider-correct frame via `frameFromText`. Hold the tail.
- On `message_stop`/`[DONE]`: flush remainder (replace any complete placeholders; leave a stray partial as-is). Non-text frames (`message_start`, usage, `stop`) pass through unchanged.
- Token/usage counts stay upstream's (computed on de-identified text) — correct and documented.

### Caller controls (mirror deja's `X-Cache-*`)
`X-Redact-Mode: reversible|strip|off` · `X-Redact-Sets: pii,phi,pci,secrets` · `X-Tenant`. Response: `X-Redacted: <n>`, `X-Redacted-Types: EMAIL:2,SSN:1` (counts only). Auth (`authorization`/`x-api-key`/`anthropic-version`) forwarded verbatim — cordon never terminates provider auth.

## Build phases (all v1; each independently shippable)
- **P0 Skeleton** — Fastify proxy, normalize/forward/passthrough, config/types, `/healthz` `/metrics`, fail-closed plumbing (transparent forward, no redaction yet).
- **P1 Detect + strip + audit** — deterministic catalog + validators + secrets; `strip` mode; hash-chained audit. *Shippable compliance product on its own.*
- **P2 Reversible (non-stream)** — vault + `apply` + full-body `reidentify`; round-trip restore.
- **P3 Streaming re-identify** — the hold-back buffer (the novel piece).
- **P4 Polish** — per-tenant policy, admin API, dashboard, consistent-pseudonyms, data-residency upstream override, Docker/compose/deploy, README, full test battery.
- **P5 (LATER, not now)** — NER sidecar implementing `Detector` over HTTP. Interface ships in P1; sidecar deferred per decision #2.

## Verification (end-to-end)
Mirror deja's harness: `_run_tests.mjs` spawns a **stub upstream that echoes the body it received** so tests assert the model **never saw raw PII**.
1. `npm install && npm run dev` → cordon on `:8080`.
2. Manual proof (reversible):
   ```
   curl :8080/v1/messages -H 'x-api-key: $K' -H 'anthropic-version: 2023-06-01' \
     -d '{"model":"claude-haiku-4-5","messages":[{"role":"user","content":"email john@acme.com re card 4012-8888-8888-1881"}]}'
   ```
   Assert: stub upstream logged `<EMAIL_1> … <CC_1>` (no raw values); client response has real values restored; resp headers show `X-Redacted-Types: EMAIL:1,CREDIT_CARD:1`.
3. `npm test` suites: **detect** (each pattern hits; Luhn/mod-97 reject false positives) · **apply** (string + content-array bodies de-identified, structure preserved, images untouched) · **reversible round-trip** · **streaming re-identify** (placeholder split across a frame boundary still restored — the critical test) · **strip** (no vault, placeholders persist, stream verbatim) · **fail-closed** (detector error ⇒ stub upstream **never called**, error returned) · **audit** (chain verifies; tamper detected; grep log proves **no values**) · **passthrough** (`count_tokens`/`models` forwarded verbatim).
4. `docker compose up -d --build` → `curl :8080/healthz` ok; `/dashboard` shows redaction counts.

## Open (non-blocking)
- **Name** — locked: **cordon**. Kept centralized in `config.brand` regardless.
- Publishing (PUBLIC repo / npm / OYS profile listing) follows the deja playbook **after** local build + tests pass.
