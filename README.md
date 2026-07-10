# cordon

[![ci](https://github.com/askalf/cordon/actions/workflows/ci.yml/badge.svg)](https://github.com/askalf/cordon/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/askalf/cordon/badge)](https://scorecard.dev/viewer/?uri=github.com/askalf/cordon)

> own your prompts — PII never leaves your perimeter.

A drop-in **LLM compliance gateway**. Point any OpenAI- or Anthropic-compatible client at cordon and raw PII / PHI / PCI / secrets are stripped or tokenized **before** the request reaches the model. In reversible mode the real values are restored in the model's reply, so the answer stays usable while the provider only ever sees placeholders. Self-hosted — your data never leaves your network.

```
client ──▶ cordon ──▶ OpenAI / Anthropic
            │  1. detect PII            (deterministic spans)
            │  2. redact / tokenize     (ephemeral per-request vault)
            │  3. forward de-identified body upstream   ← model never sees raw PII
            │  4. restore real values in the response   (reversible mode, incl. streaming)
            └─ audit: hash-chained log of counts/types (never values), fail-closed
```

## Why

The model — and everything downstream of it (provider logs, retention, subprocessors) — never sees the raw value. cordon sits between your app and the provider, so no client code changes: you only change the base URL. It is **fail-closed** — if detection errors, the request is **blocked**, never forwarded with PII intact.

## Quick start

```bash
npm install
npm run dev          # cordon on :8080
```

Point your client's base URL at cordon and send a normal request:

```bash
curl localhost:8080/v1/messages \
  -H 'content-type: application/json' \
  -H 'x-api-key: '"$ANTHROPIC_API_KEY" -H 'anthropic-version: 2023-06-01' \
  -d '{"model":"claude-haiku-4-5","messages":[{"role":"user",
       "content":"email john@acme.com re card 4012-8888-8888-1881"}]}'
```

What happens:

| | value |
|---|---|
| the **model** receives | `email <EMAIL_1> re card <CREDIT_CARD_1>` |
| the **client** receives | `email john@acme.com re card 4012-8888-8888-1881` *(restored)* |
| response headers | `X-Redacted: 2`, `X-Redacted-Types: EMAIL:1,CREDIT_CARD:1` |
| audit log | `{… entityCounts:{EMAIL:1,CREDIT_CARD:1}, total:2, prevHash, hash}` — **no values** |

## Modes

Selected per-tenant (policy) or per-request (`X-Redact-Mode` header):

- **`reversible`** *(default)* — de-identify upstream, restore the real values in the reply (including streaming). The answer stays usable; the provider only ever sees placeholders.
- **`strip`** — irreversible placeholders (`[EMAIL]`); nothing is restored. Hardened mode for when the answer never needs the real value back.
- **`off`** — transparent passthrough (still audited as a bypass).

## Detection

Deterministic by design — **regex + checksum validators, zero ML dependencies, fully auditable.** A wrong redaction corrupts the prompt, so every entity with a check digit is validated before its span is accepted (Luhn for cards, ISO 7064 mod-97 for IBANs, ABA for routing numbers, SSN area/group rules). Overlapping matches are resolved by precedence so a 16-digit card isn't also clipped as a phone number.

**Catalog** (each type tagged with the set it belongs to):

| set | entities |
|---|---|
| `pii` | EMAIL, PHONE, SSN, IPV4, IPV6, MAC, STREET_ADDRESS |
| `phi` | MRN, DATE *(+ SSN)* |
| `pci` | CREDIT_CARD, IBAN, US_ROUTING |
| `secrets` | OpenAI / Anthropic / AWS / GitHub / Google / Slack keys, JWTs, Bearer tokens, PEM private keys |

Active sets default to all four; override per-tenant or with `X-Redact-Sets: pii,pci,secrets`.

The detector is a clean interface (`src/detect`), so an optional NER/Presidio sidecar can be slotted in later without touching the proxy spine — it is **not** included here (deterministic core only).

## Caller controls

Request headers:

- `X-Redact-Mode: reversible | strip | off`
- `X-Redact-Sets: pii,phi,pci,secrets`
- `X-Tenant: <id>` *(else derived from the API key)*

Response headers: `X-Redacted: <n>`, `X-Redacted-Types: EMAIL:2,SSN:1` (counts only), `X-Redact-Mode`.

Provider auth (`authorization` / `x-api-key` / `anthropic-version`) is forwarded **verbatim** — cordon never terminates provider auth.

## Audit

Every request appends one record to a hash-chained JSONL log (`AUDIT_LOG`): `{ts, tenant, provider, model, mode, entityCounts, sets, total, prevHash, hash}` where `hash = sha256(prevHash + canonicalJSON(record))`. **Records carry counts and types only — never raw values.** Any edit, deletion, or reorder breaks the chain.

```bash
npm run audit                         # verify the chain → tamper report
curl localhost:8080/admin/audit/verify -H 'x-admin-token: …'
```

## Per-tenant policy & admin

```bash
# default mode/sets, fail-mode, stable pseudonyms, and data-residency routing per tenant
curl localhost:8080/admin/tenant -H 'x-admin-token: …' -H 'content-type: application/json' \
  -d '{"tenant":"acme","mode":"reversible","activeSets":["pii","pci"],
       "consistentPseudonyms":true,"upstreamOverride":{"anthropic":"https://eu.anthropic.example"}}'
```

- **Consistent pseudonyms** — `<EMAIL_3F2A…>` derived as `HMAC(TENANT_SECRET, value)`, so the same person maps to the same token across requests (the model can correlate) while the value is never stored.
- **Data-residency override** — route a tenant's traffic to a specific regional upstream base.

Ops endpoints: `GET /healthz`, `GET /metrics` (+ `/metrics.prom`), `GET /dashboard` (single-file ops view: redactions by type, mode mix, set mix, fail-closed count, tenant policies, audit-chain status), `GET /admin/stats`. Admin routes require `x-admin-token` when `ADMIN_TOKEN` is set (open in dev).

## Configuration

See [`.env.example`](./.env.example). Key knobs: `FAIL_MODE` (default `closed`), `DEFAULT_MODE`, `ACTIVE_SETS`, `CONSISTENT_PSEUDONYMS` + `TENANT_SECRET`, `AUDIT_LOG`, `ADMIN_TOKEN`, `OPENAI_BASE` / `ANTHROPIC_BASE`.

## Deploy

cordon keeps no cache and no shared state (the vault is per-request and ephemeral, policy is in-memory, the audit log is a local file), so it runs as a single self-contained container — no Redis/DB sidecar.

```bash
docker compose up -d --build      # cordon on 127.0.0.1:8080, audit log persisted to a volume
./deploy.sh                       # idempotent clone/pull/build/healthcheck to a remote box
```

## Tests

```bash
npm test
```

A stub upstream **echoes the body it received**, so the suites assert the model never saw raw PII while the client still gets restored values:

- **detect** — every pattern fires; Luhn / mod-97 / ABA reject false positives; set gating; overlap resolution.
- **apply** — string + content-array bodies de-identified, structure preserved, images untouched; reversible round-trip.
- **streaming re-identify** — a placeholder split across a frame boundary is still restored (the critical case).
- **strip / off / fail-closed** — strip persists placeholders; off passes through; a detection error blocks and the **upstream is never called**.
- **audit** — the chain verifies, tampering is detected, and the log is proven to contain **no values**.
- **passthrough** — `count_tokens` and other non-generation paths forward verbatim.

## Scope

cordon currently redacts the two generation endpoints (`/v1/chat/completions`, `/v1/messages`); other `/v1/*` paths (e.g. `count_tokens`, `embeddings`) pass through verbatim. Streaming token/usage counts are the upstream's (computed on the de-identified text).

## The agent-security stack

cordon — **own your prompts** — is a standalone **[Own Your Stack](https://github.com/askalf)** tool. The core agent-security stack is the trio that guards a tool call — **[redstamp](https://github.com/askalf/redstamp)** contains the call · **[truecopy](https://github.com/askalf/truecopy)** vets the tool · **[strongroom](https://github.com/askalf/strongroom)** holds the keys (**[agent-security-stack](https://github.com/askalf/agent-security-stack)**) — with **[fieldpass](https://github.com/askalf/fieldpass)** governing the browser. cordon strips PII/secrets out of the prompt before it ever reaches the model.

---
Part of the [Own Your Stack](https://sprayberrylabs.com/own-your-stack) portfolio.
