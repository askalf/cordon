# cordon

[![ci](https://github.com/askalf/cordon/actions/workflows/ci.yml/badge.svg)](https://github.com/askalf/cordon/actions/workflows/ci.yml)
[![codeql](https://github.com/askalf/cordon/actions/workflows/codeql.yml/badge.svg)](https://github.com/askalf/cordon/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/askalf/cordon/badge)](https://scorecard.dev/viewer/?uri=github.com/askalf/cordon)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A PII-redacting proxy for the OpenAI and Anthropic APIs.** Point your client at cordon instead of the provider. Emails, phone numbers, card numbers, SSNs, API keys and the rest are replaced with placeholders before the request leaves your network, and put back in the reply so your app never notices. One container, no database, no ML model, no client code changes beyond the base URL.

```
your app ──▶ cordon ──▶ api.openai.com / api.anthropic.com
              │
              ├─ model receives:    email <EMAIL_5285D1_1> re card <CREDIT_CARD_5285D1_1>
              └─ your app receives: email john@acme.com re card 4012-8888-8888-1881
```

## Run it

```bash
docker run -d --name cordon --init -p 127.0.0.1:8080:8080 \
  -v cordon-data:/app/data -e ADMIN_TOKEN=change-me \
  ghcr.io/askalf/cordon:v0.2.0
```

Then change one thing in your client: the base URL.

```bash
# Anthropic client: base URL http://localhost:8080 (was https://api.anthropic.com)
curl localhost:8080/v1/messages \
  -H 'content-type: application/json' \
  -H "x-api-key: $ANTHROPIC_API_KEY" -H 'anthropic-version: 2023-06-01' \
  -d '{"model":"claude-haiku-4-5","max_tokens":64,"messages":[{"role":"user",
       "content":"email john@acme.com re card 4012-8888-8888-1881"}]}'
```

```bash
# OpenAI client: base URL http://localhost:8080/v1 (was https://api.openai.com/v1)
curl localhost:8080/v1/chat/completions \
  -H 'content-type: application/json' -H "authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user",
       "content":"email john@acme.com re card 4012-8888-8888-1881"}]}'
```

Your provider key goes through untouched; cordon never holds it. What comes back, captured from the published image:

```
HTTP/1.1 200 OK
X-Redact-Mode: reversible
X-Redacted: 2
X-Redacted-Types: EMAIL:1,CREDIT_CARD:1

{"content":[{"type":"text","text":"email john@acme.com re card 4012-8888-8888-1881"}], ...}
```

What the provider was sent:

```
"content":"email <EMAIL_5285D1_1> re card <CREDIT_CARD_5285D1_1>"
```

The line appended to the audit log (counts and types, never values):

```json
{"ts":1790043464004,"tenant":"auth:cdba95a3…","provider":"anthropic","model":"claude-haiku-4-5",
 "mode":"reversible","entityCounts":{"EMAIL":1,"CREDIT_CARD":1},"total":2,"prevHash":"0","hash":"7b6e07…"}
```

## What it catches

Deterministic detection: regex plus checksum validators, no ML dependencies, fully auditable. Every entity with a check digit is validated before its span is accepted (Luhn for cards, ISO 7064 mod-97 for IBANs, ABA for routing numbers, SSN area/group rules), and overlapping matches resolve by precedence so a 16-digit card is not also clipped as a phone number.

| set | entities |
|---|---|
| `pii` | EMAIL, PHONE, SSN, IPV4, IPV6, MAC, STREET_ADDRESS |
| `phi` | MRN, DATE *(and SSN)* |
| `pci` | CREDIT_CARD, IBAN, US_ROUTING |
| `secrets` | OpenAI / Anthropic / AWS / GitHub / Google / Slack keys, JWTs, Bearer tokens, PEM private keys |

All four sets are on by default; narrow per tenant or per request with `X-Redact-Sets: pii,pci`.

## What it does not do

- **Names, free-text addresses, medical conditions.** There is no NER. A person's name in prose passes through. The detector is an interface (`src/detect`), so a Presidio-style sidecar can be added; it is not included.
- **Embeddings, `count_tokens`, images.** Only the three generation endpoints (`/v1/chat/completions`, `/v1/responses`, `/v1/messages`) are redacted; other `/v1/*` paths, including `/v1/responses/{id}`, pass through verbatim. Image and file parts are left untouched.
- **Token counts.** Streaming usage figures are the provider's, computed on the de-identified text.

If you need one of those, say so in an issue. The scope above is deliberate, not accidental.

## Modes

Per tenant (policy) or per request (`X-Redact-Mode` header):

- **`reversible`** *(default)*: placeholders go up, real values come back in the reply, including mid-stream. Tokens carry a per-request random nonce (`<EMAIL_5285D1_1>`, not `<EMAIL_1>`) so a caller's own placeholder-shaped text can never be rewritten to a real value.
- **`strip`**: irreversible placeholders (`[EMAIL]`); nothing is restored. For when the answer never needs the real value.
- **`off`**: passthrough, still audited as a bypass.

```
X-Redact-Mode: strip   →   "text":"email [EMAIL] re card [CREDIT_CARD]"
```

## Fail closed

If detection throws, the request is **blocked**, never forwarded with PII intact (`FAIL_MODE=closed`, the default). The test suite asserts the upstream is never called on that path.

## Audit

Every request appends one record to a hash-chained JSONL log (`AUDIT_LOG`): `{ts, tenant, provider, model, mode, entityCounts, sets, total, prevHash, hash}` with `hash = sha256(prevHash + canonicalJSON(record))`. Records carry counts and types only. Any edit, deletion or reorder breaks the chain.

```bash
npm run audit                                   # verify the chain, print a tamper report
curl localhost:8080/admin/audit/verify -H 'x-admin-token: …'
```

## Per-tenant policy

```bash
curl localhost:8080/admin/tenant -H 'x-admin-token: …' -H 'content-type: application/json' \
  -d '{"tenant":"acme","mode":"reversible","activeSets":["pii","pci"],
       "consistentPseudonyms":true,"upstreamOverride":{"anthropic":"https://eu.anthropic.example"}}'
```

- **Consistent pseudonyms**: `<EMAIL_3F2A…>` derived as `HMAC(TENANT_SECRET, value)`, so the same person maps to the same token across requests (the model can correlate) while the value is never stored. Requires a strong `TENANT_SECRET` (16+ chars); this mode fails closed without one. `ALLOW_WEAK_PSEUDONYM_SECRET=1` overrides for dev only.
- **Data residency**: route a tenant to a regional upstream base.
- **Durable policy**: `POLICY_STORE=./policies.json` persists tenant policy across restarts on the same volume as the audit log; unset keeps it in memory.
- **Tenant identity**: `X-Tenant: <id>`, else derived from the API key.

Ops: `GET /healthz`, `GET /metrics` (and `/metrics.prom`), `GET /dashboard` (single-file view of redactions by type, mode and set mix, fail-closed count, tenant policies, audit-chain status), `GET /admin/stats`. Admin routes require `x-admin-token` when `ADMIN_TOKEN` is set.

## Configuration

See [`.env.example`](./.env.example). The knobs that matter: `FAIL_MODE` (default `closed`), `DEFAULT_MODE`, `ACTIVE_SETS`, `CONSISTENT_PSEUDONYMS` with `TENANT_SECRET`, `AUDIT_LOG`, `ADMIN_TOKEN`, `POLICY_STORE`, `OPENAI_BASE` / `ANTHROPIC_BASE`.

## Deploy

No cache, no shared state: the vault is per request and ephemeral, policy is a JSON file, the audit log is a local file. One container, no Redis or database.

```bash
docker compose up -d --build      # from a clone: cordon on 127.0.0.1:8080, audit log on a volume
./deploy.sh                       # idempotent clone/pull/build/healthcheck to a remote box
```

Every tagged release publishes a multi-arch image (linux/amd64, linux/arm64) to GHCR with keyless Sigstore provenance and an SBOM. Verify it came from this repository's release workflow:

```bash
gh attestation verify oci://ghcr.io/askalf/cordon:v0.2.0 --repo askalf/cordon
```

Sharing one Claude or ChatGPT subscription through [dario](https://github.com/askalf/dario) without leaking PII: dario's [cordon integration guide](https://github.com/askalf/dario/blob/main/docs/integrations/cordon.md).

## Development

```bash
npm install
npm run dev          # cordon on :8080 from source
npm test
```

The test suite runs against a stub upstream that echoes the body it received, so every suite asserts two things at once: the model never saw raw PII, and the client still got the real values back.

- **detect**: every pattern fires; Luhn / mod-97 / ABA reject false positives; set gating; overlap resolution.
- **apply**: string and content-array bodies de-identified with structure preserved, images untouched; reversible round trip.
- **streaming**: a placeholder split across a frame boundary is still restored.
- **strip / off / fail-closed**: strip persists placeholders; off passes through; a detection error blocks and the upstream is never called.
- **audit**: the chain verifies, tampering is detected, the log is proven to contain no values.
- **passthrough**: `count_tokens` and other non-generation paths forward verbatim.

## Part of Own Your Stack

cordon guards the prompt. The rest of the [Own Your Stack](https://sprayberrylabs.com/own-your-stack) tools guard the agent around it: [redstamp](https://github.com/askalf/redstamp) contains the tool call, [truecopy](https://github.com/askalf/truecopy) vets the tool before it is installed, [browser-bridge](https://github.com/askalf/browser-bridge) governs the browser, and [plumbline](https://github.com/askalf/plumbline) watches the whole action sequence against the declared job. cordon and plumbline sit beside that path rather than in it.
