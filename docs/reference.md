# cordon reference

Back to the [README](../README.md).

## A full round trip

Both client shapes, pointed at cordon instead of the provider:

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
- **Tenant identity**: derived from the API key (`TENANT_FROM_AUTH`, default on), else `public`. `X-Tenant` is ignored unless `TRUST_TENANT_HEADER=true`. When it is honoured it may only select a tenant whose policy is at least as strict as the caller's own on every knob: `mode` (`off` < `reversible` < `strip`), `activeSets` (a superset), `failMode` (`open` < `closed`), `redactSystem` (`false` < `true`), `consistentPseudonyms` (`true` < `false`, since a stable token lets the provider link a value across requests), `allowHeaderOverride` (`true` < `false`), and the same upstream bases (a residency route has no stricter direction). Anything else is refused with 403 before the upstream is called. A tenant that differs in a looser or residency setting is reached by giving its callers their own API key and setting the policy on the key-derived tenant (`auth:` plus the first 16 hex characters of the key's SHA-256). The header also sets the tenant name in the audit log and metrics, which is the trust the setting grants.
- **Per-request headers can only tighten**: `X-Redact-Mode` must be at least as strong as the policy mode (`off` < `reversible` < `strip`) and `X-Redact-Sets` must include every policy set. Anything weaker is refused with 403 before the upstream is called. `"allowHeaderOverride": true` on a tenant (or `ALLOW_HEADER_OVERRIDE=true` globally) restores per-request loosening.

## Known subjects

`X-Cordon-Subject` is base64url JSON: `{"ref"?: string (up to 128), "media"?: "block" | "allow", "subjects": [{ "names"?, "emails"?, "phones"?, "addresses"?, "dates"?, "ids"?, "handles"?, "other"?: string[] }]}`, at most 12 KB encoded, 8 subjects, 32 strings of up to 200 characters per list. Anything else is a 400 before the upstream is called. Identifiers too short to match safely are dropped (a phone under 7 digits, an ID under 4 characters).

Tenant policy fields:

```bash
curl localhost:8080/admin/tenant -H 'x-admin-token: …' -H 'content-type: application/json' \
  -d '{"tenant":"auth:…","requireSubject":true,"subjectMedia":"block","reportOnly":false}'
```

- `requireSubject`: refuse any generation request without the header (400).
- `subjectMedia`: `"block"` (default), `"mask"` or `"allow"`; the stricter of this and the header's `media` applies. In `mask` mode each image (PNG, JPEG, WebP, GIF; up to 10 per request and 30 megapixels each, 30 seconds per read) is read, masked, re-read and sent as PNG; mask counts are added to the record as `IMAGE_<TYPE>`.
- `reportOnly`: forward unchanged and record the verdict (`X-Cordon-Report: redact=<n>; egress=<verdict>`, audit `report: true`).

All three take part in the X-Tenant strictness rule: a looser setting cannot be selected by header.

Audit records of subject requests add `subject` (a digest of the ref, keyed by `TENANT_SECRET`), `egress` (`verified`, `egress` or `media`) and `media` (a count). Records without them hash exactly as before, so older logs still verify.

```bash
curl 'localhost:8080/admin/receipts?ref=case-1042' -H 'x-admin-token: …'
# {"subject":"…","chain":{"ok":true,"records":…},"receipts":[{ts, entityCounts, total, egress, media, hash, …}]}
```

The chain is verified before receipts are served; a broken chain is a 409 with no receipts. Metrics add `subjectBlocked` (refusals by stage).

## Ops endpoints

`GET /healthz`, `GET /metrics` (and `/metrics.prom`), `GET /dashboard` (single-file view of redactions by type, mode and set mix, fail-closed count, tenant policies, audit-chain status), `GET /admin/stats`. Admin routes require `x-admin-token`; with `ADMIN_TOKEN` unset they are disabled (403). `ALLOW_OPEN_ADMIN=1` serves them with no auth, for local dev only.

Upstream failures return a fixed message and a `requestId` (also in `X-Request-Id`); the detail is logged server-side. A provider that sends no response headers within `UPSTREAM_TIMEOUT_MS` (default 600000) gets a 504; a stream that has started is never cut off.

## Configuration

See [`.env.example`](../.env.example). The knobs that matter: `FAIL_MODE` (default `closed`), `DEFAULT_MODE`, `ACTIVE_SETS`, `CONSISTENT_PSEUDONYMS` with `TENANT_SECRET`, `AUDIT_LOG`, `ADMIN_TOKEN`, `POLICY_STORE`, `OPENAI_BASE` / `ANTHROPIC_BASE`, `ALLOW_HEADER_OVERRIDE`, `TRUST_TENANT_HEADER`, `UPSTREAM_TIMEOUT_MS`, `CORDON_RESTORE_TOOLS`.

A response whose tool-call arguments hold a placeholder this request did not mint is refused: 502 with `X-Cordon-Unresolved: <count>` for a whole response, the dialect's error frame for a stream (code `cordon_unresolved_placeholder` on the OpenAI dialects, `api_error` on Messages).
