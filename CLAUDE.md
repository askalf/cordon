# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

cordon is a **PII-redacting LLM compliance gateway** — a drop-in proxy that sits between an app and OpenAI/Anthropic and guarantees raw PII/PHI/PCI/secrets never reach the model. It runs TypeScript directly via `tsx` (no build step). Node 22+ (relies on global `fetch`, `structuredClone`, and the regex `d` flag).

It is architecturally a **near-mirror of the sibling `deja` repo** (`../deja`, an LLM caching proxy) with the spine inverted — see "Architecture" before changing the proxy/streaming/providers layers; many patterns (Fastify bootstrap, `reqParts`/hijack, adapter shape, test harness) come straight from deja.

## Commands

```bash
npm install
npm run dev          # tsx watch — cordon on :8080
npm start            # tsx, no watch
npm test             # full battery: spawns echo stub + a cordon instance, runs all suites
npm run typecheck    # tsc --noEmit
npm run audit        # verify the hash-chained audit log → tamper report (src/tools/audit.ts)
docker compose up -d --build   # single self-contained container, 127.0.0.1:8080
```

**Running one suite** (the runner `_run_tests.mjs` must already have the stub on :8900 and a cordon instance on :8810 up — easiest is to keep `npm test` as the entry point, but to iterate on a single suite, launch them by hand):

```bash
node _stub-upstream.mjs &                                                   # :8900
PORT=8810 OPENAI_BASE=http://localhost:8900 ANTHROPIC_BASE=http://localhost:8900 \
  ADMIN_TOKEN=secret AUDIT_LOG=./_audit_test.jsonl CORDON_TEST_HOOKS=1 \
  node --import tsx src/index.ts &                                          # :8810
node _test_proxy.mjs        # or _test_stream.mjs ; _test_unit.mjs needs `node --import tsx`
```

`_test_unit.mjs` imports `src/*.ts` directly so it runs under `node --import tsx`. The other two suites are plain `node` and talk to the running instance over HTTP.

## Architecture

### The inversion (vs deja)
deja **fails open** (a cache miss is harmless) and forwards the body **verbatim**. cordon **fails closed** (a detection error must block, never leak) and forwards a **de-identified copy**. When touching `proxy.ts`/`streaming.ts`/`providers.ts`, preserve these two invariants.

### Request lifecycle (`src/proxy.ts` is the spine)
`index.ts` (Fastify) normalizes the request, then `reply.hijack()`s and hands the raw Node response to `handle()`:

1. Resolve `mode` and `activeSets` (precedence: **request header → tenant policy → global config**; see `providers.normalize` + `policy.ts`).
2. `mode === "off"` → transparent passthrough, audited as a bypass.
3. **Detect + redact** inside a try/catch — this is the fail-closed boundary. `applyRedaction` (`redact/apply.ts`) clones the body, walks each text field, calls the `Detector`, and replaces spans with vault placeholders. Any throw here → `onRedactionError` → **422, upstream never called** (unless `failMode === "open"`, the dev escape hatch that forwards raw).
4. **Audit append BEFORE forwarding** (`audit.ts`) — counts/types only. In closed mode an audit write failure also blocks.
5. Forward the **de-identified body** upstream (`forwardUpstream(r, deidBody)`).
6. Relay the response: reversible mode re-identifies (full-body for JSON, streaming hold-back buffer for SSE); strip/off pipe verbatim.

### Detection is per-field, not whole-body
There is no global offset space. `applyRedaction` collects each redactable text field as a get/set **slot** (`requestTextSlots`), runs `detector.detect(text, activeSets)` on that field alone (offsets are local to it), and replaces spans **right-to-left** so earlier offsets stay valid. The `Vault` dedupes by value, so the same value gets the same placeholder across fields/requests.

- `detect/index.ts` (`runAll`) is the **NER plug-in seam** — it implements the `Detector` interface; a sidecar could replace it. It runs every catalog pattern, validates checksums, and resolves overlaps by **priority desc → length desc → start** (so a card isn't also clipped as a phone).
- `detect/patterns.ts` (PII/PHI/PCI) + `detect/secrets.ts` (keys/tokens) are the catalog; `detect/validators.ts` are Luhn/IBAN-mod97/ABA/SSN checks that reject false positives. A wrong redaction corrupts the prompt, so prefer adding a validator over loosening a regex.

### Vault & placeholders (`redact/vault.ts`)
Per-request, ephemeral, **never persisted** (not to disk, audit, or any cache). reversible → `<TYPE_<nonce>_N>` (or `<TYPE_HMAC8>` with consistent pseudonyms) + a reverse map; strip → `[TYPE]` (no reverse map). Placeholder grammar is matched liberally by `PLACEHOLDER_RE`; exact restoration is decided by the vault's reverse map, so over-matching is harmless. Counter tokens carry a **per-request random nonce** (uppercase hex, e.g. `<EMAIL_7F3A2B_1>`) so a caller's own placeholder-shaped text (e.g. asking "what does `<EMAIL_1>` mean?") can't collide with a minted token and get rewritten to a real value on restore — the caller can't know the nonce. Both the nonce and the consistent-pseudonym HMAC are **uppercase hex** specifically so tokens fit the `<[A-Z][A-Z0-9_]*>` grammar the streaming buffer relies on.

**Consistent pseudonyms fail closed without a secret.** `<TYPE_HMAC8>` = `HMAC(TENANT_SECRET, value)`; with no (or a `< 16`-char) secret the tokens are reproducible from the public source — a partial-PII leak. `config.pseudonymSecretGuard` blocks boot when it's the global default, and `proxy.handle` routes a per-request-enabled tenant through `onRedactionError` (**422, upstream never called**) unless `ALLOW_WEAK_PSEUDONYM_SECRET=1` (dev escape hatch). Never reintroduce a default-key fallback in `util.hmac`.

### Streaming re-identification (the hard part — `streaming.ts` + `redact/reidentify.ts`)
A placeholder can be split across SSE frames (`<EMA`…`IL_1>`). `StreamReidentifier` keeps a rolling buffer and only flushes up to the last `<` that could still be growing into a placeholder (`isFormingPlaceholder`); the tail is held until more text arrives, then flushed at the block close. `captureAndReidentify` suppresses upstream text frames and re-emits re-identified ones via `adapter.frameFromText`, forwarding structural frames (message_start, usage, finish, `[DONE]`) verbatim. The boundary-split test in `_test_stream.mjs` is the critical case (the stub deliberately chunks output by 3 chars).

### Audit chain (`audit.ts`)
Append-only JSONL where `hash = sha256(prevHash + canonicalJSON(record))`. Appends are serialized through a tail promise so the chain stays consistent; the head is recovered from the last line on startup. **Records carry counts/types only — never values** (a test greps the log to prove this). `verify()` walks the chain and reports the first break.

### No shared state
The vault is per-request, policy is in-memory (`policy.ts`), the audit log is a local file — so cordon runs as a **single service with no Redis/DB** (unlike deja). Don't add a cache/datastore dependency without a real reason. Policy has **optional** file-backed durability (`POLICY_STORE`): `policy.load()` runs before `app.listen` and `policy.save()` fires on every `setPolicy` (serialized through a tail promise, mirroring the audit append; fail-safe on absent/malformed files). Unset = pure in-memory, the default path untouched — still no datastore.

## Conventions & gotchas
- Only `/v1/chat/completions` and `/v1/messages` are redacted; every other `/v1/*` path (count_tokens, embeddings, models) forwards **verbatim** via `passthroughUnknown` and must never be normalized.
- The brand string lives in `config.brand` — don't hardcode "cordon" in user-facing strings.
- `CORDON_TEST_HOOKS=1` enables the `X-Cordon-Fail: 1` header that forces a detection failure (to exercise fail-closed). It is **off by default** — never rely on it in production paths.
- Provider auth headers (`authorization`/`x-api-key`/`anthropic-version`) are forwarded verbatim; cordon never terminates provider auth.
- `_stub-upstream.mjs` **echoes the received body** as the assistant reply, which is what lets the suites assert (a) the model saw only placeholders and (b) reversible restores the real values. Keep that echo behavior if you edit the stub.
- The canonical reference for the design rationale and build phases is `PLAN.md`; user-facing docs are `README.md`.
