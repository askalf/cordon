# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!--
Release convention: land changes under `## [Unreleased]`. At release
time, rename that heading to `## [X.Y.Z] - YYYY-MM-DD`, bump package.json
to match, push a tag `vX.Y.Z`, and release.yml builds + pushes the GHCR
image and creates the GitHub release from this file.
-->

## [Unreleased]

### Security

- The Responses API request walk reads every input item. `function_call_output` output in its part-array form, `custom_tool_call` input, `custom_tool_call_output` output, `local_shell_call_output` output, `custom` tool descriptions and `prompt.variables` (string and `input_text` values) used to reach the provider unredacted. Input items are now walked fail-closed: every string leaf of every item is redacted, including item types cordon does not know, except structural fields the provider needs byte-exact (`type`, `role`, `status`, `id`, `call_id`, `approval_request_id`, `name`, `model`, `encrypted_content`) and media (`input_image` / `input_file` parts, `image_generation_call` items, `image_url` / `file_id` / `file_url` / `file_data`). An item nested more than 16 levels deep is refused (422) rather than forwarded partly unread.
- A near-miss spelling of a generation endpoint (`/v1/chat/completions/`, `/v1/x/../responses`, `/v1/./messages`, `/v1/Chat/Completions`, `/v1/chat/completion%73`) took the verbatim passthrough and forwarded the raw body; the upstream fetch resolves dot segments, so some of these reached the real endpoint with PII intact. The path is now classified the way the upstream can read it and such a request is redacted. It is still forwarded to the path the client sent.
- `X-Tenant` is ignored unless `TRUST_TENANT_HEADER=true`. Before, any caller could name any tenant and get its policy, including one with `mode: off` or `allowHeaderOverride`, which made "headers can only tighten" untrue by default. When the header is trusted, it may only select a tenant whose policy is at least as strict as the caller's own (mode, sets, fail mode, `redactSystem`, `consistentPseudonyms`, `allowHeaderOverride`, and identical upstream bases); anything looser is refused with 403 before the upstream is called. **Breaking** for deployments that route callers to tenants with `X-Tenant`: set `TRUST_TENANT_HEADER=true`, and move tenants with a looser or residency policy to key-derived tenants.
- Per-request headers can no longer weaken redaction. `X-Redact-Mode` may only be as strong as or stronger than the tenant/global mode (`off` < `reversible` < `strip`), and `X-Redact-Sets` must include every policy set; `X-Redact-Mode: off` or a narrower set list is refused with 403 and the upstream is never called. Until now any caller could send `X-Redact-Mode: off` and forward raw PII. Opt back in per tenant (`"allowHeaderOverride": true`) or globally (`ALLOW_HEADER_OVERRIDE=true`). **Breaking** for clients that relied on loosening headers.
- The admin API is disabled (403) when `ADMIN_TOKEN` is unset, instead of open to anyone who can reach the port. `ALLOW_OPEN_ADMIN=1` restores the open dev behaviour. The token is compared in constant time. **Breaking** for deployments that ran `/admin/*` without a token.
- Upstream failures return a fixed message and a `requestId` (also `X-Request-Id`) instead of the raw exception, which could name internal hosts such as a residency upstream; the detail is logged server-side.

### Added

- `UPSTREAM_TIMEOUT_MS` (default 600000): a provider that sends no response headers in time gets a 504 instead of holding the connection forever. Once headers arrive the body, including a long stream, is not timed.
- `TRUST_TENANT_HEADER` (default `false`): set `true` to honour `X-Tenant`, limited to tenants at least as strict as the caller's own (see Security).

## [0.3.0] - 2026-09-22

The first image since 0.2.0: it also carries 0.2.1's dependency update, which was never tagged or published as an image.

### Added

- `POST /v1/responses` (the OpenAI Responses API) is redacted like `/v1/chat/completions`. Current OpenAI clients (`client.responses.create`, the Agents SDK, Codex) use it by default, and until now it passed through verbatim, so a modern OpenAI client pointed at cordon sent raw PII upstream with `X-Redacted: 0`. The request walk covers `instructions` (under `REDACT_SYSTEM`, with `system` and `developer` items), `input` as a string or an item list (`input_text` parts, `function_call` arguments as parsed JSON, `function_call_output` text) and flat function tool definitions; `input_image` and `input_file` parts are left untouched. Non-streaming replies restore `output_text` and `refusal` parts; streaming restores `response.output_text.delta` and `response.refusal.delta` under their own event kind, giving EACH content part its own hold-back buffer keyed by `item_id` / `output_index` / `content_index` (parts of one turn interleave on the wire, and one shared buffer spliced their text together). A part is flushed on its own done frame; `output_item.done` flushes only the item it names; `response.completed` / `incomplete` / `failed`, `[DONE]`, a reader error and an upstream that stops without any terminal frame all flush whatever is still held. The full text carried by `output_text.done`, `content_part.done`, `output_item.done` and `response.completed` is restored in place. Prior assistant turns fed back as input (`output_text` and `refusal` parts) are redacted too: a stateless client appends the previous reply, which cordon had already restored. Same modes, headers and audit record (provider `openai`). Sub-paths such as `/v1/responses/{id}` still pass through verbatim.

## [0.2.1] - 2026-09-11

### Changed

- `fastify` 5.12.1 → 5.12.3. The only runtime dependency to move in this release;
  the gateway itself is unchanged.
- Dev and CI updates: `tsx`, `@types/node`, and the pinned actions group.


## [0.2.0] - 2026-09-06

First published container image: `ghcr.io/askalf/cordon` (linux/amd64 + linux/arm64, Sigstore provenance attested, SBOM attached). Everything below landed on `main` since 0.1.0 and ships in this image.

### Added

- `release.yml`: tag `vX.Y.Z` → multi-arch image on GHCR tagged `:vX.Y.Z`, `:vX.Y`, `:vX`, `:latest`, plus a GitHub release with the provenance bundle attached. Refuses a tag that does not match `package.json`.
- `build.yml`: every PR builds the image and boots it (health + fail-closed smoke), so a Dockerfile break is caught before a release.
- `POLICY_STORE` (optional): file-backed per-tenant policy persistence, loaded before serving and re-written on every admin change. Off by default; the no-datastore single-container model is unchanged. (#22)
- `REDACT_SYSTEM` (default `true`): set `false` to skip the Anthropic `system` param and OpenAI `role: system` messages, so a framework's own system prompt is not redacted while user content still is. Per-tenant `redactSystem` override. (#6)
- Property-based fuzzing of the detect → redact → re-identify plane (`npm run fuzz`, fast-check; `CORDON_FUZZ_RUNS` deepens) and ClusterFuzzLite continuous fuzzing of the same trust boundary. (#16, #34)
- CONTRIBUTING guide, code of conduct, PR triage and issue templates. (#23, #53)

### Changed

- Reversible placeholders carry a per-request uppercase-hex nonce (`<EMAIL_7F3A2B_1>`, not `<EMAIL_1>`), so a caller's own placeholder-shaped text can never collide with a minted token and be rewritten to a real value on restore. (#22)
- Consistent-pseudonym mode fails closed without an adequate `TENANT_SECRET` (min 16 chars): startup exits when it is the global default, and a tenant that enables it via `/admin/tenant` with no secret is refused with 422 per request. The hardcoded fallback secret is gone; `ALLOW_WEAK_PSEUDONYM_SECRET=1` is the dev-only escape hatch. (#22)
- Unknown `X-Redact-Sets` tokens and unknown `activeSets` in tenant policy are rejected (400) instead of silently dropped. (#8, #9)
- fastify 4 → 5. (#5)

### Fixed

- Streaming re-identification tracks content-block index and type: only `text_delta`s are rewritten, thinking / signature / tool-input deltas pass through verbatim at their original index. Real Claude Code clients using extended thinking no longer fail with "Content block is not a text block". (#6)
- Financial PII sent as a JSON number in structured fields (`tool_use.input`, `tool_calls.arguments`) is detected and redacted; checksum-validated types only, so a 10-digit id is not mistaken for a phone number. (#3, #4)
- Bare-string content-array elements are redacted; `tool_calls.arguments` JSON strings are parsed, redacted, and re-serialized. (#4)
- A placeholder truncated at the end of a stream is resolved by unique prefix instead of leaking a partial token. (#4)
- Redaction leaf writes are hardened against `__proto__` / prototype-key injection. (#15)

### Security

- Dependabot, CodeQL, OpenSSF Scorecard and ClusterFuzzLite run on every push and PR; the Dockerfile base image and every Action are digest-pinned.

## [0.1.0] - 2026-06-19

Initial release: fail-closed PII / PHI / PCI / secrets redaction in front of the Anthropic and OpenAI wire formats, reversible / strip / off modes, per-tenant policy, hash-chained audit log of counts and types only.
