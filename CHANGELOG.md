# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!--
Release convention: land changes under `## [Unreleased]`. At release
time, rename that heading to `## [X.Y.Z] - YYYY-MM-DD`, bump package.json
to match, push a tag `vX.Y.Z`, and release.yml builds + pushes the GHCR
image and creates the GitHub release from this file.
-->

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
