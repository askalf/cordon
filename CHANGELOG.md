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

### Added

- A replay suite (`_test_replay.mjs`, in `npm test`): invented people, hard names on purpose (ordinary-word names, one-word names, hyphens, apostrophes, accents), through five request shapes (a chat turn, an agent tool loop with a form submission in a JSON tool result, MCP-named tools, Chat Completions tool calls, Responses function calls). Every combination must leak nothing once redacted, ordinary lowercase use of a name's words must not be refused, and a reply's text and an allowed tool's arguments must get the real values back while an unlisted tool keeps placeholders. Generated people run through every shape as fast-check properties (`CORDON_FUZZ_RUNS` deepens them).
- Known subjects (`X-Cordon-Subject`): a caller names the people a request is about, and their names, emails, phones, addresses, dates of birth, IDs and handles are matched in the forms people write them and replaced with `<SUBJECT<n>_<KIND>_…>` placeholders ahead of the pattern catalog. An egress check then reads the de-identified body again, separator-blind and Unicode-normalised, and refuses the request (422) if any identifier is still there. Media in a subject request is refused unless both the policy and the header allow it. The audit records a digest of the caller's ref and the egress verdict, `X-Cordon-Receipt` returns the record's hash, and `GET /admin/receipts?ref=` serves a ref's records after verifying the chain.
- Tenant policy `requireSubject`, `subjectMedia` and `reportOnly` (forward unchanged and record what would have happened, for measuring a caller before enforcing).
- Image masking for subject requests (`subjectMedia: "mask"`): each image is read on the server with an offline OCR engine, the words of any subject identifier or catalog entity are painted over, and the masked image is read again and sent only if nothing is found. Media that cannot be read (PDF, audio, files, images by URL or file id) is refused in mask mode. `sharp`, `tesseract.js` and `@tesseract.js-data/eng` are optional dependencies.
- Egress findings say where they are: when the egress check finds a declared identifier, the audit record carries `egressAt` (per kind, the first place it was found, as protocol keys and array indexes with caller-defined keys written `*`, and which reading caught it), and a report-only `X-Cordon-Report` lists the kinds. Never text: a would-refuse in report-only traffic can be traced to its place in the body without the value.

### Fixed

- Subject names right after a JSON escape (`\n`, `\"` in a tool result's JSON text) are redacted: escapes are read as separators of the same length, so the word boundary holds and offsets still point into the original text. A one-word name in capitals ("GRANT") is redacted too. Username-style joins of a name (marisolvance, mvance, vancem) are matched letter-bounded, so "advancement" no longer holds a redacted "vancem", and the egress check no longer reads one across words ("the stone might" is not Mia Stone).
- Egress: a declared name's single words are no longer found in ordinary lowercase text. A word read alone counts only when it is capitalised, in capitals or spread out ("Test", "TEST", "t e s t"), so a visitor named Test User or Grant does not turn "this is a test" or "grant access" into a refusal. A one-word name is no longer a separator-blind needle either ("fragrant" held "grant"). Full names, email addresses, phone numbers and the other forms are read as before.
- A tool-call argument number made of a long run of zeros ending in another digit no longer stalls redaction: its trailing zeros are counted in linear time instead of by a backtracking regular expression.
- Tool-call argument strings in a request are redacted on their own text, so a number the walk does not change keeps its digits (an integer beyond 2^53 was rounded, legacy `function_call` and `tool_calls` alike) and the arguments keep their spacing.
- Streamed JSON tool arguments are released when the call ends and its whole-document checks pass, instead of fragment by fragment, so a refused call never reaches the client in part.
- Chat completions custom tool calls (`tool_calls[].custom.input`) are restored, whole and streamed, and redacted again when replayed as history.
- Citations into a redacted Messages document get `cited_text` and `document_title` restored and `char_location` offsets translated back to the caller's text (counted in Unicode characters, as the API counts them); a reply replayed as history has its citations' `cited_text`, `document_title` and `title` redacted again.
- A number in tool-call arguments is checked for financial identifiers on its exact decimal value, so a card written `4111111111111111.0` or `4.111111111111111e15` is still found and replaced whole.
- In reversible mode the model's tool-call arguments came back with placeholders in them. Only assistant text was restored, so a runner that executes what the model types (an opt-out form, a search, a report) ran its tool on `<EMAIL_…>` instead of the value. Tool arguments are now restored on every dialect and shape: `function_call`, `mcp_call` and `custom_tool_call` items on the Responses API (`output_item.added` / `.done`, the completed response, and the streamed `function_call_arguments`, `mcp_call_arguments` and `custom_tool_call_input` delta and done frames), `tool_calls` and the legacy `function_call` on chat completions, for every choice (the message and the streamed fragments, including a frame that carries text and a fragment together, or a fragment and `finish_reason`), and `tool_use`, `server_tool_use` and `mcp_tool_use` input on Messages (the block, `content_block_start` with input given whole, and the streamed `input_json_delta` fragments). JSON arguments are restored on their raw text: values are JSON-escaped into their string literal, the `<` spelling of a placeholder is recognised, numbers keep their digits, and a stream's fragments join into exactly what its done frame carries. A held argument tail is flushed at `[DONE]`, at a stream that simply stops, and before a choice's finish frame.
- A streamed tool input that ends in text such as `cat <README` or `x<Y` is delivered as written, as the whole document is; only the start of a token this request minted, or the minted shape, is refused as a cut-off placeholder. Responses `sequence_number` values are renumbered wherever the JSON spacing puts them, so untouched upstream frames and rewritten ones share one increasing count. Two property names that restore to the same name are refused on JSON argument text, whole and streamed, as on parsed objects.

### Security
- Tool-call arguments replayed as history are redacted in their property names too (a collision refuses the request), and structured fields are walked to 64 levels, matching the response side, with a deeper one refused instead of walked part way (it stopped silently at 16).
- The request walk reads more of the text the model sees: on Messages, `document` titles, context and text or content sources, `search_result` titles and text, `mcp_tool_result` content, and `server_tool_use` and `mcp_tool_use` input; on chat completions, an assistant message's `refusal` and legacy `function_call.arguments`. Media, ids and tool names still pass as sent (README, "Fronting an agent runner").

- Arguments that end inside a placeholder, nest deeper than 64 levels, or hold two property names that restore to the same name are refused the same way. A placeholder in a tool call's arguments that this request did not mint (a stale one from another conversation, one planted in a page the model read) now fails the call instead of reaching the client's tool: a whole response becomes 502 with the count in `X-Cordon-Unresolved`, a stream gets the dialect's error frame and ends. Only cordon's minted shapes count (`<TYPE_xxxxxx_n>`, `<TYPE_xxxxxxxx>`); a caller's own placeholder-shaped literal, and any placeholder in prose, are left as text.
- `CORDON_RESTORE_TOOLS` limits which tools, or `tool.field` pairs, get real values back in their arguments. Unset or empty restores none, so existing deployments keep redacted arguments; `*` opts in to restoring every tool's arguments. A withheld value goes out in strip form (`[EMAIL]`). A chat tool name streamed in fragments is never matched against the list until it is complete. Deciding where a value may go remains the agent runner's job (README, "Fronting an agent runner").
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
