# cordon

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

## Status

**Design / scaffold.** This repo is the anchor for plan refinement — nothing is implemented yet. The full design and build plan lives in [PLAN.md](./PLAN.md).

## Design at a glance

- **Two modes, policy-selectable** — `reversible` (restore real values in the reply) and `strip` (irreversible placeholders), chosen per-tenant or per-request via `X-Redact-Mode`.
- **Deterministic detection first** — regex + checksum validators (Luhn, IBAN mod-97, ABA), zero ML dependencies, fully auditable. A clean detector interface leaves room for an optional NER sidecar later.
- **Broad catalog, tagged by regime** — one superset of entity types (PII · PHI · PCI · secrets), each tagged `hipaa | gdpr | pci | secret`; policy selects the active sets.
- **Fail-closed** — if detection errors, the request is blocked, never forwarded.

Part of the [Own Your Stack](https://sprayberrylabs.com/own-your-stack) portfolio.
