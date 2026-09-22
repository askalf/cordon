# Developing cordon

Back to the [README](../README.md).

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
