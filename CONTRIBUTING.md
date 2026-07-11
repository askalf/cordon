# Contributing to cordon

Thanks for your interest in improving **cordon** — a PII-redacting LLM
compliance gateway. It's OpenAI/Anthropic-compatible and sits in front of your
model so PII never leaves your perimeter: own your prompts. Part of
[Own Your Stack](https://sprayberrylabs.com).

## Ground rules

- Be respectful. This project follows our [Code of Conduct](CODE_OF_CONDUCT.md).
- Found a security issue? **Do not open a public issue** — follow
  [SECURITY.md](SECURITY.md) to report it privately.

## Development setup

cordon is a TypeScript service, run with `tsx`. You need Node.js **22** (the
version CI uses).

```bash
git clone https://github.com/askalf/cordon.git
cd cordon
npm ci             # install from the frozen lockfile
npm run typecheck  # tsc --noEmit
npm test           # run the test suite
```

To run the gateway locally, use `npm run dev` (watch mode) or `npm start`.

## Making a change

1. Branch off `main`.
2. Keep the change focused — one concern per PR.
3. Add or update tests for any behavior change. cordon fails closed on PII, so
   changes to the redaction rules, the proxy, or the streaming path must be
   covered by tests.
4. Run `npm run typecheck` and `npm test` locally before pushing.
5. Open a pull request against `main`.

## What CI requires

Every PR must pass these checks to merge:

- `test` (ubuntu-latest, Node **22**) — runs `npm run typecheck` then `npm test`
- **CodeQL** static analysis (`analyze (javascript-typescript)`)

OpenSSF Scorecard also runs on the repo; a new high-severity finding will block
the change.

## Conventions

- GitHub Actions are **pinned to a commit SHA**, never a mutable tag. New or
  updated workflow steps must keep this.
- Commit messages: short imperative subject, with a wrapped body explaining the
  *why* when it isn't obvious.
- PRs are squash-merged, so your PR title becomes the commit subject on `main`.
