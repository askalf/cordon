import type { PatternDef } from "../types";

// Credential patterns — stops API keys / tokens from being pasted into a prompt and
// leaking to the model (or to logs downstream of it). All belong to the `secrets` set
// and run at high priority so a key inside a longer string still wins its span.
//
// (cordon ships these inline rather than depending on a sibling redaction lib, so the
// gateway has no cross-repo coupling.)
export const secretPatterns: PatternDef[] = [
  {
    // Anthropic keys — match before the generic sk- rule.
    type: "ANTHROPIC_KEY",
    sets: ["secrets"],
    regex: /sk-ant-[A-Za-z0-9_-]{20,}/g,
    priority: 9,
  },
  {
    // OpenAI keys (sk-, sk-proj-, etc.).
    type: "OPENAI_KEY",
    sets: ["secrets"],
    regex: /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g,
    priority: 8,
  },
  {
    type: "AWS_ACCESS_KEY",
    sets: ["secrets"],
    regex: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b/g,
    priority: 9,
  },
  {
    type: "GITHUB_TOKEN",
    sets: ["secrets"],
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
    priority: 9,
  },
  {
    type: "GOOGLE_API_KEY",
    sets: ["secrets"],
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    priority: 9,
  },
  {
    type: "SLACK_TOKEN",
    sets: ["secrets"],
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    priority: 9,
  },
  {
    type: "JWT",
    sets: ["secrets"],
    regex: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
    priority: 8,
  },
  {
    // Authorization: Bearer <token> — redact the token, keep the scheme word.
    type: "BEARER_TOKEN",
    sets: ["secrets"],
    regex: /\bBearer\s+([A-Za-z0-9._~+/=-]{16,})/gd,
    group: 1,
    priority: 7,
  },
  {
    // PEM private key blocks (RSA/EC/OPENSSH/PGP) — multiline.
    type: "PRIVATE_KEY",
    sets: ["secrets"],
    regex: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z ]+ )?PRIVATE KEY-----/g,
    priority: 10,
  },
  {
    // Stripe secret / restricted keys (underscore form — distinct from OpenAI sk-).
    type: "STRIPE_KEY",
    sets: ["secrets"],
    regex: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    priority: 9,
  },
  {
    // GitHub fine-grained PAT (the gh*_ rule above doesn't cover this prefix).
    type: "GITHUB_FINEGRAINED_PAT",
    sets: ["secrets"],
    regex: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g,
    priority: 9,
  },
  {
    type: "SENDGRID_KEY",
    sets: ["secrets"],
    regex: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
    priority: 9,
  },
  {
    type: "NPM_TOKEN",
    sets: ["secrets"],
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    priority: 9,
  },
  {
    // Google OAuth refresh token (starts 1// — rare prefix, low FP).
    type: "GOOGLE_OAUTH_REFRESH",
    sets: ["secrets"],
    regex: /\b1\/\/[0-9A-Za-z_-]{20,}\b/g,
    priority: 8,
  },
  {
    // Slack incoming-webhook URL — the path segment is the secret.
    type: "SLACK_WEBHOOK",
    sets: ["secrets"],
    regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,}/g,
    priority: 9,
  },
];
