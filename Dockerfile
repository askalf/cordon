# cordon — PII-redacting LLM compliance gateway. Runs TypeScript directly via tsx.
FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2

WORKDIR /app

# Install deps first (better layer caching). Lockfile-exact on purpose — no
# `npm install` fallback, so a lockfile drift fails the build instead of
# silently resolving fresh versions.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# App source
COPY tsconfig.json ./
COPY src ./src

# /app/data holds the audit log (mounted as a volume); make it node-writable.
RUN mkdir -p /app/data && chown -R node:node /app
USER node

ENV NODE_ENV=production \
    PORT=8080 \
    AUDIT_LOG=/app/data/audit.jsonl

EXPOSE 8080

# Node 22 has global fetch — no curl/wget dependency for the healthcheck.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# PID-1 init (zombie reaping / signal handling) is provided by compose `init: true`.
CMD ["node_modules/.bin/tsx", "src/index.ts"]
