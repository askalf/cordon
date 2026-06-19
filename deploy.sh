#!/usr/bin/env bash
# cordon → remote-server deploy. Idempotent; re-run any time to ship the latest main.
# Requires: SSH access to the server, and (first run only) gh authenticated for the
# read-only deploy-key registration. Localhost-bound (127.0.0.1:8080) by design.
# Set the target with CORDON_BOX / CORDON_SSH_KEY / CORDON_DIR.
set -euo pipefail

BOX="${CORDON_BOX:-root@your-server.example.com}"
KEY="${CORDON_SSH_KEY:-$HOME/.ssh/id_ed25519}"
DIR="${CORDON_DIR:-/opt/cordon}"
SSH="ssh -i $KEY -o StrictHostKeyChecking=no $BOX"

echo "==> ensuring box deploy key + repo registration"
PUB=$($SSH "test -f /root/.ssh/cordon_deploy || ssh-keygen -t ed25519 -f /root/.ssh/cordon_deploy -N '' -C cordon-deploy >/dev/null 2>&1; cat /root/.ssh/cordon_deploy.pub")
if command -v gh >/dev/null 2>&1; then
  echo "$PUB" | gh repo deploy-key add /dev/stdin --repo askalf/cordon --title cordon-box-deploy 2>/dev/null || true
fi

echo "==> clone / fast-forward to origin/main"
$SSH "export GIT_SSH_COMMAND='ssh -i /root/.ssh/cordon_deploy -o IdentitiesOnly=yes -o StrictHostKeyChecking=no'; \
  if [ -d $DIR/.git ]; then git -C $DIR fetch -q && git -C $DIR reset --hard -q origin/main; \
  else git clone -q git@github.com:askalf/cordon.git $DIR; fi; \
  git -C $DIR log --oneline -1"

echo "==> build + (re)start stack"
$SSH "cd $DIR && docker compose up -d --build"

echo "==> healthcheck"
sleep 6
$SSH "curl -sf http://127.0.0.1:8080/healthz && echo '  cordon healthy'"
