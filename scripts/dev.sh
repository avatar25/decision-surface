#!/usr/bin/env bash
# Bootstraps both halves of the dev environment: the OPA server that evaluates
# policies, and the Vite dev server that proxies /opa to it.
set -euo pipefail

cd "$(dirname "$0")/.."

OPA_PORT="${OPA_PORT:-8181}"
OPA_PID=""
VITE_PID=""

if ! command -v opa >/dev/null 2>&1; then
  echo "opa not found. Install it with:" >&2
  echo "  brew install opa      # macOS" >&2
  echo "  https://www.openpolicyagent.org/docs/latest/#running-opa" >&2
  exit 1
fi

[ -d node_modules ] || { echo "==> installing dependencies"; npm install; }

# Leave an already-running OPA alone so this script is safe to re-run.
if curl -sf "http://localhost:${OPA_PORT}/health" >/dev/null 2>&1; then
  echo "==> reusing OPA already listening on ${OPA_PORT}"
else
  echo "==> starting OPA on ${OPA_PORT}"
  opa run --server --addr "localhost:${OPA_PORT}" --log-level error &
  OPA_PID=$!

  for _ in $(seq 1 40); do
    curl -sf "http://localhost:${OPA_PORT}/health" >/dev/null 2>&1 && break
    sleep 0.25
  done

  if ! curl -sf "http://localhost:${OPA_PORT}/health" >/dev/null 2>&1; then
    echo "OPA did not come up on ${OPA_PORT}" >&2
    exit 1
  fi
fi

# Tear down Vite always, but only an OPA that this script actually started.
# Guarded so the INT/TERM trap and the EXIT trap don't both run it.
CLEANED=""
cleanup() {
  [ -n "$CLEANED" ] && return
  CLEANED=1
  [ -n "$VITE_PID" ] && kill "$VITE_PID" 2>/dev/null || true
  if [ -n "$OPA_PID" ]; then
    echo
    echo "==> stopping OPA"
    kill "$OPA_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "==> starting Vite"
# Backgrounded and waited on, so a signal reaches the trap instead of being
# swallowed by a foreground child.
npm run dev &
VITE_PID=$!
wait "$VITE_PID"
