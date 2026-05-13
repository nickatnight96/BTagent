#!/usr/bin/env bash
# BTagent local dev runner — starts backend + frontend in one terminal.
#
# Companion to ./infra/scripts/dev-setup.sh (which provisions deps + DB).
# After setup has run once, use this script for the day-to-day dev loop:
#
#     ./infra/scripts/dev-run.sh
#
# It will:
#   1. Make sure docker infra (postgres/redis/minio/ollama) is up
#   2. Start the backend (uvicorn) on :8000
#   3. Start the frontend (vite) on :3000
#   4. Stream both processes' logs to this terminal
#   5. Stop both cleanly on Ctrl+C
#
# Logs from the two services interleave. To debug one in isolation,
# fall back to the two-terminal commands printed by dev-setup.sh.

set -euo pipefail
set -m  # job control — lets us signal entire process groups

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Colors / log helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_RED=$'\033[31m'
  C_BOLD=$'\033[1m'
  C_OFF=$'\033[0m'
else
  C_GREEN= C_YELLOW= C_BLUE= C_RED= C_BOLD= C_OFF=
fi

step() { printf '\n%s==>%s %s%s%s\n' "$C_BLUE" "$C_OFF" "$C_BOLD" "$1" "$C_OFF"; }
ok()   { printf '   %s✓%s %s\n' "$C_GREEN" "$C_OFF" "$1"; }
warn() { printf '   %s!%s %s\n' "$C_YELLOW" "$C_OFF" "$1" >&2; }
die()  { printf '   %sx%s %s\n' "$C_RED" "$C_OFF" "$1" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Sanity: dev-setup must have run
# ---------------------------------------------------------------------------
[ -d .venv ] || die ".venv missing — run ./infra/scripts/dev-setup.sh first."
[ -d frontend/node_modules ] || die "frontend/node_modules missing — run ./infra/scripts/dev-setup.sh first."

# ---------------------------------------------------------------------------
# Step 1: ensure docker infra is up
# ---------------------------------------------------------------------------
step "Step 1/3 — Ensure docker infra is up"
docker compose -f infra/docker-compose.yml up -d postgres redis minio ollama >/dev/null
for i in $(seq 1 20); do
  if docker compose -f infra/docker-compose.yml exec -T postgres pg_isready -U btagent >/dev/null 2>&1; then
    ok "postgres ready"
    break
  fi
  sleep 1
  if [ "$i" -eq 20 ]; then
    die "postgres did not become ready after 20s. Check 'docker compose -f infra/docker-compose.yml logs postgres'."
  fi
done

# ---------------------------------------------------------------------------
# Step 2: start backend (uvicorn with --reload) on :8000
# ---------------------------------------------------------------------------
step "Step 2/3 — Backend on :8000 (uvicorn --reload)"
(
  export BTAGENT_ENV=test
  export BTAGENT_JWT_SECRET="dev-secret-for-local-only"
  export BTAGENT_DATABASE_URL="postgresql+asyncpg://btagent:btagent_dev_password@localhost:5432/btagent"
  export BTAGENT_REDIS_URL="redis://localhost:6379"
  # shellcheck source=/dev/null
  source .venv/bin/activate
  exec uvicorn btagent_backend.main:app --reload --port 8000 --app-dir backend
) &
BACKEND_PID=$!

# ---------------------------------------------------------------------------
# Step 3: start frontend (vite) on :3000
# ---------------------------------------------------------------------------
step "Step 3/3 — Frontend on :3000 (vite --host)"
(
  cd frontend
  exec npm run dev
) &
FRONTEND_PID=$!

# ---------------------------------------------------------------------------
# Cleanup on Ctrl+C / EXIT
# ---------------------------------------------------------------------------
cleanup() {
  echo
  step "Shutting down"
  # SIGTERM each process group (set -m enables this). Fall back to bare PID
  # for shells that don't allocate a group (rare on macOS bash but cheap).
  for pid in $BACKEND_PID $FRONTEND_PID; do
    kill -TERM -- -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  done
  sleep 1
  for pid in $BACKEND_PID $FRONTEND_PID; do
    kill -KILL -- -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
  done
  ok "both services stopped"
  echo "   docker infra left running. Tear down with:  ${C_BOLD}make down${C_OFF}"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Banner + wait
# ---------------------------------------------------------------------------
cat <<EOF

${C_GREEN}${C_BOLD}Both services starting up.${C_OFF}

  backend:   ${C_BLUE}http://localhost:8000${C_OFF}     (API docs: ${C_BLUE}http://localhost:8000/api/docs${C_OFF})
  frontend:  ${C_BLUE}http://localhost:3000${C_OFF}     (login: admin / admin)

Logs from both services will interleave below. Press ${C_BOLD}Ctrl+C${C_OFF} to stop both.

EOF

# Wait for either to exit; trap will handle cleanup.
while kill -0 $BACKEND_PID 2>/dev/null && kill -0 $FRONTEND_PID 2>/dev/null; do
  sleep 1
done

# Report which died first so the user knows where to look.
if ! kill -0 $BACKEND_PID 2>/dev/null; then
  warn "backend exited unexpectedly"
fi
if ! kill -0 $FRONTEND_PID 2>/dev/null; then
  warn "frontend exited unexpectedly"
fi
