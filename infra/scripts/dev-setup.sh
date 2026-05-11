#!/usr/bin/env bash
# BTagent local dev setup — idempotent.
#
# Brings the repo from a fresh clone to a state where two more commands
# (one in each of two terminals) boot the full stack:
#
#   Terminal A:  source .venv/bin/activate && \
#                BTAGENT_ENV=test \
#                BTAGENT_JWT_SECRET="dev-secret-for-local-only" \
#                BTAGENT_DATABASE_URL="postgresql+asyncpg://btagent:btagent_password@localhost:5432/btagent" \
#                BTAGENT_REDIS_URL="redis://localhost:6379" \
#                uvicorn btagent_backend.main:app --reload --port 8000 --app-dir backend
#
#   Terminal B:  cd frontend && npm run dev
#
# After both are up, open http://localhost:3000 and log in as admin / admin.
#
# Re-running the script after a successful run is safe — every step is
# either no-op or checks before mutating.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Colors / log helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_BOLD=$'\033[1m'
  C_OFF=$'\033[0m'
else
  C_RED= C_GREEN= C_YELLOW= C_BLUE= C_BOLD= C_OFF=
fi

step()  { printf '\n%s==>%s %s%s%s\n' "$C_BLUE" "$C_OFF" "$C_BOLD" "$1" "$C_OFF"; }
info()  { printf '   %s\n' "$1"; }
ok()    { printf '   %s✓%s %s\n' "$C_GREEN" "$C_OFF" "$1"; }
warn()  { printf '   %s!%s %s\n' "$C_YELLOW" "$C_OFF" "$1" >&2; }
die()   { printf '   %sx%s %s\n' "$C_RED" "$C_OFF" "$1" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Step 1: prereq checks
# ---------------------------------------------------------------------------
step "Step 1/6 — Prerequisite check"

# Python 3.12 — engine/agents pin >=3.12.
if command -v python3.12 >/dev/null 2>&1; then
  PYTHON_BIN=python3.12
  ok "python3.12: $(python3.12 --version)"
elif python3 --version 2>&1 | grep -qE '3\.(1[2-9]|[2-9][0-9])'; then
  PYTHON_BIN=python3
  ok "python3 (>=3.12): $(python3 --version)"
else
  die "Python 3.12+ required. Install via 'brew install python@3.12' (macOS) or your package manager."
fi

# uv
if ! command -v uv >/dev/null 2>&1; then
  die "uv not found. Install: curl -LsSf https://astral.sh/uv/install.sh | sh"
fi
ok "uv: $(uv --version)"

# Node 20.x — the project's CI pin and frontend peer-dep target.
if ! command -v node >/dev/null 2>&1; then
  if [ -s "$HOME/.nvm/nvm.sh" ]; then
    warn "node not on PATH but nvm is installed; sourcing ~/.nvm/nvm.sh"
    # shellcheck source=/dev/null
    . "$HOME/.nvm/nvm.sh"
    nvm use 20 >/dev/null || die "nvm doesn't have Node 20 installed. Run: nvm install 20"
  else
    die "Node 20+ required. Install via nvm: 'curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash' then 'nvm install 20'."
  fi
fi
NODE_MAJOR="$(node --version | sed 's/^v//;s/\..*//')"
if [ "$NODE_MAJOR" -lt 20 ]; then
  die "Node 20+ required (found $(node --version)). Run: nvm use 20"
fi
ok "node: $(node --version)"
ok "npm:  $(npm --version)"

# Docker
if ! docker info >/dev/null 2>&1; then
  die "Docker daemon not running. Start Docker Desktop (macOS) or 'sudo systemctl start docker' (Linux)."
fi
ok "docker: $(docker --version | awk '{print $3}' | tr -d ,)"

# ---------------------------------------------------------------------------
# Step 2: start infra (postgres + redis + minio + ollama)
# ---------------------------------------------------------------------------
step "Step 2/6 — Start infrastructure (docker compose)"

if [ ! -f infra/.env ] && [ -f infra/.env.example ]; then
  cp infra/.env.example infra/.env
  ok "copied infra/.env.example -> infra/.env"
fi

info "docker compose up -d postgres redis minio ollama"
docker compose -f infra/docker-compose.yml up -d postgres redis minio ollama

info "waiting for postgres to accept connections..."
for i in $(seq 1 30); do
  if docker compose -f infra/docker-compose.yml exec -T postgres pg_isready -U btagent >/dev/null 2>&1; then
    ok "postgres ready"
    break
  fi
  sleep 1
  if [ "$i" -eq 30 ]; then
    die "postgres did not become ready after 30s. Check 'docker compose logs postgres'."
  fi
done

info "waiting for redis..."
for i in $(seq 1 15); do
  if docker compose -f infra/docker-compose.yml exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; then
    ok "redis ready"
    break
  fi
  sleep 1
done

# ---------------------------------------------------------------------------
# Step 3: Python venv + workspace deps
# ---------------------------------------------------------------------------
step "Step 3/6 — Python venv + workspace deps"

if [ ! -d .venv ]; then
  info "creating .venv with $PYTHON_BIN"
  uv venv .venv --python "$PYTHON_BIN"
  ok ".venv created"
else
  ok ".venv already exists"
fi

# shellcheck source=/dev/null
. .venv/bin/activate

# Order matters: shared -> engine -> agents -> backend.
info "uv pip install -e shared/ engine/ agents/ backend/[dev]"
uv pip install -e shared/ -e engine/ -e agents/ -e "backend/[dev]" >/dev/null
ok "Python workspace installed"

# ---------------------------------------------------------------------------
# Step 4: frontend deps
# ---------------------------------------------------------------------------
step "Step 4/6 — Frontend deps"

if [ ! -d frontend/node_modules ]; then
  info "npm install (first time, ~30s)"
  (cd frontend && npm install --no-audit --no-fund) >/dev/null
  ok "frontend/node_modules ready"
else
  info "frontend/node_modules exists — skipping install. Delete it to force a re-install."
  ok "frontend deps ok"
fi

# ---------------------------------------------------------------------------
# Step 5: database migrations
# ---------------------------------------------------------------------------
step "Step 5/6 — Alembic migrations"

# Default compose creds; override via DATABASE_URL env if you customized the
# infra/docker-compose.yml or infra/.env.
DEV_DB_URL="${BTAGENT_DATABASE_URL:-postgresql+asyncpg://btagent:btagent_password@localhost:5432/btagent}"

info "running migrations against ${DEV_DB_URL%@*}@..."
BTAGENT_DATABASE_URL="$DEV_DB_URL" alembic -c backend/alembic.ini upgrade head
ok "migrations applied"

# ---------------------------------------------------------------------------
# Step 6: seed deterministic test users
# ---------------------------------------------------------------------------
step "Step 6/6 — Seed deterministic test users"

# BTAGENT_ENV=test makes passwords equal to usernames (admin/admin etc.)
BTAGENT_ENV=test \
  BTAGENT_DATABASE_URL="$DEV_DB_URL" \
  python infra/scripts/seed-data.py

# ---------------------------------------------------------------------------
# Done — print the two commands the user runs next.
# ---------------------------------------------------------------------------
cat <<EOF

${C_GREEN}${C_BOLD}Setup complete.${C_OFF}

Open two terminals and run:

${C_BOLD}Terminal A — backend (uvicorn with hot reload):${C_OFF}

  source .venv/bin/activate
  BTAGENT_ENV=test \\
    BTAGENT_JWT_SECRET="dev-secret-for-local-only" \\
    BTAGENT_DATABASE_URL="$DEV_DB_URL" \\
    BTAGENT_REDIS_URL="redis://localhost:6379" \\
    uvicorn btagent_backend.main:app --reload --port 8000 --app-dir backend

${C_BOLD}Terminal B — frontend (vite dev with HMR):${C_OFF}

  cd frontend && npm run dev

Then open ${C_BLUE}http://localhost:3000${C_OFF} and log in:

  admin    / admin       (admin)
  senior1  / senior1     (senior_analyst — can create workflows)
  analyst1 / analyst1    (analyst — read-only on workflows)

To tear down infra: ${C_BOLD}make down${C_OFF}

EOF
