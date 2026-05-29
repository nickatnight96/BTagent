#!/bin/bash
# SessionStart hook — bootstraps BTagent dependencies for Claude Code on the web
# so tests, linters, and type-checks work without re-bootstrapping each session.
#
# Stack (per CLAUDE.md + CI):
#   * Python 3.12 uv "workspace" — each package installs editable into a shared
#     .venv, in dependency order: shared -> engine -> agents -> backend[dev].
#   * Frontend — npm (React 19 / Vite / TS) in frontend/.
#   * E2E — Playwright (chromium) in tests/e2e/  (best-effort; needs the docker
#     stack to actually run, so we only pre-install it here).
#
# Idempotent + non-interactive. Synchronous (no async block) so the session
# only starts once deps are ready — no race where a test/lint runs too early.
set -euo pipefail

# Only run in the remote (Claude Code on the web) environment. Local sessions
# already have the developer's own venv + node_modules.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"

# ── Python: uv venv + editable workspace installs ───────────────────────────
if ! command -v uv >/dev/null 2>&1; then
  pip install uv
fi

if [ ! -d .venv ]; then
  uv venv .venv
fi

# Point uv at the project venv, then install each package editable in order.
export VIRTUAL_ENV="$CLAUDE_PROJECT_DIR/.venv"
uv pip install -e shared/ -e engine/ -e agents/ -e "backend/[dev]"

# Persist the venv on PATH for the whole session (so `python`, `pytest`,
# `ruff`, `alembic`, `uvicorn` resolve to the venv).
{
  echo "export VIRTUAL_ENV=\"$CLAUDE_PROJECT_DIR/.venv\""
  echo "export PATH=\"$CLAUDE_PROJECT_DIR/.venv/bin:\$PATH\""
} >> "$CLAUDE_ENV_FILE"

# ── Frontend: npm deps ──────────────────────────────────────────────────────
(cd frontend && npm install --no-audit --no-fund)

# ── E2E: Playwright deps (best-effort — full e2e needs `make dev` + seed) ────
# Don't fail the whole bootstrap if the browser download / apt deps are
# unavailable; backend/agents/frontend testing must still come up cleanly.
# Try the full (with apt deps) install first, then fall back to browser-only
# (the chromium binary alone is enough once the docker stack is up).
(
  cd tests/e2e \
  && npm install --no-audit --no-fund \
  && { npx playwright install --with-deps chromium \
       || npx playwright install chromium \
       || true; }
) || echo "session-start: Playwright setup incomplete (e2e deferred; core deps OK)"

echo "session-start: BTagent dependencies ready."
