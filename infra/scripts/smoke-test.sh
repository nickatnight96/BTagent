#!/usr/bin/env bash
#
# P4.8 — compose-stack smoke test.
#
# The single highest-leverage guard against the review's cross-cutting failure
# mode: a green unit suite coexisting with a stack that can't actually start or
# serve a request. It brings the real compose stack up from a clean slate and
# asserts the end-to-end path the unit tests can't see:
#
#   images build -> migrate runs -> bucket created -> /health/ready all-ok
#   -> admin bootstrap -> login through nginx -> open an investigation
#   -> the backend image actually contains engine + agents (B1 import check)
#
# Every failing step dumps the offending container logs and exits non-zero, so
# CI shows *why* the stack was unhealthy rather than a bare timeout.
#
# Usage: infra/scripts/smoke-test.sh   (run from the repo root)
set -euo pipefail

COMPOSE_FILE="infra/docker-compose.yml"
COMPOSE=(docker compose -f "$COMPOSE_FILE")
ADMIN_PW="Smoke-Test-Adm1n!"
# nginx publishes the app on :8080; the backend is also on :8000 directly.
API="http://localhost:8000"
NGINX="http://localhost:8080"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
fail() {
  printf '\n\033[1;31mSMOKE FAILED: %s\033[0m\n' "$*" >&2
  log "backend logs"; "${COMPOSE[@]}" logs --tail=80 backend || true
  log "migrate logs"; "${COMPOSE[@]}" logs --tail=40 migrate || true
  log "nginx logs";   "${COMPOSE[@]}" logs --tail=40 nginx || true
  cleanup
  exit 1
}

cleanup() {
  log "tearing the stack down"
  "${COMPOSE[@]}" down -v --remove-orphans || true
}
trap 'fail "unexpected error on line $LINENO"' ERR

# --- 0. clean slate -------------------------------------------------------- #
log "starting from a clean slate"
"${COMPOSE[@]}" down -v --remove-orphans || true

# A per-install .env so validators that reject dev defaults are satisfied.
if [[ ! -f infra/.env ]]; then
  cp infra/.env.example infra/.env
fi

# --- 1. build + start ------------------------------------------------------ #
log "building images"
"${COMPOSE[@]}" build backend frontend

log "bringing the stack up (migrate + init-storage gate the backend)"
"${COMPOSE[@]}" up -d

# --- 2. wait for backend liveness ----------------------------------------- #
log "waiting for backend liveness (/health)"
for i in $(seq 1 60); do
  if curl -fsS "$API/health" >/dev/null 2>&1; then
    break
  fi
  [[ $i -eq 60 ]] && fail "backend never became live within 60s"
  sleep 2
done

# --- 3. migrate actually ran (schema present) ------------------------------ #
log "asserting migrate ran to head (alembic_version present)"
"${COMPOSE[@]}" exec -T postgres \
  psql -U btagent -d btagent -tAc "SELECT version_num FROM alembic_version" \
  | grep -q . || fail "alembic_version empty — migrations did not run"

# --- 4. deep readiness: DB, Redis, S3, revocation all ok ------------------- #
log "asserting /health/ready reports every dependency ok"
READY="$(curl -fsS "$API/health/ready" || true)"
echo "$READY"
echo "$READY" | grep -q '"status": *"ready"' || fail "/health/ready not ready: $READY"

# --- 5. admin bootstrap (in-image bt CLI) ---------------------------------- #
log "bootstrapping the admin via the in-image bt CLI"
"${COMPOSE[@]}" exec -T -e "BTAGENT_SEED_ADMIN_PASSWORD=$ADMIN_PW" backend \
  bt create-admin || fail "bt create-admin failed"

# --- 6. login through nginx (the real ingress) ----------------------------- #
log "logging in through nginx :8080"
LOGIN_CODE="$(curl -s -o /tmp/smoke_login.json -w '%{http_code}' \
  -X POST "$NGINX/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -c /tmp/smoke_cookies.txt \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}")"
[[ "$LOGIN_CODE" == "200" ]] || fail "login returned $LOGIN_CODE (body: $(cat /tmp/smoke_login.json))"

# --- 7. open an investigation (authenticated write path) ------------------- #
log "opening an investigation with the session cookie"
INV_CODE="$(curl -s -o /tmp/smoke_inv.json -w '%{http_code}' \
  -X POST "$NGINX/api/v1/investigations" \
  -H 'Content-Type: application/json' \
  -b /tmp/smoke_cookies.txt \
  -d '{"title":"smoke-test probe","description":"","severity":"low"}')"
case "$INV_CODE" in
  200|201) : ;;
  *) fail "open investigation returned $INV_CODE (body: $(cat /tmp/smoke_inv.json))" ;;
esac

# --- 8. B1: the backend image really contains engine + agents -------------- #
log "B1 import check — engine + agents installed in the backend image"
"${COMPOSE[@]}" exec -T backend python -c \
  "import btagent_engine, btagent_agents, btagent_shared, btagent_backend" \
  || fail "backend image is missing one of engine/agents/shared/backend"

log "SMOKE PASSED"
cleanup
trap - ERR
