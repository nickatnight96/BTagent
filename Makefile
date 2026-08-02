.PHONY: dev up down build test uat eval lint fmt clean e2e e2e-headed e2e-ui e2e-debug e2e-install create-admin

# ── Development ──────────────────────────────────────────────
dev: ## Start full dev stack (infra in Docker, backend+frontend local with hot reload)
	docker compose -f infra/docker-compose.yml up -d postgres redis minio ollama
	@echo "Infra services started. Run backend and frontend separately:"
	@echo "  cd backend && uvicorn btagent_backend.main:app --reload --port 8000"
	@echo "  cd frontend && npm run dev"

up: ## Start full Docker Compose stack (runs migrations + bucket init first)
	docker compose -f infra/docker-compose.yml up -d
	@echo
	@echo "Migrations and the evidence bucket are handled by the 'migrate' and"
	@echo "'init-storage' one-shots; backend/scheduler wait for both to exit 0."
	@echo "Bootstrap the first admin (idempotent, never prints the password):"
	@echo "  make create-admin BTAGENT_SEED_ADMIN_PASSWORD=..."
	@echo "Then check:  curl -sf localhost:8000/health/ready"

up-observability: ## Start with observability stack
	docker compose -f infra/docker-compose.yml -f infra/docker-compose.observability.yml up -d

down: ## Stop all services
	docker compose -f infra/docker-compose.yml down

build: ## Build all Docker images
	docker compose -f infra/docker-compose.yml build

# ── Database ─────────────────────────────────────────────────
# NOTE: `make up` migrates by itself (the compose `migrate` one-shot). This
# target is for the host-side dev loop (`make dev`), where the backend runs
# from a local virtualenv against the dockerised Postgres.
db-migrate: ## Run Alembic migrations from the host virtualenv (dev loop)
	cd backend && alembic upgrade head

db-revision: ## Create new Alembic migration (usage: make db-revision msg="add foo table")
	cd backend && alembic revision --autogenerate -m "$(msg)"

db-seed: ## Seed database with test data (dev/test only; not for production)
	python infra/scripts/seed-data.py

db-reset-admin: ## Create/reset admin password from the host virtualenv (needs the repo)
	python infra/scripts/reset-admin-password.py

create-admin: ## Bootstrap/reset the admin INSIDE the running compose stack (the prod path)
	@test -n "$(BTAGENT_SEED_ADMIN_PASSWORD)" || \
	  { echo "set BTAGENT_SEED_ADMIN_PASSWORD, e.g. make create-admin BTAGENT_SEED_ADMIN_PASSWORD=\"$$(openssl rand -base64 24)\""; exit 1; }
	docker compose -f infra/docker-compose.yml exec \
	  -e BTAGENT_SEED_ADMIN_PASSWORD='$(BTAGENT_SEED_ADMIN_PASSWORD)' backend bt create-admin

# ── Testing ──────────────────────────────────────────────────
test: test-backend test-agents test-frontend ## Run all unit tests

test-backend: ## Run backend tests
	cd backend && python -m pytest tests/ -v

test-agents: ## Run agent tests
	cd agents && python -m pytest tests/ -v

test-frontend: ## Run frontend tests
	cd frontend && npm run test

# The UAT webhook tests need BTAGENT_WEBHOOK_SECRET, and it must match what the
# running backend was started with. Webhook auth no longer falls back to the JWT
# signing key (that fallback was GH #372), so this is exported rather than
# inherited by accident. Take it from infra/.env when present — that is the
# value the compose stack under test is actually using.
UAT_WEBHOOK_SECRET ?= $(shell sed -n 's/^BTAGENT_WEBHOOK_SECRET=//p' infra/.env 2>/dev/null)

uat: ## Run UAT tests (requires running Docker stack)
	@if [ -z "$(UAT_WEBHOOK_SECRET)" ]; then \
		echo "BTAGENT_WEBHOOK_SECRET is not set in infra/.env — the UAT webhook tests will fail."; \
		echo "Set it there (>=32 chars, different from BTAGENT_JWT_SECRET) and restart the stack."; \
		exit 1; \
	fi
	BTAGENT_WEBHOOK_SECRET="$(UAT_WEBHOOK_SECRET)" python -m pytest tests/uat/ -v --timeout=120

uat-smoke: ## Quick UAT smoke tests
	BTAGENT_WEBHOOK_SECRET="$(UAT_WEBHOOK_SECRET)" python -m pytest tests/uat/ -v -m smoke --timeout=60

eval: ## Agent evaluation — golden-dataset evals of deterministic agent components (#382)
	python -m pytest tests/agent_eval/ -v

load: ## Run k6 load tests
	k6 run tests/load/api_load.js

e2e-install: ## Install Playwright browsers (one-time setup)
	cd tests/e2e && npm install && npx playwright install --with-deps chromium

e2e: ## Run all Playwright E2E tests (chromium, headless) — needs make dev + seed-data
	cd tests/e2e && npx playwright test

e2e-headed: ## Run Playwright E2E tests in a visible browser window
	cd tests/e2e && npx playwright test --headed

e2e-ui: ## Open Playwright's interactive test runner
	cd tests/e2e && npx playwright test --ui

e2e-debug: ## Run Playwright E2E with debugger paused at first step
	cd tests/e2e && npx playwright test --debug

e2e-auth: ## Run only the auth + RBAC specs
	cd tests/e2e && npx playwright test specs/auth/

e2e-investigations: ## Run only the investigation lifecycle specs
	cd tests/e2e && npx playwright test specs/investigations/

e2e-iocs: ## Run only the IOC management specs
	cd tests/e2e && npx playwright test specs/iocs/

e2e-knowledge: ## Run only the knowledge base specs
	cd tests/e2e && npx playwright test specs/knowledge/

e2e-mitre: ## Run only the MITRE ATT&CK specs
	cd tests/e2e && npx playwright test specs/mitre/

e2e-playbooks: ## Run only the playbook specs
	cd tests/e2e && npx playwright test specs/playbooks/

e2e-security: ## Run only the security/negative specs
	cd tests/e2e && npx playwright test specs/security/

e2e-mobile: ## Run mobile-tagged tests on Pixel 7 viewport
	cd tests/e2e && npx playwright test --project=mobile-chrome

e2e-cross-browser: ## Run @cross-browser-tagged tests on Firefox + WebKit
	cd tests/e2e && npx playwright test --project=firefox --project=webkit

e2e-report: ## Open the last Playwright HTML report
	cd tests/e2e && npx playwright show-report

# ── Code Quality ─────────────────────────────────────────────
lint: ## Lint Python and TypeScript
	ruff check backend/ agents/ shared/
	cd frontend && npx tsc --noEmit

fmt: ## Format Python code
	ruff format backend/ agents/ shared/

# ── Utilities ────────────────────────────────────────────────
clean: ## Remove build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name node_modules -exec rm -rf {} + 2>/dev/null || true
	rm -rf frontend/dist backend/dist agents/dist shared/dist

wait-healthy: ## Wait for all Docker services to be healthy
	@echo "Waiting for services..."
	@until docker compose -f infra/docker-compose.yml exec -T postgres pg_isready -U btagent 2>/dev/null; do sleep 1; done
	@echo "PostgreSQL ready"
	@until docker compose -f infra/docker-compose.yml exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; do sleep 1; done
	@echo "Redis ready"
	@echo "All services healthy"

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
