.PHONY: dev up down build test uat eval lint fmt clean

# ── Development ──────────────────────────────────────────────
dev: ## Start full dev stack (infra in Docker, backend+frontend local with hot reload)
	docker compose -f infra/docker-compose.yml up -d postgres redis minio ollama
	@echo "Infra services started. Run backend and frontend separately:"
	@echo "  cd backend && uvicorn btagent_backend.main:app --reload --port 8000"
	@echo "  cd frontend && npm run dev"

up: ## Start full Docker Compose stack
	docker compose -f infra/docker-compose.yml up -d

up-observability: ## Start with observability stack
	docker compose -f infra/docker-compose.yml -f infra/docker-compose.observability.yml up -d

down: ## Stop all services
	docker compose -f infra/docker-compose.yml down

build: ## Build all Docker images
	docker compose -f infra/docker-compose.yml build

# ── Database ─────────────────────────────────────────────────
db-migrate: ## Run Alembic migrations
	cd backend && alembic upgrade head

db-revision: ## Create new Alembic migration (usage: make db-revision msg="add foo table")
	cd backend && alembic revision --autogenerate -m "$(msg)"

db-seed: ## Seed database with test data
	python infra/scripts/seed-data.py

# ── Testing ──────────────────────────────────────────────────
test: test-backend test-agents test-frontend ## Run all unit tests

test-backend: ## Run backend tests
	cd backend && python -m pytest tests/ -v

test-agents: ## Run agent tests
	cd agents && python -m pytest tests/ -v

test-frontend: ## Run frontend tests
	cd frontend && npm run test

uat: ## Run UAT tests (requires running Docker stack)
	python -m pytest tests/uat/ -v --timeout=120

uat-smoke: ## Quick UAT smoke tests
	python -m pytest tests/uat/ -v -m smoke --timeout=60

eval: ## Run agent evaluation (DeepEval)
	python -m pytest tests/agent_eval/ -v

load: ## Run k6 load tests
	k6 run tests/load/api_load.js

e2e: ## Run Playwright E2E tests
	cd tests/e2e && npx playwright test

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
