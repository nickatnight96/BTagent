# BTagent — Defensive Cyber Security AI Agent

## Project Overview
BTagent is a purpose-built AI agent platform for Defensive Cyber Security, focused on Incident Response and Proactive Threat Hunting. It combines a LangGraph-based multi-agent orchestration engine with a React analyst dashboard, FastAPI backend, and MCP-based integrations across SIEM, EDR, CTI, and ticketing systems.

## Architecture
Three-tier: React frontend → FastAPI backend → LangGraph agent engine
- **Frontend:** React 18 / TypeScript / Vite / Zustand / TailwindCSS (dark mode, security-themed)
- **Backend:** FastAPI / Python 3.12 / PostgreSQL+pgvector / Redis / MinIO
- **Agent Engine:** LangGraph / LiteLLM (6 providers) / MCP tool protocol

## Monorepo Structure
```
shared/     → Pydantic types, enums, utils (zero heavy deps)
backend/    → FastAPI app, DB, WebSocket hub, auth, observability
agents/     → LangGraph orchestrator, plugins, hooks, MCP, LLM routing
frontend/   → React SPA
infra/      → Docker Compose, Helm, Terraform, nginx
tests/      → UAT, E2E, agent evaluation, load tests
```

## Package Management
- Python: `uv` workspaces. Each package has own `pyproject.toml`.
- Frontend: npm
- Local deps: `btagent-shared = {path = "../shared", develop = true}`

## Development
```bash
make dev        # Start infra (Docker) + backend (uvicorn --reload) + frontend (vite dev)
make test       # Run all unit tests
make uat        # Run UAT suite (requires Docker stack)
make lint       # ruff check + tsc
make fmt        # ruff format
```

## Key Conventions
- Python: ruff (line-length 100), mypy strict, pytest-asyncio auto mode
- TypeScript: strict mode, path aliases (@/), ESLint
- All external data in agent prompts wrapped in `<external-data>` XML tags
- IDs use prefixed ULIDs: inv_, ioc_, evt_, usr_, etc.
- Events flow: Agent hook → Redis pub/sub → WebSocket hub → browser (50ms batched)
- Auth: JWT + RBAC (analyst, senior_analyst, incident_commander, admin)
- Secrets: `${secret:vault:path}` / `${secret:aws:name}` / `${env:VAR}` pattern

## Testing
- Unit: pytest (backend, agents) + vitest (frontend)
- UAT: 22 automated acceptance tests (pytest + httpx + websockets)
- E2E: Playwright browser tests
- Agent eval: DeepEval with golden datasets (runs in CI on every PR)
- Load: k6

## Agent Architecture
- Orchestrator routes tasks to worker subgraphs (TriageAgent, QueryAgent in Phase 1)
- Plugins: DefensivePlugin ABC with get_tools(), get_system_prompt()
- Hooks: HITL, EventEmitter, PromptBudget, EvidenceChain, ScopeEnforcement, Classification
- MCP: SIEM/EDR connectors as MCP servers with circuit breaker + connection pooling
- LLM: Task-appropriate model routing (Haiku→triage, Sonnet→query, Opus→analysis)
- Context: 4-layer cascade (externalize → compress → prune → summarize)
