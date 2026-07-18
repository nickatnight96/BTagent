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
- UAT: 52+ automated acceptance tests across Phase 1 (22) and Phase 2 (30+)
- Security UAT: 15 dedicated security tests (prompt injection, RBAC, audit, TLP, JWT)
- E2E: Playwright browser tests
- Agent eval: DeepEval with golden datasets (runs in CI on every PR)
- Load: k6

## Agent Architecture
- Orchestrator routes tasks to worker subgraphs (Triage, Query, Enrich, Knowledge)
- Plugins: 4 registered plugins (triage, query, enrichment, knowledge)
- Hooks: HITL, EventEmitter, PromptBudget, EvidenceChain, ScopeEnforcement, Classification
- MCP: 20+ SIEM/EDR/identity/email/cloud/ticketing connectors as MCP servers with circuit breaker + connection pooling; each declares a capability manifest (#100) enforcing HITL/TLP/OCSF policy at dispatch
- LLM: Task-appropriate model routing (Haiku→triage, Sonnet→query, Opus→analysis)
- Context: 4-layer cascade (externalize → compress → prune → summarize)

## Phase 2 Features
- **IOC Enrichment Pipeline**: 5-stage LangGraph subgraph (select, enrich, score, dedup, store)
- **Knowledge Agent (RAG)**: Hybrid search (pgvector + keyword + RRF), auto-indexing, knowledge injection
- **SOAR Playbooks**: YAML-defined playbooks compiled to LangGraph subgraphs (action, decision, HITL gate, parallel)
- **MITRE ATT&CK**: Keyword mapper (80+ techniques), coverage analysis, Navigator export
- **STIX 2.1**: Bidirectional IOC import/export with TLP enforcement (TLP:RED blocked)

## Phase 2 Stores
- `knowledge_documents` / `knowledge_chunks` — pgvector RAG knowledge base
- `playbooks` / `playbook_executions` — SOAR playbook definitions and execution history
- `mitre_tactics` / `mitre_techniques` / `mitre_groups` — ATT&CK matrix data

## MCP Connectors (#100 connector strategy)
The agents-side MCP server registry (`agents/btagent_agents/mcp/servers/`,
registered in `discovery._SERVER_CLASSES`) plus the engine's CTI-enrichment
integration nodes. Every connector is mock-first (`BTAGENT_MOCK_CONNECTORS`
default), resolves secrets lazily via `${secret:...}` / `${env:...}` refs, and
guards live mode behind `NotImplementedError`. Each declares a
`ConnectorManifest` (`mcp/manifests.py`) — the drift-locked source of truth for
its query/action capabilities, TLP egress, OCSF emit classes, and HITL gating.

- **SIEM:** Splunk, Microsoft Sentinel, Elastic
- **EDR / XDR:** CrowdStrike, Defender for Endpoint, SentinelOne, Palo Alto Cortex XDR
- **Identity:** Okta, Microsoft Entra ID, Google Workspace, Cisco Duo
- **Email security:** Defender for O365, Proofpoint TAP, Mimecast
- **Web proxy:** Zscaler ZIA
- **Network:** Zeek / Corelight
- **Cloud audit / posture:** AWS CloudTrail+GuardDuty, GCP Cloud Audit+SCC, Wiz (CNAPP)
- **Ticketing / comms:** Jira Service Management, ServiceNow SecOps, Slack
- **Detection repo:** Git (HITL-gated PR composer)
- **CTI enrichment (engine nodes):** VirusTotal, Shodan, GreyNoise, AbuseIPDB, MISP

All connectors surface (read-only, RBAC-gated) via `GET /connectors` and the
frontend Settings → Integrations catalog; per-org credential *references* bind
through the credential-reference API (raw material stays in Vault/AWS/env).

Containment actions (`cs_isolate_host`, `mde_isolate_machine`,
`s1_mitigate_threat`, `cortex_isolate_endpoint`) and the detection-repo PR
composer are HITL-gated; on-prem telemetry declares `TLP.RED`, org-tenant
clouds `TLP.AMBER_STRICT`.
