# BTagent

Purpose-built AI agent for **Defensive Cyber Security** — Incident Response and Proactive Threat Hunting.

## Features

### Phase 1 -- Core Platform
- **PunchList Dashboard** — Single-pane analyst starting point with live investigation status
- **AI-Powered Triage** — Automated alert classification, severity scoring, and MITRE ATT&CK mapping
- **Query Generator** — Natural language to SIEM/EDR queries (Splunk SPL, Elastic KQL, Sentinel KQL, CrowdStrike)
- **Human-in-the-Loop** — Autonomy levels L0-L4 with approval workflows for containment actions
- **MCP Tool Integration** — 9 SIEM/EDR/CTI connectors as Model Context Protocol servers
- **Multi-LLM Routing** — TLP-aware routing across 6 providers (Anthropic, OpenAI, Google, Azure, Bedrock, Ollama)
- **Full Cost Control** — Token budgets, prompt caching, model tiering, per-investigation cost tracking
- **Production-Grade** — JWT auth, RBAC, audit trail, SSL, structured logging, observability

### Phase 2 -- Advanced Capabilities
- **IOC Enrichment Pipeline** — Automated multi-source enrichment with confidence scoring and deduplication
- **Knowledge Base (RAG)** — Hybrid search knowledge agent with pgvector, auto-indexing of investigation findings
- **SOAR Playbooks** — YAML-defined security playbooks compiled to LangGraph subgraphs with HITL gates
- **MITRE ATT&CK Integration** — Technique mapping, coverage analysis, detection gap identification, Navigator export
- **STIX 2.1 Import/Export** — Bidirectional IOC exchange with TLP-aware filtering (TLP:RED blocked from export)

## Quick Start

```bash
# Prerequisites: Docker, Python 3.12, Node 20, uv
git clone https://github.com/nickatnight96/BTagent.git
cd BTagent
cp infra/.env.example infra/.env  # Edit with your API keys
make dev                           # Start everything
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Frontend (React 18 / TypeScript / Zustand)      │
└──────────────────┬──────────────────────────────┘
                   │ WebSocket + REST
┌──────────────────▼──────────────────────────────┐
│  Backend (FastAPI / PostgreSQL / Redis / MinIO)   │
└──────────────────┬──────────────────────────────┘
                   │ In-process async
┌──────────────────▼──────────────────────────────┐
│  Agent Engine (LangGraph / LiteLLM / MCP)        │
│  Orchestrator → Triage | Query | ... workers     │
└─────────────────────────────────────────────────┘
```

## Development

```bash
make dev          # Start dev stack
make test         # Run all tests
make uat          # Run acceptance tests
make lint         # Lint Python + TypeScript
make help         # Show all commands
```

## License

See [LICENSE](LICENSE) for details.
