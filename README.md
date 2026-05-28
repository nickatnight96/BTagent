<p align="center">
  <h1 align="center">BTagent</h1>
  <p align="center">AI-powered defensive cybersecurity agent for Incident Response and Proactive Threat Hunting.</p>
</p>

<p align="center">
  <a href="https://github.com/nickatnight96/BTagent/actions/workflows/ci.yml"><img src="https://github.com/nickatnight96/BTagent/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/python-3.12+-3776AB.svg" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/node-20+-339933.svg" alt="Node 20+">
  <a href="https://github.com/nickatnight96/BTagent/stargazers"><img src="https://img.shields.io/github/stars/nickatnight96/BTagent?style=social" alt="GitHub Stars"></a>
</p>

---

BTagent combines a **LangGraph multi-agent orchestrator**, **9 MCP connectors** for SIEM/EDR/CTI platforms, and a **React analyst dashboard** into a single platform that automates alert triage, IOC enrichment, SIEM query generation, SOAR playbook execution, and incident reporting -- with full human-in-the-loop controls at every stage.

## Features

| Category | Feature | Description |
|----------|---------|-------------|
| **Core** | PunchList Dashboard | Single-pane analyst workspace with live investigation status |
| **Core** | AI-Powered Triage | Automated alert classification, severity scoring, MITRE ATT&CK mapping |
| **Core** | Query Generator | Natural language to SIEM/EDR queries (Splunk SPL, Elastic KQL, Sentinel KQL, CrowdStrike) |
| **Core** | Human-in-the-Loop | Autonomy levels L0--L4 with approval workflows for containment actions |
| **Intelligence** | IOC Enrichment | 5-stage pipeline with multi-source confidence scoring and deduplication |
| **Intelligence** | Knowledge Base (RAG) | Hybrid search with pgvector, auto-indexing of investigation findings |
| **Automation** | SOAR Playbooks | Visual builder, YAML-defined playbooks compiled to LangGraph subgraphs |
| **Reporting** | Document Assistance | 4 report templates, audience-aware remediation, detection content generation |

**Security controls:** TLP-aware LLM routing, SHA-256 chained audit trail, scope enforcement, prompt injection defenses, JWT + RBAC (4 roles).

## Architecture

```
 Analyst Browser                           External Systems
 +-----------+                             +-----------+
 | React SPA | <--- WebSocket (events) --- | SIEM/EDR  |
 | Zustand   | --- REST (CRUD, auth) ----> | Webhooks  |
 +-----------+                             +-----------+
       |                                        |
       v                                        v
 +-----------------------------------------------------+
 |                   FastAPI Backend                     |
 |  /api/v1/*   /ws   /webhooks/*   /health   /metrics  |
 |  Auth(JWT)   RBAC   Rate Limiter   RequestID         |
 +-----------------------------------------------------+
       |               |               |
       v               v               v
 +----------+   +-----------+   +-----------+
 | Postgres |   |   Redis   |   |   MinIO   |
 | pgvector |   | pub/sub   |   | evidence  |
 +----------+   +-----------+   +-----------+
                      ^
                      |
 +-----------------------------------------------------+
 |             LangGraph Agent Engine                   |
 |  Orchestrator -> Worker Subgraphs                    |
 |  Triage | Query | Enrich | Knowledge | Playbook      |
 |  7 Hooks | 7 Plugins | 4-layer context cascade       |
 +-----------------------------------------------------+
       |                               |
       v                               v
 +-----------+                   +-------------+
 | LiteLLM   |                   | MCP Servers |
 | 6 providers|                  | Splunk      | CrowdStrike
 | TLP-aware  |                  | Sentinel    | Elastic
 | routing    |                  | VirusTotal  | Shodan
 +-----------+                   | GreyNoise   | AbuseIPDB
                                 | MISP        |
                                 +-------------+
```

## Quick Start

### One-command local dev (5 minutes)

```bash
git clone https://github.com/nickatnight96/BTagent.git
cd BTagent
./infra/scripts/dev-setup.sh    # prereq check + docker infra + venv + migrations + seed
```

Then in two terminals:

```bash
# Terminal A — backend
source .venv/bin/activate
BTAGENT_ENV=test \
  BTAGENT_JWT_SECRET="dev-secret-for-local-only" \
  BTAGENT_DATABASE_URL="postgresql+asyncpg://btagent:btagent_dev_password@localhost:5432/btagent" \
  BTAGENT_REDIS_URL="redis://localhost:6379" \
  uvicorn btagent_backend.main:app --reload --port 8000 --app-dir backend

# Terminal B — frontend
cd frontend && npm run dev
```

Open `http://localhost:3000` and log in with `admin` / `admin` (seeded by `dev-setup.sh` in test mode).

### Manual setup (if the script can't run)

```bash
git clone https://github.com/nickatnight96/BTagent.git
cd BTagent
cp infra/.env.example infra/.env    # edit with your API keys
make dev                             # docker infra
uv venv .venv --python 3.12 && source .venv/bin/activate
uv pip install -e shared/ -e engine/ -e agents/ -e "backend/[dev]"
cd frontend && npm install && cd ..
make db-migrate
BTAGENT_ENV=test python infra/scripts/seed-data.py
# then the two terminal commands from the one-command path above
```

Backend: `http://localhost:8000` | Frontend: `http://localhost:3000` | API docs: `http://localhost:8000/api/docs`

> **Note:** See [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) for the full step-by-step guide with environment variable walkthrough.

## Screenshots

| Dashboard | Investigation | Playbook Builder |
|-----------|---------------|------------------|
| ![PunchList Dashboard](docs/images/dashboard-dark.png) | ![Agent Chat](docs/images/investigation-dark.png) | ![SOAR Builder](docs/images/playbook-builder-dark.png) |

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Vite, Zustand, TailwindCSS, React Flow |
| Backend | FastAPI, Python 3.12, SQLAlchemy (async), Alembic, Pydantic v2 |
| Agent Engine | LangGraph, LangChain, LiteLLM (6 LLM providers) |
| Tool Protocol | Model Context Protocol (MCP) -- 9 connectors |
| Database | PostgreSQL 16 + pgvector |
| Cache/Pubsub | Redis 7 |
| Object Storage | MinIO (S3-compatible) |
| Local LLM | Ollama |
| Observability | OpenTelemetry, Prometheus, Grafana, LangFuse |
| Infrastructure | Docker Compose, Helm (Kubernetes), Terraform (AWS) |
| CI/CD | GitHub Actions |

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/GETTING_STARTED.md) | Full setup guide with environment walkthrough |
| [Architecture](docs/ARCHITECTURE.md) | System design, data flows, agent topology |
| [API Reference](docs/API.md) | REST, WebSocket, and webhook endpoint reference |
| [Deployment](docs/DEPLOYMENT.md) | Docker Compose, Kubernetes, and AWS deployment |
| [Deployment Plan](docs/DEPLOYMENT_PLAN.md) | Production deploy blockers, readiness, and roadmap sequencing |
| [SIEM Setup](docs/SIEM_SETUP.md) | Splunk, CrowdStrike, Sentinel, and Elastic connector guides |
| [Playbook Schema](docs/PLAYBOOK_SCHEMA.md) | SOAR playbook YAML reference |
| [Knowledge Base](docs/KNOWLEDGE_BASE.md) | RAG pipeline architecture and configuration |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [Security Audit](docs/SECURITY_AUDIT.md) | Phase 1 security findings and remediations |
| [Security Audit (Phase 2)](docs/SECURITY_AUDIT_PHASE2.md) | Phase 2 security findings |
| [Contributing](docs/CONTRIBUTING.md) | Development setup, plugin guide, PR process |
| [Changelog](CHANGELOG.md) | Version history |

## Contributing

We welcome contributions. Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for:

- Development environment setup
- How to add new plugins, MCP connectors, and hooks
- Code style guidelines (ruff, ESLint, mypy strict)
- PR process and CI pipeline

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md) for our disclosure policy.

For the latest audit results, see:
- [Phase 1 Security Audit](docs/SECURITY_AUDIT.md) -- 21 findings, 8 critical/high fixed
- [Phase 2 Security Audit](docs/SECURITY_AUDIT_PHASE2.md) -- 18 findings, 4 critical fixed

## License

MIT License. See [LICENSE](LICENSE) for details.
