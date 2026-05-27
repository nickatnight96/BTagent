# Getting Started with BTagent

This guide walks you through setting up BTagent for local development, from prerequisites through running your first investigation.

## Prerequisites

| Tool | Version | Purpose | Install |
|------|---------|---------|---------|
| Docker | 24+ | Infrastructure services | [docker.com](https://docs.docker.com/get-docker/) |
| Docker Compose | v2+ | Service orchestration | Included with Docker Desktop |
| Python | 3.12+ | Backend and agent engine | [python.org](https://www.python.org/downloads/) |
| uv | latest | Python package manager | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Node.js | 20+ | Frontend build toolchain | [nodejs.org](https://nodejs.org/) |
| Git | 2.40+ | Version control | [git-scm.com](https://git-scm.com/) |

Verify your tools:

```bash
docker --version          # Docker version 24.x+
docker compose version    # Docker Compose version v2.x+
python3 --version         # Python 3.12+
uv --version              # uv 0.x+
node --version            # v20.x+
git --version             # git version 2.40+
```

## 1. Clone and Setup

```bash
git clone https://github.com/nickatnight96/BTagent.git
cd BTagent
```

## 2. Environment Configuration

Create the environment file from the template:

```bash
cp infra/.env.example infra/.env
```

Open `infra/.env` and configure the following variables:

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `BTAGENT_JWT_SECRET` | JWT signing secret. Generate with `openssl rand -hex 32` | `a1b2c3d4e5f6...` (64 hex chars) |
| `BTAGENT_DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://btagent:btagent@localhost:5432/btagent` |
| `BTAGENT_REDIS_URL` | Redis connection string | `redis://localhost:6379` |

### LLM Provider Keys (at least one required)

| Variable | Description |
|----------|-------------|
| `BTAGENT_OPENAI_API_KEY` | OpenAI API key (used for embeddings and LLM calls) |
| `ANTHROPIC_API_KEY` | Anthropic API key (default LLM provider) |
| `GOOGLE_API_KEY` | Google AI API key (Gemini models) |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BTAGENT_ENV` | `dev` | Environment: `dev`, `staging`, `prod` |
| `BTAGENT_LOG_LEVEL` | `info` | Logging level: `debug`, `info`, `warning`, `error` |
| `BTAGENT_MOCK_CONNECTORS` | `false` | Set `true` to use mock SIEM/CTI connectors without real API keys |
| `BTAGENT_S3_ENDPOINT` | `http://localhost:9000` | MinIO/S3 endpoint for evidence storage |
| `BTAGENT_S3_ACCESS_KEY` | `minioadmin` | MinIO/S3 access key (change for non-dev) |
| `BTAGENT_S3_SECRET_KEY` | `minioadmin` | MinIO/S3 secret key (change for non-dev) |
| `BTAGENT_EMBEDDING_PROVIDER` | `openai` | Embedding provider: `openai` or `ollama` |
| `BTAGENT_OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama endpoint for local LLM/embedding |
| `BTAGENT_OTEL_ENABLED` | `false` | Enable OpenTelemetry tracing |
| `BTAGENT_OTEL_ENDPOINT` | `http://localhost:4317` | OTLP collector endpoint |
| `BTAGENT_LANGFUSE_ENABLED` | `false` | Enable LangFuse LLM observability |
| `BTAGENT_RATE_LIMIT_ENABLED` | `true` | Enable API rate limiting |
| `BTAGENT_EVENT_RETENTION_DAYS` | `90` | Days to retain agent events |
| `BTAGENT_AUDIT_RETENTION_YEARS` | `7` | Years to retain audit logs |
| `BTAGENT_DEFAULT_MODEL_PROVIDER` | `anthropic` | Preferred LLM provider |
| `BTAGENT_DEFAULT_MODEL_ID` | `claude-sonnet-4-20250514` | Default model for standard tasks |
| `BTAGENT_SLACK_BOT_TOKEN` | (empty) | Slack bot token for notifications |
| `BTAGENT_SLACK_CHANNEL` | (empty) | Slack channel for alerts |

> **Tip:** For a quick start without external API keys, set `BTAGENT_MOCK_CONNECTORS=true` and `BTAGENT_EMBEDDING_PROVIDER=ollama`. This runs everything locally.

## 3. Start Infrastructure

Start the infrastructure services in Docker:

```bash
make dev
```

This starts four containers:

| Service | Port | Purpose |
|---------|------|---------|
| PostgreSQL (pgvector) | 5432 | Primary database with vector extension |
| Redis | 6379 | Event pub/sub, caching, rate limiting |
| MinIO | 9000 (API), 9001 (Console) | S3-compatible evidence storage |
| Ollama | 11434 | Local LLM for TLP:RED data |

Verify the services are running:

```bash
make wait-healthy
```

## 4. Install Python Dependencies

BTagent uses a monorepo workspace with four Python packages — `shared`, `engine`, `agents`, and `backend`. The order matters: `agents` depends on `engine`, both depend on `shared`. Install them in one shot inside a `uv`-managed virtualenv:

```bash
uv venv .venv --python 3.12
source .venv/bin/activate
uv pip install -e shared/ -e engine/ -e agents/ -e "backend/[dev]"
```

> **Note:** `uv pip install -e` (editable install) is what wires the workspace path-deps so changes in `shared/` land in `engine/` and `agents/` without re-installing. `uv sync` per-package does not handle the cross-package path references correctly for this layout.

## 5. Run Database Migrations

Apply all Alembic migrations to create the database schema:

```bash
make db-migrate
```

This creates all tables including:
- Core tables: users, investigations, iocs, timeline_entries, containment_actions, evidence, events, audit_logs, org_config
- Cost and notification tables: cost_tracking, notifications
- Phase 2 tables: mitre_tactics, mitre_techniques, mitre_groups, knowledge_documents, knowledge_chunks, playbooks, playbook_executions

## 6. Seed Initial Data

Populate the database with test users and sample data:

```bash
BTAGENT_ENV=test python infra/scripts/seed-data.py
```

The seed script creates:
- An admin user
- An analyst user and a senior analyst user
- A sample investigation
- MITRE ATT&CK tactic and technique data

In **test mode** (`BTAGENT_ENV=test`) the script prints **deterministic** credentials so the local dev loop is reproducible:

```
Seed data created (test mode — deterministic credentials):
  Admin user:    admin / admin
  Analyst user:  analyst1 / analyst1
  Senior user:   senior1 / senior1
```

In any other environment (`BTAGENT_ENV=dev`, `staging`, `prod`) the script generates random passwords and prints them to stdout — **copy them from the terminal immediately, they are not stored anywhere else.**

## 7. Start the Backend

In a new terminal:

```bash
source .venv/bin/activate
BTAGENT_ENV=test \
  BTAGENT_JWT_SECRET="dev-secret-for-local-only" \
  BTAGENT_DATABASE_URL="postgresql+asyncpg://btagent:btagent_password@localhost:5432/btagent" \
  BTAGENT_REDIS_URL="redis://localhost:6379" \
  uvicorn btagent_backend.main:app --reload --port 8000 --app-dir backend
```

Flags:
- `--reload`: Auto-restart on file changes (development only)
- `--port 8000`: Listen on port 8000
- `--app-dir backend`: Tell uvicorn where the `btagent_backend` package lives so you don't have to `cd` into `backend/` first

Verify the backend is running:

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{
  "status": "ok",
  "env": "test",
  "version": "0.1.0",
  "database": "connected",
  "redis": "connected"
}
```

## 8. Start the Frontend

In another terminal:

```bash
cd frontend && npm run dev
```

(Skip `npm install` if you already ran it in step 4 / the one-command setup script.)

The Vite dev server starts at `http://localhost:3000` with hot module replacement. The port is set explicitly in `frontend/vite.config.ts:13` and the dev server proxies `/api/*` and `/ws/*` to the backend on `:8000` automatically.

> Production builds served via `vite preview` (and the Docker / Helm ingress) listen on `:5173`; that's the URL the E2E suite expects. For day-to-day dev hot-reload, use `:3000`.

## 9. Verify the Setup

1. **Health check:** `curl http://localhost:8000/health` returns `"status": "ok"`
2. **API docs:** Open `http://localhost:8000/api/docs` for the Swagger UI
3. **Login:** Open `http://localhost:3000`, log in with `admin` / `admin` (test mode default) or with the credentials the seed script printed (other envs)
4. **Dashboard:** The PunchList dashboard loads with an empty investigation list

## First Investigation Walkthrough

### Step 1: Create an Investigation

From the PunchList dashboard, click **New Investigation** and fill in:
- **Title:** Suspicious login from unknown IP
- **Severity:** Medium
- **TLP Level:** Green
- **Template:** (leave blank for general investigation)

Alternatively, use the API:

```bash
curl -X POST http://localhost:8000/api/v1/investigations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Suspicious login from unknown IP",
    "description": "User jdoe logged in from 198.51.100.23 at 03:00 UTC",
    "severity": "medium",
    "tlp_level": "green"
  }'
```

### Step 2: Triage

The agent automatically starts triage:
- Extracts IOCs from the description (IP addresses, domains, hashes, emails)
- Classifies the alert severity
- Suggests MITRE ATT&CK techniques
- Builds an initial timeline entry

Watch the real-time event stream in the AgentChat workspace.

### Step 3: Enrich IOCs

After triage, the agent routes high/critical-severity investigations to the enrichment pipeline. You can also manually trigger enrichment:

```bash
curl -X POST http://localhost:8000/api/v1/iocs/$IOC_ID/enrich \
  -H "Authorization: Bearer $TOKEN"
```

The enrichment pipeline queries configured CTI sources (VirusTotal, Shodan, GreyNoise, AbuseIPDB, MISP) and scores confidence from 0.0 to 1.0.

### Step 4: Chat with the Agent

In the AgentChat workspace, type natural language requests:

```
Search Splunk for connections to 198.51.100.23 in the last 24 hours
```

The query agent generates Splunk SPL and Elastic KQL queries from your request, incorporating known IOCs.

### Step 5: Generate a Report

When the investigation is complete, request a report:

```
Generate an executive summary of this investigation
```

The agent produces a formatted report with findings, IOC summary, timeline, and recommended actions.

## Common Issues

### Port Conflicts

**Symptom:** `docker compose up` fails with "port is already allocated."

**Solution:** Stop the conflicting service or change the port mapping in `infra/docker-compose.yml`:

```bash
# Check what is using port 5432
lsof -i :5432

# Or change the host port in docker-compose.yml
# ports:
#   - "5433:5432"  # Map to host port 5433 instead
```

### Database Connection Refused

**Symptom:** Backend fails with `connection refused` on startup.

**Solution:**
1. Verify PostgreSQL is running: `docker compose -f infra/docker-compose.yml ps postgres`
2. Check the health status: `docker compose -f infra/docker-compose.yml exec postgres pg_isready -U btagent`
3. Ensure `BTAGENT_DATABASE_URL` matches the Docker Compose configuration
4. Wait for the health check: `make wait-healthy`

### Missing Environment Variables

**Symptom:** Backend refuses to start with a `ValueError` about JWT secret or S3 credentials.

**Solution:** In non-dev environments, BTagent requires:
- `BTAGENT_JWT_SECRET`: At least 32 characters, not a known default
- `BTAGENT_S3_ACCESS_KEY`: Not `minioadmin` in staging/production

For development, set `BTAGENT_ENV=dev` to allow default values.

### Redis Not Connected

**Symptom:** Health check shows `"redis": "not_configured"` and WebSocket events do not stream.

**Solution:**
1. Verify Redis is running: `docker compose -f infra/docker-compose.yml exec redis redis-cli ping`
2. Check `BTAGENT_REDIS_URL` is set correctly
3. Redis is required for WebSocket event streaming and rate limiting

### Ollama Models Not Available

**Symptom:** TLP:RED investigations fail with "no local model available."

**Solution:** Pull a model into Ollama:

```bash
docker compose -f infra/docker-compose.yml exec ollama ollama pull llama3.3
```

### Migration Errors

**Symptom:** `alembic upgrade head` fails with version conflicts.

**Solution:**
1. Check the current migration version: `cd backend && alembic current`
2. If the database is empty, ensure PostgreSQL is running and the pgvector extension is available
3. For version conflicts, check `alembic history` and resolve manually

> **Tip:** See [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md) for a comprehensive list of issues and solutions.

## Next Steps

- [Architecture](ARCHITECTURE.md) -- understand the system design and data flows
- [API Reference](API.md) -- explore the REST, WebSocket, and webhook APIs
- [SIEM Setup](SIEM_SETUP.md) -- connect Splunk, CrowdStrike, Sentinel, or Elastic
- [Deployment](DEPLOYMENT.md) -- deploy to production with Docker Compose, Kubernetes, or AWS
- [Contributing](CONTRIBUTING.md) -- add plugins, MCP connectors, or hooks
