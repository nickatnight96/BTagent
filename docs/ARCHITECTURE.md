# BTagent Architecture

## System Overview

BTagent is a 3-tier AI agent platform for defensive cyber security operations: incident response and proactive threat hunting. The architecture consists of a React analyst dashboard, a FastAPI backend, and a LangGraph-based multi-agent orchestration engine.

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
 |  Orchestrator -> Worker Subgraphs (triage, query)    |
 |  Plugins   |  Hooks   |  MCP Connectors  |  LLM     |
 +-----------------------------------------------------+
       |                               |
       v                               v
 +-----------+                   +-----------+
 | LiteLLM   |                   | MCP Servers|
 | 6 providers|                  | Splunk     |
 |            |                  | CrowdStrike|
 |            |                  | Sentinel   |
 |            |                  | Elastic    |
 +-----------+                   +-----------+
```

## Component Diagram

```
btagent/
+-- shared/                        Pydantic types, enums, utils (zero heavy deps)
|   +-- types/                     Investigation, Event, MCP, Config, Enums
|   +-- utils/                     ID generation (prefixed ULIDs), secret resolution
|
+-- backend/                       FastAPI application
|   +-- api/v1/                    REST endpoints (auth, investigations, webhooks, config, health)
|   +-- auth/                      JWT issuance/verification, RBAC permission checks
|   +-- db/                        SQLAlchemy ORM models, Alembic migrations
|   +-- ws/                        WebSocket hub (Redis subscriber -> browser fan-out)
|   +-- services/                  Investigation service, TaskManager, audit trail, notifications
|   +-- middleware/                 Rate limiter, request-ID injection
|   +-- observability/             Structured logging, OTEL tracing, Prometheus metrics
|   +-- security/                  Rate limiter (Redis-backed sliding window)
|
+-- agents/                        LangGraph orchestration engine
|   +-- orchestrator/              StateGraph definition, nodes, edges, state schema
|   +-- plugins/                   DefensivePlugin ABC, triage plugin, query plugin
|   +-- hooks/                     7 LangChain callback-based cross-cutting concerns
|   +-- mcp/                       MCP registry, discovery, transports, 4 connector servers
|   +-- llm/                       TLP-aware LLM router, cost calculator
|   +-- events/                    RedisEmitter (agent -> Redis pub/sub)
|   +-- context/                   Token budget estimation, 4-layer context cascade
|   +-- templates/                 Investigation workflow templates (phishing, ransomware, etc.)
|
+-- frontend/                      React 18 SPA
|   +-- components/                Layout, auth, investigations, workspace, UI primitives
|   +-- stores/                    Zustand stores (auth, investigations, agents, events, UI)
|   +-- api/                       REST client (Axios), WebSocket client
|
+-- infra/                         Deployment infrastructure
|   +-- docker-compose.yml         Development and production compose
|   +-- helm/                      Kubernetes Helm chart with values per environment
|   +-- grafana/                   Provisioned dashboards and datasources
|   +-- scripts/                   Seed data, migration helpers
|
+-- tests/                         Cross-package tests
    +-- uat/                       22 automated UAT tests (sprints 1-3)
    +-- load/                      k6 load and WebSocket tests
```

## Data Flow: Alert to Resolution

```
1. Alert Ingestion
   External system (Splunk, CrowdStrike, Sentinel, Elastic)
     -> POST /api/v1/webhooks/{source}
     -> Verify X-Webhook-Secret (HMAC compare_digest)
     -> Normalize severity
     -> Create InvestigationRow (status=pending)
     -> Return 202 Accepted with investigation_id

2. Agent Startup
   TaskManager.start_investigation(inv_id, config)
     -> Build LangGraph from create_investigation_graph()
     -> Wire hooks (EventEmitter, PromptBudget, HITL, Classification, Scope, EvidenceChain)
     -> Invoke graph.ainvoke() with initial state
     -> route_task node classifies intent

3. Agent Execution Loop
   route_task -> triage/query/enrich/contain/report -> synthesize
     -> Synthesize evaluates: more work? HITL needed? done?
     -> If more work: loop back to route_task
     -> If HITL: pause at hitl_checkpoint (interrupt_before)
     -> If done: END

4. Event Streaming
   Agent hook callbacks fire on every LLM/tool event:
     -> RedisEmitter.emit(EventType, **data)
     -> Redis PUBLISH to channel btagent:events:{investigation_id}
     -> WebSocket hub pattern-subscribes to btagent:events:*
     -> Hub fans event to subscribed browser clients
     -> Frontend batches events (50ms) into Zustand stores
     -> React components re-render with live updates

5. Human-in-the-Loop
   Agent proposes containment -> synthesize detects pending actions
     -> Graph pauses at hitl_checkpoint (interrupt_before)
     -> HITL_CHECKPOINT event sent to browser
     -> Analyst approves/rejects via WebSocket hitl_response message
     -> TaskManager resumes graph with human response
     -> hitl_checkpoint_node processes response
     -> If approved: execute node runs containment
     -> If rejected: back to synthesize

6. Completion
   Synthesize detects terminal status (closed, remediated, contained)
     -> should_continue returns END
     -> Graph terminates
     -> INVESTIGATION_COMPLETE event emitted
     -> TaskManager updates DB status
```

## Agent Architecture

### Orchestrator

The orchestrator is a LangGraph `StateGraph` with the following topology:

```
                 +------------+
                 | route_task |  (entry point)
                 +------------+
                       |
          +------------+------------+
          |            |            |
     +---------+  +---------+  +---------+
     | triage  |  | query   |  | enrich  |  ... contain, report
     +---------+  +---------+  +---------+
          |            |            |
          +------------+------------+
                       |
                 +-------------+
                 | synthesize  |  (evaluates next step)
                 +-------------+
                   |    |    |
             continue  hitl  END
                   |    |
          route_task  hitl_checkpoint -> execute -> synthesize
```

**State schema** (`InvestigationState`): A `TypedDict` with 17 fields including `messages` (with `add_messages` reducer), `iocs`, `timeline`, `containment_actions`, `severity`, `tlp_level`, `autonomy_level`, `cost_usd`, and `token_usage`.

**Node functions**:
- `route_task`: Classifies analyst intent via keyword heuristic, then LLM fallback (Haiku-class). Maps to agent node name.
- `triage_node`: Extracts IOCs via regex, scores severity via keyword heuristic, builds timeline entry.
- `query_node`: Generates Splunk SPL and Elastic KQL queries from request text and known IOCs.
- `synthesize_node`: Aggregates results, determines if more work/HITL/completion needed.
- `hitl_checkpoint_node`: Processes human approval/rejection of containment actions.
- Placeholder nodes for enrich, contain, report (phase 2).

**Edge functions**:
- `route_to_agent`: Maps task_type to agent node, with synthesize as fallback.
- `should_continue`: Returns "continue", "hitl", or END based on status and pending actions.
- `after_hitl`: Routes to "execute" (approved) or "synthesize" (rejected).

### Worker Subgraphs

Phase 1 implements two worker subgraphs:

**Triage Agent**: Alert classification, severity scoring, IOC extraction, MITRE ATT&CK mapping. Uses keyword heuristics in phase 1, upgrading to LLM calls in phase 2.

**Query Agent**: Generates Splunk SPL and Elastic KQL queries incorporating known IOCs. Template-based in phase 1, LLM-generated in phase 2.

## Plugin System

Plugins are the primary extension point for adding new security capabilities.

### DefensivePlugin ABC

```python
class DefensivePlugin(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @property
    @abstractmethod
    def version(self) -> str: ...

    @abstractmethod
    def get_tools(self) -> list: ...        # LangChain BaseTool instances

    @abstractmethod
    def get_system_prompt(self) -> str: ...  # Contains {org_profile} placeholder

    @abstractmethod
    def get_metadata(self) -> DefensivePluginMetadata: ...
```

### Plugin Directory Structure

```
plugins/
  triage/
    __init__.py
    plugin.py           # TriagePlugin(DefensivePlugin) class
    module.yaml          # name, description, version, capabilities, supported_data_sources
    system_prompt.md     # Agent system prompt with {org_profile} placeholder
    tools/
      alert_classifier.py   # @tool — classify alert, extract IOCs
      severity_scorer.py     # @tool — 4-dimension severity scoring
  query/
    plugin.py           # QueryPlugin(DefensivePlugin) class
    module.yaml
    system_prompt.md
    tools/
      query_generator.py    # @tool — generate SPL/KQL queries
      query_executor.py     # @tool — execute queries against MCP connectors
```

### Plugin Loading

```python
# plugins/__init__.py
PLUGIN_MODULES = {"triage": "btagent_agents.plugins.triage", "query": "btagent_agents.plugins.query"}

def load_plugin(name: str) -> DefensivePlugin | None:
    # Cache check -> importlib.import_module -> module.plugin attribute -> instantiate
```

## Hook System

BTagent uses 7 hooks implemented as LangChain callback handlers, registered via `HookRegistry`:

| Hook | Purpose | Key Exception |
|------|---------|---------------|
| `EventEmitterHook` | Publishes THINKING/OUTPUT/TOOL_START/TOOL_END events to Redis | -- |
| `PromptBudgetHook` | Tracks token usage, enforces per-investigation token and cost limits | `PromptBudgetExceeded` |
| `HITLHook` | Checks tool calls against autonomy levels, pauses for human approval | `HITLInterrupt` |
| `ClassificationHook` | Enforces TLP classification on LLM routing, blocks TLP:RED to external providers | `TLPViolation` |
| `ScopeEnforcementHook` | Blocks tool calls targeting out-of-scope IPs, domains, CIDRs | `ScopeViolation` |
| `EvidenceChainHook` | Hashes tool outputs (SHA-256) for forensic chain of custody | -- |
| `ScopeEnforcementHook` | Prevents agents from accessing systems outside authorized investigation perimeter | `ScopeViolation` |

**Lifecycle callbacks** (async):
- `on_llm_start` / `on_chat_model_start` — Pre-LLM checks (TLP, budget)
- `on_llm_end` — Post-LLM recording (tokens, cost, classification tagging)
- `on_llm_new_token` — Streaming token relay
- `on_tool_start` — Pre-tool checks (scope, HITL approval)
- `on_tool_end` — Post-tool recording (evidence hashing, duration)
- `on_llm_error` / `on_tool_error` — Error event emission

**Registry pattern**:

```python
registry = HookRegistry()
registry.register(EventEmitterHook(emitter, inv_id))
registry.register(PromptBudgetHook(emitter, accumulator), critical=True)
registry.register(ClassificationHook(emitter, tlp, provider, inv_id), critical=True)
callbacks = registry.get_all_callbacks()
# Pass to LangGraph: config={"callbacks": callbacks}
```

## MCP Integration

### Registry and Connection Pool

`MCPConnectionRegistry` is a singleton thread-safe connection pool:
- Max 50 connections (configurable via `BTAGENT_MCP_POOL_MAX_CONNECTIONS`)
- Per-connection circuit breaker (5 failures -> open, 30s recovery, 2 successes -> close)
- Health check every 60s, keepalive every 45s
- Idle timeout eviction at 300s
- Consumer tracking per investigation

### Circuit Breaker States

```
CLOSED --[5 failures]--> OPEN --[30s]--> HALF_OPEN --[2 successes]--> CLOSED
                           ^                   |
                           +---[1 failure]-----+
```

### Lazy Discovery

`discover_tools()` reads tool metadata (name, description, input_schema) from MCP servers without loading implementations. A single `mcp_router_tool` dispatches requests to the appropriate server, keeping the agent's context window small.

### Connector Servers

| Server | Module | Capabilities |
|--------|--------|-------------|
| Splunk | `splunk_mcp.py` | SPL search, saved searches, alerts, notable events |
| CrowdStrike | `crowdstrike_mcp.py` | Falcon detections, device info, containment actions |
| Sentinel | `sentinel_mcp.py` | Incidents, alerts, entities, hunting queries |
| Elastic | `elastic_mcp.py` | Search, alerts, rules, timeline events |

## LLM Routing

### TLP-Aware Provider Selection

The `TLPAwareLLMRouter` enforces that classified data only reaches authorized providers:

| TLP Level | Allowed Providers |
|-----------|-------------------|
| RED | Ollama (local only) |
| AMBER_STRICT | Ollama, Bedrock |
| AMBER | Anthropic, Bedrock, Vertex AI |
| GREEN | Anthropic, OpenAI, Bedrock, Vertex AI, Ollama |
| WHITE | All 6 providers |

### Model Tiers

| Tier | Use Case | Anthropic | OpenAI | Gemini |
|------|----------|-----------|--------|--------|
| FAST | Triage, classification | claude-haiku-4.5 | gpt-4o-mini | gemini-2.0-flash |
| STANDARD | Query gen, analysis | claude-sonnet-4 | gpt-4o | gemini-2.5-pro |
| PREMIUM | Complex reasoning | claude-opus-4 | o3 | gemini-ultra |
| LOCAL | TLP:RED data | -- | -- | llama3.3 (Ollama) |

### Routing Logic

1. Determine allowed providers for the TLP level
2. If preferred provider is allowed and has the requested tier, use it
3. Otherwise, fall through the allowed list in preference order
4. LOCAL tier falls back to STANDARD if no local model available

## Event System

```
Agent Hook Callback
  -> RedisEmitter.emit(EventType, **data)
  -> EventEnvelope(type, id, investigation_id, parent_id, trace_id, data, timestamp)
  -> Redis PUBLISH to "btagent:events:{investigation_id}"
  -> WebSocket Hub (pattern subscriber on "btagent:events:*")
  -> Fan out to subscribed browser WebSocket connections
  -> Frontend eventStore batches at 50ms intervals
  -> React components consume from Zustand stores
```

**Event types**: THINKING, OUTPUT, OUTPUT_CHUNK, OUTPUT_COMPLETE, TOOL_START, TOOL_END, IOC_DISCOVERED, ALERT_CLASSIFIED, QUERY_GENERATED, HITL_CHECKPOINT, HITL_RESPONSE, HITL_TIMEOUT, TOKEN_USAGE, COST_UPDATE, EVIDENCE_COLLECTED, CONTAINMENT_PROPOSED, CONTAINMENT_APPROVED, CONTAINMENT_EXECUTED, INVESTIGATION_COMPLETE, INVESTIGATION_FAILED, ERROR, NOTIFICATION, SERVER_SHUTDOWN.

**Backpressure**: Critical events (HITL, errors, containment, shutdown) are always delivered. Non-critical events are dropped when a client's queue exceeds 256 pending messages.

## Database Schema

### Core Tables (9)

| Table | Purpose | Key Fields |
|-------|---------|------------|
| `users` | Authentication and RBAC | id, username, email, password_hash, role |
| `investigations` | Case tracking | id, title, status, severity, tlp_level, assigned_to, template, config (JSONB) |
| `iocs` | Indicators of Compromise | id, investigation_id, type, value, confidence, enrichment (JSONB) |
| `timeline_entries` | Chronological event log | id, investigation_id, timestamp, description, technique_id |
| `containment_actions` | Proposed/executed actions | id, investigation_id, action_type, target, status, approved_by |
| `evidence` | Forensic artifacts | id, investigation_id, title, type, content_ref, hash_sha256 |
| `events` | Agent event log | id, investigation_id, type, data (JSONB), parent_id |
| `audit_logs` | Tamper-evident audit trail | id, seq, actor, category, action, outcome, prev_hash, hash |
| `org_config` | Organization settings | id, key, value (JSONB) |

### Sprint 5 Tables (2)

| Table | Purpose | Key Fields |
|-------|---------|------------|
| `cost_tracking` | Per-invocation LLM cost records | id, investigation_id, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, cost_usd |
| `notifications` | User notification inbox | id, user_id, type, title, message, investigation_id, read |

All IDs use prefixed ULIDs (e.g., `inv_01HX...`, `ioc_01HX...`, `usr_01HX...`).

## Authentication and Authorization

### JWT Token Flow

```
POST /api/v1/auth/login { username, password }
  -> Verify bcrypt password hash
  -> Issue TokenPair { access_token (15min), refresh_token (7d) }

POST /api/v1/auth/refresh { refresh_token }
  -> Verify refresh token
  -> Issue new TokenPair

All API requests: Authorization: Bearer <access_token>
  -> decode_token() -> CurrentUser (id, username, role)
  -> require_permission("investigation:create") -> RBAC check
```

### RBAC Roles and Permissions

4 roles in hierarchical order:

| Role | Level | Key Permissions |
|------|-------|----------------|
| analyst | 0 | View/create/chat investigations, view config |
| senior_analyst | 1 | + stop investigations, HITL approve/reject, view users |
| incident_commander | 2 | + approve/execute containment |
| admin | 3 | + edit config, manage users, manage webhooks, delete investigations |

## Security

### Audit Trail

`audit_logs` table uses a hash chain for tamper detection: each record stores `prev_hash` (SHA-256 of previous record) and `hash` (SHA-256 of current record including prev_hash). 7-year retention period.

### Prompt Injection Defense

All external data (alert payloads, webhook data, user-supplied text) is wrapped in `<external-data>` XML tags before injection into LLM prompts. System prompts explicitly instruct agents to treat content within those tags as raw data only, never as instructions.

### TLP Enforcement

The `ClassificationHook` blocks LLM calls that would send classified data to unauthorized providers. TLP:RED data can only be processed by local Ollama models.

### Additional Security Controls

- Rate limiting on all API endpoints (Redis-backed sliding window)
- Request ID tracing (X-Request-ID header)
- CORS origin allowlist
- JWT secret validation (rejects known defaults in non-dev environments)
- bcrypt password hashing
- Webhook secret verification (HMAC constant-time comparison)
- Health endpoint does not leak internal error details

## Deployment

### Docker Compose (Development)

Services: PostgreSQL (pgvector), Redis, MinIO, Ollama, Backend, Frontend, Nginx.

```bash
make dev    # Start infra in Docker, run backend/frontend locally with hot reload
make up     # Start full Docker Compose stack
make down   # Stop all services
```

### Helm Chart (Kubernetes)

Located in `infra/helm/btagent/`. Includes:
- Deployment with configurable replicas and resource limits
- HPA (horizontal pod autoscaler)
- NetworkPolicy for pod-to-pod traffic restrictions
- PDB (pod disruption budget) for availability
- ConfigMap and Secret management
- Ingress with TLS termination
- ServiceAccount with minimal permissions
- Environment-specific values: `values-staging.yaml`, `values-production.yaml`

### Observability

- **Tracing**: OpenTelemetry SDK with OTLP exporter to collector
- **Metrics**: Prometheus scrape endpoint at `/metrics`
- **Logging**: Structured JSON logging via `structlog`
- **Dashboards**: Grafana with provisioned datasources and dashboards
- **LLM Observability**: LangFuse integration (optional)

### Terraform

Infrastructure-as-code for cloud provider resources (VPC, RDS, ElastiCache, S3, EKS cluster). Located in `infra/terraform/`.
