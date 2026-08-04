# BTagent Roadmap

Public roadmap for BTagent development. Phases are cumulative -- each builds on the previous.

---

## v0.1.0 -- Phase 1: Foundation

**Status: Complete**

Core platform with AI-powered incident response capabilities.

- PunchList Dashboard with live investigation status
- AI-powered triage: alert classification, severity scoring, IOC extraction
- Query generator: natural language to SIEM queries (Splunk SPL, Elastic KQL, Sentinel KQL, CrowdStrike)
- Human-in-the-Loop: autonomy levels L0-L4 with approval workflows for containment actions
- MCP tool integration: 4 SIEM/EDR connectors (Splunk, CrowdStrike, Sentinel, Elastic)
- Multi-LLM routing: TLP-aware routing across 6 providers (Anthropic, OpenAI, Google, Azure, Bedrock, Ollama)
- Full cost control: token budgets, prompt caching, model tiering, per-investigation cost tracking
- Production-grade: JWT auth, RBAC (4 roles), audit trail (hash-chained), SSL, structured logging
- WebSocket real-time event streaming with backpressure handling
- Investigation templates: phishing, ransomware, unauthorized access
- 22 automated UAT tests

---

## v0.2.0 -- Phase 2: Advanced Capabilities

**Status: Complete**

Advanced security analysis, knowledge management, and automation.

- IOC enrichment pipeline: 5-stage LangGraph subgraph with multi-source confidence scoring and deduplication
- 5 additional CTI MCP connectors: VirusTotal, Shodan, GreyNoise, AbuseIPDB, MISP
- Knowledge base (RAG): hybrid search (pgvector + keyword + RRF), auto-indexing of investigation findings
- SOAR playbooks: YAML-defined playbooks compiled to LangGraph subgraphs with HITL gates
- MITRE ATT&CK integration: technique mapping (80+ keywords), coverage analysis, detection gap identification, Navigator export
- STIX 2.1 import/export: bidirectional IOC exchange with TLP-aware filtering
- IOC Notebook: centralized IOC management across investigations
- Playbook Builder: visual YAML editor for custom playbooks
- 30+ additional UAT tests (Phase 2 features)
- 15 dedicated security UAT tests

---

## v0.3.0 -- Phase 3: Agency Tools

**Status: Complete**

Enhanced agent capabilities and operational tooling.

- MCP connection pool: max 50 connections with circuit breaker (5 failures -> open, 30s recovery)
- Scope enforcement hook: blocks agent actions targeting out-of-scope systems
- Evidence chain hook: SHA-256 hashing of all tool outputs for forensic chain of custody
- 4-layer context cascade: externalize -> compress -> prune -> summarize
- Playbook execution history and monitoring
- Knowledge base auto-indexing on investigation completion
- Agent evaluation framework: DeepEval with golden datasets
- Load testing: k6 API and WebSocket tests

---

## v0.4.0 -- Phase 4: Production Hardening

**Status: Planned**

Focus on production readiness, performance, and enterprise integrations.

### Real SIEM/EDR Connector Implementations
- Replace mock/stub MCP connectors with production API clients
- Splunk REST API and HEC integration
- CrowdStrike Falcon API with OAuth2 client credentials
- Microsoft Sentinel via Azure Resource Graph
- Elastic Security via Elasticsearch REST API
- VirusTotal v3 API with rate limit handling
- Shodan API with search credit management

### Authentication Hardening
- JWT token revocation with Redis-backed deny list
- Refresh token rotation (one-time use)
- SAML 2.0 SSO integration
- OIDC (OpenID Connect) SSO integration
- Multi-factor authentication (TOTP)
- Session management with concurrent session limits

### Report Export
- PDF report generation with configurable templates
- Executive summary, timeline, IOC table, MITRE mapping sections
- Custom branding and formatting
- Scheduled report generation and email delivery

### Performance Optimization
- Database query optimization and index tuning
- Redis caching layer for frequently accessed data
- Connection pool tuning for high-concurrency deployments
- Frontend bundle size optimization and code splitting
- WebSocket message compression

### Operational Improvements
- Health check endpoint enhancements (deep health with dependency checks)
- Graceful shutdown with in-flight request draining
- Configuration validation on startup
- Database migration safety checks

---

## v0.5.0 -- Phase 5: Enterprise Features

**Status: Planned**

Enterprise-scale features for large organizations.

### Multi-Tenancy
- Organization-scoped data isolation
- Per-tenant configuration and branding
- Tenant-aware RBAC and resource quotas
- Cross-tenant admin capabilities

### Threat Feed Ingestion
- STIX/TAXII 2.1 client for automated threat feed consumption
- Scheduled feed polling and incremental updates
- Feed-to-IOC matching with automatic enrichment
- Feed quality scoring and source reliability tracking

### IOC Relationship Graph
- Neo4j integration for IOC relationship visualization
- Automatic relationship extraction (IP -> domain -> hash -> campaign)
- Graph-based threat hunting queries
- Visual relationship explorer in the frontend

### Cross-Investigation Learning
- Pattern recognition across completed investigations
- Similar investigation detection and recommendation
- Automated runbook generation from investigation patterns
- Investigation outcome prediction

### Additional Planned Items
- Webhook output (notify external systems of findings)
- Custom dashboard builder
- API rate limiting per tenant/user with configurable quotas
- Audit log export (SIEM integration)
- Compliance reporting (SOC 2, ISO 27001)

---

## v0.6.0 -- Phase 6: Proactive Threat Hunting

**Status: Planned**

The proactive counterpart to incident response. Where Phases 1--3 react to alerts, Phase 6 hunts before the alert fires. Built on the Hunter plugin foundation ([#99](https://github.com/nickatnight96/BTagent/issues/99)) and the differentiation strategy ([#98](https://github.com/nickatnight96/BTagent/issues/98), Bets 1 and 5), this phase delivers nine agentic hunt workflows spanning the PEAK hunt taxonomy (hypothesis-driven, baseline-driven) and the 2026 threat surface (identity, cloud, agentic-AI).

These are tracked as peer feature issues, not a single epic. The dependency keystone is the shared `HuntFinding` contract ([#119](https://github.com/nickatnight96/BTagent/issues/119)), which every hunt source emits into and which bridges hunting back to the existing investigation pipeline.

> Full engineering design, schemas, and PR sequencing: [Phase 6 Threat Hunting Implementation Design](PHASE6_THREAT_HUNTING_PLAN.md).

### Hypothesis-driven hunting (PEAK)
- **Hunt Pack Runner** ([#112](https://github.com/nickatnight96/BTagent/issues/112)) -- scheduled Sigma execution, multi-backend transpile (pysigma -> SPL/KQL/EQL/CrowdStrike), per-environment noise-baseline tuning. Requires the arq scheduler ([#101](https://github.com/nickatnight96/BTagent/issues/101) Pattern 4).
- **Cross-Investigation Pattern Hunter** ([#120](https://github.com/nickatnight96/BTagent/issues/120)) -- walks the closed-investigation corpus in pgvector, surfaces recurring weak signals, and proposes hunts. The hunting expression of closed-loop org memory ([#98](https://github.com/nickatnight96/BTagent/issues/98) Bet 3).

### Baseline-driven hunting (PEAK)
- **Behavioral Hunter** ([#114](https://github.com/nickatnight96/BTagent/issues/114)) -- Living-off-the-Land detection via command-line embeddings and parent-child anomaly scoring, with LLM intent reasoning. Reuses the existing pgvector substrate; no custom ML training.

### Detection engineering closed loop (Bet 1)
- **CTI -> Detection pipeline** ([#113](https://github.com/nickatnight96/BTagent/issues/113)) -- CTI-REALM-style: report/STIX -> TTP extraction -> Sigma draft -> telemetry validation -> detection-as-code PR. Human-in-the-loop mandatory.
- **Detection Validation Agent** ([#118](https://github.com/nickatnight96/BTagent/issues/118)) -- purple-team loop: Atomic Red Team / Caldera emulation -> SIEM observation -> coverage-delta feedback. Closes the loop opened by #112 and #113.

### Domain-specialized hunters (2026 threat surface)
- **Identity Hunt Agent** ([#116](https://github.com/nickatnight96/BTagent/issues/116)) -- OAuth token abuse, dormant-app reactivation, SaaS supply-chain hunts (Salesloft/Drift/Vercel class). Gated on Okta + Entra ID + Google Workspace connectors ([#100](https://github.com/nickatnight96/BTagent/issues/100) Tier 1).
- **Cloud Control-Plane Hunter** ([#117](https://github.com/nickatnight96/BTagent/issues/117)) -- STS abuse, IAM persistence, and shadow-agent discovery across AWS/Azure/GCP. Gated on cloud connectors ([#100](https://github.com/nickatnight96/BTagent/issues/100) Tier 1/2).
- **Agentic-AI Misuse Hunter** ([#121](https://github.com/nickatnight96/BTagent/issues/121)) -- prompt-injection detection, shadow MCP server discovery, and agent-identity drift. The defensive counterpart to the agentic enterprise.

### Triage and pipeline integration
- **Hunt Triage Agent** ([#119](https://github.com/nickatnight96/BTagent/issues/119)) -- defines the shared `HuntFinding` contract, clusters findings, learns persistent suppressions, and promotes confirmed hits into the existing investigation workflow.

### Sequencing
```
[#101 arq scheduler] ──▶ [#112 Hunt Pack Runner] ──┐
[#119 HuntFinding contract] ──────────────────────┼──▶ all hunt sources emit findings
                                                   │
[#100 connectors] ──▶ [#116 Identity] [#117 Cloud] ┘
[#113 CTI->Detection] ◀──▶ [#118 Validation]  (detection-engineering loop)
[#98 Bet 3 memory] ──▶ [#120 Cross-Investigation]
```

---

## Known Limitations

The following are known limitations in the current release. Several are addressed in the roadmap above. For the must-fix deployment blockers and the sequenced path to a first production deploy, see the [Deployment Plan](DEPLOYMENT_PLAN.md).

> This table is checked against the code by `backend/tests/test_roadmap_limitations.py`.
> Every row below asserts something the code actually still does *not* do, and the
> test fails if a retired limitation is re-added or a live one silently gets fixed
> without the doc catching up. It exists because this table had gone stale in six
> of nine rows — see "Resolved" below.

| Area | Limitation | Planned Fix |
|------|-----------|-------------|
| **MCP Connectors** | All 27 registered connectors are **mock-first**: every live API path raises `NotImplementedError` behind `BTAGENT_MOCK_CONNECTORS` (default on). The manifests, policy gates, and OCSF mappings are real; the network calls are not. | #100 -- live connector wiring, one Tier-1 at a time |
| **Detection Validation** | Adversary emulation is sandbox-only. Atomic Red Team / Caldera execution against real hosts is not wired, and the emulation service refuses any non-sandbox `target_env`. | #118 -- pending offensive-tooling sign-off |
| **Agent Evaluation** | `make eval` scores only the deterministic components (MITRE mapper, triage classifier, severity scorer) against a golden dataset. No live-LLM judging of investigation transcripts. | #382 v2 -- DeepEval, behind an explicit opt-in |
| **IOC Graphs** | IOC relationships are stored flat in PostgreSQL. No graph database, so multi-hop pivots are application-side joins rather than traversals. | v0.5.0 -- graph backend |
| **Seed Data** | `make db-seed` inserts a demo investigation and sample users. Not for production — use `bt create-admin` instead. (Passwords are no longer the issue: outside test mode seeded users get random, unrecoverable passwords.) | Documented; no fix planned |
| **Staging Deploy** | No staging cluster is wired, so merges to `main` do not continuously deploy anywhere. | #140 / DEPLOYMENT_PLAN B6 |

### Resolved

These were listed as limitations here long after they shipped. Recorded so the
change is visible to anyone who read the old table, and pinned by the guard test
so they cannot creep back in:

- **JWT security** — refresh tokens rotate within a family (`fid`), reuse of a
  consumed token is detected and revokes the family, and an admin can force-revoke
  every outstanding session for a user (`POST /auth/revoke/{user_id}`).
- **SSO** — SAML 2.0 and generic OIDC are both implemented, with JIT provisioning.
- **Reports** — `GET /reports/investigations/{id}/export?format=pdf` renders a PDF.
- **Multi-tenancy** — every tenant-owned table carries `org_id`, routes scope to the
  caller's org, and cross-tenant access returns 404 rather than leaking existence.
- **Threat feeds** — TAXII 2.1 subscriptions poll on a schedule and ingest through
  the STIX path, with TLP derived from each object's markings.
- **CORS** — methods and headers are explicit allow-lists, and the backend refuses
  to start in prod on a wildcard or localhost origin.


---

## Contributing

We welcome contributions to any roadmap item. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to get started. If you are interested in working on a specific feature, open an issue to discuss the approach before submitting a PR.

---

## Feedback

Have a feature idea not on the roadmap? [Open a feature request](https://github.com/nickatnight96/BTagent/issues/new?template=feature_request.yml) and tell us about your use case.
