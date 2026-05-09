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

## Known Limitations

The following are known limitations in the current release. Several are addressed in the roadmap above.

| Area | Limitation | Planned Fix |
|------|-----------|-------------|
| **MCP Connectors** | All 9 connectors use mock/stub implementations. Set `BTAGENT_MOCK_CONNECTORS=true` for development. | v0.4.0 -- Real API implementations |
| **JWT Security** | Refresh tokens are not rotated and cannot be revoked. | v0.4.0 -- Token revocation and rotation |
| **SSO** | Only username/password authentication. No SAML or OIDC. | v0.4.0 -- SSO integration |
| **Reports** | Reports are text-only within the application. No PDF export. | v0.4.0 -- PDF export |
| **Multi-Tenancy** | Single-tenant only. All users share one organization. | v0.5.0 -- Multi-tenancy |
| **IOC Graphs** | IOC relationships are stored flat. No graph database. | v0.5.0 -- Neo4j integration |
| **Threat Feeds** | Manual STIX import only. No automated feed ingestion. | v0.5.0 -- TAXII client |
| **Seed Data** | Default seed script uses trivial passwords. Not for production. | v0.4.0 -- Secure defaults |
| **CORS** | Development config uses wildcard methods/headers. Restrict in production. | v0.4.0 -- Hardened CORS |

---

## Contributing

We welcome contributions to any roadmap item. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to get started. If you are interested in working on a specific feature, open an issue to discuss the approach before submitting a PR.

---

## Feedback

Have a feature idea not on the roadmap? [Open a feature request](https://github.com/nickatnight96/BTagent/issues/new?template=feature_request.yml) and tell us about your use case.
