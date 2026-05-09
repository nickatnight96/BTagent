# Changelog

All notable changes to BTagent are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.0] - 2026-03-28 (Phase 3)

### Added
- Coordination/Summarization Bot for agency reports (CISA, FBI, ISAC)
- Document Assistance with 4 report templates (executive summary, technical deep-dive, compliance report, after-action review)
- Playbook-NG: audience-aware remediation generation (executive/technical/compliance)
- Detection content generation (Splunk SPL, Elastic KQL, Sentinel KQL)
- Reports API with 5 endpoints for template management and report generation
- 3 new plugins (coordination, report, mitigation) -- 7 total registered plugins

## [0.2.0] - 2026-03-28 (Phase 2)

### Added
- IOC Enrichment pipeline: 5-stage LangGraph subgraph (select, enrich, score, deduplicate, store)
- 5 CTI MCP servers: VirusTotal, Shodan, MISP, GreyNoise, AbuseIPDB (9 total connectors)
- IOC Notebook UI with inline enrichment, STIX 2.1 import/export
- Knowledge Agent: pgvector RAG with hybrid search (vector + keyword + RRF fusion), auto-indexing of investigation findings and enrichment results
- MITRE ATT&CK integration: keyword-based technique mapping (80+ techniques), coverage analysis, detection gap identification, ATT&CK Navigator layer export
- Visual SOAR Playbook Builder (React Flow): drag-and-drop workflow editor with step validation
- 3 pre-built playbooks: phishing response, ransomware containment, credential compromise
- Playbook compiler with DAG cycle detection and safe condition parser (no eval)
- TLP-aware embedding routing (TLP:RED stays local via Ollama)
- Knowledge injection bridge between RAG pipeline and investigation graph
- 30+ Phase 2 UAT tests and 15 dedicated security UAT tests
- 5 new database tables: mitre_tactics, mitre_techniques, mitre_groups, knowledge_documents, knowledge_chunks, playbooks, playbook_executions

### Security
- Comprehensive Phase 2 security audit: 18 findings identified, 4 critical fixed
- CORS hardened: wildcard methods/headers restricted to explicit allowlist (SEC-P2-001)
- S3 default credentials rejected in non-dev environments (SEC-P2-002)
- Knowledge ingestion size limit enforced at 1MB (SEC-P2-003)
- STIX pattern quote injection prevented via escaping (SEC-P2-004)

## [0.1.0] - 2026-03-26 (Phase 1)

### Added
- FastAPI backend with JWT authentication and RBAC (4 roles: analyst, senior_analyst, incident_commander, admin)
- LangGraph orchestrator: 9 nodes with StateGraph topology, HITL interrupts, configurable autonomy levels (L0--L4)
- Triage agent: automated alert classification, severity scoring, IOC extraction via regex, MITRE ATT&CK mapping
- Query agent: natural language to Splunk SPL and Elastic KQL query generation
- 4 SIEM MCP servers: Splunk, CrowdStrike Falcon, Microsoft Sentinel, Elastic Security
- MCP connection pool: circuit breaker (5 failures to open, 30s recovery), health checks, keepalive, idle eviction
- React 18 frontend: dark-themed PunchList dashboard, AgentChat workspace, EventStream timeline
- WebSocket hub with Redis pub/sub: real-time event streaming with 50ms batching and backpressure (256-message queue limit)
- Webhook ingestion from 4 SIEMs with HMAC secret verification
- TLP-aware LLM routing across 6 providers (Anthropic, OpenAI, Google, Azure/Bedrock, Ollama)
- 4-layer context cascade: externalize, compress, prune, summarize
- Token budgets with per-investigation cost tracking
- SHA-256 chained audit trail with 7-year retention
- Full observability: OpenTelemetry tracing, Prometheus metrics, Grafana dashboards, structured JSON logging
- Docker Compose development and production stack
- Helm chart with HPA, PDB, NetworkPolicy, readOnlyRootFilesystem, drop ALL capabilities
- Terraform skeleton for AWS (VPC, EKS, RDS, ElastiCache)
- GitHub Actions CI/CD: lint, unit tests, agent evaluation (DeepEval), UAT smoke tests
- 22 automated UAT tests across 3 sprints
- Prompt injection defense: `<external-data>` XML boundary wrapping on all untrusted inputs

### Security
- Phase 1 security audit: 21 findings identified, 8 critical/high fixed
- SEC-001: JWT secret startup validation -- refuses to start with known defaults in non-dev (FIXED)
- SEC-002: Seed script random password generation (FIXED)
- SEC-003: Refresh token JTI claim added for future revocation (PARTIAL FIX)
- SEC-004: Health endpoint error sanitization (FIXED)
- SEC-005: LangGraph recursion_limit enforced from config max_steps (FIXED)
- SEC-006: WebSocket RBAC for HITL and chat messages (FIXED)
- SEC-007: require_role dependency uses actual role hierarchy (FIXED)
- SEC-008: Register endpoint validates role against UserRole enum (FIXED)
