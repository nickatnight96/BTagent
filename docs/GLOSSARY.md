# Glossary

Terms and definitions used throughout BTagent documentation and codebase.

---

## Security Terms

### CTI -- Cyber Threat Intelligence

Intelligence about threats and threat actors derived from analysis of adversary tactics, techniques, and procedures (TTPs). BTagent integrates CTI sources (VirusTotal, Shodan, GreyNoise, AbuseIPDB, MISP) to enrich IOCs with contextual threat data.

### EDR -- Endpoint Detection and Response

Security solutions that monitor endpoint devices (workstations, servers) for suspicious activity and provide response capabilities. BTagent integrates with CrowdStrike Falcon as an EDR source via MCP connectors.

### HITL -- Human-in-the-Loop

A safety mechanism where the AI agent pauses execution and requests human approval before proceeding with high-impact actions (e.g., host isolation, account disabling). BTagent implements HITL via LangGraph `interrupt_before` nodes with WebSocket-based approval workflows. See [ARCHITECTURE.md](ARCHITECTURE.md) for implementation details.

### IOC -- Indicator of Compromise

An observable artifact that indicates a potential security breach. Common IOC types include IP addresses, domain names, file hashes (SHA-256, SHA-1, MD5), email addresses, URLs, and CVE identifiers. BTagent automatically extracts, enriches, and manages IOCs during investigations.

### MITRE ATT&CK -- Adversarial Tactics, Techniques & Common Knowledge

A globally accessible knowledge base of adversary behavior based on real-world observations. Organized by tactics (the "why" -- e.g., Initial Access, Lateral Movement) and techniques (the "how" -- e.g., T1566 Phishing). BTagent maps triage findings to ATT&CK techniques and provides coverage analysis. See the [MITRE ATT&CK website](https://attack.mitre.org/).

### SIEM -- Security Information and Event Management

Platforms that aggregate, correlate, and analyze log data from across an organization's infrastructure. BTagent integrates with Splunk, Elastic Security, and Microsoft Sentinel via MCP connectors and supports SPL and KQL query generation.

### SOAR -- Security Orchestration, Automation and Response

Technology that enables organizations to automate and streamline security operations workflows. BTagent's playbook system provides SOAR capabilities, compiling YAML-defined playbooks into executable LangGraph subgraphs.

### STIX -- Structured Threat Information Expression

A standardized language for representing and sharing cyber threat intelligence. BTagent supports STIX 2.1 for bidirectional IOC import/export, with TLP enforcement (TLP:RED IOCs are blocked from export). See the [OASIS STIX documentation](https://oasis-open.github.io/cti-documentation/stix/intro).

### TLP -- Traffic Light Protocol

A classification system for sharing sensitive information:

| Level | Meaning | BTagent LLM Routing |
|-------|---------|---------------------|
| **TLP:RED** | Recipients only, no sharing | Local models only (Ollama) |
| **TLP:AMBER+STRICT** | Limited sharing within organization | Ollama, AWS Bedrock |
| **TLP:AMBER** | Organization-wide sharing | Anthropic, Bedrock, Vertex AI |
| **TLP:GREEN** | Community-wide sharing | Most cloud providers |
| **TLP:WHITE** | Unrestricted | All configured providers |

See the [FIRST TLP standard](https://www.first.org/tlp/).

---

## Technology Terms

### JWT -- JSON Web Token

A compact, URL-safe token format for securely transmitting claims between parties. BTagent uses JWT for authentication with access tokens (15-minute expiry) and refresh tokens (7-day expiry). Tokens contain user ID, username, and role claims. See [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519).

### LangGraph

A framework by LangChain for building stateful, multi-step AI agent workflows as directed graphs. BTagent's agent engine uses LangGraph `StateGraph` to define the orchestrator topology (route_task -> worker nodes -> synthesize) with support for loops, conditional edges, and interrupt-based HITL checkpoints.

### MCP -- Model Context Protocol

A protocol for integrating external tools and data sources with LLM-based agents. BTagent uses MCP to connect to 9 SIEM/EDR/CTI systems (Splunk, CrowdStrike, Sentinel, Elastic, VirusTotal, Shodan, GreyNoise, AbuseIPDB, MISP) through a connection pool with circuit breaker patterns.

### pgvector

A PostgreSQL extension for storing and querying vector embeddings. BTagent uses pgvector for the knowledge base's semantic search, storing document chunk embeddings alongside traditional relational data. Supports cosine similarity, inner product, and L2 distance operations.

### RAG -- Retrieval-Augmented Generation

A technique that enhances LLM responses by first retrieving relevant context from a knowledge base, then including that context in the prompt. BTagent's knowledge agent uses hybrid RAG: pgvector cosine similarity + keyword ILIKE + Reciprocal Rank Fusion (RRF) for re-ranking.

### RBAC -- Role-Based Access Control

An authorization model where permissions are assigned to roles, and users are assigned roles. BTagent implements four hierarchical roles: `analyst`, `senior_analyst`, `incident_commander`, `admin`. Each API endpoint and WebSocket action requires specific permissions checked against the user's role.

### ULID -- Universally Unique Lexicographically Sortable Identifier

A 128-bit identifier that is compatible with UUID but lexicographically sortable by creation time. BTagent uses prefixed ULIDs for all entity IDs: `inv_` (investigations), `ioc_` (IOCs), `evt_` (events), `usr_` (users), `cp_` (checkpoints), `tl_` (timeline entries), `kd_` (knowledge documents), `kc_` (knowledge chunks), `pb_` (playbooks), `pbe_` (playbook executions).

---

## See Also

- [Architecture Overview](ARCHITECTURE.md)
- [API Reference](API.md)
- [Analyst Guide](ANALYST_GUIDE.md)
- [Security Policy](../SECURITY.md)
