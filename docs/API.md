# BTagent API Reference

Base URL: `http://localhost:8000`

All authenticated endpoints require `Authorization: Bearer <access_token>`.

## Health

### GET /health

Health check with DB and Redis connectivity status. No authentication required.

**Response 200**:
```json
{
  "status": "ok",
  "env": "dev",
  "version": "0.1.0",
  "database": "connected",
  "redis": "not_configured"
}
```

When degraded:
```json
{
  "status": "degraded",
  "env": "dev",
  "version": "0.1.0",
  "database": "unreachable",
  "redis": "not_configured"
}
```

---

## Authentication

### POST /api/v1/auth/login

Authenticate user and receive a JWT token pair.

**Request**:
```json
{
  "username": "analyst1",
  "password": "s3cureP@ss"
}
```

**Response 200**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer"
}
```

**Response 401**:
```json
{
  "detail": "Invalid username or password"
}
```

### POST /api/v1/auth/refresh

Exchange a refresh token for a new token pair.

**Request**:
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response 200**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer"
}
```

**Response 401**:
```json
{
  "detail": "Invalid refresh token"
}
```

### POST /api/v1/auth/register

Register a new user. Requires `admin` role.

**Request**:
```json
{
  "username": "analyst2",
  "email": "analyst2@acme.com",
  "password": "s3cureP@ss",
  "role": "analyst"
}
```

Valid roles: `analyst`, `senior_analyst`, `incident_commander`, `admin`.

**Response 201**:
```json
{
  "id": "usr_01HX...",
  "username": "analyst2",
  "role": "analyst"
}
```

**Response 409**:
```json
{
  "detail": "Username or email already exists"
}
```

### GET /api/v1/auth/me

Get current user info from the JWT.

**Response 200**:
```json
{
  "id": "usr_01HX...",
  "username": "analyst1",
  "role": "analyst"
}
```

---

## Investigations

### POST /api/v1/investigations

Create a new investigation and start the agent. Requires `investigation:create` permission.

**Request**:
```json
{
  "title": "Phishing campaign targeting finance",
  "description": "Multiple employees received spoofed emails from ceo@acm3.com",
  "severity": "medium",
  "tlp_level": "green",
  "template": "phishing"
}
```

Fields:
- `title` (required): Investigation title.
- `description` (optional): Detailed description.
- `severity` (optional): `critical`, `high`, `medium` (default), `low`, `info`.
- `tlp_level` (optional): `red`, `amber_strict`, `amber`, `green` (default), `white`.
- `template` (optional): `phishing`, `ransomware`, `unauthorized_access`, or `null`.

**Response 201**:
```json
{
  "id": "inv_01HX...",
  "case_id": null,
  "title": "Phishing campaign targeting finance",
  "description": "Multiple employees received spoofed emails from ceo@acm3.com",
  "status": "pending",
  "severity": "medium",
  "tlp_level": "green",
  "assigned_to": "usr_01HX...",
  "template": "phishing",
  "created_at": "2026-03-26T12:00:00+00:00",
  "updated_at": "2026-03-26T12:00:00+00:00",
  "closed_at": null
}
```

### GET /api/v1/investigations

List investigations with pagination. Requires `investigation:view` permission.

**Query Parameters**:
- `page` (default 1): Page number.
- `page_size` (default 20, max 100): Items per page.
- `status` (optional): Filter by status.

**Response 200**:
```json
{
  "items": [
    {
      "id": "inv_01HX...",
      "case_id": null,
      "title": "Phishing campaign targeting finance",
      "description": "...",
      "status": "investigating",
      "severity": "medium",
      "tlp_level": "green",
      "assigned_to": "usr_01HX...",
      "template": "phishing",
      "created_at": "2026-03-26T12:00:00+00:00",
      "updated_at": "2026-03-26T12:05:00+00:00",
      "closed_at": null
    }
  ],
  "total": 42,
  "page": 1,
  "page_size": 20
}
```

### GET /api/v1/investigations/{investigation_id}

Get investigation detail. Requires `investigation:view` permission.

**Response 200**: Same shape as items in the list response.

**Response 404**:
```json
{
  "detail": "Investigation not found"
}
```

### POST /api/v1/investigations/{investigation_id}/pause

Pause a running investigation. Requires `investigation:pause` permission.

Only works when status is `investigating` or `triaging`.

**Response 200**:
```json
{
  "status": "paused",
  "investigation_id": "inv_01HX..."
}
```

**Response 400**:
```json
{
  "detail": "Cannot pause investigation in status: closed"
}
```

### POST /api/v1/investigations/{investigation_id}/resume

Resume a paused investigation. Requires `investigation:resume` permission.

Only works when status is `paused` or `paused_hitl`.

**Response 200**:
```json
{
  "status": "resumed",
  "investigation_id": "inv_01HX..."
}
```

### POST /api/v1/investigations/{investigation_id}/stop

Stop a running investigation. Requires `investigation:stop` permission (senior_analyst+).

Sets status to `cancelled` and closes the investigation.

**Response 200**:
```json
{
  "status": "cancelled",
  "investigation_id": "inv_01HX..."
}
```

### POST /api/v1/investigations/{investigation_id}/chat

Send a message to the investigation's agent. Requires `investigation:chat` permission.

**Request**:
```json
{
  "message": "Search Splunk for connections to 198.51.100.23 in the last 24 hours"
}
```

**Response 200**:
```json
{
  "status": "sent",
  "investigation_id": "inv_01HX...",
  "message": "Search Splunk for connections to 198.51.100.23 in the last 24 hours"
}
```

---

## Webhooks

All webhook endpoints require the `X-Webhook-Secret` header matching the configured webhook secret. They return 202 Accepted with the created investigation ID.

### POST /api/v1/webhooks/splunk

Receive a Splunk alert webhook.

**Request**:
```json
{
  "search_name": "Failed SSH Logins > 50",
  "app": "search",
  "owner": "admin",
  "results_link": "https://splunk.acme.com/en-US/app/search/search?sid=1234",
  "result": {
    "src_ip": "198.51.100.23",
    "dest_ip": "10.1.2.3",
    "action": "failure"
  },
  "sid": "1234",
  "severity": "high"
}
```

**Response 202**:
```json
{
  "investigation_id": "inv_01HX...",
  "status": "accepted"
}
```

### POST /api/v1/webhooks/crowdstrike

Receive a CrowdStrike Falcon detection webhook.

**Request**:
```json
{
  "detection_id": "ldt:abc123",
  "display_name": "Cobalt Strike Beacon Activity",
  "description": "Beacon detected communicating with known C2 infrastructure",
  "max_severity_displayname": "High",
  "hostname": "WORKSTATION-42",
  "tactic": "Command and Control",
  "technique": "T1071.001",
  "device": {"platform_name": "Windows", "os_version": "10.0.19045"},
  "behaviors": [{"behavior_id": "1", "pattern_disposition": "detect"}]
}
```

**Response 202**: Same shape as Splunk response.

### POST /api/v1/webhooks/sentinel

Receive a Microsoft Sentinel incident webhook.

**Request**:
```json
{
  "incident_id": "inc-2026-0042",
  "title": "Impossible travel activity",
  "description": "User login from US and China within 5 minutes",
  "severity": "High",
  "status": "New",
  "classification": "",
  "alerts": [{"alert_id": "a1", "display_name": "Impossible travel"}],
  "entities": [{"kind": "Account", "name": "jdoe@acme.com"}]
}
```

**Response 202**: Same shape as Splunk response.

### POST /api/v1/webhooks/elastic

Receive an Elastic SIEM alert webhook.

**Request**:
```json
{
  "rule_id": "r-001",
  "rule_name": "Suspicious PowerShell Execution",
  "alert_id": "alert-5678",
  "severity": "high",
  "description": "PowerShell with encoded command detected on production server",
  "source": {"host": {"name": "PROD-WEB-01"}},
  "kibana_url": "https://kibana.acme.com/app/security/alerts/alert-5678",
  "hits": [{"_source": {"process.command_line": "powershell -enc ..."}}]
}
```

**Response 202**: Same shape as Splunk response.

---

## Config

### GET /api/v1/config/org-profile

Get the organisation profile. Requires `config:view` permission.

**Response 200**:
```json
{
  "profile": {
    "name": "Acme Corp",
    "industry": "financial_services",
    "size": "enterprise",
    "security_tools": ["splunk", "crowdstrike", "sentinel"],
    "critical_assets": ["domain controllers", "payment systems"],
    "compliance_frameworks": ["PCI-DSS", "SOC2"]
  }
}
```

### PUT /api/v1/config/org-profile

Update the organisation profile. Requires `config:org_profile` permission (admin only).

**Request**: Same shape as the `profile` object in the GET response.

**Response 200**: Same shape as GET response.

### GET /api/v1/config/retention

Get data retention statistics. Requires `config:view` permission.

**Response 200**:
```json
{
  "events": {
    "total_count": 125000,
    "oldest_event": "2025-12-01T00:00:00+00:00",
    "retention_days": 90
  },
  "audit_logs": {
    "total_count": 50000,
    "oldest_log": "2020-01-01T00:00:00+00:00",
    "retention_years": 7
  },
  "investigations": {
    "total_count": 340,
    "closed_count": 280,
    "active_count": 60
  }
}
```

### POST /api/v1/config/retention/run

Trigger a data retention cleanup. Requires `config:edit` permission (admin only).

**Response 200**:
```json
{
  "events": {
    "deleted_count": 5000,
    "cutoff_date": "2025-12-26T00:00:00+00:00"
  },
  "investigations": {
    "archived_count": 15,
    "cutoff_date": "2025-12-26T00:00:00+00:00"
  },
  "audit_verification": {
    "chain_valid": true,
    "records_checked": 50000
  }
}
```

---

## WebSocket Protocol

### Connection

```
ws://localhost:8000/ws?token=<access_token>
```

The WebSocket connection requires a valid JWT access token passed as a query parameter. The server validates the token on connection and closes the socket if invalid.

### Client to Server Messages

All messages are JSON with a `type` field.

#### subscribe

Subscribe to events for an investigation.

```json
{
  "type": "subscribe",
  "investigation_id": "inv_01HX..."
}
```

Server response:
```json
{
  "type": "subscribed",
  "data": {"investigation_id": "inv_01HX..."}
}
```

#### unsubscribe

Unsubscribe from investigation events.

```json
{
  "type": "unsubscribe",
  "investigation_id": "inv_01HX..."
}
```

#### chat

Send a chat message to the investigation agent.

```json
{
  "type": "chat",
  "investigation_id": "inv_01HX...",
  "data": {
    "message": "Search for lateral movement from 10.1.2.3"
  }
}
```

#### hitl_response

Respond to a human-in-the-loop checkpoint.

```json
{
  "type": "hitl_response",
  "investigation_id": "inv_01HX...",
  "data": {
    "checkpoint_id": "cp_01HX...",
    "approved": true,
    "comment": "Approved - isolate the host immediately"
  }
}
```

### Server to Client Messages

Agent events are forwarded as `EventEnvelope` objects:

```json
{
  "type": "thinking",
  "id": "evt_01HX...",
  "investigation_id": "inv_01HX...",
  "parent_id": null,
  "trace_id": "trace_01HX...",
  "timestamp": "2026-03-26T12:00:00.123Z",
  "data": {
    "model": "claude-sonnet-4-20250514",
    "run_id": "abc123"
  }
}
```

Event types include: `thinking`, `output`, `output_chunk`, `tool_start`, `tool_end`, `ioc_discovered`, `alert_classified`, `query_generated`, `hitl_checkpoint`, `hitl_response`, `token_usage`, `cost_update`, `evidence_collected`, `containment_proposed`, `containment_approved`, `investigation_complete`, `error`, `notification`.

Protocol-level messages (not agent events):

```json
{
  "type": "error",
  "data": {"message": "Invalid investigation ID"}
}
```

### Backpressure

Critical events (HITL checkpoints, errors, containment actions, shutdown) are always delivered. Non-critical events may be dropped when a client's pending queue exceeds 256 messages.

---

## IOCs (Phase 2)

### GET /api/v1/iocs

List IOCs for an investigation. Requires `ioc:view` permission.

**Query Parameters**:
- `investigation_id` (required): Filter by investigation.
- `page` (default 1): Page number.
- `page_size` (default 20, max 100): Items per page.
- `type` (optional): Filter by IOC type (ip, domain, hash_sha256, etc.).

**Response 200**:
```json
{
  "items": [
    {
      "id": "ioc_01HX...",
      "investigation_id": "inv_01HX...",
      "type": "ip",
      "value": "198.51.100.23",
      "tlp_level": "green",
      "confidence": 0.85,
      "first_seen": "2026-03-26T12:00:00+00:00",
      "last_seen": "2026-03-26T12:05:00+00:00",
      "source": "auto_extraction",
      "enrichment": {}
    }
  ],
  "total": 15,
  "page": 1,
  "page_size": 20
}
```

### POST /api/v1/iocs

Create a new IOC. Requires `ioc:create` permission.

**Request**:
```json
{
  "investigation_id": "inv_01HX...",
  "type": "ip",
  "value": "198.51.100.23",
  "tlp_level": "green",
  "confidence": 0.5,
  "context": "Source IP from failed SSH attempts",
  "source": "manual"
}
```

**Response 201**: IOC object.

### POST /api/v1/iocs/{ioc_id}/enrich

Trigger enrichment for a specific IOC. Requires `ioc:enrich` permission. Returns 202 Accepted.

**Response 202**:
```json
{
  "status": "accepted",
  "ioc_id": "ioc_01HX...",
  "message": "Enrichment queued"
}
```

### GET /api/v1/iocs/{ioc_id}/stix

Export a single IOC as a STIX 2.1 Indicator. TLP:RED IOCs are blocked.

**Response 200**: STIX 2.1 Indicator JSON object.

### POST /api/v1/iocs/stix/import

Import IOCs from a STIX 2.1 Bundle. Requires `ioc:create` permission.

**Request**: STIX 2.1 Bundle JSON.

**Response 201**:
```json
{
  "imported_count": 5,
  "investigation_id": "inv_01HX..."
}
```

---

## MITRE ATT&CK (Phase 2)

### GET /api/v1/mitre/techniques

List MITRE ATT&CK techniques. Requires authentication.

**Query Parameters**:
- `tactic` (optional): Filter by tactic shortname (e.g. "initial-access").
- `search` (optional): Text search across technique names and descriptions.
- `page` (default 1): Page number.
- `page_size` (default 50): Items per page.

**Response 200**:
```json
{
  "items": [
    {
      "technique_id": "T1566.001",
      "name": "Phishing: Spearphishing Attachment",
      "description": "Adversaries may send spearphishing emails...",
      "tactic_ids": ["initial-access"],
      "data_sources": ["Email", "File monitoring"]
    }
  ],
  "total": 200
}
```

### GET /api/v1/mitre/tactics

List MITRE ATT&CK tactics in kill-chain order.

**Response 200**: Array of tactic objects with ordinal, name, and shortname.

### GET /api/v1/mitre/coverage

Get detection coverage map for the organisation.

**Response 200**:
```json
{
  "coverage": {
    "T1566.001": {"detected": true, "data_sources": ["email_gateway"]},
    "T1059.001": {"detected": false, "data_sources": []}
  },
  "total_techniques": 200,
  "covered_count": 85,
  "coverage_percentage": 42.5
}
```

### GET /api/v1/mitre/navigator

Export an ATT&CK Navigator layer JSON file.

**Response 200**: ATT&CK Navigator layer JSON (Content-Type: application/json).

---

## Knowledge Base (Phase 2)

### POST /api/v1/knowledge/ingest

Ingest a document into the knowledge base. Requires `knowledge:ingest` permission (senior_analyst+).

**Request**:
```json
{
  "title": "Ransomware Response Playbook",
  "content": "Full document text...",
  "source_type": "policy_document",
  "metadata": {"category": "incident_response"}
}
```

Valid source types: `policy_document`, `runbook`, `threat_report`, `investigation_report`, `enrichment_data`, `cti_feed`, `other`.

**Response 201**:
```json
{
  "id": "kd_01HX...",
  "title": "Ransomware Response Playbook",
  "source_type": "policy_document",
  "chunk_count": 12,
  "token_count": 3500
}
```

### POST /api/v1/knowledge/query

Search the knowledge base using hybrid search (vector + keyword + RRF). Requires `knowledge:query` permission.

**Request**:
```json
{
  "query": "How should we respond to ransomware?",
  "top_k": 5,
  "source_type_filter": null
}
```

**Response 200**:
```json
{
  "query": "How should we respond to ransomware?",
  "results": [
    {
      "chunk_content": "Step 1: Isolate affected systems...",
      "document_title": "Ransomware Response Playbook",
      "source_type": "policy_document",
      "relevance_score": 0.032787,
      "document_id": "kd_01HX...",
      "chunk_id": "kc_01HX..."
    }
  ],
  "total_results": 3
}
```

### GET /api/v1/knowledge/documents

List knowledge base documents. Requires `knowledge:query` permission.

**Query Parameters**:
- `source_type` (optional): Filter by source type.
- `page` (default 1): Page number.
- `page_size` (default 20): Items per page.

**Response 200**: Paginated document list.

### DELETE /api/v1/knowledge/documents/{document_id}

Delete a document and its chunks. Requires `knowledge:delete` permission (admin only).

**Response 204**: No content.

---

## Playbooks (Phase 2)

### GET /api/v1/playbooks

List playbooks. Requires `playbook:view` permission.

**Response 200**:
```json
{
  "items": [
    {
      "id": "pb_01HX...",
      "name": "Phishing Response",
      "version": "1.0",
      "description": "Automated phishing investigation",
      "trigger_type": "alert_severity",
      "is_active": true,
      "created_at": "2026-03-26T12:00:00+00:00"
    }
  ],
  "total": 3
}
```

### POST /api/v1/playbooks

Create a new playbook. Requires `playbook:create` permission (senior_analyst+).

**Request**:
```json
{
  "name": "Custom Playbook",
  "yaml_content": "name: Custom Playbook\ntrigger:\n  type: manual\nsteps:\n  ..."
}
```

**Response 201**: Playbook object with validation result.

### GET /api/v1/playbooks/{playbook_id}

Get playbook detail. Requires `playbook:view` permission.

### PUT /api/v1/playbooks/{playbook_id}

Update playbook YAML. Requires `playbook:edit` permission.

### DELETE /api/v1/playbooks/{playbook_id}

Delete a playbook. Requires `playbook:delete` permission (admin only).

### POST /api/v1/playbooks/{playbook_id}/validate

Validate playbook YAML without saving. Returns validation result with errors and warnings.

### POST /api/v1/playbooks/{playbook_id}/execute

Execute a playbook for an investigation. Requires `playbook:execute` permission.

**Request**:
```json
{
  "investigation_id": "inv_01HX...",
  "trigger_data": {"severity": "high"}
}
```

**Response 202**:
```json
{
  "execution_id": "pbe_01HX...",
  "status": "running",
  "playbook_id": "pb_01HX..."
}
```

### GET /api/v1/playbooks/{playbook_id}/executions

List execution history for a playbook. Returns execution records with status and step results.

### GET /api/v1/playbooks/executions/{execution_id}

Get execution detail including step-by-step results.

---

## Metrics

### GET /metrics

Prometheus metrics scrape endpoint. No authentication required.

Returns standard Prometheus text format with:
- HTTP request counts and latencies
- WebSocket connection counts
- Agent task counts and durations
- LLM token usage and costs
- Database connection pool statistics
