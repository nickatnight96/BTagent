# BTagent API Usage Examples

Practical examples for common API operations. Each example is shown in both cURL and Python (httpx).

For the full API reference, see [API.md](API.md).

---

## Table of Contents

- [Authentication](#authentication)
- [Create an Investigation](#create-an-investigation)
- [Send a Chat Message](#send-a-chat-message)
- [Create and Enrich IOCs](#create-and-enrich-iocs)
- [Search IOCs Across Investigations](#search-iocs-across-investigations)
- [Query the Knowledge Base](#query-the-knowledge-base)
- [Generate a Report](#generate-a-report)
- [Execute a Playbook](#execute-a-playbook)
- [WebSocket Connection](#websocket-connection)

---

## Authentication

### Login and Obtain Tokens

**cURL:**

```bash
# Login
curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst1", "password": "s3cureP@ss"}' | jq .

# Response:
# {
#   "access_token": "eyJhbGciOiJIUzI1NiIs...",
#   "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
#   "token_type": "bearer"
# }

# Store the token for subsequent requests
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst1", "password": "s3cureP@ss"}' | jq -r '.access_token')
```

**Python (httpx):**

```python
import httpx

BASE_URL = "http://localhost:8000"

# Login
response = httpx.post(f"{BASE_URL}/api/v1/auth/login", json={
    "username": "analyst1",
    "password": "s3cureP@ss",
})
response.raise_for_status()
tokens = response.json()

access_token = tokens["access_token"]
refresh_token = tokens["refresh_token"]

# Create a client with the token for subsequent requests
client = httpx.Client(
    base_url=BASE_URL,
    headers={"Authorization": f"Bearer {access_token}"},
)
```

### Refresh an Expired Token

**cURL:**

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}" | jq .
```

**Python (httpx):**

```python
response = httpx.post(f"{BASE_URL}/api/v1/auth/refresh", json={
    "refresh_token": refresh_token,
})
response.raise_for_status()
tokens = response.json()
access_token = tokens["access_token"]

# Update the client headers
client.headers["Authorization"] = f"Bearer {access_token}"
```

### Check Current User

**cURL:**

```bash
curl -s http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer $TOKEN" | jq .

# Response:
# {
#   "id": "usr_01HX...",
#   "username": "analyst1",
#   "role": "analyst"
# }
```

**Python (httpx):**

```python
response = client.get("/api/v1/auth/me")
response.raise_for_status()
user = response.json()
print(f"Logged in as {user['username']} (role: {user['role']})")
```

---

## Create an Investigation

### From Scratch

**cURL:**

```bash
curl -s -X POST http://localhost:8000/api/v1/investigations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Phishing campaign targeting finance",
    "description": "Multiple employees received spoofed emails from ceo@acm3.com with malicious attachments",
    "severity": "high",
    "tlp_level": "green",
    "template": "phishing"
  }' | jq .

# Response:
# {
#   "id": "inv_01HX...",
#   "title": "Phishing campaign targeting finance",
#   "status": "pending",
#   "severity": "high",
#   "tlp_level": "green",
#   "template": "phishing",
#   ...
# }
```

**Python (httpx):**

```python
response = client.post("/api/v1/investigations", json={
    "title": "Phishing campaign targeting finance",
    "description": "Multiple employees received spoofed emails from ceo@acm3.com with malicious attachments",
    "severity": "high",
    "tlp_level": "green",
    "template": "phishing",
})
response.raise_for_status()
investigation = response.json()
inv_id = investigation["id"]
print(f"Created investigation: {inv_id}")
```

### List Investigations with Filtering

**cURL:**

```bash
# List all active investigations
curl -s "http://localhost:8000/api/v1/investigations?status=investigating&page=1&page_size=10" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Python (httpx):**

```python
response = client.get("/api/v1/investigations", params={
    "status": "investigating",
    "page": 1,
    "page_size": 10,
})
response.raise_for_status()
result = response.json()
print(f"Found {result['total']} active investigations")
for inv in result["items"]:
    print(f"  [{inv['severity']}] {inv['title']} ({inv['status']})")
```

### Pause and Resume

**cURL:**

```bash
# Pause a running investigation
curl -s -X POST "http://localhost:8000/api/v1/investigations/$INV_ID/pause" \
  -H "Authorization: Bearer $TOKEN" | jq .

# Resume it later
curl -s -X POST "http://localhost:8000/api/v1/investigations/$INV_ID/resume" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Python (httpx):**

```python
# Pause
response = client.post(f"/api/v1/investigations/{inv_id}/pause")
response.raise_for_status()
print(f"Investigation paused: {response.json()['status']}")

# Resume
response = client.post(f"/api/v1/investigations/{inv_id}/resume")
response.raise_for_status()
print(f"Investigation resumed: {response.json()['status']}")
```

---

## Send a Chat Message

Send a message to the investigation's AI agent. The agent processes the message and streams results back via WebSocket.

**cURL:**

```bash
curl -s -X POST "http://localhost:8000/api/v1/investigations/$INV_ID/chat" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Search Splunk for all connections to 198.51.100.23 from internal hosts in the last 24 hours"
  }' | jq .

# Response:
# {
#   "status": "sent",
#   "investigation_id": "inv_01HX...",
#   "message": "Search Splunk for all connections to 198.51.100.23 from internal hosts in the last 24 hours"
# }
```

**Python (httpx):**

```python
response = client.post(f"/api/v1/investigations/{inv_id}/chat", json={
    "message": "Search Splunk for all connections to 198.51.100.23 from internal hosts in the last 24 hours",
})
response.raise_for_status()
print(f"Message sent: {response.json()['status']}")

# To see the agent's response, connect via WebSocket (see WebSocket section below)
```

---

## Create and Enrich IOCs

### Create an IOC Manually

**cURL:**

```bash
curl -s -X POST http://localhost:8000/api/v1/iocs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"investigation_id\": \"$INV_ID\",
    \"type\": \"ip\",
    \"value\": \"198.51.100.23\",
    \"tlp_level\": \"green\",
    \"confidence\": 0.5,
    \"context\": \"Source IP from failed SSH login attempts\",
    \"source\": \"manual\"
  }" | jq .
```

**Python (httpx):**

```python
response = client.post("/api/v1/iocs", json={
    "investigation_id": inv_id,
    "type": "ip",
    "value": "198.51.100.23",
    "tlp_level": "green",
    "confidence": 0.5,
    "context": "Source IP from failed SSH login attempts",
    "source": "manual",
})
response.raise_for_status()
ioc = response.json()
ioc_id = ioc["id"]
print(f"Created IOC: {ioc_id} ({ioc['type']}: {ioc['value']})")
```

### Enrich an IOC

Enrichment queries configured CTI sources (VirusTotal, Shodan, GreyNoise, AbuseIPDB, MISP) and updates the IOC with reputation data and confidence scoring.

**cURL:**

```bash
curl -s -X POST "http://localhost:8000/api/v1/iocs/$IOC_ID/enrich" \
  -H "Authorization: Bearer $TOKEN" | jq .

# Response:
# {
#   "status": "accepted",
#   "ioc_id": "ioc_01HX...",
#   "message": "Enrichment queued"
# }
```

**Python (httpx):**

```python
response = client.post(f"/api/v1/iocs/{ioc_id}/enrich")
response.raise_for_status()
print(f"Enrichment status: {response.json()['status']}")
# Enrichment runs asynchronously. Poll the IOC or listen on WebSocket for results.
```

### Export an IOC as STIX 2.1

**cURL:**

```bash
curl -s "http://localhost:8000/api/v1/iocs/$IOC_ID/stix" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Python (httpx):**

```python
response = client.get(f"/api/v1/iocs/{ioc_id}/stix")
response.raise_for_status()
stix_indicator = response.json()
print(f"STIX type: {stix_indicator['type']}")
print(f"Pattern: {stix_indicator.get('pattern', 'N/A')}")
```

### Import IOCs from STIX 2.1 Bundle

**cURL:**

```bash
curl -s -X POST "http://localhost:8000/api/v1/iocs/stix/import?investigation_id=$INV_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "bundle",
    "id": "bundle--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "objects": [
      {
        "type": "indicator",
        "id": "indicator--a1b2c3d4-e5f6-7890-abcd-ef1234567891",
        "created": "2026-03-01T00:00:00Z",
        "modified": "2026-03-01T00:00:00Z",
        "pattern": "[ipv4-addr:value = '203.0.113.50']",
        "pattern_type": "stix",
        "valid_from": "2026-03-01T00:00:00Z"
      }
    ]
  }' | jq .

# Response:
# {
#   "imported_count": 1,
#   "investigation_id": "inv_01HX..."
# }
```

**Python (httpx):**

```python
stix_bundle = {
    "type": "bundle",
    "id": "bundle--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "objects": [
        {
            "type": "indicator",
            "id": "indicator--a1b2c3d4-e5f6-7890-abcd-ef1234567891",
            "created": "2026-03-01T00:00:00Z",
            "modified": "2026-03-01T00:00:00Z",
            "pattern": "[ipv4-addr:value = '203.0.113.50']",
            "pattern_type": "stix",
            "valid_from": "2026-03-01T00:00:00Z",
        }
    ],
}

response = client.post(
    f"/api/v1/iocs/stix/import?investigation_id={inv_id}",
    json=stix_bundle,
)
response.raise_for_status()
result = response.json()
print(f"Imported {result['imported_count']} IOCs")
```

---

## Search IOCs Across Investigations

List IOCs with optional filtering by investigation, type, and pagination.

**cURL:**

```bash
# List all IP-type IOCs across all investigations
curl -s "http://localhost:8000/api/v1/iocs?type=ip&page=1&page_size=50" \
  -H "Authorization: Bearer $TOKEN" | jq .

# List IOCs for a specific investigation
curl -s "http://localhost:8000/api/v1/iocs?investigation_id=$INV_ID" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Python (httpx):**

```python
# Search for all IP IOCs
response = client.get("/api/v1/iocs", params={
    "type": "ip",
    "page": 1,
    "page_size": 50,
})
response.raise_for_status()
result = response.json()
print(f"Found {result['total']} IP IOCs")
for ioc in result["items"]:
    print(f"  {ioc['value']} (confidence: {ioc['confidence']}, investigation: {ioc['investigation_id']})")

# Search within a specific investigation
response = client.get("/api/v1/iocs", params={
    "investigation_id": inv_id,
})
response.raise_for_status()
result = response.json()
print(f"Found {result['total']} IOCs in investigation {inv_id}")
```

---

## Query the Knowledge Base

### Search with Natural Language

**cURL:**

```bash
curl -s -X POST http://localhost:8000/api/v1/knowledge/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "How should we respond to a ransomware incident?",
    "top_k": 5
  }' | jq .

# Response:
# {
#   "query": "How should we respond to a ransomware incident?",
#   "results": [
#     {
#       "chunk_content": "Step 1: Isolate affected systems...",
#       "document_title": "Ransomware Response Playbook",
#       "source_type": "policy_document",
#       "relevance_score": 0.032787,
#       "document_id": "kd_01HX...",
#       "chunk_id": "kc_01HX..."
#     }
#   ],
#   "total_results": 3
# }
```

**Python (httpx):**

```python
response = client.post("/api/v1/knowledge/query", json={
    "query": "How should we respond to a ransomware incident?",
    "top_k": 5,
})
response.raise_for_status()
result = response.json()
print(f"Found {result['total_results']} relevant documents")
for r in result["results"]:
    print(f"  [{r['source_type']}] {r['document_title']} (score: {r['relevance_score']:.4f})")
    print(f"    {r['chunk_content'][:100]}...")
```

### Ingest a Document

**cURL:**

```bash
curl -s -X POST http://localhost:8000/api/v1/knowledge/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Incident Response Runbook v2",
    "content": "This runbook describes the standard operating procedures for incident response at Acme Corp. Step 1: Identification. Upon receiving an alert, the on-call analyst should...",
    "source_type": "runbook",
    "metadata": {"category": "incident_response", "version": "2.0"}
  }' | jq .

# Response:
# {
#   "id": "kd_01HX...",
#   "title": "Incident Response Runbook v2",
#   "source_type": "runbook",
#   "chunk_count": 12,
#   "token_count": 3500
# }
```

**Python (httpx):**

```python
response = client.post("/api/v1/knowledge/ingest", json={
    "title": "Incident Response Runbook v2",
    "content": "This runbook describes the standard operating procedures...",
    "source_type": "runbook",
    "metadata": {"category": "incident_response", "version": "2.0"},
})
response.raise_for_status()
doc = response.json()
print(f"Ingested document: {doc['id']} ({doc['chunk_count']} chunks, {doc['token_count']} tokens)")
```

### List and Delete Documents

**cURL:**

```bash
# List documents
curl -s "http://localhost:8000/api/v1/knowledge/documents?source_type=runbook" \
  -H "Authorization: Bearer $TOKEN" | jq .

# Delete a document (admin only)
curl -s -X DELETE "http://localhost:8000/api/v1/knowledge/documents/$DOC_ID" \
  -H "Authorization: Bearer $TOKEN"
```

**Python (httpx):**

```python
# List documents
response = client.get("/api/v1/knowledge/documents", params={
    "source_type": "runbook",
})
response.raise_for_status()
docs = response.json()
for doc in docs["items"]:
    print(f"  {doc['id']}: {doc['title']} ({doc['source_type']})")

# Delete a document (requires admin role)
response = client.delete(f"/api/v1/knowledge/documents/{doc_id}")
response.raise_for_status()
print("Document deleted")
```

---

## Generate a Report

Report generation is triggered via the investigation chat. The agent compiles findings into a structured report.

**cURL:**

```bash
curl -s -X POST "http://localhost:8000/api/v1/investigations/$INV_ID/chat" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Generate a detailed investigation report with executive summary, timeline, IOC table, and MITRE ATT&CK mapping"
  }' | jq .
```

**Python (httpx):**

```python
response = client.post(f"/api/v1/investigations/{inv_id}/chat", json={
    "message": "Generate a detailed investigation report with executive summary, timeline, IOC table, and MITRE ATT&CK mapping",
})
response.raise_for_status()
print("Report generation requested. Connect via WebSocket to receive the output.")
```

The report content is streamed back as agent output events via WebSocket.

---

## Execute a Playbook

### List Available Playbooks

**cURL:**

```bash
curl -s http://localhost:8000/api/v1/playbooks \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Python (httpx):**

```python
response = client.get("/api/v1/playbooks")
response.raise_for_status()
playbooks = response.json()
for pb in playbooks["items"]:
    print(f"  {pb['id']}: {pb['name']} (trigger: {pb['trigger_type']}, active: {pb['is_active']})")
```

### Execute a Playbook

**cURL:**

```bash
curl -s -X POST "http://localhost:8000/api/v1/playbooks/$PLAYBOOK_ID/execute" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"investigation_id\": \"$INV_ID\",
    \"trigger_data\": {\"severity\": \"high\"}
  }" | jq .

# Response:
# {
#   "execution_id": "pbe_01HX...",
#   "status": "running",
#   "playbook_id": "pb_01HX..."
# }
```

**Python (httpx):**

```python
response = client.post(f"/api/v1/playbooks/{playbook_id}/execute", json={
    "investigation_id": inv_id,
    "trigger_data": {"severity": "high"},
})
response.raise_for_status()
execution = response.json()
execution_id = execution["execution_id"]
print(f"Playbook execution started: {execution_id} (status: {execution['status']})")
```

### Monitor Execution

**cURL:**

```bash
# Check execution status
curl -s "http://localhost:8000/api/v1/playbooks/executions/$EXECUTION_ID" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Python (httpx):**

```python
response = client.get(f"/api/v1/playbooks/executions/{execution_id}")
response.raise_for_status()
execution = response.json()
print(f"Status: {execution['status']}")
for step_id, result in execution.get("step_results", {}).items():
    print(f"  Step {step_id}: {result.get('status', 'unknown')}")
```

---

## WebSocket Connection

The WebSocket provides real-time agent events. This example uses JavaScript (browser or Node.js).

### JavaScript Example

```javascript
// Connect with JWT token
const token = "eyJhbGciOiJIUzI1NiIs...";  // from login response
const ws = new WebSocket(`ws://localhost:8000/ws?token=${encodeURIComponent(token)}`);

// Connection opened
ws.addEventListener("open", () => {
  console.log("Connected to BTagent WebSocket");

  // Subscribe to an investigation
  ws.send(JSON.stringify({
    type: "subscribe",
    investigation_id: "inv_01HX..."
  }));
});

// Handle incoming events
ws.addEventListener("message", (event) => {
  const data = JSON.parse(event.data);

  switch (data.type) {
    case "subscribed":
      console.log(`Subscribed to investigation: ${data.data.investigation_id}`);
      break;

    case "thinking":
      console.log(`[Agent] Thinking... (model: ${data.data.model})`);
      break;

    case "output":
    case "output_chunk":
      console.log(`[Agent] ${data.data.content || data.data.chunk}`);
      break;

    case "tool_start":
      console.log(`[Tool] Starting: ${data.data.tool_name}`);
      break;

    case "tool_end":
      console.log(`[Tool] Completed: ${data.data.tool_name}`);
      break;

    case "ioc_discovered":
      console.log(`[IOC] Found: ${data.data.type} = ${data.data.value}`);
      break;

    case "hitl_checkpoint":
      console.log(`[HITL] Approval needed: ${data.data.description}`);
      console.log(`       Checkpoint ID: ${data.data.checkpoint_id}`);
      // Approve the checkpoint:
      // ws.send(JSON.stringify({
      //   type: "hitl_response",
      //   investigation_id: data.investigation_id,
      //   data: {
      //     checkpoint_id: data.data.checkpoint_id,
      //     approved: true,
      //     comment: "Approved -- proceed with isolation"
      //   }
      // }));
      break;

    case "investigation_complete":
      console.log("[Done] Investigation complete");
      break;

    case "error":
      console.error(`[Error] ${data.data.message}`);
      break;

    default:
      console.log(`[${data.type}]`, data.data);
  }
});

// Send a chat message
function sendChat(investigationId, message) {
  ws.send(JSON.stringify({
    type: "chat",
    investigation_id: investigationId,
    data: { message }
  }));
}

// Respond to HITL checkpoint
function respondHITL(investigationId, checkpointId, approved, comment) {
  ws.send(JSON.stringify({
    type: "hitl_response",
    investigation_id: investigationId,
    data: {
      checkpoint_id: checkpointId,
      approved,
      comment
    }
  }));
}

// Heartbeat to keep connection alive
setInterval(() => {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: "ping" }));
  }
}, 30000);

// Clean disconnect
function disconnect() {
  ws.close(1000, "Client disconnect");
}
```

### Python WebSocket Example

```python
import asyncio
import json
import httpx
import websockets


async def main():
    # Login first
    async with httpx.AsyncClient(base_url="http://localhost:8000") as http:
        response = await http.post("/api/v1/auth/login", json={
            "username": "analyst1",
            "password": "s3cureP@ss",
        })
        response.raise_for_status()
        token = response.json()["access_token"]

    # Connect WebSocket
    uri = f"ws://localhost:8000/ws?token={token}"
    async with websockets.connect(uri) as ws:
        # Subscribe to an investigation
        await ws.send(json.dumps({
            "type": "subscribe",
            "investigation_id": "inv_01HX...",
        }))

        # Listen for events
        async for message in ws:
            event = json.loads(message)
            event_type = event.get("type", "unknown")
            data = event.get("data", {})

            if event_type == "output":
                print(f"[Agent] {data.get('content', '')}")
            elif event_type == "tool_start":
                print(f"[Tool] Starting: {data.get('tool_name', '')}")
            elif event_type == "tool_end":
                print(f"[Tool] Done: {data.get('tool_name', '')}")
            elif event_type == "hitl_checkpoint":
                print(f"[HITL] Needs approval: {data.get('description', '')}")
            elif event_type == "error":
                print(f"[Error] {data.get('message', '')}")
            else:
                print(f"[{event_type}] {data}")


asyncio.run(main())
```

---

## Complete Workflow Example

This Python script demonstrates a full workflow: login, create investigation, send chat, monitor via WebSocket.

```python
import asyncio
import json
import httpx
import websockets

BASE_URL = "http://localhost:8000"
WS_URL = "ws://localhost:8000/ws"


async def run_investigation():
    # Step 1: Login
    async with httpx.AsyncClient(base_url=BASE_URL) as http:
        login = await http.post("/api/v1/auth/login", json={
            "username": "analyst1",
            "password": "s3cureP@ss",
        })
        login.raise_for_status()
        token = login.json()["access_token"]

        headers = {"Authorization": f"Bearer {token}"}

        # Step 2: Create investigation
        inv_response = await http.post("/api/v1/investigations", json={
            "title": "Suspicious SSH activity from 198.51.100.23",
            "severity": "high",
            "tlp_level": "green",
            "template": "unauthorized_access",
        }, headers=headers)
        inv_response.raise_for_status()
        inv_id = inv_response.json()["id"]
        print(f"Created investigation: {inv_id}")

    # Step 3: Connect WebSocket and subscribe
    async with websockets.connect(f"{WS_URL}?token={token}") as ws:
        await ws.send(json.dumps({
            "type": "subscribe",
            "investigation_id": inv_id,
        }))

        # Step 4: Send a chat message via WebSocket
        await ws.send(json.dumps({
            "type": "chat",
            "investigation_id": inv_id,
            "data": {
                "message": "Search for all failed SSH logins from 198.51.100.23 in the last 48 hours and extract IOCs",
            },
        }))

        # Step 5: Process events until investigation completes
        async for message in ws:
            event = json.loads(message)
            event_type = event.get("type", "unknown")
            data = event.get("data", {})

            if event_type == "output":
                print(f"\n[Agent]: {data.get('content', '')}")
            elif event_type == "ioc_discovered":
                print(f"  [IOC] {data.get('type')}: {data.get('value')}")
            elif event_type == "query_generated":
                print(f"  [Query] {data.get('query_language')}: {data.get('query', '')[:80]}...")
            elif event_type == "hitl_checkpoint":
                print(f"\n  [HITL] Approval needed: {data.get('description')}")
                # Auto-approve for this example
                await ws.send(json.dumps({
                    "type": "hitl_response",
                    "investigation_id": inv_id,
                    "data": {
                        "checkpoint_id": data["checkpoint_id"],
                        "approved": True,
                        "comment": "Auto-approved by script",
                    },
                }))
                print("  [HITL] Auto-approved")
            elif event_type == "investigation_complete":
                print("\nInvestigation complete.")
                break
            elif event_type == "error":
                print(f"\n[Error]: {data.get('message', '')}")
                break


asyncio.run(run_investigation())
```

---

## Further Reading

- [API Reference](API.md) -- Full endpoint documentation with request/response schemas
- [WebSocket Protocol](API.md#websocket-protocol) -- Complete WebSocket message types and protocol details
- [Analyst Guide](ANALYST_GUIDE.md) -- User guide for the web interface
- [Architecture Overview](ARCHITECTURE.md) -- System design and data flow
