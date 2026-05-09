# SIEM/EDR Connector Setup

This guide covers configuring BTagent's webhook ingestion from Splunk, CrowdStrike Falcon, Microsoft Sentinel, and Elastic Security. When configured, alerts from these platforms automatically create investigations in BTagent.

## How Webhooks Work

```
 SIEM/EDR Platform              BTagent
 +-----------+                  +---------------------+
 | Alert     | --- POST -----> | /api/v1/webhooks/:source |
 | triggers  |   + payload     | Verify X-Webhook-Secret  |
 | webhook   |   + secret      | Normalize severity       |
 +-----------+                  | Create investigation     |
                                | Return 202 + inv_id      |
                                +---------------------+
                                         |
                                         v
                                Agent starts triage
```

**Authentication:** Every webhook request must include the `X-Webhook-Secret` header. BTagent verifies this against the configured secret using constant-time HMAC comparison to prevent timing attacks.

**Response:** All webhook endpoints return `202 Accepted` with the new investigation ID:

```json
{
  "investigation_id": "inv_01HX...",
  "status": "accepted"
}
```

### Configure the Webhook Secret

Set the webhook secret in your BTagent environment:

```bash
# Generate a strong secret
export BTAGENT_WEBHOOK_SECRET=$(openssl rand -hex 32)

# Add to your .env file
echo "BTAGENT_WEBHOOK_SECRET=$BTAGENT_WEBHOOK_SECRET" >> infra/.env
```

Use this same secret value in each SIEM/EDR platform's webhook configuration.

---

## Splunk

### 1. Create a Webhook Alert Action

In Splunk Web:

1. Navigate to **Settings > Searches, reports, and alerts**
2. Find the saved search you want to trigger on, click **Edit > Edit Alert**
3. Under **Trigger Actions**, click **Add Actions > Webhook**
4. Configure the webhook:

| Field | Value |
|-------|-------|
| URL | `https://btagent.example.com/api/v1/webhooks/splunk` |

### 2. Configure Custom Headers

Splunk's built-in webhook does not support custom headers directly. Use a Splunk Alert Script or the [Webhook Modular Alert](https://splunkbase.splunk.com/) app to add the secret header.

Alternatively, create a custom alert action script at `$SPLUNK_HOME/etc/apps/btagent/bin/btagent_alert.py`:

```python
import json
import sys
import requests

BTAGENT_URL = "https://btagent.example.com/api/v1/webhooks/splunk"
WEBHOOK_SECRET = "your-webhook-secret"

def send_alert(payload):
    response = requests.post(
        BTAGENT_URL,
        json=payload,
        headers={
            "Content-Type": "application/json",
            "X-Webhook-Secret": WEBHOOK_SECRET,
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()

if __name__ == "__main__":
    payload = json.loads(sys.stdin.read())
    result = send_alert(payload)
    print(f"Investigation created: {result['investigation_id']}")
```

### 3. Alert Payload Format

BTagent expects Splunk's standard alert payload:

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

Key fields:
- `search_name`: Used as the investigation title
- `severity`: Mapped to BTagent severity (critical, high, medium, low, info)
- `result`: Alert result data passed to the triage agent for IOC extraction

### 4. Test with a Sample Alert

```bash
curl -X POST https://btagent.example.com/api/v1/webhooks/splunk \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: your-webhook-secret" \
  -d '{
    "search_name": "Test: Brute Force Detection",
    "app": "search",
    "owner": "admin",
    "results_link": "https://splunk.example.com/search?sid=test",
    "result": {
      "src_ip": "198.51.100.23",
      "dest_ip": "10.1.2.3",
      "action": "failure",
      "count": "150"
    },
    "sid": "test-001",
    "severity": "high"
  }'
```

Expected response:

```json
{"investigation_id": "inv_01HX...", "status": "accepted"}
```

### 5. Troubleshooting

| Symptom | Cause | Solution |
|---------|-------|----------|
| `401 Unauthorized` | Wrong `X-Webhook-Secret` value | Verify the secret matches `BTAGENT_WEBHOOK_SECRET` |
| `500 Internal Server Error` | Payload format mismatch | Ensure the JSON matches the expected schema above |
| `Connection refused` | BTagent not reachable from Splunk | Check firewall rules, DNS resolution, and TLS certificates |
| Alert fires but no investigation | Webhook URL misconfigured | Verify the full URL path includes `/api/v1/webhooks/splunk` |

---

## CrowdStrike Falcon

### 1. Create a Webhook Notification

In the CrowdStrike Falcon console:

1. Navigate to **Endpoint Security > Configure > Notification Workflows**
2. Click **Create Workflow**
3. Set the trigger: **Detection** with desired severity filter
4. Add an action: **Webhook**
5. Configure:

| Field | Value |
|-------|-------|
| Webhook URL | `https://btagent.example.com/api/v1/webhooks/crowdstrike` |
| Content Type | `application/json` |
| Secret Header Name | `X-Webhook-Secret` |
| Secret Header Value | Your BTagent webhook secret |

### 2. Detection Payload Format

BTagent expects CrowdStrike detection payloads:

```json
{
  "detection_id": "ldt:abc123",
  "display_name": "Cobalt Strike Beacon Activity",
  "description": "Beacon detected communicating with known C2 infrastructure",
  "max_severity_displayname": "High",
  "hostname": "WORKSTATION-42",
  "tactic": "Command and Control",
  "technique": "T1071.001",
  "device": {
    "platform_name": "Windows",
    "os_version": "10.0.19045"
  },
  "behaviors": [
    {
      "behavior_id": "1",
      "pattern_disposition": "detect"
    }
  ]
}
```

Key fields:
- `display_name`: Used as the investigation title
- `max_severity_displayname`: Mapped to BTagent severity
- `technique`: MITRE ATT&CK technique ID, automatically linked
- `hostname` and `device`: Passed to triage for scope context

### 3. RTR Integration for Host Isolation

When the agent proposes containment (host isolation), BTagent routes the action through the CrowdStrike MCP connector:

1. Agent identifies a compromised host
2. Containment action proposed with target hostname
3. HITL gate pauses for analyst approval (requires `incident_commander` role)
4. On approval, the CrowdStrike MCP server calls the Real Time Response (RTR) API
5. Host is contained (network isolated) via CrowdStrike Falcon

> **Note:** RTR containment requires the CrowdStrike API client to have the `Hosts: Write` and `Real Time Response: Write` scopes.

### 4. Test

```bash
curl -X POST https://btagent.example.com/api/v1/webhooks/crowdstrike \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: your-webhook-secret" \
  -d '{
    "detection_id": "ldt:test-001",
    "display_name": "Test: Suspicious Process Execution",
    "description": "powershell.exe launched with encoded command",
    "max_severity_displayname": "Medium",
    "hostname": "TEST-WS-01",
    "tactic": "Execution",
    "technique": "T1059.001",
    "device": {"platform_name": "Windows", "os_version": "10.0.19045"},
    "behaviors": [{"behavior_id": "1", "pattern_disposition": "detect"}]
  }'
```

---

## Microsoft Sentinel

### 1. Create a Logic App or Automation Rule

#### Option A: Automation Rule (simpler)

In the Azure Portal:

1. Navigate to **Microsoft Sentinel > Configuration > Automation**
2. Click **Create > Automation rule**
3. Set the trigger: **When incident is created**
4. Add a condition: Severity >= Medium (optional)
5. Add an action: **Run playbook**
6. Select the Logic App playbook (created below)

#### Option B: Logic App Playbook

1. Navigate to **Logic Apps > Create**
2. Choose **Consumption** plan
3. Add a trigger: **When a response to a Microsoft Sentinel incident is triggered**
4. Add an action: **HTTP**
5. Configure:

| Field | Value |
|-------|-------|
| Method | POST |
| URI | `https://btagent.example.com/api/v1/webhooks/sentinel` |
| Headers | `Content-Type: application/json` and `X-Webhook-Secret: your-secret` |
| Body | Map Sentinel incident fields to the payload format below |

### 2. Incident Payload Format

```json
{
  "incident_id": "inc-2026-0042",
  "title": "Impossible travel activity",
  "description": "User login from US and China within 5 minutes",
  "severity": "High",
  "status": "New",
  "classification": "",
  "alerts": [
    {
      "alert_id": "a1",
      "display_name": "Impossible travel"
    }
  ],
  "entities": [
    {
      "kind": "Account",
      "name": "jdoe@acme.com"
    }
  ]
}
```

Key fields:
- `title`: Used as the investigation title
- `severity`: Mapped to BTagent severity
- `entities`: Extracted as IOCs during triage (Account, IP, Host, FileHash)

### 3. Payload Mapping in Logic App

Map Sentinel's dynamic content to the BTagent payload:

| BTagent Field | Sentinel Dynamic Content |
|---------------|-------------------------|
| `incident_id` | `@{triggerBody()?['object']?['properties']?['incidentNumber']}` |
| `title` | `@{triggerBody()?['object']?['properties']?['title']}` |
| `description` | `@{triggerBody()?['object']?['properties']?['description']}` |
| `severity` | `@{triggerBody()?['object']?['properties']?['severity']}` |
| `status` | `@{triggerBody()?['object']?['properties']?['status']}` |

### 4. Test

```bash
curl -X POST https://btagent.example.com/api/v1/webhooks/sentinel \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: your-webhook-secret" \
  -d '{
    "incident_id": "inc-test-001",
    "title": "Test: Impossible Travel Detected",
    "description": "User login from two countries within 5 minutes",
    "severity": "High",
    "status": "New",
    "classification": "",
    "alerts": [{"alert_id": "a1", "display_name": "Impossible travel"}],
    "entities": [{"kind": "Account", "name": "testuser@example.com"}]
  }'
```

---

## Elastic Security

### 1. Create a Connector in Kibana

1. Navigate to **Stack Management > Connectors**
2. Click **Create connector > Webhook**
3. Configure:

| Field | Value |
|-------|-------|
| Name | BTagent Webhook |
| URL | `https://btagent.example.com/api/v1/webhooks/elastic` |
| Method | POST |
| Headers | `X-Webhook-Secret: your-webhook-secret` |
| Authentication | None (secret is in the header) |

### 2. Create a Detection Rule Action

1. Navigate to **Security > Detections > Rules**
2. Edit a detection rule (or create a new one)
3. Under **Rule actions**, click **Add action**
4. Select the **BTagent Webhook** connector
5. Configure the body template:

```json
{
  "rule_id": "{{rule.id}}",
  "rule_name": "{{rule.name}}",
  "alert_id": "{{alert.id}}",
  "severity": "{{rule.severity}}",
  "description": "{{rule.description}}",
  "source": {
    "host": {
      "name": "{{context.alerts[0].host.name}}"
    }
  },
  "kibana_url": "{{kibanaBaseUrl}}/app/security/alerts/{{alert.id}}",
  "hits": []
}
```

### 3. Alert Payload Format

```json
{
  "rule_id": "r-001",
  "rule_name": "Suspicious PowerShell Execution",
  "alert_id": "alert-5678",
  "severity": "high",
  "description": "PowerShell with encoded command detected on production server",
  "source": {
    "host": {
      "name": "PROD-WEB-01"
    }
  },
  "kibana_url": "https://kibana.acme.com/app/security/alerts/alert-5678",
  "hits": [
    {
      "_source": {
        "process.command_line": "powershell -enc ..."
      }
    }
  ]
}
```

Key fields:
- `rule_name`: Used as the investigation title
- `severity`: Mapped to BTagent severity
- `hits`: Raw event data passed to triage for IOC extraction

### 4. Test

```bash
curl -X POST https://btagent.example.com/api/v1/webhooks/elastic \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: your-webhook-secret" \
  -d '{
    "rule_id": "r-test-001",
    "rule_name": "Test: Encoded PowerShell",
    "alert_id": "alert-test-001",
    "severity": "medium",
    "description": "PowerShell encoded command on test host",
    "source": {"host": {"name": "TEST-HOST-01"}},
    "kibana_url": "https://kibana.example.com/app/security/alerts/alert-test-001",
    "hits": [{"_source": {"process.command_line": "powershell -enc dGVzdA=="}}]
  }'
```

---

## Verifying Investigations Auto-Create

After configuring any webhook, verify the end-to-end flow:

### 1. Send a Test Webhook

Use the curl commands above for your SIEM platform.

### 2. Check the Investigation Was Created

```bash
# List recent investigations
curl -H "Authorization: Bearer $TOKEN" \
  https://btagent.example.com/api/v1/investigations?page=1&page_size=5
```

### 3. Monitor the Agent

Connect to the WebSocket to watch the agent process the alert in real time:

```javascript
// Browser console or Node.js
const ws = new WebSocket('wss://btagent.example.com/ws?token=YOUR_JWT');
ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'subscribe',
    investigation_id: 'inv_01HX...'  // from step 2
  }));
};
ws.onmessage = (event) => {
  console.log(JSON.parse(event.data));
};
```

### 4. Verify Triage Results

```bash
# Get investigation detail
curl -H "Authorization: Bearer $TOKEN" \
  https://btagent.example.com/api/v1/investigations/inv_01HX...

# List extracted IOCs
curl -H "Authorization: Bearer $TOKEN" \
  "https://btagent.example.com/api/v1/iocs?investigation_id=inv_01HX..."
```

---

## Common Webhook Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| `401 Unauthorized` | `X-Webhook-Secret` header missing or incorrect | Verify the secret matches `BTAGENT_WEBHOOK_SECRET` exactly |
| `422 Unprocessable Entity` | Payload does not match expected schema | Check the payload format for your SIEM platform above |
| `500 Internal Server Error` | Backend error during investigation creation | Check backend logs: `docker logs btagent-backend-1` |
| Investigation created but agent not running | Redis not connected or agent engine error | Verify Redis health and check agent logs |
| No events in WebSocket | Not subscribed to the investigation | Send a `subscribe` message with the investigation_id |
| Duplicate investigations | Webhook firing multiple times | Add idempotency checks or deduplication based on alert_id |
