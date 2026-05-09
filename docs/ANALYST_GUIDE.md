# BTagent Analyst Guide

A hands-on guide for security analysts using BTagent for incident response and threat hunting.

---

## Table of Contents

- [Logging In](#logging-in)
- [PunchList Dashboard](#punchlist-dashboard)
- [Creating an Investigation](#creating-an-investigation)
- [Investigation Templates](#investigation-templates)
- [Working with the Agent Chat](#working-with-the-agent-chat)
- [Understanding Triage Results](#understanding-triage-results)
- [Approving and Rejecting HITL Checkpoints](#approving-and-rejecting-hitl-checkpoints)
- [IOC Notebook](#ioc-notebook)
- [Knowledge Base](#knowledge-base)
- [Playbook Execution](#playbook-execution)
- [Report Generation](#report-generation)
- [MITRE ATT&CK Matrix](#mitre-attck-matrix)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Tips for Effective Use](#tips-for-effective-use)

---

## Logging In

Navigate to your BTagent instance (default: `http://localhost:5173`) and enter your credentials on the login page. Your administrator will have created your account with one of the following roles:

| Role | Level | What You Can Do |
|------|-------|-----------------|
| **Analyst** | 0 | View and create investigations, chat with the agent, view IOCs and knowledge base |
| **Senior Analyst** | 1 | Everything above, plus stop investigations, approve/reject HITL checkpoints, manage playbooks |
| **Incident Commander** | 2 | Everything above, plus approve and execute containment actions |
| **Admin** | 3 | Everything above, plus manage users, edit organization config, delete investigations, manage webhooks |

After logging in, your session is maintained via JWT tokens. The access token refreshes automatically, but you will be redirected to the login page if your session expires after prolonged inactivity.

---

## PunchList Dashboard

The PunchList is your landing page after login. It provides a single-pane view of all active investigations.

### Dashboard Sections

- **Investigation List** -- All investigations with status, severity, assignee, and timestamps. Click any row to open the investigation workspace.
- **Status indicators** -- Color-coded badges show investigation state:
  - `pending` -- Queued, agent has not started
  - `triaging` -- Agent is classifying the alert
  - `investigating` -- Active analysis in progress
  - `paused` -- Manually paused by an analyst
  - `paused_hitl` -- Waiting for human approval at a checkpoint
  - `closed` / `cancelled` -- Terminal states
- **Severity badges** -- Color-coded by severity level: critical (red), high (orange), medium (yellow), low (blue), info (gray).
- **Filters** -- Filter by status, severity, or assignee to focus on what matters.
- **TLP labels** -- Each investigation shows its Traffic Light Protocol level, which controls data sharing and LLM routing.

### Quick Actions

From the dashboard you can:
- Create a new investigation (top-right button)
- Click an investigation to open its full workspace
- Filter and sort investigations by any column

---

## Creating an Investigation

### From Scratch

1. Click **New Investigation** on the PunchList dashboard.
2. Fill in:
   - **Title** (required): A descriptive name for the investigation.
   - **Description** (optional): Detailed context about the alert or incident.
   - **Severity**: `critical`, `high`, `medium` (default), `low`, or `info`.
   - **TLP Level**: Controls data classification and LLM routing (see table below).
   - **Template** (optional): Select a pre-built investigation template.
3. Click **Create**. The agent begins processing immediately.

### TLP Levels

| Level | Meaning | LLM Routing |
|-------|---------|-------------|
| **RED** | Most restricted -- recipients only | Local models only (Ollama) |
| **AMBER+STRICT** | Limited sharing within organization | Ollama, AWS Bedrock |
| **AMBER** | Organization-wide sharing | Anthropic, Bedrock, Vertex AI |
| **GREEN** | Community sharing | Most providers (excludes Azure) |
| **WHITE** | Unrestricted | All 6 configured providers |

### From a Webhook

Investigations can also be created automatically when your SIEM or EDR sends an alert via webhook (Splunk, CrowdStrike, Sentinel, or Elastic). These appear on the PunchList with the source system noted and begin triage automatically.

---

## Investigation Templates

Templates provide pre-configured investigation workflows tailored to common incident types. When you select a template, the agent follows a structured sequence of steps specific to that scenario.

### Available Templates

| Template | Use Case | Key Steps |
|----------|----------|-----------|
| **Phishing** | Email-based attacks, spoofed messages, credential harvesting | Extract sender/URLs/attachments, check reputation, identify recipients, assess credential exposure |
| **Ransomware** | File encryption, ransom demands, data exfiltration | Identify patient zero, map lateral movement, assess encryption scope, check for data exfiltration |
| **Unauthorized Access** | Suspicious logins, privilege escalation, account compromise | Analyze authentication logs, check for impossible travel, review privilege changes, assess data access |

Without a template, the agent uses general-purpose triage and follows up based on what it discovers.

---

## Working with the Agent Chat

The investigation workspace includes a real-time chat interface where you communicate with the agent.

### Sending Messages

Type your message in the chat input and press Enter (or click Send). The agent processes your request and streams results back in real time. Example messages:

- `Search Splunk for connections to 198.51.100.23 in the last 24 hours`
- `Generate a KQL query for failed logins on WORKSTATION-42`
- `Enrich the IP address 203.0.113.50 using all available sources`
- `What does our knowledge base say about ransomware response procedures?`
- `Run the phishing response playbook`

### Understanding the Event Stream

As the agent works, you will see a stream of events in the workspace:

| Event | Icon | Meaning |
|-------|------|---------|
| **Thinking** | Brain | The agent is reasoning about the next step |
| **Output** | Message | The agent has produced a response or finding |
| **Tool Start** | Gear | The agent is calling an external tool (SIEM query, enrichment API, etc.) |
| **Tool End** | Check | A tool call completed with results |
| **IOC Discovered** | Target | A new indicator of compromise was extracted |
| **Alert Classified** | Shield | The triage agent assigned severity and category |
| **Query Generated** | Code | A SIEM/EDR query was generated |
| **HITL Checkpoint** | Hand | The agent is requesting human approval (see below) |
| **Cost Update** | Dollar | Token usage and cost updated |

### Cost Tracking

Each investigation shows a running cost badge in the workspace header. This tracks LLM token usage and estimated cost across all agent interactions in the investigation.

---

## Understanding Triage Results

When the agent triages an alert, it produces several outputs:

### Severity Assessment

The agent scores severity based on four dimensions:
- **Impact** -- Potential damage to systems, data, or operations
- **Urgency** -- How quickly the threat could escalate
- **Confidence** -- How certain the agent is about its analysis
- **Scope** -- How many systems or users are potentially affected

### Extracted IOCs

The triage agent automatically extracts indicators of compromise from alert data:
- IP addresses (IPv4 and IPv6)
- Domain names
- File hashes (SHA-256, SHA-1, MD5)
- Email addresses
- URLs
- CVE identifiers

These are added to the investigation's IOC list and can be further enriched.

### MITRE ATT&CK Mapping

The agent maps observed behaviors to MITRE ATT&CK techniques (e.g., `T1566.001 Phishing: Spearphishing Attachment`). These mappings appear in the triage output and are reflected in the MITRE ATT&CK Matrix view.

---

## Approving and Rejecting HITL Checkpoints

Human-in-the-Loop (HITL) checkpoints appear when the agent proposes an action that requires human judgment. This is a core safety mechanism in BTagent.

### When Checkpoints Appear

- The agent proposes a **containment action** (e.g., isolate a host, disable a user account)
- A playbook reaches an **HITL gate** step
- The investigation's **autonomy level** requires approval for the proposed action type

### What to Check

When a checkpoint appears, review:

1. **Proposed action** -- What exactly the agent wants to do (e.g., "Isolate host WORKSTATION-42 via CrowdStrike")
2. **Justification** -- Why the agent recommends this action
3. **Target** -- Which system, user, or resource will be affected
4. **Evidence** -- The findings that led to this recommendation
5. **Reversibility** -- Whether the action can be undone

### Responding

- **Approve**: Click the approve button and optionally add a comment. The agent proceeds with the action.
- **Reject**: Click the reject button with a reason. The agent notes the rejection and continues analysis without executing the action.

**Important:** Only users with `senior_analyst` or higher role can respond to HITL checkpoints. The investigation remains in `paused_hitl` status until a qualified user responds.

---

## IOC Notebook

The IOC Notebook (`/iocs` route) provides a centralized view of all indicators of compromise across your investigations.

### Viewing IOCs

- Browse IOCs filtered by investigation, type (IP, domain, hash, etc.), or confidence level
- Each IOC shows: type, value, confidence score, TLP level, first/last seen timestamps, and source

### Enriching IOCs

1. Select an IOC from the list.
2. Click **Enrich** to trigger the enrichment pipeline.
3. The agent queries configured CTI sources (VirusTotal, Shodan, GreyNoise, AbuseIPDB, MISP) and returns:
   - Reputation scores
   - Geolocation data
   - Associated malware families
   - Related threat intelligence reports
   - Historical context

Enrichment results are stored alongside the IOC and update the confidence score.

### Exporting IOCs

- **STIX 2.1 Export**: Export individual IOCs or bulk-export as STIX 2.1 bundles for sharing with partner organizations or MISP instances.
- **TLP enforcement**: IOCs marked as TLP:RED are blocked from export.

### Importing IOCs

Import IOCs from STIX 2.1 bundles via the import button. Imported indicators are automatically associated with the selected investigation.

---

## Knowledge Base

The Knowledge Base (`/knowledge` route) is a searchable repository of security documentation, runbooks, threat reports, and investigation findings.

### Searching

Enter a natural language query to search the knowledge base. The system uses hybrid search combining:
- Vector similarity (semantic meaning)
- Keyword matching (exact terms)
- Reciprocal Rank Fusion (RRF) to combine results

Example queries:
- `How should we respond to a ransomware incident?`
- `What is our password policy for service accounts?`
- `Previous investigations involving lateral movement`

### Ingesting Documents

Users with `senior_analyst` or higher role can add documents to the knowledge base:

1. Click **Ingest Document** on the Knowledge Base page.
2. Provide:
   - **Title**: Document name
   - **Content**: Full document text
   - **Source Type**: `policy_document`, `runbook`, `threat_report`, `investigation_report`, `enrichment_data`, `cti_feed`, or `other`
   - **Metadata**: Optional key-value pairs for categorization
3. The system automatically chunks the document, generates embeddings, and indexes it for search.

### Auto-Indexing

When an investigation is closed, BTagent automatically indexes its findings and enrichment results into the knowledge base. This means past investigations become searchable context for future work.

---

## Playbook Execution

Playbooks (`/playbooks` route) are pre-defined security workflows that automate multi-step response procedures.

### Selecting a Playbook

Browse available playbooks on the Playbook List page. Each playbook shows:
- Name and description
- Trigger type (manual, alert severity, IOC match, schedule)
- Version and active status

### Executing a Playbook

1. Navigate to the playbook and click **Execute**.
2. Select the target investigation.
3. Provide any required trigger data.
4. Click **Start Execution**.

### Monitoring Execution

The Playbook Execution View shows real-time step-by-step progress:
- Each step displays its type (action, decision, HITL gate, parallel)
- Completed steps show results and duration
- HITL gate steps pause for human approval
- Failed steps show error details and the configured failure policy (skip, abort, retry)

### Reviewing Results

After execution completes, review the full execution record:
- Overall status (completed, failed, cancelled)
- Per-step results and timing
- Any HITL decisions made during execution
- Errors and warnings

### Building Custom Playbooks

Users with `senior_analyst` or higher role can create custom playbooks using the Playbook Builder (`/playbooks/builder`). Define steps in YAML format following the [Playbook Schema](PLAYBOOK_SCHEMA.md).

---

## Report Generation

The agent can generate investigation reports summarizing findings, timeline, IOCs, and recommendations.

### Generating a Report

In the investigation workspace chat, ask the agent to generate a report:
- `Generate an executive summary report`
- `Create a detailed technical report`
- `Summarize this investigation for management`

### Report Sections

Reports typically include:
- **Executive Summary** -- High-level overview of the incident and response
- **Timeline** -- Chronological sequence of events
- **IOC Table** -- All indicators with enrichment details
- **MITRE ATT&CK Mapping** -- Techniques observed during the investigation
- **Containment Actions** -- Actions taken and their outcomes
- **Recommendations** -- Suggested follow-up actions and preventive measures

### Export

Reports are currently available as in-app text. PDF export is planned for v0.4.0 (see [ROADMAP.md](ROADMAP.md)).

---

## MITRE ATT&CK Matrix

The MITRE ATT&CK view (`/mitre` route) provides a visual heatmap of your organization's detection coverage and the techniques observed in investigations.

### Reading the Heatmap

- **Rows**: ATT&CK tactics in kill-chain order (Reconnaissance through Impact)
- **Columns**: Techniques within each tactic
- **Color intensity**: Indicates detection coverage or frequency of observation
  - Dark green: Well-covered by existing detections
  - Light green: Partially covered
  - Red/orange: Observed in investigations but not covered by detections
  - Gray: Not observed, no detection

### Technique Details

Click on any technique cell to see:
- Technique ID and full name (e.g., T1566.001 Phishing: Spearphishing Attachment)
- Description from the ATT&CK knowledge base
- Data sources needed for detection
- Investigations where this technique was observed
- Detection status (covered, gap, not assessed)

### Coverage Analysis

The coverage summary shows:
- Total techniques in the ATT&CK matrix
- Number of techniques with detections
- Coverage percentage
- Top detection gaps

### Navigator Export

Click **Export Navigator Layer** to download an ATT&CK Navigator JSON file. Import this into the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) for visualization and reporting.

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+K` / `Cmd+K` | Open command palette / quick search |
| `Ctrl+N` / `Cmd+N` | Create new investigation |
| `Ctrl+Enter` | Send chat message |
| `Escape` | Close modal / cancel action |
| `Ctrl+/` / `Cmd+/` | Show keyboard shortcuts help |

---

## Tips for Effective Use

### Writing Effective Agent Prompts

- **Be specific**: Instead of "check this IP," say "Search Splunk for all connections to 198.51.100.23 from internal hosts in the last 48 hours."
- **Provide context**: Include what you already know -- "This IP was extracted from a phishing email targeting the finance team."
- **Ask for formats**: "Generate a Splunk SPL query" or "Show results as a timeline."
- **Chain requests**: The agent maintains conversation context within an investigation. Build on previous findings.

### TLP Best Practices

- Start with **TLP:GREEN** for most investigations.
- Escalate to **TLP:AMBER** or **TLP:RED** when handling sensitive data (employee PII, active threat intelligence, etc.).
- Remember that TLP:RED restricts the agent to local Ollama models, which may reduce analysis quality.

### Investigation Workflow

1. **Start with triage**: Let the agent classify the alert and extract initial IOCs.
2. **Enrich key IOCs**: Request enrichment for high-priority indicators.
3. **Query your SIEMs**: Ask the agent to search for related activity across your data sources.
4. **Check the knowledge base**: Ask "What do we know about [threat/technique]?" to leverage organizational knowledge.
5. **Run relevant playbooks**: Use pre-built playbooks for common scenarios.
6. **Review and approve**: Carefully evaluate HITL checkpoints before approving containment actions.
7. **Generate reports**: Summarize findings before closing the investigation.

### Managing Costs

- Use investigation templates to guide the agent efficiently.
- Monitor the cost badge in the investigation workspace.
- Token budgets are enforced per investigation -- the agent will pause if the budget is exceeded.
- For simple triage tasks, the agent automatically uses cost-effective models (Haiku-class).

### Collaboration

- Multiple analysts can view the same investigation simultaneously via WebSocket.
- Use the chat to leave notes or context for other analysts.
- HITL checkpoints notify all subscribed users.
- The audit trail records all actions for accountability.

---

## Further Reading

- [Architecture Overview](ARCHITECTURE.md)
- [API Reference](API.md)
- [API Usage Examples](API_EXAMPLES.md)
- [Playbook Schema Reference](PLAYBOOK_SCHEMA.md)
- [Knowledge Base Guide](KNOWLEDGE_BASE.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Glossary of Terms](GLOSSARY.md)
