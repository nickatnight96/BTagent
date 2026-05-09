# Playbook YAML Schema Reference

BTagent playbooks are defined in YAML and compiled into LangGraph subgraphs for execution. This document describes the schema and provides examples for each step type.

## Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Playbook display name |
| `version` | string | No | Semantic version (default: "1.0") |
| `description` | string | No | Human-readable description |
| `trigger` | TriggerCondition | Yes | Trigger configuration |
| `steps` | list[Step] | Yes | Ordered list of step definitions |

## Trigger Condition

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | TriggerType | Yes | Trigger type |
| `parameters` | dict | No | Trigger-specific parameters |

### Trigger Types

| Type | Description | Parameters |
|------|-------------|------------|
| `manual` | Manually triggered by analyst | None |
| `alert_severity` | Triggered when alert severity meets threshold | `min_severity` (string) |
| `ioc_match` | Triggered when specific IOC type is discovered | `ioc_type` (string) |
| `schedule` | Triggered on a schedule (cron) | `cron` (string) |

## Step Types

### Action Step

Executes a registered tool with arguments.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique step identifier |
| `type` | "action" | Yes | Step type discriminator |
| `name` | string | Yes | Display name |
| `tool_name` | string | Yes | Registered tool name |
| `arguments` | dict | No | Tool arguments |
| `next_step` | string | No | ID of the next step |
| `timeout_seconds` | int | No | Execution timeout (default: 300) |
| `on_failure` | OnFailure | No | Failure policy: "skip", "abort", "retry" |

**Example:**
```yaml
- id: extract_iocs
  type: action
  name: Extract IOCs from email
  tool_name: alert_classifier
  arguments:
    source: email_gateway
  next_step: enrich_urls
  timeout_seconds: 120
  on_failure: skip
```

### Decision Step

Branches execution based on a condition evaluated against the execution context.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique step identifier |
| `type` | "decision" | Yes | Step type discriminator |
| `name` | string | Yes | Display name |
| `condition` | string | Yes | Condition expression (see below) |
| `true_branch` | string | Yes | Step ID when condition is true |
| `false_branch` | string | Yes | Step ID when condition is false |

**Condition Format:** `key.path OP value`

Supported operators: `>`, `<`, `>=`, `<=`, `==`, `!=`

The condition parser uses safe regex parsing and operator dispatch -- no `eval()` is ever used.

**Example:**
```yaml
- id: check_malicious
  type: decision
  name: Are IOCs malicious?
  condition: "enrichment.max_confidence > 0.7"
  true_branch: block_sender
  false_branch: log_and_close
```

**Condition Examples:**
```
enrichment.max_confidence > 0.7
alert.severity == critical
iocs.count >= 5
response.status_code != 200
```

### HITL Gate Step

Pauses execution until a human analyst approves or rejects.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique step identifier |
| `type` | "hitl_gate" | Yes | Step type discriminator |
| `name` | string | Yes | Display name |
| `prompt` | string | Yes | Question shown to analyst |
| `required_role` | string | No | Minimum role for approval (default: "senior_analyst") |
| `timeout_seconds` | int | No | Approval timeout (default: 3600) |
| `next_step` | string | No | Step ID after approval |

**Example:**
```yaml
- id: approve_containment
  type: hitl_gate
  name: Approve host isolation
  prompt: "Isolate host WORKSTATION-42 from the network?"
  required_role: incident_commander
  timeout_seconds: 1800
  next_step: execute_isolation
```

### Parallel Fork Step

Forks execution into parallel branches.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique step identifier |
| `type` | "parallel_fork" | Yes | Step type discriminator |
| `name` | string | Yes | Display name |
| `branches` | list[list[string]] | Yes | List of branch step ID sequences |

**Example:**
```yaml
- id: parallel_enrich
  type: parallel_fork
  name: Enrich IOCs in parallel
  branches:
    - [enrich_ips, score_ips]
    - [enrich_domains, score_domains]
    - [enrich_hashes]
```

### Join Step

Rejoins parallel branches (implicit after parallel fork completes).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique step identifier |
| `type` | "join" | Yes | Step type discriminator |
| `name` | string | Yes | Display name |
| `next_step` | string | No | Step ID after join |

### End Step

Terminates the playbook.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique step identifier |
| `type` | "end" | Yes | Step type discriminator |
| `name` | string | Yes | Display name |

**Example:**
```yaml
- id: done
  type: end
  name: Playbook complete
```

## OnFailure Policy

| Value | Behavior |
|-------|----------|
| `skip` | Skip failed step and continue to next |
| `abort` | Abort the entire playbook |
| `retry` | Retry the step (up to 3 attempts) |

## Validation Rules

The playbook compiler enforces:

1. **Unique step IDs** -- no duplicate IDs within a playbook.
2. **Valid step references** -- all `next_step`, `true_branch`, `false_branch` values must reference existing step IDs.
3. **DAG acyclicity** -- the step graph must be a directed acyclic graph (no cycles).
4. **Known tools** -- `tool_name` in action steps must be a registered tool.
5. **Required fields** -- `name` and `trigger` are mandatory at the top level.

## Complete Example

```yaml
name: Phishing Response
version: "1.0"
description: Automated phishing email investigation and containment
trigger:
  type: alert_severity
  parameters:
    min_severity: medium
    category: phishing
steps:
  - id: extract_iocs
    type: action
    name: Extract IOCs from email
    tool_name: alert_classifier
    arguments: {source: email_gateway}
    next_step: enrich_urls

  - id: enrich_urls
    type: action
    name: Enrich extracted URLs and domains
    tool_name: enrich_ioc
    arguments: {ioc_types: [url, domain]}
    next_step: check_malicious

  - id: check_malicious
    type: decision
    name: Are IOCs malicious?
    condition: "enrichment.max_confidence > 0.7"
    true_branch: approve_block
    false_branch: log_and_close

  - id: approve_block
    type: hitl_gate
    name: Approve sender domain block
    prompt: "Block sender domain and quarantine matching emails?"
    required_role: senior_analyst
    next_step: execute_block

  - id: execute_block
    type: action
    name: Block sender domain
    tool_name: splunk_search
    arguments: {action: block_domain}
    next_step: generate_report

  - id: log_and_close
    type: action
    name: Log and close as benign
    tool_name: alert_classifier
    arguments: {action: close_benign}
    next_step: done

  - id: generate_report
    type: action
    name: Generate investigation report
    tool_name: alert_classifier
    arguments: {action: generate_report}
    next_step: done

  - id: done
    type: end
    name: Playbook complete
```
