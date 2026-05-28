"""Event types and envelope for BTagent agent communication."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from btagent_shared.utils.ids import generate_id


class EventType(StrEnum):
    """All event types emitted by agents, adapted for defensive security."""

    # Investigation lifecycle
    INVESTIGATION_INIT = "investigation_init"
    INVESTIGATION_COMPLETE = "investigation_complete"
    INVESTIGATION_FAILED = "investigation_failed"
    INVESTIGATION_PAUSED = "investigation_paused"
    INVESTIGATION_RESUMED = "investigation_resumed"

    # Agent reasoning
    THINKING = "thinking"
    OUTPUT = "output"
    OUTPUT_CHUNK = "output_chunk"
    OUTPUT_COMPLETE = "output_complete"
    STEP_HEADER = "step_header"
    AGENT_STATUS = "agent_status"

    # Tool execution
    TOOL_START = "tool_start"
    TOOL_END = "tool_end"
    TOOL_PROGRESS = "tool_progress"

    # Human-in-the-loop
    HITL_CHECKPOINT = "hitl_checkpoint"
    HITL_RESPONSE = "hitl_response"
    HITL_TIMEOUT = "hitl_timeout"

    # Defensive-specific
    IOC_DISCOVERED = "ioc_discovered"
    IOC_ENRICHED = "ioc_enriched"
    IOC_CROSS_MATCH = "ioc_cross_match"
    IOC_ENRICHMENT_STARTED = "ioc_enrichment_started"
    IOC_ENRICHMENT_COMPLETE = "ioc_enrichment_complete"
    ALERT_CLASSIFIED = "alert_classified"
    CONTAINMENT_PROPOSED = "containment_proposed"
    CONTAINMENT_APPROVED = "containment_approved"
    CONTAINMENT_EXECUTED = "containment_executed"
    EVIDENCE_COLLECTED = "evidence_collected"
    TIMELINE_UPDATED = "timeline_updated"
    QUERY_GENERATED = "query_generated"
    QUERY_RESULTS = "query_results"
    THREAT_ASSESSMENT_UPDATE = "threat_assessment_update"
    KNOWLEDGE_INDEXED = "knowledge_indexed"
    KNOWLEDGE_QUERIED = "knowledge_queried"

    # Governance / classification (EPIC-7 UC-7.2)
    TLP_VIOLATION_ATTEMPT = "tlp.violation_attempt"

    # Report / Remediation lifecycle
    REPORT_GENERATION_STARTED = "report_generation_started"
    REPORT_GENERATION_COMPLETE = "report_generation_complete"
    REMEDIATION_GENERATED = "remediation_generated"

    # Playbook lifecycle
    PLAYBOOK_STARTED = "playbook_started"
    PLAYBOOK_STEP_COMPLETE = "playbook_step_complete"
    PLAYBOOK_COMPLETE = "playbook_complete"
    PLAYBOOK_FAILED = "playbook_failed"
    PLAYBOOK_HITL_GATE = "playbook_hitl_gate"

    # Proactive threat hunting (Phase 6)
    HUNT_STARTED = "hunt_started"
    HUNT_RULE_FIRED = "hunt_rule_fired"
    HUNT_FINDING_CREATED = "hunt_finding_created"
    HUNT_FINDING_TRIAGED = "hunt_finding_triaged"
    HUNT_FINDING_SUPPRESSED = "hunt_finding_suppressed"
    HUNT_FINDING_PROMOTED = "hunt_finding_promoted"

    # Cost & metrics
    METRICS_UPDATE = "metrics_update"
    COST_UPDATE = "cost_update"
    TOKEN_USAGE = "token_usage"

    # Errors
    ERROR = "error"
    TERMINATION_REASON = "termination_reason"

    # System
    SERVER_SHUTDOWN = "server_shutdown"
    NOTIFICATION = "notification"


class EventEnvelope(BaseModel):
    """Standard event envelope sent via WebSocket and persisted to DB."""

    type: EventType
    id: str = Field(default_factory=lambda: generate_id("evt"))
    investigation_id: str
    parent_id: str | None = None
    trace_id: str | None = None
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    data: dict[str, Any] = Field(default_factory=dict)
