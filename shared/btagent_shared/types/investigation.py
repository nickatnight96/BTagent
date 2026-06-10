"""Investigation domain models."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from btagent_shared.types.config import TLP, AutonomyLevel
from btagent_shared.types.enums import (
    ContainmentStatus,
    InvestigationStatus,
    IOCType,
    Severity,
)


class Investigation(BaseModel):
    """Core investigation model."""

    id: str
    case_id: str | None = None
    title: str
    description: str = ""
    status: InvestigationStatus = InvestigationStatus.PENDING
    severity: Severity = Severity.MEDIUM
    tlp_level: TLP = TLP.GREEN
    # HITL autonomy posture for agent work under this investigation;
    # inherited by workflow runs launched from it.
    autonomy_level: AutonomyLevel = AutonomyLevel.L2_SUPERVISED
    assigned_to: str | None = None
    template: str | None = None
    config: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None
    updated_at: datetime | None = None
    closed_at: datetime | None = None


class IOC(BaseModel):
    """Indicator of Compromise."""

    id: str
    investigation_id: str
    type: IOCType
    value: str
    tlp_level: TLP = TLP.GREEN
    confidence: float = 0.5
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    context: str = ""
    source: str = ""
    enrichment: dict[str, Any] = Field(default_factory=dict)


class TimelineEntry(BaseModel):
    """Entry in an investigation timeline."""

    id: str
    investigation_id: str
    timestamp: datetime
    description: str
    actor: str = ""
    event_type: str = ""
    evidence_id: str | None = None
    technique_id: str | None = None  # MITRE ATT&CK (populated in Phase 2)


class ContainmentAction(BaseModel):
    """A containment action taken during an investigation."""

    id: str
    investigation_id: str
    action_type: str  # host_isolation, firewall_rule, account_disable, etc.
    target: str
    status: ContainmentStatus = ContainmentStatus.PROPOSED
    initiated_by: str = ""
    approved_by: str | None = None
    initiated_at: datetime | None = None
    completed_at: datetime | None = None


class Evidence(BaseModel):
    """Collected evidence artifact."""

    id: str
    investigation_id: str
    title: str
    type: str  # pcap, memory_dump, log_export, screenshot, etc.
    content_ref: str = ""  # S3/MinIO object key
    hash_sha256: str = ""
    collected_at: datetime | None = None
    collected_by: str = ""
