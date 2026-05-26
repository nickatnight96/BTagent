"""Cross-platform correlation types (UC-1.2, #104).

The schemas the Correlation Workbench produces: a single normalized,
lineage-tracked timeline assembled from multiple security tools, plus
the audit trail and pivot suggestions the analyst acts on.

shared/ tier — pydantic only, no engine imports — so backend (API +
persistence) and frontend (via generated types) consume the same shape
the engine emits.

The whole point of UC-1.2 is *normalization*: a Splunk ``src_ip`` and an
Elastic ``source.ip`` become one canonical :attr:`NormalizedEvent.source_ip`,
and every vendor timestamp becomes one tz-aware UTC
:attr:`NormalizedEvent.timestamp`. Everything downstream (sorting, MITRE
tagging, pivoting) operates on the canonical shape.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.connector import OCSFEventClass
from btagent_shared.types.enums import IOCType


class RawEventRef(BaseModel):
    """Pointer from a normalized event back to its source raw record.

    Satisfies the UC-1.2 acceptance criterion: "data lineage from
    result → raw log". The ``locator`` is the connector-native handle
    (Splunk ``_bkt:_cd``, Elastic ``_index/_id``, EDR detection id).
    """

    model_config = ConfigDict(extra="forbid")

    connector: str
    capability_id: str
    locator: str = Field(
        default="",
        description="Connector-native record handle for retrieving the raw log.",
    )
    queried_at: datetime


class MitreTag(BaseModel):
    """A confidence-gated ATT&CK technique attached to an event."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str
    name: str = ""
    confidence: float = Field(ge=0.0, le=1.0)


class NormalizedEvent(BaseModel):
    """One event on the unified timeline, in canonical (OCSF-aligned) shape.

    Entity fields are all optional — any given event populates the
    subset relevant to its OCSF class (a DNS event has ``domain`` +
    ``source_ip``; an auth event has ``user`` + ``source_ip``).
    """

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(..., description="Deterministic id: hash of (connector, locator).")
    timestamp: datetime = Field(..., description="Normalized to tz-aware UTC.")
    source_connector: str
    ocsf_event_class: OCSFEventClass

    # Canonical entity fields (the normalization payoff)
    source_ip: str | None = None
    dest_ip: str | None = None
    user: str | None = None
    host: str | None = None
    file_hash: str | None = None
    domain: str | None = None
    action: str | None = Field(
        default=None,
        description="Canonical action verb: allowed / blocked / failure / "
        "process_created / file_written / authenticated, etc.",
    )
    summary: str = Field(default="", description="Human one-liner for the timeline row.")

    # Lineage
    raw_ref: RawEventRef
    raw_event: dict[str, Any] = Field(
        default_factory=dict,
        description="Verbatim vendor event — the lineage target.",
    )

    # Tagging
    mitre_techniques: list[MitreTag] = Field(default_factory=list)


class PivotSuggestion(BaseModel):
    """A suggested next investigative step with rationale."""

    model_config = ConfigDict(extra="forbid")

    entity_type: IOCType
    entity_value: str
    rationale: str
    suggested_connectors: list[str] = Field(default_factory=list)


class AuditEntry(BaseModel):
    """One record per connector queried — the audit-trail criterion."""

    model_config = ConfigDict(extra="forbid")

    connector: str
    capability_id: str = ""
    query: str = ""
    queried_at: datetime
    event_count: int = 0
    error: str | None = None


class CorrelationTimeline(BaseModel):
    """The full UC-1.2 output: normalized timeline + pivots + audit trail."""

    model_config = ConfigDict(extra="forbid")

    entity_type: IOCType
    entity_value: str
    events: list[NormalizedEvent] = Field(
        default_factory=list, description="Sorted by timestamp ascending."
    )
    sources_queried: list[str] = Field(default_factory=list)
    pivots: list[PivotSuggestion] = Field(default_factory=list)
    audit_trail: list[AuditEntry] = Field(default_factory=list)
    mock_mode: bool = False


__all__ = [
    "AuditEntry",
    "CorrelationTimeline",
    "MitreTag",
    "NormalizedEvent",
    "PivotSuggestion",
    "RawEventRef",
]
