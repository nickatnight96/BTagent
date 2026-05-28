"""Detection-engineering types (EPIC-4 UC-4.2, #107).

The shapes for continuous pattern detection + coverage-gap analysis:
candidate detections clustered from telemetry, and a coverage report
that shows which ATT&CK techniques have no detection in the window plus
draft Sigma rules to close the top gaps.

shared/ tier, pydantic-only. Reuses CoverageMap / TechniqueCoverage /
DetectionGap from types/mitre.py rather than redefining them.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.mitre import CoverageMap, DetectionGap


class DetectionCluster(BaseModel):
    """A candidate detection clustered from telemetry events.

    The output of continuous pattern detection: events sharing an ATT&CK
    technique + affected-entity set are grouped into one cluster the
    analyst reviews and either escalates or promotes to a rule.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    technique_id: str
    technique_name: str = ""
    confidence: float = Field(ge=0.0, le=1.0)
    affected_entities: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Entity kind -> values (hosts/users/ips) involved in the cluster.",
    )
    event_ids: list[str] = Field(
        default_factory=list, description="NormalizedEvent ids in this cluster."
    )
    summary: str = ""


class SigmaDraft(BaseModel):
    """A draft Sigma rule proposed to close a coverage gap or capture a pattern."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str
    title: str
    sigma_yaml: str
    rationale: str = ""


class CoverageGapReport(BaseModel):
    """Live ATT&CK coverage matrix + gaps + draft rules (UC-4.2 headline output)."""

    model_config = ConfigDict(extra="forbid")

    coverage_map: CoverageMap
    gaps: list[DetectionGap] = Field(default_factory=list)
    uncovered_technique_ids: list[str] = Field(
        default_factory=list,
        description="Flat list of techniques with no detection in the window.",
    )
    sigma_drafts: list[SigmaDraft] = Field(
        default_factory=list,
        description="Draft rules for the top uncovered techniques.",
    )
    window_days: int = 30
    generated_at: datetime = Field(default_factory=datetime.utcnow)


__all__ = [
    "CoverageGapReport",
    "DetectionCluster",
    "SigmaDraft",
]
