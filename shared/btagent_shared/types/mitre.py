"""MITRE ATT&CK Pydantic models for BTagent."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field, field_validator


class MitreTechnique(BaseModel):
    """A single MITRE ATT&CK technique or sub-technique."""

    id: str = Field(
        ...,
        description="Technique ID (e.g. T1059, T1059.001)",
        pattern=r"^T\d{4}(\.\d{3})?$",
    )
    name: str
    tactic: str = Field(
        ...,
        description="Primary tactic shortname (e.g. execution, persistence)",
    )
    description: str = ""
    platforms: list[str] = Field(
        default_factory=list,
        description="Applicable platforms (Windows, Linux, macOS, etc.)",
    )
    data_sources: list[str] = Field(
        default_factory=list,
        description="Data sources useful for detection",
    )
    detection: str = Field(
        default="",
        description="Detection guidance text",
    )
    url: str = Field(
        default="",
        description="ATT&CK page URL",
    )
    is_subtechnique: bool = False

    @field_validator("id")
    @classmethod
    def _validate_technique_id(cls, v: str) -> str:
        if not re.match(r"^T\d{4}(\.\d{3})?$", v):
            raise ValueError(f"Invalid technique ID format: {v}")
        return v


class MitreTactic(BaseModel):
    """A MITRE ATT&CK tactic (kill-chain phase)."""

    id: str = Field(
        ...,
        description="Tactic ID (e.g. TA0001)",
        pattern=r"^TA\d{4}$",
    )
    name: str
    shortname: str = Field(
        ...,
        description="Tactic shortname used in technique references (e.g. initial-access)",
    )
    description: str = ""
    ordinal: int = Field(
        ...,
        description="Position in the kill-chain (0-based)",
    )

    @field_validator("id")
    @classmethod
    def _validate_tactic_id(cls, v: str) -> str:
        if not re.match(r"^TA\d{4}$", v):
            raise ValueError(f"Invalid tactic ID format: {v}")
        return v


class MitreGroup(BaseModel):
    """A MITRE ATT&CK threat group."""

    id: str = Field(
        ...,
        description="Group ID (e.g. G0007)",
        pattern=r"^G\d{4}$",
    )
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str = ""
    techniques: list[str] = Field(
        default_factory=list,
        description="List of technique IDs associated with this group",
    )

    @field_validator("id")
    @classmethod
    def _validate_group_id(cls, v: str) -> str:
        if not re.match(r"^G\d{4}$", v):
            raise ValueError(f"Invalid group ID format: {v}")
        return v


class TechniqueTag(BaseModel):
    """Associates a MITRE technique with an entity (IOC, timeline entry, etc.)."""

    entity_type: str = Field(
        ...,
        description="Entity kind being tagged (ioc, timeline, alert, etc.)",
    )
    entity_id: str = Field(
        ...,
        description="ID of the entity being tagged",
    )
    technique_id: str = Field(
        ...,
        description="MITRE technique ID (e.g. T1059.001)",
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence score for the mapping (0.0-1.0)",
    )
    tagged_by: str = Field(
        default="",
        description="Who/what created this tag (user ID or agent name)",
    )


class CoverageMap(BaseModel):
    """ATT&CK coverage heatmap: tactic -> list of techniques with counts."""

    tactics: dict[str, list[TechniqueCoverage]] = Field(
        default_factory=dict,
        description="Tactic shortname -> list of covered techniques",
    )
    total_techniques: int = 0
    covered_techniques: int = 0


class TechniqueCoverage(BaseModel):
    """Coverage detail for a single technique within a tactic."""

    technique_id: str
    technique_name: str
    count: int = Field(
        default=0,
        description="Number of times this technique was tagged/detected",
    )


# Rebuild CoverageMap now that TechniqueCoverage is defined
CoverageMap.model_rebuild()


class DetectionGap(BaseModel):
    """Identifies detection gaps within a tactic."""

    tactic: str = Field(
        ...,
        description="Tactic shortname",
    )
    techniques_without_detection: list[str] = Field(
        default_factory=list,
        description="Technique IDs that lack detection data",
    )
    data_sources_missing: list[str] = Field(
        default_factory=list,
        description="Data sources that would improve coverage",
    )


class NavigatorLayer(BaseModel):
    """ATT&CK Navigator compatible JSON layer structure."""

    name: str = "BTagent Coverage"
    versions: dict[str, str] = Field(
        default_factory=lambda: {"attack": "16", "navigator": "5.1", "layer": "4.5"},
    )
    domain: str = "enterprise-attack"
    description: str = ""
    filters: dict[str, Any] = Field(
        default_factory=lambda: {"platforms": ["Windows", "Linux", "macOS"]},
    )
    sorting: int = 0
    layout: dict[str, Any] = Field(
        default_factory=lambda: {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
        },
    )
    hideDisabled: bool = False
    techniques: list[NavigatorTechnique] = Field(default_factory=list)
    gradient: dict[str, Any] = Field(
        default_factory=lambda: {
            "colors": ["#ffffff", "#66b1ff", "#0059b3"],
            "minValue": 0,
            "maxValue": 100,
        },
    )
    legendItems: list[dict[str, str]] = Field(default_factory=list)
    metadata: list[dict[str, str]] = Field(default_factory=list)
    showTacticRowBackground: bool = True
    tacticRowBackground: str = "#205b8f"
    selectTechniquesAcrossTactics: bool = True
    selectSubtechniquesWithParent: bool = False
    selectVisibleTechniques: bool = False


class NavigatorTechnique(BaseModel):
    """A single technique entry in a Navigator layer."""

    techniqueID: str
    tactic: str = ""
    color: str = ""
    comment: str = ""
    enabled: bool = True
    metadata: list[dict[str, str]] = Field(default_factory=list)
    links: list[dict[str, str]] = Field(default_factory=list)
    showSubtechniques: bool = False
    score: int = 0


# Rebuild NavigatorLayer now that NavigatorTechnique is defined
NavigatorLayer.model_rebuild()
