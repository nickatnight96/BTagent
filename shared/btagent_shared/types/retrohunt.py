"""Retro-hunt report types (EPIC-4 UC-4.3, #107).

When new threat intel arrives, the retro-hunt checks whether the
indicators were *already* present in historical telemetry (90+ days),
groups any sightings by ATT&CK tactic with a timeline, and flags
techniques that were seen but have no detection (a coverage gap).

shared/ tier, pydantic-only. Bridges the hunt module (HypothesisGen
output) and the detection module (coverage gaps).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class Sighting(BaseModel):
    """A historical match of an indicator against past telemetry."""

    model_config = ConfigDict(extra="forbid")

    ioc_value: str
    technique_id: str
    technique_name: str = ""
    tactic: str = "unknown"
    event_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    source_connectors: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)


class RetroHuntReport(BaseModel):
    """The UC-4.3 output: historical sightings grouped by tactic + gaps."""

    model_config = ConfigDict(extra="forbid")

    window_days: int = 90
    iocs_checked: int = 0
    sightings: list[Sighting] = Field(default_factory=list)
    sightings_by_tactic: dict[str, list[Sighting]] = Field(
        default_factory=dict,
        description="Tactic shortname -> sightings, for the grouped timeline view.",
    )
    techniques_with_sightings: list[str] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(
        default_factory=list,
        description="Techniques with sightings but no deployed detection — "
        "flagged to detection engineering.",
    )
    compromise_suspected: bool = Field(
        default=False,
        description="True if any sighting was found — 'were we already breached?'.",
    )
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    mock_mode: bool = False


__all__ = ["RetroHuntReport", "Sighting"]
