"""Hunt-package types (EPIC-2 UC-2.2, #105).

A "hunt package" is the artifact produced from an advisory: the
indicators extracted from it, whether they were already sighted in the
environment (retro-hunt), pre-built hunt queries per backend, and draft
Sigma detections — everything an analyst needs to act, in one object.

shared/ tier, pydantic-only. Reuses RetroHuntReport (sightings) and the
hunt Query type; SigmaDraft comes from the detection module.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.detection import SigmaDraft
from btagent_shared.types.hunt import Backend, Query
from btagent_shared.types.retrohunt import RetroHuntReport


class HuntPackage(BaseModel):
    """Everything produced from an advisory, ready to attach to a case."""

    model_config = ConfigDict(extra="forbid")

    # Persisted-store id (hpkg_...). None on a package that was generated
    # but not (yet) stored; set by the backend store on save so the caller
    # can re-open the package from history.
    id: str | None = None
    # Investigation this package was promoted into (inv_...); None until
    # the analyst opens a case from it. Row-level lineage set by the
    # backend on read, never part of the generated artifact itself.
    investigation_id: str | None = None
    source_label: str = Field(
        default="advisory",
        description="Where the package came from (advisory title / filename).",
    )
    extracted_ioc_count: int = 0
    deduped_count: int = 0
    derived_techniques: list[str] = Field(
        default_factory=list,
        description="ATT&CK techniques derived from the extracted indicators.",
    )
    retro_report: RetroHuntReport | None = Field(
        default=None,
        description="Historical sighting check across the extracted indicators.",
    )
    queries: dict[str, dict[Backend, Query]] = Field(
        default_factory=dict,
        description="Per-technique, per-backend pre-built hunt queries.",
    )
    sigma_drafts: list[SigmaDraft] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    mock_mode: bool = False


__all__ = ["HuntPackage"]
