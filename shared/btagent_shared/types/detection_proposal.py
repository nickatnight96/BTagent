"""Detection proposal types for the STIX → Sigma pipeline (issue #113 slice).

Provides:
* :class:`DetectionProposal` — a proposed Sigma rule derived from one or more
  STIX indicators, pending analyst review.
* :class:`CTIToDetectionRequest` — input bundle (raw dict or bundle-id reference)
  plus active TLP context.
* :class:`CTIToDetectionResponse` — list of proposals + a list of skipped
  indicators with the reason each was skipped.

Design constraints:
- Zero heavy deps: only pydantic and stdlib.
- ``extra="forbid"`` on all models.
- Lowercase StrEnums throughout.
- Proposal ``id`` and Sigma rule ``id`` are derived deterministically from
  the source indicator so repeated runs produce identical output.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.config import TLP

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ProposalState(StrEnum):
    """Lifecycle state of a :class:`DetectionProposal`."""

    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    MODIFIED = "modified"


class PROutcome(StrEnum):
    """Where a proposal's rule sits in the detection-repo PR lifecycle (#113 Phase C).

    * ``PROPOSED`` — no PR composed yet (the default for every fresh row).
    * ``PR_OPENED`` — the composer shipped the rule in a (mock) detection-repo PR.
    * ``MERGED`` — the PR merged; the closed loop auto-installs the rule as a
      #112 hunt-pack entry and triggers a #118 sandbox detection-validation run.
    * ``REJECTED`` — the PR was closed without merging.
    """

    PROPOSED = "proposed"
    PR_OPENED = "pr_opened"
    MERGED = "merged"
    REJECTED = "rejected"


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------


class DetectionProposal(BaseModel):
    """A Sigma rule proposal generated from a STIX 2.1 indicator.

    Proposals are returned to the caller *and* persisted, org-scoped, to
    ``detection_proposals`` by
    :func:`btagent_backend.services.cti_detection_service.persist_proposals`.
    An analyst then reviews, validates, accepts, or rejects each one through
    ``/cti/proposals`` and the Detection Proposals page.

    The ``sigma_yaml`` field contains a complete, valid Sigma rule YAML string
    that the existing hunt-pack transpiler can compile without modification.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(description="Deterministic ULID-style id derived from source_stix_id.")
    source_stix_id: str = Field(description="STIX Indicator object id this rule was derived from.")
    title: str = Field(description="Human-readable rule title.")
    sigma_yaml: str = Field(description="Complete, valid Sigma 2.1 rule as a YAML string.")
    technique_ids: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs (e.g. ['T1071.001']) mapped from the indicator.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence in the proposed rule, inherited from the source indicator.",
    )
    source_indicators: list[str] = Field(
        default_factory=list,
        description="STIX pattern strings for the underlying indicators.",
    )
    rationale: str = Field(
        default="",
        description="Short human-readable explanation of why this rule was generated.",
    )
    state: Literal["proposed", "accepted", "rejected", "modified"] = Field(
        default="proposed",
        description="Lifecycle state. Freshly generated proposals start as 'proposed'.",
    )
    generated_at: datetime = Field(description="UTC timestamp at which the proposal was created.")


class CTIToDetectionRequest(BaseModel):
    """Request payload for the CTI → Sigma proposal endpoint.

    Exactly one of ``stix_bundle``, ``stix_bundle_id`` or ``report_text``
    must be supplied. ``stix_bundle`` carries the raw STIX 2.1 bundle dict;
    ``stix_bundle_id`` references a previously-stored bundle;
    ``report_text`` is unstructured CTI prose to extract IOCs/TTPs from
    (#113 back half — converted to a synthetic bundle server-side so the
    downstream pipeline is identical).
    """

    model_config = ConfigDict(extra="forbid")

    stix_bundle: dict[str, object] | None = Field(
        default=None,
        description="Raw STIX 2.1 bundle dict to process inline.",
    )
    stix_bundle_id: str | None = Field(
        default=None,
        description="ID of a previously-imported STIX bundle (deferred — not yet resolved).",
    )
    report_text: str | None = Field(
        default=None,
        max_length=200_000,
        description="Unstructured CTI report text (#113). IOCs are extracted "
        "(defanged forms handled) into a synthetic STIX bundle and run through "
        "the same pipeline. Mutually exclusive with the bundle inputs.",
    )
    report_name: str = Field(
        default="",
        max_length=300,
        description="Optional label for the report; appears in proposal titles' provenance.",
    )
    active_tlp: TLP = Field(
        default=TLP.GREEN,
        description="TLP context for this operation. TLP:RED bundles are refused.",
    )


class SkippedIndicator(BaseModel):
    """Record of a STIX indicator that was not converted to a Sigma rule."""

    model_config = ConfigDict(extra="forbid")

    stix_id: str = Field(default="", description="STIX object id, if available.")
    pattern: str = Field(default="", description="STIX pattern string that was skipped.")
    reason: str = Field(description="Human-readable explanation of why the indicator was skipped.")


class PersistedCounts(BaseModel):
    """Outcome of upserting a propose call's output into the proposal store.

    ``unchanged`` counts proposals whose stored row an analyst has already
    decided (accepted / rejected / modified) — a re-import never clobbers a
    decision (#113 back half, slice 1).
    """

    model_config = ConfigDict(extra="forbid")

    created: int = 0
    updated: int = 0
    unchanged: int = 0


class CTIToDetectionResponse(BaseModel):
    """Response payload from the STIX → Sigma proposal endpoint."""

    model_config = ConfigDict(extra="forbid")

    proposals: list[DetectionProposal] = Field(
        default_factory=list,
        description="Generated Sigma rule proposals ready for analyst review.",
    )
    skipped: list[SkippedIndicator] = Field(
        default_factory=list,
        description="Indicators that could not be converted, with the reason.",
    )
    persisted: PersistedCounts | None = Field(
        default=None,
        description=(
            "Upsert counts when the endpoint persisted the proposals "
            "(#113 slice 1); None for callers of the pure pipeline."
        ),
    )


__all__ = [
    "CTIToDetectionRequest",
    "CTIToDetectionResponse",
    "DetectionProposal",
    "PROutcome",
    "PersistedCounts",
    "ProposalState",
    "SkippedIndicator",
]
