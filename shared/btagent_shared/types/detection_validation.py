"""Detection Validation schemas — simulation-fixture slice (#118).

Defines the contract for replaying pre-recorded MITRE-tagged attack events
through the existing Sigma hunt pipeline and producing a deterministic
coverage report.

No live Atomic Red Team / Caldera runtime is required; the simulation layer
replays *fixture* events through an injected callable (the hunt runner or a
test stub) and measures which rules fired vs. which were expected to fire.

Schema overview
---------------
SimulatedAttackEvent
    A single synthetic process/network event that a simulated ATT&CK technique
    would produce.  ``expected_to_fire`` declares whether a Sigma rule is
    expected to detect it (used to identify missed-but-expected cases).

SimulationScenario
    A named, MITRE-tagged bundle of SimulatedAttackEvents representing one
    attack technique or chain.

CoverageResult
    Per-technique roll-up: how many events were simulated, how many generated
    at least one SigmaHit, and which rule IDs fired or were expected but missed.

ValidationReport
    Top-level report produced by one validation run; the shape deferred live
    ART/Caldera execution will fill once wired in.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DetectionStatus(StrEnum):
    """Whether a simulation event was detected by at least one rule."""

    detected = "detected"
    missed = "missed"
    not_expected = "not_expected"


# ---------------------------------------------------------------------------
# Simulation input types
# ---------------------------------------------------------------------------


class SimulatedAttackEvent(BaseModel):
    """One synthetic event produced by a simulated ATT&CK technique.

    ``source_event_dict`` is the raw event payload fed directly into the hunt
    runner callable — it must match the field dialect the target Sigma rules
    expect (e.g. ``Image``, ``CommandLine`` for Windows process_creation rules).

    ``expected_to_fire`` declares whether the caller expects a Sigma rule to
    match this event.  Set to ``False`` for benign-but-similar events planted
    to verify no false positives, or for techniques where coverage is
    *intentionally* absent in the current pack (gap discovery use-case).

    ``expected_rule_id`` optionally pins *which* rule should fire.  When set,
    the coverage engine checks whether *that specific rule* is among the hits,
    not just whether any rule fired.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(..., min_length=1, max_length=200)
    technique_id: str = Field(
        ...,
        min_length=1,
        max_length=20,
        description="Primary MITRE ATT&CK technique id (e.g. 'T1059.001').",
    )
    sub_technique_id: str | None = Field(
        default=None,
        max_length=20,
        description="Sub-technique id when the primary is a parent (e.g. 'T1059.001').",
    )
    source_event_dict: dict[str, Any] = Field(
        ...,
        description="Raw event dict fed to the hunt runner — field names must match "
        "the logsource dialect of the target Sigma rules.",
    )
    expected_to_fire: bool = Field(
        default=True,
        description="Whether at least one Sigma rule is expected to match this event.",
    )
    expected_rule_id: str | None = Field(
        default=None,
        max_length=200,
        description="Optional: the specific rule ID expected to fire.  "
        "When set, coverage checks this rule is among the hits.",
    )


class SimulationScenario(BaseModel):
    """A named, MITRE-tagged bundle of SimulatedAttackEvents.

    A scenario typically represents one ATT&CK technique or a short chain
    (e.g. encoded-PowerShell → certutil download → mshta execution).
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=200)
    name: str = Field(..., min_length=1, max_length=300)
    description: str = ""
    technique_ids: list[str] = Field(
        ...,
        min_length=1,
        description="All MITRE ATT&CK technique IDs covered by this scenario.",
    )
    events: list[SimulatedAttackEvent] = Field(
        ...,
        min_length=1,
        description="Ordered list of simulated events to replay through the runner.",
    )


# ---------------------------------------------------------------------------
# Coverage / report output types
# ---------------------------------------------------------------------------


class CoverageResult(BaseModel):
    """Per-technique detection coverage roll-up.

    Aggregated from all SimulatedAttackEvents whose ``technique_id`` matches.
    """

    model_config = ConfigDict(extra="forbid")

    technique_id: str = Field(..., min_length=1, max_length=20)
    total_simulated: int = Field(
        ..., ge=0, description="Total events simulated for this technique."
    )
    detected: int = Field(
        ...,
        ge=0,
        description=(
            "Events with ``expected_to_fire=True`` whose required Sigma rule "
            "(``expected_rule_id``) fired. When no ``expected_rule_id`` is "
            "pinned, any rule firing counts. Benign-control events "
            "(``expected_to_fire=False``) NEVER contribute here (Codex #215)."
        ),
    )
    missed: int = Field(
        ...,
        ge=0,
        description=(
            "Events marked ``expected_to_fire=True`` that either produced no "
            "hit at all OR — when ``expected_rule_id`` is set — produced hits "
            "but the required rule wasn't among them. The second case used to "
            "be silently swallowed (Codex #215 P1)."
        ),
    )
    false_positives: int = Field(
        default=0,
        ge=0,
        description=(
            "Events marked ``expected_to_fire=False`` (benign controls) that "
            "nonetheless produced at least one Sigma hit — a false-positive "
            "signal for the analyst. Tracked separately so they never inflate "
            "``detected`` / ``detected_pct``."
        ),
    )
    rules_fired: list[str] = Field(
        default_factory=list,
        description="Unique rule IDs that fired on any event for this technique.",
    )
    rules_expected_but_missed: list[str] = Field(
        default_factory=list,
        description="Rule IDs declared in expected_rule_id that never fired.",
    )

    @property
    def detection_rate(self) -> float:
        """Fraction of expected-to-fire events that were detected (0.0–1.0)."""
        expected = self.detected + self.missed
        if expected == 0:
            return 1.0
        return self.detected / expected


class ValidationSummary(BaseModel):
    """Top-level summary statistics for a ValidationReport."""

    model_config = ConfigDict(extra="forbid")

    detected_pct: float = Field(
        ..., ge=0.0, le=100.0, description="Overall detection percentage across all techniques."
    )
    total_techniques: int = Field(..., ge=0)
    gaps: list[str] = Field(
        default_factory=list,
        description="Technique IDs with at least one expected-to-fire event that was missed.",
    )


class ValidationReport(BaseModel):
    """Result of one detection-validation run.

    Returned by :func:`btagent_shared.hunt.validation.replay_scenario` /
    :func:`btagent_backend.services.validation_service.run_validation`.
    The report is a *returned value*, not a persisted row, in this slice.
    Live ART/Caldera wiring (deferred) will populate the same shape.
    """

    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(..., min_length=1, max_length=200)
    scenarios_run: int = Field(..., ge=0)
    coverage_by_technique: list[CoverageResult]
    summary: ValidationSummary
    generated_at: datetime
