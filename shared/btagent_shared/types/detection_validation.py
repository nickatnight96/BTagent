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

from btagent_shared.types.enums import Severity

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DetectionStatus(StrEnum):
    """Whether a simulation event was detected by at least one rule."""

    detected = "detected"
    missed = "missed"
    not_expected = "not_expected"


class TargetEnv(StrEnum):
    """Where a detection-validation *emulation* is aimed.

    This is the single most safety-critical field in the whole feature: the
    live emulators (Atomic Red Team, MITRE Caldera) fire *real* ATT&CK
    techniques, so the sandbox-enforcement layer
    (:mod:`btagent_shared.security.sandbox`) refuses any trigger whose
    ``target_env`` is not an approved SANDBOX — with an audit-logged denial and
    without ever reaching an emulator. Only :data:`TargetEnv.SANDBOX` is
    approved for emulation; everything else (staging, production, or an
    unknown/blank value) is denied fail-closed.
    """

    SANDBOX = "sandbox"
    STAGING = "staging"
    PRODUCTION = "production"
    UNKNOWN = "unknown"


class Emulator(StrEnum):
    """Which adversary-emulation engine drives a validation run."""

    ATOMIC_RED_TEAM = "atomic_red_team"
    CALDERA = "caldera"


class ValidationVerdict(StrEnum):
    """Outcome of scoring one emulated technique against observed detections.

    * ``validated`` — an expected rule fired within the latency SLA at the
      expected severity.
    * ``wrong_severity`` — the rule fired in time but at a different severity
      than expected (a triage-quality gap, not a coverage gap).
    * ``late`` — the rule fired, but only *after* the post-trigger latency SLA
      window (a mean-time-to-detect gap).
    * ``silent_gap`` — no rule fired at all within the observation window (a
      true coverage gap).
    * ``errored`` — the emulation or observation itself failed; the run could
      not be scored (never silently treated as a pass).
    """

    VALIDATED = "validated"
    WRONG_SEVERITY = "wrong_severity"
    LATE = "late"
    SILENT_GAP = "silent_gap"
    ERRORED = "errored"


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
# Emulation request (live ATT&CK trigger — sandbox-gated)
# ---------------------------------------------------------------------------


class EmulationRequest(BaseModel):
    """A request to emulate one ATT&CK technique and validate detection of it.

    Carries the safety-critical ``target_env``: the sandbox-enforcement layer
    refuses (audited) any request whose ``target_env`` is not an approved
    SANDBOX before any emulator is dispatched. In this foundation slice the
    emulators run mock-first (``BTAGENT_MOCK_CONNECTORS`` default), so a
    request never fires a real technique regardless — but the sandbox gate is
    the control that must hold once live mode is wired.
    """

    model_config = ConfigDict(extra="forbid")

    technique_id: str = Field(
        ...,
        min_length=1,
        max_length=20,
        description="MITRE ATT&CK technique to emulate (e.g. 'T1059.001').",
    )
    target_env: TargetEnv = Field(
        default=TargetEnv.UNKNOWN,
        description="Where the emulation is aimed. Only SANDBOX is approved; "
        "anything else is refused (audited) before any emulator runs.",
    )
    emulator: Emulator = Field(
        default=Emulator.ATOMIC_RED_TEAM,
        description="Which adversary-emulation engine to drive the trigger.",
    )
    expected_severity: Severity = Field(
        default=Severity.HIGH,
        description="Severity the firing detection is expected to raise at "
        "(used to distinguish a clean pass from wrong_severity).",
    )
    latency_sla_seconds: float = Field(
        default=300.0,
        gt=0,
        description="Post-trigger window within which a detection must fire to "
        "count as on-time; a later firing scores as 'late'.",
    )
    description: str = Field(default="", max_length=500)


# ---------------------------------------------------------------------------
# Coverage / report output types
# ---------------------------------------------------------------------------


class RuleFiring(BaseModel):
    """One detection-rule firing observed from a SIEM/EDR after a trigger.

    Produced by the observe phase of the :class:`ValidationOrchestrator`: after
    an emulator fires a technique, the orchestrator polls a SIEM/EDR source for
    rules that fired and normalises each hit into a ``RuleFiring``.
    """

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., min_length=1, max_length=200)
    rule_title: str = Field(default="", max_length=300)
    technique_id: str = Field(..., min_length=1, max_length=20)
    severity: Severity = Field(default=Severity.MEDIUM)
    source: str = Field(
        default="",
        max_length=64,
        description="Detection source the firing was observed from (e.g. the "
        "SIEM/EDR MCP server_id: 'splunk', 'crowdstrike').",
    )
    latency_seconds: float = Field(
        default=0.0,
        ge=0,
        description="Seconds between the trigger and this rule firing.",
    )


class CoverageDelta(BaseModel):
    """Expected-vs-observed rule coverage for one technique.

    ``missing_rules`` is the actionable gap: rules that *should* have fired for
    the technique but did not. ``last_validated`` is when this technique last
    produced a non-errored verdict — the field the deferred ">90d untested"
    query (Phase-C, #113) will read.
    """

    model_config = ConfigDict(extra="forbid")

    technique_id: str = Field(..., min_length=1, max_length=20)
    expected_rules: list[str] = Field(default_factory=list)
    fired_rules: list[str] = Field(default_factory=list)
    missing_rules: list[str] = Field(default_factory=list)
    last_validated: datetime | None = Field(
        default=None,
        description="When this technique last produced a non-errored verdict.",
    )


class TechniqueVerdict(BaseModel):
    """Scored outcome of emulating and observing one technique."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str = Field(..., min_length=1, max_length=20)
    verdict: ValidationVerdict
    emulator: Emulator
    expected_severity: Severity
    observed_severity: Severity | None = None
    latency_seconds: float | None = Field(
        default=None, description="Latency of the earliest matching firing, if any."
    )
    latency_sla_seconds: float = Field(..., gt=0)
    fired_rules: list[RuleFiring] = Field(default_factory=list)
    coverage_delta: CoverageDelta
    detail: str = Field(default="", max_length=500)


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
    :func:`btagent_backend.services.validation_service.run_validation`, and
    persisted per run to ``detection_validation_runs``
    (:class:`btagent_backend.db.models_validation.DetectionValidationRunRow`).

    Still deterministic simulation/replay: live ART/Caldera execution is
    deferred (#118) and needs security sign-off, but it will populate this
    same shape.
    """

    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(..., min_length=1, max_length=200)
    scenarios_run: int = Field(..., ge=0)
    coverage_by_technique: list[CoverageResult]
    summary: ValidationSummary
    generated_at: datetime
    # ---- Emulation-path additions (#118 foundation) ----------------------
    # These stay optional so the in-process pySigma replay path (which builds a
    # report with build_report) is untouched; the ValidationOrchestrator fills
    # them when a run went through a sandbox-gated emulator trigger.
    emulation_target_env: TargetEnv | None = Field(
        default=None,
        description="Approved SANDBOX the emulation ran in, when this run went "
        "through the emulator path. None for pure in-process replay runs.",
    )
    verdicts: list[TechniqueVerdict] = Field(
        default_factory=list,
        description="Per-technique scored verdicts from the emulator path.",
    )
