"""Hunt Pack schemas (Phase 6 #112 — Hunt Pack Runner).

A *hunt pack* is a versioned bundle of Sigma rules (community + private) with
per-rule MITRE mapping, noise baselines, and tuning notes. The Hunt Pack
Runner transpiles each rule to every connected SIEM/EDR backend, executes on
a schedule, and lands hits as :class:`btagent_shared.types.hunt_finding.HuntFinding`
records in the #119 triage queue.

These are the data contracts; the pure pack-loading / baseline-classification
logic lives in :mod:`btagent_shared.hunt.huntpack`, the Sigma transpiler in
``agents/btagent_agents/plugins/hunter/sigma_compiler.py``, and the scheduled
runner job in ``backend/btagent_backend/scheduler``.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.config import AutonomyLevel
from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt_finding import SuppressionMatch


class SiemBackend(StrEnum):
    """SIEM/EDR query backends a Sigma rule can be transpiled to.

    Values match the platform strings already used by the query plugin
    (``agents/.../plugins/query``) so the runner can hand a compiled query
    straight to the existing executor / MCP connectors.
    """

    SPLUNK = "splunk"
    SENTINEL = "sentinel"
    ELASTIC = "elastic"
    CROWDSTRIKE = "crowdstrike"


class HuntPackSource(StrEnum):
    """Provenance of a hunt pack."""

    SIGMAHQ = "sigmahq"
    PRIVATE = "private"
    AI_AUTHORED = "ai-authored"


class HuntRuleState(StrEnum):
    """Per-rule health relative to its noise baseline.

    * ``CLEAN`` — zero hits this run, consistent with a quiet baseline.
    * ``FIRING_AS_EXPECTED`` — hits within the baseline's expected band.
    * ``OVER_FIRING`` — hits well above baseline; candidate for tuning.
    * ``UNDER_FIRING`` — long-term zero hits; possible coverage gap / stale.
    * ``ERRORED`` — transpile or execution failed on this run.
    """

    CLEAN = "clean"
    FIRING_AS_EXPECTED = "firing_as_expected"
    OVER_FIRING = "over_firing"
    UNDER_FIRING = "under_firing"
    ERRORED = "errored"


class HuntRunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class NoiseProfile(BaseModel):
    """Rolling per-rule hit-count baseline for one environment.

    Deliberately simple: an exponentially-weighted-ish rolling mean plus a
    sample count. ``expected_max`` is the over-firing threshold derived from
    the mean (see :func:`btagent_shared.hunt.huntpack.classify_rule_state`).
    """

    model_config = ConfigDict(extra="forbid")

    mean_hits: float = 0.0
    sample_count: int = 0
    last_count: int | None = None
    # Consecutive runs with zero hits — drives the UNDER_FIRING flag.
    consecutive_zero_runs: int = 0


class HuntRule(BaseModel):
    """A single Sigma rule within a pack, plus its compiled forms + tuning."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str = Field(..., min_length=1, max_length=300)
    sigma_yaml: str = Field(..., min_length=1)
    mitre_techniques: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    # Populated at compile time: backend value -> transpiled query string.
    backend_queries: dict[SiemBackend, str] = Field(default_factory=dict)
    noise_baseline: NoiseProfile = Field(default_factory=NoiseProfile)
    # Inline suppression criteria applied to this rule's hits before they
    # become findings (reuses the #119 SuppressionMatch shape).
    tuning: list[SuppressionMatch] = Field(default_factory=list)
    state: HuntRuleState = HuntRuleState.CLEAN


class HuntPackManifest(BaseModel):
    """A versioned bundle of hunt rules with provenance."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=200)
    version: str = Field(..., min_length=1, max_length=64)
    source: HuntPackSource
    signed_by: str | None = None
    description: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    enabled_by_default: bool = False
    rules: list[HuntRule] = Field(default_factory=list)


class HuntSchedule(BaseModel):
    """When + how a pack runs."""

    model_config = ConfigDict(extra="forbid")

    pack_id: str
    cron_expr: str = "0 */4 * * *"
    lookback_window: timedelta = timedelta(hours=24)
    autonomy_level: AutonomyLevel = AutonomyLevel.L2_SUPERVISED
    backends: list[SiemBackend] = Field(default_factory=list)


class HuntRun(BaseModel):
    """One execution of a pack across its scheduled backends."""

    model_config = ConfigDict(extra="forbid")

    id: str
    pack_id: str
    started_at: datetime
    completed_at: datetime | None = None
    status: HuntRunStatus = HuntRunStatus.PENDING
    rules_executed: int = 0
    findings_emitted: int = 0
    cost_estimate: float = 0.0
