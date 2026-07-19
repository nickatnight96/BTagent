"""Pydantic schemas for the threat-hunting module.

See GitHub issue #99 for the product spec. These types are the canonical
contract between:

  * The HunterPlugin (agents/btagent_agents/plugins/hunter/)
  * The HypothesisGen + RunbookCompiler nodes (engine/btagent_engine/)
  * The future hunt CRUD API + canvas (backend/, frontend/)

Design notes (avoid drift):

1. **No heavy dependencies**. shared/ is the "zero deps beyond pydantic"
   tier so any other workspace member can import these without pulling
   LangChain, LiteLLM, MCP, etc.
2. **Enum values are lowercase strings** to match the rest of
   btagent_shared.types.enums conventions (Severity, IOCType, TLP).
3. **TTPRunbookEntry is the unit of analyst work**. Everything else
   composes from it. Adding a field here is a contract change; bump
   the schema version on HuntPlan when you do.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.config import AutonomyLevel
from btagent_shared.types.enums import Severity
from btagent_shared.types.investigation import IOC

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Backend(StrEnum):
    """SIEM / EDR query backend the hunt can target.

    Order matches the connector tier ordering in the connector strategy
    (#100). Add new backends here as their connectors land.
    """

    SPLUNK = "splunk"
    SENTINEL = "sentinel"
    DEFENDER = "defender"
    ELASTIC = "elastic"
    CROWDSTRIKE = "crowdstrike"
    SIGMA = "sigma"  # canonical / source-of-truth


class TTPState(StrEnum):
    """Lifecycle of a single TTP runbook entry during execution."""

    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    CLEAN = "clean"  # query ran, no hits
    HIT = "hit"  # at least one finding


class HuntPlanState(StrEnum):
    """Lifecycle of a hunt plan as a whole."""

    DRAFT = "draft"
    READY = "ready"
    EXECUTING = "executing"
    COMPLETED = "completed"
    ARCHIVED = "archived"


# ---------------------------------------------------------------------------
# Input shapes
# ---------------------------------------------------------------------------


class HuntScope(BaseModel):
    """Where the hunt is allowed to look.

    Mirrors the per-investigation scope object — same fields, same
    semantics — so a hunt can be initiated from an existing
    Investigation without reshaping context.
    """

    model_config = ConfigDict(extra="forbid")

    environments: list[str] = Field(
        default_factory=list,
        description="Environment / tenant identifiers (e.g. ['prod-us', 'corp-eu']).",
    )
    hosts: list[str] = Field(
        default_factory=list,
        description="Specific hostnames or asset IDs; empty == any in-scope host.",
    )
    date_from: datetime | None = Field(
        default=None,
        description="Earliest event timestamp the queries should consider.",
    )
    date_to: datetime | None = Field(
        default=None,
        description="Latest event timestamp the queries should consider. None == now.",
    )
    backends: list[Backend] = Field(
        default_factory=list,
        description="Backends available for query execution. Empty == all configured.",
    )


class HuntInput(BaseModel):
    """The thing the analyst submits to kick off a hunt.

    Any combination of (adversaries, ttps, iocs) is valid; at least one
    must be non-empty. The HypothesisGen node resolves the input into
    a prioritised hypothesis list.
    """

    model_config = ConfigDict(extra="forbid")

    adversaries: list[str] = Field(
        default_factory=list,
        description="Threat-actor names (e.g. 'APT29', 'FIN7'). Resolved against MISP + MITRE Groups.",
    )
    ttps: list[str] = Field(
        default_factory=list,
        description="ATT&CK technique IDs (e.g. 'T1059.001', 'T1078.004').",
    )
    iocs: list[IOC] = Field(
        default_factory=list,
        description="Indicators of compromise. Each IOC is mapped to plausible TTPs by the keyword mapper.",
    )
    scope: HuntScope = Field(
        default_factory=HuntScope,
        description="Where the hunt is allowed to look.",
    )
    initiated_by: str = Field(
        ...,
        description="User ID of the analyst kicking off the hunt.",
    )
    autonomy_level: AutonomyLevel = Field(
        default=AutonomyLevel.L2_SUPERVISED,
        description="How autonomous the hunt is allowed to be. L0-L1 require approval per step.",
    )


# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------


class Hypothesis(BaseModel):
    """A falsifiable claim that the hunt will test.

    The HypothesisGen node turns each HuntInput into a list of these,
    ordered by priority. The RunbookCompiler then expands each
    hypothesis into a TTPRunbookEntry with per-backend queries.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Stable hypothesis id within the plan (e.g. 'h_001').")
    ttp_id: str = Field(..., description="ATT&CK technique id this hypothesis targets.")
    ttp_name: str = Field(..., description="Human-readable technique name (cached for UI).")
    rationale: str = Field(
        ...,
        description="Why this hypothesis for *this* hunt (cites adversaries / IOCs / CTI).",
    )
    behavioral_description: str = Field(
        ...,
        description="Plain-English description of the behaviour to look for. Drives QuerySynth.",
    )
    priority: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Likelihood-weighted priority in [0, 1]. Higher == hunt first.",
    )
    sources: list[str] = Field(
        default_factory=list,
        description="Provenance trail (CTI bundle ids, adversary group refs, IOC ids).",
    )


class Query(BaseModel):
    """A backend-specific query string + its metadata."""

    model_config = ConfigDict(extra="forbid")

    backend: Backend
    query: str = Field(..., description="Raw query string in the backend's native language.")
    notes: str = Field(default="", description="Author notes (caveats, false-positive sources).")


class NoiseProfile(BaseModel):
    """Expected hit volume for a query before any tuning.

    Populated by the NoiseBaseline node (Phase A follow-up — runs the
    query in count-only mode against last-N-days telemetry). For now
    the schema is here so the runbook can carry the field even before
    the node lands.
    """

    model_config = ConfigDict(extra="forbid")

    expected_hits_per_day: float | None = None
    sample_window_days: int | None = None
    computed_at: datetime | None = None


class Finding(BaseModel):
    """A single hit recorded during a hunt step."""

    model_config = ConfigDict(extra="forbid")

    id: str
    summary: str
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="EvidenceChain entry ids that back this finding.",
    )
    severity: Severity | None = None
    recorded_at: datetime = Field(default_factory=datetime.utcnow)
    recorded_by: str | None = None


class TTPRunbookEntry(BaseModel):
    """One per TTP — the unit of analyst work in a hunt plan.

    See the diagram in issue #99 for the visual layout this maps to.
    """

    model_config = ConfigDict(extra="forbid")

    ttp_id: str
    ttp_name: str
    rationale: str
    behavioral_description: str
    queries: dict[Backend, Query] = Field(
        default_factory=dict,
        description="Per-backend queries. Empty == QuerySynth hasn't run yet.",
    )
    expected_noise: NoiseProfile = Field(default_factory=NoiseProfile)
    pivot_questions: list[str] = Field(
        default_factory=list,
        description="If a hit is found, what to ask next.",
    )
    evidence_checklist: list[str] = Field(
        default_factory=list,
        description="What to collect on hit (process tree, net conns, etc.).",
    )
    owner_id: str | None = Field(
        default=None,
        description="Analyst the entry is assigned to. None == unassigned.",
    )
    state: TTPState = Field(default=TTPState.NOT_STARTED)
    findings: list[Finding] = Field(default_factory=list)


class CorrelationRule(BaseModel):
    """Cross-TTP correlation rule fired once enough entries land hits."""

    model_config = ConfigDict(extra="forbid")

    id: str
    description: str
    trigger: str = Field(..., description="Plain-English trigger condition.")
    action: Literal["escalate_to_ir", "spawn_investigation", "notify_ic"] = "notify_ic"


class PostHuntAction(BaseModel):
    """Closed-loop action fired when the hunt completes."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal[
        "index_case_lesson",
        "propose_detection",
        "spawn_investigation",
        "update_coverage_map",
    ]
    description: str
    payload: dict[str, Any] = Field(default_factory=dict)


class ExecSummary(BaseModel):
    """The top-of-plan summary the IC reads before approving the hunt."""

    model_config = ConfigDict(extra="forbid")

    adversary_profile: str = Field(default="", description="Who they are; recent campaigns.")
    scope_description: str = Field(default="", description="Which envs / data sources.")
    success_criteria: str = Field(default="", description="What counts as a hit vs clean.")
    estimated_effort_hours: float | None = Field(
        default=None,
        description="Sum of estimated per-TTP analyst time.",
    )
    coverage_delta: dict[str, bool] = Field(
        default_factory=dict,
        description="ATT&CK technique id -> already_covered_by_deployed_detection.",
    )


# ---------------------------------------------------------------------------
# Top-level plan
# ---------------------------------------------------------------------------


class HuntPlan(BaseModel):
    """A complete hunt plan ready for execution.

    Bump `schema_version` whenever you add/remove fields here so the
    persistence layer can detect old plans and migrate them.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"

    id: str = Field(..., description="Plan id, e.g. 'hunt_01HZ...'.")
    org_id: str = Field(..., description="Tenant scope (matches the auth-hardening org_id).")
    input: HuntInput
    state: HuntPlanState = Field(default=HuntPlanState.DRAFT)

    executive_summary: ExecSummary = Field(default_factory=ExecSummary)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    ttp_entries: list[TTPRunbookEntry] = Field(default_factory=list)
    correlation_rules: list[CorrelationRule] = Field(default_factory=list)
    post_actions: list[PostHuntAction] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    workflow_version_id: str | None = Field(
        default=None,
        description="If compiled to a workflow, the version id from the workflow store.",
    )


# ---------------------------------------------------------------------------
# Phase 6 proactive-hunting subsystem vocabulary (#112/#119)
#
# Cross-cutting enums shared by every hunt *source* (hunt packs, behavioral,
# identity, cloud, cross-investigation, agentic). The concrete
# finding/cluster/suppression schemas live in
# ``btagent_shared.types.hunt_finding``; the clustering + suppression logic
# in ``btagent_shared.hunt``. Kept here so both subsystems import the hunt
# vocabulary from one module.
# ---------------------------------------------------------------------------


class HuntDomain(StrEnum):
    """The detection domain a hunt finding belongs to.

    One per Phase 6 hunt agent. Used to bucket findings and to pick the
    right enrichment / promotion path downstream.
    """

    SIGMA = "sigma"
    BEHAVIORAL = "behavioral"
    IDENTITY = "identity"
    CLOUD = "cloud"
    CROSS_INVESTIGATION = "cross_investigation"
    AGENTIC = "agentic"
    EMAIL = "email"
    DECEPTION = "deception"


class HuntSource(StrEnum):
    """What produced a finding.

    Distinct from :class:`HuntDomain`: a single domain can be reached by
    more than one source (e.g. a scheduled pack run vs. a manual analyst
    hunt both land in ``SIGMA``).
    """

    HUNT_PACK = "hunt_pack"
    BEHAVIORAL = "behavioral"
    IDENTITY = "identity"
    CLOUD = "cloud"
    CROSS_INVESTIGATION = "cross_investigation"
    AGENTIC = "agentic"
    EMAIL_SECURITY = "email_security"
    DECEPTION = "deception"
    MANUAL = "manual"


class HuntFindingState(StrEnum):
    """Lifecycle state of a single hunt finding.

    * ``NEW`` — just emitted by a hunt source, not yet clustered.
    * ``CLUSTERED`` — assigned to a :class:`HuntFindingCluster`.
    * ``TRIAGED`` — an analyst has reviewed it (acknowledged, not actioned).
    * ``SUPPRESSED`` — matched an active suppression rule; hidden from the
      default triage inbox.
    * ``PROMOTED`` — escalated into a full investigation.
    * ``DISMISSED`` — explicitly closed as not-interesting (one-off, no rule).
    """

    NEW = "new"
    CLUSTERED = "clustered"
    TRIAGED = "triaged"
    SUPPRESSED = "suppressed"
    PROMOTED = "promoted"
    DISMISSED = "dismissed"


class SuppressionState(StrEnum):
    """Lifecycle of a suppression rule.

    Suppressions are deliberately *not* permanent: a stale-suppression
    sweep (the Phase 6 arq cron) flips ``ACTIVE`` rules that are past their
    ``reconfirm_at`` to ``NEEDS_RECONFIRM`` so a human re-affirms that the
    noise is still expected, and past ``expires_at`` to ``EXPIRED``.
    """

    ACTIVE = "active"
    NEEDS_RECONFIRM = "needs_reconfirm"
    EXPIRED = "expired"
    REVOKED = "revoked"
