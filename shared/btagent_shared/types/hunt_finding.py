"""Hunt finding / cluster / suppression schemas (Phase 6 keystone).

This is the contract every Phase 6 hunt source emits into and that the
Hunt Triage Agent (#119) operates on. It bridges hunting back to the
existing investigation pipeline: a promoted finding seeds an
``InvestigationRow`` carrying its observables, technique mapping, and
evidence.

These mirror :class:`btagent_backend.db.models_hunt.{HuntFindingRow,
HuntFindingClusterRow, SuppressionRuleRow}` and are the request/response
shapes for ``/api/v1/hunt/findings``.

The pure clustering + suppression-matching logic that operates on
:class:`HuntFinding` lives in :mod:`btagent_shared.hunt.triage` so it
stays free of DB / network deps and can be reused as an engine node body.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt import (
    HuntDomain,
    HuntFindingState,
    HuntSource,
    SuppressionState,
)


class HuntEntity(BaseModel):
    """A subject of a finding — a host, user, account, workload, etc.

    ``kind`` is a free-ish label (``host`` / ``user`` / ``oauth_app`` / …)
    so each hunt domain can use its own taxonomy without a schema change;
    ``value`` is the stable identifier used for clustering + suppression.
    """

    model_config = ConfigDict(extra="forbid")

    kind: str = Field(..., min_length=1, max_length=64)
    value: str = Field(..., min_length=1, max_length=512)


class HuntObservable(BaseModel):
    """An IOC-shaped artifact attached to a finding (ip, hash, domain, …)."""

    model_config = ConfigDict(extra="forbid")

    type: str = Field(..., min_length=1, max_length=64)
    value: str = Field(..., min_length=1, max_length=2048)


class SuppressionMatch(BaseModel):
    """Criteria a suppression rule matches a finding against.

    Semantics: a finding matches the rule when **every** specified
    criterion matches (AND across criteria), and within a list criterion
    an **overlap** is sufficient (OR within a list). An all-``None`` match
    matches everything — that's the canonical "over-broad" case the triage
    service refuses (see :func:`btagent_shared.hunt.triage.is_overbroad`).
    """

    model_config = ConfigDict(extra="forbid")

    source: HuntSource | None = None
    domain: HuntDomain | None = None
    technique_ids: list[str] = Field(default_factory=list)
    entity_values: list[str] = Field(default_factory=list)
    observable_values: list[str] = Field(default_factory=list)
    # Detection-rule ids, matched against ``finding.evidence["rule_id"]``
    # (the provenance every pack-runner finding carries). This is the
    # criterion the #112 noise baseline needs: "suppress THIS chronically
    # noisy rule" without touching sibling rules in the same pack/domain.
    # Findings with no evidence rule_id never match a rule_ids criterion.
    rule_ids: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Core finding
# --------------------------------------------------------------------------- #


class HuntFinding(BaseModel):
    """A single proactive-hunt result.

    Emitted by any hunt source, clustered by the triage agent, and either
    suppressed, dismissed, or promoted into an investigation.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    org_id: str
    source: HuntSource
    domain: HuntDomain
    title: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    technique_ids: list[str] = Field(default_factory=list)
    entities: list[HuntEntity] = Field(default_factory=list)
    observables: list[HuntObservable] = Field(default_factory=list)
    state: HuntFindingState = HuntFindingState.NEW
    cluster_id: str | None = None
    suppressed_by: str | None = None
    investigation_id: str | None = None
    # Free-form provenance: which run/rule/baseline produced this, plus the
    # evidence-chain hash so a promotion carries forensic lineage.
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class HuntFindingCluster(BaseModel):
    """A group of near-duplicate findings sharing a clustering signature."""

    model_config = ConfigDict(extra="forbid")

    id: str
    org_id: str
    signature: str
    title: str
    domain: HuntDomain
    severity: Severity
    technique_ids: list[str] = Field(default_factory=list)
    finding_count: int = 0
    state: HuntFindingState = HuntFindingState.CLUSTERED
    representative_finding_id: str | None = None
    created_at: datetime
    updated_at: datetime


class SuppressionRule(BaseModel):
    """A persisted noise-suppression rule."""

    model_config = ConfigDict(extra="forbid")

    id: str
    org_id: str
    name: str
    reason: str
    match: SuppressionMatch
    state: SuppressionState = SuppressionState.ACTIVE
    match_count: int = 0
    created_by: str | None = None
    created_at: datetime
    expires_at: datetime | None = None
    reconfirm_at: datetime | None = None
    # Harmful-flag: set when this rule is found to have been hiding a
    # confirmed-threat finding (set by promote_to_investigation).
    harmful_flag: bool = False
    harmful_reason: str | None = None
    harmful_finding_id: str | None = None


# --------------------------------------------------------------------------- #
# Request payloads
# --------------------------------------------------------------------------- #


class RecordFindingRequest(BaseModel):
    """Body for ``POST /hunt/findings`` — used by hunt sources (and tests).

    The id, state, cluster assignment, and timestamps are server-assigned;
    callers supply only the detection payload.
    """

    model_config = ConfigDict(extra="forbid")

    source: HuntSource
    domain: HuntDomain
    title: str = Field(..., min_length=1, max_length=300)
    description: str = Field(default="", max_length=8192)
    severity: Severity = Severity.MEDIUM
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    technique_ids: list[str] = Field(default_factory=list)
    entities: list[HuntEntity] = Field(default_factory=list)
    observables: list[HuntObservable] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class CreateSuppressionRequest(BaseModel):
    """Body for ``POST /hunt/findings/{id}/suppress`` and ``POST /hunt/suppressions``."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=200)
    reason: str = Field(..., min_length=1, max_length=2048)
    match: SuppressionMatch
    # Optional TTL + re-confirmation window (hours from now). The stale-
    # suppression sweep uses these; omitting them means "until revoked",
    # which the service still nudges via a default reconfirm window.
    expires_in_hours: int | None = Field(default=None, ge=1, le=8760)
    reconfirm_in_hours: int | None = Field(default=None, ge=1, le=8760)
    # Set to True to acknowledge that this rule is over-broad and proceed
    # anyway. Only honoured when the caller has incident_commander or admin
    # role; lower roles are still rejected regardless of this flag.
    acknowledge_overbroad: bool = False


class PromoteFindingsRequest(BaseModel):
    """Body for ``POST /hunt/findings/promote`` — escalate to an investigation."""

    model_config = ConfigDict(extra="forbid")

    finding_ids: list[str] = Field(..., min_length=1)
    title: str | None = Field(default=None, min_length=1, max_length=300)


class SuppressClusterRequest(BaseModel):
    """Body for ``POST /hunt/clusters/{id}/suppress`` — bulk-suppress a cluster.

    ``match`` is optional: when omitted, the service derives the criteria
    from the cluster's pattern (domain + technique set) so future findings
    of the same shape are suppressed too, not just the current members.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=200)
    reason: str = Field(..., min_length=1, max_length=2048)
    match: SuppressionMatch | None = None
    expires_in_hours: int | None = Field(default=None, ge=1, le=8760)
    reconfirm_in_hours: int | None = Field(default=None, ge=1, le=8760)
    # Set to True to acknowledge that this rule is over-broad and proceed
    # anyway. Only honoured when the caller has incident_commander or admin
    # role; lower roles are still rejected regardless of this flag.
    acknowledge_overbroad: bool = False


class PromoteClusterRequest(BaseModel):
    """Body for ``POST /hunt/clusters/{id}/promote`` — escalate a whole cluster."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=300)


# --------------------------------------------------------------------------- #
# Response payloads
# --------------------------------------------------------------------------- #


class HuntFindingClusterListResponse(BaseModel):
    """Clustered triage inbox: clusters + their (capped) member findings."""

    model_config = ConfigDict(extra="forbid")

    clusters: list[HuntFindingCluster]
    findings: list[HuntFinding]
    total_clusters: int
    total_findings: int


class SuppressionListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[SuppressionRule]
    total: int


class PromoteFindingsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    investigation_id: str
    promoted_finding_ids: list[str]


class HuntPackRun(BaseModel):
    """One scheduled / ad-hoc hunt-pack execution's history record (#112).

    Mirrors :class:`btagent_backend.db.models_hunt.HuntPackRunRow`. The
    ``rule_stats`` map is ``{rule_id: {"title", "hits", "errors"}}`` — the
    per-rule rollup the future noise baselines read.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    org_id: str
    run_id: str
    pack_id: str
    pack_name: str
    pack_version: str = ""
    backends: list[str] = Field(default_factory=list)
    rule_stats: dict[str, Any] = Field(default_factory=dict)
    hit_count: int = 0
    error_count: int = 0
    findings_created: int = 0
    status: str = "completed"
    error: str | None = None
    started_at: datetime
    completed_at: datetime | None = None


class HuntPackRunListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[HuntPackRun]
    total: int
