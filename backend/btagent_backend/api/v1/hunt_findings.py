"""Hunt triage API — clustered findings inbox, suppression, promotion (#119).

Thin route layer: Pydantic validation, RBAC + org scoping, and translation
of service ``ValueError`` into 4xx. All mutation flows through
:mod:`btagent_backend.services.hunt_triage_service` so the cluster-on-insert
and over-broad-suppression invariants stay in one place.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt import HuntDomain, HuntFindingState, SuppressionState
from btagent_shared.types.hunt_finding import (
    CreateSuppressionRequest,
    HuntFinding,
    HuntFindingCluster,
    HuntFindingClusterListResponse,
    HuntPackRun,
    HuntPackRunListResponse,
    PromoteClusterRequest,
    PromoteFindingsRequest,
    PromoteFindingsResponse,
    RecordFindingRequest,
    SuppressClusterRequest,
    SuppressionListResponse,
    SuppressionRule,
)
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models_hunt import (
    HuntFindingClusterRow,
    HuntFindingRow,
    HuntPackRunRow,
    SuppressionRuleRow,
)
from btagent_backend.services import (
    agentic_hunt_run_service,
    all_hunts_run_service,
    cloud_hunt_run_service,
    deception_hunt_run_service,
    email_hunt_run_service,
    hunt_pack_run_service,
    hunt_vertical_catalog,
    ndr_hunt_run_service,
    noise_baseline,
)
from btagent_backend.services import hunt_triage_service as svc

logger = logging.getLogger("btagent.api.hunt_findings")

router = APIRouter(prefix="/hunt", tags=["hunt"])


# --------------------------------------------------------------------------- #
# Row -> response converters
# --------------------------------------------------------------------------- #


def _cluster_response(row: HuntFindingClusterRow) -> HuntFindingCluster:
    return HuntFindingCluster(
        id=row.id,
        org_id=row.org_id,
        signature=row.signature,
        title=row.title,
        domain=HuntDomain(row.domain),
        severity=Severity(row.severity),
        technique_ids=list(row.technique_ids or []),
        finding_count=row.finding_count,
        state=HuntFindingState(row.state),
        representative_finding_id=row.representative_finding_id,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _pack_run_response(row: HuntPackRunRow) -> HuntPackRun:
    return HuntPackRun(
        id=row.id,
        org_id=row.org_id,
        run_id=row.run_id,
        pack_id=row.pack_id,
        pack_name=row.pack_name,
        pack_version=row.pack_version,
        backends=list(row.backends or []),
        rule_stats=dict(row.rule_stats or {}),
        hit_count=row.hit_count,
        error_count=row.error_count,
        findings_created=row.findings_created,
        status=row.status,
        error=row.error,
        started_at=row.started_at,
        completed_at=row.completed_at,
    )


def _suppression_response(row: SuppressionRuleRow) -> SuppressionRule:
    return SuppressionRule(
        id=row.id,
        org_id=row.org_id,
        name=row.name,
        reason=row.reason,
        match=svc.row_to_suppression(row),
        state=SuppressionState(row.state),
        match_count=row.match_count,
        created_by=row.created_by,
        created_at=row.created_at,
        expires_at=row.expires_at,
        reconfirm_at=row.reconfirm_at,
        harmful_flag=bool(row.harmful_flag),
        harmful_reason=row.harmful_reason,
        harmful_finding_id=row.harmful_finding_id,
    )


async def _load_finding_scoped(
    db: AsyncSession, finding_id: str, user: CurrentUser
) -> HuntFindingRow:
    """Fetch a finding; 404 if missing or cross-tenant (IDOR-safe)."""
    row = await svc.get_finding(db, finding_id)
    if row is None or row.org_id != user.org_id:
        raise HTTPException(status_code=404, detail="Hunt finding not found")
    return row


async def _load_cluster_scoped(
    db: AsyncSession, cluster_id: str, user: CurrentUser
) -> HuntFindingClusterRow:
    """Fetch a cluster; 404 if missing or cross-tenant (IDOR-safe)."""
    row = await svc.get_cluster(db, cluster_id)
    if row is None or row.org_id != user.org_id:
        raise HTTPException(status_code=404, detail="Hunt finding cluster not found")
    return row


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


@router.post("/findings", response_model=HuntFinding, status_code=201)
async def record_finding(
    body: RecordFindingRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Record a hunt finding (used by hunt sources). Clusters + suppresses on insert."""
    user.require_permission("hunt:create")
    row = await svc.record_finding(
        db,
        org_id=user.org_id,
        source=body.source.value,
        domain=body.domain.value,
        title=body.title,
        description=body.description,
        severity=body.severity,
        confidence=body.confidence,
        technique_ids=body.technique_ids,
        entities=[e.model_dump() for e in body.entities],
        observables=[o.model_dump() for o in body.observables],
        evidence=body.evidence,
    )
    return svc.row_to_finding(row)


class EmailHuntRunRequest(BaseModel):
    """Trigger an email hunt over a time window.

    Supply ``lookback_hours`` (default 24h back from now) or an explicit
    ``start`` / ``end`` ISO-8601 pair; the explicit pair wins when both are
    given.
    """

    lookback_hours: int = Field(default=24, ge=1, le=8760)
    start: str | None = Field(
        default=None, description="ISO-8601 window start (overrides lookback)"
    )
    end: str | None = Field(default=None, description="ISO-8601 window end (overrides lookback)")


class EmailHuntRunResponse(BaseModel):
    window: dict[str, str]
    total_incidents: int
    active_incident_count: int
    findings_emitted: int
    findings_created: int
    counts_by_severity: dict[str, int]


@router.post("/email/run", response_model=EmailHuntRunResponse, status_code=201)
async def run_email_hunt(
    body: EmailHuntRunRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Run an email hunt across the email connectors and land its findings.

    Gathers Defender for O365 / Proofpoint / Mimecast telemetry over the
    window, correlates it into phishing incidents, maps those into
    ``email``-domain hunt findings, and persists them into the triage inbox
    (clustered + suppression-checked on insert). Mock-first: returns the
    deterministic fixture-driven findings until the connectors are live-wired.
    """
    user.require_permission("hunt:create")

    if body.start and body.end:
        start, end = body.start, body.end
    else:
        now = datetime.now(UTC)
        start = (now - timedelta(hours=body.lookback_hours)).isoformat()
        end = now.isoformat()

    summary = await email_hunt_run_service.run_email_hunt_and_ingest(
        db, org_id=user.org_id, start=start, end=end
    )
    return EmailHuntRunResponse(**{k: summary[k] for k in EmailHuntRunResponse.model_fields})


class DeceptionHuntRunResponse(BaseModel):
    total_incidents: int
    active_intruder_count: int
    findings_emitted: int
    findings_created: int
    counts_by_severity: dict[str, int]


@router.post("/deception/run", response_model=DeceptionHuntRunResponse, status_code=201)
async def run_deception_hunt(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Run a deception hunt over the Thinkst Canary connector and land findings.

    Gathers canary incidents, correlates them into ranked deception incidents,
    maps those into ``deception``-domain hunt findings, and persists them into
    the triage inbox (clustered + suppression-checked on insert). Deception is
    the fleet's highest-fidelity signal — every canary trip is a near-zero-
    false-positive intruder signal. Mock-first until the connector is
    live-wired.
    """
    user.require_permission("hunt:create")

    summary = await deception_hunt_run_service.run_deception_hunt_and_ingest(db, org_id=user.org_id)
    return DeceptionHuntRunResponse(
        **{k: summary[k] for k in DeceptionHuntRunResponse.model_fields}
    )


class NdrHuntRunResponse(BaseModel):
    total_hosts: int
    campaign_count: int
    findings_emitted: int
    findings_created: int
    counts_by_severity: dict[str, int]


@router.post("/ndr/run", response_model=NdrHuntRunResponse, status_code=201)
async def run_ndr_hunt(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Run an NDR hunt over the Vectra AI connector and land findings.

    Gathers Vectra network detections, correlates them into ranked per-host
    kill-chain campaign rollups, maps those into ``ndr``-domain hunt findings,
    and persists them into the triage inbox (clustered + suppression-checked on
    insert). Mock-first until the connector is live-wired.
    """
    user.require_permission("hunt:create")

    summary = await ndr_hunt_run_service.run_ndr_hunt_and_ingest(db, org_id=user.org_id)
    return NdrHuntRunResponse(**{k: summary[k] for k in NdrHuntRunResponse.model_fields})


class AgenticHuntRunResponse(BaseModel):
    total_events: int
    total_identities: int
    total_workloads: int
    findings_emitted: int
    findings_created: int
    counts_by_severity: dict[str, int]


@router.post("/agentic/run", response_model=AgenticHuntRunResponse, status_code=201)
async def run_agentic_hunt(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Run an agentic-AI misuse hunt and land its findings (#121).

    Runs the connector-independent detectors (prompt-injection, shadow agent /
    MCP discovery, agent-identity abuse) over the demo observation bundle, maps
    their output into ``agentic``-domain hunt findings, and persists them into
    the triage inbox (clustered + suppression-checked on insert). Mock-first:
    the agentic domain has no live telemetry connector yet, so this runs over a
    deterministic synthetic bundle until agent-platform connectors are wired.
    """
    user.require_permission("hunt:create")

    summary = await agentic_hunt_run_service.run_agentic_hunt_and_ingest(db, org_id=user.org_id)
    return AgenticHuntRunResponse(**{k: summary[k] for k in AgenticHuntRunResponse.model_fields})


class CloudHuntRunResponse(BaseModel):
    total_identities: int
    total_workloads: int
    total_cloudtrail_events: int
    total_resource_events: int
    findings_emitted: int
    findings_created: int
    counts_by_severity: dict[str, int]


@router.post("/cloud/run", response_model=CloudHuntRunResponse, status_code=201)
async def run_cloud_hunt(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Run a cloud control-plane hunt and land its findings (#117).

    Runs the connector-independent detectors (cross-account trust abuse, shadow
    workloads, overprivileged identities, and — on the live path — STS chaining,
    IAM persistence, snapshot share, CloudTrail tamper) over the demo observation
    bundle, maps their output into ``cloud``-domain hunt findings, and persists
    them into the triage inbox (clustered + suppression-checked on insert).
    Mock-first: the cloud domain has no live control-plane connector yet, so this
    runs over a deterministic synthetic bundle until connectors are wired.
    """
    user.require_permission("hunt:create")

    summary = await cloud_hunt_run_service.run_cloud_hunt_and_ingest(db, org_id=user.org_id)
    return CloudHuntRunResponse(**{k: summary[k] for k in CloudHuntRunResponse.model_fields})


class VerticalRunSummary(BaseModel):
    findings_emitted: int
    findings_created: int
    counts_by_severity: dict[str, int]


class AllHuntsRunResponse(BaseModel):
    verticals: dict[str, VerticalRunSummary]
    total_findings_emitted: int
    total_findings_created: int
    counts_by_severity: dict[str, int]


class AllHuntsRunRequest(BaseModel):
    """Trigger a combined sweep. The window applies to the email vertical only.

    Supply ``lookback_hours`` (default 24h back from now) or an explicit
    ``start`` / ``end`` ISO-8601 pair; the explicit pair wins when both are
    given. Deception and NDR are windowless and ignore these.
    """

    lookback_hours: int = Field(default=24, ge=1, le=8760)
    start: str | None = Field(
        default=None, description="ISO-8601 email-window start (overrides lookback)"
    )
    end: str | None = Field(
        default=None, description="ISO-8601 email-window end (overrides lookback)"
    )


@router.post("/all/run", response_model=AllHuntsRunResponse, status_code=201)
async def run_all_hunts(
    body: AllHuntsRunRequest | None = None,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Run every findings-vertical hunt (email, deception, NDR) in one sweep.

    Fans out over all three verticals in sequence against the same session and
    lands their findings in the triage inbox (clustered + suppression-checked on
    insert), returning a per-vertical breakdown plus the aggregate rollup. Each
    vertical's gather is failure-tolerant, so a single down connector degrades
    that vertical to zero findings rather than sinking the sweep. Mock-first
    until the connectors are live-wired.
    """
    user.require_permission("hunt:create")

    body = body or AllHuntsRunRequest()
    summary = await all_hunts_run_service.run_all_hunts_and_ingest(
        db,
        org_id=user.org_id,
        lookback_hours=body.lookback_hours,
        start=body.start,
        end=body.end,
    )
    return AllHuntsRunResponse(
        verticals={
            name: VerticalRunSummary(**vsummary) for name, vsummary in summary["verticals"].items()
        },
        total_findings_emitted=summary["total_findings_emitted"],
        total_findings_created=summary["total_findings_created"],
        counts_by_severity=summary["counts_by_severity"],
    )


class HuntVertical(BaseModel):
    name: str
    domain: str
    source: str
    run_route: str
    windowed: bool
    scheduled: bool
    schedule_enabled: bool
    scan_interval_hours: int


class HuntVerticalListResponse(BaseModel):
    verticals: list[HuntVertical]


@router.get("/verticals", response_model=HuntVerticalListResponse)
async def get_hunt_verticals(
    user: CurrentUser = Depends(get_current_user),
):
    """List the manual-runnable findings verticals and their schedule status.

    Read-only reflection of config: each entry carries its ``run_route`` plus
    the derived ``schedule_enabled`` gate and ``scan_interval_hours`` cadence,
    so an operator can see which proactive hunts exist and which are on a cron.
    """
    user.require_permission("hunt:view")
    return HuntVerticalListResponse(
        verticals=[HuntVertical(**v) for v in hunt_vertical_catalog.list_hunt_verticals()]
    )


@router.get("/findings", response_model=HuntFindingClusterListResponse)
async def list_findings(
    include_suppressed: bool = Query(False),
    state: str = Query(
        "all",
        pattern="^(active|suppressed|promoted|all)$",
        description=(
            "Filter clusters by aggregate state, applied server-side before "
            "pagination. 'active' = new/clustered, 'suppressed', 'promoted', "
            "'all' (default, no filter). An explicit state takes precedence "
            "over include_suppressed."
        ),
    ),
    domain: str | None = Query(
        None,
        pattern="^(sigma|behavioral|identity|cloud|cross_investigation|agentic|email|deception|ndr)$",
        description=(
            "Optional ``HuntDomain`` filter applied server-side before pagination. "
            "Used by the per-domain hunt views (/cloud-hunts, /identity-hunts, …) "
            "so domain-specific pages don't have to page through cross-domain "
            "findings (Codex #216/#217)."
        ),
    ),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Clustered triage inbox for the caller's org."""
    user.require_permission("hunt:view")
    clusters, findings, total_clusters, total_findings = await svc.list_clusters(
        db,
        org_id=user.org_id,
        include_suppressed=include_suppressed,
        state=state,
        domain=domain,
        page=page,
        page_size=page_size,
    )
    return HuntFindingClusterListResponse(
        clusters=[_cluster_response(c) for c in clusters],
        findings=[svc.row_to_finding(f) for f in findings],
        total_clusters=total_clusters,
        total_findings=total_findings,
    )


@router.get("/findings/{finding_id}", response_model=HuntFinding)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    user.require_permission("hunt:view")
    row = await _load_finding_scoped(db, finding_id, user)
    return svc.row_to_finding(row)


@router.post("/findings/{finding_id}/suppress", response_model=SuppressionRule, status_code=201)
async def suppress_finding(
    finding_id: str,
    body: CreateSuppressionRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Create a suppression rule from a finding and apply it.

    The rule's ``match`` must actually match the target finding (a guard
    against pasting the wrong criteria); 409 if the rule is over-broad.
    """
    user.require_permission("hunt:suppress")
    row = await _load_finding_scoped(db, finding_id, user)

    from btagent_shared.hunt import triage

    if not triage.suppression_matches(body.match, svc.row_to_finding(row)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Suppression match does not apply to the target finding",
        )
    try:
        rule, _count = await svc.create_suppression(
            db,
            org_id=user.org_id,
            name=body.name,
            reason=body.reason,
            match=body.match,
            created_by=user.id,
            actor=user.username,
            target=f"hunt_finding:{row.id}",
            expires_in_hours=body.expires_in_hours,
            reconfirm_in_hours=body.reconfirm_in_hours,
            acknowledge_overbroad=body.acknowledge_overbroad,
            caller_role=user.role,
        )
    except svc.OverbroadSuppressionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return _suppression_response(rule)


@router.post("/findings/promote", response_model=PromoteFindingsResponse, status_code=201)
async def promote_findings(
    body: PromoteFindingsRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Escalate one or more findings into a new investigation."""
    user.require_permission("hunt:promote")
    try:
        inv, promoted = await svc.promote_to_investigation(
            db,
            org_id=user.org_id,
            finding_ids=body.finding_ids,
            title=body.title,
            assigned_to=user.id,
            actor=user.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return PromoteFindingsResponse(investigation_id=inv.id, promoted_finding_ids=promoted)


# --------------------------------------------------------------------------- #
# Cluster-level actions
# --------------------------------------------------------------------------- #


@router.post("/clusters/{cluster_id}/suppress", response_model=SuppressionRule, status_code=201)
async def suppress_cluster(
    cluster_id: str,
    body: SuppressClusterRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Bulk-suppress a cluster (one rule covering the cluster's pattern).

    Omitting ``match`` derives the criteria from the cluster's pattern
    (domain + technique set); 400 if an explicit match doesn't apply to any
    member, 409 if the rule would be over-broad.
    """
    user.require_permission("hunt:suppress")
    cluster = await _load_cluster_scoped(db, cluster_id, user)
    try:
        rule, _count = await svc.suppress_cluster(
            db,
            org_id=user.org_id,
            cluster=cluster,
            name=body.name,
            reason=body.reason,
            match=body.match,
            created_by=user.id,
            actor=user.username,
            expires_in_hours=body.expires_in_hours,
            reconfirm_in_hours=body.reconfirm_in_hours,
            acknowledge_overbroad=body.acknowledge_overbroad,
            caller_role=user.role,
        )
    except svc.OverbroadSuppressionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return _suppression_response(rule)


@router.post(
    "/clusters/{cluster_id}/promote", response_model=PromoteFindingsResponse, status_code=201
)
async def promote_cluster(
    cluster_id: str,
    body: PromoteClusterRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Escalate a cluster's eligible members into a single investigation."""
    user.require_permission("hunt:promote")
    cluster = await _load_cluster_scoped(db, cluster_id, user)
    try:
        inv, promoted = await svc.promote_cluster(
            db,
            org_id=user.org_id,
            cluster=cluster,
            title=body.title,
            assigned_to=user.id,
            actor=user.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    return PromoteFindingsResponse(investigation_id=inv.id, promoted_finding_ids=promoted)


# --------------------------------------------------------------------------- #
# Suppressions
# --------------------------------------------------------------------------- #


@router.get("/suppressions", response_model=SuppressionListResponse)
async def list_suppressions(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    user.require_permission("hunt:view")
    rows = await svc.list_suppressions(db, org_id=user.org_id)
    return SuppressionListResponse(
        items=[_suppression_response(r) for r in rows],
        total=len(rows),
    )


# --------------------------------------------------------------------------- #
# Pack-run history
# --------------------------------------------------------------------------- #


@router.get("/pack-runs", response_model=HuntPackRunListResponse)
async def list_pack_runs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Org-scoped history of scheduled / ad-hoc hunt-pack runs (#112)."""
    user.require_permission("hunt:view")
    rows, total = await hunt_pack_run_service.list_pack_runs(
        db, org_id=user.org_id, page=page, page_size=page_size
    )
    return HuntPackRunListResponse(
        items=[_pack_run_response(r) for r in rows],
        total=total,
    )


@router.get("/noise-baseline")
async def get_noise_baseline(
    lookback_runs: int = Query(50, ge=1, le=500, description="Most recent pack runs to analyse."),
    min_runs: int = Query(3, ge=1, le=100, description="Minimum observations before a verdict."),
    hit_rate_threshold: float = Query(
        0.8, ge=0.0, le=1.0, description="Fraction of runs a rule must hit in to be flagged."
    ),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Chronically-hitting pack rules — advisory suppression candidates (#112).

    Read-only analysis over the org's pack-run history (``rule_stats``);
    nothing is suppressed automatically — the analyst acts through the
    existing suppression API. RBAC: ``hunt:view``.
    """
    user.require_permission("hunt:view")
    return await noise_baseline.noise_baseline(
        db,
        org_id=user.org_id,
        lookback_runs=lookback_runs,
        min_runs=min_runs,
        hit_rate_threshold=hit_rate_threshold,
    )


@router.post("/suppressions", response_model=SuppressionRule, status_code=201)
async def create_suppression(
    body: CreateSuppressionRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Create a standalone suppression rule (not tied to a specific finding)."""
    user.require_permission("hunt:suppress")
    try:
        rule, _count = await svc.create_suppression(
            db,
            org_id=user.org_id,
            name=body.name,
            reason=body.reason,
            match=body.match,
            created_by=user.id,
            actor=user.username,
            expires_in_hours=body.expires_in_hours,
            reconfirm_in_hours=body.reconfirm_in_hours,
            acknowledge_overbroad=body.acknowledge_overbroad,
            caller_role=user.role,
        )
    except svc.OverbroadSuppressionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return _suppression_response(rule)
