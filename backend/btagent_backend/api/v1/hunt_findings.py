"""Hunt triage API — clustered findings inbox, suppression, promotion (#119).

Thin route layer: Pydantic validation, RBAC + org scoping, and translation
of service ``ValueError`` into 4xx. All mutation flows through
:mod:`btagent_backend.services.hunt_triage_service` so the cluster-on-insert
and over-broad-suppression invariants stay in one place.
"""

from __future__ import annotations

import logging

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
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models_hunt import (
    HuntFindingClusterRow,
    HuntFindingRow,
    HuntPackRunRow,
    SuppressionRuleRow,
)
from btagent_backend.services import hunt_pack_run_service
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


@router.get("/findings", response_model=HuntFindingClusterListResponse)
async def list_findings(
    include_suppressed: bool = Query(False),
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
        )
    except svc.OverbroadSuppressionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return _suppression_response(rule)
