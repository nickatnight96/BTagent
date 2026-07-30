"""Behavioral Hunter API — outlier triage, intent, promotion (#114 Phase A).

Thin route layer over :mod:`btagent_backend.services.behavioral_service`
(+ the IntentClassifier chain in
:mod:`btagent_backend.services.behavioral_intent_service`): Pydantic
validation, RBAC + org scoping, and translation of service ``ValueError``
into 4xx. All mutation flows through the services so the detection /
promotion invariants stay in one place.

Reuses the Phase 6 hunt RBAC permission scheme (``hunt:view`` /
``hunt:triage`` / ``hunt:promote``) — behavioral outliers are just another
hunt source feeding the same triage discipline.
"""

from __future__ import annotations

import logging

from btagent_shared.types.behavioral import (
    BehavioralOutlier,
    BehavioralOutlierListResponse,
    IntentLabel,
    OutlierExplanation,
    PromoteOutlierRequest,
    PromoteOutlierResponse,
    SetIntentRequest,
)
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models_behavioral import BehavioralOutlierRow
from btagent_backend.services import behavioral_intent_service
from btagent_backend.services import behavioral_service as svc

logger = logging.getLogger("btagent.api.behavioral")

router = APIRouter(prefix="/behavioral", tags=["behavioral"])


# --------------------------------------------------------------------------- #
# Row -> response converter
# --------------------------------------------------------------------------- #


def _outlier_response(row: BehavioralOutlierRow) -> BehavioralOutlier:
    """Row → API contract. One converter, owned by the service, so the outlier
    shape the explain view embeds is identical to the list/detail shape."""
    return svc.to_outlier_model(row)


async def _load_outlier_scoped(
    db: AsyncSession, outlier_id: str, user: CurrentUser
) -> BehavioralOutlierRow:
    """Fetch an outlier; 404 if missing or cross-tenant (IDOR-safe)."""
    row = await svc.get_outlier(db, outlier_id)
    if row is None or row.org_id != user.org_id:
        raise HTTPException(status_code=404, detail="Behavioral outlier not found")
    return row


# --------------------------------------------------------------------------- #
# Outliers
# --------------------------------------------------------------------------- #


@router.get("/outliers", response_model=BehavioralOutlierListResponse)
async def list_outliers(
    intent_label: IntentLabel | None = Query(
        None, description="Filter by LLM/analyst intent verdict (omit for all)."
    ),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Org-scoped, paginated behavioral-outlier list (optionally by intent)."""
    user.require_permission("hunt:view")
    rows, total = await svc.list_outliers(
        db,
        org_id=user.org_id,
        intent_label=intent_label,
        page=page,
        page_size=page_size,
    )
    return BehavioralOutlierListResponse(
        items=[_outlier_response(r) for r in rows],
        total=total,
    )


@router.get("/outliers/{outlier_id}", response_model=BehavioralOutlier)
async def get_outlier(
    outlier_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    user.require_permission("hunt:view")
    row = await _load_outlier_scoped(db, outlier_id, user)
    return _outlier_response(row)


@router.get("/outliers/{outlier_id}/explain", response_model=OutlierExplanation)
async def explain_outlier(
    outlier_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Why is this an outlier? — the analyst-facing explanation (#114 Phase B).

    Returns the anomalous event beside the entity's most-similar *normal*
    examples (the entity's own baseline patterns, plus peer baselines found
    through the pgvector nearest-neighbour path), the baseline window it was
    scored against, and the signals the detector already computed. Read-only
    and org-scoped through the same IDOR-safe loader as every other outlier
    read, so the explain view can never widen what an analyst may see.
    """
    user.require_permission("hunt:view")
    await _load_outlier_scoped(db, outlier_id, user)
    try:
        return await svc.explain_outlier(db, outlier_id=outlier_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/outliers/{outlier_id}/intent", response_model=BehavioralOutlier)
async def set_intent(
    outlier_id: str,
    body: SetIntentRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Record an intent verdict + rationale on an outlier (analyst triage)."""
    user.require_permission("hunt:triage")
    await _load_outlier_scoped(db, outlier_id, user)
    try:
        row = await svc.set_intent(
            db,
            outlier_id=outlier_id,
            label=body.intent_label,
            rationale=body.rationale,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return _outlier_response(row)


@router.post(
    "/outliers/{outlier_id}/promote", response_model=PromoteOutlierResponse, status_code=201
)
async def promote_outlier(
    outlier_id: str,
    body: PromoteOutlierRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Escalate an outlier into the #119 HuntFinding queue (senior action).

    Idempotent on retry: if the outlier already carries a
    ``promoted_to_finding_id`` we return that existing finding rather than
    inserting a second HuntFinding (which would also clobber the
    back-reference).
    """
    user.require_permission("hunt:promote")
    row = await _load_outlier_scoped(db, outlier_id, user)
    if row.promoted_to_finding_id is not None:
        return PromoteOutlierResponse(finding_id=row.promoted_to_finding_id)
    try:
        finding_id = await svc.promote_outlier(
            db, outlier_id=outlier_id, technique_ids=body.technique_ids
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return PromoteOutlierResponse(finding_id=finding_id)


@router.post("/outliers/{outlier_id}/feedback-benign", response_model=BehavioralOutlier)
async def feedback_benign(
    outlier_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Closed-loop tuning: fold a benign-triaged outlier back into the baseline.

    Requires the outlier already carry a ``benign`` intent label (set via the
    ``/intent`` endpoint); 400 otherwise. Returns the outlier unchanged — the
    service mutates the entity's baseline profile, not the outlier row.
    """
    user.require_permission("hunt:triage")
    row = await _load_outlier_scoped(db, outlier_id, user)
    try:
        await svc.feedback_benign(db, outlier_id=outlier_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return _outlier_response(row)


# --------------------------------------------------------------------------- #
# Intent classification (LLM chain)
# --------------------------------------------------------------------------- #


@router.post("/outliers/{outlier_id}/classify", response_model=BehavioralOutlier)
async def classify_outlier(
    outlier_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Run the IntentClassifier LLM chain on an outlier and persist its verdict.

    Returns the (re)classified outlier. If no LLM client is registered the row
    is returned unchanged with a ``None`` intent (the analyst can label it by
    hand via ``/intent``); the chain never hard-fails.
    """
    user.require_permission("hunt:triage")
    await _load_outlier_scoped(db, outlier_id, user)
    try:
        updated = await behavioral_intent_service.classify_outlier(db, outlier_id=outlier_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    if updated is None:
        # No model available / unusable response — return the current row.
        row = await _load_outlier_scoped(db, outlier_id, user)
        return _outlier_response(row)
    return _outlier_response(updated)
