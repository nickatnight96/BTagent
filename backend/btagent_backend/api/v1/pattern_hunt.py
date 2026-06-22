"""Pattern Hunt API — proposal list + dismiss / snooze / accept lifecycle (#120 Phase B).

Thin route layer over :mod:`btagent_backend.services.pattern_hunt_service`:
Pydantic validation, RBAC + org scoping, and translation of service
``ValueError`` into 4xx. All mutation flows through the service so the
down-weighting invariants stay in one place.

Reuses the Phase 6 hunt RBAC permission scheme:
- ``hunt:view``    — list proposals (analyst+)
- ``hunt:triage``  — dismiss / snooze / accept (analyst+, matches the rest of the
                     hunt namespace; see backend/btagent_backend/auth/rbac.py)

Note: Phase A explicitly deferred the API; Phase B adds it here as a
prerequisite for the Pattern Insights UI slice.
"""

from __future__ import annotations

import logging
from datetime import datetime

from btagent_shared.types.pattern_hunt import ProposalOutcome, ProposalState
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models_pattern import PatternHuntProposalRow
from btagent_backend.services import pattern_hunt_service as svc

logger = logging.getLogger("btagent.api.pattern_hunt")

router = APIRouter(prefix="/pattern", tags=["pattern-hunt"])


# --------------------------------------------------------------------------- #
# Response shapes
# --------------------------------------------------------------------------- #


class WeakSignalResponse(BaseModel):
    """Serialisable weak-signal member (enough for the UI card)."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: str
    value: str
    ioc_type: str | None
    first_seen: datetime
    last_seen: datetime
    investigation_refs: list[str]
    distinct_investigation_count: int


class PatternHuntProposalResponse(BaseModel):
    """API response shape for a single pattern-hunt proposal."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    cluster_id: str
    score: float
    hunt_input: dict
    rationale: str
    state: str
    outcome: str | None
    created_at: datetime
    updated_at: datetime


class PatternHuntProposalListResponse(BaseModel):
    items: list[PatternHuntProposalResponse]
    total: int


class ActionRequest(BaseModel):
    """Optional rationale for dismiss / snooze / accept transitions."""

    rationale: str = ""


# --------------------------------------------------------------------------- #
# Row → response converter
# --------------------------------------------------------------------------- #


def _proposal_response(row: PatternHuntProposalRow) -> PatternHuntProposalResponse:
    return PatternHuntProposalResponse(
        id=row.id,
        org_id=row.org_id,
        cluster_id=row.cluster_id,
        score=row.score,
        hunt_input=row.hunt_input or {},
        rationale=row.rationale or "",
        state=row.state,
        outcome=row.outcome,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def _load_proposal_scoped(
    db: AsyncSession,
    proposal_id: str,
    user: CurrentUser,
) -> PatternHuntProposalRow:
    """Fetch a proposal; 404 if missing or cross-tenant (IDOR-safe)."""
    row = await db.get(PatternHuntProposalRow, proposal_id)
    if row is None or row.org_id != user.org_id:
        raise HTTPException(status_code=404, detail="Pattern-hunt proposal not found")
    return row


# --------------------------------------------------------------------------- #
# Proposals — read
# --------------------------------------------------------------------------- #


@router.get("/proposals", response_model=PatternHuntProposalListResponse)
async def list_proposals(
    state: str | None = Query(
        None,
        description=(
            "Filter by proposal state: proposed | accepted | dismissed | snoozed. "
            "Omit for all states."
        ),
    ),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> PatternHuntProposalListResponse:
    """Org-scoped, paginated proposal list ordered by score desc."""
    user.require_permission("hunt:view")

    stmt = select(PatternHuntProposalRow).where(PatternHuntProposalRow.org_id == user.org_id)
    if state:
        stmt = stmt.where(PatternHuntProposalRow.state == state)
    # Order by score descending so the highest-ranking proposals surface first.
    stmt = stmt.order_by(PatternHuntProposalRow.score.desc())

    # Total count (re-uses the same filtered query).
    count_result = await db.execute(stmt)
    all_rows = list(count_result.scalars().all())
    total = len(all_rows)

    offset = (page - 1) * page_size
    page_rows = all_rows[offset : offset + page_size]

    return PatternHuntProposalListResponse(
        items=[_proposal_response(r) for r in page_rows],
        total=total,
    )


# --------------------------------------------------------------------------- #
# Proposals — lifecycle mutations
# --------------------------------------------------------------------------- #


@router.post("/proposals/{proposal_id}/dismiss", response_model=PatternHuntProposalResponse)
async def dismiss_proposal(
    proposal_id: str,
    body: ActionRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> PatternHuntProposalResponse:
    """Dismiss a proposal — down-weights similar future surfacing."""
    user.require_permission("hunt:triage")
    await _load_proposal_scoped(db, proposal_id, user)
    try:
        row = await svc.dismiss_proposal(db, proposal_id=proposal_id)
        await db.commit()
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _proposal_response(row)


@router.post("/proposals/{proposal_id}/snooze", response_model=PatternHuntProposalResponse)
async def snooze_proposal(
    proposal_id: str,
    body: ActionRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> PatternHuntProposalResponse:
    """Snooze a proposal — reversibly down-weights similar future surfacing."""
    user.require_permission("hunt:triage")
    await _load_proposal_scoped(db, proposal_id, user)
    try:
        row = await svc.snooze_proposal(db, proposal_id=proposal_id)
        await db.commit()
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _proposal_response(row)


@router.post("/proposals/{proposal_id}/accept", response_model=PatternHuntProposalResponse)
async def accept_proposal(
    proposal_id: str,
    body: ActionRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> PatternHuntProposalResponse:
    """Mark a proposal accepted — signals the analyst wants to run this hunt.

    HuntPlan emission is deferred to Phase C; this endpoint marks the proposal
    ``accepted`` so the UI can reflect the analyst's intent immediately.
    """
    user.require_permission("hunt:triage")
    await _load_proposal_scoped(db, proposal_id, user)
    try:
        row = await svc.set_proposal_state(
            db, proposal_id=proposal_id, state=ProposalState.ACCEPTED
        )
        await db.commit()
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _proposal_response(row)
