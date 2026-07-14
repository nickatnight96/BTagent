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
import os
from datetime import datetime

from btagent_shared.types.pattern_hunt import ProposalOutcome, ProposalState
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models_pattern import HuntPlanRow, PatternHuntProposalRow
from btagent_backend.services import hunt_plan_service
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


class HuntPlanResponse(BaseModel):
    """Compile status + serialised HuntPlan for an accepted proposal (#120 Phase C)."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    proposal_id: str
    # "pending" | "ready" | "failed" — compile lifecycle (the plan JSON's own
    # HuntPlanState tracks execution).
    status: str
    plan: dict | None
    error: str
    created_at: datetime
    updated_at: datetime


def _mock_llm_mode() -> bool:
    """Same flag the engine reasoning nodes read (default: mock on)."""
    return os.getenv("BTAGENT_MOCK_LLM", "true").strip().lower() != "false"


def _mock_connectors_mode() -> bool:
    """Same flag the engine integration nodes read (default: mock on)."""
    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").strip().lower() == "true"


class ExecutePlanResponse(BaseModel):
    """Outcome of kicking a plan execution (#120 Phase C slice 3).

    ``queued`` is True on the live-connector path — the run happens on the
    arq worker and ``findings_created`` is None; poll the plan endpoint for
    the ``last_run`` summary. Mock mode executes inline and reports counts.
    """

    plan: HuntPlanResponse
    queued: bool
    findings_created: int | None = None


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
        row = await svc.dismiss_proposal(
            db, proposal_id=proposal_id, triage_rationale=body.rationale
        )
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
        row = await svc.snooze_proposal(
            db, proposal_id=proposal_id, triage_rationale=body.rationale
        )
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
    """Mark a proposal accepted and kick off HuntPlan compilation (#120 Phase C).

    Accept records the analyst's intent immediately and creates a ``pending``
    hunt-plan row (idempotent — re-accepting reuses the existing row). The
    compile itself runs inline under mock LLM (deterministic, sub-second) and
    is enqueued to the arq worker on the live-LLM path so the multi-round-trip
    compile never rides this synchronous request. A compile failure lands on
    the plan row (``failed`` + error) — the accept itself still succeeds; poll
    ``GET /pattern/proposals/{id}/plan`` for the outcome.
    """
    user.require_permission("hunt:triage")
    await _load_proposal_scoped(db, proposal_id, user)
    try:
        row = await svc.set_proposal_state(
            db, proposal_id=proposal_id, state=ProposalState.ACCEPTED
        )
        plan_row = await hunt_plan_service.create_pending_plan(
            db, org_id=user.org_id, proposal_id=proposal_id
        )
        if plan_row.status == hunt_plan_service.STATUS_PENDING:
            if _mock_llm_mode():
                await hunt_plan_service.compile_and_store(db, plan_row_id=plan_row.id)
            else:
                await _enqueue_compile(plan_row)
        await db.commit()
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _proposal_response(row)


async def _enqueue_compile(plan_row: HuntPlanRow) -> None:
    """Enqueue the live-LLM compile job; mark the row failed if arq is down.

    Marking ``failed`` (rather than raising) keeps accept usable when the
    worker infra is unreachable — the analyst sees a failed compile with the
    reason instead of a 500 that also rolls back their accept.
    """
    try:
        from arq import create_pool

        from btagent_backend.scheduler.worker import redis_settings

        pool = await create_pool(redis_settings())
        try:
            await pool.enqueue_job("compile_proposal_plan", plan_row.id)
        finally:
            await pool.aclose()
    except Exception as exc:  # noqa: BLE001 — infra failure lands on the row
        logger.exception("Failed to enqueue HuntPlan compile for %s", plan_row.id)
        plan_row.status = hunt_plan_service.STATUS_FAILED
        plan_row.error = f"enqueue failed: {type(exc).__name__}: {exc}"


@router.post("/proposals/{proposal_id}/plan/execute", response_model=ExecutePlanResponse)
async def execute_proposal_plan(
    proposal_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> ExecutePlanResponse:
    """Execute the compiled HuntPlan for an accepted proposal (#120 Phase C).

    Runs the plan's per-TTP runbook queries through the engine integration
    nodes and lands every hit in the #119 triage inbox (clustering +
    suppressions apply). Inline under mock connectors; enqueued to the arq
    worker on the live path. 404 when no plan exists; 409 when the plan is
    not ``ready`` (still compiling, or its compile failed).
    """
    user.require_permission("hunt:run")
    await _load_proposal_scoped(db, proposal_id, user)
    plan_row = await hunt_plan_service.get_plan_for_proposal(
        db, org_id=user.org_id, proposal_id=proposal_id
    )
    if plan_row is None:
        raise HTTPException(status_code=404, detail="Proposal has no hunt plan yet")
    if plan_row.status != hunt_plan_service.STATUS_READY:
        raise HTTPException(
            status_code=409,
            detail=f"Hunt plan is not ready to execute (status={plan_row.status})",
        )

    if _mock_connectors_mode():
        plan_row, findings_created = await hunt_plan_service.execute_plan_and_ingest(
            db, plan_row_id=plan_row.id
        )
        await db.commit()
        return ExecutePlanResponse(
            plan=HuntPlanResponse.model_validate(plan_row),
            queued=False,
            findings_created=findings_created,
        )

    try:
        from arq import create_pool

        from btagent_backend.scheduler.worker import redis_settings

        pool = await create_pool(redis_settings())
        try:
            await pool.enqueue_job("execute_hunt_plan", plan_row.id)
        finally:
            await pool.aclose()
    except Exception as exc:  # noqa: BLE001 — infra failure surfaces as 503
        logger.exception("Failed to enqueue HuntPlan execution for %s", plan_row.id)
        raise HTTPException(
            status_code=503,
            detail=f"Could not queue plan execution: {type(exc).__name__}",
        ) from exc
    return ExecutePlanResponse(
        plan=HuntPlanResponse.model_validate(plan_row), queued=True, findings_created=None
    )


@router.get("/proposals/{proposal_id}/plan", response_model=HuntPlanResponse)
async def get_proposal_plan(
    proposal_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> HuntPlanResponse:
    """Read the compiled HuntPlan (or its compile status) for a proposal.

    404 until the proposal has been accepted (no plan row exists before that).
    """
    user.require_permission("hunt:view")
    await _load_proposal_scoped(db, proposal_id, user)
    plan_row = await hunt_plan_service.get_plan_for_proposal(
        db, org_id=user.org_id, proposal_id=proposal_id
    )
    if plan_row is None:
        raise HTTPException(status_code=404, detail="Proposal has no hunt plan yet")
    return HuntPlanResponse.model_validate(plan_row)
