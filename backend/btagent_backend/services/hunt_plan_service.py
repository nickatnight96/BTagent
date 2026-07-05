"""Persistence + compile orchestration for HuntPlans (#120 Phase C slice 2).

The pure-logic compiler lives in :mod:`btagent_backend.services.proposal_huntplan`
and stays side-effect-free; this module is the side-effectful shell around it:

* ``create_pending_plan`` — called on proposal accept; records the intent to
  compile as a ``pending`` :class:`HuntPlanRow`. Idempotent per proposal
  (unique index): a second accept returns the existing row instead of
  duplicating work.
* ``compile_and_store`` — runs the compiler and lands the result on the row
  (``ready`` + plan JSON, or ``failed`` + error). Called inline by the accept
  route under mock LLM (deterministic, sub-second) and by the
  ``compile_proposal_plan`` arq job on the live-LLM path, where the multiple
  LLM round-trips must not ride the synchronous HTTP accept.
* ``get_plan_for_proposal`` — org-scoped read for the API.

Per the codebase convention these helpers never commit — the route / arq job
owns the single commit.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from btagent_shared.types.pattern_hunt import PatternHuntProposal
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_pattern import HuntPlanRow, PatternHuntProposalRow

logger = logging.getLogger("btagent.services.hunt_plan")

# Row-level compile lifecycle values (deliberately not HuntPlanState — that
# enum tracks plan *execution*; this tracks plan *compilation*).
STATUS_PENDING = "pending"
STATUS_READY = "ready"
STATUS_FAILED = "failed"


def _utcnow() -> datetime:
    return datetime.now(UTC)


def row_to_proposal(row: PatternHuntProposalRow) -> PatternHuntProposal:
    """Rehydrate the shared PatternHuntProposal model from its ORM row."""
    return PatternHuntProposal.model_validate(
        {
            "id": row.id,
            "org_id": row.org_id,
            "cluster_id": row.cluster_id,
            "hunt_input": row.hunt_input or {},
            "rationale": row.rationale or "",
            "state": row.state,
            "outcome": row.outcome,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }
    )


async def create_pending_plan(
    db: AsyncSession,
    *,
    org_id: str,
    proposal_id: str,
) -> HuntPlanRow:
    """Record a pending compile for an accepted proposal (idempotent).

    Returns the existing row when one is already present for the proposal —
    re-accepting must not spawn a second plan (unique ``proposal_id`` index
    backs this at the DB layer too).
    """
    existing = await get_plan_for_proposal(db, org_id=org_id, proposal_id=proposal_id)
    if existing is not None:
        return existing

    now = _utcnow()
    row = HuntPlanRow(
        id=generate_id("hplan"),
        org_id=org_id,
        proposal_id=proposal_id,
        status=STATUS_PENDING,
        plan=None,
        error="",
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    await db.flush()
    return row


async def compile_and_store(db: AsyncSession, *, plan_row_id: str) -> HuntPlanRow:
    """Compile the row's proposal into a HuntPlan and land the result.

    Success → ``ready`` + serialised plan; any compiler exception → ``failed``
    + error string (the proposal stays accepted; the row is the visible
    record of what went wrong). Raises :class:`ValueError` only when the row
    or its proposal cannot be resolved at all.
    """
    row = (
        await db.execute(select(HuntPlanRow).where(HuntPlanRow.id == plan_row_id))
    ).scalar_one_or_none()
    if row is None:
        raise ValueError(f"Hunt plan row not found: {plan_row_id}")

    proposal_row = (
        await db.execute(
            select(PatternHuntProposalRow).where(PatternHuntProposalRow.id == row.proposal_id)
        )
    ).scalar_one_or_none()
    if proposal_row is None:
        raise ValueError(f"Proposal not found for hunt plan {plan_row_id}: {row.proposal_id}")

    # Lazy import — the compiler pulls the engine (pysigma / LLM stack) onto
    # the import path; keep that off consumers that never compile.
    from btagent_backend.services.proposal_huntplan import compile_proposal_to_huntplan

    try:
        plan = await compile_proposal_to_huntplan(row_to_proposal(proposal_row))
    except Exception as exc:  # noqa: BLE001 — any compile failure lands on the row
        logger.exception("HuntPlan compile failed for proposal %s", row.proposal_id)
        row.status = STATUS_FAILED
        row.error = f"{type(exc).__name__}: {exc}"
        row.updated_at = _utcnow()
        await db.flush()
        return row

    row.status = STATUS_READY
    row.plan = plan.model_dump(mode="json")
    row.error = ""
    row.updated_at = _utcnow()
    await db.flush()
    logger.info(
        "HuntPlan compiled for proposal %s: %s (%d hypotheses)",
        row.proposal_id,
        plan.id,
        len(plan.hypotheses),
    )
    return row


async def get_plan_for_proposal(
    db: AsyncSession,
    *,
    org_id: str,
    proposal_id: str,
) -> HuntPlanRow | None:
    """Org-scoped lookup of the plan row for a proposal."""
    result = await db.execute(
        select(HuntPlanRow).where(
            HuntPlanRow.proposal_id == proposal_id,
            HuntPlanRow.org_id == org_id,
        )
    )
    return result.scalar_one_or_none()
