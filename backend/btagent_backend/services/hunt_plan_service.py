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
* ``execute_plan_and_ingest`` — runs a ``ready`` plan's runbook, ingests hits,
  and records a :class:`PlanRunRow` history row per invocation (mirroring
  ``hunt_pack_runs``). The ``last_run`` blob alongside the plan JSON is kept
  as the quick-glance summary for backward compatibility.
* ``list_plan_runs`` — org-scoped, newest-first run history for the API.

Per the codebase convention these helpers never commit — the route / arq job
owns the single commit.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from btagent_shared.types.pattern_hunt import PatternHuntProposal
from btagent_shared.utils.ids import generate_id
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_pattern import HuntPlanRow, PatternHuntProposalRow, PlanRunRow

if TYPE_CHECKING:  # avoid importing the (pysigma-heavy) engine at module load
    from btagent_engine.hunting.plan_runner import PlanRunResult

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
            "triage_rationale": row.triage_rationale or "",
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


def _derive_plan_run_status(result: PlanRunResult) -> str:
    """Same derivation as ``hunt_pack_run_service._derive_run_status``.

    Counts every TTP×backend execution outcome: ``failed`` when every
    execution errored (and there was at least one), ``completed_with_errors``
    for a partial result, ``completed`` otherwise (including an empty runbook
    — nothing ran, nothing failed).
    """
    errored = 0
    succeeded = 0
    for ttp in result.ttp_results:
        for backend in ttp.backend_results:
            if backend.error:
                errored += 1
            else:
                succeeded += 1
    if errored == 0:
        return "completed"
    if succeeded == 0:
        return "failed"
    return "completed_with_errors"


async def list_plan_runs(
    db: AsyncSession,
    *,
    org_id: str,
    plan_row_id: str | None = None,
    proposal_id: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[PlanRunRow], int]:
    """Org-scoped plan-run history, newest-first, paginated."""
    where = [PlanRunRow.org_id == org_id]
    if plan_row_id:
        where.append(PlanRunRow.plan_row_id == plan_row_id)
    if proposal_id:
        where.append(PlanRunRow.proposal_id == proposal_id)

    total = (
        await db.execute(select(func.count()).select_from(PlanRunRow).where(*where))
    ).scalar_one() or 0
    rows = (
        (
            await db.execute(
                select(PlanRunRow)
                .where(*where)
                .order_by(PlanRunRow.started_at.desc(), PlanRunRow.id.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), int(total)


async def execute_plan_and_ingest(
    db: AsyncSession,
    *,
    plan_row_id: str,
    lookback_hours: int = 24,
    max_hits_per_query: int = 100,
) -> tuple[HuntPlanRow, int]:
    """Execute a ``ready`` plan's runbook and land hits in the triage inbox.

    Runs the engine plan runner over the compiled per-TTP queries, converts
    every hit into a ``HuntFinding`` (source/domain ``cross_investigation``,
    technique = the hit's TTP) via :func:`hunt_triage_service.record_finding`
    — so cluster-on-insert and active suppressions apply exactly as they do
    for every other hunt source. Afterwards:

    * the stored plan JSON flips to ``completed`` and gains a ``last_run``
      summary (run id, findings created, per-TTP hit/error counts);
    * a :class:`PlanRunRow` history row is recorded — one per invocation, so
      repeated executions accumulate instead of overwriting (``last_run`` is
      kept as the backward-compatible quick-glance summary);
    * the proposal's closed-loop ``outcome`` is written back — ``hit`` when
      any finding landed, ``clean`` otherwise (#120 Phase B feedback column).

    Raises :class:`ValueError` when the row is missing or not ``ready``
    (routes surface 404/409). Never commits — route / arq job owns that.
    """
    from btagent_shared.types.hunt import HuntDomain, HuntPlan, HuntPlanState, HuntSource
    from btagent_shared.types.pattern_hunt import ProposalOutcome

    row = (
        await db.execute(select(HuntPlanRow).where(HuntPlanRow.id == plan_row_id))
    ).scalar_one_or_none()
    if row is None:
        raise ValueError(f"Hunt plan row not found: {plan_row_id}")
    if row.status != STATUS_READY or not row.plan:
        raise ValueError(f"Hunt plan {plan_row_id} is not ready to execute (status={row.status})")

    # ``last_run`` rides alongside the plan fields in the stored JSON (the
    # model is extra=forbid) — pop it so a re-execute rehydrates cleanly.
    plan_data = dict(row.plan)
    plan_data.pop("last_run", None)
    plan = HuntPlan.model_validate(plan_data)

    # Lazy engine import — pulls the integration-node stack.
    from btagent_engine.hunting.plan_runner import run_plan
    from btagent_engine.node import NodeContext

    ctx = NodeContext(run_id=generate_id("hrun"), org_id=row.org_id)
    result = await run_plan(
        plan, ctx, lookback_hours=lookback_hours, max_hits_per_query=max_hits_per_query
    )

    from btagent_backend.services import hunt_triage_service

    findings_created = 0
    for hit in result.all_hits:
        await hunt_triage_service.record_finding(
            db,
            org_id=row.org_id,
            source=HuntSource.CROSS_INVESTIGATION.value,
            domain=HuntDomain.CROSS_INVESTIGATION.value,
            title=f"Pattern hunt hit: {hit.ttp_name or hit.ttp_id} ({hit.backend})",
            description=hit.summary,
            technique_ids=[hit.ttp_id],
            entities=[{"kind": e.kind, "value": e.value} for e in hit.entities],
            observables=(
                [{"type": hit.observable_type, "value": hit.observable}]
                if hit.observable and hit.observable_type
                else []
            ),
            evidence={
                "plan_id": plan.id,
                "plan_run_id": result.run_id,
                "proposal_id": row.proposal_id,
                "backend": hit.backend,
                "raw": hit.raw,
            },
        )
        findings_created += 1

    # Fold a per-TTP execution summary back into the stored plan JSON and
    # flip its execution lifecycle to COMPLETED.
    now = _utcnow()
    ttp_summary = {
        t.ttp_id: {
            "hits": len(t.hits),
            "errors": [br.error for br in t.backend_results if br.error],
        }
        for t in result.ttp_results
    }
    plan.state = HuntPlanState.COMPLETED
    plan.updated_at = now
    plan_json = plan.model_dump(mode="json")
    plan_json["last_run"] = {
        "run_id": result.run_id,
        "started_at": result.started_at.isoformat(),
        "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        "findings_created": findings_created,
        "error_count": result.error_count,
        "per_ttp": ttp_summary,
    }
    # ``HuntPlan`` is extra=forbid, so the run summary rides *alongside* the
    # plan fields in the stored JSON, not inside the model. Rehydration pops
    # it (see the top of this function).
    row.plan = plan_json
    row.updated_at = now

    # Per-run history row — one per invocation (mirrors hunt_pack_runs).
    db.add(
        PlanRunRow(
            id=generate_id("plrun"),
            org_id=row.org_id,
            plan_row_id=row.id,
            proposal_id=row.proposal_id,
            plan_id=plan.id,
            run_id=result.run_id,
            ttp_stats=ttp_summary,
            hit_count=len(result.all_hits),
            error_count=result.error_count,
            findings_created=findings_created,
            status=_derive_plan_run_status(result),
            error=None,
            started_at=result.started_at,
            completed_at=result.completed_at,
        )
    )

    # Closed-loop outcome write-back onto the proposal (#120 Phase B column).
    proposal_row = (
        await db.execute(
            select(PatternHuntProposalRow).where(PatternHuntProposalRow.id == row.proposal_id)
        )
    ).scalar_one_or_none()
    if proposal_row is not None:
        proposal_row.outcome = (
            ProposalOutcome.HIT.value if findings_created else ProposalOutcome.CLEAN.value
        )
        proposal_row.updated_at = now

    await db.flush()
    logger.info(
        "HuntPlan executed: plan=%s run=%s findings=%d errors=%d",
        plan.id,
        result.run_id,
        findings_created,
        result.error_count,
    )
    return row, findings_created
