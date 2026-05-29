"""Workflow execution + run-history service (Phase 2 — workflow run API).

Bridges the persisted workflow store to the engine's
:class:`~btagent_engine.runtime.executor.WorkflowExecutor`:

1. Deserialize a :class:`WorkflowVersionRow.definition` (the engine
   ``Workflow`` ``.model_dump()`` JSON) back into a ``Workflow``.
2. Execute it inline via the engine executor.
3. Persist a terminal :class:`WorkflowRunRow` capturing the outcome
   (status + per-step outputs + final output + node trail + error).

**Execution model (v1):** synchronous and middleware-free. The executor
resolves each step's Node id against :class:`NodeRegistry`; only nodes
*registered in the backend process* are runnable. Today that's the
reasoning/data tier (triage, response-plan, mitigation, hypothesis,
query, …) — all advisory/read-only. Integration nodes that would call
out to a SIEM/EDR aren't registered here, so a workflow referencing one
fails closed with ``WorkflowExecutionError(reason="not registered")``
rather than executing anything unexpected. Wiring the HITL / policy
middleware chain (so destructive integration nodes can run under
adaptive-consent gates) and async/checkpoint execution are tracked
follow-ups.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

# Importing these packages registers their Node classes on the shared
# NodeRegistry so the executor can resolve workflow step ids to Node classes.
# We deliberately register only the self-contained, advisory/transform tiers
# (triggers + reasoning + data). The ``integrations`` tier is NOT imported:
# those nodes call out to external SIEM/EDR/CTI services, so leaving them
# unregistered makes a workflow that references one fail closed
# (``reason="not registered"``) until the HITL/policy middleware chain is
# wired — rather than executing an un-gated side effect from this v1 path.
import btagent_engine.data  # noqa: F401
import btagent_engine.reasoning  # noqa: F401
import btagent_engine.triggers  # noqa: F401
from btagent_engine.compiler.workflow import Workflow
from btagent_engine.node import NodeContext
from btagent_engine.runtime import (
    WorkflowExecutionError,
    WorkflowExecutor,
    WorkflowPaused,
)
from btagent_shared.types.workflow import WorkflowRunStatus
from btagent_shared.utils.ids import generate_id
from pydantic import BaseModel, ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_workflow import WorkflowRow, WorkflowRunRow, WorkflowVersionRow

logger = logging.getLogger("btagent.services.workflow_run")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _dump(model: BaseModel | None) -> dict[str, Any] | None:
    """JSON-safe dump of a node output model (None passes through)."""
    return model.model_dump(mode="json") if model is not None else None


class WorkflowNotExecutable(ValueError):
    """The version's definition can't be turned into a runnable Workflow.

    Surfaced by the route layer as 422 (the version exists and is in the
    caller's org, but its stored definition is empty/malformed/has no
    entry node — i.e. it was never authored into a runnable graph).
    """


def _load_workflow(version: WorkflowVersionRow) -> Workflow:
    definition = version.definition or {}
    try:
        workflow = Workflow.model_validate(definition)
    except ValidationError as exc:
        raise WorkflowNotExecutable(
            f"Version {version.version_number} definition is not a valid workflow graph: {exc}"
        ) from exc
    if not workflow.nodes:
        raise WorkflowNotExecutable(
            f"Version {version.version_number} has no nodes; nothing to run."
        )
    return workflow


async def execute_version(
    db: AsyncSession,
    *,
    workflow: WorkflowRow,
    version: WorkflowVersionRow,
    trigger_payload: dict[str, Any],
    triggered_by: str | None,
) -> WorkflowRunRow:
    """Execute a workflow version inline and persist a terminal run row.

    Raises :class:`WorkflowNotExecutable` (→ 422) when the stored
    definition isn't a runnable graph. Engine execution errors are *not*
    raised — they're captured on the persisted row as ``status=failed``
    so the analyst gets a durable, queryable record of the failure.
    """
    wf = _load_workflow(version)  # may raise WorkflowNotExecutable (pre-flight)

    run_id = generate_id("wfrun")
    ctx = NodeContext(
        run_id=run_id,
        workflow_run_id=run_id,
        org_id=workflow.org_id,
        user_id=triggered_by,
        tlp_level="green",
    )

    status: WorkflowRunStatus
    outputs: dict[str, Any] = {}
    final_output: dict[str, Any] | None = None
    nodes_executed: list[str] = []
    error: str | None = None

    try:
        result = await WorkflowExecutor().execute(wf, trigger_payload, ctx)
        status = WorkflowRunStatus.SUCCEEDED
        outputs = {step_id: _dump(out) for step_id, out in result.outputs.items()}
        final_output = _dump(result.final_output)
        nodes_executed = list(result.nodes_executed)
    except WorkflowPaused as pause:
        status = WorkflowRunStatus.PAUSED
        nodes_executed = list(pause.state.nodes_executed)
        outputs = {step_id: _dump(out) for step_id, out in pause.state.outputs.items()}
        error = str(pause)
    except WorkflowExecutionError as exc:
        status = WorkflowRunStatus.FAILED
        error = f"{exc} (node={exc.node_id}, reason={exc.reason})"
    except Exception as exc:  # noqa: BLE001 - record any engine failure, don't 500
        status = WorkflowRunStatus.FAILED
        error = f"Unexpected execution error: {exc}"
        logger.exception("Workflow run %s crashed", run_id)

    run = WorkflowRunRow(
        id=run_id,
        workflow_id=workflow.id,
        version_id=version.id,
        version_number=version.version_number,
        org_id=workflow.org_id,
        triggered_by=triggered_by,
        status=status.value,
        trigger_payload=dict(trigger_payload),
        outputs=outputs,
        final_output=final_output,
        nodes_executed=nodes_executed,
        error=error,
        created_at=_utcnow(),
        completed_at=_utcnow(),
    )
    db.add(run)
    await db.flush()
    logger.info(
        "WorkflowRun %s: workflow=%s v%d status=%s steps=%d (org=%s)",
        run_id,
        workflow.id,
        version.version_number,
        status.value,
        len(nodes_executed),
        workflow.org_id,
    )
    return run


async def get_run(db: AsyncSession, *, run_id: str) -> WorkflowRunRow | None:
    result = await db.execute(select(WorkflowRunRow).where(WorkflowRunRow.id == run_id))
    return result.scalar_one_or_none()


async def list_runs(
    db: AsyncSession,
    *,
    workflow_id: str,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[WorkflowRunRow], int]:
    """List runs of a workflow, newest first."""
    offset = (page - 1) * page_size

    count_q = (
        select(func.count())
        .select_from(WorkflowRunRow)
        .where(WorkflowRunRow.workflow_id == workflow_id)
    )
    total = (await db.execute(count_q)).scalar_one() or 0

    rows_q = (
        select(WorkflowRunRow)
        .where(WorkflowRunRow.workflow_id == workflow_id)
        .order_by(WorkflowRunRow.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    rows = (await db.execute(rows_q)).scalars().all()
    return list(rows), int(total)
