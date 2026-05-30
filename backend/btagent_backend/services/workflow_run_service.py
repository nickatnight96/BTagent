"""Workflow execution + run-history service (Phase 2 — workflow run API).

Bridges the persisted workflow store to the engine's
:class:`~btagent_engine.runtime.executor.WorkflowExecutor`:

1. Deserialize a :class:`WorkflowVersionRow.definition` (the engine
   ``Workflow`` ``.model_dump()`` JSON) back into a ``Workflow``.
2. Execute it through a security-middleware chain
   (HITL + ConnectorPolicy + EvidenceChain).
3. Persist a terminal :class:`WorkflowRunRow` capturing the outcome
   (status + per-step outputs + final output + node trail + error).

**Execution model (v1):** synchronous. The executor walks the graph and
each step runs through the chain:

* :class:`HITLMiddleware` pauses integration nodes the agent's autonomy
  policy says require approval (``status=paused``).
* :class:`ConnectorPolicyMiddleware` enforces per-capability manifest
  policy: ``hitl_required=True`` pauses; a TLP egress violation
  (capability max < active context) refuses (``status=failed`` with the
  violation message recorded on the run row).
* :class:`EvidenceChainMiddleware` builds a hash-linked audit trail of
  every successful node run (persisted on the run row for replay).

Async / checkpoint resume of paused runs is a tracked follow-up.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

# Importing these packages registers their Node classes on the shared
# NodeRegistry so the executor can resolve workflow step ids to Node classes.
# The advisory/transform tiers (triggers + reasoning + data) are imported
# unconditionally. The ``integrations`` tier (SIEM/EDR/CTI call-outs) is
# imported too, because the middleware chain wired below (HITL +
# ConnectorPolicy + Classification) gates every integration call: a
# manifest with ``hitl_required=True`` pauses the run, a TLP violation
# refuses it, and an autonomy-policy mismatch pauses it. Without the
# chain those nodes would execute un-gated, so middleware-wiring and
# integration registration must land together.
import btagent_engine.data  # noqa: F401
import btagent_engine.integrations  # noqa: F401
import btagent_engine.reasoning  # noqa: F401
import btagent_engine.triggers  # noqa: F401
from btagent_engine.compiler.workflow import Workflow
from btagent_engine.middleware import (
    ConnectorPolicyMiddleware,
    ConnectorPolicyViolation,
    EvidenceChainMiddleware,
    EvidenceRecord,
    HITLMiddleware,
    Middleware,
)
from btagent_engine.node import NodeContext
from btagent_engine.runtime import (
    WorkflowExecutionError,
    WorkflowExecutor,
    WorkflowPaused,
)
from btagent_shared.types.config import TLP, AutonomyLevel, IntegrationAutonomy
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


def _build_middleware_chain(
    *,
    active_tlp: TLP,
    agent_autonomy: AutonomyLevel,
    integration_autonomy: IntegrationAutonomy,
    evidence_records: list[EvidenceRecord],
) -> list[Middleware]:
    """Assemble the security/observability chain for one workflow run.

    Backend-native (no agents-tier deps). Order matches the canonical
    chain in ``agents/btagent_agents/orchestrator/engine_runner.py``,
    skipping layers that depend on agents-only primitives (scope,
    LLM router, prompt budget, event emitter). The three wired here are
    the ones the audit identified as security-critical for the executor:

    * :class:`HITLMiddleware` — autonomy-policy pauses on integration nodes.
    * :class:`ConnectorPolicyMiddleware` — per-capability manifest policy
      (HITL, TLP, cost class).
    * :class:`EvidenceChainMiddleware` — hash-linked audit trail.

    Note: :class:`ClassificationMiddleware` is deliberately NOT in this
    chain. It gates *every* node's I/O on the configured egress channel
    (default ``event_emit``), so installing it here would refuse runs at
    any classified TLP regardless of whether the workflow actually emits
    to that channel. That middleware belongs at the WebSocket-broadcast
    layer where event_emit actually happens; ConnectorPolicy is what
    enforces TLP at the per-capability boundary that matters for runs.
    """
    chain: list[Middleware] = []
    chain.append(
        HITLMiddleware(
            agent_autonomy=agent_autonomy,
            integration_autonomy=integration_autonomy,
        )
    )
    chain.append(ConnectorPolicyMiddleware(active_tlp=active_tlp))
    chain.append(EvidenceChainMiddleware(records=evidence_records))
    return chain


async def execute_version(
    db: AsyncSession,
    *,
    workflow: WorkflowRow,
    version: WorkflowVersionRow,
    trigger_payload: dict[str, Any],
    triggered_by: str | None,
    active_tlp: TLP,
    agent_autonomy: AutonomyLevel = AutonomyLevel.L2_SUPERVISED,
    integration_autonomy: IntegrationAutonomy | None = None,
) -> WorkflowRunRow:
    """Execute a workflow version inline and persist a terminal run row.

    Raises :class:`WorkflowNotExecutable` (→ 422) when the stored
    definition isn't a runnable graph. Engine execution errors are *not*
    raised — they're captured on the persisted row as ``status=failed``
    so the analyst gets a durable, queryable record of the failure.

    ``active_tlp`` is **required** and carries the run's classification
    context into the middleware chain. A default would silently weaken
    the TLP egress check: a workflow on a TLP:AMBER_STRICT investigation
    that calls an AMBER-only cloud lookup must be refused, not run under
    an inferred GREEN. Callers must pass the classification of the
    triggering context (the API route defaults to TLP:RED — fail-closed
    — when the request body doesn't specify it).
    ``agent_autonomy`` / ``integration_autonomy`` default to the
    standard supervised analyst posture (L2 agent + the
    :class:`IntegrationAutonomy` defaults).
    """
    wf = _load_workflow(version)  # may raise WorkflowNotExecutable (pre-flight)

    run_id = generate_id("wfrun")
    ctx = NodeContext(
        run_id=run_id,
        workflow_run_id=run_id,
        org_id=workflow.org_id,
        user_id=triggered_by,
        tlp_level=active_tlp.value,
    )

    evidence_records: list[EvidenceRecord] = []
    middlewares = _build_middleware_chain(
        active_tlp=active_tlp,
        agent_autonomy=agent_autonomy,
        integration_autonomy=integration_autonomy or IntegrationAutonomy(),
        evidence_records=evidence_records,
    )

    status: WorkflowRunStatus
    outputs: dict[str, Any] = {}
    final_output: dict[str, Any] | None = None
    nodes_executed: list[str] = []
    error: str | None = None

    try:
        result = await WorkflowExecutor(middlewares=middlewares).execute(wf, trigger_payload, ctx)
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
        # ConnectorPolicyViolation surfaces as the `cause` here (the
        # executor wraps any non-pause middleware error as
        # WorkflowExecutionError). Show the original message — that's the
        # policy detail the approver actually needs.
        if isinstance(exc.cause, ConnectorPolicyViolation):
            error = f"Connector policy violation at node {exc.node_id!r}: {exc.cause}"
        else:
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
        evidence_chain=[r.model_dump(mode="json") for r in evidence_records],
        error=error,
        created_at=_utcnow(),
        completed_at=_utcnow(),
    )
    db.add(run)
    await db.flush()
    logger.info(
        "WorkflowRun %s: workflow=%s v%d status=%s steps=%d evidence=%d (org=%s)",
        run_id,
        workflow.id,
        version.version_number,
        status.value,
        len(nodes_executed),
        len(evidence_records),
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
