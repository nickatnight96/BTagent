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
from dataclasses import dataclass, field
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
    WorkflowState,
)
from btagent_shared.types.config import TLP, AutonomyLevel, IntegrationAutonomy
from btagent_shared.types.workflow import WorkflowRunStatus
from btagent_shared.utils.ids import generate_id
from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_workflow import WorkflowRow, WorkflowRunRow, WorkflowVersionRow

logger = logging.getLogger("btagent.services.workflow_run")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _dump(model: BaseModel | None) -> dict[str, Any] | None:
    """JSON-safe dump of a node output model (None passes through)."""
    return model.model_dump(mode="json") if model is not None else None


class _RehydratedOutput(BaseModel):
    """Permissive wrapper to rebuild a node output from persisted JSON.

    A resume needs the prior node outputs, but the original output classes
    aren't known here (every Node has its own schema). ``extra="allow"``
    lets an arbitrary dict round-trip through ``model_validate`` →
    ``model_dump`` and exposes its keys as attributes, which is all the
    executor's reuse path needs (``model_dump()`` for input-building,
    ``.branch`` for decision routing).
    """

    model_config = ConfigDict(extra="allow")


def _rehydrate_state(run: WorkflowRunRow) -> WorkflowState:
    """Rebuild a checkpoint :class:`WorkflowState` from a persisted run row."""
    outputs = {
        step_id: _RehydratedOutput.model_validate(payload or {})
        for step_id, payload in (run.outputs or {}).items()
    }
    return WorkflowState(
        outputs=outputs,
        nodes_executed=list(run.nodes_executed or []),
        metadata={"trigger_payload": dict(run.trigger_payload or {})},
    )


@dataclass
class _Outcome:
    """Terminal capture of one executor run, ready to persist on a run row."""

    status: WorkflowRunStatus
    outputs: dict[str, Any] = field(default_factory=dict)
    final_output: dict[str, Any] | None = None
    nodes_executed: list[str] = field(default_factory=list)
    evidence_chain: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    paused_node_id: str | None = None


async def _run_capture(
    *,
    workflow: Workflow,
    trigger_payload: dict[str, Any],
    ctx: NodeContext,
    active_tlp: TLP,
    agent_autonomy: AutonomyLevel,
    integration_autonomy: IntegrationAutonomy,
    resume_state: WorkflowState | None = None,
    approved_steps: set[str] | None = None,
    prior_evidence: list[EvidenceRecord] | None = None,
) -> _Outcome:
    """Run the executor once and capture a persist-ready :class:`_Outcome`.

    Never raises on an engine failure -- a paused or failed run is a
    recorded outcome, not an exception, so create + resume both get a
    durable row.

    ``prior_evidence`` is the audit chain accumulated before this attempt
    (only populated by a resume). Seeding it into the evidence-chain
    middleware means new records link to the prior tail's ``link_hash``
    instead of restarting at ``GENESIS``, preserving the tamper-evident
    chain across resume cycles. The middleware appends in place, so the
    outcome carries the full (prior + new) chain back out.
    """
    evidence_records: list[EvidenceRecord] = list(prior_evidence or [])
    middlewares = _build_middleware_chain(
        active_tlp=active_tlp,
        agent_autonomy=agent_autonomy,
        integration_autonomy=integration_autonomy,
        evidence_records=evidence_records,
    )
    try:
        result = await WorkflowExecutor(middlewares=middlewares).execute(
            workflow,
            trigger_payload,
            ctx,
            resume_state=resume_state,
            approved_steps=approved_steps,
        )
        outcome = _Outcome(
            status=WorkflowRunStatus.SUCCEEDED,
            outputs={sid: _dump(out) for sid, out in result.outputs.items()},
            final_output=_dump(result.final_output),
            nodes_executed=list(result.nodes_executed),
        )
    except WorkflowPaused as pause:
        outcome = _Outcome(
            status=WorkflowRunStatus.PAUSED,
            outputs={sid: _dump(out) for sid, out in pause.state.outputs.items()},
            nodes_executed=list(pause.state.nodes_executed),
            error=str(pause),
            paused_node_id=pause.node_id,
        )
    except WorkflowExecutionError as exc:
        if isinstance(exc.cause, ConnectorPolicyViolation):
            err = f"Connector policy violation at node {exc.node_id!r}: {exc.cause}"
        else:
            err = f"{exc} (node={exc.node_id}, reason={exc.reason})"
        outcome = _Outcome(status=WorkflowRunStatus.FAILED, error=err)
    except Exception as exc:  # noqa: BLE001 - record any engine failure, don't 500
        outcome = _Outcome(
            status=WorkflowRunStatus.FAILED, error=f"Unexpected execution error: {exc}"
        )
        logger.exception("Workflow run %s crashed", ctx.run_id)

    outcome.evidence_chain = [r.model_dump(mode="json") for r in evidence_records]
    return outcome


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
    investigation_id: str | None = None,
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
        investigation_id=investigation_id,
        org_id=workflow.org_id,
        user_id=triggered_by,
        tlp_level=active_tlp.value,
    )

    outcome = await _run_capture(
        workflow=wf,
        trigger_payload=trigger_payload,
        ctx=ctx,
        active_tlp=active_tlp,
        agent_autonomy=agent_autonomy,
        integration_autonomy=integration_autonomy or IntegrationAutonomy(),
    )

    run = WorkflowRunRow(
        id=run_id,
        workflow_id=workflow.id,
        version_id=version.id,
        version_number=version.version_number,
        org_id=workflow.org_id,
        triggered_by=triggered_by,
        investigation_id=investigation_id,
        status=outcome.status.value,
        # Persisted so a resume can faithfully rebuild the run's posture +
        # checkpoint without re-deriving them.
        active_tlp=active_tlp.value,
        agent_autonomy=agent_autonomy.value,
        paused_node_id=outcome.paused_node_id,
        approved_steps=[],
        trigger_payload=dict(trigger_payload),
        outputs=outcome.outputs,
        final_output=outcome.final_output,
        nodes_executed=outcome.nodes_executed,
        evidence_chain=outcome.evidence_chain,
        error=outcome.error,
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
        outcome.status.value,
        len(outcome.nodes_executed),
        len(outcome.evidence_chain),
        workflow.org_id,
    )
    return run


class RunNotResumable(ValueError):
    """The run isn't in a state that can be resumed.

    Surfaced by the route as 409: only a ``paused`` run with a recorded
    ``paused_node_id`` can be resumed.
    """


async def resume_run(
    db: AsyncSession,
    *,
    workflow: WorkflowRow,
    version: WorkflowVersionRow,
    run: WorkflowRunRow,
    approver_id: str | None,
    integration_autonomy: IntegrationAutonomy | None = None,
) -> WorkflowRunRow:
    """Resume a paused run: approve the paused step and continue execution.

    Re-executes the workflow from a rehydrated checkpoint -- completed steps
    are reused (not re-run), and the previously-paused node (plus any earlier
    approvals) is added to ``approved_steps`` so its gate is bypassed. The
    run row is **updated in place**: it transitions ``paused`` →
    ``succeeded`` / ``failed`` / ``paused`` (if a *later* gate trips), with
    ``approved_steps`` accumulating across resume cycles.

    Posture rehydration: ``active_tlp`` *and* ``agent_autonomy`` are read
    from the run row (snapshotted at create time), so a resume executes
    under exactly the posture the run started with -- a caller can't widen
    or narrow autonomy mid-run, and an investigation's later autonomy edits
    don't retroactively change in-flight runs. Rows that predate autonomy
    snapshotting fall back to L2 (the previous hardcoded default).

    Concurrency: the run is *atomically claimed* with a single conditional
    UPDATE (``paused`` → ``running``) and committed before invoking the
    engine. The commit makes the claim durable + visible to siblings, so a
    second approver arriving concurrently finds ``rowcount=0`` on its claim
    UPDATE and 409s without ever touching ``_run_capture`` — the approved
    integration node therefore fires at most once across racing approvers.
    This pattern is portable across Postgres, MySQL and SQLite (the previous
    ``SELECT ... FOR UPDATE`` was a no-op on aiosqlite and let both racers
    pass the in-memory status check, double-firing the destructive action;
    Codex flagged this on PR #189).

    Failure preservation: if the resumed execution fails (e.g. the connector
    TLP check rejects the approved action), the prior checkpoint outputs,
    nodes_executed, and evidence chain are RETAINED on the row -- only the
    status and error are updated, so the audit trail of what completed
    before the pause isn't erased.

    Raises :class:`RunNotResumable` (→ 409) when the run isn't paused.
    """
    # Atomic claim: single conditional UPDATE flips paused -> running; only
    # one racer can match. Commit immediately so the claim is durable +
    # visible to a sibling resume call before the engine runs (which yields
    # control on every await). Any subsequent ORM op auto-begins a fresh
    # transaction for the rest of the work.
    claim = await db.execute(
        update(WorkflowRunRow)
        .where(
            WorkflowRunRow.id == run.id,
            WorkflowRunRow.status == WorkflowRunStatus.PAUSED.value,
        )
        .values(status=WorkflowRunStatus.RUNNING.value)
    )
    await db.commit()
    if claim.rowcount != 1:
        raise RunNotResumable(f"Run {run.id} is no longer paused; cannot resume.")
    # The in-memory ORM instance is now stale -- refresh so subsequent reads
    # (paused_node_id, evidence_chain, etc.) see the just-committed row.
    await db.refresh(run)
    if not run.paused_node_id:
        # Defensive: a paused row must always carry the paused_node_id. If
        # this fires it's a data-integrity bug, not a race.
        raise RunNotResumable(f"Run {run.id} has no paused_node_id; cannot resume.")

    wf = _load_workflow(version)
    resume_state = _rehydrate_state(run)
    # Accumulate approvals: every previously-approved step plus the one the
    # caller is approving now (the node the run is currently paused at).
    approved = set(run.approved_steps or []) | {run.paused_node_id}
    # Rehydrate the prior audit chain so new records link to its tail instead
    # of restarting at GENESIS (preserves the tamper-evident chain).
    prior_evidence = [EvidenceRecord.model_validate(entry) for entry in (run.evidence_chain or [])]
    # Snapshot the pre-resume checkpoint so a failed attempt preserves it.
    prior_outputs = dict(run.outputs or {})
    prior_nodes_executed = list(run.nodes_executed or [])

    active_tlp = TLP(run.active_tlp) if run.active_tlp else TLP.RED
    # Pre-snapshot rows (before migration 0018) resumed under the hardcoded
    # L2 default; keep that exact behaviour for them.
    agent_autonomy = (
        AutonomyLevel(run.agent_autonomy) if run.agent_autonomy else AutonomyLevel.L2_SUPERVISED
    )
    ctx = NodeContext(
        run_id=run.id,
        workflow_run_id=run.id,
        investigation_id=run.investigation_id,
        org_id=workflow.org_id,
        user_id=run.triggered_by,
        tlp_level=active_tlp.value,
    )

    outcome = await _run_capture(
        workflow=wf,
        trigger_payload=dict(run.trigger_payload or {}),
        ctx=ctx,
        active_tlp=active_tlp,
        agent_autonomy=agent_autonomy,
        integration_autonomy=integration_autonomy or IntegrationAutonomy(),
        resume_state=resume_state,
        approved_steps=approved,
        prior_evidence=prior_evidence,
    )

    # Update the existing row in place. For a failed outcome retain the
    # prior checkpoint so the row still records what completed before the
    # pause; the executor doesn't return partial state on a structural
    # failure mid-walk, so overwriting with empty fields would erase the
    # only trail of what actually happened.
    run.status = outcome.status.value
    if outcome.status == WorkflowRunStatus.FAILED:
        run.outputs = prior_outputs
        run.nodes_executed = prior_nodes_executed
        run.final_output = None
        # Keep the prior evidence chain; new records (if any) the middleware
        # appended before the failure also flow back via outcome.evidence_chain
        # since _run_capture seeded it with prior_evidence -- but on a failure
        # outcome the engine may have raised mid-step so the appended set may
        # be empty. Either way, outcome.evidence_chain is "prior + any new"
        # so it strictly supersedes the prior chain and is what we persist.
        run.evidence_chain = outcome.evidence_chain or [
            r.model_dump(mode="json") for r in prior_evidence
        ]
    else:
        run.outputs = outcome.outputs
        run.final_output = outcome.final_output
        run.nodes_executed = outcome.nodes_executed
        run.evidence_chain = outcome.evidence_chain
    run.error = outcome.error
    run.paused_node_id = outcome.paused_node_id  # next pause node, or None
    run.approved_steps = sorted(approved)
    run.completed_at = _utcnow()
    await db.flush()
    logger.info(
        "WorkflowRun %s resumed by %s: status=%s steps=%d evidence=%d approved=%d (org=%s)",
        run.id,
        approver_id,
        outcome.status.value,
        len(run.nodes_executed),
        len(run.evidence_chain),
        len(approved),
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
