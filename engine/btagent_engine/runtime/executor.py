"""Workflow executor -- walks a compiled :class:`Workflow` end-to-end.

Sprint 2.5A. Bridges the gap between the compiler (Sprint 2C, which emits an
immutable graph) and the orchestrator (Sprint 3, which will catch pause
exceptions and persist checkpoints). Per-node execution still goes through
``Runner.execute`` so the cross-cutting middleware chain (HITL, EventEmitter,
EvidenceChain, Classification, Scope, PromptBudget) applies uniformly.

Execution model recap:

* **Entry detection.** A node with no incoming edges is the entry. Multiple
  entries -> ``WorkflowExecutionError``.
* **Sequential edges (label ``"next"``).** The previous node's output becomes
  the next node's input, with the next node's static ``config`` merged on top
  (static wins on key collision) before validation.
* **Decision routing.** The DecisionNode's output ``branch`` is matched against
  out-edge labels; the matching edge is taken, the rest are pruned.
* **Parallel fan-out.** ``branch.<i>`` edges are walked concurrently with
  ``asyncio.gather``; results are collected in declaration order; the
  ParallelNode then runs its merge step on the collected results, and the
  ``"join"`` edge is followed downstream.
* **HITL pause.** ``HITLPause`` raised by middleware is caught and re-raised
  as :class:`WorkflowPaused`, carrying the partial :class:`WorkflowState` so
  the caller can checkpoint + resume later. Resume itself is Sprint 3.
* **Synthetic structural nodes.** The compiler emits ``compiler.join`` /
  ``compiler.end`` placeholders that have no registered Node class; the
  executor treats them as transparent pass-throughs. The brief deliberately
  scopes resolve-against-registry as the runner's job.
* **Defence in depth.** The compiler caps step counts; the executor
  additionally caps ``nodes_executed`` at ``MAX_STEPS`` so a pathological
  cycle the compiler missed cannot run away.
"""

from __future__ import annotations

import asyncio
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.compiler.compiler import MAX_STEPS
from btagent_engine.compiler.steps import (
    DecisionNode,
    HITLGateNode,
    ParallelNode,
    ParallelNodeInput,
)
from btagent_engine.compiler.workflow import Workflow, WorkflowNode
from btagent_engine.middleware.base import Middleware, Runner
from btagent_engine.middleware.hitl import HITLPause
from btagent_engine.node import Node, NodeContext, NodeRegistry
from btagent_engine.runtime.conditions import (
    ConditionEvaluationError,
    build_condition_context,
    coerce_to_branch,
    evaluate_condition,
)
from btagent_engine.runtime.state import WorkflowState

# Synthetic node ids the compiler emits for structural ``join`` / ``end``
# steps. They have no registered Node class -- the executor short-circuits
# them and forwards the upstream payload verbatim.
_PASSTHROUGH_NODE_IDS: frozenset[str] = frozenset({"compiler.join", "compiler.end"})

# Built-in compiler-emitted node ids -- used to dispatch routing logic
# without an isinstance check (the registered class is what gets executed).
_DECISION_NODE_ID = DecisionNode.meta.id
_PARALLEL_NODE_ID = ParallelNode.meta.id
_HITL_GATE_NODE_ID = HITLGateNode.meta.id


# --------------------------------------------------------------------------- #
# Result + exception types
# --------------------------------------------------------------------------- #


class WorkflowRunResult(BaseModel):
    """Terminal result of a successful workflow execution.

    ``outputs`` mirrors :class:`WorkflowState.outputs` -- duplicated here so
    callers don't have to crack open the state object for the common case.
    ``final_output`` is whichever node had no outgoing edges (the terminal
    leaf the executor stopped at). ``nodes_executed`` is the in-order list
    of step ids the executor ran, useful for replay / audit.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    workflow_id: str
    outputs: dict[str, BaseModel] = Field(default_factory=dict)
    final_output: BaseModel | None = None
    nodes_executed: list[str] = Field(default_factory=list)


class WorkflowExecutionError(RuntimeError):
    """Raised on any structural / execution failure walking a workflow.

    ``node_id`` is the workflow step that failed (or ``None`` for failures
    that happen pre-walk, e.g. multi-entry detection). ``reason`` is a
    short human-readable tag (``"not registered"``, ``"no matching branch"``,
    ``"step cap exceeded"``, ...). ``cause`` carries the original exception
    when wrapping a Node.run failure so the traceback isn't lost.
    """

    def __init__(
        self,
        message: str,
        *,
        node_id: str | None = None,
        reason: str | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        self.node_id = node_id
        self.reason = reason
        self.cause = cause


class WorkflowPaused(Exception):
    """Raised when a workflow stops because a node requires human approval.

    Carries the partial :class:`WorkflowState` of nodes already completed
    plus the originating :class:`HITLPause` so the orchestrator (Sprint 3)
    can build a checkpoint record without having to re-derive autonomy
    levels.
    """

    def __init__(
        self,
        node_id: str,
        state: WorkflowState,
        cause: HITLPause,
    ) -> None:
        self.node_id = node_id
        self.state = state
        self.cause = cause
        super().__init__(
            f"Workflow paused at node {node_id!r} pending approval "
            f"(required={cause.required_level.value}, agent={cause.agent_level.value})"
        )


# --------------------------------------------------------------------------- #
# Executor
# --------------------------------------------------------------------------- #


class WorkflowExecutor:
    """Walks a compiled :class:`Workflow`, executing each step via ``Runner``.

    The executor is stateless across runs -- each ``execute`` call builds
    its own :class:`WorkflowState`. The middleware list is captured at
    construction time so the same set of cross-cutting concerns applies to
    every node in every workflow this executor runs (mirrors how a single
    ``Runner`` is shared across many ``execute`` calls today).
    """

    def __init__(self, middlewares: list[Middleware] | None = None) -> None:
        self._middlewares: list[Middleware] = list(middlewares or [])
        # One Runner instance, reused per node-execution call. Runner is
        # designed to be re-entered with no per-call state of its own.
        self._runner = Runner(self._middlewares)

    @property
    def middlewares(self) -> list[Middleware]:
        return list(self._middlewares)

    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #

    async def execute(
        self,
        workflow: Workflow,
        initial_input: BaseModel | dict[str, Any] | None,
        ctx: NodeContext,
    ) -> WorkflowRunResult:
        """Execute *workflow* end-to-end.

        Returns a :class:`WorkflowRunResult` on success. Raises
        :class:`WorkflowPaused` if a HITL middleware suspends execution
        (the caller is expected to checkpoint and resume), and
        :class:`WorkflowExecutionError` on any structural failure.
        """
        state = WorkflowState()
        entry_id = self._find_entry_id(workflow)
        # Initial input flows into the entry node verbatim. Treating it as
        # the synthetic "previous output" lets the standard input-build
        # logic merge it with the entry node's static config.
        await self._walk(
            workflow=workflow,
            start_step_id=entry_id,
            upstream_payload=initial_input,
            state=state,
            ctx=ctx,
            stop_at=None,
        )

        final_step = state.nodes_executed[-1] if state.nodes_executed else None
        return WorkflowRunResult(
            workflow_id=workflow.name,
            outputs=dict(state.outputs),
            final_output=state.outputs.get(final_step) if final_step else None,
            nodes_executed=list(state.nodes_executed),
        )

    # ------------------------------------------------------------------ #
    # Graph walk
    # ------------------------------------------------------------------ #

    async def _walk(
        self,
        *,
        workflow: Workflow,
        start_step_id: str,
        upstream_payload: BaseModel | dict[str, Any] | None,
        state: WorkflowState,
        ctx: NodeContext,
        stop_at: str | None,
    ) -> BaseModel | None:
        """Walk forward from *start_step_id*; return the last produced output.

        ``stop_at`` is the step id at which a sub-walk (one parallel branch)
        should halt -- it is the join target and belongs to the parent
        sequence. ``None`` means "walk until terminal".
        """
        current_id: str | None = start_step_id
        last_output: BaseModel | None = None
        carried_payload: BaseModel | dict[str, Any] | None = upstream_payload

        while current_id is not None and current_id != stop_at:
            self._enforce_step_cap(state, current_id)

            wf_node = workflow.step(current_id)
            if wf_node is None:
                raise WorkflowExecutionError(
                    f"Workflow references unknown step id {current_id!r}",
                    node_id=current_id,
                    reason="unknown step",
                )

            # Pass-through structural nodes (compiler.join, compiler.end)
            # do not execute -- they exist as graph anchors only.
            if wf_node.node_id in _PASSTHROUGH_NODE_IDS:
                # Treat upstream payload as this node's "output" for
                # downstream input-building purposes; record it so the
                # node appears in nodes_executed for audit symmetry.
                forwarded = self._coerce_passthrough(carried_payload)
                state.record(wf_node.step_id, forwarded)
                last_output = forwarded
                carried_payload = forwarded
                current_id = self._next_step(workflow, wf_node, forwarded)
                continue

            # ParallelNode is special: its out-edges are branches that run
            # concurrently *before* the merge call, then a join edge.
            if wf_node.node_id == _PARALLEL_NODE_ID:
                merged_output = await self._run_parallel(
                    workflow=workflow,
                    wf_node=wf_node,
                    upstream_payload=carried_payload,
                    state=state,
                    ctx=ctx,
                )
                last_output = merged_output
                carried_payload = merged_output
                current_id = self._next_parallel_step(workflow, wf_node)
                continue

            # Regular execute path. Resolve, build input, run via Runner.
            node_instance = self._resolve_node(wf_node)
            node_input = self._build_input(node_instance, carried_payload, wf_node.config)

            # DecisionNode condition evaluation: when the compiler stashed a
            # YAML-authored ``condition`` string in the step config, evaluate
            # it now against the current workflow state and force the result
            # into the DecisionNode's ``value`` input. The Node itself stays
            # unchanged -- it still emits ``branch=str(value)`` -- so the
            # back-compat path (literal ``value`` in input) keeps working
            # whenever the condition is empty / unset.
            if wf_node.node_id == _DECISION_NODE_ID:
                node_input = self._apply_condition(wf_node, node_input, state)

            output = await self._execute_node(
                node=node_instance,
                node_input=node_input,
                wf_node=wf_node,
                ctx=ctx,
                state=state,
            )
            state.record(wf_node.step_id, output)
            last_output = output
            carried_payload = output

            # Routing: DecisionNode picks an out-edge by label; everything
            # else takes the single non-decision out-edge if present.
            if wf_node.node_id == _DECISION_NODE_ID:
                current_id = self._next_decision_step(workflow, wf_node, output)
            else:
                current_id = self._next_step(workflow, wf_node, output)

        return last_output

    # ------------------------------------------------------------------ #
    # Per-node execution
    # ------------------------------------------------------------------ #

    async def _execute_node(
        self,
        *,
        node: Node,
        node_input: BaseModel | dict[str, Any],
        wf_node: WorkflowNode,
        ctx: NodeContext,
        state: WorkflowState,
    ) -> BaseModel:
        """Run a single node through the middleware-wrapped Runner.

        Catches HITLPause and re-raises as WorkflowPaused; wraps any other
        exception as WorkflowExecutionError so callers always see the
        failing step id rather than having to crawl the traceback.
        """
        try:
            return await self._runner.execute(node, node_input, ctx)
        except HITLPause as pause:
            raise WorkflowPaused(
                node_id=wf_node.step_id,
                state=state,
                cause=pause,
            ) from pause
        except WorkflowExecutionError:
            # Already a workflow-shaped failure (e.g. nested executor call);
            # propagate as-is so we don't double-wrap.
            raise
        except BaseException as exc:
            # KeyboardInterrupt / SystemExit / asyncio.CancelledError still
            # propagate unwrapped -- catch only the ordinary Exception layer.
            if not isinstance(exc, Exception):
                raise
            raise WorkflowExecutionError(
                f"Node {wf_node.step_id!r} failed: {exc}",
                node_id=wf_node.step_id,
                reason="run failed",
                cause=exc,
            ) from exc

    # ------------------------------------------------------------------ #
    # Parallel fork
    # ------------------------------------------------------------------ #

    async def _run_parallel(
        self,
        *,
        workflow: Workflow,
        wf_node: WorkflowNode,
        upstream_payload: BaseModel | dict[str, Any] | None,
        state: WorkflowState,
        ctx: NodeContext,
    ) -> BaseModel:
        """Fan out branches concurrently, then call ParallelNode for the merge.

        Each branch starts at the ``branch.<i>`` edge target and walks via
        ``next`` edges until either it has no outgoing edge or it would
        cross into the join target (which belongs to the parent sequence).
        Branch terminal outputs are gathered in declaration order regardless
        of completion order.
        """
        branch_edges = sorted(
            (e for e in workflow.out_edges(wf_node.step_id) if e.label.startswith("branch.")),
            key=lambda e: int(e.label.split(".", 1)[1]),
        )
        join_edge = next(
            (e for e in workflow.out_edges(wf_node.step_id) if e.label == "join"),
            None,
        )
        join_target = join_edge.target if join_edge else None

        async def _walk_branch(start_id: str) -> BaseModel | None:
            return await self._walk(
                workflow=workflow,
                start_step_id=start_id,
                upstream_payload=upstream_payload,
                state=state,
                ctx=ctx,
                stop_at=join_target,
            )

        branch_outputs = await asyncio.gather(
            *(_walk_branch(e.target) for e in branch_edges),
        )

        # ParallelNode itself does the merge call -- run it through Runner
        # so middleware (event emit, evidence chain) applies symmetrically.
        merge_input = ParallelNodeInput(branch_results=list(branch_outputs))
        parallel_node = self._resolve_node(wf_node)
        merged = await self._execute_node(
            node=parallel_node,
            node_input=merge_input,
            wf_node=wf_node,
            ctx=ctx,
            state=state,
        )
        state.record(wf_node.step_id, merged)
        return merged

    def _next_parallel_step(
        self,
        workflow: Workflow,
        wf_node: WorkflowNode,
    ) -> str | None:
        join_edge = next(
            (e for e in workflow.out_edges(wf_node.step_id) if e.label == "join"),
            None,
        )
        return join_edge.target if join_edge else None

    # ------------------------------------------------------------------ #
    # Routing
    # ------------------------------------------------------------------ #

    def _next_step(
        self,
        workflow: Workflow,
        wf_node: WorkflowNode,
        _output: BaseModel,
    ) -> str | None:
        """Pick the single ``next``/``join`` out-edge for a non-decision node.

        Tolerates terminal nodes (no out edges) by returning ``None``. If
        more than one non-decision out-edge exists at a non-decision /
        non-parallel node we treat the first ``next`` label as canonical
        (the compiler shouldn't emit ambiguous edges here, but belt +
        braces).
        """
        edges = workflow.out_edges(wf_node.step_id)
        if not edges:
            return None
        next_edge = next((e for e in edges if e.label == "next"), edges[0])
        return next_edge.target

    def _next_decision_step(
        self,
        workflow: Workflow,
        wf_node: WorkflowNode,
        output: BaseModel,
    ) -> str | None:
        """Pick the out-edge whose label matches the DecisionNode's branch."""
        branch = getattr(output, "branch", None)
        if branch is None:
            raise WorkflowExecutionError(
                f"Decision node {wf_node.step_id!r} produced output without a branch field",
                node_id=wf_node.step_id,
                reason="missing branch",
            )
        for edge in workflow.out_edges(wf_node.step_id):
            if edge.label == branch:
                return edge.target
        raise WorkflowExecutionError(
            f"Decision node {wf_node.step_id!r} chose branch {branch!r} "
            f"but no matching out-edge exists",
            node_id=wf_node.step_id,
            reason="no matching branch",
        )

    # ------------------------------------------------------------------ #
    # Input building
    # ------------------------------------------------------------------ #

    def _build_input(
        self,
        node: Node,
        upstream_payload: BaseModel | dict[str, Any] | None,
        config: dict[str, Any],
    ) -> dict[str, Any] | BaseModel:
        """Combine upstream output + static step config into the node input.

        Static config wins on key collision -- the playbook author's
        intent overrides whatever the upstream node happened to put in
        the field with the same name. Returning a dict (rather than a
        validated model) lets the Runner do its own ``model_validate``
        pass, which is the documented contract; it also avoids us
        instantiating the wrong schema if the previous output's class
        doesn't match the next node's input class.
        """
        if isinstance(upstream_payload, BaseModel):
            base: dict[str, Any] = upstream_payload.model_dump()
        elif isinstance(upstream_payload, dict):
            base = dict(upstream_payload)
        elif upstream_payload is None:
            base = {}
        else:  # pragma: no cover -- guarded by Runner.execute signature
            raise WorkflowExecutionError(
                f"Cannot build input for {node.meta.id!r} from {type(upstream_payload).__name__}",
                node_id=None,
                reason="bad upstream type",
            )

        if config:
            # Static config wins on collision per the brief.
            base.update(config)
        return base

    def _apply_condition(
        self,
        wf_node: WorkflowNode,
        node_input: BaseModel | dict[str, Any],
        state: WorkflowState,
    ) -> dict[str, Any]:
        """Evaluate a stashed ``condition`` string and rewrite the input ``value``.

        No-op when the step has no ``condition`` (or it's an empty string)
        -- the Sprint 2.5A Python-driven path with a literal ``value`` on
        the input continues to work unchanged.

        The evaluated value is coerced to the same string-branch shape
        DecisionNode itself produces (``"true"`` / ``"false"`` for bools,
        ``str(value)`` otherwise) and stuffed into ``value`` so the Node's
        own ``run`` doesn't have to know about conditions at all.
        """
        condition = wf_node.config.get("condition") if wf_node.config else None
        if not isinstance(condition, str) or not condition.strip():
            # Back-compat: no condition => let DecisionNode see the
            # upstream-provided ``value`` verbatim. We still drop unknown
            # keys here because DecisionNodeInput is ``extra="forbid"`` and
            # the upstream output may carry sibling fields (e.g. an
            # echo-shaped ``{value: True, ...}``) that the schema rejects.
            base = dict(node_input) if isinstance(node_input, dict) else node_input.model_dump()
            return {"value": base.get("value")}

        context = build_condition_context(state.outputs)
        try:
            raw = evaluate_condition(condition, context)
        except ConditionEvaluationError as exc:
            raise WorkflowExecutionError(
                f"Decision node {wf_node.step_id!r} condition {condition!r} failed: {exc}",
                node_id=wf_node.step_id,
                reason="condition evaluation failed",
                cause=exc,
            ) from exc

        # Replace the input outright -- DecisionNodeInput is ``extra="forbid"``,
        # so any sibling fields the upstream node or static config carried
        # would fail validation. The coerced branch label goes into ``value``;
        # DecisionNode's ``run`` then ``str(value)`` and emits it as ``branch``
        # for routing against the compiler-emitted out-edge labels.
        return {"value": coerce_to_branch(raw)}

    def _coerce_passthrough(
        self,
        upstream_payload: BaseModel | dict[str, Any] | None,
    ) -> BaseModel:
        """Wrap a passthrough payload in a tiny model so it round-trips.

        We need ``state.record`` to receive a BaseModel. Keep it minimal --
        the compiler doesn't define a Node class for join/end so there's no
        canonical schema to honour.
        """
        if isinstance(upstream_payload, BaseModel):
            return upstream_payload
        return _PassthroughOutput(payload=upstream_payload or {})

    # ------------------------------------------------------------------ #
    # Resolution + entry detection
    # ------------------------------------------------------------------ #

    def _resolve_node(self, wf_node: WorkflowNode) -> Node:
        """Look up the Node class in the registry and instantiate it.

        Compiler-emitted built-in steps (decision / parallel / hitl gate)
        are resolved by their well-known ids; everything else comes through
        ``NodeRegistry``. A miss raises ``WorkflowExecutionError`` with
        ``reason='not registered'`` so the caller can surface a helpful
        playbook-author-facing error.
        """
        if wf_node.node_id == _DECISION_NODE_ID:
            return DecisionNode()
        if wf_node.node_id == _PARALLEL_NODE_ID:
            return ParallelNode()
        if wf_node.node_id == _HITL_GATE_NODE_ID:
            return HITLGateNode()

        node_cls = NodeRegistry.get(wf_node.node_id)
        if node_cls is None:
            raise WorkflowExecutionError(
                f"Workflow step {wf_node.step_id!r} references node id "
                f"{wf_node.node_id!r} which is not in the registry",
                node_id=wf_node.step_id,
                reason="not registered",
            )
        return node_cls()

    def _find_entry_id(self, workflow: Workflow) -> str:
        """Return the single step id that has no incoming edges.

        Multiple entry points are an authoring bug -- the compiler doesn't
        currently flag them but the executor needs an unambiguous start
        node. Raises ``WorkflowExecutionError`` for both zero and multiple
        candidates so the caller gets actionable feedback.
        """
        if not workflow.nodes:
            raise WorkflowExecutionError(
                "Workflow has no nodes",
                reason="empty workflow",
            )

        targets = {e.target for e in workflow.edges}
        candidates = [n.step_id for n in workflow.nodes if n.step_id not in targets]
        if len(candidates) == 0:
            raise WorkflowExecutionError(
                "Workflow has no entry node (every node has an incoming edge)",
                reason="no entry",
            )
        if len(candidates) > 1:
            raise WorkflowExecutionError(
                f"Workflow has multiple entry nodes: {sorted(candidates)}",
                reason="multiple entries",
            )
        return candidates[0]

    # ------------------------------------------------------------------ #
    # Defence in depth
    # ------------------------------------------------------------------ #

    def _enforce_step_cap(self, state: WorkflowState, next_step_id: str) -> None:
        """Refuse to execute another step once MAX_STEPS is reached.

        The compiler enforces this on the *static* step list; this guard
        catches the dynamic case where (hypothetically) cycle detection
        missed something and we'd otherwise loop forever. ``next_step_id``
        is the about-to-execute step so the error message points at the
        offending step rather than the predecessor.
        """
        if len(state.nodes_executed) >= MAX_STEPS:
            raise WorkflowExecutionError(
                f"Workflow exceeded {MAX_STEPS} executed steps (would-be next: {next_step_id!r})",
                node_id=next_step_id,
                reason="step cap exceeded",
            )


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #


class _PassthroughOutput(BaseModel):
    """Minimal model used to record synthetic join/end node outputs.

    Keeps ``state.record``'s contract (must receive a BaseModel) intact
    without forcing the compiler to define a Node class for structural
    placeholders.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    payload: Any = None
