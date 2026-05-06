"""Tests for WorkflowExecutor -- walks a compiled Workflow graph.

Sprint 2.5A. Covers the contract documented in
``btagent_engine/runtime/executor.py``: linear walks, decision routing,
parallel fan-out/in, HITL pause -> WorkflowPaused, middleware ordering
across nodes, error wrapping, and the defensive step-count cap.

Tests register their nodes locally and unregister on teardown so the
suite doesn't pollute the global :class:`NodeRegistry`. They also avoid
re-using built-in (decision / parallel / hitl) ids on registration --
those are resolved by the executor without registry lookup.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, ClassVar

import pytest
from btagent_shared.types.config import AutonomyLevel
from pydantic import BaseModel

from btagent_engine import (
    Middleware,
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)
from btagent_engine.compiler.compiler import MAX_STEPS
from btagent_engine.compiler.workflow import Workflow, WorkflowEdge, WorkflowNode
from btagent_engine.middleware.hitl import HITLMiddleware
from btagent_engine.runtime import (
    WorkflowExecutionError,
    WorkflowExecutor,
    WorkflowPaused,
    WorkflowRunResult,
    WorkflowState,
)

# --------------------------------------------------------------------------- #
# Test nodes
# --------------------------------------------------------------------------- #


class _IntInput(BaseModel):
    n: int


class _IntOutput(BaseModel):
    n: int


class _EchoNode(Node[_IntInput, _IntOutput]):
    """Pass an int through unchanged. Useful as a pipeline starting point."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="test.executor.echo",
        name="Echo",
        version="0.1.0",
        category=NodeCategory.DATA,
    )
    input_schema = _IntInput
    output_schema = _IntOutput

    async def run(self, input: _IntInput, ctx: NodeContext) -> _IntOutput:
        return _IntOutput(n=input.n)


class _DoubleNode(Node[_IntInput, _IntOutput]):
    meta: ClassVar[NodeMeta] = NodeMeta(
        id="test.executor.double",
        name="Double",
        version="0.1.0",
        category=NodeCategory.DATA,
    )
    input_schema = _IntInput
    output_schema = _IntOutput

    async def run(self, input: _IntInput, ctx: NodeContext) -> _IntOutput:
        return _IntOutput(n=input.n * 2)


class _AddOneNode(Node[_IntInput, _IntOutput]):
    meta: ClassVar[NodeMeta] = NodeMeta(
        id="test.executor.add_one",
        name="Add One",
        version="0.1.0",
        category=NodeCategory.DATA,
    )
    input_schema = _IntInput
    output_schema = _IntOutput

    async def run(self, input: _IntInput, ctx: NodeContext) -> _IntOutput:
        return _IntOutput(n=input.n + 1)


class _BoomNode(Node[_IntInput, _IntOutput]):
    meta: ClassVar[NodeMeta] = NodeMeta(
        id="test.executor.boom",
        name="Boom",
        version="0.1.0",
        category=NodeCategory.DATA,
    )
    input_schema = _IntInput
    output_schema = _IntOutput

    async def run(self, input: _IntInput, ctx: NodeContext) -> _IntOutput:
        raise ValueError("kaboom")


class _SleepInput(BaseModel):
    n: int
    sleep: float = 0.0


class _SleepOutput(BaseModel):
    n: int
    slept: float


class _SleepNode(Node[_SleepInput, _SleepOutput]):
    """Sleep ``sleep`` seconds, then echo. Used to assert parallel concurrency."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="test.executor.sleep",
        name="Sleep",
        version="0.1.0",
        category=NodeCategory.DATA,
    )
    input_schema = _SleepInput
    output_schema = _SleepOutput

    async def run(self, input: _SleepInput, ctx: NodeContext) -> _SleepOutput:
        await asyncio.sleep(input.sleep)
        return _SleepOutput(n=input.n, slept=input.sleep)


class _ConfigInput(BaseModel):
    """Two-field input -- ``n`` from upstream, ``earliest`` from static config."""

    n: int
    earliest: str = "-15m"


class _ConfigOutput(BaseModel):
    n: int
    earliest: str


class _ConfigNode(Node[_ConfigInput, _ConfigOutput]):
    meta: ClassVar[NodeMeta] = NodeMeta(
        id="test.executor.config_aware",
        name="Config Aware",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
    )
    input_schema = _ConfigInput
    output_schema = _ConfigOutput

    async def run(self, input: _ConfigInput, ctx: NodeContext) -> _ConfigOutput:
        return _ConfigOutput(n=input.n, earliest=input.earliest)


class _DecideInput(BaseModel):
    """Input the executor passes to a decision step.

    The DecisionNode's input_schema is ``DecisionNodeInput(value=...)``;
    using the upstream-output -> dict -> validate path means whoever
    feeds the decision must produce a ``value`` field. This node does.
    """

    value: Any


class _DecideOutput(BaseModel):
    value: Any


class _DecideValueNode(Node[_DecideInput, _DecideOutput]):
    """Echo a value into the ``value`` field DecisionNode expects."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="test.executor.decide_value",
        name="Decide Value",
        version="0.1.0",
        category=NodeCategory.DATA,
    )
    input_schema = _DecideInput
    output_schema = _DecideOutput

    async def run(self, input: _DecideInput, ctx: NodeContext) -> _DecideOutput:
        return _DecideOutput(value=input.value)


class _IntegrationProbeNode(Node[_IntInput, _IntOutput]):
    """Integration-category node so the HITL middleware can pause it.

    The id contains ``virustotal`` so :class:`HITLMiddleware`'s autonomy
    map resolves it to ``cti_lookup``; the ``test.executor.`` prefix
    isolates us from the production VirusTotal node id.
    """

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="test.executor.integration.virustotal.probe",
        name="VT Probe",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
    )
    input_schema = _IntInput
    output_schema = _IntOutput

    async def run(self, input: _IntInput, ctx: NodeContext) -> _IntOutput:
        return _IntOutput(n=input.n)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


_TEST_NODE_CLASSES: tuple[type[Node], ...] = (
    _EchoNode,
    _DoubleNode,
    _AddOneNode,
    _BoomNode,
    _SleepNode,
    _ConfigNode,
    _DecideValueNode,
    _IntegrationProbeNode,
)


@pytest.fixture(autouse=True)
def _register_test_nodes():
    """Register each test node for the duration of the module's tests.

    All ids live under ``test.executor.*`` so they can't collide with
    sibling test modules' registrations; we still unregister on teardown
    so the registry stays clean for any later module that uses the same
    ids in a different way.
    """
    for cls in _TEST_NODE_CLASSES:
        # Defensive: tolerate a previous test crashing without teardown.
        NodeRegistry.unregister(cls.meta.id)
        NodeRegistry.register(cls)
    yield
    for cls in _TEST_NODE_CLASSES:
        NodeRegistry.unregister(cls.meta.id)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_test", org_id="org_test")


# --------------------------------------------------------------------------- #
# Workflow builders -- terse helpers so the test bodies stay readable
# --------------------------------------------------------------------------- #


def _wf(
    *,
    name: str = "test_wf",
    nodes: list[WorkflowNode],
    edges: list[WorkflowEdge],
) -> Workflow:
    return Workflow(
        name=name,
        version="1.0",
        trigger={"type": "manual", "parameters": {}},
        nodes=tuple(nodes),
        edges=tuple(edges),
    )


def _action(step_id: str, node_id: str, **config: Any) -> WorkflowNode:
    return WorkflowNode(step_id=step_id, node_id=node_id, name=step_id, config=config)


# --------------------------------------------------------------------------- #
# Linear / sequential
# --------------------------------------------------------------------------- #


async def test_linear_three_node_workflow_runs_to_completion():
    """Echo -> Double -> AddOne. Final output is AddOne's value."""
    wf = _wf(
        nodes=[
            _action("a", _EchoNode.meta.id),
            _action("b", _DoubleNode.meta.id),
            _action("c", _AddOneNode.meta.id),
        ],
        edges=[
            WorkflowEdge(source="a", target="b", label="next"),
            WorkflowEdge(source="b", target="c", label="next"),
        ],
    )
    result = await WorkflowExecutor().execute(wf, {"n": 3}, _ctx())
    assert isinstance(result, WorkflowRunResult)
    # 3 -> echo=3 -> double=6 -> add_one=7
    assert isinstance(result.final_output, _IntOutput)
    assert result.final_output.n == 7


async def test_outputs_dict_has_one_entry_per_executed_node():
    wf = _wf(
        nodes=[
            _action("a", _EchoNode.meta.id),
            _action("b", _DoubleNode.meta.id),
            _action("c", _AddOneNode.meta.id),
        ],
        edges=[
            WorkflowEdge(source="a", target="b", label="next"),
            WorkflowEdge(source="b", target="c", label="next"),
        ],
    )
    result = await WorkflowExecutor().execute(wf, {"n": 2}, _ctx())
    assert set(result.outputs.keys()) == {"a", "b", "c"}
    assert result.nodes_executed == ["a", "b", "c"]
    # Each value is a typed model.
    for v in result.outputs.values():
        assert isinstance(v, BaseModel)


async def test_initial_input_is_validated_against_entry_schema():
    """A dict initial input is validated against the entry node's input_schema."""
    wf = _wf(
        nodes=[_action("a", _EchoNode.meta.id)],
        edges=[],
    )
    # Wrong shape -> Pydantic ValidationError surfaces (not silently swallowed).
    with pytest.raises(Exception):  # pragma: no branch
        await WorkflowExecutor().execute(wf, {"not_n": "wrong"}, _ctx())

    # Correct shape produces the expected typed output.
    result = await WorkflowExecutor().execute(wf, {"n": 9}, _ctx())
    assert isinstance(result.final_output, _IntOutput)
    assert result.final_output.n == 9


async def test_sequential_propagation_passes_output_to_next_input():
    """Echo -> Double: Double's input.n is Echo's output.n (no manual wiring)."""
    wf = _wf(
        nodes=[
            _action("e", _EchoNode.meta.id),
            _action("d", _DoubleNode.meta.id),
        ],
        edges=[WorkflowEdge(source="e", target="d", label="next")],
    )
    result = await WorkflowExecutor().execute(wf, {"n": 5}, _ctx())
    # Echo passes 5 along; Double doubles to 10.
    assert isinstance(result.final_output, _IntOutput)
    assert result.final_output.n == 10
    assert result.outputs["e"].n == 5
    assert result.outputs["d"].n == 10


# --------------------------------------------------------------------------- #
# Static config merge
# --------------------------------------------------------------------------- #


async def test_static_config_is_merged_into_next_node_input():
    """A workflow step's static ``config`` flows into the node input.

    Echo emits ``{n: 7}`` -> ConfigAware's input is ``{n: 7, earliest: '-1h'}``
    because the WorkflowNode declares ``config={'earliest': '-1h'}``.
    """
    wf = _wf(
        nodes=[
            _action("e", _EchoNode.meta.id),
            _action("c", _ConfigNode.meta.id, earliest="-1h"),
        ],
        edges=[WorkflowEdge(source="e", target="c", label="next")],
    )
    result = await WorkflowExecutor().execute(wf, {"n": 7}, _ctx())
    assert isinstance(result.final_output, _ConfigOutput)
    assert result.final_output.n == 7
    assert result.final_output.earliest == "-1h"


async def test_static_config_wins_on_key_collision():
    """If upstream and config both set the same key, config wins.

    Echo emits ``{n: 7}``; static config ``{n: 99, earliest: '-1h'}`` overrides
    the upstream ``n``, so ConfigNode sees ``n=99``.
    """
    wf = _wf(
        nodes=[
            _action("e", _EchoNode.meta.id),
            _action("c", _ConfigNode.meta.id, n=99, earliest="-1h"),
        ],
        edges=[WorkflowEdge(source="e", target="c", label="next")],
    )
    result = await WorkflowExecutor().execute(wf, {"n": 7}, _ctx())
    assert isinstance(result.final_output, _ConfigOutput)
    assert result.final_output.n == 99
    assert result.final_output.earliest == "-1h"


# --------------------------------------------------------------------------- #
# Decision routing
# --------------------------------------------------------------------------- #


async def test_decision_picks_matching_branch_and_skips_the_other():
    """DecisionNode routes to the branch matching its output.branch.

    Pre-decide produces ``value=True`` -> DecisionNode emits branch='true' ->
    the 'true' edge target runs; the 'false' branch's node never executes.
    """
    wf = _wf(
        nodes=[
            _action("pre", _DecideValueNode.meta.id),
            _action("gate", "decision.branch"),
            _action("yes", _DoubleNode.meta.id),
            _action("no", _AddOneNode.meta.id),
        ],
        edges=[
            WorkflowEdge(source="pre", target="gate", label="next"),
            WorkflowEdge(source="gate", target="yes", label="true"),
            WorkflowEdge(source="gate", target="no", label="false"),
        ],
    )
    # ``pre`` accepts ``value`` field; we send True so the gate routes "true".
    # ``yes`` is a DoubleNode expecting ``n``; the DecisionNode's output is
    # ``{branch: 'true', value: True}`` -- DoubleNode validates ``n`` from
    # the merged dict, so we feed ``n`` via static config.
    wf = _wf(
        nodes=[
            _action("pre", _DecideValueNode.meta.id),
            _action("gate", "decision.branch"),
            _action("yes", _DoubleNode.meta.id, n=4),
            _action("no", _AddOneNode.meta.id, n=4),
        ],
        edges=[
            WorkflowEdge(source="pre", target="gate", label="next"),
            WorkflowEdge(source="gate", target="yes", label="true"),
            WorkflowEdge(source="gate", target="no", label="false"),
        ],
    )
    result = await WorkflowExecutor().execute(wf, {"value": True}, _ctx())
    # 'yes' ran (DoubleNode on n=4 -> 8), 'no' did not.
    assert "yes" in result.outputs
    assert "no" not in result.outputs
    assert isinstance(result.final_output, _IntOutput)
    assert result.final_output.n == 8


async def test_decision_with_no_matching_edge_raises():
    """If none of the out-edges' labels match the chosen branch, error out."""
    wf = _wf(
        nodes=[
            _action("pre", _DecideValueNode.meta.id),
            _action("gate", "decision.branch"),
            _action("yes", _DoubleNode.meta.id, n=1),
        ],
        edges=[
            WorkflowEdge(source="pre", target="gate", label="next"),
            # Only the 'true' edge exists; sending value=False should fail.
            WorkflowEdge(source="gate", target="yes", label="true"),
        ],
    )
    with pytest.raises(WorkflowExecutionError) as ei:
        await WorkflowExecutor().execute(wf, {"value": False}, _ctx())
    assert ei.value.node_id == "gate"
    assert ei.value.reason == "no matching branch"


# --------------------------------------------------------------------------- #
# Parallel fan-out
# --------------------------------------------------------------------------- #


async def test_parallel_fan_out_runs_branches_concurrently():
    """Two branches sleeping 200ms each should finish in well under 400ms."""
    wf = _wf(
        nodes=[
            _action("fan", "decision.parallel", branches=[["s1"], ["s2"]]),
            _action("s1", _SleepNode.meta.id, sleep=0.2),
            _action("s2", _SleepNode.meta.id, sleep=0.2),
            _action("end", _EchoNode.meta.id, n=0),
        ],
        edges=[
            WorkflowEdge(source="fan", target="s1", label="branch.0"),
            WorkflowEdge(source="fan", target="s2", label="branch.1"),
            WorkflowEdge(source="fan", target="end", label="join"),
        ],
    )
    start = time.perf_counter()
    # Initial input goes to ``fan`` -- ParallelNode merges branch_results.
    # We pass an explicit empty list so the merge call validates cleanly;
    # the executor overrides this with the gathered results before merging.
    result = await WorkflowExecutor().execute(wf, {"n": 1}, _ctx())
    elapsed = time.perf_counter() - start
    # Sequential lower bound is 0.4s; concurrent should be well under that.
    assert elapsed < 0.35, f"branches did not run concurrently (took {elapsed:.3f}s)"
    assert "s1" in result.outputs
    assert "s2" in result.outputs


async def test_parallel_merge_preserves_declaration_order():
    """branch_results is in branch.0, branch.1, ... order regardless of timing."""
    wf = _wf(
        nodes=[
            _action("fan", "decision.parallel", branches=[["fast"], ["slow"]]),
            # branch.0 finishes first by timing, branch.1 second.
            _action("fast", _SleepNode.meta.id, sleep=0.05),
            _action("slow", _SleepNode.meta.id, sleep=0.15),
            _action("end", _EchoNode.meta.id, n=0),
        ],
        edges=[
            WorkflowEdge(source="fan", target="fast", label="branch.0"),
            WorkflowEdge(source="fan", target="slow", label="branch.1"),
            WorkflowEdge(source="fan", target="end", label="join"),
        ],
    )
    result = await WorkflowExecutor().execute(wf, {"n": 1}, _ctx())
    fan_output = result.outputs["fan"]
    # ParallelNode emits ``merged`` (branch_results in declaration order);
    # branch.0 is the fast one (0.05s), branch.1 the slow one (0.15s). The
    # entries are the typed branch-terminal outputs (``_SleepOutput``).
    merged = fan_output.merged  # type: ignore[attr-defined]
    assert len(merged) == 2
    # ``slept`` reflects the requested sleep, so order is verifiable.
    assert merged[0].slept == pytest.approx(0.05, abs=0.05)
    assert merged[1].slept == pytest.approx(0.15, abs=0.05)


# --------------------------------------------------------------------------- #
# HITL pause
# --------------------------------------------------------------------------- #


async def test_hitl_pause_raises_workflow_paused_with_partial_state():
    """An L0 agent + integration node = pause; partial state is preserved."""
    wf = _wf(
        nodes=[
            _action("e", _EchoNode.meta.id),
            _action("vt", _IntegrationProbeNode.meta.id),
        ],
        edges=[WorkflowEdge(source="e", target="vt", label="next")],
    )
    executor = WorkflowExecutor(
        middlewares=[HITLMiddleware(agent_autonomy=AutonomyLevel.L0_MANUAL)],
    )
    with pytest.raises(WorkflowPaused) as ei:
        await executor.execute(wf, {"n": 5}, _ctx())
    paused = ei.value
    # The first (echo) node completed; the integration probe is the pause point.
    assert paused.node_id == "vt"
    assert isinstance(paused.state, WorkflowState)
    assert "e" in paused.state.outputs
    assert "vt" not in paused.state.outputs
    assert paused.state.outputs["e"].n == 5


# --------------------------------------------------------------------------- #
# Middleware ordering
# --------------------------------------------------------------------------- #


class _RecordingMW(Middleware):
    """Logs before/after for each node it sees, in graph-walk order."""

    def __init__(self, log: list[str]) -> None:
        self.name = "recording"
        self._log = log

    async def before_run(self, node, input, ctx):
        self._log.append(f"before:{node.meta.id}")

    async def after_run(self, node, input, output, ctx):
        self._log.append(f"after:{node.meta.id}")


async def test_middleware_sees_each_node_in_graph_order():
    """An inline middleware sees before/after for every executed node, in order."""
    log: list[str] = []
    wf = _wf(
        nodes=[
            _action("a", _EchoNode.meta.id),
            _action("b", _DoubleNode.meta.id),
            _action("c", _AddOneNode.meta.id),
        ],
        edges=[
            WorkflowEdge(source="a", target="b", label="next"),
            WorkflowEdge(source="b", target="c", label="next"),
        ],
    )
    await WorkflowExecutor(middlewares=[_RecordingMW(log)]).execute(
        wf, {"n": 1}, _ctx()
    )
    assert log == [
        f"before:{_EchoNode.meta.id}",
        f"after:{_EchoNode.meta.id}",
        f"before:{_DoubleNode.meta.id}",
        f"after:{_DoubleNode.meta.id}",
        f"before:{_AddOneNode.meta.id}",
        f"after:{_AddOneNode.meta.id}",
    ]


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


async def test_unregistered_node_raises_workflow_execution_error():
    wf = _wf(
        nodes=[_action("a", "test.does_not_exist")],
        edges=[],
    )
    with pytest.raises(WorkflowExecutionError) as ei:
        await WorkflowExecutor().execute(wf, {"n": 1}, _ctx())
    assert ei.value.node_id == "a"
    assert ei.value.reason == "not registered"


async def test_node_run_exception_is_wrapped_with_cause():
    wf = _wf(
        nodes=[_action("a", _BoomNode.meta.id)],
        edges=[],
    )
    with pytest.raises(WorkflowExecutionError) as ei:
        await WorkflowExecutor().execute(wf, {"n": 1}, _ctx())
    assert ei.value.node_id == "a"
    assert ei.value.reason == "run failed"
    # The original ValueError is preserved on .cause for diagnostics.
    assert isinstance(ei.value.cause, ValueError)
    assert "kaboom" in str(ei.value.cause)


async def test_multiple_entry_nodes_raises_at_start():
    """Two nodes with no incoming edges -> error before any work is done."""
    wf = _wf(
        nodes=[
            _action("a", _EchoNode.meta.id),
            _action("b", _EchoNode.meta.id),  # both 'a' and 'b' have no in-edges
        ],
        edges=[],
    )
    with pytest.raises(WorkflowExecutionError) as ei:
        await WorkflowExecutor().execute(wf, {"n": 1}, _ctx())
    assert ei.value.reason == "multiple entries"


# --------------------------------------------------------------------------- #
# Defence in depth -- step cap
# --------------------------------------------------------------------------- #


async def test_step_cap_aborts_pathological_workflow():
    """A workflow with > MAX_STEPS chained nodes aborts before exceeding.

    The compiler caps this at compile time, but the executor enforces the
    same limit at runtime as belt-and-braces against a cycle the compiler
    might have missed. We construct the Workflow directly here so we
    bypass the compiler's check and exercise the executor's guard.
    """
    n = MAX_STEPS + 5
    nodes = [_action(f"s{i}", _EchoNode.meta.id) for i in range(n)]
    edges = [
        WorkflowEdge(source=f"s{i}", target=f"s{i + 1}", label="next")
        for i in range(n - 1)
    ]
    wf = _wf(nodes=nodes, edges=edges)
    with pytest.raises(WorkflowExecutionError) as ei:
        await WorkflowExecutor().execute(wf, {"n": 1}, _ctx())
    assert ei.value.reason == "step cap exceeded"


# --------------------------------------------------------------------------- #
# Misc: terminal handling, single-node workflow
# --------------------------------------------------------------------------- #


async def test_single_node_workflow_returns_that_nodes_output():
    """Edge case: a workflow with just one node still produces final_output."""
    wf = _wf(
        nodes=[_action("only", _EchoNode.meta.id)],
        edges=[],
    )
    result = await WorkflowExecutor().execute(wf, {"n": 42}, _ctx())
    assert result.nodes_executed == ["only"]
    assert isinstance(result.final_output, _IntOutput)
    assert result.final_output.n == 42
