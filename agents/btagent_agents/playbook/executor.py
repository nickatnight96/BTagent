"""PlaybookExecutor — compiles a PlaybookDefinition into a LangGraph subgraph.

Each step type maps to a node function:
- Action: invoke tool (mock in dev)
- Decision: evaluate condition safely (no eval())
- HITL gate: use LangGraph interrupt
- Parallel fork: asyncio.gather
- Join / End: pass-through

Step results are accumulated in ``state["step_results"]``.
"""

from __future__ import annotations

import logging
from typing import Any

from btagent_shared.types.playbook import (
    ActionStep,
    DecisionStep,
    HITLGateStep,
    ParallelForkStep,
    PlaybookDefinition,
    PlaybookStep,
    StepType,
)
from langgraph.graph import END, StateGraph

from btagent_agents.playbook.state import PlaybookExecutionState
from btagent_agents.playbook.steps.action import execute_action_step
from btagent_agents.playbook.steps.decision import execute_decision_step
from btagent_agents.playbook.steps.hitl_gate import execute_hitl_gate_step
from btagent_agents.playbook.steps.parallel import execute_parallel_fork_step

logger = logging.getLogger("btagent.playbook.executor")


class PlaybookExecutor:
    """Compile a PlaybookDefinition into a LangGraph subgraph and execute it.

    Usage::

        executor = PlaybookExecutor(mock=True)
        graph = executor.compile_to_graph(playbook_def)
        result = graph.invoke(initial_state)
    """

    def __init__(self, *, mock: bool = True) -> None:
        self._mock = mock

    def compile_to_graph(
        self,
        playbook: PlaybookDefinition,
    ) -> Any:
        """Build a LangGraph StateGraph from a PlaybookDefinition.

        Each step becomes a node.  Edges follow ``next_step``, decision
        branches, and parallel forks.

        Parameters
        ----------
        playbook : PlaybookDefinition
            Validated playbook definition.

        Returns
        -------
        CompiledGraph
            A compiled LangGraph graph ready for ``.invoke()`` / ``.ainvoke()``.
        """
        graph = StateGraph(PlaybookExecutionState)

        step_map: dict[str, PlaybookStep] = {s.id: s for s in playbook.steps}
        mock = self._mock

        # --- Register a node for each step ---
        for step in playbook.steps:
            node_fn = _make_node(step, mock=mock)
            graph.add_node(step.id, node_fn)

        # --- Wire edges ---
        first_step = playbook.steps[0] if playbook.steps else None
        if first_step:
            graph.set_entry_point(first_step.id)

        for step in playbook.steps:
            if step.type == StepType.END:
                graph.add_edge(step.id, END)
                continue

            if step.type == StepType.DECISION:
                assert isinstance(step, DecisionStep)
                # Decision edges are handled via conditional routing
                graph.add_conditional_edges(
                    step.id,
                    _make_decision_router(step, step_map),
                )
                continue

            # Default: follow next_step or go to END
            if step.next_step and step.next_step in step_map:
                graph.add_edge(step.id, step.next_step)
            else:
                graph.add_edge(step.id, END)

        return graph.compile()


# ---------------------------------------------------------------------------
# Node factory functions
# ---------------------------------------------------------------------------


def _make_node(
    step: PlaybookStep,
    *,
    mock: bool = True,
) -> Any:
    """Create an async node function for a step."""

    async def _action_node(state: PlaybookExecutionState) -> dict[str, Any]:
        assert isinstance(step, ActionStep)
        context = state.get("context", {})
        result = await execute_action_step(step, context, mock=mock)
        results = list(state.get("step_results", []))
        results.append(result)
        return {
            "current_step_id": step.id,
            "step_results": results,
            "status": "running",
        }

    async def _decision_node(state: PlaybookExecutionState) -> dict[str, Any]:
        assert isinstance(step, DecisionStep)
        context = state.get("context", {})
        result = await execute_decision_step(step, context)
        results = list(state.get("step_results", []))
        results.append(result)
        return {
            "current_step_id": step.id,
            "step_results": results,
            "status": "running",
        }

    async def _hitl_node(state: PlaybookExecutionState) -> dict[str, Any]:
        assert isinstance(step, HITLGateStep)
        context = state.get("context", {})
        result = await execute_hitl_gate_step(step, context, mock=mock)
        results = list(state.get("step_results", []))
        results.append(result)
        approved = result.get("output", {}).get("approved", False)
        return {
            "current_step_id": step.id,
            "step_results": results,
            "status": "running" if approved else "paused_hitl",
            "hitl_pending": not approved and not mock,
            "hitl_prompt": step.prompt,
        }

    async def _parallel_node(state: PlaybookExecutionState) -> dict[str, Any]:
        assert isinstance(step, ParallelForkStep)
        context = state.get("context", {})
        result = await execute_parallel_fork_step(step, context)
        results = list(state.get("step_results", []))
        results.append(result)
        return {
            "current_step_id": step.id,
            "step_results": results,
            "status": "running",
        }

    async def _end_node(state: PlaybookExecutionState) -> dict[str, Any]:
        return {
            "current_step_id": step.id,
            "status": "completed",
        }

    async def _passthrough_node(state: PlaybookExecutionState) -> dict[str, Any]:
        return {
            "current_step_id": step.id,
            "status": "running",
        }

    if step.type == StepType.ACTION and isinstance(step, ActionStep):
        _action_node.__name__ = f"action_{step.id}"
        return _action_node
    elif step.type == StepType.DECISION and isinstance(step, DecisionStep):
        _decision_node.__name__ = f"decision_{step.id}"
        return _decision_node
    elif step.type == StepType.HITL_GATE and isinstance(step, HITLGateStep):
        _hitl_node.__name__ = f"hitl_{step.id}"
        return _hitl_node
    elif step.type == StepType.PARALLEL_FORK and isinstance(step, ParallelForkStep):
        _parallel_node.__name__ = f"parallel_{step.id}"
        return _parallel_node
    elif step.type == StepType.END:
        _end_node.__name__ = f"end_{step.id}"
        return _end_node
    else:
        _passthrough_node.__name__ = f"passthrough_{step.id}"
        return _passthrough_node


def _make_decision_router(
    step: DecisionStep,
    step_map: dict[str, PlaybookStep],
) -> Any:
    """Create a conditional routing function for a decision step."""

    def _router(state: PlaybookExecutionState) -> str:
        # Get the last step result which should be from this decision step
        results = state.get("step_results", [])
        for result in reversed(results):
            if result.get("step_id") == step.id:
                next_step = result.get("next_step")
                if next_step and next_step in step_map:
                    return next_step
                break

        # Fallback: evaluate condition from context
        from btagent_agents.playbook.steps.decision import evaluate_condition

        context = state.get("context", {})
        cond_result = evaluate_condition(step.condition, context)
        chosen = step.true_branch if cond_result else step.false_branch

        if chosen and chosen in step_map:
            return chosen
        return END

    _router.__name__ = f"router_{step.id}"
    return _router
