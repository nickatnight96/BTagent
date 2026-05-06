"""Integration test: prove the HITL gate actually pauses LangGraph.

Audit finding (Phase 0): the HITL hook raises ``HITLInterrupt`` from
``HITLCallback.on_tool_start`` (see ``hitl_hook.py:149-181``), but it was not
verified end-to-end that LangGraph's pause mechanism actually catches it and
returns control to the caller — versus letting the exception propagate and
crash the graph run.

Investigation result
--------------------
The orchestrator at ``btagent_agents/orchestrator/graph.py`` does NOT rely on
the ``HITLInterrupt`` exception for pausing. It uses LangGraph's native
declarative ``interrupt_before=["hitl_checkpoint"]`` config (graph.py:219).
The exception class is currently dead code — defined and raised by the
callback, but never caught by anything in the codebase.

This test therefore exercises the *real* HITL pause mechanism wired by the
orchestrator: a small StateGraph compiled with ``interrupt_before`` on a
``hitl_checkpoint`` node, using the same state schema fields the production
graph uses (``status``, ``containment_actions``, ``messages``).

It asserts:
  1. Triggering the HITL gate does NOT raise / crash — control returns to the
     caller cleanly.
  2. The checkpoint records the graph as paused before the HITL node
     (``state.next == ("hitl_checkpoint",)``) with a resumable thread.
  3. ``invoke(None, config)`` after injecting the human's response resumes
     the graph past the gate to completion.

It also covers the callback path in isolation to confirm
``requires_approval`` / ``HITLInterrupt`` behave as the docstring claims.
"""

from __future__ import annotations

from typing import Annotated, Any, TypedDict

import pytest
from btagent_shared.types.config import AutonomyLevel, IntegrationAutonomy
from btagent_shared.types.enums import ContainmentStatus, InvestigationStatus
from langchain_core.messages import AIMessage, AnyMessage, HumanMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages

from btagent_agents.hooks.hitl_hook import (
    HITLCallback,
    HITLInterrupt,
    requires_approval,
)

# ---------------------------------------------------------------------------
# Minimal state mirroring the fields the real ``hitl_checkpoint_node`` reads
# ---------------------------------------------------------------------------


class _MiniState(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]
    status: str
    containment_actions: list[dict]


# ---------------------------------------------------------------------------
# Nodes — shaped like the orchestrator's: a worker proposes containment, then
# a synthesize node decides whether to route to the hitl_checkpoint node.
# ---------------------------------------------------------------------------


def _propose_action_node(state: _MiniState) -> dict[str, Any]:
    """Worker proposes a containment action that needs approval."""
    return {
        "messages": [AIMessage(content="Proposing host isolation on host-42")],
        "status": InvestigationStatus.PAUSED_HITL,
        "containment_actions": [
            {
                "id": "act_1",
                "action_type": "host_isolation",
                "target": "host-42",
                "status": ContainmentStatus.PROPOSED,
            }
        ],
    }


def _hitl_checkpoint_node(state: _MiniState) -> dict[str, Any]:
    """Mirror of ``orchestrator.nodes.hitl_checkpoint_node`` — only runs after
    the human resumes the graph. Reads the latest HumanMessage as the verdict.
    """
    approved = False
    for msg in reversed(state.get("messages", [])):
        if isinstance(msg, HumanMessage):
            approved = "approve" in (msg.content or "").lower()
            break

    updated: list[dict] = []
    for action in state.get("containment_actions", []):
        action_copy = dict(action)
        if action_copy.get("status") == ContainmentStatus.PROPOSED:
            action_copy["status"] = (
                ContainmentStatus.APPROVED if approved else ContainmentStatus.REJECTED
            )
        updated.append(action_copy)

    return {
        "messages": [AIMessage(content=f"HITL response: approved={approved}")],
        "status": InvestigationStatus.INVESTIGATING,
        "containment_actions": updated,
    }


def _execute_node(state: _MiniState) -> dict[str, Any]:
    """Final node that only runs after the gate has been resumed."""
    return {
        "messages": [AIMessage(content="Containment executed")],
        "status": InvestigationStatus.CONTAINED,
    }


def _build_graph() -> Any:
    """Compile a StateGraph that mirrors the orchestrator's HITL wiring."""
    graph = StateGraph(_MiniState)
    graph.add_node("propose", _propose_action_node)
    graph.add_node("hitl_checkpoint", _hitl_checkpoint_node)
    graph.add_node("execute", _execute_node)
    graph.set_entry_point("propose")
    graph.add_edge("propose", "hitl_checkpoint")
    graph.add_edge("hitl_checkpoint", "execute")
    graph.add_edge("execute", END)
    return graph.compile(
        checkpointer=MemorySaver(),
        interrupt_before=["hitl_checkpoint"],
    )


# ---------------------------------------------------------------------------
# Tests — orchestrator-style interrupt_before pause + resume
# ---------------------------------------------------------------------------


async def test_hitl_gate_pauses_graph_without_raising() -> None:
    """Invoking the graph must not raise; it should return after the worker
    node and report ``hitl_checkpoint`` as the next node to execute."""
    compiled = _build_graph()
    config = {"configurable": {"thread_id": "inv_test_pause"}}

    initial: _MiniState = {
        "messages": [HumanMessage(content="please contain host-42")],
        "status": InvestigationStatus.INVESTIGATING,
        "containment_actions": [],
    }

    # Must not raise — the whole point of interrupt_before is graceful pause.
    result = await compiled.ainvoke(initial, config=config)

    # The propose node ran; the gate node did NOT run yet.
    assert result["status"] == InvestigationStatus.PAUSED_HITL
    assert any(a["status"] == ContainmentStatus.PROPOSED for a in result["containment_actions"]), (
        "expected the propose node to record a PROPOSED containment action"
    )
    assert not any(
        isinstance(m, AIMessage) and "HITL response" in (m.content or "")
        for m in result["messages"]
    ), "hitl_checkpoint node must NOT have run yet — interrupt_before should pause"

    # The checkpoint must record the graph as paused before hitl_checkpoint.
    snapshot = await compiled.aget_state(config)
    assert snapshot.next == ("hitl_checkpoint",), (
        f"graph should be paused at hitl_checkpoint, got next={snapshot.next}"
    )


async def test_hitl_gate_resumes_with_approval() -> None:
    """After injecting the human's approval into the checkpoint, invoking with
    ``None`` must resume the graph past the gate to completion."""
    compiled = _build_graph()
    config = {"configurable": {"thread_id": "inv_test_resume_ok"}}

    await compiled.ainvoke(
        {
            "messages": [HumanMessage(content="please contain host-42")],
            "status": InvestigationStatus.INVESTIGATING,
            "containment_actions": [],
        },
        config=config,
    )

    # Inject the analyst's approval into the paused checkpoint.
    await compiled.aupdate_state(config, {"messages": [HumanMessage(content="approve")]})

    # Resume — passing None tells LangGraph to continue from the checkpoint.
    final = await compiled.ainvoke(None, config=config)

    # Gate ran, action was approved, execute node ran to completion.
    assert any(
        isinstance(m, AIMessage) and "HITL response: approved=True" in (m.content or "")
        for m in final["messages"]
    ), "hitl_checkpoint node should have processed the approval"
    assert any(
        isinstance(m, AIMessage) and "Containment executed" in (m.content or "")
        for m in final["messages"]
    ), "execute node should have run after approval"
    assert final["status"] == InvestigationStatus.CONTAINED
    assert all(a["status"] == ContainmentStatus.APPROVED for a in final["containment_actions"])

    # And the graph is fully done — no further nodes pending.
    snapshot = await compiled.aget_state(config)
    assert snapshot.next == (), f"expected graph completed, got next={snapshot.next}"


async def test_hitl_gate_resumes_with_rejection() -> None:
    """A non-approval response still resumes the graph; the action is marked
    rejected and the run completes (does NOT hang or crash)."""
    compiled = _build_graph()
    config = {"configurable": {"thread_id": "inv_test_resume_reject"}}

    await compiled.ainvoke(
        {
            "messages": [HumanMessage(content="please contain host-42")],
            "status": InvestigationStatus.INVESTIGATING,
            "containment_actions": [],
        },
        config=config,
    )

    await compiled.aupdate_state(config, {"messages": [HumanMessage(content="deny")]})

    final = await compiled.ainvoke(None, config=config)

    assert all(a["status"] == ContainmentStatus.REJECTED for a in final["containment_actions"])
    snapshot = await compiled.aget_state(config)
    assert snapshot.next == ()


# ---------------------------------------------------------------------------
# Tests — the callback-based ``HITLInterrupt`` path (the audit's literal scope)
# ---------------------------------------------------------------------------


def test_requires_approval_policy_matches_docstring() -> None:
    """Sanity check on the autonomy policy used by the callback — without
    this, the callback can never decide to raise."""
    integ = IntegrationAutonomy()  # defaults

    # L0_MANUAL — everything requires approval.
    assert requires_approval("siem_query", AutonomyLevel.L0_MANUAL, integ) is True
    assert requires_approval("isolate_host", AutonomyLevel.L0_MANUAL, integ) is True

    # High-risk action under L2 supervised should still need approval given
    # the default IntegrationAutonomy values.
    assert requires_approval("isolate_host", AutonomyLevel.L2_SUPERVISED, integ) is True


class _RecordingEmitter:
    """Stand-in for ``RedisEmitter`` — just records emitted events."""

    def __init__(self) -> None:
        self.events: list[tuple[Any, dict[str, Any]]] = []

    async def emit(self, event_type: Any, **payload: Any) -> None:
        self.events.append((event_type, payload))


async def test_hitl_callback_raises_hitlinterrupt_for_high_risk_tool() -> None:
    """The callback's documented contract: when a tool requires approval,
    ``on_tool_start`` raises ``HITLInterrupt`` AFTER emitting an event.

    The orchestrator does not wire this exception path today (it uses
    ``interrupt_before`` instead), but the contract must hold so any future
    consumer that catches ``HITLInterrupt`` gets the documented behaviour.
    """
    from uuid import uuid4

    emitter = _RecordingEmitter()
    callback = HITLCallback(
        emitter=emitter,  # type: ignore[arg-type]
        agent_autonomy=AutonomyLevel.L0_MANUAL,
        integration_autonomy=IntegrationAutonomy(),
        investigation_id="inv_test",
    )

    with pytest.raises(HITLInterrupt) as exc_info:
        await callback.on_tool_start(
            serialized={"name": "isolate_host"},
            input_str="host=host-42",
            run_id=uuid4(),
        )

    err = exc_info.value
    assert err.tool_name == "isolate_host"
    assert err.checkpoint_id.startswith("cp_")
    # ``required_level`` is the tool's resolved autonomy level (host_isolation
    # defaults to L1_ASSISTED in IntegrationAutonomy), NOT the agent's level.
    assert err.required_level == AutonomyLevel.L1_ASSISTED
    # Event must have been emitted before the raise.
    assert len(emitter.events) == 1
    _event_type, payload = emitter.events[0]
    assert payload["tool_name"] == "isolate_host"
    assert payload["checkpoint_id"] == err.checkpoint_id


async def test_hitl_callback_passes_through_low_risk_tool() -> None:
    """When the policy does not require approval, the callback returns
    silently — no event, no exception."""
    from uuid import uuid4

    emitter = _RecordingEmitter()
    callback = HITLCallback(
        emitter=emitter,  # type: ignore[arg-type]
        agent_autonomy=AutonomyLevel.L4_FULL_AUTO,
        integration_autonomy=IntegrationAutonomy(),
        investigation_id="inv_test",
    )

    # Returns None without raising for an unmapped, low-risk tool.
    result = await callback.on_tool_start(
        serialized={"name": "echo_tool"},
        input_str="hello",
        run_id=uuid4(),
    )
    assert result is None
    assert emitter.events == []
