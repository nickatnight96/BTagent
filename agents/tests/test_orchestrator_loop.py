"""Regression tests for the orchestrator triage->enrich self-loop (GH #388).

Before the fix, a high/critical triage with >=1 IOC caused
``synthesize_node`` to keep status INVESTIGATING and ``should_continue`` to
return "continue", which routed back into ``route_task``. ``route_task``
re-classified the *same unchanged* human message as "triage" again, re-entered
the triage node, and the identical condition held every iteration — spinning
until LangGraph raised ``GraphRecursionError``. The graph never advanced to
enrichment, failing exactly the highest-value case (critical alert + IOCs).

The fix advances explicitly to the enrichment stage and guards
``should_continue`` against re-issuing "continue" for an already-processed
message.
"""

from __future__ import annotations

import pytest
from btagent_shared.types.enums import ContainmentStatus, InvestigationStatus, Severity
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import END

from btagent_agents.orchestrator.edges import should_continue
from btagent_agents.orchestrator.graph import create_investigation_graph
from btagent_agents.orchestrator.nodes import route_task, synthesize_node

# A critical alert whose text also carries an IOC (a C2 IP + an MD5 hash).
_CRITICAL_ALERT = (
    "Triage this alert: CRITICAL ransomware active breach in progress. "
    "C2 beacon observed to 185.220.101.5 and dropper hash "
    "44d88612fea8a8f36de82e1278abb02f."
)


def _base_state() -> dict:
    return {
        "investigation_id": "inv_loop_test",
        "messages": [HumanMessage(content=_CRITICAL_ALERT)],
        "iocs": [],
        "timeline": [],
        "containment_actions": [],
        "evidence": [],
        "severity": Severity.MEDIUM,
        "status": InvestigationStatus.INVESTIGATING,
        "task_type": "",
        "current_agent": "",
    }


def test_critical_alert_with_ioc_advances_to_enrichment_and_terminates() -> None:
    """The full graph must reach enrichment and stop — not GraphRecursionError."""
    graph = create_investigation_graph()

    visited: list[str] = []
    config = {"configurable": {"thread_id": "loop-test"}, "recursion_limit": 25}

    try:
        for event in graph.stream(_base_state(), config=config, stream_mode="updates"):
            visited.extend(event.keys())
    except Exception as exc:  # pragma: no cover - fail loudly with context
        pytest.fail(f"graph did not terminate cleanly: {type(exc).__name__}: {exc}")

    # Triage must run exactly once (not on every loop iteration).
    assert visited.count("triage") == 1, f"triage ran {visited.count('triage')}x: {visited}"
    # The graph must have advanced to the enrichment stage.
    assert "enrich" in visited, f"never advanced to enrichment: {visited}"
    # And it must have terminated well within the recursion budget.
    assert len(visited) < 25, f"suspiciously long run (possible loop): {visited}"


def test_final_state_reflects_enrichment_stage() -> None:
    graph = create_investigation_graph()
    config = {"configurable": {"thread_id": "loop-final"}, "recursion_limit": 25}
    final = graph.invoke(_base_state(), config=config)

    assert final["task_type"] == "enrich"
    # An enrichment message must be present in the transcript.
    assert any(
        isinstance(m, AIMessage) and "Enrich Agent" in str(m.content) for m in final["messages"]
    ), "no enrichment output found in final transcript"


def test_should_continue_advances_pending_enrichment_once() -> None:
    """synthesize's pending-enrich marker yields exactly one 'continue'."""
    # State as synthesize leaves it right after a high/critical triage: it has
    # advanced task_type to 'enrich' and marked current_agent='enrich'.
    pending = {
        "status": InvestigationStatus.INVESTIGATING,
        "task_type": "enrich",
        "current_agent": "enrich",
        "severity": Severity.CRITICAL,
        "iocs": [{"type": "ip", "value": "185.220.101.5"}],
        "containment_actions": [],
    }
    assert should_continue(pending) == "continue"

    # After the enrich node runs and synthesize re-runs, current_agent is
    # "synthesize" again and the IOCs carry enrichment data -> must NOT continue.
    done = {
        **pending,
        "current_agent": "synthesize",
        "iocs": [{"type": "ip", "value": "185.220.101.5", "enrichment": {"malicious": True}}],
    }
    assert should_continue(done) == END


def test_should_continue_guard_blocks_already_enriched_iocs() -> None:
    """Even if the pending marker is stale, enriched IOCs must not re-continue."""
    state = {
        "status": InvestigationStatus.INVESTIGATING,
        "task_type": "enrich",
        "current_agent": "enrich",
        "severity": Severity.CRITICAL,
        "iocs": [{"type": "ip", "value": "1.2.3.4", "enrichment": {"malicious": False}}],
        "containment_actions": [],
    }
    assert should_continue(state) == END


def test_synthesize_emits_enrich_handoff_for_critical_triage() -> None:
    state = {
        "investigation_id": "inv_x",
        "task_type": "triage",
        "current_agent": "triage",
        "severity": Severity.CRITICAL,
        "iocs": [{"type": "ip", "value": "185.220.101.5"}],
        "containment_actions": [],
        "status": InvestigationStatus.INVESTIGATING,
    }
    out = synthesize_node(state)
    assert out["task_type"] == "enrich"
    assert out["current_agent"] == "enrich"
    assert out["status"] == InvestigationStatus.INVESTIGATING


def test_route_task_honors_handoff_without_reclassifying() -> None:
    """On an internal loop-back (last msg is an AIMessage) route_task must honor
    the advanced task_type rather than re-classifying the human message."""
    state = {
        "investigation_id": "inv_x",
        # Human message text says "triage" but the stage was already advanced.
        "messages": [
            HumanMessage(content="Triage this alert: ransomware, 185.220.101.5"),
            AIMessage(content="**Investigation Synthesis** advancing to enrichment"),
        ],
        "task_type": "enrich",
        "current_agent": "enrich",
    }
    out = route_task(state)
    assert out["task_type"] == "enrich"
    assert out["current_agent"] == "enrich"


def test_route_task_still_classifies_fresh_human_turn() -> None:
    """A fresh human turn (last message is Human) is still classified normally."""
    state = {
        "investigation_id": "inv_x",
        "messages": [HumanMessage(content="Please triage this new alert about an incident")],
        "task_type": "",
        "current_agent": "",
    }
    out = route_task(state)
    assert out["task_type"] == "triage"
    assert out["current_agent"] == "triage"
