"""Root StateGraph construction for the BTagent investigation orchestrator."""

from __future__ import annotations

from typing import Any

from btagent_shared.types.enums import InvestigationStatus
from langchain_core.messages import AIMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph as CompiledGraph

from btagent_agents.orchestrator.edges import after_hitl, route_to_agent, should_continue
from btagent_agents.orchestrator.nodes import (
    coordination_node,
    enrich_node,
    hitl_checkpoint_node,
    mitigation_node,
    query_node,
    report_node,
    route_task,
    synthesize_node,
    triage_node,
)
from btagent_agents.orchestrator.state import InvestigationState

# ---------------------------------------------------------------------------
# Agent nodes: enrich + report delegate to their plugins; contain is the
# remaining phase-2 placeholder (automated containment execution).
# ---------------------------------------------------------------------------


def _enrich_node(state: InvestigationState) -> dict[str, Any]:
    """Delegate to the Enrichment plugin via nodes.enrich_node.

    Fans the investigation's IOCs out to the CTI sources (VirusTotal, Shodan,
    GreyNoise, AbuseIPDB, MISP) through the enrichment plugin's ``bulk_enrich``
    tool and merges the verdicts + confidence back onto each IOC.
    """
    return enrich_node(state)


def _contain_node(state: InvestigationState) -> dict[str, Any]:
    """Placeholder: containment execution agent (phase 2).

    Will execute approved containment actions via EDR/firewall MCP connectors.
    """
    return {
        "messages": [
            AIMessage(
                content=(
                    "**Contain Agent** (placeholder)\n"
                    "Automated containment execution is not yet implemented. "
                    "Please execute containment actions manually."
                )
            )
        ],
        "current_agent": "contain",
        "status": InvestigationStatus.INVESTIGATING,
    }


def _report_node(state: InvestigationState) -> dict[str, Any]:
    """Delegate to the ReportAgent subgraph via nodes.report_node."""
    return report_node(state)


# ---------------------------------------------------------------------------
# Execute node (runs approved containment actions)
# ---------------------------------------------------------------------------


def _execute_containment_node(state: InvestigationState) -> dict[str, Any]:
    """Execute approved containment actions.

    Phase-1 placeholder: marks actions as completed without actually executing.
    Phase 2 will call EDR/firewall MCP tools.
    """
    containment_actions: list[dict] = list(state.get("containment_actions", []))
    executed: list[str] = []

    updated_actions: list[dict] = []
    for action in containment_actions:
        action_copy = dict(action)
        if action_copy.get("status") == "approved":
            # Phase 1: mark as completed (no real execution).
            action_copy["status"] = "completed"
            executed.append(
                f"{action_copy.get('action_type', '?')} on {action_copy.get('target', '?')}"
            )
        updated_actions.append(action_copy)

    if executed:
        summary = "\n".join(f"  - {e}" for e in executed)
        msg = (
            f"**Containment Execution** (placeholder)\n"
            f"Marked {len(executed)} action(s) as completed:\n{summary}\n\n"
            f"Note: actual execution will be implemented in phase 2."
        )
    else:
        msg = "**Containment Execution**: No approved actions to execute."

    return {
        "messages": [AIMessage(content=msg)],
        "containment_actions": updated_actions,
        "current_agent": "execute",
        "status": InvestigationStatus.CONTAINED if executed else InvestigationStatus.INVESTIGATING,
    }


# ---------------------------------------------------------------------------
# Graph factory
# ---------------------------------------------------------------------------


def create_investigation_graph(config: dict[str, Any] | None = None) -> CompiledGraph:
    """Build and compile the root investigation StateGraph.

    Parameters
    ----------
    config : dict, optional
        Runtime configuration dict.  Currently used for:
        - ``checkpointer``: pass a custom checkpointer (e.g. ``PostgresSaver``
          for production).  Defaults to ``MemorySaver``.

    Returns
    -------
    CompiledGraph
        A compiled LangGraph ready for invocation via ``.invoke()`` or
        ``.stream()``.
    """
    config = config or {}
    max_steps = config.get("max_steps", 50)

    graph = StateGraph(InvestigationState)

    # --- Register nodes ---
    graph.add_node("route_task", route_task)
    graph.add_node("triage", triage_node)
    graph.add_node("query", query_node)
    graph.add_node("enrich", _enrich_node)
    graph.add_node("contain", _contain_node)
    graph.add_node("report", _report_node)
    graph.add_node("coordination", coordination_node)
    graph.add_node("mitigation", mitigation_node)
    graph.add_node("synthesize", synthesize_node)
    graph.add_node("hitl_checkpoint", hitl_checkpoint_node)
    graph.add_node("execute", _execute_containment_node)

    # --- Entry point ---
    graph.set_entry_point("route_task")

    # --- Conditional edges from route_task ---
    graph.add_conditional_edges(
        "route_task",
        route_to_agent,
        {
            "triage": "triage",
            "query": "query",
            "enrich": "enrich",
            "contain": "contain",
            "report": "report",
            "coordination": "coordination",
            "mitigation": "mitigation",
            "synthesize": "synthesize",
        },
    )

    # --- Worker → synthesize edges ---
    graph.add_edge("triage", "synthesize")
    graph.add_edge("query", "synthesize")
    graph.add_edge("enrich", "synthesize")
    graph.add_edge("contain", "synthesize")
    graph.add_edge("report", "synthesize")
    graph.add_edge("coordination", "synthesize")
    graph.add_edge("mitigation", "synthesize")

    # --- Conditional edges from synthesize ---
    graph.add_conditional_edges(
        "synthesize",
        should_continue,
        {
            "continue": "route_task",
            "knowledge": "route_task",
            "hitl": "hitl_checkpoint",
            END: END,
        },
    )

    # --- HITL checkpoint → conditional routing ---
    graph.add_conditional_edges(
        "hitl_checkpoint",
        after_hitl,
        {
            "execute": "execute",
            "synthesize": "synthesize",
        },
    )

    # --- Execute → synthesize ---
    graph.add_edge("execute", "synthesize")

    # --- Checkpointing ---
    checkpointer = config.get("checkpointer") or MemorySaver()

    # SEC-005 FIX: Store max_steps in config for enforcement at invoke() time.
    # LangGraph enforces recursion_limit via invoke(config={"recursion_limit": N}),
    # not at compile time. The TaskManager passes this when calling graph.ainvoke().
    compiled = graph.compile(
        checkpointer=checkpointer,
        interrupt_before=["hitl_checkpoint"],
    )
    # Attach max_steps so TaskManager can read it
    compiled.max_steps = max_steps  # type: ignore[attr-defined]
    return compiled
