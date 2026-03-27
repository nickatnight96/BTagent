"""Root StateGraph construction for the BTagent investigation orchestrator."""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph as CompiledGraph

from btagent_shared.types.enums import InvestigationStatus

from btagent_agents.orchestrator.edges import after_hitl, route_to_agent, should_continue
from btagent_agents.orchestrator.nodes import (
    hitl_checkpoint_node,
    query_node,
    route_task,
    synthesize_node,
    triage_node,
)
from btagent_agents.orchestrator.state import InvestigationState


# ---------------------------------------------------------------------------
# Placeholder nodes for phase-2 agents (enrich, contain, report)
# ---------------------------------------------------------------------------


def _enrich_node(state: InvestigationState) -> dict[str, Any]:
    """Placeholder: IOC enrichment agent (phase 2).

    Will call CTI tools (VirusTotal, OTX, MISP, Shodan) via MCP.
    """
    return {
        "messages": [
            AIMessage(
                content=(
                    "**Enrich Agent** (placeholder)\n"
                    "IOC enrichment is not yet implemented. "
                    "IOCs have been recorded and are available for manual lookup."
                )
            )
        ],
        "current_agent": "enrich",
        "status": InvestigationStatus.INVESTIGATING,
    }


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
    """Placeholder: report generation agent (phase 2).

    Will compile investigation findings into structured reports.
    """
    iocs = state.get("iocs", [])
    timeline = state.get("timeline", [])
    severity = state.get("severity", "medium")
    containment_actions = state.get("containment_actions", [])

    # Build a basic summary from available state even though LLM drafting
    # is not wired up yet.
    lines = [
        "**Investigation Report** (auto-generated summary)\n",
        f"- Severity: {severity}",
        f"- IOCs discovered: {len(iocs)}",
        f"- Timeline entries: {len(timeline)}",
        f"- Containment actions: {len(containment_actions)}",
    ]

    if iocs:
        lines.append("\n**IOC Summary:**")
        for ioc in iocs[:10]:  # Cap at 10 for readability
            lines.append(f"  - [{ioc.get('type', '?')}] {ioc.get('value', '?')}")
        if len(iocs) > 10:
            lines.append(f"  ... and {len(iocs) - 10} more")

    if timeline:
        lines.append("\n**Timeline:**")
        for entry in timeline[-5:]:  # Most recent 5
            lines.append(
                f"  - {entry.get('timestamp', '?')}: {entry.get('description', '?')}"
            )

    return {
        "messages": [AIMessage(content="\n".join(lines))],
        "current_agent": "report",
        "status": InvestigationStatus.INVESTIGATING,
    }


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

    graph = StateGraph(InvestigationState)

    # --- Register nodes ---
    graph.add_node("route_task", route_task)
    graph.add_node("triage", triage_node)
    graph.add_node("query", query_node)
    graph.add_node("enrich", _enrich_node)
    graph.add_node("contain", _contain_node)
    graph.add_node("report", _report_node)
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
            "synthesize": "synthesize",
        },
    )

    # --- Worker → synthesize edges ---
    graph.add_edge("triage", "synthesize")
    graph.add_edge("query", "synthesize")
    graph.add_edge("enrich", "synthesize")
    graph.add_edge("contain", "synthesize")
    graph.add_edge("report", "synthesize")

    # --- Conditional edges from synthesize ---
    graph.add_conditional_edges(
        "synthesize",
        should_continue,
        {
            "continue": "route_task",
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

    return graph.compile(
        checkpointer=checkpointer,
        interrupt_before=["hitl_checkpoint"],
    )
