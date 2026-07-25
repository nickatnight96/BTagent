"""Conditional edge functions for the BTagent investigation LangGraph."""

from __future__ import annotations

from btagent_shared.types.enums import ContainmentStatus, InvestigationStatus
from langgraph.graph import END

from btagent_agents.orchestrator.state import InvestigationState

# Valid agent node names in the graph.
_AGENT_NODES = frozenset(
    {
        "triage",
        "query",
        "enrich",
        "contain",
        "report",
        "coordination",
        "mitigation",
        "synthesize",
    }
)


def route_to_agent(state: InvestigationState) -> str:
    """Return the target node name based on the classified task type.

    Called as a conditional edge from ``route_task``.  Maps the ``task_type``
    field to the corresponding agent node.  Unmapped types fall through to
    ``synthesize`` so the graph never dead-ends.

    Returns
    -------
    str
        Node name: ``"triage"``, ``"query"``, ``"enrich"``, ``"contain"``,
        ``"report"``, ``"coordination"``, ``"mitigation"``, or ``"synthesize"``.
    """
    task_type = state.get("task_type", "general")

    routing_map: dict[str, str] = {
        "triage": "triage",
        "query": "query",
        "enrich": "enrich",
        "contain": "contain",
        "report": "report",
        "coordination": "coordination",
        "mitigation": "mitigation",
        "general": "synthesize",
    }

    target = routing_map.get(task_type, "synthesize")

    # Safety: if the target is not a registered node, go to synthesize.
    if target not in _AGENT_NODES:
        return "synthesize"

    return target


def should_continue(state: InvestigationState) -> str:
    """Decide what happens after the synthesize node.

    Returns
    -------
    str
        ``"continue"`` — re-enter ``route_task`` for the next step.
        ``"hitl"``     — pause for human-in-the-loop approval.
        ``END``        — investigation step is complete; graph finishes.
    """
    status = state.get("status", "")
    containment_actions: list[dict] = state.get("containment_actions", [])

    # If the investigation is paused waiting for human approval, go to HITL.
    if status == InvestigationStatus.PAUSED_HITL:
        return "hitl"

    # Check for any pending containment actions that need approval.
    pending = [a for a in containment_actions if a.get("status") == ContainmentStatus.PROPOSED]
    if pending:
        return "hitl"

    # If the investigation has a terminal status, end.
    terminal_statuses = {
        InvestigationStatus.CLOSED,
        InvestigationStatus.REMEDIATED,
        InvestigationStatus.CONTAINED,
        InvestigationStatus.FAILED,
        InvestigationStatus.CANCELLED,
    }
    if status in terminal_statuses:
        return END

    # Enrichment hand-off (GH #388): a high/critical triage with IOCs advances
    # to enrichment. ``synthesize_node`` signals this by setting
    # ``task_type="enrich"`` AND marking ``current_agent="enrich"`` as the
    # *pending* target (before the enrich node has actually run). We route once
    # back through ``route_task``, which honors the advanced task_type and goes
    # straight to enrichment.
    #
    # This cannot loop: after the enrich node runs and re-enters synthesize,
    # ``current_agent`` becomes "synthesize" again and the IOCs carry an
    # ``enrichment`` key, so neither guard below holds and we fall through to
    # END. The ``not already_enriched`` guard additionally prevents re-issuing
    # "continue" for a message whose IOCs were already enriched.
    iocs: list[dict] = state.get("iocs", [])
    task_type = state.get("task_type", "")
    current_agent = state.get("current_agent", "")
    already_enriched = any("enrichment" in ioc for ioc in iocs)

    if (
        status == InvestigationStatus.INVESTIGATING
        and task_type == "enrich"
        and current_agent == "enrich"
        and iocs
        and not already_enriched
    ):
        return "continue"

    # After enrichment, if knowledge base has content (indicated by
    # knowledge_context field), route to knowledge retrieval for
    # additional context before closing.
    knowledge_context = state.get("knowledge_context", "")
    if status == InvestigationStatus.INVESTIGATING and task_type == "enrich" and knowledge_context:
        return "knowledge"

    # Default: end the current graph run.  The analyst can send another message
    # to resume the investigation (new graph invocation).
    return END


def after_hitl(state: InvestigationState) -> str:
    """Route after a human-in-the-loop checkpoint response.

    Returns
    -------
    str
        ``"execute"``    — human approved; proceed with containment execution.
        ``"synthesize"`` — human rejected; go back to synthesis.
    """
    containment_actions: list[dict] = state.get("containment_actions", [])

    # Check if any actions were approved (HITL checkpoint node updates status).
    has_approved = any(a.get("status") == ContainmentStatus.APPROVED for a in containment_actions)

    if has_approved:
        return "execute"

    return "synthesize"
