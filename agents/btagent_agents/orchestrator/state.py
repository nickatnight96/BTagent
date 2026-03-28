"""Investigation state schema for the LangGraph orchestrator."""

from __future__ import annotations

from typing import Annotated, TypedDict

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages


class InvestigationState(TypedDict):
    """Root state for the BTagent investigation graph.

    Every node reads and returns a partial dict of this shape.  LangGraph merges
    the returned keys into the running state using the annotated reducers (e.g.
    ``add_messages`` for the ``messages`` list).

    Fields
    ------
    investigation_id : str
        Prefixed ULID (``inv_...``) that uniquely identifies this investigation.
    messages : list[AnyMessage]
        Conversation history.  Uses ``add_messages`` reducer so nodes can append
        without replacing the full list.
    task_type : str
        Current task classification — one of ``"triage"``, ``"query"``,
        ``"enrich"``, ``"contain"``, ``"report"``, or ``"general"``.
    severity : str
        Current assessed severity (``critical`` / ``high`` / ``medium`` /
        ``low`` / ``info``).
    tlp_level : str
        Traffic Light Protocol level governing data-sharing constraints.
    autonomy_level : str
        Human-in-the-loop autonomy level (L0 .. L4).
    iocs : list[dict]
        Indicators of Compromise discovered during investigation.
    timeline : list[dict]
        Chronological events assembled from triage / enrichment.
    containment_actions : list[dict]
        Proposed or executed containment actions.
    evidence : list[dict]
        Evidence artifacts collected during investigation.
    current_agent : str
        Name of the agent node currently executing or last executed.
    status : str
        Overall investigation status (maps to ``InvestigationStatus``).
    error : str | None
        Last error message, or ``None`` when healthy.
    org_profile : dict
        Admin-configured organisation context (industry, products, etc.).
    template_config : dict
        Investigation template workflow configuration.
    token_usage : dict
        Running token counts keyed by model name.
    cost_usd : float
        Running monetary cost of LLM calls.
    knowledge_context : str
        Retrieved knowledge base context injected by the knowledge injector.
        Populated after enrichment when the knowledge base has relevant content.
    """

    investigation_id: str
    messages: Annotated[list[AnyMessage], add_messages]
    task_type: str
    severity: str
    tlp_level: str
    autonomy_level: str
    iocs: list[dict]
    timeline: list[dict]
    containment_actions: list[dict]
    evidence: list[dict]
    current_agent: str
    status: str
    error: str | None
    org_profile: dict
    template_config: dict
    token_usage: dict
    cost_usd: float
    knowledge_context: str
