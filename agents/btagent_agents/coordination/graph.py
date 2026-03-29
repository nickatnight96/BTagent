"""LangGraph subgraph for coordination / summarization pipeline.

Pipeline: collect_data -> summarize -> format -> review -> END

Synthesizes multiple investigation reports into agency-ready summaries.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, TypedDict

from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph as CompiledGraph

from btagent_agents.plugins.coordination.tools.summarizer import (
    format_agency_report as _format_tool,
)
from btagent_agents.plugins.coordination.tools.summarizer import (
    summarize_investigation as _summarize_tool,
)
from btagent_agents.plugins.coordination.tools.summarizer import (
    summarize_multiple as _summarize_multiple_tool,
)

# --------------------------------------------------------------------------- #
# State definition
# --------------------------------------------------------------------------- #


def _merge_lists(left: list, right: list) -> list:
    """Reducer that appends new items to existing list."""
    return left + right


class CoordinationState(TypedDict):
    """State for the coordination subgraph pipeline.

    Fields
    ------
    investigation_ids : list[str]
        Investigation IDs to summarize.
    target_format : str
        Target agency format (cisa, fbi_ic3, isac, generic).
    raw_data : list[dict]
        Collected investigation data before summarization.
    summary : dict
        Summarized output from map-reduce.
    formatted_report : dict
        Agency-formatted report sections.
    review_notes : list[str]
        Quality review notes.
    errors : list[str]
        Any errors encountered during processing.
    status : str
        Pipeline status.
    """

    investigation_ids: list[str]
    target_format: str
    raw_data: list[dict]
    summary: dict
    formatted_report: dict
    review_notes: list[str]
    errors: Annotated[list[str], _merge_lists]
    status: str


# --------------------------------------------------------------------------- #
# Node implementations
# --------------------------------------------------------------------------- #


def collect_data(state: CoordinationState) -> dict[str, Any]:
    """Collect and validate investigation data for summarization."""
    investigation_ids = state.get("investigation_ids", [])
    errors: list[str] = []

    if not investigation_ids:
        errors.append("No investigation IDs provided")
        return {"errors": errors, "status": "failed"}

    # Store IDs as raw data references for the summarize step
    raw_data = [{"investigation_id": inv_id} for inv_id in investigation_ids]

    return {
        "raw_data": raw_data,
        "errors": errors,
        "status": "summarizing",
    }


def summarize(state: CoordinationState) -> dict[str, Any]:
    """Summarize investigations using map-reduce pattern."""
    investigation_ids = state.get("investigation_ids", [])
    errors: list[str] = []

    if len(investigation_ids) == 1:
        # Single investigation: use direct summarization
        result = _summarize_tool.invoke({"investigation_id": investigation_ids[0]})
    else:
        # Multiple investigations: use map-reduce aggregation
        ids_str = ",".join(investigation_ids)
        result = _summarize_multiple_tool.invoke({"investigation_ids": ids_str})

    if result.get("status") == "failed":
        errors.append(result.get("error", "Summarization failed"))
        return {"errors": errors, "status": "failed"}

    return {
        "summary": result,
        "errors": errors,
        "status": "formatting",
    }


def format_report(state: CoordinationState) -> dict[str, Any]:
    """Format summary for target agency."""
    summary = state.get("summary", {})
    target_format = state.get("target_format", "generic")
    errors: list[str] = []

    summary_json = json.dumps(summary)
    result = _format_tool.invoke({"summary_json": summary_json, "format": target_format})

    if result.get("status") == "failed":
        errors.append(result.get("error", "Formatting failed"))
        return {"errors": errors, "status": "failed"}

    return {
        "formatted_report": result,
        "errors": errors,
        "status": "reviewing",
    }


def review(state: CoordinationState) -> dict[str, Any]:
    """Quality review of the formatted report.

    Checks for completeness, consistency, and agency-specific requirements.
    """
    formatted_report = state.get("formatted_report", {})
    summary = state.get("summary", {})
    review_notes: list[str] = []

    # Check that we have sections
    sections = formatted_report.get("sections", {})
    if not sections:
        review_notes.append("WARNING: No report sections generated")

    # Check IOC count
    ioc_count = summary.get("ioc_count") or summary.get("aggregated_ioc_count", 0)
    if ioc_count == 0:
        review_notes.append("NOTE: No IOCs included in report")

    # Check recommendations
    recommendations = summary.get("recommendations", [])
    if not recommendations:
        review_notes.append("NOTE: No recommendations generated")
    elif len(recommendations) < 3:
        review_notes.append(
            f"NOTE: Only {len(recommendations)} recommendation(s) — "
            "consider adding more specific guidance"
        )

    # Check MITRE techniques
    techniques = summary.get("mitre_techniques", [])
    if not techniques:
        review_notes.append("NOTE: No MITRE ATT&CK techniques mapped")

    if not review_notes:
        review_notes.append("PASS: Report passes quality checks")

    return {
        "review_notes": review_notes,
        "status": "complete",
    }


# --------------------------------------------------------------------------- #
# Graph factory
# --------------------------------------------------------------------------- #


def create_coordination_graph(
    config: dict[str, Any] | None = None,
) -> CompiledGraph:
    """Build and compile the coordination subgraph.

    Pipeline:
        collect_data -> summarize -> format -> review -> END

    Parameters
    ----------
    config : dict, optional
        Runtime configuration. Reserved for future options.

    Returns
    -------
    CompiledGraph
        A compiled LangGraph ready for invocation.
    """
    graph = StateGraph(CoordinationState)

    # Register nodes
    graph.add_node("collect_data", collect_data)
    graph.add_node("summarize", summarize)
    graph.add_node("format", format_report)
    graph.add_node("review", review)

    # Define edges: linear pipeline
    graph.set_entry_point("collect_data")
    graph.add_edge("collect_data", "summarize")
    graph.add_edge("summarize", "format")
    graph.add_edge("format", "review")
    graph.add_edge("review", END)

    return graph.compile()
