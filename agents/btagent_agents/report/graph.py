"""LangGraph subgraph for report generation pipeline.

Pipeline: select_template -> gather_data -> generate_sections -> review_consistency -> compile -> END

Generates professional IR reports from investigation data using templates.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, TypedDict

from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph as CompiledGraph

from btagent_agents.plugins.report.tools.report_generator import (
    generate_report as _generate_report_tool,
)
from btagent_agents.plugins.report.tools.report_generator import (
    generate_section as _generate_section_tool,
)
from btagent_agents.plugins.report.tools.report_generator import (
    list_templates as _list_templates_tool,
)

# --------------------------------------------------------------------------- #
# State definition
# --------------------------------------------------------------------------- #


def _merge_lists(left: list, right: list) -> list:
    """Reducer that appends new items to existing list."""
    return left + right


class ReportState(TypedDict):
    """State for the report generation subgraph pipeline.

    Fields
    ------
    investigation_id : str
        Investigation to generate a report for.
    template_name : str
        Selected template name.
    template_config : dict
        Loaded template configuration.
    gathered_data : dict
        Investigation data gathered for the report.
    sections : dict
        Generated report sections.
    review_results : list[str]
        Consistency review findings.
    compiled_report : dict
        Final compiled report.
    errors : list[str]
        Any errors encountered during processing.
    status : str
        Pipeline status.
    """

    investigation_id: str
    template_name: str
    template_config: dict
    gathered_data: dict
    sections: dict
    review_results: list[str]
    compiled_report: dict
    errors: Annotated[list[str], _merge_lists]
    status: str


# --------------------------------------------------------------------------- #
# Node implementations
# --------------------------------------------------------------------------- #


def select_template(state: ReportState) -> dict[str, Any]:
    """Select and validate the report template."""
    template_name = state.get("template_name", "incident_report")
    errors: list[str] = []

    # List available templates to validate
    templates_result = _list_templates_tool.invoke({})
    available = [t["name"] for t in templates_result.get("templates", [])]

    if template_name not in available:
        errors.append(f"Template '{template_name}' not found. Available: {', '.join(available)}")
        return {"errors": errors, "status": "failed"}

    # Find the template config
    template_config = {}
    for tmpl in templates_result.get("templates", []):
        if tmpl["name"] == template_name:
            template_config = tmpl
            break

    return {
        "template_name": template_name,
        "template_config": template_config,
        "errors": errors,
        "status": "gathering_data",
    }


def gather_data(state: ReportState) -> dict[str, Any]:
    """Gather investigation data for report generation."""
    investigation_id = state.get("investigation_id", "")
    errors: list[str] = []

    if not investigation_id:
        errors.append("No investigation ID provided")
        return {"errors": errors, "status": "failed"}

    # Validate by generating the executive summary section
    test_result = _generate_section_tool.invoke(
        {
            "investigation_id": investigation_id,
            "section": "executive_summary",
        }
    )

    if test_result.get("status") == "failed":
        errors.append(test_result.get("error", "Failed to gather investigation data"))
        return {"errors": errors, "status": "failed"}

    return {
        "gathered_data": {"investigation_id": investigation_id, "validated": True},
        "errors": errors,
        "status": "generating_sections",
    }


def generate_sections(state: ReportState) -> dict[str, Any]:
    """Generate all report sections using the template."""
    investigation_id = state.get("investigation_id", "")
    template_name = state.get("template_name", "incident_report")
    errors: list[str] = []

    result = _generate_report_tool.invoke(
        {
            "investigation_id": investigation_id,
            "template": template_name,
        }
    )

    if result.get("status") == "failed":
        errors.append(result.get("error", "Section generation failed"))
        return {"errors": errors, "status": "failed"}

    return {
        "sections": result.get("sections", {}),
        "errors": errors,
        "status": "reviewing",
    }


def review_consistency(state: ReportState) -> dict[str, Any]:
    """Review generated sections for consistency and completeness."""
    sections = state.get("sections", {})
    template_config = state.get("template_config", {})
    review_results: list[str] = []

    expected_sections = template_config.get("sections", [])

    # Check all expected sections are present
    for section_name in expected_sections:
        if section_name not in sections:
            review_results.append(f"MISSING: Section '{section_name}' not generated")

    # Check no sections are empty
    for name, content in sections.items():
        if not content or content.strip() == "":
            review_results.append(f"EMPTY: Section '{name}' has no content")

    # Check for minimum content length
    for name, content in sections.items():
        if len(content) < 20:
            review_results.append(
                f"SHORT: Section '{name}' may be too brief ({len(content)} chars)"
            )

    if not review_results:
        review_results.append("PASS: All sections present and populated")

    return {
        "review_results": review_results,
        "status": "compiling",
    }


def compile_report(state: ReportState) -> dict[str, Any]:
    """Compile all sections into a final report."""
    investigation_id = state.get("investigation_id", "")
    template_name = state.get("template_name", "incident_report")
    sections = state.get("sections", {})
    review_results = state.get("review_results", [])
    now_iso = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    compiled_report = {
        "investigation_id": investigation_id,
        "template": template_name,
        "generated_at": now_iso,
        "sections": sections,
        "section_count": len(sections),
        "review_results": review_results,
        "status": "complete",
    }

    return {
        "compiled_report": compiled_report,
        "status": "complete",
    }


# --------------------------------------------------------------------------- #
# Graph factory
# --------------------------------------------------------------------------- #


def create_report_graph(config: dict[str, Any] | None = None) -> CompiledGraph:
    """Build and compile the report generation subgraph.

    Pipeline:
        select_template -> gather_data -> generate_sections ->
        review_consistency -> compile -> END

    Parameters
    ----------
    config : dict, optional
        Runtime configuration. Reserved for future options.

    Returns
    -------
    CompiledGraph
        A compiled LangGraph ready for invocation.
    """
    graph = StateGraph(ReportState)

    # Register nodes
    graph.add_node("select_template", select_template)
    graph.add_node("gather_data", gather_data)
    graph.add_node("generate_sections", generate_sections)
    graph.add_node("review_consistency", review_consistency)
    graph.add_node("compile", compile_report)

    # Define edges: linear pipeline
    graph.set_entry_point("select_template")
    graph.add_edge("select_template", "gather_data")
    graph.add_edge("gather_data", "generate_sections")
    graph.add_edge("generate_sections", "review_consistency")
    graph.add_edge("review_consistency", "compile")
    graph.add_edge("compile", END)

    return graph.compile()
