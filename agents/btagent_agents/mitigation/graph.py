"""LangGraph subgraph for mitigation / remediation pipeline.

Pipeline: analyze_attack -> generate_remediation -> generate_detection -> compile_playbook -> END

Generates customer-facing remediation guidance with audience-aware tone.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, TypedDict

from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph as CompiledGraph

from btagent_agents.plugins.mitigation.tools.remediation_generator import (
    generate_detection_content as _detection_tool,
)
from btagent_agents.plugins.mitigation.tools.remediation_generator import (
    generate_hardening_recommendations as _hardening_tool,
)
from btagent_agents.plugins.mitigation.tools.remediation_generator import (
    generate_remediation as _remediation_tool,
)

# --------------------------------------------------------------------------- #
# State definition
# --------------------------------------------------------------------------- #


def _merge_lists(left: list, right: list) -> list:
    """Reducer that appends new items to existing list."""
    return left + right


class MitigationState(TypedDict):
    """State for the mitigation subgraph pipeline.

    Fields
    ------
    investigation_id : str
        Investigation to generate remediation for.
    audience : str
        Target audience (executive, technical, compliance).
    detection_platform : str
        Target SIEM platform for detection content (splunk, elastic, sentinel).
    attack_analysis : dict
        Results of attack vector analysis.
    remediation_result : dict
        Audience-specific remediation checklist.
    detection_result : dict
        Platform-specific detection rules.
    hardening_result : dict
        Technical hardening recommendations.
    compiled_playbook : dict
        Final compiled playbook with all sections.
    errors : list[str]
        Any errors encountered during processing.
    status : str
        Pipeline status.
    """

    investigation_id: str
    audience: str
    detection_platform: str
    attack_analysis: dict
    remediation_result: dict
    detection_result: dict
    hardening_result: dict
    compiled_playbook: dict
    errors: Annotated[list[str], _merge_lists]
    status: str


# --------------------------------------------------------------------------- #
# Node implementations
# --------------------------------------------------------------------------- #


def analyze_attack(state: MitigationState) -> dict[str, Any]:
    """Analyze attack vectors from the investigation."""
    investigation_id = state.get("investigation_id", "")
    errors: list[str] = []

    if not investigation_id:
        errors.append("No investigation ID provided")
        return {"errors": errors, "status": "failed"}

    # Use hardening tool as a proxy to retrieve and analyze attack data
    analysis = _hardening_tool.invoke({"investigation_id": investigation_id})

    if analysis.get("status") == "failed":
        errors.append(analysis.get("error", "Attack analysis failed"))
        return {"errors": errors, "status": "failed"}

    attack_analysis = {
        "investigation_id": investigation_id,
        "attack_vectors": analysis.get("attack_vectors", []),
        "mitre_techniques": analysis.get("mitre_techniques", []),
    }

    return {
        "attack_analysis": attack_analysis,
        "errors": errors,
        "status": "generating_remediation",
    }


def gen_remediation(state: MitigationState) -> dict[str, Any]:
    """Generate audience-specific remediation checklist."""
    investigation_id = state.get("investigation_id", "")
    audience = state.get("audience", "technical")
    errors: list[str] = []

    result = _remediation_tool.invoke(
        {
            "investigation_id": investigation_id,
            "audience": audience,
        }
    )

    if result.get("status") == "failed":
        errors.append(result.get("error", "Remediation generation failed"))
        return {"errors": errors, "status": "failed"}

    return {
        "remediation_result": result,
        "errors": errors,
        "status": "generating_detection",
    }


def gen_detection(state: MitigationState) -> dict[str, Any]:
    """Generate detection content for the specified platform."""
    investigation_id = state.get("investigation_id", "")
    platform = state.get("detection_platform", "splunk")
    errors: list[str] = []

    result = _detection_tool.invoke(
        {
            "investigation_id": investigation_id,
            "platform": platform,
        }
    )

    if result.get("status") == "failed":
        errors.append(result.get("error", "Detection content generation failed"))
        return {"errors": errors, "status": "failed"}

    return {
        "detection_result": result,
        "errors": errors,
        "status": "compiling",
    }


def compile_playbook(state: MitigationState) -> dict[str, Any]:
    """Compile all mitigation outputs into a unified playbook."""
    investigation_id = state.get("investigation_id", "")
    audience = state.get("audience", "technical")
    platform = state.get("detection_platform", "splunk")
    attack_analysis = state.get("attack_analysis", {})
    remediation_result = state.get("remediation_result", {})
    detection_result = state.get("detection_result", {})

    # Also get hardening recommendations
    hardening_result = _hardening_tool.invoke({"investigation_id": investigation_id})

    now_iso = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    compiled_playbook = {
        "investigation_id": investigation_id,
        "generated_at": now_iso,
        "audience": audience,
        "detection_platform": platform,
        "attack_analysis": attack_analysis,
        "remediation": remediation_result,
        "detection_rules": detection_result,
        "hardening": hardening_result,
        "total_remediation_actions": len(remediation_result.get("actions", [])),
        "total_detection_rules": detection_result.get("rule_count", 0),
        "total_hardening_recommendations": hardening_result.get("recommendation_count", 0),
        "status": "complete",
    }

    return {
        "compiled_playbook": compiled_playbook,
        "hardening_result": hardening_result,
        "status": "complete",
    }


# --------------------------------------------------------------------------- #
# Graph factory
# --------------------------------------------------------------------------- #


def create_mitigation_graph(
    config: dict[str, Any] | None = None,
) -> CompiledGraph:
    """Build and compile the mitigation subgraph.

    Pipeline:
        analyze_attack -> generate_remediation -> generate_detection ->
        compile_playbook -> END

    Parameters
    ----------
    config : dict, optional
        Runtime configuration. Reserved for future options.

    Returns
    -------
    CompiledGraph
        A compiled LangGraph ready for invocation.
    """
    graph = StateGraph(MitigationState)

    # Register nodes
    graph.add_node("analyze_attack", analyze_attack)
    graph.add_node("generate_remediation", gen_remediation)
    graph.add_node("generate_detection", gen_detection)
    graph.add_node("compile_playbook", compile_playbook)

    # Define edges: linear pipeline
    graph.set_entry_point("analyze_attack")
    graph.add_edge("analyze_attack", "generate_remediation")
    graph.add_edge("generate_remediation", "generate_detection")
    graph.add_edge("generate_detection", "compile_playbook")
    graph.add_edge("compile_playbook", END)

    return graph.compile()
