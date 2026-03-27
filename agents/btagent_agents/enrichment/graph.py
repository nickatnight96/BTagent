"""LangGraph subgraph for IOC enrichment pipeline.

Pipeline: select_iocs -> parallel_enrich -> score_confidence -> deduplicate -> store_results -> END
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Annotated, Any, TypedDict

from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph as CompiledGraph

from btagent_agents.plugins.enrichment.tools.confidence_scorer import (
    score_confidence as _score_confidence_tool,
)
from btagent_agents.plugins.enrichment.tools.dedup import (
    deduplicate_iocs as _deduplicate_tool,
)
from btagent_agents.plugins.enrichment.tools.enrichment_executor import (
    enrich_ioc as _enrich_ioc_tool,
)


# --------------------------------------------------------------------------- #
# State definition
# --------------------------------------------------------------------------- #


def _merge_lists(left: list, right: list) -> list:
    """Reducer that appends new items to existing list."""
    return left + right


class EnrichmentState(TypedDict):
    """State for the enrichment subgraph pipeline.

    Fields
    ------
    investigation_id : str
        Parent investigation ID.
    raw_iocs : list[dict]
        Input IOCs to enrich (each has 'type' and 'value').
    selected_iocs : list[dict]
        IOCs selected for enrichment after filtering.
    enriched_iocs : list[dict]
        IOCs after enrichment with source results.
    scored_iocs : list[dict]
        IOCs after confidence scoring.
    deduplicated_iocs : list[dict]
        Final deduplicated IOC list.
    stored : bool
        Whether results have been persisted.
    errors : list[str]
        Any errors encountered during processing.
    status : str
        Pipeline status (pending, enriching, scoring, deduplicating, complete, failed).
    """

    investigation_id: str
    raw_iocs: list[dict]
    selected_iocs: list[dict]
    enriched_iocs: list[dict]
    scored_iocs: list[dict]
    deduplicated_iocs: list[dict]
    stored: bool
    errors: Annotated[list[str], _merge_lists]
    status: str


# --------------------------------------------------------------------------- #
# Node implementations
# --------------------------------------------------------------------------- #


def select_iocs(state: EnrichmentState) -> dict[str, Any]:
    """Filter and validate IOCs for enrichment.

    Removes IOCs with missing type/value, filters unsupported types, and
    prepares the list for parallel enrichment.
    """
    raw_iocs = state.get("raw_iocs", [])
    errors: list[str] = []
    selected: list[dict[str, Any]] = []

    supported_types = {"ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email"}

    for idx, ioc in enumerate(raw_iocs):
        ioc_type = ioc.get("type", "").lower().strip()
        ioc_value = ioc.get("value", "").strip()

        if not ioc_type or not ioc_value:
            errors.append(f"IOC {idx}: missing type or value")
            continue

        if ioc_type not in supported_types:
            errors.append(f"IOC {idx}: unsupported type '{ioc_type}'")
            continue

        selected.append({"type": ioc_type, "value": ioc_value})

    return {
        "selected_iocs": selected,
        "errors": errors,
        "status": "enriching",
    }


def parallel_enrich(state: EnrichmentState) -> dict[str, Any]:
    """Enrich all selected IOCs against CTI sources.

    In a production deployment this would use asyncio.gather for true
    parallelism. The mock implementation processes sequentially but the
    interface is identical.
    """
    selected_iocs = state.get("selected_iocs", [])
    enriched: list[dict[str, Any]] = []
    errors: list[str] = []

    for ioc in selected_iocs:
        try:
            result = _enrich_ioc_tool.invoke({
                "ioc_type": ioc["type"],
                "ioc_value": ioc["value"],
            })
            enriched.append(result)
        except Exception as exc:
            errors.append(
                f"Enrichment failed for {ioc['type']}:{ioc['value']}: {exc}"
            )

    return {
        "enriched_iocs": enriched,
        "errors": errors,
        "status": "scoring",
    }


def score_all_confidence(state: EnrichmentState) -> dict[str, Any]:
    """Score confidence for all enriched IOCs."""
    enriched_iocs = state.get("enriched_iocs", [])
    scored: list[dict[str, Any]] = []
    errors: list[str] = []

    for ioc in enriched_iocs:
        try:
            score_result = _score_confidence_tool.invoke({
                "enrichment_json": json.dumps(ioc),
            })
            # Merge score result back into the IOC
            ioc_scored = dict(ioc)
            ioc_scored["confidence"] = score_result.get("confidence", ioc.get("confidence", 0.0))
            ioc_scored["confidence_justification"] = score_result.get("justification", [])
            ioc_scored["recommended_action"] = score_result.get("recommended_action", "monitor")
            scored.append(ioc_scored)
        except Exception as exc:
            errors.append(
                f"Scoring failed for {ioc.get('ioc_type')}:{ioc.get('ioc_value')}: {exc}"
            )
            scored.append(ioc)  # Keep the IOC even without updated score

    return {
        "scored_iocs": scored,
        "errors": errors,
        "status": "deduplicating",
    }


def deduplicate(state: EnrichmentState) -> dict[str, Any]:
    """Deduplicate scored IOCs."""
    scored_iocs = state.get("scored_iocs", [])
    errors: list[str] = []

    try:
        dedup_result = _deduplicate_tool.invoke({
            "iocs_json": json.dumps(scored_iocs),
        })
        deduplicated = dedup_result.get("deduplicated", scored_iocs)
    except Exception as exc:
        errors.append(f"Deduplication failed: {exc}")
        deduplicated = scored_iocs

    return {
        "deduplicated_iocs": deduplicated,
        "errors": errors,
        "status": "storing",
    }


def store_results(state: EnrichmentState) -> dict[str, Any]:
    """Persist enrichment results.

    In production this writes to the IOC database table. In mock mode
    it marks the pipeline as complete without persistence.
    """
    deduplicated = state.get("deduplicated_iocs", [])
    investigation_id = state.get("investigation_id", "")

    # In mock mode, we just mark as stored.
    # Production implementation would write to DB via ioc_service.
    stored_count = len(deduplicated)

    return {
        "stored": True,
        "status": "complete",
        "errors": [] if stored_count > 0 else ["No IOCs to store"],
    }


# --------------------------------------------------------------------------- #
# Graph factory
# --------------------------------------------------------------------------- #


def create_enrichment_graph(config: dict[str, Any] | None = None) -> CompiledGraph:
    """Build and compile the enrichment subgraph.

    Pipeline:
        select_iocs -> parallel_enrich -> score_confidence -> deduplicate -> store_results -> END

    Parameters
    ----------
    config : dict, optional
        Runtime configuration. Currently unused but reserved for future
        options like custom checkpointers or source overrides.

    Returns
    -------
    CompiledGraph
        A compiled LangGraph ready for invocation.
    """
    graph = StateGraph(EnrichmentState)

    # Register nodes
    graph.add_node("select_iocs", select_iocs)
    graph.add_node("parallel_enrich", parallel_enrich)
    graph.add_node("score_confidence", score_all_confidence)
    graph.add_node("deduplicate", deduplicate)
    graph.add_node("store_results", store_results)

    # Define edges: linear pipeline
    graph.set_entry_point("select_iocs")
    graph.add_edge("select_iocs", "parallel_enrich")
    graph.add_edge("parallel_enrich", "score_confidence")
    graph.add_edge("score_confidence", "deduplicate")
    graph.add_edge("deduplicate", "store_results")
    graph.add_edge("store_results", END)

    return graph.compile()
