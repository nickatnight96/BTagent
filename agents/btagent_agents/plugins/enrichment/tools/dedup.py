"""IOC deduplication tool — merge duplicate indicators and combine enrichment."""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import tool


def _merge_enrichments(
    existing: dict[str, Any],
    incoming: dict[str, Any],
) -> dict[str, Any]:
    """Merge two enrichment dicts, keeping the richer data.

    - Combine source_results lists (deduplicate by source name, keep latest)
    - Keep the highest confidence
    - Merge MITRE technique lists
    - Keep earliest enriched_at
    """
    merged = dict(existing)

    # Merge source results by source name
    existing_sources: dict[str, dict[str, Any]] = {
        r["source"]: r for r in existing.get("source_results", [])
    }
    for result in incoming.get("source_results", []):
        source_name = result.get("source", "unknown")
        if source_name not in existing_sources:
            existing_sources[source_name] = result
    merged["source_results"] = list(existing_sources.values())

    # Keep highest confidence
    merged["confidence"] = max(
        existing.get("confidence", 0.0),
        incoming.get("confidence", 0.0),
    )

    # Merge MITRE techniques
    existing_mitre = set(existing.get("mitre_techniques", []))
    incoming_mitre = set(incoming.get("mitre_techniques", []))
    merged["mitre_techniques"] = sorted(existing_mitre | incoming_mitre)

    # Combine sources_queried
    existing_queried = set(existing.get("sources_queried", []))
    incoming_queried = set(incoming.get("sources_queried", []))
    merged["sources_queried"] = sorted(existing_queried | incoming_queried)

    # Keep earliest enriched_at
    existing_time = existing.get("enriched_at", "")
    incoming_time = incoming.get("enriched_at", "")
    if existing_time and incoming_time:
        merged["enriched_at"] = min(existing_time, incoming_time)
    elif incoming_time:
        merged["enriched_at"] = incoming_time

    return merged


@tool
def deduplicate_iocs(iocs_json: str) -> dict[str, Any]:
    """Deduplicate a list of enriched IOCs by merging same type+value pairs.

    Takes a JSON list of enriched IOC objects and merges duplicates. For IOCs
    with the same type and value, enrichment data is combined: source results
    are merged (keeping latest per source), the highest confidence score is
    retained, and MITRE technique tags are unified.

    Args:
        iocs_json: JSON string containing a list of enriched IOC objects.
            Each object should have at minimum 'ioc_type' and 'ioc_value' keys.
            Enrichment fields ('source_results', 'confidence', 'mitre_techniques')
            are merged when duplicates are found.
    """
    try:
        iocs = json.loads(iocs_json)
    except json.JSONDecodeError as exc:
        return {
            "error": f"Invalid JSON: {exc}",
            "deduplicated": [],
            "original_count": 0,
            "deduped_count": 0,
            "duplicates_merged": 0,
        }

    if not isinstance(iocs, list):
        return {
            "error": "Expected a JSON array of IOC objects",
            "deduplicated": [],
            "original_count": 0,
            "deduped_count": 0,
            "duplicates_merged": 0,
        }

    original_count = len(iocs)

    # Group by (type, value)
    groups: dict[str, dict[str, Any]] = {}
    for ioc in iocs:
        if not isinstance(ioc, dict):
            continue

        ioc_type = ioc.get("ioc_type", ioc.get("type", "")).lower().strip()
        ioc_value = ioc.get("ioc_value", ioc.get("value", "")).strip()

        if not ioc_type or not ioc_value:
            continue

        key = f"{ioc_type}:{ioc_value}"

        if key in groups:
            groups[key] = _merge_enrichments(groups[key], ioc)
        else:
            # Normalize keys
            normalized = dict(ioc)
            normalized["ioc_type"] = ioc_type
            normalized["ioc_value"] = ioc_value
            groups[key] = normalized

    deduplicated = list(groups.values())
    duplicates_merged = original_count - len(deduplicated)

    return {
        "deduplicated": deduplicated,
        "original_count": original_count,
        "deduped_count": len(deduplicated),
        "duplicates_merged": duplicates_merged,
    }
