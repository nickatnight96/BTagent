"""Confidence scoring tool for enriched IOCs."""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import tool


# --------------------------------------------------------------------------- #
# Scoring weights by source
# --------------------------------------------------------------------------- #

_SOURCE_WEIGHTS: dict[str, float] = {
    "virustotal": 0.30,
    "shodan": 0.15,
    "greynoise": 0.20,
    "abuseipdb": 0.20,
    "urlhaus": 0.15,
}

_VERDICT_SCORES: dict[str, float] = {
    "malicious": 1.0,
    "suspicious": 0.7,
    "noise": 0.3,
    "informational": 0.2,
    "clean": 0.0,
    "benign": 0.0,
}


def _score_from_source_results(source_results: list[dict[str, Any]]) -> tuple[float, list[str]]:
    """Compute weighted confidence score and justification lines.

    Returns
    -------
    tuple[float, list[str]]
        (confidence, justification_lines)
    """
    if not source_results:
        return 0.0, ["No source results to score."]

    weighted_sum = 0.0
    weight_total = 0.0
    justifications: list[str] = []
    malicious_sources: list[str] = []
    clean_sources: list[str] = []

    for result in source_results:
        source = result.get("source", "unknown")
        verdict = result.get("verdict", "informational").lower()
        weight = _SOURCE_WEIGHTS.get(source, 0.10)
        verdict_score = _VERDICT_SCORES.get(verdict, 0.2)

        weighted_sum += verdict_score * weight
        weight_total += weight

        if verdict == "malicious":
            malicious_sources.append(source)
        elif verdict in ("clean", "benign"):
            clean_sources.append(source)

        # Extract source-specific scoring context
        details = result.get("details", {})
        if source == "virustotal":
            ratio = details.get("detection_ratio", "?/?")
            justifications.append(f"VirusTotal: {ratio} engines flagged")
        elif source == "abuseipdb":
            abuse_score = details.get("abuse_confidence_score", 0)
            justifications.append(f"AbuseIPDB: confidence {abuse_score}%")
        elif source == "greynoise":
            classification = details.get("classification", "unknown")
            justifications.append(f"GreyNoise: classified as {classification}")
        elif source == "shodan":
            ports = details.get("open_ports", [])
            country = details.get("country", "?")
            justifications.append(f"Shodan: {len(ports)} open ports, country={country}")
        elif source == "urlhaus":
            url_status = details.get("url_status", "unknown")
            justifications.append(f"URLhaus: status={url_status}")

    # Base score from weighted average
    base_score = weighted_sum / weight_total if weight_total > 0 else 0.0

    # Agreement bonus: if 3+ sources agree malicious, boost above 0.8
    if len(malicious_sources) >= 3:
        base_score = max(base_score, 0.85)
        justifications.append(
            f"High agreement: {len(malicious_sources)} sources flagged malicious "
            f"({', '.join(malicious_sources)})"
        )
    elif len(malicious_sources) >= 2:
        base_score = max(base_score, 0.65)
        justifications.append(
            f"Moderate agreement: {len(malicious_sources)} sources flagged malicious"
        )

    # Disagreement penalty: if sources disagree, clamp to 0.4-0.6
    if malicious_sources and clean_sources:
        if base_score > 0.6:
            base_score = min(base_score, 0.6)
        elif base_score < 0.4:
            base_score = max(base_score, 0.4)
        justifications.append(
            f"Conflicting signals: {', '.join(malicious_sources)} say malicious, "
            f"{', '.join(clean_sources)} say clean"
        )

    # All clean → low confidence in maliciousness
    if not malicious_sources and clean_sources:
        base_score = min(base_score, 0.15)
        justifications.append("All queried sources report clean/benign")

    return round(min(1.0, max(0.0, base_score)), 2), justifications


@tool
def score_confidence(enrichment_json: str) -> dict[str, Any]:
    """Score the confidence of an enriched IOC based on source agreement.

    Takes the JSON output from enrich_ioc (or a dict with 'source_results')
    and computes a weighted confidence score factoring in source reliability,
    verdict agreement, and detection ratios.

    Scoring rules:
    - 3+ sources agree malicious: confidence > 0.8
    - 2 sources agree malicious: confidence 0.6-0.8
    - Disagreement between sources: confidence clamped to 0.4-0.6
    - All sources clean: confidence < 0.2

    Args:
        enrichment_json: JSON string containing enrichment results with
            a 'source_results' list. Each source result must have 'source'
            and 'verdict' keys.
    """
    try:
        enrichment = json.loads(enrichment_json)
    except json.JSONDecodeError as exc:
        return {
            "confidence": 0.0,
            "justification": [f"Invalid JSON input: {exc}"],
            "error": str(exc),
        }

    source_results = enrichment.get("source_results", [])
    ioc_type = enrichment.get("ioc_type", "unknown")
    ioc_value = enrichment.get("ioc_value", "unknown")

    confidence, justifications = _score_from_source_results(source_results)

    # Determine recommended action based on confidence
    if confidence >= 0.8:
        action = "block"
    elif confidence >= 0.6:
        action = "investigate"
    elif confidence >= 0.4:
        action = "monitor"
    else:
        action = "dismiss"

    return {
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "confidence": confidence,
        "justification": justifications,
        "recommended_action": action,
        "sources_evaluated": len(source_results),
    }
