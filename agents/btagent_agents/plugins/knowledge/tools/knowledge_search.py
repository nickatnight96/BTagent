"""Knowledge base search tools — hybrid search and investigation context."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from langchain_core.tools import tool


# --------------------------------------------------------------------------- #
# Mock search data (used when running without a live DB)
# --------------------------------------------------------------------------- #

_MOCK_KNOWLEDGE: list[dict[str, Any]] = [
    {
        "document_title": "APT29 Threat Profile",
        "source_type": "threat_profile",
        "content": (
            "APT29 (Cozy Bear) is a Russian state-sponsored threat group "
            "known for sophisticated cyber espionage campaigns. They employ "
            "custom malware including WellMess and WellMail, and are known "
            "for supply-chain attacks such as the SolarWinds compromise."
        ),
        "metadata": {"threat_group": "APT29", "region": "Russia"},
    },
    {
        "document_title": "Ransomware Incident Response Runbook",
        "source_type": "runbook",
        "content": (
            "Step 1: Isolate affected hosts immediately. "
            "Step 2: Identify the ransomware variant via hash or ransom note. "
            "Step 3: Check for lateral movement indicators. "
            "Step 4: Preserve forensic evidence before any remediation. "
            "Step 5: Assess backup integrity and plan recovery."
        ),
        "metadata": {"category": "ransomware", "priority": "critical"},
    },
    {
        "document_title": "Phishing Campaign Investigation - March 2026",
        "source_type": "investigation_report",
        "content": (
            "A spear-phishing campaign targeting finance department employees "
            "was detected on 2026-03-15. The campaign used lookalike domains "
            "mimicking our payment processor. 12 IOCs were identified, "
            "including 3 domains and 9 IP addresses. All were blocked at "
            "the email gateway and perimeter firewall."
        ),
        "metadata": {
            "investigation_id": "inv_sample_001",
            "severity": "high",
        },
    },
]


def _compute_relevance(query: str, content: str) -> float:
    """Compute a simple relevance score for mock search."""
    query_lower = query.lower()
    content_lower = content.lower()
    words = query_lower.split()
    if not words:
        return 0.0
    matches = sum(1 for w in words if w in content_lower)
    return round(matches / len(words), 4)


# --------------------------------------------------------------------------- #
# Tool definitions
# --------------------------------------------------------------------------- #


@tool
def search_knowledge_base(
    query: str, top_k: int = 5
) -> dict[str, Any]:
    """Search the organisation's knowledge base using hybrid retrieval.

    Combines vector similarity search with keyword matching and
    Reciprocal Rank Fusion (RRF) re-ranking to find the most relevant
    knowledge base entries for the given query.

    Args:
        query: Natural language search query describing what information
            is needed. Can include specific IOCs, threat actor names,
            technique IDs, or general topics.
        top_k: Maximum number of results to return (default 5).

    Returns:
        Dict with 'results' (list of search hits with citations),
        'total_results' (count), and 'query' (the original query).
    """
    if not query.strip():
        return {
            "results": [],
            "total_results": 0,
            "query": query,
            "error": "Empty query",
        }

    # Score and rank mock knowledge entries
    scored = []
    for entry in _MOCK_KNOWLEDGE:
        score = _compute_relevance(query, entry["content"])
        title_score = _compute_relevance(query, entry["document_title"])
        combined_score = max(score, title_score)
        if combined_score > 0:
            scored.append({
                "chunk_content": entry["content"],
                "document_title": entry["document_title"],
                "source_type": entry["source_type"],
                "relevance_score": combined_score,
                "metadata": entry.get("metadata", {}),
            })

    # Sort by relevance and take top_k
    scored.sort(key=lambda x: x["relevance_score"], reverse=True)
    results = scored[:top_k]

    # If no results from relevance matching, return top entries
    if not results and _MOCK_KNOWLEDGE:
        results = [
            {
                "chunk_content": entry["content"],
                "document_title": entry["document_title"],
                "source_type": entry["source_type"],
                "relevance_score": 0.1,
                "metadata": entry.get("metadata", {}),
            }
            for entry in _MOCK_KNOWLEDGE[:top_k]
        ]

    return {
        "results": results,
        "total_results": len(results),
        "query": query,
        "searched_at": datetime.now(timezone.utc).isoformat(),
    }


@tool
def get_investigation_context(
    investigation_id: str,
) -> dict[str, Any]:
    """Retrieve relevant knowledge for an active investigation.

    Searches the knowledge base for documents related to the given
    investigation, including past reports with similar IOCs, relevant
    runbooks, and applicable threat profiles.

    Args:
        investigation_id: The investigation ID to retrieve context for.
            Used to find related historical investigations and relevant
            knowledge base entries.

    Returns:
        Dict with 'context_documents' (list of relevant knowledge entries),
        'investigation_id', and 'total_documents'.
    """
    if not investigation_id.strip():
        return {
            "context_documents": [],
            "investigation_id": investigation_id,
            "total_documents": 0,
            "error": "Empty investigation_id",
        }

    # In production, this would query the DB for documents related
    # to the specific investigation. For mock mode, return all
    # knowledge entries as potentially relevant context.
    context_docs = []
    for entry in _MOCK_KNOWLEDGE:
        meta = entry.get("metadata", {})
        # Check if the entry is directly related to this investigation
        is_direct = meta.get("investigation_id") == investigation_id
        context_docs.append({
            "document_title": entry["document_title"],
            "source_type": entry["source_type"],
            "content_preview": entry["content"][:300],
            "metadata": meta,
            "is_direct_match": is_direct,
            "relevance": "high" if is_direct else "medium",
        })

    return {
        "context_documents": context_docs,
        "investigation_id": investigation_id,
        "total_documents": len(context_docs),
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }
