"""Knowledge context injection for the investigation orchestrator.

Queries the knowledge base for context relevant to the current investigation
and injects retrieved chunks into the system prompt context. This bridges
the knowledge RAG pipeline with the main investigation graph.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger("btagent.orchestrator.knowledge_injector")

# Maximum characters of knowledge context to inject into the system prompt
# to avoid blowing token budgets.
_MAX_CONTEXT_CHARS = 4000

# Maximum number of chunks to retrieve per query.
_DEFAULT_TOP_K = 5


def inject_knowledge_context(
    state: dict[str, Any],
    knowledge_service_url: str = "",
) -> dict[str, Any]:
    """Query knowledge base for context relevant to the current investigation.

    Injects retrieved chunks into the system prompt context.

    The function extracts key terms from the investigation state (IOC types,
    values, severity, category keywords) and queries the knowledge base for
    relevant chunks.  Retrieved context is formatted as a block suitable for
    system prompt injection and returned as the ``knowledge_context`` field
    on the updated state.

    Parameters
    ----------
    state : dict
        Current investigation state dict. Expected keys:
        - ``iocs`` (list[dict]): Discovered IOCs with type/value.
        - ``severity`` (str): Current severity assessment.
        - ``task_type`` (str): Current task classification.
        - ``messages`` (list): Conversation messages.
        - ``investigation_id`` (str): The investigation ID.
    knowledge_service_url : str
        Base URL for the knowledge service HTTP endpoint (e.g.
        ``http://localhost:8000/api/v1/knowledge``). If empty, knowledge
        injection is skipped silently.

    Returns
    -------
    dict
        Updated state with ``knowledge_context`` field containing the
        formatted context block, or an empty string if no results.
    """
    if not knowledge_service_url:
        logger.debug("Knowledge service URL not configured; skipping injection")
        return {**state, "knowledge_context": ""}

    # 1. Extract key terms from investigation
    query_terms = _extract_query_terms(state)
    if not query_terms:
        logger.debug("No query terms extracted from state; skipping injection")
        return {**state, "knowledge_context": ""}

    # 2. Query knowledge base for relevant chunks
    chunks = _query_knowledge_base(knowledge_service_url, query_terms)
    if not chunks:
        logger.debug("No knowledge chunks retrieved for query: %s", query_terms[:80])
        return {**state, "knowledge_context": ""}

    # 3. Format as context block for system prompt
    context_block = _format_context_block(chunks)

    logger.info(
        "Injected %d knowledge chunks (%d chars) for investigation %s",
        len(chunks),
        len(context_block),
        state.get("investigation_id", "unknown"),
    )

    # 4. Return updated state with knowledge_context field
    return {**state, "knowledge_context": context_block}


def _extract_query_terms(state: dict[str, Any]) -> str:
    """Build a search query from investigation state.

    Combines IOC values, severity, task type, and recent message text
    into a single query string for knowledge base retrieval.
    """
    parts: list[str] = []

    # Add severity and task type for context
    severity = state.get("severity", "")
    task_type = state.get("task_type", "")
    if severity:
        parts.append(f"severity:{severity}")
    if task_type:
        parts.append(task_type)

    # Add IOC types and values (limited to avoid query bloat)
    iocs: list[dict[str, Any]] = state.get("iocs", [])
    ioc_terms: list[str] = []
    for ioc in iocs[:10]:
        ioc_type = ioc.get("type", "")
        ioc_value = ioc.get("value", "")
        if ioc_type:
            ioc_terms.append(ioc_type)
        if ioc_value and len(ioc_value) < 100:
            ioc_terms.append(ioc_value)
    if ioc_terms:
        parts.extend(ioc_terms[:8])

    # Add text from the latest message (truncated)
    messages = state.get("messages", [])
    if messages:
        last_msg = messages[-1]
        content = getattr(last_msg, "content", "")
        if isinstance(content, str) and content:
            # Take first 200 chars of the last message
            parts.append(content[:200])

    return " ".join(parts).strip()


def _query_knowledge_base(
    base_url: str,
    query: str,
    top_k: int = _DEFAULT_TOP_K,
) -> list[dict[str, Any]]:
    """Send a synchronous query to the knowledge base HTTP endpoint.

    Returns a list of chunk dicts with keys: chunk_content, document_title,
    source_type, relevance_score, metadata.
    """
    try:
        response = httpx.post(
            f"{base_url.rstrip('/')}/query",
            json={"query": query, "top_k": top_k},
            timeout=5.0,
        )
        if response.status_code != 200:
            logger.warning(
                "Knowledge query returned HTTP %d: %s",
                response.status_code,
                response.text[:200],
            )
            return []

        data = response.json()
        return data.get("results", [])

    except httpx.TimeoutException:
        logger.warning("Knowledge query timed out for query: %s", query[:80])
        return []
    except Exception:
        logger.exception("Knowledge query failed")
        return []


def _format_context_block(chunks: list[dict[str, Any]]) -> str:
    """Format retrieved knowledge chunks as a system prompt context block.

    Output is wrapped in ``<knowledge-context>`` tags so the LLM can
    distinguish it from other context sources.
    """
    lines: list[str] = ["<knowledge-context>"]

    total_chars = 0
    for i, chunk in enumerate(chunks, 1):
        title = chunk.get("document_title", "Unknown Source")
        content = chunk.get("chunk_content", "")
        score = chunk.get("relevance_score", 0.0)

        entry = f"[Source {i}: {title} (relevance: {score:.2f})]\n{content}"

        if total_chars + len(entry) > _MAX_CONTEXT_CHARS:
            break

        lines.append(entry)
        total_chars += len(entry)

    lines.append("</knowledge-context>")
    return "\n\n".join(lines)
