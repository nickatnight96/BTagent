"""LangGraph subgraph for knowledge base retrieval (RAG pipeline).

Pipeline: understand_query -> retrieve_context -> generate_answer -> cite_sources -> END

Provides a four-stage retrieval-augmented generation pipeline:
1. Rephrase user query for better retrieval
2. Retrieve relevant chunks via hybrid search
3. Generate an answer using LLM with retrieved context
4. Extract citations and link them to source documents
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, TypedDict

from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph as CompiledGraph

# --------------------------------------------------------------------------- #
# State definition
# --------------------------------------------------------------------------- #


def _merge_lists(left: list, right: list) -> list:
    """Reducer that appends new items to existing list."""
    return left + right


class KnowledgeState(TypedDict):
    """State for the knowledge retrieval subgraph pipeline.

    Fields
    ------
    query : str
        Original user query.
    investigation_id : str
        Parent investigation ID (for context-aware retrieval).
    retrieved_chunks : list[dict]
        Chunks retrieved from the knowledge base.
    answer : str
        Generated answer based on retrieved context.
    citations : list[dict]
        Source citations extracted from the answer.
    rephrased_query : str
        Query rephrased for better retrieval.
    errors : list[str]
        Any errors encountered during processing.
    status : str
        Pipeline status.
    """

    query: str
    investigation_id: str
    retrieved_chunks: list[dict]
    answer: str
    citations: Annotated[list[dict], _merge_lists]
    rephrased_query: str
    errors: Annotated[list[str], _merge_lists]
    status: str


# --------------------------------------------------------------------------- #
# Node implementations
# --------------------------------------------------------------------------- #


def understand_query_node(state: KnowledgeState) -> dict[str, Any]:
    """Rephrase user query for better knowledge base retrieval.

    Expands abbreviations, adds context from the investigation, and
    reformulates the query to improve semantic search relevance.
    """
    query = state.get("query", "")
    investigation_id = state.get("investigation_id", "")
    errors: list[str] = []

    if not query.strip():
        errors.append("Empty query provided")
        return {
            "rephrased_query": "",
            "errors": errors,
            "status": "failed",
        }

    # In production, this would use an LLM to rephrase. For now,
    # we enhance the query with investigation context.
    rephrased_parts = [query]

    # Add investigation context if available
    if investigation_id:
        rephrased_parts.append(f"(investigation context: {investigation_id})")

    # Expand common security abbreviations
    abbreviation_map = {
        "IOC": "indicator of compromise",
        "C2": "command and control",
        "TTP": "tactics techniques and procedures",
        "APT": "advanced persistent threat",
        "EDR": "endpoint detection and response",
        "SIEM": "security information and event management",
        "MITRE": "MITRE ATT&CK framework",
        "TLP": "Traffic Light Protocol classification",
    }

    rephrased = query
    for abbr, expansion in abbreviation_map.items():
        if abbr in query.upper() and abbr not in query:
            rephrased = rephrased + f" ({abbr}: {expansion})"

    return {
        "rephrased_query": rephrased,
        "errors": errors,
        "status": "retrieving",
    }


def retrieve_context_node(state: KnowledgeState) -> dict[str, Any]:
    """Retrieve relevant chunks from the knowledge base via hybrid search.

    In production, this calls KnowledgeService.hybrid_search. In the
    subgraph context (without direct DB access), it prepares the search
    request for the orchestrator to execute.
    """
    # Propagate failure from previous node
    if state.get("status") == "failed":
        return {}

    rephrased_query = state.get("rephrased_query", state.get("query", ""))
    errors: list[str] = []

    if not rephrased_query.strip():
        return {
            "retrieved_chunks": [],
            "errors": ["No query available for retrieval"],
            "status": "failed",
        }

    # In mock/standalone mode, return placeholder chunks.
    # The orchestrator will inject real search results via tool calls.
    retrieved_chunks = [
        {
            "content": (f"[Retrieval placeholder for query: {rephrased_query[:100]}]"),
            "document_title": "Knowledge Base",
            "source_type": "knowledge_base",
            "relevance_score": 1.0,
            "metadata": {
                "retrieval_query": rephrased_query,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        }
    ]

    return {
        "retrieved_chunks": retrieved_chunks,
        "errors": errors,
        "status": "generating",
    }


def generate_answer_node(state: KnowledgeState) -> dict[str, Any]:
    """Generate an answer using the LLM with retrieved context.

    Composes a prompt with the retrieved chunks as context and uses
    the LLM to synthesize a coherent answer.
    """
    # Propagate failure from previous nodes
    if state.get("status") == "failed":
        return {}

    query = state.get("query", "")
    chunks = state.get("retrieved_chunks", [])
    errors: list[str] = []

    if not chunks:
        return {
            "answer": ("No relevant information found in the knowledge base for this query."),
            "errors": errors,
            "status": "citing",
        }

    # Compose context from retrieved chunks
    context_parts: list[str] = []
    for i, chunk in enumerate(chunks, 1):
        source = chunk.get("document_title", "Unknown")
        content = chunk.get("content", "")
        context_parts.append(f"[Source {i}: {source}]\n{content}")

    context = "\n\n---\n\n".join(context_parts)

    # In production, this would call the LLM. For standalone operation,
    # generate a structured summary from the retrieved context.
    answer = (
        f"Based on {len(chunks)} knowledge base source(s), "
        f'here is what was found for: "{query}"\n\n'
        f"Context retrieved:\n{context}"
    )

    return {
        "answer": answer,
        "errors": errors,
        "status": "citing",
    }


def cite_sources_node(state: KnowledgeState) -> dict[str, Any]:
    """Extract citations from the answer and link to source documents.

    Parses the generated answer to identify which source chunks were
    used, and creates structured citation objects.
    """
    # Propagate failure from previous nodes
    if state.get("status") == "failed":
        return {}

    chunks = state.get("retrieved_chunks", [])
    answer = state.get("answer", "")
    errors: list[str] = []

    citations: list[dict[str, Any]] = []
    for i, chunk in enumerate(chunks, 1):
        citation = {
            "citation_index": i,
            "document_title": chunk.get("document_title", "Unknown"),
            "source_type": chunk.get("source_type", "unknown"),
            "relevance_score": chunk.get("relevance_score", 0.0),
            "chunk_preview": chunk.get("content", "")[:200],
            "metadata": chunk.get("metadata", {}),
        }
        citations.append(citation)

    return {
        "citations": citations,
        "errors": errors,
        "status": "complete",
    }


# --------------------------------------------------------------------------- #
# Graph factory
# --------------------------------------------------------------------------- #


def create_knowledge_subgraph(
    config: dict[str, Any] | None = None,
) -> CompiledGraph:
    """Build and compile the knowledge retrieval subgraph.

    Pipeline:
        understand_query -> retrieve_context -> generate_answer
        -> cite_sources -> END

    Parameters
    ----------
    config : dict, optional
        Runtime configuration. Reserved for future options like
        custom checkpointers or embedding service overrides.

    Returns
    -------
    CompiledGraph
        A compiled LangGraph ready for invocation.
    """
    graph = StateGraph(KnowledgeState)

    # Register nodes
    graph.add_node("understand_query", understand_query_node)
    graph.add_node("retrieve_context", retrieve_context_node)
    graph.add_node("generate_answer", generate_answer_node)
    graph.add_node("cite_sources", cite_sources_node)

    # Define edges: linear pipeline
    graph.set_entry_point("understand_query")
    graph.add_edge("understand_query", "retrieve_context")
    graph.add_edge("retrieve_context", "generate_answer")
    graph.add_edge("generate_answer", "cite_sources")
    graph.add_edge("cite_sources", END)

    return graph.compile()
