"""KnowledgeSearchNode -- RAG retrieval over the knowledge base.

The Node delegates the actual search to a :class:`KnowledgeClient`. The
engine package has zero deps on ``btagent_backend``; production wires an
HTTP client (Sprint 5) that hits ``/api/v1/knowledge/search``. Tests
inject a :class:`FakeKnowledgeClient`.

Client wiring -- design call
----------------------------
The :class:`WorkflowExecutor` resolves a Node from the registry and
instantiates it with **no constructor arguments** (see
``runtime/executor.py`` line ``return node_cls()``). To honour both that
no-arg path AND constructor injection for direct unit-tests, we use a
hybrid:

1. ``__init__`` accepts an optional ``client`` -- if passed, that wins
   (the path tests / direct callers use).
2. Otherwise we fall back to ``cls.client_factory()`` -- a class-level
   hook the orchestrator overrides at startup to return an
   ``HttpKnowledgeClient`` bound to the FastAPI backend.
3. Default ``client_factory`` returns a :class:`FakeKnowledgeClient`,
   which makes the Node safe-by-default (a misconfigured prod env that
   forgets to override the factory ends up with empty results, not a
   real-data leak).

Empty-query short-circuit
-------------------------
``query == ""`` returns an empty result list without round-tripping the
client. Saves a network call, and matches what the backend RAG layer
would return anyway (BM25 / vector both score blanks at zero).
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import BaseModel, Field

from btagent_engine.knowledge.client import FakeKnowledgeClient, KnowledgeClient
from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class KnowledgeSearchInput(BaseModel):
    query: str = Field(
        ...,
        description="Free-text search query. Empty string short-circuits to no results.",
    )
    top_k: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Maximum number of chunks to return.",
    )
    source_type: str | None = Field(
        default=None,
        description="Optional source-type filter (e.g. 'runbook', 'cti_report').",
    )


class KnowledgeSearchResult(BaseModel):
    chunk_content: str
    document_title: str
    source_type: str
    relevance_score: float
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgeSearchOutput(BaseModel):
    results: list[KnowledgeSearchResult] = Field(default_factory=list)
    query: str = Field(
        ...,
        description="Echo of the input query for traceability across pipeline steps.",
    )


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


@NodeRegistry.register
class KnowledgeSearchNode(Node[KnowledgeSearchInput, KnowledgeSearchOutput]):
    """Retrieve top-k chunks from the knowledge base for a query."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="knowledge.search",
        name="Knowledge: Search",
        version="0.1.0",
        category=NodeCategory.KNOWLEDGE,
        description="Hybrid (vector + keyword) RAG retrieval over the "
        "knowledge base. Returns scored chunks with source metadata.",
    )
    input_schema = KnowledgeSearchInput
    output_schema = KnowledgeSearchOutput

    # Class-level factory used when no client is injected via __init__.
    # The orchestrator overrides this at startup; default to a fake so the
    # default no-arg constructor path is safe (no accidental network IO).
    client_factory: ClassVar[type[KnowledgeClient] | Any] = FakeKnowledgeClient

    def __init__(self, client: KnowledgeClient | None = None) -> None:
        # Constructor injection wins over the class-level factory; fall back
        # to the factory so the executor's no-arg ``node_cls()`` works.
        self._client: KnowledgeClient = client or type(self).client_factory()

    async def run(
        self,
        input: KnowledgeSearchInput,
        ctx: NodeContext,
    ) -> KnowledgeSearchOutput:
        # Empty-query short-circuit -- documented above.
        if not input.query:
            return KnowledgeSearchOutput(results=[], query=input.query)

        raw_results = await self._client.search(
            input.query,
            top_k=input.top_k,
            source_type=input.source_type,
        )

        adapted = [
            KnowledgeSearchResult(
                chunk_content=r.get("chunk_content", ""),
                document_title=r.get("document_title", ""),
                source_type=r.get("source_type", ""),
                relevance_score=float(r.get("relevance_score", 0.0)),
                metadata=dict(r.get("metadata") or {}),
            )
            for r in raw_results
        ]
        return KnowledgeSearchOutput(results=adapted, query=input.query)
