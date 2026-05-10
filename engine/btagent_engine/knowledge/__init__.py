"""Knowledge-base Nodes -- RAG retrieval (search) and ingestion (upsert).

The Nodes here delegate the actual storage layer to a
:class:`KnowledgeClient` Protocol so the engine package can stay
independent of ``btagent_backend``. Production wires an
``HttpKnowledgeClient`` (Sprint 5) that hits the FastAPI
``/api/v1/knowledge/`` endpoints; tests inject :class:`FakeKnowledgeClient`.

Re-exports the public surface so callers can do ::

    from btagent_engine.knowledge import (
        KnowledgeClient,
        KnowledgeSearchNode,
        KnowledgeUpsertNode,
    )

without reaching into the sub-modules. Symbol set is intentionally narrow
-- the Node input/output schemas are part of the contract; everything
else is implementation detail.
"""

from btagent_engine.knowledge.client import FakeKnowledgeClient, KnowledgeClient
from btagent_engine.knowledge.search import (
    KnowledgeSearchInput,
    KnowledgeSearchNode,
    KnowledgeSearchOutput,
    KnowledgeSearchResult,
)
from btagent_engine.knowledge.upsert import (
    KnowledgeUpsertInput,
    KnowledgeUpsertNode,
    KnowledgeUpsertOutput,
)

__all__ = [
    "FakeKnowledgeClient",
    "KnowledgeClient",
    "KnowledgeSearchInput",
    "KnowledgeSearchNode",
    "KnowledgeSearchOutput",
    "KnowledgeSearchResult",
    "KnowledgeUpsertInput",
    "KnowledgeUpsertNode",
    "KnowledgeUpsertOutput",
]
