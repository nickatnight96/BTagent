"""KnowledgeUpsertNode -- ingest a document into the knowledge base.

Mirror of :mod:`btagent_engine.knowledge.search`: delegates the actual
write to a :class:`KnowledgeClient`, which production wires to the
FastAPI backend (``POST /api/v1/knowledge/documents``) and tests stub
with :class:`FakeKnowledgeClient`.

Client wiring -- design call
----------------------------
Same hybrid pattern as :class:`KnowledgeSearchNode`: ``__init__`` takes
an optional ``client`` (constructor injection wins), otherwise we fall
back to the class-level ``client_factory``. The :class:`WorkflowExecutor`
instantiates Nodes with no constructor arguments
(``runtime/executor.py`` line ``return node_cls()``), so the factory is
the production-path hook the orchestrator overrides at startup. The
default factory is :class:`FakeKnowledgeClient` -- a misconfigured prod
env that forgets to override silently no-ops instead of leaking writes
to a real store.

TLP / classification handling
-----------------------------
The backend ``ingest_document`` raises ``TLPViolation`` on
``classification == "red"`` (Phase 0 follow-up). The engine Node passes
``classification`` through verbatim and the backend gate fires -- single
source of truth. This Node deliberately does NOT pre-validate the value;
duplicating the check here would mean two places to update next time the
TLP policy moves.
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


class KnowledgeUpsertInput(BaseModel):
    title: str = Field(
        ...,
        min_length=1,
        description="Human-readable document title (shown in search results).",
    )
    content: str = Field(
        ...,
        description="Full document body. The backend chunker splits this into "
        "embedded chunks; size limits are enforced server-side.",
    )
    source_type: str = Field(
        ...,
        min_length=1,
        description="Document source category (e.g. 'runbook', 'cti_report', 'postmortem'). "
        "Used by the search filter and by analytics.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form per-document metadata (author, tags, source URL, ...). "
        "Returned verbatim in search results.",
    )
    classification: str | None = Field(
        default=None,
        description="TLP classification ('white' / 'green' / 'amber' / 'amber_strict' / 'red'). "
        "Passed through to the backend; the backend gate raises TLPViolation on 'red'.",
    )


class KnowledgeUpsertOutput(BaseModel):
    document_id: str = Field(..., description="Backend-assigned document id (prefixed ULID).")
    chunks: int = Field(..., ge=0, description="Number of chunks the document was split into.")


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


@NodeRegistry.register
class KnowledgeUpsertNode(Node[KnowledgeUpsertInput, KnowledgeUpsertOutput]):
    """Persist a document to the knowledge base via the injected client."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="knowledge.upsert",
        name="Knowledge: Upsert",
        version="0.1.0",
        category=NodeCategory.KNOWLEDGE,
        description="Ingest a document into the RAG knowledge base. "
        "The backend chunks + embeds; classification is passed through "
        "to the backend's TLP gate (TLP:RED is rejected there).",
    )
    input_schema = KnowledgeUpsertInput
    output_schema = KnowledgeUpsertOutput

    # See module docstring for the rationale on the hybrid client wiring.
    client_factory: ClassVar[type[KnowledgeClient] | Any] = FakeKnowledgeClient

    def __init__(self, client: KnowledgeClient | None = None) -> None:
        # Constructor-injected client wins; fall back to the class factory so
        # the executor's no-arg ``node_cls()`` instantiation also works.
        self._client: KnowledgeClient = client or type(self).client_factory()

    async def run(
        self,
        input: KnowledgeUpsertInput,
        ctx: NodeContext,
    ) -> KnowledgeUpsertOutput:
        # Round-trip the field set verbatim. ``metadata`` is dict-copied to
        # avoid the client mutating the caller's dict (defensive -- the fake
        # doesn't, but a future HTTP client might serialize in-place).
        result = await self._client.upsert(
            title=input.title,
            content=input.content,
            source_type=input.source_type,
            metadata=dict(input.metadata),
            classification=input.classification,
        )
        return KnowledgeUpsertOutput(
            document_id=str(result["document_id"]),
            chunks=int(result["chunks"]),
        )
