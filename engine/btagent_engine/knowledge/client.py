"""Knowledge-base I/O contract consumed by the knowledge Nodes.

The engine package must not depend on ``btagent_backend``; the Knowledge
Nodes therefore talk to the RAG store through this :class:`KnowledgeClient`
Protocol. Production wires an HTTP client in agents/orchestrator that hits
the FastAPI ``/api/v1/knowledge/`` endpoints (Sprint 5). Tests inject
:class:`FakeKnowledgeClient`.

Why a Protocol (and not an ABC)?

* Structural typing -- the orchestrator can wire any object that quacks like
  one, including an HTTP client whose method set is wider than this one.
* No inheritance coupling -- the engine doesn't own the production impl,
  so an ABC would force an awkward import ordering (impl -> engine -> impl).
* mypy / pyright still type-check the contract because Protocol is treated
  as nominal-by-default for the consumer side.

TLP / classification handling: the backend ``ingest_document`` already
raises ``TLPViolation`` when ``classification == "red"`` (Phase 0 follow-up).
The engine Node passes ``classification`` straight through; the gate fires
on the backend. Single source of truth -- do NOT reproduce the check here.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class KnowledgeClient(Protocol):
    """Knowledge-base I/O contract.

    Production wires an HTTP client that talks to the FastAPI backend; tests
    inject a fake. The Protocol is intentionally narrow -- only the two
    operations the Knowledge Nodes call are part of the contract; anything
    richer (delete, list, reindex) lives on the production HTTP client and
    isn't surfaced to the engine.
    """

    async def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        source_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return up to ``top_k`` chunks with content + metadata + score.

        Each result dict is expected to carry, at minimum:
          - ``chunk_content``: str
          - ``document_title``: str
          - ``source_type``: str
          - ``relevance_score``: float
          - ``metadata``: dict
        Extra keys are ignored by the Node adaptor.
        """

    async def upsert(
        self,
        *,
        title: str,
        content: str,
        source_type: str,
        metadata: dict[str, Any] | None = None,
        classification: str | None = None,
    ) -> dict[str, Any]:
        """Persist a document. Returns ``{"document_id": ..., "chunks": N}``."""


class FakeKnowledgeClient:
    """In-process stub used by engine tests and as the default client when no
    production wiring has been injected.

    Records every call so tests can assert on the contract surface. Holds a
    pre-seeded chunk list for ``search``; call ``seed`` to load fixtures.
    The class deliberately does NOT enforce TLP -- that is the backend's job
    (see module docstring). It records ``classification`` so tests can verify
    the Node is passing it through correctly.
    """

    def __init__(self) -> None:
        self._seeded: list[dict[str, Any]] = []
        self.search_calls: list[dict[str, Any]] = []
        self.upsert_calls: list[dict[str, Any]] = []
        # Counter so each upsert gets a deterministic, unique document_id;
        # tests can assert on ordering without monkey-patching ULIDs.
        self._next_doc_seq: int = 1

    # ------------------------------------------------------------------
    # Test helpers (not part of the Protocol)
    # ------------------------------------------------------------------

    def seed(self, chunks: list[dict[str, Any]]) -> None:
        """Replace the seeded chunk list returned by ``search``."""
        self._seeded = list(chunks)

    # ------------------------------------------------------------------
    # KnowledgeClient implementation
    # ------------------------------------------------------------------

    async def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        source_type: str | None = None,
    ) -> list[dict[str, Any]]:
        self.search_calls.append({"query": query, "top_k": top_k, "source_type": source_type})
        results = self._seeded
        if source_type is not None:
            results = [c for c in results if c.get("source_type") == source_type]
        return results[:top_k]

    async def upsert(
        self,
        *,
        title: str,
        content: str,
        source_type: str,
        metadata: dict[str, Any] | None = None,
        classification: str | None = None,
    ) -> dict[str, Any]:
        self.upsert_calls.append(
            {
                "title": title,
                "content": content,
                "source_type": source_type,
                "metadata": dict(metadata or {}),
                "classification": classification,
            }
        )
        doc_id = f"doc_fake_{self._next_doc_seq:04d}"
        self._next_doc_seq += 1
        # Approximate the backend's chunking: roughly 1 chunk per 500 chars,
        # min 1. Tests don't depend on the exact number, only that it's > 0.
        chunks = max(1, (len(content) + 499) // 500)
        return {"document_id": doc_id, "chunks": chunks}
