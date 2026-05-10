"""Production wiring of ``btagent_engine.knowledge.KnowledgeClient``.

The engine ships a Protocol (Sprint 4C) so it stays standalone -- it
never imports from ``btagent_backend``. This module is the agents-side
production implementation that talks to the FastAPI backend's
``/api/v1/knowledge/...`` endpoints.

Importing this module sets ``KnowledgeSearchNode.client_factory`` and
``KnowledgeUpsertNode.client_factory`` so the runner-instantiated Nodes
get the production client by default. Override per-test by passing a
``KnowledgeClient`` instance to the Node constructor directly.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx
from btagent_engine.knowledge import KnowledgeClient, KnowledgeSearchNode, KnowledgeUpsertNode

logger = logging.getLogger("btagent.orchestrator.knowledge_client")


def _backend_base_url() -> str:
    """Resolve the backend's base URL.

    Honours ``BTAGENT_BACKEND_URL`` (the orchestrator config knob) and
    falls back to the in-cluster ``http://backend:8000`` so a kubernetes
    deployment without explicit config still hits the right service.
    """
    return os.getenv("BTAGENT_BACKEND_URL", "http://backend:8000").rstrip("/")


def _service_token() -> str | None:
    """Service-to-service token for backend calls.

    The orchestrator runs as a long-lived service rather than per-user,
    so it carries its own bearer token. ``BTAGENT_ORCHESTRATOR_TOKEN``
    is set at deploy time; absent in tests.
    """
    return os.getenv("BTAGENT_ORCHESTRATOR_TOKEN")


class HttpKnowledgeClient(KnowledgeClient):
    """KnowledgeClient backed by HTTP calls to the FastAPI knowledge API."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        token: str | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        self._base_url = (base_url or _backend_base_url()).rstrip("/")
        self._token = token if token is not None else _service_token()
        self._timeout = httpx.Timeout(timeout_seconds)

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        source_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Hybrid search via ``POST /api/v1/knowledge/query``."""
        if not query.strip():
            return []
        url = f"{self._base_url}/api/v1/knowledge/query"
        body: dict[str, Any] = {"query": query, "top_k": top_k}
        if source_type is not None:
            body["source_type_filter"] = source_type
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(url, json=body, headers=self._headers())
            response.raise_for_status()
            payload = response.json()
        # Backend returns ``{"query": ..., "results": [...]}`` -- engine wants
        # the ``results`` list as ``[{chunk_content, document_title, ...}]``.
        return list(payload.get("results", []))

    async def upsert(
        self,
        *,
        title: str,
        content: str,
        source_type: str,
        metadata: dict[str, Any] | None = None,
        classification: str | None = None,
    ) -> dict[str, Any]:
        """Ingest via ``POST /api/v1/knowledge/ingest``.

        Note: the backend's ingest endpoint enforces the TLP egress gate
        (Phase 0 follow-up). Passing ``classification="red"`` will return
        a TLP error from the backend. The engine Node deliberately does
        not duplicate that check -- single source of truth.
        """
        url = f"{self._base_url}/api/v1/knowledge/ingest"
        body: dict[str, Any] = {
            "title": title,
            "content": content,
            "source_type": source_type,
            "metadata": metadata or {},
        }
        if classification is not None:
            body["classification"] = classification
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(url, json=body, headers=self._headers())
            response.raise_for_status()
            payload = response.json()
        # Backend returns ``{id, title, source_type, token_count, message}``.
        # Engine expects ``{document_id, chunks}`` -- adapt.
        return {
            "document_id": payload.get("id", ""),
            "chunks": int(payload.get("token_count", 0) // 512) or 1,
        }


def install_as_default() -> None:
    """Wire ``HttpKnowledgeClient`` as the default for the engine's
    Knowledge Nodes. Call once at orchestrator startup."""
    KnowledgeSearchNode.client_factory = HttpKnowledgeClient  # type: ignore[assignment]
    KnowledgeUpsertNode.client_factory = HttpKnowledgeClient  # type: ignore[assignment]
    logger.info(
        "HttpKnowledgeClient installed as default factory for "
        "KnowledgeSearchNode + KnowledgeUpsertNode (base_url=%s)",
        _backend_base_url(),
    )


__all__ = ["HttpKnowledgeClient", "install_as_default"]
