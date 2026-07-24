"""Regression tests for the embeddings provider hardening (GH #383).

Before this fix, ``OpenAIEmbeddingService.generate_embeddings`` built an
``Authorization: Bearer {api_key}`` header unconditionally. With an empty
API key that became the literal ``Bearer `` (trailing space), which httpx
rejects with ``httpcore.LocalProtocolError`` — bubbling up as an opaque
HTTP 500 on ``/knowledge/ingest`` and ``/knowledge/query``. Because the
documented local dev flow (``make dev``) sets neither
``BTAGENT_MOCK_CONNECTORS`` nor ``OPENAI_API_KEY``, a stock local backend
500'd on every knowledge ingest/query.

These tests pin the fix at two levels:

* unit — an empty key never produces an illegal ``Bearer `` header; it yields
  a clear :class:`EmbeddingProviderError`, and the factory falls back to a
  usable local mock embedder in dev/test (but fails loudly in prod);
* route — an unconfigured/unreachable embeddings provider surfaces as a clean
  503, never a 500, and the stock test-env backend ingests successfully via
  the mock fallback.
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from btagent_backend.services import embedding_service
from btagent_backend.services.embedding_service import (
    EMBEDDING_DIM,
    EmbeddingProviderError,
    MockEmbeddingService,
    OllamaEmbeddingService,
    OpenAIEmbeddingService,
    get_embedding_service,
)
from btagent_backend.services.knowledge_service import KnowledgeService

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _settings(**overrides) -> SimpleNamespace:
    """A minimal settings stand-in (the factory only uses ``getattr``)."""
    base = {
        "mock_connectors": False,
        "embedding_provider": "openai",
        "openai_api_key": "",
        "embedding_model": "text-embedding-3-small",
        "ollama_base_url": "http://localhost:11434",
        "env": "test",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class _BoomClient:
    """Fake ``httpx.AsyncClient`` whose ``post`` always raises a transport error."""

    def __init__(self, *args, **kwargs) -> None:
        pass

    async def __aenter__(self) -> _BoomClient:
        return self

    async def __aexit__(self, *exc) -> bool:
        return False

    async def post(self, *args, **kwargs):
        raise httpx.ConnectError("connection refused")


# --------------------------------------------------------------------------- #
# Unit — OpenAI service with an empty key never emits an illegal Bearer header
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_openai_empty_key_raises_clear_error_not_illegal_header():
    """``OpenAIEmbeddingService('')`` fails with a clear provider error.

    The regression: the old code reached httpx with ``Bearer `` and raised
    ``httpcore.LocalProtocolError``. The guard now raises before any header is
    built, so the caller sees an actionable :class:`EmbeddingProviderError`.
    """
    svc = OpenAIEmbeddingService(api_key="")
    with pytest.raises(EmbeddingProviderError):
        await svc.generate_embeddings(["some text to embed"])


@pytest.mark.asyncio
async def test_openai_whitespace_key_also_guarded():
    svc = OpenAIEmbeddingService(api_key="   ")
    with pytest.raises(EmbeddingProviderError):
        await svc.generate_embeddings(["text"])


@pytest.mark.asyncio
async def test_openai_empty_input_short_circuits():
    """No key is needed to embed an empty batch (no outbound call)."""
    svc = OpenAIEmbeddingService(api_key="")
    assert await svc.generate_embeddings([]) == []


@pytest.mark.asyncio
async def test_openai_transport_error_mapped(monkeypatch):
    """A network/transport failure maps to EmbeddingProviderError, not a raw 500."""
    monkeypatch.setattr(embedding_service.httpx, "AsyncClient", _BoomClient)
    svc = OpenAIEmbeddingService(api_key="sk-configured-but-unreachable")
    with pytest.raises(EmbeddingProviderError):
        await svc.generate_embeddings(["hello"])


@pytest.mark.asyncio
async def test_ollama_unreachable_mapped(monkeypatch):
    """An unreachable local Ollama endpoint maps to EmbeddingProviderError."""
    monkeypatch.setattr(embedding_service.httpx, "AsyncClient", _BoomClient)
    svc = OllamaEmbeddingService()
    with pytest.raises(EmbeddingProviderError):
        await svc.generate_embeddings(["hello"])


# --------------------------------------------------------------------------- #
# Unit — factory selection
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_factory_falls_back_to_mock_in_test_env_without_key():
    """No key + env=test → a usable local mock embedder (stock ``make dev``)."""
    svc = get_embedding_service(_settings(env="test", openai_api_key=""))
    assert isinstance(svc, MockEmbeddingService)

    vectors = await svc.generate_embeddings(["hello", "world"])
    assert len(vectors) == 2
    assert all(len(v) == EMBEDDING_DIM for v in vectors)


def test_factory_falls_back_to_mock_in_dev_env_without_key():
    svc = get_embedding_service(_settings(env="dev", openai_api_key=""))
    assert isinstance(svc, MockEmbeddingService)


def test_factory_raises_in_prod_without_key():
    """Prod with no key fails loudly (clear config error), never an illegal header."""
    with pytest.raises(EmbeddingProviderError):
        get_embedding_service(_settings(env="prod", openai_api_key=""))


def test_factory_uses_openai_when_key_present():
    svc = get_embedding_service(_settings(env="prod", openai_api_key="sk-real-key"))
    assert isinstance(svc, OpenAIEmbeddingService)


def test_factory_mock_connectors_short_circuits():
    svc = get_embedding_service(_settings(mock_connectors=True, openai_api_key=""))
    assert isinstance(svc, MockEmbeddingService)


def test_factory_selects_ollama_provider():
    svc = get_embedding_service(_settings(embedding_provider="ollama", openai_api_key=""))
    assert isinstance(svc, OllamaEmbeddingService)


# --------------------------------------------------------------------------- #
# Route — /knowledge ingest & query never 500 on embedding-provider failure
# --------------------------------------------------------------------------- #


class _RaisingEmbeddingService:
    """Embedding service that always fails as if the provider were unconfigured."""

    @property
    def provider_name(self) -> str:
        return "raising"

    async def generate_embeddings(self, texts):
        raise EmbeddingProviderError("Embeddings provider not configured")


@pytest.fixture()
def _force_provider_failure(monkeypatch):
    """Patch the route's service factory to use a provider that always fails."""
    import btagent_backend.api.v1.knowledge as knowledge_api

    monkeypatch.setattr(
        knowledge_api,
        "_get_knowledge_service",
        lambda: KnowledgeService(embedding_service=_RaisingEmbeddingService()),
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_ingest_stock_test_env_succeeds_via_mock_fallback(client, admin_token):
    """Stock test-env backend (no key, mocks off) ingests via the mock fallback.

    This is the primary GH #383 regression: previously this path 500'd on the
    illegal ``Bearer `` header. It must now succeed (mock fallback), never 500.
    """
    resp = await client.post(
        "/api/v1/knowledge/ingest",
        headers=_auth(admin_token),
        json={
            "title": "Local dev runbook",
            "content": "PsExec lateral movement detection notes. " * 5,
            "source_type": "runbook",
        },
    )
    assert resp.status_code != 500, resp.text
    assert resp.status_code == 201, resp.text


@pytest.mark.asyncio
async def test_ingest_returns_503_when_provider_fails(client, admin_token, _force_provider_failure):
    """An unconfigured/unreachable embeddings provider → clean 503, not 500."""
    resp = await client.post(
        "/api/v1/knowledge/ingest",
        headers=_auth(admin_token),
        json={
            "title": "Doc that needs embeddings",
            "content": "content requiring embedding generation " * 5,
            "source_type": "runbook",
        },
    )
    assert resp.status_code == 503, resp.text
    assert resp.json()["detail"] == "Embeddings provider not configured"


@pytest.mark.asyncio
async def test_query_returns_503_when_provider_fails(client, admin_token, _force_provider_failure):
    """Query embeds the search text — a provider failure → 503, not 500."""
    resp = await client.post(
        "/api/v1/knowledge/query",
        headers=_auth(admin_token),
        json={"query": "lateral movement", "top_k": 5},
    )
    assert resp.status_code == 503, resp.text
    assert resp.json()["detail"] == "Embeddings provider not configured"
