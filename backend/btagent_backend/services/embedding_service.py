"""Embedding service for generating vector representations of text.

Supports OpenAI text-embedding-3-small (1536-dim) and Ollama local embeddings.
TLP-aware: TLP:RED content always uses Ollama (local only) to prevent data leakage.
"""

from __future__ import annotations

import hashlib
import logging
import struct
from abc import ABC, abstractmethod
from typing import Any

import httpx

logger = logging.getLogger("btagent.services.embedding")

EMBEDDING_DIM = 1536


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class EmbeddingService(ABC):
    """Abstract base class for embedding generation."""

    @abstractmethod
    async def generate_embeddings(
        self, texts: list[str]
    ) -> list[list[float]]:
        """Generate embedding vectors for a list of texts.

        Parameters
        ----------
        texts : list[str]
            Input texts to embed.

        Returns
        -------
        list[list[float]]
            List of embedding vectors (each of length EMBEDDING_DIM).
        """
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable name of the embedding provider."""
        ...


# ---------------------------------------------------------------------------
# OpenAI implementation
# ---------------------------------------------------------------------------


class OpenAIEmbeddingService(EmbeddingService):
    """Generate embeddings using OpenAI text-embedding-3-small (1536-dim)."""

    def __init__(
        self,
        api_key: str,
        model: str = "text-embedding-3-small",
        base_url: str = "https://api.openai.com/v1",
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")

    @property
    def provider_name(self) -> str:
        return f"openai/{self._model}"

    async def generate_embeddings(
        self, texts: list[str]
    ) -> list[list[float]]:
        if not texts:
            return []

        url = f"{self._base_url}/embeddings"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self._model,
            "input": texts,
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()

        data = resp.json()
        # Sort by index to guarantee ordering
        embeddings_data = sorted(data["data"], key=lambda x: x["index"])
        embeddings = [item["embedding"] for item in embeddings_data]

        logger.info(
            "Generated %d embeddings via OpenAI (%s)",
            len(embeddings),
            self._model,
        )
        return embeddings


# ---------------------------------------------------------------------------
# Ollama implementation (local)
# ---------------------------------------------------------------------------


class OllamaEmbeddingService(EmbeddingService):
    """Generate embeddings using a local Ollama instance."""

    def __init__(
        self,
        model: str = "nomic-embed-text",
        base_url: str = "http://localhost:11434",
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")

    @property
    def provider_name(self) -> str:
        return f"ollama/{self._model}"

    async def generate_embeddings(
        self, texts: list[str]
    ) -> list[list[float]]:
        if not texts:
            return []

        embeddings: list[list[float]] = []
        url = f"{self._base_url}/api/embeddings"

        async with httpx.AsyncClient(timeout=120.0) as client:
            for text in texts:
                payload = {"model": self._model, "prompt": text}
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                embedding = data.get("embedding", [])
                # Pad or truncate to EMBEDDING_DIM if needed
                if len(embedding) < EMBEDDING_DIM:
                    embedding += [0.0] * (EMBEDDING_DIM - len(embedding))
                elif len(embedding) > EMBEDDING_DIM:
                    embedding = embedding[:EMBEDDING_DIM]
                embeddings.append(embedding)

        logger.info(
            "Generated %d embeddings via Ollama (%s)",
            len(embeddings),
            self._model,
        )
        return embeddings


# ---------------------------------------------------------------------------
# Mock implementation (for testing)
# ---------------------------------------------------------------------------


class MockEmbeddingService(EmbeddingService):
    """Deterministic mock embedding service for testing.

    Generates consistent fake vectors based on text content hashing,
    so the same text always produces the same embedding.
    """

    @property
    def provider_name(self) -> str:
        return "mock"

    async def generate_embeddings(
        self, texts: list[str]
    ) -> list[list[float]]:
        embeddings: list[list[float]] = []
        for text in texts:
            embeddings.append(_deterministic_vector(text))
        return embeddings


def _deterministic_vector(text: str) -> list[float]:
    """Generate a deterministic 1536-dim vector from text.

    Uses SHA-256 hash expanded to fill the vector dimension, giving
    consistent results for the same input text.
    """
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    # Expand the 32-byte digest to fill 1536 floats
    vector: list[float] = []
    for i in range(EMBEDDING_DIM):
        # Cycle through digest bytes, combine index for variation
        byte_idx = i % len(digest)
        seed = digest[byte_idx] ^ (i & 0xFF)
        # Normalize to [-1, 1] range
        val = (seed / 127.5) - 1.0
        vector.append(round(val, 6))
    # Normalize to unit vector
    magnitude = sum(v * v for v in vector) ** 0.5
    if magnitude > 0:
        vector = [round(v / magnitude, 6) for v in vector]
    return vector


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def get_embedding_service(settings: Any) -> EmbeddingService:
    """Factory that returns the appropriate embedding service based on config.

    Parameters
    ----------
    settings : Settings
        Application settings instance.

    Returns
    -------
    EmbeddingService
        Configured embedding service.

    Notes
    -----
    - If ``mock_connectors`` is True, returns MockEmbeddingService.
    - If ``embedding_provider`` is "ollama", returns OllamaEmbeddingService.
    - Otherwise returns OpenAIEmbeddingService.
    """
    if getattr(settings, "mock_connectors", False):
        logger.info("Using mock embedding service")
        return MockEmbeddingService()

    provider = getattr(settings, "embedding_provider", "openai")

    if provider == "ollama":
        model = getattr(settings, "embedding_model", "nomic-embed-text")
        base_url = getattr(
            settings, "ollama_base_url", "http://localhost:11434"
        )
        logger.info("Using Ollama embedding service: %s", model)
        return OllamaEmbeddingService(model=model, base_url=base_url)

    # Default: OpenAI
    api_key = getattr(settings, "openai_api_key", "")
    model = getattr(settings, "embedding_model", "text-embedding-3-small")
    logger.info("Using OpenAI embedding service: %s", model)
    return OpenAIEmbeddingService(api_key=api_key, model=model)


def get_tlp_aware_embedding_service(
    settings: Any, tlp_level: str = "green"
) -> EmbeddingService:
    """Return an embedding service that respects TLP classification.

    TLP:RED content must never be sent to external APIs, so this always
    returns the Ollama (local) or mock service for TLP:RED.
    """
    if tlp_level.lower() == "red":
        if getattr(settings, "mock_connectors", False):
            return MockEmbeddingService()
        model = getattr(settings, "embedding_model", "nomic-embed-text")
        logger.info(
            "TLP:RED — forcing local embedding service: ollama/%s", model
        )
        return OllamaEmbeddingService(model=model)

    return get_embedding_service(settings)
