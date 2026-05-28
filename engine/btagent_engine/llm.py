"""Process-local LLM client registry.

Mirrors ``NodeRegistry``: a settable, process-local accessor the engine's
reasoning nodes consult to find the active :class:`LLMClient`. Kept off
``NodeContext`` because that model is frozen + JSON-serialisable for
snapshot/replay and must not hold live (unserialisable) client objects.

Contract:
  * ``set_llm_client(client)`` — the host (backend/agents) registers the
    concrete LiteLLM-backed client at startup.
  * ``get_llm_client()`` — reasoning nodes fetch it; ``None`` means "no
    client registered, fall back to the deterministic mock path".
  * ``clear_llm_client()`` — test teardown.

A module global (not a contextvar) is deliberate: it matches the
NodeRegistry pattern, and per-request TLP routing is carried on the
``LLMRequest`` rather than on the client instance, so one shared client
serves all requests.
"""

from __future__ import annotations

from btagent_shared.llm import LLMClient

_client: LLMClient | None = None


def set_llm_client(client: LLMClient | None) -> None:
    """Register (or clear, with None) the process-wide LLM client."""
    global _client
    _client = client


def get_llm_client() -> LLMClient | None:
    """Return the registered client, or None if the engine should mock."""
    return _client


def clear_llm_client() -> None:
    """Drop the registered client (test teardown)."""
    global _client
    _client = None


__all__ = ["clear_llm_client", "get_llm_client", "set_llm_client"]
