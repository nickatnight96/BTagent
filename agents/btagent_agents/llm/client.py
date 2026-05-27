"""LiteLLM-backed implementation of the engine's LLMClient protocol.

Bridges the engine's transport-neutral ``btagent_shared.llm.LLMClient``
contract to the TLP-aware :class:`LLMRouter` (LiteLLM via LangChain).
The engine's reasoning nodes call ``client.complete(request)``; this
class resolves the provider+model by (TLP, tier), invokes it, and maps
the result back to an ``LLMResponse``.

Wiring: the host process (backend/agents bootstrap) constructs one of
these and registers it via ``btagent_engine.llm.set_llm_client(...)``.
Until then the engine falls back to its deterministic mock path, so
demos + tests run with no API keys.
"""

from __future__ import annotations

import logging
from typing import Any

from btagent_shared.llm import LLMRequest, LLMResponse, LLMUsage

from btagent_agents.llm.router import TLPAwareLLMRouter

logger = logging.getLogger("btagent.llm.client")


class LiteLLMClient:
    """Concrete LLMClient: routes by (TLP, tier) and calls via LiteLLM."""

    def __init__(self, router: TLPAwareLLMRouter | None = None) -> None:
        self._router = router or TLPAwareLLMRouter()

    async def complete(self, request: LLMRequest) -> LLMResponse:
        from langchain_core.messages import (
            AIMessage,
            HumanMessage,
            SystemMessage,
        )

        llm = self._router.get_llm(
            request.tlp,
            request.tier,
            preferred_provider=request.preferred_provider,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
        )
        provider, model_id = self._router.resolve(
            request.tlp, request.tier, request.preferred_provider
        )

        role_map = {
            "system": SystemMessage,
            "user": HumanMessage,
            "assistant": AIMessage,
        }
        lc_messages = [
            role_map.get(m.role, HumanMessage)(content=m.content)
            for m in request.messages
        ]

        result = await llm.ainvoke(lc_messages)
        content = result.content if isinstance(result.content, str) else str(result.content)

        return LLMResponse(
            content=content,
            provider=str(provider),
            model=model_id,
            usage=_usage_from(result),
        )


def _usage_from(result: Any) -> LLMUsage:
    """Best-effort extraction of token usage from a LangChain AIMessage.

    Newer LangChain attaches ``usage_metadata``; older builds put counts
    under ``response_metadata['token_usage']``. Cost is left 0.0 here —
    the cost calculator (agents/llm/cost_calculator.py) can enrich it
    downstream where the per-model price table lives.
    """
    um = getattr(result, "usage_metadata", None)
    if isinstance(um, dict):
        return LLMUsage(
            input_tokens=int(um.get("input_tokens", 0)),
            output_tokens=int(um.get("output_tokens", 0)),
        )
    meta = getattr(result, "response_metadata", None)
    if isinstance(meta, dict):
        tu = meta.get("token_usage") or meta.get("usage") or {}
        if isinstance(tu, dict):
            return LLMUsage(
                input_tokens=int(tu.get("prompt_tokens", 0)),
                output_tokens=int(tu.get("completion_tokens", 0)),
            )
    return LLMUsage()


__all__ = ["LiteLLMClient"]
