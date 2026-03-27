"""Classification hook — TLP tagging and data leak prevention.

Tags all agent outputs with the investigation's TLP level and enforces that
TLP:RED data is never sent to external (non-local) LLM providers.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from langchain_core.callbacks import AsyncCallbackHandler, BaseCallbackHandler
from langchain_core.outputs import LLMResult

from btagent_agents.events.emitter import RedisEmitter
from btagent_agents.hooks.base import HookProvider
from btagent_shared.types.config import ModelProvider, TLP
from btagent_shared.types.events import EventType

logger = logging.getLogger("btagent.hooks.classification")

# Providers considered "local" / on-premises (safe for TLP:RED)
_LOCAL_PROVIDERS: frozenset[str] = frozenset({
    ModelProvider.OLLAMA,
})

# Providers considered "trusted cloud" (safe for TLP:AMBER_STRICT and below)
_TRUSTED_CLOUD_PROVIDERS: frozenset[str] = frozenset({
    ModelProvider.OLLAMA,
    ModelProvider.BEDROCK,
})

# TLP routing rules: which providers are allowed per classification level
TLP_ALLOWED_PROVIDERS: dict[TLP, frozenset[str]] = {
    TLP.RED: frozenset({ModelProvider.OLLAMA}),
    TLP.AMBER_STRICT: frozenset({ModelProvider.OLLAMA, ModelProvider.BEDROCK}),
    TLP.AMBER: frozenset({
        ModelProvider.ANTHROPIC, ModelProvider.BEDROCK, ModelProvider.VERTEX_AI,
    }),
    TLP.GREEN: frozenset({
        ModelProvider.ANTHROPIC, ModelProvider.OPENAI,
        ModelProvider.BEDROCK, ModelProvider.VERTEX_AI, ModelProvider.OLLAMA,
    }),
    TLP.WHITE: frozenset({
        ModelProvider.ANTHROPIC, ModelProvider.OPENAI,
        ModelProvider.BEDROCK, ModelProvider.VERTEX_AI,
        ModelProvider.AZURE, ModelProvider.OLLAMA,
    }),
}


class TLPViolation(Exception):
    """Raised when classified data would be sent to an unauthorized provider."""

    def __init__(self, tlp: TLP, provider: str) -> None:
        self.tlp = tlp
        self.provider = provider
        super().__init__(
            f"TLP:{tlp.value.upper()} data cannot be sent to provider {provider!r}"
        )


def is_provider_allowed(tlp: TLP, provider: str) -> bool:
    """Check if a provider is authorized for the given TLP level."""
    allowed = TLP_ALLOWED_PROVIDERS.get(tlp)
    if allowed is None:
        return False
    return provider in allowed


class ClassificationCallback(AsyncCallbackHandler):
    """LangChain callback that enforces TLP classification on LLM interactions."""

    def __init__(
        self,
        emitter: RedisEmitter,
        tlp_level: TLP,
        provider: str,
        investigation_id: str,
    ) -> None:
        super().__init__()
        self._emitter = emitter
        self._tlp_level = tlp_level
        self._provider = provider
        self._investigation_id = investigation_id

    async def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        await self._check_tlp_compliance(serialized, run_id)

    async def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        await self._check_tlp_compliance(serialized, run_id)

    async def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        # Tag the output with TLP metadata for downstream consumers
        # This is informational — the enforcement happens at LLM start
        for gen_list in response.generations:
            for gen in gen_list:
                if hasattr(gen, "generation_info") and gen.generation_info is not None:
                    gen.generation_info["tlp_level"] = self._tlp_level.value

    async def _check_tlp_compliance(
        self, serialized: dict[str, Any], run_id: UUID
    ) -> None:
        """Verify that the current provider is allowed for the TLP level."""
        if is_provider_allowed(self._tlp_level, self._provider):
            return

        model_name = serialized.get("name", serialized.get("id", ["unknown"])[-1])

        await self._emitter.emit(
            EventType.ERROR,
            error=(
                f"TLP:{self._tlp_level.value.upper()} data cannot be sent "
                f"to provider {self._provider!r} (model: {model_name})"
            ),
            error_type="TLPViolation",
            source="classification",
            tlp_level=self._tlp_level.value,
            provider=self._provider,
            model=model_name,
            run_id=str(run_id),
        )

        logger.error(
            "TLP violation: %s data sent to provider %s (model=%s)",
            self._tlp_level.value,
            self._provider,
            model_name,
        )

        raise TLPViolation(self._tlp_level, self._provider)


class ClassificationHook(HookProvider):
    """Hook that enforces TLP classification on all LLM interactions.

    Prevents classified data from leaking to unauthorized LLM providers.
    TLP:RED data is only allowed on local (Ollama) providers. TLP:AMBER_STRICT
    adds Bedrock. Higher TLP levels progressively allow more providers.

    Usage::

        hook = ClassificationHook(
            emitter=emitter,
            tlp_level=TLP.RED,
            provider=ModelProvider.ANTHROPIC,
            investigation_id="inv_01HX...",
        )
        registry.register(hook, critical=True)
    """

    def __init__(
        self,
        emitter: RedisEmitter,
        tlp_level: TLP,
        provider: str,
        investigation_id: str,
    ) -> None:
        self._emitter = emitter
        self._tlp_level = tlp_level
        self._provider = provider
        self._investigation_id = investigation_id

    def get_callbacks(self) -> list[BaseCallbackHandler]:
        return [
            ClassificationCallback(
                emitter=self._emitter,
                tlp_level=self._tlp_level,
                provider=self._provider,
                investigation_id=self._investigation_id,
            )
        ]

    @property
    def tlp_level(self) -> TLP:
        return self._tlp_level
