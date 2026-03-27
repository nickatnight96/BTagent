"""Prompt budget hook — tracks token usage and enforces spending limits.

Monitors every LLM call, accumulates token counts and costs, emits TOKEN_USAGE
and COST_UPDATE events, and raises when the investigation exceeds its budget.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from langchain_core.callbacks import AsyncCallbackHandler, BaseCallbackHandler
from langchain_core.outputs import LLMResult

from btagent_agents.context.budget import estimate_tokens
from btagent_agents.events.emitter import RedisEmitter
from btagent_agents.hooks.base import HookProvider
from btagent_agents.llm.cost_calculator import CostAccumulator, calculate_cost
from btagent_shared.types.events import EventType

logger = logging.getLogger("btagent.hooks.prompt_budget")

# Model family detection for char/token ratio selection
_FAMILY_KEYWORDS: dict[str, str] = {
    "claude": "claude",
    "anthropic": "claude",
    "gpt": "gpt",
    "openai": "gpt",
    "o3": "gpt",
    "gemini": "gemini",
    "vertex": "gemini",
    "azure": "gpt",
    "llama": "ollama",
    "ollama": "ollama",
    "bedrock": "claude",
}

# Threshold at which to emit a warning (percentage of max_tokens)
WARN_THRESHOLD = 0.75


def _detect_family(model_name: str) -> str:
    """Detect model family from a model name string."""
    lower = model_name.lower()
    for keyword, family in _FAMILY_KEYWORDS.items():
        if keyword in lower:
            return family
    return "claude"  # safe default


class PromptBudgetExceeded(Exception):
    """Raised when the token budget is exhausted."""

    def __init__(self, used: int, limit: int) -> None:
        self.used = used
        self.limit = limit
        super().__init__(
            f"Token budget exceeded: {used:,} tokens used, limit is {limit:,}"
        )


class PromptBudgetCallback(AsyncCallbackHandler):
    """LangChain callback that tracks token usage and enforces budget limits."""

    def __init__(
        self,
        emitter: RedisEmitter,
        accumulator: CostAccumulator,
        max_tokens: int = 80_000,
        max_cost_usd: float = 5.0,
    ) -> None:
        super().__init__()
        self._emitter = emitter
        self._accumulator = accumulator
        self._max_tokens = max_tokens
        self._max_cost_usd = max_cost_usd
        self._warned = False
        self._current_model: str = ""

    async def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        model_name = serialized.get("name", serialized.get("id", ["unknown"])[-1])
        self._current_model = model_name

    async def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        model_name = serialized.get("name", serialized.get("id", ["unknown"])[-1])
        self._current_model = model_name

    async def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        model_name = self._current_model or "unknown"
        family = _detect_family(model_name)

        # Extract token usage from the response metadata
        input_tokens = 0
        output_tokens = 0
        cache_read = 0
        cache_write = 0

        llm_output = response.llm_output or {}
        usage = llm_output.get("usage", llm_output.get("token_usage", {}))

        if usage:
            input_tokens = usage.get("prompt_tokens", usage.get("input_tokens", 0))
            output_tokens = usage.get("completion_tokens", usage.get("output_tokens", 0))
            cache_read = usage.get("cache_read_input_tokens", usage.get("cache_read", 0))
            cache_write = usage.get("cache_creation_input_tokens", usage.get("cache_write", 0))
        else:
            # Fallback: estimate from text content
            for gen_list in response.generations:
                for gen in gen_list:
                    output_tokens += estimate_tokens(gen.text, family)
            # Input tokens are harder to estimate without the prompt; use a rough heuristic
            input_tokens = output_tokens * 3  # typical input:output ratio

        # Record in accumulator
        call_cost = self._accumulator.record(
            model=model_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read=cache_read,
            cache_write=cache_write,
        )

        # Emit TOKEN_USAGE event
        await self._emitter.emit(
            EventType.TOKEN_USAGE,
            model=model_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read=cache_read,
            cache_write=cache_write,
            call_cost_usd=round(call_cost, 6),
            total_input_tokens=self._accumulator.total_input_tokens,
            total_output_tokens=self._accumulator.total_output_tokens,
        )

        # Emit COST_UPDATE event
        await self._emitter.emit(
            EventType.COST_UPDATE,
            call_cost_usd=round(call_cost, 6),
            total_cost_usd=round(self._accumulator.total_cost_usd, 6),
            max_cost_usd=self._max_cost_usd,
            call_count=self._accumulator.call_count,
        )

        # Check warning threshold
        total_tokens = (
            self._accumulator.total_input_tokens
            + self._accumulator.total_output_tokens
        )
        threshold = int(self._max_tokens * WARN_THRESHOLD)

        if total_tokens >= threshold and not self._warned:
            self._warned = True
            pct = round(total_tokens / self._max_tokens * 100, 1)
            logger.warning(
                "Token budget at %s%% (%s / %s tokens)",
                pct, f"{total_tokens:,}", f"{self._max_tokens:,}",
            )
            await self._emitter.emit(
                EventType.NOTIFICATION,
                level="warning",
                message=f"Token budget at {pct}% ({total_tokens:,} / {self._max_tokens:,})",
                tokens_used=total_tokens,
                tokens_limit=self._max_tokens,
            )

        # Enforce hard limits
        if total_tokens >= self._max_tokens:
            raise PromptBudgetExceeded(total_tokens, self._max_tokens)

        if self._accumulator.total_cost_usd >= self._max_cost_usd:
            msg = (
                f"Cost budget exceeded: ${self._accumulator.total_cost_usd:.4f} "
                f"used, limit is ${self._max_cost_usd:.2f}"
            )
            await self._emitter.emit(
                EventType.ERROR,
                error=msg,
                error_type="CostBudgetExceeded",
                source="prompt_budget",
            )
            raise RuntimeError(msg)


class PromptBudgetHook(HookProvider):
    """Hook that monitors token usage and enforces budget constraints.

    Usage::

        accumulator = CostAccumulator()
        hook = PromptBudgetHook(
            emitter=emitter,
            accumulator=accumulator,
            max_tokens=80_000,
            max_cost_usd=5.0,
        )
        registry.register(hook, critical=True)
    """

    def __init__(
        self,
        emitter: RedisEmitter,
        accumulator: CostAccumulator | None = None,
        max_tokens: int = 80_000,
        max_cost_usd: float = 5.0,
    ) -> None:
        self._emitter = emitter
        self._accumulator = accumulator or CostAccumulator()
        self._max_tokens = max_tokens
        self._max_cost_usd = max_cost_usd

    def get_callbacks(self) -> list[BaseCallbackHandler]:
        return [
            PromptBudgetCallback(
                emitter=self._emitter,
                accumulator=self._accumulator,
                max_tokens=self._max_tokens,
                max_cost_usd=self._max_cost_usd,
            )
        ]

    @property
    def accumulator(self) -> CostAccumulator:
        """Access the cost accumulator for external queries."""
        return self._accumulator
