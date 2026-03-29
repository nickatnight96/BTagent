"""Per-model pricing and cost tracking for BTagent LLM usage.

Pricing is in USD per 1M tokens (input / output / cache_read / cache_write).
Prices are approximate as of early 2026; update when providers change pricing.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("btagent.llm.cost")


@dataclass(frozen=True)
class ModelPricing:
    """Per-million-token pricing for a single model."""

    input_per_m: float
    output_per_m: float
    cache_read_per_m: float = 0.0
    cache_write_per_m: float = 0.0


# ---------------------------------------------------------------------------
# Pricing table (USD per 1M tokens)
# ---------------------------------------------------------------------------

PRICING: dict[str, ModelPricing] = {
    # Anthropic
    "claude-haiku-4-5-20251001": ModelPricing(
        input_per_m=0.80,
        output_per_m=4.00,
        cache_read_per_m=0.08,
        cache_write_per_m=1.00,
    ),
    "claude-sonnet-4-20250514": ModelPricing(
        input_per_m=3.00,
        output_per_m=15.00,
        cache_read_per_m=0.30,
        cache_write_per_m=3.75,
    ),
    "claude-opus-4-20250415": ModelPricing(
        input_per_m=15.00,
        output_per_m=75.00,
        cache_read_per_m=1.50,
        cache_write_per_m=18.75,
    ),
    # OpenAI
    "gpt-4o-mini": ModelPricing(
        input_per_m=0.15,
        output_per_m=0.60,
    ),
    "gpt-4o": ModelPricing(
        input_per_m=2.50,
        output_per_m=10.00,
    ),
    "o3": ModelPricing(
        input_per_m=10.00,
        output_per_m=40.00,
    ),
    # Google Vertex AI / Gemini
    "gemini-2.0-flash": ModelPricing(
        input_per_m=0.10,
        output_per_m=0.40,
    ),
    "gemini-2.5-pro": ModelPricing(
        input_per_m=1.25,
        output_per_m=10.00,
    ),
    "gemini-ultra": ModelPricing(
        input_per_m=7.00,
        output_per_m=21.00,
    ),
    # Azure (same models as OpenAI, pricing may differ slightly)
    "azure/gpt-4o-mini": ModelPricing(
        input_per_m=0.15,
        output_per_m=0.60,
    ),
    "azure/gpt-4o": ModelPricing(
        input_per_m=2.50,
        output_per_m=10.00,
    ),
    # AWS Bedrock (Anthropic models on Bedrock)
    "bedrock/claude-haiku-4-5-20251001": ModelPricing(
        input_per_m=1.00,
        output_per_m=5.00,
        cache_read_per_m=0.10,
        cache_write_per_m=1.25,
    ),
    "bedrock/claude-sonnet-4-20250514": ModelPricing(
        input_per_m=3.00,
        output_per_m=15.00,
        cache_read_per_m=0.30,
        cache_write_per_m=3.75,
    ),
    "bedrock/claude-opus-4-20250415": ModelPricing(
        input_per_m=15.00,
        output_per_m=75.00,
        cache_read_per_m=1.50,
        cache_write_per_m=18.75,
    ),
    # Ollama (local, free)
    "llama3.3": ModelPricing(
        input_per_m=0.0,
        output_per_m=0.0,
    ),
}

# Fallback for unknown models
_DEFAULT_PRICING = ModelPricing(input_per_m=3.00, output_per_m=15.00)


def get_pricing(model: str) -> ModelPricing:
    """Look up pricing for a model, falling back to default if unknown."""
    pricing = PRICING.get(model)
    if pricing is None:
        # Try partial match (e.g., "claude-sonnet" matches "claude-sonnet-4-...")
        for key, val in PRICING.items():
            if model in key or key in model:
                return val
        logger.warning("No pricing found for model %r, using default", model)
        return _DEFAULT_PRICING
    return pricing


def calculate_cost(
    model: str,
    input_tokens: int,
    output_tokens: int,
    cache_read: int = 0,
    cache_write: int = 0,
) -> float:
    """Calculate the cost in USD for a single LLM invocation.

    Args:
        model: Model identifier (e.g., "claude-sonnet-4-20250514").
        input_tokens: Number of non-cached input tokens.
        output_tokens: Number of output tokens.
        cache_read: Tokens read from prompt cache.
        cache_write: Tokens written to prompt cache.

    Returns:
        Cost in USD (float).
    """
    pricing = get_pricing(model)
    cost = (
        (input_tokens / 1_000_000) * pricing.input_per_m
        + (output_tokens / 1_000_000) * pricing.output_per_m
        + (cache_read / 1_000_000) * pricing.cache_read_per_m
        + (cache_write / 1_000_000) * pricing.cache_write_per_m
    )
    return cost


@dataclass
class CostAccumulator:
    """Track cumulative cost across an investigation.

    Thread-safe for single-threaded async contexts (no locking needed since
    LangGraph processes steps sequentially within a graph).
    """

    model: str = ""
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cache_read: int = 0
    total_cache_write: int = 0
    total_cost_usd: float = 0.0
    call_count: int = 0
    history: list[dict[str, Any]] = field(default_factory=list)

    def record(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cache_read: int = 0,
        cache_write: int = 0,
    ) -> float:
        """Record a single LLM call and return its cost.

        Returns:
            The cost of this individual call in USD.
        """
        cost = calculate_cost(model, input_tokens, output_tokens, cache_read, cache_write)
        self.model = model
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_cache_read += cache_read
        self.total_cache_write += cache_write
        self.total_cost_usd += cost
        self.call_count += 1
        self.history.append(
            {
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cache_read": cache_read,
                "cache_write": cache_write,
                "cost_usd": cost,
            }
        )
        return cost

    def summary(self) -> dict[str, Any]:
        """Return a summary dict suitable for event emission."""
        return {
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cache_read": self.total_cache_read,
            "total_cache_write": self.total_cache_write,
            "total_cost_usd": round(self.total_cost_usd, 6),
            "call_count": self.call_count,
        }
