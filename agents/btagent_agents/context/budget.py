"""Token estimation utilities for context budget management.

Uses character-to-token ratios per model family rather than a full tokenizer
dependency. This is intentionally approximate -- good enough for budget
decisions without pulling in tiktoken or sentencepiece.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Model-family character/token ratios
# ---------------------------------------------------------------------------
# These are empirical averages for English text. A ratio of 3.7 means ~3.7
# characters per token on average for that model family.

MODEL_FAMILY_RATIOS: dict[str, float] = {
    "claude": 3.7,
    "anthropic": 3.7,
    "gpt": 4.0,
    "openai": 4.0,
    "o3": 4.0,
    "gemini": 4.2,
    "vertex_ai": 4.2,
    "azure": 4.0,
    "ollama": 4.0,
    "llama": 4.0,
    "bedrock": 3.7,  # Bedrock hosts Anthropic models primarily
}

DEFAULT_RATIO = 4.0

# Overhead tokens per message (role markers, separators, etc.)
PER_MESSAGE_OVERHEAD = 4


def _resolve_ratio(model_family: str) -> float:
    """Resolve the char/token ratio for a model family string."""
    family_lower = model_family.lower()
    for key, ratio in MODEL_FAMILY_RATIOS.items():
        if key in family_lower:
            return ratio
    return DEFAULT_RATIO


def estimate_tokens(text: str, model_family: str = "claude") -> int:
    """Estimate the number of tokens in a text string.

    Args:
        text: The text to estimate.
        model_family: Model family name (e.g., "claude", "gpt", "gemini").
            Used to select the appropriate char/token ratio.

    Returns:
        Estimated token count (always >= 1 for non-empty text).
    """
    if not text:
        return 0
    ratio = _resolve_ratio(model_family)
    return max(1, int(len(text) / ratio))


def estimate_message_tokens(
    messages: list[dict[str, Any]],
    model_family: str = "claude",
) -> int:
    """Estimate total tokens for a list of chat messages.

    Each message is expected to have at least a ``content`` field (str or list).
    System, user, assistant, and tool messages are all counted.

    Args:
        messages: List of message dicts with ``role`` and ``content`` keys.
            Content can be a string or a list of content blocks (multimodal).
        model_family: Model family for ratio selection.

    Returns:
        Estimated total token count across all messages.
    """
    total = 0
    for msg in messages:
        total += PER_MESSAGE_OVERHEAD  # role markers, formatting

        content = msg.get("content", "")
        if isinstance(content, str):
            total += estimate_tokens(content, model_family)
        elif isinstance(content, list):
            # Multimodal content blocks (text, image, tool_use, etc.)
            for block in content:
                if isinstance(block, dict):
                    text = block.get("text", "")
                    if text:
                        total += estimate_tokens(text, model_family)
                    # Image blocks: rough estimate based on typical vision token counts
                    if block.get("type") == "image":
                        total += 1000  # conservative estimate for image tokens
                elif isinstance(block, str):
                    total += estimate_tokens(block, model_family)

        # Tool call/result content
        tool_calls = msg.get("tool_calls", [])
        for tc in tool_calls:
            fn = tc.get("function", {})
            total += estimate_tokens(fn.get("name", ""), model_family)
            total += estimate_tokens(str(fn.get("arguments", "")), model_family)

    return total


def tokens_remaining(
    messages: list[dict[str, Any]],
    max_tokens: int,
    model_family: str = "claude",
) -> int:
    """Calculate how many tokens remain within a budget.

    Args:
        messages: Current conversation messages.
        max_tokens: The token budget ceiling.
        model_family: Model family for ratio selection.

    Returns:
        Remaining tokens (may be negative if over budget).
    """
    used = estimate_message_tokens(messages, model_family)
    return max_tokens - used


def is_over_budget(
    messages: list[dict[str, Any]],
    max_tokens: int,
    model_family: str = "claude",
) -> bool:
    """Check if the current conversation exceeds the token budget."""
    return tokens_remaining(messages, max_tokens, model_family) < 0
