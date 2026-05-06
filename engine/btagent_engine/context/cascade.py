"""4-layer context-window reduction cascade.

See the package docstring (:mod:`btagent_engine.context`) for the
narrative. This module owns the per-layer functions and the orchestrator.

Token estimation is intentionally a small built-in (char/token ratio
per model family) rather than a real tokeniser dep -- the cascade
makes *budget* decisions, not exact ones, and pulling in tiktoken /
sentencepiece on the engine side would be heavyweight overkill.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.context.artifacts import (
    ArtifactRef,
    content_byte_length,
    make_artifact_ref,
)

logger = logging.getLogger("btagent_engine.context.cascade")


# --------------------------------------------------------------------------- #
# Token estimation (cheap, family-aware, no tokeniser dep)
# --------------------------------------------------------------------------- #

_MODEL_FAMILY_RATIOS: dict[str, float] = {
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
    "bedrock": 3.7,
}
_DEFAULT_RATIO = 4.0
_PER_MESSAGE_OVERHEAD = 4


def _resolve_ratio(model_family: str) -> float:
    family_lower = model_family.lower()
    for key, ratio in _MODEL_FAMILY_RATIOS.items():
        if key in family_lower:
            return ratio
    return _DEFAULT_RATIO


def estimate_tokens(text: str, model_family: str = "claude") -> int:
    """Rough token count for *text* under *model_family*'s avg char/token ratio."""
    if not text:
        return 0
    return max(1, int(len(text) / _resolve_ratio(model_family)))


def estimate_message_tokens(
    messages: list[dict[str, Any]],
    model_family: str = "claude",
) -> int:
    """Sum-of-message-tokens estimate including a per-message overhead."""
    total = 0
    for msg in messages:
        total += _PER_MESSAGE_OVERHEAD
        content = msg.get("content", "")
        if isinstance(content, str):
            total += estimate_tokens(content, model_family)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    text = block.get("text", "")
                    if text:
                        total += estimate_tokens(text, model_family)
                    if block.get("type") == "image":
                        total += 1000  # conservative vision-token estimate
                elif isinstance(block, str):
                    total += estimate_tokens(block, model_family)
        for tc in msg.get("tool_calls", []) or []:
            fn = tc.get("function", {}) if isinstance(tc, dict) else {}
            total += estimate_tokens(fn.get("name", ""), model_family)
            total += estimate_tokens(str(fn.get("arguments", "")), model_family)
    return total


# --------------------------------------------------------------------------- #
# Thresholds (tunable; see ContextLayer / apply_cascade for use)
# --------------------------------------------------------------------------- #

EXTERNALIZE_THRESHOLD = 10_240  # 10 KiB
COMPRESS_THRESHOLD = 3_072  # 3 KiB
PRUNE_KEEP_FIRST = 2  # system prompt + initial user message
PRUNE_KEEP_LAST = 3  # tail context for continuity
JSON_SAMPLE_ITEMS = 5
TEXT_TRUNCATE_SUFFIX = "\n\n[... truncated -- full output in artifact store ...]"


class ContextLayer(str, Enum):  # noqa: UP042
    """The four cascade stages, in apply order."""

    EXTERNALIZE = "externalize"
    COMPRESS = "compress"
    PRUNE = "prune"
    SUMMARIZE = "summarize"


class CascadeResult(BaseModel):
    """Output of :func:`apply_cascade`."""

    model_config = ConfigDict(extra="forbid")

    messages: list[dict[str, Any]] = Field(default_factory=list)
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    layers_applied: list[ContextLayer] = Field(default_factory=list)
    final_token_estimate: int = 0
    fits_budget: bool = True


# --------------------------------------------------------------------------- #
# Layer 0 -- externalise
# --------------------------------------------------------------------------- #


def layer0_externalize(
    messages: list[dict[str, Any]],
    threshold: int = EXTERNALIZE_THRESHOLD,
) -> tuple[list[dict[str, Any]], list[ArtifactRef]]:
    """Move large tool / function outputs to artifact references.

    Only ``tool`` / ``function`` role messages are eligible -- user and
    assistant content stays put because dropping a chunk of a user
    message would corrupt the conversation.
    """
    out: list[dict[str, Any]] = []
    artifacts: list[ArtifactRef] = []

    for msg in messages:
        content = msg.get("content", "")
        role = msg.get("role", "")
        if role not in ("tool", "function") or content_byte_length(content) < threshold:
            out.append(msg)
            continue

        artifact = make_artifact_ref(content, tool_name=msg.get("name", "unknown"))
        artifacts.append(artifact)

        new_msg = dict(msg)
        new_msg["content"] = (
            f"[Large output externalised -- {artifact.byte_size:,} bytes]\n"
            f"Artifact reference: {artifact.ref}\n"
            f"SHA-256: {artifact.sha256}"
        )
        out.append(new_msg)

    if artifacts:
        logger.info("Layer 0: externalised %d artifact(s)", len(artifacts))
    return out, artifacts


# --------------------------------------------------------------------------- #
# Layer 1 -- compress
# --------------------------------------------------------------------------- #


def _compress_json(text: str, max_items: int = JSON_SAMPLE_ITEMS) -> str:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return text

    if isinstance(data, list) and len(data) > max_items:
        sampled = data[:max_items]
        return (
            json.dumps(sampled, indent=2, default=str)
            + f"\n\n[... sampled {max_items} of {len(data)} items ...]"
        )
    if isinstance(data, dict):
        compressed: dict[str, Any] = {}
        for key, val in data.items():
            if isinstance(val, str) and len(val) > 500:
                compressed[key] = val[:500] + "..."
            elif isinstance(val, list) and len(val) > max_items:
                compressed[key] = val[:max_items]
                compressed[f"_{key}_note"] = f"sampled {max_items} of {len(val)}"
            else:
                compressed[key] = val
        return json.dumps(compressed, indent=2, default=str)
    return text


def _truncate_text(text: str, max_bytes: int) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return truncated.rstrip() + TEXT_TRUNCATE_SUFFIX


def layer1_compress(
    messages: list[dict[str, Any]],
    threshold: int = COMPRESS_THRESHOLD,
) -> list[dict[str, Any]]:
    """JSON-aware sample / truncate large tool outputs."""
    out: list[dict[str, Any]] = []
    n = 0

    for msg in messages:
        content = msg.get("content", "")
        role = msg.get("role", "")
        if role not in ("tool", "function") or content_byte_length(content) < threshold:
            out.append(msg)
            continue

        text = content if isinstance(content, str) else json.dumps(content, default=str)
        compressed = _compress_json(text)
        if len(compressed.encode("utf-8")) > threshold:
            compressed = _truncate_text(compressed, threshold)

        new_msg = dict(msg)
        new_msg["content"] = compressed
        out.append(new_msg)
        n += 1

    if n:
        logger.info("Layer 1: compressed %d tool output(s)", n)
    return out


# --------------------------------------------------------------------------- #
# Layer 2 -- prune
# --------------------------------------------------------------------------- #


def layer2_prune(
    messages: list[dict[str, Any]],
    keep_first: int = PRUNE_KEEP_FIRST,
    keep_last: int = PRUNE_KEEP_LAST,
) -> list[dict[str, Any]]:
    """Sliding-window prune: keep first-N + last-N, drop the middle.

    A marker system message replaces the dropped span so downstream
    audit reads know the gap is not a missing log line.
    """
    if len(messages) <= keep_first + keep_last:
        return messages

    head = messages[:keep_first]
    tail = messages[-keep_last:]
    pruned = len(messages) - keep_first - keep_last
    marker: dict[str, Any] = {
        "role": "system",
        "content": (
            f"[Context window pruned: {pruned} message(s) removed to stay within "
            f"token budget. Kept first {keep_first} + last {keep_last}.]"
        ),
    }
    logger.info("Layer 2: pruned %d message(s)", pruned)
    return head + [marker] + tail


# --------------------------------------------------------------------------- #
# Layer 3 -- summarize (callable-injected)
# --------------------------------------------------------------------------- #


SyncSummarizer = Callable[[list[dict[str, Any]]], str]
AsyncSummarizer = Callable[[list[dict[str, Any]]], Awaitable[str]]
Summarizer = SyncSummarizer | AsyncSummarizer


async def _call_summarizer(
    summarizer: Summarizer,
    prefix: list[dict[str, Any]],
) -> str:
    """Call *summarizer* whether sync or async; always await the result."""
    result = summarizer(prefix)
    if inspect.isawaitable(result):
        return await result  # type: ignore[no-any-return]
    return result  # type: ignore[return-value]


def _layer3_inject(
    messages: list[dict[str, Any]],
    summary: str,
    keep_last: int = PRUNE_KEEP_LAST,
) -> list[dict[str, Any]]:
    """Replace the prefix with a summary system message; keep the tail."""
    system_msgs: list[dict[str, Any]] = []
    if messages and messages[0].get("role") == "system":
        system_msgs = [messages[0]]
    summary_msg: dict[str, Any] = {
        "role": "system",
        "content": (
            "[Conversation summary -- earlier messages have been condensed]\n\n" + summary
        ),
    }
    tail = messages[-keep_last:] if keep_last < len(messages) else messages
    return system_msgs + [summary_msg] + tail


async def layer3_summarize(
    messages: list[dict[str, Any]],
    summarizer: Summarizer,
    keep_last: int = PRUNE_KEEP_LAST,
) -> list[dict[str, Any]]:
    """Summarise the prefix via *summarizer*, keep the last *keep_last* messages."""
    prefix = messages[:-keep_last] if keep_last < len(messages) else list(messages)
    summary = await _call_summarizer(summarizer, prefix)
    if not isinstance(summary, str):
        summary = str(summary)
    digest = hashlib.sha256(summary.encode("utf-8")).hexdigest()[:8]
    logger.info("Layer 3: summarised prefix (%d msgs, summary digest %s)", len(prefix), digest)
    return _layer3_inject(messages, summary, keep_last=keep_last)


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #


async def apply_cascade(
    messages: list[dict[str, Any]],
    max_tokens: int,
    *,
    model_family: str = "claude",
    summarizer: Summarizer | None = None,
) -> CascadeResult:
    """Apply layers in order until *max_tokens* is satisfied (or layers exhausted).

    The cascade is async because Layer 3 may call out to an LLM via
    *summarizer*. Layers 0-2 are pure functions and run inline.
    """
    current = list(messages)
    artifacts: list[ArtifactRef] = []
    applied: list[ContextLayer] = []

    est = estimate_message_tokens(current, model_family)
    if est <= max_tokens:
        return CascadeResult(
            messages=current,
            artifacts=artifacts,
            layers_applied=applied,
            final_token_estimate=est,
            fits_budget=True,
        )

    # Layer 0
    current, l0_artifacts = layer0_externalize(current)
    if l0_artifacts:
        artifacts.extend(l0_artifacts)
        applied.append(ContextLayer.EXTERNALIZE)
    est = estimate_message_tokens(current, model_family)
    if est <= max_tokens:
        return CascadeResult(
            messages=current,
            artifacts=artifacts,
            layers_applied=applied,
            final_token_estimate=est,
            fits_budget=True,
        )

    # Layer 1
    current = layer1_compress(current)
    applied.append(ContextLayer.COMPRESS)
    est = estimate_message_tokens(current, model_family)
    if est <= max_tokens:
        return CascadeResult(
            messages=current,
            artifacts=artifacts,
            layers_applied=applied,
            final_token_estimate=est,
            fits_budget=True,
        )

    # Layer 2
    current = layer2_prune(current)
    applied.append(ContextLayer.PRUNE)
    est = estimate_message_tokens(current, model_family)
    if est <= max_tokens:
        return CascadeResult(
            messages=current,
            artifacts=artifacts,
            layers_applied=applied,
            final_token_estimate=est,
            fits_budget=True,
        )

    # Layer 3 (only if a summariser was provided)
    if summarizer is None:
        logger.warning(
            "Layer 3 needed but no summarizer provided; over budget by %d tokens",
            est - max_tokens,
        )
        return CascadeResult(
            messages=current,
            artifacts=artifacts,
            layers_applied=applied,
            final_token_estimate=est,
            fits_budget=False,
        )

    current = await layer3_summarize(current, summarizer)
    applied.append(ContextLayer.SUMMARIZE)
    est = estimate_message_tokens(current, model_family)
    return CascadeResult(
        messages=current,
        artifacts=artifacts,
        layers_applied=applied,
        final_token_estimate=est,
        fits_budget=est <= max_tokens,
    )


__all__ = [
    "COMPRESS_THRESHOLD",
    "EXTERNALIZE_THRESHOLD",
    "PRUNE_KEEP_FIRST",
    "PRUNE_KEEP_LAST",
    "AsyncSummarizer",
    "CascadeResult",
    "ContextLayer",
    "Summarizer",
    "SyncSummarizer",
    "apply_cascade",
    "estimate_message_tokens",
    "estimate_tokens",
    "layer0_externalize",
    "layer1_compress",
    "layer2_prune",
    "layer3_summarize",
]
