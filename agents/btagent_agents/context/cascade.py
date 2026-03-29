"""4-layer context reduction cascade for token budget management.

When the conversation context approaches the token budget, this cascade
progressively reduces its size:

- Layer 0: Externalize — move tool results >10KB to artifact storage references
- Layer 1: Compress  — truncate/sample tool results >3KB
- Layer 2: Prune     — sliding window (keep first 2 + last N messages)
- Layer 3: Summarize — replace conversation prefix with an LLM-generated summary
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from btagent_agents.context.budget import estimate_message_tokens, estimate_tokens

logger = logging.getLogger("btagent.context.cascade")

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

EXTERNALIZE_THRESHOLD = 10_240  # 10KB — move to artifact ref
COMPRESS_THRESHOLD = 3_072  # 3KB — truncate / sample
PRUNE_KEEP_FIRST = 2  # system prompt + initial user message
PRUNE_KEEP_LAST = 3  # recent context for continuity
JSON_SAMPLE_ITEMS = 5  # keep first N items when sampling JSON arrays
TEXT_TRUNCATE_SUFFIX = "\n\n[... truncated — full output in artifact store ...]"
EXTERNALIZE_SUFFIX = "\n\n[Content externalized to artifact: {ref}]"


# ---------------------------------------------------------------------------
# Layer 0: Externalize
# ---------------------------------------------------------------------------


def _content_length(content: Any) -> int:
    """Get byte length of message content."""
    if isinstance(content, str):
        return len(content.encode("utf-8"))
    if isinstance(content, list):
        total = 0
        for block in content:
            if isinstance(block, dict):
                total += len(json.dumps(block, default=str).encode("utf-8"))
            elif isinstance(block, str):
                total += len(block.encode("utf-8"))
        return total
    return 0


def _make_artifact_ref(content: str) -> str:
    """Generate a deterministic artifact reference from content hash."""
    h = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
    return f"artifact:{h}"


def layer0_externalize(
    messages: list[dict[str, Any]],
    threshold: int = EXTERNALIZE_THRESHOLD,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Move large tool outputs to artifact references.

    Returns:
        Tuple of (modified messages, list of externalized artifacts with
        {ref, content, tool_name}).
    """
    result: list[dict[str, Any]] = []
    artifacts: list[dict[str, str]] = []

    for msg in messages:
        content = msg.get("content", "")
        role = msg.get("role", "")

        # Only externalize tool/function outputs
        if role not in ("tool", "function") or _content_length(content) < threshold:
            result.append(msg)
            continue

        content_str = content if isinstance(content, str) else json.dumps(content, default=str)
        ref = _make_artifact_ref(content_str)

        artifacts.append(
            {
                "ref": ref,
                "content": content_str,
                "tool_name": msg.get("name", "unknown"),
            }
        )

        new_msg = dict(msg)
        new_msg["content"] = (
            f"[Large output externalized — {len(content_str):,} bytes]\n"
            f"Artifact reference: {ref}\n"
            f"SHA-256: {hashlib.sha256(content_str.encode()).hexdigest()}"
        )
        result.append(new_msg)

    if artifacts:
        logger.info("Layer 0: externalized %d artifacts", len(artifacts))

    return result, artifacts


# ---------------------------------------------------------------------------
# Layer 1: Compress
# ---------------------------------------------------------------------------


def _compress_json(text: str, max_items: int = JSON_SAMPLE_ITEMS) -> str:
    """Try to parse as JSON and sample if it's an array or large object."""
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
        # For large dicts, keep keys but truncate large string values
        compressed = {}
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
    """Truncate text to approximately max_bytes, preserving UTF-8 boundaries."""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    # Truncate and decode back, ignoring partial characters
    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return truncated.rstrip() + TEXT_TRUNCATE_SUFFIX


def layer1_compress(
    messages: list[dict[str, Any]],
    threshold: int = COMPRESS_THRESHOLD,
) -> list[dict[str, Any]]:
    """Compress tool outputs that exceed the threshold."""
    result: list[dict[str, Any]] = []
    compressed_count = 0

    for msg in messages:
        content = msg.get("content", "")
        role = msg.get("role", "")

        if role not in ("tool", "function") or _content_length(content) < threshold:
            result.append(msg)
            continue

        content_str = content if isinstance(content, str) else json.dumps(content, default=str)

        # Try JSON-aware compression first
        compressed = _compress_json(content_str)

        # If still too large, truncate
        if len(compressed.encode("utf-8")) > threshold:
            compressed = _truncate_text(compressed, threshold)

        new_msg = dict(msg)
        new_msg["content"] = compressed
        result.append(new_msg)
        compressed_count += 1

    if compressed_count:
        logger.info("Layer 1: compressed %d tool outputs", compressed_count)

    return result


# ---------------------------------------------------------------------------
# Layer 2: Sliding window prune
# ---------------------------------------------------------------------------


def layer2_prune(
    messages: list[dict[str, Any]],
    keep_first: int = PRUNE_KEEP_FIRST,
    keep_last: int = PRUNE_KEEP_LAST,
) -> list[dict[str, Any]]:
    """Apply sliding window pruning, keeping the first and last N messages.

    The first messages typically contain the system prompt and initial context.
    The last messages contain recent conversation needed for continuity.
    """
    if len(messages) <= keep_first + keep_last:
        return messages

    head = messages[:keep_first]
    tail = messages[-keep_last:]
    pruned_count = len(messages) - keep_first - keep_last

    # Insert a marker showing what was pruned
    marker = {
        "role": "system",
        "content": (
            f"[Context window pruned: {pruned_count} messages removed to stay within "
            f"token budget. Keeping first {keep_first} + last {keep_last} messages.]"
        ),
    }

    logger.info(
        "Layer 2: pruned %d messages (kept %d + %d)",
        pruned_count,
        keep_first,
        keep_last,
    )

    return head + [marker] + tail


# ---------------------------------------------------------------------------
# Layer 3: Summarize
# ---------------------------------------------------------------------------


def build_summary_prompt(messages: list[dict[str, Any]]) -> str:
    """Build a prompt asking the LLM to summarize the conversation prefix.

    This returns the prompt text; the caller is responsible for invoking the LLM
    (to avoid circular dependency on the router).
    """
    conversation_text = ""
    for msg in messages:
        role = msg.get("role", "unknown")
        content = msg.get("content", "")
        if isinstance(content, list):
            content = json.dumps(content, default=str)
        conversation_text += f"[{role}]: {content[:2000]}\n\n"

    return (
        "Summarize the following investigation conversation concisely. "
        "Preserve all key findings, IOCs, tool results, and decisions. "
        "Omit verbose tool output details. Keep it under 500 words.\n\n"
        f"<conversation>\n{conversation_text}</conversation>"
    )


def layer3_summarize_replace(
    messages: list[dict[str, Any]],
    summary: str,
    keep_last: int = PRUNE_KEEP_LAST,
) -> list[dict[str, Any]]:
    """Replace the conversation prefix with a summary, keeping recent messages.

    Args:
        messages: Full message list.
        summary: Pre-generated summary text (from LLM invocation).
        keep_last: Number of recent messages to preserve.

    Returns:
        New message list with summary + recent messages.
    """
    # Preserve the system message if present
    system_msgs: list[dict[str, Any]] = []
    if messages and messages[0].get("role") == "system":
        system_msgs = [messages[0]]

    summary_msg: dict[str, Any] = {
        "role": "system",
        "content": ("[Conversation summary — earlier messages have been condensed]\n\n" + summary),
    }

    tail = messages[-keep_last:] if keep_last < len(messages) else messages

    logger.info(
        "Layer 3: replaced %d messages with summary (%d tokens est.)",
        len(messages) - keep_last,
        estimate_tokens(summary, "claude"),
    )

    return system_msgs + [summary_msg] + tail


# ---------------------------------------------------------------------------
# Cascade orchestrator
# ---------------------------------------------------------------------------


def apply_cascade(
    messages: list[dict[str, Any]],
    max_tokens: int,
    model_family: str = "claude",
    summary: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], int]:
    """Apply the full 4-layer context reduction cascade as needed.

    Applies layers progressively until the token estimate is within budget.

    Args:
        messages: The current conversation messages.
        max_tokens: The token budget ceiling.
        model_family: Model family for token estimation.
        summary: Optional pre-generated summary for Layer 3. If not provided
            and Layer 3 is needed, returns a flag indicating summary is needed.

    Returns:
        Tuple of (reduced_messages, externalized_artifacts, layers_applied).
        ``layers_applied`` is a bitmask: 1=externalize, 2=compress, 4=prune, 8=summarize.
    """
    current = messages
    artifacts: list[dict[str, str]] = []
    layers_applied = 0

    # Check if reduction is needed
    est = estimate_message_tokens(current, model_family)
    if est <= max_tokens:
        return current, artifacts, layers_applied

    # Layer 0: Externalize large tool outputs
    current, layer0_artifacts = layer0_externalize(current)
    artifacts.extend(layer0_artifacts)
    if layer0_artifacts:
        layers_applied |= 1

    est = estimate_message_tokens(current, model_family)
    if est <= max_tokens:
        return current, artifacts, layers_applied

    # Layer 1: Compress remaining large outputs
    current = layer1_compress(current)
    layers_applied |= 2

    est = estimate_message_tokens(current, model_family)
    if est <= max_tokens:
        return current, artifacts, layers_applied

    # Layer 2: Sliding window prune
    current = layer2_prune(current)
    layers_applied |= 4

    est = estimate_message_tokens(current, model_family)
    if est <= max_tokens:
        return current, artifacts, layers_applied

    # Layer 3: Summarize (only if summary is provided)
    if summary:
        current = layer3_summarize_replace(current, summary)
        layers_applied |= 8
    else:
        logger.warning(
            "Layer 3 summary needed but no summary provided; "
            "context may exceed budget (%d est. tokens vs %d limit)",
            estimate_message_tokens(current, model_family),
            max_tokens,
        )

    return current, artifacts, layers_applied
