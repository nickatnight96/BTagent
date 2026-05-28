"""Robust LLM-JSON helper for reasoning nodes.

Centralises the "call the model, get well-formed JSON, never crash"
pattern shared by HypothesisGen / QuerySynth / NLQuery.

Robustness levers:

1. **Strict prompting + bracket extraction.** The caller's system prompt
   demands JSON-only; this helper then extracts the first ``[``/``{`` ...
   last ``]``/``}`` span, tolerating stray prose or a ```` ```json ````
   fence around it.

   (We do NOT use Anthropic assistant-prefill: the 4.x models — e.g.
   claude-sonnet-4-6 — reject it with "This model does not support
   assistant message prefill. The conversation must end with a user
   message." Verified live. The conversation therefore ends with the
   user turn.)

2. **None on any failure.** The caller falls back to its deterministic
   generator, so a flaky response can never break a pipeline.
"""

from __future__ import annotations

import json
from typing import Any


def wrap_external_data(text: str) -> str:
    """Fence untrusted external text for LLM prompts (prompt-injection defense).

    CLAUDE.md requires all external data in agent prompts to be wrapped in
    ``<external-data>`` XML tags. Engine can't import the agents-tier helper
    (zero-dep boundary), so the reasoning nodes share this one.
    """
    return f"<external-data>\n{text}\n</external-data>"


async def call_llm_json(
    client: Any,
    *,
    system: str,
    user: str,
    tlp: Any,
    tier: Any,
    max_tokens: int = 2048,
    array: bool = True,
) -> Any | None:
    """Call ``client.complete`` and parse a JSON array (or object).

    Returns the parsed value, or ``None`` on any failure (no client error
    surfaces to the caller — it should fall back to deterministic).
    """
    from btagent_shared.llm import LLMMessage, LLMRequest

    try:
        resp = await client.complete(
            LLMRequest(
                messages=[
                    LLMMessage(role="system", content=system),
                    LLMMessage(role="user", content=user),
                ],
                tier=tier,
                tlp=tlp,
                temperature=0.2,
                max_tokens=max_tokens,
                json_mode=True,
            )
        )
    except Exception:  # noqa: BLE001 - any client/transport error -> fallback
        return None

    text = resp.content or ""
    open_c, close_c = ("[", "]") if array else ("{", "}")
    start, end = text.find(open_c), text.rfind(close_c)
    if start == -1 or end == -1 or end < start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except (ValueError, TypeError):
        return None


__all__ = ["call_llm_json", "wrap_external_data"]
