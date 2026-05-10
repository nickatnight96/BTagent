"""Engine -> legacy WebSocket event adapter.

Sprint 2B introduced a new event taxonomy in ``EventEmitterMiddleware``
(``engine/btagent_engine/middleware/event_emitter.py``). It emits a small,
uniform set of lifecycle events:

* ``node.start`` — emitted before a Node runs.
* ``node.end``   — emitted after a Node returns.
* ``node.error`` — emitted when a Node raises.

Existing browser consumers (the React analyst dashboard) still expect the
*legacy* ``EventType`` enum from
``shared/btagent_shared/types/events.py`` — ``THINKING``, ``OUTPUT``,
``OUTPUT_CHUNK``, ``TOOL_START``, ``TOOL_END``, ``ERROR``,
``HITL_CHECKPOINT``. This module sits at the consumer side of the
WebSocket hub and translates one engine emission into one legacy
``EventEnvelope``, returning ``None`` when the engine event has no
legacy mapping (e.g. categories that were never represented in the
old taxonomy).

Mapping table
-------------

+-----------------------------+--------------------------+----------------------------------------+
| Engine event                | When                     | Legacy ``EventType``                   |
+=============================+==========================+========================================+
| ``node.start`` (reasoning)  | LLMCallNode start        | ``THINKING``                           |
+-----------------------------+--------------------------+----------------------------------------+
| ``node.end``   (reasoning)  | LLMCallNode end          | ``OUTPUT`` (carries ``text`` field)    |
+-----------------------------+--------------------------+----------------------------------------+
| ``node.start`` (integration)| any tool / connector     | ``TOOL_START`` (``tool_name`` + input) |
+-----------------------------+--------------------------+----------------------------------------+
| ``node.end``   (integration)| any tool / connector     | ``TOOL_END`` (``output`` + duration)   |
+-----------------------------+--------------------------+----------------------------------------+
| ``node.error`` (any)        | error during run         | ``ERROR`` (``source`` from category)   |
+-----------------------------+--------------------------+----------------------------------------+
| ``node.start`` (decision /  | passthrough              | ``None`` — legacy didn't emit these    |
| data / output / trigger /   |                          |                                        |
| knowledge)                  |                          |                                        |
+-----------------------------+--------------------------+----------------------------------------+

``HITL_CHECKPOINT`` is emitted directly by ``HITLMiddleware`` in the
engine and does **not** pass through this adapter.

Engine event-shape assumption
-----------------------------

Each engine event is delivered as a plain dict. The keys this adapter
relies on are::

    {
        "event_type": "node.start" | "node.end" | "node.error",
        "investigation_id": "<str>",          # for the EventEnvelope
        "node": {
            "id":       "<stable node id>",   # e.g. "integration.greynoise.lookup_ip"
            "name":     "<human label>",      # used as tool_name on integration starts
            "category": "reasoning" | "integration" | "decision"
                        | "data" | "output" | "trigger" | "knowledge",
        },
        "run_id":       "<engine run id>",

        # node.start payload:
        "input":        { ... },              # validated input dump
        "model":        "<llm model>",        # optional, present on reasoning starts

        # node.end payload:
        "output":       { ... },              # validated output dump (or string)
        "duration_ms":  <float>,              # optional, derived from started_at/ended_at
        "started_at":   <epoch_seconds>,      # optional, fallback for duration calc
        "ended_at":     <epoch_seconds>,      # optional, fallback for duration calc

        # node.error payload:
        "error":        "<message>",
        "error_type":   "<exception class name>",
    }

The adapter is defensive: malformed payloads (missing ``node``, missing
``category``, unknown ``event_type``) log a warning and return
``None`` rather than raising. The hub's dispatch loop must never crash
on a bad upstream event.
"""

from __future__ import annotations

import logging
from typing import Any

from btagent_shared.types.events import EventEnvelope, EventType

logger = logging.getLogger("btagent.ws.engine_event_adapter")

# Categories that have a legacy representation. Anything outside this
# set on a ``node.start`` / ``node.end`` event is intentionally dropped.
_REASONING = "reasoning"
_INTEGRATION = "integration"
_LEGACY_CATEGORIES: frozenset[str] = frozenset({_REASONING, _INTEGRATION})

# Categories that pass through ``node.error`` -> ``ERROR``. We accept any
# category here because errors in decision/data/output nodes still need
# to surface to the analyst UI; only the ``source`` field varies.
_ERROR_SOURCE_BY_CATEGORY: dict[str, str] = {
    _REASONING: "llm",
    _INTEGRATION: "tool",
}


def _coerce_node(engine_event: dict[str, Any]) -> tuple[dict[str, Any], str] | None:
    """Pull out the ``node`` sub-dict and its ``category`` field.

    Returns ``None`` (and logs a warning) when either is missing or of the
    wrong type; the caller treats that as "skip this event".
    """
    node = engine_event.get("node")
    if not isinstance(node, dict):
        logger.warning(
            "engine event missing 'node' field; dropping (event_type=%s)",
            engine_event.get("event_type"),
        )
        return None
    category = node.get("category")
    if not isinstance(category, str):
        logger.warning(
            "engine event 'node.category' missing or non-string; dropping "
            "(event_type=%s, node_id=%s)",
            engine_event.get("event_type"),
            node.get("id"),
        )
        return None
    return node, category


def _envelope(
    *,
    event_type: EventType,
    investigation_id: str,
    data: dict[str, Any],
) -> EventEnvelope:
    """Build an ``EventEnvelope`` with sensible defaults."""
    return EventEnvelope(
        type=event_type,
        investigation_id=investigation_id,
        data=data,
    )


def _duration_ms(engine_event: dict[str, Any]) -> float | None:
    """Best-effort duration extraction.

    Prefers an explicit ``duration_ms`` (what the current
    ``EventEmitterMiddleware`` emits); falls back to
    ``ended_at - started_at`` when only the wall-clock fields are
    present (forward-compat with future emitter shapes).
    """
    explicit = engine_event.get("duration_ms")
    if isinstance(explicit, (int, float)):
        return float(explicit)
    started = engine_event.get("started_at")
    ended = engine_event.get("ended_at")
    if isinstance(started, (int, float)) and isinstance(ended, (int, float)):
        return round((ended - started) * 1000, 1)
    return None


def _extract_text(output: Any) -> str:
    """Pull a text payload out of an LLM node's output dump.

    LLM-call output schemas conventionally expose a ``text`` field
    (matching the legacy ``OUTPUT`` shape). When the dump is a bare
    string we return it as-is; otherwise we look up ``text`` /
    ``content`` / ``message``. Last resort is the JSON-ish ``str()``
    so the event isn't silently empty -- the frontend can render it
    even if the schema drifts.
    """
    if isinstance(output, str):
        return output
    if isinstance(output, dict):
        for key in ("text", "content", "message"):
            value = output.get(key)
            if isinstance(value, str):
                return value
    return str(output) if output is not None else ""


# --------------------------------------------------------------------------- #
# Public adapter
# --------------------------------------------------------------------------- #


def adapt_engine_event(engine_event: dict) -> EventEnvelope | None:
    """Translate one engine emission into a legacy ``EventEnvelope``.

    Returns ``None`` when the engine event has no legacy mapping
    (decision/data/output/trigger/knowledge starts and ends), or when
    the payload is malformed (missing ``node`` / ``category`` / known
    ``event_type``). Malformed payloads log a warning; this function
    never raises.
    """
    if not isinstance(engine_event, dict):
        logger.warning(
            "adapt_engine_event called with non-dict payload (type=%s); dropping",
            type(engine_event).__name__,
        )
        return None

    event_type = engine_event.get("event_type")
    if event_type not in {"node.start", "node.end", "node.error"}:
        logger.warning(
            "engine event has unknown event_type=%r; dropping",
            event_type,
        )
        return None

    coerced = _coerce_node(engine_event)
    if coerced is None:
        return None
    node, category = coerced

    investigation_id = engine_event.get("investigation_id") or ""
    run_id = engine_event.get("run_id")

    # node.error — surfaces for any category, but the legacy ``source`` field
    # is set to ``"llm"`` for reasoning, ``"tool"`` for integration, and the
    # category name otherwise so analysts can still filter.
    if event_type == "node.error":
        return _envelope(
            event_type=EventType.ERROR,
            investigation_id=investigation_id,
            data={
                "error": engine_event.get("error", ""),
                "error_type": engine_event.get("error_type", "UnknownError"),
                "source": _ERROR_SOURCE_BY_CATEGORY.get(category, category),
                "run_id": run_id,
                "node_id": node.get("id"),
            },
        )

    # node.start / node.end for non-legacy categories: silently skipped.
    if category not in _LEGACY_CATEGORIES:
        return None

    if event_type == "node.start":
        if category == _REASONING:
            data: dict[str, Any] = {
                "model": engine_event.get("model", node.get("name", "unknown")),
                "run_id": run_id,
                "node_id": node.get("id"),
            }
            return _envelope(
                event_type=EventType.THINKING,
                investigation_id=investigation_id,
                data=data,
            )
        # integration
        return _envelope(
            event_type=EventType.TOOL_START,
            investigation_id=investigation_id,
            data={
                "tool_name": node.get("name", node.get("id", "unknown_tool")),
                "input": engine_event.get("input", {}),
                "run_id": run_id,
                "node_id": node.get("id"),
            },
        )

    # event_type == "node.end"
    if category == _REASONING:
        return _envelope(
            event_type=EventType.OUTPUT,
            investigation_id=investigation_id,
            data={
                "text": _extract_text(engine_event.get("output")),
                "run_id": run_id,
                "node_id": node.get("id"),
            },
        )
    # integration end
    return _envelope(
        event_type=EventType.TOOL_END,
        investigation_id=investigation_id,
        data={
            "output": engine_event.get("output", {}),
            "duration_ms": _duration_ms(engine_event),
            "run_id": run_id,
            "node_id": node.get("id"),
        },
    )


__all__ = ["adapt_engine_event"]
