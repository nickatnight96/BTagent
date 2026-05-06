"""Event emitter middleware -- pushes node lifecycle events to a callable.

Engine-side port of ``agents/btagent_agents/hooks/event_emitter_hook.py``.
The original wired into LangChain's callback chain and wrote to Redis via
``RedisEmitter``. The engine has no Redis dependency, so the middleware
takes an injected ``emit_callable`` instead -- the orchestrator (Sprint 3)
supplies the Redis-backed implementation; tests inject a list-appending
fake.

Event lifecycle for a Node run:

* ``before_run`` -> ``"node.start"`` with the validated input dump.
* ``after_run``  -> ``"node.end"`` with the validated output dump and the
  measured duration in milliseconds.
* ``on_error``   -> ``"node.error"`` with the exception type + message.

Egress safety:

* The output payload is passed through ``redact_secrets`` before emit so
  credentials echoed by an upstream API are scrubbed before reaching any
  subscriber. Redaction runs on JSON-serialised payloads.
* Every emit is gated by ``assert_tlp_allows_egress`` with kind
  ``"event_emit"``. A TLPViolation is logged and the emit is dropped
  rather than re-raised -- keeping the node run flow intact when a single
  event happens to be classified above the channel.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING, Any, Protocol

from btagent_shared.security import TLPViolation, assert_tlp_allows_egress
from btagent_shared.types.config import TLP

from btagent_engine.middleware._redaction import redact_secrets
from btagent_engine.middleware.base import Middleware

if TYPE_CHECKING:
    from pydantic import BaseModel

    from btagent_engine.node import Node, NodeContext


logger = logging.getLogger("btagent.engine.middleware.event_emitter")


class EmitCallable(Protocol):
    """Async callable signature: ``await emit(event_type, **payload)``.

    The middleware never awaits the result for its own progress -- emits
    are best-effort. The orchestrator supplies the production Redis
    implementation; tests pass a list-appending fake.
    """

    async def __call__(self, event_type: str, /, **payload: Any) -> None: ...


def _dump(model: BaseModel) -> dict[str, Any]:
    """Serialise a Pydantic model to a plain dict for transport."""
    return model.model_dump(mode="json")


def _redact_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Apply secret redaction to all string values in *payload* (deep)."""
    # Round-trip through JSON so the redactor can run a single pass over the
    # serialised text, then reparse. Cheaper than a custom recursive walker
    # and handles nested dicts/lists uniformly. Acceptable cost: events are
    # already JSON-bound for transport.
    raw = json.dumps(payload, default=str)
    return json.loads(redact_secrets(raw))


class EventEmitterMiddleware(Middleware):
    """Emits ``node.start`` / ``node.end`` / ``node.error`` lifecycle events."""

    name = "event_emitter"

    # Per-node-run start times keyed by ``ctx.run_id``. Bounded by the
    # number of in-flight runs the runner is processing concurrently --
    # the orchestrator clears via after_run / on_error in normal operation.
    def __init__(
        self,
        emit_callable: EmitCallable,
        tlp_level: TLP | str | None = None,
    ) -> None:
        self._emit = emit_callable
        self._tlp_level = tlp_level
        self._start_times: dict[str, float] = {}

    async def before_run(
        self,
        node: Node,
        input: BaseModel,
        ctx: NodeContext,
    ) -> None:
        self._start_times[ctx.run_id] = time.monotonic()
        payload = {
            "node_id": node.meta.id,
            "run_id": ctx.run_id,
            "input": _redact_payload(_dump(input)),
        }
        await self._safe_emit("node.start", payload)

    async def after_run(
        self,
        node: Node,
        input: BaseModel,
        output: BaseModel,
        ctx: NodeContext,
    ) -> None:
        start = self._start_times.pop(ctx.run_id, None)
        duration_ms = round((time.monotonic() - start) * 1000, 1) if start else None
        payload = {
            "node_id": node.meta.id,
            "run_id": ctx.run_id,
            "duration_ms": duration_ms,
            "output": _redact_payload(_dump(output)),
        }
        await self._safe_emit("node.end", payload)

    async def on_error(
        self,
        node: Node,
        input: BaseModel,
        error: BaseException,
        ctx: NodeContext,
    ) -> None:
        # Drop the start time even on error so a long-running, failing
        # workflow doesn't leak entries.
        self._start_times.pop(ctx.run_id, None)
        payload = {
            "node_id": node.meta.id,
            "run_id": ctx.run_id,
            "error_type": type(error).__name__,
            "error": str(error),
        }
        await self._safe_emit("node.error", payload)

    async def _safe_emit(self, event_type: str, payload: dict[str, Any]) -> None:
        """Run TLP gate, emit. Drop (with warning) on TLPViolation."""
        try:
            assert_tlp_allows_egress(
                payload,
                "event_emit",
                classification_ctx=self._tlp_level,
            )
        except TLPViolation:
            logger.warning(
                "Dropping %s event: TLP gate refused egress (tlp_level=%s)",
                event_type,
                self._tlp_level,
            )
            return
        await self._emit(event_type, **payload)


__all__ = ["EmitCallable", "EventEmitterMiddleware"]
