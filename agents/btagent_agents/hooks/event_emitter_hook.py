"""Event emitter hook — publishes agent lifecycle events to Redis for WebSocket broadcast.

Translates LangChain callback events into BTagent EventEnvelope messages:
- LLM start  -> THINKING
- LLM end    -> OUTPUT
- LLM token  -> OUTPUT_CHUNK (streaming)
- Tool start -> TOOL_START
- Tool end   -> TOOL_END (with duration)
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any
from uuid import UUID

from btagent_shared.security import TLPViolation, assert_tlp_allows_egress
from btagent_shared.types.config import TLP
from btagent_shared.types.events import EventType
from langchain_core.callbacks import AsyncCallbackHandler, BaseCallbackHandler
from langchain_core.outputs import LLMResult

from btagent_agents.events.emitter import RedisEmitter
from btagent_agents.hooks._redaction import redact_secrets
from btagent_agents.hooks.base import HookProvider

logger = logging.getLogger("btagent.hooks.event_emitter")


def _fire_and_forget(coro: Any) -> None:
    """Schedule a coroutine without awaiting it.

    Used inside sync callback methods to push events to Redis without blocking
    the LangChain callback chain.
    """
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(coro)
    except RuntimeError:
        # No running loop — skip emission (happens in pure-sync test contexts)
        logger.debug("No running event loop; skipping async event emission")


class EventEmitterCallback(AsyncCallbackHandler):
    """LangChain async callback handler that emits BTagent events to Redis."""

    def __init__(
        self,
        emitter: RedisEmitter,
        investigation_id: str,
        tlp_level: TLP | str | None = None,
    ) -> None:
        super().__init__()
        self._emitter = emitter
        self._investigation_id = investigation_id
        self._tlp_level = tlp_level
        self._tool_start_times: dict[str, float] = {}
        self._token_index: int = 0

    # -- TLP egress gate ---------------------------------------------------

    def _tlp_check_or_drop(self, payload: Any, *, source: str) -> bool:
        """Return ``True`` if it is safe to emit *payload*; ``False`` to drop.

        The WebSocket broadcast channel is shared across analyst sessions for
        an investigation, so TLP:RED data must be filtered out before it
        reaches subscribers regardless of clearance.
        """
        try:
            assert_tlp_allows_egress(
                payload,
                "event_emit",
                classification_ctx=self._tlp_level,
            )
            return True
        except TLPViolation:
            logger.warning(
                "Dropping event from %s: TLP:RED data not permitted on "
                "broadcast channel for investigation %s",
                source,
                self._investigation_id,
            )
            return False

    # -- LLM events --------------------------------------------------------

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
        if not self._tlp_check_or_drop(
            {"model": model_name, "run_id": str(run_id)},
            source="on_llm_start",
        ):
            return
        await self._emitter.emit(
            EventType.THINKING,
            model=model_name,
            run_id=str(run_id),
        )

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
        if not self._tlp_check_or_drop(
            {"model": model_name, "run_id": str(run_id)},
            source="on_chat_model_start",
        ):
            return
        await self._emitter.emit(
            EventType.THINKING,
            model=model_name,
            run_id=str(run_id),
        )

    async def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        # Extract the generated text from the response
        text = ""
        if response.generations:
            for gen_list in response.generations:
                for gen in gen_list:
                    text += gen.text

        # Reset streaming token index
        self._token_index = 0

        if not self._tlp_check_or_drop(
            {"text": text, "run_id": str(run_id)},
            source="on_llm_end",
        ):
            return
        await self._emitter.emit(
            EventType.OUTPUT,
            text=text,
            run_id=str(run_id),
        )

    async def on_llm_new_token(
        self,
        token: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._token_index += 1
        if not self._tlp_check_or_drop(
            {"text": token, "index": self._token_index},
            source="on_llm_new_token",
        ):
            return
        await self._emitter.emit(
            EventType.OUTPUT_CHUNK,
            text=token,
            index=self._token_index,
        )

    async def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        await self._emitter.emit(
            EventType.ERROR,
            error=str(error),
            error_type=type(error).__name__,
            run_id=str(run_id),
            source="llm",
        )

    # -- Tool events -------------------------------------------------------

    async def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name", "unknown_tool")
        run_key = str(run_id)
        self._tool_start_times[run_key] = time.monotonic()

        if not self._tlp_check_or_drop(
            {"tool_name": tool_name, "input": input_str, "run_id": run_key},
            source="on_tool_start",
        ):
            return
        await self._emitter.emit(
            EventType.TOOL_START,
            tool_name=tool_name,
            input=input_str,
            run_id=run_key,
        )

    async def on_tool_end(
        self,
        output: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        run_key = str(run_id)
        start = self._tool_start_times.pop(run_key, None)
        duration_ms = round((time.monotonic() - start) * 1000, 1) if start else None

        # Defense in depth: redact secrets BEFORE truncation so credentials
        # appearing in the first 2000 chars don't leak via the truncation
        # window, then TLP-gate the (redacted, truncated) payload before it
        # reaches the broadcast channel. Order is gate-on-redacted so we never
        # log unredacted output even on a drop.
        redacted = redact_secrets(output) if output else output
        emitted = redacted[:2000] if len(redacted) > 2000 else redacted

        if not self._tlp_check_or_drop(
            {"output": emitted, "run_id": run_key},
            source="on_tool_end",
        ):
            return
        await self._emitter.emit(
            EventType.TOOL_END,
            output=emitted,
            duration_ms=duration_ms,
            run_id=run_key,
        )

    async def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        run_key = str(run_id)
        self._tool_start_times.pop(run_key, None)

        await self._emitter.emit(
            EventType.ERROR,
            error=str(error),
            error_type=type(error).__name__,
            run_id=run_key,
            source="tool",
        )


class EventEmitterHook(HookProvider):
    """Hook that emits agent lifecycle events to Redis via RedisEmitter.

    Usage::

        emitter = RedisEmitter(investigation_id, redis_url)
        hook = EventEmitterHook(emitter, investigation_id, tlp_level=TLP.GREEN)
        registry.register(hook)
    """

    def __init__(
        self,
        emitter: RedisEmitter,
        investigation_id: str,
        tlp_level: TLP | str | None = None,
    ) -> None:
        self._emitter = emitter
        self._investigation_id = investigation_id
        self._tlp_level = tlp_level

    def get_callbacks(self) -> list[BaseCallbackHandler]:
        return [
            EventEmitterCallback(
                self._emitter,
                self._investigation_id,
                tlp_level=self._tlp_level,
            )
        ]
