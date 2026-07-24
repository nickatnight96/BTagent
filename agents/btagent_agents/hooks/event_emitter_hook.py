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
import json
import logging
import re
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

# Keys whose *values* are credentials and must never reach the broadcast
# channel, regardless of value length or format.
_SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|credential)"
)

# ``${secret:...}`` / ``${env:...}`` credential references (BTagent secret
# resolver syntax) — redact the whole ref so the path/name isn't broadcast.
_SECRET_REF_RE = re.compile(r"\$\{(?:secret|env):[^}]*\}")

# Env-/query-style ``key=value`` (or ``key: value``) secret pairs for inputs
# that are not JSON. Value stops at the next delimiter; short values are caught
# too (unlike the length-gated generic redactor in ``_redaction``).
_SECRET_KV_RE = re.compile(
    r"(?i)(?P<k>password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|credential)"
    r"(?P<sep>\s*[:=]\s*)"
    r"(?P<q>['\"]?)"
    r"(?P<v>[^'\"\s,}&]+)"
    r"(?P=q)"
)


def _redact_secret_string(value: str) -> str:
    """Redact secret refs and well-known token formats inside a free string."""
    value = _SECRET_REF_RE.sub("[REDACTED:secret_ref]", value)
    return redact_secrets(value)


def _redact_secret_obj(obj: Any) -> Any:
    """Recursively redact a parsed-JSON structure by secret-looking key name."""
    if isinstance(obj, dict):
        return {
            k: ("[REDACTED]" if _SECRET_KEY_RE.search(str(k)) else _redact_secret_obj(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact_secret_obj(v) for v in obj]
    if isinstance(obj, str):
        return _redact_secret_string(obj)
    return obj


def _redact_tool_input(input_str: str) -> str:
    """Redact credentials from a tool-call argument string before broadcast.

    Tool inputs frequently carry secrets (``password``/``token``/``api_key``/
    ``authorization``/``credential`` fields and ``${secret:...}``/``${env:...}``
    refs). They were emitted verbatim to the shared WebSocket channel. Structured
    (JSON) inputs are redacted by key name; anything else falls back to
    string-level redaction of secret refs, known token formats, and ``key=value``
    pairs.
    """
    if not input_str:
        return input_str
    try:
        parsed = json.loads(input_str)
    except (json.JSONDecodeError, TypeError, ValueError):
        parsed = None
    if isinstance(parsed, (dict, list)):
        return json.dumps(_redact_secret_obj(parsed))
    return _SECRET_KV_RE.sub(
        lambda m: f"{m.group('k')}{m.group('sep')}{m.group('q')}[REDACTED]{m.group('q')}",
        _redact_secret_string(input_str),
    )


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

        # Tool arguments can carry credentials (passwords, tokens, api keys,
        # ${secret:...}/${env:...} refs). Redact BEFORE the payload reaches the
        # shared broadcast channel, and TLP-gate on the redacted form so nothing
        # unredacted is logged even on a drop (mirrors on_tool_end).
        redacted_input = _redact_tool_input(input_str)

        if not self._tlp_check_or_drop(
            {"tool_name": tool_name, "input": redacted_input, "run_id": run_key},
            source="on_tool_start",
        ):
            return
        await self._emitter.emit(
            EventType.TOOL_START,
            tool_name=tool_name,
            input=redacted_input,
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
