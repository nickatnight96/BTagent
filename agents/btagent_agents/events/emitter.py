"""Redis-based event emitter for agent-to-frontend communication.

Publishes EventEnvelope JSON to a Redis pub/sub channel so the WebSocket hub
can fan events out to connected analyst browsers.

Channel pattern: ``btagent:events:{investigation_id}``
"""

from __future__ import annotations

import logging
from typing import Any

from redis.asyncio import Redis

from btagent_shared.types.events import EventEnvelope, EventType
from btagent_shared.utils.ids import generate_id

logger = logging.getLogger("btagent.events.emitter")

CHANNEL_PREFIX = "btagent:events"


def _channel(investigation_id: str) -> str:
    return f"{CHANNEL_PREFIX}:{investigation_id}"


class RedisEmitter:
    """Publish agent events to Redis for WebSocket broadcast.

    Each investigation gets its own channel. The backend WebSocket hub subscribes
    to ``btagent:events:*`` via pattern-subscribe and fans messages out to the
    analyst's browser.

    Usage::

        emitter = RedisEmitter("inv_01HX...", "redis://localhost:6379/0")
        await emitter.connect()
        event_id = await emitter.emit(EventType.THINKING, content="Analyzing alert...")
        await emitter.close()
    """

    def __init__(
        self,
        investigation_id: str,
        redis_url: str = "redis://localhost:6379/0",
        *,
        trace_id: str | None = None,
    ) -> None:
        self._investigation_id = investigation_id
        self._redis_url = redis_url
        self._trace_id = trace_id
        self._redis: Redis | None = None
        self._channel = _channel(investigation_id)

    async def connect(self) -> None:
        """Open the Redis connection."""
        if self._redis is None:
            self._redis = Redis.from_url(self._redis_url, decode_responses=True)

    async def close(self) -> None:
        """Close the Redis connection gracefully."""
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None

    async def emit(
        self,
        event_type: EventType,
        *,
        parent_id: str | None = None,
        **data: Any,
    ) -> str:
        """Build an EventEnvelope and publish it to Redis.

        Args:
            event_type: The type of event to emit.
            parent_id: Optional parent event ID for correlation.
            **data: Arbitrary key-value pairs stored in the envelope's data dict.

        Returns:
            The generated event ID.
        """
        if self._redis is None:
            await self.connect()
        assert self._redis is not None

        envelope = EventEnvelope(
            type=event_type,
            id=generate_id("evt"),
            investigation_id=self._investigation_id,
            parent_id=parent_id,
            trace_id=self._trace_id,
            data=data,
        )

        payload = envelope.model_dump_json()
        try:
            await self._redis.publish(self._channel, payload)
        except Exception:
            logger.exception(
                "Failed to publish event %s to channel %s",
                envelope.id,
                self._channel,
            )
            raise

        logger.debug("Emitted %s event %s", event_type.value, envelope.id)
        return envelope.id

    @property
    def investigation_id(self) -> str:
        return self._investigation_id

    async def __aenter__(self) -> RedisEmitter:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
