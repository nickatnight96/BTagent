"""Tests for the TLP egress gate on the WebSocket broadcast path.

The hub's ``publish`` is the ``event_emit`` egress chokepoint: a TLP:RED
classified event (or one whose payload embeds a ``tlp:red`` tag) must be
dropped, not broadcast to browser subscribers. The ``tlp.violation_attempt``
alert is exempt so analysts still see the block.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from btagent_shared.types.events import EventEnvelope, EventType

from btagent_backend.ws import WebSocketHub


def _hub_with_fake_redis() -> tuple[WebSocketHub, AsyncMock]:
    hub = WebSocketHub(redis_url="redis://localhost:6379/0")
    fake_redis = AsyncMock()
    fake_redis.publish = AsyncMock(return_value=1)
    hub._redis = fake_redis  # type: ignore[attr-defined]
    return hub, fake_redis


@pytest.mark.asyncio
async def test_green_event_is_broadcast():
    hub, fake_redis = _hub_with_fake_redis()
    env = EventEnvelope(
        type=EventType.OUTPUT,
        investigation_id="inv_1",
        data={"tlp": "green", "text": "hello"},
    )
    count = await hub.publish(env)
    assert count == 2  # investigation channel + global channel
    assert fake_redis.publish.await_count == 2


@pytest.mark.asyncio
async def test_red_classified_event_is_dropped():
    hub, fake_redis = _hub_with_fake_redis()
    env = EventEnvelope(
        type=EventType.OUTPUT,
        investigation_id="inv_1",
        data={"tlp": "red", "text": "secret"},
    )
    count = await hub.publish(env)
    assert count == 0
    fake_redis.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_red_tagged_nested_payload_is_dropped():
    """A non-RED context but a nested tlp:red tag still blocks."""
    hub, fake_redis = _hub_with_fake_redis()
    env = EventEnvelope(
        type=EventType.IOC_ENRICHED,
        investigation_id="inv_1",
        data={"ioc": {"value": "1.2.3.4", "enrichment": {"tlp_level": "red"}}},
    )
    count = await hub.publish(env)
    assert count == 0
    fake_redis.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_violation_alert_event_is_exempt():
    """The TLP-violation alert carries data.tlp=red but MUST broadcast.

    Otherwise the gate self-triggers (block -> emit violation -> block ...)
    and analysts never see that RED was refused.
    """
    hub, fake_redis = _hub_with_fake_redis()
    env = EventEnvelope(
        type=EventType.TLP_VIOLATION_ATTEMPT,
        investigation_id="system",
        data={"tlp": "red", "egress_kind": "event_emit", "reason": "blocked"},
    )
    count = await hub.publish(env)
    assert count == 2
    assert fake_redis.publish.await_count == 2


@pytest.mark.asyncio
async def test_amber_strict_event_is_allowed():
    """AMBER_STRICT is auditable but permitted (warn, not block)."""
    hub, fake_redis = _hub_with_fake_redis()
    env = EventEnvelope(
        type=EventType.OUTPUT,
        investigation_id="inv_1",
        data={"tlp": "amber_strict", "text": "sensitive but allowed"},
    )
    count = await hub.publish(env)
    assert count == 2
    assert fake_redis.publish.await_count == 2
