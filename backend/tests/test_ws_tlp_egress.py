"""Tests for the TLP egress gate on the WebSocket broadcast path.

The gate runs at two points:

* :meth:`WebSocketHub.publish` -- send side, defence-in-depth so RED data
  never reaches Redis when the publisher is in-process.
* :meth:`WebSocketHub._dispatch` -- receive/fan-out side, the *primary*
  chokepoint that also catches direct-to-Redis publishers like
  ``RedisEmitter`` (used by ``task_manager`` and the legacy agent hooks).
  Without the dispatch-side gate, those publishers bypass the broadcast
  enforcement entirely.

The ``tlp.violation_attempt`` alert is exempt on both paths so analysts
still see the block.
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


# ---------------------------------------------------------------------------
# Dispatch-side gate: catches direct-to-Redis publishers like RedisEmitter
# that bypass ``publish()`` entirely. This is the primary chokepoint --
# without it, a RED-tagged event from task_manager or a legacy agent hook
# reaches subscribers.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_drops_red_classified_event():
    """Simulates the RedisEmitter path: event lands on Redis, hub receives.

    Before the dispatch gate, this would reach ``_enqueue`` and broadcast
    to every subscribed client.
    """
    hub, _ = _hub_with_fake_redis()
    enqueued: list[tuple[object, str]] = []

    async def fake_enqueue(client, payload, *, critical):  # noqa: ARG001
        enqueued.append((client, payload))

    hub._enqueue = fake_enqueue  # type: ignore[assignment]

    env = EventEnvelope(
        type=EventType.OUTPUT,
        investigation_id="inv_1",
        data={"tlp": "red", "text": "secret-from-redis-emitter"},
    )
    raw = env.model_dump_json()
    await hub._dispatch(f"btagent:events:investigation:{env.investigation_id}", raw)
    assert enqueued == []


@pytest.mark.asyncio
async def test_dispatch_drops_red_nested_payload():
    hub, _ = _hub_with_fake_redis()
    enqueued: list[tuple[object, str]] = []

    async def fake_enqueue(client, payload, *, critical):  # noqa: ARG001
        enqueued.append((client, payload))

    hub._enqueue = fake_enqueue  # type: ignore[assignment]

    env = EventEnvelope(
        type=EventType.IOC_ENRICHED,
        investigation_id="inv_1",
        data={"ioc": {"value": "1.2.3.4", "enrichment": {"tlp_level": "red"}}},
    )
    raw = env.model_dump_json()
    await hub._dispatch(f"btagent:events:investigation:{env.investigation_id}", raw)
    assert enqueued == []


@pytest.mark.asyncio
async def test_dispatch_exempts_violation_alert_event():
    """The violation alert must reach subscribers even though data.tlp=red."""
    from btagent_backend.auth.middleware import CurrentUser
    from btagent_backend.ws.hub import ConnectedClient

    hub, _ = _hub_with_fake_redis()
    enqueued: list[tuple[object, str]] = []

    async def fake_enqueue(client, payload, *, critical):  # noqa: ARG001
        enqueued.append((client, payload))

    hub._enqueue = fake_enqueue  # type: ignore[assignment]

    # Register a fake client on the global channel so dispatch has somewhere
    # to deliver.
    from unittest.mock import MagicMock

    fake_user = MagicMock(spec=CurrentUser)
    fake_user.id = "usr_test"
    client = ConnectedClient(ws=MagicMock(), user=fake_user)
    hub._global_clients.add(client)

    env = EventEnvelope(
        type=EventType.TLP_VIOLATION_ATTEMPT,
        investigation_id="system",
        data={"tlp": "red", "egress_kind": "event_emit", "reason": "blocked"},
    )
    raw = env.model_dump_json()
    # Use the actual global-channel name the hub publishes on.
    from btagent_backend.ws.protocol import global_channel

    await hub._dispatch(global_channel(), raw)
    assert len(enqueued) == 1
    assert enqueued[0][0] is client


@pytest.mark.asyncio
async def test_dispatch_passes_green_event():
    from btagent_backend.auth.middleware import CurrentUser
    from btagent_backend.ws.hub import ConnectedClient
    from btagent_backend.ws.protocol import global_channel

    hub, _ = _hub_with_fake_redis()
    enqueued: list[tuple[object, str]] = []

    async def fake_enqueue(client, payload, *, critical):  # noqa: ARG001
        enqueued.append((client, payload))

    hub._enqueue = fake_enqueue  # type: ignore[assignment]

    from unittest.mock import MagicMock

    fake_user = MagicMock(spec=CurrentUser)
    fake_user.id = "usr_test"
    client = ConnectedClient(ws=MagicMock(), user=fake_user)
    hub._global_clients.add(client)

    env = EventEnvelope(
        type=EventType.OUTPUT,
        investigation_id="inv_1",
        data={"tlp": "green", "text": "hello"},
    )
    await hub._dispatch(global_channel(), env.model_dump_json())
    assert len(enqueued) == 1
