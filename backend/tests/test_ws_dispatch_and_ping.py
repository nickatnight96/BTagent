"""Hub fan-out de-duplication (D10) and the ping/pong keepalive (D9).

Both defects were silent: the browser saw duplicate TLP toasts / doubled unread
counts, and a server ERROR frame every 30s that flowed through the browser's
event handler chain as a junk "event". Neither produced a server-side failure,
so only a test that counts deliveries / asserts the reply frame catches them.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from btagent_shared.types.events import EventEnvelope, EventType

from btagent_backend.auth.middleware import CurrentUser
from btagent_backend.ws import WebSocketHub
from btagent_backend.ws.hub import ConnectedClient
from btagent_backend.ws.protocol import (
    ClientMessage,
    ClientMessageType,
    ServerMessageType,
    global_channel,
    investigation_channel,
)

_INV = "inv_dispatch_dedupe"


def _hub() -> WebSocketHub:
    hub = WebSocketHub(redis_url="redis://localhost:6379/0")
    hub._redis = AsyncMock()  # type: ignore[attr-defined]
    return hub


def _client(user_id: str) -> ConnectedClient:
    fake_user = MagicMock(spec=CurrentUser)
    fake_user.id = user_id
    return ConnectedClient(ws=MagicMock(), user=fake_user)


def _envelope() -> EventEnvelope:
    return EventEnvelope(
        type=EventType.IOC_DISCOVERED,
        investigation_id=_INV,
        data={"type": "ip", "value": "203.0.113.9"},
    )


# --------------------------------------------------------------------------- #
# D10 — fan-out de-duplication
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_global_client_subscribed_to_investigation_receives_event_once():
    """A /ws/events client that also subscribed to an investigation gets ONE copy.

    ``publish()`` writes every envelope to BOTH the investigation channel and
    the global channel. Such a client sits in ``_global_clients`` AND in
    ``_investigation_clients[inv]``, so a naive dispatch delivers twice.
    """
    hub = _hub()
    client = _client("usr_dedupe")
    delivered: list[str] = []

    async def fake_enqueue(target, payload, *, critical):  # noqa: ARG001
        delivered.append(payload)

    hub._enqueue = fake_enqueue  # type: ignore[assignment,method-assign]

    hub._global_clients.add(client)
    await hub.subscribe(client, _INV)
    delivered.clear()  # drop the SUBSCRIBED ack

    raw = _envelope().model_dump_json()
    # Exactly what publish() does: the same payload on both channels.
    await hub._dispatch(investigation_channel(_INV), raw)
    await hub._dispatch(global_channel(), raw)

    assert len(delivered) == 1, "event delivered more than once to a dual-membership client"


@pytest.mark.asyncio
async def test_global_client_not_subscribed_still_receives_via_global_channel():
    """De-duplication must not starve plain global-stream clients."""
    hub = _hub()
    client = _client("usr_global_only")
    delivered: list[str] = []

    async def fake_enqueue(target, payload, *, critical):  # noqa: ARG001
        delivered.append(payload)

    hub._enqueue = fake_enqueue  # type: ignore[assignment,method-assign]
    hub._global_clients.add(client)

    raw = _envelope().model_dump_json()
    await hub._dispatch(investigation_channel(_INV), raw)
    await hub._dispatch(global_channel(), raw)

    assert len(delivered) == 1


@pytest.mark.asyncio
async def test_investigation_only_client_receives_once():
    """A /ws/investigations/{id} client is not in _global_clients — one copy."""
    hub = _hub()
    client = _client("usr_inv_only")
    delivered: list[str] = []

    async def fake_enqueue(target, payload, *, critical):  # noqa: ARG001
        delivered.append(payload)

    hub._enqueue = fake_enqueue  # type: ignore[assignment,method-assign]
    await hub.subscribe(client, _INV)
    delivered.clear()

    raw = _envelope().model_dump_json()
    await hub._dispatch(investigation_channel(_INV), raw)
    await hub._dispatch(global_channel(), raw)

    assert len(delivered) == 1


@pytest.mark.asyncio
async def test_listener_does_not_double_subscribe_the_global_channel():
    """`btagent:events:*` already matches `btagent:events:global`.

    Adding an explicit ``subscribe(global_channel())`` on top of the pattern
    makes Redis deliver each global publish twice (once as ``pmessage``, once
    as ``message``). Pin the subscription set so it can't be re-added.
    """
    hub = _hub()
    pubsub = AsyncMock()
    hub._redis.pubsub = MagicMock(return_value=pubsub)  # type: ignore[union-attr]

    # Make listen() terminate immediately so the task completes.
    async def _empty():
        return
        yield  # pragma: no cover

    pubsub.listen = MagicMock(return_value=_empty())

    await hub._pubsub_listener()

    psubscribed = {call.args[0] for call in pubsub.psubscribe.await_args_list}
    assert psubscribed == {"btagent:events:*", "btagent:notifications:*"}
    pubsub.subscribe.assert_not_awaited()


# --------------------------------------------------------------------------- #
# D9 — ping/pong keepalive
# --------------------------------------------------------------------------- #


def test_ping_parses_as_a_client_message():
    """`{"type": "ping"}` — the exact frame the browser heartbeat sends."""
    msg = ClientMessage.model_validate_json('{"type": "ping"}')
    assert msg.type is ClientMessageType.PING


@pytest.mark.asyncio
async def test_read_loop_answers_ping_with_pong_and_keeps_reading():
    """PING gets a PONG frame — not the "Unknown message type" error it used to."""
    from btagent_backend.ws.routes import _read_loop

    client = _client("usr_ping")
    sent: list[str] = []
    client.ws.send_text = AsyncMock(side_effect=lambda p: sent.append(p))

    frames = ['{"type": "ping"}', '{"type": "ping"}']

    async def receive_text() -> str:
        if frames:
            return frames.pop(0)
        raise StopAsyncIteration

    client.ws.receive_text = receive_text

    with pytest.raises(StopAsyncIteration):
        await _read_loop(client, _hub())

    assert len(sent) == 2, "the read loop must keep serving after a ping"
    for payload in sent:
        assert f'"type":"{ServerMessageType.PONG.value}"' in payload.replace(" ", "")
