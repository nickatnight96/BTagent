"""Tests for per-user notification fan-out through the WebSocket hub.

``NotificationService.send_inapp`` publishes a plain notification dict to
``btagent:notifications:{user_id}``; the hub forwards it — wrapped in a
``ServerMessage(type="notification")`` — to that user's connections only.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from btagent_backend.auth.middleware import CurrentUser
from btagent_backend.ws import WebSocketHub
from btagent_backend.ws.hub import ConnectedClient
from btagent_backend.ws.protocol import notification_channel


def _hub() -> WebSocketHub:
    hub = WebSocketHub(redis_url="redis://localhost:6379/0")
    hub._redis = AsyncMock()  # type: ignore[attr-defined]
    return hub


def _client(user_id: str) -> ConnectedClient:
    fake_user = MagicMock(spec=CurrentUser)
    fake_user.id = user_id
    return ConnectedClient(ws=MagicMock(), user=fake_user)


_PAYLOAD = {
    "id": "ntf_1",
    "type": "critical_finding",
    "title": "Critical finding",
    "message": "A malicious IP was observed.",
    "investigation_id": None,
    "read": False,
    "created_at": "2026-07-21T12:00:00Z",
}


@pytest.mark.asyncio
async def test_notification_reaches_only_target_user():
    hub = _hub()
    enqueued: list[tuple[ConnectedClient, str]] = []

    async def fake_enqueue(client, payload, *, critical):  # noqa: ARG001
        enqueued.append((client, payload))

    hub._enqueue = fake_enqueue  # type: ignore[assignment]

    target = _client("usr_target")
    other = _client("usr_other")
    hub._user_connections["usr_target"] = [target]
    hub._user_connections["usr_other"] = [other]

    await hub._dispatch(notification_channel("usr_target"), json.dumps(_PAYLOAD))

    assert len(enqueued) == 1
    client, message = enqueued[0]
    assert client is target
    parsed = json.loads(message)
    assert parsed["type"] == "notification"
    assert parsed["data"]["id"] == "ntf_1"
    assert parsed["data"]["title"] == "Critical finding"


@pytest.mark.asyncio
async def test_notification_delivered_to_all_of_users_connections():
    hub = _hub()
    enqueued: list[ConnectedClient] = []

    async def fake_enqueue(client, payload, *, critical):  # noqa: ARG001
        enqueued.append(client)

    hub._enqueue = fake_enqueue  # type: ignore[assignment]

    a, b = _client("usr_multi"), _client("usr_multi")
    hub._user_connections["usr_multi"] = [a, b]

    await hub._dispatch(notification_channel("usr_multi"), json.dumps(_PAYLOAD))
    assert enqueued == [a, b]


@pytest.mark.asyncio
async def test_notification_for_unconnected_user_is_noop():
    hub = _hub()
    enqueued: list[ConnectedClient] = []

    async def fake_enqueue(client, payload, *, critical):  # noqa: ARG001
        enqueued.append(client)

    hub._enqueue = fake_enqueue  # type: ignore[assignment]

    await hub._dispatch(notification_channel("usr_ghost"), json.dumps(_PAYLOAD))
    assert enqueued == []


@pytest.mark.asyncio
async def test_unparsable_notification_is_dropped():
    hub = _hub()
    enqueued: list[ConnectedClient] = []

    async def fake_enqueue(client, payload, *, critical):  # noqa: ARG001
        enqueued.append(client)

    hub._enqueue = fake_enqueue  # type: ignore[assignment]
    hub._user_connections["usr_target"] = [_client("usr_target")]

    await hub._dispatch(notification_channel("usr_target"), "not json {{{")
    assert enqueued == []


@pytest.mark.asyncio
async def test_event_channels_unaffected():
    """Regression: the notification branch must not swallow event channels."""
    from btagent_shared.types.events import EventEnvelope, EventType

    from btagent_backend.ws.protocol import global_channel

    hub = _hub()
    enqueued: list[ConnectedClient] = []

    async def fake_enqueue(client, payload, *, critical):  # noqa: ARG001
        enqueued.append(client)

    hub._enqueue = fake_enqueue  # type: ignore[assignment]

    client = _client("usr_g")
    hub._global_clients.add(client)

    env = EventEnvelope(
        type=EventType.OUTPUT, investigation_id="inv_1", data={"tlp": "green", "text": "hi"}
    )
    await hub._dispatch(global_channel(), env.model_dump_json())
    assert enqueued == [client]
