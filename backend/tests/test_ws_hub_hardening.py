"""P4.6: WS hub hardening — B11 fail-closed org filter, B12 accept-then-close.

B11: on the global channel (fans out to every tenant), an event with no
``data.org_id`` used to fail OPEN — reaching every org-scoped client. A TLP
violation raised outside org context leaked cross-tenant. It now fails closed
there while staying lenient on the per-investigation channel (access-checked at
subscribe time).

B12: the per-user connection-limit refusal closed the socket BEFORE accept(),
so the 4029 close code never reached the client (Starlette answers the
handshake with HTTP 403 → generic 1006 → reconnect storm). It now accepts then
closes.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from btagent_shared.types.events import EventEnvelope, EventType

from btagent_backend.auth.middleware import CurrentUser
from btagent_backend.ws import WebSocketHub
from btagent_backend.ws.hub import ConnectedClient
from btagent_backend.ws.protocol import global_channel, investigation_channel

_INV = "inv_hardening"


def _hub() -> WebSocketHub:
    hub = WebSocketHub(redis_url="redis://localhost:6379/0")
    hub._redis = AsyncMock()  # type: ignore[attr-defined]
    return hub


def _client(user_id: str, org_id: str | None) -> ConnectedClient:
    fake_user = MagicMock(spec=CurrentUser)
    fake_user.id = user_id
    return ConnectedClient(ws=MagicMock(), user=fake_user, org_id=org_id)


def _unattributed_envelope() -> str:
    # No org_id in data — the dangerous case.
    return EventEnvelope(
        type=EventType.TLP_VIOLATION_ATTEMPT,
        investigation_id=_INV,
        data={"reason": "egress blocked"},
    ).model_dump_json()


# --------------------------------------------------------------------------- #
# B11 — global channel fails closed on unattributed events
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_global_channel_drops_unattributed_event_for_org_scoped_client():
    hub = _hub()
    org_client = _client("usr_org", org_id="org_a")
    delivered: list[str] = []

    async def fake_enqueue(target, payload, *, critical):  # noqa: ARG001
        delivered.append(payload)

    hub._enqueue = fake_enqueue  # type: ignore[assignment,method-assign]
    hub._global_clients.add(org_client)

    await hub._dispatch(global_channel(), _unattributed_envelope())
    assert delivered == [], "unattributed event leaked to an org-scoped client"


@pytest.mark.asyncio
async def test_global_channel_delivers_unattributed_event_to_orgless_client():
    """A cross-org (no-org) admin stream still receives the global event."""
    hub = _hub()
    admin_client = _client("usr_admin", org_id=None)
    delivered: list[str] = []

    async def fake_enqueue(target, payload, *, critical):  # noqa: ARG001
        delivered.append(payload)

    hub._enqueue = fake_enqueue  # type: ignore[assignment,method-assign]
    hub._global_clients.add(admin_client)

    await hub._dispatch(global_channel(), _unattributed_envelope())
    assert len(delivered) == 1


@pytest.mark.asyncio
async def test_investigation_channel_stays_lenient_on_unattributed_event():
    """The per-investigation channel keeps the same-org no-op (subscribe-time
    access check already scoped the client)."""
    hub = _hub()
    org_client = _client("usr_org", org_id="org_a")
    delivered: list[str] = []

    async def fake_enqueue(target, payload, *, critical):  # noqa: ARG001
        delivered.append(payload)

    hub._enqueue = fake_enqueue  # type: ignore[assignment,method-assign]
    await hub.subscribe(org_client, _INV)
    delivered.clear()

    await hub._dispatch(investigation_channel(_INV), _unattributed_envelope())
    assert len(delivered) == 1


# --------------------------------------------------------------------------- #
# B12 — connection-limit refusal accepts before closing
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_connection_limit_accepts_then_closes():
    hub = _hub()
    hub._max_per_user = 1

    user = MagicMock(spec=CurrentUser)
    user.id = "usr_limit"

    # First connection succeeds.
    ws1 = MagicMock()
    ws1.accept = AsyncMock()
    ws1.close = AsyncMock()
    c1 = await hub.connect(ws1, user, org_id="org_a")
    assert c1 is not None

    # Second is over the limit: must accept THEN close with 4029.
    ws2 = MagicMock()
    ws2.accept = AsyncMock()
    ws2.close = AsyncMock()
    calls: list[str] = []
    ws2.accept.side_effect = lambda *a, **k: calls.append("accept")
    ws2.close.side_effect = lambda *a, **k: calls.append("close")

    c2 = await hub.connect(ws2, user, org_id="org_a")
    assert c2 is None
    assert calls == ["accept", "close"], "close must follow accept so the code reaches the client"
    assert ws2.close.await_args.kwargs["code"] == 4029
