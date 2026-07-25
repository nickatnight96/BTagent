"""Regression tests for the WS/auth security remediation (GH #384, #396, #395).

Covers three confirmed bugs on the WebSocket surface:

* **#384** — ``get_ws_user`` must run the SAME token-revocation checks as
  ``get_current_user``. A revoked / force-logged-out token must be rejected by
  the WS auth path, not just the HTTP path.
* **#396** — inbound CHAT / HITL_RESPONSE messages must enforce
  *per-investigation* authorization (not just coarse RBAC), so a user cannot
  act on an investigation channel they aren't authorized for.
* **#395** — ``WebSocketHub._enqueue``'s drain-refill path must never let
  ``asyncio.QueueFull`` escape; otherwise one slow/full client takes down the
  shared pub/sub listener for ALL clients.

The WS surface is driven via Starlette's synchronous ``TestClient`` (seeding is
async, so tests are async and ``await`` the seed helpers, then drive the WS
client synchronously) — mirroring ``test_ws_access.py`` / ``test_cookie_auth.py``.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.types.events import EventEnvelope, EventType
from btagent_shared.utils.ids import generate_id
from conftest import (  # type: ignore[import-not-found]
    _test_engine,
    _test_get_session,
    _test_session_factory,
)
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from btagent_backend.auth import revocation
from btagent_backend.auth.jwt import create_access_token, create_token_pair, hash_password
from btagent_backend.auth.middleware import CurrentUser
from btagent_backend.auth.revocation import _reset_for_tests, revoke
from btagent_backend.db.models import Base, InvestigationRow, OrganizationRow, UserRow
from btagent_backend.ws import WebSocketHub
from btagent_backend.ws.hub import ConnectedClient
from btagent_backend.ws.protocol import BACKPRESSURE_QUEUE_LIMIT

# ---------------------------------------------------------------------------
# Revocation isolation — every test starts with a clean in-memory store and
# forces the in-memory fallback (no real Redis in CI).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_revocation_store():
    _reset_for_tests()
    revocation._redis_unavailable = True
    yield
    _reset_for_tests()


# ---------------------------------------------------------------------------
# App / hub scaffolding (mirrors test_ws_access.py)
# ---------------------------------------------------------------------------


def _build_app():
    from btagent_backend.api.deps import get_db
    from btagent_backend.main import create_app

    app = create_app()
    app.dependency_overrides[get_db] = _test_get_session

    mock_tm = MagicMock()
    mock_tm.start_investigation = AsyncMock()
    mock_tm.send_message = AsyncMock()
    mock_tm.pause_investigation = AsyncMock()
    mock_tm.resume_investigation = AsyncMock()
    mock_tm.stop_investigation = AsyncMock()
    mock_tm.get_status = MagicMock(
        return_value={"running": 0, "total_started": 0, "agents_available": True}
    )
    app.state.task_manager = mock_tm
    return app


def _retranslate_jsonb_to_json() -> None:
    from sqlalchemy import JSON
    from sqlalchemy.dialects.postgresql import JSONB

    for table in Base.metadata.tables.values():
        for col in table.columns:
            if isinstance(col.type, JSONB):
                col.type = JSON()


async def _ensure_core_tables() -> None:
    """Create just the ``organizations`` / ``users`` / ``investigations`` tables.

    Idempotent — the app lifespan (triggered by ``TestClient.__enter__``) can
    otherwise leave the in-memory SQLite without them.
    """
    _retranslate_jsonb_to_json()
    needed = {"organizations", "users", "investigations"}
    tables = [t for name, t in Base.metadata.tables.items() if name in needed]
    async with _test_engine.begin() as conn:
        await conn.run_sync(
            lambda sync_conn: Base.metadata.create_all(sync_conn, tables=tables, checkfirst=True)
        )
    await _seed_org("org_default")


async def _seed_org(org_id: str) -> None:
    async with _test_session_factory() as s:
        if await s.get(OrganizationRow, org_id) is None:
            s.add(OrganizationRow(id=org_id, name=f"Org {org_id}", created_at=datetime.now(UTC)))
            await s.commit()


async def _seed_user(role: str, *, suffix: str) -> UserRow:
    async with _test_session_factory() as s:
        u = UserRow(
            id=generate_id("usr"),
            username=f"wssec_{suffix}",
            email=f"wssec_{suffix}@btagent.test",
            password_hash=hash_password("Test-P@ss-1!"),
            role=role,
            created_at=datetime.now(UTC),
        )
        s.add(u)
        await s.commit()
        await s.refresh(u)
        return u


async def _seed_investigation(
    *, assigned_to: str | None, suffix: str, org_id: str | None = None
) -> InvestigationRow:
    async with _test_session_factory() as s:
        kwargs: dict = {}
        if org_id is not None:
            kwargs["org_id"] = org_id
        inv = InvestigationRow(
            id=generate_id("inv"),
            title=f"WS-Sec-Inv-{suffix}",
            description="seed",
            status=InvestigationStatus.INVESTIGATING.value,
            severity=Severity.MEDIUM.value,
            tlp_level="green",
            assigned_to=assigned_to,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            **kwargs,
        )
        s.add(inv)
        await s.commit()
        await s.refresh(inv)
        return inv


def _token_for(user: UserRow) -> str:
    return create_token_pair(user.id, user.username, user.role).access_token


@pytest_asyncio.fixture()
async def ws_app():
    await _ensure_core_tables()
    return _build_app()


# ===========================================================================
# Bug #384 — the WS auth path enforces token revocation
# ===========================================================================


@pytest.mark.asyncio
async def test_ws_auth_rejects_revoked_token(ws_app):
    """A revoked access token is rejected by the WS auth path (get_ws_user)."""
    user = await _seed_user("analyst", suffix="revoked")
    inv = await _seed_investigation(assigned_to=user.id, suffix="revoked")

    token, jti = create_access_token(user.id, user.username, user.role)
    assert jti is not None
    await revoke(jti, ttl_seconds=60)

    with TestClient(ws_app) as tc:
        with pytest.raises(WebSocketDisconnect):
            with tc.websocket_connect(f"/ws/investigations/{inv.id}?token={token}") as ws:
                ws.receive_text()


@pytest.mark.asyncio
async def test_ws_auth_accepts_non_revoked_token(ws_app):
    """Positive control: an identical but *non-revoked* token connects fine.

    Proves the rejection above is caused by revocation, not by the harness.
    """
    user = await _seed_user("analyst", suffix="live")
    inv = await _seed_investigation(assigned_to=user.id, suffix="live")

    token, _ = create_access_token(user.id, user.username, user.role)

    with TestClient(ws_app) as tc:
        with tc.websocket_connect(f"/ws/investigations/{inv.id}?token={token}") as ws:
            # Connecting past get_ws_user proves auth passed. Drain the
            # SUBSCRIBED ack best-effort.
            try:
                ws.receive_json()
            except Exception:
                pass


@pytest.mark.asyncio
async def test_ws_auth_rejects_user_epoch_revoked_token(ws_app):
    """An admin 'log out everywhere' (per-user epoch) is honoured on the WS path."""
    import time

    user = await _seed_user("analyst", suffix="epoch")
    inv = await _seed_investigation(assigned_to=user.id, suffix="epoch")

    token, _ = create_access_token(user.id, user.username, user.role)
    # Revoke every session issued up to now (epoch = int(now)+1 > this token's iat).
    await revocation.revoke_user_tokens(user.id, ttl_seconds=3600, now=time.time() + 1)

    with TestClient(ws_app) as tc:
        with pytest.raises(WebSocketDisconnect):
            with tc.websocket_connect(f"/ws/investigations/{inv.id}?token={token}") as ws:
                ws.receive_text()


# ===========================================================================
# Bug #396 — CHAT / HITL_RESPONSE enforce per-investigation authorization
# ===========================================================================


@pytest.mark.asyncio
async def test_ws_chat_denied_for_unauthorized_investigation(ws_app):
    """A plain analyst cannot CHAT on a same-org inv assigned to someone else."""
    me = await _seed_user("analyst", suffix="chat_me")
    other = await _seed_user("analyst", suffix="chat_other")
    inv = await _seed_investigation(assigned_to=other.id, suffix="chat_denied")
    token = _token_for(me)

    with TestClient(ws_app) as tc:
        fake_redis = AsyncMock()
        tc.app.state.ws_hub._redis = fake_redis
        with tc.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.send_json(
                {"type": "chat", "investigation_id": inv.id, "data": {"text": "let me in"}}
            )
            msg = ws.receive_json()

        assert msg["type"] == "error"
        assert msg["data"]["detail"] == "Permission denied"
        # The command must NOT have been forwarded to the agent engine.
        fake_redis.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_ws_chat_allowed_for_authorized_investigation(ws_app):
    """Regression: an assigned analyst's CHAT still reaches the engine (Redis)."""
    me = await _seed_user("analyst", suffix="chat_ok")
    inv = await _seed_investigation(assigned_to=me.id, suffix="chat_ok")
    token = _token_for(me)

    with TestClient(ws_app) as tc:
        fake_redis = AsyncMock()
        tc.app.state.ws_hub._redis = fake_redis
        with tc.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.send_json(
                {"type": "chat", "investigation_id": inv.id, "data": {"text": "hello agent"}}
            )
            # Authorized CHAT sends no reply frame; drive an error-producing
            # follow-up to synchronize (the read loop is sequential, so its
            # error frame proves the first CHAT was fully processed).
            ws.send_json({"type": "chat", "data": {"text": "no inv"}})
            sync = ws.receive_json()

        assert sync["type"] == "error"
        assert sync["data"]["detail"] == "chat requires investigation_id"
        fake_redis.publish.assert_awaited_once()
        channel = fake_redis.publish.await_args.args[0]
        assert channel == f"btagent:commands:{inv.id}"


@pytest.mark.asyncio
async def test_ws_hitl_denied_for_unauthorized_investigation(ws_app):
    """A senior analyst passes HITL RBAC but is denied on a FOREIGN-org inv."""
    await _seed_org("org_foreign")
    me = await _seed_user("senior_analyst", suffix="hitl_me")  # token org = org_default
    inv = await _seed_investigation(assigned_to=None, suffix="hitl_denied", org_id="org_foreign")
    token = _token_for(me)

    with TestClient(ws_app) as tc:
        fake_redis = AsyncMock()
        tc.app.state.ws_hub._redis = fake_redis
        with tc.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.send_json(
                {
                    "type": "hitl_response",
                    "investigation_id": inv.id,
                    "data": {"decision": "approve"},
                }
            )
            msg = ws.receive_json()

        assert msg["type"] == "error"
        assert msg["data"]["detail"] == "Permission denied"
        fake_redis.publish.assert_not_awaited()


# ===========================================================================
# Bug #395 — QueueFull in the drain-refill path must not kill the listener
# ===========================================================================


def _hub() -> WebSocketHub:
    return WebSocketHub(redis_url="redis://localhost:6379/0")


def _client(user_id: str) -> ConnectedClient:
    fake_user = MagicMock(spec=CurrentUser)
    fake_user.id = user_id
    return ConnectedClient(ws=MagicMock(), user=fake_user)


def _critical_json(marker: str) -> str:
    return EventEnvelope(
        type=EventType.ERROR, investigation_id="inv_x", data={"marker": marker}
    ).model_dump_json()


def _noncritical_json(marker: str) -> str:
    return EventEnvelope(
        type=EventType.OUTPUT, investigation_id="inv_x", data={"marker": marker}
    ).model_dump_json()


@pytest.mark.asyncio
async def test_enqueue_all_critical_full_queue_does_not_raise():
    """A queue saturated with CRITICAL items must not raise QueueFull.

    Before the fix, draining a full queue of criticals, re-adding them all,
    then ``put_nowait(payload)`` raised ``asyncio.QueueFull`` — unhandled, it
    killed the shared pub/sub listener for every connected client.
    """
    hub = _hub()
    client = _client("usr_saturated")

    for i in range(BACKPRESSURE_QUEUE_LIMIT):
        client.queue.put_nowait(_critical_json(f"old-{i}"))
    assert client.queue.full()

    newest = _critical_json("newest")
    # Must not raise.
    await hub._enqueue(client, newest, critical=True)

    # Queue stays bounded and the newest critical event survived (drop-oldest).
    assert client.queue.qsize() == BACKPRESSURE_QUEUE_LIMIT
    contents = []
    while not client.queue.empty():
        contents.append(client.queue.get_nowait())
    assert newest in contents
    assert _critical_json("old-0") not in contents  # oldest was dropped


@pytest.mark.asyncio
async def test_enqueue_critical_evicts_noncritical_when_full():
    """Regression: a critical event still evicts non-critical items when full."""
    hub = _hub()
    client = _client("usr_mixed")

    for i in range(BACKPRESSURE_QUEUE_LIMIT):
        client.queue.put_nowait(_noncritical_json(f"drop-{i}"))
    assert client.queue.full()

    newest = _critical_json("keepme")
    await hub._enqueue(client, newest, critical=True)

    contents = []
    while not client.queue.empty():
        contents.append(client.queue.get_nowait())
    assert contents == [newest]


@pytest.mark.asyncio
async def test_enqueue_noncritical_dropped_when_full():
    """A non-critical event on a full queue is dropped silently (no raise)."""
    hub = _hub()
    client = _client("usr_full")

    for i in range(BACKPRESSURE_QUEUE_LIMIT):
        client.queue.put_nowait(_critical_json(f"c-{i}"))
    assert client.queue.full()

    await hub._enqueue(client, _noncritical_json("late"), critical=False)
    # Queue untouched — the non-critical event was dropped.
    assert client.queue.qsize() == BACKPRESSURE_QUEUE_LIMIT


@pytest.mark.asyncio
async def test_dispatch_does_not_die_when_a_client_queue_is_full():
    """End-to-end: _dispatch over a full-queued client must not propagate."""
    hub = _hub()
    hub._redis = AsyncMock()  # type: ignore[attr-defined]
    slow = _client("usr_slow")
    # Saturate with criticals so the drain-refill branch is taken.
    for i in range(BACKPRESSURE_QUEUE_LIMIT):
        slow.queue.put_nowait(_critical_json(f"c-{i}"))
    hub._global_clients.add(slow)

    from btagent_backend.ws.protocol import global_channel

    # A critical event on the global channel — dispatch fans it out through
    # _enqueue. This must return cleanly rather than raising QueueFull.
    await asyncio.wait_for(
        hub._dispatch(global_channel(), _critical_json("broadcast")), timeout=2.0
    )
    assert slow.queue.qsize() == BACKPRESSURE_QUEUE_LIMIT
