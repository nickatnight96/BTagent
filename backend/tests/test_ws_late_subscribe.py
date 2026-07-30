"""Late-subscribe coverage for the WS read loop (routes._read_loop, SUBSCRIBE).

Why this file exists: the SUBSCRIBE branch re-runs the per-investigation
access check for subscriptions made *after* connect (the /ws/events →
subscribe flow), and its ``except Exception`` fails closed with a generic
"Subscription check failed" error. Fail-closed is correct — but it also
means a defect *inside* the check block (during #491 a ``NameError`` on the
session-acquisition line sat exactly there) is swallowed into the same
generic error and every subscription silently fails while nothing crashes.
Only a test that asserts the SUCCESS path (authorized subscribe → SUBSCRIBED
ack) catches that class of bug; until this file, no test drove this branch
at all — connect-time subscription (``test_ws_access.py``) and CHAT/HITL
authorization (``test_ws_security_remediation.py``) both bypass it.

Harness mirrors ``test_ws_security_remediation.py``: async seed helpers +
the sync Starlette ``TestClient`` driving the WS.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id
from conftest import (  # type: ignore[import-not-found]
    _test_engine,
    _test_get_session,
    _test_session_factory,
)
from fastapi.testclient import TestClient

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import Base, InvestigationRow, OrganizationRow, UserRow

# ---------------------------------------------------------------------------
# App / seed scaffolding (mirrors test_ws_security_remediation.py)
# ---------------------------------------------------------------------------


def _build_app():
    from btagent_backend.api.deps import get_db
    from btagent_backend.main import create_app

    app = create_app()
    app.dependency_overrides[get_db] = _test_get_session

    mock_tm = MagicMock()
    mock_tm.start_investigation = AsyncMock()
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
    _retranslate_jsonb_to_json()
    needed = {"organizations", "users", "investigations"}
    tables = [t for name, t in Base.metadata.tables.items() if name in needed]
    async with _test_engine.begin() as conn:
        await conn.run_sync(
            lambda sync_conn: Base.metadata.create_all(sync_conn, tables=tables, checkfirst=True)
        )
    from btagent_backend.db.models import DEFAULT_ORG_ID

    async with _test_session_factory() as s:
        if await s.get(OrganizationRow, DEFAULT_ORG_ID) is None:
            s.add(
                OrganizationRow(
                    id=DEFAULT_ORG_ID, name="Default Organization", created_at=datetime.now(UTC)
                )
            )
            await s.commit()


async def _seed_user(role: str, *, suffix: str) -> UserRow:
    async with _test_session_factory() as s:
        u = UserRow(
            id=generate_id("usr"),
            username=f"wslate_{suffix}",
            email=f"wslate_{suffix}@btagent.test",
            password_hash=hash_password("Test-P@ss-1!"),
            role=role,
            created_at=datetime.now(UTC),
        )
        s.add(u)
        await s.commit()
        await s.refresh(u)
        return u


async def _seed_investigation(*, assigned_to: str | None, suffix: str) -> InvestigationRow:
    async with _test_session_factory() as s:
        inv = InvestigationRow(
            id=generate_id("inv"),
            title=f"WS-Late-Inv-{suffix}",
            description="seed",
            status=InvestigationStatus.INVESTIGATING.value,
            severity=Severity.MEDIUM.value,
            tlp_level="green",
            assigned_to=assigned_to,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
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


#: Frame types that are control-plane replies to a client command.
_CONTROL_TYPES = frozenset({"subscribed", "unsubscribed", "error"})


def _recv_control(ws, wanted: str, *, max_frames: int = 8) -> dict:
    """Read frames until the ``wanted`` control reply arrives.

    ``receive_json()`` returns the *next* frame, whatever it is — but the hub
    may interleave a broadcast **data** event (e.g. a replayed
    ``investigation_complete``) between a client command and its ack. Asserting
    on the next frame therefore fails intermittently; this skips data events
    instead.

    An ``error`` frame is deliberately **never** skipped: if the server rejected
    the command we want the test to fail loudly on that, not to keep reading
    until something matches and mask a real bug.
    """
    seen: list[str] = []
    for _ in range(max_frames):
        frame = ws.receive_json()
        ftype = frame.get("type")
        seen.append(ftype)
        if ftype == wanted:
            return frame
        if ftype in _CONTROL_TYPES:
            raise AssertionError(f"expected control frame {wanted!r}, got {ftype!r} (saw {seen})")
    raise AssertionError(f"no {wanted!r} frame within {max_frames} frames (saw {seen})")


# ---------------------------------------------------------------------------
# SUBSCRIBE (late, via /ws/events)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_late_subscribe_authorized_gets_subscribed_ack(ws_app):
    """The success path: an assigned analyst late-subscribes and gets the ack.

    This is the regression test for the #491 near-miss: any defect raised
    inside the SUBSCRIBE access-check block is swallowed by its fail-closed
    ``except Exception`` into a generic error frame, so only asserting the
    positive SUBSCRIBED ack proves the block actually executed.
    """
    me = await _seed_user("analyst", suffix="ok")
    inv = await _seed_investigation(assigned_to=me.id, suffix="ok")
    token = _token_for(me)

    with TestClient(ws_app) as tc:
        with tc.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.send_json({"type": "subscribe", "investigation_id": inv.id})
            msg = ws.receive_json()

    assert msg["type"] == "subscribed", f"expected subscribed ack, got: {msg}"
    assert msg["data"]["investigation_id"] == inv.id


@pytest.mark.asyncio
async def test_late_subscribe_denied_for_other_analysts_inv(ws_app):
    """A plain analyst cannot late-subscribe to a same-org inv assigned to
    someone else — same policy as the connect-time gate, same uniform
    wording as the CHAT/HITL denial so existence never leaks."""
    me = await _seed_user("analyst", suffix="denied_me")
    other = await _seed_user("analyst", suffix="denied_other")
    inv = await _seed_investigation(assigned_to=other.id, suffix="denied")
    token = _token_for(me)

    with TestClient(ws_app) as tc:
        with tc.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.send_json({"type": "subscribe", "investigation_id": inv.id})
            msg = ws.receive_json()

    assert msg["type"] == "error"
    assert msg["data"]["detail"] == "Permission denied"


@pytest.mark.asyncio
async def test_late_subscribe_senior_analyst_allowed_on_unassigned(ws_app):
    """Senior analyst may late-subscribe to any same-org investigation."""
    senior = await _seed_user("senior_analyst", suffix="senior")
    other = await _seed_user("analyst", suffix="senior_other")
    inv = await _seed_investigation(assigned_to=other.id, suffix="senior")
    token = _token_for(senior)

    with TestClient(ws_app) as tc:
        with tc.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.send_json({"type": "subscribe", "investigation_id": inv.id})
            msg = ws.receive_json()

    assert msg["type"] == "subscribed"
    assert msg["data"]["investigation_id"] == inv.id


@pytest.mark.asyncio
async def test_late_subscribe_requires_investigation_id(ws_app):
    me = await _seed_user("analyst", suffix="noid")
    token = _token_for(me)

    with TestClient(ws_app) as tc:
        with tc.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.send_json({"type": "subscribe"})
            msg = ws.receive_json()

    assert msg["type"] == "error"
    assert msg["data"]["detail"] == "subscribe requires investigation_id"


@pytest.mark.asyncio
async def test_late_subscribe_check_failure_fails_closed(ws_app, monkeypatch):
    """An unexpected error inside the access check must DENY, not grant.

    Pins the fail-closed contract of the ``except Exception`` arm — and the
    generic wording, which deliberately does not echo internals.
    """
    from btagent_backend.ws import routes as routes_mod

    async def boom(db, user, investigation_id):  # type: ignore[no-untyped-def]
        raise RuntimeError("simulated DB outage")

    monkeypatch.setattr(routes_mod, "assert_can_subscribe", boom)

    me = await _seed_user("analyst", suffix="boom")
    inv = await _seed_investigation(assigned_to=me.id, suffix="boom")
    token = _token_for(me)

    with TestClient(ws_app) as tc:
        with tc.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.send_json({"type": "subscribe", "investigation_id": inv.id})
            msg = ws.receive_json()

    assert msg["type"] == "error"
    assert msg["data"]["detail"] == "Subscription check failed"


# ---------------------------------------------------------------------------
# UNSUBSCRIBE
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unsubscribe_after_late_subscribe_gets_ack(ws_app):
    me = await _seed_user("analyst", suffix="unsub")
    inv = await _seed_investigation(assigned_to=me.id, suffix="unsub")
    token = _token_for(me)

    with TestClient(ws_app) as tc:
        with tc.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.send_json({"type": "subscribe", "investigation_id": inv.id})
            sub = _recv_control(ws, "subscribed")
            ws.send_json({"type": "unsubscribe", "investigation_id": inv.id})
            unsub = _recv_control(ws, "unsubscribed")

    assert sub["type"] == "subscribed"
    assert unsub["type"] == "unsubscribed"
    assert unsub["data"]["investigation_id"] == inv.id


@pytest.mark.asyncio
async def test_unsubscribe_requires_investigation_id(ws_app):
    me = await _seed_user("analyst", suffix="unsub_noid")
    token = _token_for(me)

    with TestClient(ws_app) as tc:
        with tc.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.send_json({"type": "unsubscribe"})
            msg = ws.receive_json()

    assert msg["type"] == "error"
    assert msg["data"]["detail"] == "unsubscribe requires investigation_id"
