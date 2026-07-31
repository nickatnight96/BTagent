"""Tests for investigation chat-transcript persistence + history (#482 debt).

The contract under test: the endpoint ``agentStore.loadHistory`` has always
called now exists, returns the frontend's ``ChatMessage[]`` shape, and the two
write paths feed it — ``POST /chat`` for user messages (synchronous, in the
request session) and the WS hub's dispatch chokepoint for the agent's
finalized ``output`` events (fire-and-forget, dedup on envelope id).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.types.events import EventEnvelope, EventType
from btagent_shared.utils.ids import generate_id
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import DEFAULT_ORG_ID, EventRow, InvestigationRow, UserRow
from btagent_backend.services import chat_history_service as svc


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _factory_for(db_session: AsyncSession):
    """A session factory that hands back the test's own session, unclosed.

    Binding the service to the fixture session keeps these tests on the one
    engine that certainly has the schema — several test modules re-import
    ``conftest`` under a second module name, so a factory imported from the
    (possibly re-registered) engine module is bound to whichever duplicate
    engine happened to be live at import time.
    """

    class _Ctx:
        async def __aenter__(self) -> AsyncSession:
            return db_session

        async def __aexit__(self, *exc: object) -> bool:
            return False

    return _Ctx


def _envelope(investigation_id: str, text: str, **data) -> EventEnvelope:
    return EventEnvelope(
        type=EventType.OUTPUT,
        investigation_id=investigation_id,
        data={"text": text, **data},
    )


# --------------------------------------------------------------------------- #
# Service
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_history_interleaves_user_and_assistant_by_time(
    db_session: AsyncSession, sample_investigation: InvestigationRow
):
    inv_id = sample_investigation.id
    await svc.record_user_message(
        db_session, investigation_id=inv_id, content="What IPs were involved?", user_id="usr_a"
    )
    assert await svc.persist_assistant_output(
        _envelope(inv_id, "Two external IPs: 203.0.113.7 and 198.51.100.9."),
        session_factory=_factory_for(db_session),
    )
    await svc.record_user_message(
        db_session, investigation_id=inv_id, content="Contain the first one.", user_id="usr_a"
    )
    await db_session.commit()

    history = await svc.get_history(db_session, investigation_id=inv_id)
    assert [m["role"] for m in history] == ["user", "assistant", "user"]
    assert history[0]["content"] == "What IPs were involved?"
    assert "203.0.113.7" in history[1]["content"]
    # The frontend ChatMessage contract: id/role/content/timestamp.
    assert set(history[0]) == {"id", "role", "content", "timestamp"}


@pytest.mark.asyncio
async def test_assistant_persist_dedups_on_envelope_id(
    db_session: AsyncSession, sample_investigation: InvestigationRow
):
    """publish() fans out to two channels; the second copy must not double-write."""
    env = _envelope(sample_investigation.id, "final answer")
    assert await svc.persist_assistant_output(env, session_factory=_factory_for(db_session)) is True
    assert (
        await svc.persist_assistant_output(env, session_factory=_factory_for(db_session)) is False
    )

    rows = (await db_session.execute(select(EventRow).where(EventRow.id == env.id))).scalars().all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_assistant_persist_skips_empty_and_survives_failure(
    db_session: AsyncSession,
    sample_investigation: InvestigationRow,
):
    assert (
        await svc.persist_assistant_output(
            _envelope(sample_investigation.id, "   "), session_factory=_factory_for(db_session)
        )
        is False
    )

    # A broken session factory must be swallowed (live delivery never depends
    # on the transcript write), not raised into the dispatch loop.
    def _boom():
        raise RuntimeError("db down")

    assert (
        await svc.persist_assistant_output(
            _envelope(sample_investigation.id, "text"), session_factory=_boom
        )
        is False
    )


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_chat_persists_the_user_message(
    client: AsyncClient,
    db_session: AsyncSession,
    analyst_token: str,
    sample_user: UserRow,
):
    create = await client.post(
        "/api/v1/investigations",
        headers=auth_header(analyst_token),
        json={"title": "History chat test"},
    )
    inv_id = create.json()["id"]

    resp = await client.post(
        f"/api/v1/investigations/{inv_id}/chat",
        headers=auth_header(analyst_token),
        json={"message": "Show me the timeline."},
    )
    assert resp.status_code == 200

    history = await client.get(
        f"/api/v1/investigations/{inv_id}/history", headers=auth_header(analyst_token)
    )
    assert history.status_code == 200
    body = history.json()
    assert isinstance(body, list)
    assert [m["role"] for m in body] == ["user"]
    assert body[0]["content"] == "Show me the timeline."


@pytest.mark.asyncio
async def test_history_route_contract(
    client: AsyncClient, db_session: AsyncSession, analyst_token: str
):
    # Unknown investigation → 404, same wording as the sibling routes.
    resp = await client.get(
        "/api/v1/investigations/inv_does_not_exist/history",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 404

    # No token → 401.
    resp = await client.get("/api/v1/investigations/inv_x/history")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_history_is_scoped_like_the_investigation(
    client: AsyncClient,
    db_session: AsyncSession,
    sample_investigation: InvestigationRow,
):
    """An analyst who isn't assigned (or is cross-org) gets the same 404."""
    other = UserRow(
        id=generate_id("usr"),
        org_id=DEFAULT_ORG_ID,
        username=f"otheranalyst_{generate_id('u')}",
        email=f"{generate_id('e')}@btagent.test",
        password_hash=hash_password("Hist0ry-P@ss!"),
        role="analyst",
        created_at=datetime.now(UTC),
    )
    db_session.add(other)
    await db_session.commit()
    token = create_token_pair(other.id, other.username, other.role, org_id=other.org_id)

    resp = await client.get(
        f"/api/v1/investigations/{sample_investigation.id}/history",
        headers=auth_header(token.access_token),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_history_of_a_fresh_investigation_is_an_empty_array(
    client: AsyncClient, db_session: AsyncSession, analyst_token: str, sample_user: UserRow
):
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=DEFAULT_ORG_ID,
        title="Fresh — no chat yet",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.LOW.value,
        tlp_level="green",
        assigned_to=sample_user.id,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(inv)
    await db_session.commit()

    resp = await client.get(
        f"/api/v1/investigations/{inv.id}/history", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 200
    assert resp.json() == []
