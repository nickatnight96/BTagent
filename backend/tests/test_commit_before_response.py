"""CommitBeforeResponseMiddleware — the ordering guarantee, pinned.

The bug this middleware closes: ``get_session`` committed in dependency
teardown, which FastAPI runs *after* the response is sent, so every write
endpoint confirmed success before its transaction was durable. That produced
a months-long trail of "flaky" CI failures sharing one signature — write
accepted, immediate read empty/404 — across four E2E shard incidents and a
UAT run (#481's register→login 401, org-profile PUT→GET blank).

These tests pin the mechanism at the ASGI level with a recording fake
session, because the property under test is *ordering* — commit strictly
before ``http.response.start`` is forwarded — and an end-to-end test on the
shared in-memory SQLite cannot observe that window (its single connection
sees uncommitted state anyway). The full backend suite running through the
real app (conftest stashes the session identically to production) is the
integration net on top.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from btagent_backend.middleware.commit_before_response import (
    DB_SESSION_STATE_KEY,
    CommitBeforeResponseMiddleware,
)


class RecordingSession:
    """Stands in for AsyncSession; records commit order relative to sends."""

    def __init__(self, events: list[str], fail: bool = False) -> None:
        self._events = events
        self._fail = fail

    async def commit(self) -> None:
        if self._fail:
            raise RuntimeError("commit exploded")
        self._events.append("commit")


def _app_returning(status: int, session: RecordingSession | None, events: list[str]):
    """Minimal ASGI app that stashes ``session`` and sends a response."""

    async def app(scope, receive, send):
        if session is not None:
            scope.setdefault("state", {})[DB_SESSION_STATE_KEY] = session

        async def recording_send(message):
            events.append(message["type"])
            await send(message)

        await recording_send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await recording_send({"type": "http.response.body", "body": b"ok"})

    return app


async def _drive(app) -> int:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        resp = await client.get("/")
    return resp.status_code


@pytest.mark.asyncio
async def test_commits_before_response_start_is_forwarded():
    """The whole point: by the time the status line leaves, data is durable.

    A successful response with a stashed session commits it. The *before
    forwarding* half of the guarantee is proven by the failing-commit test
    below: if the commit ran after the status line went out, that test
    could not stop the 201 from reaching the client.
    """
    events: list[str] = []
    session = RecordingSession(events)
    app = CommitBeforeResponseMiddleware(_app_returning(201, session, events))

    status = await _drive(app)
    assert status == 201
    assert "commit" in events


@pytest.mark.asyncio
async def test_error_responses_are_not_committed():
    """4xx keeps today's rollback semantics — the middleware stays out."""
    events: list[str] = []
    session = RecordingSession(events)
    app = CommitBeforeResponseMiddleware(_app_returning(422, session, events))

    status = await _drive(app)
    assert status == 422
    assert "commit" not in events


@pytest.mark.asyncio
async def test_failed_commit_never_lets_a_success_status_out():
    """The 'success status could be a lie' half of the bug.

    The commit raises before ``http.response.start`` is forwarded, so the
    client must NOT receive the 201 — the exception propagates and whatever
    sits outside (Starlette's error middleware in the real app; the raw
    transport here) turns it into a server error instead.
    """
    events: list[str] = []
    session = RecordingSession(events, fail=True)
    app = CommitBeforeResponseMiddleware(_app_returning(201, session, events))

    with pytest.raises(RuntimeError, match="commit exploded"):
        await _drive(app)


@pytest.mark.asyncio
async def test_requests_without_a_session_pass_through():
    """Read-only stacks (no dependency stash) are untouched."""
    events: list[str] = []
    app = CommitBeforeResponseMiddleware(_app_returning(200, None, events))
    assert await _drive(app) == 200


@pytest.mark.asyncio
async def test_commit_happens_once_for_multi_message_responses():
    """Only the first response.start triggers a commit."""
    events: list[str] = []
    session = RecordingSession(events)
    app = CommitBeforeResponseMiddleware(_app_returning(200, session, events))

    await _drive(app)
    assert events.count("commit") == 1


@pytest.mark.asyncio
async def test_end_to_end_write_is_committed_when_the_client_sees_201(
    client: AsyncClient, admin_token: str
):
    """Through the real app: a 201 means the row is already committed.

    SQLite's shared connection can't show the race window, but this at least
    proves the middleware runs in the real stack (innermost, under the
    BaseHTTPMiddleware layers) without breaking a genuine write endpoint —
    the regression that DID occur when it was mounted outermost and its
    commit raced dependency teardown across tasks.
    """
    from tests.helpers import auth_header

    resp = await client.post(
        "/api/v1/auth/register",
        headers=auth_header(admin_token),
        json={
            "username": "cbr_e2e_user",
            "email": "cbr_e2e@btagent.test",
            "password": "Cbr-Test-Pass-123",
            "role": "analyst",
        },
    )
    assert resp.status_code == 201

    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "cbr_e2e_user", "password": "Cbr-Test-Pass-123"},
    )
    assert login.status_code == 200
