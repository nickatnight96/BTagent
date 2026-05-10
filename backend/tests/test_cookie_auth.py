"""Phase C1 — httpOnly cookie auth tests.

Covers the new cookie transport that lives alongside the existing
``Authorization: Bearer …`` header path:

* ``/auth/login`` writes the ``btagent_access`` + ``btagent_refresh`` cookies
  with the correct attributes (HttpOnly, SameSite, Path).
* A subsequent request authenticated *only* via cookie succeeds.
* A subsequent request authenticated *only* via the Authorization header
  still succeeds (compat fallback for tests / mobile / CLI clients).
* ``/auth/logout`` clears both cookies AND adds the access ``jti`` to the
  revocation list so the cookie token can't be replayed.
* ``/auth/refresh`` reads the refresh cookie and writes new access + refresh
  cookies on success.
* A cookie-borne access token whose ``jti`` has been revoked is rejected
  with 401 (revocation works on the cookie path too).
* WS connect succeeds with the cookie alone (no ``?token=``); WS connect
  with neither cookie nor query token fails.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id
from conftest import (  # type: ignore[import-not-found]
    _ANALYST_PASSWORD,
    _test_engine,
    _test_get_session,
    _test_session_factory,
)
from fastapi.testclient import TestClient
from helpers import auth_header
from httpx import AsyncClient
from starlette.websockets import WebSocketDisconnect

from btagent_backend.auth import revocation
from btagent_backend.auth.cookies import (
    ACCESS_COOKIE_NAME,
    REFRESH_COOKIE_NAME,
    REFRESH_COOKIE_PATH,
)
from btagent_backend.auth.jwt import create_access_token, create_token_pair, hash_password
from btagent_backend.auth.revocation import _reset_for_tests, is_revoked
from btagent_backend.db.models import DEFAULT_ORG_ID, Base, InvestigationRow, UserRow

# ---------------------------------------------------------------------------
# Revocation isolation: every test starts with a clean in-memory store so a
# logout in one test doesn't leak into the next.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_revocation_store():
    _reset_for_tests()
    revocation._redis_unavailable = True
    yield
    _reset_for_tests()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_set_cookie(headers, name: str) -> str | None:
    """Return the raw ``Set-Cookie`` line for ``name`` (or ``None``).

    httpx exposes multi-valued headers via ``raw`` / ``get_list``; we pick the
    first matching ``name=...`` directive.
    """
    # httpx Headers exposes get_list() to retrieve multiple values for the
    # same header name.
    for line in headers.get_list("set-cookie"):
        if line.split("=", 1)[0].strip().lower() == name.lower():
            return line
    return None


async def _seed_login_user(suffix: str) -> UserRow:
    """Seed an analyst directly via the test session factory."""
    async with _test_session_factory() as s:
        u = UserRow(
            id=generate_id("usr"),
            org_id=DEFAULT_ORG_ID,
            username=f"cookieuser_{suffix}",
            email=f"cookieuser_{suffix}@btagent.test",
            password_hash=hash_password(_ANALYST_PASSWORD),
            role="analyst",
            created_at=datetime.now(UTC),
        )
        s.add(u)
        await s.commit()
        await s.refresh(u)
        return u


# ---------------------------------------------------------------------------
# /auth/login: cookies are set with the right attributes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_sets_both_cookies_with_correct_attributes(
    client: AsyncClient, sample_user: UserRow
):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": sample_user.username, "password": _ANALYST_PASSWORD},
    )
    assert resp.status_code == 200

    body = resp.json()
    # JSON body still carries tokens for the rollout window — frontend C2
    # will stop reading them, but mobile/CLI clients still need them.
    assert "access_token" in body and body["access_token"]
    assert "refresh_token" in body and body["refresh_token"]

    access_line = _find_set_cookie(resp.headers, ACCESS_COOKIE_NAME)
    refresh_line = _find_set_cookie(resp.headers, REFRESH_COOKIE_NAME)
    assert access_line is not None, "btagent_access cookie was not set"
    assert refresh_line is not None, "btagent_refresh cookie was not set"

    # Lower-casing once so we don't depend on Starlette's exact casing.
    access_lower = access_line.lower()
    refresh_lower = refresh_line.lower()

    # Access cookie: HttpOnly, SameSite=lax, Path=/
    assert "httponly" in access_lower
    assert "samesite=lax" in access_lower
    assert "path=/" in access_lower

    # Refresh cookie: HttpOnly, SameSite=strict, Path=/api/v1/auth/refresh
    assert "httponly" in refresh_lower
    assert "samesite=strict" in refresh_lower
    assert f"path={REFRESH_COOKIE_PATH.lower()}" in refresh_lower

    # Cookies are visible on the AsyncClient's jar so subsequent calls in
    # this test inherit them — exactly what the browser would do.
    assert ACCESS_COOKIE_NAME in client.cookies
    assert REFRESH_COOKIE_NAME in client.cookies


# ---------------------------------------------------------------------------
# Cookie-only request authenticates successfully
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_with_only_cookie_succeeds(client: AsyncClient, sample_user: UserRow):
    """After login, /auth/me works with cookies only (no Authorization header)."""
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": sample_user.username, "password": _ANALYST_PASSWORD},
    )
    assert login.status_code == 200

    # No auth header — the cookie jar should carry btagent_access.
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 200
    assert resp.json()["username"] == sample_user.username


# ---------------------------------------------------------------------------
# Authorization header path still works (compat fallback)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_with_only_authorization_header_still_succeeds(
    client: AsyncClient, sample_user: UserRow
):
    """The existing Authorization-header path is unchanged — header alone, no cookie."""
    pair = create_token_pair(sample_user.id, sample_user.username, sample_user.role)

    # Make sure no cookies leak in from a prior test.
    client.cookies.clear()

    resp = await client.get("/api/v1/auth/me", headers=auth_header(pair.access_token))
    assert resp.status_code == 200
    assert resp.json()["username"] == sample_user.username


# ---------------------------------------------------------------------------
# Missing both cookie and header => 401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_cookie_and_header_returns_401(client: AsyncClient):
    client.cookies.clear()
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Logout clears cookies AND revokes the access token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logout_clears_both_cookies_and_revokes_jti(
    client: AsyncClient, sample_user: UserRow
):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": sample_user.username, "password": _ANALYST_PASSWORD},
    )
    assert login.status_code == 200

    # Capture the jti from the body's access token so we can assert revocation
    # at the storage layer (regression check — cookies vs. header must share
    # the same revocation path).
    from btagent_backend.auth.jwt import decode_token

    access_jti = decode_token(login.json()["access_token"]).jti
    assert access_jti is not None

    logout = await client.post("/api/v1/auth/logout")
    assert logout.status_code == 204

    # Both Set-Cookie headers should appear with Max-Age=0 (delete_cookie
    # emits ``name=; Max-Age=0; Path=...``).
    access_line = _find_set_cookie(logout.headers, ACCESS_COOKIE_NAME)
    refresh_line = _find_set_cookie(logout.headers, REFRESH_COOKIE_NAME)
    assert access_line is not None and "max-age=0" in access_line.lower()
    assert refresh_line is not None and "max-age=0" in refresh_line.lower()

    # Regression: the access jti must be in the revocation list — logout has
    # to invalidate the *server-side* session, not just clear the browser cookie.
    assert await is_revoked(access_jti) is True


# ---------------------------------------------------------------------------
# /auth/refresh reads the refresh cookie and writes new cookies
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_reads_cookie_and_writes_new_cookies(
    client: AsyncClient, sample_user: UserRow
):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": sample_user.username, "password": _ANALYST_PASSWORD},
    )
    assert login.status_code == 200
    old_access = client.cookies.get(ACCESS_COOKIE_NAME)
    old_refresh = client.cookies.get(REFRESH_COOKIE_NAME)
    assert old_access and old_refresh

    # Empty body — the endpoint must read the refresh token from the cookie.
    refresh = await client.post("/api/v1/auth/refresh", json={})
    assert refresh.status_code == 200
    body = refresh.json()
    assert body["access_token"] and body["refresh_token"]
    # The new pair must differ from the old (rotation).
    assert body["refresh_token"] != old_refresh

    # New cookies present on the response.
    assert _find_set_cookie(refresh.headers, ACCESS_COOKIE_NAME) is not None
    assert _find_set_cookie(refresh.headers, REFRESH_COOKIE_NAME) is not None

    # The cookie jar now carries the rotated refresh.
    assert client.cookies.get(REFRESH_COOKIE_NAME) != old_refresh


# ---------------------------------------------------------------------------
# Revoked-token rejection works on the cookie path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoked_cookie_token_rejected(client: AsyncClient, sample_user: UserRow):
    """Set the cookie manually, revoke its jti, expect 401."""
    token, jti = create_access_token(sample_user.id, sample_user.username, sample_user.role)
    assert jti is not None

    client.cookies.clear()
    client.cookies.set(ACCESS_COOKIE_NAME, token, path="/")

    # Pre-revocation: cookie alone is enough.
    pre = await client.get("/api/v1/auth/me")
    assert pre.status_code == 200

    await revocation.revoke(jti, ttl_seconds=60)

    post = await client.get("/api/v1/auth/me")
    assert post.status_code == 401
    assert "invalid_token" in post.headers.get("www-authenticate", "")


# ---------------------------------------------------------------------------
# WebSocket: cookie-only connect succeeds; nothing-at-all fails
# ---------------------------------------------------------------------------


def _retranslate_jsonb_to_json() -> None:
    from sqlalchemy import JSON
    from sqlalchemy.dialects.postgresql import JSONB

    for table in Base.metadata.tables.values():
        for col in table.columns:
            if isinstance(col.type, JSONB):
                col.type = JSON()


async def _ensure_ws_tables() -> None:
    """Create the minimal schema the WS tests need.

    We can't ``create_all`` the full ``Base.metadata`` because PG-only models
    (knowledge / mitre) carry FTS indexes (``to_tsvector('english', ...)``)
    that SQLite cannot compile. We pick out only the tables exercised here.
    The ``organizations`` row is seeded so the user/investigation FK passes.

    Run on every test (no module-level cache flag): when a Redis-backed
    Lifespan runs in CI between WS tests, ``TestClient.__exit__`` triggers
    a startup/shutdown cycle whose side effects can leave the in-memory
    SQLite without the tables we need. ``create_all(checkfirst=True)`` and
    the org-row insert are both idempotent, so re-running is cheap and safe.
    """
    _retranslate_jsonb_to_json()
    needed = {"organizations", "users", "investigations"}
    tables = [t for name, t in Base.metadata.tables.items() if name in needed]
    async with _test_engine.begin() as conn:
        await conn.run_sync(
            lambda sync_conn: Base.metadata.create_all(sync_conn, tables=tables, checkfirst=True)
        )

    from btagent_backend.db.models import OrganizationRow

    async with _test_session_factory() as s:
        existing = await s.get(OrganizationRow, DEFAULT_ORG_ID)
        if existing is None:
            s.add(
                OrganizationRow(
                    id=DEFAULT_ORG_ID,
                    name="Default Organization",
                    created_at=datetime.now(UTC),
                )
            )
            await s.commit()


def _build_ws_app():
    from unittest.mock import AsyncMock, MagicMock

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

    from btagent_backend.ws import WebSocketHub, init_ws_routes

    hub = WebSocketHub(redis_url="redis://localhost:6379/0")
    init_ws_routes(hub)
    app.state.ws_hub = hub
    return app


@pytest_asyncio.fixture()
async def ws_app():
    await _ensure_ws_tables()
    return _build_ws_app()


async def _seed_ws_user_and_inv(suffix: str) -> tuple[UserRow, InvestigationRow]:
    async with _test_session_factory() as s:
        u = UserRow(
            id=generate_id("usr"),
            username=f"wsckie_{suffix}",
            email=f"wsckie_{suffix}@btagent.test",
            password_hash=hash_password("Test-P@ss-1!"),
            role="analyst",
            created_at=datetime.now(UTC),
        )
        s.add(u)
        await s.commit()
        await s.refresh(u)
        inv = InvestigationRow(
            id=generate_id("inv"),
            title=f"WS-Cookie-Inv-{suffix}",
            description="seed",
            status=InvestigationStatus.INVESTIGATING.value,
            severity=Severity.MEDIUM.value,
            tlp_level="green",
            assigned_to=u.id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        s.add(inv)
        await s.commit()
        await s.refresh(inv)
        return u, inv


@pytest.mark.asyncio
async def test_ws_connect_with_cookie_only(ws_app):
    """WS opens with the cookie alone — no ``?token=`` on the URL."""
    user, inv = await _seed_ws_user_and_inv("cookieonly")
    pair = create_token_pair(user.id, user.username, user.role)

    with TestClient(ws_app) as tc:
        # TestClient cookies feed websocket.cookies through Starlette.
        tc.cookies.set(ACCESS_COOKIE_NAME, pair.access_token)
        with tc.websocket_connect(f"/ws/investigations/{inv.id}") as ws:
            # Best-effort drain — connect itself proves auth passed.
            try:
                ws.receive_json()
            except Exception:
                pass


@pytest.mark.asyncio
async def test_ws_connect_with_no_auth_fails(ws_app):
    """No cookie and no ``?token=`` => connection rejected (closed by server)."""
    _, inv = await _seed_ws_user_and_inv("noauth")

    with TestClient(ws_app) as tc:
        tc.cookies.clear()
        with pytest.raises(WebSocketDisconnect):
            with tc.websocket_connect(f"/ws/investigations/{inv.id}") as ws:
                ws.receive_text()
