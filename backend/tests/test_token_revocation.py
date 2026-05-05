"""Tests for AUTH-A2 token revocation (jti + Redis revocation list).

These tests exercise the in-memory fallback path of
``btagent_backend.auth.revocation`` — Redis is unavailable in CI, and the
module degrades gracefully to a process-local dict, mirroring the rate
limiter's pattern.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

import pytest
from helpers import auth_header
from httpx import AsyncClient
from jose import jwt as jose_jwt

from btagent_backend.auth import revocation
from btagent_backend.auth.jwt import (
    create_access_token,
    create_refresh_token,
    create_token_pair,
)
from btagent_backend.auth.revocation import (
    _reset_for_tests,
    is_revoked,
    revoke,
)
from btagent_backend.config import get_settings
from btagent_backend.db.models import UserRow


@pytest.fixture(autouse=True)
def _isolated_revocation_store():
    """Each test starts with a clean revocation store."""
    _reset_for_tests()
    # Force the in-memory fallback so tests don't reach a real Redis instance
    # if one happens to be running in the dev container.
    revocation._redis_unavailable = True
    yield
    _reset_for_tests()


# ---------------------------------------------------------------------------
# revoke() / is_revoked() unit behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_is_revoked_false_for_unknown_jti():
    assert await is_revoked("never-seen-jti") is False


@pytest.mark.asyncio
async def test_revoke_then_is_revoked_true():
    await revoke("jti-123", ttl_seconds=60)
    assert await is_revoked("jti-123") is True


@pytest.mark.asyncio
async def test_revoke_with_zero_ttl_is_noop():
    await revoke("jti-zero", ttl_seconds=0)
    assert await is_revoked("jti-zero") is False


@pytest.mark.asyncio
async def test_revoke_empty_jti_is_noop():
    await revoke("", ttl_seconds=60)
    assert await is_revoked("") is False


# ---------------------------------------------------------------------------
# Middleware: token accepted unless revoked
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_token_accepted_when_not_revoked(
    client: AsyncClient, analyst_token: str
):
    """A freshly-minted access token is accepted by /auth/me."""
    resp = await client.get("/api/v1/auth/me", headers=auth_header(analyst_token))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_token_rejected_after_revoke(client: AsyncClient, sample_user: UserRow):
    """Revoking an access token's jti causes /auth/me to return 401."""
    token, jti = create_access_token(
        sample_user.id, sample_user.username, sample_user.role
    )

    # Pre-revocation: accepted.
    resp = await client.get("/api/v1/auth/me", headers=auth_header(token))
    assert resp.status_code == 200

    # Revoke and retry — must now be rejected with 401 + invalid_token header.
    await revoke(jti, ttl_seconds=60)
    resp = await client.get("/api/v1/auth/me", headers=auth_header(token))
    assert resp.status_code == 401
    assert "invalid_token" in resp.headers.get("www-authenticate", "")


# ---------------------------------------------------------------------------
# Logout revokes both tokens
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logout_revokes_access_and_refresh_tokens(
    client: AsyncClient, sample_user: UserRow
):
    """POST /auth/logout revokes both access and refresh tokens server-side."""
    pair = create_token_pair(sample_user.id, sample_user.username, sample_user.role)

    # Sanity: both work pre-logout.
    me = await client.get("/api/v1/auth/me", headers=auth_header(pair.access_token))
    assert me.status_code == 200

    resp = await client.post(
        "/api/v1/auth/logout",
        headers=auth_header(pair.access_token),
        json={"refresh_token": pair.refresh_token},
    )
    assert resp.status_code == 204

    # Access token now rejected.
    me_after = await client.get(
        "/api/v1/auth/me", headers=auth_header(pair.access_token)
    )
    assert me_after.status_code == 401

    # Refresh token now rejected.
    refresh_after = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": pair.refresh_token},
    )
    assert refresh_after.status_code == 401


@pytest.mark.asyncio
async def test_logout_without_refresh_token_still_revokes_access(
    client: AsyncClient, sample_user: UserRow
):
    """Logout works without a body — access token is still revoked."""
    pair = create_token_pair(sample_user.id, sample_user.username, sample_user.role)

    resp = await client.post(
        "/api/v1/auth/logout", headers=auth_header(pair.access_token)
    )
    assert resp.status_code == 204

    me_after = await client.get(
        "/api/v1/auth/me", headers=auth_header(pair.access_token)
    )
    assert me_after.status_code == 401


# ---------------------------------------------------------------------------
# Refresh-token rotation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_token_rotation_invalidates_old_refresh(
    client: AsyncClient, sample_user: UserRow
):
    """A refresh token can only be redeemed once — re-use returns 401."""
    refresh_token, _ = create_refresh_token(
        sample_user.id, sample_user.username, sample_user.role
    )

    # First redemption: returns a fresh pair.
    first = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert first.status_code == 200
    new_pair = first.json()
    assert "access_token" in new_pair
    assert new_pair["refresh_token"] != refresh_token  # rotation

    # Second redemption with the *old* refresh token: rejected.
    second = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert second.status_code == 401


@pytest.mark.asyncio
async def test_refresh_returns_new_usable_pair(
    client: AsyncClient, sample_user: UserRow
):
    """The new pair from /refresh is independent and usable."""
    refresh_token, _ = create_refresh_token(
        sample_user.id, sample_user.username, sample_user.role
    )

    resp = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert resp.status_code == 200
    new_pair = resp.json()

    # New access token works.
    me = await client.get(
        "/api/v1/auth/me", headers=auth_header(new_pair["access_token"])
    )
    assert me.status_code == 200

    # New refresh token also works (and rotates again).
    rot2 = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": new_pair["refresh_token"]}
    )
    assert rot2.status_code == 200


# ---------------------------------------------------------------------------
# Legacy tokens (no jti) — accepted with a logged warning
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_legacy_token_without_jti_accepted_with_warning(
    client: AsyncClient, sample_user: UserRow, caplog: pytest.LogCaptureFixture
):
    """A token issued before AUTH-A2 (no jti claim) is still accepted, but a
    warning is logged so we can see legacy traffic during the rollout.
    """
    settings = get_settings()
    legacy_payload = {
        "sub": sample_user.id,
        "username": sample_user.username,
        "role": sample_user.role,
        "exp": datetime.now(UTC) + timedelta(minutes=10),
        "type": "access",
        # NB: no "jti" — this is the pre-AUTH-A2 token shape.
    }
    legacy_token = jose_jwt.encode(
        legacy_payload, settings.jwt_secret, algorithm=settings.jwt_algorithm
    )

    with caplog.at_level(logging.WARNING, logger="btagent.auth.middleware"):
        resp = await client.get(
            "/api/v1/auth/me", headers=auth_header(legacy_token)
        )

    assert resp.status_code == 200
    assert any(
        "legacy access token without jti" in rec.message for rec in caplog.records
    ), f"expected legacy-token warning, got: {[r.message for r in caplog.records]}"
