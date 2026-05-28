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
    decode_token,
)
from btagent_backend.auth.revocation import (
    _reset_for_tests,
    is_family_revoked,
    is_revoked,
    is_user_revoked,
    revoke,
    revoke_user_tokens,
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
async def test_token_accepted_when_not_revoked(client: AsyncClient, analyst_token: str):
    """A freshly-minted access token is accepted by /auth/me."""
    resp = await client.get("/api/v1/auth/me", headers=auth_header(analyst_token))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_token_rejected_after_revoke(client: AsyncClient, sample_user: UserRow):
    """Revoking an access token's jti causes /auth/me to return 401."""
    token, jti = create_access_token(sample_user.id, sample_user.username, sample_user.role)

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
async def test_logout_revokes_access_and_refresh_tokens(client: AsyncClient, sample_user: UserRow):
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
    me_after = await client.get("/api/v1/auth/me", headers=auth_header(pair.access_token))
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

    resp = await client.post("/api/v1/auth/logout", headers=auth_header(pair.access_token))
    assert resp.status_code == 204

    me_after = await client.get("/api/v1/auth/me", headers=auth_header(pair.access_token))
    assert me_after.status_code == 401


# ---------------------------------------------------------------------------
# Refresh-token rotation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_token_rotation_invalidates_old_refresh(
    client: AsyncClient, sample_user: UserRow
):
    """A refresh token can only be redeemed once — re-use returns 401."""
    refresh_token, _, _ = create_refresh_token(
        sample_user.id, sample_user.username, sample_user.role
    )

    # First redemption: returns a fresh pair.
    first = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert first.status_code == 200
    new_pair = first.json()
    assert "access_token" in new_pair
    assert new_pair["refresh_token"] != refresh_token  # rotation

    # Second redemption with the *old* refresh token: rejected.
    second = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert second.status_code == 401


@pytest.mark.asyncio
async def test_refresh_returns_new_usable_pair(client: AsyncClient, sample_user: UserRow):
    """The new pair from /refresh is independent and usable."""
    refresh_token, _, _ = create_refresh_token(
        sample_user.id, sample_user.username, sample_user.role
    )

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    new_pair = resp.json()

    # New access token works.
    me = await client.get("/api/v1/auth/me", headers=auth_header(new_pair["access_token"]))
    assert me.status_code == 200

    # New refresh token also works (and rotates again).
    rot2 = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": new_pair["refresh_token"]}
    )
    assert rot2.status_code == 200


# ---------------------------------------------------------------------------
# P142: refresh-token reuse detection → family revocation (theft response)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_carries_family_id_preserved_across_rotation(
    client: AsyncClient, sample_user: UserRow
):
    """Rotation keeps the same family id (``fid``); the jti rotates."""
    refresh_token, jti0, fid0 = create_refresh_token(
        sample_user.id, sample_user.username, sample_user.role
    )

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    new_refresh = resp.json()["refresh_token"]

    rotated = decode_token(new_refresh)
    # New jti, SAME family.
    assert rotated.jti is not None and rotated.jti != jti0
    assert rotated.fid == fid0


@pytest.mark.asyncio
async def test_reusing_rotated_refresh_revokes_whole_family(
    client: AsyncClient, sample_user: UserRow
):
    """Replaying a consumed refresh token is treated as theft → family revoked.

    Sequence: R0 -> (rotate) -> R1. Replaying R0 (already consumed) must:
      1. return 401, and
      2. revoke the entire family, so the *legitimate* descendant R1 is now
         also rejected.
    """
    r0, _, fid = create_refresh_token(sample_user.id, sample_user.username, sample_user.role)

    # Legit rotation: R0 -> R1.
    first = await client.post("/api/v1/auth/refresh", json={"refresh_token": r0})
    assert first.status_code == 200
    r1 = first.json()["refresh_token"]

    # The family is not revoked yet — R1 is the live token.
    assert await is_family_revoked(fid) is False

    # Attacker replays the consumed R0 → reuse detected.
    replay = await client.post("/api/v1/auth/refresh", json={"refresh_token": r0})
    assert replay.status_code == 401

    # The whole family is now revoked at the storage layer...
    assert await is_family_revoked(fid) is True

    # ...so even the legitimate descendant R1 is dead.
    r1_attempt = await client.post("/api/v1/auth/refresh", json={"refresh_token": r1})
    assert r1_attempt.status_code == 401
    assert "invalid_token" in r1_attempt.headers.get("www-authenticate", "")


# ---------------------------------------------------------------------------
# P142: admin "revoke this user's sessions" (per-user epoch)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_revoke_user_sessions_rejects_existing_tokens(
    client: AsyncClient, admin_token: str, sample_user: UserRow
):
    """Admin POST /auth/revoke/{user_id} invalidates the target's tokens."""
    pair = create_token_pair(sample_user.id, sample_user.username, sample_user.role)

    # Pre-revoke: the user's token works.
    me = await client.get("/api/v1/auth/me", headers=auth_header(pair.access_token))
    assert me.status_code == 200

    # Admin revokes the user's sessions.
    resp = await client.post(
        f"/api/v1/auth/revoke/{sample_user.id}", headers=auth_header(admin_token)
    )
    assert resp.status_code == 204

    # The user's access token is now rejected.
    me_after = await client.get("/api/v1/auth/me", headers=auth_header(pair.access_token))
    assert me_after.status_code == 401
    assert "invalid_token" in me_after.headers.get("www-authenticate", "")

    # The user's refresh token is also rejected.
    refresh_after = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": pair.refresh_token}
    )
    assert refresh_after.status_code == 401


@pytest.mark.asyncio
async def test_admin_revoke_lets_user_log_in_again(
    client: AsyncClient, admin_token: str, sample_user: UserRow
):
    """After a force-logout, a NEW token (later iat) for the same user works."""
    import time

    # Revoke as of two seconds ago, so a token minted *now* has a strictly
    # later ``iat`` and survives (this is the "user logs back in" path).
    await revoke_user_tokens(sample_user.id, ttl_seconds=3600, now=time.time() - 2)

    fresh = create_token_pair(sample_user.id, sample_user.username, sample_user.role)
    me = await client.get("/api/v1/auth/me", headers=auth_header(fresh.access_token))
    assert me.status_code == 200


@pytest.mark.asyncio
async def test_non_admin_cannot_revoke_user_sessions(
    client: AsyncClient, analyst_token: str, sample_user: UserRow
):
    """An analyst cannot force-logout other users (RBAC: admin only)."""
    resp = await client.post(
        f"/api/v1/auth/revoke/{sample_user.id}", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_revoke_unknown_user_returns_404(client: AsyncClient, admin_token: str):
    """Revoking a non-existent user returns 404."""
    resp = await client.post(
        "/api/v1/auth/revoke/usr_does_not_exist", headers=auth_header(admin_token)
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_is_user_revoked_unit_behaviour():
    """Unit: tokens before the epoch are revoked; at/after are not; legacy is not."""
    import time

    user_id = "usr_epoch_unit"
    now = time.time()
    # Stored epoch = int(now) + 1, so tokens issued in this second or earlier
    # are revoked; tokens issued a second or more later survive.
    await revoke_user_tokens(user_id, ttl_seconds=3600, now=now)

    # Issued before the revoke second → revoked.
    assert await is_user_revoked(user_id, int(now) - 1) is True
    # Issued in the same second as the revoke → revoked (force-logout catches it).
    assert await is_user_revoked(user_id, int(now)) is True
    # Issued comfortably after the epoch → not revoked.
    assert await is_user_revoked(user_id, int(now) + 5) is False
    # Legacy token without iat → cannot be compared, not revoked.
    assert await is_user_revoked(user_id, None) is False
    # Unknown user → not revoked.
    assert await is_user_revoked("usr_never", int(now) - 100) is False


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
        resp = await client.get("/api/v1/auth/me", headers=auth_header(legacy_token))

    assert resp.status_code == 200
    assert any("legacy access token without jti" in rec.message for rec in caplog.records), (
        f"expected legacy-token warning, got: {[r.message for r in caplog.records]}"
    )
