"""Tests for authentication and authorization endpoints."""

import itertools
from datetime import UTC, datetime, timedelta

import pytest
from helpers import auth_header
from httpx import AsyncClient
from jose import jwt as jose_jwt

from btagent_backend.auth.jwt import (
    create_access_token,
    create_token_pair,
    decode_token,
    hash_password,
    verify_password,
)
from btagent_backend.config import get_settings
from btagent_backend.db.models import UserRow

# Counter for unique usernames/emails in register tests.
_reg_counter = itertools.count(1)


# ---- Password hashing / verification ----


@pytest.mark.asyncio
async def test_password_hash_and_verify():
    """hash_password + verify_password round-trips correctly."""
    plain = "Sup3r-Secur3!"
    hashed = hash_password(plain)
    assert hashed != plain
    assert verify_password(plain, hashed) is True


@pytest.mark.asyncio
async def test_password_verify_rejects_wrong():
    """verify_password rejects an incorrect password."""
    hashed = hash_password("correct-password")
    assert verify_password("wrong-password", hashed) is False


@pytest.mark.asyncio
async def test_password_hash_is_unique():
    """Two calls with the same password produce different hashes (random salt)."""
    h1 = hash_password("same-pass")
    h2 = hash_password("same-pass")
    assert h1 != h2  # bcrypt salts differ


# ---- Token creation / decoding ----


@pytest.mark.asyncio
async def test_create_token_pair_returns_both_tokens():
    """create_token_pair returns access and refresh tokens."""
    pair = create_token_pair("usr_abc", "alice", "analyst")
    assert pair.access_token
    assert pair.refresh_token
    assert pair.token_type == "bearer"
    assert pair.expires_in > 0


@pytest.mark.asyncio
async def test_decode_access_token():
    """decode_token on a fresh access token returns correct payload."""
    token = create_access_token("usr_123", "bob", "admin")
    payload = decode_token(token)
    assert payload.sub == "usr_123"
    assert payload.username == "bob"
    assert payload.role == "admin"
    assert payload.type == "access"


@pytest.mark.asyncio
async def test_expired_token_rejected():
    """decode_token raises for an expired token."""
    settings = get_settings()
    expired_payload = {
        "sub": "usr_old",
        "username": "expired_user",
        "role": "analyst",
        "exp": datetime.now(UTC) - timedelta(hours=1),
        "type": "access",
    }
    token = jose_jwt.encode(expired_payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    with pytest.raises(Exception):
        decode_token(token)


# ---- POST /api/v1/auth/login ----


@pytest.mark.asyncio
async def test_login_valid_credentials(client: AsyncClient, sample_user: UserRow):
    """Login with correct username/password returns a token pair."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": sample_user.username, "password": "Analyst-P@ss-456!"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_invalid_password(client: AsyncClient, sample_user: UserRow):
    """Login with wrong password returns 401."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": sample_user.username, "password": "wrong-password"},
    )
    assert resp.status_code == 401
    assert "Invalid" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_login_nonexistent_user(client: AsyncClient):
    """Login with a username that does not exist returns 401."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "no_such_user", "password": "anything"},
    )
    assert resp.status_code == 401


# ---- GET /api/v1/auth/me ----


@pytest.mark.asyncio
async def test_me_with_valid_token(client: AsyncClient, analyst_token: str, sample_user: UserRow):
    """GET /me with a valid bearer token returns user info."""
    resp = await client.get("/api/v1/auth/me", headers=auth_header(analyst_token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == sample_user.username
    assert body["role"] == "analyst"
    assert "id" in body


@pytest.mark.asyncio
async def test_me_without_token(client: AsyncClient):
    """GET /me without Authorization header returns 401 or 403."""
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_me_with_expired_token(client: AsyncClient):
    """GET /me with an expired token is rejected."""
    settings = get_settings()
    expired = jose_jwt.encode(
        {
            "sub": "usr_gone",
            "username": "ghost",
            "role": "analyst",
            "exp": datetime.now(UTC) - timedelta(seconds=10),
            "type": "access",
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    resp = await client.get("/api/v1/auth/me", headers=auth_header(expired))
    assert resp.status_code == 401


# ---- POST /api/v1/auth/refresh ----


@pytest.mark.asyncio
async def test_refresh_token_works(client: AsyncClient, sample_user: UserRow):
    """Exchanging a valid refresh token returns a new token pair."""
    pair = create_token_pair(sample_user.id, sample_user.username, sample_user.role)
    resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": pair.refresh_token},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert "refresh_token" in body


@pytest.mark.asyncio
async def test_refresh_with_access_token_rejected(client: AsyncClient, analyst_token: str):
    """Using an access token as a refresh token is rejected."""
    resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": analyst_token},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_with_invalid_token_rejected(client: AsyncClient):
    """A garbage refresh token is rejected."""
    resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "not.a.real.token"},
    )
    assert resp.status_code == 401


# ---- POST /api/v1/auth/register ----


@pytest.mark.asyncio
async def test_admin_can_register_user(client: AsyncClient, admin_token: str):
    """An admin can register a new user and receives 201."""
    n = next(_reg_counter)
    resp = await client.post(
        "/api/v1/auth/register",
        headers=auth_header(admin_token),
        json={
            "username": f"newanalyst_{n}",
            "email": f"new_{n}@btagent.test",
            "password": "New-P@ss-789!",
            "role": "analyst",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["username"] == f"newanalyst_{n}"
    assert body["role"] == "analyst"
    assert body["id"].startswith("usr_")


@pytest.mark.asyncio
async def test_analyst_cannot_register_user(client: AsyncClient, analyst_token: str):
    """An analyst should be forbidden from registering users (403)."""
    n = next(_reg_counter)
    resp = await client.post(
        "/api/v1/auth/register",
        headers=auth_header(analyst_token),
        json={
            "username": f"sneaky_{n}",
            "email": f"sneaky_{n}@btagent.test",
            "password": "Sneak-123!",
            "role": "analyst",
        },
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_duplicate_registration_returns_409(
    client: AsyncClient, admin_token: str, admin_user: UserRow
):
    """Registering a user with an existing username returns 409."""
    resp = await client.post(
        "/api/v1/auth/register",
        headers=auth_header(admin_token),
        json={
            "username": admin_user.username,
            "email": "dup_unique@btagent.test",
            "password": "Dup-P@ss-000!",
            "role": "analyst",
        },
    )
    assert resp.status_code == 409
    assert "already exists" in resp.json()["detail"]
