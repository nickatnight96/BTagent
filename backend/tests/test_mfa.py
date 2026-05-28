"""Tests for opt-in TOTP MFA (#144, Phase 1a).

Covers:
  * Fernet secret-at-rest round-trip + recovery-code hashing/single-use (unit).
  * enroll → confirm → login(challenge) → verify happy path (HTTP).
  * wrong TOTP code at verify is rejected.
  * a replayed challenge (same cookie reused after a successful verify) is
    rejected (jti revoked on use).
  * an expired/garbage challenge token is rejected.
  * recovery code logs in once and is then single-use (consumed).
  * REGRESSION: a user with NO MFA logs in exactly as before — a real token
    pair + auth cookies, no ``mfa_required``.

Pattern mirrors test_cookie_auth.py: seed users via the test session factory,
drive the FastAPI app through the httpx ASGI client (which carries cookies in
its jar between calls).
"""

from datetime import UTC, datetime

import pyotp
import pytest
import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from conftest import _ANALYST_PASSWORD  # type: ignore[import-not-found]
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth import mfa as mfa_lib
from btagent_backend.auth.cookies import (
    ACCESS_COOKIE_NAME,
    MFA_CHALLENGE_COOKIE_NAME,
    REFRESH_COOKIE_NAME,
)
from btagent_backend.auth.jwt import create_mfa_challenge_token, hash_password
from btagent_backend.auth.revocation import _reset_for_tests
from btagent_backend.db.models import DEFAULT_ORG_ID, UserRow
from btagent_backend.db.models_mfa import UserMFARow

# Login challenge cookie travels only to /api/v1/auth/mfa/* — the verify
# endpoint sits under that prefix so httpx's jar carries it automatically.
_VERIFY_PATH = "/api/v1/auth/mfa/verify"
_LOGIN_PATH = "/api/v1/auth/login"
_ENROLL_PATH = "/api/v1/auth/mfa/enroll"
_CONFIRM_PATH = "/api/v1/auth/mfa/confirm"


@pytest_asyncio.fixture(autouse=True)
async def _clean_revocation(_init_db):
    """Each test starts with an empty revocation list / clean Redis cache.

    Depends on ``_init_db`` so the schema is created before any test body runs
    (our seed helpers open sessions directly via ``_test_session_factory``,
    which would otherwise race ahead of table creation).
    """
    from btagent_backend.auth import revocation

    _reset_for_tests()
    # Force the in-memory revocation store (mirrors test_cookie_auth) so no
    # ambient Redis influences the single-use challenge assertions.
    revocation._redis_unavailable = True
    yield
    _reset_for_tests()


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


async def _seed_user(s: AsyncSession, suffix: str) -> UserRow:
    """Seed an analyst via the test-loop ``db_session`` (matches sample_user)."""
    u = UserRow(
        id=generate_id("usr"),
        org_id=DEFAULT_ORG_ID,
        username=f"mfauser_{suffix}",
        email=f"mfauser_{suffix}@btagent.test",
        password_hash=hash_password(_ANALYST_PASSWORD),
        role="analyst",
        created_at=datetime.now(UTC),
    )
    s.add(u)
    await s.commit()
    await s.refresh(u)
    return u


async def _enable_mfa_directly(
    s: AsyncSession, user_id: str, secret: str, recovery_codes: list[str]
) -> None:
    """Write an *enabled* MFA row straight to the DB (skip the HTTP enroll/confirm)."""
    hashes = mfa_lib.hash_recovery_codes(recovery_codes)
    s.add(
        UserMFARow(
            user_id=user_id,
            secret_enc=mfa_lib.encrypt_secret(secret),
            enabled=True,
            confirmed_at=datetime.now(UTC),
            recovery_codes_enc=mfa_lib.serialize_recovery_hashes(hashes),
        )
    )
    await s.commit()


# ---------------------------------------------------------------------------
# Unit: crypto + recovery codes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fernet_secret_round_trip():
    secret = mfa_lib.generate_secret()
    token = mfa_lib.encrypt_secret(secret)
    assert token != secret  # actually encrypted, not stored plaintext
    assert mfa_lib.decrypt_secret(token) == secret


@pytest.mark.asyncio
async def test_recovery_code_hashing_and_single_use():
    codes = mfa_lib.generate_recovery_codes(5)
    assert len(codes) == 5
    hashes = mfa_lib.hash_recovery_codes(codes)
    assert all(h != c for h, c in zip(hashes, codes))  # hashed, not plaintext

    # A valid code matches and is consumed.
    matched, remaining = mfa_lib.verify_and_consume_recovery_code(codes[0], hashes)
    assert matched is True
    assert len(remaining) == 4

    # The consumed code no longer matches the remaining list (single-use).
    matched_again, _ = mfa_lib.verify_and_consume_recovery_code(codes[0], remaining)
    assert matched_again is False

    # A bogus code never matches.
    bad, _ = mfa_lib.verify_and_consume_recovery_code("ffff-fffff", remaining)
    assert bad is False


@pytest.mark.asyncio
async def test_verify_totp_rejects_garbage():
    secret = mfa_lib.generate_secret()
    assert mfa_lib.verify_totp(secret, "000000") in (True, False)  # numeric ok to attempt
    assert mfa_lib.verify_totp(secret, "abcdef") is False
    assert mfa_lib.verify_totp(secret, "") is False
    # The right current code verifies.
    assert mfa_lib.verify_totp(secret, pyotp.TOTP(secret).now()) is True


# ---------------------------------------------------------------------------
# REGRESSION: no-MFA login is unchanged
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_without_mfa_returns_token_pair(client: AsyncClient, db_session: AsyncSession):
    """A user with no MFA row logs in exactly as before: token pair + cookies."""
    user = await _seed_user(db_session, "nomfa")
    resp = await client.post(
        _LOGIN_PATH,
        json={"username": user.username, "password": _ANALYST_PASSWORD},
    )
    assert resp.status_code == 200
    body = resp.json()
    # The old contract: a real token pair, NOT an mfa_required challenge.
    assert "mfa_required" not in body
    assert body.get("access_token")
    assert body.get("refresh_token")
    # Session cookies set; no challenge cookie.
    assert ACCESS_COOKIE_NAME in client.cookies
    assert REFRESH_COOKIE_NAME in client.cookies
    assert MFA_CHALLENGE_COOKIE_NAME not in client.cookies
    client.cookies.clear()


@pytest.mark.asyncio
async def test_login_with_unconfirmed_mfa_is_unchanged(
    client: AsyncClient, db_session: AsyncSession
):
    """A row that exists but is NOT enabled (mid-enrollment) does not gate login."""
    user = await _seed_user(db_session, "pending")
    secret = mfa_lib.generate_secret()
    db_session.add(
        UserMFARow(
            user_id=user.id,
            secret_enc=mfa_lib.encrypt_secret(secret),
            enabled=False,  # not yet confirmed
            recovery_codes_enc="[]",
        )
    )
    await db_session.commit()

    resp = await client.post(
        _LOGIN_PATH,
        json={"username": user.username, "password": _ANALYST_PASSWORD},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "mfa_required" not in body
    assert body.get("access_token")
    client.cookies.clear()


# ---------------------------------------------------------------------------
# enroll -> confirm -> login(challenge) -> verify happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enroll_confirm_then_login_requires_and_passes_mfa(
    client: AsyncClient, db_session: AsyncSession
):
    user = await _seed_user(db_session, "happy")

    # 1. Log in (no MFA yet) to get an authed session for enrollment.
    login = await client.post(
        _LOGIN_PATH, json={"username": user.username, "password": _ANALYST_PASSWORD}
    )
    assert login.status_code == 200
    assert "access_token" in login.json()

    # 2. Enroll: returns provisioning URI + secret + recovery codes.
    enroll = await client.post(_ENROLL_PATH)
    assert enroll.status_code == 200
    ebody = enroll.json()
    assert ebody["provisioning_uri"].startswith("otpauth://")
    secret = ebody["secret"]
    assert len(ebody["recovery_codes"]) == mfa_lib.RECOVERY_CODE_COUNT

    # 3. Confirm with a live TOTP code -> enabled.
    confirm = await client.post(_CONFIRM_PATH, json={"code": pyotp.TOTP(secret).now()})
    assert confirm.status_code == 204

    # 4. New login session is now MFA-gated.
    client.cookies.clear()
    login2 = await client.post(
        _LOGIN_PATH, json={"username": user.username, "password": _ANALYST_PASSWORD}
    )
    assert login2.status_code == 200
    assert login2.json() == {"mfa_required": True}
    # Challenge cookie set; NO session cookies yet.
    assert MFA_CHALLENGE_COOKIE_NAME in client.cookies
    assert ACCESS_COOKIE_NAME not in client.cookies

    # 5. Verify with a fresh TOTP -> real token pair + session cookies.
    verify = await client.post(_VERIFY_PATH, json={"code": pyotp.TOTP(secret).now()})
    assert verify.status_code == 200
    vbody = verify.json()
    assert vbody.get("access_token")
    assert vbody.get("refresh_token")
    assert ACCESS_COOKIE_NAME in client.cookies
    assert REFRESH_COOKIE_NAME in client.cookies

    # 6. The challenge-token type can't be used as a session token: /auth/me
    #    with the (now invalid) challenge would 401 — but we cleared it, so
    #    instead confirm /auth/me works with the freshly-minted access cookie.
    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["id"] == user.id
    client.cookies.clear()


# ---------------------------------------------------------------------------
# verify failure modes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_wrong_code_rejected(client: AsyncClient, db_session: AsyncSession):
    user = await _seed_user(db_session, "wrongcode")
    secret = mfa_lib.generate_secret()
    await _enable_mfa_directly(db_session, user.id, secret, mfa_lib.generate_recovery_codes())

    client.cookies.clear()
    login = await client.post(
        _LOGIN_PATH, json={"username": user.username, "password": _ANALYST_PASSWORD}
    )
    assert login.json() == {"mfa_required": True}

    # A deliberately-wrong 6-digit code (not the current TOTP) is rejected.
    current = pyotp.TOTP(secret).now()
    wrong = "000000" if current != "000000" else "111111"
    resp = await client.post(_VERIFY_PATH, json={"code": wrong})
    assert resp.status_code == 401
    assert ACCESS_COOKIE_NAME not in client.cookies
    client.cookies.clear()


@pytest.mark.asyncio
async def test_replayed_challenge_rejected(client: AsyncClient, db_session: AsyncSession):
    """A challenge is single-use: after a successful verify it cannot be reused."""
    user = await _seed_user(db_session, "replay")
    secret = mfa_lib.generate_secret()
    await _enable_mfa_directly(db_session, user.id, secret, mfa_lib.generate_recovery_codes())

    client.cookies.clear()
    await client.post(_LOGIN_PATH, json={"username": user.username, "password": _ANALYST_PASSWORD})
    # Grab the challenge cookie value so we can replay it after it's consumed.
    challenge_value = client.cookies.get(MFA_CHALLENGE_COOKIE_NAME)
    assert challenge_value

    ok = await client.post(_VERIFY_PATH, json={"code": pyotp.TOTP(secret).now()})
    assert ok.status_code == 200

    # Replay the (now-revoked) challenge directly against verify.
    client.cookies.clear()
    client.cookies.set(MFA_CHALLENGE_COOKIE_NAME, challenge_value, path="/api/v1/auth/mfa")
    replay = await client.post(_VERIFY_PATH, json={"code": pyotp.TOTP(secret).now()})
    assert replay.status_code == 401
    client.cookies.clear()


@pytest.mark.asyncio
async def test_expired_or_garbage_challenge_rejected(client: AsyncClient):
    """A malformed / unsigned challenge cookie is rejected with 401."""
    client.cookies.clear()
    client.cookies.set(MFA_CHALLENGE_COOKIE_NAME, "not-a-real-jwt", path="/api/v1/auth/mfa")
    resp = await client.post(_VERIFY_PATH, json={"code": "123456"})
    assert resp.status_code == 401

    # Missing challenge entirely -> 401.
    client.cookies.clear()
    resp2 = await client.post(_VERIFY_PATH, json={"code": "123456"})
    assert resp2.status_code == 401
    client.cookies.clear()


@pytest.mark.asyncio
async def test_challenge_token_cannot_be_used_as_session_token(
    client: AsyncClient, db_session: AsyncSession
):
    """A type=mfa_challenge token must be rejected by get_current_user."""
    user = await _seed_user(db_session, "nottoken")
    token, _ = create_mfa_challenge_token(user.id, user.username, user.role)
    # Present the challenge as a bearer access token.
    resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# recovery code login (single-use)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_recovery_code_logs_in_once(client: AsyncClient, db_session: AsyncSession):
    user = await _seed_user(db_session, "recovery")
    secret = mfa_lib.generate_secret()
    codes = mfa_lib.generate_recovery_codes()
    await _enable_mfa_directly(db_session, user.id, secret, codes)

    # Login -> challenge.
    client.cookies.clear()
    await client.post(_LOGIN_PATH, json={"username": user.username, "password": _ANALYST_PASSWORD})
    # Verify with a recovery code instead of a TOTP.
    ok = await client.post(_VERIFY_PATH, json={"code": codes[0]})
    assert ok.status_code == 200
    assert ACCESS_COOKIE_NAME in client.cookies

    # That recovery code is now consumed: a fresh login + reuse fails.
    client.cookies.clear()
    await client.post(_LOGIN_PATH, json={"username": user.username, "password": _ANALYST_PASSWORD})
    reuse = await client.post(_VERIFY_PATH, json={"code": codes[0]})
    assert reuse.status_code == 401

    # But a *different* recovery code still works.
    ok2 = await client.post(_VERIFY_PATH, json={"code": codes[1]})
    assert ok2.status_code == 200
    client.cookies.clear()
