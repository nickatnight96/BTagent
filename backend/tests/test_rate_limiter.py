"""Tests for the in-memory sliding-window rate limiter.

Exercises the rate limiter at two levels:
1. Unit tests of the RateLimitState logic (fast, no HTTP).
2. Integration tests through the FastAPI middleware (full HTTP round-trip).

P1.2 history: the HTTP-level tests below all carried
``@pytest.mark.skipif(os.environ.get("BTAGENT_ENV") == "test")`` with the
reason "middleware may not be active in test mode". It wasn't active in ANY
mode — ``RateLimiterMiddleware`` was written, unit-tested and never registered
in ``create_app``. The skip encoded the symptom as an assumption, so CI stayed
green for the entire period the app shipped with no request throttle at all.
The middleware is now registered and the skips are gone: these tests are the
thing that would have caught it.

Cross-test isolation comes from the autouse ``_isolate_rate_limiter`` fixture
in ``conftest.py`` (the state is a module-level singleton keyed by client IP,
and every ASGI-transport request in the suite shares ``127.0.0.1``).
"""

import time

import pytest
from helpers import auth_header
from httpx import AsyncClient

from btagent_backend.middleware.rate_limiter import (
    DEFAULT_LIMIT,
    ROLE_LIMITS,
    WINDOW_SECONDS,
    RateLimitState,
    rate_limit_state,
)

# ---------------------------------------------------------------------------
# Unit tests — RateLimitState
# ---------------------------------------------------------------------------


class TestRateLimitState:
    """Direct tests of the sliding-window counter."""

    def test_allows_requests_within_limit(self):
        state = RateLimitState()
        now = time.monotonic()
        for i in range(10):
            assert state.is_allowed("key_a", limit=10, now=now + i * 0.001) is True

    def test_blocks_requests_over_limit(self):
        state = RateLimitState()
        now = time.monotonic()
        # Fill up the bucket.
        for i in range(5):
            state.is_allowed("key_b", limit=5, now=now + i * 0.001)
        # Next request should be blocked.
        assert state.is_allowed("key_b", limit=5, now=now + 0.01) is False

    def test_window_expiry_allows_new_requests(self):
        state = RateLimitState()
        now = time.monotonic()
        # Fill up at time=now.
        for i in range(3):
            state.is_allowed("key_c", limit=3, now=now)
        # Blocked immediately.
        assert state.is_allowed("key_c", limit=3, now=now + 1) is False
        # After the window elapses, requests should be allowed again.
        future = now + WINDOW_SECONDS + 1
        assert state.is_allowed("key_c", limit=3, now=future) is True

    def test_different_keys_independent(self):
        state = RateLimitState()
        now = time.monotonic()
        # Exhaust key_d.
        for _ in range(2):
            state.is_allowed("key_d", limit=2, now=now)
        assert state.is_allowed("key_d", limit=2, now=now) is False
        # key_e is still fresh.
        assert state.is_allowed("key_e", limit=2, now=now) is True

    def test_reset_clears_all(self):
        state = RateLimitState()
        now = time.monotonic()
        for _ in range(5):
            state.is_allowed("key_f", limit=5, now=now)
        assert state.is_allowed("key_f", limit=5, now=now) is False
        state.reset()
        assert state.is_allowed("key_f", limit=5, now=now) is True


# ---------------------------------------------------------------------------
# Role-based limit configuration
# ---------------------------------------------------------------------------


class TestRoleLimits:
    """Verify the role -> limit mapping is sensible."""

    def test_admin_has_highest_limit(self):
        assert ROLE_LIMITS["admin"] >= ROLE_LIMITS.get("analyst", 0)

    def test_analyst_limit_exists(self):
        assert "analyst" in ROLE_LIMITS
        assert ROLE_LIMITS["analyst"] > 0

    def test_anonymous_default_is_lowest(self):
        assert min(ROLE_LIMITS.values()) >= DEFAULT_LIMIT

    def test_different_roles_have_different_limits(self):
        limits = set(ROLE_LIMITS.values())
        # At least admin and analyst should differ.
        assert ROLE_LIMITS["admin"] != ROLE_LIMITS["analyst"]


# ---------------------------------------------------------------------------
# Integration: middleware via HTTP (requires the FastAPI test client)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_middleware_is_registered(client: AsyncClient):
    """The limiter must actually be in the app's middleware stack.

    The regression that motivated P1.2 is *absence*, not misbehaviour — every
    behavioural test below passes vacuously against an app that never installed
    the middleware (nothing 429s if nothing counts). Assert the registration
    directly, and assert the ORDER: the limiter must sit inside CORSMiddleware
    so a 429 still carries the CORS headers the SPA needs to read it, and so
    preflight OPTIONS never consume quota.
    """
    from fastapi.middleware.cors import CORSMiddleware

    from btagent_backend.middleware.rate_limiter import RateLimiterMiddleware

    app = client._transport.app  # type: ignore[attr-defined]
    classes = [m.cls for m in app.user_middleware]
    assert RateLimiterMiddleware in classes, "rate limiter is not registered"
    # add_middleware prepends, so a LOWER index means further OUT.
    assert classes.index(CORSMiddleware) < classes.index(RateLimiterMiddleware)


@pytest.mark.asyncio
async def test_rate_limit_allows_within_limit(client: AsyncClient, analyst_token: str):
    """Requests within the role's limit succeed with 200."""
    for _ in range(3):
        resp = await client.get(
            "/api/v1/auth/me",
            headers=auth_header(analyst_token),
        )
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_rate_limit_blocks_over_limit(client: AsyncClient):
    """Anonymous requests exceeding the default limit receive 429."""
    # Anonymous limit is DEFAULT_LIMIT (30). We need to exceed it.
    # Since we use the test client without auth, role=anonymous, limit=30.
    # But we cannot issue 30+ requests to authenticated-only endpoints,
    # so we use /health — except /health is excluded from rate limiting.
    # Instead, craft a token for a custom "low-limit" test by using the
    # state directly and then checking via the middleware.
    #
    # For a true integration test, fire requests to a protected endpoint
    # that will 401 *after* the rate limiter runs. The rate limiter runs
    # first as middleware, so once we exceed the limit, we get 429 even
    # before the 401 auth check.

    # Use an anonymous request to a protected endpoint.
    for i in range(DEFAULT_LIMIT):
        resp = await client.get("/api/v1/investigations")
        # These will be 401/403 (no token), but rate limiter lets them through.
        assert resp.status_code in (401, 403)

    # The next request should be rate-limited.
    resp = await client.get("/api/v1/investigations")
    assert resp.status_code == 429
    assert "Rate limit" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_admin_gets_higher_limit_than_analyst(
    client: AsyncClient, admin_token: str, analyst_token: str
):
    """Admin and analyst have different rate limits; admin's is higher."""
    admin_limit = ROLE_LIMITS["admin"]
    analyst_limit = ROLE_LIMITS["analyst"]
    assert admin_limit > analyst_limit

    # Fire analyst_limit requests as analyst (all should pass).
    for _ in range(analyst_limit):
        resp = await client.get(
            "/api/v1/auth/me",
            headers=auth_header(analyst_token),
        )
        assert resp.status_code == 200

    # Analyst is now at their limit — next should be 429.
    resp = await client.get(
        "/api/v1/auth/me",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 429

    # Admin should still have headroom.
    resp = await client.get(
        "/api/v1/auth/me",
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_rate_limit_returns_retry_after_header(client: AsyncClient):
    """A 429 response includes a Retry-After header."""
    for _ in range(DEFAULT_LIMIT):
        await client.get("/api/v1/investigations")

    resp = await client.get("/api/v1/investigations")
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers
    assert int(resp.headers["Retry-After"]) == WINDOW_SECONDS


@pytest.mark.asyncio
async def test_health_probe_is_exempt(client: AsyncClient):
    """Orchestrator liveness probes must not be throttled into a restart loop."""
    for _ in range(DEFAULT_LIMIT * 2):
        resp = await client.get("/health")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Brute-force regression (P1.2): the un-authed credential endpoints
# ---------------------------------------------------------------------------
#
# ``/auth/login`` and ``/auth/mfa/verify`` are the two endpoints where an
# unregistered limiter is not merely a capacity problem but a security one:
# both are un-authed by design, both return a definitive yes/no on a guess, and
# the MFA verify handler's own docstring asserts that "the global per-IP rate
# limiter (anonymous bucket) throttles brute-force attempts" — a claim that was
# false for the entire life of the app. A failed attempt keys to the anonymous
# IP bucket (no verified token ⇒ no user key), so repeated guesses share one
# budget of DEFAULT_LIMIT per window regardless of which account is targeted.


@pytest.mark.asyncio
async def test_repeated_failed_logins_are_throttled(client: AsyncClient, sample_user):
    """Password guessing hits 429 after the anonymous budget is spent."""
    body = {"username": sample_user.username, "password": "wrong-password"}

    for i in range(DEFAULT_LIMIT):
        resp = await client.post("/api/v1/auth/login", json=body)
        assert resp.status_code == 401, f"guess {i} should be a clean auth failure"

    resp = await client.post("/api/v1/auth/login", json=body)
    assert resp.status_code == 429
    assert "Rate limit" in resp.json()["detail"]
    assert int(resp.headers["Retry-After"]) == WINDOW_SECONDS


@pytest.mark.asyncio
async def test_login_throttle_is_not_per_username(client: AsyncClient, sample_user):
    """Rotating the username does not buy a fresh budget.

    The bucket is keyed by client IP for un-authed requests, so username
    spraying (one guess each across many accounts) is throttled just like
    password guessing against a single account.
    """
    for i in range(DEFAULT_LIMIT):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": f"no_such_user_{i}", "password": "x"},
        )
        assert resp.status_code == 401

    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": sample_user.username, "password": "also-wrong"},
    )
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_repeated_mfa_verify_attempts_are_throttled(client: AsyncClient):
    """TOTP guessing hits 429 after the anonymous budget is spent.

    A 6-digit TOTP is a 10^6 space with a ~30s validity window; unthrottled,
    the second factor is materially weaker than it appears. No MFA enrollment
    is needed to exercise the throttle — every request without a valid
    challenge is a 401 that still consumes the anonymous bucket, which is
    exactly the budget an attacker would be spending.
    """
    body = {"code": "000000"}

    for i in range(DEFAULT_LIMIT):
        resp = await client.post("/api/v1/auth/mfa/verify", json=body)
        assert resp.status_code == 401, f"attempt {i} should be a clean auth failure"

    resp = await client.post("/api/v1/auth/mfa/verify", json=body)
    assert resp.status_code == 429
    assert "Rate limit" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_login_and_mfa_share_the_anonymous_budget(client: AsyncClient, sample_user):
    """The throttle is per-client, not per-endpoint — no budget laundering."""
    half = DEFAULT_LIMIT // 2
    for _ in range(half):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": sample_user.username, "password": "wrong"},
        )
        assert resp.status_code == 401
    for _ in range(DEFAULT_LIMIT - half):
        resp = await client.post("/api/v1/auth/mfa/verify", json={"code": "000000"})
        assert resp.status_code == 401

    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": sample_user.username, "password": "wrong"},
    )
    assert resp.status_code == 429
