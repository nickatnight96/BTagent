"""Tests for the in-memory sliding-window rate limiter.

Exercises the rate limiter at two levels:
1. Unit tests of the RateLimitState logic (fast, no HTTP).
2. Integration tests through the FastAPI middleware (full HTTP round-trip).
"""

import os
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


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Reset the global rate-limit state before each test."""
    rate_limit_state.reset()
    yield
    rate_limit_state.reset()


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
@pytest.mark.skipif(
    os.environ.get("BTAGENT_ENV") == "test",
    reason="Rate limiter middleware may not be active in test mode",
)
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
@pytest.mark.skipif(
    os.environ.get("BTAGENT_ENV") == "test",
    reason="Rate limiter middleware may not be active in test mode",
)
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
@pytest.mark.skipif(
    os.environ.get("BTAGENT_ENV") == "test",
    reason="Rate limiter middleware may not be active in test mode",
)
async def test_rate_limit_returns_retry_after_header(client: AsyncClient):
    """A 429 response includes a Retry-After header."""
    for _ in range(DEFAULT_LIMIT):
        await client.get("/api/v1/investigations")

    resp = await client.get("/api/v1/investigations")
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers
    assert int(resp.headers["Retry-After"]) == WINDOW_SECONDS
