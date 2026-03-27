"""In-memory sliding-window rate limiter middleware.

Production deployments should swap this for a Redis-backed implementation.
This module provides a simple per-key (user or IP) rate limiter that is
suitable for single-process dev/test usage.

Rate limits vary by role:
    admin                -> 200 req / minute
    incident_commander   -> 150 req / minute
    senior_analyst       -> 120 req / minute
    analyst              ->  60 req / minute
    anonymous (no token) ->  30 req / minute
"""

import time
from collections import defaultdict
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from btagent_backend.config import get_settings

ROLE_LIMITS: dict[str, int] = {
    "admin": 200,
    "incident_commander": 150,
    "senior_analyst": 120,
    "analyst": 60,
}

DEFAULT_LIMIT = 30  # anonymous / unrecognised role
WINDOW_SECONDS = 60


class RateLimitState:
    """Thread-safe (GIL-protected) sliding-window counter store."""

    def __init__(self):
        # key -> list of request timestamps within the current window
        self._hits: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str, limit: int, now: float | None = None) -> bool:
        now = now or time.monotonic()
        window_start = now - WINDOW_SECONDS

        # Prune expired entries.
        self._hits[key] = [t for t in self._hits[key] if t > window_start]

        if len(self._hits[key]) >= limit:
            return False

        self._hits[key].append(now)
        return True

    def reset(self):
        self._hits.clear()


# Module-level singleton so tests can access / reset state.
rate_limit_state = RateLimitState()


def _extract_role(request: Request) -> str:
    """Best-effort role extraction from the request state or auth header.

    The auth middleware sets request.state.user if a valid token is present.
    For rate-limiting purposes we fall back to 'anonymous' if unavailable.
    """
    # If our auth dependency already populated the user:
    user = getattr(request.state, "user", None)
    if user is not None:
        return getattr(user, "role", "anonymous")

    # Lightweight JWT peek without full validation (for rate limiting only).
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        try:
            import json
            import base64

            token = auth.split(" ", 1)[1]
            payload_b64 = token.split(".")[1]
            # Add padding.
            payload_b64 += "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            return payload.get("role", "anonymous")
        except Exception:
            pass

    return "anonymous"


def _client_key(request: Request) -> str:
    """Produce a rate-limit key from user ID or client IP."""
    user = getattr(request.state, "user", None)
    if user is not None and hasattr(user, "id"):
        return f"user:{user.id}"
    # Fall back to client host.
    client = request.client
    return f"ip:{client.host if client else 'unknown'}"


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware that enforces per-role request rate limits."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        settings = get_settings()
        if not settings.rate_limit_enabled:
            return await call_next(request)

        # Skip health checks.
        if request.url.path == "/health":
            return await call_next(request)

        role = _extract_role(request)
        limit = ROLE_LIMITS.get(role, DEFAULT_LIMIT)
        key = _client_key(request)

        if not rate_limit_state.is_allowed(key, limit):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={"Retry-After": str(WINDOW_SECONDS)},
            )

        response = await call_next(request)
        return response
