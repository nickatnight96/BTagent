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
from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from btagent_backend.auth.cookies import ACCESS_COOKIE_NAME
from btagent_backend.auth.jwt import TokenPayload, decode_token
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


def _verified_payload(request: Request) -> TokenPayload | None:
    """Return the *verified* access-token payload for this request, or ``None``.

    GH #378: rate-limit tiering must never trust an unverified token. The old
    implementation base64-decoded the JWT payload *without checking the
    signature*, so an attacker could send ``Bearer x.<b64 {"role":"admin"}>.x``
    and be granted the admin tier with no valid token at all. We now validate
    the bearer token with the same verifier the auth layer uses
    (:func:`btagent_backend.auth.jwt.decode_token`, as in ``get_current_user``)
    and trust its claims only when the signature, expiry and token ``type`` all
    check out. Any missing / malformed / expired / otherwise invalid token
    degrades to the anonymous tier (returns ``None``) — never a privileged
    tier, and never a 500 raised from the middleware.
    """
    # Mirror get_current_user's dual-read transport: httpOnly cookie first,
    # Authorization header second.
    token = request.cookies.get(ACCESS_COOKIE_NAME)
    if not token:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
    if not token:
        return None

    try:
        payload = decode_token(token)
    except Exception:
        # A bad signature raises JWTError; a malformed token or an unexpected
        # payload shape can raise other errors (ValueError, ValidationError,
        # …). Whatever the cause, degrade to anonymous — the limiter must stay
        # non-blocking and must never surface a 500 to the caller.
        return None

    # Only a genuine *access* token confers a tier — a refresh / mfa_challenge
    # token (or anything else) is treated as anonymous, matching the auth layer.
    if payload.type != "access":
        return None

    return payload


def _extract_role(payload: TokenPayload | None) -> str:
    """Role tier for the request, derived only from a verified token payload."""
    if payload is None:
        return "anonymous"
    return payload.role or "anonymous"


def _client_key(request: Request, payload: TokenPayload | None) -> str:
    """Produce a rate-limit key from the verified subject or the client IP."""
    if payload is not None:
        return f"user:{payload.sub}"
    # Anonymous / unverifiable requests are keyed by client host.
    client = request.client
    return f"ip:{client.host if client else 'unknown'}"


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware that enforces per-role request rate limits."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        settings = get_settings()
        if not settings.rate_limit_enabled:
            return await call_next(request)

        # Skip health/readiness probes (hit frequently by orchestrators).
        if request.url.path == "/health" or request.url.path.startswith("/health/"):
            return await call_next(request)

        # Verify the token once (GH #378) and derive both the tier and the
        # rate-limit key from the *verified* payload — an unverifiable token
        # falls back to the anonymous tier keyed by client IP.
        payload = _verified_payload(request)
        role = _extract_role(payload)
        limit = ROLE_LIMITS.get(role, DEFAULT_LIMIT)
        key = _client_key(request, payload)

        if not rate_limit_state.is_allowed(key, limit):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={"Retry-After": str(WINDOW_SECONDS)},
            )

        response = await call_next(request)
        return response
