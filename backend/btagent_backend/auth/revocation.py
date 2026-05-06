"""JWT revocation list backed by Redis.

When a user logs out, or when a refresh token is rotated, we mark the token's
``jti`` (JWT ID) as revoked. A revoked entry has TTL equal to the token's
remaining lifetime so the set self-prunes and never grows unboundedly.

This mirrors the connection pattern used by ``services/task_manager.py`` and
``ws/hub.py``: lazily open a ``redis.asyncio.Redis`` client from
``settings.redis_url``. When Redis is unreachable (typical in local unit tests)
we transparently fall back to an in-process set so the auth flow still works
deterministically — matching the graceful-degradation pattern used by the
existing rate limiter.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from btagent_backend.config import get_settings

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = logging.getLogger("btagent.auth.revocation")

_KEY_PREFIX = "btagent:revoked_jti"


def _redis_key(jti: str) -> str:
    return f"{_KEY_PREFIX}:{jti}"


# ---------------------------------------------------------------------------
# Redis client (lazy, shared)
# ---------------------------------------------------------------------------

_redis_client: Redis | None = None
_redis_unavailable: bool = False


async def _get_redis() -> Redis | None:
    """Return a shared Redis client, or None if Redis is unreachable.

    Mirrors the graceful-degradation pattern used by ``security/rate_limiter``
    and ``services/notification_service`` — never raises, just returns None so
    callers can fall back to in-memory storage.
    """
    global _redis_client, _redis_unavailable

    if _redis_unavailable:
        return None
    if _redis_client is not None:
        return _redis_client

    try:
        from redis.asyncio import Redis

        settings = get_settings()
        client = Redis.from_url(settings.redis_url, decode_responses=True)
        # Probe so we don't pay the failure cost on every call.
        await client.ping()
        _redis_client = client
        return client
    except Exception as exc:
        logger.warning(
            "Redis unavailable for token revocation (%s); falling back to in-memory store",
            exc,
        )
        _redis_unavailable = True
        return None


# ---------------------------------------------------------------------------
# In-memory fallback (single-process; for tests / dev without Redis)
# ---------------------------------------------------------------------------

# Maps jti -> unix-timestamp expiry. Pruned lazily on read.
_local_revoked: dict[str, float] = {}


def _local_prune(now: float | None = None) -> None:
    now = now if now is not None else time.time()
    for jti in [j for j, exp in _local_revoked.items() if exp <= now]:
        _local_revoked.pop(jti, None)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def revoke(jti: str, ttl_seconds: int) -> None:
    """Mark ``jti`` as revoked for ``ttl_seconds`` seconds.

    A non-positive TTL is a no-op — the token has already expired and the JWT
    library will reject it on its own.
    """
    if not jti or ttl_seconds <= 0:
        return

    redis = await _get_redis()
    if redis is not None:
        try:
            await redis.set(_redis_key(jti), "1", ex=ttl_seconds)
            return
        except Exception as exc:
            logger.warning(
                "Redis SET failed during revoke(%s): %s; using in-memory store", jti, exc
            )

    _local_revoked[jti] = time.time() + ttl_seconds


async def is_revoked(jti: str) -> bool:
    """Return True if ``jti`` is currently in the revocation list."""
    if not jti:
        return False

    redis = await _get_redis()
    if redis is not None:
        try:
            return bool(await redis.exists(_redis_key(jti)))
        except Exception as exc:
            logger.warning(
                "Redis EXISTS failed during is_revoked(%s): %s; using in-memory store", jti, exc
            )

    _local_prune()
    return jti in _local_revoked


# ---------------------------------------------------------------------------
# Test hooks
# ---------------------------------------------------------------------------


def _reset_for_tests() -> None:
    """Reset both the Redis client cache and the in-memory store.

    Tests that monkeypatch the Redis client or want a clean slate between
    cases should call this in a fixture.
    """
    global _redis_client, _redis_unavailable
    _redis_client = None
    _redis_unavailable = False
    _local_revoked.clear()
