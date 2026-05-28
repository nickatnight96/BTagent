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
# P142: a revoked refresh-token *family* (reuse-detection / theft response).
_FAMILY_PREFIX = "btagent:revoked_family"
# P142: per-user revocation epoch — any token with ``iat`` strictly before the
# stored unix timestamp is rejected (admin "revoke this user's sessions").
_USER_EPOCH_PREFIX = "btagent:user_revoked_after"


def _redis_key(jti: str) -> str:
    return f"{_KEY_PREFIX}:{jti}"


def _family_key(fid: str) -> str:
    return f"{_FAMILY_PREFIX}:{fid}"


def _user_epoch_key(user_id: str) -> str:
    return f"{_USER_EPOCH_PREFIX}:{user_id}"


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


async def close_redis() -> None:
    """Close the shared revocation Redis client (graceful-shutdown hook).

    Idempotent and never raises — safe to call from the FastAPI lifespan even
    when Redis was never opened or already failed.
    """
    global _redis_client, _redis_unavailable
    client, _redis_client = _redis_client, None
    _redis_unavailable = False
    if client is not None:
        try:
            await client.aclose()
        except Exception as exc:  # noqa: BLE001 — shutdown must not raise
            logger.warning("error closing revocation Redis client: %s", exc)


# ---------------------------------------------------------------------------
# In-memory fallback (single-process; for tests / dev without Redis)
# ---------------------------------------------------------------------------

# Maps jti -> unix-timestamp expiry. Pruned lazily on read.
_local_revoked: dict[str, float] = {}
# P142: revoked refresh-token families -> unix-timestamp expiry.
_local_revoked_families: dict[str, float] = {}
# P142: per-user revocation epoch (user_id -> unix timestamp). Tokens issued
# (``iat``) strictly before this value are rejected. Never auto-expires; it is
# overwritten on each admin revoke and is small (one entry per force-logout).
_local_user_epoch: dict[str, float] = {}


def _local_prune(now: float | None = None) -> None:
    now = now if now is not None else time.time()
    for jti in [j for j, exp in _local_revoked.items() if exp <= now]:
        _local_revoked.pop(jti, None)
    for fid in [f for f, exp in _local_revoked_families.items() if exp <= now]:
        _local_revoked_families.pop(fid, None)


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
# Refresh-token family revocation (P142 — reuse detection / theft response)
# ---------------------------------------------------------------------------


async def revoke_family(fid: str, ttl_seconds: int) -> None:
    """Revoke an entire refresh-token family.

    Called when a *consumed* (already-rotated) refresh token is replayed — a
    strong signal the family has been stolen. Every refresh token sharing this
    ``fid`` is rejected by ``is_family_revoked`` until the entry expires (TTL =
    remaining refresh lifetime, so it self-prunes once no live token could
    exist).
    """
    if not fid or ttl_seconds <= 0:
        return

    redis = await _get_redis()
    if redis is not None:
        try:
            await redis.set(_family_key(fid), "1", ex=ttl_seconds)
            return
        except Exception as exc:
            logger.warning(
                "Redis SET failed during revoke_family(%s): %s; using in-memory store", fid, exc
            )

    _local_revoked_families[fid] = time.time() + ttl_seconds


async def is_family_revoked(fid: str) -> bool:
    """Return True if the refresh-token family ``fid`` has been revoked."""
    if not fid:
        return False

    redis = await _get_redis()
    if redis is not None:
        try:
            return bool(await redis.exists(_family_key(fid)))
        except Exception as exc:
            logger.warning(
                "Redis EXISTS failed during is_family_revoked(%s): %s; using in-memory store",
                fid,
                exc,
            )

    _local_prune()
    return fid in _local_revoked_families


# ---------------------------------------------------------------------------
# Per-user revocation epoch (P142 — admin "revoke this user's sessions")
# ---------------------------------------------------------------------------


async def revoke_user_tokens(user_id: str, ttl_seconds: int, now: float | None = None) -> None:
    """Force-logout a user: invalidate every token issued before ``now``.

    Stores a revocation epoch (unix seconds) for ``user_id``. Any access or
    refresh token whose ``iat`` is strictly older than the epoch is rejected by
    ``is_user_revoked``. New tokens minted *after* this call (e.g. a fresh
    login) have a larger ``iat`` and are unaffected, so the user can log back
    in immediately.

    ``ttl_seconds`` should be at least the longest-lived token's remaining
    lifetime (refresh TTL); after that, no token old enough to be caught by the
    epoch can still exist, so the entry may expire.
    """
    if not user_id or ttl_seconds <= 0:
        return

    # ``iat`` claims are integer NumericDates (whole seconds). To guarantee
    # that *every* token issued at or before this revoke is caught — including
    # one minted in the same wall-clock second — store the epoch as the NEXT
    # whole second. ``is_user_revoked`` then rejects any token with
    # ``iat < epoch`` (i.e. iat <= current second). The trade-off: a token
    # issued earlier in the same second is also revoked, which is exactly the
    # desired force-logout behaviour. A fresh login one second later (or with a
    # later ``iat``) is unaffected.
    epoch = float(int(now if now is not None else time.time()) + 1)

    redis = await _get_redis()
    if redis is not None:
        try:
            await redis.set(_user_epoch_key(user_id), str(epoch), ex=ttl_seconds)
            return
        except Exception as exc:
            logger.warning(
                "Redis SET failed during revoke_user_tokens(%s): %s; using in-memory store",
                user_id,
                exc,
            )

    _local_user_epoch[user_id] = epoch


async def is_user_revoked(user_id: str, issued_at: int | None) -> bool:
    """Return True if a token with ``issued_at`` predates the user's epoch.

    Tokens without an ``iat`` claim (legacy, pre-P142) return ``False`` here —
    they cannot be compared against the epoch. The middleware's existing legacy
    handling (prod rejects no-jti tokens) bounds that exposure.
    """
    if not user_id or issued_at is None:
        return False

    epoch: float | None = None
    redis = await _get_redis()
    if redis is not None:
        try:
            raw = await redis.get(_user_epoch_key(user_id))
            epoch = float(raw) if raw is not None else None
        except Exception as exc:
            logger.warning(
                "Redis GET failed during is_user_revoked(%s): %s; using in-memory store",
                user_id,
                exc,
            )
            epoch = _local_user_epoch.get(user_id)
    else:
        epoch = _local_user_epoch.get(user_id)

    if epoch is None:
        return False
    # Strictly-before: a token minted in the same second as (or after) the
    # revoke still wins, matching "revoke everything issued before now".
    return issued_at < epoch


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
    _local_revoked_families.clear()
    _local_user_epoch.clear()
