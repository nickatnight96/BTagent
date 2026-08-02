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
# Redis client (lazy, shared, retry-with-backoff)
# ---------------------------------------------------------------------------

_redis_client: Redis | None = None
# B4: a failed connect schedules a *re-probe*, never a permanent latch. Before
# this, one Redis blip at first touch meant the process ran on process-local
# memory until restart — previously-revoked jtis worked again and force-logout
# stopped propagating across workers. ``inf`` (set by test fixtures) still
# forces the in-memory fallback unconditionally.
_redis_retry_at: float = 0.0
_redis_backoff: float = 0.0

_BACKOFF_INITIAL_SECONDS = 1.0
_BACKOFF_MAX_SECONDS = 30.0


def _schedule_retry(exc: Exception) -> None:
    """Record a connect failure and schedule the next probe (capped backoff)."""
    global _redis_retry_at, _redis_backoff
    _redis_backoff = min(
        max(_redis_backoff * 2, _BACKOFF_INITIAL_SECONDS),
        _BACKOFF_MAX_SECONDS,
    )
    _redis_retry_at = time.time() + _redis_backoff
    logger.warning(
        "Redis unavailable for token revocation (%s); using in-memory store, retrying in %.0fs",
        exc,
        _redis_backoff,
    )


async def _get_redis(*, force_probe: bool = False) -> Redis | None:
    """Return a shared Redis client, or None while Redis is unreachable.

    Never raises — callers fall back to in-memory storage. Unlike the
    rate-limiter's session-long degradation, revocation re-probes on a capped
    exponential backoff: fail-open on a security control must self-heal.
    ``force_probe`` (used by the readiness check) bypasses the backoff window
    so an operator-triggered probe reflects — and actively restores — the
    current state. A test-pinned window (``inf``) is never bypassed.
    """
    global _redis_client, _redis_retry_at, _redis_backoff

    if _redis_client is not None:
        return _redis_client
    if _redis_retry_at == float("inf"):
        return None
    if time.time() < _redis_retry_at and not force_probe:
        return None

    try:
        from redis.asyncio import Redis

        settings = get_settings()
        client = Redis.from_url(settings.redis_url, decode_responses=True)
        # Probe so we don't pay the failure cost on every call.
        await client.ping()
        _redis_client = client
        _redis_retry_at = 0.0
        _redis_backoff = 0.0
        return client
    except Exception as exc:
        _schedule_retry(exc)
        return None


def is_degraded() -> bool:
    """True while revocation is running on the process-local fallback.

    Surfaced on ``/health/ready`` (B4) so a fail-open revocation list is an
    operator-visible condition, not a lone log line.
    """
    return _redis_client is None and _redis_retry_at > 0.0


async def check_health() -> bool:
    """Readiness hook: probe (and thereby heal) the revocation Redis link."""
    return await _get_redis(force_probe=True) is not None


async def close_redis() -> None:
    """Close the shared revocation Redis client (graceful-shutdown hook).

    Idempotent and never raises — safe to call from the FastAPI lifespan even
    when Redis was never opened or already failed.
    """
    global _redis_client, _redis_retry_at, _redis_backoff
    client, _redis_client = _redis_client, None
    _redis_retry_at = 0.0
    _redis_backoff = 0.0
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
    cases should call this in a fixture. To force the in-memory fallback for
    a test, set ``_redis_retry_at = float("inf")`` after calling this.
    """
    global _redis_client, _redis_retry_at, _redis_backoff
    _redis_client = None
    _redis_retry_at = 0.0
    _redis_backoff = 0.0
    _local_revoked.clear()
    _local_revoked_families.clear()
    _local_user_epoch.clear()
