"""Token-bucket rate limiter with Redis-backed distributed state."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from btagent_shared.types.enums import UserRole
from fastapi import Depends, HTTPException, Request, status

from btagent_backend.config import Settings, get_settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration per role
# ---------------------------------------------------------------------------

RATE_LIMITS: dict[str, int] = {
    UserRole.ANALYST: 60,
    UserRole.SENIOR_ANALYST: 120,
    UserRole.INCIDENT_COMMANDER: 200,
    UserRole.ADMIN: 500,
}

CONCURRENT_INVESTIGATION_LIMITS: dict[str, int] = {
    UserRole.ANALYST: 3,
    UserRole.SENIOR_ANALYST: 5,
    UserRole.INCIDENT_COMMANDER: 10,
    UserRole.ADMIN: 25,
}

WEBSOCKET_CONNECTION_LIMITS: dict[str, int] = {
    UserRole.ANALYST: 2,
    UserRole.SENIOR_ANALYST: 5,
    UserRole.INCIDENT_COMMANDER: 10,
    UserRole.ADMIN: 20,
}

_KEY_PREFIX = "btagent:ratelimit"
_WS_KEY_PREFIX = "btagent:wsconn"
_INV_KEY_PREFIX = "btagent:concurrent_inv"


# ---------------------------------------------------------------------------
# Token bucket implementation
# ---------------------------------------------------------------------------


@dataclass
class TokenBucket:
    """Token bucket state for a single user."""

    capacity: int
    tokens: float
    last_refill: float
    refill_rate: float  # tokens per second


def _refill(bucket: TokenBucket, now: float) -> TokenBucket:
    elapsed = now - bucket.last_refill
    bucket.tokens = min(bucket.capacity, bucket.tokens + elapsed * bucket.refill_rate)
    bucket.last_refill = now
    return bucket


# ---------------------------------------------------------------------------
# Redis-backed rate limiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Distributed token-bucket rate limiter backed by Redis."""

    def __init__(self, redis_client: object | None = None):
        self._redis = redis_client

    # -- Token bucket (requests/min) ----------------------------------------

    async def check_rate_limit(
        self,
        user_id: str,
        role: str,
        burst: int | None = None,
    ) -> bool:
        """Return True if the request is allowed, False if rate-limited.

        Uses a Redis-based token bucket. Each user gets ``capacity`` tokens per
        minute (determined by role), refilled continuously. ``burst`` overrides
        the bucket capacity for short spikes.
        """
        capacity = burst if burst is not None else RATE_LIMITS.get(role, 60)
        refill_rate = RATE_LIMITS.get(role, 60) / 60.0  # tokens per second
        key = f"{_KEY_PREFIX}:{user_id}"

        if self._redis is None:
            return await self._check_rate_limit_local(key, capacity, refill_rate)

        return await self._check_rate_limit_redis(key, capacity, refill_rate)

    async def _check_rate_limit_redis(self, key: str, capacity: int, refill_rate: float) -> bool:
        now = time.time()
        lua = """
        local key = KEYS[1]
        local capacity = tonumber(ARGV[1])
        local refill_rate = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])

        local data = redis.call('HMGET', key, 'tokens', 'last_refill')
        local tokens = tonumber(data[1])
        local last_refill = tonumber(data[2])

        if tokens == nil then
            tokens = capacity
            last_refill = now
        end

        local elapsed = now - last_refill
        tokens = math.min(capacity, tokens + elapsed * refill_rate)

        if tokens < 1 then
            redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
            redis.call('EXPIRE', key, 120)
            return 0
        end

        tokens = tokens - 1
        redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
        redis.call('EXPIRE', key, 120)
        return 1
        """
        result = await self._redis.eval(lua, 1, key, capacity, refill_rate, now)
        return result == 1

    # Fallback: in-memory buckets (single-process only, for dev/testing)
    _local_buckets: dict[str, TokenBucket] = {}

    async def _check_rate_limit_local(self, key: str, capacity: int, refill_rate: float) -> bool:
        now = time.time()
        bucket = self._local_buckets.get(key)
        if bucket is None:
            bucket = TokenBucket(
                capacity=capacity,
                tokens=float(capacity),
                last_refill=now,
                refill_rate=refill_rate,
            )
            self._local_buckets[key] = bucket

        _refill(bucket, now)

        if bucket.tokens < 1:
            return False

        bucket.tokens -= 1
        return True

    # -- Concurrent investigations ------------------------------------------

    async def check_concurrent_investigations(self, user_id: str, role: str) -> bool:
        """Return True if the user can start another investigation."""
        limit = CONCURRENT_INVESTIGATION_LIMITS.get(role, 3)
        if self._redis is None:
            return True  # skip in local mode

        key = f"{_INV_KEY_PREFIX}:{user_id}"
        count = await self._redis.scard(key)
        return count < limit

    async def register_investigation(self, user_id: str, investigation_id: str) -> None:
        """Track an active investigation for the user."""
        if self._redis is None:
            return
        key = f"{_INV_KEY_PREFIX}:{user_id}"
        await self._redis.sadd(key, investigation_id)
        await self._redis.expire(key, 86400)

    async def unregister_investigation(self, user_id: str, investigation_id: str) -> None:
        """Remove a completed investigation from tracking."""
        if self._redis is None:
            return
        key = f"{_INV_KEY_PREFIX}:{user_id}"
        await self._redis.srem(key, investigation_id)

    # -- WebSocket connections ----------------------------------------------

    async def check_ws_limit(self, user_id: str, role: str) -> bool:
        """Return True if the user can open another WebSocket connection."""
        limit = WEBSOCKET_CONNECTION_LIMITS.get(role, 2)
        if self._redis is None:
            return True
        key = f"{_WS_KEY_PREFIX}:{user_id}"
        count = await self._redis.get(key)
        return (int(count) if count else 0) < limit

    async def register_ws(self, user_id: str) -> None:
        """Increment the WebSocket connection counter for a user."""
        if self._redis is None:
            return
        key = f"{_WS_KEY_PREFIX}:{user_id}"
        await self._redis.incr(key)
        await self._redis.expire(key, 3600)

    async def unregister_ws(self, user_id: str) -> None:
        """Decrement the WebSocket connection counter for a user."""
        if self._redis is None:
            return
        key = f"{_WS_KEY_PREFIX}:{user_id}"
        val = await self._redis.decr(key)
        if val is not None and int(val) <= 0:
            await self._redis.delete(key)


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_instance: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    """Return the global RateLimiter singleton (lazy-init, no Redis in dev)."""
    global _instance
    if _instance is None:
        _instance = RateLimiter()
    return _instance


def init_rate_limiter(redis_client: object) -> RateLimiter:
    """Initialise the global RateLimiter with a Redis connection."""
    global _instance
    _instance = RateLimiter(redis_client=redis_client)
    return _instance


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


class RateLimitDependency:
    """FastAPI dependency that enforces per-user rate limits.

    Usage::

        @router.get("/data", dependencies=[Depends(RateLimitDependency())])
        async def get_data(): ...

    Or with a custom burst size::

        @router.get("/heavy", dependencies=[Depends(RateLimitDependency(burst=10))])
        async def heavy_endpoint(): ...
    """

    def __init__(self, burst: int | None = None):
        self.burst = burst

    async def __call__(
        self,
        request: Request,
        settings: Settings = Depends(get_settings),
    ) -> None:
        if not settings.rate_limit_enabled:
            return

        # Extract user from request state (set by auth middleware)
        user = getattr(request.state, "user", None)
        if user is None:
            # Fallback: unauthenticated endpoints get a stricter global bucket
            user_id = request.client.host if request.client else "unknown"
            role = UserRole.ANALYST
        else:
            user_id = user.id
            role = user.role

        limiter = get_rate_limiter()
        allowed = await limiter.check_rate_limit(user_id=user_id, role=role, burst=self.burst)

        if not allowed:
            logger.warning("Rate limit exceeded: user=%s role=%s", user_id, role)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please wait before retrying.",
                headers={"Retry-After": "60"},
            )
