"""B4 / P2.5: token revocation must self-heal after a Redis blip.

Before the fix, one failed connect set a module-global ``_redis_unavailable``
latch that was cleared only at shutdown: after a 2-second Redis restart,
previously revoked jtis worked again and force-logout wrote to one process's
memory forever. These tests pin the retry-with-backoff replacement:

* a connect failure schedules a bounded re-probe instead of latching
* within the backoff window no reconnect is attempted (no per-request
  connect storm against a dead Redis)
* once the window passes and Redis is back, the client reconnects and the
  Redis path is used again
* the readiness hook force-probes (bypassing the window) so
  ``GET /health/ready`` both reports and actively heals the degraded state
* a test-pinned ``inf`` window is never bypassed
"""

from __future__ import annotations

import pytest

from btagent_backend.auth import revocation


class _FakeRedis:
    """Minimal async Redis stand-in recording SET/EXISTS calls."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def ping(self) -> bool:
        return True

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.store[key] = value

    async def exists(self, key: str) -> int:
        return int(key in self.store)

    async def aclose(self) -> None:
        return None


class _FlakyFactory:
    """``Redis.from_url`` replacement that fails N times, then succeeds."""

    def __init__(self, failures: int) -> None:
        self.failures = failures
        self.calls = 0
        self.instance = _FakeRedis()

    def __call__(self, *args, **kwargs):
        self.calls += 1
        if self.calls <= self.failures:
            raise ConnectionError("redis down")
        return self.instance


@pytest.fixture(autouse=True)
def _clean_revocation_state():
    revocation._reset_for_tests()
    yield
    revocation._reset_for_tests()


def _patch_factory(monkeypatch, factory) -> None:
    import redis.asyncio

    monkeypatch.setattr(redis.asyncio.Redis, "from_url", factory)


@pytest.mark.asyncio
async def test_connect_failure_schedules_retry_not_latch(monkeypatch):
    factory = _FlakyFactory(failures=1)
    _patch_factory(monkeypatch, factory)

    assert await revocation._get_redis() is None
    assert revocation.is_degraded() is True
    # A bounded retry window is scheduled — not a permanent latch.
    assert 0 < revocation._redis_retry_at < float("inf")

    # Within the window, no new connect attempt is made.
    assert await revocation._get_redis() is None
    assert factory.calls == 1

    # Once the window passes, the next call reconnects and heals.
    monkeypatch.setattr(revocation, "_redis_retry_at", 0.0)
    assert await revocation._get_redis() is factory.instance
    assert revocation.is_degraded() is False
    assert factory.calls == 2


@pytest.mark.asyncio
async def test_revocations_survive_a_redis_blip(monkeypatch):
    """The exact B4 scenario: revoke during an outage, verify after recovery.

    The in-memory entry still guards this process during the outage, and the
    reconnect makes *new* revocations shared again. (Entries written to local
    memory during the outage remain process-local — that bounded gap is why
    is_degraded() is surfaced on readiness.)
    """
    factory = _FlakyFactory(failures=1)
    _patch_factory(monkeypatch, factory)

    await revocation.revoke("jti-outage", ttl_seconds=60)
    assert await revocation.is_revoked("jti-outage") is True  # in-memory guard

    # Redis comes back; the backoff window elapses.
    monkeypatch.setattr(revocation, "_redis_retry_at", 0.0)

    await revocation.revoke("jti-after", ttl_seconds=60)
    # The post-recovery revocation went to (shared) Redis, not local memory.
    assert factory.instance.store, "expected the revocation to reach Redis"
    assert await revocation.is_revoked("jti-after") is True


@pytest.mark.asyncio
async def test_backoff_grows_and_is_capped(monkeypatch):
    factory = _FlakyFactory(failures=1000)
    _patch_factory(monkeypatch, factory)

    seen: list[float] = []
    for _ in range(8):
        monkeypatch.setattr(revocation, "_redis_retry_at", 0.0)  # window elapsed
        await revocation._get_redis()
        seen.append(revocation._redis_backoff)

    assert seen[0] == revocation._BACKOFF_INITIAL_SECONDS
    assert all(b2 >= b1 for b1, b2 in zip(seen, seen[1:]))
    assert seen[-1] == revocation._BACKOFF_MAX_SECONDS


@pytest.mark.asyncio
async def test_health_probe_bypasses_backoff_window(monkeypatch):
    factory = _FlakyFactory(failures=1)
    _patch_factory(monkeypatch, factory)

    assert await revocation._get_redis() is None  # opens a long backoff window
    assert revocation.is_degraded() is True

    # The readiness hook probes immediately — and thereby heals.
    assert await revocation.check_health() is True
    assert revocation.is_degraded() is False


@pytest.mark.asyncio
async def test_test_pinned_fallback_is_never_probed(monkeypatch):
    factory = _FlakyFactory(failures=0)
    _patch_factory(monkeypatch, factory)

    revocation._redis_retry_at = float("inf")
    assert await revocation._get_redis() is None
    assert await revocation.check_health() is False
    assert factory.calls == 0
