"""MCP Connection Registry -- singleton connection pool for BTagent MCP clients.

Provides centralised lifecycle management for MCP connections:
- Thread-safe connection pool (max 50, configurable)
- Per-connection circuit breaker (threshold=5, recovery=30s)
- Periodic health-check via ping (default 60s)
- Keepalive heartbeat (default 45s)
- Consumer tracking per investigation
- Idle-timeout eviction (default 300s)
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from btagent_shared.types.mcp import MCPConnectionStatus, MCPServerConfig

from btagent_agents.mcp.config import get_recovery_timeout_max

logger = logging.getLogger("btagent.mcp.registry")

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
MAX_CONNECTIONS = int(os.getenv("BTAGENT_MCP_POOL_MAX_CONNECTIONS", "50"))
IDLE_TIMEOUT = float(os.getenv("BTAGENT_MCP_POOL_IDLE_TIMEOUT", "300"))
HEALTH_CHECK_INTERVAL = float(os.getenv("BTAGENT_MCP_HEALTH_CHECK_INTERVAL", "60"))
KEEPALIVE_INTERVAL = float(os.getenv("BTAGENT_MCP_KEEPALIVE_INTERVAL", "45"))
SHUTDOWN_TIMEOUT = float(os.getenv("BTAGENT_MCP_SHUTDOWN_TIMEOUT", "10"))

# Circuit breaker defaults
CB_FAILURE_THRESHOLD = int(os.getenv("BTAGENT_MCP_CIRCUIT_FAILURE_THRESHOLD", "5"))
CB_RECOVERY_TIMEOUT = float(os.getenv("BTAGENT_MCP_CIRCUIT_RECOVERY_TIMEOUT", "30"))
CB_RECOVERY_TIMEOUT_MAX = float(os.getenv("BTAGENT_MCP_CIRCUIT_RECOVERY_TIMEOUT_MAX", "600"))
CB_SUCCESS_THRESHOLD = int(os.getenv("BTAGENT_MCP_CIRCUIT_SUCCESS_THRESHOLD", "2"))


# ---------------------------------------------------------------------------
# Circuit breaker (embedded to avoid external dependency)
# ---------------------------------------------------------------------------
class CircuitState(StrEnum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    """Raised when circuit is open and request is rejected."""

    def __init__(self, connection_id: str, state: CircuitState, retry_after: float) -> None:
        self.connection_id = connection_id
        self.state = state
        self.retry_after = retry_after
        super().__init__(f"Circuit open for '{connection_id}'. Retry after {retry_after:.1f}s")


@dataclass
class CircuitBreaker:
    """Per-connection circuit breaker with exponential-backoff recovery.

    States:
        CLOSED   -- normal, requests pass through
        OPEN     -- failures exceeded threshold, requests fail fast
        HALF_OPEN -- recovery window, testing if service is back

    Recovery schedule
    ~~~~~~~~~~~~~~~~~
    The first time the breaker trips it waits ``recovery_timeout`` seconds
    before transitioning to HALF_OPEN. Each subsequent re-trip (a failure
    while HALF_OPEN, or another threshold breach without an intervening
    successful close) doubles the wait, capped at ``recovery_timeout_max``::

        attempt:  1     2     3     4     5      6+
        wait(s):  30    60    120   240   480    600 (cap)

    On a successful close (HALF_OPEN -> CLOSED) the schedule resets, so a
    transient outage followed by recovery returns to the original 30s base.
    This avoids hammering a downed service every 30s indefinitely while
    still giving healthy services fast recovery.
    """

    connection_id: str
    failure_threshold: int = CB_FAILURE_THRESHOLD
    recovery_timeout: float = CB_RECOVERY_TIMEOUT
    recovery_timeout_max: float = CB_RECOVERY_TIMEOUT_MAX
    success_threshold: int = CB_SUCCESS_THRESHOLD

    _state: CircuitState = field(default=CircuitState.CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _success_count: int = field(default=0, init=False)
    _last_failure_time: float = field(default=0.0, init=False)
    # Number of consecutive trips into the OPEN state without a successful
    # close in between. Drives the exponential backoff exponent.
    _open_cycles: int = field(default=0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    # ----- properties -----

    @property
    def state(self) -> CircuitState:
        with self._lock:
            return self._effective_state()

    @property
    def failure_count(self) -> int:
        with self._lock:
            return self._failure_count

    @property
    def is_available(self) -> bool:
        return self.state != CircuitState.OPEN

    @property
    def current_recovery_timeout(self) -> float:
        """Currently scheduled wait before the next HALF_OPEN attempt."""
        with self._lock:
            return self._compute_recovery_timeout()

    # ----- internal -----

    def _compute_recovery_timeout(self) -> float:
        """Exponential backoff: base * 2^(open_cycles - 1), capped (caller holds lock)."""
        if self._open_cycles <= 0:
            return self.recovery_timeout
        # ``open_cycles`` of 1 means "first time we tripped" -> base wait.
        exponent = max(0, self._open_cycles - 1)
        # Defensive cap on the exponent to keep ``2 ** exponent`` cheap for
        # pathological inputs (the value is clamped by ``min`` immediately).
        exponent = min(exponent, 32)
        wait = self.recovery_timeout * (2**exponent)
        return min(wait, self.recovery_timeout_max)

    def _effective_state(self) -> CircuitState:
        """Evaluate state considering recovery timeout (caller holds lock)."""
        if self._state == CircuitState.OPEN:
            elapsed = time.time() - self._last_failure_time
            wait = self._compute_recovery_timeout()
            if elapsed >= wait:
                self._state = CircuitState.HALF_OPEN
                self._success_count = 0
                logger.info(
                    "Circuit %s -> HALF_OPEN after %.1fs (cycle=%d, wait=%.1fs)",
                    self.connection_id,
                    elapsed,
                    self._open_cycles,
                    wait,
                )
        return self._state

    # ----- public API -----

    def record_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
                    # Reset the backoff schedule on a clean recovery so the
                    # next outage starts again at the base wait.
                    self._open_cycles = 0
                    logger.info(
                        "Circuit %s -> CLOSED (backoff reset)", self.connection_id
                    )
            elif self._state == CircuitState.CLOSED and self._failure_count > 0:
                self._failure_count = max(0, self._failure_count - 1)

    def record_failure(self, error: Exception | None = None) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._open_cycles += 1
                next_wait = self._compute_recovery_timeout()
                logger.warning(
                    "Circuit %s re-OPENED (failure in HALF_OPEN, cycle=%d, "
                    "next wait=%.1fs): %s",
                    self.connection_id,
                    self._open_cycles,
                    next_wait,
                    error,
                )
            elif (
                self._state == CircuitState.CLOSED and self._failure_count >= self.failure_threshold
            ):
                self._state = CircuitState.OPEN
                self._open_cycles += 1
                next_wait = self._compute_recovery_timeout()
                logger.warning(
                    "Circuit %s OPENED after %d failures (cycle=%d, "
                    "next wait=%.1fs): %s",
                    self.connection_id,
                    self._failure_count,
                    self._open_cycles,
                    next_wait,
                    error,
                )

    def check_state(self) -> None:
        """Raise :class:`CircuitOpenError` if the circuit is OPEN."""
        with self._lock:
            state = self._effective_state()
            if state == CircuitState.OPEN:
                wait = self._compute_recovery_timeout()
                retry_after = wait - (time.time() - self._last_failure_time)
                raise CircuitOpenError(self.connection_id, state, max(0, retry_after))

    def reset(self) -> None:
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._last_failure_time = 0.0
            self._open_cycles = 0
            logger.info("Circuit %s manually reset", self.connection_id)

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "connection_id": self.connection_id,
                "state": self._effective_state().value,
                "failure_count": self._failure_count,
                "success_count": self._success_count,
                "last_failure_time": self._last_failure_time,
                "failure_threshold": self.failure_threshold,
                "recovery_timeout": self.recovery_timeout,
                "recovery_timeout_max": self.recovery_timeout_max,
                "open_cycles": self._open_cycles,
                "current_recovery_timeout": self._compute_recovery_timeout(),
            }


# ---------------------------------------------------------------------------
# Managed connection wrapper
# ---------------------------------------------------------------------------
@dataclass
class ManagedConnection:
    """Wraps a logical MCP connection with lifecycle metadata."""

    connection_id: str
    server_name: str
    config: MCPServerConfig

    # Lifecycle tracking
    created_at: float = field(default_factory=time.time)
    last_used_at: float = field(default_factory=time.time)
    consumers: set[str] = field(default_factory=set)

    # Health tracking
    is_healthy: bool = True
    last_health_check: float = 0.0
    health_check_failures: int = 0

    # Circuit breaker
    circuit_breaker: CircuitBreaker = field(init=False)

    # Connected state flag
    _connected: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        # ``circuit_breaker_recovery_max`` is only present on the local
        # ``MCPHardenedServerConfig`` subclass; legacy ``MCPServerConfig``
        # callers fall through to the env-driven default. This keeps
        # backwards compatibility for ad-hoc and existing config sites.
        self.circuit_breaker = CircuitBreaker(
            connection_id=self.connection_id,
            failure_threshold=self.config.circuit_breaker_threshold,
            recovery_timeout=float(self.config.circuit_breaker_recovery),
            recovery_timeout_max=get_recovery_timeout_max(self.config),
        )

    # ----- properties -----

    @property
    def consumer_count(self) -> int:
        return len(self.consumers)

    @property
    def is_idle(self) -> bool:
        return len(self.consumers) == 0

    @property
    def idle_time(self) -> float:
        return time.time() - self.last_used_at if self.is_idle else 0.0

    @property
    def connected(self) -> bool:
        return self._connected

    # ----- consumer tracking -----

    def add_consumer(self, consumer_id: str) -> None:
        self.consumers.add(consumer_id)
        self.last_used_at = time.time()

    def remove_consumer(self, consumer_id: str) -> None:
        self.consumers.discard(consumer_id)
        if self.is_idle:
            self.last_used_at = time.time()

    def touch(self) -> None:
        self.last_used_at = time.time()

    # ----- connection lifecycle -----

    async def connect(self) -> None:
        """Establish the logical connection."""
        if self._connected:
            return
        self._connected = True
        self.is_healthy = True
        self.last_health_check = time.time()
        logger.info(
            "MCP connection %s (%s) established",
            self.connection_id,
            self.server_name,
        )

    async def disconnect(self) -> None:
        """Tear down the connection."""
        self._connected = False
        self.is_healthy = False
        logger.info(
            "MCP connection %s (%s) disconnected",
            self.connection_id,
            self.server_name,
        )

    async def health_check(self) -> bool:
        """Perform a health-check ping."""
        try:
            if not self._connected:
                self.is_healthy = False
                self.health_check_failures += 1
                return False

            self.is_healthy = True
            self.health_check_failures = 0
            self.last_health_check = time.time()
            return True
        except Exception as exc:
            self.is_healthy = False
            self.health_check_failures += 1
            logger.debug(
                "Health-check failed for %s (%d failures): %s",
                self.connection_id,
                self.health_check_failures,
                exc,
            )
            return False

    async def reconnect(self) -> bool:
        """Attempt reconnection after failure."""
        await self.disconnect()
        try:
            await self.connect()
            self.circuit_breaker.reset()
            logger.info("Reconnected MCP connection %s", self.connection_id)
            return True
        except Exception as exc:
            self.circuit_breaker.record_failure(exc)
            logger.error("Reconnect failed for %s: %s", self.connection_id, exc)
            return False


# ---------------------------------------------------------------------------
# MCPConnectionRegistry -- singleton
# ---------------------------------------------------------------------------
class MCPConnectionRegistry:
    """Singleton thread-safe connection pool for MCP servers.

    Usage::

        registry = MCPConnectionRegistry.get_instance()
        conn = await registry.get_connection("splunk")
        # ... use conn ...
        registry.release_connection("splunk", consumer_id="inv_01ABC")
    """

    _instance: MCPConnectionRegistry | None = None
    _instance_lock = threading.Lock()

    # ----- singleton -----

    def __new__(cls) -> MCPConnectionRegistry:
        with cls._instance_lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._initialized = False
                cls._instance = inst
            return cls._instance

    @classmethod
    def get_instance(cls) -> MCPConnectionRegistry:
        return cls()

    @classmethod
    def reset_instance(cls) -> None:
        """Tear down and reset the singleton (useful in tests)."""
        with cls._instance_lock:
            if cls._instance is not None:
                cls._instance._shutdown()
                cls._instance = None

    # ----- init -----

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return

        self._connections: dict[str, ManagedConnection] = {}
        self._lock = threading.RLock()
        self._shutdown_event = threading.Event()
        self._max_connections = MAX_CONNECTIONS

        # Background threads
        self._health_thread: threading.Thread | None = None
        self._keepalive_thread: threading.Thread | None = None
        self._start_background_threads()

        self._initialized = True
        logger.info(
            "MCPConnectionRegistry initialised (max=%d, idle=%ds, hc=%ds, ka=%ds)",
            MAX_CONNECTIONS,
            int(IDLE_TIMEOUT),
            int(HEALTH_CHECK_INTERVAL),
            int(KEEPALIVE_INTERVAL),
        )

    # ----- background threads -----

    def _start_background_threads(self) -> None:
        if HEALTH_CHECK_INTERVAL > 0:
            self._health_thread = threading.Thread(
                target=self._health_loop,
                name="mcp-health-monitor",
                daemon=True,
            )
            self._health_thread.start()

        if KEEPALIVE_INTERVAL > 0:
            self._keepalive_thread = threading.Thread(
                target=self._keepalive_loop,
                name="mcp-keepalive",
                daemon=True,
            )
            self._keepalive_thread.start()

    def _health_loop(self) -> None:
        while not self._shutdown_event.is_set():
            if self._shutdown_event.wait(HEALTH_CHECK_INTERVAL):
                break
            self._run_health_checks()

    def _keepalive_loop(self) -> None:
        while not self._shutdown_event.is_set():
            if self._shutdown_event.wait(KEEPALIVE_INTERVAL):
                break
            self._run_keepalive()

    def _run_health_checks(self) -> None:
        with self._lock:
            conns = list(self._connections.values())
        for conn in conns:
            if self._shutdown_event.is_set():
                break
            try:
                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(conn.health_check())
                finally:
                    loop.close()
            except Exception as exc:
                logger.debug(
                    "Health-check error for %s: %s",
                    conn.connection_id,
                    exc,
                )
        # Evict idle connections after health checks
        self._evict_idle_connections()

    def _run_keepalive(self) -> None:
        """Touch active connections to keep them alive."""
        with self._lock:
            conns = list(self._connections.values())
        for conn in conns:
            if self._shutdown_event.is_set():
                break
            if conn.connected and not conn.is_idle:
                conn.touch()

    def _evict_idle_connections(self) -> int:
        """Evict connections exceeding idle timeout. Returns count."""
        evicted = 0
        with self._lock:
            to_evict = [
                cid
                for cid, c in self._connections.items()
                if c.is_idle and c.idle_time > IDLE_TIMEOUT
            ]
            for cid in to_evict:
                conn = self._connections.pop(cid, None)
                if conn:
                    evicted += 1
                    logger.info(
                        "Evicted idle MCP connection %s (idle %.0fs)",
                        cid,
                        conn.idle_time,
                    )
        return evicted

    # ----- public API -----

    async def get_connection(
        self,
        server_name: str,
        *,
        config: MCPServerConfig | None = None,
        consumer_id: str | None = None,
    ) -> ManagedConnection:
        """Get or create a managed connection for *server_name*.

        Args:
            server_name: Logical server identifier (e.g. ``"splunk"``).
            config: Server configuration; required for new connections.
            consumer_id: Investigation or caller ID for tracking.

        Returns:
            :class:`ManagedConnection` instance.

        Raises:
            CircuitOpenError: If the circuit breaker is open.
            RuntimeError: If pool is full or config is missing.
        """
        with self._lock:
            existing = self._connections.get(server_name)
            if existing is not None:
                existing.circuit_breaker.check_state()
                if existing.is_healthy:
                    if consumer_id:
                        existing.add_consumer(consumer_id)
                    return existing
                # Unhealthy -- try reconnect
                ok = await existing.reconnect()
                if ok:
                    if consumer_id:
                        existing.add_consumer(consumer_id)
                    return existing
                raise RuntimeError(f"MCP connection '{server_name}' unhealthy and reconnect failed")

            # Create new connection
            if len(self._connections) >= self._max_connections:
                self._evict_idle_connections()
                if len(self._connections) >= self._max_connections:
                    raise RuntimeError(f"MCP pool full ({self._max_connections} connections)")

            if config is None:
                raise RuntimeError(
                    f"No existing connection for '{server_name}' and no config provided"
                )

            managed = ManagedConnection(
                connection_id=server_name,
                server_name=server_name,
                config=config,
            )
            await managed.connect()
            if consumer_id:
                managed.add_consumer(consumer_id)
            self._connections[server_name] = managed
            return managed

    def release_connection(self, server_name: str, consumer_id: str) -> None:
        """Release a consumer's hold on a connection."""
        with self._lock:
            conn = self._connections.get(server_name)
            if conn is None:
                return
            conn.remove_consumer(consumer_id)
            logger.debug(
                "Released %s from %s (consumers=%d)",
                consumer_id,
                server_name,
                conn.consumer_count,
            )

    def get_status(self) -> dict[str, Any]:
        """Return pool-wide status snapshot."""
        with self._lock:
            connection_statuses: list[dict[str, Any]] = []
            for conn in self._connections.values():
                last_hc = (
                    datetime.fromtimestamp(conn.last_health_check, tz=UTC).isoformat()
                    if conn.last_health_check
                    else None
                )
                status_str = "connected"
                cb_state = conn.circuit_breaker.state
                if cb_state == CircuitState.OPEN:
                    status_str = "circuit_open"
                elif cb_state == CircuitState.HALF_OPEN:
                    status_str = "half_open"
                elif not conn.connected:
                    status_str = "disconnected"

                connection_statuses.append(
                    MCPConnectionStatus(
                        connection_id=conn.connection_id,
                        server_name=conn.server_name,
                        status=status_str,
                        last_health_check=last_hc,
                        failure_count=conn.circuit_breaker.failure_count,
                        active_consumers=conn.consumer_count,
                    ).model_dump()
                )

            return {
                "total_connections": len(self._connections),
                "max_connections": self._max_connections,
                "idle_timeout": IDLE_TIMEOUT,
                "health_check_interval": HEALTH_CHECK_INTERVAL,
                "keepalive_interval": KEEPALIVE_INTERVAL,
                "connections": connection_statuses,
            }

    def record_success(self, server_name: str) -> None:
        """Record a successful tool call on *server_name*."""
        with self._lock:
            conn = self._connections.get(server_name)
            if conn:
                conn.circuit_breaker.record_success()
                conn.touch()

    def record_failure(self, server_name: str, error: Exception | None = None) -> None:
        """Record a failed tool call on *server_name*."""
        with self._lock:
            conn = self._connections.get(server_name)
            if conn:
                conn.circuit_breaker.record_failure(error)

    # ----- shutdown -----

    def _shutdown(self) -> None:
        logger.info("Shutting down MCPConnectionRegistry ...")
        self._shutdown_event.set()
        if self._health_thread and self._health_thread.is_alive():
            self._health_thread.join(timeout=2)
        if self._keepalive_thread and self._keepalive_thread.is_alive():
            self._keepalive_thread.join(timeout=2)
        with self._lock:
            for conn in self._connections.values():
                try:
                    loop = asyncio.new_event_loop()
                    try:
                        loop.run_until_complete(conn.disconnect())
                    finally:
                        loop.close()
                except Exception as exc:
                    logger.debug(
                        "Error disconnecting %s: %s",
                        conn.connection_id,
                        exc,
                    )
            self._connections.clear()
        logger.info("MCPConnectionRegistry shutdown complete")

    async def shutdown_async(self) -> None:
        """Async-friendly shutdown."""
        self._shutdown_event.set()
        with self._lock:
            for conn in self._connections.values():
                try:
                    await conn.disconnect()
                except Exception as exc:
                    logger.debug(
                        "Error disconnecting %s: %s",
                        conn.connection_id,
                        exc,
                    )
            self._connections.clear()
