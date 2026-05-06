"""Unit tests for MCP transport hardening.

Covers the three Phase 0 audit findings:

1. TLS verification defaults to ON; disabling requires explicit opt-in and
   logs a warning at WARNING level.
2. Circuit-breaker recovery uses exponential backoff (30s, 60s, 120s, 240s,
   480s, capped at 600s) and resets to 30s after a successful close.
3. Per-response byte cap is enforced -- oversize payloads are truncated
   and the returned envelope is flagged with ``_truncated: True``.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from unittest.mock import patch

import pytest
from btagent_shared.types.config import MCPTransport
from btagent_shared.types.mcp import MCPServerConfig

from btagent_agents.mcp.config import (
    DEFAULT_MAX_RESPONSE_BYTES as CONFIG_DEFAULT_MAX_RESPONSE_BYTES,
)
from btagent_agents.mcp.config import (
    MCPHardenedServerConfig,
)
from btagent_agents.mcp.registry import (
    CB_RECOVERY_TIMEOUT,
    CB_RECOVERY_TIMEOUT_MAX,
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
    ManagedConnection,
)
from btagent_agents.mcp.transports import (
    DEFAULT_MAX_RESPONSE_BYTES,
    HTTPTransport,
    SSETransport,
    StdioTransport,
    build_transport,
    enforce_cap,
)


# ---------------------------------------------------------------------------
# Finding 1 -- TLS verification
# ---------------------------------------------------------------------------
class TestTLSVerification:
    """``verify_ssl`` must default to True; explicit-off must log a warning."""

    def test_http_default_verify_ssl_on(self) -> None:
        t = HTTPTransport(server_url="https://example.com")
        assert t.verify_ssl is True

    def test_sse_default_verify_ssl_on(self) -> None:
        t = SSETransport(server_url="https://example.com")
        assert t.verify_ssl is True

    def test_hardened_config_defaults_verify_ssl_on(self) -> None:
        cfg = MCPHardenedServerConfig(name="splunk", description="x")
        assert cfg.verify_ssl is True
        assert cfg.max_response_bytes == 10 * 1024 * 1024
        # ``circuit_breaker_recovery_max`` defaults to 600s (10 min cap).
        assert cfg.circuit_breaker_recovery_max == 600

    def test_legacy_config_falls_back_to_safe_defaults(self) -> None:
        """A legacy ``MCPServerConfig`` (no new fields) must still default
        to TLS verify ON and the 10 MiB byte cap when read via helpers."""
        from btagent_agents.mcp.config import (
            get_max_response_bytes,
            get_verify_ssl,
        )

        legacy = MCPServerConfig(name="legacy", description="x")
        assert get_verify_ssl(legacy) is True
        assert get_max_response_bytes(legacy) == 10 * 1024 * 1024

    def test_build_transport_propagates_verify_ssl_default(self) -> None:
        cfg = MCPHardenedServerConfig(
            name="vt",
            description="virustotal",
            transport=MCPTransport.STREAMABLE_HTTP,
            server_url="https://virustotal.example",
        )
        t = build_transport(cfg)
        assert isinstance(t, HTTPTransport)
        assert t.verify_ssl is True
        assert t.max_response_bytes == DEFAULT_MAX_RESPONSE_BYTES

    def test_build_transport_explicit_verify_ssl_off(self) -> None:
        cfg = MCPHardenedServerConfig(
            name="local",
            description="dev",
            transport=MCPTransport.STREAMABLE_HTTP,
            server_url="https://local.dev",
            verify_ssl=False,
        )
        t = build_transport(cfg)
        assert isinstance(t, HTTPTransport)
        assert t.verify_ssl is False

    async def test_http_verify_ssl_off_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        t = HTTPTransport(server_url="https://example.com", verify_ssl=False)
        caplog.set_level(logging.WARNING, logger="btagent.mcp.transports")
        await t.connect()
        try:
            assert any(
                "TLS verification DISABLED" in rec.message
                and rec.levelno == logging.WARNING
                for rec in caplog.records
            ), f"expected WARNING about disabled TLS, got: {caplog.records}"
        finally:
            await t.disconnect()

    async def test_sse_verify_ssl_off_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        t = SSETransport(server_url="https://example.com", verify_ssl=False)
        caplog.set_level(logging.WARNING, logger="btagent.mcp.transports")
        await t.connect()
        try:
            assert any(
                "TLS verification DISABLED" in rec.message for rec in caplog.records
            )
        finally:
            await t.disconnect()

    async def test_http_verify_ssl_on_does_not_warn(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        t = HTTPTransport(server_url="https://example.com", verify_ssl=True)
        caplog.set_level(logging.WARNING, logger="btagent.mcp.transports")
        await t.connect()
        try:
            assert not any(
                "TLS verification DISABLED" in rec.message for rec in caplog.records
            )
        finally:
            await t.disconnect()


# ---------------------------------------------------------------------------
# Finding 2 -- Exponential backoff
# ---------------------------------------------------------------------------
class _ClockStub:
    """Monotonic clock stub for ``time.time``-style patching."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _trip_to_open(
    cb: CircuitBreaker, clock: _ClockStub, *, count: int | None = None
) -> None:
    """Drive the breaker into OPEN by recording threshold failures."""
    n = count if count is not None else cb.failure_threshold
    for _ in range(n):
        cb.record_failure(RuntimeError("boom"))
    # last_failure_time is set inside record_failure via patched time.time
    assert cb.state in (CircuitState.OPEN, CircuitState.HALF_OPEN)


class TestExponentialBackoff:
    """Recovery wait must follow 30, 60, 120, 240, 480, 600(cap)."""

    def setup_method(self) -> None:
        self.clock = _ClockStub()
        self._patcher = patch("btagent_agents.mcp.registry.time.time", self.clock)
        self._patcher.start()

    def teardown_method(self) -> None:
        self._patcher.stop()

    def test_first_open_uses_base_recovery(self) -> None:
        cb = CircuitBreaker(
            connection_id="splunk",
            failure_threshold=2,
            recovery_timeout=30.0,
            recovery_timeout_max=600.0,
            success_threshold=1,
        )
        _trip_to_open(cb, self.clock, count=2)
        assert cb.current_recovery_timeout == 30.0

    def test_backoff_schedule_matches_30_60_120_240_480_600(self) -> None:
        """Drive the breaker through six consecutive OPEN cycles."""
        cb = CircuitBreaker(
            connection_id="splunk",
            failure_threshold=1,  # one failure trips it
            recovery_timeout=30.0,
            recovery_timeout_max=600.0,
            success_threshold=1,
        )

        expected_schedule = [30.0, 60.0, 120.0, 240.0, 480.0, 600.0]

        for cycle, expected_wait in enumerate(expected_schedule, start=1):
            if cycle == 1:
                # First trip: closed -> open
                cb.record_failure(RuntimeError("boom"))
            else:
                # We're already OPEN. Confirm the breaker still rejects
                # requests while we're inside the previous wait window.
                with pytest.raises(CircuitOpenError):
                    cb.check_state()
                # Advance past the previous wait so the breaker becomes
                # eligible for HALF_OPEN.
                self.clock.advance(expected_schedule[cycle - 2] + 0.001)
                # Reading state transitions OPEN -> HALF_OPEN.
                assert cb.state == CircuitState.HALF_OPEN, (
                    f"cycle {cycle}: expected HALF_OPEN, got {cb.state}"
                )
                # A failure in HALF_OPEN re-opens the breaker and bumps
                # the open-cycle counter, doubling the wait.
                cb.record_failure(RuntimeError("still down"))

            assert cb.state == CircuitState.OPEN, f"cycle {cycle}: not OPEN"
            assert cb.current_recovery_timeout == expected_wait, (
                f"cycle {cycle}: expected wait {expected_wait}s, "
                f"got {cb.current_recovery_timeout}s"
            )

    def test_backoff_caps_at_recovery_timeout_max(self) -> None:
        cb = CircuitBreaker(
            connection_id="splunk",
            failure_threshold=1,
            recovery_timeout=30.0,
            recovery_timeout_max=600.0,
            success_threshold=1,
        )
        # Force ten consecutive cycles -- wait must never exceed the cap.
        cb.record_failure(RuntimeError("boom"))
        for _ in range(15):
            self.clock.advance(700.0)  # always exceeds any expected wait
            _ = cb.state  # OPEN -> HALF_OPEN
            cb.record_failure(RuntimeError("boom"))
        assert cb.current_recovery_timeout == 600.0

    def test_backoff_resets_to_base_on_successful_close(self) -> None:
        cb = CircuitBreaker(
            connection_id="splunk",
            failure_threshold=1,
            recovery_timeout=30.0,
            recovery_timeout_max=600.0,
            success_threshold=1,
        )
        # Trip three times to escalate the schedule.
        cb.record_failure(RuntimeError("boom"))  # cycle 1 -> wait 30
        self.clock.advance(31.0)
        _ = cb.state
        cb.record_failure(RuntimeError("boom"))  # cycle 2 -> wait 60
        self.clock.advance(61.0)
        _ = cb.state
        cb.record_failure(RuntimeError("boom"))  # cycle 3 -> wait 120
        assert cb.current_recovery_timeout == 120.0

        # Recover: advance past wait, transition to HALF_OPEN, succeed.
        self.clock.advance(121.0)
        _ = cb.state  # OPEN -> HALF_OPEN
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

        # Trip again: schedule must restart at the base 30s wait.
        cb.record_failure(RuntimeError("boom"))
        assert cb.state == CircuitState.OPEN
        assert cb.current_recovery_timeout == 30.0

    def test_module_level_defaults_present(self) -> None:
        # Sanity: env-driven defaults exist and are sensible.
        assert CB_RECOVERY_TIMEOUT == 30.0
        assert CB_RECOVERY_TIMEOUT_MAX == 600.0


class TestManagedConnectionPlumbsBackoff:
    """``ManagedConnection`` must hand the recovery_max into its breaker."""

    def test_managed_connection_uses_config_recovery_max(self) -> None:
        cfg = MCPHardenedServerConfig(
            name="splunk",
            description="x",
            circuit_breaker_threshold=2,
            circuit_breaker_recovery=15,
            circuit_breaker_recovery_max=120,
        )
        mc = ManagedConnection(connection_id="splunk", server_name="splunk", config=cfg)
        assert mc.circuit_breaker.recovery_timeout == 15.0
        assert mc.circuit_breaker.recovery_timeout_max == 120.0

    def test_managed_connection_legacy_config_uses_default_recovery_max(self) -> None:
        """Legacy ``MCPServerConfig`` (no recovery_max field) must still
        get a sane default rather than crashing or using an unbounded wait."""
        cfg = MCPServerConfig(
            name="splunk",
            description="x",
            circuit_breaker_threshold=2,
            circuit_breaker_recovery=15,
        )
        mc = ManagedConnection(connection_id="splunk", server_name="splunk", config=cfg)
        assert mc.circuit_breaker.recovery_timeout == 15.0
        # Falls back to env-driven default (600s).
        assert mc.circuit_breaker.recovery_timeout_max == 600.0


# ---------------------------------------------------------------------------
# Finding 3 -- Response-size cap
# ---------------------------------------------------------------------------
class _MockAiohttpResponse:
    """Minimal stand-in for ``aiohttp.ClientResponse`` used in tests."""

    def __init__(self, body: bytes, *, chunk_size: int = 64 * 1024) -> None:
        self._body = body
        self._chunk_size = chunk_size
        self.content = self  # iter_chunked is on .content

    async def iter_chunked(self, n: int) -> Any:
        # Yield in fixed slices to mimic aiohttp's streaming semantics.
        for i in range(0, len(self._body), self._chunk_size):
            yield self._body[i : i + self._chunk_size]

    async def read(self) -> bytes:
        return self._body

    def raise_for_status(self) -> None:
        return None


class TestResponseSizeCap:
    def test_default_cap_is_10mib(self) -> None:
        assert DEFAULT_MAX_RESPONSE_BYTES == 10 * 1024 * 1024
        assert CONFIG_DEFAULT_MAX_RESPONSE_BYTES == 10 * 1024 * 1024
        cfg = MCPHardenedServerConfig(name="splunk", description="x")
        assert cfg.max_response_bytes == 10 * 1024 * 1024

    def test_enforce_cap_passes_small_payload(self) -> None:
        out = enforce_cap({"hello": "world"}, limit=1024)
        assert out == {"hello": "world"}
        assert "_truncated" not in out

    def test_enforce_cap_truncates_oversize_dict(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # 5 KiB dict, cap 1 KiB -> truncated envelope
        big = {"data": "x" * 5000}
        caplog.set_level(logging.WARNING, logger="btagent.mcp.transports")
        out = enforce_cap(big, limit=1024, transport="test")

        assert out["_truncated"] is True
        assert out["_truncated_reason"] == "max_response_bytes_exceeded"
        assert out["_truncated_transport"] == "test"
        assert out["_truncated_size_bytes"] > 1024
        assert out["_truncated_limit_bytes"] == 1024
        assert "_truncated_preview" in out
        assert any(
            "truncated" in rec.message and rec.levelno == logging.WARNING
            for rec in caplog.records
        )

    def test_enforce_cap_truncates_oversize_string(self) -> None:
        out = enforce_cap("a" * 100, limit=10)
        assert out["_truncated"] is True

    def test_enforce_cap_handles_invalid_json_at_limit(self) -> None:
        # Within limit but not valid JSON -- should still flag.
        out = enforce_cap(b"not-json-at-all", limit=10_000)
        assert out["_truncated"] is True
        assert "_truncated_parse_error" in out

    async def test_http_receive_caps_oversize_body(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        big_body = b"x" * (2 * 1024 * 1024)  # 2 MiB
        cap = 256 * 1024  # 256 KiB

        t = HTTPTransport(
            server_url="https://example.com",
            max_response_bytes=cap,
        )
        # Bypass real aiohttp: mark connected + install a dummy session.
        t._connected = True

        class _DummySession:
            def get(self_inner, url: str) -> Any:
                resp = _MockAiohttpResponse(big_body)

                class _Ctx:
                    async def __aenter__(self_ctx) -> Any:
                        return resp

                    async def __aexit__(
                        self_ctx, exc_type: Any, exc: Any, tb: Any
                    ) -> None:
                        return None

                return _Ctx()

        t._session = _DummySession()

        caplog.set_level(logging.WARNING, logger="btagent.mcp.transports")
        result = await t.receive()

        assert result["_truncated"] is True
        assert result["_truncated_transport"] == "http"
        assert result["_truncated_limit_bytes"] == cap
        assert result["_truncated_size_bytes"] >= cap
        assert any(
            "truncated" in rec.message for rec in caplog.records
        )

    async def test_http_receive_passes_small_body(self) -> None:
        small = json.dumps({"events": [1, 2, 3]}).encode()
        t = HTTPTransport(server_url="https://example.com", max_response_bytes=4096)
        t._connected = True

        class _DummySession:
            def get(self_inner, url: str) -> Any:
                resp = _MockAiohttpResponse(small)

                class _Ctx:
                    async def __aenter__(self_ctx) -> Any:
                        return resp

                    async def __aexit__(
                        self_ctx, exc_type: Any, exc: Any, tb: Any
                    ) -> None:
                        return None

                return _Ctx()

        t._session = _DummySession()
        result = await t.receive()
        assert result == {"events": [1, 2, 3]}
        assert "_truncated" not in result

    def test_stdio_transport_carries_max_bytes(self) -> None:
        t = StdioTransport(command=["echo", "hi"], max_response_bytes=2048)
        assert t.max_response_bytes == 2048

    def test_build_transport_propagates_max_response_bytes(self) -> None:
        cfg = MCPHardenedServerConfig(
            name="splunk",
            description="x",
            transport=MCPTransport.STDIO,
            command=["python", "-m", "x"],
            max_response_bytes=1024,
        )
        t = build_transport(cfg)
        assert isinstance(t, StdioTransport)
        assert t.max_response_bytes == 1024
