"""Unit tests for the Zscaler ZIA MCP connector (#100 Tier-2 slice).

First web-proxy / secure-web-gateway connector — mirrors the CloudTrail/GCP
suites (read-only telemetry, no HITL action).

Coverage:
- Weblog search: window filtering, exact user / action filters, url substring,
  limit.
- URL summary: per-destination user set, allowed/blocked counts, categories,
  threat names, bytes, not-found envelope.
- User summary: top destinations, blocked count, bytes out, not-found.
- The C2-plus-exfil story: the blocked beacon burst and the large allowed
  upload both surface on dkim's user summary.
- Live mode refuses without an API key; secret redaction; lazy secret
  resolution at construction; circuit breaker; discovery registration.
"""

from __future__ import annotations

import logging

import pytest
from btagent_shared.types.mcp import MCPServerConfig

from btagent_agents.mcp.registry import (
    CircuitOpenError,
    CircuitState,
    MCPConnectionRegistry,
)
from btagent_agents.mcp.servers._zscaler_fixtures import C2_HOST, ZSCALER_FIXTURE_WEBLOGS
from btagent_agents.mcp.servers.zscaler_mcp import (
    ZscalerMCPServer,
    _redact_secret,
)

WINDOW_START = "2026-07-14T00:00:00Z"
WINDOW_END = "2026-07-15T00:00:00Z"


def _server() -> ZscalerMCPServer:
    return ZscalerMCPServer(mock_mode=True)


# ---------------------------------------------------------------------------
# Weblog search mock
# ---------------------------------------------------------------------------


class TestWeblogSearch:
    async def test_bare_search_returns_all_in_window(self) -> None:
        out = await _server().zscaler_weblog_search(WINDOW_START, WINDOW_END)
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["total"] == len(ZSCALER_FIXTURE_WEBLOGS)

    async def test_user_filter_exact(self) -> None:
        out = await _server().zscaler_weblog_search(
            WINDOW_START, WINDOW_END, user="bwallace@example.com"
        )
        assert out["total"] == 1
        assert out["records"][0]["host"] == "docs.example.com"

    async def test_action_filter(self) -> None:
        out = await _server().zscaler_weblog_search(WINDOW_START, WINDOW_END, action="Blocked")
        assert out["total"] == 3
        assert all(r["action"] == "Blocked" for r in out["records"])

    async def test_url_contains_filter(self) -> None:
        out = await _server().zscaler_weblog_search(WINDOW_START, WINDOW_END, url_contains="paste")
        assert out["total"] == 1
        assert out["records"][0]["reqSize"] == 5_242_880

    async def test_time_window_excludes(self) -> None:
        # The three 10:xx beacons fall in-window; the 11:30 + 13:15 rows don't.
        out = await _server().zscaler_weblog_search("2026-07-14T10:00:00Z", "2026-07-14T10:30:00Z")
        assert out["total"] == 3

    async def test_limit_caps_rows(self) -> None:
        out = await _server().zscaler_weblog_search(WINDOW_START, WINDOW_END, limit=2)
        assert out["total"] == 2


# ---------------------------------------------------------------------------
# URL summary
# ---------------------------------------------------------------------------


class TestUrlSummary:
    async def test_c2_host_summary(self) -> None:
        out = await _server().zscaler_url_summary(C2_HOST, WINDOW_START, WINDOW_END)
        assert out["status"] == "success"
        assert out["total_requests"] == 3
        assert out["actions"] == {"Blocked": 3}
        assert out["distinct_users"] == ["dkim@example.com"]
        assert "Trojan.GenericBeacon" in out["threat_names"]
        assert out["categories"] == ["Malware"]

    async def test_unknown_destination_not_found(self) -> None:
        out = await _server().zscaler_url_summary("nowhere.example", WINDOW_START, WINDOW_END)
        assert out["status"] == "not_found"


# ---------------------------------------------------------------------------
# User summary
# ---------------------------------------------------------------------------


class TestUserSummary:
    async def test_compromised_user_summary(self) -> None:
        out = await _server().zscaler_user_summary("dkim@example.com", WINDOW_START, WINDOW_END)
        assert out["status"] == "success"
        assert out["total_requests"] == 4  # 3 beacons + 1 upload
        assert out["blocked_count"] == 3
        assert out["top_destinations"][C2_HOST] == 3
        # The 5 MB upload dominates the bytes-out signal.
        assert out["total_bytes_out"] >= 5_242_880
        assert "Malware" in out["categories"]

    async def test_clean_user_summary(self) -> None:
        out = await _server().zscaler_user_summary("bwallace@example.com", WINDOW_START, WINDOW_END)
        assert out["status"] == "success"
        assert out["blocked_count"] == 0
        assert out["threat_names"] == []

    async def test_unknown_user_not_found(self) -> None:
        out = await _server().zscaler_user_summary("ghost@example.com", WINDOW_START, WINDOW_END)
        assert out["status"] == "not_found"


# ---------------------------------------------------------------------------
# Cross-surface story coherence
# ---------------------------------------------------------------------------


class TestStoryCoherence:
    async def test_beacon_and_exfil_both_on_user(self) -> None:
        summary = await _server().zscaler_user_summary("dkim@example.com", WINDOW_START, WINDOW_END)
        # blocked C2 beacons + the large allowed upload are both on dkim.
        assert C2_HOST in summary["top_destinations"]
        assert "paste.example.io" in summary["top_destinations"]


# ---------------------------------------------------------------------------
# Live mode refuses without an API key
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutKey:
    async def test_live_mode_without_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_ZSCALER_API_KEY", raising=False)
        server = ZscalerMCPServer(mock_mode=False, api_key_ref="${env:BTAGENT_ZSCALER_API_KEY}")
        with pytest.raises(NotImplementedError):
            await server.zscaler_weblog_search(WINDOW_START, WINDOW_END)
        with pytest.raises(NotImplementedError):
            await server.zscaler_url_summary(C2_HOST, WINDOW_START, WINDOW_END)
        with pytest.raises(NotImplementedError):
            await server.zscaler_user_summary("dkim@example.com", WINDOW_START, WINDOW_END)

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_ZSCALER_API_KEY", "zs-key-0123456789abcdef")
        server = ZscalerMCPServer(mock_mode=False, api_key_ref="${env:BTAGENT_ZSCALER_API_KEY}")
        with pytest.raises(NotImplementedError):
            await server.zscaler_weblog_search(WINDOW_START, WINDOW_END)


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = ZscalerMCPServer(mock_mode=False, api_key_ref="${env:BTAGENT_ZSCALER_API_KEY}")
        assert "zs-key" not in repr(server)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("zs-key-0123456789abcdef")
        assert out.startswith("[redacted:zscaler-api-key:")
        assert "zs-key-0123456789" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BTAGENT_ZSCALER_API_KEY", "zs-key-0123456789abcdef")
        server = ZscalerMCPServer(mock_mode=False, api_key_ref="${env:BTAGENT_ZSCALER_API_KEY}")
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.zscaler"):
            with pytest.raises(NotImplementedError):
                await server.zscaler_weblog_search(WINDOW_START, WINDOW_END)
        for record in caplog.records:
            assert "zs-key-0123456789abcdef" not in record.getMessage()


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    def setup_method(self) -> None:
        MCPConnectionRegistry.reset_instance()

    def teardown_method(self) -> None:
        MCPConnectionRegistry.reset_instance()

    async def test_breaker_opens_after_failures_and_blocks(self) -> None:
        registry = MCPConnectionRegistry.get_instance()
        cfg = MCPServerConfig(
            name="zscaler",
            description="zscaler test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("zscaler", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("zscaler", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_zscaler_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "zscaler" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["zscaler"] is ZscalerMCPServer

    def test_tool_metadata_marks_zscaler_server(self) -> None:
        meta = _server().get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "zscaler_weblog_search",
            "zscaler_url_summary",
            "zscaler_user_summary",
        }
        assert all(m["server_id"] == "zscaler" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.zscaler_mcp.resolve_secret", _spy)
    ZscalerMCPServer(mock_mode=False)
    assert calls == []
