"""Unit tests for the Zeek / Corelight MCP connector (#100 Tier-1 slice).

First network-sensor connector — mirrors the SentinelOne / MDE suites so the
modern Tier-1 connectors stay exercised symmetrically. A Zeek sensor is
passive, so unlike the EDR suites there is no HITL-action coverage: all
capabilities are read-only.

Coverage:
- Log-stream search: routing per log type, unknown-log envelope, quoted-
  literal conjunctive narrowing, time window, limit.
- Notice list: window + note-substring filters.
- Behavioral connection summary: totals, per-destination rollup ordering,
  long-lived (exfil) detection, byte accounting, not-found envelope.
- Cross-surface joins: conn ↔ ssl ↔ notice rows on Zeek's uid; the
  DNS-tunneling story coheres across streams.
- Live mode refuses without an API token; secret redaction; lazy secret
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
from btagent_agents.mcp.servers._zeek_fixtures import ZEEK_FIXTURE_LOGS
from btagent_agents.mcp.servers.zeek_mcp import (
    LONG_LIVED_THRESHOLD_SECONDS,
    ZeekMCPServer,
    _filter_literals,
    _redact_secret,
)

# Fixture window covering every recorded row.
WINDOW_START = "2026-06-20T00:00:00Z"
WINDOW_END = "2026-06-21T00:00:00Z"

BEACON_HOST = "10.7.3.44"
BEACON_DEST = "198.51.100.150"


def _server() -> ZeekMCPServer:
    return ZeekMCPServer(mock_mode=True)


# ---------------------------------------------------------------------------
# Filter helpers (pure)
# ---------------------------------------------------------------------------


class TestFilterHelpers:
    def test_literals_extracted_in_order(self) -> None:
        expr = 'id.resp_h == "198.51.100.150" && service == "ssl"'
        assert _filter_literals(expr) == ["198.51.100.150", "ssl"]

    def test_none_and_bare_expr(self) -> None:
        assert _filter_literals(None) == []
        assert _filter_literals("id.resp_p == 443") == []


# ---------------------------------------------------------------------------
# Log search mock
# ---------------------------------------------------------------------------


class TestLogSearch:
    async def test_bare_search_returns_all_conn_rows(self) -> None:
        out = await _server().zeek_log_search("conn", WINDOW_START, WINDOW_END)
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["total"] == len(ZEEK_FIXTURE_LOGS["conn"])

    async def test_unknown_log_error_envelope(self) -> None:
        out = await _server().zeek_log_search("weird", WINDOW_START, WINDOW_END)
        assert out["status"] == "unknown_log"
        assert "conn" in out["message"]

    async def test_quoted_literal_narrows_rows(self) -> None:
        out = await _server().zeek_log_search(
            "conn", WINDOW_START, WINDOW_END, filter_expr=f'id.resp_h == "{BEACON_DEST}"'
        )
        assert out["total"] == 4  # 3 beacons + 1 exfil push
        assert all(r["id.resp_h"] == BEACON_DEST for r in out["rows"])

    async def test_multiple_literals_are_conjunctive(self) -> None:
        out = await _server().zeek_log_search(
            "dns",
            WINDOW_START,
            WINDOW_END,
            filter_expr='query has "tunnel.example-cdn.net" && qtype == "TXT"',
        )
        assert out["total"] == 2

    async def test_time_window_excludes_rows(self) -> None:
        out = await _server().zeek_log_search(
            "conn", "2026-06-20T09:00:00Z", "2026-06-20T09:02:00Z"
        )
        assert out["total"] == 2  # 09:00:05 and 09:01:06 beacons only

    async def test_limit_caps_rows(self) -> None:
        out = await _server().zeek_log_search("conn", WINDOW_START, WINDOW_END, limit=3)
        assert out["total"] == 3

    async def test_ssl_self_signed_row_present(self) -> None:
        out = await _server().zeek_log_search(
            "ssl", WINDOW_START, WINDOW_END, filter_expr='"self signed certificate"'
        )
        assert out["total"] == 1
        assert out["rows"][0]["subject"] == "CN=localhost"


# ---------------------------------------------------------------------------
# Notices mock
# ---------------------------------------------------------------------------


class TestNotices:
    async def test_all_notices_without_filters(self) -> None:
        out = await _server().zeek_list_notices()
        assert out["total"] == len(ZEEK_FIXTURE_LOGS["notice"])

    async def test_note_contains_filter(self) -> None:
        out = await _server().zeek_list_notices(note_contains="DNS_Tunneling")
        assert out["total"] == 1
        assert out["notices"][0]["src"] == BEACON_HOST

    async def test_window_excludes_early_scan_notice(self) -> None:
        out = await _server().zeek_list_notices(start="2026-06-20T09:00:00Z", end=WINDOW_END)
        assert out["total"] == 2
        assert all(n["src"] == BEACON_HOST for n in out["notices"])

    async def test_limit_caps_notices(self) -> None:
        out = await _server().zeek_list_notices(limit=1)
        assert out["total"] == 1


# ---------------------------------------------------------------------------
# Behavioral connection summary
# ---------------------------------------------------------------------------


class TestConnectionSummary:
    async def test_summary_totals_and_distinct_destinations(self) -> None:
        out = await _server().zeek_connection_summary(BEACON_HOST, WINDOW_START, WINDOW_END)
        assert out["status"] == "success"
        assert out["total_connections"] == 5  # 3 beacons + exfil + internal DNS
        assert out["distinct_destinations"] == 2

    async def test_top_destination_is_the_beacon(self) -> None:
        out = await _server().zeek_connection_summary(BEACON_HOST, WINDOW_START, WINDOW_END)
        top = out["destinations"][0]
        assert top["destination"] == f"{BEACON_DEST}:443"
        assert top["connections"] == 4

    async def test_long_lived_flags_the_exfil_push(self) -> None:
        out = await _server().zeek_connection_summary(BEACON_HOST, WINDOW_START, WINDOW_END)
        assert len(out["long_lived_connections"]) == 1
        exfil = out["long_lived_connections"][0]
        assert exfil["duration"] > LONG_LIVED_THRESHOLD_SECONDS
        assert exfil["orig_bytes"] > 1_000_000  # upload-heavy

    async def test_byte_accounting_sums_per_destination(self) -> None:
        out = await _server().zeek_connection_summary(BEACON_HOST, WINDOW_START, WINDOW_END)
        beacon_dest = out["destinations"][0]
        expected = sum(
            int(c["orig_bytes"])
            for c in ZEEK_FIXTURE_LOGS["conn"]
            if c["id.orig_h"] == BEACON_HOST and c["id.resp_h"] == BEACON_DEST
        )
        assert beacon_dest["orig_bytes"] == expected
        assert out["total_orig_bytes"] > expected  # internal DNS adds a little

    async def test_unknown_host_not_found(self) -> None:
        out = await _server().zeek_connection_summary("10.99.99.99", WINDOW_START, WINDOW_END)
        assert out["status"] == "not_found"

    async def test_window_narrows_summary(self) -> None:
        out = await _server().zeek_connection_summary(
            BEACON_HOST, "2026-06-20T09:00:00Z", "2026-06-20T09:02:00Z"
        )
        assert out["total_connections"] == 2
        assert out["long_lived_connections"] == []


# ---------------------------------------------------------------------------
# Cross-surface joins — Zeek's uid discipline
# ---------------------------------------------------------------------------


class TestJoinDiscipline:
    def test_ssl_rows_join_conn_on_uid(self) -> None:
        conn_uids = {c["uid"] for c in ZEEK_FIXTURE_LOGS["conn"]}
        beacon_ssl = ZEEK_FIXTURE_LOGS["ssl"][0]
        assert beacon_ssl["uid"] in conn_uids

    def test_invalid_cert_notice_joins_beacon_conn_on_uid(self) -> None:
        notice = next(
            n for n in ZEEK_FIXTURE_LOGS["notice"] if n["note"] == "SSL::Invalid_Server_Cert"
        )
        conn = next(c for c in ZEEK_FIXTURE_LOGS["conn"] if c["uid"] == notice["uid"])
        assert conn["id.resp_h"] == BEACON_DEST

    async def test_story_coheres_dns_to_beacon_ip(self) -> None:
        """The beacon destination is exactly what the CDN lookup resolved to."""
        out = await _server().zeek_log_search(
            "dns", WINDOW_START, WINDOW_END, filter_expr='"cdn-sync.example-cdn.net"'
        )
        assert out["total"] == 1
        assert BEACON_DEST in out["rows"][0]["answers"]


# ---------------------------------------------------------------------------
# Live mode refuses without an API token
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutToken:
    async def test_live_mode_without_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_ZEEK_API_TOKEN", raising=False)
        server = ZeekMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_ZEEK_API_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.zeek_log_search("conn", WINDOW_START, WINDOW_END)
        with pytest.raises(NotImplementedError):
            await server.zeek_list_notices()
        with pytest.raises(NotImplementedError):
            await server.zeek_connection_summary(BEACON_HOST, WINDOW_START, WINDOW_END)

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_ZEEK_API_TOKEN", "zeek-token-0123456789abcdef")
        server = ZeekMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_ZEEK_API_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.zeek_log_search("conn", WINDOW_START, WINDOW_END)


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = ZeekMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_ZEEK_API_TOKEN}")
        assert "zeek-token" not in repr(server)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("zeek-token-0123456789abcdef")
        assert out.startswith("[redacted:zeek-api-token:")
        assert "zeek-token-0123456789" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BTAGENT_ZEEK_API_TOKEN", "zeek-token-0123456789abcdef")
        server = ZeekMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_ZEEK_API_TOKEN}")
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.zeek"):
            with pytest.raises(NotImplementedError):
                await server.zeek_log_search("conn", WINDOW_START, WINDOW_END)
        for record in caplog.records:
            assert "zeek-token-0123456789abcdef" not in record.getMessage()


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
            name="zeek",
            description="zeek test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("zeek", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("zeek", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_zeek_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "zeek" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["zeek"] is ZeekMCPServer

    def test_tool_metadata_marks_zeek_server(self) -> None:
        meta = _server().get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "zeek_log_search",
            "zeek_list_notices",
            "zeek_connection_summary",
        }
        assert all(m["server_id"] == "zeek" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.zeek_mcp.resolve_secret", _spy)
    ZeekMCPServer(mock_mode=False)
    assert calls == []
