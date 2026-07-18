"""Unit tests for the Vectra AI NDR MCP connector (#100 Tier-2 slice).

First NDR connector — mirrors the Wiz/CloudTrail suites (read-only telemetry,
no HITL action).

Coverage:
- Detection list: threat floor, category / state filters, composition, limit.
- Host list: threat floor, key-assets-only filter, limit.
- Host summary: detections by category, kill-chain categories, max
  threat/certainty, the Vectra risk quadrant, not-found envelope.
- The kill-chain story: WIN10-FIN-07 escalates recon → C2 → lateral → exfil
  into the critical quadrant.
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
from btagent_agents.mcp.servers._vectra_fixtures import (
    COMPROMISED_HOST,
    VECTRA_FIXTURE_DETECTIONS,
    VECTRA_FIXTURE_HOSTS,
)
from btagent_agents.mcp.servers.vectra_mcp import (
    VectraMCPServer,
    _quadrant,
    _redact_secret,
)


def _server() -> VectraMCPServer:
    return VectraMCPServer(mock_mode=True)


# ---------------------------------------------------------------------------
# Quadrant helper (pure)
# ---------------------------------------------------------------------------


class TestQuadrant:
    def test_quadrants(self) -> None:
        assert _quadrant(91, 84) == "critical"
        assert _quadrant(82, 30) == "high"
        assert _quadrant(20, 76) == "medium"
        assert _quadrant(10, 10) == "low"


# ---------------------------------------------------------------------------
# Detection list mock
# ---------------------------------------------------------------------------


class TestListDetections:
    async def test_all_detections_by_default(self) -> None:
        out = await _server().vectra_list_detections()
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["total"] == len(VECTRA_FIXTURE_DETECTIONS)

    async def test_threat_floor(self) -> None:
        out = await _server().vectra_list_detections(min_threat=80)
        # Hidden HTTPS Tunnel (82) + Data Smuggler (91) clear the floor.
        assert out["total"] == 2
        assert all(d["threat"] >= 80 for d in out["detections"])

    async def test_category_filter(self) -> None:
        out = await _server().vectra_list_detections(category="exfiltration")
        assert out["total"] == 1
        assert out["detections"][0]["detection_id"] == "det-1004"

    async def test_state_filter(self) -> None:
        out = await _server().vectra_list_detections(state="fixed")
        assert out["total"] == 1
        assert out["detections"][0]["src_host"]["name"] == "SRV-DB-11"

    async def test_filters_compose_to_empty(self) -> None:
        out = await _server().vectra_list_detections(category="exfiltration", state="fixed")
        assert out["total"] == 0

    async def test_limit_caps(self) -> None:
        out = await _server().vectra_list_detections(limit=2)
        assert out["total"] == 2


# ---------------------------------------------------------------------------
# Host list mock
# ---------------------------------------------------------------------------


class TestListHosts:
    async def test_all_hosts_by_default(self) -> None:
        out = await _server().vectra_list_hosts()
        assert out["total"] == len(VECTRA_FIXTURE_HOSTS)

    async def test_threat_floor(self) -> None:
        out = await _server().vectra_list_hosts(min_threat=50)
        assert out["total"] == 1
        assert out["hosts"][0]["name"] == COMPROMISED_HOST

    async def test_key_assets_only(self) -> None:
        out = await _server().vectra_list_hosts(key_assets_only=True)
        names = {h["name"] for h in out["hosts"]}
        assert "WS-DESIGN-22" not in names  # not a key asset
        assert COMPROMISED_HOST in names


# ---------------------------------------------------------------------------
# Host summary
# ---------------------------------------------------------------------------


class TestHostSummary:
    async def test_compromised_host_summary(self) -> None:
        out = await _server().vectra_host_summary(COMPROMISED_HOST)
        assert out["status"] == "success"
        assert out["detection_count"] == 4
        assert out["quadrant"] == "critical"
        assert out["max_threat"] == 91
        assert set(out["kill_chain_categories"]) == {
            "reconnaissance",
            "command-and-control",
            "lateral-movement",
            "exfiltration",
        }

    async def test_low_score_host_summary(self) -> None:
        out = await _server().vectra_host_summary("SRV-DB-11")
        assert out["status"] == "success"
        assert out["detection_count"] == 1
        assert out["quadrant"] == "low"

    async def test_clean_host_summary(self) -> None:
        out = await _server().vectra_host_summary("WS-DESIGN-22")
        assert out["status"] == "success"
        assert out["detection_count"] == 0
        assert out["quadrant"] == "low"

    async def test_unknown_host_not_found(self) -> None:
        out = await _server().vectra_host_summary("WS-GHOST-99")
        assert out["status"] == "not_found"


# ---------------------------------------------------------------------------
# Cross-surface story coherence
# ---------------------------------------------------------------------------


class TestStoryCoherence:
    def test_detections_join_hosts_on_name(self) -> None:
        host_names = set(VECTRA_FIXTURE_HOSTS)
        for det in VECTRA_FIXTURE_DETECTIONS:
            assert det["src_host"]["name"] in host_names

    async def test_kill_chain_escalates_to_critical(self) -> None:
        # The host in the critical quadrant is the one with the exfil detection.
        hosts = await _server().vectra_list_hosts(min_threat=50)
        summary = await _server().vectra_host_summary(hosts["hosts"][0]["name"])
        assert summary["quadrant"] == "critical"
        assert "exfiltration" in summary["kill_chain_categories"]


# ---------------------------------------------------------------------------
# Live mode refuses without an API token
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutToken:
    async def test_live_mode_without_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_VECTRA_API_TOKEN", raising=False)
        server = VectraMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_VECTRA_API_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.vectra_list_detections()
        with pytest.raises(NotImplementedError):
            await server.vectra_list_hosts()
        with pytest.raises(NotImplementedError):
            await server.vectra_host_summary(COMPROMISED_HOST)

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_VECTRA_API_TOKEN", "vectra-token-0123456789abcdef")
        server = VectraMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_VECTRA_API_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.vectra_list_detections()


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = VectraMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_VECTRA_API_TOKEN}")
        assert "vectra-token" not in repr(server)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("vectra-token-0123456789abcdef")
        assert out.startswith("[redacted:vectra-api-token:")
        assert "vectra-token-0123456789" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BTAGENT_VECTRA_API_TOKEN", "vectra-token-0123456789abcdef")
        server = VectraMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_VECTRA_API_TOKEN}")
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.vectra"):
            with pytest.raises(NotImplementedError):
                await server.vectra_list_detections()
        for record in caplog.records:
            assert "vectra-token-0123456789abcdef" not in record.getMessage()


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
            name="vectra",
            description="vectra test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("vectra", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("vectra", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_vectra_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "vectra" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["vectra"] is VectraMCPServer

    def test_tool_metadata_marks_vectra_server(self) -> None:
        meta = _server().get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "vectra_list_detections",
            "vectra_list_hosts",
            "vectra_host_summary",
        }
        assert all(m["server_id"] == "vectra" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.vectra_mcp.resolve_secret", _spy)
    VectraMCPServer(mock_mode=False)
    assert calls == []
