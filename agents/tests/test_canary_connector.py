"""Unit tests for the Thinkst Canary (deception) MCP connector (#100 Tier-2 slice).

First deception / honeypot connector — mirrors the Vectra/Wiz suites (read-only
telemetry, no HITL action).

Coverage:
- Incident list: acknowledged filter, incident-type substring, composition,
  limit.
- Device list: kind filter, limit.
- Incident summary: per-IP incident types, decoys tripped, multi-decoy
  movement flag, unacknowledged count, not-found envelope.
- The intruder story: one attacker IP trips a canarytoken then a canary
  (multi-decoy movement across the grid).
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
from btagent_agents.mcp.servers._canary_fixtures import (
    ATTACKER_IP,
    CANARY_FIXTURE_DEVICES,
    CANARY_FIXTURE_INCIDENTS,
)
from btagent_agents.mcp.servers.canary_mcp import (
    CanaryMCPServer,
    _redact_secret,
)


def _server() -> CanaryMCPServer:
    return CanaryMCPServer(mock_mode=True)


# ---------------------------------------------------------------------------
# Incident list mock
# ---------------------------------------------------------------------------


class TestListIncidents:
    async def test_all_incidents_by_default(self) -> None:
        out = await _server().canary_list_incidents()
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["total"] == len(CANARY_FIXTURE_INCIDENTS)

    async def test_unacknowledged_filter(self) -> None:
        out = await _server().canary_list_incidents(acknowledged=False)
        assert out["total"] == 3  # the intruder's three trips
        assert all(i["acknowledged"] is False for i in out["incidents"])

    async def test_acknowledged_filter(self) -> None:
        out = await _server().canary_list_incidents(acknowledged=True)
        assert out["total"] == 1
        assert out["incidents"][0]["target"] == "vpn-portal-decoy"

    async def test_incident_type_substring(self) -> None:
        out = await _server().canary_list_incidents(incident_type_contains="canarytoken")
        assert out["total"] == 1
        assert out["incidents"][0]["target"] == "aws-key-finance"

    async def test_limit_caps(self) -> None:
        out = await _server().canary_list_incidents(limit=2)
        assert out["total"] == 2


# ---------------------------------------------------------------------------
# Device list mock
# ---------------------------------------------------------------------------


class TestListDevices:
    async def test_all_devices_by_default(self) -> None:
        out = await _server().canary_list_devices()
        assert out["total"] == len(CANARY_FIXTURE_DEVICES)

    async def test_kind_filter_token(self) -> None:
        out = await _server().canary_list_devices(kind="canarytoken")
        assert out["total"] == 1
        assert out["devices"][0]["name"] == "aws-key-finance"

    async def test_kind_filter_canary(self) -> None:
        out = await _server().canary_list_devices(kind="canary")
        names = {d["name"] for d in out["devices"]}
        assert "aws-key-finance" not in names
        assert "fileserver-decoy" in names


# ---------------------------------------------------------------------------
# Incident summary
# ---------------------------------------------------------------------------


class TestIncidentSummary:
    async def test_intruder_multi_decoy_summary(self) -> None:
        out = await _server().canary_incident_summary(ATTACKER_IP)
        assert out["status"] == "success"
        assert out["incident_count"] == 3
        assert out["unacknowledged_count"] == 3
        assert out["multi_decoy"] is True
        assert set(out["decoys_tripped"]) == {"aws-key-finance", "fileserver-decoy"}
        assert "canarytoken triggered" in out["incident_types"]

    async def test_single_trip_not_multi_decoy(self) -> None:
        out = await _server().canary_incident_summary("203.0.113.9")
        assert out["status"] == "success"
        assert out["incident_count"] == 1
        assert out["multi_decoy"] is False

    async def test_unknown_ip_not_found(self) -> None:
        out = await _server().canary_incident_summary("10.0.0.1")
        assert out["status"] == "not_found"


# ---------------------------------------------------------------------------
# Story coherence
# ---------------------------------------------------------------------------


class TestStoryCoherence:
    def test_incident_targets_are_real_devices(self) -> None:
        device_names = set(CANARY_FIXTURE_DEVICES)
        for inc in CANARY_FIXTURE_INCIDENTS:
            assert inc["target"] in device_names

    async def test_token_then_canary_progression(self) -> None:
        summary = await _server().canary_incident_summary(ATTACKER_IP)
        # The attacker used a token AND tripped a canary — grid movement.
        assert "aws-key-finance" in summary["decoys_tripped"]  # the token
        assert "fileserver-decoy" in summary["decoys_tripped"]  # the canary


# ---------------------------------------------------------------------------
# Live mode refuses without an API token
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutToken:
    async def test_live_mode_without_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_CANARY_API_TOKEN", raising=False)
        server = CanaryMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_CANARY_API_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.canary_list_incidents()
        with pytest.raises(NotImplementedError):
            await server.canary_list_devices()
        with pytest.raises(NotImplementedError):
            await server.canary_incident_summary(ATTACKER_IP)

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_CANARY_API_TOKEN", "canary-token-0123456789abcdef")
        server = CanaryMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_CANARY_API_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.canary_list_incidents()


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = CanaryMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_CANARY_API_TOKEN}")
        assert "canary-token" not in repr(server)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("canary-token-0123456789abcdef")
        assert out.startswith("[redacted:canary-api-token:")
        assert "canary-token-0123456789" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BTAGENT_CANARY_API_TOKEN", "canary-token-0123456789abcdef")
        server = CanaryMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_CANARY_API_TOKEN}")
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.canary"):
            with pytest.raises(NotImplementedError):
                await server.canary_list_incidents()
        for record in caplog.records:
            assert "canary-token-0123456789abcdef" not in record.getMessage()


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
            name="canary",
            description="canary test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("canary", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("canary", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_canary_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "canary" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["canary"] is CanaryMCPServer

    def test_tool_metadata_marks_canary_server(self) -> None:
        meta = _server().get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "canary_list_incidents",
            "canary_list_devices",
            "canary_incident_summary",
        }
        assert all(m["server_id"] == "canary" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.canary_mcp.resolve_secret", _spy)
    CanaryMCPServer(mock_mode=False)
    assert calls == []
