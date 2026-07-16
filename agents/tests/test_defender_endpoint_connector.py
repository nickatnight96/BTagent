"""Unit tests for the Defender for Endpoint MCP connector (#100 Tier-1 slice).

First EDR connector built in the modern Tier-1 style (fixtures module, lazy
secrets, guarded live mode) — mirrors the Defender O365 / GWS suites.

Coverage:
- Mock KQL semantics: table routing on the leading token, quoted-literal
  narrowing, unknown-table error envelope, limit.
- Alert list severity / status filtering.
- Machine lookup + not-found envelope.
- Isolation action: HITL flag always set, isolation-type validation,
  not-found error.
- Cross-surface joins: alerts ↔ machines on deviceId, hunting rows ↔
  machines on DeviceName.
- Live mode refuses without a client secret; secret redaction; lazy secret
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
from btagent_agents.mcp.servers._defender_endpoint_fixtures import (
    MDE_FIXTURE_ALERTS,
    MDE_FIXTURE_HUNTING_TABLES,
    MDE_FIXTURE_MACHINES,
)
from btagent_agents.mcp.servers.defender_endpoint_mcp import (
    DefenderEndpointMCPServer,
    _kql_literals,
    _kql_table,
    _redact_secret,
)


def _server() -> DefenderEndpointMCPServer:
    return DefenderEndpointMCPServer(mock_mode=True)


# ---------------------------------------------------------------------------
# KQL helpers (pure)
# ---------------------------------------------------------------------------


class TestKqlHelpers:
    def test_table_is_first_token(self) -> None:
        assert _kql_table('DeviceProcessEvents | where FileName == "x"') == "DeviceProcessEvents"

    def test_table_handles_no_space_pipe(self) -> None:
        assert _kql_table("DeviceLogonEvents|take 5") == "DeviceLogonEvents"

    def test_table_empty_query(self) -> None:
        assert _kql_table("") == ""

    def test_literals_extracted_in_order(self) -> None:
        q = 'T | where A == "one" and B has "two"'
        assert _kql_literals(q) == ["one", "two"]

    def test_no_literals(self) -> None:
        assert _kql_literals("DeviceProcessEvents | take 10") == []


# ---------------------------------------------------------------------------
# Advanced Hunting mock
# ---------------------------------------------------------------------------


class TestAdvancedHunting:
    async def test_bare_table_returns_all_rows(self) -> None:
        out = await _server().mde_advanced_hunting_query("DeviceProcessEvents")
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["table"] == "DeviceProcessEvents"
        assert out["total"] == len(MDE_FIXTURE_HUNTING_TABLES["DeviceProcessEvents"])

    async def test_quoted_literal_narrows_rows(self) -> None:
        out = await _server().mde_advanced_hunting_query(
            'DeviceProcessEvents | where DeviceName == "SRV-APP-01"'
        )
        assert out["total"] == 1
        assert out["rows"][0]["DeviceName"] == "SRV-APP-01"
        assert out["applied_literal_filters"] == ["srv-app-01"]

    async def test_multiple_literals_are_conjunctive(self) -> None:
        out = await _server().mde_advanced_hunting_query(
            'DeviceProcessEvents | where DeviceName == "WS-FINANCE-07" '
            'and FileName == "rundll32.exe"'
        )
        assert out["total"] == 1
        assert out["rows"][0]["FileName"] == "rundll32.exe"

    async def test_network_events_beacon_rows(self) -> None:
        out = await _server().mde_advanced_hunting_query(
            'DeviceNetworkEvents | where RemoteIP == "198.51.100.44"'
        )
        assert out["total"] == 2
        assert all(r["RemoteUrl"] == "update-cdn.example.org" for r in out["rows"])

    async def test_unknown_table_error_envelope(self) -> None:
        out = await _server().mde_advanced_hunting_query("DeviceFileEvents | take 5")
        assert out["status"] == "unknown_table"
        assert "DeviceProcessEvents" in out["message"]

    async def test_limit_caps_rows(self) -> None:
        out = await _server().mde_advanced_hunting_query("DeviceProcessEvents", limit=1)
        assert out["total"] == 1

    async def test_timespan_echoed(self) -> None:
        out = await _server().mde_advanced_hunting_query("DeviceLogonEvents", timespan="P7D")
        assert out["timespan"] == "P7D"


# ---------------------------------------------------------------------------
# Alerts mock
# ---------------------------------------------------------------------------


class TestAlerts:
    async def test_all_returns_every_alert(self) -> None:
        out = await _server().mde_list_alerts()
        assert out["total"] == len(MDE_FIXTURE_ALERTS)

    async def test_severity_is_minimum_threshold(self) -> None:
        out = await _server().mde_list_alerts(severity="medium")
        assert out["total"] == 2
        assert all(a["severity"] in ("medium", "high") for a in out["alerts"])

    async def test_status_filter_exact(self) -> None:
        out = await _server().mde_list_alerts(status="new")
        assert out["total"] == 1
        assert out["alerts"][0]["category"] == "CredentialAccess"

    async def test_severity_and_status_compose(self) -> None:
        out = await _server().mde_list_alerts(severity="medium", status="resolved")
        assert out["total"] == 0

    async def test_limit_caps_alerts(self) -> None:
        out = await _server().mde_list_alerts(limit=1)
        assert out["total"] == 1


# ---------------------------------------------------------------------------
# Machines + isolation mock
# ---------------------------------------------------------------------------


class TestMachines:
    async def test_get_machine_success(self) -> None:
        out = await _server().mde_get_machine("WS-FINANCE-07")
        assert out["status"] == "success"
        assert out["machine"]["riskScore"] == "High"

    async def test_get_machine_not_found(self) -> None:
        out = await _server().mde_get_machine("WS-GHOST-99")
        assert out["status"] == "not_found"

    async def test_isolate_requires_hitl(self) -> None:
        out = await _server().mde_isolate_machine("WS-FINANCE-07")
        assert out["status"] == "success"
        assert out["requires_hitl"] is True
        assert out["isolation_type"] == "selective"
        assert out["machine_id"] == MDE_FIXTURE_MACHINES["WS-FINANCE-07"]["id"]

    async def test_isolate_full_mode(self) -> None:
        out = await _server().mde_isolate_machine("WS-FINANCE-07", isolation_type="full")
        assert out["status"] == "success" and out["isolation_type"] == "full"

    async def test_isolate_invalid_type_errors(self) -> None:
        out = await _server().mde_isolate_machine("WS-FINANCE-07", isolation_type="cosmic")
        assert out["status"] == "error"

    async def test_isolate_unknown_machine_errors(self) -> None:
        out = await _server().mde_isolate_machine("WS-GHOST-99")
        assert out["status"] == "error"


# ---------------------------------------------------------------------------
# Cross-surface joins
# ---------------------------------------------------------------------------


class TestJoinDiscipline:
    def test_alerts_join_machines_on_device_id(self) -> None:
        machine_ids = {m["id"] for m in MDE_FIXTURE_MACHINES.values()}
        for alert in MDE_FIXTURE_ALERTS:
            assert alert["deviceId"] in machine_ids

    def test_hunting_rows_join_machines_on_device_name(self) -> None:
        names = set(MDE_FIXTURE_MACHINES)
        for rows in MDE_FIXTURE_HUNTING_TABLES.values():
            for row in rows:
                assert row["DeviceName"] in names

    async def test_story_coheres_alert_to_process_row(self) -> None:
        """The LSASS alert's evidence hash appears in DeviceProcessEvents."""
        lsass_alert = MDE_FIXTURE_ALERTS[0]
        sha = lsass_alert["evidence"][0]["sha256"]
        out = await _server().mde_advanced_hunting_query(
            f'DeviceProcessEvents | where SHA256 == "{sha}"'
        )
        assert out["total"] == 1
        assert out["rows"][0]["DeviceName"] == lsass_alert["computerDnsName"]


# ---------------------------------------------------------------------------
# Live mode refuses without a client secret
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutSecret:
    async def test_live_mode_without_secret_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_MDE_CLIENT_SECRET", raising=False)
        server = DefenderEndpointMCPServer(
            mock_mode=False, client_secret_ref="${env:BTAGENT_MDE_CLIENT_SECRET}"
        )
        with pytest.raises(NotImplementedError):
            await server.mde_advanced_hunting_query("DeviceProcessEvents")
        with pytest.raises(NotImplementedError):
            await server.mde_list_alerts()
        with pytest.raises(NotImplementedError):
            await server.mde_get_machine("WS-FINANCE-07")
        with pytest.raises(NotImplementedError):
            await server.mde_isolate_machine("WS-FINANCE-07")

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_MDE_CLIENT_SECRET", "mde-secret-0123456789abcdef")
        server = DefenderEndpointMCPServer(
            mock_mode=False, client_secret_ref="${env:BTAGENT_MDE_CLIENT_SECRET}"
        )
        with pytest.raises(NotImplementedError):
            await server.mde_advanced_hunting_query("DeviceProcessEvents")


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = DefenderEndpointMCPServer(
            mock_mode=False, client_secret_ref="${env:BTAGENT_MDE_CLIENT_SECRET}"
        )
        assert "mde-secret" not in repr(server)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("mde-secret-0123456789abcdef")
        assert out.startswith("[redacted:mde-client-secret:")
        assert "mde-secret" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BTAGENT_MDE_CLIENT_SECRET", "mde-secret-0123456789abcdef")
        server = DefenderEndpointMCPServer(
            mock_mode=False, client_secret_ref="${env:BTAGENT_MDE_CLIENT_SECRET}"
        )
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.defender_endpoint"):
            with pytest.raises(NotImplementedError):
                await server.mde_advanced_hunting_query("DeviceProcessEvents")
        for record in caplog.records:
            assert "mde-secret-0123456789abcdef" not in record.getMessage()


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
            name="defender_endpoint",
            description="defender_endpoint test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection(
            "defender_endpoint", config=cfg, consumer_id="inv_test"
        )
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("defender_endpoint", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_mde_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "defender_endpoint" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["defender_endpoint"] is DefenderEndpointMCPServer

    def test_tool_metadata_marks_mde_server(self) -> None:
        meta = _server().get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "mde_advanced_hunting_query",
            "mde_list_alerts",
            "mde_get_machine",
            "mde_isolate_machine",
        }
        assert all(m["server_id"] == "defender_endpoint" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.defender_endpoint_mcp.resolve_secret", _spy)
    DefenderEndpointMCPServer(mock_mode=False)
    assert calls == []
