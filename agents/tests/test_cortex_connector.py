"""Unit tests for the Palo Alto Cortex XDR MCP connector (#100 Tier-2 slice).

Second Tier-2 connector — mirrors the SentinelOne suite so the XDR-class
connectors stay exercised symmetrically.

Coverage:
- Mock XQL semantics: conjunctive quoted-literal narrowing over the single
  event stream, time-window filtering, limit.
- Incident list status / severity filtering.
- Endpoint lookup + not-found envelope.
- Isolation action: HITL flag always set, action validation, unknown-endpoint
  error, isolate/unisolate state transition.
- Cross-surface joins: incidents ↔ endpoints ↔ XQL rows on endpoint_id;
  story coherence (C2 IP appears in both DNS response and network telemetry).
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
from btagent_agents.mcp.servers._cortex_fixtures import (
    C2_IP,
    CORTEX_FIXTURE_ENDPOINTS,
    CORTEX_FIXTURE_INCIDENTS,
    CORTEX_FIXTURE_XQL_EVENTS,
)
from btagent_agents.mcp.servers.cortex_mcp import (
    ISOLATION_ACTIONS,
    CortexXDRMCPServer,
    _redact_secret,
    _xql_literals,
)

# Fixture window covering every recorded XQL event.
WINDOW_START = "2026-07-02T00:00:00Z"
WINDOW_END = "2026-07-03T00:00:00Z"

C2_ENDPOINT_ID = "ep-1101"
CLEAN_ENDPOINT_ID = "ep-2202"


def _server() -> CortexXDRMCPServer:
    return CortexXDRMCPServer(mock_mode=True)


# ---------------------------------------------------------------------------
# XQL helpers (pure)
# ---------------------------------------------------------------------------


class TestXqlHelpers:
    def test_literals_extracted_in_order(self) -> None:
        q = 'action_process_image_name = "updater.exe" and action_remote_ip = "45.77.10.204"'
        assert _xql_literals(q) == ["updater.exe", "45.77.10.204"]

    def test_no_literals(self) -> None:
        assert _xql_literals("event_type = PROCESS") == []


# ---------------------------------------------------------------------------
# XQL mock
# ---------------------------------------------------------------------------


class TestXqlQuery:
    async def test_bare_query_returns_all_in_window(self) -> None:
        out = await _server().cortex_xql_query("", WINDOW_START, WINDOW_END)
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["total"] == len(CORTEX_FIXTURE_XQL_EVENTS)

    async def test_quoted_literal_narrows_events(self) -> None:
        out = await _server().cortex_xql_query(
            'endpoint_name = "SRV-DB-11"', WINDOW_START, WINDOW_END
        )
        assert out["total"] == 1
        assert out["events"][0]["action_process_image_name"] == "sqlservr.exe"

    async def test_multiple_literals_are_conjunctive(self) -> None:
        # "51884" (the ephemeral local port) is unique to the NETWORK row, so
        # pairing it with the C2 IP selects exactly that connection.
        out = await _server().cortex_xql_query(
            'action_remote_ip = "45.77.10.204" and action_local_port = "51884"',
            WINDOW_START,
            WINDOW_END,
        )
        assert out["total"] == 1
        assert out["events"][0]["action_remote_port"] == 443

    async def test_time_window_excludes_events(self) -> None:
        # Only the 08:xx WIN10-FIN-07 rows fall in-window; the 06:00 SRV row is out.
        out = await _server().cortex_xql_query("", "2026-07-02T08:00:00Z", "2026-07-02T09:00:00Z")
        assert out["total"] == 4

    async def test_limit_caps_events(self) -> None:
        out = await _server().cortex_xql_query("", WINDOW_START, WINDOW_END, limit=2)
        assert out["total"] == 2

    async def test_c2_beacon_row_present(self) -> None:
        out = await _server().cortex_xql_query(f'"{C2_IP}"', WINDOW_START, WINDOW_END)
        # C2 IP appears in both the DNS response and the network connection row.
        assert out["total"] == 2


# ---------------------------------------------------------------------------
# Incidents mock
# ---------------------------------------------------------------------------


class TestIncidents:
    async def test_all_returns_every_incident(self) -> None:
        out = await _server().cortex_list_incidents()
        assert out["total"] == len(CORTEX_FIXTURE_INCIDENTS)

    async def test_status_filter(self) -> None:
        out = await _server().cortex_list_incidents(status="new")
        assert out["total"] == 1
        assert out["incidents"][0]["host_name"] == "WIN10-FIN-07"

    async def test_severity_filter(self) -> None:
        out = await _server().cortex_list_incidents(severity="informational")
        assert out["total"] == 1
        assert out["incidents"][0]["host_name"] == "SRV-DB-11"

    async def test_filters_compose(self) -> None:
        out = await _server().cortex_list_incidents(status="resolved", severity="high")
        assert out["total"] == 0

    async def test_limit_caps_incidents(self) -> None:
        out = await _server().cortex_list_incidents(limit=1)
        assert out["total"] == 1


# ---------------------------------------------------------------------------
# Endpoints + isolation mock
# ---------------------------------------------------------------------------


class TestEndpoints:
    async def test_get_endpoint_success(self) -> None:
        out = await _server().cortex_get_endpoint("WIN10-FIN-07")
        assert out["status"] == "success"
        assert out["endpoint"]["endpoint_status"] == "CONNECTED"

    async def test_get_endpoint_not_found(self) -> None:
        out = await _server().cortex_get_endpoint("WS-GHOST-99")
        assert out["status"] == "not_found"

    async def test_isolate_requires_hitl(self) -> None:
        out = await _server().cortex_isolate_endpoint(C2_ENDPOINT_ID, action="isolate")
        assert out["status"] == "success"
        assert out["requires_hitl"] is True
        assert out["action"] == "isolate"
        assert out["endpoint_name"] == "WIN10-FIN-07"
        assert out["isolation_status"] == "AGENT_ISOLATED"

    async def test_isolate_default_action(self) -> None:
        out = await _server().cortex_isolate_endpoint(C2_ENDPOINT_ID)
        assert out["status"] == "success" and out["action"] == "isolate"

    async def test_unisolate_sets_unisolated_state(self) -> None:
        out = await _server().cortex_isolate_endpoint(C2_ENDPOINT_ID, action="unisolate")
        assert out["isolation_status"] == "AGENT_UNISOLATED"

    async def test_isolate_invalid_action_errors(self) -> None:
        out = await _server().cortex_isolate_endpoint(C2_ENDPOINT_ID, action="obliterate")
        assert out["status"] == "error"
        for valid in ISOLATION_ACTIONS:
            assert valid in out["message"]

    async def test_isolate_unknown_endpoint_errors(self) -> None:
        out = await _server().cortex_isolate_endpoint("ep-does-not-exist")
        assert out["status"] == "error"


# ---------------------------------------------------------------------------
# Cross-surface joins
# ---------------------------------------------------------------------------


class TestJoinDiscipline:
    def test_incidents_join_endpoints_on_endpoint_id(self) -> None:
        endpoint_ids = {e["endpoint_id"] for e in CORTEX_FIXTURE_ENDPOINTS.values()}
        for inc in CORTEX_FIXTURE_INCIDENTS:
            assert inc["endpoint_id"] in endpoint_ids

    def test_xql_rows_join_endpoints_on_endpoint_id(self) -> None:
        endpoint_ids = {e["endpoint_id"] for e in CORTEX_FIXTURE_ENDPOINTS.values()}
        for row in CORTEX_FIXTURE_XQL_EVENTS:
            assert row["endpoint_id"] in endpoint_ids

    async def test_story_coheres_dns_to_network(self) -> None:
        """The C2 IP resolved by DNS is the same one the beacon connects to."""
        out = await _server().cortex_xql_query(f'"{C2_IP}"', WINDOW_START, WINDOW_END)
        kinds = {e["event_type"] for e in out["events"]}
        assert kinds == {"DNS", "NETWORK"}
        assert all(e["endpoint_name"] == "WIN10-FIN-07" for e in out["events"])

    def test_new_incident_host_matches_c2_endpoint(self) -> None:
        new_inc = next(i for i in CORTEX_FIXTURE_INCIDENTS if i["status"] == "new")
        assert new_inc["endpoint_id"] == C2_ENDPOINT_ID
        assert CORTEX_FIXTURE_ENDPOINTS["WIN10-FIN-07"]["endpoint_id"] == C2_ENDPOINT_ID


# ---------------------------------------------------------------------------
# Live mode refuses without an API key
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutKey:
    async def test_live_mode_without_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_CORTEX_API_KEY", raising=False)
        server = CortexXDRMCPServer(mock_mode=False, api_key_ref="${env:BTAGENT_CORTEX_API_KEY}")
        with pytest.raises(NotImplementedError):
            await server.cortex_xql_query("", WINDOW_START, WINDOW_END)
        with pytest.raises(NotImplementedError):
            await server.cortex_list_incidents()
        with pytest.raises(NotImplementedError):
            await server.cortex_get_endpoint("WIN10-FIN-07")
        with pytest.raises(NotImplementedError):
            await server.cortex_isolate_endpoint(C2_ENDPOINT_ID)

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_CORTEX_API_KEY", "cortex-key-0123456789abcdef")
        server = CortexXDRMCPServer(mock_mode=False, api_key_ref="${env:BTAGENT_CORTEX_API_KEY}")
        with pytest.raises(NotImplementedError):
            await server.cortex_list_incidents()


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = CortexXDRMCPServer(mock_mode=False, api_key_ref="${env:BTAGENT_CORTEX_API_KEY}")
        assert "cortex-key" not in repr(server)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("cortex-key-0123456789abcdef")
        assert out.startswith("[redacted:cortex-api-key:")
        assert "cortex-key-0123456789" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BTAGENT_CORTEX_API_KEY", "cortex-key-0123456789abcdef")
        server = CortexXDRMCPServer(mock_mode=False, api_key_ref="${env:BTAGENT_CORTEX_API_KEY}")
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.cortex"):
            with pytest.raises(NotImplementedError):
                await server.cortex_xql_query("", WINDOW_START, WINDOW_END)
        for record in caplog.records:
            assert "cortex-key-0123456789abcdef" not in record.getMessage()


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
            name="cortex",
            description="cortex test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("cortex", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("cortex", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_cortex_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "cortex" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["cortex"] is CortexXDRMCPServer

    def test_tool_metadata_marks_cortex_server(self) -> None:
        meta = _server().get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "cortex_xql_query",
            "cortex_list_incidents",
            "cortex_get_endpoint",
            "cortex_isolate_endpoint",
        }
        assert all(m["server_id"] == "cortex" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.cortex_mcp.resolve_secret", _spy)
    CortexXDRMCPServer(mock_mode=False)
    assert calls == []
