"""Unit tests for the SentinelOne MCP connector (#100 Tier-1 slice).

Third EDR connector — mirrors the Defender for Endpoint suite so the modern
Tier-1 connectors stay exercised symmetrically.

Coverage:
- Mock S1QL semantics: conjunctive quoted-literal narrowing over the single
  Deep Visibility stream, time-window filtering, limit.
- Threat list incident-status / confidence filtering.
- Agent lookup + not-found envelope.
- Mitigation action: HITL flag always set, action validation, unknown-threat
  error.
- Cross-surface joins: threats ↔ agents ↔ Deep Visibility rows on agentId;
  story coherence (ransomware threat hash appears in process telemetry).
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
from btagent_agents.mcp.servers._sentinelone_fixtures import (
    S1_FIXTURE_AGENTS,
    S1_FIXTURE_DV_EVENTS,
    S1_FIXTURE_THREATS,
)
from btagent_agents.mcp.servers.sentinelone_mcp import (
    MITIGATION_ACTIONS,
    SentinelOneMCPServer,
    _redact_secret,
    _s1ql_literals,
)

# Fixture window covering every recorded Deep Visibility event.
WINDOW_START = "2026-06-15T00:00:00Z"
WINDOW_END = "2026-06-16T00:00:00Z"

RANSOM_THREAT_ID = "1400000000000000001"
PUA_THREAT_ID = "1400000000000000002"


def _server() -> SentinelOneMCPServer:
    return SentinelOneMCPServer(mock_mode=True)


# ---------------------------------------------------------------------------
# S1QL helpers (pure)
# ---------------------------------------------------------------------------


class TestS1qlHelpers:
    def test_literals_extracted_in_order(self) -> None:
        q = 'EventType = "IP Connect" AND DstIP = "198.51.100.99"'
        assert _s1ql_literals(q) == ["IP Connect", "198.51.100.99"]

    def test_no_literals(self) -> None:
        assert _s1ql_literals("EventType = ProcessCreation") == []


# ---------------------------------------------------------------------------
# Deep Visibility mock
# ---------------------------------------------------------------------------


class TestDeepVisibility:
    async def test_bare_query_returns_all_in_window(self) -> None:
        out = await _server().s1_deep_visibility_query("", WINDOW_START, WINDOW_END)
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["total"] == len(S1_FIXTURE_DV_EVENTS)

    async def test_quoted_literal_narrows_events(self) -> None:
        out = await _server().s1_deep_visibility_query(
            'EndpointName = "SRV-BUILD-02"', WINDOW_START, WINDOW_END
        )
        assert out["total"] == 1
        assert out["events"][0]["processName"] == "msbuild.exe"

    async def test_multiple_literals_are_conjunctive(self) -> None:
        out = await _server().s1_deep_visibility_query(
            'EventType = "IP Connect" AND DstIP = "198.51.100.99"',
            WINDOW_START,
            WINDOW_END,
        )
        assert out["total"] == 1
        assert out["events"][0]["dstPort"] == 443

    async def test_time_window_excludes_events(self) -> None:
        out = await _server().s1_deep_visibility_query(
            "", "2026-06-15T14:00:00Z", "2026-06-15T14:03:00Z"
        )
        # Only the two process creations and the DNS lookup fall in-window…
        # actually: 14:01:55, 14:02:30 in; 14:03:02, 14:03:05 out; 10:20 out.
        assert out["total"] == 2

    async def test_limit_caps_events(self) -> None:
        out = await _server().s1_deep_visibility_query("", WINDOW_START, WINDOW_END, limit=2)
        assert out["total"] == 2

    async def test_vssadmin_story_row_present(self) -> None:
        out = await _server().s1_deep_visibility_query('"vssadmin.exe"', WINDOW_START, WINDOW_END)
        assert out["total"] == 1
        assert out["events"][0]["parentProcessName"] == "pennysvc.exe"


# ---------------------------------------------------------------------------
# Threats mock
# ---------------------------------------------------------------------------


class TestThreats:
    async def test_all_returns_every_threat(self) -> None:
        out = await _server().s1_list_threats()
        assert out["total"] == len(S1_FIXTURE_THREATS)

    async def test_incident_status_filter(self) -> None:
        out = await _server().s1_list_threats(incident_status="unresolved")
        assert out["total"] == 1
        assert out["threats"][0]["threatInfo"]["classification"] == "Ransomware"

    async def test_confidence_filter(self) -> None:
        out = await _server().s1_list_threats(confidence="suspicious")
        assert out["total"] == 1
        assert out["threats"][0]["threatInfo"]["classification"] == "PUA"

    async def test_filters_compose(self) -> None:
        out = await _server().s1_list_threats(incident_status="resolved", confidence="malicious")
        assert out["total"] == 0

    async def test_limit_caps_threats(self) -> None:
        out = await _server().s1_list_threats(limit=1)
        assert out["total"] == 1


# ---------------------------------------------------------------------------
# Agents + mitigation mock
# ---------------------------------------------------------------------------


class TestAgents:
    async def test_get_agent_success(self) -> None:
        out = await _server().s1_get_agent("LAPTOP-DESIGN-03")
        assert out["status"] == "success"
        assert out["agent"]["infected"] is True

    async def test_get_agent_not_found(self) -> None:
        out = await _server().s1_get_agent("WS-GHOST-99")
        assert out["status"] == "not_found"

    async def test_mitigate_requires_hitl(self) -> None:
        out = await _server().s1_mitigate_threat(RANSOM_THREAT_ID, action="kill")
        assert out["status"] == "success"
        assert out["requires_hitl"] is True
        assert out["action"] == "kill"
        assert out["hostname"] == "LAPTOP-DESIGN-03"

    async def test_mitigate_default_action_is_quarantine(self) -> None:
        out = await _server().s1_mitigate_threat(RANSOM_THREAT_ID)
        assert out["status"] == "success" and out["action"] == "quarantine"

    async def test_mitigate_invalid_action_errors(self) -> None:
        out = await _server().s1_mitigate_threat(RANSOM_THREAT_ID, action="obliterate")
        assert out["status"] == "error"
        for valid in MITIGATION_ACTIONS:
            assert valid in out["message"]

    async def test_mitigate_unknown_threat_errors(self) -> None:
        out = await _server().s1_mitigate_threat("999")
        assert out["status"] == "error"


# ---------------------------------------------------------------------------
# Cross-surface joins
# ---------------------------------------------------------------------------


class TestJoinDiscipline:
    def test_threats_join_agents_on_agent_id(self) -> None:
        agent_ids = {a["id"] for a in S1_FIXTURE_AGENTS.values()}
        for threat in S1_FIXTURE_THREATS:
            assert threat["agentRealtimeInfo"]["agentId"] in agent_ids

    def test_dv_rows_join_agents_on_agent_id(self) -> None:
        agent_ids = {a["id"] for a in S1_FIXTURE_AGENTS.values()}
        for row in S1_FIXTURE_DV_EVENTS:
            assert row["agentId"] in agent_ids

    async def test_story_coheres_threat_to_process_row(self) -> None:
        """The ransomware threat's hash appears in Deep Visibility telemetry."""
        sha = S1_FIXTURE_THREATS[0]["threatInfo"]["sha256"]
        out = await _server().s1_deep_visibility_query(
            f'Sha256 = "{sha}"', WINDOW_START, WINDOW_END
        )
        assert out["total"] == 1
        assert (
            out["events"][0]["endpointName"]
            == S1_FIXTURE_THREATS[0]["agentRealtimeInfo"]["agentComputerName"]
        )

    def test_infected_flag_matches_unresolved_threat(self) -> None:
        """The agent carrying the unmitigated threat is flagged infected."""
        assert S1_FIXTURE_AGENTS["LAPTOP-DESIGN-03"]["infected"] is True
        assert S1_FIXTURE_AGENTS["SRV-BUILD-02"]["infected"] is False


# ---------------------------------------------------------------------------
# Live mode refuses without an API token
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutToken:
    async def test_live_mode_without_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_S1_API_TOKEN", raising=False)
        server = SentinelOneMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_S1_API_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.s1_deep_visibility_query("", WINDOW_START, WINDOW_END)
        with pytest.raises(NotImplementedError):
            await server.s1_list_threats()
        with pytest.raises(NotImplementedError):
            await server.s1_get_agent("LAPTOP-DESIGN-03")
        with pytest.raises(NotImplementedError):
            await server.s1_mitigate_threat(RANSOM_THREAT_ID)

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_S1_API_TOKEN", "s1-token-0123456789abcdef")
        server = SentinelOneMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_S1_API_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.s1_list_threats()


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = SentinelOneMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_S1_API_TOKEN}")
        assert "s1-token" not in repr(server)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("s1-token-0123456789abcdef")
        assert out.startswith("[redacted:s1-api-token:")
        assert "s1-token-0123456789" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BTAGENT_S1_API_TOKEN", "s1-token-0123456789abcdef")
        server = SentinelOneMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_S1_API_TOKEN}")
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.sentinelone"):
            with pytest.raises(NotImplementedError):
                await server.s1_deep_visibility_query("", WINDOW_START, WINDOW_END)
        for record in caplog.records:
            assert "s1-token-0123456789abcdef" not in record.getMessage()


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
            name="sentinelone",
            description="sentinelone test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("sentinelone", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("sentinelone", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_s1_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "sentinelone" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["sentinelone"] is SentinelOneMCPServer

    def test_tool_metadata_marks_s1_server(self) -> None:
        meta = _server().get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "s1_deep_visibility_query",
            "s1_list_threats",
            "s1_get_agent",
            "s1_mitigate_threat",
        }
        assert all(m["server_id"] == "sentinelone" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.sentinelone_mcp.resolve_secret", _spy)
    SentinelOneMCPServer(mock_mode=False)
    assert calls == []
