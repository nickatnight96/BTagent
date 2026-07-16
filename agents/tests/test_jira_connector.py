"""Unit tests for the Jira Service Management MCP connector (#100 Tier-1 slice).

First ticketing connector — a stateful write surface, so the suite exercises
the mock ledger lifecycle end-to-end (create → comment → transition → read)
plus the seeded fixtures, mirroring the sibling suites' hygiene coverage.

Coverage:
- Create: key allocation in the configured project, field capture, blank-
  summary and invalid-severity validation.
- Comment: append + count, blank-body validation, unknown key.
- Transitions: the full happy path through the state machine, illegal-move
  error naming the legal transitions, reopen from closed, history recording.
- Read-back: seeded fixtures, not-found envelope.
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
from btagent_agents.mcp.servers.jira_mcp import (
    JIRA_TRANSITIONS,
    MOCK_TICKET_LEDGER,
    JiraMCPServer,
    _redact_secret,
    reset_mock_ledger,
)


@pytest.fixture(autouse=True)
def _fresh_ledger() -> None:
    """Every test starts from the seeded two-ticket fixture state."""
    reset_mock_ledger()


def _server() -> JiraMCPServer:
    return JiraMCPServer(mock_mode=True)


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


class TestCreateIncident:
    async def test_create_allocates_key_in_project(self) -> None:
        out = await _server().jira_create_incident(
            "Compromised access key ci-deploy",
            description="Stolen key used from 198.51.100.200",
            severity="critical",
            investigation_id="inv_test_001",
            labels=["cloud", "credential-theft"],
        )
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["issue_key"] == "SEC-102"
        ticket = out["ticket"]
        assert ticket["status"] == "new"
        assert ticket["severity"] == "critical"
        assert ticket["investigation_id"] == "inv_test_001"
        assert out["issue_key"] in MOCK_TICKET_LEDGER

    async def test_keys_increment(self) -> None:
        first = await _server().jira_create_incident("First")
        second = await _server().jira_create_incident("Second")
        assert first["issue_key"] == "SEC-102"
        assert second["issue_key"] == "SEC-103"

    async def test_blank_summary_rejected(self) -> None:
        out = await _server().jira_create_incident("   ")
        assert out["status"] == "error"
        assert "summary" in out["message"]

    async def test_invalid_severity_rejected(self) -> None:
        out = await _server().jira_create_incident("X", severity="apocalyptic")
        assert out["status"] == "error"

    async def test_custom_project_key(self) -> None:
        server = JiraMCPServer(mock_mode=True, project_key="IR")
        out = await server.jira_create_incident("Custom project")
        assert out["issue_key"].startswith("IR-")


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------


class TestComments:
    async def test_comment_appends_and_counts(self) -> None:
        out = await _server().jira_add_comment("SEC-101", "Purge completed for 2 of 3 mailboxes.")
        assert out["status"] == "success"
        assert out["comment_count"] == 1
        assert MOCK_TICKET_LEDGER["SEC-101"]["comments"][0]["body"].startswith("Purge completed")

    async def test_blank_body_rejected(self) -> None:
        out = await _server().jira_add_comment("SEC-101", "  ")
        assert out["status"] == "error"

    async def test_unknown_key_not_found(self) -> None:
        out = await _server().jira_add_comment("SEC-999", "hello")
        assert out["status"] == "not_found"


# ---------------------------------------------------------------------------
# Transitions
# ---------------------------------------------------------------------------


class TestTransitions:
    async def test_full_happy_path(self) -> None:
        server = _server()
        created = await server.jira_create_incident("Lifecycle test")
        key = created["issue_key"]
        for transition, expected in (
            ("start", "in_progress"),
            ("resolve", "resolved"),
            ("close", "closed"),
        ):
            out = await server.jira_transition_issue(key, transition)
            assert out["status"] == "success", out
            assert out["new_status"] == expected
        assert MOCK_TICKET_LEDGER[key]["history"] == ["start", "resolve", "close"]

    async def test_illegal_move_names_legal_transitions(self) -> None:
        # SEC-101 is in_progress: "close" is illegal, "resolve" is the move.
        out = await _server().jira_transition_issue("SEC-101", "close")
        assert out["status"] == "error"
        assert "resolve" in out["message"]

    async def test_reopen_from_closed(self) -> None:
        out = await _server().jira_transition_issue("SEC-100", "reopen")
        assert out["status"] == "success"
        assert out["previous_status"] == "closed"
        assert out["new_status"] == "in_progress"

    async def test_unknown_transition_rejected(self) -> None:
        out = await _server().jira_transition_issue("SEC-101", "teleport")
        assert out["status"] == "error"

    async def test_unknown_key_not_found(self) -> None:
        out = await _server().jira_transition_issue("SEC-999", "start")
        assert out["status"] == "not_found"

    def test_state_machine_targets_are_reachable_statuses(self) -> None:
        sources = {s for srcs, _t in JIRA_TRANSITIONS.values() for s in srcs}
        targets = {t for _srcs, t in JIRA_TRANSITIONS.values()}
        # Every target except the terminal "closed" can move again.
        assert targets - {"closed"} <= sources


# ---------------------------------------------------------------------------
# Read-back
# ---------------------------------------------------------------------------


class TestGetIssue:
    async def test_seeded_fixture_readable(self) -> None:
        out = await _server().jira_get_issue("SEC-100")
        assert out["status"] == "success"
        assert out["ticket"]["status"] == "closed"
        assert out["ticket"]["history"] == ["start", "resolve", "close"]

    async def test_created_ticket_round_trips(self) -> None:
        server = _server()
        created = await server.jira_create_incident("Round trip", labels=["x"])
        out = await server.jira_get_issue(created["issue_key"])
        assert out["status"] == "success"
        assert out["ticket"]["summary"] == "Round trip"

    async def test_unknown_key_not_found(self) -> None:
        out = await _server().jira_get_issue("SEC-999")
        assert out["status"] == "not_found"


# ---------------------------------------------------------------------------
# Live mode refuses without an API token
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutToken:
    async def test_live_mode_without_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_JIRA_API_TOKEN", raising=False)
        server = JiraMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_JIRA_API_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.jira_create_incident("x")
        with pytest.raises(NotImplementedError):
            await server.jira_add_comment("SEC-101", "x")
        with pytest.raises(NotImplementedError):
            await server.jira_transition_issue("SEC-101", "resolve")
        with pytest.raises(NotImplementedError):
            await server.jira_get_issue("SEC-101")

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_JIRA_API_TOKEN", "jira-token-0123456789abcdef")
        server = JiraMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_JIRA_API_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.jira_create_incident("x")


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = JiraMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_JIRA_API_TOKEN}")
        assert "jira-token" not in repr(server)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("jira-token-0123456789abcdef")
        assert out.startswith("[redacted:jira-api-token:")
        assert "jira-token-0123456789" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BTAGENT_JIRA_API_TOKEN", "jira-token-0123456789abcdef")
        server = JiraMCPServer(mock_mode=False, api_token_ref="${env:BTAGENT_JIRA_API_TOKEN}")
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.jira"):
            with pytest.raises(NotImplementedError):
                await server.jira_create_incident("x")
        for record in caplog.records:
            assert "jira-token-0123456789abcdef" not in record.getMessage()


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
            name="jira",
            description="jira test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("jira", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("jira", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_jira_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "jira" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["jira"] is JiraMCPServer

    def test_tool_metadata_marks_jira_server(self) -> None:
        meta = _server().get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "jira_create_incident",
            "jira_add_comment",
            "jira_transition_issue",
            "jira_get_issue",
        }
        assert all(m["server_id"] == "jira" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.jira_mcp.resolve_secret", _spy)
    JiraMCPServer(mock_mode=False)
    assert calls == []
