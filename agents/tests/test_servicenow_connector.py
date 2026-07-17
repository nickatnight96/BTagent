"""Unit tests for the ServiceNow SecOps MCP connector (#100 Tier-2 slice).

Third Tier-2 connector and second ticketing sink — a stateful write surface,
so the suite exercises the mock ledger lifecycle end-to-end (create → work
note → state transition → read) plus the seeded fixtures, mirroring the Jira
suite's hygiene coverage.

Coverage:
- Create: SIR number allocation, field capture, blank-short-description and
  invalid-priority validation.
- Work notes: append + count, blank-note validation, unknown number.
- State machine: the full happy path through the SIR lifecycle, illegal-move
  error naming the legal transitions, reopen from closed, history recording.
- Read-back: seeded fixtures, not-found envelope.
- Live mode refuses without an API password; secret redaction; lazy secret
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
from btagent_agents.mcp.servers.servicenow_mcp import (
    MOCK_SIR_LEDGER,
    SIR_TRANSITIONS,
    ServiceNowMCPServer,
    _redact_secret,
    reset_mock_ledger,
)


@pytest.fixture(autouse=True)
def _fresh_ledger() -> None:
    """Every test starts from the seeded two-incident fixture state."""
    reset_mock_ledger()


def _server() -> ServiceNowMCPServer:
    return ServiceNowMCPServer(mock_mode=True)


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


class TestCreateIncident:
    async def test_create_allocates_number(self) -> None:
        out = await _server().snow_create_security_incident(
            "Compromised access key ci-deploy",
            description="Stolen key used from 198.51.100.200",
            priority="1-critical",
            investigation_id="inv_test_001",
            category="credential_theft",
        )
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["number"] == "SIR0010003"
        record = out["record"]
        assert record["state"] == "analysis"
        assert record["priority"] == "1-critical"
        assert record["investigation_id"] == "inv_test_001"
        assert out["number"] in MOCK_SIR_LEDGER

    async def test_numbers_increment(self) -> None:
        first = await _server().snow_create_security_incident("First")
        second = await _server().snow_create_security_incident("Second")
        assert first["number"] == "SIR0010003"
        assert second["number"] == "SIR0010004"

    async def test_blank_short_description_rejected(self) -> None:
        out = await _server().snow_create_security_incident("   ")
        assert out["status"] == "error"
        assert "short_description" in out["message"]

    async def test_invalid_priority_rejected(self) -> None:
        out = await _server().snow_create_security_incident("X", priority="9-apocalyptic")
        assert out["status"] == "error"


# ---------------------------------------------------------------------------
# Work notes
# ---------------------------------------------------------------------------


class TestWorkNotes:
    async def test_note_appends_and_counts(self) -> None:
        out = await _server().snow_add_work_note(
            "SIR0010002", "Endpoint isolation approved and applied."
        )
        assert out["status"] == "success"
        assert out["work_note_count"] == 1
        assert MOCK_SIR_LEDGER["SIR0010002"]["work_notes"][0]["note"].startswith(
            "Endpoint isolation"
        )

    async def test_blank_note_rejected(self) -> None:
        out = await _server().snow_add_work_note("SIR0010002", "  ")
        assert out["status"] == "error"

    async def test_unknown_number_not_found(self) -> None:
        out = await _server().snow_add_work_note("SIR0019999", "hello")
        assert out["status"] == "not_found"


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------


class TestStateMachine:
    async def test_full_happy_path(self) -> None:
        server = _server()
        created = await server.snow_create_security_incident("Lifecycle test")
        number = created["number"]
        for transition, expected in (
            ("contain", "contain"),
            ("eradicate", "eradicate"),
            ("recover", "recover"),
            ("review", "review"),
            ("close", "closed"),
        ):
            out = await server.snow_update_state(number, transition)
            assert out["status"] == "success", out
            assert out["new_state"] == expected
        assert MOCK_SIR_LEDGER[number]["history"] == [
            "contain",
            "eradicate",
            "recover",
            "review",
            "close",
        ]

    async def test_illegal_move_names_legal_transitions(self) -> None:
        # SIR0010002 is in "contain": "close" is illegal, "eradicate" is the move.
        out = await _server().snow_update_state("SIR0010002", "close")
        assert out["status"] == "error"
        assert "eradicate" in out["message"]

    async def test_reopen_from_closed(self) -> None:
        out = await _server().snow_update_state("SIR0010001", "reopen")
        assert out["status"] == "success"
        assert out["previous_state"] == "closed"
        assert out["new_state"] == "analysis"

    async def test_unknown_transition_rejected(self) -> None:
        out = await _server().snow_update_state("SIR0010002", "teleport")
        assert out["status"] == "error"

    async def test_unknown_number_not_found(self) -> None:
        out = await _server().snow_update_state("SIR0019999", "contain")
        assert out["status"] == "not_found"

    def test_state_machine_targets_are_reachable_states(self) -> None:
        sources = {s for srcs, _t in SIR_TRANSITIONS.values() for s in srcs}
        targets = {t for _srcs, t in SIR_TRANSITIONS.values()}
        # Every target except the terminal "closed" can move again.
        assert targets - {"closed"} <= sources


# ---------------------------------------------------------------------------
# Read-back
# ---------------------------------------------------------------------------


class TestGetIncident:
    async def test_seeded_fixture_readable(self) -> None:
        out = await _server().snow_get_security_incident("SIR0010001")
        assert out["status"] == "success"
        assert out["record"]["state"] == "closed"
        assert out["record"]["history"] == [
            "contain",
            "eradicate",
            "recover",
            "review",
            "close",
        ]

    async def test_created_record_round_trips(self) -> None:
        server = _server()
        created = await server.snow_create_security_incident("Round trip", category="phishing")
        out = await server.snow_get_security_incident(created["number"])
        assert out["status"] == "success"
        assert out["record"]["short_description"] == "Round trip"

    async def test_unknown_number_not_found(self) -> None:
        out = await _server().snow_get_security_incident("SIR0019999")
        assert out["status"] == "not_found"


# ---------------------------------------------------------------------------
# Live mode refuses without an API password
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutPassword:
    async def test_live_mode_without_password_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_SERVICENOW_PASSWORD", raising=False)
        server = ServiceNowMCPServer(
            mock_mode=False, password_ref="${env:BTAGENT_SERVICENOW_PASSWORD}"
        )
        with pytest.raises(NotImplementedError):
            await server.snow_create_security_incident("x")
        with pytest.raises(NotImplementedError):
            await server.snow_add_work_note("SIR0010002", "x")
        with pytest.raises(NotImplementedError):
            await server.snow_update_state("SIR0010002", "eradicate")
        with pytest.raises(NotImplementedError):
            await server.snow_get_security_incident("SIR0010002")

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_SERVICENOW_PASSWORD", "snow-pass-0123456789abcdef")
        server = ServiceNowMCPServer(
            mock_mode=False, password_ref="${env:BTAGENT_SERVICENOW_PASSWORD}"
        )
        with pytest.raises(NotImplementedError):
            await server.snow_create_security_incident("x")


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = ServiceNowMCPServer(
            mock_mode=False, password_ref="${env:BTAGENT_SERVICENOW_PASSWORD}"
        )
        assert "snow-pass" not in repr(server)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("snow-pass-0123456789abcdef")
        assert out.startswith("[redacted:servicenow-password:")
        assert "snow-pass-0123456789" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BTAGENT_SERVICENOW_PASSWORD", "snow-pass-0123456789abcdef")
        server = ServiceNowMCPServer(
            mock_mode=False, password_ref="${env:BTAGENT_SERVICENOW_PASSWORD}"
        )
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.servicenow"):
            with pytest.raises(NotImplementedError):
                await server.snow_create_security_incident("x")
        for record in caplog.records:
            assert "snow-pass-0123456789abcdef" not in record.getMessage()


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
            name="servicenow",
            description="servicenow test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("servicenow", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("servicenow", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_servicenow_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "servicenow" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["servicenow"] is ServiceNowMCPServer

    def test_tool_metadata_marks_servicenow_server(self) -> None:
        meta = _server().get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "snow_create_security_incident",
            "snow_add_work_note",
            "snow_update_state",
            "snow_get_security_incident",
        }
        assert all(m["server_id"] == "servicenow" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.servicenow_mcp.resolve_secret", _spy)
    ServiceNowMCPServer(mock_mode=False)
    assert calls == []
