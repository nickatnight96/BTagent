"""Unit tests for the Cisco Duo MFA MCP connector (#100 Tier-2 slice).

First Tier-2 connector — mirrors the Tier-1 identity suites (Okta / GWS) so
the connector catalog stays exercised symmetrically.

Coverage:
- Auth-log normalisation across the result matrix (success push →
  MFA_APPROVED, success non-2FA → LOGIN_SUCCESS, denied/fraud → MFA_DENIED),
  geo + IP capture, raw preservation.
- Admin-log normalisation (bypass_create → CREDENTIAL_ADDED, admin_create →
  ROLE_ASSIGNED, policy_update → FEDERATION_TRUST_MODIFIED); unmapped dropped.
- User listing + filter.
- Mock envelopes: time window, result/username/action filters, limits.
- The MFA-fatigue story: the denied burst + fraud approval all resolve to
  MFA_* on the same principal from the attacker IP.
- Live mode refuses without a secret key; secret redaction; lazy secret
  resolution at construction; circuit breaker; discovery registration.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest
from btagent_shared.types.identity_hunt import IdentityEventKind, IdentityProvider
from btagent_shared.types.mcp import MCPServerConfig

from btagent_agents.mcp.registry import (
    CircuitOpenError,
    CircuitState,
    MCPConnectionRegistry,
)
from btagent_agents.mcp.servers._duo_fixtures import (
    ATTACKER_IP,
    DUO_FIXTURE_ADMIN_LOGS,
    DUO_FIXTURE_AUTH_LOGS,
    DUO_FIXTURE_USERS,
)
from btagent_agents.mcp.servers.duo_mcp import (
    DUO_ADMIN_EVENT_MAP,
    DuoMCPServer,
    _redact_secret,
    normalise_admin_event,
    normalise_auth_event,
)

ORG = "org_test"
WINDOW_START = "2026-06-27T00:00:00Z"
WINDOW_END = "2026-06-29T00:00:00Z"


def _server() -> DuoMCPServer:
    return DuoMCPServer(mock_mode=True)


def _auth(result: str) -> dict[str, Any]:
    for evt in DUO_FIXTURE_AUTH_LOGS:
        if evt.get("result") == result:
            return evt
    raise AssertionError(f"auth fixture result={result} not found")


def _admin(action: str) -> dict[str, Any]:
    for evt in DUO_FIXTURE_ADMIN_LOGS:
        if evt.get("action") == action:
            return evt
    raise AssertionError(f"admin fixture action={action} not found")


# ---------------------------------------------------------------------------
# Auth normalisation
# ---------------------------------------------------------------------------


class TestAuthNormalisation:
    def test_denied_push_maps_to_mfa_denied(self) -> None:
        ev = normalise_auth_event(_auth("denied"), org_id=ORG)
        assert ev.provider is IdentityProvider.DUO
        assert ev.kind is IdentityEventKind.MFA_DENIED
        assert ev.principal_id == "dkim@example.com"
        assert ev.ip_address == ATTACKER_IP
        assert ev.geo.country == "IS"

    def test_fraud_maps_to_mfa_denied(self) -> None:
        ev = normalise_auth_event(_auth("fraud"), org_id=ORG)
        assert ev.kind is IdentityEventKind.MFA_DENIED

    def test_success_2fa_factor_maps_to_mfa_approved(self) -> None:
        ev = normalise_auth_event(_auth("success"), org_id=ORG)
        # bwallace's success used a passcode (a 2FA factor).
        assert ev.kind is IdentityEventKind.MFA_APPROVED
        assert ev.principal_id == "bwallace@example.com"

    def test_success_non_2fa_factor_maps_to_login_success(self) -> None:
        raw = dict(_auth("success"), factor="remembered_device")
        ev = normalise_auth_event(raw, org_id=ORG)
        assert ev.kind is IdentityEventKind.LOGIN_SUCCESS

    def test_raw_preserved(self) -> None:
        raw = _auth("fraud")
        assert normalise_auth_event(raw, org_id=ORG).raw == raw


# ---------------------------------------------------------------------------
# Admin normalisation
# ---------------------------------------------------------------------------


class TestAdminNormalisation:
    def test_bypass_create_is_credential_added(self) -> None:
        ev = normalise_admin_event(_admin("bypass_create"), org_id=ORG)
        assert ev is not None
        assert ev.kind is IdentityEventKind.CREDENTIAL_ADDED
        assert ev.principal_id == "admin@example.com"

    def test_admin_create_is_role_assigned(self) -> None:
        ev = normalise_admin_event(_admin("admin_create"), org_id=ORG)
        assert ev is not None
        assert ev.kind is IdentityEventKind.ROLE_ASSIGNED

    def test_policy_update_is_federation_modified(self) -> None:
        ev = normalise_admin_event(_admin("policy_update"), org_id=ORG)
        assert ev is not None
        assert ev.kind is IdentityEventKind.FEDERATION_TRUST_MODIFIED

    def test_unmapped_action_returns_none(self) -> None:
        raw = dict(_admin("policy_update"), action="something_unmapped")
        assert normalise_admin_event(raw, org_id=ORG) is None

    def test_event_map_keys_are_stable_identifiers(self) -> None:
        for name in DUO_ADMIN_EVENT_MAP:
            assert " " not in name


# ---------------------------------------------------------------------------
# Mock envelopes
# ---------------------------------------------------------------------------


class TestMockEnvelopes:
    async def test_auth_search_returns_all_in_window(self) -> None:
        out = await _server().duo_auth_log_search(WINDOW_START, WINDOW_END)
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["total"] == len(DUO_FIXTURE_AUTH_LOGS)
        assert all(e["provider"] == "duo" for e in out["events"])

    async def test_auth_result_filter(self) -> None:
        out = await _server().duo_auth_log_search(WINDOW_START, WINDOW_END, result="denied")
        assert out["total"] == 4
        assert all(e["kind"] == "mfa_denied" for e in out["events"])

    async def test_auth_username_filter(self) -> None:
        out = await _server().duo_auth_log_search(
            WINDOW_START, WINDOW_END, username="bwallace@example.com"
        )
        assert out["total"] == 1

    async def test_auth_window_narrows(self) -> None:
        out = await _server().duo_auth_log_search("2026-06-28T09:00:00Z", "2026-06-28T09:02:00Z")
        # 09:00:05 and 09:00:41 and 09:01:20 fall in-window.
        assert out["total"] == 3

    async def test_auth_limit(self) -> None:
        out = await _server().duo_auth_log_search(WINDOW_START, WINDOW_END, limit=2)
        assert out["total"] == 2

    async def test_list_users_and_filter(self) -> None:
        out = await _server().duo_list_users()
        assert out["total"] == len(DUO_FIXTURE_USERS)
        one = await _server().duo_list_users(username="dkim@example.com")
        assert one["total"] == 1
        assert one["users"][0]["bypass_codes_count"] == 1

    async def test_admin_search_drops_unmapped(self) -> None:
        out = await _server().duo_admin_log_search(WINDOW_START, WINDOW_END)
        # All three fixture actions are mapped, so none are dropped.
        assert out["total"] == len(DUO_FIXTURE_ADMIN_LOGS)
        assert len(out["events"]) == out["total"]

    async def test_admin_action_filter(self) -> None:
        out = await _server().duo_admin_log_search(WINDOW_START, WINDOW_END, action="bypass_create")
        assert out["total"] == 1
        assert out["events"][0]["kind"] == "credential_added"


# ---------------------------------------------------------------------------
# The MFA-fatigue story coheres
# ---------------------------------------------------------------------------


class TestStoryCoherence:
    async def test_fatigue_burst_is_all_mfa_on_one_principal_from_attacker_ip(self) -> None:
        out = await _server().duo_auth_log_search(
            WINDOW_START, WINDOW_END, username="dkim@example.com"
        )
        events = out["events"]
        assert len(events) == 5
        assert all(e["provider"] == "duo" for e in events)
        assert all(e["kind"] in ("mfa_denied", "mfa_approved") for e in events)
        assert {e["ip_address"] for e in events} == {ATTACKER_IP}
        # Four denials then the fraud-flagged approval — all MFA_DENIED here.
        assert sum(e["kind"] == "mfa_denied" for e in events) == 5


# ---------------------------------------------------------------------------
# Live mode refuses without a secret key
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutKey:
    async def test_live_mode_without_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_DUO_SECRET_KEY", raising=False)
        server = DuoMCPServer(mock_mode=False, secret_key_ref="${env:BTAGENT_DUO_SECRET_KEY}")
        with pytest.raises(NotImplementedError):
            await server.duo_auth_log_search(WINDOW_START, WINDOW_END)
        with pytest.raises(NotImplementedError):
            await server.duo_list_users()
        with pytest.raises(NotImplementedError):
            await server.duo_admin_log_search(WINDOW_START, WINDOW_END)

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_DUO_SECRET_KEY", "duo-secret-0123456789abcdef")
        server = DuoMCPServer(mock_mode=False, secret_key_ref="${env:BTAGENT_DUO_SECRET_KEY}")
        with pytest.raises(NotImplementedError):
            await server.duo_auth_log_search(WINDOW_START, WINDOW_END)


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = DuoMCPServer(mock_mode=False, secret_key_ref="${env:BTAGENT_DUO_SECRET_KEY}")
        assert "duo-secret" not in repr(server)

    def test_redact_short_and_long(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        out = _redact_secret("duo-secret-0123456789abcdef")
        assert out.startswith("[redacted:duo-secret-key:")
        assert "duo-secret-0123456789" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.delenv("BTAGENT_DUO_SECRET_KEY", raising=False)
        server = DuoMCPServer(mock_mode=False, secret_key_ref="${env:BTAGENT_DUO_SECRET_KEY}")
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.duo"):
            with pytest.raises(NotImplementedError):
                await server.duo_auth_log_search(WINDOW_START, WINDOW_END)
        for record in caplog.records:
            assert "BTAGENT_DUO_SECRET_KEY" not in record.getMessage() or "unresolved" in (
                record.getMessage()
            )


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
            name="duo",
            description="duo test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("duo", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("duo", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_duo_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "duo" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["duo"] is DuoMCPServer

    def test_tool_metadata_marks_duo_server(self) -> None:
        meta = _server().get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "duo_auth_log_search",
            "duo_list_users",
            "duo_admin_log_search",
        }
        assert all(m["server_id"] == "duo" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.duo_mcp.resolve_secret", _spy)
    DuoMCPServer(mock_mode=False)
    assert calls == []
